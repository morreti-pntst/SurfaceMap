import ipaddress
import os
import re
import csv
import html
import io
import json
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit
from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, UploadFile, status
from fastapi.encoders import jsonable_encoder
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import FileResponse, PlainTextResponse, Response
from kombu.exceptions import OperationalError as BrokerUnavailable
from sqlalchemy import case, func, or_, select, text, union
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session
from .db import SessionLocal, get_db
from .import_service import store_import
from .importers import SUPPORTED_FORMATS, parse_import, web_identity
from .audit_plan import ACTIVE_AUDITS, build_audit_plan
from .audit_comparison import audit_asset_membership, audit_evidence, compare_audits
from .custom_commands import WORDLIST_ROOT, build_custom_command, nmap_timeout_minutes
from .models import Asset, AssetRelationship, AuditRun, Finding, ImportBatch, Observation, ObservationSighting, Project, ProjectSnapshot, ScanJob, ScopeEntry, SystemSetting, ToolOperation, Workflow, WorkflowRun
from .schemas import AssetRead, AuditManualReview, AuditPlanRequest, AuditRunCreate, AuditRunRead, FindingRead, FindingStatusUpdate, ImportBatchRead, ProjectCreate, ProjectRead, ScopeCreate, ScopeRead, SnapshotRead, ScanJobCreate, ScanJobRead, ToolOperationCreate, ToolOperationRead, ToolSettings, WorkflowCreate, WorkflowRunCreate
from .scope_guard import scope_matches
from .surface_builder import (
    MAP_LINK_LIMIT, MAP_NODE_LIMIT, MapRead, ObservedLayout, copy_observed_graph, observed_draft_query,
    router as surface_builder_router,
)
from .tool_manager import binary_path, installed_version
from .tool_operations import DEFAULT_TOOL_SETTINGS
from .tool_registry import TOOL_BY_ID, TOOLS, bounded_option, public_tool
from .wrapped_ports import HOST_TYPES, LEGACY_WRAPPED_SUFFIX, MAP_WRAPPED_LIMIT, observed_wrapped_ports

app = FastAPI(title="SURFACEMAP API", version="0.6.0", docs_url=None, redoc_url=None,
              openapi_url="/api/openapi.json", description="Local-first attack surface intelligence with scope-enforced scanner adapters.")
app.include_router(surface_builder_router)
logger = logging.getLogger(__name__)
MAX_IMPORT_BYTES = 10 * 1024 * 1024
MAX_WORDLIST_BYTES = 10 * 1024 * 1024


@app.get("/api/docs", include_in_schema=False)
def api_docs():
    return get_swagger_ui_html(openapi_url="/api/openapi.json", title="SurfaceMap API",
                               swagger_js_url="/api-docs-assets/swagger-ui-bundle.js",
                               swagger_css_url="/api-docs-assets/swagger-ui.css",
                               swagger_favicon_url="/api-docs-assets/favicon-32x32.png")

@app.on_event("startup")
def queue_missing_priority_tools():
    """Install pinned priority adapters asynchronously after migrations complete."""
    with SessionLocal() as db:
        try:
            settings = db.get(SystemSetting, "tool_manager")
        except OperationalError:
            # Test clients may use the foundation schema before applying the
            # full migration chain; production startup runs Alembic first.
            return
        preferences = {**DEFAULT_TOOL_SETTINGS, **(settings.value if settings else {})}
        if not preferences["check_updates_on_startup"]:
            return
        for tool in TOOLS:
            if not (tool.module or tool.id == "nmap"):
                continue
            current = installed_version(tool)
            if current == tool.version.lstrip("v"):
                continue
            if not preferences["automatic_updates"] or not preferences["update_stable_releases"]:
                continue
            if db.bind.dialect.name == "postgresql":
                db.execute(text("SELECT pg_advisory_xact_lock(90713)"))
            previous = db.scalar(select(ToolOperation).where(ToolOperation.tool_id == tool.id)
                                 .order_by(ToolOperation.id.desc()).limit(1))
            if previous and (previous.status in {"queued", "running"} or
                             (previous.action == "uninstall" and previous.status == "completed")):
                db.rollback()
                continue
            op = ToolOperation(tool_id=tool.id, action="update" if current else "install", version=tool.version, status="queued")
            db.add(op); db.commit(); db.refresh(op)
            _dispatch_tool_operation(op, db)

def read_import(project_id: int, file_format: str, upload: UploadFile, db: Session):
    if not db.get(Project, project_id):
        raise HTTPException(404, "Project not found")
    if file_format not in SUPPORTED_FORMATS:
        raise HTTPException(422, f"Unsupported format. Choose one of: {', '.join(sorted(SUPPORTED_FORMATS))}")
    content = upload.file.read(MAX_IMPORT_BYTES + 1)
    if len(content) > MAX_IMPORT_BYTES:
        raise HTTPException(413, "Import file exceeds the 10 MiB limit")
    try:
        decoded = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(422, "Import file must use UTF-8 encoding") from exc
    try:
        parsed = parse_import(file_format, decoded)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if not parsed.records:
        raise HTTPException(422, "No supported records found in this file")
    return parsed

@app.get("/api/health", tags=["system"])
def health(db: Session = Depends(get_db)):
    db.execute(text("SELECT 1"))
    return {"status": "ok", "database": "connected", "version": app.version}

@app.get("/api/system/status", tags=["system"])
def system_status(db: Session = Depends(get_db)):
    db.execute(text("SELECT 1"))
    redis_state = "unavailable"
    worker_state = "unavailable"
    try:
        from redis import Redis
        redis_client = Redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"), socket_connect_timeout=1, socket_timeout=1)
        redis_state = "connected" if redis_client.ping() else "unavailable"
    except Exception:
        pass
    if redis_state == "connected":
        try:
            from .worker import celery_app
            worker_state = "connected" if celery_app.control.inspect(timeout=1).ping() else "unavailable"
        except Exception:
            pass
    active_jobs = db.scalar(select(func.count(ScanJob.id)).where(ScanJob.status.in_(["queued", "running", "cancelling"]))) or 0
    active_tool_operations = db.scalar(select(func.count(ToolOperation.id)).where(ToolOperation.status.in_(["queued", "running"]))) or 0
    return {"api":"connected", "database":"connected", "redis":redis_state, "worker":worker_state,
            "active_jobs":active_jobs, "active_tool_operations":active_tool_operations}

@app.get("/api/projects", response_model=list[ProjectRead], tags=["projects"])
def list_projects(db: Session = Depends(get_db)):
    return db.scalars(select(Project).order_by(Project.created_at.desc())).all()

@app.post("/api/projects", response_model=ProjectRead, status_code=status.HTTP_201_CREATED, tags=["projects"])
def create_project(payload: ProjectCreate, db: Session = Depends(get_db)):
    project = Project()
    db.add(project)
    return _save_project(project, payload, db)


def _save_project(project: Project, payload: ProjectCreate, db: Session) -> Project:
    project.name = payload.name.strip()
    project.description = payload.description.strip()
    if not project.name:
        raise HTTPException(422, "Project name cannot be blank")
    try:
        db.commit()
        db.refresh(project)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "A project with this name already exists") from exc
    return project

@app.get("/api/projects/{project_id}", response_model=ProjectRead, tags=["projects"])
def get_project(project_id: int, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "Project not found")
    return project


@app.patch("/api/projects/{project_id}", response_model=ProjectRead, tags=["projects"])
def edit_project(project_id: int, payload: ProjectCreate, db: Session = Depends(get_db)):
    return _save_project(get_project(project_id, db), payload, db)


@app.post("/api/projects/{project_id}/duplicate", response_model=ProjectRead, status_code=201, tags=["projects"])
def duplicate_project(project_id: int, payload: ProjectCreate, db: Session = Depends(get_db)):
    source = get_project(project_id, db)
    project = Project(scopes=[ScopeEntry(kind=rule.kind, value=rule.value, excluded=rule.excluded)
                              for rule in source.scopes if rule.kind != "all"])
    db.add(project)
    return _save_project(project, payload, db)


@app.delete("/api/projects/{project_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["projects"])
def delete_project(project_id: int, db: Session = Depends(get_db)):
    _lock_scan_queue(db)
    project = get_project(project_id, db)
    if project_id in _active_scan_capacity(db)[1]:
        raise HTTPException(409, "Stop this project's running or queued jobs before deleting it")
    db.delete(project)
    db.commit()
    from .scan_runner import ARTIFACT_ROOT

    root = ARTIFACT_ROOT.resolve()
    path = root / f"project-{project_id}"
    try:
        if path.is_dir() and path.resolve().parent == root and not path.is_symlink():
            shutil.rmtree(path)
    except OSError:
        logger.exception("Could not clean up artifacts for deleted project %s", project_id)

@app.post("/api/projects/{project_id}/scope", response_model=ScopeRead, status_code=201, tags=["scope"])
def add_scope(project_id: int, payload: ScopeCreate, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "Project not found")
    value = payload.value.strip().lower()
    kind = payload.kind.lower()
    if kind not in {"domain", "ip", "cidr"}:
        raise HTTPException(422, "Scope kind must be domain, ip, or cidr")
    if not value or any(c.isspace() for c in value):
        raise HTTPException(422, "Scope value must be a single hostname or network")
    wildcard = value.startswith("*.")
    candidate = value[2:] if wildcard else value
    if wildcard and kind != "domain":
        raise HTTPException(422, "Wildcard scope is only valid for domains")
    try:
        if kind == "ip":
            value = ipaddress.ip_address(candidate).compressed
        elif kind == "cidr":
            value = ipaddress.ip_network(candidate, strict=False).with_prefixlen
        elif kind == "domain":
            candidate = candidate.encode("idna").decode("ascii").lower()
            if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", candidate):
                raise ValueError("invalid domain")
            value = f"*.{candidate}" if wildcard else candidate
    except ValueError as exc:
        raise HTTPException(422, f"Invalid {kind} scope value") from exc
    item = ScopeEntry(project_id=project_id, value=value, kind=kind, excluded=payload.excluded)
    db.add(item)
    try:
        db.commit()
        db.refresh(item)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Could not add scope entry") from exc
    return item

@app.put("/api/projects/{project_id}/scope/full-access", status_code=204, tags=["scope"])
def set_full_scope(project_id: int, enabled: bool, db: Session = Depends(get_db)):
    project = db.scalar(select(Project).where(Project.id == project_id).with_for_update())
    if not project:
        raise HTTPException(404, "Project not found")
    rules = db.scalars(select(ScopeEntry).where(
        ScopeEntry.project_id == project_id, ScopeEntry.kind == "all",
    )).all()
    if enabled and not rules:
        db.add(ScopeEntry(project_id=project_id, kind="all", value="*", excluded=False))
    elif not enabled:
        for rule in rules:
            db.delete(rule)
    db.commit()

@app.delete("/api/projects/{project_id}/scope/{scope_id}", status_code=204, tags=["scope"])
def delete_scope(project_id: int, scope_id: int, db: Session = Depends(get_db)):
    item = db.scalar(select(ScopeEntry).where(ScopeEntry.id == scope_id, ScopeEntry.project_id == project_id))
    if not item:
        raise HTTPException(404, "Scope entry not found")
    db.delete(item)
    db.commit()

def _tool_status(tool):
    installed = installed_version(tool)
    return public_tool(tool, installed, "not_installed")

@app.get("/api/tools", tags=["tools"])
def list_tools(db: Session = Depends(get_db)):
    latest_ids = select(func.max(ToolOperation.id)).group_by(ToolOperation.tool_id)
    latest_ops = {op.tool_id: op for op in db.scalars(
        select(ToolOperation).where(ToolOperation.id.in_(latest_ids))
    )}
    response = []
    for tool in TOOLS:
        status_data = _tool_status(tool)
        operation = latest_ops.get(tool.id)
        if operation:
            if not status_data["version"]:
                if operation.status in {"queued", "running"}:
                    status_data["status"] = "installing"
                elif operation.status == "failed":
                    status_data["status"] = "failed"
            if operation.status in {"queued", "running", "failed"}:
                log = operation.log.strip().splitlines()
                status_data["operation"] = {
                    "id": operation.id, "action": operation.action, "status": operation.status,
                    "version": operation.version, "progress": log[-1][:240] if log else "",
                    "error": operation.error,
                }
        response.append(status_data)
    return response


@app.get("/api/tools/setup-progress", response_class=PlainTextResponse, tags=["tools"])
def tool_setup_progress(db: Session = Depends(get_db)):
    adapters = [tool for tool in list_tools(db) if tool["active_adapter"]]
    ready = sum(tool["status"] == "installed" for tool in adapters)
    lines = [f"Ready tools: {ready}/{len(adapters)}"]
    for tool in adapters:
        if tool["status"] == "installed":
            continue
        op = tool.get("operation")
        if op:
            detail = op["error"] if op["status"] == "failed" else op["progress"]
            summary = f"{op['action']} {op['version']} {op['status']} (#{op['id']})"
        else:
            summary = tool["status"].replace("_", " ")
            detail = ""
        version = f" · detected {tool['version']}, required {tool['latest_version']}" if tool["version"] else ""
        detail = " ".join(detail.split())[:350]
        lines.append(f"  {tool['name']}: {summary}{version}" + (f" · {detail}" if detail else ""))
    if ready < len(adapters) and not any(
        tool.get("operation", {}).get("status") in {"queued", "running"} for tool in adapters
    ):
        lines.append("Setup needs attention. Open Tool Manager for errors and use Install or update all adapters to retry.")
    return "\n".join(lines) + "\n"

@app.get("/api/tool-operations", response_model=list[ToolOperationRead], tags=["tools"])
def list_tool_operations(limit: int = 100, db: Session = Depends(get_db)):
    limit = max(1, min(limit, 500))
    return db.scalars(select(ToolOperation).order_by(ToolOperation.created_at.desc()).limit(limit)).all()

@app.get("/api/wordlists", tags=["tools"])
def list_wordlists():
    WORDLIST_ROOT.mkdir(parents=True, exist_ok=True)
    return [{"name":p.name,"path":str(p),"bytes":p.stat().st_size} for p in sorted(WORDLIST_ROOT.iterdir())
            if p.is_file() and p.suffix.lower() in {".txt", ".list"} and not p.is_symlink()]

@app.post("/api/wordlists", status_code=201, tags=["tools"])
def upload_wordlist(file: UploadFile = File(...)):
    filename = os.path.basename(file.filename or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,100}\.(?:txt|list)", filename, flags=re.IGNORECASE):
        raise HTTPException(422, "Wordlist name must use letters, numbers, dot, dash, or underscore and end in .txt or .list")
    content = file.file.read(MAX_WORDLIST_BYTES + 1)
    if len(content) > MAX_WORDLIST_BYTES:
        raise HTTPException(413, "Wordlist exceeds the 10 MiB limit")
    try:
        text_content = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(422, "Wordlist must use UTF-8 encoding") from exc
    if not text_content.strip() or len(text_content.splitlines()) > 100000:
        raise HTTPException(422, "Wordlist must contain 1 to 100,000 lines")
    WORDLIST_ROOT.mkdir(parents=True, exist_ok=True)
    destination = WORDLIST_ROOT / filename
    temporary = WORDLIST_ROOT / f".{filename}.upload"
    temporary.write_text(text_content, encoding="utf-8")
    os.replace(temporary, destination)
    return {"name":filename,"path":str(destination),"bytes":destination.stat().st_size}

@app.get("/api/settings/tools", tags=["settings"])
def get_tool_settings(db: Session = Depends(get_db)):
    setting = db.get(SystemSetting, "tool_manager")
    return {**DEFAULT_TOOL_SETTINGS, **(setting.value if setting else {})}

@app.put("/api/settings/tools", tags=["settings"])
def update_tool_settings(payload: ToolSettings, db: Session = Depends(get_db)):
    setting = db.get(SystemSetting, "tool_manager")
    if not setting:
        setting = SystemSetting(key="tool_manager", value=payload.model_dump())
        db.add(setting)
    else:
        setting.value = payload.model_dump()
    db.commit()
    return setting.value

def _dispatch_tool_operation(operation: ToolOperation, db: Session) -> None:
    from .worker import manage_tool
    try:
        task = manage_tool.apply_async(args=[operation.id], retry=False)
    except (BrokerUnavailable, OSError):
        # The durable queued row will be picked up after the broker recovers.
        return
    operation.task_id = task.id
    db.commit()


def _queue_tool_operation(tool_id: str, action: str, db: Session):
    tool = TOOL_BY_ID.get(tool_id)
    if not tool:
        raise HTTPException(404, "Tool adapter not found")
    if action in {"install", "update", "reinstall"} and not tool.module and tool.id != "nmap":
        raise HTTPException(409, "This tool is part of the application image and is updated with `surfacemap update`.")
    if db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(90713)"))
    active = db.scalar(select(ToolOperation).where(
        ToolOperation.tool_id == tool_id, ToolOperation.status.in_(["queued", "running"]),
    ).order_by(ToolOperation.id.desc()).limit(1))
    if active:
        if active.version == tool.version and (active.action == action or (
            active.action in {"install", "update", "reinstall"} and action in {"install", "update", "reinstall"}
        )):
            return active
        raise HTTPException(409, f"{tool.name} operation #{active.id} ({active.action}) is {active.status}. "
                                 "Open Tool Manager → Installation history to follow its progress.")
    if action == "install" and installed_version(tool):
        raise HTTPException(409, "Tool is already installed")
    operation = ToolOperation(tool_id=tool_id, action=action, version=tool.version, status="queued")
    db.add(operation)
    db.commit(); db.refresh(operation)
    _dispatch_tool_operation(operation, db)
    db.refresh(operation)
    return operation

@app.post("/api/tools/{tool_id}/operations", response_model=ToolOperationRead, status_code=202, tags=["tools"])
def create_tool_operation(tool_id: str, payload: ToolOperationCreate, db: Session = Depends(get_db)):
    try:
        return _queue_tool_operation(tool_id, payload.action, db)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc

@app.post("/api/tools/operations/install-all", response_model=list[ToolOperationRead], status_code=202, tags=["tools"])
def install_all_tools(db: Session = Depends(get_db)):
    operations = []
    for tool in TOOLS:
        current = installed_version(tool)
        if (tool.module or tool.id == "nmap") and current != tool.version.lstrip("v"):
            try:
                operations.append(_queue_tool_operation(tool.id, "update" if current else "install", db))
            except HTTPException as exc:
                if exc.status_code != 409:
                    raise
    return operations

def _scan_command(tool_id: str, target: str, options: dict, db: Session, project_id: int):
    tool = TOOL_BY_ID.get(tool_id)
    if not tool or not tool.active:
        raise HTTPException(404, "No executable adapter is registered for this tool")
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "Project not found")
    custom = options.get("custom_command", "")
    if not isinstance(custom, str):
        raise HTTPException(422, "Custom command must be text")
    entries = db.scalars(select(ScopeEntry).where(ScopeEntry.project_id == project_id)).all()
    try:
        if custom:
            if tool_id == "nuclei":
                bounded_option(options, "timeout_minutes", 15, 5, 60)
            compiled = build_custom_command(tool_id, custom, target, "<output>",
                                            nmap_minutes=nmap_timeout_minutes(options) if tool_id == "nmap" else 5,
                                            user_agent=options.get("user_agent", ""))
            target = compiled.target
        allowed, detail = scope_matches(target, entries, allow_network=(tool_id == "nmap"))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if not allowed:
        raise HTTPException(422, {"message":"Target is outside project scope", "target":target, "reason":detail})
    if custom:
        return tool, target, compiled.argv
    allowed_options = {field["name"] for field in tool.option_fields} | {"raw_arguments"}
    unknown = set(options) - allowed_options
    if unknown:
        raise HTTPException(422, f"Unsupported options for {tool.name}: {', '.join(sorted(unknown))}")
    from .scan_runner import build_target
    try:
        normalized = build_target(tool_id, target)
        command = tool.command(normalized, options, "<output>")
    except (TypeError, ValueError) as exc:
        raise HTTPException(422, str(exc)) from exc
    return tool, normalized, command


def _job_options(payload: ScanJobCreate) -> dict:
    if payload.custom_command.strip():
        options = {"custom_command": payload.custom_command.strip()}
        if "user_agent" in payload.options:
            options["user_agent"] = payload.options["user_agent"]
        if payload.tool_id in {"nmap", "nuclei"} and "timeout_minutes" in payload.options:
            options["timeout_minutes"] = payload.options["timeout_minutes"]
        return options
    return {**payload.options, "raw_arguments": payload.raw_arguments}


def _project_finding(project_id: int, finding_id: int, db: Session) -> Finding:
    finding = db.scalar(select(Finding).where(Finding.id == finding_id, Finding.project_id == project_id))
    if not finding:
        raise HTTPException(404, "Finding not found")
    return finding


def _scan_request_options(project_id: int, payload: ScanJobCreate, db: Session) -> dict:
    if payload.retest_finding_id is None:
        return _job_options(payload)
    finding = _project_finding(project_id, payload.retest_finding_id, db)
    if (payload.tool_id != "nuclei" or payload.custom_command.strip() or payload.raw_arguments.strip()
            or set(payload.options) - {"rate"}):
        raise HTTPException(422, "An exact retest accepts only the original template, target and a request rate")
    original = web_identity(finding.matched_at)
    if not original or not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", finding.template_id):
        raise HTTPException(422, "This finding has no supported HTTP template and route for a retest")
    source = web_identity(finding.evidence.get("scan_target"))
    expected = source if source and source[0] == original[0] else original
    if web_identity(payload.target) != expected:
        raise HTTPException(422, "Use the original scan input's scheme, host, port, path and query parameter names")
    if any(not value for _, value in parse_qsl(urlsplit(payload.target).query, keep_blank_values=True)):
        raise HTTPException(422, "Fill in the original query parameters with approved test values")
    return {"rate": payload.options.get("rate", 2), "template_id": finding.template_id,
            "severity": ["critical", "high", "medium", "low", "info"]}

def _active_scan_capacity(db: Session) -> tuple[int, set[int]]:
    active_jobs = db.scalars(select(ScanJob).where(ScanJob.status.in_(["queued", "running", "cancelling"]))).all()
    active_runs = db.scalars(select(WorkflowRun).where(WorkflowRun.status.in_(["queued", "running"]))).all()
    active_job_ids = {job.id for job in active_jobs}
    reserved_projects = {run.project_id for run in active_runs if not any(job_id in active_job_ids for job_id in run.job_ids)}
    active_audit_ids = {job.audit_run_id for job in active_jobs if job.audit_run_id is not None}
    audits = db.scalars(select(AuditRun).where(AuditRun.status.in_(ACTIVE_AUDITS))).all()
    reserved_projects.update(run.project_id for run in audits if run.id not in active_audit_ids)
    project_ids = {job.project_id for job in active_jobs} | reserved_projects
    return len(active_jobs) + len(reserved_projects), project_ids

def _lock_scan_queue(db: Session) -> None:
    if db.bind and db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(574992613)"))


def _reserve_project_queue(project_id: int, db: Session) -> tuple[int, set[int]]:
    _lock_scan_queue(db)
    if db.scalar(select(Project.id).where(Project.id == project_id)) is None:
        raise HTTPException(404, "Project not found")
    return _active_scan_capacity(db)


def _audit_plan(project_id: int, payload: AuditPlanRequest, db: Session) -> dict:
    if not db.get(Project, project_id):
        raise HTTPException(404, "Project not found")
    rules = db.scalars(select(ScopeEntry).where(ScopeEntry.project_id == project_id).order_by(ScopeEntry.id)).all()
    try:
        return build_audit_plan(payload, rules, WORDLIST_ROOT)
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, str(exc)) from exc


@app.post("/api/projects/{project_id}/audits/preview", tags=["audits"])
def preview_audit(project_id: int, payload: AuditPlanRequest, db: Session = Depends(get_db)):
    return _audit_plan(project_id, payload, db)


@app.post("/api/projects/{project_id}/audits", response_model=AuditRunRead, status_code=202, tags=["audits"])
def start_audit(project_id: int, payload: AuditRunCreate, db: Session = Depends(get_db)):
    if not payload.confirm_scope:
        raise HTTPException(422, "Confirm that the selected targets and checks are authorized")
    plan = _audit_plan(project_id, payload, db)
    if payload.plan_token != plan["plan_token"]:
        raise HTTPException(409, "The plan or project scope changed. Preview the plan again before starting.")
    if not any(stage["ready"] for stage in plan["stages"]):
        raise HTTPException(409, "No planned adapter is installed at a supported version")
    active_count, active_projects = _reserve_project_queue(project_id, db)
    if active_count >= 2 or project_id in active_projects:
        raise HTTPException(429, "A scan or audit already occupies the available project or worker slot")
    run = AuditRun(project_id=project_id, target=plan["target"], profile=plan["profile"],
                   config={**plan["config"], "notes": plan["notes"], "max_jobs": plan["max_jobs"]},
                   stages=plan["stages"], scope_snapshot=plan["scope_snapshot"])
    db.add(run)
    db.commit()
    from .worker import run_audit
    try:
        run_audit.apply_async(args=[run.id], retry=False)
    except (BrokerUnavailable, OSError):
        # The periodic worker reconciler will publish the durable queued run.
        pass
    return run


@app.get("/api/projects/{project_id}/audits", response_model=list[AuditRunRead], tags=["audits"])
def list_audits(project_id: int, db: Session = Depends(get_db)):
    if not db.get(Project, project_id):
        raise HTTPException(404, "Project not found")
    return db.scalars(select(AuditRun).where(AuditRun.project_id == project_id)
                      .order_by(AuditRun.id.desc()).limit(30)).all()


def _get_audit(project_id: int, audit_id: int, db: Session, *, lock: bool = False) -> AuditRun:
    statement = select(AuditRun).where(AuditRun.project_id == project_id, AuditRun.id == audit_id)
    run = db.scalar(statement.with_for_update() if lock else statement)
    if not run:
        raise HTTPException(404, "Audit not found")
    return run


@app.get("/api/projects/{project_id}/audits/{audit_id}", response_model=AuditRunRead, tags=["audits"])
def get_audit(project_id: int, audit_id: int, db: Session = Depends(get_db)):
    return _get_audit(project_id, audit_id, db)


@app.get("/api/projects/{project_id}/audits/{audit_id}/compare/{baseline_id}", tags=["audits"])
def compare_audit_runs(project_id: int, audit_id: int, baseline_id: int, download: bool = False,
                       db: Session = Depends(get_db)):
    current = _get_audit(project_id, audit_id, db)
    baseline = _get_audit(project_id, baseline_id, db)
    if current.id == baseline.id:
        raise HTTPException(422, "Choose two different audit runs")
    if current.status in ACTIVE_AUDITS or baseline.status in ACTIVE_AUDITS:
        raise HTTPException(409, "Wait until both audits have stopped before comparing them")
    document = compare_audits(db, baseline, current, VISIBLE_ASSET)
    if download:
        return Response(json.dumps(jsonable_encoder(document), ensure_ascii=False, indent=2),
                        media_type="application/json", headers={
                            "Content-Disposition": f'attachment; filename="surfacemap-audits-{baseline_id}-{audit_id}.json"',
                        })
    return document


@app.patch("/api/projects/{project_id}/audits/{audit_id}/review/{check_id}", response_model=AuditRunRead, tags=["audits"])
def review_audit_check(project_id: int, audit_id: int, check_id: str, payload: AuditManualReview,
                       db: Session = Depends(get_db)):
    run = _get_audit(project_id, audit_id, db, lock=True)
    if not any(check["id"] == check_id for check in run.config.get("manual_checks", [])):
        raise HTTPException(404, "Manual check not found in this audit")
    run.manual_review = {**run.manual_review, check_id: {
        "status": payload.status, "notes": payload.notes.strip(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }}
    db.commit()
    return run


@app.get("/api/projects/{project_id}/audits/{audit_id}/report/{format_name}", tags=["audits"])
def export_audit_report(project_id: int, audit_id: int, format_name: str, db: Session = Depends(get_db)):
    from .audit_report import audit_document, audit_html

    if format_name not in {"json", "html"}:
        raise HTTPException(422, "Audit reports are available as JSON or HTML")
    run = _get_audit(project_id, audit_id, db)
    project = db.get(Project, project_id)
    document = audit_document(db, project, run)
    content = audit_html(document) if format_name == "html" else json.dumps(document, ensure_ascii=False, indent=2)
    return Response(content, media_type="text/html" if format_name == "html" else "application/json", headers={
        "Content-Disposition": f'attachment; filename="surfacemap-audit-{audit_id}.{format_name}"',
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
    })


def _request_audit_cancel(db: Session, run: AuditRun) -> None:
    if run.status == "queued":
        run.status = "cancelled"
        run.error = "Stopped before execution."
        run.completed_at = datetime.now(timezone.utc)
        run.stages = [{**stage, "status": "skipped", "reason": run.error} for stage in run.stages]
        return
    run.status = "cancelling"
    children = db.scalars(select(ScanJob).where(ScanJob.audit_run_id == run.id,
                          ScanJob.status.in_(["queued", "running"])).with_for_update()).all()
    for job in children:
        job.status = "cancelling"


@app.post("/api/projects/{project_id}/audits/{audit_id}/cancel", response_model=AuditRunRead, tags=["audits"])
def cancel_audit(project_id: int, audit_id: int, db: Session = Depends(get_db)):
    run = _get_audit(project_id, audit_id, db, lock=True)
    if run.status not in ACTIVE_AUDITS:
        raise HTTPException(409, "This audit has already ended")
    _request_audit_cancel(db, run)
    db.commit()
    return run

@app.post("/api/projects/{project_id}/scan-jobs/preview", tags=["scan jobs"])
def preview_scan_job(project_id: int, payload: ScanJobCreate, db: Session = Depends(get_db)):
    from .scan_runner import scan_timeout_seconds

    options = _scan_request_options(project_id, payload, db)
    tool, normalized, command = _scan_command(payload.tool_id, payload.target, options, db, project_id)
    observed_version = installed_version(tool)
    supported_version_ready = observed_version == tool.version.lstrip("v")
    rate = build_custom_command(tool.id, options["custom_command"], normalized, "<output>").rate if "custom_command" in options else tool.request_rate(options) if tool.id in {"httpx", "nuclei", "ffuf", "katana"} else None
    return {"tool_id":tool.id, "tool_name":tool.name, "target":normalized, "command":command,
            "installed":supported_version_ready, "tool_version":observed_version,
            "scope_checked":True, "limits":{"timeout_seconds":scan_timeout_seconds(tool.id, None, options),
                                          "requests_per_second":rate, "max_concurrent_jobs":2}}

@app.get("/api/projects/{project_id}/scan-jobs", response_model=list[ScanJobRead], tags=["scan jobs"])
def list_scan_jobs(project_id: int, limit: int = 100, db: Session = Depends(get_db)):
    if not db.get(Project, project_id):
        raise HTTPException(404, "Project not found")
    limit = max(1, min(limit, 500))
    return db.scalars(select(ScanJob).where(ScanJob.project_id == project_id).order_by(ScanJob.created_at.desc()).limit(limit)).all()

@app.post("/api/projects/{project_id}/scan-jobs", response_model=ScanJobRead, status_code=202, tags=["scan jobs"])
def create_scan_job(project_id: int, payload: ScanJobCreate, db: Session = Depends(get_db)):
    options = _scan_request_options(project_id, payload, db)
    tool, normalized, command = _scan_command(payload.tool_id, payload.target, options, db, project_id)
    if installed_version(tool) != tool.version.lstrip("v"):
        raise HTTPException(409, f"{tool.name} does not have the adapter's supported pinned version installed yet.")
    active_count, active_projects = _reserve_project_queue(project_id, db)
    if active_count >= 2:
        raise HTTPException(429, "The global scan concurrency limit (2) has been reached")
    if project_id in active_projects:
        raise HTTPException(429, "This project already has a queued or running scan")
    job = ScanJob(project_id=project_id, tool_id=tool.id, target=normalized, status="queued",
                  options=options, command=command, tool_version=installed_version(tool),
                  retest_finding_id=payload.retest_finding_id, created_at=datetime.now(timezone.utc))
    db.add(job); db.commit(); db.refresh(job)
    from .worker import dispatch_scan
    dispatch_scan(db, job)
    return job

@app.post("/api/projects/{project_id}/scan-jobs/{job_id}/cancel", response_model=ScanJobRead, tags=["scan jobs"])
def cancel_scan_job(project_id: int, job_id: int, db: Session = Depends(get_db)):
    job = db.scalar(select(ScanJob).where(ScanJob.id == job_id, ScanJob.project_id == project_id).with_for_update())
    if not job:
        raise HTTPException(404, "Scan job not found")
    if job.status not in {"queued", "running"}:
        raise HTTPException(409, "Only queued or running jobs can be cancelled")
    if job.status == "queued":
        job.status = "cancelled"
        job.completed_at = datetime.now(timezone.utc)
    else:
        job.status = "cancelling"
    db.commit(); db.refresh(job)
    return job

@app.post("/api/projects/{project_id}/scan-jobs/{job_id}/retry", response_model=ScanJobRead, status_code=202, tags=["scan jobs"])
def retry_scan_job(project_id: int, job_id: int, db: Session = Depends(get_db)):
    previous = db.scalar(select(ScanJob).where(ScanJob.id == job_id, ScanJob.project_id == project_id))
    if not previous:
        raise HTTPException(404, "Scan job not found")
    if previous.status not in {"failed", "cancelled"}:
        raise HTTPException(409, "Only failed or cancelled jobs can be retried")
    tool = TOOL_BY_ID.get(previous.tool_id)
    if not tool or installed_version(tool) != tool.version.lstrip("v"):
        raise HTTPException(409, "The adapter's supported pinned version must be installed before retrying")
    tool, normalized, command = _scan_command(previous.tool_id, previous.target, previous.options, db, project_id)
    active_count, active_projects = _reserve_project_queue(project_id, db)
    if active_count >= 2 or project_id in active_projects:
        raise HTTPException(429, "Scan concurrency limit prevents retrying this job")
    job = ScanJob(project_id=project_id, tool_id=tool.id, target=normalized, status="queued",
        options=previous.options, command=command, tool_version=installed_version(tool), retry_of_id=previous.id,
        retest_finding_id=previous.retest_finding_id, created_at=datetime.now(timezone.utc))
    db.add(job); db.commit(); db.refresh(job)
    from .worker import dispatch_scan
    dispatch_scan(db, job)
    return job

@app.post("/api/scan-jobs/stop-all", tags=["scan jobs"])
def stop_all_scan_jobs(db: Session = Depends(get_db)):
    _lock_scan_queue(db)
    audits = db.scalars(select(AuditRun).where(AuditRun.status.in_(ACTIVE_AUDITS)).with_for_update()).all()
    for audit in audits:
        _request_audit_cancel(db, audit)
    workflows = db.scalars(select(WorkflowRun).where(WorkflowRun.status.in_(["queued", "running"])).with_for_update()).all()
    now = datetime.now(timezone.utc)
    for workflow in workflows:
        workflow.status = "cancelled"
        workflow.completed_at = now
    jobs = db.scalars(select(ScanJob).where(ScanJob.status.in_(["queued", "running", "cancelling"])).with_for_update()).all()
    for job in jobs:
        if job.status == "queued":
            job.status = "cancelled"
            job.completed_at = now
        else:
            job.status = "cancelling"
    db.commit()
    return {"cancelled": len(jobs), "audits": len(audits), "workflows": len(workflows)}

@app.get("/api/projects/{project_id}/scan-jobs/{job_id}/logs", tags=["scan jobs"])
def get_scan_logs(project_id: int, job_id: int, db: Session = Depends(get_db)):
    from .scan_diagnostics import nmap_progress, nuclei_progress, tail
    from .scan_runner import ARTIFACT_ROOT, scan_timeout_seconds

    job = db.scalar(select(ScanJob).where(ScanJob.id == job_id, ScanJob.project_id == project_id))
    if not job:
        raise HTTPException(404, "Scan job not found")
    directory = ARTIFACT_ROOT / f"project-{project_id}" / f"scan-{job_id}"
    events = tail(directory / "events.log")
    stderr = tail(directory / "stderr.log")
    stdout = tail(directory / "console.log")
    if not stdout and job.artifact_path and job.tool_id not in {"nmap", "subfinder", "nuclei"}:
        artifact = Path(job.artifact_path)
        if artifact.parent == directory:
            stdout = tail(artifact)
    now = datetime.now(timezone.utc)
    started = job.started_at
    end = job.completed_at or now
    elapsed = (end.replace(tzinfo=end.tzinfo or timezone.utc) -
               started.replace(tzinfo=started.tzinfo or timezone.utc)).total_seconds() if started else 0
    progress = {}
    if job.tool_id == "nuclei":
        progress = nuclei_progress(stdout, stderr)
    elif job.tool_id == "nmap" and job.status == "running":
        progress = nmap_progress(stdout)
    return {
        "status": job.status, "elapsed_seconds": max(0, int(elapsed)),
        "timeout_seconds": scan_timeout_seconds(job.tool_id, job.audit_run_id, job.options),
        "progress": progress,
        "events": events, "stderr": stderr, "stdout": stdout, "error": job.error,
        "command": job.command, "tool_id": job.tool_id, "exit_code": job.exit_code,
        "diagnostic": job.result_summary.get("diagnostic"),
    }

@app.get("/api/projects/{project_id}/scan-jobs/{job_id}/artifact", tags=["scan jobs"])
def download_scan_artifact(project_id: int, job_id: int, db: Session = Depends(get_db)):
    job = db.scalar(select(ScanJob).where(ScanJob.id == job_id, ScanJob.project_id == project_id))
    if not job:
        raise HTTPException(404, "Scan job not found")
    if not job.artifact_path or not Path(job.artifact_path).is_file():
        raise HTTPException(404, "No scan artifact is available")
    return FileResponse(job.artifact_path, filename=Path(job.artifact_path).name)


@app.get("/api/projects/{project_id}/scan-jobs/{job_id}/network-report", tags=["scan jobs"])
def download_network_report(project_id: int, job_id: int, db: Session = Depends(get_db)):
    from .scan_runner import ARTIFACT_ROOT

    job = db.scalar(select(ScanJob).where(ScanJob.id == job_id, ScanJob.project_id == project_id,
                         ScanJob.tool_id == "nmap", ScanJob.status == "completed"))
    path = ARTIFACT_ROOT / f"project-{project_id}" / f"scan-{job_id}" / "output.xml"
    if not job or not path.is_file() or path.stat().st_size > MAX_IMPORT_BYTES:
        raise HTTPException(404, "No completed Nmap report is available")
    parsed = parse_import("nmap_xml", path.read_text(encoding="utf-8", errors="replace"))
    report = {"target": job.target, "scan_id": job.id,
              "hosts": [row.data for row in parsed.records if row.kind == "nmap_host" and row.asset_type in {"ipv4", "ipv6"}],
              "ports": [row.data for row in parsed.records if row.kind in {"nmap_port", "nmap_filtered_group"}],
              "tcpwrapped": [{"host": row.asset_value, **row.data} for row in parsed.records if row.kind == "nmap_wrapped_ports"],
              "warnings": parsed.warnings[:200]}
    return Response(json.dumps(report, ensure_ascii=False, indent=2), media_type="application/json", headers={
        "Content-Disposition": f'attachment; filename="nmap-{job_id}-report.json"',
    })

@app.post("/api/projects/{project_id}/imports/preview", tags=["imports"])
def preview_import(project_id: int, file_format: str = Form(...), file: UploadFile = File(...), db: Session = Depends(get_db)):
    parsed = read_import(project_id, file_format, file, db)
    return {"format": file_format, "filename": os.path.basename(file.filename or "upload")[:255],
            "records": len(parsed.records), "assets": len({(r.asset_type, r.asset_value) for r in parsed.records}),
            "findings": sum(r.finding is not None for r in parsed.records), "warnings": parsed.warnings[:200]}

@app.post("/api/projects/{project_id}/imports", response_model=ImportBatchRead, status_code=201, tags=["imports"])
def create_import(project_id: int, file_format: str = Form(...), file: UploadFile = File(...), db: Session = Depends(get_db)):
    parsed = read_import(project_id, file_format, file, db)
    return store_import(db, project_id, file_format, os.path.basename(file.filename or "upload"), parsed)

@app.get("/api/projects/{project_id}/imports", response_model=list[ImportBatchRead], tags=["imports"])
def list_imports(project_id: int, db: Session = Depends(get_db)):
    if not db.get(Project, project_id):
        raise HTTPException(404, "Project not found")
    return db.scalars(select(ImportBatch).where(ImportBatch.project_id == project_id).order_by(ImportBatch.imported_at.desc())).all()

# Older Nmap imports created service assets for ambiguous tcpwrapped responses.
# Keep their evidence in storage while excluding them from service inventory.
VISIBLE_ASSET = ~((Asset.asset_type == "service") & Asset.canonical_value.endswith(LEGACY_WRAPPED_SUFFIX))


@app.get("/api/projects/{project_id}/search", tags=["projects"])
def search_project(project_id: int, q: str = Query(min_length=2, max_length=160), db: Session = Depends(get_db)):
    get_project(project_id, db)
    query = q.strip()
    if len(query) < 2:
        return {"assets": [], "findings": []}
    assets = db.scalars(select(Asset).where(Asset.project_id == project_id, VISIBLE_ASSET,
        Asset.canonical_value.icontains(query, autoescape=True)).order_by(Asset.last_seen.desc()).limit(6)).all()
    findings = db.scalars(select(Finding).where(Finding.project_id == project_id, or_(
        Finding.title.icontains(query, autoescape=True), Finding.template_id.icontains(query, autoescape=True),
        Finding.matched_at.icontains(query, autoescape=True))).order_by(Finding.last_seen.desc()).limit(6)).all()
    return {"assets": [{"id": item.id, "label": item.canonical_value, "detail": item.asset_type} for item in assets],
            "findings": [{"id": item.id, "label": item.title, "detail": item.severity} for item in findings]}

@app.get("/api/projects/{project_id}/assets", response_model=list[AssetRead], tags=["assets"])
def list_assets(project_id: int, db: Session = Depends(get_db)):
    if not db.get(Project, project_id):
        raise HTTPException(404, "Project not found")
    return db.scalars(select(Asset).where(Asset.project_id == project_id, VISIBLE_ASSET).order_by(Asset.canonical_value)).all()


def _get_visible_asset(project_id: int, asset_id: int, db: Session) -> Asset:
    asset = db.scalar(select(Asset).where(Asset.project_id == project_id, Asset.id == asset_id, VISIBLE_ASSET))
    if not asset:
        raise HTTPException(404, "Asset not found")
    return asset


@app.get("/api/projects/{project_id}/assets/{asset_id}/evidence", tags=["assets"])
def get_asset_evidence(project_id: int, asset_id: int, audit_id: int | None = None, db: Session = Depends(get_db)):
    _get_visible_asset(project_id, asset_id, db)
    query = select(Observation, ImportBatch, ScanJob.id.label("job_id")).where(
        Observation.project_id == project_id, Observation.asset_id == asset_id, ImportBatch.project_id == project_id)
    if audit_id is None:
        query = query.join(ImportBatch, ImportBatch.id == Observation.import_id)
    else:
        evidence = audit_evidence(db, _get_audit(project_id, audit_id, db))
        provenance = union(
            select(Observation.id.label("observation_id"), Observation.import_id)
            .where(Observation.project_id == project_id, Observation.asset_id == asset_id, Observation.import_id.in_(evidence.imports)),
            select(ObservationSighting.observation_id, ObservationSighting.import_id)
            .join(Observation, Observation.id == ObservationSighting.observation_id)
            .where(Observation.project_id == project_id, Observation.asset_id == asset_id,
                   ObservationSighting.import_id.in_(evidence.imports)),
        ).subquery()
        query = query.join(provenance, provenance.c.observation_id == Observation.id).join(ImportBatch, ImportBatch.id == provenance.c.import_id)
    rows = db.execute(query.outerjoin(ScanJob, (ScanJob.project_id == project_id) &
        (ScanJob.result_summary["import_id"].as_integer() == ImportBatch.id))
        .order_by(ImportBatch.imported_at.desc(), Observation.id.desc()).limit(31)).all()
    return {
        "observations": [{"id": item.id, "import_id": batch.id, "source": item.source_tool, "kind": item.kind,
                          "observed_at": batch.imported_at, "filename": batch.filename,
                          "job_id": job_id, "data": item.data} for item, batch, job_id in rows[:30]],
        "truncated": len(rows) > 30,
    }

@app.get("/api/projects/{project_id}/findings", response_model=list[FindingRead], tags=["findings"])
def list_findings(project_id: int, audit_id: int | None = None, db: Session = Depends(get_db)):
    if not db.get(Project, project_id):
        raise HTTPException(404, "Project not found")
    query = select(Finding).where(Finding.project_id == project_id)
    if audit_id is not None:
        run = _get_audit(project_id, audit_id, db)
        query = query.where(Finding.id.in_(audit_evidence(db, run).findings))
    return db.scalars(query.order_by(Finding.last_seen.desc())).all()

@app.patch("/api/projects/{project_id}/findings/{finding_id}", response_model=FindingRead, tags=["findings"])
def update_finding_status(project_id: int, finding_id: int, payload: FindingStatusUpdate, db: Session = Depends(get_db)):
    if not db.get(Project, project_id):
        raise HTTPException(404, "Project not found")
    finding = _project_finding(project_id, finding_id, db)
    finding.status = payload.status
    updates = {key: value.strip() for key, value in payload.model_dump(exclude={"status"}, exclude_none=True).items()}
    finding.review = {**finding.review, **updates, "updated_at": datetime.now(timezone.utc).isoformat()}
    db.commit()
    db.refresh(finding)
    return finding


@app.get("/api/projects/{project_id}/findings/{finding_id}/retests", tags=["findings"])
def list_finding_retests(project_id: int, finding_id: int, db: Session = Depends(get_db)):
    _project_finding(project_id, finding_id, db)
    jobs = db.scalars(select(ScanJob).where(ScanJob.project_id == project_id, ScanJob.retest_finding_id == finding_id)
                      .order_by(ScanJob.id.desc()).limit(30)).all()
    return [{"id": job.id, "status": job.status, "tool_version": job.tool_version,
             "created_at": job.created_at, "completed_at": job.completed_at,
             "result": job.result_summary.get("retest") or (
                 {"outcome": "inconclusive", "reason": job.error or "The retest did not complete."}
                 if job.status not in {"queued", "running", "cancelling"} else {"outcome": "pending", "reason": ""}
             )} for job in jobs]

def subdomain_links(domains: dict[str, int]) -> list[tuple[int, int]]:
    """Infer the nearest known parent from DNS labels, without asserting a DNS record."""
    links = []
    for name, child in domains.items():
        labels = name.split(".")
        for index in range(1, len(labels) - 1):
            parent = domains.get(".".join(labels[index:]))
            if parent is not None:
                links.append((parent, child))
                break
    return links


@app.get("/api/projects/{project_id}/graph", tags=["assets"])
def get_asset_graph(project_id: int, focus_id: int | None = None, q: str = Query(default="", max_length=160),
                    audit_id: int | None = None, hops: int = Query(default=1, ge=1, le=2),
                    db: Session = Depends(get_db)):
    if not db.get(Project, project_id):
        raise HTTPException(404, "Project not found")
    statement = select(Asset).where(Asset.project_id == project_id, VISIBLE_ASSET)
    findings_filter = []
    observations_filter = []
    audited_http = {}
    historical = False
    imports = None
    if audit_id is not None:
        evidence = audit_evidence(db, _get_audit(project_id, audit_id, db))
        imports = evidence.imports
        membership, historical, _ = audit_asset_membership(db, project_id, evidence)
        statement = statement.where(membership)
        findings_filter = [Finding.id.in_(evidence.findings)]
        observations_filter = [or_(Observation.import_id.in_(evidence.imports), Observation.id.in_(
            select(ObservationSighting.observation_id).where(ObservationSighting.import_id.in_(evidence.imports))))]
        for job in evidence.jobs:
            if job.status == "completed" and job.tool_id == "httpx" and (http := job.result_summary.get("http")):
                if identity := web_identity(http.get("url")):
                    audited_http[identity[0]] = {"status_code": http["status"], "host_ip": http.get("address")}

    wrapped = None
    if focus_id is not None:
        focused = _get_visible_asset(project_id, focus_id, db)
        def neighbors(ids):
            return union(
                select(AssetRelationship.target_asset_id).where(AssetRelationship.project_id == project_id, AssetRelationship.source_asset_id.in_(ids)),
                select(AssetRelationship.source_asset_id).where(AssetRelationship.project_id == project_id, AssetRelationship.target_asset_id.in_(ids)),
            )

        direct = neighbors([focus_id])
        nearby = [Asset.id == focus_id, Asset.id.in_(direct)]
        if focused.asset_type == "domain":
            labels = focused.canonical_value.split(".")
            parents = [".".join(labels[index:]) for index in range(1, len(labels) - 1)]
            family = statement.where(Asset.asset_type == "domain", or_(
                Asset.id == focus_id,
                Asset.canonical_value.in_(parents),
                Asset.canonical_value.endswith("." + focused.canonical_value, autoescape=True),
            )).order_by(Asset.id).limit(MAP_NODE_LIMIT + 1)
            domains = {item.canonical_value: item.id for item in db.scalars(family)}
            inferred = subdomain_links(domains)
            related = {parent for parent, child in inferred if child == focus_id}
            related.update(child for parent, child in inferred if parent == focus_id)
            if related:
                nearby.append(Asset.id.in_(related))
                if hops == 2:
                    second = {child for parent, child in inferred if parent in related}
                    second.update(parent for parent, child in inferred if child in related)
                    nearby.extend((Asset.id.in_(second), Asset.id.in_(neighbors(related))))
        if hops == 2:
            nearby.append(Asset.id.in_(neighbors(direct)))
        statement = statement.where(or_(*nearby))
        statement = statement.order_by(case((Asset.id == focus_id, 0), else_=1))
    elif q.strip():
        term = q.strip()
        candidates = statement.where(Asset.asset_type.in_(HOST_TYPES)).with_only_columns(Asset.id, Asset.canonical_value)
        hosts = {str(host_id): host for host_id, host in db.execute(candidates)}
        wrapped = [row for row in observed_wrapped_ports(db, project_id, candidates.with_only_columns(Asset.id), imports)
                   if term.casefold() in f"{hosts[row['host_id']]}|{row['protocol']}/{row['port']} (tcpwrapped)".casefold()]
        statement = statement.where(or_(Asset.canonical_value.icontains(term, autoescape=True),
                                        Asset.id.in_({int(row["host_id"]) for row in wrapped})))
    statement = statement.order_by(case((Asset.asset_type == "endpoint", 1), else_=0), Asset.id)
    nodes = db.scalars(statement.limit(MAP_NODE_LIMIT + 1)).all()
    truncated = len(nodes) > MAP_NODE_LIMIT
    nodes = nodes[:MAP_NODE_LIMIT]
    node_ids = [node.id for node in nodes]
    host_ids = {node.id for node in nodes if node.asset_type in HOST_TYPES}
    if not node_ids:
        return {"nodes": [], "edges": [], "wrapped_ports": [], "wrapped_truncated": False,
                "truncated": False, "historical": historical}
    if wrapped is None:
        wrapped = observed_wrapped_ports(db, project_id, host_ids, imports) if host_ids else []
    else:
        wrapped = [row for row in wrapped if int(row["host_id"]) in host_ids]
    node_findings: dict[int, list[dict]] = {}
    for finding in db.scalars(select(Finding).where(Finding.project_id == project_id, Finding.asset_id.in_(node_ids), *findings_filter)
                              .order_by(Finding.severity, Finding.title)).all():
        matchers = finding.evidence.get("observed_matchers") or [finding.evidence.get("matcher-name")]
        node_findings.setdefault(finding.asset_id, []).append({
            "id": finding.id, "title": finding.title, "severity": finding.severity, "status": finding.status,
            "template_id": finding.template_id, "matched_at": finding.matched_at,
            "matchers": [item[:160] for item in matchers[:12] if isinstance(item, str)] if isinstance(matchers, list) else [],
        })
    node_sources: dict[int, list[str]] = {}
    for asset_id, source in db.execute(select(Observation.asset_id, Observation.source_tool).where(
            Observation.project_id == project_id, Observation.asset_id.in_(node_ids), *observations_filter).distinct()).all():
        node_sources.setdefault(asset_id, []).append(source)
    candidates = (Observation.project_id == project_id, Observation.asset_id.in_(node_ids),
                  Observation.kind.in_(("nmap_port", "http_service", "web_endpoint", "ffuf_endpoint")), *observations_filter)
    sightings = select(ObservationSighting.observation_id, func.max(ImportBatch.imported_at).label("seen")).join(
        ImportBatch, ImportBatch.id == ObservationSighting.import_id).where(
        ObservationSighting.observation_id.in_(select(Observation.id).where(*candidates)))
    if imports is not None:
        sightings = sightings.where(ObservationSighting.import_id.in_(imports))
    sightings = sightings.group_by(ObservationSighting.observation_id).subquery()
    seen = func.coalesce(sightings.c.seen, Observation.observed_at)
    observed = select(Observation.asset_id, Observation.data, seen.label("seen"), func.row_number().over(
        partition_by=Observation.asset_id, order_by=(seen.desc(), Observation.id.desc()),
    ).label("rank")).outerjoin(sightings, sightings.c.observation_id == Observation.id).where(*candidates).subquery()
    rows = db.execute(select(observed.c.asset_id, observed.c.data, observed.c.seen).where(observed.c.rank == 1))
    facts = {asset_id: {**data, "observed_at": date.replace(tzinfo=date.tzinfo or timezone.utc).isoformat()}
             for asset_id, data, date in rows}
    for node in nodes:
        if node.asset_type == "web_origin" and node.canonical_value in audited_http:
            facts[node.id] = {**audited_http[node.canonical_value], **facts.get(node.id, {})}
        elif node.asset_type == "service":
            data = facts.setdefault(node.id, {})
            named = str(data.get("name", "")).lower() not in {"", "unknown", "tcpwrapped"}
            identified = (data.get("method") == "probed" and named) or (
                not data.get("method") and bool(data.get("product") or data.get("version")))
            data["identification"] = "identified" if identified else "unidentified"

    def node_label(node: Asset) -> str:
        if node.asset_type not in {"service", "filtered_port"} or "|" not in node.canonical_value:
            return node.canonical_value
        port = node.canonical_value.split("|", 1)[1]
        data = facts.get(node.id, {})
        if data.get("identification") == "unidentified":
            return f"{port} · service unknown"
        product = " ".join(str(data[key]) for key in ("product", "version") if data.get(key))
        label = product or (str(data.get("name", "")) if data.get("identification") == "identified" else "")
        return f"{port} · {label[:100]}" if label else port

    relations = db.scalars(select(AssetRelationship).where(AssetRelationship.project_id == project_id,
        AssetRelationship.source_asset_id.in_(node_ids), AssetRelationship.target_asset_id.in_(node_ids)
    ).order_by(AssetRelationship.id).limit(MAP_LINK_LIMIT + 1)).all()
    inferred = subdomain_links({node.canonical_value: node.id for node in nodes if node.asset_type == "domain"})
    existing_hierarchy = {(edge.source_asset_id, edge.target_asset_id) for edge in relations
                          if edge.relationship_type == "has_subdomain"}
    inferred_edges = [{"id": f"subdomain-{child}", "source": str(parent), "target": str(child),
                       "type": "has_subdomain", "evidence": {"basis": "hostname_suffix"}}
                      for parent, child in inferred if (parent, child) not in existing_hierarchy]
    observed_edges = [{"id": str(edge.id), "source": str(edge.source_asset_id), "target": str(edge.target_asset_id),
                       "type": edge.relationship_type, "first_seen": edge.first_seen, "last_seen": edge.last_seen,
                       "evidence": edge.evidence} for edge in relations]
    edges = inferred_edges + observed_edges
    return {"nodes": [{"id": str(node.id), "label": node_label(node),
                       "canonical_value": node.canonical_value, "type": node.asset_type,
                       "first_seen": node.first_seen, "last_seen": node.last_seen,
                       "facts": {key: facts.get(node.id, {}).get(key) for key in
                                 ("method", "status", "status_code", "webserver", "host_ip", "product", "version", "ostype",
                                  "state", "reason", "name", "identification", "observed_at")
                                 if facts.get(node.id, {}).get(key) is not None},
                       "findings": node_findings.get(node.id, []), "sources": sorted(node_sources.get(node.id, []))} for node in nodes],
            "edges": edges[:MAP_LINK_LIMIT],
            "wrapped_ports": wrapped[:MAP_WRAPPED_LIMIT],
            "wrapped_truncated": len(wrapped) > MAP_WRAPPED_LIMIT,
            "truncated": truncated or len(edges) > MAP_LINK_LIMIT,
            "historical": historical}


@app.post("/api/projects/{project_id}/surface-drafts/from-observations", response_model=MapRead, tags=["map builder"])
def open_observed_draft(project_id: int, audit_id: int | None = None, layout: ObservedLayout | None = None,
                        db: Session = Depends(get_db)):
    existing = db.scalar(observed_draft_query(project_id, audit_id))
    if existing is not None:
        return existing
    graph = get_asset_graph(project_id=project_id, audit_id=audit_id, q="", hops=1, db=db)
    return copy_observed_graph(db, project_id, audit_id, graph, layout)


@app.get("/api/projects/{project_id}/reports/{format_name}", tags=["reports"])
def export_project_report(project_id: int, format_name: str, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "Project not found")
    if format_name not in {"json", "csv", "html", "pdf"}:
        raise HTTPException(422, "Report format must be json, csv, html, or pdf")
    assets = db.scalars(select(Asset).where(Asset.project_id == project_id, VISIBLE_ASSET).order_by(Asset.asset_type, Asset.canonical_value)).all()
    severity_rank = case({"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4},
                         value=Finding.severity, else_=5)
    findings = db.scalars(select(Finding).where(Finding.project_id == project_id)
                         .order_by(severity_rank, Finding.title, Finding.id)).all()
    visible_ids = select(Asset.id).where(Asset.project_id == project_id, VISIBLE_ASSET)
    links = db.scalars(select(AssetRelationship).where(
        AssetRelationship.project_id == project_id,
        AssetRelationship.source_asset_id.in_(visible_ids),
        AssetRelationship.target_asset_id.in_(visible_ids),
    ).order_by(AssetRelationship.id)).all()
    jobs = db.scalars(select(ScanJob).where(ScanJob.project_id == project_id).order_by(ScanJob.created_at.desc()).limit(100)).all()
    rows = {"assets": [{"id": a.id, "type": a.asset_type, "value": a.canonical_value, "first_seen": a.first_seen.isoformat(), "last_seen": a.last_seen.isoformat()} for a in assets],
            "relationships": [{"source_id": r.source_asset_id, "target_id": r.target_asset_id, "type": r.relationship_type, "evidence": r.evidence} for r in links],
            "findings": [{"title": f.title, "severity": f.severity, "status": f.status, "template_id": f.template_id,
                          "matched_at": f.matched_at, "evidence": f.evidence, "review": f.review,
                          "first_seen": f.first_seen.isoformat(), "last_seen": f.last_seen.isoformat()} for f in findings],
            "recent_jobs": [{"tool": j.tool_id, "target": j.target, "status": j.status, "version": j.tool_version, "results": j.results_count, "created_at": j.created_at.isoformat()} for j in jobs]}
    document = {"generated_at": datetime.now(timezone.utc).isoformat(), "project": {"id": project.id, "name": project.name, "description": project.description},
                "scope": [{"value": s.value, "kind": s.kind, "excluded": s.excluded} for s in project.scopes],
                "summary": {"assets": len(assets), "relationships": len(links), "findings": len(findings)}, **rows}
    safe_name = re.sub(r"[^a-zA-Z0-9._-]+", "-", project.name).strip("-_") or f"project-{project_id}"
    if format_name == "json":
        return Response(json.dumps(document, ensure_ascii=False, indent=2), media_type="application/json", headers={"Content-Disposition": f'attachment; filename="{safe_name}-report.json"'})
    if format_name == "csv":
        stream = io.StringIO(newline="")
        writer = csv.writer(stream)
        def spreadsheet_safe(value):
            text_value = str(value)
            return "'" + text_value if (text_value.startswith(("\t", "\r", "\n")) or
                                        text_value.lstrip().startswith(("=", "+", "-", "@"))) else text_value
        writer.writerow(["record_type", "type_or_severity", "value_or_title", "status", "first_seen", "last_seen", "details"])
        for asset in rows["assets"]:
            writer.writerow([spreadsheet_safe(value) for value in ["asset", asset["type"], asset["value"], "", asset["first_seen"], asset["last_seen"], ""]])
        for finding in rows["findings"]:
            writer.writerow([spreadsheet_safe(value) for value in ["finding", finding["severity"], finding["title"],
                finding["status"], finding["first_seen"], finding["last_seen"], finding["matched_at"]]])
        return Response(stream.getvalue(), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{safe_name}-report.csv"'})
    if format_name == "pdf":
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from xml.sax.saxutils import escape
        buffer = io.BytesIO()
        regular_font = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
        bold_font = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
        if not Path(regular_font).is_file() or not Path(bold_font).is_file():
            raise HTTPException(500, "Unicode font files are missing from the application image")
        pdfmetrics.registerFont(TTFont("SurfaceSans", regular_font))
        pdfmetrics.registerFont(TTFont("SurfaceSans-Bold", bold_font))
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name="SurfaceTitle", parent=styles["Title"], fontName="SurfaceSans-Bold", alignment=TA_LEFT, textColor=colors.HexColor("#17344a")))
        styles.add(ParagraphStyle(name="SurfaceBody", parent=styles["BodyText"], fontName="SurfaceSans", fontSize=8, leading=11, wordWrap="CJK"))
        styles.add(ParagraphStyle(name="SurfaceSmall", parent=styles["BodyText"], fontName="SurfaceSans", fontSize=7, leading=9, wordWrap="CJK"))
        document_pdf = SimpleDocTemplate(buffer, pagesize=landscape(A4), rightMargin=15*mm, leftMargin=15*mm, topMargin=15*mm, bottomMargin=15*mm, title=f"{project.name} · SurfaceMap")
        story = [Paragraph(escape(project.name), styles["SurfaceTitle"]), Paragraph(f"SurfaceMap assessment report · {escape(document['generated_at'])}", styles["SurfaceSmall"]), Spacer(1, 8*mm)]
        story.append(Paragraph(f"Assets: {len(assets)} · Relationships: {len(links)} · Findings: {len(findings)} · Recent jobs: {len(jobs)}", styles["SurfaceBody"]))
        story.extend([Spacer(1, 4*mm), Paragraph("Authorized scope", styles["Heading2"])])
        story.extend([Paragraph(f"{'EXCLUDED' if s['excluded'] else 'ALLOWED'} · {escape(s['value'])} ({escape(s['kind'])})", styles["SurfaceBody"]) for s in document["scope"]] or [Paragraph("No scope configured", styles["SurfaceBody"])])
        story.extend([Spacer(1, 4*mm), Paragraph("Asset inventory", styles["Heading2"])])
        asset_data = [[Paragraph(x, styles["SurfaceSmall"]) for x in ("Type", "Identity", "First seen", "Last seen")]]
        for asset in rows["assets"][:1000]:
            asset_data.append([Paragraph(escape(str(asset.get(k, ""))), styles["SurfaceSmall"]) for k in ("type", "value", "first_seen", "last_seen")])
        if len(rows["assets"]) > 1000:
            asset_data.append([Paragraph(f"First 1,000 of {len(rows['assets'])} assets; use JSON or CSV for the full inventory.", styles["SurfaceSmall"]), "", "", ""])
        if len(asset_data) == 1:
            asset_data.append([Paragraph("No assets recorded", styles["SurfaceSmall"]), "", "", ""])
        asset_table = Table(asset_data, colWidths=[28*mm, 104*mm, 62*mm, 62*mm], repeatRows=1)
        asset_table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#17344a")), ("TEXTCOLOR", (0,0), (-1,0), colors.white), ("GRID", (0,0), (-1,-1), .35, colors.HexColor("#c9d5dd")), ("VALIGN", (0,0), (-1,-1), "TOP"), ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f1f5f7")]), ("LEFTPADDING", (0,0), (-1,-1), 5), ("RIGHTPADDING", (0,0), (-1,-1), 5), ("TOPPADDING", (0,0), (-1,-1), 5), ("BOTTOMPADDING", (0,0), (-1,-1), 5)]))
        story.append(asset_table)
        story.extend([Spacer(1, 4*mm), Paragraph("Findings", styles["Heading2"])])
        table_data = [[Paragraph(x, styles["SurfaceSmall"]) for x in ("Severity", "Status", "Finding", "Template", "Matched target")]]
        for finding in rows["findings"]:
            table_data.append([Paragraph(escape(str(finding.get(k, ""))), styles["SurfaceSmall"]) for k in ("severity", "status", "title", "template_id", "matched_at")])
        if len(table_data) == 1:
            table_data.append([Paragraph("No findings recorded", styles["SurfaceSmall"]), "", "", "", ""])
        table = Table(table_data, colWidths=[25*mm, 25*mm, 72*mm, 45*mm, 92*mm], repeatRows=1)
        table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#17344a")), ("TEXTCOLOR", (0,0), (-1,0), colors.white), ("GRID", (0,0), (-1,-1), .35, colors.HexColor("#c9d5dd")), ("VALIGN", (0,0), (-1,-1), "TOP"), ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f1f5f7")]), ("LEFTPADDING", (0,0), (-1,-1), 5), ("RIGHTPADDING", (0,0), (-1,-1), 5), ("TOPPADDING", (0,0), (-1,-1), 5), ("BOTTOMPADDING", (0,0), (-1,-1), 5)]))
        story.append(table)
        document_pdf.build(story)
        return Response(buffer.getvalue(), media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{safe_name}-report.pdf"'})
    finding_rows = "".join(f"<tr><td>{html.escape(f['severity'])}</td><td>{html.escape(f['status'])}</td><td>{html.escape(f['title'])}</td><td>{html.escape(f['matched_at'])}</td></tr>" for f in rows["findings"])
    asset_rows = "".join(f"<tr><td>{html.escape(a['type'])}</td><td>{html.escape(a['value'])}</td><td>{html.escape(a['first_seen'])}</td><td>{html.escape(a['last_seen'])}</td></tr>" for a in rows["assets"])
    scope_rows = "".join(f"<li>{'EXCLUDED' if s['excluded'] else 'ALLOWED'} · {html.escape(s['value'])} <small>{html.escape(s['kind'])}</small></li>" for s in document["scope"])
    content = f"<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(project.name)} · SurfaceMap</title><style>body{{font:14px/1.5 system-ui,sans-serif;max-width:1100px;margin:40px auto;padding:0 24px;color:#17212b}}h1{{margin-bottom:0}}.muted{{color:#667789}}.cards{{display:flex;gap:12px;margin:24px 0}}.card{{padding:16px;border:1px solid #ccd5dc;border-radius:8px;min-width:110px}}.card b{{display:block;font-size:24px}}table{{width:100%;border-collapse:collapse}}td,th{{text-align:left;padding:9px;border-bottom:1px solid #dbe2e8;overflow-wrap:anywhere}}@media print{{body{{margin:0 auto}}}}</style></head><body><h1>{html.escape(project.name)}</h1><div class='muted'>SurfaceMap assessment report · {document['generated_at']}</div><div class='cards'><div class='card'><b>{len(assets)}</b>assets</div><div class='card'><b>{len(links)}</b>relationships</div><div class='card'><b>{len(findings)}</b>findings</div></div><h2>Authorized scope</h2><ul>{scope_rows or '<li>No scope configured</li>'}</ul><h2>Findings</h2><table><thead><tr><th>Severity</th><th>Status</th><th>Finding</th><th>Matched target</th></tr></thead><tbody>{finding_rows or '<tr><td colspan=4>No findings recorded</td></tr>'}</tbody></table><p class='muted'>Use Print → Save as PDF to create a PDF copy.</p></body></html>"
    content = content.replace("<h2>Findings</h2>", f"<h2>Asset inventory</h2><table><thead><tr><th>Type</th><th>Identity</th><th>First seen</th><th>Last seen</th></tr></thead><tbody>{asset_rows or '<tr><td colspan=4>No assets recorded</td></tr>'}</tbody></table><h2>Findings</h2>")
    return Response(content, media_type="text/html; charset=utf-8", headers={"Content-Disposition": f'inline; filename="{safe_name}-report.html"'})

@app.get("/api/projects/{project_id}/workflows", tags=["workflows"])
def list_workflows(project_id: int, db: Session = Depends(get_db)):
    if not db.get(Project, project_id):
        raise HTTPException(404, "Project not found")
    workflows = db.scalars(select(Workflow).where(Workflow.project_id == project_id).order_by(Workflow.created_at.desc())).all()
    result = []
    for workflow in workflows:
        runs = db.scalars(select(WorkflowRun).where(WorkflowRun.workflow_id == workflow.id).order_by(WorkflowRun.created_at.desc()).limit(10)).all()
        job_ids = {job_id for run in runs for job_id in run.job_ids}
        jobs = {job.id: {"id": job.id, "tool_id": job.tool_id, "status": job.status} for job in
                db.scalars(select(ScanJob).where(ScanJob.project_id == project_id, ScanJob.id.in_(job_ids)))} if job_ids else {}
        result.append({"id":workflow.id, "project_id":workflow.project_id, "name":workflow.name, "steps":workflow.steps, "created_at":workflow.created_at,
                       "runs":[{"id":r.id,"target":r.target,"status":r.status,"job_ids":r.job_ids,"error":r.error,"created_at":r.created_at,
                                "completed_at":r.completed_at, "jobs":[jobs[job_id] for job_id in r.job_ids if job_id in jobs]} for r in runs]})
    return result

@app.post("/api/projects/{project_id}/workflows", status_code=201, tags=["workflows"])
def create_workflow(project_id: int, payload: WorkflowCreate, db: Session = Depends(get_db)):
    if not db.get(Project, project_id):
        raise HTTPException(404, "Project not found")
    steps = []
    for step in payload.steps:
        tool = TOOL_BY_ID.get(step.tool_id)
        if not tool or not tool.active:
            raise HTTPException(422, f"No active adapter for {step.tool_id}")
        allowed = {field["name"] for field in tool.option_fields} | {"raw_arguments"}
        unknown = set(step.options) - allowed
        if unknown:
            raise HTTPException(422, f"Unsupported {tool.name} options: {', '.join(sorted(unknown))}")
        try:
            tool.command("workflow-target.example", step.options, "<output>")
        except (TypeError, ValueError) as exc:
            raise HTTPException(422, str(exc)) from exc
        steps.append({"tool_id": tool.id, "options": step.options})
    workflow = Workflow(project_id=project_id, name=payload.name.strip(), steps=steps)
    if not workflow.name:
        raise HTTPException(422, "Workflow name cannot be blank")
    db.add(workflow); db.commit(); db.refresh(workflow)
    return {"id":workflow.id,"project_id":workflow.project_id,"name":workflow.name,"steps":workflow.steps,"created_at":workflow.created_at,"runs":[]}

@app.post("/api/projects/{project_id}/workflows/{workflow_id}/runs", status_code=202, tags=["workflows"])
def start_workflow(project_id: int, workflow_id: int, payload: WorkflowRunCreate, db: Session = Depends(get_db)):
    workflow = db.scalar(select(Workflow).where(Workflow.id == workflow_id, Workflow.project_id == project_id))
    if not workflow:
        raise HTTPException(404, "Workflow not found")
    for step in workflow.steps:
        tool, _, _ = _scan_command(step["tool_id"], payload.target, step.get("options") or {}, db, project_id)
        if installed_version(tool) != tool.version.lstrip("v"):
            raise HTTPException(409, f"{tool.name} does not have its supported pinned version installed")
    active_count, active_projects = _reserve_project_queue(project_id, db)
    if active_count >= 2 or project_id in active_projects:
        raise HTTPException(429, "Scan concurrency limit prevents starting this workflow")
    run = WorkflowRun(workflow_id=workflow.id, project_id=project_id, target=payload.target, status="queued", job_ids=[])
    db.add(run)
    db.commit()
    from .worker import execute_workflow
    task_id = None
    try:
        task_id = execute_workflow.apply_async(args=[run.id], retry=False).id
    except (BrokerUnavailable, OSError):
        # The worker reconciler will dispatch the stored run when the broker returns.
        pass
    return {"id":run.id,"workflow_id":workflow.id,"target":run.target,"status":run.status,"job_ids":run.job_ids,"task_id":task_id}

@app.post("/api/projects/{project_id}/workflow-runs/{run_id}/cancel", tags=["workflows"])
def cancel_workflow(project_id: int, run_id: int, db: Session = Depends(get_db)):
    run = db.scalar(select(WorkflowRun).where(WorkflowRun.id == run_id, WorkflowRun.project_id == project_id)
                    .with_for_update())
    if not run:
        raise HTTPException(404, "Workflow run not found")
    if run.status not in {"queued", "running"}:
        raise HTTPException(409, "Workflow is not active")
    run.status = "cancelled"
    run.completed_at = datetime.now(timezone.utc)
    jobs = db.scalars(select(ScanJob).where(ScanJob.project_id == project_id, ScanJob.id.in_(run.job_ids),
                     ScanJob.status.in_(("queued", "running", "cancelling"))).with_for_update()).all()
    for job in jobs:
        if job.status == "queued":
            job.status = "cancelled"
            job.completed_at = run.completed_at
        else:
            job.status = "cancelling"
    db.commit()
    return {"id":run.id,"status":run.status,"cancelled_jobs":len(jobs)}

@app.get("/api/projects/{project_id}/timeline", tags=["assets"])
def get_project_timeline(project_id: int, limit: int = 100, db: Session = Depends(get_db)):
    if not db.get(Project, project_id):
        raise HTTPException(404, "Project not found")
    limit = max(1, min(limit, 500))
    rows = db.execute(select(Observation, Asset.canonical_value).join(Asset, Observation.asset_id == Asset.id)
        .where(Observation.project_id == project_id).order_by(Observation.observed_at.desc(), Observation.id.desc()).limit(limit)).all()
    events = [{"id": observation.id, "event_type": observation.kind, "asset": value, "source": observation.source_tool,
               "observed_at": observation.observed_at, "details": observation.data} for observation, value in rows]
    batches = db.scalars(select(ImportBatch).where(ImportBatch.project_id == project_id)
        .order_by(ImportBatch.imported_at.desc(), ImportBatch.id.desc()).limit(limit)).all()
    events.extend({"id": -batch.id, "event_type": "import", "asset": batch.filename, "source": batch.format,
        "observed_at": batch.imported_at, "details": {"records_seen": batch.records_seen,
        "assets_created": batch.assets_created, "findings_created": batch.findings_created}}
        for batch in batches)
    events.sort(key=lambda event: (event["observed_at"], event["event_type"] == "import", event["id"]), reverse=True)
    return events[:limit]

@app.get("/api/projects/{project_id}/snapshots", response_model=list[SnapshotRead], tags=["assets"])
def list_project_snapshots(project_id: int, db: Session = Depends(get_db)):
    if not db.get(Project, project_id):
        raise HTTPException(404, "Project not found")
    return db.scalars(select(ProjectSnapshot).where(ProjectSnapshot.project_id == project_id)
        .order_by(ProjectSnapshot.captured_at.desc(), ProjectSnapshot.id.desc()).limit(100)).all()

@app.post("/api/projects/{project_id}/snapshots", response_model=SnapshotRead, status_code=201, tags=["assets"])
def capture_project_snapshot(project_id: int, db: Session = Depends(get_db)):
    if not db.get(Project, project_id):
        raise HTTPException(404, "Project not found")
    asset_count = db.scalar(select(func.count(Asset.id)).where(Asset.project_id == project_id, VISIBLE_ASSET)) or 0
    relationship_count = db.scalar(select(func.count(AssetRelationship.id)).where(AssetRelationship.project_id == project_id)) or 0
    severities = db.execute(select(Finding.severity, func.count(Finding.id)).where(Finding.project_id == project_id).group_by(Finding.severity)).all()
    snapshot = ProjectSnapshot(project_id=project_id, asset_count=asset_count, relationship_count=relationship_count,
        finding_counts={severity: count for severity, count in severities})
    db.add(snapshot)
    db.commit()
    db.refresh(snapshot)
    return snapshot
