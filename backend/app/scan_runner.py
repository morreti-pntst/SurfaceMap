"""Bounded background execution and normalized result ingestion for scan jobs."""
import os
import signal
import subprocess
import time
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit
from sqlalchemy import select
from .audit_plan import NUCLEI_BASELINE_SECONDS, NUCLEI_EXTENDED_SECONDS
from .custom_commands import nmap_timeout_minutes
from .db import SessionLocal
from .import_service import store_import
from .importers import ParsedRecord, ParseResult, parse_import, web_identity
from .models import AuditRun, Finding, Project, ScanJob, ScopeEntry
from .scan_diagnostics import (
    REDIRECT_STATUSES, TRANSIENT_WEB_CATEGORIES, WEB_TOOLS, ScanBlocked, WebProbe, live_web_problem,
    nuclei_coverage_gap, nuclei_progress, nuclei_stopped_for_network_errors, tail, web_preflight,
)
from .retests import evaluate_retest
from .scope_guard import check_resolved_exclusions, normalize_web_target, scope_matches, target_identity
from .tool_manager import binary_path, installed_version
from .tool_registry import TOOL_BY_ID, bounded_option

MAX_ARTIFACT_BYTES = 10 * 1024 * 1024
ARTIFACT_ROOT = Path(os.getenv("SURFACEMAP_ARTIFACTS_DIR", "/data/artifacts"))


def scan_timeout_seconds(tool_id: str, audit_run_id: int | None, options: dict | None = None) -> int:
    if tool_id == "nmap":
        return nmap_timeout_minutes(options or {}) * 60
    if tool_id == "nuclei":
        options = options or {}
        if "timeout_minutes" in options:
            return bounded_option(options, "timeout_minutes", 15, 5, 60) * 60
        if audit_run_id is None:
            return TOOL_BY_ID[tool_id].timeout_seconds
        if options.get("time_budget_seconds") == NUCLEI_EXTENDED_SECONDS:
            return NUCLEI_EXTENDED_SECONDS
        return NUCLEI_BASELINE_SECONDS
    return TOOL_BY_ID[tool_id].timeout_seconds


def expire_stale_scans() -> None:
    """Release slots held by scans whose worker did not record completion."""
    now = datetime.now(timezone.utc)
    with SessionLocal.begin() as db:
        for tool in TOOL_BY_ID.values():
            overdue = db.scalars(select(ScanJob).where(
                ScanJob.tool_id == tool.id,
                ScanJob.audit_run_id.is_(None),
                ScanJob.status.in_(["running", "cancelling"]),
                ScanJob.started_at < now - timedelta(seconds=(60 if tool.id == "nmap" else min(300, tool.timeout_seconds)) + 60),
            ).with_for_update(skip_locked=True)).all()
            for job in overdue:
                started = job.started_at
                if started.tzinfo is None:
                    started = started.replace(tzinfo=timezone.utc)
                if now - started < timedelta(seconds=scan_timeout_seconds(tool.id, None, job.options) + 60):
                    continue
                if job.status == "cancelling":
                    job.status = "cancelled"
                else:
                    job.status = "failed"
                    job.error = ("The scan exceeded its time limit without a completion report. The worker may "
                                 "have restarted. Review the scanner log and retry with narrower settings.")
                job.completed_at = now


def _executable(tool_id: str) -> str:
    tool = TOOL_BY_ID[tool_id]
    path = binary_path(tool)
    if not path:
        raise RuntimeError(f"{tool.name} is not installed. Install it from Tool Manager first.")
    return path


def build_target(tool_id: str, raw_target: str) -> str:
    _, host = target_identity(raw_target)
    if tool_id in {"nmap", "dnsx", "subfinder", "amass"}:
        return host
    return normalize_web_target(raw_target)


def _http_probe_evidence(target: str, probe: WebProbe) -> dict | None:
    seed = web_identity(target)
    if not seed:
        return None
    redirect = None
    if probe.location and probe.status in REDIRECT_STATUSES:
        try:
            redirect = web_identity(urljoin(target, probe.location))
        except ValueError:
            pass
    return {
        "url": seed[1], "status": probe.status, "probe_status": probe.status, "address": probe.address,
        "posture": probe.posture, "redirect": redirect[1] if redirect else None, "source": "preflight",
    }


def _validate_scope(db, job: ScanJob) -> None:
    project = db.get(Project, job.project_id)
    if not project:
        raise RuntimeError("Project was deleted before the queued job started")
    entries = db.scalars(select(ScopeEntry).where(ScopeEntry.project_id == job.project_id)).all()
    ok, detail = scope_matches(job.target, entries, allow_network=(job.tool_id == "nmap"))
    if not ok:
        raise RuntimeError(f"Scope validation failed immediately before execution: {detail}")
    if job.audit_run_id is not None:
        audit = db.get(AuditRun, job.audit_run_id)
        if not audit or audit.project_id != job.project_id:
            raise RuntimeError("The approved audit plan could not be found")
        approved = [ScopeEntry(**rule) for rule in audit.scope_snapshot]
        ok, detail = scope_matches(job.target, approved, allow_network=(job.tool_id == "nmap"))
        if not ok:
            raise RuntimeError(f"Target is outside the scope approved at launch: {detail}")
        entries = [*entries, *approved]
    if job.tool_id == "nmap" or job.tool_id in WEB_TOOLS:
        check_resolved_exclusions(job.target, entries)


def parse_scan_output(tool_id: str, raw: str) -> ParseResult:
    tool = TOOL_BY_ID[tool_id]
    if tool.import_format == "nmap_xml":
        return parse_import("nmap_xml", raw)
    if tool.import_format == "ffuf_json":
        return parse_import("ffuf_json", raw)
    if tool.import_format in {"subfinder", "amass_jsonl", "amass_text", "dnsx_jsonl", "httpx_jsonl", "nuclei_jsonl", "katana_jsonl", "ffuf_jsonl"}:
        return parse_import(tool.import_format, raw)
    return ParseResult()


def _stop_process_group(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def execute_scan(job_id: int, *, audit_deadline: float | None = None) -> dict:
    with SessionLocal() as db, ExitStack() as resources:
        job = db.scalar(select(ScanJob).where(ScanJob.id == job_id).with_for_update())
        if not job:
            return {"status": "missing"}
        if job.status in {"cancelled", "cancelling"}:
            job.status = "cancelled"
            job.completed_at = datetime.now(timezone.utc)
            db.commit()
            return {"status": "cancelled"}
        if job.status != "queued":
            return {"status": job.status}
        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        db.commit()
        process = None
        events_path = None
        probe = None
        initial_response = None

        def event(message: str) -> None:
            if events_path is not None:
                try:
                    with events_path.open("a", encoding="utf-8") as events:
                        events.write(f"{datetime.now(timezone.utc).isoformat(timespec='seconds')}  {message}\n")
                except OSError:
                    # A failed diagnostics write must not leave the job running.
                    pass

        try:
            tool = TOOL_BY_ID[job.tool_id]
            artifact_dir = ARTIFACT_ROOT / f"project-{job.project_id}" / f"scan-{job.id}"
            artifact_dir.mkdir(parents=True, exist_ok=True)
            events_path = artifact_dir / "events.log"
            event(f"Checking scope and preparing {tool.name}.")
            if tool.id == "amass":
                # The pinned Amass CLI shares its localhost engine between processes.
                from fcntl import LOCK_EX, LOCK_NB, flock

                lock = resources.enter_context((ARTIFACT_ROOT / ".amass-engine.lock").open("a"))
                deadline = min(time.monotonic() + 120, audit_deadline or float("inf"))
                event("Waiting for the shared Amass engine.")
                while True:
                    try:
                        flock(lock, LOCK_EX | LOCK_NB)
                        break
                    except BlockingIOError:
                        db.refresh(job)
                        if job.status != "running":
                            raise RuntimeError("Scan stopped while waiting for the Amass engine.")
                        db.commit()
                        if time.monotonic() >= deadline:
                            raise TimeoutError("The Amass engine is still busy. Retry after the other discovery job finishes.")
                        time.sleep(0.5)
                db.refresh(job)
                if job.status != "running":
                    raise RuntimeError("Scan stopped before acquiring the Amass engine.")
                job.started_at = datetime.now(timezone.utc)
                db.commit()
            _validate_scope(db, job)
            scoped_target = build_target(job.tool_id, job.target)
            event("Current scope and exclusions verified.")
            extension = {"nmap_xml":"xml", "ffuf_json":"json", "subfinder":"txt", "amass_text":"txt", "amass_jsonl":"json"}.get(tool.import_format, "jsonl")
            output_path = artifact_dir / f"output.{extension}"
            command = tool.command(scoped_target, job.options, str(output_path) if job.id else "<output>")
            command[0] = _executable(job.tool_id)
            job.command = command
            job.tool_version = installed_version(tool)
            if job.tool_version != tool.version.lstrip("v"):
                raise RuntimeError(f"{tool.name} no longer has its supported version {tool.version} installed.")
            job.artifact_path = str(output_path)
            db.commit()
            stderr_path = artifact_dir / "stderr.log"
            console_path = artifact_dir / "console.log"
            stdout_path = console_path if job.tool_id in {"nmap", "subfinder", "nuclei"} else output_path
            if job.tool_id == "nuclei":
                output_path.write_bytes(b"")
            if job.tool_id in WEB_TOOLS:
                event("Checking HTTP connectivity and access to the target.")
                probe = web_preflight(scoped_target, event, user_agent=job.options.get("user_agent", ""))
                if job.tool_id == "httpx":
                    initial_response = _http_probe_evidence(scoped_target, probe)
            db.refresh(job)
            if job.status != "running":
                if job.status == "cancelling":
                    job.status = "cancelled"
                    job.completed_at = datetime.now(timezone.utc)
                db.commit()
                event("Scan stopped before the scanner was launched.")
                return {"status": job.status}
            db.commit()
            if audit_deadline is not None and time.monotonic() >= audit_deadline:
                raise TimeoutError("The overall audit time budget was reached.")
            time_limit = scan_timeout_seconds(tool.id, job.audit_run_id, job.options)
            event(f"Starting {tool.name} {job.tool_version}. Time limit: {time_limit // 60} minutes.")
            timeout_gap = None
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                           cwd=artifact_dir, start_new_session=True, close_fds=True)
                tool_deadline = time.monotonic() + time_limit
                deadline = min(tool_deadline, audit_deadline) if audit_deadline is not None else tool_deadline
                next_diagnostic = 0.0
                next_access_check = time.monotonic() + 60
                access_interrupted = False
                while process.poll() is None:
                    time.sleep(0.25)
                    db.expire(job)
                    current_job = db.get(ScanJob, job_id)
                    if current_job is None:
                        _stop_process_group(process)
                        return {"status": "cancelled"}
                    if current_job.status in {"cancelled", "cancelling"}:
                        _stop_process_group(process)
                        current_job.status = "cancelled"
                        current_job.completed_at = datetime.now(timezone.utc)
                        db.commit()
                        event("Scan cancelled.")
                        return {"status": "cancelled"}
                    if current_job.status != "running":
                        _stop_process_group(process)
                        return {"status": current_job.status}
                    if job.tool_id in WEB_TOOLS and time.monotonic() >= next_diagnostic:
                        next_diagnostic = time.monotonic() + 2
                        if problem := live_web_problem(job.tool_id, tail(stderr_path), tail(output_path)):
                            raise ScanBlocked.from_scanner(problem)
                    if probe and time.monotonic() >= next_access_check and deadline - time.monotonic() > 5:
                        try:
                            probe_update = web_preflight(scoped_target, preferred_address=probe.address,
                                                        user_agent=job.options.get("user_agent", ""))
                        except ScanBlocked as exc:
                            if exc.category not in TRANSIENT_WEB_CATEGORIES:
                                raise
                            if not access_interrupted:
                                event(f"Independent access check inconclusive: {exc} The scanner is still running.")
                            access_interrupted = True
                        else:
                            if access_interrupted:
                                event(f"Independent access recovered. HTTP {probe_update.status} via {probe_update.address}.")
                            access_interrupted = False
                        next_access_check = time.monotonic() + 60
                    if any(path.exists() and path.stat().st_size > MAX_ARTIFACT_BYTES
                           for path in {output_path, stdout_path, stderr_path}):
                        _stop_process_group(process)
                        raise RuntimeError("Tool output exceeded the 10 MiB per-job artifact limit")
                    if time.monotonic() > deadline:
                        _stop_process_group(process)
                        if job.tool_id == "nuclei":
                            timeout_gap = ("The overall audit time budget was reached." if deadline < tool_deadline
                                           else f"Nuclei reached its {time_limit // 60}-minute time limit.")
                            break
                        if deadline < tool_deadline:
                            raise TimeoutError("The overall audit time budget was reached.")
                        if tool.id == "nmap":
                            raise TimeoutError(f"Nmap reached its {time_limit // 60}-minute limit. Increase Maximum run time "
                                               "or scan a shorter list of ports or hosts.")
                        raise TimeoutError(f"Tool exceeded its {time_limit // 60} minute job limit. "
                                           "Check the live log for network errors, then narrow the target, ports or templates.")
                return_code = process.returncode
            if job.tool_id in WEB_TOOLS:
                if problem := live_web_problem(job.tool_id, tail(stderr_path), tail(output_path)):
                    raise ScanBlocked.from_scanner(problem)
            job.exit_code = return_code
            if return_code != 0 and not timeout_gap:
                message = stderr_path.read_text(errors="replace").strip()[-3000:]
                if not message:
                    message = stdout_path.read_text(errors="replace").strip()[-3000:]
                raise RuntimeError(f"Tool exited with code {return_code}: {message or 'no diagnostic output'}")
            if not output_path.exists():
                if job.tool_id == "subfinder":
                    output_path.touch()
                else:
                    raise RuntimeError("Tool finished without producing its expected output artifact")
            if output_path.stat().st_size > MAX_ARTIFACT_BYTES:
                raise RuntimeError("Tool output exceeded the 10 MiB per-job artifact limit")
            event(f"{timeout_gap} Importing the evidence collected so far." if timeout_gap
                  else "Scanner exited successfully. Parsing and importing output.")
            output = output_path.read_text(encoding="utf-8", errors="replace")
            parsed = parse_scan_output(job.tool_id, output)
            source = web_identity(scoped_target) if job.tool_id in WEB_TOOLS else None
            coverage_gap = None
            progress = {}
            if job.tool_id == "nuclei":
                progress = nuclei_progress(tail(stderr_path), tail(stdout_path))
                coverage_gap = nuclei_coverage_gap(progress)
                if timeout_gap:
                    coverage_gap = " ".join(filter(None, (timeout_gap, coverage_gap)))
                elif nuclei_stopped_for_network_errors(tail(stderr_path)):
                    coverage_gap = " ".join(filter(None, (
                        "Nuclei skipped the host after repeated network errors.",
                        coverage_gap, "Check the worker route and target logs. Retry with the baseline templates or a smaller template set.",
                    )))
            elif job.tool_id == "katana" and source and not any(
                (identity := web_identity(record.asset_value)) and identity[0] == source[0]
                and isinstance(record.data.get("status_code"), int) for record in parsed.records
            ):
                coverage_gap = "Katana did not record an HTTP response from the requested origin. Review the crawler console."
            if job.tool_id == "nuclei" and source:
                for record in parsed.records:
                    if record.finding and (matched := web_identity(record.finding["matched_at"])) and matched[0] == source[0]:
                        record.finding["evidence"]["scan_target"] = source[1]
            http_evidence = None
            if initial_response and (seed := web_identity(scoped_target)):
                for record in parsed.records:
                    status = record.data.get("status_code")
                    if record.asset_type != "web_origin" or record.asset_value != seed[0]:
                        continue
                    if not isinstance(status, int) or not 100 <= status <= 599:
                        continue
                    http_evidence = {**initial_response, "status": status}
                    http_evidence.pop("source")
                    record.data["initial_response"] = http_evidence
                    break
                redirect = initial_response["redirect"]
                if redirect or urlsplit(seed[1]).path != "/":
                    relations = [("web_origin", seed[0], "contains_endpoint")]
                    if redirect and redirect != seed[1]:
                        relations.append(("endpoint", redirect, "redirects_to"))
                    parsed.records.append(ParsedRecord("endpoint", seed[1], "http_service", {
                        "url": seed[1], "status_code": probe.status, "redirect": redirect,
                    }, related_assets=relations))
            job = db.scalar(select(ScanJob).where(ScanJob.id == job_id).with_for_update()
                            .execution_options(populate_existing=True))
            if not job:
                return {"status": "missing"}
            if job.status in {"cancelling", "cancelled"}:
                job.status = "cancelled"
                job.completed_at = datetime.now(timezone.utc)
                db.commit()
                event("Scan cancelled before import.")
                return {"status": "cancelled"}
            if job.status != "running":
                return {"status": job.status}
            retest = None
            if job.retest_finding_id is not None:
                original = db.get(Finding, job.retest_finding_id)
                if original and original.project_id == job.project_id:
                    retest = evaluate_retest(job.options["template_id"], job.target, parsed,
                        progress, probe.status if probe else None,
                        expected_match=original.matched_at, source_known=bool(original.evidence.get("scan_target")))
                    if timeout_gap and retest["outcome"] == "not_reproduced":
                        retest = {"outcome": "inconclusive", "reason": timeout_gap}
            finding_ids: set[int] = set()
            batch = store_import(db, job.project_id, tool.import_format or "subfinder",
                                 f"scan-{job.id}-{job.tool_id}.{extension}", parsed,
                                 commit=False, finding_ids=finding_ids) if parsed.records else None
            job.exit_code = return_code
            job.results_count = len(parsed.records)
            job.result_summary = {
                "import_id": batch.id if batch else None,
                "finding_ids": sorted(finding_ids),
                "warnings": parsed.warnings[:30],
            }
            if job.tool_id == "nmap":
                ports = [record.data for record in parsed.records if record.kind in {"nmap_port", "nmap_filtered_group"}]
                devices = [record.data for record in parsed.records if record.kind == "nmap_host" and record.asset_type in {"ipv4", "ipv6"}]
                wrapped_count = sum(record.data["count"] for record in parsed.records if record.kind == "nmap_wrapped_ports")
                job.result_summary["network"] = {"ports": ports[:200], "hosts": devices[:256],
                                                 "total_rows": len(ports), "wrapped_count": wrapped_count}
                diagnostics = tail(stdout_path).lower() + tail(stderr_path).lower()
                if "due to host timeout" in diagnostics or "host timed out" in diagnostics:
                    coverage_gap = ("Nmap reached the per-host time limit. Results from other hosts were kept. "
                                    "Increase Maximum run time or use a shorter list of ports.")
                elif not devices and "-sV" in command and "-Pn" not in command and "/" not in scoped_target:
                    coverage_gap = ("Nmap did not report a reachable host. Check the target and network. "
                                    "For a known reachable host that blocks discovery probes, use Custom command with -Pn -sV.")
            if http_evidence:
                job.result_summary["http"] = http_evidence
            elif initial_response:
                job.result_summary["reachable"] = initial_response
                job.result_summary["warnings"].append(
                    f"httpx returned no HTTP response. The independent probe received HTTP {probe.status}.")
            if progress:
                job.result_summary["progress"] = progress
            if coverage_gap:
                job.result_summary["coverage_gap"] = coverage_gap
                job.result_summary["warnings"].append(coverage_gap)
                event(coverage_gap)
            if retest:
                job.result_summary["retest"] = retest
                event(f"Retest outcome: {retest['outcome'].replace('_', ' ')}. {retest['reason']}")
            job.stdout_excerpt = output[-4000:]
            job.status = "completed"
            job.completed_at = datetime.now(timezone.utc)
            db.commit()
            event(f"Completed. Imported {len(parsed.records)} records.")
            response = {"status": "completed", "results": job.results_count, **job.result_summary}
            if ((reachable := response.get("reachable")) and not 200 <= reachable["status"] < 300
                    and reachable["status"] not in REDIRECT_STATUSES):
                response.pop("reachable")
            if job.audit_run_id and job.tool_id in {"subfinder", "amass"}:
                response["discovered_hosts"] = sorted({
                    record.asset_value for record in parsed.records if record.asset_type == "domain"
                })[:2000]
            return response
        except Exception as exc:
            if process is not None:
                _stop_process_group(process)
            event(f"Stopped: {str(exc)[:4000]}")
            db.rollback()
            job = db.scalar(select(ScanJob).where(ScanJob.id == job_id).with_for_update())
            if job and job.status in {"cancelled", "cancelling"}:
                job.status = "cancelled"
                job.completed_at = datetime.now(timezone.utc)
                db.commit()
                return {"status": "cancelled"}
            failure_kind = "blocked" if isinstance(exc, ScanBlocked) else "timeout" if isinstance(exc, TimeoutError) else "tool_error"
            diagnostic = {"category": exc.category, "http_status": exc.status} if isinstance(exc, ScanBlocked) else None
            if job:
                job.status = "failed"
                job.error = str(exc)[:4000]
                job.exit_code = process.returncode if process is not None else None
                job.result_summary = {"failure_kind": failure_kind}
                if diagnostic:
                    job.result_summary["diagnostic"] = diagnostic
                job.completed_at = datetime.now(timezone.utc)
                db.commit()
            response = {"status": "failed", "error": str(exc)[:1000], "failure_kind": failure_kind,
                        "diagnostic": diagnostic}
            if initial_response and not diagnostic and (
                200 <= initial_response["status"] < 300 or initial_response["status"] in REDIRECT_STATUSES
            ):
                response["reachable"] = initial_response
            return response
