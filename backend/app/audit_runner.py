"""Execute a guided audit with normal scan jobs and persisted coverage."""
from copy import deepcopy
from datetime import datetime, timezone
from time import monotonic
from urllib.parse import urlsplit

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .audit_plan import ACTIVE_AUDITS, AUDIT_LIMIT_SECONDS, planned_hosts, scoped
from .db import SessionLocal, run_lock
from .models import AuditRun, ScanJob, ScopeEntry
from .scan_diagnostics import REDIRECT_STATUSES, WEB_TOOLS
from .scan_runner import build_target, execute_scan
from .scope_guard import normalize_web_target
from .tool_manager import installed_version
from .tool_registry import TOOL_BY_ID

AUDIT_LOCK = 90715
ACTIVE_CHILDREN = ("queued", "running", "cancelling")


def locked_run(db: Session, run_id: int) -> AuditRun | None:
    return db.scalar(select(AuditRun).where(AuditRun.id == run_id).with_for_update()
                     .execution_options(populate_existing=True))


def _save(db: Session, run: AuditRun, stages: list) -> None:
    run.stages = deepcopy(stages)
    db.commit()


def _finish(db: Session, run: AuditRun, stages: list, status: str, reason: str = "") -> dict:
    if run.status == "cancelling":
        status, reason = "cancelled", "Stopped by the operator."
    unfinished = [item for stage in stages for item in stage["executions"] if item["status"] == "running"]
    if unfinished:
        jobs = db.scalars(select(ScanJob).where(ScanJob.audit_run_id == run.id,
            ScanJob.id.in_([item.get("job_id") for item in unfinished])).with_for_update()).all()
        by_id = {job.id: job for job in jobs}
        for item in unfinished:
            if not (job := by_id.get(item.get("job_id"))):
                item.update(status="skipped", reason=reason)
                continue
            if job.status in ACTIVE_CHILDREN:
                job.status = "cancelled" if status == "cancelled" else "failed"
                job.error = reason
                job.completed_at = datetime.now(timezone.utc)
            item.update(status=job.status, records=job.results_count, reason=job.error)
    for stage in stages:
        if stage["status"] in {"pending", "running"}:
            stage["status"] = "skipped" if stage["status"] == "pending" else "partial"
            stage["reason"] = reason or "The audit finished before this stage was reached."
    run.status = status
    run.error = reason
    run.completed_at = datetime.now(timezone.utc)
    _save(db, run, stages)
    return {"status": status}


def _targets(stage: dict, run: AuditRun, discovered: set[str], verified: list[str],
             rules: list[ScopeEntry]) -> list[str]:
    seed = run.config["seed_host"]
    root = run.config["root_domain"]
    if stage["source"] == "root_domain":
        return [root]
    if stage["source"] == "seed_host":
        return [seed]
    if stage["source"] == "verified_seed":
        return [target for target in verified if urlsplit(target).hostname == seed][:1]
    if stage["source"] == "verified_web":
        return verified.copy()
    hosts, dropped = planned_hosts(seed, discovered, root, run.config["expansion_limit"], rules)
    stage["excluded_or_over_limit"] = dropped
    if stage["source"] == "dns_hosts":
        return list(dict.fromkeys([root, *hosts]))
    return [run.target, *(f"https://{host}/" for host in hosts[1:])]


def _origin(target: str) -> tuple[str, str]:
    parsed = urlsplit(target)
    return parsed.scheme, parsed.netloc


def _audit_redirect(target: str, destination: str | None) -> str:
    if not destination:
        raise ValueError("No usable redirect destination was observed. Check the Location header.")
    destination = normalize_web_target(destination)
    current, next_url = urlsplit(target), urlsplit(destination)
    if current.hostname != next_url.hostname:
        raise ValueError("The destination is on a different host. Review it and start a separate scoped audit if authorized.")
    if (current.scheme == "https" and next_url.scheme != "https"
            or next_url.port is not None and next_url.port != current.port):
        raise ValueError("The destination uses an HTTPS downgrade or a new non-default port. Review it before scanning.")
    if next_url.query:
        raise ValueError("The destination contains query parameters. Review the route and provide approved test values.")
    return destination


def _verified_www_redirect(target: str, destination: str | None, verified: list[str]) -> tuple[str, str] | None:
    if not destination:
        return None
    destination = normalize_web_target(destination)
    parsed = urlsplit(destination)
    if urlsplit(target).hostname != f"www.{parsed.hostname}" or parsed.port is not None or parsed.query:
        return None
    secure_destination = parsed._replace(scheme="https").geturl()
    return (destination, secure_destination) if secure_destination in verified else None


def execute_audit(run_id: int) -> dict:
    with run_lock(AUDIT_LOCK, run_id) as acquired:
        if not acquired:
            return {"status": "busy"}
        return _execute_audit(run_id)


def _execute_audit(run_id: int) -> dict:
    with SessionLocal() as db:
        run = locked_run(db, run_id)
        if not run or run.status != "queued":
            return {"status": run.status if run else "missing"}
        stages = deepcopy(run.stages)
        run.status = "running"
        run.started_at = datetime.now(timezone.utc)
        db.commit()
        deadline = monotonic() + run.config.get("timeout_seconds", AUDIT_LIMIT_SECONDS)
        approved_rules = [ScopeEntry(**rule) for rule in run.scope_snapshot]
        discovered: set[str] = set()
        verified: list[str] = []
        blocked: dict[tuple[str, str], str] = {}
        try:
            for stage in stages:
                run = locked_run(db, run_id)
                if not run:
                    return {"status": "missing"}
                if run.status != "running" or monotonic() >= deadline:
                    return _finish(db, run, stages, "partial", "The overall audit time budget was reached.")
                targets = _targets(stage, run, discovered, verified, approved_rules)[:stage["target_limit"]]
                tool = TOOL_BY_ID[stage["tool_id"]]
                # Release the audit row before probing the installed binary.
                db.commit()
                observed_version = installed_version(tool) if targets else None
                run = locked_run(db, run_id)
                if not run:
                    return {"status": "missing"}
                if run.status != "running":
                    return _finish(db, run, stages, "partial")
                if not targets or observed_version != tool.version.lstrip("v"):
                    stage["status"] = "skipped"
                    stage["reason"] = (f"{tool.name} {tool.version} is unavailable." if targets else
                        next(iter(blocked.values()), "No web target was confirmed for this stage. Review the HTTP check console."))
                    _save(db, run, stages)
                    continue
                stage["status"] = "running"
                stage["started_at"] = datetime.now(timezone.utc).isoformat()
                _save(db, run, stages)
                candidates = [(target, 0) for target in targets]
                seen_targets = set(targets)
                for target, hops in candidates:
                    run = locked_run(db, run_id)
                    if not run:
                        return {"status": "missing"}
                    if run.status != "running" or monotonic() >= deadline:
                        return _finish(db, run, stages, "partial", "The overall audit time budget was reached.")
                    execution = {"target": target, "status": "running", "started_at": datetime.now(timezone.utc).isoformat()}
                    stage["executions"].append(execution)
                    origin = _origin(target) if tool.id in WEB_TOOLS else None
                    if origin in blocked:
                        execution.update(status="skipped", reason=blocked[origin])
                        _save(db, run, stages)
                        continue
                    current_rules = db.scalars(select(ScopeEntry).where(ScopeEntry.project_id == run.project_id)).all()
                    try:
                        scoped(target, approved_rules)
                        scoped(target, current_rules)
                        normalized = build_target(tool.id, target)
                        command = tool.command(normalized, stage["options"])
                    except (ValueError, TypeError) as exc:
                        execution.update(status="skipped", reason=str(exc))
                        _save(db, run, stages)
                        continue
                    job = ScanJob(project_id=run.project_id, audit_run_id=run.id, tool_id=tool.id,
                                  target=normalized, options=stage["options"], command=command,
                                  tool_version=observed_version, status="queued")
                    db.add(job)
                    db.flush()
                    execution["job_id"] = job.id
                    _save(db, run, stages)
                    result = execute_scan(job.id, audit_deadline=deadline)
                    execution.update(status=result["status"], records=result.get("results", 0),
                                     completed_at=datetime.now(timezone.utc).isoformat())
                    if result.get("error"):
                        execution["reason"] = result["error"]
                    if result["status"] == "completed" and (gap := result.get("coverage_gap")):
                        execution.update(status="partial", reason=gap)
                    if result.get("failure_kind") == "blocked" and origin is not None:
                        diagnostic = result.get("diagnostic") or {"category": "access"}
                        execution["diagnostic"] = diagnostic
                        execution["status"] = "blocked" if diagnostic["category"] in {"access", "rate_limit"} else "unreachable"
                        if execution["status"] == "blocked":
                            blocked[origin] = f"Further web checks paused after scan #{job.id}: {result.get('error', 'access check failed')}"
                    discovered.update(result.get("discovered_hosts", []))
                    if tool.id == "httpx":
                        http = result.get("http") or result.get("reachable")
                        if http:
                            execution["http"] = http
                            probe_status = http.get("probe_status", http["status"])
                            if probe_status in REDIRECT_STATUSES or http["status"] in REDIRECT_STATUSES:
                                try:
                                    existing = _verified_www_redirect(target, http.get("redirect"), verified)
                                    if existing:
                                        destination, secure_destination = existing
                                        for url in existing:
                                            scoped(url, approved_rules)
                                            scoped(url, current_rules)
                                        execution["reason"] = (
                                            f"WWW redirect. {secure_destination} was already verified over HTTPS in this audit."
                                        )
                                        if urlsplit(destination).scheme == "http":
                                            execution["reason"] = "HTTP downgrade observed. " + execution["reason"]
                                    else:
                                        if hops >= stage.get("redirect_limit", 0):
                                            raise ValueError("The redirect limit for this plan was reached. Review the final destination.")
                                        destination = _audit_redirect(target, http.get("redirect"))
                                        if destination in seen_targets:
                                            raise ValueError("The redirect returns to an already checked URL.")
                                        scoped(destination, approved_rules)
                                        scoped(destination, current_rules)
                                except ValueError as exc:
                                    execution.update(status="unverified", reason=f"HTTP redirect. {exc}")
                                else:
                                    if not existing:
                                        seen_targets.add(destination)
                                        candidates.append((destination, hops + 1))
                                        execution["reason"] = "HTTP redirect. The same-host destination is queued for verification."
                            else:
                                verified.append(target)
                                if http.get("source") == "preflight":
                                    execution.update(status="partial", reason=(
                                        f"The independent probe received HTTP {http['status']}. Technology detection "
                                        "is incomplete. Web checks can continue. " + execution.get("reason", "")
                                    ).strip())
                        elif result["status"] == "completed":
                            execution.update(status="unverified", reason="HTTPx returned no HTTP response for the planned origin.")
                    run = locked_run(db, run_id)
                    if not run:
                        return {"status": "missing"}
                    if run.status != "running":
                        return _finish(db, run, stages, "partial")
                    _save(db, run, stages)
                run = locked_run(db, run_id)
                if not run:
                    return {"status": "missing"}
                outcomes = {item["status"] for item in stage["executions"]}
                stage["completed_at"] = datetime.now(timezone.utc).isoformat()
                stage["status"] = ("completed" if outcomes == {"completed"} else "partial" if outcomes & {"completed", "partial"}
                                   else "skipped" if outcomes <= {"skipped", "unverified"}
                                   else "unreachable" if outcomes <= {"unreachable", "skipped"}
                                   else "blocked" if outcomes <= {"blocked", "skipped"} else "failed")
                if run.status != "running":
                    return _finish(db, run, stages, "partial")
                _save(db, run, stages)
            run = locked_run(db, run_id)
            if not run:
                return {"status": "missing"}
            if all(stage["status"] == "completed" for stage in stages):
                return _finish(db, run, stages, "completed")
            outcomes = {item["status"] for stage in stages for item in stage["executions"]}
            status = ("partial" if outcomes & {"completed", "partial", "unverified"}
                      else "blocked" if "blocked" in outcomes and "failed" not in outcomes else "failed")
            failed = next(((stage, item) for stage in stages for item in stage["executions"]
                           if item["status"] in {"failed", "blocked", "partial", "unreachable", "unverified"}), None)
            reason = f"{failed[0]['title']}: {failed[1].get('reason', failed[1]['status'])}" if failed else \
                "Some planned checks were skipped. Review stage coverage."
            return _finish(db, run, stages, status, reason[:2000])
        except Exception as exc:
            db.rollback()
            run = locked_run(db, run_id)
            return _finish(db, run, stages, "failed", str(exc)[:2000]) if run else {"status": "missing"}


def recover_audits() -> list[int]:
    """Dispatch unsent plans and close orphaned active runs without replaying scans."""
    queued = []
    with SessionLocal.begin() as db:
        if db.bind.dialect.name != "postgresql":
            return queued
        runs = db.scalars(select(AuditRun).where(AuditRun.status.in_(ACTIVE_AUDITS))
                          .with_for_update(skip_locked=True)).all()
        for run in runs:
            if not db.scalar(text("SELECT pg_try_advisory_xact_lock(:namespace, :id)"),
                             {"namespace": AUDIT_LOCK, "id": run.id}):
                continue
            if run.status == "queued":
                queued.append(run.id)
                continue
            now = datetime.now(timezone.utc)
            cancelled = run.status == "cancelling"
            reason = "Stopped by the operator." if cancelled else "The worker was interrupted. Completed scan evidence was retained."
            jobs = db.scalars(select(ScanJob).where(ScanJob.audit_run_id == run.id).with_for_update()).all()
            by_id = {job.id: job for job in jobs}
            for job in jobs:
                if job.status in ACTIVE_CHILDREN:
                    job.status = "cancelled" if cancelled else "failed"
                    job.completed_at = now
                    job.error = "" if cancelled else reason
            stages = deepcopy(run.stages)
            for stage in stages:
                for execution in stage["executions"]:
                    if execution["status"] == "running" and (job := by_id.get(execution.get("job_id"))):
                        execution.update(status=job.status, records=job.results_count, reason=job.error)
                if stage["status"] in {"pending", "running"}:
                    stage.update(status="skipped" if stage["status"] == "pending" else "partial", reason=reason)
            run.stages = stages
            run.status = "cancelled" if cancelled else "partial" if any(job.status == "completed" for job in jobs) else "failed"
            run.error = reason
            run.completed_at = now
    return queued
