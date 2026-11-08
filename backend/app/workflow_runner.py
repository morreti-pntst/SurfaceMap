"""Sequential workflow execution reusing the normal scope-checked scan runner."""
from datetime import datetime, timezone
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .db import SessionLocal, run_lock
from .models import Project, ScanJob, ScopeEntry, Workflow, WorkflowRun
from .scope_guard import scope_matches
from .scan_runner import build_target, execute_scan
from .tool_manager import installed_version
from .tool_registry import TOOL_BY_ID

WORKFLOW_LOCK = 90716
ACTIVE_WORKFLOWS = ("queued", "running")


def _locked_workflow_run(db: Session, run_id: int) -> WorkflowRun | None:
    return db.scalar(select(WorkflowRun).where(WorkflowRun.id == run_id).with_for_update()
                     .execution_options(populate_existing=True))


def execute_workflow(run_id: int) -> dict:
    with run_lock(WORKFLOW_LOCK, run_id) as acquired:
        if not acquired:
            return {"status": "busy"}
        return _execute_workflow(run_id)


def _execute_workflow(run_id: int) -> dict:
    with SessionLocal() as db:
        run = _locked_workflow_run(db, run_id)
        workflow = db.get(Workflow, run.workflow_id) if run else None
        if not run or not workflow:
            return {"status": "missing"}
        if run.status != "queued":
            return {"status": run.status}
        run.status = "running"
        db.commit()
        try:
            for step_number, step in enumerate(workflow.steps, start=1):
                tool = TOOL_BY_ID.get(step["tool_id"])
                if not tool or not tool.active:
                    raise RuntimeError(f"Workflow step {step_number} references an unavailable adapter")
                version = installed_version(tool)
                run = _locked_workflow_run(db, run_id)
                if not run or run.status != "running":
                    return {"status": run.status if run else "missing"}
                if version != tool.version.lstrip("v"):
                    raise RuntimeError(f"{tool.name} {tool.version} is unavailable for step {step_number}.")
                project = db.get(Project, run.project_id)
                if not project:
                    raise RuntimeError("Project was deleted")
                scope = db.scalars(select(ScopeEntry).where(ScopeEntry.project_id == run.project_id)).all()
                allowed, reason = scope_matches(run.target, scope, allow_network=(tool.id == "nmap"))
                if not allowed:
                    raise RuntimeError(f"Step {step_number} scope check failed: {reason}")
                options = step.get("options") or {}
                target = build_target(tool.id, run.target)
                command = tool.command(target, options, "<output>")
                job = ScanJob(project_id=run.project_id, tool_id=tool.id, target=target, status="queued",
                              task_id=f"workflow:{run.id}", options=options, command=command, tool_version=version)
                db.add(job)
                db.flush()
                run.job_ids = [*run.job_ids, job.id]
                db.commit()
                result = execute_scan(job.id)
                if result.get("status") != "completed":
                    detail = result.get("error") or result.get("status", "failed")
                    raise RuntimeError(f"Step {step_number} ({tool.name}) failed: {detail}")
            run = _locked_workflow_run(db, run_id)
            if run and run.status == "running":
                run.status = "completed"
                run.completed_at = datetime.now(timezone.utc)
                db.commit()
            return {"status": run.status if run else "missing"}
        except Exception as exc:
            db.rollback()
            run = _locked_workflow_run(db, run_id)
            if not run or run.status != "running":
                return {"status": run.status if run else "missing"}
            _interrupt(db, run, str(exc)[:4000])
            db.commit()
            return {"status": "failed", "error": run.error[:1000]}


def _interrupt(db: Session, run: WorkflowRun, reason: str) -> None:
    now = datetime.now(timezone.utc)
    for job in db.scalars(select(ScanJob).where(ScanJob.project_id == run.project_id,
            ScanJob.id.in_(run.job_ids), ScanJob.status.in_(("queued", "running", "cancelling")))
            .with_for_update()):
        job.status = "cancelled" if job.status == "cancelling" else "failed"
        job.error = "" if job.status == "cancelled" else reason
        job.completed_at = now
    run.status = "failed"
    run.error = reason
    run.completed_at = now


def recover_workflows() -> list[int]:
    """Republish unsent work and release slots held by interrupted workers."""
    queued = []
    with SessionLocal.begin() as db:
        if db.get_bind().dialect.name != "postgresql":
            return queued
        runs = db.scalars(select(WorkflowRun).where(WorkflowRun.status.in_(ACTIVE_WORKFLOWS))
                          .with_for_update(skip_locked=True)).all()
        for run in runs:
            if not db.scalar(text("SELECT pg_try_advisory_xact_lock(:namespace, :id)"),
                             {"namespace": WORKFLOW_LOCK, "id": run.id}):
                continue
            if run.status == "queued":
                queued.append(run.id)
            else:
                _interrupt(db, run, "The worker was interrupted. Completed scan evidence was retained.")
    return queued
