import os
from datetime import datetime, timedelta, timezone
from celery import Celery
from kombu.exceptions import OperationalError as BrokerUnavailable
from sqlalchemy import select
from .audit_plan import MAX_AUDIT_SECONDS
from .custom_commands import MAX_NMAP_MINUTES

celery_app = Celery("surfacemap", broker=os.getenv("REDIS_URL", "redis://localhost:6379/0"), backend=os.getenv("REDIS_URL", "redis://localhost:6379/0"))
celery_app.conf.update(task_track_started=True, task_serializer="json", accept_content=["json"], result_serializer="json")
celery_app.conf.update(task_soft_time_limit=1500, task_time_limit=1800, worker_prefetch_multiplier=1, task_acks_late=True)
visibility = MAX_AUDIT_SECONDS + 300
celery_app.conf.update(broker_transport_options={"visibility_timeout": visibility},
                       result_backend_transport_options={"visibility_timeout": visibility}, visibility_timeout=visibility)
celery_app.conf.beat_schedule = {
    "recover-tool-installations": {
        "task": "surfacemap.recover_tool_installations", "schedule": 60.0,
        "options": {"expires": 55},
    },
    "expire-interrupted-scans": {
        "task": "surfacemap.expire_interrupted_scans", "schedule": 30.0,
        "options": {"expires": 25},
    },
    "recover-audits": {
        "task": "surfacemap.recover_audits", "schedule": 30.0,
        "options": {"expires": 25},
    },
    "recover-workflows": {
        "task": "surfacemap.recover_workflows", "schedule": 30.0,
        "options": {"expires": 25},
    },
}

@celery_app.task(name="surfacemap.foundation_health")
def foundation_health():
    return {"status": "ok", "component": "worker"}

@celery_app.task(name="surfacemap.execute_scan", bind=True, acks_late=True,
                 soft_time_limit=MAX_NMAP_MINUTES * 60 + 60, time_limit=MAX_NMAP_MINUTES * 60 + 120)
def execute_scan(self, job_id: int):
    from .scan_runner import execute_scan as run
    return run(job_id)


def dispatch_scan(db, job) -> None:
    try:
        task = execute_scan.apply_async(args=[job.id], retry=False)
    except (BrokerUnavailable, OSError):
        return
    job.task_id = task.id
    db.commit()
    db.refresh(job)

@celery_app.task(name="surfacemap.manage_tool", bind=True, acks_late=True)
def manage_tool(self, operation_id: int):
    from .tool_operations import run_tool_operation
    return run_tool_operation(operation_id)

@celery_app.task(name="surfacemap.recover_tool_installations", ignore_result=True)
def recover_tool_installations():
    from .tool_operations import reconcile_tool_operations
    for operation_id in reconcile_tool_operations():
        manage_tool.apply_async(args=[operation_id], expires=75)

@celery_app.task(name="surfacemap.expire_interrupted_scans", ignore_result=True)
def expire_interrupted_scans():
    from .db import SessionLocal
    from .models import ScanJob
    from .scan_runner import expire_stale_scans
    expire_stale_scans()
    with SessionLocal() as db:
        queued = db.scalars(select(ScanJob).where(
            ScanJob.status == "queued", ScanJob.audit_run_id.is_(None), ScanJob.task_id.is_(None),
            ScanJob.created_at < datetime.now(timezone.utc) - timedelta(seconds=30),
        ).order_by(ScanJob.id).limit(10)).all()
        for job in queued:
            dispatch_scan(db, job)

@celery_app.task(name="surfacemap.run_audit", acks_late=True,
                 soft_time_limit=MAX_AUDIT_SECONDS + 60, time_limit=MAX_AUDIT_SECONDS + 120)
def run_audit(audit_id: int):
    from .audit_runner import execute_audit
    return execute_audit(audit_id)

@celery_app.task(name="surfacemap.recover_audits", ignore_result=True)
def recover_audit_runs():
    from .audit_runner import recover_audits
    for audit_id in recover_audits():
        run_audit.apply_async(args=[audit_id], expires=75)

@celery_app.task(name="surfacemap.execute_workflow", bind=True, acks_late=True, soft_time_limit=7200, time_limit=7260)
def execute_workflow(self, run_id: int):
    from .workflow_runner import execute_workflow as run_workflow
    return run_workflow(run_id)


@celery_app.task(name="surfacemap.recover_workflows", ignore_result=True)
def recover_workflow_runs():
    from .workflow_runner import recover_workflows
    for run_id in recover_workflows():
        execute_workflow.apply_async(args=[run_id], expires=75)
