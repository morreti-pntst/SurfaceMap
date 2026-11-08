from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from urllib.error import URLError

from sqlalchemy import select, text

from .db import SessionLocal, engine
from .models import SystemSetting, ToolOperation
from .tool_manager import install_version, is_transient_install_error, rollback, uninstall
from .tool_registry import TOOL_BY_ID

INSTALL_ACTIONS = {"install", "update", "reinstall"}
DEFAULT_TOOL_SETTINGS = {
    "automatic_updates": True, "update_stable_releases": True,
    "include_prereleases": False, "check_updates_on_startup": True,
}


@contextmanager
def tool_execution_lock(tool_id: str):
    if engine.dialect.name != "postgresql":
        yield True
        return
    # A session lock spans commits and releases automatically if the worker dies.
    lock = text("SELECT pg_try_advisory_lock(90712, hashtext(:tool))")
    unlock = text("SELECT pg_advisory_unlock(90712, hashtext(:tool))")
    with engine.connect() as connection:
        acquired = connection.scalar(lock, {"tool": tool_id})
        connection.commit()
        try:
            yield acquired
        finally:
            if acquired:
                connection.execute(unlock, {"tool": tool_id})


def reconcile_tool_operations() -> list[int]:
    """Find unfinished work and schedule a new attempt for transient install failures."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
    with SessionLocal() as db:
        if db.bind.dialect.name == "postgresql" and not db.scalar(
            text("SELECT pg_try_advisory_xact_lock(90713)")
        ):
            return []
        unfinished = db.scalars(select(ToolOperation).where(
            ToolOperation.status.in_(["queued", "running"]),
        ).order_by(ToolOperation.id)).all()
        pending = [
            op.id for op in unfinished
            if db.bind.dialect.name != "postgresql" or db.scalar(
                text("SELECT pg_try_advisory_xact_lock(90712, hashtext(:tool))"),
                {"tool": op.tool_id},
            )
        ]
        settings = db.get(SystemSetting, "tool_manager")
        preferences = {**DEFAULT_TOOL_SETTINGS, **(settings.value if settings else {})}
        if not preferences["automatic_updates"] or not preferences["update_stable_releases"]:
            return pending
        for tool_id, tool in TOOL_BY_ID.items():
            latest = db.scalar(select(ToolOperation).where(
                ToolOperation.tool_id == tool_id,
            ).order_by(ToolOperation.id.desc()).limit(1))
            if not latest or latest.status != "failed" or latest.action not in INSTALL_ACTIONS:
                continue
            completed = latest.completed_at
            if completed is None or completed.replace(tzinfo=completed.tzinfo or timezone.utc) > cutoff:
                continue
            if latest.version != tool.version or not is_transient_install_error(latest.error + "\n" + latest.log):
                continue
            retry = ToolOperation(tool_id=tool_id, action=latest.action, version=latest.version,
                                  status="queued", log=f"Automatic retry of operation #{latest.id}.")
            db.add(retry)
            db.flush()
            pending.append(retry.id)
        db.commit()
        return pending


def run_tool_operation(operation_id: int) -> dict:
    with SessionLocal() as db:
        operation = db.get(ToolOperation, operation_id)
        if not operation:
            return {"status": "missing"}
        tool_id = operation.tool_id
    with tool_execution_lock(tool_id) as acquired:
        if not acquired:
            return {"status": "busy"}
        return _run_tool_operation(operation_id)


def _run_tool_operation(operation_id: int) -> dict:
    with SessionLocal() as db:
        operation = db.get(ToolOperation, operation_id)
        if not operation:
            return {"status":"missing"}
        if operation.status not in {"queued", "running"}:
            return {"status": operation.status}
        if operation.status == "running" and operation.action not in INSTALL_ACTIONS:
            operation.status = "failed"
            operation.error = "Interrupted during execution. Check the installed version before retrying."
            operation.completed_at = datetime.now(timezone.utc)
            db.commit()
            return {"status": "failed", "error": operation.error}
        if operation.status == "running":
            operation.log = (operation.log + "\nResuming interrupted installation.")[-20000:]
        operation.status = "running"
        db.commit()
        def emit(message: str):
            current = db.get(ToolOperation, operation_id)
            if current:
                current.log = (current.log + "\n" + message)[-20000:]
                db.commit()
        try:
            tool = TOOL_BY_ID[operation.tool_id]
            if operation.action in INSTALL_ACTIONS:
                message = install_version(tool.id, operation.version, emit)
            elif operation.action == "rollback":
                message = rollback(tool)
            elif operation.action == "uninstall":
                message = uninstall(tool)
            else:
                raise ValueError("Unsupported tool operation")
            operation = db.get(ToolOperation, operation_id)
            operation.status = "completed"
            operation.log = (operation.log + "\n" + message)[-20000:]
            operation.completed_at = datetime.now(timezone.utc)
            db.commit()
            return {"status":"completed", "message":message}
        except Exception as exc:
            db.rollback()
            operation = db.get(ToolOperation, operation_id)
            if operation:
                operation.status = "failed"
                prefix = "Temporary network failure. " if isinstance(exc, (TimeoutError, URLError)) and (
                    not hasattr(exc, "code") or exc.code in {408, 429, 500, 502, 503, 504}
                ) else ""
                operation.error = (prefix + str(exc))[:4000]
                operation.completed_at = datetime.now(timezone.utc)
                db.commit()
            return {"status":"failed", "error":str(exc)[:1000]}
