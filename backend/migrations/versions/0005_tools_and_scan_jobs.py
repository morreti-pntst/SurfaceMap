"""Add audited tool operations and scoped scan jobs."""
from alembic import op
import sqlalchemy as sa

revision = "0005_tools_and_scan_jobs"
down_revision = "0004_project_snapshots"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tool_id", sa.String(40), nullable=False),
        sa.Column("target", sa.String(1024), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="queued"),
        sa.Column("options", sa.JSON(), nullable=False),
        sa.Column("command", sa.JSON(), nullable=False),
        sa.Column("tool_version", sa.String(64), nullable=True),
        sa.Column("task_id", sa.String(64), nullable=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("results_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("artifact_path", sa.String(2048), nullable=True),
        sa.Column("stdout_excerpt", sa.Text(), nullable=False, server_default=""),
        sa.Column("error", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    for column in ("project_id", "tool_id", "status", "task_id"):
        op.create_index(f"ix_scan_jobs_{column}", "scan_jobs", [column])
    op.create_table(
        "tool_operations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tool_id", sa.String(40), nullable=False),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="queued"),
        sa.Column("version", sa.String(64), nullable=False),
        sa.Column("task_id", sa.String(64), nullable=True),
        sa.Column("log", sa.Text(), nullable=False, server_default=""),
        sa.Column("error", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    for column in ("tool_id", "status", "task_id"):
        op.create_index(f"ix_tool_operations_{column}", "tool_operations", [column])


def downgrade():
    for column in ("tool_id", "status", "task_id"):
        op.drop_index(f"ix_tool_operations_{column}", table_name="tool_operations")
    op.drop_table("tool_operations")
    for column in ("project_id", "tool_id", "status", "task_id"):
        op.drop_index(f"ix_scan_jobs_{column}", table_name="scan_jobs")
    op.drop_table("scan_jobs")
