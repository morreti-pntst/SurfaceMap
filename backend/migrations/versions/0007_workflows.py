"""Add sequential scoped workflows."""
from alembic import op
import sqlalchemy as sa

revision = "0007_workflows"
down_revision = "0006_system_settings"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "workflows",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("steps", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_workflows_project_id", "workflows", ["project_id"])
    op.create_table(
        "workflow_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("workflow_id", sa.Integer(), sa.ForeignKey("workflows.id", ondelete="CASCADE"), nullable=False),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target", sa.String(1024), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="queued"),
        sa.Column("job_ids", sa.JSON(), nullable=False),
        sa.Column("error", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    for column in ("workflow_id", "project_id", "status"):
        op.create_index(f"ix_workflow_runs_{column}", "workflow_runs", [column])


def downgrade():
    for column in ("workflow_id", "project_id", "status"):
        op.drop_index(f"ix_workflow_runs_{column}", table_name="workflow_runs")
    op.drop_table("workflow_runs")
    op.drop_index("ix_workflows_project_id", table_name="workflows")
    op.drop_table("workflows")
