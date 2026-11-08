"""Persist guided audit runs, scan evidence lineage, and finding reviews."""
from alembic import op
import sqlalchemy as sa

revision = "0009_audit_runs"
down_revision = "0008_scan_job_retry_lineage"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "audit_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target", sa.String(1024), nullable=False),
        sa.Column("profile", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("stages", sa.JSON(), nullable=False),
        sa.Column("scope_snapshot", sa.JSON(), nullable=False),
        sa.Column("manual_review", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("error", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_audit_runs_project_id", "audit_runs", ["project_id"])
    op.create_index("ix_audit_runs_status", "audit_runs", ["status"])
    with op.batch_alter_table("scan_jobs") as batch:
        batch.add_column(sa.Column("audit_run_id", sa.Integer(), nullable=True))
        batch.create_foreign_key("fk_scan_jobs_audit_run_id", "audit_runs", ["audit_run_id"], ["id"], ondelete="SET NULL")
        batch.create_index("ix_scan_jobs_audit_run_id", ["audit_run_id"])
        batch.add_column(sa.Column("result_summary", sa.JSON(), nullable=False, server_default="{}"))
    op.add_column("findings", sa.Column("review", sa.JSON(), nullable=False, server_default="{}"))


def downgrade():
    op.drop_column("findings", "review")
    with op.batch_alter_table("scan_jobs") as batch:
        batch.drop_column("result_summary")
        batch.drop_index("ix_scan_jobs_audit_run_id")
        batch.drop_constraint("fk_scan_jobs_audit_run_id", type_="foreignkey")
        batch.drop_column("audit_run_id")
    op.drop_table("audit_runs")
