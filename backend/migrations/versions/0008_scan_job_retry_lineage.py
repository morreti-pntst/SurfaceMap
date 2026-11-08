"""Track retry lineage for scan jobs."""
from alembic import op
import sqlalchemy as sa

revision = "0008_scan_job_retry_lineage"
down_revision = "0007_workflows"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        existing = {column["name"] for column in sa.inspect(bind).get_columns("scan_jobs")}
        with op.batch_alter_table("scan_jobs") as batch:
            # SQLite may have added the column before an older migration failed on its constraint.
            if "retry_of_id" not in existing:
                batch.add_column(sa.Column("retry_of_id", sa.Integer(), nullable=True))
            batch.create_foreign_key("fk_scan_jobs_retry_of_id", "scan_jobs", ["retry_of_id"], ["id"], ondelete="SET NULL")
            batch.create_index("ix_scan_jobs_retry_of_id", ["retry_of_id"])
        return
    op.add_column("scan_jobs", sa.Column("retry_of_id", sa.Integer(), sa.ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True))
    op.create_index("ix_scan_jobs_retry_of_id", "scan_jobs", ["retry_of_id"])


def downgrade():
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("scan_jobs") as batch:
            batch.drop_index("ix_scan_jobs_retry_of_id")
            batch.drop_constraint("fk_scan_jobs_retry_of_id", type_="foreignkey")
            batch.drop_column("retry_of_id")
        return
    op.drop_index("ix_scan_jobs_retry_of_id", table_name="scan_jobs")
    op.drop_column("scan_jobs", "retry_of_id")
