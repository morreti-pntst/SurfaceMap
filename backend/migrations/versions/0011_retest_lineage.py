"""Record exact observation sightings and finding retests."""
from alembic import op
import sqlalchemy as sa

revision = "0011_retest_lineage"
down_revision = "0010_asset_sightings"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "observation_sightings",
        sa.Column("import_id", sa.Integer(), sa.ForeignKey("import_batches.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("observation_id", sa.Integer(), sa.ForeignKey("observations.id", ondelete="CASCADE"), primary_key=True),
    )
    op.create_index("ix_observation_sightings_observation_id", "observation_sightings", ["observation_id"])
    with op.batch_alter_table("scan_jobs") as batch:
        batch.add_column(sa.Column("retest_finding_id", sa.Integer(), nullable=True))
        batch.create_foreign_key("fk_scan_jobs_retest_finding", "findings", ["retest_finding_id"], ["id"], ondelete="SET NULL")
        batch.create_index("ix_scan_jobs_retest_finding_id", ["retest_finding_id"])


def downgrade():
    with op.batch_alter_table("scan_jobs") as batch:
        batch.drop_index("ix_scan_jobs_retest_finding_id")
        batch.drop_constraint("fk_scan_jobs_retest_finding", type_="foreignkey")
        batch.drop_column("retest_finding_id")
    op.drop_index("ix_observation_sightings_observation_id", table_name="observation_sightings")
    op.drop_table("observation_sightings")
