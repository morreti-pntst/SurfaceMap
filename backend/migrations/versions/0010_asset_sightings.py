"""Record asset membership of each evidence import."""
from alembic import op
import sqlalchemy as sa

revision = "0010_asset_sightings"
down_revision = "0009_audit_runs"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "asset_sightings",
        sa.Column("import_id", sa.Integer(), sa.ForeignKey("import_batches.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True),
    )
    op.create_index("ix_asset_sightings_asset_id", "asset_sightings", ["asset_id"])


def downgrade():
    op.drop_index("ix_asset_sightings_asset_id", table_name="asset_sightings")
    op.drop_table("asset_sightings")
