"""Persist project inventory snapshots for change tracking."""
from alembic import op
import sqlalchemy as sa

revision = "0004_project_snapshots"
down_revision = "0003_asset_relationships"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("project_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("asset_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("relationship_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("finding_counts", sa.JSON(), nullable=False))
    op.create_index("ix_project_snapshots_project_id", "project_snapshots", ["project_id"])

def downgrade():
    op.drop_index("ix_project_snapshots_project_id", table_name="project_snapshots")
    op.drop_table("project_snapshots")
