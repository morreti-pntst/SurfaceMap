"""Store correlated links between normalized assets."""
from alembic import op
import sqlalchemy as sa

revision = "0003_asset_relationships"
down_revision = "0002_asset_intelligence"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("asset_relationships",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_asset_id", sa.Integer(), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_asset_id", sa.Integer(), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("relationship_type", sa.String(48), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("project_id", "source_asset_id", "target_asset_id", "relationship_type", name="uq_asset_relationship_identity"))
    op.create_index("ix_asset_relationships_project_id", "asset_relationships", ["project_id"])
    op.create_index("ix_asset_relationships_source_asset_id", "asset_relationships", ["source_asset_id"])
    op.create_index("ix_asset_relationships_target_asset_id", "asset_relationships", ["target_asset_id"])

def downgrade():
    op.drop_index("ix_asset_relationships_target_asset_id", table_name="asset_relationships")
    op.drop_index("ix_asset_relationships_source_asset_id", table_name="asset_relationships")
    op.drop_index("ix_asset_relationships_project_id", table_name="asset_relationships")
    op.drop_table("asset_relationships")
