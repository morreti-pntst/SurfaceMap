"""Persist hand-built attack surface maps per project."""
from alembic import op
import sqlalchemy as sa

revision = "0012_surface_drafts"
down_revision = "0011_retest_lineage"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "surface_drafts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("nodes", sa.JSON(), nullable=False),
        sa.Column("links", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_surface_drafts_project_id", "surface_drafts", ["project_id"])


def downgrade():
    op.drop_index("ix_surface_drafts_project_id", table_name="surface_drafts")
    op.drop_table("surface_drafts")
