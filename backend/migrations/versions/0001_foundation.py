"""Create initial project and scope tables."""
from alembic import op
import sqlalchemy as sa

revision = "0001_foundation"
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("projects",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("name"))
    op.create_index("ix_projects_name", "projects", ["name"], unique=False)
    op.create_table("scope_entries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("value", sa.String(253), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False, server_default="domain"),
        sa.Column("excluded", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_scope_entries_project_id", "scope_entries", ["project_id"], unique=False)

def downgrade():
    op.drop_index("ix_scope_entries_project_id", table_name="scope_entries")
    op.drop_table("scope_entries")
    op.drop_index("ix_projects_name", table_name="projects")
    op.drop_table("projects")
