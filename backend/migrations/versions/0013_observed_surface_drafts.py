"""Link editable maps to their source graph."""
from alembic import op
import sqlalchemy as sa

revision = "0013_observed_surface_drafts"
down_revision = "0012_surface_drafts"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("surface_drafts") as batch:
        batch.add_column(sa.Column("source_key", sa.String(40), nullable=True))
        batch.add_column(sa.Column("source_truncated", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch.create_unique_constraint("uq_surface_draft_source", ["project_id", "source_key"])


def downgrade():
    with op.batch_alter_table("surface_drafts") as batch:
        batch.drop_constraint("uq_surface_draft_source", type_="unique")
        batch.drop_column("source_truncated")
        batch.drop_column("source_key")
