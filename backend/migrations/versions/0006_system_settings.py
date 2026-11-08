"""Persist local Tool Manager preferences."""
from alembic import op
import sqlalchemy as sa

revision = "0006_system_settings"
down_revision = "0005_tools_and_scan_jobs"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "system_settings",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("value", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade():
    op.drop_table("system_settings")
