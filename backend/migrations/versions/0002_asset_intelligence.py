"""Add import provenance, normalized assets, observations, and findings."""
from alembic import op
import sqlalchemy as sa

revision = "0002_asset_intelligence"
down_revision = "0001_foundation"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("import_batches",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("format", sa.String(24), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("records_seen", sa.Integer(), nullable=False),
        sa.Column("assets_created", sa.Integer(), nullable=False),
        sa.Column("findings_created", sa.Integer(), nullable=False),
        sa.Column("warnings", sa.JSON(), nullable=False))
    op.create_index("ix_import_batches_project_id", "import_batches", ["project_id"])
    op.create_table("assets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_type", sa.String(24), nullable=False),
        sa.Column("canonical_value", sa.String(1024), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("project_id", "asset_type", "canonical_value", name="uq_asset_project_identity"))
    op.create_index("ix_assets_project_id", "assets", ["project_id"])
    op.create_index("ix_assets_asset_type", "assets", ["asset_type"])
    op.create_index("ix_assets_canonical_value", "assets", ["canonical_value"])
    op.create_table("observations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("import_id", sa.Integer(), sa.ForeignKey("import_batches.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_tool", sa.String(32), nullable=False),
        sa.Column("kind", sa.String(48), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False, unique=True),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_observations_project_id", "observations", ["project_id"])
    op.create_index("ix_observations_asset_id", "observations", ["asset_id"])
    op.create_index("ix_observations_import_id", "observations", ["import_id"])
    op.create_index("ix_observations_source_tool", "observations", ["source_tool"])
    op.create_index("ix_observations_fingerprint", "observations", ["fingerprint"])
    op.create_table("findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("dedupe_key", sa.String(64), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("template_id", sa.String(255), nullable=False),
        sa.Column("matched_at", sa.String(2048), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("project_id", "dedupe_key", name="uq_finding_project_dedupe"))
    op.create_index("ix_findings_project_id", "findings", ["project_id"])
    op.create_index("ix_findings_asset_id", "findings", ["asset_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])

def downgrade():
    op.drop_index("ix_findings_severity", table_name="findings")
    op.drop_index("ix_findings_asset_id", table_name="findings")
    op.drop_index("ix_findings_project_id", table_name="findings")
    op.drop_table("findings")
    for name in ("ix_observations_fingerprint", "ix_observations_source_tool", "ix_observations_import_id", "ix_observations_asset_id", "ix_observations_project_id"):
        op.drop_index(name, table_name="observations")
    op.drop_table("observations")
    for name in ("ix_assets_canonical_value", "ix_assets_asset_type", "ix_assets_project_id"):
        op.drop_index(name, table_name="assets")
    op.drop_table("assets")
    op.drop_index("ix_import_batches_project_id", table_name="import_batches")
    op.drop_table("import_batches")
