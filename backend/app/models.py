from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .db import Base

def now_utc():
    return datetime.now(timezone.utc)

class Project(Base):
    __tablename__ = "projects"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    scopes: Mapped[list["ScopeEntry"]] = relationship(back_populates="project", cascade="all, delete-orphan")

class ScopeEntry(Base):
    __tablename__ = "scope_entries"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    value: Mapped[str] = mapped_column(String(253))
    kind: Mapped[str] = mapped_column(String(16), default="domain")
    excluded: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    project: Mapped[Project] = relationship(back_populates="scopes")


class SurfaceDraft(Base):
    __tablename__ = "surface_drafts"
    __table_args__ = (UniqueConstraint("project_id", "source_key", name="uq_surface_draft_source"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    revision: Mapped[int] = mapped_column(Integer, default=1)
    nodes: Mapped[list] = mapped_column(JSON, default=list)
    links: Mapped[list] = mapped_column(JSON, default=list)
    source_key: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    source_truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

class ImportBatch(Base):
    __tablename__ = "import_batches"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    format: Mapped[str] = mapped_column(String(24))
    filename: Mapped[str] = mapped_column(String(255))
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    records_seen: Mapped[int] = mapped_column(Integer, default=0)
    assets_created: Mapped[int] = mapped_column(Integer, default=0)
    findings_created: Mapped[int] = mapped_column(Integer, default=0)
    warnings: Mapped[list] = mapped_column(JSON, default=list)

class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("project_id", "asset_type", "canonical_value", name="uq_asset_project_identity"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    asset_type: Mapped[str] = mapped_column(String(24), index=True)
    canonical_value: Mapped[str] = mapped_column(String(1024), index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

class AssetRelationship(Base):
    __tablename__ = "asset_relationships"
    __table_args__ = (UniqueConstraint("project_id", "source_asset_id", "target_asset_id", "relationship_type", name="uq_asset_relationship_identity"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    source_asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    target_asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    relationship_type: Mapped[str] = mapped_column(String(48))
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class AssetSighting(Base):
    __tablename__ = "asset_sightings"
    import_id: Mapped[int] = mapped_column(ForeignKey("import_batches.id", ondelete="CASCADE"), primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True, index=True)


class Observation(Base):
    __tablename__ = "observations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    import_id: Mapped[int] = mapped_column(ForeignKey("import_batches.id", ondelete="CASCADE"), index=True)
    source_tool: Mapped[str] = mapped_column(String(32), index=True)
    kind: Mapped[str] = mapped_column(String(48))
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    data: Mapped[dict] = mapped_column(JSON)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class ObservationSighting(Base):
    __tablename__ = "observation_sightings"
    import_id: Mapped[int] = mapped_column(ForeignKey("import_batches.id", ondelete="CASCADE"), primary_key=True)
    observation_id: Mapped[int] = mapped_column(ForeignKey("observations.id", ondelete="CASCADE"), primary_key=True, index=True)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("project_id", "dedupe_key", name="uq_finding_project_dedupe"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[Optional[int]] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)
    dedupe_key: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    template_id: Mapped[str] = mapped_column(String(255), default="")
    matched_at: Mapped[str] = mapped_column(String(2048), default="")
    status: Mapped[str] = mapped_column(String(16), default="open")
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    review: Mapped[dict] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

class ProjectSnapshot(Base):
    __tablename__ = "project_snapshots"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    asset_count: Mapped[int] = mapped_column(Integer, default=0)
    relationship_count: Mapped[int] = mapped_column(Integer, default=0)
    finding_counts: Mapped[dict] = mapped_column(JSON, default=dict)

class AuditRun(Base):
    __tablename__ = "audit_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    target: Mapped[str] = mapped_column(String(1024))
    profile: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    stages: Mapped[list] = mapped_column(JSON, default=list)
    scope_snapshot: Mapped[list] = mapped_column(JSON, default=list)
    manual_review: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

class ScanJob(Base):
    __tablename__ = "scan_jobs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    tool_id: Mapped[str] = mapped_column(String(40), index=True)
    target: Mapped[str] = mapped_column(String(1024))
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    options: Mapped[dict] = mapped_column(JSON, default=dict)
    command: Mapped[list] = mapped_column(JSON, default=list)
    tool_version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    task_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    retry_of_id: Mapped[Optional[int]] = mapped_column(ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True, index=True)
    audit_run_id: Mapped[Optional[int]] = mapped_column(ForeignKey("audit_runs.id", ondelete="SET NULL"), nullable=True, index=True)
    retest_finding_id: Mapped[Optional[int]] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True)
    exit_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    results_count: Mapped[int] = mapped_column(Integer, default=0)
    result_summary: Mapped[dict] = mapped_column(JSON, default=dict)
    artifact_path: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    stdout_excerpt: Mapped[str] = mapped_column(Text, default="")
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

class ToolOperation(Base):
    __tablename__ = "tool_operations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tool_id: Mapped[str] = mapped_column(String(40), index=True)
    action: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    version: Mapped[str] = mapped_column(String(64))
    task_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    log: Mapped[str] = mapped_column(Text, default="")
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

class SystemSetting(Base):
    __tablename__ = "system_settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

class Workflow(Base):
    __tablename__ = "workflows"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    steps: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

class WorkflowRun(Base):
    __tablename__ = "workflow_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workflow_id: Mapped[int] = mapped_column(ForeignKey("workflows.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    target: Mapped[str] = mapped_column(String(1024))
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    job_ids: Mapped[list] = mapped_column(JSON, default=list)
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
