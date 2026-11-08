from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field
from typing import Literal

class ScopeCreate(BaseModel):
    value: str = Field(min_length=1, max_length=253)
    kind: str = "domain"
    excluded: bool = False

class ScopeRead(ScopeCreate):
    model_config = ConfigDict(from_attributes=True)
    id: int

class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=2000)

class ProjectRead(ProjectCreate):
    model_config = ConfigDict(from_attributes=True)
    id: int
    created_at: datetime
    scopes: list[ScopeRead] = []

class ImportBatchRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    project_id: int
    format: str
    filename: str
    imported_at: datetime
    records_seen: int
    assets_created: int
    findings_created: int
    warnings: list[str]

class AssetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    project_id: int
    asset_type: str
    canonical_value: str
    first_seen: datetime
    last_seen: datetime

class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    asset_id: int | None
    title: str
    severity: str
    template_id: str
    matched_at: str
    status: str
    evidence: dict
    review: dict
    first_seen: datetime
    last_seen: datetime

class SnapshotRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    project_id: int
    captured_at: datetime
    asset_count: int
    relationship_count: int
    finding_counts: dict

class FindingStatusUpdate(BaseModel):
    status: Literal["open", "confirmed", "accepted", "resolved", "false_positive"]
    notes: str | None = Field(default=None, max_length=4000)
    remediation: str | None = Field(default=None, max_length=4000)

class ScanJobCreate(BaseModel):
    tool_id: str = Field(min_length=1, max_length=40)
    target: str = Field(default="", max_length=1024)
    options: dict = Field(default_factory=dict)
    raw_arguments: str = Field(default="", max_length=512)
    custom_command: str = Field(default="", max_length=2048)
    retest_finding_id: int | None = Field(default=None, gt=0)

class ScanJobRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    project_id: int
    tool_id: str
    target: str
    status: str
    options: dict
    command: list[str]
    tool_version: str | None
    retry_of_id: int | None
    audit_run_id: int | None
    retest_finding_id: int | None
    exit_code: int | None
    results_count: int
    result_summary: dict
    artifact_path: str | None
    stdout_excerpt: str
    error: str
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None

class ToolOperationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    tool_id: str
    action: str
    status: str
    version: str
    log: str
    error: str
    created_at: datetime
    completed_at: datetime | None

class ToolOperationCreate(BaseModel):
    action: Literal["install", "update", "reinstall", "rollback", "uninstall"]

class ToolSettings(BaseModel):
    automatic_updates: bool = True
    update_stable_releases: bool = True
    include_prereleases: bool = False
    check_updates_on_startup: bool = True

class WorkflowStep(BaseModel):
    tool_id: str = Field(min_length=1, max_length=40)
    options: dict = Field(default_factory=dict)

class WorkflowCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    steps: list[WorkflowStep] = Field(min_length=1, max_length=8)

class WorkflowRunCreate(BaseModel):
    target: str = Field(min_length=1, max_length=1024)


class AuditPlanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=1024)
    user_agent: str = Field(default="", max_length=512)
    profile: Literal["full", "web", "domain", "passive"] = "web"
    root_domain: str = Field(default="", max_length=253)
    expand_subdomains: bool = False
    additional_hosts: int = Field(default=3, ge=1, le=5)
    include_amass: bool = False
    include_ports: bool = False
    ports: str = Field(default="", max_length=256)
    nmap_timeout_minutes: int = Field(default=10, ge=1, le=60, strict=True)
    nuclei_mode: Literal["baseline", "focused", "broad", "off"] = "focused"
    wordlist: str = Field(default="", max_length=512)
    rate: int = Field(default=3, ge=1, le=5)


class AuditRunCreate(AuditPlanRequest):
    confirm_scope: bool
    plan_token: str = Field(pattern=r"^[a-f0-9]{64}$")


class AuditRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    project_id: int
    target: str
    profile: str
    status: str
    config: dict
    stages: list[dict]
    scope_snapshot: list[dict]
    manual_review: dict
    error: str
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None


class AuditManualReview(BaseModel):
    status: Literal["pending", "reviewed", "gap", "not_applicable"]
    notes: str = Field(default="", max_length=4000)
