"""Project-scoped storage for operator-authored topology."""
import ipaddress
import re
from datetime import datetime
from typing import Annotated, Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, field_validator, model_validator
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .db import get_db
from .models import Project, SurfaceDraft, now_utc
from .scope_guard import normalize_web_target, target_identity

router = APIRouter(prefix="/api/projects/{project_id}/surface-drafts", tags=["map builder"])
NodeId = Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9_-]{1,64}$")]
MAP_NODE_LIMIT = 500
MAP_LINK_LIMIT = 1000
OBSERVED_KINDS = {"domain": "domain", "ipv4": "ip", "ipv6": "ip", "web_origin": "origin",
                  "endpoint": "endpoint", "service": "service", "filtered_port": "filtered_port"}
OBSERVED_RELATIONS = {
    "resolves_to": "DNS resolves to", "aliases_to": "DNS alias", "exposes": "Exposes port",
    "serves_web": "Hosts web origin", "contains_endpoint": "Contains route",
    "endpoint_host": "Hosted on", "has_filtered_port": "Filtered port", "related_to": "Related to",
    "responded_from": "Responded from", "hosts": "Hosts", "serves": "Serves",
    "redirects_to": "Redirects to", "depends_on": "Depends on", "has_subdomain": "Has subdomain",
}


class MapName(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=120)


class MapNode(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    id: NodeId
    kind: Literal["domain", "ip", "network", "origin", "endpoint", "service", "filtered_port", "device",
                  "application", "datastore", "finding", "note"]
    label: str = Field(min_length=1, max_length=160)
    value: str = Field(default="", max_length=1024)
    technology: str = Field(default="", max_length=160)
    version: str = Field(default="", max_length=100)
    os: str = Field(default="", max_length=160)
    notes: str = Field(default="", max_length=2000)
    observed_asset_id: int | None = Field(default=None, ge=1)
    x: float = Field(ge=-100000, le=100000, allow_inf_nan=False)
    y: float = Field(ge=-100000, le=100000, allow_inf_nan=False)

    @field_validator("value")
    @classmethod
    def clean_value(cls, value: str) -> str:
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("Asset identifiers must be a single line.")
        return value

    @model_validator(mode="after")
    def validate_identifier(self):
        if self.kind in {"domain", "ip", "network"}:
            expected = self.kind
            wildcard = self.kind == "domain" and self.value.startswith("*.")
            address = self.value[2:] if wildcard else self.value
            if expected == "domain" and any(char in address for char in "/:@?#[]"):
                raise ValueError("Enter a hostname without a URL or port.")
            if expected == "ip":
                try:
                    ipaddress.ip_address(address)
                except ValueError as exc:
                    raise ValueError("Enter a bare IPv4 or IPv6 address.") from exc
            if expected == "network" and "/" not in address:
                raise ValueError("Enter a network with a CIDR prefix.")
            kind, normalized = target_identity(address)
            if kind != expected:
                raise ValueError(f"Enter a valid {expected} identifier.")
            self.value = ("*." if wildcard else "") + normalized
        if self.kind in {"origin", "endpoint"}:
            parsed = urlsplit(self.value)
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
                raise ValueError("Enter a complete HTTP or HTTPS URL.")
            if self.kind == "origin" and (parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
                raise ValueError("Use an endpoint node to include a URL path or query.")
            self.value = normalize_web_target(self.value)
        if self.kind in {"service", "filtered_port"} and self.value:
            port = re.fullmatch(r"([0-9]{1,5})(?:/(tcp|udp|sctp))?", self.value.lower())
            if not port or not 1 <= int(port[1]) <= 65535:
                raise ValueError("Enter a port from 1 to 65535, for example 443/tcp.")
            self.value = f"{int(port[1])}/{port[2] or 'tcp'}"
        return self


class MapLink(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    id: NodeId
    source: NodeId
    target: NodeId
    relation: str = Field(min_length=1, max_length=80)
    notes: str = Field(default="", max_length=2000)


class MapContent(MapName):
    nodes: list[MapNode] = Field(max_length=MAP_NODE_LIMIT)
    links: list[MapLink] = Field(max_length=MAP_LINK_LIMIT)

    @model_validator(mode="after")
    def validate_links(self):
        node_ids = {node.id for node in self.nodes}
        if len(node_ids) != len(self.nodes) or len({link.id for link in self.links}) != len(self.links):
            raise ValueError("Node and link identifiers must be unique.")
        relationships = set()
        for link in self.links:
            if link.source not in node_ids or link.target not in node_ids or link.source == link.target:
                raise ValueError("Each link must connect two different nodes on this map.")
            identity = link.source, link.target, link.relation.casefold()
            if identity in relationships:
                raise ValueError("A link with that direction and relationship already exists.")
            relationships.add(identity)
        return self


class MapUpdate(MapContent):
    revision: int = Field(ge=1)


class MapSummary(MapName):
    model_config = ConfigDict(from_attributes=True)
    id: int
    revision: int
    updated_at: datetime
    source_key: str | None
    source_truncated: bool


class MapRead(MapSummary):
    # Writes are validated in MapUpdate. Return the saved document as stored.
    nodes: list[dict]
    links: list[dict]


class MapPosition(BaseModel):
    x: float = Field(ge=-100000, le=100000, allow_inf_nan=False)
    y: float = Field(ge=-100000, le=100000, allow_inf_nan=False)


class ObservedLayout(BaseModel):
    positions: dict[NodeId, MapPosition] = Field(max_length=MAP_NODE_LIMIT)


def observed_draft_query(project_id: int, audit_id: int | None):
    source = f"audit:{audit_id}" if audit_id is not None else "project"
    return select(SurfaceDraft).where(SurfaceDraft.project_id == project_id, SurfaceDraft.source_key == source)


def copy_observed_graph(db: Session, project_id: int, audit_id: int | None, graph: dict,
                        layout: ObservedLayout | None = None) -> SurfaceDraft:
    if not graph["nodes"]:
        raise HTTPException(422, "This map has no discovered assets to edit yet.")
    # Keep successive layers legible while retaining every node and edge the observed graph returned.
    groups = ("domain", "web_origin", "ipv4", "ipv6", "service", "filtered_port", "endpoint")
    order = {kind: index for index, kind in enumerate(groups)}
    nodes = []
    positions = layout.positions if layout and layout.positions.keys() == {item["id"] for item in graph["nodes"]} else {}
    column = y = 0
    previous = ""
    for item in sorted(graph["nodes"], key=lambda item: (order.get(item["type"], len(groups)), item["label"])):
        if item["type"] != previous:
            y += 120
            column = 0
            previous = item["type"]
        elif column == 7:
            y += 92
            column = 0
        facts = item["facts"]
        value = item["canonical_value"]
        notes = []
        if item["sources"]:
            notes.append("Sources · " + ", ".join(item["sources"]))
        for key, label in (("status_code", "HTTP"), ("status", "Status"), ("method", "Method"), ("host_ip", "Connected IP")):
            if key in facts:
                notes.append(f"{label} · {facts[key]}")
        if item["findings"]:
            notes.extend(f"Finding #{row['id']} · {row['title']} ({row['severity']})" for row in item["findings"][:8])
        if item["type"] in {"service", "filtered_port"}:
            notes.append("Observed service · " + value)
            port = re.fullmatch(r"(tcp|udp|sctp)/(\d+)(?: .*)?", value.partition("|")[2])
            value = f"{port[2]}/{port[1]}" if port else ""
        kind = OBSERVED_KINDS.get(item["type"], "device")
        node = dict(id=item["id"], kind=kind, label=item["label"][:160], value=value,
                    technology=str(facts.get("product") or facts.get("webserver") or "")[:160],
                    version=str(facts.get("version") or "")[:100], os=str(facts.get("ostype") or "")[:160],
                    notes="\n".join(notes)[:2000], x=(column - 3) * 220, y=y, observed_asset_id=int(item["id"]))
        if position := positions.get(item["id"]):
            node.update(position.model_dump())
        try:
            nodes.append(MapNode.model_validate(node))
        except ValidationError:
            # Legacy scanner identities can be outside the editor's input formats.
            nodes.append(MapNode.model_validate({**node, "kind": "device", "value": "",
                "notes": (f"Original {item['type']} · {item['canonical_value']}\n" + node["notes"])[:2000]}))
        column += 1

    links = []
    seen = set()
    for edge in graph["edges"]:
        relation = OBSERVED_RELATIONS.get(edge["type"], edge["type"].replace("_", " ").capitalize())
        key = edge["source"], edge["target"], relation.casefold()
        if edge["source"] == edge["target"] or key in seen:
            continue
        seen.add(key)
        notes = "Inferred from the hostname hierarchy." if edge.get("evidence", {}).get("basis") == "hostname_suffix" else ""
        links.append(MapLink(id=edge["id"], source=edge["source"], target=edge["target"], relation=relation, notes=notes))
    title = f"Audit #{audit_id} · edited map" if audit_id is not None else "Project surface · edited map"
    draft = SurfaceDraft(project_id=project_id, **MapContent(name=title, nodes=nodes, links=links).model_dump(),
                         source_key=f"audit:{audit_id}" if audit_id is not None else "project",
                         source_truncated=graph["truncated"])
    db.add(draft)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        if existing := db.scalar(observed_draft_query(project_id, audit_id)):
            return existing
        raise
    return draft


def get_draft(db: Session, project_id: int, draft_id: int) -> SurfaceDraft:
    draft = db.scalar(select(SurfaceDraft).where(SurfaceDraft.id == draft_id, SurfaceDraft.project_id == project_id))
    if draft is None:
        raise HTTPException(404, "Map not found.")
    return draft


@router.get("", response_model=list[MapSummary])
def list_drafts(project_id: int, db: Session = Depends(get_db)):
    if db.get(Project, project_id) is None:
        raise HTTPException(404, "Project not found.")
    return db.execute(select(SurfaceDraft.id, SurfaceDraft.name, SurfaceDraft.revision, SurfaceDraft.updated_at,
                             SurfaceDraft.source_key, SurfaceDraft.source_truncated)
                      .where(SurfaceDraft.project_id == project_id)
                      .order_by(SurfaceDraft.updated_at.desc(), SurfaceDraft.id.desc())).mappings().all()


@router.post("", response_model=MapRead, status_code=201)
def create_draft(project_id: int, payload: MapName, db: Session = Depends(get_db)):
    if db.get(Project, project_id) is None:
        raise HTTPException(404, "Project not found.")
    draft = SurfaceDraft(project_id=project_id, name=payload.name)
    db.add(draft)
    db.commit()
    return draft


@router.get("/{draft_id}", response_model=MapRead)
def read_draft(project_id: int, draft_id: int, db: Session = Depends(get_db)):
    return get_draft(db, project_id, draft_id)


@router.put("/{draft_id}", response_model=MapRead)
def save_draft(project_id: int, draft_id: int, payload: MapUpdate, db: Session = Depends(get_db)):
    values = payload.model_dump(exclude={"revision"})
    saved = db.scalar(update(SurfaceDraft).where(
        SurfaceDraft.project_id == project_id, SurfaceDraft.id == draft_id, SurfaceDraft.revision == payload.revision,
    ).values(**values, revision=SurfaceDraft.revision + 1, updated_at=now_utc()).returning(SurfaceDraft))
    if saved is None:
        get_draft(db, project_id, draft_id)
        raise HTTPException(409, "This map was changed in another tab. Export your edits before reloading the saved map.")
    db.commit()
    return saved


@router.delete("/{draft_id}", status_code=204)
def delete_draft(project_id: int, draft_id: int, revision: int, db: Session = Depends(get_db)):
    removed = db.scalar(delete(SurfaceDraft).where(
        SurfaceDraft.project_id == project_id, SurfaceDraft.id == draft_id, SurfaceDraft.revision == revision,
    ).returning(SurfaceDraft.id))
    if removed is None:
        get_draft(db, project_id, draft_id)
        raise HTTPException(409, "This map changed since it was opened. Reload it before deleting.")
    db.commit()
