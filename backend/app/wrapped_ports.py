"""Project Nmap's ambiguous port responses into a separate map layer."""
import re
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import Asset, AssetRelationship, ImportBatch, Observation, ObservationSighting

MAP_WRAPPED_LIMIT = 5000
LEGACY_WRAPPED_SUFFIX = " (tcpwrapped)"
HOST_TYPES = ("ipv4", "ipv6", "domain")
PORT_IDENTITY = re.compile(r"(tcp|udp|sctp)/(\d{1,5})", re.I)


def observed_wrapped_ports(db: Session, project_id: int, hosts, imports: set[int] | None = None) -> list[dict]:
    """Merge historical grouped observations and older per-port assets by host and port."""
    ports: dict[tuple[int, str, int], dict] = {}

    def record(host_id: int, value: str, first_seen: datetime, last_seen: datetime) -> None:
        match = PORT_IDENTITY.fullmatch(value)
        if not match or not 1 <= int(match[2]) <= 65535:
            return
        protocol, port = match[1].lower(), int(match[2])
        first_seen = first_seen.replace(tzinfo=first_seen.tzinfo or timezone.utc).astimezone(timezone.utc)
        last_seen = last_seen.replace(tzinfo=last_seen.tzinfo or timezone.utc).astimezone(timezone.utc)
        key = host_id, protocol, port
        row = ports.setdefault(key, {"host_id": str(host_id), "protocol": protocol, "port": port,
                                     "first_seen": first_seen, "last_seen": last_seen})
        row["first_seen"] = min(row["first_seen"], first_seen)
        row["last_seen"] = max(row["last_seen"], last_seen)

    def with_import_date(statement):
        sighting = ObservationSighting.observation_id == Observation.id
        if imports is not None:
            sighting &= ObservationSighting.import_id.in_(imports)
        return (statement.outerjoin(ObservationSighting, sighting)
                .join(ImportBatch, ImportBatch.id == func.coalesce(ObservationSighting.import_id, Observation.import_id))
                .where(ImportBatch.project_id == project_id))

    grouped = with_import_date(select(Observation.asset_id, Observation.data, ImportBatch.imported_at)
        .select_from(Observation).where(Observation.project_id == project_id,
                                       Observation.kind == "nmap_wrapped_ports", Observation.asset_id.in_(hosts)))
    if imports is not None:
        grouped = grouped.where(ImportBatch.id.in_(imports))
    for host_id, data, seen in db.execute(grouped):
        values = data.get("ports")
        for value in values if isinstance(values, list) else []:
            if isinstance(value, str):
                record(host_id, value, seen, seen)

    legacy = select(AssetRelationship.source_asset_id, Asset.canonical_value).select_from(AssetRelationship).join(
        Asset, Asset.id == AssetRelationship.target_asset_id).where(
        AssetRelationship.project_id == project_id, Asset.project_id == project_id,
        AssetRelationship.relationship_type == "exposes", AssetRelationship.source_asset_id.in_(hosts),
        Asset.asset_type == "service", Asset.canonical_value.endswith(LEGACY_WRAPPED_SUFFIX),
    )
    if imports is None:
        for host_id, identity, first, last in db.execute(legacy.add_columns(Asset.first_seen, Asset.last_seen)):
            record(host_id, identity.partition("|")[2].removesuffix(LEGACY_WRAPPED_SUFFIX), first, last)
    else:
        observed = with_import_date(legacy.add_columns(ImportBatch.imported_at)
            .join(Observation, Observation.asset_id == Asset.id)
            .where(Observation.project_id == project_id, Observation.kind == "nmap_port"))
        for host_id, identity, seen in db.execute(observed.where(ImportBatch.id.in_(imports))):
            record(host_id, identity.partition("|")[2].removesuffix(LEGACY_WRAPPED_SUFFIX), seen, seen)
    return [ports[key] for key in sorted(ports)]
