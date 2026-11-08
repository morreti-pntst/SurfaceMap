from datetime import datetime, timezone
from sqlalchemy import func, insert, select, text
from sqlalchemy.orm import Session
from .importers import ParseResult, finding_fingerprint, observation_fingerprint, related_identity, web_identity
from .models import Asset, AssetRelationship, AssetSighting, Finding, ImportBatch, Observation, ObservationSighting

def store_import(db: Session, project_id: int, file_format: str, filename: str, parsed: ParseResult,
                 *, commit: bool = True, finding_ids: set[int] | None = None) -> ImportBatch:
    if db.bind.dialect.name == "postgresql":
        # Serialize deduplication against another import for this project.
        db.execute(text("SELECT pg_advisory_xact_lock(90714, :project)"), {"project": project_id})
    now = datetime.now(timezone.utc)
    batch = ImportBatch(project_id=project_id, format=file_format, filename=filename[:255], imported_at=now,
                        records_seen=len(parsed.records), assets_created=0, findings_created=0, warnings=parsed.warnings[:200])
    db.add(batch)
    db.flush()
    assets: dict[tuple[str, str], Asset] = {}
    relationships: dict[tuple[int, int, str], AssetRelationship] = {}
    seen_observations: dict[str, int | Observation] = {}
    seen_findings: dict[str, Finding] = {}

    def resolve_asset(asset_type: str, value: str) -> Asset:
        identity = (asset_type, value)
        asset = assets.get(identity)
        if asset is None:
            asset = db.scalar(select(Asset).where(Asset.project_id == project_id, Asset.asset_type == asset_type, Asset.canonical_value == value))
            if asset is None:
                asset = Asset(project_id=project_id, asset_type=asset_type, canonical_value=value, first_seen=now, last_seen=now)
                db.add(asset)
                db.flush()
                batch.assets_created += 1
            else:
                asset.last_seen = now
            assets[identity] = asset
        return asset

    def link_assets(source: Asset, target: Asset, kind: str) -> None:
        if target.id == source.id:
            return
        identity = (source.id, target.id, kind)
        if identity in relationships:
            return
        relation = db.scalar(select(AssetRelationship).where(AssetRelationship.project_id == project_id,
            AssetRelationship.source_asset_id == source.id, AssetRelationship.target_asset_id == target.id,
            AssetRelationship.relationship_type == kind))
        if relation is None:
            relation = AssetRelationship(project_id=project_id, source_asset_id=source.id, target_asset_id=target.id,
                relationship_type=kind, evidence={"import_id": batch.id}, first_seen=now, last_seen=now)
            db.add(relation)
        else:
            relation.last_seen = now
        relationships[identity] = relation

    def legacy_finding(asset: Asset, data: dict) -> Finding | None:
        # Historical Nuclei imports attached findings to the host and kept the raw matched URL.
        if asset.asset_type != "endpoint" or not (identity := web_identity(asset.canonical_value)):
            return None
        host_type, host_name = identity[2]
        candidates = db.scalars(select(Finding).join(Asset, Finding.asset_id == Asset.id).where(
            Finding.project_id == project_id, Asset.project_id == project_id,
            Asset.asset_type == host_type, Asset.canonical_value == host_name,
            func.lower(Finding.template_id) == data["template_id"].lower(),
        ).order_by(Finding.id))
        return next((finding for finding in candidates if finding.title.lower() == data["title"].lower()
                     and web_identity(finding.matched_at) == identity), None)

    for record in parsed.records:
        asset = resolve_asset(record.asset_type, record.asset_value)
        for related_item in record.related_assets:
            if not (related := related_identity(related_item)):
                continue
            related_type, related_value, relationship_type = related
            target = resolve_asset(related_type, related_value)
            reverse = (relationship_type in {"exposes", "has_filtered_port", "contains_endpoint"} or
                       relationship_type == "serves_web" and asset.asset_type == "web_origin")
            source_asset, target_asset = (target, asset) if reverse else (asset, target)
            link_assets(source_asset, target_asset, relationship_type)
            if relationship_type == "contains_endpoint" and (web := web_identity(target.canonical_value)):
                link_assets(resolve_asset(*web[2]), target, "serves_web")
        fingerprint = observation_fingerprint(project_id, record.asset_type, record.asset_value, file_format, record.kind, record.data)
        if fingerprint not in seen_observations:
            existing = db.scalar(select(Observation.id).where(Observation.fingerprint == fingerprint))
            if existing is not None:
                seen_observations[fingerprint] = existing
            else:
                observation = Observation(project_id=project_id, asset_id=asset.id, import_id=batch.id, source_tool=file_format,
                                          kind=record.kind, fingerprint=fingerprint, data=record.data, observed_at=now)
                db.add(observation)
                seen_observations[fingerprint] = observation
        if record.finding:
            finding_data = record.finding
            dedupe = finding_fingerprint(project_id, finding_data["template_id"], finding_data["matched_at"], finding_data["title"])
            finding = seen_findings.get(dedupe)
            if finding is None:
                finding = db.scalar(select(Finding).where(Finding.project_id == project_id, Finding.dedupe_key == dedupe))
                if finding is None:
                    finding = legacy_finding(asset, finding_data)
            if finding is None:
                finding = Finding(project_id=project_id, asset_id=asset.id, dedupe_key=dedupe, title=finding_data["title"],
                               severity=finding_data["severity"], template_id=finding_data["template_id"],
                               matched_at=finding_data["matched_at"], evidence=finding_data["evidence"], first_seen=now, last_seen=now)
                db.add(finding)
                batch.findings_created += 1
            else:
                finding.asset_id = asset.id
                finding.dedupe_key = dedupe
                finding.matched_at = finding_data["matched_at"]
                finding.last_seen = now
                evidence = finding_data["evidence"]
                if "scan_target" in finding.evidence and "scan_target" not in evidence:
                    evidence = {**evidence, "scan_target": finding.evidence["scan_target"]}
                matchers = [*finding.evidence.get("observed_matchers", []), finding.evidence.get("matcher-name"),
                            evidence.get("matcher-name")]
                finding.evidence = {**evidence, "observed_matchers": list(dict.fromkeys(
                    matcher for matcher in matchers if isinstance(matcher, str) and matcher
                ))[:48]}
            seen_findings[dedupe] = finding
    db.flush()
    if assets:
        db.execute(insert(AssetSighting), [{"asset_id": asset.id, "import_id": batch.id} for asset in assets.values()])
    if seen_observations:
        db.execute(insert(ObservationSighting), [
            {"observation_id": value if isinstance(value, int) else value.id, "import_id": batch.id}
            for value in seen_observations.values()
        ])
    if finding_ids is not None:
        finding_ids.update(finding.id for finding in seen_findings.values())
    if commit:
        db.commit()
    return batch
