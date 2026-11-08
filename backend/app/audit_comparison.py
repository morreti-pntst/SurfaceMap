"""Evidence membership and observed changes between two guided audits."""
import json
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import or_, select, tuple_
from sqlalchemy.orm import Session

from .importers import related_identity, web_identity
from .models import Asset, AssetSighting, AuditRun, Finding, ImportBatch, Observation, ObservationSighting, ScanJob

DETAIL_FIELDS = {
    "http_service": ("status_code", "host_ip", "webserver", "content_type", "tech"),
    "web_endpoint": ("method", "status_code"),
    "ffuf_endpoint": ("status",),
    "nmap_port": ("state", "name", "product", "version", "ostype"),
    "dns_observation": ("a", "aaaa", "cname", "ns", "mx"),
}
ROW_LIMIT = 200
ARCHIVE_LIMIT = 24 * 1024 * 1024
ARCHIVE_ASSET_LIMIT = 10000


@dataclass(frozen=True)
class AuditEvidence:
    jobs: list[ScanJob]
    imports: set[int]
    findings: set[int]


def audit_evidence(db: Session, audit: AuditRun) -> AuditEvidence:
    jobs = list(db.scalars(select(ScanJob).where(
        ScanJob.project_id == audit.project_id, ScanJob.audit_run_id == audit.id,
    ).order_by(ScanJob.id)))
    completed = [job for job in jobs if job.status == "completed"]
    return AuditEvidence(jobs, {job.result_summary["import_id"] for job in completed if job.result_summary.get("import_id")},
                         {item for job in completed for item in job.result_summary.get("finding_ids", [])})


def audit_asset_membership(db: Session, project_id: int, evidence: AuditEvidence):
    sightings = select(AssetSighting.asset_id).where(AssetSighting.import_id.in_(evidence.imports))
    known = set(db.scalars(select(AssetSighting.import_id).where(
        AssetSighting.import_id.in_(evidence.imports)).distinct()))
    recovered_ids, recovered_imports = _recover_archive_assets(db, project_id, evidence, evidence.imports - known)
    historical = evidence.imports - known - recovered_imports
    legacy_dates = select(ImportBatch.imported_at).where(ImportBatch.project_id == project_id, ImportBatch.id.in_(historical))
    membership = or_(
        Asset.id.in_(sightings),
        Asset.id.in_(recovered_ids),
        Asset.id.in_(select(Observation.asset_id).where(Observation.project_id == project_id, Observation.import_id.in_(historical))),
        Asset.first_seen.in_(legacy_dates), Asset.last_seen.in_(legacy_dates),
        Asset.id.in_(select(Finding.asset_id).where(Finding.project_id == project_id, Finding.id.in_(evidence.findings))),
    )
    return membership, bool(historical), bool(recovered_imports)


def _recover_archive_assets(db: Session, project_id: int, evidence: AuditEvidence, missing: set[int]) -> tuple[set[int], set[int]]:
    if not missing:
        return set(), set()
    from .scan_runner import ARTIFACT_ROOT, MAX_ARTIFACT_BYTES, parse_scan_output

    remaining = ARCHIVE_LIMIT
    asset_ids: set[int] = set()
    recovered: set[int] = set()
    root = ARTIFACT_ROOT.resolve()
    for job in evidence.jobs:
        import_id = job.result_summary.get("import_id")
        if job.status != "completed" or import_id not in missing or not job.artifact_path or remaining <= 0:
            continue
        path = Path(job.artifact_path)
        expected_dir = root / f"project-{project_id}" / f"scan-{job.id}"
        try:
            if path.is_symlink() or path.resolve().parent != expected_dir or not path.is_file():
                continue
            size_limit = min(MAX_ARTIFACT_BYTES, remaining)
            if path.stat().st_size > size_limit:
                continue
            with path.open("rb") as stream:
                output = stream.read(size_limit + 1)
            remaining -= len(output)
            if len(output) > size_limit:
                continue
            parsed = parse_scan_output(job.tool_id, output.decode("utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        if len(parsed.records) != job.results_count or not parsed.records:
            continue
        identities = {(record.asset_type, record.asset_value) for record in parsed.records}
        for record in parsed.records:
            for item in record.related_assets:
                if related := related_identity(item):
                    asset_type, value, relationship = related
                    identities.add((asset_type, value))
                    if relationship == "contains_endpoint" and (web := web_identity(value)):
                        identities.add(web[2])
        found = set()
        keys = list(identities)
        if len(keys) > ARCHIVE_ASSET_LIMIT:
            continue
        for offset in range(0, len(keys), 400):
            found.update(db.scalars(select(Asset.id).where(Asset.project_id == project_id,
                tuple_(Asset.asset_type, Asset.canonical_value).in_(keys[offset:offset + 400]))))
        if len(found) == len(identities) and len(asset_ids | found) <= ARCHIVE_ASSET_LIMIT:
            recovered.add(import_id)
            asset_ids.update(found)
    return asset_ids, recovered


def _check_signature(job: ScanJob) -> tuple:
    return job.tool_id, job.target, job.tool_version, json.dumps(job.options, sort_keys=True)


def _plan_signature(audit: AuditRun) -> tuple:
    return tuple((stage["tool_id"], stage["source"], stage["target_limit"], json.dumps(stage["options"], sort_keys=True))
                 for stage in audit.stages)


def _same_scope(first: AuditRun, second: AuditRun) -> bool:
    def rules(run: AuditRun):
        return {(item["kind"], item["value"], item["excluded"]) for item in run.scope_snapshot}
    return rules(first) == rules(second)


def _observed_details(db: Session, project_id: int, imports: set[int]) -> dict:
    details: dict = {}
    if not imports:
        return details
    rows = db.execute(select(Observation.asset_id, Observation.kind, Observation.data)
        .join(ObservationSighting, ObservationSighting.observation_id == Observation.id)
        .where(Observation.project_id == project_id, Observation.kind.in_(DETAIL_FIELDS),
               ObservationSighting.import_id.in_(imports)))
    for asset_id, kind, data in rows:
        payload = {field: (sorted(data[field], key=str) if isinstance(data[field], list) else data[field])
                   for field in DETAIL_FIELDS[kind] if data.get(field) is not None}
        if payload:
            details.setdefault((asset_id, kind), set()).add(json.dumps(payload, sort_keys=True))
    return details


def _proven_imports(db: Session, import_ids: set[int]) -> set[int]:
    return set(db.scalars(select(ObservationSighting.import_id)
                          .where(ObservationSighting.import_id.in_(import_ids)).distinct()))


def _asset_row(asset: Asset) -> dict:
    return {"id": asset.id, "type": asset.asset_type, "value": asset.canonical_value}


def _finding_row(finding: Finding) -> dict:
    return {"id": finding.id, "title": finding.title, "severity": finding.severity,
            "target": finding.matched_at, "review_state": finding.status}


def _delta(before: dict, after: dict, serialize) -> dict:
    new = [serialize(after[id_]) for id_ in after.keys() - before.keys()]
    only_before = [serialize(before[id_]) for id_ in before.keys() - after.keys()]
    sort_key = lambda row: (row.get("type", row.get("severity", "")), row.get("value", row.get("title", "")), row["id"])
    return {"new_count": len(new), "only_before_count": len(only_before),
            "shared_count": len(before.keys() & after.keys()), "new": sorted(new, key=sort_key)[:ROW_LIMIT],
            "only_before": sorted(only_before, key=sort_key)[:ROW_LIMIT]}


def _check_changes(before: AuditEvidence, after: AuditEvidence) -> list[dict]:
    older = {(job.tool_id, job.target): job for job in before.jobs}
    newer = {(job.tool_id, job.target): job for job in after.jobs}
    changes = []
    for tool, target in sorted(older.keys() | newer.keys()):
        left, right = older.get((tool, target)), newer.get((tool, target))
        if not left or not right:
            change = "Added check" if right else "Check absent from this run"
        else:
            differences = [label for field, label in (("status", "status"), ("options", "arguments"), ("tool_version", "version"))
                           if getattr(left, field) != getattr(right, field)]
            if not differences:
                continue
            change = "Changed " + ", ".join(differences)
        changes.append({"tool": tool, "target": target, "change": change,
                        "before": left.status if left else None, "after": right.status if right else None,
                        "before_version": left.tool_version if left else None, "after_version": right.tool_version if right else None})
    return changes


def compare_audits(db: Session, baseline: AuditRun, current: AuditRun, visible_asset) -> dict:
    before, after = audit_evidence(db, baseline), audit_evidence(db, current)
    before_signature = {_check_signature(job) for job in before.jobs if job.status == "completed"}
    after_signature = {_check_signature(job) for job in after.jobs if job.status == "completed"}
    common = before_signature & after_signature
    reasons = []
    if current.target != baseline.target:
        reasons.append("The runs started from different targets.")
    if current.profile != baseline.profile or _plan_signature(current) != _plan_signature(baseline):
        reasons.append("The configured coverage profiles or stage options differ.")
    if not _same_scope(baseline, current):
        reasons.append("The approved scope changed between runs.")
    if before_signature != after_signature:
        reasons.append("Completed tool, target, argument or version combinations differ.")
    if baseline.status != "completed" or current.status != "completed":
        reasons.append("At least one run did not complete all planned checks.")
    if not common:
        reasons.append("There are no matching completed checks across the two runs.")

    project_id = current.project_id
    before_filter, before_historical, before_restored = audit_asset_membership(db, project_id, before)
    after_filter, after_historical, after_restored = audit_asset_membership(db, project_id, after)
    assets = select(Asset).where(Asset.project_id == project_id, visible_asset)
    before_assets = {item.id: item for item in db.scalars(assets.where(before_filter))}
    after_assets = {item.id: item for item in db.scalars(assets.where(after_filter))}
    findings = {item.id: item for item in db.scalars(select(Finding).where(
        Finding.project_id == project_id, Finding.id.in_(before.findings | after.findings),
    ))}
    before_findings = {id_: finding for id_, finding in findings.items() if id_ in before.findings}
    after_findings = {id_: finding for id_, finding in findings.items() if id_ in after.findings}

    def matching_imports(evidence: AuditEvidence):
        return {job.result_summary["import_id"] for job in evidence.jobs
                if job.status == "completed" and _check_signature(job) in common and job.result_summary.get("import_id")}

    before_imports, after_imports = matching_imports(before), matching_imports(after)
    proven_before, proven_after = _proven_imports(db, before_imports), _proven_imports(db, after_imports)
    # Compare detail fields only when the same completed check has recorded evidence in both runs.
    before_pairs = {_check_signature(job) for job in before.jobs if job.result_summary.get("import_id") in proven_before}
    after_pairs = {_check_signature(job) for job in after.jobs if job.result_summary.get("import_id") in proven_after}
    proven_common = before_pairs & after_pairs & common
    def detail_imports(evidence: AuditEvidence, proven: set[int]):
        return {job.result_summary["import_id"] for job in evidence.jobs
                if job.result_summary.get("import_id") in proven and _check_signature(job) in proven_common}

    first = _observed_details(db, project_id, detail_imports(before, proven_before))
    second = _observed_details(db, project_id, detail_imports(after, proven_after))
    changes = [
        {**_asset_row(after_assets[asset_id]), "kind": kind, "before": [json.loads(value) for value in sorted(first[key])],
         "after": [json.loads(value) for value in sorted(second[key])]}
        for key in first.keys() & second.keys()
        for asset_id, kind in [key]
        if asset_id in before_assets and asset_id in after_assets and first[key] != second[key]
    ]
    changes.sort(key=lambda row: (row["type"], row["value"], row["kind"]))
    run_row = lambda run: {"id": run.id, "target": run.target, "status": run.status,
                           "profile": run.profile, "completed_at": run.completed_at}
    check_changes = _check_changes(before, after)
    return {
        "baseline": run_row(baseline), "current": run_row(current),
        "coverage": {"aligned": not reasons, "notes": reasons, "shared_checks": len(common),
                     "baseline_checks": len(before_signature), "current_checks": len(after_signature),
                     "historical_membership": before_historical or after_historical,
                     "recovered_membership": before_restored or after_restored,
                     "historical_details": before_imports != proven_before or after_imports != proven_after,
                     "detail_checks": len(proven_common), "changed_checks": check_changes[:ROW_LIMIT],
                     "changed_check_count": len(check_changes)},
        "assets": _delta(before_assets, after_assets, _asset_row),
        "findings": _delta(before_findings, after_findings, _finding_row),
        "changed_details_count": len(changes),
        "changed_details": changes[:ROW_LIMIT],
        "row_limit": ROW_LIMIT,
    }
