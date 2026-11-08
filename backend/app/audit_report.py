"""Portable coverage and findings report for one guided audit."""
from datetime import datetime, timezone
from html import escape

from sqlalchemy import select
from sqlalchemy.orm import Session

from .audit_comparison import audit_evidence
from .models import AuditRun, Finding, Project
from .schemas import AuditRunRead, FindingRead


def audit_document(db: Session, project: Project, audit: AuditRun) -> dict:
    evidence = audit_evidence(db, audit)
    jobs, ids = evidence.jobs, evidence.findings
    findings = db.scalars(select(Finding).where(
        Finding.project_id == audit.project_id, Finding.id.in_(ids),
    ).order_by(Finding.id)).all() if ids else []
    manual_checks = [{**check, **audit.manual_review.get(check["id"], {"status": "pending", "notes": ""})}
                     for check in audit.config.get("manual_checks", [])]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": {"id": project.id, "name": project.name},
        "audit": AuditRunRead.model_validate(audit).model_dump(mode="json"),
        "coverage": {
            "planned_stages": len(audit.stages),
            "completed_stages": sum(stage["status"] == "completed" for stage in audit.stages),
            "completed_jobs": sum(job.status == "completed" for job in jobs),
            "findings": len(findings),
            "manual_checks": len(manual_checks),
            "reviewed_manual_checks": sum(check["status"] == "reviewed" for check in manual_checks),
        },
        "jobs": [
            {"id": job.id, "tool": job.tool_id, "version": job.tool_version, "target": job.target,
             "status": job.status, "records": job.results_count, "error": job.error, "evidence": job.result_summary}
            for job in jobs
        ],
        "findings": [FindingRead.model_validate(finding).model_dump(mode="json") for finding in findings],
        "manual_checks": manual_checks,
        "interpretation": [
            "Coverage reflects only the planned checks executed by this run.",
            "Skipped, blocked and unfinished checks remain gaps. A completed check with no findings is not proof of absence.",
            "Finding status and remediation reflect the current project review at the export time.",
        ],
    }


def audit_html(document: dict) -> str:
    audit = document["audit"]
    coverage = document["coverage"]

    def cells(*values) -> str:
        return "<tr>" + "".join(f"<td>{escape(str(value) if value is not None else '')}</td>" for value in values) + "</tr>"

    def table(columns, rows: str) -> str:
        headers = "".join(f"<th scope='col'>{escape(column)}</th>" for column in columns)
        return f"<table><thead><tr>{headers}</tr></thead><tbody>{rows}</tbody></table>"

    scope = "".join(cells(rule["kind"], rule["value"], "Excluded" if rule["excluded"] else "Allowed")
                    for rule in audit["scope_snapshot"]) or cells("—", "No stored entries", "—")
    steps = []
    http_rows = []
    for stage in audit["stages"]:
        steps.append(cells(stage["title"], "", stage["status"], stage.get("reason", "")))
        for execution in stage["executions"]:
            reference = f"Scan #{execution['job_id']}" if execution.get("job_id") else ""
            records = f"{execution['records']} records" if "records" in execution else ""
            detail = " · ".join(value for value in (reference, records, execution.get("reason", "")) if value)
            steps.append(cells(stage["tool_id"], execution["target"], execution["status"], detail))
            if http := execution.get("http"):
                posture = http["posture"]
                present = ", ".join(key for key, value in posture["headers_present"].items() if value)
                absent = ", ".join(key for key, value in posture["headers_present"].items() if not value)
                flags = ", ".join(f"{key} {count}" for key, count in posture["cookies"].items())
                cors = f"Wildcard {posture['cors_wildcard']} · Credentials {posture['cors_credentials']}"
                http_rows.append(cells(http["url"], http["probe_status"], present, absent, flags, cors))
        if stage.get("excluded_or_over_limit"):
            steps.append(cells(stage["tool_id"], "", "Excluded or over limit", stage["excluded_or_over_limit"]))
    findings = "".join(
        cells(finding["severity"], finding["title"], finding["matched_at"], finding["status"],
              finding["review"].get("notes", ""),
              finding["review"].get("remediation") or finding["evidence"].get("remediation", ""))
        for finding in document["findings"]
    ) or cells("—", "No findings recorded for this run", "", "", "", "")
    title = f"{document['project']['name']} · Audit #{audit['id']}"
    notes = "".join(f"<li>{escape(note)}</li>" for note in document["interpretation"])
    http_table = ("<h2>Initial HTTP response observations</h2>" + table(
        ("URL", "Status", "Headers present", "Headers absent", "Cookie flag counts", "CORS"), "".join(http_rows),
    )) if http_rows else ""
    manual_rows = "".join(cells(check["title"], check["status"].replace("_", " "), check["notes"])
                          for check in document["manual_checks"])
    manual_table = ("<h2>Manual coverage</h2>" + table(("Check", "Outcome", "Evidence or gap"), manual_rows)
                    if manual_rows else "")
    network_tables = []
    for job in document["jobs"]:
        if not (network := job["evidence"].get("network")):
            continue
        rows = "".join(cells(row["host"], f"{row['port']}/{row['protocol']}" if row.get("port") else
                            ", ".join(group["ports"] for group in row.get("groups", []) if group["ports"]) or f"{row['count']} grouped ports",
                            row["state"], " ".join(row[key] for key in ("name", "product", "version") if row.get(key)))
                       for row in network["ports"])
        if rows:
            network_tables.append(f"<h2>Nmap ports · Scan #{job['id']}</h2>" + table(("Host", "Port", "State", "Service and version"), rows))
        if network["total_rows"] > len(network["ports"]):
            network_tables.append(f"<p>{network['total_rows']} rows total. Download the full Nmap report from Scan Jobs.</p>")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>{escape(title)}</title><style>
body{{font:15px/1.55 system-ui,sans-serif;color:#203143;margin:2rem auto;max-width:1120px;padding:0 1rem}}
h1,h2{{color:#103047}}table{{width:100%;border-collapse:collapse;margin-bottom:1.5rem}}
th,td{{text-align:left;border:1px solid #cbd7df;padding:.55rem;vertical-align:top;overflow-wrap:anywhere}}
th{{background:#edf3f6}}td{{white-space:pre-wrap}}.muted{{color:#536677}}
@media print{{body{{margin:0}}thead{{display:table-header-group}}tr{{break-inside:avoid}}}}
</style></head><body>
<header><p class="muted">SURFACEMAP · AUDIT COVERAGE</p><h1>{escape(title)}</h1>
<p>{escape(audit['target'])} · {escape(audit['profile'])} · <strong>{escape(audit['status'])}</strong></p>
<p class="muted">Exported {escape(document['generated_at'])}</p></header>
<p>{coverage['completed_stages']} / {coverage['planned_stages']} stages completed ·
{coverage['completed_jobs']} completed scan jobs · {coverage['findings']} recorded findings</p>
<p>{escape(audit['error'])}</p><ul>{notes}</ul>
<h2>Authorized scope at launch</h2>{table(('Type', 'Rule', 'Decision'), scope)}
<h2>Stage coverage</h2>{table(('Stage / tool', 'Target', 'Outcome', 'Evidence or reason'), ''.join(steps))}
{http_table}
{''.join(network_tables)}
<h2>Findings and remediation</h2>{table(('Severity', 'Finding', 'Matched URL', 'Review', 'Notes', 'Remediation'), findings)}
{manual_table}
</body></html>"""
