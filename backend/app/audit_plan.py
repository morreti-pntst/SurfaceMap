"""Build a deterministic plan from explicit scope and operator-selected coverage."""
import hashlib
import json
from pathlib import Path

from .custom_commands import BUILTIN_WORDLIST, MAX_NMAP_MINUTES
from .models import ScopeEntry
from .scan_diagnostics import WEB_TOOLS, user_agent_header
from .schemas import AuditPlanRequest
from .scope_guard import normalize_web_target, scope_matches, target_identity
from .tool_manager import installed_version
from .tool_registry import TOOL_BY_ID

AUDIT_LIMIT_SECONDS = 1800
HTTP_REDIRECT_LIMIT = 2
NUCLEI_BASELINE_SECONDS = 25 * 60
NUCLEI_EXTENDED_SECONDS = 60 * 60
MAX_AUDIT_SECONDS = AUDIT_LIMIT_SECONDS + 7 * MAX_NMAP_MINUTES * 60 + 6 * NUCLEI_EXTENDED_SECONDS
ACTIVE_AUDITS = ("queued", "running", "cancelling")
BASELINE_TEMPLATES = (
    "http-missing-security-headers", "cors-misconfig", "git-config", "nginx-version",
)
MANUAL_CHECKS = (
    ("identity", "Authentication and account recovery", "Verify sign-in, account recovery, MFA and lockout with approved test accounts."),
    ("access", "Roles and object access", "Compare access across roles, tenants and ownership boundaries."),
    ("sessions", "Sessions and state changes", "Review token expiry, logout, cookie policy and protections on state-changing operations."),
    ("api", "API and input handling", "Review API coverage, client-side requests, validation and file handling."),
    ("business", "Business logic and sensitive data", "Check critical workflows, transaction limits and exposure of sensitive data."),
)


def scoped(raw: str, rules: list[ScopeEntry]) -> None:
    allowed, reason = scope_matches(raw, rules)
    if not allowed:
        raise ValueError(f"{raw}: {reason}")


def planned_hosts(seed: str, discovered: set[str], root: str, limit: int,
                  rules: list[ScopeEntry]) -> tuple[list[str], int]:
    """Expand only to observed children of the requested root and inside current scope."""
    if not limit or not root:
        return [seed], 0
    eligible = []
    rejected = 0
    for host in sorted(discovered - {seed}):
        if host != root and not host.endswith(f".{root}"):
            rejected += 1
            continue
        try:
            kind, canonical = target_identity(host)
            if kind != "domain" or canonical != host:
                raise ValueError("Not a canonical domain")
            scoped(host, rules)
        except ValueError:
            rejected += 1
            continue
        eligible.append(host)
    return [seed, *eligible[:limit]], rejected + max(0, len(eligible) - limit)


def build_audit_plan(payload: AuditPlanRequest, rules: list[ScopeEntry], wordlist_root: Path) -> dict:
    kind, host = target_identity(payload.target)
    if kind == "network":
        raise ValueError("An audit starts from one website or hostname. Use Scan Jobs for a network range.")
    target = normalize_web_target(payload.target) if payload.profile != "passive" else host
    scoped(target, rules)
    root = ""
    if payload.profile != "web":
        if kind != "domain":
            raise ValueError("Domain discovery requires a hostname")
        root = host
        if payload.root_domain:
            root_input = payload.root_domain.strip().rstrip(".")
            root_kind, root = target_identity(root_input)
            if root_kind != "domain" or any(character in root_input for character in "/:@?#[]"):
                raise ValueError("Enter a DNS root domain without a URL, port, or wildcard")
            if host != root and not host.endswith(f".{root}"):
                raise ValueError("The audit hostname must be inside the selected root domain")
        scoped(root, rules)
    full = payload.profile == "full"
    expansion = payload.additional_hosts if full or (payload.profile == "domain" and payload.expand_subdomains) else 0
    if full and payload.nuclei_mode == "off":
        raise ValueError("Choose a Nuclei template set for the full audit.")
    stages: list[dict] = []

    def add(tool_id: str, title: str, source: str, target_limit: int, options: dict | None = None):
        options = dict(options or {})
        if tool_id in WEB_TOOLS and payload.user_agent:
            user_agent_header(payload.user_agent)
            options["user_agent"] = payload.user_agent
        tool = TOOL_BY_ID[tool_id]
        version = installed_version(tool)
        stages.append({
            "id": tool_id, "tool_id": tool_id, "title": title, "source": source,
            "target_limit": target_limit, "options": options or {}, "version": tool.version,
            "ready": version == tool.version.lstrip("v"), "status": "pending", "executions": [],
        })

    timeout_seconds = AUDIT_LIMIT_SECONDS
    if root:
        add("subfinder", "Passive subdomain discovery", "root_domain", 1)
        if full or payload.include_amass:
            add("amass", "Second passive discovery source", "root_domain", 1)
    if payload.profile != "passive":
        if full or payload.profile == "domain":
            add("dnsx", "DNS records and aliases", "dns_hosts", 1 + expansion + int(root != host))
        add("httpx", "Confirm web targets and identify technologies", "web_candidates", 1 + expansion,
            {"rate": payload.rate, "raw_arguments": "-title -tech-detect -web-server"})
        stages[-1]["redirect_limit"] = HTTP_REDIRECT_LIMIT
        if full or payload.include_ports:
            ports = payload.ports.strip()
            options = {"mode": "ports", "ports": ports} if ports else {"mode": "services"}
            options["timeout_minutes"] = payload.nmap_timeout_minutes
            TOOL_BY_ID["nmap"].command(host, options)
            title = "Selected TCP ports and service versions" if ports else "Default TCP ports and service versions"
            limit = 1 + expansion + int(root != host) if full else 1
            add("nmap", title, "dns_hosts" if full else "seed_host", limit, options)
            timeout_seconds += limit * payload.nmap_timeout_minutes * 60
        add("katana", "Crawl verified web origins", "verified_web", 1 + expansion,
            {"rate": payload.rate, "depth": 2})
        wordlist = BUILTIN_WORDLIST if full and not payload.wordlist else None
        if payload.wordlist:
            wordlist = Path(payload.wordlist)
            if (wordlist.parent != wordlist_root or wordlist.is_symlink() or not wordlist.is_file()
                    or wordlist.suffix.lower() not in {".txt", ".list"}):
                raise ValueError("Choose an existing managed wordlist")
        if wordlist:
            add("ffuf", "Content discovery on verified web targets" if full else "Content discovery on the seed URL",
                "verified_web" if full else "verified_seed", 1 + expansion if full else 1,
                {"rate": payload.rate, "wordlist": str(wordlist)})
        if payload.nuclei_mode != "off":
            options = {"rate": payload.rate, "severity": ["critical", "high", "medium"]}
            if payload.nuclei_mode != "baseline":
                options["time_budget_seconds"] = NUCLEI_EXTENDED_SECONDS
                timeout_seconds += (1 + expansion) * NUCLEI_EXTENDED_SECONDS
            if payload.nuclei_mode == "focused":
                options["raw_arguments"] = "-tags exposure,misconfig"
            elif payload.nuclei_mode == "baseline":
                options.update(template_ids=list(BASELINE_TEMPLATES), severity=["info", "low", "medium", "high", "critical"])
            add("nuclei", "Web baseline templates" if payload.nuclei_mode == "baseline" else
                "HTTP vulnerability template checks", "verified_web", 1 + expansion, options)

    notes = []
    if root:
        notes.append("Passive discovery may share the root domain with configured public data sources.")
    if expansion:
        notes.append(f"At most {expansion} discovered hostnames are selected. Each must match the root and current scope. Discovered hosts use HTTPS.")
    if full and not payload.wordlist:
        notes.append("FFUF uses the built-in list of 12 common public paths. Select a managed wordlist for broader discovery.")
    if any(stage["id"] == "nmap" for stage in stages):
        notes.append(f"Nmap has up to {payload.nmap_timeout_minutes} minutes per target.")
    if payload.profile != "passive":
        notes.append("HTTP checks continue only on observed web targets. Access blocks and rate limits suspend further web checks on that origin.")
        notes.append(f"HTTP checks may verify up to {HTTP_REDIRECT_LIMIT} redirects per target on the same host. "
                     "A www alias can reuse its apex URL when that exact HTTPS destination was already verified in scope. "
                     "External hosts, new non-default ports, HTTPS downgrades and destinations with queries require review.")
        if payload.nuclei_mode != "off":
            limit = NUCLEI_BASELINE_SECONDS if payload.nuclei_mode == "baseline" else NUCLEI_EXTENDED_SECONDS
            notes.append(f"Nuclei has up to {limit // 60} minutes per origin within the audit budget. "
                         "Low rates and network errors can leave coverage gaps.")
        if payload.nuclei_mode == "baseline":
            notes.append("Baseline uses four pinned templates for headers, CORS, Git exposure and nginx version.")
    if any(not stage["ready"] for stage in stages):
        notes.append("Unavailable adapters will be skipped. Install the pinned versions in Tool Manager for complete planned coverage.")
    if any(entry.kind == "all" and not entry.excluded for entry in rules):
        notes.append("This project has full access enabled. The audit still uses only the seed and explicitly opted-in child hosts.")
    plan = {
        "target": target, "profile": payload.profile,
        "config": {"seed_host": host, "root_domain": root, "expansion_limit": expansion,
                   "timeout_seconds": timeout_seconds,
                   "request": payload.model_dump(include=set(AuditPlanRequest.model_fields)),
                   "manual_checks": [{"id": key, "title": title, "description": description}
                                     for key, title, description in MANUAL_CHECKS] if payload.profile != "passive" else []},
        "stages": stages,
        "max_jobs": sum(stage["target_limit"] * (1 + stage.get("redirect_limit", 0)) for stage in stages),
        "notes": notes,
        "scope_snapshot": [{"kind": rule.kind, "value": rule.value, "excluded": rule.excluded} for rule in rules],
    }
    # A local adapter becoming ready does not change the targets or checks the operator reviewed.
    identity = {key: plan[key] for key in ("target", "profile", "config", "scope_snapshot")}
    identity["checks"] = [{key: stage.get(key) for key in ("id", "options", "target_limit", "version", "redirect_limit")}
                          for stage in stages]
    plan["plan_token"] = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    return plan
