"""Versioned, allow-listed tool adapters and their safe command builders."""
from dataclasses import dataclass
from typing import Any
import re
import shlex
from urllib.parse import urlsplit, urlunsplit

from .custom_commands import MAX_NMAP_MINUTES, build_custom_command, command_help, nmap_timeout_minutes, nmap_timing_args, validate_ports, validate_wordlist
from .scan_diagnostics import WEB_TOOLS, user_agent_args


@dataclass(frozen=True)
class ToolAdapter:
    id: str
    name: str
    category: str
    description: str
    binary: str
    module: str | None
    version: str
    source: str
    documentation: str
    import_format: str | None
    active: bool
    fields: tuple[dict[str, Any], ...]

    @property
    def timeout_seconds(self) -> int:
        return 900 if self.id == "nuclei" else 300

    @property
    def option_fields(self) -> tuple[dict[str, Any], ...]:
        if self.id not in WEB_TOOLS:
            return self.fields
        return (*self.fields, {"name": "rate", "label": "Requests per second",
                               "type": "number", "default": 5, "min": 1, "max": 5},
                {"name": "user_agent", "label": "User-Agent (optional)", "type": "text", "default": "",
                 "help": "Leave blank to use the tool's default HTTP behavior."})

    def request_rate(self, options: dict) -> int:
        value = options.get("rate", 5)
        if type(value) is not int or not 1 <= value <= 5:
            raise ValueError("Request rate must be a whole number from 1 to 5")
        return value

    def command(self, target: str, options: dict[str, Any] | None = None, output: str = "<output>") -> list[str]:
        options = options or {}
        nmap_minutes = nmap_timeout_minutes(options) if self.id == "nmap" else 5
        if custom := options.get("custom_command"):
            return build_custom_command(self.id, custom, target, output, nmap_minutes=nmap_minutes,
                                        user_agent=options.get("user_agent", "")).argv
        raw = safe_raw_arguments(self.id, str(options.get("raw_arguments", "")))
        rate = str(self.request_rate(options)) if self.id in WEB_TOOLS else "5"
        agent = user_agent_args(options.get("user_agent", "")) if self.id in WEB_TOOLS else []
        if self.id == "nmap":
            mode = options.get("mode", "services")
            if mode not in ("services", "discovery", "ports"):
                raise ValueError("Choose services, discovery or specific ports")
            ip_mode = ["-6"] if ":" in target else []
            base = [self.binary, *ip_mode, "--reason", *nmap_timing_args(nmap_minutes)]
            if mode == "discovery":
                if any(flag != "-n" for flag in raw):
                    raise ValueError("Service and port flags do not apply to host discovery")
                return [*base, "-T3", "--max-retries", "1", "-sn", *raw, "-oX", output, target]
            ports = str(options.get("ports", "")).strip()
            if mode == "ports" and not ports:
                raise ValueError("Enter at least one TCP port or range")
            if ports and "--top-ports" in raw:
                raise ValueError("Use either a port list or --top-ports")
            if not ports:
                return [*base, "-sT", "-sV", *raw, "-oX", output, target]
            validate_ports(ports)
            return [*base, "-T3", "--max-retries", "1", *([] if "/" in target else ["-Pn"]),
                    "-sT", "-sV", "-p", ports, *raw, "-oX", output, target]
        if self.id == "subfinder":
            return [self.binary, "-d", target, "-silent", "-rl", "5", "-timeout", "10", "-max-time", "5", "-o", output, *raw]
        if self.id == "dnsx":
            return [self.binary, "-l", target, "-a", "-aaaa", "-cname", "-resp", "-json", "-silent", "-rl", "5", *raw]
        if self.id == "httpx":
            return [self.binary, "-u", target, "-json", "-silent", "-nfs", "-status-code", "-rl", rate,
                    "-timeout", "10", "-retries", "1", *agent, *raw]
        if self.id == "amass":
            return [self.binary, "enum", "-d", target, "-rigid", "-nocolor", "-timeout", "1", *raw]
        if self.id == "nuclei":
            timeout = bounded_option(options, "request_timeout", 10, 2, 30)
            retries = bounded_option(options, "request_retries", 1, 0, 2)
            concurrency = bounded_option(options, "concurrency", int(rate), 1, 5)
            bounded_option(options, "timeout_minutes", 15, 5, 60)
            severities = options.get("severity", ["critical", "high", "medium"])
            allowed = {"info", "low", "medium", "high", "critical"}
            if not isinstance(severities, list) or not severities or any(
                not isinstance(severity, str) or severity not in allowed for severity in severities
            ):
                raise ValueError("Choose one or more supported severity levels")
            template_id = options.get("template_id", "")
            if not isinstance(template_id, str) or (template_id and not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", template_id)):
                raise ValueError("Template ID must contain only letters, digits, underscores or hyphens")
            ids = options.get("template_ids", [template_id] if template_id else [])
            if not isinstance(ids, list) or len(ids) > 24 or any(not isinstance(item, str) or
                    not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", item) for item in ids):
                raise ValueError("Invalid template ID list")
            template_filter = ["-id", ",".join(ids)] if ids else []
            excluded = ["dos", "fuzz", "intrusive"]
            tag_arguments = []
            for flag, value in zip(raw[::2], raw[1::2]):
                if flag == "-exclude-tags":
                    excluded.extend(value.split(","))
                else:
                    tag_arguments.extend([flag, value])
            return [self.binary, "-u", target, "-jle", output, "-t", "/opt/nuclei-templates/http",
                    "-duc", "-ni", "-dr", "-nc", "-sj", "-si", "5", "-pt", "http", "-etags", ",".join(dict.fromkeys(excluded)),
                    "-severity", ",".join(severities), "-rl", rate, "-c", str(concurrency),
                    "-timeout", str(timeout), "-retries", str(retries), "-or", *agent, *template_filter, *tag_arguments]
        if self.id == "katana":
            depth = int(options.get("depth", 2))
            if not 1 <= depth <= 5:
                raise ValueError("Crawl depth must be between 1 and 5")
            parsed = urlsplit(target if "://" in target else f"//{target}")
            if not parsed.hostname:
                raise ValueError("Katana requires a hostname target")
            scheme = parsed.scheme or "https"
            host_scope = re.escape(f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname)
            default_port = 443 if scheme == "https" else 80
            port_scope = f":{parsed.port}" if parsed.port and parsed.port != default_port else f"(?::{default_port})?"
            crawl_scope = f"^{scheme}://{host_scope}{port_scope}(?:[/?]|$)"
            return [self.binary, "-u", target, "-jsonl", "-silent", "-dr", "-depth", str(depth), "-crawl-scope", crawl_scope, "-rl", rate, "-timeout", "10", "-crawl-duration", "4m", "-or", "-ob", *agent, *raw]
        if self.id == "ffuf":
            wordlist = str(options.get("wordlist", ""))
            validate_wordlist(wordlist)
            if "FUZZ" in target:
                raise ValueError("Enter the base URL without a FUZZ placeholder")
            parts = urlsplit(target)
            url = urlunsplit((parts.scheme, parts.netloc, parts.path.rstrip("/") + "/FUZZ", parts.query, ""))
            return [self.binary, "-u", url, "-w", wordlist, "-json", "-s", "-rate", rate, "-maxtime", "300",
                    "-mc", "200-299,301,302,307,401,403,405,429,500,503", *agent, *raw]
        raise ValueError("This tool does not have an executable adapter")


def bounded_option(options: dict, name: str, default: int, minimum: int, maximum: int) -> int:
    value = options.get(name, default)
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name.replace('_', ' ').capitalize()} must be between {minimum} and {maximum}")
    return value


TOOLS: tuple[ToolAdapter, ...] = (
    ToolAdapter("nmap", "Nmap", "Network Discovery", "Discover reachable devices, TCP ports and service versions.", "nmap", None, "7.993", "https://nmap.org/", "https://nmap.org/book/man.html", "nmap_xml", True, (
        {"name":"mode","label":"Run mode","type":"choice","default":"services","options":{"services":"Common ports and service versions","discovery":"Find live devices (IP or CIDR)","ports":"Scan specific TCP ports"}},
        {"name":"ports","label":"TCP ports","type":"text","default":"","help":"Examples: 443, 80,443, 8000-8100"},
        {"name":"timeout_minutes","label":"Maximum run time (minutes)","type":"number","default":10,"min":1,"max":MAX_NMAP_MINUTES},
    )),
    ToolAdapter("subfinder", "Subfinder", "Reconnaissance & OSINT", "Passive subdomain discovery from configured public sources.", "subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder", "v2.17.0", "https://github.com/projectdiscovery/subfinder", "https://docs.projectdiscovery.io/tools/subfinder/overview", "subfinder", True, ()),
    ToolAdapter("dnsx", "DNSx", "DNS Enumeration", "Resolve A, AAAA, and CNAME records for an in-scope hostname.", "dnsx", "github.com/projectdiscovery/dnsx/cmd/dnsx", "v1.3.1", "https://github.com/projectdiscovery/dnsx", "https://docs.projectdiscovery.io/tools/dnsx/overview", "dnsx_jsonl", True, ()),
    ToolAdapter("httpx", "httpx", "HTTP Discovery", "Probe web services with conservative rate and timeout limits.", "httpx", "github.com/projectdiscovery/httpx/cmd/httpx", "v1.12.0", "https://github.com/projectdiscovery/httpx", "https://docs.projectdiscovery.io/tools/httpx/overview", "httpx_jsonl", True, ()),
    ToolAdapter("amass", "OWASP Amass", "Reconnaissance & OSINT", "Map subdomains and DNS observations for an authorized domain.", "amass", "github.com/owasp-amass/amass/v5/cmd/amass", "v5.1.3", "https://github.com/owasp-amass/amass", "https://owasp-amass.github.io/amass/", "amass_text", True, ()),
    ToolAdapter("nuclei", "Nuclei", "Vulnerability Assessment", "Run rate-limited vulnerability templates against an authorized web target.", "nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei", "v3.11.1", "https://github.com/projectdiscovery/nuclei", "https://docs.projectdiscovery.io/tools/nuclei/overview", "nuclei_jsonl", True, (
        {"name":"severity","label":"Severity levels","type":"multi-select","default":["critical","high","medium"],"options":["critical","high","medium","low","info"]},
        {"name":"template_id","label":"Exact template ID (optional)","type":"text","default":""},
        {"name":"request_timeout","label":"HTTP timeout (seconds)","type":"number","default":10,"min":2,"max":30},
        {"name":"request_retries","label":"Retries per request","type":"number","default":1,"min":0,"max":2},
        {"name":"concurrency","label":"Parallel templates","type":"number","default":2,"min":1,"max":5},
        {"name":"timeout_minutes","label":"Maximum run time (minutes)","type":"number","default":15,"min":5,"max":60},
    )),
    ToolAdapter("katana", "Katana", "Web Crawling", "Crawl in-scope web endpoints with bounded depth and request rate.", "katana", "github.com/projectdiscovery/katana/cmd/katana", "v1.8.0", "https://github.com/projectdiscovery/katana", "https://docs.projectdiscovery.io/tools/katana/overview", "katana_jsonl", True, ({"name":"depth","label":"Crawl depth","type":"number","min":1,"max":5,"default":2},)),
    ToolAdapter("ffuf", "FFUF", "Web Content Discovery", "Discover paths using an explicitly selected managed wordlist and low request rate.", "ffuf", "github.com/ffuf/ffuf/v2", "v2.3.0", "https://github.com/ffuf/ffuf", "https://github.com/ffuf/ffuf/wiki", "ffuf_jsonl", True, ({"name":"wordlist","label":"Managed wordlist","type":"wordlist","required":True},)),
)

TOOL_BY_ID = {tool.id: tool for tool in TOOLS}

# Upstream license references shown with each adapter so operators can review
# redistribution and deployment terms before enabling a tool in their scope.
TOOL_LICENSES = {
    "nmap": {"name": "Nmap Public Source License", "url": "https://nmap.org/npsl/"},
    "subfinder": {"name": "MIT", "url": "https://github.com/projectdiscovery/subfinder/blob/main/LICENSE.md"},
    "dnsx": {"name": "MIT", "url": "https://github.com/projectdiscovery/dnsx/blob/main/LICENSE.md"},
    "httpx": {"name": "MIT", "url": "https://github.com/projectdiscovery/httpx/blob/main/LICENSE.md"},
    "amass": {"name": "Apache-2.0", "url": "https://github.com/owasp-amass/amass/blob/master/LICENSE"},
    "nuclei": {"name": "MIT", "url": "https://github.com/projectdiscovery/nuclei/blob/dev/LICENSE.md"},
    "katana": {"name": "MIT", "url": "https://github.com/projectdiscovery/katana/blob/main/LICENSE.md"},
    "ffuf": {"name": "MIT", "url": "https://github.com/ffuf/ffuf/blob/master/LICENSE"},
}


def version_tuple(value: str) -> tuple[int, ...]:
    match = re.match(r"v?(\d+(?:\.\d+){1,3})", value.strip())
    return tuple(int(part) for part in match.group(1).split(".")) if match else ()


_RAW_FLAGS: dict[str, dict[str, bool]] = {
    "nmap": {"-sC": False, "-n": False, "--top-ports": True, "--version-light": False,
             "--version-intensity": True, "--max-rate": True},
    "subfinder": {"-all": False, "-recursive": False},
    "dnsx": {"-ns": False, "-txt": False, "-mx": False, "-srv": False},
    "httpx": {"-title": False, "-tech-detect": False, "-status-code": False, "-web-server": False},
    "amass": {"-passive": False},
    "nuclei": {"-tags": True, "-exclude-tags": True},
    "katana": {"-js-crawl": False, "-known-files": True, "-strategy": True},
    "ffuf": {"-mc": True, "-fc": True, "-ic": False},
}


def safe_raw_arguments(tool_id: str, value: str) -> list[str]:
    """Parse a deliberately small per-tool advanced flag allowlist; never pass arbitrary CLI input."""
    if not value.strip():
        return []
    if len(value) > 512:
        raise ValueError("Advanced arguments are limited to 512 characters")
    try:
        tokens = shlex.split(value, posix=True)
    except ValueError as exc:
        raise ValueError("Advanced arguments contain unmatched quotes") from exc
    if len(tokens) > 20:
        raise ValueError("At most 20 advanced argument tokens are allowed")
    allowed = _RAW_FLAGS.get(tool_id, {})
    result: list[str] = []
    index = 0
    while index < len(tokens):
        flag = tokens[index]
        takes_value = allowed.get(flag)
        if flag not in allowed:
            raise ValueError(f"Advanced flag is not allowed for {tool_id}: {flag}")
        result.append(flag)
        index += 1
        if takes_value:
            if index >= len(tokens) or tokens[index].startswith("-") or len(tokens[index]) > 128:
                raise ValueError(f"{flag} requires a bounded value")
            value = tokens[index]
            if flag == "--top-ports" and (not value.isdecimal() or not 1 <= int(value) <= 65535):
                raise ValueError("--top-ports accepts a number from 1 to 65535")
            if flag == "--version-intensity" and (not value.isdecimal() or not 0 <= int(value) <= 9):
                raise ValueError("--version-intensity accepts a number from 0 to 9")
            if flag == "--max-rate" and (not value.isdecimal() or not 1 <= int(value) <= 100):
                raise ValueError("--max-rate accepts a number from 1 to 100")
            if flag in {"-tags", "-exclude-tags"} and not re.fullmatch(r"[A-Za-z0-9_-]+(?:,[A-Za-z0-9_-]+)*", value):
                raise ValueError(f"{flag} accepts comma-separated tag names")
            if flag in {"-mc", "-fc"} and not re.fullmatch(r"[0-9,]{1,128}", value):
                raise ValueError(f"{flag} accepts comma-separated HTTP status codes only")
            if flag == "-strategy" and value not in {"depth-first", "breadth-first"}:
                raise ValueError("-strategy must be depth-first or breadth-first")
            if flag == "-known-files" and value not in {"all", "robotstxt", "sitemapxml"}:
                raise ValueError("-known-files must be all, robotstxt, or sitemapxml")
            result.append(tokens[index])
            index += 1
    return result


def public_tool(tool: ToolAdapter, installed_version: str | None = None, install_state: str = "not_installed") -> dict[str, Any]:
    current = (installed_version or "").lstrip("v")
    latest = tool.version.lstrip("v")
    status = "not_installed"
    if current:
        if current == latest:
            status = "installed"
        elif version_tuple(current) and version_tuple(latest) and version_tuple(current) > version_tuple(latest):
            status = "newer_than_pinned"
        else:
            status = "update_available"
    else:
        status = install_state
    return {
        "id": tool.id, "name": tool.name, "category": tool.category,
        "description": tool.description, "binary": tool.binary,
        "version": installed_version, "latest_version": tool.version,
        "status": status,
        "source": tool.source, "documentation": tool.documentation,
        "license": TOOL_LICENSES.get(tool.id, {"name": "Review upstream terms", "url": tool.source}),
        "installation_method": "official Nmap source release with SHA-256 verification" if tool.id == "nmap" else "pinned upstream Go module build" if tool.module else "application image",
        "capabilities": [tool.import_format] if tool.import_format else [],
        "parameters": list(tool.option_fields), "active_adapter": tool.active,
        "advanced_flags": list(_RAW_FLAGS.get(tool.id, {})),
        "custom_command": command_help(tool.id),
    }
