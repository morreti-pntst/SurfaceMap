"""Version-pinned grammar for operator-authored scanner invocations."""
import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from .scan_diagnostics import WEB_TOOLS, user_agent_args
from .scope_guard import normalize_web_target, target_identity

WORDLIST_ROOT = Path(os.getenv("SURFACEMAP_WORDLISTS_DIR", "/data/wordlists")).resolve()
BUILTIN_WORDLIST = Path(__file__).resolve().with_name("public-web-paths.txt")
MAX_NMAP_MINUTES = 60


def nmap_timeout_minutes(options: dict) -> int:
    minutes = options.get("timeout_minutes", 5)
    if type(minutes) is not int or not 1 <= minutes <= MAX_NMAP_MINUTES:
        raise ValueError(f"Nmap time limit must be a whole number from 1 to {MAX_NMAP_MINUTES} minutes.")
    return minutes


def nmap_timing_args(minutes: int) -> list[str]:
    # Leave time for Nmap to finish writing XML before the worker's deadline.
    return ["--host-timeout", f"{minutes * 60 - 8}s", "--stats-every", "15s"]

# Entries use the adapter's canonical spelling followed by accepted aliases.
TARGET_FLAGS = {
    "subfinder": "-d -domain", "dnsx": "-l -list", "httpx": "-u -target",
    "amass": "-d", "nuclei": "-u -target", "katana": "-u -list", "ffuf": "-u",
}
RATES = (1, 5)
TIMEOUT = (1, 15)
OPTIONS = {
    "nmap": {
        "-sT": None, "-sV": None, "-sn": None, "-Pn": None, "-n": None, "--reason": None,
        "-v": None, "-vv": None, "-F": None, "-p": "ports", "-T": (0, 4),
        "--top-ports": (1, 65535), "--max-rate": (1, 100), "--max-retries": (0, 2),
        "--version-light": None, "--version-intensity": (0, 9),
    },
    "subfinder": {
        "-all": None, "-recursive": None, "-stats": None, "-s -sources": "names",
        "-es -exclude-sources": "names", "-rl -rate-limit": RATES,
        "-timeout": (1, 30), "-max-time": (1, 5),
    },
    "dnsx": {
        **{flag: None for flag in ("-a", "-aaaa", "-cname", "-ns", "-mx", "-txt", "-srv", "-soa", "-caa")},
        "-rl -rate-limit": RATES, "-retry": (1, 2),
    },
    "httpx": {
        "-title": None, "-tech-detect -td": None, "-web-server -server": None,
        "-status-code -sc": None, "-content-type -ct": None, "-content-length -cl": None,
        "-location": None, "-ip": None, "-cname": None, "-tls-grab": None,
        "-rl -rate-limit": RATES, "-timeout": TIMEOUT, "-retries": (0, 1),
    },
    "amass": {"-passive": None, "-timeout": (1, 4)},
    "nuclei": {
        "-id -template-id": "names", "-tags": "names", "-etags -exclude-tags": "names",
        "-severity -s": "severity", "-rl -rate-limit": RATES, "-c -concurrency": RATES,
        "-bs -bulk-size": RATES, "-timeout": TIMEOUT, "-retries": (0, 1), "-stats": None,
    },
    "katana": {
        "-depth -d": (1, 5), "-js-crawl -jc": None, "-known-files -kf": "known-files",
        "-strategy -s": "strategy", "-rl -rate-limit": RATES, "-timeout": TIMEOUT,
        "-retry": (0, 1), "-c -concurrency": RATES,
    },
    "ffuf": {
        "-w": "wordlist", "-mc": "status", "-fc": "status", "-ic": None, "-ac": None,
        "-rate": RATES, "-timeout": TIMEOUT, "-t": RATES,
    },
}
EXAMPLES = {
    "nmap": "-sV example.com",
    "subfinder": "-d example.com -recursive -timeout 10",
    "dnsx": "-l example.com -a -aaaa -mx -txt",
    "httpx": "-u https://example.com/ -title -tech-detect -web-server -rl 2",
    "amass": "enum -d example.com -passive -timeout 1",
    "nuclei": "-u https://example.com/ -id nginx-version -severity info -rl 2",
    "katana": "-u https://example.com/ -d 3 -jc -rl 2",
    "ffuf": "-u https://example.com/FUZZ -w /data/wordlists/paths.txt -mc 200,301,403 -rate 2",
}
SEVERITIES = {"info", "low", "medium", "high", "critical"}


@dataclass(frozen=True)
class Command:
    target: str
    argv: list[str]
    rate: int | None


def command_help(tool_id: str) -> dict:
    return {"example": EXAMPLES[tool_id],
            "flags": [*TARGET_FLAGS.get(tool_id, "").split(), *OPTIONS[tool_id]],
            "documentation_note": "SurfaceMap supplies structured output, limits and scoped execution."}


def validate_wordlist(value: str) -> None:
    path = Path(value)
    if path == BUILTIN_WORDLIST and path.is_file():
        return
    if (not path.is_absolute() or path.parent != WORDLIST_ROOT or path.suffix.lower() not in {".txt", ".list"}
            or path.is_symlink() or not path.is_file()):
        raise ValueError("Use -w with a wordlist uploaded in Scan Jobs")


def validate_ports(value: str) -> None:
    if not re.fullmatch(r"\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*", value):
        raise ValueError("-p expects TCP port numbers or ranges, such as 80,443,8000-8100")
    for part in value.split(","):
        ends = [int(item) for item in part.split("-")]
        if not 1 <= ends[0] <= ends[-1] <= 65535:
            raise ValueError("Port ranges must be ascending and between 1 and 65535")


def _value(flag: str, kind, value: str) -> None:
    if isinstance(kind, tuple):
        low, high = kind
        if not re.fullmatch(r"\d{1,6}", value) or not low <= int(value) <= high:
            raise ValueError(f"{flag} expects a whole number from {low} to {high}")
    elif kind == "ports":
        validate_ports(value)
    elif kind == "wordlist":
        validate_wordlist(value)
    elif kind == "names":
        if not re.fullmatch(r"[A-Za-z0-9_-]+(?:,[A-Za-z0-9_-]+)*", value) or len(value.split(",")) > 24:
            raise ValueError(f"{flag} expects a comma-separated list of up to 24 names")
    elif kind == "severity":
        if not set(value.split(",")) <= SEVERITIES:
            raise ValueError(f"{flag} expects info, low, medium, high or critical")
    elif kind == "status":
        if flag == "-mc" and value == "all":
            return
        if not re.fullmatch(r"[1-5]\d\d(?:-[1-5]\d\d)?(?:,[1-5]\d\d(?:-[1-5]\d\d)?)*", value):
            raise ValueError(f"{flag} expects HTTP status codes or ranges, such as 200-299,403")
        if any(part[:3] > part[-3:] for part in value.split(",")):
            raise ValueError(f"{flag} status ranges must be ascending")
    elif kind == "known-files" and value not in {"all", "robotstxt", "sitemapxml"}:
        raise ValueError("-known-files expects all, robotstxt or sitemapxml")
    elif kind == "strategy" and value not in {"depth-first", "breadth-first"}:
        raise ValueError("-strategy expects depth-first or breadth-first")


def _target(tool_id: str, value: str) -> tuple[str, str]:
    if len(value) > 1024 or "," in value and tool_id != "nmap":
        raise ValueError("Enter one target (a single URL, host or supported CIDR)")
    if tool_id in WEB_TOOLS:
        url = normalize_web_target(value)
        if tool_id == "ffuf":
            parts = urlsplit(url)
            if "FUZZ" in parts.netloc.upper():
                raise ValueError("Place FUZZ in a path or query on the fixed host")
            if "FUZZ" in parts.path or "FUZZ" in parts.query:
                path = parts.path.partition("FUZZ")[0] or "/"
                return urlunsplit((parts.scheme, parts.netloc, path, "", "")), url
            return url, urlunsplit((parts.scheme, parts.netloc, parts.path.rstrip("/") + "/FUZZ", parts.query, ""))
        return url, url
    kind, host = target_identity(value)
    if kind == "network" and tool_id != "nmap":
        raise ValueError("Only Nmap accepts a CIDR target")
    if tool_id in {"amass", "subfinder"} and kind != "domain":
        raise ValueError("This adapter requires a DNS domain")
    return host, host


def build_custom_command(tool_id: str, text: str, fallback_target: str, output: str, *,
                         nmap_minutes: int = 5, user_agent: str = "") -> Command:
    if tool_id not in OPTIONS:
        raise ValueError("Custom commands are unavailable for this adapter")
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError as exc:
        raise ValueError("Close the quoted argument before previewing") from exc
    if not tokens or len(text) > 2048 or len(tokens) > 64:
        raise ValueError("Enter up to 64 command arguments")
    if tokens[0].lower() in {tool_id, f"{tool_id}.exe"}:
        raise ValueError(f"Enter the arguments after {tool_id}")
    if tool_id == "amass" and tokens[0] == "enum":
        tokens = tokens[1:]
    spec = {alias: (names.split()[0], kind) for names, kind in OPTIONS[tool_id].items() for alias in names.split()}
    spec.update({flag: ("target", "target") for flag in TARGET_FLAGS.get(tool_id, "").split()})
    values: dict[str, str | None] = {}
    position = 0
    while position < len(tokens):
        token = tokens[position]
        position += 1
        if not token.startswith("-"):
            if tool_id != "nmap" or "target" in values:
                raise ValueError(f"Unexpected argument {token!r}; use one target with its documented flag")
            values["target"] = token
            continue
        flag, equal, value = token.partition("=")
        if tool_id == "nmap" and re.fullmatch(r"-(?:p[\d,-]+|T[0-4])", flag):
            flag, equal, value = flag[:2], "=", flag[2:]
        if flag not in spec:
            raise ValueError(f"{flag} is not supported for {tool_id}. See Supported flags in the command editor.")
        key, kind = spec[flag]
        if key in values:
            raise ValueError(f"{flag} appears more than once")
        if kind is None:
            if equal:
                raise ValueError(f"{flag} takes no value")
            values[key] = None
            continue
        if not equal:
            if position >= len(tokens) or tokens[position].startswith("-"):
                raise ValueError(f"{flag} requires a value")
            value = tokens[position]
            position += 1
        if not value or len(value) > 1024 or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError(f"Invalid value for {flag}")
        _value(flag, kind, value)
        values[key] = value

    requested = values.pop("target", None)
    target, scan_target = _target(tool_id, requested or fallback_target)
    if requested and fallback_target and _target(tool_id, fallback_target)[0] != target:
        raise ValueError("The command target differs from the target field. Use one target.")
    rate_key = "-rate" if tool_id == "ffuf" else "-rl"
    rate = (values.get(rate_key) or "3") if tool_id != "nmap" and tool_id != "amass" else None
    agent = user_agent_args(user_agent) if tool_id in WEB_TOOLS else []
    if tool_id == "nmap":
        if len({"-F", "-p", "--top-ports"} & values.keys()) > 1:
            raise ValueError("Choose one port selector: -p, -F, or --top-ports")
        discovery = "-sn" in values
        if discovery and {"-sV", "-sT", "-Pn", "-F", "-p", "--top-ports", "--version-light", "--version-intensity"} & values.keys():
            raise ValueError("-sn discovers hosts and cannot be combined with port scanning or -Pn")
        if "-sV" not in values and {"--version-light", "--version-intensity"} & values.keys():
            raise ValueError("Version options require -sV")
        if "--version-light" in values and "--version-intensity" in values:
            raise ValueError("Choose one version intensity setting")
        base = [*(["-6"] if ":" in target else []), *nmap_timing_args(nmap_minutes), "-oX", output]
        if not discovery:
            values.setdefault("-sT", None)
        values.setdefault("--reason", None)
        values.setdefault("--max-retries", "1")
        values.setdefault("-T", "3")
        end = [scan_target]
    elif tool_id == "subfinder":
        base = ["-d", scan_target, "-silent", "-o", output]
        values.setdefault("-max-time", "5")
        values.setdefault("-timeout", "10")
        end = []
    elif tool_id == "dnsx":
        base = ["-l", scan_target, "-resp", "-json", "-silent", "-or"]
        if not set(values) & {"-a", "-aaaa", "-cname", "-ns", "-mx", "-txt", "-srv", "-soa", "-caa"}:
            values.update({"-a": None, "-aaaa": None, "-cname": None})
        end = []
    elif tool_id == "httpx":
        base = ["-u", scan_target, "-json", "-silent", "-nfs", *agent]
        values.setdefault("-status-code", None)
        values.setdefault("-timeout", "10")
        values.setdefault("-retries", "1")
        end = []
    elif tool_id == "amass":
        base = ["enum", "-d", scan_target, "-rigid", "-nocolor"]
        values.setdefault("-timeout", "1")
        end = []
    elif tool_id == "nuclei":
        exclusions = str(values.pop("-etags", "")).split(",")
        tags = ",".join(dict.fromkeys(["dos", "fuzz", "intrusive", *(tag for tag in exclusions if tag)]))
        base = ["-u", scan_target, "-jle", output, "-t", "/opt/nuclei-templates/http",
                "-duc", "-ni", "-dr", "-nc", "-sj", "-si", "5", "-pt", "http", "-etags", tags, "-or", *agent]
        if "-id" not in values:
            values.setdefault("-severity", "critical,high,medium")
        values.setdefault("-c", rate)
        values.setdefault("-timeout", "10")
        values.setdefault("-retries", "1")
        values.pop("-stats", None)
        end = []
    elif tool_id == "katana":
        values.setdefault("-depth", "2")
        if "-known-files" in values and int(values["-depth"]) < 3:
            raise ValueError("-known-files requires a crawl depth of at least 3")
        parts = urlsplit(scan_target)
        default_port = 443 if parts.scheme == "https" else 80
        host = f"[{parts.hostname}]" if ":" in (parts.hostname or "") else parts.hostname
        port = f":{parts.port}" if parts.port else f"(?::{default_port})?"
        scope = f"^{parts.scheme}://{re.escape(host)}{port}(?:[/?]|$)"
        base = ["-u", scan_target, "-jsonl", "-silent", "-dr", "-crawl-scope", scope,
                "-crawl-duration", "4m", "-or", "-ob", *agent]
        values.setdefault("-c", rate)
        values.setdefault("-timeout", "10")
        end = []
    else:
        if "-w" not in values:
            raise ValueError("FFUF requires -w with a managed wordlist")
        base = ["-u", scan_target, "-json", "-s", "-maxtime", "300", *agent]
        values.setdefault("-mc", "200-299,301,302,307,401,403,405,429,500,503")
        values.setdefault("-t", rate)
        end = []
    if rate is not None:
        values.setdefault(rate_key, rate)
    argv = [tool_id, *base]
    for flag, value in values.items():
        argv.append(flag)
        if value is not None:
            argv.append(value)
    return Command(target, [*argv, *end], int(rate) if rate else None)
