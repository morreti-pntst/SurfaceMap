"""Bounded scan logs and actionable diagnostics for web scan failures."""
import json
import re
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from http.client import HTTPConnection, HTTPException, HTTPSConnection
from pathlib import Path
from time import monotonic, sleep
from urllib.parse import urlsplit

WEB_TOOLS = {"nuclei", "httpx", "katana", "ffuf"}
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
TRANSIENT_WEB_CATEGORIES = {"connection", "dns", "tls", "upstream"}
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def user_agent_header(value: str) -> dict[str, str]:
    if not isinstance(value, str) or len(value) > 512 or any(not 32 <= ord(char) <= 126 for char in value):
        raise ValueError("User-Agent must contain up to 512 printable ASCII characters")
    return {"User-Agent": value.strip()} if value.strip() else {}


def user_agent_args(value: str) -> list[str]:
    return [arg for name, content in user_agent_header(value).items() for arg in ("-H", f"{name}: {content}")]


def tail(path: Path, size: int = 16384) -> str:
    try:
        with path.open("rb") as stream:
            length = stream.seek(0, 2)
            stream.seek(max(0, length - size))
            return ANSI_ESCAPE.sub("", stream.read(size).decode("utf-8", errors="replace"))
    except FileNotFoundError:
        return ""


def nuclei_progress(*logs: str) -> dict:
    for log in logs:
        for line in reversed(log.splitlines()):
            if not line.startswith("{"):
                continue
            try:
                stats = json.loads(line)
            except ValueError:
                continue
            if isinstance(stats, dict) and {"requests", "total", "errors"} <= stats.keys():
                keys = ("requests", "total", "errors", "matched", "percent", "rps", "duration", "templates")
                return {key: stats[key] for key in keys if key in stats and isinstance(stats[key], (str, int, float))}
    return {}


def nmap_progress(log: str) -> dict:
    for line in reversed(log.splitlines()):
        # A newer phase can start before its first percentage is available.
        if line.startswith("Initiating "):
            return {"phase": line.removeprefix("Initiating ").split(" at ", 1)[0]}
        match = re.fullmatch(
            r"([\w -]+) Timing: About (\d{1,3}(?:\.\d+)?)% done"
            r"(?:; ETC: \S+ \((\d+):(\d{2}):(\d{2}) remaining\))?",
            line.strip(),
        )
        if match:
            phase, percent, hours, minutes, seconds = match.groups()
            progress = {"phase": phase, "phase_percent": min(float(percent), 100)}
            if hours is not None:
                progress["phase_remaining_seconds"] = int(hours) * 3600 + int(minutes) * 60 + int(seconds)
            return progress
    return {}


def nuclei_coverage_gap(stats: dict) -> str | None:
    try:
        requests, total, errors = (int(stats[key]) for key in ("requests", "total", "errors"))
    except (KeyError, TypeError, ValueError):
        return "Nuclei did not report final request counts."
    if total <= 0 or requests <= 0:
        return "Nuclei did not report any executed requests."
    if errors or requests < total:
        return f"Nuclei reported {requests}/{total} requests and {errors} errors. Review the console for incomplete coverage."
    return None


def nuclei_stopped_for_network_errors(diagnostics: str) -> bool:
    return bool(re.search(r"(?im)^\[INF\] Skipped .+ as found unresponsive permanently:", diagnostics))


class ScanBlocked(RuntimeError):
    def __init__(self, message: str, *, category: str = "access", status: int | None = None):
        super().__init__(message)
        self.category = category
        self.status = status

    @classmethod
    def from_scanner(cls, message: str) -> "ScanBlocked":
        match = re.match(r"HTTP (\d{3}):", message)
        status = int(match[1]) if match else None
        category = "rate_limit" if status == 429 else "upstream" if status in {502, 503, 504} else "access"
        return cls(message, category=category, status=status)


@dataclass(frozen=True)
class WebProbe:
    status: int
    posture: dict
    location: str
    address: str = ""


def response_posture(target: str, headers) -> dict:
    """Keep only attributes needed for review. Header and cookie values stay out of evidence."""
    relevant = (
        "content-security-policy", "content-security-policy-report-only", "x-frame-options",
        "x-content-type-options", "referrer-policy", "permissions-policy",
    )
    present = {key: bool(headers.get(key)) for key in relevant}
    if urlsplit(target).scheme == "https":
        present["strict-transport-security"] = bool(headers.get("strict-transport-security"))
    cookies = headers.get_all("Set-Cookie", [])[:64]
    cookie_flags = [{part.strip().lower().partition("=")[0] for part in value.split(";")[1:]}
                    for value in cookies]
    return {
        "headers_present": present,
        "cors_wildcard": headers.get("Access-Control-Allow-Origin", "").strip() == "*",
        "cors_credentials": headers.get("Access-Control-Allow-Credentials", "").strip().lower() == "true",
        "cookies": {"observed": len(cookie_flags), **{
            flag: sum(flag in attributes for attributes in cookie_flags)
            for flag in ("secure", "httponly", "samesite")
        }},
    }


def response_problem(code: int, headers) -> str | None:
    if code == 429:
        delay = headers.get("Retry-After")
        wait = f" Honor Retry-After ({delay[:80]})." if delay else ""
        return ("HTTP 429: the endpoint is rate limiting requests." + wait +
                " Wait for the limit to reset, narrow the scan, or agree on a scan window and rate with the owner.")
    if headers.get("cf-mitigated", "").lower() == "challenge" or headers.get("x-sucuri-block"):
        return ("The endpoint returned a web protection challenge. Ask the owner to review WAF events "
                "and approve the scanner's egress IP or a dedicated test endpoint.")
    if code in {401, 403, 407, 451}:
        return (f"HTTP {code}: the endpoint refused the initial request. Check the URL and access requirements, "
                "then ask the owner to verify authentication, proxy policy or WAF logs for the scanner IP.")
    if code in {502, 503, 504}:
        return (f"HTTP {code}: the gateway or upstream service is unavailable. Verify service health, "
                "gateway routing and any maintenance window before retrying.")
    return None


def web_preflight(target: str, event: Callable[[str], None] | None = None, *,
                  preferred_address: str = "", user_agent: str = "") -> WebProbe:
    """Try resolved addresses within a bounded budget while retaining Host and TLS SNI."""
    parts = urlsplit(target)
    host = parts.hostname or ""
    secure = parts.scheme == "https"
    port = parts.port or (443 if secure else 80)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    for attempt in range(2):
        try:
            addresses = list(dict.fromkeys((family, address) for family, _, _, _, address in
                                           socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))[:6]
            break
        except socket.gaierror as exc:
            if attempt == 0 and not preferred_address and exc.errno == socket.EAI_AGAIN:
                sleep(0.5)
                continue
            raise ScanBlocked(f"DNS failed for {host}: {exc}. Check name resolution in Docker and the active VPN.", category="dns") from exc
    if event:
        event(f"DNS {host}: " + ", ".join(address[0] for _, address in addresses))
    if preferred_address:
        # A live check samples the address that already worked before the scan.
        addresses.sort(key=lambda item: item[1][0] != preferred_address)
    attempts = addresses[:1] if preferred_address else [*addresses, *addresses[:1]]
    deadline = monotonic() + (5 if preferred_address else 14)
    failures = []
    certificate_failure = None
    tls_failure = None
    context = ssl.create_default_context() if secure else None
    for family, address in attempts:
        remaining = deadline - monotonic()
        if remaining <= 0:
            break
        ip = address[0]
        connection = HTTPSConnection(host, port, context=context) if secure else HTTPConnection(host, port)
        phase = "connect"
        try:
            with socket.socket(family, socket.SOCK_STREAM) as transport:
                transport.settimeout(min(2.5, remaining))
                transport.connect(address)
                phase = "TLS handshake" if context else "HTTP response"
                transport.settimeout(max(0.05, min(4, deadline - monotonic())))
                connection.sock = context.wrap_socket(transport, server_hostname=host) if context else transport
                phase = "HTTP response"
                connection.sock.settimeout(max(0.05, min(5, deadline - monotonic())))
                connection.request("GET", path, headers={"Connection": "close", **user_agent_header(user_agent)})
                with connection.getresponse() as response:
                    code, headers = response.status, response.headers
        except ssl.SSLCertVerificationError as exc:
            if "mismatch" in exc.verify_message.lower():
                advice = f"Configure the HTTPS listener to present a certificate whose subject alternative names include {host}."
            else:
                advice = "Check the certificate expiry and the served chain. For a private CA, configure the worker's trust store."
            certificate_failure = certificate_failure or ScanBlocked(
                f"TLS certificate verification failed for {host} at {ip}: {exc.verify_message}. {advice}", category="certificate")
            continue
        except ssl.SSLError as exc:
            tls_failure = tls_failure or ScanBlocked(
                f"TLS handshake failed for {host} at {ip}: {exc}. Check the HTTPS listener and worker network path.", category="tls")
            continue
        except (OSError, HTTPException) as exc:
            detail = f"{'IPv6' if family == socket.AF_INET6 else 'IPv4'} {ip} ({phase}): {exc}"
            if detail not in failures:
                failures.append(detail)
                if event:
                    event(detail)
            continue
        finally:
            connection.close()
        if event:
            event(f"HTTP {code} received via {ip} on port {port}.")
        if problem := response_problem(code, headers):
            category = "rate_limit" if code == 429 else "upstream" if code in {502, 503, 504} else "access"
            raise ScanBlocked(problem, category=category, status=code)
        return WebProbe(code, response_posture(target, headers), headers.get("Location", "")[:2048], ip)
    if certificate_failure:
        raise certificate_failure
    if tls_failure:
        raise tls_failure
    advice = ("TCP connected but the TLS handshake timed out. Compare HTTPS from the host and the Docker worker "
              "and check the target listener, firewall and VPN route."
              if any("(TLS handshake)" in item and "timed out" in item for item in failures)
              else "Check the worker route, VPN and service port.")
    raise ScanBlocked(f"Could not reach {host}:{port} from Docker. {' | '.join(failures)}. {advice}",
                      category="connection")


def live_web_problem(tool_id: str, diagnostics: str, output: str) -> str | None:
    # A per-path 403/404 is common during discovery. A recorded 429 is a
    # request to slow down, even if the rest of the scan has matches.
    if re.search(r"\b(?:HTTP/\d(?:\.\d)?\s+429|429 Too Many Requests)\b", diagnostics, re.I):
        return response_problem(429, {})
    if re.search(r"(?im)^\s*(?:cf-mitigated:\s*challenge|x-sucuri-block:\s*\S+)", diagnostics):
        return "A web protection challenge was observed. Review WAF events with the site owner before retrying."
    if tool_id not in {"httpx", "katana", "ffuf"}:
        return None
    for line in output.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue
        response = row.get("response")
        code = response.get("status_code") if isinstance(response, dict) else row.get("status_code", row.get("status"))
        if isinstance(response, dict) and isinstance(response.get("headers"), dict):
            headers = {key.lower().replace("_", "-"): str(value) for key, value in response["headers"].items()}
            if problem := response_problem(200, headers):
                return problem
        if code in (429, "429"):
            return response_problem(429, {})
        if tool_id == "httpx" and isinstance(code, int) and (problem := response_problem(code, {})):
            return problem
    return None
