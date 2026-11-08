"""Server-side scope gate used both when queueing and immediately before execution."""
import ipaddress
import re
import socket
from urllib.parse import urlsplit, urlunsplit
from .models import ScopeEntry


def target_identity(raw: str) -> tuple[str, str]:
    raw = raw.strip()
    if not raw or any(ord(char) < 32 or ord(char) == 127 for char in raw) or "\\" in raw:
        raise ValueError("Target contains an invalid character")
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        pass
    else:
        if "%" in raw:
            raise ValueError("IPv6 zone identifiers are not supported")
        return ("ip", address.compressed)
    if "://" not in raw and "/" in raw:
        try:
            network = ipaddress.ip_network(raw, strict=False)
            return ("network", network.with_prefixlen)
        except ValueError:
            pass
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    if "://" in raw and parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP or HTTPS URLs are accepted as scan targets")
    host = parsed.hostname or ""
    if not host or parsed.username is not None or parsed.password is not None:
        raise ValueError("Enter one hostname, IP address, or an HTTP(S) URL without credentials")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL port must be between 1 and 65535") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("URL port must be between 1 and 65535")
    try:
        address = ipaddress.ip_address(host)
        if "%" in host:
            raise ValueError("IPv6 zone identifiers are not supported")
        return ("ip", address.compressed)
    except ValueError:
        pass
    try:
        domain = host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Target is not a valid hostname") from exc
    if len(domain) > 253 or not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", domain):
        raise ValueError("Target is not a valid hostname")
    if all(re.fullmatch(r"(?:[0-9]+|0x[0-9a-f]+)", label) for label in domain.split(".")):
        raise ValueError("Use a canonical IPv4 or IPv6 address")
    return ("domain", domain)


def normalize_web_target(raw: str) -> str:
    kind, host = target_identity(raw)
    if kind == "network":
        raise ValueError("A web scan requires a hostname, IP address, or HTTP(S) URL")
    raw = raw.strip()
    bare_ipv6 = kind == "ip" and ":" in host and not raw.startswith("[") and "://" not in raw
    parts = urlsplit(raw if "://" in raw else f"//[{host}]" if bare_ipv6 else f"//{raw}")
    scheme = parts.scheme.lower() or "https"
    port = parts.port
    authority = f"[{host}]" if ":" in host else host
    if port is not None and port != (443 if scheme == "https" else 80):
        authority += f":{port}"
    if any(char.isspace() for char in parts.path + parts.query):
        raise ValueError("Encode spaces in the target URL")
    return urlunsplit((scheme, authority, parts.path or "/", parts.query, ""))


def check_resolved_exclusions(raw: str, entries: list[ScopeEntry]) -> None:
    """Check configured IP exclusions against addresses resolved before a host scan."""
    kind, host = target_identity(raw)
    denied = [ipaddress.ip_network(entry.value, strict=False) for entry in entries
              if entry.excluded and entry.kind in {"cidr", "ip"}]
    if not denied or kind == "network":
        return
    if kind == "domain":
        try:
            addresses = {item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
        except OSError as exc:
            raise ValueError("Could not resolve the target to check its configured IP exclusions") from exc
    else:
        addresses = {host}
    for value in addresses:
        address = ipaddress.ip_address(value)
        mapped = getattr(address, "ipv4_mapped", None)
        if any(address in network or (mapped is not None and mapped in network) for network in denied):
            raise ValueError("Target resolves to an address excluded by the project scope")


def scope_matches(raw: str, entries: list[ScopeEntry], *, allow_network: bool = False) -> tuple[bool, str]:
    target_kind, target = target_identity(raw)
    excluded = [entry for entry in entries if entry.excluded]
    allowed = [entry for entry in entries if not entry.excluded]

    def matches(entry: ScopeEntry) -> bool:
        value = entry.value.lower()
        if entry.kind == "domain" and target_kind == "domain":
            if value.startswith("*."):
                suffix = value[2:]
                return target == suffix or target.endswith("." + suffix)
            return target == value
        if entry.kind == "ip" and target_kind == "ip":
            return target == value
        if entry.kind == "cidr":
            try:
                network = ipaddress.ip_network(value, strict=False)
                if target_kind == "ip":
                    return ipaddress.ip_address(target) in network
                if target_kind == "network":
                    requested = ipaddress.ip_network(target, strict=False)
                    return requested.version == network.version and requested.subnet_of(network)
            except ValueError:
                return False
        return False

    if any(matches(entry) for entry in excluded):
        return False, f"{target} is explicitly excluded from this project"
    if target_kind == "network":
        if not allow_network:
            return False, "Only Nmap supports CIDR network targets"
        network = ipaddress.ip_network(target)
        if network.num_addresses > 256:
            return False, "Network scans are capped at 256 addresses per job"
        if any(
            entry.kind in {"ip", "cidr"} and network.overlaps(ipaddress.ip_network(entry.value, strict=False))
            for entry in excluded
        ):
            return False, f"Network {target} overlaps an excluded project range"
    if not any(entry.kind == "all" or matches(entry) for entry in allowed):
        return False, f"{target} is not covered by an allowed project scope entry"
    if target_kind == "domain" and "." not in target:
        return False, "Single-label hostnames cannot be scanned"
    return True, target
