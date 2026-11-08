import hashlib
import ipaddress
import json
import re
import csv
import io
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from defusedxml import ElementTree as SafeET
from .scope_guard import normalize_web_target

SUPPORTED_FORMATS = {"nmap_xml", "subfinder", "amass_jsonl", "amass_text", "dnsx_jsonl", "httpx_jsonl", "nuclei_jsonl", "katana_jsonl", "ffuf_json", "ffuf_jsonl", "generic_csv", "generic_json", "generic_xml"}
SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}
RELATIONSHIP_TYPES = {"resolves_to", "exposes", "related_to", "hosts", "serves", "redirects_to", "depends_on"}

@dataclass
class ParsedRecord:
    asset_type: str
    asset_value: str
    kind: str
    data: dict[str, Any]
    finding: dict[str, Any] | None = None
    related_assets: list[str | tuple[str, str] | tuple[str, str, str]] = field(default_factory=list)

@dataclass
class ParseResult:
    records: list[ParsedRecord] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

def _asset(value: str) -> tuple[str, str] | None:
    if not isinstance(value, str):
        return None
    value = value.strip().rstrip(".")
    if not value or len(value) > 1024 or any(c.isspace() for c in value):
        return None
    try:
        address = ipaddress.ip_address(value.strip("[]"))
        return ("ipv4" if address.version == 4 else "ipv6", address.compressed)
    except ValueError:
        pass
    try:
        domain = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", domain):
        return None
    return "domain", domain

def _record(value: str, kind: str, data: dict[str, Any], finding: dict[str, Any] | None = None,
            related_assets: list[str | tuple[str, str] | tuple[str, str, str]] | None = None) -> ParsedRecord | None:
    identity = _asset(value)
    if identity is None:
        return None
    return ParsedRecord(identity[0], identity[1], kind, data, finding, related_assets or [])


def web_identity(value: Any) -> tuple[str, str, tuple[str, str]] | None:
    """Return origin, endpoint shape (without parameter values), and host identity."""
    if not isinstance(value, str) or not re.match(r"^https?://", value, re.I) or len(value) > 4096:
        return None
    try:
        parts = urlsplit(normalize_web_target(value))
        query_keys = sorted({key for key, _ in parse_qsl(parts.query, keep_blank_values=True, max_num_fields=64)})
    except ValueError:
        return None
    origin = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
    endpoint = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode([(key, "") for key in query_keys]), ""))
    host = _asset(parts.hostname or "")
    if not host or len(endpoint) > 1024:
        return None
    return origin, endpoint, host


def related_identity(item: str | tuple[str, str] | tuple[str, str, str]) -> tuple[str, str, str] | None:
    if isinstance(item, str):
        asset_type, value, relationship = "", item, "resolves_to"
    else:
        asset_type, value = item[:2]
        relationship = item[2] if len(item) == 3 else "resolves_to"
    if asset_type in {"web_origin", "endpoint"}:
        web = web_identity(value)
        asset = (asset_type, web[0 if asset_type == "web_origin" else 1]) if web else None
    else:
        asset = _asset(value)
    return (*asset, relationship) if asset else None


def _web_record(value: Any, kind: str, data: dict, *, endpoint: bool = False,
                addresses: list[str] | None = None) -> ParsedRecord | None:
    identity = web_identity(value)
    if not identity:
        return None
    origin, route, host = identity
    relations = [("web_origin", origin, "contains_endpoint")] if endpoint else [(*host, "serves_web")]
    return ParsedRecord(
        "endpoint" if endpoint else "web_origin", route if endpoint else origin, kind,
        {**data, "url": route}, related_assets=[*relations, *(addresses or [])],
    )


def _strings(value: Any, maximum: int = 64) -> list[str]:
    values = [value] if isinstance(value, str) else value if isinstance(value, list) else []
    return [item[:2048] for item in values[:maximum] if isinstance(item, str)]

def _json_lines(content: str, result: ParseResult) -> list[dict[str, Any]]:
    stripped = content.strip()
    if stripped.startswith(("[", "{")):
        try:
            document = json.loads(stripped)
            if isinstance(document, dict):
                return [document]
            if isinstance(document, list):
                return [item for item in document if isinstance(item, dict)]
        except json.JSONDecodeError:
            pass  # Continue with JSONL parsing for newline-delimited objects.
    rows = []
    for number, line in enumerate(content.splitlines(), 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
            if not isinstance(item, dict):
                raise ValueError("record must be a JSON object")
            rows.append(item)
        except (json.JSONDecodeError, ValueError) as exc:
            result.warnings.append(f"Line {number}: invalid JSON record ({exc})")
    return rows

def parse_import(file_format: str, content: str) -> ParseResult:
    if file_format not in SUPPORTED_FORMATS:
        raise ValueError(f"Unsupported format: {file_format}")
    result = ParseResult()
    if file_format == "generic_csv":
        try:
            reader = csv.DictReader(io.StringIO(content, newline=""))
            columns = {str(name or "").strip().lower() for name in (reader.fieldnames or [])}
            if not columns.intersection({"asset", "value", "host", "hostname", "domain", "ip"}):
                raise ValueError("CSV must include an asset, value, host, hostname, domain, or ip column")
            for number, item in enumerate(reader, 2):
                if number > 100001:
                    result.warnings.append("CSV was capped at 100,000 rows")
                    break
                lowered = {key.strip().lower(): (value or "").strip()
                           for key, value in item.items() if key is not None and isinstance(value, (str, type(None)))}
                value = next((lowered.get(key, "") for key in ("asset", "value", "host", "hostname", "domain", "ip") if lowered.get(key)), "")
                identity = _asset(value)
                if not identity:
                    result.warnings.append(f"Row {number}: ignored invalid asset")
                    continue
                declared_type = lowered.get("type") or lowered.get("asset_type") or identity[0]
                if declared_type not in {"domain", "ipv4", "ipv6", "service"}:
                    declared_type = identity[0]
                data = {key[:64]: str(val)[:2048] for key, val in lowered.items() if key and val and key not in {"asset", "value", "host", "hostname", "domain", "ip", "related_asset", "relationship", "relationship_type"}}
                relation = lowered.get("related_asset", "")
                related_identity = _asset(relation) if relation else None
                relation_type = lowered.get("relationship_type") or lowered.get("relationship") or "resolves_to"
                if relation_type not in RELATIONSHIP_TYPES:
                    result.warnings.append(f"Row {number}: unsupported relationship type was changed to related_to")
                    relation_type = "related_to"
                related = [(related_identity[0], relation, relation_type)] if related_identity else []
                record = _record(value, "generic_csv", data, related_assets=related)
                if record:
                    record.asset_type = declared_type
                    result.records.append(record)
        except csv.Error as exc:
            raise ValueError(f"Invalid CSV: {exc}") from exc
        return result
    if file_format == "generic_json":
        try:
            document = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid generic JSON: {exc}") from exc
        rows = document if isinstance(document, list) else document.get("assets", []) if isinstance(document, dict) else []
        if not isinstance(rows, list):
            raise ValueError("Generic JSON must be an array or an object with an assets array")
        for number, item in enumerate(rows[:100000], 1):
            if not isinstance(item, dict):
                result.warnings.append(f"Row {number}: expected an object")
                continue
            value = next((item.get(key) for key in ("asset", "value", "host", "hostname", "domain", "ip") if item.get(key)), None)
            if not value:
                result.warnings.append(f"Row {number}: missing asset identity")
                continue
            raw_related = item.get("related_assets", item.get("related_asset", []))
            if isinstance(raw_related, str):
                raw_related = [raw_related]
            related = [str(value) for value in raw_related[:100] if isinstance(value, (str, int))] if isinstance(raw_related, list) else []
            data = {str(key)[:64]: value for key, value in item.items() if key not in {"asset", "value", "host", "hostname", "domain", "ip", "related_assets", "related_asset"}}
            record = _record(str(value), "generic_json", data, related_assets=related)
            if record:
                result.records.append(record)
        if len(rows) > 100000:
            result.warnings.append("JSON import was capped at 100,000 rows")
        return result
    if file_format == "generic_xml":
        try:
            root = SafeET.fromstring(content)
        except Exception as exc:
            raise ValueError(f"Invalid generic XML: {exc}") from exc
        for number, element in enumerate(root.iter(), 1):
            if number > 100000:
                result.warnings.append("XML import was capped at 100,000 elements")
                break
            attributes = {key.rsplit("}", 1)[-1].lower(): value for key, value in element.attrib.items()}
            value = next((attributes.get(key) for key in ("asset", "value", "host", "hostname", "domain", "ip") if attributes.get(key)), None)
            if value is None and element.tag.rsplit("}", 1)[-1].lower() in {"asset", "host", "hostname", "domain", "ip"}:
                value = (element.text or "").strip()
            if not value:
                continue
            identity = _asset(str(value))
            if not identity:
                result.warnings.append(f"Element {number}: ignored invalid asset")
                continue
            data = {key: val[:2048] for key, val in attributes.items() if key not in {"asset", "value", "host", "hostname", "domain", "ip"}}
            related_value = attributes.get("related_asset", "")
            related_identity = _asset(related_value) if related_value else None
            relation_type = attributes.get("relationship_type", "resolves_to")
            if relation_type not in RELATIONSHIP_TYPES:
                result.warnings.append(f"Element {number}: unsupported relationship type was changed to related_to")
                relation_type = "related_to"
            related = [(related_identity[0], related_value, relation_type)] if related_identity else []
            result.records.append(ParsedRecord(identity[0], identity[1], "generic_xml", data, related_assets=related))
        return result
    if file_format == "nmap_xml":
        try:
            root = SafeET.fromstring(content)
        except Exception as exc:
            raise ValueError(f"Invalid Nmap XML: {exc}") from exc
        if root.tag != "nmaprun":
            raise ValueError("XML root must be nmaprun")
        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") != "up":
                continue
            addresses = [node.get("addr", "") for node in host.findall("address") if node.get("addrtype") in {"ipv4", "ipv6"}]
            names = [node.get("name", "") for node in host.findall("./hostnames/hostname")]
            candidates = [*addresses, *names]
            primary = next((x for x in candidates if _asset(x)), None)
            if primary is None:
                continue
            wrapped = []
            devices = {"addresses": addresses, "hostnames": names,
                       "discovery_reason": status.get("reason") if status is not None else None,
                       "hardware": [{"mac": node.get("addr"), "vendor": node.get("vendor")}
                                    for node in host.findall("address") if node.get("addrtype") == "mac"],
                       "os_matches": [{"name": node.get("name"), "accuracy": node.get("accuracy")}
                                      for node in host.findall("./os/osmatch")[:5]]}
            for candidate in dict.fromkeys([*addresses, *names]):
                record = _record(candidate, "nmap_host", devices,
                                 related_assets=addresses if candidate in names else [])
                if record:
                    result.records.append(record)
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") not in {"open", "filtered", "open|filtered"}:
                    continue
                try:
                    port_number = int(port.get("portid", ""))
                    if not 1 <= port_number <= 65535:
                        raise ValueError("out of range")
                except ValueError:
                    result.warnings.append(f"Ignored invalid Nmap port on {primary}")
                    continue
                service = port.find("service")
                protocol = (port.get("protocol") or "tcp").lower()
                if service is not None and service.get("name", "").lower() == "tcpwrapped":
                    wrapped.append(f"{protocol}/{port_number}")
                    continue
                port_state = state.get("state")
                data = {"host": primary, "protocol": protocol, "port": port_number, "state": port_state,
                        "reason": state.get("reason")}
                if service is not None:
                    data.update({k: service.get(k) for k in ("name", "product", "version", "tunnel", "ostype", "devicetype", "extrainfo", "method") if service.get(k)})
                host_identity = _asset(primary)
                if host_identity:
                    host_label = primary
                    service_value = f"{host_label}|{protocol}/{port_number}"
                    relation = "exposes" if port_state == "open" else "has_filtered_port"
                    result.records.append(ParsedRecord("service" if port_state == "open" else "filtered_port", service_value,
                        "nmap_port", data, related_assets=[(host_identity[0], host_identity[1], relation)]))
            for group in host.findall("./ports/extraports"):
                if group.get("state") not in {"filtered", "open|filtered"}:
                    continue
                groups = [{"reason": item.get("reason"), "count": item.get("count"),
                           "protocol": item.get("proto"), "ports": item.get("ports", "")}
                          for item in group.findall("extrareasons")]
                observation = _record(primary, "nmap_filtered_group", {"host": primary, "state": group.get("state"),
                                      "count": group.get("count"), "groups": groups})
                if observation:
                    result.records.append(observation)
            if wrapped:
                result.warnings.append(f"{primary}: {len(wrapped)} tcpwrapped ports responded but did not expose an identifiable service.")
                observation = _record(primary, "nmap_wrapped_ports", {"ports": wrapped, "count": len(wrapped)})
                if observation:
                    result.records.append(observation)
    elif file_format == "subfinder":
        for number, line in enumerate(content.splitlines(), 1):
            value = line.strip()
            if not value:
                continue
            record = _record(value, "subdomain", {"source": "subfinder"})
            if record:
                result.records.append(record)
            else:
                result.warnings.append(f"Line {number}: ignored invalid hostname")
    else:
        if file_format == "amass_text":
            scope_section = None
            for line_number, line in enumerate(content.splitlines(), 1):
                line = line.strip()
                if line.endswith(":"):
                    scope_section = re.sub(r"[^a-z]", "", line.lower())
                    continue
                if scope_section in {"fqdn", "ipaddress"} and (identity := _asset(line)):
                    if (scope_section == "fqdn" and identity[0] == "domain") or (
                        scope_section == "ipaddress" and identity[0] in {"ipv4", "ipv6"}
                    ):
                        result.records.append(ParsedRecord(*identity, "amass_observation", {"raw_line": line[:2048]}))
                    continue
                values = re.findall(r"\[([^\]]+)\]", line)
                identities = [(value, _asset(value)) for value in values]
                identities = [(value, identity) for value, identity in identities if identity]
                if not identities:
                    continue
                for index, (value, identity) in enumerate(identities):
                    related = []
                    for target_value, target_identity in identities[index + 1:]:
                        if target_identity and target_identity[0] in {"ipv4", "ipv6"} and identity[0] == "domain":
                            related.append(target_value)
                    result.records.append(ParsedRecord(identity[0], identity[1], "amass_observation", {"raw_line": line[:2048]}, related_assets=related))
            return result
        if file_format == "ffuf_json":
            try:
                document = json.loads(content)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid FFUF JSON: {exc}") from exc
            rows = document.get("results", []) if isinstance(document, dict) else []
            for item in rows:
                if not isinstance(item, dict):
                    continue
                record = _web_record(item.get("url"), "ffuf_endpoint",
                                     {k: item[k] for k in ("status", "length", "words", "lines", "content-type") if k in item},
                                     endpoint=True)
                if record:
                    result.records.append(record)
            return result
        for item in _json_lines(content, result):
            if file_format == "amass_jsonl":
                candidates = [item.get("name", ""), item.get("domain", "")]
                addresses = item.get("addresses") if isinstance(item.get("addresses"), list) else []
                address_values = [str(a.get("ip") if isinstance(a, dict) else a) for a in addresses]
                record = next((_record(x, "amass_entity", item, related_assets=address_values) for x in candidates if x and _asset(x)), None)
                if record:
                    result.records.append(record)
                for addr in addresses:
                    value = addr.get("ip") if isinstance(addr, dict) else addr
                    record = _record(str(value or ""), "amass_address", {"source_name": item.get("name", "")})
                    if record:
                        result.records.append(record)
            elif file_format == "httpx_jsonl":
                value = item.get("url") or item.get("input")
                data = {k: item[k] for k in ("status_code", "title", "webserver", "tech", "content_type",
                    "port", "host", "host_ip", "a", "aaaa") if k in item}
                addresses = [address for key in ("a", "aaaa") for address in _strings(item.get(key))]
                peer = _asset(item.get("host_ip", ""))
                connected = peer if peer and peer[0] in {"ipv4", "ipv6"} else None
                record = _web_record(value, "http_service", data,
                                     addresses=[address for address in addresses if _asset(address) != connected])
                if record and connected:
                    record.related_assets.append((*connected, "responded_from"))
                if record is None:
                    record = _record(item.get("hostname") or item.get("host") or value, "http_service", data,
                                     related_assets=addresses)
                if record:
                    result.records.append(record)
            elif file_format == "dnsx_jsonl":
                value = item.get("host") or item.get("input") or item.get("domain")
                addresses = [address for key in ("a", "aaaa") for address in _strings(item.get(key))]
                aliases = [("domain", alias, "aliases_to") for alias in _strings(item.get("cname"))]
                data = {k: item[k] for k in ("host", "a", "aaaa", "cname", "ns", "mx", "txt", "srv", "resp", "resolver") if k in item}
                record = _record(value, "dns_observation", data, related_assets=[*addresses, *aliases])
                if record:
                    result.records.append(record)
            elif file_format == "nuclei_jsonl":
                value = item.get("matched-at") or item.get("matched_at") or item.get("url") or item.get("host")
                info = item.get("info") if isinstance(item.get("info"), dict) else {}
                identity = web_identity(value)
                host = identity[2][1] if identity else item.get("host")
                if not _asset(host):
                    try:
                        raw_host = str(item.get("host") or value or "")
                        host = urlsplit(raw_host if "://" in raw_host else "//" + raw_host).hostname
                    except ValueError:
                        continue
                severity = str(info.get("severity", "unknown")).lower()
                if severity not in SEVERITIES:
                    severity = "unknown"
                evidence = {k: str(item[k])[:2048] for k in ("matcher-name", "type", "ip") if k in item}
                for key in ("description", "remediation"):
                    if isinstance(info.get(key), str):
                        evidence[key] = info[key][:4000]
                if references := _strings(info.get("reference"), 16):
                    evidence["references"] = references
                if isinstance(info.get("classification"), dict):
                    classification = info["classification"]
                    evidence["classification"] = {
                        k: classification[k] for k in ("cve-id", "cwe-id", "cvss-score", "cvss-metrics")
                        if isinstance(classification.get(k), (str, int, float, list))
                    }
                finding = {
                    "title": str(info.get("name") or item.get("template-id") or "Nuclei finding")[:512],
                    "severity": severity, "template_id": str(item.get("template-id", ""))[:255],
                    "matched_at": (identity[1] if identity else str(value or ""))[:2048],
                    "evidence": evidence,
                }
                data = {"template_id": finding["template_id"], "severity": severity}
                record = _web_record(value, "nuclei_finding", data, endpoint=True) if identity else _record(host, "nuclei_finding", data)
                if record:
                    record.finding = finding
                    result.records.append(record)
            elif file_format == "katana_jsonl":
                request = item.get("request") if isinstance(item.get("request"), dict) else {}
                response = item.get("response") if isinstance(item.get("response"), dict) else {}
                value = item.get("url") or request.get("endpoint") or request.get("url") or item.get("request")
                data = {k: item[k] for k in ("method", "status_code", "tag") if k in item}
                if request.get("method"):
                    data["method"] = request["method"]
                if response.get("status_code") is not None:
                    data["status_code"] = response["status_code"]
                record = _web_record(value, "web_endpoint", data, endpoint=True)
                if record:
                    result.records.append(record)
            elif file_format == "ffuf_jsonl":
                data = {k: item[k] for k in ("status", "length", "words", "lines", "content-type") if k in item}
                record = _web_record(item.get("url") or item.get("input"), "ffuf_endpoint", data, endpoint=True)
                if record:
                    result.records.append(record)
    return result

def observation_fingerprint(project_id: int, asset_type: str, asset_value: str, source: str, kind: str, data: dict[str, Any]) -> str:
    payload = json.dumps([project_id, asset_type, asset_value, source, kind, data], sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()

def finding_fingerprint(project_id: int, template_id: str, matched_at: str, title: str) -> str:
    identity = web_identity(matched_at)
    target = f"web-v2\0{identity[1]}" if identity else matched_at.lower()
    payload = "\0".join([str(project_id), template_id.lower(), target, title.lower()])
    return hashlib.sha256(payload.encode()).hexdigest()
