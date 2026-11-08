# Import formats

Import Center accepts one selected format per upload. It previews counts and parser warnings before committing. The API accepts UTF-8 (optional BOM) files up to 10 MiB. Invalid records are skipped with warnings where possible; malformed Nmap XML or unsupported format names return an error. XML uses `defusedxml`. Imports are treated as data and are never executed.

| Format | Accepted input | Current normalization |
|---|---|---|
| Nmap XML | `<nmaprun>` XML | Host IPs and names, open and filtered TCP ports, service versions and available OS/MAC evidence |
| Subfinder | One hostname per line | Canonical domain assets |
| Amass JSONL | One JSON object per line | `name`/`domain` and `addresses`; address relationships when provided |
| Amass text | Human-readable text with bracketed host values | Domain and address observations from matching text lines |
| DNSx JSONL | One JSON object per line | Hostnames, A/AAAA answers, and resolution links |
| httpx JSONL | One JSON object per line | URL/host, selected HTTP metadata, `a`/`aaaa` answers and resolution links |
| Nuclei JSONL | One JSON object per line | Matched endpoint, severity, template ID, remediation and selected evidence fields |
| Katana JSONL | One JSON object per line | Web origin, route, method and status |
| FFUF JSON | FFUF `-of json` document | Host asset and path observation metadata |
| FFUF JSONL | One record per line from FFUF `-json` stdout | Host asset and matched path metadata |
| Generic CSV | Header row plus one asset per line; accepts `asset`, `value`, `host`, `hostname`, `domain`, or `ip`; optional `related_asset` and `relationship_type` | Asset observations and optional typed relationships |
| Generic JSON | An array of objects or `{ "assets": [...] }`; each object has an `asset`, `value`, `host`, `hostname`, `domain`, or `ip` field | Asset observations and optional `related_asset(s)` relationships |
| Generic XML | Safe XML elements with identity attributes (`asset`, `value`, `host`, `hostname`, `domain`, or `ip`) or text inside `asset`, `host`, `domain`, or `ip` elements | Asset observations and optional `related_asset` relationships; parsed with `defusedxml` |

Domain values are lowercased and IDNA encoded; IPs use compressed canonical notation. Assets are unique within a project by type and canonical value. Identical observations and findings are deduplicated by stable fingerprints; later sightings update last-seen timestamps. The import batch retains provenance and bounded parser warnings.

The preview's asset count counts distinct assets represented by parsed records, not only new assets. Some output variants may use fields that are not currently recognized; inspect warnings and validate the resulting inventory. Scanner jobs use the same parser and provenance path as file imports. Uploaded files are parsed as data and never executed.
