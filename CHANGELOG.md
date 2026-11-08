# Changelog

## 0.6.0 — Audit comparison and finding retests

- Added comparisons of audit coverage, assets, findings and observed HTTP, DNS and service details.
- Added finding-linked Nuclei retests with reproducibility outcomes and a console history.
- Scoped finding review and map observations to the selected audit.
- Added migration `0011` for exact observation sightings and retest lineage.

## 0.5.0 — Operator console and evidence explorer

- Added address-level connectivity diagnostics and a small, low-rate web audit baseline.
- Added custom command validation and a separate execution console for all built-in adapters.
- Added an audit-filtered surface map with topology, routes, risks and scoped test pivots.
- Added project editing, scope duplication, export, deletion and search across project evidence.
- Added migration `0010` for asset sightings from repeated imports.

## 0.4.0 — Guided audits and scan modes

- Added scoped web and domain audit plans, stage logs, portable coverage reports and manual review.
- Added Nmap device discovery and TCP version scan modes with a filtered network report.
- Added in-run access checks for web jobs and blocked-origin handling in audits.
- Added web origins and routes to the graph, evidence inspection, finding triage and exact-template retests.
- Added migration `0009` for audit runs and evidence lineage.

## 0.3.0 — First complete local workflow

- Added relationship and source provenance plus finding-aware filters to the interactive attack surface map.
- Added generic CSV, JSON, and safe XML imports, alongside import preview for every supported format.
- Added scoped retry lineage for failed or cancelled scan jobs and five built-in scan profiles.
- Added upstream license and installation method links for every built-in adapter.
- Added the typed trusted-adapter SDK contract and documented that third-party plugin code is not loaded by default.
- Added migration `0008` for scan retry lineage.

## 0.2.0 — Tool operations and scoped execution

- Added pinned command adapters for Nmap, Subfinder, DNSx, httpx, Amass, Nuclei, Katana, and FFUF.
- Added startup tool checks, managed installs, version health probes, operation logs, rollback, and saved lifecycle preferences.
- Added scope-checked command preview and background scan jobs with cancellation, time/output limits, artifacts, and normalized result ingestion.
- Added a managed wordlist upload flow for FFUF and advanced flags validated by per-tool allowlists.
- Expanded import support for DNSx and FFUF as well as Amass text output.
- Added sequential workflow templates that create standard scan jobs and reuse scope checks.
- Added project report exports in JSON, CSV, HTML, and PDF.
- Added persistent settings and migrations `0005`–`0007`.

## 0.1.0 — Foundation and import intelligence

- Added Docker Compose services for PostgreSQL, Redis, FastAPI, Celery worker, and static React frontend.
- Added launcher commands and service health checks.
- Added projects and allowed/excluded scope management.
- Added normalized assets, observations, findings, DNS relationships, timeline, snapshots, and the initial interactive attack surface map.
- Added parser preview and deduplicating import for Nmap XML, Subfinder, Amass, httpx, Nuclei, and Katana output.
