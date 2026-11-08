# Tool adapters and lifecycle

Scan Jobs and Audit open a console with live events, tool diagnostics and tool output. Nuclei reports
request, error and match counts at five-second intervals when scanning.
Web tools check the requested endpoint before starting, with redirects
disabled for the check. Access denials, protection challenges, rate limits
and connectivity failures stop the job with a diagnostic. Every 15 seconds,
SurfaceMap checks the seed URL again with the scan user agent. It also reads
rate-limit and protection signals reported by the adapter. An individual 403
or 404 on a discovered path can be a normal result. Blocks confined to an
individual template request can escape detection if the adapter omits its response.

The initial web probe tries the resolved addresses within a bounded window and verifies TLS with the target hostname. Its log shows DNS answers, the address that responded, and transport errors. If a site rate limits the scan, wait for the retry window and prepare a baseline at 1 req/s. For access rules that require approval, coordinate a test window or a dedicated endpoint with the owner.

The worker checks the installation queue every minute. It resumes interrupted
installs and delivers queued operations after the task broker becomes available
again. With automatic stable updates enabled, a temporary download failure
triggers another installation attempt after at least five minutes. The installer
reuses its module cache and keeps the current executable active until the new
one passes its version check. Persistent compatibility errors stay visible in
Installation history. A completed uninstall is respected across restarts.

SurfaceMap registers eight active command adapters: Nmap, Subfinder, DNSx, httpx, OWASP Amass, Nuclei, Katana, and FFUF. Each adapter records its pinned stable version, official source and documentation, argument builder, result format, and bounded defaults in `backend/app/tool_registry.py`.

## Installation and versions

The API checks for missing or outdated pinned adapters at startup and queues installation in the background when automatic updates and startup checks are enabled. Go tools are built from their version-pinned upstream Go module with checksum verification through Go's module system. Nmap is built from the official Nmap source archive after checking the published SHA256 digest. Executables live in a persistent Docker data volume under `/data/tools`; an atomic symlink switch activates a version after its version probe passes. Tool Manager exposes install, update, reinstall, rollback, and uninstall operations with bounded logs.

The adapter manifest is the compatibility boundary. Tool Manager intentionally installs only its pinned stable version; it does not follow arbitrary latest releases or prereleases. Update the manifest and its parser/command compatibility in a SurfaceMap release before changing a pin. Failed installation leaves a previous active version in place when one exists.

## Scan safety and limits

Choose a scenario from the Scan Jobs form. Nmap starts with its default 1,000 TCP ports
and service version detection. When adding Nmap to a guided audit, leave the custom
port list blank to use the same defaults. Scan Jobs also offers explicit ports, a full TCP range, and
device discovery with `-sn`. The device list is based on responses visible from
Docker. The network report shows open and filtered results and preserves grouped
counts when Nmap summarizes them. The inspector displays OS and hardware evidence
when it is present in the XML or reported by service detection.

**Write a command** accepts the arguments after the executable. For example,
enter `-sV example.com` for Nmap. The editor lists the supported
options for each pinned adapter. Commands take one scoped target and use
SurfaceMap's output, rate and execution limits. FFUF accepts an uploaded wordlist
path and a `FUZZ` placeholder in the path or query.

Every run belongs to a project. The API checks allowed and excluded scope entries before preview and queueing; the worker checks scope again immediately before launch. A target must match a project allow entry. Enable full access in the project scope panel to allow any supported target. Explicit exclusions take priority in either mode. Nmap CIDR targets are limited to 256 addresses and must be fully contained in an allowed CIDR unless full access is enabled. Other tools accept one hostname/IP or HTTP(S) URL, and reject CIDR input.

Commands are argument arrays. Basic options have per-adapter validation. Advanced flags use a per-tool allowlist. Most jobs have a five-minute time limit. Nmap allows 1–60 minutes. Standalone Nuclei allows 5–60 minutes, with a 15-minute default. Guided audits allow up to 25 minutes per origin for Nuclei Baseline and up to 60 minutes for the wider template sets. A Nuclei timeout retains collected evidence and records partial coverage. Jobs have a 10 MiB output limit, two global concurrent jobs, and one job per project. Output artifacts and command/version metadata are stored in the persistent local data volume. Cancellation terminates the scanner process group.

Leave User-Agent blank to use the web scanner's own HTTP behavior. When you set a User-Agent, SurfaceMap uses it for both the access check and the scanner.

Nuclei runs with the HTTP templates from ProjectDiscovery v10.5.1 bundled in the Docker image and defaults to medium, high, and critical findings. Narrow broad scans with severity and the advanced tags filter. Nmap TCP responses labeled tcpwrapped are grouped as host evidence and excluded from the service inventory. Raw XML remains downloadable. All HTTP request-based adapters use a low request rate. FFUF requires a user-uploaded UTF-8 wordlist under 10 MiB, stored in the managed wordlists directory. No external target is scanned automatically; the operator queues a specific scoped run.

## Add an adapter

Add a `ToolAdapter` with a stable ID, pinned version, official project URLs, output format, argument builder and validated UI parameters. Register a parser in `backend/app/importers.py`, and make sure the runner selects an artifact format and parser that match the actual upstream output. If it uses Go, add its official module path; otherwise add a dedicated installer and integrity check. Update the API/UI and this documentation together. Never pass raw shell text to a subprocess.
