# SurfaceMap

**A local workspace for mapping and auditing an authorized attack surface.**

[Quick start](#quick-start) · [First audit](#run-your-first-assessment) · [Commands](#terminal-commands) · [Troubleshooting](#troubleshooting) · [Licensing](#licensing)

Follow the evidence from a domain or IP address to a service, endpoint, or finding. Run a guided audit, launch individual scanners with editable presets, or import existing output.

| Workflow | What you get |
| --- | --- |
| **Discover** | Domains, DNS records, exposed services, web technologies, and paths |
| **Inspect** | An interactive attack surface map, scanner logs, and finding evidence |
| **Compare** | Changes between audit runs and exportable maps and reports |

## Quick start

Download or clone this repository. From its root, run the command for your system.

**Windows** (PowerShell)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1
```

**Kali, Debian or Ubuntu** (terminal)

```sh
bash ./install.sh
```

On Linux, run the installer as your regular user. It uses `sudo` when it needs to install packages or access Docker. The installer reuses a working Docker setup. On Windows it can install Docker Desktop through WinGet. On Kali, Debian and Ubuntu it can install Docker, Compose v2 and Buildx from the configured APT repositories. On older releases such as Debian 12, set up Docker's APT repository if the distribution only offers Compose v1. Docker Desktop on Windows may ask you to finish setup or restart for WSL. Once Docker is ready, the script builds SurfaceMap and waits for the eight pinned scanners.

[Docker setup for Kali](https://www.kali.org/docs/containers/installing-docker-on-kali/) · [Debian](https://docs.docker.com/engine/install/debian/) · [Ubuntu](https://docs.docker.com/engine/install/ubuntu/)

During tool setup, the terminal shows the state of every missing adapter, including download and build progress. Nmap may initially show the distribution version from the container while the pinned version builds. Follow the existing operation in **Tool Manager**. If setup reports a failure, expand that operation for its log and retry from **Tool Center** after addressing the error. The dashboard stays available while tools install.

If Docker and Compose are already set up, you can also start the stack directly.

```sh
docker compose up -d --build --wait
```

Open [SurfaceMap](http://localhost:8080). **Tool Manager** shows scanner setup progress. [API documentation](http://localhost:8080/api/docs)

## Terminal commands

After installation, open a new terminal. Run `surfacemap` commands from any folder on Windows or Linux.

| Command | Action |
| --- | --- |
| `surfacemap start` | Start SurfaceMap |
| `surfacemap stop` | Fully stop SurfaceMap and release the dashboard port |
| `surfacemap restart` | Stop and start SurfaceMap |
| `surfacemap status` | Check running services |
| `surfacemap logs api` | Follow API logs. Omit `api` to follow all services. |
| `surfacemap tools` | List scanner versions and availability |
| `surfacemap doctor` | Check Docker and the Compose configuration |
| `surfacemap update` | Pull current database and Redis images and rebuild SurfaceMap from this checkout |
| `surfacemap version` | Show the SurfaceMap version |

## Troubleshooting

**Linux cannot find `surfacemap`.** From the project folder, repair registration without starting Docker:

```bash
bash ./install.sh --register-cli
export PATH="$HOME/.local/bin:$PATH"
hash -r
surfacemap help
```

A new interactive Bash or Zsh terminal loads the updated PATH automatically. Other shells may need `~/.local/bin` added to their PATH. From the project folder, `bash ./surfacemap status` also works when an extractor stripped the executable bit or the project is on a mount that prevents direct execution. On an executable filesystem, `chmod u+x ./surfacemap` enables direct execution.

**Windows cannot find `surfacemap`.** Open a new PowerShell window. To repair registration, run `powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -RegisterCli` from the project folder.

**A scanner is missing or failed.** Open **Tool Manager → Installation history** for the operation log. If an older Nmap is shown, check the status of its pinned-version build. After addressing the error, use **Tool Center → Install or update all adapters** to retry.

See the [troubleshooting guide](docs/troubleshooting.md) for more cases.

## Full stop

Run `surfacemap stop` from any folder. The dashboard's **Full stop** button shows the same command. On Windows, you can also double-click `stop.cmd` in the SurfaceMap folder.

This shuts down scanners and other SurfaceMap processes, removes the project's containers and network, and releases its dashboard port. Docker keeps project volumes and images for the next launch. If you started Docker Desktop solely for SurfaceMap, you can quit it from the Windows tray after the stop completes.

To change the dashboard port, edit `API_PORT` in the local `.env` and run `surfacemap restart`.

## Uninstall

On Windows, double-click `uninstall.cmd`. On Linux, run `bash ./uninstall.sh` from the SurfaceMap folder. Keep Docker running until cleanup completes and type `DELETE` to confirm.

Uninstall removes the SurfaceMap containers, network, named volumes, locally built images, `.env`, and the terminal command registered by this installation. Projects, scan results and installed scanners are permanently deleted. Docker and shared images stay available for other projects.

After the script finishes, delete the SurfaceMap folder to remove the source files and any exports saved there. Clear site data for the dashboard address in your browser to remove local preferences and saved presets.

## Run your first assessment

1. Create a project and add an authorized hostname, IP address or CIDR in **Authorized scope**. Exclusions take precedence.
2. Open **Audit**, choose an assessment profile and review the plan. Choose **Baseline** for a short set of web checks. **Full surface audit** combines the eight adapters when installed.
3. Watch **Audit activity** and open individual scanner consoles. Review partial coverage and skipped checks before drawing conclusions.
4. Open **Map this audit** to trace domains, IPs, services, routes and findings. Use **Edit discovered map** for an editable copy. Export the map or a report when ready.

You can try the workflow without scanning a live system. In **Import Center**, choose **Nmap XML** and preview the bundled sample. [Sample Nmap output](examples/sample-nmap.xml)

## What you can do

- Run **Nmap**, **Subfinder**, **DNSx**, **httpx**, **OWASP Amass**, **Nuclei**, **Katana**, and **FFUF** from presets or validated custom arguments.
- Edit and save scanner presets in **Scan Jobs → My presets**. Use **Settings → Local nickname** to set the name displayed in this browser.
- Compare audit runs, inspect evidence, record finding reviews and run exact-template retests.
- Search, filter and edit attack surface maps. The map shows port observations from saved scans. **Show unidentified ports** includes the DNS entries labeled `domain` by Nmap. The `tcpwrapped` layer has a separate visibility control.
- Import scanner output and generic CSV, JSON or XML. Export reports in JSON, CSV, HTML or PDF.

## Local data and scope

SurfaceMap runs as a single-user application on localhost. Run it on a trusted machine and keep its web port private. Test only systems you are authorized to assess. Some discovery tools contact public data sources.

Projects, scan artifacts, wordlists and installed tools live in Docker volumes. Keep your `.env`, real scan exports and database backups private. A minimal configuration template is included. [Example configuration](.env.example)

## Licensing

SurfaceMap is **source-available** under the [SurfaceMap Community License v1.0](LICENSE). You can use it for free, including in paid pentests, audits, consulting, and training. You can study, modify, and distribute copies and forks for free. Selling copies, monetizing bundled functionality, or charging for hosted access requires a [separate signed commercial agreement](COMMERCIAL.md). [Third-party components](THIRD_PARTY.md) retain their own licenses.

## Project links

[Architecture](docs/architecture.md) · [Tool adapters](docs/tool-adapters.md) · [Development](docs/development.md) · [Contributing](CONTRIBUTING.md) · [Security reports](SECURITY.md)

Developed by **morreti**. General inquiries: [alsocwa@proton.me](mailto:alsocwa@proton.me).
