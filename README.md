# SurfaceMap

SurfaceMap is a local workspace for authorized security assessments. Define what you can test, run a guided audit or individual scanners, and trace the results on an interactive attack surface map.

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

The installer reuses a working Docker setup. On Windows it can install Docker Desktop through WinGet. On Kali, Debian and Ubuntu it can install Docker, Compose v2 and Buildx from the configured APT repositories. On older releases such as Debian 12, set up Docker's APT repository if the distribution only offers Compose v1. Docker Desktop on Windows may ask you to finish setup or restart for WSL. Once Docker is ready, the script builds SurfaceMap and waits for the eight pinned scanners.

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

If you already installed SurfaceMap, register the command from the project folder with `bash ./install.sh --register-cli` on Linux or `powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -RegisterCli` on Windows. Then open a new terminal. On Linux the installer adds the launcher to `~/.local/bin`. Bash and Zsh are configured automatically when needed. For another shell, add that directory to its PATH.

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

For setup, tool behavior and development, see [Troubleshooting](docs/troubleshooting.md), [Tool adapters](docs/tool-adapters.md), [Development](docs/development.md), and [Architecture](docs/architecture.md).

## Developer and contact

Developed by **morreti**. For advertising, suggestions and general questions, write to [alsocwa@proton.me](mailto:alsocwa@proton.me).

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines, [SECURITY.md](SECURITY.md) for vulnerability reporting, and [LICENSE](LICENSE) for the MIT license.
