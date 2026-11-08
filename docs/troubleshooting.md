# Troubleshooting

- **Docker CLI missing:** install Docker Desktop or Docker Engine with Compose v2, then reopen the terminal.
- **Windows WSL is not ready:** after enabling `VirtualMachinePlatform` and `Microsoft-Windows-Subsystem-Linux`, restart Windows, run `wsl --update`, and confirm `wsl --version` reports WSL 2.1.5 or newer before starting Docker Desktop.
- **Docker installer exits early:** check free space on the Windows system drive; the installer unpacks temporary files there even when Docker itself is installed on another drive. Review `%LOCALAPPDATA%\Docker\log\host` for the installer log.
- **Engine unreachable:** start Docker Desktop/Engine and confirm `docker info` succeeds.
- **Port 8080 is occupied:** set `API_PORT` in `.env` to an unused local port, then restart.
- **API not ready:** run `surfacemap logs api` and `surfacemap status`. The launcher waits up to two minutes.
- **Database credential changed:** update both `POSTGRES_PASSWORD` and the password in `DATABASE_URL`. Existing persistent database credentials do not change just by editing `.env`.
- **Fresh schema issue:** inspect API logs for Alembic output. Do not delete the named volume unless you intend to discard all local database data.
- **Tool install is queued or failed:** Open Tool Manager → Recent tool operations to inspect progress and the bounded installer log. Initial Go builds can take several minutes and require access to the official module source. Retry the failed operation after network access is restored.
- **No wordlist appears for FFUF:** Open Scan Jobs, choose FFUF, and upload a UTF-8 `.txt` or `.list` file (up to 10 MiB). SurfaceMap stores it in the persistent local Docker data volume.
- **A scan cannot start:** Check that the project's allow scope covers the requested hostname, IP, URL host, or Nmap CIDR, and confirm that no excluded entry covers it. Excluded targets override allowed entries.
- **A scan is cancelled or fails at five minutes:** Each run has a five-minute process limit and a 10 MiB artifact limit. Reduce Nmap ports, Katana depth, or the FFUF wordlist and retry.
