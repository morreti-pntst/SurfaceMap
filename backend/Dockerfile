# syntax=docker/dockerfile:1
FROM golang:1.27.3-bookworm AS go-runtime

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=go-runtime /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:/data/tools/current:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    GOPATH=/data/tools/gopath GOMODCACHE=/data/tools/gomodcache GOCACHE=/data/tools/gocache \
    SURFACEMAP_TOOLS_DIR=/data/tools SURFACEMAP_ARTIFACTS_DIR=/data/artifacts
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates fonts-dejavu-core libpcap-dev libpcre2-dev libssl-dev nmap zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN python - <<'PY'
import tarfile
import time
from pathlib import Path
from urllib.request import urlopen

version = "10.5.1"
url = f"https://codeload.github.com/projectdiscovery/nuclei-templates/tar.gz/refs/tags/v{version}"
for attempt in range(3):
    try:
        with urlopen(url, timeout=30) as response:
            with tarfile.open(fileobj=response, mode="r|gz") as archive:
                archive.extractall("/opt", filter="data")
        break
    except (OSError, tarfile.TarError):
        if attempt == 2:
            raise
        time.sleep(2)
templates = Path(f"/opt/nuclei-templates-{version}")
if not any((templates / "http").rglob("*.yaml")):
    raise RuntimeError("The official Nuclei template archive has no HTTP templates")
templates.rename("/opt/nuclei-templates")
PY
ENV NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates
COPY app ./app
COPY alembic.ini ./alembic.ini
COPY migrations ./migrations
RUN groupadd --system --gid 10001 surfacemap \
    && useradd --system --uid 10001 --gid surfacemap --home-dir /app surfacemap \
    && mkdir -p /app/.config/nuclei \
    && cp /opt/nuclei-templates/.nuclei-ignore /app/.config/nuclei/.nuclei-ignore \
    && chown -R surfacemap:surfacemap /app
USER 10001:10001
EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
