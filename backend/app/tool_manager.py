"""Isolated, version-pinned installation and health probes for trusted adapters."""
import os
import re
import shutil
import subprocess
import tempfile
import hashlib
import tarfile
import urllib.request
import time
from pathlib import Path
from .tool_registry import TOOL_BY_ID, ToolAdapter

TOOLS_ROOT = Path(os.getenv("SURFACEMAP_TOOLS_DIR", "/data/tools"))
VERSION_ROOT = TOOLS_ROOT / "versions"
CURRENT_ROOT = TOOLS_ROOT / "current"


def binary_path(tool: ToolAdapter) -> str | None:
    managed = CURRENT_ROOT / tool.binary
    if managed.is_file() and os.access(managed, os.X_OK):
        return str(managed)
    return shutil.which(tool.binary)


def installed_version(tool: ToolAdapter) -> str | None:
    executable = binary_path(tool)
    if not executable:
        return None
    return _probe_version(executable)


def _probe_version(executable: str) -> str | None:
    try:
        outputs = []
        for flag in ("--version", "-version", "-V"):
            result = subprocess.run([executable, flag], capture_output=True, text=True, timeout=8, check=False)
            outputs.append(result.stdout + "\n" + result.stderr)
            if result.returncode == 0 and re.search(r"\d+\.\d+", outputs[-1]):
                break
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = "\n".join(outputs).strip()
    match = re.search(r"(?i)(?:version|current version|v)(?:\s*[:=]?\s*)v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", text)
    if match:
        return match.group(1)
    # Some upstream tools print the semantic version on a short banner.
    match = re.search(r"\bv?([0-9]+\.[0-9]+\.[0-9]+)\b", text)
    return match.group(1) if match else None


def is_transient_install_error(output: str) -> bool:
    return any(marker in output.lower() for marker in (
        "unexpected eof", "tls handshake timeout", "connection reset by peer",
        "i/o timeout", "temporary failure in name resolution", "429 too many requests",
        "temporary failure", "network is unreachable", "connection refused",
        "502 bad gateway", "503 service unavailable", "504 gateway timeout",
        "temporary network failure",
    ))


def install_version(tool_id: str, version: str, emit=None) -> str:
    tool = TOOL_BY_ID.get(tool_id)
    if not tool:
        raise ValueError("This tool is installed with the application image, not by the Go installer")
    if not re.fullmatch(r"v?[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][A-Za-z0-9.-]+)?", version):
        raise ValueError("Upstream version must be a semantic version")
    if version != tool.version:
        raise ValueError("Only the pinned upstream release in the adapter manifest can be installed")
    if tool.id == "nmap":
        return _install_nmap(version, emit)
    if not tool.module:
        raise ValueError("No trusted installer is configured for this tool")
    version_root = VERSION_ROOT / tool_id
    destination = version_root / version.lstrip("v")
    executable = destination / tool.binary
    if executable.exists():
        if _probe_version(str(executable)) == version.lstrip("v"):
            activate(tool_id, destination, tool.binary)
            return f"Using verified module build {tool.module}@{version}"
        # Never remove a possibly active version directory. Stage the repair in
        # a fresh path and switch the executable symlink only after verification.
        destination = version_root / f"{version.lstrip('v')}-{time.time_ns()}"
    version_root.mkdir(parents=True, exist_ok=True)
    temp_dir = Path(tempfile.mkdtemp(prefix=".install-", dir=version_root))
    env = os.environ.copy()
    env["GOBIN"] = str(temp_dir)
    env["GOPATH"] = str(TOOLS_ROOT / "gopath")
    env["GOMODCACHE"] = str(TOOLS_ROOT / "gomodcache")
    env["GOCACHE"] = str(TOOLS_ROOT / "gocache")
    if tool.id == "amass":
        env["CGO_ENABLED"] = "1"
    command = ["go", "install"]
    if tool.id == "ffuf":
        # FFUF's upstream release build injects the tag at link time.
        package = "github.com/ffuf/ffuf/v2/pkg/ffuf"
        command.extend(["-ldflags", f"-X {package}.VERSION={version.lstrip('v')} -X {package}.VERSION_APPENDIX="])
    command.append(f"{tool.module}@{version}")
    if emit:
        emit("$ " + " ".join(command))
    try:
        # Leave time for cleanup before Celery's 1500-second soft limit.
        deadline = time.monotonic() + 1440
        for attempt in range(3):
            result = subprocess.run(
                command, env=env, capture_output=True, text=True,
                timeout=max(1, deadline - time.monotonic()), check=False,
            )
            output = result.stdout + result.stderr
            log = output[-12000:]
            if emit and log:
                emit(log)
            transient = is_transient_install_error(output)
            if not result.returncode or not transient or attempt == 2 or time.monotonic() >= deadline:
                break
            if emit:
                emit("Go module download interrupted; retrying with the existing module cache.")
            time.sleep(min(2 ** (attempt + 1), max(0, deadline - time.monotonic())))
        if result.returncode:
            hint = "Temporary network failure. " if transient else ""
            raise RuntimeError(f"{hint}Go installer failed with exit code {result.returncode}: {log[-2500:]}")
        built = temp_dir / tool.binary
        if not built.is_file():
            raise RuntimeError("Installer completed without producing the expected executable")
        if _probe_version(str(built)) != version.lstrip("v"):
            raise RuntimeError("Staged binary failed its version health check")
        temp_dir.rename(destination)
        if _probe_version(str(destination / tool.binary)) != version.lstrip("v"):
            shutil.rmtree(destination, ignore_errors=True)
            raise RuntimeError("Installed binary failed its version health check")
        activate(tool_id, destination, tool.binary)
        return f"Installed {tool.name} {version}; executable health check passed"
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise


def _install_nmap(version: str, emit=None) -> str:
    archive_name = f"nmap-{version}.tgz"
    base_url = "https://nmap.org/dist/"
    with urllib.request.urlopen(base_url + archive_name, timeout=60) as response:
        archive_bytes = response.read(40 * 1024 * 1024)
    with urllib.request.urlopen(base_url + "sigs/" + archive_name + ".digest.txt", timeout=30) as response:
        digest_text = response.read(64 * 1024).decode("ascii", "replace")
    digest_lines = digest_text.splitlines()
    digest_parts: list[str] = []
    for line_number, line in enumerate(digest_lines):
        if re.search(r"\bSHA256\s*=", line):
            digest_parts.extend(re.findall(r"[0-9a-fA-F]+", line.split("=", 1)[1]))
            for continuation in digest_lines[line_number + 1:]:
                if not continuation[:1].isspace() or not re.fullmatch(r"\s*[0-9a-fA-F ]+\s*", continuation):
                    break
                digest_parts.extend(re.findall(r"[0-9a-fA-F]+", continuation))
            break
    digest = "".join(digest_parts)[:64]
    if len(digest) != 64:
        raise RuntimeError("Official Nmap SHA256 digest was missing or malformed")
    actual = hashlib.sha256(archive_bytes).hexdigest()
    if actual.lower() != digest.lower():
        raise RuntimeError("Nmap archive integrity check failed")
    if emit:
        emit(f"Downloaded {archive_name} from the official Nmap release archive; SHA256 verified.")
    VERSION_ROOT.mkdir(parents=True, exist_ok=True)
    nmap_root = VERSION_ROOT / "nmap"
    nmap_root.mkdir(parents=True, exist_ok=True)
    destination = nmap_root / f"{version}-{time.time_ns()}"
    build_root = Path(tempfile.mkdtemp(prefix=".nmap-build-", dir=str(VERSION_ROOT)))
    archive_path = build_root / archive_name
    archive_path.write_bytes(archive_bytes)
    try:
        with tarfile.open(archive_path, "r:gz") as bundle:
            root = build_root.resolve()
            for member in bundle.getmembers():
                resolved = (build_root / member.name).resolve()
                if resolved != root and root not in resolved.parents:
                    raise RuntimeError("Nmap archive contains an unsafe path")
            bundle.extractall(build_root, filter="data")
        source = next(path for path in build_root.iterdir() if path.is_dir() and path.name.startswith("nmap-"))
        (source / "configure").chmod(0o755)
        configure = subprocess.run(["./configure", f"--prefix={destination}", "--without-zenmap"], cwd=source, capture_output=True, text=True, timeout=180, check=False)
        if configure.returncode:
            raise RuntimeError(f"Nmap configure failed: {(configure.stdout + configure.stderr)[-2500:]}")
        build = subprocess.run(["make", "-j2"], cwd=source, capture_output=True, text=True, timeout=900, check=False)
        if build.returncode:
            raise RuntimeError(f"Nmap build failed: {(build.stdout + build.stderr)[-2500:]}")
        install = subprocess.run(["make", "install"], cwd=source, capture_output=True, text=True, timeout=180, check=False)
        if install.returncode:
            raise RuntimeError(f"Nmap install failed: {(install.stdout + install.stderr)[-2500:]}")
        binary = destination / "bin" / "nmap"
        alias = destination / "nmap"
        alias.symlink_to(binary)
        probe = subprocess.run([str(binary), "--version"], capture_output=True, text=True, timeout=15, check=False)
        if version not in probe.stdout + probe.stderr:
            raise RuntimeError("Installed Nmap failed its version health check")
        activate("nmap", destination, "nmap")
        active = destination.resolve()
        older = sorted((path for path in nmap_root.iterdir() if path.is_dir() and path.resolve() != active), key=lambda path: path.stat().st_mtime, reverse=True)
        for obsolete in older[2:]:
            shutil.rmtree(obsolete, ignore_errors=True)
        return f"Installed Nmap {version}; official SHA256 and executable version checks passed"
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    finally:
        shutil.rmtree(build_root, ignore_errors=True)


def activate(tool_id: str, destination: Path, binary: str) -> None:
    CURRENT_ROOT.mkdir(parents=True, exist_ok=True)
    target = destination / binary
    temp_link = CURRENT_ROOT / f".{tool_id}.new"
    current_link = CURRENT_ROOT / binary
    temp_link.unlink(missing_ok=True)
    temp_link.symlink_to(target)
    # Replace the executable symlink atomically after the new version passed its probe.
    os.replace(temp_link, current_link)


def rollback(tool: ToolAdapter) -> str:
    base = VERSION_ROOT / tool.id
    versions = sorted((p for p in base.iterdir() if p.is_dir()), key=lambda path: path.stat().st_mtime, reverse=True) if base.exists() else []
    current = CURRENT_ROOT / tool.binary
    active = current.resolve().parent if current.exists() else None
    previous = next((path for path in versions if path != active and (path / tool.binary).is_file()), None)
    if previous is None:
        raise ValueError("There is no previous installed version to roll back to")
    activate(tool.id, previous, tool.binary)
    return f"Rolled back to {previous.name}"


def uninstall(tool: ToolAdapter) -> str:
    if tool.id == "nmap":
        raise ValueError("Nmap is supplied by the application image and is removed when that image is changed")
    base = VERSION_ROOT / tool.id
    current = CURRENT_ROOT / tool.binary
    current.unlink(missing_ok=True)
    shutil.rmtree(base, ignore_errors=True)
    return f"Removed managed installations of {tool.name}"
