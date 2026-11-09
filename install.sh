#!/usr/bin/env bash
set -euo pipefail
cd -P "$(dirname "${BASH_SOURCE[0]}")"

fail() { printf '%s\n' "$*" >&2; exit 1; }
privileged() {
  if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi
}

[ "$(uname -s)" = Linux ] || fail 'Supported platforms: Windows (install.ps1), Kali, Debian and Ubuntu.'

register_cli() {
  local bin="$HOME/.local/bin" source="$PWD/surfacemap"
  local link="$bin/surfacemap" shell_config current_shell="${SHELL:-/bin/bash}"
  local path_line='export PATH="$HOME/.local/bin:$PATH"'
  mkdir -p "$bin"
  local shim
  shim="$(printf '#!/usr/bin/env bash\n# SurfaceMap CLI\nexec bash %q "$@"\n' "$source")"
  if [[ -L "$link" && "$link" -ef "$source" ]] || [[ ! -e "$link" && ! -L "$link" ]]; then
    local temporary
    temporary="$(mktemp "$bin/.surfacemap.XXXXXX")"
    printf '%s\n' "$shim" > "$temporary"
    chmod 755 "$temporary"
    mv -fT -- "$temporary" "$link"
  elif [[ -L "$link" ]] || ! cmp -s -- "$link" <(printf '%s\n' "$shim"); then
    fail "A different surfacemap command exists at $link. Move it before registering this installation."
  else
    chmod u+x "$link"
  fi
  if [[ ! -x "$source" ]] && ! chmod u+x "$source"; then
    echo 'The project folder is read-only. Use surfacemap or bash ./surfacemap instead.'
  fi

  case "${current_shell##*/}" in
    bash) shell_config="$HOME/.bashrc" ;;
    zsh) shell_config="${ZDOTDIR:-$HOME}/.zshrc" ;;
  esac
  if [[ -n "${shell_config:-}" ]]; then
    grep -Fqx -- "$path_line" "$shell_config" 2>/dev/null ||
      printf '\n# SurfaceMap command\n%s\n' "$path_line" >> "$shell_config"
  fi
  case ":$PATH:" in
    *":$bin:"*) ;;
    *) echo 'Open a new terminal, or run: export PATH="$HOME/.local/bin:$PATH"; hash -r' ;;
  esac
  echo 'SurfaceMap CLI: surfacemap help'
}

[ "$#" -le 1 ] || fail 'Usage: bash ./install.sh [--use-existing-images|--register-cli]'
build_options=(--build)
case "${1:-}" in
  '') ;;
  --use-existing-images) build_options=(--no-build --pull never) ;;
  --register-cli) register_cli; exit 0 ;;
  *) fail 'Usage: bash ./install.sh [--use-existing-images|--register-cli]' ;;
esac

register_cli

has_compose() {
  docker compose up --help 2>/dev/null | grep -- '--wait-timeout' >/dev/null
}
has_buildx() { docker buildx version >/dev/null 2>&1; }
apt_candidate() { LC_ALL=C apt-cache policy "$1" | awk '/Candidate:/{print $2; exit}'; }

if ! has_compose || { [ "${1:-}" != --use-existing-images ] && ! has_buildx; } || ! command -v curl >/dev/null; then
  command -v apt-get >/dev/null || fail 'This installer requires APT when Docker dependencies are missing.'
  privileged apt-get update
  packages=()
  if ! has_compose; then
    compose_package=
    for candidate in docker-compose-plugin docker-compose-v2 docker-compose; do
      version="$(apt_candidate "$candidate")"
      case "${version#*:}" in
        2.*|[3-9].*|[1-9][0-9].*) compose_package="$candidate"; break ;;
      esac
    done
    [ -n "$compose_package" ] ||
      fail 'This APT release has no Compose v2 package. Install Docker Engine with Compose v2 from the Docker documentation linked in README.md, then retry.'
    packages+=("$compose_package")
  fi
  if ! command -v docker >/dev/null; then
    if [ "${compose_package:-}" = docker-compose-plugin ]; then
      packages+=(docker-ce docker-ce-cli containerd.io)
    else
      packages+=(docker.io)
    fi
  fi
  if [ "${1:-}" != --use-existing-images ] && ! has_buildx; then
    buildx_package=
    for candidate in docker-buildx-plugin docker-buildx; do
      version="$(apt_candidate "$candidate")"
      if [ -n "$version" ] && [ "$version" != "(none)" ]; then buildx_package="$candidate"; break; fi
    done
    [ -n "$buildx_package" ] || fail 'Buildx is unavailable in APT. Install the Docker Buildx plugin, then retry.'
    packages+=("$buildx_package")
  fi
  if ! command -v curl >/dev/null; then packages+=(curl); fi
  privileged apt-get install -y "${packages[@]}"
fi

docker_cli=(docker)
if ! docker info >/dev/null 2>&1; then
  if [ "$(id -u)" -ne 0 ]; then docker_cli=(sudo docker); fi
  if ! "${docker_cli[@]}" info >/dev/null 2>&1; then
    privileged systemctl start docker
  fi
fi

for ((attempt=0; attempt<60; attempt++)); do
  if "${docker_cli[@]}" info >/dev/null 2>&1; then break; fi
  sleep 2
done
"${docker_cli[@]}" info >/dev/null 2>&1 || fail 'Docker did not start. Complete its setup, then rerun the installer.'
"${docker_cli[@]}" compose up --help | grep -- '--wait-timeout' >/dev/null ||
  fail 'Update Docker Compose to a version that supports up --wait-timeout.'
"${docker_cli[@]}" compose version
[ -f .env ] || cp .env.example .env
compose=("${docker_cli[@]}" compose --env-file .env -f compose.yaml)
if ! "${compose[@]}" up -d "${build_options[@]}" --wait --wait-timeout 180; then
  if [ "${1:-}" = --use-existing-images ]; then
    fail 'Could not start from local images. Confirm a previous installation exists, the port is free, and the containers are healthy.'
  fi
  fail 'SurfaceMap could not start. Review the error above. On registry or download errors, check Docker DNS and proxy settings and retry. For an existing installation, try --use-existing-images.'
fi
binding="$("${compose[@]}" port web 80)"
url="http://127.0.0.1:${binding##*:}"
echo "Dashboard: $url"
echo 'Full stop: surfacemap stop'

tool_wait="${SURFACEMAP_INSTALL_TIMEOUT_SECONDS:-1800}"
[[ "$tool_wait" =~ ^[0-9]+$ ]] || fail 'SURFACEMAP_INSTALL_TIMEOUT_SECONDS must be an integer.'
deadline=$((SECONDS + tool_wait))
previous=
while :; do
  progress="$(curl -fsS --max-time 12 "$url/api/tools/setup-progress" || true)"
  progress="${progress:-Tool setup status unavailable. Check Docker with: docker compose logs --tail 50 worker api}"
  if [ "$progress" != "$previous" ]; then
    printf '%s\n' "$progress"
    previous="$progress"
  fi
  [[ "$progress" == "Ready tools: 8/8" ]] && break
  [[ "$progress" != *"Setup needs attention."* ]] || fail "SurfaceMap is running at $url. See the adapter status above."
  (( SECONDS < deadline )) || fail "SurfaceMap is running at $url. Some tools are still pending or failed. See the last status above and Tool Manager; rerun with --use-existing-images to check again."
  sleep 5
done
echo "SurfaceMap and all tools are ready at $url"
