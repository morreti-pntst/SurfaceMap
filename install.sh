#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

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
  if [[ -e "$link" ]] && [[ ! "$link" -ef "$source" ]]; then
    fail "A different surfacemap command exists at $link. Move it before registering this installation."
  fi
  [[ -x "$source" ]] || chmod +x "$source"
  [[ -e "$link" ]] || ln -sfn -- "$source" "$link"
  case ":$PATH:" in
    *":$bin:"*) ;;
    *)
      case "${current_shell##*/}" in
        bash) shell_config="$HOME/.bashrc" ;;
        zsh) shell_config="${ZDOTDIR:-$HOME}/.zshrc" ;;
      esac
      if [[ -n "${shell_config:-}" ]]; then
        grep -Fqx -- "$path_line" "$shell_config" 2>/dev/null ||
          printf '\n# SurfaceMap command\n%s\n' "$path_line" >> "$shell_config"
        echo 'Open a new terminal to use the surfacemap command.'
      else
        echo "Add $bin to your shell PATH to use the surfacemap command."
      fi
      ;;
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
register_cli
echo 'Full stop: surfacemap stop'

tool_wait="${SURFACEMAP_INSTALL_TIMEOUT_SECONDS:-1800}"
[[ "$tool_wait" =~ ^[0-9]+$ ]] || fail 'SURFACEMAP_INSTALL_TIMEOUT_SECONDS must be an integer.'
deadline=$((SECONDS + tool_wait))
previous=
while :; do
  payload="$(curl -fsS --max-time 8 "$url/api/tools" || true)"
  installed="$(printf '%s' "$payload" | grep -o '"status":"installed"' | wc -l | tr -d ' ' || true)"
  if [ "$installed" != "$previous" ]; then
    echo "Ready tools: ${installed:-0}/8"
    previous="$installed"
  fi
  [ "$installed" = 8 ] && break
  (( SECONDS < deadline )) || fail "Tool setup is still incomplete. Open $url and review Tool Manager, then rerun the installer."
  sleep 5
done
echo "SurfaceMap and all tools are ready at $url"
