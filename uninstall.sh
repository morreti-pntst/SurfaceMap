#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
project="$(pwd -P)"

echo 'This permanently deletes SurfaceMap projects, scan results, installed scanners and local configuration.'
read -r -p 'Type DELETE to continue: ' answer
[[ "$answer" == DELETE ]] || { echo 'Uninstall cancelled.'; exit 0; }

docker_cli=(docker)
if ! docker info >/dev/null 2>&1 && [[ "$(id -u)" != 0 ]] && command -v sudo >/dev/null; then
  docker_cli=(sudo docker)
fi
"${docker_cli[@]}" compose -f compose.yaml down --remove-orphans --volumes --rmi local

link="$HOME/.local/bin/surfacemap"
if [[ -L "$link" && "$link" -ef "$project/surfacemap" ]]; then
  rm -- "$link"
  for config in "$HOME/.bashrc" "${ZDOTDIR:-$HOME}/.zshrc"; do
    [[ -f "$config" ]] || continue
    sed -i '/^# SurfaceMap command$/{N;/\nexport PATH="\$HOME\/\.local\/bin:\$PATH"$/d;}' "$config"
  done
fi
rm -f -- .env
rmdir -- .data 2>/dev/null || true
echo 'SurfaceMap was uninstalled. You can now delete this folder and close the terminal.'
