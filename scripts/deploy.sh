#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tw_home=${TW_HOME:-"$HOME/.titanwarden"}
release_id=$(git -C "$repo_dir" rev-parse HEAD)
release_dir="$tw_home/releases/$release_id"

umask 077
mkdir -p "$tw_home/releases" "$tw_home/run" "$tw_home/log"
chmod 700 "$tw_home" "$tw_home/releases" "$tw_home/run" "$tw_home/log"

if [ ! -d "$release_dir" ]; then
  mkdir -p "$release_dir"
  rsync -a \
    --exclude '.git' \
    --exclude '.venv' \
    --exclude '__pycache__' \
    "$repo_dir/" "$release_dir/"
  uv=${UV:-$(command -v uv 2>/dev/null || true)}
  [ -n "$uv" ] || uv=/opt/homebrew/bin/uv
  "$uv" sync --frozen --project "$release_dir"
fi

next_link="$tw_home/.current-$release_id"
ln -sfn "$release_dir" "$next_link"
case $(uname) in
  Darwin) mv -h "$next_link" "$tw_home/current" ;;
  *) mv -T "$next_link" "$tw_home/current" ;;
esac

# A restart seals the vault and deactivates the console until the operator
# unseals over SSH, so only restart a broker that is already running.
if command -v launchctl >/dev/null 2>&1 && launchctl print "gui/$(id -u)/org.frontierinfra.titanwarden" >/dev/null 2>&1; then
  launchctl kickstart -k "gui/$(id -u)/org.frontierinfra.titanwarden"
elif command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet titanwarden.service; then
  sudo systemctl restart titanwarden.service
fi
