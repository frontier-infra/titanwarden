#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
case $(uname) in
  Darwin) default_home="$HOME/.titanwarden" ;;
  *) default_home=/data/titanwarden ;;
esac
tw_home=${TW_HOME:-"$default_home"}

umask 077
if [ ! -d "$tw_home" ]; then
  mkdir -p "$tw_home" 2>/dev/null || sudo install -d -o "$(id -un)" -g "$(id -gn)" -m 700 "$tw_home"
fi
for directory in state run tokens panes log backups releases; do
  mkdir -p "$tw_home/$directory"
  chmod 700 "$tw_home/$directory"
done
chmod 700 "$tw_home"

TW_HOME="$tw_home" "$repo_dir/scripts/deploy.sh"
mkdir -p "$HOME/bin"
ln -sfn "$tw_home/current/bin/tw" "$HOME/bin/tw"
ln -sfn "$tw_home/current/bin/twadmin" "$HOME/bin/twadmin"

if [ "$(uname)" = Darwin ]; then
  mkdir -p "$HOME/Library/LaunchAgents"
  for plist in "$repo_dir"/launchd/*.plist; do
    destination="$HOME/Library/LaunchAgents/$(basename "$plist")"
    # The shipped plists use /Users/USERNAME as a placeholder for this account's home.
    sed "s#/Users/USERNAME#$HOME#g" "$plist" > "$destination"
    chmod 600 "$destination"
    launchctl bootout "gui/$(id -u)" "$destination" >/dev/null 2>&1 || true
    launchctl bootstrap "gui/$(id -u)" "$destination"
  done
else
  # System units that run as the installing account: no user bus needed, and
  # twadmin reads the broker pid with systemctl show. The profile line gives
  # every SSH session the same TW_HOME the units use.
  unit_dir=/etc/systemd/system
  for unit in "$repo_dir"/systemd/titanwarden*.service "$repo_dir"/systemd/titanwarden*.timer; do
    sed -e "s/^User=titanwarden$/User=$(id -un)/" -e "s/^Group=titanwarden$/Group=$(id -gn)/" "$unit" \
      | sudo tee "$unit_dir/$(basename "$unit")" >/dev/null
    sudo chmod 644 "$unit_dir/$(basename "$unit")"
  done
  printf 'export TW_HOME=%s\n' "$tw_home" | sudo tee /etc/profile.d/titanwarden.sh >/dev/null
  sudo install -d -o "$(id -un)" -g "$(id -gn)" -m 700 /data/titanwarden-backups
  sudo systemctl daemon-reload
  sudo systemctl enable --now titanwarden.service titanwarden-watch.timer titanwarden-backup.timer
fi
