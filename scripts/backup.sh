#!/bin/sh
set -eu

# exec keeps one process, so macOS attributes external drive access to Python.app (see tw/backup.py).
tw_home=${TW_HOME:-"$HOME/.titanwarden"}
external=${TW_EXTERNAL_BACKUP:-/Volumes/Backup/titanwarden}
exec "$tw_home/current/.venv/bin/python" -m tw.backup --home "$tw_home" --external "$external" --alert
