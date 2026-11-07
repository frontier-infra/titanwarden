"""Test-only vault. Only the fake executable imports this fixture producer."""
import json
import os
from pathlib import Path
import resource
import sys
import time

ITEM = "10000000-0000-4000-8000-000000000001"
OTHER_ITEM = "10000000-0000-4000-8000-000000000002"
VALUE = "TEST_ONLY_BW_SELECTED_93e9bb49"
UNSELECTED = "TEST_ONLY_BW_UNSELECTED_b8bc3967"
REVISION = "2026-10-16T10:00:00.000Z"
LATER = "2026-10-16T11:00:00.000Z"


def main():
    root = Path(sys.argv[0]).parent
    mode = (root / "mode").read_text()
    if resource.getrlimit(resource.RLIMIT_CORE) != (0, 0):
        sys.stderr.write(VALUE)
        return 91
    if "DEBUG" in os.environ or "NODE_OPTIONS" in os.environ:
        return 93
    sync_file = root / "sync-count"
    if sys.argv[1:] == ["sync"]:
        count = int(sync_file.read_text()) + 1 if sync_file.exists() else 1
        sync_file.write_text(str(count))
        if mode == "sync_exit" or (mode == "end_sync_exit" and count >= 2):
            sys.stdout.write(VALUE)
            sys.stderr.write(UNSELECTED)
            return 1
        return 0
    if len(sys.argv) != 4 or sys.argv[1:3] != ["get", "item"]:
        return 92
    if mode in {"above_cap", "sustained"}:
        while True:
            os.write(1, b"x" * (8 * 1024 * 1024 + 1) if mode == "above_cap" else b"x" * 4097)
            if mode == "above_cap":
                return 0
    if mode in {"grandchild", "parse_grandchild"}:
        if os.fork() == 0:
            if mode == "parse_grandchild":
                os.close(1)
            time.sleep(20)
            os._exit(0)
        os.write(1, b"invalid-json")
        return 0
    if mode in {"success_grandchild", "signal_wait"}:
        if os.fork() == 0:
            os.close(1)
            time.sleep(20)
            os._exit(0)
        if mode == "signal_wait":
            marker = root / "group-ready.tmp"
            marker.write_text(str(os.getpid()))
            marker.replace(root / "group-ready")
            time.sleep(20)
    count_file = root / ("count-" + sys.argv[-1])
    count = int(count_file.read_text()) + 1 if count_file.exists() else 1
    count_file.write_text(str(count))
    item = {"id": sys.argv[-1], "revisionDate": REVISION,
            "login": {"password": VALUE, "username": UNSELECTED, "totp": UNSELECTED},
            "fields": [{"name": "token", "value": VALUE}, {"name": "unused", "value": UNSELECTED}],
            "notes": UNSELECTED}
    if mode == "exit":
        sys.stderr.write(VALUE + UNSELECTED)
        return 1
    if mode == "malformed" or (mode == "end_read_malformed" and sync_file.exists() and int(sync_file.read_text()) >= 2):
        sys.stdout.write('{"bad":' + VALUE)
        return 0
    if mode == "duplicate_json":
        sys.stdout.write('{"id":"' + VALUE + '","id":"' + UNSELECTED + '"}')
        return 0
    if mode == "revision" and count >= 2:
        item["revisionDate"] = LATER
    if mode == "cached_revision" and sync_file.exists() and int(sync_file.read_text()) >= 2:
        item["revisionDate"] = LATER
    if mode == "cached_mid_batch" and sys.argv[-1] == OTHER_ITEM and sync_file.exists() and int(sync_file.read_text()) >= 2:
        item["revisionDate"] = LATER
    if mode == "initial_stale" and not sync_file.exists():
        item["revisionDate"] = "2026-10-15T10:00:00.000Z"
        item["fields"][0]["value"] = UNSELECTED
    if mode == "second_revision" and sys.argv[-1] == OTHER_ITEM and count >= 2:
        item["revisionDate"] = LATER
    if mode == "wrong_id":
        item["id"] = OTHER_ITEM
    if mode == "bad_revision":
        item["revisionDate"] = VALUE
    if mode == "missing":
        item["fields"] = []
        item["login"] = {}
    if mode == "duplicate_field":
        item["fields"].append({"name": "token", "value": UNSELECTED})
    if mode == "empty":
        item["fields"][0]["value"] = ""
        item["login"]["password"] = ""
    if mode == "type":
        item["fields"][0]["value"] = {"sensitive": VALUE}
    if mode == "large":
        item["fields"][0]["value"] = VALUE * 50000
    sys.stdout.write(json.dumps(item))
    sys.stderr.write(UNSELECTED)
    return 0


if __name__ == "__main__":
    sys.exit(main())
