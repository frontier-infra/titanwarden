#!/usr/bin/env python3
"""Check broker socket responsiveness and heartbeat freshness."""

from __future__ import annotations

import argparse
import json
import socket
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from tw.protocol import recv_frame, send_frame


def check(home: Path) -> tuple[bool, str]:
    health_path = home / "health.json"
    try:
        health = json.loads(health_path.read_text(encoding="utf-8"))
        heartbeat = datetime.fromisoformat(health["heartbeat_at"].replace("Z", "+00:00"))
        if (datetime.now(UTC) - heartbeat).total_seconds() > 30:
            return False, "heartbeat is older than 30 seconds"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2)
            client.connect(str(home / "run" / "tw.sock"))
            send_frame(client, {"args": {}, "op": "hello", "v": 1})
            response = recv_frame(client)
        if not response.get("ok"):
            return False, "hello round trip failed"
        return True, "ok"
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        return False, type(exc).__name__


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--home", required=True)
    options = parser.parse_args(argv)
    ok, reason = check(Path(options.home))
    if ok:
        return 0
    subprocess.run(
        [
            "desk",
            "--as",
            "master",
            "blocker",
            "master",
            "Titanwarden broker is unresponsive",
            "--body",
            f"Names-only watch failure: {reason}",
        ],
        check=False,
        timeout=15,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
