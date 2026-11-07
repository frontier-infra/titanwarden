"""Read-only, explicit projection. Never select ciphertext, keys or freeform notes."""
from __future__ import annotations

import json
from datetime import datetime


class ConsoleMetadata:
    def __init__(self, store, seal):
        self.store, self.seal = store, seal

    def snapshot(self) -> dict:
        with self.store._transaction_lock:
            rows = self.store.connection.execute("""
                SELECT s.path,s.class,s.state,s.rotation_json,
                  (SELECT count(*) FROM secret_versions v WHERE v.secret_id=s.secret_id) versions,
                  (SELECT max(version_no) FROM secret_versions v
                     WHERE v.secret_id=s.secret_id AND v.state='active') active_version,
                  (SELECT count(*) FROM placements p
                     WHERE p.secret_id=s.secret_id AND p.removed_at IS NULL) placements,
                  (SELECT max(ts) FROM audit_events a WHERE a.secret_path=s.path
                     AND a.op IN ('run','use_http') AND a.decision='allow') last_used,
                  (SELECT count(DISTINCT principal_id) FROM audit_events a
                     WHERE a.secret_path=s.path AND a.op IN ('run','use_http')
                     AND a.decision='allow') dependents
                FROM secrets s ORDER BY s.path LIMIT 1001
            """).fetchall()
            secrets = []
            for row in rows[:1000]:
                item = {key: row[key] for key in ("path", "class", "state", "versions",
                        "active_version", "placements", "last_used", "dependents")}
                item["rotation_due"] = None
                try:
                    due = json.loads(row["rotation_json"]).get("due_at")
                    if isinstance(due, str):
                        item["rotation_due"] = datetime.fromisoformat(due.replace("Z", "+00:00")).isoformat()
                except (ValueError, TypeError, AttributeError):
                    pass
                secrets.append(item)
            projects = [row[0] for row in self.store.connection.execute(
                "SELECT slug FROM projects ORDER BY slug").fetchall()]
            return dict(seal_state=self.seal.state, frozen=bool(self.seal.frozen),
                        initialized=self.store.meta("store_id") is not None,
                        secrets=secrets, truncated=len(rows) > 1000, projects=projects,
                        secret_count=self.store.connection.execute("SELECT count(*) FROM secrets").fetchone()[0])
