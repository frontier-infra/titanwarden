"""Append-only hash-chained audit log."""

from __future__ import annotations

import json
import socket
import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from . import crypto
from .store import Store, canonical_text, utc_now


ZERO_HASH = bytes(32)


class AuditError(RuntimeError):
    code = "E_AUDIT"


@dataclass(frozen=True, slots=True)
class VerificationResult:
    ok: bool
    seq: int
    digest: bytes
    error: str | None = None


def _json_row(row: Mapping[str, Any]) -> bytes:
    value: dict[str, Any] = {}
    for key, item in row.items():
        if key in {"hash", "mac"}:
            continue
        if isinstance(item, bool):
            item = int(item)
        value[key] = item.hex() if isinstance(item, bytes) else item
    return canonical_text(value).encode("utf-8")


class AuditLog:
    def __init__(
        self,
        store: Store,
        *,
        mac_key: bytes | None = None,
        scrub: Callable[[str], tuple[str, bool]] | None = None,
    ) -> None:
        self.store = store
        self.mac_key = mac_key
        self.scrub = scrub

    def append(
        self,
        *,
        event_id: str,
        op: str,
        phase: str = "single",
        decision: str = "allow",
        reason_code: str | None = None,
        sealed_tail: bool | None = None,
        **fields: Any,
    ) -> sqlite3.Row:
        if phase not in {"intent", "result", "single"}:
            raise AuditError("invalid audit phase")
        if decision not in {"allow", "deny", "error"}:
            raise AuditError("invalid audit decision")
        columns = [row[1] for row in self.store.connection.execute("PRAGMA table_info(audit_events)")]
        try:
            with self.store.transaction(immediate=True) as connection:
                last = connection.execute(
                "SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                seq = 1 if last is None else int(last["seq"]) + 1
                previous = ZERO_HASH if last is None else bytes(last["hash"])
                row: dict[str, Any] = {column: None for column in columns}
                row.update(
                    {
                        "seq": seq,
                        "event_id": event_id,
                        "ts": utc_now(),
                        "host": socket.gethostname(),
                        "op": op,
                        "phase": phase,
                        "decision": decision,
                        "reason_code": reason_code,
                        "context_verified": 0,
                        "claimed_json": "{}",
                        "scrubbed": 0,
                        "detail_json": "{}",
                        "sealed_tail": int(
                            self.mac_key is None if sealed_tail is None else sealed_tail
                        ),
                        "prev_hash": previous,
                    }
                )
                unknown = set(fields) - set(columns)
                if unknown:
                    raise AuditError(f"unknown audit fields: {', '.join(sorted(unknown))}")
                row.update(fields)
                scrubbed = False
                if self.scrub is not None:
                    for name in ("reason_code", "detail_json"):
                        if row[name] is not None:
                            row[name], changed = self.scrub(str(row[name]))
                            scrubbed |= changed
                row["scrubbed"] = int(scrubbed or bool(row["scrubbed"]))
                digest = crypto.sha256(previous + _json_row(row))
                row["hash"] = digest
                row["mac"] = None if self.mac_key is None else crypto.audit_mac(self.mac_key, digest)
                placeholders = ",".join("?" for _ in columns)
                connection.execute(
                    f"INSERT INTO audit_events({','.join(columns)}) VALUES ({placeholders})",
                    tuple(row[column] for column in columns),
                )
                saved = connection.execute("SELECT * FROM audit_events WHERE seq=?", (seq,)).fetchone()
                if saved is None:
                    raise AuditError("audit write disappeared")
                return saved
        except sqlite3.Error as exc:
            raise AuditError("audit write failed") from exc

    def verify(
        self, *, require_anchors: bool = True, allow_unattested_sealed_tail: bool = False
    ) -> VerificationResult:
        previous = ZERO_HASH
        last_seq = 0
        covered_sealed: set[int] = set()
        previous_attestation = 0
        rows = list(self.store.connection.execute("SELECT * FROM audit_events ORDER BY seq"))
        rows_by_seq = {int(row["seq"]): row for row in rows}
        for row in rows:
            row_map = dict(row)
            seq = int(row["seq"])
            if seq != last_seq + 1:
                return VerificationResult(False, seq, previous, "audit sequence gap")
            if bytes(row["prev_hash"]) != previous:
                return VerificationResult(False, seq, previous, "previous hash mismatch")
            expected = crypto.sha256(previous + _json_row(row_map))
            if not crypto.compare_digest(bytes(row["hash"]), expected):
                return VerificationResult(False, seq, previous, "hash mismatch")
            if row["mac"] is not None:
                if self.mac_key is None or not crypto.verify_audit_mac(
                    self.mac_key, bytes(row["hash"]), bytes(row["mac"])
                ):
                    return VerificationResult(False, seq, previous, "MAC mismatch")
            if row["op"] == "tail_attest":
                if row["mac"] is None or int(row["sealed_tail"]):
                    return VerificationResult(False, seq, previous, "unsigned tail attestation")
                try:
                    detail = json.loads(row["detail_json"])
                    first_seq = int(detail["first_seq"])
                    last_covered = int(detail["last_seq"])
                    last_hash = bytes.fromhex(str(detail["last_hash"]))
                except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                    return VerificationResult(False, seq, previous, "invalid tail attestation")
                if first_seq <= previous_attestation or last_covered >= seq or first_seq > last_covered:
                    return VerificationResult(False, seq, previous, "invalid tail attestation range")
                covered = [rows_by_seq.get(item) for item in range(first_seq, last_covered + 1)]
                if any(
                    item is None or item["mac"] is not None or int(item["sealed_tail"]) != 1
                    for item in covered
                ):
                    return VerificationResult(False, seq, previous, "invalid sealed tail coverage")
                last_row = rows_by_seq.get(last_covered)
                if last_row is None or not crypto.compare_digest(bytes(last_row["hash"]), last_hash):
                    return VerificationResult(False, seq, previous, "tail attestation hash mismatch")
                covered_sealed.update(range(first_seq, last_covered + 1))
                previous_attestation = seq
            previous = bytes(row["hash"])
            last_seq = seq
        for row in rows:
            if row["mac"] is None and int(row["sealed_tail"]) != 1:
                return VerificationResult(False, int(row["seq"]), previous, "invalid unsigned event")
            if (
                row["mac"] is None
                and int(row["seq"]) not in covered_sealed
            ):
                if not allow_unattested_sealed_tail or int(row["seq"]) <= previous_attestation:
                    return VerificationResult(
                        False, int(row["seq"]), previous, "unattested sealed event"
                    )
        if require_anchors:
            anchor = self.store.connection.execute(
                "SELECT seq,hash FROM anchors ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            if anchor is not None:
                if int(anchor["seq"]) > last_seq:
                    return VerificationResult(False, last_seq, previous, "audit truncated before anchor")
                anchored = self.store.connection.execute(
                    "SELECT hash FROM audit_events WHERE seq=?", (anchor["seq"],)
                ).fetchone()
                if anchored is None or bytes(anchored["hash"]) != bytes(anchor["hash"]):
                    return VerificationResult(False, int(anchor["seq"]), previous, "anchor mismatch")
        return VerificationResult(True, last_seq, previous)

    def attest_sealed_tail(self, event_id: str) -> sqlite3.Row | None:
        prior = self.store.connection.execute(
            "SELECT seq FROM audit_events WHERE op='tail_attest' ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        after_seq = 0 if prior is None else int(prior["seq"])
        pending = self.store.connection.execute(
            "SELECT MIN(seq) first_seq, MAX(seq) last_seq FROM audit_events "
            "WHERE seq>? AND mac IS NULL AND sealed_tail=1",
            (after_seq,),
        ).fetchone()
        if pending is None or pending["first_seq"] is None:
            return None
        last = self.store.connection.execute(
            "SELECT hash FROM audit_events WHERE seq=?", (pending["last_seq"],)
        ).fetchone()
        detail = {
            "first_seq": int(pending["first_seq"]),
            "last_seq": int(pending["last_seq"]),
            "last_hash": bytes(last["hash"]).hex(),
        }
        return self.append(
            event_id=event_id,
            op="tail_attest",
            detail_json=canonical_text(detail),
            sealed_tail=False,
        )

    def anchor(self, anchor_id: str, destination: str, receipt: str | None = None) -> None:
        row = self.store.connection.execute(
            "SELECT seq,hash FROM audit_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return
        self.store.connection.execute(
            "INSERT INTO anchors(anchor_id,seq,hash,ts,destination,receipt) VALUES (?,?,?,?,?,?)",
            (anchor_id, row["seq"], row["hash"], utc_now(), destination, receipt),
        )

    def who_touched(self, path: str, limit: int = 10) -> list[dict[str, Any]]:
        rows = self.store.connection.execute(
            "SELECT seq,ts,principal_id,op,version_no,decision,reason_code,job,"
            "attest_status,context_verified FROM audit_events "
            "WHERE secret_path=? AND phase IN ('intent','single') "
            "ORDER BY seq DESC LIMIT ?",
            (path, max(1, min(limit, 1000))),
        )
        return [dict(row) for row in rows]

    def dependents(self, path: str) -> dict[str, list[dict[str, Any]]]:
        observed = self.store.connection.execute(
            "SELECT principal_id,orca_run_id,MAX(ts) last_seen,MAX(version_no) version_no "
            "FROM audit_events WHERE secret_path=? AND decision='allow' "
            "AND op IN ('run','inject','use') GROUP BY principal_id,orca_run_id",
            (path,),
        )
        live = self.store.connection.execute(
            "SELECT lease_id,principal_id,refs_json,opened_at FROM leases WHERE closed_at IS NULL "
            "AND refs_json LIKE ?",
            (f'%"path":"{path}"%',),
        )
        secret = self.store.connection.execute(
            "SELECT secret_id FROM secrets WHERE path=?", (path,)
        ).fetchone()
        placements = [] if secret is None else [
            dict(row)
            for row in self.store.connection.execute(
                "SELECT placement_id,sink_kind,locator_json,last_pushed_version,state "
                "FROM placements WHERE secret_id=? AND removed_at IS NULL",
                (secret["secret_id"],),
            )
        ]
        potential_rows = self.store.connection.execute(
            "SELECT grant_id,principal_id,pattern,ops,expires_at FROM grants "
            "WHERE revoked_at IS NULL AND effect='allow'"
        )
        potential = []
        for row in potential_rows:
            pattern = str(row["pattern"])
            if (pattern.endswith("*") and path.startswith(pattern[:-1])) or pattern == path:
                potential.append(dict(row))
        return {
            "observed": [dict(row) for row in observed],
            "live_leases": [dict(row) for row in live],
            "potential": potential,
            "placements": placements,
        }

