from __future__ import annotations

import json
import sqlite3
import unittest

from tw.audit import AuditError, AuditLog

from support import initialized_store


class AuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary, self.store, master, _recovery = initialized_store()
        self.keys = self.store.load_keyring(master)

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def test_chain_and_append_only_triggers(self) -> None:
        audit = AuditLog(self.store, mac_key=self.keys["audit_mac"][1])
        audit.append(event_id="evt_one", op="put", secret_path="test/name")
        audit.append(event_id="evt_two", op="run", secret_path="test/name")
        self.assertTrue(audit.verify().ok)
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.connection.execute("UPDATE audit_events SET op='x' WHERE seq=1")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.connection.execute("DELETE FROM audit_events WHERE seq=1")

    def test_sealed_tail_attestation(self) -> None:
        sealed = AuditLog(self.store)
        sealed.append(event_id="evt_sealed", op="run", decision="deny", reason_code="E_SEALED")
        audit = AuditLog(self.store, mac_key=self.keys["audit_mac"][1])
        self.assertFalse(audit.verify().ok)
        audit.attest_sealed_tail("evt_attest")
        self.assertTrue(audit.verify().ok)

    def test_tail_attestation_must_be_signed_and_match_covered_hash(self) -> None:
        sealed = AuditLog(self.store)
        sealed.append(event_id="evt_sealed", op="run", decision="deny")
        forged = sealed.append(
            event_id="evt_attest",
            op="tail_attest",
            sealed_tail=False,
            detail_json=json.dumps(
                {"first_seq": 1, "last_seq": 1, "last_hash": "00" * 32}
            ),
        )
        result = AuditLog(self.store, mac_key=self.keys["audit_mac"][1]).verify()
        self.assertFalse(result.ok)
        self.assertEqual(result.seq, forged["seq"])
        self.assertEqual(result.error, "unsigned tail attestation")

    def test_unsigned_non_sealed_row_is_never_attested(self) -> None:
        AuditLog(self.store).append(
            event_id="evt_injected", op="run", decision="deny", sealed_tail=False
        )
        audit = AuditLog(self.store, mac_key=self.keys["audit_mac"][1])
        self.assertFalse(audit.verify(allow_unattested_sealed_tail=True).ok)

    def test_boolean_fields_hash_as_sql_integers(self) -> None:
        audit = AuditLog(self.store, mac_key=self.keys["audit_mac"][1])
        audit.append(event_id="evt_bool", op="run", shell=True)
        self.assertTrue(audit.verify().ok)

    def test_t_audit_1_detects_edits_and_truncation(self) -> None:
        audit = AuditLog(self.store, mac_key=self.keys["audit_mac"][1])
        for index in range(12):
            audit.append(event_id=f"evt_{index}", op="run")
        audit.anchor("test-anchor", "test")
        self.store.connection.execute("DROP TRIGGER audit_no_update")
        self.store.connection.execute("UPDATE audit_events SET op='edited' WHERE seq=3")
        edited = audit.verify()
        self.assertFalse(edited.ok)
        self.assertEqual(edited.seq, 3)
        self.store.connection.execute("UPDATE audit_events SET op='run' WHERE seq=3")
        self.store.connection.execute("DROP TRIGGER audit_no_delete")
        self.store.connection.execute("DELETE FROM audit_events WHERE seq>2")
        truncated = audit.verify()
        self.assertFalse(truncated.ok)
        self.assertEqual(truncated.error, "audit truncated before anchor")

    def test_t_audit_2_maps_read_only_write_to_e_audit(self) -> None:
        self.store.connection.execute("PRAGMA query_only=ON")
        with self.assertRaises(AuditError) as raised:
            AuditLog(self.store, mac_key=self.keys["audit_mac"][1]).append(
                event_id="evt_read_only", op="run"
            )
        self.assertEqual(raised.exception.code, "E_AUDIT")

    def test_scrubber(self) -> None:
        def scrub(value: str) -> tuple[str, bool]:
            return value.replace("canary", "[tw:redacted]"), "canary" in value

        audit = AuditLog(self.store, mac_key=self.keys["audit_mac"][1], scrub=scrub)
        audit.append(
            event_id="evt_scrub",
            op="request",
            detail_json=json.dumps({"reason": "canary"}),
        )
        row = self.store.connection.execute("SELECT * FROM audit_events").fetchone()
        self.assertNotIn("canary", row["detail_json"])
        self.assertEqual(row["scrubbed"], 1)


if __name__ == "__main__":
    unittest.main()

