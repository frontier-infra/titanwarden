from __future__ import annotations

import io
import json
import os
import unittest
from pathlib import Path
from unittest import mock

from tw.admin import human_context_allowed, read_put_value, verify_broker_peer
from tw.admin_server import AdminService, AdminSession
from tw.seal import SealManager

from support import TEST_PASSPHRASE, initialized_store


class ConsoleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary, self.store, _master, _recovery = initialized_store()
        self.seal = SealManager(self.store)
        self.service = AdminService(self.store, self.seal)
        self.session = AdminSession()

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def authenticate(self) -> None:
        response = self.service.handle(
            self.session, {"op": "auth", "args": {"passphrase": TEST_PASSPHRASE}}, []
        )
        self.assertTrue(response["ok"])

    def test_admin_connection_requires_auth(self) -> None:
        response = self.service.handle(
            self.session, {"op": "put", "args": {"path": "infra/example"}}, []
        )
        self.assertEqual(response["code"], "E_AUTH")

    def test_operator_can_deny_restricted_request_through_admin_service(self) -> None:
        self.authenticate()
        self.store.connection.execute(
            "INSERT INTO principals(principal_id,kind,project,state,created_at) "
            "VALUES ('lead:alpha','lead','alpha','active','now')"
        )
        self.store.connection.execute(
            "INSERT INTO requests(request_id,principal_id,kind,target,ops,reason,needs,state,created_at) "
            "VALUES ('req_client','lead:alpha','access','client/key','inject','test','client','open','now')"
        )
        response = self.service.handle(
            self.session,
            {
                "op": "request_decide",
                "args": {
                    "request_id": "req_client",
                    "decision": "deny",
                    "reason": "client did not approve",
                },
            },
            [],
        )
        self.assertTrue(response["ok"], response)
        state = self.store.connection.execute(
            "SELECT state,decided_by FROM requests WHERE request_id='req_client'"
        ).fetchone()
        self.assertEqual(tuple(state), ("denied", "human:operator"))

        self.store.connection.execute(
            "INSERT INTO requests(request_id,principal_id,kind,target,ops,reason,needs,state,created_at) "
            "VALUES ('req_client_approve','lead:alpha','access','client/key','inject','test','client','open','now')"
        )
        approved = self.service.handle(
            self.session,
            {
                "op": "request_decide",
                "args": {
                    "request_id": "req_client_approve",
                    "decision": "approve",
                    "reason": "client approved",
                },
            },
            [],
        )
        self.assertTrue(approved["ok"], approved)
        grant = self.store.connection.execute(
            "SELECT conditions_json FROM grants WHERE request_id='req_client_approve'"
        ).fetchone()
        self.assertEqual(json.loads(grant[0])["max_class"], "restricted")

    def test_put_and_reveal_to_tty_only(self) -> None:
        self.authenticate()
        read_fd, write_fd = os.pipe()
        os.write(write_fd, b"long-secret-canary")
        os.close(write_fd)
        response = self.service.handle(
            self.session,
            {"op": "put", "args": {"path": "infra/example"}},
            [read_fd],
        )
        os.close(read_fd)
        self.assertTrue(response["ok"])
        master_fd, slave_fd = os.openpty()
        response = self.service.handle(
            self.session,
            {
                "op": "reveal",
                "args": {"path": "infra/example", "reason": "needed for recovery test"},
            },
            [slave_fd],
        )
        self.assertTrue(response["ok"])
        self.assertNotIn("long-secret-canary", str(response))
        self.assertIn(b"long-secret-canary", os.read(master_fd, 1024))
        os.close(slave_fd)
        os.close(master_fd)

    def test_t_noplain_put_exposes_no_value_in_response_audit_or_database(self) -> None:
        self.authenticate()
        value = b"forty-byte-canary-for-t-noplain-1234567"
        read_fd, write_fd = os.pipe()
        os.write(write_fd, value)
        os.close(write_fd)
        response = self.service.handle(
            self.session, {"op": "put", "args": {"path": "infra/canary"}}, [read_fd]
        )
        os.close(read_fd)
        self.assertTrue(response["ok"])
        self.assertNotIn(value, repr(response).encode("utf-8"))
        audit_bytes = b"".join(
            repr(dict(row)).encode("utf-8")
            for row in self.store.connection.execute("SELECT * FROM audit_events")
        )
        self.assertNotIn(value, audit_bytes)
        self.store.checkpoint()
        for path in self.store.home.rglob("*"):
            if path.is_file():
                self.assertNotIn(value, path.read_bytes(), str(path))

    def test_reveal_reason_minimum(self) -> None:
        self.authenticate()
        master_fd, slave_fd = os.openpty()
        response = self.service.handle(
            self.session,
            {"op": "reveal", "args": {"path": "infra/x", "reason": "short"}},
            [slave_fd],
        )
        self.assertEqual(response["code"], "E_BAD_REQUEST")
        os.close(slave_fd)
        os.close(master_fd)

    def test_reveal_reason_is_scrubbed(self) -> None:
        self.authenticate()
        read_fd, write_fd = os.pipe()
        os.write(write_fd, b"long-secret-canary")
        os.close(write_fd)
        self.service.handle(
            self.session, {"op": "put", "args": {"path": "infra/example"}}, [read_fd]
        )
        os.close(read_fd)
        master_fd, slave_fd = os.openpty()
        response = self.service.handle(
            self.session,
            {
                "op": "reveal",
                "args": {
                    "path": "infra/example",
                    "reason": "debugging long-secret-canary incident",
                },
            },
            [slave_fd],
        )
        self.assertTrue(response["ok"])
        detail = self.store.connection.execute(
            "SELECT detail_json,scrubbed FROM audit_events WHERE op='reveal'"
        ).fetchone()
        self.assertNotIn("long-secret-canary", detail["detail_json"])
        self.assertEqual(detail["scrubbed"], 1)
        os.close(slave_fd)
        os.close(master_fd)

    def test_sensitive_ops_refuse_orca_and_local_agents(self) -> None:
        self.assertFalse(
            human_context_allowed(
                "reveal", environ={"ORCA_TERMINAL_HANDLE": "term_x"}, process_listing=""
            )
        )
        self.assertFalse(human_context_allowed("init", environ={}, process_listing="codex worker"))
        self.assertTrue(
            human_context_allowed(
                "init", environ={"SSH_CONNECTION": "local remote"}, process_listing="codex worker"
            )
        )

    def test_reauth_checks_passphrase_without_replacing_keys(self) -> None:
        self.authenticate()
        keys = self.seal.keys
        with mock.patch.object(self.store, "load_keyring") as load_keyring:
            self.authenticate()
        self.assertIs(self.seal.keys, keys)
        load_keyring.assert_not_called()

    def test_plain_auth_cannot_clear_lockdown(self) -> None:
        self.seal.lockdown()
        response = self.service.handle(
            self.session, {"op": "auth", "args": {"passphrase": TEST_PASSPHRASE}}, []
        )
        self.assertEqual(response["code"], "E_SEALED")
        self.assertEqual(self.seal.state, "lockdown")

    def test_panic_seal_wipes_keys_even_if_database_is_read_only(self) -> None:
        self.authenticate()
        keys = self.seal.keys
        assert keys is not None
        buffers = (keys.master, keys.kek, keys.audit, keys.fingerprint)
        self.store.connection.execute("PRAGMA query_only=ON")
        response = self.service.handle(self.session, {"op": "panic_seal", "args": {}}, [])
        self.assertTrue(response["ok"])
        self.assertEqual(self.seal.state, "lockdown")
        self.assertIsNone(self.seal.keys)
        self.assertTrue(all(not any(value) for value in buffers))

    def test_redaction_plaintexts_are_built_once_at_unseal(self) -> None:
        with mock.patch.object(
            self.store, "active_plaintexts", wraps=self.store.active_plaintexts
        ) as active_plaintexts:
            self.authenticate()
            self.service._audit()
            self.service._audit()
        self.assertEqual(active_plaintexts.call_count, 1)

    def test_key_slot_changes_are_audited_on_success_and_failure(self) -> None:
        self.authenticate()
        with mock.patch.object(self.store, "change_passphrase", side_effect=ValueError("short")):
            failed = self.service.handle(
                self.session,
                {"op": "passphrase_change", "args": {"new_passphrase": "short"}},
                [],
            )
        self.assertEqual(failed["code"], "E_BAD_REQUEST")
        with mock.patch.object(self.store, "change_passphrase"):
            changed = self.service.handle(
                self.session,
                {
                    "op": "passphrase_change",
                    "args": {"new_passphrase": "another correct horse battery staple phrase"},
                },
                [],
            )
        self.assertTrue(changed["ok"])
        master_fd, slave_fd = os.openpty()
        rotated = self.service.handle(
            self.session, {"op": "recovery_rotate", "args": {}}, [slave_fd]
        )
        self.assertTrue(rotated["ok"])
        os.close(slave_fd)
        os.close(master_fd)
        rows = self.store.connection.execute(
            "SELECT op,decision FROM audit_events WHERE op IN "
            "('passphrase_change','recovery_rotate') ORDER BY seq"
        ).fetchall()
        self.assertEqual(
            [(row["op"], row["decision"]) for row in rows],
            [
                ("passphrase_change", "error"),
                ("passphrase_change", "allow"),
                ("recovery_rotate", "allow"),
            ],
        )

    def test_admin_session_expires_after_fifteen_minutes(self) -> None:
        self.authenticate()
        assert self.session.authenticated_at is not None
        self.session.authenticated_at -= 901
        response = self.service.handle(self.session, {"op": "freeze", "args": {}}, [])
        self.assertEqual(response["code"], "E_AUTH")

    def test_squatter_peer_is_rejected_before_argv_acceptance(self) -> None:
        with (
            mock.patch("tw.admin.peer_pid", return_value=123),
            mock.patch("tw.admin.service_broker_pid", return_value=456),
            mock.patch(
                "tw.admin.broker_argv",
                return_value=["python3", "-m", "tw.broker", "--home", "/safe/home"],
            ),
        ):
            self.assertFalse(verify_broker_peer(mock.Mock(), Path("/safe/home")))
        with (
            mock.patch("tw.admin.peer_pid", return_value=123),
            mock.patch("tw.admin.service_broker_pid", return_value=123),
            mock.patch(
                "tw.admin.broker_argv",
                return_value=["python3", "squat.py", "-m", "tw.broker", "--home", "/safe/home"],
            ),
        ):
            self.assertFalse(verify_broker_peer(mock.Mock(), Path("/safe/home")))

    def test_put_input_strips_exactly_one_piped_newline(self) -> None:
        stdin = mock.Mock()
        stdin.isatty.return_value = False
        stdin.buffer = io.BytesIO(b"secret\n\n")
        with mock.patch("tw.admin.sys.stdin", stdin):
            self.assertEqual(read_put_value(), b"secret\n")

    def test_put_input_uses_getpass_on_a_tty(self) -> None:
        stdin = mock.Mock()
        stdin.isatty.return_value = True
        with (
            mock.patch("tw.admin.sys.stdin", stdin),
            mock.patch("tw.admin.getpass.getpass", return_value="secret") as prompt,
        ):
            self.assertEqual(read_put_value(), b"secret")
        prompt.assert_called_once()


if __name__ == "__main__":
    unittest.main()
