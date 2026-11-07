import unittest
import json
import os
import sqlite3
import stat
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tw.identity import (
    Attestor,
    Grant,
    IdentityError,
    IdentityStore,
    LeaseIdentity,
    PermissionSet,
    ProcessInfo,
    Scope,
    system_process_resolver,
)


class ScopeTests(unittest.TestCase):
    def test_parse_and_match_table(self):
        scope = Scope.parse(
            "inject+audit:alpha/*,put:alpha/release-*,use:shared/provider@api.example.com"
        )
        cases = [
            ("inject", "alpha/key", None, True),
            ("audit", "alpha/key", None, True),
            ("put", "alpha/release-token", None, True),
            ("put", "alpha/token", None, False),
            ("inject", "beta/key", None, False),
            ("use", "shared/provider", "api.example.com", True),
            ("use", "shared/provider", "other.example.com", False),
        ]
        for operation, path, host, expected in cases:
            with self.subTest(operation=operation, path=path, host=host):
                self.assertEqual(scope.allows(operation, path, host), expected)

    def test_invalid_wildcards_and_ceiling_only_any(self):
        for text in ("inject:*/*", "inject:al*/key", "inject:alpha/a*b"):
            with self.subTest(text=text), self.assertRaises(IdentityError):
                Scope.parse(text)
        with self.assertRaises(IdentityError):
            Scope.parse("any:inject")
        self.assertTrue(Scope.parse("any:inject", allow_any=True).allows("inject", "alpha/key"))

    def test_task_scope_must_be_subset_of_parent_effective_permission(self):
        parent = PermissionSet(
            Scope.parse("any:inject+put+audit", allow_any=True),
            "restricted",
            [Grant(Scope.parse("inject+audit:alpha/*"), "sensitive")],
        )
        parent.require_subset(Scope.parse("inject:alpha/release-*"))
        with self.assertRaises(IdentityError) as caught:
            parent.require_subset(Scope.parse("inject:shared/provider"))
        self.assertEqual(caught.exception.code, "E_SCOPE")

    def test_revoked_parent_grant_immediately_narrows_task(self):
        grant = Grant(Scope.parse("inject:alpha/*"), "sensitive")
        parent = PermissionSet(
            Scope.parse("any:inject+put+audit", allow_any=True), "restricted", [grant]
        )
        task_scope = Scope.parse("inject:alpha/release-token")
        self.assertTrue(parent.allows("inject", "alpha/release-token", "standard", task_scope))
        grant.revoked = True
        self.assertFalse(parent.allows("inject", "alpha/release-token", "standard", task_scope))

    def test_deny_does_not_depend_on_path_existence(self):
        permission = PermissionSet(
            Scope.parse("any:inject", allow_any=True),
            "restricted",
            [Grant(Scope.parse("inject:alpha/*"), "sensitive")],
        )
        messages = []
        for path in ("beta/existing", "beta/absent"):
            with self.assertRaises(IdentityError) as caught:
                permission.require("inject", path, "standard")
            messages.append(str(caught.exception))
        self.assertEqual(messages[0], messages[1])
        self.assertNotIn("existing", messages[0])

    def test_broker_internal_paths_are_never_granted(self):
        permission = PermissionSet(
            Scope.parse("any:inject", allow_any=True),
            "restricted",
            [Grant(Scope.parse("inject:infra/*"), "restricted")],
        )
        self.assertFalse(permission.allows("inject", "infra/broker-sender", "standard"))


class AttestationTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "darwin", "real resolver is macOS specific")
    def test_real_process_resolver_tolerates_unreadable_ancestors(self):
        result = Attestor(
            broker_pid=-1,
            process_resolver=system_process_resolver,
            handle_principals={},
            leases_by_child={},
        ).attest(os.getpid(), "lead:test")
        self.assertIn(result.status, {"unavailable", "unresolved", "orphan"})
    def test_walk_uses_topmost_handle_and_not_child_claim(self):
        processes = {
            40: ProcessInfo(40, 30, {"ORCA_TERMINAL_HANDLE": "handle-b"}, "/bin/tool"),
            30: ProcessInfo(30, 20, {}, "/bin/shell"),
            20: ProcessInfo(20, 10, {"ORCA_TERMINAL_HANDLE": "handle-a"}, "/bin/orca"),
            10: ProcessInfo(10, 1, {}, "/sbin/launchd"),
            1: ProcessInfo(1, 0, {}, "/sbin/launchd"),
        }
        attestor = Attestor(
            broker_pid=99,
            process_resolver=processes.get,
            handle_principals={"handle-a": "lead:alpha", "handle-b": "lead:beta"},
            leases_by_child={},
        )
        result = attestor.attest(40, "lead:alpha")
        self.assertEqual(result.status, "match")
        self.assertEqual(result.attested_handle, "handle-a")
        self.assertTrue(result.context_verified)

    def test_mismatch_is_recorded_but_not_denied_for_pane_call(self):
        processes = {
            40: ProcessInfo(40, 20, {}, "/bin/tool"),
            20: ProcessInfo(20, 10, {"ORCA_TERMINAL_HANDLE": "handle-a"}, "/bin/orca"),
            10: ProcessInfo(10, 1, {}, "/sbin/launchd"),
            1: ProcessInfo(1, 0, {}, "/sbin/launchd"),
        }
        attestor = Attestor(99, processes.get, {"handle-a": "lead:alpha"}, {})
        result = attestor.attest(40, "lead:beta")
        self.assertEqual(result.status, "mismatch")
        self.assertFalse(result.context_verified)

    def test_nested_walk_stops_at_broker_and_uses_parent_lease(self):
        class UnreadableEnvironment(dict):
            def get(self, *_args, **_kwargs):
                raise AssertionError("nested environment must not be read")

        processes = {
            130: ProcessInfo(130, 120, UnreadableEnvironment(), "/bin/tw"),
            120: ProcessInfo(120, 99, UnreadableEnvironment(), "/bin/script"),
            99: ProcessInfo(99, 1, {}, "/bin/broker"),
        }
        lease = LeaseIdentity("lea_parent", 120, "tok_a", "lead:alpha", True)
        attestor = Attestor(99, processes.get, {"forged": "lead:beta"}, {120: lease})
        result = attestor.attest(130, None)
        self.assertEqual(result.status, "nested")
        self.assertEqual(result.principal_id, "lead:alpha")
        self.assertEqual(result.parent_lease_id, "lea_parent")
        self.assertTrue(result.context_verified)
        self.assertIsNone(result.attested_handle)

    def test_nested_call_presenting_another_principals_token_is_denied(self):
        processes = {
            130: ProcessInfo(130, 120, {}, "/bin/tw"),
            120: ProcessInfo(120, 99, {}, "/bin/script"),
            99: ProcessInfo(99, 1, {}, "/bin/broker"),
        }
        lease = LeaseIdentity("lea_parent", 120, "tok_a", "lead:alpha", False)
        attestor = Attestor(99, processes.get, {}, {120: lease})
        with self.assertRaises(IdentityError) as caught:
            attestor.attest(130, "lead:beta")
        self.assertEqual(caught.exception.code, "E_IDENTITY_MISMATCH")

    def test_orphaned_lease_claim_does_not_restore_nested_identity(self):
        processes = {
            130: ProcessInfo(130, 1, {}, "/bin/tw"),
            1: ProcessInfo(1, 0, {}, "/sbin/launchd"),
        }
        attestor = Attestor(99, processes.get, {}, {})
        result = attestor.attest(130, None)
        self.assertEqual(result.status, "unresolved")
        self.assertIsNone(result.principal_id)


class IdentityStoreTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(dir="/tmp", prefix="twidentity")
        self.home = Path(self.tempdir.name)
        self.connection = sqlite3.connect(":memory:")
        schema = Path(__file__).parents[1] / "tw" / "schema.sql"
        self.connection.executescript(schema.read_text())
        self.notifications = []
        self.identities = IdentityStore(
            self.connection,
            self.home,
            desk_notify=lambda kind, subject, body: self.notifications.append(
                (kind, subject, body)
            ),
        )

    def tearDown(self):
        self.connection.close()
        self.tempdir.cleanup()

    def _sync_alpha(self):
        return self.identities.roster_sync(
            {
                "team": [
                    {"id": "master", "type": "ai", "run": "run-master"},
                    {"id": "alpha", "type": "ai", "run": "run-alpha"},
                ]
            },
            [
                {"runId": "run-master", "coordinatorTerminalHandle": "master_handle"},
                {"runId": "run-alpha", "coordinatorTerminalHandle": "alpha_handle"},
            ],
        )

    def test_roster_sync_creates_principals_projects_and_guard_is_atomic(self):
        entries = [{"id": "master", "type": "ai", "run": "master-run"}]
        runs = [{"runId": "master-run", "coordinatorTerminalHandle": "master_handle"}]
        for index in range(4):
            entries.append({"id": f"lead{index}", "type": "ai", "run": f"run-{index}"})
            runs.append(
                {"runId": f"run-{index}", "coordinatorTerminalHandle": f"handle_{index}"}
            )
        result = self.identities.roster_sync({"team": entries}, runs)
        self.assertEqual(len(result["added"]), 5)
        guarded = self.identities.roster_sync({"team": entries[:1]}, runs[:1])
        self.assertEqual(len(guarded["refused"]), 4)
        active = self.connection.execute(
            "SELECT count(*) FROM principals WHERE state != 'disabled'"
        ).fetchone()[0]
        self.assertEqual(active, 5)
        self.assertEqual(self.notifications[-1][0], "ask")

    def test_real_roster_shape_uses_ai_array(self):
        entries = [{"id": "master", "run": "master-run"}]
        entries.extend({"id": f"project{index}", "run": f"run-{index}"} for index in range(25))
        result = self.identities.roster_sync({"version": "1", "ai": entries}, [])
        self.assertEqual(len(result["added"]), 26)

    def test_unrostered_run_posts_info_but_creates_no_principal(self):
        self.identities.roster_sync(
            {"team": [{"id": "master", "type": "ai", "run": "master-run"}]},
            [
                {"runId": "master-run", "coordinatorTerminalHandle": "master_handle"},
                {"runId": "mystery", "name": "lead mystery"},
            ],
        )
        self.assertEqual(self.notifications[-1][0], "info")
        count = self.connection.execute(
            "SELECT count(*) FROM principals WHERE principal_id LIKE 'lead:%'"
        ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_lead_issue_writes_ceiling_binding_and_one_default_grant(self):
        self._sync_alpha()
        first = self.identities.issue_token(
            "lead:alpha", "lead", created_by="master", handle="alpha_handle"
        )
        self.identities.issue_token(
            "lead:alpha", "lead", created_by="master", handle="alpha_handle"
        )
        row = self.connection.execute(
            "SELECT scope_json FROM tokens WHERE token_id=?", (first["token_id"],)
        ).fetchone()
        self.assertEqual(
            json.loads(row[0]),
            {"ceiling": "any:inject+put+audit", "max_class": "restricted"},
        )
        grants = self.connection.execute(
            "SELECT count(*) FROM grants WHERE principal_id='lead:alpha' "
            "AND granted_by='system:default'"
        ).fetchone()[0]
        self.assertEqual(grants, 1)
        self.assertEqual(stat.S_IMODE(os.stat(first["file_path"]).st_mode), 0o600)
        binding_path = self.home / "panes" / "alpha_handle"
        self.assertEqual(stat.S_IMODE(binding_path.stat().st_mode), 0o600)

    def test_task_scope_and_live_parent_grants(self):
        self._sync_alpha()
        parent = self.identities.issue_token(
            "lead:alpha", "lead", created_by="master", handle="alpha_handle"
        )
        expires = (datetime.now(timezone.utc) + timedelta(hours=8)).isoformat().replace(
            "+00:00", "Z"
        )
        task = self.identities.issue_task_token(
            parent["token_id"], "dispatch1", "worker_handle", "inject:alpha/release-*", expires
        )
        permission, ceiling = self.identities.permission_for_token(task["token_id"])
        self.assertTrue(permission.allows("inject", "alpha/release-key", "standard", ceiling))
        with self.assertRaises(IdentityError) as caught:
            self.identities.issue_task_token(
                parent["token_id"],
                "dispatch2",
                "worker_handle_2",
                "inject:shared/provider",
                expires,
            )
        self.assertEqual(caught.exception.code, "E_SCOPE")
        self.connection.execute(
            "UPDATE grants SET revoked_at='2026-01-01T00:00:00.000Z' WHERE principal_id='lead:alpha'"
        )
        permission, ceiling = self.identities.permission_for_token(task["token_id"])
        self.assertFalse(permission.allows("inject", "alpha/release-key", "standard", ceiling))
        self.identities.revoke_token(parent["token_id"], "test")
        with self.assertRaises(IdentityError) as revoked:
            self.identities.permission_for_token(task["token_id"])
        self.assertEqual(revoked.exception.code, "E_AUTH")

    def test_idle_expiry_is_enforced(self):
        self._sync_alpha()
        token = self.identities.issue_token(
            "lead:alpha", "lead", created_by="master", handle="alpha_handle"
        )
        self.connection.execute(
            "UPDATE tokens SET created_at='2020-01-01T00:00:00.000Z',last_used_at=NULL "
            "WHERE token_id=?",
            (token["token_id"],),
        )
        with self.assertRaises(IdentityError) as caught:
            self.identities.permission_for_token(token["token_id"])
        self.assertEqual(caught.exception.code, "E_AUTH")


if __name__ == "__main__":
    unittest.main()
