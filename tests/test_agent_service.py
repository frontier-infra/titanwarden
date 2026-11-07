import os
import json
import sqlite3
import sys
import tempfile
import secrets
import unittest
from unittest import mock
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

from tw.agent_service import (
    AgentService,
    AgentServiceError,
    _find_worker_handle,
    _read_fd_limited,
)
from tw.identity import ProcessInfo
from tw.audit import AuditLog


class FakeStore:
    def __init__(self, home):
        self.home = home
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript((Path(__file__).parents[1] / "tw" / "schema.sql").read_text())
        self.values = {}
        self.counter = 0

    def new_id(self, prefix):
        self.counter += 1
        return prefix + f"test{self.counter:08d}"

    @contextmanager
    def transaction(self, **_options):
        self.connection.execute("BEGIN")
        try:
            yield self.connection
        except BaseException:
            self.connection.rollback()
            raise
        else:
            self.connection.commit()

    def put_secret(self, path, value, **options):
        project, _name = path.split("/", 1)
        self.connection.execute(
            "INSERT OR IGNORE INTO projects(slug,change_policy,created_at) VALUES (?,'auto','now')",
            (project,),
        )
        row = self.connection.execute("SELECT secret_id FROM secrets WHERE path=?", (path,)).fetchone()
        if row is None:
            secret_id = self.new_id("sec_")
            self.connection.execute(
                "INSERT INTO secrets(secret_id,path,project,class,kind,short,state,created_at,created_by) "
                "VALUES (?,?,?,?,?,0,'active','now',?)",
                (
                    secret_id,
                    path,
                    project,
                    options.get("secret_class", "sensitive"),
                    options.get("kind", "opaque"),
                    options.get("principal_id", "test"),
                ),
            )
        else:
            secret_id = row[0]
        version = self.connection.execute(
            "SELECT coalesce(max(version_no),0)+1 FROM secret_versions WHERE secret_id=?",
            (secret_id,),
        ).fetchone()[0]
        self.connection.execute(
            "UPDATE secret_versions SET state='grace' WHERE secret_id=? AND state='active'",
            (secret_id,),
        )
        self.connection.execute(
            "INSERT INTO secret_versions(version_id,secret_id,version_no,state,ciphertext,nonce,"
            "wrapped_dek,dek_nonce,kek_id,fingerprint,length,source,created_at,created_by,activated_at) "
            "VALUES (?,?,?,'active',x'',x'',x'',x'','key',x'00',?,?, 'now',?,'now')",
            (
                self.new_id("ver_"),
                secret_id,
                version,
                len(value),
                options.get("source", "put"),
                options.get("principal_id", "test"),
            ),
        )
        self.values[(path, version)] = bytes(value)
        return {"path": path, "version_no": version, "fingerprint_prefix": "0000"}

    def reveal_secret(self, path, *, version_no=None, **_options):
        if version_no is None:
            version_no = self.connection.execute(
                "SELECT v.version_no FROM secrets s JOIN secret_versions v ON v.secret_id=s.secret_id "
                "WHERE s.path=? AND v.state='active'",
                (path,),
            ).fetchone()[0]
        return self.values[(path, version_no)]


class AgentServiceTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(dir="/tmp", prefix="twservice")
        self.home = Path(self.tempdir.name)
        self.store = FakeStore(self.home)
        self.seal = SimpleNamespace(
            state="unsealed",
            frozen=False,
            keys=SimpleNamespace(
                kek_id="kek", kek=bytearray(32), audit_id="audit", audit=bytearray(32),
                fingerprint_id="fingerprint", fingerprint=bytearray(32)
            ),
        )
        self.processes = {
            40: ProcessInfo(40, 20, {}, "/bin/tool"),
            20: ProcessInfo(20, 10, {"ORCA_TERMINAL_HANDLE": "alpha_handle"}, "/bin/orca"),
            10: ProcessInfo(10, 1, {}, "/sbin/launchd"),
            1: ProcessInfo(1, 0, {}, "/sbin/launchd"),
        }
        self.service = AgentService(
            self.store,
            self.seal,
            home=self.home,
            broker_pid=99,
            process_resolver=self.processes.get,
        )
        self.service.identities.roster_sync(
            {"ai": [{"id": "alpha", "run": "run-alpha"}]},
            [{"runId": "run-alpha", "coordinatorTerminalHandle": "alpha_handle"}],
        )
        receipt = self.service.identities.issue_token(
            "lead:alpha", "lead", created_by="master", handle="alpha_handle"
        )
        self.token_id = receipt["token_id"]
        self.token = Path(receipt["file_path"]).read_text().strip()

    def tearDown(self):
        self.service.close()
        self.store.connection.close()
        self.tempdir.cleanup()

    def _request(self, op, args):
        return {"v": 1, "op": op, "request_id": "request", "token": self.token, "args": args, "ctx": {}}

    def test_status_records_matching_attestation(self):
        result = self.service.status(self._request("status", {}), 40)
        self.assertEqual(result["principal"], "lead:alpha")
        self.assertEqual(result["attest_status"], "match")
        self.assertTrue(result["context_verified"])

    def test_pane_mismatch_proceeds_and_is_recorded(self):
        self.store.connection.execute(
            "INSERT INTO principals(principal_id,kind,project,worktree_roots_json,state,created_at) "
            "VALUES ('lead:beta','lead','beta','[]','active','now')"
        )
        self.store.connection.execute(
            "INSERT INTO pane_bindings(handle,token_id,principal_id,created_at,created_by) "
            "VALUES ('beta_handle',?,'lead:beta','now','test')",
            (self.token_id,),
        )
        self.processes[20] = ProcessInfo(
            20, 10, {"ORCA_TERMINAL_HANDLE": "beta_handle"}, "/bin/orca"
        )
        result = self.service.status(self._request("status", {}), 40)
        self.assertEqual(result["attest_status"], "mismatch")
        self.assertFalse(result["context_verified"])
        event = self.store.connection.execute(
            "SELECT attest_status,attested_handle,context_verified FROM audit_events "
            "ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        self.assertEqual(tuple(event), ("mismatch", "beta_handle", 0))

    def test_worker_handle_lookup_matches_dispatch_not_neighbor(self):
        payload = {
            "result": {
                "workers": [
                    {"dispatchId": "other", "agentTerminalHandle": "wrong"},
                    {"dispatchId": "wanted", "agentTerminalHandle": "right"},
                ]
            }
        }
        self.assertEqual(_find_worker_handle(payload, "wanted"), "right")

    def test_run_injects_and_redacts_without_returning_plaintext(self):
        value = os.urandom(40).hex().encode()
        self.store.put_secret(
            "alpha/key", value, principal_id="lead:alpha", secret_class="sensitive"
        )
        stdout = tempfile.TemporaryFile()
        stderr = tempfile.TemporaryFile()
        stdin = open(os.devnull, "rb")
        self.addCleanup(stdout.close)
        self.addCleanup(stderr.close)
        self.addCleanup(stdin.close)
        request = self._request(
            "run",
            {
                "argv": [sys.executable, "-c", "import os;print(os.environ['X'])"],
                "cwd": str(self.home),
                "environment": os.environ.copy(),
                "env_refs": {"X": "alpha/key"},
                "fd_refs": {},
                "soft_refs": {},
            },
        )
        handle = self.service.start_run(
            request, 40, [stdin.fileno(), stdout.fileno(), stderr.fileno()]
        )
        self.assertEqual(handle.wait(), 0)
        stdout.seek(0)
        output = stdout.read()
        self.assertNotIn(value, output)
        self.assertIn(b"[tw:alpha/key]", output)
        lease = self.store.connection.execute(
            "SELECT closed_at,context_verified FROM leases WHERE lease_id=?",
            (handle.request.lease_id,),
        ).fetchone()
        self.assertIsNotNone(lease[0])
        self.assertEqual(lease[1], 1)
        touched = self.store.connection.execute(
            "SELECT secret_path FROM audit_events WHERE op='run' AND phase='intent' "
            "AND secret_path IS NOT NULL"
        ).fetchall()
        self.assertEqual([row[0] for row in touched], ["alpha/key"])
        observed = AuditLog(self.store).dependents("alpha/key")["observed"]
        self.assertEqual(observed[0]["orca_run_id"], "run-alpha")

    def test_redaction_values_are_decrypted_once_for_both_output_streams(self):
        self.store.put_secret(
            "alpha/cached", b"cached-secret-value", principal_id="lead:alpha"
        )
        self.service.clear_redaction_values()
        with mock.patch.object(
            self.store, "reveal_secret", wraps=self.store.reveal_secret
        ) as reveal:
            self.service._redactor_for("lead:alpha")
            self.service._redactor_for("lead:alpha")
        self.assertEqual(reveal.call_count, 1)

    def test_short_secret_delivery_requires_console_override(self):
        self.store.put_secret(
            "alpha/short", b"short", principal_id="lead:alpha", secret_class="sensitive"
        )
        self.store.connection.execute(
            "UPDATE secrets SET short=1 WHERE path='alpha/short'"
        )
        stdout = tempfile.TemporaryFile()
        stderr = tempfile.TemporaryFile()
        stdin = open(os.devnull, "rb")
        self.addCleanup(stdout.close)
        self.addCleanup(stderr.close)
        self.addCleanup(stdin.close)
        request = self._request(
            "run",
            {
                "argv": [sys.executable, "-c", "pass"],
                "cwd": str(self.home),
                "environment": os.environ.copy(),
                "env_refs": {"X": "alpha/short"},
                "fd_refs": {},
                "soft_refs": {},
            },
        )
        with self.assertRaises(AgentServiceError) as caught:
            self.service.start_run(
                request, 40, [stdin.fileno(), stdout.fileno(), stderr.fileno()]
            )
        self.assertEqual(caught.exception.code, "E_DENIED")

    def test_nested_call_binds_to_parent_lease_and_ignores_handle_claim(self):
        self.store.connection.execute(
            "INSERT INTO leases(lease_id,token_id,principal_id,op,refs_json,pid,context_verified,opened_at) "
            "VALUES ('lea_parent',?, 'lead:alpha','run','[]',120,1,'now')",
            (self.token_id,),
        )
        nested_processes = {
            130: ProcessInfo(130, 120, {"ORCA_TERMINAL_HANDLE": "forged"}, "/bin/tw"),
            120: ProcessInfo(120, 99, {"ORCA_TERMINAL_HANDLE": "forged"}, "/bin/child"),
        }
        self.service.process_resolver = nested_processes.get
        request = {"v": 1, "op": "status", "request_id": "nested", "token": None, "args": {}, "ctx": {"lease": "wrong"}}
        result = self.service.status(request, 130)
        self.assertEqual(result["principal"], "lead:alpha")
        self.assertEqual(result["attest_status"], "nested")
        self.assertTrue(result["context_verified"])

    def test_cross_project_default_grant_and_fo_refusal(self):
        self.store.connection.execute(
            "INSERT INTO projects(slug,change_policy,created_at) VALUES ('shared','auto','now')"
        )
        self.store.put_secret(
            "shared/provider",
            os.urandom(40),
            principal_id="master",
            secret_class="standard",
        )
        permission, ceiling = self.service.identities.permission_for_token(self.token_id)
        self.assertFalse(permission.allows("inject", "shared/provider", "standard", ceiling))
        self.service.request_default_delay = 0
        result = self.service.handle(
            self._request(
                "request",
                {
                    "kind": "access",
                    "target": "shared/provider",
                    "ops": "inject",
                    "reason": "integration test",
                    "ttl": None,
                },
            ),
            40,
        )
        row = self.store.connection.execute(
            "SELECT state FROM requests WHERE request_id=?", (result["request_id"],)
        ).fetchone()
        self.assertEqual(row[0], "defaulted")
        permission, ceiling = self.service.identities.permission_for_token(self.token_id)
        self.assertTrue(permission.allows("inject", "shared/provider", "standard", ceiling))

        self.store.connection.execute(
            "INSERT INTO projects(slug,change_policy,created_at) "
            "VALUES ('client','client_approval_required','now')"
        )
        self.store.put_secret(
            "client/client-key",
            os.urandom(40),
            principal_id="master",
            secret_class="restricted",
        )
        fo_result = self.service.handle(
            self._request(
                "request",
                {
                    "kind": "access",
                    "target": "client/client-key",
                    "ops": "inject",
                    "reason": "must wait",
                },
            ),
            40,
        )
        fo_row = self.store.connection.execute(
            "SELECT state,default_at FROM requests WHERE request_id=?", (fo_result["request_id"],)
        ).fetchone()
        self.assertEqual(tuple(fo_row), ("open", None))
        permission, ceiling = self.service.identities.permission_for_token(self.token_id)
        self.assertFalse(permission.allows("inject", "client/client-key", "restricted", ceiling))

    def test_request_operations_cannot_smuggle_another_scope(self):
        with self.assertRaises(AgentServiceError) as caught:
            self.service.handle(
                self._request(
                    "request",
                    {
                        "kind": "access",
                        "target": "alpha/key",
                        "ops": "inject:beta/*,inject",
                        "reason": "malformed operations",
                    },
                ),
                40,
            )
        self.assertEqual(caught.exception.code, "E_BAD_REQUEST")
        self.assertEqual(
            self.store.connection.execute("SELECT count(*) FROM requests").fetchone()[0], 0
        )

    def test_put_checks_existing_class_and_rejects_class_changes(self):
        self.store.put_secret(
            "alpha/restricted",
            b"original-secret-value",
            principal_id="master",
            secret_class="restricted",
        )
        read_fd, write_fd = os.pipe()
        os.write(write_fd, b"replacement-secret")
        os.close(write_fd)
        self.addCleanup(os.close, read_fd)
        with self.assertRaises(AgentServiceError) as caught:
            self.service.put(
                self._request(
                    "put", {"path": "alpha/restricted", "class": "standard"}
                ),
                40,
                [read_fd],
            )
        self.assertEqual(caught.exception.code, "E_POLICY")

    def test_put_reader_enforces_size_and_deadline(self):
        with tempfile.TemporaryFile() as source:
            source.write(b"x" * (1024 * 1024 + 1))
            source.seek(0)
            with self.assertRaises(AgentServiceError) as too_large:
                _read_fd_limited(source.fileno())
        self.assertEqual(too_large.exception.code, "E_BAD_REQUEST")

        read_fd, write_fd = os.pipe()
        try:
            with self.assertRaises(AgentServiceError) as timed_out:
                _read_fd_limited(read_fd, timeout=0.01)
        finally:
            os.close(read_fd)
            os.close(write_fd)
        self.assertEqual(timed_out.exception.code, "E_BUSY")

    def test_task_token_dispatch_is_resolved_inside_lead_run(self):
        calls = []
        self.service.worker_handle_resolver = lambda dispatch, run: calls.append(
            (dispatch, run)
        ) or "worker_handle"
        result = self.service.handle(
            self._request(
                "task_token_issue",
                {"dispatch": "dispatch-one", "scope": "inject:alpha/*", "ttl": "1h"},
            ),
            40,
        )
        self.assertEqual(calls, [("dispatch-one", "run-alpha")])
        self.assertEqual(result["bound_handle"], "worker_handle")

    def test_roster_sync_reads_the_home_roster_file_by_default(self):
        (self.home / "roster.json").write_text(
            json.dumps({"ai": [{"id": "alpha", "run": "run-alpha"}, {"id": "beta", "run": "run-beta"}]}),
            encoding="utf-8",
        )
        with mock.patch("tw.agent_service._orca_run_rows", return_value=[]):
            result = self.service._master_operation("roster_sync", {})
        self.assertIn("lead:beta", result["added"])

    def test_roster_sync_default_path_stays_inside_home(self):
        with mock.patch("tw.agent_service._orca_run_rows", return_value=[]):
            with self.assertRaises(FileNotFoundError) as caught:
                self.service._master_operation("roster_sync", {"path": ""})
        self.assertEqual(Path(caught.exception.filename), self.home / "roster.json")

    def test_roster_sync_honors_an_explicit_path(self):
        roster = self.home / "elsewhere" / "custom-roster.json"
        roster.parent.mkdir()
        roster.write_text(
            json.dumps({"ai": [{"id": "alpha", "run": "run-alpha"}, {"id": "gamma", "run": "run-gamma"}]}),
            encoding="utf-8",
        )
        with mock.patch("tw.agent_service._orca_run_rows", return_value=[]):
            result = self.service._master_operation("roster_sync", {"path": str(roster)})
        self.assertIn("lead:gamma", result["added"])

    def test_roster_client_roots_feed_production_import_policy(self):
        client_root = self.home / "fake-client"
        source = client_root / ".env"
        source.parent.mkdir()
        source.write_text("TOKEN=fake-test-value-only\n")
        self.service.identities.roster_sync(
            {
                "ai": [
                    {"id": "alpha", "run": "run-alpha"},
                    {"id": "client", "run": "run-client"},
                ]
            },
            [
                {"runId": "run-alpha", "coordinatorTerminalHandle": "alpha_handle"},
                {"runId": "run-client", "worktreeRoots": [str(client_root)]},
            ],
        )
        before = source.read_bytes(), source.stat().st_mode
        with self.assertRaises(Exception) as caught:
            self.service.import_env(
                self._request("import_env", {"path": str(source), "project": "alpha"}),
                40,
            )
        self.assertEqual(getattr(caught.exception, "code", None), "E_POLICY")
        self.assertEqual((source.read_bytes(), source.stat().st_mode), before)
        self.assertFalse(source.with_name(".env.tw").exists())

    def test_import_duplicate_outside_scope_does_not_reveal_link(self):
        self.store.connection.execute(
            "INSERT INTO projects(slug,change_policy,created_at) VALUES ('beta','auto','now')"
        )
        self.store.put_secret(
            "beta/hidden", b"same-secret-value", principal_id="master"
        )
        source = self.home / "alpha.env"
        source.write_text("TOKEN=same-secret-value\n")
        with mock.patch("tw.agent_service.crypto.fingerprint", return_value=b"\x00"):
            result = self.service.import_env(
                self._request("import_env", {"path": str(source), "project": "alpha"}),
                40,
            )
        self.assertNotIn("linked_to", result["stored"][0])
        self.assertEqual(result["stored"][0]["path"], "alpha/token")

    def test_claimed_context_is_bounded_and_scrubbed(self):
        value = b"context-secret-value"
        self.store.put_secret("alpha/context", value, principal_id="lead:alpha")
        request = self._request("status", {})
        request["ctx"] = {"cwd": value.decode(), "extra": "x" * 10000}
        self.service.status(request, 40)
        claimed = self.store.connection.execute(
            "SELECT claimed_json FROM audit_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()[0]
        self.assertNotIn(value.decode(), claimed)
        self.assertNotIn("extra", json.loads(claimed))
        self.assertLessEqual(len(claimed), 4096)

    def test_request_reason_is_scrubbed_before_storage_and_flagged(self):
        value = secrets.token_urlsafe(32).encode()
        self.store.put_secret(
            "alpha/key", value, principal_id="lead:alpha", secret_class="sensitive"
        )
        result = self.service.handle(
            self._request(
                "request",
                {
                    "kind": "rotate",
                    "target": "alpha/key",
                    "reason": "rotate " + value.decode(),
                },
            ),
            40,
        )
        reason = self.store.connection.execute(
            "SELECT reason FROM requests WHERE request_id=?", (result["request_id"],)
        ).fetchone()[0]
        self.assertNotIn(value.decode(), reason)
        event = self.store.connection.execute(
            "SELECT scrubbed,detail_json FROM audit_events WHERE request_id=?",
            (result["request_id"],),
        ).fetchone()
        self.assertEqual(event[0], 1)
        self.assertNotIn(value.decode(), event[1])

    def test_production_desk_answer_path_applies_direct_operator_deny(self):
        self.store.put_secret(
            "alpha/desk", b"desk-secret-value", principal_id="lead:alpha"
        )
        self.service.desk_notify = lambda *_args: "desk-one"
        result = self.service.handle(
            self._request(
                "request",
                {
                    "kind": "access",
                    "target": "alpha/desk",
                    "ops": "inject",
                    "reason": "desk denial test",
                },
            ),
            40,
        )
        changed = self.service.apply_desk_answers(
            [
                {
                    "id": "desk-one",
                    "thread": [
                        {
                            "kind": "answer",
                            "author": "Operator",
                            "author_kind": "person",
                            "text": "Deny",
                        }
                    ],
                }
            ]
        )
        self.assertEqual(changed, 1)
        state = self.store.connection.execute(
            "SELECT state FROM requests WHERE request_id=?", (result["request_id"],)
        ).fetchone()[0]
        self.assertEqual(state, "denied")

        self.service.desk_notify = lambda *_args: "desk-two"
        pending = self.service.handle(
            self._request(
                "request",
                {
                    "kind": "access",
                    "target": "alpha/desk",
                    "ops": "inject",
                    "reason": "unsigned approval remains advisory",
                },
            ),
            40,
        )
        self.service.apply_desk_answers(
            [
                {
                    "id": "desk-two",
                    "status": "answered",
                    "thread": [
                        {
                            "kind": "answer",
                            "author": "Operator",
                            "author_kind": "person",
                            "text": "Approve",
                        }
                    ],
                }
            ]
        )
        state = self.store.connection.execute(
            "SELECT state FROM requests WHERE request_id=?", (pending["request_id"],)
        ).fetchone()[0]
        self.assertEqual(state, "open")
        ignored = self.store.connection.execute(
            "SELECT reason_code FROM audit_events WHERE op='desk_answer_ignored' "
            "AND request_id=?",
            (pending["request_id"],),
        ).fetchone()
        self.assertEqual(ignored[0], "unsigned_approval_advisory")


if __name__ == "__main__":
    unittest.main()
