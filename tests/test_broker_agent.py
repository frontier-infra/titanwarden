import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
from pathlib import Path

from tw.broker import Broker, main as broker_main
from tw.crypto import Argon2Params
import json
from tw.store import StoreError
from tw.audit import AuditLog


class BrokerAgentTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(dir="/tmp", prefix="twbroker")
        self.home = Path(self.tempdir.name) / "home"
        self.broker = Broker(self.home, desk=None)
        passphrase = "runtime generated test passphrase with sufficient length"
        self.broker.store.initialize(
            passphrase, argon2=Argon2Params(memory_kib=8192, iterations=1, lanes=1)
        )
        self.broker.seal.state = "sealed"
        self.broker.seal.unseal(passphrase)
        self.broker.service.identities.roster_sync(
            {"ai": [{"id": "alpha", "run": "run-alpha"}]}, []
        )
        receipt = self.broker.service.identities.issue_token(
            "lead:alpha", "lead", created_by="master"
        )
        self.token_path = receipt["file_path"]
        self.broker.service.process_resolver = lambda _pid: None
        self.broker.agent.bind()
        self.thread = threading.Thread(target=self.broker.agent.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.broker.close()
        self.thread.join(timeout=2)
        self.tempdir.cleanup()

    def _environment(self):
        environment = os.environ.copy()
        environment.update({"TW_HOME": str(self.home), "TW_TOKEN_FILE": self.token_path})
        return environment

    def test_run_over_socket_injects_and_redacts(self):
        value = os.urandom(40).hex().encode()
        self.broker.store.put_secret(
            "alpha/key",
            value,
            keyring=self.broker.service._keyring(),
            principal_id="lead:alpha",
            secret_class="sensitive",
        )
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "tw.cli",
                "run",
                "--env",
                "X=alpha/key",
                "--",
                sys.executable,
                "-c",
                "import os;print(os.environ['X'])",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._environment(),
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertNotIn(value, completed.stdout)
        self.assertIn(b"[tw:alpha/key]", completed.stdout)
        self.assertNotIn(value, completed.stderr)
        event = self.broker.store.connection.execute(
            "SELECT redactions FROM audit_events WHERE op='run' AND phase='result' "
            "ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        self.assertGreaterEqual(event[0], 1)

    @unittest.skipUnless(sys.platform == "darwin", "real resolver is macOS specific")
    def test_non_nested_tw_call_uses_real_process_resolver(self):
        from tw.identity import system_process_resolver

        resolved_pids = []

        def resolve(pid):
            resolved_pids.append(pid)
            return system_process_resolver(pid)

        self.broker.service.process_resolver = resolve
        # The test broker runs in this unittest process, unlike production.
        # Exclude it from nested-call detection so this subprocess models a
        # normal shell client whose ancestry continues to launchd.
        self.broker.service.broker_pid = -1
        completed = subprocess.run(
            [sys.executable, "-m", "tw.cli", "status", "--json"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._environment(),
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        payload = json.loads(completed.stdout)
        self.assertEqual(
            payload.get("principal"),
            "lead:alpha",
            (payload, completed.stderr, resolved_pids, os.getpid()),
        )

    def test_manifest_is_applied_and_literal_secret_is_refused(self):
        value = b"manifest-secret-value"
        self.broker.store.put_secret(
            "alpha/manifest",
            value,
            keyring=self.broker.service._keyring(),
            principal_id="lead:alpha",
        )
        good = self.home / "good.env.tw"
        good.write_text("X=tw://alpha/manifest\nLITERAL=safe-value\n")
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "tw.cli",
                "inject",
                "--manifest",
                str(good),
                "--",
                sys.executable,
                "-c",
                "import os;print(os.environ['X'],os.environ['LITERAL'])",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._environment(),
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertIn(b"[tw:alpha/manifest] safe-value", completed.stdout)
        self.assertNotIn(value, completed.stdout + completed.stderr)

        bad = self.home / "bad.env.tw"
        bad.write_bytes(b"BAD=" + value + b"\n")
        refused = subprocess.run(
            [
                sys.executable,
                "-m",
                "tw.cli",
                "inject",
                "--manifest",
                str(bad),
                "--",
                sys.executable,
                "-c",
                "pass",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._environment(),
            timeout=10,
        )
        self.assertEqual(refused.returncode, 77)
        self.assertNotIn(value, refused.stdout + refused.stderr)

    def test_put_value_is_read_before_global_transaction_lock(self):
        token = Path(self.token_path).read_text().strip()
        request = {
            "v": 1,
            "op": "put",
            "request_id": "outside-lock-read",
            "token": token,
            "args": {"path": "alpha/outside-lock", "class": "sensitive"},
            "ctx": {},
        }

        def read_value(_fd):
            self.assertFalse(self.broker.store._transaction_lock._is_owned())
            return b"bounded-put-value"

        with mock.patch("tw.broker._read_fd_limited", side_effect=read_value):
            response = self.broker.handle_agent(request, [123], 0)
        self.assertTrue(response["ok"], response)

    def test_startup_sweep_closes_stale_leases(self):
        token_id = self.broker.store.connection.execute(
            "SELECT token_id FROM tokens WHERE principal_id='lead:alpha' LIMIT 1"
        ).fetchone()[0]
        self.broker.store.connection.execute(
            "INSERT INTO leases(lease_id,token_id,principal_id,op,refs_json,opened_at) "
            "VALUES ('lea_stale',?,'lead:alpha','run','[]','now')",
            (token_id,),
        )
        self.broker._sweep_stale_leases()
        row = self.broker.store.connection.execute(
            "SELECT closed_at,exit_code,end_reason FROM leases WHERE lease_id='lea_stale'"
        ).fetchone()
        self.assertIsNotNone(row[0])
        self.assertEqual((row[1], row[2]), (70, "broker_restart"))

    def test_agent_socket_has_bounded_connection_slots(self):
        acquired = [
            self.broker.agent.connection_slots.acquire(blocking=False)
            for _ in range(64)
        ]
        self.assertTrue(all(acquired))
        self.assertFalse(
            self.broker.agent.connection_slots.acquire(blocking=False)
        )
        for _ in range(64):
            self.broker.agent.connection_slots.release()

    def test_agent_connection_sets_a_read_timeout(self):
        class EmptyClient:
            timeout = None

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def settimeout(self, value):
                self.timeout = value

            def getsockopt(self, *_args):
                raise OSError("test peer unavailable")

            def recvmsg(self, *_args):
                return b"", [], 0, None

        client = EmptyClient()
        self.assertTrue(self.broker.agent.connection_slots.acquire(blocking=False))
        self.broker.agent._serve_client(client)
        self.assertEqual(client.timeout, 30)

    def test_client_disconnect_kills_child_group_and_closes_lease(self):
        self.broker.service.executor.disconnect_grace = 0.1
        marker = self.home / "child-pid"
        client = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "tw.cli",
                "run",
                "--",
                sys.executable,
                "-c",
                "import os,pathlib,signal,time;"
                "signal.signal(signal.SIGTERM,lambda *_:None);"
                f"pathlib.Path({str(marker)!r}).write_text(str(os.getpid()));"
                "time.sleep(30)",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._environment(),
        )
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not marker.exists():
            time.sleep(0.02)
        self.assertTrue(marker.exists())
        child_pid = int(marker.read_text())
        os.kill(client.pid, signal.SIGKILL)
        client.wait(timeout=3)
        if client.stdout is not None:
            client.stdout.close()
        if client.stderr is not None:
            client.stderr.close()
        deadline = time.monotonic() + 3
        end_reason = None
        while time.monotonic() < deadline:
            row = self.broker.store.connection.execute(
                "SELECT end_reason FROM leases ORDER BY opened_at DESC LIMIT 1"
            ).fetchone()
            end_reason = None if row is None else row[0]
            if end_reason == "client_gone":
                break
            time.sleep(0.02)
        self.assertEqual(end_reason, "client_gone")
        with self.assertRaises(ProcessLookupError):
            os.kill(child_pid, 0)

    def test_client_signal_frame_reaches_child_group(self):
        marker = self.home / "signal-ready"
        client = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "tw.cli",
                "run",
                "--",
                sys.executable,
                "-c",
                "import pathlib,signal,sys,time;"
                "signal.signal(signal.SIGINT,lambda *_:sys.exit(42));"
                f"pathlib.Path({str(marker)!r}).touch();"
                "time.sleep(30)",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._environment(),
        )
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not marker.exists():
            time.sleep(0.02)
        self.assertTrue(marker.exists())
        client.send_signal(signal.SIGINT)
        stdout, stderr = client.communicate(timeout=5)
        self.assertEqual(client.returncode, 42, stderr.decode())
        self.assertEqual(stdout, b"")

    def test_sealed_broker_runs_without_soft_reference(self):
        self.broker.store.put_secret(
            "alpha/optional",
            os.urandom(40),
            keyring=self.broker.service._keyring(),
            principal_id="lead:alpha",
        )
        self.broker.seal.seal()
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "tw.cli",
                "run",
                "--soft",
                "OPTIONAL=alpha/optional",
                "--",
                sys.executable,
                "-c",
                "import os;print(int('OPTIONAL' in os.environ))",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._environment(),
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(completed.stdout.strip(), b"0")
        event = self.broker.store.connection.execute(
            "SELECT reason_code FROM audit_events WHERE secret_path='alpha/optional' "
            "ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        self.assertEqual(event[0], "soft_skip")

    def test_sealed_broker_starts_no_child_without_soft_reference(self):
        self.broker.seal.seal()
        marker = self.home / "must-not-start"
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "tw.cli",
                "run",
                "--",
                sys.executable,
                "-c",
                f"import pathlib;pathlib.Path({str(marker)!r}).touch()",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._environment(),
            timeout=10,
        )
        self.assertEqual(completed.returncode, 75)
        self.assertFalse(marker.exists())

    def test_duplicate_generate_request_returns_one_receipt_and_version(self):
        responses = []
        for _ in range(2):
            code = (
                "import json,os,pathlib,socket;"
                "from tw.protocol import send_frame,recv_frame;"
                "token=pathlib.Path(os.environ['TW_TOKEN_FILE']).read_text().strip();"
                "request={'v':1,'op':'generate','request_id':'same-request','token':token,"
                "'args':{'path':'alpha/generated','length':32,'charset':'urlsafe',"
                "'class':'sensitive','kind':'opaque','note':None},'ctx':{}};"
                "client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);"
                "client.connect(os.path.join(os.environ['TW_HOME'],'run','tw.sock'));"
                "send_frame(client,request);print(json.dumps(recv_frame(client)));client.close()"
            )
            completed = subprocess.run(
                [sys.executable, "-c", code],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self._environment(),
                timeout=5,
            )
            responses.append(json.loads(completed.stdout))
        self.assertTrue(responses[0]["ok"], responses[0])
        self.assertEqual(responses[0], responses[1])
        versions = self.broker.store.connection.execute(
            "SELECT count(*) FROM secret_versions v JOIN secrets s ON s.secret_id=v.secret_id "
            "WHERE s.path='alpha/generated'"
        ).fetchone()[0]
        self.assertEqual(versions, 1)

    def test_sealed_refusal_is_audited(self):
        self.broker.seal.seal()
        response = self.broker.handle_agent(
            {"v": 1, "op": "names", "request_id": "sealed", "args": {}}, [], 0
        )
        self.assertEqual(response["code"], "E_SEALED")
        row = self.broker.store.connection.execute(
            "SELECT decision,reason_code FROM audit_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        self.assertEqual(tuple(row), ("deny", "sealed"))

    def test_maintenance_audit_failure_enters_lockdown(self):
        AuditLog(
            self.broker.store, mac_key=bytes(self.broker.seal.keys.audit)
        ).append(event_id=self.broker.store.new_id("evt_"), op="test")
        self.broker.store.connection.execute("DROP TRIGGER audit_no_update")
        self.broker.store.connection.execute(
            "UPDATE audit_events SET reason_code='tampered' WHERE seq=(SELECT min(seq) FROM audit_events)"
        )
        self.broker._verify_audit()
        self.assertEqual(self.broker.seal.state, "lockdown")
        self.assertIsNone(self.broker.seal.keys)


class BrokerStartupTests(unittest.TestCase):
    def test_home_with_tombstone_but_no_store_is_refused(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="twexisting") as directory:
            (Path(directory) / "state").mkdir(mode=0o700)
            (Path(directory) / "state" / ".store-created").touch(mode=0o600)
            with self.assertRaises(StoreError):
                Broker(Path(directory), desk=None)

    def test_fresh_install_home_without_tombstone_starts(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="twfresh") as directory:
            for sub in ("state", "run", "log"):
                (Path(directory) / sub).mkdir(mode=0o700)
            broker = Broker(Path(directory), desk=None)
            self.addCleanup(broker.store.close)
            self.assertTrue((Path(directory) / "state" / "tw.db").exists())

    def test_main_sets_secure_umask_before_constructing_broker(self):
        order = []
        fake_broker = mock.Mock()
        with mock.patch(
            "tw.broker.Store.secure_process_umask",
            side_effect=lambda: order.append("umask"),
        ), mock.patch(
            "tw.broker.Broker",
            side_effect=lambda *_args, **_kwargs: (order.append("broker") or fake_broker),
        ):
            self.assertEqual(broker_main(["--home", "/tmp/tw-main-test"]), 0)
        self.assertEqual(order, ["umask", "broker"])
        fake_broker.run.assert_called_once_with()
        fake_broker.close.assert_called_once_with()

    def test_broker_configures_external_backup_allowlist(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="twbackupallow") as directory:
            broker = Broker(Path(directory) / "home", desk=None)
            try:
                self.assertTrue(
                    any(root.is_absolute() and not root.is_relative_to(broker.home)
                        for root in broker.store.backup_roots)
                )
            finally:
                broker.close()


if __name__ == "__main__":
    unittest.main()
