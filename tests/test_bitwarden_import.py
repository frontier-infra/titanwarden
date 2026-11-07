from __future__ import annotations

from contextlib import closing, redirect_stderr, redirect_stdout
import copy
import hmac
import io
import json
import logging
import os
from pathlib import Path
import resource
import signal
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tw import admin, bitwarden_import as imp
from tw.bitwarden_broker import handle_import
from tw.admin_server import AdminService, AdminSession
from bitwarden_fixtures import ITEM, OTHER_ITEM, VALUE, UNSELECTED, REVISION


def entry(**changes):
    result = dict(item_id=ITEM, field="token", project="infra", path="example", **{"class": "sensitive"})
    result.update(changes)
    return result


class FakeRuntime:
    def __init__(self):
        self.joined = True
        self.current = True
        self.receipts = {}
        self.versions = []
        self.put_calls = 0
        self.fail = ""
        self.existing = set()

    def readiness(self, entries=None):
        if self.fail == "head_exception":
            raise RuntimeError(VALUE)
        result = dict(joined=self.joined, current_head=self.current)
        if entries is not None:
            result["existing_targets"] = [imp.entry_hash(source) for source in entries
                                          if (source["project"], source["path"]) in self.existing]
        return result

    def put(self, source, rid, value):
        self.put_calls += 1
        if self.fail == "write":
            raise RuntimeError(VALUE)
        if rid not in self.receipts:
            if (source["project"], source["path"]) in self.existing:
                raise imp.ImportFailure("E_IMPORT_EXISTS")
            self.versions.append(value)
            self.existing.add((source["project"], source["path"]))
            self.receipts[rid] = dict(request_id=rid, version_id="test-version", entry=copy.deepcopy(source), value=value)
        receipt = self.receipts[rid]
        if receipt["entry"] != source:
            raise RuntimeError(UNSELECTED)
        if self.fail == "ambiguous":
            self.fail = ""
            raise ConnectionError(VALUE)
        return {key: receipt[key] for key in ("request_id", "version_id")}

    def verify(self, source, rid, key):
        if self.fail == "verify":
            raise RuntimeError(VALUE)
        receipt = self.receipts[rid]
        if receipt["entry"] != source:
            raise RuntimeError(UNSELECTED)
        value = receipt["value"] if self.fail != "mismatch" else b"different"
        return hmac.digest(key, value, "sha256")


class FakeSeal:
    state = "unsealed"

    def check_passphrase(self, _passphrase):
        return None


class FakeClient:
    def __init__(self, runtime):
        self.bitwarden_runtime = runtime
        self.seal = FakeSeal()
        self.session = AdminSession()
        self.session.authenticate()
        self._read_fd = self.read_fd

    @staticmethod
    def read_fd(fd):
        parts = []
        while chunk := os.read(fd, 65536):
            parts.append(chunk)
        return b"".join(parts)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def call(self, op, args, fds=None):
        return handle_import(self, self.session, op, args, fds or [])


class ImportTests(unittest.TestCase):
    def cloud_adapter(self):
        from test_cloud_wiring import RuntimeTests
        from tw.bitwarden_broker import CloudImportRuntime
        harness = RuntimeTests()
        self.addCleanup(harness.doCleanups)
        harness.setUp()
        return harness, CloudImportRuntime(harness.runtime)

    def test_cloud_wiring_put_verify_and_restart(self):
        from tw.bitwarden_broker import runtime_for, CloudImportRuntime
        harness, adapter = self.cloud_adapter()
        service = AdminService(harness.store, harness.seal)
        service.cloud = harness.runtime
        self.assertIsInstance(runtime_for(service), CloudImportRuntime)
        target = entry(project="a", **{"class": "standard"})
        rid = imp.request_id(target, REVISION)
        receipt = adapter.put(target, rid, VALUE.encode())
        self.assertEqual(receipt["request_id"], rid)
        restarted = runtime_for(service)
        self.assertEqual(restarted.put(target, rid, VALUE.encode()), receipt)
        self.assertEqual(restarted.verify(target, rid, b"k" * 32), hmac.digest(b"k" * 32, VALUE.encode(), "sha256"))
        intent = restarted.intent(rid)
        self.assertEqual(intent["receipt"]["version_no"], 1)
        self.assertNotIn(VALUE, json.dumps(intent))
        self.assertEqual(len(harness.fake.blobs), 1)

    def cloud_ambiguous(self):
        harness, adapter = self.cloud_adapter()
        target = entry(project="a", **{"class": "standard"})
        rid = imp.request_id(target, REVISION)
        harness.fake.lose_publication_response = True
        with self.assertRaises(Exception):
            adapter.put(target, rid, VALUE.encode())
        self.assertIsNotNone(adapter.intent(rid))
        self.assertNotIn("receipt", adapter.intent(rid))
        return harness, adapter, target, rid

    def test_cloud_ambiguous_retry_recovers_receipt(self):
        harness, adapter, target, rid = self.cloud_ambiguous()
        self.assertEqual(adapter.put(target, rid, VALUE.encode())["request_id"], rid)
        self.assertEqual(len(harness.fake.blobs), 1)

    def test_cloud_retry_wrong_principal_refuses(self):
        harness, adapter, target, rid = self.cloud_ambiguous()
        harness.runtime.pull()
        version = adapter.active(target)[1]
        key = "cloud_write_" + version["version_id"]
        receipt = json.loads(harness.store.meta(key))
        receipt["principal_id"] = "human:other"
        harness.store.set_meta(key, json.dumps(receipt))
        with self.assertRaisesRegex(imp.ImportFailure, "E_IMPORT_EXISTS"):
            adapter.put(target, rid, VALUE.encode())
        self.assertEqual(len(harness.fake.blobs), 1)

    def test_cloud_retry_wrong_fingerprint_refuses(self):
        harness, adapter, target, rid = self.cloud_ambiguous()
        harness.runtime.pull()
        secret, version = adapter.active(target)
        version = dict(version, fingerprint="0" * 64)
        with mock.patch.object(adapter, "active", return_value=(secret, version)):
            with self.assertRaisesRegex(imp.ImportFailure, "E_IMPORT_EXISTS"):
                adapter.put(target, rid, VALUE.encode())
        self.assertEqual(len(harness.fake.blobs), 1)

    def test_cloud_retry_missing_intent_refuses(self):
        harness, adapter, target, rid = self.cloud_ambiguous()
        harness.store.connection.execute("DELETE FROM meta WHERE key=?", ("bitwarden_intent_" + rid,))
        with self.assertRaisesRegex(imp.ImportFailure, "E_IMPORT_EXISTS"):
            adapter.put(target, rid, VALUE.encode())
        self.assertEqual(len(harness.fake.blobs), 1)

    def test_cloud_existing_and_race_refuse(self):
        harness, adapter = self.cloud_adapter()
        target = entry(project="a", **{"class": "standard"})
        rid = imp.request_id(target, REVISION)
        harness.runtime.put("a/example", VALUE.encode(), secret_class="standard")
        with self.assertRaisesRegex(imp.ImportFailure, "E_IMPORT_EXISTS"):
            adapter.put(target, rid, VALUE.encode())
        self.assertIsNone(adapter.intent(rid))
        other = entry(project="a", path="raced", **{"class": "standard"})
        original = harness.runtime.put
        def race(*args, **kwargs):
            original("a/raced", b"TEST-ONLY different", secret_class="standard")
            return original(*args, **kwargs)
        with mock.patch.object(harness.runtime, "put", side_effect=race):
            with self.assertRaisesRegex(imp.ImportFailure, "E_IMPORT_EXISTS"):
                adapter.put(other, imp.request_id(other, REVISION), VALUE.encode())

    def test_cloud_import_full_fake_source_and_ambiguous_resume(self):
        from tw.bitwarden_broker import runtime_for
        from support import TEST_PASSPHRASE
        harness, _adapter = self.cloud_adapter()
        self.save([entry(project="a", **{"class": "standard"})])
        self.client = FakeClient(None)
        del self.client.bitwarden_runtime
        self.client.cloud = harness.runtime
        self.client.seal = harness.seal
        harness.fake.lose_publication_response = True
        self.assertEqual(self.run_main(TEST_PASSPHRASE)[0], 1)
        self.assertEqual(self.run_main(TEST_PASSPHRASE)[0], 0)
        self.assertEqual(len(harness.fake.blobs), 1)
        self.assertEqual(self.rows()[0]["state"], "verified")
        self.assertIsNotNone(runtime_for(self.client).intent(self.rows()[0]["request_id"])["receipt"])

    def test_cloud_readiness_refuses_pending_conflict_and_seal(self):
        harness, _adapter = self.cloud_adapter()
        self.client = FakeClient(None)
        del self.client.bitwarden_runtime
        self.client.cloud = harness.runtime
        self.client.seal = harness.seal
        self.save([entry(project="a", **{"class": "standard"})])
        harness.fake.pending = True
        with mock.patch.object(imp, "sync_source") as source:
            self.assertEqual(self.run_main()[0], 1)
            source.assert_not_called()
        harness.fake.pending = False
        harness.runtime.pull()
        harness.runtime.sync().refuse("fork", harness.runtime.clock())
        with mock.patch.object(imp, "sync_source") as source:
            self.assertEqual(self.run_main()[0], 1)
            source.assert_not_called()
        harness.seal.seal()
        with mock.patch.object(harness.runtime, "pull") as pull:
            self.assertIn("E_IMPORT_SEALED", self.run_main()[2])
            pull.assert_not_called()

    def test_existing_race_keeps_fixed_exists_diagnostic(self):
        original = self.client.call
        def raced(op, args, fds=None):
            if op == "import_put":
                self.runtime.existing.add(("infra", "example"))
            return original(op, args, fds)
        with mock.patch.object(self.client, "call", side_effect=raced):
            result, _out, err = self.run_main()
        self.assertEqual(result, 1)
        self.assertIn("E_IMPORT_EXISTS", err)
        self.assertEqual(self.rows()[0]["error"], "E_IMPORT_EXISTS")
        self.assertEqual(self.runtime.versions, [])

    def test_cloud_intent_durable_before_put_and_receipt_before_verify(self):
        harness, adapter = self.cloud_adapter()
        target = entry(project="a", **{"class": "standard"})
        rid = imp.request_id(target, REVISION)
        original = harness.runtime.put
        def inspect(*args, **kwargs):
            self.assertEqual(adapter.intent(rid)["path"], "a/example")
            self.assertNotIn("receipt", adapter.intent(rid))
            with closing(sqlite3.connect(harness.store.db_path)) as independent:
                saved = independent.execute("SELECT value FROM meta WHERE key=?", ("bitwarden_intent_" + rid,)).fetchone()
                self.assertEqual(json.loads(saved[0]), adapter.intent(rid))
            return original(*args, **kwargs)
        with mock.patch.object(harness.runtime, "put", side_effect=inspect):
            adapter.put(target, rid, VALUE.encode())
        with mock.patch.object(harness.runtime.sync().__class__, "read_value", return_value=b"TEST-ONLY tampered"):
            self.assertNotEqual(adapter.verify(target, rid, b"k" * 32),
                                hmac.digest(b"k" * 32, VALUE.encode(), "sha256"))

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.home = self.root / "broker"
        (self.home / "state").mkdir(parents=True)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        # This executable contains no fixture bytes and never invokes a real bw.
        fake = self.bin / "bw"
        tests = str(Path(__file__).parent)
        fake.write_text("#!" + sys.executable + "\nimport sys\nsys.dont_write_bytecode=True\nsys.path.insert(0," + repr(tests) + ")\nfrom bitwarden_fixtures import main\nsys.exit(main())\n")
        fake.chmod(0o700)
        self.validator = imp.trusted_executable
        self.executable = str(fake)
        self.source_patches = [mock.patch.object(imp, "BW_EXECUTABLE", self.executable),
                               mock.patch.object(imp, "trusted_executable", side_effect=lambda path: path)]
        for patch in self.source_patches:
            patch.start()
        self.mode("ok")
        self.env = mock.patch.dict(os.environ, {"PATH": str(self.bin), "DEBUG": "should-be-removed", "NODE_OPTIONS": "should-be-removed", "BW_SESSION": "TEST-ONLY-session"})
        self.env.start()
        imp.disable_core()
        self.runtime = FakeRuntime()
        self.client = FakeClient(self.runtime)
        self.manifest = self.root / "manifest.json"
        self.save([entry()])
        self.log_handler = logging.FileHandler(self.root / "test.log")
        logging.getLogger().addHandler(self.log_handler)

    def tearDown(self):
        logging.getLogger().removeHandler(self.log_handler)
        self.log_handler.close()
        self.env.stop()
        for patch in reversed(self.source_patches):
            patch.stop()
        self.tmp.cleanup()

    def mode(self, mode):
        (self.bin / "mode").write_text(mode)

    def save(self, entries):
        self.manifest.write_text(json.dumps(dict(version=1, items=entries)))

    def run_main(self, passphrase="test-passphrase"):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(admin, "human_context_allowed", return_value=True), mock.patch.object(admin, "AdminClient", return_value=self.client), mock.patch("getpass.getpass", return_value=passphrase), redirect_stdout(out), redirect_stderr(err):
            code = imp.main(["--home", str(self.home), str(self.manifest)])
        self.assert_clean(out.getvalue(), err.getvalue())
        return code, out.getvalue(), err.getvalue()

    def assert_clean(self, *outputs):
        for output in outputs:
            raw = output.encode() if isinstance(output, str) else output
            self.assertTrue(all(value.encode() not in raw for value in (VALUE, UNSELECTED)), "fixture leaked in output")
        for path in self.root.rglob("*"):
            if path.is_file():
                raw = path.read_bytes()
                self.assertTrue(all(value.encode() not in raw for value in (VALUE, UNSELECTED)), "fixture leaked to a file")

    def rows(self):
        with closing(sqlite3.connect(self.home / "state" / "bitwarden-import.sqlite3")) as db:
            db.row_factory = sqlite3.Row
            return list(db.execute("SELECT * FROM items ORDER BY item"))

    def test_success_field_and_login_one_process_no_value_args(self):
        self.save([entry(), dict(item_id=OTHER_ITEM, login="password", project="infra", path="other", **{"class": "restricted"})])
        with mock.patch.object(imp.subprocess, "Popen", wraps=subprocess.Popen) as child:
            code, out, err = self.run_main()
        self.assertEqual(code, 0)
        self.assertEqual(out, "twadmin: import verified\n")
        self.assertEqual(err, "")
        self.assertEqual(len(child.call_args_list), 8)
        for index, call in enumerate(child.call_args_list):
            if index in {0, 5}:
                self.assertEqual(call.args[0], [self.executable, "sync"])
            else:
                self.assertEqual(call.args[0][:3], [self.executable, "get", "item"])
            self.assertIs(call.kwargs["shell"], False)
            self.assertIs(call.kwargs["stderr"], subprocess.DEVNULL)
            self.assertNotIn(VALUE, str(call))
            self.assertNotIn(UNSELECTED, str(call))
        self.assertTrue(all(value == VALUE.encode() for value in self.runtime.versions))
        self.assertTrue(all(row["state"] == "verified" for row in self.rows()))
        self.assertFalse((self.home / "state" / "bitwarden-import.lock").exists())

    def test_source_environment_is_fixed(self):
        hostile = {key: "TEST-ONLY-hostile" for key in (
            "PATH", "HOME", "BITWARDENCLI_APPDATA_DIR", "SSL_CERT_FILE", "SSL_CERT_DIR",
            "XDG_CONFIG_HOME", "NODE_OPTIONS", "NODE_PATH", "LANG", "LC_ALL",
            "BW_EXECUTABLE", "BW_HOME", "BW_APPDATA")}
        hostile["BW_SESSION"] = "TEST-ONLY-session"
        with mock.patch.dict(os.environ, hostile, clear=True):
            self.assertEqual(imp.source_environment("TEST-ONLY-session"), {
                "PATH": "/usr/bin:/bin", "HOME": imp.BW_HOME,
                "BITWARDENCLI_APPDATA_DIR": imp.BW_APPDATA,
                "BW_SESSION": "TEST-ONLY-session"})
            with mock.patch.object(imp.subprocess, "Popen", wraps=subprocess.Popen) as launch:
                imp.read_source(entry())
            self.assertEqual(launch.call_args.args[0][0], self.executable)
            imp.trusted_executable.assert_called_with(self.executable)
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertNotIn("BW_SESSION", imp.source_environment())

    def test_deployment_executable_chain_refuses_substitution(self):
        import stat
        from types import SimpleNamespace
        validator = self.validator
        target = Path("/deployment/client/bw")
        good = {path: SimpleNamespace(st_uid=0, st_mode=(stat.S_IFREG | 0o755)
                                      if path == target else (stat.S_IFDIR | 0o755))
                for path in (target, *target.parents)}
        def validate(rows, path=target, **options):
            with mock.patch.object(Path, "lstat", autospec=True, side_effect=lambda path: rows[path]), mock.patch.object(os, "access", return_value=True):
                return validator(str(path), **options)
        self.assertEqual(validate(good), str(target))
        for path in good:
            for owner, mode in ((1, good[path].st_mode), (0, good[path].st_mode | 0o020),
                                (0, good[path].st_mode | 0o002), (0, stat.S_IFLNK | 0o755)):
                rows = dict(good)
                rows[path] = SimpleNamespace(st_uid=owner, st_mode=mode)
                with self.subTest(component=str(path), owner=owner, mode=mode):
                    with self.assertRaises(imp.ImportFailure):
                        validate(rows)
        with self.assertRaises(imp.ImportFailure):
            validator("bw")
        with self.assertRaises(imp.ImportFailure):
            validator("/deployment/../bw")
        with mock.patch.object(Path, "lstat", autospec=True, side_effect=lambda path: good[path]), mock.patch.object(os, "access", return_value=False):
            with self.assertRaises(imp.ImportFailure):
                validator(str(target))
        rows = {path: SimpleNamespace(st_uid=42, st_mode=row.st_mode) for path, row in good.items()}
        self.assertEqual(validate(rows, expected_owner=42), str(target))

    def test_import_route_human_guard(self):
        for environment, listing in (({"ORCA_TERMINAL_HANDLE": "test-only"}, ""),
                                     ({}, "python codex worker")):
            with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(admin.subprocess, "run", return_value=mock.Mock(stdout=listing)), mock.patch.object(imp, "main") as dispatch, redirect_stderr(io.StringIO()):
                self.assertEqual(admin.main(["import-bitwarden", "manifest.json"]), 77)
                dispatch.assert_not_called()
        with mock.patch.dict(os.environ, {"BW_SESSION": "TEST-ONLY-session"}, clear=True), mock.patch.object(admin.subprocess, "run", return_value=mock.Mock(stdout="human shell")) as listing:
            self.assertTrue(admin.human_context_allowed("import-bitwarden"))
            self.assertEqual(listing.call_args.args[0][0], "/bin/ps")
            self.assertEqual(listing.call_args.kwargs["env"], {"PATH": "/usr/bin:/bin"})
        self.assertIn("import-bitwarden", admin.SENSITIVE_SCREEN_OPS)
        self.assertTrue(admin.human_context_allowed("import-bitwarden", environ={}, process_listing="human shell"))

    def test_importer_reachable_children_are_session_isolated(self):
        original = subprocess.Popen
        children = []
        observed = []
        # Exercise the real AdminClient peer-verification path with a fake socket.
        self.client.socket = mock.Mock()
        def launch(argv, **kwargs):
            observed.append((argv, kwargs, dict(os.environ)))
            if argv[0] == self.executable:
                child = original(argv, **kwargs)
                children.append(child)
                return child
            child = mock.MagicMock()
            # launchctl print output on macOS; systemctl show --value output on Linux.
            child.communicate.return_value = ("42\n" if argv[0].endswith("systemctl") else "human shell\npid = 42\n", "")
            child.poll.return_value = 0
            child.returncode = 0
            child.__enter__.return_value = child
            return child
        def enter(client):
            self.assertTrue(admin.verify_broker_peer(self.client.socket, self.home))
            return self.client
        with mock.patch.dict(os.environ, {"BW_SESSION": "TEST-ONLY-session"}, clear=True), mock.patch.object(subprocess, "Popen", side_effect=launch), mock.patch.object(admin, "peer_pid", return_value=42), mock.patch.object(admin, "broker_argv", return_value=["python", "-m", "tw.broker", "--home", str(self.home.resolve())]), mock.patch.object(admin.AdminClient, "__enter__", enter), mock.patch("getpass.getpass", return_value="test-passphrase"), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(imp.main(["--home", str(self.home), str(self.manifest)]), 0)
        service_pid_tool = "/bin/launchctl" if sys.platform == "darwin" else "/usr/bin/systemctl"
        self.assertEqual({argv[0] for argv, _, _ in observed}, {"/bin/ps", service_pid_tool, self.executable})
        for argv, options, ambient in observed:
            self.assertTrue(Path(argv[0]).is_absolute())
            self.assertNotIn("BW_SESSION", ambient)
            if argv[0] == self.executable:
                self.assertEqual(options["env"]["BW_SESSION"], "TEST-ONLY-session")
            else:
                self.assertEqual(options["env"], {"PATH": "/usr/bin:/bin"})
        self.assertTrue(all(child.returncode == 0 for child in children))

    def test_direct_module_human_guard(self):
        import runpy
        for environment, listing in (({"ORCA_TERMINAL_HANDLE": "test-only"}, "human"), ({}, "python codex worker")):
            with self.subTest(environment=environment), mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(admin.subprocess, "run", return_value=mock.Mock(stdout=listing)), mock.patch.object(admin, "AdminClient") as client, mock.patch.object(sys, "argv", ["tw.bitwarden_import", "--help"]), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(imp.main(["--help"]), 77)
                with self.assertRaises(SystemExit) as failure:
                    runpy.run_module("tw.bitwarden_import", run_name="__main__")
                self.assertEqual(failure.exception.code, 77)
                client.assert_not_called()

    def test_source_cleanup_precedes_reap_and_parse(self):
        self.mode("success_grandchild")
        events = []
        processes = []
        original = subprocess.Popen
        kill = os.killpg
        def launch(*args, **kwargs):
            child = original(*args, **kwargs)
            processes.append(child)
            wait = child.wait
            def reap(*args, **kwargs):
                events.append("reap")
                return wait(*args, **kwargs)
            child.wait = reap
            return child
        def terminate(pid, sig):
            self.assertIsNone(processes[0].returncode)
            self.assertNotIn("reap", events)
            status = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            self.assertIsNotNone(status)
            events.append("kill")
            return kill(pid, sig)
        parse = imp.parse_json
        def parsed(raw):
            self.assertEqual(events, ["kill", "reap"])
            self.assertIsNotNone(processes[0].returncode)
            return parse(raw)
        with mock.patch.object(subprocess, "Popen", side_effect=launch), mock.patch.object(os, "killpg", side_effect=terminate), mock.patch.object(imp, "parse_json", side_effect=parsed):
            self.assertEqual(imp.read_source(entry())[1], VALUE.encode())
        self.assert_group_gone(processes[0].pid)

    def assert_group_gone(self, pid):
        import time
        for _ in range(200):
            try:
                os.killpg(pid, 0)
            except ProcessLookupError:
                return
            except PermissionError:
                pass  # Darwin may still be reaping a killed orphan zombie.
            time.sleep(0.01)
        self.fail("test source process group survived")

    def test_source_close_failure_still_reaps(self):
        child = mock.Mock(pid=12345, stdout=mock.Mock())
        child.stdout.close.side_effect = OSError("test-only close failure")
        with mock.patch.object(subprocess, "Popen", return_value=child), mock.patch.object(os, "killpg") as killed, mock.patch.object(os, "waitid", return_value=mock.Mock(si_code=os.CLD_EXITED, si_status=0)):
            with self.assertRaises(OSError):
                with imp.source_output(["sync"], capture=False):
                    self.fail("close failure accepted")
        killed.assert_called_once_with(child.pid, signal.SIGKILL)
        child.wait.assert_called_once_with()

    def await_group_ready(self, marker, importer, timeout=5):
        import time
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                group = int(marker.read_text())
            except (FileNotFoundError, ValueError):
                pass
            else:
                if group > 0:
                    return group
            if importer.poll() is not None:
                self.fail("importer exited before source group was ready")
            time.sleep(0.005)
        self.fail("source group readiness timed out")

    def test_source_real_terminating_signals(self):
        self.mode("signal_wait")
        program = (
            "import sys,getpass\n"
            "sys.path.insert(0," + repr(str(Path(__file__).parent)) + ")\n"
            "from test_bitwarden_import import FakeRuntime,FakeClient\n"
            "from tw import admin,bitwarden_import as source\n"
            "source.BW_EXECUTABLE=" + repr(self.executable) + "\n"
            "source.trusted_executable=lambda path:path\n"
            "admin.human_context_allowed=lambda op:True\n"
            "admin.AdminClient=lambda home:FakeClient(FakeRuntime())\n"
            "getpass.getpass=lambda prompt:'test-passphrase'\n"
            "sys.exit(source.main(" + repr(["--home", str(self.home), str(self.manifest)]) + "))\n"
        )
        mutation = getattr(imp, "_probe_source", None)
        if mutation is not None:
            program = ("import tw.bitwarden_import as injected\nexec(compile(" + repr(mutation)
                       + ",injected.__file__,'exec'),injected.__dict__)\n" + program)
        for signum in (signal.SIGHUP, signal.SIGQUIT, signal.SIGINT, signal.SIGTERM):
            marker = self.bin / "group-ready"
            marker.unlink(missing_ok=True)
            group = None
            with subprocess.Popen([sys.executable, "-c", program], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as importer:
                try:
                    group = self.await_group_ready(marker, importer)
                    importer.send_signal(signum)
                    out, err = importer.communicate(timeout=5)
                    self.assertEqual(importer.returncode, 1)
                    self.assertIn(b"E_IMPORT_ABORT", err)
                    self.assert_group_gone(group)
                    self.assert_clean(out, err)
                finally:
                    if group is not None:
                        try:
                            os.killpg(group, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    if importer.poll() is None:
                        importer.kill()
                        importer.wait()

    def test_abort_latches_and_restores_signal_state(self):
        original_handlers = {sig: signal.getsignal(sig) for sig in imp.ABORT_SIGNALS}
        inherited_mask = signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGUSR1])
        self.addCleanup(signal.pthread_sigmask, signal.SIG_SETMASK, inherited_mask)
        original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
        captured = {}
        observed = {"deliveries": [], "blocked": False}
        install = signal.signal
        def register(sig, handler):
            if callable(handler) and handler.__name__ == "interrupted":
                captured[sig] = handler
            return install(sig, handler)
        def abort(*args, **kwargs):
            handler = captured[signal.SIGHUP]
            with self.assertRaisesRegex(imp.ImportFailure, "E_IMPORT_ABORT"):
                handler(signal.SIGHUP, None)
            observed["blocked"] = set(imp.ABORT_SIGNALS) <= signal.pthread_sigmask(signal.SIG_BLOCK, [])
            # Call directly too: the latch must work independently of OS masking.
            for sig in imp.ABORT_SIGNALS * 3:
                handler(sig, None)
                observed["deliveries"].append(sig)
            raise RuntimeError("later failure must not replace first abort")
        with mock.patch.object(signal, "signal", side_effect=register), mock.patch.object(imp, "run_import", side_effect=abort):
            code, _, err = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("E_IMPORT_ABORT", err)
        self.assertTrue(observed["blocked"])
        self.assertEqual(observed["deliveries"], list(imp.ABORT_SIGNALS * 3))
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, []), original_mask)
        self.assertEqual({sig: signal.getsignal(sig) for sig in imp.ABORT_SIGNALS}, original_handlers)

    def test_final_teardown_consumes_real_pending_signals(self):
        saved_handlers = {sig: signal.getsignal(sig) for sig in imp.ABORT_SIGNALS}
        mask, install, pending = signal.pthread_sigmask, signal.signal, signal.sigpending
        saved_mask = mask(signal.SIG_BLOCK, [])
        expected = ("twadmin: E_IMPORT_ABORT: " + imp.MESSAGES["E_IMPORT_ABORT"]
                    + "; earlier writes remain in place; resume from journal\n")
        phases = ("start", "recorders", "unmask", "pending_check", "restore")
        try:
            for queued in [(sig,) for sig in imp.ABORT_SIGNALS] + [imp.ABORT_SIGNALS]:
                for result in ("success", "failure", "refusal"):
                    for phase in phases:
                        for blocked in (False, True):
                            if blocked and phase == "restore":
                                continue  # Newly pending caller-blocked signals belong to the caller.
                            with self.subTest(signals=queued, result=result, phase=phase, blocked=blocked):
                                original_mask = (set(saved_mask) - set(imp.ABORT_SIGNALS)) | {signal.SIGUSR1}
                                if blocked:
                                    original_mask |= set(imp.ABORT_SIGNALS)
                                mask(signal.SIG_SETMASK, original_mask)
                                delivered = []
                                def caller_handler(signum, _frame):
                                    delivered.append(signum)
                                    raise RuntimeError("caller must never receive importer signals")
                                for sig in imp.ABORT_SIGNALS:
                                    install(sig, caller_handler)
                                state = {"finished": False, "queued": False, "recorders": 0,
                                         "checked": False, "restored": 0}
                                def inject(where):
                                    if phase == where and not state["queued"]:
                                        state["queued"] = True
                                        for sig in queued:
                                            os.kill(os.getpid(), sig)
                                def guard(_operation):
                                    if result == "refusal":
                                        state["finished"] = True
                                        return False
                                    return True
                                def finish(*args, **kwargs):
                                    state["finished"] = True
                                    if result == "failure":
                                        raise RuntimeError("fixture failure before teardown")
                                def masking(how, signals):
                                    previous = mask(how, signals)
                                    if state["finished"]:
                                        if how == signal.SIG_BLOCK and set(signals) == set(imp.ABORT_SIGNALS):
                                            inject("start")
                                        if how == signal.SIG_UNBLOCK:
                                            inject("unmask")
                                    return previous
                                def register(sig, handler):
                                    if state["finished"] and handler is caller_handler:
                                        inject("restore")
                                        self.assertTrue(state["checked"])
                                        self.assertEqual(mask(signal.SIG_BLOCK, []), original_mask)
                                        state["restored"] += 1
                                    previous = install(sig, handler)
                                    if callable(handler) and handler.__name__ == "record_abort":
                                        self.assertTrue(set(imp.ABORT_SIGNALS) <= mask(signal.SIG_BLOCK, []))
                                        state["recorders"] += 1
                                        if state["recorders"] == len(imp.ABORT_SIGNALS):
                                            inject("recorders")
                                    return previous
                                def checking():
                                    inject("pending_check")
                                    observed = pending()
                                    if not observed & set(imp.ABORT_SIGNALS):
                                        state["checked"] = True
                                    return observed
                                out, err = io.StringIO(), io.StringIO()
                                try:
                                    with mock.patch.object(admin, "human_context_allowed", side_effect=guard), mock.patch.object(admin, "AdminClient", return_value=self.client), mock.patch("getpass.getpass", return_value="test-passphrase"), mock.patch.object(imp, "run_import", side_effect=finish), mock.patch.object(signal, "pthread_sigmask", side_effect=masking), mock.patch.object(signal, "signal", side_effect=register), mock.patch.object(signal, "sigpending", side_effect=checking), redirect_stdout(out), redirect_stderr(err):
                                        code = imp.main(["--home", str(self.home), str(self.manifest)])
                                    self.assertTrue(state["queued"])
                                    self.assertEqual((code, out.getvalue(), err.getvalue()), (1, "", expected))
                                    self.assertEqual(state["recorders"], len(imp.ABORT_SIGNALS))
                                    self.assertEqual(state["restored"], len(imp.ABORT_SIGNALS))
                                    self.assertEqual(delivered, [])
                                    self.assertEqual(mask(signal.SIG_BLOCK, []), original_mask)
                                    self.assertEqual({sig: signal.getsignal(sig) for sig in imp.ABORT_SIGNALS}, dict.fromkeys(imp.ABORT_SIGNALS, caller_handler))
                                finally:
                                    mask(signal.SIG_BLOCK, imp.ABORT_SIGNALS)
                                    for sig in pending() & set(imp.ABORT_SIGNALS):
                                        signal.sigwait({sig})
                                    for sig, handler in saved_handlers.items():
                                        install(sig, handler)
                                    mask(signal.SIG_SETMASK, saved_mask)
        finally:
            for sig, handler in saved_handlers.items():
                install(sig, handler)
            mask(signal.SIG_SETMASK, saved_mask)

    def test_final_teardown_contains_restoration_failures(self):
        mask, install, pending = signal.pthread_sigmask, signal.signal, signal.sigpending
        original_mask = mask(signal.SIG_BLOCK, [])
        handlers = {sig: signal.getsignal(sig) for sig in imp.ABORT_SIGNALS}
        for phase in ("block", "recorder", "unblock", "pending", "mask", "handler"):
            with self.subTest(phase=phase):
                state = {"finished": False, "raised": False}
                def fail(where):
                    if state["finished"] and phase == where and not state["raised"]:
                        state["raised"] = True
                        raise BaseException("private fixture detail")
                def finish(*args, **kwargs):
                    state["finished"] = True
                def masking(how, signals):
                    previous = mask(how, signals)
                    if how == signal.SIG_BLOCK and signals:
                        fail("block")
                    elif how == signal.SIG_UNBLOCK:
                        fail("unblock")
                    elif how == signal.SIG_SETMASK:
                        fail("mask")
                    return previous
                def register(sig, handler):
                    previous = install(sig, handler)
                    if handler is handlers[sig]:
                        fail("handler")
                    elif callable(handler) and handler.__name__ == "record_abort":
                        fail("recorder")
                    return previous
                def checking():
                    result = pending()
                    fail("pending")
                    return result
                with mock.patch.object(imp, "run_import", side_effect=finish), mock.patch.object(signal, "pthread_sigmask", side_effect=masking), mock.patch.object(signal, "signal", side_effect=register), mock.patch.object(signal, "sigpending", side_effect=checking):
                    code, out, err = self.run_main()
                self.assertTrue(state["raised"])
                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                self.assertEqual(err.count("E_IMPORT_INTERNAL"), 1)
                self.assertNotIn("private fixture detail", err)
                self.assertEqual(mask(signal.SIG_BLOCK, []), original_mask)
                self.assertEqual({sig: signal.getsignal(sig) for sig in imp.ABORT_SIGNALS}, handlers)

    def test_final_teardown_caller_blocked_boundary(self):
        mask, install = signal.pthread_sigmask, signal.signal
        saved_mask = mask(signal.SIG_BLOCK, imp.ABORT_SIGNALS)
        original_mask = mask(signal.SIG_BLOCK, [])
        handlers = {sig: signal.getsignal(sig) for sig in imp.ABORT_SIGNALS}
        try:
            for queued in imp.ABORT_SIGNALS:
                with self.subTest(signal=queued):
                    state = {"finished": False, "queued": False}
                    def finish(*args, **kwargs):
                        state["finished"] = True
                    def masking(how, signals):
                        previous = mask(how, signals)
                        if state["finished"] and how == signal.SIG_SETMASK and not state["queued"]:
                            os.kill(os.getpid(), queued)
                            state["queued"] = True
                        return previous
                    with mock.patch.object(imp, "run_import", side_effect=finish), mock.patch.object(signal, "pthread_sigmask", side_effect=masking):
                        code, out, err = self.run_main()
                    self.assertTrue(state["queued"])
                    self.assertEqual((code, out, err), (0, "twadmin: import verified\n", ""))
                    self.assertIn(queued, signal.sigpending())
                    self.assertEqual(mask(signal.SIG_BLOCK, []), original_mask)
                    self.assertEqual({sig: signal.getsignal(sig) for sig in imp.ABORT_SIGNALS}, handlers)
                    signal.sigwait({queued})
        finally:
            for sig in signal.sigpending() & set(imp.ABORT_SIGNALS):
                signal.sigwait({sig})
            for sig, handler in handlers.items():
                install(sig, handler)
            mask(signal.SIG_SETMASK, saved_mask)

    def test_source_mixed_signal_flood(self):
        import time
        self.mode("signal_wait")
        # Each barrier pauses a real child lifecycle stage. Only this test's
        # importer and its recorded source group ever receive signals.
        for trigger in ("launch", "read", "cleanup"):
            with self.subTest(trigger=trigger):
                stage_file = self.bin / "flood-stage"
                release = self.bin / "flood-release"
                proof = self.bin / "flood-proof"
                for path in (stage_file, release, proof, self.bin / "group-ready"):
                    path.unlink(missing_ok=True)
                program = "\n".join([
                    "import sys,os,signal,time,json,getpass",
                    "from pathlib import Path",
                    "sys.path.insert(0," + repr(str(Path(__file__).parent)) + ")",
                    "from test_bitwarden_import import FakeRuntime,FakeClient,ImportTests",
                    "from tw import admin,bitwarden_import as source",
                    "stage_file=Path(" + repr(str(stage_file)) + ")",
                    "release=Path(" + repr(str(release)) + ")",
                    "proof=Path(" + repr(str(proof)) + ")",
                    "trigger=" + repr(trigger),
                    "if trigger=='cleanup': source.SOURCE_TIMEOUT=0.3",
                    "events=[]; masks=[]; children=[]",
                    "def stage(name):",
                    "    events.append(name)",
                    "    masks.append(set(source.ABORT_SIGNALS) <= signal.pthread_sigmask(signal.SIG_BLOCK, []))",
                    "    stage_file.write_text(name)",
                    "    deadline=time.monotonic()+8",
                    "    while not release.exists() or release.read_text()!=name:",
                    "        if time.monotonic()>deadline: raise RuntimeError('barrier timeout')",
                    "        time.sleep(0.005)",
                    "popen=source.subprocess.Popen; killpg=os.killpg",
                    "def launch(*args,**kwargs):",
                    "    child=popen(*args,**kwargs)",
                    "    children.append(child)",
                    "    if args[0][1]=='sync': return child",
                    "    wait=child.wait; close=child.stdout.close",
                    "    def reap(*args,**kwargs):",
                    "        stage('wait')",
                    "        result=wait(*args,**kwargs)",
                    "        try: os.waitpid(child.pid,os.WNOHANG)",
                    "        except ChildProcessError: events.append('reaped')",
                    "        ImportTests().assert_group_gone(child.pid)",
                    "        events.append('group-gone')",
                    "        return result",
                    "    def closing():",
                    "        stage('close')",
                    "        return close()",
                    "    child.wait=reap; child.stdout.close=closing",
                    "    if trigger=='launch': stage('launch')",
                    "    return child",
                    "def terminate(pid,sig):",
                    "    if sig==signal.SIGKILL and children[-1].stdout is not None: stage('kill')",
                    "    return killpg(pid,sig)",
                    "source.subprocess.Popen=launch; os.killpg=terminate",
                    "source.BW_EXECUTABLE=" + repr(self.executable),
                    "source.trusted_executable=lambda path:path",
                    "admin.human_context_allowed=lambda op:True",
                    "admin.AdminClient=lambda home:FakeClient(FakeRuntime())",
                    "getpass.getpass=lambda prompt:'test-passphrase'",
                    "handlers={sig:signal.getsignal(sig) for sig in source.ABORT_SIGNALS}",
                    "mask=signal.pthread_sigmask(signal.SIG_BLOCK, [])",
                    "result=source.main(" + repr(["--home", str(self.home), str(self.manifest)]) + ")",
                    "restored=mask==signal.pthread_sigmask(signal.SIG_BLOCK, []) and all(signal.getsignal(sig)==handler for sig,handler in handlers.items())",
                    "proof.write_text(json.dumps([events,masks,restored]))",
                    "sys.exit(result)",
                ])
                mutation = getattr(imp, "_probe_source", None)
                if mutation is not None:
                    program = ("import tw.bitwarden_import as injected\nexec(compile(" + repr(mutation)
                               + ",injected.__file__,'exec'),injected.__dict__)\n" + program)
                group = None
                with subprocess.Popen([sys.executable, "-c", program], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as importer:
                    def await_file(path, value=None):
                        deadline = time.monotonic() + 10
                        while time.monotonic() < deadline:
                            if path.exists() and (value is None or path.read_text() == value):
                                return
                            if importer.poll() is not None:
                                self.fail("importer exited before lifecycle barrier")
                            time.sleep(0.005)
                        self.fail("importer lifecycle barrier timed out")
                    try:
                        group = self.await_group_ready(self.bin / "group-ready", importer, timeout=10)
                        if trigger == "read":
                            importer.send_signal(signal.SIGHUP)
                        stages = (["launch"] if trigger == "launch" else []) + ["kill", "close", "wait"]
                        for stage in stages:
                            await_file(stage_file, stage)
                            # Delay every cleanup stage with a real mixed flood.
                            for sig in (signal.SIGHUP, signal.SIGTERM, signal.SIGQUIT, signal.SIGINT) * 8:
                                importer.send_signal(sig)
                                time.sleep(0.003)
                            release.write_text(stage)
                        out, err = importer.communicate(timeout=10)
                        self.assertEqual(importer.returncode, 1)
                        self.assertIn(b"E_IMPORT_ABORT", err)
                        events, masks, restored = json.loads(proof.read_text())
                        self.assertEqual(events, stages + ["reaped", "group-gone"])
                        self.assertTrue(all(masks))
                        self.assertTrue(restored)
                        self.assert_group_gone(group)
                        self.assert_clean(out, err)
                    finally:
                        if group is not None:
                            try:
                                os.killpg(group, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                        if importer.poll() is None:
                            importer.kill()
                            importer.wait()

    def test_source_bounded_reader_and_group_cleanup(self):
        import time
        import threading
        for mode in ("above_cap", "sustained", "grandchild", "parse_grandchild"):
            self.mode(mode)
            groups = []
            original = subprocess.Popen
            original_kill = os.killpg
            watchdogs = []
            source_fds = []
            def emergency(pid):
                try:
                    original_kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            def launch(*args, **kwargs):
                process = original(*args, **kwargs)
                groups.append(process)
                source_fds.append(process.stdout.fileno())
                watchdog = threading.Timer(2, emergency, args=(process.pid,))
                watchdogs.append(watchdog)
                watchdog.start()
                return process
            started = time.monotonic()
            try:
                with mock.patch.object(imp, "MAX_SOURCE", 4096), mock.patch.object(imp, "SOURCE_TIMEOUT", 0.5), mock.patch.object(imp.subprocess, "Popen", side_effect=launch) as launched, mock.patch.object(imp.os, "killpg", wraps=os.killpg) as killed, mock.patch.object(imp.os, "read", wraps=os.read) as reads:
                    with self.assertRaises(imp.ImportFailure):
                        if mode in {"above_cap", "sustained", "grandchild"}:
                            with imp.source_output(["get", "item", ITEM]):
                                pass
                        else:
                            imp.read_source(entry())
                    self.assertLess(time.monotonic() - started, 1.5)
                    if mode == "grandchild":
                        self.assertGreaterEqual(time.monotonic() - started, 0.4)
                    self.assertTrue(launched.call_args.kwargs["start_new_session"])
                    self.assertTrue(launched.call_args.kwargs["close_fds"])
                    killed.assert_called_with(groups[0].pid, signal.SIGKILL)
                    self.assertIsNotNone(groups[0].returncode)
                    self.assertTrue(groups[0].stdout.closed)
                    if mode in {"above_cap", "sustained"}:
                        # No read may request space past the cap plus one byte.
                        self.assertTrue(all(0 < call.args[1] <= 4097 for call in reads.call_args_list if call.args[0] in source_fds))
            finally:
                for watchdog in watchdogs:
                    watchdog.cancel()
                for process in groups:
                    if process.returncode is None:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    process.wait()

    def test_source_production_cap_stops_at_one_extra_byte(self):
        self.mode("above_cap")
        original = os.read
        retained = []
        def read(fd, size):
            chunk = original(fd, size)
            if size <= 65536:
                retained.append(len(chunk))
            return chunk
        with mock.patch.object(imp.os, "read", side_effect=read):
            with self.assertRaises(imp.ImportFailure):
                with imp.source_output(["get", "item", ITEM]):
                    self.fail("overflow accepted")
        self.assertEqual(sum(retained), imp.MAX_SOURCE + 1)

    def test_source_signal_cleanup(self):
        self.mode("grandchild")
        processes = []
        original = subprocess.Popen
        def launch(*args, **kwargs):
            child = original(*args, **kwargs)
            processes.append(child)
            return child
        try:
            with mock.patch.object(imp.subprocess, "Popen", side_effect=launch), mock.patch.object(imp.selectors.DefaultSelector, "select", side_effect=imp.ImportFailure("E_IMPORT_ABORT")), mock.patch.object(imp.os, "killpg", wraps=os.killpg) as killed:
                with self.assertRaises(imp.ImportFailure) as failure:
                    imp.read_source(entry())
            self.assertEqual(failure.exception.code, "E_IMPORT_ABORT")
            killed.assert_called_once()
            self.assertIsNotNone(processes[0].returncode)
        finally:
            for child in processes:
                child.wait()

    def test_manifest_strict(self):
        invalid = [dict(version=True, items=[entry()]), dict(version=1, items=[]),
                   dict(version=1, items=[entry(), entry()]), dict(version=1, items=[entry(value="forbidden")]),
                   dict(version=1, items=[entry(login="password")]), dict(version=1, items=[entry(item_id="bad")]),
                   dict(version=1, items=[entry(project="../escape")]), dict(version=1, items=[entry(path="a/b")]),
                   dict(version=1, items=[entry(**{"class": "unknown"})]), dict(version=1, items=[entry(field="")]),
                   dict(version=1, items=[entry(field="bad\nname")]), dict(version=1, items=[dict(login="uri")])]
        for manifest in invalid:
            with self.subTest(manifest_index=invalid.index(manifest)):
                self.manifest.write_text(json.dumps(manifest))
                code, _, err = self.run_main()
                self.assertEqual(code, 1)
                self.assertIn("E_IMPORT_MANIFEST", err)
        self.manifest.write_text('{"version":1,"version":1,"items":[' + json.dumps(entry()) + ']}')
        self.assertEqual(self.run_main()[0], 1)
        self.assertEqual(self.runtime.put_calls, 0)

    def test_source_failure_paths_leak_nothing(self):
        for mode in ("sync_exit", "exit", "malformed", "duplicate_json", "wrong_id", "bad_revision", "missing", "duplicate_field", "empty", "type", "large"):
            with self.subTest(mode=mode):
                self.mode(mode)
                code, _, err = self.run_main()
                self.assertEqual(code, 1)
                self.assertIn("E_IMPORT_SOURCE", err)
                self.assertEqual(self.rows()[0]["state"], "failed")
                self.assertEqual(self.rows()[0]["error"], "E_IMPORT_SOURCE")
        self.assertEqual(self.runtime.put_calls, 0)

    def test_revision_freeze_stops_before_write(self):
        self.mode("revision")
        code, _, err = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("E_IMPORT_REVISION", err)
        self.assertEqual(self.runtime.put_calls, 0)
        self.assertEqual(self.rows()[0]["revision"], REVISION)
        self.assertEqual(self.rows()[0]["error"], "E_IMPORT_REVISION")

    def test_remote_revision_after_write_marks_stale_and_blocks_resume(self):
        original = self.runtime.put
        def put(*args):
            receipt = original(*args)
            self.mode("cached_revision")  # Remote source changes just after write.
            return receipt
        self.runtime.put = put
        code, _, err = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("E_IMPORT_STALE", err)
        self.assertEqual(self.runtime.put_calls, 1)
        self.assertEqual(self.rows()[0]["state"], "failed")
        self.assertEqual(self.rows()[0]["error"], "E_IMPORT_STALE")
        self.assertEqual(int((self.bin / "sync-count").read_text()), 2)
        with mock.patch.object(imp, "read_source", side_effect=RuntimeError(VALUE)) as source:
            self.assertIn("E_IMPORT_STALE", self.run_main()[2])
        source.assert_not_called()
        self.assertEqual(self.runtime.put_calls, 1)

    def test_remote_revision_mid_batch_marks_only_changed_target_stale(self):
        self.save([entry(), entry(item_id=OTHER_ITEM, path="other")])
        original = self.runtime.put
        def put(*args):
            receipt = original(*args)
            self.mode("cached_mid_batch")  # Change is hidden until final refresh.
            return receipt
        self.runtime.put = put
        code, _, err = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("E_IMPORT_STALE", err)
        self.assertEqual(len(self.runtime.versions), 2)
        rows = {row["item"]: row for row in self.rows()}
        self.assertEqual(rows[imp.entry_hash(entry())]["state"], "verified")
        self.assertEqual(rows[imp.entry_hash(entry(item_id=OTHER_ITEM, path="other"))]["error"], "E_IMPORT_STALE")
        self.assertEqual(int((self.bin / "sync-count").read_text()), 2)

    def test_batch_refreshes_before_planning(self):
        self.mode("initial_stale")
        self.assertEqual(self.run_main()[0], 0)
        self.assertEqual(self.rows()[0]["revision"], REVISION)
        self.assertTrue(all(value == VALUE.encode() for value in self.runtime.versions))

    def test_use_check_does_not_verify_before_final_source_refresh(self):
        original = imp.sync_source
        count = 0
        def sync(**kwargs):
            nonlocal count
            count += 1
            if count == 2:
                self.assertEqual(self.rows()[0]["state"], "written")
            return original(**kwargs)
        with mock.patch.object(imp, "sync_source", side_effect=sync):
            self.assertEqual(self.run_main()[0], 0)
        self.assertEqual(count, 2)
        self.assertEqual(self.rows()[0]["state"], "verified")

    def test_final_source_failures_preserve_receipt_without_verifying(self):
        for mode in ("end_sync_exit", "end_read_malformed"):
            with self.subTest(mode=mode):
                counter = self.bin / "sync-count"
                if counter.exists():
                    counter.unlink()
                self.mode(mode)
                code, _, err = self.run_main()
                self.assertEqual(code, 1)
                self.assertIn("E_IMPORT_SOURCE", err)
                self.assertEqual(self.rows()[0]["state"], "failed")
                self.assertEqual(self.rows()[0]["error"], "E_IMPORT_SOURCE")
                self.assertEqual(len(self.runtime.versions), 1)
        self.mode("ok")
        self.assertEqual(self.run_main()[0], 0)
        self.assertEqual(len(self.runtime.versions), 1)

    def test_stable_request_id_and_ambiguous_resume(self):
        self.runtime.fail = "ambiguous"
        self.assertEqual(self.run_main()[0], 1)
        before = self.rows()[0]["request_id"]
        self.assertEqual(len(self.runtime.versions), 1)
        self.assertEqual(self.run_main()[0], 0)
        self.assertEqual(self.rows()[0]["request_id"], before)
        self.assertEqual(self.rows()[0]["state"], "verified")
        self.assertEqual(len(self.runtime.versions), 1)
        self.assertEqual(before, imp.request_id(entry(), REVISION))
        from tw.cloud_http import request_id as cloud_request_id
        self.assertEqual(cloud_request_id(before), before)
        self.assertNotEqual(before, imp.request_id(entry(), "2026-10-16T12:00:00Z"))

    def test_verified_rows_skip_source_and_write_on_resume(self):
        self.assertEqual(self.run_main()[0], 0)
        with mock.patch.object(imp, "read_source", side_effect=RuntimeError(VALUE)):
            self.assertEqual(self.run_main()[0], 0)
        self.assertEqual(self.runtime.put_calls, 1)

    def test_abort_preserves_earlier_item_and_freezes_all_revisions(self):
        self.save([entry(), entry(item_id=OTHER_ITEM, path="other")])
        self.mode("second_revision")
        code, _, err = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("earlier writes remain in place", err)
        self.assertEqual(len(self.runtime.versions), 1)
        self.assertEqual(sorted(row["state"] for row in self.rows()), ["failed", "verified"])
        self.mode("ok")
        self.assertEqual(self.run_main()[0], 0)
        self.assertEqual(len(self.runtime.versions), 2)
        self.assertEqual(self.runtime.put_calls, 2)

    def test_verify_requires_matching_decrypted_value(self):
        self.runtime.fail = "mismatch"
        code, _, err = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("E_IMPORT_VERIFY", err)
        self.assertEqual(self.rows()[0]["state"], "failed")
        self.runtime.fail = ""
        self.assertEqual(self.run_main()[0], 0)
        self.assertEqual(len(self.runtime.versions), 1)

    def test_written_state_is_durable_before_use_check(self):
        original = self.runtime.verify
        def verify(*args):
            self.assertEqual(self.rows()[0]["state"], "written")
            return original(*args)
        self.runtime.verify = verify
        self.assertEqual(self.run_main()[0], 0)

    def test_broker_readiness_fails_closed_before_source(self):
        scenarios = [("sealed", True, True, "E_IMPORT_SEALED"),
                     ("unsealed", False, True, "E_IMPORT_ORG"),
                     ("unsealed", True, False, "E_IMPORT_HEAD")]
        for seal, joined, head, code in scenarios:
            self.client.seal.state = seal
            self.runtime.joined, self.runtime.current = joined, head
            with mock.patch.object(imp, "read_source", side_effect=RuntimeError(VALUE)) as source:
                result, _, err = self.run_main()
            self.assertEqual(result, 1)
            self.assertIn(code, err)
            source.assert_not_called()
        self.assertEqual(self.runtime.put_calls, 0)

    def test_recheck_head_before_each_write(self):
        original = imp.read_source
        count = 0
        def source(target, **options):
            nonlocal count
            count += 1
            result = original(target, **options)
            if count == 2:
                self.runtime.current = False
            return result
        with mock.patch.object(imp, "read_source", side_effect=source):
            self.assertEqual(self.run_main()[0], 1)
        self.assertEqual(self.runtime.put_calls, 0)

    def test_core_limit_refusal_and_child_inheritance(self):
        with mock.patch.object(imp.resource, "setrlimit", side_effect=OSError(VALUE)):
            code, _, err = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("E_IMPORT_CORE", err)
        with mock.patch.object(imp.resource, "getrlimit", return_value=(1, 1)):
            with self.assertRaises(imp.ImportFailure):
                imp.disable_core()
            self.assertEqual(self.run_main()[0], 1)
        self.assertEqual(self.run_main()[0], 0)  # fake bw independently checks (0, 0)

    def test_lock_excludes_second_importer_and_crash_marker_survives(self):
        state = self.home / "state"
        with imp.maintenance(state):
            self.assertTrue((state / "bitwarden-import.lock").exists())
            code, _, err = self.run_main()
            self.assertEqual(code, 1)
            self.assertIn("E_IMPORT_LOCK", err)
        self.runtime.fail = "write"
        self.assertEqual(self.run_main()[0], 1)
        self.assertTrue((state / "bitwarden-import.lock").exists())

    def test_journal_permissions_fsync_and_changed_manifest_refuse(self):
        with mock.patch.object(imp.os, "fsync", wraps=os.fsync) as fsync:
            self.assertEqual(self.run_main()[0], 0)
        self.assertGreaterEqual(fsync.call_count, 8)
        path = self.home / "state" / "bitwarden-import.sqlite3"
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.save([entry(path="different")])
        code, _, err = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("E_IMPORT_JOURNAL", err)

    def test_fixed_diagnostics_all_runtime_failures(self):
        for mode, code in (("write", "E_IMPORT_WRITE"), ("verify", "E_IMPORT_VERIFY"),
                           ("head_exception", "E_IMPORT_HEAD")):
            self.runtime.fail = mode
            result, _, err = self.run_main()
            self.assertEqual(result, 1)
            self.assertIn(code, err)
        self.runtime.fail = ""
        with mock.patch.object(self.client.seal, "check_passphrase", side_effect=RuntimeError(VALUE)):
            self.assertIn("E_IMPORT_AUTH", self.run_main()[2])
        for failure, code in ((KeyboardInterrupt(), "E_IMPORT_ABORT"), (SystemExit(VALUE), "E_IMPORT_INTERNAL"),
                              (RuntimeError(VALUE), "E_IMPORT_INTERNAL"), (imp.ImportFailure("E_IMPORT_ABORT"), "E_IMPORT_ABORT")):
            with mock.patch.object(imp, "run_import", side_effect=failure):
                self.assertIn(code, self.run_main()[2])

    def test_parser_errors_and_cli_route_are_fixed(self):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(admin, "human_context_allowed", return_value=True), redirect_stdout(out), redirect_stderr(err):
            result = admin.main(["import-bitwarden", "--unknown", VALUE])
        self.assertEqual(result, 1)
        self.assert_clean(out.getvalue(), err.getvalue())
        self.assertIn("E_IMPORT_MANIFEST", err.getvalue())

    def test_broker_adapter_denies_unauthenticated_and_missing_runtime(self):
        self.client.session.clear()
        response = self.client.call("import_verify", {})
        self.assertEqual(response["code"], "E_IMPORT_AUTH")
        response = self.client.call("import_status", {"entries": [entry()]})
        self.assertEqual(response["code"], "E_IMPORT_AUTH")
        self.client.bitwarden_runtime = None
        result = self.client.call("import_status", {})["result"]
        self.assertIs(result["joined"], False)
        self.assertIs(result["current_head"], False)
        self.assert_clean(json.dumps(response), json.dumps(result))

    def test_broker_does_not_unseal_for_import_auth(self):
        self.client.seal.state = "sealed"
        with mock.patch.object(self.client.seal, "check_passphrase") as check:
            response = self.client.call("import_auth", {"passphrase": "test"})
        self.assertEqual(response["code"], "E_IMPORT_SEALED")
        check.assert_not_called()

    def test_admin_service_registers_narrow_import_dispatch(self):
        service = AdminService.__new__(AdminService)
        service.seal = self.client.seal
        service.bitwarden_runtime = self.runtime
        response = service.handle(self.client.session, dict(op="import_status", args={}), [])
        self.assertIs(response["ok"], True)
        self.assertIs(response["result"]["current_head"], True)
        self.client.session.clear()
        response = service.handle(self.client.session, dict(op="import_put", args={}), [])
        self.assertEqual(response["code"], "E_IMPORT_AUTH")

    def test_child_launch_and_timeout_diagnostics_cannot_escape(self):
        failures = [OSError(VALUE), subprocess.TimeoutExpired("bw", 30, output=VALUE.encode(), stderr=UNSELECTED.encode()),
                    UnicodeDecodeError("utf-8", VALUE.encode(), 0, 1, UNSELECTED)]
        for failure in failures:
            with mock.patch.object(imp.subprocess, "Popen", side_effect=failure):
                code, _, err = self.run_main()
            self.assertEqual(code, 1)
            self.assertIn("E_IMPORT_SOURCE", err)

    def test_journal_and_marker_symlinks_refuse(self):
        state = self.home / "state"
        target = self.root / "target"
        target.touch(mode=0o600)
        journal = state / "bitwarden-import.sqlite3"
        journal.symlink_to(target)
        self.assertIn("E_IMPORT_JOURNAL", self.run_main()[2])
        journal.unlink()
        marker = state / "bitwarden-import.lock"
        marker.unlink()
        marker.symlink_to(target)
        self.assertIn("E_IMPORT_LOCK", self.run_main()[2])

    def test_journal_sync_failure_prevents_write(self):
        with mock.patch.object(imp.Journal, "flush", side_effect=OSError(VALUE)):
            code, _, err = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("E_IMPORT_JOURNAL", err)
        self.assertEqual(self.runtime.put_calls, 0)

    def test_journal_synchronous_extra_and_metadata_only(self):
        journal = imp.Journal(self.home / "state", [entry()])
        try:
            self.assertEqual(journal.db.execute("PRAGMA synchronous").fetchone()[0], 3)
            self.assertEqual(journal.db.execute("PRAGMA temp_store").fetchone()[0], 2)
            self.assertEqual(journal.db.execute("PRAGMA journal_mode").fetchone()[0], "delete")
            journal.plan(entry(), REVISION)
            row = dict(journal.row(entry()))
            self.assertEqual(set(row), {"batch", "item", "revision", "request_id", "state", "error"})
            self.assertNotIn("token", json.dumps(row))
            self.assertNotIn("infra", json.dumps(row))
            self.assert_clean()
        finally:
            journal.close()

    def test_manifest_parser_never_emits_input_fragments(self):
        for raw in (b'{"value":' + VALUE.encode(), b'\xff' + UNSELECTED.encode()):
            with mock.patch("builtins.open", mock.mock_open(read_data=raw)):
                code, _, err = self.run_main()
            self.assertEqual(code, 1)
            self.assertIn("E_IMPORT_MANIFEST", err)

    def test_proposed_hook_marker_present_absent_and_unreadable(self):
        proposal = (Path(__file__).resolve().parents[1] / "docs" / "bitwarden-import.md").read_text()
        block = proposal.split("```diff\n", 1)[1].split("```", 1)[0]
        lines = [line[1:] for line in block.splitlines() if line.startswith((" ", "+"))]
        namespace = {}
        exec(compile("\n".join(lines), "hook-proposal", "exec"), namespace)
        check = namespace["import_maintenance_active"]
        with mock.patch.object(namespace["os"], "stat", return_value=object()):
            self.assertIs(check(), True)
        with mock.patch.object(namespace["os"], "stat", side_effect=FileNotFoundError()):
            self.assertIs(check(), False)
        with mock.patch.object(namespace["os"], "stat", side_effect=PermissionError(VALUE)):
            self.assertIs(check(), True)
        self.assertIn("+    if import_maintenance_active():\n+        return True", proposal)

    def test_separate_public_marker_directory_keeps_journal_private(self):
        public = self.root / "public-marker"
        public.mkdir(mode=0o755)
        observed = []
        original = self.runtime.put
        def put(*args):
            observed.append((public / "bitwarden-import.lock").is_file())
            return original(*args)
        self.runtime.put = put
        imp.run_import(self.home, [entry()], self.client, public)
        self.assertEqual(observed, [True])
        self.assertFalse((public / "bitwarden-import.lock").exists())
        self.assertTrue((self.home / "state" / "bitwarden-import.sqlite3").exists())
        self.assertFalse((public / "bitwarden-import.sqlite3").exists())
        self.assert_clean()

    def test_existing_target_stops_whole_plan_before_source_or_write(self):
        self.save([entry(), entry(item_id=OTHER_ITEM, path="other")])
        self.runtime.existing.add(("infra", "other"))
        with mock.patch.object(imp, "read_source", side_effect=RuntimeError(VALUE)) as source:
            code, _, err = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("E_IMPORT_EXISTS", err)
        self.assertEqual(self.runtime.put_calls, 0)
        self.assertEqual(len(self.runtime.versions), 0)
        source.assert_not_called()
        self.assertEqual(sorted(row["state"] for row in self.rows()), ["failed", "planned"])

    def test_target_creation_race_refuses_without_replacing_value(self):
        original = imp.read_source
        def source(target, **options):
            result = original(target, **options)
            self.runtime.existing.add((target["project"], target["path"]))
            return result
        with mock.patch.object(imp, "read_source", side_effect=source):
            self.assertEqual(self.run_main()[0], 1)
        self.assertEqual(len(self.runtime.versions), 0)

    def test_unexpected_exception_records_only_fixed_error(self):
        with mock.patch.object(imp, "verify", side_effect=RuntimeError(VALUE)):
            code, _, err = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("E_IMPORT_INTERNAL", err)
        self.assertEqual(self.rows()[0]["state"], "failed")
        self.assertEqual(self.rows()[0]["error"], "E_IMPORT_INTERNAL")

    def test_subprocess_source_failures_never_reach_process_output(self):
        # OS-level pipes also capture an accidentally inherited child stderr,
        # which redirect_stderr alone cannot intercept. This is a test driver
        # for the one importer process, with its normal directly spawned bw.
        tests = str(Path(__file__).parent)
        program = (
            "import sys,getpass\n"
            "sys.dont_write_bytecode=True\n"
            "sys.path.insert(0," + repr(tests) + ")\n"
            "from test_bitwarden_import import FakeRuntime,FakeClient\n"
            "from tw import admin,bitwarden_import as source\n"
            "source.BW_EXECUTABLE=" + repr(self.executable) + "\n"
            "source.trusted_executable=lambda path:path\n"
            "admin.human_context_allowed=lambda op:True\n"
            "client=FakeClient(FakeRuntime())\n"
            "admin.AdminClient=lambda _home:client\n"
            "getpass.getpass=lambda _prompt:'test-passphrase'\n"
            "sys.exit(admin.main(" + repr(["--home", str(self.home), "import-bitwarden", str(self.manifest)]) + "))\n"
        )
        # The in-memory mutation harness must reach this real process boundary.
        mutation = getattr(imp, "_probe_source", None)
        if mutation is not None:
            program = ("import tw.bitwarden_import as injected\nexec(compile(" + repr(mutation)
                       + ",injected.__file__,'exec'),injected.__dict__)\n" + program)
        for mode in ("sync_exit", "exit", "malformed", "duplicate_json", "wrong_id", "bad_revision", "missing", "duplicate_field", "empty", "type", "large"):
            with self.subTest(mode=mode):
                self.mode(mode)
                result = subprocess.run([sys.executable, "-c", program], stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, timeout=30)
                self.assertEqual(result.returncode, 1)
                self.assertIn(b"E_IMPORT_SOURCE", result.stderr)
                self.assert_clean(result.stdout, result.stderr)


if __name__ == "__main__":
    unittest.main()
