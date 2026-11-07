import base64
import hashlib
import os
import secrets
import signal
import sys
import tempfile
import time
import unittest
from pathlib import Path

from tw.execute import BusyError, ExecutionError, ExecutionRequest, Executor
from tw.redact import Redactor, build_patterns


class LeaseRecorder:
    def __init__(self):
        self.opened = []
        self.closed = []

    def open(self, **fields):
        self.opened.append(fields)

    def close(self, **fields):
        self.closed.append(fields)


class ExecutorTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(dir="/tmp", prefix="twexec")
        self.root = Path(self.tempdir.name)
        self.values = {
            "test/primary": secrets.token_urlsafe(40).encode(),
            "test/secondary": secrets.token_urlsafe(40).encode(),
        }
        self.leases = LeaseRecorder()
        self.executor = Executor(
            secret_resolver=self.values.__getitem__,
            redactor_factory=lambda _principal: Redactor(
                build_patterns(self.values, set(self.values))
            ),
            lease_open=self.leases.open,
            lease_close=self.leases.close,
            disconnect_grace=0.15,
        )

    def tearDown(self):
        self.executor.close()
        self.tempdir.cleanup()

    def _outputs(self):
        stdout = tempfile.TemporaryFile()
        stderr = tempfile.TemporaryFile()
        self.addCleanup(stdout.close)
        self.addCleanup(stderr.close)
        return stdout, stderr

    @staticmethod
    def _read(file):
        file.seek(0)
        return file.read()

    def test_child_gets_value_cwd_path_and_exit_code(self):
        digest_file = self.root / "digest"
        script = self.root / "digest-tool"
        script.write_text(
            "#!" + sys.executable + "\n"
            "import hashlib, os, pathlib, sys\n"
            "pathlib.Path(sys.argv[1]).write_text(hashlib.sha256(os.environ['X'].encode()).hexdigest() + '\\n' + os.getcwd())\n"
            "raise SystemExit(23)\n"
        )
        script.chmod(0o700)
        stdout, stderr = self._outputs()
        request = ExecutionRequest(
            lease_id="lea_run",
            token_id="tok_test",
            principal_id="lead:test",
            argv=["digest-tool", str(digest_file)],
            cwd=str(self.root),
            environment={"PATH": str(self.root), "TW_OLD": "remove", "SSH_AUTH_SOCK": "/tmp/sock"},
            env_refs={"X": "test/primary"},
        )
        handle = self.executor.start(request, stdout.fileno(), stderr.fileno())
        self.assertEqual(handle.wait(), 23)
        expected = hashlib.sha256(self.values["test/primary"]).hexdigest()
        digest, cwd = digest_file.read_text().splitlines()
        self.assertEqual(digest, expected)
        self.assertEqual(Path(cwd).resolve(), self.root.resolve())
        self.assertEqual(self.leases.opened[0]["pid"], handle.pid)
        self.assertEqual(self.leases.closed[0]["exit_code"], 23)

    def test_fd_and_stdin_delivery(self):
        stdout, stderr = self._outputs()
        code = (
            "import os,sys;"
            "a=os.read(3,10000);b=sys.stdin.buffer.read();"
            "print(len(a),len(b),int('FD_SECRET' in os.environ))"
        )
        request = ExecutionRequest(
            lease_id="lea_fd",
            token_id="tok_test",
            principal_id="lead:test",
            argv=[sys.executable, "-c", code],
            cwd=str(self.root),
            environment=os.environ.copy(),
            fd_refs={3: "test/primary"},
            stdin_ref="test/secondary",
        )
        handle = self.executor.start(request, stdout.fileno(), stderr.fileno())
        self.assertEqual(handle.wait(), 0)
        self.assertEqual(
            self._read(stdout).strip(),
            f"{len(self.values['test/primary'])} {len(self.values['test/secondary'])} 0".encode(),
        )

    def test_client_stdin_is_not_inherited_by_child(self):
        stdout, stderr = self._outputs()
        read_fd, write_fd = os.pipe()
        os.write(write_fd, b"client-input")
        os.close(write_fd)
        self.addCleanup(os.close, read_fd)
        request = ExecutionRequest(
            "lea_no_stdin",
            "tok_test",
            "lead:test",
            [sys.executable, "-c", "import sys;print(len(sys.stdin.buffer.read()))"],
            str(self.root),
            os.environ.copy(),
        )
        handle = self.executor.start(
            request, stdout.fileno(), stderr.fileno(), stdin_fd=read_fd
        )
        self.assertEqual(handle.wait(), 0)
        self.assertEqual(self._read(stdout).strip(), b"0")

    def test_binary_environment_secret_returns_fixed_error(self):
        stdout, stderr = self._outputs()
        self.values["test/binary"] = b"binary-value-\xff-secret"
        request = ExecutionRequest(
            "lea_binary",
            "tok_test",
            "lead:test",
            [sys.executable, "-c", "pass"],
            str(self.root),
            os.environ.copy(),
            env_refs={"X": "test/binary"},
        )
        with self.assertRaises(ExecutionError) as caught:
            self.executor.start(request, stdout.fileno(), stderr.fileno())
        self.assertEqual(str(caught.exception), "secret value is not valid UTF-8")
        self.assertNotIn("position", str(caught.exception))

    def test_output_is_redacted_across_encodings_and_streams(self):
        stdout, stderr = self._outputs()
        code = (
            "import base64,os,sys;v=os.environ['X'].encode();"
            "sys.stdout.buffer.write(v+b'\\n'+base64.b64encode(v)+b'\\n');"
            "sys.stderr.buffer.write(v.hex().encode()+b'\\n')"
        )
        request = ExecutionRequest(
            lease_id="lea_redact",
            token_id="tok_test",
            principal_id="lead:test",
            argv=[sys.executable, "-c", code],
            cwd=str(self.root),
            environment=os.environ.copy(),
            env_refs={"X": "test/primary"},
        )
        handle = self.executor.start(request, stdout.fileno(), stderr.fileno(), relay_chunk_size=1)
        self.assertEqual(handle.wait(), 0)
        combined = self._read(stdout) + self._read(stderr)
        value = self.values["test/primary"]
        for variant in (value, base64.b64encode(value), value.hex().encode()):
            self.assertNotIn(variant, combined)
        self.assertGreaterEqual(combined.count(b"[tw:test/primary]"), 3)

    def test_signal_is_forwarded_to_child_process_group(self):
        stdout, stderr = self._outputs()
        code = "import signal,time;signal.signal(signal.SIGINT,lambda *_:exit(42));print('ready',flush=True);time.sleep(30)"
        request = ExecutionRequest(
            "lea_signal", "tok_test", "lead:test", [sys.executable, "-c", code],
            str(self.root), os.environ.copy()
        )
        handle = self.executor.start(request, stdout.fileno(), stderr.fileno())
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and b"ready" not in self._read(stdout):
            time.sleep(0.01)
        handle.signal(signal.SIGINT)
        self.assertEqual(handle.wait(), 42)

    def test_disconnect_kills_process_group_and_closes_lease(self):
        stdout, stderr = self._outputs()
        marker = self.root / "ready"
        code = (
            "import pathlib,signal,time;"
            "signal.signal(signal.SIGTERM,lambda *_:None);"
            f"pathlib.Path({str(marker)!r}).touch();"
            "time.sleep(30)"
        )
        request = ExecutionRequest(
            "lea_gone", "tok_test", "lead:test", [sys.executable, "-c", code],
            str(self.root), os.environ.copy()
        )
        handle = self.executor.start(request, stdout.fileno(), stderr.fileno())
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and not marker.exists():
            time.sleep(0.01)
        self.assertTrue(marker.exists())
        handle.disconnect()
        self.assertEqual(handle.wait(), 128 + signal.SIGKILL)
        self.assertEqual(self.leases.closed[-1]["end_reason"], "client_gone")

    def test_lease_closes_when_grandchild_keeps_stdout_open(self):
        stdout, stderr = self._outputs()
        code = (
            "import subprocess,sys;"
            "subprocess.Popen([sys.executable,'-c','import time;time.sleep(5)']);"
            "print('parent done',flush=True)"
        )
        request = ExecutionRequest(
            "lea_grandchild",
            "tok_test",
            "lead:test",
            [sys.executable, "-c", code],
            str(self.root),
            os.environ.copy(),
        )
        handle = self.executor.start(request, stdout.fileno(), stderr.fileno())
        started = time.monotonic()
        self.assertEqual(handle.wait(), 0)
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(self.leases.closed[-1]["lease_id"], "lea_grandchild")

    def test_per_principal_cap(self):
        executor = Executor(
            secret_resolver=self.values.__getitem__,
            redactor_factory=lambda _principal: Redactor([]),
            max_total=4,
            max_per_principal=1,
            disconnect_grace=0.05,
        )
        self.addCleanup(executor.close)
        stdout, stderr = self._outputs()
        request = ExecutionRequest(
            "lea_one", "tok_test", "lead:test", [sys.executable, "-c", "import time;time.sleep(30)"],
            str(self.root), os.environ.copy()
        )
        first = executor.start(request, stdout.fileno(), stderr.fileno())
        with self.assertRaises(BusyError):
            executor.start(
                ExecutionRequest(
                    "lea_two", "tok_test", "lead:test", request.argv, request.cwd, request.environment
                ),
                stdout.fileno(),
                stderr.fileno(),
            )
        first.disconnect()
        first.wait()

    def test_no_shell_refuses_inline_code(self):
        stdout, stderr = self._outputs()
        request = ExecutionRequest(
            "lea_shell",
            "tok_test",
            "lead:test",
            ["sh", "-c", "exit 0"],
            str(self.root),
            os.environ.copy(),
            no_shell=True,
        )
        with self.assertRaises(ExecutionError) as caught:
            self.executor.start(request, stdout.fileno(), stderr.fileno())
        self.assertEqual(caught.exception.code, "E_DENIED")


if __name__ == "__main__":
    unittest.main()
