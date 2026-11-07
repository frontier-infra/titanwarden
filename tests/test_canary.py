import base64
import json
import os
import secrets
import sys
import tempfile
import subprocess
import threading
import unittest
from unittest import mock
from pathlib import Path
from urllib.parse import quote_from_bytes

from tw.execute import ExecutionRequest, Executor
from tw.redact import Redactor, build_patterns
from tw.broker import Broker
from tw.crypto import Argon2Params
from tw.protocol import encode_frame


class ExecuteCanaryTests(unittest.TestCase):
    def test_execute_path_never_relays_or_records_canary(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="twcanary") as directory:
            root = Path(directory)
            canary = secrets.token_urlsafe(40).encode()
            values = {"test/canary": canary}
            lease_rows = []
            executor = Executor(
                secret_resolver=values.__getitem__,
                redactor_factory=lambda _principal: Redactor(
                    build_patterns(values, {"test/canary"})
                ),
                lease_open=lambda **row: lease_rows.append(row),
            )
            stdout = tempfile.TemporaryFile()
            stderr = tempfile.TemporaryFile()
            self.addCleanup(executor.close)
            self.addCleanup(stdout.close)
            self.addCleanup(stderr.close)
            code = (
                "import base64,json,os,sys,urllib.parse;v=os.environ['X'].encode();"
                "forms=[v,base64.b64encode(v),base64.urlsafe_b64encode(v).rstrip(b'='),"
                "v.hex().encode(),urllib.parse.quote_from_bytes(v).encode(),"
                "json.dumps(v.decode())[1:-1].encode()];"
                "sys.stdout.buffer.write(b'\\n'.join(forms));"
                "sys.stderr.buffer.write(v)"
            )
            request = ExecutionRequest(
                "lea_canary",
                "tok_test",
                "lead:test",
                [sys.executable, "-c", code],
                str(root),
                os.environ.copy(),
                env_refs={"X": "test/canary"},
            )
            handle = executor.start(
                request, stdout.fileno(), stderr.fileno(), relay_chunk_size=1
            )
            self.assertEqual(handle.wait(), 0)
            stdout.seek(0)
            stderr.seek(0)
            artifacts = stdout.read() + stderr.read() + json.dumps(lease_rows).encode()
            variants = {
                canary,
                base64.b64encode(canary),
                base64.urlsafe_b64encode(canary).rstrip(b"="),
                canary.hex().encode(),
                quote_from_bytes(canary).encode(),
                json.dumps(canary.decode())[1:-1].encode(),
            }
            for variant in variants:
                self.assertNotIn(variant, artifacts)
            self.assertIn(b"[tw:test/canary]", artifacts)


class BrokerCanaryTests(unittest.TestCase):
    def test_every_success_and_error_frame_excludes_canaries(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="twframes") as directory:
            home = Path(directory) / "home"
            broker = Broker(home, desk=None)
            passphrase = "runtime generated frame passphrase with sufficient length"
            broker.store.initialize(
                passphrase,
                argon2=Argon2Params(memory_kib=8192, iterations=1, lanes=1),
            )
            broker.seal.state = "sealed"
            broker.seal.unseal(passphrase)
            broker.service.identities.roster_sync(
                {"ai": [{"id": "alpha", "run": "run-alpha"}]}, []
            )
            token = broker.service.identities.issue_token(
                "lead:alpha", "lead", created_by="master"
            )
            broker.service.process_resolver = lambda _pid: None
            success_canary = secrets.token_urlsafe(40).encode()
            error_canary = secrets.token_urlsafe(40).encode() + b"\xff"
            for name, value in (("success", success_canary), ("error", error_canary)):
                broker.store.put_secret(
                    f"alpha/{name}",
                    value,
                    keyring=broker.service._keyring(),
                    principal_id="lead:alpha",
                )
            frames = []
            original_send = __import__("tw.broker", fromlist=["send_frame"]).send_frame

            def capture(sock, value):
                frames.append(encode_frame(value))
                return original_send(sock, value)

            environment = os.environ.copy()
            environment.update(
                {"TW_HOME": str(home), "TW_TOKEN_FILE": token["file_path"]}
            )
            with mock.patch("tw.broker.send_frame", side_effect=capture):
                broker.agent.bind()
                thread = threading.Thread(
                    target=broker.agent.serve_forever, daemon=True
                )
                thread.start()
                try:
                    success = subprocess.run(
                        [
                            sys.executable,
                            "-m",
                            "tw.cli",
                            "run",
                            "--env",
                            "X=alpha/success",
                            "--",
                            sys.executable,
                            "-c",
                            "pass",
                        ],
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        env=environment,
                        timeout=10,
                    )
                    error = subprocess.run(
                        [
                            sys.executable,
                            "-m",
                            "tw.cli",
                            "run",
                            "--env",
                            "X=alpha/error",
                            "--",
                            sys.executable,
                            "-c",
                            "pass",
                        ],
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        env=environment,
                        timeout=10,
                    )
                    self.assertEqual(success.returncode, 0, success.stderr.decode())
                    self.assertNotEqual(error.returncode, 0)
                    self.assertGreaterEqual(len(frames), 3)
                    for frame in frames:
                        self.assertNotIn(success_canary, frame)
                        self.assertNotIn(error_canary[:-1], frame)
                finally:
                    broker.close()
                    thread.join(timeout=2)

    def test_canary_absent_from_outputs_database_wal_audit_and_backup(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="twcanarybroker") as directory:
            home = Path(directory) / "home"
            broker = Broker(home, desk=None)
            passphrase = "runtime generated canary passphrase with sufficient length"
            broker.store.initialize(
                passphrase,
                argon2=Argon2Params(memory_kib=8192, iterations=1, lanes=1),
            )
            broker.seal.state = "sealed"
            broker.seal.unseal(passphrase)
            broker.service.identities.roster_sync(
                {"ai": [{"id": "alpha", "run": "run-alpha"}]}, []
            )
            token = broker.service.identities.issue_token(
                "lead:alpha", "lead", created_by="master"
            )
            broker.service.process_resolver = lambda _pid: None
            canary = secrets.token_urlsafe(40).encode()
            broker.store.put_secret(
                "alpha/canary",
                canary,
                keyring=broker.service._keyring(),
                principal_id="lead:alpha",
            )
            broker.agent.bind()
            thread = threading.Thread(target=broker.agent.serve_forever, daemon=True)
            thread.start()
            environment = os.environ.copy()
            environment.update(
                {"TW_HOME": str(home), "TW_TOKEN_FILE": token["file_path"]}
            )
            code = (
                "import base64,json,os,sys,urllib.parse;v=os.environ['X'].encode();"
                "forms=[v,base64.b64encode(v),base64.urlsafe_b64encode(v).rstrip(b'='),"
                "v.hex().encode(),urllib.parse.quote_from_bytes(v).encode(),"
                "json.dumps(v.decode())[1:-1].encode()];"
                "sys.stdout.buffer.write(b'\\n'.join(forms));"
                "sys.stderr.buffer.write(v)"
            )
            try:
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "tw.cli",
                        "run",
                        "--env",
                        "X=alpha/canary",
                        "--",
                        sys.executable,
                        "-c",
                        code,
                    ],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=environment,
                    timeout=10,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr.decode())
                broker.store.checkpoint()
                backup = broker.store.backup(home / "backups" / "backup.db")
                variants = {
                    canary,
                    base64.b64encode(canary),
                    base64.urlsafe_b64encode(canary).rstrip(b"="),
                    canary.hex().encode(),
                    quote_from_bytes(canary).encode(),
                    json.dumps(canary.decode())[1:-1].encode(),
                }
                artifacts = [completed.stdout, completed.stderr, backup.read_bytes()]
                artifacts.extend(
                    path.read_bytes()
                    for path in home.rglob("*")
                    if path.is_file() and path != backup
                )
                for artifact in artifacts:
                    for variant in variants:
                        self.assertNotIn(variant, artifact)
                self.assertIn(b"[tw:alpha/canary]", completed.stdout)
            finally:
                broker.close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
