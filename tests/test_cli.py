import contextlib
import io
import os
import socket
import secrets
import tempfile
import threading
import sys
import unittest
from pathlib import Path
from unittest import mock

from tw import cli
from tw.protocol import recv_frame_with_fds, send_frame


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(dir="/tmp", prefix="twcli")
        self.home = Path(self.tempdir.name)

    def tearDown(self):
        self.tempdir.cleanup()

    def _token_file(self, name="token"):
        path = self.home / name
        path.write_text("twt_" + secrets.token_urlsafe(32) + "\n")
        os.chmod(path, 0o600)
        return path

    def test_identity_resolution_order(self):
        direct = self._token_file("direct")
        pane = self._token_file("pane-token")
        (self.home / "panes").mkdir()
        (self.home / "panes" / "pane_handle").write_text(str(pane) + "\n")
        token, lease = cli.resolve_identity(
            self.home,
            {
                "TW_TOKEN_FILE": str(direct),
                "TW_LEASE": "lea_claim",
                "ORCA_TERMINAL_HANDLE": "pane_handle",
            },
        )
        self.assertIsNotNone(token)
        self.assertIsNone(lease)
        token, lease = cli.resolve_identity(
            self.home,
            {"TW_LEASE": "lea_claim", "ORCA_TERMINAL_HANDLE": "pane_handle"},
        )
        self.assertIsNone(token)
        self.assertEqual(lease, "lea_claim")
        token, lease = cli.resolve_identity(
            self.home, {"ORCA_TERMINAL_HANDLE": "pane_handle"}
        )
        self.assertIsNotNone(token)
        self.assertIsNone(lease)

    def test_response_with_token_shaped_text_is_refused(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(cli.CliError):
            cli._safe_output({"unsafe": "twt_" + secrets.token_urlsafe(32)})
        self.assertEqual(output.getvalue(), "")

    def test_names_request_uses_protocol_and_prints_names_only(self):
        token_file = self._token_file()
        run_dir = self.home / "run"
        run_dir.mkdir()
        socket_path = run_dir / "tw.sock"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(socket_path))
        server.listen(1)
        captured = {}

        def serve():
            connection, _address = server.accept()
            with connection:
                request, fds = recv_frame_with_fds(connection)
                captured.update(request)
                for fd in fds:
                    os.close(fd)
                send_frame(
                    connection,
                    {
                        "ok": True,
                        "code": "ok",
                        "result": {"names": [{"path": "alpha/key", "class": "standard"}]},
                    },
                )

        thread = threading.Thread(target=serve)
        thread.start()
        output = io.StringIO()
        errors = io.StringIO()
        environment = {"TW_HOME": str(self.home), "TW_TOKEN_FILE": str(token_file)}
        try:
            with mock.patch.dict(os.environ, environment, clear=True), contextlib.redirect_stdout(
                output
            ), contextlib.redirect_stderr(errors):
                exit_code = cli.main(["names", "alpha"])
        finally:
            thread.join(timeout=2)
            server.close()
        self.assertEqual(exit_code, 0)
        self.assertEqual(errors.getvalue(), "")
        self.assertIn("alpha/key", output.getvalue())
        self.assertNotIn("twt_", output.getvalue())
        self.assertEqual(captured["op"], "names")
        self.assertEqual(captured["args"], {"project": "alpha"})

    def test_unreachable_broker_runs_locally_when_every_reference_is_soft(self):
        marker = self.home / "ran"
        errors = io.StringIO()
        environment = {"TW_HOME": str(self.home)}
        with mock.patch.dict(os.environ, environment, clear=True), contextlib.redirect_stderr(
            errors
        ):
            exit_code = cli.main(
                [
                    "run",
                    "--soft",
                    "OPTIONAL=alpha/key",
                    "--",
                    sys.executable,
                    "-c",
                    f"import pathlib;pathlib.Path({str(marker)!r}).touch()",
                ]
            )
        self.assertEqual(exit_code, 0)
        self.assertTrue(marker.exists())
        self.assertIn("OPTIONAL not set", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
