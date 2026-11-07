"""Linux halves of the platform seams: /proc resolver, systemd pid, unit argv grammar."""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tw import admin, identity


class LinuxProcessResolverTests(unittest.TestCase):
    def test_reads_ppid_executable_and_selected_environment_from_proc(self):
        with tempfile.TemporaryDirectory() as root:
            proc = Path(root)
            entry = proc / "42"
            entry.mkdir()
            (entry / "stat").write_text("42 (py thon) S 7 42 42 0 -1 4194560 0 0 0 0 0 0\n")
            os.symlink("/usr/bin/python3.12", entry / "exe")
            (entry / "environ").write_bytes(b"ORCA_TERMINAL_HANDLE=h1\0PATH=/x\0SECRET=no\0")
            info = identity._linux_process_info(42, proc)
            self.assertEqual((info.pid, info.ppid, info.executable), (42, 7, "/usr/bin/python3.12"))
            self.assertEqual(dict(info.environment), {"ORCA_TERMINAL_HANDLE": "h1"})
            self.assertIsNone(identity._linux_process_info(43, proc))


class SystemdBrokerPidTests(unittest.TestCase):
    def run_with(self, stdout, returncode=0):
        completed = subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")
        with mock.patch.object(admin.subprocess, "run", return_value=completed):
            return admin.systemd_broker_pid()

    def test_pid_zero_failure_and_garbage_are_not_a_broker(self):
        self.assertEqual(self.run_with("1234\n"), 1234)
        self.assertIsNone(self.run_with("0\n"))
        self.assertIsNone(self.run_with("1234\n", returncode=1))
        self.assertIsNone(self.run_with("MainPID=1234\n"))

    def test_proc_cmdline_requires_the_trailing_nul(self):
        with tempfile.TemporaryDirectory() as root:
            proc = Path(root) / "proc"
            (proc / "9").mkdir(parents=True)
            (proc / "9" / "cmdline").write_bytes(b"python\0-m\0tw.broker\0")
            with mock.patch.object(admin, "PROC", proc):
                self.assertEqual(admin.proc_cmdline(9), ["python", "-m", "tw.broker"])
                (proc / "9" / "cmdline").write_bytes(b"truncated")
                self.assertIsNone(admin.proc_cmdline(9))
                self.assertIsNone(admin.proc_cmdline(10))


class SystemdUnitArgvTests(unittest.TestCase):
    """The shipped unit must satisfy the same peer grammar as the launchd plist."""

    def setUp(self):
        unit = Path(__file__).resolve().parents[1] / "systemd/titanwarden.service"
        line = next(l for l in unit.read_text().splitlines() if l.startswith("ExecStart="))
        self.shipped = line[len("ExecStart="):].split()
        self.home = Path(self.shipped[self.shipped.index("--home") + 1])

    def verify(self, argv):
        with mock.patch("tw.admin.peer_pid", return_value=123), \
                mock.patch("tw.admin.service_broker_pid", return_value=123), \
                mock.patch("tw.admin.broker_argv", return_value=argv):
            return admin.verify_broker_peer(mock.Mock(), self.home)

    def test_shipped_unit_argv_is_accepted_and_extras_are_rejected(self):
        self.assertTrue(self.verify(self.shipped))
        self.assertFalse(self.verify(self.shipped + ["--extra"]))
        self.assertFalse(self.verify(self.shipped[:4] + ["/agent/chosen-home"] + self.shipped[5:]))


if __name__ == "__main__":
    unittest.main()
