import tempfile
import unittest
from pathlib import Path

from tw.admin import AdminClient


class AdminClientConnectTests(unittest.TestCase):
    def test_enter_does_not_connect_before_the_first_call(self):
        # The broker drops a silent admin connection after 30 seconds, so the
        # client must not hold one open while a human types a passphrase.
        with tempfile.TemporaryDirectory() as home:
            Path(home, "run").mkdir()
            with AdminClient(Path(home)) as client:
                self.assertIsNone(client.socket)
                with self.assertRaises(OSError):
                    client.call("status", {})


if __name__ == "__main__":
    unittest.main()


class OperatorTtyTests(unittest.TestCase):
    def test_uses_the_named_pty_of_the_first_terminal_fd(self):
        from unittest import mock
        from tw import admin
        names = {2: "/dev/ttys9"}
        def ttyname(fd):
            if fd in names:
                return names[fd]
            raise OSError(25, "not a tty")
        with mock.patch.object(admin.os, "ttyname", side_effect=ttyname):
            self.assertEqual(admin.operator_tty(), "/dev/ttys9")
        with mock.patch.object(admin.os, "ttyname", side_effect=OSError(25, "not a tty")):
            with self.assertRaises(RuntimeError):
                admin.operator_tty()


class InitTerminalGuardTests(unittest.TestCase):
    def test_init_refuses_before_initialize_when_the_terminal_is_not_writable(self):
        import errno
        import os
        from unittest import mock
        from tw.admin_server import AdminService, AdminSession
        from tw.seal import SealManager
        from tw.store import Store
        with tempfile.TemporaryDirectory() as home:
            with Store(home).open(create=True) as store:
                service = AdminService(store, SealManager(store))
                master, slave = os.openpty()
                try:
                    with mock.patch.object(store, "initialize", return_value=(bytes(32), "words")) as initialize, \
                            mock.patch("tw.admin_server.os.write", side_effect=OSError(errno.EIO, "Input/output error")):
                        response = service.handle(AdminSession(), dict(op="init", args=dict(passphrase="x", cloud_broker=False)), [slave])
                    self.assertFalse(response["ok"])
                    self.assertIn("terminal write failed", response["error"])
                    initialize.assert_not_called()
                finally:
                    os.close(master)
                    os.close(slave)
