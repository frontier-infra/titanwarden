"""Concurrency regression: a slow metadata read must not hold the auth lock."""
from __future__ import annotations

import socket
import threading
import unittest
from types import SimpleNamespace

from tw.console import COOKIE, ConsoleApplication, ConsoleServer

SNAPSHOT = dict(seal_state="sealed", frozen=False, initialized=True, secret_count=1, truncated=False,
                secrets=[dict(path="fixture/example", **{"class": "sensitive"}, state="active",
                              versions=1, active_version=1, placements=0, last_used=None,
                              dependents=0, rotation_due=None)])


class Config:
    rp_id = "broker.fixture.ts.net"
    origin = "https://broker.fixture.ts.net"
    allowed_user = "human@example.test"
    active = True
    credentials = ()

    def __init__(self):
        self._lock = threading.RLock()
        self.closed = False

    def close(self):
        self.closed = True


class ConsoleAuthLockTests(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.first_call = threading.Lock()
        self.entered = threading.Event()
        self.finished = threading.Event()
        self.release = threading.Event()
        self.app = ConsoleApplication(SimpleNamespace(snapshot=self.snapshot), self.config)
        self.server = ConsoleServer(self.app, port=0)
        self.server.bind()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.assertTrue(self.server.serving.wait(2))
        self.clients = []

    def snapshot(self):
        with self.first_call:
            first = not self.entered.is_set()
            if first:
                self.entered.set()
        if first:
            self.release.wait(3)
            self.finished.set()
        return SNAPSHOT

    def tearDown(self):
        self.release.set()
        for client in self.clients:
            client.close()
        self.server.close()
        self.thread.join(2)
        self.assertFalse(self.thread.is_alive())

    def connect(self):
        client = socket.create_connection(("127.0.0.1", self.server.server_port), timeout=2)
        self.clients.append(client)
        return client

    def get(self, client, token, timeout):
        client.sendall(b"GET /secrets HTTP/1.1\r\nHost: broker.fixture.ts.net\r\n"
                       b"Tailscale-User-Login: human@example.test\r\n"
                       + f"Cookie: {COOKIE}={token}\r\n".encode()
                       + b"Connection: close\r\n\r\n")
        client.settimeout(timeout)
        chunks = []
        while chunk := client.recv(65536):
            chunks.append(chunk)
        return b"".join(chunks)

    def test_metadata_read_does_not_hold_the_auth_lock(self):
        token, _session = self.app.auth.new_session(authenticated=True)
        results = {}

        def slow():
            try:
                results["first"] = self.get(self.connect(), token, 3)
            except OSError as error:
                results["first_error"] = error

        reader = threading.Thread(target=slow, daemon=True)
        reader.start()
        self.assertTrue(self.entered.wait(2), "first request never reached the metadata read")
        try:
            second = self.get(self.connect(), token, .25)
        except OSError as error:
            second = repr(error).encode()
        still_reading = not self.finished.is_set()
        self.release.set()
        reader.join(3)
        self.assertFalse(reader.is_alive())
        self.assertTrue(still_reading, "the first request left the metadata read before the second was answered")
        self.assertTrue(second.startswith(b"HTTP/1.1 200"), second[:80])
        self.assertIn(b"fixture/example", second)
        self.assertTrue(results.get("first", b"").startswith(b"HTTP/1.1 200"), results.get("first", b"")[:80])
        self.assertNotIn("first_error", results)


if __name__ == "__main__":
    unittest.main()
