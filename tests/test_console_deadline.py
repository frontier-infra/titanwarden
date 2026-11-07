"""Synthetic loopback-only C7-01 regressions. No store, keys or enrollment."""
from __future__ import annotations

import socket
import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from tw.broker import Broker
from tw.console import COOKIE, ConsoleApplication, ConsoleHandler, ConsoleServer


class Config:
    rp_id = "broker.fixture.ts.net"
    origin = "https://broker.fixture.ts.net"
    allowed_user = "human@example.test"
    active = False
    credentials = ()

    def __init__(self):
        self._lock = threading.RLock()
        self.closed = False

    def close(self):
        self.closed = True


class ConsoleDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.app = ConsoleApplication(SimpleNamespace(snapshot=self.forbidden_metadata), self.config)
        self.server = ConsoleServer(self.app, port=0)
        self.server._CONNECTION_SECONDS = .5
        self.server.bind()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.assertTrue(self.server.serving.wait(2))
        self.clients = []

    def forbidden_metadata(self):
        self.fail("Inactive fixture must not access metadata")

    def tearDown(self):
        # Release clients first even when an assertion fails against old code.
        for client in self.clients:
            client.close()
        self.server.close()
        self.thread.join(2)
        self.assertFalse(self.thread.is_alive())

    def connect(self, opening=b""):
        client = socket.create_connection(("127.0.0.1", self.server.server_port), timeout=1)
        client.settimeout(.15)
        self.clients.append(client)
        client.sendall(opening)
        return client

    @staticmethod
    def headers(method="GET", path="/"):
        return (f"{method} {path} HTTP/1.1\r\nHost: broker.fixture.ts.net\r\n"
                "Tailscale-User-Login: human@example.test\r\n").encode()

    def wait_for(self, condition, timeout=2, message="condition not met in time"):
        end = time.monotonic() + timeout
        while not condition() and time.monotonic() < end:
            time.sleep(.01)
        self.assertTrue(condition(), message)

    def read(self, client):
        client.settimeout(2)
        chunks = []
        while chunk := client.recv(65536):
            chunks.append(chunk)
        return b"".join(chunks)

    def test_partial_request_line_headers_body_and_silent_peer_expire(self):
        # Four shapes, asserted in this test's own body. Subtests would report
        # the parent as PASSED beside four SUBFAILED lines, so every test-level
        # dashboard would show green while all four shapes were broken. Failures
        # are collected so all four still run, then raised once here.
        failures = []
        for opening in (b"", b"GET /", b"GET / HTTP/1.1\r\nX-Slow: ",
                        self.headers("POST", "/auth/options") +
                        b"Origin: https://broker.fixture.ts.net\r\nContent-Type: application/json\r\n"
                        b"Content-Length: 65536\r\n\r\n"):
            try:
                self.assert_partial_expires(opening)
            except AssertionError as error:
                failures.append(f"{opening!r}: {error}")
        self.assertEqual(failures, [], "partial request shapes did not expire cleanly")

    def assert_partial_expires(self, opening):
        before = sum(self.server.expired_interrupted.values())
        client = self.connect(opening)
        self.wait_for(lambda: self.server.capacity._value == 31, message="request was not admitted")
        end = time.monotonic() + .8
        while time.monotonic() < end:
            if opening:
                try:
                    client.sendall(b"x")
                except OSError:
                    pass
            time.sleep(.04)
        self.wait_for(lambda: self.server.capacity._value == 32,
                      message="expired request kept its capacity slot")
        # A request cut off by the deadline must not end in silence: either the
        # client gets an explicit status line, or the event is counted where an
        # operator can see it. Both are honest; zero bytes with no record is not.
        try:
            response = self.read(client)
        except OSError:
            response = b""
        recorded = sum(self.server.expired_interrupted.values()) - before
        self.assertTrue(response.startswith(b"HTTP/1.1 503") or recorded == 1,
                        (opening, response[:40], recorded))

    def test_fragmented_valid_get_and_post_keep_authentication_checks(self):
        client = self.connect(self.headers()[:5])
        time.sleep(.04)
        client.sendall(self.headers()[5:] + b"\r\n")
        response = self.read(client)
        self.assertTrue(response.startswith(b"HTTP/1.1 200"))
        self.assertIn(b"Activate your console", response)
        token, session = self.app.auth.new_session()
        post = self.headers("POST", "/logout") + (
            f"Origin: {self.config.origin}\r\nCookie: {COOKIE}={token}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 10\r\n\r\n").encode()
        client = self.connect(post + b"csrf=")
        time.sleep(.04)
        client.sendall(b"wrong")
        self.assertTrue(self.read(client).startswith(b"HTTP/1.1 403"))
        self.assertIs(self.app.auth.sessions[token], session)

    def test_capacity_recovers_after_all_32_partial_connections_expire(self):
        for _ in range(32):
            self.connect(b"GET /")
        self.wait_for(lambda: self.server.capacity._value == 0)
        self.wait_for(lambda: self.server.capacity._value == 32)
        self.assertTrue(self.read(self.connect(self.headers() + b"\r\n")).startswith(b"HTTP/1.1 200"))

    def test_broker_close_interrupts_clients_then_clears_auth_and_seals(self):
        self.server._CONNECTION_SECONDS = 5
        self.connect(b"GET / HTTP/1.1\r\nX-Slow: ")
        self.wait_for(lambda: self.server.capacity._value == 31)
        self.app.auth.new_session()
        sealed = threading.Event()
        noop = SimpleNamespace(close=lambda: None)
        broker = SimpleNamespace(stop_event=threading.Event(), console=self.server,
                                 agent=noop, service=noop, admin=noop, store=noop,
                                 seal=SimpleNamespace(seal=sealed.set))
        started = time.monotonic()
        Broker.close(broker)
        self.assertLess(time.monotonic() - started, 2)
        self.assertTrue(sealed.is_set())
        self.assertTrue(self.config.closed)
        self.assertEqual(self.app.auth.sessions, {})
        self.assertEqual(self.server.capacity._value, 32)
        self.assertEqual(self.server._connections, {})
        self.assertEqual(self.server._workers, set())

    def test_overrunning_handler_without_status_is_answered_503(self):
        def stalled(handler):
            time.sleep(1.2)
            handler._send(200, "late page")
        with mock.patch.object(ConsoleHandler, "do_GET", stalled):
            client = self.connect(self.headers() + b"\r\n")
            response = self.read(client)
        # Before this fix the client received zero bytes and no status line,
        # which in a credential vault reads as the console going blank.
        self.assertTrue(response.startswith(b"HTTP/1.1 503"), response[:80])
        self.assertIn(b"Console request timed out", response)
        self.assertEqual(sum(self.server.expired_interrupted.values()), 0,
                         "the client was answered, so nothing was lost")
        self.wait_for(lambda: self.server.capacity._value == 32)

    def test_broker_close_closes_store_when_console_close_raises(self):
        calls = []

        def console_close():
            calls.append("console.close")
            raise TimeoutError("Console workers did not stop within the shutdown budget")

        def recorder(name):
            return SimpleNamespace(close=lambda: calls.append(name))

        broker = SimpleNamespace(
            stop_event=threading.Event(), console=SimpleNamespace(close=console_close),
            agent=recorder("agent.close"), service=recorder("service.close"),
            admin=recorder("admin.close"),
            seal=SimpleNamespace(seal=lambda: calls.append("seal.seal")),
            store=recorder("store.close"))
        with self.assertRaisesRegex(TimeoutError, "workers"):
            Broker.close(broker)
        self.assertIn("store.close", calls)
        self.assertEqual(calls[-1], "store.close", calls)
        self.assertLess(calls.index("seal.seal"), calls.index("console.close"), calls)
        self.assertLess(calls.index("console.close"), calls.index("store.close"), calls)

    def test_response_write_stall_releases_auth_lock_and_worker(self):
        def large_page(handler):
            with handler.app.auth.lock:
                handler._send(200, b"x" * (16 * 1024 * 1024))
        with mock.patch.object(ConsoleHandler, "do_GET", large_page):
            client = self.connect()
            client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
            client.sendall(self.headers() + b"\r\n")
            self.wait_for(lambda: self.server.capacity._value == 31)
            self.wait_for(lambda: self.server.capacity._value == 32)
            self.assertTrue(self.app.auth.lock.acquire(timeout=.5))
            self.app.auth.lock.release()

    def test_worker_start_failure_releases_admission_and_close_still_works(self):
        server_socket, peer = socket.socketpair()
        self.addCleanup(peer.close)
        self.addCleanup(server_socket.close)
        actual_start = threading.Thread.start
        def start(thread):
            if isinstance(thread, threading.Timer):
                return actual_start(thread)
            raise RuntimeError("synthetic worker start failure")
        with mock.patch.object(threading.Thread, "start", start):
            with self.assertRaisesRegex(RuntimeError, "synthetic worker"):
                self.server.process_request(server_socket, ("127.0.0.1", 1))
        self.assertEqual(self.server.capacity._value, 32)
        self.assertEqual(self.server._connections, {})
        self.assertEqual(self.server._workers, set())

    def test_stuck_non_network_worker_has_bounded_join_and_broker_is_sealed(self):
        entered, release, sealed = threading.Event(), threading.Event(), threading.Event()
        def stalled(handler):
            with handler.app.auth.lock:
                entered.set()
                release.wait(3)
        noop = SimpleNamespace(close=lambda: None)
        broker = SimpleNamespace(stop_event=threading.Event(), console=self.server,
                                 agent=noop, service=noop, admin=noop, store=noop,
                                 seal=SimpleNamespace(seal=sealed.set))
        self.server._JOIN_SECONDS = .15
        with mock.patch.object(ConsoleHandler, "do_GET", stalled):
            self.connect(self.headers() + b"\r\n")
            self.assertTrue(entered.wait(1))
            try:
                started = time.monotonic()
                with self.assertRaisesRegex(TimeoutError, "workers"):
                    Broker.close(broker)
                self.assertLess(time.monotonic() - started, 1)
                self.assertTrue(sealed.is_set())
                # Encodes the recorded wipe decision, not an oversight: a worker
                # is still inside do_GET holding the auth lock, so ConsoleServer
                # deliberately does not zero the config it may still be reading.
                # The vault is already sealed and the store is closed by
                # Broker.close. See the wipe-decision comment in console.close().
                self.assertFalse(self.config.closed)
            finally:
                release.set()
            self.wait_for(lambda: self.server.capacity._value == 32)

    def test_busy_auth_cleanup_has_a_finite_budget(self):
        entered, release = threading.Event(), threading.Event()
        def hold():
            with self.app.auth.lock:
                entered.set()
                release.wait(3)
        holder = threading.Thread(target=hold, daemon=True)
        holder.start()
        self.assertTrue(entered.wait(1))
        self.server._JOIN_SECONDS = .15
        try:
            with self.assertRaisesRegex(TimeoutError, "auth state"):
                self.server.close()
            # Same recorded decision as the worker-timeout case above: the lock
            # is held by live code, so the key wipe is skipped deliberately.
            self.assertFalse(self.config.closed)
        finally:
            release.set()
            holder.join(1)

    def test_close_before_serve_and_late_timeout_cannot_touch_new_socket(self):
        other = ConsoleServer(self.app, port=0)
        other.bind()
        other.close()
        other.serve_forever()
        self.assertFalse(other.serving.is_set())
        retired, peer = socket.socketpair()
        self.addCleanup(peer.close)
        retired.close()
        with mock.patch.object(self.server, "_interrupt") as interrupt:
            self.server._expire(retired)
            interrupt.assert_not_called()


if __name__ == "__main__":
    unittest.main()
