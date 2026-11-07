from __future__ import annotations

import os
import array
import hashlib
import json
import socket
import struct
import unittest
from pathlib import Path

from tw.broker import AGENT_OPS, CONSOLE_OPS, Broker
from tw.protocol import (
    AGENT_RESPONSE_FIELDS,
    ProtocolError,
    encode_frame,
    filter_result,
    recv_frame,
    recv_frame_with_fds,
    send_frame_with_fds,
)

from support import initialized_store


class ProtocolTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        left.sendall(encode_frame({"args": {}, "op": "hello", "v": 1}))
        self.assertEqual(recv_frame(right)["op"], "hello")

    def test_file_descriptor_round_trip(self) -> None:
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, read_fd)
        send_frame_with_fds(left, {"op": "put"}, [write_fd])
        os.close(write_fd)
        request, received = recv_frame_with_fds(right)
        self.assertEqual(request["op"], "put")
        os.write(received[0], b"ok")
        os.close(received[0])
        self.assertEqual(os.read(read_fd, 2), b"ok")

    def test_malformed_frames_close_received_file_descriptors(self) -> None:
        before = len(list(Path("/dev/fd").iterdir()))
        for _ in range(25):
            left, right = socket.socketpair()
            read_fd, write_fd = os.pipe()
            try:
                payload = b'{"op":"put"} '
                frame = struct.pack(">I", len(payload)) + payload
                left.sendmsg(
                    [frame],
                    [
                        (
                            socket.SOL_SOCKET,
                            socket.SCM_RIGHTS,
                            array.array("i", [read_fd]),
                        )
                    ],
                )
                with self.assertRaises(ProtocolError):
                    recv_frame_with_fds(right)
            finally:
                os.close(read_fd)
                os.close(write_fd)
                left.close()
                right.close()
        after = len(list(Path("/dev/fd").iterdir()))
        self.assertLessEqual(after, before + 2)

    def test_response_allowlist_rejects_extra_field(self) -> None:
        with self.assertRaises(ProtocolError):
            filter_result("hello", {"broker_version": "x", "value": "forbidden"})

    def test_agent_and_console_sets_are_closed(self) -> None:
        self.assertEqual(AGENT_OPS, frozenset(AGENT_RESPONSE_FIELDS))
        self.assertTrue({"reveal", "unseal"}.isdisjoint(AGENT_OPS))
        self.assertTrue({"reveal", "unseal"}.issubset(CONSOLE_OPS))

    def test_unknown_read_ops_are_denied(self) -> None:
        temporary, store, _master, _recovery = initialized_store()
        store.close()
        self.addCleanup(temporary.cleanup)
        broker = Broker(store.home)
        self.addCleanup(broker.close)
        for op in ("get", "reveal", "read", "export"):
            response = broker.handle_agent({"op": op, "args": {}}, [])
            self.assertEqual(response["code"], "E_UNKNOWN_OP")
        rows = broker.store.connection.execute(
            "SELECT op,decision,reason_code,detail_json FROM audit_events ORDER BY seq"
        ).fetchall()
        self.assertEqual(
            [(row["op"], row["decision"], row["reason_code"]) for row in rows],
            [("unknown", "deny", "unknown_op")] * 4,
        )
        self.assertEqual(
            [json.loads(row["detail_json"])["op_sha256"] for row in rows],
            [hashlib.sha256(op.encode()).hexdigest() for op in ("get", "reveal", "read", "export")],
        )
        for row, raw_op in zip(rows, ("get", "reveal", "read", "export"), strict=True):
            self.assertNotEqual(row["op"], raw_op)
            self.assertNotIn(raw_op, row["detail_json"])


if __name__ == "__main__":
    unittest.main()
