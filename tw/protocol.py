"""Titanwarden wire protocol helpers.

Frames are a 4-byte unsigned big-endian length followed by canonical UTF-8
JSON. File descriptors, when present, are carried with ``SCM_RIGHTS`` on the
same Unix socket message as the frame header.
"""

from __future__ import annotations

import array
import json
import socket
import struct
from collections.abc import Mapping, Sequence
from typing import Any, Final


PROTOCOL_VERSION: Final = 1
MAX_FRAME_SIZE: Final = 1024 * 1024
HEADER_SIZE: Final = 4
MAX_FDS: Final = 16


class ProtocolError(ValueError):
    """A malformed or unsupported wire frame."""

    code = "E_BAD_REQUEST"


ERROR_EXIT_CODES: Final[dict[str, int]] = {
    "E_USAGE": 64,
    "E_BAD_REQUEST": 64,
    "E_UNREACHABLE": 69,
    "E_INTEGRITY": 70,
    "E_AUDIT": 70,
    "E_SEALED": 75,
    "E_FROZEN": 75,
    "E_BUSY": 75,
    "E_POLICY_CONFLICT": 75,
    "E_POLICY_STALE": 75,
    "E_SYNC_RETRY": 75,
    "E_AUTH": 77,
    "E_DENIED": 77,
    "E_SCOPE": 77,
    "E_POLICY": 77,
    "E_IDENTITY_MISMATCH": 77,
    "E_UNKNOWN_OP": 77,
    "E_NO_IDENTITY": 78,
    "E_NOT_IMPLEMENTED": 78,
    "E_ROTATION_UNAVAILABLE": 78,
}

# Result keys are the only fields an agent response may expose for each op.
# The broker must pass every result through ``filter_result`` before framing it.
AGENT_RESPONSE_FIELDS: Final[dict[str, frozenset[str]]] = {
    "hello": frozenset({"broker_version", "protocol_version", "seal_state", "frozen"}),
    "status": frozenset(
        {
            "principal",
            "project",
            "token_id",
            "attest_status",
            "context_verified",
            "scope",
            "open_leases",
            "open_requests",
            "seal_state",
            "frozen",
        }
    ),
    "names": frozenset({"names"}),
    "run": frozenset(
        {"event", "lease_id", "exit_code", "signal", "redactions", "injected_paths"}
    ),
    "put": frozenset({"path", "version_no", "fingerprint_prefix"}),
    "generate": frozenset({"path", "version_no"}),
    "request": frozenset({"request_id", "needs", "desk_item", "default_decision", "default_at"}),
    "task_token_issue": frozenset({"token_id", "principal_id", "bound_handle"}),
    "task_token_revoke": frozenset({"revoked"}),
    "token_revoke_self": frozenset({"revoked"}),
    "who_touched": frozenset({"events"}),
    "dependents": frozenset({"observed", "live_leases", "potential", "placements"}),
    "roster_sync": frozenset({"added", "updated", "disabled", "refused"}),
    "token_issue": frozenset({"token_id", "file_path", "bound_handle"}),
    "grant_add": frozenset({"grant_id"}),
    "grant_rm": frozenset({"revoked"}),
    "request_decide": frozenset({"request_id", "state"}),
    "freeze": frozenset({"frozen"}),
    "unfreeze": frozenset({"frozen"}),
    "panic_seal": frozenset({"seal_state"}),
    "import_env": frozenset({"stored", "skipped", "manifest_path", "quarantine_id"}),
}

CONSOLE_ONLY_OPS: Final[frozenset[str]] = frozenset(
    {
        "init",
        "unseal",
        "seal",
        "reveal",
        "passphrase_change",
        "recovery_rotate",
        "lockdown_clear",
        "backup",
    }
)


def canonical_json(value: Any) -> bytes:
    """Encode a value in Titanwarden's canonical JSON form."""

    try:
        text = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ProtocolError("value is not canonical JSON") from exc
    return text.encode("utf-8")


def decode_json(payload: bytes) -> Any:
    """Decode one UTF-8 JSON payload and reject trailing or invalid data."""

    try:
        text = payload.decode("utf-8")
        value = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("invalid UTF-8 JSON frame") from exc
    if canonical_json(value) != payload:
        raise ProtocolError("JSON frame is not canonical")
    return value


def encode_frame(value: Any) -> bytes:
    payload = canonical_json(value)
    if len(payload) > MAX_FRAME_SIZE:
        raise ProtocolError("frame exceeds 1 MiB")
    return struct.pack(">I", len(payload)) + payload


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError("socket closed during frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_frame(sock: socket.socket) -> Any:
    header = _recv_exact(sock, HEADER_SIZE)
    (size,) = struct.unpack(">I", header)
    if size > MAX_FRAME_SIZE:
        raise ProtocolError("frame exceeds 1 MiB")
    return decode_json(_recv_exact(sock, size))


def send_frame(sock: socket.socket, value: Any) -> None:
    sock.sendall(encode_frame(value))


def send_frame_with_fds(sock: socket.socket, value: Any, fds: Sequence[int]) -> None:
    """Send one frame and optional file descriptors in a single message."""

    if len(fds) > MAX_FDS:
        raise ProtocolError(f"at most {MAX_FDS} file descriptors are allowed")
    frame = encode_frame(value)
    if not fds:
        sock.sendall(frame)
        return
    fd_array = array.array("i", fds)
    sent = sock.sendmsg([frame], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fd_array)])
    if sent != len(frame):
        sock.sendall(frame[sent:])


def recv_frame_with_fds(
    sock: socket.socket, *, max_fds: int = MAX_FDS
) -> tuple[Any, list[int]]:
    """Receive one frame and descriptors attached to its first message."""

    if not 0 <= max_fds <= MAX_FDS:
        raise ProtocolError(f"max_fds must be between 0 and {MAX_FDS}")
    item_size = array.array("i").itemsize
    ancillary_size = socket.CMSG_SPACE(max_fds * item_size)
    received: list[int] = []
    try:
        header, ancillary, flags, _address = sock.recvmsg(HEADER_SIZE, ancillary_size)
        for level, kind, data in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                continue
            usable = len(data) - (len(data) % item_size)
            fd_array = array.array("i")
            fd_array.frombytes(data[:usable])
            received.extend(fd_array.tolist())
        if not header:
            raise EOFError("socket closed before frame")
        if flags & getattr(socket, "MSG_CTRUNC", 0):
            raise ProtocolError("file descriptor control data was truncated")
        if len(header) < HEADER_SIZE:
            header += _recv_exact(sock, HEADER_SIZE - len(header))
        (size,) = struct.unpack(">I", header)
        if size > MAX_FRAME_SIZE:
            raise ProtocolError("frame exceeds 1 MiB")
        if len(received) > max_fds:
            raise ProtocolError("too many file descriptors")
        value = decode_json(_recv_exact(sock, size))
    except BaseException:
        for fd in received:
            try:
                socket.close(fd)
            except OSError:
                pass
        raise
    return value, received


def filter_result(op: str, result: Mapping[str, Any]) -> dict[str, Any]:
    """Return only fields explicitly allowed for an agent operation."""

    allowed = AGENT_RESPONSE_FIELDS.get(op)
    if allowed is None:
        raise ProtocolError("unknown operation")
    unexpected = set(result) - allowed
    if unexpected:
        names = ", ".join(sorted(unexpected))
        raise ProtocolError(f"response contains disallowed fields: {names}")
    return dict(result)


def success(op: str, result: Mapping[str, Any]) -> dict[str, Any]:
    return {"ok": True, "code": "ok", "result": filter_result(op, result)}


def failure(code: str, message: str) -> dict[str, Any]:
    if code not in ERROR_EXIT_CODES:
        code = "E_BAD_REQUEST"
    safe_message = " ".join(str(message).splitlines()).strip()
    if not safe_message.startswith("tw:"):
        safe_message = f"tw: {safe_message}"
    return {"ok": False, "code": code, "error": safe_message}


def exit_code_for(code: str) -> int:
    return ERROR_EXIT_CODES.get(code, 70)
