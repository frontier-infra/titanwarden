"""Human-only admin socket service."""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .audit import AuditError, AuditLog
from .desk import DeskClient, DeskError
from .protocol import failure, recv_frame_with_fds, send_frame
from .seal import SealError, SealManager
from .store import Store, StoreError, canonical_text, utc_now
from .policy_log import PolicyError
from .agent_service import _default_grant_expiry, _request_entry


MAX_SECRET_BYTES = 1024 * 1024
ADMIN_SESSION_SECONDS = 15 * 60


@dataclass(slots=True)
class AdminSession:
    authenticated: bool = False
    authenticated_at: float | None = None

    def authenticate(self) -> None:
        self.authenticated = True
        self.authenticated_at = time.monotonic()

    def clear(self) -> None:
        self.authenticated = False
        self.authenticated_at = None

    def is_authenticated(self) -> bool:
        if not self.authenticated or self.authenticated_at is None:
            return False
        if time.monotonic() - self.authenticated_at > ADMIN_SESSION_SECONDS:
            self.clear()
            return False
        return True


class AdminService:
    def __init__(
        self,
        store: Store,
        seal: SealManager,
        *,
        desk: DeskClient | None = None,
    ) -> None:
        self.store = store
        self.seal = seal
        self.desk = desk
        self._redaction_values: list[tuple[str, str]] = []
        self.redaction_sink = None
        self.cloud = None
        self.console_config = None

    def _keyring(self) -> dict[str, tuple[str, bytes]]:
        keys = self.seal.keys
        if self.seal.state != "unsealed" or keys is None:
            raise SealError("broker is sealed")
        return {
            "kek": (keys.kek_id, bytes(keys.kek)),
            "audit_mac": (keys.audit_id, bytes(keys.audit)),
            "fingerprint": (keys.fingerprint_id, bytes(keys.fingerprint)),
        }

    def _audit(self) -> AuditLog:
        keys = self.seal.keys
        if keys is None:
            return AuditLog(self.store)
        def scrub(text: str) -> tuple[str, bool]:
            changed = False
            for path, candidate in self._redaction_values:
                if candidate and candidate in text:
                    text = text.replace(candidate, f"[tw:{path}]")
                    changed = True
            return text, changed

        return AuditLog(self.store, mac_key=bytes(keys.audit), scrub=scrub)

    def _rebuild_redaction_set(self) -> None:
        if self.cloud is not None and self.cloud.enabled:
            self._clear_redaction_set()
            return
        values: list[tuple[str, str]] = []
        raw_values: dict[str, list[bytes]] = {}
        for path, value in self.store.active_plaintexts(keyring=self._keyring()):
            raw_values.setdefault(path, []).append(value)
            try:
                candidate = value.decode("utf-8")
            except UnicodeDecodeError:
                continue
            values.append((path, candidate))
        self._redaction_values = values
        if self.redaction_sink is not None:
            self.redaction_sink("rebuild", raw_values)

    def _clear_redaction_set(self) -> None:
        self._redaction_values.clear()
        if self.redaction_sink is not None:
            self.redaction_sink("clear", {})

    def _audit_denied_auth(self, op: str, error: SealError) -> None:
        try:
            self._audit().append(
                event_id=self.store.new_id("evt_"),
                op=op,
                decision="deny",
                reason_code=error.code,
                principal_id="human:operator",
            )
        except AuditError:
            pass

    def _audit_best_effort(self, *, op: str, decision: str = "allow", **fields: Any) -> None:
        try:
            self._audit().append(
                event_id=self.store.new_id("evt_"), op=op, decision=decision, **fields
            )
        except AuditError:
            pass

    @staticmethod
    def _read_fd(fd: int) -> bytes:
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(fd, min(65536, MAX_SECRET_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_SECRET_BYTES:
                raise StoreError("input exceeds 1 MiB")
        return b"".join(chunks)

    @staticmethod
    def _write_tty(fd: int, value: bytes) -> None:
        if not os.isatty(fd):
            raise StoreError("reveal output must be a tty")
        view = memoryview(value + b"\n")
        while view:
            try:
                written = os.write(fd, view)
            except OSError as exc:
                raise StoreError(f"terminal write failed: {exc.strerror}; pass the named pty, not /dev/tty") from None
            view = view[written:]

    def put_value(
        self,
        path: str,
        value: bytes,
        *,
        secret_class: str = "sensitive",
        kind: str = "opaque",
        note: str | None = None,
    ) -> dict[str, Any]:
        """Store a value as the human operator: twadmin put and the console share this path."""
        put_secret = self.cloud.put if self.cloud is not None and self.cloud.enabled else self.store.put_secret
        result = put_secret(
            path,
            value,
            keyring=self._keyring(),
            principal_id="human:operator",
            secret_class=secret_class,
            kind=kind,
            note=note,
        )
        self._audit().append(
            event_id=self.store.new_id("evt_"),
            op="put",
            principal_id="human:operator",
            secret_path=result["path"],
            version_no=result["version_no"],
        )
        self._rebuild_redaction_set()
        return result

    def unseal_value(self, passphrase: str, *, op: str = "unseal") -> None:
        """Unseal with the passphrase as the human operator: twadmin unseal and the console share this."""
        try:
            self.seal.unseal(passphrase)
            self._rebuild_redaction_set()
        except SealError as exc:
            self._audit_denied_auth(op, exc)
            raise
        self._audit().append(event_id=self.store.new_id("evt_"), op="unseal", principal_id="human:operator")

    def seal_value(self) -> None:
        """Seal now: keys wiped, redaction set cleared, audited. Never needs the passphrase."""
        self.seal.seal()
        self._clear_redaction_set()
        self._audit_best_effort(op="seal", principal_id="human:operator")

    def reveal_value(self, path: str, reason: str) -> bytes:
        """Read one active value as the human operator, after the caller proved the passphrase.

        twadmin reveal (admin session) and the console (passkey plus passphrase)
        share this path: the reason is required, the audit event and the Desk
        line are written here, and the caller alone decides where the bytes go
        (a named pty, or the operator's own browser for thirty seconds).
        """
        if len(reason) < 10:
            raise StoreError("reveal reason must be at least 10 characters")
        value = self.store.reveal_secret(path, keyring=self._keyring())
        self._audit().append(
            event_id=self.store.new_id("evt_"),
            op="reveal",
            principal_id="human:operator",
            secret_path=path,
            detail_json=canonical_text({"reason": reason}),
        )
        if self.desk is not None:
            try:
                self.desk.outcome(f"Operator revealed {path}; reason recorded in audit")
            except DeskError:
                pass
        return value

    def handle(
        self,
        session: AdminSession,
        request: dict[str, Any],
        fds: list[int],
    ) -> dict[str, Any]:
        op = str(request.get("op", ""))
        args = request.get("args", {})
        if not isinstance(args, dict):
            return failure("E_BAD_REQUEST", "args must be an object")
        from .bitwarden_broker import OPS as IMPORT_OPS, handle_import
        if op in IMPORT_OPS:
            return handle_import(self, session, op, args, fds)
        try:
            if op == "console_prepare_enrollment":
                # Every activation proves the knowledge factor against this vault.
                if (self.console_config is None
                        or set(args) != {"passphrase", "rp_id", "allowed_user"}
                        or args["rp_id"] != self.console_config.rp_id
                        or args["allowed_user"] != self.console_config.allowed_user):
                    raise SealError("Console enrollment is not authorized", "E_AUTH")
                from .console_auth import ConsoleDenied
                try:
                    result = self.console_config.prepare_enrollment(args["passphrase"])
                except ConsoleDenied:
                    raise SealError("Console enrollment authentication failed", "E_AUTH") from None
                return {"ok": True, "code": "ok", "result": result}
            if op == "status":
                return {
                    "ok": True,
                    "code": "ok",
                    "result": {"seal_state": self.seal.state, "frozen": self.seal.frozen},
                }
            if op == "init":
                if self.seal.state != "uninitialized":
                    raise StoreError("store is already initialized")
                if not fds:
                    raise StoreError("init requires a tty file descriptor")
                passphrase = str(args.get("passphrase", ""))
                cloud_broker = args.get("cloud_broker", False)
                if type(cloud_broker) is not bool:
                    raise StoreError("cloud_broker must be boolean")
                if cloud_broker and not os.isatty(fds[0]):
                    raise StoreError("cloud broker initialization requires a tty")
                # Prove the terminal is writable from this process before the
                # store exists: a failed write after initialize would leave a
                # store whose recovery key nobody ever saw.
                self._write_tty(fds[0], b"Titanwarden recovery key (record it offline):")
                _master, recovery = self.store.initialize(passphrase, cloud_broker=cloud_broker)
                if recovery:
                    self._write_tty(fds[0], recovery.encode("ascii"))
                self.seal.state = "sealed"
                return {"ok": True, "code": "ok", "result": {"initialized": True}}
            if op == "auth" or op == "unseal":
                if self.seal.state == "unsealed":
                    try:
                        self.seal.check_passphrase(str(args.get("passphrase", "")))
                    except SealError as exc:
                        self._audit_denied_auth(op, exc)
                        raise
                    self._audit().append(
                        event_id=self.store.new_id("evt_"), op="auth", principal_id="human:operator"
                    )
                else:
                    self.unseal_value(str(args.get("passphrase", "")), op=op)
                session.authenticate()
                return {"ok": True, "code": "ok", "result": {"seal_state": "unsealed"}}
            if op == "lockdown_clear":
                try:
                    self.seal.clear_lockdown(str(args.get("passphrase", "")))
                    self._rebuild_redaction_set()
                except SealError as exc:
                    self._audit_denied_auth(op, exc)
                    raise
                session.authenticate()
                return {"ok": True, "code": "ok", "result": {"seal_state": "unsealed"}}
            if not session.is_authenticated():
                raise SealError("admin connection is not authenticated", "E_AUTH")
            if op.startswith('cloud_'):
                self._keyring()
                if self.cloud is None:
                    raise StoreError('cloud runtime unavailable')
                if op == 'cloud_join':
                    result = self.cloud.join(origin=args['origin'],org=args['org'],name=args['name'],code=args['code'])
                elif op == 'cloud_pair':
                    result = self.cloud.pair(args['words'])
                elif op == 'cloud_poll':
                    result = self.cloud.pull()
                elif op == 'cloud_status':
                    result = self.cloud.status()
                elif op == 'cloud_resolve':
                    result = self.cloud.resolve(session,expected_head=args['head'],through_conflict=args['through_conflict'],typed_root=args['typed_root'])
                else:
                    raise StoreError('unknown cloud operation')
                self._audit().append(event_id=self.store.new_id('evt_'),op=op,principal_id='human:operator')
                return {'ok':True,'code':'ok','result':result}
            if op == "seal":
                self.seal_value()
                session.clear()
                return {"ok": True, "code": "ok", "result": {"seal_state": "sealed"}}
            if op == "put":
                if not fds:
                    raise StoreError("put requires an input file descriptor")
                result = self.put_value(
                    str(args.get("path", "")),
                    self._read_fd(fds[0]),
                    secret_class=str(args.get("class", "sensitive")),
                    kind=str(args.get("kind", "opaque")),
                    note=args.get("note"),
                )
                return {"ok": True, "code": "ok", "result": result}
            if op == "request_decide":
                if self.cloud is not None and self.cloud.enabled:
                    raise StoreError('cloud grants require signed console policy')
                request_id = str(args.get("request_id", ""))
                decision = str(args.get("decision", ""))
                if decision not in {"approve", "deny"}:
                    raise StoreError("invalid request decision")
                row = self.store.connection.execute(
                    "SELECT * FROM requests WHERE request_id=? AND state='open'",
                    (request_id,),
                ).fetchone()
                if row is None:
                    raise StoreError("request is not open")
                if decision == "approve":
                    entry = _request_entry(str(row["ops"]), str(row["target"]))
                    secret = self.store.connection.execute(
                        "SELECT class FROM secrets WHERE path=? AND state='active'",
                        (row["target"],),
                    ).fetchone()
                    maximum = "restricted" if secret is None else str(secret[0])
                    self.store.connection.execute(
                        "INSERT INTO grants(grant_id,principal_id,pattern,ops,conditions_json,effect,"
                        "granted_by,reason,request_id,created_at,expires_at) "
                        "VALUES (?,?,?,?,?,'allow','human:operator',?,?,?,?)",
                        (
                            self.store.new_id("grt_"),
                            row["principal_id"],
                            f"{entry.project}/{entry.name}",
                            "+".join(sorted(entry.operations)),
                            json.dumps({"max_class": maximum}, separators=(",", ":")),
                            str(args.get("reason", "approved by the operator")),
                            request_id,
                            utc_now(),
                            _default_grant_expiry(str(row["target"]), maximum),
                        ),
                    )
                state = "approved" if decision == "approve" else "denied"
                self.store.connection.execute(
                    "UPDATE requests SET state=?,decided_by='human:operator',decided_at=? "
                    "WHERE request_id=?",
                    (state, utc_now(), request_id),
                )
                self._audit().append(
                    event_id=self.store.new_id("evt_"),
                    op="request_decide",
                    principal_id="human:operator",
                    request_id=request_id,
                    decision="allow",
                    reason_code=state,
                )
                return {
                    "ok": True,
                    "code": "ok",
                    "result": {"request_id": request_id, "state": state},
                }
            if op == "reveal":
                if not fds:
                    raise StoreError("reveal requires a tty file descriptor")
                path = str(args.get("path", ""))
                value = self.reveal_value(path, str(args.get("reason", "")))
                self._write_tty(fds[0], value)
                return {"ok": True, "code": "ok", "result": {"path": path, "revealed": True}}
            if op == "freeze":
                self.seal.freeze()
                self._audit().append(
                    event_id=self.store.new_id("evt_"), op="freeze", principal_id="human:operator"
                )
                return {"ok": True, "code": "ok", "result": {"frozen": True}}
            if op == "unfreeze":
                self.seal.unfreeze()
                self._audit().append(
                    event_id=self.store.new_id("evt_"), op="unfreeze", principal_id="human:operator"
                )
                return {"ok": True, "code": "ok", "result": {"frozen": False}}
            if op == "panic_seal":
                self.seal.lockdown()
                self._clear_redaction_set()
                session.clear()
                self._audit_best_effort(op="panic_seal", principal_id="human:operator")
                return {"ok": True, "code": "ok", "result": {"seal_state": "lockdown"}}
            if op == "passphrase_change":
                if self.seal.keys is None:
                    raise SealError("broker is sealed")
                try:
                    self.store.change_passphrase(
                        bytes(self.seal.keys.master), str(args.get("new_passphrase", ""))
                    )
                except (StoreError, ValueError):
                    self._audit_best_effort(
                        op="passphrase_change", decision="error", reason_code="E_BAD_REQUEST"
                    )
                    raise
                self._audit().append(
                    event_id=self.store.new_id("evt_"),
                    op="passphrase_change",
                    principal_id="human:operator",
                )
                return {"ok": True, "code": "ok", "result": {"changed": True}}
            if op == "recovery_rotate":
                if self.store.meta('cloud_broker') == '1':
                    raise StoreError('cloud brokers recover by reenrollment')
                if not fds:
                    raise StoreError("recovery rotate requires a tty file descriptor")
                if self.seal.keys is None:
                    raise SealError("broker is sealed")
                try:
                    recovery = self.store.rotate_recovery(bytes(self.seal.keys.master))
                except (StoreError, ValueError):
                    self._audit_best_effort(
                        op="recovery_rotate", decision="error", reason_code="E_BAD_REQUEST"
                    )
                    raise
                self._audit().append(
                    event_id=self.store.new_id("evt_"),
                    op="recovery_rotate",
                    principal_id="human:operator",
                )
                self._write_tty(fds[0], recovery.encode("ascii"))
                return {"ok": True, "code": "ok", "result": {"rotated": True}}
            if op == "audit_verify":
                result = self._audit().verify()
                self.seal.handle_verify_failure(result)
                return {
                    "ok": result.ok,
                    "code": "ok" if result.ok else "E_INTEGRITY",
                    "result": {"seq": result.seq, "hash": result.digest.hex(), "error": result.error},
                }
            if op == "audit_tail":
                limit = max(1, min(int(args.get("n", 20)), 1000))
                rows = self.store.connection.execute(
                    "SELECT seq,event_id,ts,op,phase,decision,reason_code,principal_id,"
                    "secret_path,version_no,attest_status,context_verified FROM audit_events "
                    "ORDER BY seq DESC LIMIT ?",
                    (limit,),
                )
                return {"ok": True, "code": "ok", "result": {"events": [dict(row) for row in rows]}}
            if op == "who_touched":
                events = self._audit().who_touched(str(args.get("path", "")), int(args.get("n", 10)))
                return {"ok": True, "code": "ok", "result": {"events": events}}
            if op == "dependents":
                result = self._audit().dependents(str(args.get("path", "")))
                return {"ok": True, "code": "ok", "result": result}
            if op == "backup":
                destination = self.store.backup(str(args.get("destination", "")))
                return {"ok": True, "code": "ok", "result": {"path": str(destination)}}
            return failure("E_UNKNOWN_OP", "unknown admin operation")
        except SealError as exc:
            return failure(exc.code, str(exc))
        except PolicyError as exc:
            return failure(exc.code, str(exc))
        except AuditError as exc:
            return failure("E_AUDIT", str(exc))
        except (StoreError, ValueError) as exc:
            return failure("E_BAD_REQUEST", str(exc))


class AdminSocketServer:
    def __init__(self, service: AdminService, socket_path: Path) -> None:
        self.service = service
        self.socket_path = socket_path
        self.socket: socket.socket | None = None
        self.stop_event = threading.Event()
        self.connection_slots = threading.BoundedSemaphore(16)

    def bind(self) -> None:
        self.socket_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.socket_path.exists():
            self.socket_path.unlink()
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        server.listen(16)
        server.settimeout(1)
        self.socket = server

    def serve_forever(self) -> None:
        if self.socket is None:
            self.bind()
        assert self.socket is not None
        while not self.stop_event.is_set():
            try:
                client, _ = self.socket.accept()
            except TimeoutError:
                continue
            if not self.connection_slots.acquire(blocking=False):
                with client:
                    send_frame(client, failure("E_BUSY", "connection limit reached"))
                continue
            thread = threading.Thread(target=self._serve_client, args=(client,), daemon=True)
            thread.start()

    def _serve_client(self, client: socket.socket) -> None:
        try:
            with client:
                client.settimeout(30)
                session = AdminSession()
                while True:
                    fds: list[int] = []
                    try:
                        request, fds = recv_frame_with_fds(client)
                        if not isinstance(request, dict):
                            send_frame(client, failure("E_BAD_REQUEST", "request must be an object"))
                            continue
                        response = self.service.handle(session, request, fds)
                        send_frame(client, response)
                    except (EOFError, TimeoutError):
                        return
                    finally:
                        for fd in fds:
                            try:
                                os.close(fd)
                            except OSError:
                                pass
        finally:
            self.connection_slots.release()

    def close(self) -> None:
        self.stop_event.set()
        if self.socket is not None:
            self.socket.close()
        if self.socket_path.exists():
            self.socket_path.unlink()

