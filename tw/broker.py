"""Titanwarden broker process and socket lifecycle."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import resource
import signal
import socket
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

from . import VERSION
from .agent_service import AgentService, NESTED_ALLOWED, _read_fd_limited
from .admin_server import AdminService, AdminSocketServer
from .audit import AuditLog
from .desk import DeskClient, DeskError
from .protocol import AGENT_RESPONSE_FIELDS, failure, recv_frame_with_fds, send_frame, success
from .seal import SealManager
from .store import Store, utc_now
from .identity import system_process_resolver


Handler = Callable[[dict[str, Any]], dict[str, Any]]
MUTATING_AGENT_OPS = frozenset(
    {
        "put",
        "generate",
        "request",
        "task_token_issue",
        "task_token_revoke",
        "token_revoke_self",
        "roster_sync",
        "token_issue",
        "grant_add",
        "grant_rm",
        "request_decide",
        "freeze",
        "unfreeze",
        "panic_seal",
        "import_env",
    }
)

# Closed set. Implemented handlers are installed per Broker instance. The v1
# operations stay absent until they can fail closed with E_NOT_IMPLEMENTED.
AGENT_OPS = frozenset(AGENT_RESPONSE_FIELDS)
CONSOLE_OPS = frozenset(
    {
        "init",
        "auth",
        "unseal",
        "seal",
        "reveal",
        "put",
        "freeze",
        "unfreeze",
        "panic_seal",
        "lockdown_clear",
        "passphrase_change",
        "recovery_rotate",
        "audit_verify",
        "audit_tail",
        "who_touched",
        "dependents",
        "backup",
        "cloud_join", "cloud_pair", "cloud_poll", "cloud_status", "cloud_resolve",
    }
)


class AgentSocketServer:
    def __init__(self, broker: Broker, socket_path: Path) -> None:
        self.broker = broker
        self.socket_path = socket_path
        self.socket: socket.socket | None = None
        self.stop_event = threading.Event()
        self.connection_slots = threading.BoundedSemaphore(64)

    def bind(self) -> None:
        self.socket_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.socket_path.exists():
            self.socket_path.unlink()
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        server.listen(64)
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
            threading.Thread(target=self._serve_client, args=(client,), daemon=True).start()

    def _serve_client(self, client: socket.socket) -> None:
        try:
            with client:
                client.settimeout(30)
                peer_pid, peer_uid = _peer_credentials(client)
                if peer_uid is not None and peer_uid != os.getuid():
                    send_frame(client, failure("E_AUTH", "peer uid is not authorized"))
                    return
                while True:
                    fds: list[int] = []
                    try:
                        request, fds = recv_frame_with_fds(client)
                        if isinstance(request, dict) and request.get("op") == "run":
                            self._serve_run(client, request, fds, peer_pid)
                            return
                        response = self.broker.handle_agent(request, fds, peer_pid)
                        send_frame(client, response)
                    except (EOFError, TimeoutError):
                        return
                    except Exception as exc:
                        try:
                            send_frame(
                                client,
                                failure(getattr(exc, "code", "E_BAD_REQUEST"), "invalid request"),
                            )
                        except OSError:
                            pass
                        return
                    finally:
                        for fd in fds:
                            try:
                                os.close(fd)
                            except OSError:
                                pass
        finally:
            self.connection_slots.release()

    def _serve_run(
        self,
        client: socket.socket,
        request: dict[str, Any],
        fds: list[int],
        peer_pid: int,
    ) -> None:
        try:
            with self.broker.store._transaction_lock:
                handle = self.broker.service.start_run(request, peer_pid, fds)
        except Exception as exc:
            send_frame(client, failure(getattr(exc, "code", "E_BAD_REQUEST"), str(exc)))
            return
        try:
            send_frame(
                client,
                success("run", {"event": "started", "lease_id": handle.request.lease_id}),
            )
        except OSError:
            handle.disconnect()
            handle.wait()
            return
        client.settimeout(0.1)
        while handle.process.poll() is None:
            try:
                frame = recv_frame_with_fds(client, max_fds=0)[0]
            except TimeoutError:
                continue
            except (EOFError, OSError):
                handle.disconnect()
                handle.wait()
                return
            except Exception:
                handle.disconnect()
                handle.wait()
                return
            if not isinstance(frame, dict) or frame.get("op") != "signal":
                continue
            signal_name = str(frame.get("args", {}).get("sig", ""))
            signals = {"INT": signal.SIGINT, "TERM": signal.SIGTERM, "HUP": signal.SIGHUP}
            if signal_name in signals:
                handle.signal(signals[signal_name])
        exit_code = handle.wait()
        signal_number = exit_code - 128 if exit_code >= 128 else None
        try:
            send_frame(
                client,
                success(
                    "run",
                    {
                        "event": "exit",
                        "lease_id": handle.request.lease_id,
                        "exit_code": exit_code,
                        "signal": signal_number,
                        "redactions": sum(handle.redaction_counts.values()),
                        "injected_paths": sorted(
                            {
                                *handle.request.env_refs.values(),
                                *handle.request.fd_refs.values(),
                                *handle.request.soft_refs.values(),
                                *(
                                    [handle.request.stdin_ref]
                                    if handle.request.stdin_ref
                                    else []
                                ),
                            }
                        ),
                    },
                ),
            )
        except OSError:
            pass

    def close(self) -> None:
        self.stop_event.set()
        if self.socket is not None:
            self.socket.close()
        if self.socket_path.exists():
            self.socket_path.unlink()


class Broker:
    def __init__(self, home: Path, *, desk: DeskClient | None = None) -> None:
        self.home = home.expanduser().resolve()
        self.console = None  # Optional human HTTP surface; disabled unless explicitly configured.
        self.store = Store(
            self.home,
            # An external drive on macOS, and a second copy on Linux (same host, separate tree).
            backup_allowlist=[Path("/Volumes/Backup/titanwarden"), Path("/data/titanwarden-backups")],
        ).open(
            create=True,
            # Refuse only when a store existed here before (tombstone) and tw.db is gone;
            # a fresh install (home created by install.sh, no tombstone) may create one.
            refuse_create=(self.home / "state" / ".store-created").exists()
            and not (self.home / "state" / "tw.db").exists(),
        )
        self.seal = SealManager(self.store)
        self.desk = desk
        self.admin = AdminSocketServer(
            AdminService(self.store, self.seal, desk=desk), self.home / "run" / "admin.sock"
        )
        self.agent = AgentSocketServer(self, self.home / "run" / "tw.sock")
        self.started = time.monotonic()
        self.stop_event = threading.Event()
        self.sealed_alert_sent = False
        self.lock_file = None
        self.service = AgentService(
            self.store,
            self.seal,
            home=self.home,
            broker_pid=os.getpid(),
            process_resolver=system_process_resolver,
            desk_notify=self._desk_notify,
            desk_default=self._desk_default,
        )
        self.admin.service.redaction_sink = self._redaction_cache_event
        from .cloud_runtime import CloudRuntime
        self.cloud = CloudRuntime(self.store, self.seal)
        self.service.cloud = self.cloud
        self.admin.service.cloud = self.cloud
        self.cloud.redaction_sink = self.service.clear_redaction_values
        self.service.identities.grant_provider = lambda principal: (
            self.cloud.permission_grants(principal) if self.cloud.enabled else None)
        self._sweep_stale_leases()

    def _redaction_cache_event(
        self, action: str, values: dict[str, list[bytes]]
    ) -> None:
        if action == "rebuild":
            self.service.set_redaction_values(values)
        else:
            self.service.clear_redaction_values()

    def _desk_notify(self, kind: str, subject: str, body: str) -> str | None:
        if self.desk is None:
            return None
        if kind == "ask":
            return self.desk.ask(subject, body)
        elif kind == "action":
            return self.desk.action(subject, body)
        elif kind == "info":
            return self.desk.info(subject, body)
        return None

    def _desk_default(self, item_id: str, decision: str) -> None:
        if self.desk is not None:
            self.desk.default(item_id, decision)

    def acquire_lock(self) -> None:
        lock_path = self.home / "run" / "broker.lock"
        lock_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.lock_file = lock_path.open("a+")
        try:
            fcntl.flock(self.lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise RuntimeError("another Titanwarden broker is running") from exc

    def handle_agent(
        self, request: Any, fds: list[int], peer_pid: int = 0
    ) -> dict[str, Any]:
        put_value = None
        if isinstance(request, dict) and request.get("op") == "put" and fds:
            try:
                put_value = _read_fd_limited(fds[0])
            except Exception as exc:
                return failure(getattr(exc, "code", "E_BAD_REQUEST"), str(exc))
        if self.cloud.enabled:
            with self.cloud.lock, self.store._transaction_lock:
                result=self._handle_agent_locked(request,fds,peer_pid,put_value=put_value)
            # Publication performs its own verified state checks and must run
            # outside delivery locks while the cloud is on the network.
            return result() if callable(result) else result
        with self.store._transaction_lock:
            return self._handle_agent_locked(request, fds, peer_pid, put_value=put_value)

    def _handle_agent_locked(
        self,
        request: Any,
        fds: list[int],
        peer_pid: int,
        *,
        put_value: bytes | None = None,
    ) -> dict[str, Any]:
        if not isinstance(request, dict):
            return failure("E_BAD_REQUEST", "request must be an object")
        op = str(request.get("op", ""))
        if op not in AGENT_OPS:
            try:
                AuditLog(
                    self.store,
                    mac_key=None if self.seal.keys is None else bytes(self.seal.keys.audit),
                ).append(
                    event_id=self.store.new_id("evt_"),
                    op="unknown",
                    decision="deny",
                    reason_code="unknown_op",
                    detail_json=json.dumps(
                        {"op_sha256": hashlib.sha256(op.encode()).hexdigest()},
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                )
            except Exception:
                pass
            return failure("E_UNKNOWN_OP", "unknown operation")
        if op == "hello":
            return success(
                "hello",
                {
                    "broker_version": VERSION,
                    "protocol_version": 1,
                    "seal_state": self.seal.state,
                    "frozen": self.seal.frozen,
                },
            )
        if op == "status":
            try:
                return success("status", self.service.status(request, peer_pid))
            except Exception as exc:
                return failure(getattr(exc, "code", "E_BAD_REQUEST"), str(exc))
        try:
            self.seal.check_agent_operation(op)
        except Exception as exc:
            try:
                AuditLog(
                    self.store,
                    mac_key=None if self.seal.keys is None else bytes(self.seal.keys.audit),
                ).append(
                    event_id=self.store.new_id("evt_"),
                    op=op,
                    decision="deny",
                    reason_code=str(getattr(exc, "code", "E_SEALED")).removeprefix("E_").lower(),
                )
            except Exception as audit_exc:
                return failure(getattr(audit_exc, "code", "E_AUDIT"), str(audit_exc))
            return failure(getattr(exc, "code", "E_SEALED"), str(exc))
        try:
            request_id = str(request.get("request_id", ""))
            receipt_principal = None
            if op in MUTATING_AGENT_OPS:
                if not request_id:
                    return failure("E_BAD_REQUEST", "mutating request needs request_id")
                token, _permission, _ceiling, receipt_attestation = self.service.authenticate(
                    request, peer_pid
                )
                if receipt_attestation.status == "nested" and op not in NESTED_ALLOWED:
                    return failure("E_SCOPE", "operation is unavailable in a nested call")
                receipt_principal = str(token["principal_id"])
                cached = self.store.receipt(
                    request_id, op=op, principal_id=receipt_principal
                )
                if cached is not None:
                    return success(op, cached)
            if op == "names":
                result = self.service.names(request, peer_pid)
            elif op in {"put", "generate"}:
                if self.cloud.enabled:
                    def publish():
                        try:
                            result=self.service.put(request,peer_pid,fds,value=put_value)
                            if receipt_principal is not None:
                                with self.cloud.lock,self.store._transaction_lock:
                                    self.store.save_receipt(request_id,op,receipt_principal,result)
                            return success(op,result)
                        except Exception as exc:
                            return failure(getattr(exc,'code','E_BAD_REQUEST'),str(exc))
                    return publish
                result = self.service.put(request, peer_pid, fds, value=put_value)
            elif op == "import_env":
                result = self.service.import_env(request, peer_pid)
            else:
                result = self.service.handle(request, peer_pid)
            if receipt_principal is not None:
                self.store.save_receipt(request_id, op, receipt_principal, result)
            return success(op, result)
        except Exception as exc:
            return failure(getattr(exc, "code", "E_BAD_REQUEST"), str(exc))

    def _sweep_stale_leases(self) -> None:
        self.store.connection.execute(
            "UPDATE leases SET closed_at=?,exit_code=70,end_reason='broker_restart' "
            "WHERE closed_at IS NULL",
            (utc_now(),),
        )

    def _health(self) -> dict[str, Any]:
        audit = self.store.connection.execute(
            "SELECT seq FROM audit_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        leases = self.store.connection.execute(
            "SELECT COUNT(*) FROM leases WHERE closed_at IS NULL"
        ).fetchone()[0]
        requests = self.store.connection.execute(
            "SELECT COUNT(*) FROM requests WHERE state='open'"
        ).fetchone()[0]
        return {
            "state": self.seal.state,
            "frozen": self.seal.frozen,
            "heartbeat_at": utc_now(),
            "audit_seq": 0 if audit is None else audit["seq"],
            "audit_chain_ok": None if self.seal.keys is None else AuditLog(
                self.store, mac_key=bytes(self.seal.keys.audit)
            ).verify().ok,
            "open_leases": leases,
            "open_requests": requests,
            "blocked_rotations": 0,
            "denies_last_10m": 0,
            "last_backup_at": None,
            "last_roster_refresh_ok": None,
            "last_orca_refresh_ok": None,
        }

    def maintenance(self) -> None:
        health_path = self.home / "health.json"
        while not self.stop_event.wait(10):
            try:
                self.cloud.tick()
                with self.store._transaction_lock:
                    if not self.cloud.enabled:
                        self.service.apply_request_defaults()
                    if self.desk is not None and not self.cloud.enabled:
                        self.service.apply_desk_answers(self.desk.items())
            except Exception:
                pass
            self._verify_audit()
            with self.store._transaction_lock:
                health = self._health()
            temporary = health_path.with_suffix(".tmp")
            temporary.write_text(
                json.dumps(health, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            os.chmod(temporary, 0o600)
            temporary.replace(health_path)
            if (
                self.desk is not None
                and self.seal.state in {"sealed", "lockdown"}
                and not self.sealed_alert_sent
                and time.monotonic() - self.started >= 300
            ):
                try:
                    self.desk.blocker(
                        "Unseal Titanwarden",
                        "Run twadmin unseal over SSH from your own device, not in an Orca pane. Agents fall back to bw until then.",
                    )
                    self.sealed_alert_sent = True
                except DeskError:
                    pass

    def _verify_audit(self) -> None:
        if self.seal.keys is None:
            return
        with self.store._transaction_lock:
            verification = AuditLog(
                self.store, mac_key=bytes(self.seal.keys.audit)
            ).verify()
            self.seal.handle_verify_failure(verification)

    def run(self) -> None:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        self.acquire_lock()
        self.admin.bind()
        self.agent.bind()
        threads = [
            threading.Thread(target=self.admin.serve_forever, daemon=True),
            threading.Thread(target=self.agent.serve_forever, daemon=True),
            threading.Thread(target=self.maintenance, daemon=True),
        ]
        if self.console is not None:
            self.console.bind()
            threads.append(threading.Thread(target=self.console.serve_forever, daemon=True))
        for thread in threads:
            thread.start()
        self.stop_event.wait()

    def close(self) -> None:
        self.stop_event.set()
        self.agent.close()
        self.service.close()
        self.admin.close()
        # Stop vault-operation surfaces and wipe vault keys before waiting on
        # optional HTTP workers. A stuck console must not defer sealing.
        self.seal.seal()
        try:
            if self.console is not None:
                self.console.close()
        finally:
            # ConsoleServer.close() may raise TimeoutError when auth state could
            # not be quiesced. The store is the vault itself and must still be
            # closed; the TimeoutError is re-raised afterwards so the exit is
            # visibly abnormal rather than a clean shutdown that was not clean.
            self.store.close()


def _peer_credentials(client: socket.socket) -> tuple[int, int | None]:
    if sys.platform == "darwin":
        try:
            peer_pid = struct.unpack("=i", client.getsockopt(0, 2, 4))[0]
            credentials = client.getsockopt(0, 1, 12)
            peer_uid = struct.unpack_from("=I", credentials, 4)[0]
            return peer_pid, peer_uid
        except OSError:
            return 0, None
    if hasattr(socket, "SO_PEERCRED"):
        try:
            peer_pid, peer_uid, _peer_gid = struct.unpack(
                "=iii", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            return peer_pid, peer_uid
        except OSError:
            pass
    return 0, None


def main(argv: list[str] | None = None) -> int:
    Store.secure_process_umask()
    parser = argparse.ArgumentParser(prog="python -m tw.broker")
    parser.add_argument("--home", default=os.environ.get("TW_HOME", "~/.titanwarden"))
    parser.add_argument("--desk-identity", default="master")
    parser.add_argument("--desk-project", default="master")
    parser.add_argument("--console-config", type=Path,
                        help="Opt-in human console configuration; binds only 127.0.0.1:8787")
    parser.add_argument("--console-rp-id", help="Exact ts.net hostname")
    parser.add_argument("--console-user", help="Exact allowed Tailscale login")
    parser.add_argument("--console-support", default=os.environ.get("TW_CONSOLE_SUPPORT"),
                        help="Support contact the console's /support pages show; defaults to the project's "
                             "GitHub Issues and Security tab")
    options = parser.parse_args(argv)
    if (options.console_config is None) != (options.console_rp_id is None and options.console_user is None):
        parser.error("Console requires config, RP ID and user together")
    if options.console_config is not None and (not options.console_rp_id or not options.console_user):
        parser.error("Console requires config, RP ID and user together")
    desk = DeskClient(identity=options.desk_identity, project=options.desk_project)
    broker = Broker(Path(options.home), desk=desk)

    def stop(_signum: int, _frame: object) -> None:
        broker.stop_event.set()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGHUP, stop)
    try:
        if options.console_config is not None:
            from .console import ConsoleApplication, ConsoleServer
            from .console_auth import PasskeyConfig
            from .console_metadata import ConsoleMetadata
            config = PasskeyConfig.for_broker(broker.store, options.console_rp_id, options.console_user,
                                             expected_path=options.console_config, seal=broker.seal)
            broker.admin.service.console_config = config
            broker.console = ConsoleServer(ConsoleApplication(ConsoleMetadata(broker.store, broker.seal), config,
                                                              put=broker.admin.service.put_value,
                                                              reveal=broker.admin.service.reveal_value,
                                                              check_passphrase=broker.seal.check_passphrase,
                                                              unseal=broker.admin.service.unseal_value,
                                                              seal=broker.admin.service.seal_value,
                                                              support=options.console_support))
        broker.run()
    finally:
        broker.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
