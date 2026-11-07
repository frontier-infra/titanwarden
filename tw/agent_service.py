"""Authenticated implementation of the Titanwarden agent operations."""

from __future__ import annotations

import hashlib
import json
import os
import select
import secrets
import sqlite3
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from .execute import ExecutionError, ExecutionHandle, ExecutionRequest, Executor
from .identity import (
    Attestation,
    Attestor,
    IdentityError,
    IdentityStore,
    LeaseIdentity,
    PermissionSet,
    ProcessInfo,
    Scope,
)
from .importers.envfile import EnvImporter, EnvImportError, parse_manifest
from .redact import Redactor, build_patterns, scrub_text
from .audit import AuditLog
from .desk import classify_answer
from . import crypto


NESTED_ALLOWED = frozenset(
    {"run", "put", "generate", "import_env", "names", "status", "who_touched", "dependents"}
)
MAX_SECRET_BYTES = 1024 * 1024
PUT_READ_SECONDS = 5.0
REQUEST_OPERATIONS = frozenset({"inject", "put", "audit", "use"})


class AgentServiceError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class AgentService:
    def __init__(
        self,
        store: Any,
        seal: Any,
        *,
        home: Path,
        broker_pid: int,
        process_resolver: Callable[[int], ProcessInfo | None],
        desk_notify: Callable[[str, str, str], str | None] | None = None,
        desk_default: Callable[[str, str], None] | None = None,
        worker_handle_resolver: Callable[[str, str | None], str | None] | None = None,
    ):
        self.store = store
        self.seal = seal
        self.home = home
        self.broker_pid = broker_pid
        self.process_resolver = process_resolver
        self.desk_notify = desk_notify or (lambda _kind, _subject, _body: None)
        self.desk_default = desk_default or (lambda _item, _decision: None)
        self.identities = IdentityStore(store.connection, home, desk_notify=self.desk_notify)
        self.worker_handle_resolver = worker_handle_resolver or _orca_worker_handle
        self.executor = Executor(
            secret_resolver=self._secret_value,
            redactor_factory=self._redactor_for,
            lease_open=self._lease_open,
            lease_close=self._lease_close,
        )
        self.request_default_delay = 3600.0
        self._cached_values: dict[str, list[bytes]] | None = None
        self.cloud = None

    def _cloud_mode(self):
        return self.cloud is not None and self.cloud.enabled

    def close(self) -> None:
        self.executor.close()

    def _keyring(self) -> dict[str, tuple[str, bytes]]:
        keys = self.seal.keys
        if keys is None:
            raise AgentServiceError("E_SEALED", "broker is sealed")
        return {
            "kek": (keys.kek_id, bytes(keys.kek)),
            "audit_mac": (keys.audit_id, bytes(keys.audit)),
            "fingerprint": (keys.fingerprint_id, bytes(keys.fingerprint)),
        }

    def _secret_value(self, path: str) -> bytes:
        try:
            if self._cloud_mode():
                return self.cloud.read(path)
            return self.store.reveal_secret(path, keyring=self._keyring())
        except AgentServiceError:
            raise
        except Exception as exc:
            if self._cloud_mode() and getattr(exc, 'code', None) in ('E_POLICY_CONFLICT','E_POLICY_STALE','E_SYNC_RETRY','E_SEALED'):
                raise
            raise AgentServiceError("E_DENIED", "secret access denied") from exc

    def _secret_row(self, path: str) -> sqlite3.Row | None:
        if self._cloud_mode():
            return self.cloud.secret_row(path)
        return self.store.connection.execute(
            "SELECT s.*,p.no_shell project_no_shell FROM secrets s JOIN projects p "
            "ON p.slug=s.project WHERE s.path=? AND s.state='active'",
            (path,),
        ).fetchone()

    def _all_values(self) -> dict[str, list[bytes]]:
        if self._cloud_mode():
            return self.cloud.values()
        if self._cached_values is not None:
            return self._cached_values
        values: dict[str, list[bytes]] = {}
        now = _now()
        rows = self.store.connection.execute(
            "SELECT s.path,v.version_no,v.state,v.grace_until FROM secrets s "
            "JOIN secret_versions v ON v.secret_id=s.secret_id "
            "WHERE v.state IN ('active','grace')"
        )
        for row in rows:
            if row[2] == "grace" and row[3] and str(row[3]) <= now:
                continue
            try:
                values.setdefault(str(row[0]), []).append(
                    self.store.reveal_secret(
                        str(row[0]), keyring=self._keyring(), version_no=int(row[1])
                    )
                )
            except Exception:
                continue
        self._cached_values = values
        return values

    def set_redaction_values(self, values: Mapping[str, list[bytes]]) -> None:
        self._cached_values = {
            str(path): [bytes(value) for value in path_values]
            for path, path_values in values.items()
        }

    def clear_redaction_values(self) -> None:
        self._cached_values = None

    def _redactor_for(self, principal_id: str) -> Redactor:
        values = self._all_values()
        visible: set[str] = set()
        token = self.store.connection.execute(
            "SELECT token_id FROM tokens WHERE principal_id=? AND revoked_at IS NULL "
            "ORDER BY created_at DESC LIMIT 1",
            (principal_id,),
        ).fetchone()
        if token is not None:
            try:
                permission, task_ceiling = self.identities.permission_for_token(str(token[0]))
                for path in values:
                    row = self._secret_row(path)
                    if row and permission.allows("inject", path, str(row["class"]), task_ceiling):
                        visible.add(path)
            except IdentityError:
                pass
        return Redactor(build_patterns(values, visible))

    def _attestor(self) -> Attestor:
        handles = {
            str(row[0]): str(row[1])
            for row in self.store.connection.execute(
                "SELECT handle,principal_id FROM pane_bindings WHERE revoked_at IS NULL"
            )
        }
        leases = {
            int(row[1]): LeaseIdentity(
                str(row[0]), int(row[1]), str(row[2]), str(row[3]), bool(row[4])
            )
            for row in self.store.connection.execute(
                "SELECT lease_id,pid,token_id,principal_id,context_verified FROM leases "
                "WHERE closed_at IS NULL AND pid IS NOT NULL"
            )
        }
        return Attestor(self.broker_pid, self.process_resolver, handles, leases)

    def authenticate(
        self, request: Mapping[str, Any], peer_pid: int
    ) -> tuple[sqlite3.Row, PermissionSet, Scope | None, Attestation]:
        token_text = request.get("token")
        token_row = None
        claimed_principal = None
        if token_text:
            token_row = self.store.connection.execute(
                "SELECT * FROM tokens WHERE token_hash=? AND revoked_at IS NULL",
                (hashlib.sha256(str(token_text).encode()).digest(),),
            ).fetchone()
            if token_row is None:
                raise AgentServiceError("E_AUTH", "authentication failed")
            if token_row["hard_expires_at"] and str(token_row["hard_expires_at"]) <= _now():
                raise AgentServiceError("E_AUTH", "authentication failed")
            if token_row["parent_token_id"]:
                parent = self.store.connection.execute(
                    "SELECT revoked_at FROM tokens WHERE token_id=?",
                    (token_row["parent_token_id"],),
                ).fetchone()
                if parent is None or parent[0] is not None:
                    raise AgentServiceError("E_AUTH", "authentication failed")
            claimed_principal = str(token_row["principal_id"])
        try:
            attestation = self._attestor().attest(peer_pid, claimed_principal)
        except IdentityError as exc:
            raise AgentServiceError(exc.code, str(exc)) from exc
        if attestation.status == "nested":
            token_row = self.store.connection.execute(
                "SELECT * FROM tokens WHERE token_id=? AND revoked_at IS NULL",
                (
                    self.store.connection.execute(
                        "SELECT token_id FROM leases WHERE lease_id=?",
                        (attestation.parent_lease_id,),
                    ).fetchone()[0],
                ),
            ).fetchone()
        if token_row is None:
            raise AgentServiceError("E_NO_IDENTITY", "no identity for this pane")
        try:
            permission, task_ceiling = self.identities.permission_for_token(str(token_row["token_id"]))
        except IdentityError as exc:
            raise AgentServiceError(exc.code, str(exc)) from exc
        self.store.connection.execute(
            "UPDATE tokens SET last_used_at=? WHERE token_id=?", (_now(), token_row["token_id"])
        )
        audit_key = None if self.seal.keys is None else bytes(self.seal.keys.audit)
        AuditLog(self.store, mac_key=audit_key).append(
            event_id=self.store.new_id("evt_"),
            op=str(request.get("op", "unknown")),
            principal_id=str(token_row["principal_id"]),
            token_id=str(token_row["token_id"]),
            parent_lease_id=attestation.parent_lease_id,
            attest_status=attestation.status,
            attested_handle=attestation.attested_handle,
            context_verified=int(attestation.context_verified),
            peer_pid=peer_pid,
            peer_exe=attestation.evidence_executable,
            claimed_json=self._safe_claimed_json(request.get("ctx", {}), str(token_row["principal_id"])),
        )
        return token_row, permission, task_ceiling, attestation

    def _safe_claimed_json(self, value: object, principal_id: str) -> str:
        allowed = {"cwd", "pid", "argv0", "job", "orca_terminal", "orca_run", "dispatch", "lease"}
        source = value if isinstance(value, Mapping) else {}
        bounded: dict[str, object] = {}
        for key in allowed:
            item = source.get(key)
            if item is None or isinstance(item, (bool, int, float)):
                bounded[key] = item
            else:
                bounded[key] = str(item)[:400]
        rendered = json.dumps(bounded, sort_keys=True, separators=(",", ":"))
        if len(rendered) > 4096:
            rendered = "{}"
        return scrub_text(rendered, self._redactor_for(principal_id))[0]

    def status(self, request: Mapping[str, Any], peer_pid: int) -> dict[str, Any]:
        token, _permission, task_ceiling, attestation = self.authenticate(request, peer_pid)
        project = self.store.connection.execute(
            "SELECT project FROM principals WHERE principal_id=?", (token["principal_id"],)
        ).fetchone()
        return {
            "principal": token["principal_id"],
            "project": None if project is None else project[0],
            "token_id": token["token_id"],
            "attest_status": attestation.status,
            "context_verified": attestation.context_verified,
            "scope": [] if task_ceiling is None else [_scope_text(task_ceiling)],
            "open_leases": self.store.connection.execute(
                "SELECT count(*) FROM leases WHERE principal_id=? AND closed_at IS NULL",
                (token["principal_id"],),
            ).fetchone()[0],
            "open_requests": self.store.connection.execute(
                "SELECT count(*) FROM requests WHERE principal_id=? AND state='open'",
                (token["principal_id"],),
            ).fetchone()[0],
            "seal_state": self.seal.state,
            "frozen": self.seal.frozen,
        }

    def start_run(
        self,
        request: Mapping[str, Any],
        peer_pid: int,
        client_fds: list[int],
    ) -> ExecutionHandle:
        observe_freeze = getattr(self.seal, "observe_freeze_file", None)
        if observe_freeze is not None:
            observe_freeze()
        token, permission, task_ceiling, attestation = self.authenticate(request, peer_pid)
        if attestation.status == "nested" and request.get("op") not in NESTED_ALLOWED:
            raise AgentServiceError("E_SCOPE", "operation is unavailable in a nested call")
        args = _args(request)
        if args.get("manifest"):
            try:
                manifest = parse_manifest(
                    str(args["manifest"]), self._stored_value_matches
                )
            except (EnvImportError, OSError, UnicodeError) as exc:
                raise AgentServiceError(
                    getattr(exc, "code", "E_POLICY"), "manifest is invalid or unavailable"
                ) from exc
            args = dict(args)
            combined_refs = dict(manifest["env_refs"])
            combined_refs.update(dict(args.get("env_refs", {})))
            combined_environment = dict(args.get("environment", {}))
            combined_environment.update(manifest["literals"])
            args["env_refs"] = combined_refs
            args["environment"] = combined_environment
        if len(client_fds) < 3:
            raise AgentServiceError("E_BAD_REQUEST", "run requires standard stream descriptors")
        refs = dict(args.get("env_refs", {}))
        refs.update(dict(args.get("soft_refs", {})))
        refs.update({str(key): value for key, value in dict(args.get("fd_refs", {})).items()})
        if args.get("stdin_ref"):
            refs["stdin"] = str(args["stdin_ref"])
        no_shell = False
        for path in refs.values():
            row = self._secret_row(str(path))
            if row is None or not permission.allows(
                "inject", str(path), str(row["class"]), task_ceiling
            ):
                raise AgentServiceError("E_DENIED", "secret access denied")
            if row["short"] and not row["allow_short_delivery"]:
                raise AgentServiceError("E_DENIED", "secret access denied")
            no_shell = no_shell or bool(row["no_shell"]) or bool(row["project_no_shell"])
        soft_refs = dict(args.get("soft_refs", {}))
        hard_refs = bool(
            args.get("env_refs") or args.get("fd_refs") or args.get("stdin_ref")
        )
        temporarily_unavailable = self.seal.state != "unsealed" or self.seal.frozen
        if temporarily_unavailable:
            if hard_refs or not soft_refs:
                code = "E_FROZEN" if self.seal.frozen else "E_SEALED"
                raise AgentServiceError(code, "broker is temporarily unavailable")
            for path in soft_refs.values():
                AuditLog(
                    self.store,
                    mac_key=None if self.seal.keys is None else bytes(self.seal.keys.audit),
                ).append(
                    event_id=self.store.new_id("evt_"),
                    op="run",
                    decision="allow",
                    reason_code="soft_skip",
                    principal_id=str(token["principal_id"]),
                    token_id=str(token["token_id"]),
                    secret_path=str(path),
                    parent_lease_id=attestation.parent_lease_id,
                    attest_status=attestation.status,
                    context_verified=int(attestation.context_verified),
                )
            soft_refs = {}
        execution = ExecutionRequest(
            lease_id=self.store.new_id("lea_"),
            token_id=str(token["token_id"]),
            principal_id=str(token["principal_id"]),
            argv=list(args.get("argv", [])),
            cwd=str(args.get("cwd", "")),
            environment=dict(args.get("environment", {})),
            env_refs=dict(args.get("env_refs", {})),
            fd_refs={int(key): str(value) for key, value in dict(args.get("fd_refs", {})).items()},
            stdin_ref=args.get("stdin_ref"),
            soft_refs=soft_refs,
            job=args.get("job"),
            parent_lease_id=attestation.parent_lease_id,
            context_verified=attestation.context_verified,
            no_shell=no_shell,
        )
        try:
            return self.executor.start(
                execution, client_fds[1], client_fds[2], stdin_fd=client_fds[0]
            )
        except (ExecutionError, IdentityError) as exc:
            raise AgentServiceError(getattr(exc, "code", "E_EXEC"), str(exc)) from exc

    def _stored_value_matches(self, value: bytes) -> bool:
        if self._cloud_mode():
            return any(crypto.compare_digest(value,candidate) for values in self.cloud.values().values() for candidate in values)
        fingerprint = crypto.fingerprint(self._keyring()["fingerprint"][1], value)
        return self.store.connection.execute(
            "SELECT 1 FROM secret_versions WHERE fingerprint=? AND state IN ('active','grace') LIMIT 1",
            (fingerprint,),
        ).fetchone() is not None

    def names(self, request: Mapping[str, Any], peer_pid: int) -> dict[str, Any]:
        token, permission, task_ceiling, _attestation = self.authenticate(request, peer_pid)
        project = _args(request).get("project")
        if self._cloud_mode():
            return {"names": [{"path": row['path'], "class": row['class']} for row in self.cloud.sync().agent_metadata()
                if (not project or row['project'] == project) and any(permission.allows(op,row['path'],row['class'],task_ceiling)
                    for op in ('inject','put'))]}
        query = (
            "SELECT s.path,s.class,v.version_no,v.length,v.activated_at,s.rotation_json "
            "FROM secrets s JOIN secret_versions v ON v.secret_id=s.secret_id AND v.state='active'"
        )
        parameters: tuple[object, ...] = ()
        if project:
            query += " WHERE s.project=?"
            parameters = (project,)
        result = []
        for row in self.store.connection.execute(query, parameters):
            path = str(row[0])
            if token["principal_id"] != "master" and not any(
                permission.allows(op, path, str(row[1]), task_ceiling)
                for op in ("inject", "put")
            ):
                continue
            result.append(
                {
                    "path": path,
                    "class": row[1],
                    "version_no": row[2],
                    "length_bucket": _length_bucket(int(row[3])),
                    "last_rotated": row[4],
                    "adapter": json.loads(row[5]).get("adapter"),
                }
            )
        return {"names": result}

    def handle(self, request: Mapping[str, Any], peer_pid: int) -> dict[str, Any]:
        op = str(request.get("op", ""))
        token, permission, task_ceiling, attestation = self.authenticate(request, peer_pid)
        if attestation.status == "nested" and op not in NESTED_ALLOWED:
            raise AgentServiceError("E_SCOPE", "operation is unavailable in a nested call")
        args = _args(request)
        principal_id = str(token["principal_id"])
        if op == "request":
            return self._request_access(principal_id, args)
        if op == "task_token_issue":
            if token["kind"] != "lead":
                raise AgentServiceError("E_SCOPE", "only a lead may issue task tokens")
            dispatch = str(args.get("dispatch") or args.get("task") or "")
            run_row = self.store.connection.execute(
                "SELECT orca_run_id FROM principals WHERE principal_id=?", (principal_id,)
            ).fetchone()
            lead_run = None if run_row is None else run_row[0]
            handle = self.worker_handle_resolver(dispatch, lead_run)
            if not handle:
                raise AgentServiceError("E_SCOPE", "worker dispatch is not active")
            expires = datetime.now(timezone.utc) + _duration(str(args.get("ttl", "8h")), 24)
            issued = self.identities.issue_task_token(
                str(token["token_id"]),
                dispatch,
                handle,
                str(args.get("scope", "")),
                expires.isoformat().replace("+00:00", "Z"),
            )
            principal = self.store.connection.execute(
                "SELECT principal_id FROM tokens WHERE token_id=?", (issued["token_id"],)
            ).fetchone()[0]
            return {
                "token_id": issued["token_id"],
                "principal_id": principal,
                "bound_handle": issued["bound_handle"],
            }
        if op == "task_token_revoke":
            target = str(args.get("token_id", ""))
            row = self.store.connection.execute(
                "SELECT parent_token_id FROM tokens WHERE token_id=?", (target,)
            ).fetchone()
            if row is None or (principal_id != "master" and row[0] != token["token_id"]):
                raise AgentServiceError("E_SCOPE", "token revocation denied")
            self.identities.revoke_token(target, str(args.get("reason", "revoked")))
            return {"revoked": True}
        if op == "token_revoke_self":
            self.identities.revoke_token(str(token["token_id"]), str(args.get("reason", "self")))
            return {"revoked": True}
        if op in {"who_touched", "dependents"}:
            path = str(args.get("path", ""))
            row = self._secret_row(path)
            if row is None or (
                principal_id != "master"
                and not permission.allows("audit", path, str(row["class"]), task_ceiling)
            ):
                raise AgentServiceError("E_DENIED", "secret access denied")
            audit = AuditLog(self.store, mac_key=bytes(self.seal.keys.audit))
            if op == "who_touched":
                return {"events": audit.who_touched(path, int(args.get("n", 10)))}
            return audit.dependents(path)
        if op in {"freeze", "unfreeze", "panic_seal", "roster_sync", "token_issue", "grant_add", "grant_rm", "request_decide"}:
            if principal_id != "master":
                raise AgentServiceError("E_SCOPE", "master capability required")
            return self._master_operation(op, args)
        raise AgentServiceError("E_NOT_IMPLEMENTED", "operation is not implemented")

    def _master_operation(self, op: str, args: Mapping[str, Any]) -> dict[str, Any]:
        if self._cloud_mode() and op in ('grant_add','grant_rm','request_decide'):
            raise AgentServiceError('E_POLICY', 'cloud grants require signed console policy')
        if op == "freeze":
            self.seal.freeze()
            return {"frozen": True}
        if op == "unfreeze":
            self.seal.unfreeze()
            return {"frozen": False}
        if op == "panic_seal":
            self.seal.lockdown()
            return {"seal_state": self.seal.state}
        if op == "token_issue":
            principal = str(args.get("principal", ""))
            row = self.store.connection.execute(
                "SELECT kind,coordinator_handle FROM principals WHERE principal_id=?", (principal,)
            ).fetchone()
            if row is None or row[0] not in {"lead", "job"}:
                raise AgentServiceError("E_SCOPE", "token issue denied")
            return self.identities.issue_token(
                principal,
                str(row[0]),
                created_by="master",
                handle=row[1],
            )
        if op == "grant_add":
            scope = Scope.parse(str(args.get("scope", "")))
            if len(scope.entries) != 1:
                raise AgentServiceError("E_SCOPE", "one grant entry is required")
            entry = scope.entries[0]
            if entry.project in {"shared", None}:
                raise AgentServiceError("E_SCOPE", "direct cross-project grant denied")
            principal = str(args.get("principal", ""))
            project = self.store.connection.execute(
                "SELECT project FROM principals WHERE principal_id=?", (principal,)
            ).fetchone()
            if project is None or project[0] != entry.project:
                raise AgentServiceError("E_SCOPE", "direct cross-project grant denied")
            grant_id = self._insert_grant(
                principal,
                entry,
                "sensitive",
                "master",
                str(args.get("reason", "grant")),
                _expiry(args.get("ttl")),
                None,
            )
            return {"grant_id": grant_id}
        if op == "grant_rm":
            self.store.connection.execute(
                "UPDATE grants SET revoked_at=? WHERE grant_id=? AND revoked_at IS NULL",
                (_now(), str(args.get("grant_id", ""))),
            )
            return {"revoked": True}
        if op == "request_decide":
            request_id = str(args.get("request_id", ""))
            decision = str(args.get("decision", ""))
            if decision not in {"approve", "deny"}:
                raise AgentServiceError("E_BAD_REQUEST", "invalid request decision")
            row = self.store.connection.execute(
                "SELECT * FROM requests WHERE request_id=? AND state='open'", (request_id,)
            ).fetchone()
            if row is None:
                raise AgentServiceError("E_SCOPE", "request is not open")
            if row["principal_id"] == "master":
                raise AgentServiceError("E_SCOPE", "master cannot approve its own request")
            secret = self._secret_row(str(row["target"]))
            if secret is None or secret["class"] != "standard" or str(row["target"]).startswith("client/"):
                raise AgentServiceError("E_SCOPE", "request needs the operator in twadmin")
            if decision == "approve":
                entry = _request_entry(str(row["ops"]), str(row["target"]))
                self._insert_grant(
                    str(row["principal_id"]), entry, "standard", "master",
                    str(args.get("reason", "approved")), _default_grant_expiry(str(row["target"]), "standard"), request_id
                )
            self.store.connection.execute(
                "UPDATE requests SET state=?,decided_by='master',decided_at=? WHERE request_id=?",
                ("approved" if decision == "approve" else "denied", _now(), request_id),
            )
            return {"request_id": request_id, "state": "approved" if decision == "approve" else "denied"}
        if op == "roster_sync":
            # The roster lives in this install's TW_HOME unless the caller names a path.
            roster_path = Path(str(args.get("path") or Path(self.home) / "state" / "team.json")).expanduser()
            roster = json.loads(roster_path.read_text(encoding="utf-8"))
            return self.identities.roster_sync(roster, _orca_run_rows())
        raise AgentServiceError("E_NOT_IMPLEMENTED", "operation is not implemented")

    def _request_access(self, principal_id: str, args: Mapping[str, Any]) -> dict[str, Any]:
        if self._cloud_mode():
            raise AgentServiceError('E_NOT_IMPLEMENTED', 'cloud request creation is unavailable')
        kind = str(args.get("kind", ""))
        target = str(args.get("target", ""))
        ops = _request_ops(str(args.get("ops") or "inject"))
        if kind not in {"access", "create", "rotate"}:
            raise AgentServiceError("E_BAD_REQUEST", "invalid request kind")
        request_id = self.store.new_id("req_")
        secret = self._secret_row(target)
        project = target.partition("/")[0]
        secret_class = "sensitive" if secret is None else str(secret["class"])
        project_row = self.store.connection.execute(
            "SELECT change_policy FROM projects WHERE slug=?", (project,)
        ).fetchone()
        restricted = (
            secret_class == "restricted"
            or project == "client"
            or (project_row is not None and project_row[0] == "client_approval_required")
        )
        default_at = None
        default_decision = None
        needs = "client" if project == "client" else "operator"
        if kind == "access" and not restricted:
            needs = "master" if project == "shared" else "operator"
            default_decision = "approve"
            default_at = (
                datetime.now(timezone.utc) + timedelta(seconds=self.request_default_delay)
            ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        desk_item = self.desk_notify(
            "action" if restricted else "ask",
            f"Titanwarden {kind} request for {target}",
            f"Requested by {principal_id}. Decision owner: {needs}. "
            + (
                f"Default: {default_decision} at {default_at}. "
                if default_decision
                else "Default: wait for the operator. "
            )
            + "Titanwarden runs this default itself; leave this item for the operator.",
        )
        reason, _scrubbed = scrub_text(
            str(args.get("reason", "")), self._redactor_for(principal_id)
        )
        AuditLog(
            self.store,
            mac_key=None if self.seal.keys is None else bytes(self.seal.keys.audit),
        ).append(
            event_id=self.store.new_id("evt_"),
            op="request",
            principal_id=principal_id,
            request_id=request_id,
            scrubbed=int(_scrubbed),
            detail_json=json.dumps({"reason": reason}, sort_keys=True, separators=(",", ":")),
        )
        self.store.connection.execute(
            "INSERT INTO requests(request_id,principal_id,kind,target,ops,reason,ttl,needs,"
            "default_decision,default_at,desk_item,state,created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,'open',?)",
            (
                request_id, principal_id, kind, target, "+".join(ops), reason,
                args.get("ttl"), needs, default_decision, default_at, desk_item, _now()
            ),
        )
        self.apply_request_defaults()
        row = self.store.connection.execute(
            "SELECT state,desk_item FROM requests WHERE request_id=?", (request_id,)
        ).fetchone()
        return {
            "request_id": request_id,
            "needs": needs,
            "desk_item": row["desk_item"],
            "default_decision": default_decision,
            "default_at": default_at,
        }

    def apply_request_defaults(self, now: str | None = None) -> int:
        if self._cloud_mode():
            return 0
        instant = now or _now()
        rows = list(
            self.store.connection.execute(
                "SELECT * FROM requests WHERE state='open' AND default_decision='approve' "
                "AND default_at<=?", (instant,)
            )
        )
        for row in rows:
            secret = self._secret_row(str(row["target"]))
            if secret is None or secret["class"] == "restricted" or str(row["target"]).startswith("client/"):
                continue
            entry = _request_entry(str(row["ops"]), str(row["target"]))
            maximum = str(secret["class"])
            self._insert_grant(
                str(row["principal_id"]), entry, maximum, "policy",
                "request default", _default_grant_expiry(str(row["target"]), maximum), str(row["request_id"])
            )
            self.store.connection.execute(
                "UPDATE requests SET state='defaulted',decided_by='system:default',decided_at=? "
                "WHERE request_id=?", (instant, row["request_id"])
            )
            if row["desk_item"]:
                self.desk_default(str(row["desk_item"]), "Approve")
        return len(rows)

    def apply_desk_answers(self, items: list[dict[str, Any]]) -> int:
        by_id = {str(item.get("id")): item for item in items}
        changed = 0
        rows = self.store.connection.execute(
            "SELECT * FROM requests WHERE state='open' AND desk_item IS NOT NULL"
        ).fetchall()
        for row in rows:
            item = by_id.get(str(row["desk_item"]))
            if item is None:
                continue
            decision = classify_answer(item)
            if decision.accepted and decision.decision == "deny":
                self.store.connection.execute(
                    "UPDATE requests SET state='denied',decided_by='desk:operator',decided_at=? "
                    "WHERE request_id=? AND state='open'",
                    (_now(), row["request_id"]),
                )
                AuditLog(
                    self.store,
                    mac_key=None if self.seal.keys is None else bytes(self.seal.keys.audit),
                ).append(
                    event_id=self.store.new_id("evt_"),
                    op="request_decide",
                    principal_id="human:operator",
                    request_id=row["request_id"],
                    reason_code="desk_denied",
                )
                changed += 1
                continue
            if item.get("status") not in {"answered", "done"}:
                continue
            already_recorded = self.store.connection.execute(
                "SELECT 1 FROM audit_events WHERE op='desk_answer_ignored' "
                "AND request_id=? LIMIT 1",
                (row["request_id"],),
            ).fetchone()
            if already_recorded is not None:
                continue
            AuditLog(
                self.store,
                mac_key=None if self.seal.keys is None else bytes(self.seal.keys.audit),
            ).append(
                event_id=self.store.new_id("evt_"),
                op="desk_answer_ignored",
                decision="deny",
                principal_id=str(row["principal_id"]),
                request_id=row["request_id"],
                reason_code=decision.reason,
                detail_json=json.dumps(
                    {"author": decision.author}, sort_keys=True, separators=(",", ":")
                ),
            )
            self.desk_notify(
                "info",
                f"Ignored Desk answer for Titanwarden request {row['request_id']}",
                "The request remains open. The operator can deny or approve it with twadmin.",
            )
        return changed

    def _insert_grant(
        self,
        principal_id: str,
        entry: Any,
        max_class: str,
        granted_by: str,
        reason: str,
        expires_at: str | None,
        request_id: str | None,
    ) -> str:
        grant_id = self.store.new_id("grt_")
        self.store.connection.execute(
            "INSERT INTO grants(grant_id,principal_id,pattern,ops,conditions_json,effect,"
            "granted_by,reason,request_id,created_at,expires_at) VALUES (?,?,?,?,?,'allow',?,?,?,?,?)",
            (
                grant_id, principal_id, f"{entry.project}/{entry.name}",
                "+".join(sorted(entry.operations)), json.dumps({"max_class": max_class}, separators=(",", ":")),
                granted_by, reason, request_id, _now(), expires_at
            ),
        )
        return grant_id

    def put(
        self,
        request: Mapping[str, Any],
        peer_pid: int,
        fds: list[int],
        *,
        value: bytes | None = None,
    ) -> dict[str, Any]:
        token, permission, task_ceiling, attestation = self.authenticate(request, peer_pid)
        if attestation.status == "nested" and request.get("op") not in NESTED_ALLOWED:
            raise AgentServiceError("E_SCOPE", "operation is unavailable in a nested call")
        args = _args(request)
        path = str(args.get("path", ""))
        existing = self._secret_row(path)
        requested_class = str(args.get("class", existing["class"] if existing else "sensitive"))
        secret_class = (
            str(existing["class"])
            if existing
            else self._effective_secret_class(path, requested_class)
        )
        if existing is not None and requested_class != secret_class:
            raise AgentServiceError("E_POLICY", "secret class cannot be changed by put")
        if not permission.allows("put", path, secret_class, task_ceiling):
            raise AgentServiceError("E_DENIED", "secret access denied")
        if request.get("op") == "generate":
            value = _generate(int(args.get("length", 0)), str(args.get("charset", "urlsafe")))
        else:
            if value is None and not fds:
                raise AgentServiceError("E_BAD_REQUEST", "put requires a value descriptor")
            if value is None:
                value = _read_fd_limited(fds[0])
        put_secret = self.cloud.put if self._cloud_mode() else self.store.put_secret
        cloud_options = {}
        if self._cloud_mode():
            def authorize_publication():
                current, ceiling = self.identities.permission_for_token(str(token['token_id']))
                if not current.allows('put',path,secret_class,ceiling):
                    raise AgentServiceError('E_DENIED','cloud publication grant is no longer active')
            cloud_options['authorize'] = authorize_publication
        result = put_secret(
            path,
            value,
            keyring=self._keyring(),
            principal_id=str(token["principal_id"]),
            secret_class=secret_class,
            kind=str(args.get("kind", "opaque")),
            note=args.get("note"),
            source="generate" if request.get("op") == "generate" else "put",
            **cloud_options,
        )
        self._cached_values = None
        if request.get("op") == "generate":
            return {"path": result["path"], "version_no": result["version_no"]}
        return result

    def import_env(self, request: Mapping[str, Any], peer_pid: int) -> dict[str, Any]:
        if self._cloud_mode():
            raise AgentServiceError('E_NOT_IMPLEMENTED', 'cloud imports require individual put operations')
        token, permission, task_ceiling, attestation = self.authenticate(request, peer_pid)
        if attestation.status == "nested" and request.get("op") not in NESTED_ALLOWED:
            raise AgentServiceError("E_SCOPE", "operation is unavailable in a nested call")
        args = _args(request)
        project = str(args.get("project", ""))
        client_roots = self._client_path_roots()
        importer = EnvImporter(
            Path(__file__).parents[1] / "config" / "policies.json",
            store_value=lambda _path, _value, _source: {},
            store_quarantine=lambda _project, _path, _payload: "",
        )
        importer.ensure_allowed(
            str(args.get("path", "")), project, extra_path_roots=client_roots
        )
        probe_path = project + "/import"
        import_class = self._effective_secret_class(probe_path, "sensitive")
        if not permission.allows("put", probe_path, import_class, task_ceiling):
            raise AgentServiceError("E_DENIED", "secret access denied")
        principal_id = str(token["principal_id"])

        def store_value(path: str, value: bytes, source: str) -> Mapping[str, object]:
            fingerprint = crypto.fingerprint(self._keyring()["fingerprint"][1], value)
            candidates = self.store.connection.execute(
                "SELECT s.path,v.version_no FROM secrets s JOIN secret_versions v "
                "ON v.secret_id=s.secret_id WHERE v.fingerprint=? AND v.state='active'",
                (fingerprint,),
            ).fetchall()
            for existing in candidates:
                existing_row = self._secret_row(str(existing[0]))
                if existing_row is not None and permission.allows(
                    "put", str(existing[0]), str(existing_row["class"]), task_ceiling
                ):
                    return {"path": path, "version_no": existing[1], "linked_to": existing[0]}
            return self.store.put_secret(
                path,
                value,
                keyring=self._keyring(),
                principal_id=principal_id,
                source=source,
            )

        def quarantine(project_name: str, original_path: str, payload: bytes) -> str:
            quarantine_id = self.store.new_id("qua_")
            self.store.connection.execute(
                "INSERT OR IGNORE INTO projects(slug,change_policy,created_at) "
                "VALUES ('infra','auto',?)",
                (_now(),),
            )
            secret_path = f"infra/broker-quarantine-{quarantine_id.removeprefix('qua_')}"
            receipt = self.store.put_secret(
                secret_path,
                payload,
                keyring=self._keyring(),
                principal_id=principal_id,
                kind="env_file_blob",
                source="import_env",
            )
            secret_id = self.store.connection.execute(
                "SELECT secret_id FROM secrets WHERE path=?", (receipt["path"],)
            ).fetchone()[0]
            self.store.connection.execute(
                "INSERT INTO env_quarantine(quarantine_id,project,original_path,git_tracked,"
                "secret_id,state,created_at,created_by) VALUES (?,?,?,?,?,'original_kept',?,?)",
                (quarantine_id, project_name, original_path, 0, secret_id, _now(), principal_id),
            )
            return quarantine_id

        importer = EnvImporter(
            Path(__file__).parents[1] / "config" / "policies.json",
            store_value=store_value,
            store_quarantine=quarantine,
        )
        result = importer.import_file(
            str(args.get("path", "")), project, extra_path_roots=client_roots
        )
        self._cached_values = None
        return result

    def _client_path_roots(self) -> tuple[str, ...]:
        row = self.store.connection.execute(
            "SELECT worktree_roots_json FROM principals WHERE principal_id='lead:client'"
        ).fetchone()
        if row is None:
            return ()
        try:
            roots = json.loads(row[0])
        except (TypeError, json.JSONDecodeError):
            return ()
        return tuple(str(root) for root in roots if isinstance(root, str))

    def _effective_secret_class(self, path: str, requested: str) -> str:
        project = path.partition("/")[0]
        row = self.store.connection.execute(
            "SELECT change_policy FROM projects WHERE slug=?", (project,)
        ).fetchone()
        if project == "client" or (
            row is not None and row[0] == "client_approval_required"
        ):
            return "restricted"
        return requested

    def _lease_open(self, **fields: Any) -> None:
        lock = getattr(self.store, "_transaction_lock", None)
        if lock is None:
            self._lease_open_locked(**fields)
            return
        with lock:
            self._lease_open_locked(**fields)

    def _lease_open_locked(self, **fields: Any) -> None:
        principal = self.store.connection.execute(
            "SELECT orca_run_id FROM principals WHERE principal_id=?",
            (fields["principal_id"],),
        ).fetchone()
        orca_run_id = None if principal is None else principal[0]
        refs = []
        for ref in fields.pop("refs"):
            row = self.store.connection.execute(
                "SELECT v.version_no FROM secrets s JOIN secret_versions v ON v.secret_id=s.secret_id "
                "WHERE s.path=? AND v.state='active'",
                (ref["path"],),
            ).fetchone()
            refs.append({**ref, "version_no": None if row is None else row[0]})
        shell = fields.pop("shell")
        self.store.connection.execute(
            "INSERT INTO leases(lease_id,token_id,principal_id,op,refs_json,pid,pgid,argv0,"
            "argv_sha256,cwd,job,parent_lease_id,context_verified,opened_at) "
            "VALUES (?,?,?,'run',?,?,?,?,?,?,?,?,?,?)",
            (
                fields["lease_id"],
                fields["token_id"],
                fields["principal_id"],
                json.dumps(refs, sort_keys=True, separators=(",", ":")),
                fields["pid"],
                fields["pgid"],
                fields["argv0"],
                fields["argv_sha256"],
                fields["cwd"],
                fields["job"],
                fields["parent_lease_id"],
                int(fields["context_verified"]),
                _now(),
            ),
        )
        AuditLog(
            self.store,
            mac_key=None if self.seal.keys is None else bytes(self.seal.keys.audit),
        ).append(
            event_id=self.store.new_id("evt_"),
            op="run",
            phase="intent",
            decision="allow",
            principal_id=fields["principal_id"],
            orca_run_id=orca_run_id,
            token_id=fields["token_id"],
            lease_id=fields["lease_id"],
            parent_lease_id=fields["parent_lease_id"],
            context_verified=int(fields["context_verified"]),
            argv0=fields["argv0"],
            argv_sha256=fields["argv_sha256"],
            shell=int(shell),
        )
        for ref in refs:
            AuditLog(
                self.store,
                mac_key=None if self.seal.keys is None else bytes(self.seal.keys.audit),
            ).append(
                event_id=self.store.new_id("evt_"),
                op="run",
                phase="intent",
                decision="allow",
                principal_id=fields["principal_id"],
                orca_run_id=orca_run_id,
                token_id=fields["token_id"],
                lease_id=fields["lease_id"],
                parent_lease_id=fields["parent_lease_id"],
                context_verified=int(fields["context_verified"]),
                secret_path=ref["path"],
                version_no=ref["version_no"],
                job=fields["job"],
                argv0=fields["argv0"],
                argv_sha256=fields["argv_sha256"],
                shell=int(shell),
            )

    def _lease_close(self, **fields: Any) -> None:
        lock = getattr(self.store, "_transaction_lock", None)
        if lock is None:
            self._lease_close_locked(**fields)
            return
        with lock:
            self._lease_close_locked(**fields)

    def _lease_close_locked(self, **fields: Any) -> None:
        self.store.connection.execute(
            "UPDATE leases SET closed_at=?,exit_code=?,end_reason=? WHERE lease_id=?",
            (_now(), fields["exit_code"], fields["end_reason"], fields["lease_id"]),
        )
        lease = self.store.connection.execute(
            "SELECT * FROM leases WHERE lease_id=?", (fields["lease_id"],)
        ).fetchone()
        if lease is not None:
            AuditLog(
                self.store,
                mac_key=None if self.seal.keys is None else bytes(self.seal.keys.audit),
            ).append(
                event_id=self.store.new_id("evt_"),
                op="run",
                phase="result",
                decision="allow",
                reason_code=str(fields["end_reason"]),
                principal_id=lease["principal_id"],
                token_id=lease["token_id"],
                lease_id=lease["lease_id"],
                parent_lease_id=lease["parent_lease_id"],
                context_verified=int(lease["context_verified"]),
                argv0=lease["argv0"],
                argv_sha256=lease["argv_sha256"],
                exit_code=int(fields["exit_code"]),
                redactions=int(fields.get("redactions", 0)),
            )


def _args(request: Mapping[str, Any]) -> Mapping[str, Any]:
    args = request.get("args", {})
    if not isinstance(args, Mapping):
        raise AgentServiceError("E_BAD_REQUEST", "args must be an object")
    return args


def _read_fd_limited(
    fd: int,
    *,
    maximum: int = MAX_SECRET_BYTES,
    timeout: float = PUT_READ_SECONDS,
) -> bytes:
    chunks: list[bytes] = []
    size = 0
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise AgentServiceError("E_BUSY", "put value read timed out")
        chunk = os.read(fd, min(65536, maximum + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
        if size > maximum:
            raise AgentServiceError("E_BAD_REQUEST", "put value exceeds 1 MiB")
    return b"".join(chunks)


def _request_ops(text: str) -> tuple[str, ...]:
    operations = tuple(part.strip() for part in text.split("+") if part.strip())
    if not operations or len(set(operations)) != len(operations):
        raise AgentServiceError("E_BAD_REQUEST", "invalid request operations")
    if any(operation not in REQUEST_OPERATIONS for operation in operations):
        raise AgentServiceError("E_BAD_REQUEST", "invalid request operations")
    return operations


def _request_entry(ops: str, target: str):
    operations = _request_ops(ops)
    try:
        scope = Scope.parse(f"{'+'.join(operations)}:{target}")
    except IdentityError as exc:
        raise AgentServiceError("E_BAD_REQUEST", "invalid request target") from exc
    if len(scope.entries) != 1 or scope.entries[0].is_any:
        raise AgentServiceError("E_BAD_REQUEST", "invalid request target")
    return scope.entries[0]


def _generate(length: int, charset: str) -> bytes:
    if length < 8 or length > 4096:
        raise AgentServiceError("E_BAD_REQUEST", "invalid generated value length")
    if charset == "hex":
        return secrets.token_hex((length + 1) // 2)[:length].encode()
    if charset == "urlsafe":
        output = ""
        while len(output) < length:
            output += secrets.token_urlsafe(length)
        return output[:length].encode()
    if charset == "alnum":
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return "".join(secrets.choice(alphabet) for _ in range(length)).encode()
    raise AgentServiceError("E_BAD_REQUEST", "invalid generated value charset")


def _length_bucket(length: int) -> str:
    if length < 16:
        return "8-15"
    if length < 32:
        return "16-31"
    if length < 64:
        return "32-63"
    if length < 256:
        return "64-255"
    return "256+"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _scope_text(scope: Scope) -> str:
    parts = []
    for entry in scope.entries:
        if entry.is_any:
            parts.append("any:" + "+".join(sorted(entry.operations)))
        else:
            part = "+".join(sorted(entry.operations)) + f":{entry.project}/{entry.name}"
            if entry.hosts:
                part += "@" + "|".join(sorted(entry.hosts))
            parts.append(part)
    return ",".join(parts)


def _duration(text: str, maximum_hours: int) -> timedelta:
    units = {"m": 1 / 60, "h": 1, "d": 24}
    if len(text) < 2 or text[-1] not in units:
        raise AgentServiceError("E_BAD_REQUEST", "invalid duration")
    try:
        hours = float(text[:-1]) * units[text[-1]]
    except ValueError as exc:
        raise AgentServiceError("E_BAD_REQUEST", "invalid duration") from exc
    if hours <= 0 or hours > maximum_hours:
        raise AgentServiceError("E_SCOPE", "duration exceeds policy")
    return timedelta(hours=hours)


def _expiry(value: object) -> str | None:
    if not value:
        return None
    return (
        datetime.now(timezone.utc) + _duration(str(value), 24 * 365)
    ).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _default_grant_expiry(path: str, secret_class: str) -> str:
    if secret_class == "sensitive":
        duration = timedelta(hours=4)
    elif path.startswith("shared/"):
        duration = timedelta(days=7)
    else:
        duration = timedelta(hours=24)
    return (datetime.now(timezone.utc) + duration).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _orca_worker_handle(identifier: str, run_id: str | None = None) -> str | None:
    if not identifier:
        return None
    executable = os.environ.get("ORCA_CLI_COMMAND", "orca")
    if run_id:
        commands = [[
            executable,
            "orchestration",
            "worker-list",
            "--run",
            run_id,
            "--include-remote",
            "--json",
        ]]
    else:
        commands = [
            [executable, "orchestration", "worker-show", "--dispatch", identifier, "--json"],
            [executable, "orchestration", "worker-list", "--include-remote", "--json"],
        ]
    for index, command in enumerate(commands):
        try:
            completed = subprocess.run(
                command,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
            )
            if completed.returncode != 0:
                continue
            payload = json.loads(completed.stdout)
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            continue
        handle = _find_worker_handle(
            payload, identifier, allow_unmatched=not run_id and index == 0
        )
        if handle:
            return handle
    return None


def _find_worker_handle(
    value: object, identifier: str, *, allow_unmatched: bool = False
) -> str | None:
    if isinstance(value, dict):
        identities = {
            str(value.get(key, ""))
            for key in ("dispatchId", "dispatch_id", "taskId", "task_id", "id")
        }
        handle = value.get(
            "agentTerminalHandle",
            value.get("agent_terminal_handle", value.get("workerHandle")),
        )
        if handle and (identifier in identities or (allow_unmatched and not any(identities))):
            return str(handle)
        for child in value.values():
            found = _find_worker_handle(child, identifier, allow_unmatched=allow_unmatched)
            if found:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _find_worker_handle(child, identifier, allow_unmatched=allow_unmatched)
            if found:
                return found
    return None


def _orca_run_rows() -> list[Mapping[str, object]]:
    executable = os.environ.get("ORCA_CLI_COMMAND", "orca")
    cursor: str | None = None
    rows: list[Mapping[str, object]] = []
    while True:
        command = [executable, "orchestration", "run-list", "--json"]
        if cursor:
            command.extend(("--cursor", cursor))
        try:
            completed = subprocess.run(
                command,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
            )
            if completed.returncode != 0:
                break
            payload = json.loads(completed.stdout)
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            break
        rows.extend(_collect_run_rows(payload))
        page = _find_page(payload)
        next_cursor = None if page is None else page.get("nextCursor", page.get("next_cursor"))
        has_more = False if page is None else bool(page.get("hasMore", page.get("has_more")))
        if not has_more or not next_cursor:
            break
        cursor = str(next_cursor)
    return rows


def _collect_run_rows(value: object) -> list[Mapping[str, object]]:
    rows: list[Mapping[str, object]] = []
    if isinstance(value, dict):
        if any(key in value for key in ("runId", "run_id")):
            rows.append(value)
        for child in value.values():
            rows.extend(_collect_run_rows(child))
    elif isinstance(value, list):
        for child in value:
            rows.extend(_collect_run_rows(child))
    return rows


def _find_page(value: object) -> Mapping[str, object] | None:
    if isinstance(value, dict):
        page = value.get("page")
        if isinstance(page, Mapping):
            return page
        for child in value.values():
            found = _find_page(child)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _find_page(child)
            if found is not None:
                return found
    return None
