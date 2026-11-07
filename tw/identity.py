"""Scope evaluation and process-tree attestation for Titanwarden."""

from __future__ import annotations

from pathlib import Path

import re
import base64
import hashlib
import json
import os
import secrets
import sqlite3
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterable, Mapping


OPS = frozenset({"inject", "put", "audit", "use", "push", "share"})
CLASS_RANK = {"standard": 0, "sensitive": 1, "restricted": 2}
PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}\*?$")


class IdentityError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ScopeEntry:
    operations: frozenset[str]
    project: str | None
    name: str | None
    hosts: frozenset[str] = frozenset()

    @property
    def is_any(self) -> bool:
        return self.project is None

    def matches(self, operation: str, path: str, host: str | None = None) -> bool:
        if operation not in self.operations:
            return False
        if self.is_any:
            return True
        try:
            project, name = path.split("/", 1)
        except ValueError:
            return False
        if project != self.project:
            return False
        if self.name == "*":
            name_matches = True
        elif self.name and self.name.endswith("*"):
            name_matches = name.startswith(self.name[:-1])
        else:
            name_matches = name == self.name
        if not name_matches:
            return False
        return not self.hosts or host in self.hosts

    def contains(self, other: "ScopeEntry") -> bool:
        if not other.operations.issubset(self.operations):
            return False
        if self.is_any:
            return True
        if other.is_any or self.project != other.project:
            return False
        if self.name == "*":
            name_contains = True
        elif self.name and self.name.endswith("*"):
            prefix = self.name[:-1]
            name_contains = bool(other.name and other.name.startswith(prefix))
        else:
            name_contains = self.name == other.name
        if not name_contains:
            return False
        if self.hosts:
            return bool(other.hosts) and other.hosts.issubset(self.hosts)
        return not other.hosts


@dataclass(frozen=True)
class Scope:
    entries: tuple[ScopeEntry, ...]

    @classmethod
    def parse(cls, text: str, allow_any: bool = False, *, allow_nested: bool = False) -> "Scope":
        if text.startswith("any:"):
            if not allow_any or "," in text:
                raise IdentityError("E_SCOPE", "invalid scope")
            operations = _parse_operations(text[4:])
            return cls((ScopeEntry(operations, None, None),))
        if not text:
            raise IdentityError("E_SCOPE", "invalid scope")
        entries = tuple(_parse_entry(part,allow_nested=allow_nested) for part in text.split(","))
        return cls(entries)

    def allows(self, operation: str, path: str, host: str | None = None) -> bool:
        return any(entry.matches(operation, path, host) for entry in self.entries)

    def contains(self, other: "Scope") -> bool:
        return all(any(entry.contains(item) for entry in self.entries) for item in other.entries)


def _parse_operations(text: str) -> frozenset[str]:
    operations = frozenset(text.split("+"))
    if not operations or "" in operations or not operations.issubset(OPS):
        raise IdentityError("E_SCOPE", "invalid scope")
    return operations


def _parse_entry(text: str, *, allow_nested=False) -> ScopeEntry:
    try:
        left, target = text.split(":", 1)
    except ValueError as exc:
        raise IdentityError("E_SCOPE", "invalid scope") from exc
    operations = _parse_operations(left)
    path, separator, host_text = target.partition("@")
    if path.count("/") != 1 and not allow_nested or '/' not in path:
        raise IdentityError("E_SCOPE", "invalid scope")
    project, name = path.split("/", 1)
    if "*" in project or not PROJECT_RE.fullmatch(project):
        raise IdentityError("E_SCOPE", "invalid scope")
    if name == "*":
        pass
    elif allow_nested:
        parts=name.split('/')
        if len(name)>2048 or any(part in ('','.','..') or not (re.fullmatch(r'[A-Za-z0-9_.-]+',part) or part=='*' and index==len(parts)-1)
                                for index,part in enumerate(parts)):
            raise IdentityError('E_SCOPE','invalid cloud scope')
    elif not NAME_RE.fullmatch(name) or ("*" in name and not name.endswith("*")):
        raise IdentityError("E_SCOPE", "invalid scope")
    if separator and "use" not in operations:
        raise IdentityError("E_SCOPE", "invalid scope")
    hosts = frozenset(host_text.split("|")) if separator else frozenset()
    if separator and (not host_text or "" in hosts):
        raise IdentityError("E_SCOPE", "invalid scope")
    return ScopeEntry(operations, project, name, hosts)


@dataclass
class Grant:
    scope: Scope
    max_class: str
    effect: str = "allow"
    expires_at: datetime | None = None
    revoked: bool = False

    def live(self, now: datetime | None = None) -> bool:
        instant = now or datetime.now(timezone.utc)
        return not self.revoked and (self.expires_at is None or self.expires_at > instant)


@dataclass
class PermissionSet:
    ceiling: Scope
    max_class: str
    grants: list[Grant] = field(default_factory=list)

    def allows(
        self,
        operation: str,
        path: str,
        secret_class: str,
        task_ceiling: Scope | None = None,
        host: str | None = None,
        now: datetime | None = None,
    ) -> bool:
        if path.startswith("infra/broker-"):
            return False
        if secret_class not in CLASS_RANK or CLASS_RANK[secret_class] > CLASS_RANK[self.max_class]:
            return False
        if not self.ceiling.allows(operation, path, host):
            return False
        if task_ceiling is not None and not task_ceiling.allows(operation, path, host):
            return False
        live = [grant for grant in self.grants if grant.live(now)]
        denied = any(
            grant.effect == "deny" and grant.scope.allows(operation, path, host)
            for grant in live
        )
        if denied:
            return False
        return any(
            grant.effect == "allow"
            and CLASS_RANK[secret_class] <= CLASS_RANK[grant.max_class]
            and grant.scope.allows(operation, path, host)
            for grant in live
        )

    def require(
        self,
        operation: str,
        path: str,
        secret_class: str,
        task_ceiling: Scope | None = None,
    ) -> None:
        if not self.allows(operation, path, secret_class, task_ceiling):
            raise IdentityError("E_DENIED", "access denied")

    def require_subset(self, requested: Scope) -> None:
        if not self.ceiling.contains(requested):
            raise IdentityError("E_SCOPE", "requested scope exceeds effective permission")
        for entry in requested.entries:
            covered = False
            for grant in self.grants:
                if (
                    grant.effect == "allow"
                    and grant.live()
                    and grant.scope.contains(Scope((entry,)))
                ):
                    covered = True
                    break
            if not covered:
                raise IdentityError("E_SCOPE", "requested scope exceeds effective permission")


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    ppid: int
    environment: Mapping[str, str]
    executable: str


@dataclass(frozen=True)
class LeaseIdentity:
    lease_id: str
    child_pid: int
    token_id: str
    principal_id: str
    context_verified: bool


@dataclass(frozen=True)
class Attestation:
    status: str
    principal_id: str | None
    context_verified: bool
    attested_handle: str | None = None
    attested_principal: str | None = None
    parent_lease_id: str | None = None
    evidence_executable: str | None = None


class Attestor:
    def __init__(
        self,
        broker_pid: int,
        process_resolver: Callable[[int], ProcessInfo | None],
        handle_principals: Mapping[str, str],
        leases_by_child: Mapping[int, LeaseIdentity],
    ):
        self.broker_pid = broker_pid
        self.process_resolver = process_resolver
        self.handle_principals = handle_principals
        self.leases_by_child = leases_by_child

    def attest(self, peer_pid: int, claimed_principal: str | None) -> Attestation:
        pid = peer_pid
        below_broker: int | None = None
        last: ProcessInfo | None = None
        chain: list[ProcessInfo] = []
        seen: set[int] = set()
        while pid > 0 and pid not in seen:
            seen.add(pid)
            if pid == self.broker_pid:
                if below_broker is None:
                    raise IdentityError("E_NO_IDENTITY", "no identity for caller")
                lease = self.leases_by_child.get(below_broker)
                if lease is None:
                    raise IdentityError("E_NO_IDENTITY", "no identity for caller")
                if claimed_principal is not None and claimed_principal != lease.principal_id:
                    raise IdentityError(
                        "E_IDENTITY_MISMATCH", "presented identity does not match parent lease"
                    )
                return Attestation(
                    "nested",
                    lease.principal_id,
                    lease.context_verified,
                    parent_lease_id=lease.lease_id,
                )
            try:
                process = self.process_resolver(pid)
            except OSError:
                process = None
            if process is None:
                return Attestation("unavailable", claimed_principal, False)
            chain.append(process)
            last = process
            below_broker = pid
            if pid == 1:
                break
            pid = process.ppid

        pane_root: ProcessInfo | None = None
        pane_handle: str | None = None
        for process in chain:
            try:
                handle = process.environment.get("ORCA_TERMINAL_HANDLE")
            except OSError:
                handle = None
            if handle:
                pane_root = process
                pane_handle = handle
        if pane_root is None or pane_handle is None:
            return Attestation(
                "unresolved",
                claimed_principal,
                False,
                evidence_executable=last.executable if last else None,
            )
        if pane_root.ppid == 1:
            return Attestation(
                "orphan",
                claimed_principal,
                False,
                pane_handle,
                evidence_executable=pane_root.executable,
            )
        attested_principal = self.handle_principals.get(pane_handle)
        if attested_principal is None:
            return Attestation(
                "unresolved", claimed_principal, False, pane_handle, evidence_executable=pane_root.executable
            )
        status = "match" if claimed_principal == attested_principal else "mismatch"
        return Attestation(
            status,
            claimed_principal,
            status == "match",
            pane_handle,
            attested_principal,
            evidence_executable=pane_root.executable,
        )


def _now_text() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _new_id(prefix: str) -> str:
    encoded = base64.b32encode(secrets.token_bytes(8)).decode("ascii").lower().rstrip("=")
    return prefix + encoded[:12]


TOKEN_CEILINGS = {
    "master": {"ceiling": "any:inject+audit", "max_class": "sensitive"},
    "lead": {"ceiling": "any:inject+put+audit", "max_class": "restricted"},
    "job": {"ceiling": "any:inject", "max_class": "sensitive"},
}


class IdentityStore:
    """SQLite-backed principals, grants, tokens, and pane bindings."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        home: str | os.PathLike[str],
        *,
        desk_notify: Callable[[str, str, str], object] | None = None,
    ):
        self.connection = connection
        self.home = os.path.realpath(os.path.expanduser(os.fspath(home)))
        self.desk_notify = desk_notify or (lambda _kind, _subject, _body: None)

    def roster_sync(
        self,
        roster: Mapping[str, object] | list[object],
        runs: Iterable[Mapping[str, object]],
    ) -> dict[str, object]:
        raw_entries: object
        if isinstance(roster, list):
            raw_entries = roster
        else:
            raw_entries = roster.get(
                "ai", roster.get("team", roster.get("members", roster.get("agents", [])))
            )
        if not isinstance(raw_entries, list):
            raise IdentityError("E_POLICY", "invalid roster")
        entries: dict[str, Mapping[str, object]] = {}
        for raw in raw_entries:
            if not isinstance(raw, Mapping):
                continue
            roster_id = str(raw.get("id", ""))
            role = raw.get("kind", raw.get("type"))
            if roster_id in {"shared", "infra"}:
                raise IdentityError("E_POLICY", "roster uses a reserved project id")
            if not roster_id or (roster_id != "master" and role not in {None, "ai"} and not raw.get("ai")):
                continue
            entries[roster_id] = raw

        run_rows = list(runs)
        run_by_id = {
            str(run.get("runId", run.get("run_id", run.get("id", "")))): run
            for run in run_rows
        }
        existing_rows = self.connection.execute(
            "SELECT principal_id FROM principals WHERE kind IN ('master','lead') AND state != 'disabled'"
        ).fetchall()
        existing = {str(row[0]) for row in existing_rows}
        desired = {"master" if key == "master" else f"lead:{key}" for key in entries}
        removed = sorted(existing - desired)
        if len(removed) > 3:
            names = ", ".join(removed)
            self.desk_notify(
                "ask",
                f"Roster sync would disable {len(removed)} principals",
                f"Names: {names}. Default: wait for you.",
            )
            return {"added": [], "updated": [], "disabled": [], "refused": removed}

        now = _now_text()
        added: list[str] = []
        updated: list[str] = []
        disabled: list[str] = []
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            for roster_id, entry in entries.items():
                principal_id = "master" if roster_id == "master" else f"lead:{roster_id}"
                kind = "master" if roster_id == "master" else "lead"
                project = None if roster_id == "master" else roster_id
                run_id = str(entry.get("run", entry.get("orca_run_id", ""))) or None
                run = run_by_id.get(run_id or "", {})
                handle = run.get(
                    "coordinatorTerminalHandle",
                    run.get("coordinator_handle", run.get("terminalHandle")),
                )
                roots = run.get("worktreeRoots", run.get("worktree_roots", [])) or []
                previous = self.connection.execute(
                    "SELECT 1 FROM principals WHERE principal_id=?", (principal_id,)
                ).fetchone()
                self.connection.execute(
                    "INSERT INTO principals(principal_id,kind,display,project,parent_id,orca_run_id,"
                    "coordinator_handle,desk_identity,worktree_roots_json,state,synced_at,created_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(principal_id) DO UPDATE SET "
                    "display=excluded.display,project=excluded.project,orca_run_id=excluded.orca_run_id,"
                    "coordinator_handle=excluded.coordinator_handle,desk_identity=excluded.desk_identity,"
                    "worktree_roots_json=excluded.worktree_roots_json,state=excluded.state,synced_at=excluded.synced_at",
                    (
                        principal_id,
                        kind,
                        str(entry.get("name", entry.get("display", roster_id))),
                        project,
                        None,
                        run_id,
                        handle,
                        "master" if roster_id == "master" else f"lead-{roster_id}",
                        json.dumps(roots, sort_keys=True, separators=(",", ":")),
                        "active" if handle else "unbound",
                        now,
                        now,
                    ),
                )
                if project:
                    policy = "client_approval_required" if project == "client" else "auto"
                    self.connection.execute(
                        "INSERT INTO projects(slug,lead_principal,change_policy,created_at) VALUES (?,?,?,?) "
                        "ON CONFLICT(slug) DO UPDATE SET lead_principal=excluded.lead_principal",
                        (project, principal_id, policy, now),
                    )
                (updated if previous else added).append(principal_id)
                if handle:
                    self._rewrite_binding(principal_id, str(handle), now)
            for principal_id in removed:
                self.connection.execute(
                    "UPDATE principals SET state='disabled',synced_at=? WHERE principal_id=?",
                    (now, principal_id),
                )
                self.connection.execute(
                    "UPDATE tokens SET revoked_at=?,revoked_reason='roster_parent_removed' "
                    "WHERE parent_token_id IN (SELECT token_id FROM tokens WHERE principal_id=?) "
                    "AND revoked_at IS NULL",
                    (now, principal_id),
                )
                self.connection.execute(
                    "UPDATE tokens SET revoked_at=?,revoked_reason='roster_removed' "
                    "WHERE principal_id=? AND revoked_at IS NULL",
                    (now, principal_id),
                )
                self.connection.execute(
                    "UPDATE pane_bindings SET revoked_at=? WHERE principal_id=? AND revoked_at IS NULL",
                    (now, principal_id),
                )
                self.connection.execute(
                    "UPDATE pane_bindings SET revoked_at=? WHERE token_id IN "
                    "(SELECT token_id FROM tokens WHERE parent_token_id IN "
                    "(SELECT token_id FROM tokens WHERE principal_id=?)) AND revoked_at IS NULL",
                    (now, principal_id),
                )
                disabled.append(principal_id)
            self.connection.commit()
        except BaseException:
            self.connection.rollback()
            raise

        known_run_ids = {
            str(entry.get("run", entry.get("orca_run_id", ""))) for entry in entries.values()
        }
        for run in run_rows:
            run_id = str(run.get("runId", run.get("run_id", run.get("id", ""))))
            name = str(run.get("name", ""))
            coordinator = run.get("coordinatorTerminalHandle", run.get("coordinator_handle"))
            if run_id not in known_run_ids and ("lead" in name.lower() or coordinator):
                self.desk_notify(
                    "info",
                    "Unrostered Orca run",
                    f"{name or run_id}: no Titanwarden principal until added to team.json",
                )
        return {"added": added, "updated": updated, "disabled": disabled, "refused": []}

    def _rewrite_binding(self, principal_id: str, handle: str, now: str) -> None:
        token = self.connection.execute(
            "SELECT token_id FROM tokens WHERE principal_id=? AND revoked_at IS NULL "
            "ORDER BY created_at DESC LIMIT 1",
            (principal_id,),
        ).fetchone()
        if token is None:
            return
        self.connection.execute(
            "UPDATE pane_bindings SET revoked_at=? WHERE principal_id=? AND revoked_at IS NULL",
            (now, principal_id),
        )
        self.connection.execute(
            "INSERT INTO pane_bindings(handle,token_id,principal_id,created_at,created_by,revoked_at) "
            "VALUES (?,?,?,?,?,NULL) ON CONFLICT(handle) DO UPDATE SET token_id=excluded.token_id,"
            "principal_id=excluded.principal_id,created_at=excluded.created_at,"
            "created_by=excluded.created_by,revoked_at=NULL",
            (handle, token[0], principal_id, now, "system:roster"),
        )
        self._write_binding_file(handle, str(token[0]))

    def issue_token(
        self,
        principal_id: str,
        kind: str,
        *,
        created_by: str,
        handle: str | None = None,
        ceiling: Scope | None = None,
        max_class: str | None = None,
        parent_token_id: str | None = None,
        hard_expires_at: str | None = None,
    ) -> dict[str, object]:
        if kind not in {"master", "lead", "job", "task"}:
            raise IdentityError("E_SCOPE", "invalid token kind")
        principal = self.connection.execute(
            "SELECT project FROM principals WHERE principal_id=? AND state != 'disabled'",
            (principal_id,),
        ).fetchone()
        if principal is None:
            raise IdentityError("E_AUTH", "principal is not active")
        if kind == "task":
            if ceiling is None or parent_token_id is None:
                raise IdentityError("E_SCOPE", "task token requires parent and scope")
            ceiling_text = _scope_text(ceiling)
            ceiling_data = {"ceiling": ceiling_text, "max_class": max_class or "sensitive"}
        else:
            ceiling_data = dict(TOKEN_CEILINGS[kind])
            if max_class:
                ceiling_data["max_class"] = max_class
        token_id = _new_id("tok_")
        token = "twt_" + token_id + "_" + base64.urlsafe_b64encode(
            secrets.token_bytes(32)
        ).decode("ascii").rstrip("=")
        tokens_dir = os.path.join(self.home, "tokens")
        os.makedirs(tokens_dir, mode=0o700, exist_ok=True)
        os.chmod(tokens_dir, 0o700)
        token_path = os.path.join(tokens_dir, token_id + ".token")
        fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, token.encode("ascii") + b"\n")
            os.fsync(fd)
        finally:
            os.close(fd)
        now = _now_text()
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            self.connection.execute(
                "INSERT INTO tokens(token_id,principal_id,kind,token_hash,parent_token_id,scope_json,"
                "file_path,idle_expiry_days,hard_expires_at,created_at,created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    token_id,
                    principal_id,
                    kind,
                    hashlib.sha256(token.encode("ascii")).digest(),
                    parent_token_id,
                    json.dumps(ceiling_data, sort_keys=True, separators=(",", ":")),
                    token_path,
                    None if kind == "task" else 90,
                    hard_expires_at,
                    now,
                    created_by,
                ),
            )
            self._ensure_default_grants(principal_id, kind, principal[0], now)
            if handle:
                self.connection.execute(
                    "UPDATE pane_bindings SET revoked_at=? WHERE handle=? AND revoked_at IS NULL",
                    (now, handle),
                )
                self.connection.execute(
                    "INSERT INTO pane_bindings(handle,token_id,principal_id,created_at,created_by) "
                    "VALUES (?,?,?,?,?) ON CONFLICT(handle) DO UPDATE SET token_id=excluded.token_id,"
                    "principal_id=excluded.principal_id,created_at=excluded.created_at,"
                    "created_by=excluded.created_by,revoked_at=NULL",
                    (handle, token_id, principal_id, now, created_by),
                )
            self.connection.commit()
        except BaseException:
            self.connection.rollback()
            os.unlink(token_path)
            raise
        if handle:
            self._write_binding_file(handle, token_id)
        return {"token_id": token_id, "file_path": token_path, "bound_handle": handle}

    def _ensure_default_grants(self, principal_id: str, kind: str, project: object, now: str) -> None:
        if self.connection.execute("SELECT 1 FROM meta WHERE key='cloud_connection'").fetchone():
            return
        defaults: list[tuple[str, str, str]] = []
        if kind == "lead" and project:
            defaults.append((str(project) + "/*", "inject+put+audit", "sensitive"))
        elif kind == "master":
            defaults.append(("infra/*", "inject", "sensitive"))
        for pattern, ops, maximum in defaults:
            exists = self.connection.execute(
                "SELECT 1 FROM grants WHERE principal_id=? AND pattern=? AND ops=? "
                "AND granted_by='system:default'",
                (principal_id, pattern, ops),
            ).fetchone()
            if exists is None:
                self.connection.execute(
                    "INSERT INTO grants(grant_id,principal_id,pattern,ops,conditions_json,effect,"
                    "granted_by,reason,created_at) VALUES (?,?,?,?,?,'allow','system:default',?,?)",
                    (
                        _new_id("grt_"),
                        principal_id,
                        pattern,
                        ops,
                        json.dumps({"max_class": maximum}, separators=(",", ":")),
                        "default grant",
                        now,
                    ),
                )

    def _write_binding_file(self, handle: str, token_id: str) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_-]+", handle):
            raise IdentityError("E_POLICY", "invalid pane handle")
        token = self.connection.execute(
            "SELECT file_path FROM tokens WHERE token_id=?", (token_id,)
        ).fetchone()
        if token is None:
            raise IdentityError("E_AUTH", "token not found")
        panes_dir = os.path.join(self.home, "panes")
        os.makedirs(panes_dir, mode=0o700, exist_ok=True)
        os.chmod(panes_dir, 0o700)
        path = os.path.join(panes_dir, handle)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, os.fspath(token[0]).encode("utf-8") + b"\n")
        finally:
            os.close(fd)

    def permission_for_token(self, token_id: str) -> tuple[PermissionSet, Scope | None]:
        token = self.connection.execute(
            "SELECT principal_id,kind,parent_token_id,scope_json,revoked_at,hard_expires_at "
            "FROM tokens WHERE token_id=?",
            (token_id,),
        ).fetchone()
        if token is None or token[4] is not None:
            raise IdentityError("E_AUTH", "token is not active")
        if token[5] and str(token[5]) <= _now_text():
            raise IdentityError("E_AUTH", "token is not active")
        idle = self.connection.execute(
            "SELECT idle_expiry_days,last_used_at,created_at FROM tokens WHERE token_id=?",
            (token_id,),
        ).fetchone()
        if idle and idle[0] is not None:
            baseline = datetime.fromisoformat(str(idle[1] or idle[2]).replace("Z", "+00:00"))
            if baseline + timedelta(days=int(idle[0])) <= datetime.now(timezone.utc):
                raise IdentityError("E_AUTH", "token is not active")
        data = json.loads(token[3])
        provider = getattr(self, 'grant_provider', None)
        if provider is None and self.connection.execute("SELECT 1 FROM meta WHERE key='cloud_connection'").fetchone():
            raise IdentityError('E_POLICY','cloud permission provider unavailable')
        cloud_grants = None if provider is None else provider(str(token[0]))
        own_ceiling = Scope.parse(data["ceiling"], allow_any=True,allow_nested=cloud_grants is not None)
        if cloud_grants is not None:
            principal = self.connection.execute('SELECT state FROM principals WHERE principal_id=?',(token[0],)).fetchone()
            if principal is None or principal[0] != 'active':
                raise IdentityError('E_AUTH','principal is not active')
        if token[1] == "task":
            parent = self.permission_for_token(str(token[2]))[0]
            return parent, own_ceiling
        grants = []
        if cloud_grants is not None:
            for grant in cloud_grants:
                grants.append(Grant(Scope.parse('+'.join(grant['ops'])+':'+grant['pattern'],allow_nested=True),
                    grant['max_class'],'allow',None if grant['expires_at'] is None else datetime.fromisoformat(grant['expires_at'].replace('Z','+00:00')),False))
            return PermissionSet(own_ceiling,str(data['max_class']),grants),None
        rows = self.connection.execute(
            "SELECT pattern,ops,conditions_json,effect,expires_at,revoked_at FROM grants "
            "WHERE principal_id=?",
            (token[0],),
        )
        for row in rows:
            conditions = json.loads(row[2])
            expires = (
                datetime.fromisoformat(str(row[4]).replace("Z", "+00:00")) if row[4] else None
            )
            grants.append(
                Grant(
                    Scope.parse(f"{row[1]}:{row[0]}"),
                    str(conditions.get("max_class", data["max_class"])),
                    str(row[3]),
                    expires,
                    row[5] is not None,
                )
            )
        return PermissionSet(own_ceiling, str(data["max_class"]), grants), None

    def issue_task_token(
        self,
        parent_token_id: str,
        dispatch_id: str,
        worker_handle: str,
        scope_text: str,
        hard_expires_at: str,
    ) -> dict[str, object]:
        parent = self.connection.execute(
            "SELECT principal_id,scope_json FROM tokens WHERE token_id=? AND kind='lead' "
            "AND revoked_at IS NULL",
            (parent_token_id,),
        ).fetchone()
        if parent is None:
            raise IdentityError("E_AUTH", "parent token is not active")
        cloud_mode=self.connection.execute("SELECT 1 FROM meta WHERE key='cloud_connection'").fetchone() is not None
        requested = Scope.parse(scope_text,allow_nested=cloud_mode)
        permission, _task = self.permission_for_token(parent_token_id)
        permission.require_subset(requested)
        lead_id = str(parent[0]).removeprefix("lead:")
        principal_id = f"worker:{lead_id}/{dispatch_id}"
        now = _now_text()
        self.connection.execute(
            "INSERT INTO principals(principal_id,kind,project,parent_id,dispatch_id,worker_handle,"
            "worktree_roots_json,state,created_at) VALUES (?,?,?,?,?,?,?,'active',?) "
            "ON CONFLICT(principal_id) DO UPDATE SET worker_handle=excluded.worker_handle,state='active'",
            (principal_id, "worker", lead_id, parent[0], dispatch_id, worker_handle, "[]", now),
        )
        self.connection.commit()
        maximum = json.loads(parent[1])["max_class"]
        return self.issue_token(
            principal_id,
            "task",
            created_by=str(parent[0]),
            handle=worker_handle,
            ceiling=requested,
            max_class=maximum,
            parent_token_id=parent_token_id,
            hard_expires_at=hard_expires_at,
        )

    def revoke_token(self, token_id: str, reason: str) -> None:
        now = _now_text()
        self.connection.execute(
            "UPDATE tokens SET revoked_at=?,revoked_reason=? WHERE token_id=? AND revoked_at IS NULL",
            (now, reason, token_id),
        )
        self.connection.execute(
            "UPDATE tokens SET revoked_at=?,revoked_reason='parent_revoked' "
            "WHERE parent_token_id=? AND revoked_at IS NULL",
            (now, token_id),
        )


def _scope_text(scope: Scope) -> str:
    parts = []
    for entry in scope.entries:
        if entry.is_any:
            parts.append("any:" + "+".join(sorted(entry.operations)))
            continue
        part = "+".join(sorted(entry.operations)) + ":" + str(entry.project) + "/" + str(entry.name)
        if entry.hosts:
            part += "@" + "|".join(sorted(entry.hosts))
        parts.append(part)
    return ",".join(parts)


WANTED_ENVIRONMENT = {"ORCA_TERMINAL_HANDLE", "XPC_SERVICE_NAME"}


def system_process_resolver(pid: int) -> ProcessInfo | None:
    """Read process ancestry and selected exec-time environment (macOS or Linux)."""

    if pid <= 0:
        return None
    if sys.platform == "linux":
        return _linux_process_info(pid)
    if sys.platform != "darwin":
        return None
    try:
        completed = subprocess.run(
            ["/bin/ps", "-o", "ppid=", "-p", str(pid)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=2,
        )
        if completed.returncode != 0 or not completed.stdout.strip():
            return None
        ppid = int(completed.stdout.strip())
        executable = _macos_executable(pid)
        environment = _LazySelectedEnvironment(pid)
        return ProcessInfo(pid, ppid, environment, executable)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


class _LazySelectedEnvironment(Mapping[str, str]):
    def __init__(self, pid: int, loader=None):
        self.pid = pid
        self._loader = loader or (lambda: _macos_environment(pid))
        self._values: dict[str, str] | None = None

    def _load(self) -> dict[str, str]:
        if self._values is None:
            self._values = self._loader()
        return self._values

    def __getitem__(self, key: str) -> str:
        return self._load()[key]

    def __iter__(self):
        return iter(self._load())

    def __len__(self) -> int:
        return len(self._load())


def _linux_process_info(pid: int, proc: Path = Path("/proc")) -> ProcessInfo | None:
    entry = proc / str(pid)
    try:
        stat = (entry / "stat").read_text()
        # "pid (comm) state ppid ..."; comm may contain spaces, so split after the last ")".
        ppid = int(stat[stat.rindex(")") + 1:].split()[1])
        executable = os.readlink(entry / "exe")
    except (OSError, ValueError, IndexError):
        return None
    environment = _LazySelectedEnvironment(pid, lambda: _linux_environment(entry / "environ"))
    return ProcessInfo(pid, ppid, environment, executable)


def _linux_environment(path: Path) -> dict[str, str]:
    environment: dict[str, str] = {}
    for entry in path.read_bytes().split(b"\0"):
        key, separator, value = entry.partition(b"=")
        decoded_key = key.decode("utf-8", "replace")
        if separator and decoded_key in WANTED_ENVIRONMENT:
            environment[decoded_key] = value.decode("utf-8", "replace")
    return environment


def _macos_executable(pid: int) -> str:
    import ctypes

    libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    buffer = ctypes.create_string_buffer(4096)
    length = libproc.proc_pidpath(pid, buffer, len(buffer))
    if length <= 0:
        raise OSError(ctypes.get_errno(), "proc_pidpath failed")
    return buffer.value.decode("utf-8", "replace")


def _macos_environment(pid: int) -> dict[str, str]:
    import ctypes
    import struct

    libc = ctypes.CDLL(None, use_errno=True)
    mib = (ctypes.c_int * 3)(1, 49, pid)  # CTL_KERN, KERN_PROCARGS2, pid
    size = ctypes.c_size_t()
    if libc.sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0:
        raise OSError(ctypes.get_errno(), "sysctl size failed")
    buffer = ctypes.create_string_buffer(size.value)
    if libc.sysctl(mib, 3, buffer, ctypes.byref(size), None, 0) != 0:
        raise OSError(ctypes.get_errno(), "sysctl process args failed")
    payload = bytes(buffer.raw[: size.value])
    if len(payload) < 4:
        raise OSError("short process args")
    argc = struct.unpack_from("=i", payload)[0]
    position = 4

    def next_string() -> bytes:
        nonlocal position
        end = payload.find(b"\x00", position)
        if end < 0:
            end = len(payload)
        value = payload[position:end]
        position = min(end + 1, len(payload))
        return value

    next_string()
    while position < len(payload) and payload[position] == 0:
        position += 1
    for _ in range(max(argc, 0)):
        next_string()
    environment: dict[str, str] = {}
    wanted = WANTED_ENVIRONMENT
    while position < len(payload):
        entry = next_string()
        if not entry:
            continue
        key, separator, value = entry.partition(b"=")
        decoded_key = key.decode("utf-8", "replace")
        if separator and decoded_key in wanted:
            environment[decoded_key] = value.decode("utf-8", "replace")
    return environment
