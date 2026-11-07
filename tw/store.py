"""SQLite persistence and envelope-store operations."""

from __future__ import annotations

import json
import base64
import os
import secrets
import sqlite3
import stat
import threading
from collections.abc import Iterable, Iterator, Mapping
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from . import crypto


SCHEMA_VERSION: Final = 1


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def canonical_text(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class StoreError(RuntimeError):
    pass


class CloudPublicationConflict(StoreError):
    """Verified publication disagrees with a locally retained signed write."""


class Store:
    def __init__(
        self,
        home: str | os.PathLike[str],
        *,
        backup_allowlist: Iterable[str | os.PathLike[str]] = (),
    ) -> None:
        self.home = Path(home).expanduser().resolve()
        self.state_dir = self.home / "state"
        self.db_path = self.state_dir / "tw.db"
        self._connection: sqlite3.Connection | None = None
        # v0 ceiling: one process-wide connection shared by socket threads.
        # Every explicit transaction holds this lock from BEGIN through commit.
        self._transaction_lock = threading.RLock()
        self.backup_roots = (self.home / "backups",) + tuple(
            Path(path).expanduser().resolve() for path in backup_allowlist
        )

    @staticmethod
    def secure_process_umask() -> int:
        """Set the broker's file-creation mask and return the previous value."""

        return os.umask(0o077)

    @property
    def connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise StoreError("store is not open")
        return self._connection

    def open(self, *, create: bool = False, refuse_create: bool = False) -> Store:
        if create and refuse_create and not self.db_path.exists():
            raise StoreError("refusing to create a store in an existing home")
        if create:
            self.home.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(self.home, 0o700)
            os.chmod(self.state_dir, 0o700)
        elif not self.db_path.exists():
            raise StoreError("store is not initialized")
        is_new = create and not self.db_path.exists()
        connection = sqlite3.connect(
            self.db_path, timeout=5, isolation_level=None, check_same_thread=False
        )
        if is_new:
            # ponytail: a tombstone that outlives tw.db; its presence without tw.db means a store was deleted
            tombstone = self.state_dir / ".store-created"
            tombstone.touch(mode=0o600, exist_ok=True)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA busy_timeout = 5000")
        self._connection = connection
        if create and not self._has_schema():
            schema = Path(__file__).with_name("schema.sql").read_text(encoding="utf-8")
            connection.executescript(schema)
        if self.db_path.exists():
            os.chmod(self.db_path, stat.S_IRUSR | stat.S_IWUSR)
        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{self.db_path}{suffix}")
            if sidecar.exists():
                os.chmod(sidecar, stat.S_IRUSR | stat.S_IWUSR)
        return self

    def close(self) -> None:
        with self._transaction_lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _has_schema(self) -> bool:
        row = self.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'"
        ).fetchone()
        return row is not None

    @contextmanager
    def transaction(self, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        with self._transaction_lock:
            connection = self.connection
            connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            try:
                yield connection
            except BaseException:
                connection.rollback()
                raise
            else:
                connection.commit()

    def meta(self, key: str) -> str | None:
        with self._transaction_lock:
            row = self.connection.execute(
                "SELECT value FROM meta WHERE key = ?", (key,)
            ).fetchone()
        return None if row is None else str(row["value"])

    def set_meta(self, key: str, value: str) -> None:
        with self._transaction_lock:
            self.connection.execute(
                "INSERT INTO meta(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def initialize(
        self,
        passphrase: str,
        *,
        argon2: crypto.Argon2Params | None = None,
        cloud_broker: bool = False,
    ) -> tuple[bytes, str]:
        if self.meta("store_id") is not None:
            raise StoreError("store is already initialized")
        if cloud_broker and any(self.connection.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone()
                                for table in ("secrets", "principals", "grants")):
            raise StoreError("cloud broker initialization requires an empty store")
        if len(passphrase) < crypto.MIN_PASSPHRASE_LENGTH:
            raise ValueError("passphrase must be at least 30 characters")
        now = utc_now()
        store_id = os.urandom(16).hex()
        generation = 1
        master_key = crypto.random_key()
        recovery = None if cloud_broker else crypto.recovery_key()
        params = argon2 or crypto.Argon2Params()
        pass_salt = os.urandom(crypto.SALT_BYTES)
        pass_key = crypto.derive_passphrase_key(passphrase, pass_salt, params)
        pass_slot = "slot_passphrase"
        recovery_slot = "slot_recovery"
        pass_wrapped, pass_nonce = crypto.wrap_key(
            pass_key, master_key, crypto.slot_aad(store_id, pass_slot, generation)
        )
        if recovery is not None:
            recovery_wrapped, recovery_nonce = crypto.wrap_key(
                crypto.derive_recovery_slot_key(recovery), master_key,
                crypto.slot_aad(store_id, recovery_slot, generation),
            )
        key_rows: list[tuple[object, ...]] = []
        for purpose in ("kek", "audit_mac", "fingerprint"):
            key_id = f"key_{purpose}_1"
            key = crypto.random_key()
            wrapped, nonce = crypto.wrap_key(
                master_key,
                key,
                crypto.keyring_aad(store_id, key_id, purpose, generation),
            )
            key_rows.append(
                (key_id, purpose, 1, wrapped, nonce, generation, 0, "active", now)
            )
        with self.transaction(immediate=True) as connection:
            for key, value in {
                "store_id": store_id,
                "schema_version": str(SCHEMA_VERSION),
                "mk_generation": str(generation),
                "created_at": now,
                "seal_policy": "passphrase",
                **({"cloud_broker": "1"} if cloud_broker else {}),
            }.items():
                connection.execute("INSERT INTO meta(key, value) VALUES (?, ?)", (key, value))
            connection.execute(
                "INSERT INTO slots VALUES (?, 'passphrase', ?, ?, ?, ?, ?, NULL, NULL)",
                (
                    pass_slot,
                    canonical_text(params.as_dict(pass_salt)),
                    pass_wrapped,
                    pass_nonce,
                    generation,
                    now,
                ),
            )
            if recovery is not None:
                connection.execute(
                    "INSERT INTO slots VALUES (?, 'recovery', '{}', ?, ?, ?, ?, NULL, NULL)",
                    (recovery_slot, recovery_wrapped, recovery_nonce, generation, now),
                )
            connection.executemany(
                "INSERT INTO keyring(key_id,purpose,version,wrapped_key,nonce,mk_generation,"
                "wrap_count,state,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                key_rows,
            )
            connection.executemany(
                "INSERT INTO projects(slug,change_policy,no_shell,created_at) VALUES (?,?,0,?)",
                (("infra", "auto", now), ("shared", "auto", now)),
            )
            connection.executemany(
                "INSERT INTO principals(principal_id,kind,display,state,created_at) "
                "VALUES (?,?,?,?,?)",
                (
                    ("human:operator", "human", "Operator", "active", now),
                    ("master", "master", "Master", "unbound", now),
                ),
            )
        return master_key, "" if recovery is None else crypto.encode_recovery_key(recovery)

    def unlock_passphrase(self, passphrase: str) -> bytes:
        row = self.connection.execute(
            "SELECT * FROM slots WHERE kind='passphrase' AND disabled_at IS NULL "
            "ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        if row is None:
            raise StoreError("no active passphrase slot")
        params, salt = crypto.Argon2Params.from_dict(json.loads(row["params_json"]))
        key = crypto.derive_passphrase_key(
            passphrase, salt, params, enforce_strength=False
        )
        return self._unwrap_slot(row, key)

    def unlock_recovery(self, recovery: str) -> bytes:
        row = self.connection.execute(
            "SELECT * FROM slots WHERE kind='recovery' AND disabled_at IS NULL "
            "ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        if row is None:
            raise StoreError("no active recovery slot")
        key = crypto.derive_recovery_slot_key(crypto.decode_recovery_key(recovery))
        return self._unwrap_slot(row, key)

    def _unwrap_slot(self, row: sqlite3.Row, slot_key: bytes) -> bytes:
        store_id = self.meta("store_id")
        if store_id is None:
            raise StoreError("store metadata is missing")
        return crypto.unwrap_key(
            slot_key,
            row["wrapped_mk"],
            row["nonce"],
            crypto.slot_aad(store_id, row["slot_id"], row["mk_generation"]),
        )

    def load_keyring(self, master_key: bytes) -> dict[str, tuple[str, bytes]]:
        result = {
            purpose: self.load_key(master_key, purpose)
            for purpose in ("kek", "audit_mac", "fingerprint")
        }
        return result

    def load_key(self, master_key: bytes, purpose: str) -> tuple[str, bytes]:
        store_id = self.meta("store_id")
        if store_id is None:
            raise StoreError("store metadata is missing")
        row = self.connection.execute(
            "SELECT * FROM keyring WHERE purpose=? AND state='active'", (purpose,)
        ).fetchone()
        if row is None:
            raise StoreError(f"active {purpose} key is missing")
        key = crypto.unwrap_key(
            master_key,
            row["wrapped_key"],
            row["nonce"],
            crypto.keyring_aad(
                store_id,
                row["key_id"],
                row["purpose"],
                row["mk_generation"],
            ),
        )
        return str(row["key_id"]), key

    @staticmethod
    def new_id(prefix: str) -> str:
        value = base64.b32encode(secrets.token_bytes(8)).decode("ascii").lower().rstrip("=")
        return f"{prefix}{value[:12]}"

    def put_secret(
        self,
        path: str,
        value: bytes,
        *,
        keyring: Mapping[str, tuple[str, bytes]],
        principal_id: str,
        secret_class: str = "sensitive",
        kind: str = "opaque",
        note: str | None = None,
        source: str = "console",
        grace_hours: int = 24,
    ) -> dict[str, Any]:
        project, separator, name = path.partition("/")
        if not separator or not project or not name or "/" in name:
            raise StoreError("secret path must be project/name")
        if secret_class not in {"standard", "sensitive", "restricted"}:
            raise StoreError("invalid secret class")
        if len(value) == 0:
            raise StoreError("secret value cannot be empty")
        project_row = self.connection.execute(
            "SELECT slug,change_policy FROM projects WHERE slug=?", (project,)
        ).fetchone()
        if project_row is None:
            raise StoreError("project does not exist")
        if project == "client" or project_row["change_policy"] == "client_approval_required":
            secret_class = "restricted"
        now = utc_now()
        store_id = self.meta("store_id")
        if store_id is None:
            raise StoreError("store metadata is missing")
        with self.transaction(immediate=True) as connection:
            secret = connection.execute("SELECT * FROM secrets WHERE path=?", (path,)).fetchone()
            if secret is None:
                secret_id = self.new_id("sec_")
                connection.execute(
                    "INSERT INTO secrets(secret_id,path,project,class,kind,short,note,created_at,created_by) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        secret_id,
                        path,
                        project,
                        secret_class,
                        kind,
                        int(len(value) < 8),
                        note,
                        now,
                        principal_id,
                    ),
                )
                version_no = 1
            else:
                secret_id = str(secret["secret_id"])
                if str(secret["class"]) != secret_class:
                    raise StoreError("secret class cannot be changed by put")
                row = connection.execute(
                    "SELECT COALESCE(MAX(version_no),0)+1 next_version FROM secret_versions "
                    "WHERE secret_id=?",
                    (secret_id,),
                ).fetchone()
                version_no = int(row["next_version"])
                grace_until = datetime.fromtimestamp(
                    datetime.now(UTC).timestamp() + grace_hours * 3600, UTC
                ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                connection.execute(
                    "UPDATE secret_versions SET state='grace',grace_until=? "
                    "WHERE secret_id=? AND state='active'",
                    (grace_until, secret_id),
                )
            version_id = self.new_id("ver_")
            dek = crypto.random_key()
            ciphertext, nonce = crypto.encrypt(
                dek, value, crypto.value_aad(store_id, secret_id, version_no)
            )
            kek_id, kek = keyring["kek"]
            wrapped_dek, dek_nonce = crypto.wrap_key(
                kek, dek, crypto.dek_aad(store_id, version_id, kek_id)
            )
            fingerprint_key = keyring["fingerprint"][1]
            connection.execute(
                "INSERT INTO secret_versions(version_id,secret_id,version_no,state,ciphertext,"
                "nonce,wrapped_dek,dek_nonce,kek_id,fingerprint,length,source,created_at,created_by,"
                "activated_at) VALUES (?,?,?,'active',?,?,?,?,?,?,?,?,?,?,?)",
                (
                    version_id,
                    secret_id,
                    version_no,
                    ciphertext,
                    nonce,
                    wrapped_dek,
                    dek_nonce,
                    kek_id,
                    crypto.fingerprint(fingerprint_key, value),
                    len(value),
                    source,
                    now,
                    principal_id,
                    now,
                ),
            )
            connection.execute(
                "UPDATE keyring SET wrap_count=wrap_count+1 WHERE key_id=? AND state='active'",
                (kek_id,),
            )
        return {
            "path": path,
            "version_no": version_no,
            "fingerprint_prefix": crypto.fingerprint(fingerprint_key, value).hex()[:4],
        }

    def reveal_secret(
        self,
        path: str,
        *,
        keyring: Mapping[str, tuple[str, bytes]],
        version_no: int | None = None,
    ) -> bytes:
        store_id = self.meta("store_id")
        if store_id is None:
            raise StoreError("store metadata is missing")
        params: list[object] = [path]
        clause = "v.state='active'"
        if version_no is not None:
            clause = "v.version_no=?"
            params.append(version_no)
        row = self.connection.execute(
            "SELECT s.secret_id,v.* FROM secrets s JOIN secret_versions v "
            f"ON v.secret_id=s.secret_id WHERE s.path=? AND {clause} "
            "ORDER BY v.version_no DESC LIMIT 1",
            tuple(params),
        ).fetchone()
        if row is None:
            raise StoreError("secret not found")
        kek_id, kek = keyring["kek"]
        if row["kek_id"] != kek_id:
            raise StoreError("required KEK is not active")
        dek = crypto.unwrap_key(
            kek,
            row["wrapped_dek"],
            row["dek_nonce"],
            crypto.dek_aad(store_id, row["version_id"], row["kek_id"]),
        )
        return crypto.decrypt(
            dek,
            row["ciphertext"],
            row["nonce"],
            crypto.value_aad(store_id, row["secret_id"], row["version_no"]),
        )

    def active_plaintexts(
        self, *, keyring: Mapping[str, tuple[str, bytes]]
    ) -> list[tuple[str, bytes]]:
        """Return active and grace values for the in-memory broker scrubber."""

        store_id = self.meta("store_id")
        if store_id is None:
            raise StoreError("store metadata is missing")
        kek_id, kek = keyring["kek"]
        rows = self.connection.execute(
            "SELECT s.path,s.secret_id,v.* FROM secrets s JOIN secret_versions v "
            "ON v.secret_id=s.secret_id WHERE v.state IN ('active','grace')"
        )
        result: list[tuple[str, bytes]] = []
        for row in rows:
            if row["kek_id"] != kek_id:
                raise StoreError("required KEK is not active")
            dek = crypto.unwrap_key(
                kek,
                row["wrapped_dek"],
                row["dek_nonce"],
                crypto.dek_aad(store_id, row["version_id"], row["kek_id"]),
            )
            value = crypto.decrypt(
                dek,
                row["ciphertext"],
                row["nonce"],
                crypto.value_aad(store_id, row["secret_id"], row["version_no"]),
            )
            result.append((str(row["path"]), value))
        return result

    def change_passphrase(
        self,
        master_key: bytes,
        new_passphrase: str,
        *,
        argon2: crypto.Argon2Params | None = None,
    ) -> None:
        if len(new_passphrase) < crypto.MIN_PASSPHRASE_LENGTH:
            raise ValueError("passphrase must be at least 30 characters")
        store_id = self.meta("store_id")
        generation_text = self.meta("mk_generation")
        if store_id is None or generation_text is None:
            raise StoreError("store metadata is missing")
        generation = int(generation_text)
        params = argon2 or crypto.Argon2Params()
        salt = os.urandom(crypto.SALT_BYTES)
        slot_key = crypto.derive_passphrase_key(new_passphrase, salt, params)
        slot_id = self.new_id("slot_")
        wrapped, nonce = crypto.wrap_key(
            slot_key, master_key, crypto.slot_aad(store_id, slot_id, generation)
        )
        now = utc_now()
        with self.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE slots SET disabled_at=?,disabled_reason='passphrase changed' "
                "WHERE kind='passphrase' AND disabled_at IS NULL",
                (now,),
            )
            connection.execute(
                "INSERT INTO slots VALUES (?,'passphrase',?,?,?,?,?,NULL,NULL)",
                (slot_id, canonical_text(params.as_dict(salt)), wrapped, nonce, generation, now),
            )

    def rotate_recovery(self, master_key: bytes) -> str:
        store_id = self.meta("store_id")
        generation_text = self.meta("mk_generation")
        if store_id is None or generation_text is None:
            raise StoreError("store metadata is missing")
        generation = int(generation_text)
        raw = crypto.recovery_key()
        slot_key = crypto.derive_recovery_slot_key(raw)
        slot_id = self.new_id("slot_")
        wrapped, nonce = crypto.wrap_key(
            slot_key, master_key, crypto.slot_aad(store_id, slot_id, generation)
        )
        now = utc_now()
        with self.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE slots SET disabled_at=?,disabled_reason='recovery rotated' "
                "WHERE kind='recovery' AND disabled_at IS NULL",
                (now,),
            )
            connection.execute(
                "INSERT INTO slots VALUES (?,'recovery','{}',?,?,?,?,NULL,NULL)",
                (slot_id, wrapped, nonce, generation, now),
            )
        return crypto.encode_recovery_key(raw)

    def receipt(
        self,
        request_id: str,
        *,
        op: str | None = None,
        principal_id: str | None = None,
    ) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT op,principal_id,response_json FROM receipts WHERE request_id=?",
            (request_id,),
        ).fetchone()
        if row is None:
            return None
        if (op is not None and row["op"] != op) or (
            principal_id is not None and row["principal_id"] != principal_id
        ):
            raise StoreError("request_id was already used for another operation")
        return json.loads(row["response_json"])

    def save_receipt(
        self, request_id: str, op: str, principal_id: str, response: Mapping[str, Any]
    ) -> None:
        self.connection.execute(
            "INSERT INTO receipts(request_id,op,principal_id,response_json,created_at) "
            "VALUES (?,?,?,?,?)",
            (request_id, op, principal_id, canonical_text(response), utc_now()),
        )

    def initialize_cloud_replay(self, org_id: str, pinned_root: str) -> None:
        """Explicit offline opt-in with an independently supplied immutable pin.

        Opening an existing local store never calls this migration. Execute each
        complete statement inside our transaction; executescript would commit a
        caller's pending transaction before applying this additive schema.
        """
        from .cloud_wire import org_id as checked_org, digest

        checked_org(org_id)
        digest(pinned_root)
        cloud_schema = Path(__file__).with_name("cloud_schema.sql").read_text(encoding="utf-8")
        with self.transaction(immediate=True) as db:
            statement = ""
            for line in cloud_schema.splitlines(keepends=True):
                statement += line
                if sqlite3.complete_statement(statement):
                    db.execute(statement)
                    statement = ""
            if statement.strip():
                raise StoreError("incomplete cloud replay schema")
            prior = db.execute("SELECT root_hash FROM cloud_pins WHERE org_id=?", (org_id,)).fetchone()
            if prior is not None and prior["root_hash"] != pinned_root:
                raise StoreError("independent cloud root pin differs")
            if prior is None:
                db.execute("INSERT INTO cloud_pins(org_id,root_hash) VALUES (?,?)", (org_id, pinned_root))

    def cloud_pin(self, org_id: str) -> str | None:
        with self._transaction_lock:
            if self.connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='cloud_pins'").fetchone() is None:
                return None
            row = self.connection.execute("SELECT root_hash FROM cloud_pins WHERE org_id=?", (org_id,)).fetchone()
            return None if row is None else row["root_hash"]

    def initialize_cloud_sync(self) -> None:
        """Separate explicit opt-in; offline replay keeps its original six tables."""
        schema = (Path(__file__).with_name('cloud_sync.sql').read_text(encoding='utf-8')
            + '\n' + Path(__file__).with_name('cloud_runtime.sql').read_text(encoding='utf-8'))
        with self.transaction(immediate=True) as db:
            statement = ''
            for line in schema.splitlines(keepends=True):
                statement += line
                if sqlite3.complete_statement(statement):
                    db.execute(statement)
                    statement = ''
            if statement.strip():
                raise StoreError('incomplete cloud sync schema')

    def save_cloud_replay(self, verifier, epoch_state=None, *, expected_head=None,
                          sync_blobs=None, observed_at=None, sync_broker=None) -> None:
        """Persist a completed independent verifier, never a cloud snapshot.

        Local evidence lives in separate append-only tables and is never rebuilt
        from authority snapshots. Head comparison serializes competing imports.
        """
        from .cloud_wire import parse_head, org_id as checked_org
        from .policy_log import OfflineCloudVerifier, PolicyError

        if isinstance(verifier, OfflineCloudVerifier):
            if epoch_state is not None:
                raise StoreError("epochs must come from the composed verifier")
            try:
                checkpoint = verifier.export_checkpoint()
            except PolicyError as exc:
                raise StoreError(str(exc)) from exc
            org, head, state = checkpoint["org_id"], checkpoint["head"], checkpoint["authority"]
            pinned_root, epoch_state = checkpoint["pinned_root"], checkpoint["epochs"]
            verified_heads = checkpoint["verified_heads"]
        else:
            raise StoreError("successful independent verifier required")
        checked_org(org)
        parse_head(head)
        if not isinstance(state, dict) or state.get("org_id") != org or state.get("head") != head:
            raise StoreError("authority snapshot head differs")
        authority_json = crypto.canonical_json(state).decode("utf-8")
        epoch_json = None if epoch_state is None else crypto.canonical_json(epoch_state).decode("utf-8")
        def has_private_slot(value):
            if isinstance(value, dict):
                return "wrapped_priv" in value or any(has_private_slot(v) for v in value.values())
            return isinstance(value, list) and any(has_private_slot(v) for v in value)
        if has_private_slot(state) or has_private_slot(epoch_state):
            raise StoreError("private slot blobs cannot enter replay snapshots")
        if sync_blobs is not None:
            from .cloud_recovery import RecoveryVerifier
            from .cloud_epochs import EpochReplay
            from .policy_log import utc_millis
            if not isinstance(verifier, RecoveryVerifier) or observed_at is None:
                raise StoreError("complete recovery/request verifier and local observation required")
            utc_millis(observed_at)
            checker = EpochReplay()
            checker._state = epoch_state
            checker.verify_current_ciphertexts(sync_blobs, projects=None if checkpoint['ciphertext_scope'] == 'full' else checkpoint['ciphertext_scope'])
            request_json = crypto.canonical_json(verifier.request_state).decode()
        if self.cloud_branch(org) is not None:
            self.save_cloud_branch(verifier, sync_blobs, observed_at, sync_broker, expected_head)
            return
        with self.transaction(immediate=True) as db:
            pin = db.execute("SELECT root_hash FROM cloud_pins WHERE org_id=?", (org,)).fetchone()
            if pin is None or pin["root_hash"] != pinned_root or (head["seq"] > 0 and state.get("root") != pin["root_hash"]):
                raise StoreError("independent cloud root pin differs")
            current = db.execute("SELECT seq,hash FROM cloud_replay WHERE org_id=? ORDER BY seq DESC LIMIT 1", (org,)).fetchone()
            current_head = None if current is None else dict(current)
            if expected_head is not None and current_head != expected_head:
                raise StoreError("cloud replay head changed")
            if current and (current["seq"] > head["seq"] or current["seq"] == head["seq"] and current["hash"] != head["hash"]):
                raise StoreError("cloud replay head regressed or forked")
            if current and verified_heads.get(current["seq"]) != current["hash"]:
                raise StoreError("cloud replay prefix does not extend the persisted head")
            prior = db.execute("SELECT hash,authority_json,epoch_json FROM cloud_replay WHERE org_id=? AND seq=?", (org, head["seq"])).fetchone()
            if prior is not None:
                if tuple(prior) != (head["hash"], authority_json, epoch_json):
                    raise StoreError("immutable cloud snapshot differs")
            else:
                db.execute("INSERT INTO cloud_replay(org_id,seq,hash,authority_json,epoch_json) VALUES (?,?,?,?,?)", (org, head["seq"], head["hash"], authority_json, epoch_json))
            if sync_blobs is not None:
                self.reconcile_cloud_unpublished(db, org, verifier, epoch_state)
                db.execute("INSERT OR IGNORE INTO cloud_sync_state VALUES (?,?,?)", (org, head['seq'], request_json))
                db.execute("DELETE FROM cloud_sync_blobs WHERE org_id=?", (org,))
                for blob in sync_blobs:
                    db.execute("INSERT INTO cloud_sync_blobs VALUES (?,?,?,?)", (org, blob['version_id'], head['seq'], crypto.canonical_json(blob).decode()))
                db.execute("INSERT INTO cloud_head_observations(org_id,seq,hash,observed_at) VALUES (?,?,?,?)", (org, head['seq'], head['hash'], observed_at))
                for proposal_hash, proposal in state['proposals'].items():
                    live = not proposal['activated'] and 0 <= utc_millis(observed_at) - utc_millis(proposal['ts']) <= 600000
                    db.execute('INSERT OR IGNORE INTO cloud_proposal_observations VALUES (?,?,?,?)', (org, proposal_hash, 'live' if live else 'history', observed_at))
                for item in verifier.hold_evidence:
                    db.execute('INSERT OR IGNORE INTO cloud_sync_holds VALUES (?,?,?,?,?,?,?)',
                        (org, item['proposal_hash'], item['head']['seq'], item['head']['hash'], item['status'], item['observed_at'], head['seq']))
                if sync_broker is not None:
                    self.prune_cloud_custody(db, org, sync_broker, state, epoch_state)

    def reconcile_cloud_unpublished(self, db, org, verifier, epochs, *, conflict_message='verified version differs from unpublished commitments'):
        """Reconcile only against accepted history, inside the pull transaction."""
        published = {v['version_id'] for v in epochs['versions']}
        for pending in db.execute('SELECT version_id,payload_json FROM cloud_unpublished WHERE org_id=?', (org,)).fetchall():
            payload = json.loads(pending['payload_json'])
            body = payload['entries'][-1]['entry']['body']
            if pending['version_id'] in published:
                # A later legitimate rewrap may have changed the current
                # envelope; compare the original accepted signed commitments.
                if not any(e['kind'] == 'version_add' and all(e['body'].get(k) == body[k]
                        for k in ('version_id', 'value_digest', 'envelope_digest')) for e in verifier._records):
                    raise CloudPublicationConflict(conflict_message)
            else:
                consumed = any(v['secret_id'] == body['secret_id']
                    and v['version_no'] >= body['version_no']
                    and v['version_id'] != pending['version_id'] for v in epochs['versions'])
                new_secret = payload.get('secret')
                name_taken = new_secret is not None and any(
                    s['project'] == new_secret['project'] and s['path'] == new_secret['path']
                    and s['secret_id'] != new_secret['secret_id'] for s in epochs['secrets'].values())
                if not (consumed or name_taken):
                    continue
            # Accepted ids reconcile as before. A consumed number or unique
            # name instead lets the next put stage a fresh identity and request.
            db.execute('DELETE FROM cloud_unpublished WHERE org_id=? AND version_id=?', (org, pending['version_id']))

    def prune_cloud_custody(self, db, org, broker, authority, epochs):
        """Run on verified pull and pickup, without waiting for another key GET.

        A committed narrowing certificate immediately drops unauthorized project
        KEKs. A former full broker retains its OMK until the covering full epoch
        commits, so a pending rekey never destroys its working custody early.
        """
        from .cloud_policy import AuthorityView
        from .cloud_epochs import EpochView
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='cloud_local_keys'").fetchone() is None:
            return
        view = AuthorityView(authority)
        cert = view.broker_certificate_at(broker, authority['head'])
        if cert is None or cert['scope'] == 'full':
            return
        snapshot = view.epoch_snapshot(authority['head'], sorted(epochs['active_kek']))
        custody = EpochView(epochs, snapshot).custody_evidence(broker, authority['head'])
        if custody['custody'] != 'full':
            db.execute("DELETE FROM cloud_local_keys WHERE org_id=? AND broker_id=? AND purpose='omk'", (org, broker))
        for row in db.execute("SELECT key_id,generation,scope FROM cloud_local_keys WHERE org_id=? AND broker_id=? AND purpose='kek'", (org, broker)).fetchall():
            if row['scope'] not in cert['scope']:
                db.execute('DELETE FROM cloud_local_keys WHERE org_id=? AND broker_id=? AND key_id=? AND generation=?', (org, broker, row['key_id'], row['generation']))

    def cloud_branch(self, org):
        if self.connection.execute("SELECT 1 FROM sqlite_master WHERE name='cloud_active_branch'").fetchone() is None:
            return None
        row = self.connection.execute('SELECT branch_id FROM cloud_active_branch WHERE org_id=?',(org,)).fetchone()
        return None if row is None else row[0]

    def cloud_request_state(self, org, head):
        branch = self.cloud_branch(org)
        row = (self.connection.execute('SELECT request_json FROM cloud_branch_replay WHERE branch_id=? AND seq=? AND hash=?',(branch,head['seq'],head['hash'])).fetchone()
            if branch is not None else self.connection.execute('SELECT request_json FROM cloud_sync_state WHERE org_id=? AND seq=?',(org,head['seq'])).fetchone())
        return {} if row is None else json.loads(row[0])

    def save_cloud_branch(self, verifier, blobs, observed_at, broker, expected_head):
        """Append a verified extension to the selected branch in one transaction."""
        from .policy_log import utc_millis
        checkpoint = verifier.export_checkpoint()
        org,head = checkpoint['org_id'],checkpoint['head']
        if blobs is None or observed_at is None or broker is None:
            raise StoreError('selected history requires complete cloud pull')
        utc_millis(observed_at)
        with self.transaction(immediate=True) as db:
            branch = self.cloud_branch(org)
            current = self.load_cloud_replay(org)
            if branch is None or current is None or expected_head != current['head']:
                raise StoreError('selected cloud head changed')
            if checkpoint['pinned_root'] != self.cloud_pin(org) or checkpoint['verified_heads'].get(current['head']['seq']) != current['head']['hash']:
                raise StoreError('selected cloud prefix does not extend verified head')
            values = (branch,head['seq'],head['hash'],crypto.canonical_json(checkpoint['authority']).decode(),
                crypto.canonical_json(checkpoint['epochs']).decode(),crypto.canonical_json(verifier.request_state).decode())
            prior = db.execute('SELECT * FROM cloud_branch_replay WHERE branch_id=? AND seq=?',(branch,head['seq'])).fetchone()
            if prior is not None and tuple(prior) != values:
                raise StoreError('immutable selected cloud snapshot differs')
            db.execute('INSERT OR IGNORE INTO cloud_branch_replay VALUES (?,?,?,?,?,?)',values)
            self.reconcile_cloud_unpublished(db, org, verifier, checkpoint['epochs'],
                conflict_message='verified publication differs from retained write')
            db.execute('DELETE FROM cloud_sync_blobs WHERE org_id=?',(org,))
            for blob in blobs:
                db.execute('INSERT INTO cloud_sync_blobs VALUES (?,?,?,?)',(org,blob['version_id'],head['seq'],crypto.canonical_json(blob).decode()))
            db.execute('INSERT INTO cloud_branch_observations VALUES (?,?,?,?)',(branch,head['seq'],head['hash'],observed_at))
            for digest,proposal in checkpoint['authority']['proposals'].items():
                live = not proposal['activated'] and 0 <= utc_millis(observed_at)-utc_millis(proposal['ts']) <= 600000
                db.execute('INSERT OR IGNORE INTO cloud_branch_proposals VALUES (?,?,?,?)',(branch,digest,'live' if live else 'history',observed_at))
            self.prune_cloud_custody(db,org,broker,checkpoint['authority'],checkpoint['epochs'])

    def load_cloud_replay(self, org_id: str):
        branch = self.cloud_branch(org_id)
        if branch is not None:
            row = self.connection.execute('SELECT * FROM cloud_branch_replay WHERE branch_id=? ORDER BY seq DESC LIMIT 1',(branch,)).fetchone()
            return None if row is None else dict(head=dict(seq=row['seq'],hash=row['hash']),authority=json.loads(row['authority_json']),epochs=json.loads(row['epoch_json']))
        """Read local checkpoint data; no network data is accepted here."""
        with self._transaction_lock:
            row = self.connection.execute("SELECT seq,hash,authority_json,epoch_json FROM cloud_replay WHERE org_id=? ORDER BY seq DESC LIMIT 1", (org_id,)).fetchone()
            if row is None:
                return None
            return dict(head=dict(seq=row["seq"], hash=row["hash"]), authority=json.loads(row["authority_json"]), epochs=None if row["epoch_json"] is None else json.loads(row["epoch_json"]))

    def _cloud_persisted_head(self, db, org_id, head):
        from .cloud_wire import parse_head

        parse_head(head)
        branch = self.cloud_branch(org_id)
        row = (db.execute('SELECT hash FROM cloud_branch_replay WHERE branch_id=? AND seq=?',(branch,head['seq'])).fetchone()
            if branch is not None else db.execute("SELECT hash FROM cloud_replay WHERE org_id=? AND seq=?", (org_id, head["seq"])).fetchone())
        if row is None or row["hash"] != head["hash"]:
            raise StoreError("unverified cloud evidence head")

    def observe_cloud_head(self, org_id: str, head: dict, observed_at: str) -> None:
        from .policy_log import utc_millis

        utc_millis(observed_at)
        with self.transaction(immediate=True) as db:
            self._cloud_persisted_head(db, org_id, head)
            # Each successful unchanged-head pull is retained separately.
            db.execute("INSERT INTO cloud_head_observations(org_id,seq,hash,observed_at) VALUES (?,?,?,?)", (org_id, head["seq"], head["hash"], observed_at))

    def observe_cloud_proposal(self, org_id: str, proposal_hash: str, mode: str, observed_at: str) -> None:
        from .cloud_wire import digest
        from .policy_log import utc_millis

        digest(proposal_hash)
        utc_millis(observed_at)
        if mode not in ("live", "history"):
            raise StoreError("invalid proposal observation mode")
        with self.transaction(immediate=True) as db:
            row = db.execute("SELECT authority_json FROM cloud_replay WHERE org_id=? ORDER BY seq DESC LIMIT 1", (org_id,)).fetchone()
            if row is None or proposal_hash not in json.loads(row["authority_json"])["proposals"]:
                raise StoreError("unverified proposal observation")
            db.execute("INSERT OR IGNORE INTO cloud_proposal_observations(org_id,proposal_hash,mode,first_seen_at) VALUES (?,?,?,?)", (org_id, proposal_hash, mode, observed_at))

    def cloud_observations(self, org_id: str) -> dict:
        from .cloud_policy import empty_observations, observe_head
        branch = self.cloud_branch(org_id)
        if branch is not None:
            return dict(heads=[dict(row) for row in self.connection.execute('SELECT seq,hash,observed_at FROM cloud_branch_observations WHERE branch_id=?',(branch,))],
                proposals={row['proposal_hash']:dict(mode=row['mode'],first_seen_at=row['first_seen_at'])
                    for row in self.connection.execute('SELECT * FROM cloud_branch_proposals WHERE branch_id=?',(branch,))})

        result = empty_observations()
        with self._transaction_lock:
            for row in self.connection.execute("SELECT seq,hash,observed_at FROM cloud_head_observations WHERE org_id=? ORDER BY observation_id", (org_id,)):
                result = observe_head(result, dict(seq=row["seq"], hash=row["hash"]), row["observed_at"])
            for row in self.connection.execute("SELECT proposal_hash,mode,first_seen_at FROM cloud_proposal_observations WHERE org_id=?", (org_id,)):
                result["proposals"][row["proposal_hash"]] = dict(mode=row["mode"], **({"first_seen_at": row["first_seen_at"]} if row["mode"] == "live" else {}))
        return result

    def record_cloud_hold(self, org_id: str, proposal_hash: str, activation_head: dict, status: str, observed_at: str) -> None:
        from .cloud_wire import digest
        from .cloud_policy import check_hold
        from .policy_log import utc_millis

        digest(proposal_hash)
        utc_millis(observed_at)
        if status not in ("locally_observed", "hold_not_locally_observed"):
            raise StoreError("invalid hold evidence status")
        with self.transaction(immediate=True) as db:
            self._cloud_persisted_head(db, org_id, activation_head)
            row = db.execute("SELECT authority_json FROM cloud_replay WHERE org_id=? AND seq=?", (org_id, activation_head["seq"])).fetchone()
            proposal = json.loads(row["authority_json"])["proposals"].get(proposal_hash)
            if not proposal or not proposal["activated"] or not proposal["hold"] or proposal.get("activation_seq") != activation_head["seq"] or proposal.get("activation_hash") != activation_head["hash"]:
                raise StoreError("unverified hold activation")
            observation = self.cloud_observations(org_id)["proposals"].get(proposal_hash)
            actual_status = check_hold(proposal["ts"], proposal["activation_received_at"], observation, observed_at)
            if actual_status != status:
                raise StoreError("hold status differs from local evidence")
            db.execute("INSERT INTO cloud_hold_evidence(org_id,proposal_hash,activation_seq,activation_hash,status,observed_at) VALUES (?,?,?,?,?,?)", (org_id, proposal_hash, activation_head["seq"], activation_head["hash"], status, observed_at))

    def record_cloud_conflict(self, org_id: str, head: dict, reason: str, observed_at: str) -> None:
        from .cloud_wire import text
        from .policy_log import utc_millis

        text(reason)
        utc_millis(observed_at)
        with self.transaction(immediate=True) as db:
            self._cloud_persisted_head(db, org_id, head)
            db.execute("INSERT INTO cloud_conflicts(org_id,seq,hash,reason,observed_at) VALUES (?,?,?,?,?)", (org_id, head["seq"], head["hash"], reason, observed_at))

    def checkpoint(self) -> None:
        self.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def backup(self, destination: str | os.PathLike[str]) -> Path:
        target = Path(destination).expanduser().resolve()
        if not any(target.is_relative_to(root) for root in self.backup_roots):
            raise StoreError("backup destination is outside the allowed roots")
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with closing(sqlite3.connect(target)) as output:
            self.connection.backup(output)
        os.chmod(target, 0o600)
        return target

    def initialize_cloud_custody(self) -> None:
        """Add local cloud custody tables only on explicit cloud-mode invocation."""
        schema = Path(__file__).with_name("cloud_custody.sql").read_text(encoding="utf-8")
        with self.transaction(immediate=True) as db:
            statement = ""
            for line in schema.splitlines(keepends=True):
                statement += line
                if sqlite3.complete_statement(statement):
                    db.execute(statement)
                    statement = ""
            if statement.strip():
                raise StoreError("incomplete custody schema")
            columns = {row['name'] for row in db.execute('PRAGMA table_info(cloud_enrollments)')}
            if 'custody_json' not in columns:
                db.execute('ALTER TABLE cloud_enrollments ADD COLUMN custody_json TEXT')

    def put_cloud_local_key(self, blk: bytes, *, org: str, broker: str,
                            key_id: str, purpose: str, scope: str,
                            generation: int, key: bytes) -> None:
        """Encrypt local custody under BLK with complete identity-bound AAD."""
        from .cloud_wire import org_id, integer, text
        org_id(org); integer(generation, 1)
        for value in (broker, key_id, purpose, scope):
            text(value)
        aad = crypto.local_key_aad(org, broker, key_id, purpose, scope, generation)
        wrapped, nonce = crypto.wrap_key(blk, key, aad)
        with self.transaction(immediate=True) as db:
            prior = db.execute("SELECT * FROM cloud_local_keys WHERE org_id=? AND broker_id=? AND key_id=? AND generation=?",
                               (org, broker, key_id, generation)).fetchone()
            if prior is not None:
                if prior['purpose'] != purpose or prior['scope'] != scope:
                    raise StoreError("local custody metadata changed")
                previous = crypto.unwrap_key(blk, bytes(prior['wrapped_key']), bytes(prior['nonce']), aad)
                if not crypto.compare_digest(previous, key):
                    raise StoreError("local custody key rebinding")
                return
            db.execute("INSERT INTO cloud_local_keys VALUES (?,?,?,?,?,?,?,?)",
                       (org, broker, key_id, purpose, scope, generation, wrapped, nonce))

    def cloud_local_key(self, blk: bytes, *, org: str, broker: str,
                        key_id: str, purpose: str, scope: str, generation: int) -> bytes:
        with self._transaction_lock:
            row = self.connection.execute("SELECT * FROM cloud_local_keys WHERE org_id=? AND broker_id=? AND key_id=? AND generation=?",
                                          (org, broker, key_id, generation)).fetchone()
            if row is None or row['purpose'] != purpose or row['scope'] != scope:
                raise StoreError("local custody key unavailable")
            return crypto.unwrap_key(blk, bytes(row['wrapped_key']), bytes(row['nonce']),
                crypto.local_key_aad(org, broker, key_id, purpose, scope, generation))
