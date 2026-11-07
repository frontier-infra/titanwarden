"""Seal, lockdown, freeze, and unseal rate-limit state."""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from . import crypto
from .audit import AuditLog, VerificationResult
from .store import Store, StoreError


SealState = Literal["uninitialized", "sealed", "unsealed", "lockdown"]


class SealError(RuntimeError):
    def __init__(self, message: str, code: str = "E_SEALED") -> None:
        super().__init__(message)
        self.code = code


@dataclass(slots=True)
class KeyringMemory:
    master: bytearray
    kek_id: str
    kek: bytearray
    audit_id: str
    audit: bytearray
    fingerprint_id: str
    fingerprint: bytearray

    def wipe(self) -> None:
        for value in (self.master, self.kek, self.audit, self.fingerprint):
            value[:] = bytes(len(value))


class SealManager:
    def __init__(self, store: Store) -> None:
        self.store = store
        self.freeze_path = store.home / "FREEZE"
        self.frozen = self.freeze_path.exists()
        self.keys: KeyringMemory | None = None
        self.wrong_attempts: deque[float] = deque()
        self.auth_lock = threading.Lock()
        if store.meta("store_id") is None:
            self.state: SealState = "uninitialized"
        elif store.meta("lockdown") == "1":
            self.state = "lockdown"
        else:
            self.state = "sealed"

    def observe_freeze_file(self) -> bool:
        if self.freeze_path.exists():
            self.frozen = True
        return self.frozen

    def freeze(self) -> None:
        self.freeze_path.touch(mode=0o600, exist_ok=True)
        self.frozen = True

    def unfreeze(self) -> None:
        self.frozen = False
        if self.freeze_path.exists():
            self.freeze_path.unlink()

    def check_agent_operation(self, op: str) -> None:
        self.observe_freeze_file()
        if self.frozen and op not in {"hello", "status"}:
            raise SealError("broker is frozen", "E_FROZEN")
        if self.state != "unsealed" and op not in {"hello", "status"}:
            raise SealError("broker is sealed", "E_SEALED")

    def _check_rate_limit(self, now: float) -> None:
        cutoff = now - 600
        while self.wrong_attempts and self.wrong_attempts[0] < cutoff:
            self.wrong_attempts.popleft()
        if len(self.wrong_attempts) >= 5:
            raise SealError("too many wrong passphrases; retry later", "E_BUSY")

    def check_passphrase(self, passphrase: str) -> None:
        with self.auth_lock:
            if self.state == "lockdown":
                raise SealError("broker is in lockdown", "E_SEALED")
            if self.state != "unsealed" or self.keys is None:
                raise SealError("broker is sealed", "E_SEALED")
            now = time.monotonic()
            self._check_rate_limit(now)
            try:
                master = self.store.unlock_passphrase(passphrase)
            except (crypto.CryptoError, ValueError):
                self.wrong_attempts.append(now)
                raise SealError("authentication failed", "E_AUTH") from None
            if not crypto.compare_digest(master, bytes(self.keys.master)):
                self.wrong_attempts.append(now)
                raise SealError("authentication failed", "E_AUTH")
            self.wrong_attempts.clear()

    def unseal(self, passphrase: str) -> KeyringMemory:
        with self.auth_lock:
            return self._unseal_locked(passphrase)

    def _unseal_locked(self, passphrase: str) -> KeyringMemory:
        if self.state == "lockdown":
            raise SealError("broker is in lockdown", "E_SEALED")
        if self.state == "unsealed":
            raise SealError("broker is already unsealed", "E_BUSY")
        now = time.monotonic()
        self._check_rate_limit(now)
        candidate: KeyringMemory | None = None
        master_memory: bytearray | None = None
        audit_memory: bytearray | None = None
        try:
            master = self.store.unlock_passphrase(passphrase)
            master_memory = bytearray(master)
            _audit_id, audit_key = self.store.load_key(master, "audit_mac")
            audit_memory = bytearray(audit_key)
        except (crypto.CryptoError, StoreError, ValueError):
            self.wrong_attempts.append(now)
            raise SealError("unseal failed", "E_AUTH") from None
        try:
            audit = AuditLog(self.store, mac_key=bytes(audit_memory))
            verified = audit.verify(allow_unattested_sealed_tail=True)
            if not verified.ok:
                self.handle_verify_failure(verified)
                raise SealError("audit verification failed", "E_INTEGRITY")
            audit.attest_sealed_tail(f"evt_unseal_tail_{time.time_ns()}")
            verified = audit.verify()
            if not verified.ok:
                self.handle_verify_failure(verified)
                raise SealError("audit verification failed", "E_INTEGRITY")
            audit.anchor(f"anchor_unseal_{time.time_ns()}", "local:unseal")
            loaded = self.store.load_keyring(bytes(master_memory))
            candidate = KeyringMemory(
                master_memory,
                loaded["kek"][0],
                bytearray(loaded["kek"][1]),
                loaded["audit_mac"][0],
                bytearray(loaded["audit_mac"][1]),
                loaded["fingerprint"][0],
                bytearray(loaded["fingerprint"][1]),
            )
            self.store.set_meta("lockdown", "0")
            self.keys = candidate
            self.state = "unsealed"
            self.wrong_attempts.clear()
            return candidate
        except BaseException:
            if candidate is not None and self.keys is not candidate:
                candidate.wipe()
            elif master_memory is not None and self.keys is None:
                master_memory[:] = bytes(len(master_memory))
            raise
        finally:
            if audit_memory is not None:
                audit_memory[:] = bytes(len(audit_memory))

    def seal(self) -> None:
        try:
            if self.keys is not None:
                AuditLog(self.store, mac_key=bytes(self.keys.audit)).anchor(
                    f"anchor_seal_{time.time_ns()}", "local:seal"
                )
        except Exception:
            pass
        finally:
            if self.keys is not None:
                self.keys.wipe()
                self.keys = None
            self.state = "sealed"

    def lockdown(self) -> None:
        try:
            self.seal()
        finally:
            try:
                self.store.set_meta("lockdown", "1")
            except Exception:
                pass
        self.state = "lockdown"

    def handle_verify_failure(self, result: VerificationResult) -> None:
        if not result.ok:
            self.lockdown()

    def clear_lockdown(self, passphrase: str) -> KeyringMemory:
        with self.auth_lock:
            self.store.set_meta("lockdown", "0")
            self.state = "sealed"
            try:
                return self._unseal_locked(passphrase)
            except BaseException:
                self.store.set_meta("lockdown", "1")
                self.state = "lockdown"
                raise


class CloudCustody:
    """Explicit local BLK custody, separate from the standalone seal manager.

    No broker/admin route constructs this draft helper. Slot keys are supplied by
    an authenticated local ceremony; only caller-approved public KDF parameters
    belong in params. The secret BLK stays out of repr and persisted plaintext.
    """
    def __init__(self, store: Store, org: str, broker: str, blk: bytes):
        from .cloud_wire import org_id, text
        org_id(org); text(broker)
        if not isinstance(blk, bytes) or len(blk) != 32:
            raise ValueError('BLK must be 32 bytes')
        self.store, self.org, self.broker = store, org, broker
        self._blk = bytearray(blk)
        self._closed = False
        store.initialize_cloud_custody()

    def close(self):
        self._blk[:] = bytes(len(self._blk))
        self._closed = True

    def wrap_slot(self, slot_id: str, slot_key: bytes, *, generation: int, params: dict):
        from .cloud_wire import integer, text
        if self._closed:
            raise SealError('cloud custody is sealed')
        text(slot_id); integer(generation, 1)
        encoded = crypto.canonical_json(params).decode()
        aad = crypto.local_slot_aad(self.org, self.broker, slot_id, generation)
        wrapped, nonce = crypto.wrap_key(slot_key, bytes(self._blk), aad)
        with self.store.transaction(immediate=True) as db:
            prior = db.execute('SELECT * FROM cloud_local_slots WHERE org_id=? AND broker_id=? AND slot_id=? AND generation=?',
                (self.org, self.broker, slot_id, generation)).fetchone()
            if prior is not None:
                if prior['params_json'] != encoded or crypto.unwrap_key(slot_key, bytes(prior['wrapped_blk']), bytes(prior['nonce']), aad) != bytes(self._blk):
                    raise StoreError('local slot rebinding')
                return
            db.execute('INSERT INTO cloud_local_slots VALUES (?,?,?,?,?,?,?)',
                (self.org,self.broker,slot_id,generation,encoded,wrapped,nonce))

    @classmethod
    def unseal_slot(cls, store, org: str, broker: str, slot_id: str, generation: int, slot_key: bytes):
        row = store.connection.execute('SELECT * FROM cloud_local_slots WHERE org_id=? AND broker_id=? AND slot_id=? AND generation=?',
            (org,broker,slot_id,generation)).fetchone()
        if row is None:
            raise SealError('cloud unlock slot unavailable')
        blk = crypto.unwrap_key(slot_key,bytes(row['wrapped_blk']),bytes(row['nonce']),crypto.local_slot_aad(org,broker,slot_id,generation))
        return cls(store,org,broker,blk)
