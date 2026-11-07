"""Narrow authenticated import adapter. No plaintext in protocol responses.

The importer adapter binds stable requests to durable intent metadata before
P2 publication and records its receipt afterward. A cached metadata fingerprint
is insufficient for verify: decrypt the receipt's stored version inside the
broker and compute HMAC-SHA256 with the supplied one-use key.
"""

from __future__ import annotations

from typing import Protocol
import hmac
import json
import uuid

from .bitwarden_import import ImportFailure, MAX_VALUE, MESSAGES, require, validate_entry


OPS = frozenset({"import_status", "import_auth", "import_put", "import_verify"})


class ImportRuntime(Protocol):
    def readiness(self, entries: list[dict] | None = None) -> dict:
        """Return joined/current_head; if entries given, existing target hashes.

        Target inspection must use the verified signed directory, never cloud
        row metadata. Put must independently refuse an existing target unless
        the exact request already has its durable receipt.
        """
        ...

    def put(self, entry: dict, request_id: str, value: bytes) -> dict:
        """Return a durable {request_id, version_id} receipt, including on retry."""
        ...

    def verify(self, entry: dict, request_id: str, key: bytes) -> bytes:
        """Return HMAC-SHA256(key, decrypted stored version), never the value."""
        ...


def runtime_for(service):
    if hasattr(service, "bitwarden_runtime"):
        return service.bitwarden_runtime
    cloud = getattr(service, "cloud", None)
    return CloudImportRuntime(cloud) if cloud is not None and cloud.enabled else None


class CloudImportRuntime:
    """Importer-owned metadata ledger over P2's value-idempotent publication.

    The authenticated admin identity matches the existing admin put operation.
    No value or unkeyed value digest is persisted in this ledger.
    """

    principal = "human:operator"

    def __init__(self, cloud):
        self.cloud = cloud

    def readiness(self, entries=None):
        cloud = self.cloud
        require(cloud.pull().get("state") == "active", "E_IMPORT_HEAD")
        with cloud.lock, cloud.store._transaction_lock:
            status = cloud.status()
            sync = cloud.sync()
            sync.certificate()
            require(not sync.conflicts(), "E_IMPORT_HEAD")
            result = dict(joined=status["enrollment_state"] == "complete",
                          current_head=status["head"] == sync.checkpoint()["head"])
            if entries is not None:
                from .bitwarden_import import entry_hash
                paths = {s["path"] for s in sync.checkpoint()["epochs"]["secrets"].values()}
                result["existing_targets"] = [entry_hash(e) for e in entries if self.path(e) in paths]
            return result

    @staticmethod
    def path(entry):
        return entry["project"] + "/" + entry["path"]

    def intent(self, rid):
        raw = self.cloud.store.meta("bitwarden_intent_" + rid)
        return None if raw is None else json.loads(raw)

    def fingerprint(self, value):
        from . import crypto
        cloud = self.cloud
        sync = cloud.sync()
        epochs = sync.checkpoint()["epochs"]
        key_id = next(k["key_id"] for k in epochs["keyring"] if k["purpose"] == "fingerprint")
        key = cloud.store.cloud_local_key(cloud.blk(), org=sync.org, broker=sync.broker,
            key_id=key_id, purpose="fingerprint", scope="*", generation=epochs["generation"])
        return crypto.cloud_fingerprint(key, value).hex()

    def active(self, entry):
        epochs = self.cloud.sync().checkpoint()["epochs"]
        secret = next((s for s in epochs["secrets"].values() if s["path"] == self.path(entry)), None)
        if secret is None:
            return None, None
        version = next((v for v in epochs["versions"] if v["secret_id"] == secret["secret_id"]
                        and v["state"] == "active"), None)
        return secret, version

    def matching(self, entry, intent):
        secret, version = self.active(entry)
        require(intent is not None, "E_IMPORT_EXISTS")
        require(intent["principal_id"] == self.principal, "E_IMPORT_EXISTS")
        require(intent["path"] == self.path(entry), "E_IMPORT_EXISTS")
        require(secret is not None and secret["class"] == entry["class"] and version is not None,
                "E_IMPORT_EXISTS")
        require(hmac.compare_digest(version["fingerprint"], intent["fingerprint"]), "E_IMPORT_EXISTS")
        raw = self.cloud.store.meta("cloud_write_" + version["version_id"])
        require(raw is not None, "E_IMPORT_EXISTS")
        receipt = json.loads(raw)
        require(receipt["principal_id"] == self.principal, "E_IMPORT_EXISTS")
        require(receipt["path"] == intent["path"] and receipt["fingerprint"] == intent["fingerprint"],
                "E_IMPORT_EXISTS")
        return version

    def put(self, entry, rid, value):
        cloud = self.cloud
        # Refresh before checking for an existing name, then repeat the check
        # inside P2's authorize callback after its own pull and under its lock.
        self.readiness()
        with cloud.lock, cloud.store._transaction_lock:
            fingerprint = self.fingerprint(value)
            intent = self.intent(rid)
            secret, _version = self.active(entry)
            if secret is not None:
                self.matching(entry, intent)
            expected = dict(principal_id=self.principal, path=self.path(entry), fingerprint=fingerprint)
            require(intent is None or all(intent[k] == v for k, v in expected.items()), "E_IMPORT_EXISTS")
            if intent is None:
                cloud.store.set_meta("bitwarden_intent_" + rid, json.dumps(expected, sort_keys=True))

        def authorize():
            require(self.cloud.seal.state == "unsealed", "E_IMPORT_SEALED")
            intent = self.intent(rid)
            require(intent is not None and all(intent[k] == v for k, v in expected.items()), "E_IMPORT_EXISTS")
            if self.active(entry)[0] is not None:
                self.matching(entry, intent)
            require(self.fingerprint(value) == fingerprint, "E_IMPORT_WRITE")

        receipt = cloud.put(self.path(entry), value, secret_class=entry["class"],
                            source="bitwarden-import", principal_id=self.principal, authorize=authorize)
        with cloud.lock, cloud.store._transaction_lock:
            intent = self.intent(rid)
            version = self.matching(entry, intent)
            require(receipt == dict(path=self.path(entry), version_no=version["version_no"],
                    fingerprint_prefix=fingerprint[:12]), "E_IMPORT_WRITE")
            intent["receipt"] = receipt
            cloud.store.set_meta("bitwarden_intent_" + rid, json.dumps(intent, sort_keys=True))
            return dict(request_id=rid, version_id=version["version_id"])

    def verify(self, entry, rid, key):
        cloud = self.cloud
        self.readiness()
        with cloud.lock, cloud.store._transaction_lock:
            intent = self.intent(rid)
            version = self.matching(entry, intent)
            require(intent.get("receipt") == dict(path=self.path(entry), version_no=version["version_no"],
                    fingerprint_prefix=version["fingerprint"][:12]), "E_IMPORT_VERIFY")
            value = cloud.sync().read_value(version["version_id"], cloud.blk(), now=cloud.clock())
            return hmac.digest(key, value, "sha256")


def readiness(service, runtime, entries=None):
    sealed = service.seal.state != "unsealed"
    if runtime is None or sealed:
        return dict(seal_state=service.seal.state, joined=False, current_head=False)
    result = runtime.readiness() if entries is None else runtime.readiness(entries)
    response = dict(seal_state=service.seal.state, joined=result.get("joined") is True,
                    current_head=result.get("current_head") is True)
    if entries is not None:
        from .bitwarden_import import entry_hash
        existing = result.get("existing_targets")
        expected = {entry_hash(entry) for entry in entries}
        require(type(existing) is list and all(type(item) is str and item in expected for item in existing), "E_IMPORT_HEAD")
        response["existing_targets"] = existing
    return response


def require_ready(service, runtime):
    result = readiness(service, runtime)
    require(result["seal_state"] == "unsealed", "E_IMPORT_SEALED")
    require(result["joined"], "E_IMPORT_ORG")
    require(result["current_head"], "E_IMPORT_HEAD")


def handle_import(service, session, op, args, fds):
    """All input-derived exceptions terminate here with fixed messages only."""
    try:
        require(op in OPS and type(args) is dict, "E_IMPORT_INTERNAL")
        runtime = runtime_for(service)
        if op == "import_status":
            require(set(args) <= {"entries"} and not fds, "E_IMPORT_INTERNAL")
            entries = args.get("entries")
            if "entries" in args:
                require(session.is_authenticated(), "E_IMPORT_AUTH")
                require(type(entries) is list and 0 < len(entries) <= 1000, "E_IMPORT_MANIFEST")
                for entry in entries:
                    validate_entry(entry)
            return dict(ok=True, code="ok", result=readiness(service, runtime, entries))
        if op == "import_auth":
            require(set(args) == {"passphrase"} and type(args["passphrase"]) is str and not fds,
                    "E_IMPORT_AUTH")
            # Unlike the legacy auth operation, import never unseals a broker.
            require_ready(service, runtime)
            service.seal.check_passphrase(args["passphrase"])
            session.authenticate()
            return dict(ok=True, code="ok", result={})
        require(session.is_authenticated(), "E_IMPORT_AUTH")
        require_ready(service, runtime)
        expected = {"entry", "request_id"} | ({"key"} if op == "import_verify" else set())
        require(set(args) == expected, "E_IMPORT_INTERNAL")
        entry = validate_entry(args["entry"])
        rid = args["request_id"]
        require(type(rid) is str and str(uuid.UUID(rid)) == rid and uuid.UUID(rid).version == 4, "E_IMPORT_INTERNAL")
        if op == "import_put":
            require(len(fds) == 1, "E_IMPORT_WRITE")
            value = service._read_fd(fds[0])
            require(0 < len(value) <= MAX_VALUE, "E_IMPORT_WRITE")
            receipt = runtime.put(entry, rid, value)
            del value
            require(type(receipt) is dict and receipt.get("request_id") == rid
                    and type(receipt.get("version_id")) is str, "E_IMPORT_WRITE")
            # Caller needs no cloud metadata beyond its own receipt identity.
            return dict(ok=True, code="ok", result={"request_id": rid})
        require(not fds and type(args["key"]) is str and len(args["key"]) == 64, "E_IMPORT_VERIFY")
        key = bytes.fromhex(args["key"])
        require(len(key) == 32, "E_IMPORT_VERIFY")
        digest = runtime.verify(entry, rid, key)
        require(type(digest) is bytes and len(digest) == 32, "E_IMPORT_VERIFY")
        return dict(ok=True, code="ok", result={"digest": digest.hex()})
    except BaseException as failure:
        code = failure.code if type(failure) is ImportFailure else "E_IMPORT_INTERNAL"
        return dict(ok=False, code=code, error=MESSAGES[code])
