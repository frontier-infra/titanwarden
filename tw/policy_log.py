"""Strict policy chain and blob verifier, independent of HTTP and storage.

Authority, certificate, epoch and authorization transitions are mandatory hooks.
Hooks must reject every kind they do not implement. A persistent appender must
serialize append and its database write in the same transaction.
"""

from __future__ import annotations

import copy
import datetime as dt
import re
from dataclasses import dataclass
from typing import Callable, Any

from tw import crypto

ZERO_HASH = "0" * 64


class PolicyError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class PolicyRecord:
    data: bytes
    hash: str
    signature: bytes | None
    received_at: str


@dataclass(frozen=True)
class PolicyHooks:
    resolve_key: Callable[[dict, Any], bytes]
    authorize: Callable[[dict, Any], Any]
    derive: Callable[[dict, Any, str], Any]
    commitments: Callable[[dict, Any], list[dict]] | None = None


def _digest(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("invalid digest")
    return value


def _text(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("invalid string")
    return value


def utc_millis(value: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?Z", value
    ):
        raise ValueError("invalid UTC timestamp")
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    canonical = parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    if canonical.replace(".000Z", "Z") != value.replace(".000Z", "Z"):
        raise ValueError("invalid UTC timestamp")
    delta = parsed - dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1000 + delta.microseconds // 1000


# Explicit body-root schema fields only. Project-map keys are application data.
BODY_INTEGERS = (
    "seq",
    "generation",
    "omk_generation",
    "blk_generation",
    "mk_generation",
    "from_generation",
    "to_generation",
    "prior_cert_seq",
    "epoch_seq",
    "trigger_seq",
    "recipients_count",
    "fence",
    "cert_no",
    "version_no",
    "page",
)


def _body_integers(body: dict) -> None:
    for field in BODY_INTEGERS:
        if field in body:
            crypto.safe_integer(body[field], True)
    # Kind-specific hooks own nested schema fields and all further validation.


def parse_entry(data: bytes) -> dict:
    if len(data) > 65536:
        raise ValueError("entry exceeds 64 KiB")
    e = crypto.parse_canonical(data)
    if (
        not isinstance(e, dict)
        or set(e) != {"body", "kind", "org_id", "prev_hash", "seq", "signer", "ts", "v"}
        or type(e["v"]) is not int
        or e["v"] != 2
        or not isinstance(e["org_id"], str)
        or not re.fullmatch(r"[0-9a-f]{32}", e["org_id"])
    ):
        raise ValueError("invalid entry schema")
    crypto.safe_integer(e["seq"], True)
    _digest(e["prev_hash"])
    utc_millis(e["ts"])
    _text(e["kind"])
    if not isinstance(e["body"], dict) or not isinstance(e["signer"], dict):
        raise ValueError("invalid object")
    s = e["signer"]
    _text(s.get("kind"))
    if s["kind"] == "derived":
        if set(s) != {"kind"}:
            raise ValueError("invalid derived signer")
    else:
        _text(s.get("id"))
        if "key" in s:
            _text(s["key"])
        if set(s) - {"kind", "id", "key"}:
            raise ValueError("invalid signer")
    _body_integers(e["body"])
    return e


class PolicyVerifier:
    def __init__(
        self,
        org_id: str,
        pinned_root: str,
        state: Any,
        hooks: PolicyHooks,
    ):
        if not re.fullmatch(r"[0-9a-f]{32}", org_id):
            raise ValueError("invalid org id")
        _digest(pinned_root)
        if not hooks or not all(
            callable(getattr(hooks, name, None))
            for name in ("resolve_key", "authorize", "derive")
        ):
            raise ValueError("mandatory policy hooks missing")
        if isinstance(state, dict) and "head" in state and state["head"] != {"seq": 0, "hash": ZERO_HASH}:
            raise ValueError("supplied policy checkpoint state is forbidden")
        self.org_id = org_id
        self.pinned_root = pinned_root
        self.hooks = hooks
        self._head = {"seq": 0, "hash": ZERO_HASH}
        self._verified_heads = {self._head["seq"]: self._head["hash"]}
        self._state = copy.deepcopy(state)
        self._committed = {}
        self.conflict = False

    @property
    def head(self) -> dict:
        return dict(self._head)

    @property
    def verified_heads(self) -> dict:
        return dict(self._verified_heads)

    @property
    def state(self) -> Any:
        return copy.deepcopy(self._state)

    @property
    def commitments(self) -> list[dict]:
        return [{"id": k, "digest": v} for k, v in self._committed.items()]

    def verify_record(self, record: PolicyRecord) -> dict:
        if self.conflict:
            raise PolicyError("E_POLICY_CONFLICT", "verifier is in conflict")
        before = self.head
        try:
            e = parse_entry(record.data)
            utc_millis(record.received_at)
            digest = crypto.sha256(record.data).hex()
            _digest(record.hash)
            if (
                digest != record.hash
                or e["org_id"] != self.org_id
                or e["seq"] != before["seq"] + 1
                or e["prev_hash"] != before["hash"]
            ):
                raise ValueError("chain mismatch")
            if (
                (e["kind"] != "genesis" or digest != self.pinned_root)
                if e["seq"] == 1
                else e["kind"] == "genesis"
            ):
                raise ValueError("genesis pin mismatch")
            state = self.state
            if e["signer"]["kind"] == "derived":
                if record.signature is not None:
                    raise ValueError("derived signature")
                state = self.hooks.derive(e, state, record.received_at)
            else:
                if record.signature is None or not crypto.p256_verify(
                    self.hooks.resolve_key(e, state),
                    crypto.policy_context(self.org_id, digest),
                    record.signature,
                ):
                    raise ValueError("bad signature")
                state = self.hooks.authorize(e, state)
            committed = dict(self._committed)
            self._update_commitments(e, committed)
            if self.hooks.commitments:
                for c in self.hooks.commitments(e, state):
                    committed[c["id"]] = _digest(c["digest"])
            if self._head != before:
                raise PolicyError("E_POLICY_HEAD", "concurrent verification; retry")
            if self.conflict:
                raise ValueError("verifier entered conflict during verification")
            next_state = copy.deepcopy(state)
            self._state = next_state
            self._head = {"seq": e["seq"], "hash": digest}
            self._verified_heads[e["seq"]] = digest
            self._committed = committed
            return self.head
        except Exception as exc:
            if isinstance(exc, PolicyError) and exc.code == "E_POLICY_HEAD":
                raise
            self.conflict = True
            raise PolicyError("E_POLICY_CONFLICT", str(exc)) from exc

    def append(self, record: PolicyRecord, now: int) -> dict:
        e = parse_entry(record.data)
        if e["prev_hash"] != self._head["hash"] or e["seq"] != self._head["seq"] + 1:
            raise PolicyError("E_POLICY_HEAD", "head changed; re-sign")
        if (
            type(now) is not int
            or abs(utc_millis(e["ts"]) - now) > 300000
            or utc_millis(record.received_at) != now
        ):
            raise PolicyError("E_POLICY_TIME", "live timestamp outside bound")
        return self.verify_record(record)

    @staticmethod
    def _update_commitments(e: dict, committed: dict) -> None:
        b = e["body"]
        if e["kind"] == "version_add":
            ident = _text(b.get("version_id"))
            if "value:" + ident in committed:
                raise ValueError("duplicate version")
            committed["value:" + ident] = _digest(b.get("value_digest"))
            committed["envelope:" + ident] = _digest(b.get("envelope_digest"))
        if e["kind"] == "dek_rewrap":
            items = b.get("items")
            if not isinstance(items, list) or not 1 <= len(items) <= 200:
                raise ValueError("invalid rewrap batch")
            seen = set()
            for item in items:
                ident = _text(item.get("version_id"))
                if ident in seen or committed.get("envelope:" + ident) != _digest(
                    item.get("from_envelope_digest")
                ):
                    raise ValueError("stale or duplicate envelope")
                seen.add(ident)
                committed["envelope:" + ident] = _digest(item.get("to_envelope_digest"))

    def check_blob(self, ident: str, actual_digest: str) -> None:
        if (
            self.conflict
            or ident not in self._committed
            or self._committed[ident] != actual_digest
        ):
            self.conflict = True
            raise PolicyError("E_POLICY_CONFLICT", "blob commitment mismatch")

    def check_value(self, ident: str, ciphertext: bytes, nonce: bytes) -> None:
        self.check_blob("value:" + ident, crypto.value_digest(ciphertext, nonce))

    def check_envelope(
        self, ident: str, kek: str, wrapped: bytes, nonce: bytes
    ) -> None:
        self.check_blob(
            "envelope:" + ident, crypto.envelope_digest(kek, wrapped, nonce)
        )

    def check_wrap(self, ident: str, box: crypto.SealedBox) -> None:
        self.check_blob(ident, crypto.wrap_digest(box.eph_pub, box.nonce, box.wrapped))


def policy_record(
    entry: dict, signature: bytes | None, received_at: str
) -> PolicyRecord:
    data = crypto.canonical_json(entry)
    return PolicyRecord(data, crypto.sha256(data).hex(), signature, received_at)


class OfflineCloudVerifier:
    """Compose strict authority and epoch replay without a production caller.

    Projects and evidence ports must be independently verified inputs. In
    particular, remote recipient hints and remote authority snapshots are never
    accepted. Each record either advances both copied state machines or leaves
    their accepted prefixes unchanged and puts the verifier in conflict.
    """

    def __init__(self, org_id: str, pinned_root: str, *, projects=(), runtime=None):
        from . import cloud_policy, cloud_epochs, cloud_wire
        import threading

        self._lock = threading.RLock()
        self._runtime = self._checked_runtime(runtime)
        if self._runtime.get("mode", "history") not in ("live", "history"):
            raise ValueError("unknown offline observation mode")
        project_list = list(projects)
        if len(set(project_list)) != len(project_list):
            raise ValueError("duplicate project")
        for project in project_list:
            cloud_wire.text(project)
        self._projects = tuple(sorted(project_list))
        self._epochs = cloud_epochs.EpochReplay()
        self._hold_evidence = []
        self._initial_references = []
        self._active_evidence = None
        self._active_runtime = {}
        self._candidate_epochs = None
        self._stage = None
        self._blob = None
        hooks = PolicyHooks(self._resolve_key, self._authorize, self._derive)
        self._verifier = PolicyVerifier(org_id, pinned_root, cloud_policy.empty_authority(org_id), hooks)

    @property
    def head(self):
        with self._lock:
            return self._verifier.head

    @property
    def state(self):
        with self._lock:
            return self._verifier.state

    @property
    def epoch_state(self):
        with self._lock:
            return self._epochs.state

    @property
    def conflict(self):
        with self._lock:
            return self._verifier.conflict

    @property
    def hold_evidence(self):
        with self._lock:
            return copy.deepcopy(self._hold_evidence)

    @staticmethod
    def _checked_runtime(runtime):
        value = dict(runtime or {})
        if value.keys() - {"mode", "now", "observations"}:
            raise ValueError("unsupported offline runtime field")
        return copy.deepcopy(value)

    def _snapshot(self, state, epochs):
        from .cloud_policy import AuthorityView

        view = AuthorityView(state)
        snapshot = view.epoch_snapshot(state["head"], list(self._projects))
        epoch_view = epochs.view(snapshot)
        for broker in snapshot["brokers"]:
            broker["full_custody_generation"] = epoch_view.custody_evidence(broker["id"], state["head"])["full_custody_generation"]
        return snapshot

    def authority_view(self):
        from .cloud_policy import AuthorityView

        with self._lock:
            return AuthorityView(self.state)

    def epoch_view(self):
        with self._lock:
            return self._epochs.view(self._snapshot(self.state, self._epochs))

    def export_checkpoint(self):
        with self._lock:
            if self.conflict:
                raise PolicyError("E_POLICY_CONFLICT", "verifier is in conflict")
            heads = self._verifier.verified_heads
            if (set(heads) != set(range(self.head["seq"] + 1)) or heads.get(0) != ZERO_HASH
                    or heads.get(1) != self._verifier.pinned_root):
                raise PolicyError("E_POLICY_CONFLICT", "complete replay from pinned genesis required")
            if getattr(self, "_finalized_head", None) != self.head:
                raise PolicyError("E_POLICY_CONFLICT", "current ciphertext envelopes require final verification")
            return dict(org_id=self._verifier.org_id, pinned_root=self._verifier.pinned_root,
                        head=self.head, authority=self.state, epochs=self.epoch_state,
                        verified_heads=self._verifier.verified_heads,
                        ciphertext_scope=copy.deepcopy(getattr(self, '_ciphertext_scope', 'full')))

    def finish_history(self, blobs, *, evidence=None):
        """Verify the complete current ciphertext set after historical rewraps."""
        with self._lock:
            if self.conflict:
                raise PolicyError("E_POLICY_CONFLICT", "verifier is in conflict")
            try:
                self._epochs.verify_current_ciphertexts(blobs)
                if self._initial_references:
                    from .cloud_policy import AuthorityEvidence
                    if not isinstance(evidence, AuthorityEvidence):
                        raise ValueError("final initial-slot evidence required")
                    evidence.finalize_references(self._initial_references)
                self._finalized_head = self.head
            except Exception as exc:
                self._verifier.conflict = True
                if isinstance(exc, PolicyError):
                    raise
                raise PolicyError("E_POLICY_CONFLICT", str(exc)) from exc

    def _authority_hooks(self):
        from .cloud_policy import authority_hooks

        return authority_hooks(self._active_runtime)

    def _resolve_key(self, entry, state):
        from .cloud_policy import AUTHORITY_KINDS, AuthorityView
        from .cloud_epochs import EPOCH_KINDS, CIPHERTEXT_KINDS, VERSION_STATE_KINDS

        if entry["kind"] in AUTHORITY_KINDS:
            return self._authority_hooks().resolve_key(entry, state)
        if entry["kind"] not in EPOCH_KINDS | CIPHERTEXT_KINDS | VERSION_STATE_KINDS:
            raise ValueError("Member signer required" if entry["signer"]["kind"] == "broker" else "Unsupported authority entry")
        view, signer = AuthorityView(state), entry["signer"]
        if signer["kind"] == "member":
            cert = view.certificate_at(signer["key"], state["head"]["seq"])
            if not cert or cert["state"] != "active" or cert["member_id"] != signer["id"]:
                raise ValueError("Certified member signer required")
        elif signer["kind"] == "broker":
            cert = view.broker_certificate_at(signer["id"], state["head"])
            if not cert:
                raise ValueError("uncertified epoch broker")
        else:
            raise ValueError("invalid epoch signer")
        return crypto.unb64url(cert["sign_pub"])

    def _authorize(self, entry, state):
        from .cloud_policy import AUTHORITY_KINDS
        from .cloud_epochs import EPOCH_KINDS, CIPHERTEXT_KINDS, VERSION_STATE_KINDS, RECIPIENT_CHANGES

        snapshot = None if entry["kind"] == "genesis" else self._snapshot(state, self._candidate_epochs)
        if entry["kind"] in AUTHORITY_KINDS:
            before = copy.deepcopy(state)
            result = self._authority_hooks().authorize(entry, state)
            if self._active_evidence is not None:
                self._active_evidence.verify_certificate_additions(entry, before, result)
                for wrap in self._active_evidence.confirmed_wraps:
                    self._candidate_epochs.confirm_member_wrap(entry, wrap)
            if snapshot is not None and entry["kind"] in RECIPIENT_CHANGES:
                self._candidate_epochs.observe_authority(entry, snapshot)
            return result
        if entry["kind"] in EPOCH_KINDS | CIPHERTEXT_KINDS | VERSION_STATE_KINDS:
            if state["founder_pending"]:
                raise ValueError("founder certificate required before epochs")
            self._candidate_epochs.apply(entry, snapshot, stage=self._stage, received_at=self._active_runtime["received_at"], blob=self._blob, mode=self._active_runtime["mode"])
            if entry["kind"] == "version_state":
                from .cloud_version_state import authorize
                authorize(entry, state, self._active_runtime)
            committed = {row["id"]: row["digest"] for row in state["core_commitments"]}
            PolicyVerifier._update_commitments(entry, committed)
            state["core_commitments"] = [dict(id=ident, digest=value) for ident, value in committed.items()]
            state["head"] = dict(seq=entry["seq"], hash=crypto.sha256(crypto.canonical_json(entry)).hex())
            return state
        raise ValueError("Unsupported authority entry")

    def _derive(self, entry, state, received_at):
        snapshot = self._snapshot(state, self._candidate_epochs)
        before = copy.deepcopy(state)
        result = self._authority_hooks().derive(entry, state, received_at)
        if self._active_evidence is not None:
            self._active_evidence.verify_certificate_additions(entry, before, result)
        self._candidate_epochs.observe_authority(entry, snapshot)
        return result

    def verify_record(self, record: PolicyRecord, *, stage=None, blob=None, runtime=None, evidence=None):
        from .cloud_wire import parse_signed_entry

        with self._lock:
            if self.conflict:
                raise PolicyError("E_POLICY_CONFLICT", "verifier is in conflict")
            try:
                entry = parse_entry(record.data)
                signed = dict(entry=entry)
                if record.signature is not None:
                    signed["sig"] = crypto.b64url(record.signature)
                parse_signed_entry(signed)
                candidate = copy.deepcopy(self._epochs)
                audits = []
                runtime = dict(self._runtime, **self._checked_runtime(runtime), received_at=record.received_at)
                if runtime.get("submission") or runtime.get("mode", "history") not in ("live", "history"):
                    raise ValueError("invalid offline replay runtime")
                runtime.setdefault("mode", "history")
                runtime.setdefault("now", record.received_at)
                runtime["audit_hold"] = lambda proposal, status: audits.append(dict(proposal_hash=proposal, status=status))
                # The exact predecessor epoch is the only custody source.
                runtime["effective_custody"] = lambda broker, head: candidate.view(self._snapshot(self.state, candidate)).custody_evidence(broker, head)
                runtime["project_exists"] = lambda project: project in self._projects
                self._active_evidence = evidence
                if entry["kind"] == "member_cert" and ("initial_slot_sha256" in entry["body"] or "wrap" in entry["body"]) and evidence is None:
                    raise ValueError("typed initial-slot or confirmation evidence required")
                if evidence is not None:
                    from .cloud_policy import AuthorityEvidence
                    if not isinstance(evidence, AuthorityEvidence):
                        raise ValueError("typed offline authority evidence required")
                    runtime.update(evidence.runtime(committed_generation=lambda head: candidate.view(self._snapshot(self.state, candidate)).committed_generation(head)))
                self._candidate_epochs, self._active_runtime = candidate, runtime
                self._stage, self._blob = copy.deepcopy(stage), copy.deepcopy(blob)
                head = (self._verifier.append(record, utc_millis(record.received_at))
                        if runtime["mode"] == "live" else self._verifier.verify_record(record))
                self._epochs = candidate
                self._finalized_head = None
                self._hold_evidence.extend(dict(item, head=head, observed_at=runtime["now"]) for item in audits)
                if evidence is not None:
                    self._initial_references.extend(evidence.initial_references)
                return head
            except Exception as exc:
                self._verifier.conflict = True
                if isinstance(exc, PolicyError):
                    raise
                raise PolicyError("E_POLICY_CONFLICT", str(exc)) from exc
            finally:
                self._candidate_epochs = self._stage = self._blob = self._active_evidence = None

    def verify_signed(self, signed: dict, received_at: str, *, stage=None, blob=None, runtime=None, evidence=None):
        from .cloud_wire import parse_signed_entry

        with self._lock:
            try:
                value = parse_signed_entry(signed)
                signature = crypto.unb64url(value["sig"]) if "sig" in value else None
                return self.verify_record(policy_record(value["entry"], signature, received_at), stage=stage, blob=blob, runtime=runtime, evidence=evidence)
            except Exception as exc:
                self._verifier.conflict = True
                if isinstance(exc, PolicyError):
                    raise
                raise PolicyError("E_POLICY_CONFLICT", str(exc)) from exc
