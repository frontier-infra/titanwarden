"""Strict cloud wire codecs and proof checks, with no transport or live caller.

Cryptographic operations use tw.crypto. Schema validation never confers authority;
the offline policy and epoch replayers own transitions at a verified predecessor.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from tw import crypto
from tw.policy_log import parse_entry, utc_millis


def exact(value: object, fields, optional=()) -> dict:
    if not isinstance(value, dict) or set(fields) - value.keys() or value.keys() - set(fields) - set(optional):
        raise ValueError("unexpected schema")
    return value


def text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-16-le")) > 8192:
        raise ValueError("invalid identifier")
    return value


def integer(value: object, min: int = 0) -> int:
    crypto.safe_integer(value, True)
    if value < min:
        raise ValueError("integer below minimum")
    return value


def digest(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("invalid digest")
    return value


def org_id(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{32}", value):
        raise ValueError("invalid organization")
    return value


def binary(value: object, size: int, maximum: int | None = None) -> bytes:
    text(value)
    maximum = size if maximum is None else maximum
    if len(value) > (maximum * 4 + 2) // 3:
        raise ValueError("encoded bytes too long")
    raw = crypto.unb64url(value)
    if not size <= len(raw) <= maximum:
        raise ValueError("invalid byte length")
    return raw


def point(value: object) -> str:
    crypto.import_point(binary(value, 65))
    return value


def hash_object(value: object) -> str:
    return crypto.sha256(crypto.canonical_json(value)).hex()


def rank(role: str) -> int:
    return {"member": 1, "approver": 1, "auditor": 1, "admin": 2, "owner": 3}[role]


def parse_head(value: object) -> dict:
    row = exact(value, ("seq", "hash"))
    integer(row["seq"])
    digest(row["hash"])
    return copy.deepcopy(row)


def cose_point(encoded: str) -> bytes:
    """Decode only canonical EC2/ES256/P-256 COSE, with ordered labels."""
    raw = binary(encoded, 1, 256)
    # All labels and fixed values have one canonical representation. Both
    # coordinates must use byte strings of exactly 32 bytes.
    if len(raw) != 77 or raw[:10] != bytes.fromhex("a5010203262001215820") or raw[42:45] != bytes.fromhex("225820"):
        raise ValueError("invalid canonical COSE key")
    result = b"\x04" + raw[10:42] + raw[45:77]
    crypto.import_point(result)
    return result


def der_signature(raw: bytes) -> bytes:
    """Validate minimal positive DER scalars and convert to P1363."""
    try:
        return crypto.der_to_p1363(raw)
    except crypto.CryptoError as exc:
        raise ValueError("Invalid DER signature") from exc


def parse_certificate(value: object, org: str) -> dict:
    org_id(org)
    row = exact(value, ("v", "org_id", "member_id", "workos_user_id", "cert_no", "role", "reveal", "key_holder", "member_key_id", "sign_pub", "kx_pub", "passkeys", "state"))
    if type(row["v"]) is not int or row["v"] != 1 or row["org_id"] != org or row["role"] not in ("owner", "admin", "approver", "auditor", "member") or row["state"] not in ("active", "removed"):
        raise ValueError("invalid certificate")
    for key in ("member_id", "workos_user_id", "member_key_id"):
        text(row[key])
    integer(row["cert_no"], 1)
    point(row["sign_pub"])
    point(row["kx_pub"])
    if type(row["reveal"]) is not bool or type(row["key_holder"]) is not bool or row["key_holder"] != (rank(row["role"]) >= 2 or row["reveal"]):
        raise ValueError("inconsistent key holder")
    if not isinstance(row["passkeys"], list) or len(row["passkeys"]) > 32:
        raise ValueError("invalid passkeys")
    seen = set()
    for raw in row["passkeys"]:
        key = exact(raw, ("credential_id", "cose_key"))
        binary(key["credential_id"], 1, 3072)
        cose_point(key["cose_key"])
        if key["credential_id"] in seen:
            raise ValueError("duplicate credential")
        seen.add(key["credential_id"])
    if row["state"] == "active" and row["key_holder"] and not seen:
        raise ValueError("key holder requires passkey")
    return copy.deepcopy(row)


def parse_broker_certificate(value: object, org: str, project_exists: Callable[[str], bool] | None = None) -> dict:
    org_id(org)
    row = exact(value, ("v", "org_id", "broker_id", "cert_no", "name", "sign_pub", "kx_pub", "scope", "keeper", "local_admin_approvals", "state", "transcript_digest", "wrap_digests"))
    if type(row["v"]) is not int or row["v"] != 1 or row["org_id"] != org or row["state"] not in ("active", "revoked") or type(row["keeper"]) is not bool or type(row["local_admin_approvals"]) is not bool:
        raise ValueError("invalid broker certificate")
    text(row["broker_id"])
    text(row["name"])
    integer(row["cert_no"], 1)
    point(row["sign_pub"])
    point(row["kx_pub"])
    digest(row["transcript_digest"])
    scope = row["scope"]
    if scope != "full":
        if not isinstance(scope, list) or not scope or row["keeper"] or any(not isinstance(p, str) or project_exists is None or not project_exists(p) for p in scope) or scope != sorted(set(scope)):
            raise ValueError("invalid broker scope")
    if not isinstance(row["wrap_digests"], list):
        raise ValueError("invalid wrap commitments")
    seen = set()
    for raw in row["wrap_digests"]:
        item = exact(raw, ("id", "digest"))
        if not isinstance(item["id"], str) or not re.fullmatch(r"enw_[0-9a-f]{32}", item["id"]) or item["id"] in seen:
            raise ValueError("invalid enrollment blob id")
        seen.add(item["id"])
        digest(item["digest"])
    return copy.deepcopy(row)


def parse_requested(value: object, org: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError("requested object required")
    if value.get("kind") == "member":
        row = exact(value, ("kind", "certificate"))
        parse_certificate(row["certificate"], org)
    else:
        row = exact(value, ("kind", "recovery_kx_pub", "recovery_sign_pub"))
        if row["kind"] != "recovery_rotation":
            raise ValueError("unknown requested kind")
        point(row["recovery_kx_pub"])
        point(row["recovery_sign_pub"])
    return copy.deepcopy(row)


def parse_signed_entry(value: object) -> dict:
    if not isinstance(value, dict) or not isinstance(value.get("entry"), dict):
        raise ValueError("signed entry object required")
    entry = parse_entry(crypto.canonical_json(value["entry"]))
    s = entry["signer"]
    kind = s["kind"]
    if kind == "derived":
        exact(value, ("entry",))
    else:
        exact(value, ("entry", "sig"))
        binary(value["sig"], 64)
        if kind == "member":
            exact(s, ("kind", "id", "key"))
        elif kind == "broker":
            exact(s, ("kind", "id"))
        elif kind == "recovery":
            exact(s, ("kind", "id"))
            if s["id"] != "recovery":
                raise ValueError("invalid recovery signer")
        else:
            raise ValueError("unknown signer kind")
    return copy.deepcopy(value)


def parse_authorization(value: object) -> dict:
    a = exact(value, ("v", "dom", "org_id", "actor", "op", "target", "core_change_sha256", "policy_head", "request_id", "challenge", "issued_at", "expires_at"))
    if type(a["v"]) is not int or a["v"] != 2 or a["dom"] != "titanwarden.com/authz" or not isinstance(a["target"], dict):
        raise ValueError("invalid authorization")
    org_id(a["org_id"])
    for value in exact(a["actor"], ("member_id", "member_key_id", "credential_id")).values():
        text(value)
    for key in ("op", "request_id"):
        text(a[key])
    parse_head(a["policy_head"])
    digest(a["core_change_sha256"])
    binary(a["challenge"], 32)
    issued, expires = utc_millis(a["issued_at"]), utc_millis(a["expires_at"])
    if not 0 < expires - issued <= 120000:
        raise ValueError("invalid authorization validity")
    return copy.deepcopy(a)


def _json_object(raw: bytes) -> dict:
    def pairs(items):
        result = {}
        for k, v in items:
            if k in result:
                raise ValueError("duplicate JSON field")
            result[k] = v
        return result
    result = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid JSON number")))
    if not isinstance(result, dict):
        raise ValueError("JSON object required")
    return result


def verify_assertion(assertion: object, passkey: dict, challenge_hash: bytes) -> None:
    a = exact(assertion, ("credential_id", "clientDataJSON", "authenticatorData", "signature"))
    exact(passkey, ("credential_id", "cose_key"))
    if a["credential_id"] != passkey["credential_id"] or len(challenge_hash) != 32:
        raise ValueError("assertion credential mismatch")
    client_bytes = binary(a["clientDataJSON"], 1, 8192)
    client = _json_object(client_bytes)
    if client.get("type") != "webauthn.get" or client.get("challenge") != crypto.b64url(challenge_hash) or client.get("origin") != "https://app.titanwarden.com" or ("crossOrigin" in client and client["crossOrigin"] is not False):
        raise ValueError("invalid WebAuthn client data")
    auth = binary(a["authenticatorData"], 37)
    flags = auth[32]
    if auth[:32] != crypto.sha256(b"titanwarden.com") or flags & 5 != 5 or flags & 0xE2 or (flags & 0x10 and not flags & 0x08):
        raise ValueError("invalid authenticator data")
    signature = der_signature(binary(a["signature"], 8, 72))
    if not crypto.p256_verify(cose_point(passkey["cose_key"]), auth + crypto.sha256(client_bytes), signature):
        raise ValueError("invalid WebAuthn signature")


def _verify_authorization(entry: dict, actor: dict, target: dict, used_challenges, runtime: dict, *, possession=False, request_id=None) -> str:
    """Check a historical proof or a live proof with explicit issued evidence.

    Live callers must recheck the half-open window after their final awaited
    audit. This module has no asynchronous side effects or production caller.
    """
    a = parse_authorization(entry["body"].get("authz"))
    signer = entry["signer"]
    identity = a["actor"]
    signed, issued, expires = map(utc_millis, (entry["ts"], a["issued_at"], a["expires_at"]))
    expected_head = {"seq": entry["seq"] - 1, "hash": entry["prev_hash"]}
    expected_request_id = entry['body'].get('request_id') if request_id is None else request_id
    if a["org_id"] != entry["org_id"] or actor["org_id"] != entry["org_id"] or actor["state"] != "active" or a["op"] != entry["kind"] or crypto.canonical_json(a["target"]) != crypto.canonical_json(target) or a["request_id"] != expected_request_id or (not possession and (identity["member_id"] != signer.get("id") or identity["member_key_id"] != signer.get("key"))) or identity["member_id"] != actor["member_id"] or identity["member_key_id"] != actor["member_key_id"] or a["policy_head"] != expected_head or a["core_change_sha256"] != hash_object(crypto.policy_core_change(entry)) or not issued <= signed <= expires or a["challenge"] in used_challenges:
        raise ValueError("Authorization binding or validity failed")
    if runtime.get("submission"):
        now = utc_millis(runtime["now"])
        if not issued <= now < expires or abs(issued - now) > 300000:
            raise ValueError("authorization expired or not issued")
        lookup = runtime.get("challenge")
        stored = lookup(a["challenge"]) if callable(lookup) else (lookup or {}).get(a["challenge"])
        if not stored or any(stored.get(k) != v for k, v in {"member_id": actor["member_id"], "op": entry["kind"], "issued_at": a["issued_at"], "expires_at": a["expires_at"], "used_at": None}.items()):
            raise ValueError("unknown or consumed challenge")
    if runtime.get("mode", "history") != "history":
        observations = runtime.get("observations", {})
        heads = observations.get("heads", []) if isinstance(observations, dict) else observations.heads
        for head in heads:
            if head["seq"] < expected_head["seq"]:
                continue
            if head["seq"] == expected_head["seq"] and head["hash"] != expected_head["hash"]:
                raise ValueError("observed conflicting predecessor")
            observed = utc_millis(head["observed_at"])
            if observed - signed > 600000 or observed - expires > 600000:
                raise ValueError("verified late admission")
    passkey = next((p for p in actor["passkeys"] if p["credential_id"] == identity["credential_id"]), None)
    if passkey is None:
        raise ValueError("Uncertified passkey")
    verify_assertion(entry["body"].get("assertion"), passkey, crypto.sha256(crypto.canonical_json(a)))
    return a["challenge"]



def verify_authorization(entry, actor, target, used_challenges, runtime):
    return _verify_authorization(entry, actor, target, used_challenges, runtime)


def verify_version_authorization(entry, actor, target, used_challenges, runtime):
    return _verify_authorization(entry, actor, target, used_challenges, runtime,
        request_id=entry['body']['version_id'])


def verify_grant_authorization(entry, actor, target, used_challenges, runtime):
    return _verify_authorization(entry, actor, target, used_challenges, runtime,
        request_id=entry['body']['grant_id'])


def verify_possession_authorization(entry, subject, target, used_challenges, runtime):
    """New credential possession; authority must be verified independently.

    Keep the original outer signer in the core digest, including paper recovery.
    """
    return _verify_authorization(entry, subject, target, used_challenges, runtime, possession=True)


def parse_slot_metadata(value: object) -> dict:
    row = exact(value, ("slot_id", "member_key_id", "kind", "params", "label"))
    text(row["slot_id"])
    text(row["member_key_id"])
    if row["label"] is not None and (not isinstance(row["label"], str) or len(row["label"]) > 4096):
        raise ValueError("invalid slot label")
    if row["kind"] == "webauthn_prf":
        params = exact(row["params"], ("credential_id", "prf_salt"))
        binary(params["credential_id"], 1, 3072)
        binary(params["prf_salt"], 32)
    elif row["kind"] == "passphrase":
        params = exact(row["params"], ("salt", "memory_kib", "iterations", "lanes"))
        binary(params["salt"], 16)
        for key, lo, hi in (("memory_kib", 262144, 1048576), ("iterations", 3, 10), ("lanes", 1, 4)):
            if not lo <= integer(params[key]) <= hi:
                raise ValueError("weak or unbounded slot")
    else:
        raise ValueError("unknown slot kind")
    crypto.canonical_json(row)
    return copy.deepcopy(row)


def slot_metadata(slot: dict) -> dict:
    return parse_slot_metadata({k: slot[k] for k in ("slot_id", "member_key_id", "kind", "params", "label")})


def parse_slot(value: object, certificate: dict | None = None) -> dict:
    row = exact(value, ("slot_id", "member_key_id", "kind", "params", "wrapped_priv", "nonce", "label"))
    slot_metadata(row)
    binary(row["wrapped_priv"], 16, 8192)
    binary(row["nonce"], 12)
    if certificate is not None:
        if row["member_key_id"] != certificate["member_key_id"] or (row["kind"] == "passphrase" and certificate["key_holder"]) or (row["kind"] == "webauthn_prf" and not any(p["credential_id"] == row["params"]["credential_id"] for p in certificate["passkeys"])):
            raise ValueError("slot not bound to certificate")
    return copy.deepcopy(row)


def parse_slot_descriptor(value: object) -> dict:
    row = exact(value, ("slot_id", "member_key_id", "kind", "params", "label", "slot_digest"))
    slot_metadata(row)
    digest(row["slot_digest"])
    return copy.deepcopy(row)


def parse_slot_blob(value: object) -> dict:
    row = exact(value, ("slot_id", "wrapped_priv", "nonce"))
    text(row["slot_id"])
    binary(row["wrapped_priv"], 16, 8192)
    binary(row["nonce"], 12)
    return copy.deepcopy(row)


def parse_recipient(value: object) -> dict:
    row = exact(value, ("kind", "id", "kx_pub_sha256", "wrap_digest"))
    if row["kind"] not in ("member_key", "broker", "recovery"):
        raise ValueError("unknown recipient kind")
    text(row["id"])
    if row["kind"] == "recovery" and row["id"] != "recovery":
        raise ValueError("invalid recovery recipient")
    digest(row["kx_pub_sha256"])
    digest(row["wrap_digest"])
    return copy.deepcopy(row)


def parse_scoped_commitment(value: object) -> dict:
    row = exact(value, ("broker_id", "key_id", "project", "wrap_digest"))
    for key in ("broker_id", "key_id", "project"):
        text(row[key])
    digest(row["wrap_digest"])
    return copy.deepcopy(row)


def parse_key_commitment(value: object) -> dict:
    row = exact(value, ("key_id", "purpose", "scope", "digest"))
    text(row["key_id"])
    text(row["scope"])
    if row["purpose"] not in ("kek", "fingerprint") or (row["purpose"] == "fingerprint" and row["scope"] != "*"):
        raise ValueError("invalid key purpose or scope")
    digest(row["digest"])
    return copy.deepcopy(row)


def slot_blob_digest(blob: object) -> str:
    if not isinstance(blob, dict):
        raise ValueError("slot blob required")
    binary(blob.get("wrapped_priv"), 16, 8192)
    binary(blob.get("nonce"), 12)
    return crypto.sha256(b"tw2|slot-blob|" + crypto.canonical_json({"wrapped_priv": blob["wrapped_priv"], "nonce": blob["nonce"]})).hex()


@dataclass(frozen=True)
class SlotCommitment:
    kind: str
    digest: str

    def __post_init__(self):
        if self.kind not in ("initial_slot", "slot_blob"):
            raise ValueError("unknown slot commitment kind")
        digest(self.digest)

    def matches(self, slot: dict) -> bool:
        return self == slot_commitment(slot, self.kind)


def slot_commitment(slot: dict, kind: str) -> SlotCommitment:
    parsed = parse_slot(slot)
    if kind == "initial_slot":
        value = hash_object(parsed)
    elif kind == "slot_blob":
        value = slot_blob_digest(parsed)
    else:
        raise ValueError("unknown slot commitment kind")
    return SlotCommitment(kind, value)


def member_accept_context(org: str, payload_hash: str) -> bytes:
    org_id(org)
    digest(payload_hash)
    return crypto.member_accept_context(org, payload_hash)


def member_accept_payload(invite_id: str, certificate: dict, slot: dict) -> dict:
    parse_slot(slot, certificate)
    return {"invite_id": text(invite_id), "member_key": copy.deepcopy(certificate), "slot": {**slot_metadata(slot), "commitment_sha256": slot_blob_digest(slot)}}


def verify_member_accept(value: object, org: str, *, private_slot: dict | None = None) -> dict:
    row = exact(value, ("invite_id", "member_key", "slot", "proof"))
    certificate = parse_certificate(row["member_key"], org)
    slot = exact(row["slot"], ("slot_id", "member_key_id", "kind", "params", "label", "commitment_sha256"))
    metadata = slot_metadata(slot)
    digest(slot["commitment_sha256"])
    if certificate["cert_no"] != 1 or certificate["state"] != "active" or metadata["member_key_id"] != certificate["member_key_id"] or (certificate["key_holder"] and metadata["kind"] != "webauthn_prf") or (metadata["kind"] == "webauthn_prf" and not any(p["credential_id"] == metadata["params"]["credential_id"] for p in certificate["passkeys"])):
        raise ValueError("invalid member acceptance")
    payload = {"invite_id": text(row["invite_id"]), "member_key": certificate, "slot": copy.deepcopy(slot)}
    if not crypto.p256_verify(crypto.unb64url(certificate["sign_pub"]), member_accept_context(org, hash_object(payload)), binary(row["proof"], 64)):
        raise ValueError("invalid member possession proof")
    if private_slot is not None and member_accept_payload(row["invite_id"], certificate, private_slot) != payload:
        raise ValueError("member acceptance slot mismatch")
    return payload


def passkey_binding_context(entry: dict) -> bytes:
    return f"tw2|passkey-binding|{org_id(entry['org_id'])}|{hash_object(crypto.policy_core_change(entry))}".encode("ascii")


def load_pinned_json(path: str | Path, expected_sha256: str):
    """Check immutable file bytes before any JSON decoding or parsing."""
    digest(expected_sha256)
    raw = Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("fixture SHA256 mismatch")
    return json.loads(raw.decode("utf-8"))


def vector_key(path: str, index: int, vector: dict) -> tuple[str, int, str]:
    integer(index)
    value = vector.get("value")
    kind = "boolean" if type(value) is bool else "number" if type(value) in (int, float) else "string" if isinstance(value, str) else "null" if value is None else type(value).__name__
    return (path, index, kind)
