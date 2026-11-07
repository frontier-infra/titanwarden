"""Titanwarden cryptographic primitives.

This is the only module permitted to import ``cryptography``. Callers provide
row identity to the AAD helpers so ciphertext cannot be moved between rows.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as stdlib_hmac
import json
import re
import os
import secrets
from dataclasses import dataclass
from typing import Final, Literal
from urllib.parse import quote

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


KEY_BYTES: Final = 32
NONCE_BYTES: Final = 12
SALT_BYTES: Final = 16
MIN_PASSPHRASE_LENGTH: Final = 30
ARGON2_MEMORY_KIB: Final = 1_048_576
ARGON2_ITERATIONS: Final = 3
ARGON2_LANES: Final = 4


class CryptoError(Exception):
    """Authenticated decryption or key derivation failed."""

    code = "E_INTEGRITY"


@dataclass(frozen=True, slots=True)
class Argon2Params:
    memory_kib: int = ARGON2_MEMORY_KIB
    iterations: int = ARGON2_ITERATIONS
    lanes: int = ARGON2_LANES
    length: int = KEY_BYTES

    def as_dict(self, salt: bytes) -> dict[str, object]:
        return {
            "kdf": "argon2id",
            "memory_kib": self.memory_kib,
            "iterations": self.iterations,
            "lanes": self.lanes,
            "length": self.length,
            "salt": base64.urlsafe_b64encode(salt).decode("ascii").rstrip("="),
        }

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> tuple[Argon2Params, bytes]:
        if value.get("kdf") != "argon2id":
            raise CryptoError("unsupported passphrase KDF")
        encoded = str(value["salt"])
        salt = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        params = cls(
            memory_kib=int(value["memory_kib"]),
            iterations=int(value["iterations"]),
            lanes=int(value["lanes"]),
            length=int(value.get("length", KEY_BYTES)),
        )
        return params, salt


def random_key() -> bytes:
    return os.urandom(KEY_BYTES)


def random_nonce() -> bytes:
    return os.urandom(NONCE_BYTES)


def recovery_key() -> bytes:
    return random_key()


def encode_recovery_key(value: bytes) -> str:
    if len(value) != KEY_BYTES:
        raise ValueError("recovery key must be 32 bytes")
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def decode_recovery_key(value: str) -> bytes:
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError as exc:
        raise CryptoError("invalid recovery key") from exc
    if len(raw) != KEY_BYTES:
        raise CryptoError("invalid recovery key")
    return raw


def derive_passphrase_key(
    passphrase: str,
    salt: bytes,
    params: Argon2Params | None = None,
    *,
    enforce_strength: bool = True,
) -> bytes:
    if enforce_strength and len(passphrase) < MIN_PASSPHRASE_LENGTH:
        raise ValueError("passphrase must be at least 30 characters")
    selected = params or Argon2Params()
    kdf = Argon2id(
        salt=salt,
        length=selected.length,
        iterations=selected.iterations,
        lanes=selected.lanes,
        memory_cost=selected.memory_kib,
        ad=None,
        secret=None,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def hkdf(key: bytes, info: bytes, *, salt: bytes | None = None) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=salt,
        info=info,
    ).derive(key)


def derive_recovery_slot_key(value: bytes) -> bytes:
    return hkdf(value, b"tw1 slot-recovery")


def _aad(*parts: object) -> bytes:
    return context(*parts)


def value_aad(store_id: str, secret_id: str, version_no: int) -> bytes:
    return _aad("tw1", "val", store_id, secret_id, version_no)


def dek_aad(store_id: str, version_id: str, kek_id: str) -> bytes:
    return _aad("tw1", "dek", store_id, version_id, kek_id)


def keyring_aad(store_id: str, key_id: str, purpose: str, mk_generation: int) -> bytes:
    return _aad("tw1", "key", store_id, key_id, purpose, mk_generation)


def slot_aad(store_id: str, slot_id: str, mk_generation: int) -> bytes:
    return _aad("tw1", "slot", store_id, slot_id, mk_generation)


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    nonce = random_nonce()
    return AESGCM(key).encrypt(nonce, plaintext, aad), nonce


def decrypt(key: bytes, ciphertext: bytes, nonce: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except (InvalidTag, ValueError) as exc:
        raise CryptoError("authenticated decryption failed") from exc


def wrap_key(wrapping_key: bytes, key: bytes, aad: bytes) -> tuple[bytes, bytes]:
    if len(key) != KEY_BYTES:
        raise ValueError("wrapped keys must be 32 bytes")
    return encrypt(wrapping_key, key, aad)


def unwrap_key(
    wrapping_key: bytes, wrapped_key: bytes, nonce: bytes, aad: bytes
) -> bytes:
    key = decrypt(wrapping_key, wrapped_key, nonce, aad)
    if len(key) != KEY_BYTES:
        raise CryptoError("unwrapped key has invalid length")
    return key


def fingerprint(key: bytes, value: bytes) -> bytes:
    return stdlib_hmac.new(key, value, hashlib.sha256).digest()[:16]


def cloud_fingerprint(key: bytes, value: bytes) -> bytes:
    return stdlib_hmac.new(key, value, hashlib.sha256).digest()


def audit_mac(key: bytes, digest: bytes) -> bytes:
    signer = hmac.HMAC(key, hashes.SHA256())
    signer.update(digest)
    return signer.finalize()


def verify_audit_mac(key: bytes, digest: bytes, mac_value: bytes) -> bool:
    return stdlib_hmac.compare_digest(audit_mac(key, digest), mac_value)


def token_hash(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


def new_token(token_id: str) -> str:
    random_part = (
        base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    )
    return f"twt_{token_id}_{random_part}"


def compare_token(candidate: str, expected_hash: bytes) -> bool:
    return stdlib_hmac.compare_digest(token_hash(candidate), expected_hash)


def compare_digest(left: bytes, right: bytes) -> bool:
    return stdlib_hmac.compare_digest(left, right)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


KeyPurpose = Literal["kek", "audit_mac", "fingerprint"]


# Cloud protocol v2. Legacy single-tenant helpers above retain their exact bytes.

SAFE_INTEGER = 2**53 - 1
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def safe_integer(value: object, nonnegative: bool = False) -> int:
    if (
        type(value) is not int
        or abs(value) > SAFE_INTEGER
        or (nonnegative and value < 0)
    ):
        raise ValueError("invalid integer")
    return value


def _valid_string(value: str) -> str:
    value.encode("utf-8", errors="strict")
    return value


def canonical_json(value: object) -> bytes:
    def check(item: object, seen: set[int]) -> None:
        if item is None or type(item) is bool:
            return
        if type(item) is int:
            safe_integer(item)
        elif type(item) is str:
            _valid_string(item)
        elif type(item) in (list, dict):
            if id(item) in seen:
                raise ValueError("cyclic object")
            seen.add(id(item))
            if type(item) is dict:
                for key, val in item.items():
                    if type(key) is not str or not key.isascii():
                        raise ValueError("non-ASCII key")
                    check(val, seen)
            else:
                for val in item:
                    check(val, seen)
            seen.remove(id(item))
        else:
            raise ValueError("invalid canonical type")

    check(value, set())
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def parse_canonical(data: bytes) -> object:
    value = json.loads(data.decode("utf-8", errors="strict"))
    if canonical_json(value) != data:
        raise ValueError("non-canonical bytes")
    return value


def context(*parts: str | int) -> bytes:
    result = []
    for part in parts:
        if type(part) is int:
            result.append(str(safe_integer(part, True)))
        elif (
            type(part) is str
            and part
            and re.fullmatch(r"[\x20-\x7e]+", part)
            and "|" not in part
        ):
            result.append(part)
        else:
            raise ValueError("invalid context field")
    return "|".join(result).encode("ascii")


def cloud_keyring_aad(
    org: str, key: str, purpose: str, scope: str, generation: int
) -> bytes:
    return context("tw2", "key", org, key, purpose, scope, generation)


def org_key_wrap_aad(org: str, kind: str, recipient: str, generation: int) -> bytes:
    return context("tw2", "okw", org, kind, recipient, generation)


def broker_key_wrap_aad(
    org: str, broker: str, key: str, purpose: str, scope: str
) -> bytes:
    return context("tw2", "bkw", org, broker, key, purpose, scope)


def member_slot_aad(org: str, member: str, key: str, slot: str) -> bytes:
    return context("tw2", "mks", org, member, key, slot)


def local_key_aad(
    org: str, broker: str, key: str, purpose: str, scope: str, generation: int
) -> bytes:
    return context("tw2", "blk", org, broker, key, purpose, scope, generation)


def local_slot_aad(org: str, broker: str, slot: str, generation: int) -> bytes:
    return context("tw2", "slot", org, broker, slot, generation)


def policy_context(org: str, digest: str) -> bytes:
    return context("tw2", "pol", org, digest)


def canonical_query(params: list[tuple[str, str]]) -> str:
    for key, value in params:
        _valid_string(key)
        _valid_string(value)
    return (
        "&".join(
            quote(key, safe="-._~") + "=" + quote(value, safe="-._~")
            for key, value in sorted(params)
        )
        or "-"
    )


def request_context(
    org: str,
    broker: str,
    method: str,
    path: str,
    query: list[tuple[str, str]],
    request: str,
    ts: str,
    nonce: str,
    digest: str,
) -> bytes:
    return context(
        "tw2",
        "req",
        org,
        broker,
        method,
        path,
        canonical_query(query),
        request,
        ts,
        nonce,
        digest,
    )


def enrollment_context(org: str, ticket: str, transcript_hash: str) -> bytes:
    return context("tw2", "enroll", org, ticket, transcript_hash)


_MISSING_RECEIPT_FIELD = object()


def checkpoint_context(
    org: str,
    chain: str,
    seq: int,
    digest: str,
    ts: str,
    receipt: bool = False,
    checkpoint_sig: object = _MISSING_RECEIPT_FIELD,
    key_id: object = _MISSING_RECEIPT_FIELD,
    issued_at: object = _MISSING_RECEIPT_FIELD,
) -> bytes:
    if type(receipt) is not bool:
        raise ValueError("invalid checkpoint mode")
    ack = context("tw2", "ack", org, chain, seq, digest, ts)
    if not receipt:
        if any(value is not _MISSING_RECEIPT_FIELD for value in (checkpoint_sig, key_id, issued_at)):
            raise ValueError("receipt fields require receipt context")
        return ack
    if (
        (checkpoint_sig is not None and type(checkpoint_sig) is not str)
        or type(key_id) is not str or not key_id
        or type(issued_at) is not str or not issued_at
    ):
        raise ValueError("receipt issuance evidence required")
    return context("tw2", "rcpt", org, chain) + b"|" + canonical_json({
        "seq": seq, "hash": digest, "ts": ts, "sig": checkpoint_sig,
        "key_id": key_id, "issued_at": issued_at,
    })


def sas_context(
    org: str, root: str, kind: str, subject: str, sign: str, kx: str
) -> bytes:
    return context("tw2", "sas", org, root, kind, subject, sign, kx)


def claim_sas_context(
    org: str,
    root: str,
    broker: str,
    sign: str,
    kx: str,
    member_key: str,
    member_sign: str,
    member_kx: str,
) -> bytes:
    return context(
        "tw2",
        "sas",
        org,
        root,
        "claim",
        broker,
        sign,
        kx,
        member_key,
        member_sign,
        member_kx,
    )


def pair_context(org: str, root: str, seq: int, digest: str) -> bytes:
    return context("tw2", "pair", org, root, seq, digest)


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def unb64url(value: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]*", value):
        raise CryptoError("cryptographic operation failed")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        if b64url(raw) != value:
            raise ValueError()
        return raw
    except ValueError as exc:
        raise CryptoError("cryptographic operation failed") from exc


def hkdf_sha256(ikm: bytes, info: str, salt: bytes = b"", length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=length, salt=salt, info=info.encode("utf-8")
    ).derive(ikm)


def import_point(point: bytes) -> ec.EllipticCurvePublicKey:
    try:
        if len(point) != 65 or point[0] != 4:
            raise ValueError()
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    except ValueError as exc:
        raise CryptoError("cryptographic operation failed") from exc


def export_point(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def generate_p256_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def private_jwk(key: ec.EllipticCurvePrivateKey) -> dict[str, object]:
    n = key.private_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "d": b64url(n.private_value.to_bytes(32, "big")),
        "x": b64url(n.public_numbers.x.to_bytes(32, "big")),
        "y": b64url(n.public_numbers.y.to_bytes(32, "big")),
        "ext": True,
    }


def import_private(jwk: dict[str, object]) -> ec.EllipticCurvePrivateKey:
    try:
        if jwk["kty"] != "EC" or jwk["crv"] != "P-256":
            raise ValueError()
        d = unb64url(jwk["d"])
        x, y = unb64url(jwk["x"]), unb64url(jwk["y"])
        if len(d) != 32 or len(x) != 32 or len(y) != 32:
            raise ValueError()
        return ec.EllipticCurvePrivateNumbers(
            int.from_bytes(d, "big"),
            ec.EllipticCurvePublicNumbers(
                int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
            ),
        ).private_key()
    except (ValueError, KeyError, TypeError) as exc:
        raise CryptoError("cryptographic operation failed") from exc


def p256_sign(key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    r, s = utils.decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def der_to_p1363(raw: bytes) -> bytes:
    """Accept only minimal DER with positive, in-range P-256 scalars."""
    try:
        if not isinstance(raw, bytes) or not 8 <= len(raw) <= 72 or raw[0] != 0x30 or raw[1] != len(raw) - 2:
            raise ValueError()
        r, s = utils.decode_dss_signature(raw)
        order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        if not 0 < r < order or not 0 < s < order:
            raise ValueError()
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    except (ValueError, TypeError) as exc:
        raise CryptoError("cryptographic operation failed") from exc


def member_accept_context(org: str, payload_hash: str) -> bytes:
    return context("tw2", "maccept", org, payload_hash)


def p256_verify(point: bytes, message: bytes, signature: bytes) -> bool:
    try:
        if len(signature) != 64:
            return False
        der = utils.encode_dss_signature(
            int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
        )
        import_point(point).verify(der, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, CryptoError):
        return False


def aes_encrypt(
    key: bytes, plaintext: bytes, aad: bytes, nonce: bytes | None = None
) -> tuple[bytes, bytes]:
    nonce = random_nonce() if nonce is None else nonce
    if len(key) != 32 or len(nonce) != 12:
        raise CryptoError("cryptographic operation failed")
    return AESGCM(key).encrypt(nonce, plaintext, aad), nonce


def aes_decrypt(key: bytes, ciphertext: bytes, nonce: bytes, aad: bytes) -> bytes:
    try:
        if len(key) != 32 or len(nonce) != 12 or len(ciphertext) < 16:
            raise ValueError()
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except (InvalidTag, ValueError) as exc:
        raise CryptoError("cryptographic operation failed") from exc


@dataclass(frozen=True)
class SealedBox:
    eph_pub: bytes
    nonce: bytes
    wrapped: bytes
    wrap_digest: str


def wrap_digest(eph_pub: bytes, nonce: bytes, wrapped: bytes) -> str:
    return sha256(eph_pub + nonce + wrapped).hex()


def seal(recipient: bytes, key: bytes, aad: bytes) -> SealedBox:
    if len(key) != 32:
        raise CryptoError("cryptographic operation failed")
    pub = import_point(recipient)
    eph = generate_p256_key()
    eph_pub = export_point(eph.public_key())
    z = eph.exchange(ec.ECDH(), pub)
    k = hkdf_sha256(z, "tw2 wrap", eph_pub + recipient)
    wrapped, nonce = aes_encrypt(k, key, aad)
    return SealedBox(eph_pub, nonce, wrapped, wrap_digest(eph_pub, nonce, wrapped))


def unseal(
    private_key: ec.EllipticCurvePrivateKey,
    recipient: bytes,
    box: SealedBox,
    aad: bytes,
) -> bytes:
    try:
        if (
            len(box.nonce) != 12
            or len(box.wrapped) != 48
            or wrap_digest(box.eph_pub, box.nonce, box.wrapped) != box.wrap_digest
        ):
            raise ValueError()
        import_point(recipient)
        z = private_key.exchange(ec.ECDH(), import_point(box.eph_pub))
        k = hkdf_sha256(z, "tw2 wrap", box.eph_pub + recipient)
        result = aes_decrypt(k, box.wrapped, box.nonce, aad)
        if len(result) != 32:
            raise ValueError()
        return result
    except (ValueError, CryptoError) as exc:
        raise CryptoError("cryptographic operation failed") from exc


def derive_recovery(value: bytes, purpose: str) -> ec.EllipticCurvePrivateKey:
    if len(value) != 32 or purpose not in ("kx", "sign"):
        raise CryptoError("cryptographic operation failed")
    raw = hkdf_sha256(value, "tw2 recovery-" + purpose, length=48)
    return ec.derive_private_key(
        int.from_bytes(raw, "big") % (P256_ORDER - 1) + 1, ec.SECP256R1()
    )


def encode_paper_key(value: bytes) -> str:
    if len(value) != 32:
        raise CryptoError("cryptographic operation failed")
    raw = base64.b32encode(value).decode("ascii").rstrip("=")
    return " ".join(raw[i : i + 4] for i in range(0, 52, 4))


def decode_paper_key(value: str) -> bytes:
    raw = value.replace(" ", "")
    try:
        if not re.fullmatch(r"[A-Z2-7]{52}", raw) or (
            value != raw and not re.fullmatch(r"(?:[A-Z2-7]{4} ){12}[A-Z2-7]{4}", value)
        ):
            raise ValueError()
        key = base64.b32decode(raw + "====")
        if encode_paper_key(key).replace(" ", "") != raw:
            raise ValueError()
        return key
    except ValueError as exc:
        raise CryptoError("cryptographic operation failed") from exc


def derive_prf_slot(prf: bytes) -> bytes:
    if len(prf) != 32:
        raise CryptoError("cryptographic operation failed")
    return hkdf_sha256(prf, "tw2 slot-prf")


def derive_passphrase_slot(
    passphrase: str, salt: bytes, params: Argon2Params | None = None
) -> bytes:
    p = params or Argon2Params(memory_kib=262144, iterations=3, lanes=1)
    for n in (p.memory_kib, p.iterations, p.lanes):
        safe_integer(n, True)
    if (
        not 1 <= p.lanes <= 4
        or not 8 * p.lanes <= p.memory_kib <= 1048576
        or not 1 <= p.iterations <= 10
        or p.length != 32
        or len(salt) != 16
        or len(passphrase) < 20
    ):
        raise CryptoError("cryptographic operation failed")
    _valid_string(passphrase)
    return derive_passphrase_key(passphrase, salt, p, enforce_strength=False)


def sas_words(transcript: bytes) -> str:
    """Six 11-bit indices, MSB first, in the pinned BIP39 English list."""
    wordlist = SAS_WORDLIST
    first = int.from_bytes(sha256(transcript), "big") >> (256 - 66)
    return " ".join(wordlist[(first >> (55 - i * 11)) & 2047] for i in range(6))


def value_digest(ciphertext: bytes, nonce: bytes) -> str:
    return sha256(ciphertext + nonce).hex()


def envelope_digest(kek: str, wrapped: bytes, nonce: bytes) -> str:
    return sha256(kek.encode("utf-8") + wrapped + nonce).hex()


# BIP39 English, pinned by the shared vector manifest.
SAS_WORDLIST = tuple(
    """
abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid
acoustic acquire across act action actor actress actual adapt add addict address adjust admit adult advance
advice aerobic affair afford afraid again age agent agree ahead aim air airport aisle alarm album
alcohol alert alien all alley allow almost alone alpha already also alter always amateur amazing among
amount amused analyst anchor ancient anger angle angry animal ankle announce annual another answer antenna antique
anxiety any apart apology appear apple approve april arch arctic area arena argue arm armed armor
army around arrange arrest arrive arrow art artefact artist artwork ask aspect assault asset assist assume
asthma athlete atom attack attend attitude attract auction audit august aunt author auto autumn average avocado
avoid awake aware away awesome awful awkward axis baby bachelor bacon badge bag balance balcony ball
bamboo banana banner bar barely bargain barrel base basic basket battle beach bean beauty because become
beef before begin behave behind believe below belt bench benefit best betray better between beyond bicycle
bid bike bind biology bird birth bitter black blade blame blanket blast bleak bless blind blood
blossom blouse blue blur blush board boat body boil bomb bone bonus book boost border boring
borrow boss bottom bounce box boy bracket brain brand brass brave bread breeze brick bridge brief
bright bring brisk broccoli broken bronze broom brother brown brush bubble buddy budget buffalo build bulb
bulk bullet bundle bunker burden burger burst bus business busy butter buyer buzz cabbage cabin cable
cactus cage cake call calm camera camp can canal cancel candy cannon canoe canvas canyon capable
capital captain car carbon card cargo carpet carry cart case cash casino castle casual cat catalog
catch category cattle caught cause caution cave ceiling celery cement census century cereal certain chair chalk
champion change chaos chapter charge chase chat cheap check cheese chef cherry chest chicken chief child
chimney choice choose chronic chuckle chunk churn cigar cinnamon circle citizen city civil claim clap clarify
claw clay clean clerk clever click client cliff climb clinic clip clock clog close cloth cloud
clown club clump cluster clutch coach coast coconut code coffee coil coin collect color column combine
come comfort comic common company concert conduct confirm congress connect consider control convince cook cool copper
copy coral core corn correct cost cotton couch country couple course cousin cover coyote crack cradle
craft cram crane crash crater crawl crazy cream credit creek crew cricket crime crisp critic crop
cross crouch crowd crucial cruel cruise crumble crunch crush cry crystal cube culture cup cupboard curious
current curtain curve cushion custom cute cycle dad damage damp dance danger daring dash daughter dawn
day deal debate debris decade december decide decline decorate decrease deer defense define defy degree delay
deliver demand demise denial dentist deny depart depend deposit depth deputy derive describe desert design desk
despair destroy detail detect develop device devote diagram dial diamond diary dice diesel diet differ digital
dignity dilemma dinner dinosaur direct dirt disagree discover disease dish dismiss disorder display distance divert divide
divorce dizzy doctor document dog doll dolphin domain donate donkey donor door dose double dove draft
dragon drama drastic draw dream dress drift drill drink drip drive drop drum dry duck dumb
dune during dust dutch duty dwarf dynamic eager eagle early earn earth easily east easy echo
ecology economy edge edit educate effort egg eight either elbow elder electric elegant element elephant elevator
elite else embark embody embrace emerge emotion employ empower empty enable enact end endless endorse enemy
energy enforce engage engine enhance enjoy enlist enough enrich enroll ensure enter entire entry envelope episode
equal equip era erase erode erosion error erupt escape essay essence estate eternal ethics evidence evil
evoke evolve exact example excess exchange excite exclude excuse execute exercise exhaust exhibit exile exist exit
exotic expand expect expire explain expose express extend extra eye eyebrow fabric face faculty fade faint
faith fall false fame family famous fan fancy fantasy farm fashion fat fatal father fatigue fault
favorite feature february federal fee feed feel female fence festival fetch fever few fiber fiction field
figure file film filter final find fine finger finish fire firm first fiscal fish fit fitness
fix flag flame flash flat flavor flee flight flip float flock floor flower fluid flush fly
foam focus fog foil fold follow food foot force forest forget fork fortune forum forward fossil
foster found fox fragile frame frequent fresh friend fringe frog front frost frown frozen fruit fuel
fun funny furnace fury future gadget gain galaxy gallery game gap garage garbage garden garlic garment
gas gasp gate gather gauge gaze general genius genre gentle genuine gesture ghost giant gift giggle
ginger giraffe girl give glad glance glare glass glide glimpse globe gloom glory glove glow glue
goat goddess gold good goose gorilla gospel gossip govern gown grab grace grain grant grape grass
gravity great green grid grief grit grocery group grow grunt guard guess guide guilt guitar gun
gym habit hair half hammer hamster hand happy harbor hard harsh harvest hat have hawk hazard
head health heart heavy hedgehog height hello helmet help hen hero hidden high hill hint hip
hire history hobby hockey hold hole holiday hollow home honey hood hope horn horror horse hospital
host hotel hour hover hub huge human humble humor hundred hungry hunt hurdle hurry hurt husband
hybrid ice icon idea identify idle ignore ill illegal illness image imitate immense immune impact impose
improve impulse inch include income increase index indicate indoor industry infant inflict inform inhale inherit initial
inject injury inmate inner innocent input inquiry insane insect inside inspire install intact interest into invest
invite involve iron island isolate issue item ivory jacket jaguar jar jazz jealous jeans jelly jewel
job join joke journey joy judge juice jump jungle junior junk just kangaroo keen keep ketchup
key kick kid kidney kind kingdom kiss kit kitchen kite kitten kiwi knee knife knock know
lab label labor ladder lady lake lamp language laptop large later latin laugh laundry lava law
lawn lawsuit layer lazy leader leaf learn leave lecture left leg legal legend leisure lemon lend
length lens leopard lesson letter level liar liberty library license life lift light like limb limit
link lion liquid list little live lizard load loan lobster local lock logic lonely long loop
lottery loud lounge love loyal lucky luggage lumber lunar lunch luxury lyrics machine mad magic magnet
maid mail main major make mammal man manage mandate mango mansion manual maple marble march margin
marine market marriage mask mass master match material math matrix matter maximum maze meadow mean measure
meat mechanic medal media melody melt member memory mention menu mercy merge merit merry mesh message
metal method middle midnight milk million mimic mind minimum minor minute miracle mirror misery miss mistake
mix mixed mixture mobile model modify mom moment monitor monkey monster month moon moral more morning
mosquito mother motion motor mountain mouse move movie much muffin mule multiply muscle museum mushroom music
must mutual myself mystery myth naive name napkin narrow nasty nation nature near neck need negative
neglect neither nephew nerve nest net network neutral never news next nice night noble noise nominee
noodle normal north nose notable note nothing notice novel now nuclear number nurse nut oak obey
object oblige obscure observe obtain obvious occur ocean october odor off offer office often oil okay
old olive olympic omit once one onion online only open opera opinion oppose option orange orbit
orchard order ordinary organ orient original orphan ostrich other outdoor outer output outside oval oven over
own owner oxygen oyster ozone pact paddle page pair palace palm panda panel panic panther paper
parade parent park parrot party pass patch path patient patrol pattern pause pave payment peace peanut
pear peasant pelican pen penalty pencil people pepper perfect permit person pet phone photo phrase physical
piano picnic picture piece pig pigeon pill pilot pink pioneer pipe pistol pitch pizza place planet
plastic plate play please pledge pluck plug plunge poem poet point polar pole police pond pony
pool popular portion position possible post potato pottery poverty powder power practice praise predict prefer prepare
present pretty prevent price pride primary print priority prison private prize problem process produce profit program
project promote proof property prosper protect proud provide public pudding pull pulp pulse pumpkin punch pupil
puppy purchase purity purpose purse push put puzzle pyramid quality quantum quarter question quick quit quiz
quote rabbit raccoon race rack radar radio rail rain raise rally ramp ranch random range rapid
rare rate rather raven raw razor ready real reason rebel rebuild recall receive recipe record recycle
reduce reflect reform refuse region regret regular reject relax release relief rely remain remember remind remove
render renew rent reopen repair repeat replace report require rescue resemble resist resource response result retire
retreat return reunion reveal review reward rhythm rib ribbon rice rich ride ridge rifle right rigid
ring riot ripple risk ritual rival river road roast robot robust rocket romance roof rookie room
rose rotate rough round route royal rubber rude rug rule run runway rural sad saddle sadness
safe sail salad salmon salon salt salute same sample sand satisfy satoshi sauce sausage save say
scale scan scare scatter scene scheme school science scissors scorpion scout scrap screen script scrub sea
search season seat second secret section security seed seek segment select sell seminar senior sense sentence
series service session settle setup seven shadow shaft shallow share shed shell sheriff shield shift shine
ship shiver shock shoe shoot shop short shoulder shove shrimp shrug shuffle shy sibling sick side
siege sight sign silent silk silly silver similar simple since sing siren sister situate six size
skate sketch ski skill skin skirt skull slab slam sleep slender slice slide slight slim slogan
slot slow slush small smart smile smoke smooth snack snake snap sniff snow soap soccer social
sock soda soft solar soldier solid solution solve someone song soon sorry sort soul sound soup
source south space spare spatial spawn speak special speed spell spend sphere spice spider spike spin
spirit split spoil sponsor spoon sport spot spray spread spring spy square squeeze squirrel stable stadium
staff stage stairs stamp stand start state stay steak steel stem step stereo stick still sting
stock stomach stone stool story stove strategy street strike strong struggle student stuff stumble style subject
submit subway success such sudden suffer sugar suggest suit summer sun sunny sunset super supply supreme
sure surface surge surprise surround survey suspect sustain swallow swamp swap swarm swear sweet swift swim
swing switch sword symbol symptom syrup system table tackle tag tail talent talk tank tape target
task taste tattoo taxi teach team tell ten tenant tennis tent term test text thank that
theme then theory there they thing this thought three thrive throw thumb thunder ticket tide tiger
tilt timber time tiny tip tired tissue title toast tobacco today toddler toe together toilet token
tomato tomorrow tone tongue tonight tool tooth top topic topple torch tornado tortoise toss total tourist
toward tower town toy track trade traffic tragic train transfer trap trash travel tray treat tree
trend trial tribe trick trigger trim trip trophy trouble truck true truly trumpet trust truth try
tube tuition tumble tuna tunnel turkey turn turtle twelve twenty twice twin twist two type typical
ugly umbrella unable unaware uncle uncover under undo unfair unfold unhappy uniform unique unit universe unknown
unlock until unusual unveil update upgrade uphold upon upper upset urban urge usage use used useful
useless usual utility vacant vacuum vague valid valley valve van vanish vapor various vast vault vehicle
velvet vendor venture venue verb verify version very vessel veteran viable vibrant vicious victory video view
village vintage violin virtual virus visa visit visual vital vivid vocal voice void volcano volume vote
voyage wage wagon wait walk wall walnut want warfare warm warrior wash wasp waste water wave
way wealth weapon wear weasel weather web wedding weekend weird welcome west wet whale what wheat
wheel when where whip whisper wide width wife wild will win window wine wing wink winner
winter wire wisdom wise wish witness wolf woman wonder wood wool word work world worry worth
wrap wreck wrestle wrist write wrong yard year yellow you young youth zebra zero zone zoo
""".split()
)


def ecdh(private_key: ec.EllipticCurvePrivateKey, point: bytes) -> bytes:
    try:
        return private_key.exchange(ec.ECDH(), import_point(point))
    except (ValueError, CryptoError) as exc:
        raise CryptoError("cryptographic operation failed") from exc


def policy_core_change(entry: dict) -> dict:
    return {
        "kind": entry["kind"],
        "prev_hash": entry["prev_hash"],
        "signer": entry["signer"],
        "body": {
            k: v for k, v in entry["body"].items() if k not in ("authz", "assertion")
        },
    }


def request_core_change(body: dict, method: str, path: str) -> dict:
    core = {k: v for k, v in body.items() if k not in ("authz", "assertion")}
    if "method" in core or "path" in core:
        raise ValueError("reserved core change field")
    return {**core, "method": method, "path": path}
