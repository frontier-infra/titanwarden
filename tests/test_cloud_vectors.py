from __future__ import annotations
import json
import unittest
from pathlib import Path
from tw import crypto as c
from tw.policy_log import PolicyVerifier, PolicyHooks, PolicyRecord, utc_millis

FIXTURE = json.loads(
    (Path(__file__).parent / "vectors" / "protocol-v2.json").read_text()
)

CONTEXTS = {
    "valueAad": c.value_aad,
    "dekAad": c.dek_aad,
    "legacyKeyringAad": c.keyring_aad,
    "legacySlotAad": c.slot_aad,
    "keyringAad": c.cloud_keyring_aad,
    "orgKeyWrapAad": c.org_key_wrap_aad,
    "brokerKeyWrapAad": c.broker_key_wrap_aad,
    "memberSlotAad": c.member_slot_aad,
    "localKeyAad": c.local_key_aad,
    "localSlotAad": c.local_slot_aad,
    "policyContext": c.policy_context,
    "requestContext": c.request_context,
    "enrollmentContext": c.enrollment_context,
    "checkpointContext": c.checkpoint_context,
    "sasContext": c.sas_context,
    "claimSasContext": c.claim_sas_context,
    "pairContext": c.pair_context,
}
b = bytes.fromhex


def box(v):
    return c.SealedBox(
        b(v["eph_pub"]), b(v["nonce"]), b(v["wrapped"]), v["wrap_digest"]
    )


def fixture_hooks(point):
    def authorize(e, state):
        if e["kind"] not in (
            "genesis",
            "version_add",
            "dek_rewrap",
            "epoch_rotate",
            "epoch_rotate_projects",
        ):
            raise ValueError("authority denied")
        return {"count": state["count"] + 1}

    def derive(e, state, received):
        if e["kind"] != "cert_activate" or e["body"] != {"proposal_hash": "c" * 64}:
            raise ValueError("invalid derived transition")
        return {"count": state["count"] + 1}

    return PolicyHooks(lambda e, s: point, authorize, derive)


def assert_unseal_guard(a):
    if not a.get("guard"):
        return
    sealed = box(a["box"])
    assert (
        c.wrap_digest(sealed.eph_pub, sealed.nonce, sealed.wrapped)
        == sealed.wrap_digest
    ), "fixture fails digest guard"
    if a["guard"] == "length":
        assert (
            len(sealed.wrapped) != 48 or len(sealed.nonce) != 12
        ), "fixture must fail length guard"
        return
    assert (
        len(sealed.wrapped) == 48 and len(sealed.nonce) == 12
    ), "fixture fails early length guard"
    c.import_point(b(a["recipient"]))
    if a["guard"] == "point":
        rejected = False
        try:
            c.import_point(sealed.eph_pub)
        except c.CryptoError:
            rejected = True
        assert rejected, "fixture must fail point guard"
    elif a["guard"] == "gcm":
        c.import_point(sealed.eph_pub)
    else:
        raise AssertionError("unknown fixture guard")


def run_vector(v):
    a, op = v["args"], v["op"]
    if op == "canonical":
        return c.canonical_json(a).hex()
    if op == "parse":
        return c.parse_canonical(b(a))
    if op == "context":
        return CONTEXTS[a["name"]](*a["args"]).hex()
    if op == "query":
        return c.canonical_query(a)
    if op == "sha256":
        return c.sha256(b(a)).hex()
    if op == "hkdf":
        return c.hkdf_sha256(b(a["ikm"]), a["info"], b(a["salt"]), a["length"]).hex()
    if op == "prf":
        return c.derive_prf_slot(b(a)).hex()
    if op == "argon":
        return c.derive_passphrase_slot(
            a["pass"], b(a["salt"]), c.Argon2Params(**a["params"])
        ).hex()
    if op == "paper":
        return c.encode_paper_key(b(a))
    if op == "paper-decode":
        return c.decode_paper_key(a).hex()
    if op == "recovery":
        return c.private_jwk(c.derive_recovery(b(a["key"]), a["purpose"]))
    if op == "policy-core":
        return c.policy_core_change(a)
    if op == "request-core":
        return c.request_core_change(a["body"], a["method"], a["path"])
    if op == "ecdh":
        return c.ecdh(c.import_private(a["jwk"]), b(a["point"])).hex()
    if op == "encrypt":
        return c.aes_encrypt(
            b(a["key"]), b(a["plaintext"]), b(a["aad"]), b(a["nonce"])
        )[0].hex()
    if op == "verify":
        return c.p256_verify(b(a["point"]), b(a["message"]), b(a["signature"]))
    if op == "point":
        c.import_point(b(a))
        return True
    if op == "decrypt":
        return c.aes_decrypt(
            b(a["key"]), b(a["ciphertext"]), b(a["nonce"]), b(a["aad"])
        ).hex()
    if op == "timestamp":
        return utc_millis(a)
    if op == "unseal":
        assert_unseal_guard(a)
        return c.unseal(
            c.import_private(a["jwk"]), b(a["recipient"]), box(a["box"]), b(a["aad"])
        ).hex()
    if op == "value-digest":
        return c.value_digest(b(a["ciphertext"]), b(a["nonce"]))
    if op == "envelope-digest":
        return c.envelope_digest(a["kek"], b(a["wrapped"]), b(a["nonce"]))
    if op == "wrap-digest":
        return c.wrap_digest(b(a["eph_pub"]), b(a["nonce"]), b(a["wrapped"]))
    if op == "object-hash":
        return c.sha256(c.canonical_json(a)).hex()
    if op == "sas":
        return c.sas_words(b(a))
    if op == "policy":
        verifier = PolicyVerifier(
            a["org"], a["root"], {"count": 0}, fixture_hooks(b(a["point"]))
        )
        for r in a["records"]:
            record = PolicyRecord(
                b(r["bytes"]),
                r["hash"],
                b(r["signature"]) if "signature" in r else None,
                r["received_at"],
            )
            if a.get("append"):
                verifier.append(record, a["now"])
            else:
                verifier.verify_record(record)
        if "blob" in a:
            verifier.check_blob(a["blob"]["id"], a["blob"]["digest"])
        return verifier.head
    raise ValueError("unknown vector op " + op)


class SharedVectorsTests(unittest.TestCase):
    def test_manifest(self):
        print(f"Consuming {FIXTURE['count']} shared vectors")
        self.assertEqual(FIXTURE["count"], len(FIXTURE["vectors"]))
        self.assertEqual(FIXTURE["count"], len({v["id"] for v in FIXTURE["vectors"]}))
        self.assertEqual(list(c.SAS_WORDLIST), FIXTURE["wordlist"])
        self.assertEqual(
            c.sha256(("\n".join(c.SAS_WORDLIST) + "\n").encode()).hex(),
            FIXTURE["wordlist_sha256"],
        )

    def test_vectors(self):
        for v in FIXTURE["vectors"]:
            with self.subTest(v["id"]):
                if v.get("error"):
                    if "error_message" in v:
                        with self.assertRaises(c.CryptoError) as caught:
                            run_vector(v)
                        self.assertEqual(str(caught.exception), v["error_message"])
                    else:
                        with self.assertRaises(Exception):
                            run_vector(v)
                else:
                    self.assertEqual(run_vector(v), v["expected"])
