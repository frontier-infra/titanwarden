from __future__ import annotations
import unittest
from tw import crypto as c
from tw.policy_log import (
    PolicyError,
    PolicyHooks,
    PolicyVerifier,
    PolicyRecord,
    utc_millis,
)
from test_cloud_vectors import FIXTURE, fixture_hooks, box

A = next(v["args"] for v in FIXTURE["vectors"] if v["id"] == "policy-valid-history")
RECORDS = [
    PolicyRecord(
        bytes.fromhex(r["bytes"]),
        r["hash"],
        bytes.fromhex(r["signature"]) if "signature" in r else None,
        r["received_at"],
    )
    for r in A["records"]
]


def verifier(hooks=None):
    return PolicyVerifier(
        A["org"],
        A["root"],
        {"count": 0},
        hooks or fixture_hooks(bytes.fromhex(A["point"])),
    )


class PolicyLogTests(unittest.TestCase):
    def test_hooks_required(self):
        with self.assertRaises(ValueError):
            PolicyVerifier(A["org"], A["root"], {}, None)

    def test_checkpoint_state_copies(self):
        v = verifier()
        v.verify_record(RECORDS[0])
        head, state = v.head, v.state
        head["seq"], state["count"] = 99, 99
        self.assertEqual(v.head["seq"], 1)
        self.assertEqual(v.state["count"], 1)

    def test_bad_authority_preserves_checkpoint_and_fails_closed(self):
        hooks = fixture_hooks(bytes.fromhex(A["point"]))

        def authorize(e, state):
            if e["seq"] == 2:
                state["count"] = 100
                raise ValueError("authority denied")
            return hooks.authorize(e, state)

        v = verifier(PolicyHooks(hooks.resolve_key, authorize, hooks.derive))
        v.verify_record(RECORDS[0])
        for _ in range(2):
            with self.assertRaises(PolicyError) as caught:
                v.verify_record(RECORDS[1])
            self.assertEqual(caught.exception.code, "E_POLICY_CONFLICT")
        self.assertEqual(v.head["seq"], 1)
        self.assertEqual(v.state["count"], 1)
        self.assertEqual(v.commitments, [])

    def test_stale_head_can_retry_without_conflict(self):
        v = verifier()
        v.verify_record(RECORDS[0])
        with self.assertRaises(PolicyError) as caught:
            v.append(RECORDS[0], utc_millis(RECORDS[0].received_at))
        self.assertEqual(caught.exception.code, "E_POLICY_HEAD")
        self.assertFalse(v.conflict)
        v.verify_record(RECORDS[1])
        self.assertEqual(v.head["seq"], 2)

    def test_history_and_live_time_differ(self):
        v = verifier()
        with self.assertRaises(PolicyError) as caught:
            v.append(RECORDS[0], 0)
        self.assertEqual(caught.exception.code, "E_POLICY_TIME")
        self.assertFalse(v.conflict)
        v.verify_record(RECORDS[0])

    def test_revoked_signer_is_rejected(self):
        hooks = fixture_hooks(bytes.fromhex(A["point"]))

        def resolve(e, state):
            if state["count"]:
                raise ValueError("revoked certificate")
            return hooks.resolve_key(e, state)

        v = verifier(PolicyHooks(resolve, hooks.authorize, hooks.derive))
        v.verify_record(RECORDS[0])
        with self.assertRaises(PolicyError):
            v.verify_record(RECORDS[1])

    def test_wrap_commitment_hook(self):
        sealed = box(
            next(
                v["args"]["box"]
                for v in FIXTURE["vectors"]
                if v["id"] == "sealed-valid"
            )
        )
        hooks = fixture_hooks(bytes.fromhex(A["point"]))
        v = verifier(
            PolicyHooks(
                hooks.resolve_key,
                hooks.authorize,
                hooks.derive,
                lambda e, s: [{"id": "wrap:recipient", "digest": sealed.wrap_digest}],
            )
        )
        v.verify_record(RECORDS[0])
        v.check_wrap("wrap:recipient", sealed)
        with self.assertRaises(PolicyError):
            v.check_wrap(
                "wrap:recipient",
                c.SealedBox(
                    sealed.eph_pub, bytes(12), sealed.wrapped, sealed.wrap_digest
                ),
            )

    def test_value_and_latest_envelope(self):
        sealed = box(
            next(
                v["args"]["box"]
                for v in FIXTURE["vectors"]
                if v["id"] == "sealed-valid"
            )
        )
        v = verifier()
        for r in RECORDS:
            v.verify_record(r)
        v.check_value("ver_aaaaaaaaaaaa", sealed.wrapped, sealed.nonce)
        v.check_envelope("ver_aaaaaaaaaaaa", "new", sealed.wrapped, sealed.nonce)
        with self.assertRaises(PolicyError):
            v.check_envelope("ver_aaaaaaaaaaaa", "old", sealed.wrapped, sealed.nonce)

    def test_p1363_runtime_signature(self):
        key = c.generate_p256_key()
        sig = c.p256_sign(key, b"message")
        self.assertEqual(len(sig), 64)
        self.assertTrue(
            c.p256_verify(c.export_point(key.public_key()), b"message", sig)
        )
        self.assertFalse(
            c.p256_verify(c.export_point(key.public_key()), b"tampered", sig)
        )

    def test_runtime_sealed_box_uniform_failure(self):
        key = c.generate_p256_key()
        recipient = c.export_point(key.public_key())
        aad = c.org_key_wrap_aad(A["org"], "member_key", "member", 1)
        sealed = c.seal(recipient, bytes(32), aad)
        self.assertEqual(c.unseal(key, recipient, sealed, aad), bytes(32))
        for tampered in (
            c.SealedBox(bytes(65), sealed.nonce, sealed.wrapped, sealed.wrap_digest),
            c.SealedBox(sealed.eph_pub, bytes(1), sealed.wrapped, sealed.wrap_digest),
        ):
            with self.assertRaisesRegex(
                c.CryptoError, "^cryptographic operation failed$"
            ):
                c.unseal(key, recipient, tampered, aad)

    def test_unsafe_in_memory_objects(self):
        for item in (
            1.0,
            float("nan"),
            float("inf"),
            2**53,
            {"é": 1},
            {1: "key"},
            "\ud800",
            b"bytes",
        ):
            with self.subTest(item=repr(item)):
                with self.assertRaises((ValueError, UnicodeError)):
                    c.canonical_json(item)
        cycle = []
        cycle.append(cycle)
        with self.assertRaises(ValueError):
            c.canonical_json(cycle)
