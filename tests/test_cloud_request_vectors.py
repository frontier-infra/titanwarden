"""Consume every exact request handoff vector and indexed recovery vector."""

import unittest
from copy import deepcopy

from cloud_fixtures import ROOT, fixture

from tw import cloud_wire as wire
from tw import crypto
from tw.cloud_recovery import (
    RecoveryEvidence,
    independent_recovery_endorser,
    possession_authorization,
    verify_subject_proofs,
)
from tw.cloud_requests import (
    derive_default,
    maximum_policy_age,
    request_grant_id,
    row_for,
)


class RequestVectorTests(unittest.TestCase):
    def test_every_request_vector(self):
        doc = wire.load_pinned_json(
            ROOT / "control/src/requests/vectors/h4-v1.json",
            "47d19a0f5e61984403c05b82844db4db18753de07cbb36bd230aceaf8a5718e3",
        )
        self.assertEqual(len(doc["cases"]), 19)
        for i, c in enumerate(doc["cases"]):
            with self.subTest(index=i, name=c["name"]):
                raw = crypto.canonical_json(c["body"])
                self.assertEqual(raw.decode(), c["body_canonical"])
                self.assertEqual(crypto.sha256(raw).hex(), c["body_sha256"])
                if not c["accepted"]:
                    with self.assertRaises(ValueError):
                        derive_default(c["body"], c["opened"], c["context"])
                    continue
                grant = derive_default(c["body"], c["opened"], c["context"])
                self.assertEqual(grant, c["grant"])
                self.assertEqual(
                    crypto.canonical_json(grant).decode(), c["grant_canonical"]
                )
                self.assertEqual(wire.hash_object(grant), c["grant_sha256"])
                self.assertEqual(
                    request_grant_id(c["body"]["request_id"]), c["request_grant_id"]
                )
                if "expected_row" in c:
                    self.assertEqual(
                        row_for(c["opened"]["request"], c["context"]), c["expected_row"]
                    )

    def test_every_indexed_recovery_vector(self):
        doc = fixture("control/test/recovery/vectors.json")
        self.assertEqual(len(doc["vectors"]), 21)
        for i, v in enumerate(doc["vectors"]):
            with self.subTest(index=i, id=v["id"], type=type(v.get("value")).__name__):
                op = v["op"]
                if op == "maximum_policy_age":
                    if v["expected"]:
                        self.assertEqual(maximum_policy_age(v["value"]), v["value"])
                    else:
                        with self.assertRaises(ValueError):
                            maximum_policy_age(v["value"])
                elif op == "recovery_endorser":
                    self.assertEqual(
                        independent_recovery_endorser(
                            v["generator"], v["subject"], v["endorser"]
                        ),
                        v["expected"],
                    )
                elif op == "slot_digest":
                    self.assertEqual(wire.slot_blob_digest(v["blob"]), v["expected"])
                elif op in ("reset_cancel", "claim"):
                    digest = wire.hash_object(v["entry"])
                    signature = crypto.unb64url(v["signature"])
                    self.assertEqual(
                        crypto.p256_verify(
                            crypto.unb64url(v["public_key"]),
                            crypto.policy_context(v["entry"]["org_id"], digest),
                            signature,
                        ),
                        v["expected"],
                    )
                    if "canonical_hex" in v:
                        self.assertEqual(
                            crypto.canonical_json(v["entry"]).hex(), v["canonical_hex"]
                        )
                        self.assertEqual(digest, v["hash"])
                    if op == "claim":
                        e = v["entry"]
                        cert = e["body"]["requested"]["certificate"]
                        proofs, seen = verify_subject_proofs(e, cert)
                        self.assertEqual(len(seen), len(cert["passkeys"]))
                        auth = deepcopy(e)
                        auth["body"]["assertion"] = proofs["authorization"]
                        possession_authorization(
                            auth, cert, [], dict(mode="history", now=e["ts"])
                        )
                        self.assertEqual(
                            wire.slot_blob_digest(v["private_slot_blob"]),
                            e["body"]["requested"]["slot"]["slot_digest"],
                        )
                        evidence = RecoveryEvidence(
                            blobs={"org_key_wraps": [v["member_wrap"]]}
                        )
                        self.assertEqual(
                            evidence.claim_wrap(e["body"]["requested"]["member_wrap"]),
                            v["member_wrap"],
                        )
                elif op == "binding_context":
                    context = wire.passkey_binding_context(v["entry"])
                    self.assertEqual(
                        wire.hash_object(crypto.policy_core_change(v["entry"])),
                        v["core_digest"],
                    )
                    self.assertEqual(context.hex(), v["context_hex"])
                    self.assertEqual(crypto.sha256(context).hex(), v["challenge_hex"])
                elif op == "subject_signature":
                    self.assertEqual(
                        crypto.p256_verify(
                            crypto.unb64url(v["public_key"]),
                            wire.passkey_binding_context(v["entry"]),
                            crypto.unb64url(v["signature"]),
                        ),
                        v["expected"],
                    )
                elif op == "possession":
                    if v["expected"]:
                        wire.verify_assertion(
                            v["assertion"],
                            v["passkey"],
                            crypto.sha256(wire.passkey_binding_context(v["entry"])),
                        )
                    else:
                        with self.assertRaises(ValueError):
                            wire.verify_assertion(
                                v["assertion"],
                                v["passkey"],
                                crypto.sha256(wire.passkey_binding_context(v["entry"])),
                            )
                else:
                    self.fail("Unknown vector operation")


if __name__ == "__main__":
    unittest.main()
