from __future__ import annotations

import copy
import hashlib
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from tw import crypto as c
from tw import cloud_wire as w
from cloud_fixtures import FIXTURES, ROOT, fixture
from test_cloud_vectors import run_vector


class CloudFixtureTests(unittest.TestCase):
    def test_all_fixture_bytes_match_pinned_cloud(self):
        for name, expected in FIXTURES.items():
            with self.subTest(name=name):
                self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), expected)

    def test_bad_hash_precedes_parsing(self):
        # A mismatched existing fixture must never be parsed.
        with self.assertRaisesRegex(ValueError, "SHA256"):
            w.load_pinned_json(ROOT / "control/src/genesis/vectors.json", "0" * 64)

    def test_v0_all_356_positive_and_negative_cases(self):
        document = fixture("core/vectors/protocol-v2.json")
        self.assertEqual(document["count"], 356)
        self.assertEqual(len(document["vectors"]), 356)
        self.assertEqual(len({v["id"] for v in document["vectors"]}), 356)
        self.assertEqual(document["wordlist"], list(c.SAS_WORDLIST))
        self.assertEqual(c.sha256(("\n".join(c.SAS_WORDLIST) + "\n").encode()).hex(), document["wordlist_sha256"])
        for index, vector in enumerate(document["vectors"]):
            with self.subTest(file="core/vectors/protocol-v2.json", index=index, id=vector["id"]):
                if vector.get("error"):
                    if "error_message" in vector:
                        with self.assertRaises(c.CryptoError) as caught:
                            run_vector(vector)
                        self.assertEqual(str(caught.exception), vector["error_message"])
                    else:
                        with self.assertRaises(Exception):
                            run_vector(vector)
                else:
                    self.assertEqual(run_vector(vector), vector["expected"])

    def test_v1_every_expected_founder_field(self):
        document = fixture("control/vectors/authority-v1.json")
        self.assertEqual(len(document["founder_vectors"]), 3)
        for index, vector in enumerate(document["founder_vectors"]):
            with self.subTest(file="control/vectors/authority-v1.json", index=index):
                cert = w.parse_certificate(vector["certificate"], vector["certificate"]["org_id"])
                self.assertEqual(w.hash_object(cert), vector["expected_digest"])
                if "canonical" in vector:
                    self.assertEqual(c.canonical_json(cert).decode(), vector["canonical"])
                founder = vector["founder"]
                matches = (w.hash_object(cert) == founder["certificate_sha256"] and all(cert[a] == founder[b] for a, b in (("member_id", "id"), ("member_key_id", "key"), ("sign_pub", "sign_pub"), ("kx_pub", "kx_pub"))))
                self.assertEqual(matches, vector["matches"])

    def test_v2_accept_every_expected_field_and_wrong_domain(self):
        document = fixture("control/src/genesis/vectors.json")
        v = document["accept"]
        self.assertEqual(c.canonical_json(v["payload"]).hex(), v["canonical_hex"])
        self.assertEqual(w.hash_object(v["payload"]), v["payload_sha256"])
        message = w.member_accept_context(document["org_id"], v["payload_sha256"])
        self.assertEqual(message.hex(), v["context_hex"])
        verified = w.verify_member_accept({**v["payload"], "proof": v["proof"]}, document["org_id"], private_slot=v["private_slot"])
        self.assertEqual(verified, v["payload"])
        self.assertFalse(c.p256_verify(c.unb64url(document["certificate"]["sign_pub"]), c.policy_context(document["org_id"], v["payload_sha256"]), c.unb64url(v["proof"])))
        changed = copy.deepcopy(v["private_slot"])
        changed["label"] = "substituted"
        with self.assertRaises(ValueError):
            w.verify_member_accept({**v["payload"], "proof": v["proof"]}, document["org_id"], private_slot=changed)

    def test_v2_initial_slot_exact_bytes_and_distinct_tags(self):
        document = fixture("control/src/genesis/vectors.json")
        v = document["initial_slot"]
        slot = w.parse_slot(v["slot"], document["certificate"])
        self.assertEqual(slot["member_key_id"], v["member_key_id"])
        self.assertEqual(c.canonical_json(slot).hex(), v["canonical_hex"])
        initial, blob = w.slot_commitment(slot, "initial_slot"), w.slot_commitment(slot, "slot_blob")
        self.assertEqual(initial.digest, v["sha256"])
        self.assertNotEqual(initial, blob)
        self.assertTrue(initial.matches(slot))
        self.assertNotEqual(initial, w.SlotCommitment("slot_blob", initial.digest))
        with self.assertRaises(ValueError):
            w.slot_commitment(slot, "untyped")

    def test_v2_founder_and_confirmation_every_expected_field(self):
        document = fixture("control/src/genesis/vectors.json")
        for section in ("founder", "confirmation"):
            v = document[section]
            with self.subTest(section=section):
                signed = w.parse_signed_entry(v["signed"])
                entry = signed["entry"]
                self.assertEqual(c.canonical_json(entry).hex(), v["canonical_hex"])
                self.assertEqual(w.hash_object(entry), v["entry_sha256"])
                self.assertEqual(w.hash_object(c.policy_core_change(entry)), v["core_change_sha256"])
                context = c.policy_context(document["org_id"], v["entry_sha256"])
                self.assertTrue(c.p256_verify(c.unb64url(document["owner"]["sign_pub"]), context, c.unb64url(signed["sig"])))
                if section == "founder":
                    slot = w.parse_slot(v["slot"], document["owner"])
                    self.assertEqual(w.slot_commitment(slot, "initial_slot").digest, v["slot_sha256"])
                    self.assertEqual(entry["body"]["initial_slot_sha256"], v["slot_sha256"])
                else:
                    self.assertEqual(context.hex(), v["policy_context_hex"])
                    self.assertEqual(w.verify_authorization(entry, document["owner"], {"member_id": document["certificate"]["member_id"]}, [], {"mode": "history"}), entry["body"]["authz"]["challenge"])
                    wrap = v["wrap"]
                    self.assertEqual(c.wrap_digest(bytes.fromhex(wrap["eph_pub"]), bytes.fromhex(wrap["nonce"]), bytes.fromhex(wrap["wrapped_omk"])), wrap["wrap_digest"])
                    changed = copy.deepcopy(entry)
                    changed["body"]["wrap"]["omk_generation"] = 2
                    self.assertNotEqual(w.hash_object(c.policy_core_change(changed)), v["core_change_sha256"])
                    self.assertFalse(c.p256_verify(c.unb64url(document["owner"]["sign_pub"]), c.policy_context(document["org_id"], w.hash_object(changed)), c.unb64url(signed["sig"])))

    def test_v3_binding_and_slot_vectors_by_file_index_and_type(self):
        # Recovery transition semantics belong to B6. B1 consumes the shared
        # binding-domain, possession and slot commitment cases only.
        name = "control/test/recovery/vectors.json"
        document = fixture(name)
        selected = [6, 8, 9, 10, 11, 12]
        keys = [w.vector_key(name, i, document["vectors"][i]) for i in range(len(document["vectors"]))]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertNotEqual(keys[15], keys[20])
        for i in selected:
            v = document["vectors"][i]
            with self.subTest(key=keys[i]):
                if v["op"] == "slot_digest":
                    self.assertEqual(w.slot_blob_digest(v["blob"]), v["expected"])
                elif v["op"] == "binding_context":
                    self.assertEqual(w.hash_object(c.policy_core_change(v["entry"])), v["core_digest"])
                    context = w.passkey_binding_context(v["entry"])
                    self.assertEqual(context.hex(), v["context_hex"])
                    self.assertEqual(c.sha256(context).hex(), v["challenge_hex"])
                elif v["op"] == "subject_signature":
                    self.assertEqual(c.p256_verify(c.unb64url(v["public_key"]), w.passkey_binding_context(v["entry"]), c.unb64url(v["signature"])), v["expected"])
                elif v["expected"]:
                    w.verify_assertion(v["assertion"], v["passkey"], c.sha256(w.passkey_binding_context(v["entry"])))
                else:
                    with self.assertRaises(ValueError):
                        w.verify_assertion(v["assertion"], v["passkey"], c.sha256(w.passkey_binding_context(v["entry"])))


class StrictWireTests(unittest.TestCase):
    def setUp(self):
        self.document = fixture("control/src/genesis/vectors.json")
        self.cert = self.document["owner"]
        self.entry = self.document["confirmation"]["signed"]["entry"]

    def test_certificate_unknown_fields_and_keyholder_consistency(self):
        for mutate in (
            lambda c: c.update(email="owner@example.test"),
            lambda c: c.update(v=True),
            lambda c: c.update(cert_no=True),
            lambda c: c.update(key_holder=False),
            lambda c: c.update(passkeys=[]),
            lambda c: c["passkeys"].append(copy.deepcopy(c["passkeys"][0])),
            lambda c: c.update(sign_pub=c["sign_pub"] + "="),
            lambda row: row.update(kx_pub=c.b64url(bytes(65))),
        ):
            candidate = copy.deepcopy(self.cert)
            with self.subTest(mutation=mutate):
                mutate(candidate)
                with self.assertRaises((ValueError, c.CryptoError)):
                    w.parse_certificate(candidate, self.document["org_id"])

    def test_strict_cose_encoding_and_point(self):
        encoded = self.cert["passkeys"][0]["cose_key"]
        raw = c.unb64url(encoded)
        self.assertEqual(len(w.cose_point(encoded)), 65)
        bad = [raw + b"\x00", raw[:-1], b"\xa6" + raw[1:], raw[:2] + b"\x03" + raw[3:], raw[:10] + bytes(67), raw[:1] + b"\x18\x01" + raw[2:]]
        for candidate in bad:
            with self.subTest(raw=candidate.hex()), self.assertRaises((ValueError, c.CryptoError)):
                w.cose_point(c.b64url(candidate))

    def test_minimal_positive_in_range_der(self):
        valid = encode_dss_signature(1, 2)
        self.assertEqual(w.der_signature(valid), bytes(31) + b"\x01" + bytes(31) + b"\x02")
        order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        for candidate in (valid + b"\x00", b"\x30\x07\x02\x02\x00\x01\x02\x01\x02", encode_dss_signature(0, 2), encode_dss_signature(order, 2), b"\x30\x06\x02\x01\x80\x02\x01\x02"):
            with self.subTest(raw=candidate.hex()), self.assertRaises(ValueError):
                w.der_signature(candidate)

    def test_authz_binds_actor_target_core_head_and_challenge(self):
        for path, replacement in (("op", "broker_cert"), ("org_id", "b" * 32), ("request_id", "other"), ("target", {}), ("core_change_sha256", "0" * 64), ("policy_head", {"seq": 0, "hash": "0" * 64}), ("actor", {**self.entry["body"]["authz"]["actor"], "member_id": "other"}), ("challenge", c.b64url(bytes(32)))):
            entry = copy.deepcopy(self.entry)
            entry["body"]["authz"][path] = replacement
            with self.subTest(field=path), self.assertRaises(ValueError):
                w.verify_authorization(entry, self.cert, {"member_id": self.document["certificate"]["member_id"]}, [], {"mode": "history"})
        with self.assertRaises(ValueError):
            w.verify_authorization(self.entry, self.cert, {"member_id": self.document["certificate"]["member_id"]}, [self.entry["body"]["authz"]["challenge"]], {"mode": "history"})

    def test_live_proof_needs_unused_issue_and_half_open_validity(self):
        auth = self.entry["body"]["authz"]
        stored = {**auth, "member_id": self.cert["member_id"], "used_at": None}
        runtime = {"mode": "live", "submission": True, "now": auth["issued_at"], "challenge": {auth["challenge"]: stored}}
        target = {"member_id": self.document["certificate"]["member_id"]}
        w.verify_authorization(self.entry, self.cert, target, [], runtime)
        for change in ({"now": auth["expires_at"]}, {"challenge": {}}, {"challenge": {auth["challenge"]: {**stored, "used_at": auth["issued_at"]}}}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                w.verify_authorization(self.entry, self.cert, target, [], {**runtime, **change})

    def test_webauthn_origin_flags_rp_and_counter_length(self):
        assertion = self.entry["body"]["assertion"]
        passkey = self.cert["passkeys"][0]
        challenge = c.sha256(c.canonical_json(self.entry["body"]["authz"]))
        for field, value in (("origin", "https://evil.test"), ("type", "webauthn.create"), ("crossOrigin", True), ("crossOrigin", 0), ("challenge", "AA")):
            changed = copy.deepcopy(assertion)
            data = json.loads(c.unb64url(changed["clientDataJSON"]))
            data[field] = value
            changed["clientDataJSON"] = c.b64url(json.dumps(data).encode())
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                w.verify_assertion(changed, passkey, challenge)
        raw = c.unb64url(assertion["authenticatorData"])
        for data in (raw[:-1], raw + b"\x00", bytes(32) + raw[32:], raw[:32] + b"\x01" + raw[33:], raw[:32] + b"\x04" + raw[33:], raw[:32] + b"\x85" + raw[33:]):
            changed = {**assertion, "authenticatorData": c.b64url(data)}
            with self.subTest(auth=data.hex()), self.assertRaises(ValueError):
                w.verify_assertion(changed, passkey, challenge)

    def test_slot_bounds_and_certificate_ownership(self):
        slot = self.document["founder"]["slot"]
        for field, value in (("member_key_id", "other"), ("nonce", c.b64url(bytes(11))), ("wrapped_priv", c.b64url(bytes(15))), ("extra", True)):
            candidate = {**slot, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                w.parse_slot(candidate, self.cert)
        passphrase = {**slot, "kind": "passphrase", "params": {"salt": c.b64url(bytes(16)), "memory_kib": 262144, "iterations": 3, "lanes": 1}}
        w.parse_slot(passphrase)
        with self.assertRaises(ValueError):
            w.parse_slot(passphrase, self.cert)
        for field, value in (("memory_kib", 262143), ("memory_kib", 1048577), ("iterations", 2), ("iterations", 11), ("lanes", True), ("lanes", 5)):
            candidate = copy.deepcopy(passphrase)
            candidate["params"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                w.parse_slot(candidate)

    def test_signed_entry_closed_signer_schemas(self):
        signed = self.document["confirmation"]["signed"]
        for signer in ({"kind": "member", "id": "x"}, {"kind": "broker", "id": "x", "key": "bad"}, {"kind": "recovery", "id": "x"}, {"kind": "unknown", "id": "x"}):
            candidate = copy.deepcopy(signed)
            candidate["entry"]["signer"] = signer
            with self.subTest(signer=signer), self.assertRaises(ValueError):
                w.parse_signed_entry(candidate)
        candidate = copy.deepcopy(signed)
        candidate["entry"]["signer"] = {"kind": "derived"}
        with self.assertRaises(ValueError):
            w.parse_signed_entry(candidate)
        del candidate["sig"]
        w.parse_signed_entry(candidate)

    def test_safe_head_integer_and_numeric_project_keys(self):
        for value in (True, -1, 1.5, 2**53):
            with self.subTest(value=value), self.assertRaises(ValueError):
                w.parse_head({"seq": value, "hash": "0" * 64})
        # Application map keys are strings, not integer schema positions.
        self.assertEqual(c.canonical_json({"01": "k", "1": "j"}), b'{"01":"k","1":"j"}')

    def test_shared_commitments_keep_exact_identity_and_unknown_fields_closed(self):
        slot = self.document["founder"]["slot"]
        descriptor = {**w.slot_metadata(slot), "slot_digest": w.slot_blob_digest(slot)}
        blob = {k: slot[k] for k in ("slot_id", "wrapped_priv", "nonce")}
        recipient = dict(kind="recovery", id="recovery", kx_pub_sha256="a" * 64, wrap_digest="b" * 64)
        scoped = dict(broker_id="broker", key_id="key", project="01", wrap_digest="a" * 64)
        key = dict(key_id="key", purpose="fingerprint", scope="*", digest="a" * 64)
        for parse, value in ((w.parse_slot_descriptor, descriptor), (w.parse_slot_blob, blob), (w.parse_recipient, recipient), (w.parse_scoped_commitment, scoped), (w.parse_key_commitment, key)):
            with self.subTest(parser=parse.__name__):
                self.assertEqual(parse(value), value)
                with self.assertRaises(ValueError):
                    parse({**value, "unknown": True})
        with self.assertRaises(ValueError):
            w.parse_recipient({**recipient, "id": "substituted"})
        with self.assertRaises(ValueError):
            w.parse_key_commitment({**key, "scope": "project"})

    def test_broker_schema_uses_certified_scope_and_deduplicates_blob_ids(self):
        cert = dict(v=1, org_id=self.document["org_id"], broker_id="broker", cert_no=1,
                    name="test", sign_pub=self.cert["sign_pub"], kx_pub=self.cert["kx_pub"],
                    scope="full", keeper=True, local_admin_approvals=False, state="active",
                    transcript_digest="a" * 64, wrap_digests=[dict(id="enw_" + "a" * 32, digest="b" * 64)])
        w.parse_broker_certificate(cert, self.document["org_id"], lambda p: p in ("a", "b"))
        scoped = dict(cert, scope=["a"], keeper=False)
        w.parse_broker_certificate(scoped, self.document["org_id"], lambda p: p in ("a", "b"))
        for candidate in (dict(cert, scope=["a"]), dict(scoped, scope=["*"]), dict(scoped, scope=["b", "a"]), dict(scoped, scope=["a", "a"]), dict(scoped, scope=["unknown"]), dict(cert, wrap_digests=cert["wrap_digests"] * 2), dict(cert, cert_no=True)):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                w.parse_broker_certificate(candidate, self.document["org_id"], lambda p: p in ("a", "b"))


if __name__ == "__main__":
    unittest.main()
