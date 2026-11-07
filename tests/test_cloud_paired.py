"""Committed paired fixture integrity, profile fence and independent replay."""
import unittest

from tw import crypto
from tw.cloud_wire import hash_object
from cloud_fixtures import paired_manifest, paired_traces, production_manifest, production_traces, ROOT
from tw.cloud_wire import load_pinned_json
from tw.policy_log import PolicyError
from paired_cloud_fixtures import PairedReplay


def record_signature_matches(record, trace):
    entry = record["entry"]
    signer = entry["signer"]
    if signer["kind"] == "derived":
        return record["sig"] is None
    if record["sig"] is None:
        return False
    if entry["kind"] == "genesis":
        points = [entry["body"]["founder"]["sign_pub"]]
    elif signer["kind"] == "member":
        points = [v["certificate"]["sign_pub"] for v in trace["final_state"]["authority"]["certificates"]
                  if v["certificate"]["member_id"] == signer["id"] and v["certificate"]["member_key_id"] == signer.get("key")]
    elif signer["kind"] == "broker":
        points = [v["certificate"]["sign_pub"] for v in trace["final_state"]["authority"]["brokers"]
                  if v["certificate"]["broker_id"] == signer["id"]]
        founder = trace["final_state"]["authority"].get("founding_broker")
        if founder and founder["id"] == signer["id"]:
            points.append(founder["sign_pub"])
    else:
        points = []
    return any(crypto.p256_verify(crypto.unb64url(p), crypto.policy_context(entry["org_id"], record["hash"]), crypto.unb64url(record["sig"])) for p in points)


class PairedFixtureTests(unittest.TestCase):
    def test_production_manifest_every_file_and_count(self):
        manifest = production_manifest()
        for item in manifest["files"]:
            document = load_pinned_json(ROOT / "core/vectors" / item["file"], item["sha256"])
            with self.subTest(file=item["file"]):
                self.assertEqual(len(document["records"]), item["records"])
                self.assertEqual(len(document["cases"]), item["cases"])
        traces = list(production_traces())
        self.assertEqual(len(traces), 10)
        self.assertEqual(sum(len(doc["records"]) for _, doc in traces), 106)
        self.assertEqual(sum(len(doc["cases"]) for _, doc in traces), 159)
        for name, trace in traces:
            self.assertEqual(trace["profile"], "production")
            self.assertIs(trace["production_acceptable"], True)
            for index, record in enumerate(trace["records"] + [c["record"] for c in trace["cases"]]):
                with self.subTest(file=name, index=index):
                    self.assertEqual(crypto.canonical_json(record["entry"]).hex(), record["canonical_hex"])
                    self.assertEqual(hash_object(record["entry"]), record["hash"])
                    if index < len(trace["records"]):
                        self.assertTrue(record_signature_matches(record, trace))
                    else:
                        record_signature_matches(record, trace)
            self.assertEqual(hash_object(trace["final_state"]["authority"]), trace["records"][-1]["expected"]["authority_sha256"])
            self.assertEqual(hash_object(trace["final_state"]["epoch"]), trace["records"][-1]["expected"]["epoch_sha256"])

    def test_all_production_b1_b2_b3_prefixes_and_b6_fence(self):
        from tw.cloud_policy import AUTHORITY_KINDS
        from tw.cloud_epochs import EPOCH_KINDS, CIPHERTEXT_KINDS

        accepted, fenced = 0, 0
        kinds = set()
        fields = ("status", "head", "authority_core", "authority_core_sha256", "epoch_sha256", "snapshot", "commitments", "custody", "events")
        for name, trace in production_traces():
            replay = PairedReplay(trace)
            self.assertEqual(replay.summary(), {k: v for k, v in trace["records"][0]["predecessor"].items() if k != "authority_sha256"})
            complete = True
            for index, record in enumerate(trace["records"]):
                with self.subTest(file=name, index=index, id=record["id"]):
                    before = replay.summary()
                    self.assertEqual(before, {k: v for k, v in record["predecessor"].items() if k != "authority_sha256"})
                    actual = replay.run(record)
                    if "passkey_binding" in record["entry"]["body"]:
                        fenced += 1
                        complete = False
                        self.assertEqual(actual["status"], "rejected")
                        self.assertEqual(actual["code"], "E_POLICY_CONFLICT")
                        self.assertEqual(replay.summary(), before)
                        self.assertTrue(replay.replay.conflict)
                        break
                    accepted += 1
                    kinds.add(record["entry"]["kind"])
                    for key in fields:
                        self.assertEqual(actual[key], record["expected"][key], key)
            if complete:
                finished = replay.finish()
                expected = trace["finalize_expected"]
                self.assertIsNotNone(expected)
                for key in ("status", "head", "authority_core", "authority_core_sha256", "epoch_sha256", "snapshot", "commitments", "custody"):
                    self.assertEqual(finished[key], expected[key], key)
        self.assertEqual(accepted, 99)
        self.assertEqual(fenced, 5)
        self.assertEqual(kinds, AUTHORITY_KINDS | EPOCH_KINDS | CIPHERTEXT_KINDS)

    def test_all_142_non_binding_negatives_preserve_verified_prefix(self):
        count = 0
        fields = ("status", "code", "head", "authority_core", "authority_core_sha256", "epoch_sha256", "snapshot", "commitments", "custody")
        for name, trace in production_traces():
            if "typed-passkey-binding" in name:
                continue
            for index, case in enumerate(trace["cases"]):
                with self.subTest(file=name, index=index, id=case["id"]):
                    replay = PairedReplay(trace)
                    for record in trace["records"][:case["prefix_length"]]:
                        self.assertNotIn("passkey_binding", record["entry"]["body"])
                        self.assertEqual(replay.run(record)["status"], "accepted")
                    before = replay.summary()
                    self.assertEqual(before, {k: v for k, v in case["record"]["predecessor"].items() if k != "authority_sha256"})
                    actual = replay.run(case["record"])
                    expected = case["record"]["expected"]
                    for key in fields:
                        self.assertEqual(actual[key], expected[key], key)
                    self.assertEqual(actual["status"], "rejected")
                    self.assertEqual(replay.summary(), before)
                    count += 1
        self.assertEqual(count, 142)

    def test_manifest_counts_and_all_supplied_policy_bytes(self):
        manifest = paired_manifest()
        traces = list(paired_traces())
        self.assertEqual(len(traces), len(manifest["files"]))
        for (name, trace), item in zip(traces, manifest["files"]):
            with self.subTest(file=name):
                self.assertEqual(len(trace["records"]), item["records"])
                self.assertEqual(len(trace["cases"]), item["cases"])
                self.assertEqual(trace["pinned_root"], trace["records"][0]["hash"])
                for index, record in enumerate(trace["records"] + [case["record"] for case in trace["cases"]]):
                    with self.subTest(index=index, id=record["id"]):
                        self.assertEqual(crypto.canonical_json(record["entry"]).hex(), record["canonical_hex"])
                        self.assertEqual(hash_object(record["entry"]), record["hash"])
                        if index < len(trace["records"]):
                            self.assertTrue(record_signature_matches(record, trace))
                        else:
                            # Run the verification even for intentionally invalid
                            # signatures; semantic rejection belongs to replay.
                            record_signature_matches(record, trace)
                self.assertEqual(hash_object(trace["final_state"]["authority"]), trace["records"][-1]["expected"]["authority_sha256"])
                self.assertEqual(hash_object(trace["final_state"]["epoch"]), trace["records"][-1]["expected"]["epoch_sha256"])

    def test_reference_only_profiles_cannot_establish_acceptance(self):
        count = 0
        for name, trace in paired_traces():
            if not trace["production_acceptable"]:
                count += 1
                with self.subTest(file=name), self.assertRaisesRegex(ValueError, "reference-only"):
                    PairedReplay(trace)
        self.assertEqual(count, 9)

    def test_production_binding_trace_b1_b2_prefix(self):
        _, trace = next((name, trace) for name, trace in paired_traces() if trace["production_acceptable"])
        replay = PairedReplay(trace)
        # Typed binding transitions belong to B6. The first four records are
        # genuine production genesis, founder, initial epoch and ordinary member.
        for index, record in enumerate(trace["records"][:4]):
            with self.subTest(index=index):
                actual = replay.run(record)
                self.assertEqual(actual["status"], "accepted", actual)
                for key in ("head", "epoch_sha256", "snapshot", "commitments", "custody", "events"):
                    self.assertEqual(actual[key], record["expected"][key], key)
        replay.finish()


if __name__ == "__main__":
    unittest.main()
