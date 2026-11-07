"""B6 full production prefix parity, including retained slots and negatives."""

import unittest
from copy import deepcopy

from cloud_fixtures import production_traces
from paired_cloud_fixtures import PairedReplay
from test_cloud_policy import cloud_authority_projection

from tw.cloud_recovery import RecoveryEvidence, RecoveryVerifier
from tw.cloud_wire import hash_object


class RecoveryPairedReplay(PairedReplay):
    def __init__(self, trace):
        super().__init__(trace, verifier=RecoveryVerifier, evidence=RecoveryEvidence)

    def summary(self):
        result = super().summary()
        full = cloud_authority_projection(self.replay.state)
        result["authority_sha256"] = hash_object(full)
        result["authority_core"].pop("recovery_protocol", None)
        protocol = full.get("recovery_protocol", {})
        result["authority_core"]["retired_recovery_points"] = dict(
            sign_pub=protocol.get("used_recovery_sign_keys", []),
            kx_pub=protocol.get("used_recovery_exchange_keys", []),
        )
        result["authority_core_sha256"] = hash_object(result["authority_core"])
        return result


class RecoveryProductionTests(unittest.TestCase):
    def test_all_ten_production_traces_genesis_to_head(self):
        count = 0
        for name, trace in production_traces():
            p = RecoveryPairedReplay(trace)
            for index, record in enumerate(trace["records"]):
                with self.subTest(file=name, index=index, id=record["id"]):
                    self.assertEqual(p.summary(), record["predecessor"])
                    result = p.run(record)
                    self.assertEqual(
                        result["status"], "accepted", result.get("message")
                    )
                    for field, expected in record["expected"].items():
                        if field not in ("code", "message"):
                            self.assertEqual(result[field], expected, field)
                    count += 1
            self.assertEqual(
                cloud_authority_projection(p.replay.state),
                trace["final_state"]["authority"],
            )
            actual = p.finish()
            for key, value in trace["finalize_expected"].items():
                self.assertEqual(actual[key], value, key)
        self.assertEqual(count, 106)

    def test_all_159_negatives_preserve_the_complete_verified_prefix(self):
        count = 0
        for name, trace in production_traces():
            for case in trace["cases"]:
                with self.subTest(file=name, id=case["id"]):
                    p = RecoveryPairedReplay(trace)
                    for record in trace["records"][: case["prefix_length"]]:
                        self.assertEqual(p.run(record)["status"], "accepted")
                    before = deepcopy(p.summary())
                    self.assertEqual(before, case["record"]["predecessor"])
                    actual = p.run(case["record"])
                    self.assertEqual(actual["status"], "rejected")
                    for field, value in case["record"]["expected"].items():
                        self.assertEqual(actual[field], value, field)
                    self.assertEqual(p.summary(), before)
                    self.assertTrue(p.replay.conflict)
                    count += 1
        self.assertEqual(count, 159)


if __name__ == "__main__":
    unittest.main()
