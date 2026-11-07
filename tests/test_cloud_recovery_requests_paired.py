"""Cloud-generated B6/B7 companion traces, never checkpoint-seeded authority."""

import unittest
from copy import deepcopy
from pathlib import Path

from test_cloud_recovery import RecoveryPairedReplay

from tw import crypto
from tw.cloud_policy import require
from tw.cloud_recovery import RecoveryEvidence
from tw.cloud_wire import hash_object, load_pinned_json
from tw.policy_log import PolicyError

REVISION = "177766e1de71acbff0a188fa4d4b487db6c28391"
ROOT = Path(__file__).parent / "fixtures/cloud" / REVISION / "core/vectors"
MANIFEST = "paired-broker-manifest-recovery-requests-v1.json"
MANIFEST_SHA256 = "f8a4fdf8cf978f4b9604ec769c563b143a12c2f748e1d80b1d0b6ad0525e4128"


def traces():
    manifest = load_pinned_json(ROOT / MANIFEST, MANIFEST_SHA256)
    for item in manifest["files"]:
        yield item, load_pinned_json(ROOT / item["file"], item["sha256"])


class CompanionReplay(RecoveryPairedReplay):
    """Test storage ports follow the cloud runtime's documented public inputs.

    The SQL materialized metadata is evidence to compare, never replay authority.
    Server notice delivery and human endpoint quotas have no broker caller here.
    """

    def __init__(self, trace):
        super().__init__(trace)
        self.evidence_factory = self.evidence
        self.operations = 0

    def evidence(self, rows, blobs):
        facts = dict(
            head=self.replay.head,
            principals=[
                dict(
                    id=p["principal_id"],
                    project=p["project"],
                    active=p["state"] == "active",
                    broker_id=p.get("broker_id"),
                    member_id=p.get("member_id"),
                )
                for p in rows.get("principals", [])
            ],
            tokens=[],
            targets=[
                dict(
                    path=t["path"],
                    project=t["project"],
                    **{"class": t["class"]},
                    active=True,
                    client_approval_required=False,
                )
                for t in rows.get("secrets", [])
            ],
            managed_projects={"lead": ["b"]},
            grants=[],
        )

        def typed_gates(binding):
            matches = [
                p
                for p in blobs.get("fixture_typed_gates", [])
                if p["binding"] == binding
            ]
            require(len(matches) == 1, "Independent typed-gate evidence unavailable")
            return deepcopy(matches[0])

        retained = deepcopy(blobs)
        wraps = retained.setdefault("org_key_wraps", [])
        for wrap in self.replay.epoch_state["org_wraps"]:
            if not any(
                all(
                    r.get(k) == wrap[k]
                    for k in ("omk_generation", "recipient_kind", "recipient_id")
                )
                for r in wraps
            ):
                wraps.append(deepcopy(wrap))
        return RecoveryEvidence(
            rows, retained, reset_sas_verifier=typed_gates, request_facts=facts
        )

    def operation(self, op):
        self.install(op.get("evidence", []))
        request = op["request"]
        require(
            crypto.canonical_json(request).hex() == op["request_canonical_hex"],
            "Operational request canonical bytes differ",
        )
        body = request.get("body")
        route = request["routeId"]
        if op.get("http") and op["http"]["body_canonical_hex"] is not None:
            require(
                crypto.canonical_json(body).hex() == op["http"]["body_canonical_hex"],
                "Operational HTTP canonical bytes differ",
            )
        before = self.summary()
        staged = deepcopy(self.blobs)
        try:
            member = next(
                (
                    c
                    for c in self.replay.authority_view().active()
                    if c["workos_user_id"] == request.get("identity", {}).get("id")
                ),
                None,
            )
            if route not in ("resetLifecycle", "claimCleanup"):
                require(
                    member
                    and request["identity"]["kind"] == "human"
                    and request["org_id"] == self.replay.state["org_id"],
                    "Human fixture session differs",
                )
            if route in ("keyReset", "recoverySession"):
                for blob in body.get("slots", []):
                    descriptor = body["entry"]["body"]["slot"]
                    rows = staged.setdefault("recovery_slot_blobs", [])
                    require(
                        not any(r["slot_id"] == blob["slot_id"] for r in rows),
                        "Slot id reserved by another operation",
                    )
                    rows.append(dict(blob, member_key_id=descriptor["member_key_id"]))
                response = self.replay.verify_operational(
                    {k: body[k] for k in ("entry", "sig")},
                    op["received_at"],
                    evidence=self.evidence(self.rows, staged),
                )
                self.blobs = staged
            elif route == "recoveryWrap":
                require(
                    any(
                        p["workos_user_id"] == request["identity"]["id"]
                        and p["org_root"] == self.replay.state["root"]
                        for p in staged.get("fixture_device_pins", [])
                    ),
                    "Independent fixture device pin missing",
                )
                response = self.replay.recovery_wrap(
                    evidence=self.evidence(self.rows, staged)
                )
            elif route == "resetLifecycle":
                response = self.replay.synchronize_operations(op["received_at"])
            elif route == "claimCleanup":
                response, cleaned = self.replay.cleanup_claim_staging(
                    op["received_at"], evidence=self.evidence(self.rows, staged)
                )
                self.rows, self.blobs = cleaned._rows, cleaned._blobs
            else:
                raise ValueError("Unknown companion operational route")
            result = dict(
                status="accepted",
                response=response,
                response_canonical_hex=crypto.canonical_json(response).hex(),
            )
        except (ValueError, PolicyError) as exc:
            # TypeScript operational Error/RecoveryNotReady exports have no code.
            code = (
                "Error"
                if not isinstance(exc, PolicyError)
                or exc.code == "E_RECOVERY_NOT_READY"
                else exc.code
            )
            result = dict(status="rejected", code=code, message=str(exc))
        require(before == self.summary(), "Operational input changed policy authority")
        self.operations += 1
        return result

    def prefix(self, length, operations_length=None):
        operations = self.trace.get("operations", [])
        limit = len(operations) if operations_length is None else operations_length
        for i in range(length + 1):
            while (
                self.operations < limit
                and operations[self.operations]["prefix_length"] == i
            ):
                op = operations[self.operations]
                result = self.operation(op)
                require(
                    result["status"] == op["expected"]["status"],
                    "Operational prefix rejected",
                )
            if i < length:
                require(
                    self.run(self.trace["records"][i])["status"] == "accepted",
                    "Companion prefix rejected",
                )


def check_summary(test, actual, expected):
    for field in (
        "head",
        "authority_sha256",
        "authority_core",
        "authority_core_sha256",
        "epoch_sha256",
        "snapshot",
        "commitments",
        "custody",
    ):
        test.assertEqual(actual[field], expected[field], field)
    materialized = expected.get("materialized")
    if materialized is not None:
        test.assertEqual(hash_object(materialized), expected["materialized_sha256"])


def check_operational_core(test, replay, expected):
    materialized = expected["materialized"]["operational_state"]
    test.assertEqual(
        list(replay.replay._operational.pending.values()),
        materialized["recovery_pending_resets"],
    )
    test.assertEqual(
        list(replay.replay._reset_proposals.values()),
        materialized["recovery_reset_proposals"],
    )
    test.assertEqual(
        list(replay.replay._reset_activations.values()),
        materialized["recovery_reset_activations"],
    )
    test.assertEqual(
        replay.replay._operational.session_reports,
        materialized["recovery_session_reports"],
    )


class CompanionFixtureTests(unittest.TestCase):
    def test_complete_production_traces_and_operational_records(self):
        records = operations = 0
        for item, trace in traces():
            self.assertEqual(len(trace["records"]), item["records"])
            self.assertEqual(len(trace["cases"]), item["cases"])
            self.assertEqual(len(trace["operations"]), item["operations"])
            p = CompanionReplay(trace)
            for i in range(len(trace["records"]) + 1):
                while (
                    p.operations < len(trace["operations"])
                    and trace["operations"][p.operations]["prefix_length"] == i
                ):
                    op = trace["operations"][p.operations]
                    actual = p.operation(op)
                    with self.subTest(file=item["file"], operation=op["id"]):
                        expected = op["expected"]
                        self.assertEqual(
                            actual["status"], expected["status"], actual.get("message")
                        )
                        if actual["status"] == "accepted":
                            self.assertEqual(actual["response"], expected["response"])
                            self.assertEqual(
                                actual["response_canonical_hex"],
                                expected["response_canonical_hex"],
                            )
                        else:
                            self.assertEqual(actual["code"], expected["code"])
                        check_summary(self, p.summary(), expected)
                        check_operational_core(self, p, expected)
                        operations += 1
                if i == len(trace["records"]):
                    break
                record = trace["records"][i]
                with self.subTest(file=item["file"], record=record["id"]):
                    check_summary(self, p.summary(), record["predecessor"])
                    actual = p.run(record)
                    self.assertEqual(
                        actual["status"], "accepted", actual.get("message")
                    )
                    check_summary(self, actual, record["expected"])
                    check_operational_core(self, p, record["expected"])
                    self.assertEqual(
                        list(p.replay._requests.request_rows.values()),
                        record["expected"]["materialized"]["requests"],
                    )
                    self.assertEqual(
                        list(p.replay._requests.grant_rows.values()),
                        record["expected"]["materialized"]["grants"],
                    )
                    records += 1
            actual = p.finish()
            check_summary(self, actual, trace["finalize_expected"])
        self.assertEqual((records, operations), (150, 20))

    def test_all_76_policy_negatives_with_exact_operational_prefix(self):
        count = 0
        for item, trace in traces():
            for case in trace["cases"]:
                with self.subTest(file=item["file"], case=case["id"]):
                    p = CompanionReplay(trace)
                    p.prefix(case["prefix_length"], case["operations_length"])
                    before = p.summary()
                    check_summary(self, before, case["record"]["predecessor"])
                    actual = p.run(case["record"])
                    expected = case["record"]["expected"]
                    self.assertEqual(actual["status"], "rejected")
                    self.assertEqual(
                        actual["code"], expected["code"], actual.get("message")
                    )
                    if case["id"] == "reset-activation-sas-mismatch":
                        # Python checks the immutable stage's context before the
                        # later proposal/activation match. Both refuse the case.
                        self.assertEqual(
                            expected["message"],
                            "Reset activation SAS differs from proposal",
                        )
                        self.assertEqual(
                            actual["message"], "Immutable reset SAS transcript differs"
                        )
                    else:
                        self.assertEqual(actual["message"], expected["message"])
                    check_summary(self, actual, expected)
                    self.assertEqual(p.summary(), before)
                    count += 1
        self.assertEqual(count, 76)

    def test_historical_reset_uses_immutable_receipts_after_lifecycle_changes(self):
        _, trace = next(
            (i, t)
            for i, t in traces()
            if i["file"] == "broker-recovery-reset-activate-v1.json"
        )
        live = CompanionReplay(trace)
        live.prefix(len(trace["records"]))
        pending = deepcopy(list(live.replay._operational.pending.values()))
        for row in pending:
            row["state"] = "cancelled"
        proposals = deepcopy(list(live.replay._reset_proposals.values()))
        activations = deepcopy(list(live.replay._reset_activations.values()))
        history = CompanionReplay(trace)
        factory = history.evidence_factory

        def retained(rows, blobs):
            rows = deepcopy(rows)
            rows.update(
                recovery_pending_resets=pending,
                recovery_reset_proposals=proposals,
                recovery_reset_activations=activations,
            )
            retained_blobs = deepcopy(blobs)
            slots = retained_blobs.setdefault("recovery_slot_blobs", [])
            for slot in live.blobs.get("recovery_slot_blobs", []):
                if not any(s["slot_id"] == slot["slot_id"] for s in slots):
                    slots.append(deepcopy(slot))
            evidence = factory(rows, retained_blobs)

            def unavailable(binding):
                raise AssertionError("History consulted a live SAS gate")

            evidence.reset_sas_verifier = unavailable
            return evidence

        history.evidence_factory = retained
        for record in trace["records"]:
            historical = dict(record, mode="history")
            actual = history.run(historical)
            self.assertEqual(actual["status"], "accepted", actual.get("message"))
            check_summary(self, actual, record["expected"])
        history.finish()


if __name__ == "__main__":
    unittest.main()
