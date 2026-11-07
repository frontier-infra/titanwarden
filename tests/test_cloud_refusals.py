"""Single-fault broker refusal tests, not cross-language fixture evidence.

Local state/proof adapters isolate transition rules. Immutable cloud fixtures
remain unchanged and supply the separate end-to-end cross-language evidence.
"""

import json
import unittest
from copy import deepcopy
from functools import lru_cache
from unittest.mock import patch

from test_cloud_recovery_requests_paired import CompanionReplay, traces

from tw import (
    cloud_recovery as recovery,
)
from tw import (
    cloud_requests as requests,
)
from tw import (
    cloud_wire as wire,
)
from tw import (
    crypto,
)
from tw.cloud_policy import AuthorityView
from tw.policy_log import PolicyError


@lru_cache(None)
def document(name):
    return next(t for item, t in traces() if item["file"] == name)


def prefix(name, count, operations=0):
    p = CompanionReplay(document(name))
    p.prefix(count, operations)
    return p


class LiveRefusalTests(unittest.TestCase):
    def request_case(self, index=11):
        p = prefix("broker-requests-policy-decisions-v1.json", index)
        e = deepcopy(p.trace["records"][index]["entry"])
        facts = p.evidence(p.rows, p.blobs).request_facts
        facts["open_inbox"] = []
        return p, e, facts, dict(mode="live", now=e["ts"], received_at=e["ts"])

    def test_live_agent_phantom_requires_matching_open_inbox(self):
        p, e, facts, runtime = self.request_case()
        spec = deepcopy(next(iter(p.replay._requests.requests.values()))["request"])
        spec["request_id"] = "req_zzzzzzzzzzzz"
        e["body"].update(request_id=spec["request_id"], request=spec)
        with self.assertRaisesRegex(
            PolicyError, "No matching open agent inbox request"
        ):
            deepcopy(p.replay._requests).apply(e, p.replay.state, facts, runtime)
        # A genuine local open and a historical restatement remain valid.
        for mode, inbox in [
            ("live", [dict(state="open", request=spec)]),
            ("history", []),
        ]:
            m = deepcopy(p.replay._requests)
            m.apply(
                e,
                p.replay.state,
                dict(facts, open_inbox=inbox),
                dict(runtime, mode=mode),
            )
            self.assertIn("grt_zzzzzzzzzzzz", m.grants)
        for change in [
            dict(state="withdrawn", request=spec),
            dict(state="open", request=dict(spec, reason="changed")),
        ]:
            with self.assertRaisesRegex(
                PolicyError, "No matching open agent inbox request"
            ):
                deepcopy(p.replay._requests).apply(
                    e, p.replay.state, dict(facts, open_inbox=[change]), runtime
                )

    def test_live_signed_open_cannot_collide_with_agent_inbox(self):
        p, e, facts, runtime = self.request_case(10)
        facts["open_inbox"] = [dict(state="open", request=e["body"]["request"])]
        with self.assertRaisesRegex(PolicyError, "Duplicate request"):
            p.replay._requests.apply(e, p.replay.state, facts, runtime)

    def test_live_quorum_binding_checks_usable_slots_before_proposal(self):
        p = prefix("broker-recovery-reset-activate-v1.json", 10)
        state = p.replay.state
        subject = AuthorityView(state).current("reset-subject-activate")
        old = subject["certificate"]
        retained = dict(old["passkeys"][0], credential_id="dW5pdC1vbmx5")
        old["passkeys"].append(retained)
        next(row for row in state["certificates"] if row["seq"] == subject["seq"])[
            "certificate"
        ] = old
        cert = dict(old, cert_no=old["cert_no"] + 1, passkeys=[retained])
        e = deepcopy(p.trace["records"][10]["entry"])
        e["body"].update(
            requested=dict(kind="member", certificate=cert),
            prior_cert_seq=subject["seq"],
        )
        e["body"]["passkey_binding"].update(
            reset_id=None, prior_cert_seq=subject["seq"], slots=[]
        )
        v = p.replay
        v._active_runtime = dict(mode="live", now=e["ts"], received_at=e["ts"])
        v._active_evidence = p.evidence(p.rows, p.blobs)
        with (
            patch.object(
                recovery,
                "verify_subject_proofs",
                return_value=({"authorization": {}}, {retained["credential_id"]}),
            ),
            patch.object(wire, "verify_authorization", return_value="local-unit-proof"),
        ):
            with self.assertRaisesRegex(ValueError, "Last usable slot or passkey slot"):
                v._binding(e, state)


def activate(p, index):
    v = p.replay
    record = p.trace["records"][index]
    e = deepcopy(record["entry"])
    v._active_runtime = dict(
        mode=record["mode"],
        now=record["received_at"],
        received_at=record["received_at"],
        observations={"heads": [], "proposals": {}},
        audit_hold=lambda *args: None,
    )
    v._active_evidence = p.evidence(p.rows, p.blobs)
    v._candidate_epochs = deepcopy(v._epochs)
    return v, e, deepcopy(v.state)


class RecoveryRefusalTests(unittest.TestCase):
    def claim(self, n=10):
        p = prefix("broker-recovery-claims-activate-v1.json", n)
        v, e, state = activate(p, n)
        return p, v, e, state

    def reset(self, n=10):
        p = prefix("broker-recovery-reset-activate-v1.json", n, 1 if n == 10 else 2)
        p.install(p.trace["records"][n]["evidence"])
        v, e, state = activate(p, n)
        return p, v, e, state

    def test_activation_counts_only_independent_continuously_eligible_endorsers(self):
        for fault in ("generator", "lowered"):
            p, v, e, state = self.claim(12)
            claim = state["recovery_protocol"]["claims"][e["body"]["proposal_hash"]]
            member = claim["endorsements"][0]
            if fault == "generator":
                claim["recovery_generated_by"] = member
            else:
                current = AuthorityView(state).current(member)
                state["head"]["seq"] += 1
                e["seq"] += 1
                state["certificates"].append(
                    dict(
                        seq=state["head"]["seq"],
                        certificate=dict(
                            current["certificate"], role="member", key_holder=False
                        ),
                    )
                )
            with (
                self.subTest(fault=fault),
                self.assertRaisesRegex(ValueError, "Logged hold too short"),
            ):
                v._recovery_derive(
                    e,
                    state,
                    v._active_runtime["received_at"],
                    recovery.policy.authority_hooks(v._active_runtime),
                )

    def test_activation_rechecks_generation_even_before_supersede_projection(self):
        p, v, e, state = self.claim(12)
        with (
            patch.object(v, "_generation", return_value=2),
            self.assertRaisesRegex(ValueError, "Recovery claim expired or superseded"),
        ):
            v._recovery_derive(e, state, v._active_runtime["received_at"], None)

    def test_reset_receipt_time_window_and_exact_seven_day_ttl(self):
        for fault in ("future_created", "expired", "long_ttl"):
            p, v, e, state = self.reset()
            ev = v._evidence()
            row = ev._rows["recovery_pending_resets"][0]
            if fault == "future_created":
                row["created_at"] = requests.iso(
                    requests.timestamp(row["created_at"]) + 1
                )
            elif fault == "expired":
                v._active_runtime["received_at"] = row["expires_at"]
            else:
                row["expires_at"] = requests.iso(
                    requests.timestamp(row["expires_at"]) + 1
                )
            cert = e["body"]["requested"]["certificate"]
            binding = e["body"]["passkey_binding"]
            with (
                self.subTest(fault=fault),
                self.assertRaisesRegex(ValueError, "Reset expired at admission"),
            ):
                ev.reset_sas(
                    e, state, cert, v._active_runtime, binding, v._history_states
                )

    def test_sas_admin_cannot_be_subject_even_if_subject_is_admin(self):
        p, v, e, state = self.reset()
        cert = e["body"]["requested"]["certificate"]
        current = AuthorityView(state).current(cert["member_id"])
        row = dict(
            reset_id="r",
            subject_member_id=cert["member_id"],
            admin_member_id=cert["member_id"],
            admin_cert_seq=current["seq"],
            sas_transcript_digest="0" * 64,
            verified_at=e["ts"],
        )
        with self.assertRaisesRegex(
            ValueError, "Reset SAS subject or transcript differs"
        ):
            recovery.checked_reset_evidence(row, "r", cert, state, e["ts"])

    def test_history_receipt_rechecks_the_sas_context_before_activation(self):
        p, v, e, state = self.reset(12)
        # Receipts come from prior accepted local stages, never a remote checkpoint.
        proposal = p.trace["records"][10]
        evidence = v._evidence()
        row = evidence._rows["recovery_reset_proposals"][0]
        sas = json.loads(row["sas_evidence_json"])
        sas["sas_transcript_digest"] = "0" * 64
        row["sas_evidence_json"] = json.dumps(sas)
        before = v._history_states[10]
        cert = proposal["entry"]["body"]["requested"]["certificate"]
        with self.assertRaisesRegex(
            ValueError, "Immutable reset SAS transcript differs"
        ):
            evidence.reset_sas(
                proposal["entry"],
                before,
                cert,
                dict(mode="history", received_at=proposal["received_at"]),
                proposal["entry"]["body"]["passkey_binding"],
                v._history_states,
            )

    def test_activation_sas_rechecks_proposal_match_independently(self):
        p, v, e, state = self.reset(12)
        binding = state["recovery_protocol"]["bindings"][e["body"]["proposal_hash"]]
        altered = dict(
            binding["sas_evidence"],
            verified_at=v._active_runtime["received_at"],
            sas_transcript_digest="0" * 64,
        )
        with (
            patch.object(recovery.RecoveryEvidence, "reset_sas", return_value=altered),
            self.assertRaisesRegex(
                ValueError, "Reset activation SAS differs from proposal"
            ),
        ):
            v._recovery_derive(e, state, v._active_runtime["received_at"], None)

    def test_admin_cannot_cancel_an_admin_reset(self):
        p = prefix("broker-recovery-reset-owner-cancel-v1.json", 6, 2)
        v, e, state = activate(p, 6)
        signer = AuthorityView(state).current(e["signer"]["id"])
        next(x for x in state["certificates"] if x["seq"] == signer["seq"])[
            "certificate"
        ]["role"] = "admin"
        with self.assertRaisesRegex(
            ValueError, "Reset cancellation needs subject rank authority"
        ):
            v._recovery_authorize(e, state, None)

    def test_signed_cancellation_blocks_a_subsequent_binding(self):
        p, v, e, state = self.reset()
        state["recovery_protocol"]["cancelled_resets"] = {
            e["body"]["passkey_binding"]["reset_id"]: dict(
                member_id=e["body"]["subject"]
            )
        }
        with self.assertRaisesRegex(ValueError, "Reset has a signed cancellation"):
            v._binding(e, state)

    def test_cancellation_also_cancels_open_binding_proposals(self):
        p, v, unused, state = self.reset(11)
        digest = next(iter(state["recovery_protocol"]["bindings"]))
        binding = state["recovery_protocol"]["bindings"][digest]
        proposal = state["proposals"][digest]
        subject = AuthorityView(state).current(proposal["subject"])["certificate"]
        e = dict(
            v=2,
            org_id=state["org_id"],
            seq=state["head"]["seq"] + 1,
            prev_hash=state["head"]["hash"],
            ts=v._active_runtime["now"],
            kind="member_key_reset_cancel",
            signer=dict(
                kind="member", id=subject["member_id"], key=subject["member_key_id"]
            ),
            body=dict(
                reset_id=binding["reset_id"],
                member_id=subject["member_id"],
                prior_cert_seq=binding["prior_cert_seq"],
                request_id="unit-cancel",
            ),
        )
        v._recovery_authorize(e, state, None)
        self.assertTrue(state["proposals"][digest]["cancelled"])

    def test_reset_reservation_is_only_reusable_by_its_own_binding(self):
        p, v, e, state = self.reset()
        slot = e["body"]["passkey_binding"]["slots"][0]
        with self.assertRaisesRegex(ValueError, "Slot id already reserved by reset"):
            v._reserve_descriptor(slot, state, reset_id="different-reset")
        v._reserve_descriptor(
            slot, state, reset_id=e["body"]["passkey_binding"]["reset_id"]
        )

    def test_wrap_requires_current_recovery_point_and_a_later_commit(self):
        for fault in ("point", "fence"):
            p = prefix("broker-recovery-claims-activate-v1.json", 14)
            v = p.replay
            if fault == "point":
                for e in v._records:
                    if e["kind"] == "epoch_rotate":
                        for r in e["body"]["recipients"]:
                            if r["kind"] == "recovery":
                                r["kx_pub_sha256"] = "0" * 64
                message = "Recovery epoch names an old recipient"
            else:
                v._verifier._state["recovery_seq"] = v.epoch_state["epochs"][-1][
                    "commit_seq"
                ]
                message = "Current full recovery epoch unavailable"
            with (
                self.subTest(fault=fault),
                self.assertRaisesRegex(PolicyError, message),
            ):
                v.recovery_wrap(evidence=p.evidence(p.rows, p.blobs))

    def test_claim_wrap_pending_rechecks_current_generation(self):
        p, v, e, state = self.claim(11)
        claim = next(iter(state["recovery_protocol"]["claims"].values()))
        self.assertTrue(
            recovery.claim_wrap_pending(claim, state, 1, requests.timestamp(e["ts"]))
        )
        self.assertFalse(
            recovery.claim_wrap_pending(claim, state, 2, requests.timestamp(e["ts"]))
        )

    def test_self_reset_and_non_owner_high_rank_certifiers_are_refused(self):
        for fault, message in [
            ("self", "Reset needs other certifiers"),
            ("admin", "No binding certifier quorum"),
        ]:
            p, v, e, state = self.reset()
            subject = e["body"]["subject"]
            if fault == "self":
                old = AuthorityView(state).current(subject)["certificate"]
                e["signer"] = dict(kind="member", id=subject, key=old["member_key_id"])
                e["body"]["passkey_binding"]["mode"] = "self"
                e["kind"] = "member_cert"
                for field in ("subject", "prior_cert_seq", "reason"):
                    e["body"].pop(field)
            else:
                actor = AuthorityView(state).current("helper")
                e["signer"] = dict(
                    kind="member",
                    id="helper",
                    key=actor["certificate"]["member_key_id"],
                )
                next(c for c in state["certificates"] if c["seq"] == actor["seq"])[
                    "certificate"
                ]["role"] = "admin"
            cert = e["body"]["requested"]["certificate"]
            with (
                patch.object(
                    recovery,
                    "verify_subject_proofs",
                    return_value=(
                        {"authorization": {}},
                        {p["credential_id"] for p in cert["passkeys"]},
                    ),
                ),
                patch.object(wire, "verify_authorization", return_value="unit-proof"),
            ):
                with (
                    self.subTest(fault=fault),
                    self.assertRaisesRegex(ValueError, message),
                ):
                    v._binding(e, state)

    def test_claim_and_binding_require_every_new_credential_proof(self):
        p, v, e, state = self.claim()
        cert = e["body"]["requested"]["certificate"]
        other = dict(cert["passkeys"][0], credential_id="c2Vjb25kLWNyZWRlbnRpYWw")
        cert["passkeys"].append(other)
        with (
            patch.object(
                recovery,
                "verify_subject_proofs",
                return_value=(
                    {"authorization": {}},
                    {cert["passkeys"][0]["credential_id"]},
                ),
            ),
            patch.object(
                recovery, "possession_authorization", return_value="unit-proof"
            ),
            self.assertRaisesRegex(
                ValueError, "Recovery possession credential mismatch"
            ),
        ):
            v._recovery_authorize(e, state, None)
        p, v, e, state = self.reset()
        cert = e["body"]["requested"]["certificate"]
        other = dict(cert["passkeys"][0], credential_id="c2Vjb25kLWNyZWRlbnRpYWw")
        added = deepcopy(cert["passkeys"]) + [other]
        old = AuthorityView(state).current(cert["member_id"])["certificate"]
        for field in ("member_key_id", "sign_pub", "kx_pub"):
            cert[field] = old[field]
        cert["passkeys"] = deepcopy(old["passkeys"]) + added
        e["body"]["passkey_binding"]["reset_id"] = None
        e["body"]["passkey_binding"]["slots"][0]["member_key_id"] = cert[
            "member_key_id"
        ]
        e["body"]["passkey_binding"]["slots"][0]["slot_id"] = "first-unit-slot"
        slot = deepcopy(e["body"]["passkey_binding"]["slots"][0])
        slot["slot_id"] = "second-unit-slot"
        slot["params"]["credential_id"] = other["credential_id"]
        e["body"]["passkey_binding"]["slots"].append(slot)
        with (
            patch.object(
                recovery,
                "verify_subject_proofs",
                return_value=(
                    {"authorization": {}},
                    {added[0]["credential_id"]},
                ),
            ),
            patch.object(wire, "verify_authorization", return_value="unit-proof"),
            self.assertRaisesRegex(ValueError, "Missing added credential possession"),
        ):
            v._binding(e, state)

    def test_recovery_bootstrap_requires_the_sole_privileged_member(self):
        p = prefix("broker-recovery-revoke-and-set-v1.json", 9)
        e = deepcopy(p.trace["cases"][0]["record"]["entry"])
        v = p.replay
        state = v.state
        # Synthetic authority view isolates this otherwise closed bootstrap rule.
        state["founder"]["mode"] = "broker"
        state["recovery"] = None
        state["recovery_ever_set"] = False
        v._active_runtime = dict(mode="history", now=e["ts"], received_at=e["ts"])
        v._active_evidence = p.evidence(p.rows, p.blobs)
        actor = AuthorityView(state).current(e["signer"]["id"])["certificate"]
        extra = dict(
            actor,
            member_id="unit-other-owner",
            member_key_id="unit-other-key",
            workos_user_id="unit-other-human",
        )
        state["certificates"].append(dict(seq=state["head"]["seq"], certificate=extra))
        with (
            patch.object(wire, "verify_authorization", return_value="unit-proof"),
            self.assertRaisesRegex(ValueError, "Recovery bootstrap unavailable"),
        ):
            v._recovery_authorize(e, state, None)

    def test_claim_requires_new_member_key_and_unconsumed_paper_key(self):
        p, v, e, state = self.claim()
        old = AuthorityView(state).current(e["body"]["subject"])["certificate"]
        cert = e["body"]["requested"]["certificate"]
        for key in ("member_key_id", "sign_pub", "kx_pub"):
            cert[key] = old[key]
        with self.assertRaisesRegex(
            ValueError, "Recovery requires new owner keys and passkey"
        ):
            v._recovery_authorize(e, state, None)
        p, v, e, state = self.claim()
        state["recovery_protocol"]["used_recovery_sign_keys"].append(
            state["recovery"]["sign_pub"]
        )
        with self.assertRaisesRegex(ValueError, "Typed recovery claim required"):
            v._recovery_authorize(e, state, None)

    def test_pending_reset_checks_signature_and_signed_time(self):
        p = prefix("broker-recovery-reset-activate-v1.json", 10)
        op = p.trace["operations"][0]
        signed = {k: deepcopy(op["request"]["body"][k]) for k in ("entry", "sig")}
        recovery.verify_pending_reset(signed, p.replay.state, op["received_at"])
        for fault in ("signature", "time"):
            altered = deepcopy(signed)
            if fault == "signature":
                altered["sig"] = crypto.b64url(bytes(64))
            else:
                altered["entry"]["ts"] = requests.iso(
                    requests.timestamp(op["received_at"]) - 300001
                )
            with (
                self.subTest(fault=fault),
                self.assertRaisesRegex(
                    ValueError, "Pending reset signature or time differs"
                ),
            ):
                recovery.verify_pending_reset(
                    altered, p.replay.state, op["received_at"]
                )

    def test_recovery_session_refuses_a_certified_prf_slot(self):
        from cryptography.hazmat.primitives.asymmetric import ec

        p = prefix("broker-recovery-session-v1.json", 4)
        op = p.trace["operations"][0]
        signed = {k: deepcopy(op["request"]["body"][k]) for k in ("entry", "sig")}
        state = p.replay.state
        # Public test-only scalar. It is never stored or treated as cloud evidence.
        key = ec.derive_private_key(421, ec.SECP256R1())
        owner = AuthorityView(state).current("owner")
        next(v for v in state["certificates"] if v["seq"] == owner["seq"])[
            "certificate"
        ]["sign_pub"] = crypto.b64url(crypto.export_point(key.public_key()))
        signed["entry"]["body"]["slot_id"] = next(
            s["slot_id"]
            for s in state["recovery_protocol"]["slots"]
            if s["kind"] == "webauthn_prf"
        )
        signed["sig"] = crypto.b64url(
            crypto.p256_sign(
                key,
                crypto.policy_context(
                    state["org_id"], wire.hash_object(signed["entry"])
                ),
            )
        )
        with self.assertRaisesRegex(ValueError, "Active own passphrase slot required"):
            recovery.RecoveryOperations().report_session(
                signed, state, op["received_at"]
            )

    def test_claim_wrap_reference_must_name_the_new_member_key(self):
        p, v, e, state = self.claim()
        e["body"]["requested"]["member_wrap"]["recipient"]["id"] = "unit-other-key"
        cert = e["body"]["requested"]["certificate"]
        # The independent proof adapters are held valid to isolate the signed
        # reference rule; no synthetic bytes are offered as cloud evidence.
        with (
            patch.object(
                recovery,
                "verify_subject_proofs",
                return_value=(
                    {"authorization": {}},
                    {key["credential_id"] for key in cert["passkeys"]},
                ),
            ),
            patch.object(
                recovery, "possession_authorization", return_value="unit-proof"
            ),
            self.assertRaisesRegex(
                ValueError, "Current member wrap commitment differs"
            ),
        ):
            v._recovery_authorize(e, state, None)


class RequestRefusalTests(unittest.TestCase):
    request_case = LiveRefusalTests.request_case

    def test_principal_and_associated_member_cannot_decide_their_own_request(self):
        cert = {"member_id": "unit-owner", "role": "owner"}
        target = {
            "class": "standard",
            "client_approval_required": False,
            "project": "a",
        }
        for principal in [
            dict(id="unit-owner"),
            dict(id="other", member_id="unit-owner"),
        ]:
            self.assertFalse(requests.member_may_decide(cert, principal, target, {}))

    def test_rules_cannot_loosen_any_baseline_dimension(self):
        for fault in ("delay", "ttl", "enable", "ops"):
            name = (
                "shared_standard"
                if fault in ("delay", "ttl")
                else "restricted"
                if fault == "enable"
                else "create"
            )
            rule = deepcopy(requests.baseline_rules()[name])
            if fault == "delay":
                rule["delay_seconds"] -= 1
            elif fault == "ttl":
                rule["ttl_cap_seconds"] += 1
            elif fault == "enable":
                rule["enabled"] = True
            else:
                rule["ops"] = ["use"]
            with (
                self.subTest(fault=fault),
                self.assertRaisesRegex(ValueError, "Rules may only tighten"),
            ):
                requests.tighten_rules({name: rule})

    def test_manual_grant_bounds_requested_operations_ttl_and_server_time(self):
        for fault in ("ops", "ttl", "server_clock"):
            p, e, facts, runtime = self.request_case()
            runtime["mode"] = "history"
            if fault == "ops":
                e["body"]["grant"]["ops"] = ["audit"]
            elif fault == "ttl":
                spec = next(iter(p.replay._requests.requests.values()))["request"]
                e["body"]["grant"]["expires_at"] = requests.iso(
                    requests.timestamp(e["ts"]) + spec["ttl_seconds"] * 1000 + 1
                )
            else:
                runtime["now"] = requests.iso(requests.timestamp(e["ts"]) - 1000)
                spec = next(iter(p.replay._requests.requests.values()))["request"]
                e["body"]["grant"]["expires_at"] = requests.iso(
                    requests.timestamp(e["ts"]) + spec["ttl_seconds"] * 1000
                )
            with (
                self.subTest(fault=fault),
                self.assertRaisesRegex(
                    PolicyError, "Manual grant exceeds request or server-clock bound"
                ),
            ):
                p.replay._requests.apply(e, p.replay.state, facts, runtime)

    def test_terminal_deny_cannot_be_decided_again_without_grant_collision(self):
        p, e, facts, runtime = self.request_case()
        runtime["mode"] = "history"
        p.replay._requests.requests[e["body"]["request_id"]]["state"] = "denied"
        e["body"].update(decision="deny", grant=None)
        with self.assertRaisesRegex(PolicyError, "Request already terminal"):
            p.replay._requests.apply(e, p.replay.state, facts, runtime)

    def test_default_signed_position_and_evaluation_clock_are_both_bounded(self):
        p, e, facts, runtime = self.request_case(13)
        opened = p.replay._requests.requests[e["body"]["request_id"]]
        e["ts"] = opened["default_at"]
        runtime.update(
            mode="history", now=requests.iso(requests.timestamp(e["ts"]) + 1000)
        )
        with self.assertRaisesRegex(PolicyError, "Default deadline mismatch"):
            p.replay._requests.apply(e, p.replay.state, facts, runtime)
        from cloud_fixtures import ROOT

        doc = wire.load_pinned_json(
            ROOT / "control/src/requests/vectors/h4-v1.json",
            "47d19a0f5e61984403c05b82844db4db18753de07cbb36bd230aceaf8a5718e3",
        )
        case = deepcopy(doc["cases"][0])
        case["context"]["now"] = requests.timestamp(case["opened"]["default_at"])
        with self.assertRaisesRegex(ValueError, "Default deadline mismatch"):
            requests.derive_default(case["body"], case["opened"], case["context"])

    def test_grant_id_and_linked_request_collisions_never_overwrite(self):
        for fault in ("own_id", "external_deny", "linked_request"):
            p, e, facts, runtime = self.request_case()
            runtime["mode"] = "history"
            ident = requests.request_grant_id(e["body"]["request_id"])
            if fault == "own_id":
                p.replay._requests.grants[ident] = {"canary": "untouched"}
            elif fault == "external_deny":
                facts["grants"] = [
                    dict(grant_id=ident, request_id="unrelated", effect="deny")
                ]
            else:
                facts["grants"] = [
                    dict(
                        grant_id="different",
                        request_id=e["body"]["request_id"],
                        effect="allow",
                    )
                ]
            with (
                self.subTest(fault=fault),
                self.assertRaisesRegex(
                    PolicyError, "Request grant collides with existing policy"
                ),
            ):
                p.replay._requests.apply(e, p.replay.state, facts, runtime)

    def test_restricted_and_client_decisions_cannot_omit_passkey_authorization(self):
        for fault in ("restricted", "client"):
            p, e, facts, runtime = self.request_case()
            runtime["mode"] = "history"
            target = next(
                t
                for t in facts["targets"]
                if t["path"] == e["body"]["grant"]["pattern"]
            )
            if fault == "restricted":
                target["class"] = "restricted"
                e["body"]["grant"]["max_class"] = "restricted"
            else:
                target["client_approval_required"] = True
                e["body"]["client_approval_ref"] = "unit-client-ref"
            with (
                self.subTest(fault=fault),
                self.assertRaisesRegex(PolicyError, "unexpected schema"),
            ):
                p.replay._requests.apply(e, p.replay.state, facts, runtime)

    def test_default_refuses_a_demoted_member_opener(self):
        p, e, facts, runtime = self.request_case(13)
        runtime["mode"] = "history"
        state = p.replay.state
        opened = p.replay._requests.requests[e["body"]["request_id"]]
        source = p.replay._requests.sources[opened["request"]["request_id"]]
        member = source["signer"]["id"]
        current = AuthorityView(state).current(member)
        state["head"]["seq"] += 1
        e["seq"] += 1
        facts["head"] = deepcopy(state["head"])
        state["certificates"].append(
            dict(
                seq=state["head"]["seq"],
                certificate=dict(current["certificate"], role="member", reveal=True),
            )
        )
        with self.assertRaisesRegex(PolicyError, "Member opener no longer eligible"):
            p.replay._requests.apply(e, state, facts, runtime)

    def test_default_origin_cannot_be_agent_even_with_nonnull_open_sequence(self):
        from cloud_fixtures import ROOT

        doc = wire.load_pinned_json(
            ROOT / "control/src/requests/vectors/h4-v1.json",
            "47d19a0f5e61984403c05b82844db4db18753de07cbb36bd230aceaf8a5718e3",
        )
        case = deepcopy(doc["cases"][0])
        case["opened"]["origin"] = "agent"
        with self.assertRaisesRegex(ValueError, "Request cannot default"):
            requests.derive_default(case["body"], case["opened"], case["context"])


class AdditionalRefusalTests(unittest.TestCase):
    def test_freshness_checks_credential_ids_points_empty_lists_and_all_key_history(
        self,
    ):
        p = prefix("broker-recovery-claims-activate-v1.json", 10)
        state = p.replay.state
        source = p.trace["records"][10]["entry"]["body"]["requested"]["certificate"]
        old = AuthorityView(state).current(source["member_id"])["certificate"]
        recovery.assert_fresh_key_set(state, source["member_id"], source)
        for fault in ("id", "point", "empty", "key_history"):
            cert = deepcopy(source)
            if fault == "id":
                cert["passkeys"][0]["credential_id"] = old["passkeys"][0][
                    "credential_id"
                ]
            elif fault == "point":
                cert["passkeys"][0]["cose_key"] = old["passkeys"][0]["cose_key"]
            elif fault == "empty":
                cert["passkeys"] = []
            else:
                cert["member_key_id"] = old["member_key_id"]
            message = (
                "New member keys reuse prior key material"
                if fault == "key_history"
                else "Reset passkeys must be fresh against subject history"
            )
            with self.subTest(fault=fault), self.assertRaisesRegex(ValueError, message):
                recovery.assert_fresh_key_set(state, source["member_id"], cert)

    def test_pending_admission_reserves_claim_binding_reset_initial_and_private_ids(
        self,
    ):
        for pool, message in [
            ("claim", "Slot id already reserved"),
            ("binding", "Slot id already reserved"),
            ("reset", "Slot id already reserved by reset"),
            ("initial", "Slot id reserved by initial slot"),
            ("private", "Slot id reserved by private staging"),
        ]:
            p = prefix("broker-recovery-reset-activate-v1.json", 10)
            op = p.trace["operations"][0]
            signed = {k: deepcopy(op["request"]["body"][k]) for k in ("entry", "sig")}
            slot = signed["entry"]["body"]["slot"]
            v = p.replay
            rows = deepcopy(p.rows)
            blobs = deepcopy(p.blobs)
            blobs.setdefault("recovery_slot_blobs", []).append(
                dict(
                    op["request"]["body"]["slots"][0],
                    member_key_id=slot["member_key_id"],
                )
            )
            protocol = v._verifier._state["recovery_protocol"]
            if pool == "claim":
                protocol["claims"]["unit-reserved"] = {"slot": slot}
            elif pool == "binding":
                protocol["bindings"] = {"unit-reserved": {"slots": [slot]}}
            elif pool == "reset":
                rows["recovery_pending_resets"] = [
                    dict(
                        reset_id="another",
                        request_json=json.dumps({"entry": {"body": {"slot": slot}}}),
                    )
                ]
            elif pool == "private":
                rows["recovery_slot_blobs"] = [dict(slot_id=slot["slot_id"])]
            evidence = p.evidence(rows, blobs)
            with patch.object(
                v,
                "_initial_slots",
                return_value=[dict(slot_id=slot["slot_id"])]
                if pool == "initial"
                else [],
            ):
                with (
                    self.subTest(pool=pool),
                    self.assertRaisesRegex(ValueError, message),
                ):
                    v.verify_operational(signed, op["received_at"], evidence=evidence)
            self.assertEqual(v.operational_state["pending_resets"], {})

    def test_evidence_overlay_copies_instead_of_mutating_the_callers_rows(self):
        p = prefix("broker-recovery-reset-activate-v1.json", 10, 1)
        v = p.replay
        evidence = p.evidence(p.rows, p.blobs)
        before = deepcopy(evidence._rows)
        v._active_evidence = evidence
        self.assertTrue(v._evidence()._rows["recovery_pending_resets"])
        self.assertEqual(evidence._rows, before)

    def test_authorization_signer_binding_with_valid_local_passkey_signature(self):
        from test_cloud_policy import SignedAuthorityTraceTests

        local = SignedAuthorityTraceTests()
        local.setUp()
        e = local.entry("member_cert", dict(request_id="local-signer-binding"))
        e["signer"] = dict(kind="member", id="different-member", key="different-key")
        target = dict(member_id=local.cert["member_id"])
        # The public test-only keys in that helper create a real assertion over
        # the changed core, so no other binding or signature masks this refusal.
        local.prove(e, target)
        with self.assertRaisesRegex(
            ValueError, "Authorization binding or validity failed"
        ):
            wire.verify_authorization(e, local.cert, target, [], local.runtime)

    def test_recovery_session_mode_never_grants_privileged_actions(self):
        for action in ("unwrap_omk", "sign_policy", "reveal", "export"):
            self.assertFalse(
                recovery.recovery_session_allows("passphrase_recovery", action)
            )
        self.assertTrue(
            recovery.recovery_session_allows("passphrase_recovery", "bind_passkey")
        )
