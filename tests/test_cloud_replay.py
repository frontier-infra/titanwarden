"""Signed offline composition, atomicity and restart evidence on disposable stores."""
import sqlite3
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric import ec

from tw import crypto
from tw.cloud_policy import empty_observations
from tw.cloud_wire import hash_object
from tw.policy_log import OfflineCloudVerifier, PolicyError, policy_record
from tw.store import Store, StoreError
from test_cloud_epochs import initial, POINT, TS
import test_cloud_policy as policy_tests


ORG = "0" * 32


class OfflineCompositionTests(unittest.TestCase):
    def setUp(self):
        self.key = ec.derive_private_key(1, ec.SECP256R1())
        public = crypto.b64url(bytes.fromhex(POINT))
        self.genesis = dict(v=2, org_id=ORG, seq=1, prev_hash="0" * 64,
            ts=TS, kind="genesis", signer=dict(kind="broker", id="founder"),
            body=dict(org_id=ORG, founder=dict(kind="broker", id="founder", sign_pub=public, kx_pub=public), recovery_kx_pub=None, recovery_sign_pub=None, default_rules={}, max_policy_age=3600))
        self.root = hash_object(self.genesis)
        self.replay = OfflineCloudVerifier(ORG, self.root, projects=["a"])
        self.append(self.genesis)

    def record(self, entry):
        return policy_record(entry, crypto.p256_sign(self.key, crypto.policy_context(ORG, hash_object(entry))), TS)

    def append(self, entry, **kwargs):
        return self.replay.verify_record(self.record(entry), **kwargs)

    def init(self):
        snapshot = self.replay.authority_view().epoch_snapshot(self.replay.head, ["a"])
        entry, stage = initial(snapshot)
        self.append(entry, stage=stage)
        return entry, stage

    def test_signed_genesis_and_epoch_share_one_exact_chain(self):
        entry, stage = self.init()
        self.assertEqual(self.replay.head, dict(seq=2, hash=hash_object(entry)))
        self.assertEqual(self.replay.state["head"], self.replay.head)
        self.assertEqual(self.replay.epoch_view().committed_generation(self.replay.head), dict(kind="committed", generation=1))
        self.assertEqual(self.replay.epoch_state["org_wraps"], stage["wraps"])
        self.assertEqual(self.replay.state["brokers"], [])

    def test_bad_policy_signature_cannot_activate_valid_epoch(self):
        snap = self.replay.authority_view().epoch_snapshot(self.replay.head, ["a"])
        entry, stage = initial(snap)
        record = self.record(entry)
        tampered = type(record)(record.data, record.hash, bytes(64), record.received_at)
        before = (self.replay.head, self.replay.state, self.replay.epoch_state)
        with self.assertRaises(PolicyError):
            self.replay.verify_record(tampered, stage=stage)
        self.assertEqual((self.replay.head, self.replay.state, self.replay.epoch_state), before)
        self.assertTrue(self.replay.conflict)

    def test_signed_stage_substitution_preserves_both_prefixes(self):
        snap = self.replay.authority_view().epoch_snapshot(self.replay.head, ["a"])
        entry, stage = initial(snap)
        stage["keyring"][0]["wrapped_key"] = "22" * 48
        before = (self.replay.head, self.replay.state, self.replay.epoch_state)
        with self.assertRaises(PolicyError):
            self.append(entry, stage=stage)
        self.assertEqual((self.replay.head, self.replay.state, self.replay.epoch_state), before)

    def test_unknown_kind_and_unknown_derived_kind_fail_closed(self):
        for signer in (dict(kind="broker", id="founder"), dict(kind="derived")):
            replay = OfflineCloudVerifier(ORG, self.root, projects=["a"])
            replay.verify_record(self.record(self.genesis))
            entry = dict(self.genesis, seq=2, prev_hash=self.root, kind="future_kind", body={}, signer=signer)
            record = policy_record(entry, None, TS) if signer["kind"] == "derived" else self.record(entry)
            with self.subTest(signer=signer), self.assertRaises(PolicyError):
                replay.verify_record(record)
            self.assertEqual(replay.head["seq"], 1)
            self.assertTrue(replay.conflict)

    def test_malformed_signed_wire_preserves_typed_conflict_contract(self):
        head = self.replay.head
        with self.assertRaises(PolicyError) as caught:
            self.replay.verify_signed({"entry": {}}, TS)
        self.assertEqual(caught.exception.code, "E_POLICY_CONFLICT")
        self.assertTrue(self.replay.conflict)
        self.assertEqual(self.replay.head, head)

    def test_exact_head_views_reject_boolean_and_float_aliases(self):
        self.assertIsNone(self.replay.authority_view().broker_certificate_at("founder", {**self.replay.head, "seq": True}))
        self.init()
        head = {**self.replay.head, "seq": 2.0}
        self.assertIsNone(self.replay.authority_view().broker_certificate_at("founder", head))
        with self.assertRaises(PolicyError):
            self.replay.epoch_view().active_kek("a", head)


class CloudPersistenceTests(unittest.TestCase):
    record = OfflineCompositionTests.record
    append = OfflineCompositionTests.append
    init = OfflineCompositionTests.init

    def setUp(self):
        OfflineCompositionTests.setUp(self)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name).open(create=True)
        self.addCleanup(self.store.close)
        self.store.initialize_cloud_replay(ORG, self.root)
        self.replay.finish_history([])
        self.store.save_cloud_replay(self.replay)

    def test_restart_keeps_pin_observations_and_conflict_separate(self):
        head = self.replay.head
        self.store.observe_cloud_head(ORG, head, TS)
        self.store.observe_cloud_head(ORG, head, "2026-10-16T00:01:00Z")
        self.store.record_cloud_conflict(ORG, head, "fork", TS)
        self.init()
        self.replay.finish_history([])
        self.store.save_cloud_replay(self.replay, expected_head=head)
        self.store.close()
        self.store.open()
        self.assertEqual(self.store.cloud_pin(ORG), self.root)
        self.assertEqual(self.store.load_cloud_replay(ORG)["head"], self.replay.head)
        observations = self.store.cloud_observations(ORG)
        self.assertEqual(observations["heads"], [dict(head, observed_at="2026-10-16T00:01:00Z")])
        self.assertEqual(self.store.connection.execute("SELECT count(*) FROM cloud_head_observations").fetchone()[0], 2)
        self.assertEqual(self.store.connection.execute("SELECT reason FROM cloud_conflicts").fetchone()[0], "fork")

    def test_independent_pin_and_evidence_cannot_be_overwritten(self):
        with self.assertRaises(StoreError):
            self.store.initialize_cloud_replay(ORG, "f" * 64)
        self.store.observe_cloud_head(ORG, self.replay.head, TS)
        for table in ("cloud_pins", "cloud_replay", "cloud_head_observations"):
            with self.subTest(table=table), self.assertRaises(sqlite3.IntegrityError):
                self.store.connection.execute("DELETE FROM " + table)
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.connection.execute("UPDATE cloud_head_observations SET observed_at=?", ("2026-10-17T00:00:00Z",))

    def test_conflicted_or_competing_snapshot_cannot_replace_prefix(self):
        old_head = self.replay.head
        self.init()
        self.replay.finish_history([])
        with self.assertRaises(StoreError):
            self.store.save_cloud_replay(self.replay, expected_head=dict(seq=0, hash="0" * 64))
        self.assertEqual(self.store.load_cloud_replay(ORG)["head"], old_head)
        with self.assertRaises(PolicyError):
            self.replay.verify_signed({"entry": {}}, TS)
        with self.assertRaises(StoreError):
            self.store.save_cloud_replay(self.replay)

    def test_observations_require_a_persisted_verified_head(self):
        with self.assertRaises(StoreError):
            self.store.observe_cloud_head(ORG, dict(seq=1, hash="f" * 64), TS)
        with self.assertRaises(StoreError):
            self.store.observe_cloud_proposal(ORG, "f" * 64, "live", TS)
        self.assertEqual(self.store.cloud_observations(ORG), empty_observations())

    def test_epochs_cannot_be_substituted_into_authority_checkpoint(self):
        from tw.policy_log import PolicyVerifier, PolicyHooks
        generic = PolicyVerifier(ORG, self.root, {}, PolicyHooks(lambda *a: b'', lambda *a: {}, lambda *a: {}))
        with self.assertRaises(StoreError):
            self.store.save_cloud_replay(generic, {"generation": 999})
        with self.assertRaises(StoreError):
            self.store.save_cloud_replay(self.replay, {"generation": 999})

    def test_longer_validly_signed_fork_cannot_replace_persisted_prefix(self):
        init_entry, stage = self.init()
        head = self.replay.head
        original = dict(self.genesis, seq=3, prev_hash=head["hash"], kind="secret_create",
                        body=dict(secret_id="one", path="a/one", project="a", **{"class": "standard"}))
        self.append(original)
        self.replay.finish_history([])
        self.store.save_cloud_replay(self.replay)
        persisted = self.replay.head
        branch = OfflineCloudVerifier(ORG, self.root, projects=["a"])
        branch.verify_record(self.record(self.genesis))
        branch.verify_record(self.record(init_entry), stage=stage)
        for name in ("two", "three"):
            row = dict(self.genesis, seq=branch.head["seq"] + 1, prev_hash=branch.head["hash"], kind="secret_create",
                       body=dict(secret_id=name, path="a/" + name, project="a", **{"class": "standard"}))
            branch.verify_record(self.record(row))
        branch.finish_history([])
        with self.assertRaisesRegex(StoreError, "does not extend"):
            self.store.save_cloud_replay(branch)
        self.assertEqual(self.store.load_cloud_replay(ORG)["head"], persisted)

    def test_catchup_hold_and_audit_survive_replay_refresh(self):
        from cloud_fixtures import production_traces
        from paired_cloud_fixtures import PairedReplay
        _, document = next((p, d) for p, d in production_traces() if 'authority-holds-v2' in p)
        trace = PairedReplay(document)
        activation_index = next(i for i, r in enumerate(document['records']) if r['entry']['kind'] == 'cert_activate')
        for record in document['records'][:activation_index]:
            self.assertEqual(trace.run(record)['status'], 'accepted')
        activation = document['records'][activation_index]
        proposal = activation['entry']['body']['proposal_hash']
        member_org, later = document['org_id'], activation['received_at']
        self.store.initialize_cloud_replay(member_org, document['pinned_root'])
        trace.finish()
        self.store.save_cloud_replay(trace.replay)
        self.store.observe_cloud_proposal(member_org, proposal, "history", TS)
        self.store.observe_cloud_proposal(member_org, proposal, "live", TS)
        self.assertEqual(self.store.cloud_observations(member_org)["proposals"][proposal], dict(mode="history"))
        self.assertEqual(trace.run(activation)['status'], 'accepted')
        trace.finish()
        self.store.save_cloud_replay(trace.replay)
        with self.assertRaises(StoreError):
            self.store.record_cloud_hold(member_org, proposal, trace.replay.head, "locally_observed", later)
        self.store.record_cloud_hold(member_org, proposal, trace.replay.head, "hold_not_locally_observed", later)
        self.store.save_cloud_replay(trace.replay)
        self.store.close()
        self.store.open()
        self.assertEqual(self.store.connection.execute("SELECT status FROM cloud_hold_evidence").fetchone()[0], "hold_not_locally_observed")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.connection.execute("UPDATE cloud_hold_evidence SET status='locally_observed'")


if __name__ == "__main__":
    unittest.main()
