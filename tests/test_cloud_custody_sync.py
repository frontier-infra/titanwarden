"""Production key pickup plus single-fault broker custody refusal regressions."""
import copy
import json
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec

from tw import crypto
from tw.cloud_sync import CloudSync
from tw.cloud_recovery import RecoveryEvidence, RecoveryVerifier
from tw.cloud_sync_verifier import SyncVerifier
from paired_cloud_fixtures import decode
from tw.policy_log import PolicyError
from tw.policy_log import OfflineCloudVerifier
from tw.store import StoreError
from ops_cloud_fixtures import documents
import test_cloud_ops_paired as ops_tests
from test_cloud_ops_paired import result
import test_cloud_sync as sync_tests
from test_cloud_sync import ORG, BROKER, NOW


class CustodyGuardTests(unittest.TestCase):
    def scoped(self):
        helper = ops_tests.OperationalFixtureTests()
        helper.docs = documents()
        self.addCleanup(helper.doCleanups)
        doc, replay, session, store, blk = helper.scoped_setup()
        sync = CloudSync(store, doc['org_id'], session.broker_id)
        sync.accept_pull(replay.harness.replay, [], observed_at=doc['received_at'])
        return doc, replay, session, store, blk, sync

    def test_scoped_pickup_exact_commitments_generation_duplicates_and_completeness(self):
        doc, replay, session, store, blk, sync = self.scoped()
        valid = result(doc['steps'][6])
        for fault in ('generation', 'commitment', 'scope', 'duplicate', 'missing'):
            response = copy.deepcopy(valid)
            if fault == 'generation': response['omk_generation'] = 2
            if fault == 'commitment': response['broker_key_wraps'][0]['wrapped_key'] = '11' * 48
            if fault == 'scope': response['broker_key_wraps'][0]['project'] = 'b'
            if fault == 'duplicate': response['broker_key_wraps'] *= 2
            if fault == 'missing': response['broker_key_wraps'] = response['broker_key_wraps'][:1]
            with self.subTest(fault=fault), self.assertRaises((PolicyError, ValueError)):
                sync.pickup_keys(response, blk, session.exchange_key)
        sync.pickup_keys(valid, blk, session.exchange_key)
        sync.refuse('fork', doc['received_at'])
        with self.assertRaisesRegex(PolicyError, 'conflicted key pickup'):
            sync.pickup_keys(valid, blk, session.exchange_key)

    def test_key_pickup_rechecks_head_and_rejects_local_rebinding(self):
        doc, replay, session, store, blk, sync = self.scoped()
        valid = result(doc['steps'][6])
        state = sync.checkpoint()
        changed = copy.deepcopy(state)
        changed['head']['seq'] += 1
        with (patch.object(sync, 'checkpoint', side_effect=[state, state, changed]),
              self.assertRaisesRegex(PolicyError, 'key pickup head changed')):
            sync.pickup_keys(valid, blk, session.exchange_key)
        store.initialize_cloud_custody()
        store.put_cloud_local_key(blk, org=doc['org_id'], broker=session.broker_id, key_id='fk', purpose='fingerprint', scope='*', generation=1, key=bytes([88]) * 32)
        with self.assertRaisesRegex(PolicyError, 'custody rebinding'):
            sync.pickup_keys(valid, blk, session.exchange_key)
        self.assertEqual(store.connection.execute("SELECT count(*) FROM cloud_local_keys WHERE purpose='kek'").fetchone()[0], 0)

    def test_full_pickup_requires_exact_current_omk_and_keyring(self):
        h = sync_tests.SyncTests()
        h.setUp()
        self.addCleanup(h.doCleanups)
        epoch = h.sync.checkpoint()['epochs']
        response = dict(omk_generation=1, my_wrap=epoch['org_wraps'][0], keyring=epoch['keyring'])
        blk = bytes([77]) * 32
        h.sync.pickup_keys(response, blk, h.exchange)
        for fault in ('omk', 'keyring'):
            bad = copy.deepcopy(response)
            if fault == 'omk': bad['my_wrap']['wrapped_omk'] = '11' * 48
            if fault == 'keyring': bad['keyring'][0]['wrapped_key'] = '11' * 48
            with self.subTest(fault=fault), self.assertRaisesRegex(PolicyError, 'commitment differs'):
                h.sync.pickup_keys(bad, blk, h.exchange)

    def test_unpublished_rebuild_guards_and_delivery_snapshot_guard(self):
        h = sync_tests.SyncTests()
        h.setUp()
        self.addCleanup(h.doCleanups)
        with self.assertRaisesRegex(PolicyError, 'retained payload'):
            h.sync.rebuild_unpublished('missing', h.keys['ka'], h.keys['ka'], h.signing, now=NOW)
        h.sync.stage_version(h.payload(), now=NOW)
        original = h.store.connection.execute('SELECT payload_json FROM cloud_unpublished').fetchone()[0]
        missing = json.loads(original)
        missing.pop('secret')
        h.store.connection.execute('UPDATE cloud_unpublished SET payload_json=?', (crypto.canonical_json(missing).decode(),))
        with self.assertRaisesRegex(PolicyError, 'secret missing'):
            h.sync.rebuild_unpublished('version', h.keys['ka'], h.keys['ka'], h.signing, now=NOW)
        h.store.connection.execute('UPDATE cloud_unpublished SET payload_json=?', (original,))
        with self.assertRaisesRegex(PolicyError, 'signing key differs'):
            h.sync.rebuild_unpublished('version', h.keys['ka'], h.keys['ka'], ec.derive_private_key(122, ec.SECP256R1()), now=NOW)
        state = h.sync.checkpoint()
        changed = copy.deepcopy(state)
        changed['head']['seq'] += 1
        with (patch.object(h.sync, 'checkpoint', side_effect=[state, state, changed]),
              self.assertRaisesRegex(PolicyError, 'rebuild head changed')):
            h.sync.rebuild_unpublished('version', h.keys['ka'], h.keys['ka'], h.signing, now=NOW)
        calls = 0
        def raced_checkpoint():
            nonlocal calls
            calls += 1
            if calls == 3:
                h.store.connection.execute("UPDATE cloud_unpublished SET payload_json='{}'")
            return state
        with (patch.object(h.sync, 'checkpoint', side_effect=raced_checkpoint),
              self.assertRaisesRegex(PolicyError, 'rebuild raced')):
            h.sync.rebuild_unpublished('version', h.keys['ka'], h.keys['ka'], h.signing, now=NOW)
        with self.assertRaisesRegex(PolicyError, 'verified version'):
            h.sync.read_value('unknown', bytes(32), now=NOW)
        h.store.connection.execute('DELETE FROM cloud_unpublished')
        payload = h.payload()
        h.append(payload['entries'][0]['entry'])
        h.append(payload['entries'][1]['entry'], blob=payload['version'])
        h.verifier.finish_history([payload['version']], evidence=h.proof, broker_id=BROKER)
        h.sync.accept_pull(h.verifier, [payload['version']], observed_at=NOW)
        h.store.connection.execute('UPDATE cloud_sync_blobs SET head_seq=0')
        with self.assertRaisesRegex(PolicyError, 'requires pull'):
            h.sync.read_value('version', bytes(32), now=NOW)

    def test_enrollment_projection_guards_independently_bind_recipient_and_project(self):
        # Isolate only the new projection checks. Parent signature/archive
        # verification is separately exercised by the complete cloud replay.
        for filename, table, field, value, message in [
            ('broker-ops-reports-v1.json', 'org_key_wraps', 'recipient_id', 'other', 'OMK identity'),
            ('broker-ops-scoped-v1.json', 'broker_key_wraps', 'project', 'b', 'scoped key')]:
            doc = next(d for item,d in documents() if item['file'] == filename)
            replay = ops_tests.OpsReplay(doc)
            for step in doc['steps'][:4]:
                replay.step(step)
            verifier = replay.harness.replay
            step = doc['steps'][4]
            tables = decode(step['post_state']['tables'])
            entry = ops_tests.request_body(step)['entry']
            ids = {r['id'] for r in entry['body']['requested']['wrap_digests']}
            next(r for r in tables[table] if r.get('wrap_id') in ids)[field] = value
            evidence = RecoveryEvidence(tables, tables)
            verifier._active_evidence = evidence
            verifier._candidate_epochs = copy.deepcopy(verifier._epochs)
            with (patch.object(RecoveryVerifier, '_authorize', return_value=verifier.state),
                  self.assertRaisesRegex(PolicyError, message)):
                verifier._authorize(entry, verifier.state)

    def test_sync_persistence_refuses_partial_kind_composition_or_missing_clock(self):
        h = sync_tests.SyncTests()
        h.setUp()
        self.addCleanup(h.doCleanups)
        base = OfflineCloudVerifier(ORG, h.root, projects=['a', 'b'])
        for record, stage, blob, evidence in h.frames:
            base.verify_record(record, stage=stage, blob=blob, evidence=evidence)
        base.finish_history([])
        with self.assertRaisesRegex(StoreError, 'complete recovery/request'):
            h.store.save_cloud_replay(base, sync_blobs=[], observed_at=NOW)
        with self.assertRaisesRegex(StoreError, 'local observation'):
            h.store.save_cloud_replay(h.verifier, sync_blobs=[])

    def test_scoped_initial_acceptance_checks_omk_and_project_before_unsealing(self):
        doc, replay, session, store, blk, sync = self.scoped()
        verifier = replay.harness.replay
        snapshot = verifier.export_checkpoint()
        poll = result(doc['steps'][5])
        fields = ('broker_id','key_id','purpose','project','eph_pub','nonce','wrapped_key','wrap_digest')
        blobs = [dict(id=w['wrap_id'], **{k:w[k] for k in fields}) for w in poll['scoped_seals']]
        changed = copy.deepcopy(blobs)
        changed[0]['project'] = 'b'
        with self.assertRaisesRegex(ValueError, 'key identity or project'):
            session.accept_custody(store, blk, verifier, changed, allow_scoped=True)
        full = next(d for item,d in documents() if item['file'] == 'broker-ops-reports-v1.json')
        body = ops_tests.request_body(full['steps'][4])
        full_blobs = body['wraps']
        cert = snapshot['authority']['brokers'][-1]['certificate']
        cert['wrap_digests'] = copy.deepcopy(body['entry']['body']['requested']['wrap_digests'])
        with (patch.object(verifier, 'export_checkpoint', return_value=snapshot),
              self.assertRaisesRegex(ValueError, 'cannot accept OMK')):
            session.accept_custody(store, blk, verifier, full_blobs, allow_scoped=True)


if __name__ == '__main__':
    unittest.main()
