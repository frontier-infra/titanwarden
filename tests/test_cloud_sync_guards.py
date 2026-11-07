"""Additional isolated broker guard regressions; all keys are TEST-ONLY."""
import copy
import json
import sqlite3
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec

from tw import crypto
from tw.cloud_keeper import Keeper
from tw.cloud_sync import CloudSync
from tw.policy_log import PolicyError
from tw.store import StoreError
import test_cloud_sync as sync_tests
from test_cloud_sync import ORG, BROKER, NOW, LATER, EXPIRES


class SyncGuardTests(unittest.TestCase):
    def setUp(self):
        self.h = sync_tests.SyncTests()
        self.h.setUp()
        self.addCleanup(self.h.doCleanups)

    def publish_test_version(self):
        h = self.h
        payload = h.payload()
        h.append(payload['entries'][0]['entry'])
        h.append(payload['entries'][1]['entry'], blob=payload['version'])
        h.verifier.finish_history([payload['version']], evidence=h.proof, broker_id=BROKER)
        h.sync.accept_pull(h.verifier, [payload['version']], observed_at=NOW)
        version = h.verifier.epoch_state['versions'][0]
        row = dict(payload['version'], **{k:version[k] for k in ('version_no', 'state', 'fingerprint', 'length', 'source', 'envelope_digest')}, ciphertext_digest=version['value_digest'])
        return payload, dict(secrets=[payload['secret']], versions=[row], cursor=None)

    def test_sync_page_ciphertext_metadata_scope_suffix_and_limits(self):
        h = self.h
        payload, page = self.publish_test_version()
        self.assertEqual(h.sync.sync_pages([page], now=NOW), [payload['version']])
        for fault in ('secret', 'duplicate-secret', 'version', 'duplicate-version', 'signed-meta', 'ciphertext', 'missing-secret', 'missing-version', 'limit'):
            bad = copy.deepcopy(page)
            if fault == 'secret': bad['secrets'][0]['path'] = 'a/substituted'
            if fault == 'duplicate-secret': bad['secrets'] *= 2
            if fault == 'version': bad['versions'][0]['version_id'] = 'foreign'
            if fault == 'duplicate-version': bad['versions'] *= 2
            if fault == 'signed-meta': bad['versions'][0]['source'] = 'unsigned'
            if fault == 'ciphertext': bad['versions'][0]['ciphertext'] = '11' * 40
            if fault == 'missing-secret': bad['secrets'] = []
            if fault == 'missing-version': bad['versions'] = []
            if fault == 'limit': bad['secrets'] *= 101
            with self.subTest(fault=fault), self.assertRaises((PolicyError, ValueError)):
                h.sync.sync_pages([bad], now=NOW)
        self.assertEqual(json.loads(h.store.connection.execute('SELECT blob_json FROM cloud_sync_blobs').fetchone()[0]), payload['version'])

    def test_pull_sql_crash_rolls_back_policy_blobs_and_freshness_together(self):
        h = self.h
        payload = h.payload()
        h.append(payload['entries'][0]['entry'])
        h.append(payload['entries'][1]['entry'], blob=payload['version'])
        h.verifier.finish_history([payload['version']], evidence=h.proof, broker_id=BROKER)
        before = h.sync.checkpoint()
        observed = h.store.connection.execute('SELECT count(*) FROM cloud_head_observations').fetchone()[0]
        h.store.connection.execute("CREATE TRIGGER test_only_crash BEFORE INSERT ON cloud_sync_blobs BEGIN SELECT RAISE(ABORT,'interrupted pull'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            h.sync.accept_pull(h.verifier, [payload['version']], observed_at=LATER)
        self.assertEqual(h.sync.checkpoint(), before)
        self.assertEqual(h.store.connection.execute('SELECT count(*) FROM cloud_head_observations').fetchone()[0], observed)

    def test_unknown_conflict_reason_and_no_verified_policy_refuse(self):
        h = self.h
        with self.assertRaisesRegex(PolicyError, 'unknown conflict reason'):
            h.sync.refuse('unknown', NOW)
        with patch.object(h.store, 'load_cloud_replay', return_value=None), self.assertRaisesRegex(PolicyError, 'verified policy required'):
            h.sync.checkpoint()

    def test_report_and_completion_need_committed_epoch(self):
        h = self.h
        state = h.sync.checkpoint()
        state['epochs']['epochs'] = []
        with patch.object(h.sync, 'checkpoint', return_value=state):
            for op in (lambda: h.sync.report(h.client(), 'https://test.invalid'), h.sync.completion):
                with self.assertRaisesRegex(PolicyError, 'committed epoch required'):
                    op()

    def test_write_shape_pending_immutability_and_offline_head_fence(self):
        h = self.h
        payload = h.payload()
        with self.assertRaisesRegex(PolicyError, 'entry count'):
            h.sync.stage_version(dict(payload, entries=[]), now=NOW)
        h.sync.stage_version(payload, now=NOW)
        changed = copy.deepcopy(payload)
        changed['entries'][-1]['entry']['body']['source'] = 'changed'
        changed['entries'][-1] = h.signed(changed['entries'][-1]['entry'])
        with self.assertRaisesRegex(PolicyError, 'unpublished version changed'):
            h.sync.stage_version(changed, now=NOW)
        with self.assertRaisesRegex(PolicyError, 'unpublished version missing'):
            h.sync.upload_version('missing', h.client(), 'https://test.invalid', now=NOW)
        state = h.sync.checkpoint()
        state['head'] = dict(seq=5, hash='1' * 64)
        with patch.object(h.sync, 'checkpoint', return_value=state), self.assertRaisesRegex(PolicyError, 'fresh authorization'):
            h.sync.upload_version('version', h.client(), 'https://test.invalid', now=NOW)
        client = h.client()
        client.broker = 'other'
        with self.assertRaisesRegex(PolicyError, 'upload signer'):
            h.sync.upload_version('version', client, 'https://test.invalid', now=NOW)

    def test_keeper_eligibility_continuity_and_token_substitution(self):
        h = self.h
        keeper, _ = h.keeper()
        cert = h.sync.certificate()
        for field, value in [('scope', ['a']), ('keeper', False)]:
            with patch.object(h.sync, 'certificate', return_value=dict(cert, **{field:value})), self.assertRaisesRegex(PolicyError, 'full keeper'):
                keeper.snapshot()
        snapshot = keeper.snapshot()
        snapshot['brokers'][0]['keeper_since_seq'] = 20
        with patch.object(keeper, 'snapshot', return_value=snapshot), self.assertRaisesRegex(PolicyError, 'continuity'):
            keeper.lease(NOW)
        keeper._token = 'rkc_' + crypto.b64url(bytes([46]) * 32)
        with self.assertRaisesRegex(PolicyError, 'fresh keeper claim'):
            keeper.lease(NOW)
        h.sync.refuse('fork', NOW)
        with self.assertRaisesRegex(PolicyError, 'conflicted keeper'):
            keeper.snapshot()

    def test_keeper_credential_shape_and_policy_key_checks(self):
        h = self.h
        keeper, response = h.keeper()
        with self.assertRaisesRegex(PolicyError, 'credential shape'):
            keeper.accept_claim(dict(response, claim_token='invalid'), expected_head=h.verifier.head, now=NOW)
        with self.assertRaisesRegex(PolicyError, 'complete local keyring'):
            keeper.build_rotation({}, h.signing, now=NOW)
        with self.assertRaisesRegex(PolicyError, 'policy key differs'):
            keeper.build_rotation(h.keys, ec.derive_private_key(119, ec.SECP256R1()), now=NOW)

    def test_keeper_renewal_and_stage_publish_transport_identity(self):
        h = self.h
        keeper, _ = h.keeper()
        client = h.client(lambda req: dict(claimed_until='2026-10-16T00:12:00.000Z'))
        keeper.renew(client, 'https://test.invalid', now=LATER, completed_at=LATER)
        self.assertEqual(keeper._row()['claimed_until'], '2026-10-16T00:12:00.000Z')
        with self.assertRaisesRegex(PolicyError, 'duration'):
            keeper.renew(h.client(lambda req: dict(claimed_until=NOW)), 'https://test.invalid', now=LATER, completed_at=LATER)
        stage, signed = keeper.build_rotation(h.keys, h.signing, now=LATER)
        sent = []
        client = h.client(lambda req: sent.append(req) or dict(staged=True))
        keeper.stage(client, 'https://test.invalid', stage, now=LATER)
        keeper.publish(client, 'https://test.invalid', signed, now=LATER)
        self.assertEqual(len(sent), 2)
        self.assertEqual(crypto.parse_canonical(sent[0].body)['fence'], 1)
        bad = copy.deepcopy(signed)
        bad['entry']['body']['fence'] = 2
        with self.assertRaisesRegex(PolicyError, 'intent fence'):
            keeper.publish(client, 'https://test.invalid', bad, now=LATER)
        client.broker = 'other'
        with self.assertRaisesRegex(PolicyError, 'transport identity'):
            keeper.stage(client, 'https://test.invalid', stage, now=LATER)
        with self.assertRaisesRegex(PolicyError, 'publish identity'):
            keeper.publish(client, 'https://test.invalid', signed, now=LATER)

    def test_refusal_guards_have_independently_valid_fault_inputs(self):
        h = self.h
        # Re-sign every changed policy input so the signature guard cannot hide
        # a missing predecessor, entry-order, metadata or stale-epoch guard.
        for fault, message in [('predecessor', 'predecessor'), ('order', 'entry order'), ('secret', 'unsigned secret'), ('kek', 'stale KEK')]:
            payload = h.payload()
            if fault == 'predecessor':
                payload['entries'][0]['entry']['prev_hash'] = '0' * 64
                payload['entries'][1]['entry']['prev_hash'] = '0' * 64
            if fault == 'order':
                payload['entries'][0]['entry']['kind'] = 'version_add'
            if fault == 'secret':
                payload['secret'] = dict(payload['secret'], path='a/unsigned')
            if fault == 'kek':
                version = payload['version']
                wrapped, nonce = crypto.wrap_key(bytes([39]) * 32, bytes([11]) * 32, crypto.dek_aad(ORG, 'version', 'retired'))
                version.update(kek_id='retired', wrapped_dek=wrapped.hex(), dek_nonce=nonce.hex())
                payload['entries'][-1]['entry']['body'].update(kek_id='retired', envelope_digest=crypto.envelope_digest('retired', wrapped, nonce))
            payload['entries'] = [h.signed(s['entry']) for s in payload['entries']]
            # If the first hash changed, preserve continuity of the second.
            if fault != 'predecessor':
                payload['entries'][1]['entry']['prev_hash'] = crypto.sha256(crypto.canonical_json(payload['entries'][0]['entry'])).hex()
                payload['entries'][1] = h.signed(payload['entries'][1]['entry'])
            with self.subTest(fault=fault), self.assertRaisesRegex(PolicyError, message):
                h.sync.stage_version(payload, now=NOW)

    def test_sync_page_size_limit_is_independent_of_metadata(self):
        h = self.h
        # A cursor is otherwise valid canonical JSON. The page's framing alone
        # exceeds the response budget before cursor parsing can consume it.
        with self.assertRaisesRegex(PolicyError, 'page limit'):
            h.sync.sync_pages([dict(secrets=[], versions=[], cursor='x' * 3000001)], now=NOW)

    def test_sync_and_write_head_races_refuse_before_commit(self):
        h = self.h
        state = h.sync.checkpoint()
        changed = copy.deepcopy(state)
        changed['head'] = dict(seq=5, hash='1' * 64)
        for op in (lambda: h.sync.sync_pages([dict(secrets=[], versions=[], cursor=None)], now=NOW), lambda: h.sync.stage_version(h.payload(), now=NOW)):
            with patch.object(h.sync, 'checkpoint', side_effect=[state, state, changed]), self.assertRaisesRegex(PolicyError, 'head changed'):
                op()

    def test_claim_expiry_and_head_race_are_independent(self):
        h = self.h
        keeper, valid = h.keeper()
        for until in (NOW, '2026-10-16T00:10:00.001Z'):
            # A higher fresh fence prevents the monotonic fence check from
            # masking a missing lease duration check.
            with self.assertRaisesRegex(PolicyError, 'duration'):
                keeper.accept_claim(dict(valid, fence=2, claimed_until=until), expected_head=h.verifier.head, now=NOW)
        snapshot = keeper.snapshot()
        changed = copy.deepcopy(snapshot)
        changed['head']['seq'] += 1
        with patch.object(keeper, 'snapshot', side_effect=[snapshot, changed]), self.assertRaisesRegex(PolicyError, 'authority changed'):
            keeper.accept_claim(dict(valid, fence=2), expected_head=h.verifier.head, now=NOW)

    def test_keeper_large_intent_requires_paging(self):
        h = self.h
        keeper, _ = h.keeper()
        # A locally derived very large plan id makes a valid signed intent
        # exceed the policy envelope bound, without changing epoch semantics.
        keeper.plan = 'a' * 65536
        with (patch.object(keeper, 'lease', return_value=dict(fence=1, claim_token='TEST-ONLY')),
              self.assertRaisesRegex(PolicyError, 'Snapshot head mismatch')):
            keeper.build_rotation(h.keys, h.signing, now=NOW)

    def test_real_delivery_conflict_restart_and_metadata_no_key_leakage(self):
        h = self.h
        payload, page = self.publish_test_version()
        h.store.initialize_cloud_custody()
        blk = bytes([77]) * 32
        h.store.put_cloud_local_key(blk, org=ORG, broker=BROKER, key_id='omk_1', purpose='omk', scope='*', generation=1, key=h.omk)
        self.assertEqual(h.sync.read_value('version', blk, now=NOW), b'public test-only value')
        self.assertEqual(h.sync.agent_metadata(), [payload['secret']])
        self.assertNotIn('wrapped', json.dumps(h.sync.agent_metadata()))
        h.sync.refuse('envelope_mismatch', NOW)
        h.reopen()
        with self.assertRaisesRegex(PolicyError, 'unresolved local conflict'):
            h.sync.read_value('version', blk, now=NOW)

    def test_unpublished_rewrap_is_explicit_and_preserves_ciphertext(self):
        h = self.h
        payload = h.payload()
        h.sync.stage_version(payload, now=NOW)
        keeper, _ = h.keeper()
        stage, signed = keeper.build_rotation(h.keys, h.signing, now=NOW)
        h.verifier.verify_signed(signed, NOW, stage=stage, evidence=h.proof)
        h.verifier.finish_history([], evidence=h.proof, broker_id=BROKER)
        h.sync.accept_pull(h.verifier, [], observed_at=NOW)
        with self.assertRaisesRegex(PolicyError, 'fresh authorization'):
            h.sync.upload_version('version', h.client(), 'https://test.invalid', now=NOW)
        wrap = stage['wraps'][0]
        omk = crypto.unseal(h.exchange, h.kx, crypto.SealedBox(bytes.fromhex(wrap['eph_pub']), bytes.fromhex(wrap['nonce']), bytes.fromhex(wrap['wrapped_omk']), wrap['wrap_digest']), crypto.org_key_wrap_aad(ORG, 'broker', BROKER, 2))
        kid = h.verifier.epoch_state['active_kek']['a']
        row = next(k for k in stage['keyring'] if k['key_id'] == kid)
        kek = crypto.unwrap_key(omk, bytes.fromhex(row['wrapped_key']), bytes.fromhex(row['nonce']), crypto.cloud_keyring_aad(ORG, kid, 'kek', 'a', 2))
        rebuilt = h.sync.rebuild_unpublished('version', h.keys['ka'], kek, h.signing, now=NOW)
        self.assertEqual(rebuilt['version']['ciphertext'], payload['version']['ciphertext'])
        self.assertEqual(rebuilt['version']['nonce'], payload['version']['nonce'])
        self.assertNotEqual(rebuilt['entries'][-1]['entry']['body']['envelope_digest'], payload['entries'][-1]['entry']['body']['envelope_digest'])
        h.sync.stage_version(rebuilt, now=NOW)

    def test_committed_rekey_batches_rewrap_envelopes_and_resume_from_verified_head(self):
        h = self.h
        payload, _ = self.publish_test_version()
        keeper, _ = h.keeper()
        with self.assertRaisesRegex(PolicyError, 'independently committed'):
            keeper.build_rewrap(h.keys, h.signing, now=NOW)
        stage, signed = keeper.build_rotation(h.keys, h.signing, now=NOW)
        h.verifier.verify_signed(signed, NOW, stage=stage, evidence=h.proof)
        h.verifier.finish_history([payload['version']], evidence=h.proof, broker_id=BROKER)
        h.sync.accept_pull(h.verifier, [payload['version']], observed_at=NOW)
        wrap = stage['wraps'][0]
        omk = crypto.unseal(h.exchange, h.kx, crypto.SealedBox(bytes.fromhex(wrap['eph_pub']), bytes.fromhex(wrap['nonce']), bytes.fromhex(wrap['wrapped_omk']), wrap['wrap_digest']), crypto.org_key_wrap_aad(ORG, 'broker', BROKER, 2))
        keys = {row['key_id']:crypto.unwrap_key(omk, bytes.fromhex(row['wrapped_key']), bytes.fromhex(row['nonce']), crypto.cloud_keyring_aad(ORG, row['key_id'], row['purpose'], row['project'] or '*', 2)) for row in stage['keyring']}
        with self.assertRaisesRegex(PolicyError, 'KEK missing'):
            keeper.build_rewrap({}, h.signing, now=NOW)
        with self.assertRaisesRegex(PolicyError, 'policy key differs'):
            keeper.build_rewrap(keys, ec.derive_private_key(123, ec.SECP256R1()), now=NOW)
        batch = keeper.build_rewrap(keys, h.signing, now=NOW)
        sent = []
        client = h.client(lambda request: sent.append(request) or dict(remaining=0))
        keeper.rewrap(client, 'https://test.invalid', batch, now=NOW)
        self.assertTrue(sent[0].url.endswith('/keys/rewrap'))
        with self.assertRaisesRegex(PolicyError, 'batch fence'):
            keeper.rewrap(client, 'https://test.invalid', dict(batch, fence=2), now=NOW)
        client.broker = 'other'
        with self.assertRaisesRegex(PolicyError, 'transport identity'):
            keeper.rewrap(client, 'https://test.invalid', batch, now=NOW)
        h.verifier.verify_signed({k:batch[k] for k in ('entry','sig')}, NOW, evidence=h.proof)
        blob = dict(payload['version'], **{k:batch['items'][0][k] for k in ('kek_id','wrapped_dek','dek_nonce')})
        h.verifier.finish_history([blob], evidence=h.proof, broker_id=BROKER)
        h.sync.accept_pull(h.verifier, [blob], observed_at=NOW)
        self.assertIsNone(keeper.build_rewrap(keys, h.signing, now=NOW))


if __name__ == '__main__':
    unittest.main()
