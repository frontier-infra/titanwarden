"""PR 17 review reproductions using disposable stores and public test-only keys."""
import copy
import json
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from tw import crypto
from tw.cloud_sync import CloudSync
from tw.policy_log import PolicyError, policy_record
from tw.store import StoreError, Store
import test_cloud_sync as unit
import test_cloud_audit_sync as audit_tests
from tw.cloud_audit import AuditSync, AuditConflict
from tw.cloud_http import decode_response


class ReviewRegressionTests(unittest.TestCase):
    def setUp(self):
        self.h = unit.SyncTests()
        self.h.setUp()
        self.addCleanup(self.h.doCleanups)

    def publish(self):
        h = self.h
        payload = h.payload()
        h.sync.stage_version(payload, now=unit.NOW)
        for signed in payload['entries']:
            h.append(signed['entry'], blob=payload['version'] if signed['entry']['kind'] == 'version_add' else None)
        h.verifier.finish_history([payload['version']], evidence=h.proof, broker_id=unit.BROKER)
        h.sync.accept_pull(h.verifier, [payload['version']], observed_at=unit.NOW)
        return payload

    def test_verified_publication_reconciles_atomically_and_never_sends_duplicate(self):
        h = self.h
        payload = self.publish()
        self.assertEqual(h.store.connection.execute('SELECT count(*) FROM cloud_unpublished').fetchone()[0], 0)
        sent = []
        client = h.client(lambda request: sent.append(request))
        for operation in (
            lambda: h.sync.rebuild_unpublished('version', h.keys['ka'], h.keys['ka'], h.signing, now=unit.NOW),
            lambda: h.sync.upload_version('version', client, 'https://test.invalid', now=unit.NOW),
            lambda: h.sync.stage_version(payload, now=unit.NOW)):
            with self.assertRaises(PolicyError):
                operation()
        self.assertFalse(sent)

    def test_unpublished_work_survives_an_honest_unchanged_pull(self):
        h = self.h
        h.sync.stage_version(h.payload(),now=unit.NOW)
        h.sync.accept_pull(h.verifier,[],observed_at=unit.LATER)
        self.assertEqual(h.store.connection.execute('SELECT count(*) FROM cloud_unpublished').fetchone()[0],1)
        self.assertFalse(h.sync.conflicts())

    def test_published_ids_refuse_even_with_fresh_signatures_and_a_legacy_pending_row(self):
        h = self.h
        payload = self.publish()
        entry = h.entry('version_add',copy.deepcopy(payload['entries'][-1]['entry']['body']))
        fresh = dict(version=payload['version'],entries=[h.signed(entry)])
        with self.assertRaisesRegex(PolicyError,'already published'):
            h.sync.stage_version(fresh,now=unit.NOW)
        h.store.connection.execute('INSERT INTO cloud_unpublished VALUES (?,?,?,?,?)',(unit.ORG,'version',crypto.canonical_json(h.verifier.head).decode(),'ka',crypto.canonical_json(fresh).decode()))
        with self.assertRaisesRegex(PolicyError,'already published'):
            h.sync.rebuild_unpublished('version',h.keys['ka'],h.keys['ka'],h.signing,now=unit.NOW)
        sent = []
        with self.assertRaisesRegex(PolicyError,'already published'):
            h.sync.upload_version('version',h.client(lambda r:sent.append(r)),'https://test.invalid',now=unit.NOW)
        self.assertFalse(sent)

    def test_honest_save_race_retries_without_durable_conflict(self):
        h = self.h
        original = h.store.save_cloud_replay
        calls = []
        def raced(*args, **kwargs):
            calls.append(1)
            if len(calls) == 1:
                raise StoreError('cloud replay head changed')
            return original(*args, **kwargs)
        with patch.object(h.store, 'save_cloud_replay', side_effect=raced):
            h.sync.pull(iter(h.frames), [], projects=['a', 'b'], evidence=h.proof, observed_at=unit.NOW)
        self.assertEqual(len(calls), 2)
        self.assertFalse(h.sync.conflicts())

    def test_transport_retry_and_shorter_honest_prefix_are_not_forks(self):
        h = self.h
        calls = []
        def fetch():
            calls.append(1)
            if len(calls) == 1:
                raise TimeoutError('TEST-ONLY transport interruption')
            return h.frames
        h.sync.pull(fetch, [], projects=['a', 'b'], evidence=h.proof, observed_at=unit.NOW)
        self.assertEqual(len(calls), 2)
        prefix = list(h.frames)
        self.publish()
        with self.assertRaises(PolicyError) as caught:
            h.sync.pull(prefix, [], projects=['a', 'b'], evidence=h.proof, observed_at=unit.NOW)
        self.assertEqual(caught.exception.code, 'E_SYNC_RETRY')
        self.assertFalse(h.sync.conflicts())

    def test_remote_policy_error_is_not_independent_conflict_evidence(self):
        h = self.h
        def fetch():
            return decode_response(409,crypto.canonical_json(dict(ok=False,code='E_POLICY_CONFLICT',error='remote assertion',next='retry')))
        with self.assertRaises(PolicyError):
            h.sync.pull(fetch,[],projects=['a','b'],evidence=h.proof,observed_at=unit.NOW)
        self.assertFalse(h.sync.conflicts())

    def test_malformed_frame_is_protocol_violation_and_bad_signature_is_distinct(self):
        h = self.h
        entry = h.entry('secret_create', dict(secret_id='malformed', path='a/malformed', project='a', **{'class':'standard'}, authz='not-an-object'))
        record = policy_record(entry, crypto.unb64url(h.signed(entry)['sig']), unit.NOW)
        with self.assertRaises(PolicyError):
            h.sync.pull(h.frames + [(record, None, None, h.proof)], [], projects=['a','b'], evidence=h.proof, observed_at=unit.NOW)
        self.assertEqual(h.sync.conflicts()[-1]['reason'], 'protocol_violation')

    def test_store_readable_values_cannot_resolve(self):
        h = self.h
        h.sync.refuse('fork', unit.NOW)
        with self.assertRaisesRegex(PolicyError, 'authenticated admin.*verified history'):
            h.sync.resolve(expected_head=h.sync.checkpoint()['head'], through_conflict=h.sync.conflicts()[-1]['conflict_id'], typed_root=h.store.cloud_pin(unit.ORG), now=unit.NOW)
        self.assertTrue(h.sync.conflicts())

    def test_older_head_observation_does_not_refresh_current_head_P03(self):
        h = self.h
        h.append(h.entry('secret_create', dict(secret_id='new', path='a/new', project='a', **{'class':'standard'})))
        h.verifier.finish_history([], evidence=h.proof, broker_id=unit.BROKER)
        h.store.save_cloud_replay(h.verifier, sync_blobs=[], observed_at=unit.NOW)
        old = dict(seq=2, hash=h.frames[1][0].hash)
        h.store.observe_cloud_head(unit.ORG, old, '2026-10-16T02:00:00.000Z')
        with self.assertRaisesRegex(PolicyError, 'stale'):
            h.sync.require_delivery('a', 'restricted', '2026-10-16T02:00:01.000Z')

    def test_valid_ciphertext_substitution_fails_commitment_before_decryption_P05(self):
        h = self.h
        payload = self.publish()
        h.store.initialize_cloud_custody()
        blk = bytes([77]) * 32
        h.store.put_cloud_local_key(blk, org=unit.ORG, broker=unit.BROKER, key_id='omk_1', purpose='omk', scope='*', generation=1, key=h.omk)
        blob = copy.deepcopy(payload['version'])
        ciphertext, nonce = crypto.aes_encrypt(bytes([11])*32, b'authenticated but uncommitted TEST-ONLY replacement', crypto.value_aad(unit.ORG, 'secret', 1))
        blob.update(ciphertext=ciphertext.hex(), nonce=nonce.hex())
        h.store.connection.execute('UPDATE cloud_sync_blobs SET blob_json=?', (crypto.canonical_json(blob).decode(),))
        with self.assertRaisesRegex(PolicyError, 'commitment'):
            h.sync.read_value('version', blk, now=unit.NOW)

    def test_sync_state_is_append_only_and_conflicted_sync_refuses(self):
        h = self.h
        for sql in ('UPDATE cloud_sync_state SET request_json=request_json', 'DELETE FROM cloud_sync_state'):
            with self.assertRaises(sqlite3.IntegrityError):
                h.store.connection.execute(sql)
        h.sync.refuse('fork', unit.NOW)
        with self.assertRaisesRegex(PolicyError, 'conflict'):
            h.sync.sync_pages([dict(secrets=[], versions=[], cursor=None)], now=unit.NOW)

    def test_audit_diagnostics_are_retained_without_policy_authority_P14(self):
        h = self.h
        a = audit_tests.AuditSyncTests()
        a.setUp()
        self.addCleanup(a.doCleanups)
        sync = AuditSync(h.store, unit.ORG, audit_tests.CHAIN, a.pins, broker_public=a.ak_public)
        bad = dict(a.receipt, receipt_sig=crypto.b64url(bytes(64)))
        with self.assertRaises(AuditConflict):
            sync.accept(a.rows, a.expected, bad, observed_at=unit.NOW)
        self.assertEqual(h.store.connection.execute('SELECT count(*) FROM cloud_audit_conflicts').fetchone()[0], 1)
        self.assertFalse(h.sync.conflicts())
        h.sync.require_delivery('a', 'standard', unit.NOW)
        with self.assertRaises(AuditConflict):
            sync.accept(a.rows, dict(a.expected, ts='malformed'), a.receipt, observed_at=unit.NOW)
        self.assertEqual(h.store.connection.execute('SELECT count(*) FROM cloud_audit_conflicts').fetchone()[0], 2)
        for sql in ('DELETE FROM cloud_audit_conflicts', 'UPDATE cloud_audit_conflicts SET reason=reason'):
            with self.assertRaises(sqlite3.IntegrityError):
                h.store.connection.execute(sql)

    def test_unknown_receipt_key_with_valid_known_key_signature_refuses_P24(self):
        a = audit_tests.AuditSyncTests()
        a.setUp()
        self.addCleanup(a.doCleanups)
        signed = a.sign_receipt(a.expected, key_id='attacker-selected')
        with self.assertRaisesRegex(AuditConflict, 'unknown receipt'):
            a.pins.verify(audit_tests.ORG, audit_tests.CHAIN, a.expected, signed)

    def test_revoked_but_otherwise_authentic_omk_pickup_refuses_P17(self):
        h = self.h
        epoch = h.sync.checkpoint()['epochs']
        response = dict(omk_generation=1, my_wrap=dict(epoch['org_wraps'][0], revoked_at=unit.NOW), keyring=epoch['keyring'])
        with self.assertRaisesRegex(PolicyError, 'OMK commitment'):
            h.sync.pickup_keys(response, bytes([77])*32, h.exchange)

    def test_published_commitment_disagreement_and_crash_do_not_acknowledge(self):
        h = self.h
        original = h.payload()
        h.sync.stage_version(original, now=unit.NOW)
        alternate = copy.deepcopy(original)
        cipher, nonce = crypto.aes_encrypt(bytes([11])*32, b'other public TEST-ONLY value', crypto.value_aad(unit.ORG, 'secret', 1))
        alternate['version'].update(ciphertext=cipher.hex(), nonce=nonce.hex())
        alternate['entries'][-1]['entry']['body'].update(value_digest=crypto.value_digest(cipher,nonce), length=len(cipher))
        for signed in alternate['entries']:
            h.append(signed['entry'], blob=alternate['version'] if signed['entry']['kind']=='version_add' else None)
        h.verifier.finish_history([alternate['version']], evidence=h.proof, broker_id=unit.BROKER)
        before = h.sync.checkpoint()
        with self.assertRaisesRegex(PolicyError, 'unpublished commitments'):
            h.sync.accept_pull(h.verifier, [alternate['version']], observed_at=unit.NOW)
        self.assertEqual(h.sync.checkpoint(), before)
        self.assertEqual(h.sync.conflicts()[-1]['reason'], 'envelope_mismatch')
        self.assertEqual(h.store.connection.execute('SELECT count(*) FROM cloud_unpublished').fetchone()[0], 1)

    def test_expired_keeper_claim_omits_old_credential(self):
        h = self.h
        keeper, response = h.keeper()
        sent = []
        fresh = dict(response, fence=2, claimed_until='2026-10-16T00:20:00.000Z')
        client = h.client(lambda request: sent.append(request) or fresh)
        client._clock = lambda:unit.EXPIRES
        keeper.claim(client, 'https://test.invalid', now=unit.EXPIRES)
        self.assertEqual(crypto.parse_canonical(sent[0].body), {})
        self.assertEqual(keeper.lease(unit.EXPIRES)['fence'], 2)

    def test_secret_create_cannot_target_another_secret(self):
        h = self.h
        payload = h.payload()
        payload['version']['secret_id'] = 'other'
        payload['entries'][-1]['entry']['body']['secret_id'] = 'other'
        payload['entries'][-1] = h.signed(payload['entries'][-1]['entry'])
        with self.assertRaisesRegex(PolicyError, 'match a new version target'):
            h.sync.stage_version(payload, now=unit.NOW)

    def test_http_response_status_and_envelope_consistency(self):
        refusal = crypto.canonical_json(dict(ok=False,code='E_ROLE',error='refused',next='retry'))
        for status, body in ((600,refusal),(200,refusal),(409,crypto.canonical_json(dict(ok=True,code='ok',result={})))):
            with self.subTest(status=status),self.assertRaises(ValueError):
                decode_response(status,body)
        self.assertEqual(decode_response(200,crypto.canonical_json(dict(ok=True,code='ok',result=dict(accepted=True)))),dict(accepted=True))

    def test_epoch_candidate_rejects_invalid_version_state(self):
        h = self.h
        payload = h.payload()
        payload['entries'][-1]['entry']['body']['state'] = 'destroyed'
        payload['entries'][-1] = h.signed(payload['entries'][-1]['entry'])
        with self.assertRaisesRegex(PolicyError,'Invalid new version'):
            h.sync.stage_version(payload,now=unit.NOW)

    def test_failed_publication_ack_rolls_back_checkpoint_and_pending_delete(self):
        h = self.h
        payload = h.payload()
        h.sync.stage_version(payload,now=unit.NOW)
        for signed in payload['entries']:
            h.append(signed['entry'],blob=payload['version'] if signed['entry']['kind']=='version_add' else None)
        h.verifier.finish_history([payload['version']],evidence=h.proof,broker_id=unit.BROKER)
        before = h.sync.checkpoint()
        h.store.connection.execute("CREATE TRIGGER test_only_ack_crash AFTER DELETE ON cloud_unpublished BEGIN SELECT RAISE(ABORT,'TEST-ONLY interrupted acknowledgement'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            h.sync.accept_pull(h.verifier,[payload['version']],observed_at=unit.NOW)
        self.assertEqual(h.sync.checkpoint(),before)
        self.assertEqual(h.store.connection.execute('SELECT count(*) FROM cloud_unpublished').fetchone()[0],1)

    def test_audit_requires_independent_pin_before_installing_any_tables(self):
        a = audit_tests.AuditSyncTests()
        a.setUp()
        self.addCleanup(a.doCleanups)
        with tempfile.TemporaryDirectory() as temporary:
            with Store(temporary).open(create=True) as store:
                with self.assertRaisesRegex(AuditConflict, 'independent cloud pin'):
                    AuditSync(store, unit.ORG, audit_tests.CHAIN, a.pins)
                self.assertEqual(store.connection.execute("SELECT count(*) FROM sqlite_master WHERE name LIKE 'cloud_%'").fetchone()[0], 0)

    def test_bad_signature_fork_and_late_admission_are_classified(self):
        h = self.h
        bad = h.frames[-1][0]
        frames = h.frames[:-1] + [(type(bad)(bad.data,bad.hash,bytes(64),bad.received_at), h.frames[-1][1],None,h.proof)]
        with self.assertRaises(PolicyError):
            h.sync.pull(frames, [], projects=['a','b'], evidence=h.proof, observed_at=unit.NOW)
        self.assertEqual(h.sync.conflicts()[-1]['reason'], 'bad_signature')
        self.setUp()
        h = self.h
        original = self.publish()
        # Both branches carry genuine test-only signatures and pass full replay.
        branch = copy.deepcopy(original)
        branch['entries'][0]['entry']['body']['path'] = 'a/another-branch'
        branch['entries'][0] = h.signed(branch['entries'][0]['entry'])
        branch['entries'][1]['entry']['prev_hash'] = crypto.sha256(crypto.canonical_json(branch['entries'][0]['entry'])).hex()
        branch['entries'][1] = h.signed(branch['entries'][1]['entry'])
        frames = h.frames[:2] + [(policy_record(s['entry'],crypto.unb64url(s['sig']),unit.NOW),None,branch['version'] if s['entry']['kind']=='version_add' else None,h.proof) for s in branch['entries']]
        with self.assertRaisesRegex(PolicyError, 'divergent signed history'):
            h.sync.pull(frames, [branch['version']], projects=['a','b'], evidence=h.proof, observed_at=unit.NOW)
        self.assertEqual(h.sync.conflicts()[-1]['reason'], 'fork')


class SyncHoldReviewTests(unittest.TestCase):
    """Real signed cloud holds through pull and persistence, without a value path.

    The hold corpus has no broker certificate. This observation-only test adapter
    finalizes full history without asking for broker custody; all signatures,
    authority transitions, recovery slots and local hold checks remain real.
    """
    def fixture(self):
        from cloud_fixtures import production_traces
        from paired_cloud_fixtures import PairedReplay
        from tw.cloud_recovery import RecoveryEvidence
        from tw.cloud_sync_verifier import SyncVerifier
        _, trace = next((n,d) for n,d in production_traces() if 'authority-holds' in n)
        builder = PairedReplay(trace)
        frames = []
        for r in trace['records']:
            builder.install(r['evidence'])
            record = policy_record(r['entry'], None if r['sig'] is None else crypto.unb64url(r['sig']),r['received_at'])
            frames.append((record,builder.stage(r['entry']),None,RecoveryEvidence(builder.rows,builder.blobs)))
        evidence = RecoveryEvidence(builder.rows,builder.blobs)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        store = Store(temporary.name).open(create=True)
        self.addCleanup(store.close)
        store.initialize_cloud_replay(trace['org_id'],trace['pinned_root'])
        sync = CloudSync(store,trace['org_id'],'TEST-ONLY-observation-adapter')
        class HoldVerifier(SyncVerifier):
            def finish_history(self, blobs, *, evidence=None, broker_id=None):
                return super().finish_history(blobs,evidence=evidence)
        def accept(verifier, blobs, *, observed_at):
            store.save_cloud_replay(verifier,sync_blobs=blobs,observed_at=observed_at)
            return verifier.head
        self.enterContext(patch('tw.cloud_sync_verifier.SyncVerifier',HoldVerifier))
        self.enterContext(patch.object(sync,'accept_pull',side_effect=accept))
        return trace,frames,evidence,store,sync

    def test_live_hold_early_activation_is_durable_hold_too_short_P18(self):
        trace,frames,evidence,store,sync = self.fixture()
        sync.pull(frames[:6],[],projects=['a','b'],evidence=evidence,observed_at='2027-01-16T08:10:00.000Z')
        proposal = crypto.sha256(frames[5][0].data).hex()
        self.assertEqual(store.cloud_observations(trace['org_id'])['proposals'][proposal]['mode'],'live')
        with self.assertRaisesRegex(PolicyError,'hold too short'):
            sync.pull(frames,[],projects=['a','b'],evidence=evidence,observed_at='2027-01-17T07:59:59.999Z')
        self.assertEqual(sync.conflicts()[-1]['reason'],'hold_too_short')

    def test_old_proposal_is_history_and_catchup_hold_is_persisted_P21(self):
        trace,frames,evidence,store,sync = self.fixture()
        sync.pull(frames[:6],[],projects=['a','b'],evidence=evidence,observed_at='2027-01-16T08:10:00.001Z')
        proposal = crypto.sha256(frames[5][0].data).hex()
        self.assertEqual(store.cloud_observations(trace['org_id'])['proposals'][proposal]['mode'],'history')
        sync.pull(frames,[],projects=['a','b'],evidence=evidence,observed_at='2027-01-19T08:00:00.000Z')
        row = store.connection.execute('SELECT status FROM cloud_sync_holds WHERE proposal_hash=?',(proposal,)).fetchone()
        self.assertEqual(row[0],'hold_not_locally_observed')

    def test_successful_live_hold_records_local_observation_on_sync_path(self):
        trace,frames,evidence,store,sync = self.fixture()
        sync.pull(frames[:6],[],projects=['a','b'],evidence=evidence,observed_at='2027-01-16T08:10:00.000Z')
        proposal = crypto.sha256(frames[5][0].data).hex()
        sync.pull(frames,[],projects=['a','b'],evidence=evidence,observed_at='2027-01-19T08:00:00.000Z')
        self.assertEqual(store.connection.execute('SELECT status FROM cloud_sync_holds WHERE proposal_hash=?',(proposal,)).fetchone()[0],'locally_observed')
