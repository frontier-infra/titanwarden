"""Broker refusal unit tests with public TEST-ONLY keys, not cloud fixtures.

These inputs exercise the broker's own guards. Cross-language claims belong to
the separately pinned generated-by-cloud production operational companion.
"""
import copy
import json
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec

from tw import crypto
from tw.cloud_epochs import derive_recipients, keyring_digest, recipient_hints
from tw.cloud_http import SignedClient, verify_request
from tw.cloud_keeper import Keeper
from tw.cloud_policy import AuthorityView
from tw.cloud_recovery import RecoveryVerifier, RecoveryEvidence
from tw.cloud_sync import CloudSync
from tw.cloud_wire import hash_object
from tw.policy_log import PolicyError, policy_record
from tw.store import Store, StoreError

ORG, BROKER = 'b' * 32, 'test-only-broker'
NOW = '2026-10-16T00:00:00.000Z'
LATER = '2026-10-16T00:02:00.000Z'
EXPIRES = '2026-10-16T00:10:00.000Z'


class SyncTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = Store(self.temporary.name).open(create=True)
        self.addCleanup(self.store.close)
        # Public, deliberately labelled test-only key material.
        self.signing = ec.derive_private_key(91, ec.SECP256R1())
        self.exchange = ec.derive_private_key(93, ec.SECP256R1())
        self.public = crypto.export_point(self.signing.public_key())
        self.kx = crypto.export_point(self.exchange.public_key())
        self.genesis = dict(v=2, org_id=ORG, seq=1, prev_hash='0' * 64, ts=NOW, kind='genesis',
            signer=dict(kind='broker', id=BROKER), body=dict(org_id=ORG,
                founder=dict(kind='broker', id=BROKER, sign_pub=crypto.b64url(self.public), kx_pub=crypto.b64url(self.kx)),
                recovery_kx_pub=None, recovery_sign_pub=None, default_rules={}, max_policy_age=3600))
        self.root = hash_object(self.genesis)
        self.store.initialize_cloud_replay(ORG, self.root)
        self.verifier = RecoveryVerifier(ORG, self.root, projects=['a', 'b'])
        self.proof = RecoveryEvidence()
        self.frames = []
        self.append(self.genesis)
        self.omk = bytes([31]) * 32
        self.keys = dict(ka=bytes([32]) * 32, kb=bytes([33]) * 32, fk=bytes([34]) * 32)
        rows = []
        for kid, purpose, project in [('ka', 'kek', 'a'), ('kb', 'kek', 'b'), ('fk', 'fingerprint', None)]:
            wrapped, nonce = crypto.wrap_key(self.omk, self.keys[kid], crypto.cloud_keyring_aad(ORG, kid, purpose, project or '*', 1))
            rows.append(dict(key_id=kid, purpose=purpose, project=project, version=1, wrapped_key=wrapped.hex(), nonce=nonce.hex(), mk_generation=1, aad_v=2))
        box = crypto.seal(self.kx, self.omk, crypto.org_key_wrap_aad(ORG, 'broker', BROKER, 1))
        wrap = dict(recipient_kind='broker', recipient_id=BROKER, omk_generation=1,
            eph_pub=box.eph_pub.hex(), nonce=box.nonce.hex(), wrapped_omk=box.wrapped.hex(), wrap_digest=box.wrap_digest)
        snapshot = self.verifier.authority_view().epoch_snapshot(self.verifier.head, ['a', 'b'])
        recipients = [dict(r, wrap_digest=box.wrap_digest) for r in derive_recipients(snapshot)]
        stage = dict(keyring=rows, wraps=[wrap], scoped_seals=[])
        body = dict(generation=1, recipients=recipients, scoped_seals=[],
            keyring=[dict(key_id=k['key_id'], purpose=k['purpose'], scope=k['project'] or '*', digest=keyring_digest(k)) for k in rows],
            active_kek=dict(a='ka', b='kb'))
        self.append(self.entry('epoch_init', body), stage=stage)
        self.verifier.finish_history([], evidence=self.proof, broker_id=BROKER)
        self.sync = CloudSync(self.store, ORG, BROKER)
        self.sync.accept_pull(self.verifier, [], observed_at=NOW)

    def entry(self, kind, body):
        return dict(v=2, org_id=ORG, seq=self.verifier.head['seq'] + 1, prev_hash=self.verifier.head['hash'],
            ts=NOW, kind=kind, body=body, signer=dict(kind='broker', id=BROKER))

    def signed(self, entry):
        return dict(entry=entry, sig=crypto.b64url(crypto.p256_sign(self.signing, crypto.policy_context(ORG, hash_object(entry)))))

    def append(self, entry, stage=None, blob=None):
        signed = self.signed(entry)
        record = policy_record(entry, crypto.unb64url(signed['sig']), NOW)
        self.verifier.verify_record(record, stage=stage, blob=blob, evidence=self.proof)
        self.frames.append((record, stage, blob, self.proof))
        return signed

    def reopen(self):
        self.store.close()
        self.store.open()
        self.sync = CloudSync(self.store, ORG, BROKER)

    def client(self, transport=None):
        return SignedClient(ORG, BROKER, self.signing, clock=lambda: NOW, transport=transport)

    def test_local_mode_has_no_cloud_tables_and_pin_is_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            with Store(temporary).open(create=True) as store:
                self.assertEqual(store.connection.execute("SELECT count(*) FROM sqlite_master WHERE name LIKE 'cloud_%'").fetchone()[0], 0)
                with self.assertRaisesRegex(PolicyError, 'pin required'):
                    CloudSync(store, ORG, BROKER)
        with self.assertRaisesRegex(PolicyError, 'pin required'):
            CloudSync(self.store, 'c' * 32, BROKER)

    def test_conflict_survives_restart_and_requires_exact_local_resolution(self):
        self.sync.refuse('fork', NOW)
        self.reopen()
        with self.assertRaisesRegex(PolicyError, 'unresolved local conflict'):
            self.sync.require_delivery('a', 'standard', NOW)
        conflict = self.sync.conflicts()[-1]['conflict_id']
        args = dict(expected_head=self.verifier.head, through_conflict=conflict, typed_root=self.root, now=NOW)
        for field, value in [('typed_root', '0' * 64), ('expected_head', dict(seq=2, hash='0' * 64)), ('through_conflict', conflict + 1)]:
            with self.subTest(field=field), self.assertRaises(PolicyError):
                self.sync.resolve(**dict(args, **{field: value}))
        with self.assertRaisesRegex(PolicyError, 'authenticated admin'):
            self.sync.resolve(**args)
        self.reopen()
        with self.assertRaisesRegex(PolicyError, 'unresolved local conflict'):
            self.sync.require_delivery('a', 'standard', NOW)
        self.sync.refuse('wrap_mismatch', NOW)
        with self.assertRaises(PolicyError):
            self.sync.require_delivery('a', 'standard', NOW)
        for table in ('cloud_conflicts',):
            with self.assertRaises(sqlite3.IntegrityError):
                self.store.connection.execute('DELETE FROM ' + table)

    def test_resolution_requires_local_root_and_current_conflict_set(self):
        self.sync.refuse('fork', NOW)
        conflict = self.sync.conflicts()[-1]['conflict_id']
        self.sync.refuse('fork', NOW)
        with self.assertRaisesRegex(PolicyError, 'authenticated admin'):
            self.sync.resolve(expected_head=self.verifier.head, through_conflict=conflict, typed_root=self.root, now=NOW)

    def test_restricted_age_boundary_future_clock_and_repeated_head_refresh(self):
        self.assertEqual(self.sync.require_delivery('a', 'restricted', NOW), self.verifier.head)
        for now in ('2026-10-15T23:59:59.999Z', '2026-10-16T01:00:00.000Z'):
            with self.subTest(now=now), self.assertRaisesRegex(PolicyError, 'stale'):
                self.sync.require_delivery('a', 'restricted', now)
        self.sync.accept_pull(self.verifier, [], observed_at=LATER)
        self.reopen()
        self.sync.require_delivery('a', 'restricted', '2026-10-16T01:01:59.999Z')
        self.sync.require_delivery('a', 'sensitive', '2026-10-17T00:00:00Z')
        # A new verified checkpoint can exist without operational pull evidence.
        self.append(self.entry('secret_create', dict(secret_id='missing-evidence', path='a/missing-evidence', project='a', **{'class':'standard'})))
        self.verifier.finish_history([], evidence=self.proof, broker_id=BROKER)
        self.store.save_cloud_replay(self.verifier)
        with self.assertRaisesRegex(PolicyError, 'stale'):
            self.sync.require_delivery('a', 'restricted', LATER)

    def test_scope_revocation_and_unknown_class_refuse(self):
        state = self.sync.checkpoint()
        cert = dict(self.sync.certificate(), scope=['a'])
        state['authority']['brokers'].append(dict(seq=2, certificate=cert))
        with patch.object(self.sync, 'checkpoint', return_value=state):
            self.sync.require_delivery('a', 'standard', NOW)
            with self.assertRaisesRegex(PolicyError, 'outside certified scope'):
                self.sync.require_delivery('b', 'standard', NOW)
            with self.assertRaisesRegex(PolicyError, 'unknown secret class'):
                self.sync.require_delivery('a', 'future-class', NOW)
            cert['state'] = 'revoked'
            with self.assertRaisesRegex(PolicyError, 'active certified broker'):
                self.sync.require_delivery('a', 'standard', NOW)

    def test_bad_pull_is_durable_and_preserves_snapshot(self):
        before = self.sync.checkpoint()
        record, stage, blob, proof = self.frames[-1]
        bad = type(record)(record.data, record.hash, bytes(64), record.received_at)
        with self.assertRaises(PolicyError):
            self.sync.pull(self.frames[:-1] + [(bad, stage, blob, proof)], [], projects=['a', 'b'], evidence=self.proof, observed_at=NOW)
        self.assertEqual(before, self.sync.checkpoint())
        self.reopen()
        with self.assertRaises(PolicyError):
            self.sync.require_delivery('a', 'standard', NOW)

    def test_complete_pull_uses_all_kind_owners_and_exact_pin_scope(self):
        self.assertEqual(self.sync.pull(self.frames, [], projects=['a', 'b'], evidence=self.proof, observed_at=LATER), self.verifier.head)
        with self.assertRaisesRegex(PolicyError, 'kind owners'):
            self.sync.accept_pull(object(), [], observed_at=NOW)
        snapshot = self.verifier.export_checkpoint()
        for field, value in [('org_id', 'c' * 32), ('pinned_root', '0' * 64), ('ciphertext_scope', ['a'])]:
            with patch.object(self.verifier, 'export_checkpoint', return_value=dict(snapshot, **{field: value})), self.assertRaises(PolicyError):
                self.sync.accept_pull(self.verifier, [], observed_at=NOW)

    def test_unverified_blob_cannot_commit_head_or_observation(self):
        before = self.store.connection.execute('SELECT count(*) FROM cloud_head_observations').fetchone()[0]
        with self.assertRaises(PolicyError):
            self.sync.accept_pull(self.verifier, [dict(version_id='injected')], observed_at=NOW)
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM cloud_head_observations').fetchone()[0], before)

    def test_report_requests_sign_exact_body_and_no_private_material(self):
        client = self.client()
        for reason in (None, 'fork'):
            request = self.sync.report(client, 'https://test.invalid', reason=reason)
            verify_request(request, ORG, BROKER, self.public, NOW)
            expected = self.sync.completion() if reason is None else dict(head=self.verifier.head, reason=reason)
            self.assertEqual(crypto.parse_canonical(request.body), expected)
            self.assertNotIn('claim_token', request.body.decode())
        with self.assertRaises(PolicyError):
            self.sync.report(client, 'https://test.invalid', reason='future-reason')
        client.broker = 'other'
        with self.assertRaisesRegex(PolicyError, 'identity differs'):
            self.sync.report(client, 'https://test.invalid')

    def payload(self):
        secret = dict(secret_id='secret', path='a/test', project='a', **{'class': 'standard'})
        create = self.entry('secret_create', secret)
        cipher, nonce = crypto.aes_encrypt(bytes([11]) * 32, b'public test-only value', crypto.value_aad(ORG, 'secret', 1))
        wrapped, dek_nonce = crypto.wrap_key(self.keys['ka'], bytes([11]) * 32, crypto.dek_aad(ORG, 'version', 'ka'))
        version = dict(version_id='version', secret_id='secret', kek_id='ka', ciphertext=cipher.hex(), nonce=nonce.hex(), wrapped_dek=wrapped.hex(), dek_nonce=dek_nonce.hex())
        body = dict(version_id='version', secret_id='secret', version_no=1, state='active', kek_id='ka', fingerprint='11' * 32, length=len(cipher), source='TEST-ONLY', value_digest=crypto.value_digest(cipher, nonce), envelope_digest=crypto.envelope_digest('ka', wrapped, dek_nonce))
        add = dict(self.entry('version_add', body), seq=create['seq'] + 1, prev_hash=hash_object(create))
        return dict(version=version, entries=[self.signed(create), self.signed(add)], secret=secret)

    def test_version_upload_one_attempt_and_ambiguous_result_retained(self):
        payload = self.payload()
        vid = self.sync.stage_version(payload, now=NOW)
        sent = []
        def transport(request):
            sent.append(request)
            raise TimeoutError('response lost after remote commit')
        with self.assertRaises(TimeoutError):
            self.sync.upload_version(vid, self.client(transport), 'https://test.invalid', now=NOW)
        self.assertEqual(len(sent), 1)
        self.assertEqual(crypto.parse_canonical(sent[0].body), payload)
        self.reopen()
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM cloud_unpublished').fetchone()[0], 1)

    def test_version_identity_signature_predecessor_and_stale_epoch_refuse(self):
        valid = self.payload()
        for fault in ('order', 'secret', 'kek', 'identity', 'predecessor', 'signature', 'ciphertext'):
            payload = copy.deepcopy(valid)
            if fault == 'order':
                payload['entries'].reverse()
            elif fault == 'secret':
                payload['secret']['path'] = 'a/unsigned'
            elif fault == 'kek':
                payload['version']['kek_id'] = 'retired'
            elif fault == 'identity':
                payload['version']['secret_id'] = 'unsigned'
            elif fault == 'predecessor':
                payload['entries'][0]['entry']['prev_hash'] = '0' * 64
            elif fault == 'signature':
                payload['entries'][0]['sig'] = crypto.b64url(bytes(64))
            else:
                payload['version']['ciphertext'] = '11' * 40
            with self.subTest(fault=fault), self.assertRaises((PolicyError, ValueError)):
                self.sync.stage_version(payload, now=NOW)

    def test_empty_and_single_page_sync_and_cursor_binding(self):
        self.assertEqual(self.sync.sync_pages([dict(secrets=[], versions=[], cursor=None)], now=NOW), [])
        with self.assertRaisesRegex(PolicyError, 'missing sync snapshot'):
            self.sync.sync_pages([], now=NOW)
        cursor = dict(org_id=ORG, broker_id=BROKER, seq=self.verifier.head['seq'], scope=['*'], offsets=dict(secrets=0, versions=0))
        pages = [dict(secrets=[], versions=[], cursor=crypto.b64url(crypto.canonical_json(cursor))), dict(secrets=[], versions=[], cursor=None)]
        self.sync.sync_pages(pages, now=NOW)
        for field, value in [('org_id', 'c' * 32), ('broker_id', 'other'), ('seq', 1), ('scope', ['a']), ('offsets', dict(secrets=1, versions=0)), ('offsets', dict(secrets=False, versions=0))]:
            first = dict(pages[0], cursor=crypto.b64url(crypto.canonical_json(dict(cursor, **{field:value}))))
            with self.subTest(field=field), self.assertRaisesRegex(PolicyError, 'cursor binding'):
                self.sync.sync_pages([first, pages[1]], now=NOW)
        with self.assertRaisesRegex(PolicyError, 'pagination incomplete'):
            self.sync.sync_pages(pages[:1], now=NOW)

    def keeper(self):
        keeper = Keeper(self.sync, 'test-plan')
        response = dict(fence=1, claim_token='rkc_' + crypto.b64url(bytes([44]) * 32), claimed_until=EXPIRES, hints=recipient_hints(keeper.snapshot()))
        keeper.accept_claim(response, expected_head=self.verifier.head, now=NOW)
        return keeper, response

    def test_keeper_lease_renewal_cadence_restart_and_no_token_at_rest(self):
        keeper, response = self.keeper()
        self.assertFalse(keeper.renewal_due(NOW))
        self.assertTrue(keeper.renewal_due(LATER))
        saved = dict(keeper._row())
        self.assertNotIn(response['claim_token'], json.dumps(saved))
        self.assertEqual(keeper.lease(NOW)['fence'], 1)
        self.reopen()
        with self.assertRaisesRegex(PolicyError, 'fresh keeper claim'):
            Keeper(self.sync, 'test-plan').lease(NOW)
        for now in (EXPIRES, '2026-10-15T23:59:59.999Z'):
            with self.assertRaises(PolicyError):
                keeper.lease(now)

    def test_keeper_claim_fence_hints_head_duration_and_identity(self):
        keeper, valid = self.keeper()
        for fault in ('fence', 'credential', 'hints', 'head', 'expiry', 'duration'):
            response = copy.deepcopy(valid)
            head = self.verifier.head
            if fault == 'fence': response['fence'] = 0
            if fault == 'credential': response['claim_token'] = 'rkc_' + crypto.b64url(bytes([45]) * 32)
            if fault == 'hints': response['hints']['recipients'][0]['kx_pub'] = self.public.hex()
            if fault == 'head': head = dict(seq=1, hash=self.root)
            if fault == 'expiry': response['claimed_until'] = NOW
            if fault == 'duration': response['claimed_until'] = '2026-10-16T00:10:00.001Z'
            with self.subTest(fault=fault), self.assertRaises((PolicyError, ValueError)):
                keeper.accept_claim(response, expected_head=head, now=NOW)
        with self.assertRaisesRegex(PolicyError, 'invalid plan'):
            Keeper(self.sync, '../other')

    def test_keeper_real_crypto_rotation_replays_and_keeps_old_keys(self):
        keeper, _ = self.keeper()
        stage, signed = keeper.build_rotation(self.keys, self.signing, now=NOW)
        box = stage['wraps'][0]
        omk = crypto.unseal(self.exchange, self.kx, crypto.SealedBox(bytes.fromhex(box['eph_pub']), bytes.fromhex(box['nonce']), bytes.fromhex(box['wrapped_omk']), box['wrap_digest']), crypto.org_key_wrap_aad(ORG, 'broker', BROKER, 2))
        for row in stage['keyring']:
            key = crypto.unwrap_key(omk, bytes.fromhex(row['wrapped_key']), bytes.fromhex(row['nonce']), crypto.cloud_keyring_aad(ORG, row['key_id'], row['purpose'], row['project'] or '*', 2))
            if row['key_id'] in self.keys:
                self.assertEqual(key, self.keys[row['key_id']])
        self.verifier.verify_signed(signed, NOW, stage=stage, evidence=self.proof)
        self.verifier.finish_history([], evidence=self.proof, broker_id=BROKER)
        self.sync.accept_pull(self.verifier, [], observed_at=NOW)
        self.assertEqual(self.sync.checkpoint()['epochs']['generation'], 2)
        with self.assertRaises(PolicyError):
            keeper.build_rotation(self.keys, self.signing, now=NOW)


if __name__ == '__main__':
    unittest.main()
