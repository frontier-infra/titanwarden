"""Consume real cloud operational traces without a live network or seeded state."""
import copy
import json
import tempfile
import unittest
from urllib.parse import urlsplit, parse_qsl

from tw import crypto
from tw.cloud_audit import ReceiptPins, AuditSync, verify_checkpoint
from tw.cloud_enroll import EnrollmentSession, save_reservation, ticket_id
from tw.cloud_epochs import epoch_checkpoint
from tw.cloud_http import SignedRequest, SignedClient, verify_request, decode_response, CloudResponseError
from tw.cloud_keeper import Keeper
from tw.cloud_policy import AuthorityView
from tw.cloud_recovery import RecoveryEvidence
from tw.cloud_sync import CloudSync
from tw.cloud_sync_verifier import SyncVerifier
from tw.cloud_wire import hash_object
from tw.policy_log import PolicyError
from tw.store import Store, StoreError
from ops_cloud_fixtures import documents, ROOT
from paired_cloud_fixtures import decode
from test_cloud_recovery import RecoveryPairedReplay


def result(step):
    return json.loads(step['response']['body']).get('result')


def request_body(step):
    encoded = step['input'].get('request', {}).get('body_b64')
    return None if encoded is None else crypto.parse_canonical(crypto.unb64url(encoded))


class OpsReplay:
    def __init__(self, document):
        self.document = document
        first = document['steps'][0]['input']
        trace = dict(profile=document['profile'], production_acceptable=document['production_acceptable'],
            org_id=document['org_id'], pinned_root=first['root'], records=first['records'])
        self.harness = RecoveryPairedReplay(trace)
        self.harness.replay = SyncVerifier(document['org_id'], first['root'], projects=next(r['entry']['body']['active_kek'] for r in first['records'] if r['entry']['kind'] == 'epoch_init'))
        for record in first['records']:
            # The exporter replaces its unsigned initial stage before signing
            # epoch_init. Model that SQLite upsert rather than append duplicates.
            if any(e['table'] == 'epoch_staging' for e in record['evidence']):
                self.harness.blobs['epoch_staging'] = []
            outcome = self.harness.run(dict(record, mode='history'))
            if outcome['status'] != 'accepted':
                raise AssertionError(outcome)

    def step(self, step):
        p = self.harness
        tables = decode(step['post_state']['tables'])
        for table, rows in tables.items():
            p.rows[table] = rows
            if table in ('epoch_staging', 'keyring', 'org_key_wraps', 'broker_key_wraps', 'secret_versions'):
                p.blobs[table] = rows
        body = request_body(step)
        target = step['post_state']['authority_core']['head']
        signed = []
        if body and step['response']['status'] < 400 and target['seq'] > p.replay.head['seq']:
            signed = body.get('entries', [dict(entry=body['entry'], sig=body['sig'])] if 'entry' in body else [])
        for item in signed:
            entry = item['entry']
            blob = body.get('version') if entry['kind'] == 'version_add' else None
            p.replay.verify_signed(item, step['received_at'], stage=p.stage(entry), blob=blob,
                evidence=RecoveryEvidence(p.rows, p.blobs),
                runtime=dict(mode='history', now=step['received_at'], observations=dict(heads=[], proposals={})))
        return p.summary()

    def finish(self, broker):
        p = self.harness
        scope = p.replay.authority_view().broker_certificate_at(broker, p.replay.head)['scope']
        expected = p.replay.epoch_state['versions']
        blobs = [p.ciphertext(r) for r in p.blobs.get('secret_versions', []) if any(v['version_id'] == r['version_id'] and (scope == 'full' or v['project'] in scope) for v in expected)]
        p.replay.finish_history(blobs, evidence=RecoveryEvidence(p.rows, p.blobs), broker_id=broker)
        return blobs


class OperationalFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.docs = documents()

    def test_manifest_profiles_counts_response_bytes_and_refusal_rollback(self):
        self.assertEqual(crypto.sha256((ROOT / 'PAIRED-BROKER.md').read_bytes()).hex(), '949880b093a0a0a3608c93343d85f439e8da22f40d7b2d433123628bc8291f69')
        count = refused = 0
        for item, doc in self.docs:
            self.assertEqual(doc['profile'], 'production')
            self.assertIs(doc['production_acceptable'], True)
            self.assertEqual(len(doc['steps']), item['records'])
            self.assertEqual(sum(s['response']['status'] >= 400 for s in doc['steps']), item['cases'])
            for step in doc['steps']:
                count += 1
                response = step['response']
                if 'body_b64' in response:
                    self.assertEqual(crypto.unb64url(response['body_b64']), response['body'].encode())
                self.assertEqual(hash_object(step['post_state']['authority_core']), step['post_state']['authority_core_sha256'])
                if response['status'] >= 400:
                    refused += 1
                    self.assertEqual(step['post_state']['authority_core'], step['predecessor']['authority_core'])
                    for table in ('seen_nonces', 'receipts', 'recovery_head_reports', 'recovery_conflict_reports'):
                        self.assertEqual(step['post_state']['tables'][table], step['predecessor']['tables'][table])
        self.assertEqual((count, refused), (103, 20))

    def test_every_signed_transport_and_complete_policy_prefix_agree(self):
        checked = records = 0
        for item, doc in self.docs:
            replay = OpsReplay(doc)
            for step in doc['steps']:
                with self.subTest(file=item['file'], step=step['id']):
                    req = step['input'].get('request', {})
                    if 'TW-Broker' in req.get('headers', {}):
                        broker = req['headers']['TW-Broker']
                        cert = replay.harness.replay.authority_view().broker_certificate_at(broker, replay.harness.replay.head)
                        public = crypto.unb64url(cert['sign_pub']) if cert else crypto.export_point(crypto.import_private(doc['test_only_keys']['signing_jwk']).public_key())
                        signed = SignedRequest(req['url'], req['method'], tuple(req['headers'].items()), crypto.unb64url(req['body_b64']) if 'body_b64' in req else b'')
                        verify_request(signed, doc['org_id'], broker, public, step['received_at'])
                        self.assertEqual(urlsplit(req['url']).path, req['path'])
                        self.assertEqual(crypto.canonical_query(parse_qsl(urlsplit(req['url']).query, keep_blank_values=True)), req['canonical_query'])
                        self.assertEqual(signed.forwarding(), {k:req[k] for k in ('url', 'method', 'headers', 'body_b64') if k in req})
                        checked += 1
                    before = replay.harness.replay.head['seq']
                    actual = replay.step(step)
                    records += replay.harness.replay.head['seq'] - before
                    for field in ('authority_core', 'authority_core_sha256'):
                        self.assertEqual(actual[field], step['post_state'][field], field)
                    self.assertEqual([dict(broker_id=broker, **view) for broker, view in sorted(actual['custody'].items())], step['post_state']['custody'])
                    self.assertEqual(epoch_checkpoint(replay.harness.replay.epoch_state), step['post_state']['epoch'])
            broker = next(s['input']['request']['headers']['TW-Broker'] for s in doc['steps'] if 'TW-Broker' in s['input'].get('request', {}).get('headers', {}))
            replay.finish(broker)
        self.assertEqual(checked, 51)
        self.assertEqual(records, 19)

    def test_every_authenticated_cloud_anchor_receipt_uses_the_release_pin(self):
        checked = 0
        for _, doc in self.docs:
            key = doc['test_only_keys']['receipt']
            pins = ReceiptPins(key['key_id'], crypto.unb64url(key['public_key']))
            for step in doc['steps']:
                for anchor in step['post_state']['tables']['anchors']:
                    evidence = json.loads(anchor['receipt'])
                    receipt = evidence['receipt']
                    expected = {k:receipt[k] for k in ('seq', 'hash', 'ts', 'sig')}
                    pins.verify(doc['org_id'], anchor['chain_id'], expected, receipt)
                    checked += 1
                for receipt in step['post_state']['tables']['receipts']:
                    self.assertNotIn('claim_token', receipt['response_json'])
        self.assertEqual(checked, 1167)

    def test_all_twenty_recorded_refusals_reach_broker_transport_and_local_guards(self):
        refused = versions = cursors = 0
        for item, doc in self.docs:
            replay = OpsReplay(doc)
            broker = result(doc['steps'][2])['broker_id']
            with tempfile.TemporaryDirectory() as temporary:
                with Store(temporary).open(create=True) as store:
                    store.initialize_cloud_replay(doc['org_id'],doc['steps'][0]['input']['root'])
                    sync = CloudSync(store,doc['org_id'],broker)
                    for step in doc['steps']:
                        if step['response']['status'] >= 400:
                            refused += 1
                            before = sync.checkpoint()
                            expected = json.loads(step['response']['body'])['code']
                            req = step['input']['request']
                            if 'TW-Broker' in req.get('headers',{}):
                                request = SignedRequest(req['url'],req['method'],tuple(req['headers'].items()),crypto.unb64url(req['body_b64']) if 'body_b64' in req else b'')
                                client = SignedClient(doc['org_id'],broker,crypto.import_private(doc['test_only_keys']['signing_jwk']),clock=lambda:step['received_at'],transport=lambda request:(step['response']['status'],step['response']['body'].encode()))
                                operation = lambda:client.send_http(request)
                            else:
                                operation = lambda:decode_response(step['response']['status'],step['response']['body'].encode())
                            with self.subTest(file=item['file'],step=step['id']), self.assertRaises(CloudResponseError) as caught:
                                operation()
                            self.assertEqual(caught.exception.code,expected)
                            if step['id'] in ('stale-policy-head-refusal','retired-epoch-refusal'):
                                versions += 1
                                with self.assertRaises(PolicyError) as local:
                                    sync.stage_version(request_body(step),now=step['received_at'])
                                self.assertEqual(local.exception.code, 'E_POLICY_HEAD' if expected=='E_POLICY_HEAD' else 'E_STALE_EPOCH')
                            after = dict(parse_qsl(urlsplit(req['url']).query)).get('after')
                            if after is not None:
                                cursors += 1
                                with self.assertRaises(PolicyError) as local:
                                    sync.validate_cursor(after)
                                self.assertEqual(local.exception.code,expected)
                            self.assertEqual(sync.checkpoint(),before)
                            self.assertFalse(sync.conflicts())
                        replay.step(step)
                        if replay.harness.replay.head['seq'] >= 4:
                            blobs = replay.finish(broker)
                            sync.accept_pull(replay.harness.replay,blobs,observed_at=step['received_at'])
        self.assertEqual((refused,versions,cursors),(20,2,8))

    def scoped_setup(self):
        doc = next(d for item, d in self.docs if item['file'] == 'broker-ops-scoped-v1.json')
        replay = OpsReplay(doc)
        for step in doc['steps'][:5]:
            replay.step(step)
        reserve = doc['steps'][2]
        payload = request_body(reserve)
        session = EnrollmentSession(doc['org_id'], payload['transcript'],
            crypto.import_private(doc['test_only_keys']['signing_jwk']), crypto.import_private(doc['test_only_keys']['kx_jwk']))
        session.accept_reservation(result(reserve))
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        store = Store(temporary.name).open(create=True)
        self.addCleanup(store.close)
        blk = crypto.random_key()
        save_reservation(session, store, blk, ticket_id(payload['ticket_code']), payload['proof'])
        genesis = bytes.fromhex(doc['steps'][0]['input']['records'][0]['canonical_hex'])
        root = crypto.sha256(genesis).hex()
        words = crypto.sas_words(crypto.sas_context(doc['org_id'], root, 'broker', session.broker_id, session.transcript['sign_pub'], session.transcript['kx_pub']))
        self.assertEqual(session.pin(store, genesis, typed_words=words), root)
        replay.finish(session.broker_id)
        return doc, replay, session, store, blk

    def test_positive_scoped_initial_acceptance_opens_only_active_project_kek_and_fk(self):
        doc, replay, session, store, blk = self.scoped_setup()
        poll = result(doc['steps'][5])
        accepted = session.accept_poll(store, blk, replay.harness.replay, poll, allow_scoped=True)
        self.assertEqual(accepted['certificate']['scope'], ['a'])
        self.assertEqual(accepted['certificate']['wrap_digests'], replay.harness.replay.state['brokers'][-1]['certificate']['wrap_digests'])
        for kid, plain in doc['test_only_keys']['scoped_plaintexts'].items():
            purpose, scope = ('fingerprint', '*') if kid == 'fk' else ('kek', 'a')
            key = store.cloud_local_key(blk, org=doc['org_id'], broker=session.broker_id, key_id=kid, purpose=purpose, scope=scope, generation=1)
            self.assertEqual(key.hex(), plain)
            # Scoped key material is distinct from OMK and cannot open the
            # actual OMK-encrypted, policy-committed keyring.
            for row in replay.harness.replay.epoch_state['keyring']:
                with self.assertRaises(crypto.CryptoError):
                    crypto.unwrap_key(key, bytes.fromhex(row['wrapped_key']), bytes.fromhex(row['nonce']), crypto.cloud_keyring_aad(doc['org_id'], row['key_id'], row['purpose'], row['project'] or '*', 1))
        for kid, purpose, scope in [('omk_1', 'omk', '*'), ('kek_b_1', 'kek', 'b')]:
            with self.assertRaises(StoreError):
                store.cloud_local_key(blk, org=doc['org_id'], broker=session.broker_id, key_id=kid, purpose=purpose, scope=scope, generation=1)
        store.initialize_cloud_replay(doc['org_id'], session.pinned_root)
        sync = CloudSync(store, doc['org_id'], session.broker_id)
        sync.accept_pull(replay.harness.replay, [], observed_at=doc['received_at'])
        self.assertEqual(sync.sync_pages([result(doc['steps'][7])], now=doc['received_at']), [])
        with self.assertRaisesRegex(PolicyError, 'outside certified scope'):
            sync.require_delivery('b', 'standard', doc['received_at'])
        self.assertEqual(sync.pickup_keys(result(doc['steps'][6]), blk, session.exchange_key), ['fk', 'kek_a_1'])

    def test_cloud_version_recovery_and_scoped_pulls_drive_real_local_delivery(self):
        delivered = 0
        for filename in ('broker-ops-versions-v1.json', 'broker-ops-sync-v1.json'):
            doc = next(d for item,d in self.docs if item['file'] == filename)
            replay = OpsReplay(doc)
            broker = result(doc['steps'][2])['broker_id']
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            store = Store(temporary.name).open(create=True)
            self.addCleanup(store.close)
            store.initialize_cloud_replay(doc['org_id'], doc['steps'][0]['input']['root'])
            sync = CloudSync(store, doc['org_id'], broker)
            blk = crypto.random_key()
            exchange = crypto.import_private(doc['test_only_keys']['kx_jwk'])
            for step in doc['steps']:
                replay.step(step)
                if replay.harness.replay.head['seq'] < 4:
                    continue
                blobs = replay.finish(broker)
                sync.accept_pull(replay.harness.replay, blobs, observed_at=step['received_at'])
                if step['id'] == 'scope-narrowing':
                    self.assertEqual(store.connection.execute("SELECT count(*) FROM cloud_local_keys WHERE scope='b'").fetchone()[0],0)
                body = result(step)
                if step['id'] in ('recover-current-keys', 'scoped-key-pull', 'narrowed-key-pull'):
                    sync.pickup_keys(body, blk, exchange)
                if step['id'] == 'pull-committed-versions':
                    sync.sync_pages([body], now=step['received_at'])
                    for version in body['versions']:
                        value = sync.read_value(version['version_id'], blk, now=step['received_at'])
                        self.assertIsInstance(value, bytes)
                        self.assertTrue(value)
                        delivered += 1
                if step['id'] == 'blob-first-page':
                    # W17 marks these as unsigned storage-only pagination rows.
                    # They never become policy authority in the broker.
                    with self.assertRaisesRegex(PolicyError, 'secret metadata'):
                        sync.sync_pages([body], now=step['received_at'])
                if step['id'] == 'narrowed-key-pull':
                    self.assertEqual(store.connection.execute("SELECT count(*) FROM cloud_local_keys WHERE scope='b'").fetchone()[0], 0)
            self.assertNotIn('wrapped', json.dumps(sync.agent_metadata()))
        self.assertGreaterEqual(delivered, 3)

    def test_real_audit_push_receipt_roundtrip_and_closed_pull_boundaries(self):
        doc = next(d for item,d in self.docs if item['file'] == 'broker-ops-audit-v1.json')
        step = doc['steps'][5]
        body = request_body(step)
        broker = body['chain_id']
        key = doc['test_only_keys']['receipt']
        pins = ReceiptPins(key['key_id'], crypto.unb64url(key['public_key']))
        public = crypto.export_point(crypto.import_private(doc['test_only_keys']['signing_jwk']).public_key())
        with tempfile.TemporaryDirectory() as temporary:
            with Store(temporary).open(create=True) as store:
                store.initialize_cloud_replay(doc['org_id'], doc['steps'][0]['input']['root'])
                sync = AuditSync(store, doc['org_id'], broker, pins, broker_public=public)
                receipt = result(step)['receipt']
                sync.accept(body['events'], body['checkpoint'], receipt, observed_at=step['received_at'])
                sync.accept([], body['checkpoint'], result(doc['steps'][6])['receipt'], observed_at=step['received_at'])
                self.assertEqual(sync.retained()['seq'], result(step)['accepted_through_seq'])
                changed = dict(receipt, ts='2027-01-15T08:00:00.001Z')
                with self.assertRaisesRegex(ValueError, 'original checkpoint'):
                    pins.verify(doc['org_id'], broker, body['checkpoint'], changed)
        self.assertEqual((doc['steps'][-2]['response']['status'], json.loads(doc['steps'][-2]['response']['body'])['code']), (403, 'E_ROLE'))
        self.assertEqual((doc['steps'][-1]['response']['status'], json.loads(doc['steps'][-1]['response']['body'])['code']), (501, 'E_NOT_IMPLEMENTED'))

    def test_interrupted_keeper_lease_and_full_downgrade_custody_follow_committed_epoch(self):
        doc = next(d for item,d in self.docs if item['file'] == 'broker-ops-keeper-rekey-v1.json')
        replay = OpsReplay(doc)
        second = request_body(doc['steps'][8])['entry']['body']['requested']['broker_id']
        primary = result(doc['steps'][2])['broker_id']
        exchange = crypto.import_private(doc['test_only_keys']['kx_jwk'])
        with tempfile.TemporaryDirectory() as temporary:
            with Store(temporary).open(create=True) as store:
                store.initialize_cloud_replay(doc['org_id'], doc['steps'][0]['input']['root'])
                primary_sync = CloudSync(store, doc['org_id'], primary)
                narrowed_sync = CloudSync(store, doc['org_id'], second)
                blk = crypto.random_key()
                keeper = None
                for step in doc['steps']:
                    replay.step(step)
                    if replay.harness.replay.head['seq'] < 4:
                        continue
                    blobs = replay.finish(primary)
                    primary_sync.accept_pull(replay.harness.replay, blobs, observed_at=step['received_at'])
                    epoch = replay.harness.replay.epoch_state
                    if step['id'] == 'second-full-certificate':
                        keys = dict(omk_generation=1, my_wrap=next(w for w in epoch['org_wraps'] if w['recipient_id'] == second), keyring=epoch['keyring'])
                        narrowed_sync.pickup_keys(keys, blk, exchange)
                    if step['id'] == 'keeper-claim':
                        plan = step['input']['request']['path'].split('/')[-2]
                        keeper = Keeper(primary_sync, plan)
                        keeper.accept_claim(result(step), expected_head=replay.harness.replay.head, now=step['received_at'])
                    if step['id'] in ('keeper-renew', 'resume-lease-after-crash'):
                        self.assertEqual(keeper.lease(step['received_at'])['fence'], 1)
                    if step['id'] == 'exclusive-lease-expiry':
                        with self.assertRaisesRegex(PolicyError, 'lease expired'):
                            keeper.lease(step['received_at'])
                    if step['id'] == 'claim-after-expiry-new-fence':
                        keeper.accept_claim(result(step), expected_head=replay.harness.replay.head, now=step['received_at'])
                        self.assertEqual(keeper.lease(step['received_at'])['fence'], 2)
                    if step['id'] in ('downgrade-full-custody', 'resume-new-fence-commit'):
                        # This broker's verified pull must prune custody even if
                        # it never follows the commit with another key pickup.
                        narrowed_blobs = replay.finish(second)
                        narrowed_sync.accept_pull(replay.harness.replay,narrowed_blobs,observed_at=step['received_at'])
                        before_pickup = store.connection.execute("SELECT count(*) FROM cloud_local_keys WHERE broker_id=? AND purpose='omk'",(second,)).fetchone()[0]
                        self.assertEqual(before_pickup,1 if step['id']=='downgrade-full-custody' else 0)
                        rows = [w for w in epoch['broker_wraps'] if w['broker_id'] == second and any(k['key_id'] == w['key_id'] for k in epoch['keyring']) and (w['purpose'] == 'fingerprint' or w['project'] == 'a')]
                        narrowed_sync.pickup_keys(dict(omk_generation=epoch['generation'], broker_key_wraps=rows), blk, exchange)
                        omks = store.connection.execute("SELECT count(*) FROM cloud_local_keys WHERE broker_id=? AND purpose='omk'", (second,)).fetchone()[0]
                        self.assertEqual(omks, 1 if step['id'] == 'downgrade-full-custody' else 0)
                        with self.assertRaisesRegex(PolicyError, 'outside certified scope'):
                            narrowed_sync.require_delivery('b', 'standard', step['received_at'])
                self.assertIsNotNone(keeper)
                with self.assertRaisesRegex(PolicyError, 'fresh keeper claim'):
                    Keeper(primary_sync, keeper.plan).lease(doc['steps'][-1]['received_at'])
                self.assertEqual(store.connection.execute("SELECT count(*) FROM cloud_local_keys WHERE broker_id=? AND scope='b'", (second,)).fetchone()[0], 0)


if __name__ == '__main__':
    unittest.main()
