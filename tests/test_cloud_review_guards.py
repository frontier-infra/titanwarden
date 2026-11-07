"""Negative boundary probes built from recorded cloud enrollment material."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import PropertyMock, patch

from tw import crypto
from tw.cloud_enroll import EnrollmentSession, load_reservation, save_reservation, ticket_id
from tw.cloud_epochs import EpochView
from tw.policy_log import OfflineCloudVerifier, PolicyError
from tw.store import Store
from test_cloud_enrollment_production import documents, replay_join, body, result
from support import TEST_PASSPHRASE, TEST_ARGON2


class EnrollmentGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        docs = documents()
        cls.join = next(d for _, d in docs if 'broker_local_sas' in d)
        cls.adopt = next(d for item, d in docs if 'adopt' in item['file'])

    def fresh(self, *, adopt=False, pair=False):
        doc = self.adopt if adopt else self.join
        reserve = next(s for s in doc['steps'] if s['id'] in ('adopt-reservation', 'broker-enrollment-possession-proof'))
        payload = crypto.parse_canonical(body(reserve['input']['request']))
        session = EnrollmentSession(doc['org_id'], payload['transcript'],
            crypto.import_private(doc['test_only_keys']['signing_jwk']),
            crypto.import_private(doc['test_only_keys']['kx_jwk']))
        session.accept_reservation(result(reserve)['result'])
        temporary = tempfile.TemporaryDirectory(prefix='tw-review-enrollment-')
        self.addCleanup(temporary.cleanup)
        store = Store(Path(temporary.name)).open(create=True)
        self.addCleanup(store.close)
        if adopt:
            store.set_meta('store_id', doc['org_id'])
            batch = doc['steps'][5]['input']['input']['body']
            genesis = crypto.canonical_json(batch['entries'][0]['entry'])
        else:
            store.initialize(TEST_PASSPHRASE, argon2=TEST_ARGON2)
            genesis = bytes.fromhex(doc['steps'][0]['input']['records'][0]['canonical_hex'])
        blk = crypto.random_key()
        ticket = ticket_id(payload['ticket_code'])
        save_reservation(session, store, blk, ticket, payload['proof'])
        if pair:
            session.pin(store, genesis, typed_words=self.words(session, genesis))
        return session, store, blk, ticket, payload, genesis

    @staticmethod
    def words(session, genesis):
        return crypto.sas_words(crypto.sas_context(session.org, crypto.sha256(genesis).hex(), 'broker',
            session.broker_id, session.transcript['sign_pub'], session.transcript['kx_pub']))

    def setUp(self):
        self.session, self.store, self.blk, self.ticket, self.payload, self.genesis = self.fresh(pair=True)
        self.verifier = replay_join(self.join).replay
        self.poll = result(self.join['steps'][-1])['result']
        self.snapshot = self.verifier.export_checkpoint()
        fields = ('omk_generation', 'recipient_kind', 'recipient_id', 'eph_pub', 'nonce', 'wrapped_omk', 'wrap_digest')
        self.blobs = [dict(id=w['wrap_id'], **{k:w[k] for k in fields}) for w in self.poll['wraps']]

    def accept(self, verifier=None, blobs=None):
        return self.session.accept_custody(self.store, self.blk,
            self.verifier if verifier is None else verifier, self.blobs if blobs is None else blobs)

    def assert_no_omk(self):
        self.assertEqual(self.store.connection.execute("SELECT count(*) FROM cloud_local_keys WHERE purpose='omk'").fetchone()[0], 0)

    def test_unfinished_reviewer_probe_and_conflicted_verifier_refuse(self):
        unfinished = replay_join(self.join, finalize=False).replay
        for operation in (unfinished.export_checkpoint,
                          lambda: self.session.accept_poll(self.store,self.blk,unfinished,self.poll),
                          lambda: self.accept(unfinished)):
            with self.assertRaisesRegex(PolicyError, 'final verification'):
                operation()
        self.verifier._verifier.conflict = True
        with self.assertRaisesRegex(PolicyError, 'verifier is in conflict'):
            self.accept()
        self.assert_no_omk()

    def test_custody_reads_only_one_finalized_checkpoint(self):
        with patch.object(self.verifier,'export_checkpoint',return_value=self.snapshot) as export, \
             patch.object(OfflineCloudVerifier,'state',new_callable=PropertyMock,side_effect=AssertionError('live state read')), \
             patch.object(OfflineCloudVerifier,'epoch_state',new_callable=PropertyMock,side_effect=AssertionError('live epoch read')), \
             patch.object(self.verifier,'epoch_view',side_effect=AssertionError('live epoch view')):
            self.session.accept_poll(self.store,self.blk,self.verifier,self.poll)
        export.assert_called_once_with()

    def test_verifier_type_refuses_even_with_plausible_checkpoint(self):
        fake = SimpleNamespace(export_checkpoint=lambda:self.snapshot)
        with self.assertRaisesRegex(ValueError,'independent enrollment verification'):
            self.accept(fake)
        self.assert_no_omk()

    def test_checkpoint_and_stored_root_and_org_bindings(self):
        for location,field,value in (('checkpoint','org_id','b'*32),('authority','org_id','b'*32),
                                     ('checkpoint','pinned_root','b'*64),('authority','root','b'*64)):
            with self.subTest(location=location,field=field):
                snapshot = copy.deepcopy(self.snapshot)
                (snapshot if location=='checkpoint' else snapshot['authority'])[field] = value
                with patch.object(self.verifier,'export_checkpoint',return_value=snapshot), \
                     self.assertRaisesRegex(ValueError,'independent enrollment pin differs'):
                    self.accept()
        with patch.object(self.store,'cloud_pin',return_value='b'*64), \
             self.assertRaisesRegex(ValueError,'independent enrollment pin differs'):
            self.accept()
        self.assert_no_omk()

    def test_each_certificate_state_identity_and_digest_guard(self):
        point = crypto.b64url(crypto.export_point(crypto.generate_p256_key().public_key()))
        for field,value in (('state','revoked'),('name','another broker'),('sign_pub',point),('kx_pub',point),('transcript_digest','0'*64)):
            with self.subTest(field=field):
                snapshot = copy.deepcopy(self.snapshot)
                snapshot['authority']['brokers'][-1]['certificate'][field] = value
                with patch.object(self.verifier,'export_checkpoint',return_value=snapshot), \
                     self.assertRaisesRegex(ValueError,'verified certificate identity differs'):
                    self.accept()
        self.assert_no_omk()

    def test_no_committed_epoch_and_scoped_initial_acceptance_refuse(self):
        with patch.object(EpochView,'committed_generation',return_value=dict(kind='none_committed',generation=1)), \
             self.assertRaisesRegex(ValueError,'committed epoch required'):
            self.accept()
        snapshot = copy.deepcopy(self.snapshot)
        snapshot['authority']['brokers'][-1]['certificate']['scope'] = ['a']
        with patch.object(self.verifier,'export_checkpoint',return_value=snapshot), \
             self.assertRaisesRegex(ValueError,'scoped enrollment custody disabled'):
            self.accept()
        self.assert_no_omk()

    def test_poll_state_and_revoked_wrap_reach_their_semantic_guards(self):
        with self.assertRaisesRegex(ValueError,'active enrollment'):
            self.session.accept_poll(self.store,self.blk,self.verifier,dict(self.poll,state='pending'))
        poll = copy.deepcopy(self.poll)
        poll['wraps'][0]['revoked_at'] = '2027-01-15T08:00:00.000Z'
        with self.assertRaisesRegex(ValueError,'revoked enrollment wrap'):
            self.session.accept_poll(self.store,self.blk,self.verifier,poll)
        self.assert_no_omk()

    def test_duplicate_logical_wrap_exact_set_and_completeness(self):
        snapshot = copy.deepcopy(self.snapshot)
        cert = snapshot['authority']['brokers'][-1]['certificate']
        extra = dict(self.blobs[0],id='enw_'+'f'*32)
        cert['wrap_digests'].append(dict(id=extra['id'],digest=extra['wrap_digest']))
        with patch.object(self.verifier,'export_checkpoint',return_value=snapshot), \
             self.assertRaisesRegex(ValueError,'duplicate logical enrollment wrap'):
            self.accept(blobs=self.blobs+[extra])
        with self.assertRaisesRegex(ValueError,'exact certificate wrap set'):
            self.accept(blobs=[])
        snapshot = copy.deepcopy(self.snapshot)
        snapshot['authority']['brokers'][-1]['certificate']['wrap_digests'] = []
        with patch.object(self.verifier,'export_checkpoint',return_value=snapshot), \
             self.assertRaisesRegex(ValueError,'incomplete enrollment custody'):
            self.accept(blobs=[])
        self.assert_no_omk()

    def test_existing_org_pin_cannot_skip_this_brokers_typed_sas(self):
        session,store,blk,ticket,_,_ = self.fresh()
        root = self.snapshot['pinned_root']
        store.initialize_cloud_replay(session.org,root)
        resumed = load_reservation(store,blk,session.org,ticket)
        self.assertIsNone(resumed.pinned_root)
        with self.assertRaisesRegex(ValueError,'typed SAS pairing required'):
            resumed.accept_poll(store,blk,self.verifier,self.poll)
        # Supplying the in-memory attribute still cannot bypass the DB state.
        resumed.pinned_root = root
        with self.assertRaisesRegex(ValueError,'typed SAS pairing required'):
            resumed.accept_custody(store,blk,self.verifier,self.blobs)
        with self.assertRaises(TypeError):
            EnrollmentSession(session.org,session.transcript,session.signing_key,session.exchange_key,pinned_root=root)
        self.assertEqual(store.connection.execute('SELECT state FROM cloud_enrollments').fetchone()[0],'reserved')
        self.assertEqual(store.connection.execute("SELECT count(*) FROM cloud_local_keys WHERE purpose='omk'").fetchone()[0],0)

    def test_missing_duplicate_and_changed_paired_rows_refuse_atomically(self):
        original = dict(self.store.connection.execute('SELECT * FROM cloud_enrollments').fetchone())
        cases = ('missing','duplicate','transcript','root','reserved')
        for case in cases:
            with self.subTest(case=case):
                with self.store.transaction(immediate=True) as db:
                    db.execute('DELETE FROM cloud_enrollments')
                    if case!='missing':
                        row = dict(original)
                        if case=='transcript': row['transcript_json']='{}'
                        if case=='root': row['candidate_root']='b'*64
                        if case=='reserved': row['state']='reserved'
                        fields=','.join(row);values=','.join('?' for _ in row)
                        db.execute(f'INSERT INTO cloud_enrollments({fields}) VALUES ({values})',tuple(row.values()))
                        if case=='duplicate':
                            row['ticket_id'] += '_second'
                            db.execute(f'INSERT INTO cloud_enrollments({fields}) VALUES ({values})',tuple(row.values()))
                message = 'persisted pairing' if case in ('transcript','root') else 'typed SAS pairing'
                with self.assertRaisesRegex(ValueError,message):
                    self.accept()
                self.assert_no_omk()

    def test_complete_retries_bind_certificate_generation_and_wrap_digests(self):
        self.accept()
        self.accept()
        stored = self.store.connection.execute('SELECT custody_json FROM cloud_enrollments').fetchone()[0]
        self.assertEqual(json.loads(stored),dict(generation=1,wrap_digests=self.snapshot['authority']['brokers'][-1]['certificate']['wrap_digests']))
        for field in ('certificate','generation','wrap_digests'):
            with self.subTest(field=field):
                if field=='certificate':
                    self.store.connection.execute("UPDATE cloud_enrollments SET certificate_json='{}'")
                else:
                    accepted=json.loads(stored)
                    accepted[field]=2 if field=='generation' else []
                    self.store.connection.execute('UPDATE cloud_enrollments SET custody_json=?',(crypto.canonical_json(accepted).decode(),))
                with self.assertRaisesRegex(ValueError,'only identical custody retries'):
                    self.accept()
                self.store.connection.execute('UPDATE cloud_enrollments SET certificate_json=?,custody_json=?',
                    (crypto.canonical_json(self.snapshot['authority']['brokers'][-1]['certificate']).decode(),stored))

    def test_completion_requires_one_changed_row_and_rolls_back_new_keys(self):
        self.store.connection.execute("CREATE TRIGGER ignore_completion BEFORE UPDATE ON cloud_enrollments BEGIN SELECT RAISE(IGNORE); END")
        with self.assertRaisesRegex(ValueError,'exactly one paired enrollment'):
            self.accept()
        self.assert_no_omk()
        self.assertEqual(self.store.connection.execute('SELECT state FROM cloud_enrollments').fetchone()[0],'pinned')

    def test_every_genesis_field_in_pin_is_checked_after_parsing(self):
        for field,value in (('kind','broker_cert'),('seq',2),('org_id','b'*32),('prev_hash','1'*64)):
            with self.subTest(field=field):
                session,store,_,_,_,raw = self.fresh()
                entry=crypto.parse_canonical(raw);entry[field]=value;raw=crypto.canonical_json(entry)
                with self.assertRaisesRegex(ValueError,'invalid pairing genesis'):
                    session.pin(store,raw,typed_words=self.words(session,raw))

    def test_pin_reservation_sas_and_prior_pin_are_required(self):
        session,store,_,_,_,raw = self.fresh()
        with self.assertRaisesRegex(ValueError,'independent typed SAS'):
            session.pin(store,raw,typed_words='sas_matched')
        session.pinned_root = '0'*64
        with self.assertRaisesRegex(ValueError,'pairing root changed'):
            session.pin(store,raw,typed_words=self.words(session,raw))
        session.broker_id = None
        with self.assertRaisesRegex(ValueError,'broker reservation required'):
            session.pin(store,raw,typed_words='irrelevant')

    def test_pin_adopt_store_and_every_founder_binding(self):
        session,store,_,_,_,raw = self.fresh(adopt=True)
        store.set_meta('store_id','b'*32)
        with self.assertRaisesRegex(ValueError,'existing local store id'):
            session.pin(store,raw,typed_words=self.words(session,raw))
        for field,value in (('kind','member'),('id','other'),('sign_pub',self.join['broker_local_sas']['kx_pub']),('kx_pub',self.join['broker_local_sas']['sign_pub'])):
            with self.subTest(field=field):
                session,store,_,_,_,raw = self.fresh(adopt=True)
                entry=crypto.parse_canonical(raw);entry['body']['founder'][field]=value;raw=crypto.canonical_json(entry)
                with self.assertRaisesRegex(ValueError,'adoption genesis founder differs'):
                    session.pin(store,raw,typed_words=self.words(session,raw))

    def test_pin_candidate_root_and_persisted_identity_bindings(self):
        session,store,_,_,_,raw = self.fresh(adopt=True)
        session.candidate_root = '0'*64
        with self.assertRaisesRegex(ValueError,'adoption accepted root differs'):
            session.pin(store,raw,typed_words=self.words(session,raw))
        for field,value in (('transcript_json','{}'),('candidate_root','b'*64)):
            with self.subTest(field=field):
                session,store,_,_,_,raw = self.fresh()
                store.connection.execute(f'UPDATE cloud_enrollments SET {field}=?',(value,))
                with self.assertRaisesRegex(ValueError,'persisted pairing identity or root'):
                    session.pin(store,raw,typed_words=self.words(session,raw))

    def test_save_reservation_checks_proof_before_persisting_and_retry_key(self):
        session,store,blk,ticket,payload,_ = self.fresh()
        store.connection.execute('DELETE FROM cloud_enrollments')
        store.connection.execute('DELETE FROM cloud_local_keys')
        wrong = bytearray(crypto.unb64url(payload['proof']));wrong[0]^=1
        with self.assertRaisesRegex(ValueError,'enrollment proof differs'):
            save_reservation(session,store,blk,ticket,crypto.b64url(bytes(wrong)))
        self.assertEqual(store.connection.execute('SELECT count(*) FROM cloud_local_keys').fetchone()[0],0)
        save_reservation(session,store,blk,ticket,payload['proof'])
        with patch.object(store,'cloud_local_key',return_value=b'X'*32), \
             self.assertRaisesRegex(ValueError,'reserved private key differs'):
            save_reservation(session,store,blk,ticket,payload['proof'])

    def test_save_root_proof_refuses_persisted_changed_root(self):
        session,store,_,ticket,_,raw = self.fresh(adopt=True)
        store.connection.execute('UPDATE cloud_enrollments SET candidate_root=?',('b'*64,))
        with self.assertRaisesRegex(ValueError,'persisted adoption root changed'):
            session.save_root_proof(store,ticket,crypto.sha256(raw).hex())

    def test_reloading_pinned_row_checks_stored_root(self):
        self.store.connection.execute('UPDATE cloud_enrollments SET candidate_root=?',('b'*64,))
        with self.assertRaisesRegex(ValueError,'persisted pairing root differs'):
            load_reservation(self.store,self.blk,self.session.org,self.ticket)

    def test_each_omk_recipient_and_generation_field_is_checked(self):
        for field,value in (('recipient_kind','member_key'),('recipient_id','other-broker'),('omk_generation',2)):
            with self.subTest(field=field):
                blobs=copy.deepcopy(self.blobs);blobs[0][field]=value
                with self.assertRaisesRegex(ValueError,'OMK recipient or generation differs'):
                    self.accept(blobs=blobs)
        self.assert_no_omk()

    def test_explicit_schema_upgrade_and_old_complete_rows_fail_closed(self):
        self.store.connection.execute('ALTER TABLE cloud_enrollments DROP COLUMN custody_json')
        self.store.initialize_cloud_custody()
        self.assertIn('custody_json',{r['name'] for r in self.store.connection.execute('PRAGMA table_info(cloud_enrollments)')})
        self.store.connection.execute("UPDATE cloud_enrollments SET state='complete',certificate_json=?",
            (crypto.canonical_json(self.snapshot['authority']['brokers'][-1]['certificate']).decode(),))
        with self.assertRaisesRegex(ValueError,'only identical custody retries'):
            self.accept()
        self.assert_no_omk()

    def test_poll_verifier_type_and_array_shapes_are_explicit(self):
        fake=SimpleNamespace(export_checkpoint=lambda:self.snapshot)
        with self.assertRaisesRegex(ValueError,'active enrollment and independent verifier required'):
            self.session.accept_poll(self.store,self.blk,fake,self.poll)
        for field in ('wraps','scoped_seals'):
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'enrollment wrap arrays required'):
                self.session.accept_poll(self.store,self.blk,self.verifier,dict(self.poll,**{field:tuple(self.poll[field])}))
        self.assert_no_omk()

    def test_pin_typed_sas_requires_text_and_custody_requires_local_identity(self):
        session,store,_,_,_,raw=self.fresh()
        with self.assertRaisesRegex(ValueError,'independent typed SAS differs'):
            session.pin(store,raw,typed_words=True)
        for field in ('pinned_root','broker_id'):
            with self.subTest(field=field):
                old=getattr(self.session,field);setattr(self.session,field,None)
                try:
                    with self.assertRaisesRegex(ValueError,'independent enrollment verification required'):
                        self.accept()
                finally:
                    setattr(self.session,field,old)
        self.assert_no_omk()

    def test_each_exact_wrap_set_condition_is_reached(self):
        for blobs in (self.blobs+self.blobs,[dict(self.blobs[0],id='enw_'+'f'*32)]):
            with self.subTest(blobs=blobs),self.assertRaisesRegex(ValueError,'exact certificate wrap set required'):
                self.accept(blobs=blobs)
        self.assert_no_omk()

    def test_reload_refuses_null_root_even_if_persisted_candidate_is_null(self):
        self.store.connection.execute('UPDATE cloud_enrollments SET candidate_root=NULL')
        with patch.object(self.store,'cloud_pin',return_value=None), \
             self.assertRaisesRegex(ValueError,'persisted pairing root differs'):
            load_reservation(self.store,self.blk,self.session.org,self.ticket)

    def test_save_root_proof_requires_the_exact_persisted_reservation(self):
        for field,value in (('missing',None),('broker_id','other'),('transcript_json','{}')):
            with self.subTest(field=field):
                session,store,_,ticket,_,raw=self.fresh(adopt=True)
                if field=='missing': store.connection.execute('DELETE FROM cloud_enrollments')
                else: store.connection.execute(f'UPDATE cloud_enrollments SET {field}=?',(value,))
                with self.assertRaisesRegex(ValueError,'persisted reservation differs'):
                    session.save_root_proof(store,ticket,crypto.sha256(raw).hex())

    def test_session_constructor_requires_both_matching_private_keys(self):
        for field in ('signing_key','exchange_key'):
            with self.subTest(field=field):
                values=dict(org=self.session.org,transcript=self.session.transcript,
                    signing_key=self.session.signing_key,exchange_key=self.session.exchange_key)
                values[field]=crypto.generate_p256_key()
                with self.assertRaisesRegex(ValueError,'local enrollment key differs'):
                    EnrollmentSession(**values)

    def test_custody_retry_checks_existing_metadata_and_plaintext(self):
        self.accept()
        original=dict(self.store.connection.execute("SELECT * FROM cloud_local_keys WHERE purpose='omk'").fetchone())
        for field,value in (('purpose','other'),('scope','other'),('key',None)):
            with self.subTest(field=field):
                if field=='key':
                    wrapped,nonce=crypto.wrap_key(self.blk,crypto.random_key(),crypto.local_key_aad(
                        self.session.org,self.session.broker_id,'omk_1','omk','*',1))
                    self.store.connection.execute("UPDATE cloud_local_keys SET wrapped_key=?,nonce=? WHERE key_id='omk_1'",(wrapped,nonce))
                else:
                    self.store.connection.execute(f"UPDATE cloud_local_keys SET {field}=? WHERE key_id='omk_1'",(value,))
                with self.assertRaisesRegex(ValueError,'custody retry changed key'):
                    self.accept()
                self.store.connection.execute("UPDATE cloud_local_keys SET purpose=?,scope=?,wrapped_key=?,nonce=? WHERE key_id='omk_1'",
                    (original['purpose'],original['scope'],original['wrapped_key'],original['nonce']))

    def test_declared_wrap_digest_is_checked_before_unsealing(self):
        blobs=copy.deepcopy(self.blobs);blobs[0]['wrap_digest']='0'*64
        with self.assertRaisesRegex(ValueError,'enrollment wrap bytes differ'):
            self.accept(blobs=blobs)
        self.assert_no_omk()

    def test_save_reservation_requires_identity_and_exact_retry_binding(self):
        for field,value in (('broker_id','other-broker'),('transcript_json','{}')):
            with self.subTest(field=field):
                session,store,blk,ticket,payload,_=self.fresh()
                store.connection.execute(f'UPDATE cloud_enrollments SET {field}=?',(value,))
                with self.assertRaisesRegex(ValueError,'reservation retry identity differs'):
                    save_reservation(session,store,blk,ticket,payload['proof'])
        session,store,blk,ticket,payload,_=self.fresh();session.broker_id=None
        with self.assertRaisesRegex(ValueError,'reservation identity required'):
            save_reservation(session,store,blk,ticket,payload['proof'])
