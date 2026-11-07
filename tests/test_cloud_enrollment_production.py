"""Compare cloud production traces without network or seeded authority state."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlsplit, parse_qsl

from tw import crypto
from tw.cloud_enroll import EnrollmentSession, save_reservation, verify_proof, ticket_id
from tw.cloud_http import SignedRequest, verify_request, request_url
from tw.cloud_wire import load_pinned_json, hash_object
from tw.cloud_epochs import epoch_checkpoint
from tw.cloud_policy import AuthorityEvidence
from tw.policy_log import PolicyRecord, OfflineCloudVerifier
from tw.store import Store
from paired_cloud_fixtures import PairedReplay, decode
from support import TEST_PASSPHRASE, TEST_ARGON2

PIN='177766e1de71acbff0a188fa4d4b487db6c28391'
ROOT=Path(__file__).parent/'fixtures/cloud'/PIN/'core/vectors'
MANIFEST_SHA='2ff2581fc1ff717439327688475dad7c35cc0c9065bd11dff66b50c88b2081f8'


def documents():
    manifest=load_pinned_json(ROOT/'paired-broker-manifest-enrollment-v1.json',MANIFEST_SHA)
    return [(item,load_pinned_json(ROOT/item['file'],item['sha256'])) for item in manifest['files']]


def result(step):
    return json.loads(step['response']['body'])


def body(request):
    return crypto.unb64url(request['body_b64']) if 'body_b64' in request else b''


def replay_join(document, *, approve=True, finalize=True):
    prefix=document['steps'][0]['input']
    trace=dict(profile=document['profile'],production_acceptable=document['production_acceptable'],
        org_id=document['org_id'],pinned_root=prefix['root'],records=prefix['records'])
    harness=PairedReplay(trace)
    for record in prefix['records']:
        actual=harness.run(record)
        if actual['status']!='accepted':
            raise AssertionError(actual)
        for field in ('head','authority_core','authority_core_sha256','epoch_sha256','snapshot','commitments','custody'):
            if actual[field]!=record['expected'][field]:
                raise AssertionError('prefix '+field+' differs')
    if not approve:
        if finalize:
            harness.replay.finish_history([],evidence=AuthorityEvidence(harness.rows,harness.blobs))
        return harness
    # Approval bytes and evidence are exported by cloud. They are not generated
    # or signed by this test and no authority checkpoint is installed.
    step=next(s for s in document['steps'] if s['id']=='certificate-and-wrap-committed-response-lost')
    approval=crypto.parse_canonical(body(step['input']['request']))
    for table,rows in step['post_state']['tables'].items():
        harness.rows[table]=decode(rows)
    harness.blobs['org_key_wraps']=approval['wraps']
    harness.blobs['broker_key_wraps']=approval['scoped_seals']
    entry=approval['entry'];raw=crypto.canonical_json(entry)
    evidence=AuthorityEvidence(harness.rows,harness.blobs)
    harness.replay.verify_record(PolicyRecord(raw,crypto.sha256(raw).hex(),crypto.unb64url(approval['sig']),step['received_at']),
        runtime=dict(mode='history',now=step['received_at'],observations=dict(heads=[],proposals={})),evidence=evidence)
    if finalize:
        harness.replay.finish_history([],evidence=evidence)
    return harness


class ProductionEnrollmentTests(unittest.TestCase):
    def test_manifest_every_step_profile_counts_and_recorded_refusals(self):
        self.assertEqual(crypto.sha256((ROOT/'PAIRED-BROKER.md').read_bytes()).hex(),
            '6a566ba577f3bf389e2e9e2e6a5c83641f037130a38724a7c244f18fa05fca10')
        total=refused=0
        for item,doc in documents():
            self.assertEqual(doc['profile'],'production')
            self.assertIs(doc['production_acceptable'],True)
            self.assertEqual(len(doc['steps']),item['records'])
            self.assertEqual(sum(s['response']['status']>=400 for s in doc['steps']),item['cases'])
            for step in doc['steps']:
                total+=1
                self.assertEqual(hash_object(step['post_state']['authority_core']),step['post_state']['authority_core_sha256'])
                wire_result=result(step)
                self.assertEqual(wire_result['ok'],step['response']['status']<400)
                if step['response']['status']>=400:
                    refused+=1
                    self.assertEqual(step['post_state'],step['predecessor'])
        self.assertEqual((total,refused),(39,13))

    def test_every_recorded_signed_transport_and_nonce_outcome(self):
        checked=0
        for item,doc in documents():
            public=crypto.export_point(crypto.import_private(doc['test_only_keys']['signing_jwk']).public_key())
            for step in doc['steps']:
                req=step['input'].get('request',{})
                if 'TW-Broker' not in req.get('headers',{}):
                    continue
                with self.subTest(file=item['file'],step=step['id']):
                    checked+=1
                    signed=SignedRequest(req['url'],req['method'],tuple(req['headers'].items()),body(req))
                    self.assertEqual(signed.forwarding(),{k:req[k] for k in ('url','method','headers','body_b64') if k in req})
                    self.assertEqual(urlsplit(req['url']).path,req['path'])
                    query=parse_qsl(urlsplit(req['url']).query,keep_blank_values=True)
                    self.assertEqual(crypto.canonical_query(query),req['canonical_query'])
                    # Nonce replay is a server ledger decision. Cryptographic
                    # admission still verifies those exact bytes independently.
                    expected_accept=step['response']['status']==200 or step['id']=='nonce-replay-refused'
                    if expected_accept:
                        verify_request(signed,doc['org_id'],req['headers']['TW-Broker'],public,step['received_at'])
                    else:
                        with self.assertRaises(ValueError):
                            verify_request(signed,doc['org_id'],req['headers']['TW-Broker'],public,step['received_at'])
                    if step['id']=='nonce-replay-refused':
                        nonce=req['headers']['TW-Nonce']
                        self.assertTrue(any(row['nonce']==nonce for row in step['predecessor']['tables']['seen_nonces']))
                    if step['response']['status']==200:
                        self.assertTrue(any(row['nonce']==req['headers']['TW-Nonce'] for row in step['post_state']['tables']['seen_nonces']))
        self.assertEqual(checked,17)

    def test_join_from_genesis_and_real_certificate_into_local_custody(self):
        doc=next(d for _,d in documents() if 'broker_local_sas' in d)
        harness=replay_join(doc)
        final=doc['steps'][-1]['post_state']
        self.assertEqual(harness.summary()['authority_core'],final['authority_core'])
        # Certificate enrollment adds a committed recipient wrap without an
        # epoch policy entry. Compare that separately authenticated addition.
        projected=epoch_checkpoint(harness.replay.epoch_state)
        projected['org_wraps'] += [{k:v for k,v in wrap.items() if k!='id'} for wrap in harness.blobs['org_key_wraps']]
        self.assertEqual(projected,final['epoch'])
        reserve=next(s for s in doc['steps'] if s['id']=='broker-enrollment-possession-proof')
        payload=crypto.parse_canonical(body(reserve['input']['request']))
        session=EnrollmentSession(doc['org_id'],payload['transcript'],crypto.import_private(doc['test_only_keys']['signing_jwk']),crypto.import_private(doc['test_only_keys']['kx_jwk']))
        session.accept_reservation(result(reserve)['result'])
        verify_proof(doc['org_id'],ticket_id(payload['ticket_code']),payload['transcript'],payload['proof'])
        temp=tempfile.TemporaryDirectory(prefix='tw-pr2-production-')
        self.addCleanup(temp.cleanup)
        store=Store(Path(temp.name)).open(create=True)
        self.addCleanup(store.close)
        store.initialize(TEST_PASSPHRASE,argon2=TEST_ARGON2)
        blk=crypto.random_key()
        save_reservation(session,store,blk,ticket_id(payload['ticket_code']),payload['proof'])
        sas=doc['broker_local_sas']
        self.assertEqual(crypto.sas_context(session.org,sas['org_root'],'broker',session.broker_id,session.transcript['sign_pub'],session.transcript['kx_pub']).hex(),sas['context_hex'])
        self.assertEqual(crypto.sas_words(bytes.fromhex(sas['context_hex'])),sas['words'])
        genesis=bytes.fromhex(doc['steps'][0]['input']['records'][0]['canonical_hex'])
        with self.assertRaises(ValueError):
            session.pin(store,genesis,typed_words='sas_matched')
        session.pin(store,genesis,typed_words=sas['words'])
        poll=result(doc['steps'][-1])['result']
        with self.assertRaises(ValueError):
            session.accept_poll(store,blk,replay_join(doc,approve=False).replay,poll)
        accepted=session.accept_poll(store,blk,harness.replay,poll)
        self.assertEqual(accepted['head'],final['authority_core']['head'])
        self.assertEqual(accepted['generation'],final['epoch']['generation'])
        self.assertEqual(accepted['generation'],poll['wraps'][0]['omk_generation'])
        self.assertEqual(accepted['generation'],final['epoch']['epochs'][-1]['generation'])
        omk=store.cloud_local_key(blk,org=session.org,broker=session.broker_id,key_id='omk_1',purpose='omk',scope='*',generation=1)
        self.assertEqual(omk.hex(),doc['test_only_keys']['wrapped_omk_hex'])
        self.assertEqual(store.connection.execute('SELECT state FROM cloud_enrollments').fetchone()[0],'complete')
        session.accept_poll(store,blk,harness.replay,poll)
        for bad in (dict(poll,cert_seq=3),dict(poll,wraps=[])):
            with self.assertRaises(ValueError):
                session.accept_poll(store,blk,harness.replay,bad)
        bad=copy.deepcopy(poll);bad['wraps'][0]['wrapped_omk']='00'*48
        with self.assertRaises(ValueError):
            session.accept_poll(store,blk,harness.replay,bad)
        # A pending poll cannot complete even when a wrap is otherwise valid.
        with self.assertRaises(ValueError):
            session.accept_poll(store,blk,harness.replay,dict(poll,state='pending'))
        self.assertEqual(store.connection.execute('SELECT count(*) FROM cloud_local_keys WHERE purpose="omk"').fetchone()[0],1)

    def test_recorded_adoption_two_proofs_genesis_and_closed_boundaries(self):
        from test_cloud_policy import cloud_authority_projection
        doc=next(d for item,d in documents() if 'adopt' in item['file'])
        reserve=doc['steps'][2]
        payload=crypto.parse_canonical(body(reserve['input']['request']))
        ticket=ticket_id(payload['ticket_code'])
        verify_proof(doc['org_id'],ticket,payload['transcript'],payload['proof'])
        session=EnrollmentSession(doc['org_id'],payload['transcript'],crypto.import_private(doc['test_only_keys']['signing_jwk']),crypto.import_private(doc['test_only_keys']['kx_jwk']))
        session.accept_reservation(result(reserve)['result'])
        accepted=doc['steps'][5]
        enrollment=accepted['input']['enrollment']
        root=enrollment['candidate_root']
        verify_proof(doc['org_id'],ticket,payload['transcript'],enrollment['root_proof'],root)
        with self.assertRaises(ValueError):
            verify_proof(doc['org_id'],ticket,payload['transcript'],payload['proof'],root)
        wrong=doc['steps'][3]['input']['enrollment']
        with self.assertRaises(ValueError):
            verify_proof(doc['org_id'],ticket,payload['transcript'],wrong['root_proof'],wrong['candidate_root'])
        batch=accepted['input']['input']['body']
        verifier=OfflineCloudVerifier(doc['org_id'],root,projects=batch['entries'][1]['entry']['body']['active_kek'])
        evidence=AuthorityEvidence(decode(accepted['post_state']['tables']))
        for signed in batch['entries']:
            raw=crypto.canonical_json(signed['entry'])
            verifier.verify_record(PolicyRecord(raw,crypto.sha256(raw).hex(),crypto.unb64url(signed['sig']),accepted['received_at']),
                stage=batch['stage'] if signed['entry']['kind']=='epoch_init' else None,
                runtime=dict(mode='history',now=accepted['received_at']),evidence=evidence)
        verifier.finish_history([],evidence=evidence)
        projected=cloud_authority_projection(verifier.state)
        projected['retired_recovery_points']=dict(sign_pub=[],kx_pub=[])
        self.assertEqual(projected,accepted['post_state']['authority_core'])
        self.assertEqual(epoch_checkpoint(verifier.epoch_state),accepted['post_state']['epoch'])
        self.assertEqual(result(doc['steps'][4])['code'],'E_LEGACY_ADOPTION')
        self.assertEqual(result(doc['steps'][6])['code'],'E_NOT_FOUND')
        self.assertEqual(verifier.state['certificates'],[])
        self.assertEqual(verifier.state['brokers'],[])
        temp=tempfile.TemporaryDirectory(prefix='tw-pr2-adopt-production-')
        self.addCleanup(temp.cleanup)
        store=Store(Path(temp.name)).open(create=True)
        self.addCleanup(store.close)
        # This disposable fixture store has no pre-existing keys to rebind.
        store.set_meta('store_id',doc['org_id'])
        blk=crypto.random_key()
        save_reservation(session,store,blk,ticket,payload['proof'])
        session.save_root_proof(store,ticket,root)
        from tw.cloud_enroll import load_reservation
        resumed=load_reservation(store,blk,doc['org_id'],ticket)
        with self.assertRaises(ValueError):
            resumed.root_proof(ticket,'a'*64)
        words=crypto.sas_words(crypto.sas_context(doc['org_id'],root,'broker',session.broker_id,session.transcript['sign_pub'],session.transcript['kx_pub']))
        resumed.pin(store,crypto.canonical_json(batch['entries'][0]['entry']),typed_words=words)
        with self.assertRaises(ValueError):
            resumed.accept_custody(store,blk,verifier,[])
        self.assertEqual(store.connection.execute('SELECT count(*) FROM cloud_local_keys WHERE purpose="omk"').fetchone()[0],0)

    def test_recorded_lost_response_retries_converge_and_body_rebinding_refuses(self):
        doc=next(d for _,d in documents() if 'broker_local_sas' in d)
        steps={s['id']:s for s in doc['steps']}
        first=steps['broker-enrollment-possession-proof']
        retry=steps['lost-enrollment-response-retry']
        self.assertEqual(first['input'],retry['input'])
        self.assertEqual(first['response'],retry['response'])
        first=steps['certificate-and-wrap-committed-response-lost']
        retry=steps['lost-approval-response-retry-same-uuid']
        self.assertEqual(first['input'],retry['input'])
        self.assertEqual(first['response'],retry['response'])
        self.assertEqual(first['post_state']['authority_core'],retry['post_state']['authority_core'])
        self.assertEqual(first['post_state']['tables']['receipts'],retry['post_state']['tables']['receipts'])
        changed=steps['same-uuid-different-body-refused']
        self.assertEqual(first['input']['request']['headers']['TW-Request-Id'],changed['input']['request']['headers']['TW-Request-Id'])
        self.assertNotEqual(body(first['input']['request']),body(changed['input']['request']))
        self.assertEqual(result(changed)['code'],'E_CONFLICT')
