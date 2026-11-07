"""Public broker mode against real, immutable cloud handler responses."""
from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from tw import crypto,cloud_wire as wire
from tw.cloud_public import decode_evidence,PublicHistoryVerifier,commitment_stage
from tw.policy_log import policy_record,PolicyError
from evidence_cloud_fixtures import document,records


class PublicHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc=document()
        cls.rows=records(cls.doc)
        cls.cases={case['id']:case for scenario in cls.doc['scenarios'] for case in scenario['cases']}

    def page(self,name='full-first-page'):
        return json.loads(self.cases[name]['response']['body'])['result']

    def bundle(self,page=None,rows=None):
        page=self.page() if page is None else page
        return decode_evidence([page],self.rows if rows is None else rows,org=self.doc['org_id'],broker=page['broker_id'])

    def replay(self,bundle):
        verifier=PublicHistoryVerifier(self.doc['org_id'],self.rows[0]['hash'],projects=['a','b'])
        for seq,(entry,sig) in bundle['records'].items():
            verifier.verify_record(policy_record(entry,None if sig is None else crypto.unb64url(sig),entry['ts']),
                stage=bundle['stages'].get(seq),evidence=bundle['evidence'],runtime=dict(mode='history',now=entry['ts'],observations=dict(heads=[],proposals={})))
        return verifier

    def test_full_and_scoped_real_handler_replay(self):
        for name in ('full-first-page','scoped-first-page'):
            page=self.page(name);bundle=self.bundle(page);verifier=self.replay(bundle)
            verifier.finish_history([],evidence=bundle['evidence'],broker_id=page['broker_id'])
            self.assertEqual(verifier.head,page['head'])
            self.assertEqual(verifier.export_checkpoint()['ciphertext_scope'],page['scope'])
            for own in page['own_payloads']:
                self.assertTrue(all(w['recipient_id']==page['broker_id'] for w in own['wraps']))
                self.assertTrue(all(w['broker_id']==page['broker_id'] for w in own['scoped_seals']))
                if name=='scoped-first-page':
                    self.assertEqual(own['keyring'],[])
                    self.assertEqual(own['wraps'],[])

    def test_cloud_supplied_client_negatives(self):
        reasons={'commitment-mismatch':'commitment mismatch','swapped-own-wrap':'Substituted wrap',
            'another-recipient-wrap-present':'another recipient','page-mixes-heads':'incomplete policy'}
        for case in self.doc['client_refusals']:
            with self.subTest(id=case['id']),self.assertRaisesRegex((ValueError,PolicyError),reasons[case['id']]):
                self.bundle(case['response']['result'])

    def test_cloud_transport_refusals_are_not_authority(self):
        from tw.cloud_http import decode_response,CloudResponseError
        for name,case in self.cases.items():
            if case['response']['status']>=400:
                with self.subTest(name=name),self.assertRaises(CloudResponseError):
                    decode_response(case['response']['status'],case['response']['body'].encode())

    def test_forged_signature_still_refuses_public_mode(self):
        rows=deepcopy(self.rows);rows[-1]['sig']=crypto.b64url(bytes(64))
        with self.assertRaisesRegex(PolicyError,'bad signature'):
            self.replay(self.bundle(rows=rows))

    def test_valid_broker_signature_cannot_sign_member_administration(self):
        from tw.cloud_policy import AuthorityView
        bundle=self.bundle();verifier=self.replay(bundle)
        previous=next(e for e,sig in bundle['records'].values() if e['kind']=='broker_cert')
        entry=deepcopy(previous)
        entry.update(seq=verifier.head['seq']+1,prev_hash=verifier.head['hash'],signer=dict(kind='broker',id=self.page()['broker_id']))
        key=crypto.import_private(self.doc['test_only_keys']['signing_jwk'])
        signature=crypto.p256_sign(key,crypto.policy_context(self.doc['org_id'],wire.hash_object(entry)))
        with self.assertRaisesRegex(PolicyError,'Member signer required'):
            verifier.verify_record(policy_record(entry,signature,entry['ts']),evidence=bundle['evidence'])

    def test_public_page_guards(self):
        mutations=[('schema','bad','page binding'),('org_id','b'*32,'page binding'),('broker_id','foreign','page binding'),
            ('scope',['b'],'another recipient'),('from_seq',2,'page binding'),('through_seq',99,'pagination'),
            ('next_from_seq',2,'pagination'),('tables',{},'table allowlist')]
        for field,value,reason in mutations:
            page=self.page();page[field]=value
            with self.subTest(field=field),self.assertRaises((ValueError,PolicyError)):
                decode_evidence([page],self.rows,org=self.doc['org_id'],broker=self.page()['broker_id'])
        page=self.page();page['tables']['enrollment_records'][0]['unexpected']=True
        with self.assertRaisesRegex(ValueError,'schema'):
            self.bundle(page)

    def test_missing_or_swapped_own_keyring_refuses(self):
        for mode in ('missing','swapped'):
            page=self.page()
            if mode=='missing':
                page['own_payloads'][-1]['keyring']=[]
                reason='missing own encrypted keyring'
            else:
                page['own_payloads'][-1]['keyring'][0]['wrapped_key']='00'*48
                reason='own keyring digest'
            with self.subTest(mode=mode),self.assertRaisesRegex((ValueError,PolicyError),reason):
                self.bundle(page)

    def test_public_scope_is_checked_against_verified_certificate(self):
        bundle=self.bundle();verifier=self.replay(bundle)
        bundle['evidence'].expected_scope=['b']
        with self.assertRaisesRegex(ValueError,'scope differs'):
            verifier.finish_history([],evidence=bundle['evidence'],broker_id=self.page()['broker_id'])

    def test_stage_boundary_negative_matrix(self):
        def check(change,reason,*,scoped=False):
            page=self.page('scoped-first-page' if scoped else 'full-first-page')
            public,own=page['public_staging'][-1],page['own_payloads'][-1]
            entry=deepcopy(self.bundle(page)['records'][public['policy_seq']][0])
            change(public,own,entry)
            with self.assertRaisesRegex((ValueError,PolicyError),reason):
                commitment_stage(public,own,entry,broker=page['broker_id'],scope=page['scope'])
        checks=[
            (lambda p,o,e:o.update(policy_seq=1),'stage position'),
            (lambda p,o,e:o.update(plan_id='wrong'),'stage identity'),
            (lambda p,o,e:o.update(wraps={}),'stage arrays'),
            (lambda p,o,e:(p['keyring'].append(deepcopy(p['keyring'][0])),e['body']['keyring'].append(deepcopy(e['body']['keyring'][0]))),'duplicate public key'),
            (lambda p,o,e:p['keyring_metadata'][0].update(project='wrong'),'public key metadata'),
            (lambda p,o,e:p['keyring_metadata'].pop(),'incomplete public key'),
            (lambda p,o,e:o['wraps'][0].update(omk_generation=999),'own wrap commitment'),
            (lambda p,o,e:o.update(wraps=[]),'missing own committed wrap'),
            (lambda p,o,e:(p['scoped_seals'].append(dict(broker_id='foreign',key_id='unknown',project='a',wrap_digest='0'*64)),e['body']['scoped_seals'].append(dict(broker_id='foreign',key_id='unknown',project='a',wrap_digest='0'*64))),'seal key metadata'),
        ]
        for change,reason in checks:
            with self.subTest(reason=reason):check(change,reason)
        for change,reason in [
            (lambda p,o,e:o.update(keyring=[deepcopy(self.page()['own_payloads'][-1]['keyring'][0])]),'scoped broker received'),
            (lambda p,o,e:o['scoped_seals'][0].update(broker_id='foreign'),'another recipient seal'),
            (lambda p,o,e:o['scoped_seals'][0].update(purpose='fingerprint'),'own seal commitment'),
            (lambda p,o,e:o.update(scoped_seals=[]),'missing own committed seal'),
        ]:
            with self.subTest(reason=reason):check(change,reason,scoped=True)

    def test_finalization_certificate_and_initial_commitment_guards(self):
        for change,reason in [
            (lambda b:b['evidence']._rows.update(initial_member_slot_commitments=[]),'initial slot commitment'),
            (lambda b:b['evidence']._rows['initial_member_slot_commitments'][0]['reference'].update(policy_seq=99),'initial slot reference position'),
        ]:
            bundle=self.bundle();verifier=self.replay(bundle);change(bundle)
            with self.subTest(reason=reason),self.assertRaisesRegex(ValueError,reason):
                verifier.finish_history([],evidence=bundle['evidence'],broker_id=self.page()['broker_id'])
        bundle=self.bundle();verifier=self.replay(bundle)
        with self.assertRaisesRegex(ValueError,'certified public history broker'):
            verifier.finish_history([],evidence=bundle['evidence'],broker_id='unknown')
        with self.assertRaisesRegex(ValueError,'public history evidence'):
            verifier.finish_history([],evidence=None,broker_id=self.page()['broker_id'])

    def test_policy_evidence_negative_matrix(self):
        def reject(change,reason):
            page=self.page();rows=deepcopy(self.rows)
            change(page,rows)
            with self.assertRaisesRegex((ValueError,PolicyError),reason):
                self.bundle(page,rows)
        for change,reason in [
            (lambda p,r:r.clear(),'^complete policy and evidence required$'),
            (lambda p,r:p.update(scope=[]),'invalid evidence scope'),
            (lambda p,r:r[0].update(kind='wrong'),'policy row commitment'),
            (lambda p,r:r.pop(),'incomplete policy'),
            (lambda p,r:p.update(through_seq=99),'pagination incomplete'),
            (lambda p,r:p.update(public_staging={}), 'stage array'),
            (lambda p,r:p['public_staging'][0].update(policy_seq=99),'stage position'),
            (lambda p,r:p['own_payloads'].pop(),'own payload missing'),
        ]:
            with self.subTest(reason=reason):reject(change,reason)

    def test_unrelated_and_incomplete_paginated_stage_refusals(self):
        page=self.page()
        page['public_staging'][-1]['policy_seq']=4
        page['own_payloads'][-1]['policy_seq']=4
        with self.assertRaisesRegex(ValueError,'unrelated public stage'):self.bundle(page)
        page=self.page();rows=deepcopy(self.rows)
        entry=crypto.parse_canonical(rows[-1]['entry_json'].encode())
        entry['body'].update(recipients_count=len(entry['body']['recipients'])+1,recipients_sha256='0'*64)
        rows[-1].update(entry_json=crypto.canonical_json(entry).decode(),hash=wire.hash_object(entry))
        page['head']['hash']=rows[-1]['hash']
        key=crypto.import_private(self.doc['test_only_keys']['signing_jwk'])
        rows[-1]['sig']=crypto.b64url(crypto.p256_sign(key,crypto.policy_context(self.doc['org_id'],rows[-1]['hash'])))
        with self.assertRaisesRegex(ValueError,'public recipient commitment'):self.bundle(page,rows)


class PublicPrivateBoundaryTests(unittest.TestCase):
    def test_member_confirmation_public_commitment_boundaries(self):
        from cloud_fixtures import fixture
        from tw.cloud_public import PublicEvidence
        from tw.cloud_policy import empty_authority
        data=fixture('control/src/genesis/vectors.json')
        cert=data['certificate'];entry=data['confirmation']['signed']['entry']
        pending=dict(member_id=cert['member_id'],transcript_json=crypto.canonical_json(data['accept']['payload']).decode(),proof=data['accept']['proof'])
        state=empty_authority(data['org_id'])
        evidence=PublicEvidence(dict(genesis_acceptances=[pending]))
        evidence.verify_member_confirmation_wrap(entry,cert,state,lambda head:dict(kind='committed',generation=1))
        wrong=deepcopy(entry);wrong['kind']='cert_proposal'
        with self.assertRaisesRegex(ValueError,'confirmation differs'):
            evidence.verify_member_confirmation_wrap(wrong,cert,state,lambda head:dict(kind='committed',generation=1))
        with self.assertRaisesRegex(ValueError,'generation differs'):
            evidence.verify_member_confirmation_wrap(entry,cert,state,lambda head:dict(kind='committed',generation=2))
        nonholder=deepcopy(cert);nonholder.update(role='member',key_holder=False,reveal=False,passkeys=[])
        accepted=deepcopy(data['accept']['payload']);accepted['member_key']=nonholder
        with patch.object(wire,'verify_member_accept',return_value=accepted),self.assertRaisesRegex(ValueError,'nonholder carries wrap'):
            evidence.verify_member_confirmation_wrap(entry,nonholder,state,lambda head:dict(kind='committed',generation=1))

    def test_outside_scope_signed_version_commitment_checks(self):
        from cloud_runtime_fake import FakeCloud,ORG,BROKER,NOW
        from tw.cloud_public import PublicEpochReplay
        fake=FakeCloud();self.addCleanup(fake.close)
        state=fake.h.verifier.epoch_state
        state['secrets']['test-only']=dict(secret_id='test-only',path='a/key',project='a',**{'class':'standard'})
        snapshot=fake.h.verifier.authority_view().epoch_snapshot(fake.h.verifier.head,['a','b'])
        body=dict(version_id='test-only-v1',secret_id='test-only',version_no=1,state='active',kek_id='ka',fingerprint='0'*64,
            length=32,source='TEST-ONLY',value_digest='1'*64,envelope_digest='2'*64)
        entry=fake.h.entry('version_add',body)
        checker=PublicEpochReplay();checker._state=deepcopy(state)
        checker.apply(entry,snapshot,mode='history')
        self.assertEqual(checker.state['versions'][0]['value_digest'],'1'*64)
        for field,value,reason in [('secret_id','unknown','invalid public version'),('kek_id','unknown','stale KEK'),
            ('version_no',2,'identity differs'),('length',1048577,'length differs')]:
            checker=PublicEpochReplay();checker._state=deepcopy(state)
            bad=deepcopy(entry);bad['body'][field]=value
            with self.subTest(field=field):
                with self.assertRaises(PolicyError) as caught:
                    checker.apply(bad,snapshot,mode='history')
                self.assertRegex(str(caught.exception.__cause__),reason)
