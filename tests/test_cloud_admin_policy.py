"""W21 broker replay unit regressions with labelled TEST-ONLY signing keys."""
from copy import deepcopy
import unittest

from tw import crypto,cloud_wire as wire
from tw.cloud_public import PublicHistoryVerifier,PublicEvidence
from tw.cloud_admin_policy import apply
from tw.policy_log import policy_record,PolicyError
import test_cloud_policy as authority_tests


class AdminPolicyTests(unittest.TestCase):
    def setUp(self):
        self.unit=authority_tests.SignedAuthorityTraceTests()
        self.unit.setUp()
        self.evidence=PublicEvidence({},request_facts={})
        self.verifier=PublicHistoryVerifier(authority_tests.ORG,wire.hash_object(self.unit.genesis),projects=['a'])
        self.append(self.unit.genesis)
        bootstrap=dict(self.unit.genesis,seq=2,prev_hash=wire.hash_object(self.unit.genesis),kind='member_cert',
            body=dict(requested=dict(kind='member',certificate=self.unit.cert),request_id='bootstrap'))
        self.unit.prove(bootstrap,dict(member_id='owner'))
        self.append(bootstrap)

    def entry(self,kind,body):
        return dict(v=2,org_id=authority_tests.ORG,seq=self.verifier.head['seq']+1,prev_hash=self.verifier.head['hash'],
            ts=authority_tests.NOW,kind=kind,body=body,signer=dict(kind='member',id='owner',key='owner-key'))

    def append(self,entry,signature=None):
        signature=signature if signature is not None else crypto.p256_sign(self.unit.sign_key,crypto.policy_context(authority_tests.ORG,wire.hash_object(entry)))
        self.verifier.verify_record(policy_record(entry,signature,entry['ts']),evidence=self.evidence,
            runtime=dict(mode='history',now=entry['ts'],observations=dict(heads=[],proposals={})))

    def base(self):
        self.append(self.entry('project_put',dict(slug='a',change_policy='auto',no_shell=False,lead_principal=None)))
        self.append(self.entry('principal_add',dict(principal_id='lead:a',kind='lead',display='TEST-ONLY lead',project='a',parent_id=None,broker_id=None)))

    def grant(self,**updates):
        return dict(dict(grant_id='grt_test_only',principal_id='lead:a',pattern='a/key',ops=['inject','put'],
            max_class='standard',expires_at=None,reason='TEST-ONLY grant'),**updates)

    def test_signed_metadata_and_grant_projection(self):
        self.base()
        self.append(self.entry('grant_add',self.grant()))
        state=self.verifier.state['admin_policy']
        self.assertEqual(state['grants']['grt_test_only']['ops'],['inject','put'])
        self.append(self.entry('grant_revoke',dict(grant_id='grt_test_only')))
        self.assertTrue(self.verifier.state['admin_policy']['grants']['grt_test_only']['revoked'])
        self.append(self.entry('principal_disable',dict(principal_id='lead:a')))
        self.assertEqual(self.verifier.state['admin_policy']['principals']['lead:a']['state'],'disabled')

    def test_signed_project_members_secret_policy_and_placement(self):
        self.base()
        self.append(self.entry('project_member_put',dict(slug='a',member_id='owner',enabled=True)))
        self.append(self.entry('secret_create',dict(secret_id='test-only-secret',path='a/key',project='a',**{'class':'standard'})))
        self.append(self.entry('secret_update',dict(secret_id='test-only-secret',**{'class':'sensitive'},no_shell=True,allowed_hosts=['api.example.com'])))
        self.append(self.entry('placement_add',dict(placement_id='test-only-placement',secret_id='test-only-secret',sink_kind='manual',locator={'url':'https://api.example.com/','note':'TEST-ONLY'})))
        self.assertTrue(self.verifier.state['admin_policy']['project_members']['a']['owner'])
        self.assertTrue(self.verifier.epoch_state['secrets']['test-only-secret']['no_shell'])
        self.assertEqual(self.verifier.epoch_state['secrets']['test-only-secret']['allowed_hosts'],['api.example.com'])
        self.assertIn('test-only-placement',self.verifier.state['admin_policy']['placements'])
        self.append(self.entry('placement_rm',dict(placement_id='test-only-placement')))
        self.assertEqual(self.verifier.state['admin_policy']['placements']['test-only-placement']['state'],'removed')

    def test_forged_administration_signature_refuses(self):
        with self.assertRaisesRegex(PolicyError,'bad signature'):
            self.append(self.entry('project_put',dict(slug='a',change_policy='auto',no_shell=False,lead_principal=None)),bytes(64))

    def test_restricted_grant_requires_bound_passkey(self):
        self.base()
        with self.assertRaises(PolicyError):
            self.append(self.entry('grant_add',self.grant(max_class='restricted')))

    def test_role_client_disabled_expiry_and_unknown_target_refusals(self):
        self.base()
        base=self.verifier.state
        epoch=self.verifier.epoch_state
        cases=[('grant_add',self.grant(principal_id='unknown'),'unknown administration target'),
            ('grant_add',self.grant(expires_at='2025-01-01T00:00:00Z'),'already expired'),
            ('grant_add',self.grant(pattern='a/ke*'),'invalid direct grant pattern'),
            ('secret_update',dict(secret_id='unknown',**{'class':'standard'},no_shell=False,allowed_hosts=[]),'requires admin'),
            ('placement_add',dict(placement_id='p',secret_id='unknown',sink_kind='env',locator={}), 'invalid placement target')]
        for kind,body,reason in cases:
            state=deepcopy(base)
            with self.subTest(kind=kind,reason=reason),self.assertRaisesRegex(ValueError,reason):
                apply(self.entry(kind,body),state,deepcopy(epoch),projects=['a'],runtime=self.unit.runtime)
        for role in ('member','auditor','approver'):
            state=deepcopy(base);state['certificates'][0]['certificate']['role']=role
            with self.subTest(role=role),self.assertRaisesRegex(ValueError,'admin role'):
                apply(self.entry('project_put',dict(slug='a',change_policy='auto',no_shell=False,lead_principal=None)),state,epoch,projects=['a'],runtime=self.unit.runtime)
        state=deepcopy(base);state['admin_policy']['projects']['a']['change_policy']='client_approval_required'
        with self.assertRaisesRegex(ValueError,'client projects'):
            apply(self.entry('grant_add',self.grant()),state,epoch,projects=['a'],runtime=self.unit.runtime)
        state=deepcopy(base);state['admin_policy']['principals']['lead:a']['state']='disabled'
        with self.assertRaisesRegex(ValueError,'disabled grant'):
            apply(self.entry('grant_add',self.grant()),state,epoch,projects=['a'],runtime=self.unit.runtime)


    def test_administration_guard_negative_matrix(self):
        self.base();base=self.verifier.state;epochs=self.verifier.epoch_state
        owner=self.unit.cert['member_id']
        def check(kind,body,reason,change=lambda s,e:None):
            state=deepcopy(base);ep=deepcopy(epochs);change(state,ep)
            with self.assertRaisesRegex(ValueError,reason):
                apply(self.entry(kind,body),state,ep,projects=['a'],runtime=self.unit.runtime)
        cases=[
            ('principal_disable',{'principal_id':'bad|id'},'invalid administration identifier',lambda s,e:None),
            ('principal_add',dict(principal_id='new',kind='lead',display=None,project='unknown',parent_id=None,broker_id=None),'unknown administration project',lambda s,e:None),
            ('principal_add',dict(principal_id='new',kind='lead',display=None,project='a',parent_id=None,broker_id=None),'role or project denied',lambda s,e:s['certificates'][0]['certificate'].update(role='member')),
            ('project_put',dict(slug='a',change_policy='invalid',no_shell=False,lead_principal=None),'invalid project policy',lambda s,e:None),
            ('project_put',dict(slug='a',change_policy='client_approval_required',no_shell=False,lead_principal=None),'requires owner',lambda s,e:s['certificates'][0]['certificate'].update(role='admin')),
            ('project_member_put',dict(slug='a',member_id=owner,enabled='true'),'membership requires admin',lambda s,e:None),
            ('project_member_put',dict(slug='a',member_id='unknown',enabled=True),'unknown project member',lambda s,e:None),
            ('principal_add',dict(principal_id='lead:a',kind='lead',display=None,project='a',parent_id=None,broker_id=None),'identity already exists',lambda s,e:None),
            ('principal_add',dict(principal_id='new',kind='invalid',display=None,project='a',parent_id=None,broker_id=None),'invalid principal kind',lambda s,e:None),
            ('principal_add',dict(principal_id='new',kind='lead',display=None,project='a',parent_id=None,broker_id='unknown'),'uncertified principal broker',lambda s,e:None),
            ('grant_add',self.grant(),'grant identity already exists',lambda s,e:s['admin_policy']['grants'].update(grt_test_only=self.grant())),
            ('grant_add',self.grant(max_class='invalid'),'invalid direct grant class',lambda s,e:None),
            ('grant_add',self.grant(authz={},assertion={}),'schema',lambda s,e:None),
        ]
        for kind,body,reason,change in cases:
            with self.subTest(reason=reason):check(kind,body,reason,change)
        def managed_other(state,ep):
            state['certificates'][0]['certificate'].update(role='member')
            state['admin_policy']['project_members']['a']={owner:True}
            state['admin_policy']['principals']['lead:a']['project']='b'
        check('grant_add',self.grant(),'member grant exceeds',managed_other)
        def secret(state,ep):ep['secrets']['test-only']=dict(secret_id='test-only',path='a/key',project='a',**{'class':'standard'})
        check('secret_update',dict(secret_id='test-only',**{'class':'standard'},no_shell='true',allowed_hosts=[]),'invalid secret policy',secret)
        check('placement_add',dict(placement_id='p',secret_id='test-only',sink_kind='manual',locator='bad'),'invalid placement locator',secret)
        def placement(state,ep):state['admin_policy']['placements']['p']=dict(secret_id='unknown',state='active')
        check('placement_rm',dict(placement_id='p'),'unknown placement secret',placement)

    def restricted_proof(self,entry,request_id=None):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        grant=entry['body']['grant_id']
        authz=dict(v=2,dom='titanwarden.com/authz',org_id=authority_tests.ORG,
            actor=dict(member_id='owner',member_key_id='owner-key',credential_id=self.unit.cert['passkeys'][0]['credential_id']),
            op='grant_add',target=dict(grant_id=grant),core_change_sha256=wire.hash_object(crypto.policy_core_change(entry)),
            policy_head=dict(seq=entry['seq']-1,hash=entry['prev_hash']),request_id=grant if request_id is None else request_id,
            challenge=crypto.b64url(bytes([entry['seq']])*32),issued_at=authority_tests.NOW,expires_at='2026-01-01T00:02:00Z')
        client=crypto.canonical_json(dict(type='webauthn.get',challenge=crypto.b64url(crypto.sha256(crypto.canonical_json(authz))),origin='https://app.titanwarden.com'))
        auth=crypto.sha256(b'titanwarden.com')+bytes([5])+bytes(4)
        signature=self.unit.passkey.sign(auth+crypto.sha256(client),ec.ECDSA(hashes.SHA256()))
        entry['body'].update(authz=authz,assertion=dict(credential_id=authz['actor']['credential_id'],clientDataJSON=crypto.b64url(client),
            authenticatorData=crypto.b64url(auth),signature=crypto.b64url(signature)))

    def test_restricted_grant_uses_grant_id_without_body_request_id(self):
        self.base();entry=self.entry('grant_add',self.grant(max_class='restricted'))
        self.restricted_proof(entry);self.assertNotIn('request_id',entry['body'])
        self.append(entry)
        self.assertEqual(self.verifier.state['admin_policy']['grants']['grt_test_only']['max_class'],'restricted')

    def test_restricted_grant_rejects_valid_passkey_over_wrong_request_id(self):
        self.base();entry=self.entry('grant_add',self.grant(max_class='restricted'))
        self.restricted_proof(entry,request_id='different-grant')
        with self.assertRaisesRegex(PolicyError,'Authorization binding'):
            self.append(entry)


    def test_admin_can_keep_client_policy_while_changing_metadata(self):
        self.base();state=self.verifier.state
        state['admin_policy']['projects']['a']['change_policy']='client_approval_required'
        state['certificates'][0]['certificate']['role']='admin'
        body=dict(slug='a',change_policy='client_approval_required',no_shell=True,lead_principal=None)
        result=apply(self.entry('project_put',body),state,self.verifier.epoch_state,projects=['a'],runtime=self.unit.runtime)
        self.assertTrue(result['admin_policy']['projects']['a']['no_shell'])
        with self.assertRaisesRegex(ValueError,'requires owner'):
            apply(self.entry('project_put',dict(body,change_policy='auto')),state,self.verifier.epoch_state,projects=['a'],runtime=self.unit.runtime)


    def test_w21_parser_and_transition_boundaries(self):
        from tw.cloud_admin_policy import slug,locator
        with self.assertRaisesRegex(ValueError,'project slug'):slug('BadProject')
        for kind,value,reason in [
            ('railway_var',dict(project='not-uuid',environment='not-uuid',service='not-uuid',var='TOKEN'),'explicit UUIDs'),
            ('github_secret',dict(repo='bad-repo',name='TOKEN'),'repository'),
            ('manual',dict(url='http://api.example.com',note='TEST-ONLY'),'console URL'),
        ]:
            with self.subTest(reason=reason),self.assertRaisesRegex(ValueError,reason):locator(kind,value)
        self.base();base=self.verifier.state;epochs=self.verifier.epoch_state
        def check(kind,body,reason,change=lambda s,e:None):
            state=deepcopy(base);ep=deepcopy(epochs);change(state,ep)
            with self.assertRaisesRegex(ValueError,reason):
                apply(self.entry(kind,body),state,ep,projects=['a'],runtime=self.unit.runtime)
        owner=self.unit.cert['member_id']
        for kind,body,reason,change in [
            ('project_put',dict(slug='b',change_policy='auto',no_shell=False,lead_principal='lead:a'),'lead project mismatch',lambda s,e:None),
            ('project_member_put',dict(slug='a',member_id=owner,enabled=False),'membership absent',lambda s,e:None),
            ('principal_add',dict(principal_id='new',kind='lead',display=None,project='a',parent_id='lead:a',broker_id=None),'parent project mismatch',lambda s,e:s['admin_policy']['principals']['lead:a'].update(project='b')),
            ('principal_disable',dict(principal_id='lead:a'),'already disabled',lambda s,e:s['admin_policy']['principals']['lead:a'].update(state='disabled')),
            ('grant_add',self.grant(ops=['put','inject']),'must be sorted',lambda s,e:None),
            ('grant_add',self.grant(authz={}), 'incomplete direct grant authorization',lambda s,e:None),
            ('grant_add',self.grant(),'target class mismatch',lambda s,e:e['secrets'].update(s=dict(path='a/key',project='a',**{'class':'restricted'}))),
        ]:
            with self.subTest(reason=reason):check(kind,body,reason,change)
        def revocation(state,ep):
            state['admin_policy']['grants']['g']=dict(self.grant(),revoked=False)
            state['certificates'][0]['certificate'].update(role='member')
            state['admin_policy']['project_members']['a']={owner:True}
            state['admin_policy']['principals']['lead:a']['project']='b'
        check('grant_revoke',dict(grant_id='g'),'member revocation exceeds',revocation)
        body=dict(placement_id='new',secret_id='secret',sink_kind='manual',locator=dict(url='https://api.example.com/',note='TEST-ONLY'))
        def duplicate(state,ep):
            ep['secrets']['secret']=dict(secret_id='secret',path='a/key',project='a',**{'class':'standard'})
            state['admin_policy']['placements']['old']=dict(body,placement_id='old',state='active')
        check('placement_add',body,'duplicate placement destination',duplicate)
        def member(state,ep):
            ep['secrets']['secret']=dict(secret_id='secret',path='a/key',project='a',**{'class':'restricted'},allowed_hosts=[])
            state['certificates'][0]['certificate'].update(role='member')
            state['admin_policy']['project_members']['a']={owner:True}
        check('placement_add',body,'member placement exceeds',member)

    def test_first_project_predecessor_and_trigger_provenance(self):
        from admin_cloud_fixtures import document,Replay
        from tw.cloud_public import PublicEpochReplay
        data=document();history=Replay(data)
        for row in data['records'][:4]:history.append(row)
        entry=data['records'][4]['entry'];snapshot=history.replay.epoch_view().snapshot
        checker=PublicEpochReplay();state=history.replay.epoch_state
        change=entry['body']['projects']['cutover']
        self.assertTrue(checker._first_project(state,entry,snapshot,'cutover',change))
        self.assertFalse(checker._first_project(state,entry,snapshot,'cutover',dict(change,from_kek_id='existing-key')))
        mixed=deepcopy(entry)
        prior=next(iter(state['active_kek']))
        mixed['body']['projects'][prior]=dict(from_kek_id=state['active_kek'][prior],to_kek_id='TEST-ONLY-new-key')
        with self.assertRaisesRegex(ValueError,'first project KEK predecessor'):
            checker._first_project(state,mixed,snapshot,'cutover',change)
        invalid=deepcopy(snapshot);invalid['project_creations']={}
        with self.assertRaisesRegex(ValueError,'first project KEK predecessor'):
            checker._first_project(state,entry,invalid,'cutover',change)
        state['used_triggers'].append(entry['body']['trigger_seq'])
        with self.assertRaisesRegex(ValueError,'first project KEK trigger'):
            checker._trigger(state,entry,snapshot,['cutover'])


    def test_locator_names_only_shared_grammar(self):
        from tw.cloud_admin_policy import locator
        for kind,value,reason in [
            ('github_secret',dict(repo='bad?/repo',name='TOKEN'),'opaque locator segment'),
            ('github_secret',dict(repo='owner/repo',name='TOKEN-WITH-DASH'),'locator variable name'),
            ('cloudflare_secret',dict(account_id='invalid',script='worker',name='TOKEN'),'cloudflare account'),
            ('manual',dict(url='https://api.example.com/path/1234',note='TEST-ONLY'),'manual console path'),
            ('manual',dict(url='https://api.example.com/',note='token=TEST_ONLY'),'manual console note'),
        ]:
            with self.subTest(reason=reason),self.assertRaisesRegex(ValueError,reason):locator(kind,value)
        self.assertEqual(locator('manual',dict(url='https://api.example.com/dashboard',note='Reviewed console')).get('note'),'Reviewed console')


class PublicRequestBoundaryTests(unittest.TestCase):
    def setUp(self):
        from cloud_fixtures import fixture
        from tw import cloud_policy
        self.cert=deepcopy(fixture('control/vectors/authority-v1.json')['founder_vectors'][0]['certificate'])
        self.state=cloud_policy.empty_authority(self.cert['org_id'])
        self.state['head']=dict(seq=2,hash='1'*64)
        self.state['certificates']=[dict(seq=2,certificate=self.cert)]
        self.now='2026-01-01T00:00:00.000Z'
        self.runtime=dict(mode='history',now=self.now,received_at=self.now,observations=dict(heads=[],proposals={}))
        self.request=dict(request_id='req_aaaaaaaaaaaa',principal_id='lead:a',token_id='unverifiable-remote-token',kind='access',
            target='a/key',ops=['inject'],reason='TEST-ONLY request',ttl_seconds=300)
        self.grant=dict(principal_id='lead:a',pattern='a/key',ops=['inject'],max_class='standard',expires_at='2026-01-01T00:04:00.000Z')
        self.body=dict(request_id=self.request['request_id'],decision='approve',reason='TEST-ONLY signed grant',
            grant=self.grant,request=self.request,client_approval_ref=None)

    def checker(self):
        from tw.cloud_public import PublicRequestReplay
        checker=PublicRequestReplay()
        checker.targets={'s':dict(secret_id='s',path='a/key',project='a',**{'class':'standard'})}
        return checker

    def entry(self,kind='request_decide',body=None):
        return dict(v=2,org_id=self.cert['org_id'],seq=3,prev_hash='1'*64,ts=self.now,kind=kind,
            body=deepcopy(self.body if body is None else body),signer=dict(kind='member',id=self.cert['member_id'],key=self.cert['member_key_id']))

    def test_unverifiable_token_open_never_authorizes_delivery(self):
        checker=self.checker()
        entry=self.entry('request_open',dict(request=self.request,default_at='2026-01-01T00:01:00.000Z'))
        checker.apply(entry,self.state,{},self.runtime)
        self.assertEqual(checker.grants,{})
        self.assertEqual(checker.requests[self.request['request_id']]['request']['token_id'],'unverifiable-remote-token')
        default=self.entry('request_default',dict(request_id=self.request['request_id']))
        default.update(signer=dict(kind='derived'),ts='2026-01-01T00:01:01.000Z')
        checker.apply(default,self.state,{},self.runtime)
        self.assertEqual(checker.grants,{})
        checker=self.checker();checker.apply(self.entry(),self.state,{},self.runtime)
        self.assertEqual(checker.grants['grt_aaaaaaaaaaaa'],self.grant)

    def test_request_and_signed_grant_refusals(self):
        cases=[
            (lambda c,e,s:e.update(seq=4),'predecessor'),
            (lambda c,e,s:e['body'].update(decision='unknown'),'invalid public decision'),
            (lambda c,e,s:c.requests.update(req_aaaaaaaaaaaa=dict(state='approved')),'already terminal'),
            (lambda c,e,s:e['body'].update(request_id='req_bbbbbbbbbbbb'),'restatement differs'),
            (lambda c,e,s:s['certificates'][0]['certificate'].update(role='auditor'),'admin role'),
            (lambda c,e,s:e['body']['request'].update(principal_id=self.cert['member_id']),'self approval'),
            (lambda c,e,s:c.targets.clear(),'unknown public grant target'),
            (lambda c,e,s:e['body'].update(decision='deny'),'denial contains grant'),
            (lambda c,e,s:e['body']['grant'].update(ops=['put']),'exceeds signed request'),
            (lambda c,e,s:c.grants.update(grt_aaaaaaaaaaaa=self.grant),'duplicate public grant'),
        ]
        for change,reason in cases:
            checker=self.checker();entry=self.entry();state=deepcopy(self.state);change(checker,entry,state)
            with self.subTest(reason=reason),self.assertRaisesRegex((ValueError,PolicyError),reason):
                checker.apply(entry,state,{},self.runtime)

    def test_open_and_default_refusals(self):
        for change,reason in [
            (lambda c,e:c.requests.update(req_aaaaaaaaaaaa=dict(state='open')),'duplicate public request'),
            (lambda c,e:e.update(signer=dict(kind='derived')),'signer outside scope'),
            (lambda c,e:e['body'].update(default_at='2025-01-01T00:00:00.000Z'),'deadline differs'),
        ]:
            checker=self.checker();entry=self.entry('request_open',dict(request=self.request,default_at=None));change(checker,entry)
            with self.subTest(reason=reason),self.assertRaisesRegex((ValueError,PolicyError),reason):
                checker.apply(entry,self.state,{},self.runtime)
        checker=self.checker()
        with self.assertRaisesRegex((ValueError,PolicyError),'default deadline'):
            checker.apply(self.entry('request_default',dict(request_id=self.request['request_id'])),self.state,{},self.runtime)


    def test_client_policy_requires_passkey_and_client_reference(self):
        from unittest.mock import patch
        checker=self.checker();state=deepcopy(self.state)
        state['admin_policy']=dict(projects={'a':dict(change_policy='client_approval_required')})
        protected=self.entry();protected['body']['client_approval_ref']='TEST-ONLY reviewed client approval'
        with self.assertRaises(PolicyError):checker.apply(protected,state,{},self.runtime)
        with patch.object(wire,'verify_authorization',return_value='TEST-ONLY challenge'):
            with self.assertRaises(PolicyError):self.checker().apply(self.entry(),state,{},self.runtime)
            checker=self.checker();checker.apply(protected,state,{},self.runtime)
            self.assertEqual(checker.grants['grt_aaaaaaaaaaaa'],self.grant)
        entry=self.entry();entry['body']['client_approval_ref']='unexpected reference'
        with self.assertRaisesRegex(PolicyError,'unexpected public client'):
            self.checker().apply(entry,self.state,{},self.runtime)


class AdminProductionFixtureTests(unittest.TestCase):
    def test_all_22_live_signed_records_and_13_negatives(self):
        from admin_cloud_fixtures import document,Replay
        from tw.cloud_epochs import epoch_checkpoint
        data=document();replay=Replay(data)
        for row in data['records']:
            with self.subTest(id=row['id']):
                replay.append(row)
                self.assertEqual(replay.replay.head,row['expected']['head'])
                self.assertEqual(replay.authority(),row['expected']['authority_core'])
                self.assertEqual(wire.hash_object(replay.authority()),row['expected']['authority_core_sha256'])
                self.assertEqual(wire.hash_object(epoch_checkpoint(replay.replay.epoch_state)),row['expected']['epoch_sha256'])
        self.assertEqual(len(data['records']),22)
        self.assertEqual(replay.replay.head,data['finalize_expected']['head'])
        for case in data['cases']:
            candidate=Replay(data)
            for row in data['records'][:case['prefix_length']]:candidate.append(row)
            before=candidate.replay.state
            with self.subTest(id=case['id']),self.assertRaises(PolicyError) as caught:
                candidate.append(case['record'])
            self.assertEqual(caught.exception.code,case['record']['expected']['code'])
            reasons={'first-key-nonnull-predecessor':'Project predecessor mismatch','unknown-project':'unknown administration project',
                'duplicate-id':'principal identity already exists','absent-grant-revoke':'unknown administration target','stale-prev-hash':'chain mismatch',
                'duplicate-grant-id':'grant identity already exists','restricted-grant-without-passkey':'schema','placement-remove-twice':'placement is not active',
                'revoke-grant-twice':'direct grant is not live','grant-disabled-principal':'disabled grant principal','wrong-role':'admin role',
                'revoked-signer':'Inactive member signer','client-direct-grant-refused':'client projects require request decisions'}
            self.assertRegex(str(caught.exception),reasons[case['id']])
            self.assertEqual(candidate.replay.state,before)
        self.assertEqual(len(data['cases']),13)

    def test_all_signed_access_projection_fields_match_cloud(self):
        from admin_cloud_fixtures import document,Replay
        data=document();replay=Replay(data)
        for row in data['records']:replay.append(row)
        policy=replay.replay.state['admin_policy'];expected=data['admin_projection']
        self.assertEqual(set(policy['projects']),{row['slug'] for row in expected['projects']})
        for row in expected['projects']:
            actual=policy['projects'][row['slug']]
            self.assertEqual((actual['change_policy'],bool(actual['no_shell']),actual['lead_principal']),
                (row['change_policy'],bool(row['no_shell']),row.get('lead_principal')))
        signed_principals={row['entry']['body']['principal_id'] for row in data['records'] if row['entry']['kind']=='principal_add'}
        self.assertEqual(set(policy['principals']),signed_principals)
        for row in expected['principals']:
            if row['principal_id'] not in signed_principals:
                self.assertNotIn(row['principal_id'],policy['principals'])
                continue
            actual=policy['principals'][row['principal_id']]
            self.assertEqual(actual,{k:row[k] for k in actual})
        self.assertEqual(set(policy['grants']),{row['grant_id'] for row in expected['grants']})
        for row in expected['grants']:
            import json
            actual=policy['grants'][row['grant_id']]
            self.assertEqual(actual['ops'],json.loads(row['ops']))
            self.assertEqual(actual['max_class'],json.loads(row['conditions_json'])['max_class'])
            self.assertEqual(actual['revoked'],row['revoked_at'] is not None)
            for field in ('principal_id','pattern','expires_at','reason'):self.assertEqual(actual[field],row[field])
        for row in expected['placements']:
            actual=policy['placements'][row['placement_id']]
            self.assertEqual(actual['locator'],json.loads(row['locator_json']))
            for field in ('secret_id','sink_kind','state'):self.assertEqual(actual[field],row[field])
        for row in expected['secrets']:
            actual=replay.replay.epoch_state['secrets'][row['secret_id']]
            self.assertEqual(actual['allowed_hosts'],json.loads(row['allowed_hosts_json']))
            self.assertEqual((actual['class'],actual['no_shell']),(row['class'],bool(row['no_shell'])))
        self.assertEqual([member for rows in policy['project_members'].values() for member,enabled in rows.items() if enabled],[])

    def test_every_fixture_record_is_bound_to_its_real_live_admission(self):
        import json
        from admin_cloud_fixtures import document
        data=document();steps={step['id']:step for step in data['live_steps']}
        self.assertEqual(data['initial_projects'],[])
        for row in data['records']:
            admission=row['admission'];self.assertEqual(admission['mode'],'live')
            step=steps[admission['step_id']]
            self.assertEqual(step['input']['request']['url'],admission['route'])
            self.assertTrue(200<=step['response']['status']<300)
            body=crypto.parse_canonical(crypto.unb64url(step['input']['request']['body_b64']))
            submitted=body.get('entries',[body])
            signed=next(item for item in submitted if item.get('entry',item)==row['entry'])
            self.assertEqual(crypto.canonical_json(signed.get('entry',signed)).hex(),row['canonical_hex'])
            self.assertEqual(signed['sig'],row['sig'])
            self.assertGreaterEqual(step['after']['head']['seq'],row['entry']['seq'])
        for case in data['cases']:
            self.assertEqual(case['control']['history']['code'],case['record']['expected']['code'])
            self.assertEqual(case['control']['history']['reason'],case['record']['expected']['message'])
            step=steps[case['admission_step']]
            self.assertEqual(step['response']['status'],case['control']['live']['status'])
            self.assertEqual(json.loads(step['response']['body'])['code'],case['control']['live']['code'])
