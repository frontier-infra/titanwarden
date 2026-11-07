"""Production boundary tests, using TEST-ONLY values and isolated temporary stores."""
import io
import os
import socket
import tempfile
import unittest
from unittest.mock import Mock, patch

from tw import admin, cli, crypto, cloud_wire as wire
from tw.admin_server import AdminService, AdminSession
from tw.cloud_http import HTTPSTransport, SignedRequest, MAX_BODY, public_origin
from tw.protocol import failure, recv_frame, send_frame
from tw.seal import SealManager
from tw.store import Store, StoreError
from support import TEST_PASSPHRASE, TEST_ARGON2


class CloudInitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name).open(create=True)
        self.addCleanup(self.store.close)

    def test_no_recovery_is_generated_or_stored(self):
        with patch.object(crypto, 'recovery_key', side_effect=AssertionError('recovery forbidden')):
            master, recovery = self.store.initialize(TEST_PASSPHRASE, argon2=TEST_ARGON2, cloud_broker=True)
        self.assertEqual(recovery, '')
        self.assertEqual(self.store.unlock_passphrase(TEST_PASSPHRASE), master)
        self.assertEqual([r[0] for r in self.store.connection.execute('SELECT kind FROM slots')], ['passphrase'])
        self.assertEqual(self.store.meta('cloud_broker'), '1')
        with self.assertRaises(StoreError):
            self.store.unlock_recovery('TEST-ONLY-invalid-recovery')

    def test_nonempty_principal_secret_and_grant_refused(self):
        inserts = [
            "INSERT INTO principals(principal_id,kind,display,state,created_at) VALUES ('test-only','human','Test','active','now')",
            "INSERT INTO projects(slug,change_policy,created_at) VALUES ('a','auto','now')",
        ]
        for sql in inserts:
            self.store.connection.execute(sql)
        with self.assertRaisesRegex(StoreError, 'empty store'):
            self.store.initialize(TEST_PASSPHRASE, argon2=TEST_ARGON2, cloud_broker=True)
        self.store.connection.execute('DELETE FROM principals')
        self.store.connection.execute("INSERT INTO secrets(secret_id,path,project,class,kind,state,created_at,created_by) VALUES ('test-only','a/key','a','standard','opaque','active','now','test-only')")
        with self.assertRaisesRegex(StoreError, 'empty store'):
            self.store.initialize(TEST_PASSPHRASE, argon2=TEST_ARGON2, cloud_broker=True)
        self.assertIsNone(self.store.meta('store_id'))
        self.store.connection.execute('DELETE FROM secrets')
        self.store.connection.execute('PRAGMA foreign_keys=OFF')
        self.store.connection.execute("INSERT INTO grants(grant_id,principal_id,pattern,ops,conditions_json,effect,granted_by,reason,created_at) VALUES ('TEST-ONLY-orphan','TEST-ONLY-missing','a/*','inject','{}','allow','TEST-ONLY','TEST-ONLY','now')")
        self.store.connection.execute('PRAGMA foreign_keys=ON')
        with self.assertRaisesRegex(StoreError,'empty store'):
            self.store.initialize(TEST_PASSPHRASE,argon2=TEST_ARGON2,cloud_broker=True)

    def test_socket_cloud_init_requires_tty(self):
        service = AdminService(self.store, SealManager(self.store))
        read, write = os.pipe()
        try:
            result = service.handle(AdminSession(), {'op':'init', 'args':{'cloud_broker':True,'passphrase':TEST_PASSPHRASE}}, [write])
        finally:
            os.close(read)
            os.close(write)
        self.assertFalse(result['ok'])
        self.assertIsNone(self.store.meta('store_id'))

    def test_human_boundary_refuses_before_socket(self):
        for args in (['init','--cloud-broker'], ['join','--org','a'*32,'--name','test-only'], ['resolve','--head','2:'+'b'*64,'--through-conflict','1']):
            with patch.dict(os.environ, {'ORCA_TERMINAL_HANDLE':'test-only'}), patch.object(admin,'AdminClient') as client, patch('sys.stderr',io.StringIO()):
                self.assertEqual(admin.main(args),77)
                client.assert_not_called()


class HTTPSBoundaryTests(unittest.TestCase):
    def test_origin_rejections(self):
        for value in ('http://api.example.com','https://user' + ':pass@api.example.com','https://api.example.com/path', 'https://api.example.com/?code=test-only','https://localhost','https://127.0.0.1','https://10.0.0.1','https://api.example.com/#fragment','https://machine','https://[::1]'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                public_origin(value)
        self.assertEqual(public_origin('https://api.example.com/'),'https://api.example.com')

    def transport(self, status=200, body=b'{}', declared=None):
        connection = Mock()
        response = connection.getresponse.return_value
        response.status = status
        response.read.return_value = body
        response.getheader.return_value = declared
        return HTTPSTransport('https://api.example.com',connection_factory=Mock(return_value=connection)), connection

    def test_raw_bytes_and_no_redirects(self):
        transport, connection = self.transport()
        request = SignedRequest('https://api.example.com/v1/enroll','POST',(),b'{"test":"only"}')
        self.assertEqual(transport(request),(200,b'{}'))
        self.assertEqual(connection.request.call_args.kwargs['body'],request.body)
        connection.close.assert_called_once()
        import ssl
        context=transport.connection_factory.call_args.kwargs['context']
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode,ssl.CERT_REQUIRED)
        self.assertEqual(transport.connection_factory.call_args.kwargs['timeout'],15)
        for body in ('not bytes',b'x'*(MAX_BODY+1)):
            with self.assertRaisesRegex(ValueError,'body'):
                transport(SignedRequest('https://api.example.com/v1/enroll','POST',(),body))
        for status in (301,302,307,308):
            transport, connection = self.transport(status=status)
            with self.assertRaisesRegex(ValueError,'redirect'):
                transport(request)
            connection.close.assert_called_once()

    def test_cap_and_origin_are_enforced(self):
        request = SignedRequest('https://api.example.com/v1/enroll','POST',(),b'{}')
        for body, declared in ((b'x'*(MAX_BODY+1),None),(b'',str(MAX_BODY+1)),(b'','invalid')):
            transport, connection = self.transport(body=body,declared=declared)
            with self.assertRaisesRegex(ValueError,'oversized'):
                transport(request)
            connection.close.assert_called_once()
        transport, connection = self.transport()
        with self.assertRaisesRegex(ValueError,'origin'):
            transport(SignedRequest('https://evil.example.com/path','GET',(),b''))
        connection.request.assert_not_called()


class CloudProtocolTests(unittest.TestCase):
    def test_policy_refusals_survive_socket_and_cli_as_75(self):
        for code,expected in (('E_POLICY_CONFLICT',75),('E_POLICY_STALE',75),('E_SYNC_RETRY',75),('E_ROTATION_UNAVAILABLE',78)):
            with self.subTest(code=code):
                left,right=socket.socketpair()
                try:
                    send_frame(left,failure(code,'TEST-ONLY refusal'))
                    response=recv_frame(right)
                finally:
                    left.close()
                    right.close()
                with patch.object(cli,'_connect') as connect, patch.object(cli,'recv_frame',return_value=response), patch.object(cli,'send_frame_with_fds'), patch.object(cli,'resolve_identity',return_value=('TEST-ONLY',None)), patch('sys.stderr',io.StringIO()):
                    connect.return_value.__enter__.return_value=Mock()
                    self.assertEqual(cli.main(['names','a']),expected)


from pathlib import Path
from types import SimpleNamespace
from copy import deepcopy
import json
import subprocess
import sys
import threading
from datetime import datetime,timezone,timedelta

from cloud_runtime_fake import FakeCloud,ORG,BROKER,NOW
from tw.cloud_enroll import EnrollmentSession,save_reservation,proof_message
from tw.cloud_runtime import CloudRuntime,CONFIG
from tw.cloud_sync import PullRetry
from tw.policy_log import PolicyError
from tw.agent_service import AgentService
from tw.identity import IdentityStore


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.fake=FakeCloud()
        self.addCleanup(self.fake.close)
        self.store=self.fake.h.store
        self.master,_=self.store.initialize(TEST_PASSPHRASE,argon2=TEST_ARGON2,cloud_broker=True)
        self.seal=SealManager(self.store)
        self.seal.unseal(TEST_PASSPHRASE)
        self.addCleanup(self.seal.seal)
        transcript=dict(name='TEST-ONLY broker',version='test-only',mode='join',
            sign_pub=crypto.b64url(self.fake.h.public),kx_pub=crypto.b64url(self.fake.h.kx))
        self.session=EnrollmentSession(ORG,transcript,self.fake.h.signing,self.fake.h.exchange,broker_id=BROKER)
        ticket='enr_aaaaaaaaaaaa'
        proof=crypto.b64url(crypto.p256_sign(self.fake.h.signing,proof_message(ORG,ticket,transcript)))
        save_reservation(self.session,self.store,self.master,ticket,proof)
        words=crypto.sas_words(crypto.sas_context(ORG,self.fake.h.root,'broker',BROKER,transcript['sign_pub'],transcript['kx_pub']))
        self.session.pin(self.store,crypto.canonical_json(self.fake.h.genesis),typed_words=words)
        # Unit-only founding-broker harness represents an already enrolled store.
        self.store.connection.execute("UPDATE cloud_enrollments SET state='complete'")
        self.store.set_meta(CONFIG,crypto.canonical_json(dict(origin='https://api.example.com',org=ORG,broker=BROKER,
            ticket=ticket,genesis=self.fake.h.signed(self.fake.h.genesis))).decode())
        self.runtime=CloudRuntime(self.store,self.seal,transport_factory=lambda origin:self.fake,clock=lambda:NOW,monotonic=lambda:100.)

    def test_pull_put_reads_cloud_only_and_restart(self):
        self.runtime.pull()
        value=b'TEST-ONLY cloud canary value 123456789'
        result=self.runtime.put('a/key',value,secret_class='standard')
        self.assertEqual(result['version_no'],1)
        self.assertNotIn(value,crypto.canonical_json(result))
        self.assertEqual(self.runtime.read('a/key'),value)
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM secrets').fetchone()[0],0)
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM secret_versions').fetchone()[0],0)
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM cloud_unpublished').fetchone()[0],0)
        self.assertTrue(all('TW-Sig' in dict(call.headers) for call in self.fake.calls))
        self.assertTrue(all(value not in call.body for call in self.fake.calls))
        restarted=CloudRuntime(self.store,self.seal,transport_factory=lambda origin:self.fake,clock=lambda:NOW)
        self.assertEqual(restarted.read('a/key'),value)
        self.assertEqual({row['observed_at'] for row in self.store.cloud_observations(ORG)['heads']},{NOW})

    def test_pending_defers_all_policy_and_custody_reads(self):
        self.fake.pending=True
        self.assertEqual(self.runtime.pull(),dict(state='pending'))
        self.assertEqual(len(self.fake.calls),1)
        self.assertTrue(self.fake.calls[0].url.endswith('/broker/enrollment'))

    def test_transport_backoff_and_sealed_local_idle(self):
        self.fake.failure=PullRetry('TEST-ONLY unavailable')
        self.runtime.tick()
        count=len(self.fake.calls)
        self.assertEqual(self.runtime.failures,1)
        self.assertEqual(self.runtime.next_attempt,102.)
        self.runtime.tick()
        self.assertEqual(len(self.fake.calls),count)
        self.runtime.monotonic=lambda:103.
        self.runtime.tick()
        self.assertEqual(self.runtime.next_attempt,107.)
        self.assertEqual(self.runtime.sync().conflicts(),[])
        self.seal.seal()
        self.runtime.monotonic=lambda:999.
        self.runtime.tick()
        self.assertEqual(len(self.fake.calls),count+1)

    def test_resolve_existing_session_atomically_and_preserve_history(self):
        self.runtime.pull()
        self.runtime.sync().refuse('fork',NOW)
        conflicts=self.runtime.sync().conflicts()
        conflict=conflicts[-1]['conflict_id']
        head=self.runtime.sync().checkpoint()['head']
        args=dict(expected_head=head,through_conflict=conflict,typed_root=self.fake.h.root)
        with self.assertRaisesRegex(PolicyError,'authenticated'):
            self.runtime.resolve(AdminSession(),**args)
        session=AdminSession();session.authenticate()
        for field,value in (('typed_root','0'*64),('through_conflict',conflict+1),('expected_head',dict(seq=2,hash='0'*64))):
            reason={'typed_root':'independent resolution root','through_conflict':'cover exactly current','expected_head':'selected resolution head'}[field]
            with self.subTest(field=field),self.assertRaisesRegex(PolicyError,reason):
                self.runtime.resolve(session,**dict(args,**{field:value}))
        result=self.runtime.resolve(session,**args)
        self.assertTrue(result['resolved'])
        self.assertEqual(self.runtime.sync().conflicts(),[])
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM cloud_conflicts').fetchone()[0],1)
        self.assertIsNotNone(self.store.cloud_branch(ORG))
        self.runtime.pull()
        self.runtime.sync().require_delivery('a','restricted',NOW)
        self.runtime.sync().refuse('fork',NOW)
        self.assertEqual(len(self.runtime.sync().conflicts()),1)

    def test_resolution_session_expiry_and_race_leave_everything_unchanged(self):
        self.runtime.pull();self.runtime.sync().refuse('fork',NOW)
        session=AdminSession();session.authenticate()
        head=self.runtime.sync().checkpoint()['head'];conflict=self.runtime.sync().conflicts()[-1]['conflict_id']
        args=dict(expected_head=head,through_conflict=conflict,typed_root=self.fake.h.root)
        self.fake.after_fetch=session.clear
        with self.assertRaisesRegex(PolicyError,'expired'):
            self.runtime.resolve(session,**args)
        self.assertIsNone(self.store.cloud_branch(ORG))
        session.authenticate()
        self.fake.after_fetch=lambda:self.runtime.sync().refuse('fork',NOW)
        with self.assertRaisesRegex(PolicyError,'changed'):
            self.runtime.resolve(session,**args)
        self.assertIsNone(self.store.cloud_branch(ORG))
        self.assertEqual(len(self.runtime.sync().conflicts()),2)

    def test_resolution_rollback_keeps_delivery_closed(self):
        self.runtime.pull();self.runtime.sync().refuse('fork',NOW)
        session=AdminSession();session.authenticate()
        head=self.runtime.sync().checkpoint()['head'];conflict=self.runtime.sync().conflicts()[-1]['conflict_id']
        self.store.connection.execute("CREATE TRIGGER test_only_fail_selection BEFORE INSERT ON cloud_branch_observations BEGIN SELECT RAISE(ABORT,'TEST-ONLY rollback'); END")
        with self.assertRaises(Exception):
            self.runtime.resolve(session,expected_head=head,through_conflict=conflict,typed_root=self.fake.h.root)
        self.assertIsNone(self.store.cloud_branch(ORG))
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM cloud_verified_branches').fetchone()[0],0)
        with self.assertRaisesRegex(PolicyError,'unresolved'):
            self.runtime.sync().require_delivery('a','standard',NOW)

    def test_admin_routes_reuse_session_and_refuse_sealed(self):
        service=AdminService(self.store,self.seal);service.cloud=self.runtime
        session=AdminSession()
        response=service.handle(session,dict(op='cloud_status',args={}),[])
        self.assertEqual(response['code'],'E_AUTH')
        session.authenticate()
        response=service.handle(session,dict(op='cloud_status',args={}),[])
        self.assertTrue(response['ok'])
        self.seal.seal()
        response=service.handle(session,dict(op='cloud_status',args={}),[])
        self.assertEqual(response['code'],'E_SEALED')

    def test_local_grants_cannot_authorize_cloud_or_issue_task(self):
        self.runtime.pull()
        identities=IdentityStore(self.store.connection,self.store.home)
        identities.roster_sync({'ai':[{'id':'a','run':'TEST-ONLY-run'}]},[])
        self.store.connection.execute("UPDATE principals SET state='active' WHERE principal_id='lead:a'")
        token=identities.issue_token('lead:a','lead',created_by='master')
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM grants').fetchone()[0],0)
        self.store.connection.execute("INSERT INTO grants(grant_id,principal_id,pattern,ops,conditions_json,effect,granted_by,reason,created_at) VALUES ('test-only','lead:a','a/*','inject+put','{}','allow','test-only','test-only','now')")
        identities.grant_provider=self.runtime.permission_grants
        permission,_=identities.permission_for_token(token['token_id'])
        self.assertFalse(permission.allows('inject','a/key','standard'))
        with self.assertRaises(Exception):
            identities.issue_task_token(token['token_id'],'test-dispatch','test-handle','inject:a/key','2099-01-01T00:00:00Z')
        count=len(self.fake.calls)
        # Unit-only signed-policy provider isolates local token mechanics.
        identities.grant_provider=lambda principal:[dict(principal_id=principal,pattern='a/key',ops=['inject'],max_class='standard',expires_at='2099-01-01T00:00:00Z')]
        task=identities.issue_task_token(token['token_id'],'test-dispatch','test-handle','inject:a/key','2099-01-01T00:00:00Z')
        permission,ceiling=identities.permission_for_token(task['token_id'])
        self.assertTrue(permission.allows('inject','a/key','standard',ceiling))
        self.assertFalse(permission.allows('put','a/key','standard',ceiling))
        self.assertEqual(len(self.fake.calls),count)

    def test_agent_run_and_inject_keep_value_out_of_output(self):
        from tw.broker import Broker
        self.runtime.pull()
        canary=b'TEST-ONLY cloud transcript canary 123456789'
        self.runtime.put('a/key',b'TEST-ONLY superseded cloud value',secret_class='standard')
        self.runtime.put('a/key',canary,secret_class='standard')
        self.runtime.put('a/restricted',b'TEST-ONLY restricted cloud canary',secret_class='restricted')
        broker=Broker.__new__(Broker)
        broker.store=self.store;broker.seal=self.seal;broker.cloud=self.runtime
        broker.service=AgentService(self.store,self.seal,home=self.store.home,broker_pid=-1,process_resolver=lambda pid:None)
        broker.service.cloud=self.runtime
        broker.service.identities.roster_sync({'ai':[{'id':'a','run':'TEST-ONLY-run'}]},[])
        self.store.connection.execute("UPDATE principals SET state='active' WHERE principal_id='lead:a'")
        token=broker.service.identities.issue_token('lead:a','lead',created_by='master',max_class='restricted')
        broker.service.identities.grant_provider=lambda principal:[dict(principal_id=principal,pattern='a/*',ops=['inject'],max_class='restricted',expires_at='2099-01-01T00:00:00Z')]
        from tw.broker import AgentSocketServer
        broker.agent=AgentSocketServer(broker,self.store.home/'run/tw.sock');broker.agent.bind()
        thread=threading.Thread(target=broker.agent.serve_forever,daemon=True);thread.start()
        try:
            for op in ('run','inject'):
                completed=subprocess.run([sys.executable,'-m','tw.cli',op,'--env','X=a/key','--',sys.executable,'-c',"import os; assert os.environ['X'] == 'TEST-ONLY cloud transcript canary 123456789'; print(os.environ['X'])"],
                    env=dict(os.environ,TW_HOME=str(self.store.home),TW_TOKEN_FILE=token['file_path']),capture_output=True,timeout=10)
                self.assertEqual(completed.returncode,0,completed.stderr)
                self.assertNotIn(canary,completed.stdout+completed.stderr)
                self.assertIn(b'[tw:a/key]',completed.stdout)
            self.runtime.clock=lambda:'2026-10-16T01:00:00.000Z'
            stale=subprocess.run([sys.executable,'-m','tw.cli','run','--env','X=a/restricted','--',sys.executable,'-c',"print('TEST-ONLY started')"],
                env=dict(os.environ,TW_HOME=str(self.store.home),TW_TOKEN_FILE=token['file_path']),capture_output=True,timeout=10)
            self.assertEqual(stale.returncode,75,stale.stderr)
            self.assertNotIn(b'TEST-ONLY started',stale.stdout)
            self.runtime.clock=lambda:NOW
            self.runtime.sync().refuse('fork',NOW)
            conflict=subprocess.run([sys.executable,'-m','tw.cli','inject','--env','X=a/key','--',sys.executable,'-c',"print('TEST-ONLY started')"],
                env=dict(os.environ,TW_HOME=str(self.store.home),TW_TOKEN_FILE=token['file_path']),capture_output=True,timeout=10)
            self.assertEqual(conflict.returncode,75,conflict.stderr)
            self.assertNotIn(b'TEST-ONLY started',conflict.stdout)
        finally:
            broker.agent.close();broker.service.close();thread.join(timeout=2)

    def test_ambiguous_publication_reconciles_before_retry_without_duplicate(self):
        self.runtime.pull()
        self.fake.lose_publication_response=True
        with self.assertRaises(PullRetry):
            self.runtime.put('a/key',b'TEST-ONLY ambiguous canary',secret_class='standard')
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM cloud_unpublished').fetchone()[0],1)
        receipt=self.runtime.put('a/key',b'TEST-ONLY ambiguous canary',secret_class='standard')
        self.assertEqual(receipt['version_no'],1)
        self.assertEqual(len([c for c in self.fake.calls if c.url.endswith('/sync/versions')]),1)
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM cloud_unpublished').fetchone()[0],0)

    def test_publication_rechecks_permission_after_fresh_pull(self):
        self.runtime.pull()
        def revoked():
            raise PolicyError('E_DENIED','TEST-ONLY revoked during pull')
        with self.assertRaisesRegex(PolicyError,'revoked'):
            self.runtime.put('a/key',b'TEST-ONLY denied value',secret_class='standard',authorize=revoked)
        self.assertFalse(any(c.url.endswith('/sync/versions') for c in self.fake.calls))
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM cloud_unpublished').fetchone()[0],0)

    def test_resolution_selects_a_genuinely_divergent_verified_branch(self):
        self.fake.h.append(self.fake.h.entry('secret_create',dict(secret_id='TEST-ONLY-first',path='a/first',project='a',**{'class':'standard'})))
        self.fake.h.verifier.finish_history([],evidence=self.fake.h.proof,broker_id=BROKER)
        self.runtime.pull()
        original=self.runtime.sync().checkpoint()['head']
        from tw.cloud_recovery import RecoveryVerifier
        from tw.policy_log import policy_record
        prefix=self.fake.h.frames[:2]
        alternate=deepcopy(json.loads(self.fake.h.frames[-1][0].data))
        alternate['body'].update(secret_id='TEST-ONLY-alternate',path='a/alternate')
        record=policy_record(alternate,crypto.unb64url(self.fake.h.signed(alternate)['sig']),NOW)
        verifier=RecoveryVerifier(ORG,self.fake.h.root,projects=['a','b'])
        for item,stage,blob,evidence in prefix:
            verifier.verify_record(item,stage=stage,blob=blob,evidence=evidence)
        verifier.verify_record(record,evidence=self.fake.h.proof)
        verifier.finish_history([],evidence=self.fake.h.proof,broker_id=BROKER)
        self.fake.h.verifier=verifier
        self.fake.h.frames=prefix+[(record,None,None,self.fake.h.proof)]
        with self.assertRaisesRegex(PolicyError,'divergent'):
            self.runtime.pull()
        self.assertEqual([row['reason'] for row in self.runtime.sync().conflicts()],['fork'])
        session=AdminSession();session.authenticate()
        conflict=self.runtime.sync().conflicts()[-1]['conflict_id']
        self.runtime.resolve(session,expected_head=verifier.head,through_conflict=conflict,typed_root=self.fake.h.root)
        self.assertNotEqual(self.runtime.sync().checkpoint()['head'],original)
        self.assertEqual(self.runtime.sync().checkpoint()['head'],verifier.head)
        self.assertEqual(self.store.connection.execute('SELECT hash FROM cloud_replay WHERE org_id=? ORDER BY seq DESC LIMIT 1',(ORG,)).fetchone()[0],original['hash'])
        self.runtime.pull()
        self.assertEqual(self.runtime.sync().conflicts(),[])


class EnrollmentWiringTests(unittest.TestCase):
    def test_real_enrollment_api_ceremony_and_initial_custody_on_fake_transport(self):
        import test_cloud_enrollment_production as enrollment_fixtures
        from tw.cloud_public import PublicEvidence,commitment_stage
        from tw.cloud_http import verify_request
        from tw.cloud_enroll import verify_proof,ticket_id
        from tw.policy_log import policy_record
        document=next(doc for item,doc in enrollment_fixtures.documents() if 'broker_local_sas' in doc)
        harness=enrollment_fixtures.replay_join(document)
        reserve=next(s for s in document['steps'] if s['id']=='broker-enrollment-possession-proof')
        enrollment=crypto.parse_canonical(enrollment_fixtures.body(reserve['input']['request']))
        reserved=enrollment_fixtures.result(reserve)['result']
        poll=enrollment_fixtures.result(document['steps'][-1])['result']
        transcript=enrollment['transcript']
        signing=crypto.import_private(document['test_only_keys']['signing_jwk'])
        exchange=crypto.import_private(document['test_only_keys']['kx_jwk'])
        org,broker=document['org_id'],reserved['broker_id']
        tables=deepcopy(harness.rows)
        tables['enrollment_binding_evidence']=tables['enrollment_wrap_digests']
        tables['initial_member_slot_commitments']=[]
        for cert,commitment,kind,metadata in harness.replay._initial_references:
            source=next(v for v in harness.replay.state['certificates'] if v['certificate']==cert)
            slot=next(r for r in harness.blobs['member_slots'] if r['member_key_id']==cert['member_key_id'])
            tables['initial_member_slot_commitments'].append(dict(certificate=cert,reference=dict(member_key_id=cert['member_key_id'],
                policy_seq=source['seq'],slot_id=slot['slot_id'],commitment_sha256=commitment,commitment_kind=kind)))
        evidence=PublicEvidence(tables,request_facts={});evidence.expected_scope='full'
        frames=[]
        prefix=document['steps'][0]['input']['records']
        approval=next(s for s in document['steps'] if s['id']=='certificate-and-wrap-committed-response-lost')
        signed=crypto.parse_canonical(enrollment_fixtures.body(approval['input']['request']))
        entries=[dict(entry=r['entry'],sig=r['sig']) for r in prefix]+[dict(entry=signed['entry'],sig=signed['sig'])]
        for item in entries:
            entry=item['entry'];stage=None
            if entry['kind']=='epoch_init':
                payload=harness.stage(entry)
                public=dict(schema='tw-epoch-public-v1',policy_seq=entry['seq'],plan_id='__epoch_init__',fence=0,created_at=entry['ts'],
                    keyring=entry['body']['keyring'],keyring_metadata=[{k:row[k] for k in ('key_id','purpose','project','version','mk_generation','aad_v')} for row in payload['keyring']],
                    recipients=entry['body']['recipients'],scoped_seals=entry['body']['scoped_seals'])
                own=dict(policy_seq=entry['seq'],plan_id='__epoch_init__',fence=0,keyring=payload['keyring'],wraps=[],scoped_seals=[])
                stage=commitment_stage(public,own,entry,broker=broker,scope='full')
            frames.append((policy_record(entry,crypto.unb64url(item['sig']),entry['ts']),stage,None,evidence))
        class EnrollmentTransport:
            approved=False
            calls=[]
            def enroll(self,body):
                self.calls.append('enroll')
                verify_proof(org,ticket_id(body['ticket_code']),body['transcript'],body['proof'])
                return reserved
            def __call__(self,request):
                self.calls.append(request.url)
                verify_request(request,org,broker,crypto.export_point(signing.public_key()),document['received_at'])
                if request.url.endswith('/broker/enrollment'):
                    result=poll if self.approved else dict(state='pending')
                elif request.url.endswith('/keys'):
                    result=dict(omk_generation=1,my_wrap=poll['wraps'][0],keyring=harness.replay.epoch_state['keyring'])
                elif '/policy?' in request.url:
                    result=dict(entries=[],head=harness.replay.head,control_head=dict(seq=1,hash='1'*64))
                elif request.url.endswith('/sync/head'):
                    result=dict(recorded=True)
                else:
                    raise AssertionError('unexpected enrollment fake route')
                return 200,crypto.canonical_json(dict(ok=True,code='ok',result=result))
        transport=EnrollmentTransport()
        with tempfile.TemporaryDirectory() as temporary:
            with Store(temporary).open(create=True) as store:
                master,_=store.initialize(TEST_PASSPHRASE,argon2=TEST_ARGON2,cloud_broker=True)
                seal=SealManager(store);seal.unseal(TEST_PASSPHRASE)
                try:
                    runtime=CloudRuntime(store,seal,transport_factory=lambda origin:transport,clock=lambda:document['received_at'])
                    session=EnrollmentSession(org,transcript,signing,exchange)
                    with patch.object(EnrollmentSession,'create',return_value=session):
                        joined=runtime.join(origin='https://api.example.com',org=org,name=transcript['name'],code=enrollment['ticket_code'])
                    self.assertEqual(joined['words'],document['broker_local_sas']['words'])
                    with self.assertRaisesRegex(ValueError,'SAS'):
                        runtime.pair('TEST-ONLY wrong SAS')
                    runtime.pair(document['broker_local_sas']['words'])
                    self.assertEqual(runtime.pull(),dict(state='pending'))
                    self.assertEqual(store.connection.execute('SELECT count(*) FROM cloud_replay').fetchone()[0],0)
                    transport.approved=True
                    with patch.object(runtime,'fetch',return_value=(dict(evidence=evidence,scope='full',head=harness.replay.head),frames,[],[dict(secrets=[],versions=[],cursor=None)],['a','b'])):
                        runtime.pull()
                    self.assertEqual(store.connection.execute('SELECT state FROM cloud_enrollments').fetchone()[0],'complete')
                    omk=store.cloud_local_key(master,org=org,broker=broker,key_id='omk_1',purpose='omk',scope='*',generation=1)
                    self.assertEqual(omk.hex(),document['test_only_keys']['wrapped_omk_hex'])
                    self.assertIsNone(store.connection.execute("SELECT 1 FROM slots WHERE kind='recovery'").fetchone())
                finally:
                    seal.seal()


class RuntimeGuardTests(unittest.TestCase):
    setUp=RuntimeTests.setUp

    def test_configuration_seal_enrollment_and_delivery_guards(self):
        with patch.object(self.store,'meta',return_value=None),self.assertRaisesRegex(PolicyError,'has not joined'):
            self.runtime.config()
        keys=self.seal.keys
        self.seal.keys=None
        try:
            with self.assertRaisesRegex(PolicyError,'sealed'):self.runtime.blk()
        finally:self.seal.keys=keys
        self.store.set_meta('cloud_broker','0')
        with self.assertRaisesRegex(PolicyError,'empty cloud broker'):
            self.runtime.join(origin='https://api.example.com',org=ORG,name='TEST-ONLY',code='unused')
        self.store.set_meta('cloud_broker','1')
        with self.assertRaisesRegex(PolicyError,'another organization'):
            self.runtime.join(origin='https://other.example.com',org=ORG,name='TEST-ONLY',code='unused')
        self.store.connection.execute("INSERT INTO secrets(secret_id,path,project,class,kind,state,created_at,created_by) VALUES ('TEST-ONLY','infra/key','infra','standard','opaque','active','now','TEST-ONLY')")
        with self.assertRaisesRegex(PolicyError,'adoption ceremony'):
            self.runtime.join(origin='https://api.example.com',org=ORG,name='TEST-ONLY',code='unused')
        self.store.connection.execute('DELETE FROM secrets')
        self.runtime.pull()
        with self.assertRaisesRegex(PolicyError,'secret unavailable'):self.runtime.read('a/unknown')
        self.fake.h.append(self.fake.h.entry('secret_create',dict(secret_id='TEST-ONLY-empty',path='a/empty',project='a',**{'class':'standard'})))
        self.fake.h.verifier.finish_history([],evidence=self.fake.h.proof,broker_id=BROKER)
        self.runtime.pull()
        with self.assertRaisesRegex(PolicyError,'active version unavailable'):self.runtime.read('a/empty')
        with patch.object(self.store,'cloud_request_state',return_value={}),self.assertRaisesRegex(PolicyError,'verified grants'):
            self.runtime.permission_grants('lead:a')
        with self.assertRaisesRegex(PolicyError,'unknown cloud project'):
            self.runtime.put('unknown/key',b'TEST-ONLY unused value',secret_class='standard')

    def test_policy_budget_missing_page_and_evidence_head_guards(self):
        with patch('tw.cloud_runtime.len',return_value=10000,create=True),self.assertRaisesRegex(PolicyError,'evidence page limit'):
            self.runtime.policy_evidence(self.runtime.client(),self.fake.h.verifier.head)
        with patch('tw.cloud_runtime.len',return_value=1000000,create=True),self.assertRaisesRegex(PolicyError,'policy prefix limit'):
            self.runtime.fetch(self.runtime.client())
        original=self.runtime.call
        def empty(client,method,path,body=None,query=None):
            result=original(client,method,path,body,query)
            if path=='policy':result['entries']=[]
            return result
        with patch.object(self.runtime,'call',side_effect=empty),self.assertRaisesRegex(PolicyError,'policy page missing'):
            self.runtime.fetch(self.runtime.client())
        def wrong_head(client,method,path,body=None,query=None):
            result=original(client,method,path,body,query)
            if path=='policy':result['head']=dict(seq=1,hash=self.fake.h.root)
            return result
        with patch.object(self.runtime,'call',side_effect=wrong_head),self.assertRaisesRegex(PolicyError,'policy continuation does not progress'):
            self.runtime.fetch(self.runtime.client())

    def test_ciphertext_budget_repeated_and_wrong_binding_cursors(self):
        with patch('tw.cloud_pull.MAX_PULL_PAGES',2),self.assertRaisesRegex(PolicyError,'page budget'):
            self.runtime.pull()
        original=self.runtime.call
        head=self.fake.h.verifier.head
        cursor=crypto.b64url(crypto.canonical_json(dict(org_id=ORG,broker_id=BROKER,seq=head['seq'],scope=['*'],offsets=dict(secrets=0,versions=0))))
        calls=[0]
        def repeated(client,method,path,body=None,query=None):
            result=original(client,method,path,body,query)
            if path=='sync/secrets':
                calls[0]+=1
                result['cursor']=cursor if calls[0]<3 else None
            return result
        with patch.object(self.runtime,'call',side_effect=repeated),self.assertRaisesRegex(PolicyError,'ciphertext continuation does not progress'):
            self.runtime.fetch(self.runtime.client())
        def wrong(client,method,path,body=None,query=None):
            result=original(client,method,path,body,query)
            if path=='sync/secrets':
                result['cursor']=crypto.b64url(crypto.canonical_json(dict(org_id='c'*32,broker_id=BROKER,seq=head['seq'],scope=['*'],offsets=dict(secrets=0,versions=0))))
            return result
        with patch.object(self.runtime,'call',side_effect=wrong),self.assertRaisesRegex(PolicyError,'cursor binding differs'):
            self.runtime.fetch(self.runtime.client())

    def test_pending_pairing_active_state_and_verified_scope_guards(self):
        self.store.connection.execute("UPDATE cloud_enrollments SET state='reserved',candidate_root=NULL")
        with self.assertRaisesRegex(PolicyError,'typed SAS pairing'):self.runtime.pull()
        self.store.connection.execute("UPDATE cloud_enrollments SET state='complete',candidate_root=?",(self.fake.h.root,))
        original=self.runtime.call
        def revoked(client,method,path,body=None,query=None):
            return dict(state='revoked') if path=='broker/enrollment' else original(client,method,path,body,query)
        with patch.object(self.runtime,'call',side_effect=revoked),self.assertRaisesRegex(PolicyError,'broker is not active'):
            self.runtime.pull()
        bundle,*rest=self.runtime.fetch(self.runtime.client())
        bundle['scope']=['a']
        with patch.object(self.runtime,'fetch',return_value=(bundle,*rest)),self.assertRaisesRegex(PolicyError,'evidence scope differs'):
            self.runtime.pull()

    def stage_failed_publication(self):
        original=self.fake
        def failed(request):
            if request.url.endswith('/sync/versions'):raise PullRetry('TEST-ONLY before publication')
            return original(request)
        self.runtime.transport_factory=lambda origin:failed
        with self.assertRaises(PullRetry):
            self.runtime.put('a/key',b'TEST-ONLY staged value',secret_class='standard')
        self.runtime.transport_factory=lambda origin:original

    def test_pending_publication_identity_class_and_reconciliation_guards(self):
        self.stage_failed_publication()
        with self.assertRaisesRegex(PolicyError,'another publication is pending'):
            self.runtime.put('a/key',b'TEST-ONLY different value',secret_class='standard')
        vid=self.store.connection.execute('SELECT version_id FROM cloud_unpublished').fetchone()[0]
        self.store.connection.execute('DELETE FROM meta WHERE key=?',('cloud_publish_'+vid,))
        with self.assertRaisesRegex(PolicyError,'publication request identity missing'):
            self.runtime.put('a/key',b'TEST-ONLY staged value',secret_class='standard')
        self.store.set_meta('cloud_publish_'+vid,'12345678-1234-4123-8123-123456789abc')
        self.fake.h.append(self.fake.h.entry('secret_create',dict(secret_id='test-only-other',path='b/other',project='b',**{'class':'standard'})))
        self.fake.h.verifier.finish_history([],evidence=self.fake.h.proof,broker_id=BROKER)
        old_logical=self.store.meta('cloud_publish_'+vid)
        checked=Mock()
        result=self.runtime.put('a/key',b'TEST-ONLY staged value',secret_class='standard',authorize=checked)
        self.assertEqual(result['version_no'],1)
        checked.assert_called_once()
        self.assertNotEqual(self.store.meta('cloud_publish_'+vid),old_logical)
        self.assertEqual(self.runtime.read('a/key'),b'TEST-ONLY staged value')

    def test_unverified_success_does_not_acknowledge_publication(self):
        original=self.fake
        def dishonest(request):
            if request.url.endswith('/sync/versions'):
                return original.response(dict(recorded=True))
            return original(request)
        self.runtime.transport_factory=lambda origin:dishonest
        with self.assertRaisesRegex(PolicyError,'publication awaiting verified pull'):
            self.runtime.put('a/key',b'TEST-ONLY retained staged value',secret_class='standard')
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM cloud_unpublished').fetchone()[0],1)

    def test_reclassification_and_resolution_scope_guards(self):
        self.runtime.put('a/key',b'TEST-ONLY class canary',secret_class='standard')
        with self.assertRaisesRegex(PolicyError,'secret class differs'):
            self.runtime.put('a/key',b'TEST-ONLY class canary new',secret_class='sensitive')
        self.runtime.sync().refuse('fork',NOW)
        session=AdminSession();session.authenticate()
        bundle,*rest=self.runtime.fetch(self.runtime.client());bundle['scope']=['a']
        with patch.object(self.runtime,'fetch',return_value=(bundle,*rest)),self.assertRaisesRegex(PolicyError,'resolution certificate scope'):
            self.runtime.resolve(session,expected_head=bundle['head'],through_conflict=self.runtime.sync().conflicts()[-1]['conflict_id'],typed_root=self.fake.h.root)


class JoinRetryBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.fake=FakeCloud();self.addCleanup(self.fake.close)
        self.store=self.fake.h.store
        self.master,_=self.store.initialize(TEST_PASSPHRASE,argon2=TEST_ARGON2,cloud_broker=True)
        self.seal=SealManager(self.store);self.seal.unseal(TEST_PASSPHRASE);self.addCleanup(self.seal.seal)
        self.code='enr_aaaaaaaaaaaa.'+'a'*26
        self.arguments=dict(origin='https://api.example.com',org=ORG,name='TEST-ONLY joining broker',code=self.code)
        class Transport:
            fail=False
            def __init__(transport,fixture):
                transport.result=dict(org_id=ORG,broker_id='brk_'+'c'*32,genesis=fixture.h.signed(fixture.h.genesis),policy_head=fixture.h.verifier.head,state='pending')
            def enroll(transport,body):
                if transport.fail:raise PullRetry('TEST-ONLY reservation response lost')
                return deepcopy(transport.result)
        self.transport=Transport(self.fake)
        self.runtime=CloudRuntime(self.store,self.seal,transport_factory=lambda origin:self.transport,clock=lambda:NOW)

    def test_encrypted_key_retry_never_stores_ticket_secret(self):
        transcript=dict(name=self.arguments['name'],version='0.1.0',mode='join',sign_pub=crypto.b64url(self.fake.h.public),kx_pub=crypto.b64url(self.fake.h.kx))
        session=EnrollmentSession(ORG,transcript,self.fake.h.signing,self.fake.h.exchange)
        self.transport.fail=True
        with patch.object(EnrollmentSession,'create',return_value=session) as create:
            with self.assertRaises(PullRetry):self.runtime.join(**self.arguments)
            pending=self.store.meta('cloud_pending_join')
            self.assertNotIn(self.code,pending)
            self.assertNotIn(crypto.b64url(self.fake.h.signing.private_numbers().private_value.to_bytes(32,'big')),pending)
            self.assertIsNone(self.store.meta(CONFIG))
            with self.assertRaisesRegex(PolicyError,'pending enrollment identity'):
                self.runtime.join(**dict(self.arguments,origin='https://other.example.com'))
            self.transport.fail=False
            joined=self.runtime.join(**self.arguments)
            self.assertEqual(create.call_count,1)
        resumed=self.runtime.session()
        self.assertEqual(resumed.transcript,transcript)
        self.assertEqual(joined['broker_id'],'brk_'+'c'*32)

    def test_missing_and_wrong_identity_genesis_refused(self):
        self.transport.result['genesis']=None
        with self.assertRaisesRegex(PolicyError,'existing organization genesis'):
            self.runtime.join(**self.arguments)
        self.transport.result['genesis']=self.fake.h.signed(self.fake.h.genesis)
        self.transport.result['genesis']['entry']['kind']='secret_create'
        with self.assertRaisesRegex(PolicyError,'genesis identity differs'):
            self.runtime.join(**self.arguments)
        self.assertIsNone(self.store.meta(CONFIG))


class RuntimeIdentityBoundaryTests(unittest.TestCase):
    setUp=RuntimeTests.setUp

    def test_cloud_nested_grants_and_task_ceiling_without_network(self):
        from tw.identity import Scope,IdentityError
        self.runtime.pull()
        identities=IdentityStore(self.store.connection,self.store.home)
        identities.roster_sync({'ai':[{'id':'a','run':'TEST-ONLY-run'}]},[])
        self.store.connection.execute("UPDATE principals SET state='active' WHERE principal_id='lead:a'")
        token=identities.issue_token('lead:a','lead',created_by='master')
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM grants').fetchone()[0],0)
        with self.assertRaisesRegex(IdentityError,'provider unavailable'):
            identities.permission_for_token(token['token_id'])
        identities.grant_provider=lambda principal:[dict(principal_id=principal,pattern='a/service/*',ops=['inject'],max_class='standard',expires_at=None)]
        count=len(self.fake.calls)
        task=identities.issue_task_token(token['token_id'],'test-nested','test-handle','inject:a/service/Key','2099-01-01T00:00:00Z')
        task_principal=self.store.connection.execute('SELECT principal_id FROM tokens WHERE token_id=?',(task['token_id'],)).fetchone()[0]
        permission,ceiling=identities.permission_for_token(task['token_id'])
        self.assertTrue(permission.allows('inject','a/service/Key','standard',ceiling))
        self.assertFalse(permission.allows('inject','a/service/Other','standard',ceiling))
        self.assertFalse(permission.allows('inject','a/service-other/Key','standard',ceiling))
        self.assertEqual(len(self.fake.calls),count)
        with self.assertRaises(IdentityError):Scope.parse('inject:a/service/Key')
        for nested in (False,True):
            with self.assertRaises(IdentityError):Scope.parse('inject:a',allow_nested=nested)
        for text in ('inject:a/service/../Key','inject:a/service*/Key','inject:a//Key'):
            with self.subTest(text=text),self.assertRaises(IdentityError):Scope.parse(text,allow_nested=True)
        self.store.connection.execute("UPDATE principals SET state='disabled' WHERE principal_id=?",(task_principal,))
        with self.assertRaisesRegex(IdentityError,'not active'):
            identities.permission_for_token(task['token_id'])
        self.store.connection.execute("UPDATE principals SET state='active' WHERE principal_id=?",(task_principal,))
        def policy(principal):
            if principal==task_principal:
                return self.runtime.permission_grants(principal)
            return [dict(principal_id=principal,pattern='a/service/*',ops=['inject'],max_class='standard',expires_at=None)]
        sync=self.runtime.sync();state=sync.checkpoint()
        state['authority']['admin_policy']=dict(principals={task_principal:dict(state='disabled',broker_id=BROKER)})
        identities.grant_provider=policy
        with patch.object(self.runtime,'sync',return_value=sync),patch.object(sync,'checkpoint',return_value=state),self.assertRaisesRegex(PolicyError,'signed principal is disabled'):
            identities.permission_for_token(task['token_id'])

    def test_remote_error_values_and_arbitrary_codes_never_reach_a_pane(self):
        from tw.cloud_http import CloudResponseError
        canary='TEST-ONLY remote error canary value'
        for code,expected in (('E_DENIED','E_DENIED'),('E_'+canary,'E_SYNC_RETRY')):
            self.fake.failure=CloudResponseError(code,canary)
            with self.subTest(code=expected),self.assertRaises(PolicyError) as caught:
                self.runtime.pull()
            self.assertEqual(caught.exception.code,expected)
            self.assertNotIn(canary,str(caught.exception))
        self.fake.failure=None
        original=self.fake
        def upload(request):
            if request.url.endswith('/sync/versions'):raise CloudResponseError('E_'+canary,canary)
            return original(request)
        self.runtime.transport_factory=lambda origin:upload
        with self.assertRaises(PullRetry) as caught:
            self.runtime.put('a/key',b'TEST-ONLY staged remote refusal',secret_class='standard')
        self.assertNotIn(canary,str(caught.exception))


class RuntimeEvidenceClassificationTests(unittest.TestCase):
    setUp=RuntimeTests.setUp

    def test_missing_evidence_retries_with_backoff_without_policy_conflict(self):
        self.runtime.put('a/key',b'TEST-ONLY cached outage value',secret_class='standard')
        original=self.runtime.policy_evidence
        def missing(client,head):
            pages=list(original(client,head))
            pages[0]['public_staging']=[];pages[0]['own_payloads']=[]
            return pages
        with patch.object(self.runtime,'policy_evidence',side_effect=missing):
            self.runtime.tick()
        self.assertEqual(self.runtime.last_code,'E_SYNC_RETRY')
        self.assertEqual(self.runtime.failures,1)
        self.assertEqual(self.runtime.next_attempt,102.)
        self.assertEqual(self.runtime.sync().conflicts(),[])
        self.assertEqual(self.runtime.read('a/key'),b'TEST-ONLY cached outage value')

    def test_substituted_own_payload_is_local_protocol_evidence_never_fork(self):
        self.runtime.put('a/key',b'TEST-ONLY blocked cached value',secret_class='standard')
        original=self.runtime.policy_evidence
        def substituted(client,head):
            pages=list(original(client,head))
            pages[0]['own_payloads'][0]['wraps'][0]['wrapped_omk']='00'*48
            return pages
        with patch.object(self.runtime,'policy_evidence',side_effect=substituted),self.assertRaises(PolicyError):
            self.runtime.pull()
        self.assertEqual([c['reason'] for c in self.runtime.sync().conflicts()],['protocol_violation'])
        with self.assertRaisesRegex(PolicyError,'unresolved'):
            self.runtime.read('a/key')


class BranchImmutabilityTests(unittest.TestCase):
    setUp=RuntimeTests.setUp

    def test_authenticated_selection_and_replay_rows_are_immutable(self):
        import sqlite3
        self.runtime.pull();self.runtime.sync().refuse('fork',NOW)
        session=AdminSession();session.authenticate()
        self.runtime.resolve(session,expected_head=self.runtime.sync().checkpoint()['head'],through_conflict=self.runtime.sync().conflicts()[-1]['conflict_id'],typed_root=self.fake.h.root)
        for sql,reason in [
            ("UPDATE cloud_verified_branches SET authenticated_by='TEST-ONLY forged'",'authenticated history selection is immutable'),
            ('DELETE FROM cloud_verified_branches','authenticated history selection is immutable'),
            ("UPDATE cloud_branch_replay SET hash='0'",'verified branch is immutable'),
            ('DELETE FROM cloud_branch_replay','verified branch is immutable'),
        ]:
            with self.subTest(sql=sql),self.assertRaisesRegex(sqlite3.IntegrityError,reason):
                self.store.connection.execute(sql)

    def test_selected_branch_rejects_incomplete_raced_forked_and_changed_snapshots(self):
        from tw.store import CloudPublicationConflict
        self.runtime.put('a/key',b'TEST-ONLY branch publication',secret_class='standard')
        self.runtime.sync().refuse('fork',NOW)
        session=AdminSession();session.authenticate()
        head=self.runtime.sync().checkpoint()['head']
        self.runtime.resolve(session,expected_head=head,through_conflict=self.runtime.sync().conflicts()[-1]['conflict_id'],typed_root=self.fake.h.root)
        verifier=self.fake.h.verifier
        arguments=dict(verifier=verifier,blobs=self.fake.blobs,observed_at=NOW,broker=BROKER,expected_head=head)
        for field in ('blobs','observed_at','broker'):
            with self.subTest(field=field),self.assertRaisesRegex(StoreError,'complete cloud pull'):
                self.store.save_cloud_branch(**dict(arguments,**{field:None}))
        with self.assertRaisesRegex(StoreError,'head changed'):
            self.store.save_cloud_branch(**dict(arguments,expected_head=dict(seq=1,hash=self.fake.h.root)))
        checkpoint=verifier.export_checkpoint()
        for change in ('pin','prefix','state'):
            changed=deepcopy(checkpoint)
            if change=='pin':changed['pinned_root']='0'*64
            elif change=='prefix':changed['verified_heads'][head['seq']]='0'*64
            else:changed['authority']['TEST-ONLY-changed-state']=True
            reason='immutable selected cloud snapshot' if change=='state' else 'selected cloud prefix'
            with self.subTest(change=change),patch.object(verifier,'export_checkpoint',return_value=changed),self.assertRaisesRegex(StoreError,reason):
                self.store.save_cloud_branch(**arguments)
        version=self.fake.h.verifier.epoch_state['versions'][0]
        payload=dict(entries=[dict(entry=dict(body=dict(version_id=version['version_id'],value_digest='f'*64,envelope_digest=version['envelope_digest'])))])
        self.store.connection.execute('INSERT INTO cloud_unpublished VALUES (?,?,?,?,?)',(ORG,version['version_id'],crypto.canonical_json(head).decode(),version['kek_id'],crypto.canonical_json(payload).decode()))
        with self.assertRaisesRegex(CloudPublicationConflict,'retained write'):
            self.store.save_cloud_branch(**arguments)


class AdditionalConsoleBoundaryTests(unittest.TestCase):
    def test_cloud_init_never_falls_back_to_non_tty_passphrase(self):
        read,write=os.pipe()
        tty=Mock();tty.fileno.return_value=read
        client=Mock();client.call.return_value=dict(ok=True,code='ok',result=dict(initialized=True))
        try:
            with (patch.object(admin,'human_context_allowed',return_value=True),patch.object(admin,'AdminClient') as factory,
                patch.object(admin.os,'open',return_value=write),patch('builtins.open') as opened,
                patch.object(admin.getpass,'getpass',return_value=TEST_PASSPHRASE) as prompt,
                patch('sys.stderr',io.StringIO()),patch('sys.stdout',io.StringIO())):
                factory.return_value.__enter__.return_value=client
                opened.return_value.__enter__.return_value=tty
                self.assertEqual(admin.main(['init','--cloud-broker']),69)
                prompt.assert_not_called()
                client.call.assert_not_called()
        finally:
            os.close(read)

    def test_cloud_init_flag_is_strict_boolean(self):
        with tempfile.TemporaryDirectory() as temporary:
            with Store(temporary).open(create=True) as store:
                service=AdminService(store,SealManager(store))
                master,slave=os.openpty()
                try:
                    with patch.object(store,'initialize',return_value=(bytes(32),'')) as initialize:
                        response=service.handle(AdminSession(),dict(op='init',args=dict(passphrase=TEST_PASSPHRASE,cloud_broker=1)),[slave])
                        self.assertFalse(response['ok'])
                        self.assertIn('boolean',response['error'])
                        initialize.assert_not_called()
                finally:
                    os.close(master);os.close(slave)


class RemainingProductionBoundaryTests(unittest.TestCase):
    setUp=RuntimeTests.setUp

    def test_no_local_cloud_grants_requests_imports_or_recovery_ceremony(self):
        from tw.agent_service import AgentServiceError
        service=AgentService(self.store,self.seal,home=self.store.home,broker_pid=-1,process_resolver=lambda pid:None)
        service.cloud=self.runtime;self.addCleanup(service.close)
        service.identities.roster_sync({'ai':[{'id':'a','run':'TEST-ONLY-run'}]},[])
        self.store.connection.execute("UPDATE principals SET state='active' WHERE principal_id='lead:a'")
        with self.assertRaisesRegex(AgentServiceError,'signed console policy'):
            service._master_operation('grant_add',dict(scope='inject:a/*',principal='lead:a',reason='TEST-ONLY'))
        with self.assertRaisesRegex(AgentServiceError,'request creation'):
            service._request_access('lead:a',dict(kind='access',target='a/key',ops='inject',reason='TEST-ONLY'))
        with self.assertRaises(AgentServiceError) as caught:
            service.import_env(dict(op='import_env',args={}),0)
        self.assertEqual(caught.exception.code,'E_NOT_IMPLEMENTED')
        self.runtime.put('a/key',b'TEST-ONLY timer value',secret_class='standard')
        self.store.connection.execute("INSERT INTO requests(request_id,principal_id,kind,target,ops,reason,needs,state,created_at,default_decision,default_at) VALUES ('test-only-local-request','lead:a','access','a/key','inject','TEST-ONLY','operator','open',?,'approve',?)",(NOW,NOW))
        self.assertEqual(service.apply_request_defaults(NOW),0)
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM grants').fetchone()[0],0)
        admin_service=AdminService(self.store,self.seal);admin_service.cloud=self.runtime
        session=AdminSession();session.authenticate()
        response=admin_service.handle(session,dict(op='request_decide',args=dict(request_id='test-only-local-request',decision='approve',reason='TEST-ONLY')),[])
        self.assertIn('signed console policy',response['error'])
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM grants').fetchone()[0],0)
        master,slave=os.openpty()
        try:
            with patch.object(self.store,'rotate_recovery',side_effect=AssertionError('TEST-ONLY recovery forbidden')):
                response=admin_service.handle(session,dict(op='recovery_rotate',args={}),[slave])
                self.assertFalse(response['ok'])
                self.assertIn('reenrollment',response['error'])
        finally:os.close(master);os.close(slave)
        admin_service.cloud=None
        response=admin_service.handle(session,dict(op='cloud_status',args={}),[])
        self.assertIn('runtime unavailable',response['error'])

    def test_cloud_operations_remain_closed_on_agent_socket_dispatch(self):
        from tw.broker import Broker
        broker=Broker.__new__(Broker)
        broker.store=self.store;broker.seal=self.seal;broker.cloud=self.runtime
        for op in ('cloud_join','cloud_pair','cloud_resolve','cloud_status','cloud_poll'):
            result=broker.handle_agent(dict(op=op,args={}),[],0)
            self.assertEqual(result['code'],'E_UNKNOWN_OP')
        self.assertEqual(self.fake.calls,[])

    def test_daemon_cloud_tick_never_runs_local_default_or_desk_grant_timers(self):
        from tw.broker import Broker
        broker=Broker.__new__(Broker);broker.home=self.store.home;broker.store=self.store;broker.seal=self.seal
        broker.cloud=SimpleNamespace(enabled=True,tick=Mock())
        broker.stop_event=Mock();broker.stop_event.wait.side_effect=[False,True]
        broker.service=Mock();broker.desk=Mock();broker.sealed_alert_sent=False;broker.started=0
        broker._verify_audit=Mock();broker._health=Mock(return_value={})
        broker.maintenance()
        broker.cloud.tick.assert_called_once()
        broker.service.apply_request_defaults.assert_not_called()
        broker.service.apply_desk_answers.assert_not_called()

    def test_cloud_lock_order_precedes_store_lock_for_operations(self):
        from tw.broker import Broker
        class Lock:
            depth=0
            def __enter__(lock):lock.depth+=1;return lock
            def __exit__(lock,*args):lock.depth-=1
        broker=Broker.__new__(Broker);cloud_lock=Lock();store_lock=Lock()
        broker.cloud=SimpleNamespace(enabled=True,lock=cloud_lock)
        broker.store=SimpleNamespace(_transaction_lock=store_lock)
        def handle(*args,**kwargs):
            self.assertEqual(cloud_lock.depth,1 if broker.cloud.enabled else 0)
            self.assertEqual(store_lock.depth,1)
            return dict(ok=True)
        broker._handle_agent_locked=handle
        self.assertTrue(broker.handle_agent(dict(op='hello'),[])['ok'])
        broker.cloud.enabled=False
        self.assertTrue(broker.handle_agent(dict(op='hello'),[])['ok'])
        self.assertEqual((cloud_lock.depth,store_lock.depth),(0,0))

    def test_production_pull_publication_and_resolution_use_local_clock(self):
        local='2026-10-16T00:02:00.000Z'
        self.runtime.clock=lambda:local
        self.runtime.pull()
        self.assertEqual(self.store.cloud_observations(ORG)['heads'][-1]['observed_at'],local)
        self.runtime.put('a/local-clock',b'TEST-ONLY local observation clock',secret_class='standard')
        self.assertEqual(self.store.cloud_observations(ORG)['heads'][-1]['observed_at'],local)
        posted=next(request for request in self.fake.calls if request.url.endswith('/sync/versions'))
        self.assertTrue(all(item['entry']['ts']==local for item in json.loads(posted.body)['entries']))
        self.runtime.sync().refuse('fork',local)
        session=AdminSession();session.authenticate()
        self.runtime.resolve(session,expected_head=self.runtime.sync().checkpoint()['head'],through_conflict=self.runtime.sync().conflicts()[-1]['conflict_id'],typed_root=self.fake.h.root)
        self.assertEqual(self.store.cloud_observations(ORG)['heads'][-1]['observed_at'],local)

    def test_unexpected_error_pages_retry_without_manufacturing_conflict(self):
        from tw.cloud_http import CloudResponseError
        connection=Mock();response=connection.getresponse.return_value
        response.status=503;response.read.return_value=b'<html>TEST-ONLY upstream outage</html>'
        response.getheader.return_value=None
        transport=HTTPSTransport('https://api.example.com',connection_factory=Mock(return_value=connection))
        self.runtime.transport_factory=lambda origin:transport
        self.runtime.tick()
        self.assertEqual(self.runtime.last_code,'E_SYNC_RETRY')
        self.assertEqual(self.runtime.failures,1)
        self.assertEqual(self.runtime.sync().conflicts(),[])
        response.read.assert_not_called()
        connection.close.assert_called_once()
        response.status=403
        with self.assertRaises(PolicyError) as caught:self.runtime.pull()
        self.assertEqual(caught.exception.code,'E_DENIED')

    def test_internal_redactor_cannot_open_outside_current_certified_scope(self):
        self.runtime.put('b/key',b'TEST-ONLY out of scope canary',secret_class='standard')
        sync=self.runtime.sync();version=sync.checkpoint()['epochs']['versions'][0]
        certificate=sync.certificate();certificate['scope']=['a']
        with patch.object(sync,'certificate',return_value=certificate),self.assertRaisesRegex(PolicyError,'redaction outside certified scope'):
            sync._read_value(version['version_id'],self.master,now=NOW,delivery=False)


class PublicationLifecycleTests(unittest.TestCase):
    setUp=RuntimeTests.setUp

    def test_existing_names_publish_pending_then_activate(self):
        self.runtime.put('a/key',b'TEST-ONLY first value',secret_class='standard',principal_id='lead:a')
        result=self.runtime.put('a/key',b'TEST-ONLY replacement',secret_class='standard',principal_id='lead:a')
        self.assertEqual(result['version_no'],2)
        self.assertEqual(self.runtime.read('a/key'),b'TEST-ONLY replacement')
        self.assertEqual([v['state'] for v in self.runtime.sync().checkpoint()['epochs']['versions']],['retired','active'])
        writes=[r for r in self.fake.calls if r.method=='POST' and r.url.endswith('/sync/versions')]
        self.assertEqual(json.loads(writes[-1].body)['entries'][-1]['entry']['body']['state'],'pending')
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM cloud_unpublished').fetchone()[0],0)

    def test_pending_retry_is_bound_to_original_local_principal(self):
        RuntimeGuardTests.stage_failed_publication(self)
        with self.assertRaisesRegex(PolicyError,'another principal'):
            self.runtime.put('a/key',b'TEST-ONLY staged value',secret_class='standard',principal_id='different-principal')
        self.assertFalse(any(request.url.endswith('/sync/versions') for request in self.fake.calls))

    def test_retry_without_retained_key_stays_closed(self):
        RuntimeGuardTests.stage_failed_publication(self)
        self.fake.h.append(self.fake.h.entry('secret_create',dict(secret_id='test-only-other',path='b/other',project='b',**{'class':'standard'})))
        self.fake.h.verifier.finish_history([],evidence=self.fake.h.proof,broker_id=BROKER)
        original=self.store.connection
        # Pull still restores current custody; hide only the dedicated retained
        # publication-key query to model an unavailable historical key.
        class Connection:
            def __getattr__(proxy,name):return getattr(original,name)
            def execute(proxy,sql,parameters=()):
                if sql.startswith('SELECT generation FROM cloud_local_keys'):
                    return SimpleNamespace(fetchone=lambda:None)
                return original.execute(sql,parameters)
        with patch.object(self.store,'_connection',Connection()),self.assertRaisesRegex(PolicyError,'retained publication key unavailable'):
            self.runtime.put('a/key',b'TEST-ONLY staged value',secret_class='standard')


class TTYFallbackTests(unittest.TestCase):
    def test_lost_tty_cannot_fall_back_to_stdin_for_cloud_passphrase(self):
        import warnings
        read,write=os.pipe();tty=Mock();tty.fileno.return_value=read
        client=Mock();client.call.return_value=dict(ok=True,code='ok',result=dict(initialized=True))
        def fallback(*args,**kwargs):
            warnings.warn('TEST-ONLY getpass fallback',admin.getpass.GetPassWarning)
            return TEST_PASSPHRASE
        try:
            with warnings.catch_warnings(record=True):
                warnings.simplefilter('always',admin.getpass.GetPassWarning)
                with (patch.object(admin,'human_context_allowed',return_value=True),patch.object(admin,'AdminClient') as factory,
                    patch.object(admin.os,'open',return_value=write),patch.object(admin.os,'isatty',return_value=True),patch('builtins.open') as opened,
                    patch.object(admin.getpass,'getpass',side_effect=fallback),patch('sys.stderr',io.StringIO()),patch('sys.stdout',io.StringIO())):
                    factory.return_value.__enter__.return_value=client;opened.return_value.__enter__.return_value=tty
                    self.assertEqual(admin.main(['init','--cloud-broker']),69)
                    client.call.assert_not_called()
        finally:os.close(read)


class PendingPublicationRefusalTests(unittest.TestCase):
    setUp=RuntimeTests.setUp

    def test_pending_version_is_never_reported_as_a_completed_put(self):
        original=self.fake
        def legacy_pending(request):
            if request.url.endswith('/sync/versions'):
                payload=json.loads(request.body)
                payload['entries'][-1]['entry']['body']['state']='pending'
                entry=payload['entries'][-1]['entry']
                payload['entries'][-1]['sig']=crypto.b64url(crypto.p256_sign(self.fake.h.signing,crypto.policy_context(ORG,crypto.sha256(crypto.canonical_json(entry)).hex())))
                prepared=self.fake.h.client().prepare('POST',request.url,payload,logical_id=dict(request.headers)['TW-Request-Id'])
                return original(prepared)
            return original(request)
        self.runtime.transport_factory=lambda origin:legacy_pending
        with self.assertRaises(PolicyError) as caught:
            self.runtime.put('a/key',b'TEST-ONLY inactive publication',secret_class='standard')
        self.assertEqual(caught.exception.code,'E_ROTATION_UNAVAILABLE')
        self.runtime.transport_factory=lambda origin:original
        with self.assertRaises(PolicyError) as caught:
            self.runtime.put('a/key',b'TEST-ONLY inactive publication',secret_class='standard')
        self.assertEqual(caught.exception.code,'E_ROTATION_UNAVAILABLE')


class ConsistentMaterialPullTests(unittest.TestCase):
    setUp=RuntimeTests.setUp

    def test_honest_head_change_during_material_reads_is_retryable(self):
        original=self.runtime.call;changed=[False]
        def raced(client,method,path,body=None,query=None):
            if path=='sync/secrets' and not changed[0]:
                changed[0]=True
                self.fake.h.append(self.fake.h.entry('secret_create',dict(secret_id='TEST-ONLY-race',path='a/race',project='a',**{'class':'standard'})))
                self.fake.h.verifier.finish_history([],evidence=self.fake.h.proof,broker_id=BROKER)
            return original(client,method,path,body,query)
        with patch.object(self.runtime,'call',side_effect=raced),self.assertRaisesRegex(PolicyError,'head changed during material') as caught:
            self.runtime.pull()
        self.assertEqual(caught.exception.code,'E_SYNC_RETRY')
        self.assertEqual(self.runtime.sync().conflicts(),[])
        self.runtime.pull()
        self.assertEqual(self.runtime.sync().checkpoint()['head'],self.fake.h.verifier.head)

    def test_new_enrollment_cannot_use_synthetic_founder_or_changed_completion_head(self):
        self.store.connection.execute("UPDATE cloud_enrollments SET state='pinned'")
        with self.assertRaisesRegex(PolicyError,'logged certificate'):
            self.runtime.pull()
        self.assertEqual(self.store.connection.execute('SELECT state FROM cloud_enrollments').fetchone()[0],'pinned')

    def test_enrollment_completion_rechecks_local_head(self):
        self.store.connection.execute("UPDATE cloud_enrollments SET state='pinned'")
        sync=self.runtime.sync();checkpoint=sync.checkpoint;certificate=sync.certificate
        changed=[False]
        def checked():
            state=checkpoint()
            if changed[0]:state['head']=dict(seq=state['head']['seq']+1,hash='0'*64)
            return state
        def logged(*args,**kwargs):return dict(certificate(*args,**kwargs),source='certificate')
        paired=EnrollmentSession._paired_row
        def paired_then_raced(session,store,db):
            result=paired(session,store,db);changed[0]=True;return result
        with (patch.object(self.runtime,'sync',return_value=sync),patch.object(sync,'checkpoint',side_effect=checked),
              patch.object(sync,'certificate',side_effect=logged),patch.object(EnrollmentSession,'_paired_row',new=paired_then_raced),
              self.assertRaisesRegex(PolicyError,'enrollment head changed')):
            self.runtime.pull()
        self.assertEqual(self.store.connection.execute('SELECT state FROM cloud_enrollments').fetchone()[0],'pinned')


class CurrentEpochEnrollmentTests(unittest.TestCase):
    def test_join_completes_after_committed_rekey_replaces_initial_wraps(self):
        import test_cloud_public as public_fixtures
        from tw.cloud_http import verify_request
        from tw.policy_log import policy_record
        public_fixtures.PublicHistoryTests.setUpClass()
        fixture=public_fixtures.PublicHistoryTests()
        page=fixture.page();bundle=fixture.bundle(page);verified=fixture.replay(bundle)
        verified.finish_history([],evidence=bundle['evidence'],broker_id=page['broker_id'])
        doc=fixture.doc;org,broker=doc['org_id'],page['broker_id']
        record=next(row for row in page['tables']['enrollment_records'] if row['broker_id']==broker)
        transcript=json.loads(record['transcript_json'])
        signing=crypto.import_private(doc['test_only_keys']['signing_jwk']);exchange=crypto.import_private(doc['test_only_keys']['kx_jwk'])
        certificate=verified.authority_view().broker_certificate_at(broker,verified.head)
        epochs=verified.epoch_state
        wrap=next(row for row in epochs['org_wraps'] if row['recipient_kind']=='broker' and row['recipient_id']==broker)
        poll=dict(state='active',cert_seq=next(v['seq'] for v in verified.state['brokers'] if v['certificate']['broker_id']==broker),wraps=[dict(wrap,wrap_id='TEST-ONLY-current-epoch-wrap')],scoped_seals=[])
        now=fixture.cases['full-first-page']['input']['received_at']
        def transport(request):
            verify_request(request,org,broker,crypto.export_point(signing.public_key()),now)
            if request.url.endswith('/broker/enrollment'):result=poll
            elif request.url.endswith('/keys'):result=dict(omk_generation=epochs['generation'],my_wrap=wrap,keyring=epochs['keyring'])
            elif '/policy?' in request.url:result=dict(entries=[],head=verified.head,control_head=dict(seq=1,hash='1'*64))
            elif request.url.endswith('/sync/head'):result=dict(recorded=True)
            else:raise AssertionError('unexpected TEST-ONLY enrollment transport')
            return 200,crypto.canonical_json(dict(ok=True,code='ok',result=result))
        with tempfile.TemporaryDirectory() as temporary:
            with Store(temporary).open(create=True) as store:
                master,_=store.initialize(TEST_PASSPHRASE,argon2=TEST_ARGON2,cloud_broker=True)
                seal=SealManager(store);seal.unseal(TEST_PASSPHRASE)
                try:
                    session=EnrollmentSession(org,transcript,signing,exchange,broker_id=broker)
                    save_reservation(session,store,master,record['ticket_id'],record['proof'])
                    genesis=bundle['records'][1][0]
                    root=crypto.sha256(crypto.canonical_json(genesis)).hex()
                    words=crypto.sas_words(crypto.sas_context(org,root,'broker',broker,transcript['sign_pub'],transcript['kx_pub']))
                    session.pin(store,crypto.canonical_json(genesis),typed_words=words)
                    store.set_meta(CONFIG,crypto.canonical_json(dict(org=org,broker=broker,ticket=record['ticket_id'],origin='https://api.example.com',genesis=dict(entry=genesis,sig=bundle['records'][1][1]))).decode())
                    runtime=CloudRuntime(store,seal,transport_factory=lambda origin:transport,clock=lambda:now)
                    frames=[(policy_record(entry,None if sig is None else crypto.unb64url(sig),entry['ts']),bundle['stages'].get(seq),None,bundle['evidence']) for seq,(entry,sig) in bundle['records'].items()]
                    with patch.object(runtime,'fetch',return_value=(bundle,frames,[],[dict(secrets=[],versions=[],cursor=None)],['a','b'])):
                        runtime.pull()
                    self.assertEqual(store.connection.execute('SELECT state FROM cloud_enrollments').fetchone()[0],'complete')
                    self.assertEqual(epochs['generation'],2)
                    self.assertEqual(len(store.cloud_local_key(master,org=org,broker=broker,key_id='omk_2',purpose='omk',scope='*',generation=2)),32)
                finally:seal.seal()


class EnrollmentReadRaceTests(unittest.TestCase):
    setUp=RuntimeTests.setUp

    def test_enrollment_state_change_between_material_reads_is_retryable(self):
        original=self.runtime.call;polls=[0]
        def changed(client,method,path,body=None,query=None):
            if path=='broker/enrollment':
                polls[0]+=1
                if polls[0]==2:return dict(state='pending')
            return original(client,method,path,body,query)
        with patch.object(self.runtime,'call',side_effect=changed),self.assertRaisesRegex(PolicyError,'enrollment changed during pull') as caught:
            self.runtime.pull()
        self.assertEqual(caught.exception.code,'E_SYNC_RETRY')
        self.assertEqual(self.runtime.sync().conflicts(),[])


class PullContainmentTests(unittest.TestCase):
    setUp=RuntimeTests.setUp

    def test_decoder_exceptions_are_recorded_and_tick_can_pull_later_revoke(self):
        self.runtime.pull()
        for failure in (StopIteration(), IndexError(), AttributeError(), OverflowError(), RecursionError()):
            with self.subTest(failure=type(failure).__name__), patch.object(self.runtime,'fetch',side_effect=failure):
                self.runtime.next_attempt=0
                self.runtime.tick()
                self.assertEqual(self.runtime.last_code,'E_POLICY_CONFLICT')
                self.assertTrue(self.runtime.sync().conflicts())
        # Honest later signed changes are still fetched after a malformed read.
        self.fake.calls.clear()
        self.runtime.next_attempt=0
        self.runtime.tick()
        self.assertTrue(any('/policy?' in request.url for request in self.fake.calls))

    def test_policy_page_must_progress_before_another_request(self):
        original=self.runtime.call
        calls=[]
        def repeated(client,method,path,body=None,query=None):
            result=original(client,method,path,body,query)
            if path=='policy':
                calls.append(query)
                result['head']=dict(seq=1000000,hash='1'*64)
                if len(calls)>2:raise AssertionError('nonprogressing page fetched again')
            return result
        with patch.object(self.runtime,'call',side_effect=repeated),self.assertRaises(PolicyError):
            self.runtime.pull()
        self.assertLessEqual(len(calls),2)

    def test_evidence_continuation_is_bound_before_appending(self):
        original=self.runtime.call
        calls=[]
        def repeated(client,method,path,body=None,query=None):
            result=original(client,method,path,body,query)
            if path=='policy/evidence':
                calls.append(query)
                result['next_from_seq']=1
                if len(calls)>1:raise AssertionError('invalid continuation fetched again')
            return result
        with patch.object(self.runtime,'call',side_effect=repeated),self.assertRaises(PolicyError):
            self.runtime.pull()
        self.assertEqual(len(calls),1)

    def test_slow_network_does_not_hold_delivery_lock(self):
        import threading
        self.runtime.pull()
        entered,released=threading.Event(),threading.Event()
        original=self.runtime.fetch
        errors=[]
        def slow(client):
            entered.set()
            if not released.wait(3):raise RuntimeError('TEST-ONLY timed out')
            return original(client)
        def pull():
            try:self.runtime.pull()
            except Exception as error:errors.append(error)
        with patch.object(self.runtime,'fetch',side_effect=slow):
            worker=threading.Thread(target=pull);worker.start()
            try:
                self.assertTrue(entered.wait(1))
                acquired=self.runtime.lock.acquire(timeout=0.1)
                if acquired:self.runtime.lock.release()
                self.assertTrue(acquired,'slow fetch held delivery lock')
            finally:released.set();worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors,[])


class PullAdversarialTests(unittest.TestCase):
    setUp=RuntimeTests.setUp

    def test_invalid_signature_prefix_without_epoch_init_reaches_verifier(self):
        self.runtime.pull()
        original=self.runtime.call
        genesis=self.fake.h.frames[0][0]
        invalid=dict(self.fake.h.genesis,seq=2,prev_hash=genesis.hash,kind='secret_create',
            body=dict(secret_id='TEST-ONLY-invalid',path='a/invalid',project='a',**{'class':'standard'}))
        rows=[]
        for entry,sig in ((self.fake.h.genesis,genesis.signature),(invalid,bytes(64))):
            rows.append(dict(seq=entry['seq'],prev_hash=entry['prev_hash'],hash=wire.hash_object(entry),kind=entry['kind'],
                entry_json=crypto.canonical_json(entry).decode(),signer_kind=entry['signer']['kind'],
                signer_id=entry['signer']['id'],sig=crypto.b64url(sig)))
        head=dict(seq=2,hash=wire.hash_object(invalid))
        def malicious(client,method,path,body=None,query=None):
            result=original(client,method,path,body,query)
            if path=='policy':result.update(entries=rows if query['after']==0 else [],head=head)
            if path=='policy/evidence':result.update(head=head,public_staging=[],own_payloads=[])
            return result
        with patch.object(self.runtime,'call',side_effect=malicious):
            self.runtime.tick()
        self.assertEqual(self.runtime.last_code,'E_POLICY_CONFLICT')
        self.assertEqual([row['reason'] for row in self.runtime.sync().conflicts()],['bad_signature'])
        # A later honest request still runs, even while delivery stays conflicted.
        self.fake.calls.clear();self.runtime.next_attempt=0;self.runtime.tick()
        self.assertTrue(any('/policy?' in request.url for request in self.fake.calls))

    def test_tick_containment_allows_later_valid_signed_grant_revoke(self):
        from test_cloud_admin_policy import AdminPolicyTests
        history=AdminPolicyTests();history.setUp();history.base()
        history.append(history.entry('grant_add',history.grant()))
        revoke=history.entry('grant_revoke',dict(grant_id='grt_test_only'))
        with patch.object(self.runtime,'pull',side_effect=StopIteration()):self.runtime.tick()
        self.assertEqual(self.runtime.last_code,'E_POLICY_CONFLICT')
        self.runtime.next_attempt=0
        with patch.object(self.runtime,'pull',side_effect=lambda:history.append(revoke)) as pull:
            self.runtime.tick()
        pull.assert_called_once()
        self.assertTrue(history.verifier.state['admin_policy']['grants']['grt_test_only']['revoked'])
        self.assertIsNone(self.runtime.last_code)

    def test_one_budget_spans_all_response_types(self):
        for name,value,reason in [('MAX_PULL_BYTES',2000,'byte'),('MAX_PULL_PAGES',2,'page'),
                                  ('MAX_PULL_RECORDS',3,'record')]:
            with self.subTest(name=name),patch('tw.cloud_pull.'+name,value),self.assertRaises(PolicyError) as caught:
                self.runtime.pull()
            self.assertEqual(caught.exception.code,'E_SYNC_RETRY')
            self.assertIn(reason,str(caught.exception))
        self.assertEqual(self.runtime.sync().conflicts(),[])

    def test_elapsed_budget_aborts_before_next_page(self):
        now=[0.0];self.runtime.monotonic=lambda:now[0]
        original=self.fake
        def slow(request):
            result=original(request);now[0]+=11
            return result
        self.runtime.transport_factory=lambda origin:slow
        with self.assertRaisesRegex(PolicyError,'elapsed budget') as caught:self.runtime.pull()
        self.assertEqual(caught.exception.code,'E_SYNC_RETRY')
        self.assertEqual(len(self.fake.calls),2)
        self.assertEqual(self.runtime.sync().conflicts(),[])

    def test_maintenance_recovers_after_unexpected_tick_failure(self):
        from tw.broker import Broker
        broker=Broker.__new__(Broker);broker.home=self.store.home;broker.store=self.store;broker.seal=self.seal
        broker.cloud=SimpleNamespace(enabled=True,tick=Mock(side_effect=[StopIteration(),None]))
        broker.stop_event=Mock();broker.stop_event.wait.side_effect=[False,False,True]
        broker.service=Mock();broker.desk=None;broker.sealed_alert_sent=False;broker.started=0
        broker._verify_audit=Mock();broker._health=Mock(return_value={})
        broker.maintenance()
        self.assertEqual(broker.cloud.tick.call_count,2)
        self.assertEqual(broker._health.call_count,2)

    def test_slow_socket_does_not_block_names_run_inject_or_put(self):
        import threading
        from tw.broker import Broker
        self.runtime.pull()
        entered,released=threading.Event(),threading.Event()
        original=self.fake;errors=[]
        def socket_read(request):
            if '/policy?' in request.url:
                entered.set()
                if not released.wait(3):raise RuntimeError('TEST-ONLY slow socket timeout')
            return original(request)
        self.runtime.transport_factory=lambda origin:socket_read
        def pull():
            try:self.runtime.pull()
            except Exception as exc:errors.append(exc)
        broker=Broker.__new__(Broker);broker.cloud=self.runtime;broker.store=self.store
        broker._handle_agent_locked=lambda request,*args,**kwargs:dict(ok=True,op=request['op'])
        worker=threading.Thread(target=pull);worker.start()
        try:
            self.assertTrue(entered.wait(1))
            for op in ('names','run','inject','put'):
                self.assertTrue(broker.handle_agent(dict(op=op),[])['ok'])
            # A real put fails promptly and retryably behind the in-flight pull.
            with self.assertRaisesRegex(PolicyError,'already in progress'):
                self.runtime.put('a/next',b'TEST-ONLY value',secret_class='standard')
        finally:released.set();worker.join(3)
        self.assertEqual(errors,[])
        self.assertFalse(worker.is_alive())

    def test_fetch_streams_frames_and_spools_raw_pages(self):
        from tw.cloud_pull import PageSpool
        client=self.runtime.client()
        try:
            bundle,frames,blobs,pages,projects=self.runtime.fetch(client)
            self.assertTrue(callable(frames))
            self.assertIsInstance(pages,PageSpool)
            self.assertEqual(projects,[])
            self.assertEqual(len(list(frames())),bundle['head']['seq'])
        finally:
            for spool in client.spools:spool.close()


class PullDeadlineTests(unittest.TestCase):
    def test_absolute_deadline_interrupts_an_inflight_body_read(self):
        import time
        from tw.cloud_pull import PullBudget
        from tw.cloud_sync import PullRetry
        left,right=socket.socketpair()
        left.settimeout(1)
        connection=Mock();connection.sock=left
        response=connection.getresponse.return_value
        response.status=200;response.getheader.return_value=None
        response.read.side_effect=lambda size:left.recv(size)
        transport=HTTPSTransport('https://api.example.com',connection_factory=Mock(return_value=connection))
        with patch('tw.cloud_pull.MAX_PULL_SECONDS',0.05):transport.budget=PullBudget(time.monotonic)
        started=time.monotonic()
        try:
            with self.assertRaises((PullRetry,OSError)):
                transport(SignedRequest('https://api.example.com/v1/enroll','POST',(),b'{}'))
            self.assertLess(time.monotonic()-started,1)
        finally:left.close();right.close()

    def test_default_byte_budget_caps_individually_legal_responses(self):
        test=RuntimeTests();test.setUp()
        try:
            original=test.fake
            pages=[]
            def oversized(request):
                if '/policy?' not in request.url:return original(request)
                seq=len(pages)+1;pages.append(seq)
                row=dict(seq=seq,entry_json='x'*(2*1024*1024))
                return original.response(dict(entries=[row],head=dict(seq=5,hash='1'*64),control_head=dict(seq=1,hash='1'*64)))
            test.runtime.transport_factory=lambda origin:oversized
            with self.assertRaisesRegex(PolicyError,'byte or page budget') as caught:test.runtime.pull()
            self.assertEqual(caught.exception.code,'E_SYNC_RETRY')
            self.assertLess(len(pages),5)
            self.assertEqual(test.runtime.sync().conflicts(),[])
        finally:test.doCleanups()


class PullCommitRaceTests(unittest.TestCase):
    setUp=RuntimeTests.setUp

    def test_local_seal_race_retries_before_commit(self):
        self.runtime.pull();original=self.fake
        def raced(request):
            result=original(request)
            if request.url.endswith('/keys'):self.seal.seal()
            return result
        self.runtime.transport_factory=lambda origin:raced
        with self.assertRaises(PolicyError) as caught:self.runtime.pull()
        self.assertEqual(caught.exception.code,'E_SYNC_RETRY')
        self.assertEqual(self.runtime.sync().conflicts(),[])

    def test_local_head_race_retries_before_commit(self):
        self.runtime.pull();original=self.runtime.call
        old=self.runtime.sync().checkpoint()['head']
        def raced(client,method,path,body=None,query=None):
            result=original(client,method,path,body,query)
            if path=='policy' and query['after']>0:
                self.fake.h.append(self.fake.h.entry('secret_create',dict(secret_id='TEST-ONLY-local-race',path='a/race',project='a',**{'class':'standard'})))
                self.fake.h.verifier.finish_history([],evidence=self.fake.h.proof,broker_id=BROKER)
                self.store.save_cloud_replay(self.fake.h.verifier,expected_head=old)
            return result
        with patch.object(self.runtime,'call',side_effect=raced),patch('tw.cloud_sync.CloudSync.accept_pull',side_effect=AssertionError('unrechecked commit')) as commit:
            with self.assertRaises(PolicyError) as caught:self.runtime.pull()
        self.assertEqual(caught.exception.code,'E_SYNC_RETRY')
        commit.assert_not_called()
        self.assertEqual(self.runtime.sync().conflicts(),[])


class PullStreamingGuardTests(unittest.TestCase):
    setUp=RuntimeTests.setUp

    def test_evidence_binding_rejected_before_page_is_retained(self):
        from tw.cloud_pull import PageSpool
        original=self.runtime.call;append=PageSpool.append;retained=[]
        def substituted(client,method,path,body=None,query=None):
            result=original(client,method,path,body,query)
            if path=='policy/evidence':result['broker_id']='TEST-ONLY-other-broker'
            return result
        def tracked(spool,page):
            if page.get('schema')=='tw-policy-evidence-v1':retained.append(page)
            return append(spool,page)
        with patch.object(self.runtime,'call',side_effect=substituted),patch.object(PageSpool,'append',tracked):
            with self.assertRaises(PolicyError):self.runtime.pull()
        self.assertEqual(retained,[])

    def test_ciphertext_row_limit_is_checked_before_blob_extraction(self):
        original=self.runtime.call
        def oversized(client,method,path,body=None,query=None):
            result=original(client,method,path,body,query)
            if path=='sync/secrets':result['versions']=[dict(index=i) for i in range(101)]
            return result
        with patch.object(self.runtime,'call',side_effect=oversized),self.assertRaisesRegex(PolicyError,'ciphertext page rows exceeded'):
            self.runtime.pull()

    def test_replay_checks_deadline_between_records(self):
        from tw.cloud_public import PublicHistoryVerifier
        for index in range(2):
            self.fake.h.append(self.fake.h.entry('secret_create',dict(secret_id='TEST-ONLY-replay-'+str(index),path='a/replay'+str(index),project='a',**{'class':'standard'})))
        self.fake.h.verifier.finish_history([],evidence=self.fake.h.proof,broker_id=BROKER)
        now=[0.0];self.runtime.monotonic=lambda:now[0]
        verify=PublicHistoryVerifier.verify_record;verified=[]
        def elapsed(verifier,*args,**kwargs):
            result=verify(verifier,*args,**kwargs);verified.append(result);now[0]+=11
            return result
        with patch.object(PublicHistoryVerifier,'verify_record',elapsed),self.assertRaisesRegex(PolicyError,'elapsed budget'):
            self.runtime.pull()
        self.assertEqual(len(verified),2)

    def test_slow_publication_does_not_hold_delivery_locks(self):
        import threading
        original=self.fake;entered,released=threading.Event(),threading.Event();errors=[]
        def slow(request):
            if request.url.endswith('/sync/versions'):
                entered.set()
                if not released.wait(3):raise RuntimeError('TEST-ONLY publication timeout')
            return original(request)
        self.runtime.transport_factory=lambda origin:slow
        def put():
            try:self.runtime.put('a/slow',b'TEST-ONLY publication',secret_class='standard')
            except Exception as exc:errors.append(exc)
        worker=threading.Thread(target=put);worker.start()
        try:
            self.assertTrue(entered.wait(1))
            acquired=self.runtime.lock.acquire(timeout=0.1)
            if acquired:self.runtime.lock.release()
            self.assertTrue(acquired)
            acquired=self.store._transaction_lock.acquire(timeout=0.1)
            if acquired:self.store._transaction_lock.release()
            self.assertTrue(acquired)
        finally:released.set();worker.join(3)
        self.assertEqual(errors,[])
        self.assertFalse(worker.is_alive())


class PullDecodeCodeTests(unittest.TestCase):
    setUp=RuntimeTests.setUp

    def test_pull_records_every_cloud_decoder_failure(self):
        for error in (crypto.CryptoError,StopIteration,IndexError,AttributeError,OverflowError,RecursionError,ValueError,TypeError,KeyError):
            with self.subTest(error=error.__name__),patch.object(self.runtime,'fetch',side_effect=error):
                with self.assertRaises(PolicyError) as caught:self.runtime.pull()
                self.assertEqual(caught.exception.code,'E_POLICY_CONFLICT')
                self.assertEqual(self.runtime.last_code,'E_POLICY_CONFLICT')
                self.assertTrue(self.runtime.sync().conflicts())


class CloudEncodingContainmentTests(unittest.TestCase):
    setUp=RuntimeTests.setUp

    def check_encoding(self, path, corrupt):
        self.runtime.pull()
        self.runtime.put('a/key',b'TEST-ONLY malformed encoding canary',secret_class='standard')
        tables=('cloud_replay','cloud_sync_blobs','cloud_local_keys','cloud_enrollments',
                'cloud_head_observations','cloud_sync_state')
        def snapshot():
            return {name:[tuple(row) for row in self.store.connection.execute('SELECT * FROM '+name)] for name in tables}
        before=snapshot()
        def transport(request):
            status,body=self.fake(request)
            if request.url.split('?',1)[0].endswith('/'+path):
                response=json.loads(body)
                corrupt(response['result'])
                body=json.dumps(response).encode()
            return status,body
        self.runtime.transport_factory=lambda origin:transport
        with self.assertRaises(PolicyError) as caught:self.runtime.pull()
        self.assertEqual(caught.exception.code,'E_POLICY_CONFLICT')
        self.assertEqual(self.runtime.last_code,'E_POLICY_CONFLICT')
        self.assertEqual([row['reason'] for row in self.runtime.sync().conflicts()],['protocol_violation'])
        self.assertEqual(snapshot(),before)
        self.runtime.last_code=None
        self.runtime.tick()
        self.assertEqual(self.runtime.last_code,'E_POLICY_CONFLICT')
        self.assertEqual(self.runtime.next_attempt,130.)
        self.assertEqual(snapshot(),before)

        # Run the production maintenance loop on a real thread and observe it
        # still waiting for its next iteration after the malformed pull.
        from tw.broker import Broker
        broker=Broker.__new__(Broker);broker.home=self.store.home;broker.store=self.store;broker.seal=self.seal
        broker.cloud=self.runtime;broker.service=Mock();broker.desk=None
        stop=threading.Event();healthy=threading.Event()
        broker.stop_event=SimpleNamespace(wait=lambda seconds:stop.wait(.01))
        broker._verify_audit=Mock()
        broker._health=Mock(side_effect=lambda:healthy.set() or {})
        self.runtime.next_attempt=0;self.runtime.last_code=None
        worker=threading.Thread(target=broker.maintenance,daemon=True)
        worker.start()
        try:
            self.assertTrue(healthy.wait(3),'maintenance did not reach its health update')
            self.assertTrue(worker.is_alive())
            self.assertEqual(self.runtime.last_code,'E_POLICY_CONFLICT')
        finally:
            stop.set();worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(snapshot(),before)
        self.assertTrue(self.runtime.sync().conflicts())
        self.runtime.transport_factory=lambda origin:self.fake
        self.fake.calls.clear();self.runtime.next_attempt=0;self.runtime.tick()
        self.assertTrue(any('/policy?' in request.url for request in self.fake.calls))

    def test_malformed_signature_encoding(self):
        self.check_encoding('policy',lambda page:page['entries'][0].update(sig='%') if page['entries'] else None)

    def test_malformed_public_key_encoding(self):
        self.check_encoding('policy/evidence',lambda page:page['own_payloads'][0]['wraps'][0].update(eph_pub='04'+'00'*64))

    def test_malformed_ciphertext_encoding(self):
        self.check_encoding('sync/secrets',lambda page:page['versions'][0].update(ciphertext='%'))

    def test_malformed_cursor_encoding(self):
        self.check_encoding('sync/secrets',lambda page:page.update(cursor='%'))

    def test_malformed_evidence_encoding(self):
        self.check_encoding('policy/evidence',lambda page:page['own_payloads'][0]['keyring'][0].update(nonce='%'))

    def test_malformed_key_response_encoding(self):
        self.check_encoding('keys',lambda page:page['my_wrap'].update(eph_pub='%'))

    def test_local_enrollment_corruption_is_not_a_protocol_diagnostic(self):
        self.runtime.pull()
        self.store.connection.execute("UPDATE cloud_local_keys SET wrapped_key=? WHERE purpose='broker_sign'",(b'TEST-ONLY corrupt local key',))
        with self.assertRaisesRegex(StoreError,'local enrollment custody'):self.runtime.pull()
        self.assertIsNone(self.runtime.last_code)
        self.assertEqual(self.runtime.sync().conflicts(),[])

    def test_local_pickup_corruption_is_not_a_protocol_diagnostic(self):
        self.runtime.pull()
        self.store.connection.execute("UPDATE cloud_local_keys SET wrapped_key=? WHERE purpose='omk'",(b'TEST-ONLY corrupt local key',))
        with self.assertRaisesRegex(StoreError,'local pickup custody'):self.runtime.pull()
        self.assertIsNone(self.runtime.last_code)
        self.assertEqual(self.runtime.sync().conflicts(),[])

    def test_programming_errors_are_not_normalized(self):
        self.runtime.pull()
        with patch.object(self.runtime,'fetch',side_effect=RuntimeError('TEST-ONLY programming failure')):
            with self.assertRaises(RuntimeError):self.runtime.pull()
        self.assertIsNone(self.runtime.last_code)
        self.assertEqual(self.runtime.sync().conflicts(),[])


class ResolutionNetworkLockTests(unittest.TestCase):
    setUp=RuntimeTests.setUp

    def test_resolution_network_reads_release_delivery_lock(self):
        import threading
        self.runtime.pull();self.runtime.sync().refuse('fork',NOW)
        session=AdminSession();session.authenticate()
        arguments=dict(expected_head=self.runtime.sync().checkpoint()['head'],through_conflict=self.runtime.sync().conflicts()[-1]['conflict_id'],typed_root=self.fake.h.root)
        entered,released=threading.Event(),threading.Event();errors=[]
        fetch=self.runtime.fetch
        def slow(client):
            entered.set()
            if not released.wait(3):raise RuntimeError('TEST-ONLY resolution timeout')
            return fetch(client)
        def resolve():
            try:self.runtime.resolve(session,**arguments)
            except Exception as exc:errors.append(exc)
        with patch.object(self.runtime,'fetch',side_effect=slow):
            worker=threading.Thread(target=resolve);worker.start()
            try:
                self.assertTrue(entered.wait(1))
                acquired=self.runtime.lock.acquire(timeout=0.1)
                if acquired:self.runtime.lock.release()
                self.assertTrue(acquired)
            finally:released.set();worker.join(3)
        self.assertEqual(errors,[])
        self.assertFalse(worker.is_alive())


class BrokerPublicationLockTests(unittest.TestCase):
    setUp=RuntimeTests.setUp

    def test_agent_publication_runs_outside_both_delivery_locks(self):
        import threading
        from tw.broker import Broker
        self.runtime.pull()
        entered,released=threading.Event(),threading.Event();responses=[]
        def publish(*args,**kwargs):
            entered.set()
            if not released.wait(3):raise RuntimeError('TEST-ONLY broker publication timeout')
            return dict(path='a/slow',version_no=1,fingerprint_prefix='TESTONLY')
        broker=Broker.__new__(Broker);broker.cloud=self.runtime;broker.store=self.store;broker.seal=self.seal
        broker.service=SimpleNamespace(put=publish,authenticate=lambda *args: (dict(principal_id='TEST-ONLY'),None,None,SimpleNamespace(status='human')))
        request=dict(op='put',request_id='TEST-ONLY-broker-publication',args=dict(path='a/slow'))
        worker=threading.Thread(target=lambda:responses.append(broker.handle_agent(request,[])));worker.start()
        try:
            self.assertTrue(entered.wait(1))
            for lock in (self.runtime.lock,self.store._transaction_lock):
                acquired=lock.acquire(timeout=0.1)
                if acquired:lock.release()
                self.assertTrue(acquired)
        finally:released.set();worker.join(3)
        self.assertEqual(len(responses),1)
        self.assertTrue(responses[0]['ok'])
        self.assertIsNotNone(self.store.receipt(request['request_id'],op='put',principal_id='TEST-ONLY'))
