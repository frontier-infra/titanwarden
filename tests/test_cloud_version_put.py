"""P8 crash/retry, authority refresh and active-only delivery boundaries."""
from copy import deepcopy
import json
import tempfile
import sqlite3
import unittest
from unittest.mock import Mock, patch

import test_cloud_wiring as wiring
from tw import crypto
from tw.cloud_runtime import CloudRuntime
from tw.admin_server import AdminSession
from tw.cloud_sync import PullRetry
from tw.policy_log import PolicyError
from tw.seal import SealManager
from tw.store import Store
from support import TEST_PASSPHRASE


class VersionPutTests(unittest.TestCase):
    setUp = wiring.RuntimeTests.setUp

    def put(self, value=b'TEST-ONLY new version', **kw):
        return self.runtime.put('a/key', value, secret_class=kw.pop('secret_class','standard'), **kw)

    def writes(self, suffix):
        return [r for r in self.fake.calls if r.method == 'POST' and r.url.endswith(suffix)]

    def test_three_versions_and_only_active_delivery(self):
        for secret_class in ('standard','sensitive'):
            path='a/'+secret_class
            for n in range(1,4):
                value=('TEST-ONLY version '+str(n)).encode()
                self.assertEqual(self.runtime.put(path,value,secret_class=secret_class)['version_no'], n)
                self.assertEqual(self.runtime.read(path), value)
            state=self.runtime.sync().checkpoint()
            secret=next(s for s in state['epochs']['secrets'].values() if s['path']==path)
            versions=[v for v in state['epochs']['versions'] if v['secret_id']==secret['secret_id']]
            self.assertEqual([v['state'] for v in versions], ['retired','retired','active'])
            for v in versions[:2]:
                with self.assertRaisesRegex(PolicyError,'only the active version'):
                    self.runtime.sync().read_value(v['version_id'],self.master,now=wiring.NOW)

    def test_restricted_existing_name_requires_person_in_console(self):
        self.put(secret_class='restricted')
        count=len(self.writes('/sync/versions'))
        for value in (b'TEST-ONLY new version',b'TEST-ONLY restricted replacement'):
            with self.assertRaisesRegex(PolicyError,'person must activate.*console') as error:
                self.put(value,secret_class='restricted')
            self.assertEqual(error.exception.code,'E_ROTATION_UNAVAILABLE')
        self.assertEqual(len(self.writes('/sync/versions')),count)
        self.assertEqual(self.writes('/policy'),[])

    def test_revoked_put_grant_before_publication_and_before_activation(self):
        self.put(b'TEST-ONLY original')
        denied=PolicyError('E_DENIED','TEST-ONLY revoked grant')
        with self.assertRaises(PolicyError):
            self.put(authorize=Mock(side_effect=denied))
        self.assertEqual(len(self.writes('/sync/versions')),1)
        check=Mock(side_effect=[None,denied])
        with self.assertRaisesRegex(PolicyError,'revoked grant'):
            self.put(authorize=check)
        self.assertEqual(check.call_count,2)
        self.assertEqual(self.runtime.read('a/key'),b'TEST-ONLY original')
        self.assertEqual(self.writes('/policy'),[])
        pending=self.runtime.sync().checkpoint()['epochs']['versions'][-1]
        self.assertEqual(pending['state'],'pending')
        with self.assertRaisesRegex(PolicyError,'only the active version'):
            self.runtime.sync().read_value(pending['version_id'],self.master,now=wiring.NOW)
        self.assertEqual(self.put(authorize=Mock())['version_no'],2)
        self.assertEqual(len(self.writes('/sync/versions')),2)
        self.assertEqual(self.runtime.read('a/key'),b'TEST-ONLY new version')

    def test_ambiguous_pending_publication_resumes_same_version(self):
        self.put(b'TEST-ONLY original')
        self.fake.lose_publication_response=True
        with self.assertRaises(PullRetry):self.put()
        version=self.fake.h.verifier.epoch_state['versions'][-1]['version_id']
        self.assertEqual(self.put()['version_no'],2)
        self.assertEqual(len(self.writes('/sync/versions')),2)
        self.assertEqual(json.loads(self.writes('/policy')[0].body)['entry']['body']['version_id'],version)

    def test_ambiguous_accepted_activation_reconciles_without_duplicate(self):
        self.put(b'TEST-ONLY original')
        def transport(request):
            response=self.fake(request)
            if request.method=='POST' and request.url.endswith('/policy'):
                raise PullRetry('TEST-ONLY lost activation response')
            return response
        self.runtime.transport_factory=lambda origin:transport
        with self.assertRaises(PullRetry):self.put()
        self.runtime.transport_factory=lambda origin:self.fake
        self.assertEqual(self.put()['version_no'],2)
        self.assertEqual(len(self.writes('/policy')),1)
        self.assertEqual(len(self.writes('/sync/versions')),2)

    def test_unaccepted_activation_retry_after_restart_has_stable_request_and_bytes(self):
        self.put(b'TEST-ONLY original')
        lost=[]
        def transport(request):
            if request.method=='POST' and request.url.endswith('/policy'):
                lost.append(request)
                raise PullRetry('TEST-ONLY activation never reached cloud')
            return self.fake(request)
        self.runtime.transport_factory=lambda origin:transport
        with self.assertRaises(PullRetry):self.put()
        self.runtime=CloudRuntime(self.store,self.seal,transport_factory=lambda origin:self.fake,
            clock=lambda:wiring.NOW,monotonic=lambda:100.)
        self.assertEqual(self.put()['version_no'],2)
        accepted=self.writes('/policy')[-1]
        self.assertEqual(lost[0].body,accepted.body)
        self.assertEqual(dict(lost[0].headers)['TW-Request-Id'],dict(accepted.headers)['TW-Request-Id'])
        self.assertNotEqual(dict(lost[0].headers)['TW-Nonce'],dict(accepted.headers)['TW-Nonce'])
        self.assertEqual(len(self.writes('/sync/versions')),2)

    def second_writer(self):
        # Independent durable state and runtime, with the same TEST-ONLY broker
        # certificate, model two writers racing from a common verified prefix.
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        store = Store(temporary.name).open(create=True)
        self.addCleanup(store.close)
        self.store.connection.backup(store.connection)
        seal = SealManager(store)
        seal.unseal(TEST_PASSPHRASE)
        self.addCleanup(seal.seal)
        return CloudRuntime(store, seal, transport_factory=lambda origin:self.fake,
            clock=lambda:wiring.NOW, monotonic=lambda:100.)

    def retain_publication(self, value=b'TEST-ONLY retained value'):
        lost = []
        def transport(request):
            if request.method == 'POST' and request.url.endswith('/sync/versions'):
                lost.append(request)
                raise PullRetry('TEST-ONLY publication never reached cloud')
            return self.fake(request)
        self.runtime.transport_factory = lambda origin:transport
        with self.assertRaises(PullRetry):
            self.put(value)
        return lost[0]

    def restart(self):
        self.store.close()
        self.store.open()
        self.runtime = CloudRuntime(self.store, self.seal, transport_factory=lambda origin:self.fake,
            clock=lambda:wiring.NOW, monotonic=lambda:100.)

    def test_consumed_retained_version_after_restart_same_value(self):
        self.consumed_retained_version(b'TEST-ONLY retained value')

    def test_consumed_retained_version_after_restart_different_value(self):
        self.consumed_retained_version(b'TEST-ONLY changed value')

    def test_consumed_retained_version_with_later_accepted_number(self):
        self.consumed_retained_version(b'TEST-ONLY retained value', advance=True)

    def test_consumed_retained_version_on_selected_history(self):
        self.consumed_retained_version(b'TEST-ONLY retained value', selected=True)

    def consumed_retained_version(self, retry_value, advance=False, selected=False):
        self.put(b'TEST-ONLY original')
        if selected:
            sync = self.runtime.sync()
            sync.refuse('fork', wiring.NOW)
            session = AdminSession()
            session.authenticate()
            self.runtime.resolve(session, expected_head=sync.checkpoint()['head'],
                through_conflict=sync.conflicts()[-1]['conflict_id'], typed_root=self.fake.h.root)
        other = self.second_writer()
        lost = self.retain_publication()
        retained = json.loads(lost.body)
        if advance:
            other.put('a/key', b'TEST-ONLY earlier competing value', secret_class='standard')
        # A second writer consumes the retained number, or a later number,
        # with a valid signed pending version.
        denied = PolicyError('E_DENIED', 'TEST-ONLY stop before activation')
        with self.assertRaisesRegex(PolicyError, 'stop before activation'):
            other.put('a/key', b'TEST-ONLY competing value', secret_class='standard',
                authorize=Mock(side_effect=[None, denied]))
        self.restart()
        self.assertEqual(self.runtime.read('a/key'), b'TEST-ONLY original')
        expected_number = 4 if advance else 3
        self.assertEqual(self.put(retry_value)['version_no'], expected_number)
        fresh_request = self.writes('/sync/versions')[-1]
        fresh = json.loads(fresh_request.body)
        old_body, new_body = retained['entries'][-1]['entry']['body'], fresh['entries'][-1]['entry']['body']
        self.assertNotEqual(old_body['version_id'], new_body['version_id'])
        self.assertEqual(new_body['version_no'], expected_number)
        for field in ('value_digest', 'envelope_digest'):
            self.assertNotEqual(old_body[field], new_body[field])
        self.assertNotEqual(retained['version']['ciphertext'], fresh['version']['ciphertext'])
        self.assertNotEqual(dict(lost.headers)['TW-Request-Id'], dict(fresh_request.headers)['TW-Request-Id'])
        self.assertEqual(self.runtime.read('a/key'), retry_value)
        self.assertEqual(self.put(retry_value)['version_no'], expected_number)
        versions = self.runtime.sync().checkpoint()['epochs']['versions']
        self.assertEqual([v['state'] for v in versions], (['retired'] if advance else []) + ['retired', 'pending', 'active'])
        self.assertNotIn(old_body['version_id'], [v['version_id'] for v in versions])
        self.assertEqual(len(self.writes('/sync/versions')), 4 if advance else 3)
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM cloud_unpublished').fetchone()[0], 0)

    def test_consumed_row_deletion_and_pull_projection_are_atomic(self):
        self.put(b'TEST-ONLY original')
        other = self.second_writer()
        self.retain_publication()
        before = self.runtime.sync().checkpoint()['head']
        other.put('a/key', b'TEST-ONLY competing value', secret_class='standard')
        self.restart()
        self.store.connection.execute("CREATE TRIGGER test_only_discard_crash AFTER DELETE ON cloud_unpublished BEGIN SELECT RAISE(ABORT,'TEST-ONLY interrupted discard'); END")
        with self.assertRaisesRegex(sqlite3.IntegrityError, 'interrupted discard'):
            self.runtime.pull()
        self.assertEqual(self.runtime.sync().checkpoint()['head'], before)
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM cloud_unpublished').fetchone()[0], 1)
        self.store.connection.execute('DROP TRIGGER test_only_discard_crash')
        self.assertEqual(self.put()['version_no'], 3)

    def test_new_name_collision_after_restart_same_value(self):
        self.new_name_collision(b'TEST-ONLY retained value')

    def test_new_name_collision_after_restart_different_value(self):
        self.new_name_collision(b'TEST-ONLY changed value')

    def new_name_collision(self, retry_value):
        self.runtime.pull()
        other = self.second_writer()
        lost = self.retain_publication()
        retained = json.loads(lost.body)
        other.put('a/key', b'TEST-ONLY competing creation', secret_class='standard')
        self.restart()
        self.assertEqual(self.put(retry_value)['version_no'], 2)
        fresh_request = self.writes('/sync/versions')[-1]
        fresh = json.loads(fresh_request.body)
        self.assertNotEqual(retained['version']['secret_id'], fresh['version']['secret_id'])
        self.assertNotEqual(retained['version']['version_id'], fresh['version']['version_id'])
        self.assertNotEqual(retained['version']['ciphertext'], fresh['version']['ciphertext'])
        self.assertNotEqual(dict(lost.headers)['TW-Request-Id'], dict(fresh_request.headers)['TW-Request-Id'])
        self.assertEqual(len(fresh['entries']), 1)
        self.assertEqual(fresh['entries'][0]['entry']['body']['state'], 'pending')
        self.assertEqual(self.runtime.read('a/key'), retry_value)
        self.assertEqual(self.put(retry_value)['version_no'], 2)
        self.assertEqual([v['state'] for v in self.runtime.sync().checkpoint()['epochs']['versions']], ['retired', 'active'])
        self.assertEqual(len(self.writes('/sync/versions')), 2)
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM cloud_unpublished').fetchone()[0], 0)

    def test_retained_new_name_kept_without_proven_name_collision(self):
        self.runtime.pull()
        self.retain_publication()
        before = tuple(self.store.connection.execute('SELECT * FROM cloud_unpublished').fetchone())
        self.runtime.transport_factory = lambda origin:self.fake
        self.runtime.put('a/other', b'TEST-ONLY another name', secret_class='standard')
        self.restart()
        self.runtime.pull()
        self.assertEqual(tuple(self.store.connection.execute('SELECT * FROM cloud_unpublished').fetchone()), before)
        self.assertEqual(self.put(b'TEST-ONLY retained value')['version_no'], 1)

    def test_retained_row_kept_without_proven_consumed_number(self):
        self.put(b'TEST-ONLY original')
        lost = self.retain_publication()
        before = tuple(self.store.connection.execute('SELECT * FROM cloud_unpublished').fetchone())
        # A higher version of a different secret and an older version of the
        # same secret do not prove this retained publication impossible.
        self.runtime.transport_factory = lambda origin:self.fake
        self.runtime.put('b/other', b'TEST-ONLY other secret', secret_class='standard')
        self.runtime.put('b/other', b'TEST-ONLY other rotation', secret_class='standard')
        self.restart()
        self.runtime.pull()
        self.assertEqual(tuple(self.store.connection.execute('SELECT * FROM cloud_unpublished').fetchone()), before)
        self.fake.failure = PullRetry('TEST-ONLY withheld response')
        with self.assertRaises(PullRetry):
            self.runtime.pull()
        self.assertEqual(tuple(self.store.connection.execute('SELECT * FROM cloud_unpublished').fetchone()), before)
        self.fake.failure = None
        self.assertEqual(self.put(b'TEST-ONLY retained value')['version_no'], 2)
        self.assertEqual(json.loads(lost.body)['version']['version_id'],
            json.loads(self.writes('/sync/versions')[-1].body)['version']['version_id'])

    def test_scope_is_rechecked_for_rotation(self):
        self.put(b'TEST-ONLY original')
        sync=self.runtime.sync()
        cert=sync.certificate();cert['scope']=['b']
        with patch.object(self.runtime,'pull'),patch.object(self.runtime,'sync',return_value=sync),patch.object(sync,'certificate',return_value=cert):
            with self.assertRaises(PolicyError):self.put()
        self.assertEqual(len(self.writes('/sync/versions')),1)

    def test_single_active_delivery_check(self):
        self.put()
        sync=self.runtime.sync();state=deepcopy(sync.checkpoint())
        version=state['epochs']['versions'][0]
        state['epochs']['versions'].append(dict(version,version_id='TEST-ONLY-duplicate'))
        with patch.object(sync,'checkpoint',return_value=state):
            with self.assertRaisesRegex(PolicyError,'single active version'):
                sync.read_value(version['version_id'],self.master,now=wiring.NOW)

    def stage_pending(self):
        self.put(b'TEST-ONLY original')
        denied=PolicyError('E_DENIED','TEST-ONLY stop after publication')
        with self.assertRaises(PolicyError):self.put(authorize=Mock(side_effect=[None,denied]))
        return self.runtime.sync().checkpoint()['epochs']['versions'][-1]['version_id']

    def test_activation_local_guards_and_verified_result(self):
        vid=self.stage_pending()
        sync=self.runtime.sync();base=sync.checkpoint()
        for name,change,reason in [
            ('missing target',lambda s:s['epochs']['versions'].pop(),'no longer pending'),
            ('active target',lambda s:s['epochs']['versions'][-1].update(state='active'),'no longer pending'),
            ('restricted',lambda s:s['epochs']['secrets'][s['epochs']['versions'][-1]['secret_id']].update({'class':'restricted'}),'person must activate'),
            ('changed class',lambda s:s['epochs']['secrets'][s['epochs']['versions'][-1]['secret_id']].update({'class':'sensitive'}),'class changed before activation'),
            ('stale KEK',lambda s:s['epochs']['versions'][-1].update(kek_id='TEST-ONLY-stale'),'current project KEK'),
            ('missing predecessor',lambda s:s['epochs']['versions'][0].update(state='retired'),'one active predecessor'),
        ]:
            state=deepcopy(base);change(state)
            with self.subTest(check=name),patch.object(self.runtime,'sync',return_value=sync),patch.object(sync,'checkpoint',return_value=state):
                with self.assertRaisesRegex(PolicyError,reason):self.runtime._activate_version(vid,secret_class='standard',authorize=Mock())
        self.assertEqual(self.writes('/policy'),[])
        def transport(request):
            if request.method=='POST' and request.url.endswith('/policy'):
                return self.fake.response(dict(head=base['head']))
            return self.fake(request)
        self.runtime.transport_factory=lambda origin:transport
        with self.assertRaisesRegex(PolicyError,'awaiting verified pull'):
            self.runtime._activate_version(vid,secret_class='standard',authorize=Mock())

    def test_changed_head_rebuilds_activation_but_keeps_version_id(self):
        vid=self.stage_pending()
        attempts=[]
        def transport(request):
            if request.method=='POST' and request.url.endswith('/policy'):
                attempts.append(request)
                raise PullRetry('TEST-ONLY no activation admission')
            return self.fake(request)
        self.runtime.transport_factory=lambda origin:transport
        with self.assertRaises(PullRetry):self.put()
        self.fake.h.append(self.fake.h.entry('secret_create',dict(secret_id='TEST-ONLY-unrelated',path='b/unrelated',project='b',**{'class':'standard'})))
        self.runtime.transport_factory=lambda origin:self.fake
        self.put()
        final=self.writes('/policy')[-1]
        self.assertNotEqual(json.loads(attempts[0].body)['entry']['prev_hash'],json.loads(final.body)['entry']['prev_hash'])
        self.assertEqual(json.loads(final.body)['entry']['body']['version_id'],vid)
        self.assertNotEqual(dict(attempts[0].headers)['TW-Request-Id'],dict(final.headers)['TW-Request-Id'])
        self.assertEqual(len(self.writes('/sync/versions')),2)

    def test_published_pending_retry_cannot_change_caller_or_value(self):
        self.stage_pending()
        for principal,value,reason in [('other',b'TEST-ONLY new version','another principal'),
                ('human:operator',b'TEST-ONLY different bytes','another activation is pending')]:
            with self.subTest(principal=principal),self.assertRaisesRegex(PolicyError,reason):
                self.put(value,principal_id=principal)
        self.assertEqual(len(self.writes('/sync/versions')),2)
        self.assertEqual(self.writes('/policy'),[])

    def test_existing_secret_without_active_predecessor_stays_closed(self):
        self.put()
        sync=self.runtime.sync();state=deepcopy(sync.checkpoint())
        state['epochs']['versions'][0]['state']='pending'
        with patch.object(self.runtime,'sync',return_value=sync),patch.object(sync,'checkpoint',return_value=state):
            with self.assertRaisesRegex(PolicyError,'single active predecessor'):
                self.runtime._publish_version('a/key',b'TEST-ONLY unrelated',secret_class='standard')
