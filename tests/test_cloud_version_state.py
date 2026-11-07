"""P8 independent replay of production accepted bytes and signed refusals."""
from copy import deepcopy
import unittest

from tw.cloud_epochs import epoch_checkpoint
from tw.policy_log import PolicyError
from admin_cloud_fixtures import Replay
from version_state_cloud_fixtures import document


class ActivationReplay(Replay):
    def install(self, items):
        # Exporter uses the internal table name; public evidence renames it.
        super().install([dict(item, table='enrollment_binding_evidence')
            if item['table'] == 'enrollment_wrap_digests' else item for item in items])


class VersionStateFixtureTests(unittest.TestCase):
    def history(self, count=None):
        base, data = document()
        replay = ActivationReplay(base)
        for row in base['records']:
            replay.append(row)
        for row in data['records'][:count]:
            if row['entry']['kind'] == 'broker_cert':
                # The fixture exports these encrypted boxes in final_epoch;
                # certificate digests, not this transport placement, bind them.
                cert = row['entry']['body']['requested']
                replay.blobs['broker_key_wraps'] = [dict(w, wrap_id=next(c['id'] for c in cert['wrap_digests']
                    if c['digest'] == w['wrap_digest'])) for w in data['final_epoch']['broker_wraps']]
            replay.append(row)
            self.assertEqual(replay.authority(), row['expected']['authority_core'])
        return replay, data

    def test_accepted_history_and_retired_projection(self):
        replay, data = self.history()
        self.assertEqual(epoch_checkpoint(replay.replay.epoch_state), data['final_epoch'])
        actual = {v['version_id']:v['state'] for v in replay.replay.epoch_state['versions']}
        self.assertEqual(actual, {v['version_id']:v['state'] for v in data['final_versions']})
        self.assertEqual(list(actual.values()).count('retired'), 2)
        self.assertEqual(list(actual.values()).count('active'), 4)
        self.assertEqual(len(data['records']), 14)

    def test_replay_owned_policy_history_spends_activation_challenge(self):
        # Unit boundary: a replay-owned, already verified record carries a
        # spent activation proof, even though it is outside authority core.
        _, data = document()
        index = len(data['records'])-1
        replay, _ = self.history(index)
        row = data['records'][index]
        replay.replay._records.append(deepcopy(row['entry']))
        with self.assertRaisesRegex(PolicyError, 'Authorization binding or validity failed'):
            replay.append(row)

    def test_all_signed_negative_cases_preserve_history(self):
        _, data = document()
        for case in data['cases']:
            with self.subTest(case=case['id']):
                replay, _ = self.history(case['prefix_length'])
                before = deepcopy((replay.replay.state, replay.replay.epoch_state, replay.replay.request_state))
                with self.assertRaises(PolicyError):
                    replay.append(case['record'])
                self.assertEqual((replay.replay.state, replay.replay.epoch_state, replay.replay.request_state), before)
        self.assertEqual(len(data['cases']), 18)


class ActivationGuardTests(unittest.TestCase):
    def setUp(self):
        self.state=dict(secrets={'s':dict(secret_id='s',project='a',state='active',**{'class':'standard'})},
            active_kek={'a':'k'},versions=[dict(version_id='old',secret_id='s',project='a',state='active',version_no=1,kek_id='k'),
                dict(version_id='new',secret_id='s',project='a',state='pending',version_no=2,kek_id='k')])
        self.entry=dict(kind='version_state',signer=dict(kind='broker',id='b'),body=dict(secret_id='s',version_id='new',
            from_state='pending',to_state='active',supersedes_version_id='old'))
        self.snapshot=dict(projects=['a'],brokers=[dict(id='b',scope=['a'])],members=[])

    def test_success_and_every_activation_guard(self):
        from tw.cloud_version_state import activate
        from tw.cloud_epochs import EpochReplay
        base=deepcopy(self.state)
        activate(self.state,self.entry,self.snapshot)
        self.assertEqual([v['state'] for v in self.state['versions']],['retired','active'])
        cases=[
            ('missing',lambda s,e,p:e['body'].pop('secret_id')),
            ('extra',lambda s,e,p:e['body'].update(extra=True)),
            ('identity type',lambda s,e,p:e['body'].update(version_id=1)),
            ('empty identity',lambda s,e,p:e['body'].update(version_id='')),
            ('long identity',lambda s,e,p:e['body'].update(version_id='x'*2049)),
            ('from',lambda s,e,p:e['body'].update(from_state='active')),
            ('to',lambda s,e,p:e['body'].update(to_state='retired')),
            ('unpaired authz',lambda s,e,p:e['body'].update(authz={})),
            ('unpaired assertion',lambda s,e,p:e['body'].update(assertion={})),
            ('unknown secret',lambda s,e,p:e['body'].update(secret_id='unknown')),
            ('inactive secret',lambda s,e,p:s['secrets']['s'].update(state='destroyed')),
            ('secret class',lambda s,e,p:s['secrets']['s'].update({'class':'unknown'})),
            ('standard proof',lambda s,e,p:e['body'].update(authz={},assertion={})),
            ('restricted missing proof',lambda s,e,p:s['secrets']['s'].update({'class':'restricted'})),
            ('unknown target',lambda s,e,p:e['body'].update(version_id='absent')),
            ('unknown prior',lambda s,e,p:e['body'].update(supersedes_version_id='absent')),
            ('target secret',lambda s,e,p:s['versions'][1].update(secret_id='other')),
            ('prior secret',lambda s,e,p:s['versions'][0].update(secret_id='other')),
            ('target project',lambda s,e,p:s['versions'][1].update(project='b')),
            ('prior project',lambda s,e,p:s['versions'][0].update(project='b')),
            ('same identity',lambda s,e,p:e['body'].update(supersedes_version_id='new')),
            ('active target',lambda s,e,p:s['versions'][1].update(state='active')),
            ('retired target',lambda s,e,p:s['versions'][1].update(state='retired')),
            ('pending prior',lambda s,e,p:s['versions'][0].update(state='pending')),
            ('retired prior',lambda s,e,p:s['versions'][0].update(state='retired')),
            ('duplicate active',lambda s,e,p:s['versions'].append(dict(s['versions'][0],version_id='duplicate'))),
            ('equal number',lambda s,e,p:s['versions'][1].update(version_no=1)),
            ('backward number',lambda s,e,p:s['versions'][0].update(version_no=3)),
            ('bool number',lambda s,e,p:s['versions'][0].update(version_no=True)),
            ('unsafe number',lambda s,e,p:s['versions'][1].update(version_no=9007199254740992)),
            ('zero number',lambda s,e,p:s['versions'][0].update(version_no=0)),
            ('missing KEK',lambda s,e,p:s['active_kek'].clear()),
            ('stale KEK',lambda s,e,p:s['active_kek'].update(a='new-kek')),
            ('outside scope',lambda s,e,p:p['brokers'][0].update(scope=['b'])),
            ('uncertified broker',lambda s,e,p:p['brokers'].clear()),
            ('derived signer',lambda s,e,p:e.update(signer=dict(kind='derived'))),
            ('restricted broker',lambda s,e,p:(s['secrets']['s'].update({'class':'restricted'}),e['body'].update(authz={'v':2},assertion={}))),
        ]
        for name,mutate in cases:
            with self.subTest(check=name):
                state,entry,snapshot=deepcopy((base,self.entry,self.snapshot))
                mutate(state,entry,snapshot)
                snapshot['head']=dict(seq=1,hash='1'*64)
                entry.update(v=2,org_id='a'*32,seq=2,prev_hash='1'*64,ts='2026-10-17T08:00:00.000Z')
                replay=EpochReplay();replay._state=deepcopy(state)
                with self.assertRaisesRegex((ValueError,PolicyError), 'Invalid version identity' if 'identity' in name and name != 'same identity' else '.'):
                    replay.apply(entry,snapshot)
                self.assertEqual(replay.state,state)

    def test_restricted_proof_is_bound_spent_and_uses_predecessor_certificate(self):
        from tw.cloud_version_state import authorize
        helper=VersionStateFixtureTests()
        _,data=document()
        index=next(i for i,r in enumerate(data['records']) if r['id']=='restricted-activate')
        replay,_=helper.history(index)
        state=replay.replay.state
        entry=data['records'][index]['entry']
        runtime=dict(mode='history',now=entry['ts'],observations=dict(heads=[],proposals={}))
        valid=deepcopy(state)
        authorize(entry,valid,runtime)
        self.assertIn(entry['body']['authz']['challenge'],valid['used_challenges'])
        with self.assertRaises((ValueError,PolicyError)):authorize(entry,valid,runtime)
        for key,value in [('request_id','wrong'),('op','secret_update'),('target',dict(secret_id='wrong',version_id='wrong')),
                ('core_change_sha256','0'*64),('policy_head',dict(seq=1,hash='0'*64))]:
            bad=deepcopy(entry);bad['body']['authz'][key]=value
            with self.subTest(binding=key),self.assertRaises((ValueError,PolicyError)):authorize(bad,deepcopy(state),runtime)
        for field,value in [('key_holder',False),('state','removed'),('member_id','other')]:
            bad=deepcopy(state)
            cert=next(v['certificate'] for v in bad['certificates'] if v['certificate']['member_key_id']==entry['signer']['key'])
            cert[field]=value
            with self.subTest(certificate=field),self.assertRaises((ValueError,PolicyError)):authorize(entry,bad,runtime)
        broker=deepcopy(entry);broker['signer']=dict(kind='broker',id='b')
        with self.assertRaises((ValueError,PolicyError)):authorize(broker,deepcopy(state),runtime)
