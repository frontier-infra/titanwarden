"""Real SQLite public resolver views in locally assembled transport envelopes."""
from copy import deepcopy
from pathlib import Path
import json
import unittest

from tw import crypto
from tw.cloud_public import TABLES,decode_evidence,PublicHistoryVerifier
from tw.cloud_epochs import epoch_checkpoint,epoch_blob_commitments,keyring_digest
from tw.cloud_wire import load_pinned_json
from tw.policy_log import policy_record,PolicyError
from paired_cloud_fixtures import PairedReplay

REVISION='74bf35dc5984db091fdc072356436311285a6b45'
SHA256='fb1bd95ac1292c7a9027db57ec7b19f8c3dae312bc3444fb90e966aaee0f9fdc'
PATH=Path(__file__).parent/'fixtures/cloud'/REVISION/'core/vectors/broker-policy-evidence-pages-v1.json'
SOURCE=Path(__file__).parent/'fixtures/cloud'/REVISION/'core/vectors/broker-epoch-pages-v2.json'


class PublicPagesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=load_pinned_json(PATH,SHA256)
        if cls.data['profile']!='production' or cls.data['production_acceptable'] is not True:
            raise ValueError('production resolver fixture required')
        cls.source=load_pinned_json(SOURCE,cls.data['source_sha256'])
        cls.views={case['id']:json.loads(case['response']['body'])['result'] for case in cls.data['cases']}

    def packet(self,case,*,bad_view=None):
        prefix=self.source['records'][:case['through_seq']]
        reference=PairedReplay(self.source)
        for record in prefix:self.assertEqual(reference.run(record)['status'],'accepted')
        public,own,rows=[],[],[]
        for record in prefix:
            entry=record['entry'];seq=entry['seq'];body=entry['body']
            rows.append(dict(seq=seq,prev_hash=entry['prev_hash'],hash=record['hash'],kind=entry['kind'],
                entry_json=bytes.fromhex(record['canonical_hex']).decode(),signer_kind=entry['signer']['kind'],signer_id=entry['signer'].get('id'),sig=record['sig']))
            if entry['kind'] not in ('epoch_init','epoch_rotate','epoch_commit'):continue
            intent=prefix[body['epoch_seq']-1]['entry'] if entry['kind']=='epoch_commit' else entry
            plan,fence=('__epoch_init__',0) if entry['kind']=='epoch_init' else (intent['body']['plan_id'],intent['body']['fence'])
            stage=json.loads(next(row for row in reference.blobs['epoch_staging'] if row['plan_id']==plan and row['fence']==fence)['payload_json'])
            if entry['kind']=='epoch_init':
                view=dict(schema='tw-epoch-public-v1',policy_seq=seq,plan_id=plan,fence=fence,created_at=entry['ts'],
                    keyring=body['keyring'],keyring_metadata=[{k:row[k] for k in ('key_id','purpose','project','version','mk_generation','aad_v')} for row in stage['keyring']],
                    recipients=body['recipients'],scoped_seals=body['scoped_seals'])
                keys=stage['keyring']
            else:
                label='committed' if intent['seq']==4 and case['through_seq']>=6 else 'pending' if intent['seq']==4 else case['id']
                view=deepcopy(bad_view if bad_view is not None and label=='pending' else self.views[label])
                view['policy_seq']=seq
                keys=stage['keyring'] if intent['seq']==4 and case['through_seq']>=6 else []
            public.append(view)
            own.append(dict(policy_seq=seq,plan_id=plan,fence=fence,keyring=keys,wraps=[],scoped_seals=[]))
        packet=dict(schema='tw-policy-evidence-v1',org_id=self.source['org_id'],broker_id='TEST-ONLY-public-recipient',scope='full',head=case['head'],
            from_seq=1,through_seq=case['through_seq'],next_from_seq=None,control_head=dict(seq=1,hash='1'*64),public_staging=public,own_payloads=own,
            tables={table:[] for table in TABLES})
        return packet,rows,reference

    def test_pending_committed_cancelled_cleanup_and_restart(self):
        for case in self.data['cases']:
            with self.subTest(id=case['id']):
                packet,rows,reference=self.packet(case)
                bundle=decode_evidence([packet],rows,org=self.source['org_id'],broker=packet['broker_id'])
                verifier=PublicHistoryVerifier(self.source['org_id'],self.source['pinned_root'],projects=['a','b'])
                for seq,(entry,sig) in bundle['records'].items():
                    verifier.verify_record(policy_record(entry,None if sig is None else crypto.unb64url(sig),entry['ts']),stage=bundle['stages'].get(seq),
                        evidence=bundle['evidence'],runtime=dict(mode='history',now=entry['ts'],observations=dict(heads=[],proposals={})))
                self.assertEqual(verifier.head,case['head'])
                actual={row['id']:row['digest'] for row in epoch_blob_commitments(verifier.epoch_state)}
                expected={row['id']:row['digest'] for row in epoch_blob_commitments(reference.replay.epoch_state)}
                self.assertEqual(actual,expected)
                public=epoch_checkpoint(verifier.epoch_state);full=epoch_checkpoint(reference.replay.epoch_state)
                for field in ('keyring','org_wraps','broker_wraps'):
                    public.pop(field);full.pop(field)
                self.assertEqual(public,full)
                # This source history has no enrolled broker. Public replay is
                # not allowed to certify synthetic delivery custody.
                with self.assertRaisesRegex(ValueError,'certified public history broker'):
                    verifier.finish_history([],evidence=bundle['evidence'],broker_id=packet['broker_id'])

    def test_recipient_array_must_match_signed_digest(self):
        case=next(case for case in self.data['cases'] if case['id']=='pending')
        bad=self.data['client_refusals'][0]['response']['result']
        packet,rows,_=self.packet(case,bad_view=bad)
        with self.assertRaisesRegex(ValueError,'public recipient commitment mismatch'):
            decode_evidence([packet],rows,org=self.source['org_id'],broker=packet['broker_id'])
