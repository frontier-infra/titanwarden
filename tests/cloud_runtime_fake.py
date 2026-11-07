"""TEST-ONLY deterministic fake cloud. No production or deployed credentials."""
from copy import deepcopy
import json
from urllib.parse import urlsplit,parse_qs

from tw import crypto
from tw.cloud_http import verify_request
from tw.cloud_public import TABLES
from tw.policy_log import policy_record
from test_cloud_sync import SyncTests,ORG,BROKER,NOW


class FakeCloud:
    def __init__(self):
        self.harness=SyncTests()
        self.harness.setUp()
        self.h=self.harness
        self.calls=[]
        self.blobs=[]
        self.pending=False
        self.failure=None
        self.after_fetch=None
        self.lose_publication_response=False

    def close(self):
        self.harness.doCleanups()

    def response(self,result):
        return 200,json.dumps(dict(ok=True,code='ok',result=result)).encode()

    def __call__(self,request):
        self.calls.append(request)
        if self.failure:
            raise self.failure
        verify_request(request,ORG,BROKER,self.h.public,NOW)
        path=urlsplit(request.url).path.split('/'+ORG+'/')[1]
        state=self.h.verifier.epoch_state
        head=self.h.verifier.head
        if path=='broker/enrollment':
            return self.response(dict(state='pending') if self.pending else dict(state='active',cert_seq=2,wraps=[],scoped_seals=[]))
        if path=='policy' and request.method == 'GET':
            after=int(parse_qs(urlsplit(request.url).query).get('after',['0'])[0])
            rows=[]
            for record,stage,blob,evidence in self.h.frames:
                e=json.loads(record.data)
                if e['seq']<=after:continue
                rows.append(dict(seq=e['seq'],prev_hash=e['prev_hash'],hash=record.hash,
                    kind=e['kind'],entry_json=record.data.decode(),signer_kind=e['signer']['kind'],
                    signer_id=e['signer'].get('id'),sig=None if record.signature is None else crypto.b64url(record.signature)))
            return self.response(dict(entries=rows,head=head,control_head=dict(seq=1,hash='1'*64)))
        if path=='policy/evidence':
            public,own=[],[]
            for record,stage,blob,evidence in self.h.frames:
                if stage is None:continue
                e=json.loads(record.data);b=e['body']
                public.append(dict(schema='tw-epoch-public-v1',policy_seq=e['seq'],plan_id='__epoch_init__',fence=0,
                    created_at=e['ts'],keyring=b['keyring'],keyring_metadata=[{k:r[k] for k in ('key_id','purpose','project','version','mk_generation','aad_v')} for r in stage['keyring']],
                    recipients=b['recipients'],scoped_seals=b['scoped_seals']))
                own.append(dict(policy_seq=e['seq'],plan_id='__epoch_init__',fence=0,**stage))
            return self.response(dict(schema='tw-policy-evidence-v1',org_id=ORG,broker_id=BROKER,scope='full',head=head,
                from_seq=1,through_seq=head['seq'],next_from_seq=None,control_head=dict(seq=1,hash='1'*64),
                public_staging=public,own_payloads=own,tables={name:[] for name in TABLES}))
        if path=='sync/secrets':
            rows=[]
            for blob in self.blobs:
                metadata=next(v for v in state['versions'] if v['version_id']==blob['version_id'])
                rows.append(dict(blob,**{k:metadata[k] for k in ('version_no','state','fingerprint','length','source','envelope_digest')},ciphertext_digest=metadata['value_digest']))
            return self.response(dict(secrets=list(state['secrets'].values()),versions=rows,cursor=None))
        if path=='keys':
            if self.after_fetch:self.after_fetch()
            return self.response(dict(omk_generation=state['generation'],my_wrap=state['org_wraps'][0],keyring=state['keyring']))
        if path=='sync/head':return self.response(dict(recorded=True))
        if path=='policy' and request.method == 'POST':
            signed=json.loads(request.body)
            e=signed['entry'];record=policy_record(e,crypto.unb64url(signed['sig']),NOW)
            self.h.verifier.verify_record(record,evidence=self.h.proof)
            self.h.frames.append((record,None,None,self.h.proof))
            self.h.verifier.finish_history(self.blobs,evidence=self.h.proof,broker_id=BROKER)
            return self.response(dict(head=self.h.verifier.head))
        if path=='sync/versions':
            body=json.loads(request.body);blob=body['version']
            for signed in body['entries']:
                e=signed['entry'];record=policy_record(e,crypto.unb64url(signed['sig']),NOW)
                self.h.verifier.verify_record(record,blob=blob if e['kind']=='version_add' else None,evidence=self.h.proof)
                self.h.frames.append((record,None,blob if e['kind']=='version_add' else None,self.h.proof))
            self.blobs.append(blob)
            self.h.verifier.finish_history(self.blobs,evidence=self.h.proof,broker_id=BROKER)
            if self.lose_publication_response:
                self.lose_publication_response=False
                from tw.cloud_sync import PullRetry
                raise PullRetry('TEST-ONLY lost publication response')
            return self.response(dict(head=self.h.verifier.head))
        raise AssertionError('unexpected TEST-ONLY cloud route '+path)
