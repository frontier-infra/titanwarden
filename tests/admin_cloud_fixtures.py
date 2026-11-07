"""SHA-checked W21 production administration history from an immutable commit."""
from pathlib import Path
from copy import deepcopy
from tw import crypto
from tw.cloud_wire import load_pinned_json
from tw.cloud_public import PublicHistoryVerifier,PublicEvidence
from tw.policy_log import policy_record
from test_cloud_recovery import RecoveryPairedReplay
from test_cloud_policy import cloud_authority_projection

REVISION='b9e8e22db38fa2b4b1c6205befd36b0dd8c983a4'
SHA256='380a5d0a6893129de6ed7fbb7f2facde7c5ac23797ee23ff700fcdfe63bd7987'
ROOT=Path(__file__).parent/'fixtures/cloud'/REVISION/'core/vectors'
PATH=ROOT/'broker-admin-policy-v1.json'
MANIFEST_SHA='c60881fe619ac24aac49c253222c7585c2722c75c3ef254d9435698f98fc4ee7'


def document():
    manifest=load_pinned_json(ROOT/'paired-broker-manifest-admin-v1.json',MANIFEST_SHA)
    data=load_pinned_json(PATH,SHA256)
    item=next(item for item in manifest['files'] if item['file']==PATH.name)
    if item['sha256']!=SHA256 or item['records']!=len(data['records']) or item['cases']!=len(data['cases']):
        raise ValueError('admin manifest contract differs')
    if manifest['revision']!=3 or data['revision']!=3:
        raise ValueError('admin revision 3 required')
    if data['profile']!='production' or data['production_acceptable'] is not True:
        raise ValueError('production admin fixture required')
    return data


class Replay(RecoveryPairedReplay):
    def __init__(self,data):
        super().__init__(data)
        projects=next(r['entry']['body']['active_kek'] for r in data['records'] if r['entry']['kind']=='epoch_init')
        self.replay=PublicHistoryVerifier(data['org_id'],data['pinned_root'],projects=projects)

    def append(self,row):
        self.install(row['evidence'])
        entry=row['entry']
        evidence=PublicEvidence(self.rows,self.blobs,request_facts={})
        blob=self.ciphertext(next(r for r in self.blobs.get('secret_versions',[]) if r['version_id']==entry['body'].get('version_id'))) if entry['kind']=='version_add' else None
        raw=crypto.canonical_json(entry)
        if raw.hex()!=row['canonical_hex'] or crypto.sha256(raw).hex()!=row['hash']:
            raise AssertionError('cloud supplied canonical entry bytes differ')
        return self.replay.verify_record(policy_record(entry,None if row['sig'] is None else crypto.unb64url(row['sig']),row['received_at']),
            stage=self.stage(entry),blob=blob,evidence=evidence,runtime=dict(mode='history',now=row['received_at'],observations=dict(heads=[],proposals={})))

    def authority(self):
        state=cloud_authority_projection(self.replay.state)
        state.pop('admin_policy',None)
        protocol=state.pop('recovery_protocol',{})
        state['retired_recovery_points']=dict(sign_pub=protocol.get('used_recovery_sign_keys',[]),kx_pub=protocol.get('used_recovery_exchange_keys',[]))
        return state
