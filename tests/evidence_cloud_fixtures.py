"""Real cloud handler evidence bytes, SHA-checked before parsing."""
from pathlib import Path
from tw import crypto
from tw.cloud_wire import load_pinned_json

REVISION='74bf35dc5984db091fdc072356436311285a6b45'
SHA256='b852f4e34f69349411cde3d1ca3a907cd7e83bc3a5ea10e2f424c8d19ed716e4'
PATH=Path(__file__).parent/'fixtures/cloud'/REVISION/'core/vectors/broker-policy-evidence-v1.json'


def document():
    result=load_pinned_json(PATH,SHA256)
    if result['profile']!='production' or result['production_acceptable'] is not True:
        raise ValueError('production cloud handler fixture required')
    return result


def records(document):
    scenario=document['scenarios'][0]
    rows={r['entry']['seq']:r for r in scenario['setup'][0]['records']}
    for step in scenario['setup'][1:]:
        encoded=step.get('request',{}).get('body_b64')
        if encoded is None:continue
        body=crypto.parse_canonical(crypto.unb64url(encoded))
        for signed in body.get('entries',[body] if 'entry' in body and 'sig' in body else []):
            rows[signed['entry']['seq']]=signed
    return [dict(seq=seq,prev_hash=row['entry']['prev_hash'],hash=crypto.sha256(crypto.canonical_json(row['entry'])).hex(),
        kind=row['entry']['kind'],entry_json=crypto.canonical_json(row['entry']).decode(),
        signer_kind=row['entry']['signer']['kind'],signer_id=row['entry']['signer'].get('id'),sig=row.get('sig')) for seq,row in sorted(rows.items())]
