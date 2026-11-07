"""Local enrollment ceremony and custody acceptance, without a production caller."""
from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field

from . import crypto, cloud_wire as wire
from .cloud_policy import AuthorityEvidence
from .policy_log import OfflineCloudVerifier, parse_entry


def checked_transcript(value: object) -> dict:
    # Share the existing offline verifier's strict cloud transcript contract.
    result = AuthorityEvidence._transcript(value)
    if result['mode'] == 'adopt' and 'store_id' not in result:
        raise ValueError('adopt transcript requires store_id')
    return result


def ticket_id(ticket_code: str) -> str:
    if not isinstance(ticket_code, str) or not re.fullmatch(r'enr_[a-z2-7]{12}\.[a-z2-7]{26}', ticket_code):
        raise ValueError('invalid enrollment ticket')
    # 128 bits in 26 base32 characters leave two zero padding bits.
    import base64
    import binascii
    suffix = ticket_code.split('.')[1]
    try:
        raw = base64.b32decode(suffix.upper() + '======')
    except binascii.Error as exc:
        raise ValueError('invalid enrollment ticket') from exc
    if base64.b32encode(raw).decode().lower().rstrip('=') != suffix:
        raise ValueError('noncanonical enrollment ticket')
    return ticket_code.split('.')[0]


def proof_message(org: str, ticket: str, transcript: dict, candidate_root: str | None = None) -> bytes:
    wire.org_id(org)
    if not re.fullmatch(r'enr_[a-z2-7]{12}', ticket):
        raise ValueError('invalid ticket id')
    transcript = checked_transcript(transcript)
    value = transcript
    if candidate_root is not None:
        wire.digest(candidate_root)
        if transcript['mode'] != 'adopt' or transcript['store_id'] != org:
            raise ValueError('adoption identity differs')
        value = dict(purpose='adopt_root', transcript=transcript, candidate_root=candidate_root)
    return crypto.enrollment_context(org, ticket, wire.hash_object(value))


def verify_proof(org: str, ticket: str, transcript: dict, proof: str, candidate_root: str | None = None) -> None:
    if not crypto.p256_verify(crypto.unb64url(transcript['sign_pub']),
            proof_message(org, ticket, transcript, candidate_root), wire.binary(proof, 64)):
        raise ValueError('enrollment proof differs')


@dataclass
class EnrollmentSession:
    org: str
    transcript: dict
    signing_key: object = field(repr=False)
    exchange_key: object = field(repr=False)
    broker_id: str | None = None
    pinned_root: str | None = field(default=None, init=False)
    candidate_root: str | None = None

    def __post_init__(self):
        wire.org_id(self.org)
        self.transcript = checked_transcript(self.transcript)
        if self.transcript['mode'] == 'adopt' and self.transcript['store_id'] != self.org:
            raise ValueError('adoption store identity differs')
        for name, key in (('sign_pub', self.signing_key), ('kx_pub', self.exchange_key)):
            if crypto.b64url(crypto.export_point(key.public_key())) != self.transcript[name]:
                raise ValueError('local enrollment key differs')

    @classmethod
    def create(cls, org: str, name: str, version: str, *, mode='join', store_id=None):
        sign, kx = crypto.generate_p256_key(), crypto.generate_p256_key()
        transcript = dict(name=name, version=version, mode=mode,
            sign_pub=crypto.b64url(crypto.export_point(sign.public_key())),
            kx_pub=crypto.b64url(crypto.export_point(kx.public_key())))
        if mode == 'adopt':
            transcript['store_id'] = store_id
        return cls(org, transcript, sign, kx)

    def reservation(self, ticket_code: str) -> dict:
        ticket = ticket_id(ticket_code)
        return dict(ticket_code=ticket_code, transcript=copy.deepcopy(self.transcript),
            proof=crypto.b64url(crypto.p256_sign(self.signing_key, proof_message(self.org, ticket, self.transcript))))

    def accept_reservation(self, response: dict) -> None:
        r = wire.exact(response, ('org_id', 'broker_id', 'genesis', 'policy_head', 'state'))
        if r['org_id'] != self.org or r['state'] != 'pending':
            raise ValueError('reservation identity differs')
        if not isinstance(r['broker_id'], str) or not re.fullmatch(r'brk_[0-9a-f]{32}',r['broker_id']):
            raise ValueError('invalid reserved broker id')
        wire.parse_head(r['policy_head'])
        if self.broker_id is not None and self.broker_id != r['broker_id']:
            raise ValueError('reservation retry changed broker identity')
        if self.transcript['mode'] == 'adopt' and (r['genesis'] is not None or r['policy_head'] != dict(seq=0, hash='0'*64)):
            raise ValueError('adoption reservation must precede genesis')
        self.broker_id = r['broker_id']

    def root_proof(self, ticket: str, candidate_root: str) -> str:
        if self.broker_id is None:
            raise ValueError('reserve broker identity before constructing genesis')
        if self.candidate_root is not None and candidate_root != self.candidate_root:
            raise ValueError('adoption candidate root changed')
        message = proof_message(self.org, ticket, self.transcript, candidate_root)
        self.candidate_root = candidate_root
        return crypto.b64url(crypto.p256_sign(self.signing_key, message))

    def save_root_proof(self, store, ticket: str, candidate_root: str) -> str:
        proof = self.root_proof(ticket,candidate_root)
        with store.transaction(immediate=True) as db:
            row = db.execute('SELECT * FROM cloud_enrollments WHERE org_id=? AND ticket_id=?',(self.org,ticket)).fetchone()
            if row is None or row['broker_id'] != self.broker_id or row['transcript_json'] != crypto.canonical_json(self.transcript).decode():
                raise ValueError('persisted reservation differs')
            if row['candidate_root'] is not None and row['candidate_root'] != candidate_root:
                raise ValueError('persisted adoption root changed')
            db.execute('UPDATE cloud_enrollments SET candidate_root=?,root_proof=? WHERE org_id=? AND ticket_id=?',
                (candidate_root,proof,self.org,ticket))
        return proof

    def pin(self, store, genesis: bytes, *, typed_words: str) -> str:
        """Pin only locally parsed genesis after a human typed the independent SAS."""
        if self.broker_id is None:
            raise ValueError('broker reservation required')
        entry = parse_entry(genesis)
        if entry['kind'] != 'genesis' or entry['org_id'] != self.org or entry['seq'] != 1 or entry['prev_hash'] != '0'*64:
            raise ValueError('invalid pairing genesis')
        if self.transcript['mode'] == 'adopt':
            if store.meta('store_id') != self.org:
                raise ValueError('adoption org must equal the existing local store id')
            founder = entry['body'].get('founder', {})
            if founder.get('kind') != 'broker' or founder.get('id') != self.broker_id or any(founder.get(k) != self.transcript[k] for k in ('sign_pub', 'kx_pub')):
                raise ValueError('adoption genesis founder differs')
        root = crypto.sha256(genesis).hex()
        if self.candidate_root is not None and root != self.candidate_root:
            raise ValueError('adoption accepted root differs')
        expected = crypto.sas_words(crypto.sas_context(self.org, root, 'broker', self.broker_id,
            self.transcript['sign_pub'], self.transcript['kx_pub']))
        if not isinstance(typed_words, str) or not crypto.compare_digest(typed_words.encode(), expected.encode()):
            raise ValueError('independent typed SAS differs')
        if self.pinned_root is not None and root != self.pinned_root:
            raise ValueError('pairing root changed')
        from sqlite3 import OperationalError
        try:
            saved = store.connection.execute('SELECT * FROM cloud_enrollments WHERE org_id=? AND broker_id=?',(self.org,self.broker_id)).fetchall()
        except OperationalError as exc:
            if 'no such table' not in str(exc):
                raise
            saved = []
        for row in saved:
            if row['transcript_json'] != crypto.canonical_json(self.transcript).decode() or (row['candidate_root'] is not None and row['candidate_root'] != root):
                raise ValueError('persisted pairing identity or root differs')
        store.initialize_cloud_replay(self.org, root)
        # Persist local ceremony progress if this identity was saved already.
        try:
            with store.transaction(immediate=True) as db:
                db.execute("UPDATE cloud_enrollments SET state='pinned',candidate_root=? WHERE org_id=? AND broker_id=? AND state='reserved'",(root,self.org,self.broker_id))
        except OperationalError as exc:
            if 'no such table' not in str(exc):
                raise
        self.pinned_root = root
        return root

    def _paired_row(self, store, db):
        rows = db.execute('SELECT * FROM cloud_enrollments WHERE org_id=? AND broker_id=?',
            (self.org,self.broker_id)).fetchall()
        if len(rows) != 1 or rows[0]['state'] not in ('pinned','complete'):
            raise ValueError('typed SAS pairing required for this enrollment')
        row = rows[0]
        if row['transcript_json'] != crypto.canonical_json(self.transcript).decode() or row['candidate_root'] != self.pinned_root:
            raise ValueError('persisted pairing identity or root differs')
        return row

    def accept_poll(self, store, blk: bytes, verifier: OfflineCloudVerifier, response: dict, *, allow_scoped: bool = False) -> dict:
        r = wire.exact(response,('state','cert_seq','wraps','scoped_seals'))
        if r['state'] != 'active' or not isinstance(verifier,OfflineCloudVerifier):
            raise ValueError('active enrollment and independent verifier required')
        wire.integer(r['cert_seq'],1)
        self._paired_row(store,store.connection)
        blobs = []
        if not isinstance(r['wraps'],list) or not isinstance(r['scoped_seals'],list):
            raise ValueError('enrollment wrap arrays required')
        for rows,fields in ((r['wraps'],('omk_generation','recipient_kind','recipient_id','eph_pub','nonce','wrapped_omk','wrap_digest')),
                            (r['scoped_seals'],('broker_id','key_id','purpose','project','eph_pub','nonce','wrapped_key','wrap_digest'))):
            for value in rows:
                value = wire.exact(value,('wrap_id',*fields,'created_by','created_at','revoked_at'))
                if value['revoked_at'] is not None:
                    raise ValueError('revoked enrollment wrap')
                blobs.append(dict(id=value['wrap_id'],**{k:value[k] for k in fields}))
        return self.accept_custody(store,blk,verifier,blobs,certificate_seq=r['cert_seq'],allow_scoped=allow_scoped)

    def accept_custody(self, store, blk: bytes, verifier: OfflineCloudVerifier, blobs: list[dict], *, certificate_seq: int | None = None, allow_scoped: bool = False) -> dict:
        """Use the concrete offline verifier, real certificate and exact-head epoch.

        Every wrap is checked and decrypted before any local write. Archived-only
        proof permits history replay but cannot supply initial decryptable custody.
        """
        if not isinstance(verifier, OfflineCloudVerifier) or not self.pinned_root or not self.broker_id:
            raise ValueError('independent enrollment verification required')
        checkpoint = verifier.export_checkpoint()
        state, epoch, head = checkpoint['authority'], checkpoint['epochs'], checkpoint['head']
        if (checkpoint['org_id'] != self.org or state['org_id'] != self.org
                or checkpoint['pinned_root'] != self.pinned_root or state['root'] != self.pinned_root
                or store.cloud_pin(self.org) != self.pinned_root):
            raise ValueError('independent enrollment pin differs')
        matches = [r for r in state['brokers'] if r['certificate']['broker_id'] == self.broker_id]
        if not matches:
            raise ValueError('real verified broker certificate required')
        if certificate_seq is not None and matches[-1]['seq'] != certificate_seq:
            raise ValueError('poll certificate sequence differs from verified history')
        cert = matches[-1]['certificate']
        if cert['scope'] != 'full' and not allow_scoped:
            raise ValueError('scoped enrollment custody disabled until the PR 4 positive trace')
        if cert['state'] != 'active' or any(cert[k] != self.transcript[k] for k in ('name', 'sign_pub', 'kx_pub')) or cert['transcript_digest'] != wire.hash_object(self.transcript):
            raise ValueError('verified certificate identity differs')
        from .cloud_epochs import EpochView
        # Cloud 177766e control/src/enroll/control.ts:195-196 delegates the poll
        # to keys at the current verified head; epochs/control.ts:394-401 serves
        # exactly that generation's committed wrap (keys route uses state.generation
        # at epochs/control.ts:288). Approval separately binds
        # its predecessor generation in enroll/composition.ts:42-45.
        generation = EpochView(epoch,dict(head=head)).committed_generation(head)
        if generation['kind'] != 'committed':
            raise ValueError('committed epoch required')
        generation = generation['generation']
        expected = {r['id']: r['digest'] for r in cert['wrap_digests']}
        if len(blobs) != len(expected) or {b.get('id') for b in blobs} != set(expected):
            raise ValueError('exact certificate wrap set required')
        keys, logical = [], set()
        for blob in blobs:
            field = 'wrapped_omk' if 'wrapped_omk' in blob else 'wrapped_key'
            b = wire.exact(blob, ('id', 'eph_pub', 'nonce', field, 'wrap_digest',
                *(('recipient_kind','recipient_id','omk_generation') if field == 'wrapped_omk' else ('broker_id','key_id','purpose','project'))))
            from .cloud_epochs import binary as hex_binary
            box = crypto.SealedBox(hex_binary(b['eph_pub'],65),hex_binary(b['nonce'],12),hex_binary(b[field],48),wire.digest(b['wrap_digest']))
            if crypto.wrap_digest(box.eph_pub, box.nonce, box.wrapped) != expected[b['id']] or b['wrap_digest'] != expected[b['id']]:
                raise ValueError('enrollment wrap bytes differ')
            if field == 'wrapped_omk':
                if cert['scope'] != 'full':
                    raise ValueError('scoped enrollment cannot accept OMK custody')
                if b['recipient_kind'] != 'broker' or b['recipient_id'] != self.broker_id or b['omk_generation'] != generation:
                    raise ValueError('OMK recipient or generation differs')
                key_id, purpose, scope = f'omk_{generation}', 'omk', '*'
                aad = crypto.org_key_wrap_aad(self.org, 'broker', self.broker_id, generation)
            else:
                if cert['scope'] == 'full':
                    raise ValueError('full enrollment requires an OMK wrap')
                row = next((r for r in epoch['keyring'] if r['key_id'] == b['key_id']), None)
                if (b['broker_id'] != self.broker_id or row is None or b['purpose'] != row['purpose'] or b['project'] != row['project']
                        or (b['purpose'] == 'kek' and (b['project'] not in cert['scope'] or epoch['active_kek'].get(b['project']) != b['key_id']))
                        or b['purpose'] not in ('kek', 'fingerprint')):
                    raise ValueError('scoped enrollment key identity or project differs')
                key_id, purpose, scope = b['key_id'], b['purpose'], b['project'] or '*'
                aad = crypto.broker_key_wrap_aad(self.org, self.broker_id, key_id, purpose, scope)
            if (purpose, scope) in logical:
                raise ValueError('duplicate logical enrollment wrap')
            logical.add((purpose, scope))
            key = crypto.unseal(self.exchange_key, crypto.unb64url(self.transcript['kx_pub']), box, aad)
            if purpose == 'omk':
                # An authenticated wrap alone does not prove current key custody.
                # Require the OMK to open the independently committed keyring.
                for row in epoch['keyring']:
                    crypto.unwrap_key(key, bytes.fromhex(row['wrapped_key']), bytes.fromhex(row['nonce']),
                        crypto.cloud_keyring_aad(self.org,row['key_id'],row['purpose'],row['project'] or '*',row['mk_generation']))
            wrapped, nonce = crypto.wrap_key(blk, key, crypto.local_key_aad(self.org, self.broker_id, key_id, purpose, scope, generation))
            keys.append((self.org, self.broker_id, key_id, purpose, scope, generation, wrapped, nonce))
        required = {('omk', '*')} if cert['scope'] == 'full' else {('kek', p) for p in cert['scope']} | {('fingerprint', '*')}
        if logical != required:
            raise ValueError('incomplete enrollment custody')
        store.initialize_cloud_custody()
        with store.transaction(immediate=True) as db:
            paired = self._paired_row(store, db)
            custody_json = crypto.canonical_json(dict(generation=generation,wrap_digests=cert['wrap_digests'])).decode()
            if paired['state'] == 'complete' and (paired['certificate_json'] != crypto.canonical_json(cert).decode()
                    or paired['custody_json'] != custody_json):
                raise ValueError('completed enrollment permits only identical custody retries')
            for values in keys:
                prior = db.execute('SELECT * FROM cloud_local_keys WHERE org_id=? AND broker_id=? AND key_id=? AND generation=?', (values[0], values[1], values[2], values[5])).fetchone()
                if prior is not None:
                    aad = crypto.local_key_aad(*values[:6])
                    if prior['purpose'] != values[3] or prior['scope'] != values[4] or crypto.unwrap_key(blk, bytes(prior['wrapped_key']), bytes(prior['nonce']), aad) != crypto.unwrap_key(blk, values[6], values[7], aad):
                        raise ValueError('custody retry changed key')
                else:
                    db.execute('INSERT INTO cloud_local_keys VALUES (?,?,?,?,?,?,?,?)', values)
            changed = db.execute("UPDATE cloud_enrollments SET state='complete',certificate_json=?,head_json=?,custody_json=? WHERE org_id=? AND broker_id=? AND transcript_json=? AND state IN ('pinned','complete')",
                (crypto.canonical_json(cert).decode(),crypto.canonical_json(head).decode(),custody_json,self.org,self.broker_id,crypto.canonical_json(self.transcript).decode()))
            if changed.rowcount != 1:
                raise ValueError('custody completion requires exactly one paired enrollment')
        return dict(certificate=copy.deepcopy(cert), head=copy.deepcopy(head), generation=generation)


def legacy_ingestion(*_args, **_kwargs):
    raise RuntimeError('E_LEGACY_ADOPTION: paired legacy ingestion and first-owner claim unavailable')


def save_reservation(session: EnrollmentSession, store, blk: bytes, ticket: str, proof: str) -> None:
    """Persist reserved identity and encrypted private scalars atomically for retry."""
    if session.broker_id is None:
        raise ValueError('reservation identity required')
    verify_proof(session.org,ticket,session.transcript,proof)
    values=[]
    for purpose,key in (('broker_sign',session.signing_key),('broker_kx',session.exchange_key)):
        key_id=ticket+'_'+purpose
        scalar=key.private_numbers().private_value.to_bytes(32,'big')
        wrapped,nonce=crypto.wrap_key(blk,scalar,crypto.local_key_aad(session.org,session.broker_id,key_id,purpose,'*',1))
        values.append((session.org,session.broker_id,key_id,purpose,'*',1,wrapped,nonce))
    store.initialize_cloud_custody()
    transcript_json=crypto.canonical_json(session.transcript).decode()
    with store.transaction(immediate=True) as db:
        prior=db.execute('SELECT * FROM cloud_enrollments WHERE org_id=? AND ticket_id=?',(session.org,ticket)).fetchone()
        if prior:
            if prior['broker_id']!=session.broker_id or prior['transcript_json']!=transcript_json:
                raise ValueError('reservation retry identity differs')
            # ECDSA proofs can differ between identical logical retries, but
            # the saved private keys must still open under this same local BLK.
            for purpose,key in (('broker_sign',session.signing_key),('broker_kx',session.exchange_key)):
                saved=store.cloud_local_key(blk,org=session.org,broker=session.broker_id,
                    key_id=ticket+'_'+purpose,purpose=purpose,scope='*',generation=1)
                if saved != key.private_numbers().private_value.to_bytes(32,'big'):
                    raise ValueError('reserved private key differs')
            return
        for value in values:
            db.execute('INSERT INTO cloud_local_keys VALUES (?,?,?,?,?,?,?,?)',value)
        db.execute('INSERT INTO cloud_enrollments(org_id,ticket_id,broker_id,transcript_json,proof,state) VALUES (?,?,?,?,?,?)',
            (session.org,ticket,session.broker_id,transcript_json,proof,'reserved'))


def load_reservation(store, blk: bytes, org: str, ticket: str) -> EnrollmentSession:
    import json
    row=store.connection.execute('SELECT * FROM cloud_enrollments WHERE org_id=? AND ticket_id=?',(org,ticket)).fetchone()
    if row is None:
        raise ValueError('enrollment reservation unavailable')
    transcript=json.loads(row['transcript_json'])
    keys=[]
    for purpose,field in (('broker_sign','sign_pub'),('broker_kx','kx_pub')):
        scalar=store.cloud_local_key(blk,org=org,broker=row['broker_id'],key_id=ticket+'_'+purpose,purpose=purpose,scope='*',generation=1)
        point=crypto.unb64url(transcript[field])
        keys.append(crypto.import_private(dict(kty='EC',crv='P-256',d=crypto.b64url(scalar),x=crypto.b64url(point[1:33]),y=crypto.b64url(point[33:]))))
    verify_proof(org,ticket,transcript,row['proof'])
    result=EnrollmentSession(org,transcript,*keys,broker_id=row['broker_id'],candidate_root=row['candidate_root'])
    if row['state'] in ('pinned','complete'):
        pin = store.cloud_pin(org)
        if pin is None or row['candidate_root'] != pin:
            raise ValueError('persisted pairing root differs')
        result.pinned_root=pin
    return result
