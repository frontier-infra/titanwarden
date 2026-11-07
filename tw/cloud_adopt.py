"""Resumable local adoption staging, exclusively on disposable backup copies.

Cloud legacy ingestion and first-owner claim do not exist. Staging never changes
legacy keys, slots, ciphertexts or envelopes and never reports retirement. A
future paired protocol must authorize publication and the eventual cutover.
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

from . import crypto
from .backup import file_sha256
from .cloud_wire import hash_object, integer, org_id

BLOCKER = 'E_LEGACY_ADOPTION: cloud legacy ingestion, legacy KEK representation and first-owner claim unavailable'


def _rows(store, table):
    return [{k: (v.hex() if isinstance(v, bytes) else v) for k, v in dict(r).items()}
            for r in store.connection.execute(f'SELECT * FROM {table} ORDER BY 1')]


class AdoptionDraft:
    def __init__(self, store, master: bytes, omk: bytes, blk: bytes, *, broker: str):
        self.store, self.master, self.omk, self.blk, self.broker = store, master, omk, blk, broker
        marker_path = store.home / 'ADOPTION-DRAFT-COPY.json'
        if not marker_path.is_file() or marker_path.is_symlink():
            raise ValueError('adoption draft requires a marked disposable copy')
        marker = json.loads(marker_path.read_text())
        if marker.get('format') != 1 or marker.get('target') != str(store.db_path) or marker.get('source') == str(store.db_path):
            raise ValueError('disposable copy identity differs')
        checkpoint = store.home / 'ADOPTION-SOURCE.db'
        if (marker.get('checkpoint') != str(checkpoint) or not checkpoint.is_file()
                or checkpoint.is_symlink() or file_sha256(checkpoint) != marker.get('sha256')):
            raise ValueError('disposable snapshot checksum differs')
        self.org = org_id(store.meta('store_id'))
        self.source = {t: _rows(store, t) for t in ('meta', 'keyring', 'slots', 'projects', 'secrets', 'secret_versions')}
        self.source_digest = hash_object(self.source)
        if marker.get('inventory_digest') != self.source_digest:
            raise ValueError('disposable source inventory differs from backup')
        store.initialize_cloud_custody()

    def _source_keys(self):
        return {r['key_id']: crypto.unwrap_key(self.master, bytes.fromhex(r['wrapped_key']), bytes.fromhex(r['nonce']),
            crypto.keyring_aad(self.org, r['key_id'], r['purpose'], r['mk_generation'])) for r in self.source['keyring']}

    def _check_source(self):
        current = {t: _rows(self.store, t) for t in self.source}
        if hash_object(current) != self.source_digest:
            raise ValueError('source inventory changed during adoption draft')

    def _journal(self):
        row = self.store.connection.execute('SELECT * FROM cloud_adoption_journal WHERE org_id=?', (self.org,)).fetchone()
        if row is None or row['source_digest'] != self.source_digest:
            raise ValueError('adoption journal source differs')
        return row, json.loads(row['plan_json'])

    def _aad(self, row, generation):
        if row['purpose'] == 'audit_mac':
            return crypto.local_key_aad(self.org, self.broker, row['key_id'], row['purpose'], '*', generation)
        return crypto.cloud_keyring_aad(self.org, row['key_id'], row['purpose'], row['scope'], generation)

    def rewrite_local_keyring(self, *, from_generation: int, to_generation: int,
                              expected_key_ids: list[str], checkpoint=lambda phase: None) -> dict:
        """Crash checkpoints follow committed transactions; reruns verify all stages.

        The input key set covers every retained source row, including local AK.
        New project KEKs are journaled once. Retained legacy KEKs use a local-only
        '*' scope which must never be uploaded to today's cloud stage schema.
        """
        integer(from_generation, 1); integer(to_generation, 1)
        if to_generation != from_generation + 1:
            raise ValueError('adoption generation differs')
        if not isinstance(expected_key_ids, list) or any(not isinstance(k, str) for k in expected_key_ids) or len(set(expected_key_ids)) != len(expected_key_ids) or set(expected_key_ids) != {r['key_id'] for r in self.source['keyring']}:
            raise ValueError('exact retained key set required')
        self._check_source()
        source_keys = self._source_keys()
        # Bind resumption to the same encryption keys even if the first crash
        # happened before key staging. Custody is encrypted locally under BLK.
        for key_id,purpose,key in (('adoption_omk','omk',self.omk),('adoption_legacy_mk','legacy_mk',self.master)):
            self.store.put_cloud_local_key(self.blk,org=self.org,broker=self.broker,key_id=key_id,
                purpose=purpose,scope='*',generation=to_generation,key=key)
        projects = sorted(r['slug'] for r in self.source['projects'])
        with self.store.transaction(immediate=True) as db:
            prior = db.execute('SELECT * FROM cloud_adoption_journal WHERE org_id=?', (self.org,)).fetchone()
            if prior is None:
                plan = dict(from_generation=from_generation, to_generation=to_generation,
                    expected_key_ids=sorted(expected_key_ids), broker=self.broker, legacy_mk_generation=int(self.store.meta('mk_generation')),
                    project_keys={p: 'kek_draft_' + uuid.uuid4().hex for p in projects})
                db.execute('INSERT INTO cloud_adoption_journal VALUES (?,?,?,?)',
                    (self.org, self.source_digest, crypto.canonical_json(plan).decode(), 'inventoried'))
            else:
                plan = json.loads(prior['plan_json'])
                if prior['source_digest'] != self.source_digest or any(plan[k] != v for k,v in dict(from_generation=from_generation, to_generation=to_generation, expected_key_ids=sorted(expected_key_ids), broker=self.broker).items()):
                    raise ValueError('adoption resume input or source differs')
        checkpoint('inventoried')
        row, plan = self._journal()
        targets = [dict(key_id=r['key_id'], purpose=r['purpose'], scope='*') for r in self.source['keyring']]
        targets += [dict(key_id=k, purpose='kek', scope=p) for p,k in plan['project_keys'].items()]
        if row['phase'] == 'inventoried':
            with self.store.transaction(immediate=True) as db:
                for target in targets:
                    key = source_keys[target['key_id']] if target['key_id'] in source_keys else crypto.random_key()
                    wrapping = self.blk if target['purpose'] == 'audit_mac' else self.omk
                    wrapped, nonce = crypto.wrap_key(wrapping, key, self._aad(target, to_generation))
                    db.execute('INSERT INTO cloud_adoption_keys VALUES (?,?,?,?,?,?,?,2)',
                        (self.org, target['key_id'], target['purpose'], target['scope'], to_generation, wrapped, nonce))
                db.execute("UPDATE cloud_adoption_journal SET phase='keys_staged' WHERE org_id=?", (self.org,))
            checkpoint('keys_staged')
        staged = list(self.store.connection.execute('SELECT * FROM cloud_adoption_keys WHERE org_id=?', (self.org,)))
        if {r['key_id'] for r in staged} != {r['key_id'] for r in targets}:
            raise ValueError('staged key set differs')
        target_by_id = {r['key_id']: r for r in targets}
        keys = {}
        for r in staged:
            target = target_by_id[r['key_id']]
            if r['aad_v'] != 2 or r['generation'] != to_generation or any(r[k] != target[k] for k in ('purpose','scope')):
                raise ValueError('staged key metadata differs')
            keys[r['key_id']] = crypto.unwrap_key(self.blk if r['purpose']=='audit_mac' else self.omk,
                bytes(r['wrapped_key']), bytes(r['nonce']), self._aad(r, to_generation))
            if r['key_id'] in source_keys and keys[r['key_id']] != source_keys[r['key_id']]:
                raise ValueError('retained source key changed')
        secrets = {r['secret_id']: r for r in self.source['secrets']}
        retained = []
        for v in self.source['secret_versions']:
            fields = ('ciphertext','nonce','wrapped_dek','dek_nonce','kek_id')
            if all(v[f] is None for f in fields):
                continue
            if any(v[f] is None for f in fields):
                raise ValueError('incomplete retained ciphertext envelope')
            retained.append(v)
        for offset in range(0, len(retained), 200):
            with self.store.transaction(immediate=True) as db:
                for v in retained[offset:offset+200]:
                    target_id = plan['project_keys'][secrets[v['secret_id']]['project']]
                    dek = crypto.unwrap_key(source_keys[v['kek_id']], bytes.fromhex(v['wrapped_dek']), bytes.fromhex(v['dek_nonce']), crypto.dek_aad(self.org, v['version_id'], v['kek_id']))
                    old = db.execute('SELECT * FROM cloud_adoption_envelopes WHERE org_id=? AND version_id=?', (self.org,v['version_id'])).fetchone()
                    if old is None:
                        wrapped, nonce = crypto.wrap_key(keys[target_id], dek, crypto.dek_aad(self.org,v['version_id'],target_id))
                        db.execute('INSERT INTO cloud_adoption_envelopes VALUES (?,?,?,?,?,?,?,?)',
                            (self.org,v['version_id'],v['kek_id'],target_id,wrapped,nonce,
                             crypto.envelope_digest(v['kek_id'],bytes.fromhex(v['wrapped_dek']),bytes.fromhex(v['dek_nonce'])),
                             crypto.envelope_digest(target_id,wrapped,nonce)))
            checkpoint('envelope_batch')
        with self.store.transaction(immediate=True) as db:
            db.execute("UPDATE cloud_adoption_journal SET phase='envelopes_staged' WHERE org_id=?", (self.org,))
        checkpoint('envelopes_staged')
        envelopes = {r['version_id']:r for r in self.store.connection.execute('SELECT * FROM cloud_adoption_envelopes WHERE org_id=?',(self.org,))}
        if set(envelopes) != {v['version_id'] for v in retained}:
            raise ValueError('rewritten version set differs')
        for v in retained:
            r = envelopes[v['version_id']]
            target_id = plan['project_keys'][secrets[v['secret_id']]['project']]
            before = crypto.unwrap_key(source_keys[v['kek_id']],bytes.fromhex(v['wrapped_dek']),bytes.fromhex(v['dek_nonce']),crypto.dek_aad(self.org,v['version_id'],v['kek_id']))
            after = crypto.unwrap_key(keys[target_id],bytes(r['wrapped_dek']),bytes(r['nonce']),crypto.dek_aad(self.org,v['version_id'],target_id))
            if r['from_kek_id'] != v['kek_id'] or r['to_kek_id'] != target_id or before != after or r['from_digest'] != crypto.envelope_digest(v['kek_id'],bytes.fromhex(v['wrapped_dek']),bytes.fromhex(v['dek_nonce'])) or r['to_digest'] != crypto.envelope_digest(target_id,bytes(r['wrapped_dek']),bytes(r['nonce'])):
                raise ValueError('rewritten DEK verification differs')
        self._check_source()
        with self.store.transaction(immediate=True) as db:
            db.execute("UPDATE cloud_adoption_journal SET phase='verified_draft' WHERE org_id=?", (self.org,))
        checkpoint('verified_draft')
        return dict(rewritten_key_ids=sorted(expected_key_ids), all_aad_v=2, legacy_retired=False,
                    phase='verified_draft', blocker=BLOCKER, staged_project_keys=plan['project_keys'])

    def stage_local_slots(self, slot_keys: dict[str, bytes], *, generation: int) -> None:
        from .seal import CloudCustody
        integer(generation,1)
        self._check_source()
        slots = [r for r in self.source['slots'] if r['disabled_at'] is None]
        if set(slot_keys) != {r['slot_id'] for r in slots}:
            raise ValueError('every retained usable slot requires local unlock proof')
        for row in slots:
            old = crypto.unwrap_key(slot_keys[row['slot_id']],bytes.fromhex(row['wrapped_mk']),
                bytes.fromhex(row['nonce']),crypto.slot_aad(self.org,row['slot_id'],row['mk_generation']))
            if old != self.master:
                raise ValueError('local slot unlock proof differs')
        custody = CloudCustody(self.store,self.org,self.broker,self.blk)
        try:
            for row in slots:
                custody.wrap_slot(row['slot_id'],slot_keys[row['slot_id']],generation=generation,
                    params=json.loads(row['params_json']))
        finally:
            custody.close()

    def publish(self):
        raise RuntimeError(BLOCKER)

    def retire_legacy(self):
        raise RuntimeError(BLOCKER)
