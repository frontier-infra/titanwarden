"""Offline keeper execution. Claim credentials exist only in process memory."""
import hmac
import json
import re
import uuid

from . import crypto, cloud_wire as wire
from .cloud_epochs import derive_recipients, recipient_hints, verify_recipient_hints, keyring_digest
from .cloud_policy import AuthorityView
from .cloud_sync import guard
from .policy_log import utc_millis


class Keeper:
    def __init__(self, sync, plan_id):
        wire.text(plan_id)
        guard(re.fullmatch(r'[-a-zA-Z0-9_]+', plan_id) is not None, 'invalid plan route identifier')
        self.sync, self.plan = sync, plan_id
        self._token = None

    def snapshot(self):
        state = self.sync.checkpoint()
        cert = self.sync.certificate(state)
        guard(cert['scope'] == 'full' and cert['keeper'], 'full keeper certificate required', 'E_CLAIM')
        guard(not self.sync.conflicts(), 'conflicted keeper refuses execution')
        return AuthorityView(state['authority']).epoch_snapshot(state['head'], sorted(state['epochs']['active_kek']))

    def _row(self):
        return self.sync.store.connection.execute('SELECT * FROM cloud_keeper_leases WHERE org_id=? AND plan_id=?', (self.sync.org, self.plan)).fetchone()

    def accept_claim(self, response, *, expected_head, now):
        wire.exact(response, ('fence', 'claim_token', 'claimed_until', 'hints'))
        snapshot = self.snapshot()
        guard(expected_head == snapshot['head'] and type(expected_head.get('seq')) is int, 'claim head changed', 'E_CLAIM')
        wire.integer(response['fence'], 1)
        guard(isinstance(response['claim_token'], str) and re.fullmatch(r'rkc_[A-Za-z0-9_-]{43}', response['claim_token']) is not None, 'claim credential shape differs', 'E_CLAIM')
        guard(0 < utc_millis(response['claimed_until']) - utc_millis(now) <= 600000, 'claim lease duration differs', 'E_CLAIM')
        verify_recipient_hints(snapshot, response['hints'])
        digest = crypto.sha256(response['claim_token'].encode()).hex()
        with self.sync.store.transaction(immediate=True) as db:
            guard(self.snapshot() == snapshot, 'claim authority changed', 'E_CLAIM')
            prior = self._row()
            guard(prior is None or response['fence'] > prior['fence'] or (response['fence'] == prior['fence'] and digest == prior['token_hash'] and response['claimed_until'] == prior['claimed_until']), 'claim fence regressed or credential changed', 'E_CLAIM')
            db.execute('INSERT INTO cloud_keeper_leases VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(org_id,plan_id) DO UPDATE SET broker_id=excluded.broker_id,fence=excluded.fence,head_json=excluded.head_json,token_hash=excluded.token_hash,claimed_until=excluded.claimed_until,renewed_at=excluded.renewed_at',
                (self.sync.org, self.plan, self.sync.broker, response['fence'], crypto.canonical_json(expected_head).decode(), digest, response['claimed_until'], now))
        self._token = response['claim_token']

    def lease(self, now):
        snapshot, row = self.snapshot(), self._row()
        guard(row is not None and self._token is not None and row['broker_id'] == self.sync.broker and hmac.compare_digest(row['token_hash'], crypto.sha256(self._token.encode()).hex()), 'fresh keeper claim required after restart', 'E_CLAIM')
        guard(utc_millis(row['renewed_at']) <= utc_millis(now) < utc_millis(row['claimed_until']), 'keeper lease expired or clock regressed', 'E_CLAIM')
        broker = next(b for b in snapshot['brokers'] if b['id'] == self.sync.broker)
        guard(broker['keeper_since_seq'] is not None and broker['keeper_since_seq'] <= json.loads(row['head_json'])['seq'], 'keeper continuity lost', 'E_CLAIM')
        return dict(fence=row['fence'], claim_token=self._token)

    def renewal_due(self, now):
        self.lease(now)
        return utc_millis(now) - utc_millis(self._row()['renewed_at']) >= 120000

    def claim(self, client, base_url, *, now):
        snapshot = self.snapshot()
        row = self._row()
        # After exclusive expiry the cloud requires fresh authorization and no
        # stale credential, even when this process still holds the old token.
        body = self.lease(now) if row is not None and self._token is not None and utc_millis(now) < utc_millis(row['claimed_until']) else {}
        response = self._send(client, base_url, 'claim', body)
        self.accept_claim(response, expected_head=snapshot['head'], now=now)
        return dict(fence=response['fence'], claimed_until=response['claimed_until'])

    def _send(self, client, base_url, action, body):
        guard(client.org == self.sync.org and client.broker == self.sync.broker, 'keeper transport identity differs', 'E_CLAIM')
        return client.send_once(client.prepare('POST', base_url.rstrip('/') + f'/v1/orgs/{self.sync.org}/rekey/{self.plan}/{action}', body))

    def renew(self, client, base_url, *, now, completed_at):
        credentials = self.lease(now)
        response = self._send(client, base_url, 'renew', credentials)
        wire.exact(response, ('claimed_until',))
        self.lease(completed_at)
        guard(0 < utc_millis(response['claimed_until']) - utc_millis(completed_at) <= 600000, 'renewed lease duration differs', 'E_CLAIM')
        with self.sync.store.transaction(immediate=True) as db:
            self.lease(completed_at)
            db.execute('UPDATE cloud_keeper_leases SET claimed_until=?,renewed_at=? WHERE org_id=? AND plan_id=?', (response['claimed_until'], completed_at, self.sync.org, self.plan))
        return response

    def build_rotation(self, keys, signing_key, *, now, reason='manual', trigger_seq=None):
        """Wrap all retained keys and fresh project KEKs before staging an intent.

        Callers obtain keys by opening verified local BLK custody. The returned
        stage contains only ciphertext; the fresh OMK is sealed to the exact
        independently derived recipient set, including this keeper.
        """
        credentials, snapshot = self.lease(now), self.snapshot()
        state = self.sync.checkpoint()['epochs']
        guard(set(keys) == {k['key_id'] for k in state['keyring']} and all(isinstance(k, bytes) and len(k) == 32 for k in keys.values()), 'complete local keyring required')
        generation = state['generation'] + 1
        omk, stage, active = crypto.random_key(), dict(keyring=[], wraps=[], scoped_seals=[]), {}
        material = dict(keys)
        rows = [dict(r) for r in state['keyring']]
        for project, previous in state['active_kek'].items():
            old = next(k for k in rows if k['key_id'] == previous)
            kid = 'k_' + uuid.uuid4().hex
            material[kid] = crypto.random_key()
            rows.append(dict(key_id=kid, purpose='kek', project=project, version=old['version'] + 1))
            active[project] = kid
        for row in rows:
            kid = row['key_id']
            wrapped, nonce = crypto.wrap_key(omk, material[kid], crypto.cloud_keyring_aad(self.sync.org, kid, row['purpose'], row['project'] or '*', generation))
            stage['keyring'].append(dict(key_id=kid, purpose=row['purpose'], project=row['project'], version=row['version'], wrapped_key=wrapped.hex(), nonce=nonce.hex(), mk_generation=generation, aad_v=2))
        hints = recipient_hints(snapshot)
        recipients = derive_recipients(snapshot)
        for recipient in recipients:
            public = next(r['kx_pub'] for r in hints['recipients'] if r['kind'] == recipient['kind'] and r['id'] == recipient['id'])
            box = crypto.seal(bytes.fromhex(public), omk, crypto.org_key_wrap_aad(self.sync.org, recipient['kind'], recipient['id'], generation))
            stage['wraps'].append(dict(recipient_kind=recipient['kind'], recipient_id=recipient['id'], omk_generation=generation, eph_pub=box.eph_pub.hex(), nonce=box.nonce.hex(), wrapped_omk=box.wrapped.hex(), wrap_digest=box.wrap_digest))
            recipient['wrap_digest'] = box.wrap_digest
        for broker in hints['scoped']:
            for project in broker['projects']:
                kid = active[project]
                box = crypto.seal(bytes.fromhex(broker['kx_pub']), material[kid], crypto.broker_key_wrap_aad(self.sync.org, broker['broker_id'], kid, 'kek', project))
                stage['scoped_seals'].append(dict(broker_id=broker['broker_id'], key_id=kid, purpose='kek', project=project, eph_pub=box.eph_pub.hex(), nonce=box.nonce.hex(), wrapped_key=box.wrapped.hex(), wrap_digest=box.wrap_digest))
        body = dict(from_generation=state['generation'], to_generation=generation, recipients=recipients,
            scoped_seals=[{k:s[k] for k in ('broker_id', 'key_id', 'project', 'wrap_digest')} for s in stage['scoped_seals']],
            keyring=[dict(key_id=k['key_id'], purpose=k['purpose'], scope=k['project'] or '*', digest=keyring_digest(k)) for k in stage['keyring']],
            active_kek=active, plan_id=self.plan, fence=credentials['fence'])
        if trigger_seq is None:
            body['reason'] = reason
        else:
            body['trigger_seq'] = trigger_seq
        entry = dict(v=2, org_id=self.sync.org, seq=snapshot['head']['seq'] + 1, prev_hash=snapshot['head']['hash'], ts=now,
            kind='epoch_rotate', body=body, signer=dict(kind='broker', id=self.sync.broker))
        # Independently exercise the same epoch machine before sending anything.
        from .cloud_epochs import EpochReplay
        checker = EpochReplay()
        checker._state = state
        checker.apply(entry, snapshot, stage=stage, received_at=now)
        public = crypto.unb64url(self.sync.certificate()['sign_pub'])
        guard(crypto.export_point(signing_key.public_key()) == public, 'keeper policy key differs')
        signed = dict(entry=entry, sig=crypto.b64url(crypto.p256_sign(signing_key, crypto.policy_context(self.sync.org, wire.hash_object(entry)))))
        return stage, signed

    def stage(self, client, base_url, stage, *, now):
        credentials = self.lease(now)
        return self._send(client, base_url, 'keys', dict(stage, **credentials))

    def publish(self, client, base_url, signed, *, now):
        credentials = self.lease(now)
        entry = wire.parse_signed_entry(signed)['entry']
        guard(entry['body'].get('plan_id') == self.plan and entry['body'].get('fence') == credentials['fence'], 'keeper intent fence differs', 'E_CLAIM')
        guard(client.org == self.sync.org and client.broker == self.sync.broker, 'keeper publish identity differs', 'E_CLAIM')
        return client.send_once(client.prepare('POST', base_url.rstrip('/') + f'/v1/orgs/{self.sync.org}/policy', dict(signed, **credentials)))

    def build_rewrap(self, keys, signing_key, *, now):
        """Resume up to 200 outstanding envelopes at a committed epoch.

        Read the latest verified envelopes each time. Ciphertexts remain fixed;
        a lost response is reconciled by pulling policy before building again.
        """
        self.lease(now)
        state = self.sync.checkpoint()
        epochs = state['epochs']
        committed = next((e for e in reversed(epochs['epochs']) if e.get('plan_id') == self.plan), None)
        guard(committed is not None, 'rekey epoch must be independently committed')
        items, commitments = [], []
        for version in epochs['versions']:
            kid = epochs['active_kek'][version['project']]
            if version['project'] not in committed['projects'] or version['kek_id'] == kid:
                continue
            row = self.sync.store.connection.execute('SELECT blob_json FROM cloud_sync_blobs WHERE org_id=? AND version_id=?', (self.sync.org, version['version_id'])).fetchone()
            guard(row is not None and version['kek_id'] in keys and kid in keys, 'rekey envelope or local KEK missing')
            blob = json.loads(row[0])
            from .cloud_epochs import EpochReplay
            checker = EpochReplay()
            checker._state = epochs
            checker.verify_ciphertext(blob)
            dek = crypto.unwrap_key(keys[version['kek_id']], bytes.fromhex(blob['wrapped_dek']), bytes.fromhex(blob['dek_nonce']), crypto.dek_aad(self.sync.org, version['version_id'], version['kek_id']))
            wrapped, nonce = crypto.wrap_key(keys[kid], dek, crypto.dek_aad(self.sync.org, version['version_id'], kid))
            items.append(dict(version_id=version['version_id'], kek_id=kid, wrapped_dek=wrapped.hex(), dek_nonce=nonce.hex()))
            commitments.append(dict(version_id=version['version_id'], from_kek_id=version['kek_id'], from_envelope_digest=version['envelope_digest'], to_kek_id=kid, to_envelope_digest=crypto.envelope_digest(kid, wrapped, nonce)))
            if len(items) == 200:
                break
        if not items:
            return None
        entry = dict(v=2, org_id=self.sync.org, seq=state['head']['seq'] + 1, prev_hash=state['head']['hash'], ts=now,
            kind='dek_rewrap', body=dict(epoch_seq=committed['seq'], items=commitments), signer=dict(kind='broker', id=self.sync.broker))
        guard(crypto.export_point(signing_key.public_key()) == crypto.unb64url(self.sync.certificate()['sign_pub']), 'rekey policy key differs')
        signed = dict(entry=entry, sig=crypto.b64url(crypto.p256_sign(signing_key, crypto.policy_context(self.sync.org, wire.hash_object(entry)))))
        return dict(signed, plan_id=self.plan, items=items, **self.lease(now))

    def rewrap(self, client, base_url, payload, *, now):
        credentials = self.lease(now)
        guard(payload['plan_id'] == self.plan and payload['fence'] == credentials['fence'] and payload['claim_token'] == credentials['claim_token'], 'rekey batch fence differs', 'E_CLAIM')
        guard(client.org == self.sync.org and client.broker == self.sync.broker, 'rekey batch transport identity differs', 'E_CLAIM')
        return client.send_once(client.prepare('POST', base_url.rstrip('/') + f'/v1/orgs/{self.sync.org}/keys/rewrap', payload))
