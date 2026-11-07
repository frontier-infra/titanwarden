"""Verified cloud orchestration with injected transport and local persistence.

Only independently replayed prefixes enter the store. Transport is injected and
one-attempt, and operational server observations never establish authority.
Local mode does not instantiate this module or install its tables.
"""
from copy import deepcopy
import json
import sqlite3

from . import crypto, cloud_wire as wire
from .cloud_epochs import EpochReplay
from .cloud_policy import AuthorityView, check_late_admission
from .cloud_recovery import RecoveryVerifier, RecoveryEvidence
from .cloud_requests import restricted_policy_fresh
from .policy_log import PolicyError, utc_millis
from .store import StoreError, CloudPublicationConflict


REASONS = frozenset(('bad_signature', 'fork', 'invalid_derived', 'recipient_mismatch',
    'envelope_mismatch', 'wrap_mismatch', 'pin_mismatch', 'late_admission', 'hold_too_short'))
LOCAL_REASONS = REASONS | {'protocol_violation'}


class PullRetry(PolicyError):
    def __init__(self, message):
        super().__init__('E_SYNC_RETRY', message)


def guard(condition, message, code='E_POLICY_CONFLICT'):
    if not condition:
        raise PolicyError(code, message)


class CloudSync:
    def __init__(self, store, org, broker, *, verifier_type=None):
        wire.org_id(org)
        wire.text(broker)
        self.store, self.org, self.broker = store, org, broker
        self._verifier_type = verifier_type
        guard(store.cloud_pin(org) is not None, 'independent cloud pin required')
        store.initialize_cloud_sync()

    def checkpoint(self):
        state = self.store.load_cloud_replay(self.org)
        guard(state is not None and state['head']['seq'] > 0, 'verified policy required')
        return state

    def certificate(self, checkpoint=None):
        state = self.checkpoint() if checkpoint is None else checkpoint
        cert = AuthorityView(state['authority']).broker_certificate_at(self.broker, state['head'])
        guard(cert is not None, 'active certified broker required')
        return cert

    def conflicts(self):
        db = self.store.connection
        # Offline acknowledgements are not authenticated resolutions. No row in
        # cloud_resolutions can clear a gate until the admin wiring is reviewed.
        branch = self.store.cloud_branch(self.org)
        through = 0 if branch is None else db.execute('SELECT through_conflict FROM cloud_verified_branches WHERE branch_id=?',(branch,)).fetchone()[0]
        return [dict(r) for r in db.execute('SELECT * FROM cloud_conflicts WHERE org_id=? AND conflict_id>? ORDER BY conflict_id', (self.org,through))]

    def refuse(self, reason, observed_at):
        guard(reason in LOCAL_REASONS, 'unknown conflict reason')
        self.store.record_cloud_conflict(self.org, self.checkpoint()['head'], reason, observed_at)

    def require_delivery(self, project, secret_class, now):
        """Re-read durable state for every value movement, including after restart."""
        with self.store._transaction_lock:
            guard(not self.conflicts(), 'unresolved local conflict')
            state = self.checkpoint()
            cert = self.certificate(state)
            guard(secret_class in ('standard', 'sensitive', 'restricted'), 'unknown secret class')
            guard(cert['scope'] == 'full' or project in cert['scope'], 'project outside certified scope')
            if secret_class == 'restricted':
                requests = self.store.cloud_request_state(self.org,state['head'])
                observations = self.store.cloud_observations(self.org)['heads']
                times = [utc_millis(o['observed_at']) for o in observations if dict(seq=o['seq'], hash=o['hash']) == state['head']]
                guard(restricted_policy_fresh(requests.get('max_policy_age'), max(times) if times else None, utc_millis(now)), 'restricted policy is stale', 'E_POLICY_STALE')
            return deepcopy(state['head'])

    def resolve(self, *, expected_head, through_conflict, typed_root, now):
        """Closed until the existing broker admin session can select a history."""
        raise PolicyError('E_POLICY_RESOLUTION_UNAVAILABLE', 'resolution requires an authenticated admin session and independently verified history; wiring unavailable')

    def accept_pull(self, verifier, blobs, *, observed_at):
        guard(isinstance(verifier, RecoveryVerifier), 'all policy kind owners required')
        checkpoint = verifier.export_checkpoint()
        guard(checkpoint['org_id'] == self.org and checkpoint['pinned_root'] == self.store.cloud_pin(self.org), 'pull independent pin differs')
        cert = AuthorityView(checkpoint['authority']).broker_certificate_at(self.broker, checkpoint['head'])
        guard(cert is not None and checkpoint['ciphertext_scope'] == cert['scope'], 'pull ciphertext scope differs')
        current = self.store.load_cloud_replay(self.org)
        old = None if current is None else current['head']
        if old is not None:
            heads = checkpoint['verified_heads']
            if old['seq'] > checkpoint['head']['seq']:
                raise PullRetry('local head advanced; fetch a current prefix')
            if heads.get(old['seq']) != old['hash']:
                self.refuse('fork', observed_at)
                raise PolicyError('E_POLICY_CONFLICT', 'verified divergent signed history')
        try:
            self.store.save_cloud_replay(verifier, expected_head=old, sync_blobs=blobs, observed_at=observed_at, sync_broker=self.broker)
        except CloudPublicationConflict as exc:
            self.refuse('envelope_mismatch', observed_at)
            raise PolicyError('E_POLICY_CONFLICT', str(exc)) from exc
        return deepcopy(checkpoint['head'])

    def pull(self, frames, blobs, *, projects, evidence, observed_at, commit=True):
        """Replay a full prefix, with observations obtained only from local storage.

        A frame is a local adapter tuple (PolicyRecord, stage, ciphertext,
        RecoveryEvidence). HTTP decoding must preserve the signed policy bytes.
        Cloud timestamps do not replace this machine's observation clock.
        """
        from .cloud_sync_verifier import SyncVerifier
        from .cloud_http import CloudResponseError
        cached_frames = None
        for attempt in range(3):
            verifier = (self._verifier_type or SyncVerifier)(self.org, self.store.cloud_pin(self.org), projects=projects)
            observations = self.store.cloud_observations(self.org)
            prior = self.store.load_cloud_replay(self.org)
            known_seq = 0 if prior is None else prior['head']['seq']
            phase = 'frames'
            try:
                if callable(frames):
                    source = frames()
                else:
                    if cached_frames is None:
                        cached_frames = list(frames)
                    source = cached_frames
                for record, stage, blob, proof in source:
                    phase = 'protocol_violation'
                    entry = crypto.parse_canonical(record.data)
                    wire.exact(entry['body'].get('authz', {}), (), tuple(entry['body'].get('authz', {})))
                    phase = 'verification'
                    verifier.verify_record(record, stage=stage, blob=blob, evidence=proof,
                        runtime=dict(mode='history', now=observed_at, observations=observations if entry['seq'] > known_seq else dict(heads=[], proposals={})))
                    if entry['seq'] > known_seq:
                        phase = 'late_admission'
                        check_late_admission(observations, dict(seq=entry['seq'] - 1, hash=entry['prev_hash']), entry['ts'], entry['body'].get('authz', {}).get('expires_at'))
                phase = 'verification'
                verifier.finish_history(blobs, evidence=evidence, broker_id=self.broker)
                if not commit:return verifier
                phase = 'save'
                return self.accept_pull(verifier, blobs, observed_at=observed_at)
            except CloudResponseError:
                raise  # A remote refusal supplies no independent fork evidence.
            except (OSError, StoreError, sqlite3.Error, PullRetry) as exc:
                # Local optimistic races and transport/storage outages do not
                # establish a signed fork. A fetch factory can retry transport.
                if attempt < 2 and (phase == 'save' or callable(frames)):
                    continue
                raise PullRetry(str(exc)) from exc
            except (PolicyError, ValueError, TypeError, KeyError, AttributeError) as exc:
                if phase == 'save':
                    raise  # accept_pull already classified verified evidence.
                message = str(exc).lower()
                reason = phase if phase in ('protocol_violation', 'late_admission') else 'protocol_violation'
                for fragment, classified in (('observed conflicting predecessor','fork'), ('bad signature','bad_signature'), ('hold too short','hold_too_short'), ('wrap','wrap_mismatch'), ('ciphertext','envelope_mismatch'), ('envelope','envelope_mismatch'), ('recipient','recipient_mismatch'), ('derived','invalid_derived')):
                    if fragment in message:
                        reason = classified
                        break
                if prior is not None:
                    self.refuse(reason, observed_at)
                raise PolicyError('E_POLICY_CONFLICT', str(exc)) from exc

    def report(self, client, base_url, *, reason=None):
        state = self.checkpoint()
        self.certificate(state)
        if reason is None:
            epochs = state['epochs']['epochs']
            guard(bool(epochs), 'committed epoch required for head report')
            body = dict(head=state['head'], epoch=epochs[-1]['seq'])
            route = 'head-report'
        else:
            guard(reason in REASONS, 'unknown conflict reason')
            body, route = dict(head=state['head'], reason=reason), 'conflict'
        guard(client.org == self.org and client.broker == self.broker, 'report signer identity differs')
        return client.prepare('POST', base_url.rstrip('/') + f'/v1/orgs/{self.org}/sync/{route}', body)

    def completion(self):
        state = self.checkpoint()
        self.certificate(state)
        epochs = state['epochs']['epochs']
        guard(bool(epochs), 'committed epoch required for completion')
        return dict(head=state['head'], epoch=epochs[-1]['seq'])

    def sync_pages(self, pages, *, now):
        """Validate a complete scoped snapshot before retaining any ciphertext."""
        guard(not self.conflicts(), 'conflicted sync refuses')
        state, cert = self.checkpoint(), self.certificate()
        scope = ['*'] if cert['scope'] == 'full' else cert['scope']
        expected_secrets = {k: v for k, v in state['epochs']['secrets'].items() if scope == ['*'] or v['project'] in scope}
        secrets, versions, offsets = {}, {}, dict(secrets=0, versions=0)
        guard(bool(pages), 'missing sync snapshot')
        for i, page in enumerate(pages):
            wire.exact(page, ('secrets', 'versions', 'cursor'))
            guard(isinstance(page['secrets'], list) and isinstance(page['versions'], list) and len(page['secrets']) <= 100 and len(page['versions']) <= 100 and len(crypto.canonical_json(page)) <= 3000000, 'sync page limit exceeded')
            for row in page['secrets']:
                sid = row.get('secret_id')
                guard(sid not in secrets and sid in expected_secrets and {'secret_id', 'path', 'project', 'class'} <= row.keys() <= {'secret_id', 'path', 'project', 'class', 'kind', 'provider'} and all(v == expected_secrets[sid].get(k, 'opaque' if k == 'kind' else None) for k,v in row.items()), 'sync secret metadata differs')
                secrets[sid] = row
            for row in page['versions']:
                vid = row.get('version_id')
                expected = next((v for v in state['epochs']['versions'] if v['version_id'] == vid), None)
                guard(vid not in versions and expected is not None and expected['secret_id'] in expected_secrets, 'sync version outside snapshot')
                blob = {k: row[k] for k in ('version_id', 'secret_id', 'kek_id', 'ciphertext', 'nonce', 'wrapped_dek', 'dek_nonce')}
                # The complete-set check below verifies each commitment once.
                metadata = dict(expected, ciphertext_digest=expected['value_digest'])
                guard(all(row.get(k) == metadata[k] for k in ('version_no', 'state', 'fingerprint', 'length', 'source', 'ciphertext_digest', 'envelope_digest')), 'sync signed version metadata differs')
                versions[vid] = blob
            for field in offsets:
                offsets[field] += len(page[field])
            if page['cursor'] is not None:
                cursor = crypto.parse_canonical(crypto.unb64url(page['cursor']))
                guard(cursor == dict(org_id=self.org, broker_id=self.broker, seq=state['head']['seq'], scope=scope, offsets=offsets) and type(cursor['seq']) is int and all(type(cursor['offsets'][k]) is int for k in ('secrets', 'versions')), 'sync cursor binding differs')
            guard((page['cursor'] is None) == (i == len(pages) - 1), 'sync pagination incomplete')
        guard(set(secrets) == set(expected_secrets), 'sync secret suffix missing')
        checker = EpochReplay()
        checker._state = state['epochs']
        checker.verify_current_ciphertexts(list(versions.values()), projects=None if scope == ['*'] else scope)
        utc_millis(now)
        with self.store.transaction(immediate=True) as db:
            guard(self.checkpoint()['head'] == state['head'], 'sync head changed')
            db.execute('DELETE FROM cloud_sync_blobs WHERE org_id=?', (self.org,))
            for vid, blob in versions.items():
                db.execute('INSERT INTO cloud_sync_blobs VALUES (?,?,?,?)', (self.org, vid, state['head']['seq'], crypto.canonical_json(blob).decode()))
        return list(versions.values())

    def validate_cursor(self, encoded):
        """Check an outgoing opaque blob cursor against verified local scope."""
        state, cert = self.checkpoint(), self.certificate()
        cursor = crypto.parse_canonical(crypto.unb64url(encoded))
        wire.exact(cursor, ('org_id','broker_id','seq','scope','offsets'))
        scope = ['*'] if cert['scope'] == 'full' else cert['scope']
        guard(cursor['org_id'] == self.org and cursor['broker_id'] == self.broker and type(cursor['seq']) is int and cursor['seq'] == state['head']['seq'] and cursor['scope'] == scope, 'sync snapshot changed', 'E_CONFLICT')
        offsets = wire.exact(cursor['offsets'], ('secrets','versions'))
        secrets = {s['secret_id'] for s in state['epochs']['secrets'].values() if scope == ['*'] or s['project'] in scope}
        limits = dict(secrets=len(secrets), versions=sum(v['secret_id'] in secrets for v in state['epochs']['versions']))
        guard(all(type(offsets[k]) is int and 0 <= offsets[k] <= limits[k] for k in limits), 'invalid sync offset')
        return cursor

    def stage_version(self, payload, *, now):
        wire.exact(payload, ('version', 'entries'), ('secret',))
        guard(isinstance(payload['entries'], list) and 1 <= len(payload['entries']) <= 2, 'invalid version entry count')
        entries = [wire.parse_signed_entry(e) for e in payload['entries']]
        guard([e['entry']['kind'] for e in entries] in (['version_add'], ['secret_create', 'version_add']), 'invalid version entry order')
        state = self.checkpoint()
        last = entries[-1]['entry']['body']
        guard(not any(v['version_id'] == last['version_id'] for v in state['epochs']['versions']), 'version is already published')
        version = payload['version']
        wire.exact(version, ('version_id', 'secret_id', 'kek_id', 'ciphertext', 'nonce', 'wrapped_dek', 'dek_nonce'))
        secret = state['epochs']['secrets'].get(last['secret_id'])
        if secret is None and len(entries) == 2:
            secret = entries[0]['entry']['body']
        guard(secret is not None and ('secret' not in payload or payload['secret'] == secret), 'unsigned secret metadata')
        guard(len(entries) != 2 or (entries[0]['entry']['body']['secret_id'] == last['secret_id'] and last['secret_id'] not in state['epochs']['secrets']), 'secret creation must match a new version target')
        self.require_delivery(secret['project'], secret['class'], now)
        guard(version['kek_id'] == state['epochs']['active_kek'].get(secret['project']), 'unpublished version uses stale KEK', 'E_STALE_EPOCH')
        expected_seq, expected_hash = state['head']['seq'] + 1, state['head']['hash']
        public = crypto.unb64url(self.certificate(state)['sign_pub'])
        for signed in entries:
            entry = signed['entry']
            guard(entry['org_id'] == self.org and entry['seq'] == expected_seq and entry['prev_hash'] == expected_hash and entry['signer'] == dict(kind='broker', id=self.broker), 'version policy predecessor differs', 'E_POLICY_HEAD')
            guard(crypto.p256_verify(public, crypto.policy_context(self.org, wire.hash_object(entry)), wire.binary(signed['sig'], 64)), 'version policy signature differs')
            expected_seq, expected_hash = expected_seq + 1, wire.hash_object(entry)
        # EpochReplay below checks blob identity, lengths, value and envelope
        # commitments once, together with the signed transition's semantics.
        checker = EpochReplay()
        checker._state = deepcopy(state['epochs'])
        snapshot = AuthorityView(state['authority']).epoch_snapshot(state['head'], sorted(state['epochs']['active_kek']))
        for signed in entries:
            checker.apply(signed['entry'], snapshot, received_at=now, blob=version if signed['entry']['kind'] == 'version_add' else None)
            snapshot = dict(snapshot, head=dict(seq=signed['entry']['seq'], hash=wire.hash_object(signed['entry'])))
        raw = crypto.canonical_json(payload).decode()
        with self.store.transaction(immediate=True) as db:
            guard(self.checkpoint()['head'] == state['head'], 'write head changed', 'E_POLICY_HEAD')
            prior = db.execute('SELECT payload_json FROM cloud_unpublished WHERE org_id=? AND version_id=?', (self.org, version['version_id'])).fetchone()
            guard(prior is None or prior[0] == raw, 'unpublished version changed; explicitly rebuild after pull')
            db.execute('INSERT OR IGNORE INTO cloud_unpublished VALUES (?,?,?,?,?)', (self.org, version['version_id'], crypto.canonical_json(state['head']).decode(), version['kek_id'], raw))
        return version['version_id']

    def upload_version(self, version_id, client, base_url, *, now):
        row = self.store.connection.execute('SELECT * FROM cloud_unpublished WHERE org_id=? AND version_id=?', (self.org, version_id)).fetchone()
        guard(row is not None, 'unpublished version missing')
        payload = json.loads(row['payload_json'])
        guard(json.loads(row['head_json']) == self.checkpoint()['head'], 'offline write requires fresh authorization', 'E_POLICY_HEAD')
        self.stage_version(payload, now=now)
        guard(client.org == self.org and client.broker == self.broker, 'upload signer identity differs')
        response = client.send_once(client.prepare('POST', base_url.rstrip('/') + f'/v1/orgs/{self.org}/sync/versions', payload))
        # A transport success does not delete pending work. Only a verified pull
        # proving the exact version commitment may acknowledge publication.
        return response

    def rebuild_unpublished(self, version_id, old_kek, new_kek, signing_key, *, now):
        """Explicitly rewrap and re-sign after an independently verified pull."""
        row = self.store.connection.execute('SELECT * FROM cloud_unpublished WHERE org_id=? AND version_id=?', (self.org, version_id)).fetchone()
        guard(row is not None, 'unpublished rebuild requires retained payload')
        payload, state = json.loads(row['payload_json']), self.checkpoint()
        guard(not any(v['version_id'] == version_id for v in state['epochs']['versions']), 'version is already published')
        original = deepcopy(payload['version'])
        secret = state['epochs']['secrets'].get(original['secret_id'], payload.get('secret'))
        guard(secret is not None, 'unpublished secret missing')
        self.require_delivery(secret['project'], secret['class'], now)
        kid = state['epochs']['active_kek'][secret['project']]
        dek = crypto.unwrap_key(old_kek, bytes.fromhex(original['wrapped_dek']), bytes.fromhex(original['dek_nonce']), crypto.dek_aad(self.org, version_id, original['kek_id']))
        wrapped, nonce = crypto.wrap_key(new_kek, dek, crypto.dek_aad(self.org, version_id, kid))
        payload['version'].update(kek_id=kid, wrapped_dek=wrapped.hex(), dek_nonce=nonce.hex())
        bodies = [(e['entry']['kind'], e['entry']['body']) for e in payload['entries']]
        if original['secret_id'] in state['epochs']['secrets']:
            bodies = [(k, b) for k, b in bodies if k != 'secret_create']
            payload.pop('secret', None)
        bodies[-1][1].update(kek_id=kid, envelope_digest=crypto.envelope_digest(kid, wrapped, nonce))
        public = crypto.export_point(signing_key.public_key())
        guard(public == crypto.unb64url(self.certificate(state)['sign_pub']), 'unpublished signing key differs')
        seq, prev = state['head']['seq'] + 1, state['head']['hash']
        payload['entries'] = []
        for kind, body in bodies:
            entry = dict(v=2, org_id=self.org, seq=seq, prev_hash=prev, ts=now, kind=kind, body=body, signer=dict(kind='broker', id=self.broker))
            prev, seq = wire.hash_object(entry), seq + 1
            payload['entries'].append(dict(entry=entry, sig=crypto.b64url(crypto.p256_sign(signing_key, crypto.policy_context(self.org, prev)))))
        with self.store.transaction(immediate=True) as db:
            guard(self.checkpoint()['head'] == state['head'], 'unpublished rebuild head changed', 'E_POLICY_HEAD')
            current = db.execute('SELECT payload_json FROM cloud_unpublished WHERE org_id=? AND version_id=?', (self.org, version_id)).fetchone()
            guard(current is not None and current[0] == row['payload_json'], 'unpublished rebuild raced')
            db.execute('UPDATE cloud_unpublished SET head_json=?,kek_id=?,payload_json=? WHERE org_id=? AND version_id=?',
                (crypto.canonical_json(state['head']).decode(), kid, crypto.canonical_json(payload).decode(), self.org, version_id))
        return payload

    def read_value(self, version_id, blk, *, now):
        """Offline value delivery, gated again at the point of decryption."""
        return self._read_value(version_id,blk,now=now,delivery=True)

    def _read_value(self, version_id, blk, *, now, delivery):
        """Internal decryption also feeds the in-broker output scrubber."""
        with self.store._transaction_lock:
            state = self.checkpoint()
            version = next((v for v in state['epochs']['versions'] if v['version_id'] == version_id), None)
            guard(version is not None, 'verified version required')
            secret = state['epochs']['secrets'][version['secret_id']]
            if delivery:
                guard(version['state'] == 'active', 'only the active version may be delivered', 'E_DENIED')
                guard(sum(v['secret_id'] == version['secret_id'] and v['state'] == 'active' for v in state['epochs']['versions']) == 1, 'single active version required')
                self.require_delivery(secret['project'], secret['class'], now)
            else:
                cert = self.certificate(state)
                guard(cert['scope']=='full' or secret['project'] in cert['scope'],'redaction outside certified scope')
            row = self.store.connection.execute('SELECT * FROM cloud_sync_blobs WHERE org_id=? AND version_id=?', (self.org, version_id)).fetchone()
            guard(row is not None and row['head_seq'] == state['head']['seq'], 'ciphertext snapshot requires pull')
            blob = json.loads(row['blob_json'])
            checker = EpochReplay()
            checker._state = state['epochs']
            checker.verify_ciphertext(blob)
            generation = state['epochs']['generation']
            cert = self.certificate(state)
            if cert['scope'] == 'full':
                omk = self.store.cloud_local_key(blk, org=self.org, broker=self.broker, key_id=f'omk_{generation}', purpose='omk', scope='*', generation=generation)
                key = next(k for k in state['epochs']['keyring'] if k['key_id'] == blob['kek_id'])
                kek = crypto.unwrap_key(omk, bytes.fromhex(key['wrapped_key']), bytes.fromhex(key['nonce']), crypto.cloud_keyring_aad(self.org, key['key_id'], 'kek', secret['project'], generation))
            else:
                kek = self.store.cloud_local_key(blk, org=self.org, broker=self.broker, key_id=blob['kek_id'], purpose='kek', scope=secret['project'], generation=generation)
            dek = crypto.unwrap_key(kek, bytes.fromhex(blob['wrapped_dek']), bytes.fromhex(blob['dek_nonce']), crypto.dek_aad(self.org, version_id, blob['kek_id']))
            return crypto.aes_decrypt(dek, bytes.fromhex(blob['ciphertext']), bytes.fromhex(blob['nonce']), crypto.value_aad(self.org, blob['secret_id'], version['version_no']))

    def agent_metadata(self):
        """Explicit metadata allowlist. Never project internal state to agents."""
        state = self.checkpoint()
        cert = self.certificate(state)
        return [dict(secret_id=s['secret_id'], path=s['path'], project=s['project'], **{'class': s['class']})
                for s in state['epochs']['secrets'].values() if cert['scope'] == 'full' or s['project'] in cert['scope']]

    def pickup_keys(self, response, blk, exchange_key, *, checkpoint=None, commit=True):
        """Unseal only current, independently committed custody; persist atomically."""
        from .cloud_epochs import EpochView
        if checkpoint is None:
            state, cert = self.checkpoint(), self.certificate()
        else:
            state, cert = checkpoint, self.certificate(checkpoint)
        if commit:guard(not self.conflicts(), 'conflicted key pickup refuses')
        epoch, generation = state['epochs'], state['epochs']['generation']
        full = cert['scope'] == 'full'
        wire.exact(response, ('omk_generation', 'my_wrap', 'keyring') if full else ('omk_generation', 'broker_key_wraps'))
        guard(response['omk_generation'] == generation and type(response['omk_generation']) is int, 'key pickup generation differs')
        public = crypto.unb64url(cert['kx_pub'])
        keys = {}

        def open_box(row, field, aad):
            box = crypto.SealedBox(bytes.fromhex(row['eph_pub']), bytes.fromhex(row['nonce']), bytes.fromhex(row[field]), row['wrap_digest'])
            return crypto.unseal(exchange_key, public, box, aad)

        if full:
            fields = ('recipient_kind', 'recipient_id', 'omk_generation', 'eph_pub', 'nonce', 'wrapped_omk', 'wrap_digest')
            wrap = response['my_wrap']
            expected = next((w for w in epoch['org_wraps'] if w['recipient_kind'] == 'broker' and w['recipient_id'] == self.broker and w['omk_generation'] == generation), None)
            guard(expected is not None and {k:wrap[k] for k in fields} == expected and wrap.get('revoked_at') is None, 'key pickup OMK commitment differs')
            rows = [{k:r[k] for k in ('key_id', 'purpose', 'project', 'version', 'wrapped_key', 'nonce', 'mk_generation', 'aad_v')} for r in response['keyring']]
            guard(sorted(rows, key=lambda r:r['key_id']) == sorted(epoch['keyring'], key=lambda r:r['key_id']), 'key pickup keyring commitment differs')
            omk = open_box(wrap, 'wrapped_omk', crypto.org_key_wrap_aad(self.org, 'broker', self.broker, generation))
            keys[f'omk_{generation}'] = (omk, 'omk', '*')
            for row in rows:
                key = crypto.unwrap_key(omk, bytes.fromhex(row['wrapped_key']), bytes.fromhex(row['nonce']), crypto.cloud_keyring_aad(self.org, row['key_id'], row['purpose'], row['project'] or '*', generation))
                keys[row['key_id']] = (key, row['purpose'], row['project'] or '*')
        else:
            fields = ('broker_id', 'key_id', 'purpose', 'project', 'eph_pub', 'nonce', 'wrapped_key', 'wrap_digest')
            for wrap in response['broker_key_wraps']:
                row = {k:wrap[k] for k in fields}
                expected = next((w for w in epoch['broker_wraps'] if w['broker_id'] == self.broker and w['key_id'] == wrap['key_id']), None)
                guard(expected == row and wrap.get('revoked_at') is None and (row['purpose'] == 'fingerprint' or row['project'] in cert['scope']), 'key pickup scoped commitment differs')
                guard(row['key_id'] not in keys, 'duplicate scoped pickup key')
                scope = row['project'] or '*'
                keys[row['key_id']] = (open_box(row, 'wrapped_key', crypto.broker_key_wrap_aad(self.org, self.broker, row['key_id'], row['purpose'], scope)), row['purpose'], scope)
            required = {epoch['active_kek'][p] for p in cert['scope']} | {k['key_id'] for k in epoch['keyring'] if k['purpose'] == 'fingerprint'}
            guard(required <= keys.keys(), 'key pickup active custody incomplete')
        if not commit:return sorted(keys)
        self.store.initialize_cloud_custody()
        with self.store.transaction(immediate=True) as db:
            guard(self.checkpoint()['head'] == state['head'], 'key pickup head changed')
            for kid, (key, purpose, scope) in keys.items():
                aad = crypto.local_key_aad(self.org, self.broker, kid, purpose, scope, generation)
                wrapped, nonce = crypto.wrap_key(blk, key, aad)
                prior = db.execute('SELECT * FROM cloud_local_keys WHERE org_id=? AND broker_id=? AND key_id=? AND generation=?', (self.org, self.broker, kid, generation)).fetchone()
                try:
                    prior_key = None if prior is None else crypto.unwrap_key(blk, bytes(prior['wrapped_key']), bytes(prior['nonce']), aad)
                except crypto.CryptoError as exc:
                    raise StoreError('local pickup custody failed verification') from exc
                guard(prior is None or (prior['purpose'] == purpose and prior['scope'] == scope and prior_key == key), 'local pickup custody rebinding')
                db.execute('INSERT OR IGNORE INTO cloud_local_keys VALUES (?,?,?,?,?,?,?,?)', (self.org, self.broker, kid, purpose, scope, generation, wrapped, nonce))
            self.store.prune_cloud_custody(db, self.org, self.broker, state['authority'], epoch)
        return sorted(keys)
