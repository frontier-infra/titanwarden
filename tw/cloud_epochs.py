"""Independent, deterministic replay of committed cloud epoch and ciphertext data.

Inputs must come from the signature-verified policy prefix, including the exact
predecessor authority snapshot. Staging is inert until its signed commitments
activate. This module has no transport, credentials, timers or production caller.
"""
from __future__ import annotations

import copy
import hashlib
import re
from tw import crypto
from tw.policy_log import PolicyError, utc_millis

EPOCH_KINDS = frozenset(('epoch_init', 'epoch_rotate', 'epoch_rotate_projects',
                         'epoch_recipients', 'epoch_commit', 'epoch_cancel', 'dek_rewrap'))
CIPHERTEXT_KINDS = frozenset(('secret_create', 'version_add'))
VERSION_STATE_KINDS = frozenset(('version_state',))
RECIPIENT_CHANGES = frozenset(('member_cert', 'member_revoke', 'cert_activate',
                             'broker_cert', 'broker_revoke', 'recovery_set',
                             'recovery_rotate', 'project_put'))


def fail(message, code='E_POLICY_CONFLICT'):
    raise PolicyError(code, message)


def exact(value, required, optional=()):
    if not isinstance(value, dict) or set(required) - value.keys() or value.keys() - set(required) - set(optional):
        fail('Unexpected or missing field')
    return value


def text(value):
    if not isinstance(value, str) or not re.fullmatch(r'[!-~]+', value) or '|' in value:
        fail('Invalid identifier')
    return value


def integer(value, minimum=0):
    if type(value) is not int or not minimum <= value <= 9007199254740991:
        fail('Invalid integer')
    return value


def digest(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
        fail('Invalid digest')
    return value


def binary(value, length=None):
    if not isinstance(value, str) or not re.fullmatch(r'(?:[0-9a-f]{2})*', value):
        fail('Invalid binary encoding')
    result = bytes.fromhex(value)
    if length is not None and len(result) != length:
        fail('Invalid binary length')
    return result


def array(value):
    if not isinstance(value, list):
        fail('Expected array')
    return value


def unique(items, fields):
    keys = [tuple(item[f] for f in fields) for item in items]
    if len(keys) != len(set(keys)):
        fail('Duplicate item')


def hash_object(value):
    return hashlib.sha256(crypto.canonical_json(value)).hexdigest()


def keyring_digest(row):
    """K1 digest, deliberately without a separator before canonical JSON."""
    if 'wrapped_key' not in row and 'commitment_digest' in row:
        return digest(row['commitment_digest'])
    core = dict(kek_id=row['key_id'], version=row['version'], purpose=row['purpose'],
                nonce=row['nonce'], wrapped_key=row['wrapped_key'])
    return hashlib.sha256(b'tw2|keyring-digest' + crypto.canonical_json(core)).hexdigest()


def checked_key(row):
    exact(row, ('key_id', 'purpose', 'project', 'version', 'wrapped_key', 'nonce', 'mk_generation', 'aad_v'))
    text(row['key_id']); integer(row['version'], 1); integer(row['mk_generation'], 1)
    binary(row['wrapped_key'], 48); binary(row['nonce'], 12)
    if type(row['aad_v']) is not int or row['aad_v'] != 2 or row['purpose'] not in ('kek', 'fingerprint'):
        fail('Invalid key')
    if row['purpose'] == 'kek':
        text(row['project'])
    elif row['project'] is not None:
        fail('Fingerprint scope must be null')
    return row


def _box(row, field):
    point = binary(row['eph_pub'], 65)
    try:
        crypto.import_point(point)
    except (ValueError, TypeError) as exc:
        fail('Invalid ephemeral point')
    if crypto.wrap_digest(point, binary(row['nonce'], 12), binary(row[field], 48)) != digest(row['wrap_digest']):
        fail('Substituted wrap')


class PublicStage(dict):
    """Internal verified commitment view, never a complete StagePayload."""


def checked_stage(value):
    if isinstance(value, PublicStage):
        return copy.deepcopy(value)
    exact(value, ('keyring', 'wraps', 'scoped_seals'))
    stage = copy.deepcopy(value)
    for row in array(stage['keyring']):
        checked_key(row)
    for row in array(stage['wraps']):
        exact(row, ('recipient_kind', 'recipient_id', 'omk_generation', 'eph_pub', 'nonce', 'wrapped_omk', 'wrap_digest'))
        if row['recipient_kind'] not in ('member_key', 'broker', 'recovery'):
            fail('Invalid recipient')
        text(row['recipient_id']); integer(row['omk_generation'], 1); _box(row, 'wrapped_omk')
    for row in array(stage['scoped_seals']):
        exact(row, ('broker_id', 'key_id', 'purpose', 'project', 'eph_pub', 'nonce', 'wrapped_key', 'wrap_digest'))
        text(row['broker_id']); text(row['key_id'])
        if row['purpose'] == 'kek':
            text(row['project'])
        elif row['purpose'] != 'fingerprint' or row['project'] is not None:
            fail('Invalid scoped key')
        _box(row, 'wrapped_key')
    unique(stage['keyring'], ('key_id',))
    unique(stage['wraps'], ('recipient_kind', 'recipient_id'))
    unique(stage['scoped_seals'], ('broker_id', 'key_id'))
    return stage


def checked_scope(value):
    if value == 'full':
        return ['*']
    value = array(value)
    if any(not isinstance(p, str) or not p or '|' in p for p in value) or len(set(value)) != len(value) or '*' in value:
        fail('Invalid certified scope')
    if value != sorted(value):
        fail('Unsorted certified scope')
    return value[:]


def derive_recipients(snapshot):
    result = []
    for kind, rows in (('member_key', snapshot['members']), ('broker', [b for b in snapshot['brokers'] if b['scope'] == 'full']),
                       ('recovery', [snapshot['recovery']] if snapshot.get('recovery') else [])):
        for row in rows:
            point = binary(row['kx_pub'], 65)
            crypto.import_point(point)
            result.append(dict(kind=kind, id=text(row['id']), kx_pub_sha256=hashlib.sha256(point).hexdigest()))
    unique(result, ('kind', 'id'))
    return sorted(result, key=lambda r: (r['kind'], r['id']))


def recipient_hints(snapshot):
    derive_recipients(snapshot)
    recipients = [dict(kind='member_key', id=m['id'], kx_pub=m['kx_pub']) for m in snapshot['members']]
    recipients += [dict(kind='broker', id=b['id'], kx_pub=b['kx_pub']) for b in snapshot['brokers'] if b['scope'] == 'full']
    if snapshot.get('recovery'):
        recipients.append(dict(kind='recovery', id=snapshot['recovery']['id'], kx_pub=snapshot['recovery']['kx_pub']))
    scoped = [dict(broker_id=b['id'], kx_pub=b['kx_pub'], projects=checked_scope(b['scope'])) for b in snapshot['brokers'] if b['scope'] != 'full']
    return dict(recipients=sorted(recipients, key=lambda r: (r['kind'], r['id'])), scoped=sorted(scoped, key=lambda r: r['broker_id']))


def verify_recipient_hints(snapshot, hints):
    if hints != recipient_hints(snapshot):
        fail('rekey_recipient_mismatch')


def checked_recipients(value):
    rows = array(value)
    for r in rows:
        exact(r, ('kind', 'id', 'kx_pub_sha256', 'wrap_digest'))
        if r['kind'] not in ('member_key', 'broker', 'recovery'):
            fail('Invalid recipient kind')
        text(r['id']); digest(r['kx_pub_sha256']); digest(r['wrap_digest'])
    unique(rows, ('kind', 'id'))
    if rows != sorted(rows, key=lambda r: (r['kind'], r['id'])):
        fail('Recipient ordering')
    return rows


def _identities(rows):
    return [{k: v for k, v in r.items() if k != 'wrap_digest'} for r in rows]


def _keeper(signer, snapshot):
    if signer['kind'] == 'member' and any(m['id'] == signer.get('key') and m['member_id'] == signer.get('id') for m in snapshot['members']):
        return
    if signer['kind'] == 'broker' and any(b['id'] == signer.get('id') and b['scope'] == 'full' and b['keeper'] is True for b in snapshot['brokers']):
        return
    fail('Keeper certificate required')


def _writer(signer, project, snapshot):
    if project not in snapshot['projects']:
        fail('Unknown project')
    if signer['kind'] == 'member':
        return _keeper(signer, snapshot)
    if signer['kind'] == 'broker' and any(b['id'] == signer.get('id') and (b['scope'] == 'full' or project in checked_scope(b['scope'])) for b in snapshot['brokers']):
        return
    fail('Writer certificate required')


class EpochReplay:
    def _first_project(self, state, entry, snapshot, project, change):
        return False
    """Atomic replay; rejected entries never mutate any accepted state."""
    def __init__(self):
        self._state = dict(generation=0, active_kek={}, keyring=[], org_wraps=[], broker_wraps=[],
                          epochs=[], used_triggers=[], last_discretionary_rotation=None,
                          pending=None, versions=[], secrets={})

    @property
    def state(self):
        return copy.deepcopy(self._state)

    def apply(self, entry, snapshot, *, stage=None, received_at=None, blob=None, mode='live'):
        try:
            return self._apply(entry, snapshot, stage=stage, received_at=received_at, blob=blob, mode=mode)
        except (KeyError, TypeError, ValueError, OverflowError, crypto.CryptoError) as exc:
            raise PolicyError('E_POLICY_CONFLICT', 'Malformed epoch input') from exc

    def _apply(self, entry, snapshot, *, stage=None, received_at=None, blob=None, mode='live'):
        if mode not in ('live', 'history'):
            fail('Invalid epoch replay mode')
        exact(entry, ('v', 'org_id', 'seq', 'prev_hash', 'ts', 'kind', 'body', 'signer'))
        exact(snapshot.get('head'), ('seq', 'hash'))
        integer(entry['seq'], 1); digest(entry['prev_hash'])
        if entry['v'] != 2 or not isinstance(entry['kind'], str) or not isinstance(entry['body'], dict) or not isinstance(entry['signer'], dict):
            fail('Malformed epoch entry')
        if entry['seq'] != snapshot['head']['seq'] + 1 or entry['prev_hash'] != snapshot['head']['hash'] or len(crypto.canonical_json(entry)) > 65536:
            fail('Snapshot head mismatch')
        if entry['kind'] not in EPOCH_KINDS | CIPHERTEXT_KINDS | VERSION_STATE_KINDS:
            fail('Unsupported epoch kind')
        received_at = received_at or entry['ts']
        utc_millis(received_at); utc_millis(entry['ts'])
        state = copy.deepcopy(self._state)
        self._transition(state, entry, snapshot, received_at, stage, blob, mode)
        self._state = state
        return copy.deepcopy(state)

    def observe_authority(self, entry, snapshot):
        """Call only after independently accepting an authority entry."""
        if entry['seq'] != snapshot['head']['seq'] + 1 or entry['prev_hash'] != snapshot['head']['hash']:
            fail('Snapshot head mismatch')
        if entry['kind'] not in RECIPIENT_CHANGES:
            fail('Unsupported authority observation')
        if self._state['pending']:
            self._state['pending']['superseded'] = True

    def confirm_member_wrap(self, entry, wrap):
        """Install only the independently verified, signed confirmation box."""
        body = entry['body']; cert = body['requested']['certificate']
        checked = checked_stage(dict(keyring=[], wraps=[wrap], scoped_seals=[]))['wraps'][0]
        if entry['kind'] != 'member_cert' or not cert['key_holder'] or checked['recipient_kind'] != 'member_key' or checked['recipient_id'] != cert['member_key_id'] or checked['omk_generation'] != self._state['generation'] or body['wrap'] != dict(omk_generation=checked['omk_generation'], wrap_digest=checked['wrap_digest']):
            fail('Confirmed member wrap mismatch')
        self._state['org_wraps'] = [w for w in self._state['org_wraps'] if not (w['omk_generation'] == checked['omk_generation'] and w['recipient_kind'] == 'member_key' and w['recipient_id'] == checked['recipient_id'])] + [checked]
        if self._state['pending']:
            self._state['pending']['superseded'] = True

    def _pending(self, state, entry, received):
        pending = state['pending']
        if not pending or pending['superseded'] or integer(entry['body']['epoch_seq'], 1) != pending['seq'] or not 0 <= utc_millis(received) - utc_millis(pending['received_at']) < 1800000:
            fail('Epoch superseded', 'E_EPOCH_SUPERSEDED')
        if pending['signer'] != entry['signer']:
            fail('Intent keeper required')
        return pending

    def _keys(self, state, entry, snapshot, stage):
        b = entry['body']; initializing = entry['kind'] == 'epoch_init'; full = entry['kind'] != 'epoch_rotate_projects'
        generation = integer(b['generation'] if initializing else b['to_generation'] if full else b['omk_generation'], 1)
        if (initializing and (state['generation'] != 0 or generation != 1)) or (not initializing and full and (integer(b['from_generation'], 1) != state['generation'] or generation != state['generation'] + 1)) or (not full and generation != state['generation']):
            fail('Generation mismatch')
        if full:
            active = b['active_kek']
            if not isinstance(active, dict) or sorted(active) != sorted(snapshot['projects']):
                fail('Project set mismatch')
            for p, k in active.items():
                text(p); text(k)
            projects = sorted(active)
        else:
            changes = b['projects']
            if not isinstance(changes, dict) or not changes:
                fail('Empty project rekey')
            projects = sorted(changes); active = dict(state['active_kek'])
            for p, c in changes.items():
                exact(c, ('from_kek_id', 'to_kek_id'))
                first = self._first_project(state,entry,snapshot,p,c)
                if p not in snapshot['projects'] or not first and state['active_kek'].get(p) != text(c['from_kek_id']):
                    fail('Project predecessor mismatch')
                active[p] = text(c['to_kek_id'])
        fresh = []
        for p in projects:
            key = next((k for k in stage['keyring'] if k['key_id'] == active[p]), None)
            old = next((k for k in state['keyring'] if k['key_id'] == state['active_kek'].get(p)), None)
            first = not full and self._first_project(state,entry,snapshot,p,b['projects'][p])
            version = 1 if initializing or first else integer(old['version'] if old else None, 1) + 1
            if not key or key['purpose'] != 'kek' or key['project'] != p or key['mk_generation'] != generation or key['version'] != version or any(k['key_id'] == active[p] for k in state['keyring']) or any(active[p] in e['active_kek'].values() for e in state['epochs']):
                fail('Active KEK mismatch')
            fresh.append(key)
        if initializing:
            if len(stage['keyring']) != len(projects) + 1 or sum(k['purpose'] == 'fingerprint' and k['version'] == 1 and k['mk_generation'] == 1 for k in stage['keyring']) != 1:
                fail('Initial keyring mismatch')
        elif full:
            if len(stage['keyring']) != len(state['keyring']) + len(fresh):
                fail('Historical keyring missing')
            for old in state['keyring']:
                key = next((k for k in stage['keyring'] if k['key_id'] == old['key_id']), None)
                if not key or any(key[f] != old[f] for f in ('version', 'purpose', 'project')) or key['mk_generation'] != generation:
                    fail('Historical key metadata changed')
        elif len(stage['keyring']) != len(projects):
            fail('Unrelated project keys')
        commitments = array(b['keyring'])
        for c in commitments:
            exact(c, ('key_id', 'purpose', 'scope', 'digest')); text(c['key_id']); text(c['scope']); digest(c['digest'])
        unique(commitments, ('key_id',))
        expected = [dict(key_id=k['key_id'], purpose=k['purpose'], scope=k['project'] or '*', digest=keyring_digest(k)) for k in stage['keyring']]
        if sorted(commitments, key=lambda k: k['key_id']) != sorted(expected, key=lambda k: k['key_id']):
            fail('Keyring digest mismatch')
        seals = array(b['scoped_seals'])
        for s in seals:
            exact(s, ('broker_id', 'key_id', 'project', 'wrap_digest')); digest(s['wrap_digest'])
        unique(seals, ('broker_id', 'key_id'))
        expected = [dict(broker_id=broker['id'], key_id=k['key_id'], project=k['project']) for broker in snapshot['brokers'] if broker['scope'] != 'full' for k in fresh if k['project'] in checked_scope(broker['scope'])]
        if sorted(({k: v for k, v in s.items() if k != 'wrap_digest'} for s in seals), key=lambda s: (s['broker_id'], s['key_id'])) != sorted(expected, key=lambda s: (s['broker_id'], s['key_id'])):
            fail('Scoped seal mismatch')
        actual = [dict(broker_id=w['broker_id'], key_id=w['key_id'], project=w['project'], wrap_digest=w['wrap_digest']) for w in stage['scoped_seals'] if w['purpose'] == 'kek']
        if len(actual) != len(stage['scoped_seals']) or sorted(actual, key=lambda s: (s['broker_id'], s['key_id'])) != sorted(seals, key=lambda s: (s['broker_id'], s['key_id'])):
            fail('Scoped blob mismatch')
        return active, projects

    def _trigger(self, state, entry, snapshot, projects, budget=True):
        b = entry['body']
        if 'trigger_seq' in b:
            seq = integer(b['trigger_seq'], 1)
            trigger = next((t for t in snapshot.get('rekey_triggers', []) if t['seq'] == seq), None)
            if 'reason' in b or seq > snapshot['head']['seq'] or seq in state['used_triggers'] or not trigger or trigger['kind'] != ('full' if entry['kind'] == 'epoch_rotate' else 'projects') or (trigger['kind'] == 'projects' and sorted(trigger['projects']) != projects):
                fail('Invalid or reused trigger')
            reasons = ('key_holder_removed', 'key_holder_key_reset', 'recovery_rotated', 'full_broker_revoked', 'full_to_scoped_downgrade', 'manual', 'scheduled') if trigger['kind'] == 'full' else ('scoped_broker_revoked', 'scoped_broker_narrowed')
            reason = trigger['reason']
            if reason not in reasons:
                fail('Undefined trigger reason')
        else:
            reason = b.get('reason')
            if entry['kind'] != 'epoch_rotate' or reason not in ('manual', 'scheduled'):
                fail('Trigger required')
        if budget and reason in ('manual', 'scheduled') and state['last_discretionary_rotation'] and utc_millis(entry['ts']) - utc_millis(state['last_discretionary_rotation']) < 86400000:
            fail('Rotation daily limit')
        return reason

    def _wraps(self, recipients, stage, generation):
        actual = sorted((dict(kind=w['recipient_kind'], id=w['recipient_id'], wrap_digest=w['wrap_digest']) for w in stage['wraps'] if w['omk_generation'] == generation), key=lambda r: (r['kind'], r['id']))
        if len(actual) != len(stage['wraps']) or actual != [{k: v for k, v in r.items() if k != 'kx_pub_sha256'} for r in recipients]:
            fail('OMK blob mismatch')

    def _activate(self, state, entry, snapshot, stage, active, projects, reason, intent_seq=None):
        project_only = entry['kind'] == 'epoch_rotate_projects'; b = entry['body']
        state['generation'] = state['generation'] if project_only else b.get('generation', b.get('to_generation'))
        state['active_kek'] = copy.deepcopy(active)
        state['keyring'] = state['keyring'] + stage['keyring'] if project_only else copy.deepcopy(stage['keyring'])
        covered = [] if project_only or entry['kind'] == 'epoch_init' else [t['seq'] for t in snapshot.get('rekey_triggers', []) if t['seq'] <= snapshot['head']['seq']]
        if 'trigger_seq' in b:
            covered.append(b['trigger_seq'])
        if reason in ('manual', 'scheduled'):
            state['last_discretionary_rotation'] = entry['ts']
        covered = sorted(set(covered)); state['used_triggers'] = sorted(set(state['used_triggers'] + covered))
        state['epochs'].append(dict(seq=intent_seq or entry['seq'], commit_seq=entry['seq'], kind='projects' if project_only else 'full', covered_triggers=covered, generation=state['generation'], active_kek=copy.deepcopy(active), projects=projects, full_brokers=[w['recipient_id'] for w in stage['wraps'] if w['recipient_kind'] == 'broker'] if not project_only else [], **{k: b[k] for k in ('plan_id', 'trigger_seq') if k in b}))
        if not project_only:
            state['org_wraps'] = copy.deepcopy(stage['wraps'])
        seals = {(w['broker_id'], w['key_id']) for w in stage['scoped_seals']}
        state['broker_wraps'] = [w for w in state['broker_wraps'] if (w['broker_id'], w['key_id']) not in seals] + stage['scoped_seals']
        state['pending'] = None
        self._collect(state)

    @staticmethod
    def _collect(state):
        needed = set(state['active_kek'].values()) | {v['kek_id'] for v in state['versions']}
        state['keyring'] = [k for k in state['keyring'] if k['purpose'] == 'fingerprint' or k['key_id'] in needed]
        retained = {k['key_id'] for k in state['keyring']}
        state['broker_wraps'] = [w for w in state['broker_wraps'] if w['key_id'] in retained]

    def _transition(self, state, entry, snapshot, received, stage_input, blob, mode):
        kind = entry['kind']; b = entry['body']
        if kind == 'version_state':
            from .cloud_version_state import activate
            return activate(state, entry, snapshot)
        if kind in CIPHERTEXT_KINDS:
            return self._ciphertext(state, entry, snapshot, blob, mode)
        if kind == 'epoch_commit' and state['pending'] is None:
            fail('Missing intent')
        pending = self._pending(state, entry, received) if kind in ('epoch_recipients', 'epoch_commit', 'epoch_cancel') else None
        if kind == 'epoch_init':
            founder = snapshot.get('founder')
            if not founder or state['generation'] or entry['signer'] != founder['signer'] or snapshot['head']['seq'] != founder['init_after_seq'] or entry['seq'] != founder['init_after_seq'] + 1:
                fail('Invalid initial epoch position')
            if founder['mode'] == 'browser':
                if len(snapshot['members']) != 1 or snapshot['brokers'] or not snapshot.get('recovery') or snapshot['members'][0]['id'] != entry['signer'].get('key'):
                    fail('Browser founder recipients')
            elif founder['mode'] != 'broker' or snapshot['members'] or len(snapshot['brokers']) != 1 or snapshot.get('recovery') or snapshot['brokers'][0]['id'] != entry['signer']['id'] or snapshot['brokers'][0]['scope'] != 'full':
                fail('Broker founder recipients')
        else:
            _keeper(entry['signer'], snapshot)
        if kind in ('epoch_init', 'epoch_rotate', 'epoch_rotate_projects'):
            if kind == 'epoch_init':
                exact(b, ('generation', 'recipients', 'scoped_seals', 'keyring', 'active_kek'))
            elif kind == 'epoch_rotate':
                exact(b, ('from_generation', 'to_generation', 'recipients', 'scoped_seals', 'keyring', 'active_kek'), ('trigger_seq', 'reason', 'plan_id', 'fence', 'kind', 'recipients_count', 'recipients_sha256'))
            else:
                exact(b, ('trigger_seq', 'omk_generation', 'projects', 'keyring', 'scoped_seals'), ('plan_id', 'fence'))
            if 'plan_id' in b:
                text(b['plan_id'])
            if 'fence' in b:
                integer(b['fence'], 1)
            if ('kind' in b and b['kind'] != 'full') or (('recipients_count' in b) != ('recipients_sha256' in b)):
                fail('Invalid pagination or epoch kind')
            stage = checked_stage(stage_input)
            active, projects = self._keys(state, entry, snapshot, stage)
            recipients = [] if kind == 'epoch_rotate_projects' else checked_recipients(b['recipients'])
            reason = None if kind == 'epoch_init' else self._trigger(state, entry, snapshot, projects, 'recipients_count' not in b)
            if kind == 'epoch_rotate_projects':
                if stage['wraps']:
                    fail('Project rekey carries OMK wraps')
            elif 'recipients_count' in b:
                count = integer(b['recipients_count'], 1); digest(b['recipients_sha256'])
                expected = derive_recipients(snapshot)
                if count != len(expected) or not 0 < len(recipients) < count or _identities(recipients) != expected[:len(recipients)] or len(stage['wraps']) != count:
                    fail('Invalid first page')
                state['pending'] = dict(seq=entry['seq'], signer=copy.deepcopy(entry['signer']), received_at=received, body=copy.deepcopy(b), recipients=copy.deepcopy(recipients), next_page=1, superseded=False, stage=copy.deepcopy(stage))
                return
            else:
                if _identities(recipients) != derive_recipients(snapshot):
                    fail('rekey_recipient_mismatch')
                self._wraps(recipients, stage, b.get('generation', b.get('to_generation')))
            self._activate(state, entry, snapshot, stage, active, projects, reason)
        elif kind == 'epoch_recipients':
            exact(b, ('epoch_seq', 'page', 'items'))
            if integer(b['page'], 1) != pending['next_page']:
                fail('Non-contiguous recipient page')
            items = checked_recipients(b['items'])
            if not items:
                fail('Empty recipient page')
            recipients = checked_recipients(pending['recipients'] + items)
            if len(recipients) > pending['body']['recipients_count'] or _identities(recipients) != derive_recipients(snapshot)[:len(recipients)]:
                fail('rekey_recipient_mismatch')
            pending['recipients'] = recipients; pending['next_page'] += 1
        elif kind == 'epoch_cancel':
            exact(b, ('epoch_seq',)); pending['superseded'] = True
        elif kind == 'epoch_commit':
            exact(b, ('epoch_seq',))
            if len(pending['recipients']) != pending['body']['recipients_count'] or hash_object(pending['recipients']) != pending['body']['recipients_sha256'] or _identities(pending['recipients']) != derive_recipients(snapshot):
                fail('Incomplete recipient pages')
            stage = checked_stage(stage_input)
            if stage != pending['stage']:
                fail('Staged payload changed after intent')
            intent = dict(entry, kind='epoch_rotate', body=pending['body'])
            active, projects = self._keys(state, intent, snapshot, stage)
            self._wraps(pending['recipients'], stage, pending['body']['to_generation'])
            reason = self._trigger(state, intent, snapshot, projects)
            self._activate(state, intent, snapshot, stage, active, projects, reason, pending['seq'])
        elif kind == 'dek_rewrap':
            exact(b, ('epoch_seq', 'items'))
            epoch = next((e for e in state['epochs'] if e['seq'] == integer(b['epoch_seq'], 1)), None)
            items = array(b['items'])
            if not epoch or not 1 <= len(items) <= 200:
                fail('Uncommitted epoch or invalid rewrap batch')
            seen = set()
            for item in items:
                exact(item, ('version_id', 'from_kek_id', 'from_envelope_digest', 'to_kek_id', 'to_envelope_digest'))
                vid = text(item['version_id']); version = next((v for v in state['versions'] if v['version_id'] == vid), None)
                if vid in seen or not version or version['kek_id'] != text(item['from_kek_id']) or version['envelope_digest'] != digest(item['from_envelope_digest']) or item['to_kek_id'] != epoch['active_kek'].get(version['project']) or item['to_kek_id'] != state['active_kek'].get(version['project']) or item['to_kek_id'] == item['from_kek_id'] or version['project'] not in epoch['projects']:
                    fail('Stale, duplicate or unrelated envelope')
                seen.add(vid); version['kek_id'] = text(item['to_kek_id']); version['envelope_digest'] = digest(item['to_envelope_digest'])
            self._collect(state)

    def _ciphertext(self, state, entry, snapshot, blob, mode):
        b = entry['body']
        if entry['kind'] == 'secret_create':
            exact(b, ('secret_id', 'path', 'project', 'class'), ('kind', 'provider'))
            sid = text(b['secret_id']); project = text(b['project']); path = text(b['path'])
            if b['class'] not in ('standard', 'sensitive', 'restricted') or not path.startswith(project + '/') or sid in state['secrets'] or any(s['path'] == path for s in state['secrets'].values()):
                fail('Invalid or duplicate secret metadata')
            if 'kind' in b:
                text(b['kind'])
            if b.get('provider') is not None:
                text(b['provider'])
            _writer(entry['signer'], project, snapshot)
            state['secrets'][sid] = copy.deepcopy(b)
            return
        exact(b, ('version_id', 'secret_id', 'version_no', 'state', 'kek_id', 'fingerprint', 'length', 'source', 'value_digest', 'envelope_digest'))
        vid = text(b['version_id']); sid = text(b['secret_id']); secret = state['secrets'].get(sid)
        if not secret or b['state'] not in ('pending', 'active'):
            fail('Invalid new version')
        project = secret['project']; _writer(entry['signer'], project, snapshot)
        if state['active_kek'].get(project) != text(b['kek_id']):
            fail('Current project KEK required', 'E_STALE_EPOCH')
        existing = [v for v in state['versions'] if v['secret_id'] == sid]
        if any(v['version_id'] == vid for v in state['versions']) or integer(b['version_no'], 1) != max((v['version_no'] for v in existing), default=0) + 1 or (b['state'] == 'active' and any(v['state'] == 'active' for v in existing)):
            fail('Version identity, sequence or active conflict')
        exact(blob, ('version_id', 'secret_id', 'kek_id', 'ciphertext', 'nonce', 'wrapped_dek', 'dek_nonce'))
        if any(blob[k] != b[k] for k in ('version_id', 'secret_id')) or (mode == 'live' and blob['kek_id'] != b['kek_id']):
            fail('Ciphertext identity mismatch')
        ciphertext = binary(blob['ciphertext']); nonce = binary(blob['nonce'], 12)
        wrapped = binary(blob['wrapped_dek'], 48); dek_nonce = binary(blob['dek_nonce'], 12)
        if not 16 <= len(ciphertext) <= 1048576 or integer(b['length'], 16) != len(ciphertext) or crypto.value_digest(ciphertext, nonce) != digest(b['value_digest']):
            fail('Substituted value ciphertext')
        text(blob['kek_id'])
        envelope_matches = crypto.envelope_digest(b['kek_id'], wrapped, dek_nonce) == digest(b['envelope_digest'])
        if not envelope_matches and mode == 'live':
            fail('Substituted DEK envelope')
        binary(b['fingerprint'], 32); text(b['source'])
        state['versions'].append(dict(copy.deepcopy(b), project=project))

    def verify_ciphertext(self, blob):
        exact(blob, ('version_id', 'secret_id', 'kek_id', 'ciphertext', 'nonce', 'wrapped_dek', 'dek_nonce'))
        expected = next((v for v in self._state['versions'] if v['version_id'] == blob['version_id']), None)
        if not expected or any(expected[k] != blob[k] for k in ('secret_id', 'kek_id')) or len(binary(blob['ciphertext'])) != expected['length'] or crypto.value_digest(binary(blob['ciphertext']), binary(blob['nonce'], 12)) != expected['value_digest'] or crypto.envelope_digest(blob['kek_id'], binary(blob['wrapped_dek'], 48), binary(blob['dek_nonce'], 12)) != expected['envelope_digest']:
            fail('Current ciphertext commitment mismatch')
        return copy.deepcopy(expected)

    def verify_current_ciphertexts(self, blobs, *, projects=None):
        """Finalize history against every current envelope, including dropped rows.

        Historical version entries bind immutable ciphertext while rewrap entries
        advance envelope commitments. Rebuild must call this after the complete
        log before treating any supplied current blob as verified material.
        """
        rows = array(blobs)
        for row in rows:
            exact(row, ('version_id', 'secret_id', 'kek_id', 'ciphertext', 'nonce', 'wrapped_dek', 'dek_nonce'))
        unique(rows, ('version_id',))
        if {r['version_id'] for r in rows} != {v['version_id'] for v in self._state['versions'] if projects is None or v['project'] in projects}:
            fail('Missing or extra current ciphertext rows')
        return [self.verify_ciphertext(row) for row in rows]

    def view(self, snapshot):
        return EpochView(self._state, snapshot)


class EpochView:
    """Copied exact-head commitments and retained exposure, independent of scope."""
    def __init__(self, state, snapshot):
        self._state = copy.deepcopy(state); self.snapshot = copy.deepcopy(snapshot)

    def _head(self, head):
        exact(head, ('seq', 'hash'))
        integer(head['seq']); digest(head['hash'])
        if head != self.snapshot['head']:
            fail('Epoch head mismatch')
        if any(type(e['commit_seq']) is not int or not e['seq'] <= e['commit_seq'] <= head['seq'] for e in self._state['epochs']):
            fail('Epoch predecessor mismatch')

    def committed_generation(self, head):
        self._head(head)
        if not self._state['epochs']:
            if self._state['generation']:
                fail('Missing verified epoch commit')
            return dict(kind='none_committed')
        if self._state['epochs'][-1]['generation'] != self._state['generation']:
            fail('Epoch generation checkpoint mismatch')
        return dict(kind='committed', generation=self._state['generation'])

    def active_kek(self, project, head):
        self._head(head)
        if project not in self._state['active_kek']:
            fail('Unknown project')
        return self._state['active_kek'][project]

    def custody_evidence(self, broker_id, head):
        self._head(head)
        broker = next((b for b in self.snapshot['brokers'] if b['id'] == broker_id), None)
        if not broker:
            fail('Unknown broker')
        covered = sorted({t for e in self._state['epochs'] for t in e['covered_triggers']})
        pending_projects = set(); downgrades = []; exposure_generations = []
        for change in broker.get('scope_changes', []):
            integer(change['seq'], 1)
            if change['seq'] > head['seq']:
                continue
            if change['from_scope'] == 'full' and change['to_scope'] != 'full':
                trigger = next((t for t in self.snapshot.get('rekey_triggers', []) if t['seq'] == change['seq']), None)
                if not trigger or trigger['kind'] != 'full' or trigger['reason'] != 'full_to_scoped_downgrade':
                    fail('Unverified downgrade trigger')
                downgrades.append(change['seq'])
                exposure_generations.extend(e['generation'] for e in self._state['epochs'] if e['commit_seq'] < change['seq'])
            elif change['from_scope'] != 'full' and change['to_scope'] != 'full':
                for p in set(checked_scope(change['from_scope'])) - set(checked_scope(change['to_scope'])):
                    if not any(e['commit_seq'] > change['seq'] and p in e['projects'] and change['seq'] in e['covered_triggers'] and (e['kind'] == 'full' or e.get('trigger_seq') == change['seq']) for e in self._state['epochs']):
                        pending_projects.add(p)
        exposure_generations.extend(e['generation'] for e in self._state['epochs'] if broker_id in e['full_brokers'])
        if broker['scope'] == 'full' and self._state['generation']:
            exposure_generations.append(self._state['generation'])
        full_generation = max(exposure_generations, default=None)
        full = broker['scope'] == 'full' or full_generation == self._state['generation']
        custody = 'full' if full else sorted(set(checked_scope(broker['scope'])) | pending_projects)
        pending = sorted(set(downgrades) - set(covered))
        if pending and custody != 'full':
            fail('Pending downgrade has no matching committed full epoch')
        self.committed_generation(head)
        return dict(verified=True, head=copy.deepcopy(head), custody=custody, pending_downgrades=pending, covered_triggers=covered, generation=self._state['generation'], full_custody_generation=full_generation)


def epoch_checkpoint(state):
    """Project replay data to the pinned cloud EpochState checkpoint contract.

    Local secret metadata, recipient exposure provenance and immutable staging
    evidence remain local. The cloud checkpoint names the immutable value hash
    ciphertext_digest; the signed policy name remains value_digest.
    """
    fields = ('generation', 'active_kek', 'keyring', 'org_wraps', 'broker_wraps',
              'epochs', 'used_triggers', 'last_discretionary_rotation', 'pending', 'versions')
    exact(state, fields, ('secrets',))
    projected = copy.deepcopy(state)
    projected.pop('secrets', None)
    for epoch in array(projected['epochs']):
        exact(epoch, ('seq', 'commit_seq', 'kind', 'covered_triggers', 'generation',
                      'active_kek', 'projects'), ('plan_id', 'trigger_seq', 'full_brokers'))
        epoch.pop('full_brokers', None)
    pending = projected['pending']
    if pending is not None:
        exact(pending, ('seq', 'signer', 'received_at', 'body', 'recipients',
                        'next_page', 'superseded'), ('stage',))
        pending.pop('stage', None)
    for version in array(projected['versions']):
        exact(version, ('version_id', 'secret_id', 'version_no', 'state', 'fingerprint',
                        'length', 'source', 'project', 'kek_id', 'envelope_digest', 'value_digest'))
        version['ciphertext_digest'] = version.pop('value_digest')
    return projected


def epoch_blob_commitments(state):
    """Recompute every current keyring, OMK wrap and scoped-wrap commitment."""
    return ([dict(id='keyring:' + k['key_id'], digest=keyring_digest(k)) for k in state['keyring']]
            + [dict(id=f"org_wrap:{w['omk_generation']}:{w['recipient_kind']}:{w['recipient_id']}",
                    digest=w['wrap_digest']) for w in state['org_wraps']]
            + [dict(id=f"broker_wrap:{w['broker_id']}:{w['key_id']}", digest=w['wrap_digest'])
               for w in state['broker_wraps']])
