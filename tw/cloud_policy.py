"""Offline authority replay against an independently pinned policy chain.

Local observations are separate from replay snapshots. Evidence ports accept only
independently verified enrollment, slot, wrap and epoch custody information.
"""
from __future__ import annotations

from copy import deepcopy

from tw import crypto, cloud_wire as wire
from tw.policy_log import PolicyHooks, ZERO_HASH, utc_millis

AUTHORITY_KINDS = frozenset(('genesis', 'member_cert', 'member_revoke',
    'cert_proposal', 'recovery_rotate', 'cert_endorse', 'cert_cancel',
    'cert_activate', 'broker_cert', 'broker_revoke'))
HOLD_MS = 86400000
EVIDENCE_MARGIN_MS = 600000
PROOF = ('request_id', 'authz', 'assertion')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def empty_authority(org_id):
    return dict(v=1, org_id=org_id, head=dict(seq=0, hash=ZERO_HASH), root=None,
        certificates=[], proposals={}, recovery=None, recovery_ever_set=False,
        founding_broker=None, used_challenges=[], founder=None,
        founder_pending=None, recovery_seq=0, triggers={}, brokers=[], core_commitments=[],
        used_recovery_points=[])


class AuthorityView:
    def __init__(self, state):
        self.state = deepcopy(state)

    def current(self, member_id):
        return next((deepcopy(v) for v in reversed(self.state['certificates'])
                     if v['certificate']['member_id'] == member_id), None)

    def active(self):
        latest = {v['certificate']['member_id']: v['certificate']
                  for v in self.state['certificates']}
        return deepcopy([c for c in latest.values() if c['state'] == 'active'])

    def certificate_at(self, key_id, seq):
        if type(seq) is not int or not 1 <= seq <= self.state['head']['seq']:
            return None
        latest = {v['certificate']['member_id']: v['certificate']
                  for v in self.state['certificates'] if v['seq'] <= seq}
        return next((deepcopy(c) for c in latest.values()
                     if c['member_key_id'] == key_id), None)

    def is_certified(self, key_id, min_rank, head):
        try:
            wire.parse_head(head)
        except (ValueError, TypeError):
            return False
        if head != self.state['head'] or type(min_rank) is not int or not 1 <= min_rank <= 3:
            return False
        cert = self.certificate_at(key_id, head['seq'])
        return bool(cert and cert['state'] == 'active' and wire.rank(cert['role']) >= min_rank)

    def broker_certificate_at(self, broker_id, head):
        try:
            wire.parse_head(head)
        except (ValueError, TypeError):
            return None
        if head != self.state['head']:
            return None
        cert = next((v['certificate'] for v in reversed(self.state['brokers'])
                     if v['certificate']['broker_id'] == broker_id), None)
        if cert:
            return dict(deepcopy(cert), source='certificate') if cert['state'] == 'active' else None
        founder = self.state['founding_broker']
        if not (founder and founder['id'] == broker_id and self.state['root'] and
                self.state['founder']['mode'] == 'broker'):
            return None
        return dict(source='genesis', org_id=self.state['org_id'], broker_id=broker_id,
            sign_pub=founder['sign_pub'], kx_pub=founder['kx_pub'], scope='full',
            keeper=True, state='active', local_admin_approvals=False)

    def trigger_at(self, trigger_seq, head):
        try:
            wire.parse_head(head)
        except (ValueError, TypeError):
            return None
        if head != self.state['head'] or type(trigger_seq) is not int or not 1 <= trigger_seq <= head['seq']:
            return None
        return deepcopy(self.state['triggers'].get(str(trigger_seq)))

    def epoch_snapshot(self, head, projects, custody=None):
        """Project authority and immutable certificate history at this head.

        Epoch replay derives custody itself. The optional legacy custody argument
        is unused, avoiding a cycle between authority and epoch verification.
        """
        wire.parse_head(head)
        require(head == self.state['head'], 'Authority predecessor mismatch')
        brokers = []
        ids = {v['certificate']['broker_id'] for v in self.state['brokers']}
        founder = self.state['founding_broker']
        if founder:
            ids.add(founder['id'])
        for broker_id in sorted(ids):
            cert = self.broker_certificate_at(broker_id, head)
            if not cert:
                continue
            previous_scope = 'full' if founder and founder['id'] == broker_id else None
            keeper_since = 1 if previous_scope == 'full' else None
            changes = []
            versions = sorted((v for v in self.state['brokers']
                               if v['certificate']['broker_id'] == broker_id), key=lambda v: v['seq'])
            for version in versions:
                row = version['certificate']
                if previous_scope is not None and previous_scope != row['scope']:
                    changes.append(dict(seq=version['seq'], from_scope=deepcopy(previous_scope),
                                        to_scope=deepcopy(row['scope'])))
                previous_scope = row['scope']
                if row['state'] == 'active' and row['scope'] == 'full' and row['keeper']:
                    if keeper_since is None:
                        keeper_since = version['seq']
                else:
                    keeper_since = None
            brokers.append(dict(id=broker_id, kx_pub=crypto.unb64url(cert['kx_pub']).hex(),
                scope=deepcopy(cert['scope']), keeper=cert['keeper'],
                keeper_since_seq=keeper_since, full_custody_generation=None, scope_changes=changes))
        members = []
        for cert in self.active():
            if not cert['key_holder']:
                continue
            keeper_since = None
            for version in sorted((v for v in self.state['certificates']
                                   if v['certificate']['member_id'] == cert['member_id']), key=lambda v: v['seq']):
                row = version['certificate']
                if row['state'] == 'active' and row['key_holder'] and row['member_key_id'] == cert['member_key_id']:
                    if keeper_since is None:
                        keeper_since = version['seq']
                else:
                    keeper_since = None
            members.append(dict(id=cert['member_key_id'], member_id=cert['member_id'],
                workos_user_id=cert['workos_user_id'], kx_pub=crypto.unb64url(cert['kx_pub']).hex(), keeper_since_seq=keeper_since))
        recovery = self.state['recovery']
        return dict(head=deepcopy(head), members=members, brokers=brokers,
            recovery=dict(id='recovery', kx_pub=crypto.unb64url(recovery['kx_pub']).hex(), recovery_seq=self.state['recovery_seq']) if recovery else None,
            projects=deepcopy(projects), rekey_triggers=deepcopy(list(self.state['triggers'].values())),
            founder=dict(signer=deepcopy(self.founder['signer']), mode=self.founder['mode'],
                         init_after_seq=self.founder['init_predecessor_seq']))

    @property
    def founder(self):
        require(self.state['founder'] is not None, 'No verified founder')
        return deepcopy(self.state['founder'])


def empty_observations():
    return dict(heads=[], proposals={})


def observe_head(state, head, observed_at):
    wire.exact(head, ('seq', 'hash'))
    wire.integer(head['seq'])
    wire.digest(head['hash'])
    now = utc_millis(observed_at)
    result = deepcopy(state)
    for item in result['heads']:
        require(item['seq'] != head['seq'] or item['hash'] == head['hash'], 'Verified head fork')
        if item['seq'] == head['seq']:
            if utc_millis(item['observed_at']) < now:
                item['observed_at'] = observed_at
            return result
    result['heads'].append(dict(head, observed_at=observed_at))
    return result


def observe_proposal(state, digest, mode, now):
    wire.digest(digest)
    utc_millis(now)
    require(mode in ('live', 'history'), 'Invalid observation mode')
    result = deepcopy(state)
    result['proposals'].setdefault(digest, dict(mode=mode, **({'first_seen_at': now} if mode == 'live' else {})))
    return result


def check_late_admission(state, predecessor, ts, expires_at=None):
    signed = utc_millis(ts)
    expiry = utc_millis(expires_at) if expires_at is not None else float('inf')
    for item in state['heads']:
        if item['seq'] < predecessor['seq']:
            continue
        require(item['seq'] != predecessor['seq'] or item['hash'] == predecessor['hash'], 'Observed conflicting predecessor')
        observed = utc_millis(item['observed_at'])
        require(observed - signed <= EVIDENCE_MARGIN_MS and observed - expiry <= EVIDENCE_MARGIN_MS,
                'Verified late admission')


def check_hold(proposal_ts, received_at, observation, now):
    require(utc_millis(received_at) - utc_millis(proposal_ts) >= HOLD_MS, 'Logged hold too short')
    if not observation or observation['mode'] != 'live':
        return 'hold_not_locally_observed'
    require(utc_millis(now) - utc_millis(observation['first_seen_at']) >= HOLD_MS - EVIDENCE_MARGIN_MS,
            'Locally observed hold too short')
    return 'locally_observed'


def signature_still_eligible(state, proposal, member_id):
    if member_id not in proposal['eligible'] or member_id not in proposal['signature_keys'] or member_id not in proposal['signature_seqs']:
        return False
    key, seq = proposal['signature_keys'][member_id], proposal['signature_seqs'][member_id]
    if type(seq) is not int or not proposal['seq'] <= seq <= state['head']['seq']:
        return False
    versions = sorted((v for v in state['certificates'] if v['certificate']['member_id'] == member_id), key=lambda v: v['seq'])
    baseline = next((v['certificate'] for v in reversed(versions) if v['seq'] <= seq), None)
    if not baseline or baseline['state'] != 'active' or baseline['member_key_id'] != key or wire.rank(baseline['role']) < 2:
        return False
    has_role = member_id in proposal.get('signature_roles', {})
    has_rank = member_id in proposal.get('signature_ranks', {})
    if has_role != has_rank or (has_role and (proposal['signature_roles'][member_id] != baseline['role'] or proposal['signature_ranks'][member_id] != wire.rank(baseline['role']))):
        return False
    previous = wire.rank(baseline['role'])
    for version in versions:
        if version['seq'] <= seq:
            continue
        cert = version['certificate']
        current = wire.rank(cert['role'])
        if cert['state'] != 'active' or cert['member_key_id'] != key or current < previous:
            return False
        previous = current
    cert = AuthorityView(state).current(member_id)['certificate']
    return cert['state'] == 'active' and cert['member_key_id'] == key and wire.rank(cert['role']) >= 2


def _actor(entry, state):
    signer = entry['signer']
    require(signer['kind'] == 'member' and signer.get('id') and signer.get('key'), 'Member signer required')
    cert = AuthorityView(state).certificate_at(signer['key'], state['head']['seq'])
    require(cert and cert['state'] == 'active' and cert['member_id'] == signer['id'], 'Inactive member signer')
    return cert


def _identity(old, cert, state):
    require(cert['cert_no'] == (old['certificate']['cert_no'] if old else 0) + 1, 'Certificate identity or number changed')
    if old:
        require(all(old['certificate'][k] == cert[k] for k in ('member_id', 'workos_user_id')), 'Certificate identity or number changed')
    for version in state['certificates']:
        prior = version['certificate']
        if prior['member_id'] != cert['member_id']:
            require(not any(prior[k] == cert[k] for k in ('workos_user_id', 'member_key_id', 'sign_pub')) and
                not {p['credential_id'] for p in prior['passkeys']} & {p['credential_id'] for p in cert['passkeys']}, 'Certificate identity reused')
        if prior['member_key_id'] == cert['member_key_id']:
            require(all(prior[k] == cert[k] for k in ('sign_pub', 'kx_pub')), 'Key id rebound')


def _last_owner(old, cert, state):
    if old and old['certificate']['state'] == 'active' and old['certificate']['role'] == 'owner' and (cert['state'] != 'active' or cert['role'] != 'owner'):
        require(sum(c['role'] == 'owner' for c in AuthorityView(state).active()) > 1, 'Last owner cannot be removed or demoted')


def _self_lowering(old, cert):
    if cert['state'] == 'removed':
        excluded = ('state', 'cert_no')
        return {k:v for k,v in old.items() if k not in excluded} == {k:v for k,v in cert.items() if k not in excluded}
    excluded = ('role', 'reveal', 'cert_no', 'key_holder')
    return (not cert['key_holder'] or old['key_holder']) and {k:v for k,v in old.items() if k not in excluded} == {k:v for k,v in cert.items() if k not in excluded} and (cert['role'] == old['role'] or wire.rank(cert['role']) < wire.rank(old['role'])) and (not cert['reveal'] or old['reveal']) and (wire.rank(cert['role']) < wire.rank(old['role']) or (old['reveal'] and not cert['reveal']))


def _requested(value, org):
    require(isinstance(value, dict), 'Invalid requested object')
    if value.get('kind') == 'member':
        wire.exact(value, ('kind', 'certificate'))
        return dict(kind='member', certificate=wire.parse_certificate(value['certificate'], org))
    wire.exact(value, ('kind', 'recovery_kx_pub', 'recovery_sign_pub'))
    require(value['kind'] == 'recovery_rotation', 'Unknown requested kind')
    return dict(kind='recovery_rotation', recovery_kx_pub=wire.point(value['recovery_kx_pub']), recovery_sign_pub=wire.point(value['recovery_sign_pub']))


def _transition(requested, subject, state, signer, *, allow_revoke_key_edits=False):
    view = AuthorityView(state)
    old = view.current(subject) if requested['kind'] == 'member' else None
    if requested['kind'] == 'member':
        cert = requested['certificate']
        require(cert['member_id'] == subject, 'Subject mismatch')
        require(cert['state'] != 'removed' or (old and old['certificate']['state'] == 'active'), 'No active certificate to revoke')
        if old and not (allow_revoke_key_edits and cert['state'] == 'removed'):
            require(all(old['certificate'][k] == cert[k] for k in ('member_key_id', 'sign_pub', 'kx_pub', 'passkeys')),
                    'Typed passkey binding required')
        _identity(old, cert, state)
        _last_owner(old, cert, state)
        require(not (old and not old['certificate']['key_holder'] and cert['state'] == 'active' and cert['key_holder']),
                'Key holder promotion requires committed wrap support')
        if signer['member_id'] == subject and old and _self_lowering(old['certificate'], cert):
            return dict(eligible=[subject], required=1, hold=False, prior=old['seq'])
    else:
        require(subject == 'recovery' and state['recovery_ever_set'] and state['recovery'], 'Recovery rotation outside established state')
    eligible = sorted(c['member_id'] for c in view.active() if wire.rank(c['role']) >= 2 and c['member_id'] != subject)
    change_rank = max(wire.rank(old['certificate']['role']) if old else 0, wire.rank(requested['certificate']['role'])) if requested['kind'] == 'member' else 3
    require(signer['member_id'] in eligible and (signer['role'] == 'owner' if change_rank >= 2 else wire.rank(signer['role']) >= 2), 'Ineligible proposer')
    return dict(eligible=eligible, required=1 if change_rank == 1 else 2, hold=change_rank >= 2 and len(eligible) < 2, prior=old['seq'] if old else (0 if requested['kind'] == 'member' else state['recovery_seq']))


def _fresh_recovery(requested, state):
    points = [requested['recovery_kx_pub'], requested['recovery_sign_pub']]
    retired = set(state.get('used_recovery_points', []))
    protocol = state.get('recovery_protocol', {})
    retired.update(protocol.get('used_recovery_sign_keys', []))
    retired.update(protocol.get('used_recovery_exchange_keys', []))
    if state['recovery']:
        retired.update(state['recovery'].values())
    require(points[0] != points[1] and not retired.intersection(points), 'Recovery keys must be fresh')


def _apply(state, requested, seq):
    if requested['kind'] == 'member':
        cert = requested['certificate']
        old = AuthorityView(state).current(cert['member_id'])
        _last_owner(old, cert, state)
        _identity(old, cert, state)
        prior = old['certificate'] if old else None
        reason = None
        if prior and prior['key_holder']:
            if cert['state'] != 'active' or not cert['key_holder']:
                reason = 'key_holder_removed'
            elif any(prior[k] != cert[k] for k in ('member_key_id', 'sign_pub', 'kx_pub')):
                reason = 'key_holder_key_reset'
        if reason:
            state['triggers'][str(seq)] = dict(seq=seq, kind='full', reason=reason, projects=[])
        state['certificates'].append(dict(seq=seq, certificate=deepcopy(cert)))
    else:
        _fresh_recovery(requested, state)
        state.setdefault('used_recovery_points', []).extend(state['recovery'].values())
        state.update(recovery=dict(kx_pub=requested['recovery_kx_pub'], sign_pub=requested['recovery_sign_pub']), recovery_seq=seq, recovery_ever_set=True)
        state['triggers'][str(seq)] = dict(seq=seq, kind='full', reason='recovery_rotated', projects=[])


def _proposal(entry, state):
    value = state['proposals'].get(wire.text(entry['body']['proposal_hash']))
    require(value is not None, 'Unknown proposal')
    require(not value['cancelled'] and not value['activated'], 'Settled proposal')
    old = AuthorityView(state).current(value['subject']) if value['requested']['kind'] == 'member' else None
    prior = (old['seq'] if old else 0) if value['requested']['kind'] == 'member' else state['recovery_seq']
    require(prior == value['prior_cert_seq'], 'Subject certificate changed')
    return value


def verified_broker_custody(port, prior, state):
    require(callable(port), 'Verified broker custody unavailable')
    evidence = port(prior['broker_id'], deepcopy(state['head']))
    require(isinstance(evidence, dict) and evidence.get('verified') is True and evidence.get('head') == state['head'], 'Broker custody predecessor mismatch')
    for name in ('pending_downgrades', 'covered_triggers'):
        items = evidence[name]
        require(isinstance(items, list) and all(type(s) is int and 1 <= s <= state['head']['seq'] and str(s) in state['triggers'] for s in items) and items == sorted(set(items)), 'Unverified broker custody trigger')
    pending = []
    projects = set() if prior['scope'] == 'full' else set(prior['scope'])
    for version in state['brokers']:
        if version['certificate']['broker_id'] != prior['broker_id']:
            continue
        trigger = state['triggers'].get(str(version['seq']))
        if not trigger or version['seq'] in evidence['covered_triggers']:
            continue
        if trigger['kind'] == 'full' and trigger['reason'] == 'full_to_scoped_downgrade':
            pending.append(version['seq'])
        if trigger['kind'] == 'projects':
            projects.update(trigger['projects'])
    require(evidence['pending_downgrades'] == pending, 'Broker custody downgrade coverage mismatch')
    require(evidence['custody'] == ('full' if prior['scope'] == 'full' or pending else sorted(projects)), 'Broker custody coverage mismatch')
    return deepcopy(evidence)


def _genesis(entry, state):
    body = wire.exact(entry['body'], ('org_id', 'founder', 'recovery_kx_pub', 'recovery_sign_pub', 'default_rules', 'max_policy_age'))
    require(entry['seq'] == 1 and state['root'] is None and body['org_id'] == entry['org_id'], 'Invalid genesis')
    require(body['default_rules'] == {} and 300 <= wire.integer(body['max_policy_age']) <= 86400, 'Invalid genesis rules')
    founder = body['founder']
    if founder.get('kind') == 'member':
        wire.exact(founder, ('kind', 'id', 'key', 'sign_pub', 'kx_pub', 'certificate_sha256'))
        wire.text(founder['id']); wire.text(founder['key']); wire.digest(founder['certificate_sha256'])
        require(entry['signer'] == dict(kind='member', id=founder['id'], key=founder['key']), 'Invalid founder')
        state['founder_pending'] = {k: deepcopy(v) for k,v in founder.items() if k != 'kind'}
        state.update(recovery=dict(kx_pub=wire.point(body['recovery_kx_pub']), sign_pub=wire.point(body['recovery_sign_pub'])), recovery_ever_set=True, recovery_seq=1)
        state['founder'] = dict(mode='browser', signer=deepcopy(entry['signer']), init_predecessor_seq=2)
    else:
        wire.exact(founder, ('kind', 'id', 'sign_pub', 'kx_pub'))
        wire.text(founder['id'])
        require(founder['kind'] == 'broker' and entry['signer'] == dict(kind='broker', id=founder['id']) and body['recovery_kx_pub'] is None and body['recovery_sign_pub'] is None, 'Invalid broker founder')
        state['founding_broker'] = {k:deepcopy(v) for k,v in founder.items() if k != 'kind'}
        state['founder'] = dict(mode='broker', signer=deepcopy(entry['signer']), init_predecessor_seq=1)
    wire.point(founder['sign_pub']); wire.point(founder['kx_pub'])
    state['root'] = wire.hash_object(entry)


def _bootstrap(entry, state):
    founder = state['founder_pending']
    require(founder and entry['kind'] == 'member_cert' and entry['seq'] == 2 and state['head']['seq'] == 1, 'Founder bootstrap certificate required')
    wire.exact(entry['body'], ('requested', *PROOF), ('initial_slot_sha256',))
    requested = _requested(entry['body']['requested'], state['org_id'])
    require(requested['kind'] == 'member', 'Founder certificate required')
    cert = requested['certificate']
    require(cert['role'] == 'owner' and cert['state'] == 'active' and cert['cert_no'] == 1 and cert['member_id'] == founder['id'] and cert['member_key_id'] == founder['key'] and cert['sign_pub'] == founder['sign_pub'] and cert['kx_pub'] == founder['kx_pub'] and wire.hash_object(cert) == founder['certificate_sha256'] and entry['signer'] == dict(kind='member', id=founder['id'], key=founder['key']), 'Founder certificate commitment mismatch')
    return cert


def _port(runtime, name, *args):
    import inspect

    port = runtime.get(name)
    require(callable(port), name + ' verifier unavailable')
    result = port(*deepcopy(args))
    if inspect.isawaitable(result):
        if inspect.iscoroutine(result):
            result.close()
        raise ValueError(name + ' requires a synchronous offline verifier')
    require(result is None, name + ' must return successfully or raise')


def _broker(entry, state, signer, runtime):
    wire.exact(entry['body'], ('requested', *PROOF))
    require(wire.rank(signer['role']) >= 2, 'Admin broker certifier required')
    cert = wire.parse_broker_certificate(entry['body']['requested'], state['org_id'], runtime.get('project_exists'))
    prior = next((v['certificate'] for v in reversed(state['brokers']) if v['certificate']['broker_id'] == cert['broker_id']), None)
    founding = state['founding_broker']
    if not prior and founding and founding['id'] == cert['broker_id']:
        require(entry['kind'] == 'broker_cert' and cert['state'] == 'active' and cert['cert_no'] == 1, 'Founding broker certificate bootstrap unavailable')
        _port(runtime, 'verify_founding_broker_enrollment', entry, cert, state)
    require(cert['cert_no'] == (prior['cert_no'] if prior else 0) + 1 and (not prior or all(cert[k] == prior[k] for k in ('sign_pub', 'kx_pub', 'transcript_digest'))), 'Broker identity changed')
    require((entry['kind'] == 'broker_revoke') == (cert['state'] == 'revoked') and not (cert['local_admin_approvals'] and not (prior and prior['local_admin_approvals']) and signer['role'] != 'owner'), 'Broker authorization invalid')
    require(not prior or prior['state'] != 'revoked', 'Revoked broker cannot be recertified')
    custody = verified_broker_custody(runtime.get('effective_custody'), prior, state) if prior else None
    if prior and prior['scope'] == 'full' and cert['state'] == 'active' and cert['scope'] != 'full':
        require(type(custody.get('generation')) is int and custody['generation'] >= 1 and custody.get('full_custody_generation') == custody['generation'], 'Verified current full custody generation required for downgrade')
    if custody and custody['pending_downgrades'] and cert['state'] == 'active':
        require(cert['scope'] != 'full' and not (prior['scope'] != 'full' and any(p not in prior['scope'] for p in cert['scope'])), 'Pending downgrade cannot widen scope')
    if entry['kind'] == 'broker_cert':
        _port(runtime, 'verify_broker_bindings', entry, cert, state)
    else:
        require(prior and dict(prior, cert_no=cert['cert_no'], state='revoked') == cert, 'Revoke changes broker fields')
    state['used_challenges'].append(wire.verify_authorization(entry, signer, dict(broker_id=cert['broker_id']), state['used_challenges'], runtime))
    state['brokers'].append(dict(seq=entry['seq'], certificate=cert))
    narrowed = prior and cert['scope'] != 'full' and (prior['scope'] == 'full' or any(p not in cert['scope'] for p in prior['scope']))
    if prior and (cert['state'] == 'revoked' or narrowed):
        full = custody['custody'] == 'full'
        revoked = cert['state'] == 'revoked'
        state['triggers'][str(entry['seq'])] = dict(seq=entry['seq'], kind='full' if full else 'projects', reason=('full_broker_revoked' if revoked else 'full_to_scoped_downgrade') if full else ('scoped_broker_revoked' if revoked else 'scoped_broker_narrowed'), projects=[] if full else custody['custody'] if revoked else [p for p in prior['scope'] if p not in cert['scope']])


def authority_hooks(runtime, *, recovery_parity=False):
    """Build mandatory hooks for PolicyVerifier; runtime contains trusted ports.

    No recovery-claim, timer or production admission path is enabled here.
    """
    def advance(state, entry):
        state['head'] = dict(seq=entry['seq'], hash=wire.hash_object(entry))
        return state

    def resolve_key(entry, state):
        if entry['kind'] == 'genesis':
            candidate = deepcopy(state)
            _genesis(entry, candidate)
            cert = candidate['founding_broker'] or candidate['founder_pending']
        elif state['founder_pending']:
            cert = _bootstrap(entry, state)
        else:
            cert = _actor(entry, state)
        return crypto.unb64url(cert['sign_pub'])

    def authorize(entry, state):
        require(entry['kind'] in AUTHORITY_KINDS and entry['kind'] != 'cert_activate', 'Unsupported authority entry')
        if runtime.get('submission'):
            require(abs(utc_millis(entry['ts']) - utc_millis(runtime['now'])) <= 300000, 'Live submission outside timestamp bound')
        if runtime.get('mode') == 'live':
            check_late_admission(runtime.get('observations', empty_observations()), dict(seq=entry['seq'] - 1, hash=entry['prev_hash']), entry['ts'], entry['body'].get('authz', {}).get('expires_at'))
        if entry['kind'] == 'genesis':
            _genesis(entry, state)
            return advance(state, entry)
        if state['founder_pending']:
            cert = _bootstrap(entry, state)
            if 'initial_slot_sha256' in entry['body']:
                _port(runtime, 'verify_bootstrap_slot', entry, cert, state)
            state['used_challenges'].append(wire.verify_authorization(entry, cert, dict(member_id=cert['member_id']), state['used_challenges'], runtime))
            state['certificates'].append(dict(seq=2, certificate=cert))
            state['founder_pending'] = None
            return advance(state, entry)
        signer = _actor(entry, state)
        kind, body = entry['kind'], entry['body']
        if kind in ('broker_cert', 'broker_revoke'):
            _broker(entry, state, signer, runtime)
        elif kind in ('member_cert', 'member_revoke'):
            wire.exact(body, ('requested', *PROOF), ('wrap',) if kind == 'member_cert' else ())
            requested = _requested(body['requested'], state['org_id'])
            require(requested['kind'] == 'member' and (kind == 'member_revoke') == (requested['certificate']['state'] == 'removed'), 'Wrong certificate entry kind')
            cert = requested['certificate']
            if 'wrap' in body:
                require(cert['key_holder'], 'Nonholder confirmation wrap forbidden')
                wire.exact(body['wrap'], ('omk_generation', 'wrap_digest'))
                wire.integer(body['wrap']['omk_generation'], 1); wire.digest(body['wrap']['wrap_digest'])
                _port(runtime, 'verify_member_confirmation_wrap', entry, cert, state)
            elif runtime.get('verify_member_confirmation_wrap'):
                _port(runtime, 'verify_member_confirmation_wrap', entry, cert, state)
            rule = _transition(requested, cert['member_id'], state, signer, allow_revoke_key_edits=recovery_parity and kind == 'member_revoke')
            require(rule['required'] == 1 and not rule['hold'], 'Logged proposal required')
            state['used_challenges'].append(wire.verify_authorization(entry, signer, dict(member_id=cert['member_id']), state['used_challenges'], runtime))
            _apply(state, requested, entry['seq'])
        elif kind in ('cert_proposal', 'recovery_rotate'):
            wire.exact(body, ('subject', 'prior_cert_seq', 'requested', 'reason', *PROOF))
            requested, subject = _requested(body['requested'], state['org_id']), wire.text(body['subject'])
            require((requested['kind'] == 'recovery_rotation') == (kind == 'recovery_rotate'), 'Wrong proposal kind')
            if requested['kind'] == 'recovery_rotation':
                _fresh_recovery(requested, state)
            rule = _transition(requested, subject, state, signer)
            require(wire.integer(body['prior_cert_seq']) == rule['prior'] and not (rule['required'] == 1 and not rule['hold']), 'Invalid proposal predecessor or threshold')
            target = dict(member_id=subject) if requested['kind'] == 'member' else dict(recovery=True)
            state['used_challenges'].append(wire.verify_authorization(entry, signer, target, state['used_challenges'], runtime))
            digest, member = wire.hash_object(entry), signer['member_id']
            state['proposals'][digest] = dict(hash=digest, seq=entry['seq'], ts=entry['ts'], subject=subject, prior_cert_seq=rule['prior'], requested=requested, reason=wire.text(body['reason']), eligible=rule['eligible'], proposer=member, endorsements=[member], signature_keys={member:signer['member_key_id']}, signature_seqs={member:entry['seq']}, signature_roles={member:signer['role']}, signature_ranks={member:wire.rank(signer['role'])}, cancelled=False, activated=False, required=rule['required'], hold=rule['hold'])
        else:
            wire.exact(body, ('proposal_hash', *PROOF))
            proposal = _proposal(entry, state)
            require(signer['member_id'] in proposal['eligible'] and wire.rank(signer['role']) >= 2, 'Ineligible proposal signer')
            state['used_challenges'].append(wire.verify_authorization(entry, signer, dict(proposal_hash=proposal['hash']), state['used_challenges'], runtime))
            if kind == 'cert_endorse':
                member = signer['member_id']
                require(member not in proposal['endorsements'], 'Duplicate endorsement')
                proposal['endorsements'].append(member)
                for field, value in (('signature_keys', signer['member_key_id']), ('signature_seqs', entry['seq']), ('signature_roles', signer['role']), ('signature_ranks', wire.rank(signer['role']))):
                    proposal.setdefault(field, {})[member] = value
            elif kind == 'cert_cancel':
                proposal['cancelled'] = True
            else:
                raise ValueError('Unsupported proposal operation')
        return advance(state, entry)

    def derive(entry, state, received_at):
        require(entry['kind'] == 'cert_activate' and entry['signer'] == dict(kind='derived') and not state['founder_pending'], 'Unsupported derived authority entry')
        wire.exact(entry['body'], ('proposal_hash',))
        proposal = _proposal(entry, state)
        counted = {m for m in proposal['endorsements'] if signature_still_eligible(state, proposal, m)}
        current = AuthorityView(state).current(proposal['proposer'])
        require(proposal['proposer'] in counted and (proposal['required'] != 2 or current['certificate']['role'] == 'owner'), 'Proposer no longer certified')
        if proposal['hold']:
            observations = runtime.get('observations', empty_observations())
            status = check_hold(proposal['ts'], received_at, observations['proposals'].get(proposal['hash']), runtime['now'])
            if runtime.get('audit_hold'):
                runtime['audit_hold'](proposal['hash'], status)
        else:
            require(len(counted) >= proposal['required'], 'Endorsement threshold unmet')
        _apply(state, proposal['requested'], entry['seq'])
        proposal['activated'] = True
        proposal['activation_seq'] = entry['seq']
        proposal['activation_hash'] = wire.hash_object(entry)
        proposal['activation_received_at'] = received_at
        return advance(state, entry)

    return PolicyHooks(resolve_key=resolve_key, authorize=authorize, derive=derive)


class AuthorityEvidence:
    """Immutable offline enrollment and initial-slot proof material.

    Rows and blobs are independent retained provenance, never authority grants.
    History permits collected ciphertext at an intermediate prefix, but finalize
    requires every initial slot because this surface implements no B6 deletion.
    """
    def __init__(self, rows=None, blobs=None, *, mode='history'):
        require(mode == 'history', 'Offline authority evidence requires history mode')
        self._rows = self._tables(rows or {})
        self._blobs = self._tables(blobs or {})
        self._initial = []
        self._confirmed_wraps = []

    @property
    def initial_references(self):
        return deepcopy(self._initial)

    @property
    def confirmed_wraps(self):
        return deepcopy(self._confirmed_wraps)

    def verify_certificate_additions(self, entry, before, after):
        if entry['kind'] == 'member_cert':
            return
        prior = AuthorityView(before)
        for version in after['certificates'][len(before['certificates']):]:
            cert = version['certificate']
            pending = any(row.get('member_key_id') == cert['member_key_id']
                          for row in self._rows.get('genesis_acceptances', ()))
            require(not (cert['state'] == 'active' and pending and prior.current(cert['member_id']) is None),
                    'Pending invite requires direct confirmation')

    @staticmethod
    def _tables(value):
        require(isinstance(value, dict) and all(isinstance(k, str) and isinstance(v, (list, tuple)) and all(isinstance(r, dict) for r in v) for k, v in value.items()), 'Invalid evidence tables')
        return deepcopy(value)

    def _one(self, table, predicate, *, blobs=False):
        items = [row for row in (self._blobs if blobs else self._rows).get(table, ()) if predicate(row)]
        require(len(items) <= 1, 'Ambiguous retained evidence')
        return deepcopy(items[0]) if items else None

    @staticmethod
    def _json(value):
        import json
        require(isinstance(value, str), 'Retained JSON string required')
        result = json.loads(value)
        require(isinstance(result, dict), 'Retained JSON object required')
        return result

    @staticmethod
    def _slot(row, certificate):
        import json
        if 'params_json' in row:
            slot = dict(slot_id=row['slot_id'], member_key_id=row['member_key_id'], kind=row['kind'],
                params=json.loads(row['params_json']), wrapped_priv=row['wrapped_priv'], nonce=row['nonce'], label=row['label'])
        else:
            slot = {k: row[k] for k in ('slot_id', 'member_key_id', 'kind', 'params', 'wrapped_priv', 'nonce', 'label')}
        for key in ('wrapped_priv', 'nonce'):
            if isinstance(slot[key], bytes):
                slot[key] = crypto.b64url(slot[key])
        slot = wire.parse_slot(slot)
        require(slot['member_key_id'] == certificate['member_key_id'], 'Slot member key differs')
        if slot['kind'] == 'webauthn_prf':
            require(any(key['credential_id'] == slot['params']['credential_id'] for key in certificate['passkeys']), 'Unbound slot passkey')
        else:
            require(not certificate['key_holder'], 'Key holder requires a PRF slot')
        return slot

    def _matching_slot(self, certificate, digest, kind, metadata=None):
        for row in self._blobs.get('member_slots', ()):
            if row.get('member_key_id') != certificate['member_key_id']:
                continue
            try:
                slot = self._slot(row, certificate)
                if metadata is not None and wire.slot_metadata(slot) != metadata:
                    continue
                if wire.SlotCommitment(kind, digest).matches(slot):
                    return slot
            except (KeyError, TypeError, ValueError, crypto.CryptoError):
                continue
        return None

    def verify_bootstrap_slot(self, entry, certificate, state):
        commitment = entry['body'].get('initial_slot_sha256')
        rows = [r for r in self._blobs.get('member_slots', ()) if r.get('member_key_id') == certificate['member_key_id']]
        if not rows and commitment is None:
            return
        require(entry['kind'] == 'member_cert' and entry['seq'] == 2, 'Committed founder slot required')
        wire.digest(commitment)
        self._matching_slot(certificate, commitment, 'initial_slot')
        self._initial.append((deepcopy(certificate), commitment, 'initial_slot', None))

    @staticmethod
    def _hex(value, length):
        import re
        if isinstance(value, bytes):
            value = value.hex()
        require(isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(length * 2) + '}', value), 'Invalid retained ciphertext bytes')
        return bytes.fromhex(value)

    def _wrap_digest(self, row, field):
        eph = self._hex(row['eph_pub'], 65)
        wire.point(crypto.b64url(eph))
        nonce, wrapped = self._hex(row['nonce'], 12), self._hex(row[field], 48)
        actual = crypto.wrap_digest(eph, nonce, wrapped)
        require(actual == self._hex(row['wrap_digest'], 32).hex(), 'Retained wrap digest differs')
        return actual

    def verify_member_confirmation_wrap(self, entry, certificate, state, committed_generation):
        prior = AuthorityView(state).current(certificate['member_id'])
        require(not prior or prior['certificate']['key_holder'] or not certificate['key_holder'] or certificate['state'] != 'active', 'Key holder promotion requires committed wrap support')
        pending = self._one('genesis_acceptances', lambda r: r.get('member_id') == certificate['member_id'])
        if not pending or prior:
            require('wrap' not in entry['body'], 'Unknown or already certified confirmation')
            return
        accepted = wire.verify_member_accept(dict(self._json(pending['transcript_json']), proof=pending['proof']), state['org_id'])
        require(entry['kind'] == 'member_cert' and accepted['member_key'] == certificate, 'Confirmation differs from accepted keys')
        slot = deepcopy(accepted['slot'])
        digest = slot.pop('commitment_sha256')
        require(self._one('member_slots', lambda r: r.get('slot_id') == slot['slot_id']) is None, 'Slot id already belongs to a committed key')
        self._matching_slot(certificate, digest, 'slot_blob', slot)
        self._initial.append((deepcopy(certificate), digest, 'slot_blob', slot))
        if not certificate['key_holder']:
            require('wrap' not in entry['body'], 'Nonholder has no OMK wrap')
            return
        commitment = wire.exact(entry['body'].get('wrap'), ('omk_generation', 'wrap_digest'))
        generation = committed_generation(deepcopy(state['head']))
        require(isinstance(generation, dict) and generation.get('kind') == 'committed', 'No committed generation')
        wire.integer(generation['generation'], 1)
        wire.integer(commitment['omk_generation'], 1)
        wire.digest(commitment['wrap_digest'])
        require(commitment['omk_generation'] == generation['generation'], 'Wrap generation differs')
        row = self._one('org_key_wraps', lambda r: r.get('recipient_kind') == 'member_key' and r.get('recipient_id') == certificate['member_key_id'] and r.get('omk_generation') == generation['generation'], blobs=True)
        require(row is not None, 'Missing confirmed wrap')
        require(self._wrap_digest(row, 'wrapped_omk') == commitment['wrap_digest'], 'Wrap digest differs')
        self._confirmed_wraps.append(dict(recipient_kind='member_key', recipient_id=certificate['member_key_id'],
            omk_generation=generation['generation'], eph_pub=self._hex(row['eph_pub'], 65).hex(),
            nonce=self._hex(row['nonce'], 12).hex(), wrapped_omk=self._hex(row['wrapped_omk'], 48).hex(),
            wrap_digest=commitment['wrap_digest']))

    @staticmethod
    def _transcript(value):
        import re
        row = wire.exact(value, ('name', 'version', 'mode', 'sign_pub', 'kx_pub'), ('store_id',) if value.get('mode') == 'adopt' else ())
        for field, limit in (('name', 128), ('version', 64)):
            text = wire.text(row[field])
            require(len(text.encode('utf-16-le')) // 2 <= limit and not re.search(r'[\x00-\x1f\x7f]', text), 'Invalid enrollment text')
        require(row['mode'] in ('join', 'adopt'), 'Unknown enrollment mode')
        if row['mode'] == 'adopt':
            wire.org_id(row.get('store_id'))
        wire.point(row['sign_pub']); wire.point(row['kx_pub'])
        return deepcopy(row)

    def verify_enrollment_identity(self, certificate, state):
        row = self._one('enrollment_records', lambda r: r.get('broker_id') == certificate['broker_id'])
        require(row is not None, 'Enrollment record missing')
        transcript = self._transcript(self._json(row['transcript_json']))
        digest = wire.hash_object(transcript)
        proof = wire.binary(row['proof'], 64)
        require(crypto.p256_verify(crypto.unb64url(transcript['sign_pub']), crypto.enrollment_context(state['org_id'], wire.text(row['ticket_id']), digest), proof), 'Enrollment possession proof invalid')
        if transcript['mode'] == 'adopt':
            adopted = self._one('enrollment_adoption_proofs', lambda r: r.get('broker_id') == certificate['broker_id'])
            require(adopted is not None and adopted.get('candidate_root') == state['root'], 'Adoption root differs')
            digest_root = wire.hash_object(dict(purpose='adopt_root', transcript=transcript, candidate_root=state['root']))
            require(crypto.p256_verify(crypto.unb64url(transcript['sign_pub']), crypto.enrollment_context(state['org_id'], row['ticket_id'], digest_root), wire.binary(adopted['proof'], 64)), 'Adoption root proof invalid')
        require(row['transcript_digest'] == digest == certificate['transcript_digest'] and all(certificate[k] == transcript[k] for k in ('name', 'sign_pub', 'kx_pub')), 'Enrollment certificate identity differs')

    def verify_broker_bindings(self, entry, certificate, state):
        require(entry['org_id'] == state['org_id'] and entry['seq'] == state['head']['seq'] + 1 and entry['prev_hash'] == state['head']['hash'], 'Enrollment predecessor differs')
        self.verify_enrollment_identity(certificate, state)
        ids = [wrap['id'] for wrap in certificate['wrap_digests']]
        require(len(ids) == len(set(ids)), 'Duplicate enrollment wrap ids')
        for wrap in certificate['wrap_digests']:
            archived = self._one('enrollment_wrap_digests', lambda r: r.get('blob_id') == wrap['id'])
            require(archived and archived.get('broker_id') == certificate['broker_id'] and archived.get('cert_seq') == entry['seq'] and archived.get('wrap_digest') == wrap['digest'], 'Enrollment wrap archive differs')
            surviving = [r for table in ('org_key_wraps', 'broker_key_wraps') for r in self._blobs.get(table, ()) if r.get('wrap_id') == wrap['id']]
            require(len(surviving) <= 1, 'Ambiguous enrollment wrap blob')
            if surviving:
                row = surviving[0]
                require(self._wrap_digest(row, 'wrapped_omk' if 'wrapped_omk' in row else 'wrapped_key') == wrap['digest'], 'Enrollment wrap bytes differ')

    def verify_founding_broker_enrollment(self, entry, certificate, state):
        founder = state['founding_broker']
        require(founder and state['founder']['mode'] == 'broker' and state['root'] and certificate['broker_id'] == founder['id'] and all(certificate[k] == founder[k] for k in ('sign_pub', 'kx_pub')) and certificate['cert_no'] == 1 and certificate['state'] == 'active' and certificate['scope'] == 'full' and certificate['keeper'] and entry['kind'] == 'broker_cert', 'Founding broker enrollment differs')
        self.verify_broker_bindings(entry, certificate, state)

    def runtime(self, *, committed_generation):
        require(callable(committed_generation), 'Exact-head committed generation provider required')
        return dict(verify_bootstrap_slot=self.verify_bootstrap_slot,
            verify_member_confirmation_wrap=lambda e, c, s: self.verify_member_confirmation_wrap(e, c, s, committed_generation),
            verify_broker_bindings=self.verify_broker_bindings,
            verify_founding_broker_enrollment=self.verify_founding_broker_enrollment)

    def finalize(self, state):
        self.finalize_references(self._initial)

    def finalize_references(self, references):
        for certificate, digest, kind, metadata in references:
            require(self._matching_slot(certificate, digest, kind, metadata) is not None,
                    'Missing committed initial slot without verified deletion')
