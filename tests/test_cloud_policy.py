"""Authority semantics and verifier-local evidence, independent of cloud rows."""
import copy
import unittest
from unittest.mock import patch

from tw import cloud_policy as policy, cloud_wire as wire, crypto
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from tw.policy_log import PolicyVerifier, policy_record, PolicyError
from tw.policy_log import ZERO_HASH

ORG = 'a' * 32
NOW = '2026-01-01T00:00:00Z'
LATER = '2026-01-02T00:00:00Z'


def cloud_authority_projection(state):
    """Exact TS authority state, excluding explicitly local replay evidence.

    Retain every protocol field, including fields unknown to this helper, so an
    unexpected implementation field cannot silently disappear from comparisons.
    """
    result = copy.deepcopy(state)
    result.pop('used_recovery_points', None)
    for proposal in result['proposals'].values():
        for field in ('activation_seq', 'activation_hash', 'activation_received_at'):
            proposal.pop(field, None)
    return result


def cloud_authority_digest(state):
    return wire.hash_object(cloud_authority_projection(state))


def cloud_snapshot_projection(snapshot, epoch_state):
    """Translate the internal scope representation to the exported TS snapshot.

    This is comparison-only code. It does not validate or accept remote policy,
    provenance, reference-only fixture hooks, or supplied authority snapshots.
    """
    if snapshot is None:
        return None
    result = copy.deepcopy(snapshot)
    result['projects'].sort()
    result['rekey_triggers'].sort(key=lambda trigger: trigger['seq'])
    for broker in result['brokers']:
        if broker['scope'] == 'full':
            broker['scope'] = ['*']
        pending = set()
        for change in broker['scope_changes']:
            if change['seq'] > result['head']['seq'] or change['from_scope'] == 'full' or change['to_scope'] == 'full':
                continue
            for project in set(change['from_scope']) - set(change['to_scope']):
                covered = any(epoch['commit_seq'] > change['seq'] and epoch['commit_seq'] <= result['head']['seq']
                    and project in epoch['projects'] and change['seq'] in epoch['covered_triggers']
                    and (epoch['kind'] == 'full' or epoch.get('trigger_seq') == change['seq'])
                    for epoch in epoch_state['epochs'])
                if not covered:
                    pending.add(project)
        broker['pending_removed_projects'] = sorted(pending)
    return result


class AuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from cloud_fixtures import fixture
        cls.fixture = fixture('control/vectors/authority-v1.json')['founder_vectors'][0]

    def setUp(self):
        self.cert = copy.deepcopy(self.fixture['certificate'])
        self.state = policy.empty_authority(ORG)
        self.state['head'] = dict(seq=2, hash='1' * 64)
        self.state['certificates'] = [dict(seq=2, certificate=self.cert)]
        self.runtime = dict(mode='history', now=LATER, observations=policy.empty_observations())
        self.hooks = policy.authority_hooks(self.runtime)

    def entry(self, kind, body, seq=3, derived=False):
        return dict(v=2, org_id=ORG, seq=seq, prev_hash=self.state['head']['hash'], ts=NOW,
                    kind=kind, body=body, signer=dict(kind='derived') if derived else
                    dict(kind='member', id=self.cert['member_id'], key=self.cert['member_key_id']))

    def cert_for(self, role='admin'):
        cert = copy.deepcopy(self.cert)
        cert.update(member_id='other', member_key_id='other-key', workos_user_id='other-user', role=role)
        # Identity uniqueness also binds public signing keys and credentials.
        cert['sign_pub'] = wire.point('BGsX0fLhLEJH-Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU')
        cert['passkeys'] = [] if role == 'member' else copy.deepcopy(cert['passkeys'])
        if cert['passkeys']:
            cert['passkeys'][0]['credential_id'] = 'YW5vdGhlcg'
        cert['key_holder'] = role in ('owner', 'admin')
        return cert

    def proposal(self):
        requested = dict(kind='member', certificate=self.cert_for())
        entry = self.entry('cert_proposal', dict(subject='other', prior_cert_seq=0,
            requested=requested, reason='grant admin', request_id='request', authz={}, assertion={}))
        with patch.object(wire, 'verify_authorization', return_value='challenge'):
            self.hooks.authorize(entry, self.state)
        return wire.hash_object(entry)

    def test_comparison_projection_retains_all_protocol_fields(self):
        state = copy.deepcopy(self.state)
        state['unexpected_protocol_field'] = {'keep': True}
        state['used_recovery_points'] = ['local']
        state['proposals']['p'] = dict(activated=True, activation_seq=3,
            activation_hash='2'*64, activation_received_at=LATER, signature_ranks={'owner': 3})
        projected = cloud_authority_projection(state)
        self.assertNotIn('used_recovery_points', projected)
        self.assertEqual(projected['proposals']['p'], dict(activated=True, signature_ranks={'owner': 3}))
        self.assertEqual(projected['unexpected_protocol_field'], {'keep': True})
        self.assertIn('activation_seq', state['proposals']['p'])

    def test_snapshot_comparison_translates_scope_and_tracks_project_rekey(self):
        snapshot = dict(head=dict(seq=8, hash='1'*64), members=[], recovery=None,
            projects=['b', 'a'], rekey_triggers=[], brokers=[dict(id='b', scope=['a'],
                scope_changes=[dict(seq=5, from_scope=['a', 'b'], to_scope=['a'])])])
        projected = cloud_snapshot_projection(snapshot, dict(epochs=[]))
        self.assertEqual(projected['brokers'][0]['pending_removed_projects'], ['b'])
        epoch = dict(seq=6, commit_seq=7, projects=['b'], covered_triggers=[5], kind='projects', trigger_seq=5)
        projected = cloud_snapshot_projection(snapshot, dict(epochs=[epoch]))
        self.assertEqual(projected['brokers'][0]['pending_removed_projects'], [])
        snapshot['brokers'][0]['scope'] = 'full'
        self.assertEqual(cloud_snapshot_projection(snapshot, dict(epochs=[]))['brokers'][0]['scope'], ['*'])
        self.assertNotIn('pending_removed_projects', snapshot['brokers'][0])

    def test_exact_head_views_and_snapshot_copies(self):
        view = policy.AuthorityView(self.state)
        self.assertTrue(view.is_certified(self.cert['member_key_id'], 3, self.state['head']))
        self.assertFalse(view.is_certified(self.cert['member_key_id'], 3, dict(seq=2, hash='2'*64)))
        copy_cert = view.current(self.cert['member_id'])
        copy_cert['certificate']['role'] = 'member'
        self.assertEqual(view.active()[0]['role'], 'owner')

    def test_proposal_hold_requires_logged_activation_and_full_day(self):
        digest = self.proposal()
        self.assertEqual(len(self.state['certificates']), 1)
        proposal = self.state['proposals'][digest]
        self.assertEqual(proposal['eligible'], [self.cert['member_id']])
        self.assertEqual(proposal['signature_ranks'][self.cert['member_id']], 3)
        activation = self.entry('cert_activate', dict(proposal_hash=digest), seq=4, derived=True)
        with self.assertRaises(ValueError):
            self.hooks.derive(activation, copy.deepcopy(self.state), '2026-01-01T23:59:59Z')
        state = self.hooks.derive(activation, self.state, LATER)
        self.assertTrue(state['proposals'][digest]['activated'])
        self.assertEqual(policy.AuthorityView(state).current('other')['certificate']['role'], 'admin')

    def test_rank_one_direct_certification_and_identity_rebinding(self):
        cert = self.cert_for('member')
        entry = self.entry('member_cert', dict(requested=dict(kind='member', certificate=cert),
            request_id='direct', authz={}, assertion={}))
        with patch.object(wire, 'verify_authorization', return_value='direct-challenge'):
            self.hooks.authorize(entry, self.state)
        self.assertEqual(policy.AuthorityView(self.state).current('other')['seq'], 3)
        changed = dict(cert, cert_no=2, sign_pub=self.cert['sign_pub'])
        with self.assertRaises(ValueError):
            policy._identity(policy.AuthorityView(self.state).current('other'), changed, self.state)

    def test_two_person_threshold_and_subject_exclusion(self):
        admin = self.cert_for()
        self.state['certificates'].append(dict(seq=2, certificate=admin))
        candidate = self.cert_for()
        candidate.update(member_id='third', workos_user_id='third-user', member_key_id='third-key')
        # Transition tests do not parse cryptographic fields.
        candidate['sign_pub'] = 'new-point'
        candidate['passkeys'] = []
        rule = policy._transition(dict(kind='member', certificate=candidate), 'third', self.state, self.cert)
        self.assertEqual(rule['eligible'], sorted([self.cert['member_id'], 'other']))
        self.assertEqual(rule['required'], 2)
        self.assertFalse(rule['hold'])
        with self.assertRaisesRegex(ValueError, 'Ineligible proposer'):
            policy._transition(dict(kind='member', certificate=candidate), 'third', self.state, admin)

    def test_subject_certificate_changes_invalidate_pending_proposal(self):
        digest = self.proposal()
        self.state['certificates'].append(dict(seq=4, certificate=self.cert_for()))
        with self.assertRaisesRegex(ValueError, 'Subject certificate changed'):
            self.hooks.derive(self.entry('cert_activate', dict(proposal_hash=digest), seq=5, derived=True), self.state, LATER)

    def test_successful_broker_certificate_still_requires_exact_custody_on_update(self):
        cert = dict(v=1, org_id=ORG, broker_id='broker', cert_no=1, name='test',
            sign_pub=self.cert['sign_pub'], kx_pub=self.cert['kx_pub'], scope='full', keeper=True,
            local_admin_approvals=False, state='active', transcript_digest='1'*64, wrap_digests=[])
        self.runtime['verify_broker_bindings'] = lambda *args: None
        entry = self.entry('broker_cert', dict(requested=cert, request_id='r', authz={}, assertion={}))
        with patch.object(wire, 'verify_authorization', return_value='broker-challenge'):
            self.hooks.authorize(entry, self.state)
        self.assertEqual(policy.AuthorityView(self.state).broker_certificate_at('broker', self.state['head'])['source'], 'certificate')
        entry = self.entry('broker_cert', dict(requested=dict(cert, cert_no=2), request_id='r2', authz={}, assertion={}), seq=4)
        with self.assertRaisesRegex(ValueError, 'custody unavailable'):
            self.hooks.authorize(entry, self.state)
        self.runtime['effective_custody'] = lambda *args: dict(verified=True, head=dict(seq=3, hash='0'*64), custody='full', pending_downgrades=[], covered_triggers=[])
        with self.assertRaisesRegex(ValueError, 'predecessor mismatch'):
            self.hooks.authorize(entry, self.state)

    def test_live_hold_audit_records_verifier_result(self):
        digest = self.proposal()
        records = []
        self.runtime['audit_hold'] = lambda *args: records.append(args)
        self.hooks.derive(self.entry('cert_activate', dict(proposal_hash=digest), seq=4, derived=True), self.state, LATER)
        self.assertEqual(records, [(digest, 'hold_not_locally_observed')])

    def test_genesis_rejects_unknown_fields_and_unavailable_default_rules(self):
        state = policy.empty_authority(ORG)
        entry = self.entry('genesis', dict(org_id=ORG, founder=self.fixture['founder'],
            recovery_kx_pub=self.cert['kx_pub'], recovery_sign_pub=self.cert['sign_pub'],
            default_rules={'automatic': True}, max_policy_age=3600), seq=1)
        with self.assertRaises(ValueError):
            self.hooks.authorize(entry, state)
        entry['body']['default_rules'] = {}
        entry['body']['unexpected'] = True
        with self.assertRaises(ValueError):
            self.hooks.authorize(entry, state)

    def test_founder_certificate_commitment_and_bootstrap_slot_port(self):
        state = policy.empty_authority(ORG)
        genesis = self.entry('genesis', dict(org_id=ORG, founder=self.fixture['founder'],
            recovery_kx_pub=self.cert['kx_pub'], recovery_sign_pub=self.cert['sign_pub'],
            default_rules={}, max_policy_age=3600), seq=1)
        state = self.hooks.authorize(genesis, state)
        entry = self.entry('member_cert', dict(requested=dict(kind='member', certificate=self.cert),
            request_id='bootstrap', authz={}, assertion={}, initial_slot_sha256='1'*64), seq=2)
        with self.assertRaisesRegex(ValueError, 'verify_bootstrap_slot'):
            self.hooks.authorize(entry, copy.deepcopy(state))
        self.runtime['verify_bootstrap_slot'] = lambda *args: None
        with patch.object(wire, 'verify_authorization', return_value='bootstrap-challenge'):
            result = self.hooks.authorize(entry, state)
        self.assertIsNone(result['founder_pending'])
        self.assertEqual(result['certificates'][0]['certificate'], self.cert)

    def test_existing_key_and_passkey_edits_remain_closed_until_typed_binding(self):
        for field, value in (('member_key_id', 'replacement'), ('passkeys', [])):
            with self.subTest(field=field):
                cert = dict(self.cert, cert_no=2)
                cert[field] = value
                with self.assertRaisesRegex(ValueError, 'Typed passkey binding'):
                    policy._transition(dict(kind='member', certificate=cert), cert['member_id'], self.state, self.cert)

    def test_recovery_rotation_retains_consumed_points(self):
        self.state['recovery'] = dict(kx_pub='old-exchange', sign_pub='old-sign')
        requested = dict(kind='recovery_rotation', recovery_kx_pub='new-exchange', recovery_sign_pub='new-sign')
        policy._apply(self.state, requested, 3)
        self.assertEqual(set(self.state['used_recovery_points']), {'old-exchange', 'old-sign'})
        self.assertEqual(self.state['triggers']['3']['reason'], 'recovery_rotated')
        for exchange, signing in (('old-exchange', 'another'), ('new-sign', 'another'), ('same', 'same')):
            with self.subTest(exchange=exchange):
                with self.assertRaisesRegex(ValueError, 'Recovery keys must be fresh'):
                    policy._fresh_recovery(dict(recovery_kx_pub=exchange, recovery_sign_pub=signing), self.state)

    def test_cancel_is_terminal(self):
        digest = self.proposal()
        cancel = self.entry('cert_cancel', dict(proposal_hash=digest, request_id='cancel', authz={}, assertion={}), seq=4)
        with patch.object(wire, 'verify_authorization', return_value='cancel-challenge'):
            self.hooks.authorize(cancel, self.state)
        with self.assertRaises(ValueError):
            self.hooks.derive(self.entry('cert_activate', dict(proposal_hash=digest), seq=5, derived=True), self.state, LATER)

    def test_rank_decrease_permanently_invalidates_signature(self):
        digest = self.proposal()
        proposal = self.state['proposals'][digest]
        for seq, role in ((4, 'admin'), (5, 'owner')):
            cert = dict(self.cert, cert_no=seq, role=role)
            self.state['certificates'].append(dict(seq=seq, certificate=cert))
        self.state['head']['seq'] = 5
        self.assertFalse(policy.signature_still_eligible(self.state, proposal, self.cert['member_id']))

    def test_last_owner_cannot_self_remove(self):
        cert = dict(self.cert, cert_no=2, state='removed')
        entry = self.entry('member_revoke', dict(requested=dict(kind='member', certificate=cert), request_id='r', authz={}, assertion={}))
        with self.assertRaises(ValueError):
            self.hooks.authorize(entry, self.state)

    def test_broker_binding_port_missing_fails_closed(self):
        cert = dict(v=1, org_id=ORG, broker_id='broker', cert_no=1, name='test',
            sign_pub=self.cert['sign_pub'], kx_pub=self.cert['kx_pub'], scope='full', keeper=True,
            local_admin_approvals=False, state='active', transcript_digest='1'*64, wrap_digests=[])
        entry = self.entry('broker_cert', dict(requested=cert, request_id='r', authz={}, assertion={}))
        with self.assertRaisesRegex(ValueError, 'verify_broker_bindings'):
            self.hooks.authorize(entry, self.state)

    def test_unknown_kind_and_derived_authority_fail_closed(self):
        with self.assertRaises(ValueError):
            self.hooks.authorize(self.entry('unrecognized', {}), self.state)
        with self.assertRaises(ValueError):
            self.hooks.derive(self.entry('member_cert', {}, derived=True), self.state, LATER)

    def test_observations_refresh_and_preserve_catchup(self):
        head = dict(seq=2, hash='1'*64)
        observed = policy.observe_head(policy.empty_observations(), head, NOW)
        observed = policy.observe_head(observed, head, LATER)
        self.assertEqual(len(observed['heads']), 1)
        with self.assertRaisesRegex(ValueError, 'late admission'):
            policy.check_late_admission(observed, head, NOW)
        policy.check_late_admission(policy.empty_observations(), head, NOW)
        observed = policy.observe_proposal(observed, '2'*64, 'history', NOW)
        observed = policy.observe_proposal(observed, '2'*64, 'live', LATER)
        self.assertEqual(observed['proposals']['2'*64], dict(mode='history'))
        with self.assertRaises(ValueError):
            policy.observe_head(observed, dict(seq=2, hash='3'*64), LATER)

    def test_live_hold_requires_local_elapsed_time_and_reports_catchup(self):
        observation = dict(mode='live', first_seen_at=LATER)
        with self.assertRaisesRegex(ValueError, 'Locally observed'):
            policy.check_hold(NOW, LATER, observation, LATER)
        self.assertEqual(policy.check_hold(NOW, LATER, dict(mode='history'), LATER), 'hold_not_locally_observed')

    def test_genesis_broker_view_is_not_a_synthetic_certificate(self):
        state = policy.empty_authority(ORG)
        founder = dict(kind='broker', id='founder', sign_pub=self.cert['sign_pub'], kx_pub=self.cert['kx_pub'])
        entry = dict(v=2, org_id=ORG, seq=1, prev_hash=ZERO_HASH, ts=NOW, kind='genesis', signer=dict(kind='broker', id='founder'), body=dict(org_id=ORG, founder=founder, recovery_kx_pub=None, recovery_sign_pub=None, default_rules={}, max_policy_age=3600))
        self.hooks.resolve_key(entry, state)
        state = self.hooks.authorize(entry, state)
        view = policy.AuthorityView(state).broker_certificate_at('founder', state['head'])
        self.assertEqual(view['source'], 'genesis')
        self.assertNotIn('cert_no', view)
        self.assertEqual(state['brokers'], [])




class SignedAuthorityTraceTests(unittest.TestCase):
    """Locally generated signatures prove composition, not paired fixture bytes."""
    def setUp(self):
        self.sign_key = ec.derive_private_key(17, ec.SECP256R1())
        self.passkey = ec.derive_private_key(19, ec.SECP256R1())
        point = crypto.export_point(self.passkey.public_key())
        cose = bytes.fromhex('a5010203262001215820') + point[1:33] + bytes.fromhex('225820') + point[33:]
        public = crypto.b64url(crypto.export_point(self.sign_key.public_key()))
        self.cert = dict(v=1, org_id=ORG, member_id='owner', workos_user_id='human',
            cert_no=1, role='owner', reveal=False, key_holder=True, member_key_id='owner-key',
            sign_pub=public, kx_pub=public, state='active',
            passkeys=[dict(credential_id='Y3JlZGVudGlhbA', cose_key=crypto.b64url(cose))])
        self.runtime = dict(mode='history', now=LATER, observations=policy.empty_observations())
        self.genesis = dict(v=2, org_id=ORG, seq=1, prev_hash=ZERO_HASH, ts=NOW,
            kind='genesis', signer=dict(kind='member', id='owner', key='owner-key'),
            body=dict(org_id=ORG, founder=dict(kind='member', id='owner', key='owner-key',
                sign_pub=public, kx_pub=public, certificate_sha256=wire.hash_object(self.cert)),
                recovery_kx_pub=public, recovery_sign_pub=public, default_rules={}, max_policy_age=3600))
        self.verifier = PolicyVerifier(ORG, wire.hash_object(self.genesis), policy.empty_authority(ORG), policy.authority_hooks(self.runtime))
        self.append(self.genesis)
        entry = self.entry('member_cert', dict(requested=dict(kind='member', certificate=self.cert), request_id='bootstrap'))
        self.prove(entry, dict(member_id='owner'))
        self.append(entry)

    def append(self, entry, received=NOW):
        signature = None if entry['signer']['kind'] == 'derived' else crypto.p256_sign(self.sign_key,
            crypto.policy_context(ORG, wire.hash_object(entry)))
        return self.verifier.verify_record(policy_record(entry, signature, received))

    def entry(self, kind, body, derived=False):
        head = self.verifier.head
        return dict(v=2, org_id=ORG, seq=head['seq']+1, prev_hash=head['hash'], ts=NOW,
                    kind=kind, body=body, signer=dict(kind='derived') if derived else dict(kind='member', id='owner', key='owner-key'))

    def prove(self, entry, target, challenge=None):
        authz = dict(v=2, dom='titanwarden.com/authz', org_id=ORG,
            actor=dict(member_id='owner', member_key_id='owner-key', credential_id=self.cert['passkeys'][0]['credential_id']),
            op=entry['kind'], target=target, core_change_sha256=wire.hash_object(crypto.policy_core_change(entry)),
            policy_head=dict(seq=entry['seq']-1, hash=entry['prev_hash']), request_id=entry['body']['request_id'],
            challenge=challenge or crypto.b64url(bytes([entry['seq']])*32), issued_at=NOW, expires_at='2026-01-01T00:02:00Z')
        client = crypto.canonical_json(dict(type='webauthn.get', challenge=crypto.b64url(crypto.sha256(crypto.canonical_json(authz))), origin='https://app.titanwarden.com'))
        auth = crypto.sha256(b'titanwarden.com') + bytes([5]) + bytes(4)
        signature = self.passkey.sign(auth + crypto.sha256(client), ec.ECDSA(hashes.SHA256()))
        entry['body'].update(authz=authz, assertion=dict(credential_id=authz['actor']['credential_id'], clientDataJSON=crypto.b64url(client), authenticatorData=crypto.b64url(auth), signature=crypto.b64url(signature)))

    def proposal(self):
        key = crypto.b64url(crypto.export_point(ec.derive_private_key(23, ec.SECP256R1()).public_key()))
        candidate = dict(self.cert, member_id='new-admin', workos_user_id='another-human',
            member_key_id='admin-key', sign_pub=key, kx_pub=key,
            passkeys=[dict(self.cert['passkeys'][0], credential_id='YW5vdGhlcg')], role='admin')
        entry = self.entry('cert_proposal', dict(subject='new-admin', prior_cert_seq=0,
            requested=dict(kind='member', certificate=candidate), reason='certification', request_id='proposal'))
        self.prove(entry, dict(member_id='new-admin'))
        self.append(entry)
        return wire.hash_object(entry)

    def test_signed_genesis_bootstrap_proposal_hold_and_activation(self):
        digest = self.proposal()
        observed = policy.observe_proposal(policy.empty_observations(), digest, 'live', NOW)
        self.runtime.update(mode='live', observations=observed, now=LATER)
        activation = self.entry('cert_activate', dict(proposal_hash=digest), derived=True)
        self.append(activation, LATER)
        view = policy.AuthorityView(self.verifier.state)
        self.assertTrue(view.is_certified('admin-key', 2, self.verifier.head))
        self.assertFalse(view.is_certified('admin-key', 3, self.verifier.head))

    def test_real_policy_signature_rejects_modified_authorization(self):
        entry = self.entry('cert_cancel', dict(proposal_hash=self.proposal(), request_id='cancel'))
        self.prove(entry, dict(proposal_hash=entry['body']['proposal_hash']))
        entry['body']['authz']['target'] = dict(proposal_hash='0'*64)
        with self.assertRaises(PolicyError):
            self.append(entry)
        self.assertTrue(self.verifier.conflict)

    def test_real_passkey_assertion_and_challenge_reuse_fail_closed(self):
        digest = self.proposal()
        entry = self.entry('cert_cancel', dict(proposal_hash=digest, request_id='cancel'))
        self.prove(entry, dict(proposal_hash=digest), challenge=crypto.b64url(bytes([3])*32))
        with self.assertRaises(PolicyError):
            self.append(entry)

    def test_signed_hold_requires_local_observation_even_with_valid_chain(self):
        digest = self.proposal()
        self.runtime.update(mode='live', observations=policy.observe_proposal(policy.empty_observations(), digest, 'live', LATER), now=LATER)
        activation = self.entry('cert_activate', dict(proposal_hash=digest), derived=True)
        with self.assertRaisesRegex(PolicyError, 'Locally observed'):
            self.append(activation, LATER)



class AuthorityEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.cloud_fixtures import fixture, paired_traces
        cls.v = fixture('control/src/genesis/vectors.json')
        cls.brokers = next(doc for path, doc in paired_traces() if path.endswith('broker-brokers-rekeys-v1.json'))

    def test_founder_exact_initial_tag_and_immutable_bytes(self):
        vector = self.v['founder']
        entry = vector['signed']['entry']
        certificate = entry['body']['requested']['certificate']
        blobs = dict(member_slots=[copy.deepcopy(vector['slot'])])
        evidence = policy.AuthorityEvidence(blobs=blobs)
        blobs['member_slots'][0]['label'] = 'tampered after construction'
        evidence.verify_bootstrap_slot(entry, certificate, policy.empty_authority(certificate['org_id']))
        evidence.finalize({})
        bad = copy.deepcopy(entry)
        bad['body']['initial_slot_sha256'] = wire.slot_blob_digest(vector['slot'])
        rejected = policy.AuthorityEvidence(blobs=dict(member_slots=[vector['slot']]))
        rejected.verify_bootstrap_slot(bad, certificate, {})
        with self.assertRaisesRegex(ValueError, 'Missing committed initial slot'):
            rejected.finalize({})

    def acceptance_evidence(self):
        vector = self.v['accept']
        cert = self.v['certificate']
        row = dict(member_id=cert['member_id'], transcript_json=crypto.canonical_json(vector['payload']).decode(), proof=vector['proof'])
        wrap = copy.deepcopy(self.v['confirmation']['wrap'])
        return dict(genesis_acceptances=[row]), dict(member_slots=[vector['private_slot']], org_key_wraps=[wrap])

    def test_acceptance_binds_real_signature_metadata_and_current_generation(self):
        rows, blobs = self.acceptance_evidence()
        evidence = policy.AuthorityEvidence(rows, blobs)
        entry = self.v['confirmation']['signed']['entry']
        cert = entry['body']['requested']['certificate']
        state = policy.empty_authority(cert['org_id'])
        state['head'] = dict(seq=3, hash=entry['prev_hash'])
        provider = lambda head: dict(kind='committed', generation=1)
        evidence.verify_member_confirmation_wrap(entry, cert, state, provider)
        evidence.finalize(state)
        with self.assertRaisesRegex(ValueError, 'Wrap generation differs'):
            evidence.verify_member_confirmation_wrap(entry, cert, state, lambda head: dict(kind='committed', generation=2))
        changed = dict(cert, sign_pub=self.v['owner']['sign_pub'])
        with self.assertRaisesRegex(ValueError, 'accepted keys'):
            evidence.verify_member_confirmation_wrap(entry, changed, state, provider)
        rows['genesis_acceptances'][0]['proof'] = crypto.b64url(bytes(64))
        with self.assertRaises(ValueError):
            policy.AuthorityEvidence(rows, blobs).verify_member_confirmation_wrap(entry, cert, state, provider)

    def test_confirmed_wrap_surviving_bytes_are_checked(self):
        rows, blobs = self.acceptance_evidence()
        blobs['org_key_wraps'][0]['wrapped_omk'] = '00' * 48
        entry = self.v['confirmation']['signed']['entry']
        cert = entry['body']['requested']['certificate']
        state = policy.empty_authority(cert['org_id'])
        with self.assertRaisesRegex(ValueError, 'wrap digest'):
            policy.AuthorityEvidence(rows, blobs).verify_member_confirmation_wrap(entry, cert, state, lambda head: dict(kind='committed', generation=1))

    def test_retained_broker_wrap_archive_binds_cert_seq_and_surviving_bytes(self):
        record = next(r for r in self.brokers['records'] if r['entry']['kind'] == 'broker_cert')
        entry = copy.deepcopy(record['entry'])
        cert = entry['body']['requested']
        rows = {}
        for chunk in record['evidence']:
            if chunk.get('source') != 'blobs':
                rows.setdefault(chunk['table'], []).extend(copy.deepcopy(chunk['rows']))
        wrap = copy.deepcopy(self.v['confirmation']['wrap'])
        blob_id = 'enw_' + '1'*32
        wrap['wrap_id'] = blob_id
        cert['wrap_digests'] = [dict(id=blob_id, digest=wrap['wrap_digest'])]
        rows['enrollment_wrap_digests'] = [dict(blob_id=blob_id, broker_id=cert['broker_id'],
            cert_seq=entry['seq'], wrap_digest=wrap['wrap_digest'])]
        state = policy.empty_authority(entry['org_id'])
        state['head'] = record['predecessor']['head']
        # Retained digest provenance suffices after encrypted blob collection.
        policy.AuthorityEvidence(rows).verify_broker_bindings(entry, cert, state)
        policy.AuthorityEvidence(rows, dict(org_key_wraps=[wrap])).verify_broker_bindings(entry, cert, state)
        wrap['wrapped_omk'] = '00'*48
        with self.assertRaisesRegex(ValueError, 'wrap digest'):
            policy.AuthorityEvidence(rows, dict(org_key_wraps=[wrap])).verify_broker_bindings(entry, cert, state)
        rows['enrollment_wrap_digests'][0]['cert_seq'] += 1
        with self.assertRaisesRegex(ValueError, 'archive differs'):
            policy.AuthorityEvidence(rows).verify_broker_bindings(entry, cert, state)

    def test_real_enrollment_transcript_binds_broker_certificate(self):
        record = next(r for r in self.brokers['records'] if r['entry']['kind'] == 'broker_cert')
        entry = record['entry']
        cert = entry['body']['requested']
        rows = {}
        for chunk in record['evidence']:
            if chunk.get('source') != 'blobs':
                rows.setdefault(chunk['table'], []).extend(copy.deepcopy(chunk['rows']))
        state = policy.empty_authority(entry['org_id'])
        state['head'] = record['predecessor']['head']
        evidence = policy.AuthorityEvidence(rows)
        evidence.verify_enrollment_identity(cert, state)
        with self.assertRaisesRegex(ValueError, 'identity differs'):
            evidence.verify_enrollment_identity(dict(cert, name='substituted'), state)
        rows['enrollment_records'][0]['proof'] = crypto.b64url(bytes(64))
        with self.assertRaisesRegex(ValueError, 'proof invalid'):
            policy.AuthorityEvidence(rows).verify_enrollment_identity(cert, state)


if __name__ == '__main__':
    unittest.main()
