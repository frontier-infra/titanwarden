"""Independent guard regressions from PR 14 review, including valid attack signatures."""
import copy
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from tw import cloud_policy as policy, cloud_wire as wire, crypto
from tw.policy_log import OfflineCloudVerifier, PolicyVerifier, PolicyHooks, PolicyError, policy_record, ZERO_HASH
from tw.store import Store, StoreError, SCHEMA_VERSION
import test_cloud_policy as authority_tests
import test_cloud_replay as replay_tests


class AuthorityGuardTests(unittest.TestCase):
    def setUp(self):
        authority_tests.AuthorityTests.setUpClass()
        self.h = authority_tests.AuthorityTests()
        self.h.setUp()

    def test_single_owner_cannot_directly_grant_admin(self):
        h = self.h
        cert = h.cert_for('admin')
        entry = h.entry('member_cert', dict(requested=dict(kind='member', certificate=cert),
                                          request_id='direct-escalation', authz={}, assertion={}))
        with patch.object(wire, 'verify_authorization', return_value='valid-challenge'):
            with self.assertRaisesRegex(ValueError, '^Logged proposal required$'):
                h.hooks.authorize(entry, h.state)

    def recovery_proposal(self, *, reused=False):
        h = self.h
        fresh = [crypto.b64url(crypto.export_point(ec.derive_private_key(n, ec.SECP256R1()).public_key())) for n in (23, 29)]
        h.state.update(recovery=dict(kx_pub=h.cert['kx_pub'], sign_pub=h.cert['sign_pub']),
                       recovery_ever_set=True, recovery_seq=1)
        request = dict(kind='recovery_rotation', recovery_kx_pub=h.cert['kx_pub'] if reused else fresh[0],
                       recovery_sign_pub=fresh[1])
        entry = h.entry('recovery_rotate', dict(subject='recovery', prior_cert_seq=1,
            requested=request, reason='manual', request_id='rotate', authz={}, assertion={}))
        return entry

    def test_recovery_proposal_rejects_consumed_point_at_authorize(self):
        entry = self.recovery_proposal(reused=True)
        with patch.object(wire, 'verify_authorization', return_value='valid-challenge'):
            with self.assertRaisesRegex(ValueError, '^Recovery keys must be fresh$'):
                self.h.hooks.authorize(entry, self.h.state)

    def test_recovery_activation_rechecks_consumed_point(self):
        entry = self.recovery_proposal()
        with patch.object(wire, 'verify_authorization', return_value='valid-challenge'):
            self.h.hooks.authorize(entry, self.h.state)
        self.h.state['used_recovery_points'].append(entry['body']['requested']['recovery_kx_pub'])
        activation = self.h.entry('cert_activate', dict(proposal_hash=wire.hash_object(entry)), seq=4, derived=True)
        with self.assertRaisesRegex(ValueError, '^Recovery keys must be fresh$'):
            self.h.hooks.derive(activation, self.h.state, authority_tests.LATER)

    def test_broker_revoke_cannot_edit_prior_name(self):
        h = self.h
        prior = dict(v=1, org_id=authority_tests.ORG, broker_id='broker', cert_no=1,
            name='original', sign_pub=h.cert['sign_pub'], kx_pub=h.cert['kx_pub'],
            scope='full', keeper=True, local_admin_approvals=False, state='active',
            transcript_digest='1'*64, wrap_digests=[])
        h.state['brokers'].append(dict(seq=2, certificate=prior))
        h.runtime['effective_custody'] = lambda *args: dict(verified=True, head=h.state['head'],
            pending_downgrades=[], covered_triggers=[], custody='full', generation=1, full_custody_generation=1)
        revoke = dict(prior, cert_no=2, state='revoked', name='edited during revoke')
        entry = h.entry('broker_revoke', dict(requested=revoke, request_id='revoke', authz={}, assertion={}))
        with patch.object(wire, 'verify_authorization', return_value='valid-challenge'):
            with self.assertRaisesRegex(ValueError, '^Revoke changes broker fields$'):
                h.hooks.authorize(entry, h.state)

    def test_broker_custody_requires_every_pending_downgrade(self):
        state = self.h.state
        state['head']['seq'] = 4
        prior = dict(broker_id='broker', scope=['a'])
        state['brokers'] = [dict(seq=3, certificate=prior)]
        state['triggers']['3'] = dict(seq=3, kind='full', reason='full_to_scoped_downgrade', projects=[])
        evidence = dict(verified=True, head=copy.deepcopy(state['head']), pending_downgrades=[],
                        covered_triggers=[], custody='full')
        with self.assertRaisesRegex(ValueError, '^Broker custody downgrade coverage mismatch$'):
            policy.verified_broker_custody(lambda *args: evidence, prior, state)


class ResignedWebAuthnTests(unittest.TestCase):
    def setUp(self):
        self.key = ec.derive_private_key(71, ec.SECP256R1())
        point = crypto.export_point(self.key.public_key())
        cose = bytes.fromhex('a5010203262001215820') + point[1:33] + bytes.fromhex('225820') + point[33:]
        self.passkey = dict(credential_id='Y3JlZGVudGlhbA', cose_key=crypto.b64url(cose))
        self.challenge = crypto.sha256(b'bound-authorization')

    def assertion(self, *, origin='https://app.titanwarden.com', rp=None, flags=5):
        client = crypto.canonical_json(dict(type='webauthn.get', challenge=crypto.b64url(self.challenge), origin=origin))
        auth = (crypto.sha256(b'titanwarden.com') if rp is None else rp) + bytes([flags]) + bytes(4)
        message = auth + crypto.sha256(client)
        der = self.key.sign(message, ec.ECDSA(hashes.SHA256()))
        # Prove the altered data has a genuine signature before testing a guard.
        self.assertTrue(crypto.p256_verify(wire.cose_point(self.passkey['cose_key']), message, wire.der_signature(der)))
        return dict(credential_id=self.passkey['credential_id'], clientDataJSON=crypto.b64url(client),
                    authenticatorData=crypto.b64url(auth), signature=crypto.b64url(der))

    def test_resigned_wrong_origin(self):
        wire.verify_assertion(self.assertion(), self.passkey, self.challenge)
        with self.assertRaisesRegex(ValueError, '^invalid WebAuthn client data$'):
            wire.verify_assertion(self.assertion(origin='https://evil.test'), self.passkey, self.challenge)

    def test_resigned_wrong_rp_hash(self):
        with self.assertRaisesRegex(ValueError, '^invalid authenticator data$'):
            wire.verify_assertion(self.assertion(rp=crypto.sha256(b'evil.test')), self.passkey, self.challenge)

    def test_resigned_missing_or_forbidden_flags(self):
        wire.verify_assertion(self.assertion(flags=0x1D), self.passkey, self.challenge)
        for flags in (0x01, 0x04, 0x07, 0x25, 0x45, 0x85, 0x15):
            with self.subTest(flags=flags), self.assertRaisesRegex(ValueError, '^invalid authenticator data$'):
                wire.verify_assertion(self.assertion(flags=flags), self.passkey, self.challenge)


class CompositionBoundaryTests(unittest.TestCase):
    def test_authority_fixture_hash_failure_is_explicit(self):
        import cloud_fixtures
        with patch.dict(cloud_fixtures.FIXTURES, {'control/vectors/authority-v1.json': '0'*64}):
            with self.assertRaisesRegex(ValueError, '^fixture SHA256 mismatch$'):
                authority_tests.AuthorityTests.setUpClass()

    def test_pending_invitee_cannot_activate_through_proposal(self):
        h = authority_tests.SignedAuthorityTraceTests()
        h.setUp()
        h.verifier = OfflineCloudVerifier(authority_tests.ORG, wire.hash_object(h.genesis))
        h.append(h.genesis)
        bootstrap = h.entry('member_cert', dict(requested=dict(kind='member', certificate=h.cert), request_id='bootstrap'))
        h.prove(bootstrap, dict(member_id='owner'))
        h.append(bootstrap)
        proposal = h.proposal()
        before = (h.verifier.head, h.verifier.state, h.verifier.epoch_state)
        activation = h.entry('cert_activate', dict(proposal_hash=proposal), derived=True)
        evidence = policy.AuthorityEvidence(rows=dict(genesis_acceptances=[
            dict(member_key_id='admin-key', member_id='new-admin', confirmed_seq=None)]))
        with self.assertRaisesRegex(PolicyError, '^Pending invite requires direct confirmation$'):
            h.verifier.verify_record(policy_record(activation, None, authority_tests.LATER), evidence=evidence)
        self.assertEqual((h.verifier.head, h.verifier.state, h.verifier.epoch_state), before)

    def test_runtime_cannot_inject_authority_or_evidence_ports(self):
        h = replay_tests.OfflineCompositionTests()
        h.setUp()
        for name in ('verify_bootstrap_slot', 'verify_member_confirmation_wrap', 'verify_broker_bindings',
                     'verify_founding_broker_enrollment', 'effective_custody', 'project_exists', 'challenge', 'audit_hold'):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, '^unsupported offline runtime field$'):
                    OfflineCloudVerifier(replay_tests.ORG, h.root, runtime={name: lambda *args: None})
                replay = OfflineCloudVerifier(replay_tests.ORG, h.root)
                with self.assertRaisesRegex(PolicyError, '^unsupported offline runtime field$'):
                    replay.verify_record(h.record(h.genesis), runtime={name: lambda *args: None})
                self.assertEqual(replay.head['seq'], 0)


class PersistenceBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name).open(create=True)
        self.addCleanup(self.store.close)
        self.h = replay_tests.OfflineCompositionTests()
        self.h.setUp()

    def test_new_and_existing_stores_only_create_cloud_schema_on_explicit_use(self):
        def tables():
            return [r[0] for r in self.store.connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        base = tables()
        self.assertFalse(any(name.startswith('cloud_') for name in base))
        self.store.close()
        self.store.open()
        self.assertEqual(tables(), base)
        self.store.initialize_cloud_replay(replay_tests.ORG, self.h.root)
        self.assertEqual(len([name for name in tables() if name.startswith('cloud_')]), 6)
        self.assertEqual(SCHEMA_VERSION, 1)

    def test_fabricated_seq_50_and_checkpoint_constructor_are_refused(self):
        head = dict(seq=50, hash='d'*64)
        state = dict(policy.empty_authority(replay_tests.ORG), root=self.h.root, head=head)
        hooks = PolicyHooks(lambda *args: b'', lambda *args: state, lambda *args: state)
        with self.assertRaisesRegex(ValueError, 'checkpoint state is forbidden'):
            PolicyVerifier(replay_tests.ORG, self.h.root, state, hooks)
        with self.assertRaises(TypeError):
            PolicyVerifier(replay_tests.ORG, self.h.root, {}, hooks, checkpoint=head)
        # Test-only fabrication recreates the old constructor's resulting object.
        fake = PolicyVerifier(replay_tests.ORG, self.h.root, {}, hooks)
        fake._head, fake._state, fake._verified_heads = head, state, {50: head['hash']}
        self.store.initialize_cloud_replay(replay_tests.ORG, self.h.root)
        with self.assertRaisesRegex(StoreError, '^successful independent verifier required$'):
            self.store.save_cloud_replay(fake)
        self.assertIsNone(self.store.load_cloud_replay(replay_tests.ORG))

    def test_checkpoint_save_requires_final_ciphertext_check_at_exact_head(self):
        h = self.h
        self.store.initialize_cloud_replay(replay_tests.ORG, h.root)
        with self.assertRaisesRegex(StoreError, 'require final verification'):
            self.store.save_cloud_replay(h.replay)
        h.init()
        ent = dict(h.genesis, seq=h.replay.head['seq']+1, prev_hash=h.replay.head['hash'], kind='secret_create',
                   body=dict(secret_id='s', path='a/token', project='a', **{'class': 'standard'}))
        h.append(ent)
        blob = dict(version_id='v', secret_id='s', kek_id='ka', ciphertext='ab'*25,
                    nonce='00'*12, wrapped_dek='22'*48, dek_nonce='00'*12)
        body = dict(version_id='v', secret_id='s', version_no=1, state='active', kek_id='ka',
                    fingerprint='aa'*32, length=25, source='manual',
                    value_digest=crypto.value_digest(bytes.fromhex(blob['ciphertext']), bytes(12)),
                    envelope_digest=crypto.envelope_digest('ka', bytes.fromhex(blob['wrapped_dek']), bytes(12)))
        ent = dict(ent, seq=h.replay.head['seq']+1, prev_hash=h.replay.head['hash'], kind='version_add', body=body)
        h.append(ent, blob=blob)
        with self.assertRaisesRegex(StoreError, 'require final verification'):
            self.store.save_cloud_replay(h.replay)
        h.replay.finish_history([blob])
        self.store.save_cloud_replay(h.replay)
        ent = dict(ent, seq=h.replay.head['seq']+1, prev_hash=h.replay.head['hash'], kind='secret_create',
                   body=dict(secret_id='next', path='a/next', project='a', **{'class': 'standard'}))
        h.append(ent)
        with self.assertRaisesRegex(StoreError, 'require final verification'):
            self.store.save_cloud_replay(h.replay)


if __name__ == '__main__':
    unittest.main()
