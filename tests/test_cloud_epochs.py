"""Offline adversarial epoch replay and ciphertext commitment checks."""
import copy
import hashlib
import pathlib
import unittest
from cryptography.hazmat.primitives.asymmetric import ec
from tw import crypto
from tw.cloud_epochs import (EpochReplay, checked_stage, derive_recipients,
                             epoch_blob_commitments, epoch_checkpoint,
                             hash_object, keyring_digest, recipient_hints,
                             verify_recipient_hints)
from tw.policy_log import PolicyError

POINT = crypto.export_point(ec.derive_private_key(1, ec.SECP256R1()).public_key()).hex()
SIGNER = dict(kind='broker', id='founder')
TS = '2026-10-16T00:00:00Z'


def key(kid='ka', purpose='kek', project='a', version=1, generation=1):
    return dict(key_id=kid, purpose=purpose, project=project, version=version,
                nonce='00' * 12, wrapped_key='11' * 48, mk_generation=generation, aad_v=2)


def wrap(kind='broker', rid='founder', generation=1):
    return dict(recipient_kind=kind, recipient_id=rid, omk_generation=generation,
                eph_pub=POINT, nonce='00' * 12, wrapped_omk='22' * 48,
                wrap_digest=crypto.wrap_digest(bytes.fromhex(POINT), bytes(12), bytes.fromhex('22' * 48)))


def snapshot(seq=1, members=None, brokers=None, recovery=None):
    return dict(head=dict(seq=seq, hash='a' * 64), members=members or [],
                brokers=brokers if brokers is not None else [dict(id='founder', kx_pub=POINT, scope='full', keeper=True, full_custody_generation=1)],
                recovery=recovery, projects=['a'], rekey_triggers=[],
                founder=dict(signer=SIGNER, mode='broker', init_after_seq=1))


def entry(kind, body, snap, signer=None, ts=TS):
    return dict(v=2, org_id='0' * 32, seq=snap['head']['seq'] + 1,
                prev_hash=snap['head']['hash'], ts=ts, kind=kind, body=body,
                signer=signer or SIGNER)


def commitments(rows):
    return [dict(key_id=k['key_id'], purpose=k['purpose'], scope=k['project'] or '*', digest=keyring_digest(k)) for k in rows]


def initial(snap=None):
    snap = snap or snapshot()
    stage = dict(keyring=[key(), key('fk', 'fingerprint', None)], wraps=[wrap()], scoped_seals=[])
    recipients = [dict(r, wrap_digest=stage['wraps'][0]['wrap_digest']) for r in derive_recipients(snap)]
    body = dict(generation=1, recipients=recipients, scoped_seals=[], keyring=commitments(stage['keyring']), active_kek={'a': 'ka'})
    return entry('epoch_init', body, snap), stage


class EpochTests(unittest.TestCase):
    def setUp(self):
        self.replay = EpochReplay()
        self.snap = snapshot()
        self.init_entry, self.stage = initial(self.snap)

    def init(self):
        self.replay.apply(self.init_entry, self.snap, stage=self.stage)

    def rotation(self, *, paginated=False, snap=None):
        snap = snap or snapshot(2)
        rows = [dict(k, mk_generation=2) for k in self.replay.state['keyring']] + [key('kb', version=2, generation=2)]
        wraps = [wrap(r['kind'], r['id'], 2) for r in derive_recipients(snap)]
        recipients = [dict(r, wrap_digest=w['wrap_digest']) for r, w in zip(derive_recipients(snap), wraps)]
        stage = dict(keyring=rows, wraps=wraps, scoped_seals=[])
        body = dict(from_generation=1, to_generation=2, recipients=recipients, scoped_seals=[], keyring=commitments(rows), active_kek={'a': 'kb'}, reason='manual')
        if paginated:
            body.update(recipients=recipients[:1], recipients_count=len(recipients), recipients_sha256=hash_object(recipients))
        return entry('epoch_rotate', body, snap), stage, recipients

    def test_k1_pinned_inline_vector(self):
        root = pathlib.Path(__file__).parent / 'fixtures/cloud/6a2d52f7cfcd9be944cb880602007832de637dc0'
        data = (root / 'control/test/epoch-ports.test.ts').read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), 'ac0810acdcd3530f2e2b5ef3914188f98b0ca4c778ccc9dfbd09cd5e0a4838cc')
        expected = '5e97acbf89ba93d9b8bdb661533f998359f7ba49157f506c10bdd722db9d9d3a'
        self.assertIn(expected.encode(), data)
        row = key('key-a', version=2, generation=2)
        self.assertEqual(keyring_digest(row), expected)
        for field, value in [('key_id', 'key-b'), ('version', 3), ('nonce', '01' * 12), ('wrapped_key', '12' * 48), ('purpose', 'fingerprint')]:
            with self.subTest(field=field):
                self.assertNotEqual(keyring_digest(dict(row, **{field: value})), expected)

    def test_init_and_exact_head_view(self):
        self.init()
        view = self.replay.view(snapshot(2))
        self.assertEqual(view.committed_generation(snapshot(2)['head']), dict(kind='committed', generation=1))
        self.assertEqual(view.active_kek('a', snapshot(2)['head']), 'ka')
        with self.assertRaises(PolicyError):
            view.active_kek('a', self.snap['head'])
        with self.assertRaises(PolicyError):
            self.replay.apply(self.init_entry, self.snap, stage=self.stage)

    def test_init_field_and_commitment_mutations_fail_atomically(self):
        for change in ('extra', 'generation', 'digest', 'recipient', 'stage', 'position', 'scope'):
            with self.subTest(change=change):
                ent, stage = copy.deepcopy(self.init_entry), copy.deepcopy(self.stage)
                snap = copy.deepcopy(self.snap)
                if change == 'extra': ent['body']['unknown'] = 1
                elif change == 'generation': ent['body']['generation'] = 2
                elif change == 'digest': ent['body']['keyring'][0]['digest'] = '0' * 64
                elif change == 'recipient': ent['body']['recipients'][0]['kx_pub_sha256'] = '0' * 64
                elif change == 'stage': stage['wraps'][0]['wrapped_omk'] = '00' * 48
                elif change == 'position': ent['seq'] += 1
                elif change == 'scope': snap['brokers'][0]['scope'] = ['a']
                with self.assertRaises(PolicyError): self.replay.apply(ent, snap, stage=stage)
                self.assertEqual(self.replay.state['generation'], 0)

    def test_stage_validation_negative_matrix(self):
        for field, value in [('nonce', 'AA' * 12), ('nonce', '00' * 11), ('wrapped_key', '00' * 47), ('aad_v', True), ('project', None), ('purpose', 'unknown'), ('version', 0)]:
            with self.subTest(field=field, value=value):
                stage = copy.deepcopy(self.stage); stage['keyring'][0][field] = value
                with self.assertRaises(PolicyError): checked_stage(stage)

    def test_full_rotation_and_rolling_budget(self):
        self.init(); snap = snapshot(2)
        ent, stage, _ = self.rotation(snap=snap)
        self.replay.apply(ent, snap, stage=stage)
        self.assertEqual(self.replay.state['generation'], 2)
        self.assertEqual(self.replay.state['active_kek'], {'a': 'kb'})
        self.assertEqual([k['key_id'] for k in self.replay.state['keyring']], ['fk', 'kb'])
        self.assertEqual(self.replay.state['last_discretionary_rotation'], TS)
        state = copy.deepcopy(self.replay.state)
        with self.assertRaises(PolicyError):
            self.replay._trigger(state, dict(ent, ts='2026-10-16T23:59:59Z'), snap, ['a'])
        self.assertEqual(self.replay._trigger(state, dict(ent, ts='2026-10-17T00:00:00Z'), snap, ['a']), 'manual')

    def test_historical_keyring_missing_rejected(self):
        self.init(); ent, stage, _ = self.rotation()
        stage['keyring'] = [k for k in stage['keyring'] if k['key_id'] != 'fk']
        ent['body']['keyring'] = commitments(stage['keyring'])
        with self.assertRaises(PolicyError): self.replay.apply(ent, snapshot(2), stage=stage)

    def test_recipient_hints_compare_every_field(self):
        hints = recipient_hints(self.snap)
        verify_recipient_hints(self.snap, hints)
        for modified in [dict(hints, extra=1), dict(hints, recipients=[]), dict(hints, recipients=[dict(hints['recipients'][0], kx_pub='00' * 65)])]:
            with self.assertRaises(PolicyError): verify_recipient_hints(self.snap, modified)

    def test_paginated_intent_is_inert_and_stage_immutable(self):
        self.init(); snap = snapshot(2, recovery=dict(id='recovery', kx_pub=POINT))
        ent, stage, recipients = self.rotation(paginated=True, snap=snap)
        self.replay.apply(ent, snap, stage=stage)
        self.assertEqual(self.replay.state['generation'], 1)
        commit_snap = copy.deepcopy(snap); commit_snap['head']['seq'] = 3
        commit = entry('epoch_commit', dict(epoch_seq=3), commit_snap)
        with self.assertRaises(PolicyError): self.replay.apply(commit, commit_snap, stage=stage)
        page = entry('epoch_recipients', dict(epoch_seq=3, page=1, items=recipients[1:]), commit_snap)
        self.replay.apply(page, commit_snap)
        commit_snap['head']['seq'] = 4; commit = entry('epoch_commit', dict(epoch_seq=3), commit_snap)
        changed = copy.deepcopy(stage); changed['keyring'][0]['nonce'] = '11' * 12
        with self.assertRaises(PolicyError): self.replay.apply(commit, commit_snap, stage=changed)
        reordered = copy.deepcopy(stage)
        reordered['keyring'].reverse()
        # All signed sets and byte digests still agree. Only immutable staging
        # identity rejects this otherwise equivalent payload representation.
        with self.assertRaisesRegex(PolicyError, '^Staged payload changed after intent$'):
            self.replay.apply(commit, commit_snap, stage=reordered)
        self.replay.apply(commit, commit_snap, stage=stage)
        self.assertEqual(self.replay.state['epochs'][-1]['seq'], 3)
        self.assertEqual(self.replay.state['epochs'][-1]['commit_seq'], 5)

    def test_pending_expiry_and_keeper_cancel(self):
        self.init(); snap = snapshot(2, recovery=dict(id='recovery', kx_pub=POINT))
        ent, stage, _ = self.rotation(paginated=True, snap=snap)
        self.replay.apply(ent, snap, stage=stage)
        snap['head']['seq'] = 3; cancel = entry('epoch_cancel', dict(epoch_seq=3), snap)
        with self.assertRaises(PolicyError) as caught:
            self.replay.apply(cancel, snap, received_at='2026-10-16T00:30:00Z')
        self.assertEqual(caught.exception.code, 'E_EPOCH_SUPERSEDED')
        with self.assertRaises(PolicyError):
            self.replay.apply(dict(cancel, signer=dict(kind='broker', id='successor')), snap)
        self.replay.apply(cancel, snap)
        self.assertTrue(self.replay.state['pending']['superseded'])

    def test_authority_change_supersedes_pending(self):
        self.init(); snap = snapshot(2, recovery=dict(id='recovery', kx_pub=POINT))
        ent, stage, _ = self.rotation(paginated=True, snap=snap)
        self.replay.apply(ent, snap, stage=stage)
        snap['head']['seq'] = 3
        self.replay.observe_authority(entry('broker_cert', {}, snap), snap)
        self.assertTrue(self.replay.state['pending']['superseded'])

    def ciphertext(self):
        self.init(); snap = snapshot(2)
        self.replay.apply(entry('secret_create', dict(secret_id='s', path='a/token', project='a', **{'class': 'sensitive'}), snap), snap)
        snap['head']['seq'] = 3
        blob = dict(version_id='v', secret_id='s', kek_id='ka', ciphertext='ab' * 25, nonce='00' * 12, wrapped_dek='22' * 48, dek_nonce='00' * 12)
        body = dict(version_id='v', secret_id='s', version_no=1, state='active', kek_id='ka', fingerprint='aa' * 32, length=25, source='manual', value_digest=crypto.value_digest(bytes.fromhex(blob['ciphertext']), bytes(12)), envelope_digest=crypto.envelope_digest('ka', bytes.fromhex(blob['wrapped_dek']), bytes(12)))
        return snap, entry('version_add', body, snap), blob

    def test_ciphertext_commitments_and_negative_metadata(self):
        snap, ent, blob = self.ciphertext()
        for field, value in [('length', 9), ('value_digest', '0' * 64), ('envelope_digest', '0' * 64), ('version_no', 2), ('fingerprint', '00'), ('state', 'retired')]:
            with self.subTest(field=field):
                changed = copy.deepcopy(ent); changed['body'][field] = value
                with self.assertRaises(PolicyError): self.replay.apply(changed, snap, blob=blob)
        self.replay.apply(ent, snap, blob=blob)
        self.assertEqual(self.replay.verify_ciphertext(blob)['length'], 25)
        with self.assertRaises(PolicyError): self.replay.verify_ciphertext(dict(blob, ciphertext='ac' * 25))
        with self.assertRaises(PolicyError): self.replay.apply(ent, snap, blob=blob)

    def test_rewrap_latest_envelope_and_atomic_duplicates(self):
        snap, ent, blob = self.ciphertext(); self.replay.apply(ent, snap, blob=blob)
        snap['head']['seq'] = 4; rotate, stage, _ = self.rotation(snap=snap)
        self.replay.apply(rotate, snap, stage=stage)
        self.assertIn('ka', [k['key_id'] for k in self.replay.state['keyring']])
        snap['head']['seq'] = 5
        item = dict(version_id='v', from_kek_id='ka', from_envelope_digest=ent['body']['envelope_digest'], to_kek_id='kb', to_envelope_digest='b' * 64)
        rewrap = entry('dek_rewrap', dict(epoch_seq=5, items=[item, item]), snap)
        with self.assertRaises(PolicyError): self.replay.apply(rewrap, snap)
        self.assertEqual(self.replay.state['versions'][0]['kek_id'], 'ka')
        rewrap['body']['items'] = [item]; self.replay.apply(rewrap, snap)
        self.assertNotIn('ka', [k['key_id'] for k in self.replay.state['keyring']])
        with self.assertRaises(PolicyError): self.replay.apply(rewrap, snap)

    def test_scoped_writer_and_unsupported_metadata(self):
        self.init(); snap = snapshot(2, brokers=[dict(id='scoped', kx_pub=POINT, scope=['a'], keeper=False)])
        body = dict(secret_id='s', path='a/token', project='a', **{'class': 'standard'})
        self.replay.apply(entry('secret_create', body, snap, signer=dict(kind='broker', id='scoped')), snap)
        for changed in [dict(body, secret_id='x', path='b/token', project='b'), dict(body, rotation_period_days=1)]:
            with self.assertRaises(PolicyError): self.replay.apply(entry('secret_create', changed, snap, signer=dict(kind='broker', id='scoped')), snap)

    def test_scope_custody_and_committed_coverage(self):
        self.init(); snap = snapshot(3)
        snap['brokers'][0].update(scope=['a'], scope_changes=[dict(seq=3, from_scope='full', to_scope=['a'])])
        snap['rekey_triggers'] = [dict(seq=3, kind='full', reason='full_to_scoped_downgrade', projects=['a'])]
        evidence = self.replay.view(snap).custody_evidence('founder', snap['head'])
        self.assertEqual(evidence['custody'], 'full'); self.assertEqual(evidence['pending_downgrades'], [3])
        snap['brokers'][0]['full_custody_generation'] = None
        self.assertEqual(self.replay.view(snap).custody_evidence('founder', snap['head'])['custody'], 'full')
        snap['rekey_triggers'] = []
        with self.assertRaises(PolicyError): self.replay.view(snap).custody_evidence('founder', snap['head'])

    def test_browser_init_exact_founder_recipients(self):
        signer = dict(kind='member', id='owner', key='owner-key')
        snap = snapshot(2, members=[dict(id='owner-key', member_id='owner', kx_pub=POINT)], brokers=[], recovery=dict(id='recovery', kx_pub=POINT))
        snap['founder'] = dict(signer=signer, mode='browser', init_after_seq=2)
        ent, stage = initial(snap)
        ent['signer'] = signer
        stage['wraps'] = [wrap(r['kind'], r['id']) for r in derive_recipients(snap)]
        ent['body']['recipients'] = [dict(r, wrap_digest=w['wrap_digest']) for r, w in zip(derive_recipients(snap), stage['wraps'])]
        self.replay.apply(ent, snap, stage=stage)
        self.assertEqual(self.replay.state['generation'], 1)

    def test_project_rekey_preserves_generation_and_unrelated_keys(self):
        self.init(); snap = snapshot(2)
        snap['rekey_triggers'] = [dict(seq=2, kind='projects', reason='scoped_broker_revoked', projects=['a'])]
        stage = dict(keyring=[key('kb', version=2)], wraps=[], scoped_seals=[])
        body = dict(trigger_seq=2, omk_generation=1, projects={'a': dict(from_kek_id='ka', to_kek_id='kb')}, keyring=commitments(stage['keyring']), scoped_seals=[])
        ent = entry('epoch_rotate_projects', body, snap)
        self.replay.apply(ent, snap, stage=stage)
        self.assertEqual(self.replay.state['generation'], 1)
        self.assertEqual(self.replay.state['active_kek'], {'a': 'kb'})
        self.assertEqual(self.replay.state['org_wraps'], self.stage['wraps'])
        self.assertEqual(self.replay.state['used_triggers'], [2])
        self.assertEqual(self.replay.state['keyring'][0]['key_id'], 'fk')
        with self.assertRaises(PolicyError): self.replay.apply(ent, snap, stage=stage)

    def test_scoped_seals_bind_exact_certified_projects(self):
        self.init(); snap = snapshot(2)
        snap['brokers'].append(dict(id='scoped', kx_pub=POINT, scope=['a'], keeper=False))
        ent, stage, _ = self.rotation(snap=snap)
        seal = dict(broker_id='scoped', key_id='kb', purpose='kek', project='a', eph_pub=POINT, nonce='00' * 12, wrapped_key='22' * 48, wrap_digest=self.stage['wraps'][0]['wrap_digest'])
        stage['scoped_seals'] = [seal]
        ent['body']['scoped_seals'] = [dict(broker_id='scoped', key_id='kb', project='a', wrap_digest=seal['wrap_digest'])]
        wrong = copy.deepcopy(stage); wrong['scoped_seals'][0]['broker_id'] = 'other'
        with self.assertRaises(PolicyError): self.replay.apply(ent, snap, stage=wrong)
        self.replay.apply(ent, snap, stage=stage)
        self.assertEqual(self.replay.state['broker_wraps'], [seal])

    def test_malformed_nested_input_preserves_typed_failure(self):
        self.init(); snap = snapshot(2)
        for body in [{}, {'epoch_seq': 0}, {'epoch_seq': True}]:
            with self.assertRaises(PolicyError): self.replay.apply(entry('epoch_commit', body, snap), snap)

    def test_committed_full_rekey_covers_downgrade_and_narrowing(self):
        self.init()
        signer = dict(kind='member', id='owner', key='owner-key')
        snap = snapshot(4, members=[dict(id='owner-key', member_id='owner', kx_pub=POINT)])
        snap['brokers'][0].update(scope=[], scope_changes=[dict(seq=3, from_scope='full', to_scope=['a']), dict(seq=4, from_scope=['a'], to_scope=[])])
        snap['rekey_triggers'] = [dict(seq=3, kind='full', reason='full_to_scoped_downgrade', projects=[]), dict(seq=4, kind='full', reason='full_to_scoped_downgrade', projects=[])]
        evidence = self.replay.view(snap).custody_evidence('founder', snap['head'])
        self.assertEqual(evidence['custody'], 'full')
        ent, stage, _ = self.rotation(snap=snap); ent['signer'] = signer
        self.replay.apply(ent, snap, stage=stage)
        snap['head']['seq'] = 5
        evidence = self.replay.view(snap).custody_evidence('founder', snap['head'])
        self.assertEqual(evidence['custody'], [])
        self.assertEqual(evidence['pending_downgrades'], [])
        self.assertEqual(evidence['covered_triggers'], [3, 4])
        self.assertEqual(evidence['full_custody_generation'], 1)

    def test_returned_state_cannot_mutate_replay(self):
        self.init()
        returned = self.replay.state
        returned['active_kek']['a'] = 'substitute'
        returned['epochs'].clear()
        self.assertEqual(self.replay.state['active_kek']['a'], 'ka')
        self.assertEqual(len(self.replay.state['epochs']), 1)

    def test_history_replays_current_rewrapped_blob_then_checks_latest_envelope(self):
        snap, ent, original = self.ciphertext()
        current = dict(original, kek_id='kb', wrapped_dek='33' * 48, dek_nonce='44' * 12)
        with self.assertRaises(PolicyError): self.replay.apply(ent, snap, blob=current)
        self.replay.apply(ent, snap, blob=current, mode='history')
        # A missing rewrap suffix must leave the current envelope unverified.
        with self.assertRaises(PolicyError): self.replay.verify_current_ciphertexts([current])
        snap['head']['seq'] = 4; rotate, stage, _ = self.rotation(snap=snap)
        self.replay.apply(rotate, snap, stage=stage)
        snap['head']['seq'] = 5
        target_digest = crypto.envelope_digest('kb', bytes.fromhex(current['wrapped_dek']), bytes.fromhex(current['dek_nonce']))
        item = dict(version_id='v', from_kek_id='ka', from_envelope_digest=ent['body']['envelope_digest'], to_kek_id='kb', to_envelope_digest=target_digest)
        self.replay.apply(entry('dek_rewrap', dict(epoch_seq=5, items=[item]), snap), snap)
        self.assertEqual(self.replay.verify_current_ciphertexts([current])[0]['kek_id'], 'kb')
        for rows in [[], [current, current], [original], [dict(current, ciphertext='ff' * 25)], [dict(current, wrapped_dek='55' * 48)]]:
            with self.subTest(rows=rows):
                with self.assertRaises(PolicyError): self.replay.verify_current_ciphertexts(rows)

    def test_history_never_defers_immutable_ciphertext_checks(self):
        snap, ent, blob = self.ciphertext()
        for field, value in [('ciphertext', 'cc' * 25), ('nonce', '11' * 12), ('secret_id', 'other'), ('version_id', 'other'), ('wrapped_dek', '00' * 47)]:
            with self.subTest(field=field):
                with self.assertRaises(PolicyError): self.replay.apply(ent, snap, blob=dict(blob, **{field: value}), mode='history')
        self.assertEqual(self.replay.state['versions'], [])

    def test_unknown_kinds_fail_closed(self):
        with self.assertRaises(PolicyError): self.replay.apply(entry('version_state', {}, self.snap), self.snap)


class ReferenceEpochBytesTests(unittest.TestCase):
    """Reference-only exports establish bytes, never production acceptance."""
    def traces(self):
        from tests.cloud_fixtures import paired_traces
        return [(name, document) for name, document in paired_traces()
                if '/broker-epoch-' in name]

    def test_all_reference_wire_bytes_and_signatures(self):
        traces = self.traces()
        self.assertEqual(len(traces), 3)
        for name, document in traces:
            self.assertEqual(document['profile'], 'reference_only')
            self.assertIs(document['production_acceptable'], False)
            keys = {}
            founder = document['records'][0]['entry']['body']['founder']
            keys[founder['key']] = crypto.unb64url(founder['sign_pub'])
            for record in document['records']:
                requested = record['entry']['body'].get('requested', {})
                cert = requested.get('certificate')
                if cert and requested['kind'] == 'member':
                    keys[cert['member_key_id']] = crypto.unb64url(cert['sign_pub'])
            rows = [(index, record) for index, record in enumerate(document['records'])]
            rows += [('case:' + case['id'], case['record']) for case in document['cases']]
            for index, record in rows:
                with self.subTest(file=name, index=index, kind=record['entry']['kind']):
                    raw = crypto.canonical_json(record['entry'])
                    self.assertEqual(raw.hex(), record['canonical_hex'])
                    expected_hash = crypto.sha256(raw).hex()
                    self.assertEqual(expected_hash, record['hash'])
                    signer_key = keys[record['entry']['signer']['key']]
                    valid = crypto.p256_verify(signer_key, crypto.policy_context(document['org_id'], expected_hash), crypto.unb64url(record['sig']))
                    self.assertEqual(valid, record['id'] != 'bad-signature')
                    # Signature validity above confers no policy authority.
                    if record['id'] == 'bad-signature':
                        self.assertEqual(record['expected']['status'], 'rejected')
                        self.assertEqual(record['expected']['code'], 'E_POLICY_CONFLICT')

    def test_reference_final_epoch_projection_and_commitment_bytes(self):
        for name, document in self.traces():
            with self.subTest(file=name):
                expected = document['final_state']['epoch']
                internal = copy.deepcopy(expected)
                internal['secrets'] = {}
                for version in internal['versions']:
                    version['value_digest'] = version.pop('ciphertext_digest')
                for epoch in internal['epochs']:
                    epoch['full_brokers'] = []
                if internal['pending']:
                    internal['pending']['stage'] = {'local_evidence': True}
                projected = epoch_checkpoint(internal)
                self.assertEqual(projected, expected)
                final_expected = document['records'][-1]['expected']
                self.assertEqual(hash_object(projected), final_expected['epoch_sha256'])
                values = [item for version in internal['versions'] for item in (dict(id='value:' + version['version_id'], digest=version['value_digest']), dict(id='envelope:' + version['version_id'], digest=version['envelope_digest']))]
                self.assertEqual(values + epoch_blob_commitments(internal), final_expected['commitments'])
                # The export explicitly has no production finalization verdict.
                self.assertIsNone(document['finalize_expected'])


if __name__ == '__main__':
    unittest.main()
