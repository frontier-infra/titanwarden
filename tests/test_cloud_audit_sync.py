"""V6 byte agreement plus TEST-ONLY single-fault receipt refusal inputs."""
import copy
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

from tw import crypto
from tw.cloud_audit import (AuditConflict, AuditSync, ReceiptPins, audit_row_hash,
    checkpoint, verify_checkpoint)
from tw.cloud_http import SignedClient
from tw.cloud_wire import load_pinned_json
from tw.store import Store

ORG = 'b' * 32
CHAIN = 'test-only-audit-broker'
NOW = '2026-10-16T00:00:00.000Z'
CUTOFF = '2026-10-17T00:00:00.000Z'
V6 = 'control/test/vectors/audit.json'
SHA256 = 'bae399778ce4aa6ec3c1439cc9ddfccda0121036e813aa7daf815689e926c616'


def vectors():
    root = Path(__file__).parent / 'fixtures/cloud/177766e1de71acbff0a188fa4d4b487db6c28391'
    return load_pinned_json(root / V6, SHA256)


class AuditSyncTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = Store(self.temporary.name).open(create=True)
        self.addCleanup(self.store.close)
        self.store.initialize_cloud_replay(ORG, 'a' * 64)
        # Public test-only receipt and broker AK keys. Never release pins.
        self.ak = ec.derive_private_key(101, ec.SECP256R1())
        self.receipt_key = ec.derive_private_key(103, ec.SECP256R1())
        self.ak_public = crypto.export_point(self.ak.public_key())
        self.cloud_public = crypto.export_point(self.receipt_key.public_key())
        self.pins = ReceiptPins('TEST-ONLY-current', self.cloud_public,
            retained=[('TEST-ONLY-retired', self.cloud_public, CUTOFF)])
        self.rows = [v['row'] for v in vectors()['vectors']]
        self.expected = checkpoint(ORG, CHAIN, {k:self.rows[-1][k] for k in ('seq', 'hash')}, NOW, self.ak)
        self.receipt = self.sign_receipt(self.expected)
        self.sync = AuditSync(self.store, ORG, CHAIN, self.pins, broker_public=self.ak_public)

    def sign_receipt(self, expected, *, chain=CHAIN, key_id='TEST-ONLY-current', issued_at=NOW):
        value = dict(expected, key_id=key_id, issued_at=issued_at)
        message = crypto.checkpoint_context(ORG, chain, value['seq'], value['hash'], value['ts'], True, value['sig'], key_id, issued_at)
        return dict(value, receipt_sig=crypto.b64url(crypto.p256_sign(self.receipt_key, message)))

    def test_v6_exact_canonical_bytes_digests_and_provenance(self):
        doc = vectors()
        self.assertEqual(doc['source_commit'], '703cb50a8488c842132b226a96da9c32bf96ee7d')
        self.assertEqual(set(doc['source_sha256']), {'tw/audit.py', 'tw/schema.sql', 'tw/store.py'})
        self.assertEqual(len(doc['vectors']), 3)
        for vector in doc['vectors']:
            row = vector['row']
            canonical = {k:v for k,v in row.items() if k not in ('hash', 'mac')}
            self.assertEqual(crypto.canonical_json(canonical).hex(), vector['canonical_hex'])
            self.assertEqual(audit_row_hash(row), row['hash'])

    def test_receipt_acceptance_is_atomic_durable_idempotent_and_append_only(self):
        result = self.sync.accept(self.rows, self.expected, self.receipt, observed_at=NOW)
        self.assertEqual(result['assertion'], 'broker_signed')
        self.store.close()
        self.store.open()
        self.assertEqual(self.sync.retained(), {k:self.expected[k] for k in ('seq', 'hash')})
        self.sync.accept([], self.expected, self.receipt, observed_at=NOW)
        for table in ('cloud_audit_rows', 'cloud_audit_receipts'):
            with self.assertRaises(sqlite3.IntegrityError):
                self.store.connection.execute('DELETE FROM ' + table)
            with self.assertRaises(sqlite3.IntegrityError):
                self.store.connection.execute('UPDATE ' + table + ' SET seq=seq')

    def test_each_checkpoint_and_receipt_binding_rejects_without_retaining(self):
        for field, value in [('seq', 2), ('hash', '1' * 64), ('ts', CUTOFF), ('sig', crypto.b64url(bytes(64))), ('key_id', 'attacker-selected'), ('issued_at', CUTOFF), ('receipt_sig', crypto.b64url(bytes(64)))]:
            receipt = dict(self.receipt, **{field: value})
            with self.subTest(field=field), self.assertRaises((AuditConflict, ValueError)):
                self.sync.accept(self.rows, self.expected, receipt, observed_at=NOW)
            self.assertEqual(self.sync.retained(), dict(seq=0, hash='0' * 64))
        with self.assertRaises(AuditConflict):
            self.pins.verify(ORG, 'other-chain', self.expected, self.receipt)
        with self.assertRaises(AuditConflict):
            self.pins.verify('c' * 32, CHAIN, self.expected, self.receipt)

    def test_valid_cloud_signature_over_different_original_tuple_refuses(self):
        changed = dict(self.expected, ts=CUTOFF)
        signed = self.sign_receipt(changed)
        with self.assertRaisesRegex(AuditConflict, 'original checkpoint'):
            self.pins.verify(ORG, CHAIN, self.expected, signed)

    def test_retirement_uses_authenticated_issued_at_exclusive_cutoff(self):
        for issued_at, accepted in [('2026-10-16T23:59:59.999Z', True), (CUTOFF, False)]:
            receipt = self.sign_receipt(self.expected, key_id='TEST-ONLY-retired', issued_at=issued_at)
            if accepted:
                self.pins.verify(ORG, CHAIN, self.expected, receipt)
            else:
                with self.assertRaisesRegex(AuditConflict, 'retirement'):
                    self.pins.verify(ORG, CHAIN, self.expected, receipt)
        with self.assertRaisesRegex(AuditConflict, 'duplicate'):
            ReceiptPins('same', self.cloud_public, retained=[('same', self.cloud_public, CUTOFF)])

    def test_lost_suffix_reordered_edited_and_dropped_history_refuse(self):
        variants = [self.rows[::-1], self.rows[:-1], [dict(self.rows[0], op='edited')] + self.rows[1:], [dict(self.rows[0], prev_hash='1' * 64)] + self.rows[1:]]
        for rows in variants:
            with self.subTest(rows=rows), self.assertRaises(AuditConflict):
                self.sync.accept(rows, self.expected, self.receipt, observed_at=NOW)
        self.sync.accept(self.rows, self.expected, self.receipt, observed_at=NOW)
        older = checkpoint(ORG, CHAIN, {k:self.rows[0][k] for k in ('seq', 'hash')}, NOW, self.ak)
        with self.assertRaisesRegex(AuditConflict, 'suffix'):
            self.sync.accept([], older, self.sign_receipt(older), observed_at=NOW)

    def test_broker_checkpoint_signature_and_control_assertion_are_separate(self):
        with self.assertRaisesRegex(AuditConflict, 'signature'):
            verify_checkpoint(ORG, CHAIN, dict(self.expected, sig=crypto.b64url(bytes(64))), self.ak_public)
        value = dict(self.expected, sig=None)
        receipt = self.sign_receipt(value, chain='control')
        control = AuditSync(self.store, ORG, 'control', self.pins)
        self.assertEqual(control.accept(self.rows, value, receipt, observed_at=NOW)['assertion'], 'cloud_asserted')
        with self.assertRaisesRegex(AuditConflict, 'cloud assertion'):
            verify_checkpoint(ORG, 'control', self.expected, None)
        with self.assertRaisesRegex(AuditConflict, 'assertion differs'):
            self.pins.verify(ORG, CHAIN, value, receipt)

    def test_row_schema_types_flags_identity_and_hash_are_checked(self):
        for field, value in [('event_id', ''), ('op', 2), ('context_verified', 2), ('seq', True), ('ts', 'not-time'), ('hash', 'invalid')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                audit_row_hash(dict(self.rows[0], **{field:value}))
        with self.assertRaises(ValueError):
            audit_row_hash(dict(self.rows[0], unknown='field'))

    def test_push_matches_cloud_sync_audit_wire_and_is_one_attempt(self):
        sent = []
        client = SignedClient(ORG, CHAIN, self.ak, clock=lambda: NOW, transport=lambda req: sent.append(req) or {'accepted_through_seq':3})
        self.sync.push(client, 'https://test.invalid', self.rows, self.expected)
        self.assertEqual(len(sent), 1)
        self.assertTrue(sent[0].url.endswith('/sync/audit'))
        self.assertEqual(crypto.parse_canonical(sent[0].body), dict(chain_id=CHAIN, events=self.rows, checkpoint=self.expected))
        with self.assertRaisesRegex(AuditConflict, 'batch limit'):
            self.sync.push(client, 'https://test.invalid', [], self.expected)
        client.broker = 'other'
        with self.assertRaisesRegex(AuditConflict, 'identity'):
            self.sync.push(client, 'https://test.invalid', self.rows, self.expected)

    def test_empty_checkpoints_and_unconfigured_release_pins_refuse(self):
        with self.assertRaisesRegex(AuditConflict, 'nonempty'):
            checkpoint(ORG, CHAIN, dict(seq=0, hash='0' * 64), NOW, self.ak)
        value = dict(seq=0, hash='0' * 64, ts=NOW)
        value['sig'] = crypto.b64url(crypto.p256_sign(self.ak, crypto.checkpoint_context(ORG, CHAIN, 0, '0' * 64, NOW)))
        with self.assertRaisesRegex(AuditConflict, 'empty audit'):
            verify_checkpoint(ORG, CHAIN, value, self.ak_public)
        with self.assertRaisesRegex(AuditConflict, 'pins required'):
            AuditSync(self.store, ORG, CHAIN, object())

    def test_null_broker_assertion_with_valid_cloud_signature_refuses(self):
        expected = dict(self.expected, sig=None)
        signed = self.sign_receipt(expected)
        with self.assertRaisesRegex(AuditConflict, 'chain assertion'):
            self.pins.verify(ORG, CHAIN, expected, signed)

    def test_validly_signed_wrong_audit_head_and_reissued_receipt_refuse(self):
        expected = checkpoint(ORG, CHAIN, dict(seq=3, hash='1' * 64), NOW, self.ak)
        with self.assertRaisesRegex(AuditConflict, 'head differs'):
            self.sync.accept(self.rows, expected, self.sign_receipt(expected), observed_at=NOW)
        self.sync.accept(self.rows, self.expected, self.receipt, observed_at=NOW)
        new_receipt = self.sign_receipt(self.expected, issued_at='2026-10-16T00:00:01.000Z')
        with self.assertRaisesRegex(AuditConflict, 'retained audit receipt differs'):
            self.sync.accept([], self.expected, new_receipt, observed_at=NOW)

    def test_audit_concurrent_retained_head_change_refuses(self):
        from unittest.mock import patch
        initial = dict(seq=0, hash='0' * 64)
        changed = dict(seq=1, hash=self.rows[0]['hash'])
        with (patch.object(self.sync, 'retained', side_effect=[initial, changed]),
              self.assertRaisesRegex(AuditConflict, 'retained head changed')):
            self.sync.accept(self.rows, self.expected, self.receipt, observed_at=NOW)


if __name__ == '__main__':
    unittest.main()
