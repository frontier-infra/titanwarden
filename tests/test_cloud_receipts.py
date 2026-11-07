from __future__ import annotations

import json
import unittest

from tw import crypto as c


class ReceiptContextTests(unittest.TestCase):
    def setUp(self) -> None:
        self.digest = "b" * 64
        self.ts = "2026-10-16T00:04:59.000Z"
        self.issued_at = "2026-10-16T00:00:00.000Z"

    def test_broker_ack_bytes_are_unchanged(self) -> None:
        self.assertEqual(
            c.checkpoint_context("org", "broker", 3, self.digest, self.ts),
            f"tw2|ack|org|broker|3|{self.digest}|{self.ts}".encode(),
        )

    def test_receipt_uses_canonical_evidence_and_distinct_server_time(self) -> None:
        encoded = c.checkpoint_context(
            "org", "broker", 3, self.digest, self.ts, True,
            "AQID", "release-1", self.issued_at,
        )
        expected = (
            'tw2|rcpt|org|broker|{"hash":"' + self.digest
            + '","issued_at":"2026-10-16T00:00:00.000Z","key_id":"release-1",'
            '"seq":3,"sig":"AQID","ts":"2026-10-16T00:04:59.000Z"}'
        ).encode()
        self.assertEqual(encoded, expected)

    def test_control_receipt_has_no_broker_signature(self) -> None:
        encoded = c.checkpoint_context(
            "org", "control", 3, self.digest, self.ts, True,
            None, "release-1", self.issued_at,
        )
        prefix = b"tw2|rcpt|org|control|"
        self.assertTrue(encoded.startswith(prefix))
        self.assertIsNone(json.loads(encoded[len(prefix):])["sig"])

    def test_legacy_and_incomplete_receipt_contexts_fail_closed(self) -> None:
        for suffix in [
            (True,),
            (True, "AQID", "", self.issued_at),
            (True, "AQID", "release-1", ""),
            (True, 4, "release-1", self.issued_at),
            (False, "AQID", "release-1", self.issued_at),
            (1,),
        ]:
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                c.checkpoint_context("org", "broker", 3, self.digest, self.ts, *suffix)

    def test_cloud_signature_authenticates_checkpoint_and_issuance_fields(self) -> None:
        broker, cloud = c.generate_p256_key(), c.generate_p256_key()
        ack = c.checkpoint_context("org", "broker", 3, self.digest, self.ts)
        broker_sig = c.p256_sign(broker, ack)
        self.assertTrue(c.p256_verify(c.export_point(broker.public_key()), ack, broker_sig))
        args = ["org", "broker", 3, self.digest, self.ts, True,
                c.b64url(broker_sig), "release-1", self.issued_at]
        message = c.checkpoint_context(*args)
        signature = c.p256_sign(cloud, message)
        point = c.export_point(cloud.public_key())
        self.assertTrue(c.p256_verify(point, message, signature))
        for index, value in [
            (0, "foreign"), (1, "another"), (2, 4), (3, "c" * 64),
            (4, "2026-10-16T00:05:00.000Z"), (6, "AQID"),
            (7, "release-2"), (8, "2026-10-15T23:59:59.999Z"),
        ]:
            changed = list(args)
            changed[index] = value
            with self.subTest(field=index):
                self.assertFalse(c.p256_verify(point, c.checkpoint_context(*changed), signature))
