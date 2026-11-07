from __future__ import annotations

import threading
import time
import unittest
from unittest import mock

from tw.audit import AuditLog
from tw.seal import SealError, SealManager

from support import TEST_PASSPHRASE, initialized_store


class SealTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary, self.store, _master, _recovery = initialized_store()
        self.seal = SealManager(self.store)

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def test_starts_sealed_and_unseals(self) -> None:
        self.assertEqual(self.seal.state, "sealed")
        with self.assertRaises(SealError):
            self.seal.check_agent_operation("run")
        self.seal.unseal(TEST_PASSPHRASE)
        self.assertEqual(self.seal.state, "unsealed")
        keys = self.seal.keys
        assert keys is not None
        key_buffers = (keys.master, keys.kek, keys.audit, keys.fingerprint)
        self.seal.seal()
        self.assertEqual(self.seal.state, "sealed")
        self.assertTrue(all(not any(value) for value in key_buffers))

    def test_five_wrong_attempts_rate_limit(self) -> None:
        for _ in range(5):
            with self.assertRaisesRegex(SealError, "unseal failed"):
                self.seal.unseal("wrong")
        with self.assertRaisesRegex(SealError, "too many"):
            self.seal.unseal(TEST_PASSPHRASE)

    def test_freeze_latches(self) -> None:
        self.seal.unseal(TEST_PASSPHRASE)
        self.seal.freeze()
        self.seal.freeze_path.unlink()
        with self.assertRaisesRegex(SealError, "frozen"):
            self.seal.check_agent_operation("run")
        self.seal.unfreeze()
        self.seal.check_agent_operation("run")

    def test_lockdown_requires_passphrase_clear(self) -> None:
        self.seal.lockdown()
        self.assertEqual(self.seal.state, "lockdown")
        with self.assertRaisesRegex(SealError, "lockdown"):
            self.seal.unseal(TEST_PASSPHRASE)
        self.seal.clear_lockdown(TEST_PASSPHRASE)
        self.assertEqual(self.seal.state, "unsealed")

    def test_unseal_verifies_before_attesting_unsigned_rows(self) -> None:
        AuditLog(self.store).append(
            event_id="evt_injected", op="run", decision="deny", sealed_tail=False
        )
        with mock.patch.object(self.store, "load_keyring", wraps=self.store.load_keyring) as load:
            with self.assertRaisesRegex(SealError, "audit verification"):
                self.seal.unseal(TEST_PASSPHRASE)
        load.assert_not_called()
        self.assertEqual(self.seal.state, "lockdown")
        self.assertIsNone(self.seal.keys)
        self.assertIsNone(
            self.store.connection.execute(
                "SELECT 1 FROM audit_events WHERE op='tail_attest'"
            ).fetchone()
        )

    def test_authentication_work_is_serialized(self) -> None:
        original = self.store.unlock_passphrase
        active = 0
        maximum = 0
        guard = threading.Lock()

        def observed(passphrase: str) -> bytes:
            nonlocal active, maximum
            with guard:
                active += 1
                maximum = max(maximum, active)
            try:
                time.sleep(0.02)
                return original(passphrase)
            finally:
                with guard:
                    active -= 1

        errors: list[SealError] = []

        def attempt() -> None:
            try:
                self.seal.unseal("wrong")
            except SealError as exc:
                errors.append(exc)

        with mock.patch.object(self.store, "unlock_passphrase", side_effect=observed):
            threads = [threading.Thread(target=attempt) for _ in range(4)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        self.assertEqual(len(errors), 4)
        self.assertEqual(maximum, 1)


if __name__ == "__main__":
    unittest.main()
