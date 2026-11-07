from __future__ import annotations

import ast
import tempfile
import unittest
from pathlib import Path

from tw import crypto
from tw.store import Store

from support import TEST_ARGON2, TEST_PASSPHRASE, initialized_store


class CryptoTests(unittest.TestCase):
    def test_round_trip_and_wrong_aad(self) -> None:
        key = crypto.random_key()
        ciphertext, nonce = crypto.encrypt(key, b"canary", b"correct")
        self.assertEqual(crypto.decrypt(key, ciphertext, nonce, b"correct"), b"canary")
        with self.assertRaises(crypto.CryptoError):
            crypto.decrypt(key, ciphertext, nonce, b"wrong")

    def test_slot_round_trips(self) -> None:
        temporary, store, master, recovery = initialized_store()
        self.addCleanup(temporary.cleanup)
        self.addCleanup(store.close)
        self.assertEqual(store.unlock_passphrase(TEST_PASSPHRASE), master)
        self.assertEqual(store.unlock_recovery(recovery), master)
        with self.assertRaises(crypto.CryptoError):
            store.unlock_passphrase("wrong")

    def test_production_parameters(self) -> None:
        params = crypto.Argon2Params()
        self.assertEqual(params.memory_kib, 1_048_576)
        self.assertEqual(params.iterations, 3)
        self.assertEqual(params.lanes, 4)
        self.assertEqual(TEST_ARGON2.memory_kib, 8192)

    def test_passphrase_strength(self) -> None:
        with self.assertRaises(ValueError):
            crypto.derive_passphrase_key("short", bytes(16), TEST_ARGON2)

    def test_init_rejects_short_passphrase(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="tw", dir="/tmp")
        self.addCleanup(temporary.cleanup)
        store = Store(temporary.name).open(create=True)
        self.addCleanup(store.close)
        with self.assertRaises(ValueError):
            store.initialize("short", argon2=TEST_ARGON2)

    def test_only_crypto_imports_cryptography(self) -> None:
        root = Path(__file__).parents[1] / "tw"
        offenders: list[str] = []
        for path in root.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                if any(name == "cryptography" or name.startswith("cryptography.") for name in names):
                    if path.name != "crypto.py":
                        offenders.append(path.name)
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()

