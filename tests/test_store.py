from __future__ import annotations

import base64
import os
import tempfile
import threading
import unittest
from pathlib import Path

from tw import crypto
from tw.store import Store, StoreError

from support import initialized_store


class StoreTests(unittest.TestCase):
    def test_modes_and_keyring(self) -> None:
        temporary, store, master, _recovery = initialized_store()
        self.addCleanup(temporary.cleanup)
        self.addCleanup(store.close)
        self.assertEqual(os.stat(store.home).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(store.db_path).st_mode & 0o777, 0o600)
        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{store.db_path}{suffix}")
            self.assertTrue(sidecar.exists())
            self.assertEqual(os.stat(sidecar).st_mode & 0o777, 0o600)
        self.assertEqual(set(store.load_keyring(master)), {"kek", "audit_mac", "fingerprint"})

    def test_receipt_is_stable(self) -> None:
        temporary, store, _master, _recovery = initialized_store()
        self.addCleanup(temporary.cleanup)
        self.addCleanup(store.close)
        response = {"path": "test/name", "version_no": 1}
        store.save_receipt("request", "put", "master", response)
        self.assertEqual(store.receipt("request"), response)

    def test_receipt_is_bound_to_operation_and_principal(self) -> None:
        temporary, store, _master, _recovery = initialized_store()
        self.addCleanup(temporary.cleanup)
        self.addCleanup(store.close)
        response = {"path": "test/name", "version_no": 1}
        store.save_receipt("bound", "put", "lead:alpha", response)
        self.assertEqual(
            store.receipt("bound", op="put", principal_id="lead:alpha"), response
        )
        with self.assertRaises(StoreError):
            store.receipt("bound", op="generate", principal_id="lead:alpha")
        with self.assertRaises(StoreError):
            store.receipt("bound", op="put", principal_id="lead:beta")

    def test_plaintext_not_in_database_after_checkpoint(self) -> None:
        temporary, store, master, _recovery = initialized_store()
        self.addCleanup(temporary.cleanup)
        self.addCleanup(store.close)
        value = b"forty-byte-test-canary-1234567890-abcdef"
        keys = store.load_keyring(master)
        store.put_secret(
            "infra/at-rest-test", value, keyring=keys, principal_id="human:operator"
        )
        store.checkpoint()
        encodings = (
            value,
            base64.b64encode(value),
            value.hex().encode("ascii"),
            master,
        )
        for path in store.home.rglob("*"):
            if path.is_file():
                content = path.read_bytes()
                for encoding in encodings:
                    self.assertNotIn(encoding, content)

    def test_put_reveal_and_version_grace(self) -> None:
        temporary, store, master, _recovery = initialized_store()
        self.addCleanup(temporary.cleanup)
        self.addCleanup(store.close)
        keys = store.load_keyring(master)
        first = store.put_secret(
            "infra/example", b"first-long-value", keyring=keys, principal_id="human:operator"
        )
        second = store.put_secret(
            "infra/example", b"second-long-value", keyring=keys, principal_id="human:operator"
        )
        self.assertEqual(first["version_no"], 1)
        self.assertEqual(second["version_no"], 2)
        self.assertEqual(store.reveal_secret("infra/example", keyring=keys), b"second-long-value")
        states = store.connection.execute(
            "SELECT version_no,state FROM secret_versions ORDER BY version_no"
        ).fetchall()
        self.assertEqual([(row[0], row[1]) for row in states], [(1, "grace"), (2, "active")])

    def test_client_policy_forces_restricted_and_class_is_immutable(self) -> None:
        temporary, store, master, _recovery = initialized_store()
        self.addCleanup(temporary.cleanup)
        self.addCleanup(store.close)
        keys = store.load_keyring(master)
        store.connection.execute(
            "INSERT INTO projects(slug,change_policy,created_at) "
            "VALUES ('client','client_approval_required','now')"
        )
        store.put_secret(
            "client/client-key",
            b"first-long-secret",
            keyring=keys,
            principal_id="human:operator",
            secret_class="standard",
        )
        row = store.connection.execute(
            "SELECT class FROM secrets WHERE path='client/client-key'"
        ).fetchone()
        self.assertEqual(row[0], "restricted")
        store.connection.execute(
            "INSERT INTO projects(slug,change_policy,created_at) "
            "VALUES ('alpha','auto','now')"
        )
        store.put_secret(
            "alpha/fixed-class",
            b"original-sensitive",
            keyring=keys,
            principal_id="human:operator",
            secret_class="sensitive",
        )
        with self.assertRaises(StoreError):
            store.put_secret(
                "alpha/fixed-class",
                b"replacement-secret",
                keyring=keys,
                principal_id="human:operator",
                secret_class="standard",
            )

    def test_slot_rotation_disables_old_slot(self) -> None:
        temporary, store, master, recovery = initialized_store()
        self.addCleanup(temporary.cleanup)
        self.addCleanup(store.close)
        store.change_passphrase(
            master,
            "another correct horse battery staple phrase",
            argon2=crypto.Argon2Params(memory_kib=8192, iterations=1, lanes=1),
        )
        with self.assertRaises(crypto.CryptoError):
            store.unlock_passphrase("correct horse battery staple with seven words")
        self.assertEqual(
            store.unlock_passphrase("another correct horse battery staple phrase"), master
        )
        new_recovery = store.rotate_recovery(master)
        with self.assertRaises(crypto.CryptoError):
            store.unlock_recovery(recovery)
        self.assertEqual(store.unlock_recovery(new_recovery), master)

    def test_transactions_are_serialized_across_socket_threads(self) -> None:
        temporary, store, _master, _recovery = initialized_store()
        self.addCleanup(temporary.cleanup)
        self.addCleanup(store.close)
        errors: list[BaseException] = []

        def writer(index: int) -> None:
            try:
                with store.transaction(immediate=True) as connection:
                    connection.execute(
                        "INSERT INTO meta(key,value) VALUES (?,?)",
                        (f"thread-{index}", str(index)),
                    )
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(index,)) for index in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        count = store.connection.execute(
            "SELECT COUNT(*) FROM meta WHERE key LIKE 'thread-%'"
        ).fetchone()[0]
        self.assertEqual(count, 16)

    def test_put_increments_active_kek_wrap_count(self) -> None:
        temporary, store, master, _recovery = initialized_store()
        self.addCleanup(temporary.cleanup)
        self.addCleanup(store.close)
        keys = store.load_keyring(master)
        store.put_secret("infra/one", b"first-secret", keyring=keys, principal_id="human:operator")
        store.put_secret("infra/two", b"second-secret", keyring=keys, principal_id="human:operator")
        count = store.connection.execute(
            "SELECT wrap_count FROM keyring WHERE purpose='kek' AND state='active'"
        ).fetchone()[0]
        self.assertEqual(count, 2)

    def test_refuse_create_flag_protects_an_existing_home(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="tw", dir="/tmp")
        self.addCleanup(temporary.cleanup)
        with self.assertRaises(StoreError):
            Store(temporary.name).open(create=True, refuse_create=True)

    def test_fresh_home_without_tombstone_can_create_and_leaves_tombstone(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="tw", dir="/tmp")
        self.addCleanup(temporary.cleanup)
        home = Path(temporary.name)
        (home / "state").mkdir(mode=0o700)
        store = Store(home).open(create=True, refuse_create=False)
        self.addCleanup(store.close)
        tombstone = home / "state" / ".store-created"
        self.assertTrue(tombstone.exists())
        self.assertEqual(tombstone.stat().st_mode & 0o777, 0o600)

    def test_broker_refuses_to_recreate_a_deleted_store(self) -> None:
        from tw.broker import Broker

        temporary = tempfile.TemporaryDirectory(prefix="tw", dir="/tmp")
        self.addCleanup(temporary.cleanup)
        home = Path(temporary.name)
        Store(home).open(create=True).close()
        (home / "state" / "tw.db").unlink()
        with self.assertRaises(StoreError):
            Broker(home)

    def test_backup_is_limited_to_home_or_named_allowlist(self) -> None:
        temporary, store, _master, _recovery = initialized_store()
        self.addCleanup(temporary.cleanup)
        self.addCleanup(store.close)
        with self.assertRaises(StoreError):
            store.backup(Path(temporary.name).parent / "outside.db")
        internal = store.backup(store.home / "backups" / "inside.db")
        self.assertTrue(internal.exists())
        allowed = tempfile.TemporaryDirectory(prefix="tw-backup", dir="/tmp")
        self.addCleanup(allowed.cleanup)
        other = Store(store.home, backup_allowlist=[allowed.name])
        other._connection = store.connection
        external = other.backup(Path(allowed.name) / "named.db")
        self.assertTrue(external.exists())


if __name__ == "__main__":
    unittest.main()

