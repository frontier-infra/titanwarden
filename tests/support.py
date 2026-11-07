from __future__ import annotations

import tempfile
from pathlib import Path

from tw import crypto
from tw.store import Store


TEST_PASSPHRASE = "correct horse battery staple with seven words"
TEST_ARGON2 = crypto.Argon2Params(memory_kib=8192, iterations=1, lanes=1)


def initialized_store() -> tuple[tempfile.TemporaryDirectory[str], Store, bytes, str]:
    temporary = tempfile.TemporaryDirectory(prefix="tw", dir="/tmp")
    store = Store(Path(temporary.name)).open(create=True)
    master, recovery = store.initialize(TEST_PASSPHRASE, argon2=TEST_ARGON2)
    return temporary, store, master, recovery

