"""H1 acceptance predicates against old and corrected enrollment entry points.

All paths, keys and passphrases here are synthetic. No socket or live store.
The compatibility branch reaches the old public entry point before the fix,
and the broker entry point after it; a missing new API is not the red signal.
"""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tw import crypto
from tw.console_auth import ConsoleAuth, ConsoleDenied, PasskeyConfig, encode
from tw import console_setup

RP = "broker.fixture.ts.net"
USER = "human@example.test"
AGENT_CODE = "synthetic attacker chosen enrollment capability"
HUMAN_PASSPHRASE = "synthetic human knowledge factor for tests only"


class FixtureVault:
    """Synthetic knowledge verifier; no Argon2, Store.open or database IO."""
    def __init__(self, home):
        self.home = home
        self.calls = 0

    def meta(self, key):
        return "synthetic-store-id" if key == "store_id" else None

    def unlock_passphrase(self, value):
        self.calls += 1
        if value != HUMAN_PASSPHRASE:
            raise crypto.CryptoError("authentication failed")
        return b"S" * 32


def untrusted_config(path):
    path.write_text(json.dumps(dict(rp_id=RP, allowed_user=USER,
        user_id=encode(b"U" * 32), enrollment_digest=hashlib.sha256(AGENT_CODE.encode()).hexdigest(),
        credentials=[])))
    path.chmod(0o600)


class EnrollmentBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tw-console-h1-")
        self.home = Path(self.temp.name)
        self.directory = self.home / "console"
        self.directory.mkdir(mode=0o700)
        self.path = self.directory / "config.json"
        self.vault = FixtureVault(self.home)

    def tearDown(self):
        self.temp.cleanup()

    def test_agent_with_forged_tty_environment_cannot_prepare_enrollment(self):
        vault = self.vault
        class Client:
            def __init__(self, home):
                pass
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                pass
            def call(self, op, args, fds=None):
                # The old setup never calls the broker, so this is deliberately
                # unused in the red run. The fixed setup reaches the real gate.
                config = PasskeyConfig.for_broker(vault, RP, USER)
                try:
                    result = config.prepare_enrollment(args.get("passphrase", ""))
                    return {"ok": True, "result": result}
                except ConsoleDenied:
                    return {"ok": False, "code": "E_AUTH"}
        with mock.patch.dict("os.environ", {"SSH_CONNECTION": "forged by agent"}, clear=True), \
                mock.patch("os.isatty", return_value=True), \
                mock.patch("getpass.getpass", return_value=AGENT_CODE), \
                mock.patch("tw.admin.AdminClient", Client):
            with self.assertRaises(SystemExit):
                console_setup.main(["--rp-id", RP, "--user", USER, "--config", str(self.path)])
        self.assertFalse(self.path.exists())

    def test_config_not_created_by_broker_is_refused_at_load(self):
        untrusted_config(self.path)
        with self.assertRaises(ConsoleDenied):
            PasskeyConfig(self.path)

    def test_enrollment_without_vault_passphrase_is_refused(self):
        if hasattr(PasskeyConfig, "for_broker"):
            config = PasskeyConfig.for_broker(self.vault, RP, USER)
            with self.assertRaises(ConsoleDenied):
                config.prepare_enrollment("")
            self.assertEqual(self.vault.calls, 1)
            self.assertFalse(self.path.exists())
        else:
            untrusted_config(self.path)
            auth = ConsoleAuth(PasskeyConfig(self.path))
            _token, session = auth.new_session()
            with self.assertRaises(ConsoleDenied):
                auth.options(session, enroll=True, capability=AGENT_CODE)


if __name__ == "__main__":
    unittest.main()
