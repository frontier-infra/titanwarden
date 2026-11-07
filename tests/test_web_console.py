"""New-console-only fixtures. No live home, Store.open, broker or Argon2."""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from webauthn.helpers.encode_cbor import encode_cbor

from tw import crypto
from tw.console import (COOKIE, ConsoleApplication, ConsoleServer, login_page,
                        vault_page)
from tw.console_auth import (ConsoleAuth, ConsoleDenied, Credential, PasskeyConfig,
                             decode, encode)
from tw.console_metadata import ConsoleMetadata
from test_console_enrollment_boundary import FixtureVault, HUMAN_PASSPHRASE

RP = "broker.fixture.ts.net"
USER = "human@example.test"
CAPABILITY = "synthetic enrollment capability never used outside tests"


def config_file(root: Path, *, enrolled=False):
    key = crypto.generate_p256_key()
    point = crypto.export_point(key.public_key())
    cose = encode_cbor({1: 2, 3: -7, -1: 1, -2: point[1:33], -3: point[33:]})
    credential_id = b"synthetic-credential-id"
    config = PasskeyConfig.for_broker(FixtureVault(root), RP, USER)
    result = config.prepare_enrollment(HUMAN_PASSPHRASE)
    config.test_capability = result["enrollment_code"]
    if enrolled:
        config.credentials = [Credential(encode(credential_id), encode(cose), 0)]
        config.enrollment_digest = None
        config.save()
    return config, key, cose, credential_id


def reload_config(config):
    loaded = PasskeyConfig.for_broker(config.store, RP, USER)
    loaded.prepare_enrollment(HUMAN_PASSPHRASE)
    return loaded


def client_data(challenge, *, origin=None, kind="webauthn.get", cross=False):
    return json.dumps(dict(type=kind, challenge=encode(challenge), origin=origin or "https://" + RP,
                           crossOrigin=cross), separators=(",", ":")).encode()


def assertion(key, credential_id, challenge, *, origin=None, flags=5, counter=1, cross=False):
    data = client_data(challenge, origin=origin, cross=cross)
    auth_data = hashlib.sha256(RP.encode()).digest() + bytes([flags]) + counter.to_bytes(4, "big")
    signature = crypto.p256_sign(key, auth_data + hashlib.sha256(data).digest())
    der = crypto.utils.encode_dss_signature(int.from_bytes(signature[:32], "big"),
                                          int.from_bytes(signature[32:], "big"))
    return dict(id=encode(credential_id), rawId=encode(credential_id), type="public-key",
                response=dict(clientDataJSON=encode(data), authenticatorData=encode(auth_data),
                              signature=encode(der), userHandle=None))


class ConsoleAuthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tw-console-test-")
        self.config, self.key, self.cose, self.credential_id = config_file(Path(self.temp.name), enrolled=True)
        self.now = 100.0
        self.auth = ConsoleAuth(self.config, clock=lambda: self.now)

    def tearDown(self):
        self.temp.cleanup()

    def test_real_signed_assertion_and_persisted_counter(self):
        _, session = self.auth.new_session()
        self.auth.options(session)
        credential = assertion(self.key, self.credential_id, session.challenge)
        self.auth.verify(session, credential)
        self.assertEqual(reload_config(self.config).credentials[0].sign_count, 1)
        self.assertIsNone(session.challenge)

    def test_wrong_origin_user_presence_verification_and_signature_reject(self):
        for changes in ({"origin": "https://evil.example"}, {"flags": 1}, {"flags": 4}, {"cross": True}):
            with self.subTest(changes=changes):
                _, session = self.auth.new_session()
                self.auth.options(session)
                with self.assertRaises(ConsoleDenied):
                    self.auth.verify(session, assertion(self.key, self.credential_id, session.challenge, **changes))
        _, session = self.auth.new_session()
        self.auth.options(session)
        other = crypto.generate_p256_key()
        with self.assertRaises(ConsoleDenied):
            self.auth.verify(session, assertion(other, self.credential_id, session.challenge))

    def test_challenge_is_single_use_and_expires(self):
        _, session = self.auth.new_session()
        self.auth.options(session)
        credential = assertion(self.key, self.credential_id, session.challenge)
        self.auth.verify(session, credential)
        with self.assertRaises(ConsoleDenied):
            self.auth.verify(session, credential)
        _, session = self.auth.new_session()
        self.auth.options(session)
        credential = assertion(self.key, self.credential_id, session.challenge, counter=2)
        self.now += 120
        with self.assertRaises(ConsoleDenied):
            self.auth.verify(session, credential)

    def test_unknown_credential_and_counter_replay_fail_closed(self):
        _, session = self.auth.new_session()
        self.auth.options(session)
        with self.assertRaises(ConsoleDenied):
            self.auth.verify(session, assertion(self.key, b"unknown", session.challenge))
        self.config.credentials[0].sign_count = 2
        _, session = self.auth.new_session()
        self.auth.options(session)
        with self.assertRaises(ConsoleDenied):
            self.auth.verify(session, assertion(self.key, self.credential_id, session.challenge, counter=1))

    def test_session_is_fifteen_minutes_without_sliding_extension(self):
        token, session = self.auth.new_session(authenticated=True)
        self.now = 999.0
        self.assertIs(self.auth.session(token, authenticated=True), session)
        self.now = 1000.0
        with self.assertRaises(ConsoleDenied):
            self.auth.session(token, authenticated=True)
        _, preauth = self.auth.new_session()
        with self.assertRaises(ConsoleDenied):
            self.auth.csrf(preauth, "wrong")

    def test_enrollment_requires_capability_and_verifies_real_attestation(self):
        root = Path(self.temp.name) / "fresh-broker"
        root.mkdir(mode=0o700)
        self.config, self.key, self.cose, self.credential_id = config_file(root, enrolled=False)
        self.auth = ConsoleAuth(self.config, clock=lambda: self.now)
        capability = self.config.test_capability
        _, session = self.auth.new_session()
        with self.assertRaises(ConsoleDenied):
            self.auth.options(session, enroll=True, capability="incorrect")
        self.auth.options(session, enroll=True, capability=capability)
        client = client_data(session.challenge, kind="webauthn.create")
        auth_data = (hashlib.sha256(RP.encode()).digest() + b"\x45" + b"\x00" * 4 + b"\x00" * 16
                     + len(self.credential_id).to_bytes(2, "big") + self.credential_id + self.cose)
        attestation = encode_cbor({"fmt": "none", "attStmt": {}, "authData": auth_data})
        credential = dict(id=encode(self.credential_id), rawId=encode(self.credential_id), type="public-key",
                          response=dict(clientDataJSON=encode(client), attestationObject=encode(attestation)))
        self.auth.verify(session, credential, enroll=True)
        saved = reload_config(self.config)
        self.assertIsNone(saved.enrollment_digest)
        self.assertEqual(saved.credentials[0].id, encode(self.credential_id))
        self.assertNotIn(capability, self.config.path.read_text())
        with self.assertRaises(ConsoleDenied):
            self.auth.options(session, enroll=True, capability=capability)

    def test_rate_and_session_inventory_are_bounded(self):
        _, session = self.auth.new_session()
        for _ in range(10):
            self.auth.options(session)
        with self.assertRaises(ConsoleDenied):
            self.auth.options(session)
        for _ in range(self.auth.MAX_SESSIONS - 1):
            self.auth.new_session()
        with self.assertRaises(ConsoleDenied):
            self.auth.new_session()

    def test_configuration_rejects_lan_public_host_and_world_readability(self):
        for host in ("192.0.2.10", "localhost", "example.com", "broker.fixture.ts.net/evil"):
            with self.assertRaises(ConsoleDenied):
                PasskeyConfig.for_broker(self.config.store, host, USER)
        self.config.path.chmod(0o644)
        with self.assertRaises(ConsoleDenied):
            PasskeyConfig.for_broker(self.config.store, RP, USER)


class ConsoleProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tw-console-provenance-")
        self.root = Path(self.temp.name).resolve()
        self.config, _, _, _ = config_file(self.root, enrolled=True)

    def tearDown(self):
        self.config.close()
        self.temp.cleanup()

    def test_broker_file_is_authenticated_and_not_caller_selected(self):
        text = self.config.path.read_text()
        self.assertNotIn(HUMAN_PASSPHRASE, text)
        self.assertNotIn(self.config.credentials[0].public_key, text)
        self.assertEqual(self.config.path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(ConsoleDenied):
            PasskeyConfig.for_broker(self.config.store, RP, USER, expected_path=self.root / "other.json")
        with self.assertRaises(ConsoleDenied):
            PasskeyConfig(self.config.path)

    def test_restart_requires_passphrase_even_with_preexisting_passkey(self):
        loaded = PasskeyConfig.for_broker(self.config.store, RP, USER)
        self.assertFalse(loaded.active)
        auth = ConsoleAuth(loaded)
        _, session = auth.new_session()
        with self.assertRaises(ConsoleDenied):
            auth.options(session)
        result = loaded.prepare_enrollment(HUMAN_PASSPHRASE)
        self.assertFalse(result["enrollment_required"])
        self.assertEqual(loaded.credentials[0].id, self.config.credentials[0].id)
        self.assertTrue(auth.options(session)["allowCredentials"])

    def test_tampered_ciphertext_and_other_broker_home_fail_closed(self):
        original = self.config.path.read_bytes()
        data = json.loads(original)
        ciphertext = bytearray(decode(data["ciphertext"]))
        ciphertext[-1] ^= 1
        data["ciphertext"] = encode(ciphertext)
        self.config.path.write_text(json.dumps(data))
        tampered = self.config.path.read_bytes()
        loaded = PasskeyConfig.for_broker(self.config.store, RP, USER)
        with self.assertRaises(ConsoleDenied):
            loaded.prepare_enrollment(HUMAN_PASSPHRASE)
        self.assertFalse(loaded.active)
        self.assertEqual(self.config.path.read_bytes(), tampered)
        other_home = self.root / "different-home"
        other_home.mkdir(mode=0o700)
        (other_home / "console").mkdir(mode=0o700)
        other_file = other_home / "console" / "config.json"
        other_file.write_bytes(original)
        other_file.chmod(0o600)
        copied = PasskeyConfig.for_broker(FixtureVault(other_home), RP, USER)
        with self.assertRaises(ConsoleDenied):
            copied.prepare_enrollment(HUMAN_PASSPHRASE)
        self.assertFalse(copied.active)

    def test_wrong_passphrase_cannot_change_active_authority(self):
        prior = self.config.credentials[0].id
        before = self.config.path.read_bytes()
        with self.assertRaises(ConsoleDenied):
            self.config.prepare_enrollment("unknown agent passphrase")
        self.assertTrue(self.config.active)
        self.assertEqual(self.config.credentials[0].id, prior)
        self.assertEqual(self.config.path.read_bytes(), before)

    def test_empty_vault_has_no_enrollment_or_fallback(self):
        home = self.root / "empty"
        home.mkdir(mode=0o700)
        vault = FixtureVault(home)
        vault.meta = lambda _key: None
        config = PasskeyConfig.for_broker(vault, RP, USER)
        with self.assertRaises(ConsoleDenied):
            config.prepare_enrollment(HUMAN_PASSPHRASE)
        self.assertEqual(vault.calls, 0)
        self.assertFalse(config.active)
        self.assertFalse(config.path.exists())

    def test_admin_rpc_checks_knowledge_even_without_an_admin_session(self):
        from tw.admin_server import AdminService, AdminSession
        seal = SimpleNamespace(state="sealed")
        service = AdminService(self.config.store, seal)
        service.console_config = self.config
        session = AdminSession()
        denied = service.handle(session, {"op": "console_prepare_enrollment", "args": dict(
            passphrase="unknown agent passphrase", rp_id=RP, allowed_user=USER)}, [])
        self.assertFalse(denied["ok"])
        allowed = service.handle(session, {"op": "console_prepare_enrollment", "args": dict(
            passphrase=HUMAN_PASSPHRASE, rp_id=RP, allowed_user=USER)}, [])
        self.assertTrue(allowed["ok"])
        self.assertFalse(allowed["result"]["enrollment_required"])
        self.assertEqual(seal.state, "sealed")
        self.assertFalse(session.is_authenticated())

    def test_admin_peer_grammar_keeps_off_mode_and_exact_console_suffix(self):
        from unittest import mock
        from tw.admin import verify_broker_peer
        base = ["python", "-m", "tw.broker", "--home", str(self.root)]
        console = base + ["--console-config", str(self.config.path), "--console-rp-id", RP,
                          "--console-user", USER]
        for argv, expected in ((base, True), (console, True), (console + ["--extra"], False),
                               (base + ["--console-config", "/agent/chosen.json"], False),
                               (["python", "squatter.py"] + base[1:], False)):
            with mock.patch("tw.admin.peer_pid", return_value=123), \
                    mock.patch("tw.admin.service_broker_pid", return_value=123), \
                    mock.patch("tw.admin.broker_argv", return_value=argv):
                self.assertEqual(verify_broker_peer(mock.Mock(), self.root), expected)


class ConsoleMetadataTests(unittest.TestCase):
    def test_projection_is_read_only_and_never_selects_value_columns(self):
        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        self.addCleanup(db.close)
        db.executescript(Path(__file__).resolve().parents[1].joinpath("tw/schema.sql").read_text())
        db.execute("INSERT INTO projects(slug,created_at) VALUES('fixture','now')")
        db.execute("INSERT INTO secrets(secret_id,path,project,class,note,created_at,created_by) "
                   "VALUES('s','fixture/example','fixture','sensitive',?,'now','fixture')", ("SYNTHETIC_VALUE_NOT_FOR_RENDER",))
        before = db.total_changes
        db.execute("PRAGMA query_only=ON")
        store = SimpleNamespace(connection=db, _transaction_lock=threading.RLock(), meta=lambda _key: None)
        snapshot = ConsoleMetadata(store, SimpleNamespace(state="uninitialized", frozen=False)).snapshot()
        self.assertEqual(db.total_changes, before)
        self.assertEqual(snapshot["secret_count"], 1)
        self.assertEqual(snapshot["secrets"][0]["path"], "fixture/example")
        self.assertNotIn("SYNTHETIC_VALUE_NOT_FOR_RENDER", repr(snapshot))
        self.assertFalse(snapshot["initialized"])
        self.assertEqual(snapshot["projects"], ["fixture"])

    def test_html_escapes_metadata_and_has_no_value_surface(self):
        snapshot = fixture_snapshot()
        snapshot["secrets"][0]["path"] = '<script>alert("fixture")</script>'
        rendered = vault_page(snapshot, "csrf")
        self.assertIn("&lt;script&gt;", rendered)
        self.assertNotIn('<script>alert', rendered)
        self.assertNotIn("clipboard", rendered)
        self.assertNotIn("Copy", rendered)
        self.assertIn("Versions", rendered)
        self.assertIn("Placements", rendered)
        self.assertIn("Rotation due", rendered)
        self.assertNotIn("Add a secret", rendered)

    def test_put_form_renders_only_when_wired_and_escapes_project_names(self):
        snapshot = fixture_snapshot()
        snapshot["projects"] = ['<b>x</b>']
        rendered = vault_page(snapshot, "csrf", listing=True, can_put=True)
        self.assertIn("Add a secret", rendered)
        self.assertIn('<option value="&lt;b&gt;x&lt;/b&gt;">', rendered)
        self.assertNotIn("<b>x</b>", rendered)
        self.assertNotIn("Add a secret", vault_page(snapshot, "csrf", listing=False, can_put=True))
        self.assertNotIn("Add a secret", vault_page(snapshot, "csrf", listing=True, can_put=False))
        with_reveal = vault_page(snapshot, "csrf", listing=True, can_reveal=True)
        self.assertIn("Reveal a value", with_reveal)
        self.assertIn('data-path="infra/example"', with_reveal)
        self.assertNotIn("Reveal a value", vault_page(snapshot, "csrf", listing=False, can_reveal=True))
        self.assertNotIn("clipboard", with_reveal)
        self.assertNotIn("Copy", with_reveal)
        sealed = fixture_snapshot()
        self.assertIn("unseal-form", vault_page(sealed, "csrf", can_unseal=True))
        self.assertNotIn("Seal vault", vault_page(sealed, "csrf", can_seal=True))
        sealed["seal_state"] = "unsealed"
        self.assertIn("Seal vault", vault_page(sealed, "csrf", can_seal=True))
        self.assertNotIn("unseal-form", vault_page(sealed, "csrf", can_unseal=True))
        self.assertNotIn("Seal vault", vault_page(sealed, "csrf"))


def fixture_snapshot():
    return dict(seal_state="sealed", frozen=False, initialized=True, secret_count=2, truncated=False,
        projects=["infra", "shared"],
        secrets=[dict(path="infra/example", **{"class": "sensitive"}, state="active", versions=2,
                      active_version=2, placements=1, last_used="2026-10-23T10:00:00Z", dependents=3,
                      rotation_due="2026-11-01T00:00:00+00:00"),
                 dict(path="shared/example", **{"class": "restricted"}, state="active", versions=1,
                      active_version=1, placements=0, last_used=None, dependents=0, rotation_due=None)])


PUT = {"project": "infra", "name": "example", "class": "sensitive", "kind": "opaque", "note": "",
       "value": "TEST-ONLY-value"}
REVEAL = {"path": "infra/example", "reason": "needed for the recovery drill", "passphrase": "TEST-ONLY-pass"}


class ConsoleHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tw-console-http-")
        self.config, self.key, _, self.credential_id = config_file(Path(self.temp.name), enrolled=True)
        self.calls = 0
        def snapshot():
            self.calls += 1
            return fixture_snapshot()
        self.app = ConsoleApplication(SimpleNamespace(snapshot=snapshot), self.config)
        self.server = ConsoleServer(self.app, port=0)
        self.server.bind()
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.assertTrue(self.server.serving.wait(2))

    def tearDown(self):
        self.server.close()
        self.thread.join(2)
        self.temp.cleanup()

    def request(self, path="/", *, method="GET", body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        fields = {"Host": RP, "Tailscale-User-Login": USER}
        fields.update(headers or {})
        connection.request(method, path, body=body, headers=fields)
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read().decode()
        connection.close()
        return result

    def test_support_pages_point_at_the_public_tracker_by_default(self):
        with mock.patch.dict(os.environ):
            os.environ.pop("TW_SUPPORT_CONTACT", None)
            for path in ("/support/llms.txt", "/support/agent.md"):
                status, _, body = self.request(path)
                self.assertEqual(status, 200)
                self.assertIn("Support: https://github.com/frontier-infra/titanwarden/issues", body)
                self.assertIn("SECURITY.md", body)
                self.assertNotIn("@", body)

    def test_support_contact_is_configurable(self):
        with mock.patch.dict(os.environ, {"TW_SUPPORT_CONTACT": "Support: https://support.example.test"}):
            status, _, body = self.request("/support/llms.txt")
        self.assertEqual(status, 200)
        self.assertIn("Support: https://support.example.test", body)
        self.assertNotIn("github.com/frontier-infra/titanwarden/issues", body)

    def test_forged_identity_headers_alone_cannot_read_metadata(self):
        status, headers, body = self.request("/secrets")
        self.assertEqual(status, 200)
        self.assertIn("Continue with passkey", body)
        self.assertNotIn("infra/example", body)
        self.assertEqual(self.calls, 0)
        cookie = headers["Set-Cookie"]
        for flag in ("Secure", "HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=120"):
            self.assertIn(flag, cookie)
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_wrong_identity_and_host_are_denied(self):
        self.assertEqual(self.request(headers={"Tailscale-User-Login": "other@example.test"})[0], 403)
        self.assertEqual(self.request(headers={"Host": "localhost"})[0], 403)
        self.assertEqual(self.calls, 0)
        self.assertEqual(self.server.server_address[0], "127.0.0.1")

    def test_valid_signed_login_rotates_session_and_serves_metadata(self):
        token, session = self.app.auth.new_session()
        self.app.auth.options(session)
        credential = assertion(self.key, self.credential_id, session.challenge)
        status, headers, _body = self.request("/auth/verify", method="POST",
            body=json.dumps({"credential": credential}), headers={"Cookie": f"{COOKIE}={token}",
                "Origin": "https://" + RP, "X-CSRF-Token": session.csrf, "Content-Type": "application/json"})
        self.assertEqual(status, 200)
        self.assertNotIn(token, headers["Set-Cookie"])
        self.assertIn("Max-Age=900", headers["Set-Cookie"])
        status, _, body = self.request("/secrets", headers={"Cookie": headers["Set-Cookie"].split(";", 1)[0]})
        self.assertEqual(status, 200)
        self.assertIn("infra/example", body)
        self.assertEqual(self.calls, 1)

    def test_csrf_origin_cross_site_and_oversized_body_reject(self):
        token, session = self.app.auth.new_session()
        base = {"Cookie": f"{COOKIE}={token}", "Origin": "https://" + RP,
                "X-CSRF-Token": session.csrf, "Content-Type": "application/json"}
        for change in ({"Origin": "https://evil.test"}, {"X-CSRF-Token": "wrong"},
                       {"Sec-Fetch-Site": "cross-site"}, {"Content-Length": "65537"}):
            with self.subTest(change=change):
                status, _, body = self.request("/auth/options", method="POST", body="{}", headers=base | change)
                self.assertEqual(status, 403)
                self.assertNotIn("Traceback", body)

    def put_headers(self, authenticated=True):
        token, session = self.app.auth.new_session(authenticated=authenticated)
        return {"Cookie": f"{COOKIE}={token}", "Origin": "https://" + RP, "X-CSRF-Token": session.csrf,
                "Content-Type": "application/json"}

    def put(self, payload, **kwargs):
        return self.request("/secrets/put", method="POST", body=json.dumps(payload), headers=self.put_headers(**kwargs))

    def test_put_is_absent_and_unrendered_on_a_read_only_console(self):
        self.assertEqual(self.put(PUT)[0], 404)
        token, _ = self.app.auth.new_session(authenticated=True)
        self.assertNotIn("Add a secret", self.request("/secrets", headers={"Cookie": f"{COOKIE}={token}"})[2])

    def test_put_stores_through_the_broker_and_never_echoes_the_value(self):
        calls = []
        def put(path, value, *, secret_class, kind, note):
            calls.append((path, value, secret_class, kind, note))
            return {"path": path, "version_no": 3}
        self.app.put = put
        status, headers, body = self.put(PUT)
        self.assertEqual(status, 200, body)
        self.assertEqual(calls, [("infra/example", b"TEST-ONLY-value", "sensitive", "opaque", None)])
        self.assertEqual(json.loads(body), {"ok": True, "path": "infra/example", "version": 3})
        self.assertNotIn("TEST-ONLY-value", body + json.dumps(headers))
        token, _ = self.app.auth.new_session(authenticated=True)
        self.assertIn("Add a secret", self.request("/secrets", headers={"Cookie": f"{COOKIE}={token}"})[2])

    def test_put_needs_a_signed_in_session_csrf_and_exact_fields(self):
        self.app.put = lambda *_args, **_kwargs: self.fail("put must not run")
        self.assertEqual(self.put(PUT, authenticated=False)[0], 403)
        headers = self.put_headers()
        headers["X-CSRF-Token"] = "wrong"
        self.assertEqual(self.request("/secrets/put", method="POST", body=json.dumps(PUT), headers=headers)[0], 403)
        for broken in (dict(PUT, extra="x"), dict(PUT, name="a/b"), dict(PUT, name="two words"),
                       dict(PUT, value=""), {k: v for k, v in PUT.items() if k != "note"},
                       dict(PUT, **{"class": "secret"}), dict(PUT, value=7)):
            status, _, body = self.put(broken)
            self.assertEqual(status, 400, repr(broken))
            self.assertNotIn("TEST-ONLY-value", body)

    def test_put_reports_sealed_and_store_errors_without_a_value(self):
        from tw.seal import SealError
        from tw.store import StoreError
        self.app.put = lambda *_args, **_kwargs: (_ for _ in ()).throw(SealError("broker is sealed"))
        status, _, body = self.put(PUT)
        self.assertEqual(status, 409)
        self.assertIn("sealed", body)
        self.app.put = lambda *_args, **_kwargs: (_ for _ in ()).throw(StoreError("project does not exist"))
        status, _, body = self.put(PUT)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body), {"error": "project does not exist"})
        self.assertNotIn("TEST-ONLY-value", body)

    def wire_reveal(self, *, accept=True, value=b"TEST-ONLY-revealed", sealed=False):
        from tw.seal import SealError
        calls = {"check": [], "reveal": []}
        def check_passphrase(passphrase):
            calls["check"].append(passphrase)
            if sealed:
                raise SealError("broker is sealed", "E_SEALED")
            if not accept:
                raise SealError("authentication failed", "E_AUTH")
        def reveal(path, reason):
            calls["reveal"].append((path, reason))
            return value
        self.app.reveal, self.app.check_passphrase = reveal, check_passphrase
        return calls

    def reveal(self, payload, **kwargs):
        return self.request("/secrets/reveal", method="POST", body=json.dumps(payload),
                            headers=self.put_headers(**kwargs))

    def test_reveal_is_absent_unless_both_reveal_and_passphrase_check_are_wired(self):
        self.assertEqual(self.reveal(REVEAL)[0], 404)
        token, _ = self.app.auth.new_session(authenticated=True)
        self.assertNotIn("Reveal a value", self.request("/secrets", headers={"Cookie": f"{COOKIE}={token}"})[2])
        app = ConsoleApplication(self.app.metadata, self.config, reveal=lambda *_a: b"x")
        self.assertIsNone(app.reveal)
        self.assertIsNone(app.check_passphrase)

    def test_reveal_needs_passkey_session_then_passphrase_then_returns_the_value_once(self):
        calls = self.wire_reveal()
        self.assertEqual(self.reveal(REVEAL, authenticated=False)[0], 403)
        self.assertEqual(calls["check"], [])
        status, _, body = self.reveal(REVEAL)
        self.assertEqual(status, 200, body)
        self.assertEqual(calls["check"], ["TEST-ONLY-pass"])
        self.assertEqual(calls["reveal"], [("infra/example", "needed for the recovery drill")])
        self.assertEqual(json.loads(body), {"ok": True, "path": "infra/example", "value": "TEST-ONLY-revealed",
                                            "encoding": "text"})
        token, _ = self.app.auth.new_session(authenticated=True)
        listing = self.request("/secrets", headers={"Cookie": f"{COOKIE}={token}"})[2]
        self.assertIn("Reveal a value", listing)
        self.assertIn('data-path="infra/example"', listing)
        self.assertNotIn("TEST-ONLY-revealed", listing)

    def test_reveal_refuses_wrong_passphrase_sealed_vault_and_bad_fields(self):
        calls = self.wire_reveal(accept=False)
        status, _, body = self.reveal(REVEAL)
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body), {"error": "Passphrase not accepted."})
        self.assertEqual(calls["reveal"], [])
        calls = self.wire_reveal(sealed=True)
        self.assertEqual(self.reveal(REVEAL)[0], 409)
        self.assertEqual(calls["reveal"], [])
        calls = self.wire_reveal()
        for broken in (dict(REVEAL, reason="short"), dict(REVEAL, path="noslash"), dict(REVEAL, passphrase=""),
                       dict(REVEAL, extra="x"), {k: v for k, v in REVEAL.items() if k != "reason"}):
            status, _, body = self.reveal(broken)
            self.assertEqual(status, 400, repr(broken))
            self.assertNotIn("TEST-ONLY", body)
        self.assertEqual(calls["check"], [])

    def test_reveal_encodes_binary_values_and_reports_store_refusals(self):
        from tw.store import StoreError
        calls = self.wire_reveal(value=b"\xff\x00binary")
        status, _, body = self.reveal(REVEAL)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["encoding"], "base64")
        self.app.reveal = lambda *_a: (_ for _ in ()).throw(StoreError("secret not found"))
        status, _, body = self.reveal(REVEAL)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body), {"error": "secret not found"})

    def wire_seal(self, *, accept=True):
        from tw.seal import SealError
        calls = {"unseal": [], "seal": 0}
        def unseal(passphrase):
            calls["unseal"].append(passphrase)
            if not accept:
                raise SealError("unseal failed", "E_AUTH")
        def seal():
            calls["seal"] += 1
        self.app.unseal, self.app.seal = unseal, seal
        return calls

    def test_seal_and_unseal_are_absent_until_wired(self):
        self.assertEqual(self.request("/seal", method="POST", body="{}", headers=self.put_headers())[0], 404)
        self.assertEqual(self.request("/unseal", method="POST", body=json.dumps({"passphrase": "x"}),
                                      headers=self.put_headers(authenticated=False))[0], 404)
        token, _ = self.app.auth.new_session(authenticated=True)
        body = self.request("/", headers={"Cookie": f"{COOKIE}={token}"})[2]
        self.assertNotIn("Seal vault", body)
        self.assertNotIn("unseal-form", body)

    def test_seal_needs_a_passkey_session_and_unseal_accepts_the_login_session(self):
        calls = self.wire_seal()
        self.assertEqual(self.request("/seal", method="POST", body="{}",
                                      headers=self.put_headers(authenticated=False))[0], 403)
        self.assertEqual(calls["seal"], 0)
        status, _, body = self.request("/seal", method="POST", body="{}", headers=self.put_headers())
        self.assertEqual(status, 200, body)
        self.assertEqual(calls["seal"], 1)
        self.assertEqual(self.request("/seal", method="POST", body=json.dumps({"x": 1}),
                                      headers=self.put_headers())[0], 403)
        status, _, body = self.request("/unseal", method="POST", body=json.dumps({"passphrase": HUMAN_PASSPHRASE}),
                                       headers=self.put_headers(authenticated=False))
        self.assertEqual(status, 200, body)
        self.assertEqual(calls["unseal"], [HUMAN_PASSPHRASE])
        self.assertEqual(json.loads(body), {"ok": True, "seal_state": "unsealed", "console_active": True})
        self.assertNotIn(HUMAN_PASSPHRASE, body)
        for broken in ({"passphrase": ""}, {"passphrase": 1}, {"passphrase": "x", "extra": 1}):
            self.assertEqual(self.request("/unseal", method="POST", body=json.dumps(broken),
                                          headers=self.put_headers(authenticated=False))[0], 400)
        calls = self.wire_seal(accept=False)
        status, _, body = self.request("/unseal", method="POST", body=json.dumps({"passphrase": "wrong"}),
                                       headers=self.put_headers(authenticated=False))
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body), {"error": "Passphrase not accepted."})

    def test_unseal_after_a_restart_activates_the_saved_passkey_without_ssh(self):
        calls = self.wire_seal()
        loaded = PasskeyConfig.for_broker(self.config.store, RP, USER)
        self.assertFalse(loaded.active)
        self.app.config = self.app.auth.config = loaded
        status, headers, body = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn("Unseal your vault", body)
        self.assertIn("unseal-form", body)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        session = self.app.auth.session(cookie.split("=", 1)[1])
        status, _, body = self.request("/unseal", method="POST", body=json.dumps({"passphrase": HUMAN_PASSPHRASE}),
                                       headers={"Cookie": cookie, "Origin": "https://" + RP,
                                                "X-CSRF-Token": session.csrf, "Content-Type": "application/json"})
        self.assertEqual(status, 200, body)
        self.assertTrue(loaded.active)
        self.assertEqual(loaded.credentials[0].id, self.config.credentials[0].id)
        self.assertEqual(calls["unseal"], [HUMAN_PASSPHRASE])
        self.assertIn("Welcome back", self.request("/")[2])

    def test_unsupported_value_operations_are_absent(self):
        token, session = self.app.auth.new_session(authenticated=True)
        for path in ("/reveal", "/unseal", "/admin", "/api/secret/value"):
            self.assertEqual(self.request(path, headers={"Cookie": f"{COOKIE}={token}"})[0], 404)
        status, _, _body = self.request("/reveal", method="POST", body="{}", headers={
            "Cookie": f"{COOKIE}={token}", "Origin": "https://" + RP,
            "X-CSRF-Token": session.csrf, "Content-Type": "application/json"})
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
