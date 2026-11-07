"""Broker-authenticated console configuration and bounded browser sessions.

Only vault knowledge activates the domain-separated configuration key. No
caller-created file, environment marker or chosen capability grants authority.
WebAuthn verification and config.save() share the auth lock to keep credential updates atomic between writers.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from . import crypto

from webauthn import (generate_authentication_options, generate_registration_options,
                      options_to_json, verify_authentication_response,
                      verify_registration_response)
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria,
                                     PublicKeyCredentialDescriptor,
                                     UserVerificationRequirement)


class ConsoleDenied(ValueError):
    """Deliberately carries no submitted data or verifier exception text."""


def encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def decode(value: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ConsoleDenied("Invalid credential encoding")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@dataclass
class Credential:
    id: str
    public_key: str
    sign_count: int


class PasskeyConfig:
    def __init__(self, path: Path):
        # There is no caller-file constructor. Only a broker-bound authority
        # may create an inactive instance and verify its vault knowledge factor.
        raise ConsoleDenied("Console configuration must be created by the broker")

    @classmethod
    def for_broker(cls, store, rp_id: str, allowed_user: str, *, expected_path=None, seal=None):
        home = Path(store.home).resolve()
        obj = cls.__new__(cls)
        obj.store = store
        obj.seal = seal
        obj.home = home
        obj.path = home / "console" / "config.json"
        if expected_path is not None and Path(expected_path).absolute() != obj.path:
            raise ConsoleDenied("Console configuration must be inside the broker home")
        obj.rp_id, obj.allowed_user = rp_id, allowed_user
        obj.origin = "https://" + rp_id
        obj._validate_identity()
        obj.path.parent.mkdir(mode=0o700, exist_ok=True)
        obj._private_directory(home)
        obj._private_directory(obj.path.parent)
        obj.credentials = []
        obj.enrollment_digest = None
        obj.user_id = None
        obj.active = False
        obj._key = None
        obj._file_digest = None
        obj._envelope = None
        obj._lock = threading.RLock()
        obj._attempts = []
        if obj.path.exists() or obj.path.is_symlink():
            raw = obj._read_owned()
            try:
                envelope = json.loads(raw)
                if (set(envelope) != {"format", "nonce", "ciphertext"}
                        or envelope["format"] != "tw-console-v1"
                        or len(decode(envelope["nonce"])) != 12
                        or not 16 <= len(decode(envelope["ciphertext"])) <= 65536):
                    raise ValueError()
            except Exception:
                raise ConsoleDenied("Configuration was not issued by this broker") from None
            # Even a well-shaped envelope remains UNTRUSTED until the passphrase
            # activates its AEAD key. No public key or capability is loaded here.
            obj._envelope = envelope
            obj._file_digest = hashlib.sha256(raw).hexdigest()
        return obj

    @staticmethod
    def _private_directory(path):
        info = path.stat()
        if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ConsoleDenied("Console directory must be owned and private")

    def _read_owned(self):
        self._private_directory(self.path.parent)
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > 131072):
                raise ConsoleDenied("Console configuration must be an owned private regular file")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                return stream.read(131073)
        finally:
            os.close(fd)

    def _validate_identity(self):
        if not isinstance(self.rp_id, str) or not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.[a-z0-9-]+\.ts\.net", self.rp_id):
            raise ConsoleDenied("Console RP must be the exact ts.net hostname")
        if (not isinstance(self.allowed_user, str) or not 1 <= len(self.allowed_user) <= 254
                or any(ord(c) < 33 or ord(c) > 126 for c in self.allowed_user)):
            raise ConsoleDenied("Invalid console user")

    def _binding(self):
        store_id = self.store.meta("store_id")
        if not isinstance(store_id, str) or not store_id:
            raise ConsoleDenied("Human vault initialization is required before enrollment")
        return json.dumps(["tw1 console config", str(self.home), store_id, self.rp_id,
                           self.allowed_user], separators=(",", ":")).encode()

    def _load_payload(self, data):
        if set(data) != {"rp_id", "allowed_user", "user_id", "enrollment_digest", "credentials"}:
            raise ConsoleDenied("Invalid console configuration")
        if data["rp_id"] != self.rp_id or data["allowed_user"] != self.allowed_user:
            raise ConsoleDenied("Console identity mismatch")
        if len(decode(data["user_id"])) != 32:
            raise ConsoleDenied("Invalid console user ID")
        digest = data["enrollment_digest"]
        if digest is not None and (not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest)):
            raise ConsoleDenied("Invalid enrollment digest")
        if not isinstance(data["credentials"], list) or len(data["credentials"]) > 16:
            raise ConsoleDenied("Invalid passkey inventory")
        credentials = [Credential(**item) for item in data["credentials"]]
        if len({c.id for c in credentials}) != len(credentials):
            raise ConsoleDenied("Duplicate passkey")
        for credential in credentials:
            if (not 1 <= len(decode(credential.id)) <= 1024
                    or not 1 <= len(decode(credential.public_key)) <= 4096
                    or type(credential.sign_count) is not int or credential.sign_count < 0):
                raise ConsoleDenied("Invalid passkey")
        self.user_id, self.enrollment_digest, self.credentials = data["user_id"], digest, credentials

    def has_envelope(self) -> bool:
        """A saved, still-encrypted console record exists; activation can decrypt it."""
        return self._envelope is not None

    def prepare_enrollment(self, passphrase):
        with self._lock:
            if not isinstance(passphrase, str) or len(passphrase) > 4096:
                raise ConsoleDenied("Invalid authentication input")
            if self.seal is not None and self.seal.state == "lockdown":
                raise ConsoleDenied("Broker is in lockdown")
            now = time.monotonic()
            self._attempts = [ts for ts in self._attempts if now - ts < 60]
            if len(self._attempts) >= 5:
                raise ConsoleDenied("Try again later")
            self._attempts.append(now)
            prior = (self._key, self.active, self.credentials, self.enrollment_digest, self.user_id)
            key = None
            try:
                binding = self._binding()
                master = self.store.unlock_passphrase(passphrase)
                key = bytearray(crypto.hkdf(master, b"tw1 console config key\x00" + binding))
                del master
                if self._envelope is not None and not self.active:
                    payload = crypto.decrypt(bytes(key), decode(self._envelope["ciphertext"]),
                                             decode(self._envelope["nonce"]), binding)
                    self._load_payload(json.loads(payload))
                self._key = key
                self.active = True
                if self.credentials:
                    result = {"enrollment_required": False}
                else:
                    # Broker-only capability, after the real knowledge factor.
                    capability = secrets.token_urlsafe(32)
                    self.user_id = self.user_id or encode(secrets.token_bytes(32))
                    self.enrollment_digest = hashlib.sha256(capability.encode()).hexdigest()
                    self.save()
                    result = {"enrollment_required": True, "enrollment_code": capability}
                self._attempts.clear()
                if prior[0] is not None:
                    prior[0][:] = b"\x00" * len(prior[0])
                return result
            except Exception:
                if key is not None:
                    key[:] = b"\x00" * len(key)
                self._key, self.active, self.credentials, self.enrollment_digest, self.user_id = prior
                raise ConsoleDenied("Vault authentication or configuration verification failed") from None

    def save(self) -> None:
        if not self.active or self._key is None:
            raise ConsoleDenied("Broker passphrase activation required")
        data = dict(rp_id=self.rp_id, allowed_user=self.allowed_user, user_id=self.user_id,
                    enrollment_digest=self.enrollment_digest,
                    credentials=[asdict(c) for c in self.credentials])
        ciphertext, nonce = crypto.encrypt(bytes(self._key), json.dumps(data, separators=(",", ":")).encode(),
                                           self._binding())
        envelope = dict(format="tw-console-v1", nonce=encode(nonce), ciphertext=encode(ciphertext))
        raw = json.dumps(envelope, separators=(",", ":")).encode()
        self._private_directory(self.path.parent)
        fd, temporary = tempfile.mkstemp(prefix=".console-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            if self._file_digest is None:
                os.link(temporary, self.path)  # Exclusive initial publication by the broker.
            else:
                if hashlib.sha256(self._read_owned()).hexdigest() != self._file_digest:
                    raise ConsoleDenied("Console configuration changed outside the broker")
                os.replace(temporary, self.path)
            self._file_digest = hashlib.sha256(raw).hexdigest()
            self._envelope = envelope
            directory = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def close(self):
        if self._key is not None:
            self._key[:] = b"\x00" * len(self._key)
        self._key = None
        self.active = False
        self.credentials = []
        self.enrollment_digest = None


@dataclass
class BrowserSession:
    csrf: str
    expires: float
    authenticated: bool = False
    challenge: bytes | None = None
    purpose: str | None = None
    challenge_expires: float = 0


class ConsoleAuth:
    SESSION_SECONDS = 900
    CHALLENGE_SECONDS = 120
    MAX_SESSIONS = 256

    def __init__(self, config: PasskeyConfig, *, clock=time.monotonic):
        self.config = config
        self.clock = clock
        self.lock = config._lock
        self.sessions: dict[str, BrowserSession] = {}
        self.attempts: list[float] = []

    def session(self, token: str | None, *, authenticated=False) -> BrowserSession:
        session = self.sessions.get(token or "")
        if session is None or self.clock() >= session.expires:
            self.sessions.pop(token or "", None)
            raise ConsoleDenied("Session expired")
        if authenticated and not session.authenticated:
            raise ConsoleDenied("Passkey required")
        return session

    def new_session(self, *, authenticated=False) -> tuple[str, BrowserSession]:
        now = self.clock()
        self.sessions = {k: v for k, v in self.sessions.items() if now < v.expires}
        if len(self.sessions) >= self.MAX_SESSIONS:
            raise ConsoleDenied("Too many sessions")
        token = secrets.token_urlsafe(32)
        session = BrowserSession(secrets.token_urlsafe(32), now + (
            self.SESSION_SECONDS if authenticated else self.CHALLENGE_SECONDS), authenticated)
        self.sessions[token] = session
        return token, session

    def csrf(self, session: BrowserSession, supplied: str) -> None:
        if not isinstance(supplied, str) or not hmac.compare_digest(session.csrf, supplied):
            raise ConsoleDenied("Invalid request token")

    def options(self, session: BrowserSession, *, enroll=False, capability="") -> dict:
        if not self.config.active:
            raise ConsoleDenied("Broker passphrase activation required")
        now = self.clock()
        self.attempts = [ts for ts in self.attempts if now - ts < 60]
        if len(self.attempts) >= 10:
            raise ConsoleDenied("Try again later")
        self.attempts.append(now)
        if session.authenticated:
            raise ConsoleDenied("Already authenticated")
        if enroll:
            expected = self.config.enrollment_digest
            if (self.config.credentials or expected is None or not isinstance(capability, str)
                    or not 32 <= len(capability) <= 256
                    or not hmac.compare_digest(hashlib.sha256(capability.encode()).hexdigest(), expected)):
                raise ConsoleDenied("Enrollment is not authorized")
        elif not self.config.credentials:
            raise ConsoleDenied("Human passkey enrollment required")
        session.challenge = secrets.token_bytes(32)
        session.purpose = "enroll" if enroll else "login"
        session.challenge_expires = now + self.CHALLENGE_SECONDS
        if enroll:
            options = generate_registration_options(
                rp_id=self.config.rp_id, rp_name="Titanwarden", user_id=decode(self.config.user_id),
                user_name=self.config.allowed_user, challenge=session.challenge,
                authenticator_selection=AuthenticatorSelectionCriteria(
                    user_verification=UserVerificationRequirement.REQUIRED))
        else:
            options = generate_authentication_options(
                rp_id=self.config.rp_id, challenge=session.challenge,
                user_verification=UserVerificationRequirement.REQUIRED,
                allow_credentials=[PublicKeyCredentialDescriptor(id=decode(c.id))
                                   for c in self.config.credentials])
        return json.loads(options_to_json(options))

    def verify(self, session: BrowserSession, credential: dict, *, enroll=False) -> None:
        challenge, purpose = session.challenge, session.purpose
        session.challenge = None  # Every verification attempt consumes its challenge.
        session.purpose = None
        if (not challenge or purpose != ("enroll" if enroll else "login")
                or self.clock() >= session.challenge_expires or session.authenticated):
            raise ConsoleDenied("Passkey challenge expired")
        try:
            client_bytes = decode(credential["response"]["clientDataJSON"])
            if len(client_bytes) > 4096:
                raise ConsoleDenied("Invalid client data")
            client_data = json.loads(client_bytes)
            if (client_data.get("crossOrigin", False) is not False or "topOrigin" in client_data):
                raise ConsoleDenied("Cross-origin passkey refused")
            if enroll:
                if self.config.credentials or self.config.enrollment_digest is None:
                    raise ConsoleDenied("Enrollment is closed")
                result = verify_registration_response(
                    credential=credential, expected_challenge=challenge,
                    expected_rp_id=self.config.rp_id, expected_origin=self.config.origin,
                    require_user_verification=True)
                new = Credential(encode(result.credential_id), encode(result.credential_public_key),
                                 result.sign_count)
                prior_digest = self.config.enrollment_digest
                self.config.credentials = [new]
                self.config.enrollment_digest = None
                try:
                    self.config.save()
                except Exception:
                    self.config.credentials = []
                    self.config.enrollment_digest = prior_digest
                    raise
            else:
                existing = next(c for c in self.config.credentials if c.id == credential.get("id"))
                result = verify_authentication_response(
                    credential=credential, expected_challenge=challenge,
                    expected_rp_id=self.config.rp_id, expected_origin=self.config.origin,
                    credential_public_key=decode(existing.public_key),
                    credential_current_sign_count=existing.sign_count,
                    require_user_verification=True)
                prior_count = existing.sign_count
                existing.sign_count = result.new_sign_count
                try:
                    self.config.save()
                except Exception:
                    existing.sign_count = prior_count
                    raise
        except Exception:
            # Vendor exceptions may contain submitted fields. Never propagate them.
            raise ConsoleDenied("Passkey verification failed") from None
