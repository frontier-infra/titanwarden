"""PRD7.2 human console. Opt-in broker surface, fixed IPv4 loopback bind.

No value-returning operation exists in this first slice. Tailscale headers are
only an identity filter; metadata always additionally requires a passkey.
"""
from __future__ import annotations

import base64

import collections
import html
import json
import os
import socket
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .console_auth import ConsoleAuth, ConsoleDenied, PasskeyConfig

from .seal import SealError
from .store import StoreError

COOKIE = "__Host-tw-console"
SECRET_CLASSES = ("standard", "sensitive", "restricted")
ASSETS = Path(__file__).with_name("console_assets")
DEFAULT_SUPPORT_CONTACT = ("Support: https://github.com/frontier-infra/titanwarden/issues. "
                           "Security reports: the repository Security tab (see SECURITY.md)")


def support_contact() -> str:
    """The contact line on the /support pages. TW_SUPPORT_CONTACT replaces the default."""
    return os.environ.get("TW_SUPPORT_CONTACT", "").strip() or DEFAULT_SUPPORT_CONTACT


def support_text() -> str:
    return ("Titanwarden human console. Read-only metadata requires Tailscale identity "
            "and a passkey. Agents cannot enroll, initialize, unseal or reveal. "
            "Use the CLI agent surface for credential use. Never send a passphrase, "
            "recovery key or credential value to an agent. " + support_contact() + "\n")


def page(content: str, *, csrf="", title="Overview", authenticated=False) -> str:
    esc = html.escape
    nav = ('<a href="/">Overview</a><a href="/secrets">Secrets</a>' if authenticated else '')
    logout = ('<form action="/logout" method="post"><input type="hidden" name="csrf" value="'
              + esc(csrf, quote=True) + '"><button class="quiet">Sign out</button></form>'
              if authenticated else '')
    return ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta name="csrf-token" content="' + esc(csrf, quote=True) + '">'
            '<title>' + esc(title) + ' | Titanwarden</title>'
            '<link rel="stylesheet" href="/assets/console.css">'
            '<script src="/assets/console.js" defer></script></head><body>'
            '<aside><a class="brand" href="/"><span class="mark">T</span>Titanwarden</a>'
            '<p class="eyebrow">Your vault, under your control</p><nav>' + nav + '</nav>'
            '<div class="sidebar-bottom"><span class="status-dot"></span> Tailnet only'
            '<a href="/support/agent.md">Help and safety</a></div></aside><main>'
            '<header><span class="eyebrow">Vault console</span>' + logout + '</header>'
            + content + '<footer>Use credentials without exposing them.</footer></main></body></html>')


def unseal_form(csrf: str = "") -> str:
    return ('<form id="unseal-form" class="put-form" autocomplete="off">'
            '<label for="unseal-passphrase">Vault passphrase</label>'
            '<input id="unseal-passphrase" name="passphrase" type="password" required autocomplete="off">'
            '<button type="submit">Unseal</button>'
            '<p id="unseal-message" role="status" aria-live="polite"></p></form>')


def seal_form() -> str:
    return ('<form id="seal-form" autocomplete="off"><button type="submit" class="seal">Seal vault</button>'
            '<p id="seal-message" role="status" aria-live="polite"></p></form>')


def login_page(csrf: str, *, enrollment: bool, active=True, can_unseal=False) -> str:
    if not active:
        if can_unseal:
            body = ('<section class="login"><span class="pill">Private access</span>'
                    '<h1>Unseal your vault</h1><p>The broker restarted, so the vault is sealed and this '
                    'console is inactive. Your vault passphrase unseals it and activates your passkey.</p>'
                    + unseal_form(csrf)
                    + '<p class="muted">First-time passkey enrollment still happens from your own SSH '
                    'session. An uninitialized vault must be initialized by its human owner first.</p></section>')
            return page(body, csrf=csrf, title="Unseal your vault")
        return page('<section class="login"><span class="pill">Private access</span>'
                    '<h1>Activate your console</h1><p>Use your vault passphrase in your own SSH session '
                    'to activate this console. This is required after a broker restart.</p>'
                    '<p>An uninitialized vault must be initialized by its human owner first.</p></section>',
                    title="Activate your console")
    heading = "Enroll your passkey" if enrollment else "Welcome back"
    instructions = ("Use the enrollment code issued by your broker in your own SSH session. "
                    "A passkey will protect access to your vault console." if enrollment else
                    "Verify with your passkey to see your vault. Your Tailscale identity is also required.")
    field = ('<label for="enrollment-code">Enrollment code</label>'
             '<input id="enrollment-code" type="password" autocomplete="off"'
             ' minlength="32" maxlength="256" required>' if enrollment else '')
    return page('<section class="login"><span class="pill">Private access</span><h1>'
                + heading + '</h1><p>' + instructions + '</p><form id="passkey-form" data-enroll="'
                + ('true' if enrollment else 'false') + '">' + field
                + '<button type="submit">' + ('Create a passkey' if enrollment else 'Continue with passkey')
                + '</button><p id="auth-message" role="status" aria-live="polite"></p></form>'
                '<p class="muted">Open this console on your own phone or laptop.</p></section>',
                csrf=csrf, title=heading)


def vault_page(snapshot: dict, csrf: str, *, listing=False, can_put=False, can_reveal=False,
               can_seal=False, can_unseal=False) -> str:
    esc = lambda value: html.escape(str(value), quote=True)
    state = snapshot["seal_state"]
    descriptions = {"uninitialized": "Your vault has not been initialized. No credentials have been added.",
                    "sealed": "Your vault is sealed. Credential values remain locked.",
                    "unsealed": "Your vault is available to authorized operations.",
                    "lockdown": "Your vault is in lockdown. Human attention is required."}
    rows = []
    reveal_column = listing and can_reveal
    for item in snapshot["secrets"]:
        rows.append('<tr><th scope="row">' + esc(item["path"]) + '</th><td><span class="tag">'
                    + esc(item["class"]) + '</span></td><td>' + esc(item["versions"])
                    + '</td><td>' + esc(item["placements"]) + '</td><td>'
                    + esc(item["last_used"] or "Not used") + '</td><td>' + esc(item["dependents"])
                    + '</td><td>' + esc(item["rotation_due"] or "Not scheduled") + '</td>'
                    + ('<td><button type="button" class="quiet reveal-pick" data-path="' + esc(item["path"])
                       + '">Reveal</button></td>' if reveal_column else '') + '</tr>')
    table = ('<div class="table-scroll"><table><thead><tr><th>Path</th><th>Class</th><th>Versions</th>'
             '<th>Placements</th><th>Last used</th><th>Dependents</th><th>Rotation due</th>'
             + ('<th>Value</th>' if reveal_column else '') + '</tr></thead>'
             '<tbody>' + ''.join(rows) + '</tbody></table></div>' if rows else
             '<div class="empty"><span class="empty-symbol" aria-hidden="true">◇</span>'
             '<h3>No secrets yet</h3><p>Credential names and their access history will appear here.</p></div>')
    body = ('<div class="page-heading"><div><p class="eyebrow">Private vault</p><h1>'
            + ('Secrets' if listing else 'Your vault at a glance') + '</h1></div>'
            '<span class="pill">' + ('Put and reveal' if can_put and can_reveal else 'Metadata and put'
                                      if can_put else 'Read-only') + '</span></div>'
            '<section class="state-panel"><div>'
            '<span class="eyebrow">Vault state</span><h2>' + esc(state.capitalize()) + '</h2><p>'
            + descriptions.get(state, "Vault state is unavailable.") + '</p>'
            + (seal_form() if state == "unsealed" and can_seal else '')
            + (unseal_form(csrf) if state == "sealed" and can_unseal else '')
            + '</div><div class="count">'
            + esc(snapshot["secret_count"]) + '<span>secrets</span></div></section>'
            + ('<p class="notice">Credential operations are frozen.</p>' if snapshot["frozen"] else '')
            + '<section class="inventory"><div class="section-heading"><h2>Secrets inventory</h2>'
            '<span class="muted">Metadata only</span></div>' + table
            + ('<p class="notice">Showing the first 1,000 names. The count above covers all secrets.</p>'
               if snapshot["truncated"] else '') + '</section>'
            + (reveal_form() if reveal_column else '')
            + (put_form(snapshot.get("projects", [])) if listing and can_put else ''))
    return page(body, csrf=csrf, authenticated=True, title="Secrets" if listing else "Overview")


def put_form(projects) -> str:
    esc = lambda value: html.escape(str(value), quote=True)
    options = ''.join('<option value="' + esc(slug) + '">' + esc(slug) + '</option>' for slug in projects)
    classes = ''.join('<option value="' + name + '"' + (' selected' if name == 'sensitive' else '') + '>'
                      + name + '</option>' for name in SECRET_CLASSES)
    return ('<section class="put"><div class="section-heading"><h2>Add a secret</h2>'
            '<span class="muted">Encrypted on save. The value is never shown here again.</span></div>'
            '<form id="put-form" class="put-form" autocomplete="off">'
            '<label>Project<select name="project" required>' + options + '</select></label>'
            '<label>Name<input name="name" required maxlength="128" pattern="[^/\\s]+" placeholder="API_KEY"></label>'
            '<label>Class<select name="class">' + classes + '</select></label>'
            '<label>Kind<input name="kind" value="opaque" maxlength="32"></label>'
            '<label>Note (names only, no values)<input name="note" maxlength="200"></label>'
            '<label>Value<textarea name="value" class="secret" required rows="3" spellcheck="false"></textarea></label>'
            '<button type="submit">Store secret</button>'
            '<p id="put-message" role="status" aria-live="polite"></p></form></section>')


def reveal_form() -> str:
    return ('<section class="reveal" id="reveal" hidden><div class="section-heading"><h2>Reveal a value</h2>'
            '<span class="muted">Shown here for 30 seconds, then masked. Your reason goes in the audit log.</span></div>'
            '<form id="reveal-form" class="put-form" autocomplete="off">'
            '<label>Path<input name="path" readonly></label>'
            '<label>Reason (at least 10 characters)<input name="reason" required minlength="10" maxlength="300"></label>'
            '<label>Vault passphrase<input name="passphrase" type="password" required autocomplete="off"></label>'
            '<button type="submit">Reveal for 30 seconds</button>'
            '<p id="reveal-message" role="status" aria-live="polite"></p>'
            '<pre id="revealed" class="revealed" hidden></pre></form></section>')


def reveal_fields(payload: dict) -> tuple[dict | None, str | None]:
    """Exact field set for /secrets/reveal; the passphrase is forwarded, never stored or echoed."""
    expected = {"path", "reason", "passphrase"}
    if set(payload) != expected or not all(isinstance(payload[key], str) for key in expected):
        return None, "Send path, reason and passphrase as text."
    path = payload["path"].strip()
    project, separator, name = path.partition("/")
    if not separator or not project or not name or "/" in name or len(path) > 200:
        return None, "Path must be project/name."
    reason = payload["reason"].strip()
    if not 10 <= len(reason) <= 300:
        return None, "Reason must be 10 to 300 characters."
    if not payload["passphrase"]:
        return None, "Passphrase is empty."
    return dict(path=path, reason=reason, passphrase=payload["passphrase"]), None


def put_fields(payload: dict) -> tuple[dict | None, str | None]:
    """Exact field set for /secrets/put; returns (fields, None) or (None, reason). Never echoes the value."""
    expected = {"project", "name", "class", "kind", "note", "value"}
    if set(payload) != expected or not all(isinstance(payload[key], str) for key in expected):
        return None, "Send project, name, class, kind, note and value as text."
    project, name = payload["project"].strip(), payload["name"].strip()
    if not project or "/" in project or len(project) > 64:
        return None, "Choose a project."
    if not name or "/" in name or any(c.isspace() for c in name) or len(name) > 128:
        return None, "Name must be one word without slashes."
    if payload["class"] not in SECRET_CLASSES:
        return None, "Class must be standard, sensitive or restricted."
    kind = payload["kind"].strip() or "opaque"
    if len(kind) > 32:
        return None, "Kind is too long."
    note = payload["note"].strip()
    if len(note) > 200:
        return None, "Note is too long."
    if not payload["value"]:
        return None, "Value is empty."
    return dict(project=project, name=name, secret_class=payload["class"], kind=kind,
                note=note or None, value=payload["value"]), None


class ConsoleApplication:
    def __init__(self, metadata, config: PasskeyConfig, put=None, reveal=None, check_passphrase=None,
                 unseal=None, seal=None):
        self.metadata = metadata
        self.auth = ConsoleAuth(config)
        self.config = config
        # AdminService.put_value when the broker wires it; None keeps the console read-only.
        self.put = put
        # AdminService.reveal_value plus SealManager.check_passphrase: a reveal needs the
        # passkey session and the vault passphrase (PRD 7.2), and both or neither are wired.
        self.reveal = reveal if reveal is not None and check_passphrase is not None else None
        self.check_passphrase = check_passphrase if self.reveal is not None else None
        # AdminService.unseal_value and seal_value. Unseal takes the passphrase (the knowledge factor
        # the admin socket already accepts from any same-uid process, rate limited the same way) and
        # then activates the saved passkey record; seal needs only the passkey session.
        self.unseal = unseal
        self.seal = seal


class _Attempt:
    """Per-request state shared by the deadline timer, the server and the handler.

    The server needs to know whether a status line reached the client, and the
    handler needs to know whether its budget already ran out. One object is
    fewer moving parts than three flags kept in step by hand.
    """
    __slots__ = ("expired", "status_written", "dispatched", "reading", "interrupted", "stalled_op")

    def __init__(self):
        self.expired = False
        self.status_written = False
        self.dispatched = False
        self.reading = False
        self.interrupted = False
        self.stalled_op = ""


class ConsoleHandler(BaseHTTPRequestHandler):
    server_version = "Titanwarden"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    attempt = None

    def log_message(self, *_args):
        pass  # Request lines, bodies, credentials and verifier errors are never logged.

    def send_error(self, code, message=None, explain=None):
        # BaseHTTPRequestHandler otherwise reflects method/request text in an HTML error.
        self._send(code, "Request denied", content_type="text/plain; charset=utf-8")

    def setup(self):
        super().setup()
        self.connection.settimeout(5)
        with self.server._lifecycle:
            timer = self.server._connections.get(self.request)
            self.attempt = timer.owner if timer is not None else None
        if self.attempt is not None:
            self.attempt.reading = True  # the request line is read first

    def parse_request(self):
        parsed = super().parse_request()
        if self.attempt is not None:
            # Past this point a handler is running that the deadline can leave
            # alone to finish and be answered explicitly.
            self.attempt.reading = False
            self.attempt.dispatched = parsed
        return parsed

    def read_body(self, length: int) -> bytes:
        """Read a declared body under the same deadline as the rest of the request."""
        if self.attempt is None:
            return self.rfile.read(length)
        self.attempt.reading = True
        try:
            return self.rfile.read(length)
        finally:
            self.attempt.reading = False

    def handle(self):
        try:
            super().handle()
        finally:
            if self.attempt is not None:
                # Parsing is over, so the command (or its absence) is now known.
                self.attempt.stalled_op = getattr(self, "command", None) or ""
                if self.attempt.expired and not self.attempt.status_written:
                    # Answered here, before finish() closes the writer. A request
                    # that overran must never leave the client with no status.
                    self.answer_timeout()

    def answer_timeout(self) -> None:
        """Answer a request that ran past the connection budget with a status line.

        The peer may already be gone, so nothing is raised: a failed write here
        is the same silence this replaces and must not surface as a traceback.
        """
        # Parsing may never have finished. Without a request line, log_request()
        # has nothing to format, and the HTTP/0.9 default suppresses the status
        # line itself, which is the silent truncation this replaces.
        if getattr(self, "requestline", None) is None:
            self.requestline = ""
        if getattr(self, "command", None) is None:
            self.command = None
        if getattr(self, "request_version", None) in (None, self.default_request_version):
            # Every response this server sends carries a status line, so a
            # request that failed before its version was known is answered as
            # HTTP/1.1 rather than with the status-less HTTP/0.9 default.
            self.request_version = "HTTP/1.1"
        self.close_connection = True
        try:
            self._send(503, "Console request timed out", allow_after_expiry=True)
        except OSError:
            pass

    @property
    def app(self) -> ConsoleApplication:
        return self.server.app

    def _single(self, name: str) -> str:
        values = self.headers.get_all(name, [])
        if len(values) != 1:
            raise ConsoleDenied("Required header missing or repeated")
        return values[0]

    def _context(self, *, mutation=False):
        if self.client_address[0] != "127.0.0.1":
            raise ConsoleDenied("Loopback only")
        if self._single("Host") not in {self.app.config.rp_id, self.app.config.rp_id + ":443"}:
            raise ConsoleDenied("Wrong host")
        if self._single("Tailscale-User-Login") != self.app.config.allowed_user:
            raise ConsoleDenied("Tailscale identity required")
        if mutation and self._single("Origin") != self.app.config.origin:
            raise ConsoleDenied("Wrong origin")
        if mutation and self.headers.get("Sec-Fetch-Site") not in {None, "same-origin"}:
            raise ConsoleDenied("Cross-site request denied")

    def _token(self) -> str | None:
        raw = self.headers.get_all("Cookie", [])
        if len(raw) > 1:
            raise ConsoleDenied("Repeated cookie header")
        text = raw[0] if raw else ""
        if sum(part.strip().split("=", 1)[0] == COOKIE for part in text.split(";")) > 1:
            raise ConsoleDenied("Repeated session cookie")
        cookie = SimpleCookie()
        cookie.load(text)
        return cookie[COOKIE].value if COOKIE in cookie else None

    def _send(self, status: int, body: str | bytes, *, content_type="text/html; charset=utf-8", token=None, age=900,
              allow_after_expiry=False):
        if self.attempt is not None and self.attempt.expired and not allow_after_expiry:
            # The budget already ran out and the client is being answered
            # with an explicit 503. A late response must not race it, and
            # the handler must not go back to reading another request.
            self.close_connection = True
            return
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; "
                         "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        self.send_header("Permissions-Policy", "clipboard-read=(), clipboard-write=(), "
                         "publickey-credentials-get=(self), publickey-credentials-create=(self)")
        if token is not None:
            self.send_header("Set-Cookie", f"{COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={age}")
        self.send_header("Connection", "close")
        self.end_headers()
        if self.attempt is not None:
            # Only now is a status line actually on the wire. Setting this any
            # earlier would let a failed write look like a delivered answer.
            self.attempt.status_written = True
        self.close_connection = True
        if getattr(self, "command", None) != "HEAD":
            self.wfile.write(data)

    def _json(self, data, **kwargs):
        self._send(200, json.dumps(data, separators=(",", ":")), content_type="application/json", **kwargs)

    def do_GET(self):
        try:
            self._context()
            if self.path in {"/assets/console.css", "/assets/console.js"}:
                name = self.path.rsplit("/", 1)[1]
                self._send(200, (ASSETS / name).read_bytes(), content_type=(
                    "text/css; charset=utf-8" if name.endswith("css") else "text/javascript; charset=utf-8"))
                return
            if self.path in {"/support/llms.txt", "/support/agent.md"}:
                self._send(200, support_text(), content_type="text/plain; charset=utf-8")
                return
            if self.path not in {"/", "/secrets"}:
                self._send(404, "Not found")
                return
            # The lock covers the auth decision and nothing else. The snapshot it
            # used to be held across is a 1001-row projection with four correlated
            # subqueries, so one slow page load stalled every console user,
            # including login, plus the bounded deadline and shutdown paths that
            # wait on this same lock.
            with self.app.auth.lock:
                try:
                    session = self.app.auth.session(self._token(), authenticated=True)
                except ConsoleDenied:
                    token, session = self.app.auth.new_session()
                    login = (token, not self.app.config.credentials, self.app.config.active)
                else:
                    login = None
                csrf = session.csrf
            if login is not None:
                token, enrollment, active = login
                self._send(200, login_page(csrf, enrollment=enrollment, active=active,
                                           can_unseal=self.app.unseal is not None), token=token, age=120)
                return
            # Revocation window, accepted for this page: the session is validated
            # under the lock above and the lock is released before this read, so a
            # revocation or lockdown can land in between and this request still
            # renders. That is acceptable here. The page is metadata only, paths,
            # classes, counts and timestamps, never a value, and this slice has no
            # operation to reach with it. The snapshot is read after any such event,
            # so it reports the new seal state instead of a stale one. The
            # alternative is holding the global auth lock across the query again,
            # which is the stall this change exists to remove.
            self._send(200, vault_page(self.app.metadata.snapshot(), csrf,
                                      listing=self.path == "/secrets", can_put=self.app.put is not None,
                                      can_reveal=self.app.reveal is not None,
                                      can_seal=self.app.seal is not None, can_unseal=self.app.unseal is not None))
        except ConsoleDenied:
            self._send(403, "Access denied")
        except Exception:
            self._send(503, "Console temporarily unavailable")

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        try:
            self._context(mutation=True)
            if self.headers.get_all("Transfer-Encoding"):
                raise ConsoleDenied("Transfer encoding refused")
            length = self._single("Content-Length")
            if not length.isascii() or not length.isdecimal() or not 1 <= int(length) <= 65536:
                raise ConsoleDenied("Invalid body size")
            content_type = self._single("Content-Type")
            if content_type not in {"application/json", "application/x-www-form-urlencoded"}:
                raise ConsoleDenied("Unsupported body")
            raw = self.read_body(int(length))
            if len(raw) != int(length):
                raise ConsoleDenied("Incomplete body")
            # This lock covers the auth decision and the state change it guards:
            # the consumed challenge, the sign count and the session rotation.
            # Response builds and socket writes are left to run after it is
            # released, so a peer that stops reading cannot stall every other
            # console user. verify() does make one single-row store.meta read
            # inside config.save(); that read cannot be separated from the atomic
            # save without weakening it, and it is not the snapshot query.
            with self.app.auth.lock:
                token = self._token()
                session = self.app.auth.session(token)
                if self.path == "/logout" and content_type == "application/x-www-form-urlencoded":
                    from urllib.parse import parse_qs
                    fields = parse_qs(raw.decode("utf-8"), strict_parsing=True)
                    if set(fields) != {"csrf"} or len(fields["csrf"]) != 1:
                        raise ConsoleDenied("Invalid logout")
                    self.app.auth.csrf(session, fields["csrf"][0])
                    self.app.auth.session(token, authenticated=True)
                    self.app.auth.sessions.pop(token)
                    answer = lambda: self._send(
                        200, page("<h1>Signed out</h1><p><a href=\"/\">Sign in again</a></p>"),
                        token="", age=0)
                elif content_type != "application/json":
                    raise ConsoleDenied("JSON required")
                else:
                    self.app.auth.csrf(session, self._single("X-CSRF-Token"))
                    payload = json.loads(raw)
                    if not isinstance(payload, dict):
                        raise ConsoleDenied("Invalid request")
                    if self.path in {"/auth/options", "/auth/register/options"}:
                        enroll = self.path == "/auth/register/options"
                        if set(payload) != ({"capability"} if enroll else set()):
                            raise ConsoleDenied("Invalid options request")
                        options = self.app.auth.options(session, enroll=enroll,
                                                       capability=payload.get("capability", ""))
                        answer = lambda: self._json(options)
                    elif self.path in {"/auth/verify", "/auth/register/verify"}:
                        if set(payload) != {"credential"} or not isinstance(payload["credential"], dict):
                            raise ConsoleDenied("Invalid verification request")
                        self.app.auth.verify(session, payload["credential"],
                                             enroll=self.path == "/auth/register/verify")
                        self.app.auth.sessions.pop(token)
                        new_token, _session = self.app.auth.new_session(authenticated=True)
                        answer = lambda: self._json({"ok": True}, token=new_token)
                    elif self.path == "/secrets/put" and self.app.put is not None:
                        self.app.auth.session(token, authenticated=True)
                        fields, reason = put_fields(payload)
                        if fields is None:
                            answer = lambda: self._send(400, json.dumps({"error": reason}),
                                                        content_type="application/json")
                        else:
                            # Runs after the auth lock is released; the store serializes itself.
                            answer = lambda: self._put(fields)
                    elif self.path == "/secrets/reveal" and self.app.reveal is not None:
                        self.app.auth.session(token, authenticated=True)
                        fields, reason = reveal_fields(payload)
                        if fields is None:
                            answer = lambda: self._send(400, json.dumps({"error": reason}),
                                                        content_type="application/json")
                        else:
                            # Argon2 and the store run after the auth lock is released.
                            answer = lambda: self._reveal(fields)
                    elif self.path == "/unseal" and self.app.unseal is not None:
                        # Any console session may ask: after a restart there is no passkey session yet.
                        if set(payload) != {"passphrase"} or not isinstance(payload["passphrase"], str) \
                                or not payload["passphrase"]:
                            answer = lambda: self._send(400, json.dumps({"error": "Passphrase is empty."}),
                                                        content_type="application/json")
                        else:
                            answer = lambda: self._unseal(payload)
                    elif self.path == "/seal" and self.app.seal is not None:
                        self.app.auth.session(token, authenticated=True)
                        if payload:
                            raise ConsoleDenied("Invalid seal request")
                        answer = lambda: self._seal()
                    else:
                        answer = lambda: self._send(404, "Not found")
            answer()
        except (ConsoleDenied, ValueError, UnicodeError):
            self._send(403, '{"error":"Request denied"}', content_type="application/json")
        except Exception:
            self._send(503, '{"error":"Console temporarily unavailable"}', content_type="application/json")


    def _put(self, fields: dict) -> None:
        try:
            result = self.app.put(fields["project"] + "/" + fields["name"], fields["value"].encode("utf-8"),
                                  secret_class=fields["secret_class"], kind=fields["kind"], note=fields["note"])
        except SealError:
            self._send(409, json.dumps({"error": "The vault is sealed. Unseal it with twadmin in your own "
                                        "SSH session, then try again."}), content_type="application/json")
            return
        except StoreError as exc:
            self._send(400, json.dumps({"error": str(exc)}), content_type="application/json")
            return
        self._json({"ok": True, "path": result["path"], "version": result["version_no"]})


    def _unseal(self, payload: dict) -> None:
        try:
            self.app.unseal(payload["passphrase"])
        except SealError as exc:
            if exc.code == "E_AUTH":
                self._send(403, json.dumps({"error": "Passphrase not accepted."}), content_type="application/json")
            else:
                self._send(409, json.dumps({"error": str(exc)}), content_type="application/json")
            payload["passphrase"] = ""
            return
        activated = self.app.config.active
        if not activated and self.app.config.has_envelope():
            # The passphrase just unsealed the vault; the same factor activates the saved passkey.
            try:
                result = self.app.config.prepare_enrollment(payload["passphrase"])
                if result.get("enrollment_required"):
                    # No passkey enrolled yet: first enrollment stays an SSH ceremony (the code must
                    # reach the operator's own terminal), so do not leave enrollment open from here.
                    self.app.config.close()
                else:
                    activated = True
            except ConsoleDenied:
                activated = False
        payload["passphrase"] = ""
        self._json({"ok": True, "seal_state": "unsealed", "console_active": activated})

    def _seal(self) -> None:
        self.app.seal()
        self._json({"ok": True, "seal_state": "sealed"})

    def _reveal(self, fields: dict) -> None:
        try:
            self.app.check_passphrase(fields["passphrase"])
        except SealError as exc:
            if exc.code == "E_AUTH":
                self._send(403, json.dumps({"error": "Passphrase not accepted."}), content_type="application/json")
            else:
                self._send(409, json.dumps({"error": str(exc)}), content_type="application/json")
            return
        finally:
            fields["passphrase"] = ""
        try:
            value = self.app.reveal(fields["path"], fields["reason"])
        except SealError as exc:
            self._send(409, json.dumps({"error": str(exc)}), content_type="application/json")
            return
        except StoreError as exc:
            self._send(400, json.dumps({"error": str(exc)}), content_type="application/json")
            return
        try:
            body = {"ok": True, "path": fields["path"], "value": value.decode("utf-8"), "encoding": "text"}
        except UnicodeDecodeError:
            body = {"ok": True, "path": fields["path"], "value": base64.b64encode(value).decode("ascii"),
                    "encoding": "base64"}
        self._json(body)


class ConsoleServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False
    request_queue_size = 16
    _CONNECTION_SECONDS = 5
    _JOIN_SECONDS = 5

    def __init__(self, app: ConsoleApplication, *, port=8787):
        if port not in {0, 8787}:
            raise ValueError("Console port must be 8787 (or ephemeral for isolated tests)")
        self.app = app
        self.capacity = threading.BoundedSemaphore(32)
        self.serving = threading.Event()
        self._lifecycle = threading.RLock()
        self._close_lock = threading.Lock()
        self._closing = False
        self._connections = {}
        self._workers = set()
        # Operator-visible counters. log_message and handle_error stay silent
        # about request content, so counted events replace log lines.
        self.expired_interrupted: collections.Counter[str] = collections.Counter()
        self.unexpected_errors = 0
        super().__init__(("127.0.0.1", port), ConsoleHandler, bind_and_activate=False)

    def bind(self):
        self.server_bind()
        self.server_activate()

    def serve_forever(self, poll_interval=0.1):
        with self._lifecycle:
            if self._closing:
                return
            self.serving.set()
        try:
            super().serve_forever(poll_interval)
        finally:
            self.serving.clear()

    def process_request(self, request, client_address):
        with self._lifecycle:
            if self._closing or not self.capacity.acquire(blocking=False):
                self.shutdown_request(request)
                return
            # One absolute budget covers socket reads and response writes.
            # Socket timeouts alone can be renewed by partial input indefinitely.
            # It does NOT cover a handler blocked on the global auth lock, which is
            # bounded only by the _JOIN_SECONDS join at shutdown. That hold is now
            # narrow: session validation, challenge generation and passkey
            # verification. It is never held across metadata.snapshot() or a
            # response write, so a slow page load no longer stalls every user or
            # either bounded path.
            attempt = _Attempt()
            timer = threading.Timer(self._CONNECTION_SECONDS, self._expire, args=(request,))
            timer.daemon = True
            timer.owner = attempt
            self._connections[request] = timer
            worker = threading.Thread(target=self.process_request_thread,
                                      args=(request, client_address), daemon=self.daemon_threads)
            self._workers.add(worker)
            try:
                timer.start()
                worker.start()
            except Exception:
                self._workers.discard(worker)
                self._retire(request)
                raise

    @staticmethod
    def _interrupt(request):
        try:
            request.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    @staticmethod
    def _stop_reading(request):
        # Unblocks this side's read so the worker can return and release its
        # capacity slot. Measured on Darwin, SHUT_RD also ends the client's
        # stream, so the client may never see the 503 that follows. That is why
        # an interrupted request is counted in expired_interrupted: the status
        # line is best effort, the record is not.
        try:
            request.shutdown(socket.SHUT_RD)
        except OSError:
            pass

    # Everything shared here is guarded by _lifecycle, the same lock admission
    # and retirement use, so a timer cannot race a handler that is answering.
    def _expire(self, request):
        with self._lifecycle:
            # Keep the socket object, never its reusable integer descriptor.
            timer = self._connections.get(request)
            if timer is not None:
                attempt = timer.owner
                attempt.expired = True
                if attempt.status_written:
                    # Mid-response: the client already has a status line, so a
                    # cut body is visible rather than silent. Stop the worker.
                    self._interrupt(request)
                elif attempt.reading:
                    # Blocked on the request line, a header or a declared body.
                    # Unblock the read. The client never sent a whole request, so
                    # it may never see the answer; retirement records the event.
                    attempt.interrupted = True
                    self._stop_reading(request)
                elif attempt.dispatched:
                    # A handler is running. Leave the socket alone: it answers
                    # 503 itself when it returns. A handler inside a metadata
                    # read holds no auth lock now, so the remaining wait is a
                    # passkey verification; closing the socket here would only
                    # turn a visible stall into silence.
                    pass
                else:
                    attempt.interrupted = True
                    self._stop_reading(request)

    def _retire(self, request):
        with self._lifecycle:
            timer = self._connections.pop(request, None)
            if timer is not None:
                timer.cancel()
                self.capacity.release()
                owner = timer.owner
                if owner.expired and (owner.interrupted or not owner.status_written):
                    # Counted, never logged with request content. Covers both a
                    # deadline that had to interrupt an incomplete request and
                    # an answer that never reached the wire. If the handler could
                    # answer, it already did, inside handle().
                    self.expired_interrupted[owner.stalled_op or "request"] += 1

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._retire(request)
            with self._lifecycle:
                self._workers.discard(threading.current_thread())

    def handle_error(self, request, client_address):
        # Reachable only for a failure outside do_GET/do_POST (both catch
        # Exception themselves). Record it: a missing log line must never be
        # the reason a console failure goes unnoticed.
        with self._lifecycle:
            self.unexpected_errors += 1

    def close(self):
        with self._close_lock:
            with self._lifecycle:
                self._closing = True
                serving = self.serving.is_set()
                for request, timer in self._connections.items():
                    timer.cancel()
                    self._interrupt(request)
            if serving:
                self.shutdown()
            with self._lifecycle:
                workers = list(self._workers)
            # Share one finite join budget. _CONNECTION_SECONDS bounds socket I/O
            # and response writes only, so this join is the only bound on a
            # handler blocked on the auth lock. Metadata reads and response
            # writes no longer hold that lock; passkey verification and its
            # config save still do. Both raises below are deliberate: they
            # report that the auth state could not be quiesced in time.
            deadline = time.monotonic() + self._JOIN_SECONDS
            for worker in workers:
                worker.join(max(0, deadline - time.monotonic()))
            self.server_close()
            # Wipe decision (deliberate): a clean shutdown clears the sessions and
            # zeroes the config key, credentials and enrollment digest. The two
            # timeout paths below deliberately leave the key in memory instead.
            # Those raises only happen while a worker is still inside do_GET or
            # do_POST holding the auth lock, so it may be reading the config as we
            # return; wiping under it would zero memory mid-operation. The vault
            # seal and store teardown have already run in Broker.close and do not
            # depend on this wipe. A supervisor that catches TimeoutError and keeps
            # the process alive gets a closed listener, a cancelled timer and
            # nothing else: the key and credentials stay resident, sessions stay
            # valid, and the config is never reopened. Treat that process as
            # compromised and restart it rather than keeping it in service.
            if any(worker.is_alive() for worker in workers):
                raise TimeoutError("Console workers did not stop within the shutdown budget")
            if not self.app.auth.lock.acquire(timeout=max(0, deadline - time.monotonic())):
                raise TimeoutError("Console auth state remained busy during shutdown")
            try:
                self.app.auth.sessions.clear()
                self.app.config.close()
            finally:
                self.app.auth.lock.release()
