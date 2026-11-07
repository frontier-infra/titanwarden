"""Signed cloud request preparation and bounded HTTPS transport.

The injected transport sends raw body bytes to the public URL. Its response does
not establish policy authority. Ambiguous writes require reconciliation before a
caller may explicitly prepare a retry with the same logical request id.
"""
from __future__ import annotations

import os
import re
import uuid
import http.client
import ipaddress
import ssl
import socket
import threading
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, urlsplit

from . import crypto
from .cloud_wire import org_id as checked_org
from .policy_log import utc_millis, PolicyError
from . import cloud_wire as wire

TW_HEADERS = ("TW-Broker", "TW-Date", "TW-Nonce", "TW-Request-Id", "TW-Sig")
MAX_BODY = 3 * 1024 * 1024
_UUID4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")


def public_origin(value):
    """Persist an origin only, never URL credentials, paths or query strings."""
    u = urlsplit(value)
    if (u.scheme != 'https' or not u.hostname or u.username is not None
            or u.password is not None or u.path not in ('', '/') or u.query or u.fragment
            or re.search(r'[\x00-\x20\x7f\\]', value)
            or u.hostname.lower() == 'localhost' or u.hostname.lower().endswith(('.localhost', '.local'))):
        raise ValueError('public HTTPS origin required')
    try:
        address = ipaddress.ip_address(u.hostname)
    except ValueError:
        if '.' not in u.hostname:
            raise ValueError('public HTTPS origin required') from None
    else:
        if not address.is_global:
            raise ValueError('public HTTPS origin required')
    _ = u.port
    return 'https://' + u.netloc.lower()


class HTTPSTransport:
    """One raw HTTPS attempt, bounded reads and no redirect handling."""
    def __init__(self, origin, *, timeout=15, connection_factory=None):
        self.origin = public_origin(origin)
        self.budget = None
        self.timeout = timeout
        self.connection_factory = connection_factory or http.client.HTTPSConnection

    def __call__(self, request):
        u = urlsplit(request.url)
        if public_origin('https://' + u.netloc) != self.origin or u.scheme != 'https' or u.fragment:
            raise ValueError('cloud request origin differs')
        if not isinstance(request.body, bytes) or len(request.body) > MAX_BODY:
            raise ValueError('invalid or oversized body')
        budget = self.budget
        if budget is not None:budget.check()
        remaining = self.timeout if budget is None else min(self.timeout, budget.deadline-budget.monotonic())
        connection = self.connection_factory(u.hostname, u.port or 443,
            timeout=remaining, context=ssl.create_default_context())
        active_socket=[None]
        def expire():
            # Interrupt even a peer trickling headers or body inside one read.
            sock = active_socket[0] or connection.sock
            if sock is not None:
                try:sock.shutdown(socket.SHUT_RDWR)
                except OSError:pass
            connection.close()
        timer = threading.Timer(remaining, expire)
        timer.daemon = True
        timer.start()
        try:
            headers = dict(request.headers)
            headers['Content-Type'] = 'application/json'
            connection.request(request.method, u.path + ('?' + u.query if u.query else ''),
                body=request.body, headers=headers)
            active_socket[0] = connection.sock
            response = connection.getresponse()
            if 300 <= response.status < 400:
                raise ValueError('cloud redirects are refused')
            if response.status >= 400:
                code = 'E_DENIED' if response.status in (401,403,404) else 'E_SYNC_RETRY'
                raise CloudResponseError(code,'cloud service refused request')
            declared = response.getheader('Content-Length')
            if declared is not None and (not declared.isdecimal() or int(declared) > MAX_BODY):
                raise ValueError('oversized cloud response')
            body = response.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:
                raise ValueError('oversized cloud response')
            if budget is not None:budget.check()
            return response.status, body
        except (OSError, http.client.HTTPException) as exc:
            raise CloudResponseError('E_SYNC_RETRY', 'cloud transport unavailable') from exc
        finally:
            timer.cancel()
            connection.close()

    def enroll(self, body):
        request = SignedRequest(self.origin + '/v1/enroll', 'POST', (), crypto.canonical_json(body))
        return decode_response(*self(request))


class CloudResponseError(PolicyError):
    """A cloud refusal is a transport result, never verified policy evidence."""


def decode_response(status, body):
    if type(status) is not int or not 100 <= status <= 599 or not isinstance(body, bytes) or len(body) > MAX_BODY:
        raise ValueError('invalid cloud HTTP response')
    value = wire._json_object(body)
    if value.get('ok') is False:
        wire.exact(value, ('ok', 'code', 'error', 'next'))
        if status < 400 or not isinstance(value['code'], str) or not value['code'].startswith('E_') or not isinstance(value['error'], str) or not isinstance(value['next'], str):
            raise ValueError('invalid cloud refusal envelope')
        raise CloudResponseError(value['code'], value['error'])
    wire.exact(value, ('ok', 'code', 'result'))
    if value['ok'] is not True or not 200 <= status < 300 or value['code'] != 'ok':
        raise ValueError('invalid cloud success envelope')
    return value['result']


def request_id(value: str) -> str:
    if not isinstance(value, str) or not _UUID4.fullmatch(value):
        raise ValueError("lowercase UUIDv4 request id required")
    return value


def request_url(url: str, org: str) -> tuple[str, list[tuple[str, str]]]:
    checked_org(org)
    u = urlsplit(url)
    if (u.scheme != "https" or not u.hostname or u.username is not None
            or u.password is not None or u.fragment or "#" in url
            or re.search(r"[\x00-\x20\x7f\\]", url)
            or not u.path.startswith(f"/v1/orgs/{org}/")
            or re.search(r"%(?![0-9A-Fa-f]{2})", url)
            or any(part in (".", "..") for part in u.path.split("/"))
            or re.search(r"%2e", u.path, re.I)):
        raise ValueError("invalid public org URL")
    # Accessing port also rejects malformed/out-of-range ports.
    _ = u.port
    query = parse_qsl(u.query, keep_blank_values=True, encoding="utf-8", errors="strict")
    if len({k for k, _ in query}) != len(query):
        raise ValueError("repeated decoded broker query key")
    # WHATWG URL path percent-encode set, matching cloud new URL(...).pathname.
    # Preserve valid escapes and path punctuation that WHATWG leaves literal.
    path = quote(u.path, safe="!$%&'()*+,-./:;=@_~[]|", encoding='utf-8', errors='strict')
    return path, query


def canonical_body(method: str, body: bytes) -> object:
    if not isinstance(body, bytes) or len(body) > MAX_BODY:
        raise ValueError("invalid or oversized body")
    if method in ("GET", "HEAD"):
        if body:
            raise ValueError("GET/HEAD requires empty body")
        return {}
    return crypto.parse_canonical(body)


@dataclass(frozen=True)
class SignedRequest:
    url: str
    method: str
    headers: tuple[tuple[str, str], ...]
    body: bytes

    def forwarding(self) -> dict:
        """Exact Worker-to-Org transport shape, for recorded compatibility tests."""
        result = dict(url=self.url, method=self.method, headers=dict(self.headers))
        if self.method not in ("GET", "HEAD"):
            result["body_b64"] = crypto.b64url(self.body)
        return result


def verify_request(request: SignedRequest, org: str, broker: str, public: bytes, now: str) -> bytes:
    """Admission-compatible local check; does not consume the server's nonce."""
    if request.method not in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"):
        raise ValueError("invalid method")
    path, query = request_url(request.url, org)
    h = dict(request.headers)
    if len(request.headers) != 5 or set(h) != set(TW_HEADERS) or h["TW-Broker"] != broker:
        raise ValueError("exact five TW headers required")
    request_id(h["TW-Request-Id"])
    if len(crypto.unb64url(h["TW-Nonce"])) != 16:
        raise ValueError("nonce must contain 16 bytes")
    if abs(utc_millis(h["TW-Date"]) - utc_millis(now)) > 300000:
        raise ValueError("request date outside admission window")
    canonical_body(request.method, request.body)
    message = crypto.request_context(org, broker, request.method, path, query,
        h["TW-Request-Id"], h["TW-Date"], h["TW-Nonce"], crypto.sha256(request.body).hex())
    if not crypto.p256_verify(public, message, crypto.unb64url(h["TW-Sig"])):
        raise ValueError("request signature differs")
    return message


class SignedClient:
    """Explicit one-attempt transport; no hidden retry of a signed write."""
    def __init__(self, org: str, broker: str, signing_key, *, clock, transport=None):
        checked_org(org)
        crypto.context(broker)
        self.org, self.broker, self._signing_key = org, broker, signing_key
        self._clock, self._transport = clock, transport
        self.budget = None
        self._logical_requests = {}

    def prepare(self, method: str, url: str, body=None, *, logical_id: str | None = None) -> SignedRequest:
        method = method.upper()
        path, query = request_url(url, self.org)
        if method not in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"):
            raise ValueError("invalid method")
        if method in ("GET", "HEAD"):
            if body is not None:
                raise ValueError("GET/HEAD requires no logical body")
            raw = b""
        else:
            raw = crypto.canonical_json({} if body is None else body)
        canonical_body(method, raw)
        rid, date, nonce = request_id(str(uuid.uuid4()) if logical_id is None else logical_id), self._clock(), crypto.b64url(os.urandom(16))
        utc_millis(date)
        identity = (method, url, raw)
        prior = self._logical_requests.get(rid)
        if prior is not None and prior != identity:
            raise ValueError('logical request retry changed method, URL or body')
        self._logical_requests[rid] = identity
        message = crypto.request_context(self.org, self.broker, method, path, query, rid, date, nonce, crypto.sha256(raw).hex())
        headers = tuple(zip(TW_HEADERS, (self.broker, date, nonce, rid, crypto.b64url(crypto.p256_sign(self._signing_key, message)))))
        return SignedRequest(url, method, headers, raw)

    def send_once(self, request: SignedRequest):
        verify_request(request, self.org, self.broker, crypto.export_point(self._signing_key.public_key()), self._clock())
        if self._transport is None:
            raise RuntimeError("no cloud transport configured")
        return self._transport(request)

    def send_http(self, request: SignedRequest):
        """Explicit raw HTTP adapter: injected transport returns (status, bytes)."""
        if self.budget is not None:self.budget.check()
        status, body = self.send_once(request)
        if self.budget is not None:self.budget.response(len(body))
        result = decode_response(status, body)
        if self.budget is not None:self.budget.count(result)
        return result
