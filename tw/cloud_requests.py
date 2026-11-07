"""Strict offline request transitions and the single policy-rules router.

Facts must be obtained from independently verified predecessor state. This module
has no HTTP, timer, persistence or production broker entry point.
"""

import re
from copy import deepcopy
from datetime import datetime, timedelta, timezone

from tw import cloud_wire as wire
from tw import crypto
from tw.cloud_policy import AuthorityView, require
from tw.policy_log import PolicyError, utc_millis

REQUEST_KINDS = frozenset(
    ("request_open", "request_decide", "request_default", "policy_rules")
)
BASELINES = {
    "own": (0, 604800, True),
    "shared_standard": (3600, 604800, True),
    "other_standard": (3600, 86400, True),
    "cross_sensitive": (3600, 14400, True),
    "restricted": (0, 14400, False),
    "client": (0, 14400, False),
    "create": (0, 604800, True),
    "rotate": (0, 14400, False),
}


def iso(ms):
    value = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=ms)
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def timestamp(value):
    require(
        isinstance(value, str)
        and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", value),
        "Invalid request timestamp",
    )
    return utc_millis(value)


def text(value):
    require(
        isinstance(value, str) and value.strip() and len(value) <= 4096,
        "Invalid request text",
    )
    return value


def operations(value):
    require(
        isinstance(value, list)
        and 1 <= len(value) <= 4
        and all(v in ("audit", "inject", "put", "use") for v in value)
        and len(set(value)) == len(value),
        "Parsed operations required",
    )
    return sorted(value)


def target_path(value):
    text(value)
    require(
        len(value) <= 512
        and re.fullmatch(r"[-a-z0-9_]+(?:/[-a-z0-9_.]+)+", value)
        and not any(s in (".", "..") for s in value.split("/")),
        "Exact target required",
    )
    return value


def request_identifier(value):
    require(
        isinstance(value, str) and re.fullmatch(r"req_[a-z2-7]{12}", value),
        "Canonical request id required",
    )
    return value


def request_grant_id(value):
    return "grt_" + request_identifier(value)[4:]


def parse_request(value):
    r = deepcopy(
        wire.exact(
            value,
            (
                "request_id",
                "principal_id",
                "token_id",
                "kind",
                "target",
                "ops",
                "reason",
                "ttl_seconds",
            ),
        )
    )
    request_identifier(r["request_id"])
    text(r["principal_id"])
    if r["token_id"] is not None:
        text(r["token_id"])
    require(r["kind"] in ("access", "create", "rotate"), "Invalid request kind")
    r["target"] = target_path(r["target"])
    r["ops"] = operations(r["ops"])
    text(r["reason"])
    require(1 <= wire.integer(r["ttl_seconds"]) <= 604800, "Invalid request TTL")
    return r


def baseline_rules():
    return {
        k: dict(
            enabled=e,
            delay_seconds=d,
            ttl_cap_seconds=t,
            ops=["put"]
            if k in ("create", "rotate")
            else ["audit", "inject", "put", "use"],
        )
        for k, (d, t, e) in BASELINES.items()
    }


def tighten_rules(value):
    wire.exact(value, (), tuple(BASELINES))
    result, baselines = {}, baseline_rules()
    for name, raw in value.items():
        r = wire.exact(raw, ("enabled", "delay_seconds", "ttl_cap_seconds", "ops"))
        base = baselines[name]
        allowed = operations(r["ops"])
        require(
            type(r["enabled"]) is bool
            and (not r["enabled"] or base["enabled"])
            and wire.integer(r["delay_seconds"]) >= base["delay_seconds"]
            and 1 <= wire.integer(r["ttl_cap_seconds"]) <= base["ttl_cap_seconds"]
            and set(allowed) <= set(base["ops"]),
            "Rules may only tighten",
        )
        result[name] = dict(r, ops=allowed)
    return result


def stricter(a, b):
    if not a or not b or not a["enabled"] or not b["enabled"]:
        return None
    allowed = sorted(set(a["ops"]) & set(b["ops"]))
    return (
        dict(
            enabled=True,
            delay_seconds=max(a["delay_seconds"], b["delay_seconds"]),
            ttl_cap_seconds=min(a["ttl_cap_seconds"], b["ttl_cap_seconds"]),
            ops=allowed,
        )
        if allowed
        else None
    )


def row_for(request, context):
    t, p = context["target"], context["principal"]
    if t["client_approval_required"]:
        return "client"
    if t["class"] == "restricted":
        return "restricted"
    if request["kind"] == "rotate":
        return "rotate"
    if request["kind"] == "create":
        return "create" if t["project"] == p["project"] else "restricted"
    if t["class"] == "sensitive" and t["project"] == "shared":
        return "cross_sensitive"
    if t["project"] == p["project"]:
        return "own"
    if t["class"] == "sensitive":
        return "cross_sensitive"
    return "shared_standard" if t["project"] == "shared" else "other_standard"


def assert_live(request, c):
    p, t, token = c["principal"], c["target"], c["token"]
    require(
        type(c["now"]) is int
        and p["active"] is True
        and p["id"] == request["principal_id"]
        and t["active"] is True
        and t["path"] == request["target"]
        and t["project"] == request["target"].split("/")[0]
        and (
            request["token_id"] is None
            or token
            and token["active"] is True
            and token["id"] == request["token_id"]
            and token["principal_id"] == request["principal_id"]
        ),
        "Inactive request subject",
    )


def opening_rule(request, context):
    name = row_for(request, context)
    return stricter(baseline_rules()[name], tighten_rules(context["rules"]).get(name))


def derive_default(body, opened, context):
    b = wire.exact(body, ("request_id",))
    r = parse_request(opened["request"])
    assert_live(r, context)
    require(
        b["request_id"] == r["request_id"]
        and opened["origin"] != "agent"
        and type(opened["open_seq"]) is int
        and opened["open_seq"] >= 1
        and opened["state"] == "open"
        and context["policy_fresh"] is True,
        "Request cannot default",
    )
    effective = stricter(opened["rule"], opening_rule(r, context))
    require(effective is not None, "No default policy")
    deadline = timestamp(opened["opened_at"]) + effective["delay_seconds"] * 1000
    require(
        opened["default_at"] is not None
        and timestamp(opened["default_at"]) == deadline
        and context["now"] > deadline,
        "Default deadline mismatch",
    )
    allowed = sorted(set(r["ops"]) & set(effective["ops"]))
    expiry = deadline + min(r["ttl_seconds"], effective["ttl_cap_seconds"]) * 1000
    require(allowed and context["now"] < expiry, "Empty or expired default grant")
    return dict(
        principal_id=r["principal_id"],
        pattern=r["target"],
        ops=allowed,
        max_class=context["target"]["class"],
        expires_at=iso(expiry),
    )


def maximum_policy_age(value):
    require(type(value) is int and 300 <= value <= 86400, "Invalid maximum policy age")
    return value


def restricted_policy_fresh(age, last_pull, now):
    try:
        return (
            type(last_pull) is int
            and type(now) is int
            and 0 <= last_pull <= now
            and now - last_pull < maximum_policy_age(age) * 1000
        )
    except ValueError:
        return False


def member_may_decide(cert, principal, target, facts):
    if cert["member_id"] in (principal["id"], principal.get("member_id")):
        return False
    if cert["role"] in ("owner", "admin"):
        return True
    if (
        target["class"] == "restricted"
        or target["client_approval_required"]
        or target["class"] == "sensitive"
        and (target["project"] == "shared" or target["project"] != principal["project"])
    ):
        return False
    return (
        cert["role"] == "approver"
        and target["class"] == "standard"
        or cert["role"] == "member"
        and target["project"] in facts["managed_projects"].get(cert["member_id"], [])
    )


class RequestReplay:
    """Copy this object with the authority/epoch candidate for atomic replay."""

    def __init__(self):
        self.requests = {}
        self.grants = {}
        self.rules = {}
        self.max_policy_age = None
        self.sources = {}
        self.used_challenges = []
        self.request_rows = {}
        self.grant_rows = {}

    def resolve_key(self, entry, state):
        view, signer = AuthorityView(state), entry["signer"]
        cert = view.current(signer.get("id")) if signer["kind"] == "member" else None
        cert = (
            cert["certificate"]
            if cert
            else view.broker_certificate_at(signer.get("id"), state["head"])
            if signer["kind"] == "broker"
            else None
        )
        require(
            cert
            and cert["state"] == "active"
            and (
                signer["kind"] != "member" or cert["member_key_id"] == signer.get("key")
            ),
            "Certified request signer required",
        )
        return crypto.unb64url(cert["sign_pub"])

    def _context(self, request, state, facts, runtime):
        require(facts["head"] == state["head"], "Request facts predecessor mismatch")
        p = next(
            (p for p in facts["principals"] if p["id"] == request["principal_id"]), None
        )
        t = next((t for t in facts["targets"] if t["path"] == request["target"]), None)
        token = next(
            (t for t in facts["tokens"] if t["id"] == request["token_id"]), None
        )
        require(p and t, "Unknown request subject")
        if request["kind"] == "create":
            require(
                p["project"] == request["target"].split("/")[0]
                and isinstance(facts.get("existing_paths"), list)
                and request["target"] not in facts["existing_paths"]
                and t.get("prospective") is True,
                "Create requires absent own-project target and verified project policy",
            )
        now = utc_millis(runtime["now"])
        fresh = self.max_policy_age is not None and runtime["mode"] == "history"
        if runtime["mode"] != "history":
            pull = facts.get("last_verified_pull_at", {}).get(p.get("broker_id"))
            broker = AuthorityView(state).broker_certificate_at(
                p.get("broker_id"), state["head"]
            )
            fresh = bool(
                pull
                and broker
                and pull["head"] == state["head"]
                and (broker["scope"] == "full" or t["project"] in broker["scope"])
                and restricted_policy_fresh(self.max_policy_age, pull["at"], now)
            )
        c = dict(
            now=now,
            principal=p,
            token=token,
            target=t,
            rules=self.rules,
            policy_fresh=fresh,
        )
        assert_live(request, c)
        return c

    def apply(self, entry, state, facts, runtime):
        try:
            return self._apply(entry, state, facts, runtime)
        except PolicyError:
            raise
        except (ValueError, KeyError, TypeError) as exc:
            raise PolicyError("E_REQUEST", str(exc)) from exc

    def _apply(self, entry, state, facts, runtime):
        require(
            entry["org_id"] == state["org_id"]
            and entry["seq"] == state["head"]["seq"] + 1
            and entry["prev_hash"] == state["head"]["hash"],
            "Request predecessor mismatch",
        )
        spent = list(dict.fromkeys(state["used_challenges"] + self.used_challenges))
        kind, b = entry["kind"], entry["body"]
        derived = entry["signer"]["kind"] == "derived"
        signer = entry["signer"]
        view = AuthorityView(state)
        cert = view.current(signer.get("id")) if signer["kind"] == "member" else None
        cert = cert["certificate"] if cert else None
        if cert:
            require(
                cert["state"] == "active"
                and cert["member_key_id"] == signer.get("key"),
                "Active member signer required",
            )
        if kind == "policy_rules":
            variant = b.get("variant")
            require(
                variant in ("request_rules", "maximum_policy_age"),
                "Unknown policy variant",
            )
            field = "request_rules" if variant == "request_rules" else "max_policy_age"
            try:
                wire.exact(b, ("variant", field, "request_id", "authz", "assertion"))
            except ValueError as exc:
                raise ValueError("Unexpected request fields") from exc
            require(
                not derived and cert and cert["role"] == "owner",
                "Owner maximum-age signer required"
                if variant == "maximum_policy_age"
                else "Owner rules signer required",
            )
            value = (
                tighten_rules(b[field])
                if field == "request_rules"
                else maximum_policy_age(b[field])
            )
            self.used_challenges.append(
                wire.verify_authorization(
                    entry, cert, dict(policy=variant), spent, runtime
                )
            )
            if field == "request_rules":
                self.rules = value
            else:
                self.max_policy_age = value
            return
        if kind == "request_open":
            wire.exact(b, ("request", "default_at"))
            r = parse_request(b["request"])
            require(
                not derived
                and r["request_id"] not in self.requests
                and timestamp(entry["ts"]) <= timestamp(runtime["received_at"]),
                "Duplicate or invalid signed open",
            )
            if runtime["mode"] == "live":
                inbox = facts.get("open_inbox")
                require(isinstance(inbox, list), "Verified open inbox unavailable")
                require(
                    not any(
                        parse_request(row["request"])["request_id"] == r["request_id"]
                        for row in inbox
                    ),
                    "Duplicate request",
                )
            c = self._context(r, state, facts, runtime)
            broker = (
                view.broker_certificate_at(signer.get("id"), state["head"])
                if signer["kind"] == "broker"
                else None
            )
            require(
                cert
                and cert["key_holder"]
                or broker
                and c["principal"].get("broker_id") == broker["broker_id"]
                and (
                    broker["scope"] == "full"
                    or c["target"]["project"] in broker["scope"]
                ),
                "Broker request outside ownership or scope"
                if signer["kind"] == "broker"
                else "Key holder open required",
            )
            rule = opening_rule(r, c)
            delay = (
                rule["delay_seconds"] * 1000
                if rule and self.max_policy_age is not None
                else None
            )
            require(
                b["default_at"]
                == (iso(timestamp(entry["ts"]) + delay) if delay is not None else None),
                "Signed default deadline mismatch",
            )
            self.requests[r["request_id"]] = dict(
                request=r,
                opened_by=dict(kind=signer["kind"], id=signer["id"]),
                origin=signer["kind"],
                opened_at=runtime["received_at"],
                open_seq=entry["seq"],
                default_at=iso(timestamp(runtime["received_at"]) + delay)
                if delay is not None
                else None,
                rule=rule,
                state="open",
            )
            self.sources[r["request_id"]] = deepcopy(entry)
            self._request_row(self.requests[r["request_id"]], c)
            return
        if kind == "request_default":
            wire.exact(b, ("request_id",))
            opened = self.requests.get(b["request_id"])
            require(derived and opened, "Derived default requires signed request")
            r = opened["request"]
            c = self._context(r, state, facts, runtime)
            source = self.sources[r["request_id"]]
            opener = source["signer"]
            if opener["kind"] == "member":
                current = view.current(opener["id"])
                original = view.certificate_at(opener["key"], opened["open_seq"])
                require(
                    current
                    and original
                    and current["certificate"]["state"] == "active"
                    and current["certificate"]["key_holder"]
                    and current["certificate"]["member_key_id"] == opener["key"]
                    and wire.rank(current["certificate"]["role"])
                    >= wire.rank(original["role"]),
                    "Member opener no longer eligible",
                )
            else:
                broker = view.broker_certificate_at(opener["id"], state["head"])
                require(
                    broker
                    and c["principal"].get("broker_id") == broker["broker_id"]
                    and (
                        broker["scope"] == "full"
                        or c["target"]["project"] in broker["scope"]
                    ),
                    "Broker open no longer authorized",
                )
            require(
                timestamp(entry["ts"]) > timestamp(opened["default_at"]),
                "Default deadline mismatch",
            )
            grant = derive_default(b, opened, c)
            self._grant(grant, opened, facts, entry)
            opened["state"] = "defaulted"
            self._request_row(opened, c, "default", entry["ts"])
            return
        require(kind == "request_decide" and not derived, "Unknown request transition")
        wire.exact(
            b,
            (
                "request_id",
                "decision",
                "reason",
                "grant",
                "request",
                "client_approval_ref",
            ),
            ("authz", "assertion"),
        )
        require(b["decision"] in ("approve", "deny"), "Invalid request decision")
        text(b["reason"])
        opened = self.requests.get(b["request_id"])
        require(not opened or opened["state"] == "open", "Request already terminal")
        if opened and opened["origin"] != "agent":
            require(b["request"] is None, "Signed request cannot be restated")
        else:
            r = parse_request(b["request"])
            require(r["request_id"] == b["request_id"], "Restatement request mismatch")
            if runtime["mode"] == "live":
                inbox = facts.get("open_inbox")
                require(isinstance(inbox, list), "Verified open inbox unavailable")
                require(
                    any(
                        row["state"] == "open" and parse_request(row["request"]) == r
                        for row in inbox
                    ),
                    "No matching open agent inbox request",
                )
            if opened:
                require(opened["request"] == r, "Agent restatement differs")
            opened = dict(
                request=r,
                origin="agent",
                opened_at=entry["ts"],
                open_seq=None,
                default_at=None,
                rule=None,
                state="open",
            )
        r = opened["request"]
        c = self._context(r, state, facts, runtime)
        t, p = c["target"], c["principal"]
        if cert:
            require(
                not (
                    opened.get("opened_by", {}).get("kind") == "member"
                    and opened["opened_by"]["id"] == cert["member_id"]
                )
                and cert["member_id"] not in (p["id"], p.get("member_id")),
                "Self decision forbidden",
            )
            require(
                member_may_decide(cert, p, t, facts),
                "Member cannot decide request class",
            )
            if (
                t["class"] == "restricted"
                or t["client_approval_required"]
                or "authz" in b
                or "assertion" in b
            ):
                self.used_challenges.append(
                    wire.verify_authorization(
                        entry, cert, dict(request_id=b["request_id"]), spent, runtime
                    )
                )
        else:
            broker = (
                view.broker_certificate_at(signer.get("id"), state["head"])
                if signer["kind"] == "broker"
                else None
            )
            require(
                opened["origin"] != "agent"
                and broker
                and broker["local_admin_approvals"]
                and t["class"] == "restricted"
                and not t["client_approval_required"]
                and p.get("broker_id") == broker["broker_id"]
                and (broker["scope"] == "full" or t["project"] in broker["scope"])
                and "authz" not in b
                and "assertion" not in b,
                "Broker approval forbidden",
            )
        if t["client_approval_required"] and b["decision"] == "approve":
            text(b["client_approval_ref"])
        else:
            require(b["client_approval_ref"] is None, "Unexpected client reference")
        if b["decision"] == "deny":
            require(b["grant"] is None, "Denial contains grant")
        else:
            if r["kind"] == "rotate":
                raise PolicyError(
                    "E_ROTATION_UNAVAILABLE",
                    "Rotation decision integration unavailable",
                )
            g = wire.exact(
                b["grant"],
                ("principal_id", "pattern", "ops", "max_class", "expires_at"),
            )
            allowed = operations(g["ops"])
            expiry = timestamp(g["expires_at"])
            require(
                g["principal_id"] == r["principal_id"]
                and g["pattern"] == r["target"]
                and g["max_class"] == t["class"]
                and set(allowed) <= set(r["ops"])
                and (r["kind"] != "create" or allowed == ["put"])
                and c["now"]
                < expiry
                <= min(timestamp(entry["ts"]), c["now"]) + r["ttl_seconds"] * 1000,
                "Manual grant exceeds request or server-clock bound",
            )
            self._grant(dict(g, ops=allowed), opened, facts, entry)
        opened["state"] = "approved" if b["decision"] == "approve" else "denied"
        self.requests[r["request_id"]] = opened
        self._request_row(opened, c, signer["id"], entry["ts"])

    def _request_row(self, opened, context, decider=None, decided_at=None):
        r = opened["request"]
        name = row_for(r, context)
        needs = (
            "client"
            if name == "client"
            else "admin"
            if name in ("restricted", "cross_sensitive", "rotate")
            else "policy"
            if name in ("own", "create")
            else "approver"
        )
        self.request_rows[r["request_id"]] = dict(
            request_id=r["request_id"],
            principal_id=r["principal_id"],
            kind=r["kind"],
            target=r["target"],
            ops=crypto.canonical_json(r["ops"]).decode(),
            reason=r["reason"],
            ttl=str(r["ttl_seconds"]),
            needs=needs,
            default_decision="approve" if opened["default_at"] is not None else None,
            default_at=opened["default_at"],
            state=opened["state"],
            decided_by=decider,
            decided_at=decided_at,
            created_at=opened["opened_at"],
            policy_seq=opened["open_seq"],
            origin=opened["origin"],
            request_json=crypto.canonical_json(r).decode(),
            open_rule_json=crypto.canonical_json(opened["rule"]).decode()
            if opened["rule"] is not None
            else None,
            open_signer_json=crypto.canonical_json(opened["opened_by"]).decode()
            if opened.get("opened_by")
            else None,
        )

    def _grant(self, grant, opened, facts, entry):
        require(
            isinstance(facts.get("grants"), list),
            "Verified existing grant set unavailable",
        )
        ident = request_grant_id(opened["request"]["request_id"])
        require(
            ident not in self.grants
            and not any(
                g.get("grant_id") == ident
                or g.get("request_id") == opened["request"]["request_id"]
                for g in facts.get("grants", [])
            ),
            "Request grant collides with existing policy",
        )
        self.grants[ident] = deepcopy(grant)
        self.grant_rows[ident] = dict(
            grant_id=ident,
            principal_id=grant["principal_id"],
            pattern=grant["pattern"],
            ops=crypto.canonical_json(grant["ops"]).decode(),
            conditions_json=crypto.canonical_json(
                dict(max_class=grant["max_class"])
            ).decode(),
            effect="allow",
            granted_by="default"
            if entry["signer"]["kind"] == "derived"
            else entry["signer"]["id"],
            reason=opened["request"]["reason"],
            request_id=opened["request"]["request_id"],
            created_at=entry["ts"],
            expires_at=grant["expires_at"],
            revoked_at=None,
        )
