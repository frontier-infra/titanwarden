"""Offline recovery, typed credential bindings and composed request replay.

Only verified log prefixes confer authority. External blobs and immutable reset
receipts are checked against that prefix; private slot bytes never enter state.
This verifier is opt-in and has no production broker caller or persistence.
"""

import inspect
import json
from copy import deepcopy

from tw import cloud_policy as policy
from tw import cloud_wire as wire
from tw import crypto
from tw.cloud_policy import AuthorityEvidence, AuthorityView, require
from tw.cloud_requests import REQUEST_KINDS, RequestReplay, iso, maximum_policy_age
from tw.policy_log import OfflineCloudVerifier, PolicyError, PolicyHooks, utc_millis

SLOT_KINDS = frozenset(
    (
        "member_slot_add",
        "member_slot_disable",
        "member_slot_delete",
        "member_slot_enable",
    )
)
RECOVERY_KINDS = SLOT_KINDS | {"member_key_reset_cancel", "recovery_set"}
DAY = 86400000


def recovery_state(state):
    return state.get(
        "recovery_protocol", dict(v=1, claims={}, slots=[], used_recovery_sign_keys=[])
    )


def mutable(state):
    if "recovery_protocol" not in state:
        state["recovery_protocol"] = recovery_state(state)
    return state["recovery_protocol"]


def normalize(state):
    if "recovery_protocol" not in state:
        return
    protocol = mutable(state)
    for i, slot in enumerate(protocol["slots"]):
        if slot.get("initial") and slot["deleted"]:
            protocol["slots"][i] = {
                k: deepcopy(slot[k])
                for k in (
                    "slot_id",
                    "member_key_id",
                    "slot_digest",
                    "initial",
                    "initial_policy_seq",
                    "initial_commitment_kind",
                    "policy_seq",
                    "disabled_at",
                    "deleted",
                )
            }
            protocol["slots"][i].update(kind=None, params={})
    protocol["slots"].sort(key=lambda s: (s["slot_id"], s["member_key_id"]))


def advance(state, entry):
    normalize(state)
    state["head"] = dict(seq=entry["seq"], hash=wire.hash_object(entry))
    return state


def descriptor(value, cert, ts):
    slot = wire.parse_slot_descriptor(value)
    require(
        slot["member_key_id"] == cert["member_key_id"],
        "Invalid slot owner or commitment",
    )
    require(
        slot["kind"] != "webauthn_prf"
        or any(
            p["credential_id"] == slot["params"]["credential_id"]
            for p in cert["passkeys"]
        ),
        "Uncertified slot credential",
    )
    return dict(slot, created_at=ts, disabled_at=None, deleted=False)


def require_usable_slots(slots, cert):
    if cert["state"] != "active":
        return
    usable = [
        s
        for s in slots
        if s["member_key_id"] == cert["member_key_id"]
        and not s["deleted"]
        and s["disabled_at"] is None
    ]
    require(
        usable
        and (
            not cert["key_holder"]
            or any(
                s["kind"] == "webauthn_prf"
                and any(
                    p["credential_id"] == s["params"]["credential_id"]
                    for p in cert["passkeys"]
                )
                for s in usable
            )
        ),
        "Last usable slot or passkey slot",
    )


def recovery_point_set(state):
    r = recovery_state(state)
    return set(
        r["used_recovery_sign_keys"]
        + r.get("used_recovery_exchange_keys", [])
        + (list(state["recovery"].values()) if state["recovery"] else [])
    )


def assert_fresh_key_set(state, subject, next_cert, recovery=None):
    history = [
        v["certificate"]
        for v in state["certificates"]
        if v["certificate"]["member_id"] == subject
    ]
    old = {c[k] for c in history for k in ("sign_pub", "kx_pub")} | recovery_point_set(
        state
    )
    points = [wire.point(next_cert[k]) for k in ("sign_pub", "kx_pub")]
    require(
        not any(
            v["certificate"]["member_key_id"] == next_cert["member_key_id"]
            for v in state["certificates"]
        )
        and len(set(points)) == 2
        and not set(points) & old,
        "New member keys reuse prior key material",
    )
    ids = {p["credential_id"] for c in history for p in c["passkeys"]}
    keys = {wire.cose_point(p["cose_key"]) for c in history for p in c["passkeys"]}
    require(
        next_cert["passkeys"]
        and not any(
            p["credential_id"] in ids or wire.cose_point(p["cose_key"]) in keys
            for p in next_cert["passkeys"]
        ),
        "Reset passkeys must be fresh against subject history",
    )
    if recovery:
        points += [wire.point(recovery[k]) for k in ("sign_pub", "kx_pub")]
        require(
            len(set(points)) == 4 and not set(points) & old,
            "Recovery and member keys must be mutually fresh",
        )


def changes_certified_key(entry, state):
    if entry["kind"] not in ("member_cert", "cert_proposal"):
        return False
    requested = entry["body"].get("requested")
    if not isinstance(requested, dict) or requested.get("kind") != "member":
        return False
    cert = requested.get("certificate")
    if not isinstance(cert, dict):
        return False
    prior = AuthorityView(state).current(cert.get("member_id"))
    return bool(
        prior
        and any(
            prior["certificate"][k] != cert.get(k)
            for k in ("member_key_id", "sign_pub", "kx_pub", "passkeys")
        )
    )


def checked_reset_evidence(value, reset_id, subject, state, received_at):
    r = wire.exact(
        value,
        (
            "reset_id",
            "subject_member_id",
            "admin_member_id",
            "admin_cert_seq",
            "sas_transcript_digest",
            "verified_at",
        ),
    )
    require(
        r["reset_id"] == reset_id
        and r["subject_member_id"] == subject["member_id"]
        and r["admin_member_id"] != subject["member_id"],
        "Reset SAS subject or transcript differs",
    )
    wire.digest(r["sas_transcript_digest"])
    utc_millis(r["verified_at"])
    wire.integer(r["admin_cert_seq"], 1)
    require(r["verified_at"] == received_at, "Reset SAS admission time differs")
    version = AuthorityView(state).current(r["admin_member_id"])
    require(
        version
        and version["seq"] == r["admin_cert_seq"] <= state["head"]["seq"]
        and version["certificate"]["state"] == "active"
        and version["certificate"]["role"] in ("owner", "admin"),
        "Certified independent reset admin required",
    )
    return deepcopy(r)


def independent_recovery_endorser(generator, subject, member):
    return isinstance(generator, str) and generator != member and subject != member


def recovery_session_allows(mode, action):
    return action in (
        "bind_passkey",
        "unwrap_omk",
        "sign_policy",
        "reveal",
        "export",
    ) and (
        mode == "normal" or mode == "passphrase_recovery" and action == "bind_passkey"
    )


def verify_subject_proofs(entry, cert, permitted=None):
    proofs = wire.exact(
        entry["body"]["assertion"], ("authorization", "possession", "subject_signature")
    )
    context = wire.passkey_binding_context(entry)
    require(
        crypto.p256_verify(
            crypto.unb64url(cert["sign_pub"]),
            context,
            wire.binary(proofs["subject_signature"], 64),
        ),
        "Subject member signature failed",
    )
    require(
        isinstance(proofs["possession"], list) and 1 <= len(proofs["possession"]) <= 32,
        "Missing possession proof",
    )
    permitted = cert["passkeys"] if permitted is None else permitted
    seen = set()
    for assertion in proofs["possession"]:
        credential = next(
            (
                p
                for p in permitted
                if p["credential_id"] == assertion.get("credential_id")
            ),
            None,
        )
        require(
            credential and credential["credential_id"] not in seen,
            "Unexpected or duplicate possession credential",
        )
        wire.verify_assertion(assertion, credential, crypto.sha256(context))
        seen.add(credential["credential_id"])
    return proofs, seen


def possession_authorization(entry, cert, used, runtime):
    # Only the independently checked subject proof substitutes the outer paper
    # signature. All ordinary Authz bindings still use the proposed identity.
    return wire.verify_possession_authorization(
        entry, cert, dict(member_id=cert["member_id"]), used, runtime
    )


class RecoveryEvidence(AuthorityEvidence):
    """Retained private bytes plus independently authenticated SAS gate verifier.

    The SAS callback is a trusted local port, never a callback from a cloud row.
    Historical replay uses immutable locally retained acceptance receipts; live
    admission always authenticates both independently supplied typed gates.
    """

    def __init__(
        self, rows=None, blobs=None, *, reset_sas_verifier=None, request_facts=None
    ):
        super().__init__(rows, blobs)
        self.reset_sas_verifier = reset_sas_verifier
        self.request_facts = deepcopy(request_facts)

    def slot_blob(self, slot):
        row = self._one(
            "recovery_slot_blobs",
            lambda r: (
                r.get("slot_id") == slot["slot_id"]
                and r.get("member_key_id", slot["member_key_id"])
                == slot["member_key_id"]
            ),
            blobs=True,
        )
        if row is None:
            row = self._one(
                "member_slots",
                lambda r: (
                    r.get("slot_id") == slot["slot_id"]
                    and r.get("member_key_id", slot["member_key_id"])
                    == slot["member_key_id"]
                ),
                blobs=True,
            )
        require(row is not None, "Missing committed slot ciphertext")
        blob = {k: row[k] for k in ("slot_id", "wrapped_priv", "nonce")}
        for k in ("wrapped_priv", "nonce"):
            if isinstance(blob[k], bytes):
                blob[k] = crypto.b64url(blob[k])
        wire.parse_slot_blob(blob)
        if wire.slot_blob_digest(blob) != slot["slot_digest"]:
            raise PolicyError("Error", "Slot ciphertext commitment mismatch")
        return blob

    def reset_sas(self, entry, before, cert, runtime, binding, verified_states):
        reset_id = binding["reset_id"]
        row = self._one(
            "recovery_pending_resets", lambda r: r.get("reset_id") == reset_id
        )
        require(
            row
            and row["member_id"] == cert["member_id"]
            and row["old_cert_seq"]
            == AuthorityView(before).current(cert["member_id"])["seq"],
            "Pending reset predecessor mismatch",
        )
        now = utc_millis(runtime["received_at"])
        require(
            utc_millis(row["created_at"]) <= now < utc_millis(row["expires_at"])
            and utc_millis(row["expires_at"]) - utc_millis(row["created_at"])
            == 7 * DAY,
            "Reset expired at admission",
        )
        candidate = wire.parse_signed_entry(json.loads(row["request_json"]))
        require(
            crypto.canonical_json(candidate).decode() == row["request_json"],
            "Noncanonical pending reset candidate",
        )
        ce = candidate["entry"]
        cb = ce["body"]
        require(
            ce["org_id"] == before["org_id"]
            and ce["kind"] == "member_key_reset_pending"
            and cb["reset_id"] == reset_id
            and cb["prior_cert_seq"] == row["old_cert_seq"]
            and cb["certificate"] == cert,
            "Pending reset candidate mismatch",
        )
        candidate_state = verified_states.get(ce["seq"] - 1)
        require(
            candidate_state and candidate_state["head"]["hash"] == ce["prev_hash"],
            "Pending reset requires verified predecessor",
        )
        verify_pending_reset(candidate, candidate_state, row["created_at"])
        receipt = self._one(
            "recovery_reset_proposals",
            lambda r: (
                r.get("proposal_hash") == entry["body"].get("proposal_hash")
                if entry["kind"] == "cert_activate"
                else r.get("proposal_seq") == entry["seq"]
            ),
        )
        history = runtime["mode"] == "history"
        if history or entry["kind"] == "cert_activate":
            require(
                receipt
                and receipt["reset_id"] == reset_id
                and receipt["member_id"] == cert["member_id"]
                and receipt["old_cert_seq"] == row["old_cert_seq"],
                "Immutable reset acceptance required",
            )
            require(
                receipt["candidate_json"] == row["request_json"]
                and receipt["candidate_created_at"] == row["created_at"]
                and receipt["expires_at"] == row["expires_at"]
                and utc_millis(receipt["accepted_at"]) <= now,
                "Immutable reset candidate differs",
            )
        if history:
            if entry["kind"] == "cert_activate":
                stage = self._one(
                    "recovery_reset_activations",
                    lambda r: (
                        r.get("activation_seq") == entry["seq"]
                        and r.get("proposal_hash") == entry["body"]["proposal_hash"]
                    ),
                )
                require(
                    stage
                    and stage["reset_id"] == reset_id
                    and stage["entry_json"] == crypto.canonical_json(entry).decode()
                    and stage["accepted_at"] == runtime["received_at"],
                    "Immutable reset activation required",
                )
                evidence = json.loads(stage["sas_evidence_json"])
            else:
                require(
                    receipt["entry_json"] == crypto.canonical_json(entry).decode()
                    and receipt["accepted_at"] == runtime["received_at"],
                    "Immutable reset acceptance required",
                )
                evidence = json.loads(receipt["sas_evidence_json"])
            expected = checked_reset_evidence(
                evidence, reset_id, cert, before, runtime["received_at"]
            )
            context = crypto.sas_context(
                before["org_id"],
                before["root"],
                "member_key",
                cert["member_key_id"],
                cert["sign_pub"],
                cert["kx_pub"],
            )
            require(
                expected["sas_transcript_digest"] == crypto.sha256(context).hex(),
                "Immutable reset SAS transcript differs",
            )
            return expected
        require(
            row["state"] == "pending" and callable(self.reset_sas_verifier),
            "Independent typed SAS gate verifier unavailable",
        )
        sas_binding = dict(
            org_id=before["org_id"],
            org_root=before["root"],
            reset_id=reset_id,
            member_id=cert["member_id"],
            prior_cert_seq=row["old_cert_seq"],
            member_key_id=cert["member_key_id"],
            sign_pub=cert["sign_pub"],
            kx_pub=cert["kx_pub"],
        )
        proof = self.reset_sas_verifier(deepcopy(sas_binding))

        if inspect.isawaitable(proof):
            if inspect.iscoroutine(proof):
                proof.close()
            raise ValueError("Typed SAS gates require a synchronous offline verifier")
        wire.exact(proof, ("binding", "invitee", "admin"))
        invitee = wire.exact(proof["invitee"], ("member_key_id", "local_typed_match"))
        admin_proof = wire.exact(proof["admin"], ("member_key_id", "local_typed_match"))
        admin = AuthorityView(before).certificate_at(
            admin_proof["member_key_id"], before["head"]["seq"]
        )
        require(
            proof["binding"] == sas_binding
            and invitee["member_key_id"] == cert["member_key_id"]
            and invitee["local_typed_match"] is True
            and admin_proof["local_typed_match"] is True
            and admin
            and admin["member_id"] != cert["member_id"]
            and admin["state"] == "active"
            and admin["role"] in ("owner", "admin"),
            "Independent typed SAS gates differ",
        )
        context = crypto.sas_context(
            before["org_id"],
            before["root"],
            "member_key",
            cert["member_key_id"],
            cert["sign_pub"],
            cert["kx_pub"],
        )
        actual = dict(
            reset_id=reset_id,
            subject_member_id=cert["member_id"],
            admin_member_id=admin["member_id"],
            admin_cert_seq=AuthorityView(before).current(admin["member_id"])["seq"],
            sas_transcript_digest=crypto.sha256(context).hex(),
            verified_at=runtime["received_at"],
        )
        return checked_reset_evidence(
            actual, reset_id, cert, before, runtime["received_at"]
        )

    def claim_wrap(self, ref, *, proposal_hash=None, required=True):
        if proposal_hash:
            row = self._one(
                "recovery_claim_member_wraps",
                lambda r: r.get("proposal_hash") == proposal_hash,
            ) or self._one(
                "recovery_claim_member_wraps",
                lambda r: r.get("proposal_hash") == proposal_hash,
                blobs=True,
            )
            if row:
                wrap = json.loads(row["payload_json"])
            else:
                wrap = None
        else:
            wrap = None
        if wrap is None:
            row = self._one(
                "org_key_wraps",
                lambda r: (
                    r.get("recipient_kind") == "member_key"
                    and r.get("recipient_id") == ref["recipient"]["id"]
                    and r.get("omk_generation") == ref["omk_generation"]
                ),
                blobs=True,
            )
            wrap = (
                {
                    k: row[k]
                    for k in (
                        "omk_generation",
                        "recipient_kind",
                        "recipient_id",
                        "eph_pub",
                        "nonce",
                        "wrapped_omk",
                        "wrap_digest",
                    )
                }
                if row
                else None
            )
        require(
            wrap is not None or not required, "Private claim member wrap unavailable"
        )
        if wrap is None:
            return None
        wrap = deepcopy(wrap)
        for k in ("eph_pub", "nonce", "wrapped_omk", "wrap_digest"):
            if isinstance(wrap[k], bytes):
                wrap[k] = wrap[k].hex()
        wire.exact(
            wrap,
            (
                "omk_generation",
                "recipient_kind",
                "recipient_id",
                "eph_pub",
                "nonce",
                "wrapped_omk",
                "wrap_digest",
            ),
        )
        try:
            digest = self._wrap_digest(wrap, "wrapped_omk")
        except ValueError as exc:
            if str(exc) == "Retained wrap digest differs":
                raise ValueError("Substituted wrap") from exc
            raise
        require(
            wrap["recipient_kind"] == "member_key"
            and wrap["recipient_id"] == ref["recipient"]["id"]
            and wrap["omk_generation"] == ref["omk_generation"]
            and digest == ref["recipient"]["wrap_digest"],
            "Private member wrap does not match claim",
        )
        return wrap


def verify_pending_reset(signed, state, received_at):
    signed = wire.parse_signed_entry(signed)
    e = signed["entry"]
    b = wire.exact(
        e["body"],
        (
            "reset_id",
            "prior_cert_seq",
            "certificate",
            "slot",
            "request_id",
            "authz",
            "assertion",
        ),
    )
    cert = wire.parse_certificate(b["certificate"], state["org_id"])
    prior = AuthorityView(state).current(cert["member_id"])
    require(
        e["kind"] == "member_key_reset_pending"
        and e["org_id"] == state["org_id"]
        and e["signer"]
        == dict(kind="member", id=cert["member_id"], key=cert["member_key_id"])
        and e["seq"] == state["head"]["seq"] + 1
        and e["prev_hash"] == state["head"]["hash"],
        "Pending reset predecessor mismatch",
    )
    wire.text(b["reset_id"])
    wire.integer(b["prior_cert_seq"], 1)
    require(
        prior and b["prior_cert_seq"] == prior["seq"],
        "Pending reset certificate predecessor mismatch",
    )
    old = prior["certificate"]
    require(
        cert["state"] == "active"
        and all(
            old[k] == cert[k]
            for k in ("member_id", "workos_user_id", "role", "reveal", "key_holder")
        )
        and cert["cert_no"] == old["cert_no"] + 1,
        "Pending reset changes authority",
    )
    assert_fresh_key_set(state, cert["member_id"], cert)
    slot = descriptor(b["slot"], cert, e["ts"])
    require(slot["kind"] == "webauthn_prf", "Reset requires PRF slot")
    require(
        abs(utc_millis(e["ts"]) - utc_millis(received_at)) <= 300000
        and crypto.p256_verify(
            crypto.unb64url(cert["sign_pub"]),
            crypto.policy_context(e["org_id"], wire.hash_object(e)),
            wire.binary(signed["sig"], 64),
        ),
        "Pending reset signature or time differs",
    )
    possession_authorization(
        e, cert, state["used_challenges"], dict(mode="history", now=received_at)
    )
    return deepcopy(cert)


class RecoveryVerifier(OfflineCloudVerifier):
    """Opt-in B6/B7 verifier; the original B1-B3 verifier stays unchanged."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._records = []
        self._history_states = {0: self.state}
        self._operational = RecoveryOperations()
        self._reset_proposals = {}
        self._reset_activations = {}
        self._requests = RequestReplay()
        self._candidate_requests = None

    @property
    def operational_state(self):
        with self._lock:
            return deepcopy(
                dict(
                    pending_resets=self._operational.pending,
                    session_reports=self._operational.session_reports,
                    reserved_slots=sorted(self._operational.reserved_slots),
                )
            )

    @property
    def request_state(self):
        with self._lock:
            return deepcopy(
                dict(
                    requests=self._requests.requests,
                    grants=self._requests.grants,
                    rules=self._requests.rules,
                    max_policy_age=self._requests.max_policy_age,
                )
            )

    def verify_operational(self, signed, received_at, *, evidence):
        """Verify a pending reset or session without advancing signed authority."""
        with self._lock:
            require(
                not self.conflict and isinstance(evidence, RecoveryEvidence),
                "Operational verified predecessor required",
            )
            candidate = deepcopy(self._operational)
            self._active_evidence = evidence
            try:
                entry = wire.parse_signed_entry(signed)["entry"]
                if entry["kind"] == "member_key_reset_pending":
                    row = candidate.submit_pending(
                        signed,
                        self.state,
                        received_at,
                        evidence,
                        reserve=lambda slot: self._reserve_descriptor(slot, self.state),
                        initial_slots=self._initial_slots(self.state),
                    )
                    result = dict(reset_id=row["reset_id"], state="pending")
                elif entry["kind"] == "member_recovery_session":
                    result = candidate.report_session(
                        signed, self.state, received_at, self._initial_slots(self.state)
                    )
                else:
                    raise ValueError("Unsupported operational record")
                self._operational = candidate
                return result
            finally:
                self._active_evidence = None

    def synchronize_operations(self, now):
        """Reconcile local candidates with verified cancellations and activations."""
        with self._lock:
            self._operational.synchronize(self.state, now)
            return dict(synchronized=True)

    def pending_claim_wrap(self, proposal_hash, now, *, evidence):
        with self._lock:
            require(
                not self.conflict and isinstance(evidence, RecoveryEvidence),
                "Verified claim evidence required",
            )
            claim = recovery_state(self.state)["claims"].get(proposal_hash)
            require(
                claim
                and claim_wrap_pending(
                    claim, self.state, self.epoch_state["generation"], utc_millis(now)
                ),
                "Claim member wrap no longer pending",
            )
            return evidence.claim_wrap(
                claim["member_wrap"], proposal_hash=proposal_hash
            )

    def cleanup_claim_staging(self, now, *, evidence):
        """Return pruned in-memory private staging; retain all signed tombstones."""
        with self._lock:
            require(
                not self.conflict and isinstance(evidence, RecoveryEvidence),
                "Verified claim evidence required",
            )
            state = self.state
            protocol = recovery_state(state)
            rows, blobs = deepcopy(evidence._rows), deepcopy(evidence._blobs)
            claims = protocol["claims"]
            generation = self.epoch_state["generation"]
            remove = {
                r["proposal_hash"]
                for r in rows.get("recovery_claim_member_wraps", [])
                if r["proposal_hash"] in claims
                and not claim_wrap_pending(
                    claims[r["proposal_hash"]], state, generation, utc_millis(now)
                )
            }
            live = {
                (s["slot_id"], s["member_key_id"])
                for s in protocol["slots"]
                if not s["deleted"]
            }
            for claim in claims.values():
                if claim_wrap_pending(claim, state, generation, utc_millis(now)):
                    live.add((claim["slot"]["slot_id"], claim["slot"]["member_key_id"]))
            for digest, binding in protocol.get("bindings", {}).items():
                proposal = state["proposals"].get(digest)
                if proposal and not proposal["cancelled"] and not proposal["activated"]:
                    live.update(
                        (s["slot_id"], s["member_key_id"]) for s in binding["slots"]
                    )
            for pending in list(self._operational.pending.values()) + rows.get(
                "recovery_pending_resets", []
            ):
                if pending["state"] == "pending":
                    slot = json.loads(pending["request_json"])["entry"]["body"]["slot"]
                    live.add((slot["slot_id"], slot["member_key_id"]))
            retired = {
                (claims[h]["slot"]["slot_id"], claims[h]["slot"]["member_key_id"])
                for h in remove
            } - live
            for table in (rows, blobs):
                table["recovery_claim_member_wraps"] = [
                    r
                    for r in table.get("recovery_claim_member_wraps", [])
                    if r["proposal_hash"] not in remove
                ]
                table["recovery_slot_blobs"] = [
                    r
                    for r in table.get("recovery_slot_blobs", [])
                    if (r["slot_id"], r.get("member_key_id")) not in retired
                ]
            return dict(removed=len(remove)), RecoveryEvidence(
                rows,
                blobs,
                reset_sas_verifier=evidence.reset_sas_verifier,
                request_facts=evidence.request_facts,
            )

    def recovery_wrap(self, *, evidence):
        """Serve only ciphertext committed to current recovery by a full epoch."""
        with self._lock:
            require(
                not self.conflict and isinstance(evidence, RecoveryEvidence),
                "Verified recovery evidence required",
            )
            state, epochs = self.state, self.epoch_state
            recovery = state["recovery"]
            current = next(
                (
                    e
                    for e in reversed(epochs["epochs"])
                    if e["kind"] == "full" and e["generation"] == epochs["generation"]
                ),
                None,
            )
            if (
                not recovery
                or not current
                or current["kind"] != "full"
                or current["commit_seq"] <= state["recovery_seq"]
                or current["generation"] != epochs["generation"]
            ):
                raise PolicyError(
                    "E_RECOVERY_NOT_READY", "Current full recovery epoch unavailable"
                )
            source = next(
                (e for e in self._records if e["seq"] == current["seq"]), None
            )
            require(
                source and source["kind"] in ("epoch_init", "epoch_rotate"),
                "Verified recovery epoch source missing",
            )
            recipients = deepcopy(source["body"]["recipients"])
            if "recipients_count" in source["body"]:
                pages = [
                    e
                    for e in self._records
                    if current["seq"] < e["seq"] < current["commit_seq"]
                    and e["kind"] == "epoch_recipients"
                    and e["body"]["epoch_seq"] == current["seq"]
                ]
                for page, e in enumerate(pages, 1):
                    require(
                        e["body"]["page"] == page and e["signer"] == source["signer"],
                        "Recovery recipient page differs",
                    )
                    recipients.extend(e["body"]["items"])
                require(
                    len(recipients) == source["body"]["recipients_count"]
                    and wire.hash_object(recipients)
                    == source["body"]["recipients_sha256"],
                    "Recovery recipient commitment differs",
                )
            recipient = [r for r in recipients if r["kind"] == "recovery"]
            if (
                len(recipient) != 1
                or recipient[0]["id"] != "recovery"
                or recipient[0]["kx_pub_sha256"]
                != crypto.sha256(crypto.unb64url(recovery["kx_pub"])).hex()
            ):
                raise PolicyError(
                    "E_RECOVERY_NOT_READY", "Recovery epoch names an old recipient"
                )
            wrap = next(
                (
                    w
                    for w in epochs["org_wraps"]
                    if w["omk_generation"] == epochs["generation"]
                    and w["recipient_kind"] == "recovery"
                    and w["recipient_id"] == "recovery"
                ),
                None,
            )
            require(
                wrap and wrap["wrap_digest"] == recipient[0]["wrap_digest"],
                "Recovery wrap commitment differs",
            )
            row = evidence._one(
                "org_key_wraps",
                lambda r: (
                    r.get("omk_generation") == epochs["generation"]
                    and r.get("recipient_kind") == "recovery"
                    and r.get("recipient_id") == "recovery"
                ),
                blobs=True,
            )
            require(
                row
                and evidence._wrap_digest(row, "wrapped_omk") == wrap["wrap_digest"],
                "Recovery wrap bytes unavailable",
            )
            for field in ("eph_pub", "nonce", "wrapped_omk"):
                require(
                    (row[field].hex() if isinstance(row[field], bytes) else row[field])
                    == wrap[field],
                    "Recovery wrap bytes differ",
                )
            return dict(
                omk_generation=epochs["generation"],
                wrap=deepcopy(wrap),
                recovery_kx_pub=recovery["kx_pub"],
                recovery_sign_pub=recovery["sign_pub"],
            )

    def _snapshot(self, state, epochs):
        snapshot = super()._snapshot(state, epochs)
        # Cloud keeper tenure follows continuous member eligibility, including a
        # certified reset to a fresh key. It does not restart at the new key id.
        for member in snapshot["members"]:
            since = None
            for version in state["certificates"]:
                cert = version["certificate"]
                if cert["member_id"] != member["member_id"]:
                    continue
                if cert["state"] == "active" and cert["key_holder"]:
                    if since is None:
                        since = version["seq"]
                else:
                    since = None
            member["keeper_since_seq"] = since
        return snapshot

    def _evidence(self):
        require(
            isinstance(self._active_evidence, RecoveryEvidence),
            "Typed recovery evidence unavailable",
        )
        evidence = deepcopy(self._active_evidence)
        for table, values, key in (
            ("recovery_pending_resets", self._operational.pending, "reset_id"),
            ("recovery_reset_proposals", self._reset_proposals, "proposal_hash"),
            ("recovery_reset_activations", self._reset_activations, "activation_seq"),
        ):
            rows = evidence._rows.setdefault(table, [])
            for row in values.values():
                if not any(r.get(key) == row[key] for r in rows):
                    rows.append(deepcopy(row))
        return evidence

    def _generation(self, state):
        value = self._candidate_epochs.view(
            self._snapshot(state, self._candidate_epochs)
        ).committed_generation(state["head"])
        require(
            value["kind"] == "committed", "Current committed generation unavailable"
        )
        return value["generation"]

    def _initial_slots(self, state):
        result = []
        evidence = self._evidence()
        for cert, digest, kind, metadata in self._initial_references:
            source = next(
                (v for v in state["certificates"] if v["certificate"] == cert), None
            )
            if not source:
                continue
            raw = evidence._matching_slot(cert, digest, kind, metadata)
            if raw is None:
                continue
            result.append(
                dict(
                    slot_id=raw["slot_id"],
                    member_key_id=cert["member_key_id"],
                    kind=raw["kind"],
                    params=raw["params"],
                    disabled_at=None,
                    deleted=False,
                    initial=True,
                    policy_seq=source["seq"],
                    initial_policy_seq=source["seq"],
                    slot_digest=digest,
                    initial_commitment_kind=kind,
                )
            )
        return result

    def _merge_initial(self, state):
        slots = mutable(state)["slots"]
        for initial in self._initial_slots(state):
            require(
                not any(
                    s["slot_id"] == initial["slot_id"]
                    and s["member_key_id"] != initial["member_key_id"]
                    for s in slots
                ),
                "Slot id belongs to another member key",
            )
            if not any(
                s["slot_id"] == initial["slot_id"]
                and s["member_key_id"] == initial["member_key_id"]
                for s in slots
            ):
                slots.append(initial)

    def _handles(self, entry, state):
        b, kind = entry["body"], entry["kind"]
        protocol = recovery_state(state)
        if kind in RECOVERY_KINDS or changes_certified_key(entry, state):
            return True
        if kind == "cert_proposal" and entry["signer"]["kind"] == "recovery":
            return True
        if (
            kind in ("cert_endorse", "cert_cancel", "cert_activate")
            and b.get("proposal_hash") in protocol["claims"]
        ):
            return True
        if kind == "cert_activate" and b.get("proposal_hash") in protocol.get(
            "bindings", {}
        ):
            return True
        return False

    def _resolve_key(self, entry, state):
        if entry["kind"] in REQUEST_KINDS:
            return self._candidate_requests.resolve_key(entry, state)
        if entry["signer"]["kind"] == "recovery" and entry["kind"] == "cert_proposal":
            require(
                entry["signer"] == dict(kind="recovery", id="recovery")
                and state["recovery"],
                "Certified recovery signer required",
            )
            return crypto.unb64url(state["recovery"]["sign_pub"])
        if entry["kind"] in RECOVERY_KINDS:
            try:
                actor = policy._actor(entry, state)
            except ValueError as exc:
                raise ValueError("Active member signer required") from exc
            return crypto.unb64url(actor["sign_pub"])
        return super()._resolve_key(entry, state)

    def _authority_hooks(self):
        base = policy.authority_hooks(self._active_runtime, recovery_parity=True)
        return PolicyHooks(
            base.resolve_key,
            lambda e, s: (
                self._recovery_authorize(e, s, base)
                if self._handles(e, s)
                else base.authorize(e, s)
            ),
            lambda e, s, t: (
                self._recovery_derive(e, s, t, base)
                if self._handles(e, s)
                else base.derive(e, s, t)
            ),
        )

    def _gate(self, entry, state):
        require(
            entry["org_id"] == state["org_id"]
            and entry["seq"] == state["head"]["seq"] + 1
            and entry["prev_hash"] == state["head"]["hash"]
            and state["root"],
            "Recovery predecessor mismatch",
        )
        if self._active_runtime["mode"] == "live":
            policy.check_late_admission(
                self._active_runtime.get("observations", policy.empty_observations()),
                state["head"],
                entry["ts"],
            )

    def _reserve_descriptor(self, slot, state, *, reset_id=None):
        """Retained reservations deny reuse; they can never grant authority."""
        protocol = recovery_state(state)
        staged = [c["slot"] for c in protocol["claims"].values()]
        staged += [s for b in protocol.get("bindings", {}).values() for s in b["slots"]]
        require(
            not any(s["slot_id"] == slot["slot_id"] for s in staged),
            "Slot id already reserved",
        )
        records = list(self._operational.pending.values()) + list(
            self._evidence()._rows.get("recovery_pending_resets", [])
        )
        for row in records:
            candidate = json.loads(row["request_json"])["entry"]["body"]["slot"]
            if candidate["slot_id"] != slot["slot_id"]:
                continue
            allowed = row["reset_id"] == reset_id and candidate == {
                k: slot[k]
                for k in (
                    "slot_id",
                    "member_key_id",
                    "kind",
                    "params",
                    "label",
                    "slot_digest",
                )
            }
            require(allowed, "Slot id already reserved by reset")

    def _binding(self, entry, state):
        require("passkey_binding" in entry["body"], "Typed passkey binding required")
        self._merge_initial(state)
        b = wire.exact(
            entry["body"],
            (
                "requested",
                "passkey_binding",
                *policy.PROOF,
                *(
                    ("subject", "prior_cert_seq", "reason")
                    if entry["kind"] == "cert_proposal"
                    else ()
                ),
            ),
        )
        req = wire.exact(b["requested"], ("kind", "certificate"))
        cert = wire.parse_certificate(req["certificate"], state["org_id"])
        prior = AuthorityView(state).current(cert["member_id"])
        require(
            req["kind"] == "member"
            and prior
            and prior["certificate"]["state"] == cert["state"] == "active",
            "Active binding subject required",
        )
        old = prior["certificate"]
        reset = any(old[k] != cert[k] for k in ("member_key_id", "sign_pub", "kx_pub"))
        expected = dict(old, cert_no=old["cert_no"] + 1, passkeys=cert["passkeys"])
        if reset:
            expected.update(
                {k: cert[k] for k in ("member_key_id", "sign_pub", "kx_pub")}
            )
            assert_fresh_key_set(state, cert["member_id"], cert)
        require(expected == cert, "Binding changes unrelated authority")
        policy._identity(prior, cert, state)
        binding = wire.exact(
            b["passkey_binding"],
            ("mode", "member_id", "prior_cert_seq", "reset_id", "slots"),
        )
        require(
            binding["mode"] in ("self", "quorum")
            and binding["member_id"] == cert["member_id"]
            and wire.integer(binding["prior_cert_seq"]) == prior["seq"]
            and isinstance(binding["slots"], list),
            "Invalid typed binding",
        )
        require(
            isinstance(binding["reset_id"], str) and binding["reset_id"]
            if reset
            else binding["reset_id"] is None,
            "Binding reset id mismatch",
        )
        added = [p for p in cert["passkeys"] if p not in old["passkeys"]]
        proofs, seen = verify_subject_proofs(
            entry, cert, added or [p for p in cert["passkeys"] if p in old["passkeys"]]
        )
        require(
            all(p["credential_id"] in seen for p in added),
            "Missing added credential possession",
        )
        slots = [descriptor(s, cert, entry["ts"]) for s in binding["slots"]]
        for slot in slots:
            self._reserve_descriptor(slot, state, reset_id=binding["reset_id"])
        require(
            len({s["slot_id"] for s in slots}) == len(slots)
            and not any(
                s["slot_id"] == old["slot_id"]
                for s in slots
                for old in mutable(state)["slots"]
            ),
            "Reused binding slot id",
        )
        require(
            all(
                any(
                    s["kind"] == "webauthn_prf"
                    and s["params"]["credential_id"] == p["credential_id"]
                    for s in slots
                )
                for p in added
            ),
            "New credential needs PRF slot",
        )
        if self._active_runtime["mode"] == "live":
            require_usable_slots(mutable(state)["slots"] + slots, cert)
        actor = policy._actor(entry, state)
        self_service = binding["mode"] == "self"
        require(
            not self_service or not reset and actor["member_id"] == cert["member_id"],
            "Reset needs other certifiers",
        )
        eligible = sorted(
            c["member_id"]
            for c in AuthorityView(state).active()
            if wire.rank(c["role"]) >= 2 and c["member_id"] != cert["member_id"]
        )
        required = 2 if wire.rank(cert["role"]) >= 2 else 1
        require(
            self_service
            or actor["member_id"] in eligible
            and (required != 2 or actor["role"] == "owner"),
            "No binding certifier quorum",
        )
        auth_entry = deepcopy(entry)
        auth_entry["body"]["assertion"] = proofs["authorization"]
        challenge = wire.verify_authorization(
            auth_entry,
            actor,
            dict(member_id=cert["member_id"]),
            state["used_challenges"],
            self._active_runtime,
        )
        record = dict(
            reset=reset,
            slots=slots,
            prior_cert_seq=prior["seq"],
            reset_id=binding["reset_id"],
        )
        if reset:
            require(
                binding["reset_id"] not in mutable(state).get("cancelled_resets", {}),
                "Reset has a signed cancellation",
            )
            record["sas_evidence"] = self._evidence().reset_sas(
                entry, state, cert, self._active_runtime, record, self._history_states
            )
        state["used_challenges"].append(challenge)
        hold = not self_service and required == 2 and len(eligible) < 2
        if self_service or required == 1 and not hold:
            require(entry["kind"] == "member_cert", "Direct typed binding required")
            if reset:
                mutable(state).setdefault("bindings", {})[wire.hash_object(entry)] = (
                    record
                )
            state["certificates"].append(dict(seq=entry["seq"], certificate=cert))
            self._apply_slots(state, cert, slots, entry)
            if reset and old["key_holder"]:
                state["triggers"][str(entry["seq"])] = dict(
                    seq=entry["seq"],
                    kind="full",
                    reason="key_holder_key_reset",
                    projects=[],
                )
        else:
            require(
                entry["kind"] == "cert_proposal"
                and b["subject"] == cert["member_id"]
                and b["prior_cert_seq"] == prior["seq"],
                "Binding quorum proposal required",
            )
            digest = wire.hash_object(entry)
            member = actor["member_id"]
            state["proposals"][digest] = dict(
                hash=digest,
                seq=entry["seq"],
                ts=entry["ts"],
                subject=cert["member_id"],
                prior_cert_seq=prior["seq"],
                requested=dict(kind="member", certificate=cert),
                reason=wire.text(b["reason"]),
                eligible=eligible,
                proposer=member,
                endorsements=[member],
                signature_keys={member: actor["member_key_id"]},
                signature_seqs={member: entry["seq"]},
                signature_roles={member: actor["role"]},
                signature_ranks={member: wire.rank(actor["role"])},
                cancelled=False,
                activated=False,
                required=required,
                hold=hold,
            )
            mutable(state).setdefault("bindings", {})[digest] = record
        return advance(state, entry)

    def _apply_slots(self, state, cert, slots, entry):
        existing = mutable(state)["slots"]
        for s in existing:
            if (
                s["member_key_id"] == cert["member_key_id"]
                and s["kind"] == "webauthn_prf"
                and not s["deleted"]
                and not any(
                    p["credential_id"] == s["params"]["credential_id"]
                    for p in cert["passkeys"]
                )
            ):
                if s["disabled_at"] is None:
                    s["disabled_at"] = entry["ts"]
                s["policy_seq"] = entry["seq"]
        require(
            not any(s["slot_id"] == old["slot_id"] for s in slots for old in existing),
            "Binding slot id reused",
        )
        existing.extend(dict(s, policy_seq=entry["seq"]) for s in slots)
        if self._active_runtime["mode"] == "live":
            require_usable_slots(existing, cert)

    def _claim(self, entry, state):
        claim = mutable(state)["claims"].get(wire.text(entry["body"]["proposal_hash"]))
        require(
            claim
            and not any(
                claim[k] for k in ("cancelled", "activated", "superseded", "expired")
            ),
            "Settled recovery claim",
        )
        require(
            AuthorityView(state).current(claim["subject"])["seq"]
            == claim["prior_cert_seq"]
            and state["recovery_seq"] == claim["recovery_prior_seq"],
            "Recovery claim predecessor changed",
        )
        return claim

    def _recovery_authorize(self, entry, state, base):
        self._gate(entry, state)
        kind, b = entry["kind"], entry["body"]
        if changes_certified_key(entry, state):
            return self._binding(entry, state)
        if kind == "member_key_reset_cancel":
            wire.exact(
                b,
                ("reset_id", "member_id", "prior_cert_seq", "request_id"),
                ("authz", "assertion"),
            )
            actor = policy._actor(entry, state)
            subject = AuthorityView(state).current(wire.text(b["member_id"]))
            prior = next(
                (
                    v["certificate"]
                    for v in state["certificates"]
                    if v["seq"] == wire.integer(b["prior_cert_seq"], 1)
                    and v["certificate"]["member_id"] == b["member_id"]
                ),
                None,
            )
            require(subject and prior, "Reset cancellation identities differ")
            wire.text(b["request_id"])
            wire.text(b["reset_id"])
            own = (
                actor["member_id"] == b["member_id"]
                and actor["member_key_id"]
                == prior["member_key_id"]
                == subject["certificate"]["member_key_id"]
            )
            require(
                own
                or actor["role"] in ("owner", "admin")
                and (
                    max(
                        wire.rank(prior["role"]),
                        wire.rank(subject["certificate"]["role"]),
                    )
                    < 2
                    or actor["role"] == "owner"
                ),
                "Reset cancellation needs subject rank authority",
            )
            has_auth = "authz" in b or "assertion" in b
            require(own or has_auth, "Admin cancellation requires a passkey")
            if has_auth:
                state["used_challenges"].append(
                    wire.verify_authorization(
                        entry,
                        actor,
                        dict(member_id=b["member_id"]),
                        state["used_challenges"],
                        self._active_runtime,
                    )
                )
            mutable(state).setdefault("cancelled_resets", {})[b["reset_id"]] = dict(
                member_id=b["member_id"],
                prior_cert_seq=b["prior_cert_seq"],
                seq=entry["seq"],
            )
            for digest, binding in mutable(state).get("bindings", {}).items():
                p = state["proposals"].get(digest)
                if (
                    p
                    and binding["reset_id"] == b["reset_id"]
                    and binding["prior_cert_seq"] == b["prior_cert_seq"]
                    and p["subject"] == b["member_id"]
                    and not p["activated"]
                ):
                    p["cancelled"] = True
        elif kind in SLOT_KINDS:
            wire.exact(
                b,
                ("member_id", "slot", *policy.PROOF)
                if kind == "member_slot_add"
                else ("member_id", "slot_id", "slot_digest", *policy.PROOF),
            )
            actor = policy._actor(entry, state)
            owner = AuthorityView(state).current(wire.text(b["member_id"]))
            require(
                owner and owner["certificate"]["state"] == "active",
                "Slot owner signature required",
            )
            owner = owner["certificate"]
            require(
                actor["member_id"] == owner["member_id"]
                or kind == "member_slot_disable"
                and wire.rank(actor["role"]) >= 2,
                "Slot owner signature required",
            )
            self._merge_initial(state)
            slots = mutable(state)["slots"]
            challenge = wire.verify_authorization(
                entry,
                actor,
                dict(member_id=owner["member_id"]),
                state["used_challenges"],
                self._active_runtime,
            )
            if kind == "member_slot_add":
                slot = descriptor(b["slot"], owner, entry["ts"])
                self._reserve_descriptor(slot, state)
                require(
                    not any(s["slot_id"] == slot["slot_id"] for s in slots),
                    "Slot id reused",
                )
                slots.append(dict(slot, policy_seq=entry["seq"]))
            else:
                wire.digest(b["slot_digest"])
                wire.text(b["slot_id"])
                slot = next(
                    (
                        s
                        for s in slots
                        if s["slot_id"] == b["slot_id"]
                        and s["member_key_id"] == owner["member_key_id"]
                        and not s["deleted"]
                    ),
                    None,
                )
                if (
                    slot is None
                    and self._active_runtime["mode"] == "history"
                    and kind != "member_slot_enable"
                ):
                    refs = [
                        (c, d, k, m)
                        for c, d, k, m in self._initial_references
                        if c["member_key_id"] == owner["member_key_id"]
                        and d == b["slot_digest"]
                        and (m is None or m["slot_id"] == b["slot_id"])
                    ]
                    require(
                        len(refs) == 1, "Unknown historical initial slot commitment"
                    )
                    c, d, k, m = refs[0]
                    source = next(
                        v for v in state["certificates"] if v["certificate"] == c
                    )
                    slot = dict(
                        slot_id=b["slot_id"],
                        member_key_id=owner["member_key_id"],
                        kind=None,
                        params={},
                        slot_digest=d,
                        initial=True,
                        initial_policy_seq=source["seq"],
                        initial_commitment_kind=k,
                        policy_seq=entry["seq"],
                        disabled_at=entry["ts"]
                        if kind == "member_slot_disable"
                        else None,
                        deleted=kind == "member_slot_delete",
                    )
                    slots.append(slot)
                else:
                    require(
                        slot and slot["slot_digest"] == b["slot_digest"],
                        "Slot change commitment mismatch",
                    )
                    if kind == "member_slot_enable":
                        require(
                            slot["disabled_at"] is not None
                            and 0
                            <= utc_millis(entry["ts"]) - utc_millis(slot["disabled_at"])
                            <= 30 * DAY
                            and (
                                self._active_runtime["mode"] == "history"
                                or utc_millis(self._active_runtime["received_at"])
                                < utc_millis(slot["disabled_at"]) + 30 * DAY
                            ),
                            "Slot re-enable deadline elapsed",
                        )
                        slot["disabled_at"] = None
                    elif kind == "member_slot_disable":
                        require(slot["disabled_at"] is None, "Slot already disabled")
                        slot["disabled_at"] = entry["ts"]
                    else:
                        slot["deleted"] = True
                    slot["policy_seq"] = entry["seq"]
            if self._active_runtime["mode"] == "live":
                require_usable_slots(slots, owner)
            state["used_challenges"].append(challenge)
        elif kind == "recovery_set":
            wire.exact(b, ("recovery_kx_pub", "recovery_sign_pub", *policy.PROOF))
            actor = policy._actor(entry, state)
            privileged = [
                c for c in AuthorityView(state).active() if wire.rank(c["role"]) >= 2
            ]
            require(
                state["founder"]["mode"] == "broker"
                and not state["recovery_ever_set"]
                and not state["recovery"]
                and actor["role"] == "owner"
                and len(privileged) == 1
                and privileged[0]["member_id"] == actor["member_id"],
                "Recovery bootstrap unavailable",
            )
            wire.point(b["recovery_kx_pub"])
            wire.point(b["recovery_sign_pub"])
            policy._fresh_recovery(b, state)
            state["used_challenges"].append(
                wire.verify_authorization(
                    entry,
                    actor,
                    dict(recovery=True),
                    state["used_challenges"],
                    self._active_runtime,
                )
            )
            state.update(
                recovery=dict(
                    kx_pub=b["recovery_kx_pub"], sign_pub=b["recovery_sign_pub"]
                ),
                recovery_ever_set=True,
                recovery_seq=entry["seq"],
            )
            mutable(state)["recovery_generated_by"] = actor["member_id"]
            state["triggers"][str(entry["seq"])] = dict(
                seq=entry["seq"], kind="full", reason="recovery_rotated", projects=[]
            )
        elif kind == "cert_proposal":
            wire.exact(
                b, ("subject", "prior_cert_seq", "requested", "reason", *policy.PROOF)
            )
            r = wire.exact(
                b["requested"],
                (
                    "kind",
                    "certificate",
                    "recovery_kx_pub",
                    "recovery_sign_pub",
                    "slot",
                    "member_wrap",
                ),
            )
            require(
                entry["signer"] == dict(kind="recovery", id="recovery")
                and state["recovery"]
                and state["recovery"]["sign_pub"]
                not in mutable(state)["used_recovery_sign_keys"]
                and r["kind"] == b["reason"] == "recovery_claim",
                "Typed recovery claim required",
            )
            cert = wire.parse_certificate(r["certificate"], state["org_id"])
            prior = AuthorityView(state).current(cert["member_id"])
            policy._identity(prior, cert, state)
            require(
                prior
                and b["subject"] == cert["member_id"]
                and b["prior_cert_seq"] == prior["seq"]
                and cert["state"] == "active"
                and cert["role"] == "owner"
                and cert["key_holder"]
                and cert["passkeys"]
                and prior["certificate"]["member_key_id"] != cert["member_key_id"],
                "Recovery requires new owner keys and passkey",
            )
            policy._fresh_recovery(r, state)
            keys = dict(sign_pub=r["recovery_sign_pub"], kx_pub=r["recovery_kx_pub"])
            assert_fresh_key_set(state, cert["member_id"], cert, keys)
            ref = wire.exact(r["member_wrap"], ("omk_generation", "recipient"))
            wire.integer(ref["omk_generation"], 1)
            recipient = wire.parse_recipient(ref["recipient"])
            generation = self._generation(state)
            require(
                ref["omk_generation"] == generation
                and recipient["kind"] == "member_key"
                and recipient["id"] == cert["member_key_id"]
                and recipient["kx_pub_sha256"]
                == crypto.sha256(crypto.unb64url(cert["kx_pub"])).hex(),
                "Current member wrap commitment differs",
            )
            slot = descriptor(r["slot"], cert, entry["ts"])
            self._reserve_descriptor(slot, state)
            require(
                slot["kind"] == "webauthn_prf"
                and not any(
                    s["slot_id"] == slot["slot_id"] for s in mutable(state)["slots"]
                ),
                "Recovery requires fresh PRF slot",
            )
            proofs, seen = verify_subject_proofs(entry, cert)
            require(
                len(seen) == len(cert["passkeys"]),
                "Recovery possession credential mismatch",
            )
            auth_entry = deepcopy(entry)
            auth_entry["body"]["assertion"] = proofs["authorization"]
            state["used_challenges"].append(
                possession_authorization(
                    auth_entry, cert, state["used_challenges"], self._active_runtime
                )
            )
            digest = wire.hash_object(entry)
            eligible = sorted(
                c["member_id"]
                for c in AuthorityView(state).active()
                if wire.rank(c["role"]) >= 2 and c["member_id"] != cert["member_id"]
            )
            mutable(state)["claims"][digest] = dict(
                hash=digest,
                seq=entry["seq"],
                ts=entry["ts"],
                subject=cert["member_id"],
                prior_cert_seq=prior["seq"],
                requested=dict(kind="member", certificate=cert),
                reason="recovery_claim",
                eligible=eligible,
                proposer="recovery",
                endorsements=[],
                signature_keys={},
                signature_seqs={},
                signature_roles={},
                signature_ranks={},
                cancelled=False,
                activated=False,
                required=1,
                hold=True,
                recovery_prior_seq=state["recovery_seq"],
                recovery_sign_pub=keys["sign_pub"],
                recovery_kx_pub=keys["kx_pub"],
                slot=slot,
                member_wrap=deepcopy(ref),
                accepted_at=self._active_runtime["received_at"],
                expires_at=iso(
                    utc_millis(self._active_runtime["received_at"]) + 7 * DAY
                ),
                superseded=False,
                expired=False,
                recovery_generated_by=mutable(state).get("recovery_generated_by"),
            )
        else:
            wire.exact(b, ("proposal_hash", *policy.PROOF))
            claim = self._claim(entry, state)
            actor = policy._actor(entry, state)
            member = actor["member_id"]
            require(
                member in claim["eligible"] and wire.rank(actor["role"]) >= 2,
                "Ineligible recovery signer",
            )
            state["used_challenges"].append(
                wire.verify_authorization(
                    entry,
                    actor,
                    dict(proposal_hash=claim["hash"]),
                    state["used_challenges"],
                    self._active_runtime,
                )
            )
            if kind == "cert_cancel":
                claim["cancelled"] = True
            else:
                require(
                    kind == "cert_endorse"
                    and independent_recovery_endorser(
                        claim["recovery_generated_by"], claim["subject"], member
                    ),
                    "Recovery key generator cannot endorse claim",
                )
                require(
                    member not in claim["endorsements"],
                    "Duplicate recovery endorsement",
                )
                claim["endorsements"].append(member)
                for field, value in (
                    ("signature_keys", actor["member_key_id"]),
                    ("signature_seqs", entry["seq"]),
                    ("signature_roles", actor["role"]),
                    ("signature_ranks", wire.rank(actor["role"])),
                ):
                    claim[field][member] = value
        return advance(state, entry)

    def _recovery_derive(self, entry, state, received_at, base):
        self._gate(entry, state)
        wire.exact(entry["body"], ("proposal_hash",))
        require(
            entry["kind"] == "cert_activate"
            and entry["signer"] == dict(kind="derived"),
            "Derived recovery activation required",
        )
        digest = entry["body"]["proposal_hash"]
        binding = mutable(state).get("bindings", {}).get(digest)
        if binding:
            proposal = state["proposals"].get(digest)
            require(
                proposal and proposal["requested"]["kind"] == "member",
                "Unknown binding proposal",
            )
            cert = proposal["requested"]["certificate"]
            policy._identity(
                AuthorityView(state).current(cert["member_id"]), cert, state
            )
            if binding["reset"]:
                evidence = self._evidence().reset_sas(
                    entry,
                    state,
                    cert,
                    self._active_runtime,
                    binding,
                    self._history_states,
                )
                old = binding.get("sas_evidence")
                require(
                    old
                    and all(
                        old[k] == evidence[k]
                        for k in (
                            "reset_id",
                            "subject_member_id",
                            "sas_transcript_digest",
                        )
                    ),
                    "Reset activation SAS differs from proposal",
                )
                mutable(state).setdefault("reset_activation_evidence", {})[
                    str(entry["seq"])
                ] = evidence
            result = base.derive(entry, state, received_at)
            self._apply_slots(result, cert, binding["slots"], entry)
            return result
        claim = self._claim(entry, state)
        require(
            utc_millis(claim["accepted_at"])
            <= utc_millis(received_at)
            < utc_millis(claim["expires_at"])
            and self._generation(state) == claim["member_wrap"]["omk_generation"],
            "Recovery claim expired or superseded",
        )
        if not any(
            independent_recovery_endorser(
                claim["recovery_generated_by"], claim["subject"], m
            )
            and policy.signature_still_eligible(state, claim, m)
            for m in claim["endorsements"]
        ):
            obs = self._active_runtime.get("observations", policy.empty_observations())
            status = policy.check_hold(
                claim["ts"],
                received_at,
                obs["proposals"].get(claim["hash"]),
                self._active_runtime["now"],
            )
            self._active_runtime["audit_hold"](claim["hash"], status)
        cert = claim["requested"]["certificate"]
        prior = AuthorityView(state).current(cert["member_id"])
        policy._identity(prior, cert, state)
        if not prior["certificate"]["key_holder"] and cert["key_holder"]:
            raise PolicyError(
                "Error", "Key holder promotion requires committed wrap support"
            )
        mutable(state)["used_recovery_sign_keys"].append(state["recovery"]["sign_pub"])
        mutable(state).setdefault("used_recovery_exchange_keys", []).append(
            state["recovery"]["kx_pub"]
        )
        state["certificates"].append(dict(seq=entry["seq"], certificate=deepcopy(cert)))
        require(
            not any(
                s["slot_id"] == claim["slot"]["slot_id"]
                for s in mutable(state)["slots"]
            ),
            "Recovery slot id reused",
        )
        mutable(state)["slots"].append(dict(claim["slot"], policy_seq=entry["seq"]))
        state.update(
            recovery=dict(
                kx_pub=claim["recovery_kx_pub"], sign_pub=claim["recovery_sign_pub"]
            ),
            recovery_seq=entry["seq"],
            recovery_ever_set=True,
        )
        mutable(state)["recovery_generated_by"] = claim["subject"]
        claim["activated"] = True
        state["triggers"][str(entry["seq"])] = dict(
            seq=entry["seq"], kind="full", reason="recovery_rotated", projects=[]
        )
        wrap = self._evidence().claim_wrap(claim["member_wrap"], required=False)
        if wrap:
            existing = self._candidate_epochs._state["org_wraps"]
            prior = next(
                (
                    w
                    for w in existing
                    if all(
                        w[k] == wrap[k]
                        for k in ("recipient_id", "recipient_kind", "omk_generation")
                    )
                ),
                None,
            )
            require(prior is None or prior == wrap, "Claim bootstrap wrap collision")
            if prior is None:
                existing.append(wrap)
        return advance(state, entry)

    def _project(self, before, after, entry):
        if "recovery_protocol" not in after and not (
            entry["kind"] == "genesis" and after["founder"]["mode"] == "browser"
        ):
            return after
        protocol = mutable(after)
        if entry["kind"] == "genesis" and after["founder"]["mode"] == "browser":
            protocol["recovery_generated_by"] = after["founder"]["signer"]["id"]
        if entry["kind"] == "cert_activate":
            proposal = before["proposals"].get(entry["body"]["proposal_hash"])
            if proposal and proposal["requested"]["kind"] == "recovery_rotation":
                protocol["used_recovery_sign_keys"].append(
                    before["recovery"]["sign_pub"]
                )
                protocol.setdefault("used_recovery_exchange_keys", []).append(
                    before["recovery"]["kx_pub"]
                )
                protocol["recovery_generated_by"] = proposal["proposer"]
        for old in AuthorityView(before).active():
            current = AuthorityView(after).current(old["member_id"])
            if (
                current
                and current["certificate"]["state"] == "active"
                and current["certificate"]["member_key_id"] == old["member_key_id"]
            ):
                continue
            source = next(
                v
                for v in before["certificates"]
                if v["certificate"]["member_key_id"] == old["member_key_id"]
            )
            initial = next(
                (
                    s
                    for s in protocol["slots"]
                    if s.get("initial") and s["member_key_id"] == old["member_key_id"]
                ),
                None,
            )
            commitment, kind = (
                (initial["slot_digest"], initial["initial_commitment_kind"])
                if initial
                else (None, None)
            )
            if commitment is None:
                ref = next(
                    (
                        (d, k)
                        for c, d, k, m in self._initial_references
                        if c["member_key_id"] == old["member_key_id"]
                    ),
                    None,
                )
                if ref:
                    commitment, kind = ref
            protocol.setdefault("retired_member_keys", {})[old["member_key_id"]] = dict(
                seq=entry["seq"],
                member_id=old["member_id"],
                source_cert_seq=source["seq"],
                initial_commitment=commitment,
                initial_commitment_kind=kind,
            )
            for slot in protocol["slots"]:
                if slot["member_key_id"] == old["member_key_id"]:
                    slot["deleted"] = True
                    if slot["disabled_at"] is None:
                        slot["disabled_at"] = entry["ts"]
                    slot["policy_seq"] = entry["seq"]
        for claim in protocol["claims"].values():
            if any(
                claim[k] for k in ("cancelled", "activated", "superseded", "expired")
            ):
                continue
            if (
                AuthorityView(after).current(claim["subject"])["seq"]
                != claim["prior_cert_seq"]
                or after["recovery_seq"] != claim["recovery_prior_seq"]
                or self._generation(after) != claim["member_wrap"]["omk_generation"]
            ):
                claim["superseded"] = True
            if utc_millis(self._active_runtime["received_at"]) >= utc_millis(
                claim["expires_at"]
            ):
                claim["expired"] = True
        if self._active_runtime["mode"] == "live":
            prior_protocol = recovery_state(before)
            for digest, binding in protocol.get("bindings", {}).items():
                if digest not in prior_protocol.get("bindings", {}):
                    for slot in binding["slots"]:
                        self._evidence().slot_blob(slot)
            for digest, claim in protocol["claims"].items():
                if digest not in prior_protocol["claims"]:
                    self._evidence().slot_blob(claim["slot"])
                    self._evidence().claim_wrap(
                        claim["member_wrap"], proposal_hash=digest
                    )
            prior_slots = recovery_state(before)["slots"]
            for slot in protocol["slots"]:
                if (
                    not slot["deleted"]
                    and not slot.get("initial")
                    and slot not in prior_slots
                ):
                    self._evidence().slot_blob(slot)
        normalize(after)
        return after

    def _authorize(self, entry, state):
        before = deepcopy(state)
        if entry["kind"] in REQUEST_KINDS:
            evidence = self._evidence()
            require(
                evidence.request_facts is not None,
                "Independent request facts unavailable",
            )
            request = entry["body"].get("request")
            if request and request.get("kind") == "create":
                require(
                    request["target"].split("/")[0] in self._projects,
                    "Unknown create project",
                )
            self._candidate_requests.apply(
                entry, state, evidence.request_facts, self._request_runtime(entry)
            )
            result = advance(state, entry)
        elif entry["kind"] in RECOVERY_KINDS:
            result = self._recovery_authorize(
                entry,
                state,
                policy.authority_hooks(self._active_runtime, recovery_parity=True),
            )
            if entry["kind"] == "recovery_set":
                self._candidate_epochs.observe_authority(
                    entry, self._snapshot(before, self._candidate_epochs)
                )
        else:
            result = super()._authorize(entry, state)
        if entry["kind"] == "genesis":
            self._candidate_requests.max_policy_age = maximum_policy_age(
                entry["body"]["max_policy_age"]
            )
        return self._project(before, result, entry)

    def _derive(self, entry, state, received_at):
        before = deepcopy(state)
        if entry["kind"] == "request_default":
            evidence = self._evidence()
            require(
                evidence.request_facts is not None,
                "Independent request facts unavailable",
            )
            self._candidate_requests.apply(
                entry, state, evidence.request_facts, self._request_runtime(entry)
            )
            result = advance(state, entry)
        else:
            result = super()._derive(entry, state, received_at)
        return self._project(before, result, entry)

    def _request_runtime(self, entry):
        runtime = deepcopy(self._active_runtime)
        # Historical grants are evaluated at their signed position, with the
        # observed admission as an upper bound, never at today's wall clock.
        if runtime["mode"] == "history":
            runtime["now"] = iso(
                min(utc_millis(entry["ts"]), utc_millis(runtime["now"]))
            )
        return runtime

    def verify_record(self, record, **kwargs):
        with self._lock:
            candidate = deepcopy(self._requests)
            self._candidate_requests = candidate
            try:
                result = super().verify_record(record, **kwargs)
                entry = json.loads(record.data)
                self._requests = candidate
                self._records.append(entry)
                self._history_states[result["seq"]] = self.state
                protocol = recovery_state(self.state)
                if entry["kind"] in ("member_cert", "cert_proposal") and entry[
                    "body"
                ].get("passkey_binding", {}).get("reset_id"):
                    digest = wire.hash_object(entry)
                    binding = protocol["bindings"][digest]
                    pending = self._operational.pending.get(
                        binding["reset_id"]
                    ) or next(
                        r
                        for r in kwargs["evidence"]._rows["recovery_pending_resets"]
                        if r["reset_id"] == binding["reset_id"]
                    )
                    self._reset_proposals[digest] = dict(
                        proposal_hash=digest,
                        proposal_seq=entry["seq"],
                        entry_json=crypto.canonical_json(entry).decode(),
                        reset_id=binding["reset_id"],
                        member_id=pending["member_id"],
                        old_cert_seq=pending["old_cert_seq"],
                        candidate_json=pending["request_json"],
                        sas_evidence_json=crypto.canonical_json(
                            binding["sas_evidence"]
                        ).decode(),
                        accepted_at=record.received_at,
                        candidate_created_at=pending["created_at"],
                        expires_at=pending["expires_at"],
                    )
                if entry["kind"] == "cert_activate" and str(
                    entry["seq"]
                ) in protocol.get("reset_activation_evidence", {}):
                    digest = entry["body"]["proposal_hash"]
                    self._reset_activations[entry["seq"]] = dict(
                        activation_seq=entry["seq"],
                        proposal_hash=digest,
                        reset_id=protocol["bindings"][digest]["reset_id"],
                        entry_json=crypto.canonical_json(entry).decode(),
                        sas_evidence_json=crypto.canonical_json(
                            protocol["reset_activation_evidence"][str(entry["seq"])]
                        ).decode(),
                        accepted_at=record.received_at,
                    )
                return result
            except PolicyError as exc:
                cause = exc.__cause__
                if isinstance(cause, PolicyError) and cause.code == "Error":
                    raise cause from exc
                raise
            finally:
                self._candidate_requests = None

    def finish_history(self, blobs, *, evidence=None, broker_id=None):
        with self._lock:
            if self.conflict:
                raise PolicyError("E_POLICY_CONFLICT", "verifier is in conflict")
            try:
                require(
                    isinstance(evidence, RecoveryEvidence),
                    "Final recovery evidence required",
                )
                scope = 'full'
                if broker_id is not None:
                    cert = AuthorityView(self.state).broker_certificate_at(broker_id, self.head)
                    require(cert is not None, "Certified sync broker required")
                    scope = cert['scope']
                self._epochs.verify_current_ciphertexts(blobs, projects=None if scope == 'full' else scope)
                state = self.state
                protocol = recovery_state(state)
                slots = deepcopy(protocol["slots"])
                self._active_evidence = evidence
                for initial in self._initial_slots(state):
                    if not any(
                        s["slot_id"] == initial["slot_id"]
                        and s["member_key_id"] == initial["member_key_id"]
                        for s in slots
                    ):
                        slots.append(initial)
                retired = protocol.get("retired_member_keys", {})
                for cert, digest, kind, metadata in self._initial_references:
                    tombstones = [
                        s
                        for s in slots
                        if s.get("initial")
                        and s["member_key_id"] == cert["member_key_id"]
                        and s["slot_digest"] == digest
                        and s.get("initial_commitment_kind") == kind
                        and s["deleted"]
                    ]
                    if cert["member_key_id"] in retired or tombstones:
                        continue
                    require(
                        evidence._matching_slot(cert, digest, kind, metadata),
                        "Missing committed initial slot without verified deletion",
                    )
                for cert in AuthorityView(state).active():
                    require_usable_slots(slots, cert)
                owners = {}
                for slot in slots:
                    require(
                        slot["slot_id"] not in owners
                        or owners[slot["slot_id"]] == slot["member_key_id"],
                        "Slot id belongs to another member key",
                    )
                    owners[slot["slot_id"]] = slot["member_key_id"]
                    if not slot.get("initial") and not slot["deleted"]:
                        evidence.slot_blob(slot)
                for claim in protocol["claims"].values():
                    if (
                        claim["activated"]
                        and claim["member_wrap"]["omk_generation"]
                        == self.epoch_state["generation"]
                        and any(
                            c["member_key_id"]
                            == claim["member_wrap"]["recipient"]["id"]
                            for c in AuthorityView(state).active()
                        )
                    ):
                        evidence.claim_wrap(claim["member_wrap"])
                self._finalized_head = self.head
                self._ciphertext_scope = scope
            except Exception as exc:
                self._verifier.conflict = True
                if isinstance(exc, PolicyError):
                    raise
                raise PolicyError("E_POLICY_CONFLICT", str(exc)) from exc
            finally:
                self._active_evidence = None


class RecoveryOperations:
    """Operational signed records never advance a policy head or grant custody."""

    def __init__(self):
        self.pending = {}
        self.session_reports = []
        self.reserved_slots = set()

    def synchronize(self, state, now):
        protocol = recovery_state(state)
        for reset_id, pending in self.pending.items():
            if pending["state"] != "pending":
                continue
            if reset_id in protocol.get("cancelled_resets", {}):
                pending["state"] = "cancelled"
            else:
                candidate = json.loads(pending["request_json"])["entry"]["body"][
                    "certificate"
                ]
                current = AuthorityView(state).current(pending["member_id"])
                if (
                    current
                    and current["certificate"]["member_key_id"]
                    == candidate["member_key_id"]
                ):
                    pending["state"] = "activated"
                elif utc_millis(now) >= utc_millis(pending["expires_at"]):
                    pending["state"] = "expired"

    def submit_pending(
        self, signed, state, received_at, evidence, *, reserve, initial_slots=()
    ):
        cert = verify_pending_reset(signed, state, received_at)
        e = signed["entry"]
        b = e["body"]
        reset_id = b["reset_id"]
        require(
            reset_id not in self.pending
            and not any(
                r["member_id"] == cert["member_id"]
                and r["state"] == "pending"
                and utc_millis(received_at) < utc_millis(r["expires_at"])
                for r in self.pending.values()
            ),
            "A reset is already pending",
        )
        slot = descriptor(b["slot"], cert, e["ts"])
        require(
            slot["slot_id"] not in self.reserved_slots
            and not any(
                s["slot_id"] == slot["slot_id"] for s in recovery_state(state)["slots"]
            ),
            "Slot id already used",
        )
        reserve(slot)
        require(
            not any(s["slot_id"] == slot["slot_id"] for s in initial_slots),
            "Slot id reserved by initial slot",
        )
        require(
            not any(
                r["slot_id"] == slot["slot_id"]
                for r in evidence._rows.get("recovery_slot_blobs", [])
            ),
            "Slot id reserved by private staging",
        )
        evidence.slot_blob(slot)
        self.pending[reset_id] = dict(
            reset_id=reset_id,
            member_id=cert["member_id"],
            old_cert_seq=b["prior_cert_seq"],
            request_json=crypto.canonical_json(signed).decode(),
            created_at=received_at,
            expires_at=iso(utc_millis(received_at) + 7 * DAY),
            state="pending",
        )
        self.reserved_slots.add(slot["slot_id"])
        return deepcopy(self.pending[reset_id])

    def report_session(self, signed, state, received_at, initial_slots=()):
        signed = wire.parse_signed_entry(signed)
        e = signed["entry"]
        b = wire.exact(e["body"], ("slot_id", "nonce", "request_id"))
        cert = policy._actor(e, state)
        wire.text(b["slot_id"])
        wire.text(b["request_id"])
        wire.binary(b["nonce"], 16)
        require(
            e["kind"] == "member_recovery_session"
            and e["org_id"] == state["org_id"]
            and e["seq"] == state["head"]["seq"] + 1
            and e["prev_hash"] == state["head"]["hash"]
            and abs(utc_millis(e["ts"]) - utc_millis(received_at)) <= 300000
            and crypto.p256_verify(
                crypto.unb64url(cert["sign_pub"]),
                crypto.policy_context(e["org_id"], wire.hash_object(e)),
                wire.binary(signed["sig"], 64),
            ),
            "Recovery session report proof failed",
        )
        slots = {s["slot_id"]: s for s in initial_slots}
        slots.update({s["slot_id"]: s for s in recovery_state(state)["slots"]})
        slot = slots.get(b["slot_id"])
        require(
            slot
            and slot["member_key_id"] == cert["member_key_id"]
            and slot["kind"] == "passphrase"
            and not slot["deleted"]
            and slot["disabled_at"] is None,
            "Active own passphrase slot required",
        )
        require(
            not any(
                r["member_id"] == cert["member_id"]
                and (r["nonce"] == b["nonce"] or r["request_id"] == b["request_id"])
                for r in self.session_reports
            ),
            "Recovery session report replay",
        )
        self.session_reports.append(
            dict(
                member_id=cert["member_id"],
                member_key_id=cert["member_key_id"],
                slot_id=b["slot_id"],
                request_id=b["request_id"],
                nonce=b["nonce"],
                entry_json=crypto.canonical_json(e).decode(),
                sig=signed["sig"],
                created_at=received_at,
            )
        )
        return dict(recorded=True, source="client_reported")


def claim_wrap_pending(claim, state, generation, now):
    current = AuthorityView(state).current(claim["subject"])
    return (
        not any(claim[k] for k in ("cancelled", "activated", "superseded", "expired"))
        and now < utc_millis(claim["expires_at"])
        and claim["recovery_prior_seq"] == state["recovery_seq"]
        and current is not None
        and current["seq"] == claim["prior_cert_seq"]
        and generation == claim["member_wrap"]["omk_generation"]
    )
