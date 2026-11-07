"""Replay committed production traces with concrete offline evidence verifiers.

Fixture evidence is injected only in this deterministic test harness. Runtime
applications must obtain observation time and independent proof material locally.
"""
import copy
import json

from tw import crypto
from tw.cloud_policy import AuthorityEvidence
from tw.cloud_epochs import epoch_checkpoint, epoch_blob_commitments
from tw.cloud_wire import hash_object
from tw.policy_log import OfflineCloudVerifier, PolicyError, PolicyRecord
import test_cloud_policy as policy_tests


def decode(value):
    if isinstance(value, dict):
        if set(value) == {"$bytes"}:
            return bytes.fromhex(value["$bytes"])
        return {k: decode(v) for k, v in value.items()}
    if isinstance(value, list):
        return [decode(v) for v in value]
    return value


class PairedReplay:
    def __init__(self, trace, *, verifier=OfflineCloudVerifier, evidence=AuthorityEvidence):
        if trace.get("production_acceptable") is not True or trace.get("profile") != "production":
            raise ValueError("reference-only fixture cannot establish production acceptance")
        self.trace = trace
        self.evidence_factory = evidence
        projects = next(r["entry"]["body"]["active_kek"] for r in trace["records"] if r["entry"]["kind"] == "epoch_init")
        self.replay = verifier(trace["org_id"], trace["pinned_root"], projects=projects)
        self.rows, self.blobs = {}, {}
        self.accepted = []
        self._ciphertexts = {}

    def install(self, items):
        for item in items:
            store = self.blobs if item.get("source") == "blobs" else self.rows
            table = item["table"]
            values = decode(item["rows"])
            store[table] = values if item.get("replace") else store.get(table, []) + values

    def stage(self, entry):
        if entry["kind"] not in ("epoch_init", "epoch_rotate", "epoch_rotate_projects", "epoch_commit"):
            return None
        if entry["kind"] == "epoch_commit" and self.replay.epoch_state["pending"] is None:
            return None
        body = self.replay.epoch_state["pending"]["body"] if entry["kind"] == "epoch_commit" else entry["body"]
        plan, fence = ("__epoch_init__", 0) if entry["kind"] == "epoch_init" else (body.get("plan_id"), body.get("fence"))
        row = next((r for r in self.blobs.get("epoch_staging", []) if r.get("plan_id") == plan and r.get("fence") == fence), None)
        return None if row is None else json.loads(row["payload_json"])

    @staticmethod
    def ciphertext(row, secret_id=None):
        fields = ("version_id", "secret_id", "kek_id", "ciphertext", "nonce", "wrapped_dek", "dek_nonce")
        if "secret_id" not in row:
            row = dict(row, secret_id=secret_id)
        return {k: row[k].hex() if isinstance(row[k], bytes) else row[k] for k in fields}

    def summary(self):
        authority = policy_tests.cloud_authority_projection(self.replay.state)
        retired = self.replay.state.get("used_recovery_points", [])
        authority["retired_recovery_points"] = dict(sign_pub=retired[1::2], kx_pub=retired[::2])
        epoch_state = self.replay.epoch_state
        snapshot = None
        custody = {}
        if authority["root"] and not authority["founder_pending"]:
            view = self.replay.epoch_view()
            snapshot = policy_tests.cloud_snapshot_projection(view.snapshot, epoch_state)
            custody = {b["id"]: view.custody_evidence(b["id"], authority["head"]) for b in view.snapshot["brokers"]}
        return dict(head=authority["head"], authority_core=authority,
                    authority_core_sha256=hash_object(authority), epoch_sha256=hash_object(epoch_checkpoint(epoch_state)),
                    snapshot=snapshot, commitments=authority["core_commitments"] + epoch_blob_commitments(epoch_state), custody=custody)

    def run(self, record):
        entry = record["entry"]
        data = crypto.canonical_json(entry)
        if data.hex() != record["canonical_hex"] or crypto.sha256(data).hex() != record["hash"]:
            raise AssertionError("supplied canonical policy bytes or hash differs")
        self.install(record["evidence"])
        signature = None if record["sig"] is None else crypto.unb64url(record["sig"])
        policy_record = PolicyRecord(data, record["hash"], signature, record["received_at"])
        observations = next((json.loads(r["observations_json"]) for r in self.rows.get("authority_observations", []) if r["singleton"] == 1), dict(heads=[], proposals={}))
        runtime = dict(mode=record["mode"], now=record["received_at"], observations=observations)
        evidence = self.evidence_factory(self.rows, self.blobs)
        blob = next((r for r in self.blobs.get("secret_versions", []) if r["version_id"] == entry["body"].get("version_id")), None)
        before_events = len(self.replay.hold_evidence)
        try:
            self.replay.verify_record(policy_record, stage=self.stage(entry), blob=None if blob is None else self.ciphertext(blob, entry["body"].get("secret_id")), runtime=runtime, evidence=evidence)
            self.accepted.append(record)
            for version in self.replay.epoch_state["versions"]:
                vid = version["version_id"]
                current = dict(self._ciphertexts.get(vid, {}))
                raw = next((r for r in self.blobs.get("secret_versions", []) if r["version_id"] == vid), {})
                for field in ("ciphertext", "nonce", "wrapped_dek", "dek_nonce"):
                    if field in raw:
                        current[field] = raw[field]
                current.update(version_id=vid, secret_id=version["secret_id"], kek_id=version["kek_id"])
                self._ciphertexts[vid] = current
            events = [dict(proposal_hash=e["proposal_hash"], status=e["status"], first_recorded_at=e["observed_at"]) for e in self.replay.hold_evidence[before_events:]]
            result = dict(status="accepted", events=events)
        except PolicyError as exc:
            result = dict(status="rejected", code=exc.code, message=str(exc))
        return dict(result, **self.summary())

    def finish(self):
        self.replay.finish_history([self.ciphertext(r) for r in self._ciphertexts.values()], evidence=self.evidence_factory(self.rows, self.blobs))
        return dict(status="accepted", **self.summary())
