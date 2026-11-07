-- CLOUD SYNC: installed only by explicit offline sync opt-in.
-- Local acknowledgements never delete the conflict evidence they cover.
CREATE TABLE IF NOT EXISTS cloud_resolutions (
  resolution_id INTEGER PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES cloud_pins(org_id),
  through_conflict INTEGER NOT NULL REFERENCES cloud_conflicts(conflict_id),
  seq INTEGER NOT NULL,
  hash TEXT NOT NULL,
  resolved_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cloud_sync_blobs (
  org_id TEXT NOT NULL REFERENCES cloud_pins(org_id),
  version_id TEXT NOT NULL,
  head_seq INTEGER NOT NULL,
  blob_json TEXT NOT NULL,
  PRIMARY KEY (org_id, version_id)
);

CREATE TABLE IF NOT EXISTS cloud_sync_state (
  org_id TEXT NOT NULL REFERENCES cloud_pins(org_id),
  seq INTEGER NOT NULL,
  request_json TEXT NOT NULL,
  PRIMARY KEY (org_id, seq)
);
CREATE TRIGGER IF NOT EXISTS cloud_sync_state_no_update BEFORE UPDATE ON cloud_sync_state
BEGIN SELECT RAISE(ABORT, 'verified request state is immutable'); END;
CREATE TRIGGER IF NOT EXISTS cloud_sync_state_no_delete BEFORE DELETE ON cloud_sync_state
BEGIN SELECT RAISE(ABORT, 'verified request state is immutable'); END;

-- Audit exchange diagnostics have no policy authority and do not clear or set
-- the policy delivery gate. They are retained independently of signed reports.
CREATE TABLE IF NOT EXISTS cloud_audit_conflicts (
  conflict_id INTEGER PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES cloud_pins(org_id),
  chain_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  observed_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS cloud_audit_conflicts_no_update BEFORE UPDATE ON cloud_audit_conflicts
BEGIN SELECT RAISE(ABORT, 'audit diagnostic is immutable'); END;
CREATE TRIGGER IF NOT EXISTS cloud_audit_conflicts_no_delete BEFORE DELETE ON cloud_audit_conflicts
BEGIN SELECT RAISE(ABORT, 'audit diagnostic is immutable'); END;

CREATE TABLE IF NOT EXISTS cloud_sync_holds (
  org_id TEXT NOT NULL REFERENCES cloud_pins(org_id),
  proposal_hash TEXT NOT NULL,
  activation_seq INTEGER NOT NULL,
  activation_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  verified_at_seq INTEGER NOT NULL,
  PRIMARY KEY (org_id, proposal_hash, activation_seq),
  FOREIGN KEY (org_id, verified_at_seq) REFERENCES cloud_replay(org_id, seq)
);
CREATE TRIGGER IF NOT EXISTS cloud_sync_holds_no_update BEFORE UPDATE ON cloud_sync_holds
BEGIN SELECT RAISE(ABORT, 'local hold audit is immutable'); END;
CREATE TRIGGER IF NOT EXISTS cloud_sync_holds_no_delete BEFORE DELETE ON cloud_sync_holds
BEGIN SELECT RAISE(ABORT, 'local hold audit is immutable'); END;

CREATE TABLE IF NOT EXISTS cloud_unpublished (
  org_id TEXT NOT NULL REFERENCES cloud_pins(org_id),
  version_id TEXT NOT NULL,
  head_json TEXT NOT NULL,
  kek_id TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  PRIMARY KEY (org_id, version_id)
);

CREATE TABLE IF NOT EXISTS cloud_keeper_leases (
  org_id TEXT NOT NULL REFERENCES cloud_pins(org_id),
  plan_id TEXT NOT NULL,
  broker_id TEXT NOT NULL,
  fence INTEGER NOT NULL,
  head_json TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  claimed_until TEXT NOT NULL,
  renewed_at TEXT NOT NULL,
  PRIMARY KEY (org_id, plan_id)
);

CREATE TABLE IF NOT EXISTS cloud_audit_receipts (
  org_id TEXT NOT NULL REFERENCES cloud_pins(org_id),
  chain_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  receipt_json TEXT NOT NULL,
  PRIMARY KEY (org_id, chain_id, seq)
);

CREATE TABLE IF NOT EXISTS cloud_audit_rows (
  org_id TEXT NOT NULL REFERENCES cloud_pins(org_id),
  chain_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  row_json TEXT NOT NULL,
  PRIMARY KEY (org_id, chain_id, seq)
);
CREATE TRIGGER IF NOT EXISTS cloud_audit_rows_no_update BEFORE UPDATE ON cloud_audit_rows
BEGIN SELECT RAISE(ABORT, 'audit row is immutable'); END;
CREATE TRIGGER IF NOT EXISTS cloud_audit_rows_no_delete BEFORE DELETE ON cloud_audit_rows
BEGIN SELECT RAISE(ABORT, 'audit row is immutable'); END;

CREATE TRIGGER IF NOT EXISTS cloud_resolutions_no_update BEFORE UPDATE ON cloud_resolutions
BEGIN SELECT RAISE(ABORT, 'local resolution is immutable'); END;
CREATE TRIGGER IF NOT EXISTS cloud_resolutions_no_delete BEFORE DELETE ON cloud_resolutions
BEGIN SELECT RAISE(ABORT, 'local resolution is immutable'); END;
CREATE TRIGGER IF NOT EXISTS cloud_receipts_no_update BEFORE UPDATE ON cloud_audit_receipts
BEGIN SELECT RAISE(ABORT, 'audit receipt is immutable'); END;
CREATE TRIGGER IF NOT EXISTS cloud_receipts_no_delete BEFORE DELETE ON cloud_audit_receipts
BEGIN SELECT RAISE(ABORT, 'audit receipt is immutable'); END;
