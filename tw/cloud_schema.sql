-- CLOUD REPLAY SCHEMA: additive, offline-only. Existing stores opt in explicitly.
CREATE TABLE IF NOT EXISTS cloud_pins (
  org_id TEXT PRIMARY KEY,
  root_hash TEXT NOT NULL,
  CHECK (length(org_id) = 32),
  CHECK (length(root_hash) = 64)
);

CREATE TABLE IF NOT EXISTS cloud_replay (
  org_id TEXT NOT NULL REFERENCES cloud_pins(org_id),
  seq INTEGER NOT NULL CHECK (seq >= 0),
  hash TEXT NOT NULL CHECK (length(hash) = 64),
  authority_json TEXT NOT NULL,
  epoch_json TEXT,
  PRIMARY KEY (org_id, seq)
);

CREATE TABLE IF NOT EXISTS cloud_head_observations (
  observation_id INTEGER PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES cloud_pins(org_id),
  seq INTEGER NOT NULL,
  hash TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  FOREIGN KEY (org_id, seq) REFERENCES cloud_replay(org_id, seq)
);

CREATE TABLE IF NOT EXISTS cloud_proposal_observations (
  org_id TEXT NOT NULL REFERENCES cloud_pins(org_id),
  proposal_hash TEXT NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('live','history')),
  first_seen_at TEXT NOT NULL,
  PRIMARY KEY (org_id, proposal_hash)
);

CREATE TABLE IF NOT EXISTS cloud_hold_evidence (
  org_id TEXT NOT NULL REFERENCES cloud_pins(org_id),
  proposal_hash TEXT NOT NULL,
  activation_seq INTEGER NOT NULL,
  activation_hash TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('locally_observed','hold_not_locally_observed')),
  observed_at TEXT NOT NULL,
  PRIMARY KEY (org_id, proposal_hash, activation_seq),
  FOREIGN KEY (org_id, activation_seq) REFERENCES cloud_replay(org_id, seq)
);

CREATE TABLE IF NOT EXISTS cloud_conflicts (
  conflict_id INTEGER PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES cloud_pins(org_id),
  seq INTEGER NOT NULL,
  hash TEXT NOT NULL,
  reason TEXT NOT NULL,
  observed_at TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS cloud_pins_no_update BEFORE UPDATE ON cloud_pins
BEGIN SELECT RAISE(ABORT, 'independent pin is immutable'); END;
CREATE TRIGGER IF NOT EXISTS cloud_pins_no_delete BEFORE DELETE ON cloud_pins
BEGIN SELECT RAISE(ABORT, 'independent pin is immutable'); END;
CREATE TRIGGER IF NOT EXISTS cloud_replay_no_update BEFORE UPDATE ON cloud_replay
BEGIN SELECT RAISE(ABORT, 'verified prefix is immutable'); END;
CREATE TRIGGER IF NOT EXISTS cloud_replay_no_delete BEFORE DELETE ON cloud_replay
BEGIN SELECT RAISE(ABORT, 'verified prefix is immutable'); END;
CREATE TRIGGER IF NOT EXISTS cloud_heads_no_update BEFORE UPDATE ON cloud_head_observations
BEGIN SELECT RAISE(ABORT, 'local observation is immutable'); END;
CREATE TRIGGER IF NOT EXISTS cloud_heads_no_delete BEFORE DELETE ON cloud_head_observations
BEGIN SELECT RAISE(ABORT, 'local observation is immutable'); END;
CREATE TRIGGER IF NOT EXISTS cloud_proposals_no_update BEFORE UPDATE ON cloud_proposal_observations
BEGIN SELECT RAISE(ABORT, 'local observation is immutable'); END;
CREATE TRIGGER IF NOT EXISTS cloud_proposals_no_delete BEFORE DELETE ON cloud_proposal_observations
BEGIN SELECT RAISE(ABORT, 'local observation is immutable'); END;
CREATE TRIGGER IF NOT EXISTS cloud_holds_no_update BEFORE UPDATE ON cloud_hold_evidence
BEGIN SELECT RAISE(ABORT, 'hold evidence is immutable'); END;
CREATE TRIGGER IF NOT EXISTS cloud_holds_no_delete BEFORE DELETE ON cloud_hold_evidence
BEGIN SELECT RAISE(ABORT, 'hold evidence is immutable'); END;
CREATE TRIGGER IF NOT EXISTS cloud_conflicts_no_update BEFORE UPDATE ON cloud_conflicts
BEGIN SELECT RAISE(ABORT, 'conflict evidence is immutable'); END;
CREATE TRIGGER IF NOT EXISTS cloud_conflicts_no_delete BEFORE DELETE ON cloud_conflicts
BEGIN SELECT RAISE(ABORT, 'conflict evidence is immutable'); END;
