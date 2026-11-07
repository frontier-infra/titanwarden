-- Installed only with cloud sync. Each selected history preserves earlier branches.
CREATE TABLE IF NOT EXISTS cloud_verified_branches (
  branch_id INTEGER PRIMARY KEY,
  org_id TEXT NOT NULL,
  through_conflict INTEGER NOT NULL,
  selected_head_json TEXT NOT NULL,
  root_hash TEXT NOT NULL,
  authenticated_by TEXT NOT NULL,
  selected_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cloud_active_branch (
  org_id TEXT PRIMARY KEY,
  branch_id INTEGER NOT NULL REFERENCES cloud_verified_branches(branch_id)
);
CREATE TABLE IF NOT EXISTS cloud_branch_replay (
  branch_id INTEGER NOT NULL REFERENCES cloud_verified_branches(branch_id),
  seq INTEGER NOT NULL,
  hash TEXT NOT NULL,
  authority_json TEXT NOT NULL,
  epoch_json TEXT NOT NULL,
  request_json TEXT NOT NULL,
  PRIMARY KEY(branch_id,seq)
);
CREATE TABLE IF NOT EXISTS cloud_branch_observations (
  branch_id INTEGER NOT NULL REFERENCES cloud_verified_branches(branch_id),
  seq INTEGER NOT NULL,
  hash TEXT NOT NULL,
  observed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cloud_branch_proposals (
  branch_id INTEGER NOT NULL REFERENCES cloud_verified_branches(branch_id),
  proposal_hash TEXT NOT NULL,
  mode TEXT NOT NULL,
  first_seen_at TEXT NOT NULL,
  PRIMARY KEY(branch_id,proposal_hash)
);
CREATE TRIGGER IF NOT EXISTS cloud_verified_branches_no_update BEFORE UPDATE ON cloud_verified_branches
BEGIN SELECT RAISE(ABORT,'authenticated history selection is immutable'); END;
CREATE TRIGGER IF NOT EXISTS cloud_verified_branches_no_delete BEFORE DELETE ON cloud_verified_branches
BEGIN SELECT RAISE(ABORT,'authenticated history selection is immutable'); END;
CREATE TRIGGER IF NOT EXISTS cloud_branch_replay_no_update BEFORE UPDATE ON cloud_branch_replay
BEGIN SELECT RAISE(ABORT,'verified branch is immutable'); END;
CREATE TRIGGER IF NOT EXISTS cloud_branch_replay_no_delete BEFORE DELETE ON cloud_branch_replay
BEGIN SELECT RAISE(ABORT,'verified branch is immutable'); END;
