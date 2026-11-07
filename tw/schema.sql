PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE slots (
  slot_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('passphrase','recovery','file','secure_enclave','tpm')),
  params_json TEXT NOT NULL,
  wrapped_mk BLOB NOT NULL,
  nonce BLOB NOT NULL,
  mk_generation INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  disabled_at TEXT,
  disabled_reason TEXT
);

CREATE TABLE keyring (
  key_id TEXT PRIMARY KEY,
  purpose TEXT NOT NULL CHECK (purpose IN ('kek','audit_mac','fingerprint')),
  version INTEGER NOT NULL,
  wrapped_key BLOB NOT NULL,
  nonce BLOB NOT NULL,
  mk_generation INTEGER NOT NULL,
  wrap_count INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL CHECK (state IN ('active','retired')),
  created_at TEXT NOT NULL
);

CREATE TABLE projects (
  slug TEXT PRIMARY KEY,
  lead_principal TEXT,
  change_policy TEXT NOT NULL DEFAULT 'auto'
    CHECK (change_policy IN ('auto','desk_approval','client_approval_required')),
  no_shell INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE secrets (
  secret_id TEXT PRIMARY KEY,
  path TEXT NOT NULL UNIQUE,
  project TEXT NOT NULL REFERENCES projects(slug),
  class TEXT NOT NULL CHECK (class IN ('standard','sensitive','restricted')),
  kind TEXT NOT NULL DEFAULT 'opaque',
  provider TEXT,
  provider_ref_json TEXT NOT NULL DEFAULT '{}',
  rotation_json TEXT NOT NULL DEFAULT '{}',
  allowed_hosts_json TEXT NOT NULL DEFAULT '[]',
  short INTEGER NOT NULL DEFAULT 0,
  allow_short_delivery INTEGER NOT NULL DEFAULT 0,
  no_shell INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL DEFAULT 'active',
  note TEXT,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL
);

CREATE TABLE secret_versions (
  version_id TEXT PRIMARY KEY,
  secret_id TEXT NOT NULL REFERENCES secrets(secret_id),
  version_no INTEGER NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending','active','grace','revoked','destroyed')),
  ciphertext BLOB,
  nonce BLOB,
  wrapped_dek BLOB,
  dek_nonce BLOB,
  kek_id TEXT,
  fingerprint BLOB NOT NULL,
  length INTEGER NOT NULL,
  source TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  activated_at TEXT,
  grace_until TEXT,
  revoked_at TEXT,
  destroyed_at TEXT,
  UNIQUE (secret_id, version_no)
);

CREATE UNIQUE INDEX one_active_version_per_secret
  ON secret_versions(secret_id) WHERE state = 'active';

CREATE TABLE placements (
  placement_id TEXT PRIMARY KEY,
  secret_id TEXT NOT NULL REFERENCES secrets(secret_id),
  sink_kind TEXT NOT NULL,
  locator_json TEXT NOT NULL,
  last_pushed_version INTEGER,
  last_verified_at TEXT,
  state TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  removed_at TEXT,
  UNIQUE (secret_id, sink_kind, locator_json)
);

CREATE TABLE principals (
  principal_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  display TEXT,
  project TEXT,
  parent_id TEXT,
  orca_run_id TEXT,
  coordinator_handle TEXT,
  dispatch_id TEXT,
  task_id TEXT,
  worker_handle TEXT,
  desk_identity TEXT,
  launchd_label TEXT,
  worktree_roots_json TEXT NOT NULL DEFAULT '[]',
  state TEXT NOT NULL,
  synced_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE tokens (
  token_id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(principal_id),
  kind TEXT NOT NULL CHECK (kind IN ('master','lead','job','task','host')),
  token_hash BLOB NOT NULL UNIQUE,
  parent_token_id TEXT REFERENCES tokens(token_id),
  scope_json TEXT NOT NULL,
  file_path TEXT NOT NULL,
  idle_expiry_days INTEGER,
  hard_expires_at TEXT,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at TEXT,
  revoked_reason TEXT
);

CREATE TABLE pane_bindings (
  handle TEXT PRIMARY KEY,
  token_id TEXT NOT NULL REFERENCES tokens(token_id),
  principal_id TEXT NOT NULL REFERENCES principals(principal_id),
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  revoked_at TEXT
);

CREATE TABLE grants (
  grant_id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(principal_id),
  pattern TEXT NOT NULL,
  ops TEXT NOT NULL,
  conditions_json TEXT NOT NULL DEFAULT '{}',
  effect TEXT NOT NULL DEFAULT 'allow' CHECK (effect IN ('allow','deny')),
  granted_by TEXT NOT NULL,
  reason TEXT NOT NULL,
  request_id TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT,
  revoked_at TEXT
);

CREATE TABLE leases (
  lease_id TEXT PRIMARY KEY,
  token_id TEXT NOT NULL REFERENCES tokens(token_id),
  principal_id TEXT NOT NULL REFERENCES principals(principal_id),
  op TEXT NOT NULL,
  refs_json TEXT NOT NULL,
  pid INTEGER,
  pgid INTEGER,
  argv0 TEXT,
  argv_sha256 TEXT,
  cwd TEXT,
  job TEXT,
  parent_lease_id TEXT REFERENCES leases(lease_id),
  context_verified INTEGER NOT NULL DEFAULT 0,
  opened_at TEXT NOT NULL,
  closed_at TEXT,
  exit_code INTEGER,
  end_reason TEXT
);

CREATE TABLE requests (
  request_id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(principal_id),
  kind TEXT NOT NULL CHECK (kind IN ('access','create','rotate')),
  target TEXT NOT NULL,
  ops TEXT,
  reason TEXT NOT NULL,
  ttl TEXT,
  needs TEXT NOT NULL CHECK (needs IN ('policy','master','operator','client')),
  default_decision TEXT,
  default_at TEXT,
  desk_item TEXT,
  state TEXT NOT NULL CHECK (state IN ('open','approved','denied','defaulted','expired')),
  decided_by TEXT,
  decided_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE receipts (
  request_id TEXT PRIMARY KEY,
  op TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  response_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE env_quarantine (
  quarantine_id TEXT PRIMARY KEY,
  project TEXT NOT NULL,
  original_path TEXT NOT NULL,
  git_tracked INTEGER NOT NULL,
  secret_id TEXT NOT NULL REFERENCES secrets(secret_id),
  manifest_path TEXT,
  desk_item TEXT,
  state TEXT NOT NULL CHECK (state IN ('imported','original_kept','delete_approved','original_deleted','restored')),
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL
);

CREATE TABLE audit_events (
  seq INTEGER PRIMARY KEY,
  event_id TEXT NOT NULL UNIQUE,
  ts TEXT NOT NULL,
  host TEXT NOT NULL,
  op TEXT NOT NULL,
  phase TEXT NOT NULL CHECK (phase IN ('intent','result','single')),
  decision TEXT NOT NULL CHECK (decision IN ('allow','deny','error')),
  reason_code TEXT,
  principal_id TEXT,
  token_id TEXT,
  parent_principal_id TEXT,
  project TEXT,
  secret_path TEXT,
  version_no INTEGER,
  lease_id TEXT,
  parent_lease_id TEXT,
  plan_id TEXT,
  share_id TEXT,
  request_id TEXT,
  orca_run_id TEXT,
  dispatch_id TEXT,
  task_id TEXT,
  job TEXT,
  launchd_label TEXT,
  attest_status TEXT,
  attested_handle TEXT,
  context_verified INTEGER NOT NULL DEFAULT 0,
  peer_uid INTEGER,
  peer_pid INTEGER,
  peer_exe TEXT,
  claimed_json TEXT NOT NULL DEFAULT '{}',
  argv0 TEXT,
  argv_sha256 TEXT,
  shell INTEGER,
  exit_code INTEGER,
  redactions INTEGER,
  scrubbed INTEGER NOT NULL DEFAULT 0,
  detail_json TEXT NOT NULL DEFAULT '{}',
  sealed_tail INTEGER NOT NULL DEFAULT 0,
  prev_hash BLOB NOT NULL,
  hash BLOB NOT NULL,
  mac BLOB
);

CREATE INDEX audit_secret ON audit_events (secret_path, seq);
CREATE INDEX audit_principal ON audit_events (principal_id, seq);

CREATE TRIGGER audit_no_update
BEFORE UPDATE ON audit_events
BEGIN
  SELECT RAISE(ABORT, 'append-only');
END;

CREATE TRIGGER audit_no_delete
BEFORE DELETE ON audit_events
BEGIN
  SELECT RAISE(ABORT, 'append-only');
END;

CREATE TABLE anchors (
  anchor_id TEXT PRIMARY KEY,
  seq INTEGER NOT NULL,
  hash BLOB NOT NULL,
  ts TEXT NOT NULL,
  destination TEXT NOT NULL,
  receipt TEXT
);

CREATE TABLE rotation_plans (
  plan_id TEXT PRIMARY KEY,
  secret_id TEXT NOT NULL REFERENCES secrets(secret_id),
  trigger TEXT NOT NULL CHECK (trigger IN ('manual','schedule','leak','provider_expiry')),
  adapter TEXT NOT NULL,
  from_version INTEGER,
  to_version INTEGER,
  state TEXT NOT NULL,
  dependents_json TEXT NOT NULL,
  placements_json TEXT NOT NULL,
  desk_item TEXT,
  grace_until TEXT,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  error TEXT
);

CREATE TABLE rotation_steps (
  plan_id TEXT NOT NULL REFERENCES rotation_plans(plan_id),
  step_no INTEGER NOT NULL,
  action TEXT NOT NULL,
  idem_key TEXT NOT NULL,
  intent_at TEXT,
  effect_at TEXT,
  receipt_json TEXT,
  state TEXT NOT NULL CHECK (state IN ('intent','done','failed','skipped')),
  PRIMARY KEY (plan_id, step_no)
);
