-- Explicit cloud-mode migration only. Never included by schema.sql or Store.open.
CREATE TABLE IF NOT EXISTS cloud_local_keys (
  org_id TEXT NOT NULL,
  broker_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  purpose TEXT NOT NULL,
  scope TEXT NOT NULL,
  generation INTEGER NOT NULL CHECK (generation > 0),
  wrapped_key BLOB NOT NULL,
  nonce BLOB NOT NULL,
  PRIMARY KEY (org_id,broker_id,key_id,generation)
);
CREATE TABLE IF NOT EXISTS cloud_local_slots (
  org_id TEXT NOT NULL,
  broker_id TEXT NOT NULL,
  slot_id TEXT NOT NULL,
  generation INTEGER NOT NULL CHECK (generation > 0),
  params_json TEXT NOT NULL,
  wrapped_blk BLOB NOT NULL,
  nonce BLOB NOT NULL,
  PRIMARY KEY (org_id,broker_id,slot_id,generation)
);
CREATE TABLE IF NOT EXISTS cloud_enrollments (
  org_id TEXT NOT NULL,
  ticket_id TEXT NOT NULL,
  broker_id TEXT NOT NULL,
  transcript_json TEXT NOT NULL,
  proof TEXT NOT NULL,
  candidate_root TEXT,
  root_proof TEXT,
  state TEXT NOT NULL CHECK (state IN ('reserved','pinned','complete')),
  certificate_json TEXT,
  head_json TEXT,
  custody_json TEXT,
  PRIMARY KEY (org_id,ticket_id)
);
CREATE TABLE IF NOT EXISTS cloud_adoption_journal (
  org_id TEXT PRIMARY KEY,
  source_digest TEXT NOT NULL,
  plan_json TEXT NOT NULL,
  phase TEXT NOT NULL CHECK (phase IN ('inventoried','keys_staged','envelopes_staged','verified_draft'))
);
CREATE TABLE IF NOT EXISTS cloud_adoption_keys (
  org_id TEXT NOT NULL REFERENCES cloud_adoption_journal(org_id),
  key_id TEXT NOT NULL,
  purpose TEXT NOT NULL,
  scope TEXT NOT NULL,
  generation INTEGER NOT NULL,
  wrapped_key BLOB NOT NULL,
  nonce BLOB NOT NULL,
  aad_v INTEGER NOT NULL CHECK (aad_v=2),
  PRIMARY KEY (org_id,key_id)
);
CREATE TABLE IF NOT EXISTS cloud_adoption_envelopes (
  org_id TEXT NOT NULL REFERENCES cloud_adoption_journal(org_id),
  version_id TEXT NOT NULL,
  from_kek_id TEXT NOT NULL,
  to_kek_id TEXT NOT NULL,
  wrapped_dek BLOB NOT NULL,
  nonce BLOB NOT NULL,
  from_digest TEXT NOT NULL,
  to_digest TEXT NOT NULL,
  PRIMARY KEY (org_id,version_id)
);
