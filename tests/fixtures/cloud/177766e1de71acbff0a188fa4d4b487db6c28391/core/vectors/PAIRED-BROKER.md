# Paired broker fixtures, revision 2

Generate with pinned Node 22.20.0 from the repository root:

```sh
npm ci
npm --prefix control ci
npm run fixtures
FIXTURES_CHECK=1 npm run fixtures
npm --prefix control test -- exported-fixtures
```

The production files are generated from merged cloud revision 2738f37. All ten
v2 trace files use the enrollment base with genesis, recovery and requests hooks
and all three wrappers, with recovery hooks enabled and successful final replay.
Use paired-broker-manifest-v2.json as the current inventory: production v2 files
are listed first, followed by the unchanged v1 files and their original hashes.
The v1 manifest and traces remain byte-for-byte reproducible with
FIXTURES_LEGACY=1 npm run fixtures (add FIXTURES_CHECK=1 to verify only).

| Production file | Coverage |
| --- | --- |
| broker-authority-ranks-v2.json | All five ranks, holds, quorum, removal and rejected untyped passkey and certificate key edits |
| broker-authority-holds-v2.json | Hold durations, cancellation, continuous eligibility, recovery rotation and owner protections |
| broker-authority-invite-wrap-v2.json | Signed acceptance, confirmed slot and OMK wrap, substitution rejection and self lowering |
| broker-typed-passkey-binding-v2.json | Self and quorum bindings, possession and subject signatures, untyped edits and slot substitution rejection |
| broker-genesis-v2.json | Broker founder, immutable adoption provenance and initial full custody epoch |
| broker-epoch-manual-v2.json | Manual full rotation, ciphertext commitments and envelope rewrap |
| broker-epoch-scheduled-v2.json | Scheduled full rotation, ciphertext commitments and envelope rewrap |
| broker-epoch-pages-v2.json | Recipient pages, commit, cancellation, expiry and supersession |
| broker-brokers-rekeys-v2.json | Enrollment provenance, custody downgrade, full and projects rekeys and revocation |
| broker-full-revoke-v2.json | Full custody revocation and mandatory full rekey |
| paired-broker-manifest-v2.json | Production-first inventory, counts and exact byte SHA256 hashes |

The production ranks trace keeps generic passkey additions and key resets only
as negative cases. The existing protocol rejects these edits with
E_POLICY_CONFLICT, Typed passkey binding required. Certificates retain their
original keys until removal. Active members without an initial acceptance slot
receive a signed typed self binding with independent possession and subject
proofs before final replay. The original negative cases remain, with ten added
untyped edit cases. Immutable received_at values govern every replay and expiry.
All families are producible on the production composition without protocol or
production configuration changes.

The original v1 files are generated from merged cloud revision 96ee0c4, using the real
createAuthorityEpochLog composition, PolicyVerifier, authority machine,
WebAuthn verifier, genesis confirmation hooks, enrollment provenance verifier
and epoch/ciphertext transitions. There are no permissive authorization or
certificate binding hooks. The production profile composes the single
enrollment base with genesis, recovery and request hooks and all three wrappers,
and also runs final replay to verify retained private slot material. Tests load every exported trace and replay its
positive prefix before evaluating each negative. They compare exact errors,
heads, snapshots, state digests, custody and commitments, and independently
regenerate every file to prevent byte drift. No production source or runtime
configuration is changed.

| Original file | Coverage |
| --- | --- |
| broker-authority-ranks-v1.json | Founder slot commitment; member, approver, auditor, admin and owner create/change/key reset/remove; typed COSE passkey bindings; hold and quorum paths; wrong rank and self removal |
| broker-authority-holds-v1.json | 24-hour hold, short logged/local holds, endorsements, cancellation, frozen eligibility, prior certificate, last owner, rank decrease/restore, fresh recovery points and self lowering |
| broker-authority-invite-wrap-v1.json | Signed member acceptance and encrypted slot, confirmed OMK wrap, substitution rejection and reveal self lowering |
| broker-typed-passkey-binding-v1.json | Optional recovery composition: self/quorum binding, independent subject and credential possession signatures, lifted/duplicate proofs and substituted private slot |
| broker-genesis-v1.json | Broker founder genesis and initial full-custody epoch without browser or recovery recipients |
| broker-epoch-manual-v1.json | Initial epoch, manual full rotation, secret/version, staged bytes, envelope rewrap and adversarial recipient/commitment cases |
| broker-epoch-scheduled-v1.json | Initial epoch, scheduled full rotation, secret/version, staged bytes, envelope rewrap and adversarial recipient/commitment cases |
| broker-epoch-pages-v1.json | Paginated intent, pages and commit; early/duplicate commit; missing/duplicate pages; expiration, cancellation, supersession and invalid keeper |
| broker-brokers-rekeys-v1.json | Enrollment proof and provenance, owner approval toggle, full-to-scoped custody, trigger full rekey, scoped narrowing, projects-only rekey and revocation |
| broker-full-revoke-v1.json | Full-custody revocation and its mandatory full rekey |
| paired-broker-manifest-v1.json | Counts and SHA256 of exact UTF-8 bytes for all trace files |

Every v2 predecessor, expected outcome and finalize_expected also contains
an authority_core object and authority_core_sha256 (SHA256 of core canonical
JSON). The explicit projection in control/fixtures/authority-core.ts includes:
v, org_id, head, root, certificates, proposals, recovery, recovery_ever_set,
founding_broker, used_challenges, founder, founder_pending, recovery_seq,
triggers, brokers and core_commitments. It adds retired_recovery_points with
sign_pub and kx_pub arrays from used_recovery_sign_keys and
used_recovery_exchange_keys, defaulting to empty arrays. Array order is retained.
It excludes recovery_protocol and its slot, claim, binding and reset metadata.
The full authority_sha256 and final_state.authority remain available. Epoch
snapshots, commitments and broker custody stay alongside the projection. Cloud
tests independently project every replayed record and negative state and check
the recorded canonical digest.

Each trace starts at genesis, pins its root independently and contains:

- revision and description, org_id, pinned_root and producer metadata.
- profile and production_acceptable: all v2 files and the v1 typed binding trace use the full composed stack, labeled
  production with production_acceptable true. All base-only exports are labeled
  reference_only and production_acceptable false. A broker must never accept
  those reference traces as production protocol authority.
- recovery_hooks: selects the optional merged recovery composition. The typed
  binding trace enables it and verifies live challenge consumption and external
  slot bytes. The base authority traces exercise the existing authority/epoch
  composition with this opt-in disabled, including its generic certificate edits.
  A broker must select the matching profile, rather than silently accepting
  generic key edits when its recovery hook is enabled.
- records: the complete successful chain. Each record has entry and sig
  (canonical base64url raw 64-byte P-256 signature, or null for a derived
  activation), hash (lowercase SHA256), canonical_hex (the exact canonical
  UTF-8 entry bytes), fixed received_at, verification mode and external evidence.
- predecessor: the authoritative cloud summary before that record. It contains
  head, authority_sha256, epoch_sha256, epoch recipient snapshot, commitments
  and effective broker custody. State hashes use core canonical JSON. The first
  record has an empty predecessor and bootstrap can have a null snapshot.
- expected: accepted or rejected status, exact error code and message on
  rejection, and the same post-record summary. Accepted records also expose the
  cloud hold audit events. A negative preserves the verified state and head.
- cases: each names a prefix_length and one negative record. Start afresh at
  genesis, verify exactly that many successful records, install the negative's
  external evidence, and compare with its recorded expected outcome. Cases do
  not modify the successful chain or each other.
- final_state: the complete replay-derived authority and epoch state after the
  successful chain. This includes all certificate versions, proposal eligibility,
  keyring rows, envelope commitments, generations and custody history.

Evidence is test storage input, separate from signed policy authority. Each item
names a table, rows, optional source (blobs versus rows), and optional replace.
A SQL binary value is represented as an object with exactly one $bytes field
containing lowercase hex. Other strings remain strings. epoch_staging rows
contain payload_json: the exact canonical StagePayload bytes, encoded as a JSON
string. They include the encrypted keyring, OMK wraps and scoped seals. The log
commits their digests independently. Keyring and wrap bytes use lowercase hex;
certificate public points, passkeys, WebAuthn assertions and signatures use the
cloud's canonical base64url encodings. Numeric ranks and roles must come from
verified certificates, including the entire version history for continuous
signature eligibility.

received_at is immutable fixture input. The broker must use it for replay and
hold/intent expiration, never substitute its current clock. Live cases include
explicit local observation/challenge evidence. This evidence represents a local
verifier's prior observations and must never be accepted from an untrusted cloud
in a real broker. Most traces deliberately run in history mode, without
pretending to have witnessed a hold locally. The merged confirmation hook
currently refuses promotion of an existing nonholder to a key holder; this is
exported as a rejection, without extending the protocol.

All entropy and key material is public and test-only. The isolated generator
installs a deterministic WebCrypto adapter for generateKey, getRandomValues and
ECDSA signing (RFC6979 P-256 via the already pinned noble dependency). The core
sign, generateKey, seal and AES functions still execute; hash, AES, ECDH, imports
and every verifier use real WebCrypto. The adapter is restored afterward, is
never installed by replay tests, and has no production import path. Signatures
are deterministic test signatures rather than a source of fresh randomness.

## Production enrollment and HTTP admission supplement

The enrollment supplement is generated from merged cloud revision 6a2d52f.
Its inventory is paired-broker-manifest-enrollment-v1.json, listing only the
three new files and SHA256 of their exact UTF-8 bytes. The original v1 and v2
inventories and trace bytes remain unchanged. The new traces use revision 3
because their steps include HTTP transport, operational storage and response
bytes in addition to policy records. All use the single enrollment base with
genesis, recovery and requests hooks and all three wrappers, profile production
and production_acceptable true. No protocol or production configuration changes
are included.

| File | Coverage |
| --- | --- |
| broker-enrollment-join-v3.json | Ticket issuance, enrollment possession proof, signed pending poll, owner WebAuthn authorization, broker certificate and committed OMK wrap, active acceptance and lost enrollment/approval response retries |
| broker-enrollment-adopt-v3.json | Real preparation and deadline, adopt reservation, substituted root rejection, domain-separated adopt-root proof, legacy ingestion refusal, successful broker-founder genesis/epoch and first certificate prerequisite refusal |
| broker-request-admission-v3.json | Exact signed timestamp boundaries, nonce replay, fresh nonce with reused UUID, empty/absent/noncanonical POST bodies, duplicate JSON keys, duplicate decoded query keys and accepted noncanonical query ordering |

Run npm run fixtures to generate all supplements, or run
node core/scripts/export-enrollment-fixtures.mjs for this supplement alone.
FIXTURES_CHECK=1 selects byte verification. Run
npm --prefix control test -- enrollment-exported-fixtures to replay every new
file against the real production composition in SQLite. The tests also verify
manifest hashes, regenerate exact bytes, check rejection rollback and open an
accepted OMK wrap with the exported public test KX private key.

Each step has an immutable received_at, exact input, predecessor, cloud response
status and body bytes as a UTF-8 string, and post_state. Request inputs include
method, URL, raw path, raw query, canonical query, headers and body_b64 for the
exact forwarded bytes. GET has no body_b64, matching production forwarding.
For broker requests the five TW headers are exactly those forwarded by the
Worker. The successful genesis prefix includes every signed entry and external
storage input needed for real final replay; it is not a seeded authority state.
Post-state contains authority_core and its canonical SHA256, including the root
and head, verified certificate sequence, epoch state, archived enrollment wrap
commitments, receipts, nonces, adoption proof and preparation deadline. Audit
operations are recorded; the private audit receipt key and audit signatures are
not exported. AuditMirror still signs and verifies every control event.

The test_only_keys block contains public, deterministic signing and KX private
JWKs for the enrollment broker only, clearly marked test-only. The known OMK
plaintext is public fixture material. These keys permit independent signature
and ciphertext checks without generating replacement material. Ticket and broker
ID entropy and observation time are fixed only in the isolated test worker.
Cloud policy signatures, WebAuthn assertions, enrollment proofs, ECDH, AES,
transport restoration, custody and all authority transitions use merged code.
The production entry point imports none of these adapters.

SAS pinning is a broker-local action. The join trace includes broker_local_sas
with the exact core sasContext bytes, six words, transcript identity, independent
root and initial pin. This is comparison input for the paired broker, not cloud
attestation of a human match. There is no cloud broker SAS endpoint. The cloud
acceptance path separately records the verified certificate and committed wrap.

POST body cases isolate restoreBrokerRequest and
EnrollmentControl.signedRequest with a no-op admitted effect on the production
composition. Canonical {} passes admission; absent bytes, duplicate keys and
noncanonical JSON fail with 409 E_ENROLLMENT. The downstream sync/head operation
additionally requires head and epoch. Raw query order and percent encoding are
canonicalized in the signed context: unique parameters in noncanonical wire
order are accepted today. Repeated decoded keys, including percent-encoded
aliases, fail with 409 E_ENROLLMENT. No stricter query protocol was invented.
Signed timestamps exactly 300000 ms ahead or behind are accepted; 300001 ms
is refused with 409 E_ENROLLMENT. A committed nonce cannot replay, but a read
with the same UUID and fresh nonce succeeds. Approval retries with the same UUID
and identical body return the prior accepted sequence without another
certificate, wrap or receipt. A changed body with that UUID gives 409 E_CONFLICT.
Lost-response steps retain the actual committed response for comparison, then
repeat the same request as if the caller had not received it.

Two adoption boundaries remain closed in the current protocol. Legacy aad_v1
ingestion is refused with 409 E_LEGACY_ADOPTION; its attempted preparation and
root consumption roll back, allowing the valid tw2 batch afterward. After that
real broker-founder batch, there is no certified human owner/admin and no
recovery point. The first-owner broker claim is closed in authority/machine.ts,
and broker certificate approval requires an already certified human. The trace
therefore records the real 404 E_NOT_FOUND approval refusal rather than injecting
an owner or a synthetic prior broker certificate. A positive first founding
certificate from genesis cannot be produced on this profile until that protocol
boundary is opened. This is the same unresolved adoption boundary as legacy
ingestion and the first-owner claim, not a fixture authorization bypass.

## Production recovery and request companion, revision 1

The recovery/request companion is generated from merged cloud revision 6a2d52f.
Run with pinned Node 22.20.0 and the installed root and control dependencies:

```sh
node core/scripts/export-recovery-requests.mjs
FIXTURES_CHECK=1 node core/scripts/export-recovery-requests.mjs
npm --prefix control test -- exported-recovery-requests
```

Use paired-broker-manifest-recovery-requests-v1.json for the independent exact-byte
SHA256 inventory: 15 production trace files, 150 accepted log records, 76 rejected
log cases and 20 operational cases. Every trace starts at its independently pinned
genesis and uses the single enrollment base, genesis/recovery/request hooks and
all three wrappers. All have production_acceptable true. No production source,
configuration, protocol or existing vectors were changed.

| Files | Coverage |
| --- | --- |
| broker-recovery-slots-v1.json | Add, admin disable, slot-owner enable, 30-day boundary, last PRF protection, exact digest, initial deletion, normalized tombstones and permanent id reservation |
| broker-recovery-claims-activate-v1.json | Fresh member/paper keys and passkeys, proposal, subject/generator exclusion, endorsement, committed current-generation bootstrap wrap, activation, retired paper points, full-epoch recovery-wrap fence and cleanup |
| broker-recovery-claims-cancel-v1.json | Signed cancellation, permanent activation rejection and candidate staging cleanup |
| broker-recovery-claims-supersede-v1.json | Generation advance, superseded flag, activation rejection and cleanup |
| broker-recovery-claims-expire-v1.json | Exclusive seven-day receipt-based expiry, expired flag and cleanup |
| broker-recovery-reset-activate-v1.json | Real pending-reset HTTP admission, duplicate rejection, independent typed SAS gates, immutable proposal/activation receipts, matching transcript rule and full epoch |
| broker-recovery-reset-old-key-cancel-v1.json | Old-key signed cancellation without a passkey, retained candidate metadata and operational staging cleanup |
| broker-recovery-reset-owner-cancel-v1.json | Owner passkey cancellation of an admin reset; missing-passkey rejection |
| broker-recovery-reset-admin-cancel-v1.json | Admin passkey cancellation of a member reset; missing-passkey rejection |
| broker-recovery-session-v1.json | Signed client-reported passphrase session HTTP admission, nonce replay rejection and refusal as a policy-log entry |
| broker-recovery-revoke-and-set-v1.json | Accepted member_revoke certificates changing keys or passkeys and rejected recovery_set after browser genesis |
| broker-requests-policy-decisions-v1.json | Both policy_rules variants, signed opens, effective received_at deadlines, defaults, approvals, denial, terminal replay and cross-project sensitive admin/owner gates |
| broker-requests-broker-local-v1.json | Real enrollment provenance, local-admin toggle, own-principal restricted approval and foreign-principal/agent-origin rejection |
| broker-recovery-nonholder-promotion-v1.json | Explicit rejected nonholder promotion through recovery |
| broker-recovery-set-broker-boundary-v1.json | Broker genesis and full epoch, rejected first-owner bootstrap and recovery_set |

The log record format retains canonical bytes, real signatures, immutable
received_at, predecessor and exact expected outcome, complete authority and epoch
hashes, authority_core and authority_core_sha256 on both sides, final state and
final replay. materialized and materialized_sha256 additionally cover request and
grant rows, member slots, installed wraps and retained operational tables. A case
also pins operations_length, so its prefix cannot accidentally include a later
cleanup or local admission at the same policy head.

Operational cases have profile operational and never enter the signed policy
chain. Their request is the complete test Dispatch, with request_canonical_hex;
http separately identifies the method, route and exact canonical signed body
bytes. Accepted results include response and response_canonical_hex. The local
maintenance cases identify the production cleanup/lifecycle function rather than
inventing an HTTP route. Tests replay the successful policy prefix and every
preceding operational case before comparing the complete recorded result.

Pending resets and session reports run the real RecoveryControl against migrated
SQLite populated only from the verified prefix and retained local input. The
public test session identity, independently held device pin and browser typed-gate
attestation are explicit test evidence ports. The audit sink records the handler's
metadata calls and supplies no authorization; these vectors do not assert an
AuditMirror receipt or browser ceremony occurred. Historical reset SAS validation
uses createRecoveryTransitionPorts and immutable accepted proposal/activation
records produced by retainResetAcceptance and retainResetActivation. Tests check
SQL immutability and revalidate history without consulting live browser gates.
Recovery sessions grant no authority and cannot activate a reset or sign policy.
All keys, credential material, ciphertext and session inputs are public test-only
material generated using the existing isolated deterministic crypto adapter.

Two known protocol gaps remain explicit:

- Recovery of an existing nonholder to owner is rejected by the genesis wrapper:
  code Error, message Key holder promotion requires committed wrap support.
  Positive recovery claims therefore start with an existing key holder.
- Positive recovery_set is unreachable from a broker-founded genesis while its
  first owner cannot be claimed. The attempted first certificate rejects with
  E_POLICY_CONFLICT / Inactive member signer, and recovery_set rejects with
  E_POLICY_CONFLICT / Active member signer required. Browser-founded recovery_set
  also rejects with E_POLICY_CONFLICT / Recovery bootstrap unavailable.

These are exports of current merged behavior, without protocol changes. Historical
slot enable accepts exactly 30 days and rejects one millisecond later, as the
current signed transition specifies. Immutable received_at remains the replay
clock for all deadlines and accepted reset evidence.
