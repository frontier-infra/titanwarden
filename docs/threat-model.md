# Titanwarden v0 threat model

## Assets

Titanwarden protects provider credentials, database passwords, signing keys,
broker tokens, encryption keys, recovery material, and the integrity of the
access audit. The store and its backups contain ciphertext and wrapped keys.

## Trust boundaries

Offline copies are protected by AES-256-GCM envelope encryption. A random
master key is wrapped by Argon2id-derived passphrase and recovery slots. AAD
binds values, wrapped DEKs, keyring entries, and slots to their exact rows.

The agent protocol is a closed operation set with result allowlists. It has no
plaintext-returning operation. Secret delivery requires an audit intent commit
before the child or tty receives a value. Audit rows form a hash chain and are
MACed while unsealed. Events written while sealed are covered by a later tail
attestation.

## v0 guardrails

The broker, agents, token files, code, and state all run as the same OS user.
A determined same-user process can read tokens, replace code, inspect child
environments, attempt process attachment, delete state, or impersonate a pane.
Therefore v0 prevents accidental disclosure and records honest use. It is not a
boundary against a hostile local agent.

Whole-store streaming redaction reduces transcript leaks but is not complete.
Unknown transforms can bypass it, and a same-user process can inspect another
process environment. File descriptor and standard-input delivery reduce that
window. The v1 dedicated-user design is required for a local security boundary.

The admin client refuses sensitive display operations from an Orca pane. In a
local session it also refuses while Orca, Claude, or Codex is running. SSH from
the human operator's own device keeps recovery and reveal material off the
broker machine's screen. Client-side peer inspection rejects a casual socket squatter.

## Failure behavior

Sealed, frozen, lockdown, expired, unauthenticated, out-of-scope, or unauditable
means no value moves. Every restart seals the broker. Audit verification failure
enters lockdown. The freeze file latches and cannot be cleared by deleting it.
Backups are ciphertext-only and require a passphrase or recovery key to open.

The protected client project has mandatory restricted classification, refuses
environment import, and never receives a default approval. This policy is not
relaxed by an operator convenience path.
