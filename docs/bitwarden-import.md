# Bitwarden import

This command is a stage 1 gate for Daybreak H-03. It is a human operation run
as the dedicated broker service user, with a trusted, installed Bitwarden CLI.
It does not establish confidentiality against root, that service user, or a
compromised Bitwarden executable. A maintenance window must also prohibit
source rotations outside the local agent hook. The revision comparison detects
a change before the write; it cannot lock the remote vault.

## Manifest and invocation

The manifest has names only. Unknown keys, repeated JSON keys, duplicate targets,
invalid classes, traversal names and multiple selectors are refused. The path
is the name within the explicitly named project, with no slash. Select exactly
one custom field or one login member, username, password or totp. A totp import
copies the stored seed, not a generated one-time code.

```json
{
  "version": 1,
  "items": [
    {
      "item_id": "10000000-0000-4000-8000-000000000001",
      "field": "token",
      "project": "infra",
      "path": "example",
      "class": "sensitive"
    }
  ]
}
```

Run the installed command with an explicit broker home. For the dedicated-user
layout, P5 must provision /var/run/titanwarden as a service-owned directory with
mode 0755, so the hook can inspect a marker without access to private state.
No secret value is a command argument or environment assignment.

```sh
sudo -u titanwarden twadmin --home /var/db/titanwarden import-bitwarden --maintenance-dir /var/run/titanwarden manifest.json
```

The broker must already be unsealed, joined and at a verified current head.
Import authentication checks the passphrase without unsealing. An absent cloud
runtime refuses every import. The existing authenticated admin socket and its
peer verification remain the transport boundary.

The optional maintenance directory must match the hook's installed constant.
Without it, the marker is in the broker's state directory, suitable only when
the hook can traverse that directory. A hook denied access fails closed. P5's
sudo entry must pin the maintenance directory and installed executable and
must not allow an agent to substitute either.

The first SIGINT, SIGTERM, SIGHUP or SIGQUIT latches an abort and blocks all
four signals before raising the fixed E_IMPORT_ABORT failure. Later deliveries
are inert. Child creation and assignment, and group kill through stdout close
and direct-child reap, run with those signals blocked. The caller's signal mask
and handlers are restored before return. Final teardown blocks all four signals,
installs non-raising handlers that record only the first signal, then unblocks
all four, including any originally blocked by the caller. A Python execution
checkpoint and an empty abort-signal pending check precede restoring the exact
caller mask and original handlers. Every result is selected after teardown;
an abort overrides success, another failure, help and human-context refusal.
Restoration exceptions are contained and use fixed diagnostics.

The lifetime boundary is per signal: after its original handler is restored,
a new delivery belongs to the caller. After the exact caller mask is restored,
a newly arriving signal that the caller had blocked stays pending for the caller
and also belongs to the caller. Signals queued before recorder delivery are
handled as importer aborts even if the caller originally blocked them.

## Recovery and storage

The command is one Python process plus the directly executed bw child for each
read, with a direct bw sync at batch start and batch end to refresh the encrypted
local source cache. There is no per-item sync.
It never invokes a shell, editor or parser subprocess. Each child inherits
a hard and soft zero core limit. The deployment pins BW_EXECUTABLE to
/usr/local/libexec/titanwarden/bw, BW_HOME to /var/db/titanwarden, and BW_APPDATA
to /var/db/titanwarden/bitwarden in installed code. No environment variable or
CLI flag changes those settings. The executable and every parent must be
root-owned, without group or other write permission, with no symlink component;
the executable must be a regular executable file. Deploy a real file at that
path rather than a package-manager symlink. Tests alone inject an expected owner.
The child environment contains only PATH=/usr/bin:/bin, the fixed HOME and
BITWARDENCLI_APPDATA_DIR, and BW_SESSION if present. Caller home, app-data,
XDG, CA, locale, NODE and other runtime settings are discarded. BW_SESSION is
removed from os.environ as the first action of importer main, retained locally,
and passed explicitly through source calls only to the validated bw children.
The peer verifier uses /bin/launchctl and the human guard uses /bin/ps, each
with only PATH=/usr/bin:/bin in its replacement environment;
P5 must replace it with the protected service-user human ceremony before a real
vault import. The human-context check refuses Orca terminals and local agent
processes on both the twadmin route and direct module entry, using the existing
SSH exception. It remains a guardrail, not P5.

Source stdout stays in memory and source stderr goes to the null device.
Reads stop at 8 MiB plus one byte and refuse overflow, with a 30-second deadline
covering reads and child exit. Every child starts a new process group with closed
inherited descriptors. SIGINT, SIGTERM, SIGHUP and SIGQUIT all enter the same
bounded abort path. waitid with WNOWAIT observes successful exit without
releasing the leader PID or PGID. Cleanup kills the group while the leader is
unreaped, ignores ESRCH, closes stdout and always reaps even if close fails,
before any parsing or return. Darwin's EPERM for a zombie-only group is accepted
only after a non-reaping exit observation. Cleanup runs on success and on
overflow, timeout, interruption or parse failure, so a descendant
retaining stdout cannot keep the importer waiting. Only the selected UTF-8 field
becomes the write bytes.

All entries get journal rows before source reads. After the initial cache sync,
the command plans every source revision before any write, then rereads each
cached source just before its write. An end-of-batch sync and revision-only
check detect a remote source change hidden by the cache during the window.
A whole-manifest preflight first refuses any existing target with E_IMPORT_EXISTS,
before any source read or write. Updating an existing cloud secret is unavailable
until signed version activation is implemented. The runtime must also refuse a
target created after planning unless it can recover this exact request's receipt.
A revision change stops that item and the batch. Request UUIDs are derived from
the complete validated entry and revision using SHA-256, in the v4 UUID wire
shape accepted by the importer transport. Retrying a written or failed entry
uses that UUID. The production importer adapter records an intent under that
stable UUID before invoking P2 publication. Its binding contains the project/path,
a broker-computed keyed fingerprint and the authenticated admin principal. P2
is idempotent by that principal, path and value, so an ambiguous retry can recover
the original version without adding a caller request ID to the cloud runtime.
The adapter records the returned path, version_no and fingerprint_prefix as its
receipt after checking the verified active version. An existing name is accepted
only when the prior intent, signed active fingerprint and durable P2 principal
receipt all agree. A missing intent, different fingerprint or different principal
refuses with E_IMPORT_EXISTS. The write authorization callback repeats these
checks under the P2 write lock after its refreshed pull, covering a name created
after planning.
Verified entries are skipped exactly, including their source reads.

The private state file bitwarden-import.sqlite3 contains hashes of manifest and
entry, the strictly formatted source revision, request UUID, state and a fixed
error code. It contains no source value, field name, path, broker response or
exception text. A separate importer-owned metadata ledger in the broker database
uses bitwarden_intent_ keys, storing only stable request identity, principal, path,
keyed fingerprint and the publication receipt. The broker database commits this
intent durably before publication and retains it across restart; it never stores
the imported value in this ledger. The client journal uses a rollback journal,
synchronous EXTRA and in-memory temporary tables. Explicit fsync covers the database and directory after each
transition. SQLite recovery sidecars contain only this same metadata; there is
no plaintext spool or value temporary file.

A journal is bound to the exact manifest, including entry order. A changed
manifest is refused. Keep the completed journal as evidence, then explicitly
archive it before starting a different manifest. Never delete a journal for an
ambiguous write. No abort rolls back earlier writes. On any failure, the marker
remains until a successful exact resume; an operator should retain it while
investigating. The permanent mutex inode is never unlinked, preventing a lock
replacement race.

After each receipt, the importer generates a random one-use HMAC key and compares
its HMAC of the source with the broker's HMAC of the receipt's decrypted stored
version. The row remains written until that proof and the final refreshed source
revision both agree. Neither side prints a value or
digest. This verifies value equality for that version; it does not prove a
provider credential remains valid or authorize a cutover on another host.

A source change observed after writing is journaled as failed with
E_IMPORT_STALE. Final checking includes earlier verified rows when resuming a
partial batch, and it still runs for known writes after an abort. A stale row
cannot resume to success or overwrite its target. Retain the journal and import
to an approved new name until signed activation for updates is available.

All diagnostics use the fixed E_IMPORT codes in tw/bitwarden_import.py. Parser,
child, transport and broker exception messages are never displayed. A failure
reports that earlier writes remain in place and instructs exact journal resume.

## Separate bw-guard patch proposal

Do not apply this proposal as part of the broker change. The hook lives in
the command repository at bin/hooks/bw-guard.py. Add these exact lines after
the existing imports, and the second block immediately after the existing
has_bw_read early return in decide. This check must precede every parser-file
or single-field allow rule. There is no importer allow exception: its child
is a direct subprocess of a human operation, not an agent Bash tool invocation.

```diff
 import json
+import os
 import re
 import sys
+
+MAINTENANCE_LOCK = "/var/run/titanwarden/bitwarden-import.lock"
+
+def import_maintenance_active():
+    try:
+        os.stat(MAINTENANCE_LOCK, follow_symlinks=False)
+    except FileNotFoundError:
+        return False
+    except OSError:
+        return True
+    return True
```

```diff
     if not has_bw_read:
         return False
+    if import_maintenance_active():
+        return True
```

The existing matcher identifies get, list, export, edit and create. For the
window, also extend its verb list with delete, restore, purge and import, so
agent source mutations detected by that matcher refuse while the marker exists:

```diff
-        re.search(r'(?:^|[;&|(]|\$\()\s*(?:\w+=\S*\s+)*(?:sudo\s+|env\s+\S+\s+)*bw (?:get|list|export|edit|create)\b', command, re.M)
+        re.search(r'(?:^|[;&|(]|\$\()\s*(?:\w+=\S*\s+)*(?:sudo\s+|env\s+\S+\s+)*bw (?:get|list|export|edit|create|delete|restore|purge|import)\b', command, re.M)
```

This remains a hook guardrail, with the existing command parser's limitations.
It does not freeze another device or a direct same-user process. The dedicated
service account, protected executable, pinned sudo entry and operator source
freeze are required deployment controls. Never add a general agent importer
exception or permission to run arbitrary code as the service user.

## Verification and mutation witnesses

Tests use only a generated fake bw executable. Its source references a test-only
fixture producer; it contains no fixture value bytes. Failure tests inspect
stdout, stderr, the journal and every file in their temporary directory,
including simulated logs. The fake verifies inherited core limits itself.
