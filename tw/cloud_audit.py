"""Offline broker audit exchange with independently configured release pins.

An HTTP response cannot select a trust key. Control-chain receipts are cloud
assertions, and neither receipts nor archive diagnostics authorize deletion.
"""
from copy import deepcopy
import json

from . import crypto, cloud_wire as wire
from .audit import _json_row
from .policy_log import utc_millis, PolicyError


class AuditConflict(ValueError):
    code = 'E_AUDIT'


def check(condition, message):
    if not condition:
        raise AuditConflict(message)


AUDIT_COLUMNS = tuple(('seq event_id ts host op phase decision reason_code principal_id token_id '
    'parent_principal_id project secret_path version_no lease_id parent_lease_id plan_id share_id '
    'request_id orca_run_id dispatch_id task_id job launchd_label attest_status attested_handle '
    'context_verified peer_uid peer_pid peer_exe claimed_json argv0 argv_sha256 shell exit_code '
    'redactions scrubbed detail_json sealed_tail prev_hash hash mac').split())
NUMERIC = frozenset(('seq', 'version_no', 'context_verified', 'peer_uid', 'peer_pid', 'shell',
    'exit_code', 'redactions', 'scrubbed', 'sealed_tail'))
REQUIRED = frozenset(('seq event_id ts host op phase decision context_verified claimed_json '
    'scrubbed detail_json sealed_tail prev_hash hash').split())


def audit_row_hash(row):
    wire.exact(row, AUDIT_COLUMNS)
    for key, value in row.items():
        if value is None and key not in REQUIRED:
            continue
        if key in NUMERIC:
            crypto.safe_integer(value)
        else:
            check(isinstance(value, str), 'audit row field type differs')
    check(row['seq'] >= 1 and row['event_id'] and row['phase'] in ('intent', 'result', 'single') and row['decision'] in ('allow', 'deny', 'error'), 'audit row identity differs')
    check(all(row[k] is None or row[k] in (0, 1) for k in ('context_verified', 'shell', 'scrubbed', 'sealed_tail')), 'audit flag differs')
    utc_millis(row['ts'])
    wire.digest(row['prev_hash'])
    wire.digest(row['hash'])
    if row['mac'] is not None:
        wire.digest(row['mac'])
    return crypto.sha256(bytes.fromhex(row['prev_hash']) + _json_row(row)).hex()


def checkpoint(org, chain, head, ts, audit_key):
    wire.parse_head(head)
    utc_millis(ts)
    check(head['seq'] > 0 and chain != 'control', 'broker checkpoint requires nonempty broker chain')
    message = crypto.checkpoint_context(org, chain, head['seq'], head['hash'], ts)
    return dict(head, ts=ts, sig=crypto.b64url(crypto.p256_sign(audit_key, message)))


def verify_checkpoint(org, chain, value, public):
    wire.exact(value, ('seq', 'hash', 'ts', 'sig'))
    wire.parse_head({k: value[k] for k in ('seq', 'hash')})
    utc_millis(value['ts'])
    check(value['seq'] > 0, 'empty audit checkpoint')
    if chain == 'control':
        check(value['sig'] is None and public is None, 'control checkpoint must be a cloud assertion')
    else:
        check(public is not None and crypto.p256_verify(public, crypto.checkpoint_context(org, chain, value['seq'], value['hash'], value['ts']), wire.binary(value['sig'], 64)), 'broker audit checkpoint signature differs')


class ReceiptPins:
    """Construct from release configuration, never from a fetched response."""
    def __init__(self, current_id, current_public, *, retained=()):
        self.current_id = wire.text(current_id)
        crypto.import_point(current_public)
        self._keys = {current_id: (bytes(current_public), None)}
        for key_id, public, retired_at in retained:
            wire.text(key_id)
            crypto.import_point(public)
            utc_millis(retired_at)
            check(key_id not in self._keys, 'duplicate receipt release key id')
            self._keys[key_id] = (bytes(public), retired_at)

    def verify(self, org, chain, expected, receipt):
        wire.exact(receipt, ('seq', 'hash', 'ts', 'sig', 'key_id', 'issued_at', 'receipt_sig'))
        check(all(receipt[k] == expected[k] for k in ('seq', 'hash', 'ts', 'sig')), 'receipt original checkpoint differs')
        wire.integer(receipt['seq'], 1)
        wire.digest(receipt['hash'])
        utc_millis(receipt['ts'])
        utc_millis(receipt['issued_at'])
        check((receipt['sig'] is None) == (chain == 'control'), 'receipt chain assertion differs')
        key = self._keys.get(receipt['key_id'])
        check(key is not None, 'unknown receipt release key')
        message = crypto.checkpoint_context(org, chain, receipt['seq'], receipt['hash'], receipt['ts'], True, receipt['sig'], receipt['key_id'], receipt['issued_at'])
        check(crypto.p256_verify(key[0], message, wire.binary(receipt['receipt_sig'], 64)), 'cloud receipt signature differs')
        check(key[1] is None or utc_millis(receipt['issued_at']) < utc_millis(key[1]), 'receipt issued after release key retirement')
        return deepcopy(receipt)


class AuditSync:
    def __init__(self, store, org, chain, pins, *, broker_public=None):
        wire.org_id(org)
        wire.text(chain)
        check(isinstance(pins, ReceiptPins), 'release receipt pins required')
        self.store, self.org, self.chain = store, org, chain
        self.pins, self.public = pins, broker_public
        check(store.cloud_pin(org) is not None, 'independent cloud pin required for audit sync')
        store.initialize_cloud_sync()

    def retained(self):
        row = self.store.connection.execute('SELECT receipt_json FROM cloud_audit_receipts WHERE org_id=? AND chain_id=? ORDER BY seq DESC LIMIT 1', (self.org, self.chain)).fetchone()
        return dict(seq=0, hash='0' * 64) if row is None else {k: json.loads(row[0])[k] for k in ('seq', 'hash')}

    def accept(self, rows, expected, receipt, *, observed_at):
        utc_millis(observed_at)
        try:
            verify_checkpoint(self.org, self.chain, expected, self.public)
            self.pins.verify(self.org, self.chain, expected, receipt)
            retained = self.retained()
            check(expected['seq'] >= retained['seq'] and len(rows) == expected['seq'] - retained['seq'], 'audit suffix lost or incomplete')
            head = retained
            for row in rows:
                check(row['seq'] == head['seq'] + 1 and row['prev_hash'] == head['hash'] and audit_row_hash(row) == row['hash'], 'audit history reordered or edited')
                head = {k: row[k] for k in ('seq', 'hash')}
            check(head == {k: expected[k] for k in ('seq', 'hash')}, 'audit head differs')
            with self.store.transaction(immediate=True) as db:
                check(self.retained() == retained, 'audit retained head changed')
                prior = db.execute('SELECT receipt_json FROM cloud_audit_receipts WHERE org_id=? AND chain_id=? AND seq=?', (self.org, self.chain, expected['seq'])).fetchone()
                raw = crypto.canonical_json(receipt).decode()
                check(prior is None or prior[0] == raw, 'retained audit receipt differs')
                for row in rows:
                    db.execute('INSERT INTO cloud_audit_rows VALUES (?,?,?,?)', (self.org, self.chain, row['seq'], crypto.canonical_json(row).decode()))
                db.execute('INSERT OR IGNORE INTO cloud_audit_receipts VALUES (?,?,?,?)', (self.org, self.chain, expected['seq'], raw))
            return dict(head, assertion='cloud_asserted' if self.chain == 'control' else 'broker_signed')
        except (ValueError, KeyError, TypeError, PolicyError) as exc:
            # Receipt/exchange failures are audit diagnostics, not evidence of
            # divergent policy. Keep them separate from the value delivery gate.
            with self.store.transaction(immediate=True) as db:
                db.execute('INSERT INTO cloud_audit_conflicts(org_id,chain_id,reason,observed_at) VALUES (?,?,?,?)', (self.org, self.chain, 'audit_integrity', observed_at))
            if isinstance(exc, AuditConflict):
                raise
            raise AuditConflict(str(exc)) from exc

    def push(self, client, base_url, rows, expected):
        verify_checkpoint(self.org, self.chain, expected, self.public)
        check(client.org == self.org and client.broker == self.chain and self.chain != 'control', 'audit upload identity differs')
        check(isinstance(rows, list) and 1 <= len(rows) <= 500, 'audit upload batch limit exceeded')
        return client.send_once(client.prepare('POST', base_url.rstrip('/') + f'/v1/orgs/{self.org}/sync/audit', dict(chain_id=self.chain, events=rows, checkpoint=expected)))
