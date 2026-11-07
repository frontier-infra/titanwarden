"""PR 4 enrollment custody projection on the complete recovery/request verifier.

The earlier offline verifier remains byte compatible. This explicit extension
also materializes surviving, certificate-committed enrollment wraps, matching
the production enrollment control's epoch checkpoint integration.
"""
from copy import deepcopy

from .cloud_recovery import RecoveryVerifier
from .cloud_sync import guard


class SyncVerifier(RecoveryVerifier):
    def _authorize(self, entry, state):
        result = super()._authorize(entry, state)
        if entry['kind'] != 'broker_cert':
            return result
        cert = entry['body']['requested']
        if cert['state'] != 'active':
            return result
        epochs = self._candidate_epochs._state
        evidence = self._active_evidence
        for commitment in cert['wrap_digests']:
            found = [(table, row) for table in ('org_key_wraps', 'broker_key_wraps')
                for row in evidence._blobs.get(table, ()) if row.get('wrap_id') == commitment['id']]
            if not found:
                continue  # Archived digest still verifies history after GC.
            table, blob = found[0]
            full = table == 'org_key_wraps'
            if full:
                guard(cert['scope'] == 'full' and blob['recipient_kind'] == 'broker' and blob['recipient_id'] == cert['broker_id'] and blob['omk_generation'] == epochs['generation'], 'certified enrollment OMK identity differs')
                fields = ('recipient_kind', 'recipient_id', 'omk_generation', 'eph_pub', 'nonce', 'wrapped_omk', 'wrap_digest')
                identity = ('recipient_kind', 'recipient_id', 'omk_generation')
                target = 'org_wraps'
            else:
                key = next((k for k in epochs['keyring'] if k['key_id'] == blob['key_id']), None)
                guard(cert['scope'] != 'full' and blob['broker_id'] == cert['broker_id'] and key is not None and blob['purpose'] == key['purpose'] and blob['project'] == key['project'] and (blob['purpose'] == 'fingerprint' or blob['project'] in cert['scope'] and epochs['active_kek'].get(blob['project']) == blob['key_id']), 'certified enrollment scoped key differs')
                fields = ('broker_id', 'key_id', 'purpose', 'project', 'eph_pub', 'nonce', 'wrapped_key', 'wrap_digest')
                identity, target = ('broker_id', 'key_id'), 'broker_wraps'
            row = {k: blob[k].hex() if isinstance(blob[k], bytes) else blob[k] for k in fields}
            epochs[target] = [r for r in epochs[target] if any(r[k] != row[k] for k in identity)] + [row]
        return result
