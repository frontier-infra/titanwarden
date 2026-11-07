"""Integrated offline adversarial gate on disposable stores, without a browser."""
import copy
import sqlite3
import unittest

from tw import crypto
from tw.admin import resolve_cloud_policy
from tw.cloud_epochs import EpochReplay
from tw.policy_log import PolicyError, policy_record
import test_cloud_sync as sync_tests
import test_cloud_adopt as adoption_tests
from test_cloud_sync import ORG, BROKER, NOW


class BrokerReleaseTests(unittest.TestCase):
    def test_late_admission_observed_head_and_outage_residual(self):
        for witnessed in (False, True):
            with self.subTest(witnessed=witnessed):
                h = sync_tests.SyncTests()
                h.setUp()
                self.addCleanup(h.doCleanups)
                payload = h.payload()
                frames = list(h.frames)
                for signed in payload['entries']:
                    record = policy_record(signed['entry'], crypto.unb64url(signed['sig']), NOW)
                    blob = payload['version'] if signed['entry']['kind'] == 'version_add' else None
                    frames.append((record, None, blob, h.proof))
                if witnessed:
                    h.store.observe_cloud_head(ORG, h.verifier.head, '2026-10-16T00:15:00.000Z')
                    with self.assertRaisesRegex(PolicyError, 'late admission'):
                        h.sync.pull(frames, [payload['version']], projects=['a', 'b'], evidence=h.proof, observed_at='2026-10-16T00:30:00.000Z')
                    self.assertEqual(h.sync.conflicts()[-1]['reason'],'late_admission')
                    h.reopen()
                    with self.assertRaisesRegex(PolicyError, 'unresolved local conflict'):
                        h.sync.require_delivery('a', 'standard', NOW)
                else:
                    # No intervening observation means late admission cannot be
                    # proved. Preserve the explicitly documented outage residual.
                    h.sync.pull(frames, [payload['version']], projects=['a', 'b'], evidence=h.proof, observed_at='2026-10-16T00:30:00.000Z')
                    self.assertFalse(h.sync.conflicts())

    def test_local_resolution_is_explicit_and_cannot_erase_evidence(self):
        h = sync_tests.SyncTests()
        h.setUp()
        self.addCleanup(h.doCleanups)
        with self.assertRaisesRegex(ValueError, 'local cloud sync'):
            resolve_cloud_policy(object(), expected_head={}, through_conflict=1, typed_root=h.root, now=NOW)
        h.sync.refuse('fork', NOW)
        last = h.sync.conflicts()[-1]['conflict_id']
        with self.assertRaisesRegex(PolicyError, 'authenticated admin'):
            resolve_cloud_policy(h.sync, expected_head=h.verifier.head, through_conflict=last, typed_root=h.root, now=NOW)
        h.reopen()
        self.assertEqual(h.store.connection.execute('SELECT count(*) FROM cloud_conflicts').fetchone()[0], 1)
        self.assertTrue(h.sync.conflicts())
        # Legacy offline acknowledgement rows confer no resolution authority.
        h.store.connection.execute('INSERT INTO cloud_resolutions(org_id,through_conflict,seq,hash,resolved_at) VALUES (?,?,?,?,?)', (ORG,last,h.verifier.head['seq'],h.verifier.head['hash'],NOW))
        self.assertTrue(h.sync.conflicts())
        h.store.connection.execute('INSERT INTO cloud_sync_holds VALUES (?,?,?,?,?,?,?)', (ORG, 'a' * 64, h.verifier.head['seq'], h.verifier.head['hash'], 'TEST-ONLY', NOW, h.verifier.head['seq']))
        for table, column in [('cloud_resolutions', 'resolved_at'), ('cloud_conflicts', 'reason'), ('cloud_sync_holds', 'status')]:
            with self.assertRaises(sqlite3.IntegrityError):
                h.store.connection.execute('DELETE FROM ' + table)
            with self.assertRaises(sqlite3.IntegrityError):
                h.store.connection.execute('UPDATE ' + table + ' SET ' + column + '=' + column)

    def test_scoped_ciphertext_finalization_requires_all_and_only_its_projects(self):
        h = sync_tests.SyncTests()
        h.setUp()
        self.addCleanup(h.doCleanups)
        payload = h.payload()
        metadata = dict(payload['entries'][-1]['entry']['body'], project='a')
        checker = EpochReplay()
        checker._state['versions'] = [metadata, dict(metadata, version_id='other-project', project='b')]
        checker.verify_current_ciphertexts([payload['version']], projects=['a'])
        with self.assertRaisesRegex(PolicyError, 'Missing or extra'):
            checker.verify_current_ciphertexts([], projects=['a'])
        with self.assertRaisesRegex(PolicyError, 'Certified sync broker'):
            h.verifier.finish_history([], evidence=h.proof, broker_id='unknown')

    def test_interrupted_copy_adoption_preserves_every_source_version_and_stays_closed(self):
        h = adoption_tests.LocalAdoptionTests()
        h.setUp()
        self.addCleanup(h.doCleanups)
        store = h.copy()
        before = copy.deepcopy(h.snapshot)
        def interrupt(phase):
            if phase == 'envelope_batch':
                raise InterruptedError('TEST-ONLY simulated power loss')
        with self.assertRaises(InterruptedError):
            h.run_draft(h.draft(store), checkpoint=interrupt)
        store.close()
        store.open()
        result = h.run_draft(h.draft(store))
        self.assertEqual(result['phase'], 'verified_draft')
        self.assertFalse(result['legacy_retired'])
        self.assertEqual({t:adoption_tests._rows(h.source,t) for t in before}, before)
        with self.assertRaisesRegex(RuntimeError, 'E_LEGACY_ADOPTION'):
            h.draft(store).publish()
        with self.assertRaisesRegex(RuntimeError, 'E_LEGACY_ADOPTION'):
            h.draft(store).retire_legacy()


if __name__ == '__main__':
    unittest.main()
