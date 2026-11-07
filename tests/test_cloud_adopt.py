import json
import tempfile
import unittest
from pathlib import Path

from tw import crypto
from tw.backup import disposable_adoption_copy
from tw.cloud_adopt import AdoptionDraft, _rows
from tw.store import Store
from tw.seal import CloudCustody, SealError
from support import TEST_PASSPHRASE, TEST_ARGON2


class LocalAdoptionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='tw-pr2-')
        self.addCleanup(self.tmp.cleanup)
        self.source = Store(Path(self.tmp.name)/'source').open(create=True)
        self.addCleanup(self.source.close)
        self.master,self.recovery = self.source.initialize(TEST_PASSPHRASE,argon2=TEST_ARGON2)
        keys = self.source.load_keyring(self.master)
        for project in ('a','b'):
            self.source.connection.execute('INSERT INTO projects(slug,created_at) VALUES (?,?)',(project,'now'))
            for i in range(2):
                self.source.put_secret(project+'/value',('test-value-'+str(i)).encode(),keyring=keys,principal_id='human:test')
        self.source.checkpoint()
        self.snapshot={t:_rows(self.source,t) for t in ('keyring','slots','projects','secrets','secret_versions')}
        self.omk,self.blk=crypto.random_key(),crypto.random_key()
        self.ids=[r['key_id'] for r in self.snapshot['keyring']]

    def copy(self,name='copy'):
        home=disposable_adoption_copy(self.source.home,Path(self.tmp.name)/name)
        store=Store(home).open()
        self.addCleanup(store.close)
        return store

    def draft(self,store):
        return AdoptionDraft(store,self.master,self.omk,self.blk,broker='brk_test')

    def run_draft(self,draft,**kwargs):
        return draft.rewrite_local_keyring(from_generation=1,to_generation=2,expected_key_ids=self.ids,**kwargs)

    def test_rewrite_keeps_all_retained_versions_and_source_unchanged(self):
        store=self.copy()
        draft=self.draft(store)
        result=self.run_draft(draft)
        self.assertEqual(result['all_aad_v'],2)
        self.assertFalse(result['legacy_retired'])
        self.assertEqual(result['rewritten_key_ids'],sorted(self.ids))
        self.assertEqual(set(result['staged_project_keys']),{r['slug'] for r in self.snapshot['projects']})
        self.assertEqual(store.connection.execute('SELECT count(*) FROM cloud_adoption_envelopes').fetchone()[0],4)
        self.assertEqual({t:_rows(store,t) for t in self.snapshot},self.snapshot)
        self.assertEqual({t:_rows(self.source,t) for t in self.snapshot},self.snapshot)
        for row in store.connection.execute('SELECT * FROM cloud_adoption_envelopes'):
            original=next(v for v in self.snapshot['secret_versions'] if v['version_id']==row['version_id'])
            self.assertNotEqual(row['to_kek_id'],row['from_kek_id'])
            self.assertNotEqual(bytes(row['nonce']).hex(),original['dek_nonce'])
        with self.assertRaisesRegex(RuntimeError,'E_LEGACY_ADOPTION'):
            draft.publish()
        with self.assertRaisesRegex(RuntimeError,'E_LEGACY_ADOPTION'):
            draft.retire_legacy()
        before=_rows(store,'cloud_adoption_keys'),_rows(store,'cloud_adoption_envelopes')
        self.run_draft(self.draft(store))
        self.assertEqual((_rows(store,'cloud_adoption_keys'),_rows(store,'cloud_adoption_envelopes')),before)

    def test_restart_after_each_committed_checkpoint(self):
        for phase in ('inventoried','keys_staged','envelope_batch','envelopes_staged','verified_draft'):
            with self.subTest(phase=phase):
                store=self.copy(phase)
                def crash(checkpoint):
                    if checkpoint==phase:
                        raise InterruptedError('disposable simulated crash')
                with self.assertRaises(InterruptedError):
                    self.run_draft(self.draft(store),checkpoint=crash)
                store.close()
                store=Store(store.home).open()
                self.addCleanup(store.close)
                result=self.run_draft(self.draft(store))
                self.assertEqual(result['phase'],'verified_draft')
                self.assertEqual({t:_rows(store,t) for t in self.snapshot},self.snapshot)

    def test_exact_set_changed_source_and_tampered_stage_refuse(self):
        store=self.copy()
        with self.assertRaises(ValueError):
            self.draft(store).rewrite_local_keyring(from_generation=1,to_generation=2,expected_key_ids=self.ids[:-1])
        draft=self.draft(store)
        self.run_draft(draft)
        store.connection.execute("UPDATE cloud_adoption_keys SET nonce=zeroblob(12) WHERE key_id=?",(self.ids[0],))
        with self.assertRaises(crypto.CryptoError):
            self.run_draft(self.draft(store))
        store.connection.execute("UPDATE secret_versions SET source='tampered'")
        with self.assertRaisesRegex(ValueError,'source'):
            self.run_draft(draft)
        with self.assertRaisesRegex(ValueError,'source'):
            self.run_draft(self.draft(store))

    def test_refuse_live_or_unmarked_store(self):
        with self.assertRaisesRegex(ValueError,'disposable copy'):
            self.draft(self.source)
        with self.assertRaises(ValueError):
            disposable_adoption_copy(self.source.home,self.source.home.parent/'source')

    def test_default_schema_remains_local_and_custody_binds_identity(self):
        self.assertFalse(self.source.connection.execute("SELECT 1 FROM sqlite_master WHERE name LIKE 'cloud_%'").fetchall())
        store=self.copy()
        org=store.meta('store_id')
        cust=CloudCustody(store,org,'brk_test',self.blk)
        slot_key=crypto.random_key()
        cust.wrap_slot('slot_test',slot_key,generation=1,params={'kind':'test'})
        cust.close()
        self.assertEqual(bytes(cust._blk),bytes(32))
        with self.assertRaises(SealError):
            cust.wrap_slot('slot_test',slot_key,generation=1,params={})
        reopened=CloudCustody.unseal_slot(store,org,'brk_test','slot_test',1,slot_key)
        self.addCleanup(reopened.close)
        self.assertEqual(bytes(reopened._blk),self.blk)
        key=crypto.random_key()
        args=dict(org=org,broker='brk_test',key_id='key_test',purpose='omk',scope='*',generation=1)
        store.put_cloud_local_key(self.blk,key=key,**args)
        self.assertEqual(store.cloud_local_key(self.blk,**args),key)
        with self.assertRaises(Exception):
            store.cloud_local_key(crypto.random_key(),**args)
        with self.assertRaises(Exception):
            store.cloud_local_key(self.blk,**dict(args,scope='other'))
        with self.assertRaises(Exception):
            store.put_cloud_local_key(self.blk,key=crypto.random_key(),**args)

    def test_local_unlock_slots_are_staged_under_blk_and_rebinding_fails(self):
        store=self.copy()
        draft=self.draft(store)
        slot_keys={}
        for row in self.snapshot['slots']:
            params=json.loads(row['params_json'])
            if row['kind']=='passphrase':
                # Match the existing standalone slot derivation exactly.
                argon,salt=crypto.Argon2Params.from_dict(params)
                slot_keys[row['slot_id']]=crypto.derive_passphrase_key(TEST_PASSPHRASE,salt,argon)
        with self.assertRaises(ValueError):
            draft.stage_local_slots(slot_keys,generation=2)
        slot_keys['slot_recovery']=crypto.derive_recovery_slot_key(crypto.decode_recovery_key(self.recovery))
        draft.stage_local_slots(slot_keys,generation=2)
        self.assertEqual(store.connection.execute('SELECT count(*) FROM cloud_local_slots').fetchone()[0],2)
        recovered=CloudCustody.unseal_slot(store,store.meta('store_id'),'brk_test','slot_passphrase',2,slot_keys['slot_passphrase'])
        self.addCleanup(recovered.close)
        self.assertEqual(bytes(recovered._blk),self.blk)
        self.run_draft(draft)
        with self.assertRaises(Exception):
            self.run_draft(AdoptionDraft(store,self.master,crypto.random_key(),self.blk,broker='brk_test'))

    def test_dek_batches_resume_without_rewriting_completed_batch(self):
        keys=self.source.load_keyring(self.master)
        for index in range(197):
            self.source.put_secret('a/value',('extra-retained-'+str(index)).encode(),keyring=keys,principal_id='human:test')
        self.source.checkpoint()
        self.snapshot={t:_rows(self.source,t) for t in self.snapshot}
        store=self.copy()
        def crash(phase):
            if phase=='envelope_batch':
                raise InterruptedError('first batch committed')
        with self.assertRaises(InterruptedError):
            self.run_draft(self.draft(store),checkpoint=crash)
        first=_rows(store,'cloud_adoption_envelopes')
        self.assertEqual(len(first),200)
        self.run_draft(self.draft(store))
        all_rows={r['version_id']:r for r in _rows(store,'cloud_adoption_envelopes')}
        self.assertEqual(len(all_rows),201)
        self.assertEqual(first,[all_rows[r['version_id']] for r in first])

    def test_failure_inside_key_transaction_rolls_back_entire_stage(self):
        from unittest.mock import patch
        store=self.copy()
        original=crypto.wrap_key
        calls=[]
        def fail(wrapping,key,aad):
            if aad.startswith(b'tw2|key|'):
                calls.append(aad)
                if len(calls)==2:
                    raise InterruptedError('inside key transaction')
            return original(wrapping,key,aad)
        with patch.object(crypto,'wrap_key',fail),self.assertRaises(InterruptedError):
            self.run_draft(self.draft(store))
        self.assertEqual(store.connection.execute('SELECT count(*) FROM cloud_adoption_keys').fetchone()[0],0)
        self.assertEqual(store.connection.execute('SELECT phase FROM cloud_adoption_journal').fetchone()[0],'inventoried')
        self.assertEqual(self.run_draft(self.draft(store))['phase'],'verified_draft')

    def test_tampered_envelope_and_missing_key_never_retire(self):
        store=self.copy()
        self.run_draft(self.draft(store))
        store.connection.execute('UPDATE cloud_adoption_envelopes SET wrapped_dek=zeroblob(48)')
        with self.assertRaises(crypto.CryptoError):
            self.run_draft(self.draft(store))
        store.connection.execute('DELETE FROM cloud_adoption_keys WHERE key_id=?',(self.ids[0],))
        with self.assertRaisesRegex(ValueError,'key set'):
            self.run_draft(self.draft(store))
        self.assertEqual({t:_rows(store,t) for t in self.snapshot},self.snapshot)

    def test_local_master_generation_is_distinct_from_cloud_epoch_generation(self):
        # A legacy local master may have rotated before cloud enrollment starts
        # its independent OMK generation-one bootstrap.
        self.source.set_meta('mk_generation','7')
        self.source.checkpoint()
        store=self.copy()
        with self.assertRaisesRegex(ValueError,'adoption generation differs'):
            self.draft(store).rewrite_local_keyring(from_generation=1,to_generation=3,expected_key_ids=self.ids)
        result=self.run_draft(self.draft(store))
        self.assertEqual(result['phase'],'verified_draft')
        plan=json.loads(store.connection.execute('SELECT plan_json FROM cloud_adoption_journal').fetchone()[0])
        self.assertEqual(plan['legacy_mk_generation'],7)
        self.assertEqual((plan['from_generation'],plan['to_generation']),(1,2))

    def test_every_marker_identity_field_and_inventory_digest(self):
        for field,value,error in (('format',2,'copy identity'),('target','different','copy identity'),
                                  ('source',None,'copy identity'),('checkpoint','different','snapshot checksum'),('inventory_digest','0'*64,'source inventory')):
            with self.subTest(field=field):
                store=self.copy('marker-'+field)
                path=store.home/'ADOPTION-DRAFT-COPY.json'
                marker=json.loads(path.read_text())
                marker[field]=str(store.db_path) if field=='source' else value
                path.write_text(json.dumps(marker))
                with self.assertRaisesRegex(ValueError,error): self.draft(store)

    def test_immutable_checkpoint_checksum_is_checked_on_every_open(self):
        for completed in (False,True):
            with self.subTest(completed=completed):
                store=self.copy('checksum-'+str(completed))
                draft=self.draft(store)
                if completed: self.run_draft(draft)
                path=store.home/'ADOPTION-SOURCE.db'
                path.chmod(0o600)
                with path.open('ab') as output: output.write(b'tampered trailing bytes')
                with self.assertRaisesRegex(ValueError,'snapshot checksum differs'): self.draft(store)

    def test_copy_rejects_nested_and_existing_targets_and_reads_source_only(self):
        import sqlite3
        from unittest.mock import patch
        with self.assertRaisesRegex(ValueError,'distinct disposable target'):
            disposable_adoption_copy(self.source.home,self.source.home/'nested')
        existing=Path(self.tmp.name)/'already-exists';existing.mkdir()
        with self.assertRaises(FileExistsError): disposable_adoption_copy(self.source.home,existing)
        connect=sqlite3.connect
        attempted=[]
        def checked(*args,**kwargs):
            connection=connect(*args,**kwargs)
            if not attempted:
                attempted.append(True)
                try:
                    with self.assertRaisesRegex(sqlite3.OperationalError,'readonly'):
                        connection.execute('CREATE TABLE readonly_probe(value TEXT)')
                except BaseException:
                    connection.close()
                    raise
            return connection
        with patch('tw.backup.sqlite3.connect',side_effect=checked):
            disposable_adoption_copy(self.source.home,Path(self.tmp.name)/'read-only-copy')
        self.assertEqual(attempted,[True])

    def test_changed_resume_plan_and_incomplete_envelope_refuse(self):
        store=self.copy()
        self.run_draft(self.draft(store))
        row=store.connection.execute('SELECT plan_json FROM cloud_adoption_journal').fetchone()
        plan=json.loads(row[0]);plan['broker']='other-broker'
        store.connection.execute('UPDATE cloud_adoption_journal SET plan_json=?',(crypto.canonical_json(plan).decode(),))
        with self.assertRaisesRegex(ValueError,'resume input or source'): self.run_draft(self.draft(store))
        self.source.connection.execute('UPDATE secret_versions SET ciphertext=NULL WHERE version_id=(SELECT version_id FROM secret_versions LIMIT 1)')
        self.source.checkpoint()
        incomplete=self.copy('incomplete')
        with self.assertRaisesRegex(ValueError,'incomplete retained ciphertext envelope'):
            self.run_draft(self.draft(incomplete))

    def test_local_slot_rebinding_is_an_explicit_refusal(self):
        from tw.store import StoreError
        store=self.copy();org=store.meta('store_id');key=crypto.random_key()
        first=CloudCustody(store,org,'brk_test',self.blk);self.addCleanup(first.close)
        first.wrap_slot('test-slot',key,generation=1,params={'kind':'test'})
        with self.assertRaisesRegex(StoreError,'local slot rebinding'):
            first.wrap_slot('test-slot',key,generation=1,params={'kind':'changed'})
        other=CloudCustody(store,org,'brk_test',crypto.random_key());self.addCleanup(other.close)
        with self.assertRaisesRegex(StoreError,'local slot rebinding'):
            other.wrap_slot('test-slot',key,generation=1,params={'kind':'test'})

    def test_staged_key_metadata_and_retained_plaintext_are_verified(self):
        for field,value in (('generation',3),('scope','different'),('purpose','fingerprint'),('key',None)):
            with self.subTest(field=field):
                store=self.copy('staged-'+field);draft=self.draft(store);self.run_draft(draft)
                row=dict(store.connection.execute("SELECT * FROM cloud_adoption_keys WHERE purpose='kek' AND scope='*' LIMIT 1").fetchone())
                raw=draft._source_keys()[row['key_id']]
                if field=='key': raw=crypto.random_key()
                else: row[field]=value
                wrapped,nonce=crypto.wrap_key(self.omk,raw,draft._aad(row,2))
                store.connection.execute('UPDATE cloud_adoption_keys SET generation=?,purpose=?,scope=?,wrapped_key=?,nonce=? WHERE key_id=?',
                    (row['generation'],row['purpose'],row['scope'],wrapped,nonce,row['key_id']))
                message='retained source key changed' if field=='key' else 'staged key metadata differs'
                with self.assertRaisesRegex(ValueError,message): self.run_draft(self.draft(store))

    def test_rewrapped_dek_plaintext_is_verified_even_with_valid_aead_and_digest(self):
        store=self.copy();draft=self.draft(store);self.run_draft(draft)
        row=dict(store.connection.execute('SELECT * FROM cloud_adoption_envelopes LIMIT 1').fetchone())
        target=dict(store.connection.execute('SELECT * FROM cloud_adoption_keys WHERE key_id=?',(row['to_kek_id'],)).fetchone())
        key=crypto.unwrap_key(self.omk,bytes(target['wrapped_key']),bytes(target['nonce']),draft._aad(target,2))
        wrapped,nonce=crypto.wrap_key(key,crypto.random_key(),crypto.dek_aad(draft.org,row['version_id'],row['to_kek_id']))
        store.connection.execute('UPDATE cloud_adoption_envelopes SET wrapped_dek=?,nonce=?,to_digest=? WHERE version_id=?',
            (wrapped,nonce,crypto.envelope_digest(row['to_kek_id'],wrapped,nonce),row['version_id']))
        with self.assertRaisesRegex(ValueError,'rewritten DEK verification differs'): self.run_draft(self.draft(store))

    def test_local_custody_metadata_is_checked_before_crypto(self):
        from tw.store import StoreError
        store=self.copy();store.initialize_cloud_custody();org=store.meta('store_id');key=crypto.random_key()
        args=dict(org=org,broker='brk_test',key_id='review_key',purpose='omk',scope='*',generation=1)
        store.put_cloud_local_key(self.blk,key=key,**args)
        for field in ('purpose','scope'):
            with self.subTest(field=field):
                store.connection.execute(f'UPDATE cloud_local_keys SET {field}=?',('other',))
                with self.assertRaisesRegex(StoreError,'local custody metadata changed'):
                    store.put_cloud_local_key(self.blk,key=key,**args)
                store.connection.execute(f'UPDATE cloud_local_keys SET {field}=?',(args[field],))
                changed=dict(args,**{field:'other'})
                with self.assertRaisesRegex(StoreError,'local custody key unavailable'):
                    store.cloud_local_key(self.blk,**changed)
        with self.assertRaisesRegex(StoreError,'local custody key rebinding'):
            store.put_cloud_local_key(self.blk,key=crypto.random_key(),**args)
        store.connection.execute('DELETE FROM cloud_local_keys')
        with self.assertRaisesRegex(StoreError,'local custody key unavailable'):
            store.cloud_local_key(self.blk,**args)

    def test_slot_unlock_proof_must_match_the_supplied_master(self):
        store=self.copy();slot_keys={}
        for row in self.snapshot['slots']:
            if row['kind']=='passphrase':
                params,salt=crypto.Argon2Params.from_dict(json.loads(row['params_json']))
                slot_keys[row['slot_id']]=crypto.derive_passphrase_key(TEST_PASSPHRASE,salt,params)
            elif row['kind']=='recovery':
                slot_keys[row['slot_id']]=crypto.derive_recovery_slot_key(crypto.decode_recovery_key(self.recovery))
        draft=AdoptionDraft(store,crypto.random_key(),self.omk,self.blk,broker='brk_test')
        with self.assertRaisesRegex(ValueError,'local slot unlock proof differs'):
            draft.stage_local_slots(slot_keys,generation=2)
        self.assertEqual(store.connection.execute('SELECT count(*) FROM cloud_local_slots').fetchone()[0],0)

    def test_marker_and_checkpoint_symlinks_and_missing_checkpoint_refuse(self):
        for case in ('marker_symlink','checkpoint_symlink','checkpoint_missing'):
            with self.subTest(case=case):
                store=self.copy(case)
                if case=='marker_symlink':
                    path=store.home/'ADOPTION-DRAFT-COPY.json'
                    original=path.with_name('original-marker.json');path.rename(original);path.symlink_to(original)
                    message='marked disposable copy'
                else:
                    path=store.home/'ADOPTION-SOURCE.db'
                    if case=='checkpoint_symlink':
                        original=path.with_name('original-source.db');path.rename(original);path.symlink_to(original)
                    else:
                        path.unlink()
                    message='snapshot checksum differs'
                with self.assertRaisesRegex(ValueError,message): self.draft(store)

    def test_each_rewritten_envelope_metadata_commitment_is_verified(self):
        for field in ('from_kek_id','to_kek_id','from_digest','to_digest'):
            with self.subTest(field=field):
                store=self.copy('envelope-'+field);self.run_draft(self.draft(store))
                value='wrong-key' if field.endswith('kek_id') else '0'*64
                store.connection.execute(f'UPDATE cloud_adoption_envelopes SET {field}=?',(value,))
                with self.assertRaisesRegex(ValueError,'rewritten DEK verification differs'):
                    self.run_draft(self.draft(store))

    def test_staged_aad_version_and_journal_source_digest_are_verified(self):
        store=self.copy();self.run_draft(self.draft(store))
        store.connection.execute('PRAGMA ignore_check_constraints=ON')
        store.connection.execute('UPDATE cloud_adoption_keys SET aad_v=1')
        with self.assertRaisesRegex(ValueError,'staged key metadata differs'):
            self.run_draft(self.draft(store))
        store.connection.execute('UPDATE cloud_adoption_keys SET aad_v=2')
        store.connection.execute('UPDATE cloud_adoption_journal SET source_digest=?',('0'*64,))
        with self.assertRaisesRegex(ValueError,'resume input or source differs'):
            self.run_draft(self.draft(store))

    def test_journal_rechecked_after_durable_inventory_checkpoint(self):
        for case in ('missing','changed'):
            with self.subTest(case=case):
                store=self.copy('journal-'+case)
                def changed(phase):
                    if phase=='inventoried':
                        if case=='missing': store.connection.execute('DELETE FROM cloud_adoption_journal')
                        else: store.connection.execute('UPDATE cloud_adoption_journal SET source_digest=?',('0'*64,))
                with self.assertRaisesRegex(ValueError,'adoption journal source differs'):
                    self.run_draft(self.draft(store),checkpoint=changed)

    def test_rewritten_version_set_refuses_extra_or_missing_envelopes(self):
        for case in ('extra','missing'):
            with self.subTest(case=case):
                store=self.copy('versions-'+case);self.run_draft(self.draft(store))
                row=dict(store.connection.execute('SELECT * FROM cloud_adoption_envelopes LIMIT 1').fetchone())
                if case=='extra':
                    row['version_id']='unexpected-version'
                    store.connection.execute('INSERT INTO cloud_adoption_envelopes VALUES (?,?,?,?,?,?,?,?)',tuple(row.values()))
                else:
                    store.connection.execute('DELETE FROM cloud_adoption_envelopes WHERE version_id=?',(row['version_id'],))
                    # A durable phase must not silently refill a missing staged
                    # row during verification. Observe the exact-set verifier.
                    original=store.connection.execute
                    # Remove the row after all rewrap batches have committed.
                    def drop(phase):
                        if phase=='envelopes_staged':
                            original('DELETE FROM cloud_adoption_envelopes WHERE version_id=?',(row['version_id'],))
                    with self.assertRaisesRegex(ValueError,'rewritten version set differs'):
                        self.run_draft(self.draft(store),checkpoint=drop)
                    continue
                with self.assertRaisesRegex(ValueError,'rewritten version set differs'):
                    self.run_draft(self.draft(store))
