import copy
import json
import tempfile
import unittest
from pathlib import Path

from tw import crypto
from tw.cloud_enroll import (proof_message, verify_proof, EnrollmentSession,
    ticket_id, checked_transcript, save_reservation, load_reservation, legacy_ingestion)
from tw.admin import pin_cloud_enrollment
from tw.store import Store
from support import TEST_PASSPHRASE, TEST_ARGON2
from test_cloud_http import vectors


class EnrollmentTests(unittest.TestCase):
    def test_all_v4_enrollment_proofs_and_adoption_aad(self):
        for v in vectors():
            with self.subTest(v['id']):
                if v['op']=='enrollment':
                    message=proof_message(v['org_id'],v['ticket_id'],v['transcript'])
                    self.assertEqual(crypto.canonical_json(v['transcript']).decode(),v['canonical_json'])
                    self.assertEqual(crypto.sha256(crypto.canonical_json(v['transcript'])).hex(),v['transcript_digest'])
                    verify_proof(v['org_id'],v['ticket_id'],v['transcript'],v['signature'])
                elif v['op']=='adopt-root':
                    t=v['payload']['transcript'];root=v['payload']['candidate_root']
                    message=proof_message(v['org_id'],v['ticket_id'],t,root)
                    self.assertEqual(crypto.canonical_json(v['payload']).decode(),v['canonical_json'])
                    verify_proof(v['org_id'],v['ticket_id'],t,v['signature'],root)
                    with self.assertRaises(ValueError):
                        verify_proof(v['org_id'],v['ticket_id'],t,v['signature'])
                    with self.assertRaises(ValueError):
                        verify_proof(v['org_id'],v['ticket_id'],t,v['signature'],'b'*64)
                elif v['op']=='keyring-aad':
                    message=crypto.cloud_keyring_aad(v['org_id'],v['key_id'],v['purpose'],v['scope'],v['generation'])
                else:
                    continue
                self.assertEqual(message.hex(),v['message_hex'])

    def test_ticket_and_transcript_strictness(self):
        self.assertEqual(ticket_id('enr_'+'a'*12+'.'+'a'*26),'enr_'+'a'*12)
        for code in ('enr_'+'a'*12+'.'+'b'*26,'enr_'+'a'*12+'.'+'a'*25,'ENR_'+'a'*12+'.'+'a'*26):
            with self.assertRaises(ValueError):
                ticket_id(code)
        t=copy.deepcopy(vectors()[0]['transcript'])
        for field,value in (('name','x'*129),('name','\n'),('mode','other'),('store_id','a'*32),('extra',True)):
            with self.subTest(field=field),self.assertRaises(Exception):
                checked_transcript(dict(t,**{field:value}))
        t['mode']='adopt'
        with self.assertRaises(Exception):
            checked_transcript(t)

    def test_reservation_resume_and_independent_typed_pin(self):
        temp=tempfile.TemporaryDirectory(prefix='tw-pr2-enroll-')
        self.addCleanup(temp.cleanup)
        store=Store(Path(temp.name)).open(create=True)
        self.addCleanup(store.close)
        store.initialize(TEST_PASSPHRASE,argon2=TEST_ARGON2)
        fixture=Path(__file__).parent/'fixtures/cloud/6a2d52f7cfcd9be944cb880602007832de637dc0/core/vectors/broker-genesis-v2.json'
        trace=json.loads(fixture.read_text())
        genesis=bytes.fromhex(trace['records'][0]['canonical_hex'])
        org=trace['org_id']; root=trace['pinned_root']
        session=EnrollmentSession.create(org,'Local test broker','2.0')
        response=dict(org_id=org,broker_id='brk_'+'a'*32,genesis=None,policy_head=dict(seq=0,hash='0'*64),state='pending')
        session.accept_reservation(response)
        reservation=session.reservation('enr_'+'a'*12+'.'+'a'*26)
        blk=crypto.random_key()
        save_reservation(session,store,blk,'enr_'+'a'*12,reservation['proof'])
        with self.assertRaises(crypto.CryptoError):
            save_reservation(session,store,crypto.random_key(),'enr_'+'a'*12,reservation['proof'])
        resumed=load_reservation(store,blk,org,'enr_'+'a'*12)
        self.assertEqual(resumed.transcript,session.transcript)
        self.assertEqual(crypto.private_jwk(resumed.exchange_key),crypto.private_jwk(session.exchange_key))
        with self.assertRaises(ValueError):
            resumed.accept_reservation(dict(response,broker_id='brk_'+'b'*32))
        with self.assertRaises(ValueError):
            pin_cloud_enrollment(resumed,store,genesis,typed_words='sas_matched')
        words=crypto.sas_words(crypto.sas_context(org,root,'broker','brk_'+'a'*32,session.transcript['sign_pub'],session.transcript['kx_pub']))
        self.assertEqual(pin_cloud_enrollment(resumed,store,genesis,typed_words=words),root)
        self.assertEqual(load_reservation(store,blk,org,'enr_'+'a'*12).pinned_root,root)
        with self.assertRaisesRegex(RuntimeError,'E_LEGACY_ADOPTION'):
            legacy_ingestion()

    def test_adopt_reservation_does_not_accept_genesis_or_root_substitution(self):
        org='a'*32
        session=EnrollmentSession.create(org,'Local test','2',mode='adopt',store_id=org)
        with self.assertRaises(ValueError):
            session.root_proof('enr_'+'a'*12,'b'*64)
        response=dict(org_id=org,broker_id='brk_'+'a'*32,genesis=None,policy_head=dict(seq=0,hash='0'*64),state='pending')
        with self.assertRaises(ValueError):
            session.accept_reservation(dict(response,genesis={}))
        session.accept_reservation(response)
        proof=session.root_proof('enr_'+'a'*12,'b'*64)
        verify_proof(org,'enr_'+'a'*12,session.transcript,proof,'b'*64)
        with self.assertRaises(ValueError):
            verify_proof(org,'enr_'+'a'*12,session.transcript,proof,'c'*64)
