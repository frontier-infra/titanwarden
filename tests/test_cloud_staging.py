"""Lead-run staging check. No production store or deployed credentials are used."""
import os
import tempfile
import time
import unittest
from urllib.parse import urlsplit
from tw.cloud_http import public_origin

from tw import crypto
from tw.admin import human_context_allowed
from tw.cloud_runtime import CloudRuntime
from tw.seal import SealManager
from tw.store import Store
from support import TEST_PASSPHRASE,TEST_ARGON2


@unittest.skipUnless(os.environ.get('TW_STAGING_URL'), 'TW_STAGING_URL is not set')
class StagingIntegrationTests(unittest.TestCase):
    def test_ephemeral_enrollment_pull_put_and_custody_read(self):
        self.assertTrue(human_context_allowed('join'), 'staging enrollment requires a human terminal outside Orca')
        required=('TW_STAGING_ORG_ID','TW_STAGING_ENROLLMENT_CODE')
        self.assertTrue(all(os.environ.get(name) for name in required),'missing named staging enrollment inputs')
        origin=public_origin(os.environ['TW_STAGING_URL'])
        self.assertNotIn(urlsplit(origin).hostname,('api.titanwarden.com','app.titanwarden.com'),'use staging only')
        with tempfile.TemporaryDirectory(prefix='tw-staging-test-') as temporary:
            with Store(temporary).open(create=True) as store:
                store.initialize(TEST_PASSPHRASE,argon2=TEST_ARGON2,cloud_broker=True)
                seal=SealManager(store);seal.unseal(TEST_PASSPHRASE)
                try:
                    runtime=CloudRuntime(store,seal)
                    reserved=runtime.join(origin=origin,org=os.environ['TW_STAGING_ORG_ID'],
                        name='TEST-ONLY ephemeral staging broker',code=os.environ['TW_STAGING_ENROLLMENT_CODE'])
                    with open('/dev/tty','r+') as tty:
                        tty.write('TEST-ONLY staging broker SAS: '+reserved['words']+'\nType the console SAS words: ')
                        tty.flush()
                        words=tty.readline().strip()
                    runtime.pair(words)
                    deadline=time.monotonic()+180
                    while runtime.pull()['state']=='pending':
                        self.assertLess(time.monotonic(),deadline,'console approval deadline elapsed')
                        time.sleep(2)
                    project=os.environ.get('TW_STAGING_PROJECT','infra')
                    path=project+'/test-only-'+os.urandom(8).hex()
                    canary=b'TEST-ONLY staging custody canary '+os.urandom(24).hex().encode()
                    result=runtime.put(path,canary,secret_class='standard')
                    self.assertEqual(runtime.read(path),canary)
                    self.assertNotIn(canary,crypto.canonical_json(result))
                    self.assertEqual(store.connection.execute('SELECT count(*) FROM secrets').fetchone()[0],0)
                finally:
                    seal.seal()
