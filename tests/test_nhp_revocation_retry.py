import importlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'accesspages_online_test/rootfs/opt/accesspages-test/guest_gateway'))

import nhp
from access_service import AccessServiceError

class RevocationRetryTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.env=patch.dict(os.environ,{'GATEWAY_DATA_DIR':self.directory.name})
        self.env.start();self.addCleanup(self.env.stop)
        with nhp.revocation_db() as c:
            c.execute('INSERT INTO links VALUES(?,?)',('invitation-id','private-demo-invitation'))

    def pending(self):
        with nhp.revocation_db() as c:return c.execute('SELECT COUNT(*) FROM pending_revocations').fetchone()[0]

    def test_service_outage_then_process_restart_retries_and_erases_secret(self):
        with patch.object(nhp,'machine',side_effect=AccessServiceError('unavailable')):
            with self.assertRaises(AccessServiceError):nhp.NHPClient().delete_access_link(access_link_id='invitation-id')
        self.assertEqual(self.pending(),1)
        # Only the SQLite outbox crosses this fresh process boundary.
        code="import nhp; nhp.machine=lambda body:{'state':'revoked','network_admission_update':'applied'}; nhp.retry_revocations()"
        subprocess.run([os.sys.executable,'-c',code],env={**os.environ,'PYTHONPATH':str(Path(nhp.__file__).parent)},check=True)
        self.assertEqual(self.pending(),0)
        with nhp.revocation_db() as c:self.assertEqual(c.execute('SELECT COUNT(*) FROM links').fetchone()[0],0)
        self.assertTrue(nhp.NHPClient().delete_access_link(access_link_id='invitation-id'))

    def test_unconfirmed_network_withdrawal_stays_pending(self):
        for result in [{'state':'revoked'},{'state':'revoked','network_admission_update':'pending'}]:
            with patch.object(nhp,'machine',return_value=result):
                with self.assertRaises(AccessServiceError):nhp.NHPClient().delete_access_link(access_link_id='invitation-id')
            self.assertEqual(self.pending(),1)

    def test_competing_retry_keeps_durable_intent(self):
        nhp._revocation_lock.acquire()
        try:
            with patch.object(nhp,'machine') as machine:
                with self.assertRaises(AccessServiceError):nhp.NHPClient().delete_access_link(access_link_id='invitation-id')
                machine.assert_not_called()
            self.assertEqual(self.pending(),1)
        finally:nhp._revocation_lock.release()

    def test_native_timeout_has_safe_retryable_error(self):
        with patch.object(nhp.subprocess,'run',side_effect=subprocess.TimeoutExpired('machinectl',30)):
            with self.assertRaises(AccessServiceError):nhp.NHPClient().delete_access_link(access_link_id='invitation-id')
        self.assertEqual(self.pending(),1)

if __name__=='__main__':unittest.main()
