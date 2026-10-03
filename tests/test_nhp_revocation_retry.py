import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'accesspages_online_test/rootfs/opt/accesspages-test/guest_gateway'))

import importlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import nhp
import route_reservations
from access_service import AccessServiceError

class RegistrySchemaTests(unittest.TestCase):
    def test_empty_and_reservations_only_databases_initialize_current_tables(self):
        for reserved in (False, True):
            with self.subTest(reserved=reserved), tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'GATEWAY_DATA_DIR': directory}):
                if reserved:
                    route_reservations.reserve(directory, 'page', 'instance', 'hash')
                before = route_reservations.pending(directory)
                with nhp.revocation_db() as c:
                    self.assertEqual([tuple(r) for r in c.execute('PRAGMA table_info(links)')], [(0, 'id', 'TEXT', 0, None, 1)])
                    self.assertEqual([tuple(r) for r in c.execute('PRAGMA table_info(pending_revocations)')], [
                        (0, 'id', 'TEXT', 0, None, 1), (1, 'page', 'TEXT', 1, "''", 0), (2, 'grant_id', 'TEXT', 1, "''", 0)])
                self.assertEqual(route_reservations.pending(directory), before)

    def test_current_identifiers_and_pending_work_survive_process_reopen_unchanged(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'GATEWAY_DATA_DIR': directory}):
            with nhp.revocation_db() as c:
                c.execute("INSERT INTO links VALUES('known')")
                c.execute("INSERT INTO pending_revocations VALUES('known','page','grant')")
                c.execute("INSERT INTO pending_revocations(id) VALUES('orphan')")
            path = Path(directory) / 'nhp-links.db'
            before = path.read_bytes()
            subprocess.run([os.sys.executable, '-B', '-c', 'import nhp\nwith nhp.revocation_db(): pass'],
                           env={**os.environ, 'PYTHONPATH': str(Path(nhp.__file__).parent)}, check=True)
            self.assertEqual(path.read_bytes(), before)
            with nhp.revocation_db() as c:
                self.assertEqual([tuple(r) for r in c.execute('SELECT * FROM links')], [('known',)])
                self.assertEqual([tuple(r) for r in c.execute('SELECT * FROM pending_revocations ORDER BY id')],
                                 [('known', 'page', 'grant'), ('orphan', '', '')])

    def test_incompatible_tables_are_refused_without_mutation_or_missing_table_creation(self):
        current_links = 'CREATE TABLE links(id TEXT PRIMARY KEY);'
        old_links = "CREATE TABLE links(id TEXT PRIMARY KEY, secret TEXT NOT NULL); INSERT INTO links VALUES('known','synthetic-secret');"
        old_pending = "CREATE TABLE pending_revocations(id TEXT PRIMARY KEY); INSERT INTO pending_revocations VALUES('pending');"
        partial_pending = "CREATE TABLE pending_revocations(id TEXT PRIMARY KEY, page TEXT NOT NULL DEFAULT ''); INSERT INTO pending_revocations VALUES('pending','page');"
        current_pending = "CREATE TABLE pending_revocations(id TEXT PRIMARY KEY, page TEXT NOT NULL DEFAULT '', grant_id TEXT NOT NULL DEFAULT ''); INSERT INTO pending_revocations VALUES('pending','page','grant');"
        for schema in (old_links, old_pending, partial_pending, old_links + old_pending,
                       old_links + current_pending, current_links + old_pending, current_links + partial_pending):
            with self.subTest(schema=schema), tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'GATEWAY_DATA_DIR': directory}):
                path = Path(directory) / 'nhp-links.db'
                with sqlite3.connect(path) as c:
                    c.executescript(schema)
                before = path.read_bytes()
                with self.assertRaisesRegex(sqlite3.DatabaseError, 'recover from an accepted v3 backup'):
                    with nhp.revocation_db():
                        self.fail('Incompatible registry was accepted')
                self.assertEqual(path.read_bytes(), before)

class RevocationRetryTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.env=patch.dict(os.environ,{'GATEWAY_DATA_DIR':self.directory.name})
        self.env.start();self.addCleanup(self.env.stop)
        with nhp.revocation_db() as c:
            c.execute('INSERT INTO links(id) VALUES(?)',('invitation-id',))

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
