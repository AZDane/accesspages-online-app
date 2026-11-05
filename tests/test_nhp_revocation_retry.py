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
        cursor=patch.object(nhp,'_revocation_cursor',0,create=True)
        cursor.start();self.addCleanup(cursor.stop)
        warning=patch.object(nhp,'_revocation_warning_at',None)
        warning.start();self.addCleanup(warning.stop)
        retry=patch.object(nhp,'_revocation_retry',{})
        retry.start();self.addCleanup(retry.stop)
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
            with self.assertRaises(nhp.NativeAccessServiceError) as failure:
                nhp.NHPClient().delete_access_link(access_link_id='invitation-id')
        self.assertEqual(failure.exception.category,'native_timeout')
        self.assertEqual(self.pending(),1)

    def test_native_failure_category_is_preserved_without_raw_output(self):
        output=json.dumps({'ok':False,'category':'local_lock_contention',
                           'error':'private identifier must be ignored'})
        with patch.object(nhp.subprocess,'run',return_value=subprocess.CompletedProcess([],1,stdout=output)):
            with self.assertRaises(nhp.NativeAccessServiceError) as failure:
                nhp.machine({'op':'revoke_link','access_link_id':'private-id'})
        self.assertEqual(failure.exception.category,'local_lock_contention')
        self.assertNotIn('private',str(failure.exception))

    def test_persistent_revocations_use_bounded_per_item_backoff(self):
        with nhp.revocation_db() as c:
            c.executemany('INSERT INTO pending_revocations(id) VALUES(?)',
                          [('stale-one',),('stale-two',)])
        failure=nhp.NativeAccessServiceError('local_lock_contention')
        with patch.object(nhp,'machine',side_effect=failure) as send:
            nhp.retry_revocations(now=0)
            self.assertEqual(send.call_count,2)
            nhp.retry_revocations(now=1)
            self.assertEqual(send.call_count,2,'backoff must suppress the two-second worker retry')
            nhp.retry_revocations(now=5)
            self.assertEqual(send.call_count,4)
        self.assertEqual({attempts for attempts,_ in nhp._revocation_retry.values()},{2})
        self.assertEqual({deadline for _,deadline in nhp._revocation_retry.values()},{15})
        self.assertEqual(self.pending(),2)

    def test_failed_old_entries_cannot_starve_later_revocations(self):
        with nhp.revocation_db() as c:
            c.executemany('INSERT INTO pending_revocations(id) VALUES(?)',
                          [(f'old-{i}',) for i in range(9)]+[('current',)])
        attempted=[]
        def send(body):
            attempted.append(body['access_link_id'])
            if body['access_link_id'].startswith('old-'):
                raise AccessServiceError('unavailable')
            return {'state':'revoked','network_admission_update':'applied'}
        with patch.object(nhp,'machine',side_effect=send):
            nhp.retry_revocations(now=0)
            self.assertLessEqual(len(attempted),8)
            nhp.retry_revocations(now=0)
        self.assertIn('current',attempted)
        with nhp.revocation_db() as c:
            self.assertEqual({r['id'] for r in c.execute('SELECT id FROM pending_revocations')},
                             {f'old-{i}' for i in range(9)})
        with patch.object(nhp,'machine',return_value={'state':'revoked','network_admission_update':'applied'}):
            nhp.retry_revocations(now=60)
            nhp.retry_revocations(now=60)
        self.assertEqual(self.pending(),0,'Previously failed work must remain retryable')

    def test_bad_local_page_does_not_block_other_pages_or_send_unsafe_revocation(self):
        from pages import PageConfigError, PageNotFoundError
        from unittest.mock import Mock
        store=Mock()
        store.remove_access_grant.side_effect=[PageConfigError('bad page'),PageNotFoundError('already removed')]
        with nhp.revocation_db() as c:
            c.executemany('INSERT INTO pending_revocations VALUES(?,?,?)',
                          [('bad','bad-page','bad-grant'),('good','good-page','good-grant')])
        with patch.object(nhp,'machine',return_value={'state':'revoked','network_admission_update':'applied'}) as send:
            nhp.retry_revocations(store)
        send.assert_called_once_with({'op':'revoke_link','access_link_id':'good','defer_transport':15})
        with nhp.revocation_db() as c:
            self.assertEqual([r['id'] for r in c.execute('SELECT id FROM pending_revocations')],['bad'])

    def test_invalid_native_response_remains_retryable(self):
        for output in ('not json','[]','null'):
            with self.subTest(output=output), patch.object(nhp.subprocess,'run',return_value=subprocess.CompletedProcess([],0,stdout=output)):
                with self.assertRaises(AccessServiceError):
                    nhp.machine({'op':'revoke_link','access_link_id':'invitation-id'})

    def test_pending_diagnostics_are_rate_limited_and_do_not_log_link_or_error_data(self):
        with nhp.revocation_db() as c:
            c.execute("INSERT INTO pending_revocations(id) VALUES('private-link-id')")
        with patch.object(nhp,'audit') as log, patch.object(nhp.time,'monotonic',side_effect=[100,101,160]), \
             patch.object(nhp,'machine',side_effect=AccessServiceError('private-native-output')):
            nhp.retry_revocations()
            nhp.retry_revocations()
            nhp.retry_revocations()
        self.assertEqual(log.call_count,2)
        for call in log.call_args_list:
            self.assertEqual(call.args,('service_revocations_pending',))
            self.assertEqual(call.kwargs,{'remaining':1,'reasons':['service_confirmation_unavailable']})
        self.assertNotIn('private-',str(log.call_args_list))
        with patch.object(nhp,'audit') as log, patch.object(nhp,'machine',return_value={'state':'revoked','network_admission_update':'applied'}):
            nhp.retry_revocations()
        log.assert_called_once_with('service_revocations_completed',completed=1,remaining=0)
        self.assertIsNone(nhp._revocation_warning_at)

    def test_worker_survives_local_failure_and_keeps_preparations_independent(self):
        class StopWorker(Exception):pass
        with patch.object(nhp.threading,'Thread') as thread, \
             patch.object(nhp,'retry_revocations',side_effect=[ValueError('private-state'),None]) as retry, \
             patch.object(nhp,'retry_preparations') as prepare, \
             patch.object(nhp.time,'sleep',side_effect=[None,StopWorker]), \
             patch.object(nhp,'audit') as log:
            nhp.start_revocation_worker()
            with self.assertRaises(StopWorker):
                thread.call_args.kwargs['target']()
        self.assertEqual(retry.call_count,2)
        self.assertEqual(prepare.call_count,2)
        log.assert_called_once_with('service_revocations_pending',remaining=None,reasons=['local_state_unavailable'])

if __name__=='__main__':unittest.main()
