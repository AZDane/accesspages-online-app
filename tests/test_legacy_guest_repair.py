"""A beta.26 state fixture is retired explicitly, without changing identity."""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch, Mock

import legacy_guest_repair as repair


class LegacyRepairTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ('admin/pages/.removed-links', 'admin/installation/machine/etc', 'broker', 'connector', 'tls'):
            (self.root/name).mkdir(parents=True)
        self.write('admin/installation/binding.json', {'gateway_id': 'synthetic-gateway', 'route': {'epoch': 7}})
        self.write('admin/installation/profile.json', {'version': 3})
        self.write('admin/pages/page.json', {'id': 'page', 'instance_id': 'stable-instance', 'title': 'Preserve me',
                   'resources': [{'entity_id': 'sensor.synthetic'}],
                   'access_grants': [{'id': 'old-grant', 'access_link_id': 'old-id', 'access_link_url': 'https://old.invalid/#old-secret'}]})
        for name in ('options.json', 'admin/installation/machine/private-key', 'admin/installation/machine/etc/config.toml',
                     'admin/installation/guest.key', 'connector/private-key', 'tls/guest.key', 'admin/pages/.removed-links/marker'):
            (self.root/name).write_text('preserve-'+name)
        self.write('admin/page-capabilities.json', {'old': 'capability'})
        self.write('admin/ready-routes.json', {'old': 'ready'})
        with closing(sqlite3.connect(self.root/repair.REGISTRY)) as db, db:
            db.executescript("""CREATE TABLE links(id TEXT PRIMARY KEY,secret TEXT NOT NULL);
                CREATE TABLE pending_revocations(id TEXT PRIMARY KEY,page TEXT NOT NULL DEFAULT '',grant_id TEXT NOT NULL DEFAULT '');
                CREATE TABLE pending_routes(token_hash TEXT PRIMARY KEY,page_id TEXT NOT NULL,instance_id TEXT NOT NULL,expires INTEGER NOT NULL);
                INSERT INTO links VALUES('old-id','old-secret');
                INSERT INTO pending_revocations VALUES('old-id','page','old-grant');
                INSERT INTO pending_routes VALUES('hash','page','instance',9999999999);""")
        with closing(sqlite3.connect(self.root/'broker/guest-sessions.db')) as db, db:
            db.executescript("""CREATE TABLE used(id TEXT PRIMARY KEY,expires INTEGER NOT NULL);
                CREATE TABLE sessions(hash TEXT PRIMARY KEY,page TEXT NOT NULL,grant_id TEXT NOT NULL,expires INTEGER NOT NULL,policy_hash TEXT NOT NULL,token_hash TEXT NOT NULL,gateway_id TEXT NOT NULL,epoch INTEGER NOT NULL,resource TEXT NOT NULL);
                INSERT INTO used VALUES('old-handoff',9999999999);
                INSERT INTO sessions VALUES('session','page','old-grant',9999999999,'policy','token','gateway',7,'resource');""")

    def write(self, name, value):
        (self.root/name).write_text(json.dumps(value))

    def files(self):
        return {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob('*') if p.is_file() and repair.REPAIR_DIR not in p.parts}

    def test_inspection_is_read_only_and_complete_repair_preserves_unrelated_state(self):
        before = self.files()
        inode = (self.root/'admin/installation/machine/etc/config.toml').stat().st_ino
        self.assertEqual(repair.status(self.root), 'required')
        self.assertEqual(before, self.files())
        self.assertEqual(repair.repair(self.root), {'repaired': True, 'pages_preserved': 1, 'retired_guests': 1})
        self.assertEqual(repair.status(self.root), 'none')
        import nhp
        with patch.dict(os.environ, {'GATEWAY_DATA_DIR': str(self.root/'admin')}):
            with nhp.revocation_db() as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM pending_preparations').fetchone()[0], 0)
        after = self.files()
        expected_changes = {repair.REGISTRY, 'broker/guest-sessions.db', 'admin/pages/page.json', 'admin/page-capabilities.json', 'admin/ready-routes.json'}
        self.assertEqual({p for p in before if before[p] != after.get(p)}, expected_changes)
        old_page = json.loads(before['admin/pages/page.json'])
        self.assertEqual(json.loads(after['admin/pages/page.json']), dict(old_page, access_grants=[]))
        self.assertEqual((self.root/'admin/installation/machine/etc/config.toml').stat().st_ino, inode)
        with closing(sqlite3.connect(self.root/repair.REGISTRY)) as db:
            self.assertEqual([r[1] for r in db.execute('PRAGMA table_info(links)')], ['id'])
            self.assertEqual(db.execute('SELECT COUNT(*) FROM links').fetchone(), (0,))
            self.assertEqual(db.execute('SELECT COUNT(*) FROM pending_revocations').fetchone(), (0,))
        with closing(sqlite3.connect(self.root/'broker/guest-sessions.db')) as db:
            for table in ('sessions', 'used'):
                self.assertEqual(db.execute('SELECT COUNT(*) FROM '+table).fetchone(), (0,))
        folder = self.root/repair.REPAIR_DIR
        plan = json.loads((folder/'plan.json').read_text())
        for index, entry in enumerate(plan['entries']):
            self.assertEqual((folder/(str(index)+'.original')).read_bytes(), before[entry['path']])
        self.assertEqual(folder.stat().st_mode & 0o777, 0o700)
        self.assertEqual({p.stat().st_mode & 0o777 for p in folder.iterdir()}, {0o600})
        with self.assertRaises(ValueError): repair.repair(self.root)

    def test_interruption_midway_is_resumable_and_blocks_startup(self):
        repair.prepare(self.root)
        original_atomic = repair.atomic
        mutations = 0
        def interrupted(path, *args, **kwargs):
            nonlocal mutations
            original_atomic(path, *args, **kwargs)
            if repair.REPAIR_DIR not in path.parts:
                mutations += 1
                raise OSError('synthetic interrupted write')
        with patch.object(repair, 'atomic', side_effect=interrupted):
            with self.assertRaises(OSError): repair.repair(self.root)
        self.assertEqual(mutations, 1)
        self.assertEqual(repair.status(self.root), 'required')
        self.assertTrue(repair.repair(self.root)['repaired'])
        self.assertEqual(repair.status(self.root), 'none')

    def test_bad_or_mixed_data_is_refused_without_mutation(self):
        page = json.loads((self.root/'admin/pages/page.json').read_text())
        page['access_grants'][0]['invitation_state'] = 'ready'
        self.write('admin/pages/page.json', page)
        before = self.files()
        self.assertEqual(repair.status(self.root), 'blocked')
        with self.assertRaises(ValueError): repair.repair(self.root)
        self.assertEqual(before, self.files())
        self.assertFalse((self.root/repair.REPAIR_DIR).exists())

    def test_unknown_schema_symlinks_and_hardlinks_are_refused(self):
        with closing(sqlite3.connect(self.root/repair.REGISTRY)) as db, db:
            db.execute('CREATE TABLE unknown(value TEXT)')
        self.assertEqual(repair.status(self.root), 'blocked')
        with closing(sqlite3.connect(self.root/repair.REGISTRY)) as db, db:
            db.execute('DROP TABLE unknown')
        target = self.root/'admin/pages/page.json'
        target.rename(target.with_suffix('.saved'))
        target.symlink_to(target.with_suffix('.saved'))
        self.assertEqual(repair.status(self.root), 'blocked')
        target.unlink()
        os.link(target.with_suffix('.saved'), target)
        self.assertEqual(repair.status(self.root), 'blocked')

    def test_changed_backup_or_live_state_cannot_be_overwritten_on_retry(self):
        plan = repair.prepare(self.root)
        path = self.root/plan['entries'][0]['path']
        path.write_text('unexpected change')
        with self.assertRaises(ValueError): repair.repair(self.root)
        self.assertEqual(path.read_text(), 'unexpected change')

    def test_backup_failure_does_not_mutate_live_state(self):
        before = self.files()
        with patch.object(repair, 'atomic', side_effect=OSError('disk full')):
            with self.assertRaises(OSError): repair.repair(self.root)
        self.assertEqual(before, self.files())

    def test_current_registry_and_fresh_installation_need_no_repair(self):
        repair.repair(self.root)
        before = self.files()
        self.assertEqual(repair.status(self.root), 'none')
        with self.assertRaises(ValueError): repair.repair(self.root)
        self.assertEqual(before, self.files())
        with tempfile.TemporaryDirectory() as fresh:
            self.assertEqual(repair.status(Path(fresh)), 'none')

    def test_private_checkpoint_cannot_be_read_by_app_roles(self):
        repair.prepare(self.root)
        folder = self.root/repair.REPAIR_DIR
        self.assertEqual(folder.stat().st_uid, os.geteuid())
        self.assertEqual(folder.stat().st_mode & 0o077, 0)
        for path in folder.iterdir():
            self.assertEqual(path.stat().st_uid, os.geteuid())
            self.assertEqual(path.stat().st_mode & 0o077, 0)

    def test_runtime_requires_confirmation_gate_and_no_running_guest_writers(self):
        import runtime
        import threading
        instance = runtime.Runtime.__new__(runtime.Runtime)
        instance.lock = threading.RLock()
        instance.legacy_repair = 'required'
        instance.children = {'admin': Mock()}
        with patch.object(runtime, 'ROOT', self.root):
            with self.assertRaises(ValueError): instance.repair_legacy_guests()
            self.assertFalse((self.root/repair.REPAIR_DIR).exists())
            instance.children = {'ingress': Mock()}
            self.assertTrue(instance.repair_legacy_guests()['repaired'])
            self.assertEqual(instance.legacy_repair, 'none')


if __name__ == '__main__':
    unittest.main()
