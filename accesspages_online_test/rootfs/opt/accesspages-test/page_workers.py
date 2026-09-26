"""Supervisor-owned per-page identities, files and worker lifecycle."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil

from installation import atomic
from pages import PageStore, validate_page_id

POLICY_GROUP = 2000
GUEST_BROKER_GROUP = 2001
FRONTEND_GROUP = 2002
FIRST_PAGE_UID = 20000
LAST_PAGE_UID = 59999


def directory(path, uid, gid, mode):
    if path.is_symlink():
        raise ValueError('Unexpected runtime symlink')
    path.mkdir(parents=True, exist_ok=True)
    os.chown(path, uid, gid)
    path.chmod(mode)


def publish(path, content, uid, gid, mode=0o640):
    if path.is_symlink():
        raise ValueError('Unexpected runtime symlink')
    changed = not path.exists() or path.read_text() != content
    if changed:
        atomic(path, content, mode)
    os.chown(path, uid, gid)
    path.chmod(mode)
    return changed


class PageWorkers:
    def __init__(self, root, gateway, runtime):
        self.root, self.gateway, self.runtime = Path(root), Path(gateway), runtime
        self.state_path = self.root / 'page-workers.json'
        self.state = json.loads(self.state_path.read_text()) if self.state_path.exists() else {'next_uid': FIRST_PAGE_UID, 'pages': {}}
        self._validate()

    def _validate(self):
        value = self.state
        if not isinstance(value, dict) or set(value) != {'next_uid', 'pages'} or type(value['next_uid']) is not int or not FIRST_PAGE_UID <= value['next_uid'] <= LAST_PAGE_UID + 1 or not isinstance(value['pages'], dict):
            raise ValueError('Invalid page worker state')
        uids = set()
        for page, record in value['pages'].items():
            validate_page_id(page)
            if (not isinstance(record, dict) or set(record) != {'uid', 'capability', 'instance_id'} or type(record['uid']) is not int
                    or not FIRST_PAGE_UID <= record['uid'] < value['next_uid'] or record['uid'] in uids
                    or not isinstance(record['instance_id'], str) or not re.fullmatch(r'(?:[a-f0-9]{32})?', record['instance_id'])
                    or not isinstance(record['capability'], str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', record['capability'])):
                raise ValueError('Invalid page worker identity')
            uids.add(record['uid'])

    def path(self, record):
        return self.root / 'workers' / str(record['uid'])

    def socket(self, record):
        return self.path(record) / 'http/api.sock'

    def reset(self):
        self.state['pages'] = {}
        self._save()

    def _save(self):
        if publish(self.state_path, json.dumps(self.state, sort_keys=True), 0, 0, 0o600):
            # Persist the rename before issuing an identity to a child process.
            fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)

    def reconcile(self, common, *, broker_uid, tls_uid, admin_uid, manifest):
        source = PageStore(self.root / 'admin/pages', file_mode=0o640)
        # One snapshot under the Admin/Broker authority lock; publish only public
        # page policy to workers. Grants and invitation credentials stay in Admin.
        with source.authority_guard():
            pages = {p['id']: source.load(p['id']) for p in source.list_pages()}
        old = self.state['pages']
        records = {page: old[page] for page in pages if page in old and old[page]['instance_id'] == pages[page].get('instance_id', '')}
        for page in sorted(set(pages) - set(records)):
            uid = self.state['next_uid']
            if uid > LAST_PAGE_UID:
                raise RuntimeError('Page identity capacity exhausted')
            self.state['next_uid'] += 1
            records[page] = {'uid': uid, 'capability': secrets.token_urlsafe(32), 'instance_id': pages[page].get('instance_id', '')}
        self.state['pages'] = records
        self._save()
        # Publish denial before stopping a removed worker. UIDs are never reused,
        # including when an owner later creates the same page ID again.
        identities = {str(r['uid']): {'page': p, 'instance_id': r['instance_id'], 'capability_hash': hashlib.sha256(r['capability'].encode()).hexdigest()} for p, r in records.items()}
        publish(self.root / 'broker/page-workers.json', json.dumps(identities), 0, broker_uid)
        hashes = {r['page']: r['capability_hash'] for r in identities.values()}
        publish(self.root / 'admin/page-capabilities.json', json.dumps(hashes), admin_uid, admin_uid, 0o600)
        active = {str(r['uid']) for r in records.values()}
        for role in list(self.runtime.children):
            if role.startswith('page:') and role[5:] not in active:
                self.runtime.stop(role)
        directory(self.root / 'workers', 0, 0, 0o711)
        directory(self.root / 'public/guest-shells', 0, 0, 0o755)
        # Also finish deletions interrupted by a supervisor crash after the
        # allocation ledger was saved. Never reuse the retired numeric identity.
        for path in (self.root / 'workers').iterdir():
            if path.name not in active:
                if not path.name.isdecimal() or path.is_symlink():
                    raise ValueError('Unexpected worker directory')
                shutil.rmtree(path)
        for path in (self.root / 'public/guest-shells').glob('*.html'):
            if path.stem not in active:
                path.unlink()
        for page, record in records.items():
            uid = record['uid']
            root = self.path(record)
            directory(root, 0, 0, 0o711)
            directory(root / 'private', 0, uid, 0o750)
            directory(root / 'private/pages', 0, uid, 0o750)
            directory(root / 'state', uid, uid, 0o700)
            # A worker can create its own API socket, but cannot traverse another
            # worker's socket directory. Only the TLS frontend shares this group.
            directory(root / 'http', uid, FRONTEND_GROUP, 0o2710)
            projection = {**pages[page], 'access_grants': []}
            publish(root / 'private/pages' / (page + '.json'), json.dumps(projection), 0, uid)
            publish(root / 'private/pages/.authority.lock', '', 0, uid, 0o440)
            publish(root / 'private/capability.json', json.dumps({page: record['capability']}), 0, uid)
            routes = [r for r in manifest['resources'] if r['page_id'] == page and r['instance_id'] == record['instance_id']]
            publish(root / 'private/routes.json', json.dumps({**manifest, 'resources': routes}), 0, uid)
            shell = (self.gateway / 'static/access.html').read_text().replace('<html lang="en">', '<html lang="en" data-page-id="' + page + '">', 1)
            publish(self.root / 'public/guest-shells' / (str(uid) + '.html'), shell, 0, 0, 0o644)
            self.runtime.start('page:' + str(uid), ['python3', str(self.gateway / 'server.py')], {
                **common, 'GATEWAY_ROLE': 'guest', 'GATEWAY_BOUND_PAGE_ID': page,
                'GATEWAY_DATA_DIR': str(root / 'state'), 'GATEWAY_PAGES_DIR': str(root / 'private/pages'),
                'GATEWAY_HTTP_SOCKET': str(self.socket(record)), 'GATEWAY_FRONTEND_UID': str(tls_uid),
                'HA_GUEST_BROKER_SOCKET': str(self.root / 'guest-broker/http.sock'), 'HA_BROKER_UID': str(broker_uid),
                'NHP_PAGE_CAPABILITIES_FILE': str(root / 'private/capability.json'),
                'NHP_ROUTES_FILE': str(root / 'private/routes.json'),
                'ACTIVITY_BROKER_URL': 'http://127.0.0.1:8081', 'VERIFICATION_BROKER_URL': 'http://127.0.0.1:8081',
            }, uid=uid, groups=[GUEST_BROKER_GROUP])
        return records
