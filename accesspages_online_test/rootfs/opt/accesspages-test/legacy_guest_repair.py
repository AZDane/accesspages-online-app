"""Explicit, local retirement of the beta.26 guest format, before workers start.

This never converts or reauthorizes invitations. Normal registry initialization
remains strict. Only HA Ingress confirmation may invoke repair().
"""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat


REGISTRY = 'admin/nhp-links.db'
REPAIR_DIR = 'legacy-guest-repair'
REGISTRY_COLUMNS = {
    'links': ('id', 'secret'),
    'pending_revocations': ('id', 'page', 'grant_id'),
    'pending_routes': ('token_hash', 'page_id', 'instance_id', 'expires'),
}
SESSION_COLUMNS = {
    'sessions': ('hash', 'page', 'grant_id', 'expires', 'policy_hash', 'token_hash', 'gateway_id', 'epoch', 'resource'),
    'used': ('id', 'expires'),
}
VERIFICATION_COLUMNS = {
    'sessions': ('token_hash', 'page_id', 'grant_id', 'expires_at'),
    'challenges': ('page_id', 'grant_id', 'code_hash', 'expires_at', 'attempts', 'sent_at'),
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked(root, relative):
    path = root / relative
    if path.is_symlink() or any(p.is_symlink() for p in path.parents if p != root.parent):
        raise ValueError('Unexpected repair path')
    if path.exists() and (not path.is_file() or path.stat().st_nlink != 1):
        raise ValueError('Unexpected repair file')
    return path


def read_db(path):
    return closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=2))


def validate_db(path, expected):
    with read_db(path) as db:
        if db.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
            raise ValueError('Damaged guest database')
        if db.execute("SELECT 1 FROM sqlite_master WHERE type IN ('trigger','view')").fetchone():
            raise ValueError('Unexpected guest database objects')
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not tables or not tables <= expected.keys():
            raise ValueError('Unsupported guest database')
        for table in tables:
            columns = tuple(r[1] for r in db.execute('PRAGMA table_info(' + table + ')'))
            if columns != expected[table]:
                raise ValueError('Unsupported guest database columns')


def inventory(root):
    """Validate the complete repair scope before making any changes."""
    registry = checked(root, REGISTRY)
    validate_db(registry, REGISTRY_COLUMNS)
    with read_db(registry) as db:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE name='links'").fetchone():
            raise ValueError('Missing legacy registry')
    binding = json.loads(checked(root, 'admin/installation/binding.json').read_text())
    profile = json.loads(checked(root, 'admin/installation/profile.json').read_text())
    if not binding.get('gateway_id') or profile.get('version') != 3:
        raise ValueError('An enrolled v3 installation is required')
    pages = {}
    for path in sorted((root/'admin/pages').glob('*.json')):
        checked(root, str(path.relative_to(root)))
        page = json.loads(path.read_text())
        if not isinstance(page, dict) or not isinstance(page.get('access_grants'), list):
            raise ValueError('Unsupported page')
        for grant in page['access_grants']:
            if (not isinstance(grant, dict) or 'invitation_state' in grant or
                    '#v3.' in str(grant.get('access_link_url', ''))):
                raise ValueError('Mixed invitation formats require operator recovery')
        pages[str(path.relative_to(root))] = page
    databases = {REGISTRY: REGISTRY_COLUMNS}
    for relative, columns in (
        ('broker/guest-sessions.db', SESSION_COLUMNS),
        ('admin/guest-runtime/verification.sqlite3', VERIFICATION_COLUMNS),
    ):
        path = checked(root, relative)
        if path.exists():
            validate_db(path, columns)
            databases[relative] = columns
    return pages, databases


def status(root):
    try:
        folder = root/REPAIR_DIR
        if folder.is_symlink():
            return 'blocked'
        if folder.exists():
            info = folder.stat()
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                return 'blocked'
            manifest = checked(root, REPAIR_DIR+'/plan.json')
            if manifest.exists() and json.loads(manifest.read_text()).get('phase') == 'prepared':
                return 'required'
        path = checked(root, REGISTRY)
        if not path.exists():
            return 'none'
        with read_db(path) as db:
            columns = tuple(r[1] for r in db.execute('PRAGMA table_info(links)'))
        if columns in ((), ('id',)):
            return 'none'
        inventory(root)
        return 'required'
    except (OSError, ValueError, TypeError, AttributeError, KeyError, sqlite3.Error):
        return 'blocked'


def atomic(path, body, uid=None, gid=None, mode=0o600):
    temporary = path.with_name(path.name+'.repair-pending')
    temporary.unlink(missing_ok=True)
    with temporary.open('xb') as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())
        os.fchmod(output.fileno(), mode)
        if uid is not None:
            os.fchown(output.fileno(), uid, gid)
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def save_plan(folder, plan):
    temporary = folder/'plan.json.repair-pending'
    # An interrupted write has never been made authoritative.
    temporary.unlink(missing_ok=True)
    atomic(folder/'plan.json', json.dumps(plan).encode())


def prepare(root):
    pages, databases = inventory(root)
    folder = root/REPAIR_DIR
    folder.mkdir(mode=0o700, exist_ok=True)
    # No guest processes have started. Preserve all affected files, including
    # SQLite sidecars, before installing any replacement.
    targets = {relative: 'page' for relative in pages}
    for relative in databases:
        targets[relative] = 'database'
        for suffix in ('-wal', '-shm', '-journal'):
            if checked(root, relative+suffix).exists():
                targets[relative+suffix] = 'remove'
    for relative in ('admin/page-capabilities.json', 'admin/ready-routes.json'):
        if checked(root, relative).exists():
            targets[relative] = 'remove'
    entries = []
    for index, (relative, kind) in enumerate(targets.items()):
        path = checked(root, relative)
        info = path.stat()
        original = folder/(str(index)+'.original')
        # An interrupted preparation has not changed live files. Reuse its
        # byte-identical backup; refuse unexpected drift rather than overwrite it.
        if original.exists():
            if original.read_bytes() != path.read_bytes():
                raise ValueError('Repair backup differs from source')
        else:
            atomic(original, path.read_bytes())
        replacement = folder/(str(index)+'.replacement')
        replacement.unlink(missing_ok=True)
        if kind == 'page':
            page = dict(pages[relative], access_grants=[])
            atomic(replacement, json.dumps(page, indent=2).encode()+b'\n')
        elif kind == 'database':
            with closing(sqlite3.connect(replacement)) as db:
                if relative == REGISTRY:
                    db.executescript('''CREATE TABLE links(id TEXT PRIMARY KEY);
                        CREATE TABLE pending_revocations(id TEXT PRIMARY KEY, page TEXT NOT NULL DEFAULT '', grant_id TEXT NOT NULL DEFAULT '');
                        CREATE TABLE pending_preparations(request_id TEXT PRIMARY KEY,id TEXT NOT NULL DEFAULT '',created INTEGER NOT NULL);''')
                else:
                    with read_db(path) as source:
                        source.backup(db)
                    db.execute('PRAGMA journal_mode=DELETE')
                    with db:
                        for table in databases[relative]:
                            if db.execute('SELECT 1 FROM sqlite_master WHERE type=? AND name=?', ('table', table)).fetchone():
                                db.execute('DELETE FROM '+table)
                    db.execute('VACUUM')
                if db.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                    raise ValueError('Invalid staged database')
            replacement.chmod(0o600)
            with replacement.open('rb') as stream:
                os.fsync(stream.fileno())
        entries.append({'path': relative, 'original': digest(original),
                        'replacement': None if kind == 'remove' else digest(replacement),
                        'uid': info.st_uid, 'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode)})
    plan = {'version': 1, 'phase': 'prepared', 'entries': entries,
            'pages_preserved': len(pages),
            'retired_guests': sum(len(p['access_grants']) for p in pages.values())}
    save_plan(folder, plan)
    return plan


def repair(root):
    """Caller holds runtime lock and has not started any guest/connector writers."""
    if status(root) != 'required':
        raise ValueError('No supported legacy repair is pending')
    folder = root/REPAIR_DIR
    manifest = folder/'plan.json'
    plan = json.loads(manifest.read_text()) if manifest.exists() else prepare(root)
    if plan.get('version') != 1 or plan.get('phase') != 'prepared':
        raise ValueError('Unsupported repair checkpoint')
    for index, entry in enumerate(plan['entries']):
        path = checked(root, entry['path'])
        # The private root-owned checkpoint can only refer to the fixed guest
        # stores or page JSON, never installation keys or arbitrary files.
        relative = entry['path']
        page = relative.startswith('admin/pages/') and Path(relative).parent == Path('admin/pages') and relative.endswith('.json')
        allowed = [REGISTRY, 'broker/guest-sessions.db', 'admin/guest-runtime/verification.sqlite3']
        if not (page or relative in ('admin/page-capabilities.json', 'admin/ready-routes.json') or
                any(relative == db+suffix for db in allowed for suffix in ('', '-wal', '-shm', '-journal'))):
            raise ValueError('Invalid repair scope')
        if digest(folder/(str(index)+'.original')) != entry['original']:
            raise ValueError('Repair backup changed')
        if entry['replacement'] is not None and digest(folder/(str(index)+'.replacement')) != entry['replacement']:
            raise ValueError('Staged repair changed')
        current = digest(path) if path.exists() else None
        if current not in (entry['original'], entry['replacement']):
            raise ValueError('Guest data changed during repair')
    # Remove sidecars before replacing their database. A prepared checkpoint
    # blocks all workers across any interrupted multi-file installation.
    for index, entry in sorted(enumerate(plan['entries']), key=lambda item: item[1]['replacement'] is not None):
        path = checked(root, entry['path'])
        if entry['replacement'] is None:
            path.unlink(missing_ok=True)
        else:
            path.with_name(path.name+'.repair-pending').unlink(missing_ok=True)
            atomic(path, (folder/(str(index)+'.replacement')).read_bytes(), entry['uid'], entry['gid'], entry['mode'])
    plan['phase'] = 'complete'
    save_plan(folder, plan)
    return {'repaired': True, 'pages_preserved': plan['pages_preserved'], 'retired_guests': plan['retired_guests']}
