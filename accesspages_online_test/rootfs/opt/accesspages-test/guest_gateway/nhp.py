"""Optional NHP transport for the existing Admin and Guest Pages boundaries."""
import hashlib, json, os, re, secrets, sqlite3, subprocess, time
import threading
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from datetime import datetime, timezone
from access_service import AccessServiceError
from pages import validate_page_id
import route_reservations

ENABLED = os.getenv('ACCESS_TRANSPORT') == 'nhp'
RESOURCE = os.getenv('NHP_DEFAULT_RESOURCE', 'ha-guest-gateway')
ORIGIN = os.getenv('NHP_GATEWAY_ORIGIN', 'https://gateway-a.localhost:8088')
LANDING_ORIGIN = os.getenv('NHP_LANDING_ORIGIN', 'https://localhost:8090')
INSTALLATION_ROUTING = os.getenv('NHP_INSTALLATION_ROUTING') == '1'
ACCESS_LINK_MAX_LIFETIME_SECONDS = 30 * 24 * 60 * 60
try:
    PAGE_RESOURCES = json.loads(os.getenv('NHP_PAGE_RESOURCE_MAP', '{}'))
except json.JSONDecodeError:
    PAGE_RESOURCES = {}

def route_manifest():
    try:
        value = json.loads(Path(os.environ['NHP_ROUTES_FILE']).read_text())
        binding = json.loads(Path(os.environ['NHP_BINDING_FILE']).read_text())
        if value['gateway_id'] != binding['gateway_id'] or value['epoch'] != binding['route']['epoch']:
            raise ValueError('Stale route manifest')
        if value['isolation'] not in ('page', 'guest'):
            raise ValueError('Invalid isolation mode')
        return value
    except (OSError, KeyError, ValueError) as error:
        raise AccessServiceError('Page routes are not ready') from error

def resource_for_grant(page, instance_id=None, token_hash=''):
    if INSTALLATION_ROUTING:
        validate_page_id(page)
        manifest = route_manifest()
        scope = token_hash if manifest['isolation'] == 'guest' else ''
        if manifest['isolation'] == 'guest' and not re.fullmatch(r'[a-f0-9]{64}', scope):
            raise AccessServiceError('Guest route is not ready')
        matches = [r for r in manifest['resources'] if r['page_id'] == page and r['guest_hash'] == scope and (instance_id is None or r['instance_id'] == instance_id)]
        if len(matches) != 1:
            raise AccessServiceError('Page route is not ready')
        return matches[0]['resource_id']
    value = PAGE_RESOURCES.get(page, RESOURCE)
    return value if isinstance(value, str) and value else RESOURCE

def origin_for_resource(resource):
    if INSTALLATION_ROUTING:
        matches = [r for r in route_manifest()['resources'] if r['resource_id'] == resource]
        if len(matches) != 1:
            raise AccessServiceError('Page route is not ready')
        return 'https://' + matches[0]['host'] + ':' + str(matches[0]['port'])
    defaults = {
        'ha-guest-gateway': 'https://gateway-a.localhost:8088',
        'ha-guest-gateway-page-b': 'https://gateway-a.localhost:18444',
        'ha-guest-gateway-page-c': 'https://gateway-a.localhost:18445',
    }
    try:
        configured = json.loads(os.getenv('NHP_RESOURCE_ORIGIN_MAP', '{}'))
    except json.JSONDecodeError:
        configured = {}
    return configured.get(resource, defaults.get(resource, ORIGIN))


def wait_for_guest_route(page, instance, token_hash):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        manifest = route_manifest()
        if manifest['isolation'] != 'guest':
            raise AccessServiceError('Resource isolation changed; please retry')
        try:
            resource = resource_for_grant(page, instance, token_hash)
            ready = json.loads(Path(os.environ['NHP_READY_ROUTES_FILE']).read_text())
            if (ready['gateway_id'] == manifest['gateway_id'] and ready['epoch'] == manifest['epoch']
                    and ready['isolation'] == 'guest' and 0 <= time.time() - ready['checked_at'] < 10
                    and resource in ready['resources']):
                return resource
        except (AccessServiceError, OSError, ValueError, KeyError):
            pass
        time.sleep(0.5)
    raise AccessServiceError('Guest route is not ready; capacity or connection may be unavailable. Please retry.')

def machine(body):
    try:
        result = subprocess.run(['/opt/machinectl'], input=json.dumps(body), text=True, capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as error:
        raise AccessServiceError('NHP Server is unavailable; the operation can be retried') from error
    if result.returncode:
        raise AccessServiceError('NHP Server denied the operation or is unavailable')
    return json.loads(result.stdout)

def db(name):
    path=Path(os.environ['GATEWAY_DATA_DIR']) / (name+'.db')
    path.parent.mkdir(parents=True,exist_ok=True)
    conn=sqlite3.connect(path,timeout=10);conn.row_factory=sqlite3.Row
    return conn

def access_credential(link):
    fragment=urlparse(link).fragment
    if re.fullmatch(r'[A-Za-z0-9_-]{43}',fragment):return fragment
    raise AccessServiceError('Invalid AccessLink returned by the service')

class NHPClient:
    configured=True
    resource_id=RESOURCE
    def verification_status(self):
        result = machine({'op': 'verification_status'})
        methods = result.get('methods') if isinstance(result, dict) else None
        if (not isinstance(result, dict)
                or type(result.get('version')) is not int or result['version'] != 1
                or not isinstance(methods, dict)
                or set(methods) != {'none', 'google', 'email'}
                or any(type(value) is not bool for value in methods.values())
                or methods['none'] is not True):
            raise AccessServiceError('Hosted verification status is unavailable')
        if result.get('multi_method') is True:
            methods = {**methods, 'google_or_email': methods['google'] or methods['email']}
        return {'version': 1, 'methods': methods}
    def create_access_link(self, *, target_path, expires_in, one_time_use=False, verification_method="none", verification_email="", **kwargs):
        token=parse_qs(urlparse(target_path).query)['access_token'][0]
        page = urlparse(target_path).path.removeprefix('/access/').strip('/')
        instance = kwargs.get('page_instance_id', '')
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        try:
            ttl=int(expires_in[:-1])*{'m':60,'h':3600,'d':86400,'w':604800}[expires_in[-1]]
        except (KeyError, TypeError, ValueError):
            raise AccessServiceError('Invalid AccessLink lifetime')
        if not 1<=ttl<=ACCESS_LINK_MAX_LIFETIME_SECONDS:
            raise AccessServiceError('Access Pages invitations support up to 30 days')
        guest_mode = INSTALLATION_ROUTING and route_manifest()['isolation'] == 'guest'
        if guest_mode:
            route_reservations.reserve(os.environ['GATEWAY_DATA_DIR'], page, instance, token_hash)
        try:
            resource = wait_for_guest_route(page, instance, token_hash) if guest_mode else resource_for_grant(page, instance, token_hash)
            result=machine({'op':'mint_access_link','guest_token':token,'resource':resource,'ttl':ttl,'one_time_use':one_time_use,'verification_method':verification_method,'verification_email':verification_email})
            secret=access_credential(result['access_link'])
            ident=hashlib.sha256(secret.encode()).hexdigest()
            with db('nhp-links') as c:
                c.execute('CREATE TABLE IF NOT EXISTS links(id TEXT PRIMARY KEY, secret TEXT NOT NULL)')
                c.execute('INSERT INTO links VALUES(?,?)',(ident,secret))
        except Exception:
            if guest_mode:
                route_reservations.cancel(os.environ['GATEWAY_DATA_DIR'], token_hash)
            raise
        return {'access_link_url':result['access_link'],'access_link_id':ident,'resource_id':resource,'type':'nhp','target_path_applied':True,'expires_at':datetime.fromtimestamp(result['expires'],timezone.utc).isoformat()}
    def prepare_revocation(self, *, access_link_id, page_id, grant_id):
        # Durable owner intent precedes local mutation. A restarted worker finishes
        # local denial before sending authority revocation; it never regrants.
        self.prepare_revocations(page_id, [{'access_link_id': access_link_id, 'id': grant_id}])

    def prepare_revocations(self, page_id, grants):
        # Capture an entire local removal atomically using the existing outbox.
        # Duplicate/restarted preparation cannot postpone native withdrawal.
        rows = [(g['access_link_id'], page_id, g['id']) for g in grants if g.get('access_link_id')]
        if rows:
            with revocation_db() as c:
                c.executemany('INSERT OR IGNORE INTO pending_revocations(id,page,grant_id) VALUES(?,?,?)', rows)

    def delete_access_link(self, *, access_link_id, **kwargs):
        # Commit the outbox before trying the network. The local guest has
        # already been disabled; service outages must not lose revocation.
        with revocation_db() as c:
            row=c.execute('SELECT secret FROM links WHERE id=?',(access_link_id,)).fetchone()
            if row is None:return True
            c.execute('INSERT OR IGNORE INTO pending_revocations(id) VALUES(?)',(access_link_id,))
        if not _revocation_lock.acquire(blocking=False):
            raise AccessServiceError('Local access revoked; service revocation is queued for retry')
        try:_send_revocation(access_link_id)
        finally:_revocation_lock.release()
        return False

_revocation_lock=threading.Lock()

@contextmanager
def revocation_db():
    c=db('nhp-links')
    c.execute('PRAGMA synchronous=FULL')
    try:
        with c:
            c.execute('CREATE TABLE IF NOT EXISTS links(id TEXT PRIMARY KEY,secret TEXT NOT NULL)')
            c.execute('CREATE TABLE IF NOT EXISTS pending_revocations(id TEXT PRIMARY KEY)')
            columns={r['name'] for r in c.execute('PRAGMA table_info(pending_revocations)')}
            for name in ('page','grant_id'):
                if name not in columns:c.execute(f"ALTER TABLE pending_revocations ADD COLUMN {name} TEXT NOT NULL DEFAULT ''")
            yield c
    finally:c.close()

def _send_revocation(ident):
    with revocation_db() as c:
        row=c.execute('SELECT secret FROM links WHERE id=?',(ident,)).fetchone()
    if row is not None:
        result=machine({'op':'revoke_link','access':row['secret'],'defer_transport':15})
        if result.get('state')!='revoked' or result.get('network_admission_update') not in ('applied','deferred'):
            raise AccessServiceError('Local access revoked; network revocation is awaiting confirmation')
    with revocation_db() as c:
        c.execute('DELETE FROM pending_revocations WHERE id=?',(ident,))
        c.execute('DELETE FROM links WHERE id=?',(ident,))

def retry_revocations(page_store=None):
    if not _revocation_lock.acquire(blocking=False):return
    try:
        with revocation_db() as c:
            rows=c.execute('SELECT id,page,grant_id FROM pending_revocations ORDER BY rowid LIMIT 8').fetchall()
        for row in rows:
            try:
                if row['page']:
                    if page_store is None:continue
                    from pages import PageNotFoundError
                    try:page_store.remove_access_grant(row['page'],row['grant_id'])
                    except PageNotFoundError:pass
                _send_revocation(row['id'])
            except AccessServiceError:break
    finally:_revocation_lock.release()

def start_revocation_worker(page_store=None):
    def run():
        while True:
            try:retry_revocations(page_store)
            except (OSError, sqlite3.Error):pass
            time.sleep(2)
    worker=threading.Thread(target=run,name='nhp-revocation',daemon=True)
    worker.start()


def handoff(handler, authority):
    from guest_auth import GuestAuthorizationError
    if handler.headers.get('Origin') != LANDING_ORIGIN:
        handler._send_json(403, {'error': 'Origin rejected'})
        return
    try:
        size = int(handler.headers.get('Content-Length', '0'))
        if not 0 < size <= 8192:
            raise ValueError()
        form = parse_qs(handler.rfile.read(size).decode(), max_num_fields=2)
        if set(form) != {'nhp_token'} or len(form['nhp_token']) != 1:
            raise ValueError()
        result = authority.redeem(form['nhp_token'][0], handler.headers.get('Origin'), handler.headers.get('X-NHP-Resource', ''))
        page, token = result['page_id'], result['session']
        selector = session_selector(token)
        handler._send_json(303, {'authenticated': True}, {
            'Location': '/access/' + page + '#session=' + selector,
            'Set-Cookie': cookie_name(page, selector) + '=' + token +
                '; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=' + str(max(0, int(result['expires'] - time.time())))})
    except (ValueError, KeyError, GuestAuthorizationError):
        handler._send_json(401, {'error': 'Invalid, used or expired NHP handoff'})


def session_selector(token):
    # Public, one-way selector; only the separate HttpOnly cookie grants access.
    return hashlib.sha256(('nhp-session-selector:' + token).encode()).hexdigest()[:32]


def cookie_name(page_id, selector):
    return '__Host-nhp_guest_' + hashlib.sha256(page_id.encode()).hexdigest()[:24] + '_' + selector


def authorize(handler, page, runtime):
    from broker_transport import GuestBrokerError, guest_request
    from ha import AUTHORIZED_NHP_GUEST, GuestContext, page_capability, HomeAssistantError
    AUTHORIZED_NHP_GUEST.set(None)
    handler.active_grant = {}
    try:
        selector = handler.headers.get('X-NHP-Session', '')
        if not re.fullmatch(r'[a-f0-9]{32}', selector):
            raise ValueError()
        token = handler._cookie(cookie_name(page['id'], selector))
        if not token or not secrets.compare_digest(session_selector(token), selector):
            raise ValueError()
        origin = handler.headers.get('Origin', '')
        resource = handler.headers.get('X-NHP-Resource', '')
        result = guest_request('/v1/session', {}, headers={
            'X-Broker-Token': page_capability(page['id']), 'X-Guest-Session': token,
            'X-Guest-Method': handler.command, 'Origin': origin, 'X-NHP-Resource': resource})
        AUTHORIZED_NHP_GUEST.set(GuestContext(page['id'], token, origin, resource))
        handler.active_grant = result['grant']
        handler.camera_access_scope = 'grant:' + result['grant']['id']
        handler.action_deadline = datetime.fromtimestamp(result['expires'], timezone.utc).isoformat()
        return True
    except (ValueError, KeyError, GuestBrokerError, HomeAssistantError) as error:
        status = 403 if getattr(error, 'status', None) == 403 else 401
        handler._send_json(status, {'error': 'This access link has expired or been revoked.'})
        return False
