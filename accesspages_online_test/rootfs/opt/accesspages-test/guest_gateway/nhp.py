"""Optional NHP transport for the existing Admin and Guest Pages boundaries."""
import base64, hashlib, json, os, re, secrets, sqlite3, subprocess, time
import threading
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from datetime import datetime, timezone
from access_service import AccessServiceError
from pages import validate_page_id

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

def resource_for_target(target_path):
    page = urlparse(target_path).path.removeprefix('/access/').strip('/')
    return resource_for_page(page)

def resource_for_page(page):
    if INSTALLATION_ROUTING:
        return validate_page_id(page)
    value = PAGE_RESOURCES.get(page, RESOURCE)
    return value if isinstance(value, str) and value else RESOURCE

def origin_for_resource(resource):
    if INSTALLATION_ROUTING:
        return ORIGIN
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
        resource = resource_for_target(target_path)
        try:
            ttl=int(expires_in[:-1])*{'m':60,'h':3600,'d':86400,'w':604800}[expires_in[-1]]
        except (KeyError, TypeError, ValueError):
            raise AccessServiceError('Invalid AccessLink lifetime')
        if not 1<=ttl<=ACCESS_LINK_MAX_LIFETIME_SECONDS:
            raise AccessServiceError('Access Pages invitations support up to 30 days')
        if INSTALLATION_ROUTING:
            machine({'op':'assign_page','page_id':resource})
        result=machine({'op':'mint_access_link','guest_token':token,'resource':resource,'ttl':ttl,'one_time_use':one_time_use,'verification_method':verification_method,'verification_email':verification_email})
        secret=access_credential(result['access_link'])
        ident=hashlib.sha256(secret.encode()).hexdigest()
        with db('nhp-links') as c:
            c.execute('CREATE TABLE IF NOT EXISTS links(id TEXT PRIMARY KEY, secret TEXT NOT NULL)')
            c.execute('INSERT INTO links VALUES(?,?)',(ident,secret))
        return {'access_link_url':result['access_link'],'access_link_id':ident,'resource_id':resource,'type':'nhp','target_path_applied':True,'expires_at':datetime.fromtimestamp(result['expires'],timezone.utc).isoformat()}
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
    try:
        with c:
            c.execute('CREATE TABLE IF NOT EXISTS links(id TEXT PRIMARY KEY,secret TEXT NOT NULL)')
            c.execute('CREATE TABLE IF NOT EXISTS pending_revocations(id TEXT PRIMARY KEY)')
            yield c
    finally:c.close()

def _send_revocation(ident):
    with revocation_db() as c:
        row=c.execute('SELECT secret FROM links WHERE id=?',(ident,)).fetchone()
    if row is not None:
        result=machine({'op':'revoke_link','access':row['secret']})
        if result.get('state')!='revoked' or result.get('network_admission_update')!='applied':
            raise AccessServiceError('Local access revoked; network revocation is awaiting confirmation')
    with revocation_db() as c:
        c.execute('DELETE FROM pending_revocations WHERE id=?',(ident,))
        c.execute('DELETE FROM links WHERE id=?',(ident,))

def retry_revocations():
    if not _revocation_lock.acquire(blocking=False):return
    try:
        with revocation_db() as c:
            rows=c.execute('SELECT id FROM pending_revocations ORDER BY rowid LIMIT 8').fetchall()
        for row in rows:
            try:_send_revocation(row['id'])
            except AccessServiceError:break
    finally:_revocation_lock.release()

def start_revocation_worker():
    def run():
        while True:
            try:retry_revocations()
            except (OSError, sqlite3.Error):pass
            time.sleep(2)
    worker=threading.Thread(target=run,name='nhp-revocation',daemon=True)
    worker.start()


# Match the browser's bounded issue-time allowance across independent clocks.
# Expiration and the absolute session deadline remain strict.
ISSUED_AT_CLOCK_SKEW_SECONDS = 5

def verification_policy(grant):
    """Bind browser sessions to the current, locally saved invitation policy."""
    if grant.get('verification_required'):
        raise ValueError('Local verification is unavailable for NHP guests')
    method = grant.get('verification_method', 'none')
    email = str(grant.get('verification_email', '')).strip().lower()
    if method not in ('none', 'google', 'email', 'google_or_email'):
        raise ValueError('Unknown verification policy')
    if method != 'none' and (len(email) > 254 or email.count('@') != 1 or any(c.isspace() for c in email) or not all(email.split('@'))):
        raise ValueError('Invited email required')
    return method, email if method != 'none' else ''

def policy_hash(grant):
    return hashlib.sha256(json.dumps(verification_policy(grant), separators=(',', ':')).encode()).hexdigest()

def require_verified_guest(grant, claims):
    method, email = verification_policy(grant)
    if method != 'none':
        expected = {'google': {'google_oidc'}, 'email': {'email_otp'}, 'google_or_email': {'google_oidc', 'email_otp'}}[method]
        if claims.get('verification_method') not in expected or claims.get('verified_email') != email:
            raise ValueError('Handoff does not satisfy the invited guest policy')

def verify(token):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if len(token)>4096:raise ValueError()
    prefix,body,sig=token.split('.')
    if prefix!='nhp-guest-v1':raise ValueError()
    decode=lambda v:base64.urlsafe_b64decode(v+'='*(-len(v)%4))
    key=base64.b64decode(Path(os.getenv('NHP_VERIFY_KEY_FILE','/run/verify/public-key')).read_text())
    Ed25519PublicKey.from_public_bytes(key).verify(decode(sig),(prefix+'.'+body).encode())
    claims=json.loads(decode(body));now=int(time.time())
    binding=json.loads(Path(os.getenv('NHP_BINDING_FILE','/run/nhp-binding.json')).read_text())
    gid=binding['gateway_id']
    allowed_resources = {RESOURCE, *[v for v in PAGE_RESOURCES.values() if isinstance(v, str)]}
    resource_allowed = claims.get('resource') in allowed_resources
    if INSTALLATION_ROUTING:
        resource_allowed = isinstance(claims.get('resource'),str) and validate_page_id(claims['resource'])==claims['resource']
        if type(claims.get('gateway_epoch')) is not int or claims['gateway_epoch']!=binding['route']['epoch']:raise ValueError()
    if (claims.get('iss')!='nhp-guest-authority' or claims.get('aud')!='guest-gateway' or claims.get('gateway_id')!=gid or not resource_allowed
        or type(claims.get('iat')) is not int or type(claims.get('exp')) is not int or claims['iat']>now+ISSUED_AT_CLOCK_SKEW_SECONDS or now>=claims['exp'] or not 0<claims['exp']-claims['iat']<=60
        or not isinstance(claims.get('guest_token'),str) or len(claims['guest_token'])!=43 or not isinstance(claims.get('grant_id'),str) or len(claims['grant_id'])!=43):raise ValueError()
    return claims

def handoff(handler,runtime):
    if runtime.GATEWAY_ROLE!='guest':handler._send_json(404,{'error':'not found'});return
    if handler.headers.get('Origin')!=LANDING_ORIGIN:handler._send_json(403,{'error':'Origin rejected'});return
    try:
        size=int(handler.headers.get('Content-Length','0'))
        if not 0<size<=8192:raise ValueError()
        form=parse_qs(handler.rfile.read(size).decode(),max_num_fields=2)
        if set(form)!={'nhp_token'} or len(form['nhp_token'])!=1:raise ValueError()
        claims=verify(form['nhp_token'][0]);digest=hashlib.sha256(claims['guest_token'].encode()).hexdigest()
        # Open the database before reading authority. Grant mutation and session
        # issuance then share the PageStore's cross-process read/write boundary.
        with db('nhp-sessions') as c, runtime.PAGE_STORE.authority_guard():
            c.executescript('CREATE TABLE IF NOT EXISTS used(id TEXT PRIMARY KEY,expires INTEGER); CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY,page TEXT,grant_id TEXT,expires INTEGER);')
            c.execute('BEGIN IMMEDIATE')
            if 'policy_hash' not in {row['name'] for row in c.execute('PRAGMA table_info(sessions)')}:
                c.execute("ALTER TABLE sessions ADD COLUMN policy_hash TEXT NOT NULL DEFAULT ''")
            now=int(time.time())
            if claims['exp']<=now:raise ValueError()
            match=None
            for item in runtime.PAGE_STORE.list_pages():
                page=runtime.PAGE_STORE.load(item['id'])
                for grant in page['access_grants']:
                    if grant['token_hash']==digest and runtime.parse_time(grant['expires_at'])>runtime.utc_now() and not grant.get('verification_required'):
                        if match is not None:raise ValueError()
                        require_verified_guest(grant, claims)
                        match=(page['id'],grant['id'],int(runtime.parse_time(grant['expires_at']).timestamp()),policy_hash(grant))
            if match is None or claims['resource'] != resource_for_page(match[0]):raise ValueError()
            if INSTALLATION_ROUTING and claims.get('destination') != urlparse(ORIGIN).netloc:raise ValueError()
            session_end=min(now+3600,match[2])
            if INSTALLATION_ROUTING:
                if type(claims.get('session_exp')) is not int or not now<claims['session_exp']<=claims['iat']+3600:raise ValueError()
                session_end=min(session_end,claims['session_exp'])
            token=secrets.token_urlsafe(32)
            c.execute('DELETE FROM used WHERE expires<=?',(now,))
            c.execute('DELETE FROM sessions WHERE expires<=?',(now,))
            c.execute('INSERT INTO used VALUES(?,?)',(claims['grant_id'],claims['exp']))
            c.execute('INSERT INTO sessions(hash,page,grant_id,expires,policy_hash) VALUES(?,?,?,?,?)',(session_hash(token,claims.get('gateway_epoch')),match[0],match[1],session_end,match[3]))
            # Commit while the grant read lock is held, so a completed revocation
            # always precedes a rejection or follows an already issued session.
            c.commit()
        handler._send_json(303,{'authenticated':True},{'Location':'/access/'+match[0],'Set-Cookie':cookie_name(match[0])+'='+token+'; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age='+str(session_end-now)})
    except Exception:
        handler._send_json(401,{'error':'Invalid, used or expired NHP handoff'})

def cookie_name(page_id):
    # Host-only cookies prevent one page's handoff from replacing another's.
    return '__Host-nhp_guest_'+hashlib.sha256(page_id.encode()).hexdigest()[:24]

def session_hash(token,epoch=None):
    if INSTALLATION_ROUTING:
        if epoch is None:
            binding=json.loads(Path(os.getenv('NHP_BINDING_FILE','/run/nhp-binding.json')).read_text())
            epoch=binding['route']['epoch']
        token=token+':'+str(epoch)
    return hashlib.sha256(token.encode()).hexdigest()

def authorize(handler,page,runtime):
    from ha import AUTHORIZED_NHP_PAGE
    AUTHORIZED_NHP_PAGE.set('')
    handler.active_grant = {}
    token=handler._cookie(cookie_name(page['id']))
    try:
        with db('nhp-sessions') as c:
            row=c.execute('SELECT * FROM sessions WHERE hash=? AND page=? AND expires>?',(session_hash(token),page['id'],int(time.time()))).fetchone()
        grant=next((g for g in page['access_grants'] if row and g['id']==row['grant_id'] and runtime.parse_time(g['expires_at'])>runtime.utc_now() and not g.get('verification_required')),None)
        if grant is None or 'policy_hash' not in row.keys() or row['policy_hash'] != policy_hash(grant):raise ValueError()
        expected_origin=origin_for_resource(resource_for_page(page['id']))
        if handler.command not in ('GET','HEAD') and handler.headers.get('Origin')!=expected_origin:
            handler._send_json(403,{'error':'Origin rejected'});return False
        AUTHORIZED_NHP_PAGE.set(page['id'])
        handler.active_grant=grant;handler.camera_access_scope='grant:'+grant['id'];return True
    except (ValueError,sqlite3.Error,TypeError):
        handler._send_json(401,{'error':'Valid NHP guest session required'});return False
