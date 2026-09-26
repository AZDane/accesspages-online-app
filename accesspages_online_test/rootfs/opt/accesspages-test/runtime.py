"""Standalone HA beta app: local Admin, isolated Guest, native NHP and FRPC."""
import base64
import hashlib
import http.client
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from urllib.parse import urlparse

from installation import Installation, atomic
from app_options import read_options, discovery_environment, resource_isolation

ROOT=Path(os.getenv('ACCESSPAGES_DATA_DIR','/data'))
APP=Path(__file__).resolve().parent
GATEWAY=APP/'guest_gateway' if (APP/'guest_gateway').is_dir() else APP.parent/'guest_gateway'
sys.path.insert(0,str(GATEWAY))
from page_workers import PageWorkers, directory, publish, POLICY_GROUP, GUEST_BROKER_GROUP, FRONTEND_GROUP
from guest_frontend import nginx_config
from pages import PageStore
import route_reservations
from resource_inventory import inventory as route_inventory

GROUP=POLICY_GROUP
USERS={'admin':1001,'broker':1003,'tls':1004,'connector':1005}


def gateway_environment():
    version=(APP/'version').read_text().strip() if (APP/'version').is_file() else 'development'
    return {
        **discovery_environment(read_options(ROOT)),
        'GATEWAY_FEATURE_PROFILE':'sensors_lights' if (APP/'pilot-features').exists() else os.getenv('GATEWAY_FEATURE_PROFILE','full'),
        'GATEWAY_VERSION':version,
    }

def configured_server_address():
    if os.getenv('NHP_SERVER_ADDRESS'):return os.environ['NHP_SERVER_ADDRESS']
    path=ROOT/'options.json'
    if not path.exists():return None
    options=json.loads(path.read_text())
    if not isinstance(options,dict):raise ValueError('Invalid app configuration')
    value=options.get('server_address')
    if value is not None and (not isinstance(value,str) or not value.strip()):
        raise ValueError('Invalid NHP Server address')
    return value.strip() if value else None


def broker_backend_environment():
    ha_token=os.getenv('HA_TOKEN') or os.getenv('SUPERVISOR_TOKEN')
    if os.getenv('HA_TOKEN_FILE'):
        ha_token=Path(os.environ['HA_TOKEN_FILE']).read_text().strip()
    if not ha_token:raise RuntimeError('Home Assistant credentials unavailable')
    return {'HA_BROKER_BACKEND':'homeassistant',
            'HA_BASE_URL':os.getenv('HA_BASE_URL','http://supervisor/core'),'HA_TOKEN':ha_token}


class Runtime:
    def __init__(self):
        os.umask(0o077)
        self.product=gateway_environment()
        ROOT.mkdir(exist_ok=True,mode=0o755);ROOT.chmod(0o755)
        for role,uid in USERS.items():
            role_dir=ROOT/role;role_dir.mkdir(exist_ok=True,mode=0o700)
            role_dir.chmod(0o700)
            os.chown(role_dir,uid,GROUP if role=='admin' else uid)
            # Authenticated restore extraction intentionally uses root/0600.
            # Repair only known role trees; reject unexpected symlinks.
            for child in role_dir.rglob('*'):
                if child.is_symlink():
                    raise ValueError('Unexpected runtime symlink')
                os.chown(child,uid,GROUP if role=='admin' else uid)
                child.chmod(0o700 if child.is_dir() or child==ROOT/'connector/frpc' else 0o600)
        (ROOT/'public').mkdir(exist_ok=True,mode=0o755)
        (ROOT/'public').chmod(0o755)
        self.installation=Installation(ROOT/'admin/installation',server_address=configured_server_address())
        self.lock=threading.RLock();self.children={};self.started={};self.stopping=False
        self.page_workers=PageWorkers(ROOT,GATEWAY,self)
        self.csrf=secrets.token_urlsafe(32)
        self.message='Paste the enrollment API token to connect this Home Assistant.'
        self.admin_token=self.secret('admin-token')
        self.broker_admin=self.secret('broker-admin-token')
        self.connector_health_password=self.secret('connector-health-token')
        self.allowed_proxies=set(os.getenv('NHP_ADMIN_PROXY_IPS','172.30.32.2').split(','))
        self.last_connector_status=0;self.last_certificate=0;self.last_authority=0
        self.phase='installation status';self.last_error=None
        self.frpc_digest=hashlib.sha256(Path('/opt/frpc').read_bytes()).hexdigest()

    def secret(self,name):
        path=ROOT/name
        if not path.exists():atomic(path,secrets.token_urlsafe(32))
        return path.read_text().strip()

    def start(self,role,command,env,*,uid=None,groups=None):
        previous=self.children.get(role)
        if previous is not None and previous.poll() is None:return
        if previous is not None:self.stop(role)
        # No Supervisor token, AWS credential, native key or Admin secret is
        # inherited by Guest/TLS/FRPC. Different UIDs protect /proc and files.
        base={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'PYTHONUNBUFFERED':'1',
              'HOME':env.get('GATEWAY_DATA_DIR',str(ROOT/role)),'PYTHONPATH':str(GATEWAY)}
        self.children[role]=subprocess.Popen(command,env={**base,**env},stdin=subprocess.DEVNULL,
                                            user=uid if uid is not None else USERS[role],
                                            group=uid if uid is not None else USERS[role],
                                            extra_groups=groups if groups is not None else ([GROUP] if role in ('admin','broker') else [FRONTEND_GROUP] if role=='tls' else []),
                                            start_new_session=True)
        self.started[role]=time.monotonic()

    def stop(self,role):
        child=self.children.pop(role,None)
        if child:
            # Stop the process group too. The registry independently denies a
            # retired UID, even if compromised code escaped its process group.
            try:os.killpg(child.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            try:child.wait(5)
            except subprocess.TimeoutExpired:pass
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            child.wait(5)

    def enroll(self,link):
        with self.lock:
            route=self.installation.enroll(link)
            self.message='Setting up your secure connection'
            return {'enrolled':True,'gateway_id':route['gateway_id']}

    def reset_service_connection(self):
        """Remove local service identities while preserving owner configuration."""
        request=ROOT/'admin/reset-connection.request'
        for role in list(self.children):self.stop(role)
        for path in (
            self.installation.root,
            ROOT/'connector',
            ROOT/'tls',
            ROOT/'public',
        ):
            if path.is_symlink() or path.is_file():path.unlink(missing_ok=True)
            elif path.exists():shutil.rmtree(path)
        for path in (
            ROOT/'admin/page-capabilities.json',
            ROOT/'broker/page-workers.json',
            ROOT/'broker/routes.json', ROOT/'admin/routes.json',
            ROOT/'admin/ready-routes.json',
            ROOT/'broker/guest-sessions.db',
            ROOT/'workers',
        ):
            if path.is_symlink() or path.is_file():path.unlink(missing_ok=True)
            elif path.exists():shutil.rmtree(path)
        self.page_workers.reset()
        route_reservations.cancel(ROOT/'admin')
        for role in ('connector','tls'):
            directory(ROOT/role,USERS[role],USERS[role],0o700)
        (ROOT/'public').mkdir(mode=0o755)
        self.installation=Installation(
            ROOT/'admin/installation',
            server_address=configured_server_address(),
        )
        self.last_connector_status=0;self.last_certificate=0;self.last_authority=0
        self.last_error=None
        self.message='Paste the enrollment API token to connect this Home Assistant.'
        request.unlink(missing_ok=True)

    def public_status(self):
        roles=[*(r for r in USERS if r!='connector' or getattr(self,'resources',[])),*('page:'+str(record['uid']) for record in self.page_workers.state['pages'].values())]
        ready=not getattr(self,'routes_pending',False) and all(self.children.get(r) and self.children[r].poll() is None and time.monotonic()-self.started.get(r,0)>2 for r in roles)
        if ready:
            try:
                for port in (8081,8083,8444):
                    with socket.create_connection(('127.0.0.1',port),timeout=0.2):pass
                for record in self.page_workers.state['pages'].values():
                    with socket.socket(socket.AF_UNIX) as connection:
                        connection.settimeout(0.2)
                        connection.connect(str(self.page_workers.socket(record)))
            except OSError:ready=False
        if ready:ready=self.connector_ready()
        enrolled=(self.installation.root/'binding.json').exists()
        message='Finishing your connection…' if not ready and self.message.startswith('Ready') else self.message
        if enrolled and message=='Paste the enrollment API token to connect this Home Assistant.':
            message='Your enrollment is saved. Reconnecting to Access Pages…'
        if enrolled and message.startswith('Waiting for ') and message.endswith('. Retrying automatically.'):
            message='We could not finish connecting yet. Retrying automatically; your enrollment is saved. If this continues, contact support.'
        return {'message':message,'enrolled':enrolled,
                'ready':bool(ready),'admin_ready':self.admin_ready()}

    def admin_ready(self):
        # Owner controls must remain reachable through HA Ingress when the
        # remote tunnel is unavailable, so local revocation can be queued.
        for role,port in [('admin',8081),('broker',8083)]:
            child=self.children.get(role)
            if child is None or child.poll() is not None:return False
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=0.2):pass
            except OSError:return False
        return True

    def connector_ready(self):
        expected={r['resource_id'] for r in getattr(self,'resources',[])}
        if not expected:return True
        connection=http.client.HTTPConnection('127.0.0.1',8084,timeout=0.5)
        try:
            basic=base64.b64encode(('runtime:'+self.connector_health_password).encode()).decode()
            connection.request('GET','/api/status',headers={'Authorization':'Basic '+basic})
            response=connection.getresponse()
            value=json.loads(response.read(32768))
            return response.status==200 and expected=={p.get('name') for p in value.get('tcp',[]) if p.get('status')=='running'}
        except (OSError,ValueError,http.client.HTTPException):return False
        finally:connection.close()

    def prepare(self):
        self.phase='installation status'
        now=time.monotonic()
        if now-self.last_authority>3600:
            self.installation.refresh_authority();self.last_authority=now
        binding=self.installation.recover_binding()
        if not (self.installation.root/'connector.json').exists():
            self.installation.ensure_connector()
        if now-self.last_connector_status>45:
            self.phase='connector status'
            self.installation.refresh_connector()
            binding=self.installation.recover_binding()
            self.last_connector_status=now
        source=PageStore(ROOT/'admin/pages',file_mode=0o640)
        mode=resource_isolation(read_options(ROOT))
        mode_path=ROOT/'resource-isolation.json'
        previous=json.loads(mode_path.read_text()) if mode_path.exists() else 'page'
        with source.authority_guard(write=True):
            if previous!=mode:
                self.stop('connector')
                (ROOT/'admin/ready-routes.json').unlink(missing_ok=True)
                for role in ('admin','broker'):
                    publish(ROOT/role/'routes.json',json.dumps({'gateway_id':binding['gateway_id'],
                        'epoch':binding['route']['epoch'],'isolation':mode,'resources':[]}),0,USERS[role])
                # Revoke before persisting the new mode. Restart repeats any
                # interrupted purge; no old invitation is carried across modes.
                source.revoke_all_access_grants()
                route_reservations.cancel(ROOT/'admin')
                for path in source.directory.glob('*.json'):
                    os.chown(path,USERS['admin'],GROUP)
            if previous!=mode or not mode_path.exists():atomic(mode_path,json.dumps(mode))
            inventory=route_inventory([source.load(p['id']) for p in source.list_pages()],mode,route_reservations.pending(ROOT/'admin'))
        retry_after=5 if getattr(self,'routes_pending',False) else 45
        self.routes_pending=False
        if inventory!=getattr(self,'last_attempted_inventory',None) or now-getattr(self,'last_page_sync',0)>retry_after:
            (ROOT/'admin/ready-routes.json').unlink(missing_ok=True)
            self.phase='page routes'
            self.last_page_sync=now
            self.last_attempted_inventory=inventory
            try:
                self.installation.sync_page_routes(inventory)
            except RuntimeError:
                # Keep local Admin available while capacity/withdrawal is pending.
                self.routes_pending=True
            binding=self.installation.recover_binding()
        route=binding['route']
        current={(p['page_id'],p['instance_id'],p['guest_hash']) for p in inventory}
        self.resources=[r for r in route.get('resources',[]) if (r['page_id'],r['instance_id'],r['guest_hash']) in current]
        self.routes_pending=self.routes_pending or len(self.resources)!=len(inventory) or any(not r['dns_ready'] for r in self.resources)
        manifest={'gateway_id':binding['gateway_id'],'epoch':route['epoch'],'isolation':mode,'resources':self.resources}
        if now-self.last_certificate>3600 or not (ROOT/'tls/guest.crt').exists():
            self.phase='customer certificate issuance'
            if not self.installation.ensure_certificate():
                self.message='Setting up your secure connection'
                return False
            changed=not (ROOT/'tls/guest.crt').exists() or (ROOT/'tls/guest.crt').read_bytes()!=(self.installation.root/'guest.crt').read_bytes()
            for name in ('guest.crt','guest.key'):
                atomic(ROOT/'tls'/name,(self.installation.root/name).read_text(),0o600)
                os.chown(ROOT/'tls'/name,USERS['tls'],USERS['tls'])
            if changed:self.stop('tls')
            self.last_certificate=now
        for role in ('admin','broker'):
            publish(ROOT/role/'routes.json',json.dumps(manifest),0,USERS[role])
        atomic(ROOT/'public/handoff-public-key',(self.installation.root/'handoff-public-key').read_text(),0o644)
        atomic(ROOT/'public/binding.json',json.dumps({'gateway_id':binding['gateway_id'],'route':{'epoch':route['epoch']}}),0o644)
        pages=ROOT/'admin/pages';pages.mkdir(exist_ok=True,mode=0o750)
        os.chown(pages,USERS['admin'],GROUP);pages.chmod(0o2750)
        for page in pages.iterdir():
            if page.is_file():page.chmod(0o640)
        # Only Admin and Broker can read grants; page workers receive projections.
        (ROOT/'admin').chmod(0o710)
        lock=pages/'.authority.lock'
        if not lock.exists():atomic(lock,'',0o640)
        os.chown(lock,USERS['admin'],GROUP)
        for child in self.installation.root.rglob('*'):
            os.chown(child,USERS['admin'],GROUP)
        os.chown(self.installation.root,USERS['admin'],GROUP)
        admin_capabilities=ROOT/'admin/page-capabilities.json'
        ca=os.getenv('NHP_SERVICE_CA_FILE')
        if ca:atomic(ROOT/'public/service-ca.crt',Path(ca).read_text(),0o644)
        product=self.product
        common={**product,'ACCESS_TRANSPORT':'nhp','NHP_INSTALLATION_ROUTING':'1',
                'NHP_LANDING_ORIGIN':json.loads((self.installation.root/'profile.json').read_text())['landing_origin'],
                'NHP_BINDING_FILE':str(ROOT/'public/binding.json'),
                'NHP_VERIFY_KEY_FILE':str(ROOT/'public/handoff-public-key'),
                'HOST':'127.0.0.1',
                'PAGE_FILE_MODE':'640','HA_BROKER_URL':'http://127.0.0.1:8083'}
        directory(ROOT/'guest-broker',USERS['broker'],GUEST_BROKER_GROUP,0o2710)
        directory(ROOT/'handoff',USERS['broker'],FRONTEND_GROUP,0o2710)
        workers=self.page_workers.reconcile(common,broker_uid=USERS['broker'],tls_uid=USERS['tls'],admin_uid=USERS['admin'],manifest=manifest)
        guest_socket=str(ROOT/'guest-broker/http.sock')
        self.phase='Home Assistant connection'
        self.start('broker',['python3',str(GATEWAY/'ha_broker.py')],{
            **common,'NHP_ROUTES_FILE':str(ROOT/'broker/routes.json'),'HA_BROKER_HOST':'127.0.0.1','HA_BROKER_PORT':'8083',
            'HA_BROKER_ADMIN_TOKEN':self.broker_admin,
            'HA_GUEST_BROKER_SOCKET':guest_socket,
            'HA_HANDOFF_SOCKET':str(ROOT/'handoff/http.sock'),'GATEWAY_FRONTEND_UID':str(USERS['tls']),
            'HA_GUEST_SESSION_DB':str(ROOT/'broker/guest-sessions.db'),
            **broker_backend_environment(),'HA_BROKER_POLICY_DIR':str(pages),
            'HA_PAGE_WORKER_REGISTRY':str(ROOT/'broker/page-workers.json')})
        self.start('admin',['python3',str(GATEWAY/'server.py')],{**common,
            'NHP_READY_ROUTES_FILE':str(ROOT/'admin/ready-routes.json'),
            'NHP_ROUTES_FILE':str(ROOT/'admin/routes.json'),'GATEWAY_ROLE':'admin','GATEWAY_DATA_DIR':str(ROOT/'admin'),'PORT':'8081',
            'ADMIN_TOKEN':self.admin_token,'HA_BROKER_TOKEN':self.broker_admin,
            'PAGE_CAPABILITY_REGISTRY_FILE':str(admin_capabilities),
            'MACHINE_DIR':str(self.installation.machine_dir)})
        config=nginx_config(ROOT,GATEWAY,route['host'],workers,self.resources)
        configuration=ROOT/'tls/nginx.conf'
        changed=not configuration.exists() or configuration.read_text()!=config
        if changed:
            (ROOT/'admin/ready-routes.json').unlink(missing_ok=True)
            # Check before reloading; never leave a partially written routing table.
            candidate=ROOT/'tls/nginx.next.conf'
            publish(candidate,config,USERS['tls'],USERS['tls'],0o600)
            subprocess.run(['nginx','-t','-e','stderr','-c',str(candidate)],
                           check=True,user=USERS['tls'],group=USERS['tls'],extra_groups=[FRONTEND_GROUP],
                           stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            candidate.replace(configuration)
            child=self.children.get('tls')
            if child is not None and child.poll() is None:child.send_signal(signal.SIGHUP)
        self.start('tls',['nginx','-e','stderr','-c',str(ROOT/'tls/nginx.conf'),'-g','daemon off;'],{})
        if not self.resources:
            self.stop('connector')
            self.last_error=None
            self.message='Waiting for page routes. Retrying automatically.' if self.routes_pending else 'Ready to create pages and test guest invitations.'
            return True
        connector_config=self.installation.connector_config(self.resources,self.connector_health_password).replace(str(self.installation.root/'frp-ca.crt'),str(ROOT/'connector/frp-ca.crt'))
        configuration=ROOT/'connector/frpc.toml'
        if not configuration.exists() or configuration.read_text()!=connector_config:self.stop('connector')
        for name,value in [('frpc.toml',connector_config),('frp-ca.crt',(self.installation.root/'frp-ca.crt').read_text())]:
            atomic(ROOT/'connector'/name,value);os.chown(ROOT/'connector'/name,USERS['connector'],USERS['connector'])
        # NHP-FRP starts its embedded scoped Agent beside its executable.
        for source in (self.installation.root/'connector-nhp/etc').glob('*.toml'):
            target=ROOT/'connector/etc'/source.name
            atomic(target,source.read_text());os.chown(target,USERS['connector'],USERS['connector'])
        os.chown(ROOT/'connector/etc',USERS['connector'],USERS['connector'])
        marker=ROOT/'connector/binary.sha256'
        if not marker.exists() or marker.read_text()!=self.frpc_digest:
            self.stop('connector')
            shutil.copyfile('/opt/frpc',ROOT/'connector/frpc.new')
            os.chmod(ROOT/'connector/frpc.new',0o700);os.chown(ROOT/'connector/frpc.new',USERS['connector'],USERS['connector'])
            (ROOT/'connector/frpc.new').replace(ROOT/'connector/frpc')
            atomic(marker,self.frpc_digest)
        child=self.children.get('connector')
        if child is None or child.poll() is not None:
            self.phase='connector admission'
            result=self.installation.operation({'op':'probe','nhp_resource':'frp-connector','transport_only':True},connector=True)
            if result.get('ack',{}).get('errCode')!='0':raise RuntimeError('Connector admission rejected')
        # Once FRPC is running, its embedded Agent owns this native identity.
        # Do not run a competing native Agent using the same key in parallel.
        self.start('connector',[str(ROOT/'connector/frpc'),'-c',str(ROOT/'connector/frpc.toml')],{})
        ready=not changed and self.connector_ready() and all(self.children.get(r) and self.children[r].poll() is None for r in ('tls','broker'))
        publish(ROOT/'admin/ready-routes.json',json.dumps({
            'gateway_id':manifest['gateway_id'],'epoch':manifest['epoch'],'isolation':mode,
            'checked_at':time.time(),'resources':[r['resource_id'] for r in self.resources if r['dns_ready']] if ready else []}),0,USERS['admin'])
        self.last_error=None
        self.message='Waiting for page routes. Retrying automatically.' if self.routes_pending else 'Ready to create pages and test guest invitations.'
        return True

    def loop(self):
        while not self.stopping:
            with self.lock:
                if (ROOT/'admin/reset-connection.request').exists():
                    self.reset_service_connection()
                if (self.installation.root/'binding.json').exists():
                    try:self.prepare()
                    except Exception as error:
                        self.stop('connector')
                        (ROOT/'admin/ready-routes.json').unlink(missing_ok=True)
                        self.message='Waiting for '+self.phase+'. Retrying automatically.'
                        signature=(self.phase,type(error).__name__)
                        if signature!=self.last_error:
                            print('Customer runtime waiting:',self.phase,type(error).__name__,flush=True)
                            self.last_error=signature
            time.sleep(2)


class Ingress(BaseHTTPRequestHandler):
    runtime=None
    def log_message(self,*_args):pass
    def send(self,status,body,content_type='application/json'):
        if not isinstance(body,bytes):body=json.dumps(body).encode()
        self.send_response(status);self.send_header('Content-Type',content_type)
        self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff');self.send_header('Referrer-Policy','no-referrer')
        self.end_headers();self.wfile.write(body)
    def handle_request(self):
        runtime=self.runtime
        if self.client_address[0] not in runtime.allowed_proxies:self.send(403,{'error':'Use Home Assistant Ingress'});return
        if self.command not in ('GET','HEAD') and self.headers.get('X-Access-Pages-CSRF')!=runtime.csrf:self.send(403,{'error':'Reload the local app'});return
        try:
            length=int(self.headers.get('Content-Length','0'))
            if not 0<=length<=512000:raise ValueError()
            body=self.rfile.read(length) if length else b''
            path=urlparse(self.path).path
            if path=='/setup/status':self.send(200,runtime.public_status());return
            if path=='/setup/enroll' and self.command=='POST':
                value=json.loads(body)
                if not isinstance(value,dict) or set(value)!={'enrollment_token'}:raise ValueError()
                self.send(200,runtime.enroll(value['enrollment_token']));return
            if self.command=='GET' and not runtime.admin_ready():
                if path.startswith('/api/'):
                    self.send(503,{'error':'Application is starting'});return
                if runtime.public_status().get('enrolled'):
                    self.send(200,(APP/'waiting.html').read_bytes(),'text/html; charset=utf-8');return
                markup=(APP/'setup.html').read_text().replace('SETUP_CSRF',runtime.csrf).replace('SERVICE_ADDRESS',html.escape(runtime.installation.server_address))
                self.send(200,markup.encode(),'text/html; charset=utf-8');return
            target='/admin' if path=='/' else self.path
            connection=http.client.HTTPConnection('127.0.0.1',8081,timeout=130)
            try:
                headers={'X-Admin-Token':runtime.admin_token,'Content-Type':self.headers.get('Content-Type','application/json')}
                connection.request(self.command,target,body,headers)
                response=connection.getresponse();payload=response.read(2*1024*1024)
                kind=response.getheader('Content-Type','application/json')
                if 'text/html' in kind:
                    payload=payload.replace(b'</head>',f'<meta name="access-pages-csrf" content="{runtime.csrf}"></head>'.encode())
                self.send(response.status,payload,kind)
            finally:connection.close()
        except Exception:self.send(400,{'error':'Operation failed. Check the enrollment token and service connection.'})
    do_GET=handle_request
    do_POST=handle_request
    do_PUT=handle_request
    do_DELETE=handle_request


def main():
    runtime=Runtime();Ingress.runtime=runtime
    server=ThreadingHTTPServer(('0.0.0.0',8099),Ingress);server.daemon_threads=True
    threading.Thread(target=runtime.loop,daemon=True).start()
    def stop(*_args):
        runtime.stopping=True
        threading.Thread(target=server.shutdown,daemon=True).start()
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    try:server.serve_forever()
    finally:
        runtime.stopping=True
        for role in list(runtime.children):runtime.stop(role)


if __name__=='__main__':main()
