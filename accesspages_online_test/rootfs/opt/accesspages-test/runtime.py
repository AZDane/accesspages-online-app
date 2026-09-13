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
import threading
import time
from urllib.parse import urlparse

from installation import Installation, atomic

ROOT=Path(os.getenv('ACCESSPAGES_DATA_DIR','/data'))
APP=Path(__file__).resolve().parent
GATEWAY=APP/'guest_gateway'
GROUP=2000
USERS={'admin':1001,'guest':1002,'broker':1003,'tls':1004,'connector':1005}
# The installable NHP test app includes this immutable marker. Live-HA lab
# fixtures omit it; injected credentials cannot switch the test app to live HA.
DEMO_DATA=(APP/'demo-data').is_file()

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
    if DEMO_DATA:
        return {'HA_BROKER_BACKEND':'demo'}
    ha_token=os.getenv('HA_TOKEN') or os.getenv('SUPERVISOR_TOKEN')
    if os.getenv('HA_TOKEN_FILE'):
        ha_token=Path(os.environ['HA_TOKEN_FILE']).read_text().strip()
    if not ha_token:raise RuntimeError('Home Assistant credentials unavailable')
    return {'HA_BROKER_BACKEND':'homeassistant',
            'HA_BASE_URL':os.getenv('HA_BASE_URL','http://supervisor/core'),'HA_TOKEN':ha_token}


class Runtime:
    def __init__(self):
        os.umask(0o077)
        ROOT.mkdir(exist_ok=True,mode=0o755);ROOT.chmod(0o755)
        for role,uid in USERS.items():
            directory=ROOT/role;directory.mkdir(exist_ok=True,mode=0o700)
            os.chown(directory,uid,GROUP)
            # Authenticated restore extraction intentionally uses root/0600.
            # Repair only known role trees; reject unexpected symlinks.
            for child in directory.rglob('*'):
                if child.is_symlink():
                    if role!='guest' or child!=directory/'pages' or child.resolve()!=ROOT/'admin/pages':
                        raise ValueError('Unexpected runtime symlink')
                    continue
                os.chown(child,uid,GROUP)
                child.chmod(0o700 if child.is_dir() or child==ROOT/'connector/frpc' else 0o600)
        (ROOT/'public').mkdir(exist_ok=True,mode=0o755)
        (ROOT/'public').chmod(0o755)
        self.installation=Installation(ROOT/'admin/installation',server_address=configured_server_address())
        self.lock=threading.RLock();self.children={};self.started={};self.stopping=False
        self.csrf=secrets.token_urlsafe(32)
        self.message='Paste the enrollment API token to connect this Home Assistant.'
        self.admin_token=self.secret('admin-token')
        self.broker_admin=self.secret('broker-admin-token')
        self.broker_unused=self.secret('broker-unused-token')
        self.connector_health_password=self.secret('connector-health-token')
        self.allowed_proxies=set(os.getenv('NHP_ADMIN_PROXY_IPS','172.30.32.2').split(','))
        self.last_connector_status=0;self.last_certificate=0;self.last_authority=0
        self.phase='installation status';self.last_error=None
        self.frpc_digest=hashlib.sha256(Path('/opt/frpc').read_bytes()).hexdigest()

    def secret(self,name):
        path=ROOT/name
        if not path.exists():atomic(path,secrets.token_urlsafe(32))
        return path.read_text().strip()

    def start(self,role,command,env):
        previous=self.children.get(role)
        if previous is not None and previous.poll() is None:return
        # No Supervisor token, AWS credential, native key or Admin secret is
        # inherited by Guest/TLS/FRPC. Different UIDs protect /proc and files.
        base={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'PYTHONUNBUFFERED':'1',
              'HOME':str(ROOT/role),'PYTHONPATH':str(GATEWAY)}
        self.children[role]=subprocess.Popen(command,env={**base,**env},stdin=subprocess.DEVNULL,
                                            user=USERS[role],group=GROUP,extra_groups=[])
        self.started[role]=time.monotonic()

    def stop(self,role):
        child=self.children.pop(role,None)
        if child and child.poll() is None:
            child.terminate()
            try:child.wait(5)
            except subprocess.TimeoutExpired:child.kill();child.wait(5)

    def enroll(self,link):
        with self.lock:
            route=self.installation.enroll(link)
            self.message='Enrolled. Preparing the customer TLS certificate.'
            return {'enrolled':True,'gateway_id':route['gateway_id']}

    def public_status(self):
        ready=all(self.children.get(r) and self.children[r].poll() is None and time.monotonic()-self.started.get(r,0)>2 for r in USERS)
        if ready:
            try:
                for port in (8081,8082,8083,8444):
                    with socket.create_connection(('127.0.0.1',port),timeout=0.2):pass
            except OSError:ready=False
        if ready:ready=self.connector_ready()
        message='Starting local app services.' if not ready and self.message.startswith('Ready') else self.message
        return {'message':message,'enrolled':(self.installation.root/'binding.json').exists(),
                'ready':bool(ready),'admin_ready':self.admin_ready(),
                'device_data':'demo' if DEMO_DATA else 'homeassistant'}

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
        connection=http.client.HTTPConnection('127.0.0.1',8084,timeout=0.5)
        try:
            basic=base64.b64encode(('runtime:'+self.connector_health_password).encode()).decode()
            connection.request('GET','/api/status',headers={'Authorization':'Basic '+basic})
            response=connection.getresponse()
            value=json.loads(response.read(32768))
            return response.status==200 and any(p.get('name')=='guest' and p.get('status')=='running' for p in value.get('tcp',[]))
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
        route=binding['route'];origin='https://'+route['host']+':'+str(route['port'])
        if now-self.last_certificate>3600 or not (ROOT/'tls/guest.crt').exists():
            self.phase='customer certificate issuance'
            if not self.installation.ensure_certificate():
                self.message='Enrolled. Waiting for the customer TLS certificate.'
                return False
            changed=not (ROOT/'tls/guest.crt').exists() or (ROOT/'tls/guest.crt').read_bytes()!=(self.installation.root/'guest.crt').read_bytes()
            for name in ('guest.crt','guest.key'):
                atomic(ROOT/'tls'/name,(self.installation.root/name).read_text(),0o600)
                os.chown(ROOT/'tls'/name,USERS['tls'],GROUP)
            if changed:self.stop('tls')
            self.last_certificate=now
        for name,source in [('handoff-public-key','handoff-public-key'),('binding.json','binding.json')]:
            atomic(ROOT/'public'/name,(self.installation.root/source).read_text(),0o644)
        pages=ROOT/'admin/pages';pages.mkdir(exist_ok=True,mode=0o750)
        os.chown(pages,USERS['admin'],GROUP);pages.chmod(0o750)
        for page in pages.iterdir():
            if page.is_file():page.chmod(0o640)
        guest_pages=ROOT/'guest/pages'
        if not guest_pages.exists():guest_pages.symlink_to(pages)
        # Only this directory is traversable by the Guest group; all Admin
        # runtime and native identity directories remain owner-only.
        (ROOT/'admin').chmod(0o710)
        for directory in self.installation.root.rglob('*'):
            os.chown(directory,USERS['admin'],GROUP)
        os.chown(self.installation.root,USERS['admin'],GROUP)
        capabilities_path=ROOT/'guest/page-capabilities.json'
        capabilities=json.loads(capabilities_path.read_text()) if capabilities_path.exists() else {}
        ids={p.stem for p in pages.glob('*.json')}
        capabilities={page:capabilities.get(page,secrets.token_urlsafe(32)) for page in ids}
        atomic(capabilities_path,json.dumps(capabilities));os.chown(capabilities_path,USERS['guest'],GROUP)
        atomic(ROOT/'broker/page-capabilities.json',json.dumps({page:hashlib.sha256(value.encode()).hexdigest() for page,value in capabilities.items()}))
        os.chown(ROOT/'broker/page-capabilities.json',USERS['broker'],GROUP)
        # Admin owns activity and notification policy. Give it only capability
        # hashes; the guest process uses its existing per-page credentials.
        admin_capabilities=ROOT/'admin/page-capabilities.json'
        atomic(admin_capabilities,json.dumps({page:hashlib.sha256(value.encode()).hexdigest() for page,value in capabilities.items()}))
        os.chown(admin_capabilities,USERS['admin'],GROUP)
        ca=os.getenv('NHP_SERVICE_CA_FILE')
        if ca:atomic(ROOT/'public/service-ca.crt',Path(ca).read_text(),0o644)
        common={'ACCESS_TRANSPORT':'nhp','NHP_INSTALLATION_ROUTING':'1',
                'NHP_GATEWAY_ORIGIN':origin,'NHP_LANDING_ORIGIN':json.loads((self.installation.root/'profile.json').read_text())['landing_origin'],
                'NHP_BINDING_FILE':str(ROOT/'public/binding.json'),
                'NHP_VERIFY_KEY_FILE':str(ROOT/'public/handoff-public-key'),
                'HOST':'127.0.0.1','ACCESS_LINK_MAX_LIFETIME_DAYS':'1',
                'PAGE_FILE_MODE':'640','HA_BROKER_URL':'http://127.0.0.1:8083'}
        self.phase='demo data' if DEMO_DATA else 'Home Assistant connection'
        self.start('broker',['python3',str(GATEWAY/'ha_broker.py')],{
            'HA_BROKER_HOST':'127.0.0.1','HA_BROKER_PORT':'8083',
            'HA_BROKER_TOKEN':self.broker_unused,'HA_BROKER_ADMIN_TOKEN':self.broker_admin,
            **broker_backend_environment(),'HA_BROKER_POLICY_DIR':str(pages),
            'HA_PAGE_CAPABILITY_REGISTRY':str(ROOT/'broker/page-capabilities.json')})
        self.start('admin',['python3',str(GATEWAY/'server.py')],{**common,
            'GATEWAY_ROLE':'admin','GATEWAY_DATA_DIR':str(ROOT/'admin'),'PORT':'8081',
            'ADMIN_TOKEN':self.admin_token,'HA_BROKER_TOKEN':self.broker_admin,
            'PAGE_CAPABILITY_REGISTRY_FILE':str(admin_capabilities),
            'MACHINE_DIR':str(self.installation.machine_dir)})
        self.start('guest',['python3',str(GATEWAY/'server.py')],{**common,
            'GATEWAY_ROLE':'guest','GATEWAY_DATA_DIR':str(ROOT/'guest'),'PORT':'8082',
            'HA_BROKER_TOKEN':'page-scoped-capabilities-required',
            'ACTIVITY_BROKER_URL':'http://127.0.0.1:8081',
            'VERIFICATION_BROKER_URL':'http://127.0.0.1:8081',
            'NHP_PAGE_CAPABILITIES_FILE':str(capabilities_path)})
        config=f'''pid {ROOT}/tls/nginx.pid;
error_log stderr warn;
events {{ worker_connections 128; }}
http {{
 server_names_hash_bucket_size 256;
 client_body_temp_path {ROOT}/tls/body;
 proxy_temp_path {ROOT}/tls/proxy;
 fastcgi_temp_path {ROOT}/tls/fastcgi;
 uwsgi_temp_path {ROOT}/tls/uwsgi;
 scgi_temp_path {ROOT}/tls/scgi;
 access_log off;
 server {{
  listen 127.0.0.1:8444 ssl default_server;
  ssl_reject_handshake on;
 }}
 server {{
  listen 127.0.0.1:8444 ssl;
  server_name {route['host']};
  ssl_certificate {ROOT}/tls/guest.crt;
  ssl_certificate_key {ROOT}/tls/guest.key;
  ssl_protocols TLSv1.2 TLSv1.3;
  client_max_body_size 32k;
  location / {{ proxy_pass http://127.0.0.1:8082; proxy_set_header Host $http_host; }}
 }}
}}
'''
        atomic(ROOT/'tls/nginx.conf',config);os.chown(ROOT/'tls/nginx.conf',USERS['tls'],GROUP)
        self.start('tls',['nginx','-c',str(ROOT/'tls/nginx.conf'),'-g','daemon off;'],{})
        connector_config=self.installation.connector_config(self.connector_health_password).replace(str(self.installation.root/'frp-ca.crt'),str(ROOT/'connector/frp-ca.crt'))
        configuration=ROOT/'connector/frpc.toml'
        if not configuration.exists() or configuration.read_text()!=connector_config:self.stop('connector')
        for name,value in [('frpc.toml',connector_config),('frp-ca.crt',(self.installation.root/'frp-ca.crt').read_text())]:
            atomic(ROOT/'connector'/name,value);os.chown(ROOT/'connector'/name,USERS['connector'],GROUP)
        # NHP-FRP starts its embedded scoped Agent beside its executable.
        for source in (self.installation.root/'connector-nhp/etc').glob('*.toml'):
            target=ROOT/'connector/etc'/source.name
            atomic(target,source.read_text());os.chown(target,USERS['connector'],GROUP)
        os.chown(ROOT/'connector/etc',USERS['connector'],GROUP)
        marker=ROOT/'connector/binary.sha256'
        if not marker.exists() or marker.read_text()!=self.frpc_digest:
            self.stop('connector')
            shutil.copyfile('/opt/frpc',ROOT/'connector/frpc.new')
            os.chmod(ROOT/'connector/frpc.new',0o700);os.chown(ROOT/'connector/frpc.new',USERS['connector'],GROUP)
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
        self.last_error=None
        self.message='Ready to create pages and test guest invitations.'
        return True

    def loop(self):
        while not self.stopping:
            with self.lock:
                if (self.installation.root/'binding.json').exists():
                    try:self.prepare()
                    except Exception as error:
                        self.stop('connector')
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
                if DEMO_DATA:
                    markup=markup.replace('<form>', '<p><strong>NHP test: demo data only.</strong> This app does not access Home Assistant devices. Demo actions reset when the app restarts.</p><form>')
                self.send(200,markup.encode(),'text/html; charset=utf-8');return
            target='/admin' if path=='/' else self.path
            connection=http.client.HTTPConnection('127.0.0.1',8081,timeout=40)
            try:
                headers={'X-Admin-Token':runtime.admin_token,'Content-Type':self.headers.get('Content-Type','application/json')}
                connection.request(self.command,target,body,headers)
                response=connection.getresponse();payload=response.read(2*1024*1024)
                kind=response.getheader('Content-Type','application/json')
                if 'text/html' in kind:
                    payload=payload.replace(b'</head>',f'<meta name="access-pages-csrf" content="{runtime.csrf}"></head>'.encode())
                    if DEMO_DATA:
                        payload=payload.replace(b'<body>', b'<body><p role="note" style="padding:12px;text-align:center">NHP test: demo data only. No Home Assistant device access. Demo actions reset when the app restarts.</p>')
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
