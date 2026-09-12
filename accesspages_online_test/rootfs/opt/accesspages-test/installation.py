"""Customer-owned enrollment and native OpenNHP operation client."""
import base64
import json
import os
from pathlib import Path
import ssl
import subprocess
from urllib.parse import urlparse
from urllib.request import build_opener, HTTPSHandler, HTTPRedirectHandler

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Unexpected profile redirect')


def atomic(path, value, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists() and path.read_text()==value:
        path.chmod(mode)
        return
    temporary = path.with_name(path.name+'.pending')
    with temporary.open('w') as output:
        os.chmod(temporary, mode)
        output.write(value)
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)


class Installation:
    def __init__(self, root, service_url=None):
        self.root = Path(root)
        self.machine_dir = self.root/'machine'
        self.service_url = (service_url or os.getenv('NHP_SERVICE_URL', 'https://access.beta.accesspages.app')).rstrip('/')
        parsed=urlparse(self.service_url)
        if (parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or
            parsed.path or parsed.params or parsed.query or parsed.fragment or
            any(character.isspace() for character in self.service_url)):
            raise ValueError('Service address must be an HTTPS origin')
        if parsed.port is not None and not 1<=parsed.port<=65535:
            raise ValueError('Invalid service port')
        # Never send an enrolled identity to a newly configured authority.
        binding_path=self.root/'binding.json'
        if binding_path.exists():
            binding=json.loads(binding_path.read_text())
            saved=binding.get('service_url')
            if saved is None and (self.root/'profile.json').exists():
                saved=json.loads((self.root/'profile.json').read_text()).get('landing_origin')
            if saved!=self.service_url:
                raise ValueError('Service address does not match this enrolled installation')
        self.context = ssl.create_default_context(cafile=os.getenv('NHP_SERVICE_CA_FILE') or None)

    def operation(self, body, *, connector=False):
        result = subprocess.run(['/opt/machinectl'], input=json.dumps(body),
                                text=True, capture_output=True, timeout=35,
                                env={**os.environ, 'MACHINE_DIR':str(self.root/'connector-nhp' if connector else self.machine_dir)})
        if result.returncode:
            raise RuntimeError('OpenNHP operation denied or unavailable')
        value = json.loads(result.stdout)
        if not isinstance(value, dict):
            raise RuntimeError('Invalid OpenNHP response')
        return value

    def profile(self):
        opener = build_opener(HTTPSHandler(context=self.context), NoRedirect())
        with opener.open(self.service_url+'/installation.json', timeout=10) as response:
            if response.geturl() != self.service_url+'/installation.json':
                raise ValueError('Unexpected profile redirect')
            raw = response.read(16385)
        if len(raw)>16384:
            raise ValueError('Invalid installation profile')
        profile=json.loads(raw)
        if profile.get('version')!=1 or profile.get('landing_origin')!=self.service_url or profile.get('server_port')!=62206:
            raise ValueError('Unsupported installation service')
        for field in ('server_public_key','handoff_public_key'):
            if len(base64.b64decode(profile[field],validate=True))!=32:
                raise ValueError('Invalid service public key')
        for field in ('control_certificate','frp_certificate'):
            x509.load_pem_x509_certificate(profile[field].encode())
        if not isinstance(profile.get('server_host'),str) or len(profile['server_host'])>253:
            raise ValueError('Invalid NHP Server address')
        return profile

    def refresh_authority(self):
        """Refresh public verification material through the trusted HTTPS origin."""
        profile=self.profile()
        for target,value,mode in (
            (self.machine_dir/'control.crt',profile['control_certificate'],0o644),
            (self.root/'frp-ca.crt',profile['frp_certificate'],0o644),
            (self.root/'handoff-public-key',profile['handoff_public_key'],0o644),
            (self.root/'profile.json',json.dumps(profile),0o644)):
            if not target.exists() or target.read_text()!=value:atomic(target,value,mode)
        # Preserve config.toml's inode: it is also the native operation lock.
        server=f'[[Servers]]\nName = "authority"\nPubKeyBase64 = {json.dumps(profile["server_public_key"])}\nExpireTime = 1924991999\n[[Servers.Instances]]\nHost = {json.dumps(profile["server_host"])}\nPort = 62206\n'
        for directory in (self.machine_dir,self.root/'connector-nhp'):
            if directory.exists():
                target=directory/'etc/server.toml'
                if not target.exists() or target.read_text()!=server:atomic(target,server)
        return profile

    def refresh_connector(self):
        binding_path=self.root/'binding.json'
        binding=json.loads(binding_path.read_text())
        route=self.operation({'op':'installation_status'})
        if route.get('gateway_id')!=binding['gateway_id']:raise ValueError('Gateway identity mismatch')
        previous=json.loads((self.root/'connector.json').read_text())
        if route['epoch']!=previous['route']['epoch']:
            # Management status only succeeds after an operator has reconciled
            # this Gateway. Old connector credentials never survive its epoch.
            self.refresh_authority()
            binding['route']=route;atomic(binding_path,json.dumps(binding))
            return self.ensure_connector()
        key=x25519.X25519PrivateKey.from_private_bytes(base64.b64decode((self.root/'connector-nhp/private-key').read_text()))
        public=base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode()
        connector=self.operation({'op':'connector_status','connector_public_key':public})
        if connector!=previous:atomic(self.root/'connector.json',json.dumps(connector))
        if binding.get('route')!=route:
            binding['route']=route;atomic(binding_path,json.dumps(binding))
        return connector

    def enroll(self, credential):
        if not isinstance(credential,str):raise ValueError('Invalid enrollment token')
        credential=credential.strip()
        valid=lambda s:all(c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in s)
        if len(credential)!=43 or not valid(credential):
            raise ValueError('Invalid enrollment token')
        gid,bootstrap=None,credential
        binding_path=self.root/'binding.json'
        if binding_path.exists():
            previous=json.loads(binding_path.read_text())
            if gid is not None and previous['gateway_id'] is not None and previous['gateway_id']!=gid:
                raise ValueError('This app already belongs to another installation')
            gid=previous['gateway_id'] or gid
            if previous.get('state')=='enrolled':
                try:route=self.operation({'op':'installation_status'})
                except RuntimeError:
                    # The owner may be presenting a new one-use bootstrap
                    # after an explicit operator reset of this same Gateway.
                    # REG still must authorize it; failure never changes trust.
                    pass
                else:
                    if route.get('gateway_id')!=gid:raise ValueError('Gateway identity mismatch')
                    if not (self.root/'connector.json').exists():self.ensure_connector()
                    return route
        profile=self.profile()
        key_path=self.machine_dir/'private-key'
        if not key_path.exists():
            key=x25519.X25519PrivateKey.generate()
            atomic(key_path,base64.b64encode(key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())).decode())
        private=key_path.read_text().strip()
        atomic(self.machine_dir/'etc/config.toml',f'PrivateKeyBase64 = "{private}"\nDefaultCipherScheme = 0\nUserId = "machine"\nLogLevel = 0\n')
        atomic(self.machine_dir/'etc/server.toml',f'''[[Servers]]
Name = "authority"
PubKeyBase64 = {json.dumps(profile['server_public_key'])}
ExpireTime = 1924991999
[[Servers.Instances]]
Host = {json.dumps(profile['server_host'])}
Port = 62206
''')
        atomic(self.machine_dir/'etc/resource.toml',''.join(f'[[Resources]]\nAuthServiceId = "guest"\nResourceId = "{r}"\nCluster = "authority"\n' for r in ('gateway-mint','frp-connector')))
        atomic(self.machine_dir/'etc/dhp.toml','')
        atomic(self.machine_dir/'control.crt',profile['control_certificate'],0o644)
        atomic(self.root/'frp-ca.crt',profile['frp_certificate'],0o644)
        atomic(self.root/'handoff-public-key',profile['handoff_public_key'],0o644)
        atomic(self.root/'profile.json',json.dumps(profile),0o644)
        # Persist the intended binding before REG. After a lost RAK/restart,
        # authenticated status proves successful prior enrollment without reuse.
        atomic(binding_path,json.dumps({'gateway_id':gid,'state':'enrolling','bootstrap':bootstrap,'service_url':self.service_url}))
        try:
            route=self.operation({'op':'installation_status'})
        except RuntimeError:
            self.operation({'op':'bind','gateway_id':gid or 'gateway-registration','bootstrap':bootstrap})
            route=self.operation({'op':'installation_status'})
        actual=route.get('gateway_id','')
        if not actual.startswith('gw_') or len(actual)!=46 or not valid(actual) or (gid is not None and actual!=gid):
            raise ValueError('Gateway identity mismatch')
        atomic(binding_path,json.dumps({'gateway_id':actual,'state':'enrolled','route':route,'service_url':self.service_url}))
        self.ensure_connector()
        return route

    def recover_binding(self):
        path=self.root/'binding.json'
        binding=json.loads(path.read_text())
        if binding.get('state')=='enrolled':return binding
        try:
            route=self.operation({'op':'installation_status'})
        except RuntimeError:
            self.operation({'op':'bind','gateway_id':binding['gateway_id'] or 'gateway-registration','bootstrap':binding['bootstrap']})
            route=self.operation({'op':'installation_status'})
        actual=route.get('gateway_id','')
        if not actual.startswith('gw_') or len(actual)!=46 or (binding['gateway_id'] is not None and actual!=binding['gateway_id']):
            raise ValueError('Gateway identity mismatch')
        binding={'gateway_id':actual,'state':'enrolled','route':route,'service_url':self.service_url}
        atomic(path,json.dumps(binding))
        return binding

    def ensure_connector(self):
        gid=json.loads((self.root/'binding.json').read_text())['gateway_id']
        connector_dir=self.root/'connector-nhp'
        connector_key=connector_dir/'private-key'
        if not connector_key.exists():
            key=x25519.X25519PrivateKey.generate()
            atomic(connector_key,base64.b64encode(key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())).decode())
        key=x25519.X25519PrivateKey.from_private_bytes(base64.b64decode(connector_key.read_text()))
        public=base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode()
        atomic(connector_dir/'etc/config.toml',f'PrivateKeyBase64 = "{connector_key.read_text().strip()}"\nDefaultCipherScheme = 0\nUserId = "connector"\nLogLevel = 0\n')
        atomic(connector_dir/'etc/server.toml',(self.machine_dir/'etc/server.toml').read_text())
        atomic(connector_dir/'etc/resource.toml','[[Resources]]\nAuthServiceId = "guest"\nResourceId = "frp-connector"\nCluster = "authority"\n')
        atomic(connector_dir/'etc/dhp.toml','')
        connector=self.operation({'op':'register_connector','connector_public_key':public})
        if connector.get('connector_bootstrap'):
            self.operation({'op':'bind','gateway_id':gid+':connector','bootstrap':connector['connector_bootstrap'],'nhp_resource':'frp-connector'},connector=True)
        connector.pop('connector_bootstrap',None)
        atomic(self.root/'connector.json',json.dumps(connector))
        return connector

    def ensure_certificate(self):
        binding=json.loads((self.root/'binding.json').read_text())
        host=binding['route']['host']
        key_path=self.root/'guest.key'
        if not key_path.exists():
            key=ec.generate_private_key(ec.SECP256R1())
            atomic(key_path,key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode())
        key=serialization.load_pem_private_key(key_path.read_bytes(),password=None)
        csr_path=self.root/'guest.csr'
        if not csr_path.exists():
            csr=x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).add_extension(
                x509.SubjectAlternativeName([x509.DNSName('*.'+host.split('.',1)[1])]),critical=False).sign(key,hashes.SHA256())
            atomic(csr_path,csr.public_bytes(serialization.Encoding.PEM).decode())
        result=self.operation({'op':'request_certificate','csr':csr_path.read_text()})
        if result.get('pending'):
            return False
        certificate=result.get('certificate','')
        leaf=x509.load_pem_x509_certificate(certificate.encode())
        public=lambda key:key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        if public(leaf.public_key())!=public(key.public_key()) or leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)!=['*.'+host.split('.',1)[1]]:
            raise ValueError('Certificate does not belong to this Gateway')
        # Verify the delivered certificate chain with trusted roots before use.
        candidate=self.root/'certificate-candidate.crt';atomic(candidate,certificate,0o644)
        ca=os.getenv('NHP_SERVICE_CA_FILE') or '/etc/ssl/certs/ca-certificates.crt'
        verify=subprocess.run(['openssl','verify','-CAfile',ca,'-untrusted',str(candidate),str(candidate)],capture_output=True)
        if verify.returncode:
            raise ValueError('Untrusted Gateway certificate chain')
        atomic(self.root/'guest.crt',certificate,0o644)
        candidate.unlink()
        return True

    def connector_config(self,health_password=None):
        value=json.loads((self.root/'connector.json').read_text())
        route=value['route']
        health='' if health_password is None else f'webServer.addr = "127.0.0.1"\nwebServer.port = 8084\nwebServer.user = "runtime"\nwebServer.password = {json.dumps(health_password)}\n'
        return health+f'''serverAddr = {json.dumps(value['connector_host'])}
serverPort = {value['connector_port']}
loginFailExit = false
auth.method = "token"
auth.token = {json.dumps(value['connector_token'])}
auth.additionalScopes = ["HeartBeats", "NewWorkConns"]
transport.tls.enable = true
transport.tls.trustedCaFile = {json.dumps(str(self.root/'frp-ca.crt'))}
transport.tls.serverName = "frp-service"
transport.heartbeatInterval = 10
transport.heartbeatTimeout = 30
log.level = "warn"
[[proxies]]
name = "guest"
type = "tcp"
localIP = "127.0.0.1"
localPort = 8444
remotePort = {route['port']}
'''
