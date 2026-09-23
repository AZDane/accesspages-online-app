"""Certificate-wait reporting and the actual unprivileged Nginx startup path.

Set GATEWAY_TLS_INTEGRATION=1 inside the disposable package container to run
the real TLS check. It needs no network beyond container loopback or live keys.
"""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

import runtime


def pending_runtime(root):
    for name in ('admin/installation', 'tls', 'public', 'guest', 'broker'):
        (root / name).mkdir(parents=True, exist_ok=True)
    installation = root / 'admin/installation'
    (installation / 'connector.json').write_text('{}')
    (installation / 'binding.json').write_text('{"synthetic_secret":"do-not-render"}')
    (installation / 'profile.json').write_text('{"landing_origin":"https://access.example.test"}')
    (installation / 'handoff-public-key').write_text('synthetic-public-key')
    instance = runtime.Runtime.__new__(runtime.Runtime)
    instance.installation = Mock(root=installation)
    instance.installation.recover_binding.return_value = {
        'route': {'host': 'gateway.example.test', 'port': 20001}}
    instance.installation.ensure_certificate.return_value = False
    instance.ha_ready = True
    instance.ha_reason = ''
    instance.device_mode = 'homeassistant'
    instance.last_authority = instance.last_connector_status = time.monotonic()
    instance.last_certificate = 0
    instance.children = {}
    instance.started = {}
    instance.product = {}
    instance.broker_unused = 'synthetic-unused'
    instance.broker_admin = 'synthetic-broker'
    instance.admin_token = 'synthetic-admin'
    return instance


class CertificateSetupTests(unittest.TestCase):
    def test_pending_certificate_explains_wait_without_starting_or_reenrolling(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            instance = pending_runtime(root)
            before = (instance.installation.root / 'binding.json').read_bytes()
            with patch.object(runtime, 'ROOT', root), patch.object(instance, 'start') as start:
                for _ in range(3):
                    self.assertFalse(instance.prepare())
                    status = instance.public_status()
                    self.assertTrue(status['enrolled'])
                    self.assertFalse(status['ready'])
                    self.assertFalse(status['admin_ready'])
                    self.assertIn('certificate setup', status['message'])
                    self.assertIn('couple of minutes', status['message'])
                    self.assertIn('continue automatically', status['message'])
                    self.assertNotIn('do-not-render', json.dumps(status))
                start.assert_not_called()
            instance.installation.enroll.assert_not_called()
            self.assertEqual((instance.installation.root / 'binding.json').read_bytes(), before)

    @unittest.skipUnless(os.getenv('GATEWAY_TLS_INTEGRATION') == '1',
                         'Run inside the built package with GATEWAY_TLS_INTEGRATION=1')
    def test_real_tls_startup_uses_stderr_and_preserves_uid_and_log_policy(self):
        class StopAfterTLS(Exception):
            pass

        class Backend(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'ok')

            def log_message(self, *_):
                pass

        self.assertEqual(os.geteuid(), 0, 'Integration fixture requires container root')
        server = ThreadingHTTPServer(('127.0.0.1', 8082), Backend)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                root.chmod(0o755)
                instance = pending_runtime(root)
                installation = instance.installation.root
                subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                                '-days', '1', '-subj', '/CN=gateway.example.test',
                                '-addext', 'subjectAltName=DNS:gateway.example.test',
                                '-keyout', str(installation / 'guest.key'),
                                '-out', str(installation / 'guest.crt')],
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                os.chown(root / 'tls', runtime.USERS['tls'], runtime.GROUP)
                instance.installation.ensure_certificate.return_value = True
                started = []
                real_popen = subprocess.Popen

                def capture_process(*args, **kwargs):
                    return real_popen(*args, **kwargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                def start(role, command, env):
                    started.append(role)
                    if role == 'tls':
                        runtime.Runtime.start(instance, role, command, env)
                        raise StopAfterTLS()

                with patch.object(runtime, 'ROOT', root), \
                     patch.dict(os.environ, {'HA_TOKEN': 'synthetic-test-token', 'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'}, clear=True), \
                     patch.object(instance, 'start', side_effect=start), \
                     patch.object(runtime.subprocess, 'Popen', side_effect=capture_process):
                    with self.assertRaises(StopAfterTLS):
                        instance.prepare()
                process = instance.children['tls']
                try:
                    context = ssl.create_default_context(cafile=str(installation / 'guest.crt'))
                    for attempt in range(50):
                        self.assertIsNone(process.poll(), 'Nginx exited during startup')
                        try:
                            connection = context.wrap_socket(
                                socket.create_connection(('127.0.0.1', 8444), timeout=1),
                                server_hostname='gateway.example.test')
                            break
                        except ConnectionRefusedError:
                            time.sleep(0.05)
                    else:
                        self.fail('Nginx did not listen')
                    connection.sendall(b'GET /health?privacy-canary HTTP/1.1\r\nHost: gateway.example.test\r\nConnection: close\r\n\r\n')
                    response = http.client.HTTPResponse(connection)
                    response.begin()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.read(), b'ok')
                    connection.close()
                    uid_line = next(line for line in Path('/proc', str(process.pid), 'status').read_text().splitlines() if line.startswith('Uid:'))
                    self.assertEqual(set(uid_line.split()[1:]), {str(runtime.USERS['tls'])})
                    config = (root / 'tls/nginx.conf').read_text()
                    self.assertIn('error_log stderr warn;', config)
                    self.assertIn('access_log off;', config)
                    self.assertNotIn('debug', config)
                finally:
                    process.terminate()
                    stdout, stderr = process.communicate(timeout=10)
                self.assertNotIn(b'could not open error log file', stderr)
                self.assertNotIn(b'privacy-canary', stdout + stderr)
                self.assertEqual(started, ['broker', 'admin', 'guest', 'tls'])
        finally:
            server.shutdown()
            server.server_close()


if __name__ == '__main__':
    unittest.main()
