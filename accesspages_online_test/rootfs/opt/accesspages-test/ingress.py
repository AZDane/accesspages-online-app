"""Unprivileged HA Ingress and setup frontend. Admin upstream is fixed locally."""
import html
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import secrets
from socketserver import TCPServer
from urllib.parse import urlsplit

from ingress_control import BoundedThreads, ControlError, INGRESS_UID, LimitWarning, request

APP = Path(__file__).resolve().parent
MAX_REQUEST_BYTES = 512000
MAX_RESPONSE_BYTES = 2*1024*1024


class Ingress(BaseHTTPRequestHandler):
    # One request per connection, bounded workers and an idle read/write timeout.
    timeout = 10

    def log_message(self, *_args):
        pass

    def send(self, status, body, content_type='application/json'):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.send_response(status)
        for key, value in [('Content-Type', content_type), ('Content-Length', str(len(body))),
                           ('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff'),
                           ('Referrer-Policy', 'no-referrer')]:
            self.send_header(key, value)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def handle_request(self):
        if self.client_address[0] not in self.server.allowed_proxies:
            self.send(403, {'error': 'Use Home Assistant Ingress'})
            return
        if self.command not in ('GET', 'HEAD') and self.headers.get('X-Access-Pages-CSRF') != self.server.csrf:
            self.send(403, {'error': 'Reload the local app'})
            return
        try:
            target = urlsplit(self.path)
            if (not self.path.startswith('/') or self.requestline.split()[1].startswith('//') or
                    target.scheme or target.netloc or target.fragment):
                raise ValueError()
            lengths = self.headers.get_all('Content-Length', [])
            if len(lengths) > 1 or 'Transfer-Encoding' in self.headers:
                raise ValueError()
            length = int(lengths[0]) if lengths else 0
            if not 0 <= length <= MAX_REQUEST_BYTES:
                if length > MAX_REQUEST_BYTES:
                    self.server.request_size_warning.report()
                raise ValueError()
            body = self.rfile.read(length) if length else b''
            if len(body) != length:
                raise ValueError()
            path = target.path
            if path == '/setup/status' and self.command in ('GET', 'HEAD'):
                self.send(200, self.server.control('status'))
                return
            if path == '/setup/enroll' and self.command == 'POST':
                value = json.loads(body)
                if (not isinstance(value, dict) or set(value) != {'enrollment_token'} or
                        not isinstance(value['enrollment_token'], str)):
                    raise ValueError()
                self.send(200, self.server.control('enroll', token=value['enrollment_token'].strip()))
                return
            state = self.server.control('status')
            if not state.get('admin_ready'):
                if self.command not in ('GET', 'HEAD') or path.startswith('/api/'):
                    self.send(503, {'error': 'Application is starting'})
                elif state.get('enrolled'):
                    self.send(200, (APP/'waiting.html').read_bytes(), 'text/html; charset=utf-8')
                else:
                    markup = (APP/'setup.html').read_text().replace('SETUP_CSRF', self.server.csrf).replace(
                        'SERVICE_ADDRESS', html.escape(self.server.service_address))
                    self.send(200, markup.encode(), 'text/html; charset=utf-8')
                return
            connection = http.client.HTTPConnection('127.0.0.1', 8081, timeout=130)
            try:
                # No caller-controlled authority, source, cookie or proxy headers.
                headers = {'X-Admin-Token': self.server.admin_token,
                           'Content-Type': self.headers.get('Content-Type', 'application/json')}
                connection.request(self.command, '/admin' if path == '/' else self.path, body, headers)
                response = connection.getresponse()
                payload = response.read(MAX_RESPONSE_BYTES + 1)
                if len(payload) > MAX_RESPONSE_BYTES:
                    self.server.response_size_warning.report()
                    raise ValueError()
                kind = response.getheader('Content-Type', 'application/json')
                if 'text/html' in kind:
                    payload = payload.replace(b'</head>', f'<meta name="access-pages-csrf" content="{self.server.csrf}"></head>'.encode())
                self.send(response.status, payload, kind)
            finally:
                connection.close()
        except ControlError as error:
            self.send(400 if error.code in ('invalid', 'failed') else 503,
                      {'error': 'Setup operation unavailable. Check the enrollment token and service connection.'})
        except (OSError, ValueError, http.client.HTTPException, RecursionError):
            self.send(400, {'error': 'Operation failed. Check the enrollment token and service connection.'})

    do_GET = handle_request
    do_HEAD = handle_request
    do_POST = handle_request
    do_PUT = handle_request
    do_DELETE = handle_request


class IngressServer(BoundedThreads, HTTPServer):
    def __init__(self, address):
        self.allowed_proxies = set(os.environ['NHP_ADMIN_PROXY_IPS'].split(','))
        self.csrf = secrets.token_urlsafe(32)
        self.admin_token = os.environ['ADMIN_TOKEN']
        self.service_address = os.environ['NHP_SERVER_ADDRESS']
        self.control_path = os.environ['INGRESS_CONTROL_SOCKET']
        self.request_size_warning = LimitWarning('ingress_request_bytes_limit', MAX_REQUEST_BYTES)
        self.response_size_warning = LimitWarning('ingress_response_bytes_limit', MAX_RESPONSE_BYTES)
        super().__init__(address, Ingress)

    def server_bind(self):
        # HTTPServer otherwise performs a hostname lookup before listening.
        TCPServer.server_bind(self)
        self.server_name = 'localhost'
        self.server_port = self.server_address[1]

    def control(self, operation, **fields):
        return request(self.control_path, operation, **fields)

    def handle_error(self, request, client_address):
        # Disconnects and malformed input must not log owner request material.
        pass


def main():
    if os.geteuid() != INGRESS_UID or os.getegid() != INGRESS_UID or os.getgroups():
        raise RuntimeError('Ingress requires its dedicated unprivileged identity')
    with IngressServer(('0.0.0.0', 8099)) as server:
        server.serve_forever()


if __name__ == '__main__':
    main()
