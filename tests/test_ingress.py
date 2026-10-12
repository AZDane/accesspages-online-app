"""Owner flow and hostile HTTP inputs through the real Ingress handler."""
import http.client
import json
import os
import socket
import threading
import unittest
from unittest.mock import Mock, patch

import ingress
from ingress_control import ControlError
import runtime


class IngressTests(unittest.TestCase):
    def setUp(self):
        with patch.dict(os.environ, {'ADMIN_TOKEN': 'synthetic-admin',
                'NHP_ADMIN_PROXY_IPS': '127.0.0.1', 'NHP_SERVER_ADDRESS': 'nhp.example.test:62206',
                'INGRESS_CONTROL_SOCKET': '/unused/control.sock'}):
            self.server = ingress.IngressServer(('127.0.0.1', 0))
        self.state = {'enrolled': False, 'ready': False, 'admin_ready': False, 'message': 'waiting'}
        self.server.control = Mock(side_effect=lambda op, **fields:
            self.state if op == 'status' else {'enrolled': True})
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.addCleanup(self.close)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)

    def call(self, path='/', method='GET', body=None, headers=None):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=3)
        try:
            connection.request(method, path, body, headers or {})
            response = connection.getresponse()
            return response.status, response.read(), response.headers
        finally:
            connection.close()

    def raw(self, request):
        with socket.create_connection(self.server.server_address, timeout=3) as client:
            client.sendall(request)
            client.shutdown(socket.SHUT_WR)
            response = http.client.HTTPResponse(client)
            response.begin()
            return response.status, response.read()

    def test_fresh_enrollment_saved_wait_and_offline_admin_transition(self):
        status, body, headers = self.call()
        self.assertEqual(status, 200)
        self.assertIn(self.server.csrf.encode(), body)
        self.assertIn(b'nhp.example.test:62206', body)
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertEqual(self.call('/setup/enroll', 'POST', '{"enrollment_token":"  ' + 'A'*43 + '  "}',
            {'X-Access-Pages-CSRF': self.server.csrf})[0], 200)
        self.server.control.assert_called_with('enroll', token='A'*43)
        self.state['enrolled'] = True
        self.assertIn(b'Your enrollment is saved', self.call()[1])
        self.assertNotIn(b'<form', self.call()[1])
        self.assertEqual(self.call('/api/admin/pages')[0], 503)
        self.state['admin_ready'] = True  # Remote transport remains unavailable.
        actual_connection = http.client.HTTPConnection
        backend = Mock()
        backend.getresponse.return_value = Mock(status=200)
        backend.getresponse.return_value.read.return_value = b'<head></head><body>Admin</body>'
        backend.getresponse.return_value.getheader.return_value = 'text/html'
        def connect(host, port, **options):
            return backend if (host, port) == ('127.0.0.1', 8081) else actual_connection(host, port, **options)
        with patch.object(ingress.http.client, 'HTTPConnection', side_effect=connect):
            status, body, _ = self.call(headers={'Host': 'attacker.invalid', 'X-Admin-Token': 'forged',
                'Authorization': 'Bearer forged', 'Cookie': 'forged', 'X-Forwarded-For': '192.0.2.1'})
        self.assertEqual(status, 200)
        self.assertIn(b'access-pages-csrf', body)
        backend.request.assert_called_once_with('GET', '/admin', b'',
            {'X-Admin-Token': 'synthetic-admin', 'Content-Type': 'application/json'})
        backend.close.assert_called_once()

    def test_authorization_uses_actual_peer_and_current_csrf(self):
        for path in ('/setup/enroll', '/setup/repair', '/api/admin/pages'):
            for csrf in ('', 'old-csrf'):
                self.assertEqual(self.call(path, 'POST', '{}', {'X-Access-Pages-CSRF': csrf})[0], 403)
        self.server.allowed_proxies = {'192.0.2.1'}
        for host in ('127.0.0.1', 'attacker.invalid', '[::1]'):
            self.assertEqual(self.call(headers={'Host': host, 'X-Forwarded-For': '192.0.2.1',
                'X-Ingress-Path': '/', 'X-Access-Pages-CSRF': self.server.csrf})[0], 403)
        self.server.control.assert_not_called()

    def test_repair_screen_requires_exact_confirmed_post_and_does_not_expose_data(self):
        self.state.update(enrolled=True, repair='required')
        status, body, _ = self.call()
        self.assertEqual(status, 200)
        self.assertIn(b'Repair older guest access', body)
        self.assertIn(self.server.csrf.encode(), body)
        self.assertNotIn(self.server.admin_token.encode(), body)
        self.assertEqual(self.call('/api/admin/pages')[0], 503)
        for payload in ('{}', '{"confirm":false}', '{"confirm":1}', '{"confirm":true,"path":"/data"}'):
            self.assertEqual(self.call('/setup/repair', 'POST', payload, {'X-Access-Pages-CSRF': self.server.csrf})[0], 400)
        self.assertEqual(self.call('/setup/repair', 'POST', '{"confirm":true}', {'X-Access-Pages-CSRF': self.server.csrf})[0], 200)
        self.server.control.assert_called_with('repair_legacy_guests', confirm=True)

    def test_bad_framing_and_targets_do_not_reach_control_or_admin(self):
        for target in (b'http://attacker.invalid/', b'//attacker.invalid/', b'/#fragment'):
            self.assertEqual(self.raw(b'GET '+target+b' HTTP/1.1\r\nHost: test\r\n\r\n')[0], 400)
        for headers, body in [(b'Content-Length: 1\r\nContent-Length: 1', b'a'),
                              (b'Transfer-Encoding: chunked', b'0\r\n\r\n'),
                              (b'Content-Length: 512001', b''),
                              (b'Content-Length: -1', b''),
                              (b'Content-Length: 3', b'a')]:
            self.assertEqual(self.raw(b'GET / HTTP/1.1\r\nHost: test\r\n'+headers+b'\r\n\r\n'+body)[0], 400)
        self.assertEqual(self.raw(b'CONNECT attacker.invalid:443 HTTP/1.1\r\nHost: test\r\n\r\n')[0], 501)
        self.assertEqual(self.raw(b'GET / HTTP/1.1\r\nX: '+b'a'*65536+b'\r\n\r\n')[0], 431)
        self.server.control.assert_not_called()

    def test_control_unavailable_fails_closed_and_status_recovers(self):
        self.server.control.side_effect = ControlError()
        for path in ('/', '/api/admin/pages', '/setup/status'):
            self.assertEqual(self.call(path)[0], 503)
        self.server.control.side_effect = None
        self.server.control.return_value = self.state
        self.assertEqual(json.loads(self.call('/setup/status')[1]), self.state)

    def test_concurrency_warning_preserves_disconnect_and_recovery(self):
        for _ in range(self.server.max_clients):
            self.assertTrue(self.server.slots.acquire(blocking=False))
        try:
            with self.assertLogs('accesspages.ingress', level='WARNING') as logs:
                for _ in range(2):
                    with self.assertRaises((http.client.RemoteDisconnected, ConnectionResetError)):
                        self.call('/setup/status?token=private-token', headers={'Cookie': 'private-cookie'})
            self.assertEqual([r.getMessage() for r in logs.records],
                ['ingress_http_concurrency_limit limit=16 events_total=1'])
            self.server.control.assert_not_called()
        finally:
            for _ in range(self.server.max_clients):
                self.server.slots.release()
        self.assertEqual(self.call('/setup/status')[0], 200)

    def test_size_warnings_are_bounded_and_contain_no_request_or_response_data(self):
        self.state['admin_ready'] = True
        actual_connection = http.client.HTTPConnection
        backend = Mock()
        backend.getresponse.return_value = Mock(status=200)
        backend.getresponse.return_value.read.return_value = b'private-response' + b'x'*ingress.MAX_RESPONSE_BYTES
        def connect(host, port, **options):
            return backend if (host, port) == ('127.0.0.1', 8081) else actual_connection(host, port, **options)
        with self.assertLogs('accesspages.ingress', level='WARNING') as logs:
            for _ in range(2):
                self.assertEqual(self.raw(b'GET /private-page?token=private-token HTTP/1.1\r\n'
                    b'Host: private-host\r\nCookie: private-cookie\r\n'
                    b'Content-Length: 512001\r\n\r\nprivate-body')[0], 400)
            self.server.control.assert_not_called()
            with patch.object(ingress.http.client, 'HTTPConnection', side_effect=connect):
                for _ in range(2):
                    self.assertEqual(self.call('/private-page?token=private-token')[0], 400)
        self.assertEqual([r.getMessage() for r in logs.records], [
            'ingress_request_bytes_limit limit=512000 events_total=1',
            'ingress_response_bytes_limit limit=2097152 events_total=1'])
        self.assertEqual(backend.close.call_count, 2)
        self.state['admin_ready'] = False
        self.assertEqual(self.call('/setup/status')[0], 200)

    def test_local_admin_readiness_is_independent_of_the_remote_tunnel(self):
        instance = runtime.Runtime.__new__(runtime.Runtime)
        instance.children = {role: Mock(poll=Mock(return_value=None)) for role in ('admin', 'broker')}
        with patch.object(runtime.socket, 'create_connection') as connect:
            self.assertTrue(instance.admin_ready())
            self.assertEqual([call.args[0] for call in connect.call_args_list],
                             [('127.0.0.1', 8081), ('127.0.0.1', 8083)])
        instance.children['admin'].poll.return_value = 1
        self.assertFalse(instance.admin_ready())


if __name__ == '__main__':
    unittest.main()
