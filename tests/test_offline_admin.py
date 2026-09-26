"""Owner controls stay available through trusted Ingress during tunnel outages."""
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

import runtime


class OfflineAdminTests(unittest.TestCase):
    def test_admin_readiness_does_not_require_remote_tunnel(self):
        instance=runtime.Runtime.__new__(runtime.Runtime)
        instance.children={name:Mock(poll=Mock(return_value=None)) for name in ('admin','broker')}
        instance.connector_ready=Mock(side_effect=AssertionError('Remote tunnel must not gate local owner controls'))
        with patch.object(runtime.socket,'create_connection') as connect:
            self.assertTrue(instance.admin_ready())
            self.assertEqual([call.args[0] for call in connect.call_args_list],[('127.0.0.1',8081),('127.0.0.1',8083)])
        instance.children['admin'].poll.return_value=1
        self.assertFalse(instance.admin_ready())

    def test_offline_owner_can_load_admin_and_guest_list(self):
        for path,target in [('/','/admin'),('/api/admin/pages','/api/admin/pages')]:
            with self.subTest(path=path):
                handler=self.handler(path,True)
                response=Mock(status=200)
                response.read.return_value=b'{"pages":[]}'
                response.getheader.return_value='application/json'
                connection=Mock();connection.getresponse.return_value=response
                with patch.object(runtime.http.client,'HTTPConnection',return_value=connection):
                    handler.handle_request()
                connection.request.assert_called_once_with('GET',target,b'',{'X-Admin-Token':'synthetic-admin','Content-Type':'application/json'})
                self.assertEqual(handler.sent[0][0],200)
                connection.close.assert_called_once()

    def test_unready_local_admin_still_returns_setup_or_503(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory,'setup.html').write_text('<html>SETUP_CSRF</html>')
            for path,expected in [('/',200),('/api/admin/pages',503)]:
                handler=self.handler(path,False)
                with patch.object(runtime,'APP',Path(directory)),patch.object(runtime.http.client,'HTTPConnection') as connect:
                    handler.handle_request()
                self.assertEqual(handler.sent[0][0],expected)
                connect.assert_not_called()

    def test_untrusted_source_cannot_use_offline_admin(self):
        handler=self.handler('/',True);handler.client_address=('192.0.2.50',9999)
        with patch.object(runtime.http.client,'HTTPConnection') as connect:handler.handle_request()
        self.assertEqual(handler.sent[0][0],403);connect.assert_not_called()

    def test_enrollment_requires_trusted_ingress_and_csrf(self):
        for source, csrf, status in [('127.0.0.1', 'synthetic-csrf', 200),
                                     ('127.0.0.1', '', 403),
                                     ('192.0.2.50', 'synthetic-csrf', 403)]:
            with self.subTest(source=source, csrf=csrf):
                handler = self.handler('/setup/enroll', False)
                body = json.dumps({'enrollment_token': 'synthetic-token'}).encode()
                handler.command = 'POST'
                handler.client_address = (source, 1234)
                handler.headers = {'Content-Length': str(len(body)), 'X-Access-Pages-CSRF': csrf}
                handler.rfile = io.BytesIO(body)
                handler.runtime.enroll = Mock(return_value={'enrolled': True})
                handler.handle_request()
                self.assertEqual(handler.sent[0][0], status)
                if status == 200:
                    handler.runtime.enroll.assert_called_once_with('synthetic-token')
                else:
                    handler.runtime.enroll.assert_not_called()

    def test_enrolled_restart_does_not_ask_for_another_token(self):
        handler=self.handler('/',False)
        handler.runtime.public_status=lambda:{'ready':False,'enrolled':True}
        packaged=Path(runtime.__file__).parent
        with patch.object(runtime,'APP',packaged),patch.object(runtime.http.client,'HTTPConnection') as connect:
            handler.handle_request()
        status,body,kind=handler.sent[0]
        self.assertEqual((status,kind),(200,'text/html; charset=utf-8'))
        self.assertIn(b'Your enrollment is saved',body)
        self.assertNotIn(b'<form',body)
        self.assertNotIn(b'enrollment_token',body)
        connect.assert_not_called()

    @staticmethod
    def handler(path,ready):
        handler=runtime.Ingress.__new__(runtime.Ingress)
        handler.path=path;handler.command='GET';handler.headers={};handler.rfile=io.BytesIO()
        handler.client_address=('127.0.0.1',1234)
        handler.runtime=SimpleNamespace(allowed_proxies={'127.0.0.1'},csrf='synthetic-csrf',admin_token='synthetic-admin',
            admin_ready=lambda:ready,public_status=lambda:{'ready':False},installation=SimpleNamespace(server_address='nhp.example.test:62206'))
        handler.sent=[];handler.send=lambda *args:handler.sent.append(args)
        return handler


if __name__=='__main__':unittest.main()
