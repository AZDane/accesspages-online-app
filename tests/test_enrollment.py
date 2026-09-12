"""Enrollment contracts exercised inside the packaged app, without networking."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from installation import Installation, atomic
import nhp
import runtime

SERVICE = 'https://service.example.test'
TOKEN = 'A' * 43
GATEWAY = 'gw_' + 'B' * 43

class FakeInstallation(Installation):
    def __init__(self, root):
        super().__init__(root, SERVICE)
        self.bound = False
        self.lost_ack = False
        self.calls = []
    def profile(self):
        return {'server_public_key': 'C' * 44, 'server_host': 'nhp.example.test',
                'control_certificate': 'test', 'frp_certificate': 'test',
                'handoff_public_key': 'test', 'landing_origin': SERVICE}
    def operation(self, body, **kwargs):
        self.calls.append(body)
        if body['op'] == 'bind':
            if body['bootstrap'] != TOKEN: raise RuntimeError('denied')
            self.bound = True
            if self.lost_ack: raise RuntimeError('lost acknowledgment')
            return {'ok': True}
        if not self.bound: raise RuntimeError('not enrolled')
        return {'gateway_id': GATEWAY, 'epoch': 1}
    def ensure_connector(self):
        return None

class EnrollmentTests(unittest.TestCase):
    def test_raw_token_resolves_identity_and_discards_bootstrap(self):
        with tempfile.TemporaryDirectory() as root:
            app = FakeInstallation(root)
            self.assertEqual(app.enroll(TOKEN)['gateway_id'], GATEWAY)
            self.assertEqual([x for x in app.calls if x['op'] == 'bind'],
                             [{'op': 'bind', 'gateway_id': 'gateway-registration', 'bootstrap': TOKEN}])
            state = json.loads((Path(root) / 'binding.json').read_text())
            self.assertNotIn('bootstrap', state)
            self.assertEqual(state['service_url'], SERVICE)
            self.assertEqual(state['gateway_id'], GATEWAY)

    def test_lost_registration_reply_recovers_using_saved_identity(self):
        with tempfile.TemporaryDirectory() as root:
            app = FakeInstallation(root); app.lost_ack = True
            with self.assertRaises(RuntimeError): app.enroll(TOKEN)
            state = app.recover_binding()
            self.assertEqual(state['gateway_id'], GATEWAY)
            self.assertNotIn('bootstrap', state)
            self.assertEqual(sum(x['op'] == 'bind' for x in app.calls), 1)

    def test_service_change_is_rejected_for_old_and_new_bindings(self):
        for saved_url in [True, False]:
            with self.subTest(saved_url=saved_url), tempfile.TemporaryDirectory() as root:
                state = {'gateway_id': GATEWAY, 'state': 'enrolled'}
                if saved_url: state['service_url'] = SERVICE
                atomic(Path(root) / 'binding.json', json.dumps(state))
                atomic(Path(root) / 'profile.json', json.dumps({'landing_origin': SERVICE}))
                Installation(root, SERVICE)
                with self.assertRaises(ValueError): Installation(root, 'https://different.example.test')

    def test_invalid_service_addresses_and_credentials_fail_before_enrollment(self):
        for address in ['http://service.example.test', 'https://user:secret@service.example.test',
                        SERVICE + '/api', SERVICE + '?token=x', SERVICE + '#x', 'https://bad host']:
            with self.subTest(address=address), tempfile.TemporaryDirectory() as root:
                with self.assertRaises(ValueError): Installation(root, address)
        with tempfile.TemporaryDirectory() as root:
            app = FakeInstallation(root)
            for credential in ['', 'short', TOKEN + '!', None, SERVICE + '/enroll#gateway=' + GATEWAY + '&bootstrap=' + TOKEN]:
                with self.assertRaises(ValueError): app.enroll(credential)
            self.assertEqual(app.calls, [])

    def test_service_address_reads_app_configuration(self):
        with tempfile.TemporaryDirectory() as root, patch.object(runtime, 'ROOT', Path(root)), patch.dict(os.environ, {}, clear=True):
            atomic(Path(root) / 'options.json', json.dumps({'service_url': SERVICE}))
            self.assertEqual(runtime.configured_service_url(), SERVICE)
            atomic(Path(root) / 'options.json', json.dumps({'service_url': 1}))
            with self.assertRaises(ValueError): runtime.configured_service_url()

    def test_short_link_mint_and_revocation_retain_local_tracking(self):
        for short in [True]:
            with self.subTest(short=short), tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {'GATEWAY_DATA_DIR': root}), patch.object(nhp, 'INSTALLATION_ROUTING', True):
                link = SERVICE + ('/#' + TOKEN if short else '/#access=' + TOKEN + '&resource=front-door')
                calls = []
                def operation(body):
                    calls.append(body)
                    return {'access_link': link, 'expires': 1900000000}
                with patch.object(nhp, 'machine', side_effect=operation):
                    client = nhp.NHPClient()
                    result = client.create_access_link(target_path='/access/front-door?access_token=' + 'G' * 43, expires_in='1h')
                    self.assertEqual(result['access_link_url'], link)
                    self.assertEqual(result['access_link_id'], hashlib.sha256(TOKEN.encode()).hexdigest())
                    client.delete_access_link(access_link_id=result['access_link_id'])
                    self.assertEqual(calls[-1], {'op': 'revoke_link', 'access': TOKEN})

if __name__ == '__main__': unittest.main(verbosity=2)
