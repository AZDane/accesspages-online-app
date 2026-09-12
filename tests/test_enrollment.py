"""Enrollment contracts exercised inside the packaged app, without networking."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import installation
from installation import Installation, atomic
import nhp
import runtime

SERVER = 'nhp.example.test:62206'
LANDING = 'https://access.example.test'
TOKEN = 'A' * 43
GATEWAY = 'gw_' + 'B' * 43

class FakeInstallation(Installation):
    def __init__(self, root):
        super().__init__(root, SERVER)
        self.bound = False
        self.lost_ack = False
        self.calls = []
    def profile(self):
        return {'server_public_key': 'C' * 44, 'server_host': 'nhp.example.test',
                'control_certificate': 'test-control', 'frp_certificate': 'test-frp',
                'handoff_public_key': 'test-handoff', 'landing_origin': LANDING,
                'version': 3, 'server_port': 62206}
    def operation(self, body, **kwargs):
        self.calls.append(body)
        if body['op'] == 'bind':
            if body['bootstrap'] != TOKEN: raise RuntimeError('denied')
            self.bound = True
            if self.lost_ack: raise RuntimeError('lost acknowledgment')
            return {'ok': True}
        if not self.bound: raise RuntimeError('not enrolled')
        return {'gateway_id': GATEWAY, 'epoch': 1, 'host': 'guest.example.test', 'port': 20002}
    def ensure_connector(self):
        return None

class EnrollmentTests(unittest.TestCase):
    def test_packaged_bootstrap_uses_no_network_and_rejects_invalid_settings(self):
        packaged = json.loads(Path(installation.__file__).with_name('bootstrap.json').read_text())
        self.assertEqual(packaged['version'], 3)
        with tempfile.TemporaryDirectory() as root, patch('socket.create_connection', side_effect=AssertionError('No discovery socket')), patch('urllib.request.OpenerDirector.open', side_effect=AssertionError('No HTTP discovery')):
            path = Path(root)/'bootstrap.json'
            with patch.dict(os.environ, {'NHP_BOOTSTRAP_FILE': str(path)}):
                atomic(path, json.dumps(packaged))
                app = Installation(root)
                self.assertEqual(app.profile(), packaged)
                app.refresh_authority()
                self.assertEqual((Path(root)/'machine/control.crt').read_text(), packaged['control_certificate'])
                for changes in [{'version': 1}, {'version': 2}, {'service_origin': LANDING},
                                {'server_port': 443}, {'server_host': 'https://nhp.example.test'},
                                {'landing_origin': LANDING+'/admin'}, {'landing_origin': 'http://access.example.test'},
                                {'server_public_key': 'invalid'}, {'control_certificate': 'invalid'}]:
                    with self.subTest(changes=changes), self.assertRaises((ValueError, TypeError)):
                        atomic(path, json.dumps({**packaged, **changes}))
                        Installation(root)

    def test_native_address_migration_preserves_keys_without_network(self):
        current = FakeInstallation.profile(None)
        for old in [LANDING, 'https://relay.example.test']:
            with self.subTest(old=old), tempfile.TemporaryDirectory() as root:
                state = {'gateway_id': GATEWAY, 'state': 'enrolled', 'service_url': old}
                previous = {**current, 'version': 2, 'service_origin': old}
                atomic(Path(root)/'binding.json', json.dumps(state))
                atomic(Path(root)/'profile.json', json.dumps(previous))
                atomic(Path(root)/'machine/private-key', 'fixture-private-key')
                with patch.object(Installation, 'profile', return_value=current), patch.object(Installation, 'operation', side_effect=AssertionError('No native operation during metadata migration')), patch('socket.create_connection', side_effect=AssertionError('No discovery socket')):
                    Installation(root, SERVER)
                self.assertEqual(json.loads((Path(root)/'binding.json').read_text()),
                                 {'gateway_id': GATEWAY, 'state': 'enrolled', 'server_address': SERVER})
                self.assertEqual((Path(root)/'machine/private-key').read_text(), 'fixture-private-key')

    def test_native_address_migration_rejects_changed_trust_before_writes(self):
        current = FakeInstallation.profile(None)
        for name in ['server_public_key', 'handoff_public_key', 'control_certificate', 'frp_certificate', 'landing_origin']:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as root:
                state = json.dumps({'gateway_id': GATEWAY, 'state': 'enrolled', 'service_url': LANDING})
                previous = json.dumps({**current, 'version': 1})
                atomic(Path(root)/'binding.json', state); atomic(Path(root)/'profile.json', previous)
                with patch.object(Installation, 'profile', return_value={**current, name: 'changed'}), self.assertRaises(ValueError):
                    Installation(root, SERVER)
                self.assertEqual((Path(root)/'binding.json').read_text(), state)
                self.assertEqual((Path(root)/'profile.json').read_text(), previous)

    def test_raw_token_resolves_identity_and_discards_bootstrap(self):
        with tempfile.TemporaryDirectory() as root, patch('urllib.request.OpenerDirector.open', side_effect=AssertionError('No HTTP discovery')):
            app = FakeInstallation(root)
            self.assertEqual(app.enroll(TOKEN)['gateway_id'], GATEWAY)
            self.assertEqual([x for x in app.calls if x['op'] == 'bind'],
                             [{'op': 'bind', 'gateway_id': 'gateway-registration', 'bootstrap': TOKEN}])
            state = json.loads((Path(root)/'binding.json').read_text())
            self.assertNotIn('bootstrap', state)
            self.assertEqual(state['server_address'], SERVER)
            self.assertEqual(state['gateway_id'], GATEWAY)

    def test_lost_registration_reply_recovers_using_saved_identity(self):
        with tempfile.TemporaryDirectory() as root:
            app = FakeInstallation(root); app.lost_ack = True
            with self.assertRaises(RuntimeError): app.enroll(TOKEN)
            state = app.recover_binding()
            self.assertEqual(state['gateway_id'], GATEWAY)
            self.assertNotIn('bootstrap', state)
            self.assertEqual(sum(x['op'] == 'bind' for x in app.calls), 1)

    def test_server_change_is_rejected_for_existing_bindings(self):
        with tempfile.TemporaryDirectory() as root, patch.object(Installation, 'profile', return_value=FakeInstallation.profile(None)):
            state = {'gateway_id': GATEWAY, 'state': 'enrolled', 'server_address': SERVER}
            atomic(Path(root)/'binding.json', json.dumps(state))
            Installation(root, SERVER)
            with self.assertRaises(ValueError): Installation(root, 'different.example.test:62206')
            atomic(Path(root)/'binding.json', json.dumps({**state, 'server_address': 'different.example.test:62206'}))
            with self.assertRaises(ValueError): Installation(root, SERVER)

    def test_invalid_addresses_and_credentials_fail_before_enrollment(self):
        for address in ['http://service.example.test', 'https://relay.beta.accesspages.app',
                        'user:secret@nhp.example.test', SERVER+'/api', SERVER+'?token=x',
                        SERVER+'#x', 'bad host', 'nhp.beta.accesspages.app:443']:
            with self.subTest(address=address), tempfile.TemporaryDirectory() as root:
                with self.assertRaises(ValueError): Installation(root, address)
        with tempfile.TemporaryDirectory() as root:
            app = FakeInstallation(root)
            for credential in ['', 'short', TOKEN+'!', None, LANDING+'/enroll#gateway='+GATEWAY+'&bootstrap='+TOKEN]:
                with self.assertRaises(ValueError): app.enroll(credential)
            self.assertEqual(app.calls, [])

    def test_server_address_reads_app_configuration(self):
        with tempfile.TemporaryDirectory() as root, patch.object(runtime, 'ROOT', Path(root)), patch.dict(os.environ, {}, clear=True):
            atomic(Path(root)/'options.json', json.dumps({'server_address': SERVER}))
            self.assertEqual(runtime.configured_server_address(), SERVER)
            atomic(Path(root)/'options.json', json.dumps({'server_address': 1}))
            with self.assertRaises(ValueError): runtime.configured_server_address()
            # Obsolete HTTP discovery options cannot restore that network path.
            atomic(Path(root)/'options.json', json.dumps({'service_url': 'https://relay.beta.accesspages.app'}))
            self.assertIsNone(runtime.configured_server_address())

    def test_short_link_mint_and_revocation_retain_local_tracking(self):
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {'GATEWAY_DATA_DIR': root}), patch.object(nhp, 'INSTALLATION_ROUTING', True):
            link = LANDING+'/#'+TOKEN
            calls = []
            def operation(body):
                calls.append(body)
                return {'access_link': link, 'expires': 1900000000}
            with patch.object(nhp, 'machine', side_effect=operation):
                client = nhp.NHPClient()
                result = client.create_access_link(target_path='/access/front-door?access_token='+'G'*43, expires_in='1h')
                self.assertEqual(result['access_link_url'], link)
                self.assertEqual(result['access_link_id'], hashlib.sha256(TOKEN.encode()).hexdigest())
                client.delete_access_link(access_link_id=result['access_link_id'])
                self.assertEqual(calls[-1], {'op': 'revoke_link', 'access': TOKEN})

if __name__ == '__main__': unittest.main(verbosity=2)
