"""Home Assistant credentials remain confined to the local device broker."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from app_options import discovery_environment
import runtime


class HACredentialsTests(unittest.TestCase):
    def test_only_broker_receives_credentials_without_a_mode_option(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(runtime, 'ROOT', Path(directory)), patch.dict(os.environ, {'SUPERVISOR_TOKEN': 'synthetic-supervisor'}, clear=True):
            broker = runtime.broker_backend_environment()
            self.assertEqual(broker, {'HA_BROKER_BACKEND': 'homeassistant', 'HA_BASE_URL': 'http://supervisor/core', 'HA_TOKEN': 'synthetic-supervisor'})
            instance = runtime.Runtime.__new__(runtime.Runtime)
            instance.children = {}; instance.started = {}
            for role in (*runtime.USERS, 'page:20000'):
                identity = {'uid': 20000, 'groups': [runtime.GUEST_BROKER_GROUP]} if role.startswith('page:') else {}
                with patch.object(runtime.subprocess, 'Popen', return_value=Mock()) as spawn:
                    instance.start(role, ['synthetic'], broker if role == 'broker' else runtime.gateway_environment(), **identity)
                env = spawn.call_args.kwargs['env']
                self.assertNotIn('SUPERVISOR_TOKEN', env)
                self.assertEqual('HA_TOKEN' in env, role == 'broker')
                uid = identity.get('uid', runtime.USERS.get(role))
                self.assertEqual(spawn.call_args.kwargs['user'], uid)
                self.assertEqual(spawn.call_args.kwargs['group'], uid)
                groups = [runtime.GUEST_BROKER_GROUP] if identity else [runtime.GROUP] if role in ('admin', 'broker') else [runtime.FRONTEND_GROUP] if role == 'tls' else []
                self.assertEqual(spawn.call_args.kwargs['extra_groups'], groups)

    def test_missing_credentials_do_not_start_a_broker_backend(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, 'credentials unavailable'):
                runtime.broker_backend_environment()

    def test_selected_credential_file_cannot_fall_back_to_another_token(self):
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / 'ha-token'
            with patch.dict(os.environ, {'HA_TOKEN_FILE': str(token), 'SUPERVISOR_TOKEN': 'synthetic-supervisor'}, clear=True):
                with self.assertRaises(OSError): runtime.broker_backend_environment()
                token.write_text(' \n')
                with self.assertRaises(RuntimeError): runtime.broker_backend_environment()
                token.write_text('synthetic-file-token\n')
                self.assertEqual(runtime.broker_backend_environment()['HA_TOKEN'], 'synthetic-file-token')

    def test_filter_validation_does_not_accept_environment_injection(self):
        self.assertEqual(discovery_environment({'include_areas': 'kitchen,kitchen'})['HA_ENTITY_INCLUDE_AREAS'], 'kitchen')
        with self.assertRaises(ValueError): discovery_environment({'include_domains': 'light\nHA_TOKEN=secret'})


if __name__ == '__main__': unittest.main()
