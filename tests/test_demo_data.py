"""Run inside the packaged app on a disposable Linux CI runner only."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import time
import unittest
from unittest.mock import Mock, patch

import runtime
from demo_ha import DemoHomeAssistantClient
from ha import HomeAssistantError
from pages import PageStore


class DemoDataTests(unittest.TestCase):
    def setUp(self):
        # Any accidental fallback to the real HA HTTP client fails this test.
        self.network = patch('ha.urlopen', side_effect=AssertionError('Unexpected HA request'))
        self.network.start()
        self.addCleanup(self.network.stop)
        self.client = DemoHomeAssistantClient()

    def test_discovery_and_actions_without_credentials(self):
        entities = self.client.discover_entities()['entities']
        self.assertEqual(len(entities), 3)
        self.assertTrue(all('nhp_demo_' in e['entity_id'] for e in entities))
        self.client.call_service('lock', 'unlock', 'lock.nhp_demo_door')
        self.assertEqual(self.client.get_states({'lock.nhp_demo_door'})[0]['state'], 'unlocked')
        self.client.call_service('light', 'turn_on', 'light.nhp_demo_light', {'brightness_pct': 40})
        light = self.client.get_states({'light.nhp_demo_light'})[0]
        self.assertEqual((light['state'], light['attributes']['brightness']), ('on', 102))
        self.assertEqual(self.client.get_states({'lock.real_ha_entity'}), [])

    def test_demo_instances_and_returned_values_are_independent(self):
        self.client.call_service('lock', 'unlock', 'lock.nhp_demo_door')
        other = DemoHomeAssistantClient()
        states = other.get_states({'lock.nhp_demo_door'})
        self.assertEqual(states[0]['state'], 'locked')
        states[0]['state'] = 'unlocked'
        self.assertEqual(other.get_states({'lock.nhp_demo_door'})[0]['state'], 'locked')

    def test_unsupported_features_fail_without_ha_requests(self):
        for operation in (
            lambda: self.client.call_service('lock', 'unlock', 'lock.real_ha_entity'),
            lambda: self.client.call_service('sensor', 'turn_on', 'sensor.nhp_demo_temperature'),
            lambda: self.client.call_service('light', 'turn_on', 'light.nhp_demo_light', {'brightness_pct': float('inf')}),
            lambda: self.client.get_camera_image('camera.real_ha_entity'),
            lambda: self.client.verify_proximity('page', {'latitude': 0, 'longitude': 0}, 100),
            lambda: self.client._request('POST', '/api/services/notify/mobile_app_phone', {}),
        ):
            with self.subTest(operation=operation), self.assertRaises(HomeAssistantError):
                operation()

    def test_packaged_mode_ignores_injected_ha_credentials(self):
        self.assertTrue(runtime.DEMO_DATA)
        with patch.dict(os.environ, {
            'HA_TOKEN': 'synthetic-unused', 'SUPERVISOR_TOKEN': 'synthetic-unused',
            'HASSIO_TOKEN': 'synthetic-unused', 'HA_TOKEN_FILE': '/must-not-be-read',
            'HA_BASE_URL': 'http://must-not-be-contacted.invalid',
            'HA_BROKER_BACKEND': 'homeassistant',
        }):
            self.assertEqual(runtime.broker_backend_environment(), {'HA_BROKER_BACKEND': 'demo'})
            instance = runtime.Runtime.__new__(runtime.Runtime)
            instance.children = {}; instance.started = {}
            with patch('runtime.subprocess.Popen', return_value=Mock()) as spawn:
                instance.start('broker', ['python3', 'ha_broker.py'], runtime.broker_backend_environment())
            env = spawn.call_args.kwargs['env']
            self.assertEqual(env['HA_BROKER_BACKEND'], 'demo')
            self.assertFalse(set(env) & {'HA_TOKEN', 'SUPERVISOR_TOKEN', 'HASSIO_TOKEN', 'HA_TOKEN_FILE', 'HA_BASE_URL'})
            self.assertEqual(spawn.call_args.kwargs['user'], runtime.USERS['broker'])


class BrokerRoundTripTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.instance = runtime.Runtime.__new__(runtime.Runtime)
        cls.instance.children = {}; cls.instance.started = {}
        cls.directory = Path('/data/broker/ci-pages')
        store = PageStore(cls.directory)
        for page, domain, entity, service in (
            ('door-page', 'lock', 'lock.nhp_demo_door', 'unlock'),
            ('light-page', 'light', 'light.nhp_demo_light', 'turn_on'),
        ):
            store.create({'id': page, 'title': page, 'resources': [{
                'id': 'device', 'name': 'Demo device', 'entity_id': entity,
                'domain': domain, 'actions': [{'id': 'act', 'name': 'Demo action', 'service': service}],
            }]})
        registry = Path('/data/broker/ci-capabilities.json')
        registry.write_text(json.dumps({
            page: hashlib.sha256(('synthetic-' + page).encode()).hexdigest()
            for page in ('door-page', 'light-page')
        }))
        for path in [cls.directory, *cls.directory.iterdir(), registry]:
            os.chown(path, runtime.USERS['broker'], runtime.GROUP)
        cls.instance.start('broker', ['python3', str(runtime.GATEWAY / 'ha_broker.py')], {
            **runtime.broker_backend_environment(),
            'HA_BROKER_HOST': '127.0.0.1', 'HA_BROKER_PORT': '8083',
            'HA_BROKER_TOKEN': 'synthetic-unused-guest', 'HA_BROKER_ADMIN_TOKEN': 'synthetic-admin',
            'HA_BROKER_POLICY_DIR': str(cls.directory), 'HA_PAGE_CAPABILITY_REGISTRY': str(registry),
        })
        cls.addClassCleanup(cls.instance.stop, 'broker')
        for _ in range(30):
            try:
                status, _ = cls.request('/v1/discovery', {}, admin=True)
                if status == 200:
                    return
            except OSError:
                pass
            if cls.instance.children['broker'].poll() is not None:
                raise AssertionError('Demo broker exited during startup')
            time.sleep(0.1)
        raise AssertionError('Demo broker did not become ready')

    @staticmethod
    def request(path, body, *, admin=False, token=None):
        connection = http.client.HTTPConnection('127.0.0.1', 8083, timeout=2)
        try:
            connection.request('POST', path, json.dumps(body), {
                'Content-Type': 'application/json',
                'X-Broker-Role': 'admin' if admin else 'guest',
                'X-Broker-Token': token if token is not None else ('synthetic-admin' if admin else 'synthetic-door-page'),
            })
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_real_broker_discovery_and_scoped_demo_action(self):
        status, discovery = self.request('/v1/discovery', {}, admin=True)
        self.assertEqual((status, discovery['entity_count']), (200, 3))
        status, _ = self.request('/v1/page-action', {'resource_id': 'device', 'action_id': 'act'})
        self.assertEqual(status, 200)
        status, states = self.request('/v1/states', {'entity_ids': ['lock.nhp_demo_door']})
        self.assertEqual((status, states[0]['state']), (200, 'unlocked'))

    def test_authentication_and_page_boundaries_remain_enforced(self):
        self.assertEqual(self.request('/v1/discovery', {}, admin=True, token='wrong')[0], 401)
        self.assertEqual(self.request('/v1/discovery', {})[0], 403)
        self.assertEqual(self.request('/v1/states', {'entity_ids': ['light.nhp_demo_light']})[0], 403)
        # A caller-supplied page cannot override the page bound to its capability.
        status, _ = self.request('/v1/page-action', {
            'page_id': 'light-page', 'resource_id': 'device', 'action_id': 'act',
            'parameters': {'brightness_pct': 50},
        })
        self.assertEqual(status, 400)
        self.assertEqual(self.request('/v1/notification-targets', {}, admin=True), (200, {'targets': []}))


if __name__ == '__main__':
    unittest.main(verbosity=2)
