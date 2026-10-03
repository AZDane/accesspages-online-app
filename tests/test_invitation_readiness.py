import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'accesspages_online_test/rootfs/opt/accesspages-test/guest_gateway'))

"""Page readiness is derived from the same current route used by issuance."""
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

os.environ.setdefault('HA_BASE_URL', 'http://ha.invalid')
os.environ.setdefault('HA_TOKEN', 'synthetic-ha')
os.environ.setdefault('ADMIN_TOKEN', 'synthetic-admin')
import admin
import nhp
import server
from activity import GuestActivityStore
from invitation_fixture import key_delivery
from pages import PageStore


class InvitationReadinessTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.pages = PageStore(self.root / 'pages')
        self.manifest = {'gateway_id': 'gw', 'epoch': 1, 'isolation': 'page', 'resources': []}
        (self.root / 'binding').write_text(json.dumps({'gateway_id': 'gw', 'route': {'epoch': 1}}))
        self.publish()
        self.handler = object.__new__(server.Handler)
        self.handler._send_json = Mock()
        self.handler._require_admin = Mock(return_value=True)
        self.handler._validate_entity_policy = Mock()
        for change in (
            patch.dict(os.environ, {'GATEWAY_DATA_DIR': str(self.root),
                'NHP_ROUTES_FILE': str(self.root / 'routes'), 'NHP_BINDING_FILE': str(self.root / 'binding')}),
            patch.object(nhp, 'ENABLED', True), patch.object(nhp, 'INSTALLATION_ROUTING', True),
            patch.object(server, 'PAGE_STORE', self.pages),
            patch.object(server, 'POLICY_PUBLISHER', Mock()),
            patch.object(server, 'ACCESS_SERVICE_CLIENT', nhp.NHPClient()),
            patch.object(server, 'ACTIVITY_STORE', GuestActivityStore(self.root / 'activity.db')),
            patch.object(server, 'audit'),
        ):
            change.start()
            self.addCleanup(change.stop)

    def publish(self):
        (self.root / 'routes').write_text(json.dumps(self.manifest))

    def create_page(self, ident='page'):
        admin.handle_post(self.handler, '/api/admin/pages',
            {'id': ident, 'title': 'Synthetic', 'resources': []}, server)
        status, page = self.handler._send_json.call_args.args
        self.assertEqual(status, 201)
        return page

    def route(self, ident='page', **changes):
        return {'page_id': ident, 'instance_id': self.pages.load(ident)['instance_id'],
            'guest_hash': '', 'resource_id': 'b' * 48, **changes}

    def view(self, ident='page'):
        admin.handle_get(self.handler, None, '/api/admin/pages/' + ident, server)
        status, page = self.handler._send_json.call_args.args
        self.assertEqual(status, 200)
        return page

    def test_create_remains_editable_then_exact_route_allows_first_invitation(self):
        page = self.create_page()
        self.assertFalse(page['invitation_ready'])
        self.assertEqual(self.pages.load('page')['title'], 'Synthetic')
        admin.handle_post(self.handler, '/api/admin/pages/page',
            {'id': 'page', 'title': 'Edited while provisioning', 'resources': []}, server)
        self.assertEqual(self.handler._send_json.call_args.args[0], 200)
        self.assertFalse(self.view()['invitation_ready'])
        self.manifest['resources'] = [self.route()]
        self.publish()
        self.assertTrue(self.view()['invitation_ready'])
        # No retry or sleep: the first submission after readiness prepares once.
        def machine(request):
            if request['op'] == 'prepare_invitation':
                return key_delivery(int(time.time()) + 3600)
            grant = self.pages.load('page')['access_grants'][0]
            return {'state': 'unused', 'guest_token_hash': grant['token_hash'], 'resource': grant['resource_id']}
        with patch.object(nhp, 'machine', side_effect=machine) as send:
            self.handler._create_access_link('page', {'label': 'Guest', 'lifetime': '1h'})
        self.assertEqual(self.handler._send_json.call_args.args[0], 201)
        self.assertEqual([call.args[0]['op'] for call in send.call_args_list],
                         ['prepare_invitation', 'activate_invitation'])
        self.assertEqual(len(self.pages.load('page')['access_grants']), 1)
        self.assertNotIn('invitation_ready', self.pages.load('page'))

    def test_existing_page_is_independent_and_route_removal_is_visible(self):
        self.create_page('existing')
        self.manifest['resources'] = [self.route('existing')]
        self.publish()
        self.assertFalse(self.create_page()['invitation_ready'])
        self.assertTrue(self.view('existing')['invitation_ready'])
        self.assertFalse(self.view()['invitation_ready'])
        self.manifest['resources'] = []
        self.publish()
        self.assertFalse(self.view('existing')['invitation_ready'])

    def test_wrong_page_instance_scope_gateway_or_epoch_never_marks_ready(self):
        self.create_page()
        for changes in ({'page_id': 'other'}, {'instance_id': 'old'}, {'guest_hash': 'a' * 64}):
            with self.subTest(changes=changes):
                self.manifest['resources'] = [self.route(**changes)]
                self.publish()
                self.assertFalse(self.view()['invitation_ready'])
        self.manifest['resources'] = [self.route()]
        for field, value in (('epoch', 2), ('gateway_id', 'other')):
            original = self.manifest[field]
            self.manifest[field] = value
            self.publish()
            self.assertFalse(self.view()['invitation_ready'])
            self.manifest[field] = original

    def test_direct_submission_without_route_fails_before_native_preparation(self):
        self.create_page()
        with patch.object(nhp, 'machine') as send:
            self.handler._create_access_link('page', {'label': 'Guest', 'lifetime': '1h'})
        self.assertEqual(self.handler._send_json.call_args.args,
                         (502, {'error': 'Page route is not ready'}))
        send.assert_not_called()
        self.assertEqual(self.pages.load('page')['access_grants'], [])
        self.assertFalse((self.root / 'nhp-links.db').exists())

    def test_missing_manifest_is_unready_and_guest_mode_keeps_issuance_prerequisite(self):
        self.create_page()
        (self.root / 'routes').unlink()
        self.assertFalse(self.view()['invitation_ready'])
        self.manifest['isolation'] = 'guest'
        self.publish()
        self.assertTrue(self.view()['invitation_ready'])


if __name__ == '__main__':
    unittest.main()
