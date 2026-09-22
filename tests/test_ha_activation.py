"""An upgrade cannot turn fake-device invitations into real HA permissions."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from app_options import device_mode, discovery_environment
from ha_activation import activation_status
import runtime


class HAActivationTests(unittest.TestCase):
    def test_missing_and_legacy_demo_never_select_normal_ha(self):
        self.assertEqual(device_mode({}),'review_required')
        self.assertEqual(device_mode({'device_mode':'demo'}),'review_required')
        self.assertEqual(device_mode({'device_mode':'homeassistant'},demo_only=True),'review_required')
        with self.assertRaises(ValueError):device_mode({'device_mode':'automatic'})

    def test_explicit_selection_persists_only_after_empty_grant_review(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);pages=root/'admin/pages';pages.mkdir(parents=True)
            p=pages/'page.json';p.write_text(json.dumps({'resources':[],'access_grants':[{'id':'old'}]}))
            before=p.read_bytes()
            self.assertFalse(activation_status(root,'homeassistant')[0]);self.assertEqual(p.read_bytes(),before)
            self.assertFalse((root/'ha-integration-approved.json').exists())
            p.write_text(json.dumps({'resources':[],'access_grants':[]}))
            self.assertTrue(activation_status(root,'homeassistant')[0])
            self.assertEqual((root/'ha-integration-approved.json').stat().st_mode&0o777,0o600)
            # Newly issued normal-HA invitations survive ordinary restart.
            p.write_text(json.dumps({'resources':[],'access_grants':[{'id':'new'}]}))
            self.assertTrue(activation_status(root,'homeassistant')[0])

    def test_legacy_fake_entity_ids_are_not_reinterpreted(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);p=root/'admin/pages/page.json';p.parent.mkdir(parents=True)
            p.write_text(json.dumps({'access_grants':[],'resources':[{'entity_id':'light.nhp_demo_light'}]}))
            self.assertFalse(activation_status(root,'homeassistant')[0])
            self.assertFalse((root/'ha-integration-approved.json').exists())

    def test_corrupt_pages_marker_and_disk_failure_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);p=root/'admin/pages/page.json';p.parent.mkdir(parents=True);p.write_text('{')
            self.assertFalse(activation_status(root,'homeassistant')[0]);p.unlink()
            with patch('ha_activation.atomic',side_effect=OSError('disk full')):self.assertFalse(activation_status(root,'homeassistant')[0])
            (root/'ha-integration-approved.json').write_text('{}')
            self.assertFalse(activation_status(root,'homeassistant')[0])

    def test_review_mode_neither_writes_approval_nor_obtains_credentials(self):
        with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,{'SUPERVISOR_TOKEN':'synthetic-supervisor'}):
            self.assertFalse(activation_status(d,'review_required')[0])
            self.assertEqual(list(Path(d).iterdir()),[])
            with self.assertRaises(RuntimeError):runtime.broker_backend_environment('review_required')
            instance=runtime.Runtime.__new__(runtime.Runtime);instance.ha_ready=False;instance.ha_reason='Review'
            instance.installation=Mock()
            self.assertFalse(instance.prepare());self.assertEqual(instance.installation.mock_calls,[])

    def test_only_local_broker_inherits_selected_ha_credential(self):
        with tempfile.TemporaryDirectory() as d,patch.object(runtime,'ROOT',Path(d)),patch.dict(os.environ,{'SUPERVISOR_TOKEN':'synthetic-supervisor'},clear=True):
            broker=runtime.broker_backend_environment('homeassistant')
            self.assertEqual(broker['HA_BASE_URL'],'http://supervisor/core')
            instance=runtime.Runtime.__new__(runtime.Runtime);instance.children={};instance.started={}
            for role in runtime.USERS:
                with patch.object(runtime.subprocess,'Popen',return_value=Mock()) as spawn:
                    instance.start(role,['synthetic'],broker if role=='broker' else {})
                env=spawn.call_args.kwargs['env']
                self.assertNotIn('SUPERVISOR_TOKEN',env)
                self.assertEqual('HA_TOKEN' in env,role=='broker')
                self.assertEqual(spawn.call_args.kwargs['user'],runtime.USERS[role])

    def test_missing_ha_credential_does_not_fall_back_to_demo(self):
        with patch.dict(os.environ,{},clear=True):
            with self.assertRaises(RuntimeError):runtime.broker_backend_environment('homeassistant')

    def test_filter_validation_does_not_accept_environment_injection(self):
        self.assertEqual(discovery_environment({'include_areas':'demo,demo'})['HA_ENTITY_INCLUDE_AREAS'],'demo')
        with self.assertRaises(ValueError):discovery_environment({'include_domains':'light\nHA_TOKEN=secret'})


if __name__=='__main__':unittest.main()
