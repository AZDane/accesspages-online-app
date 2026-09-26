"""Pilot configuration must not silently enable HA or leak its credentials."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import runtime
from app_options import device_mode, discovery_environment


class AppOptionsTests(unittest.TestCase):
    def test_missing_pilot_mode_defaults_to_demo_and_old_marker_stays_enforced(self):
        self.assertEqual(device_mode({}), "review_required")
        self.assertEqual(device_mode({"device_mode": "homeassistant"}, demo_only=True), "review_required")
        with self.assertRaises(ValueError):
            device_mode({"device_mode": "automatic"})

    def test_filters_cannot_inject_other_environment_settings(self):
        expected = discovery_environment({"include_areas": "kitchen, kitchen", "exclude_entities": "light.private"})
        self.assertEqual(expected["HA_ENTITY_INCLUDE_AREAS"], "kitchen")
        self.assertEqual(expected["HA_ENTITY_EXCLUDE_ENTITIES"], "light.private")
        for value in (["light.one"], "light.one\nHA_TOKEN=secret", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                discovery_environment({"exclude_entities": value})

    def test_supervisor_credentials_go_only_to_selected_ha_broker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            options = root / "options.json"
            with patch.object(runtime, "ROOT", root), patch.object(runtime, "DEMO_DATA", False), patch.dict(os.environ, {"SUPERVISOR_TOKEN": "synthetic-supervisor"}, clear=True):
                options.write_text(json.dumps({"server_address": "synthetic:62206"}))
                with self.assertRaises(RuntimeError):
                    runtime.broker_backend_environment()
                options.write_text(json.dumps({"device_mode": "homeassistant"}))
                broker = runtime.broker_backend_environment()
                self.assertEqual(broker["HA_TOKEN"], "synthetic-supervisor")
                instance = runtime.Runtime.__new__(runtime.Runtime)
                instance.children = {}; instance.started = {}
                for role in (*runtime.USERS, 'page:20000'):
                    identity = {'uid': 20000, 'groups': [runtime.GUEST_BROKER_GROUP]} if role.startswith('page:') else {}
                    with patch.object(runtime.subprocess, "Popen", return_value=Mock()) as spawn:
                        instance.start(role, ["synthetic"], broker if role == "broker" else runtime.gateway_environment(), **identity)
                    env = spawn.call_args.kwargs["env"]
                    self.assertNotIn("SUPERVISOR_TOKEN", env)
                    self.assertEqual("HA_TOKEN" in env, role == "broker")
                    uid = identity.get('uid', runtime.USERS.get(role))
                    self.assertEqual(spawn.call_args.kwargs["user"], uid)
                    self.assertEqual(spawn.call_args.kwargs["group"], uid)
                    groups = [runtime.GUEST_BROKER_GROUP] if identity else [runtime.GROUP] if role in ('admin', 'broker') else [runtime.FRONTEND_GROUP] if role == 'tls' else []
                    self.assertEqual(spawn.call_args.kwargs['extra_groups'], groups)

    def test_version_and_profile_come_from_package_and_filters_from_options(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pilot-features").write_text("sensors_lights")
            (root / "version").write_text("synthetic-candidate\n")
            (root / "options.json").write_text(json.dumps({"include_areas": "kitchen"}))
            with patch.object(runtime, "APP", root), patch.object(runtime, "ROOT", root), patch.object(runtime, "DEMO_DATA", False):
                env = runtime.gateway_environment()
                self.assertEqual(env["GATEWAY_DEVICE_DATA"], "review_required")
                self.assertEqual(env["GATEWAY_FEATURE_PROFILE"], "sensors_lights")
                self.assertEqual(env["GATEWAY_VERSION"], "synthetic-candidate")
                self.assertEqual(env["HA_ENTITY_INCLUDE_AREAS"], "kitchen")

    def test_connection_reset_removes_identities_and_preserves_owner_data(self):
        class FakeInstallation:
            def __init__(self, root, server_address=None):
                self.root = Path(root)
                self.server_address = server_address

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            preserved = {
                root / "admin/pages/front-door.json": "page",
                root / "admin/admin-runtime/smtp.json": "mail",
            }
            removed = {
                root / "admin/installation/binding.json": "binding",
                root / "connector/frpc.toml": "connector",
                root / "tls/guest.key": "key",
                root / "public/binding.json": "public",
                root / "admin/page-capabilities.json": "admin-capability",
                root / "broker/page-workers.json": "worker-identities",
                root / "broker/guest-sessions.db": "sessions",
                root / "admin/routes.json": "admin-routes",
                root / "broker/routes.json": "broker-routes",
                root / "admin/ready-routes.json": "ready-routes",
                root / "workers/20000/private/capability.json": "page-capability",
            }
            for path, value in {**preserved, **removed}.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(value)
            request = root / "admin/reset-connection.request"
            request.write_text("reset\n")
            instance = runtime.Runtime.__new__(runtime.Runtime)
            instance.children = {role: Mock() for role in runtime.USERS}
            instance.installation = FakeInstallation(root / "admin/installation")
            instance.page_workers = runtime.PageWorkers(root, runtime.GATEWAY, instance)
            instance.page_workers.state['next_uid'] = 20001
            import route_reservations
            route_reservations.reserve(root / 'admin', 'front-door', 'a' * 32, 'b' * 64)
            with (
                patch.object(runtime, "ROOT", root),
                patch.object(runtime, "Installation", FakeInstallation),
                patch.object(runtime, "configured_server_address", return_value="synthetic:62206"),
                patch.object(runtime.os, "chown"),
                patch.object(instance, "stop") as stop,
            ):
                instance.reset_service_connection()
            self.assertEqual(stop.call_count, len(runtime.USERS))
            for path, value in preserved.items():
                self.assertEqual(path.read_text(), value)
            for path in removed:
                self.assertFalse(path.exists())
            self.assertEqual(instance.page_workers.state, {'next_uid': 20001, 'pages': {}})
            self.assertEqual(route_reservations.pending(root / 'admin'), [])
            self.assertFalse(request.exists())
            self.assertEqual(instance.message, "Paste the enrollment API token to connect this Home Assistant.")
