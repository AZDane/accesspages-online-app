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
        self.assertEqual(device_mode({}), "demo")
        self.assertEqual(device_mode({"device_mode": "homeassistant"}, demo_only=True), "demo")
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
                self.assertEqual(runtime.broker_backend_environment(), {"HA_BROKER_BACKEND": "demo"})
                options.write_text(json.dumps({"device_mode": "homeassistant"}))
                broker = runtime.broker_backend_environment()
                self.assertEqual(broker["HA_TOKEN"], "synthetic-supervisor")
                instance = runtime.Runtime.__new__(runtime.Runtime)
                instance.children = {}; instance.started = {}
                for role in ("admin", "guest", "tls", "connector", "broker"):
                    with patch.object(runtime.subprocess, "Popen", return_value=Mock()) as spawn:
                        instance.start(role, ["synthetic"], broker if role == "broker" else runtime.gateway_environment())
                    env = spawn.call_args.kwargs["env"]
                    self.assertNotIn("SUPERVISOR_TOKEN", env)
                    self.assertEqual("HA_TOKEN" in env, role == "broker")
                    self.assertEqual(spawn.call_args.kwargs["user"], runtime.USERS[role])

    def test_version_and_profile_come_from_package_and_filters_from_options(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pilot-features").write_text("sensors_lights")
            (root / "version").write_text("synthetic-candidate\n")
            (root / "options.json").write_text(json.dumps({"include_areas": "kitchen"}))
            with patch.object(runtime, "APP", root), patch.object(runtime, "ROOT", root), patch.object(runtime, "DEMO_DATA", False):
                env = runtime.gateway_environment()
                self.assertEqual(env["GATEWAY_DEVICE_DATA"], "demo")
                self.assertEqual(env["GATEWAY_FEATURE_PROFILE"], "sensors_lights")
                self.assertEqual(env["GATEWAY_VERSION"], "synthetic-candidate")
                self.assertEqual(env["HA_ENTITY_INCLUDE_AREAS"], "kitchen")
