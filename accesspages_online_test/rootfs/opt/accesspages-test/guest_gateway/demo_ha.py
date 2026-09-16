"""In-memory device data for testing the real NHP path without HA access."""
from copy import deepcopy
from threading import RLock

from ha import HomeAssistantClient, HomeAssistantError


class DemoHomeAssistantClient(HomeAssistantClient):
    """Reuse entity discovery, but never issue a Home Assistant request."""

    def __init__(self, **policy):
        super().__init__("", "", **policy)
        self._lock = RLock()
        self._states = {
            "lock.nhp_demo_door": {
                "state": "locked", "attributes": {"friendly_name": "Demo door"},
            },
            "light.nhp_demo_light": {
                "state": "off",
                "attributes": {"friendly_name": "Demo light", "brightness": 128},
            },
            "sensor.nhp_demo_temperature": {
                "state": "21.5", "attributes": {
                    "friendly_name": "Demo temperature", "device_class": "temperature",
                    "unit_of_measurement": "°C",
                },
            },
        }
        self._services = {"lock": ("lock", "unlock"), "light": ("turn_on", "turn_off")}

    def _request(self, method, path, payload=None):
        with self._lock:
            return self._local_request(method, path, payload)

    def _local_request(self, method, path, payload):
        if method == "GET" and path == "/api/states":
            return deepcopy([
                {"entity_id": entity_id, **state}
                for entity_id, state in self._states.items()
            ])
        if method == "GET" and path == "/api/services":
            return [
                {"domain": domain, "services": {
                    service: {"target": {}, "fields": {}, "description": "Change demo data only"}
                    for service in services
                }}
                for domain, services in self._services.items()
            ]
        if method == "POST" and path == "/api/template":
            return [
                {"entity_id": entity_id, "area_id": "nhp_demo", "area_name": "NHP demo"}
                for entity_id in self._states
            ]
        if method == "POST" and path.startswith("/api/services/"):
            parts = path.split("/")
            if len(parts) != 5:
                raise HomeAssistantError("Unknown demo action")
            domain, service = parts[3:]
            payload = payload or {}
            entity_id = payload.get("entity_id")
            if (
                entity_id not in self._states
                or not entity_id.startswith(domain + ".")
                or service not in self._services.get(domain, ())
            ):
                raise HomeAssistantError("Unknown demo entity or action")
            allowed = {"entity_id"}
            if domain == "light" and service == "turn_on":
                allowed.add("brightness_pct")
            if set(payload) - allowed:
                raise HomeAssistantError("Unknown demo action parameters")
            state = self._states[entity_id]
            if "brightness_pct" in payload:
                value = payload["brightness_pct"]
                if type(value) is not int or not 1 <= value <= 100:
                    raise HomeAssistantError("Invalid demo brightness")
                state["attributes"]["brightness"] = round(value * 255 / 100)
            state["state"] = {
                "lock": "locked", "unlock": "unlocked", "turn_on": "on", "turn_off": "off",
            }[service]
            self._discovery_cache = None
            return deepcopy([{"entity_id": entity_id, **state}])
        raise HomeAssistantError("This feature is unavailable with demo data")

    def get_camera_image(self, entity_id, **_policy):
        raise HomeAssistantError("Cameras are unavailable with demo data")
