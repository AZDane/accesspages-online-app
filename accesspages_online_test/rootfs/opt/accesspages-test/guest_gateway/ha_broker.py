from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
from hashlib import sha256
import json
import math
import os
import feature_policy
from pathlib import Path

from ha import (
    CAMERA_IMAGE_TYPES,
    HomeAssistantClient,
    HomeAssistantError,
    normalize_capabilities,
)
from pages import PageConfigError, PageNotFoundError, PageStore


HOST = os.getenv("HA_BROKER_HOST", "0.0.0.0")
PORT = int(os.getenv("HA_BROKER_PORT", "8082"))
TOKEN = os.environ["HA_BROKER_TOKEN"]
ADMIN_TOKEN = os.environ["HA_BROKER_ADMIN_TOKEN"]
if hmac.compare_digest(TOKEN, ADMIN_TOKEN):
    raise RuntimeError("HA broker guest and admin tokens must be distinct")
PAGE_STORE = PageStore(Path(os.getenv("HA_BROKER_POLICY_DIR", "/policy")))
PAGE_CAPABILITY_REGISTRY = Path(os.getenv(
    "HA_PAGE_CAPABILITY_REGISTRY", "/policy-capabilities/page-capabilities.json"
))
BACKEND = os.getenv("HA_BROKER_BACKEND", "homeassistant")
DISCOVERY_POLICY = {
    name: frozenset(value.strip() for value in os.getenv("HA_ENTITY_" + name.upper(), "").split(",") if value.strip())
    for name in ("include_areas", "include_domains", "include_device_classes", "include_entities",
                 "exclude_areas", "exclude_domains", "exclude_device_classes", "exclude_entities")
}
if BACKEND == "demo":
    from demo_ha import DemoHomeAssistantClient
    HA_CLIENT = DemoHomeAssistantClient(**DISCOVERY_POLICY)
elif BACKEND == "homeassistant":
    HA_CLIENT = HomeAssistantClient(os.environ["HA_BASE_URL"], os.environ["HA_TOKEN"], **DISCOVERY_POLICY)
else:
    raise RuntimeError("Unknown device data backend")


class BrokerPolicyError(ValueError):
    def __init__(self, message, status=HTTPStatus.BAD_REQUEST):
        super().__init__(message)
        self.status = status


def _page(page_id):
    try:
        return PAGE_STORE.load(page_id)
    except PageNotFoundError as error:
        raise BrokerPolicyError("Page not found", HTTPStatus.NOT_FOUND) from error
    except PageConfigError as error:
        raise BrokerPolicyError("Page policy is invalid") from error


def _resource_action(page, resource_id, action_id):
    resource = next(
        (item for item in page["resources"] if item["id"] == resource_id),
        None,
    )
    if resource is None:
        raise BrokerPolicyError("Resource not found", HTTPStatus.NOT_FOUND)
    try:
        feature_policy.validate_page(page)
    except ValueError as error:
        raise BrokerPolicyError(str(error), HTTPStatus.FORBIDDEN) from error
    action = next(
        (item for item in resource["actions"] if item["id"] == action_id),
        None,
    )
    if action is None:
        raise BrokerPolicyError("Action not permitted", HTTPStatus.NOT_FOUND)
    if resource["domain"] == "sensor" or action["service"] == "view":
        raise BrokerPolicyError("Resource is read-only", HTTPStatus.FORBIDDEN)
    return resource, action


def camera_image(page_id, resource_id):
    if feature_policy.limited():
        raise BrokerPolicyError("Cameras are not enabled in this pilot", HTTPStatus.FORBIDDEN)
    page = _page(page_id)
    resource = next(
        (item for item in page["resources"] if item["id"] == resource_id),
        None,
    )
    if resource is None or resource["domain"] != "camera":
        raise BrokerPolicyError("Camera not found", HTTPStatus.NOT_FOUND)
    return HA_CLIENT.get_camera_image(resource["entity_id"])


def _finite(value, message):
    try:
        result = float(value)
    except (TypeError, ValueError) as error:
        raise BrokerPolicyError(message) from error
    if not math.isfinite(result):
        raise BrokerPolicyError(message)
    return result


def _matches_step(value, minimum, maximum, step):
    if value == maximum:
        return True
    quotient = (value - minimum) / step
    return math.isclose(quotient, round(quotient), abs_tol=1e-7)


def authorized_states(requested):
    if not feature_policy.limited():
        return HA_CLIENT.get_states(requested)
    if any(not isinstance(item, str) or not feature_policy.entity_allowed(item, item.split(".")[0]) for item in requested):
        raise BrokerPolicyError("Entity is outside the sensor/light pilot", HTTPStatus.FORBIDDEN)
    states = HA_CLIENT.get_states(requested)
    areas = HA_CLIENT.get_entity_areas() if HA_CLIENT.include_areas or HA_CLIENT.exclude_areas else {}
    result = []
    for state in states:
        entity_id = state.get("entity_id", "")
        if entity_id not in requested:
            continue
        attrs = state.get("attributes") or {}
        if not HA_CLIENT.entity_allowed(entity_id, entity_id.split(".")[0], attrs.get("device_class", ""), areas.get(entity_id, {}).get("area_id", "")):
            raise BrokerPolicyError("Entity is excluded by app configuration", HTTPStatus.FORBIDDEN)
        result.append({"entity_id": entity_id, "state": state.get("state", "unavailable"), "attributes": feature_policy.attributes(attrs)})
    return result


def _service_data(resource, action, supplied):
    if not isinstance(supplied, dict):
        raise BrokerPolicyError("Parameters must be an object")
    try:
        feature_policy.validate_resource(resource)
        feature_policy.validate_parameters(resource["domain"], action["service"], supplied)
    except ValueError as error:
        raise BrokerPolicyError(str(error)) from error
    states = authorized_states({resource["entity_id"]})
    state = next(
        (item for item in states if item.get("entity_id") == resource["entity_id"]),
        None,
    )
    if state is None:
        raise BrokerPolicyError("Assigned entity not found", HTTPStatus.NOT_FOUND)
    if feature_policy.limited():
        if state.get("state") in {"unknown", "unavailable"}:
            raise BrokerPolicyError("Assigned entity is unavailable", HTTPStatus.CONFLICT)
        if "brightness_pct" in supplied and not feature_policy.brightness_supported(state.get("attributes") or {}):
            raise BrokerPolicyError("This light does not support brightness")
    capabilities = normalize_capabilities(
        resource["domain"],
        state.get("state"),
        state.get("attributes") or {},
        {item["service"] for item in resource["actions"]},
    )
    domain = resource["domain"]
    service = action["service"]
    allowed_keys = set()
    result = {}

    if domain == "climate" and service == "set_temperature":
        allowed_keys = {"temperature"}
        value = _finite(supplied.get("temperature"), "Invalid temperature")
        cap = capabilities.get("climate", {}).get("temperature")
        if (
            not cap
            or value < cap["min"]
            or value > cap["max"]
            or not _matches_step(value, cap["min"], cap["max"], cap["step"])
        ):
            raise BrokerPolicyError("Temperature is outside live capability")
        result["temperature"] = value
    elif domain == "climate" and service == "set_hvac_mode":
        allowed_keys = {"hvac_mode"}
        value = str(supplied.get("hvac_mode", "")).strip()
        if value not in capabilities.get("climate", {}).get("hvac_modes", []):
            raise BrokerPolicyError("Unsupported HVAC mode")
        result["hvac_mode"] = value
    elif domain in {"number", "input_number"}:
        allowed_keys = {"value"}
        value = _finite(supplied.get("value"), "Invalid numeric value")
        cap = capabilities.get("number")
        if (
            not cap
            or value < cap["min"]
            or value > cap["max"]
            or not _matches_step(value, cap["min"], cap["max"], cap["step"])
        ):
            raise BrokerPolicyError("Value is outside live capability")
        result["value"] = value
    elif domain in {"select", "input_select"}:
        allowed_keys = {"option"}
        value = str(supplied.get("option", "")).strip()
        if value not in capabilities.get("select", {}).get("options", []):
            raise BrokerPolicyError("Unsupported option")
        result["option"] = value
    elif domain == "fan" and service == "set_percentage":
        allowed_keys = {"percentage"}
        try:
            value = int(supplied.get("percentage"))
        except (TypeError, ValueError, OverflowError) as error:
            raise BrokerPolicyError("Invalid fan percentage") from error
        if value not in capabilities.get("fan_percentage", {}).get("values", []):
            raise BrokerPolicyError("Unsupported fan percentage")
        result["percentage"] = value
    elif (
        domain == "light"
        and service == "turn_on"
        and "brightness_pct" in supplied
    ):
        allowed_keys = {"brightness_pct"}
        try:
            value = int(supplied.get("brightness_pct"))
        except (TypeError, ValueError, OverflowError) as error:
            raise BrokerPolicyError("Invalid brightness") from error
        if value < 1 or value > 100:
            raise BrokerPolicyError("Brightness is outside capability")
        result["brightness_pct"] = value
    elif domain == "media_player" and service == "volume_set":
        allowed_keys = {"volume_level"}
        value = _finite(supplied.get("volume_level"), "Invalid volume")
        if value < 0 or value > 1:
            raise BrokerPolicyError("Volume is outside capability")
        result["volume_level"] = value

    if set(supplied) - allowed_keys:
        raise BrokerPolicyError("Unknown action parameters")
    return result


def execute_page_action(page_id, resource_id, action_id, parameters):
    page = _page(page_id)
    resource, action = _resource_action(page, resource_id, action_id)
    service_data = _service_data(resource, action, parameters)
    HA_CLIENT.call_service(
        resource["domain"],
        action["service"],
        resource["entity_id"],
        service_data,
    )
    return {"success": True}


def verify_page_proximity(page_id, reading):
    if feature_policy.limited():
        raise BrokerPolicyError("Location-based controls are not enabled in this pilot", HTTPStatus.FORBIDDEN)
    page = _page(page_id)
    policy = page.get("proximity", {})
    if not policy.get("enabled", False):
        raise BrokerPolicyError("Proximity is not enabled for this page")
    if not isinstance(reading, dict):
        raise BrokerPolicyError("Location reading is invalid")
    try:
        within_range = HA_CLIENT.verify_proximity(
            page_id,
            reading,
            int(policy["radius_meters"]),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise BrokerPolicyError("Location reading is invalid") from error
    return {"within_range": within_range}


def notification_targets():
    services = HA_CLIENT._request("GET", "/api/services")
    notify = next(
        (item for item in services if item.get("domain") == "notify"), {}
    )
    service_catalog = notify.get("services") or {}
    if isinstance(service_catalog, dict):
        service_names = service_catalog
    elif isinstance(service_catalog, list):
        service_names = [
            str(item.get("service") or item.get("name") or "")
            for item in service_catalog if isinstance(item, dict)
        ]
    else:
        service_names = []
    legacy = {
        f"notify.{name}" for name in service_names
        if str(name).startswith("mobile_app_")
    }
    states = HA_CLIENT._request("GET", "/api/states")
    entities = {
        str(item.get("entity_id", "")) for item in states
        if isinstance(item, dict)
        and str(item.get("entity_id", "")).startswith("notify.mobile_app_")
    }
    return sorted(legacy | entities)


def send_notification(target, title, message):
    if target not in notification_targets():
        raise BrokerPolicyError("Notification target is not registered")
    states = HA_CLIENT._request("GET", "/api/states")
    entity_ids = {
        str(item.get("entity_id", "")) for item in states
        if isinstance(item, dict)
    }
    payload = {"title": str(title)[:120], "message": str(message)[:500]}
    if target in entity_ids:
        payload["target"] = {"entity_id": target}
        path = "/api/services/notify/send_message"
    else:
        path = f"/api/services/notify/{target.removeprefix('notify.')}"
    HA_CLIENT._request("POST", path, payload)
    return {"success": True}


class Handler(BaseHTTPRequestHandler):
    def _authorized(self, *, admin=False):
        supplied = self.headers.get("X-Broker-Token", "")
        if admin:
            return hmac.compare_digest(supplied, ADMIN_TOKEN)
        return hmac.compare_digest(supplied, TOKEN)

    def _admin_request(self):
        role = self.headers.get("X-Broker-Role", "guest")
        if role not in {"guest", "admin"}:
            return None
        return self.path == "/v1/discovery" or role == "admin"

    def _authorized_page(self):
        supplied = self.headers.get("X-Broker-Token", "")
        if not supplied:
            return ""
        try:
            registry = json.loads(
                PAGE_CAPABILITY_REGISTRY.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError):
            return ""
        supplied_hash = sha256(supplied.encode()).hexdigest()
        for page_id, expected_hash in registry.items():
            if hmac.compare_digest(supplied_hash, str(expected_hash)):
                return str(page_id)
        return ""

    def log_message(self, *_args):
        return

    def _send(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_image(self, body, content_type):
        if content_type not in CAMERA_IMAGE_TYPES:
            raise BrokerPolicyError("Unsupported camera image")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _payload(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > 64 * 1024:
            raise BrokerPolicyError("Invalid request size")
        value = json.loads(self.rfile.read(length))
        if not isinstance(value, dict):
            raise BrokerPolicyError("Request must be an object")
        return value

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"status": "ok"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        role = self.headers.get("X-Broker-Role", "guest")
        admin_request = role == "admin"
        bound_page_id = "" if admin_request else self._authorized_page()
        if role not in {"guest", "admin"} or not (
            self._authorized(admin=True) if admin_request else bound_page_id
        ):
            self._send(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        try:
            payload = self._payload()
            if feature_policy.limited():
                allowed = {
                    "/v1/states": {"entity_ids"},
                    "/v1/page-action": {"page_id", "resource_id", "action_id", "parameters"},
                    "/v1/discovery": {"force"},
                    "/v1/notification-targets": set(),
                    "/v1/send-notification": {"target", "title", "message"},
                }
                if self.path not in allowed:
                    raise BrokerPolicyError("This operation is not enabled in this pilot", HTTPStatus.FORBIDDEN)
                if set(payload) - allowed[self.path]:
                    raise BrokerPolicyError("Unknown request fields")
            if self.path == "/v1/states":
                requested = payload.get("entity_ids")
                if not isinstance(requested, list) or not requested or not all(isinstance(item, str) for item in requested):
                    raise BrokerPolicyError("Entity IDs are required")
                assigned = {
                    resource["entity_id"]
                    for page in (
                        [_page(bound_page_id)] if bound_page_id else
                        [_page(item["id"]) for item in PAGE_STORE.list_pages()]
                    )
                    for resource in page["resources"]
                }
                if any(item not in assigned for item in requested):
                    raise BrokerPolicyError("Entity is not assigned", HTTPStatus.FORBIDDEN)
                states = authorized_states(set(requested))
                self._send(200, states)
            elif self.path == "/v1/camera-image":
                body, content_type = camera_image(
                    bound_page_id or str(payload.get("page_id", "")),
                    str(payload.get("resource_id", "")),
                )
                self._send_image(body, content_type)
            elif self.path == "/v1/page-action":
                self._send(
                    200,
                    execute_page_action(
                        bound_page_id or str(payload.get("page_id", "")),
                        str(payload.get("resource_id", "")),
                        str(payload.get("action_id", "")),
                        payload.get("parameters", {}),
                    ),
                )
            elif self.path == "/v1/proximity":
                self._send(
                    200,
                    verify_page_proximity(
                        bound_page_id or str(payload.get("page_id", "")),
                        payload.get("reading"),
                    ),
                )
            elif self.path == "/v1/notification-targets":
                if not admin_request:
                    raise BrokerPolicyError("Admin authority required", HTTPStatus.FORBIDDEN)
                self._send(
                    200,
                    {"targets": notification_targets()},
                )
            elif self.path == "/v1/send-notification":
                if not admin_request:
                    raise BrokerPolicyError("Admin authority required", HTTPStatus.FORBIDDEN)
                self._send(
                    200,
                    send_notification(
                        str(payload.get("target", "")),
                        str(payload.get("title", "")),
                        str(payload.get("message", "")),
                    ),
                )
            elif self.path == "/v1/discovery":
                if not admin_request:
                    raise BrokerPolicyError("Admin authority required", HTTPStatus.FORBIDDEN)
                self._send(
                    200,
                    HA_CLIENT.discover_entities(
                        force=bool(payload.get("force", False))
                    ),
                )
            else:
                self._send(404, {"error": "not found"})
        except (BrokerPolicyError, json.JSONDecodeError) as error:
            self._send(
                getattr(error, "status", HTTPStatus.BAD_REQUEST),
                {"error": str(error) or "Invalid request"},
            )
        except HomeAssistantError:
            self._send(HTTPStatus.BAD_GATEWAY, {"error": "Home Assistant failed"})


def run():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    run()
