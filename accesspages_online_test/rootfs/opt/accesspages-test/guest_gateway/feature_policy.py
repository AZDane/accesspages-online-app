"""Enabled product capabilities, independent of discovery preferences."""
import os
import re

PROFILE = os.getenv("GATEWAY_FEATURE_PROFILE", "full")
if PROFILE not in {"full", "sensors_lights"}:
    raise RuntimeError("Unknown Guest Gateway feature profile")
DOMAINS = frozenset({"sensor", "binary_sensor", "light"})
ATTRIBUTES = frozenset({
    "friendly_name", "device_class", "unit_of_measurement", "brightness",
    "supported_color_modes", "color_mode", "supported_features",
})


def limited():
    return PROFILE == "sensors_lights"


def entity_allowed(entity_id, domain):
    return not limited() or (
        domain in DOMAINS
        and isinstance(entity_id, str)
        and re.fullmatch(r"[a-z_]+\.[a-z0-9_]+", entity_id) is not None
        and entity_id.startswith(domain + ".")
    )


def service_allowed(domain, service):
    return not limited() or (
        domain in DOMAINS and (
            service == "view" or (domain == "light" and service in {"turn_on", "turn_off"})
        )
    )


def validate_resource(resource):
    if not limited():
        return
    if not isinstance(resource, dict) or not isinstance(resource.get("actions", []), list):
        raise ValueError("Invalid page resource")
    domain = resource.get("domain")
    if not entity_allowed(resource.get("entity_id"), domain):
        raise ValueError("This pilot supports sensors and lights only. Edit this page to remove unsupported entities.")
    if any(not isinstance(action, dict) or not service_allowed(domain, action.get("service")) for action in resource.get("actions", [])):
        raise ValueError("This page includes a control unavailable in the sensor/light pilot.")


def validate_page(page):
    if not limited():
        return
    if not isinstance(page, dict) or not isinstance(page.get("resources", []), list):
        raise ValueError("Invalid page")
    proximity = page.get("proximity") or {}
    if not isinstance(proximity, dict):
        raise ValueError("Invalid proximity policy")
    if proximity.get("enabled"):
        raise ValueError("Location-based controls are not enabled in this pilot.")
    for resource in page.get("resources", []):
        validate_resource(resource)


def attributes(value):
    return {key: item for key, item in value.items() if key in ATTRIBUTES} if limited() else value


def brightness_supported(value):
    modes = value.get("supported_color_modes")
    if isinstance(modes, list):
        return bool(set(modes) & {"brightness", "color_temp", "hs", "xy", "rgb", "rgbw", "rgbww", "white"})
    # Older integrations and demo data can expose brightness without modes.
    return type(value.get("brightness")) in {int, float} and 0 <= value["brightness"] <= 255


def validate_parameters(domain, service, payload):
    if not limited():
        return
    if domain != "light" or service not in {"turn_on", "turn_off"}:
        raise ValueError("This control is unavailable in the sensor/light pilot.")
    keys = {"brightness_pct"} if service == "turn_on" else set()
    if not isinstance(payload, dict) or set(payload) - keys:
        raise ValueError("Unknown action parameters")
    if "brightness_pct" in payload:
        value = payload["brightness_pct"]
        if type(value) is not int or not 1 <= value <= 100:
            raise ValueError("Brightness must be a whole number from 1 to 100")
