"""Authoritative policy enforcement and dispatch for guest HA actions."""

import math
import feature_policy

from ha import HomeAssistantError


def _matches_step(value, minimum, maximum, step):
    if math.isclose(value, maximum, abs_tol=1e-7):
        return True
    offset = (value - minimum) / step
    return math.isclose(offset, round(offset), abs_tol=1e-7)


def execute_public_action(
    handler,
    ha_client,
    page,
    resource_id,
    action_id,
    payload,
    normalize_capabilities,
    audit,
):
    try:
        feature_policy.validate_page(page)
        if feature_policy.limited() and (not isinstance(payload, dict) or "proximity" in payload):
            raise ValueError("Unknown action parameters")
    except ValueError as error:
        handler._send_json(403, {"error": str(error)})
        return
    if not handler._require_proximity(page, payload):
        return
    payload = {
        key: value
        for key, value in payload.items()
        if key != "proximity"
    }
    resource = next(
        (
            item
            for item in page["resources"]
            if item["id"] == resource_id
        ),
        None,
    )

    if resource is None:
        handler._record_security_event(
            page["id"],
            "unapproved_action_attempt",
            grant_id=getattr(handler, "active_grant", {}).get("id"),
            details={
                "resource_id": resource_id,
                "action_id": action_id,
                "reason": "resource_not_assigned",
            },
        )
        handler._send_json(404, {"error": "Resource not found"})
        return

    action = next(
        (
            item
            for item in resource["actions"]
            if item["id"] == action_id
        ),
        None,
    )

    if action is None:
        handler._record_security_event(
            page["id"],
            "unapproved_action_attempt",
            grant_id=getattr(handler, "active_grant", {}).get("id"),
            details={
                "resource_id": resource_id,
                "action_id": action_id,
                "reason": "action_not_permitted",
            },
        )
        handler._send_json(404, {"error": "Action not permitted"})
        return

    # Sensors are deliberately read-only.  Their synthetic "view" action
    # exists only so an administrator can include them on a page.
    if resource["domain"] == "sensor" or action["service"] == "view":
        handler._send_json(403, {"error": "This resource is read-only"})
        return

    try:
        feature_policy.validate_parameters(resource["domain"], action["service"], payload)
    except ValueError as error:
        handler._send_json(400, {"error": str(error)})
        return

    service_data = {}

    # Only accept tightly-scoped parameters for approved climate actions.
    # The client can never choose an entity, domain, or arbitrary service.
    if resource["domain"] == "climate":
        try:
            state = next(
                item for item in ha_client.get_states(
                    {resource["entity_id"]}
                )
                if item.get("entity_id") == resource["entity_id"]
            )
        except StopIteration:
            handler._send_json(404, {"error": "Climate entity not found"})
            return
        except HomeAssistantError as error:
            handler._send_ha_error(error)
            return

        attributes = state.get("attributes") or {}
        capabilities = normalize_capabilities(
            "climate",
            state.get("state"),
            attributes,
            {item["service"] for item in resource["actions"]},
        ).get("climate", {})

        if action["service"] == "set_temperature":
            try:
                temperature = float(payload.get("temperature"))
            except (TypeError, ValueError):
                handler._send_json(400, {"error": "A numeric temperature is required"})
                return
            if not math.isfinite(temperature):
                handler._send_json(400, {"error": "A finite temperature is required"})
                return

            temperature_capability = capabilities.get("temperature")
            if not temperature_capability:
                handler._send_json(
                    409,
                    {"error": "Temperature control is not currently available"},
                )
                return
            minimum = temperature_capability["min"]
            maximum = temperature_capability["max"]
            step = temperature_capability["step"]
            if temperature < minimum or temperature > maximum:
                handler._send_json(
                    400,
                    {"error": f"Temperature must be between {minimum:g} and {maximum:g}"},
                )
                return
            if not _matches_step(temperature, minimum, maximum, step):
                handler._send_json(
                    400,
                    {"error": f"Temperature must use a step of {step:g}"},
                )
                return
            service_data["temperature"] = temperature

        elif action["service"] == "set_hvac_mode":
            hvac_mode = str(payload.get("hvac_mode", "")).strip()
            allowed_modes = capabilities.get("hvac_modes") or []
            if hvac_mode not in allowed_modes:
                handler._send_json(400, {"error": "Unsupported HVAC mode"})
                return
            service_data["hvac_mode"] = hvac_mode

    elif resource["domain"] in {"number", "input_number"}:
        try:
            value = float(payload.get("value"))
        except (TypeError, ValueError):
            handler._send_json(400, {"error": "A numeric value is required"})
            return
        if not math.isfinite(value):
            handler._send_json(400, {"error": "A finite value is required"})
            return
        try:
            state = next(
                item for item in ha_client.get_states(
                    {resource["entity_id"]}
                )
                if item.get("entity_id") == resource["entity_id"]
            )
        except StopIteration:
            handler._send_json(404, {"error": "Number entity not found"})
            return
        except HomeAssistantError as error:
            handler._send_ha_error(error)
            return
        attributes = state.get("attributes") or {}
        capability = normalize_capabilities(
            resource["domain"],
            state.get("state"),
            attributes,
            {item["service"] for item in resource["actions"]},
        ).get("number")
        if not capability:
            handler._send_json(
                409,
                {"error": "Value control is not currently available"},
            )
            return
        minimum = capability["min"]
        maximum = capability["max"]
        step = capability["step"]
        if value < minimum or value > maximum:
            handler._send_json(
                400,
                {"error": f"Value must be between {minimum:g} and {maximum:g}"},
            )
            return
        if not _matches_step(value, minimum, maximum, step):
            handler._send_json(
                400,
                {"error": f"Value must use a step of {step:g}"},
            )
            return
        service_data["value"] = value

    elif resource["domain"] in {"select", "input_select"}:
        option = str(payload.get("option", "")).strip()
        try:
            state = next(
                item for item in ha_client.get_states(
                    {resource["entity_id"]}
                )
                if item.get("entity_id") == resource["entity_id"]
            )
        except StopIteration:
            handler._send_json(404, {"error": "Select entity not found"})
            return
        except HomeAssistantError as error:
            handler._send_ha_error(error)
            return
        capability = normalize_capabilities(
            resource["domain"],
            state.get("state"),
            state.get("attributes") or {},
            {item["service"] for item in resource["actions"]},
        ).get("select")
        if not capability or option not in capability["options"]:
            handler._send_json(400, {"error": "Unsupported option"})
            return
        service_data["option"] = option

    elif resource["domain"] == "fan" and action["service"] == "set_percentage":
        try:
            percentage = int(payload.get("percentage"))
        except (TypeError, ValueError, OverflowError):
            handler._send_json(400, {"error": "A percentage is required"})
            return
        try:
            state = next(
                item for item in ha_client.get_states(
                    {resource["entity_id"]}
                )
                if item.get("entity_id") == resource["entity_id"]
            )
        except StopIteration:
            handler._send_json(404, {"error": "Fan entity not found"})
            return
        except HomeAssistantError as error:
            handler._send_ha_error(error)
            return
        capability = normalize_capabilities(
            "fan",
            state.get("state"),
            state.get("attributes") or {},
            {item["service"] for item in resource["actions"]},
        ).get("fan_percentage")
        allowed_values = capability.get("values", []) if capability else []
        if percentage not in allowed_values:
            handler._send_json(
                400,
                {"error": "Unsupported fan percentage"},
            )
            return
        service_data["percentage"] = percentage

    elif resource["domain"] == "light" and action["service"] == "turn_on":
        if "brightness_pct" in payload:
            try:
                brightness = int(payload["brightness_pct"])
            except (TypeError, ValueError, OverflowError):
                handler._send_json(400, {"error": "A brightness percentage is required"})
                return
            if brightness < 1 or brightness > 100:
                handler._send_json(
                    400,
                    {"error": "Brightness must be between 1 and 100"},
                )
                return
            service_data["brightness_pct"] = brightness

    elif resource["domain"] == "media_player" and action["service"] == "volume_set":
        try:
            volume = float(payload.get("volume_level"))
        except (TypeError, ValueError):
            handler._send_json(400, {"error": "A volume level is required"})
            return
        if not math.isfinite(volume):
            handler._send_json(400, {"error": "A finite volume level is required"})
            return
        if volume < 0 or volume > 1:
            handler._send_json(400, {"error": "Volume must be between 0 and 1"})
            return
        service_data["volume_level"] = volume

    try:
        ha_client.call_service(
            resource["domain"],
            action["service"],
            resource["entity_id"],
            service_data,
            page_id=page["id"],
            resource_id=resource_id,
            action_id=action_id,
            **({"grant_deadline": handler.action_deadline} if isinstance(getattr(handler, "action_deadline", None), str) else {}),
        )
    except HomeAssistantError as error:
        handler._record_guest_action(
            resource,
            action,
            service_data,
            "failed",
            "Home Assistant rejected the action",
        )
        handler._record_security_event(
            page["id"],
            "home_assistant_action_rejected",
                grant_id=getattr(handler, "active_grant", {}).get("id"),
            details={
                "resource_id": resource_id,
                "action_id": action_id,
                "reason": "upstream_rejection",
            },
        )
        handler._send_ha_error(error)
        return

    handler._record_guest_action(
        resource,
        action,
        service_data,
        "success",
    )
    grant_id = getattr(handler, "active_grant", {}).get("id", "preview")
    if getattr(handler, "page_attributed_access", False):
        grant_id = "page"
    audit(
        "action_executed",
        page_id=page["id"],
        grant_id=grant_id,
        resource_id=resource_id,
        entity_id=resource["entity_id"],
        action_id=action_id,
        client_ip=handler.client_address[0],
    )
    handler._send_json(
        200,
        {
            "success": True,
            "page": page["id"],
            "resource": resource_id,
            "action": action_id,
        },
    )
