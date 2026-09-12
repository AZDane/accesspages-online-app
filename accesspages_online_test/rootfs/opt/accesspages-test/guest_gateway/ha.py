import json
import math
import os
from pathlib import Path
from contextvars import ContextVar
from time import monotonic
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

# Each HTTP request binds its authorized page before contacting the HA broker.
# ContextVar keeps simultaneous requests on the shared Gateway independent.
AUTHORIZED_NHP_PAGE = ContextVar('authorized_nhp_page', default='')


CURATED_ACTIONS = {
    "lock": {
        "lock": "Lock",
        "unlock": "Unlock",
    },
    "cover": {
        "open_cover": "Open",
        "close_cover": "Close",
        "stop_cover": "Stop",
    },
    "switch": {
        "turn_on": "Turn on",
        "turn_off": "Turn off",
    },
    "input_boolean": {
        "turn_on": "Turn on",
        "turn_off": "Turn off",
    },
    "sensor": {
        "view": "Display",
    },
    "light": {
        "turn_on": "Turn on",
        "turn_off": "Turn off",
    },
    "climate": {
        "set_temperature": "Set temperature",
        "set_hvac_mode": "Set mode",
    },
    "fan": {
        "turn_on": "Turn on",
        "turn_off": "Turn off",
        "set_percentage": "Set speed",
    },
    "button": {"press": "Press"},
    "input_button": {"press": "Press"},
    "number": {"set_value": "Set value"},
    "input_number": {"set_value": "Set value"},
    "select": {"select_option": "Select option"},
    "input_select": {"select_option": "Select option"},
    "vacuum": {
        "start": "Start",
        "pause": "Pause",
        "stop": "Stop",
        "return_to_base": "Return to base",
    },
    "media_player": {
        "media_play": "Play",
        "media_pause": "Pause",
        "media_stop": "Stop",
        "volume_set": "Set volume",
    },
    "script": {
        "turn_on": "Run",
    },
    "scene": {
        "turn_on": "Activate",
    },
}

HIDDEN_STATES = {"unavailable", "unknown"}
CAMERA_IMAGE_MAX_BYTES = 5 * 1024 * 1024
CAMERA_IMAGE_TYPES = frozenset({
    "image/jpeg",
    "image/jpg",
    "image/png",
    "image/webp",
})


def distance_meters(latitude_one, longitude_one, latitude_two, longitude_two):
    """Return the great-circle distance between two WGS84 coordinates."""
    earth_radius = 6371008.8
    lat_one = math.radians(latitude_one)
    lat_two = math.radians(latitude_two)
    lat_delta = lat_two - lat_one
    lon_delta = math.radians(longitude_two - longitude_one)
    value = (
        math.sin(lat_delta / 2) ** 2
        + math.cos(lat_one) * math.cos(lat_two)
        * math.sin(lon_delta / 2) ** 2
    )
    return earth_radius * 2 * math.atan2(math.sqrt(value), math.sqrt(1 - value))


def _finite_number(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _small_discrete_values(minimum, maximum, step, limit=6):
    count = round((maximum - minimum) / step)
    if count < 0 or count + 1 > limit:
        return []
    values = [
        round(minimum + (index * step), 9)
        for index in range(count + 1)
    ]
    if not math.isclose(values[-1], maximum, abs_tol=1e-7):
        return []
    return [
        int(value) if float(value).is_integer() else value
        for value in values
    ]


def normalize_capabilities(domain, state, attributes, action_services=()):
    """Return the safe, entity-specific controls advertised by HA."""
    attributes = attributes or {}
    action_services = set(action_services)
    capabilities = {}

    if domain in {"number", "input_number"} and "set_value" in action_services:
        minimum = _finite_number(attributes.get("min"))
        maximum = _finite_number(attributes.get("max"))
        step = _finite_number(attributes.get("step"))
        value = _finite_number(state)
        if (
            minimum is not None
            and maximum is not None
            and step is not None
            and step > 0
            and value is not None
            and minimum <= value <= maximum
        ):
            number = {
                "min": minimum,
                "max": maximum,
                "step": step,
                "value": value,
            }
            values = _small_discrete_values(minimum, maximum, step)
            if values:
                number["values"] = values
            capabilities["number"] = number

    if domain == "fan" and "set_percentage" in action_services:
        percentage = _finite_number(attributes.get("percentage"))
        percentage_step = _finite_number(attributes.get("percentage_step"))
        if (
            percentage is not None
            and percentage_step is not None
            and percentage_step > 0
        ):
            level_count = max(1, round(100 / percentage_step))
            values = (
                [
                    100 if index == level_count - 1
                    else math.floor(((index + 1) * 100) / level_count)
                    for index in range(level_count)
                ]
                if level_count <= 100
                else []
            )
            if values:
                capabilities["fan_percentage"] = {
                    "value": percentage,
                    "values": values,
                }

    if domain == "climate":
        climate = {}
        if "set_temperature" in action_services:
            minimum = _finite_number(attributes.get("min_temp"))
            maximum = _finite_number(attributes.get("max_temp"))
            raw_step = attributes.get("target_temp_step")
            step = 1.0 if raw_step is None else _finite_number(raw_step)
            value = _finite_number(attributes.get("temperature"))
            if (
                minimum is not None
                and maximum is not None
                and step is not None
                and step > 0
                and value is not None
                and minimum <= value <= maximum
            ):
                climate["temperature"] = {
                    "min": minimum,
                    "max": maximum,
                    "step": step,
                    "value": value,
                    "unit": attributes.get("temperature_unit") or "°",
                }
        modes = attributes.get("hvac_modes")
        if (
            "set_hvac_mode" in action_services
            and isinstance(modes, list)
            and all(isinstance(mode, str) for mode in modes)
            and modes
        ):
            climate["hvac_modes"] = modes
        if climate:
            capabilities["climate"] = climate

    if domain in {"select", "input_select"} and "select_option" in action_services:
        options = attributes.get("options")
        if (
            isinstance(options, list)
            and options
            and all(isinstance(option, str) for option in options)
        ):
            capabilities["select"] = {
                "value": state,
                "options": options,
            }

    if domain == "light" and "turn_on" in action_services:
        brightness = _finite_number(attributes.get("brightness"))
        if brightness is not None and 0 <= brightness <= 255:
            capabilities["brightness"] = {
                "min": 1,
                "max": 100,
                "step": 1,
                "value": max(1, round((brightness / 255) * 100)),
            }

    if domain == "media_player" and "volume_set" in action_services:
        volume = _finite_number(attributes.get("volume_level"))
        if volume is not None and 0 <= volume <= 1:
            capabilities["volume"] = {
                "min": 0,
                "max": 100,
                "step": 1,
                "value": round(volume * 100),
            }

    if domain == "cover":
        position = _finite_number(attributes.get("current_position"))
        capabilities["cover"] = {
            "position": position if position is not None else None,
            "operations": [
                service for service in ("open_cover", "close_cover", "stop_cover")
                if service in action_services
            ],
        }

    return capabilities


class HomeAssistantError(Exception):
    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        detail: str | None = None,
    ):
        super().__init__(message)
        self.status = status
        self.detail = detail


class HomeAssistantClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        timeout: int = 10,
        *,
        include_areas: frozenset[str] = frozenset(),
        include_domains: frozenset[str] = frozenset(),
        include_device_classes: frozenset[str] = frozenset(),
        include_entities: frozenset[str] = frozenset(),
        exclude_areas: frozenset[str] = frozenset(),
        exclude_domains: frozenset[str] = frozenset(),
        exclude_device_classes: frozenset[str] = frozenset(),
        exclude_entities: frozenset[str] = frozenset(),
    ):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.include_areas = include_areas
        self.include_domains = include_domains
        self.include_device_classes = include_device_classes
        self.include_entities = include_entities
        self.exclude_areas = exclude_areas
        self.exclude_domains = exclude_domains
        self.exclude_device_classes = exclude_device_classes
        self.exclude_entities = exclude_entities
        self._discovery_cache = None
        self._discovery_cached_at = 0.0

    @property
    def policy_restricted(self) -> bool:
        return bool(
            self.include_areas
            or self.include_domains
            or self.include_device_classes
            or self.include_entities
        )

    def entity_allowed(
        self,
        entity_id: str,
        domain: str,
        device_class: str = "",
        area_id: str = "",
    ) -> bool:
        if (
            entity_id in self.exclude_entities
            or domain in self.exclude_domains
            or (area_id and area_id in self.exclude_areas)
            or (
                device_class
                and device_class in self.exclude_device_classes
            )
        ):
            return False

        if not self.policy_restricted:
            return True

        return bool(
            entity_id in self.include_entities
            or domain in self.include_domains
            or (area_id and area_id in self.include_areas)
            or (
                device_class
                and device_class in self.include_device_classes
            )
        )

    def _request(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
    ) -> dict | list:
        data = None
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
        }

        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"

        request = Request(
            f"{self.base_url}{path}",
            data=data,
            method=method,
            headers=headers,
        )

        try:
            # The base URL is administrator-controlled Home Assistant config.
            with urlopen(request, timeout=self.timeout) as response:  # nosec B310
                body = response.read()
                if not body:
                    return {}
                return json.loads(body.decode("utf-8"))

        except HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            raise HomeAssistantError(
                "Home Assistant returned an error",
                status=error.code,
                detail=detail,
            ) from error

        except URLError as error:
            raise HomeAssistantError(
                "Could not reach Home Assistant",
                detail=str(error.reason),
            ) from error

        except json.JSONDecodeError as error:
            raise HomeAssistantError(
                "Home Assistant returned invalid JSON",
                detail=str(error),
            ) from error

    def call_service(
        self,
        domain: str,
        service: str,
        entity_id: str,
        service_data: dict | None = None,
        *,
        page_id: str = "",
        resource_id: str = "",
        action_id: str = "",
    ) -> dict | list:
        payload = {"entity_id": entity_id}
        if service_data:
            payload.update(service_data)

        return self._request(
            "POST",
            f"/api/services/{domain}/{service}",
            payload,
        )

    def get_camera_image(self, entity_id, **_policy):
        if not isinstance(entity_id, str) or not entity_id.startswith("camera."):
            raise HomeAssistantError("Camera entity is invalid")
        request = Request(
            f"{self.base_url}/api/camera_proxy/{quote(entity_id, safe='')}",
            method="GET",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "image/jpeg,image/png,image/webp",
            },
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:  # nosec B310
                content_type = response.headers.get_content_type().lower()
                if content_type not in CAMERA_IMAGE_TYPES:
                    raise HomeAssistantError(
                        "Home Assistant returned an unsupported camera image"
                    )
                length = response.headers.get("Content-Length")
                if length:
                    try:
                        if int(length) > CAMERA_IMAGE_MAX_BYTES:
                            raise HomeAssistantError("Camera image is too large")
                    except ValueError as error:
                        raise HomeAssistantError(
                            "Home Assistant returned an invalid camera image"
                        ) from error
                body = response.read(CAMERA_IMAGE_MAX_BYTES + 1)
                if not body or len(body) > CAMERA_IMAGE_MAX_BYTES:
                    raise HomeAssistantError("Camera image is too large")
                return body, content_type
        except HTTPError as error:
            raise HomeAssistantError(
                "Home Assistant returned an error",
                status=error.code,
            ) from error
        except URLError as error:
            raise HomeAssistantError(
                "Could not reach Home Assistant",
                detail=str(error.reason),
            ) from error

    def get_states(
        self,
        entity_ids: set[str] | frozenset[str] | None = None,
    ) -> list[dict]:
        result = self._request("GET", "/api/states")
        if not isinstance(result, list):
            raise HomeAssistantError("Home Assistant returned an invalid state list")
        if entity_ids is None:
            return result
        return [
            state
            for state in result
            if state.get("entity_id") in entity_ids
        ]

    def get_services(self) -> list[dict]:
        result = self._request("GET", "/api/services")
        if not isinstance(result, list):
            raise HomeAssistantError("Home Assistant returned an invalid service list")
        return result

    def get_location(self) -> dict:
        result = self._request("GET", "/api/config")
        if not isinstance(result, dict):
            raise HomeAssistantError("Home Assistant returned invalid configuration")
        latitude = _finite_number(result.get("latitude"))
        longitude = _finite_number(result.get("longitude"))
        if (
            latitude is None
            or longitude is None
            or not -90 <= latitude <= 90
            or not -180 <= longitude <= 180
        ):
            raise HomeAssistantError("Home Assistant has no valid registered location")
        return {"latitude": latitude, "longitude": longitude}

    def verify_proximity(self, page_id, reading, radius_meters):
        home = self.get_location()
        distance = distance_meters(
            float(reading["latitude"]),
            float(reading["longitude"]),
            home["latitude"],
            home["longitude"],
        )
        return distance <= radius_meters

    def get_entity_areas(self) -> dict[str, dict]:
        # Home Assistant's REST API does not expose registry lists directly.
        # This fixed, non-user-controlled template uses HA's public area helper
        # functions to return only entity/area identifiers and display names.
        template = """
{% set ns = namespace(items=[]) %}
{% for area_id in areas() %}
  {% for entity_id in area_entities(area_id) %}
    {% set ns.items = ns.items + [{
      "entity_id": entity_id,
      "area_id": area_id,
      "area_name": area_name(area_id)
    }] %}
  {% endfor %}
{% endfor %}
{{ ns.items | to_json }}
""".strip()
        result = self._request(
            "POST",
            "/api/template",
            {"template": template},
        )
        if not isinstance(result, list):
            raise HomeAssistantError(
                "Home Assistant returned invalid area metadata"
            )
        return {
            str(item.get("entity_id", "")): {
                "area_id": str(item.get("area_id", "")),
                "area_name": str(item.get("area_name", "")),
            }
            for item in result
            if isinstance(item, dict) and item.get("entity_id")
        }

    def discover_entities(self, *, force: bool = False) -> dict:
        if (
            not force
            and self._discovery_cache is not None
            and monotonic() - self._discovery_cached_at < 30
        ):
            return self._discovery_cache

        states = self.get_states()
        try:
            entity_areas = self.get_entity_areas()
        except HomeAssistantError:
            # Area browsing is an enhancement; state/action discovery remains
            # useful on older HA versions where template helpers are absent.
            entity_areas = {}
        service_domains = {
            item.get("domain"): item.get("services", {})
            for item in self.get_services()
            if isinstance(item, dict) and item.get("domain")
        }

        entities = []

        for state in states:
            entity_id = state.get("entity_id", "")
            if "." not in entity_id:
                continue

            domain, _ = entity_id.split(".", 1)
            attributes = state.get("attributes") or {}
            device_class = str(attributes.get("device_class") or "")
            area = entity_areas.get(entity_id, {})

            if not self.entity_allowed(
                entity_id,
                domain,
                device_class,
                area.get("area_id", ""),
            ):
                continue

            entity_state = state.get("state")
            if (
                entity_state in HIDDEN_STATES
                and domain not in {"button", "input_button"}
            ):
                continue

            available_services = service_domains.get(domain, {})
            curated_services = CURATED_ACTIONS.get(domain, {})
            actions = []

            for service_name, display_name in curated_services.items():
                # Sensors are read-only.  The synthetic "view" action allows
                # the admin UI to include them without exposing a HA service.
                if domain == "sensor" and service_name == "view":
                    actions.append(
                        {
                            "service": "view",
                            "name": display_name,
                            "description": "Show this sensor as read-only",
                            "fields": {},
                        }
                    )
                    continue

                service_definition = available_services.get(service_name)

                if not isinstance(service_definition, dict):
                    continue

                # Home Assistant uses target metadata for services that can be
                # applied to an entity, device, or area.
                if service_definition.get("target") is None:
                    continue

                actions.append(
                    {
                        "service": service_name,
                        "name": display_name,
                        "description": service_definition.get("description", ""),
                        "fields": service_definition.get("fields", {}),
                    }
                )

            # Every available HA entity can be deliberately shared read-only.
            # Only curated domains gain service actions.
            if not actions:
                actions.append(
                    {
                        "service": "view",
                        "name": "Display",
                        "description": "Show this entity as read-only",
                        "fields": {},
                    }
                )

            entities.append(
                {
                    "entity_id": entity_id,
                    "domain": domain,
                    "name": attributes.get("friendly_name") or entity_id,
                    "state": entity_state,
                    "device_class": device_class,
                    "type": device_class or domain,
                    "area_id": area.get("area_id", ""),
                    "area_name": area.get("area_name", ""),
                    "attributes": attributes,
                    "actions": actions,
                }
            )

        entities.sort(key=lambda entity: (entity["domain"], entity["name"].lower()))

        domain_counts = {}
        for entity in entities:
            domain_counts[entity["domain"]] = (
                domain_counts.get(entity["domain"], 0) + 1
            )

        result = {
            "entity_count": len(entities),
            "domain_count": len(domain_counts),
            "domain_counts": domain_counts,
            "allowed_domains": sorted(domain_counts),
            "policy": {
                "restricted": self.policy_restricted,
                "include_areas": sorted(self.include_areas),
                "include_domains": sorted(self.include_domains),
                "include_device_classes": sorted(
                    self.include_device_classes
                ),
                "include_entities": sorted(self.include_entities),
                "exclude_domains": sorted(self.exclude_domains),
                "exclude_areas": sorted(self.exclude_areas),
                "exclude_device_classes": sorted(
                    self.exclude_device_classes
                ),
                "exclude_entities": sorted(self.exclude_entities),
            },
            "entities": entities,
        }
        self._discovery_cache = result
        self._discovery_cached_at = monotonic()
        return result


class BrokerHomeAssistantClient(HomeAssistantClient):
    """Credential-free client for the policy-enforcing HA broker."""

    def __init__(
        self,
        broker_url: str,
        broker_token: str,
        *,
        broker_role: str = "guest",
        **policy,
    ):
        super().__init__(base_url=broker_url, token=broker_token, **policy)
        if broker_role not in {"guest", "admin"}:
            raise ValueError("Broker role must be guest or admin")
        self.broker_role = broker_role

    def _request_token(self, page_id=''):
        path = os.getenv('NHP_PAGE_CAPABILITIES_FILE', '')
        if self.broker_role != 'guest' or not path:
            return self.token
        authorized = AUTHORIZED_NHP_PAGE.get()
        if not authorized or (page_id and page_id != authorized):
            raise HomeAssistantError('Authorized page required for HA broker')
        try:
            value = json.loads(Path(path).read_text())[authorized]
            if not isinstance(value, str) or len(value) != 43:
                raise ValueError()
            return value
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise HomeAssistantError('Page capability unavailable') from error

    def _request(self, method, path, payload=None):
        data = None
        headers = {
            "X-Broker-Token": self._request_token((payload or {}).get('page_id', '')),
            "X-Broker-Role": self.broker_role,
            "Accept": "application/json",
        }
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(
            f"{self.base_url}{path}",
            data=data,
            method=method,
            headers=headers,
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:  # nosec B310
                body = response.read()
                return json.loads(body.decode("utf-8")) if body else {}
        except HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            raise HomeAssistantError(
                "Home Assistant broker rejected the request",
                status=error.code,
                detail=detail,
            ) from error
        except URLError as error:
            raise HomeAssistantError(
                "Could not reach Home Assistant broker",
                detail=str(error.reason),
            ) from error
        except json.JSONDecodeError as error:
            raise HomeAssistantError(
                "Home Assistant broker returned invalid JSON",
            ) from error

    def get_camera_image(self, entity_id, *, page_id="", resource_id=""):
        if not page_id or not resource_id:
            raise HomeAssistantError(
                "Broker camera requests require saved policy identifiers"
            )
        data = json.dumps({
            "page_id": page_id,
            "resource_id": resource_id,
        }).encode("utf-8")
        request = Request(
            f"{self.base_url}/v1/camera-image",
            data=data,
            method="POST",
            headers={
                "X-Broker-Token": self._request_token(page_id),
                "X-Broker-Role": self.broker_role,
                "Content-Type": "application/json",
                "Accept": "image/jpeg,image/png,image/webp",
            },
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:  # nosec B310
                content_type = response.headers.get_content_type().lower()
                if content_type not in CAMERA_IMAGE_TYPES:
                    raise HomeAssistantError(
                        "Home Assistant broker returned an unsupported camera image"
                    )
                body = response.read(CAMERA_IMAGE_MAX_BYTES + 1)
                if not body or len(body) > CAMERA_IMAGE_MAX_BYTES:
                    raise HomeAssistantError("Camera image is too large")
                return body, content_type
        except HTTPError as error:
            raise HomeAssistantError(
                "Home Assistant broker rejected the request",
                status=error.code,
            ) from error
        except URLError as error:
            raise HomeAssistantError(
                "Could not reach Home Assistant broker",
                detail=str(error.reason),
            ) from error

    def get_states(self, entity_ids=None):
        if not entity_ids:
            raise HomeAssistantError(
                "Broker state requests require assigned entity IDs"
            )
        result = self._request(
            "POST",
            "/v1/states",
            {"entity_ids": sorted(entity_ids)},
        )
        if not isinstance(result, list):
            raise HomeAssistantError(
                "Home Assistant broker returned an invalid state list"
            )
        return result

    def call_service(
        self,
        domain,
        service,
        entity_id,
        service_data=None,
        *,
        page_id="",
        resource_id="",
        action_id="",
    ):
        if not page_id or not resource_id or not action_id:
            raise HomeAssistantError(
                "Broker actions require saved policy identifiers"
            )
        return self._request(
            "POST",
            "/v1/page-action",
            {
                "page_id": page_id,
                "resource_id": resource_id,
                "action_id": action_id,
                "parameters": service_data or {},
            },
        )

    def verify_proximity(self, page_id, reading, radius_meters):
        result = self._request(
            "POST",
            "/v1/proximity",
            {"page_id": page_id, "reading": reading},
        )
        if not isinstance(result, dict) or not isinstance(
            result.get("within_range"), bool
        ):
            raise HomeAssistantError(
                "Home Assistant broker returned invalid proximity data"
            )
        return result["within_range"]

    def notification_targets(self):
        return self._request(
            "POST",
            "/v1/notification-targets",
            {},
        ).get("targets", [])

    def send_notification(self, target, title, message):
        return self._request(
            "POST",
            "/v1/send-notification",
            {"target": target, "title": title, "message": message},
        )

    def discover_entities(self, *, force=False):
        result = self._request(
            "POST",
            "/v1/discovery",
            {"force": bool(force)},
        )
        if not isinstance(result, dict):
            raise HomeAssistantError(
                "Home Assistant broker returned invalid discovery data"
            )
        return result
