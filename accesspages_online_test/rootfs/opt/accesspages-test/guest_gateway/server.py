from datetime import datetime, timedelta, timezone
from contextlib import ExitStack, contextmanager
from hashlib import sha256
from http import HTTPStatus
from http.client import HTTPConnection, HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import BoundedSemaphore, Lock, RLock, Thread
from urllib.parse import parse_qs, quote, urlencode, urlparse
import base64
import hmac
import json
import feature_policy
import math
import re
import mimetypes
import os
import secrets
import sqlite3
import sys
import time

import access as access_routes
import admin as admin_routes
import internal as internal_routes
from activity import BrokerGuestActivityStore, GuestActivityStore
from actions import execute_public_action
from audit import audit
from rate_limit import MinimumIntervalRateLimiter, SlidingWindowRateLimiter
from config import (
    ADMIN_TOKEN,
    ACTIVITY_DB_FILE,
    ACTIVITY_BROKER_URL,
    CONNECTOR_PAGE_ROUTES_FILE,
    CONNECTOR_STATUS_FILE,
    GATEWAY_VERSION,
    GATEWAY_ROLE,
    GATEWAY_BOUND_PAGE_ID,
    HA_BASE_URL,
    HA_BROKER_TOKEN,
    HA_BROKER_URL,
    HA_ENTITY_EXCLUDE_AREAS,
    HA_ENTITY_EXCLUDE_DEVICE_CLASSES,
    HA_ENTITY_EXCLUDE_DOMAINS,
    HA_ENTITY_EXCLUDE_ENTITIES,
    HA_ENTITY_INCLUDE_DEVICE_CLASSES,
    HA_ENTITY_INCLUDE_AREAS,
    HA_ENTITY_INCLUDE_DOMAINS,
    HA_ENTITY_INCLUDE_ENTITIES,
    HA_TOKEN,
    HOST,
    ACCESS_LINK_MAX_LIFETIME_DAYS,
    PAGES_DIR,
    PAGE_CAPABILITY_REGISTRY_FILE,
    PAGE_CAPABILITY_TOKEN,
    PORT,
    POLICY_PUBLISH_TOKEN,
    POLICY_PUBLISH_URL,
    RESET_REQUEST_FILE,
    SMTP_CONFIG_FILE,
    ALERT_CONFIG_FILE,
    VERIFICATION_BROKER_URL,
    VERIFICATION_DB_FILE,
    VERIFICATION_RECIPIENT_FILE,
)
from email_delivery import (
    EmailConfigError,
    SMTPConfigStore,
    NotificationTargetStore,
    VerificationRecipientStore,
    guest_invitation_email_content,
    send_email,
    verification_email_content,
    validate_email,  # exported through the shared route runtime
)
from ha import (
    BrokerHomeAssistantClient,
    HomeAssistantClient,
    HomeAssistantError,
    nhp_page_capability,
    normalize_capabilities,
)
from access_service import AccessServiceError
from pages import (
    PageConfigError,
    PageNotFoundError,
    PageStore,
    page_admin_view,  # noqa: F401 - exported through the shared route runtime
    validate_notifications,
)
from policy import (
    PolicyPublisher,
    PolicyPublishError,  # noqa: F401 - exported through the shared route runtime
)
from verification import VerificationStore
import nhp


PROXIMITY_READING_MAX_AGE_SECONDS = 300
PROXIMITY_MAX_ACCURACY_METERS = 1000

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

ACCESS_LINK_LIFETIME_RE = re.compile(r"^([1-9][0-9]{0,4})([mhdw])$")
ACCESS_LINK_MAX_LIFETIME = timedelta(days=ACCESS_LINK_MAX_LIFETIME_DAYS)


def parse_access_link_lifetime(value):
    lifetime = str(value).strip().lower()
    match = ACCESS_LINK_LIFETIME_RE.fullmatch(lifetime)
    if not match:
        raise ValueError(
            "Use a whole-number duration such as 30m, 12h, 3d, or 1w"
        )

    amount = int(match.group(1))
    unit = match.group(2)
    multipliers = {
        "m": timedelta(minutes=1),
        "h": timedelta(hours=1),
        "d": timedelta(days=1),
        "w": timedelta(weeks=1),
    }
    duration = amount * multipliers[unit]
    if duration > ACCESS_LINK_MAX_LIFETIME:
        raise ValueError(
            "AccessLink lifetime exceeds the configured maximum of "
            f"{ACCESS_LINK_MAX_LIFETIME_DAYS} days"
        )
    return lifetime, duration

HA_CLIENT_CLASS = (
    BrokerHomeAssistantClient
    if HA_BROKER_URL
    else HomeAssistantClient
)
HA_CLIENT = HA_CLIENT_CLASS(
    **(
        {
            "broker_url": HA_BROKER_URL,
            "broker_token": HA_BROKER_TOKEN,
            "broker_role": (
                "admin" if GATEWAY_ROLE in {"admin", "combined"} else "guest"
            ),
        }
        if HA_BROKER_URL
        else {"base_url": HA_BASE_URL, "token": HA_TOKEN}
    ),
    include_areas=HA_ENTITY_INCLUDE_AREAS,
    include_domains=HA_ENTITY_INCLUDE_DOMAINS,
    include_device_classes=HA_ENTITY_INCLUDE_DEVICE_CLASSES,
    include_entities=HA_ENTITY_INCLUDE_ENTITIES,
    exclude_areas=HA_ENTITY_EXCLUDE_AREAS,
    exclude_domains=HA_ENTITY_EXCLUDE_DOMAINS,
    exclude_device_classes=HA_ENTITY_EXCLUDE_DEVICE_CLASSES,
    exclude_entities=HA_ENTITY_EXCLUDE_ENTITIES,
)
PAGE_STORE = PageStore(
    PAGES_DIR,
    file_mode=int(os.getenv("PAGE_FILE_MODE", "600"), 8),
)
POLICY_PUBLISHER = PolicyPublisher(
    POLICY_PUBLISH_URL,
    POLICY_PUBLISH_TOKEN,
)
ACTIVITY_STORE = (
    BrokerGuestActivityStore(
        ACTIVITY_BROKER_URL, PAGE_CAPABILITY_TOKEN, GATEWAY_BOUND_PAGE_ID,
    )
    if GATEWAY_ROLE == "guest" and ACTIVITY_BROKER_URL
    else GuestActivityStore(ACTIVITY_DB_FILE)
)
SMTP_CONFIG_STORE = SMTPConfigStore(SMTP_CONFIG_FILE)
NOTIFICATION_TARGET_STORE = NotificationTargetStore(ALERT_CONFIG_FILE)
VERIFICATION_STORE = VerificationStore(VERIFICATION_DB_FILE)
VERIFICATION_RECIPIENTS = VerificationRecipientStore(
    VERIFICATION_RECIPIENT_FILE,
)
ACTION_RATE_LIMITER = SlidingWindowRateLimiter(limit=12, window_seconds=60)
UNAUTHORIZED_READ_RATE_LIMITER = SlidingWindowRateLimiter(
    limit=30,
    window_seconds=60,
)
SECURITY_EVENT_RATE_LIMITER = SlidingWindowRateLimiter(
    limit=10,
    window_seconds=60,
)
CAMERA_IMAGE_RATE_LIMITER = SlidingWindowRateLimiter(
    limit=10,
    window_seconds=60,
)
CAMERA_REFRESH_RATE_LIMITER = MinimumIntervalRateLimiter(max_entries=10000)
MANUAL_CAMERA_MIN_INTERVAL_SECONDS = 2
_PAGE_ACTION_LOCKS = {}
_PAGE_ACTION_LOCKS_GUARD = Lock()
RUNTIME = sys.modules[__name__]


@contextmanager
def page_action_lock(page_id):
    """Return the lock that linearizes actions and local revocation per page."""
    with _PAGE_ACTION_LOCKS_GUARD:
        entry = _PAGE_ACTION_LOCKS.setdefault(
            page_id,
            {"lock": RLock(), "users": 0},
        )
        entry["users"] += 1
    entry["lock"].acquire()
    try:
        yield
    finally:
        entry["lock"].release()
        with _PAGE_ACTION_LOCKS_GUARD:
            entry["users"] -= 1
            if entry["users"] == 0 and _PAGE_ACTION_LOCKS.get(page_id) is entry:
                del _PAGE_ACTION_LOCKS[page_id]


def access_service_error_diagnostics(error):
    """Return non-sensitive fields suitable for operational audit logs."""
    status = error.status if isinstance(error.status, int) else None
    if status in (401, 403):
        category = "authentication"
    elif status == 429:
        category = "rate_limit"
    elif status is not None and status >= 500:
        category = "upstream"
    elif status is not None:
        category = "api_rejection"
    else:
        category = "network_or_protocol"
    diagnostics = {"error_category": category}
    if status is not None:
        diagnostics["http_status"] = status
    return diagnostics


class GatewayHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64
    connection_timeout = 15
    max_active_requests = 64

    def __init__(self, *args, **kwargs):
        self._request_slots = BoundedSemaphore(self.max_active_requests)
        super().__init__(*args, **kwargs)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(self.connection_timeout)
        return connection, address

    def process_request(self, request, client_address):
        if not self._request_slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


ACCESS_SERVICE_CLIENT = nhp.NHPClient()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def token_hash(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()





class Handler(BaseHTTPRequestHandler):
    max_header_count = 64
    max_header_bytes = 32 * 1024

    server_version = "GuestGateway/0.5"

    def _role_allows(self, path):
        if path == "/admin" or path.startswith("/api/admin/"):
            return GATEWAY_ROLE in {"admin", "combined"}
        if path.startswith("/access/") or path.startswith("/api/access/"):
            return (
                GATEWAY_ROLE in {"admin", "guest", "combined"}
                or bool(self._proxied_page_id())
            )
        if path.startswith("/api/internal/"):
            return GATEWAY_ROLE in {"admin", "combined"}
        return True

    def _require_role(self, path):
        if self._role_allows(path):
            return True
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
        return False

    def _validate_entity_policy(self, payload):
        try:
            feature_policy.validate_page(payload)
        except ValueError as error:
            raise PageConfigError(str(error)) from error
        resources = payload.get("resources", [])
        if not resources:
            return
        discovered = {
            item["entity_id"]: item
            for item in HA_CLIENT.discover_entities()["entities"]
        }
        for resource in resources:
            if not isinstance(resource, dict):
                continue
            entity_id = str(resource.get("entity_id", "")).strip()
            domain = str(resource.get("domain", "")).strip()
            entity = discovered.get(entity_id)
            if (
                entity is None
                or domain != entity.get("domain")
                or not HA_CLIENT.entity_allowed(
                    entity_id,
                    domain,
                    entity.get("device_class", ""),
                    entity.get("area_id", ""),
                )
            ):
                raise PageConfigError(
                    f"Entity is unavailable under the gateway policy: "
                    f"{entity_id}"
                )

            allowed_actions = {
                str(action.get("service", "")): str(action.get("name", ""))
                for action in entity.get("actions", [])
                if isinstance(action, dict) and action.get("service")
            }
            for action in resource.get("actions", []):
                if not isinstance(action, dict):
                    raise PageConfigError(f"Invalid action for {entity_id}")
                action_id = str(action.get("id", "")).strip()
                service = str(action.get("service", "")).strip()
                name = str(action.get("name", "")).strip()
                if (
                    service not in allowed_actions
                    or action_id != service
                    or name != allowed_actions[service]
                ):
                    raise PageConfigError(
                        f"Action is unavailable under the gateway policy: "
                        f"{domain}.{service or action_id}"
                    )

    def log_message(self, format, *args):
        # Avoid writing query-string bearer tokens into normal request logs.
        safe_path = urlparse(self.path).path
        message = "%s - - [%s] %s\n" % (
            self.address_string(),
            self.log_date_time_string(),
            format % ((safe_path,) + args[1:])
            if args and isinstance(args[0], str) and "?" in args[0]
            else format % args,
        )
        self.stderr_write(message)

    def stderr_write(self, message):
        import sys
        sys.stderr.write(message)

    def _send_bytes(self, status, body, content_type, extra_headers=None):
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' data:; "
                "style-src 'self'; script-src 'self'; "
                "connect-src 'self'; frame-ancestors 'none';",
            )
            for name, value in (extra_headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            # Disconnected and deliberately slow clients are expected under
            # the network-abuse controls and should not create traceback noise.
            self.close_connection = True

    def _send_json(self, status, payload, extra_headers=None):
        body = json.dumps(payload).encode("utf-8")
        self._send_bytes(
            status,
            body,
            "application/json; charset=utf-8",
            extra_headers,
        )

    def send_error(self, code, message=None, explain=None):
        # BaseHTTPRequestHandler otherwise emits an HTML error without the
        # Gateway's no-store, no-referrer, nosniff, and CSP protections.
        self._send_json(code, {"error": HTTPStatus(code).phrase})

    def _valid_request_envelope(self):
        header_count = len(self.headers)
        header_bytes = sum(
            len(name.encode("utf-8"))
            + len(value.encode("utf-8"))
            + 4
            for name, value in self.headers.items()
        )
        if (
            header_count > self.max_header_count
            or header_bytes > self.max_header_bytes
        ):
            self.close_connection = True
            self._send_json(
                HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
                {"error": "Request headers are too large"},
            )
            return False
        return True

    def _send_static_file(self, filename):
        target = (STATIC_DIR / filename).resolve()

        if STATIC_DIR.resolve() not in target.parents or not target.is_file():
            self._send_json(404, {"error": "not found"})
            return

        content_type = (
            mimetypes.guess_type(target.name)[0]
            or "application/octet-stream"
        )
        self._send_bytes(200, target.read_bytes(), content_type)

    def _send_access_shell(self, page_id):
        target = STATIC_DIR / "access.html"
        body = target.read_text(encoding="utf-8").replace(
            '<html lang="en">',
            f'<html lang="en" data-page-id="{page_id}">',
            1,
        )
        self._send_bytes(200, body.encode("utf-8"), "text/html; charset=utf-8")

    def _connector_bound_page_id(self):
        if nhp.ENABLED:
            return ""
        proxied = self._proxied_page_id()
        if proxied:
            return proxied
        if GATEWAY_ROLE != "guest":
            return ""
        if GATEWAY_BOUND_PAGE_ID:
            return GATEWAY_BOUND_PAGE_ID
        local_address = self.connection.getsockname()[0]
        try:
            routes = json.loads(
                CONNECTOR_PAGE_ROUTES_FILE.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError):
            return "__unmapped_connector__"
        if not isinstance(routes, dict):
            return "__unmapped_connector__"
        return str(
            routes.get(local_address, "__unmapped_connector__")
        ).strip()

    def _proxied_page_id(self):
        cached = getattr(self, "_validated_proxied_page_id", None)
        if cached is not None:
            return cached
        headers = getattr(self, "headers", {})
        page_id = headers.get("X-Guest-Gateway-Page-ID", "").strip()
        valid = (
            GATEWAY_ROLE in {"admin", "combined"}
            and bool(page_id)
            and self._is_page_broker(page_id)
        )
        self._validated_proxied_page_id = page_id if valid else ""
        return self._validated_proxied_page_id

    def _read_json(self, max_bytes=512_000):
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError as error:
            raise ValueError("Invalid Content-Length") from error

        if content_length <= 0:
            return {}
        if content_length > max_bytes:
            raise ValueError("Request body is too large")

        body = self.rfile.read(content_length)

        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError(
                "Request body must be valid JSON"
            ) from error
        if not isinstance(payload, dict):
            raise ValueError("Request body must be a JSON object")
        return payload

    def _query(self):
        return parse_qs(urlparse(self.path).query)

    def _cookie(self, name):
        for item in self.headers.get("Cookie", "").split(";"):
            key, separator, value = item.strip().partition("=")
            if separator and key == name:
                return value
        return ""

    def _admin_token(self):
        return self.headers.get("X-Admin-Token", "")

    def _is_admin(self):
        supplied = self._admin_token().encode("utf-8")
        expected = ADMIN_TOKEN.encode("utf-8")
        return bool(supplied) and hmac.compare_digest(
            supplied,
            expected,
        )

    def _require_admin(self):
        if self._is_admin():
            return True

        self._send_json(
            HTTPStatus.UNAUTHORIZED,
            {"error": "Valid admin token required"},
        )
        return False

    def _is_page_broker(self, page_id):
        supplied = self.headers.get("X-Page-Capability", "")
        if not supplied or not page_id:
            return False
        try:
            registry = json.loads(
                PAGE_CAPABILITY_REGISTRY_FILE.read_text(encoding="utf-8")
            )
            expected = str(registry.get(page_id, ""))
        except (OSError, json.JSONDecodeError):
            return False
        return bool(expected) and hmac.compare_digest(
            sha256(supplied.encode()).hexdigest(), expected,
        )

    def _send_verification_email(self, page_id, grant, code):
        if not VERIFICATION_BROKER_URL:
            # Combined/local development mode keeps the same authoritative
            # grant lookup and never accepts a recipient from the browser.
            text, html = verification_email_content(code)
            send_email(
                SMTP_CONFIG_STORE.load(),
                VERIFICATION_RECIPIENTS.get(page_id, grant["id"]),
                "Your Access Pages verification code",
                text,
                html_body=html,
            )
            return
        body = json.dumps({
            "page_id": page_id, "grant_id": grant["id"], "code": code,
        }).encode()
        broker = urlparse(VERIFICATION_BROKER_URL)
        if broker.scheme != "http" or not broker.hostname:
            raise EmailConfigError("Verification email could not be sent")
        connection = HTTPConnection(
            broker.hostname,
            broker.port or 80,
            timeout=15,
        )
        try:
            connection.request(
                "POST",
                "/api/internal/email/verification",
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "X-Page-Capability": PAGE_CAPABILITY_TOKEN,
                },
            )
            response = connection.getresponse()
            response.read()
            if response.status != HTTPStatus.OK:
                raise EmailConfigError("Verification email could not be sent")
        except (OSError, HTTPException) as error:
            raise EmailConfigError("Verification email could not be sent") from error
        finally:
            connection.close()

    def _send_guest_notification(
        self, page_id, event_type, *, resource_id="", action_id="", outcome=""
    ):
        grant = getattr(self, "active_grant", {})
        broker_url = VERIFICATION_BROKER_URL
        capability = PAGE_CAPABILITY_TOKEN
        if nhp.ENABLED and GATEWAY_ROLE == "guest":
            _, capability = nhp_page_capability(page_id)
        if not broker_url:
            # Compiled page endpoints proxy into the trusted gateway. Re-enter
            # its narrow internal notification route on loopback so recipient
            # selection remains entirely server-controlled.
            if self._proxied_page_id() != page_id:
                return
            broker_url = f"http://127.0.0.1:{PORT}"
            capability = getattr(self, "headers", {}).get(
                "X-Page-Capability", ""
            )
            if not capability:
                return
        broker = urlparse(broker_url)
        connection = HTTPConnection(broker.hostname, broker.port, timeout=5)
        try:
            connection.request(
                "POST",
                "/api/internal/guest-notification",
                body=json.dumps({
                    "page_id": page_id,
                    "grant_id": grant.get("id", ""),
                    "event_type": event_type,
                    "resource_id": resource_id,
                    "action_id": action_id,
                    "outcome": outcome,
                }).encode("utf-8"),
                headers={
                    "X-Page-Capability": capability,
                    "Content-Type": "application/json",
                },
            )
            response = connection.getresponse()
            response.read()
            if response.status >= 400:
                raise HomeAssistantError("Guest notification failed")
        except (OSError, HTTPException) as error:
            raise HomeAssistantError("Guest notification failed") from error
        finally:
            connection.close()

    def _send_guest_invitation(
        self, page_id, grant, recipient, access_url,
    ):
        try:
            text, html = guest_invitation_email_content(
                grant["access_link_url"], access_url,
                verification_method=grant.get("verification_method", "none") if nhp.ENABLED else None,
            )
            send_email(
                SMTP_CONFIG_STORE.load(),
                recipient,
                "Your Access Pages invitation",
                text,
                html_body=html,
            )
            audit(
                "guest_invitation_email_sent",
                page_id=page_id,
                grant_id=grant["id"],
            )
            return True
        except (EmailConfigError, OSError):
            audit(
                "guest_invitation_email_failed",
                page_id=page_id,
                grant_id=grant["id"],
            )
            return False

    def _load_page(self, page_id):
        try:
            return PAGE_STORE.load(page_id)
        except (PageConfigError, PageNotFoundError) as error:
            self._send_page_error(error)
            return None

    def _active_grant_for_token(self, page, supplied_token):
        if not supplied_token:
            return None, "missing"

        supplied_hash = token_hash(supplied_token)
        now = utc_now()

        for grant in page["access_grants"]:
            if not hmac.compare_digest(
                supplied_hash,
                grant["token_hash"],
            ):
                continue

            try:
                expires_at = parse_time(grant["expires_at"])
            except ValueError:
                return None, "invalid"

            if expires_at <= now:
                return grant, "expired"

            return grant, "active"

        return None, "invalid"

    def _preview_token(self, page_id, expires_at):
        message = f"{page_id}:{expires_at}".encode("utf-8")
        signature = hmac.new(
            ADMIN_TOKEN.encode("utf-8"),
            message,
            "sha256",
        ).digest()
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        return f"{expires_at}.{encoded}"

    def _valid_preview_token(self, page_id, supplied_token):
        if GATEWAY_ROLE == "guest":
            return False
        if not supplied_token or "." not in supplied_token:
            return False

        expires_text, supplied_signature = supplied_token.split(".", 1)
        try:
            expires_at = int(expires_text)
        except ValueError:
            return False

        if expires_at <= int(utc_now().timestamp()):
            return False

        expected = self._preview_token(page_id, expires_at)
        return hmac.compare_digest(supplied_token, expected)

    def _require_page_access(self, page, *, record_invalid=False):
        # Public/OpenNHP Service authorization is deliberately separate from admin
        # authorization. An admin token is never accepted on guest routes.
        query = self._query()
        preview_token = query.get("preview_token", [""])[0]
        if self._valid_preview_token(page["id"], preview_token):
            self.camera_access_scope = "preview:" + sha256(
                preview_token.encode("utf-8")
            ).hexdigest()[:24]
            return True

        if nhp.ENABLED:
            if not nhp.authorize(self, page, RUNTIME):
                return False
            self.active_grant = {**self.active_grant, "_page_id": page["id"]}
            self._record_initial_guest_access(page, self.active_grant)
            return True

        bound_page_id = self._connector_bound_page_id()
        if bound_page_id:
            if not hmac.compare_digest(bound_page_id, page["id"]):
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return False
            now = utc_now()
            if any(
                parse_time(grant["expires_at"]) > now
                and not grant.get("verification_required")
                for grant in page["access_grants"]
            ):
                self.page_attributed_access = True
                self.camera_access_scope = "connector"
                return True
            self._send_json(
                HTTPStatus.GONE,
                {"error": "This Access Page is no longer active"},
            )
            return False

        supplied = query.get("access_token", [""])[0]
        grant, status = self._active_grant_for_token(page, supplied)

        if grant is not None and status == "active":
            self.active_grant = grant
            self.camera_access_scope = f"grant:{grant['id']}"
            try:
                ACTIVITY_STORE.register_guest(page["id"], grant)
            except (OSError, sqlite3.Error):
                audit(
                    "guest_activity_storage_failed",
                    operation="register",
                    page_id=page["id"],
                    grant_id=grant["id"],
                )
            if grant.get("verification_required"):
                session = self._cookie("access_service_verified")
                try:
                    verified = VERIFICATION_STORE.valid_session(
                        session, page["id"], grant["id"],
                    )
                except (OSError, sqlite3.Error):
                    audit(
                        "verification_storage_failed",
                        operation="session_check",
                        page_id=page["id"],
                        grant_id=grant["id"],
                    )
                    self._send_json(
                        HTTPStatus.SERVICE_UNAVAILABLE,
                        {"error": "Guest verification is temporarily unavailable"},
                    )
                    return False
                if not verified:
                    self._send_json(HTTPStatus.FORBIDDEN, {
                        "error": "Email verification is required",
                        "verification_required": True,
                        "email_hint": (
                            "the email address supplied by the administrator"
                        ),
                    })
                    return False
            self._record_initial_guest_access(page, grant)
            return True

        if status == "expired" and grant is not None:
            self._cleanup_expired_grants(page["id"])
            self._record_security_event(
                page["id"],
                "expired_access_attempt",
                grant_id=grant["id"],
                details={"reason": "grant_expired"},
            )
            self._send_json(
                HTTPStatus.GONE,
                {"error": "This access link has expired"},
            )
        else:
            if status == "invalid" and record_invalid:
                self._record_security_event(
                    page["id"],
                    "invalid_action_token",
                    details={"reason": "action_token_not_recognized"},
                )
            if status == "invalid" and not record_invalid:
                client_ip = getattr(
                    self,
                    "client_address",
                    ("unknown",),
                )[0]
                rate_key = f"{page['id']}:{client_ip}"
                if not UNAUTHORIZED_READ_RATE_LIMITER.allow(rate_key):
                    self._send_json(
                        HTTPStatus.TOO_MANY_REQUESTS,
                        {
                            "error": (
                                "Too many unauthorized requests; "
                                "try again shortly"
                            )
                        },
                    )
                    return False
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "A valid page access token is required"},
            )
        return False

    def _record_security_event(
        self,
        page_id,
        event_type,
        *,
        grant_id=None,
        details=None,
    ):
        client_ip = getattr(self, "client_address", ("unknown",))[0]
        rate_key = f"{page_id}:{event_type}:{client_ip}"
        if not SECURITY_EVENT_RATE_LIMITER.allow(rate_key):
            return
        try:
            ACTIVITY_STORE.record_security_event(
                page_id=page_id,
                grant_id=grant_id,
                event_type=event_type,
                details=details or {},
            )
            if grant_id and event_type in {
                "action_rate_limited",
                "unapproved_action_attempt",
            }:
                self._send_guest_notification(
                    page_id,
                    "blocked_action",
                    resource_id=str((details or {}).get("resource_id", "")),
                    action_id=str((details or {}).get("action_id", "")),
                    outcome=event_type,
                )
        except HomeAssistantError:
            audit(
                "guest_notification_failed",
                event_type="blocked_action",
                page_id=page_id,
                grant_id=grant_id,
            )
        except (OSError, sqlite3.Error):
            audit(
                "guest_activity_storage_failed",
                operation="record_security_event",
                page_id=page_id,
                grant_id=grant_id,
            )

    def _cleanup_expired_grants(self, page_id):
        if GATEWAY_ROLE == "guest":
            try:
                return PAGE_STORE.load(page_id)
            except (PageConfigError, PageNotFoundError):
                return None
        try:
            page, expired = PAGE_STORE.expire_access_grants(page_id)
        except (PageConfigError, PageNotFoundError, ValueError):
            return None

        for grant in expired:
            try:
                expired_at = parse_time(grant["expires_at"])
                ACTIVITY_STORE.mark_revoked(
                    page_id,
                    grant,
                    revoked_at=expired_at,
                )
                ACTIVITY_STORE.record_security_event(
                    page_id=page_id,
                    grant_id=grant["id"],
                    event_type="guest_access_expired",
                    details={"reason": "lifetime_ended"},
                )
            except (OSError, sqlite3.Error, ValueError):
                audit(
                    "guest_activity_storage_failed",
                    operation="expire",
                    page_id=page_id,
                    grant_id=grant["id"],
                )

            access_link_id = grant.get("access_link_id", "")
            if access_link_id:
                try:
                    ACCESS_SERVICE_CLIENT.delete_access_link(
                        resource_id=grant.get("resource_id", ""),
                        access_link_id=access_link_id,
                        page_id=page_id,
                        grant_id=grant["id"],
                    )
                except AccessServiceError as error:
                    audit(
                        "expired_access_link_cleanup_failed",
                        page_id=page_id,
                        grant_id=grant["id"],
                        access_link_id=access_link_id,
                        **access_service_error_diagnostics(error),
                    )
        return page

    def _send_ha_error(self, error):
        payload = {"error": str(error)}
        if error.status is not None:
            payload["ha_status"] = error.status
        self._send_json(HTTPStatus.BAD_GATEWAY, payload)

    def _send_access_service_error(self, error):
        payload = {"error": str(error)}
        if error.status is not None:
            payload["access_service_status"] = error.status
        self._send_json(HTTPStatus.BAD_GATEWAY, payload)

    def _send_page_error(self, error):
        if isinstance(error, PageNotFoundError):
            self._send_json(404, {"error": "Page not found"})
        else:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": str(error)},
            )

    def _record_initial_guest_access(self, page, grant):
        # The store upserts the guest and atomically marks first access. All
        # NHP guest processes use the admin-owned broker/store for this event.
        try:
            first_access = ACTIVITY_STORE.record_initial_access(page["id"], grant)
            if first_access:
                self._send_guest_notification(page["id"], "initial_login")
        except (OSError, sqlite3.Error, HomeAssistantError, HTTPException):
            audit(
                "guest_notification_failed",
                event_type="initial_login",
                page_id=page["id"],
                grant_id=grant["id"],
            )

    def _record_guest_action(
        self,
        resource,
        action,
        service_data,
        outcome,
        error="",
    ):
        grant_id = getattr(self, "active_grant", {}).get("id", "")
        if not grant_id:
            return
        try:
            ACTIVITY_STORE.record_action(
                grant_id=grant_id,
                entity_id=resource["entity_id"],
                entity_name=resource.get("name") or resource["entity_id"],
                action_id=action["id"],
                parameters=service_data,
                outcome=outcome,
                error=error,
            )
            self._send_guest_notification(
                    getattr(self, "active_grant", {}).get("_page_id", ""),
                    "entity_action",
                    resource_id=resource["id"],
                    action_id=action["id"],
                    outcome=outcome,
                )
        except HomeAssistantError:
            audit(
                "guest_notification_failed",
                event_type="entity_use",
                grant_id=grant_id,
            )
        except (OSError, sqlite3.Error):
            audit(
                "guest_activity_storage_failed",
                operation="record_action",
                page_id=getattr(self, "active_grant", {}).get(
                    "_page_id",
                    "",
                ),
                grant_id=grant_id,
            )

    def _public_page(self, page):
        try:
            feature_policy.validate_page(page)
        except ValueError as error:
            raise HomeAssistantError(str(error), status=403) from error
        entity_ids = {
            resource["entity_id"]
            for resource in page["resources"]
        }

        states_by_entity = {}

        if entity_ids:
            states = HA_CLIENT.get_states(entity_ids)
            states_by_entity = {
                state.get("entity_id"): state
                for state in states
                if state.get("entity_id") in entity_ids
            }

        resources = []

        for resource in page["resources"]:
            state_record = states_by_entity.get(
                resource["entity_id"],
                {},
            )
            attributes = state_record.get("attributes") or {}
            action_services = {
                action["service"]
                for action in resource["actions"]
            }

            public_resource = {
                "id": resource["id"],
                "name": (
                        resource["name"]
                        or attributes.get("friendly_name")
                        or resource["entity_id"]
                ),
                "domain": resource["domain"],
                "state": state_record.get("state", "unavailable"),
                "capabilities": normalize_capabilities(
                        resource["domain"],
                        state_record.get("state"),
                        attributes,
                        action_services,
                ),
                "state_attributes": {
                        "friendly_name": attributes.get("friendly_name"),
                        "device_class": attributes.get("device_class"),
                        "unit_of_measurement": attributes.get(
                            "unit_of_measurement"
                        ),
                        "current_position": attributes.get(
                            "current_position"
                        ),
                        "percentage": attributes.get("percentage"),
                        "percentage_step": attributes.get("percentage_step"),
                        "temperature": attributes.get("temperature"),
                        "current_temperature": attributes.get(
                            "current_temperature"
                        ),
                        "temperature_unit": attributes.get("temperature_unit"),
                        "min_temp": attributes.get("min_temp"),
                        "max_temp": attributes.get("max_temp"),
                        "target_temp_step": attributes.get("target_temp_step"),
                        "target_temp_low": attributes.get("target_temp_low"),
                        "target_temp_high": attributes.get("target_temp_high"),
                        "hvac_modes": attributes.get("hvac_modes"),
                        "hvac_action": attributes.get("hvac_action"),
                        "last_triggered": attributes.get("last_triggered"),
                        "options": attributes.get("options"),
                        "min": attributes.get("min"),
                        "max": attributes.get("max"),
                        "step": attributes.get("step"),
                        "brightness": attributes.get("brightness"),
                        "volume_level": attributes.get("volume_level"),
                        "media_title": attributes.get("media_title"),
                        "media_artist": attributes.get("media_artist"),
                        "source": attributes.get("source"),
                        "latitude": attributes.get("latitude"),
                        "longitude": attributes.get("longitude"),
                        "location_name": attributes.get("location_name"),
                        "message": attributes.get("message"),
                        "start_time": attributes.get("start_time"),
                        "end_time": attributes.get("end_time"),
                        "forecast": attributes.get("forecast"),
                },
                "actions": [
                        {
                            "id": action["id"],
                            "name": action["name"],
                        }
                        for action in resource["actions"]
                ],
            }
            if resource["domain"] == "camera":
                public_resource["camera_refresh_interval"] = resource.get(
                    "camera_refresh_interval", 30
                )
            resources.append(public_resource)

        return {
            "id": page["id"],
            "title": page["title"],
            "description": page["description"],
            "proximity": {
                "required": bool(
                    page.get("proximity", {}).get("enabled", False)
                ),
                "radius_meters": int(
                    page.get("proximity", {}).get("radius_meters", 500)
                ),
                "verification_ttl_seconds": (
                    PROXIMITY_READING_MAX_AGE_SECONDS
                ),
            },
            "refreshed_at": isoformat(utc_now()),
            "resources": resources,
        }

    def _send_camera_image(self, page, resource_id):
        resource = next(
            (
                item for item in page["resources"]
                if item["id"] == resource_id and item["domain"] == "camera"
            ),
            None,
        )
        if resource is None:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Camera not found"})
            return
        access_scope = getattr(self, "camera_access_scope", None)
        if not access_scope:
            grant_id = getattr(self, "active_grant", {}).get("id", "preview")
            access_scope = f"grant:{grant_id}"
        rate_key = f"{page['id']}:{access_scope}:{resource_id}"
        configured_interval = resource.get("camera_refresh_interval", 30)
        minimum_interval = (
            MANUAL_CAMERA_MIN_INTERVAL_SECONDS
            if configured_interval == 0
            else configured_interval
        )
        allowed, retry_after = CAMERA_REFRESH_RATE_LIMITER.check(
            rate_key, minimum_interval
        )
        if not allowed:
            self._send_json(
                HTTPStatus.TOO_MANY_REQUESTS,
                {"error": "Camera image is not ready to refresh"},
                {"Retry-After": str(retry_after)},
            )
            return
        if not CAMERA_IMAGE_RATE_LIMITER.allow(rate_key):
            self._send_json(
                HTTPStatus.TOO_MANY_REQUESTS,
                {"error": "Camera image refresh limit reached"},
                {"Retry-After": "6"},
            )
            return
        try:
            body, content_type = HA_CLIENT.get_camera_image(
                resource["entity_id"],
                page_id=page["id"],
                resource_id=resource_id,
            )
        except HomeAssistantError as error:
            self._send_ha_error(error)
            return
        self._send_bytes(
            HTTPStatus.OK,
            body,
            content_type,
            {"Content-Disposition": "inline"},
        )

    def _require_proximity(self, page, payload):
        policy = page.get("proximity", {})
        if not policy.get("enabled", False):
            return True
        reading = payload.get("proximity")
        if not isinstance(reading, dict):
            self._send_json(
                HTTPStatus.FORBIDDEN,
                {"error": "You must be near the home to use controls"},
            )
            return False
        try:
            latitude = float(reading["latitude"])
            longitude = float(reading["longitude"])
            accuracy = float(reading["accuracy_meters"])
            measured_at = float(reading["measured_at"])
        except (KeyError, TypeError, ValueError):
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "The location reading is invalid"},
            )
            return False
        if not all(math.isfinite(value) for value in (
            latitude, longitude, accuracy, measured_at
        )) or not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "The location reading is invalid"},
            )
            return False
        radius = int(policy.get("radius_meters", 500))
        if accuracy < 0 or accuracy > min(
            PROXIMITY_MAX_ACCURACY_METERS,
            radius,
        ):
            self._send_json(
                HTTPStatus.FORBIDDEN,
                {"error": "Your location is not accurate enough to use controls"},
            )
            return False
        age = utc_now().timestamp() - measured_at
        if age < -30 or age > PROXIMITY_READING_MAX_AGE_SECONDS:
            self._send_json(
                HTTPStatus.FORBIDDEN,
                {"error": "Your location check has expired; try again"},
            )
            return False
        try:
            within_range = HA_CLIENT.verify_proximity(
                page["id"],
                {
                    "latitude": latitude,
                    "longitude": longitude,
                    "accuracy_meters": accuracy,
                    "measured_at": measured_at,
                },
                radius,
            )
        except (HomeAssistantError, KeyError, TypeError, ValueError):
            self._send_json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "Could not verify the Home location"},
            )
            return False
        if not within_range:
            self._send_json(
                HTTPStatus.FORBIDDEN,
                {"error": "You are too far from the home to use controls"},
            )
            return False
        return True

    def _create_access_link(self, page_id, payload):
        page = self._load_page(page_id)
        if page is None:
            return

        try:
            lifetime, lifetime_delta = parse_access_link_lifetime(
                payload.get("lifetime", "24h")
            )
        except ValueError as error:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": str(error)},
            )
            return

        label = str(payload.get("label", "")).strip()[:120]
        one_time_use = bool(payload.get("one_time_use", False))
        verification_required = bool(
            payload.get("verification_required", False)
        )
        nhp_options = {}
        if nhp.ENABLED:
            method = payload.get("verification_method", "none")
            email = str(payload.get("verification_email", "")).strip().lower()
            if method not in ("none", "google", "email", "google_or_email") or (method != "none" and (len(email) > 254 or email.count("@") != 1 or any(c.isspace() for c in email) or not all(email.split("@")))):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Choose a verification method and enter the guest email"})
                return
            nhp_options = {"verification_method": method, "verification_email": email if method != "none" else ""}
        send_invitation = payload.get("send_invitation_email", False)
        invitation_email = ""
        try:
            if type(send_invitation) is not bool:
                raise EmailConfigError("Choose whether to email the invitation")
            if send_invitation:
                invitation_email = validate_email(payload.get("invitation_email", ""), "Invitation recipient").lower()
                if not SMTP_CONFIG_STORE.configured():
                    raise EmailConfigError("Configure local SMTP before emailing invitations")
                if nhp_options.get("verification_method", "none") != "none" and invitation_email != nhp_options["verification_email"]:
                    raise EmailConfigError("Send the invitation to the email selected for guest verification")
        except (EmailConfigError, OSError) as error:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
            return
        notifications = payload.get("notifications")
        if notifications is not None:
            try:
                notifications = validate_notifications(notifications)
                available = set(NOTIFICATION_TARGET_STORE.load())
                if SMTP_CONFIG_STORE.configured():
                    available.add("email")
                if any(item not in available for item in notifications["targets"]):
                    raise PageConfigError("A notification target is not configured")
            except PageConfigError as error:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            except HomeAssistantError as error:
                self._send_ha_error(error)
                return
        if verification_required:
            self._send_json(
                HTTPStatus.CONFLICT,
                {
                    "error": (
                        "Choose Google sign-in or Email code under Verification method. "
                        "Guest verification is handled by OpenNHP Service."
                    )
                },
            )
            return
        verification_email = ""
        if one_time_use and not nhp.ENABLED:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "One-time-use AccessLinks are not supported yet"},
            )
            return

        raw_token = secrets.token_urlsafe(32)
        grant_id = f"grant_{secrets.token_urlsafe(12)}"
        target_path = (
            f"/access/{quote(page_id, safe='')}?"
            f"{urlencode({'access_token': raw_token})}"
        )
        created_at = utc_now()
        local_expires_at = created_at + lifetime_delta

        try:
            access_link = ACCESS_SERVICE_CLIENT.create_access_link(
                label=label,
                expires_in=lifetime,
                one_time_use=one_time_use,
                page_id=page_id,
                grant_id=grant_id,
                target_path=target_path,
                **nhp_options,
            )
        except AccessServiceError as error:
            self._send_access_service_error(error)
            return

        expires_at = access_link.get("expires_at") or isoformat(local_expires_at)

        grant = {
            "id": grant_id,
            "token_hash": token_hash(raw_token),
            "created_at": isoformat(created_at),
            "expires_at": expires_at,
            "label": label,
            "lifetime": lifetime,
            "one_time_use": one_time_use,
            **nhp_options,
            "access_link_url": access_link["access_link_url"],
            "access_link_site": access_link.get("access_link_site", ""),
            "resource_id": access_link.get("resource_id", "") or ACCESS_SERVICE_CLIENT.resource_id,
            "access_link_id": access_link.get("access_link_id", ""),
            "type": access_link.get("type", ""),
            "verification_required": verification_required,
            "notifications": notifications or {"targets": [], "events": []},
            "target_path_applied": bool(access_link.get("target_path_applied", False)),
        }

        if verification_required:
            try:
                VERIFICATION_RECIPIENTS.set(page_id, grant_id, verification_email)
            except (EmailConfigError, OSError):
                try:
                    ACCESS_SERVICE_CLIENT.delete_access_link(
                        resource_id=grant.get("resource_id", ""),
                        access_link_id=grant.get("access_link_id", ""),
                        page_id=page_id,
                        grant_id=grant_id,
                    )
                except AccessServiceError:
                    pass
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"error": "Could not store verification recipient"},
                )
                return
        # The remote AccessLink request may take long enough for an administrator to
        # update or revoke this page. Reload before committing so a stale page
        # snapshot can never restore revoked grants or overwrite newer policy.
        page = PAGE_STORE.load(page_id)
        page["access_grants"].insert(0, grant)
        PAGE_STORE.replace(page_id, page)
        try:
            ACTIVITY_STORE.register_guest(page_id, grant)
        except (OSError, sqlite3.Error):
            audit(
                "guest_activity_storage_failed",
                operation="register",
                page_id=page_id,
                grant_id=grant["id"],
            )
        audit(
            "access_link_created",
            page_id=page_id,
            grant_id=grant["id"],
            access_link_id=grant.get("access_link_id"),
        )

        public_grant = {
            key: value
            for key, value in grant.items()
            if key != "token_hash"
        }

        public_grant["access_url"] = access_link["access_link_url"]
        public_grant["single_link"] = True

        email_delivery = {"requested": send_invitation, "sent": False}
        if send_invitation:
            email_delivery["sent"] = self._send_guest_invitation(
                page_id,
                grant,
                invitation_email,
                "",
            )

        self._send_json(
            HTTPStatus.CREATED,
            {
                "success": True,
                "grant": public_grant,
                "email_delivery": email_delivery,
            },
        )

    def _revoke_grant(self, page_id, grant_id):
        with page_action_lock(page_id):
            try:
                page = PAGE_STORE.load(page_id)
            except (PageConfigError, PageNotFoundError) as error:
                self._send_page_error(error)
                return

            grant = next(
                (
                    item
                    for item in page["access_grants"]
                    if item["id"] == grant_id
                ),
                None,
            )
            if grant is None:
                self._send_json(404, {"error": "Access link not found"})
                return

            try:
                PAGE_STORE.remove_access_grant(page_id, grant_id)
                try:
                    VERIFICATION_STORE.revoke(page_id, grant_id)
                    VERIFICATION_RECIPIENTS.delete(page_id, grant_id)
                except (OSError, sqlite3.Error, EmailConfigError):
                    audit(
                        "verification_session_cleanup_failed",
                        page_id=page_id,
                        grant_id=grant_id,
                    )
            except (PageConfigError, PageNotFoundError) as error:
                self._send_page_error(error)
                return
            try:
                ACTIVITY_STORE.mark_revoked(page_id, grant)
            except (OSError, sqlite3.Error):
                audit(
                    "guest_activity_storage_failed",
                    operation="revoke",
                    page_id=page_id,
                    grant_id=grant_id,
                )

        # Disable local access first so revocation is immediate even if OpenNHP Service
        # is temporarily unavailable. The OpenNHP Service DELETE endpoint revokes the
        # remote AccessLink while retaining any history OpenNHP Service keeps for it.
        access_link_id = grant.get("access_link_id", "")
        remote_error = None
        if not access_link_id:
            remote_error = "Missing AccessLink ID; local access was revoked"
        else:
            try:
                remote_already_missing = bool(ACCESS_SERVICE_CLIENT.delete_access_link(
                    resource_id=grant.get("resource_id", ""),
                    access_link_id=access_link_id,
                    page_id=page_id,
                    grant_id=grant_id,
                ))
            except AccessServiceError as error:
                remote_error = str(error)
                remote_already_missing = False
        if not access_link_id:
            remote_already_missing = False

        audit(
            "access_grant_revoked",
            page_id=page_id,
            grant_id=grant_id,
            access_link_id=access_link_id,
            remote_revoked=not remote_error,
            remote_already_missing=remote_already_missing,
        )

        if remote_error:
            self._send_json(
                HTTPStatus.BAD_GATEWAY,
                {
                    "success": False,
                    "local_access_revoked": True,
                    "remote_access_revoked": False,
                    "grant_id": grant_id,
                    "remote_error": remote_error,
                },
            )
            return

        self._send_json(
            200,
            {
                "success": True,
                "local_access_revoked": True,
                "remote_access_revoked": True,
                "remote_already_missing": remote_already_missing,
                "grant_id": grant_id,
            },
        )

    def _revoke_all_grants(self, page_id):
        with page_action_lock(page_id):
            page = self._load_page(page_id)
            if page is None:
                return

            grants = list(page["access_grants"])
            revoked_count = len(grants)

            # Disable local access first so revocation is immediate even if
            # OpenNHP Service is temporarily unavailable. Remote failures are reported
            # without restoring local access.
            page["access_grants"] = []
            PAGE_STORE.replace(page_id, page)
            for grant in grants:
                try:
                    VERIFICATION_STORE.revoke(page_id, grant["id"])
                    VERIFICATION_RECIPIENTS.delete(page_id, grant["id"])
                except (OSError, sqlite3.Error, EmailConfigError):
                    audit("verification_session_cleanup_failed", page_id=page_id, grant_id=grant["id"])
                try:
                    ACTIVITY_STORE.mark_revoked(page_id, grant)
                except (OSError, sqlite3.Error, EmailConfigError):
                    audit(
                        "guest_activity_storage_failed",
                        operation="revoke",
                        page_id=page_id,
                        grant_id=grant["id"],
                    )

        remote_failures = []
        for grant in grants:
            access_link_id = grant.get("access_link_id", "")
            if not access_link_id:
                remote_failures.append({
                    "grant_id": grant["id"],
                    "error": "Missing AccessLink ID; local access was revoked",
                })
                continue
            try:
                ACCESS_SERVICE_CLIENT.delete_access_link(
                    resource_id=grant.get("resource_id", ""),
                    access_link_id=access_link_id,
                    page_id=page_id,
                    grant_id=grant["id"],
                )
            except AccessServiceError as error:
                remote_failures.append({
                    "grant_id": grant["id"],
                    "access_link_id": access_link_id,
                    "error": str(error),
                })

        audit(
            "access_links_revoked",
            page_id=page_id,
            revoked_count=revoked_count,
            remote_failure_count=len(remote_failures),
        )
        self._send_json(
            HTTPStatus.BAD_GATEWAY if remote_failures else 200,
            {
                "success": not remote_failures,
                "local_access_revoked": True,
                "revoked_count": revoked_count,
                "remote_failures": remote_failures,
            },
        )

    def _reset_service_connection(self, payload):
        if payload.get("confirmation") != "RESET":
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "Type RESET to confirm the OpenNHP Service connection reset"},
            )
            return

        page_ids = sorted(item["id"] for item in PAGE_STORE.list_pages())
        with ExitStack() as locks:
            for page_id in page_ids:
                locks.enter_context(page_action_lock(page_id))
            pages_updated, grants = PAGE_STORE.revoke_all_access_grants()
            for grant in grants:
                try:
                    VERIFICATION_STORE.revoke(grant.get("_page_id", ""), grant["id"])
                    VERIFICATION_RECIPIENTS.delete(grant.get("_page_id", ""), grant["id"])
                except (OSError, sqlite3.Error, EmailConfigError):
                    audit("verification_session_cleanup_failed", page_id=grant.get("_page_id", ""), grant_id=grant["id"])
                try:
                    ACTIVITY_STORE.mark_revoked(
                        grant.get("_page_id", ""),
                        grant,
                    )
                except (OSError, sqlite3.Error):
                    audit(
                        "guest_activity_storage_failed",
                        operation="revoke",
                        grant_id=grant["id"],
                    )
        remote_failures = []
        for grant in grants:
            access_link_id = grant.get("access_link_id", "")
            if not access_link_id:
                remote_failures.append({
                    "grant_id": grant["id"],
                    "error": "Missing AccessLink ID; local access was revoked",
                })
                continue
            try:
                ACCESS_SERVICE_CLIENT.delete_access_link(
                    resource_id=grant.get("resource_id", ""),
                    access_link_id=access_link_id,
                    page_id=grant.get("_page_id", ""),
                    grant_id=grant["id"],
                )
            except AccessServiceError as error:
                remote_failures.append({
                    "grant_id": grant["id"],
                    "access_link_id": access_link_id,
                    "error": str(error),
                })

        RESET_REQUEST_FILE.parent.mkdir(parents=True, exist_ok=True)
        temporary = RESET_REQUEST_FILE.with_name(
            f".{RESET_REQUEST_FILE.name}.tmp"
        )
        temporary.write_text("reset\n", encoding="utf-8")
        temporary.chmod(0o600)
        audit(
            "access_service_connection_reset_requested",
            pages_updated=pages_updated,
            grants_revoked=len(grants),
            remote_failure_count=len(remote_failures),
        )
        try:
            self._send_json(
                HTTPStatus.ACCEPTED,
                {
                    "success": True,
                    "pages_preserved": True,
                    "pages_updated": pages_updated,
                    "grants_revoked": len(grants),
                    "remote_failures": remote_failures,
                    "reset_scheduled": True,
                },
            )
        finally:
            # Arm the supervisor only after the response is written, so it
            # cannot stop this gateway mid-response.
            temporary.replace(RESET_REQUEST_FILE)

    def _execute_public_action(
        self,
        page,
        resource_id,
        action_id,
        payload,
    ):
        execute_public_action(
            self,
            HA_CLIENT,
            page,
            resource_id,
            action_id,
            payload,
            normalize_capabilities,
            audit,
        )



    def do_GET(self):
        if not self._valid_request_envelope():
            return
        parsed = urlparse(self.path)
        path = parsed.path
        if not self._require_role(path):
            return

        if path == "/admin":
            # The shell contains no admin data. API requests remain protected
            # by X-Admin-Token, allowing a scrubbed URL to survive reloads.
            self._send_static_file("admin.html")
            return

        if path == "/" and (
            GATEWAY_ROLE == "guest" or self._proxied_page_id()
        ):
            page_id = self._connector_bound_page_id()
            if not page_id:
                self._send_json(404, {"error": "not found"})
                return
            page = self._load_page(page_id)
            if page is None:
                return
            self._send_access_shell(page_id)
            return

        if path.startswith("/access/"):
            page_id = path.removeprefix("/access/").strip("/")
            if not page_id or "/" in page_id:
                self._send_json(404, {"error": "not found"})
                return

            page = self._load_page(page_id)
            if page is None:
                return

            # The HTML shell is viewable through the OpenNHP Service-protected route.
            # Live state and every Home Assistant action remain token-gated.
            self._send_access_shell(page_id)
            return

        if path == "/health":
            connector_status = {"total": 0, "active": 0}
            mobile_notification_count = 0
            try:
                stored_status = json.loads(
                    CONNECTOR_STATUS_FILE.read_text(encoding="utf-8")
                )
                connector_status = {
                    "total": max(0, int(stored_status.get("total", 0))),
                    "active": max(0, int(stored_status.get("active", 0))),
                }
                connector_status["active"] = min(
                    connector_status["active"], connector_status["total"]
                )
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                pass
            if GATEWAY_ROLE in {"admin", "combined"}:
                try:
                    mobile_notification_count = len(
                        HA_CLIENT.notification_targets()
                    )
                except (HomeAssistantError, TypeError):
                    pass
            self._send_json(
                200,
                {
                    "status": "ok",
                    "version": GATEWAY_VERSION,
                    "device_data": os.getenv("GATEWAY_DEVICE_DATA", "homeassistant"),
                    "feature_profile": feature_policy.PROFILE,
                    "page_count": len(PAGE_STORE.list_pages()),
                    "connectors": connector_status,
                    "access_service_api_configured": ACCESS_SERVICE_CLIENT.configured,
                    "role": GATEWAY_ROLE,
                    "email_configured": (
                        SMTP_CONFIG_STORE.configured()
                        if GATEWAY_ROLE in {"admin", "combined"}
                        else False
                    ),
                    "notification_email_configured": (
                        SMTP_CONFIG_STORE.configured()
                        if GATEWAY_ROLE in {"admin", "combined"}
                        else False
                    ),
                    "mobile_notification_count": (
                        mobile_notification_count
                    ),
                },
            )
            return

        if path.startswith("/api/admin/"):
            admin_routes.handle_get(self, parsed, path, RUNTIME)
            return
        if path.startswith("/api/access/"):
            access_routes.handle_get(self, path, RUNTIME)
            return
        if path.startswith("/static/"):
            filename = path.removeprefix("/static/")
            if not filename:
                self._send_json(404, {"error": "not found"})
                return
            self._send_static_file(filename)
            return
        self._send_json(404, {"error": "not found"})




    def do_POST(self):
        if nhp.ENABLED and urlparse(self.path).path == "/handoff":
            if self._valid_request_envelope(): nhp.handoff(self, RUNTIME)
            return
        if not self._valid_request_envelope():
            return
        path = urlparse(self.path).path
        if not self._require_role(path):
            return
        try:
            payload = self._read_json()
        except ValueError as error:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": str(error)},
            )
            return

        if path.startswith("/api/internal/"):
            internal_routes.handle_post(self, path, payload, RUNTIME)
            return
        if path.startswith("/api/admin/"):
            admin_routes.handle_post(self, path, payload, RUNTIME)
            return
        if path.startswith("/api/access/"):
            access_routes.handle_post(self, path, payload, RUNTIME)
            return
        self._send_json(404, {"error": "not found"})

    def do_PUT(self):
        if not self._valid_request_envelope():
            return
        path = urlparse(self.path).path
        if not self._require_role(path):
            return
        admin_routes.handle_put(self, path, RUNTIME)

    def do_DELETE(self):
        if not self._valid_request_envelope():
            return
        path = urlparse(self.path).path
        if not self._require_role(path):
            return
        admin_routes.handle_delete(self, path, RUNTIME)



def run():
    if nhp.ENABLED and GATEWAY_ROLE in {"admin", "combined"}:
        nhp.start_revocation_worker()
    PAGES_DIR.mkdir(parents=True, exist_ok=True)
    if (
        GATEWAY_ROLE == "guest"
        and not nhp.ENABLED
        and not GATEWAY_BOUND_PAGE_ID
        and CONNECTOR_PAGE_ROUTES_FILE
    ):
        servers = {}
        try:
            while True:
                try:
                    routes = json.loads(
                        CONNECTOR_PAGE_ROUTES_FILE.read_text(encoding="utf-8")
                    )
                except (OSError, json.JSONDecodeError):
                    routes = {}
                desired = {
                    address
                    for address in routes
                    if isinstance(address, str) and address.startswith("127.77.")
                } if isinstance(routes, dict) else set()
                for address in sorted(desired - set(servers)):
                    page_server = GatewayHTTPServer((address, PORT), Handler)
                    thread = Thread(
                        target=page_server.serve_forever,
                        daemon=True,
                    )
                    thread.start()
                    servers[address] = (page_server, thread)
                    print(
                        f"OpenNHP Service page gateway listening on http://{address}:{PORT}",
                        flush=True,
                    )
                for address in sorted(set(servers) - desired):
                    page_server, thread = servers.pop(address)
                    page_server.shutdown()
                    page_server.server_close()
                    thread.join(timeout=2)
                time.sleep(0.5)
        finally:
            for page_server, thread in servers.values():
                page_server.shutdown()
                page_server.server_close()
                thread.join(timeout=2)
        return
    server = GatewayHTTPServer((HOST, PORT), Handler)
    print(f"OpenNHP Service HA gateway listening on http://{HOST}:{PORT}")
    print(f"Pages directory: {PAGES_DIR}")
    print(f"OpenNHP Service API configured: {ACCESS_SERVICE_CLIENT.configured}")
    server.serve_forever()


if __name__ == "__main__":
    run()
