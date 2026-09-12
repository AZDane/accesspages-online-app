import fcntl
import json
import os
import re
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from threading import RLock, local


PAGE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
ACTION_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
TOKEN_HASH_RE = re.compile(r"^[a-f0-9]{64}$")
ALLOWED_WIDGETS = {"auto", "read_only", "thermostat", "sensor", "toggle"}
CAMERA_REFRESH_INTERVALS = {0, 15, 30, 60, 120, 300}


class PageConfigError(ValueError):
    pass


class PageNotFoundError(FileNotFoundError):
    pass


class PageStore:
    def __init__(self, directory: Path, file_mode: int = 0o600):
        self.directory = directory
        self.file_mode = file_mode
        self._lock = RLock()
        self._guard_state = local()

    @contextmanager
    def authority_guard(self, *, write=False):
        """Linearize grant reads/issuance with writes across Admin/Guest processes.

        The stable lock lives beside the atomically replaced page files. Guest
        mounts need only read access; the Admin creates it on first use.
        """
        with self._lock:
            if getattr(self._guard_state, 'active', False):
                if write and not self._guard_state.write:
                    raise RuntimeError('Cannot write inside a grant read boundary')
                yield
                return
            self.ensure_directory()
            path = self.directory / '.authority.lock'
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            except FileNotFoundError:
                fd = os.open(path, os.O_RDONLY | os.O_CREAT | os.O_NOFOLLOW, self.file_mode)
            try:
                # A restrictive process umask must not remove the configured
                # Guest read permission. Only the file owner repairs its mode;
                # the Guest can acquire the read lock without write authority.
                if os.fstat(fd).st_uid == os.geteuid():
                    os.fchmod(fd, self.file_mode)
                fcntl.flock(fd, fcntl.LOCK_EX if write else fcntl.LOCK_SH)
                self._guard_state.active = True
                self._guard_state.write = write
                try:
                    yield
                finally:
                    self._guard_state.active = False
                    fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def ensure_directory(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)

    def _path(self, page_id: str) -> Path:
        validate_page_id(page_id)
        return self.directory / f"{page_id}.json"

    def list_pages(self) -> list[dict]:
        with self.authority_guard():
            return self._list_pages_unlocked()

    def _list_pages_unlocked(self) -> list[dict]:
        self.ensure_directory()
        pages = []

        for path in sorted(self.directory.glob("*.json")):
            try:
                page = self.load(path.stem)
            except (PageConfigError, PageNotFoundError):
                continue

            pages.append(page_admin_summary(page))

        pages.sort(key=lambda item: item["title"].lower())
        return pages

    def load(self, page_id: str) -> dict:
        with self.authority_guard():
            return self._load_unlocked(page_id)

    def _load_unlocked(self, page_id: str) -> dict:
        path = self._path(page_id)

        if not path.is_file():
            raise PageNotFoundError(page_id)

        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise PageConfigError(
                f"Could not read page configuration: {error}"
            ) from error

        return validate_page(payload, required_id=page_id)

    def create(self, payload: object) -> dict:
        with self.authority_guard(write=True):
            return self._create_unlocked(payload)

    def _create_unlocked(self, payload: object) -> dict:
        page = validate_page(payload)
        path = self._path(page["id"])

        if path.exists():
            raise PageConfigError(
                f"A page with the ID '{page['id']}' already exists"
            )

        self._write(path, page)
        return page

    def update(self, page_id: str, payload: object) -> dict:
        with self.authority_guard(write=True):
            return self._update_unlocked(page_id, payload)

    def _update_unlocked(self, page_id: str, payload: object) -> dict:
        current_path = self._path(page_id)

        if not current_path.exists():
            raise PageNotFoundError(page_id)

        current = self._load_unlocked(page_id)
        page = validate_page(payload, required_id=page_id)

        # Access grants are security state and are never accepted from the
        # browser's normal page-edit payload.
        page["access_grants"] = current["access_grants"]
        self._write(current_path, page)
        return page

    def replace(self, page_id: str, page: dict) -> dict:
        with self.authority_guard(write=True):
            return self._replace_unlocked(page_id, page)

    def remove_access_grant(self, page_id: str, grant_id: str) -> dict:
        """Remove one gateway access grant and return the updated page.

        This revokes the gateway token immediately without affecting any
        other grants for the page.
        """
        with self.authority_guard(write=True):
            page = self._load_unlocked(page_id)
            grants = page["access_grants"]
            remaining = [grant for grant in grants if grant["id"] != grant_id]
            if len(remaining) == len(grants):
                raise PageNotFoundError(grant_id)
            page["access_grants"] = remaining
            return self._replace_unlocked(page_id, page)

    def expire_access_grants(
        self,
        page_id: str,
        *,
        now: datetime | None = None,
    ) -> tuple[dict, list[dict]]:
        """Remove expired grants atomically and return the page and removals."""
        current_time = now or datetime.now(timezone.utc)
        with self.authority_guard(write=True):
            page = self._load_unlocked(page_id)
            expired = []
            active = []
            for grant in page["access_grants"]:
                expires_at = datetime.fromisoformat(
                    grant["expires_at"].replace("Z", "+00:00")
                )
                if expires_at <= current_time:
                    expired.append(grant)
                else:
                    active.append(grant)
            if expired:
                page["access_grants"] = active
                page = self._replace_unlocked(page_id, page)
            return page, expired

    def revoke_all_access_grants(self) -> tuple[int, list[dict]]:
        """Revoke every local grant while preserving all page definitions."""
        with self.authority_guard(write=True):
            self.ensure_directory()
            updated_pages = 0
            revoked_grants = []
            for path in sorted(self.directory.glob("*.json")):
                try:
                    page = self._load_unlocked(path.stem)
                except (PageConfigError, PageNotFoundError):
                    continue
                grants = list(page["access_grants"])
                if not grants:
                    continue
                revoked_grants.extend(
                    {**grant, "_page_id": page["id"]}
                    for grant in grants
                )
                page["access_grants"] = []
                self._replace_unlocked(page["id"], page)
                updated_pages += 1
            return updated_pages, revoked_grants

    def _replace_unlocked(self, page_id: str, page: dict) -> dict:
        path = self._path(page_id)
        if not path.exists():
            raise PageNotFoundError(page_id)
        validated = validate_page(page, required_id=page_id)
        self._write(path, validated)
        return validated

    def delete(self, page_id: str) -> None:
        with self.authority_guard(write=True):
            self._delete_unlocked(page_id)

    def _delete_unlocked(self, page_id: str) -> None:
        path = self._path(page_id)

        if not path.exists():
            raise PageNotFoundError(page_id)

        path.unlink()

    def _write(self, path: Path, page: dict) -> None:
        self.ensure_directory()

        with NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=self.directory,
            delete=False,
        ) as temporary:
            json.dump(page, temporary, indent=2)
            temporary.write("\n")
            temporary_path = Path(temporary.name)

        temporary_path.replace(path)
        path.chmod(self.file_mode)


def validate_page_id(page_id: str) -> str:
    page_id = str(page_id).strip()

    if not PAGE_ID_RE.fullmatch(page_id):
        raise PageConfigError(
            "Page ID must use lowercase letters, numbers, hyphens, or "
            "underscores and be no longer than 64 characters"
        )

    return page_id


def validate_access_grants(raw_grants: object) -> list[dict]:
    if raw_grants is None:
        return []
    if not isinstance(raw_grants, list):
        raise PageConfigError("access_grants must be a list")

    grants = []
    seen_ids = set()

    for raw in raw_grants:
        if not isinstance(raw, dict):
            raise PageConfigError("Each access grant must be an object")

        allowed_fields = {
            "id",
            "token_hash",
            "created_at",
            "expires_at",
            "label",
            "lifetime",
            "one_time_use",
            "access_link_url",
            "access_link_site",
            "resource_id",
            "access_link_id",
            "type",
            "verification_required",
            "verification_method",
            "verification_email",
            "notifications",
            "target_path_applied",
        }
        unexpected_fields = set(raw) - allowed_fields
        if unexpected_fields:
            raise PageConfigError(
                "Access grant contains unsupported fields: "
                + ", ".join(sorted(unexpected_fields))
            )

        grant_id = str(raw.get("id", "")).strip()
        token_hash = str(raw.get("token_hash", "")).strip().lower()
        expires_at = str(raw.get("expires_at", "")).strip()
        created_at = str(raw.get("created_at", "")).strip()

        if not grant_id or len(grant_id) > 80:
            raise PageConfigError("Invalid access grant ID")
        if grant_id in seen_ids:
            raise PageConfigError("Duplicate access grant ID")
        seen_ids.add(grant_id)

        if not TOKEN_HASH_RE.fullmatch(token_hash):
            raise PageConfigError("Invalid access-token hash")
        if not expires_at or not created_at:
            raise PageConfigError("Access grant is missing timestamps")
        for timestamp in (created_at, expires_at):
            try:
                parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                if parsed.tzinfo is None or parsed.utcoffset() is None:
                    raise ValueError("Timezone required")
            except ValueError as error:
                raise PageConfigError(
                    "Access grant timestamps must be valid and timezone-aware"
                ) from error

        if raw.get("verification_method", "none") not in ("none", "google", "email"):
            raise PageConfigError("Invalid NHP verification method")
        grants.append(
            {
                "id": grant_id,
                "token_hash": token_hash,
                "created_at": created_at,
                "expires_at": expires_at,
                "label": str(raw.get("label", "")).strip()[:120],
                "lifetime": str(raw.get("lifetime", "")).strip()[:20],
                "one_time_use": bool(raw.get("one_time_use", False)),
                "access_link_url": str(raw.get("access_link_url", "")).strip(),
                "access_link_site": str(raw.get("access_link_site", "")).strip(),
                "resource_id": str(raw.get("resource_id", "")).strip(),
                "access_link_id": str(raw.get("access_link_id", "")).strip(),
                "type": str(raw.get("type", "")).strip(),
                "verification_required": bool(raw.get("verification_required", False)),
                **{key: str(raw[key]) for key in ("verification_method", "verification_email") if key in raw},
                "notifications": validate_notifications(raw.get("notifications")),
                "target_path_applied": bool(raw.get("target_path_applied", False)),
            }
        )

    grants.sort(key=lambda item: item["created_at"], reverse=True)
    return grants


def validate_notifications(raw: object) -> dict:
    if raw is None:
        return {"targets": [], "events": []}
    if not isinstance(raw, dict) or set(raw) - {"targets", "events"}:
        raise PageConfigError("Invalid guest notification settings")
    targets = raw.get("targets", [])
    events = raw.get("events", [])
    if not isinstance(targets, list) or not isinstance(events, list):
        raise PageConfigError("Invalid guest notification settings")
    targets = list(dict.fromkeys(str(item).strip() for item in targets))
    events = list(dict.fromkeys(str(item).strip() for item in events))
    if not targets and not events:
        return {"targets": [], "events": []}
    if any(
        target != "email"
        and not re.fullmatch(r"notify\.mobile_app_[a-z0-9_]+", target)
        for target in targets
    ):
        raise PageConfigError("Invalid guest notification target")
    allowed_events = {"initial_login", "successful_action", "failed_action"}
    if not targets or not events or any(item not in allowed_events for item in events):
        raise PageConfigError("Notification targets and events are required")
    return {"targets": targets, "events": events}


def validate_page(payload: object, required_id: str | None = None) -> dict:
    if not isinstance(payload, dict):
        raise PageConfigError("Page must be a JSON object")

    page_id = validate_page_id(payload.get("id", ""))

    if required_id is not None and page_id != required_id:
        raise PageConfigError("The page ID cannot be changed after creation")

    title = str(payload.get("title", "")).strip()
    if not title or len(title) > 80:
        raise PageConfigError("Page title must contain 1–80 characters")

    description = str(payload.get("description", "")).strip()
    if len(description) > 240:
        raise PageConfigError(
            "Page description must be no longer than 240 characters"
        )

    raw_proximity = payload.get("proximity", {})
    if raw_proximity is None:
        raw_proximity = {}
    if not isinstance(raw_proximity, dict):
        raise PageConfigError("proximity must be an object")
    proximity_enabled = raw_proximity.get("enabled", False)
    if not isinstance(proximity_enabled, bool):
        raise PageConfigError("Proximity enabled must be true or false")
    try:
        proximity_radius = int(raw_proximity.get("radius_meters", 500))
    except (TypeError, ValueError) as error:
        raise PageConfigError("Proximity radius must be a whole number") from error
    if proximity_radius < 50 or proximity_radius > 50000:
        raise PageConfigError(
            "Proximity radius must be between 50 and 50000 metres"
        )

    raw_resources = payload.get("resources", [])
    if not isinstance(raw_resources, list):
        raise PageConfigError("resources must be a list")

    resources = []
    seen_resource_ids = set()

    for raw_resource in raw_resources:
        if not isinstance(raw_resource, dict):
            raise PageConfigError("Each resource must be an object")

        resource_id = str(raw_resource.get("id", "")).strip()
        if not PAGE_ID_RE.fullmatch(resource_id):
            raise PageConfigError(
                f"Invalid resource ID: {resource_id!r}"
            )
        if resource_id in seen_resource_ids:
            raise PageConfigError(
                f"Duplicate resource ID: {resource_id}"
            )
        seen_resource_ids.add(resource_id)

        entity_id = str(raw_resource.get("entity_id", "")).strip()
        if "." not in entity_id:
            raise PageConfigError(
                f"Invalid Home Assistant entity ID: {entity_id!r}"
            )

        domain = str(raw_resource.get("domain", "")).strip()
        entity_domain = entity_id.split(".", 1)[0]
        if domain != entity_domain:
            raise PageConfigError(
                f"Domain mismatch for {entity_id}"
            )

        name = str(raw_resource.get("name", entity_id)).strip()
        if not name or len(name) > 100:
            raise PageConfigError(
                f"Invalid resource name for {entity_id}"
            )

        widget = str(raw_resource.get("widget", "auto")).strip() or "auto"
        if widget not in ALLOWED_WIDGETS:
            raise PageConfigError(f"Invalid widget for {entity_id}: {widget!r}")
        if widget == "thermostat" and domain != "climate":
            raise PageConfigError("Thermostat widgets require a climate entity")
        if widget == "sensor" and domain != "sensor":
            raise PageConfigError("Sensor widgets require a sensor entity")
        if widget == "toggle" and domain not in {"switch", "input_boolean"}:
            raise PageConfigError("Toggle widgets require a switch or input_boolean")

        has_camera_interval = "camera_refresh_interval" in raw_resource
        if domain != "camera" and has_camera_interval:
            raise PageConfigError(
                "Still-image refresh is supported only for camera entities"
            )
        camera_refresh_interval = None
        if domain == "camera":
            raw_interval = raw_resource.get("camera_refresh_interval", 30)
            if isinstance(raw_interval, bool) or not isinstance(raw_interval, int):
                raise PageConfigError(
                    f"Invalid still-image refresh interval for {entity_id}"
                )
            if raw_interval not in CAMERA_REFRESH_INTERVALS:
                raise PageConfigError(
                    f"Unsupported still-image refresh interval for {entity_id}"
                )
            camera_refresh_interval = raw_interval

        raw_actions = raw_resource.get("actions", [])
        if not isinstance(raw_actions, list):
            raise PageConfigError(f"Actions for {entity_id} must be a list")
        if not raw_actions and widget not in {"read_only", "sensor"} and domain != "sensor":
            raise PageConfigError(
                f"{entity_id} must have at least one approved action"
            )

        actions = []
        seen_action_ids = set()

        for raw_action in raw_actions:
            if not isinstance(raw_action, dict):
                raise PageConfigError(
                    f"Invalid action for {entity_id}"
                )

            action_id = str(raw_action.get("id", "")).strip()
            if not ACTION_ID_RE.fullmatch(action_id):
                raise PageConfigError(
                    f"Invalid action ID for {entity_id}: {action_id!r}"
                )
            if action_id in seen_action_ids:
                raise PageConfigError(
                    f"Duplicate action ID for {entity_id}: {action_id}"
                )
            seen_action_ids.add(action_id)

            name_value = str(raw_action.get("name", action_id)).strip()
            service = str(raw_action.get("service", "")).strip()

            if not name_value or len(name_value) > 60:
                raise PageConfigError(
                    f"Invalid action name for {entity_id}"
                )

            if not service or "." in service:
                raise PageConfigError(
                    f"Invalid service for {entity_id}: {service!r}"
                )

            actions.append(
                {
                    "id": action_id,
                    "name": name_value,
                    "service": service,
                }
            )

        resource = {
            "id": resource_id,
            "name": name,
            "entity_id": entity_id,
            "domain": domain,
            "widget": widget,
            "actions": actions,
        }
        if camera_refresh_interval is not None:
            resource["camera_refresh_interval"] = camera_refresh_interval
        resources.append(resource)

    return {
        "id": page_id,
        "title": title,
        "description": description,
        "proximity": {
            "enabled": proximity_enabled,
            "radius_meters": proximity_radius,
        },
        "resources": resources,
        "access_grants": validate_access_grants(
            payload.get("access_grants", [])
        ),
    }


def grant_admin_view(grant: dict) -> dict:
    return {
        key: value
        for key, value in grant.items()
        if key != "token_hash"
    }


def page_admin_view(page: dict) -> dict:
    return {
        "id": page["id"],
        "title": page["title"],
        "description": page["description"],
        "proximity": page.get("proximity", {
            "enabled": False,
            "radius_meters": 500,
        }),
        "resources": page["resources"],
        "access_grants": [
            grant_admin_view(grant)
            for grant in page["access_grants"]
        ],
    }


def page_admin_summary(page: dict) -> dict:
    return {
        "id": page["id"],
        "title": page["title"],
        "description": page["description"],
        "proximity_enabled": bool(
            page.get("proximity", {}).get("enabled", False)
        ),
        "resource_count": len(page["resources"]),
        "access_path": f"/access/{page['id']}",
        "grant_count": len(page["access_grants"]),
    }
