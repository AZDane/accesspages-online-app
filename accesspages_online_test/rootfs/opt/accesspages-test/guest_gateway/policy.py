import json
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen
from pages import validate_page_id


class PolicyPublishError(RuntimeError):
    pass


class PolicyPublisher:
    def __init__(self, base_url="", token=None, pending_directory=None):
        self.base_url = base_url.rstrip("/")
        self.token = (token or "").strip()
        self.pending_directory = Path(pending_directory) if pending_directory is not None else None

    def _marker(self, page_id):
        return self.pending_directory / (".policy-pending-" + validate_page_id(page_id))

    def pending(self, page_id):
        return bool(self.pending_directory and self._marker(page_id).exists())

    def pending_pages(self):
        if self.pending_directory is None:
            return []
        return [p.name.removeprefix(".policy-pending-") for p in self.pending_directory.glob(".policy-pending-*")]

    def prepare(self, page_id):
        """Persist publication intent before a local page mutation."""
        self._mark(page_id)

    def _mark(self, page_id):
        if self.configured and self.pending_directory is not None:
            self.pending_directory.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(self._marker(page_id), os.O_WRONLY | os.O_CREAT, 0o600)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            self._sync_directory()

    def _clear(self, page_id):
        if self.configured and self.pending_directory is not None:
            try:
                self._marker(page_id).unlink(missing_ok=True)
                self._sync_directory()
            except OSError:
                # Publication was acknowledged. A marker cleanup failure must
                # never trigger rollback to a different local policy. A
                # surviving marker simply causes safe, idempotent republication.
                return

    def _sync_directory(self):
        descriptor = os.open(self.pending_directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @property
    def configured(self):
        return bool(self.base_url and self.token)

    def _request(self, method, page_id, payload=None):
        if not self.configured:
            return
        body = None
        headers = {
            "X-Policy-Token": self.token,
            "Accept": "application/json",
        }
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(
            f"{self.base_url}/v1/pages/{quote(page_id, safe='')}",
            data=body,
            method=method,
            headers=headers,
        )
        try:
            with urlopen(request, timeout=10) as response:  # nosec B310
                response.read()
        except HTTPError as error:
            error.read()
            raise PolicyPublishError(
                f"Policy publisher rejected the request ({error.code})"
            ) from error
        except URLError as error:
            raise PolicyPublishError(
                "Authoritative policy store is unavailable"
            ) from error

    def publish(self, page):
        policy = {**page, "access_grants": []}
        self._mark(page["id"])
        self._request("PUT", page["id"], policy)
        self._clear(page["id"])

    def delete(self, page_id):
        self._mark(page_id)
        self._request("DELETE", page_id)
        self._clear(page_id)
