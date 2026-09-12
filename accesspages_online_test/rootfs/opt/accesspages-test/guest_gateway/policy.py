import json
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


class PolicyPublishError(RuntimeError):
    pass


class PolicyPublisher:
    def __init__(self, base_url="", token=None):
        self.base_url = base_url.rstrip("/")
        self.token = (token or "").strip()

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
        self._request("PUT", page["id"], policy)

    def delete(self, page_id):
        self._request("DELETE", page_id)
