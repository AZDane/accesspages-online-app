from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
import os
from pathlib import Path

from pages import PageConfigError, PageNotFoundError, PageStore, validate_page


HOST = os.getenv("POLICY_STORE_HOST", "0.0.0.0")
PORT = int(os.getenv("POLICY_STORE_PORT", "8084"))
TOKEN = os.environ["POLICY_STORE_TOKEN"]
STORE = PageStore(
    Path(os.getenv("POLICY_STORE_DIR", "/data/pages")),
    file_mode=int(os.getenv("POLICY_FILE_MODE", "600"), 8),
)


def publish_page(page_id, payload):
    page = validate_page(
        {**payload, "access_grants": []},
        required_id=page_id,
    )
    try:
        STORE.replace(page_id, page)
    except PageNotFoundError:
        STORE.create(page)
    return page


def delete_page(page_id):
    try:
        STORE.delete(page_id)
    except PageNotFoundError:
        pass


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def _send(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        return hmac.compare_digest(
            self.headers.get("X-Policy-Token", ""),
            TOKEN,
        )

    def _page_id(self):
        prefix = "/v1/pages/"
        if not self.path.startswith(prefix):
            return ""
        page_id = self.path.removeprefix(prefix)
        return page_id if page_id and "/" not in page_id else ""

    def _payload(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as error:
            raise PageConfigError("Invalid request size") from error
        if length <= 0 or length > 256 * 1024:
            raise PageConfigError("Invalid request size")
        value = json.loads(self.rfile.read(length))
        return value

    def do_GET(self):
        self._send(
            200 if self.path == "/health" else 404,
            {"status": "ok"} if self.path == "/health" else {"error": "not found"},
        )

    def do_PUT(self):
        if not self._authorized():
            self._send(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        page_id = self._page_id()
        if not page_id:
            self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        try:
            publish_page(page_id, self._payload())
            self._send(200, {"success": True, "page_id": page_id})
        except (PageConfigError, json.JSONDecodeError) as error:
            self._send(HTTPStatus.BAD_REQUEST, {"error": str(error)})
        except OSError:
            self._send(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "Policy storage failed"},
            )

    def do_DELETE(self):
        if not self._authorized():
            self._send(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        page_id = self._page_id()
        if not page_id:
            self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        try:
            delete_page(page_id)
        except (PageConfigError, OSError):
            self._send(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "Policy storage failed"},
            )
            return
        self._send(200, {"success": True, "page_id": page_id})


def run():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    run()
