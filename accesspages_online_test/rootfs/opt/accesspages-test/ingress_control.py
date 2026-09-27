"""Two bounded setup operations over a Unix socket, authenticated by kernel UID."""
import json
import logging
import os
from pathlib import Path
import re
import socket
import socketserver
import stat
import struct
import threading
import time

INGRESS_UID = 1006
MAX_FRAME = 4096


class LimitWarning:
    """Fixed event metadata only; count every hit, log at most once per minute."""
    def __init__(self, event, limit):
        self.event, self.limit = event, limit
        self.count = 0
        self.last_warning = None
        self.lock = threading.Lock()

    def report(self):
        with self.lock:
            self.count += 1
            now = time.monotonic()
            if self.last_warning is not None and now - self.last_warning < 60:
                return
            self.last_warning = now
            logging.getLogger('accesspages.ingress').warning(
                '%s limit=%d events_total=%d', self.event, self.limit, self.count)


class ControlError(Exception):
    def __init__(self, code='unavailable'):
        self.code = code


def peer_uid(connection):
    return struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]


def receive(connection, timeout):
    deadline = time.monotonic() + timeout

    def read(size):
        chunks = bytearray()
        while len(chunks) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            connection.settimeout(remaining)
            chunk = connection.recv(size - len(chunks))
            if not chunk:
                raise ValueError('Incomplete frame')
            chunks.extend(chunk)
        return chunks

    size, = struct.unpack('!I', read(4))
    if not 0 < size <= MAX_FRAME:
        raise ValueError('Invalid frame size')
    return json.loads(read(size))


def send(connection, value):
    body = json.dumps(value).encode()
    if len(body) > MAX_FRAME:
        raise ValueError('Response too large')
    connection.settimeout(3)
    connection.sendall(struct.pack('!I', len(body)) + body)


class BoundedThreads(socketserver.ThreadingMixIn):
    daemon_threads = True
    max_clients = 16
    client_limit_event = 'ingress_http_concurrency_limit'

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(self.max_clients)
        self.client_limit_warning = LimitWarning(self.client_limit_event, self.max_clients)
        super().__init__(*args, **kwargs)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            self.client_limit_warning.report()
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


class ControlHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            value = receive(self.request, 3)
            if value == {'op': 'status'}:
                result = self.server.runtime.public_status()
            elif (isinstance(value, dict) and set(value) == {'op', 'token'} and
                  value['op'] == 'enroll' and isinstance(value['token'], str) and
                  re.fullmatch(r'[A-Za-z0-9_-]{43}', value['token'])):
                # A slow enrollment cannot accumulate blocked enrollment workers.
                if not self.server.enrolling.acquire(blocking=False):
                    raise ControlError('busy')
                try:
                    result = self.server.runtime.enroll(value['token'])
                finally:
                    self.server.enrolling.release()
            else:
                raise ControlError('invalid')
            send(self.request, {'ok': True, 'result': result})
        except Exception as error:
            # Neither native errors nor credentials are returned or logged.
            try:
                send(self.request, {'ok': False, 'error': error.code if isinstance(error, ControlError) else 'failed'})
            except (OSError, ValueError):
                pass


class ControlServer(BoundedThreads, socketserver.UnixStreamServer):
    max_clients = 8
    client_limit_event = 'ingress_control_concurrency_limit'

    def __init__(self, path, runtime):
        path = Path(path)
        path.parent.mkdir(mode=0o750, exist_ok=True)
        if path.parent.is_symlink():
            raise ValueError('Unexpected control directory')
        os.chown(path.parent, 0, INGRESS_UID)
        path.parent.chmod(0o750)
        if path.exists() or path.is_symlink():
            entry = path.lstat()
            if not stat.S_ISSOCK(entry.st_mode) or entry.st_uid != 0:
                raise ValueError('Unexpected control socket')
            path.unlink()
        self.runtime = runtime
        self.enrolling = threading.Lock()
        super().__init__(str(path), ControlHandler)
        os.chown(path, 0, INGRESS_UID)
        path.chmod(0o660)

    def verify_request(self, request, address):
        # Authorize before parsing any bytes. Client-supplied IDs have no role.
        return peer_uid(request) == INGRESS_UID


def request(path, operation, **fields):
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(3)
            connection.connect(str(path))
            if peer_uid(connection) != 0:
                raise ControlError()
            send(connection, {'op': operation, **fields})
            reply = receive(connection, 130 if operation == 'enroll' else 5)
        if not isinstance(reply, dict) or type(reply.get('ok')) is not bool:
            raise ControlError()
        if not reply['ok']:
            raise ControlError(reply.get('error'))
        result = reply.get('result')
        if not isinstance(result, dict):
            raise ControlError()
        if operation == 'status' and (set(result) != {'message', 'enrolled', 'ready', 'admin_ready'} or
                not isinstance(result['message'], str) or
                any(type(result[key]) is not bool for key in ('enrolled', 'ready', 'admin_ready'))):
            raise ControlError()
        if operation == 'enroll' and result.get('enrolled') is not True:
            raise ControlError()
        return result
    except (OSError, ValueError, RecursionError) as error:
        raise ControlError() from error
