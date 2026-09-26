"""Local Guest-to-broker HTTP transport, authenticated by Unix peer identity."""
from http.client import HTTPConnection, HTTPException
import json
import os
import socket
import struct


class GuestBrokerError(Exception):
    def __init__(self, message, status=503):
        super().__init__(message)
        self.status = status


def peer_uid(connection):
    return struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]


class GuestConnection(HTTPConnection):
    def __init__(self, timeout=10):
        super().__init__('localhost', timeout=timeout)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(os.environ['HA_GUEST_BROKER_SOCKET'])
        if peer_uid(self.sock) != int(os.environ['HA_BROKER_UID']):
            self.close()
            raise GuestBrokerError('Unexpected broker identity')


def guest_request(path, payload, *, headers=None, image=False):
    conn = GuestConnection()
    try:
        conn.request('POST', path, json.dumps(payload), {'Content-Type': 'application/json', **(headers or {})})
        response = conn.getresponse()
        body = response.read(10 * 1024 * 1024 + 1)
        if response.status != 200:
            raise GuestBrokerError('Guest broker rejected the request', response.status)
        if len(body) > 10 * 1024 * 1024:
            raise GuestBrokerError('Broker response too large')
        if image:
            return body, response.headers.get_content_type().lower()
        return json.loads(body)
    except GuestBrokerError:
        raise
    except (OSError, ValueError, KeyError, HTTPException) as error:
        raise GuestBrokerError('Guest broker unavailable') from error
    finally:
        conn.close()
