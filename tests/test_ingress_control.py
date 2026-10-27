"""Bounded frames and the supervisor's closed operation vocabulary."""
from concurrent.futures import ThreadPoolExecutor
import socket
import struct
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import ingress_control as control


class ControlTests(unittest.TestCase):
    def exchange(self, value=None, raw=None, locked=False):
        runtime = Mock()
        runtime.public_status.return_value = {'enrolled': False}
        runtime.enroll.return_value = {'enrolled': True}
        server = SimpleNamespace(runtime=runtime, enrolling=threading.Lock())
        if locked:
            server.enrolling.acquire()
        client, supervisor = socket.socketpair()
        with client, supervisor:
            if raw is None:
                control.send(client, value)
            else:
                client.sendall(raw)
            client.shutdown(socket.SHUT_WR)
            control.ControlHandler(supervisor, None, server)
            return control.receive(client, 1), runtime

    def test_only_exact_status_and_enroll_operations_dispatch(self):
        for value in ({'op': 'status'}, {'op': 'enroll', 'token': 'A'*43}):
            reply, runtime = self.exchange(value)
            self.assertTrue(reply['ok'])
            self.assertEqual(len(runtime.mock_calls), 1)
        for value in ({'op': 'exec', 'command': 'id'}, {'op': 'read', 'path': '/data/admin-token'},
                      {'op': 'status', 'uid': 1006}, {'op': 'status', 'url': 'http://example.invalid'},
                      {'op': 'enroll', 'token': 'A'*43, 'server': 'example.invalid'},
                      {'op': 'enroll', 'token': 'a'*42}, {'op': 'enroll', 'token': '../'*14+'a'},
                      {'op': 'repair_legacy_guests', 'confirm': True}, {'op': 'repair_legacy_guests'}, {'op': 'repair_legacy_guests', 'confirm': False},
                      {'op': 'repair_legacy_guests', 'confirm': 1}, {'op': 'repair_legacy_guests', 'confirm': True, 'path': '/data'},
                      {'op': 'enroll', 'token': []}, ['status'], None):
            reply, runtime = self.exchange(value)
            self.assertFalse(reply['ok'])
            self.assertEqual(runtime.mock_calls, [])

    def test_oversized_truncated_nested_or_invalid_frames_do_not_dispatch(self):
        bad_json = b'['*1500 + b']'*1500
        for raw in (struct.pack('!I', 4097), struct.pack('!I', 0), b'\x00',
                    struct.pack('!I', 20)+b'{}', struct.pack('!I', 1)+b'!',
                    struct.pack('!I', len(bad_json))+bad_json):
            reply, runtime = self.exchange(raw=raw)
            self.assertFalse(reply['ok'])
            self.assertEqual(runtime.mock_calls, [])

    def test_busy_enrollment_does_not_queue_or_block_status(self):
        reply, runtime = self.exchange({'op': 'enroll', 'token': 'A'*43}, locked=True)
        self.assertEqual(reply, {'ok': False, 'error': 'busy'})
        self.assertEqual(runtime.mock_calls, [])
        self.assertTrue(self.exchange({'op': 'status'}, locked=True)[0]['ok'])
        reply, runtime = self.exchange({'op': 'repair_legacy_guests', 'confirm': True}, locked=True)
        self.assertEqual(reply, {'ok': False, 'error': 'invalid'})
        self.assertEqual(runtime.mock_calls, [])

    def test_total_receive_deadline_and_thread_limit(self):
        connection = Mock()
        connection.recv.side_effect = [b'\x00', b'\x00', b'\x00', b'\x01', b'0']
        with patch.object(control.time, 'monotonic', side_effect=[0, 0, 1, 2, 3]):
            with self.assertRaises(TimeoutError):
                control.receive(connection, 3)
        for settings in (control.BoundedThreads, control.ControlServer):
            class Server(control.BoundedThreads):
                max_clients = settings.max_clients
                client_limit_event = settings.client_limit_event
                shutdown_request = Mock()
            server = Server()
            for _ in range(server.max_clients):
                self.assertTrue(server.slots.acquire(blocking=False))
            with self.assertLogs('accesspages.ingress', level='WARNING') as logs:
                server.process_request(connection, ('private-client', 1234))
            server.shutdown_request.assert_called_once_with(connection)
            self.assertEqual([r.getMessage() for r in logs.records],
                [f'{settings.client_limit_event} limit={settings.max_clients} events_total=1'])

    def test_limit_warning_counts_parallel_hits_without_flooding_logs(self):
        warning = control.LimitWarning('ingress_http_concurrency_limit', 16)
        with self.assertLogs('accesspages.ingress', level='WARNING') as logs:
            with patch.object(control.time, 'monotonic', return_value=100) as clock:
                warning.report()
                with ThreadPoolExecutor(max_workers=8) as pool:
                    list(pool.map(lambda _: warning.report(), range(32)))
                clock.return_value = 159.999
                warning.report()
                clock.return_value = 160
                warning.report()
        self.assertEqual([r.getMessage() for r in logs.records], [
            'ingress_http_concurrency_limit limit=16 events_total=1',
            'ingress_http_concurrency_limit limit=16 events_total=35'])


if __name__ == '__main__':
    unittest.main()
