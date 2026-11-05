import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'accesspages_online_test/rootfs/opt/accesspages-test'))

"""Bounded connector preservation for categorized status failures."""
import json
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

import runtime


def established_runtime(root, category='local_lock_contention'):
    installation=root/'admin/installation'
    installation.mkdir(parents=True,exist_ok=True)
    (installation/'binding.json').write_text(json.dumps({
        'gateway_id':'gw_synthetic', 'route':{'epoch':1}}))
    instance=runtime.Runtime.__new__(runtime.Runtime)
    instance.installation=Mock(root=installation)
    instance.installation.refresh_connector.side_effect=runtime.NativeOperationError(category)
    connector=Mock()
    connector.poll.return_value=None
    instance.children={'connector':connector}
    instance.last_connector_status=100
    instance.next_connector_status=0
    instance.connector_status_stale_since=None
    instance.connector_status_failure_category=None
    instance.phase='installation status'
    instance.last_error=None
    instance.message='Ready to create pages and test guest invitations.'
    instance.connector_ready=Mock(return_value=True)
    instance.lock=threading.RLock()
    instance.stopping=False
    return instance


class ConnectorStatusResilienceTests(unittest.TestCase):
    def test_local_lock_contention_preserves_established_connector_and_blocks_new_work(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            ready=root/'admin/ready-routes.json'
            ready.parent.mkdir(parents=True)
            ready.write_text('{"private":"must-not-log"}')
            instance=established_runtime(root)
            with patch.object(runtime,'ROOT',root),patch('builtins.print') as output:
                self.assertFalse(instance.refresh_connector_status(146))
                self.assertIs(instance.children['connector'].poll.return_value,None)
                self.assertFalse(ready.exists(),'stale status must block new invitation readiness')
                self.assertEqual(instance.connector_status_stale_since,100)
                self.assertEqual(instance.next_connector_status,156)
                self.assertFalse(instance.refresh_connector_status(150))
            instance.installation.refresh_connector.assert_called_once_with()
            rendered=str(output.call_args_list)
            self.assertIn('local_lock_contention',rendered)
            self.assertNotIn('private',rendered)

    def test_success_clears_staleness_and_authenticated_denial_never_preserves(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            instance=established_runtime(root)
            with patch.object(runtime,'ROOT',root),patch('builtins.print'):
                self.assertFalse(instance.refresh_connector_status(146))
                instance.installation.refresh_connector.side_effect=None
                self.assertTrue(instance.refresh_connector_status(156))
            self.assertIsNone(instance.connector_status_stale_since)
            self.assertEqual(instance.last_connector_status,156)

            denied=established_runtime(root,'authenticated_denial')
            with patch.object(runtime,'ROOT',root):
                with self.assertRaises(runtime.NativeOperationError) as failure:
                    denied.refresh_connector_status(146)
            self.assertEqual(failure.exception.category,'authenticated_denial')
            self.assertIsNone(denied.connector_status_stale_since)

            changed=established_runtime(root)
            changed_error=runtime.NativeOperationError('local_lock_contention')
            changed_error.connector_configuration_changed=True
            changed.installation.refresh_connector.side_effect=changed_error
            with patch.object(runtime,'ROOT',root):
                with self.assertRaises(runtime.NativeOperationError):
                    changed.refresh_connector_status(146)
            self.assertIsNone(changed.connector_status_stale_since)

    def test_stale_deadline_and_connector_process_failure_are_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            instance=established_runtime(root)
            with patch.object(runtime,'ROOT',root),patch('builtins.print'):
                self.assertFalse(instance.refresh_connector_status(146))
                with self.assertRaises(runtime.ConnectorStatusStale):
                    instance.refresh_connector_status(220)

            stopped=established_runtime(root)
            with patch.object(runtime,'ROOT',root),patch('builtins.print'):
                self.assertFalse(stopped.refresh_connector_status(146))
                stopped.children['connector'].poll.return_value=1
                with self.assertRaises(runtime.ConnectorStatusStale):
                    stopped.refresh_connector_status(150)

    def test_loop_stops_connector_for_confirmed_unsafe_status_failure(self):
        class StopLoop(Exception):
            pass
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            instance=established_runtime(root,'authenticated_denial')
            instance.prepare=Mock(side_effect=runtime.NativeOperationError('authenticated_denial'))
            instance.start_ingress=Mock()
            instance.stop=Mock()
            with patch.object(runtime,'ROOT',root),patch.object(runtime.time,'sleep',side_effect=StopLoop),patch('builtins.print'):
                with self.assertRaises(StopLoop):
                    instance.loop()
            instance.stop.assert_called_once_with('connector')
            self.assertEqual(instance.last_error,('installation status','authenticated_denial'))


if __name__=='__main__':
    unittest.main()
