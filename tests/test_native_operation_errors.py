import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'accesspages_online_test/rootfs/opt/accesspages-test'))

"""The machine boundary preserves only allowlisted diagnostic categories."""
import json
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from installation import Installation, NativeOperationError


class NativeOperationErrorTests(unittest.TestCase):
    def installation(self, root):
        value=Installation.__new__(Installation)
        value.root=Path(root)
        value.machine_dir=value.root/'machine'
        return value

    def test_machine_category_crosses_boundary_without_raw_error(self):
        with tempfile.TemporaryDirectory() as directory:
            output=json.dumps({'ok':False,'category':'local_lock_contention',
                               'error':'private gateway identifier'})
            result=subprocess.CompletedProcess([],1,stdout=output,stderr='private helper output')
            with patch('installation.subprocess.run',return_value=result):
                with self.assertRaises(NativeOperationError) as failure:
                    self.installation(directory).operation({'op':'installation_status'})
        self.assertEqual(failure.exception.category,'local_lock_contention')
        self.assertNotIn('private',str(failure.exception))

    def test_timeout_unknown_category_and_invalid_success_are_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            installation=self.installation(directory)
            with patch('installation.subprocess.run',side_effect=subprocess.TimeoutExpired('machinectl',35)):
                with self.assertRaises(NativeOperationError) as timeout:
                    installation.operation({'op':'installation_status'})
            self.assertEqual(timeout.exception.category,'native_timeout')

            unknown=subprocess.CompletedProcess([],1,stdout='{"category":"private-value"}')
            with patch('installation.subprocess.run',return_value=unknown):
                with self.assertRaises(NativeOperationError) as failure:
                    installation.operation({'op':'installation_status'})
            self.assertEqual(failure.exception.category,'native_failure')

            invalid=subprocess.CompletedProcess([],0,stdout='[]')
            with patch('installation.subprocess.run',return_value=invalid):
                with self.assertRaises(NativeOperationError) as failure:
                    installation.operation({'op':'installation_status'})
            self.assertEqual(failure.exception.category,'invalid_response')

    def test_confirmed_epoch_change_marks_transient_reconfiguration_failure_unsafe(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'binding.json').write_text(json.dumps({
                'gateway_id':'gw_synthetic','route':{'epoch':1}}))
            (root/'connector.json').write_text(json.dumps({'route':{'epoch':1}}))
            installation=self.installation(root)
            installation.operation=Mock(return_value={'gateway_id':'gw_synthetic','epoch':2})
            installation.refresh_authority=Mock()
            failure=NativeOperationError('local_lock_contention')
            installation.ensure_connector=Mock(side_effect=failure)
            with self.assertRaises(NativeOperationError) as raised:
                installation.refresh_connector()
        self.assertTrue(raised.exception.connector_configuration_changed)


if __name__=='__main__':
    unittest.main()
