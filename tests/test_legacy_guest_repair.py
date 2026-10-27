"""The retired repair capability must not return to the distributed package."""
import importlib.util
import unittest
import runtime


class RetiredRepairTests(unittest.TestCase):
    def test_legacy_module_and_runtime_operation_are_absent(self):
        self.assertIsNone(importlib.util.find_spec('legacy_guest_repair'))
        self.assertFalse(hasattr(runtime.Runtime, 'repair_legacy_guests'))
