"""Prevent the legacy-config fallback from silently returning to package CI."""
from pathlib import Path
import tempfile
import unittest

from check_build import PACKAGE, package_version


class BuildConfigurationTests(unittest.TestCase):
    @unittest.skipUnless(PACKAGE.is_dir(), 'Build context is validated on the host before building')
    def test_shipped_package_uses_supervisor_dockerfile_defaults(self):
        self.assertTrue(package_version(PACKAGE))

    def test_legacy_configuration_is_rejected_before_building(self):
        for suffix in ('yaml', 'yml', 'json'):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as temporary:
                package = Path(temporary)
                (package / 'config.yaml').write_text('version: 0.1.0-test\n')
                # Supervisor falls back even for malformed or empty build files.
                (package / f'build.{suffix}').write_text('')
                with self.assertRaisesRegex(ValueError, 'Legacy build configuration'):
                    package_version(package)


if __name__ == '__main__':
    unittest.main()
