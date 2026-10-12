"""The known hostname move preserves identities and cannot change service trust."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from installation import Installation, OLD_SERVER, NEW_SERVER, TRUST_FIELDS


class DomainMigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.previous = dict(version=3, server_host=OLD_SERVER.split(':')[0], server_port=62206,
                             landing_origin='https://access.beta.accesspages.app',
                             **{k: 'unchanged-' + k for k in TRUST_FIELDS})
        self.current = dict(self.previous, server_host=NEW_SERVER.split(':')[0],
                            landing_origin='https://access.accesspages.app')
        self.binding = dict(server_address=OLD_SERVER, gateway_id='gateway-fixture', state='enrolled',
                            route={'host': 'resource.installation.sites.beta.accesspages.app', 'epoch': 7})
        (self.root/'profile.json').write_text(json.dumps(self.previous))
        (self.root/'binding.json').write_text(json.dumps(self.binding))
        for folder in ('machine', 'connector-nhp'):
            (self.root/folder/'etc').mkdir(parents=True)
            (self.root/folder/'private-key').write_text('preserved-' + folder)
            (self.root/folder/'etc/config.toml').write_text('preserved native lock inode')
        self.inodes = {p: p.stat().st_ino for p in self.root.glob('*/etc/config.toml')}

    def install(self, address=OLD_SERVER):
        with patch.object(Installation, 'profile', return_value=self.current), patch.dict(os.environ, {}, clear=True):
            return Installation(self.root, server_address=address)

    def test_migration_preserves_identity_and_updates_both_native_endpoints(self):
        instance = self.install()
        self.assertEqual(instance.server_address, NEW_SERVER)
        self.assertEqual(json.loads((self.root/'binding.json').read_text()), dict(self.binding, server_address=NEW_SERVER))
        self.assertEqual(json.loads((self.root/'profile.json').read_text()), self.current)
        for folder in ('machine', 'connector-nhp'):
            self.assertEqual((self.root/folder/'private-key').read_text(), 'preserved-' + folder)
            server = (self.root/folder/'etc/server.toml').read_text()
            self.assertIn('nhp.accesspages.app', server)
            self.assertNotIn('beta', server)
        self.assertEqual({p: p.stat().st_ino for p in self.inodes}, self.inodes)
        self.install()  # Saved HA options can retain the old default; retries are idempotent.

    def test_arbitrary_endpoints_and_changed_trust_fail_without_mutation(self):
        original = (self.root/'binding.json').read_bytes()
        for field in (*TRUST_FIELDS, 'landing_origin'):
            current = copy.deepcopy(self.current)
            current[field] = 'changed'
            with self.subTest(field=field), patch.object(Installation, 'profile', return_value=current):
                with self.assertRaises(ValueError): Installation(self.root, server_address=NEW_SERVER)
                self.assertEqual((self.root/'binding.json').read_bytes(), original)
        for address in ('attacker.example:62206', 'nhp.accesspages.app:443'):
            with self.assertRaises(ValueError): self.install(address)
        self.previous['server_host'] = 'attacker.example'
        (self.root/'profile.json').write_text(json.dumps(self.previous))
        with self.assertRaises(ValueError): self.install()
        self.assertEqual((self.root/'binding.json').read_bytes(), original)

    def test_new_bootstrap_with_old_ha_option_does_not_require_existing_state(self):
        (self.root/'binding.json').unlink()
        (self.root/'profile.json').unlink()
        self.assertEqual(self.install().server_address, NEW_SERVER)
        self.assertFalse((self.root/'binding.json').exists())

    def test_missing_saved_trust_and_unrelated_binding_fail_closed(self):
        (self.root/'profile.json').unlink()
        original = (self.root/'binding.json').read_bytes()
        with self.assertRaises(ValueError): self.install()
        self.assertEqual((self.root/'binding.json').read_bytes(), original)
        (self.root/'binding.json').write_text(json.dumps(dict(self.binding, server_address='other.example:62206')))
        with self.assertRaises(ValueError): self.install()

    def test_interrupted_migration_recovers_through_normal_authority_refresh(self):
        with patch.object(Installation, 'refresh_authority', side_effect=OSError('interrupted')):
            with self.assertRaises(OSError): self.install()
        self.assertEqual(json.loads((self.root/'binding.json').read_text())['server_address'], NEW_SERVER)
        instance = self.install()
        with patch.object(Installation, 'profile', return_value=self.current): instance.refresh_authority()
        self.assertEqual(json.loads((self.root/'profile.json').read_text()), self.current)

    def test_changed_route_regenerates_csr_without_replacing_tls_key(self):
        instance = self.install()
        key = ec.generate_private_key(ec.SECP256R1())
        private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        (self.root/'guest.key').write_bytes(private)
        old = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).add_extension(
            x509.SubjectAlternativeName([x509.DNSName('*.installation.sites.beta.accesspages.app')]), critical=False).sign(key, hashes.SHA256())
        (self.root/'guest.csr').write_bytes(old.public_bytes(serialization.Encoding.PEM))
        binding = json.loads((self.root/'binding.json').read_text())
        binding['route']['host'] = 'resource.installation.sites.accesspages.app'
        (self.root/'binding.json').write_text(json.dumps(binding))
        with patch.object(instance, 'operation', return_value={'pending': True}) as call:
            self.assertFalse(instance.ensure_certificate())
            csr = x509.load_pem_x509_csr(call.call_args.args[0]['csr'].encode())
            self.assertEqual(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName), ['*.installation.sites.accesspages.app'])
        self.assertEqual((self.root/'guest.key').read_bytes(), private)
