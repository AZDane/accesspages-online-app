import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'accesspages_online_test/rootfs/opt/accesspages-test/guest_gateway'))

"""Real local stores/outboxes at the private-key delivery transaction boundary."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import tempfile
import time
import unittest
from unittest.mock import patch

import nhp
from access_service import AccessServiceError
from invitation_fixture import key_delivery
from pages import PageStore, page_admin_view


class InvitationIssuanceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for change in [patch.dict(os.environ, {'GATEWAY_DATA_DIR': str(self.root)}),
                       patch.object(nhp, 'INSTALLATION_ROUTING', False)]:
            change.start()
            self.addCleanup(change.stop)
        self.store = PageStore(self.root/'pages', before_revoke=nhp.NHPClient().prepare_revocations)
        self.store.create({'id': 'page', 'title': 'Synthetic', 'resources': []})
        self.token = secrets.token_urlsafe(32)
        self.delivery = key_delivery(int(time.time())+600)
        self.client = nhp.NHPClient()

    def create(self, save=True):
        with patch.object(nhp, 'machine', return_value=self.delivery):
            value = self.client.create_access_link(target_path='/access/page?access_token='+self.token, expires_in='10m')
        grant = {'id': 'guest', 'created_at':'2026-01-01T00:00:00Z', 'token_hash': hashlib.sha256(self.token.encode()).hexdigest(), **value}
        if save:
            page = self.store.load('page')
            page['access_grants'] = [grant]
            self.store.replace('page', page)
        return grant

    def age(self):
        with nhp.revocation_db() as db:
            db.execute('UPDATE pending_preparations SET created=?', (int(time.time())-121,))

    def confirmed(self, grant):
        return {'state': 'unused', 'guest_token_hash': grant['token_hash'], 'resource': grant['resource_id']}

    def test_pending_is_hidden_then_activation_can_recover_lost_response(self):
        grant = self.create()
        self.assertEqual(page_admin_view(self.store.load('page'))['access_grants'][0]['access_link_url'], '')
        with patch.object(nhp, 'machine', side_effect=AccessServiceError('lost acknowledgement')):
            with self.assertRaises(AccessServiceError): self.client.activate_access_link(self.store, 'page', 'guest')
        self.age()
        with patch.object(nhp, 'machine', return_value=self.confirmed(grant)) as send:
            nhp.retry_preparations(self.store)
        send.assert_called_once_with({'op':'activate_invitation', 'access_link_id':grant['access_link_id']})
        saved = self.store.load('page')['access_grants'][0]
        self.assertEqual(saved['invitation_state'], 'ready')
        self.assertEqual(saved['access_link_url'], grant['access_link_url'])
        self.assertEqual(saved['expires_at'], grant['expires_at'])
        with nhp.revocation_db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM pending_preparations').fetchone()[0], 0)

    def test_delivery_without_local_commit_is_cancelled_using_only_request_id(self):
        self.create(save=False)
        self.age()
        with patch.object(nhp, 'machine', return_value={'cancelled':True}) as send:
            nhp.retry_preparations(self.store)
        self.assertEqual(set(send.call_args.args[0]), {'op','request_id'})
        self.assertEqual(send.call_args.args[0]['op'], 'cancel_preparation')
        self.assertNotIn(self.token, json.dumps(send.call_args.args[0]))
        self.assertNotIn(self.delivery['private_key'].encode(), (self.root/'nhp-links.db').read_bytes())

    def test_lost_key_delivery_is_not_reissued_or_retained(self):
        with patch.object(nhp, 'machine', side_effect=AccessServiceError('lost response')):
            with self.assertRaises(AccessServiceError):
                self.client.create_access_link(target_path='/access/page?access_token='+self.token, expires_in='10m')
        self.age()
        with patch.object(nhp, 'machine', return_value={'cancelled': True}) as send:
            nhp.retry_preparations(self.store)
        self.assertEqual(send.call_args.args[0]['op'], 'cancel_preparation')
        self.assertEqual(self.store.load('page')['access_grants'], [])

    def test_expired_preparation_removes_unusable_sharing_copy_and_queues_revocation(self):
        self.create()
        self.age()
        with patch.object(nhp, 'machine', side_effect=[AccessServiceError('expired'), {'state':'revoked'}]):
            nhp.retry_preparations(self.store)
        self.assertEqual(self.store.load('page')['access_grants'], [])
        with nhp.revocation_db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM pending_preparations').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT count(*) FROM pending_revocations').fetchone()[0], 1)
        for path in self.root.rglob('*'):
            if path.is_file(): self.assertNotIn(self.delivery['private_key'].encode(), path.read_bytes())

    def test_activation_cannot_resurrect_removed_grant_or_accept_wrong_scope(self):
        grant = self.create()
        def activate(_):
            self.store.remove_access_grant('page', 'guest')
            return self.confirmed(grant)
        with patch.object(nhp, 'machine', side_effect=activate):
            with self.assertRaises(AccessServiceError): self.client.activate_access_link(self.store,'page','guest')
        self.assertEqual(self.store.load('page')['access_grants'], [])

    def test_activation_cannot_accept_wrong_guest_scope(self):
        grant = self.create()
        with patch.object(nhp, 'machine', return_value={**self.confirmed(grant), 'guest_token_hash':'0'*64}):
            with self.assertRaises(AccessServiceError): self.client.activate_access_link(self.store,'page','guest')
        self.assertEqual(page_admin_view(self.store.load('page'))['access_grants'][0]['access_link_url'], '')

    def test_key_delivery_substitution_is_rejected_before_local_save(self):
        for field in ['private_key', 'public_key', 'invitation_id', 'landing_url']:
            with self.subTest(field=field), patch.object(nhp, 'machine', return_value={**self.delivery,field:'substituted'}):
                with self.assertRaises(AccessServiceError):
                    self.client.create_access_link(target_path='/access/page?access_token='+self.token,expires_in='10m')
        self.assertEqual(self.store.load('page')['access_grants'], [])
