"""Page default, guest provisioning overlap, expiry and deliberate mode reset."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import runtime
from app_options import resource_isolation
from resource_inventory import inventory
from pages import PageStore
import route_reservations
from test_certificate_setup import pending_runtime


def grant(guest, deadline=None):
    return {'id':guest,'token_hash':guest*64,'created_at':datetime.now(timezone.utc).isoformat(),'expires_at':datetime.fromtimestamp(deadline or time.time()+600,timezone.utc).isoformat()}


class ResourceInventoryTests(unittest.TestCase):
    def test_default_page_and_guest_scopes_with_overlap_expiry_and_recreation(self):
        self.assertEqual(resource_isolation({}), 'page')
        with self.assertRaises(ValueError):resource_isolation({'resource_isolation':'shared'})
        pages=[{'id':'front','instance_id':'a'*32,'access_grants':[grant('a'),grant('b'),grant('c',time.time()-1)]}]
        self.assertEqual(inventory(pages,'page',[]),[{'page_id':'front','instance_id':'a'*32,'guest_hash':''}])
        pending=[{'page_id':'front','instance_id':'a'*32,'guest_hash':s*64} for s in ('a','d')]
        pending.append({'page_id':'front','instance_id':'b'*32,'guest_hash':'e'*64})
        pending.append({'page_id':'deleted','instance_id':'a'*32,'guest_hash':'f'*64})
        desired=inventory(pages,'guest',pending)
        self.assertEqual([r['guest_hash'] for r in desired],['a'*64,'b'*64,'d'*64])
        pages[0]['access_grants'].append(grant('d'))
        self.assertEqual(inventory(pages,'guest',pending),desired,'committing a grant must not replace its pending route')
        pages[0]['access_grants']=[grant('b')]
        self.assertEqual(inventory(pages,'guest',[]),[{'page_id':'front','instance_id':'a'*32,'guest_hash':'b'*64}])

    def test_mode_change_revokes_all_grants_keeps_pages_and_denies_inflight_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            instance=pending_runtime(root)
            store=PageStore(root/'admin/pages')
            store.create({'id':'front','title':'Front','resources':[]})
            page=store.load('front');page['access_grants']=[grant('a')];store.replace('front',page)
            route_reservations.reserve(root/'admin','front',page['instance_id'],'b'*64)
            with patch.object(runtime,'ROOT',root),patch.object(runtime.os,'chown'),patch.object(instance,'stop'):
                instance.prepare()
                self.assertEqual(len(store.load('front')['access_grants']),1,'initial default preserves grants')
                (root/'options.json').write_text('{"resource_isolation":"guest"}')
                instance.prepare()
                self.assertEqual(store.load('front')['access_grants'],[])
                self.assertEqual(store.load('front')['instance_id'],page['instance_id'])
                self.assertEqual(route_reservations.pending(root/'admin'),[])
                for role in ('admin','broker'):
                    manifest=json.loads((root/role/'routes.json').read_text())
                    self.assertEqual(manifest['isolation'],'guest')
                    self.assertEqual(manifest['resources'],[],'inflight mint must not commit using old route')
                page['access_grants']=[grant('c')];store.replace('front',page)
                instance.prepare()
                self.assertEqual(store.load('front')['access_grants'][0]['id'],'c','unchanged mode must not revoke again')
                (root/'options.json').write_text('{}')
                instance.prepare()
                self.assertEqual(store.load('front')['access_grants'],[])
                self.assertEqual(store.load('front')['title'],'Front')
                self.assertEqual(json.loads((root/'resource-isolation.json').read_text()),'page')
