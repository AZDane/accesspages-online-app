"""Complete desired network scopes from current pages and provisioning intents."""
from guest_auth import grant_expiry
import time


def inventory(pages, mode, pending):
    scopes = set()
    current = {p['id']: p.get('instance_id', '') for p in pages}
    for page in pages:
        if mode == 'page':
            scopes.add((page['id'], current[page['id']], ''))
        elif mode == 'guest':
            for grant in page['access_grants']:
                if grant_expiry(grant) > time.time():
                    scopes.add((page['id'], current[page['id']], grant['token_hash']))
        else:
            raise ValueError('Unknown resource isolation')
    if mode == 'guest':
        for route in pending:
            if current.get(route['page_id']) == route['instance_id']:
                scopes.add((route['page_id'], route['instance_id'], route['guest_hash']))
    return [dict(zip(('page_id', 'instance_id', 'guest_hash'), scope)) for scope in sorted(scopes)]
