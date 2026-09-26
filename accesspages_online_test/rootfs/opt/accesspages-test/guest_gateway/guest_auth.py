"""Broker-owned handoff redemption and current guest-session authority."""
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import nhp


class GuestAuthorizationError(Exception):
    pass


def verification_policy(grant):
    if grant.get('verification_required'):
        raise ValueError('Local verification is unavailable for NHP guests')
    method = grant.get('verification_method', 'none')
    email = str(grant.get('verification_email', '')).strip().lower()
    if method not in ('none', 'google', 'email', 'google_or_email'):
        raise ValueError('Unknown verification policy')
    if method != 'none' and (len(email) > 254 or email.count('@') != 1 or any(c.isspace() for c in email) or not all(email.split('@'))):
        raise ValueError('Invited email required')
    return method, email if method != 'none' else ''


def policy_hash(grant):
    return hashlib.sha256(json.dumps(verification_policy(grant), separators=(',', ':')).encode()).hexdigest()


def grant_expiry(grant):
    return datetime.fromisoformat(grant['expires_at'].replace('Z', '+00:00')).timestamp()


class GuestAuthority:
    def __init__(self, page_store, path):
        self.pages = page_store
        self.path = Path(path)

    @contextmanager
    def database(self):
        # The runtime creates the broker-only parent. No guest-owned ledger is
        # opened or upgraded: cutover requires fresh guest grants/admissions.
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                conn.execute('CREATE TABLE IF NOT EXISTS used(id TEXT PRIMARY KEY,expires INTEGER NOT NULL)')
                conn.execute('CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY,page TEXT NOT NULL,grant_id TEXT NOT NULL,expires INTEGER NOT NULL,policy_hash TEXT NOT NULL,token_hash TEXT NOT NULL,gateway_id TEXT NOT NULL,epoch INTEGER NOT NULL,resource TEXT NOT NULL)')
                yield conn
        finally:
            conn.close()

    def binding(self):
        value = json.loads(Path(os.environ['NHP_BINDING_FILE']).read_text())
        epoch = value['route']['epoch'] if nhp.INSTALLATION_ROUTING else 0
        if type(epoch) is not int or epoch < 0 or not isinstance(value['gateway_id'], str):
            raise ValueError('Invalid gateway binding')
        return value['gateway_id'], epoch

    def verify(self, token):
        if not isinstance(token, str) or len(token) > 4096:
            raise ValueError('Invalid handoff')
        prefix, body, signature = token.split('.')
        if prefix != 'nhp-guest-v1':
            raise ValueError('Invalid handoff')
        decode = lambda value: base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
        key = base64.b64decode(Path(os.environ['NHP_VERIFY_KEY_FILE']).read_text())
        Ed25519PublicKey.from_public_bytes(key).verify(decode(signature), (prefix + '.' + body).encode())
        claims = json.loads(decode(body))
        gateway_id, epoch = self.binding()
        now = int(time.time())
        if (claims.get('iss') != 'nhp-guest-authority' or claims.get('aud') != 'guest-gateway'
                or claims.get('gateway_id') != gateway_id
                or type(claims.get('iat')) is not int or type(claims.get('exp')) is not int
                or claims['iat'] > now + 5 or now >= claims['exp'] or not 0 < claims['exp'] - claims['iat'] <= 60
                or not isinstance(claims.get('guest_token'), str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', claims['guest_token'])
                or not isinstance(claims.get('grant_id'), str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', claims['grant_id'])):
            raise ValueError('Invalid handoff')
        if nhp.INSTALLATION_ROUTING and (type(claims.get('gateway_epoch')) is not int or claims['gateway_epoch'] != epoch):
            raise ValueError('Invalid gateway epoch')
        return claims, gateway_id, epoch

    def redeem(self, token, origin, frontend_resource):
        try:
            if origin != nhp.LANDING_ORIGIN:
                raise ValueError('Origin rejected')
            claims, gateway_id, epoch = self.verify(token)
            digest = hashlib.sha256(claims['guest_token'].encode()).hexdigest()
            with self.database() as conn, self.pages.authority_guard():
                conn.execute('BEGIN IMMEDIATE')
                now = int(time.time())
                if claims['exp'] <= now or self.binding() != (gateway_id, epoch):
                    raise ValueError('Expired handoff')
                match = None
                for item in self.pages.list_pages():
                    page = self.pages.load(item['id'])
                    for grant in page['access_grants']:
                        if grant['token_hash'] == digest and grant_expiry(grant) > now:
                            if match is not None:
                                raise ValueError('Ambiguous grant')
                            match = (page, grant)
                if match is None:
                    raise ValueError('Missing grant')
                page, grant = match
                if claims['resource'] != frontend_resource or claims['resource'] != nhp.resource_for_grant(page['id'], page.get('instance_id', ''), digest):
                    raise ValueError('Wrong resource')
                method, email = verification_policy(grant)
                if method != 'none':
                    expected = {'google': {'google_oidc'}, 'email': {'email_otp'}, 'google_or_email': {'google_oidc', 'email_otp'}}[method]
                    if claims.get('verification_method') not in expected or claims.get('verified_email') != email:
                        raise ValueError('Handoff does not satisfy guest policy')
                expires = min(now + 3600, int(grant_expiry(grant)))
                if nhp.INSTALLATION_ROUTING:
                    if claims.get('destination') != urlparse(nhp.origin_for_resource(claims['resource'])).netloc:
                        raise ValueError('Wrong destination')
                    if type(claims.get('session_exp')) is not int or not now < claims['session_exp'] <= claims['iat'] + 3600:
                        raise ValueError('Invalid session deadline')
                    expires = min(expires, claims['session_exp'])
                secret = secrets.token_urlsafe(32)
                conn.execute('DELETE FROM used WHERE expires<=?', (now,))
                conn.execute('DELETE FROM sessions WHERE expires<=?', (now,))
                conn.execute('INSERT INTO used VALUES(?,?)', (claims['grant_id'], claims['exp']))
                conn.execute('INSERT INTO sessions VALUES(?,?,?,?,?,?,?,?,?)', (
                    hashlib.sha256(secret.encode()).hexdigest(), page['id'], grant['id'], expires,
                    policy_hash(grant), digest, gateway_id, epoch, claims['resource']))
                conn.commit()
                return {'page_id': page['id'], 'session': secret, 'expires': expires}
        except Exception as error:
            raise GuestAuthorizationError('Invalid, used or expired NHP handoff') from error

    def authorize(self, page_id, secret, resource):
        """Caller holds authority_guard through authorization and HA dispatch."""
        try:
            if not isinstance(secret, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', secret):
                raise ValueError('Missing session')
            with self.database() as conn:
                row = conn.execute('SELECT * FROM sessions WHERE hash=? AND page=? AND expires>?', (
                    hashlib.sha256(secret.encode()).hexdigest(), page_id, int(time.time()))).fetchone()
            if row is None or row['resource'] != resource or self.binding() != (row['gateway_id'], row['epoch']):
                raise ValueError('Invalid session')
            page = self.pages.load(page_id)
            if row['resource'] != nhp.resource_for_grant(page_id, page.get('instance_id', ''), row['token_hash']):
                raise ValueError('Page route changed')
            grant = next((g for g in page['access_grants'] if g['id'] == row['grant_id']), None)
            if (grant is None or grant_expiry(grant) <= time.time()
                    or grant['token_hash'] != row['token_hash'] or policy_hash(grant) != row['policy_hash']):
                raise ValueError('Guest authorization changed')
            return {'grant': {k: v for k, v in grant.items() if k != 'token_hash'},
                    'expires': min(row['expires'], grant_expiry(grant)), 'resource': row['resource']}
        except Exception as error:
            raise GuestAuthorizationError('This access link has expired or been revoked.') from error
