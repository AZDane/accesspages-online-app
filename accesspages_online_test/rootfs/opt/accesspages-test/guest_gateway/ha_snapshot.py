"""Broker-owned HA entity feed and restricted-credential snapshot fallback."""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import logging
import math
import re
import threading
from time import monotonic
from urllib.parse import urlsplit, urlunsplit

from ha import HomeAssistantError, StateSnapshot


MAX_ENTITIES = 256
MAX_MESSAGE_BYTES = 1024 * 1024
READ_TIMEOUT = 6.0
IDLE_GRACE = 30.0
POLICY_INTERVAL = 1.0
MAX_DEMANDS = 128
MAX_CACHE_BYTES = 4 * MAX_MESSAGE_BYTES
# Frame-level debug logging must never expose the HA authentication message.
WIRE_LOGGER = logging.Logger('ha-snapshot-wire', level=logging.CRITICAL + 1)


def receive(connection, timeout):
    message = json.loads(connection.recv(timeout=timeout))
    if not isinstance(message, dict):
        raise ValueError('Invalid HA message')
    return message


@contextmanager
def open_ha(client):
    from websockets.sync.client import connect
    parsed = urlsplit(client.base_url)
    if parsed.scheme not in ('http', 'https') or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('Invalid HA base URL')
    url = urlunsplit(('wss' if parsed.scheme == 'https' else 'ws', parsed.netloc,
                     parsed.path.rstrip('/') + '/api/websocket', '', ''))
    with connect(url, open_timeout=2, close_timeout=0.2,
                 max_size=MAX_MESSAGE_BYTES, max_queue=1, compression=None,
                 ping_interval=None, proxy=None, logger=WIRE_LOGGER) as connection:
        greeting = receive(connection, 2)
        if greeting.get('type') != 'auth_required':
            raise ValueError('Expected HA authentication')
        version = re.match(r'^(\d+)\.(\d+)\.', str(greeting.get('ha_version', '')))
        if not version or tuple(map(int, version.groups())) < (2022, 4):
            raise ValueError('Filtered states require HA 2022.4 or later')
        connection.send(json.dumps({'type': 'auth', 'access_token': client.token}))
        if receive(connection, 2).get('type') != 'auth_ok':
            raise ValueError('HA authentication failed')
        yield connection


def _timestamp(value):
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError('Invalid HA timestamp')
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def decode_snapshot(event, requested):
    """Accept the initial additions map only, never a delta or unrequested data."""
    if not isinstance(event, dict) or set(event) != {'a'} or not isinstance(event['a'], dict):
        raise ValueError('Expected an HA initial snapshot')
    if not event['a'].keys() <= requested:
        raise ValueError('Unexpected HA entity')
    states = []
    for entity_id, value in event['a'].items():
        if (not isinstance(value, dict) or not isinstance(value.get('s'), str)
                or not isinstance(value.get('a'), dict)):
            raise ValueError('Invalid HA state')
        states.append({
            'entity_id': entity_id, 'state': value['s'], 'attributes': value['a'],
            'last_changed': _timestamp(value['lc']),
            'last_updated': _timestamp(value.get('lu', value['lc'])),
        })
    return states


class EntitySnapshots:
    """At most one HA socket and eight admitted readers, with no idle activity."""

    def __init__(self, client):
        self.client = client
        self._readers = threading.BoundedSemaphore(8)
        self._connection = threading.Lock()

    def read(self, entity_ids):
        requested = frozenset(entity_ids)
        if (not requested or len(requested) > MAX_ENTITIES
                or any(not isinstance(item, str) or not re.fullmatch(r'[a-z0-9_]+\.[a-z0-9_]+', item)
                       for item in requested)):
            raise HomeAssistantError('Invalid filtered state request')
        if not self._readers.acquire(blocking=False):
            raise HomeAssistantError('State reader is busy')
        deadline = monotonic() + READ_TIMEOUT
        acquired = False
        try:
            acquired = self._connection.acquire(timeout=READ_TIMEOUT)
            if not acquired:
                raise TimeoutError('State reader is busy')
            return self._read(requested, deadline)
        except HomeAssistantError:
            raise
        except Exception as error:
            # No upstream message, URL, token, or raw entity attributes in errors.
            raise HomeAssistantError('Home Assistant state snapshot failed') from error
        finally:
            if acquired:
                self._connection.release()
            self._readers.release()

    def _read(self, requested, deadline):
        def remaining():
            value = deadline - monotonic()
            if value <= 0:
                raise TimeoutError('HA snapshot deadline exceeded')
            return value

        remaining()
        with open_ha(self.client) as connection:
            connection.send(json.dumps({'id': 1, 'type': 'subscribe_entities',
                                        'entity_ids': sorted(requested)}))
            result = receive(connection, remaining())
            if result.get('id') != 1 or result.get('type') != 'result' or result.get('success') is not True:
                raise ValueError('HA subscription failed')
            message = receive(connection, remaining())
            observed_at = datetime.now(timezone.utc).isoformat()
            if message.get('id') != 1 or message.get('type') != 'event':
                raise ValueError('Expected HA snapshot')
            states = decode_snapshot(message.get('event'), requested)
            connection.send(json.dumps({'id': 2, 'type': 'unsubscribe_events', 'subscription': 1}))
            # Closing also removes the listener if the unsubscribe is not acked.
            # No further event on this connection can supply a later request.
            return StateSnapshot(states, observed_at)


def apply_delta(states, event, requested):
    """Apply HA compressed diffs to a private candidate, then publish atomically."""
    if not isinstance(event, dict) or not set(event) <= {'a', 'c', 'r'}:
        raise ValueError('Invalid HA update')
    changed = set()
    for state in decode_snapshot({'a': event.get('a', {})}, requested):
        states[state['entity_id']] = state
        changed.add(state['entity_id'])
    removed = event.get('r', [])
    if not isinstance(removed, list) or any(not isinstance(item, str) or item not in requested for item in removed):
        raise ValueError('Invalid HA removal')
    for entity in removed:
        states.pop(entity, None)
        changed.add(entity)
    updates = event.get('c', {})
    if not isinstance(updates, dict) or not updates.keys() <= requested:
        raise ValueError('Invalid HA changes')
    for entity, diff in updates.items():
        if entity not in states or not isinstance(diff, dict) or not set(diff) <= {'+', '-'}:
            raise ValueError('HA changed an unknown entity')
        added, deleted = diff.get('+', {}), diff.get('-', {})
        if not isinstance(added, dict) or not isinstance(deleted, dict) or not set(deleted) <= {'a'}:
            raise ValueError('Invalid HA change')
        state = states[entity]
        if 's' in added:
            if not isinstance(added['s'], str):
                raise ValueError('Invalid HA state')
            state['state'] = added['s']
        if 'lc' in added:
            state['last_changed'] = state['last_updated'] = _timestamp(added['lc'])
        elif 'lu' in added:
            state['last_updated'] = _timestamp(added['lu'])
        attributes = added.get('a', {})
        removed_attributes = deleted.get('a', [])
        if (not isinstance(attributes, dict) or not isinstance(removed_attributes, list)
                or any(not isinstance(key, str) for key in removed_attributes)):
            raise ValueError('Invalid HA attributes')
        state['attributes'].update(attributes)
        for key in removed_attributes:
            state['attributes'].pop(key, None)
        changed.add(entity)
    if len(json.dumps(states).encode()) > MAX_CACHE_BYTES:
        raise ValueError('HA state cache too large')
    return changed


@dataclass(frozen=True)
class Demand:
    requested: frozenset
    eligible: frozenset
    until: float


class EntityStateFeed:
    """One connection for the union of recently authorized guest reads.

    resolve(key, requested) revalidates broker authority without HA/network I/O.
    It is called outside the feed lock, so policy and cache locks never invert.
    """
    def __init__(self, client, resolve):
        self.client, self.resolve = client, resolve
        self.fallback = EntitySnapshots(client)
        self._condition = threading.Condition()
        self._demands = {}
        self._target = frozenset()
        self._generation = 0
        self._states, self._observed = {}, {}
        self._synced = None
        self._requested_probe = self._confirmed_probe = 0
        self._errors = 0
        self._stopped = False
        self._thread = None
        self._readers = threading.BoundedSemaphore(8)

    def _invalidate(self):
        self._generation += 1
        self._states, self._observed, self._synced = {}, {}, None
        self._confirmed_probe = 0
        self._condition.notify_all()

    def _retarget(self):
        target = frozenset().union(*(d.eligible for d in self._demands.values()))
        if len(target) > MAX_ENTITIES:
            raise HomeAssistantError('Too many active HA entities')
        if target != self._target:
            self._target = target
            self._invalidate()

    def clear(self):
        with self._condition:
            self._demands.clear()
            self._target = frozenset()
            self._invalidate()

    def withdraw(self, key):
        with self._condition:
            self._demands.pop(key, None)
            self._retarget()

    def reconcile(self):
        with self._condition:
            demands = list(self._demands.items())
        for key, demand in demands:
            try:
                eligible = frozenset(self.resolve(key, demand.requested)) if monotonic() < demand.until else frozenset()
                eligible &= demand.requested
            except Exception:
                eligible = frozenset()
            with self._condition:
                if self._demands.get(key) is not demand:
                    continue
                if eligible:
                    self._demands[key] = Demand(demand.requested, eligible, demand.until)
                else:
                    self._demands.pop(key, None)
                self._retarget()

    def read(self, entity_ids, *, demand_key):
        if not self._readers.acquire(blocking=False):
            raise HomeAssistantError('State reader is busy')
        try:
            return self._read(entity_ids, demand_key)
        finally:
            self._readers.release()

    def _read(self, entity_ids, demand_key):
        requested = frozenset(entity_ids)
        if not requested or len(requested) > MAX_ENTITIES:
            raise HomeAssistantError('Invalid state demand')
        # A fixed, constant template proves current token validity AND admin
        # status. It reads no entities and cannot be supplied by a guest.
        try:
            admin = self.client._request('POST', '/api/template', {'template': 'true'})
            if admin is not True:
                raise HomeAssistantError('HA state authority could not be established')
        except HomeAssistantError as error:
            self.clear()
            if error.status in (401, 403):
                # Restricted HA users must have fresh entity permission checks.
                # An invalid token still fails the new connection's auth step.
                return self.fallback.read(requested)
            raise HomeAssistantError('HA state authority unavailable') from error
        with self._condition:
            if self._stopped:
                raise HomeAssistantError('State feed is stopped')
            if demand_key not in self._demands and len(self._demands) >= MAX_DEMANDS:
                raise HomeAssistantError('Too many active guest state sessions')
            union = requested.union(*(d.eligible for key, d in self._demands.items() if key != demand_key))
            if len(union) > MAX_ENTITIES:
                raise HomeAssistantError('Too many active HA entities')
            self._demands[demand_key] = Demand(requested, requested, monotonic() + IDLE_GRACE)
            self._retarget()
            self._requested_probe += 1
            probe, errors = self._requested_probe, self._errors
            if self._thread is None:
                self._thread = threading.Thread(target=self._run, name='ha-entity-feed', daemon=True)
                self._thread.start()
            self._condition.notify_all()
            deadline = monotonic() + READ_TIMEOUT
            while True:
                if self._stopped or self._errors != errors or demand_key not in self._demands:
                    raise HomeAssistantError('HA state feed unavailable')
                if self._synced and requested <= self._target and self._confirmed_probe >= probe:
                    observed = max((self._observed.get(entity, self._synced) for entity in requested))
                    return StateSnapshot(deepcopy([self._states[entity] for entity in sorted(requested) if entity in self._states]), observed)
                remaining = deadline - monotonic()
                if remaining <= 0:
                    self._errors += 1
                    self._invalidate()
                    raise HomeAssistantError('HA state feed timed out')
                self._condition.wait(remaining)

    def close(self):
        with self._condition:
            self._stopped = True
            self._invalidate()
        if self._thread:
            self._thread.join(timeout=7)

    def _run(self):
        backoff = 1.0
        while True:
            self.reconcile()
            with self._condition:
                if self._stopped:
                    return
                if not self._target:
                    self._condition.wait()
                    continue
                generation, target = self._generation, self._target
            try:
                # Shares the connection limit with the restricted-user fallback.
                with self.fallback._connection:
                    with open_ha(self.client) as connection:
                        self._listen(connection, generation, target)
                backoff = 1.0
            except Exception:
                with self._condition:
                    if self._stopped:
                        return
                    if generation == self._generation:
                        self._errors += 1
                        self._invalidate()
                    retry_at = monotonic() + backoff
                    while not self._stopped and self._target and monotonic() < retry_at:
                        self._condition.wait(retry_at - monotonic())
                backoff = min(30.0, backoff * 2)

    def _listen(self, connection, generation, target):
        # This one narrow event invalidates state across HA user/group changes.
        # It also requires admin privileges, independently of the REST guard.
        connection.send(json.dumps({'id': 1, 'type': 'subscribe_events', 'event_type': 'user_updated'}))
        result = receive(connection, 2)
        if result.get('id') != 1 or result.get('type') != 'result' or result.get('success') is not True:
            raise ValueError('HA authority subscription failed')
        connection.send(json.dumps({'id': 2, 'type': 'subscribe_entities', 'entity_ids': sorted(target)}))
        ready = False
        awaiting_initial = True
        next_policy = 0.0
        initial_deadline = monotonic() + 3
        next_ping, ping_deadline, pending_ping = 0.0, 0.0, None
        sequence = 2
        while True:
            now = monotonic()
            if now >= next_policy:
                self.reconcile()
                next_policy = now + POLICY_INTERVAL
            with self._condition:
                if self._stopped or generation != self._generation:
                    connection.send(json.dumps({'id': sequence + 1, 'type': 'unsubscribe_events', 'subscription': 2}))
                    return
                need_probe = self._requested_probe > self._confirmed_probe
                if ready and not awaiting_initial and pending_ping is None and (need_probe or now >= next_ping):
                    sequence += 1
                    pending_ping = (sequence, self._requested_probe)
                    connection.send(json.dumps({'id': sequence, 'type': 'ping'}))
                    ping_deadline = now + 3
            if (awaiting_initial and now >= initial_deadline) or (pending_ping and now >= ping_deadline):
                raise TimeoutError('HA state feed is uncertain')
            try:
                message = receive(connection, .1)
            except TimeoutError:
                continue
            kind, identifier = message.get('type'), message.get('id')
            if kind == 'event' and identifier == 1:
                raise ValueError('HA user authority changed; resynchronize')
            if kind == 'result' and identifier == 2 and message.get('success') is True and not ready:
                ready = True
            elif kind == 'event' and identifier == 2 and ready:
                with self._condition:
                    if generation != self._generation:
                        return
                    candidate = deepcopy(self._states)
                    if awaiting_initial:
                        candidate = {state['entity_id']: state for state in decode_snapshot(message.get('event'), target)}
                        if len(json.dumps(candidate).encode()) > MAX_CACHE_BYTES:
                            raise ValueError('HA state cache too large')
                        changed = target
                    else:
                        changed = apply_delta(candidate, message.get('event'), target)
                    stamp = datetime.now(timezone.utc).isoformat()
                    self._states = candidate
                    for entity in changed:
                        self._observed[entity] = stamp
                    if awaiting_initial:
                        self._synced = stamp
                        awaiting_initial = False
                    self._condition.notify_all()
            elif kind == 'pong' and pending_ping and identifier == pending_ping[0]:
                with self._condition:
                    if generation == self._generation:
                        self._confirmed_probe = pending_ping[1]
                        self._condition.notify_all()
                pending_ping = None
                next_ping = monotonic() + 5
            else:
                raise ValueError('Unexpected HA feed message')
