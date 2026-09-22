"""Explicit local HA activation; never turn a legacy demo grant into real access."""
import json
import os
from pathlib import Path

from installation import atomic

LEGACY_DEMO_ENTITIES = frozenset({
    'light.nhp_demo_light', 'lock.nhp_demo_door', 'sensor.nhp_demo_temperature',
})


def activation_status(root, mode):
    """Return readiness/reason. Only an explicit HA selection can persist approval.

    Existing page/grant records are never migrated, deleted or reinterpreted.
    The owner must revoke old invitations and replace fake resources through the
    established Admin UI before installing/activating this candidate.
    """
    root = Path(root)
    if mode != 'homeassistant':
        return False, 'Select Home Assistant explicitly in the app configuration after reviewing its entities.'
    marker = root / 'ha-integration-approved.json'
    expected = {'version': 1, 'backend': 'homeassistant'}
    if marker.exists():
        try:
            if json.loads(marker.read_text()) == expected:
                return True, ''
        except (OSError, ValueError):
            pass
        return False, 'Home Assistant activation state needs owner review.'
    try:
        for path in (root / 'admin/pages').glob('*.json'):
            page = json.loads(path.read_text())
            if not isinstance(page, dict) or not isinstance(page.get('access_grants', []), list) or not isinstance(page.get('resources', []), list):
                raise ValueError('Invalid page')
            if page.get('access_grants'):
                return False, 'Revoke existing invitations in the previous app version before activating normal Home Assistant.'
            if any(resource.get('entity_id') in LEGACY_DEMO_ENTITIES for resource in page.get('resources', [])):
                return False, 'Replace legacy fake entities using the previous app Admin UI before activating normal Home Assistant.'
        atomic(marker, json.dumps(expected) + '\n')
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except (OSError, ValueError, TypeError, AttributeError):
        return False, 'Home Assistant activation state needs owner review.'
    return True, ''
