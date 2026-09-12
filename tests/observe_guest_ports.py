"""Bounded TCP observation from a runner that receives no AccessLink credentials."""
import ipaddress
import json
import os
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone


def stamp():
    return datetime.now(timezone.utc).isoformat()


def main():
    inputs = json.loads(os.environ.pop('ACCESSPAGES_OBSERVER_TARGETS'))
    address = str(ipaddress.IPv4Address(inputs['address']))
    ports = inputs['ports']
    if not ipaddress.ip_address(address).is_global or ports != [20002, 20003]:
        raise ValueError('Unexpected observer scope')
    print('::add-mask::' + address, flush=True)

    def reachable(port):
        try:
            with socket.create_connection((address, port), timeout=1.5):
                return True
        except OSError:
            return False

    report = {'started': stamp(), 'credential_free': True, 'samples': []}
    end = time.monotonic() + 240
    with ThreadPoolExecutor(max_workers=2) as pool:
        while time.monotonic() < end:
            started = time.monotonic()
            values = list(pool.map(reachable, ports))
            report['samples'].append({'at': stamp(), 'demo_1_reachable': values[0], 'demo_2_reachable': values[1]})
            time.sleep(max(0, 3 - (time.monotonic() - started)))
    report['finished'] = stamp()
    report['passed'] = bool(report['samples']) and all(not x['demo_1_reachable'] and not x['demo_2_reachable'] for x in report['samples'])
    print('OBSERVER_CHECK_RESULT ' + json.dumps(report, separators=(',', ':')), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print('OBSERVER_CHECK_RESULT ' + json.dumps({'passed': False, 'failure_type': type(error).__name__}), flush=True)
        raise SystemExit(1)
