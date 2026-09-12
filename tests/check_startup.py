"""Exercise the actual app entry point in disposable, network-isolated containers.

Run on a Linux CI runner with the app image and its AppArmor profile loaded.
No Home Assistant token, cloud credentials, host files, or public ports are used.
"""
import json
from pathlib import Path
import subprocess
import sys
import time


def docker(*args, check=True):
    return subprocess.run(
        ['docker', *args], check=check, capture_output=True, text=True, timeout=20,
    )


def check_startup(image, name, *, apparmor=False):
    args = ['run', '--detach', '--network', 'none', '--cap-drop', 'NET_RAW',
            '--pids-limit', '128', '--memory', '512m', '--tmpfs', '/data:rw,mode=0755',
            '--env', 'NHP_ADMIN_PROXY_IPS=127.0.0.1']
    if apparmor:
        args += ['--security-opt', 'apparmor=accesspages_online_test']
    ident = docker(*args, image).stdout.strip()
    result = {'case': name, 'passed': False}
    probe = (
        "import json,urllib.request; "
        "r=urllib.request.urlopen('http://127.0.0.1:8099/setup/status',timeout=2); "
        "s=json.load(r); assert r.status==200 and s['enrolled'] is False "
        "and s['ready'] is False and s['device_data']=='demo'; "
        "page=urllib.request.urlopen('http://127.0.0.1:8099/',timeout=2).read(); "
        "assert b'enrollment_token' in page and b'demo data only' in page and b'SERVICE_ADDRESS' not in page; print('setup-ready')"
    )
    try:
        for _ in range(20):
            running = docker('inspect', '--format', '{{.State.Running}}', ident).stdout.strip()
            if running != 'true':
                break
            reply = docker('exec', ident, 'python3', '-c', probe, check=False)
            if reply.returncode == 0 and reply.stdout.strip() == 'setup-ready':
                if apparmor:
                    label = docker('exec', ident, 'cat', '/proc/self/attr/current').stdout.strip()
                    assert label == 'accesspages_online_test (enforce)', label
                    result['apparmor_enforced'] = True
                    boundary = (
                        "import os; "
                        "assert 'installation.py' in os.listdir('/opt/accesspages-test'); "
                        "p='/opt/accesspages-test/installation.py'; "
                        "print('readable' if open(p,'rb').read(1) else 'empty'); "
                        "\ntry: fd=os.open(p,os.O_WRONLY)"
                        "\nexcept PermissionError: print('code-write-denied')"
                        "\nelse: os.close(fd); raise AssertionError('App code is writable')"
                    )
                    protection = docker('exec', ident, 'python3', '-c', boundary)
                    assert protection.stdout.strip() == 'readable\ncode-write-denied'
                    result['app_code_write_denied'] = True
                demo = subprocess.run(
                    ['docker', 'exec', '-i', '--env',
                     'PYTHONPATH=/opt/accesspages-test:/opt/accesspages-test/guest_gateway',
                     ident, 'python3', '-B', '-'],
                    input=Path(__file__).with_name('test_demo_data.py').read_text(),
                    text=True, capture_output=True, timeout=30,
                )
                result['demo_tests_passed'] = demo.returncode == 0
                result['demo_tests_output'] = demo.stderr[-12000:]
                enrollment = subprocess.run(
                    ['docker', 'exec', '-i', '--env',
                     'PYTHONPATH=/opt/accesspages-test:/opt/accesspages-test/guest_gateway',
                     ident, 'python3', '-B', '-'],
                    input=Path(__file__).with_name('test_enrollment.py').read_text(),
                    text=True, capture_output=True, timeout=30,
                )
                result['enrollment_tests_passed'] = enrollment.returncode == 0
                result['enrollment_tests_output'] = enrollment.stderr[-12000:]
                result['passed'] = demo.returncode == 0 and enrollment.returncode == 0
                break
            time.sleep(0.5)
        if not result['passed']:
            result['logs'] = docker('logs', ident, check=False).stderr[-12000:]
    finally:
        docker('rm', '--force', ident, check=False)
    print(json.dumps(result), flush=True)
    return result['passed']


if __name__ == '__main__':
    image = sys.argv[1]
    results = [
        check_startup(image, 'default-container'),
        check_startup(image, 'app-apparmor', apparmor=True),
    ]
    raise SystemExit(0 if all(results) else 1)
