"""Build as Supervisor does, then verify the installed architecture and APK lock.

Run on a native Linux runner for each advertised architecture. No BUILD_FROM is
injected: that previously hid Supervisor's rejection of digest-valued build.yaml.
See home-assistant/supervisor commit 3e750c3041066ddd551334d00e0cf9fb482a3b94,
supervisor/apps/build.py (_read_build_config and get_docker_args).
"""
import argparse
import json
from pathlib import Path
import re
import subprocess


PACKAGE = Path(__file__).resolve().parents[1] / 'accesspages_online_test'
ARCHITECTURES = {'amd64': ('linux/amd64', 'x86_64'),
                 'aarch64': ('linux/arm64', 'aarch64')}


def package_version(package):
    for suffix in ('yaml', 'yml', 'json'):
        if (package / f'build.{suffix}').exists():
            raise ValueError('Legacy build configuration would override Dockerfile base selection')
    match = re.search(r'^version: ([\w.\-]+)$', (package / 'config.yaml').read_text(), re.M)
    if not match:
        raise ValueError('Missing unquoted package version in config.yaml')
    return match[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image')
    parser.add_argument('--arch', choices=ARCHITECTURES, required=True)
    parser.add_argument('--docker-wrapper', type=Path)
    parser.add_argument('--check-only', action='store_true', help='Check an already built image')
    args = parser.parse_args()
    version = package_version(PACKAGE)
    platform, apk_arch = ARCHITECTURES[args.arch]
    docker = ([str(args.docker_wrapper.resolve(strict=True)), 'docker']
              if args.docker_wrapper else ['docker'])
    if not args.check_only:
        # Same platform, build arguments and pull behavior as Supervisor with no
        # build.yaml. Image labels come from the Dockerfile as well as Supervisor.
        subprocess.run([*docker, 'build', '--progress=plain', '--pull',
                        '--platform', platform, '--build-arg', f'BUILD_ARCH={args.arch}',
                        '--build-arg', f'BUILD_VERSION={version}',
                        '-t', args.image, str(PACKAGE)], check=True)

    metadata = json.loads(subprocess.check_output(
        [*docker, 'image', 'inspect', '--format',
         '{"architecture":{{json .Architecture}},"labels":{{json .Config.Labels}}}',
         args.image], text=True))
    if metadata['architecture'] != platform.split('/')[1]:
        raise ValueError(f'Wrong image architecture: {metadata}')
    for key, value in {'io.hass.arch': args.arch, 'io.hass.version': version}.items():
        if metadata['labels'].get(key) != value:
            raise ValueError(f'Wrong image label {key}')
    expected = {'architecture': apk_arch, 'version': version,
                'packages': PACKAGE.joinpath('apk.lock').read_text().splitlines()}
    probe = '''
import json, pathlib, subprocess, sys
expected = json.load(sys.stdin)
architecture = subprocess.check_output(['apk', '--print-arch'], text=True).strip()
assert architecture == expected['architecture'], architecture
alpine = pathlib.Path('/etc/alpine-release').read_text().strip()
assert alpine.startswith('3.22.'), alpine
installed = set(subprocess.check_output(['apk', 'info', '-v'], text=True).splitlines())
missing = sorted(pin for pin in expected['packages'] if pin.replace('=', '-', 1) not in installed)
assert not missing, missing
assert pathlib.Path('/opt/accesspages-test/version').read_text().strip() == expected['version']
print(json.dumps({'architecture': architecture, 'alpine': alpine,
                  'locked_packages': len(expected['packages']), 'passed': True}))
'''
    subprocess.run([*docker, 'run', '--rm', '-i', '--network', 'none',
                    '--entrypoint', 'python3', args.image, '-B', '-c', probe],
                   input=json.dumps(expected), text=True, check=True)


if __name__ == '__main__':
    main()
