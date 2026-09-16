#!/bin/sh
set -eu
patch_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "${1:-/src}"
# Pinned protocol implementation: change diagnostic content only.
check_hash() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum -c
    else shasum -a 256 -c
    fi
}
check_hash <<'HASHES'
0a16248d9fa1663bd863cfc0016740360c0edde236a2e8688ddef89e565af8ea  nhp/core/device.go
HASHES
git apply --check "$patch_dir/native-payload-logging.patch"
git apply "$patch_dir/native-payload-logging.patch"
