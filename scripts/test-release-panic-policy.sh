#!/usr/bin/env bash
# Exercise the actual workspace release profile in a standalone child process.
# No network, privileged operation or installed daemon is involved.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="$(mktemp -d "${TMPDIR:-/tmp}/aegis-panic-release.XXXXXX")"
trap 'rm -rf "${TARGET}"' EXIT

CARGO_TARGET_DIR="${TARGET}" cargo build --locked --release \
  --manifest-path "${ROOT}/Cargo.toml" -p aegis-panic-release-proof --quiet

python3 - "${TARGET}/release/aegis-panic-release-proof" <<'PY'
import resource
import subprocess
import sys

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
result = subprocess.run([sys.argv[1]], stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, text=True, timeout=10)
if result.returncode != 0 or result.stdout.strip() != 'release_panic_caught_and_guard_dropped':
    raise SystemExit('release panic policy failed: worker abort or rollback Drop was lost')
print('release panic catch and rollback Drop: PASS')
PY
