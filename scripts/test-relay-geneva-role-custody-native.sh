#!/usr/bin/env bash
# Root-only filesystem and proc regressions; no client/service/network activation.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
cd "$root"
# Retain compiler diagnostics on failure. CI uploads this private, uniquely
# named directory even when compilation prevents the native tests from running.
build_dir=$(umask 077; mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/aegis-role-custody-build.XXXXXXXX")
build_json="$build_dir/compiler.jsonl"
(umask 077; : > "$build_json")
cargo test --locked -p aegis-client --all-features --bin aegis-client --no-run --message-format=json > "$build_json"
test_binary=$(python3 - "$build_json" <<'PYCODE'
import json, sys
from pathlib import Path
rows=[json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines()]
binaries=[r['executable'] for r in rows if r.get('reason')=='compiler-artifact' and r.get('target',{}).get('name')=='aegis-client' and r.get('profile',{}).get('test') is True and r.get('executable')]
if len(binaries)!=1: raise SystemExit('one exact client test executable required')
p=Path(binaries[0]); p=p.resolve(strict=True)
if not p.is_file(): raise SystemExit('ordinary test executable required')
print(p)
PYCODE
)
sudo timeout --signal=TERM --kill-after=3s 30s "$test_binary"   profile_relay_geneva_role::linux::native_tests:: --ignored --test-threads=1
