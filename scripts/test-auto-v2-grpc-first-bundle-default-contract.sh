#!/usr/bin/env bash
# Actual secret-reader and bundle-renderer contract for the legacy AUTO V2
# wide TCP probe. Only fresh defaults change; explicit operator plans survive.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/aegis-v2-bundle-default.XXXXXX")"
chmod 0700 "$WORK"
trap 'rm -rf "$WORK"' EXIT
READER="${AEGIS_TEST_SECRET_READER:-${ROOT}/target/debug/aegis-server}"
[[ "$READER" == /* && -x "$READER" ]] || { echo 'actual Rust secret reader required' >&2; exit 2; }
[[ "$("$READER" installer-secret version)" == installer-secret-v1 ]] || exit 2
TOKEN='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
printf '%s\n' '-----BEGIN CERTIFICATE-----' 'contract' '-----END CERTIFICATE-----' > "$WORK/ca.pem"

# The real server installer passes this variable to the real renderer. Assert
# their default stays aligned while still exercising the renderer below.
python3 -I - "$ROOT/install.sh" <<'PY_CHECK_WIRING'
from pathlib import Path
import re, sys
text=Path(sys.argv[1]).read_text()
want='grpc_stream,https_ws,legacy_tls,masque_derived'
assert re.findall(r'^RELAY_TRANSPORT_PRIORITY="([^"]+)"$', text, re.M)==[want]
assert '"${RELAY_TRANSPORT_PRIORITY}"' in text
PY_CHECK_WIRING

printf '%s' "$TOKEN" | bash "$ROOT/scripts/render-client-bundle.sh" \
  "$WORK/default" '192.0.2.44:443' 'relay.fixture.invalid' \
  --auth-token-stdin "$WORK/ca.pem" "$READER" >"$WORK/default.stdout" 2>"$WORK/default.stderr"
printf '%s' "$TOKEN" | bash "$ROOT/scripts/render-client-bundle.sh" \
  "$WORK/explicit" '192.0.2.44:443' 'relay.fixture.invalid' \
  --auth-token-stdin "$WORK/ca.pem" "$READER" '' \
  'https_ws,grpc_stream,legacy_tls,masque_derived' >"$WORK/explicit.stdout" 2>"$WORK/explicit.stderr"

python3 -I - "$WORK" "$TOKEN" <<'PY_CHECK_BUNDLES'
import os, pathlib, stat, sys, tomllib
root=pathlib.Path(sys.argv[1]); token=sys.argv[2]
expected={
    'default':['grpc_stream','https_ws','legacy_tls','masque_derived'],
    'explicit':['https_ws','grpc_stream','legacy_tls','masque_derived'],
}
for name, plan in expected.items():
    bundle=root/name
    assert stat.S_IMODE(bundle.stat().st_mode)==0o700
    for leaf in ('aegis-client.toml','aegis-client-privileged-dns.toml'):
        path=bundle/leaf
        assert stat.S_IMODE(path.stat().st_mode)==0o600
        parsed=tomllib.loads(path.read_text())
        relay=parsed['relay']
        assert relay['transport_priority']==plan
        assert relay['auth_token']==token
        assert relay['server']=='192.0.2.44:443'
        assert relay['server_name']=='relay.fixture.invalid'
    for leaf in (name+'.stdout', name+'.stderr'):
        assert token.encode() not in (root/leaf).read_bytes()
print('ok')
PY_CHECK_BUNDLES
