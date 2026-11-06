#!/usr/bin/env bash
# Regression: full-wide root capture must pin every relay pool endpoint, not
# only relay.server. A hostname left inside an inline endpoints array resolves
# through fake-IP DNS after activation and recursively captures the client's own
# Cloudflare gRPC control connection.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-pin-relays.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

awk '
  /^pin_relay_server_to_resolved_ipv4\(\)/ { in_function=1 }
  in_function && /python3 -I - "\$cfg" <<'\''PY'\''/ { in_python=1; next }
  in_python && /^PY$/ { exit }
  in_python { print }
' "${ROOT}/install.sh" > "${TMP_DIR}/pin.py"

cat > "${TMP_DIR}/client.toml" <<'EOF'
[relay]
server = "localhost:443"
server_name = "primary.example"
transport_priority = ["grpc_stream"]
endpoints = [
  { server = "localhost:443", server_name = "failover-one.example" },
  { server = "localhost:8443", server_name = "failover-two.example" }
]
masque_server = "203.0.113.9:8443"
EOF

python3 -I "${TMP_DIR}/pin.py" "${TMP_DIR}/client.toml" 2>"${TMP_DIR}/pin.log"

count="$(grep -Ec '\bserver = "127\.0\.0\.1:(443|8443)"' "${TMP_DIR}/client.toml")"
[[ "${count}" == "3" ]] || {
  echo "expected all three relay endpoints to be pinned, got ${count}" >&2
  cat "${TMP_DIR}/client.toml" >&2
  exit 1
}
grep -Fq 'server_name = "primary.example"' "${TMP_DIR}/client.toml"
grep -Fq 'server_name = "failover-one.example"' "${TMP_DIR}/client.toml"
grep -Fq 'server_name = "failover-two.example"' "${TMP_DIR}/client.toml"
grep -Fq 'masque_server = "203.0.113.9:8443"' "${TMP_DIR}/client.toml"
[[ "$(grep -Fc 'relay loop-avoidance: pinned endpoint' "${TMP_DIR}/pin.log")" == "3" ]]

cat > "${TMP_DIR}/invalid.toml" <<'EOF'
[relay]
server = "127.0.0.1:443"
server_name = "primary.example"
endpoints = [
  { server = "localhost:not-a-port", server_name = "broken.example" }
]
EOF
cp "${TMP_DIR}/invalid.toml" "${TMP_DIR}/invalid.before"
if python3 -I "${TMP_DIR}/pin.py" "${TMP_DIR}/invalid.toml" 2>"${TMP_DIR}/invalid.log"; then
  echo "pinning unexpectedly accepted an unusable relay endpoint" >&2
  exit 1
fi
cmp "${TMP_DIR}/invalid.before" "${TMP_DIR}/invalid.toml"
grep -Fq 'refusing full-wide activation with an unpinned relay endpoint' "${TMP_DIR}/invalid.log"

# relay_hosts_from_config must also understand the inline endpoint form; keep a
# textual guard so the firewall-exclusion path cannot silently regress to only
# parsing [[relay.endpoints]] array-of-table syntax.
grep -Fq 'hosts.extend(em.group(1) for em in re.finditer' "${ROOT}/install.sh"
grep -Fq 'relay.group(0)' "${ROOT}/install.sh"

echo "PASS: every inline relay endpoint is pinned for full-wide loop avoidance"
