#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

OLD="$(printf '1%.0s' {1..64})"
NEW="$(printf '2%.0s' {1..64})"
SOCKS="$(printf '3%.0s' {1..64})"
EXPIRY="$(( $(date +%s) + 3600 ))"

cat >"${TMP}/server.toml" <<EOF
listen = "127.0.0.1:8443"
cert = "cert.pem"
key = "key.pem"
auth_token = "${OLD}"

[transport]
grpc_path = "/rpc"
EOF
chmod 640 "${TMP}/server.toml"

printf '%s' "${NEW}" | python3 "${ROOT}/scripts/lib/rotate-auth-token-remote.py" \
  "${TMP}/server.toml" server legacy-test "${EXPIRY}" >/dev/null
grep -qF "auth_token = \"${NEW}\"" "${TMP}/server.toml"
grep -qF 'id = "legacy-test"' "${TMP}/server.toml"
grep -qF "auth_token = \"${OLD}\"" "${TMP}/server.toml"
grep -qF "not_after_unix_secs = ${EXPIRY}" "${TMP}/server.toml"
[[ "$(stat -c %a "${TMP}/server.toml" 2>/dev/null || stat -f %Lp "${TMP}/server.toml")" == 640 ]]
server_backups=("${TMP}"/server.toml.pre-rotate.*)
[[ ${#server_backups[@]} -eq 1 ]]
[[ "$(stat -c %a "${server_backups[0]}" 2>/dev/null || stat -f %Lp "${server_backups[0]}")" == 600 ]]

cat >"${TMP}/client.toml" <<EOF
[socks]
auth_token = "${SOCKS}"

[relay]
auth_token = "${OLD}"
EOF
chmod 600 "${TMP}/client.toml"
printf '%s' "${NEW}" | python3 "${ROOT}/scripts/lib/rotate-auth-token-remote.py" \
  "${TMP}/client.toml" client >/dev/null
grep -qF "auth_token = \"${SOCKS}\"" "${TMP}/client.toml"
grep -qF "auth_token = \"${NEW}\"" "${TMP}/client.toml"
! grep -qF "auth_token = \"${OLD}\"" "${TMP}/client.toml"

# Refuse paths/configs that a less-privileged local user could redirect or
# rewrite between validation and replacement.
ln -s "${TMP}/client.toml" "${TMP}/client-link.toml"
set +e
printf '%s' "${OLD}" | python3 "${ROOT}/scripts/lib/rotate-auth-token-remote.py" \
  "${TMP}/client-link.toml" client >"${TMP}/symlink.out" 2>&1
rc=$?
set -e
[[ ${rc} -ne 0 ]]
grep -qF 'stable regular file' "${TMP}/symlink.out"

cp "${TMP}/client.toml" "${TMP}/world-writable-client.toml"
chmod 666 "${TMP}/world-writable-client.toml"
set +e
printf '%s' "${OLD}" | python3 "${ROOT}/scripts/lib/rotate-auth-token-remote.py" \
  "${TMP}/world-writable-client.toml" client >"${TMP}/world-writable.out" 2>&1
rc=$?
set -e
[[ ${rc} -ne 0 ]]
grep -qF 'not group/world writable' "${TMP}/world-writable.out"

cat >"${TMP}/incident-current.toml" <<EOF
listen = "127.0.0.1:8443"
cert = "cert.pem"
key = "key.pem"
auth_token = "${NEW}"
EOF
cat >"${TMP}/incident-backup.toml" <<EOF
listen = "127.0.0.1:8443"
cert = "cert.pem"
key = "key.pem"
auth_token = "${OLD}"
EOF
chmod 600 "${TMP}/incident-backup.toml"
python3 "${ROOT}/scripts/lib/stage-legacy-auth-token-remote.py" \
  "${TMP}/incident-current.toml" "${TMP}/incident-backup.toml" legacy-incident "${EXPIRY}" \
  >/dev/null
grep -qF "auth_token = \"${NEW}\"" "${TMP}/incident-current.toml"
grep -qF "auth_token = \"${OLD}\"" "${TMP}/incident-current.toml"
grep -qF 'id = "legacy-incident"' "${TMP}/incident-current.toml"

cp "${TMP}/incident-current.toml.pre-legacy."* "${TMP}/insecure-backup.toml"
chmod 644 "${TMP}/insecure-backup.toml"
cp "${TMP}/incident-current.toml" "${TMP}/incident-current-2.toml"
set +e
python3 "${ROOT}/scripts/lib/stage-legacy-auth-token-remote.py" \
  "${TMP}/incident-current-2.toml" "${TMP}/insecure-backup.toml" legacy-insecure "${EXPIRY}" \
  >"${TMP}/insecure-backup.out" 2>&1
rc=$?
set -e
[[ ${rc} -ne 0 ]]
grep -qF 'mode 0600 or stricter' "${TMP}/insecure-backup.out"

set +e
bash "${ROOT}/scripts/rotate-relay-auth-token.sh" \
  --relays relay.invalid --clients client.invalid \
  --legacy-id legacy-test --legacy-not-after "${EXPIRY}" \
  >"${TMP}/no-confirm.out" 2>&1
rc=$?
set -e
[[ ${rc} -eq 2 ]]
grep -qF -- '--confirm-staged-rotation' "${TMP}/no-confirm.out"

echo "staged auth rotation contract passed"
