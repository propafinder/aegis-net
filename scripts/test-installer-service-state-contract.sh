#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="${ROOT}/install.sh"

grep -Fq -- '--manifest-path "${ROOT}/Cargo.toml"' "${INSTALLER}"
grep -Fq -- 'inject_client_service_state_path "${config_path}" "${state_dir}"' "${INSTALLER}"
grep -Fq -- 'service_state_path="${state_dir%/}/state.json"' "${INSTALLER}"
grep -Fq -- '-z "${AEGIS_INSTALL_NONINTERACTIVE:-}"' "${INSTALLER}"

# Service hardening and the rewritten state path are one contract: ProtectHome
# remains enabled while the Brain writes only under the allowed state dir.
grep -Fq 'ProtectHome=true' "${ROOT}/packaging/systemd/aegis-client.service"
grep -Fq 'ReadWritePaths=__AEGIS_CLIENT_STATE_DIR__' "${ROOT}/packaging/systemd/aegis-client.service"

# The server and pinned origin guard do not perform outbound bootstrap work.
# Requiring network-online made Debian ifupdown relays wait for an unrelated
# systemd-networkd timeout before either unit could start after reboot.
grep -Fq 'After=network.target aegis-origin-guard.service' "${ROOT}/packaging/systemd/aegis-server.service"
grep -Fq 'Wants=network.target' "${ROOT}/packaging/systemd/aegis-server.service"
if grep -Fq 'network-online.target' "${ROOT}/packaging/systemd/aegis-server.service"; then
  echo "server unit must not wait for network-online.target" >&2
  exit 1
fi
grep -Fq 'After=network.target nftables.service' "${ROOT}/packaging/systemd/aegis-origin-guard.service"
grep -Fq 'Before=aegis-server.service' "${ROOT}/packaging/systemd/aegis-origin-guard.service"
if grep -Fq 'network-online.target' "${ROOT}/packaging/systemd/aegis-origin-guard.service"; then
  echo "origin guard must not wait for network-online.target" >&2
  exit 1
fi

echo "PASS: source install is CWD-independent, noninteractive and uses service-writable state"
