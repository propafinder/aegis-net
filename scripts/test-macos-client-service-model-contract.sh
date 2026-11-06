#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/build-macos-client-tarball.sh"
INSTALL_SH="${ROOT}/install.sh"
AGENT_TEMPLATE="${ROOT}/packaging/launchd/dev.aegis.client.plist"
DAEMON_TEMPLATE="${ROOT}/packaging/launchd/dev.aegis.client.daemon.plist"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-macos-service-model.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

render_template() {
  local template="$1"
  local output="$2"
  sed \
    -e "s|__AEGIS_CLIENT_BIN__|/Users/aegis/.local/bin/aegis-client|g" \
    -e "s|__AEGIS_CLIENT_CONFIG__|/Users/aegis/.config/aegis/aegis.toml|g" \
    -e "s|__AEGIS_CLIENT_STATE_DIR__|/Users/aegis/.local/state/aegis|g" \
    -e "s|__AEGIS_CLIENT_RUNTIME_EVENTS_JSONL__|/Users/aegis/.local/state/aegis/runtime-events.jsonl|g" \
    -e "s|__AEGIS_CLIENT_LOG_DIR__|/Users/aegis/.local/state/aegis/log|g" \
    -e "s|__AEGIS_CLIENT_USER__|aegis|g" \
    -e "s|__AEGIS_CLIENT_GROUP__|staff|g" \
    "${template}" > "${output}"
}

render_template "${AGENT_TEMPLATE}" "${TMP_DIR}/agent.plist"
render_template "${DAEMON_TEMPLATE}" "${TMP_DIR}/daemon.plist"

plist_value() {
  local plist="$1"
  local key="$2"
  plutil -extract "${key}" raw -o - "${plist}"
}

require_plist_value() {
  local plist="$1"
  local key="$2"
  local expected="$3"
  local actual
  actual="$(plist_value "${plist}" "${key}")"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "unexpected plist value ${key}: ${actual}" >&2
    exit 1
  fi
}

reject_plist_key() {
  local plist="$1"
  local key="$2"
  if plutil -extract "${key}" raw -o - "${plist}" >/dev/null 2>&1; then
    echo "unexpected plist key exists: ${key}" >&2
    exit 1
  fi
}

require_fragment() {
  local file="$1"
  local fragment="$2"
  if ! grep -Fq -- "${fragment}" "${file}"; then
    echo "missing expected fragment: ${fragment}" >&2
    exit 1
  fi
}

require_plist_value "${TMP_DIR}/agent.plist" "Label" "dev.aegis.client"
reject_plist_key "${TMP_DIR}/agent.plist" "UserName"
require_plist_value "${TMP_DIR}/agent.plist" "ProgramArguments.0" "/Users/aegis/.local/bin/aegis-client"
require_plist_value "${TMP_DIR}/agent.plist" "StandardOutPath" "/Users/aegis/.local/state/aegis/log/aegis-client.out.log"

require_plist_value "${TMP_DIR}/daemon.plist" "Label" "dev.aegis.client"
require_plist_value "${TMP_DIR}/daemon.plist" "UserName" "aegis"
require_plist_value "${TMP_DIR}/daemon.plist" "GroupName" "staff"
require_plist_value "${TMP_DIR}/daemon.plist" "WorkingDirectory" "/Users/aegis/.local/state/aegis"
require_plist_value "${TMP_DIR}/daemon.plist" "ProgramArguments.2" "/Users/aegis/.config/aegis/aegis.toml"

for fragment in \
  "--service-mode <mode>" \
  "auto|launchagent|launchdaemon|foreground" \
  "detect_gui_launchd_domain" \
  "LaunchAgent was not loaded" \
  "SERVICE_STATUS=\"PARTIAL\"" \
  "SERVICE_STATUS=\"BLOCKED\"" \
  'launchctl bootstrap "gui/$(target_uid)"' \
  "launchctl bootstrap system" \
  "launchctl print system/dev.aegis.client" \
  "launchctl bootout system" \
  "Foreground/operator mode selected" \
  "dev.aegis.client.daemon.plist" \
  "LaunchAgent loaded" \
  "LaunchAgent bootstrap returned but launchctl print did not find"; do
  require_fragment "${SCRIPT}" "${fragment}"
done

for fragment in \
  "launchd_gui_domain_exists" \
  "LaunchAgent asset installed" \
  "LaunchAgent status: \${launchagent_status}" \
  "No gui/\${uid} launchd domain is visible" \
  "launchctl bootstrap \"gui/\${uid}\"" \
  "launchctl print \"gui/\${uid}/dev.aegis.client\"" \
  "--service-mode launchdaemon --service-user <user>" \
  "foreground/operator mode"; do
  require_fragment "${INSTALL_SH}" "${fragment}"
done

echo "PASS: macOS client service model contract"
