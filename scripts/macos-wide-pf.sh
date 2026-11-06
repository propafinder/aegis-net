#!/usr/bin/env bash
set -euo pipefail

SELF_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UNAME_S="${AEGIS_MACOS_PF_HELPER_UNAME:-$(uname -s)}"
PFCTL_BIN="${AEGIS_MACOS_PF_HELPER_PFCTL_BIN:-pfctl}"
IFCONFIG_BIN="${AEGIS_MACOS_PF_HELPER_IFCONFIG_BIN:-ifconfig}"
ROUTE_BIN="${AEGIS_MACOS_PF_HELPER_ROUTE_BIN:-route}"
SUDO_BIN="${AEGIS_MACOS_PF_HELPER_SUDO_BIN:-sudo}"
STATE_BASE_DIR="${AEGIS_MACOS_PF_STATE_DIR:-}"
if [[ -z "${STATE_BASE_DIR}" ]]; then
  if [[ -z "${AEGIS_MACOS_PF_STATE_PATH:-}" && -z "${HOME:-}" ]]; then
    echo "AEGIS_MACOS_PF_STATE_PATH or HOME is required to resolve the default macOS PF state path" >&2
    exit 1
  fi
  STATE_BASE_DIR="${HOME}/Library/Application Support/.aegis/macos-pf"
fi
DEFAULT_STATE_BASENAME="$(
  cargo run -q --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure -- macos-pf-state-basename \
    --state-base-dir "${STATE_BASE_DIR}" \
    --home "${HOME:-}" \
    --user "${USER:-}"
)"
STATE_PATH="${AEGIS_MACOS_PF_STATE_PATH:-${STATE_BASE_DIR}/${DEFAULT_STATE_BASENAME}}"
STATE_DIR="$(dirname "${STATE_PATH}")"
ANCHOR_NAME="${AEGIS_MACOS_PF_ANCHOR_NAME:-com.apple/aegis_tcp_only}"
ANCHOR_FILE="${AEGIS_MACOS_PF_ANCHOR_FILE:-${STATE_PATH}.anchor.conf}"
APPLY_MODE="${AEGIS_MACOS_PF_HELPER_APPLY_MODE:-pfctl}"
LISTEN_ADDR="${AEGIS_MACOS_PF_LISTEN:-127.0.0.1:15080}"
REDIRECT_FROM_ADDR="${AEGIS_MACOS_PF_REDIRECT_FROM:-127.0.0.1:18080}"
TARGET_ADDR="${AEGIS_MACOS_PF_TARGET:-127.0.0.1:18081}"
DNS_PREVIEW_ENABLED="${AEGIS_MACOS_PF_DNS_PREVIEW_ENABLED:-0}"
DNS_REDIRECT_FROM_ADDR="${AEGIS_MACOS_PF_DNS_REDIRECT_FROM:-}"
DNS_TARGET_ADDR="${AEGIS_MACOS_PF_DNS_TARGET:-}"
SYSTEM_WIDE_ENABLED="${AEGIS_MACOS_PF_SYSTEM_WIDE_ENABLED:-0}"
PREPARED_BOUNDARY_ENABLED="${AEGIS_MACOS_PF_PREPARED_BOUNDARY_ENABLED:-0}"
# B2 (Track B macOS PF phase-4): bind-capable system-wide mode — PF rdr rules
# materialize on egress interface (not just lo0 or comment-only placeholder).
# Opt-in for production operators; phase-3 boundary remains the default.
# AEGIS_MACOS_PF_PHASE4_ENABLED=1 AND AEGIS_MACOS_PF_SYSTEM_WIDE_ENABLED=1 → phase-4.
# AEGIS_MACOS_PF_EGRESS_IF — the interface on which rdr rules install (default en0).
PHASE4_ENABLED="${AEGIS_MACOS_PF_PHASE4_ENABLED:-0}"
EGRESS_IF="${AEGIS_MACOS_PF_EGRESS_IF:-en0}"

# Audit H4: ANCHOR_NAME is interpolated into `pfctl -a "<name>"` and into the
# pf anchor rule text, and EGRESS_IF into `rdr pass on <if>` rules. Reject
# values outside a strict charset so a hostile env var cannot inject additional
# pf rules (via an embedded newline) or extra pfctl arguments.
if [[ ! "${ANCHOR_NAME}" =~ ^[A-Za-z0-9._/][A-Za-z0-9._/-]*$ ]]; then
  echo "FATAL: AEGIS_MACOS_PF_ANCHOR_NAME has an invalid character (got '${ANCHOR_NAME}')" >&2
  exit 2
fi
if [[ ! "${EGRESS_IF}" =~ ^[A-Za-z0-9]{1,15}$ ]]; then
  echo "FATAL: AEGIS_MACOS_PF_EGRESS_IF must be a valid interface name (got '${EGRESS_IF}')" >&2
  exit 2
fi

usage() {
  cat <<'EOF'
Usage:
  bash scripts/macos-wide-pf.sh contract [--json]
  bash scripts/macos-wide-pf.sh check [--json]
  bash scripts/macos-wide-pf.sh apply [--json]
  bash scripts/macos-wide-pf.sh setup [--json]
  bash scripts/macos-wide-pf.sh status [--json]
  bash scripts/macos-wide-pf.sh evidence [--json]
  bash scripts/macos-wide-pf.sh cleanup [--json]

Canonical phase-1 flow:
  check -> apply/setup -> status -> evidence -> cleanup

Environment overrides:
  AEGIS_MACOS_PF_STATE_PATH
  AEGIS_MACOS_PF_LISTEN
  AEGIS_MACOS_PF_REDIRECT_FROM
  AEGIS_MACOS_PF_TARGET
  AEGIS_MACOS_PF_DNS_PREVIEW_ENABLED=0|1
  AEGIS_MACOS_PF_DNS_REDIRECT_FROM=127.0.0.x:port
  AEGIS_MACOS_PF_DNS_TARGET=127.0.0.x:port
  AEGIS_MACOS_PF_SYSTEM_WIDE_ENABLED=0|1
  AEGIS_MACOS_PF_PREPARED_BOUNDARY_ENABLED=0|1
  AEGIS_MACOS_PF_PHASE4_ENABLED=0|1   # B2 bind-capable phase-4 (requires SYSTEM_WIDE_ENABLED=1)
  AEGIS_MACOS_PF_EGRESS_IF=en0        # egress interface for phase-4 rdr rules (default en0)
  AEGIS_MACOS_PF_HELPER_APPLY_MODE=pfctl|simulate
EOF
}

ensure_private_state_dir() {
  mkdir -p "${STATE_DIR}"
  chmod 700 "${STATE_DIR}"
}

write_private_text_file() {
  local path="$1"
  local contents="$2"
  ensure_private_state_dir
  umask 077
  printf '%s' "${contents}" >"${path}"
  chmod 600 "${path}"
}

json_bool() {
  if [[ "$1" == "true" ]]; then
    printf 'true'
  else
    printf 'false'
  fi
}

command_present() {
  command -v "$1" >/dev/null 2>&1
}

supports_live_pf() {
  [[ "$UNAME_S" == "Darwin" ]] || return 1
  command_present "$PFCTL_BIN" || return 1
  command_present "$IFCONFIG_BIN" || return 1
  command_present "$ROUTE_BIN" || return 1
}

has_sudo_or_root() {
  if [[ "${EUID}" -eq 0 ]]; then
    return 0
  fi
  if command_present "$SUDO_BIN" && "$SUDO_BIN" -n true >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

run_privileged() {
  if [[ "${EUID}" -eq 0 ]]; then
    "$@"
  else
    "$SUDO_BIN" "$@"
  fi
}

require_ipv4_socket_addr() {
  local value="$1"
  local name="$2"
  if [[ ! "$value" =~ ^127\.0\.0\.[0-9]+:[0-9]+$ ]]; then
    echo "invalid ${name}: expected local 127.0.0.x:port shape, got ${value}" >&2
    exit 1
  fi
}

require_ipv4_any_socket_addr() {
  local value="$1"
  local name="$2"
  if [[ ! "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]+$ ]]; then
    echo "invalid ${name}: expected ipv4 host:port shape, got ${value}" >&2
    exit 1
  fi
}

socket_host() {
  printf '%s' "${1%:*}"
}

socket_port() {
  printf '%s' "${1##*:}"
}

json_string_or_null() {
  if [[ -z "$1" ]]; then
    printf 'null'
  else
    printf '"%s"' "$1"
  fi
}

dns_preview_enabled() {
  if [[ "$DNS_PREVIEW_ENABLED" == "1" || "$DNS_PREVIEW_ENABLED" == "true" ]]; then
    return 0
  fi
  return 1
}

system_wide_enabled() {
  if [[ "$SYSTEM_WIDE_ENABLED" == "1" || "$SYSTEM_WIDE_ENABLED" == "true" ]]; then
    return 0
  fi
  return 1
}

prepared_boundary_enabled() {
  if [[ "$PREPARED_BOUNDARY_ENABLED" == "1" || "$PREPARED_BOUNDARY_ENABLED" == "true" ]]; then
    return 0
  fi
  return 1
}

# B2: phase-4 bind-capable flag. Gated behind both the env var AND the
# system_wide_enabled gate — phase-4 only makes sense within the system-wide
# scope family. A phase-4 activation REPLACES prepared-boundary-only
# semantics with real PF rdr rules on the egress interface.
phase4_enabled() {
  if ! system_wide_enabled; then
    return 1
  fi
  if [[ "$PHASE4_ENABLED" == "1" || "$PHASE4_ENABLED" == "true" ]]; then
    return 0
  fi
  return 1
}

current_stage_name() {
  if phase4_enabled; then
    printf 'system_wide_phase4_live'
  elif system_wide_enabled; then
    if prepared_boundary_enabled; then
      printf 'system_wide_phase3_prepared_boundary'
    else
      printf 'system_wide_phase3_boundary'
    fi
  elif dns_preview_enabled; then
    printf 'dns_preview_phase2_live'
  else
    printf 'tcp_only_phase1_live'
  fi
}

scope_target_name() {
  if phase4_enabled; then
    printf 'system_wide_phase4'
  elif system_wide_enabled; then
    printf 'system_wide_phase3'
  elif dns_preview_enabled; then
    printf 'dns_preview_phase2'
  else
    printf 'tcp_only_phase1'
  fi
}

runtime_active_value() {
  # Phase-4: materialized, so runtime_active=true.
  # Phase-3 (boundary/prepared-boundary): NOT materialized, runtime_active=false.
  # tcp_only/dns_preview: runtime_active=true.
  if phase4_enabled; then
    printf 'true'
  elif system_wide_enabled; then
    printf 'false'
  else
    printf 'true'
  fi
}

write_anchor_file() {
  ensure_private_state_dir
  # B2: phase-4 materializes real PF rdr rules on the egress interface.
  # Unlike phase-3 boundary (comment-only placeholder), phase-4 publishes
  # an rdr rule that actually redirects outbound TCP on `${EGRESS_IF}` to
  # aegis-client's loopback listener. This is the bind-capable surface.
  if phase4_enabled; then
    local redirect_host redirect_port listen_host listen_port
    redirect_host="$(socket_host "$REDIRECT_FROM_ADDR")"
    redirect_port="$(socket_port "$REDIRECT_FROM_ADDR")"
    listen_host="$(socket_host "$LISTEN_ADDR")"
    listen_port="$(socket_port "$LISTEN_ADDR")"
    umask 077
    cat >"${ANCHOR_FILE}" <<EOF
# system_wide_phase4 bind-capable: rdr rules on ${EGRESS_IF} actively redirect
# outbound TCP targeting ${redirect_host}:${redirect_port} to ${listen_host}:${listen_port}
rdr pass on ${EGRESS_IF} inet proto tcp from any to ${redirect_host} port ${redirect_port} -> ${listen_host} port ${listen_port}
rdr pass on lo0 inet proto tcp from any to ${redirect_host} port ${redirect_port} -> ${listen_host} port ${listen_port}
EOF
    if dns_preview_enabled; then
      local dns_redirect_host dns_redirect_port
      dns_redirect_host="$(socket_host "$DNS_REDIRECT_FROM_ADDR")"
      dns_redirect_port="$(socket_port "$DNS_REDIRECT_FROM_ADDR")"
      cat >>"${ANCHOR_FILE}" <<EOF
rdr pass on ${EGRESS_IF} inet proto udp from any to ${dns_redirect_host} port ${dns_redirect_port} -> ${listen_host} port ${listen_port}
rdr pass on lo0 inet proto udp from any to ${dns_redirect_host} port ${dns_redirect_port} -> ${listen_host} port ${listen_port}
EOF
    fi
    chmod 600 "${ANCHOR_FILE}"
    return 0
  fi
  if system_wide_enabled; then
    local boundary_comment="system_wide_phase3 boundary only"
    if prepared_boundary_enabled; then
      boundary_comment="system_wide_phase3 prepared boundary only"
    fi
    umask 077
    cat >"${ANCHOR_FILE}" <<EOF
# ${boundary_comment}
# broader PF rules are intentionally not materialized yet
EOF
    chmod 600 "${ANCHOR_FILE}"
    return 0
  fi
  local redirect_host redirect_port listen_host listen_port
  redirect_host="$(socket_host "$REDIRECT_FROM_ADDR")"
  redirect_port="$(socket_port "$REDIRECT_FROM_ADDR")"
  listen_host="$(socket_host "$LISTEN_ADDR")"
  listen_port="$(socket_port "$LISTEN_ADDR")"
  umask 077
  cat >"${ANCHOR_FILE}" <<EOF
rdr pass on lo0 inet proto tcp from any to ${redirect_host} port ${redirect_port} -> ${listen_host} port ${listen_port}
EOF
  if dns_preview_enabled; then
    local dns_redirect_host dns_redirect_port
    dns_redirect_host="$(socket_host "$DNS_REDIRECT_FROM_ADDR")"
    dns_redirect_port="$(socket_port "$DNS_REDIRECT_FROM_ADDR")"
    cat >>"${ANCHOR_FILE}" <<EOF
rdr pass on lo0 inet proto udp from any to ${dns_redirect_host} port ${dns_redirect_port} -> ${listen_host} port ${listen_port}
EOF
  fi
  chmod 600 "${ANCHOR_FILE}"
}

write_state_file() {
  local pf_rule_active="$1"
  ensure_private_state_dir
  umask 077
  cat >"${STATE_PATH}" <<EOF
{
  "track": "macos_pf_wide_epic",
  "backend": "macos_pf",
  "runtime_active": $(runtime_active_value),
  "current_stage": "$(current_stage_name)",
  "scope_target": "$(scope_target_name)",
  "apply_mode": "${APPLY_MODE}",
  "listen": "${LISTEN_ADDR}",
  "redirect_from": "${REDIRECT_FROM_ADDR}",
  "target": "${TARGET_ADDR}",
  "dns_preview_enabled": $(json_bool "$( dns_preview_enabled && printf 'true' || printf 'false' )"),
  "dns_redirect_from": $(json_string_or_null "${DNS_REDIRECT_FROM_ADDR}"),
  "dns_target": $(json_string_or_null "${DNS_TARGET_ADDR}"),
  "system_wide_enabled": $(json_bool "$( system_wide_enabled && printf 'true' || printf 'false' )"),
  "prepared_boundary_enabled": $(json_bool "$( prepared_boundary_enabled && printf 'true' || printf 'false' )"),
  "phase4_enabled": $(json_bool "$( phase4_enabled && printf 'true' || printf 'false' )"),
  "egress_if": $(json_string_or_null "$( phase4_enabled && printf '%s' "${EGRESS_IF}" || printf '' )"),
  "anchor_name": "${ANCHOR_NAME}",
  "anchor_file": "${ANCHOR_FILE}",
  "pf_rule_active": $(json_bool "$pf_rule_active")
}
EOF
  chmod 600 "${STATE_PATH}"
}

state_exists() {
  [[ -f "${STATE_PATH}" ]]
}

read_state_json() {
  cargo run -q --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure -- macos-pf-read-state-json --state-path "${STATE_PATH}"
}

read_state_field() {
  cargo run -q --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure -- macos-pf-read-state-field --state-path "${STATE_PATH}" --field "$1"
}

check_prerequisites() {
  [[ "$UNAME_S" == "Darwin" ]] || return 1
  command_present "$PFCTL_BIN" || return 1
  command_present "$IFCONFIG_BIN" || return 1
  command_present "$ROUTE_BIN" || return 1
  if system_wide_enabled; then
    require_ipv4_any_socket_addr "$LISTEN_ADDR" "AEGIS_MACOS_PF_LISTEN"
    require_ipv4_any_socket_addr "$REDIRECT_FROM_ADDR" "AEGIS_MACOS_PF_REDIRECT_FROM"
    require_ipv4_any_socket_addr "$TARGET_ADDR" "AEGIS_MACOS_PF_TARGET"
  else
    require_ipv4_socket_addr "$LISTEN_ADDR" "AEGIS_MACOS_PF_LISTEN"
    require_ipv4_socket_addr "$REDIRECT_FROM_ADDR" "AEGIS_MACOS_PF_REDIRECT_FROM"
    require_ipv4_socket_addr "$TARGET_ADDR" "AEGIS_MACOS_PF_TARGET"
  fi
  if dns_preview_enabled; then
    if system_wide_enabled; then
      require_ipv4_any_socket_addr "$DNS_REDIRECT_FROM_ADDR" "AEGIS_MACOS_PF_DNS_REDIRECT_FROM"
      require_ipv4_any_socket_addr "$DNS_TARGET_ADDR" "AEGIS_MACOS_PF_DNS_TARGET"
    else
      require_ipv4_socket_addr "$DNS_REDIRECT_FROM_ADDR" "AEGIS_MACOS_PF_DNS_REDIRECT_FROM"
      require_ipv4_socket_addr "$DNS_TARGET_ADDR" "AEGIS_MACOS_PF_DNS_TARGET"
    fi
  fi
  return 0
}

apply_pf_rules() {
  # Tier 2.2: phase-4 (bind-capable system_wide) MUST invoke pfctl to
  # publish real rdr rules. Previous logic short-circuited the system_wide
  # branch (boundary-only phase-3) before any pfctl call, leaving phase-4
  # paper-only. Now we route phase-4 through the live-pfctl path while
  # phase-3 (boundary placeholder) still skips pfctl as designed.
  if phase4_enabled && system_wide_enabled; then
    if [[ "$APPLY_MODE" == "simulate" ]]; then
      write_anchor_file
      write_state_file "false"
      return 0
    fi
    if ! supports_live_pf; then
      echo "phase-4 live PF apply requires Darwin host tools" >&2
      exit 1
    fi
    write_anchor_file
    run_privileged "$PFCTL_BIN" -E >/dev/null
    run_privileged "$PFCTL_BIN" -a "$ANCHOR_NAME" -f "$ANCHOR_FILE" >/dev/null
    write_state_file "true"
    return 0
  fi
  if system_wide_enabled; then
    # phase-3 boundary-only: no live rules, marker file only.
    write_anchor_file
    write_state_file "false"
    return 0
  fi
  if [[ "$APPLY_MODE" == "simulate" ]]; then
    write_state_file "false"
    return 0
  fi
  if ! supports_live_pf; then
    echo "live PF apply requires Darwin host tools" >&2
    exit 1
  fi
  write_anchor_file
  run_privileged "$PFCTL_BIN" -E >/dev/null
  run_privileged "$PFCTL_BIN" -a "$ANCHOR_NAME" -f "$ANCHOR_FILE" >/dev/null
  write_state_file "true"
}

cleanup_pf_rules() {
  local pf_rule_active="false"
  if state_exists; then
    pf_rule_active="$(read_state_field "pf_rule_active")"
  fi
  if [[ "$pf_rule_active" == "true" && "$APPLY_MODE" != "simulate" && "$UNAME_S" == "Darwin" ]]; then
    run_privileged "$PFCTL_BIN" -a "$ANCHOR_NAME" -F rules >/dev/null || true
  fi
  rm -f "${STATE_PATH}" "${ANCHOR_FILE}"
}

emit_contract_json() {
  cat <<EOF
{
  "track": "macos_pf_wide_epic",
  "backend": "macos_pf",
  "current_stage": "system_wide_phase3_boundary_capable",
  "scope_target": "system_wide_phase3",
  "future_phases": ["system_wide_phase3_prepared_boundary"],
  "requires_privileged_local_acceptance": true,
  "state_path_default": "${STATE_PATH}",
  "canonical_commands": {
    "contract": "bash scripts/macos-wide-pf.sh contract --json",
    "check": "bash scripts/macos-wide-pf.sh check --json",
    "apply": "bash scripts/macos-wide-pf.sh apply --json",
    "status": "bash scripts/macos-wide-pf.sh status --json",
    "evidence": "bash scripts/macos-wide-pf.sh evidence --json",
    "cleanup": "bash scripts/macos-wide-pf.sh cleanup --json"
  }
}
EOF
}

emit_check_json() {
  local is_darwin="$1"
  local pfctl_present="$2"
  local ifconfig_present="$3"
  local route_present="$4"
  local has_sudo="$5"
  local state_present="$6"
  local status reason_code
  if [[ "$is_darwin" != "true" ]]; then
    status="error"
    reason_code="unsupported_host_platform"
  elif [[ "$pfctl_present" != "true" || "$ifconfig_present" != "true" || "$route_present" != "true" ]]; then
    status="error"
    reason_code="missing_host_tools"
  elif [[ "$state_present" == "true" ]]; then
    status="ok"
    reason_code="helper_state_present"
  elif [[ "$APPLY_MODE" != "simulate" && "$has_sudo" != "true" ]]; then
    status="degraded"
    reason_code="privilege_escalation_required_for_live_apply"
  else
    status="ok"
    reason_code="ready_for_apply"
  fi
  cat <<EOF
{
  "track": "macos_pf_wide_epic",
  "backend": "macos_pf",
  "platform": "$(printf '%s' "$UNAME_S" | tr '[:upper:]' '[:lower:]')",
  "supported_host": $(json_bool "$is_darwin"),
  "status": "$status",
  "reason_code": "$reason_code",
  "current_stage": "$(current_stage_name)",
  "scope_target": "$(scope_target_name)",
  "state_path": "${STATE_PATH}",
  "apply_mode": "${APPLY_MODE}",
  "state_present": $(json_bool "$state_present"),
  "dns_preview_enabled": $(json_bool "$( dns_preview_enabled && printf 'true' || printf 'false' )"),
  "system_wide_enabled": $(json_bool "$( system_wide_enabled && printf 'true' || printf 'false' )"),
  "prepared_boundary_enabled": $(json_bool "$( prepared_boundary_enabled && printf 'true' || printf 'false' )"),
  "tools": {
    "pfctl": $(json_bool "$pfctl_present"),
    "ifconfig": $(json_bool "$ifconfig_present"),
    "route": $(json_bool "$route_present"),
    "sudo_or_root": $(json_bool "$has_sudo")
  }
}
EOF
}

emit_status_json() {
  local is_darwin="$1"
  local state_present="$2"
  local runtime_active="false"
  local runtime_claim="degraded_fallback_only"
  local listen="null"
  local redirect_from="null"
  local target="null"
  local current_stage="tcp_only_phase1"
  local scope_target="tcp_only_phase1"
  local dns_preview_state="false"
  local system_wide_state="false"
  local prepared_boundary_state="false"
  local dns_redirect_from="null"
  local dns_target="null"
  if [[ "$state_present" == "true" ]]; then
    runtime_active="$(read_state_field "runtime_active")"
    listen="\"$(read_state_field "listen")\""
    redirect_from="\"$(read_state_field "redirect_from")\""
    target="\"$(read_state_field "target")\""
    current_stage="$(read_state_field "current_stage")"
    scope_target="$(read_state_field "scope_target")"
    dns_preview_state="$(read_state_field "dns_preview_enabled")"
    system_wide_state="$(read_state_field "system_wide_enabled")"
    prepared_boundary_state="$(read_state_field "prepared_boundary_enabled")"
    local dns_redirect_from_value dns_target_value
    dns_redirect_from_value="$(read_state_field "dns_redirect_from")"
    dns_target_value="$(read_state_field "dns_target")"
    if [[ -n "$dns_redirect_from_value" && "$dns_redirect_from_value" != "None" ]]; then
      dns_redirect_from="\"${dns_redirect_from_value}\""
    fi
    if [[ -n "$dns_target_value" && "$dns_target_value" != "None" ]]; then
      dns_target="\"${dns_target_value}\""
    fi
    local phase4_state
    phase4_state="$(read_state_field "phase4_enabled")"
    if [[ "$phase4_state" == "true" && "$runtime_active" == "true" ]]; then
      # B2: phase-4 bind-capable runtime claim
      runtime_claim="system_wide_phase4_active"
    elif [[ "$runtime_active" == "true" ]]; then
      if [[ "$dns_preview_state" == "true" ]]; then
        runtime_claim="dns_preview_phase2_active"
      else
        runtime_claim="tcp_only_phase1_active"
      fi
    elif [[ "$system_wide_state" == "true" ]]; then
      if [[ "$prepared_boundary_state" == "true" ]]; then
        runtime_claim="system_wide_phase3_prepared_boundary_only"
      else
        runtime_claim="system_wide_phase3_boundary_only"
      fi
    fi
  fi
  cat <<EOF
{
  "track": "macos_pf_wide_epic",
  "backend": "macos_pf",
  "platform": "$(printf '%s' "$UNAME_S" | tr '[:upper:]' '[:lower:]')",
  "supported_host": $(json_bool "$is_darwin"),
  "current_stage": "${current_stage}",
  "scope_target": "${scope_target}",
  "runtime_active": $(json_bool "$runtime_active"),
  "runtime_claim": "${runtime_claim}",
  "state_present": $(json_bool "$state_present"),
  "dns_preview_enabled": $(json_bool "${dns_preview_state}"),
  "system_wide_enabled": $(json_bool "${system_wide_state}"),
  "prepared_boundary_enabled": $(json_bool "${prepared_boundary_state}"),
  "phase4_enabled": $(json_bool "$( [[ "$state_present" == "true" ]] && read_state_field "phase4_enabled" || printf 'false' )"),
  "listen": ${listen},
  "redirect_from": ${redirect_from},
  "target": ${target},
  "dns_redirect_from": ${dns_redirect_from},
  "dns_target": ${dns_target}
}
EOF
}

emit_evidence_json() {
  local is_darwin="$1"
  local state_present="$2"
  local verdict="degraded_until_helper_state_exists"
  local state_json="{}"
  local green_gate_label="tcp_only_happy_path_evidence"
  if [[ "$state_present" == "true" ]]; then
    if [[ "$(read_state_field "phase4_enabled")" == "true" ]]; then
      # B2: phase-4 bind-capable materialized verdict
      verdict="system_wide_phase4_helper_materialized"
      green_gate_label="system_wide_phase4_bind_capable_contract"
    elif [[ "$(read_state_field "system_wide_enabled")" == "true" ]]; then
      if [[ "$(read_state_field "prepared_boundary_enabled")" == "true" ]]; then
        verdict="system_wide_phase3_prepared_boundary_materialized"
        green_gate_label="system_wide_phase3_prepared_boundary_contract"
      else
        verdict="system_wide_phase3_boundary_materialized"
        green_gate_label="system_wide_phase3_boundary_contract"
      fi
    elif [[ "$(read_state_field "dns_preview_enabled")" == "true" ]]; then
      verdict="dns_preview_phase2_helper_materialized"
      green_gate_label="dns_preview_happy_path_evidence"
    else
      verdict="tcp_only_phase1_helper_materialized"
    fi
    state_json="$(read_state_json)"
  fi
  cat <<EOF
{
  "track": "macos_pf_wide_epic",
  "backend": "macos_pf",
  "supported_host": $(json_bool "$is_darwin"),
  "current_stage": "$(current_stage_name)",
  "scope_target": "$(scope_target_name)",
  "green_gate": [
    "darwin_fallback_contract_green",
    "local_pf_helper_materialized",
    "${green_gate_label}"
  ],
  "current_verdict": "${verdict}",
  "state_present": $(json_bool "$state_present"),
  "helper_state": ${state_json}
}
EOF
}

emit_cleanup_json() {
  cat <<EOF
{
  "track": "macos_pf_wide_epic",
  "backend": "macos_pf",
  "status": "ok",
  "action": "cleanup_applied",
  "reason_code": "helper_state_removed"
}
EOF
}

main() {
  local subcommand="${1:-}"
  local json_mode="${2:-}"
  if [[ -z "$subcommand" ]]; then
    usage
    exit 1
  fi

  local is_darwin="false"
  local pfctl_present="false"
  local ifconfig_present="false"
  local route_present="false"
  local has_sudo="false"
  local state_present="false"

  [[ "$UNAME_S" == "Darwin" ]] && is_darwin="true"
  command_present "$PFCTL_BIN" && pfctl_present="true"
  command_present "$IFCONFIG_BIN" && ifconfig_present="true"
  command_present "$ROUTE_BIN" && route_present="true"
  has_sudo_or_root && has_sudo="true"
  state_exists && state_present="true"

  case "$subcommand" in
    contract)
      if [[ "$json_mode" == "--json" ]]; then
        emit_contract_json
      else
        echo "backend=macos_pf"
        echo "current_stage=system_wide_phase3_boundary_capable"
        echo "scope_target=system_wide_phase3"
        echo "future_phases=system_wide_phase3_prepared_boundary"
        echo "canonical_helper=${SELF_PATH}"
      fi
      ;;
    check)
      if [[ "$json_mode" == "--json" ]]; then
        emit_check_json "$is_darwin" "$pfctl_present" "$ifconfig_present" "$route_present" "$has_sudo" "$state_present"
      else
        echo "platform=${UNAME_S}"
        echo "supported_host=${is_darwin}"
        echo "pfctl=${pfctl_present}"
        echo "ifconfig=${ifconfig_present}"
        echo "route=${route_present}"
        echo "sudo_or_root=${has_sudo}"
        echo "apply_mode=${APPLY_MODE}"
        echo "state_present=${state_present}"
      fi
      ;;
    apply|setup)
      if prepared_boundary_enabled && ! system_wide_enabled; then
        echo "prepared boundary requires AEGIS_MACOS_PF_SYSTEM_WIDE_ENABLED=1" >&2
        exit 1
      fi
      # B2: phase-4 requires system_wide (it's a specialization of phase-3)
      if [[ "$PHASE4_ENABLED" == "1" || "$PHASE4_ENABLED" == "true" ]] && ! system_wide_enabled; then
        echo "phase-4 requires AEGIS_MACOS_PF_SYSTEM_WIDE_ENABLED=1" >&2
        exit 1
      fi
      check_prerequisites
      apply_pf_rules
      if [[ "$json_mode" == "--json" ]]; then
        emit_status_json "$is_darwin" "true"
      else
        echo "applied=true"
        echo "runtime_active=$(read_state_field "runtime_active")"
        echo "current_stage=$(read_state_field "current_stage")"
        echo "scope_target=$(read_state_field "scope_target")"
        echo "listen=${LISTEN_ADDR}"
        echo "redirect_from=${REDIRECT_FROM_ADDR}"
        echo "target=${TARGET_ADDR}"
      fi
      ;;
    status)
      if [[ "$json_mode" == "--json" ]]; then
        emit_status_json "$is_darwin" "$state_present"
      else
        echo "runtime_active=$( [[ "$state_present" == "true" ]] && read_state_field "runtime_active" || printf 'false' )"
        echo "state_present=${state_present}"
      fi
      ;;
    evidence)
      if [[ "$json_mode" == "--json" ]]; then
        emit_evidence_json "$is_darwin" "$state_present"
      else
        if [[ "$state_present" == "true" ]]; then
          if [[ "$(read_state_field "phase4_enabled")" == "true" ]]; then
            echo "current_verdict=system_wide_phase4_helper_materialized"
          elif [[ "$(read_state_field "system_wide_enabled")" == "true" ]]; then
            if [[ "$(read_state_field "prepared_boundary_enabled")" == "true" ]]; then
              echo "current_verdict=system_wide_phase3_prepared_boundary_materialized"
            else
              echo "current_verdict=system_wide_phase3_boundary_materialized"
            fi
          elif [[ "$(read_state_field "dns_preview_enabled")" == "true" ]]; then
            echo "current_verdict=dns_preview_phase2_helper_materialized"
          else
            echo "current_verdict=tcp_only_phase1_helper_materialized"
          fi
        else
          echo "current_verdict=degraded_until_helper_state_exists"
        fi
        echo "state_path=${STATE_PATH}"
      fi
      ;;
    cleanup)
      cleanup_pf_rules
      if [[ "$json_mode" == "--json" ]]; then
        emit_cleanup_json
      else
        echo "cleanup_applied=true"
        echo "state_path=${STATE_PATH}"
      fi
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
