#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HELPER="${ROOT}/scripts/macos-wide-pf.sh"

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

require_file_contains() {
  local file="$1"
  local expected="$2"
  if ! grep -Fq -- "${expected}" "${file}"; then
    local compact_file=""
    local compact_expected=""
    compact_file="$(tr -d '[:space:]' < "${file}")"
    compact_expected="$(printf '%s' "${expected}" | tr -d '[:space:]')"
    if [[ "${compact_file}" != *"${compact_expected}"* ]]; then
      echo "expected ${file} to contain: ${expected}" >&2
      echo "--- ${file} ---" >&2
      cat "${file}" >&2
      exit 1
    fi
  fi
}

reject_path_exists() {
  local path="$1"
  if [[ -e "${path}" ]]; then
    echo "expected path to be removed: ${path}" >&2
    exit 1
  fi
}

make_stub() {
  local path="$1"
  cat >"${path}" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${path}"
}

make_stub "${tmpdir}/pfctl"
make_stub "${tmpdir}/ifconfig"
make_stub "${tmpdir}/route"

# Recording pfctl stub for phase-4 live-apply coverage. Writes one
# arg-list line per invocation so test can assert pfctl was called
# with -E followed by -a anchor -f anchor_file (Tier 2.2 phase-4
# bind-capable contract).
recording_pfctl="${tmpdir}/recording-pfctl"
recording_log="${tmpdir}/pfctl-invocations.log"
cat >"${recording_pfctl}" <<EOF
#!/usr/bin/env bash
printf '%s\\n' "\$*" >>"${recording_log}"
exit 0
EOF
chmod +x "${recording_pfctl}"

# Recording sudo: just exec the next arg list so privileged calls are
# observable in the same log.
recording_sudo="${tmpdir}/recording-sudo"
cat >"${recording_sudo}" <<'EOF'
#!/usr/bin/env bash
"$@"
EOF
chmod +x "${recording_sudo}"

state_path="${tmpdir}/macos-pf-state.json"

contract_json="$(
  AEGIS_MACOS_PF_HELPER_UNAME=Darwin \
  AEGIS_MACOS_PF_HELPER_PFCTL_BIN="${tmpdir}/pfctl" \
  AEGIS_MACOS_PF_HELPER_IFCONFIG_BIN="${tmpdir}/ifconfig" \
  AEGIS_MACOS_PF_HELPER_ROUTE_BIN="${tmpdir}/route" \
  AEGIS_MACOS_PF_HELPER_APPLY_MODE=simulate \
  AEGIS_MACOS_PF_STATE_PATH="${state_path}" \
  bash "${HELPER}" contract --json
)"

check_json="$(
  AEGIS_MACOS_PF_HELPER_UNAME=Darwin \
  AEGIS_MACOS_PF_HELPER_PFCTL_BIN="${tmpdir}/pfctl" \
  AEGIS_MACOS_PF_HELPER_IFCONFIG_BIN="${tmpdir}/ifconfig" \
  AEGIS_MACOS_PF_HELPER_ROUTE_BIN="${tmpdir}/route" \
  AEGIS_MACOS_PF_HELPER_APPLY_MODE=simulate \
  AEGIS_MACOS_PF_STATE_PATH="${state_path}" \
  bash "${HELPER}" check --json
)"

check_live_without_privilege_json="$(
  AEGIS_MACOS_PF_HELPER_UNAME=Darwin \
  AEGIS_MACOS_PF_HELPER_PFCTL_BIN="${tmpdir}/pfctl" \
  AEGIS_MACOS_PF_HELPER_IFCONFIG_BIN="${tmpdir}/ifconfig" \
  AEGIS_MACOS_PF_HELPER_ROUTE_BIN="${tmpdir}/route" \
  AEGIS_MACOS_PF_HELPER_SUDO_BIN="${tmpdir}/sudo-missing" \
  AEGIS_MACOS_PF_STATE_PATH="${tmpdir}/macos-pf-live-check-state.json" \
  bash "${HELPER}" check --json
)"

apply_json="$(
  AEGIS_MACOS_PF_HELPER_UNAME=Darwin \
  AEGIS_MACOS_PF_HELPER_PFCTL_BIN="${tmpdir}/pfctl" \
  AEGIS_MACOS_PF_HELPER_IFCONFIG_BIN="${tmpdir}/ifconfig" \
  AEGIS_MACOS_PF_HELPER_ROUTE_BIN="${tmpdir}/route" \
  AEGIS_MACOS_PF_HELPER_APPLY_MODE=simulate \
  AEGIS_MACOS_PF_STATE_PATH="${state_path}" \
  AEGIS_MACOS_PF_LISTEN="127.0.0.1:25080" \
  AEGIS_MACOS_PF_REDIRECT_FROM="127.0.0.1:28080" \
  AEGIS_MACOS_PF_TARGET="127.0.0.1:28081" \
  bash "${HELPER}" apply --json
)"

status_json="$(
  AEGIS_MACOS_PF_HELPER_UNAME=Darwin \
  AEGIS_MACOS_PF_HELPER_PFCTL_BIN="${tmpdir}/pfctl" \
  AEGIS_MACOS_PF_HELPER_IFCONFIG_BIN="${tmpdir}/ifconfig" \
  AEGIS_MACOS_PF_HELPER_ROUTE_BIN="${tmpdir}/route" \
  AEGIS_MACOS_PF_HELPER_APPLY_MODE=simulate \
  AEGIS_MACOS_PF_STATE_PATH="${state_path}" \
  bash "${HELPER}" status --json
)"

dns_state_path="${tmpdir}/macos-pf-dns-state.json"
system_wide_state_path="${tmpdir}/macos-pf-system-wide-state.json"
prepared_state_path="${tmpdir}/macos-pf-system-wide-prepared-state.json"

dns_apply_json="$(
  AEGIS_MACOS_PF_HELPER_UNAME=Darwin \
  AEGIS_MACOS_PF_HELPER_PFCTL_BIN="${tmpdir}/pfctl" \
  AEGIS_MACOS_PF_HELPER_IFCONFIG_BIN="${tmpdir}/ifconfig" \
  AEGIS_MACOS_PF_HELPER_ROUTE_BIN="${tmpdir}/route" \
  AEGIS_MACOS_PF_HELPER_APPLY_MODE=simulate \
  AEGIS_MACOS_PF_STATE_PATH="${dns_state_path}" \
  AEGIS_MACOS_PF_LISTEN="127.0.0.1:25081" \
  AEGIS_MACOS_PF_REDIRECT_FROM="127.0.0.1:28082" \
  AEGIS_MACOS_PF_TARGET="127.0.0.1:28083" \
  AEGIS_MACOS_PF_DNS_PREVIEW_ENABLED=1 \
  AEGIS_MACOS_PF_DNS_REDIRECT_FROM="127.0.0.1:25353" \
  AEGIS_MACOS_PF_DNS_TARGET="127.0.0.1:25354" \
  bash "${HELPER}" apply --json
)"

dns_evidence_json="$(
  AEGIS_MACOS_PF_HELPER_UNAME=Darwin \
  AEGIS_MACOS_PF_HELPER_PFCTL_BIN="${tmpdir}/pfctl" \
  AEGIS_MACOS_PF_HELPER_IFCONFIG_BIN="${tmpdir}/ifconfig" \
  AEGIS_MACOS_PF_HELPER_ROUTE_BIN="${tmpdir}/route" \
  AEGIS_MACOS_PF_HELPER_APPLY_MODE=simulate \
  AEGIS_MACOS_PF_STATE_PATH="${dns_state_path}" \
  AEGIS_MACOS_PF_DNS_PREVIEW_ENABLED=1 \
  bash "${HELPER}" evidence --json
)"

system_wide_apply_json="$(
  AEGIS_MACOS_PF_HELPER_UNAME=Darwin \
  AEGIS_MACOS_PF_HELPER_PFCTL_BIN="${tmpdir}/pfctl" \
  AEGIS_MACOS_PF_HELPER_IFCONFIG_BIN="${tmpdir}/ifconfig" \
  AEGIS_MACOS_PF_HELPER_ROUTE_BIN="${tmpdir}/route" \
  AEGIS_MACOS_PF_HELPER_APPLY_MODE=simulate \
  AEGIS_MACOS_PF_STATE_PATH="${system_wide_state_path}" \
  AEGIS_MACOS_PF_LISTEN="0.0.0.0:25082" \
  AEGIS_MACOS_PF_REDIRECT_FROM="10.10.0.5:28084" \
  AEGIS_MACOS_PF_TARGET="1.1.1.1:53" \
  AEGIS_MACOS_PF_SYSTEM_WIDE_ENABLED=1 \
  bash "${HELPER}" apply --json
)"

system_wide_evidence_json="$(
  AEGIS_MACOS_PF_HELPER_UNAME=Darwin \
  AEGIS_MACOS_PF_HELPER_PFCTL_BIN="${tmpdir}/pfctl" \
  AEGIS_MACOS_PF_HELPER_IFCONFIG_BIN="${tmpdir}/ifconfig" \
  AEGIS_MACOS_PF_HELPER_ROUTE_BIN="${tmpdir}/route" \
  AEGIS_MACOS_PF_HELPER_APPLY_MODE=simulate \
  AEGIS_MACOS_PF_STATE_PATH="${system_wide_state_path}" \
  AEGIS_MACOS_PF_SYSTEM_WIDE_ENABLED=1 \
  bash "${HELPER}" evidence --json
)"

prepared_apply_json="$(
  AEGIS_MACOS_PF_HELPER_UNAME=Darwin \
  AEGIS_MACOS_PF_HELPER_PFCTL_BIN="${tmpdir}/pfctl" \
  AEGIS_MACOS_PF_HELPER_IFCONFIG_BIN="${tmpdir}/ifconfig" \
  AEGIS_MACOS_PF_HELPER_ROUTE_BIN="${tmpdir}/route" \
  AEGIS_MACOS_PF_HELPER_APPLY_MODE=simulate \
  AEGIS_MACOS_PF_STATE_PATH="${prepared_state_path}" \
  AEGIS_MACOS_PF_LISTEN="0.0.0.0:25083" \
  AEGIS_MACOS_PF_REDIRECT_FROM="10.10.0.6:28085" \
  AEGIS_MACOS_PF_TARGET="8.8.8.8:53" \
  AEGIS_MACOS_PF_SYSTEM_WIDE_ENABLED=1 \
  AEGIS_MACOS_PF_PREPARED_BOUNDARY_ENABLED=1 \
  bash "${HELPER}" apply --json
)"

prepared_status_json="$(
  AEGIS_MACOS_PF_HELPER_UNAME=Darwin \
  AEGIS_MACOS_PF_HELPER_PFCTL_BIN="${tmpdir}/pfctl" \
  AEGIS_MACOS_PF_HELPER_IFCONFIG_BIN="${tmpdir}/ifconfig" \
  AEGIS_MACOS_PF_HELPER_ROUTE_BIN="${tmpdir}/route" \
  AEGIS_MACOS_PF_HELPER_APPLY_MODE=simulate \
  AEGIS_MACOS_PF_STATE_PATH="${prepared_state_path}" \
  AEGIS_MACOS_PF_SYSTEM_WIDE_ENABLED=1 \
  AEGIS_MACOS_PF_PREPARED_BOUNDARY_ENABLED=1 \
  bash "${HELPER}" status --json
)"

prepared_evidence_json="$(
  AEGIS_MACOS_PF_HELPER_UNAME=Darwin \
  AEGIS_MACOS_PF_HELPER_PFCTL_BIN="${tmpdir}/pfctl" \
  AEGIS_MACOS_PF_HELPER_IFCONFIG_BIN="${tmpdir}/ifconfig" \
  AEGIS_MACOS_PF_HELPER_ROUTE_BIN="${tmpdir}/route" \
  AEGIS_MACOS_PF_HELPER_APPLY_MODE=simulate \
  AEGIS_MACOS_PF_STATE_PATH="${prepared_state_path}" \
  AEGIS_MACOS_PF_SYSTEM_WIDE_ENABLED=1 \
  AEGIS_MACOS_PF_PREPARED_BOUNDARY_ENABLED=1 \
  bash "${HELPER}" evidence --json
)"

evidence_json="$(
  AEGIS_MACOS_PF_HELPER_UNAME=Darwin \
  AEGIS_MACOS_PF_HELPER_PFCTL_BIN="${tmpdir}/pfctl" \
  AEGIS_MACOS_PF_HELPER_IFCONFIG_BIN="${tmpdir}/ifconfig" \
  AEGIS_MACOS_PF_HELPER_ROUTE_BIN="${tmpdir}/route" \
  AEGIS_MACOS_PF_HELPER_APPLY_MODE=simulate \
  AEGIS_MACOS_PF_STATE_PATH="${state_path}" \
  bash "${HELPER}" evidence --json
)"

linux_json="$(
  AEGIS_MACOS_PF_HELPER_UNAME=Linux \
  bash "${HELPER}" check --json
)"

cleanup_json="$(
  AEGIS_MACOS_PF_HELPER_APPLY_MODE=simulate \
  AEGIS_MACOS_PF_STATE_PATH="${state_path}" \
  bash "${HELPER}" cleanup --json
)"

dns_cleanup_json="$(
  AEGIS_MACOS_PF_HELPER_APPLY_MODE=simulate \
  AEGIS_MACOS_PF_STATE_PATH="${dns_state_path}" \
  bash "${HELPER}" cleanup --json
)"

system_wide_cleanup_json="$(
  AEGIS_MACOS_PF_HELPER_APPLY_MODE=simulate \
  AEGIS_MACOS_PF_STATE_PATH="${system_wide_state_path}" \
  bash "${HELPER}" cleanup --json
)"

prepared_cleanup_json="$(
  AEGIS_MACOS_PF_HELPER_APPLY_MODE=simulate \
  AEGIS_MACOS_PF_STATE_PATH="${prepared_state_path}" \
  bash "${HELPER}" cleanup --json
)"

contract_path="${tmpdir}/contract.json"
check_path="${tmpdir}/check.json"
check_live_without_privilege_path="${tmpdir}/check-live-without-privilege.json"
apply_path="${tmpdir}/apply.json"
status_path="${tmpdir}/status.json"
dns_apply_path="${tmpdir}/dns-apply.json"
dns_evidence_path="${tmpdir}/dns-evidence.json"
system_wide_apply_path="${tmpdir}/system-wide-apply.json"
system_wide_evidence_path="${tmpdir}/system-wide-evidence.json"
prepared_apply_path="${tmpdir}/prepared-apply.json"
prepared_status_path="${tmpdir}/prepared-status.json"
prepared_evidence_path="${tmpdir}/prepared-evidence.json"
evidence_path="${tmpdir}/evidence.json"
linux_path="${tmpdir}/linux.json"
cleanup_path="${tmpdir}/cleanup.json"
dns_cleanup_path="${tmpdir}/dns-cleanup.json"
system_wide_cleanup_path="${tmpdir}/system-wide-cleanup.json"
prepared_cleanup_path="${tmpdir}/prepared-cleanup.json"

printf '%s\n' "${contract_json}" >"${contract_path}"
printf '%s\n' "${check_json}" >"${check_path}"
printf '%s\n' "${check_live_without_privilege_json}" >"${check_live_without_privilege_path}"
printf '%s\n' "${apply_json}" >"${apply_path}"
printf '%s\n' "${status_json}" >"${status_path}"
printf '%s\n' "${dns_apply_json}" >"${dns_apply_path}"
printf '%s\n' "${dns_evidence_json}" >"${dns_evidence_path}"
printf '%s\n' "${system_wide_apply_json}" >"${system_wide_apply_path}"
printf '%s\n' "${system_wide_evidence_json}" >"${system_wide_evidence_path}"
printf '%s\n' "${prepared_apply_json}" >"${prepared_apply_path}"
printf '%s\n' "${prepared_status_json}" >"${prepared_status_path}"
printf '%s\n' "${prepared_evidence_json}" >"${prepared_evidence_path}"
printf '%s\n' "${evidence_json}" >"${evidence_path}"
printf '%s\n' "${linux_json}" >"${linux_path}"
printf '%s\n' "${cleanup_json}" >"${cleanup_path}"
printf '%s\n' "${dns_cleanup_json}" >"${dns_cleanup_path}"
printf '%s\n' "${system_wide_cleanup_json}" >"${system_wide_cleanup_path}"
printf '%s\n' "${prepared_cleanup_json}" >"${prepared_cleanup_path}"

require_file_contains "${contract_path}" '"track":"macos_pf_wide_epic"'
require_file_contains "${contract_path}" '"current_stage":"system_wide_phase3_boundary_capable"'
require_file_contains "${contract_path}" '"scope_target":"system_wide_phase3"'
require_file_contains "${contract_path}" '"system_wide_phase3_prepared_boundary"'
require_file_contains "${contract_path}" '"apply"'
require_file_contains "${check_path}" '"supported_host":true'
require_file_contains "${check_path}" '"status":"ok"'
require_file_contains "${check_path}" '"reason_code":"ready_for_apply"'
require_file_contains "${check_path}" '"pfctl":true'
require_file_contains "${check_path}" '"ifconfig":true'
require_file_contains "${check_path}" '"route":true'
require_file_contains "${check_live_without_privilege_path}" '"supported_host":true'
require_file_contains "${check_live_without_privilege_path}" '"status":"degraded"'
require_file_contains "${check_live_without_privilege_path}" '"reason_code":"privilege_escalation_required_for_live_apply"'
require_file_contains "${check_live_without_privilege_path}" '"sudo_or_root":false'
require_file_contains "${apply_path}" '"runtime_active":true'
require_file_contains "${apply_path}" '"runtime_claim":"tcp_only_phase1_active"'
require_file_contains "${apply_path}" '"listen":"127.0.0.1:25080"'
require_file_contains "${apply_path}" '"redirect_from":"127.0.0.1:28080"'
require_file_contains "${apply_path}" '"target":"127.0.0.1:28081"'
require_file_contains "${status_path}" '"runtime_active":true'
require_file_contains "${status_path}" '"runtime_claim":"tcp_only_phase1_active"'
require_file_contains "${dns_apply_path}" '"runtime_active":true'
require_file_contains "${dns_apply_path}" '"runtime_claim":"dns_preview_phase2_active"'
require_file_contains "${dns_apply_path}" '"dns_preview_enabled":true'
require_file_contains "${dns_apply_path}" '"dns_redirect_from":"127.0.0.1:25353"'
require_file_contains "${dns_apply_path}" '"dns_target":"127.0.0.1:25354"'
require_file_contains "${dns_evidence_path}" '"current_verdict":"dns_preview_phase2_helper_materialized"'
require_file_contains "${dns_evidence_path}" '"dns_preview_happy_path_evidence"'
require_file_contains "${dns_evidence_path}" '"dns_preview_enabled":true'
require_file_contains "${dns_evidence_path}" '"dns_target":"127.0.0.1:25354"'
require_file_contains "${system_wide_apply_path}" '"runtime_active":false'
require_file_contains "${system_wide_apply_path}" '"runtime_claim":"system_wide_phase3_boundary_only"'
require_file_contains "${system_wide_apply_path}" '"system_wide_enabled":true'
require_file_contains "${system_wide_apply_path}" '"current_stage":"system_wide_phase3_boundary"'
require_file_contains "${system_wide_apply_path}" '"scope_target":"system_wide_phase3"'
require_file_contains "${system_wide_apply_path}" '"listen":"0.0.0.0:25082"'
require_file_contains "${system_wide_evidence_path}" '"current_verdict":"system_wide_phase3_boundary_materialized"'
require_file_contains "${system_wide_evidence_path}" '"system_wide_phase3_boundary_contract"'
require_file_contains "${system_wide_evidence_path}" '"system_wide_enabled":true'
require_file_contains "${system_wide_evidence_path}" '"runtime_active":false'
require_file_contains "${prepared_apply_path}" '"runtime_active":false'
require_file_contains "${prepared_apply_path}" '"runtime_claim":"system_wide_phase3_prepared_boundary_only"'
require_file_contains "${prepared_apply_path}" '"system_wide_enabled":true'
require_file_contains "${prepared_apply_path}" '"prepared_boundary_enabled":true'
require_file_contains "${prepared_apply_path}" '"current_stage":"system_wide_phase3_prepared_boundary"'
require_file_contains "${prepared_apply_path}" '"scope_target":"system_wide_phase3"'
require_file_contains "${prepared_status_path}" '"runtime_claim":"system_wide_phase3_prepared_boundary_only"'
require_file_contains "${prepared_status_path}" '"prepared_boundary_enabled":true'
require_file_contains "${prepared_evidence_path}" '"current_verdict":"system_wide_phase3_prepared_boundary_materialized"'
require_file_contains "${prepared_evidence_path}" '"system_wide_phase3_prepared_boundary_contract"'
require_file_contains "${prepared_evidence_path}" '"prepared_boundary_enabled":true'
require_file_contains "${prepared_evidence_path}" '"runtime_active":false'
require_file_contains "${evidence_path}" '"current_verdict":"tcp_only_phase1_helper_materialized"'
require_file_contains "${evidence_path}" '"target":"127.0.0.1:28081"'
require_file_contains "${linux_path}" '"supported_host":false'
require_file_contains "${linux_path}" '"status":"error"'
require_file_contains "${linux_path}" '"reason_code":"unsupported_host_platform"'
for path in "${cleanup_path}" "${dns_cleanup_path}" "${system_wide_cleanup_path}" "${prepared_cleanup_path}"; do
  require_file_contains "${path}" '"status":"ok"'
  require_file_contains "${path}" '"action":"cleanup_applied"'
done

###############################################################################
# Tier 2.2: phase-4 bind-capable live-apply contract.
#
# When AEGIS_MACOS_PF_PHASE4_ENABLED=1 AND SYSTEM_WIDE_ENABLED=1, helper
# MUST: (a) call pfctl -E to enable PF, (b) call pfctl -a <anchor> -f
# <anchor_file> to load the rdr rules, (c) write state with
# pf_rule_active=true, runtime_active=true, current_stage=
# "system_wide_phase4_live", phase4_enabled=true.
###############################################################################
phase4_state_path="${tmpdir}/macos-pf-state-phase4.json"
phase4_anchor_path="${tmpdir}/macos-pf-anchor-phase4.conf"
> "${recording_log}"

phase4_apply_json="$(
  AEGIS_MACOS_PF_HELPER_UNAME=Darwin \
  AEGIS_MACOS_PF_HELPER_PFCTL_BIN="${recording_pfctl}" \
  AEGIS_MACOS_PF_HELPER_IFCONFIG_BIN="${tmpdir}/ifconfig" \
  AEGIS_MACOS_PF_HELPER_ROUTE_BIN="${tmpdir}/route" \
  AEGIS_MACOS_PF_HELPER_SUDO_BIN="${recording_sudo}" \
  AEGIS_MACOS_PF_HELPER_APPLY_MODE=pfctl \
  AEGIS_MACOS_PF_STATE_PATH="${phase4_state_path}" \
  AEGIS_MACOS_PF_ANCHOR_FILE="${phase4_anchor_path}" \
  AEGIS_MACOS_PF_SYSTEM_WIDE_ENABLED=1 \
  AEGIS_MACOS_PF_PHASE4_ENABLED=1 \
  AEGIS_MACOS_PF_EGRESS_IF=en0 \
  bash "${HELPER}" apply --json
)"

phase4_state_json="$(cat "${phase4_state_path}")"
phase4_anchor_body="$(cat "${phase4_anchor_path}")"
phase4_invocations="$(cat "${recording_log}")"
phase4_apply_path="${tmpdir}/phase4-apply.json"
phase4_state_copy="${tmpdir}/phase4-state.copy.json"
phase4_anchor_copy="${tmpdir}/phase4-anchor.copy.conf"
phase4_invocations_path="${tmpdir}/phase4-invocations.log"
printf '%s\n' "${phase4_apply_json}" >"${phase4_apply_path}"
printf '%s\n' "${phase4_state_json}" >"${phase4_state_copy}"
printf '%s\n' "${phase4_anchor_body}" >"${phase4_anchor_copy}"
printf '%s\n' "${phase4_invocations}" >"${phase4_invocations_path}"

require_file_contains "${phase4_apply_path}" '"current_stage":"system_wide_phase4_live"'
require_file_contains "${phase4_apply_path}" '"runtime_active":true'
require_file_contains "${phase4_apply_path}" '"phase4_enabled":true'
require_file_contains "${phase4_state_copy}" '"phase4_enabled":true'
require_file_contains "${phase4_state_copy}" '"runtime_active":true'
require_file_contains "${phase4_state_copy}" '"pf_rule_active":true'
require_file_contains "${phase4_state_copy}" '"current_stage":"system_wide_phase4_live"'
require_file_contains "${phase4_state_copy}" '"egress_if":"en0"'
require_file_contains "${phase4_invocations_path}" "-E"
require_file_contains "${phase4_invocations_path}" "-a"
require_file_contains "${phase4_invocations_path}" "-f"
require_file_contains "${phase4_anchor_copy}" "rdr pass on en0"

echo "macos_pf_helper_phase4_live_apply_ok"

###############################################################################
# Tier 2.2: phase-4 cleanup MUST flush the anchor (pfctl -a anchor -F rules)
# and remove state + anchor file.
###############################################################################
> "${recording_log}"
phase4_cleanup_json="$(
  AEGIS_MACOS_PF_HELPER_UNAME=Darwin \
  AEGIS_MACOS_PF_HELPER_PFCTL_BIN="${recording_pfctl}" \
  AEGIS_MACOS_PF_HELPER_IFCONFIG_BIN="${tmpdir}/ifconfig" \
  AEGIS_MACOS_PF_HELPER_ROUTE_BIN="${tmpdir}/route" \
  AEGIS_MACOS_PF_HELPER_SUDO_BIN="${recording_sudo}" \
  AEGIS_MACOS_PF_HELPER_APPLY_MODE=pfctl \
  AEGIS_MACOS_PF_STATE_PATH="${phase4_state_path}" \
  AEGIS_MACOS_PF_ANCHOR_FILE="${phase4_anchor_path}" \
  AEGIS_MACOS_PF_SYSTEM_WIDE_ENABLED=1 \
  AEGIS_MACOS_PF_PHASE4_ENABLED=1 \
  AEGIS_MACOS_PF_EGRESS_IF=en0 \
  bash "${HELPER}" cleanup --json
)"
phase4_cleanup_invocations="$(cat "${recording_log}")"
phase4_cleanup_path="${tmpdir}/phase4-cleanup.json"
phase4_cleanup_invocations_path="${tmpdir}/phase4-cleanup-invocations.log"
printf '%s\n' "${phase4_cleanup_json}" >"${phase4_cleanup_path}"
printf '%s\n' "${phase4_cleanup_invocations}" >"${phase4_cleanup_invocations_path}"
require_file_contains "${phase4_cleanup_path}" '"status":"ok"'
require_file_contains "${phase4_cleanup_path}" '"action":"cleanup_applied"'
require_file_contains "${phase4_cleanup_invocations_path}" "-a"
require_file_contains "${phase4_cleanup_invocations_path}" "-F"
require_file_contains "${phase4_cleanup_invocations_path}" "rules"
reject_path_exists "${phase4_state_path}"
reject_path_exists "${phase4_anchor_path}"

echo "macos_pf_helper_phase4_cleanup_ok"

echo "macos_pf_helper_contract_ok"
