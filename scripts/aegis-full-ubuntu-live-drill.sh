#!/usr/bin/env bash
# aegis-full-ubuntu-live-drill.sh — Ubuntu acceptance orchestrator.
#
# Single-entrypoint live drill that exercises (or skips with explicit
# verdict) every Ubuntu acceptance lane and aggregates results into a
# single artifact directory. Operator-facing; designed to be re-runnable.
#
# Required env:
#   RELAY_HOST            explicit relay IPv4 address (for direct exempt)
#   EXPECTED_EGRESS_IPS    independent comma-separated canonical IPv4 allow-set
#   VPS_A_HOST             literal IPv4 address of the installed Ubuntu host
#   VPS_A_SSH_ALIAS        operator-pinned known_hosts name for VPS_A (port22)
#   VPS_A_SSH_KEY          absolute path to the operator-owned private key
#   AEGIS_SSH_KNOWN_HOSTS  absolute path to operator-pinned known_hosts
# Optional:
#   VPS_B_HOST, VPS_B_SSH_ALIAS, VPS_B_SSH_KEY  downstream host/identity tuple
#   ARTIFACT_DIR          where to write evidence (default: ${AEGIS_EVIDENCE_DIR:-~/aegis-evidence}/live/$(date +%F)/full-ubuntu-acceptance)
#   AEGIS_VERSION_EXPECT  expected aegis-client version (default: skip check)
#   SKIP_LANES            comma-list of lanes to skip (socks,transport_matrix,brain,redirect_wide,dns_off,dns_preview,tproxy_gateway,ipv6,uninstall)
#
# Password inputs are refused; see docs/operations/full-ubuntu-live-drill.md.
# Output: ${ARTIFACT_DIR}/{result.json, summary.md, commands.log, lane-*.txt, runtime-events.jsonl, *-state.txt}
#
# Verdicts per lane:
#   PASS     — live evidence confirms expected behavior
#   PARTIAL  — partially proven; specific gap documented
#   BLOCKER  — known-broken; reason documented
#   SKIPPED  — operator requested skip, OR prerequisite missing (e.g. VPS_B not provided)
#   N/A      — lane not applicable in current topology

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---- arg parsing ----
VPS_A_HOST="${VPS_A_HOST:-}"
VPS_A_SSH_ALIAS="${VPS_A_SSH_ALIAS:-}"
VPS_A_SSH_KEY="${VPS_A_SSH_KEY:-}"
VPS_B_HOST="${VPS_B_HOST:-}"
VPS_B_SSH_ALIAS="${VPS_B_SSH_ALIAS:-}"
VPS_B_SSH_KEY="${VPS_B_SSH_KEY:-}"
AEGIS_SSH_KNOWN_HOSTS="${AEGIS_SSH_KNOWN_HOSTS:-}"
RELAY_HOST="${RELAY_HOST:-}"
ARTIFACT_DIR="${ARTIFACT_DIR:-${AEGIS_EVIDENCE_DIR:-${HOME}/aegis-evidence}/live/$(date -u +%F)/full-ubuntu-acceptance}"
SKIP_LANES="${SKIP_LANES:-}"

usage() {
    cat <<USAGE
Usage: RELAY_HOST=ipv4 EXPECTED_EGRESS_IPS=ipv4,ipv4 VPS_A_HOST=ipv4 VPS_A_SSH_ALIAS=name VPS_A_SSH_KEY=/private/key \
       AEGIS_SSH_KNOWN_HOSTS=/private/known_hosts $0

Required env:
  RELAY_HOST            Explicit canonical IPv4 relay address
  EXPECTED_EGRESS_IPS    Independent allow-set (1..16 canonical IPv4s; <=256 bytes)
  VPS_A_HOST             Installed Ubuntu host's literal IPv4 address
  VPS_A_SSH_ALIAS        Independently pinned known_hosts name (port22)
  VPS_A_SSH_KEY          Absolute, operator-owned mode0400/0600 private-key path
  AEGIS_SSH_KNOWN_HOSTS  Absolute, operator-owned mode0400/0600 known_hosts path

Optional env:
  VPS_B_HOST, VPS_B_SSH_ALIAS, VPS_B_SSH_KEY  Complete downstream identity tuple
  ARTIFACT_DIR        Output directory
  SKIP_LANES          Comma-list to skip: socks,transport_matrix,brain,redirect_wide,
                      dns_off,dns_preview,tproxy_gateway,ipv6,uninstall
Password inputs VPS_A_PASS/VPS_B_PASS are unsupported and refused.
USAGE
}

# No password value is read, copied or printed, including legacy input refusal.
if [[ "${VPS_A_PASS+x}" == x || "${VPS_B_PASS+x}" == x ]]; then
    echo "FATAL: legacy SSH password inputs are unsupported" >&2
    exit 2
fi

# The relay exemption identity is operator-selected, never discovered.
# Admit only an unambiguous IPv4 literal before key lookup, output or transport.
relay_input_refused() {
    echo "FATAL: explicit canonical IPv4 RELAY_HOST required" >&2
    exit 2
}
relay_host_ready() {
    local address="$1" part
    [[ "$address" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    for part in ${address//./ }; do
        [[ "$part" == 0 || "$part" =~ ^[1-9][0-9]{0,2}$ ]] || return 1
        (( 10#$part <= 255 )) || return 1
    done
}
relay_host_ready "$RELAY_HOST" || relay_input_refused

# Expected egress is an independent operator reference, not a discovered value.
EXPECTED_EGRESS_IPS="${EXPECTED_EGRESS_IPS:-}"
EXPECTED_EGRESS_SET=()
expected_egress_refused() {
    echo "FATAL: explicit canonical IPv4 EXPECTED_EGRESS_IPS allow-set required" >&2
    exit 2
}
expected_egress_ready() {
    local LC_ALL=C address
    [[ -n "$EXPECTED_EGRESS_IPS" && ${#EXPECTED_EGRESS_IPS} -le 256 ]] || return 1
    [[ "$EXPECTED_EGRESS_IPS" =~ ^[0-9.,]+$ ]] || return 1
    case "$EXPECTED_EGRESS_IPS" in ,*|*,|*,,*) return 1 ;; esac
    IFS=, read -r -a EXPECTED_EGRESS_SET <<< "$EXPECTED_EGRESS_IPS"
    [[ ${#EXPECTED_EGRESS_SET[@]} -ge 1 && ${#EXPECTED_EGRESS_SET[@]} -le 16 ]] || return 1
    for address in "${EXPECTED_EGRESS_SET[@]}"; do
        relay_host_ready "$address" || return 1
    done
}
expected_egress_ready || expected_egress_refused

# The trace/event output may contain other fields, but only one complete ip=
# line is evidence. Duplicate or conflicting ip= lines cannot manufacture PASS.
expected_egress_matches() {
    local line address selected count=0 matched=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        case "$line" in
            ip=*)
                count=$((count + 1))
                [[ "$count" -eq 1 ]] || return 1
                address="${line#ip=}"
                relay_host_ready "$address" || return 1
                for selected in "${EXPECTED_EGRESS_SET[@]}"; do
                    [[ "$address" != "$selected" ]] || matched=1
                done
                ;;
        esac
    done <<< "$1"
    [[ "$count" -eq 1 && "$matched" -eq 1 ]]
}

ssh_input_refused() {
    echo "FATAL: preconfigured SSH identity and pinned host key required" >&2
    exit 2
}

ssh_private_file_ready() {
    local path="$1" mode
    [[ "$path" == /* && -f "$path" && ! -L "$path" && -r "$path" && -O "$path" ]] || return 1
    # Reject config/token syntax so both -i and UserKnownHostsFile designate
    # the exact metadata-inspected pathname without OpenSSH expansion.
    [[ ! "$path" =~ [[:space:][:cntrl:]] ]] || return 1
    case "$path" in *'"'*|*"'"*|*'\'*|*'$'*|*'%'*) return 1 ;; esac
    # Only metadata is read. GNU stat is native on Ubuntu; BSD stat keeps the
    # offline operator contract portable without reading private key contents.
    mode="$(stat -c '%a' -- "$path" 2>/dev/null)" || \
        mode="$(stat -f '%Lp' "$path" 2>/dev/null)" || return 1
    [[ "$mode" == 400 || "$mode" == 600 ]]
}

ssh_host_ready() {
    local address="$1" alias="$2" key="$3" part
    [[ "$address" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    for part in ${address//./ }; do
        (( 10#$part <= 255 )) || return 1
    done
    [[ "$alias" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || return 1
    ssh_private_file_ready "$key" || return 1
    # This reads only the public known_hosts entry; its contents never enter
    # stdout/stderr, journals or argv. No keyscan, SSH or DNS contact is made.
    ssh-keygen -F "$alias" -f "$AEGIS_SSH_KNOWN_HOSTS" >/dev/null 2>&1
}

ssh_private_file_ready "$AEGIS_SSH_KNOWN_HOSTS" || ssh_input_refused
command -v ssh >/dev/null 2>&1 && command -v scp >/dev/null 2>&1 && \
    command -v ssh-keygen >/dev/null 2>&1 || ssh_input_refused
ssh_host_ready "$VPS_A_HOST" "$VPS_A_SSH_ALIAS" "$VPS_A_SSH_KEY" || ssh_input_refused
if [[ -n "$VPS_B_HOST" || -n "$VPS_B_SSH_ALIAS" || -n "$VPS_B_SSH_KEY" ]]; then
    ssh_host_ready "$VPS_B_HOST" "$VPS_B_SSH_ALIAS" "$VPS_B_SSH_KEY" || ssh_input_refused
fi

mkdir -p "${ARTIFACT_DIR}"
COMMANDS_LOG="${ARTIFACT_DIR}/commands.log"
: > "${COMMANDS_LOG}"

# ---- helpers ----
# An explicit HostName maps each public network address to its pinned alias.
# -F /dev/null suppresses user/system SSH configuration and implicit proxies.
ssh_a() {
    ssh -F /dev/null -i "$VPS_A_SSH_KEY" \
        -o "HostName=$VPS_A_HOST" -o "HostKeyAlias=$VPS_A_SSH_ALIAS" -o Port=22 \
        -o "UserKnownHostsFile=$AEGIS_SSH_KNOWN_HOSTS" -o GlobalKnownHostsFile=/dev/null \
        -o StrictHostKeyChecking=yes -o BatchMode=yes -o IdentitiesOnly=yes \
        -o IdentityAgent=none -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
        -o ConnectTimeout=10 root@"$VPS_A_SSH_ALIAS" "$@" 2>&1
}
ssh_b() {
    [[ -z "${VPS_B_HOST}" ]] && return 99
    ssh -F /dev/null -i "$VPS_B_SSH_KEY" \
        -o "HostName=$VPS_B_HOST" -o "HostKeyAlias=$VPS_B_SSH_ALIAS" -o Port=22 \
        -o "UserKnownHostsFile=$AEGIS_SSH_KNOWN_HOSTS" -o GlobalKnownHostsFile=/dev/null \
        -o StrictHostKeyChecking=yes -o BatchMode=yes -o IdentitiesOnly=yes \
        -o IdentityAgent=none -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
        -o ConnectTimeout=10 root@"$VPS_B_SSH_ALIAS" "$@" 2>&1
}
scp_a() {
    scp -F /dev/null -i "$VPS_A_SSH_KEY" \
        -o "HostName=$VPS_A_HOST" -o "HostKeyAlias=$VPS_A_SSH_ALIAS" -o Port=22 \
        -o "UserKnownHostsFile=$AEGIS_SSH_KNOWN_HOSTS" -o GlobalKnownHostsFile=/dev/null \
        -o StrictHostKeyChecking=yes -o BatchMode=yes -o IdentitiesOnly=yes \
        -o IdentityAgent=none -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
        "$@" 2>&1
}

log() {
    local msg="$1"
    echo "[$(date -u +%H:%M:%S)] ${msg}" | tee -a "${COMMANDS_LOG}" >&2
}

skip_lane() {
    [[ ",${SKIP_LANES}," == *",$1,"* ]]
}

# Verdicts collected as bash associative array
declare -A VERDICT
declare -A REASON
record_verdict() {
    local lane="$1" status="$2" reason="${3:-}"
    VERDICT[$lane]="${status}"
    REASON[$lane]="${reason}"
    log "lane=${lane} verdict=${status} ${reason:+reason=${reason}}"
}

# ---- pre-flight ----
log "Pre-flight: probing VPS_A ${VPS_A_HOST}"
if ! ssh_a 'uname -a; aegis-client --version 2>&1 || echo "no aegis-client"' \
        > "${ARTIFACT_DIR}/preflight-vps-a.txt"; then
    log "FATAL: VPS_A ssh failed"; exit 3
fi
if [[ -n "${VPS_B_HOST}" ]]; then
    log "Pre-flight: probing VPS_B ${VPS_B_HOST}"
    ssh_b 'uname -a' > "${ARTIFACT_DIR}/preflight-vps-b.txt" || \
        { log "WARN: VPS_B unreachable, gateway drill will SKIP"; VPS_B_HOST=""; }
fi

# ---- before-state snapshot ----
log "Capturing BEFORE state on VPS_A"
ssh_a 'echo "=== iptables nat ==="; iptables -t nat -L -n -v;
       echo "=== iptables filter ==="; iptables -L -n -v | head -30;
       echo "=== iptables mangle ==="; iptables -t mangle -L -n -v;
       echo "=== ip rule ==="; ip rule show;
       echo "=== ip -4 route ==="; ip -4 route show;
       echo "=== ip -4 route table 100 ==="; ip -4 route show table 100;
       echo "=== ss -lnp ==="; ss -lnp | head -20;
       echo "=== aegis config ==="; grep -E "^primary|^\[" /etc/aegis/client/aegis.toml | head -20;
       echo "=== curl direct ==="; curl -4 -sS --max-time 6 https://1.1.1.1/cdn-cgi/trace 2>&1 | head -10' \
       > "${ARTIFACT_DIR}/state-BEFORE.txt"

# ---- lane: SOCKS5 baseline (default install posture) ----
if ! skip_lane socks; then
    log "Lane: SOCKS5 baseline"
    out="$(ssh_a '> /var/log/aegis-client/runtime-events.jsonl 2>/dev/null;
        chown aegis:aegis /var/log/aegis-client/runtime-events.jsonl 2>/dev/null || true;
        # Force SOCKS5 mode if currently wide
        if grep -q "^primary = \"wide\"" /etc/aegis/client/aegis.toml; then
            sed -i "s|^primary = \"wide\"|primary = \"socks5\"|" /etc/aegis/client/aegis.toml
            systemctl restart aegis-client; sleep 3
        fi
        ss -lntp | grep -E ":1080|:15080" | head -3
        echo "---curl via SOCKS---"
        curl -4 --max-time 12 --socks5-hostname 127.0.0.1:1080 -sS https://1.1.1.1/cdn-cgi/trace 2>&1 | head -5
        echo "---runtime events tail---"
        grep -E "relay_session_succeeded|relay_session_started" /var/log/aegis-client/runtime-events.jsonl | tail -2 | head -2')"
    echo "${out}" > "${ARTIFACT_DIR}/lane-socks.txt"
    if expected_egress_matches "${out}"; then
        record_verdict socks PASS "curl via SOCKS returned relay IP"
    else
        record_verdict socks PARTIAL "SOCKS curl did not return relay IP — see lane-socks.txt"
    fi
else
    record_verdict socks SKIPPED "operator requested skip"
fi

# ---- lane: relay transport matrix ----
# Drive each transport family explicitly by pinning transport_priority to a
# single entry, then verifying the matching PascalCase `"transport":"<X>"`
# field appears in runtime-events.jsonl. Restores original config at the end.
#
# This replaces the earlier "scan whatever the window contained" pattern
# which yielded PARTIAL ("only 1 transport observed") whenever the drill
# window was short.
if ! skip_lane transport_matrix; then
    log "Lane: relay transport matrix (4-way drive)"
    # The four canonical transport families. Left = config snake_case,
    # Right = JSONL Debug-form PascalCase (see aegis-client/src/relay/events.rs).
    transports_snake="https_ws grpc_stream masque_derived legacy_tls"
    pass_count=0
    fail_list=""
    matrix_log="${ARTIFACT_DIR}/lane-transport-matrix.txt"
    : > "${matrix_log}"

    # Snapshot original config so we can restore at the end.
    ssh_a 'cp -a /etc/aegis/client/aegis.toml /etc/aegis/client/aegis.toml.transport-matrix.bak 2>/dev/null
           # If a SOCKS-mode primary is active, switch to it for the drill so
           # curl --socks5 reaches the listener (wide mode would also work but
           # SOCKS keeps the lane independent from redirect_wide lane).
           if grep -q "^primary = \"wide\"" /etc/aegis/client/aegis.toml; then
               sed -i "s|^primary = \"wide\"|primary = \"socks5\"|" /etc/aegis/client/aegis.toml
           fi' >/dev/null 2>&1

    for snake in ${transports_snake}; do
        case "${snake}" in
            https_ws)        pascal="HttpsWs" ;;
            grpc_stream)     pascal="GrpcStream" ;;
            masque_derived)  pascal="MasqueDerived" ;;
            legacy_tls)      pascal="LegacyTls" ;;
        esac
        echo "=== drive snake=${snake} expect-pascal=${pascal} ===" >> "${matrix_log}"
        # Pin transport, disable rotation, restart client.
        ssh_a "sed -i 's|^transport_priority *=.*|transport_priority = [\"${snake}\"]|' /etc/aegis/client/aegis.toml
               sed -i 's|^rotate_transports_per_session *=.*|rotate_transports_per_session = false|' /etc/aegis/client/aegis.toml
               sed -i 's|^max_transport_attempts *=.*|max_transport_attempts = 1|' /etc/aegis/client/aegis.toml
               systemctl restart aegis-client
               sleep 3
               : > /var/log/aegis-client/runtime-events.jsonl
               chown aegis:aegis /var/log/aegis-client/runtime-events.jsonl 2>/dev/null || true
               curl -4 --max-time 12 --socks5-hostname 127.0.0.1:1080 -sS \
                    https://1.1.1.1/cdn-cgi/trace 2>&1 | head -3
               echo '---runtime tail---'
               grep -E 'relay_transport_selected|relay_session_succeeded|relay_transport_failed' \
                    /var/log/aegis-client/runtime-events.jsonl | tail -6" \
            >> "${matrix_log}" 2>&1 || true
        # Verify: grep for transport in relay_session_succeeded events.
        # The actual JSONL field is "chosen_transport":"<Pascal>" on
        # relay_session_succeeded and "transport":"<Pascal>" on
        # relay_transport_selected — accept either by stripping both
        # prefixes after the regex match.
        observed="$(ssh_a "grep -E 'relay_transport_selected|relay_session_succeeded' \
                          /var/log/aegis-client/runtime-events.jsonl \
                          | awk 'match(\$0, /\"(chosen_transport|transport)\":\"[A-Za-z]+\"/) {
                                    s = substr(\$0, RSTART, RLENGTH);
                                    sub(/^\"(chosen_transport|transport)\":\"/, \"\", s);
                                    sub(/\"\$/, \"\", s);
                                    print s
                                 }' \
                          | sort -u")"
        echo "observed transports for ${snake}: ${observed}" >> "${matrix_log}"
        if echo "${observed}" | grep -qx "${pascal}"; then
            pass_count=$((pass_count + 1))
        else
            fail_list="${fail_list} ${snake}=>${observed:-(none)}"
        fi
    done

    # Restore original config.
    ssh_a 'if [[ -f /etc/aegis/client/aegis.toml.transport-matrix.bak ]]; then
               mv /etc/aegis/client/aegis.toml.transport-matrix.bak /etc/aegis/client/aegis.toml
               systemctl restart aegis-client; sleep 2
           fi' >/dev/null 2>&1

    echo "" >> "${matrix_log}"
    echo "matrix verdict: pass=${pass_count}/4" >> "${matrix_log}"
    if [[ ${pass_count} -eq 4 ]]; then
        record_verdict transport_matrix PASS "4/4 transports drove a matching relay event"
    elif [[ ${pass_count} -ge 2 ]]; then
        record_verdict transport_matrix PARTIAL "${pass_count}/4 transports verified; missing:${fail_list}"
    elif [[ ${pass_count} -eq 1 ]]; then
        record_verdict transport_matrix PARTIAL "only 1/4 transports verified; missing:${fail_list}"
    else
        record_verdict transport_matrix PARTIAL "0/4 transports verified — see lane-transport-matrix.txt"
    fi
else
    record_verdict transport_matrix SKIPPED ""
fi

# ---- lane: Brain operational events (drive via external calibration) ----
# Replaces the old "scan whatever's in the window" pattern that produced
# PARTIAL on every short drill. Now we:
#   1. Compose a minimal valid external_calibration_summary on VPS_A
#   2. Run `aegis-client --apply-external-calibration-summary` (one-shot)
#   3. Restart the daemon so it consumes the calibration snapshot
#   4. Drive a SOCKS request to force a relay session evaluation
#   5. Verify both external_calibration_applied AND brain_select_order_explained
#      appear in runtime-events.jsonl
if ! skip_lane brain; then
    log "Lane: Brain operational events (forced via external calibration)"
    out="$(ssh_a "cat > /tmp/aegis-brain-calibration.json <<'CALIBJSON'
{
  \"event\": \"external_calibration_summary\",
  \"schema_version\": 1,
  \"witness\": { \"labels\": [
      { \"label\": \"https_ws\", \"records\": 5, \"combined_avg\": 0.85,
        \"ja3_present_avg\": 1.0, \"alpn_match_avg\": 0.9, \"sni_structure_avg\": 0.7 },
      { \"label\": \"grpc_stream\", \"records\": 4, \"combined_avg\": 0.7,
        \"ja3_present_avg\": 1.0, \"alpn_match_avg\": 0.8, \"sni_structure_avg\": 0.55 }
  ]},
  \"adversarial\": { \"transports\": [
      { \"transport\": \"https_ws\", \"records\": 5, \"measured\": 5, \"planned\": 0,
        \"passed\": 5, \"failed\": 0, \"pass_rate\": 1.0, \"threshold\": 0.85 }
  ]},
  \"verdict\": { \"status\": \"MEASURED\", \"acceptance_degraded\": false, \"reasons\": [] }
}
CALIBJSON
        : > /var/log/aegis-client/runtime-events.jsonl
        chown aegis:aegis /var/log/aegis-client/runtime-events.jsonl 2>/dev/null || true
        # Run calibration as the aegis user so the state.json + seed files it
        # writes inherit aegis:aegis ownership. Running as root would leave
        # them owned by root and crash the daemon on next restart with
        # \"state /var/lib/aegis-client/state.json: Permission denied\" —
        # exactly what blocked redirect_wide + dns_preview lanes when this
        # ran before fix.
        # --runtime-events-jsonl must be passed to the apply CLI too: the
        # runtime_jsonl::emit_external_calibration_applied call inside
        # apply_external_calibration_summary() (aegis-client/src/main.rs)
        # only writes when GLOBAL_STREAM is initialised — which only
        # happens when --runtime-events-jsonl is on the command line.
        # Without it the emit is a no-op and the orchestrator never sees
        # the event even though state was correctly applied.
        sudo -u aegis aegis-client --config /etc/aegis/client/aegis.toml \
            --runtime-events-jsonl /var/log/aegis-client/runtime-events.jsonl \
            --apply-external-calibration-summary /tmp/aegis-brain-calibration.json --json 2>&1 | tail -5
        # Belt-and-braces in case sudo dropped a fresh file owned wrong:
        chown -R aegis:aegis /var/lib/aegis-client 2>/dev/null || true
        systemctl restart aegis-client
        sleep 3
        # Drive a relay session so the brain selector runs.
        curl -4 --max-time 12 --socks5-hostname 127.0.0.1:1080 -sS \
             https://1.1.1.1/cdn-cgi/trace 2>&1 | head -3
        echo '---runtime events tail---'
        grep -E 'external_calibration_applied|brain_select_order_explained' \
             /var/log/aegis-client/runtime-events.jsonl | tail -5")"
    echo "${out}" > "${ARTIFACT_DIR}/lane-brain.txt"
    have_cal=$(echo "${out}" | grep -c "external_calibration_applied" || true)
    have_brain=$(echo "${out}" | grep -c "brain_select_order_explained" || true)
    if [[ ${have_cal} -gt 0 && ${have_brain} -gt 0 ]]; then
        record_verdict brain PASS "external_calibration_applied + brain_select_order_explained both observed in fresh drill window"
    elif [[ ${have_cal} -gt 0 ]]; then
        record_verdict brain PARTIAL "external_calibration_applied present; brain_select_order_explained missing (no relay session triggered?)"
    elif [[ ${have_brain} -gt 0 ]]; then
        record_verdict brain PARTIAL "brain_select_order_explained present but external_calibration_applied missing"
    else
        record_verdict brain PARTIAL "no brain events in this drill window — see lane-brain.txt"
    fi
else
    record_verdict brain SKIPPED ""
fi

# ---- lane: REDIRECT wide enable ----
if ! skip_lane redirect_wide; then
    log "Lane: REDIRECT wide enable + curl direct"
    # Switch to wide primary
    ssh_a 'sed -i "s|^primary = \"socks5\"|primary = \"wide\"|" /etc/aegis/client/aegis.toml
           systemctl restart aegis-client; sleep 3
           AEGIS_WIDE_ROLLBACK_SECS=900 /tmp/aegis-wide-helpers/aegis-wide-enable.sh -y \
               --mode=redirect --ssh-safe-ports=22 --dns=off --ipv6=block 2>&1 | tail -5
           touch /run/aegis-wide-confirmed
           sleep 1' > "${ARTIFACT_DIR}/lane-redirect-wide-enable.txt"
    out="$(ssh_a 'curl -4 -sS --max-time 12 https://1.1.1.1/cdn-cgi/trace 2>&1 | head -10')"
    echo "---curl direct without SOCKS---" >> "${ARTIFACT_DIR}/lane-redirect-wide-enable.txt"
    echo "${out}" >> "${ARTIFACT_DIR}/lane-redirect-wide-enable.txt"
    if expected_egress_matches "${out}"; then
        record_verdict redirect_wide PASS "curl direct went through AEGIS (returned relay IP)"
    else
        record_verdict redirect_wide PARTIAL "curl direct returned: $(echo "${out}" | grep ^ip= | head -1)"
    fi
else
    record_verdict redirect_wide SKIPPED ""
fi

# ---- lane: DNS off (fail-closed) ----
# Test that an unprivileged subprocess on the host can't resolve via UDP/53
# while the wide-redirect chain has dns=off. We use the `nobody` user
# (always present on Linux) instead of the previously-hardcoded
# `aegis-test-user` (never present) which produced a bogus PARTIAL.
if ! skip_lane dns_off; then
    log "Lane: DNS off fail-closed"
    out="$(ssh_a 'sudo -u nobody timeout 6 getent ahostsv4 example.com 2>&1; echo "rc=$?"')"
    echo "${out}" > "${ARTIFACT_DIR}/lane-dns-off.txt"
    # Empty getent output OR rc==2 (host not found) = blocked = expected for dns=off.
    if [[ -z "$(echo "${out}" | grep -v "^rc=" | grep -v "^$")" ]] || echo "${out}" | grep -q "rc=2"; then
        record_verdict dns_off PASS "DNS UDP/53 blocked as expected (fail-closed) — nobody-user resolve returned empty"
    else
        record_verdict dns_off PARTIAL "DNS resolved despite dns=off — see lane-dns-off.txt"
    fi
else
    record_verdict dns_off SKIPPED ""
fi

# ---- lane: DNS preview (v0.3.13 fake-IP architecture) ----
if ! skip_lane dns_preview; then
    log "Lane: DNS preview (fake-IP fake-IP→hostname recovery)"
    ssh_a '/tmp/aegis-wide-helpers/aegis-wide-disable.sh > /dev/null 2>&1; sleep 1
           > /var/log/aegis-client/runtime-events.jsonl
           chown aegis:aegis /var/log/aegis-client/runtime-events.jsonl 2>/dev/null || true
           AEGIS_WIDE_ROLLBACK_SECS=900 /tmp/aegis-wide-helpers/aegis-wide-enable.sh -y \
               --mode=redirect --ssh-safe-ports=22 --dns=preview --ipv6=block 2>&1 | tail -5
           touch /run/aegis-wide-confirmed' > "${ARTIFACT_DIR}/lane-dns-preview-enable.txt"
    out="$(ssh_a 'echo "---fake-IP listener bound on :53---"
                  ss -lnup | grep ":53 " | head -2
                  echo "---resolv.conf---"
                  head -3 /etc/resolv.conf
                  echo "---getent hosts example.com (expects fake IP from 198.18/15)---"
                  getent hosts example.com 2>&1 | head -3
                  echo "---getent hosts cloudflare.com---"
                  getent hosts cloudflare.com 2>&1 | head -3
                  echo "---curl https://example.com/ (no SOCKS, through fake-IP path)---"
                  curl -4 -sS --max-time 15 -o /dev/null -w "code=%{http_code} ip=%{remote_ip} size=%{size_download}\n" https://example.com/ 2>&1 | tail -2
                  echo "---curl https://1.1.1.1/cdn-cgi/trace (raw IP still through wide)---"
                  curl -4 -sS --max-time 10 https://1.1.1.1/cdn-cgi/trace 2>&1 | grep "^ip="
                  echo "---unknown fake-IP rejection (198.18.99.99 has no mapping)---"
                  timeout 3 curl -4 -sS --max-time 3 -o /dev/null -w "code=%{http_code}\n" https://198.18.99.99/ 2>&1 | tail -1
                  echo "---runtime events: dns_fake_ip_assigned + wide_fake_ip_hostname_recovered + relay_session_succeeded target=hostname---"
                  grep -E "dns_fake_ip_assigned|wide_fake_ip_hostname_recovered|wide_fake_ip_hostname_missing|dns_preview_enabled" /var/log/aegis-client/runtime-events.jsonl | tail -5
                  echo "---relay session target=example.com---"
                  grep "relay_session_succeeded" /var/log/aegis-client/runtime-events.jsonl | grep -oE "\"target\":\"[^\"]*\"" | sort | uniq -c | head -5')"
    echo "${out}" > "${ARTIFACT_DIR}/lane-dns-preview.txt"
    pass_signals=0
    echo "${out}" | grep -q "198\.1[89]\..*example.com" && pass_signals=$((pass_signals+1))
    echo "${out}" | grep -q "code=200" && pass_signals=$((pass_signals+1))
    echo "${out}" | grep -q "dns_fake_ip_assigned" && pass_signals=$((pass_signals+1))
    echo "${out}" | grep -q "wide_fake_ip_hostname_recovered" && pass_signals=$((pass_signals+1))
    echo "${out}" | grep -q '"target":"example.com"' && pass_signals=$((pass_signals+1))
    if [[ ${pass_signals} -ge 4 ]]; then
        record_verdict dns_preview PASS "${pass_signals}/5 fake-IP signals confirmed: getent returns 198.18/15, curl returns 200, dns_fake_ip_assigned + wide_fake_ip_hostname_recovered emitted, relay_session_succeeded target=example.com"
    elif [[ ${pass_signals} -ge 2 ]]; then
        record_verdict dns_preview PARTIAL "${pass_signals}/5 fake-IP signals confirmed; see lane-dns-preview.txt"
    else
        record_verdict dns_preview BLOCKER "fake-IP path did not produce expected signals; see lane-dns-preview.txt"
    fi
else
    record_verdict dns_preview SKIPPED ""
fi

# ---- lane: TPROXY gateway 2-VPS via GRE tunnel ----
# Topology:
#   VPS_B (.77 downstream) ──GRE tunnel──► VPS_A (.197 gateway, wide TPROXY)
#                                            └─► example.com relay ──► test target
#
# Why GRE: VPS_A and VPS_B are typically on different L3 subnets (cloud-fabric
# anti-spoofing also drops bare-routed forwarded TCP). GRE encapsulates the
# inner spoofed-src reply inside an outer header that carries VPS_A's real IP,
# bypassing the anti-spoof filter.
#
# Why listen=0.0.0.0:15080: the bundle default 127.0.0.1:15080 only handles
# locally-originated traffic. Transit packets from the tunnel arrive with
# arbitrary destination IPs and route_localnet alone is not enough — listener
# must accept any address.
#
# Cleanup: restore listen to 127.0.0.1:15080, disable wide, teardown GRE.
#
# Verdict gates by time-window + target-tuple to reject scan-noise contamination.
TEST_TARGET="${TPROXY_GATEWAY_TEST_TARGET:-9.9.9.9}"
TUNNEL_GW_TIP="${TPROXY_GATEWAY_TUNNEL_GW_TIP:-10.255.0.1}"
TUNNEL_DS_TIP="${TPROXY_GATEWAY_TUNNEL_DS_TIP:-10.255.0.2}"

if ! skip_lane tproxy_gateway; then
    if [[ -z "${VPS_B_HOST}" ]]; then
        record_verdict tproxy_gateway SKIPPED "VPS_B_HOST not provided"
    else
        log "Lane: TPROXY gateway via GRE tunnel (target=${TEST_TARGET})"
        gw_log="${ARTIFACT_DIR}/lane-tproxy-gateway-enable.txt"
        vb_log="${ARTIFACT_DIR}/lane-tproxy-gateway-vps-b.txt"
        : > "${gw_log}"; : > "${vb_log}"

        # 1. Snapshot+swap listen → 0.0.0.0:15080, ensure GRE up, bring up wide tproxy on aegis-gre0.
        ssh_a "set -e
               /tmp/aegis-wide-helpers/aegis-wide-disable.sh >/dev/null 2>&1; sleep 1
               # Snapshot listen (idempotent across reruns)
               cp -an /etc/aegis/client/aegis.toml /etc/aegis/client/aegis.toml.tproxy-gateway.bak 2>/dev/null
               sed -i 's|^listen = \"127.0.0.1:15080\"|listen = \"0.0.0.0:15080\"|' /etc/aegis/client/aegis.toml
               systemctl restart aegis-client; sleep 3
               > /var/log/aegis-client/runtime-events.jsonl
               chown aegis:aegis /var/log/aegis-client/runtime-events.jsonl 2>/dev/null || true
               sysctl -wq net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
               # GRE tunnel — idempotent
               /tmp/aegis-wide-helpers/aegis-gre-gateway-setup.sh apply --role=gateway \
                   --peer-ip=${VPS_B_HOST} \
                   --local-tip=${TUNNEL_GW_TIP}/30 \
                   --peer-tip=${TUNNEL_DS_TIP} 2>&1 | tail -4
               # Wide TPROXY on the tunnel
               AEGIS_WIDE_ROLLBACK_SECS=900 /tmp/aegis-wide-helpers/aegis-wide-enable.sh -y \
                   --mode=tproxy --interface=aegis-gre0 --ssh-safe-ports=22 \
                   --dns=off --ipv6=block 2>&1 | tail -2
               touch /run/aegis-wide-confirmed" \
            >> "${gw_log}" 2>&1

        # 2. Bring up GRE on VPS_B, install test-target route, capture t_start, drive curl, capture t_end.
        ssh_b "set -e
               /tmp/aegis-wide-helpers/aegis-gre-gateway-setup.sh apply --role=downstream \
                   --peer-ip=${VPS_A_HOST} \
                   --local-tip=${TUNNEL_DS_TIP}/30 \
                   --peer-tip=${TUNNEL_GW_TIP} 2>&1 | tail -4
               ip route add ${TEST_TARGET}/32 via ${TUNNEL_GW_TIP} dev aegis-gre0 2>&1
               T_START_MS=\$(date +%s%3N)
               echo \"T_START_MS=\${T_START_MS}\"
               echo '---DURING curl https://${TEST_TARGET}/ via GRE tunnel + VPS_A gateway---'
               timeout 12 curl -4 -sS --max-time 10 -o /tmp/gw-body \\
                    -w 'code=%{http_code} remote=%{remote_ip} time=%{time_total}s\n' \\
                    https://${TEST_TARGET}/ 2>&1 | tail -2
               T_END_MS=\$(date +%s%3N)
               echo \"T_END_MS=\${T_END_MS}\"
               echo '---response body (first 100b)---'
               head -c 100 /tmp/gw-body 2>/dev/null; echo
               ip route del ${TEST_TARGET}/32 via ${TUNNEL_GW_TIP} dev aegis-gre0 2>&1
               /tmp/aegis-wide-helpers/aegis-gre-gateway-setup.sh teardown 2>&1 | tail -2" \
            >> "${vb_log}" 2>&1

        # 3. Extract time window from VPS_B log
        t_start_ms=$(grep '^T_START_MS=' "${vb_log}" | tail -1 | cut -d= -f2)
        t_end_ms=$(grep '^T_END_MS=' "${vb_log}" | tail -1 | cut -d= -f2)
        curl_code=$(grep -oE 'code=[0-9]+' "${vb_log}" | head -1 | cut -d= -f2)
        curl_remote=$(grep -oE 'remote=[0-9.]+' "${vb_log}" | head -1 | cut -d= -f2)

        # 4. Pull TPROXY chain stats + time-window+target-filtered events.
        ssh_a "echo '---TPROXY chain hits (post-drill)---'
               iptables -t mangle -L AEGIS_WIDE_TPROXY -n -v | head -10
               echo '---target=${TEST_TARGET} events (no time filter)---'
               grep '\"target\":\"${TEST_TARGET}\"' /var/log/aegis-client/runtime-events.jsonl \\
                   | grep -oE '\"event_code\":\"[^\"]*\"' | sort | uniq -c | sort -rn
               echo '---target=${TEST_TARGET} events IN time window [${t_start_ms}, ${t_end_ms}]---'
               awk -v T0=${t_start_ms} -v T1=${t_end_ms} '
                   /\"target\":\"${TEST_TARGET}\"/ {
                       # "ts_unix_ms": is 13 chars (incl. opening quote, colon).
                       # Numeric value starts at RSTART+13, length = RLENGTH-13.
                       if (match(\$0, /\"ts_unix_ms\":[0-9]+/)) {
                           ts = substr(\$0, RSTART+13, RLENGTH-13)
                           if (ts+0 >= T0+0 && ts+0 <= T1+0+5000) {
                               # \"event_code\":\" is 14 chars (incl. open quote).
                               # Value starts at RSTART+14, length = RLENGTH-15
                               # (drops trailing closing quote).
                               if (match(\$0, /\"event_code\":\"[^\"]*\"/)) {
                                   ev = substr(\$0, RSTART+14, RLENGTH-15)
                                   print ev
                               }
                           }
                       }
                   }
               ' /var/log/aegis-client/runtime-events.jsonl | sort | uniq -c | sort -rn" \
            >> "${vb_log}" 2>&1

        # 5. Cleanup VPS_A side: disable wide, restore listen, teardown GRE
        ssh_a "/tmp/aegis-wide-helpers/aegis-wide-disable.sh >/dev/null 2>&1
               /tmp/aegis-wide-helpers/aegis-gre-gateway-setup.sh teardown >/dev/null 2>&1
               if [[ -f /etc/aegis/client/aegis.toml.tproxy-gateway.bak ]]; then
                   mv /etc/aegis/client/aegis.toml.tproxy-gateway.bak /etc/aegis/client/aegis.toml
                   systemctl restart aegis-client
               fi" >> "${gw_log}" 2>&1

        # 6. Verdict
        windowed_sess=$(grep -c "relay_session_succeeded" "${vb_log}" || echo 0)
        # Look at the last "IN time window" block specifically
        end_block=$(awk '/---target=.*events IN time window/,0' "${vb_log}")
        windowed_succ=$(echo "${end_block}" | grep -c "relay_session_succeeded" || true)
        windowed_brain=$(echo "${end_block}" | grep -c "brain_select_order_explained" || true)

        if [[ "${curl_remote}" == "${TEST_TARGET}" && "${curl_code}" =~ ^[2-5][0-9][0-9]$ && ${windowed_succ} -ge 1 ]]; then
            record_verdict tproxy_gateway PASS "downstream curl returned code=${curl_code} from remote=${curl_remote}; relay_session_succeeded for target=${TEST_TARGET} in time-window [${t_start_ms},${t_end_ms}]"
        elif [[ "${curl_remote}" == "${TEST_TARGET}" && "${curl_code}" =~ ^[2-5][0-9][0-9]$ ]]; then
            record_verdict tproxy_gateway PARTIAL "downstream curl reached target (code=${curl_code} remote=${curl_remote}) but windowed relay_session_succeeded not captured — see lane-tproxy-gateway-vps-b.txt"
        else
            record_verdict tproxy_gateway PARTIAL "downstream curl did not reach target (code=${curl_code:-none} remote=${curl_remote:-none}) — GRE / wide setup may have failed; see lane-tproxy-gateway-enable.txt"
        fi
    fi
else
    record_verdict tproxy_gateway SKIPPED ""
fi

# ---- lane: IPv6 policy ----
# Self-contained: bring up wide redirect mode with --ipv6=block, curl IPv6,
# tear down. Earlier versions implicitly inherited the block chain from
# whichever lane ran last with --ipv6=block; the tproxy_gateway lane
# rewrite explicitly tears its wide+GRE state down, so ipv6 lane must
# enable its own.
if ! skip_lane ipv6; then
    log "Lane: IPv6 block policy"
    ssh_a '/tmp/aegis-wide-helpers/aegis-wide-disable.sh >/dev/null 2>&1; sleep 1
           AEGIS_WIDE_ROLLBACK_SECS=900 /tmp/aegis-wide-helpers/aegis-wide-enable.sh -y \
               --mode=redirect --ssh-safe-ports=22 --dns=off --ipv6=block 2>&1 | tail -2
           touch /run/aegis-wide-confirmed
           sleep 1' >> "${ARTIFACT_DIR}/lane-ipv6.txt"
    out="$(ssh_a 'curl -6 -sS --max-time 6 https://[2606:4700:4700::1111]/cdn-cgi/trace 2>&1; echo "rc=$?"')"
    echo "${out}" >> "${ARTIFACT_DIR}/lane-ipv6.txt"
    ssh_a '/tmp/aegis-wide-helpers/aegis-wide-disable.sh >/dev/null 2>&1' >/dev/null 2>&1
    if echo "${out}" | grep -qE "rc=(6|7|28|56)|Could not resolve|connect.*[Ff]ail|operation not permitted|Network unreachable"; then
        record_verdict ipv6 PASS "IPv6 egress blocked (rc≠0)"
    else
        record_verdict ipv6 PARTIAL "IPv6 not blocked: $(echo "${out}" | tail -3 | head -1)"
    fi
else
    record_verdict ipv6 SKIPPED ""
fi

# ---- lane: disable wide + verify clean ----
log "Tearing down wide mode"
ssh_a '/tmp/aegis-wide-helpers/aegis-wide-disable.sh 2>&1 | tail -5
       echo "---post-disable nat OUTPUT---"
       iptables -t nat -L OUTPUT -n -v | head -5
       echo "---post-disable mangle PREROUTING---"
       iptables -t mangle -L PREROUTING -n -v | head -5
       echo "---post-disable ip rule---"
       ip rule show | grep fwmark || echo "(no fwmark rules — clean)"
       echo "---post-disable route table 100---"
       ip -4 route show table 100 2>&1 || echo "(empty)"
       echo "---curl direct after disable---"
       curl -4 -sS --max-time 6 https://1.1.1.1/cdn-cgi/trace 2>&1 | grep "^ip="
       # Restore SOCKS primary
       sed -i "s|^primary = \"wide\"|primary = \"socks5\"|" /etc/aegis/client/aegis.toml
       systemctl restart aegis-client' > "${ARTIFACT_DIR}/lane-disable-cleanup.txt"

# Stale rules check
stale=$(ssh_a 'for t in nat mangle filter; do
    iptables -t $t -L -n 2>/dev/null | grep -E "^Chain AEGIS_WIDE_" | grep -v "policy ACCEPT" || true
done')
if [[ -z "${stale}" ]]; then
    record_verdict cleanup PASS "no AEGIS_WIDE_* chains remain"
else
    record_verdict cleanup PARTIAL "stale chains: ${stale}"
fi

# ---- uninstall lane (default: SKIP unless explicitly requested) ----
# Hardened path: copy scripts/aegis-ubuntu-uninstall.sh to the host,
# run `purge`, capture output, then assert verify=PASS in the result.
# Refuses to record PASS unless verify=PASS is in the captured output.
if [[ ",${SKIP_LANES}," != *",uninstall,"* ]] && [[ "${RUN_UNINSTALL:-0}" == "1" ]]; then
    log "Lane: uninstall (RUN_UNINSTALL=1 acknowledged — destructive)"
    # Ship the uninstall helper to the remote.
    scp_a "${SCRIPT_DIR}/aegis-ubuntu-uninstall.sh" \
        root@"${VPS_A_SSH_ALIAS}":/tmp/aegis-ubuntu-uninstall.sh \
        >> "${COMMANDS_LOG}" 2>&1 || true
    out="$(ssh_a 'chmod +x /tmp/aegis-ubuntu-uninstall.sh
                  /tmp/aegis-ubuntu-uninstall.sh purge 2>&1
                  echo "---rc=$?---"')"
    echo "${out}" > "${ARTIFACT_DIR}/lane-uninstall.txt"
    if echo "${out}" | grep -q '^result=PASS$' && \
       echo "${out}" | grep -q '^verify=PASS '; then
        record_verdict uninstall PASS "client installation purge + scoped verification; identity and release-floor state retained"
    elif echo "${out}" | grep -q '^result=PASS_VACUOUS'; then
        record_verdict uninstall PASS "no client installation detected; scoped verification passed; identity and release-floor state retained"
    else
        leftover=$(echo "${out}" | grep -c '^verify=leftover ' || true)
        record_verdict uninstall PARTIAL "purge ran but ${leftover} leftover paths/units remain — see lane-uninstall.txt"
    fi
else
    record_verdict uninstall SKIPPED "default skip (set RUN_UNINSTALL=1 to enable)"
fi

# ---- AFTER state ----
log "Capturing AFTER state on VPS_A"
ssh_a 'echo "=== nat ==="; iptables -t nat -L -n -v | head -20
       echo "=== mangle ==="; iptables -t mangle -L -n -v | head -20
       echo "=== ip rule ==="; ip rule show
       echo "=== route table 100 ==="; ip -4 route show table 100
       echo "=== curl direct ==="; curl -4 -sS --max-time 6 https://1.1.1.1/cdn-cgi/trace 2>&1 | head -10' \
       > "${ARTIFACT_DIR}/state-AFTER.txt"

# ---- copy runtime-events.jsonl ----
log "Pulling runtime-events.jsonl"
scp_a root@"${VPS_A_SSH_ALIAS}":/var/log/aegis-client/runtime-events.jsonl \
    "${ARTIFACT_DIR}/runtime-events.jsonl" >> "${COMMANDS_LOG}" 2>&1 || \
    log "WARN: failed to fetch runtime-events"

# ---- aggregate result.json ----
log "Aggregating result.json"
{
    echo "{"
    echo "  \"artifact\": \"full-ubuntu-acceptance\","
    echo "  \"artifact_schema\": \"full_ubuntu_acceptance_v1\","
    echo "  \"created_at_utc\": \"$(date -u +%FT%TZ)\","
    echo "  \"orchestrator_script\": \"scripts/aegis-full-ubuntu-live-drill.sh\","
    echo "  \"vps_a_host\": \"${VPS_A_HOST}\","
    echo "  \"vps_b_host\": \"${VPS_B_HOST:-null}\","
    echo "  \"lanes\": {"
    first=1
    for lane in socks transport_matrix brain redirect_wide dns_off dns_preview tproxy_gateway ipv6 cleanup uninstall; do
        [[ ${first} -eq 1 ]] && first=0 || echo ","
        verdict="${VERDICT[$lane]:-NOT_RUN}"
        reason="${REASON[$lane]:-}"
        # Escape quotes in reason
        reason="${reason//\"/\\\"}"
        printf '    "%s": { "status": "%s", "reason": "%s" }' "${lane}" "${verdict}" "${reason}"
    done
    echo ""
    echo "  }"
    echo "}"
} > "${ARTIFACT_DIR}/result.json"

# ---- summary.md ----
{
    echo "# Full Ubuntu acceptance run — $(date -u +%F)"
    echo
    echo "VPS_A: ${VPS_A_HOST}"
    echo "VPS_B: ${VPS_B_HOST:-(not provided — gateway lane SKIPPED)}"
    echo
    echo "## Lane verdicts"
    echo
    printf "| Lane | Status | Reason |\n"
    printf "|---|---|---|\n"
    for lane in socks transport_matrix brain redirect_wide dns_off dns_preview tproxy_gateway ipv6 cleanup uninstall; do
        printf "| %s | %s | %s |\n" "${lane}" "${VERDICT[$lane]:-NOT_RUN}" "${REASON[$lane]:-}"
    done
    echo
    echo "## Files"
    echo "- result.json — machine-readable verdicts"
    echo "- summary.md — this file"
    echo "- commands.log — orchestrator timing log"
    echo "- state-BEFORE.txt / state-AFTER.txt — VPS_A iptables/routes/curl snapshots"
    echo "- lane-*.txt — per-lane evidence"
    echo "- runtime-events.jsonl — aegis-client runtime events from this drill"
} > "${ARTIFACT_DIR}/summary.md"

# ---- print final summary ----
log "DRILL COMPLETE"
log "Artifact: ${ARTIFACT_DIR}"
echo
echo "===== FINAL SUMMARY ====="
cat "${ARTIFACT_DIR}/summary.md"
