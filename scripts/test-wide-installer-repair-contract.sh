#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

require_contains() {
  local file="$1"
  local needle="$2"
  if ! grep -Fq -- "$needle" "$file"; then
    echo "expected ${file} to contain: ${needle}" >&2
    exit 1
  fi
}

require_not_contains() {
  local file="$1"
  local needle="$2"
  if grep -Fq -- "$needle" "$file"; then
    echo "expected ${file} not to contain: ${needle}" >&2
    exit 1
  fi
}

require_no_live_source_verdict() {
  local file="$1"
  local verdict="$2"
  if grep -F -- "$verdict" "$file" | grep -Fv 'contains(' >/dev/null; then
    echo "expected ${file} not to emit old verdict: ${verdict}" >&2
    exit 1
  fi
}

# Regression: the release installer previously installed only the low-level
# REDIRECT helper, then enabled DNS preview through UDP NAT REDIRECT. That path
# is known to lose the DNS original-destination and can blackhole name
# resolution. Turnkey redirect+DNS-preview must go through aegis-wide-enable.sh,
# which installs fake-IP resolver DNS and SSH/rollback guardrails.
require_contains "${ROOT}/install.sh" 'aegis-wide-enable.sh'
require_contains "${ROOT}/install.sh" 'aegis-wide-disable.sh'
require_contains "${ROOT}/install.sh" 'aegis-wide-persist-install.sh'
require_contains "${ROOT}/install.sh" 'for wrapper_script in aegis-wide-enable.sh aegis-wide-disable.sh aegis-wide-persist-install.sh janitor-wide-linux-tproxy.sh'
require_contains "${ROOT}/install.sh" 'used_wrapper=1'
require_contains "${ROOT}/install.sh" '--dns=preview'
require_contains "${ROOT}/install.sh" 'touch /run/aegis-wide-confirmed'
require_contains "${ROOT}/install.sh" '"${backend}" != "linux_redirect"'
require_contains "${ROOT}/install.sh" 'pin_relay_server_to_resolved_ipv4'
require_contains "${ROOT}/install.sh" 'server_name remains the TLS/HTTP authority'
require_contains "${ROOT}/install.sh" 'refusing full-wide activation with an unpinned relay endpoint'
require_contains "${ROOT}/install.sh" 'relay endpoint pinning failed; refusing capture activation.'
require_contains "${ROOT}/install.sh" 'Fallback SOCKS mode restored in client config.'
require_contains "${ROOT}/install.sh" 'aborting: a requested system service is not active.'
require_contains "${ROOT}/install.sh" 'systemctl restart "${unit_name}"'
require_contains "${ROOT}/install.sh" 'requested full/wide capture did not activate; the install is incomplete. Check the rollback messages and host networking before retrying.'
require_not_contains "${ROOT}/install.sh" 'WARN: wide capture not active; client still installed (SOCKS/relay usable).'
require_contains "${ROOT}/scripts/aegis-wide-enable.sh" 'dns_preview_listen'
require_contains "${ROOT}/scripts/aegis-wide-enable.sh" '127.0.0.1:53'
require_contains "${ROOT}/scripts/aegis-wide-enable.sh" 'nameserver 127.0.0.1'

# --udp-carry: generic v4 UDP (incl QUIC/443) carry over the UDP relay plan. Must set
# the generic_capture_unstable contract (so the daemon spawns the redirect proxy)
# AND propagate AEGIS_WIDE_UDP_REDIRECT_PORT into the apply path (so the firewall
# REDIRECTs UDP to the proxy instead of REJECT-ing it). Only the linux_redirect
# backend runs the proxy — other backends must warn, not silently promise carry.
require_contains "${ROOT}/install.sh" '--udp-carry'
require_contains "${ROOT}/install.sh" 'set_client_config_udp_contract'
require_contains "${ROOT}/install.sh" 'udp_transport_priority'
require_contains "${ROOT}/install.sh" '["masque_derived", "grpc_datagram"]'
require_contains "${ROOT}/install.sh" "setk(nb, 'masque_server_name', host)"
require_contains "${ROOT}/install.sh" '"${BUNDLE_PATH}/masque-ca.pem"'
require_contains "${ROOT}/install.sh" 'using bundled masque-ca.pem for the direct UDP leg.'
require_contains "${ROOT}/install.sh" 'generic_capture_unstable'
require_contains "${ROOT}/install.sh" 'AEGIS_WIDE_UDP_REDIRECT_PORT="${udp_redirect_port}"'
require_contains "${ROOT}/scripts/aegis-wide-enable.sh" 'AEGIS_WIDE_UDP_REDIRECT_PORT'

full_wide_validate="$(AEGIS_INSTALL_VALIDATE_MODE_ONLY=1 bash "${ROOT}/install.sh" client --profile full-wide-tun 2>/dev/null)"
grep -Fq 'udp_carry=1' <<<"${full_wide_validate}" || {
  echo "full-wide-tun must enable UDP carry without an extra --udp-carry flag" >&2
  exit 1
}

# Geneva hybrid reuses the proven full-wide TUN lifecycle but must render an
# explicit Auto/Geneva-only runtime contract before systemd is started.
require_contains "${ROOT}/install.sh" 'full-wide-hybrid-geneva'
require_contains "${ROOT}/install.sh" 'set_client_config_hybrid_geneva'
require_contains "${ROOT}/install.sh" 'set_section_value("direct", "hybrid_geneva", "true")'
require_contains "${ROOT}/install.sh" 'set_section_value("relay", "transport_priority", '\''["grpc_stream"]'\'')'
require_contains "${ROOT}/install.sh" 'PRIVACY DISCLOSURE: the access network sees each direct IPv4 destination IP.'

# DNS turnkey on the tun/direct path: the fake-IP listener must bind :53 (not the
# wide TCP port), and install.sh must tell the low-level redirect helper to repoint
# resolv.conf (AEGIS_WIDE_MANAGE_RESOLV) — otherwise the fake-IP server is silently
# bypassed (queries hit systemd-resolved) and DNS-under-wide only "works" by leaking
# real resolution. The wrapper path keeps its own resolv.conf handling and must NOT
# also get MANAGE_RESOLV (double-management).
require_contains "${ROOT}/install.sh" 'set_client_dns_preview "$cfg" "127.0.0.1:53"'
require_contains "${ROOT}/install.sh" 'AEGIS_WIDE_MANAGE_RESOLV="${k_dns_preview}"'
require_contains "${ROOT}/scripts/setup-wide-linux-redirect.sh" 'MANAGE_RESOLV'
require_contains "${ROOT}/scripts/setup-wide-linux-redirect.sh" 'nameserver 127.0.0.1'
require_contains "${ROOT}/scripts/setup-wide-linux-redirect.sh" 'aegis_root_resolver_preflight'
require_contains "${ROOT}/scripts/lib/root-state.sh" 'resolver-save --path "$legacy"'
require_contains "${ROOT}/scripts/setup-wide-linux-redirect.sh" 'managed_resolv=0'
require_contains "${ROOT}/scripts/setup-wide-linux-redirect.sh" 'aegis_root_resolver_restore'
require_contains "${ROOT}/scripts/setup-wide-linux-redirect.sh" 'NETWORKMANAGER_DNS_CONF="/run/NetworkManager/conf.d/90-aegis-wide-dns.conf"'
require_contains "${ROOT}/scripts/setup-wide-linux-redirect.sh" 'networkmanager_dns_hold'
require_contains "${ROOT}/scripts/setup-wide-linux-redirect.sh" 'dns=none'
require_contains "${ROOT}/scripts/setup-wide-linux-redirect.sh" 'networkmanager_dns_release'
require_contains "${ROOT}/scripts/aegis-wide-disable.sh" 'aegis_root_resolver_restore'
require_contains "${ROOT}/scripts/aegis-wide-disable.sh" '/run/NetworkManager/conf.d/90-aegis-wide-dns.conf'
require_contains "${ROOT}/scripts/purge-installed-aegis.sh" '/run/NetworkManager/conf.d/90-aegis-wide-dns.conf'
require_contains "${ROOT}/scripts/aegis-ubuntu-uninstall.sh" '/run/NetworkManager/conf.d/90-aegis-wide-dns.conf'
require_contains "${ROOT}/scripts/aegis-wide-disable.sh" 'systemctl start --no-block systemd-resolved'
require_contains "${ROOT}/scripts/aegis-wide-enable.sh" 'aegis_root_network_preflight'
require_contains "${ROOT}/scripts/aegis-wide-enable.sh" 'aegis_root_resolver_restore'

# The backup must happen before stopping systemd-resolved. Otherwise Ubuntu's
# /run-backed resolv.conf symlink becomes broken and `-e` skips the backup,
# leaving DNS dead after an otherwise successful capture teardown.
python3 - "${ROOT}/scripts/setup-wide-linux-redirect.sh" "${ROOT}/scripts/aegis-wide-enable.sh" <<'PY'
import sys
from pathlib import Path

for path_arg in sys.argv[1:]:
    path = Path(path_arg)
    text = path.read_text(encoding="utf-8")
    backup = text.index("aegis_root_resolver_save")
    stop = text.index("systemctl stop systemd-resolved", backup)
    if backup >= stop:
        raise SystemExit(f"resolver backup must precede systemd-resolved stop in {path}")
PY

# Capture-root: full-wide-tun runs the client as root, so "exempt all uid 0" would
# leak every root daemon's traffic. Strict TUN activation uses the verified
# service cgroup; compatibility modes retain their existing helper arguments.
require_contains "${ROOT}/scripts/setup-wide-linux-redirect.sh" 'CAPTURE_ROOT'
require_contains "${ROOT}/install.sh" 'AEGIS_WIDE_REQUIRE_CGROUP=1 AEGIS_WIDE_EXEMPT_SERVICE="$exempt_service"'
require_contains "${ROOT}/install.sh" 'bash "$persisted" cgroup-path'
require_contains "${ROOT}/scripts/setup-wide-linux-redirect.sh" 'add_relay_exclude_returns'
require_contains "${ROOT}/install.sh" 'AEGIS_WIDE_CAPTURE_ROOT="${capture_root}"'
require_contains "${ROOT}/install.sh" 'AEGIS_WIDE_RELAY_EXCLUDE_IPS="${relay_exclude_ips}"'
require_contains "${ROOT}/install.sh" 'AEGIS_HYBRID_DIRECT_SOCKET_MARK=44641'
require_contains "${ROOT}/install.sh" 'AEGIS_DIRECT_SOCKET_MARK="${direct_socket_mark}"'
require_contains "${ROOT}/install.sh" 'removed stale 20-ipv6-tun.conf'
require_contains "${ROOT}/install.sh" 'restart_systemd_unit_checked()'
require_contains "${ROOT}/install.sh" 'systemctl reset-failed "${unit_name}"'
require_contains "${ROOT}/install.sh" 'did not restart with the rendered wide config; refusing capture activation'
require_contains "${ROOT}/scripts/setup-wide-linux-redirect.sh" 'DIRECT_SOCKET_MARK'
require_contains "${ROOT}/aegis-core/src/socket_mark.rs" 'libc::SO_MARK'

# Reboot-persistence: every safe wide product must install a boot unit only
# after its live egress/DNS probes pass. full-wide-tun keeps the specialised
# unit; redirect/TPROXY profiles use the generic wrapper-backed unit. A manual
# disable must remove both so capture cannot silently return after opt-out.
require_contains "${ROOT}/install.sh" 'install_wide_tun_boot_unit'
require_contains "${ROOT}/install.sh" 'aegis-wide-tun-firewall.service'
require_contains "${ROOT}/install.sh" 'systemctl reset-failed aegis-wide-tun-firewall.service'
require_contains "${ROOT}/install.sh" 'PartOf=aegis-client.service'
require_contains "${ROOT}/install.sh" 'WantedBy=multi-user.target aegis-client.service'
require_contains "${ROOT}/install.sh" 'systemctl enable --now aegis-wide-tun-firewall.service'
require_contains "${ROOT}/install.sh" 'systemctl is-active --quiet aegis-wide-tun-firewall.service'
require_contains "${ROOT}/install.sh" 'full-wide-tun capture persistence failed; capture is removed and the independent guard is retained.'
require_contains "${ROOT}/install.sh" 'install_wide_profile_boot_unit'
require_contains "${ROOT}/install.sh" 'aegis-wide.service'
require_contains "${ROOT}/install.sh" 'wide reboot persistence failed; tearing down rather than leaving a reboot-fail-open install.'
require_contains "${ROOT}/install.sh" 'deactivate_existing_wide_boot_units'
require_contains "${ROOT}/scripts/aegis-wide-disable.sh" 'aegis-wide-tun-firewall.service'
require_contains "${ROOT}/scripts/aegis-wide-disable.sh" 'AEGIS_WIDE_DISABLE_FROM_UNIT'
require_contains "${ROOT}/scripts/aegis-wide-disable.sh" 'aegis-wide.service'
# The boot-unit removal must be UNCONDITIONAL: a `list-unit-files | grep -q` guard
# is skipped under `set -o pipefail` (grep -q SIGPIPEs the producer -> pipeline
# fails -> guard false), silently leaving the unit so wide re-applies after opt-out.
require_not_contains "${ROOT}/scripts/aegis-wide-disable.sh" "list-unit-files 2>/dev/null | grep -q '^aegis-wide-tun-firewall"
require_contains "${ROOT}/scripts/setup-wide-linux-redirect.sh" 'restored /etc/resolv.conf'
require_contains "${ROOT}/scripts/setup-wide-linux-redirect.sh" 'systemctl start --no-block systemd-resolved'
require_contains "${ROOT}/scripts/setup-wide-linux-redirect.sh" 'delete_parent_jumps iptables nat OUTPUT "${OUTPUT_CHAIN}"'
require_contains "${ROOT}/scripts/setup-wide-linux-redirect.sh" 'delete_parent_jumps iptables nat PREROUTING "${PREROUTING_CHAIN}"'

# Regression: redirect-family systemd drop-in runs aegis-client as a dedicated uid.
# The client config + ca.pem must be chowned to that uid, else every relay transport
# fails with `open ca_cert`.
require_contains "${ROOT}/install.sh" 'local config_path="$1" ca_path="$2"'
require_contains "${ROOT}/install.sh" 'chown "root:${svc}" "${config_root}" "${config_path}"'
require_contains "${ROOT}/install.sh" 'chown "root:${svc}" "${ca_path}"'
require_contains "${ROOT}/install.sh" 'chmod 0640 "${ca_path}"'

# Regression (login-user collision): wide loop-avoidance EXEMPTS the client's uid
# from capture. If the machine's login user is literally named 'aegis' (uid >= 1000)
# the installer must NOT run the wide client as that account — else the operator's
# own apps bypass the tunnel (native IP; foreign sites blocked) and a broken
# activation can take the box off the network. install.sh must resolve a dedicated
# SYSTEM account (fallback 'aegis-svc'); aegis-wide-enable.sh must honor the
# passed uid and REFUSE to exempt a uid >= 1000.
require_contains "${ROOT}/install.sh" 'resolve_wide_client_service_user() {'
require_contains "${ROOT}/install.sh" 'svc=aegis-svc'
require_contains "${ROOT}/install.sh" 'User=${svc}'
require_contains "${ROOT}/scripts/aegis-wide-enable.sh" 'AEGIS_UID="${AEGIS_EXEMPT_UID:-$(detect_aegis_uid)}"'
require_contains "${ROOT}/scripts/aegis-wide-enable.sh" 'refusing to exempt uid'
require_contains "${ROOT}/scripts/aegis-wide-enable.sh" 'systemctl show aegis-client.service -p User --value'

# Regression (config ownership reset by wide activation): rewriting the client
# config for dns-preview does an atomic `mv` (→ root-owned), so it must be
# re-owned to the uid the service ACTUALLY runs as — NOT a hardcoded `aegis`,
# which on a dedicated-uid (aegis-svc) install left the config root-owned and
# crash-looped the client (`load config … Permission denied`) so wide never came
# up. aegis-wide-enable.sh chowns to ${AEGIS_UID}; install.sh re-owns after
# activate_wide_capture as a belt-and-suspenders for the non-wrapper path.
require_contains "${ROOT}/scripts/aegis-wide-enable.sh" 'chown "root:${aegis_wide_config_group}" "${config_file}" || return 1'
require_contains "${ROOT}/scripts/aegis-wide-enable.sh" 'chmod "${aegis_wide_config_mode}" "${config_file}" || return 1'
require_contains "${ROOT}/scripts/aegis-wide-enable.sh" 'aegis_root_state write --path "${config_file}" --preserve-mode'
require_not_contains "${ROOT}/scripts/aegis-wide-enable.sh" 'chown aegis:aegis "${config_file}"'
require_contains "${ROOT}/install.sh" 'chown "root:${_wsvc}" "${config_path}"'

# Regression (wide->socks downgrade residue): a socks-only / tproxy reinstall on a
# host that previously ran a redirect-family wide install must purge the stale
# 10-dedicated-uid.conf drop-in (User=aegis) — otherwise the root-owned socks
# config crash-loops the service with `load config … Permission denied`. The
# post-service dispatch must have a default arm that removes it; only
# redirect-family installs (re)create it (full-wide-tun purges it itself).
require_contains "${ROOT}/install.sh" 'remove_client_dedicated_uid_dropin() {'
require_contains "${ROOT}/install.sh" 'removed stale 10-dedicated-uid.conf (root-runtime profile reads its root-owned config directly).'
require_contains "${ROOT}/install.sh" '      remove_client_dedicated_uid_dropin'

# Regression: `operator apply --apply-confirm` printed applied=true while it
# only rendered an auditable plan. Keep that honest until a real mutation backend
# is implemented in the operator command itself.
require_contains "${ROOT}/aegis-client/src/operator.rs" 'APPLY_PLAN_READY'
require_contains "${ROOT}/aegis-client/src/operator.rs" 'ROLLBACK_PLAN_READY'
require_no_live_source_verdict "${ROOT}/aegis-client/src/operator.rs" '"APPLY_READY"'
require_no_live_source_verdict "${ROOT}/aegis-client/src/operator.rs" '"ROLLBACK_READY"'

# Release/package builders must include the wrappers, otherwise fresh installs
# from the public tarball fail even though source-tree installs pass.
for file in \
  "${ROOT}/scripts/build-release-bundle.sh" \
  "${ROOT}/scripts/build-package-root.sh" \
  "${ROOT}/scripts/build-split-deb-packages.sh" \
  "${ROOT}/scripts/test-installer-user-flow-contract.sh" \
  "${ROOT}/scripts/test-bootstrap-install-contract.sh" \
  "${ROOT}/scripts/test-release-bundle-contract.sh" \
  "${ROOT}/scripts/test-package-root-contract.sh"; do
  require_contains "$file" 'aegis-wide-enable.sh'
  require_contains "$file" 'aegis-wide-disable.sh'
  require_contains "$file" 'aegis-wide-persist-install.sh'
  require_contains "$file" 'janitor-wide-linux-tproxy.sh'
done

echo "PASS: wide installer repair contract"
