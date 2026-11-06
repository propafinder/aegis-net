#!/usr/bin/env bash
# Contract self-test for installed AEGIS purge helper.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/purge-installed-aegis.sh"
tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/aegis-purge-contract.XXXXXX")"
tmpdir="$(cd "${tmpdir}" && pwd -P)"
trap 'rm -rf "${tmpdir}"' EXIT
mkdir -p "${tmpdir}/runtime-tmp"
export AEGIS_PURGE_TMPDIR="${tmpdir}/runtime-tmp"

make_stub_bin() {
  local bindir="$1"
  local log_file="$2"
  mkdir -p "${bindir}"

  cat > "${bindir}/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'systemctl %s\n' "$*" >> "${AEGIS_PURGE_TEST_LOG:?}"
exit 0
EOF
  chmod +x "${bindir}/systemctl"

  for tool in iptables ip6tables nft ip pkill userdel groupdel; do
    cat > "${bindir}/${tool}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s %s\n' "$(basename "$0")" "$*" >> "${AEGIS_PURGE_TEST_LOG:?}"
exit 0
EOF
    chmod +x "${bindir}/${tool}"
  done
}

seed_fake_install_root() {
  local fake_root="$1"
  mkdir -p \
    "${fake_root}/usr/local/bin" \
    "${fake_root}/usr/local/lib/aegis/helpers" \
    "${fake_root}/etc/systemd/system/aegis-client.service.d" \
    "${fake_root}/usr/lib/systemd/system/aegis-client.service.d" \
    "${fake_root}/usr/lib/systemd/system-preset" \
    "${fake_root}/usr/lib/sysusers.d" \
    "${fake_root}/usr/lib/tmpfiles.d" \
    "${fake_root}/usr/share/aegis" \
    "${fake_root}/etc/default" \
    "${fake_root}/etc/aegis/server" \
    "${fake_root}/etc/aegis/client" \
    "${fake_root}/var/lib/aegis-server" \
    "${fake_root}/var/lib/aegis-client" \
    "${fake_root}/var/lib/aegis-install/auto-client" \
    "${fake_root}/var/log/aegis-client"

  touch \
    "${fake_root}/usr/local/bin/aegis-server" \
    "${fake_root}/usr/local/bin/aegis-client" \
    "${fake_root}/usr/local/lib/aegis/helpers/setup-wide-linux-tproxy.sh" \
    "${fake_root}/etc/systemd/system/aegis-server.service" \
    "${fake_root}/etc/systemd/system/aegis-client.service" \
    "${fake_root}/etc/systemd/system/aegis-client.service.d/10-dedicated-uid.conf" \
    "${fake_root}/usr/lib/systemd/system/aegis-client.service.d/20-ipv6-tun.conf" \
    "${fake_root}/etc/systemd/system/aegis-wide.service" \
    "${fake_root}/etc/systemd/system/aegis-wide-tun-firewall.service" \
    "${fake_root}/usr/lib/systemd/system-preset/90-aegis.preset" \
    "${fake_root}/usr/lib/systemd/system-preset/90-aegis-server.preset" \
    "${fake_root}/usr/lib/systemd/system-preset/90-aegis-client.preset" \
    "${fake_root}/usr/lib/sysusers.d/aegis-server.conf" \
    "${fake_root}/usr/lib/tmpfiles.d/aegis-server.conf" \
    "${fake_root}/usr/lib/tmpfiles.d/aegis-client.conf" \
    "${fake_root}/etc/default/aegis-server" \
    "${fake_root}/etc/default/aegis-client" \
    "${fake_root}/etc/aegis/server/aegis-server.toml" \
    "${fake_root}/etc/aegis/client/aegis.toml" \
    "${fake_root}/var/lib/aegis-server/state" \
    "${fake_root}/var/lib/aegis-client/state" \
    "${fake_root}/var/lib/aegis-install/auto-client/wide-profile.json" \
    "${fake_root}/var/log/aegis-client/runtime-events.jsonl"
  touch "${fake_root}/usr/share/aegis/shared-artifact"
}

require_file_contains() {
  local file="$1"
  local expected="$2"
  if ! grep -Fq -- "${expected}" "${file}"; then
    echo "expected ${file} to contain: ${expected}" >&2
    echo "--- ${file} ---" >&2
    cat "${file}" >&2
    exit 1
  fi
}

require_path_exists() {
  local path="$1"
  if [[ ! -e "${path}" ]]; then
    echo "expected path to exist: ${path}" >&2
    exit 1
  fi
}

reject_path_exists() {
  local path="$1"
  if [[ -e "${path}" ]]; then
    echo "expected path to be removed: ${path}" >&2
    exit 1
  fi
}

run_dry_run_case() {
  local case_dir="${tmpdir}/dry-run"
  local fake_root="${case_dir}/root"
  local bindir="${case_dir}/bin"
  local log_file="${case_dir}/commands.log"

  mkdir -p "${case_dir}"
  make_stub_bin "${bindir}" "${log_file}"
  seed_fake_install_root "${fake_root}"

  env \
    AEGIS_PURGE_ROOT="${fake_root}" \
    AEGIS_PURGE_SYSTEMCTL_BIN="${bindir}/systemctl" \
    AEGIS_PURGE_IPTABLES_BIN="${bindir}/iptables" \
    AEGIS_PURGE_IP6TABLES_BIN="${bindir}/ip6tables" \
    AEGIS_PURGE_NFT_BIN="${bindir}/nft" \
    AEGIS_PURGE_IP_BIN="${bindir}/ip" \
    AEGIS_PURGE_PKILL_BIN="${bindir}/pkill" \
    AEGIS_PURGE_USERDEL_BIN="${bindir}/userdel" \
    AEGIS_PURGE_GROUPDEL_BIN="${bindir}/groupdel" \
    AEGIS_PURGE_TEST_LOG="${log_file}" \
    /bin/bash "${SCRIPT}" all > "${case_dir}/stdout.txt"

  require_file_contains "${case_dir}/stdout.txt" "mode: dry-run"
  require_path_exists "${fake_root}/usr/local/bin/aegis-server"
  require_path_exists "${fake_root}/usr/local/bin/aegis-client"
  require_path_exists "${fake_root}/usr/local/lib/aegis/helpers/setup-wide-linux-tproxy.sh"
  require_path_exists "${fake_root}/etc/aegis/server/aegis-server.toml"
  require_path_exists "${fake_root}/etc/aegis/client/aegis.toml"
}

run_force_case() {
  local case_dir="${tmpdir}/force"
  local fake_root="${case_dir}/root"
  local bindir="${case_dir}/bin"
  local log_file="${case_dir}/commands.log"

  mkdir -p "${case_dir}"
  make_stub_bin "${bindir}" "${log_file}"
  seed_fake_install_root "${fake_root}"

  env \
    AEGIS_PURGE_ROOT="${fake_root}" \
    AEGIS_PURGE_SYSTEMCTL_BIN="${bindir}/systemctl" \
    AEGIS_PURGE_IPTABLES_BIN="${bindir}/iptables" \
    AEGIS_PURGE_IP6TABLES_BIN="${bindir}/ip6tables" \
    AEGIS_PURGE_NFT_BIN="${bindir}/nft" \
    AEGIS_PURGE_IP_BIN="${bindir}/ip" \
    AEGIS_PURGE_PKILL_BIN="${bindir}/pkill" \
    AEGIS_PURGE_USERDEL_BIN="${bindir}/userdel" \
    AEGIS_PURGE_GROUPDEL_BIN="${bindir}/groupdel" \
    AEGIS_PURGE_TEST_LOG="${log_file}" \
    /bin/bash "${SCRIPT}" all --force > "${case_dir}/stdout.txt"

  require_file_contains "${case_dir}/stdout.txt" "mode: destructive purge"
  reject_path_exists "${fake_root}/usr/local/bin/aegis-server"
  reject_path_exists "${fake_root}/usr/local/bin/aegis-client"
  reject_path_exists "${fake_root}/usr/local/lib/aegis"
  reject_path_exists "${fake_root}/etc/systemd/system/aegis-client.service.d"
  reject_path_exists "${fake_root}/usr/lib/systemd/system/aegis-client.service.d"
  reject_path_exists "${fake_root}/etc/systemd/system/aegis-wide.service"
  reject_path_exists "${fake_root}/etc/systemd/system/aegis-wide-tun-firewall.service"
  reject_path_exists "${fake_root}/usr/lib/sysusers.d/aegis-server.conf"
  reject_path_exists "${fake_root}/usr/lib/tmpfiles.d/aegis-server.conf"
  reject_path_exists "${fake_root}/usr/lib/tmpfiles.d/aegis-client.conf"
  reject_path_exists "${fake_root}/etc/aegis"
  reject_path_exists "${fake_root}/var/lib/aegis-server"
  reject_path_exists "${fake_root}/var/lib/aegis-client"
  reject_path_exists "${fake_root}/var/log/aegis-client"
  require_file_contains "${log_file}" "systemctl stop aegis-server.service"
  require_file_contains "${log_file}" "systemctl stop aegis-client.service"
  require_file_contains "${log_file}" "systemctl stop aegis-wide.service"
  require_file_contains "${log_file}" "systemctl stop aegis-wide-tun-firewall.service"
  require_file_contains "${log_file}" "iptables -t nat -F AEGIS_WIDE_OUTPUT"
  require_file_contains "${log_file}" "ip rule del fwmark 1 lookup 100"
}

run_client_only_case() {
  local case_dir="${tmpdir}/client-only"
  local fake_root="${case_dir}/root"
  local bindir="${case_dir}/bin"
  local log_file="${case_dir}/commands.log"

  mkdir -p "${case_dir}"
  make_stub_bin "${bindir}" "${log_file}"
  seed_fake_install_root "${fake_root}"

  env \
    AEGIS_PURGE_ROOT="${fake_root}" \
    AEGIS_PURGE_SYSTEMCTL_BIN="${bindir}/systemctl" \
    AEGIS_PURGE_IPTABLES_BIN="${bindir}/iptables" \
    AEGIS_PURGE_IP6TABLES_BIN="${bindir}/ip6tables" \
    AEGIS_PURGE_NFT_BIN="${bindir}/nft" \
    AEGIS_PURGE_IP_BIN="${bindir}/ip" \
    AEGIS_PURGE_PKILL_BIN="${bindir}/pkill" \
    AEGIS_PURGE_USERDEL_BIN="${bindir}/userdel" \
    AEGIS_PURGE_GROUPDEL_BIN="${bindir}/groupdel" \
    AEGIS_PURGE_TEST_LOG="${log_file}" \
    /bin/bash "${SCRIPT}" client --force > "${case_dir}/stdout.txt"

  reject_path_exists "${fake_root}/usr/local/bin/aegis-client"
  reject_path_exists "${fake_root}/var/lib/aegis-install/auto-client"
  reject_path_exists "${fake_root}/usr/lib/tmpfiles.d/aegis-client.conf"
  require_path_exists "${fake_root}/usr/local/bin/aegis-server"
  require_path_exists "${fake_root}/etc/aegis/server/aegis-server.toml"
  require_path_exists "${fake_root}/usr/lib/sysusers.d/aegis-server.conf"
  require_path_exists "${fake_root}/usr/lib/tmpfiles.d/aegis-server.conf"
  require_path_exists "${fake_root}/usr/share/aegis/shared-artifact"
}

run_server_only_case() {
  local case_dir="${tmpdir}/server-only"
  local fake_root="${case_dir}/root"
  local bindir="${case_dir}/bin"
  local log_file="${case_dir}/commands.log"

  mkdir -p "${case_dir}"
  make_stub_bin "${bindir}" "${log_file}"
  seed_fake_install_root "${fake_root}"

  env \
    AEGIS_PURGE_ROOT="${fake_root}" \
    AEGIS_PURGE_SYSTEMCTL_BIN="${bindir}/systemctl" \
    AEGIS_PURGE_IPTABLES_BIN="${bindir}/iptables" \
    AEGIS_PURGE_IP6TABLES_BIN="${bindir}/ip6tables" \
    AEGIS_PURGE_NFT_BIN="${bindir}/nft" \
    AEGIS_PURGE_IP_BIN="${bindir}/ip" \
    AEGIS_PURGE_PKILL_BIN="${bindir}/pkill" \
    AEGIS_PURGE_USERDEL_BIN="${bindir}/userdel" \
    AEGIS_PURGE_GROUPDEL_BIN="${bindir}/groupdel" \
    AEGIS_PURGE_TEST_LOG="${log_file}" \
    /bin/bash "${SCRIPT}" server --force > "${case_dir}/stdout.txt"

  reject_path_exists "${fake_root}/usr/local/bin/aegis-server"
  reject_path_exists "${fake_root}/usr/lib/sysusers.d/aegis-server.conf"
  reject_path_exists "${fake_root}/usr/lib/tmpfiles.d/aegis-server.conf"
  require_path_exists "${fake_root}/usr/local/bin/aegis-client"
  require_path_exists "${fake_root}/etc/aegis/client/aegis.toml"
  require_path_exists "${fake_root}/usr/lib/tmpfiles.d/aegis-client.conf"
  require_path_exists "${fake_root}/usr/share/aegis/shared-artifact"
}

run_last_role_removes_shared_case() {
  local case_dir="${tmpdir}/last-role"
  local fake_root="${case_dir}/root"
  local bindir="${case_dir}/bin"
  local log_file="${case_dir}/commands.log"

  mkdir -p "${case_dir}"
  make_stub_bin "${bindir}" "${log_file}"
  seed_fake_install_root "${fake_root}"
  rm -rf \
    "${fake_root}/usr/local/bin/aegis-server" \
    "${fake_root}/etc/systemd/system/aegis-server.service" \
    "${fake_root}/etc/aegis/server"

  env \
    AEGIS_PURGE_ROOT="${fake_root}" \
    AEGIS_PURGE_SYSTEMCTL_BIN="${bindir}/systemctl" \
    AEGIS_PURGE_IPTABLES_BIN="${bindir}/iptables" \
    AEGIS_PURGE_IP6TABLES_BIN="${bindir}/ip6tables" \
    AEGIS_PURGE_NFT_BIN="${bindir}/nft" \
    AEGIS_PURGE_IP_BIN="${bindir}/ip" \
    AEGIS_PURGE_PKILL_BIN="${bindir}/pkill" \
    AEGIS_PURGE_USERDEL_BIN="${bindir}/userdel" \
    AEGIS_PURGE_GROUPDEL_BIN="${bindir}/groupdel" \
    AEGIS_PURGE_TEST_LOG="${log_file}" \
    /bin/bash "${SCRIPT}" client --force > "${case_dir}/stdout.txt"

  reject_path_exists "${fake_root}/usr/share/aegis"
  reject_path_exists "${fake_root}/usr/lib/systemd/system-preset/90-aegis.preset"
}

run_preserve_installer_input_case() {
  local case_dir="${tmpdir}/preserve-installer-input"
  local fake_root="${case_dir}/root"
  local bindir="${case_dir}/bin"
  local log_file="${case_dir}/commands.log"
  local runtime_tmp="${case_dir}/runtime-tmp"
  local preserved_parent=""
  local preserved_bundle=""
  local stale_client_tmp=""

  mkdir -p "${case_dir}" "${runtime_tmp}"
  make_stub_bin "${bindir}" "${log_file}"
  seed_fake_install_root "${fake_root}"
  preserved_parent="$(mktemp -d "${runtime_tmp}/aegis-client-bundle.XXXXXX")"
  preserved_bundle="${preserved_parent}/extracted/client-bundle"
  stale_client_tmp="$(mktemp -d "${runtime_tmp}/aegis-client-stale.XXXXXX")"
  mkdir -p "${preserved_bundle}"
  printf '%s\n' 'must-survive-purge' >"${preserved_bundle}/ca.pem"
  printf '%s\n' 'must-be-removed' >"${stale_client_tmp}/stale"

  env \
    AEGIS_PURGE_ROOT="${fake_root}" \
    AEGIS_PURGE_TMPDIR="${runtime_tmp}" \
    AEGIS_PURGE_PRESERVE_PATH="${preserved_bundle}" \
    AEGIS_PURGE_SYSTEMCTL_BIN="${bindir}/systemctl" \
    AEGIS_PURGE_IPTABLES_BIN="${bindir}/iptables" \
    AEGIS_PURGE_IP6TABLES_BIN="${bindir}/ip6tables" \
    AEGIS_PURGE_NFT_BIN="${bindir}/nft" \
    AEGIS_PURGE_IP_BIN="${bindir}/ip" \
    AEGIS_PURGE_PKILL_BIN="${bindir}/pkill" \
    AEGIS_PURGE_USERDEL_BIN="${bindir}/userdel" \
    AEGIS_PURGE_GROUPDEL_BIN="${bindir}/groupdel" \
    AEGIS_PURGE_TEST_LOG="${log_file}" \
    /bin/bash "${SCRIPT}" client --force >"${case_dir}/stdout.txt"

  require_path_exists "${preserved_bundle}/ca.pem"
  reject_path_exists "${stale_client_tmp}"
  require_file_contains "${case_dir}/stdout.txt" \
    "Preserving validated installer input; skipping client temporary-process sweep."
  require_file_contains "${case_dir}/stdout.txt" \
    "Preserving validated installer input during temporary cleanup."
  if grep -Fq -- "pkill -f ${runtime_tmp}/aegis-client-" "${log_file}"; then
    echo "purge swept the process family containing preserved installer input" >&2
    exit 1
  fi
}

run_device_guard_preservation_case() {
  local case_dir="${tmpdir}/device-guard" fake_root
  fake_root="${case_dir}/root"
  seed_fake_install_root "$fake_root"
  mkdir -p "$fake_root/var/lib/aegis-install/client"
  printf 'armed=1\n' > "$fake_root/var/lib/aegis-install/client/device-guard.conf"
  if AEGIS_PURGE_ROOT="$fake_root" bash "$SCRIPT" client --force > "$case_dir/armed.log" 2>&1; then
    echo 'guarded alternate-root purge unexpectedly succeeded' >&2; exit 1
  fi
  require_path_exists "$fake_root/usr/local/bin/aegis-client"
  require_path_exists "$fake_root/var/lib/aegis-install/client/device-guard.conf"
  require_file_contains "$case_dir/armed.log" 'generic purge refused before mutation'
  rm "$fake_root/var/lib/aegis-install/client/device-guard.conf"
  touch "$fake_root/etc/systemd/system/aegis-device-egress-guard.service"
  if AEGIS_PURGE_ROOT="$fake_root" bash "$SCRIPT" client --force > "$case_dir/orphan.log" 2>&1; then
    echo 'orphan guard purge unexpectedly succeeded' >&2; exit 1
  fi
  require_path_exists "$fake_root/usr/local/bin/aegis-client"
  require_path_exists "$fake_root/etc/systemd/system/aegis-device-egress-guard.service"
  require_file_contains "$case_dir/orphan.log" 'generic purge refused before mutation'
}

run_auto_v2_preservation_case() {
  local case_dir="${tmpdir}/auto-v2" fake_root marker selected count=0
  fake_root="${case_dir}/root"
  seed_fake_install_root "$fake_root"
  for selected in \
    /var/lib/aegis-auto/control \
    /var/lib/aegis-install/client/auto-guardian-install.json \
    /var/lib/aegis-install/client/auto-guard-first-arm.json \
    /var/lib/aegis-install/client/device-guard.conf \
    /var/lib/aegis-auto/fresh-passive-abort-current.json \
    /etc/systemd/system/aegis-auto-guardian.service \
    /etc/systemd/system/aegis-auto-guardian-watchdog.service \
    /etc/systemd/system/aegis-auto-terminal-transition.service \
    /etc/systemd/system/aegis-auto-terminal-observer.service \
    /etc/systemd/system/aegis-auto-terminal-a@.service \
    /etc/systemd/system/aegis-auto-terminal-b@.service \
    /etc/aegis-auto-terminal-source.json \
    /etc/aegis-auto-terminal-store.json \
    /usr/lib/systemd/system-shutdown/aegis-auto-terminal-hook \
    /etc/systemd/system/aegis-auto-capture-topology.service \
    /etc/systemd/system/aegis-auto-trace-rollback-actor.service \
    /etc/systemd/system/aegis-device-egress-guard.service \
    /etc/systemd/system/aegis-foreign-policy-monitor.service \
    /etc/systemd/system/aegis-auto-clean-shutdown.service \
    /etc/systemd/system/aegis-device-dhcp-refresh.service \
    /etc/systemd/system/aegis-device-dhcp-refresh.timer; do
    marker="$fake_root$selected"
    mkdir -p "$(dirname "$marker")"
    if [[ "$selected" == /var/lib/aegis-auto/control ]]; then
      mkdir "$marker"
      printf 'pending\n' > "$marker/current.json"
    elif [[ "$selected" == /etc/systemd/system/aegis-foreign-policy-monitor.service ]]; then
      ln -s /missing "$marker"
    else
      printf 'retained owner\n' > "$marker"
    fi
    if AEGIS_PURGE_ROOT="$fake_root" bash "$SCRIPT" client --force > "$case_dir/force-$count.log" 2>&1; then
      echo "AUTO V2 owner $selected unexpectedly allowed purge" >&2; exit 1
    fi
    require_path_exists "$fake_root/usr/local/bin/aegis-client"
    require_file_contains "$case_dir/force-$count.log" 'generic purge refused before mutation'
    if AEGIS_PURGE_ROOT="$fake_root" bash "$SCRIPT" client > "$case_dir/dry-run-$count.log" 2>&1; then
      echo "AUTO V2 owner $selected unexpectedly allowed dry-run" >&2; exit 1
    fi
    require_file_contains "$case_dir/dry-run-$count.log" 'generic purge refused before mutation'
    if [[ "$selected" == /var/lib/aegis-auto/control ]]; then
      rm "$marker/current.json"
      rmdir "$marker"
    else
      rm "$marker"
    fi
    count=$((count + 1))
  done
  [[ "$count" -eq 21 ]] || { echo 'AUTO V2 owner matrix incomplete' >&2; exit 1; }
  echo "PASS: ${count} AUTO V2 owners each refuse force and dry-run before mutation"
}

# Cross-check the actual fresh-admission path sets against actual removal and
# pre-mutation ownership gates. The shared legacy config is an all-role removal;
# client-only purge deliberately preserves it on a combined host.
python3 - "${ROOT}" <<'PY_FRESH_PURGE_COVERAGE'
import ast
from pathlib import Path
import re
import sys
root = Path(sys.argv[1])
module = ast.parse((root/'scripts/lib/aegis_installer_auto_v2.py').read_text())
fresh = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == 'fresh_installed_package')
sets = []
for node in fresh.body:
    if not isinstance(node, ast.For) or not isinstance(node.iter, ast.Call):
        continue
    if not isinstance(node.iter.func, ast.Name) or node.iter.func.id != 'enumerate':
        continue
    if any(isinstance(n, ast.Constant) and n.value in ('absent_path', 'empty_dir') for n in ast.walk(node)):
        sets.extend(ast.literal_eval(node.iter.args[0]))
assert len(sets) == len(set(sets)) == 25
purge = (root/'scripts/purge-installed-aegis.sh').read_text()
removed = re.findall(r'remove_path "\$\(path_in_root "(/[^"$]+)"\)"', purge)
gate = purge[purge.index('for selected in'):purge.index('cleanup_auto_runtime_logs check')]
assert '/var/lib/aegis-auto/control' in gate and 'exit 1' in gate
builder = (root/'scripts/build-split-deb-packages.sh').read_text()
owner_line = re.compile(r'^\s+(/[^\\\s;]+)', re.M)
purge_owners = owner_line.findall(gate.split('for selected in', 1)[1].split('; do', 1)[0])
# The DEB hooks now authenticate source and delegate to the typed coordinator;
# the old inline shell owner loop no longer exists. Generic alternate-root
# purge still refuses every owner above before mutation (executed below).
assert len(purge_owners) == len(set(purge_owners)) == 21
fixture = (root/'scripts/test-purge-installed-aegis-contract.sh').read_text()
owner_case = fixture.split('run_auto_v2_preservation_case() {', 1)[1].split('\n}', 1)[0]
fixture_owners = owner_line.findall(owner_case.split('for selected in', 1)[1].split('; do', 1)[0])
assert len(fixture_owners) == 21 and set(fixture_owners) == set(purge_owners)
prerm = builder[builder.index('write_prerm() {'):builder.index('write_postrm() {')]
assert 'write_client_removal_hook "$path" prerm' in prerm
hook = builder.split("<<'PY_REMOVAL'\n", 1)[1].split('\nPY_REMOVAL', 1)[0]
hook_ast = ast.parse(hook)
calls = {(n.func.value.id, n.func.attr) for n in ast.walk(hook_ast)
         if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
         and isinstance(n.func.value, ast.Name)}
assert {('coordinator', 'passive_package_prerm'),
        ('coordinator', '_passive_removal_no_owner'),
        ('coordinator', '_passive_removal_actors'),
        ('coordinator', '_passive_removal_recheck_payload')} <= calls
assert purge[:purge.index('cleanup_auto_runtime_logs check')].count('aegis_installer_auto_v2.py uninstall') == 2
passive_prerm = next(n for n in module.body if isinstance(n, ast.FunctionDef)
                    and n.name == 'passive_package_prerm')
assert any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
           and isinstance(n.func.value, ast.Name)
           and n.func.value.id == 'uninstall_journal'
           and n.func.attr == 'verify_package_handoff'
           for n in ast.walk(passive_prerm))
special = '/etc/systemd/system/aegis-device-egress-guard.service'
assert special in purge and 'recover_client_device_guard || {' in purge
for name in sets:
    if name in purge_owners or name.startswith('/var/lib/aegis-auto/control/'):
        continue
    assert any(name == parent or name.startswith(parent+'/') for parent in removed), name
assert '/var/lib/aegis-install/auto-client' in removed
assert '/etc/aegis/aegis.toml' in sets and '/etc/aegis' in removed
print('PASS: all fresh absent/empty paths have purge removal or ownership refusal; shared legacy config requires all-role purge')
PY_FRESH_PURGE_COVERAGE

run_device_guard_preservation_case
run_auto_v2_preservation_case
run_dry_run_case
run_force_case
run_client_only_case
run_server_only_case
run_last_role_removes_shared_case
run_preserve_installer_input_case
echo "PASS: purge helper contract"
