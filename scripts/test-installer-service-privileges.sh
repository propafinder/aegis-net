#!/usr/bin/env bash
# Inert rendering fixture: UID/account/filesystem mutations are stubbed and
# reject every path outside the temporary directory. Native systemd remains a
# separate acceptance gate.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
FIXTURE="$(mktemp -d)"
FIXTURE="$(cd "${FIXTURE}" && pwd -P)"
trap 'rm -rf -- "${FIXTURE}"' EXIT
export FIXTURE
sed -n '/^install_client_dedicated_uid_dropin() {$/,/^}$/p' "${ROOT}/install.sh" \
  | sed 's/\[\[ ${EUID} -eq 0 \]\] || return 0/: # fixture simulates the root-only branch/' > "${FIXTURE}/functions.sh"
sed -n '/^install_client_ipv6_tun_dropin() {$/,/^}$/p' "${ROOT}/install.sh" >> "${FIXTURE}/functions.sh"
source "${FIXTURE}/functions.sh"
SYSTEMD_DIR="${FIXTURE}/systemd"
AEGIS_HYBRID_DIRECT_SOCKET_MARK=44641
mkdir -p "${FIXTURE}/config" "${FIXTURE}/state"
touch "${FIXTURE}/config/aegis.toml" "${FIXTURE}/config/ca.pem"
assert_fixture_path() { [[ "$1" == "${FIXTURE}/"* ]] || { echo "Unexpected mutation path: $1" >&2; exit 90; }; }
ensure_dir() { assert_fixture_path "$1"; mkdir -p "$1"; }
resolve_wide_client_service_user() { printf 'fixture-service'; }
install_text_file() { assert_fixture_path "$1"; printf '%s\n' "$3" > "$1"; }
chown() {
  printf '%s\n' "$*" >> "${FIXTURE}/chown.log"
  for arg in "$@"; do [[ "${arg}" != /* ]] || assert_fixture_path "${arg}"; done
}
chmod() { for arg in "$@"; do [[ "${arg}" != /* ]] || assert_fixture_path "${arg}"; done; }
install_client_dedicated_uid_dropin "${FIXTURE}/config/aegis.toml" "${FIXTURE}/config/ca.pem" "${FIXTURE}/state" /dev/null ""
cp "${SYSTEMD_DIR}/aegis-client.service.d/10-dedicated-uid.conf" "${FIXTURE}/socks.conf"
PRODUCT_MODE=full-wide-tun
install_client_ipv6_tun_dropin
cp "${SYSTEMD_DIR}/aegis-client.service.d/20-ipv6-tun.conf" "${FIXTURE}/tun.conf"
PRODUCT_MODE=full-wide-hybrid-geneva
install_client_ipv6_tun_dropin
cp "${SYSTEMD_DIR}/aegis-client.service.d/20-ipv6-tun.conf" "${FIXTURE}/hybrid.conf"
python3 - "${FIXTURE}" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1])
for name, expected in (("socks", set()), ("tun", {"CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE"}), ("hybrid", {"CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE", "CAP_NET_RAW"})):
    text = (root / (name + ".conf")).read_text()
    assert "NoNewPrivileges=true" in text
    for key in ("AmbientCapabilities", "CapabilityBoundingSet"):
        values = {"CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_NET_BIND_SERVICE"}
        for line in text.splitlines():
            if line.startswith(key + "="):
                value = line.split("=", 1)[1].strip()
                if value: values.update(value.split())
                else: values.clear()
        assert values == expected, (name, key, values)
    assert not any(line.startswith("ReadWritePaths=") and "/dev" in line for line in text.splitlines())
assert "/dev" not in (root / "chown.log").read_text()
print("PASS: capability resets remove inherited union, SOCKS zero/TUN bounded/hybrid raw, NNP enabled, /dev/null never chowns /dev")
PY

# Additional inert account/admission cases. Extract only the permitted owners;
# no installer entry point, account command, systemd or capture command is run.
sed -n '/^resolve_wide_client_service_user() {$/,/^}$/p' "${ROOT}/install.sh" > "${FIXTURE}/resolver.sh"
sed -n '/^install_text_file() {$/,/^}$/p' "${ROOT}/install.sh" > "${FIXTURE}/install-text-file.sh"
sed -n '/^  normalize_auto_limited_config "${config_path}"$/,/^  activate_systemd_unit "aegis-client.service"$/p' "${ROOT}/install.sh" > "${FIXTURE}/service-boundary.sh"
python3 - "${FIXTURE}" <<'PYQA'
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

fixture = Path(sys.argv[1])
resolver = (fixture / "resolver.sh").read_text()
writer = (fixture / "install-text-file.sh").read_text()
helper = (fixture / "functions.sh").read_text()
boundary = (fixture / "service-boundary.sh").read_text()
assert resolver.startswith("resolve_wide_client_service_user() {\n")
assert writer.startswith("install_text_file() {\n")
assert helper.startswith("install_client_dedicated_uid_dropin() {\n")
assert boundary.startswith('  normalize_auto_limited_config "${config_path}"\n')
assert boundary.endswith('  activate_systemd_unit "aegis-client.service"\n')
# Simulate only the root branch, matching the existing rendering fixture seam.
assert boundary.count('if [[ ${EUID} -eq 0 ]]; then') == 1
boundary = boundary.replace('if [[ ${EUID} -eq 0 ]]; then', 'if :; then')
account_stubs = r"""
id() {
  [[ "$#" == 2 && "$1" == -u ]] || return 90
  case "$2" in aegis|aegis-svc) ;; *) return 90 ;; esac
  [[ -f "${ACCOUNTS}/$2" ]] || return 1
  cat "${ACCOUNTS}/$2"
}
useradd() {
  # useradd has seven arguments; neither this stub nor a fixture runs host useradd.
  [[ "$#" == 7 && "$1" == --system && "$2" == --no-create-home && "$3" == --home-dir && "$4" == "$STATE" && "$5" == --shell && "$6" == /usr/sbin/nologin ]] || return 90
  case "$7" in aegis|aegis-svc) ;; *) return 90 ;; esac
  printf '%s\n' "$7" >> "$CREATE_LOG"
  [[ "$CREATE_RESULT" == success ]] || return 37
  if [[ "$CREATE_UID" != missing ]]; then printf '%s\n' "$CREATE_UID" > "${ACCOUNTS}/$7"; fi
}
command_not_found_handle() { printf 'unexpected fixture command: %s\n' "$1" >&2; return 90; }
"""
filesystem_stubs = r"""
assert_fixture_path() { [[ "$1" == "${CASE}/"* ]] || return 90; }
record() { printf '%s\n' "$1" >> "$ORDER"; }
resolve_wide_client_service_user() { [[ "$FAILURE" != resolver ]] || return 37; printf fixture-service; }
ensure_dir() { assert_fixture_path "$1" || return 90; record ensure; [[ "$FAILURE" != ensure ]] || return 37; mkdir -p "$1"; }
chown() { for arg in "$@"; do [[ "$arg" != /* ]] || assert_fixture_path "$arg" || return 90; done; record chown; [[ "$FAILURE" != chown ]] || return 37; }
chmod() { for arg in "$@"; do [[ "$arg" != /* ]] || assert_fixture_path "$arg" || return 90; done; record chmod; [[ "$FAILURE" != chmod ]] || return 37; }
install_text_file() { assert_fixture_path "$1" || return 90; record write; [[ "$FAILURE" != write ]] || return 37; printf '%s\n' "$3" > "$1"; }
rm() {
  [[ "$#" == 2 && "$1" == -f ]] || return 90
  assert_fixture_path "$2" || return 90
  record unlink
  [[ "$FAILURE" != unlink ]] || return 37
  command rm -f -- "$2"
}
normalize_auto_limited_config() { record normalize; }
install_client_service_assets() { record assets; printf 'new base unit\n' > "$BASE_UNIT"; }
activate_systemd_unit() { [[ "$1" == aegis-client.service ]] || return 90; record activate; }
remove_client_dedicated_uid_dropin() { record root-profile; }
command_not_found_handle() { printf 'unexpected fixture command: %s\n' "$1" >&2; return 90; }
"""

class AccountAdmission(unittest.TestCase):
    def account(self, primary, fallback=None, create="success", created_uid="38", success=True, selected="aegis", created=None, error=None):
        with tempfile.TemporaryDirectory(prefix="account-", dir=fixture) as temp:
            work = Path(temp)
            accounts = work / "accounts"
            accounts.mkdir()
            if primary is not None: (accounts / "aegis").write_text(primary + "\n")
            if fallback is not None: (accounts / "aegis-svc").write_text(fallback + "\n")
            env = {**os.environ, "ACCOUNTS": str(accounts), "STATE": str(work / "state"),
                   "CREATE_LOG": str(work / "create.log"), "CREATE_RESULT": create, "CREATE_UID": created_uid}
            call = 'if name="$(resolve_wide_client_service_user "$STATE")"; then status=0; else status=$?; fi\nprintf "%s" "$name"\nexit "$status"\n'
            result = subprocess.run(["/bin/bash", "-c", "set -eu\n" + resolver + account_stubs + call], env=env, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0 if success else 1, result.stderr)
            if error is not None: self.assertIn(error, result.stderr)
            self.assertEqual(result.stdout, selected if success else "")
            log = work / "create.log"
            self.assertEqual(log.read_text().splitlines() if log.exists() else [], [] if created is None else [created])

    def profile(self, failure="", mode=None, caps="none", success=False, preserved=True):
        with tempfile.TemporaryDirectory(prefix="profile-", dir=fixture) as temp:
            work = Path(temp)
            for directory in ("config", "state", "systemd/aegis-client.service.d"):
                (work / directory).mkdir(parents=True)
            config = work / "config/aegis.toml"
            ca = work / "config/ca.pem"
            config.write_text("synthetic configuration\n")
            ca.write_text("synthetic public CA\n")
            dropins = work / "systemd/aegis-client.service.d"
            prior10, prior20, base = dropins / "10-dedicated-uid.conf", dropins / "20-ipv6-tun.conf", work / "systemd/aegis-client.service"
            prior10.write_text("previous dedicated profile\n")
            prior20.write_text("previous teardown profile\n")
            base.write_text("previous base unit\n")
            binary = work / "client-policy"
            binary.write_text('#!/bin/bash\n[[ "$#" == 5 && "$1" == profile && "$2" == service-policy && "$3" == --config && "$4" == "$CONFIG" && "$5" == --json ]] || exit 90\nprintf "%s" "$POLICY"\n')
            binary.chmod(0o700)
            policy = {"schema": "aegis_client_service_policy_v1", "dedicated_uid": caps != "root", "capabilities": [] if caps in ("none", "root") else ["CAP_NET_BIND_SERVICE"]}
            env = {**os.environ, "CASE": str(work), "ORDER": str(work / "order"), "FAILURE": failure,
                   "SYSTEMD_DIR": str(work / "systemd"), "STATE": str(work / "state"), "CONFIG": str(config),
                   "CA": str(ca), "BASE_UNIT": str(base), "BINARY": str(binary), "POLICY": json.dumps(policy),
                   "OPERATOR_MODE": mode or "client-socks", "AEGIS_HYBRID_DIRECT_SOCKET_MARK": "44641"}
            wrapper = 'actual_client_service_boundary() {\n  local config_path="$CONFIG" ca_path="$CA" state_dir="$STATE" runtime_events_path=/dev/null bin_path="$BINARY"\n' + boundary + '}\n'
            call = 'actual_client_service_boundary' if mode else 'install_client_dedicated_uid_dropin "$CONFIG" "$CA" "$STATE" /dev/null ""'
            conditional = 'if ' + call + '; then status=0; else status=$?; fi\nexit "$status"\n'
            result = subprocess.run(["/bin/bash", "-c", "set -eu\n" + helper + filesystem_stubs + wrapper + conditional], env=env, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0 if success else 1, result.stderr)
            if failure == "resolver":
                self.assertIn("ERROR: could not resolve/create a dedicated system user; client activation was not attempted.", result.stderr)
            order_file = work / "order"
            order = order_file.read_text().splitlines() if order_file.exists() else []
            if not success: self.assertNotIn("activate", order)
            if preserved:
                self.assertEqual(prior10.read_text(), "previous dedicated profile\n")
                self.assertEqual(prior20.read_text(), "previous teardown profile\n")
                self.assertEqual(base.read_text(), "previous base unit\n")
            if failure == "resolver":
                self.assertEqual(order, ["normalize"] if mode else [])
            elif failure == "chown":
                self.assertEqual(order, ["chown"])
            elif failure in ("write", "ensure", "unlink"):
                self.assertEqual(order[-1], failure)
                if failure == "unlink":
                    self.assertIn("User=fixture-service\n", prior10.read_text())
                    self.assertEqual(prior20.read_text(), "previous teardown profile\n")
                    self.assertEqual(base.read_text(), "previous base unit\n")
            if success and caps != "root":
                self.assertIn("User=fixture-service\n", prior10.read_text())
                self.assertIn("NoNewPrivileges=true\n", prior10.read_text())
                self.assertIn("CapabilityBoundingSet=\n", prior10.read_text())
                self.assertFalse(prior20.exists())
                self.assertLess(order.index("chown"), order.index("write"))
                if mode:
                    self.assertLess(order.index("unlink"), order.index("assets"))
                    self.assertLess(order.index("assets"), order.index("activate"))
                    expected = "" if caps == "none" else "CAP_NET_BIND_SERVICE"
                    self.assertIn("AmbientCapabilities=" + expected + "\n", prior10.read_text())
            if success and caps == "root":
                self.assertIn("root-profile", order)
                self.assertNotIn("write", order)
                self.assertLess(order.index("assets"), order.index("activate"))

    def test01_existing_system_uid(self): self.account("37")
    def test02_primary_root_refused(self): self.account("0", success=False, error="'aegis' must be a non-root system account")
    def test03_primary_malformed_refused(self): self.account("invalid", success=False, error="'aegis' must be a non-root system account")
    def test04_login_uses_existing_system_fallback(self): self.account("1000", "42", selected="aegis-svc")
    def test05_root_fallback_refused(self): self.account("1000", "0", success=False, error='must have a non-root system uid below 1000.')
    def test06_login_fallback_refused(self): self.account("1000", "1001", success=False, error='must have a non-root system uid below 1000.')
    def test07_failed_creation_refused(self): self.account(None, create="failed", success=False, created="aegis")
    def test08_created_system_uid_rechecked(self): self.account(None, created="aegis")
    def test09_created_root_uid_refused(self): self.account(None, created_uid="0", success=False, created="aegis", error='must have a non-root system uid below 1000.')
    def test10_creation_without_account_refused(self): self.account(None, created_uid="missing", success=False, created="aegis", error='is unavailable after creation.')
    def test11_login_creates_safe_fallback(self): self.account("1000", created="aegis-svc", selected="aegis-svc")
    def test12_malformed_fallback_refused(self): self.account("1000", "invalid", success=False, error='must have a non-root system uid below 1000.')
    def test13_resolver_failure_preserves_prior_profile(self): self.profile("resolver")
    def test14_ownership_failure_preserves_prior_profile(self): self.profile("chown")
    def test15_dropin_write_failure_preserves_prior_profile(self): self.profile("write")
    def test16_dropin_directory_failure_preserves_prior_profile(self): self.profile("ensure")
    def test17_stale_unlink_failure_reports_partial_failure(self): self.profile("unlink", preserved=False)
    def test18_socks_zero_caps_caller_refuses_failed_uid(self): self.profile("resolver", "client-socks", "none")
    def test19_socks_bind_caller_refuses_failed_uid(self): self.profile("resolver", "client-socks", "bind")
    def test20_redirect_caller_refuses_failed_uid(self): self.profile("resolver", "client-wide-redirect")
    def test21_nfqueue_caller_refuses_failed_uid(self): self.profile("resolver", "client-wide-nfqueue-observer")
    def test22_socks_zero_caps_precedes_assets_and_activation(self): self.profile(mode="client-socks", caps="none", success=True, preserved=False)
    def test23_socks_bind_precedes_assets_and_activation(self): self.profile(mode="client-socks", caps="bind", success=True, preserved=False)
    def test24_rust_root_policy_preserved(self): self.profile(mode="client-socks", caps="root", success=True, preserved=False)

    def test25_failed_previous_profile_backup_stops_write(self):
        with tempfile.TemporaryDirectory(prefix="backup-", dir=fixture) as temp:
            work = Path(temp)
            destination = work / "profile.conf"
            destination.write_text("previous service profile\n")
            order = work / "order"
            stubs = r"""
install_atomic_write() {
  [[ "$1" == "$DESTINATION" || "$1" == "$DESTINATION".bak.* ]] || return 90
  [[ "$2" == 0644 && "$3" == strict ]] || return 90
  printf '%s\n' "${4:-write}" >> "$ORDER"
  if [[ "${4:-write}" == write ]]; then cat > "$DESTINATION"; fi
}
cp() {
  [[ "$#" == 3 && "$1" == -a && "$2" == "$DESTINATION" && "$3" == "$DESTINATION".bak.* ]] || return 90
  printf 'backup-copy\n' >> "$ORDER"
  return 37
}
"""
            env = {**os.environ, "FORCE": "1", "DESTINATION": str(destination), "ORDER": str(order)}
            call = 'if install_text_file "$DESTINATION" 0644 new-profile; then status=0; else status=$?; fi\nexit "$status"\n'
            result = subprocess.run(["/bin/bash", "-c", "set -eu\n" + writer + stubs + call], env=env, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(order.read_text().splitlines(), ["validate", "validate", "backup-copy"])
            self.assertEqual(destination.read_text(), "previous service profile\n")
            self.assertEqual(list(work.glob("profile.conf.bak.*")), [])

unittest.main(argv=[sys.argv[0]], verbosity=2)
PYQA
