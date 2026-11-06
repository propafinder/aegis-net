#!/usr/bin/env bash
# Phase 5.0.B contract: the aegis-client `.deb` postinst must self-heal
# the canonical config path when a server-rendered bundle was dropped
# in directly (i.e. only `aegis-client.toml` is present, not
# `aegis.toml`).
#
# The first iteration of this fix put the self-heal in the systemd unit
# as ExecStartPre. systemd's unit-file parser eats `$(...)` and `$VAR`
# as specifier-style expansion, so the rendered ExecStartPre tripped
# `systemd-analyze verify` in CI. Moving the logic to the postinst keeps
# the unit file clean (no shell substitution surface) and runs the
# self-heal at the realistic moment — package install time.
#
# This test extracts the postinst script that
# `scripts/build-split-deb-packages.sh::write_postinst` writes for the
# `aegis-client` package, drops it into a tempdir alongside fake
# `/etc/aegis/client/` state, and runs the relevant block directly.
# Asserts the three cases:
#   - only aegis-client.toml present → symlink created
#   - canonical aegis.toml already present → postinst is a no-op
#   - neither present → postinst does not fabricate a file
#   - dangling canonical symlink already present → postinst preserves it
#
# Runs offline. No real dpkg, no systemd, no cargo build.

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${ROOT}/scripts/build-split-deb-packages.sh"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

[[ -f "${SCRIPT}" ]] || fail "missing ${SCRIPT}"

# Extract the function `write_postinst` source from build-split-deb-packages.sh
# and source it so we can call it directly. The function uses awk's
# brace-tracking to avoid pulling in the wider script's side effects.
extracted_helpers="$(mktemp -d)"/postinst-helper.sh
tmpdir="$(mktemp -d)"
trap 'rm -rf "$(dirname "${extracted_helpers}")" "${tmpdir}"' EXIT

awk '
  /^write_postinst\(\) \{/ {
    in_fn = 1; brace = 0
  }
  in_fn {
    print
    n = gsub(/\{/, "{")
    brace += n
    n = gsub(/\}/, "}")
    brace -= n
    if (brace == 0 && /^\}/) { in_fn = 0 }
  }
' "${SCRIPT}" > "${extracted_helpers}"
# shellcheck disable=SC1090
. "${extracted_helpers}"

generated_postinst="${tmpdir}/postinst"
write_postinst "${generated_postinst}" "aegis-client"

# The generated postinst hardcodes CLIENT_CONFIG_DIR=/etc/aegis/client.
# Patch that for the test so it operates against our tempdir instead.
config_dir="${tmpdir}/aegis-client-config"
sed -i.bak "s|CLIENT_CONFIG_DIR=\"/etc/aegis/client\"|CLIENT_CONFIG_DIR=\"${config_dir}\"|" \
  "${generated_postinst}"
rm -f "${generated_postinst}.bak"

# Keep setup calls inert and force the foreign-root branch regardless of the
# host running this contract test.
shimdir="${tmpdir}/bin"
mkdir -p "${shimdir}"
cat > "${shimdir}/systemd-tmpfiles" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod 0755 "${shimdir}/systemd-tmpfiles"
export PATH="${shimdir}:${PATH}"
sed -i.bak \
  -e "s|/run/systemd/system|${tmpdir}/inactive-systemd|g" \
  -e "s|/proc/1/root|${tmpdir}/inactive-init-root|g" \
  "${generated_postinst}"
rm -f "${generated_postinst}.bak"

inode_of() {
  if stat -c '%i' "$1" >/dev/null 2>&1; then
    stat -c '%i' "$1"
  else
    stat -f '%i' "$1"
  fi
}

# The postinst setup call uses the inert shim above; this test concerns only
# the symlink logic. The separate scriptlet test exercises setup failures.

# ---- Case 1: only aegis-client.toml present → expect symlink ----
mkdir -p "${config_dir}"
echo "# bundle" > "${config_dir}/aegis-client.toml"
[[ ! -e "${config_dir}/aegis.toml" ]] || fail "test setup: aegis.toml should not exist yet"

bash "${generated_postinst}" configure
[[ -L "${config_dir}/aegis.toml" ]] \
  || fail "case 1: aegis.toml was not created as a symlink"
target="$(readlink "${config_dir}/aegis.toml")"
[[ "${target}" == "aegis-client.toml" ]] \
  || fail "case 1: symlink target unexpected: ${target}"
[[ -f "${config_dir}/aegis.toml" ]] \
  || fail "case 1: symlink does not resolve to a real file"

# ---- Case 2: aegis.toml already present → postinst is a no-op ----
rm -rf "${config_dir}"
mkdir -p "${config_dir}"
echo "# canonical" > "${config_dir}/aegis.toml"
echo "# bundle leftover" > "${config_dir}/aegis-client.toml"
inode_before="$(inode_of "${config_dir}/aegis.toml")"

bash "${generated_postinst}" configure
[[ ! -L "${config_dir}/aegis.toml" ]] \
  || fail "case 2: canonical aegis.toml turned into a symlink (should be untouched)"
inode_after="$(inode_of "${config_dir}/aegis.toml")"
[[ "${inode_before}" == "${inode_after}" ]] \
  || fail "case 2: aegis.toml inode changed (should be untouched)"

# ---- Case 3: neither file present → postinst must not fabricate one ----
rm -rf "${config_dir}"
mkdir -p "${config_dir}"

bash "${generated_postinst}" configure
[[ ! -e "${config_dir}/aegis.toml" ]] \
  || fail "case 3: aegis.toml was created from nothing"

# ---- Case 4: dangling canonical symlink is administrator state ----
rm -rf "${config_dir}"
mkdir -p "${config_dir}"
echo "# bundle" > "${config_dir}/aegis-client.toml"
ln -s missing-admin-target.toml "${config_dir}/aegis.toml"
bash "${generated_postinst}" configure
[[ -L "${config_dir}/aegis.toml" ]] \
  || fail "case 4: dangling canonical symlink was removed"
[[ "$(readlink "${config_dir}/aegis.toml")" == "missing-admin-target.toml" ]] \
  || fail "case 4: dangling canonical symlink target changed"

# ---- Case 5: systemd unit must NOT contain the old buggy ExecStartPre ----
# (Regression guard: an ExecStartPre with `$(...)` would re-trip
# systemd-analyze verify in CI. Keep the unit clean.)
UNIT="${ROOT}/packaging/systemd/aegis-client.service"
if grep -qE '^ExecStartPre=' "${UNIT}"; then
  if grep -qE '\$\(' "${UNIT}"; then
    fail "case 5: aegis-client.service contains \$(...) inside ExecStartPre — systemd-analyze will reject this"
  fi
fi

echo "ok: client config canonical-name self-heal (5 cases, postinst-based)"
