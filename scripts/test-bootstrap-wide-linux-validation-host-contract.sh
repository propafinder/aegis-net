#!/usr/bin/env bash
# Contract self-test for richer-host bootstrap helper.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/bootstrap-wide-linux-validation-host.sh"
tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/aegis-bootstrap-host-contract.XXXXXX")"
trap 'rm -rf "${tmpdir}"' EXIT

cargo build -q -p aegis-measure
export AEGIS_MEASURE_BIN="${ROOT}/target/debug/aegis-measure"

make_common_bin() {
  local bindir="$1"
  mkdir -p "${bindir}"
  ln -sf /bin/bash "${bindir}/bash"

  cat > "${bindir}/uname" <<'EOF'
#!/usr/bin/env bash
printf 'Linux\n'
EOF
  chmod +x "${bindir}/uname"

  cat > "${bindir}/ip" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${bindir}/ip"

  cat > "${bindir}/iptables" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${bindir}/iptables"

  cat > "${bindir}/ip6tables" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${bindir}/ip6tables"

  cat > "${bindir}/nft" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${bindir}/nft"

  cat > "${bindir}/openssl" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${bindir}/openssl"

  cat > "${bindir}/sudo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "-n" && "${2:-}" == "true" ]]; then
  exit 0
fi
"$@"
EOF
  chmod +x "${bindir}/sudo"
}

run_json_case_capture_status() {
  local output_path="$1"
  shift

  local status=0
  set +e
  "$@" > "${output_path}"
  status=$?
  set -e
  printf '%s\n' "${status}"
}

run_check_happy_case() {
  local case_dir="${tmpdir}/happy"
  mkdir -p "${case_dir}"
  make_common_bin "${case_dir}/bin"

  cat > "${case_dir}/bin/cargo" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${case_dir}/bin/cargo"

  PATH="${case_dir}/bin:/usr/bin:/bin" bash "${SCRIPT}" --check > "${case_dir}/output.log"

  grep -Fq "Host prerequisites look ready for richer-host validation." "${case_dir}/output.log"
  grep -Fq "cargo" "${case_dir}/output.log"
  grep -Fq "ok" "${case_dir}/output.log"
}

run_missing_cargo_case() {
  local case_dir="${tmpdir}/missing-cargo"
  mkdir -p "${case_dir}"
  mkdir -p "${case_dir}/home"
  make_common_bin "${case_dir}/bin"

  set +e
  HOME="${case_dir}/home" PATH="${case_dir}/bin:/usr/bin:/bin" bash "${SCRIPT}" --check > "${case_dir}/output.log" 2>&1
  local status=$?
  set -e

  if [[ "${status}" -eq 0 ]]; then
    echo "expected missing cargo check to fail" >&2
    exit 1
  fi

  grep -Fq "cargo" "${case_dir}/output.log"
  if ! grep -Fq "Missing richer-host validation prerequisites" "${case_dir}/output.log" \
    && ! grep -Fq "Host prerequisites are incomplete." "${case_dir}/output.log"; then
    echo "expected missing prerequisite text" >&2
    cat "${case_dir}/output.log" >&2
    exit 1
  fi
  grep -Fq "bootstrap-wide-linux-validation-host.sh --install" "${case_dir}/output.log"
}

run_json_missing_cargo_case() {
  local case_dir="${tmpdir}/json-missing-cargo"
  local status=0
  mkdir -p "${case_dir}"
  mkdir -p "${case_dir}/home"
  make_common_bin "${case_dir}/bin"

  status="$(run_json_case_capture_status "${case_dir}/output.json" env HOME="${case_dir}/home" PATH="${case_dir}/bin:/usr/bin:/bin" /bin/bash "${SCRIPT}" --check --json)"

  cargo run -q -p aegis-measure -- check-wide-linux-validation-host-bootstrap-contract-case \
    --case-id json_missing_cargo \
    --output-json "${case_dir}/output.json" \
    --status "${status}"
}

run_json_check_missing_sudo_case() {
  local case_dir="${tmpdir}/json-check-missing-sudo"
  local status=0
  mkdir -p "${case_dir}"
  make_common_bin "${case_dir}/bin"
  ln -sf /bin/bash "${case_dir}/bin/bash"
  rm -f "${case_dir}/bin/sudo"

  cat > "${case_dir}/bin/cargo" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${case_dir}/bin/cargo"

  status="$(run_json_case_capture_status "${case_dir}/output.json" env AEGIS_BOOTSTRAP_TEST_FORCE_NONROOT=1 PATH="${case_dir}/bin" /bin/bash "${SCRIPT}" --check --json)"

  cargo run -q -p aegis-measure -- check-wide-linux-validation-host-bootstrap-contract-case \
    --case-id json_check_missing_sudo \
    --output-json "${case_dir}/output.json" \
    --status "${status}"
}

run_install_json_skip_rustup_missing_cargo_case() {
  local case_dir="${tmpdir}/json-install-skip-rustup-missing-cargo"
  local status=0
  mkdir -p "${case_dir}"
  mkdir -p "${case_dir}/home"
  make_common_bin "${case_dir}/bin"

  cat > "${case_dir}/bin/apt-get" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${case_dir}/bin/apt-get"

  status="$(run_json_case_capture_status "${case_dir}/output.json" env HOME="${case_dir}/home" PATH="${case_dir}/bin:/usr/bin:/bin" /bin/bash "${SCRIPT}" --install --skip-rustup --json)"

  cargo run -q -p aegis-measure -- check-wide-linux-validation-host-bootstrap-contract-case \
    --case-id install_skip_rustup_missing_cargo \
    --output-json "${case_dir}/output.json" \
    --status "${status}"
}

run_json_case() {
  local case_dir="${tmpdir}/json"
  local status=0
  mkdir -p "${case_dir}/home"
  make_common_bin "${case_dir}/bin"

  cat > "${case_dir}/bin/cargo" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${case_dir}/bin/cargo"

  # Keep the check case independent of the host package manager and the
  # runner's real ~/.cargo/bin.  The contract supplies every command it needs;
  # leaking /usr/bin/apt-get made the same fixture mean something different on
  # Ubuntu than it did on macOS.
  status="$(run_json_case_capture_status "${case_dir}/output.json" env HOME="${case_dir}/home" PATH="${case_dir}/bin" /bin/bash "${SCRIPT}" --check --json)"

  cargo run -q -p aegis-measure -- check-wide-linux-validation-host-bootstrap-contract-case \
    --case-id json \
    --output-json "${case_dir}/output.json" \
    --status "${status}"
}

run_json_cargo_in_home_bin_case() {
  local case_dir="${tmpdir}/json-cargo-in-home-bin"
  local status=0
  mkdir -p "${case_dir}/bin" "${case_dir}/home/.cargo/bin"
  make_common_bin "${case_dir}/bin"

  cat > "${case_dir}/home/.cargo/bin/cargo" <<'EOF'
#!/usr/bin/env bash
printf 'cargo-from-home-bin\n'
EOF
  chmod +x "${case_dir}/home/.cargo/bin/cargo"

  status="$(run_json_case_capture_status "${case_dir}/output.json" env HOME="${case_dir}/home" PATH="${case_dir}/bin:/usr/bin:/bin" /bin/bash "${SCRIPT}" --check --json)"

  cargo run -q -p aegis-measure -- check-wide-linux-validation-host-bootstrap-contract-case \
    --case-id json_cargo_in_home_bin \
    --output-json "${case_dir}/output.json" \
    --status "${status}" \
    --expected-cargo "${case_dir}/home/.cargo/bin/cargo"
}

run_json_interactive_sudo_warning_case() {
  local case_dir="${tmpdir}/json-interactive-sudo-warning"
  local status=0
  mkdir -p "${case_dir}"
  make_common_bin "${case_dir}/bin"

  cat > "${case_dir}/bin/cargo" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${case_dir}/bin/cargo"

  cat > "${case_dir}/bin/sudo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "-n" && "${2:-}" == "true" ]]; then
  exit 1
fi
"$@"
EOF
  chmod +x "${case_dir}/bin/sudo"

  status="$(run_json_case_capture_status "${case_dir}/output.json" env AEGIS_BOOTSTRAP_TEST_FORCE_NONROOT=1 PATH="${case_dir}/bin:/usr/bin:/bin" /bin/bash "${SCRIPT}" --check --json)"

  cargo run -q -p aegis-measure -- check-wide-linux-validation-host-bootstrap-contract-case \
    --case-id json_interactive_sudo_warning \
    --output-json "${case_dir}/output.json" \
    --status "${status}"
}

run_json_unsupported_platform_case() {
  local case_dir="${tmpdir}/json-unsupported-platform"
  local status=0
  mkdir -p "${case_dir}"
  make_common_bin "${case_dir}/bin"

  cat > "${case_dir}/bin/uname" <<'EOF'
#!/usr/bin/env bash
printf 'Darwin\n'
EOF
  chmod +x "${case_dir}/bin/uname"

  status="$(run_json_case_capture_status "${case_dir}/output.json" env PATH="${case_dir}/bin:/usr/bin:/bin" /bin/bash "${SCRIPT}" --check --json)"

  cargo run -q -p aegis-measure -- check-wide-linux-validation-host-bootstrap-contract-case \
    --case-id json_unsupported_platform \
    --output-json "${case_dir}/output.json" \
    --status "${status}"
}

run_json_unknown_argument_case() {
  local case_dir="${tmpdir}/json-unknown-argument"
  local status=0
  mkdir -p "${case_dir}"
  make_common_bin "${case_dir}/bin"

  status="$(run_json_case_capture_status "${case_dir}/output.json" env PATH="${case_dir}/bin:/usr/bin:/bin" /bin/bash "${SCRIPT}" --json --bogus)"

  cargo run -q -p aegis-measure -- check-wide-linux-validation-host-bootstrap-contract-case \
    --case-id json_unknown_argument \
    --output-json "${case_dir}/output.json" \
    --status "${status}"
}

run_json_unknown_argument_before_json_case() {
  local case_dir="${tmpdir}/json-unknown-argument-before-json"
  local status=0
  mkdir -p "${case_dir}"
  make_common_bin "${case_dir}/bin"

  status="$(run_json_case_capture_status "${case_dir}/output.json" env PATH="${case_dir}/bin:/usr/bin:/bin" /bin/bash "${SCRIPT}" --bogus --json)"

  cargo run -q -p aegis-measure -- check-wide-linux-validation-host-bootstrap-contract-case \
    --case-id json_unknown_argument_before_json \
    --output-json "${case_dir}/output.json" \
    --status "${status}"
}

run_install_json_unsupported_package_manager_case() {
  local case_dir="${tmpdir}/json-install-unsupported"
  local status=0
  mkdir -p "${case_dir}"
  make_common_bin "${case_dir}/bin"

  cat > "${case_dir}/bin/curl" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${case_dir}/bin/curl"

  status="$(run_json_case_capture_status "${case_dir}/output.json" env PATH="${case_dir}/bin" /bin/bash "${SCRIPT}" --install --json)"

  cargo run -q -p aegis-measure -- check-wide-linux-validation-host-bootstrap-contract-case \
    --case-id install_unsupported_package_manager \
    --output-json "${case_dir}/output.json" \
    --status "${status}"
}

run_install_json_missing_curl_case() {
  local case_dir="${tmpdir}/json-install-missing-curl"
  local status=0
  mkdir -p "${case_dir}"
  mkdir -p "${case_dir}/home"
  make_common_bin "${case_dir}/bin"
  rm -f "${case_dir}/bin/curl"

  cat > "${case_dir}/bin/apt-get" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${case_dir}/bin/apt-get"

  status="$(run_json_case_capture_status "${case_dir}/output.json" env HOME="${case_dir}/home" PATH="${case_dir}/bin" /bin/bash "${SCRIPT}" --install --json)"

  cargo run -q -p aegis-measure -- check-wide-linux-validation-host-bootstrap-contract-case \
    --case-id install_missing_curl \
    --output-json "${case_dir}/output.json" \
    --status "${status}"
}

run_install_json_missing_sudo_case() {
  local case_dir="${tmpdir}/json-install-missing-sudo"
  local status=0
  mkdir -p "${case_dir}"
  make_common_bin "${case_dir}/bin"
  rm -f "${case_dir}/bin/sudo"

  cat > "${case_dir}/bin/apt-get" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${case_dir}/bin/apt-get"

  status="$(run_json_case_capture_status "${case_dir}/output.json" env AEGIS_BOOTSTRAP_TEST_FORCE_NONROOT=1 PATH="${case_dir}/bin" /bin/bash "${SCRIPT}" --install --json)"

  cargo run -q -p aegis-measure -- check-wide-linux-validation-host-bootstrap-contract-case \
    --case-id install_missing_sudo \
    --output-json "${case_dir}/output.json" \
    --status "${status}"
}

run_install_json_package_update_failed_case() {
  local case_dir="${tmpdir}/json-install-package-update-failed"
  local status=0
  mkdir -p "${case_dir}"
  make_common_bin "${case_dir}/bin"

  cat > "${case_dir}/bin/cargo" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${case_dir}/bin/cargo"

  cat > "${case_dir}/bin/apt-get" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "update" ]]; then
  exit 33
fi
exit 0
EOF
  chmod +x "${case_dir}/bin/apt-get"

  status="$(run_json_case_capture_status "${case_dir}/output.json" env PATH="${case_dir}/bin:/usr/bin:/bin" /bin/bash "${SCRIPT}" --install --json)"

  cargo run -q -p aegis-measure -- check-wide-linux-validation-host-bootstrap-contract-case \
    --case-id install_package_update_failed \
    --output-json "${case_dir}/output.json" \
    --status "${status}"
}

run_install_json_package_install_failed_case() {
  local case_dir="${tmpdir}/json-install-package-failed"
  local status=0
  mkdir -p "${case_dir}"
  make_common_bin "${case_dir}/bin"

  cat > "${case_dir}/bin/cargo" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${case_dir}/bin/cargo"

  cat > "${case_dir}/bin/apt-get" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "update" ]]; then
  exit 0
fi
exit 42
EOF
  chmod +x "${case_dir}/bin/apt-get"

  status="$(run_json_case_capture_status "${case_dir}/output.json" env PATH="${case_dir}/bin:/usr/bin:/bin" /bin/bash "${SCRIPT}" --install --json)"

  cargo run -q -p aegis-measure -- check-wide-linux-validation-host-bootstrap-contract-case \
    --case-id install_package_install_failed \
    --output-json "${case_dir}/output.json" \
    --status "${status}"
}

run_install_json_rustup_download_failed_case() {
  local case_dir="${tmpdir}/json-install-rustup-download-failed"
  local status=0
  mkdir -p "${case_dir}"
  mkdir -p "${case_dir}/home"
  make_common_bin "${case_dir}/bin"

  cat > "${case_dir}/bin/apt-get" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${case_dir}/bin/apt-get"

  cat > "${case_dir}/bin/curl" <<'EOF'
#!/usr/bin/env bash
exit 17
EOF
  chmod +x "${case_dir}/bin/curl"

  status="$(run_json_case_capture_status "${case_dir}/output.json" env HOME="${case_dir}/home" PATH="${case_dir}/bin:/usr/bin:/bin" /bin/bash "${SCRIPT}" --install --json)"

  cargo run -q -p aegis-measure -- check-wide-linux-validation-host-bootstrap-contract-case \
    --case-id install_rustup_download_failed \
    --output-json "${case_dir}/output.json" \
    --status "${status}"
}

run_install_json_rustup_install_failed_case() {
  local case_dir="${tmpdir}/json-install-rustup-failed"
  local status=0
  mkdir -p "${case_dir}"
  mkdir -p "${case_dir}/home"
  make_common_bin "${case_dir}/bin"

  cat > "${case_dir}/bin/apt-get" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${case_dir}/bin/apt-get"

  cat > "${case_dir}/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
outfile=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "-o" ]]; then
    outfile="$2"
    shift 2
    continue
  fi
  shift
done
printf '%s\n' '#!/usr/bin/env bash' 'exit 9' > "${outfile}"
EOF
  chmod +x "${case_dir}/bin/curl"

  status="$(run_json_case_capture_status "${case_dir}/output.json" env HOME="${case_dir}/home" PATH="${case_dir}/bin:/usr/bin:/bin" /bin/bash "${SCRIPT}" --install --json)"

  cargo run -q -p aegis-measure -- check-wide-linux-validation-host-bootstrap-contract-case \
    --case-id install_rustup_install_failed \
    --output-json "${case_dir}/output.json" \
    --status "${status}"
}

run_install_json_happy_case() {
  local case_dir="${tmpdir}/json-install-happy"
  local status=0
  local command_log="${case_dir}/commands.log"
  mkdir -p "${case_dir}"
  make_common_bin "${case_dir}/bin"

  cat > "${case_dir}/bin/cargo" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${case_dir}/bin/cargo"

  cat > "${case_dir}/bin/apt-get" <<'EOF'
#!/usr/bin/env bash
printf 'apt-get %s\n' "$*" >> "${AEGIS_BOOTSTRAP_HELPER_COMMAND_LOG}"
exit 0
EOF
  chmod +x "${case_dir}/bin/apt-get"

  status="$(run_json_case_capture_status "${case_dir}/output.json" env AEGIS_BOOTSTRAP_HELPER_COMMAND_LOG="${command_log}" PATH="${case_dir}/bin:/usr/bin:/bin" /bin/bash "${SCRIPT}" --install --json)"

  cargo run -q -p aegis-measure -- check-wide-linux-validation-host-bootstrap-contract-case \
    --case-id install_happy \
    --output-json "${case_dir}/output.json" \
    --status "${status}" \
    --command-log "${command_log}"
}

run_install_json_alt_package_manager_happy_case() {
  local package_manager="$1"
  local case_name="$2"
  local command_snippet="$3"
  local case_dir="${tmpdir}/${case_name}"
  local status=0
  local command_log="${case_dir}/commands.log"
  mkdir -p "${case_dir}"
  make_common_bin "${case_dir}/bin"

  cat > "${case_dir}/bin/cargo" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${case_dir}/bin/cargo"

  cat > "${case_dir}/bin/${package_manager}" <<EOF
#!/usr/bin/env bash
printf '${package_manager} %s\n' "\$*" >> "\${AEGIS_BOOTSTRAP_HELPER_COMMAND_LOG}"
exit 0
EOF
  chmod +x "${case_dir}/bin/${package_manager}"

  status="$(run_json_case_capture_status "${case_dir}/output.json" env AEGIS_BOOTSTRAP_HELPER_COMMAND_LOG="${command_log}" PATH="${case_dir}/bin" /bin/bash "${SCRIPT}" --install --json)"

  cargo run -q -p aegis-measure -- check-wide-linux-validation-host-bootstrap-contract-case \
    --case-id install_alt_package_manager_happy \
    --output-json "${case_dir}/output.json" \
    --status "${status}" \
    --command-log "${command_log}" \
    --package-manager "${package_manager}" \
    --command-snippet "${command_snippet}"
}

run_install_json_dnf_happy_case() {
  run_install_json_alt_package_manager_happy_case \
    "dnf" \
    "json-install-dnf-happy" \
    "dnf install -y"
}

run_install_json_yum_happy_case() {
  run_install_json_alt_package_manager_happy_case \
    "yum" \
    "json-install-yum-happy" \
    "yum install -y"
}

run_install_json_zypper_happy_case() {
  run_install_json_alt_package_manager_happy_case \
    "zypper" \
    "json-install-zypper-happy" \
    "zypper --non-interactive install"
}

run_install_json_skip_rustup_happy_case() {
  local case_dir="${tmpdir}/json-install-skip-rustup-happy"
  local status=0
  local command_log="${case_dir}/commands.log"
  mkdir -p "${case_dir}"
  make_common_bin "${case_dir}/bin"

  cat > "${case_dir}/bin/cargo" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${case_dir}/bin/cargo"

  cat > "${case_dir}/bin/apt-get" <<'EOF'
#!/usr/bin/env bash
printf 'apt-get %s\n' "$*" >> "${AEGIS_BOOTSTRAP_HELPER_COMMAND_LOG}"
exit 0
EOF
  chmod +x "${case_dir}/bin/apt-get"

  status="$(run_json_case_capture_status "${case_dir}/output.json" env AEGIS_BOOTSTRAP_HELPER_COMMAND_LOG="${command_log}" PATH="${case_dir}/bin:/usr/bin:/bin" /bin/bash "${SCRIPT}" --install --skip-rustup --json)"

  cargo run -q -p aegis-measure -- check-wide-linux-validation-host-bootstrap-contract-case \
    --case-id install_skip_rustup_happy \
    --output-json "${case_dir}/output.json" \
    --status "${status}" \
    --command-log "${command_log}"
}

run_install_case() {
  local case_dir="${tmpdir}/install"
  local command_log="${case_dir}/commands.log"
  mkdir -p "${case_dir}"
  make_common_bin "${case_dir}/bin"

  cat > "${case_dir}/bin/cargo" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${case_dir}/bin/cargo"

  cat > "${case_dir}/bin/apt-get" <<'EOF'
#!/usr/bin/env bash
printf 'apt-get %s\n' "$*" >> "${AEGIS_BOOTSTRAP_HELPER_COMMAND_LOG}"
exit 0
EOF
  chmod +x "${case_dir}/bin/apt-get"

  AEGIS_BOOTSTRAP_HELPER_COMMAND_LOG="${command_log}" \
    PATH="${case_dir}/bin:/usr/bin:/bin" \
    bash "${SCRIPT}" --install > "${case_dir}/output.log"

  grep -Fq "apt-get update" "${command_log}"
  grep -Fq "apt-get install -y --no-install-recommends" "${command_log}"
  grep -Fq "Detected package manager: apt-get" "${case_dir}/output.log"
  grep -Fq "Host prerequisites look ready for richer-host validation." "${case_dir}/output.log"
}

cargo run -q -p aegis-measure -- check-wide-linux-validation-host-bootstrap-coverage \
  --repo-root "${ROOT}"

run_check_happy_case
run_missing_cargo_case
run_json_missing_cargo_case
run_json_check_missing_sudo_case
run_install_json_skip_rustup_missing_cargo_case
run_json_case
run_json_cargo_in_home_bin_case
run_json_interactive_sudo_warning_case
run_json_unsupported_platform_case
run_json_unknown_argument_case
run_json_unknown_argument_before_json_case
run_install_json_unsupported_package_manager_case
run_install_json_missing_curl_case
run_install_json_missing_sudo_case
run_install_json_package_update_failed_case
run_install_json_package_install_failed_case
run_install_json_rustup_download_failed_case
run_install_json_rustup_install_failed_case
run_install_json_happy_case
run_install_json_dnf_happy_case
run_install_json_yum_happy_case
run_install_json_zypper_happy_case
run_install_json_skip_rustup_happy_case
run_install_case

echo "bootstrap wide linux validation host contract ok"
