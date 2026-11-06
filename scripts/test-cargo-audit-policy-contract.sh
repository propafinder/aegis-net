#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="${ROOT}/scripts/security/cargo-audit.toml"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

grep -Fq 'ignore = ["RUSTSEC-2026-0173"]' "${CONFIG}"
grep -Fq 'deny = ["warnings"]' "${CONFIG}"
grep -Fq 'bash scripts/security/audit-dependencies.sh' "${ROOT}/.github/workflows/ci.yml"
grep -Fq 'cargo audit --deny warnings --file' "${ROOT}/scripts/security/audit-dependencies.sh"
grep -Fq 'cp "${POLICY}" "${AUDIT_WORKDIR}/.cargo/audit.toml"' "${ROOT}/scripts/security/audit-dependencies.sh"
python3 - "${ROOT}/.github/workflows/ci.yml" <<'PY'
from pathlib import Path
import sys

workflow = Path(sys.argv[1]).read_text()
job = workflow.split("\n  dependency-security:\n", 1)[1].split("\n  rust:\n", 1)[0]
steps = (
    "      - name: Install Rust 1.97.1\n",
    "      - name: Dependency audit policy contract\n",
    "      - name: Install dependency auditor\n",
    "      - name: Dependency vulnerability audit\n",
)
positions = [job.index(step) for step in steps]
assert positions == sorted(positions), "dependency-security audit step order changed"
contract = job.split(steps[1], 1)[1].split("      - name: ", 1)[0]
assert "        if: ${{ !cancelled() }}\n" in contract
assert "        run: bash scripts/test-cargo-audit-policy-contract.sh\n" in contract
PY

# Exercise policy discovery, exact lockfile selection, audit failure propagation
# and temporary-directory cleanup without consulting an advisory database.
mkdir -p "${TMP}/bin"
cat >"${TMP}/bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$#" == 6 && "$1" == audit && "$2" == --deny && "$3" == warnings && "$4" == --file ]]
[[ "$6" == --no-fetch ]]
[[ "$5" == "${AUDIT_EXPECTED_ROOT}/Cargo.lock" || \
   "$5" == "${AUDIT_EXPECTED_ROOT}/tools/macos/aegis-network-extension/Cargo.lock" || \
   "$5" == "${AUDIT_EXPECTED_ROOT}/third_party/h2/Cargo.lock" ]]
cmp .cargo/audit.toml "${AUDIT_EXPECTED_ROOT}/scripts/security/cargo-audit.toml"
pwd >"${AUDIT_OBSERVED_CWD}"
printf '%s\n' "$5" >>"${AUDIT_OBSERVED_FILES}"
if [[ "$5" == "${AUDIT_FIXTURE_FAIL_LOCK}" ]]; then
  exit 37
fi
EOF
chmod +x "${TMP}/bin/cargo"
for failing_lock in none root macos h2; do
  case "${failing_lock}" in
    none) fail_path=""; expected_exit=0 ;;
    root) fail_path="${ROOT}/Cargo.lock"; expected_exit=37 ;;
    macos) fail_path="${ROOT}/tools/macos/aegis-network-extension/Cargo.lock"; expected_exit=37 ;;
    h2) fail_path="${ROOT}/third_party/h2/Cargo.lock"; expected_exit=37 ;;
  esac
  : >"${TMP}/audit-files"
  actual_exit=0
  PATH="${TMP}/bin:${PATH}" AUDIT_EXPECTED_ROOT="${ROOT}" \
    AUDIT_OBSERVED_CWD="${TMP}/audit-cwd" AUDIT_OBSERVED_FILES="${TMP}/audit-files" \
    AUDIT_FIXTURE_FAIL_LOCK="${fail_path}" \
    bash "${ROOT}/scripts/security/audit-dependencies.sh" --no-fetch || actual_exit=$?
  [[ "${actual_exit}" == "${expected_exit}" ]]
  [[ ! -e "$(cat "${TMP}/audit-cwd")" ]]
  case "${failing_lock}" in
    root) printf '%s\n' "${ROOT}/Cargo.lock" >"${TMP}/expected-files" ;;
    macos) printf '%s\n' "${ROOT}/Cargo.lock" \
         "${ROOT}/tools/macos/aegis-network-extension/Cargo.lock" >"${TMP}/expected-files" ;;
    *) printf '%s\n' "${ROOT}/Cargo.lock" \
         "${ROOT}/tools/macos/aegis-network-extension/Cargo.lock" \
         "${ROOT}/third_party/h2/Cargo.lock" >"${TMP}/expected-files" ;;
  esac
  cmp "${TMP}/audit-files" "${TMP}/expected-files"
done

cargo tree \
  --manifest-path "${ROOT}/Cargo.toml" \
  --workspace \
  --all-features \
  --target all \
  --locked \
  --prefix none \
  --format '{p}' \
  >"${TMP}/tree.txt"

cargo tree \
  --manifest-path "${ROOT}/tools/macos/aegis-network-extension/Cargo.toml" \
  --all-features \
  --target all \
  --locked \
  --prefix none \
  --format '{p}' \
  >"${TMP}/macos-tree.txt"

grep -Fq 'name = "proc-macro-error2"' "${ROOT}/Cargo.lock" || {
  echo "proc-macro-error2 is no longer in Cargo.lock; remove the stale audit ignore" >&2
  exit 1
}
if grep -Eq '^proc-macro-error2 v' "${TMP}/tree.txt"; then
  echo "RUSTSEC-2026-0173 ignore is unsafe: proc-macro-error2 entered the active graph" >&2
  exit 1
fi
if grep -Eq '^proc-macro-error2 v' "${TMP}/macos-tree.txt"; then
  echo "RUSTSEC-2026-0173 ignore is unsafe: proc-macro-error2 entered the macOS extension active graph" >&2
  exit 1
fi

echo "cargo-audit policy contract: PASS"
