#!/usr/bin/env bash
# Run every contract the workflow does not name individually.
#
# The repo had 156 contract scripts and CI ran 46. The other 110 passed when
# anyone ran them by hand and guarded nothing in between, which is the same as
# not having them: an unenforced contract and an unenforceable one look
# identical from the outside.
#
# This inverts the default. Every scripts/test-*contract*.sh runs here unless
# it is either named explicitly in a workflow step or listed in EXCLUDE below
# WITH A REASON. Adding a contract now wires it in automatically; excluding one
# takes a deliberate edit that says why.
#
# Empirically triaged 2026-08-12 on Linux: of the 98 candidates that need only
# cargo, shell, python or root networking, 85 passed as-is.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

# Excluded, each with the reason it cannot run on a plain Linux CI runner.
# Anything not listed here runs. Keep the reasons specific enough that someone
# can tell whether they still apply.
declare -a EXCLUDE=(
  # --- needs a platform this job is not ---
  "macos-bootstrap-tempdir:macOS only"
  "macos-bpf-observer:macOS only"
  "macos-client-service-model:macOS only"
  "macos-networkextension-system-wide-proof:macOS only"
  "macos-release-cargo-resolution:macOS only"
  "macos-utun-w3-relay-path-proof:macOS only"
  "macos-utun-w4-policy-cleanup:macOS only"
  "macos-utun-w5-controlled-external-relay-path:macOS only"
  "macos-wide-pf:macOS only"
  "windows-install-scaffold:Windows only"
  "windows-reboot-proof-powershell-wrapper:Windows only"
  "windows-uninstall-scaffold:Windows only"
  "windows-wide-service-reboot-proof:Windows only"
  "phase-d-windows-dns-udp-next-scope:Windows only"
  "phase-d-windows-reach-evidence:Windows only"
  "windows-wfp-proof-manual:Windows only, manual"
  # --- needs infrastructure a runner does not have ---
  "adversarial-gateway-docker:needs a Docker gateway container"
  "phase-c-fronted-transport-two-vps-live-runner:needs two live VPS"
  "redeploy-two-vps-current-bundle:needs two live VPS"
  "redeploy-two-vps-release:needs two live VPS"
)

is_excluded() {
  local name="$1" entry
  for entry in "${EXCLUDE[@]}"; do
    [[ "${entry%%:*}" == "${name}" ]] && return 0
  done
  return 1
}

named_in_workflow() {
  grep -qF "$1" .github/workflows/*.yml 2>/dev/null
}

run_with_timeout() {
  local script="$1"
  if command -v timeout >/dev/null 2>&1; then
    timeout 420 bash "${script}"
  elif command -v gtimeout >/dev/null 2>&1; then
    gtimeout 420 bash "${script}"
  else
    python3 - "${script}" <<'PY'
import subprocess
import sys

try:
    completed = subprocess.run(["bash", sys.argv[1]], timeout=420, check=False)
except subprocess.TimeoutExpired:
    print(f"contract timed out after 420s: {sys.argv[1]}", file=sys.stderr)
    raise SystemExit(124)
raise SystemExit(completed.returncode)
PY
  fi
}

pass=0; fail=0; skipped=0
declare -a FAILED=()

for script in scripts/test-*contract*.sh; do
  base="$(basename "${script}")"
  name="${base#test-}"; name="${name%-contract.sh}"

  if named_in_workflow "${base}"; then
    continue  # a dedicated step already runs it
  fi
  if is_excluded "${name}"; then
    skipped=$((skipped + 1))
    continue
  fi

  # A cold build inside one contract can take minutes. Emit its name before
  # execution so live CI logs identify the active check instead of appearing
  # stalled until the entire suite finishes. Keep successful command output
  # suppressed; names and elapsed time contain no fixture credentials.
  started_at="${SECONDS}"
  printf 'contract: %s RUNNING\n' "${name}"
  if out="$(run_with_timeout "${script}" 2>&1)"; then
    pass=$((pass + 1))
    printf 'contract: %s PASS (%ss)\n' "${name}" "$((SECONDS - started_at))"
  else
    fail=$((fail + 1))
    FAILED+=("${name}")
    printf 'contract: %s FAIL (%ss)\n' "${name}" "$((SECONDS - started_at))"
    echo "--- FAIL ${name} ---"
    echo "${out}" | tail -20
  fi
done

echo
echo "unwired contracts: ${pass} passed, ${fail} failed, ${skipped} excluded by name"

if [[ ${fail} -gt 0 ]]; then
  echo "failed: ${FAILED[*]}" >&2
  exit 1
fi
