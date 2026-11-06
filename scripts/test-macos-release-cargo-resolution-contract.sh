#!/usr/bin/env bash
# Phase 5.0.C contract: `scripts/build-macos-client-tarball.sh` must
# invoke cargo via a resolved binary path (`${CARGO_BIN}`), not via a
# bare `cargo` token that gets bound by `$PATH` lookup. The macOS
# GitHub runner (observed 2026-05-14) ships a `cargo` shim in PATH
# that's actually `rustup-init`, which has no `run` subcommand. The
# build script must defend against that.
#
# This test is static: it greps the script for any remaining bare
# `cargo run` / `cargo build` invocations. Any match is a failure.
# We also verify the CARGO_BIN resolution block exists and uses
# `rustup which cargo`.
#
# Runs offline. No real macOS build.

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${ROOT}/scripts/build-macos-client-tarball.sh"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

[[ -f "${SCRIPT}" ]] || fail "missing ${SCRIPT}"

# 1) CARGO_BIN must be defined and assigned via rustup-which.
grep -q '^CARGO_BIN="cargo"$' "${SCRIPT}" \
  || fail "expected CARGO_BIN baseline assignment 'CARGO_BIN=\"cargo\"'"
grep -q 'rustup which cargo' "${SCRIPT}" \
  || fail "expected rustup-which-cargo resolution in build script"

# 2) No remaining bare `cargo run` or `cargo build` invocations.
bare_run="$(grep -nE '^[[:space:]]*cargo (run|build)' "${SCRIPT}" || true)"
[[ -z "${bare_run}" ]] \
  || fail "bare 'cargo run' / 'cargo build' found (must use \${CARGO_BIN}):
${bare_run}"

# 3) Every cargo invocation in the script should go through CARGO_BIN.
cargo_call_count="$(grep -cE '"\$\{CARGO_BIN\}" (run|build)' "${SCRIPT}")"
[[ "${cargo_call_count}" -ge 3 ]] \
  || fail "expected at least 3 \${CARGO_BIN} invocations (metadata, build, manifest, sha256), found ${cargo_call_count}"

# 4) Shellcheck-friendly sanity: the resolution block falls back to
#    the PATH cargo when rustup is absent (e.g. local dev box without
#    rustup). This keeps the script working on hosts that have plain
#    cargo without rustup.
grep -q 'command -v rustup' "${SCRIPT}" \
  || fail "expected 'command -v rustup' guard for non-rustup environments"

# 5) The release.yml workflow still wires this script into the
#    macOS job. If someone refactors the workflow off this script,
#    the contract loses coverage.
WORKFLOW="${ROOT}/.github/workflows/release.yml"
if [[ -f "${WORKFLOW}" ]]; then
  grep -q 'build-macos-client-tarball.sh' "${WORKFLOW}" \
    || fail "release.yml no longer references build-macos-client-tarball.sh"
fi

echo "ok: macOS release cargo resolution (CARGO_BIN via rustup-which, no bare 'cargo run/build')"
