#!/usr/bin/env bash
# Synthetic builder: proves lock drift aborts before packaging or signing.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
FIXTURE="$(mktemp -d)"
finish_fixture() {
  local result=$? name
  if [[ "${result}" -ne 0 ]]; then
    for name in stdout stderr calls; do
      if [[ -f "${FIXTURE}/${name}" ]]; then
        printf 'release lock fixture diagnostic: %s\n' "${name}" >&2
        tail -n 40 "${FIXTURE}/${name}" >&2
      fi
    done
  fi
  rm -rf -- "${FIXTURE}"
  exit "${result}"
}
trap finish_fixture EXIT
mkdir -p "${FIXTURE}/scripts/lib" "${FIXTURE}/home/.cargo/bin" "${FIXTURE}/target/release"
cp "${ROOT}/scripts/build-release-bundle.sh" "${FIXTURE}/scripts/"
cp "${ROOT}/scripts/lib/host-arch.sh" "${FIXTURE}/scripts/lib/"
cp "${ROOT}/scripts/lib/release-toolchain.sh" "${FIXTURE}/scripts/lib/"
cp "${ROOT}/rust-toolchain.toml" "${FIXTURE}/"
FIXTURE_RUST_VERSION="$(sed -n 's/^channel = "\([0-9][0-9.]*\)"$/\1/p' "${FIXTURE}/rust-toolchain.toml")"
[[ -n "${FIXTURE_RUST_VERSION}" ]]
printf 'original fixture lock\n' > "${FIXTURE}/Cargo.lock"
cat > "${FIXTURE}/home/.cargo/bin/rustc" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 1 && "$1" == --version ]] || exit 92
printf 'rustc %s\n' "$*" >> "${AEGIS_LOCK_TEST_ROOT}/calls"
printf 'rustc %s (fixture)\n' "${AEGIS_LOCK_TEST_RUST_VERSION:?}"
SH
cat > "${FIXTURE}/home/.cargo/bin/cargo" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ " $* " == *' --locked '* ]] || exit 91
printf '%s\n' "$*" >> "${AEGIS_LOCK_TEST_ROOT}/calls"
if [[ " $* " == *' release-package-metadata '* ]]; then
  printf '%s\n1.2.3\n' "${AEGIS_LOCK_TEST_ROOT}/target"
elif [[ " $* " == *' build '* ]]; then
  printf 'changed fixture lock\n' > "${AEGIS_LOCK_TEST_ROOT}/Cargo.lock"
fi
SH
cat > "${FIXTURE}/home/.cargo/bin/cmake" <<'SH'
#!/usr/bin/env bash
exit 0
SH
chmod +x "${FIXTURE}/home/.cargo/bin/"*
if HOME="${FIXTURE}/home" AEGIS_LOCK_TEST_ROOT="${FIXTURE}" AEGIS_LOCK_TEST_RUST_VERSION="${FIXTURE_RUST_VERSION}" AEGIS_BUILD_GIT_SHA="fixture" AEGIS_BUILD_TIMESTAMP="2026-09-11T00:00:00Z" \
  bash "${FIXTURE}/scripts/build-release-bundle.sh" "${FIXTURE}/out" \
  >"${FIXTURE}/stdout" 2>"${FIXTURE}/stderr"; then
  echo 'FAIL: build accepted changed Cargo.lock' >&2; exit 1
fi
grep -Fq 'Cargo.lock changed during release build' "${FIXTURE}/stderr"
grep -Fqx 'rustc --version' "${FIXTURE}/calls"
[[ ! -e "${FIXTURE}/out/aegis-1.2.3-linux-x86_64.tar.gz" ]]
if grep -Eq 'build-release-bundle-manifest|write-archive-sha256' "${FIXTURE}/calls"; then
  echo 'FAIL: metadata packaging reached after lock drift' >&2; exit 1
fi
printf '%s\n' 'PASS: every builder Cargo invocation is locked; changed lock stops before package metadata and archive generation'
