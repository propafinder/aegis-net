#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE="$(mktemp -d)"
trap 'rm -rf "${FIXTURE}"' EXIT

mkdir -p "${FIXTURE}/scripts" "${FIXTURE}/bin" \
  "${FIXTURE}/third_party/h2" "${FIXTURE}/third_party/tungstenite" \
  "${FIXTURE}/tools/macos/aegis-network-extension" "${FIXTURE}/tools/extra"
cp "${ROOT}/scripts/check-cargo-lockfiles.sh" "${FIXTURE}/scripts/"
printf '[workspace]\n' > "${FIXTURE}/Cargo.toml"
printf '# root lock\n' > "${FIXTURE}/Cargo.lock"
printf '[package]\nname = "h2"\nversion = "0.4.16"\n' > "${FIXTURE}/third_party/h2/Cargo.toml"
printf '# h2 lock\n' > "${FIXTURE}/third_party/h2/Cargo.lock"
printf '[package]\nname = "tungstenite"\nversion = "0.24.0"\n' > "${FIXTURE}/third_party/tungstenite/Cargo.toml"
printf '# tungstenite lock\n' > "${FIXTURE}/third_party/tungstenite/Cargo.lock"
printf '[workspace]\n' > "${FIXTURE}/tools/macos/aegis-network-extension/Cargo.toml"
printf '# extension lock\n' > "${FIXTURE}/tools/macos/aegis-network-extension/Cargo.lock"
printf '[workspace]\n' > "${FIXTURE}/tools/extra/Cargo.toml"
printf '# extra lock\n' > "${FIXTURE}/tools/extra/Cargo.lock"
printf 'untracked poison\n' > "${FIXTURE}/third_party/h2/poison"
git -C "${FIXTURE}" init -q
git -C "${FIXTURE}" add -- Cargo.toml Cargo.lock scripts/check-cargo-lockfiles.sh \
  third_party/h2/Cargo.toml third_party/h2/Cargo.lock \
  third_party/tungstenite/Cargo.toml third_party/tungstenite/Cargo.lock \
  tools/macos/aegis-network-extension/Cargo.toml tools/macos/aegis-network-extension/Cargo.lock \
  tools/extra/Cargo.toml tools/extra/Cargo.lock

cat > "${FIXTURE}/bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == metadata ]]
args=" $* "
[[ "${args}" == *' --locked '* && "${args}" == *' --offline '* && \
   "${args}" == *' --format-version 1 '* && \
   "${args}" != *' --no-deps '* ]]
manifest=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == --manifest-path ]]; then
    manifest="$2"
    break
  fi
  shift
done
[[ -n "${manifest}" && -f "${manifest}" ]]
case "${manifest}" in
  "${AEGIS_LOCK_TEST_ROOT}/Cargo.toml") name=root ;;
  "${AEGIS_LOCK_TEST_ROOT}/tools/macos/aegis-network-extension/Cargo.toml") name=extension ;;
  "${AEGIS_LOCK_TEST_ROOT}/tools/extra/Cargo.toml") name=extra ;;
  */third_party/h2/Cargo.toml)
    name=h2
    [[ "${manifest}" != "${AEGIS_LOCK_TEST_ROOT}/third_party/h2/Cargo.toml" ]]
    [[ ! -e "$(dirname "${manifest}")/poison" ]]
    cmp "$(dirname "${manifest}")/Cargo.lock" "${AEGIS_LOCK_TEST_ROOT}/third_party/h2/Cargo.lock"
    ;;
  */third_party/tungstenite/Cargo.toml)
    name=tungstenite
    [[ "${manifest}" != "${AEGIS_LOCK_TEST_ROOT}/third_party/tungstenite/Cargo.toml" ]]
    cmp "$(dirname "${manifest}")/Cargo.lock" "${AEGIS_LOCK_TEST_ROOT}/third_party/tungstenite/Cargo.lock"
    ;;
  *) exit 96 ;;
esac
printf '%s\n' "${name}" >> "${AEGIS_LOCK_TEST_OBSERVED}"
[[ "${AEGIS_LOCK_TEST_MODE:-pass}" != "fail-${name}" ]] || exit 37
if [[ "${AEGIS_LOCK_TEST_MODE:-pass}" == drift-h2 && "${name}" == h2 ]]; then
  printf '# drift\n' >> "$(dirname "${manifest}")/Cargo.lock"
fi
if [[ "${AEGIS_LOCK_TEST_MODE:-pass}" == drift-root && "${name}" == root ]]; then
  printf '# drift\n' >> "${AEGIS_LOCK_TEST_ROOT}/Cargo.lock"
fi
EOF
chmod +x "${FIXTURE}/bin/cargo"
export PATH="${FIXTURE}/bin:${PATH}"
export AEGIS_LOCK_TEST_ROOT="${FIXTURE}"
export AEGIS_LOCK_TEST_OBSERVED="${FIXTURE}/observed"

: > "${AEGIS_LOCK_TEST_OBSERVED}"
bash "${FIXTURE}/scripts/check-cargo-lockfiles.sh" > "${FIXTURE}/pass.stdout"
grep -Fq 'Cargo lockfiles checked: 5; failures: 0' "${FIXTURE}/pass.stdout"
printf 'root\nh2\ntungstenite\nextra\nextension\n' > "${FIXTURE}/expected"
cmp "${AEGIS_LOCK_TEST_OBSERVED}" "${FIXTURE}/expected"

if AEGIS_LOCK_TEST_MODE=fail-extension \
    bash "${FIXTURE}/scripts/check-cargo-lockfiles.sh" > "${FIXTURE}/failure.stdout" 2> "${FIXTURE}/failure.stderr"; then
  echo 'cargo metadata failure was accepted' >&2
  exit 1
fi
grep -Fq 'FAIL tools/macos/aegis-network-extension/Cargo.lock: cargo metadata --locked --offline' "${FIXTURE}/failure.stderr"

if AEGIS_LOCK_TEST_MODE=drift-h2 \
    bash "${FIXTURE}/scripts/check-cargo-lockfiles.sh" > "${FIXTURE}/drift.stdout" 2> "${FIXTURE}/drift.stderr"; then
  echo 'isolated lock mutation was accepted' >&2
  exit 1
fi
grep -Fq 'FAIL third_party/h2/Cargo.lock: Cargo.lock changed during metadata' "${FIXTURE}/drift.stderr"
printf '# h2 lock\n' | cmp - "${FIXTURE}/third_party/h2/Cargo.lock"

if AEGIS_LOCK_TEST_MODE=drift-root \
    bash "${FIXTURE}/scripts/check-cargo-lockfiles.sh" > "${FIXTURE}/root-drift.stdout" 2> "${FIXTURE}/root-drift.stderr"; then
  echo 'direct root lock mutation was accepted' >&2
  exit 1
fi
grep -Fq 'FAIL Cargo.lock: Cargo.lock changed during metadata' "${FIXTURE}/root-drift.stderr"
printf '# root lock\n' > "${FIXTURE}/Cargo.lock"

rm "${FIXTURE}/tools/macos/aegis-network-extension/Cargo.toml"
if bash "${FIXTURE}/scripts/check-cargo-lockfiles.sh" > "${FIXTURE}/missing.stdout" 2> "${FIXTURE}/missing.stderr"; then
  echo 'missing sibling manifest was accepted' >&2
  exit 1
fi
grep -Fq 'FAIL tools/macos/aegis-network-extension/Cargo.lock: tracked regular Cargo.lock and sibling Cargo.toml required' "${FIXTURE}/missing.stderr"
printf '[workspace]\n' > "${FIXTURE}/tools/macos/aegis-network-extension/Cargo.toml"

git -C "${FIXTURE}" rm --cached -q -- tools/macos/aegis-network-extension/Cargo.lock
if bash "${FIXTURE}/scripts/check-cargo-lockfiles.sh" > "${FIXTURE}/staged-delete.stdout" 2> "${FIXTURE}/staged-delete.stderr"; then
  echo 'staged deletion of required lock was accepted' >&2
  exit 1
fi
grep -Fq 'FAIL tools/macos/aegis-network-extension/Cargo.lock: required Cargo.lock is not tracked' "${FIXTURE}/staged-delete.stderr"

echo 'Cargo lockfile preflight contract: PASS'
