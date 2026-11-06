#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[[ "$(uname -s)" == Linux ]] || { echo 'Linux root ancestry contract requires Linux' >&2; exit 1; }
cd "${ROOT}"
build_messages="$(mktemp)"
trap 'rm -f "${build_messages}"' EXIT
cargo test --locked -p aegis-core --lib --no-run --message-format=json >"${build_messages}"
test_binary="$(jq -rs '
  [.[] | select(.reason == "compiler-artifact" and .target.name == "aegis_core"
    and .profile.test == true and .executable != null) | .executable]
  | if length == 1 then .[0] else error("expected one core test executable") end
' "${build_messages}")"
[[ ! -L "${test_binary}" && -f "${test_binary}" && -x "${test_binary}" ]]
test_binary="$(realpath "${test_binary}")"
case "${test_binary}" in
  "${ROOT}"/target/debug/deps/aegis_core-*) ;;
  *) echo 'unexpected core test executable location' >&2; exit 1 ;;
esac
selector=operator_artifact::tests::linux_root_rejects_foreign_ancestor_and_accepts_isolated_output
listed="$(timeout --kill-after=5s 30s "${test_binary}" --exact "${selector}" --ignored --list)"
printf '%s\n' "${listed}" | awk -v expected="${selector}: test" \
  '$0 == expected { count++ } END { exit count == 1 ? 0 : 1 }' || {
    echo 'native root ancestry contract must select exactly one test' >&2; exit 1;
  }
status=0
executed="$(timeout --kill-after=5s 60s sudo -n -- "${test_binary}" \
  --exact "${selector}" --ignored --nocapture --test-threads=1)" || status=$?
printf '%s\n' "${executed}"
(( status == 0 )) || exit "${status}"
printf '%s\n' "${executed}" | awk \
  '/^test result: ok\. 1 passed; 0 failed; 0 ignored;/ { count++ }
   END { exit count == 1 ? 0 : 1 }' || {
    echo 'native root ancestry contract did not execute exactly one passing test' >&2; exit 1;
  }
