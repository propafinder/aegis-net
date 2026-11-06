#!/usr/bin/env bash
set -euo pipefail

# CI invokes this in a private mount namespace. The builder is an inert fixture;
# this checks real UID/mount/link custody, not delivery or installed acceptance.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[[ "$(uname -s)" == Linux && "${EUID}" == 0 ]]
[[ ! -e /aegis-delivery && ! -L /aegis-delivery ]]
fixture="$(mktemp -d)"
cleanup() {
  local status=$?
  trap - EXIT
  if mountpoint -q /aegis-delivery/nested; then umount /aegis-delivery/nested; fi
  if mountpoint -q /aegis-delivery; then umount /aegis-delivery; fi
  rmdir /aegis-delivery
  rm -rf -- "${fixture}"
  exit "${status}"
}
mkdir /aegis-delivery
trap cleanup EXIT
mkdir -p "${fixture}/source/scripts" "${fixture}/external"
cp "${ROOT}/scripts/build-container-release-delivery.sh" "${fixture}/source/scripts/"
cmp "${ROOT}/scripts/build-container-release-delivery.sh" "${fixture}/source/scripts/build-container-release-delivery.sh"
printf 'outside sentinel\n' >"${fixture}/external/keep"
chown 65534:65534 "${fixture}/external" "${fixture}/external/keep"
outside_before="$(stat -c '%u:%g:%a:%s' "${fixture}/external/keep")"
outside_hash="$(sha256sum "${fixture}/external/keep")"
cat >"${fixture}/source/scripts/build-release-delivery.sh" <<'BUILDER'
#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[[ "$1" == /aegis-delivery && "$(stat -c '%u:%g:%a' "$1")" == 0:0:700 ]]
printf 'inert output\n' >"$1/operator"
chmod 0600 "$1/operator"
ln -s "${ROOT}/../external/keep" "$1/outside-link"
case "$(cat "${ROOT}/scenario")" in
  success) exit 0 ;;
  fail) exit 23 ;;
  nested-fail|nested-success)
    mkdir "$1/nested"
    mount --bind "${ROOT}/../external" "$1/nested"
    [[ "$(cat "${ROOT}/scenario")" == nested-success ]] && exit 0
    exit 27 ;;
  *) exit 99 ;;
esac
BUILDER

new_output() {
  if mountpoint -q /aegis-delivery/nested; then umount /aegis-delivery/nested; fi
  if mountpoint -q /aegis-delivery; then umount /aegis-delivery; fi
  mkdir "${fixture}/$1"
  chmod 0700 "${fixture}/$1"
  chown 65534:65534 "${fixture}/$1"
  mount --bind "${fixture}/$1" /aegis-delivery
}
invoke() {
  local expected=$1 status=0
  AEGIS_DELIVERY_UID=65534 AEGIS_DELIVERY_GID=65534 \
    bash "${fixture}/source/scripts/build-container-release-delivery.sh" || status=$?
  [[ "${status}" == "${expected}" ]]
  [[ "$(stat -c '%u:%g:%a:%s' "${fixture}/external/keep")" == "${outside_before}" ]]
  [[ "$(sha256sum "${fixture}/external/keep")" == "${outside_hash}" ]]
}
for scenario in success fail nested-fail nested-success; do
  new_output "${scenario}"
  printf '%s\n' "${scenario}" >"${fixture}/source/scenario"
  case "${scenario}" in
    success) invoke 0 ;;
    fail) invoke 23 ;;
    nested-fail) invoke 27 ;;
    nested-success) invoke 1 ;;
  esac
  if [[ "${scenario}" == success || "${scenario}" == fail ]]; then
    [[ "$(stat -c '%u:%g:%a' /aegis-delivery)" == 65534:65534:700 ]]
    [[ "$(stat -c '%u:%g:%a' /aegis-delivery/operator)" == 65534:65534:600 ]]
    [[ "$(stat -c '%u:%g' /aegis-delivery/outside-link)" == 65534:65534 ]]
  else
    [[ "$(stat -c '%u:%g' /aegis-delivery)" == 0:0 ]]
  fi
done
new_output existing
printf 'retained failed output\n' >/aegis-delivery/prior-attempt
existing_before="$(stat -c '%u:%g:%a' /aegis-delivery)"
invoke 1
[[ "$(stat -c '%u:%g:%a' /aegis-delivery)" == "${existing_before}" ]]
[[ "$(cat /aegis-delivery/prior-attempt)" == 'retained failed output' ]]
new_output wrong-owner
status=0
AEGIS_DELIVERY_UID=0 AEGIS_DELIVERY_GID=0 \
  bash "${fixture}/source/scripts/build-container-release-delivery.sh" || status=$?
[[ "${status}" == 1 && "$(stat -c '%u:%g' /aegis-delivery)" == 65534:65534 ]]
new_output enumeration-error
mkdir "${fixture}/fault-bin"
# Fault injection affects only the enumeration command's error result. Actual
# mount/UID checks run natively; the unchanged helper must refuse empty stdout
# with a nonzero status before invoking its inert builder or changing ownership.
cat >"${fixture}/fault-bin/find" <<'FIND'
#!/usr/bin/env bash
exit 44
FIND
chmod 0700 "${fixture}/fault-bin/find"
status=0
PATH="${fixture}/fault-bin:${PATH}" AEGIS_DELIVERY_UID=65534 AEGIS_DELIVERY_GID=65534 \
  bash "${fixture}/source/scripts/build-container-release-delivery.sh" || status=$?
[[ "${status}" == 1 && "$(stat -c '%u:%g' /aegis-delivery)" == 65534:65534 ]]
[[ ! -e /aegis-delivery/operator ]]
printf 'native isolated delivery custody contracts PASS\n'
