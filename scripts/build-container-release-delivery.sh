#!/usr/bin/env bash
set -euo pipefail

# Only the fresh, separately mounted output becomes root-owned. The checkout,
# build cache and guarded artifact reader keep their existing trust boundaries.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT=/aegis-delivery
readonly ROOT OUTPUT
[[ "$(uname -s)" == Linux && "${EUID}" == 0 ]] || {
  echo 'container delivery requires Linux root' >&2; exit 1;
}
delivery_uid="${AEGIS_DELIVERY_UID:-}"
delivery_gid="${AEGIS_DELIVERY_GID:-}"
for identity in "${delivery_uid}" "${delivery_gid}"; do
  [[ "${identity}" =~ ^(0|[1-9][0-9]{0,9})$ ]] &&
    (( identity <= 4294967294 )) || {
      echo 'container delivery requires explicit numeric runner ownership' >&2; exit 1;
    }
done
readonly delivery_uid delivery_gid

no_nested_mounts() {
  awk '$5 ~ /^\/aegis-delivery\// { found = 1 } END { exit found ? 1 : 0 }' /proc/self/mountinfo
}
[[ -d "${OUTPUT}" && ! -L "${OUTPUT}" ]] && mountpoint -q "${OUTPUT}" &&
  no_nested_mounts || { echo 'delivery output must be an isolated mount' >&2; exit 1; }
[[ "$(stat -c '%u:%g' "${OUTPUT}")" == "${delivery_uid}:${delivery_gid}" ]] || {
  echo 'delivery mount owner does not match runner identity' >&2; exit 1;
}
delivery_contents="$(find -P "${OUTPUT}" -mindepth 1 -maxdepth 1 -printf x -quit)" || {
  echo 'delivery output enumeration failed' >&2; exit 1;
}
[[ -z "${delivery_contents}" ]] || {
  echo 'delivery output must be fresh and empty' >&2; exit 1;
}
delivery_mount_identity="$(stat -c '%d:%i' "${OUTPUT}")"
readonly delivery_mount_identity

handoff_output() {
  local builder_status=$? restore_status=0
  trap - EXIT
  if [[ -d "${OUTPUT}" && ! -L "${OUTPUT}" ]] &&
    mountpoint -q "${OUTPUT}" && no_nested_mounts &&
    [[ "$(stat -c '%d:%i' "${OUTPUT}")" == "${delivery_mount_identity}" ]]; then
    # -P and chown -h never follow links; -depth hands the root back last.
    # Reject nested mounts first: -xdev alone cannot reject same-device binds.
    timeout --kill-after=5s 30s find -P "${OUTPUT}" -xdev -depth \
      -exec chown -h -- "${delivery_uid}:${delivery_gid}" {} + || restore_status=$?
  else
    restore_status=1
  fi
  if (( restore_status != 0 )); then
    echo 'delivery output ownership handoff failed' >&2
    (( builder_status != 0 )) || builder_status=${restore_status}
  fi
  exit "${builder_status}"
}
trap handoff_output EXIT
chown -- 0:0 "${OUTPUT}"
chmod 0700 "${OUTPUT}"
bash "${ROOT}/scripts/build-release-delivery.sh" "${OUTPUT}" "$@"
