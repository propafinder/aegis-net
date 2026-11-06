#!/usr/bin/env bash
# Shared status helpers for guarded CI smoke steps.
GUARDED_SMOKE_ARTIFACT_DIR=""
GUARDED_SMOKE_ARTIFACT_ID=""
GUARDED_SMOKE_EVIDENCE_DIR=""

# Root producers must not write receipts into a runner-owned or shared TMPDIR.
# /run prevents the runner from replacing the parent after allocation.
guarded_smoke_artifacts_init() {
  GUARDED_SMOKE_ARTIFACT_DIR="$(sudo -n /usr/bin/mktemp -d /run/aegis-ci-smoke-artifacts.XXXXXXXX)" || return 1
  [[ "${GUARDED_SMOKE_ARTIFACT_DIR}" =~ ^/run/aegis-ci-smoke-artifacts\.[[:alnum:]]{8}$ ]] || return 1
  GUARDED_SMOKE_ARTIFACT_ID="$(sudo -n /usr/bin/stat -c '%d:%i' "${GUARDED_SMOKE_ARTIFACT_DIR}")" || return 1
  GUARDED_SMOKE_EVIDENCE_DIR="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/aegis-guarded-smoke-evidence.XXXXXXXX")" || return 1
}

guarded_smoke_artifacts_cleanup() {
  [[ -n "${GUARDED_SMOKE_ARTIFACT_DIR}" ]] || return 0
  [[ "${GUARDED_SMOKE_ARTIFACT_DIR}" =~ ^/run/aegis-ci-smoke-artifacts\.[[:alnum:]]{8}$ ]] || return 1
  local actual=""
  actual="$(sudo -n /usr/bin/stat -c '%u:%g:%a:%d:%i' "${GUARDED_SMOKE_ARTIFACT_DIR}")" || return 1
  [[ "${actual}" == "0:0:700:${GUARDED_SMOKE_ARTIFACT_ID}" ]] || return 1
  local leaf=""
  for leaf in contract.json runtime-events.jsonl; do
    if sudo -n /usr/bin/test -e "${GUARDED_SMOKE_ARTIFACT_DIR}/${leaf}" || sudo -n /usr/bin/test -L "${GUARDED_SMOKE_ARTIFACT_DIR}/${leaf}"; then
      sudo -n /usr/bin/test ! -L "${GUARDED_SMOKE_ARTIFACT_DIR}/${leaf}" || return 1
      sudo -n /usr/bin/test -f "${GUARDED_SMOKE_ARTIFACT_DIR}/${leaf}" || return 1
      # The caller opens its private destination; sudo only reads the receipt.
      (umask 077; sudo -n /usr/bin/cat "${GUARDED_SMOKE_ARTIFACT_DIR}/${leaf}" > "${GUARDED_SMOKE_EVIDENCE_DIR}/${leaf}") || return 1
    fi
  done
  printf 'GUARDED_SMOKE_EVIDENCE=%s\n' "${GUARDED_SMOKE_EVIDENCE_DIR}"
  sudo -n /usr/bin/rm -f -- "${GUARDED_SMOKE_ARTIFACT_DIR}/contract.json" \
    "${GUARDED_SMOKE_ARTIFACT_DIR}/runtime-events.jsonl" || return 1
  # Unknown inventory is retained. Never recursively remove a staging path.
  sudo -n /usr/bin/rmdir -- "${GUARDED_SMOKE_ARTIFACT_DIR}" || return 1
  GUARDED_SMOKE_ARTIFACT_DIR=""
  GUARDED_SMOKE_ARTIFACT_ID=""
}

guarded_smoke_status_dir() {
  local base="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
  printf '%s/aegis-guarded-smoke-status' "${base}"
}

guarded_smoke_status_init() {
  local name="$1"
  local dir=""
  dir="$(guarded_smoke_status_dir)"
  mkdir -p "${dir}"
  GUARDED_SMOKE_STATUS_FILE="${dir}/${name}.txt"
  export GUARDED_SMOKE_STATUS_FILE
}

guarded_smoke_status_write() {
  printf '%s\n' "$1" > "${GUARDED_SMOKE_STATUS_FILE}"
}
