#!/usr/bin/env bash

# Verify that generic Linux release binaries do not import GLIBC symbols newer
# than the advertised runtime baseline. The caller receives the measured values
# through exported variables so bundle/package manifests can record the same
# proof that was enforced before publication.
verify_linux_release_abi() {
  local server_binary="$1"
  local client_binary="$2"
  local bridge_binary="${3:-}"
  local measure_binary="${4:-}"
  local transport_lab_binary="${5:-}"
  local administrative_binary="${6:-}"
  local abi_pair=""
  local binary_name=""
  local required_glibc=""

  if [[ "$(uname -s)" != "Linux" ]]; then
    export AEGIS_RELEASE_MAX_GLIBC="not-checked-non-linux-host"
    export AEGIS_SERVER_REQUIRED_GLIBC="not-checked-non-linux-host"
    export AEGIS_CLIENT_REQUIRED_GLIBC="not-checked-non-linux-host"
    return 0
  fi

  if ! command -v readelf >/dev/null 2>&1; then
    echo "readelf (binutils) is required to verify the Linux release ABI baseline" >&2
    return 1
  fi

  AEGIS_RELEASE_MAX_GLIBC="${AEGIS_RELEASE_MAX_GLIBC:-2.34}"
  if [[ ! "${AEGIS_RELEASE_MAX_GLIBC}" =~ ^[0-9]+(\.[0-9]+)+$ ]]; then
    echo "invalid AEGIS_RELEASE_MAX_GLIBC baseline: ${AEGIS_RELEASE_MAX_GLIBC}" >&2
    return 1
  fi

  max_glibc_requirement() {
    readelf --version-info "$1" \
      | grep -Eo 'GLIBC_[0-9]+(\.[0-9]+)*' \
      | sed 's/^GLIBC_//' \
      | sort -V \
      | tail -n 1
  }

  glibc_requirement_exceeds_baseline() {
    local required="$1"
    local baseline="$2"
    [[ "${required}" != "${baseline}" ]] \
      && [[ "$(printf '%s\n%s\n' "${required}" "${baseline}" | sort -V | tail -n 1)" == "${required}" ]]
  }

  AEGIS_SERVER_REQUIRED_GLIBC="$(max_glibc_requirement "${server_binary}")"
  AEGIS_CLIENT_REQUIRED_GLIBC="$(max_glibc_requirement "${client_binary}")"
  if [[ -z "${AEGIS_SERVER_REQUIRED_GLIBC}" || -z "${AEGIS_CLIENT_REQUIRED_GLIBC}" ]]; then
    echo "could not determine GLIBC symbol requirements for release binaries" >&2
    return 1
  fi

  local abi_pairs=("aegis-server:${AEGIS_SERVER_REQUIRED_GLIBC}" "aegis-client:${AEGIS_CLIENT_REQUIRED_GLIBC}")
  if [[ -n "${bridge_binary}" ]]; then
    AEGIS_GENEVA_REQUIRED_GLIBC="$(max_glibc_requirement "${bridge_binary}")"
    [[ -n "${AEGIS_GENEVA_REQUIRED_GLIBC}" ]] || { echo "could not determine Geneva bridge GLIBC requirement" >&2; return 1; }
    abi_pairs+=("aegis-geneva-bridge:${AEGIS_GENEVA_REQUIRED_GLIBC}")
    export AEGIS_GENEVA_REQUIRED_GLIBC
  fi

  if [[ -n "${measure_binary}" || -n "${transport_lab_binary}" ]]; then
    [[ -n "${measure_binary}" && -n "${transport_lab_binary}" ]] || { echo 'research ABI pair is incomplete' >&2; return 1; }
    AEGIS_MEASURE_REQUIRED_GLIBC="$(max_glibc_requirement "${measure_binary}")"
    AEGIS_TRANSPORT_LAB_REQUIRED_GLIBC="$(max_glibc_requirement "${transport_lab_binary}")"
    [[ -n "${AEGIS_MEASURE_REQUIRED_GLIBC}" && -n "${AEGIS_TRANSPORT_LAB_REQUIRED_GLIBC}" ]] || { echo 'research ABI measurements missing' >&2; return 1; }
    abi_pairs+=("aegis-measure:${AEGIS_MEASURE_REQUIRED_GLIBC}" "aegis-transport-lab:${AEGIS_TRANSPORT_LAB_REQUIRED_GLIBC}")
    export AEGIS_MEASURE_REQUIRED_GLIBC AEGIS_TRANSPORT_LAB_REQUIRED_GLIBC
  fi

  if [[ -n "${administrative_binary}" ]]; then
    AEGIS_ADMIN_MEASURE_REQUIRED_GLIBC="$(max_glibc_requirement "${administrative_binary}")"
    [[ -n "${AEGIS_ADMIN_MEASURE_REQUIRED_GLIBC}" ]] || { echo 'administrative measure ABI measurement missing' >&2; return 1; }
    abi_pairs+=("aegis-measure-administrative:${AEGIS_ADMIN_MEASURE_REQUIRED_GLIBC}")
    export AEGIS_ADMIN_MEASURE_REQUIRED_GLIBC
  fi

  for abi_pair in \
    "${abi_pairs[@]}"; do
    binary_name="${abi_pair%%:*}"
    required_glibc="${abi_pair#*:}"
    if glibc_requirement_exceeds_baseline "${required_glibc}" "${AEGIS_RELEASE_MAX_GLIBC}"; then
      echo "${binary_name} requires GLIBC_${required_glibc}; generic release baseline is GLIBC_${AEGIS_RELEASE_MAX_GLIBC}" >&2
      echo "Build the generic Linux artifact on the Alma/RHEL 9 (glibc 2.34) release builder." >&2
      return 1
    fi
  done

  export AEGIS_RELEASE_MAX_GLIBC AEGIS_SERVER_REQUIRED_GLIBC AEGIS_CLIENT_REQUIRED_GLIBC
}
