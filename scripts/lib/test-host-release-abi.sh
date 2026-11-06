#!/usr/bin/env bash

# Test-only helper for release fixtures that are built and executed on the
# current Linux host.  Production release builders must not call this: their
# default GLIBC_2.34 ceiling is enforced by scripts/lib/release-abi.sh and the
# AlmaLinux 9 release job.
aegis_test_use_host_release_abi() {
  local contract_name="${1:-release contract}"
  local host_glibc_version

  if [[ "$(uname -s)" != "Linux" ]]; then
    return 0
  fi
  if ! command -v getconf >/dev/null 2>&1; then
    echo "getconf is required to determine host glibc for ${contract_name}" >&2
    return 1
  fi

  host_glibc_version="$(getconf GNU_LIBC_VERSION | awk '{print $2}')"
  if [[ ! "${host_glibc_version}" =~ ^[0-9]+(\.[0-9]+)+$ ]]; then
    echo "could not determine host glibc for ${contract_name}" >&2
    return 1
  fi
  export AEGIS_RELEASE_MAX_GLIBC="${host_glibc_version}"
}
