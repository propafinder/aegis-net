#!/usr/bin/env bash
# The caller supplies ROOT; this helper runs before any Cargo build.
verify_release_toolchain() {
  local expected actual
  expected="$(sed -n 's/^channel = "\([0-9][0-9.]*\)"$/\1/p' "${ROOT}/rust-toolchain.toml")"
  actual="$(rustc --version | awk '{print $2}')"
  if [[ -z "${expected}" || "${actual}" != "${expected}" ]]; then
    echo "release requires the exact rust-toolchain.toml compiler; found ${actual}, expected ${expected:-missing pin}" >&2
    return 1
  fi
}

release_source_timestamp() {
  # Build metadata is stable across attempts from the same commit. This does
  # not claim bit-for-bit reproducibility of the native linker/tool packages.
  git -C "${ROOT}" show -s --format=%cI HEAD
}
