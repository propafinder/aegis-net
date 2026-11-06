#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

release_crates=(
  aegis-client
  aegis-core
  aegis-geneva
  aegis-quic-boring
  aegis-server
)

version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' aegis-client/Cargo.toml | head -1)"
if [[ -z "${version}" ]]; then
  echo "could not resolve release version from aegis-client/Cargo.toml" >&2
  exit 1
fi

for crate in "${release_crates[@]}"; do
  crate_version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "${crate}/Cargo.toml" | head -1)"
  if [[ "${crate_version}" != "${version}" ]]; then
    echo "release version mismatch: ${crate}=${crate_version}, expected=${version}" >&2
    exit 1
  fi
done

notes="docs/RELEASE-NOTES-${version}.md"
if [[ ! -f "${notes}" ]]; then
  echo "missing release notes for ${version}: ${notes}" >&2
  exit 1
fi
grep -Fq "# AEGIS ${version}" "${notes}"

metadata_versions="$(cargo metadata --locked --no-deps --format-version 1 | jq -r '
  .packages[] |
  select(.name == "aegis-client" or .name == "aegis-core" or
         .name == "aegis-geneva" or .name == "aegis-quic-boring" or
         .name == "aegis-server") |
  "\(.name)=\(.version)"
')"
for crate in "${release_crates[@]}"; do
  grep -Fxq "${crate}=${version}" <<<"${metadata_versions}"
done

echo "PASS: release version ${version} is consistent across manifests, lockfile metadata and notes"
