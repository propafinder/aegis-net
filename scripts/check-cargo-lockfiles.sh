#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROSTER="$(mktemp)"
TRACKED="$(mktemp)"
ISOLATION="$(mktemp -d)"
trap 'rm -f "${ROSTER}" "${TRACKED}"; rm -rf "${ISOLATION}"' EXIT

# Each independently locked workspace must resolve from its own tracked lock.
git -C "${ROOT}" ls-files -z -- '*Cargo.lock' > "${ROSTER}"
[[ -s "${ROSTER}" ]] || {
  echo 'No tracked Cargo.lock files found' >&2
  exit 1
}

checked=0
failed=0
for required in \
  Cargo.lock \
  third_party/h2/Cargo.lock \
  third_party/tungstenite/Cargo.lock \
  tools/macos/aegis-network-extension/Cargo.lock; do
  if ! git -C "${ROOT}" ls-files --error-unmatch -- "${required}" > /dev/null 2>&1; then
    echo "FAIL ${required}: required Cargo.lock is not tracked" >&2
    failed=$((failed + 1))
  fi
done

while IFS= read -r -d '' lockfile; do
  manifest="${lockfile%Cargo.lock}Cargo.toml"
  if [[ ! -f "${ROOT}/${lockfile}" || -L "${ROOT}/${lockfile}" || \
        ! -f "${ROOT}/${manifest}" || -L "${ROOT}/${manifest}" ]] || \
     ! git -C "${ROOT}" ls-files --error-unmatch -- "${manifest}" > /dev/null 2>&1; then
    echo "FAIL ${lockfile}: tracked regular Cargo.lock and sibling Cargo.toml required" >&2
    failed=$((failed + 1))
    continue
  fi

  checked=$((checked + 1))
  manifest_path="${ROOT}/${manifest}"
  lock_path="${ROOT}/${lockfile}"
  snapshot_path="${ISOLATION}/snapshots/${lockfile}"
  mkdir -p "$(dirname "${snapshot_path}")"
  cp "${ROOT}/${lockfile}" "${snapshot_path}"
  # A vendored package under the root workspace may have its own upstream
  # Cargo.lock without declaring a workspace. Cargo otherwise uses the parent
  # workspace and never examines that sibling lock. Resolve only tracked files
  # in a temporary copy of the package.
  if [[ "${manifest}" != Cargo.toml ]] && \
     ! grep -Eq '^[[:space:]]*\[workspace\][[:space:]]*$' "${manifest_path}"; then
    package_dir="${manifest%/Cargo.toml}"
    git -C "${ROOT}" ls-files -z -- "${package_dir}" > "${TRACKED}"
    while IFS= read -r -d '' source_file; do
      if [[ ! -f "${ROOT}/${source_file}" || -L "${ROOT}/${source_file}" ]]; then
        echo "FAIL ${lockfile}: tracked package member ${source_file} is not a regular file" >&2
        failed=$((failed + 1))
        continue
      fi
      mkdir -p "${ISOLATION}/$(dirname "${source_file}")"
      cp "${ROOT}/${source_file}" "${ISOLATION}/${source_file}"
    done < "${TRACKED}"
    manifest_path="${ISOLATION}/${manifest}"
    lock_path="${ISOLATION}/${lockfile}"
  fi

  if cargo metadata \
      --manifest-path "${manifest_path}" \
      --format-version 1 --locked --offline > /dev/null; then
    metadata_ok=1
  else
    echo "FAIL ${lockfile}: cargo metadata --locked --offline" >&2
    failed=$((failed + 1))
    metadata_ok=0
  fi
  if ! cmp -s "${snapshot_path}" "${ROOT}/${lockfile}" || \
     ! cmp -s "${snapshot_path}" "${lock_path}"; then
    echo "FAIL ${lockfile}: Cargo.lock changed during metadata" >&2
    failed=$((failed + 1))
  elif [[ "${metadata_ok}" -eq 1 ]]; then
    echo "PASS ${lockfile}"
  fi
done < "${ROSTER}"

echo "Cargo lockfiles checked: ${checked}; failures: ${failed}"
[[ "${failed}" -eq 0 ]]
