#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.cargo/bin:${PATH}"

if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "SKIP: release delivery contract requires dpkg-deb on the builder host" >&2
  exit 0
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-release-delivery.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

if AEGIS_BUILD_GIT_SHA=unknown \
  "${ROOT}/scripts/build-release-delivery.sh" "${TMP_DIR}/unknown" \
  >"${TMP_DIR}/unknown.stdout" 2>"${TMP_DIR}/unknown.stderr"; then
  echo "release delivery accepted unknown source provenance" >&2
  exit 1
fi
grep -Fq "release delivery requires exact source provenance" "${TMP_DIR}/unknown.stderr"

# This contract validates delivery layout on the current CI host. Production
# portable artifacts remain ABI-gated on the AlmaLinux release builder.
# shellcheck source=scripts/lib/test-host-release-abi.sh
. "${ROOT}/scripts/lib/test-host-release-abi.sh"
aegis_test_use_host_release_abi "release-delivery contract"
"${ROOT}/scripts/build-release-delivery.sh" "${TMP_DIR}" >/dev/null

MANIFEST_JSON="${TMP_DIR}/release.manifest.json"
BOOTSTRAP_SH="${TMP_DIR}/bootstrap-install.sh"
EXPECTED_GIT_SHA="$(git -C "${ROOT}" rev-parse HEAD)"

jq -e --arg git_sha "${EXPECTED_GIT_SHA}" '
  .schema == "aegis_linux_release_manifest_v1"
  and .platform == "linux"
  and (.version | length > 0)
  and .git_sha == $git_sha
  and (.build_timestamp | length > 0)
  and (.channel | length > 0)
  and (.prerelease == true or .prerelease == false)
  and (.target_triple | length > 0)
  and .delivery_contract.role_config_install_requires_bundle == true
  and .delivery_contract.server_installer_entrypoint == "./install-server.sh"
  and .delivery_contract.bootstrap_installer_entrypoint == "./bootstrap-install.sh"
  and .artifacts.bundle.status == "ready"
  and .artifacts.deb.status == "ready"
  and .install_matrix.bootstrap_default.artifact == "bundle"
  and (.artifacts.bundle.archive.sha256 | length == 64)
  and (.artifacts.package_root.archive.sha256 | length == 64)
  and (.artifacts.deb.combined.sha256 | length == 64)
  and (.artifacts.deb.split.server.sha256 | length == 64)
  and (.artifacts.deb.split.client.sha256 | length == 64)
  and (.artifacts.rpm.status == "ready" or .artifacts.rpm.status == "unavailable")
  and (
    if .artifacts.rpm.status == "ready"
    then true
    else (.artifacts.rpm.reason | length > 0)
    end
  )
' "${MANIFEST_JSON}" >/dev/null

for path in \
  "${TMP_DIR}/install-server.sh" \
  "${TMP_DIR}/bootstrap-install.sh" \
  "${TMP_DIR}/$(jq -r '.artifacts.bundle.archive.path' "${MANIFEST_JSON}")" \
  "${TMP_DIR}/$(jq -r '.artifacts.bundle.archive.sha256_path' "${MANIFEST_JSON}")" \
  "${TMP_DIR}/$(jq -r '.artifacts.package_root.archive.path' "${MANIFEST_JSON}")" \
  "${TMP_DIR}/$(jq -r '.artifacts.deb.combined.path' "${MANIFEST_JSON}")" \
  "${TMP_DIR}/$(jq -r '.artifacts.deb.split.server.path' "${MANIFEST_JSON}")" \
  "${TMP_DIR}/$(jq -r '.artifacts.deb.split.client.path' "${MANIFEST_JSON}")"; do
  if [[ ! -f "${path}" ]]; then
    echo "missing release delivery artifact: ${path}" >&2
    exit 1
  fi
done

if [[ "$(jq -r '.artifacts.rpm.status' "${MANIFEST_JSON}")" == "ready" ]]; then
  for path in \
    "${TMP_DIR}/$(jq -r '.artifacts.rpm.split.server.path' "${MANIFEST_JSON}")" \
    "${TMP_DIR}/$(jq -r '.artifacts.rpm.split.client.path' "${MANIFEST_JSON}")"; do
    if [[ ! -f "${path}" ]]; then
      echo "missing rpm release delivery artifact: ${path}" >&2
      exit 1
    fi
  done
fi

# The administrative bundle keeps host helpers. Research tools have a separate
# private archive bound into this same signed parent, never a public client leaf.
jq -e '.distribution == "private_administrative_operator" and
    .artifacts.private_research.distribution == "private_research_only" and
    .artifacts.private_research.automatic_service_activation == false and
    .artifacts.private_research.installed_fullwide_owner == false' "${MANIFEST_JSON}" >/dev/null
for field in archive.path archive.sha256_path manifest_path; do
  relative="$(jq -er --arg field "$field" '.artifacts.private_research | getpath($field | split("."))' "${MANIFEST_JSON}")"
  [[ -f "${TMP_DIR}/${relative}" ]] || { echo 'missing private research delivery asset' >&2; exit 1; }
done

# The generic bundle and every native package are one release, not merely
# builds from similar source. The delivery gate must reject provenance/hash
# drift between the canonical bundle and package-root used by deb/rpm.
ARCH="$(jq -r '.arch' "${MANIFEST_JSON}")"
VERSION="$(jq -r '.version' "${MANIFEST_JSON}")"
BUNDLE_BIN_DIR="${TMP_DIR}/aegis-${VERSION}-linux-${ARCH}/bin"
PACKAGE_ROOT_BIN_DIR="${TMP_DIR}/aegis-package-root-${VERSION}-linux-${ARCH}/rootfs/usr/local/bin"
for binary_name in aegis-server aegis-client; do
  cmp "${BUNDLE_BIN_DIR}/${binary_name}" "${PACKAGE_ROOT_BIN_DIR}/${binary_name}"
  "${BUNDLE_BIN_DIR}/${binary_name}" --version | grep -Fq 'cargo-lock '
  if "${BUNDLE_BIN_DIR}/${binary_name}" --version | grep -Fq 'cargo-lock unknown'; then
    echo "release ${binary_name} has unknown Cargo.lock provenance" >&2
    exit 1
  fi
done

# The manifest URL is assembled from a base plus an arch-aware file name
# (AEGIS_MANIFEST_NAME), so asserting one literal URL string breaks the moment
# per-architecture manifests are introduced — which is exactly what happened:
# this check has failed since the aarch64 release work landed, and it took CI
# down with it. Assert the two things that actually matter instead.
grep -Fq -- "propafinder/aegis-release/releases/latest/download" "${BOOTSTRAP_SH}"
grep -Fq -- 'AEGIS_MANIFEST_NAME="release.manifest.json"' "${BOOTSTRAP_SH}"
grep -Fq -- '${AEGIS_MANIFEST_NAME}' "${BOOTSTRAP_SH}"
grep -Fq -- "Installing Ubuntu prerequisites via apt-get" "${BOOTSTRAP_SH}"
grep -Fq -- "install -y \${packages}" "${BOOTSTRAP_SH}"
grep -Fq -- "Unsupported host family for auto-install" "${BOOTSTRAP_SH}"

echo "PASS: release delivery contract"
