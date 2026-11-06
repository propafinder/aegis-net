#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.cargo/bin:${PATH}"
. "${ROOT}/scripts/lib/release-toolchain.sh"

usage() {
  cat <<'EOF'
Usage:
  scripts/build-release-delivery.sh <output-dir> [--channel <name>] [--prerelease true|false] [--debian-revision <positive-integer>]

Builds the Linux release deliverables and writes an external release manifest:
  - release bundle (.tar.gz + .sha256)
  - package-root baseline
  - combined .deb baseline
  - split .deb packages
  - split .rpm packages when rpmbuild/rpm are available

Outputs:
  <output-dir>/release.manifest.json
EOF
}

if [[ $# -lt 1 ]]; then
  usage >&2
  exit 1
fi

OUTPUT_DIR="$1"
verify_release_toolchain
shift
CHANNEL="stable"
PRERELEASE="false"
DEBIAN_REVISION=""
GIT_SHA="${AEGIS_BUILD_GIT_SHA:-$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')}"
BUILD_TIMESTAMP="${AEGIS_BUILD_TIMESTAMP:-$(release_source_timestamp)}"
if [[ -z "${GIT_SHA}" || "${GIT_SHA}" == "unknown" ]]; then
  echo "release delivery requires exact source provenance; set AEGIS_BUILD_GIT_SHA" >&2
  exit 1
fi
export AEGIS_BUILD_GIT_SHA="${GIT_SHA}"
export AEGIS_BUILD_TIMESTAMP="${BUILD_TIMESTAMP}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --channel)
      CHANNEL="$2"
      shift 2
      ;;
    --prerelease)
      PRERELEASE="$2"
      case "${PRERELEASE}" in
        true|false) ;;
        *)
          echo "--prerelease must be true or false" >&2
          exit 1
          ;;
      esac
      shift 2
      ;;
    --debian-revision)
      DEBIAN_REVISION="${2:-}"
      if [[ ! "${DEBIAN_REVISION}" =~ ^[1-9][0-9]{0,17}$ ]]; then
        echo "Debian revision must be a canonical positive integer" >&2
        exit 1
      fi
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

mkdir -p "${OUTPUT_DIR}"
cp "${ROOT}/bootstrap-install.sh" "${OUTPUT_DIR}/bootstrap-install.sh"
cp "${ROOT}/install-server.sh" "${OUTPUT_DIR}/install-server.sh"

"${ROOT}/scripts/build-package-root.sh" "${OUTPUT_DIR}" >/dev/null
"${ROOT}/scripts/build-deb-package.sh" "${OUTPUT_DIR}" >/dev/null
split_args=()
if [[ -n "${DEBIAN_REVISION}" ]]; then
  split_args=(--debian-revision "${DEBIAN_REVISION}")
fi
"${ROOT}/scripts/build-split-deb-packages.sh" "${OUTPUT_DIR}" "${split_args[@]}" >/dev/null

# The final administrative bundle must seal the exact client package before
# it can authorize a stopped V2 generation to enter dpkg preinst. The split
# package set is built and verified first; its archive bytes then become
# ordinary SHA256SUMS/manifest members of the administrative bundle.
. "${ROOT}/scripts/lib/host-arch.sh"
ARCH="$(host_arch)"
case "${ARCH}" in
  x86_64) DEB_ARCH=amd64 ;;
  aarch64|arm64) DEB_ARCH=arm64 ;;
  armv7l) DEB_ARCH=armhf ;;
  *) echo "unsupported release DEB architecture: ${ARCH}" >&2; exit 1 ;;
esac
META="$(cargo run --locked -q -p aegis-measure -- release-package-metadata --root "${ROOT}")"
VERSION="$(printf '%s\n' "${META}" | sed -n '2p')"
SPLIT_VERSION="${VERSION}"
if [[ -n "${DEBIAN_REVISION}" ]]; then
  SPLIT_VERSION="${VERSION}-${DEBIAN_REVISION}"
fi
python3 -I -B "${ROOT}/scripts/verify-split-deb-package-set.py" "${OUTPUT_DIR}" \
  --arch "${DEB_ARCH}" --version "${SPLIT_VERSION}" >/dev/null
bundle_revision_args=()
if [[ -n "${DEBIAN_REVISION}" ]]; then
  bundle_revision_args=(--debian-revision "${DEBIAN_REVISION}")
fi
"${ROOT}/scripts/build-release-bundle.sh" "${OUTPUT_DIR}" \
  --client-deb "${OUTPUT_DIR}/aegis-client_${SPLIT_VERSION}_${DEB_ARCH}.deb" \
  --split-deb-manifest "${OUTPUT_DIR}/split-deb-packages.manifest.json" \
  "${bundle_revision_args[@]}" >/dev/null

# Every packaging format must carry the exact same server/client executables as
# the canonical tar bundle. Rebuilding package roots used to omit the
# Cargo.lock provenance environment, producing different binaries that
# reported `cargo-lock unknown` even though all files came from one source
# checkout. Fail closed before writing/publishing the external manifest.
# shellcheck source=scripts/lib/host-arch.sh
BUNDLE_BIN_DIR="${OUTPUT_DIR}/aegis-${VERSION}-linux-${ARCH}/bin"
PACKAGE_ROOT_BIN_DIR="${OUTPUT_DIR}/aegis-package-root-${VERSION}-linux-${ARCH}/rootfs/usr/local/bin"
for binary_name in aegis-server aegis-client; do
  if ! cmp -s \
    "${BUNDLE_BIN_DIR}/${binary_name}" \
    "${PACKAGE_ROOT_BIN_DIR}/${binary_name}"; then
    echo "release binary parity failure: bundle and package-root ${binary_name} differ" >&2
    exit 1
  fi
done

RPM_STATUS="unavailable"
RPM_REASON="rpmbuild_or_rpm_missing"
if command -v rpmbuild >/dev/null 2>&1 && command -v rpm >/dev/null 2>&1; then
  if "${ROOT}/scripts/build-rpm-packages.sh" "${OUTPUT_DIR}" >/dev/null; then
    python3 -I -B "${ROOT}/scripts/verify-rpm-package-set.py" "${OUTPUT_DIR}" \
      --arch "${ARCH}" --version "${VERSION}"
    RPM_STATUS="ready"
    RPM_REASON=""
  else
    # Release delivery must stay publishable even when optional RPM packaging
    # is broken on the current builder/runner.
    RPM_STATUS="unavailable"
    RPM_REASON="rpm_build_failed"
  fi
fi
# Optional RPM failure must not leak an incomplete or stale RPM set through
# release upload globs. A reusable output with RPM bytes, sidecars or an
# orphan completion marker is refused until repaired or replaced by a fresh
# output directory. Upload globs include JSON even when RPM status is unavailable.
if [[ "${RPM_STATUS}" != "ready" ]]; then
  for residual in "${OUTPUT_DIR}"/*.rpm "${OUTPUT_DIR}"/*.rpm.sha256 \
                  "${OUTPUT_DIR}"/rpm-packages*.manifest.json; do
    [[ -e "${residual}" || -L "${residual}" ]] || continue
    echo "unready RPM artifact in release output: ${residual}" >&2
    exit 1
  done
fi

# The public client is a separate artifact; operator tarballs and package roots
# stay available to authenticated builders/operators, outside public mirrors.
cargo run --locked -q -p aegis-measure -- build-public-client-delivery \
  --root "${ROOT}" \
  --operator-bundle "${OUTPUT_DIR}/aegis-${VERSION}-linux-${ARCH}" \
  --output-dir "${OUTPUT_DIR}" \
  --channel "${CHANNEL}" --prerelease "${PRERELEASE}"

cargo run --locked -q -p aegis-measure -- build-release-delivery-manifest \
  --root "${ROOT}" \
  --output-dir "${OUTPUT_DIR}" \
  --channel "${CHANNEL}" \
  --prerelease "${PRERELEASE}" \
  --rpm-status "${RPM_STATUS}" \
  --rpm-reason "${RPM_REASON}" \
  --git-sha "${GIT_SHA}" \
  --build-timestamp "${BUILD_TIMESTAMP}" \
  "${bundle_revision_args[@]}"

cat <<EOF
Linux release delivery created
-----------------------------
Output directory:
  ${OUTPUT_DIR}

External manifest:
  ${OUTPUT_DIR}/release.manifest.json
EOF
