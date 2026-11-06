#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.cargo/bin:${PATH}"
# shellcheck source=scripts/lib/release-toolchain.sh
. "${ROOT}/scripts/lib/release-toolchain.sh"

usage() {
  cat <<'EOF'
Usage:
  scripts/build-release-bundle.sh <output-dir> [--client-deb <path> --split-deb-manifest <path> [--debian-revision <positive-integer>]]

Builds release binaries and produces a self-contained install bundle:
  <output-dir>/aegis-<version>-linux-<arch>/
  <output-dir>/aegis-<version>-linux-<arch>.tar.gz
  <output-dir>/aegis-research-<version>-linux-<arch>.tar.gz

The resulting bundle can be unpacked on another Linux host and installed via:
  ./install.sh server
  ./install.sh client --bundle /path/to/client-bundle
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -ne 1 && $# -ne 5 && $# -ne 7 ]]; then
  usage >&2
  exit 1
fi

CLIENT_DEB=""
SPLIT_DEB_MANIFEST=""
DEBIAN_REVISION=""
if [[ $# -eq 5 || $# -eq 7 ]]; then
  [[ "$2" == --client-deb && "$4" == --split-deb-manifest ]] || {
    usage >&2; exit 1;
  }
  CLIENT_DEB="$3"
  SPLIT_DEB_MANIFEST="$5"
  if [[ $# -eq 7 ]]; then
    [[ "$6" == --debian-revision ]] || { usage >&2; exit 1; }
    DEBIAN_REVISION="$7"
    [[ "${DEBIAN_REVISION}" =~ ^[1-9][0-9]{0,17}$ ]] || {
      echo "Debian revision must be a canonical positive integer" >&2; exit 1;
    }
  fi
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required; install Rust via rustup first" >&2
  exit 1
fi

OUTPUT_DIR="$1"
verify_release_toolchain
# shellcheck source=scripts/lib/host-arch.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/host-arch.sh"
ARCH="$(host_arch)"
GIT_SHA="${AEGIS_BUILD_GIT_SHA:-$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')}"
BUILD_TIMESTAMP="${AEGIS_BUILD_TIMESTAMP:-$(release_source_timestamp)}"
export AEGIS_BUILD_GIT_SHA="${GIT_SHA}"
export AEGIS_BUILD_TIMESTAMP="${BUILD_TIMESTAMP}"
case "${ARCH}" in
  x86_64) TARGET_TRIPLE="x86_64-unknown-linux-gnu" ;;
  aarch64|arm64) TARGET_TRIPLE="aarch64-unknown-linux-gnu" ;;
  armv7l) TARGET_TRIPLE="armv7-unknown-linux-gnueabihf" ;;
  *) TARGET_TRIPLE="${ARCH}-unknown-linux-gnu" ;;
esac
hash_lockfile() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${ROOT}/Cargo.lock" | awk '{print $1}'
  else
    shasum -a 256 "${ROOT}/Cargo.lock" | awk '{print $1}'
  fi
}
CARGO_LOCK_SHA256="$(hash_lockfile)"
verify_lockfile_unchanged() {
  if [[ "$(hash_lockfile)" != "${CARGO_LOCK_SHA256}" ]]; then
    echo "Cargo.lock changed during release build; refusing to package or sign this candidate." >&2
    return 1
  fi
}
export AEGIS_BUILD_TARGET="${TARGET_TRIPLE}"
export AEGIS_CARGO_LOCK_SHA256="${CARGO_LOCK_SHA256}"
HELPER_SCRIPTS=(
  "lib/root-state.sh"
  "lib/aegis_installer_auto_v2.py"
  "lib/aegis_auto_uninstall_journal.py"
  "lib/aegis_auto_capture.py"
  "lib/aegis_auto_capture_topology.py"
  "lib/aegis_auto_endpoint.py"
  "lib/aegis_auto_guard_policy.py"
  "lib/aegis_auto_foreign_policy.py"
  "lib/aegis_auto_foreign_monitor.py"
  "lib/aegis_auto_ufw_pins.json"
  "lib/aegis_initrd_policy.py"
  "lib/aegis_initrd_classic.py"
  "lib/aegis_auto_guardian.py"
  "lib/aegis_auto_guardian_watchdog.py"
  "lib/aegis_auto_terminal_witness.py"
  "lib/aegis_auto_terminal_boot_store.py"
  "lib/aegis_auto_terminal_register.py"
  "lib/aegis_auto_boot_transition.py"
  "lib/aegis_auto_launch.py"
  "lib/aegis_auto_native_witness.py"
  "lib/aegis_auto_sink.py"
  "lib/aegis_auto_trace_rollback.py"
  "lib/aegis_auto_witness_topology.py"
  "aegis-device-egress-guard.sh"
  "aegis-relay-geneva-profile.sh"
  "bootstrap-wide-linux-validation-host.sh"
  "generate-relay-materials.sh"
  "render-client-bundle.sh"
  "package-client-bundle.sh"
  "issue-fronted-bundle.sh"
  "purge-installed-aegis.sh"
  "aegis-ubuntu-uninstall.sh"
  "aegis-origin-guard.sh"
  "aegis-wide-enable.sh"
  "aegis-wide-disable.sh"
  "aegis-wide-persist-install.sh"
  "janitor-wide-linux-tproxy.sh"
  "setup-wide-linux-redirect.sh"
  "setup-wide-linux-tproxy.sh"
  "setup-wide-linux-nfqueue.sh"
  "aegis-rpi-gateway.sh"
  "validate-debian-package-host.sh"
  "build-ubuntu-controlled-pilot-playbook.sh"
  "build-ubuntu-operator-reapply-canary.sh"
  "build-ubuntu-controlled-pilot-bundle.sh"
  "build-ubuntu-release-review.sh"
  "build-ubuntu-controlled-pilot-review-bundle.sh"
  "ubuntu-release-wave-status.sh"
  "build-ubuntu-release-wave-bundle.sh"
  "build-ubuntu-field-pilot-remote-bundle.sh"
  "build-post-release-stealth-wave-summary.sh"
  "mimicry-wire-validation-contract.sh"
  "build-mimicry-wire-witness-summary.sh"
  "validate-mimicry-wire-host.sh"
  "build-ubuntu-mimicry-next-contour.sh"
)

META="$(cargo run --locked -q -p aegis-measure -- release-package-metadata --root "${ROOT}")"
verify_lockfile_unchanged

TARGET_DIR="$(printf '%s\n' "${META}" | sed -n '1p')"
VERSION="$(printf '%s\n' "${META}" | sed -n '2p')"
BUNDLE_NAME="aegis-${VERSION}-linux-${ARCH}"
BUNDLE_DIR="${OUTPUT_DIR}/${BUNDLE_NAME}"
ARCHIVE_PATH="${OUTPUT_DIR}/${BUNDLE_NAME}.tar.gz"
ARCHIVE_SHA256_PATH="${ARCHIVE_PATH}.sha256"
RESEARCH_NAME="aegis-research-${VERSION}-linux-${ARCH}"
RESEARCH_DIR="${OUTPUT_DIR}/${RESEARCH_NAME}"
RESEARCH_ARCHIVE="${OUTPUT_DIR}/${RESEARCH_NAME}.tar.gz"

mkdir -p "${OUTPUT_DIR}"
rm -rf "${BUNDLE_DIR}" "${ARCHIVE_PATH}" "${ARCHIVE_SHA256_PATH}" \
  "${RESEARCH_DIR}" "${RESEARCH_ARCHIVE}" "${RESEARCH_ARCHIVE}.sha256"

cd "${ROOT}"
# aws-lc-sys (the chrome-like-tls backend) needs cmake. Check before the long
# server build so a runner without it fails in a second with a clear message
# instead of ten minutes in with a native-build error.
if ! command -v cmake >/dev/null 2>&1; then
  echo "cmake is required to build the chrome-like-tls feature (aws-lc-sys)." >&2
  echo "A build without it cannot produce a Chrome-class TLS ClientHello." >&2
  exit 1
fi
AEGIS_BUILD_FEATURES="none" cargo build --locked --release -p aegis-server
CLIENT_BUILD_MESSAGES="$(mktemp "${OUTPUT_DIR}/client-build-${ARCH}.jsonl.XXXXXX")"
chmod 0600 "${CLIENT_BUILD_MESSAGES}"
AEGIS_BUILD_FEATURES="raw-socket,chrome-like-tls,chrome-like-quic" \
  cargo build --locked --release -p aegis-client --features raw-socket,chrome-like-tls,chrome-like-quic \
    --target "${TARGET_TRIPLE}" --message-format=json-render-diagnostics > "${CLIENT_BUILD_MESSAGES}"
AEGIS_BUILD_FEATURES="live-linux" cargo build --locked --release -p aegis-geneva --features live-linux --bin aegis-geneva-bridge
AEGIS_BUILD_FEATURES="none" cargo build --locked --release -p aegis-measure -p aegis-transport-lab --bins
verify_lockfile_unchanged

# Building on a newer distro can silently import newer GLIBC symbols even when
# the architecture is correct. Gate the ELF pair before packaging; the
# installer executes the selected candidate again before mutating the host.
# shellcheck source=scripts/lib/release-abi.sh
. "${ROOT}/scripts/lib/release-abi.sh"
verify_linux_release_abi \
  "${TARGET_DIR}/release/aegis-server" \
  "${TARGET_DIR}/${TARGET_TRIPLE}/release/aegis-client" \
  "${TARGET_DIR}/release/aegis-geneva-bridge" \
  "${TARGET_DIR}/release/aegis-research-measure" \
  "${TARGET_DIR}/release/aegis-transport-lab" \
  "${TARGET_DIR}/release/aegis-measure"

mkdir -p "${BUNDLE_DIR}/bin" "${BUNDLE_DIR}/scripts"
cp "${TARGET_DIR}/release/aegis-server" "${BUNDLE_DIR}/bin/aegis-server"
cp "${TARGET_DIR}/${TARGET_TRIPLE}/release/aegis-client" "${BUNDLE_DIR}/bin/aegis-client"
cp "${TARGET_DIR}/release/aegis-geneva-bridge" "${BUNDLE_DIR}/bin/aegis-geneva-bridge"
# Administrative helpers retain the full normal producer, never the research role.
cp "${TARGET_DIR}/release/aegis-measure" "${BUNDLE_DIR}/bin/aegis-measure"
chmod 0755 "${BUNDLE_DIR}/bin/aegis-measure"
# Only the just-built fixed roles are invoked, under a finite build-side bound.
mkdir -p "${RESEARCH_DIR}/bin" "${RESEARCH_DIR}/research"
# The internal producer name is fixed; never substitute the full build-side tool.
cp "${TARGET_DIR}/release/aegis-research-measure" "${RESEARCH_DIR}/bin/aegis-measure"
cp "${TARGET_DIR}/release/aegis-transport-lab" "${RESEARCH_DIR}/bin/aegis-transport-lab"
chmod 0755 "${RESEARCH_DIR}/bin/aegis-measure" "${RESEARCH_DIR}/bin/aegis-transport-lab"
timeout 10s "${RESEARCH_DIR}/bin/aegis-measure" research-build-info > "${RESEARCH_DIR}/research/aegis-measure.build-info.json"
timeout 10s "${RESEARCH_DIR}/bin/aegis-transport-lab" --build-info > "${RESEARCH_DIR}/research/aegis-transport-lab.build-info.json"
for tool in aegis-measure aegis-transport-lab; do
  [[ $(wc -c < "${RESEARCH_DIR}/research/${tool}.build-info.json") -le 8192 ]] || { echo 'research producer snapshot exceeded bound' >&2; exit 1; }
done
cp "${ROOT}/docs/research/private-operator-delivery.md" "${RESEARCH_DIR}/research/README.md"
# Exact private guide closure, shared with Rust package admission. Never copy a
# repository tree, discovered link target, source file or operator credential.
guide_count=0
while IFS= read -r document || [[ -n "$document" ]]; do
  [[ "$document" =~ ^[a-z0-9][a-z0-9-]*\.md$ ]] || { echo 'Invalid private operator guide name' >&2; exit 1; }
  guide_count=$((guide_count + 1))
  [[ "$guide_count" -le 32 ]] || { echo 'Private operator guide count exceeded bound' >&2; exit 1; }
  [[ -f "${ROOT}/docs/research/${document}" && ! -L "${ROOT}/docs/research/${document}" ]] || { echo "Missing regular private operator guide: ${document}" >&2; exit 1; }
  cp "${ROOT}/docs/research/${document}" "${RESEARCH_DIR}/research/${document}"
done < "${ROOT}/packaging/research-operator-guides.txt"
[[ "$guide_count" -gt 0 ]] || { echo 'Private operator guide inventory is empty' >&2; exit 1; }
timeout 30s "${TARGET_DIR}/release/aegis-measure" research-tool-notices \
  --root "${ROOT}" --target "${TARGET_TRIPLE}" --output "${RESEARCH_DIR}/research/THIRD-PARTY-NOTICES.txt"
mkdir -p "${BUNDLE_DIR}/tools/geneva" "${BUNDLE_DIR}/docs"
cp "${ROOT}/tools/geneva/install-bridge.sh" "${BUNDLE_DIR}/tools/geneva/install-bridge.sh"
cp "${ROOT}/tools/geneva/install-relay-profile.sh" "${BUNDLE_DIR}/tools/geneva/install-relay-profile.sh"
cp "${ROOT}/tools/geneva/uninstall-relay-profile.sh" "${BUNDLE_DIR}/tools/geneva/uninstall-relay-profile.sh"
cp "${ROOT}/docs/geneva-live-bridge.md" "${BUNDLE_DIR}/docs/geneva-live-bridge.md"
cp "${ROOT}/docs/relay-geneva-installed-profile.md" "${BUNDLE_DIR}/docs/relay-geneva-installed-profile.md"
mkdir -p "${BUNDLE_DIR}/docs/operations"
cp "${ROOT}/docs/operations/https-bridge.md" "${BUNDLE_DIR}/docs/operations/https-bridge.md"
cp "${ROOT}/docs/operations/carrier-program.md" "${BUNDLE_DIR}/docs/operations/carrier-program.md"
cp "${ROOT}/docs/operations/web-response-carrier.md" "${BUNDLE_DIR}/docs/operations/web-response-carrier.md"
cp "${ROOT}/docs/operations/webrtc-native.md" "${BUNDLE_DIR}/docs/operations/webrtc-native.md"
cp "${ROOT}/docs/operations/traffic-privacy.md" "${BUNDLE_DIR}/docs/operations/traffic-privacy.md"
cp "${ROOT}/install.sh" "${BUNDLE_DIR}/install.sh"
cp "${ROOT}/README.md" "${BUNDLE_DIR}/README.md"
for project_license in LICENSE-MIT LICENSE-APACHE NOTICE THIRD-PARTY-NOTICES; do
  cp "${ROOT}/${project_license}" "${BUNDLE_DIR}/${project_license}"
  chmod 0644 "${BUNDLE_DIR}/${project_license}"
done
mkdir -p "${BUNDLE_DIR}/third-party/h2"
cp "${ROOT}/third_party/h2/LICENSE" "${BUNDLE_DIR}/third-party/h2/LICENSE"
chmod 0644 "${BUNDLE_DIR}/third-party/h2/LICENSE"
mkdir -p "${BUNDLE_DIR}/third-party/tungstenite"
for license_file in LICENSE-MIT LICENSE-APACHE; do
  cp "${ROOT}/third_party/tungstenite/${license_file}" "${BUNDLE_DIR}/third-party/tungstenite/${license_file}"
  chmod 0644 "${BUNDLE_DIR}/third-party/tungstenite/${license_file}"
done
cp "${ROOT}/config.example.toml" "${BUNDLE_DIR}/config.example.toml"
cp "${ROOT}/aegis-server.toml.example" "${BUNDLE_DIR}/aegis-server.toml.example"
cp "${ROOT}/Cargo.lock" "${BUNDLE_DIR}/Cargo.lock"
for helper_script in "${HELPER_SCRIPTS[@]}"; do
  mkdir -p "$(dirname "${BUNDLE_DIR}/scripts/${helper_script}")"
  cp "${ROOT}/scripts/${helper_script}" "${BUNDLE_DIR}/scripts/${helper_script}"
done
cp -R "${ROOT}/packaging" "${BUNDLE_DIR}/packaging"

# Release delivery builds the split packages before the final administrative
# manifest. Only that authenticated handoff adds the exact incoming client
# package; a standalone bundle build retains its original file set.
if [[ -n "${CLIENT_DEB}" ]]; then
  DEB_VERSION="${VERSION}"
  if [[ -n "${DEBIAN_REVISION}" ]]; then
    DEB_VERSION="${VERSION}-${DEBIAN_REVISION}"
  fi
  python3 -I -B - "${CLIENT_DEB}" "${SPLIT_DEB_MANIFEST}" "${BUNDLE_DIR}" "${DEB_VERSION}" "${ARCH}" <<'PY_AUTO_SIGNED_DEB'
import hashlib,json,os,pathlib,re,shutil,stat,sys
deb,marker,bundle=map(pathlib.Path,sys.argv[1:4]);version,arch=sys.argv[4:]
deb_arch={'x86_64':'amd64','aarch64':'arm64','arm64':'arm64','armv7l':'armhf'}.get(arch)
def need(ok):
    if not ok: raise SystemExit('release client DEB source closure refused')
need(deb_arch is not None and marker.name=='split-deb-packages.manifest.json' and
     deb.parent==marker.parent and
     deb.name==f'aegis-client_{version}_{deb_arch}.deb')
def bounded(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=limit)
        h=hashlib.sha256();count=0
        while block:=os.read(fd,65536):
            count+=len(block);need(count<=limit);h.update(block)
        after=os.fstat(fd)
        need(count==before.st_size and all(getattr(before,k)==getattr(after,k) for k in
             ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns')))
        return h.hexdigest()
    finally: os.close(fd)
deb_sha=bounded(deb,512*1024*1024)
marker_sha=bounded(marker,1024*1024)
sidecar=deb.with_name(deb.name+'.sha256')
sidecar_fd=os.open(sidecar,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
try:
    sidecar_before=os.fstat(sidecar_fd)
    need(stat.S_ISREG(sidecar_before.st_mode) and sidecar_before.st_nlink==1 and
         0<sidecar_before.st_size<=128)
    sidecar_raw=os.read(sidecar_fd,129)
    sidecar_after=os.fstat(sidecar_fd)
    need(len(sidecar_raw)==sidecar_before.st_size and
         all(getattr(sidecar_before,k)==getattr(sidecar_after,k) for k in
             ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns')) and
         sidecar_raw==f'{deb_sha}  {deb.name}\n'.encode())
finally: os.close(sidecar_fd)
marker_fd=os.open(marker,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
try:
    marker_before=os.fstat(marker_fd)
    need(stat.S_ISREG(marker_before.st_mode) and marker_before.st_nlink==1 and
         0<marker_before.st_size<=1024*1024)
    marker_raw=os.read(marker_fd,1024*1024+1)
    marker_after=os.fstat(marker_fd)
    need(len(marker_raw)==marker_before.st_size and
         all(getattr(marker_before,k)==getattr(marker_after,k) for k in
             ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns')) and
         hashlib.sha256(marker_raw).hexdigest()==marker_sha)
finally: os.close(marker_fd)
document=json.loads(marker_raw,object_pairs_hook=lambda pairs:
    dict(pairs) if len(dict(pairs))==len(pairs) else need(False))
need(document['version']==version and document['deb_arch']==deb_arch and
     document['packages']['aegis-client']['deb_file']==deb.name and
     set(document['packages'])=={'aegis-client','aegis-server'})
target=bundle/'packages';target.mkdir(mode=0o755)
for original in (deb,sidecar,marker):
    destination=target/original.name
    need(not destination.exists() and not destination.is_symlink())
    shutil.copyfile(original,destination,follow_symlinks=False)
    destination.chmod(0o644)
need(bounded(target/deb.name,512*1024*1024)==deb_sha and
     bounded(target/marker.name,1024*1024)==marker_sha)
PY_AUTO_SIGNED_DEB
fi

chmod 0755 \
  "${BUNDLE_DIR}/install.sh" \
  "${BUNDLE_DIR}/bin/aegis-server" \
  "${BUNDLE_DIR}/bin/aegis-client" \
  "${BUNDLE_DIR}/bin/aegis-geneva-bridge" \
  "${BUNDLE_DIR}/tools/geneva/install-bridge.sh" \
  "${BUNDLE_DIR}/tools/geneva/install-relay-profile.sh" \
  "${BUNDLE_DIR}/tools/geneva/uninstall-relay-profile.sh"
for helper_script in "${HELPER_SCRIPTS[@]}"; do
  chmod 0755 "${BUNDLE_DIR}/scripts/${helper_script}"
done

# Keep the bundle self-describing so a remote host can verify what was packed
# before installing anything from the archive.
if command -v sha256sum >/dev/null 2>&1; then
  ADMIN_MEASURE_SHA256="$(sha256sum "${TARGET_DIR}/release/aegis-measure" | awk '{print $1}')"
else
  ADMIN_MEASURE_SHA256="$(shasum -a 256 "${TARGET_DIR}/release/aegis-measure" | awk '{print $1}')"
fi
cargo run --locked -q -p aegis-measure -- build-release-bundle-manifest \
  --bundle-dir "${BUNDLE_DIR}" \
  --version "${VERSION}" \
  --arch "${ARCH}" \
  --target-triple "${TARGET_TRIPLE}" \
  --git-sha "${GIT_SHA}" \
  --build-timestamp "${BUILD_TIMESTAMP}" \
  --administrative-measure-sha256 "${ADMIN_MEASURE_SHA256}" \
  --client-build-messages "${CLIENT_BUILD_MESSAGES}"
cargo run --locked -q -p aegis-measure -- build-private-research-manifest \
  --bundle-dir "${RESEARCH_DIR}" --version "${VERSION}" --arch "${ARCH}" \
  --target-triple "${TARGET_TRIPLE}" --git-sha "${GIT_SHA}" \
  --cargo-lock-sha256 "${CARGO_LOCK_SHA256}"
verify_lockfile_unchanged

# Keep the unsigned handoff on a single bounded USTAR dialect. The offline
# custodian intentionally refuses GNU LongLink/PAX extension records.
tar --format=ustar --owner=0 --group=0 --numeric-owner -C "${OUTPUT_DIR}" -czf "${ARCHIVE_PATH}" "${BUNDLE_NAME}"

cargo run --locked -q -p aegis-measure -- write-archive-sha256 \
  --archive "${ARCHIVE_PATH}" \
  --sha256-path "${ARCHIVE_SHA256_PATH}"
verify_lockfile_unchanged

tar --format=ustar --owner=0 --group=0 --numeric-owner -C "${OUTPUT_DIR}" -czf "${RESEARCH_ARCHIVE}" "${RESEARCH_NAME}"
cargo run --locked -q -p aegis-measure -- write-archive-sha256 \
  --archive "${RESEARCH_ARCHIVE}" --sha256-path "${RESEARCH_ARCHIVE}.sha256"
verify_lockfile_unchanged

cat <<EOF
Release bundle created
----------------------
Administrative bundle directory:
  ${BUNDLE_DIR}

Separate private research archive:
  ${RESEARCH_ARCHIVE}

Archive:
  ${ARCHIVE_PATH}

Archive checksum:
  ${ARCHIVE_SHA256_PATH}

Install entrypoints inside the bundle:
  ./install.sh server
  ./install.sh client --bundle /path/to/client-bundle
EOF
