#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.cargo/bin:${PATH}"

usage() {
  cat <<'EOF'
Usage:
  scripts/build-rpm-packages.sh <output-dir>

Builds role-specific RPM packages on top of the canonical package-root:
  <output-dir>/aegis-server-<version>-1.<arch>.rpm
  <output-dir>/aegis-client-<version>-1.<arch>.rpm
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -ne 1 ]]; then
  usage >&2
  exit 1
fi

if ! command -v rpmbuild >/dev/null 2>&1; then
  echo "rpmbuild is required" >&2
  exit 1
fi

if ! command -v rpm >/dev/null 2>&1; then
  echo "rpm is required" >&2
  exit 1
fi
if ! command -v rpm2cpio >/dev/null 2>&1 || ! command -v cpio >/dev/null 2>&1; then
  echo "rpm2cpio and cpio are required for final RPM binary parity verification" >&2
  exit 1
fi

OUTPUT_DIR="$1"
# shellcheck source=scripts/lib/host-arch.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/host-arch.sh"
ARCH="$(host_arch)"
META="$(cargo run --locked -q -p aegis-measure -- release-package-metadata --root "${ROOT}")"
VERSION="$(printf '%s\n' "${META}" | sed -n '2p')"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-rpm-build.XXXXXX")"
STAGED_SET=""
PRESERVE_RPM_FAILURE=0
cleanup_rpm_build() {
  local status=$?
  if [[ -n "${STAGED_SET}" ]]; then
    rm -rf -- "${STAGED_SET}"
  fi
  if [[ "${status}" -ne 0 && "${PRESERVE_RPM_FAILURE}" -eq 1 ]]; then
    # A rejected package stays in its private 0700 build directory for diagnosis,
    # never in the caller's release output directory.
    echo "rejected RPM build retained privately: ${TMP_DIR}" >&2
  else
    rm -rf -- "${TMP_DIR}"
  fi
}
trap cleanup_rpm_build EXIT

"${ROOT}/scripts/build-package-root.sh" "${TMP_DIR}" >/dev/null

PACKAGE_ROOT_DIR="${TMP_DIR}/aegis-package-root-${VERSION}-linux-${ARCH}"
ROOTFS_DIR="${PACKAGE_ROOT_DIR}/rootfs"
PROJECT_LICENSE_PATHS=(
  "usr/share/doc/aegis/LICENSE-MIT"
  "usr/share/doc/aegis/LICENSE-APACHE"
  "usr/share/doc/aegis/NOTICE"
  "usr/share/doc/aegis/THIRD-PARTY-NOTICES"
)
H2_LICENSE_PATH="usr/share/doc/aegis/third-party/h2/LICENSE"
TUNGSTENITE_LICENSE_PATHS=(
  "usr/share/doc/aegis/third-party/tungstenite/LICENSE-MIT"
  "usr/share/doc/aegis/third-party/tungstenite/LICENSE-APACHE"
)
RPM_TOPDIR="${TMP_DIR}/rpmbuild"

mkdir -p "${OUTPUT_DIR}" "${RPM_TOPDIR}"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

copy_rootfs_file() {
  local rel="$1"
  local stage_root="$2"
  local destination="${3:-${rel}}"
  mkdir -p "${stage_root}/$(dirname "${destination}")"
  cp --preserve=mode "${ROOTFS_DIR}/${rel}" "${stage_root}/${destination}"
}

make_source_tree() {
  local package_name="$1"
  local stage_root="${TMP_DIR}/${package_name}-rootfs"
  shift

  rm -rf "${stage_root}"
  mkdir -p "${stage_root}"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      usr/share/doc/aegis/LICENSE-MIT|usr/share/doc/aegis/LICENSE-APACHE|usr/share/doc/aegis/NOTICE|usr/share/doc/aegis/THIRD-PARTY-NOTICES)
        copy_rootfs_file "$1" "${stage_root}" "usr/share/doc/${package_name}/${1##*/}"
        ;;
      usr/share/doc/aegis/third-party/h2/LICENSE|usr/share/doc/aegis/third-party/tungstenite/LICENSE-MIT|usr/share/doc/aegis/third-party/tungstenite/LICENSE-APACHE)
        copy_rootfs_file "$1" "${stage_root}" "usr/share/doc/${package_name}/${1#usr/share/doc/aegis/}"
        ;;
      *) copy_rootfs_file "$1" "${stage_root}" ;;
    esac
    shift
  done
  printf '%s\n' "${stage_root}"
}

write_spec() {
  local spec_path="$1"
  local package_name="$2"
  local summary="$3"
  local source_name="$4"
  local source_root="$5"
  local config_path="$6"
  local dir_entries="$7"
  local file_entries="$8"
  local post_script="$9"
  local preun_script="${10}"
  local postun_script="${11}"
  local project_license_entries
  project_license_entries="$(printf '%%license /usr/share/doc/%s/%s\n' \
    "${package_name}" LICENSE-MIT "${package_name}" LICENSE-APACHE "${package_name}" NOTICE "${package_name}" THIRD-PARTY-NOTICES)"
  project_license_entries+=$'\n'"%license /usr/share/doc/${package_name}/third-party/h2/LICENSE"
  project_license_entries+=$'\n'"%license /usr/share/doc/${package_name}/third-party/tungstenite/LICENSE-MIT"
  project_license_entries+=$'\n'"%license /usr/share/doc/${package_name}/third-party/tungstenite/LICENSE-APACHE"

  # The config file is emitted below as %config(noreplace), so it must not also
  # appear in the plain file list: rpmbuild rejects the spec outright with
  # "File listed twice". Filtering here rather than trusting each caller to
  # leave it out keeps the file lists a complete manifest of the package and
  # makes the invariant impossible to break from a call site.
  file_entries="$(printf '%s\n' "${file_entries}" | grep -vxF "${config_path}" || true)"

  cat > "${spec_path}" <<EOF
Name:           ${package_name}
Version:        ${VERSION}
Release:        1%{?dist}
Summary:        ${summary}
License:        MIT OR Apache-2.0
URL:            https://github.com/example-org/aegis
BuildArch:      ${ARCH}
Source0:        ${source_name}
# Rust release binaries are already stripped according to the canonical Cargo
# profile. Red Hat's default brp-strip would mutate them after the package-root
# parity gate, so make the strip macro a no-op and verify final RPM payloads
# again after rpmbuild completes.
%global __strip /bin/true
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
Role-specific RPM package generated from the canonical AEGIS package-root staging layout.

%prep
rm -rf %{_builddir}/${package_name}-${VERSION}
mkdir -p %{_builddir}/${package_name}-${VERSION}
tar --no-same-owner -xzf %{SOURCE0} -C %{_builddir}/${package_name}-${VERSION}

%build

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a %{_builddir}/${package_name}-${VERSION}/${source_root}/. %{buildroot}/

%post
${post_script}

%preun
${preun_script}

%postun
${postun_script}

%files
%defattr(-,root,root,-)
%config(noreplace) ${config_path}
${dir_entries}
${file_entries}
${project_license_entries}
EOF
}

build_package() {
  local package_name="$1"
  local summary="$2"
  local config_path="$3"
  local dir_entries="$4"
  local file_entries="$5"
  local post_script="$6"
  local preun_script="$7"
  local postun_script="$8"
  shift 8

  local source_root=""
  local source_name="${package_name}-${VERSION}-${ARCH}-rootfs.tar.gz"
  local source_archive="${RPM_TOPDIR}/SOURCES/${source_name}"
  local spec_path="${RPM_TOPDIR}/SPECS/${package_name}.spec"

  source_root="$(make_source_tree "${package_name}" "$@")"

  # RPM does not infer directory ownership from %license or regular files.
  # Both roles may own their shared parents; RPM retains a nonempty parent.
  local private_dir
  for private_dir in \
    "/usr/share/doc/${package_name}" \
    "/usr/share/doc/${package_name}/third-party" \
    "/usr/share/doc/${package_name}/third-party/h2" \
    "/usr/share/doc/${package_name}/third-party/tungstenite" \
    "/usr/share/doc/aegis" \
    "/usr/share/aegis" \
    "/usr/share/aegis/scripts" \
    "/usr/share/aegis/examples"
  do
    if [[ -d "${source_root}${private_dir}" && ! -L "${source_root}${private_dir}" ]]; then
      chmod 0755 "${source_root}${private_dir}"
      dir_entries+=$'\n'"%dir ${private_dir}"
    fi
  done

  # Create %dir entries in the staging root so rpmbuild finds them in BUILDROOT
  while IFS= read -r dir_line; do
    dir_path="${dir_line#%dir }"
    [[ -n "${dir_path}" ]] && mkdir -p "${source_root}${dir_path}"
  done <<< "${dir_entries}"

  tar --owner=0 --group=0 --numeric-owner -C "${TMP_DIR}" -czf "${source_archive}" "$(basename "${source_root}")"

  write_spec \
    "${spec_path}" \
    "${package_name}" \
    "${summary}" \
    "${source_name}" \
    "$(basename "${source_root}")" \
    "${config_path}" \
    "${dir_entries}" \
    "${file_entries}" \
    "${post_script}" \
    "${preun_script}" \
    "${postun_script}"

  rpmbuild --define "_topdir ${RPM_TOPDIR}" -bb "${spec_path}" >/dev/null
}

SERVER_POST='set -e
command -v systemd-sysusers >/dev/null 2>&1
command -v systemd-tmpfiles >/dev/null 2>&1
systemd-sysusers /usr/lib/sysusers.d/aegis-server.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/aegis-server.conf
# Only contact the booted system manager in the same root. A chroot with a
# bind-mounted /run must not reconfigure host units.
aegis_live_systemd() {
  [ -d /run/systemd/system ] || return 1
  [ -e /proc/1/root ] || return 1
  current_root=$(stat -Lc %d:%i /) || return 1
  init_root=$(stat -Lc %d:%i /proc/1/root) || return 1
  [ "$current_root" = "$init_root" ]
}
if aegis_live_systemd; then
  command -v systemctl >/dev/null 2>&1
  systemctl daemon-reload
  # RPM passes 1 on first install and a larger count on upgrade.
  if [ "${1:-}" -eq 1 ]; then
    systemctl preset aegis-server.service
  fi
fi
if [ -n "${AEGIS_RPM_POSTINSTALL_NONCE:-}" ]; then
  case "$AEGIS_RPM_POSTINSTALL_NONCE" in
    *[!a-zA-Z0-9]*) exit 1 ;;
  esac
  [ -d /run ] && [ ! -L /run ]
  [ "$(stat -Lc %u /run)" = 0 ]
  run_mode=$(stat -Lc %a /run)
  case "$run_mode" in
    ""|*[!0-7]*) exit 1 ;;
  esac
  [ "$((0$run_mode & 022))" -eq 0 ]
  receipt_dir="/run/aegis-rpm-postinstall.${AEGIS_RPM_POSTINSTALL_NONCE}"
  [ -d "$receipt_dir" ] && [ ! -L "$receipt_dir" ]
  [ "$(stat -Lc %u:%a "$receipt_dir")" = "0:700" ]
  printf "%s\n" "$AEGIS_RPM_POSTINSTALL_NONCE" > "$receipt_dir/aegis-server.ok"
fi'

SERVER_PREUN='if [ "$1" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
  systemctl --no-reload disable --now aegis-server.service >/dev/null 2>&1 || true
fi'
SERVER_POSTUN='if [ "$1" -eq 0 ] && command -v systemd-tmpfiles >/dev/null 2>&1; then
  systemd-tmpfiles --remove /usr/lib/tmpfiles.d/aegis-server.conf >/dev/null 2>&1 || true
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi'

CLIENT_POST='set -e
command -v systemd-tmpfiles >/dev/null 2>&1
systemd-tmpfiles --create /usr/lib/tmpfiles.d/aegis-client.conf
# Only contact the booted system manager in the same root. A chroot with a
# bind-mounted /run must not reconfigure host units.
aegis_live_systemd() {
  [ -d /run/systemd/system ] || return 1
  [ -e /proc/1/root ] || return 1
  current_root=$(stat -Lc %d:%i /) || return 1
  init_root=$(stat -Lc %d:%i /proc/1/root) || return 1
  [ "$current_root" = "$init_root" ]
}
if aegis_live_systemd; then
  command -v systemctl >/dev/null 2>&1
  systemctl daemon-reload
  # RPM passes 1 on first install and a larger count on upgrade.
  if [ "${1:-}" -eq 1 ]; then
    systemctl preset aegis-client.service
  fi
fi
if [ -n "${AEGIS_RPM_POSTINSTALL_NONCE:-}" ]; then
  case "$AEGIS_RPM_POSTINSTALL_NONCE" in
    *[!a-zA-Z0-9]*) exit 1 ;;
  esac
  [ -d /run ] && [ ! -L /run ]
  [ "$(stat -Lc %u /run)" = 0 ]
  run_mode=$(stat -Lc %a /run)
  case "$run_mode" in
    ""|*[!0-7]*) exit 1 ;;
  esac
  [ "$((0$run_mode & 022))" -eq 0 ]
  receipt_dir="/run/aegis-rpm-postinstall.${AEGIS_RPM_POSTINSTALL_NONCE}"
  [ -d "$receipt_dir" ] && [ ! -L "$receipt_dir" ]
  [ "$(stat -Lc %u:%a "$receipt_dir")" = "0:700" ]
  printf "%s\n" "$AEGIS_RPM_POSTINSTALL_NONCE" > "$receipt_dir/aegis-client.ok"
fi'

CLIENT_PREUN='if [ "$1" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
  systemctl --no-reload disable --now aegis-client.service >/dev/null 2>&1 || true
fi'
CLIENT_POSTUN='if [ "$1" -eq 0 ] && command -v systemd-tmpfiles >/dev/null 2>&1; then
  systemd-tmpfiles --remove /usr/lib/tmpfiles.d/aegis-client.conf >/dev/null 2>&1 || true
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi'

SERVER_DIRS=$'%dir /etc/aegis\n%dir /etc/aegis/server\n%dir /var/lib/aegis-server'
SERVER_FILES=$'/usr/local/bin/aegis-server\n/usr/lib/systemd/system/aegis-server.service\n/usr/lib/systemd/system-preset/90-aegis-server.preset\n/usr/lib/sysusers.d/aegis-server.conf\n/usr/lib/tmpfiles.d/aegis-server.conf\n/etc/default/aegis-server\n/usr/share/aegis/examples/aegis-server.toml.example\n/usr/share/aegis/scripts/generate-relay-materials.sh\n/usr/share/aegis/scripts/render-client-bundle.sh\n/usr/share/aegis/scripts/package-client-bundle.sh\n/usr/share/doc/aegis/README.server.Debian\n/usr/share/doc/aegis/README.md'
CLIENT_DIRS=$'%dir /etc/aegis\n%dir /etc/aegis/client\n%dir /var/lib/aegis-client\n%dir /var/log/aegis-client'
CLIENT_FILES=$'/usr/local/bin/aegis-client\n/usr/lib/systemd/system/aegis-client.service\n/usr/lib/systemd/system-preset/90-aegis-client.preset\n/usr/lib/tmpfiles.d/aegis-client.conf\n/etc/default/aegis-client\n/usr/share/doc/aegis/README.client.Debian\n/usr/share/aegis/examples/config.example.toml'

build_package \
  "aegis-server" \
  "AEGIS relay server" \
  "/etc/default/aegis-server" \
  "${SERVER_DIRS}" \
  "${SERVER_FILES}" \
  "${SERVER_POST}" \
  "${SERVER_PREUN}" \
  "${SERVER_POSTUN}" \
  "usr/local/bin/aegis-server" \
  "usr/lib/systemd/system/aegis-server.service" \
  "usr/lib/systemd/system-preset/90-aegis-server.preset" \
  "usr/lib/sysusers.d/aegis-server.conf" \
  "usr/lib/tmpfiles.d/aegis-server.conf" \
  "etc/default/aegis-server" \
  "usr/share/aegis/examples/aegis-server.toml.example" \
  "usr/share/aegis/scripts/generate-relay-materials.sh" \
  "usr/share/aegis/scripts/render-client-bundle.sh" \
  "usr/share/aegis/scripts/package-client-bundle.sh" \
  "usr/share/doc/aegis/README.server.Debian" \
  "usr/share/doc/aegis/README.md" \
  "${PROJECT_LICENSE_PATHS[@]}" \
  "${H2_LICENSE_PATH}" \
  "${TUNGSTENITE_LICENSE_PATHS[@]}"

build_package \
  "aegis-client" \
  "AEGIS Linux-first client runtime" \
  "/etc/default/aegis-client" \
  "${CLIENT_DIRS}" \
  "${CLIENT_FILES}" \
  "${CLIENT_POST}" \
  "${CLIENT_PREUN}" \
  "${CLIENT_POSTUN}" \
  "usr/local/bin/aegis-client" \
  "usr/lib/systemd/system/aegis-client.service" \
  "usr/lib/systemd/system-preset/90-aegis-client.preset" \
  "usr/lib/tmpfiles.d/aegis-client.conf" \
  "etc/default/aegis-client" \
  "usr/share/doc/aegis/README.client.Debian" \
  "usr/share/aegis/examples/config.example.toml" \
  "${PROJECT_LICENSE_PATHS[@]}" \
  "${H2_LICENSE_PATH}" \
  "${TUNGSTENITE_LICENSE_PATHS[@]}"

# Bind every verification to exactly the two files from this invocation's fresh
# RPM_TOPDIR. A reused OUTPUT_DIR may contain older dist suffixes; reject them
# before publishing so the manifest cannot select a stale matching package.
PRESERVE_RPM_FAILURE=1
RPM_PACKAGE_PATHS=()
RPM_PACKAGE_NAMES=()
rpm_count=0
while IFS= read -r -d '' built_rpm; do
  rpm_count=$((rpm_count + 1))
done < <(find "${RPM_TOPDIR}/RPMS" -type f -name '*.rpm' -print0)
if [[ "${rpm_count}" -ne 2 ]]; then
  echo "expected exactly two fresh RPMs, found ${rpm_count}" >&2
  exit 1
fi

# rpmbuild post-processing may add metadata, but must not alter the canonical
# executables or emit a package whose final header names a non-root owner.
RPM_VERIFY_ROOT="${TMP_DIR}/rpm-final-payload"
mkdir -p "${RPM_VERIFY_ROOT}"
for package_name in aegis-server aegis-client; do
  candidates=()
  while IFS= read -r -d '' built_rpm; do
    candidates+=("${built_rpm}")
  done < <(find "${RPM_TOPDIR}/RPMS" -type f -name "${package_name}-${VERSION}-1*.${ARCH}.rpm" -print0)
  if [[ "${#candidates[@]}" -ne 1 ]]; then
    echo "expected exactly one fresh ${package_name} RPM for ${VERSION}/${ARCH}" >&2
    exit 1
  fi
  package_path="${candidates[0]}"
  rpm_name="$(basename "${package_path}")"
  for existing in "${OUTPUT_DIR}/${package_name}-${VERSION}-1"*."${ARCH}".rpm; do
    [[ -e "${existing}" || -L "${existing}" ]] || continue
    if [[ "$(basename "${existing}")" != "${rpm_name}" || ! -f "${existing}" || -L "${existing}" ]]; then
      echo "reused output contains a conflicting ${package_name} RPM: ${existing}" >&2
      exit 1
    fi
  done
  owner_rows="$(rpm -qp --queryformat '[%{FILEUSERNAME}:%{FILEGROUPNAME}\n]' "${package_path}")" || {
    echo "final RPM owner query failed: ${package_name}" >&2
    exit 1
  }
  if [[ -z "${owner_rows}" ]] || grep -vFx 'root:root' <<< "${owner_rows}" >/dev/null; then
    echo "final RPM contains a non-root owner or group: ${package_name}" >&2
    exit 1
  fi
  (
    cd "${RPM_VERIFY_ROOT}"
    rpm2cpio "${package_path}" | cpio -idmu --quiet
  )
  if ! cmp -s \
    "${ROOTFS_DIR}/usr/local/bin/${package_name}" \
    "${RPM_VERIFY_ROOT}/usr/local/bin/${package_name}"; then
    echo "final RPM binary parity failure: ${package_name} payload differs from canonical package-root" >&2
    exit 1
  fi
  RPM_PACKAGE_PATHS+=("${package_path}")
  RPM_PACKAGE_NAMES+=("${rpm_name}")
done

# Stage the entire pair and metadata on the destination filesystem. The manifest
# is the completion marker; consumers verify it and both sidecars before use.
STAGED_SET="$(mktemp -d "${OUTPUT_DIR}/.rpm-set.XXXXXX")"
for index in 0 1; do
  cp -- "${RPM_PACKAGE_PATHS[index]}" "${STAGED_SET}/${RPM_PACKAGE_NAMES[index]}"
  chmod 0644 "${STAGED_SET}/${RPM_PACKAGE_NAMES[index]}"
  if ! cmp -s "${RPM_PACKAGE_PATHS[index]}" "${STAGED_SET}/${RPM_PACKAGE_NAMES[index]}"; then
    echo "staged RPM differs from verified source: ${RPM_PACKAGE_NAMES[index]}" >&2
    exit 1
  fi
done
cargo run --locked -q -p aegis-measure -- build-rpm-packages-manifest \
  --output-dir "${STAGED_SET}" \
  --version "${VERSION}" \
  --arch "${ARCH}"
python3 -I -B "${ROOT}/scripts/verify-rpm-package-set.py" "${STAGED_SET}" \
  --arch "${ARCH}" --version "${VERSION}"

# Invalidate a prior completion marker before replacing any visible member.
# A crash leaves an incomplete pair without its marker; a later retry must
# verify/publish afresh. Keep the old marker in the private failed-attempt tree.
if [[ -e "${OUTPUT_DIR}/rpm-packages.manifest.json" || -L "${OUTPUT_DIR}/rpm-packages.manifest.json" ]]; then
  mv -- "${OUTPUT_DIR}/rpm-packages.manifest.json" "${TMP_DIR}/prior-rpm-packages.manifest.json"
fi
for index in 0 1; do
  mv -f -- "${STAGED_SET}/${RPM_PACKAGE_NAMES[index]}" "${OUTPUT_DIR}/${RPM_PACKAGE_NAMES[index]}"
  mv -f -- "${STAGED_SET}/${RPM_PACKAGE_NAMES[index]}.sha256" "${OUTPUT_DIR}/${RPM_PACKAGE_NAMES[index]}.sha256"
done
# A second check on the visible members catches a failed or interrupted rename
# before the only completion marker becomes visible.
for index in 0 1; do
  cmp -s "${RPM_PACKAGE_PATHS[index]}" "${OUTPUT_DIR}/${RPM_PACKAGE_NAMES[index]}" || {
    echo "published RPM differs from verified source: ${RPM_PACKAGE_NAMES[index]}" >&2
    exit 1
  }
done
mv -- "${STAGED_SET}/rpm-packages.manifest.json" "${OUTPUT_DIR}/rpm-packages.manifest.json"
python3 -I -B "${ROOT}/scripts/verify-rpm-package-set.py" "${OUTPUT_DIR}" \
  --arch "${ARCH}" --version "${VERSION}"
rmdir -- "${STAGED_SET}"

cat <<EOF
Split RPM packages created
-------------------------
Manifest:
  ${OUTPUT_DIR}/rpm-packages.manifest.json
EOF
