#!/usr/bin/env bash
# Build a macOS client tarball for release distribution.
#
# Usage:
#   scripts/build-macos-client-tarball.sh <output-dir> <target-triple>
#
# <target-triple>:
#   x86_64-apple-darwin   -> Intel Mac
#   aarch64-apple-darwin  -> Apple Silicon (M1/M2/M3/M4)
#
# Output (under <output-dir>):
#   aegis-client-<VERSION>-macos-<arch>.tar.gz
#   aegis-client-<VERSION>-macos-<arch>.tar.gz.sha256
#
# Tarball contents:
#   aegis-client-<VERSION>-macos-<arch>/
#     bin/aegis-client
#     config.example.toml
#     README.macos.txt
#     install-macos-client.sh   (unpacks + copies bin + config, optional launchd plist)
#
# Designed to be runnable:
#   - Locally on a Mac dev host (self-build)
#   - In GitHub Actions on macos-13 (Intel) or macos-14 (Apple Silicon) runners
#
# Script assumes `cargo` and `rustup` available; ensures target is installed
# via rustup before building.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${CARGO_HOME:-${HOME}/.cargo}/bin:${PATH}"
. "${ROOT}/scripts/lib/release-toolchain.sh"

usage() {
  cat <<'EOF'
Usage:
  scripts/build-macos-client-tarball.sh <output-dir> <target-triple>

Target triples:
  x86_64-apple-darwin    Intel Mac
  aarch64-apple-darwin   Apple Silicon Mac

Produces:
  <output-dir>/aegis-client-<version>-macos-<arch>.tar.gz(+.sha256)
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -ne 2 ]]; then
  usage >&2
  exit 1
fi

OUTPUT_DIR="$1"
TARGET_TRIPLE="$2"
GIT_SHA="${AEGIS_BUILD_GIT_SHA:-$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')}"
BUILD_TIMESTAMP="${AEGIS_BUILD_TIMESTAMP:-$(release_source_timestamp)}"
export AEGIS_BUILD_GIT_SHA="${GIT_SHA}"
export AEGIS_BUILD_TIMESTAMP="${BUILD_TIMESTAMP}"

case "${TARGET_TRIPLE}" in
  x86_64-apple-darwin)
    ARCH="x86_64"
    ;;
  aarch64-apple-darwin)
    ARCH="aarch64"
    ;;
  *)
    echo "Unsupported target triple: ${TARGET_TRIPLE}" >&2
    echo "Expected: x86_64-apple-darwin | aarch64-apple-darwin" >&2
    exit 1
    ;;
esac

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required; install Rust via rustup first" >&2
  exit 1
fi

# Resolve the entire pinned toolchain before Cargo starts parallel workers.
# Resolving only Cargo leaves its child rustc processes using rustup proxies;
# those can concurrently try to install components from a crate's override.
# `rustup which cargo` also avoids the rustup-init shim seen on macOS runners.
# Checked non-rustup installations remain supported.
CARGO_BIN="cargo"
if ! command -v rustc >/dev/null 2>&1; then
  echo "rustc is required; install the pinned Rust toolchain first" >&2
  exit 1
fi
RUSTC_BIN="$(command -v rustc)"
if command -v rustup >/dev/null 2>&1; then
  release_toolchain="$(sed -n 's/^channel = "\([0-9][0-9.]*\)"$/\1/p' "${ROOT}/rust-toolchain.toml")"
  if [[ -z "${release_toolchain}" ]]; then
    echo "release requires an exact rust-toolchain.toml compiler pin" >&2
    exit 1
  fi
  export RUSTUP_TOOLCHAIN="${release_toolchain}"
  CARGO_BIN="$(rustup which --toolchain "${release_toolchain}" cargo)"
  RUSTC_BIN="$(rustup which --toolchain "${release_toolchain}" rustc)"
  RUSTDOC_BIN="$(rustup which --toolchain "${release_toolchain}" rustdoc)"
  for tool in "${CARGO_BIN}" "${RUSTC_BIN}" "${RUSTDOC_BIN}"; do
    if [[ ! -x "${tool}" ]]; then
      echo "resolved pinned toolchain binary is not executable: ${tool}" >&2
      exit 1
    fi
  done
  export RUSTDOC="${RUSTDOC_BIN}"
  export PATH="$(dirname "${RUSTC_BIN}"):${PATH}"
fi
export RUSTC="${RUSTC_BIN}"
verify_release_toolchain

# Target installation is serial, uses the same pin, and must succeed before
# any build. Do not mask preparation errors or fall back to another toolchain.
if command -v rustup >/dev/null 2>&1; then
  rustup target add --toolchain "${release_toolchain}" "${TARGET_TRIPLE}"
fi

# Resolve the package version without compiling helper crates. GitHub macOS
# runners have shown transient rustup/rust-src component conflicts before the
# actual client build starts; using the manifest as the source of truth keeps
# packaging out of that rustup path.
VERSION="$(
  awk '
    $1 == "version" {
      gsub(/"/, "", $3);
      print $3;
      exit
    }
  ' "${ROOT}/aegis-client/Cargo.toml"
)"
if [[ -z "${VERSION}" ]]; then
  echo "Unable to resolve aegis-client version from Cargo.toml" >&2
  exit 1
fi

BUNDLE_NAME="aegis-client-${VERSION}-macos-${ARCH}"
BUNDLE_DIR="${OUTPUT_DIR}/${BUNDLE_NAME}"
ARCHIVE_PATH="${OUTPUT_DIR}/${BUNDLE_NAME}.tar.gz"
SHA256_PATH="${ARCHIVE_PATH}.sha256"

mkdir -p "${OUTPUT_DIR}"
rm -rf "${BUNDLE_DIR}" "${ARCHIVE_PATH}" "${SHA256_PATH}"

cd "${ROOT}"

# Build aegis-client only for macOS. Server not packaged (macOS operator host
# is not the primary deployment path — relay servers live on Linux VPS).
#
# Feature set must match the Linux release bundle (build-release-bundle.sh) for
# everything that is portable. `raw-socket` is Linux-only, but the two TLS/QUIC
# mimicry features are not: without them the config default
# `chrome_like_experimental` degrades at connect time to the rustls
# ClientHello, which is trivially distinguishable from a browser. That degrade
# is a warn line, so a macOS build missing the feature shipped the headline
# anti-DPI capability switched off and looked fine doing it.
#
# aws-lc-sys needs cmake. Fail loudly rather than let a runner without it fall
# back to a binary that quietly cannot mimic Chrome.
if ! command -v cmake >/dev/null 2>&1; then
  echo "cmake is required to build the chrome-like-tls feature (aws-lc-sys)." >&2
  echo "Install it (brew install cmake) and re-run; a build without this" >&2
  echo "feature ships a distinguishable TLS ClientHello and is not releasable." >&2
  exit 1
fi

"${CARGO_BIN}" build --locked --release -p aegis-client \
  --features chrome-like-tls,chrome-like-quic \
  --target "${TARGET_TRIPLE}"

TARGET_BIN="${ROOT}/target/${TARGET_TRIPLE}/release/aegis-client"
if [[ ! -x "${TARGET_BIN}" ]]; then
  echo "Build completed but binary not found at ${TARGET_BIN}" >&2
  exit 1
fi

mkdir -p "${BUNDLE_DIR}/bin"
cp "${TARGET_BIN}" "${BUNDLE_DIR}/bin/aegis-client"
chmod 0755 "${BUNDLE_DIR}/bin/aegis-client"
"${RUSTC_BIN}" --edition=2021 --target "${TARGET_TRIPLE}" -O \
  "${ROOT}/tools/macos/proxy-keychain.rs" -o "${BUNDLE_DIR}/bin/aegis-proxy-keychain"
chmod 0755 "${BUNDLE_DIR}/bin/aegis-proxy-keychain"

cp "${ROOT}/config.example.toml" "${BUNDLE_DIR}/config.example.toml"
for project_license in LICENSE-MIT LICENSE-APACHE NOTICE; do
  [[ -f "${ROOT}/${project_license}" && ! -L "${ROOT}/${project_license}" ]] || {
    echo "Missing regular project license text: ${project_license}" >&2
    exit 1
  }
  cp -P "${ROOT}/${project_license}" "${BUNDLE_DIR}/${project_license}"
  [[ -f "${BUNDLE_DIR}/${project_license}" && ! -L "${BUNDLE_DIR}/${project_license}" ]] || exit 1
  chmod 0644 "${BUNDLE_DIR}/${project_license}"
done

# macOS-specific operator README — concise install pointer.
cat > "${BUNDLE_DIR}/README.macos.txt" <<EOF
AEGIS client for macOS (${ARCH}) — version ${VERSION}
===============================================

## Quick install

\`\`\`
tar xzf ${BUNDLE_NAME}.tar.gz
cd ${BUNDLE_NAME}
sudo ./install-macos-client.sh --bundle-url-file /absolute/root-private/access-url.txt
\`\`\`

## Manual install

\`\`\`
sudo cp bin/aegis-client /usr/local/bin/aegis-client
sudo chmod 0755 /usr/local/bin/aegis-client
mkdir -p ~/.config/aegis
# fetch client-bundle.tar.gz from your operator's bundle URL
# extract config.toml + ca.pem + auth-token.txt into ~/.config/aegis/
aegis-client --config ~/.config/aegis/aegis.toml
\`\`\`

The client exposes a SOCKS5 proxy on \`127.0.0.1:1080\` (or whatever is
configured). Point your browser / tools at it.

Verify traffic is tunneled:

\`\`\`
curl --socks5-hostname 127.0.0.1:1080 https://httpbin.org/ip
# should return the relay server's IP, not your local IP
\`\`\`

For operator bundle generation instructions see the Linux server release
README.
EOF

# v0.3.2: full-featured install helper. Mirrors Linux install.sh client
# capabilities — SPKI pin extraction from URL, SOCKS5 RFC 1929 auth_token
# injection, launchd LaunchAgent registration with idempotent unload+load,
# --reinstall purge, --insecure TOFU mode for legacy URLs without pin.
cat > "${BUNDLE_DIR}/install-macos-client.sh" <<'EOF'
#!/usr/bin/env bash
# Install aegis-client on macOS from this tarball + an operator-supplied
# bundle URL with optional &pin=sha256// query param.
set -euo pipefail

usage() {
  cat <<'HELP'
Usage:
  ./install-macos-client.sh --bundle-url-file <path> [options]

Required:
  --bundle-url-file <path>    Owner-private HTTPS/file URL record for the client-bundle
                              tarball. URLs with &pin=sha256//<base64>
                              query param trigger SPKI public-key pin
                              validation (recommended; v0.3.1+ servers).

Options:
  --service-mode <mode>       auto, launchagent, launchdaemon, foreground.
                              auto selects LaunchAgent only when the target
                              user has an active gui/<uid> launchd domain;
                              otherwise it installs files and prints a
                              foreground/LaunchDaemon recommendation.
  --service-user <user>       Target user for LaunchDaemon mode (required
                              for launchdaemon; usually "aegis").
  --user-home <path>          Home directory for --service-user when running
                              installer as root. Public-text installation requires
                              physical HOME ownership by that exact target UID;
                              new objects must share a filesystem with trusted /tmp.
  --bundle-cacert-pin <pin>   Explicit pin override (sha256//<base64>).
  --insecure                  Skip TLS validation entirely (TOFU; only
                              safe over a trusted bundle URL channel).
  --no-browser-proxy          Skip browser credential preparation.
  --prepare-browser-proxy     Require preparation (automatic for a local
                              logged-in user by default). Prepare the local SOCKS Keychain credential and
                              restricted Safari/system consumer access. Run
                              as the logged-in install user. Does not change
                              system routing; macOS may ask once to authorize.
  --reinstall                 Purge any prior macOS install before
                              installing fresh (rm config + plist +
                              binary, launchctl unload).
  --config-dir <path>         Override default ~/.config/aegis.
  -h, --help                  This help.

Installs:
  ~/.local/bin/aegis-client                              (binary, no sudo)
  ~/.config/aegis/aegis.toml                             (config, 0o600)
  ~/.config/aegis/ca.pem                                 (CA, 0o600)
  ~/.local/share/doc/aegis/{LICENSE-MIT,LICENSE-APACHE,NOTICE} (project texts, 0o644)
  ~/Library/LaunchAgents/dev.aegis.client.plist          (LaunchAgent)
  /Library/LaunchDaemons/dev.aegis.client.plist          (LaunchDaemon,
                                                          explicit mode only)
  ~/.local/state/aegis/runtime-events.jsonl              (runtime log)
HELP
}

if [[ $# -eq 0 ]]; then
  usage
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUNDLE_URL_FILE=""
BUNDLE_LOCAL_ONLY=0
BUNDLE_CACERT_PIN=""
BUNDLE_INSECURE=0
REINSTALL=0
CONFIG_DIR_OVERRIDE=""
SERVICE_MODE="auto"
SERVICE_USER=""
PREPARE_BROWSER_PROXY=auto
USER_HOME_OVERRIDE=""

# Old inline/positional URL entry forms are refused without reflecting input.
if [[ "$#" -eq 1 && "$1" != -* ]]; then
  echo "Inline bundle URLs are refused; use --bundle-url-file." >&2; exit 2
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle-url|--bundle-url=*|--auth-token|--auth-token=*) echo "Inline secrets are refused; use --bundle-url-file." >&2; exit 2 ;;
    --bundle-url-file) [[ $# -ge 2 && -z "$BUNDLE_URL_FILE" ]] || exit 2; BUNDLE_URL_FILE="$2"; shift 2 ;;
    --bundle-local-only) BUNDLE_LOCAL_ONLY=1; shift ;;
    --bundle-cacert-pin) BUNDLE_CACERT_PIN="$2"; shift 2 ;;
    --insecure) BUNDLE_INSECURE=1; shift ;;
    --no-browser-proxy) PREPARE_BROWSER_PROXY=0; shift ;;
    --prepare-browser-proxy) PREPARE_BROWSER_PROXY=1; shift ;;
    --reinstall) REINSTALL=1; shift ;;
    --config-dir) CONFIG_DIR_OVERRIDE="$2"; shift 2 ;;
    --service-mode) SERVICE_MODE="$2"; shift 2 ;;
    --service-user) SERVICE_USER="$2"; shift 2 ;;
    --user-home) USER_HOME_OVERRIDE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unsupported installer input; use --bundle-url-file and documented options." >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "${BUNDLE_URL_FILE}" ]]; then
  echo "--bundle-url-file is required" >&2
  usage >&2
  exit 1
fi

case "${SERVICE_MODE}" in
  auto|launchagent|launchdaemon|foreground) ;;
  *)
    echo "--service-mode must be one of: auto, launchagent, launchdaemon, foreground" >&2
    exit 1
    ;;
esac

resolve_user_home() {
  local user="$1"
  local resolved=""
  if command -v dscl >/dev/null 2>&1; then
    resolved="$(dscl . -read "/Users/${user}" NFSHomeDirectory 2>/dev/null | awk '{print $2; exit}' || true)"
  fi
  if [[ -z "${resolved}" ]]; then
    resolved="$(eval "printf '%s' ~${user}" 2>/dev/null || true)"
  fi
  printf '%s\n' "${resolved}"
}

INSTALL_USER="${SERVICE_USER:-$(id -un)}"
if [[ "${SERVICE_MODE}" == "launchdaemon" && -z "${SERVICE_USER}" ]]; then
  echo "--service-user is required for LaunchDaemon mode (for example: --service-user aegis)" >&2
  exit 1
fi

INSTALL_HOME="${USER_HOME_OVERRIDE:-}"
if [[ -z "${INSTALL_HOME}" ]]; then
  if [[ "${INSTALL_USER}" == "$(id -un)" ]]; then
    INSTALL_HOME="${HOME}"
  else
    INSTALL_HOME="$(resolve_user_home "${INSTALL_USER}")"
  fi
fi
if [[ -z "${INSTALL_HOME}" || "${INSTALL_HOME}" == "~${INSTALL_USER}" ]]; then
  echo "Could not resolve home directory for ${INSTALL_USER}; pass --user-home" >&2
  exit 1
fi

# Private URL and its optional pin are parsed only by the packaged Rust client.
[[ "$("$SCRIPT_DIR/bin/aegis-client" profile installer-secret version)" == installer-secret-v1 ]] || {
  echo "Selected release lacks the private installer input protocol." >&2; exit 2;
}

CONFIG_DIR="${CONFIG_DIR_OVERRIDE:-${INSTALL_HOME}/.config/aegis}"
BIN_DIR="${INSTALL_HOME}/.local/bin"
BIN_DEST="${BIN_DIR}/aegis-client"
DOC_DIR="${INSTALL_HOME}/.local/share/doc/aegis"
LAUNCH_AGENT_DIR="${INSTALL_HOME}/Library/LaunchAgents"
PLIST_PATH="${LAUNCH_AGENT_DIR}/dev.aegis.client.plist"
DAEMON_PLIST_PATH="/Library/LaunchDaemons/dev.aegis.client.plist"
STATE_DIR="${INSTALL_HOME}/.local/state/aegis"
LOG_DIR="${STATE_DIR}/log"
RUNTIME_EVENTS="${STATE_DIR}/runtime-events.jsonl"
INSTALL_GROUP="$(id -gn "${INSTALL_USER}" 2>/dev/null || printf 'staff')"

target_uid() {
  id -u "${INSTALL_USER}" 2>/dev/null
}

detect_gui_launchd_domain() {
  local uid
  uid="$(target_uid)" || return 1
  launchctl print "gui/${uid}" >/dev/null 2>&1
}

chown_target_user() {
  if [[ ${EUID} -eq 0 ]]; then
    chown -R "${INSTALL_USER}:${INSTALL_GROUP}" "$@"
  fi
}

macos_temp_candidates() {
  if [[ -n "${AEGIS_INSTALL_TMPDIR_CANDIDATES:-}" ]]; then
    printf '%s\n' "${AEGIS_INSTALL_TMPDIR_CANDIDATES}" | tr ':' '\n'
    return 0
  fi

  printf '%s\n' \
    "${TMPDIR:-/tmp}" \
    "${INSTALL_HOME}/.cache/aegis/tmp" \
    "${STATE_DIR}/tmp"
}

# True for paths AEGIS owns, where re-owning to the install user is correct even
# when the directory already exists. A shared system temp dir is NOT one of these.
aegis_owned_temp_base() {
  local candidate="${1%/}"
  case "${candidate}" in
    "${INSTALL_HOME%/}/.cache/aegis" | "${INSTALL_HOME%/}/.cache/aegis"/*) return 0 ;;
    "${STATE_DIR%/}" | "${STATE_DIR%/}"/*) return 0 ;;
    *) return 1 ;;
  esac
}

prepare_temp_base() {
  local candidate="$1"
  local existed=0

  [[ -n "${candidate}" ]] || return 1
  [[ -d "${candidate}" ]] && existed=1
  mkdir -p "${candidate}" 2>/dev/null || return 1
  # Only adjust ownership/permissions on a directory we just created, or on one
  # AEGIS owns.
  #
  # This used to also fire whenever EUID was 0. `sudo` resets the environment and
  # does not keep TMPDIR, so under the documented `sudo ./install-macos-client.sh`
  # the first candidate resolves to the shared /tmp — which already exists — and the
  # installer would `chmod 0700 /tmp` (taking the system temp dir away from every
  # other process on the machine) and `chown -R` it to the unprivileged install
  # user, handing them every root-owned file and socket sitting there.
  if [[ "${existed}" -eq 0 ]] || aegis_owned_temp_base "${candidate}"; then
    chmod 0700 "${candidate}" 2>/dev/null || true
    chown_target_user "${candidate}"
  fi
  [[ -d "${candidate}" && -w "${candidate}" && -x "${candidate}" ]]
}

make_macos_temp_dir() {
  local prefix="$1"
  local candidate=""

  while IFS= read -r candidate; do
    if prepare_temp_base "${candidate}"; then
      mktemp -d "${candidate%/}/${prefix}.XXXXXX"
      return 0
    fi
  done < <(macos_temp_candidates)

  echo "[install-macos] no writable temp directory found; set TMPDIR or AEGIS_INSTALL_TMPDIR_CANDIDATES" >&2
  return 1
}

render_plist_template() {
  local template="$1"
  local output="$2"
  sed \
    -e "s|__AEGIS_CLIENT_BIN__|${BIN_DEST}|g" \
    -e "s|__AEGIS_CLIENT_CONFIG__|${CONFIG_DIR}/aegis.toml|g" \
    -e "s|__AEGIS_CLIENT_STATE_DIR__|${STATE_DIR}|g" \
    -e "s|__AEGIS_CLIENT_RUNTIME_EVENTS_JSONL__|${RUNTIME_EVENTS}|g" \
    -e "s|__AEGIS_CLIENT_LOG_DIR__|${LOG_DIR}|g" \
    -e "s|__AEGIS_CLIENT_USER__|${INSTALL_USER}|g" \
    -e "s|__AEGIS_CLIENT_GROUP__|${INSTALL_GROUP}|g" \
    "${template}" > "${output}"
}

# Admission staging must survive the later reinstall purge. Never chmod,
# chown, or create an existing installation's temp base during this preflight.
# A state-only or nonexistent fallback now refuses before teardown.
make_macos_preflight_temp_dir() {
  local prefix="$1" candidate="" base="" root="" forbidden=0
  while IFS= read -r candidate; do
    [[ -d "$candidate" && -w "$candidate" && -x "$candidate" ]] || continue
    base="$(cd "$candidate" && pwd -P)" || continue
    forbidden=0
    for root in "$CONFIG_DIR" "$STATE_DIR" "$DOC_DIR" "$INSTALL_HOME/.local/lib/aegis" "$BIN_DEST" "$PLIST_PATH"; do
      [[ -d "$root" ]] || continue
      root="$(cd "$root" && pwd -P)" || return 1
      case "$base/" in "$root/"*) forbidden=1 ;; esac
    done
    [[ "$forbidden" == 0 ]] || continue
    mktemp -d "$base/${prefix}.XXXXXX"
    return $?
  done < <(macos_temp_candidates)
  echo "[install-macos] no existing temporary base outside reinstall roots; set TMPDIR" >&2
  return 1
}

# Detect existing install (without --reinstall) and prompt or fail.
if [[ -f "${PLIST_PATH}" || -f "${DAEMON_PLIST_PATH}" || -f "${CONFIG_DIR}/aegis.toml" || -f "${BIN_DEST}" ]]; then
  if [[ "${REINSTALL}" -eq 0 ]]; then
    echo "[install-macos] existing install detected (config, binary, LaunchAgent, or LaunchDaemon)" >&2
    echo "[install-macos] re-run with --reinstall to wipe and install fresh" >&2
    exit 1
  fi
fi


TMP_BUNDLE="$(make_macos_preflight_temp_dir "aegis-bundle")"
trap 'rm -rf "${TMP_BUNDLE}"' EXIT

# Expected project bytes are bound into this generated installer by the builder
# and covered by the software archive/manifest. Initial release trust must still
# be verified independently; these hashes do not authenticate an untrusted tar.
project_license_expected_hash() {
  case "$1" in
    LICENSE-MIT) printf '%s\n' '__AEGIS_PROJECT_LICENSE_MIT_SHA256__' ;;
    LICENSE-APACHE) printf '%s\n' '__AEGIS_PROJECT_LICENSE_APACHE_SHA256__' ;;
    NOTICE) printf '%s\n' '__AEGIS_PROJECT_NOTICE_SHA256__' ;;
    *) return 1 ;;
  esac
}
[[ "$("$SCRIPT_DIR/bin/aegis-client" profile project-license version)" == project-license-v1 ]] || {
  echo '[install-macos] packaged client lacks public project-text protocol' >&2; exit 2;
}
PROJECT_TARGET_UID="$(target_uid)"
PROJECT_TARGET_GID="$(id -g "${INSTALL_USER}")"
project_document_operation() {
  local action="$1" leaf="$2"
  case "$action" in check|install) ;; *) return 1 ;; esac
  if "$SCRIPT_DIR/bin/aegis-client" profile project-license "$action" \
    --home "$INSTALL_HOME" --owner-uid "$PROJECT_TARGET_UID" --owner-gid "$PROJECT_TARGET_GID" \
    --leaf "$leaf" --expected-sha256 "$(project_license_expected_hash "$leaf")" \
    < "$PROJECT_LICENSE_STAGE/$leaf"; then
    return 0
  fi
  # The client's private event logger deliberately hides internal error text.
  # Emit only this closed public operation label, never input, paths or payload.
  case "$action" in
    check) echo '[install-macos] public project text check refused' >&2 ;;
    install) echo '[install-macos] public project text install refused' >&2 ;;
  esac
  return 1
}
PROJECT_LICENSE_STAGE="${TMP_BUNDLE}/project-license-texts"
mkdir "${PROJECT_LICENSE_STAGE}"
chmod 0700 "${PROJECT_LICENSE_STAGE}"
for project_license in LICENSE-MIT LICENSE-APACHE NOTICE; do
  project_source="${SCRIPT_DIR}/${project_license}"
  project_snapshot="${PROJECT_LICENSE_STAGE}/${project_license}"
  [[ -f "${project_source}" && ! -L "${project_source}" ]] || {
    echo "[install-macos] missing regular project text: ${project_license}" >&2; exit 1;
  }
  # -P never follows a source symlink substituted during the snapshot copy.
  cp -P "${project_source}" "${project_snapshot}"
  [[ -f "${project_snapshot}" && ! -L "${project_snapshot}" ]] || exit 1
  [[ "$(wc -c < "${project_snapshot}")" -le 65536 ]] || exit 1
  project_expected="$(project_license_expected_hash "${project_license}")"
  [[ "${project_expected}" =~ ^[0-9a-f]{64}$ ]] || exit 1
  project_actual="$(shasum -a 256 "${project_snapshot}" | awk '{print $1}')"
  [[ "${project_actual}" == "${project_expected}" ]] || {
    echo "[install-macos] changed project text: ${project_license}" >&2; exit 1;
  }
  chmod 0644 "${project_snapshot}"
  project_document_operation check "$project_license"
done

echo "[install-macos] fetching client bundle using the private access record"
private_fetch_args=(profile installer-secret fetch --input "$BUNDLE_URL_FILE"
  --output "$TMP_BUNDLE/client-bundle.tar.gz" --connect-seconds 10 --total-seconds 120 --allow-local-path)
[[ -z "$BUNDLE_CACERT_PIN" ]] || private_fetch_args+=(--pin "$BUNDLE_CACERT_PIN")
[[ "$BUNDLE_INSECURE" != 1 ]] || private_fetch_args+=(--insecure)
[[ "$BUNDLE_LOCAL_ONLY" != 1 ]] || private_fetch_args+=(--local-only)
"$SCRIPT_DIR/bin/aegis-client" "${private_fetch_args[@]}"

tar --no-same-owner -xzf "${TMP_BUNDLE}/client-bundle.tar.gz" -C "${TMP_BUNDLE}"
BUNDLE_ROOT=""
for candidate in "${TMP_BUNDLE}/client-bundle" "${TMP_BUNDLE}"/*/; do
  if [[ -f "${candidate}/aegis-client.toml" ]]; then
    BUNDLE_ROOT="${candidate}"
    break
  fi
done
if [[ -z "${BUNDLE_ROOT}" ]]; then
  echo "[install-macos] bundle missing aegis-client.toml" >&2
  exit 1
fi


# Stage only an explicitly referenced well-known bundled public MASQUE CA.
# The packaged client owns TOML parsing and guarded writes; no config is printed.
[[ "$("$SCRIPT_DIR/bin/aegis-client" profile bundle-ca version)" == bundle-ca-v1 ]] || {
  echo "[install-macos] packaged client lacks bundled CA staging protocol" >&2
  exit 2
}
BUNDLE_CONFIG_STAGE="${TMP_BUNDLE}/installed-config-stage"
BUNDLED_CA_PURGE_ARGS=()
if [[ "$REINSTALL" -eq 1 ]]; then BUNDLED_CA_PURGE_ARGS+=(--purge-existing); fi
"$SCRIPT_DIR/bin/aegis-client" profile bundle-ca prepare \
  --bundle-root "$BUNDLE_ROOT" --stage-root "$BUNDLE_CONFIG_STAGE" \
  --config-dir "$CONFIG_DIR" --owner-uid "$(target_uid)" ${BUNDLED_CA_PURGE_ARGS[@]+"${BUNDLED_CA_PURGE_ARGS[@]}"}

if [[ "${REINSTALL}" -eq 1 ]]; then
  echo "[install-macos] --reinstall: purging previous install"
  if [[ -f "${PLIST_PATH}" ]]; then
    if detect_gui_launchd_domain; then
      launchctl bootout "gui/$(target_uid)" "${PLIST_PATH}" 2>/dev/null || true
    fi
    launchctl unload -w "${PLIST_PATH}" 2>/dev/null || true
  fi
  if [[ ${EUID} -eq 0 && -f "${DAEMON_PLIST_PATH}" ]]; then
    launchctl bootout system "${DAEMON_PLIST_PATH}" 2>/dev/null || true
    rm -f "${DAEMON_PLIST_PATH}" 2>/dev/null || true
  fi
  rm -rf "${CONFIG_DIR}" "${STATE_DIR}" "${PLIST_PATH}" "${BIN_DEST}" 2>/dev/null || true
  # Cleanup of v0.3.1-leftover Linux-bundle install paths
  rm -rf "${INSTALL_HOME}/.local/lib/aegis" 2>/dev/null || true
fi

mkdir -p "${BIN_DIR}" "${CONFIG_DIR}" "${STATE_DIR}" "${LOG_DIR}" "${LAUNCH_AGENT_DIR}"
chmod 0700 "${CONFIG_DIR}" "${STATE_DIR}" 2>/dev/null || true
chown_target_user "${BIN_DIR}" "${CONFIG_DIR}" "${STATE_DIR}" "${LOG_DIR}" "${LAUNCH_AGENT_DIR}"

echo "[install-macos] installing binary → ${BIN_DEST}"
cp "${SCRIPT_DIR}/bin/aegis-client" "${BIN_DEST}"
chmod 0755 "${BIN_DEST}"
chown_target_user "${BIN_DEST}"

# Project documentation is public payload, separate from private configuration
# and state. Install only the preflight-verified private snapshots.
# The Rust helper binds physical HOME to the exact target UID and holds every
# suffix descriptor. Existing directories receive no chmod/chown. Fresh objects
# are prepared privately and atomically published; cross-filesystem HOME staging
# refuses EXDEV without fallback. Initial tar authenticity remains external.
for project_license in LICENSE-MIT LICENSE-APACHE NOTICE; do
  project_document_operation install "$project_license"
done

write_install_manifest() {
  local manifest_path="${STATE_DIR}/install-manifest.json"
  local bundle_manifest_path="${SCRIPT_DIR}/macos-client-bundle.manifest.json"
  local source_manifest_url="${AEGIS_INSTALL_SOURCE_MANIFEST_URL:-}"
  local source_manifest_json="null"
  local installed_at
  local binary_sha256
  local version
  local git_sha
  local build_timestamp
  local platform
  local arch
  local target_triple
  local binary_path_canonical
  mkdir -p "$(dirname "${manifest_path}")"

  json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
  }

  json_string_field() {
    local key="$1"
    awk -v key="${key}" '
      $0 ~ "\"" key "\"" "[[:space:]]*:" {
        value = $0
        sub(/^[^:]*:[[:space:]]*"/, "", value)
        sub(/".*$/, "", value)
        print value
        exit
      }
    ' "${bundle_manifest_path}"
  }

  version="$(json_string_field version)"
  git_sha="$(json_string_field git_sha)"
  build_timestamp="$(json_string_field build_timestamp)"
  platform="$(json_string_field platform)"
  arch="$(json_string_field arch)"
  target_triple="$(json_string_field target_triple)"
  [[ -z "${git_sha}" ]] && git_sha="unknown"
  [[ -z "${platform}" ]] && platform="macos"

  installed_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  binary_sha256="$(shasum -a 256 "${BIN_DEST}" | awk '{print $1}')"
  binary_path_canonical="$(printf '%s' "${BIN_DEST}" | sed 's|//*|/|g')"
  if [[ -n "${source_manifest_url}" ]]; then
    source_manifest_json="\"$(json_escape "${source_manifest_url}")\""
  fi

  cat > "${manifest_path}" <<MANIFEST_EOF
{
  "arch": "$(json_escape "${arch}")",
  "binary_path": "$(json_escape "${binary_path_canonical}")",
  "binary_sha256": "${binary_sha256}",
  "build_timestamp": "$(json_escape "${build_timestamp}")",
  "git_sha": "$(json_escape "${git_sha}")",
  "installed_at": "${installed_at}",
  "platform": "$(json_escape "${platform}")",
  "role": "client",
  "schema": "aegis_install_manifest_v1",
  "source_manifest_url": ${source_manifest_json},
  "target_triple": "$(json_escape "${target_triple}")",
  "version": "$(json_escape "${version}")"
}
MANIFEST_EOF
  chmod 0644 "${manifest_path}" 2>/dev/null || true
  chown_target_user "${manifest_path}"
}


# Substitute __CLIENT_CA_CERT_PATH__ placeholder with actual path.
CA_PATH="${CONFIG_DIR}/ca.pem"
if [[ -f "${BUNDLE_ROOT}/ca.pem" ]]; then
  cp "${BUNDLE_ROOT}/ca.pem" "${CA_PATH}"
  chmod 0600 "${CA_PATH}"
  chown_target_user "${CA_PATH}"
fi
"$SCRIPT_DIR/bin/aegis-client" profile bundle-ca install \
  --stage-root "$BUNDLE_CONFIG_STAGE" --config-dir "$CONFIG_DIR" --owner-uid "$(target_uid)"
if [[ -f "${BUNDLE_CONFIG_STAGE}/masque-ca.pem" ]]; then
  chown_target_user "${CONFIG_DIR}/masque-ca.pem"
fi
sed "s|__CLIENT_CA_CERT_PATH__|${CA_PATH}|g" "${BUNDLE_CONFIG_STAGE}/aegis-client.toml" > "${CONFIG_DIR}/aegis.toml"
chmod 0600 "${CONFIG_DIR}/aegis.toml"
chown_target_user "${CONFIG_DIR}/aegis.toml"
write_install_manifest

# Inject per-install random SOCKS5 RFC 1929 auth_token + local_hardened
# stealth profile (matches Linux install.sh client behavior).
export -n SOCKS_TOKEN
if command -v openssl >/dev/null 2>&1; then
  SOCKS_TOKEN="$(openssl rand -hex 32)"
else
  SOCKS_TOKEN="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
fi

printf '%s\n' "${SOCKS_TOKEN}" | awk '
  BEGIN {
    if ((getline token < "/dev/stdin") != 1 || length(token) != 64 || token !~ /^[[:xdigit:]]+$/) {
      exit 1
    }
    close("/dev/stdin")
  }
  function trim(value) {
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
    return value
  }
  function push(value) {
    out[++out_count] = value
  }
  function emit_ingress_block() {
    print "[ingress]"
    print "primary = \"socks5\""
    print "allow_fallback = true"
    print ""
  }
  {
    lines[++line_count] = $0
    if ($0 ~ /^[[:space:]]*local_stealth_profile[[:space:]]*=/) {
      has_local_stealth = 1
    }
  }
  END {
    for (idx = 1; idx <= line_count; idx++) {
      line = lines[idx]
      s = trim(line)
      if (s ~ /^\[.*\]$/) {
        if (in_socks && !injected_token) {
          push("auth_token = \"" token "\"")
          injected_token = 1
        }
        in_socks = (s == "[socks]")
      }
      if (in_socks && line ~ /^[[:space:]]*auth_token[[:space:]]*=/) {
        push("auth_token = \"" token "\"")
        injected_token = 1
        continue
      }
      push(line)
    }
    if (in_socks && !injected_token) {
      push("auth_token = \"" token "\"")
      injected_token = 1
    }
    if (!injected_token) {
      push("")
      push("[socks]")
      push("auth_token = \"" token "\"")
    }

    final_count = 0
    if (!has_local_stealth) {
      final[++final_count] = "# v0.3.2 default: hide aegis-client name in `ps`"
      final[++final_count] = "local_stealth_profile = \"local_hardened\""
      final[++final_count] = ""
    }

    in_ingress = 0
    for (idx = 1; idx <= out_count; idx++) {
      line = out[idx]
      s = trim(line)
      if (s ~ /^\[.*\]$/) {
        in_ingress = (s == "[ingress]")
      }
      if (in_ingress && line ~ /^[[:space:]]*primary[[:space:]]*=/) {
        final[++final_count] = "primary = \"socks5\""
        replaced_ingress_primary = 1
        continue
      }
      final[++final_count] = line
    }

    if (replaced_ingress_primary) {
      for (idx = 1; idx <= final_count; idx++) {
        print final[idx]
      }
      exit
    }

    inserted_ingress = 0
    for (idx = 1; idx <= final_count; idx++) {
      s = trim(final[idx])
      if (!inserted_ingress && s ~ /^\[/ && s != "[ingress]") {
        emit_ingress_block()
        inserted_ingress = 1
      }
      print final[idx]
    }
    if (!inserted_ingress) {
      print ""
      emit_ingress_block()
    }
  }
' "${CONFIG_DIR}/aegis.toml" > "${CONFIG_DIR}/aegis.toml.tmp"
mv "${CONFIG_DIR}/aegis.toml.tmp" "${CONFIG_DIR}/aegis.toml"
chmod 0600 "${CONFIG_DIR}/aegis.toml"
chown_target_user "${CONFIG_DIR}/aegis.toml"

# Prepare browser credentials before starting the client. Never grant every app
# access or feed a Keychain login password through the installer.
if [[ "${PREPARE_BROWSER_PROXY}" == auto ]]; then
  PREPARE_BROWSER_PROXY=0
  if [[ "${EUID}" -ne 0 && "${INSTALL_USER}" == "$(id -un)" ]]; then
    PREPARE_BROWSER_PROXY=1
  fi
fi
if [[ "${PREPARE_BROWSER_PROXY}" -eq 1 ]]; then
  [[ "${EUID}" -ne 0 && "${INSTALL_USER}" == "$(id -un)" ]] || {
    echo "Browser proxy preparation requires the logged-in install user, without sudo." >&2
    exit 1
  }
  proxy_fields="$(awk '
    /^[[:space:]]*\[/ { inside = ($0 ~ /^[[:space:]]*\[socks\][[:space:]]*$/); next }
    inside && /^[[:space:]]*(listen|auth_user)[[:space:]]*=/ {
      key=$0; sub(/[[:space:]]*=.*$/, "", key); gsub(/[[:space:]]/, "", key)
      value=$0; sub(/^[^=]*=[[:space:]]*"/, "", value); sub(/".*$/, "", value)
      print key "=" value
    }
  ' "${CONFIG_DIR}/aegis.toml")"
  proxy_listen="$(printf '%s\n' "$proxy_fields" | sed -n 's/^listen=//p')"
  proxy_user="$(printf '%s\n' "$proxy_fields" | sed -n 's/^auth_user=//p')"
  [[ -n "$proxy_user" ]] || proxy_user=aegis
  [[ "$proxy_listen" =~ ^127\.0\.0\.1:([0-9]+)$ ]] || {
    echo "Browser proxy preparation requires an explicit IPv4 loopback SOCKS port." >&2
    exit 1
  }
  printf '%s\n' "${SOCKS_TOKEN}" | "${SCRIPT_DIR}/bin/aegis-proxy-keychain" "${BASH_REMATCH[1]}" "$proxy_user"
  echo "Browser credential ready. Enable SOCKS proxy for your network service using $proxy_listen / $proxy_user."
fi

AGENT_PLIST_TEMPLATE="${SCRIPT_DIR}/packaging/launchd/dev.aegis.client.plist"
DAEMON_PLIST_TEMPLATE="${SCRIPT_DIR}/packaging/launchd/dev.aegis.client.daemon.plist"
SERVICE_STATUS="FOREGROUND"
SERVICE_MESSAGE="Foreground/operator mode selected; no launchd service was started."
EFFECTIVE_SERVICE_MODE="${SERVICE_MODE}"

if [[ "${SERVICE_MODE}" == "auto" ]]; then
  if detect_gui_launchd_domain; then
    EFFECTIVE_SERVICE_MODE="launchagent"
  else
    EFFECTIVE_SERVICE_MODE="foreground"
    SERVICE_STATUS="PARTIAL"
    SERVICE_MESSAGE="No gui/$(target_uid 2>/dev/null || printf '?') launchd domain exists for ${INSTALL_USER}; LaunchAgent was not loaded."
  fi
fi

if [[ "${EFFECTIVE_SERVICE_MODE}" == "launchagent" ]]; then
  if [[ ! -f "${AGENT_PLIST_TEMPLATE}" ]]; then
    echo "[install-macos] WARNING: packaging/launchd/dev.aegis.client.plist missing" >&2
    SERVICE_STATUS="BLOCKED"
    SERVICE_MESSAGE="LaunchAgent template missing."
  elif ! detect_gui_launchd_domain; then
    SERVICE_STATUS="BLOCKED"
    SERVICE_MESSAGE="No gui/$(target_uid 2>/dev/null || printf '?') launchd domain exists for ${INSTALL_USER}; LaunchAgent not loaded."
    render_plist_template "${AGENT_PLIST_TEMPLATE}" "${PLIST_PATH}"
    chmod 0644 "${PLIST_PATH}"
    chown_target_user "${PLIST_PATH}"
  else
    render_plist_template "${AGENT_PLIST_TEMPLATE}" "${PLIST_PATH}"
    chmod 0644 "${PLIST_PATH}"
    chown_target_user "${PLIST_PATH}"
    launchctl bootout "gui/$(target_uid)" "${PLIST_PATH}" 2>/dev/null || true
    launchctl bootstrap "gui/$(target_uid)" "${PLIST_PATH}"
    if launchctl print "gui/$(target_uid)/dev.aegis.client" >/dev/null 2>&1; then
      SERVICE_STATUS="LIVE"
      SERVICE_MESSAGE="LaunchAgent loaded in gui/$(target_uid)."
      echo "[install-macos] LaunchAgent loaded: ${PLIST_PATH}"
    else
      SERVICE_STATUS="BLOCKED"
      SERVICE_MESSAGE="LaunchAgent bootstrap returned but launchctl print did not find gui/$(target_uid)/dev.aegis.client."
      echo "[install-macos] WARNING: ${SERVICE_MESSAGE}" >&2
    fi
  fi
elif [[ "${EFFECTIVE_SERVICE_MODE}" == "launchdaemon" ]]; then
  if [[ ${EUID} -ne 0 ]]; then
    SERVICE_STATUS="BLOCKED"
    SERVICE_MESSAGE="LaunchDaemon mode requires root. Rerun with sudo --service-mode launchdaemon --service-user ${INSTALL_USER} --user-home ${INSTALL_HOME}."
  elif [[ ! -f "${DAEMON_PLIST_TEMPLATE}" ]]; then
    SERVICE_STATUS="BLOCKED"
    SERVICE_MESSAGE="LaunchDaemon template missing."
  else
    render_plist_template "${DAEMON_PLIST_TEMPLATE}" "${DAEMON_PLIST_PATH}"
    chmod 0644 "${DAEMON_PLIST_PATH}"
    chown root:wheel "${DAEMON_PLIST_PATH}" 2>/dev/null || chown root:0 "${DAEMON_PLIST_PATH}"
    launchctl bootout system "${DAEMON_PLIST_PATH}" 2>/dev/null || true
    launchctl bootstrap system "${DAEMON_PLIST_PATH}"
    if launchctl print system/dev.aegis.client >/dev/null 2>&1; then
      SERVICE_STATUS="LIVE"
      SERVICE_MESSAGE="LaunchDaemon loaded in system domain as ${INSTALL_USER}."
      echo "[install-macos] LaunchDaemon loaded: ${DAEMON_PLIST_PATH}"
    else
      SERVICE_STATUS="BLOCKED"
      SERVICE_MESSAGE="LaunchDaemon bootstrap returned but launchctl print did not find system/dev.aegis.client."
      echo "[install-macos] WARNING: ${SERVICE_MESSAGE}" >&2
    fi
  fi
fi

if [[ "${SERVICE_STATUS}" == "PARTIAL" || "${SERVICE_STATUS}" == "BLOCKED" ]]; then
  cat >&2 <<SERVICE_EOF
[install-macos] service_status=${SERVICE_STATUS}
[install-macos] ${SERVICE_MESSAGE}
[install-macos] Options:
[install-macos]   - interactive desktop user: rerun from a logged-in session with --service-mode launchagent
[install-macos]   - headless/dedicated user: sudo ./install-macos-client.sh --service-mode launchdaemon --service-user ${INSTALL_USER} --user-home ${INSTALL_HOME} --bundle-url-file /absolute/root-private/client-access-url.txt
[install-macos]   - debug fallback: ${BIN_DEST} --config ${CONFIG_DIR}/aegis.toml --runtime-events-jsonl ${RUNTIME_EVENTS}
SERVICE_EOF
fi

if [[ "${SERVICE_STATUS}" == "BLOCKED" && "${SERVICE_MODE}" == "launchdaemon" ]]; then
  exit 2
fi

# Determine SOCKS listen address from final config (section-aware).
SOCKS_LISTEN="$(awk '
  /^[[:space:]]*\[/ {
    in_socks = ($0 ~ /^[[:space:]]*\[socks\][[:space:]]*$/)
    next
  }
  in_socks && /^[[:space:]]*listen[[:space:]]*=/ {
    value = $0
    sub(/^[^=]*=[[:space:]]*"/, "", value)
    sub(/".*$/, "", value)
    print value
    exit
  }
' "${CONFIG_DIR}/aegis.toml"
)"
[[ -z "${SOCKS_LISTEN}" ]] && SOCKS_LISTEN="127.0.0.1:<dynamic>"

cat <<USAGE_EOF

✅ AEGIS macOS client installed.

  Binary:        ${BIN_DEST}
  Config:        ${CONFIG_DIR}/aegis.toml (0600)
  CA cert:       ${CA_PATH} (0600)
  Service mode:  ${EFFECTIVE_SERVICE_MODE}
  Service state: ${SERVICE_STATUS}
  LaunchAgent:   ${PLIST_PATH}
  LaunchDaemon:  ${DAEMON_PLIST_PATH}
  Runtime log:   ${RUNTIME_EVENTS}

  SOCKS5 proxy:  ${SOCKS_LISTEN}
  Local credentials are stored in the private config above.
  For Safari, prepare browser credentials as the logged-in install user
  and enable this SOCKS proxy in your network service settings.

  Manage LaunchAgent:
    launchctl list | grep dev.aegis.client
    launchctl bootout gui/\$(id -u ${INSTALL_USER}) ${PLIST_PATH}
    launchctl bootstrap gui/\$(id -u ${INSTALL_USER}) ${PLIST_PATH}

  Manage LaunchDaemon:
    sudo launchctl print system/dev.aegis.client
    sudo launchctl bootout system ${DAEMON_PLIST_PATH}
    sudo launchctl bootstrap system ${DAEMON_PLIST_PATH}

════════════════════════════════════════════════════════════════════════
USAGE_EOF
EOF
chmod 0755 "${BUNDLE_DIR}/install-macos-client.sh"

# Bind the exact copied source texts into the installer before its manifest hash
# is emitted. Only closed uppercase placeholder names and hexadecimal hashes.
project_mit_sha="$(shasum -a 256 "${BUNDLE_DIR}/LICENSE-MIT" | awk '{print $1}')"
project_apache_sha="$(shasum -a 256 "${BUNDLE_DIR}/LICENSE-APACHE" | awk '{print $1}')"
project_notice_sha="$(shasum -a 256 "${BUNDLE_DIR}/NOTICE" | awk '{print $1}')"
for project_digest in "$project_mit_sha" "$project_apache_sha" "$project_notice_sha"; do
  [[ "$project_digest" =~ ^[0-9a-f]{64}$ ]] || exit 1
done
sed -e "s/__AEGIS_PROJECT_LICENSE_MIT_SHA256__/${project_mit_sha}/g" \
  -e "s/__AEGIS_PROJECT_LICENSE_APACHE_SHA256__/${project_apache_sha}/g" \
  -e "s/__AEGIS_PROJECT_NOTICE_SHA256__/${project_notice_sha}/g" \
  "${BUNDLE_DIR}/install-macos-client.sh" > "${BUNDLE_DIR}/install-macos-client.sh.rendered"
mv "${BUNDLE_DIR}/install-macos-client.sh.rendered" "${BUNDLE_DIR}/install-macos-client.sh"
chmod 0755 "${BUNDLE_DIR}/install-macos-client.sh"

# v0.3.2: ship the LaunchAgent plist template inside the macOS tarball
# so install-macos-client.sh can render it at install time.
mkdir -p "${BUNDLE_DIR}/packaging/launchd"
cp "${ROOT}/packaging/launchd/dev.aegis.client.plist" "${BUNDLE_DIR}/packaging/launchd/dev.aegis.client.plist"
cp "${ROOT}/packaging/launchd/dev.aegis.client.daemon.plist" "${BUNDLE_DIR}/packaging/launchd/dev.aegis.client.daemon.plist"

"${CARGO_BIN}" run --locked -q -p aegis-measure -- build-macos-client-tarball-manifest \
  --bundle-dir "${BUNDLE_DIR}" \
  --version "${VERSION}" \
  --arch "${ARCH}" \
  --target-triple "${TARGET_TRIPLE}" \
  --git-sha "${GIT_SHA}" \
  --build-timestamp "${BUILD_TIMESTAMP}"

# Produce the final tarball + sha256.
tar -czf "${ARCHIVE_PATH}" -C "${OUTPUT_DIR}" "${BUNDLE_NAME}"
"${CARGO_BIN}" run --locked -q -p aegis-measure -- write-archive-sha256 \
  --archive "${ARCHIVE_PATH}" \
  --sha256-path "${SHA256_PATH}"

cat <<EOF
macOS client tarball built
--------------------------
Bundle dir:   ${BUNDLE_DIR}
Archive:      ${ARCHIVE_PATH}
SHA256 file:  ${SHA256_PATH}
Target:       ${TARGET_TRIPLE}
Version:      ${VERSION}
EOF
