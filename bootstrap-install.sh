#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
AEGIS bootstrap installer
=========================

Usage:
  ./bootstrap-install.sh server [bootstrap-options] [install-options]
  ./bootstrap-install.sh client [bootstrap-options] [install-options]

Bootstrap options:
  --manifest-url <url>    External release manifest URL
  --source <url>          Ordered manifest source; repeat for mirrors (replaces GitHub default)
  --offline               Use local file:// sources and installed prerequisites only
  --download-only         Verify and retain the public release without installing
  --download-dir <path>   Reuse this directory for downloaded release assets
  --keep-downloads        Do not remove auto-created temporary downloads
  --require-release-policy  Refuse legacy manifests without signed expiry metadata
  --allow-historical-policy  Permit a policy-less archive only with both independent pins
  --historical-manifest-sha256 <hex>  Independently trusted historical manifest digest
  --historical-signature-sha256 <hex>  Independently trusted historical signature digest
  --minimum-release-sequence <n>  Independently supplied release floor (requires authority)
  --release-authority <id>  Trusted workflow authority for the sequence floor
  --recover-interrupted-release <inspect|confirm-installed|discard-failed>
                           Inspect or explicitly resolve an interrupted install journal

Examples:
  ./bootstrap-install.sh server --manifest-url file:///tmp/release.manifest.json
  ./bootstrap-install.sh client --bundle-url-file /absolute/owner-private/client-access-url.txt

All unknown options are forwarded to the bundled install.sh role installer.
EOF
}

if [[ $# -lt 1 ]]; then
  usage >&2
  exit 1
fi

ROLE="$1"
shift

case "${ROLE}" in
  server|client) ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    echo "Role must be either 'server' or 'client'" >&2
    usage >&2
    exit 1
    ;;
esac

# Resolve the release manifest by host arch. aarch64 (Raspberry Pi 4/5, ARM VPS)
# ships as a SEPARATE signed manifest (release.manifest-aarch64.json); x86_64 uses
# release.manifest.json. No cross-arch fallback: falling back to the x86_64 manifest
# on an ARM host would install a binary that can't run. If a release has no arm64
# manifest, the ARM install fails cleanly rather than installing the wrong arch.
AEGIS_HOST_ARCH="${AEGIS_BOOTSTRAP_ARCH_OVERRIDE:-$(uname -m 2>/dev/null || echo x86_64)}"
case "${AEGIS_HOST_ARCH}" in
  aarch64|arm64) AEGIS_MANIFEST_NAME="release.manifest-aarch64.json" ;;
  *) AEGIS_MANIFEST_NAME="release.manifest.json" ;;
esac

# Operators deliberately use one architecture-neutral install command. When
# that command names the canonical HTTP(S) x86 manifest, select the canonical
# ARM sibling on an ARM host. Keep custom filenames and file:// fixtures intact:
# they may already serve an architecture-specific manifest under another name.
manifest_url_for_host_arch() {
  local url="$1"
  if [[ "${AEGIS_MANIFEST_NAME}" == "release.manifest-aarch64.json" ]]; then
    case "${url}" in
      http://*/client-release.manifest.json|https://*/client-release.manifest.json)
        printf '%s\n' "${url%client-release.manifest.json}client-release.manifest-aarch64.json"
        return 0
        ;;
      http://*/release.manifest.json|https://*/release.manifest.json)
        printf '%s\n' "${url%release.manifest.json}${AEGIS_MANIFEST_NAME}"
        return 0
        ;;
    esac
  fi
  printf '%s\n' "${url}"
}

DEFAULT_MANIFEST_NAME="${AEGIS_MANIFEST_NAME}"
[[ "${ROLE}" == "client" ]] && DEFAULT_MANIFEST_NAME="client-${AEGIS_MANIFEST_NAME}"
MANIFEST_URL="$(manifest_url_for_host_arch "${AEGIS_INSTALL_MANIFEST_URL:-https://github.com/propafinder/aegis-release/releases/latest/download/${DEFAULT_MANIFEST_NAME}}")"
# Phase 5.0.D: bootstrap manifest fallback. Operators (or users running
# from regions where the primary manifest host is blocked) may supply a
# comma-separated list of mirror manifest URLs via AEGIS_INSTALL_MIRRORS.
# Each entry must be a full manifest URL (not a release base); the
# bootstrap tries each in order and records the one that succeeded into
# AEGIS_INSTALL_SOURCE_MANIFEST_URL so the inner install.sh sees the
# real source. Empty/unset → primary only (legacy single-URL behavior).
MANIFEST_URL_MIRRORS_RAW="${AEGIS_INSTALL_MIRRORS:-}"
# Tracks the URL that actually delivered the manifest. Updated by
# download_url_with_fallback after the first successful attempt.
MANIFEST_URL_RESOLVED_BY_FALLBACK=""
DOWNLOAD_DIR=""
EXPLICIT_SOURCES=()
OFFLINE=0
DOWNLOAD_ONLY=0

# --- Release manifest signature anchor (Phase 1 critical hardening) ---
# A mirror is untrusted transport. Checksums inside the manifest are only
# as trustworthy as the manifest itself, and on the mirror-fallback path
# the manifest no longer benefits from GitHub TLS authentication. We
# therefore require a detached ed25519 signature over release.manifest.json,
# verified against this PINNED public key before ANY manifest field
# (including checksums) is trusted. The signing private key is operator-held
# and never ships in the repo. Operators may override the pinned key for
# their own signing identity via AEGIS_INSTALL_MANIFEST_PUBKEY (path to a
# PEM). Unsigned manifests are always refused: an unverified manifest cannot
# establish or bypass the persisted release policy.
AEGIS_MANIFEST_PUBKEY_PEM="${AEGIS_INSTALL_MANIFEST_PUBKEY:-}"
AEGIS_MANIFEST_PINNED_PUBKEY="-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA6T0PK4ao6847zmnihkPAI3sRIvhuBTfw4GDX04rZ4m0=
-----END PUBLIC KEY-----"
AEGIS_ALLOW_UNSIGNED_MANIFEST="${AEGIS_INSTALL_ALLOW_UNSIGNED:-0}"
REQUIRE_RELEASE_POLICY=1
ALLOW_HISTORICAL_POLICY=0
HISTORICAL_MANIFEST_SHA256=""
HISTORICAL_SIGNATURE_SHA256=""
RECOVER_INTERRUPTED_RELEASE=""
MINIMUM_RELEASE_SEQUENCE=0
RELEASE_POLICY_AUTHORITY=""

# Verify a detached ed25519 signature over the manifest using the pinned
# (or operator-overridden) public key. Returns 0 on success, non-zero on
# any failure. Never trusts manifest contents before this passes.
verify_manifest_signature() {
  local manifest_path="$1"
  local sig_path="$2"
  local pubkey_file
  # The manifest already lives in protected staging. Never reopen the trust
  # anchor through an unrelated TMPDIR that may belong to the service UID.
  pubkey_file="$(mktemp "${manifest_path}.pub.XXXXXXXX")" || return 1
  if [[ -n "${AEGIS_MANIFEST_PUBKEY_PEM}" ]]; then
    if ! python3 -I - "${AEGIS_MANIFEST_PUBKEY_PEM}" "${pubkey_file}" <<'PY_OPERATOR_ANCHOR'
import os, stat, sys
path = os.path.abspath(sys.argv[1])
if sys.platform == "darwin":
    for prefix in ("/var/", "/tmp/", "/etc/"):
        if path == prefix[:-1] or path.startswith(prefix):
            path = "/private" + path
            break
parts = [p for p in path.split("/") if p]
admin = os.geteuid()
parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    if not parts or ".." in parts: raise ValueError("invalid anchor path")
    for part in parts[:-1]:
        child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        os.close(parent); parent = child
        st = os.fstat(parent)
        if st.st_uid not in (0, admin) or (st.st_mode & 0o022 and not (st.st_uid == 0 and st.st_mode & stat.S_ISVTX)):
            raise ValueError("untrusted anchor ancestor")
    source = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    with os.fdopen(source, "rb") as stream:
        st = os.fstat(stream.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid not in (0, admin) or st.st_mode & 0o022 or st.st_size > 16384:
            raise ValueError("untrusted or oversized anchor file")
        data = stream.read(16385)
        if not data or len(data) > 16384: raise ValueError("invalid anchor size")
    output = os.open(sys.argv[2], os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
    with os.fdopen(output, "wb") as stream: stream.write(data)
except (OSError, ValueError):
    print("bootstrap-install: operator manifest key must be a bounded administrator-owned regular file in trusted directories", file=sys.stderr)
    raise SystemExit(1)
finally:
    os.close(parent)
PY_OPERATOR_ANCHOR
    then
      rm -f -- "${pubkey_file}"
      return 1
    fi
  else
    printf '%s\n' "${AEGIS_MANIFEST_PINNED_PUBKEY}" > "${pubkey_file}"
  fi
  local rc=0
  if ! openssl pkeyutl -verify -pubin -inkey "${pubkey_file}" \
        -rawin -in "${manifest_path}" -sigfile "${sig_path}" >/dev/null 2>&1; then
    rc=1
  fi
  rm -f "${pubkey_file}"
  return ${rc}
}
# Signature verification precedes both policy validation and persistent floor
# inspection. A mirror can transport authorized bytes but cannot relax policy.
validate_release_policy() {
  python3 -I - "$1" "${MINIMUM_RELEASE_SEQUENCE:-0}" "${RELEASE_POLICY_AUTHORITY:-}" "${REQUIRE_RELEASE_POLICY:-1}" \
    "${ALLOW_HISTORICAL_POLICY:-0}" "${HISTORICAL_MANIFEST_SHA256:-}" "${HISTORICAL_SIGNATURE_SHA256:-}" <<'PY_POLICY'
import hashlib, json, re, sys, time
from pathlib import Path
path = Path(sys.argv[1])
if path.stat().st_size > 65536:
    raise SystemExit("release policy: manifest exceeds 64 KiB")
minimum, authority, required, historical, manifest_pin, signature_pin = sys.argv[2:]
if not re.fullmatch(r"0|[1-9][0-9]*", minimum) or len(minimum) > 16:
    raise SystemExit("release policy: invalid independent sequence floor")
minimum = int(minimum)
if minimum and not authority:
    raise SystemExit("release policy: a sequence floor requires an independent authority")
raw = path.read_bytes()
digest = hashlib.sha256(raw).hexdigest()
m = json.loads(raw)
p = m.get("release_policy")
if p is None:
    if required == "1" or historical != "1" or minimum or authority:
        raise SystemExit("release policy: signed freshness metadata required")
    if not all(re.fullmatch(r"[0-9a-f]{64}", value) for value in (manifest_pin, signature_pin)):
        raise SystemExit("release policy: historical mode requires independent manifest and signature SHA-256 pins")
    signature = Path(str(path) + ".sig").read_bytes()
    if digest != manifest_pin or hashlib.sha256(signature).hexdigest() != signature_pin:
        raise SystemExit("release policy: historical independent pin mismatch")
    print("bootstrap-install: explicitly pinned historical metadata; existing release floors still apply", file=sys.stderr)
    print(digest)
    raise SystemExit(0)
keys = {"schema", "authority", "sequence", "tag", "issued_at_unix", "expires_at_unix"}
if not isinstance(p, dict) or set(p) != keys or p["schema"] != "aegis_release_policy_v1":
    raise SystemExit("release policy: unsupported signed policy")
if not isinstance(p["authority"], str) or not re.fullmatch(r"github:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+:\.github/workflows/release\.yml", p["authority"]):
    raise SystemExit("release policy: invalid signed authority")
if authority and p["authority"] != authority:
    raise SystemExit("release policy: independent authority mismatch")
sequence, issued, expires = (p[key] for key in ("sequence", "issued_at_unix", "expires_at_unix"))
if any(type(value) is not int for value in (sequence, issued, expires)) or not 0 < sequence < 2**53:
    raise SystemExit("release policy: invalid sequence or timestamps")
if sequence < minimum:
    raise SystemExit("release policy: below the independently trusted release floor")
now = int(time.time())
if not 0 < issued < expires or expires - issued > 30 * 86400 or issued > now + 300 or now >= expires:
    raise SystemExit("release policy: expired, future-dated or excessive validity")
number = r"(?:0|[1-9][0-9]*)"
tag = re.fullmatch(rf"v(?P<version>{number}\.{number}\.{number})(?:-(?P<channel>rc|nightly)\.{number})?", p["tag"] if isinstance(p["tag"], str) else "")
if not tag or tag["version"] != m.get("version") or (tag["channel"] or "stable") != m.get("channel") or m.get("prerelease") is not bool(tag["channel"]):
    raise SystemExit("release policy: tag and manifest identity mismatch")
print("bootstrap-install: signed release freshness policy verified", file=sys.stderr)
print(digest)
PY_POLICY
}

# The same trusted bootstrap code supervises the complete installation
# transaction for system/root and per-user installs. No candidate executable is
# loaded before the final floor check under flock. A crash releases the lock;
# its separate journal records the unresolved installation, never a stale PID.
release_floor_run() {
  local action="$1" manifest="$2" digest="$3"
  shift 3
  local state_root scope arch
  if [[ "${EUID}" -eq 0 ]]; then
    if [[ "${OS_KIND:-linux}" == macos ]]; then
      state_root="/Library/Application Support/Aegis/Install/releases"
    else
      state_root="/var/lib/aegis-install/releases"
    fi
  else
    state_root="${HOME}/.local/state/aegis-install/releases"
  fi
  arch="${AEGIS_HOST_ARCH:-$(uname -m)}"
  case "${arch}" in arm64) arch=aarch64 ;; amd64) arch=x86_64 ;; esac
  scope="${ROLE:-client}-${OS_KIND:-linux}-${arch}"
  python3 -I - "${action}" "${state_root}" "${scope}" "${manifest}" "${digest}" "$@" 3<&0 <<'PY_RELEASE_FLOOR'
import fcntl, hashlib, json, os, re, secrets, signal, stat, subprocess, sys, time
from pathlib import Path

action, root, scope, manifest, digest, *command = sys.argv[1:]
admin = os.geteuid()
if action not in ("check", "install", "inspect", "confirm-installed", "discard-failed"):
    raise SystemExit("release floor: unsupported operation")
if not re.fullmatch(r"(?:client|server)-(?:linux|macos)-(?:x86_64|aarch64)", scope):
    raise SystemExit("release floor: unsupported installation scope")
if sys.platform == "darwin":
    for prefix in ("/var/", "/tmp/", "/etc/"):
        if root.startswith(prefix):
            root = "/private" + root
            break
if not os.path.isabs(root) or ".." in root.split("/"):
    raise SystemExit("release floor: absolute administrator state path required")
parts = [part for part in root.split("/") if part]
directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
lock = None
child = None
interrupted = 0
name, pending_name = scope + ".json", scope + ".pending.json"

def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate release metadata field")
        value[key] = item
    return value

def validate_record(value):
    if not isinstance(value, dict) or set(value) != {"schema", "scope", "authority", "sequence", "manifest_sha256"}:
        raise ValueError("unsupported release floor record")
    if value["schema"] != "aegis_release_floor_v1" or value["scope"] != scope:
        raise ValueError("release floor scope mismatch")
    if not isinstance(value["authority"], str) or not re.fullmatch(r"github:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+:\.github/workflows/release\.yml", value["authority"]):
        raise ValueError("invalid release floor authority")
    if type(value["sequence"]) is not int or not 0 < value["sequence"] < 2**53:
        raise ValueError("invalid release floor sequence")
    if not isinstance(value["manifest_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["manifest_sha256"]):
        raise ValueError("invalid release floor digest")
    return value

def checked_file(fd):
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != admin or st.st_mode & 0o077 or st.st_nlink != 1:
        raise ValueError("release metadata must be administrator-owned private regular files")
    return st

def read_record(leaf):
    try:
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        checked_file(stream.fileno())
        data = stream.read(65537)
    if len(data) > 65536:
        raise ValueError("release metadata exceeds 64 KiB")
    return validate_record(json.loads(data, object_pairs_hook=unique))

def advance_allowed(candidate, floor):
    if floor is None:
        return
    if candidate is None:
        raise ValueError("historical metadata cannot bypass an existing release floor")
    if candidate["authority"] != floor["authority"]:
        raise ValueError("release authority change requires independent operator recovery")
    if candidate["sequence"] < floor["sequence"]:
        raise ValueError("release sequence is below the installed floor")
    if candidate["sequence"] == floor["sequence"] and candidate["manifest_sha256"] != floor["manifest_sha256"]:
        raise ValueError("same release sequence has different manifest bytes")

def write_record(leaf, value):
    temporary = ".release-" + secrets.token_hex(16)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write((json.dumps(value, sort_keys=True) + "\n").encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, leaf, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try: os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError: pass

def clear_pending():
    os.unlink(pending_name, dir_fd=directory)
    os.fsync(directory)

try:
    for index, part in enumerate(parts):
        try:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
        except FileNotFoundError:
            if action in ("check", "inspect"):
                if action == "inspect": print('{"status":"no_release_floor"}')
                raise SystemExit(0)
            os.mkdir(part, 0o700, dir_fd=directory)
            os.fsync(directory)
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
        st = os.fstat(following)
        sticky_ancestor = index < len(parts) - 1 and st.st_uid == 0 and st.st_mode & stat.S_ISVTX
        if st.st_uid not in (0, admin) or (st.st_mode & 0o022 and not sticky_ancestor):
            os.close(following)
            raise ValueError("untrusted release metadata ancestor")
        if index == len(parts) - 1 and st.st_uid != admin:
            os.close(following)
            raise ValueError("release metadata directory has another owner")
        os.close(directory)
        directory = following

    if action != "check":
        lock = os.open(scope + ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
        checked_file(lock)
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise ValueError("another installation transaction is active")
    floor, pending = read_record(name), read_record(pending_name)
    if action == "inspect":
        print(json.dumps({"scope": scope, "floor": floor, "pending": pending}, sort_keys=True))
        raise SystemExit(0)
    if action in ("confirm-installed", "discard-failed"):
        if pending is None:
            raise ValueError("no interrupted installation journal to recover")
        advance_allowed(pending, floor)
        if action == "confirm-installed":
            write_record(name, pending)
        clear_pending()
        print("release floor: explicit interrupted-install recovery completed", file=sys.stderr)
        raise SystemExit(0)
    if pending is not None and pending != floor:
        raise ValueError("interrupted installation requires --recover-interrupted-release inspect, then explicit operator recovery")
    if pending is not None and action == "install":
        # Floor commit reached disk before the previous process died. The
        # byte-identical journal is redundant, not an unresolved install.
        clear_pending()

    raw = Path(manifest).read_bytes()
    if len(raw) > 65536 or not re.fullmatch(r"[0-9a-f]{64}", digest) or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("verified manifest bytes changed before floor check")
    metadata = json.loads(raw, object_pairs_hook=unique)
    policy = metadata.get("release_policy")
    if policy is not None:
        now = int(time.time())
        issued, expires = policy["issued_at_unix"], policy["expires_at_unix"]
        if type(issued) is not int or type(expires) is not int or not 0 < issued < expires or expires - issued > 30 * 86400 or issued > now + 300 or now >= expires:
            raise ValueError("release policy is no longer valid before installation")
    candidate = None if policy is None else validate_record({"schema": "aegis_release_floor_v1", "scope": scope,
        "authority": policy["authority"], "sequence": policy["sequence"], "manifest_sha256": digest})
    advance_allowed(candidate, floor)
    if action == "check":
        raise SystemExit(0)
    if not command:
        raise ValueError("installation command missing")
    if candidate is not None:
        write_record(pending_name, candidate)

    def forward_signal(signum, frame):
        global interrupted
        interrupted = signum
        if child is not None and child.poll() is None:
            try: os.killpg(child.pid, signum)
            except ProcessLookupError: pass
        else:
            raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, forward_signal)
    signal.signal(signal.SIGINT, forward_signal)
    try:
        # Descendants retain the flock until they finish even if this
        # supervisor is killed. The journal covers a crash before floor commit.
        child = subprocess.Popen(command, stdin=3, start_new_session=True, pass_fds=(lock,))
        result = child.wait()
    except BaseException:
        if child is not None and child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
            child.wait()
        # Keep the pending journal on an uncertain/interrupted outcome.
        raise
    if interrupted or result < 0:
        raise SystemExit(128 + (interrupted or -result))
    if result != 0:
        # A nonzero installer result does not prove that earlier binary,
        # configuration or service writes were rolled back. Retain the journal
        # until the operator verifies the outcome and explicitly recovers it.
        raise SystemExit(result if result > 0 else 128 - result)
    if candidate is not None:
        write_record(name, candidate)
        clear_pending()
    print("release floor: installation completed and protected state committed", file=sys.stderr)
except (OSError, ValueError, KeyError, TypeError) as error:
    print("release floor: " + str(error), file=sys.stderr)
    raise SystemExit(1)
finally:
    if lock is not None: os.close(lock)
    os.close(directory)
PY_RELEASE_FLOOR
}

KEEP_DOWNLOADS=0
AUTO_DOWNLOAD_DIR=0
FORWARDED_ARGS=()
APT_GET_BIN="${AEGIS_BOOTSTRAP_APT_GET_BIN:-apt-get}"
DNF_BIN="${AEGIS_BOOTSTRAP_DNF_BIN:-dnf}"
SUDO_BIN="${AEGIS_BOOTSTRAP_SUDO_BIN:-sudo}"
PREREQ_SIMULATE_MISSING_COMMANDS="${AEGIS_BOOTSTRAP_SIMULATE_MISSING_COMMANDS:-}"
HOST_FAMILY_OVERRIDE="${AEGIS_BOOTSTRAP_HOST_FAMILY_OVERRIDE:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest-url)
      MANIFEST_URL="$(manifest_url_for_host_arch "$2")"
      shift 2
      ;;
    --source)
      EXPLICIT_SOURCES+=("$(manifest_url_for_host_arch "$2")")
      shift 2
      ;;
    --require-release-policy)
      REQUIRE_RELEASE_POLICY=1
      ALLOW_HISTORICAL_POLICY=0
      shift
      ;;
    --allow-historical-policy)
      ALLOW_HISTORICAL_POLICY=1
      REQUIRE_RELEASE_POLICY=0
      shift
      ;;
    --historical-manifest-sha256)
      HISTORICAL_MANIFEST_SHA256="$2"
      shift 2
      ;;
    --historical-signature-sha256)
      HISTORICAL_SIGNATURE_SHA256="$2"
      shift 2
      ;;
    --recover-interrupted-release)
      RECOVER_INTERRUPTED_RELEASE="$2"
      shift 2
      ;;
    --minimum-release-sequence)
      MINIMUM_RELEASE_SEQUENCE="$2"
      shift 2
      ;;
    --release-authority)
      RELEASE_POLICY_AUTHORITY="$2"
      shift 2
      ;;
    --offline)
      OFFLINE=1
      shift
      ;;
    --download-only)
      DOWNLOAD_ONLY=1
      KEEP_DOWNLOADS=1
      shift
      ;;
    --download-dir)
      DOWNLOAD_DIR="$2"
      shift 2
      ;;
    --keep-downloads)
      KEEP_DOWNLOADS=1
      shift
      ;;
    --bundle-url|--bundle-url=*|--auth-token|--auth-token=*)
      echo "Inline installer secrets are refused; use --bundle-url-file or --auth-token-file." >&2
      exit 2
      ;;
    --bundle-url-file|--auth-token-file)
      [[ $# -ge 2 ]] || exit 2
      FORWARDED_ARGS+=("$1" "$2")
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      FORWARDED_ARGS+=("$1")
      shift
      ;;
  esac
done

cleanup() {
  if [[ "${AUTO_DOWNLOAD_DIR}" -eq 1 && "${KEEP_DOWNLOADS}" -eq 0 && -n "${DOWNLOAD_DIR}" && -d "${DOWNLOAD_DIR}" ]]; then
    rm -rf "${DOWNLOAD_DIR}"
  fi
}

trap cleanup EXIT

bootstrap_temp_candidates() {
  if [[ -n "${AEGIS_BOOTSTRAP_TMPDIR_CANDIDATES:-}" ]]; then
    printf '%s\n' "${AEGIS_BOOTSTRAP_TMPDIR_CANDIDATES}" | tr ':' '\n'
    return 0
  fi

  printf '%s\n' \
    "${TMPDIR:-/tmp}" \
    "/tmp" \
    "${HOME:-.}/.cache/aegis/tmp" \
    "${HOME:-.}/.local/state/aegis/tmp"
}

# A signature authenticates bytes, not a service-owned staging pathname. Keep
# the verified manifest, archive and extracted installer in administrator-only
# directories for their complete lifetime, including explicit --download-dir.
prepare_bootstrap_directory() {
  python3 -I - "$1" "${2:-private}" <<'PY_BOOTSTRAP_DIRECTORY'
import os, stat, sys
path, mode = sys.argv[1:]
path = os.path.abspath(path)
if sys.platform == "darwin":
    for prefix in ("/var/", "/tmp/", "/etc/"):
        if path == prefix[:-1] or path.startswith(prefix):
            path = "/private" + path
            break
if mode not in ("private", "parent") or ".." in path.split("/"):
    raise SystemExit("bootstrap staging: invalid directory")
parts = [part for part in path.split("/") if part]
if not parts:
    raise SystemExit("bootstrap staging: root is not a download directory")
admin = os.geteuid()
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
directory = os.open("/", flags)
try:
    for index, part in enumerate(parts):
        try:
            following = os.open(part, flags, dir_fd=directory)
        except FileNotFoundError:
            if mode == "parent": raise
            os.mkdir(part, 0o700, dir_fd=directory)
            following = os.open(part, flags, dir_fd=directory)
        st = os.fstat(following)
        sticky = st.st_uid == 0 and st.st_mode & stat.S_ISVTX and (mode == "parent" or index < len(parts) - 1)
        if st.st_uid not in (0, admin) or (st.st_mode & 0o022 and not sticky):
            os.close(following)
            raise ValueError("untrusted staging ancestor")
        os.close(directory);directory = following
    if mode == "private":
        if os.fstat(directory).st_uid != admin:
            raise ValueError("download directory belongs to another administrator")
        budget = [0]
        def check_tree(fd, depth=0):
            if depth > 12: raise ValueError("staging tree too deep")
            for name in os.listdir(fd):
                budget[0] += 1
                if budget[0] > 10000: raise ValueError("staging tree too large")
                st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if st.st_uid != admin or st.st_mode & 0o022:
                    raise ValueError("untrusted existing staging entry")
                if stat.S_ISDIR(st.st_mode):
                    child = os.open(name, flags, dir_fd=fd)
                    try: check_tree(child, depth + 1)
                    finally: os.close(child)
                elif not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                    raise ValueError("existing staging links/special files are not accepted")
        check_tree(directory)
        os.fchmod(directory, 0o700)
    print(path)
except (OSError, ValueError) as error:
    print("bootstrap staging: " + str(error), file=sys.stderr)
    raise SystemExit(1)
finally:
    os.close(directory)
PY_BOOTSTRAP_DIRECTORY
}

make_bootstrap_temp_dir() {
  local prefix="$1"
  local candidate=""

  while IFS= read -r candidate; do
    [[ -n "${candidate}" ]] || continue
    candidate="$(prepare_bootstrap_directory "${candidate}" parent 2>/dev/null)" || continue
    if [[ -d "${candidate}" && -w "${candidate}" && -x "${candidate}" ]]; then
      mktemp -d "${candidate%/}/${prefix}.XXXXXX"
      return 0
    fi
  done < <(bootstrap_temp_candidates)

  echo "No writable temp directory found; set TMPDIR or AEGIS_BOOTSTRAP_TMPDIR_CANDIDATES" >&2
  return 1
}

has_command() {
  command -v "${1}" >/dev/null 2>&1
}

prereq_has_command() {
  local name="$1"

  case ",${PREREQ_SIMULATE_MISSING_COMMANDS}," in
    *",${name},"*)
      return 1
      ;;
  esac

  has_command "${name}"
}

run_as_root() {
  if [[ ${EUID} -eq 0 ]]; then
    "$@"
    return 0
  fi
  if has_command "${SUDO_BIN}"; then
    "${SUDO_BIN}" "$@"
    return 0
  fi

  echo "Need root or sudo to auto-install missing OS prerequisites" >&2
  exit 1
}

append_unique_word() {
  local current="$1"
  local value="$2"

  case " ${current} " in
    *" ${value} "*)
      printf '%s\n' "${current}"
      ;;
    *)
      if [[ -n "${current}" ]]; then
        printf '%s %s\n' "${current}" "${value}"
      else
        printf '%s\n' "${value}"
      fi
      ;;
  esac
}

has_ca_certificates() {
  [[ -r /etc/ssl/certs/ca-certificates.crt || -r /etc/pki/tls/certs/ca-bundle.crt || -d /etc/ssl/certs ]]
}

automatic_client_requested() {
  local selected_profile="${AEGIS_INSTALL_PROFILE:-${AEGIS_INSTALL_MODE:-}}"
  local argument previous_argument=""
  for argument in "${FORWARDED_ARGS[@]:-}"; do
    case "${previous_argument}" in
      --profile|--mode|--operator-mode) selected_profile="${argument}" ;;
    esac
    previous_argument="${argument}"
  done
  [[ "${ROLE}" == "client" && ( -z "${selected_profile}" || "${selected_profile}" == "auto" ) ]]
}

bootstrap_prereq_packages() {
  local packages="" family="${1:-debian_like}"
  local ip_package=iproute2 iptables_package=iptables getent_package=libc-bin
  if [[ "$family" == rhel_like ]]; then
    ip_package=iproute; iptables_package=iptables-nft; getent_package=glibc-common
  fi

  if ! has_ca_certificates; then
    packages="$(append_unique_word "${packages}" "ca-certificates")"
  fi
  if ! prereq_has_command tar; then
    packages="$(append_unique_word "${packages}" "tar")"
  fi
  if ! prereq_has_command python3; then
    packages="$(append_unique_word "${packages}" "python3")"
  fi
  if ! prereq_has_command curl && ! prereq_has_command wget; then
    packages="$(append_unique_word "${packages}" "curl")"
  fi
  # Both roles verify Ed25519 release signatures before trusting the manifest.
  if ! prereq_has_command openssl; then
    packages="$(append_unique_word "${packages}" "openssl")"
  fi

  # Host orchestration only: Rust decides which profile these capabilities can
  # support. Install missing command packages for the ordinary Linux client.
  if [[ "${DOWNLOAD_ONLY:-0}" != "1" ]] && automatic_client_requested; then
    prereq_has_command ip || packages="$(append_unique_word "${packages}" "${ip_package}")"
    if ! prereq_has_command iptables || ! prereq_has_command ip6tables; then
      packages="$(append_unique_word "${packages}" "${iptables_package}")"
    fi
    prereq_has_command nft || packages="$(append_unique_word "${packages}" "nftables")"
    prereq_has_command flock || packages="$(append_unique_word "${packages}" "util-linux")"
    prereq_has_command curl || packages="$(append_unique_word "${packages}" "curl")"
    prereq_has_command getent || packages="$(append_unique_word "${packages}" "${getent_package}")"
    prereq_has_command timeout || packages="$(append_unique_word "${packages}" "coreutils")"
  fi

  printf '%s\n' "${packages}"
}

install_debian_like_prereqs() {
  local packages="$1"

  if [[ -z "${packages}" ]]; then
    return 0
  fi
  if ! has_command "${APT_GET_BIN}"; then
    echo "debian_like host detected but ${APT_GET_BIN} is unavailable; install ${packages} manually" >&2
    exit 1
  fi

  echo "Installing Ubuntu prerequisites via apt-get: ${packages}" >&2
  run_as_root "${APT_GET_BIN}" update
  # Keep package-manager automation in bootstrap because this is the product entrypoint.
  run_as_root "${APT_GET_BIN}" install -y ${packages}
}

install_rhel_like_prereqs() {
  local packages="$1"
  [[ -n "$packages" ]] || return 0
  if ! has_command "$DNF_BIN"; then
    echo "rhel_like host detected but $DNF_BIN is unavailable; install $packages manually" >&2
    exit 1
  fi
  echo "Installing RHEL-family prerequisites via dnf: $packages" >&2
  run_as_root "$DNF_BIN" --setopt=gpgcheck=1 '--setopt=*.gpgcheck=1' --setopt=localpkg_gpgcheck=1 install -y ${packages}
}

ensure_bootstrap_prereqs() {
  local host_family="$1"
  local packages=""

  packages="$(bootstrap_prereq_packages "${host_family}")"

  if [[ ( "${OFFLINE:-0}" == "1" || "${DOWNLOAD_ONLY:-0}" == "1" ) && -n "${packages}" ]]; then
    echo "Offline installation needs these installed OS packages: ${packages}" >&2
    echo "Prepare them from a trusted distribution repository before retrying; no network request was made." >&2
    exit 1
  fi

  case "${host_family}" in
    debian_like)
      install_debian_like_prereqs "${packages}"
      ;;
    rhel_like)
      install_rhel_like_prereqs "${packages}"
      ;;
    *)
      if [[ -n "${packages}" ]]; then
        if [[ "${ROLE}" == "server" ]]; then
          echo "Unsupported host family for auto-install; install ${packages} manually or use Ubuntu/debian-apt" >&2
        else
          echo "Unsupported host family for auto-install; install ${packages} manually or use Ubuntu/debian-apt" >&2
        fi
        exit 1
      fi
      ;;
  esac
}

download_url() {
  local url="$1"
  local destination="$2"
  if [[ "${OFFLINE:-0}" == "1" && "${url}" != file:///* ]]; then
    echo "download: stage=preflight reason=offline_requires_local_file" >&2
    return 1
  fi

  # Both installers are standalone assets, so keep this bounded downloader
  # self-contained. Python supervises wget as well: its socket timeout alone
  # does not bound a server that keeps sending a slow stream of bytes.
  python3 -I - "${url}" "${destination}" \
    "${AEGIS_DOWNLOAD_CONNECT_TIMEOUT_SECONDS:-10}" \
    "${AEGIS_DOWNLOAD_TOTAL_TIMEOUT_SECONDS:-120}" "" "0" <<'PY'
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

url, destination, connect_raw, total_raw, pin, insecure = sys.argv[1:]
try:
    connect, total = int(connect_raw), int(total_raw)
    if not 1 <= connect <= min(total, 300) or not 1 <= total <= 3600:
        raise ValueError()
except ValueError:
    print("download: stage=preflight reason=invalid_time_budget", file=sys.stderr)
    raise SystemExit(2)

destination = Path(destination)
partial = None
process = None
spawning = False
pending_signal = None

def cancelled(signum, _frame):
    global pending_signal
    if spawning:
        # Popen may already have created its separate child session without
        # returning its handle yet. Defer until cleanup owns that handle.
        pending_signal = signum
        return
    print("download: stage=transfer reason=cancelled", file=sys.stderr)
    raise SystemExit(128 + signum)

signal.signal(signal.SIGTERM, cancelled)
signal.signal(signal.SIGINT, cancelled)
try:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.unlink(missing_ok=True)
    descriptor, partial = tempfile.mkstemp(prefix=destination.name + ".part.", dir=destination.parent)
    os.close(descriptor)
    curl, wget = shutil.which("curl"), shutil.which("wget")
    if url.startswith("file://"):
        downloader = "python"
    elif curl:
        downloader = "curl"
    elif wget:
        downloader = "wget"
    else:
        downloader = "python"

    if pin and downloader != "curl" and not url.startswith("file://"):
        print("download: stage=preflight reason=spki_pin_requires_curl", file=sys.stderr)
        raise SystemExit(1)
    if downloader == "curl":
        command = [curl, "-fsSL", "--http1.1", "--connect-timeout", str(connect),
                   "--max-time", str(total), "--retry", "0"]
        if pin:
            pin = pin if pin.startswith("sha256//") else "sha256//" + pin
            command += ["--insecure", "--pinnedpubkey", pin]
        elif insecure == "1":
            print("download: WARNING explicit insecure TLS without a pin", file=sys.stderr)
            command += ["--insecure"]
        command += ["-o", partial, "--", url]
    elif downloader == "wget":
        command = [wget, "--timeout=" + str(connect), "--tries=1", "-qO", partial]
        if insecure == "1":
            print("download: WARNING explicit insecure TLS without a pin", file=sys.stderr)
            command += ["--no-check-certificate"]
        command += ["--", url]
    else:
        # The subprocess has the same hard total budget as curl/wget. urllib
        # also checks the declared length, including premature EOF during reads.
        code = """
import sys
import urllib.request
url, destination, connect = sys.argv[1:]
with urllib.request.urlopen(url, timeout=int(connect)) as response:
    expected = response.headers.get("Content-Length")
    received = 0
    with open(destination, "wb") as output:
        while True:
            chunk = response.read(65536)
            if not chunk:
                break
            output.write(chunk)
            received += len(chunk)
    if expected is not None and received != int(expected):
        raise SystemExit(18)
"""
        command = [sys.executable, "-I", "-c", code, url, partial, str(connect)]

    # No downloader retries: a client-bundle URL may already have been
    # redeemed after a partial response. Errors never print the private URL.
    spawning = True
    try:
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
    finally:
        spawning = False
        if pending_signal is not None:
            cancelled(pending_signal, None)
    try:
        status = process.wait(timeout=total)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        status = 124
    if status != 0:
        status = status if status > 0 else 128 - status
        print(f"download: stage=transfer reason=failed exit_code={status}", file=sys.stderr)
        raise SystemExit(status)
    if Path(partial).stat().st_size == 0:
        print("download: stage=transfer reason=empty_response", file=sys.stderr)
        raise SystemExit(65)
    os.replace(partial, destination)
    partial = None
except OSError:
    print("download: stage=staging reason=local_io_failed", file=sys.stderr)
    raise SystemExit(1)
finally:
    # Downloader children have their own session so timeout/cancellation can
    # stop only this transfer. Never leave that session behind on Ctrl-C or
    # TERM, including between spawn and the supervised wait.
    if process is not None and process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
    if partial is not None:
        Path(partial).unlink(missing_ok=True)
PY
}

# The selected signature fixes the archive identity. Other configured sources
# may transport those same bytes, but cannot substitute their own release/hash.
download_archive_with_fallback() {
  local destination="$1" expected="$2" relative_path="$3" selected_manifest="$4"
  shift 4
  local source archive_url attempt=0 visited duplicate
  local tried_sources=()
  ARCHIVE_URL_RESOLVED=""
  for source in "$selected_manifest" "$@"; do
    [[ -z "$source" ]] && continue
    duplicate=0
    for visited in "${tried_sources[@]:-}"; do
      [[ "$visited" == "$source" ]] && duplicate=1
    done
    [[ "$duplicate" == "1" ]] && continue
    tried_sources+=("$source")
    archive_url="$(python3 -I -c 'import sys; from urllib.parse import urljoin; print(urljoin(sys.argv[1], sys.argv[2]))' "$source" "$relative_path")" || return 1
    attempt=$((attempt + 1))
    if download_url "$archive_url" "$destination"; then
      if python3 -I - "$destination" "$expected" <<'PY_DIGEST'
import hashlib, re, sys
from pathlib import Path
expected = sys.argv[2]
if not re.fullmatch(r"[0-9a-f]{64}", expected):
    raise SystemExit("invalid signed archive digest")
h = hashlib.sha256()
with Path(sys.argv[1]).open("rb") as f:
    for chunk in iter(lambda: f.read(1048576), b""):
        h.update(chunk)
if h.hexdigest() != expected:
    raise SystemExit("bundle checksum mismatch")
PY_DIGEST
      then
        ARCHIVE_URL_RESOLVED="$archive_url"
        echo "bootstrap-install: archive source_index=${attempt} verified" >&2
        return 0
      fi
    fi
    rm -f -- "$destination"
    echo "bootstrap-install: archive source_index=${attempt} unavailable_or_invalid" >&2
  done
  return 1
}

# Phase 5.0.D: try each URL in `$@[1..]` (primary plus optional mirrors)
# and commit the first complete verified manifest/signature pair to `$1`.
# Tracks the URL that succeeded in MANIFEST_URL_RESOLVED_BY_FALLBACK so
# downstream evidence captures the actual source.
#
# Returns 0 on first verified source; returns 1 if every source failed.
# Diagnostics identify stages and source indexes, not potentially private URLs.
download_url_with_fallback() {
  local destination="$1"
  shift
  local url="" candidate_root="" candidate_manifest="" candidate_sig=""
  local accepted=0 verified=0 attempted=0 reason="" candidate_sha=""
  MANIFEST_URL_RESOLVED_BY_FALLBACK=""
  MANIFEST_SIGNATURE_VERIFIED=0
  MANIFEST_VERIFIED_SHA256=""
  # A previous invocation in --download-dir must not supply either half.
  rm -f -- "${destination}" "${destination}.sig" || return 1
  for url in "$@"; do
    [[ -z "${url}" ]] && continue
    attempted=$((attempted + 1))
    candidate_root="$(mktemp -d "${destination}.source.XXXXXX")" || return 1
    candidate_manifest="${candidate_root}/manifest.json"
    candidate_sig="${candidate_manifest}.sig"
    accepted=0
    verified=0
    candidate_sha=""
    reason="manifest_transfer_failed"
    if download_url "${url}" "${candidate_manifest}"; then
      reason="signature_transfer_failed"
      if download_url "${url}.sig" "${candidate_sig}"; then
        if verify_manifest_signature "${candidate_manifest}" "${candidate_sig}"; then
          accepted=1
          verified=1
        else
          reason="signature_verification_failed"
          echo "bootstrap-install: release manifest signature verification FAILED" >&2
        fi
      elif [[ "${AEGIS_ALLOW_UNSIGNED_MANIFEST:-0}" == "1" ]]; then
        echo "bootstrap-install: unsigned manifests are refused even when AEGIS_INSTALL_ALLOW_UNSIGNED=1" >&2
        reason="signed_release_policy_required"
      fi
    fi
    if [[ "${accepted}" -eq 1 && "${verified}" -eq 1 ]]; then
      if ! candidate_sha="$(validate_release_policy "${candidate_manifest}")" ||
         ! release_floor_run check "${candidate_manifest}" "${candidate_sha}"; then
        accepted=0
        reason="release_policy_failed"
      fi
    elif [[ "${accepted}" -eq 1 ]]; then
      # An unsigned escape hatch cannot establish or bypass trusted state.
      accepted=0
      reason="signed_release_policy_required"
    fi
    if [[ "${accepted}" -eq 1 ]]; then
      if mv -- "${candidate_manifest}" "${destination}" &&
        { [[ "${verified}" -eq 0 ]] || mv -- "${candidate_sig}" "${destination}.sig"; }; then
        rm -rf -- "${candidate_root}"
        MANIFEST_URL_RESOLVED_BY_FALLBACK="${url}"
        MANIFEST_SIGNATURE_VERIFIED="${verified}"
        MANIFEST_VERIFIED_SHA256="${candidate_sha}"
        if [[ "${verified}" -eq 1 ]]; then
          echo "bootstrap-install: release manifest signature verified (ed25519 pinned key)" >&2
        fi
        if [[ "${attempted}" -gt 1 ]]; then
          echo "bootstrap-install: verified manifest fallback succeeded at source ${attempted}" >&2
        fi
        return 0
      fi
      rm -f -- "${destination}" "${destination}.sig"
      reason="manifest_staging_failed"
    fi
    rm -rf -- "${candidate_root}"
    echo "bootstrap-install: stage=manifest_source source=${attempted} reason=${reason}" >&2
  done
  echo "bootstrap-install: no manifest signature-verified source available; exhausted ${attempted} sources" >&2
  return 1
}

detect_os_kind() {
  # v0.3.2: top-level OS dispatch. Returns "macos" / "linux" / "other".
  # macOS path bypasses the Linux full-bundle manifest entirely and
  # downloads the per-arch macOS client tarball published since v0.1.3.
  local override="${AEGIS_BOOTSTRAP_OS_KIND_OVERRIDE:-}"
  if [[ -n "${override}" ]]; then
    printf '%s\n' "${override}"
    return 0
  fi
  # Existing contract tests pass HOST_FAMILY_OVERRIDE (Linux family
  # override) — when present, force Linux dispatch regardless of host
  # uname so tests stay deterministic on macOS dev hosts.
  if [[ -n "${AEGIS_BOOTSTRAP_HOST_FAMILY_OVERRIDE:-}" ]]; then
    printf 'linux\n'
    return 0
  fi
  case "$(uname -s 2>/dev/null || echo unknown)" in
    Darwin) printf 'macos\n' ;;
    Linux) printf 'linux\n' ;;
    *) printf 'other\n' ;;
  esac
}

detect_family() {
  local id=""
  local like=""

  if [[ -n "${HOST_FAMILY_OVERRIDE}" ]]; then
    printf '%s\n' "${HOST_FAMILY_OVERRIDE}"
    return 0
  fi

  if [[ ! -f /etc/os-release ]]; then
    printf 'generic_linux\n'
    return 0
  fi

  # shellcheck disable=SC1091
  . /etc/os-release
  id="${ID:-}"
  like="${ID_LIKE:-}"
  case " ${id} ${like} " in
    *" debian "*|*" ubuntu "*)
      printf 'debian_like\n'
      ;;
    *" rhel "*|*" fedora "*|*" centos "*|*" rocky "*|*" alma "*)
      printf 'rhel_like\n'
      ;;
    *" suse "*|*" opensuse "*|*" sles "*)
      printf 'suse_like\n'
      ;;
    *)
      printf 'generic_linux\n'
      ;;
  esac
}

OS_KIND="$(detect_os_kind)"

if [[ -n "${RECOVER_INTERRUPTED_RELEASE}" ]]; then
  case "${RECOVER_INTERRUPTED_RELEASE}" in
    inspect|confirm-installed|discard-failed) ;;
    *) echo "Recovery must be inspect, confirm-installed or discard-failed" >&2; exit 2 ;;
  esac
  release_floor_run "${RECOVER_INTERRUPTED_RELEASE}" "" ""
  exit 0
fi

if [[ "${OS_KIND}" == "macos" ]]; then
  if [[ "${OFFLINE}" == "1" || "${DOWNLOAD_ONLY}" == "1" || ${#EXPLICIT_SOURCES[@]} -gt 0 ]]; then
    echo "--offline, --download-only and --source currently support Linux only." >&2
    exit 1
  fi
  if [[ "${ROLE}" != "client" ]]; then
    echo "macOS only supports the 'client' role; AEGIS server requires Linux." >&2
    exit 1
  fi
  # macOS arch detection. uname -m returns arm64 on Apple Silicon and
  # x86_64 on Intel; release tarballs are named with the standard
  # aarch64 / x86_64 strings, so we translate.
  case "$(uname -m 2>/dev/null || echo unknown)" in
    arm64|aarch64) MAC_ARCH="aarch64" ;;
    x86_64) MAC_ARCH="x86_64" ;;
    *)
      echo "Unsupported macOS architecture: $(uname -m). Expected arm64 or x86_64." >&2
      exit 1
      ;;
  esac

  RELEASE_BASE="${AEGIS_BOOTSTRAP_RELEASE_BASE:-https://github.com/propafinder/aegis-release/releases/latest/download}"
  MAC_TARBALL_URL="${RELEASE_BASE}/aegis-client-VERSION-macos-${MAC_ARCH}.tar.gz"

  if [[ -z "${DOWNLOAD_DIR}" ]]; then
    DOWNLOAD_DIR="$(make_bootstrap_temp_dir "aegis-bootstrap-mac")"
    AUTO_DOWNLOAD_DIR=1
  fi
  DOWNLOAD_DIR="$(prepare_bootstrap_directory "${DOWNLOAD_DIR}")"
  MAC_ARCHIVE_PATH="${DOWNLOAD_DIR}/aegis-client-macos-${MAC_ARCH}.tar.gz"
  MAC_EXTRACT_ROOT="$(mktemp -d "${DOWNLOAD_DIR}/macos-bundle.XXXXXX")"

  # Resolve VERSION via the latest-redirect: GitHub serves the manifest
  # at /releases/latest/download/release.manifest.json which contains
  # the resolved version string. We re-use that for arch-specific URL.
  MANIFEST_URL_RESOLVED="${RELEASE_BASE}/release.manifest.json"
  MAC_MANIFEST_PATH="${DOWNLOAD_DIR}/release.manifest.json"
  MAC_MANIFEST_SIG_PATH="${MAC_MANIFEST_PATH}.sig"

  # VERIFY BEFORE TRUSTING ANY FIELD.
  #
  # This path used to skip signature verification entirely: it re-downloaded an
  # unsigned manifest, read the version out of it, fetched the tarball, and checked
  # it only against a .sha256 served from the same origin — a self-referential check
  # that whoever controls the asset also controls. The pinned ed25519 key that
  # guards the Linux path was never consulted, so swapping the release asset (or
  # pointing AEGIS_BOOTSTRAP_RELEASE_BASE at a hostile host) delivered an arbitrary
  # client binary to every Mac, which is then `exec bash`-ed below.
  # Use the same isolated pair gate; never reuse a stale or partial signature.
  if ! download_url_with_fallback "${MAC_MANIFEST_PATH}" "${MANIFEST_URL_RESOLVED}"; then
    echo "[bootstrap] FATAL: could not verify the macOS release manifest signature" >&2
    exit 1
  fi

  MAC_VERSION="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "${MAC_MANIFEST_PATH}")"
  MAC_CHANNEL="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get("channel","stable"))' "${MAC_MANIFEST_PATH}")"
  MAC_TARBALL_URL="${RELEASE_BASE}/aegis-client-${MAC_VERSION}-macos-${MAC_ARCH}.tar.gz"
  # Require this arch's digest from the exact signature-verified manifest before
  # fetching any archive. Legacy unsigned flags cannot relax archive identity.
  MAC_TARBALL_SHA256="$(
    python3 -I - "${MAC_MANIFEST_PATH}" "${MAC_ARCH}" "${MANIFEST_VERIFIED_SHA256}" <<'PY'
import hashlib, json, re, sys
from pathlib import Path
raw = Path(sys.argv[1]).read_bytes()
if len(raw) > 65536 or hashlib.sha256(raw).hexdigest() != sys.argv[3]:
    raise SystemExit("verified macOS manifest bytes changed")
entry = json.loads(raw)
for key in ("artifacts", "macos_client", "split", sys.argv[2]):
    if not isinstance(entry, dict):
        raise SystemExit("signed manifest has no valid macOS archive digest")
    entry = entry.get(key)
digest = entry.get("sha256") if isinstance(entry, dict) else None
if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
    raise SystemExit("signed manifest has no valid macOS archive digest")
print(digest)
PY
  )"

  cat <<EOF
AEGIS bootstrap installer
------------------------
OS kind:         macos (uname -s = Darwin)
Architecture:    ${MAC_ARCH} (uname -m = $(uname -m))
Release channel: ${MAC_CHANNEL}
Release version: ${MAC_VERSION}
Bundle source:   ${MAC_TARBALL_URL}

macOS client uses a per-arch tarball (no full Linux bundle). The
tarball includes install-macos-client.sh which handles SOCKS5 auth,
launchd LaunchAgent registration, and SPKI pin extraction from the
operator-supplied private access record.

EOF

  download_url "${MAC_TARBALL_URL}" "${MAC_ARCHIVE_PATH}"

  # Compare against the digest inside the signature-verified manifest, never
  # against a checksum file fetched next to the archive.
  python3 -I - "${MAC_ARCHIVE_PATH}" "${MAC_TARBALL_SHA256}" <<'PY'
import hashlib, sys
from pathlib import Path
archive = Path(sys.argv[1])
expected = sys.argv[2].strip().lower()
actual = hashlib.sha256(archive.read_bytes()).hexdigest()
if expected != actual:
    print(f"sha256 mismatch: manifest says {expected}, downloaded archive is {actual}", file=sys.stderr)
    sys.exit(1)
PY

  tar --no-same-owner -xzf "${MAC_ARCHIVE_PATH}" -C "${MAC_EXTRACT_ROOT}"

  # Find the extracted root containing install-macos-client.sh.
  MAC_BUNDLE_ROOT=""
  for candidate in "${MAC_EXTRACT_ROOT}"/*/; do
    if [[ -f "${candidate}install-macos-client.sh" ]]; then
      MAC_BUNDLE_ROOT="${candidate}"
      break
    fi
  done
  if [[ -z "${MAC_BUNDLE_ROOT}" ]]; then
    echo "Extracted macOS tarball has no install-macos-client.sh — possibly an older v<0.3.2 tarball." >&2
    echo "Upgrade the release and use --bundle-url-file with a private access record." >&2
    exit 1
  fi

  chmod +x "${MAC_BUNDLE_ROOT}install-macos-client.sh"
  # bash 3.2 (macOS system default) treats "${array[@]}" as unbound under
  # `set -u` even when the array IS declared. Use the ${var+alt}
  # parameter-expansion form which is safe-empty-aware.
  AEGIS_INSTALL_SOURCE_MANIFEST_URL="${MANIFEST_URL_RESOLVED}" \
  AEGIS_INSTALL_SOURCE_RELEASE_CHANNEL="${MAC_CHANNEL}" \
  AEGIS_INSTALL_RELEASE_VERSION="${MAC_VERSION}" \
  release_floor_run install "${MAC_MANIFEST_PATH}" "${MANIFEST_VERIFIED_SHA256}" \
    bash "${MAC_BUNDLE_ROOT}install-macos-client.sh" ${FORWARDED_ARGS[@]+"${FORWARDED_ARGS[@]}"}
  exit 0
fi

HOST_FAMILY="$(detect_family)"
ensure_bootstrap_prereqs "${HOST_FAMILY}"

# Dependencies and OS dispatch must precede the first signed asset download.
if [[ -z "${DOWNLOAD_DIR}" ]]; then
  DOWNLOAD_DIR="$(make_bootstrap_temp_dir "aegis-bootstrap")"
  AUTO_DOWNLOAD_DIR=1
fi
DOWNLOAD_DIR="$(prepare_bootstrap_directory "${DOWNLOAD_DIR}")"

MANIFEST_PATH="${DOWNLOAD_DIR}/release.manifest.json"
ARCHIVE_PATH="${DOWNLOAD_DIR}/release-bundle.tar.gz"
EXTRACT_ROOT="$(mktemp -d "${DOWNLOAD_DIR}/bundle.XXXXXX")"

# Phase 5.0.D: build the manifest fetch list — primary URL plus any
# comma-separated mirrors from AEGIS_INSTALL_MIRRORS. The legacy single-
# URL behavior is preserved when no mirrors are configured.
MANIFEST_URLS_TO_TRY=("${MANIFEST_URL}")
if [[ ${#EXPLICIT_SOURCES[@]} -gt 0 ]]; then
  MANIFEST_URLS_TO_TRY=("${EXPLICIT_SOURCES[@]}")
fi
if [[ -n "${MANIFEST_URL_MIRRORS_RAW}" ]]; then
  # Split on commas, trim whitespace, skip empty entries.
  while IFS= read -r mirror_entry; do
    mirror_entry="${mirror_entry#"${mirror_entry%%[![:space:]]*}"}"
    mirror_entry="${mirror_entry%"${mirror_entry##*[![:space:]]}"}"
    [[ -z "${mirror_entry}" ]] && continue
    mirror_entry="$(manifest_url_for_host_arch "${mirror_entry}")"
    MANIFEST_URLS_TO_TRY+=("${mirror_entry}")
  done < <(printf '%s\n' "${MANIFEST_URL_MIRRORS_RAW}" | tr ',' '\n')
fi

if ! download_url_with_fallback "${MANIFEST_PATH}" "${MANIFEST_URLS_TO_TRY[@]}"; then
  echo "bootstrap-install: manifest fetch failed across all configured sources" >&2
  exit 1
fi
# Re-anchor MANIFEST_URL to the URL that actually delivered the manifest
# so downstream consumers (release_base derivation, environment exports)
# see the real source rather than the primary that may have failed.
MANIFEST_URL="${MANIFEST_URL_RESOLVED_BY_FALLBACK}"

# The fallback helper already verified both files from the SAME source before
# selecting it. Do not fetch the signature again or reuse a prior partial pair.
MANIFEST_SIG_PATH="${MANIFEST_PATH}.sig"
MANIFEST_SIG_URL="${MANIFEST_URL}.sig"

MANIFEST_FIELDS="$(
  python3 -I - <<'PY' "${MANIFEST_PATH}" "${MANIFEST_URL}" "${ROLE}"
import json
import sys
from pathlib import Path
from urllib.parse import urljoin

manifest_path = Path(sys.argv[1])
manifest_url = sys.argv[2]
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
if manifest.get("distribution") == "public_client" and sys.argv[3] != "client":
    raise SystemExit("this release contains only the client")

if manifest.get("schema") != "aegis_linux_release_manifest_v1":
    raise SystemExit("unsupported release manifest schema")

bundle = manifest["artifacts"]["bundle"]
archive_rel = bundle["archive"]["path"]
from pathlib import PurePosixPath
if (not isinstance(archive_rel, str) or not archive_rel
        or PurePosixPath(archive_rel).name != archive_rel
        or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for c in archive_rel)
        or not archive_rel.endswith(".tar.gz")):
    raise SystemExit("release archive must be a relative tarball filename")

# The archive hash MUST come from the signed manifest, not from a .sha256 file
# fetched alongside the archive. The ed25519 signature covers this manifest and
# nothing else, so anchoring on a separately-downloaded checksum let a malicious
# mirror serve the genuine manifest + genuine signature + a tampered archive with
# a matching .sha256 — every check passed and install.sh then ran it as root.
archive_sha256 = bundle["archive"].get("sha256")
if not archive_sha256:
    raise SystemExit(
        "release manifest does not carry artifacts.bundle.archive.sha256; "
        "refusing to fall back to an unsigned .sha256 file"
    )

print(urljoin(manifest_url, archive_rel))
print(archive_sha256)
print(manifest["version"])
print(manifest["channel"])
print(manifest.get("git_sha", "unknown"))
print(manifest.get("build_timestamp", "unknown"))
print(manifest.get("platform", "linux"))
print(manifest.get("arch", "unknown"))
print(manifest.get("target_triple", "unknown"))
print(str(manifest.get("prerelease", False)).lower())
print(archive_rel)
print(manifest.get("bootstrap", {}).get("sha256", ""))
PY
)"

BUNDLE_URL="$(printf '%s\n' "${MANIFEST_FIELDS}" | sed -n '1p')"
# Signature-anchored expected digest (see the manifest parser above).
BUNDLE_SHA256="$(printf '%s\n' "${MANIFEST_FIELDS}" | sed -n '2p')"
RELEASE_VERSION="$(printf '%s\n' "${MANIFEST_FIELDS}" | sed -n '3p')"
RELEASE_CHANNEL="$(printf '%s\n' "${MANIFEST_FIELDS}" | sed -n '4p')"
RELEASE_GIT_SHA="$(printf '%s\n' "${MANIFEST_FIELDS}" | sed -n '5p')"
RELEASE_BUILD_TIMESTAMP="$(printf '%s\n' "${MANIFEST_FIELDS}" | sed -n '6p')"
RELEASE_PLATFORM="$(printf '%s\n' "${MANIFEST_FIELDS}" | sed -n '7p')"
RELEASE_ARCH="$(printf '%s\n' "${MANIFEST_FIELDS}" | sed -n '8p')"
RELEASE_TARGET_TRIPLE="$(printf '%s\n' "${MANIFEST_FIELDS}" | sed -n '9p')"
RELEASE_PRERELEASE="$(printf '%s\n' "${MANIFEST_FIELDS}" | sed -n '10p')"
BUNDLE_RELATIVE_PATH="$(printf '%s\n' "${MANIFEST_FIELDS}" | sed -n '11p')"
BOOTSTRAP_SHA256="$(printf '%s\n' "${MANIFEST_FIELDS}" | sed -n '12p')"

if [[ "${ROLE}" == "server" || "${ROLE}" == "client" ]]; then
  # Normalise before comparing: `uname -m` says arm64 on Darwin and aarch64 on
  # Linux for the same architecture, while release artifacts are always named
  # aarch64. Comparing the raw value rejected valid arm64 releases. This is the
  # same normalisation scripts/lib/host-arch.sh applies; it is inlined because
  # bootstrap-install.sh is fetched and run standalone via curl.
  HOST_ARCH="${AEGIS_BOOTSTRAP_ARCH_OVERRIDE:-$(uname -m 2>/dev/null || echo unknown)}"
  case "${HOST_ARCH}" in
    arm64) HOST_ARCH="aarch64" ;;
    amd64) HOST_ARCH="x86_64" ;;
  esac
  if [[ "${RELEASE_PLATFORM}" != "linux" ]]; then
    echo "Unsupported release platform: ${RELEASE_PLATFORM}; expected linux." >&2
    exit 1
  fi
  if [[ "${RELEASE_ARCH}" != "${HOST_ARCH}" ]]; then
    echo "Unsupported architecture for this release: host=${HOST_ARCH}, release=${RELEASE_ARCH}, target=${RELEASE_TARGET_TRIPLE}." >&2
    exit 1
  fi
fi

if ! download_archive_with_fallback "${ARCHIVE_PATH}" "${BUNDLE_SHA256}" \
  "${BUNDLE_RELATIVE_PATH}" "${MANIFEST_URL}" "${MANIFEST_URLS_TO_TRY[@]}"; then
  echo "bootstrap-install: archive fetch/verification failed across configured sources" >&2
  exit 1
fi
BUNDLE_URL="${ARCHIVE_URL_RESOLVED}"
if [[ "${DOWNLOAD_ONLY}" == "1" ]]; then
  mv -- "${ARCHIVE_PATH}" "${DOWNLOAD_DIR}/${BUNDLE_RELATIVE_PATH}"
  if [[ -n "${BOOTSTRAP_SHA256}" ]]; then
    download_archive_with_fallback "${DOWNLOAD_DIR}/bootstrap-install.sh" "${BOOTSTRAP_SHA256}" \
      "bootstrap-install.sh" "${MANIFEST_URL}" "${MANIFEST_URLS_TO_TRY[@]}" || exit 1
  fi
  cat > "${DOWNLOAD_DIR}/INSTALL-OFFLINE.txt" <<'EOF'
Copy this complete directory to the Linux machine of the matching architecture.
Install the OS prerequisites before disconnecting (Python 3, OpenSSL, tar, curl;
automatic client mode additionally requires iproute2/iproute, iptables, nftables
and util-linux).
Use the verified bootstrap from this kit, or your previously trusted bootstrap:
  bash ./bootstrap-install.sh client --offline --source "file://$PWD/release.manifest.json" --bundle /absolute/path/to/private-client-bundle
The private client access bundle is issued separately and is never in this kit.
EOF
  echo "Verified public release saved in ${DOWNLOAD_DIR}; see INSTALL-OFFLINE.txt."
  exit 0
fi
if [[ "${OFFLINE}" == "1" && "$ROLE" == client ]]; then
  # Private URL is not read here. The signed client owns local-only admission
  # after the public release is verified and extracted.
  FORWARDED_ARGS+=(--bundle-local-only)
fi

mkdir -p "${EXTRACT_ROOT}"
tar --no-same-owner -xzf "${ARCHIVE_PATH}" -C "${EXTRACT_ROOT}"

# Heredoc into a variable, then pipe — never a heredoc directly inside
# "$( ... )". bash 3.2 (still /bin/bash on macOS) parses the heredoc body for
# quotes in that position, so an odd number of apostrophes in the body makes it
# swallow everything that follows, including the next function definitions. The
# failure is not a syntax error; the script just dies later with
# "command not found". detect_os_kind() is defined immediately below this
# block, which is exactly what would disappear.
PY_FIND_BUNDLE=''
IFS= read -r -d '' PY_FIND_BUNDLE <<'PY' || true
import sys
from pathlib import Path

root = Path(sys.argv[1])
for candidate in sorted(root.iterdir()):
    if candidate.is_dir() and (candidate / "install.sh").is_file():
        print(candidate)
        sys.exit(0)
sys.exit(1)
PY
BUNDLE_DIR="$(printf '%s' "${PY_FIND_BUNDLE}" | python3 -I - "${EXTRACT_ROOT}")"

# New v3 adds a bounded producer-bound graph. This prelaunch check does not
# execute the packaged client or installer and does not certify linked/native SBOM.
python3 -I - "${BUNDLE_DIR}" "${MANIFEST_PATH}" "${MANIFEST_VERIFIED_SHA256}" <<'PY_SHIPPING_INVENTORY'
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
def validate_shipping_client_inventory(raw, provenance, actual_binary_sha256):
    """Require the Rust producer's closed graph and exact artifact bindings.

    A valid signed record is producer-observed evidence, never independent
    compiler linkage, native dependency completeness or legal acceptance.
    """
    import json
    import re

    def need(condition):
        if not condition:
            raise ValueError("shipping Cargo inventory rejected")

    def unique(items):
        value = {}
        for key, item in items:
            need(key not in value)
            value[key] = item
        return value

    def hex_value(value, length=64):
        return isinstance(value, str) and re.fullmatch("[0-9a-f]{" + str(length) + "}", value) is not None

    def token(value):
        return isinstance(value, str) and 0 < len(value) <= 256 and re.fullmatch(r"[A-Za-z0-9._+\-]+", value) is not None

    def ordered_strings(values, safe=False):
        return isinstance(values, list) and all(isinstance(v, str) and (not safe or token(v)) for v in values) and all(a < b for a, b in zip(values, values[1:]))

    need(isinstance(raw, bytes) and 0 < len(raw) <= 4 * 1024 * 1024)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                           parse_constant=lambda _: need(False))
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise ValueError("shipping Cargo inventory rejected") from None
    fields = {"schema", "scope", "native_payload_complete", "compiler_linkage_proven",
              "source_revision", "target_triple", "default_features", "requested_features",
              "cargo_lock_sha256", "client_binary_sha256", "cargo_metadata_sha256",
              "producer", "root_component", "components"}
    need(isinstance(value, dict) and set(value) == fields)
    need(value["schema"] == "aegis_shipping_client_cargo_inventory_v1" and
         value["scope"] == "selected_target_filtered_cargo_graph_not_compiler_linkage" and
         value["native_payload_complete"] is False and value["compiler_linkage_proven"] is False and
         value["default_features"] is True and hex_value(value["cargo_metadata_sha256"]))
    features = ["chrome-like-quic", "chrome-like-tls", "raw-socket"]
    need(isinstance(provenance, dict) and hex_value(provenance.get("git_sha"), 40) and
         hex_value(provenance.get("cargo_lock_sha256")) and hex_value(actual_binary_sha256) and
         provenance.get("target_triple") in ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"))
    need(provenance.get("schema") == "aegis_client_release_bundle_manifest_v3" and set(provenance) == {
        "schema", "distribution", "bundle_name", "version", "arch", "platform", "target_triple",
        "git_sha", "build_timestamp", "cargo_lock_sha256", "runtime_abi", "binaries", "files", "install_entrypoints"})
    need(provenance["distribution"] == "public_client" and provenance["platform"] == "linux" and
         provenance["arch"] in ("x86_64", "aarch64") and provenance["target_triple"] == provenance["arch"] + "-unknown-linux-gnu")
    binaries = provenance.get("binaries")
    need(isinstance(binaries, dict) and set(binaries) == {"aegis-client"})
    binary = binaries["aegis-client"]
    need(isinstance(binary, dict) and set(binary) == {"features", "path", "sha256"} and binary.get("path") == "bin/aegis-client" and
         binary.get("sha256") == actual_binary_sha256 and isinstance(binary.get("features"), list) and
         len(binary["features"]) == 3 and all(isinstance(f, str) for f in binary["features"]) and
         set(binary["features"]) == set(features))
    need(value["source_revision"] == provenance["git_sha"] and
         value["target_triple"] == provenance["target_triple"] and
         value["cargo_lock_sha256"] == provenance["cargo_lock_sha256"] and
         value["client_binary_sha256"] == actual_binary_sha256 and
         value["requested_features"] == features)
    record = value["producer"]
    record_fields = {"schema", "source_revision", "target_triple", "cargo_lock_sha256",
                     "binary_sha256", "default_features", "requested_features", "resolved_root_features",
                     "compiler_artifact_message_sha256", "build_message_stream_sha256", "target_evidence"}
    need(isinstance(record, dict) and set(record) == record_fields)
    need(record["schema"] == "aegis_linux_client_build_record_v1" and
         record["source_revision"] == provenance["git_sha"] and record["target_triple"] == provenance["target_triple"] and
         record["cargo_lock_sha256"] == provenance["cargo_lock_sha256"] and
         record["binary_sha256"] == actual_binary_sha256 and record["default_features"] is True and
         record["requested_features"] == features and
         record["target_evidence"] == "explicit_cargo_target_and_fixed_producer_invocation" and
         hex_value(record["compiler_artifact_message_sha256"]) and hex_value(record["build_message_stream_sha256"]) and
         ordered_strings(record["resolved_root_features"], safe=True) and
         set(features).issubset(record["resolved_root_features"]))
    components = value["components"]
    need(isinstance(components, list) and 0 < len(components) <= 4096 and isinstance(value["root_component"], str))
    by_key, order, edges = {}, [], 0
    component_fields = {"key", "name", "version", "source_kind", "source_identity_sha256", "features", "dependencies"}
    for item in components:
        need(isinstance(item, dict) and set(item) == component_fields and token(item["name"]) and token(item["version"]) and
             hex_value(item["source_identity_sha256"]) and item["source_kind"] in ("reviewed_local_manifest", "crates_io_registry"))
        key = item["name"] + "@" + item["version"] + "#" + item["source_identity_sha256"]
        need(item["key"] == key and key not in by_key and ordered_strings(item["features"], safe=True) and
             ordered_strings(item["dependencies"]))
        by_key[key] = item
        order.append(key)
        edges += len(item["dependencies"])
    need(edges <= 16384 and all(a < b for a, b in zip(order, order[1:])) and value["root_component"] in by_key)
    root = by_key[value["root_component"]]
    need(root["name"] == "aegis-client" and root["source_kind"] == "reviewed_local_manifest" and
         root["features"] == record["resolved_root_features"] and set(features).issubset(root["features"]))
    visited, pending = set(), [value["root_component"]]
    while pending:
        key = pending.pop()
        need(key in by_key)
        if key in visited:
            continue
        visited.add(key)
        pending.extend(by_key[key]["dependencies"])
    need(len(visited) == len(by_key))
    return {"schema": value["schema"], "source_revision": value["source_revision"],
            "target_triple": value["target_triple"], "client_binary_sha256": actual_binary_sha256,
            "components": len(components), "native_payload_complete": False, "compiler_linkage_proven": False}

root = Path(sys.argv[1])
def bounded(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            raise SystemExit("public v3 provenance input rejected")
        data = stream.read(limit + 1)
        if len(data) != info.st_size or len(data) > limit:
            raise SystemExit("public v3 provenance input rejected")
        return data
outer_raw = bounded(Path(sys.argv[2]), 1024 * 1024)
if hashlib.sha256(outer_raw).hexdigest() != sys.argv[3]:
    raise SystemExit("verified release custody changed")
outer = json.loads(outer_raw)
if not isinstance(outer, dict) or outer.get("schema") != "aegis_linux_release_manifest_v1":
    raise SystemExit("unsupported verified outer release")
public_outer = outer.get("distribution") == "public_client"
inner_path = root / "bundle.manifest.json"
try:
    raw = bounded(inner_path, 1024 * 1024)
except FileNotFoundError:
    # Preserve the existing private signed source-layout bootstrap path.
    # Public releases never acquire this absence exception.
    source_layout = (root / "Cargo.toml").is_file() and (root / "aegis-client").is_dir() and (root / "aegis-server").is_dir()
    if not public_outer and source_layout:
        sys.exit(0)
    raise SystemExit("verified release inner provenance missing")
manifest = json.loads(raw)
if manifest.get("schema") == "aegis_client_release_bundle_manifest_v3":
    if not public_outer:
        raise SystemExit("public v3 distribution scope mismatch")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("public v3 duplicate provenance field")
            result[key] = value
        return result
    manifest = json.loads(raw, object_pairs_hook=unique)
    public = set("""bin/aegis-client install.sh config.example.toml
scripts/setup-wide-linux-redirect.sh scripts/setup-wide-linux-tproxy.sh
scripts/aegis-wide-enable.sh scripts/aegis-wide-disable.sh scripts/aegis-wide-persist-install.sh
scripts/purge-installed-aegis.sh scripts/aegis-ubuntu-uninstall.sh scripts/janitor-wide-linux-tproxy.sh
scripts/aegis-rpi-gateway.sh scripts/lib/root-state.sh packaging/systemd/aegis-client.service
packaging/env/aegis-client.env.example README.txt THIRD-PARTY-NOTICES.txt
scripts/aegis-device-egress-guard.sh client-cargo-inventory.json SHA256SUMS""".split())
    listed = manifest.get("files")
    if not isinstance(listed, list) or not all(isinstance(name, str) for name in listed) or len(listed) != len(public) or set(listed) != public:
        raise SystemExit("public v3 inventory policy rejected")
    observed = set()
    observed_bytes = 0
    for item in root.rglob("*"):
        info = item.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise SystemExit("public v3 archive link or special file rejected")
        observed.add(item.relative_to(root).as_posix())
        observed_bytes += info.st_size
        if observed_bytes > 64 * 1024 * 1024:
            raise SystemExit("public v3 payload exceeds bound")
    if observed != public | {"bundle.manifest.json"}:
        raise SystemExit("public v3 archive inventory rejected")
    contents = {}
    remaining = 64 * 1024 * 1024 - len(raw)
    for name in sorted(public):
        leaf_limit = 4 * 1024 * 1024 if name == "client-cargo-inventory.json" else 64 * 1024 * 1024
        content = bounded(root / name, min(leaf_limit, remaining))
        remaining -= len(content)
        if remaining < 0:
            raise SystemExit("public v3 payload exceeds bound")
        contents[name] = content
    sums = {}
    for line in contents["SHA256SUMS"].decode("utf-8").splitlines():
        parts = line.split()
        if len(parts) != 2 or parts[1] not in public - {"SHA256SUMS"} or parts[1] in sums or parts[0] != hashlib.sha256(contents[parts[1]]).hexdigest():
            raise SystemExit("public v3 checksum inventory rejected")
        sums[parts[1]] = parts[0]
    if set(sums) != public - {"SHA256SUMS"}:
        raise SystemExit("public v3 checksum inventory incomplete")
    binary_hash = hashlib.sha256(contents["bin/aegis-client"]).hexdigest()
    validate_shipping_client_inventory(contents["client-cargo-inventory.json"], manifest, binary_hash)
PY_SHIPPING_INVENTORY



cat <<EOF
AEGIS bootstrap installer
------------------------
Host family: ${HOST_FAMILY}
Release channel: ${RELEASE_CHANNEL}
Release version: ${RELEASE_VERSION}
Bundle source: ${BUNDLE_URL}

Using release bundle because role-aware server/client configuration currently
lives in install.sh inside the bundle delivery contract.
EOF

AEGIS_INSTALL_SOURCE_MANIFEST_URL="${MANIFEST_URL}" \
AEGIS_INSTALL_SOURCE_RELEASE_CHANNEL="${RELEASE_CHANNEL}" \
AEGIS_INSTALL_RELEASE_VERSION="${RELEASE_VERSION}" \
AEGIS_INSTALL_RELEASE_GIT_SHA="${RELEASE_GIT_SHA}" \
AEGIS_INSTALL_RELEASE_BUILD_TIMESTAMP="${RELEASE_BUILD_TIMESTAMP}" \
AEGIS_INSTALL_RELEASE_PRERELEASE="${RELEASE_PRERELEASE}" \
release_floor_run install "${MANIFEST_PATH}" "${MANIFEST_VERIFIED_SHA256}" \
  "${BUNDLE_DIR}/install.sh" "${ROLE}" ${FORWARDED_ARGS[@]+"${FORWARDED_ARGS[@]}"}
