#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.cargo/bin:${PATH}"
# Portable install fixtures retain OS account tools but exclude Rustup bins.
INSTALL_FIXTURE_PATH="/usr/sbin:/usr/bin:/sbin:/bin"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required; install Rust via rustup first" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-release-contract.XXXXXX")"
# The real server account must traverse this disposable fixture to read its
# group-readable bundle. Secret leaves retain their installer-set permissions.
if [[ ${EUID} -eq 0 ]]; then
  chmod 0711 "${TMP_DIR}"
fi
ARTIFACT_DIR="${AEGIS_RELEASE_CONTRACT_ARTIFACT_DIR:-}"
ARTIFACT_IDENTITY=""
ARTIFACT_FINISHED=0

retain_release_contract_artifacts() {
  python3 -E - "$1" "${ARTIFACT_DIR}" "${ARTIFACT_IDENTITY}" "${TMP_DIR}" \
    "${PUBLIC_CLIENT:-}" "${VERSION:-}" "${ARCH:-}" "${2:-0}" <<'PY'
import datetime, hashlib, io, json, os, re, stat, sys, tarfile
from pathlib import Path

action, raw, identity, temporary, public, version, arch, status = sys.argv[1:]
destination = Path(raw)
assert destination.is_absolute() and str(destination) == raw, "artifact destination must be absolute"
if action == "init":
    destination.mkdir(mode=0o700)  # Existing directories and links must fail.
    info = destination.lstat()
    print(f"{info.st_dev}:{info.st_ino}")
    raise SystemExit(0)
info = destination.lstat()
assert stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077
assert identity == f"{info.st_dev}:{info.st_ino}", "artifact destination changed"
assert not list(destination.iterdir()), "artifact destination is not empty"
receipt = {
    "schema": "aegis_release_contract_public_artifacts_v1",
    "recorded_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "contract_result": "PASS" if action == "success" else "FAIL",
    "contract_exit_code": int(status),
    "scope": "Unsigned local release-bundle contract evidence; not signed candidate, publication, native boot or fleet acceptance.",
    "copied_file_sha256": {},
}

def write_receipt():
    with (destination / "receipt.json").open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(receipt, indent=2, sort_keys=True) + "\n")

if action != "success":
    # The outer runner captures stderr. No generated credentials, installed
    # state or arbitrary private temporary logs are retained on failure.
    receipt["retention_result"] = "FAILURE_STATUS_ONLY"
    write_receipt()
    raise SystemExit(0)

created_files, created_dirs = [], []
try:
    limit = 64 * 1024 * 1024  # Matches the public delivery producer's bound.

    def read_public(path):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            assert len(data) == before.st_size <= limit
            assert (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            return data

    assert re.fullmatch(r"[0-9.]+", version) and arch in ("x86_64", "aarch64")
    bundle = Path(public)
    assert bundle == Path(temporary) / f"aegis-client-{version}-linux-{arch}"
    assert stat.S_ISDIR(bundle.lstat().st_mode)
    manifest = json.loads(read_public(bundle / "bundle.manifest.json"))
    allowed = set("""bin/aegis-client install.sh config.example.toml
scripts/setup-wide-linux-redirect.sh scripts/setup-wide-linux-tproxy.sh
scripts/aegis-wide-enable.sh scripts/aegis-wide-disable.sh scripts/aegis-wide-persist-install.sh
scripts/purge-installed-aegis.sh scripts/aegis-ubuntu-uninstall.sh scripts/janitor-wide-linux-tproxy.sh
scripts/aegis-rpi-gateway.sh scripts/lib/root-state.sh packaging/systemd/aegis-client.service
packaging/env/aegis-client.env.example README.txt THIRD-PARTY-NOTICES.txt""".split())
    assert manifest["schema"] in ("aegis_client_release_bundle_manifest_v1", "aegis_client_release_bundle_manifest_v2", "aegis_client_release_bundle_manifest_v3")
    if manifest["schema"] in ("aegis_client_release_bundle_manifest_v2", "aegis_client_release_bundle_manifest_v3"):
        allowed.add("scripts/aegis-device-egress-guard.sh")
    if manifest["schema"] == "aegis_client_release_bundle_manifest_v3":
        allowed.add("client-cargo-inventory.json")
    allowed.update(("SHA256SUMS", "bundle.manifest.json"))
    assert manifest["distribution"] == "public_client" and manifest["bundle_name"] == bundle.name
    observed = set()
    for directory, dirs, files in os.walk(bundle, followlinks=False):
        for name in dirs:
            assert stat.S_ISDIR((Path(directory) / name).lstat().st_mode), "linked public directory"
        observed.update((Path(directory) / name).relative_to(bundle).as_posix() for name in files)
    assert observed == allowed, "public client inventory mismatch"
    contents = {name: read_public(bundle / name) for name in sorted(allowed)}
    assert sum(map(len, contents.values())) <= limit, "public payload exceeds bound"
    copies = {f"{bundle.name}/{name}": data for name, data in contents.items()}
    archive_path = Path(str(bundle) + ".tar.gz")
    checksum_path = Path(str(archive_path) + ".sha256")
    if os.path.lexists(archive_path):
        archive_bytes = read_public(archive_path)
        seen = set()
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
            for member in archive:
                assert member.isfile() and member.name in copies and member.name not in seen
                assert member.size == len(copies[member.name])
                assert archive.extractfile(member).read(limit + 1) == copies[member.name]
                seen.add(member.name)
        assert seen == set(copies), "public archive inventory mismatch"
        copies[archive_path.name] = archive_bytes
    if os.path.lexists(checksum_path):
        assert archive_path.name in copies, "orphan public archive checksum"
        checksum = read_public(checksum_path)
        assert checksum.decode().split() == [hashlib.sha256(copies[archive_path.name]).hexdigest(), archive_path.name]
        copies[checksum_path.name] = checksum
    # Copy only the validated public bytes, never the operator bundle or TMP_DIR.
    for name, data in sorted(copies.items()):
        target = destination / name
        for parent in reversed(target.parents):
            if parent != destination and destination in parent.parents and not parent.exists():
                parent.mkdir(mode=0o755)
                created_dirs.append(parent)
        with target.open("xb") as stream:
            created_files.append(target)
            stream.write(data)
        target.chmod(0o755 if name.endswith(".sh") or name == f"{bundle.name}/bin/aegis-client" else 0o644)
        receipt["copied_file_sha256"][name] = hashlib.sha256(data).hexdigest()
    receipt["retention_result"] = "PUBLIC_CLIENT_ARTIFACTS_COPIED"
    receipt["public_bundle"] = bundle.name
    receipt["public_bundle_schema"] = manifest["schema"]
    write_receipt()
except Exception:
    # Partial retention contains only files created above. Leave status alone,
    # rather than keeping an incomplete payload that could be mistaken for PASS.
    for path in reversed(created_files):
        path.unlink()
    for path in reversed(created_dirs):
        path.rmdir()
    receipt["copied_file_sha256"] = {}
    receipt["retention_result"] = "RETENTION_FAILED_AFTER_CONTRACT_PASS"
    write_receipt()
    raise SystemExit("public release contract artifact retention failed")
PY
}

cleanup_release_contract() {
  local status="$?"
  if [[ -n "${ARTIFACT_IDENTITY}" && "${ARTIFACT_FINISHED}" == 0 ]]; then
    retain_release_contract_artifacts failure "${status}" || status=1
  fi
  rm -rf "${TMP_DIR}"
  trap - EXIT
  exit "${status}"
}
trap cleanup_release_contract EXIT
if [[ -n "${ARTIFACT_DIR}" ]]; then
  ARTIFACT_IDENTITY="$(retain_release_contract_artifacts init)"
fi

require_file_contains() {
  local file="$1"
  local expected="$2"
  if ! grep -Fq -- "${expected}" "${file}"; then
    echo "expected ${file} to contain: ${expected}" >&2
    echo "--- ${file} ---" >&2
    cat "${file}" >&2
    exit 1
  fi
}

reject_file_contains() {
  local file="$1"
  local unexpected="$2"
  if grep -Fq -- "${unexpected}" "${file}"; then
    echo "expected ${file} not to contain: ${unexpected}" >&2
    echo "--- ${file} ---" >&2
    cat "${file}" >&2
    exit 1
  fi
}

require_regular_file() {
  local path="$1"
  if [[ ! -f "${path}" ]]; then
    echo "expected file to exist: ${path}" >&2
    exit 1
  fi
}

require_directory() {
  local path="$1"
  if [[ ! -d "${path}" ]]; then
    echo "expected directory to exist: ${path}" >&2
    exit 1
  fi
}

# The fixture is installed only on the CI host. Portable release artifacts are
# independently built and ABI-gated on AlmaLinux 9 by release.yml.
# shellcheck source=scripts/lib/test-host-release-abi.sh
. "${ROOT}/scripts/lib/test-host-release-abi.sh"
aegis_test_use_host_release_abi "release-bundle contract"
"${ROOT}/scripts/build-release-bundle.sh" "${TMP_DIR}" >/dev/null
mkdir -p "${TMP_DIR}/home"

# shellcheck source=scripts/lib/host-arch.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/host-arch.sh"
ARCH="$(host_arch)"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "${ROOT}/aegis-server/Cargo.toml" | head -n 1)"
BUNDLE_DIR="${TMP_DIR}/aegis-${VERSION}-linux-${ARCH}"
ARCHIVE_PATH="${BUNDLE_DIR}.tar.gz"
ARCHIVE_SHA256_PATH="${ARCHIVE_PATH}.sha256"

require_directory "${BUNDLE_DIR}"
require_regular_file "${ARCHIVE_PATH}"
require_regular_file "${ARCHIVE_SHA256_PATH}"

BUNDLE_MANIFEST="${BUNDLE_DIR}/bundle.manifest.json"
require_file_contains "${BUNDLE_MANIFEST}" "\"bundle_name\": \"$(basename "${BUNDLE_DIR}")\""
require_file_contains "${BUNDLE_MANIFEST}" '"platform": "linux"'
require_file_contains "${BUNDLE_MANIFEST}" '"target_triple": "'
require_file_contains "${BUNDLE_MANIFEST}" '"git_sha": "'
require_file_contains "${BUNDLE_MANIFEST}" '"build_timestamp": "'
require_file_contains "${BUNDLE_MANIFEST}" '"schema": "aegis_release_bundle_manifest_v2"'
require_file_contains "${BUNDLE_MANIFEST}" '"cargo_lock_sha256": "'
require_file_contains "${BUNDLE_MANIFEST}" '"runtime_abi": {'
require_file_contains "${BUNDLE_MANIFEST}" '"generic_linux_min_glibc": "'
require_file_contains "${BUNDLE_MANIFEST}" '"binary_required_glibc": {'
require_file_contains "${BUNDLE_MANIFEST}" '"candidate --version before install-prefix mutation"'
require_file_contains "${BUNDLE_MANIFEST}" '"sha256": "'
require_file_contains "${BUNDLE_MANIFEST}" '"raw-socket"'
require_file_contains "${BUNDLE_MANIFEST}" '"chrome-like-tls"'
require_file_contains "${BUNDLE_MANIFEST}" '"chrome-like-quic"'
require_file_contains "${BUNDLE_MANIFEST}" '"bin/aegis-server"'
require_file_contains "${BUNDLE_MANIFEST}" '"bin/aegis-client"'
require_file_contains "${BUNDLE_MANIFEST}" '"packaging/systemd/aegis-server.service"'
require_file_contains "${BUNDLE_MANIFEST}" '"packaging/systemd/aegis-client.service"'
require_file_contains "${BUNDLE_MANIFEST}" '"scripts/bootstrap-wide-linux-validation-host.sh"'
require_file_contains "${BUNDLE_MANIFEST}" '"scripts/package-client-bundle.sh"'
require_file_contains "${BUNDLE_MANIFEST}" '"scripts/issue-fronted-bundle.sh"'
require_file_contains "${BUNDLE_MANIFEST}" '"scripts/aegis-origin-guard.sh"'
require_file_contains "${BUNDLE_MANIFEST}" '"scripts/aegis-wide-enable.sh"'
require_file_contains "${BUNDLE_MANIFEST}" '"scripts/aegis-wide-disable.sh"'
require_file_contains "${BUNDLE_MANIFEST}" '"scripts/aegis-wide-persist-install.sh"'
require_file_contains "${BUNDLE_MANIFEST}" '"scripts/janitor-wide-linux-tproxy.sh"'
require_file_contains "${BUNDLE_MANIFEST}" '"scripts/setup-wide-linux-redirect.sh"'
require_file_contains "${BUNDLE_MANIFEST}" '"scripts/validate-debian-package-host.sh"'
require_file_contains "${BUNDLE_MANIFEST}" '"scripts/build-ubuntu-field-pilot-remote-bundle.sh"'
require_file_contains "${BUNDLE_MANIFEST}" '"scripts/build-post-release-stealth-wave-summary.sh"'
require_file_contains "${BUNDLE_MANIFEST}" '"scripts/build-ubuntu-mimicry-next-contour.sh"'
require_file_contains "${BUNDLE_MANIFEST}" '"scripts/setup-wide-linux-tproxy.sh"'
require_file_contains "${BUNDLE_MANIFEST}" '"SHA256SUMS"'
require_regular_file "${BUNDLE_DIR}/docs/operations/https-bridge.md"
cmp "${ROOT}/docs/operations/https-bridge.md" "${BUNDLE_DIR}/docs/operations/https-bridge.md"
require_file_contains "${BUNDLE_MANIFEST}" '"docs/operations/https-bridge.md"'
require_file_contains "${BUNDLE_DIR}/SHA256SUMS" ' docs/operations/https-bridge.md'
for guide in carrier-program.md web-response-carrier.md webrtc-native.md traffic-privacy.md; do
  require_regular_file "${BUNDLE_DIR}/docs/operations/${guide}"
  cmp "${ROOT}/docs/operations/${guide}" "${BUNDLE_DIR}/docs/operations/${guide}"
  require_file_contains "${BUNDLE_MANIFEST}" "\"docs/operations/${guide}\""
  guide_sha="$(shasum -a 256 "${ROOT}/docs/operations/${guide}" | awk '{print $1}')"
  require_file_contains "${BUNDLE_DIR}/SHA256SUMS" "${guide_sha}  docs/operations/${guide}"
done

expected_archive_sha="$(shasum -a 256 "${ARCHIVE_PATH}" | awk '{print $1}')"
stored_archive_sha="$(awk '{print $1; exit}' "${ARCHIVE_SHA256_PATH}")"
if [[ "${expected_archive_sha}" != "${stored_archive_sha}" ]]; then
  echo "archive checksum mismatch" >&2
  exit 1
fi

require_file_contains "${BUNDLE_DIR}/SHA256SUMS" " install.sh"
require_file_contains "${BUNDLE_DIR}/SHA256SUMS" " bin/aegis-server"
require_file_contains "${BUNDLE_DIR}/SHA256SUMS" " bin/aegis-client"
require_file_contains "${BUNDLE_DIR}/SHA256SUMS" " Cargo.lock"

# Any post-build payload drift must block installation before files are copied.
cp "${BUNDLE_DIR}/bin/aegis-client" "${TMP_DIR}/aegis-client.pristine"
printf '\ncorruption\n' >> "${BUNDLE_DIR}/bin/aegis-client"
if HOME="${TMP_DIR}/home" PATH="${INSTALL_FIXTURE_PATH}" \
  AEGIS_INSTALL_TEST_OS_KIND=linux AEGIS_INSTALL_NONINTERACTIVE=1 \
  "${BUNDLE_DIR}/install.sh" client --prefix "${TMP_DIR}/must-not-install" \
  --config-dir "${TMP_DIR}/must-not-configure" --state-dir "${TMP_DIR}/must-not-state" \
  --bundle "${TMP_DIR}/server/client-bundle" --profile socks-only --force \
  >/dev/null 2>"${TMP_DIR}/tampered-bundle.stderr"; then
  echo "tampered release bundle unexpectedly passed provenance verification" >&2
  exit 1
fi
require_file_contains "${TMP_DIR}/tampered-bundle.stderr" \
  "computed checksum did NOT match"
cp "${TMP_DIR}/aegis-client.pristine" "${BUNDLE_DIR}/bin/aegis-client"

# A provenance-valid but host-incompatible candidate must be rejected before
# the installer creates or overwrites the destination binary. This models an
# ELF loader/glibc failure without depending on the CI host's actual libc.
ABI_MISMATCH_DIR="${TMP_DIR}/abi-mismatch-bundle"
cp -R "${BUNDLE_DIR}" "${ABI_MISMATCH_DIR}"
ABI_CLIENT_BUNDLE="${TMP_DIR}/abi-client-bundle"
mkdir -p "${ABI_CLIENT_BUNDLE}"
printf '%s\n' 'contract-client-config' > "${ABI_CLIENT_BUNDLE}/aegis-client.toml"
printf '%s\n' 'contract-client-ca' > "${ABI_CLIENT_BUNDLE}/ca.pem"
cat > "${ABI_MISMATCH_DIR}/bin/aegis-client" <<'EOF'
#!/usr/bin/env sh
echo 'simulated loader: GLIBC baseline unavailable' >&2
exit 42
EOF
chmod 0755 "${ABI_MISMATCH_DIR}/bin/aegis-client"
abi_mismatch_sha="$(shasum -a 256 "${ABI_MISMATCH_DIR}/bin/aegis-client" | awk '{print $1}')"
python3 - "${ABI_MISMATCH_DIR}" "${abi_mismatch_sha}" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
digest = sys.argv[2]
manifest_path = root / "bundle.manifest.json"
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
manifest["binaries"]["aegis-client"]["sha256"] = digest
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

sums_path = root / "SHA256SUMS"
lines = sums_path.read_text(encoding="utf-8").splitlines()
lines = [
    f"{digest}  bin/aegis-client" if line.endswith("  bin/aegis-client") else line
    for line in lines
]
sums_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
# Bundle preflight intentionally runs before binary ABI preflight. Keep this
# fixture valid so the case reaches the incompatible candidate rather than
# correctly stopping at a missing client bundle.
if HOME="${TMP_DIR}/home" PATH="${INSTALL_FIXTURE_PATH}" \
  AEGIS_INSTALL_TEST_OS_KIND=linux AEGIS_INSTALL_NONINTERACTIVE=1 \
  "${ABI_MISMATCH_DIR}/install.sh" client \
  --prefix "${TMP_DIR}/abi-must-not-install" \
  --config-dir "${TMP_DIR}/abi-must-not-configure" \
  --state-dir "${TMP_DIR}/abi-must-not-state" \
  --bundle "${ABI_CLIENT_BUNDLE}" --profile socks-only --force \
  >"${TMP_DIR}/abi-mismatch.stdout" 2>"${TMP_DIR}/abi-mismatch.stderr"; then
  echo "runtime-incompatible release binary unexpectedly installed" >&2
  exit 1
fi
require_file_contains "${TMP_DIR}/abi-mismatch.stderr" \
  "Prebuilt aegis-client is not executable on this host"
if [[ -e "${TMP_DIR}/abi-must-not-install/bin/aegis-client" ]]; then
  echo "runtime-incompatible binary mutated the install prefix" >&2
  exit 1
fi

require_file_contains "${BUNDLE_DIR}/SHA256SUMS" " scripts/bootstrap-wide-linux-validation-host.sh"
require_file_contains "${BUNDLE_DIR}/SHA256SUMS" " scripts/aegis-wide-enable.sh"
require_file_contains "${BUNDLE_DIR}/SHA256SUMS" " scripts/aegis-wide-disable.sh"
require_file_contains "${BUNDLE_DIR}/SHA256SUMS" " scripts/aegis-wide-persist-install.sh"
require_file_contains "${BUNDLE_DIR}/SHA256SUMS" " scripts/janitor-wide-linux-tproxy.sh"
require_file_contains "${BUNDLE_DIR}/SHA256SUMS" " scripts/setup-wide-linux-redirect.sh"
require_file_contains "${BUNDLE_DIR}/SHA256SUMS" " scripts/validate-debian-package-host.sh"

HOME="${TMP_DIR}/home" PATH="${INSTALL_FIXTURE_PATH}" \
AEGIS_INSTALL_TEST_OS_KIND=linux \
AEGIS_INSTALL_NONINTERACTIVE=1 \
"${BUNDLE_DIR}/install.sh" server \
  --prefix "${TMP_DIR}/prefix" \
  --config-dir "${TMP_DIR}/server" \
  --state-dir "${TMP_DIR}/server-state" \
  --systemd-dir "${TMP_DIR}/systemd" \
  --env-dir "${TMP_DIR}/env" \
  --relay-address "relay.example.org:8443" \
  --server-name "relay.example.org" \
  --no-auto-token \
  --force >/dev/null

HOME="${TMP_DIR}/home" PATH="${INSTALL_FIXTURE_PATH}" \
AEGIS_INSTALL_TEST_OS_KIND=linux \
AEGIS_INSTALL_NONINTERACTIVE=1 \
"${BUNDLE_DIR}/install.sh" client \
  --prefix "${TMP_DIR}/prefix" \
  --config-dir "${TMP_DIR}/client" \
  --state-dir "${TMP_DIR}/client-state" \
  --log-dir "${TMP_DIR}/client-log" \
  --systemd-dir "${TMP_DIR}/systemd" \
  --env-dir "${TMP_DIR}/env" \
  --bundle "${TMP_DIR}/server/client-bundle" \
  --profile socks-only \
  --force >/dev/null

# Verify that the rendered units are concrete install artifacts and not templates
# with unresolved placeholders.
reject_file_contains "${TMP_DIR}/systemd/aegis-server.service" "__AEGIS_"
reject_file_contains "${TMP_DIR}/systemd/aegis-client.service" "__AEGIS_"
reject_file_contains "${TMP_DIR}/client/aegis.toml" "__CLIENT_CA_CERT_PATH__"
reject_file_contains "${TMP_DIR}/client/aegis-privileged-dns.toml.example" "__CLIENT_CA_CERT_PATH__"
require_file_contains "${TMP_DIR}/systemd/aegis-server.service" "ExecStart="
require_file_contains "${TMP_DIR}/systemd/aegis-client.service" "ExecStart="
require_file_contains "${TMP_DIR}/systemd/aegis-client.service" "runtime-events.jsonl"
require_file_contains "${TMP_DIR}/client/aegis.toml" 'capture_dns = false'
require_file_contains "${TMP_DIR}/client/aegis-privileged-dns.toml.example" 'platform_backend = "linux_tproxy"'
require_file_contains "${TMP_DIR}/client/aegis-privileged-dns.toml.example" 'rollout_profile = "transparent_privileged"'
require_file_contains "${TMP_DIR}/client/aegis-privileged-dns.toml.example" 'capture_dns = true'
require_regular_file "${TMP_DIR}/prefix/lib/aegis/helpers/setup-wide-linux-redirect.sh"
require_regular_file "${TMP_DIR}/prefix/lib/aegis/helpers/lib/root-state.sh"
require_regular_file "${TMP_DIR}/prefix/lib/aegis/helpers/setup-wide-linux-tproxy.sh"
require_regular_file "${TMP_DIR}/prefix/lib/aegis/helpers/purge-installed-aegis.sh"
require_regular_file "${TMP_DIR}/prefix/lib/aegis/helpers/aegis-ubuntu-uninstall.sh"
bash "${TMP_DIR}/prefix/lib/aegis/helpers/aegis-ubuntu-uninstall.sh" --help >/dev/null
bash "${TMP_DIR}/prefix/lib/aegis/helpers/aegis-wide-disable.sh" --help >/dev/null

SERVER_INSTALL_MANIFEST="${TMP_DIR}/server-state/install-manifest.json"
CLIENT_INSTALL_MANIFEST="${TMP_DIR}/client-state/install-manifest.json"
if [[ ${EUID} -eq 0 ]]; then
  SERVER_INSTALL_MANIFEST="${TMP_DIR}/server-state.install-metadata/install-manifest.json"
  CLIENT_INSTALL_MANIFEST="${TMP_DIR}/client-state.install-metadata/install-manifest.json"
  # Exercise the production custody boundary, including an actual service UID.
  python3 - "${TMP_DIR}" <<'PY'
import os, pwd, stat, sys
from pathlib import Path
root = Path(sys.argv[1])
for role in ("server", "client"):
    state = root / f"{role}-state"
    metadata = root / f"{role}-state.install-metadata"
    assert not (state / "install-manifest.json").exists()
    for path in (metadata, metadata / "install-manifest.json"):
        info = path.lstat()
        assert info.st_uid == 0 and not info.st_mode & 0o022
    assert stat.S_ISDIR(metadata.lstat().st_mode)
    receipt = (metadata / "install-manifest.json").lstat()
    assert stat.S_ISREG(receipt.st_mode) and receipt.st_nlink == 1
assert (root / "server-state").stat().st_uid == pwd.getpwnam("aegis").pw_uid != 0
PY
fi
require_file_contains "${SERVER_INSTALL_MANIFEST}" '"schema": "aegis_install_manifest_v1"'
require_file_contains "${SERVER_INSTALL_MANIFEST}" '"role": "server"'
require_file_contains "${SERVER_INSTALL_MANIFEST}" '/aegis-server"'
require_file_contains "${SERVER_INSTALL_MANIFEST}" '"binary_sha256": "'
require_file_contains "${SERVER_INSTALL_MANIFEST}" '"binary_version": "aegis-server'
require_file_contains "${CLIENT_INSTALL_MANIFEST}" '"schema": "aegis_install_manifest_v1"'
require_file_contains "${CLIENT_INSTALL_MANIFEST}" '"role": "client"'
require_file_contains "${CLIENT_INSTALL_MANIFEST}" '/aegis-client"'
require_file_contains "${CLIENT_INSTALL_MANIFEST}" '"binary_sha256": "'
require_file_contains "${CLIENT_INSTALL_MANIFEST}" '"binary_version": "aegis-client'

if command -v systemd-analyze >/dev/null 2>&1; then
  # Verify the rendered units with the host systemd parser when available so the
  # service layer is checked as real unit syntax, not just as plain text files.
  systemd-analyze verify \
    "${TMP_DIR}/systemd/aegis-server.service" \
    "${TMP_DIR}/systemd/aegis-client.service" >/dev/null
fi

# Exercise the actual installer with the minimal client inventory, including a
# reapply over the existing client and preservation of the colocated server.
cargo run --locked -q -p aegis-measure -- build-public-client-delivery \
  --root "${ROOT}" --operator-bundle "${BUNDLE_DIR}" --output-dir "${TMP_DIR}" \
  --channel rc --prerelease true
PUBLIC_CLIENT="${TMP_DIR}/aegis-client-${VERSION}-linux-${ARCH}"
[[ ! -e "${PUBLIC_CLIENT}/bin/aegis-server" && ! -e "${PUBLIC_CLIENT}/Cargo.lock" ]]
[[ ! -e "${PUBLIC_CLIENT}/scripts/generate-relay-materials.sh" ]]
server_before="$(shasum -a 256 "${TMP_DIR}/prefix/bin/aegis-server")"
HOME="${TMP_DIR}/home" PATH="${INSTALL_FIXTURE_PATH}" \
AEGIS_INSTALL_TEST_OS_KIND=linux AEGIS_INSTALL_NONINTERACTIVE=1 \
"${PUBLIC_CLIENT}/install.sh" client \
  --prefix "${TMP_DIR}/prefix" --config-dir "${TMP_DIR}/client" \
  --state-dir "${TMP_DIR}/client-state" --log-dir "${TMP_DIR}/client-log" \
  --systemd-dir "${TMP_DIR}/systemd" --env-dir "${TMP_DIR}/env" \
  --bundle "${TMP_DIR}/server/client-bundle" --profile socks-only --force >/dev/null
[[ "$(shasum -a 256 "${TMP_DIR}/prefix/bin/aegis-server")" == "${server_before}" ]]
require_file_contains "${CLIENT_INSTALL_MANIFEST}" '"role": "client"'
require_regular_file "${TMP_DIR}/prefix/lib/aegis/helpers/purge-installed-aegis.sh"
if AEGIS_INSTALL_TEST_OS_KIND=linux AEGIS_INSTALL_NONINTERACTIVE=1 \
  "${PUBLIC_CLIENT}/install.sh" server --prefix "${TMP_DIR}/public-must-not-install-server" --force >/dev/null 2>&1; then
  echo "public client release accepted server role" >&2
  exit 1
fi
[[ ! -e "${TMP_DIR}/public-must-not-install-server/bin/aegis-server" ]]

if [[ -n "${ARTIFACT_IDENTITY}" ]]; then
  ARTIFACT_FINISHED=1
  retain_release_contract_artifacts success
fi
echo "PASS: operator and minimal public client release bundle contracts"
