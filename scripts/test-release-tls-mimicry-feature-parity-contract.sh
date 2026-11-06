#!/usr/bin/env bash
# Every build path that produces a binary an operator actually runs must compile
# the Chrome-class TLS ClientHello in.
#
# Why this contract exists: `relay.tls_backend` defaults to
# `chrome_like_experimental`, but a build without the `chrome-like-tls` feature
# degrades to the rustls ClientHello at connect time. The degrade was a single
# `warn!` line, so a release path that forgot the feature shipped the headline
# anti-DPI capability switched off while the config, the docs and the runtime
# events all still said "chrome_like_experimental". That is exactly what
# happened to the macOS tarball (scripts/build-macos-client-tarball.sh built
# plain `--release -p aegis-client` while the Linux bundle and the Debian
# package both passed the feature).
#
# The check is textual on purpose: it has to hold on a machine that cannot run
# a macOS build, and it has to fail when someone adds a *new* release path.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# Build paths that produce an operator-facing aegis-client binary.
RELEASE_BUILDERS=(
  "scripts/build-release-bundle.sh"
  "scripts/build-package-root.sh"
  "scripts/build-macos-client-tarball.sh"
)

for builder in "${RELEASE_BUILDERS[@]}"; do
  [[ -f "${builder}" ]] || fail "release builder missing: ${builder}"

  # The aegis-client build line in this script.
  client_build="$(grep -n 'build .*-p aegis-client' "${builder}" || true)"
  [[ -n "${client_build}" ]] || fail "${builder}: no aegis-client build line found"

  # Line continuations are common here, so match against the whole file with
  # newlines folded away rather than a single grep line.
  folded="$(tr '\n' ' ' < "${builder}")"

  case "${folded}" in
    *"chrome-like-tls"*) ;;
    *) fail "${builder}: builds aegis-client without the chrome-like-tls feature.
   The binary would silently fall back to the rustls ClientHello, which is
   trivially distinguishable from a browser. Add
   --features chrome-like-tls to the release build." ;;
  esac

  # Without raw-socket, RawCapabilities reports ipv4_raw_send=false however
  # privileged the process is, and the direct planner filters out EVERY
  # packet-shaping strategy — geneva, ttl_desync, overlap, the lot — leaving
  # only passthrough. The session then dies with "no strategy" and the config
  # still says geneva is selected. Measured on the fleet: tcp_repair_query was
  # true (so CAP_NET_ADMIN was present) while ipv4_raw_send was false, which is
  # the signature of the feature being compiled out rather than a permissions
  # problem.
  case "${folded}" in
    *"raw-socket"*) ;;
    *) fail "${builder}: builds aegis-client without the raw-socket feature.
   Every packet-manipulating direct strategy would be filtered at plan time and
   the session would fail with \"no strategy\". Add --features raw-socket." ;;
  esac

  case "${folded}" in
    *"chrome-like-quic"*) ;;
    *) fail "${builder}: builds aegis-client without the chrome-like-quic feature.
   MASQUE would keep the rustls QUIC ClientHello. Add
   --features chrome-like-quic to the release build." ;;
  esac
done

# The operator bundle and native package root must use the same explicit
# client target. An implicit host build creates a different executable even
# when its feature list and source are identical, and release delivery must
# reject that drift. Keep the server build path independent.
python3 - <<'PY_TARGET_PARITY'
from pathlib import Path
import re

for name in ("build-release-bundle.sh", "build-package-root.sh"):
    source = (Path("scripts") / name).read_text()
    folded = source.replace("\\\n", " ")
    assert re.search(
        r'cargo build --locked --release -p aegis-client --features '
        r'raw-socket,chrome-like-tls,chrome-like-quic\s+'
        r'--target "\$\{TARGET_TRIPLE\}"',
        folded,
    ), f"{name}: client build must select TARGET_TRIPLE explicitly"
    assert source.count('"${TARGET_DIR}/${TARGET_TRIPLE}/release/aegis-client"') >= 2, (
        f"{name}: ABI verification and package copy must use the selected client target"
    )

# ARM64 workflows inspect the same explicit-target client that the bundle and
# package-root producers stage; the server remains in the host target path.
for name in ("ci.yml", "release.yml"):
    source = (Path(".github/workflows") / name).read_text()
    assert source.count("./target/aarch64-unknown-linux-gnu/release/aegis-client") == 3, (
        f"{name}: ARM64 file/version probes must use the selected client target"
    )
    assert "./target/release/aegis-client" not in source, (
        f"{name}: stale implicit-target client probe"
    )
PY_TARGET_PARITY

# Host-only contract fixtures may accept the current runner ABI, but no
# production builder may weaken the generic Linux GLIBC_2.34 ceiling.
grep -Fq 'AEGIS_RELEASE_MAX_GLIBC="${AEGIS_RELEASE_MAX_GLIBC:-2.34}"' \
  scripts/lib/release-abi.sh \
  || fail "generic Linux release ABI ceiling is no longer GLIBC_2.34"
for builder in \
  scripts/build-release-bundle.sh \
  scripts/build-release-delivery.sh \
  scripts/build-package-root.sh \
  scripts/build-deb-package.sh \
  scripts/build-split-deb-packages.sh \
  scripts/build-rpm-packages.sh; do
  if grep -Fq 'test-host-release-abi.sh' "${builder}"; then
    fail "${builder}: production builder imports the test-only host ABI helper"
  fi
done

# A repo/source install is also an operator-facing build path. It must not
# install a binary that silently degrades the configured Chrome-class backend.
source_installer_folded="$(tr '\n' ' ' < install.sh)"
for feature in raw-socket chrome-like-tls chrome-like-quic; do
  case "${source_installer_folded}" in
    *"--features raw-socket,chrome-like-tls,chrome-like-quic"*) ;;
    *) fail "install.sh source build omits ${feature}" ;;
  esac
done

# The feature has a native build dependency (aws-lc-sys needs cmake). A release
# script that enables the feature but does not check for cmake fails late and
# confusingly on a fresh runner.
for builder in "${RELEASE_BUILDERS[@]}"; do
  grep -q 'cmake' "${builder}" \
    || fail "${builder}: enables chrome-like-tls (aws-lc-sys) but never checks for cmake"
done

# The degrade must remain observable. If someone removes the effective-backend
# reporting, a future build regression becomes invisible again.
grep -q 'relay_tls_backend_effective' aegis-client/src/relay/events.rs \
  || fail "relay events no longer publish relay_tls_backend_effective"
grep -q 'relay_tls_backend_degraded' aegis-client/src/relay/events.rs \
  || fail "relay events no longer publish relay_tls_backend_degraded"

echo "release tls mimicry feature parity contract: ok"
