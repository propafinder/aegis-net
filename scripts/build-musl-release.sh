#!/usr/bin/env bash
# Static musl build — the only binary that runs on Alpine.
#
# The glibc release binaries are dynamically linked against
# /lib64/ld-linux-x86-64.so.2, which Alpine does not have. Proven, not assumed:
# inside an Alpine 3.21 minirootfs the glibc binary fails with
# "No such file or directory" (the missing interpreter, not the missing file)
# while this build reports its version normally.
# See evidence-archive/live/2026-08-11/alpine-musl-support.
#
# aws-lc-sys needs a real musl C toolchain — the Rust target alone is not
# enough, and AlmaLinux base repos carry no musl-gcc. Install the cross
# toolchain first:
#
#   curl -O https://musl.cc/x86_64-linux-musl-cross.tgz
#   tar xzf x86_64-linux-musl-cross.tgz -C /opt
#
# Usage: build-musl-release.sh [output-dir]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-${ROOT}/dist/musl}"
TOOLCHAIN="${AEGIS_MUSL_TOOLCHAIN:-/opt/x86_64-linux-musl-cross/bin}"
TARGET=x86_64-unknown-linux-musl

if [[ ! -x "${TOOLCHAIN}/x86_64-linux-musl-gcc" ]]; then
  echo "musl cross toolchain not found at ${TOOLCHAIN}" >&2
  echo "Install it (see the header of this script) or set AEGIS_MUSL_TOOLCHAIN." >&2
  exit 1
fi

export PATH="${TOOLCHAIN}:${PATH}"
export CC_x86_64_unknown_linux_musl=x86_64-linux-musl-gcc
export CXX_x86_64_unknown_linux_musl=x86_64-linux-musl-g++
export AR_x86_64_unknown_linux_musl=x86_64-linux-musl-ar
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-musl-gcc

rustup target add "${TARGET}" >/dev/null 2>&1 || true

cd "${ROOT}"
cargo build --release -p aegis-server --target "${TARGET}"
# The client carries the Chrome-class mimicry, same as every other release
# path. This script used to build it bare, on the reasoning that chrome-like-tls
# under musl was untested — but it still published the result, so the Alpine
# tarball shipped a client with the distinguishable rustls ClientHello while
# looking supported. That is the macOS-tarball failure repeated.
#
# aws-lc-sys does cross-compile against the musl toolchain, and the resulting
# client's canonical JA4 is t13d1516h2_8daaf6152771_806a8c22fdea — byte-identical
# to the glibc client and to live Chrome 151, measured on the wire against a real
# relay: evidence-archive/live/2026-08-11/musl-client-ja4-parity.
cargo build --release -p aegis-client --target "${TARGET}" \
  --features chrome-like-tls,chrome-like-quic,raw-socket

mkdir -p "${OUT}"
for bin in aegis-server aegis-client; do
  src="${ROOT}/target/${TARGET}/release/${bin}"
  [[ -x "${src}" ]] || { echo "missing ${src}" >&2; exit 1; }
  # Static or it does not belong here: a musl build that still needs an
  # interpreter defeats the point.
  #
  # `file` says "statically linked" for a classic static ELF and
  # "static-pie linked" for a static position-independent one. Rust's musl
  # target produces the latter by default on this toolchain, so matching only
  # the first string rejected a perfectly good binary and made the Alpine build
  # look broken. Accept both, and keep rejecting anything with an interpreter.
  if ! file "${src}" | grep -qE "statically linked|static-pie linked"; then
    echo "${bin} is not statically linked; refusing to publish it as the Alpine build" >&2
    exit 1
  fi
  install -m 0755 "${src}" "${OUT}/${bin}"
done

echo "musl binaries in ${OUT}:"
(cd "${OUT}" && sha256sum aegis-server aegis-client)
