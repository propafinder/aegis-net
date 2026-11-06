#!/usr/bin/env bash
# Phase 5.0.A contract: the rendered client bundle must advertise the
# same port the server is actually listening on. Specifically, when
# `install.sh server` is run with an explicit `--listen 0.0.0.0:N`
# (and no explicit `--relay-address`), the bundle's `[relay] server`
# entry must end with `:N`, not the historical hardcoded `:8443`.
#
# This test does NOT run a full install — it loads install.sh as a
# library (via `set -n` + `source`-style guard), exercises
# `choose_bundle_relay_endpoint` directly with the new `default_relay_port`
# argument, and asserts every emitted endpoint ends with the supplied
# port.
#
# Runs offline. No network, no systemd, no cargo build.

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Source install.sh helpers without executing the main install flow. The
# script's body is gated by `main "$@"` at the bottom, so a non-`main`
# entry point + `INSTALL_SH_TEST_HARNESS=1` skips the dispatch.
INSTALL_SH_TEST_HARNESS=1
# install.sh exits hard on `main` argument mismatches; running it with
# no args + the harness flag short-circuits before any side effect.
# We extract only the helper definitions by using bash -c with a
# constrained scope.

extracted_helpers="$(mktemp -d)"/install-helpers.sh
trap 'rm -rf "$(dirname "${extracted_helpers}")"' EXIT
# install.sh doesn't have a `main "$@"` wrapper — the role dispatch is
# inline at the bottom. Extract only the function definitions for the
# helpers this test exercises, by grepping the file for the matching
# function bodies. This keeps the harness side-effect-free even though
# install.sh would otherwise run its top-level argparse + dispatch.
awk '
  /^choose_bundle_relay_endpoint\(\) \{/ ||
  /^host_has_nonlocal_resolution\(\) \{/ ||
  /^detected_relay_ip_fallback\(\) \{/ ||
  /^host_is_local_only\(\) \{/ ||
  /^host_from_address\(\) \{/ ||
  /^port_from_address\(\) \{/ {
    in_fn = 1; brace = 0
  }
  in_fn {
    print
    n = gsub(/\{/, "{")
    brace += n
    n = gsub(/\}/, "}")
    brace -= n
    if (brace == 0 && /^\}/) { in_fn = 0 }
  }
' "${ROOT}/install.sh" > "${extracted_helpers}"
# shellcheck disable=SC1090
. "${extracted_helpers}"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# Stub `host_has_nonlocal_resolution` so we exercise both branches without
# real DNS lookups. The first invocation per test sets the answer.
host_has_nonlocal_resolution() { return "${HOST_HAS_NONLOCAL:-1}"; }
detected_relay_ip_fallback() { printf '%s\n' "${FALLBACK_IP:-203.0.113.10}"; }
host_is_local_only() { return "${HOST_IS_LOCAL:-1}"; }

# Case 1: explicit DNS path takes :443 when listen was 0.0.0.0:443.
HOST_HAS_NONLOCAL=0 \
  output_443="$(choose_bundle_relay_endpoint "relay.example.org" "relay.example.org" "443")"
endpoint_443="$(printf '%s\n' "${output_443}" | sed -n '1p')"
[[ "${endpoint_443}" == "relay.example.org:443" ]] \
  || fail "explicit-dns path expected relay.example.org:443, got '${endpoint_443}'"

# Case 2: fallback-IP path with explicit server name + :443.
HOST_HAS_NONLOCAL=1 FALLBACK_IP=192.0.2.55 \
  output_fbi="$(choose_bundle_relay_endpoint "" "relay.example.org" "443")"
endpoint_fbi="$(printf '%s\n' "${output_fbi}" | sed -n '1p')"
[[ "${endpoint_fbi}" == "192.0.2.55:443" ]] \
  || fail "fallback-ip explicit-name path expected 192.0.2.55:443, got '${endpoint_fbi}'"

# Case 3: fallback-IP path with non-local DNS candidate + :443.
HOST_HAS_NONLOCAL=1 FALLBACK_IP=192.0.2.66 HOST_IS_LOCAL=1 \
  output_dns="$(choose_bundle_relay_endpoint "edge.example.org" "" "443")"
endpoint_dns="$(printf '%s\n' "${output_dns}" | sed -n '1p')"
[[ "${endpoint_dns}" == "192.0.2.66:443" ]] \
  || fail "fallback-ip dns-fallback path expected 192.0.2.66:443, got '${endpoint_dns}'"

# Case 4: bare-fallback path (no DNS, no explicit name) + :443.
HOST_HAS_NONLOCAL=1 FALLBACK_IP=192.0.2.77 HOST_IS_LOCAL=0 \
  output_bare="$(choose_bundle_relay_endpoint "" "" "443")"
endpoint_bare="$(printf '%s\n' "${output_bare}" | sed -n '1p')"
[[ "${endpoint_bare}" == "192.0.2.77:443" ]] \
  || fail "bare fallback path expected 192.0.2.77:443, got '${endpoint_bare}'"

# Case 5: regression — when no port is supplied, the historical :8443
# default still applies (backwards-compatible).
HOST_HAS_NONLOCAL=0 \
  output_default="$(choose_bundle_relay_endpoint "relay.example.org" "relay.example.org")"
endpoint_default="$(printf '%s\n' "${output_default}" | sed -n '1p')"
[[ "${endpoint_default}" == "relay.example.org:8443" ]] \
  || fail "no-port-argument backwards-compat expected :8443, got '${endpoint_default}'"

# Case 6: custom port other than 443/8443 (e.g. :9443) also flows through.
HOST_HAS_NONLOCAL=0 \
  output_9443="$(choose_bundle_relay_endpoint "relay.example.org" "" "9443")"
endpoint_9443="$(printf '%s\n' "${output_9443}" | sed -n '1p')"
[[ "${endpoint_9443}" == "relay.example.org:9443" ]] \
  || fail "custom-port path expected relay.example.org:9443, got '${endpoint_9443}'"

echo "ok: bundle relay port coherence (6 cases, ports 443/8443/9443)"
