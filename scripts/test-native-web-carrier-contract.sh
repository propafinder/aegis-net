#!/usr/bin/env bash
# Local synthetic cross-binary acceptance. Does not contact the deployed fleet.
set -euo pipefail
repo="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repo"
mode="${1:-web}"
case "$mode" in
  web) cargo build --locked --offline -p aegis-client --bin aegis-client -p aegis-server --bin aegis-server ;;
  webrtc) cargo build --locked --offline -p aegis-client --bin aegis-client -p aegis-server --bin aegis-server --features aegis-client/webrtc-carrier,aegis-server/webrtc-carrier ;;
  *) echo "expected web or webrtc acceptance mode" >&2; exit 2 ;;
esac
client_dir="${CARGO_TARGET_DIR:-$repo/target}"
if [[ "$client_dir" != /* ]]; then client_dir="$repo/$client_dir"; fi
export AEGIS_NATIVE_CLIENT_BIN="$client_dir/debug/aegis-client"
if [[ "$mode" == webrtc ]]; then
  cargo test --locked --offline -p aegis-server --features webrtc-carrier --test opaque_carrier_auth native_webrtc_socks5_verified_broker_device_and_cancellation_acceptance -- --ignored --nocapture --test-threads=1
else
  cargo test --locked --offline -p aegis-server --test opaque_carrier_auth native_web_carrier_socks5_device_and_egress_acceptance -- --ignored --nocapture --test-threads=1
fi
