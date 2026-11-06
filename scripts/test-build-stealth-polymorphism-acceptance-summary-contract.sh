#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/build-stealth-polymorphism-acceptance-summary.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-stealth-acceptance.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

bash "${SCRIPT}" "${TMP_DIR}/out" --config "${ROOT}/config.example.toml" >/dev/null

OUTPUT_JSON="${TMP_DIR}/out/stealth-polymorphism-acceptance-summary.json"
OUTPUT_MD="${TMP_DIR}/out/stealth-polymorphism-acceptance-summary.md"

jq -e '
  .artifact_schema == "stealth_polymorphism_acceptance_summary_v1"
  and .verdict == "green"
  and .status == "acceptance_green"
  and .checks.direct_window_stability == true
  and .checks.direct_catalog_coverage == true
  and .checks.relay_catalog_and_path_coverage == true
  and .checks.cross_layer_independence == true
  and .direct.catalog_ids_expected == [
    "browser_split_balanced",
    "browser_split_wide",
    "mobile_compact",
    "cli_conservative",
    "browser_fragment_dense",
    "mobile_burst_fragmented",
    "desktop_latency_smoothed",
    "edge_middlebox_evasive"
  ]
  and .relay.profile_ids_expected == [
    "browser_like_balanced",
    "browser_like_chatty",
    "cli_https_compact",
    "mobile_safari_tight",
    "desktop_chrome_streaming",
    "enterprise_java_client",
    "mobile_wifi",
    "mobile_4g",
    "desktop_electron",
    "realtime_websocket",
    "grpc_api",
    "noisy_cafe",
    "congested_hotel",
    "corp_middlebox",
    "iot_telemetry",
    "video_stream_h264",
    "api_batch_poller",
    "tablet_safari"
  ]
  and .relay.websocket_paths_seen == [
    "/aegis/ws",
    "/realtime/connect",
    "/socket",
    "/ws"
  ]
  and .relay.grpc_paths_seen == [
    "/aegis.tunnel.v1.TunnelService/Open",
    "/cdn.tunnel.v1.Session/Open",
    "/grpc.gateway.v1.Proxy/Connect",
    "/rpc.Tunnel/Open"
  ]
  and .relay.masque_paths_seen == [
    "/.well-known/masque/connect-udp",
    "/.well-known/masque/udp",
    "/masque/v1/udp",
    "/relay/datagram"
  ]
  and .relay.accept_language_variants_seen == [
    "<none>",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.8",
    "en-US,en;q=0.9",
    "en-US,en;q=0.9,*;q=0.5"
  ]
  and .relay.cache_control_variants_seen == [
    "<none>",
    "max-age=0",
    "max-age=300",
    "no-cache",
    "no-store"
  ]
  and .relay.websocket_origin_variants_seen == [
    "<none>",
    "https://localhost"
  ]
  and .relay.grpc_accept_encoding_variants_seen == [
    "<none>",
    "gzip",
    "gzip, deflate",
    "gzip, identity",
    "identity"
  ]
  and .relay.grpc_encoding_variants_seen == [
    "<none>",
    "gzip",
    "identity"
  ]
  and .relay.grpc_timeout_variants_seen == [
    "10S",
    "12S",
    "15S",
    "20S",
    "25S",
    "30S",
    "60S",
    "<none>"
  ]
  and .relay.grpc_message_type_variants_seen == [
    "<none>",
    "SessionOpenRequest",
    "TunnelRequest"
  ]
  and .relay.masque_alt_used_variants_seen == [
    "<none>",
    "localhost"
  ]
  and .cross_layer.direct_to_relay_min_profiles >= 2
  and .cross_layer.relay_to_direct_min_families >= 2
' "${OUTPUT_JSON}" >/dev/null

grep -Fq -- "Stealth Polymorphism Acceptance" "${OUTPUT_MD}"
grep -Fq -- "- Verdict: \`green\`" "${OUTPUT_MD}"
grep -Fq -- "- \`cross_layer_independence\`: \`true\`" "${OUTPUT_MD}"
grep -Fq -- "- Expected profile ids: \`browser_like_balanced, browser_like_chatty, cli_https_compact, mobile_safari_tight, desktop_chrome_streaming, enterprise_java_client, mobile_wifi, mobile_4g, desktop_electron, realtime_websocket, grpc_api, noisy_cafe, congested_hotel, corp_middlebox, iot_telemetry, video_stream_h264, api_batch_poller, tablet_safari\`" "${OUTPUT_MD}"
grep -Fq -- "- Accept-Language variants: \`<none>, en-GB,en;q=0.9, en-US,en;q=0.8, en-US,en;q=0.9, en-US,en;q=0.9,*;q=0.5\`" "${OUTPUT_MD}"
grep -Fq -- "- WebSocket paths: \`/aegis/ws, /realtime/connect, /socket, /ws\`" "${OUTPUT_MD}"
grep -Fq -- "- gRPC paths: \`/aegis.tunnel.v1.TunnelService/Open, /cdn.tunnel.v1.Session/Open, /grpc.gateway.v1.Proxy/Connect, /rpc.Tunnel/Open\`" "${OUTPUT_MD}"
grep -Fq -- "- MASQUE paths: \`/.well-known/masque/connect-udp, /.well-known/masque/udp, /masque/v1/udp, /relay/datagram\`" "${OUTPUT_MD}"
grep -Fq -- "- WebSocket Origin variants: \`<none>, https://localhost\`" "${OUTPUT_MD}"
grep -Fq -- "- gRPC accept-encoding variants: \`<none>, gzip, gzip, deflate, gzip, identity, identity\`" "${OUTPUT_MD}"
grep -Fq -- "- gRPC timeout variants: \`10S, 12S, 15S, 20S, 25S, 30S, 60S, <none>\`" "${OUTPUT_MD}"
grep -Fq -- "- gRPC message-type variants: \`<none>, SessionOpenRequest, TunnelRequest\`" "${OUTPUT_MD}"
grep -Fq -- "- MASQUE Alt-Used variants: \`<none>, localhost\`" "${OUTPUT_MD}"

echo "stealth polymorphism acceptance summary contract: ok"
