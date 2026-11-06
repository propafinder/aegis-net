#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

grep -Fq 'TRANSPORT_PRIORITY="grpc_stream"' "${ROOT}/scripts/issue-fronted-bundle.sh"
grep -Fq 'RELAY_TRANSPORT_PRIORITY="grpc_stream"' "${ROOT}/install.sh"

if grep -Fq 'TRANSPORT_PRIORITY="https_ws,grpc_stream"' "${ROOT}/scripts/issue-fronted-bundle.sh"; then
  echo "fronted bundle still defaults to the unverified RFC 8441 WebSocket contour" >&2
  exit 1
fi

grep -Fq 'currently supports only grpc_stream' "${ROOT}/aegis-client/src/operator.rs"
grep -Fq 'RFC 8441 https_ws' "${ROOT}/aegis-client/src/operator.rs"

grep -Fq '| Fronted TCP | Forced `grpc_stream`' "${ROOT}/README.md"
grep -Fq 'Cloudflare fronting uses `grpc_stream`; RFC 8441 `https_ws` is not accepted for that path.' "${ROOT}/README.md"
grep -Fq '| Cloudflare HTTP fronting | `grpc_stream`' "${ROOT}/INSTALL.md"
grep -Fq 'forced Cloudflare-fronted transport:' "${ROOT}/docs/cloudflare-fronted-operator-guide.md"
grep -Fq -- '--relay-transport-priority grpc_stream' "${ROOT}/docs/cloudflare-fronted-operator-guide.md"

if grep -Fq '| Fronted TCP | Forced `https_ws`' "${ROOT}/README.md" ||
   grep -Fq '| Cloudflare HTTP fronting | `https_ws`' "${ROOT}/INSTALL.md"; then
  echo "operator docs still advertise unverified fronted https_ws" >&2
  exit 1
fi

echo "PASS: Cloudflare-fronted defaults and operator claims are gRPC-only"
