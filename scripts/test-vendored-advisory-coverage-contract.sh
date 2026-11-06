#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# A new path fork must participate in the dependency gate rather than inherit
# the false assurance of a clean registry-only audit.
grep -Fq 'bash ./scripts/audit-vendored-dependencies.sh' "$ROOT/.github/workflows/ci.yml"
grep -Fq '.source == null' "$ROOT/scripts/audit-vendored-dependencies.sh"
jq -e '
  .name == "h2" and .version == "0.4.16" and
  (.archive_sha256 | test("^[0-9a-f]{64}$")) and
  .local_modifications == ["src/frame/headers.rs", "src/client.rs",
    "src/frame/priority.rs", "Cargo.lock", "src/share.rs",
    "src/proto/streams/streams.rs", "src/proto/streams/recv.rs"] and
  (.local_patches | keys == ["Cargo.lock", "src/client.rs", "src/frame/headers.rs",
    "src/frame/priority.rs", "src/proto/streams/recv.rs",
    "src/proto/streams/streams.rs", "src/share.rs"])
' "$ROOT/third_party/h2/UPSTREAM.json" > /dev/null
grep -Fq 'version = "0.4.16"' "$ROOT/third_party/h2/Cargo.toml"
echo 'vendored advisory coverage contract: PASS'
