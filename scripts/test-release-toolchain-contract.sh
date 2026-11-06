#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
. "$ROOT/scripts/lib/release-toolchain.sh"
verify_release_toolchain
FIXTURE="$(mktemp -d)"
trap 'rm -rf "$FIXTURE"' EXIT
cat > "$FIXTURE/rustc" <<'SH'
#!/usr/bin/env bash
echo 'rustc 0.0.0 (fixture)'
SH
chmod +x "$FIXTURE/rustc"
if PATH="$FIXTURE:$PATH" verify_release_toolchain 2>/dev/null; then
  echo 'FAIL: release accepted a different compiler' >&2; exit 1
fi
[[ "$(release_source_timestamp)" == "$(git -C "$ROOT" show -s --format=%cI HEAD)" ]]
echo 'PASS: exact release compiler and commit-derived build timestamp'
