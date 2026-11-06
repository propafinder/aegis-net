#!/usr/bin/env bash
# The vendored h2 must keep emitting :authority before :scheme.
#
# Chrome sends :method/:authority/:scheme/:path. Upstream h2 sends
# :method/:scheme/:authority/:path and hardcodes it, so AEGIS vendors h2 and
# swaps the two. If a version bump silently drops the patch, every request we
# make becomes distinguishable from a browser's again on the first HEADERS
# frame -- with nothing failing and nothing logged.
#
# The check is textual. It cannot prove what goes on the wire; it exists so a
# lost patch fails in CI instead of being discovered by a censor. The wire
# measurement is evidence-archive/live/2026-08-11/http2-pseudo-header-order.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

fail() { echo "FAIL: $*" >&2; exit 1; }

HEADERS="third_party/h2/src/frame/headers.rs"
[[ -f "${HEADERS}" ]] || fail "vendored h2 is missing: ${HEADERS}
   Cargo.toml patches crates-io h2 to this path. Without it the build silently
   falls back to upstream h2 and the pseudo-header order regresses."

grep -q 'AEGIS PATCH' "${HEADERS}" \
  || fail "${HEADERS}: the AEGIS PATCH marker is gone. A version bump probably
   overwrote it. See third_party/h2/AEGIS-PATCH.md to re-apply."

# The order that matters, read out of the iterator body.
order="$(grep -oE 'pseudo\.(authority|scheme)\.take\(\)' "${HEADERS}" | head -2 | sed -E 's/pseudo\.([a-z]+)\.take\(\)/\1/' | tr '\n' ' ')"
[[ "${order}" == "authority scheme " ]] \
  || fail "third_party/h2 drains pseudo-headers as '${order}' but must drain
   'authority scheme ' -- Chrome sends :method/:authority/:scheme/:path."

# Parse the actual [patch.crates-io] table. Inline-table spacing, key order,
# version constraints and comments do not determine Cargo patch semantics.
python3 -I - Cargo.toml <<'PY_MANIFEST' || fail "Cargo.toml does not declare the reviewed vendored h2 patch."
from pathlib import Path
import sys
import tomllib

try:
    manifest = Path(sys.argv[1]).resolve(strict=True)
    with manifest.open("rb") as source:
        data = tomllib.load(source)
    h2 = data["patch"]["crates-io"]["h2"]
    if not isinstance(h2, dict) or not isinstance(h2.get("path"), str):
        raise ValueError("invalid patch shape")
    if "package" in h2 and h2["package"] != "h2":
        raise ValueError("patch alias must name h2")
    declared = Path(h2["path"])
    if declared.is_absolute() or ".." in declared.parts:
        raise ValueError("patch path must stay within the reviewed repository")
    reviewed = (manifest.parent / "third_party/h2").resolve(strict=True)
    if (manifest.parent / declared).resolve(strict=True) != reviewed:
        raise ValueError("wrong reviewed patch directory")
except (OSError, KeyError, TypeError, ValueError, tomllib.TOMLDecodeError):
    # TOML parser errors may contain source text; report only a fixed failure.
    raise SystemExit(1)
PY_MANIFEST

echo "h2 pseudo-header order contract: ok"
