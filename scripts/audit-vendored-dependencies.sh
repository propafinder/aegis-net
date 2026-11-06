#!/usr/bin/env bash
# cargo-audit does not match path packages to crates.io advisories. Audit their
# explicitly recorded upstream identities too, without changing Cargo.lock.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cargo metadata --locked --format-version 1 > "$TMP/metadata.json"
printf 'version = 4\n' > "$TMP/upstream.lock"
count=0
while IFS= read -r record; do
  name="$(jq -r '.name' <<< "$record")"
  version="$(jq -r '.version' <<< "$record")"
  manifest="$(jq -r '.manifest_path' <<< "$record")"
  provenance="${manifest%/*}/UPSTREAM.json"
  [[ "$name" =~ ^[a-zA-Z0-9_-]+$ && "$version" =~ ^[a-zA-Z0-9.+_-]+$ ]] || exit 1
  [[ -f "$provenance" ]] || { echo "Missing vendored provenance: $name" >&2; exit 1; }
  jq -e --arg name "$name" --arg version "$version" '
    .name == $name and .version == $version and
    .registry == "https://github.com/rust-lang/crates.io-index" and
    (.archive_sha256 | test("^[0-9a-f]{64}$"))
  ' "$provenance" > /dev/null
  # Advisory identity alone cannot detect source tampering. Preserve original
  # upstream hashes and verify documented local patches against both baselines.
  python3 -I - "$provenance" <<'PY'
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

provenance = Path(sys.argv[1])
root = provenance.parent

def require(condition, reason):
    if not condition:
        raise SystemExit(f"vendored integrity FAIL ({root.name}): {reason}")

def safe_path(value):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_./-]+", value),
            "invalid recorded file path")
    require(not PurePosixPath(value).is_absolute() and
            all(part not in ("", ".", "..") for part in value.split("/")),
            "recorded file path escapes its package")
    return value

def digest(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value),
            "invalid recorded file checksum")
    return value

def checksum_map(value, label):
    require(isinstance(value, dict), f"missing {label}")
    return {safe_path(path): digest(checksum) for path, checksum in value.items()}

def checked_bytes(relative, expected):
    path = root / relative
    require(all(not parent.is_symlink() for parent in (path, *path.parents)
                if parent == root or root in parent.parents),
            f"symlinked file: {relative}")
    require(path.is_file(), f"missing file: {relative}")
    content = path.read_bytes()
    require(hashlib.sha256(content).hexdigest() == expected,
            f"checksum mismatch: {relative}")
    return content

def reconstructed_upstream(current, delta, relative):
    # Reverse a single-file unified diff without invoking a patch program or
    # accepting diff paths that could write outside an isolated package.
    source = current.decode("utf-8").splitlines(keepends=True)
    patch = delta.decode("utf-8").splitlines(keepends=True)
    require(patch[:2] == [f"--- a/{relative}\n", f"+++ b/{relative}\n"],
            f"patch must describe exactly one file: {relative}")
    output, position, index, hunks = [], 0, 2, 0
    while index < len(patch):
        match = re.fullmatch(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\r\n]*\n", patch[index])
        require(match is not None, f"invalid patch hunk: {relative}")
        old_start, old_count, new_start, new_count = (
            int(match[1]), int(match[2] or 1), int(match[3]), int(match[4] or 1))
        start = new_start - 1 if new_count else new_start
        require(position <= start <= len(source), f"invalid patch position: {relative}")
        output.extend(source[position:start])
        require(len(output) == (old_start - 1 if old_count else old_start),
                f"invalid upstream patch position: {relative}")
        consumed, produced = 0, 0
        index += 1
        while index < len(patch) and not patch[index].startswith("@@ "):
            line = patch[index]
            require(line[:1] in (" ", "+", "-"), f"invalid patch line: {relative}")
            if line[0] in (" ", "+"):
                require(start + consumed < len(source) and source[start + consumed] == line[1:],
                        f"patch does not match patched bytes: {relative}")
                consumed += 1
            if line[0] in (" ", "-"):
                output.append(line[1:])
                produced += 1
            index += 1
        require(consumed == new_count and produced == old_count,
                f"patch hunk length mismatch: {relative}")
        position = start + consumed
        hunks += 1
    require(hunks > 0, f"empty local patch: {relative}")
    output.extend(source[position:])
    return "".join(output).encode("utf-8")

require(not provenance.is_symlink(), "symlinked provenance metadata")
record = json.loads(provenance.read_text())
upstream = checksum_map(record.get("upstream_files_sha256"), "upstream file checksums")
require(bool(upstream), "empty upstream file inventory")
modifications = record.get("local_modifications")
require(isinstance(modifications, list), "missing local modification inventory")
modified = {safe_path(path) for path in modifications}
require(len(modified) == len(modifications) and modified <= upstream.keys(),
        "local modifications must uniquely name upstream files")
patches = record.get("local_patches", {})
require(isinstance(patches, dict) and patches.keys() == modified,
        "each local modification needs exactly one custody record")
metadata = checksum_map(record.get("local_metadata_sha256", {}), "local metadata checksums")
require(not metadata.keys() & upstream.keys() and "UPSTREAM.json" not in upstream and
        "UPSTREAM.json" not in metadata, "upstream and local metadata inventories overlap")
patch_files = set()
for relative, custody in patches.items():
    require(isinstance(custody, dict), f"invalid patch custody: {relative}")
    patched_hash = digest(custody.get("patched_sha256"))
    require(patched_hash != upstream[relative], f"local patch relabelled as upstream: {relative}")
    patch_file = safe_path(custody.get("patch_file"))
    require(patch_file not in upstream and patch_file not in metadata and
            patch_file != "UPSTREAM.json" and patch_file not in patch_files,
            f"overlapping patch artifact: {patch_file}")
    patch_files.add(patch_file)
    documentation = safe_path(custody.get("documentation"))
    require(documentation in metadata, f"missing patch documentation checksum: {relative}")
    current = checked_bytes(relative, patched_hash)
    delta = checked_bytes(patch_file, digest(custody.get("patch_sha256")))
    restored = reconstructed_upstream(current, delta, relative)
    require(hashlib.sha256(restored).hexdigest() == upstream[relative],
            f"patch does not reconstruct recorded upstream: {relative}")
for relative, checksum in upstream.items():
    if relative not in modified:
        checked_bytes(relative, checksum)
for relative, checksum in metadata.items():
    checked_bytes(relative, checksum)
expected = set(upstream) | set(metadata) | patch_files | {"UPSTREAM.json"}
actual = {path.relative_to(root).as_posix() for path in root.rglob("*")
          if path.is_file() or path.is_symlink()}
require(actual == expected,
        f"unrecorded or missing files: {', '.join(sorted(actual ^ expected))}")
print(f"vendored source integrity: PASS ({root.name}; {len(upstream)} upstream files, {len(modified)} local patches)")
PY
  printf '\n[[package]]\nname = "%s"\nversion = "%s"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n' \
    "$name" "$version" >> "$TMP/upstream.lock"
  count=$((count + 1))
done < <(jq -c --arg prefix "$ROOT/third_party/" '
  .packages[] | select(.source == null and (.manifest_path | startswith($prefix)))
' "$TMP/metadata.json")
[[ "$count" -gt 0 ]] || { echo 'No vendored dependencies found; review the audit policy.' >&2; exit 1; }
args=(audit --file "$TMP/upstream.lock" --deny warnings --no-yanked)
if [[ -n "${AEGIS_CARGO_AUDIT_DB:-}" ]]; then
  args+=(--db "$AEGIS_CARGO_AUDIT_DB" --no-fetch)
fi
cargo "${args[@]}"
echo "vendored dependency audit: PASS ($count upstream identities)"
