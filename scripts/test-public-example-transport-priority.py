#!/usr/bin/env python3
"""Source contract for the release bundle's default transport example."""

from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parent.parent
example = (ROOT / "config.example.toml").read_text(encoding="utf-8")
builder = (ROOT / "scripts/build-release-bundle.sh").read_text(encoding="utf-8")
priority = tomllib.loads(example)["relay"]["transport_priority"]

assert priority[:2] == ["https_ws", "grpc_stream"]
assert "legacy_tls" not in priority, "legacy TLS is active in the shipped example"
assert "legacy_tls" in example, "explicit old-relay compatibility example absent"
assert "JA4" in example, "legacy compatibility warning absent"
assert 'cp "${ROOT}/config.example.toml" "${BUNDLE_DIR}/config.example.toml"' in builder
print("PASS: release example defaults exclude legacy TLS; opt-in warning retained")
