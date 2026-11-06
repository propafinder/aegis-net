#!/usr/bin/env python3
"""Reject known credential forms in tracked, bounded text evidence.

This is a narrow containment gate, not a history/archive or general secret audit.
Diagnostics contain paths and finding classes only, never matched contents.
"""
from pathlib import Path
import json
import re
import subprocess
import sys
import tomllib

MAX_TEXT_BYTES = 2 * 1024 * 1024
# Retained evidence fixtures that CI contracts read. The historical evidence
# tree was moved to an archive outside Git on 6 November 2026.
EVIDENCE_PREFIX = "scripts/tests/fixtures/evidence/"
TEXT_SUFFIXES = {".toml", ".json", ".md", ".txt", ".private", ".log", ".sh",
                 ".py", ".yaml", ".yml", ".csv", ".out", ".stdout", ".stderr",
                 ".pem", ".key", ".crt", ".conf", ".env"}
TOKEN = re.compile(r'''(?:^\s*auth_token\s*=\s*|[,{]\s*["']auth_token["']\s*:\s*|^\s*["']auth_token["']\s*:\s*)["']([^"'\r\n]+)["']''', re.M)
REDACTION = re.compile(r"^(?:REDACTED(?:[_ -][A-Za-z0-9_-]+)?|<REDACTED(?:[_ -][A-Za-z0-9_ -]+)?>|\[REDACTED\])$", re.I)
PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----")
SHELL_TEMPLATE = re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*\}$")


def credential_values(content: str, suffix: str) -> list[str]:
    values = TOKEN.findall(content)
    # A usable configuration can quote/escape keys and span string values.
    # Decode complete bounded TOML/JSON before checking those semantic values;
    # historical fragments and logs retain the narrower lexical inspection.
    parser = {".toml": tomllib.loads, ".json": json.loads}.get(suffix)
    if parser is None:
        return values
    try:
        pending = [parser(content)]
    except (ValueError, RecursionError):
        return values
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            for key, value in item.items():
                if key == "auth_token" and isinstance(value, str):
                    values.append(value)
                elif isinstance(value, (dict, list)):
                    pending.append(value)
        elif isinstance(item, list):
            pending.extend(value for value in item if isinstance(value, (dict, list)))
    return values


def scan(root: Path, paths: list[str]) -> dict:
    findings = []
    inspected = excluded = 0
    for name in paths:
        if not name.startswith(EVIDENCE_PREFIX):
            continue
        path = root / name
        if (path.suffix not in TEXT_SUFFIXES and not path.name.startswith(".env.")) or path.is_symlink():
            excluded += 1
            continue
        try:
            if path.stat().st_size > MAX_TEXT_BYTES:
                excluded += 1
                continue
            raw = path.read_bytes()
            content = raw.decode("utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8")
        except (OSError, UnicodeError):
            findings.append({"path": name, "kind": "evidence_text_unreadable"})
            continue
        inspected += 1
        if any(value and not REDACTION.fullmatch(value.strip()) and not SHELL_TEMPLATE.fullmatch(value.strip())
               for value in credential_values(content, path.suffix)):
            findings.append({"path": name, "kind": "unredacted_relay_credential"})
        if PRIVATE_KEY.search(content):
            findings.append({"path": name, "kind": "private_key_material"})
        if path.name == "bundle-url.private" and content.strip() and content.strip() != "https://redacted.invalid/private-bundle-url-removed":
            findings.append({"path": name, "kind": "private_bundle_url"})
    return {"gate": "tracked_bounded_text_evidence", "inspected_files": inspected,
            "excluded_binary_large_or_other_files": excluded, "findings": findings,
            "history_archives_and_credential_revocation_verified": False}


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(["git", "ls-files", "-z", "--", EVIDENCE_PREFIX], cwd=root,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    if result.returncode:
        print(json.dumps({"gate": "tracked_bounded_text_evidence", "error": "tracked_inventory_unavailable"}))
        return 1
    report = scan(root, [p.decode("utf-8", errors="strict") for p in result.stdout.split(b"\0") if p])
    print(json.dumps(report, sort_keys=True))
    return int(bool(report["findings"]))


if __name__ == "__main__":
    sys.exit(main())
