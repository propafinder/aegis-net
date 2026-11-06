#!/usr/bin/env python3
"""Contain bearer URLs in bounded tracked evidence; never verify live validity.

The inventory includes .raw receipts. Output uses opaque indices because paths
can themselves carry credentials. Archives/history and excluded files remain
outside this narrow gate and must be handled by the private incident review.
"""
from pathlib import Path
import importlib.util
import json
import re
import subprocess
import sys
import tomllib
from urllib.parse import parse_qsl, urlsplit

spec = importlib.util.spec_from_file_location("evidence_guard", Path(__file__).with_name("check-tracked-evidence-secrets.py"))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
URL = re.compile(r'''https?://[^\s<>"'`]+''', re.I)
BINARY_URL_START = re.compile(rb"https?://", re.I)
BINARY_UTF16_URL_START = (
    re.compile(rb"h\x00t\x00t\x00p\x00(?:s\x00)?:\x00/\x00/\x00", re.I),
    re.compile(rb"\x00h\x00t\x00t\x00p(?:\x00s)?\x00:\x00/\x00/", re.I),
)
MAX_BINARY_URL_BYTES = 8192
MAX_BINARY_URL_CANDIDATES = 4096
BINARY_URL_DELIMITERS = b" \t\r\n<>\"'`"
SECRET_KEYS = {"token", "access_token", "api_key", "apikey", "auth", "authorization",
               "credential", "key", "password", "secret", "sig", "signature", "x-amz-signature"}
SHELL_QUERY_TEMPLATE = re.compile(r"(?:\$\{[A-Za-z_][A-Za-z0-9_]*\})+\Z")
SHELL_URL_ALTERNATION = "http://*|https://*)"


def safe_query_placeholder(value, following):
    """Admit only a redaction marker or pure shell variable expansion."""
    candidate = value.strip()
    if candidate.endswith("\\") and following in ("\"", "'"):
        candidate = candidate[:-1]
    return bool(guard.REDACTION.fullmatch(candidate) or SHELL_QUERY_TEMPLATE.fullmatch(candidate))


def decoded_texts(content, suffix):
    texts = [content]
    parser = {".json": json.loads, ".toml": tomllib.loads}.get(suffix)
    if parser is not None:
        try:
            pending = [parser(content)]
        except (ValueError, RecursionError):
            return texts
        while pending:
            item = pending.pop()
            if isinstance(item, str):
                texts.append(item)
            elif isinstance(item, dict):
                pending.extend(item.keys())
                pending.extend(item.values())
            elif isinstance(item, list):
                pending.extend(item)
    return texts


def finding_classes(content, suffix):
    classes = set()
    for text in decoded_texts(content, suffix):
        for match in URL.finditer(text):
            # A second URL marker within the same regex span can hide a bearer
            # in an outer fragment or path. Both text and raw-byte scans use
            # this classifier, so reject the entire ambiguous candidate.
            candidate = match.group()
            if (URL.search(candidate, candidate.find("://") + 3)
                    and candidate.casefold() != SHELL_URL_ALTERNATION):
                classes.add("nested_url_marker")
            try:
                url = urlsplit(candidate)
                if url.username is not None:
                    classes.add("url_userinfo")
                for key, value in parse_qsl(url.query, keep_blank_values=True):
                    if key.casefold() in SECRET_KEYS and value and not safe_query_placeholder(value, text[match.end():match.end() + 1]):
                        classes.add("unredacted_url_credential")
            except ValueError:
                classes.add("malformed_url")
    return sorted(classes)


def binary_raw_url_classes(raw):
    """Check every .raw byte stream for ASCII and BOM-less UTF-16 URLs."""
    classes = set()
    candidate_count = 0

    def claim_candidate():
        nonlocal candidate_count
        candidate_count += 1
        if candidate_count > MAX_BINARY_URL_CANDIDATES:
            classes.add("binary_url_candidate_limit")
            return False
        return True

    def classify(candidate):
        try:
            url = urlsplit(candidate)
            if not url.hostname:
                classes.add("malformed_url")
        except ValueError:
            classes.add("malformed_url")
        classes.update(finding_classes(candidate, ".raw"))

    ascii_consumed_end = -1
    for start in BINARY_URL_START.finditer(raw):
        if start.start() < ascii_consumed_end:
            continue
        if not claim_candidate():
            return sorted(classes)
        tail = raw[start.start():start.start() + MAX_BINARY_URL_BYTES + 1]
        end = len(tail)
        for offset, byte in enumerate(tail):
            if byte in BINARY_URL_DELIMITERS:
                end = offset
                break
            if byte < 0x21 or byte > 0x7e:
                classes.add("malformed_url")
                end = offset
                break
        ascii_consumed_end = start.start() + min(end, MAX_BINARY_URL_BYTES + 1)
        if end > MAX_BINARY_URL_BYTES:
            classes.add("malformed_url")
            continue
        if end < start.end() - start.start():
            classes.add("malformed_url")
            continue
        candidate = tail[:end].decode("ascii")
        following = chr(tail[end]) if end < len(tail) and tail[end] in (34, 39) else ""
        classify(candidate + following if following in ("\"", "'") else candidate)

    markers = sorted((match.start(), match.end(), byte_order)
                     for byte_order, pattern in (("little", BINARY_UTF16_URL_START[0]),
                                                 ("big", BINARY_UTF16_URL_START[1]))
                     for match in pattern.finditer(raw))
    previous_end = -1
    for marker_start, marker_end, byte_order in markers:
        # Opposite-endian patterns overlap by one byte on ordinary UTF-16.
        # Inspect the leftmost complete marker once, not its shifted alias.
        if marker_start < previous_end:
            continue
        if not claim_candidate():
            return sorted(classes)
        previous_end = marker_end
        cursor = marker_start
        characters = []
        ambiguous = False
        while cursor + 1 < len(raw):
            code_unit = int.from_bytes(raw[cursor:cursor + 2], byte_order)
            if code_unit == 0 or code_unit in BINARY_URL_DELIMITERS:
                break
            if code_unit < 0x21 or code_unit > 0x7e:
                ambiguous = True
                break
            characters.append(chr(code_unit))
            cursor += 2
            if len(characters) > MAX_BINARY_URL_BYTES:
                ambiguous = True
                break
        if cursor + 1 == len(raw):
            ambiguous = True
        previous_end = max(previous_end, cursor)
        if ambiguous:
            classes.add("malformed_url")
        if len(characters) <= MAX_BINARY_URL_BYTES:
            classify("".join(characters))
    return sorted(classes)

def scan(root, paths):
    result = {"gate": "tracked_bounded_evidence_url_credentials", "inspected_files": 0,
              "excluded_files": 0, "raw_byte_scanned_files": 0, "non_utf8_raw_files": 0,
              "findings": [], "live_validity_or_revocation_verified": False,
              "history_and_archive_scan_complete": False}
    for index, name in enumerate(paths, 1):
        if not name.startswith(guard.EVIDENCE_PREFIX):
            continue
        path = root / name
        if path.is_symlink() or (path.suffix not in guard.TEXT_SUFFIXES | {".raw"} and not path.name.startswith(".env.")):
            result["excluded_files"] += 1
            continue
        try:
            if path.stat().st_size > guard.MAX_TEXT_BYTES:
                if path.suffix == ".raw":
                    result["findings"].append({"file_index": index, "class": "oversized_raw_evidence"})
                else:
                    result["excluded_files"] += 1
                continue
            with path.open("rb") as source:
                raw = source.read(guard.MAX_TEXT_BYTES + 1)
            if len(raw) > guard.MAX_TEXT_BYTES:
                if path.suffix == ".raw":
                    result["findings"].append({"file_index": index, "class": "oversized_raw_evidence"})
                else:
                    result["excluded_files"] += 1
                continue
        except OSError:
            result["findings"].append({"file_index": index, "class": "unreadable_evidence"})
            continue
        classes = set()
        if path.suffix == ".raw":
            result["raw_byte_scanned_files"] += 1
            classes.update(binary_raw_url_classes(raw))
        try:
            content = raw.decode("utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8")
        except UnicodeError:
            if path.suffix != ".raw":
                result["findings"].append({"file_index": index, "class": "unreadable_evidence"})
                continue
            result["non_utf8_raw_files"] += 1
        else:
            classes.update(finding_classes(content, path.suffix))
        result["inspected_files"] += 1
        for kind in sorted(classes):
            result["findings"].append({"file_index": index, "class": kind})
    return result

def main():
    root = Path(__file__).resolve().parents[2]
    try:
        inventory = subprocess.run(["git", "ls-files", "-z", "--", guard.EVIDENCE_PREFIX], cwd=root,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
        if inventory.returncode:
            raise ValueError("inventory_unavailable")
        paths = [p.decode("utf-8", errors="strict") for p in inventory.stdout.split(b"\0") if p]
    except (OSError, ValueError, UnicodeError):
        # Git permits arbitrary filename bytes; decode failures must never
        # disclose the raw inventory in a traceback or partially scan it.
        print(json.dumps({"gate": "tracked_bounded_evidence_url_credentials", "error": "inventory_unavailable"}))
        return 1
    report = scan(root, paths)
    print(json.dumps(report, sort_keys=True))
    return int(bool(report["findings"]))


if __name__ == "__main__":
    sys.exit(main())
