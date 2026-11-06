#!/usr/bin/env python3
"""Read-only verification of the original 37 grant checklist identifiers."""

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path


EXPECTED_IDS = frozenset(
    f"P{family}.{item}"
    for family, maximum in ((0, 10), (1, 10), (2, 9), (3, 8))
    for item in range(1, maximum + 1)
)
MAX_INPUT_BYTES = 1024 * 1024
IDENTIFIER = re.compile(r"P[0-3]\.[1-9][0-9]*\Z")
GRANT_LIKE = re.compile(r"P(?:[0-9.:_-]|\Z)")
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")


class InputArgumentsRejected(ValueError):
    """Argument rejection without retaining or displaying supplied text."""


class AggregateArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default error includes untrusted arguments and usage.
        # Do not echo them or retain its message in the raised exception.
        raise InputArgumentsRejected()


def analyze_register(text):
    """Count IDs only in the first cell of real, non-fenced Markdown rows.

    Introductory prose, table headers, separators and code examples are not
    evidence of coverage. This verifies identifier coverage, not full Markdown
    syntax or the truth of each row. No source text or identifiers are returned.
    """
    seen = Counter()
    unknown = 0
    malformed = 0
    fence_character = None
    fence_length = 0
    for line in text.splitlines():
        match = FENCE.match(line)
        if fence_character is not None:
            if (
                match
                and match[1][0] == fence_character
                and len(match[1]) >= fence_length
                and not match[2].strip()
            ):
                fence_character = None
            continue
        if match:
            fence_character = match[1][0]
            fence_length = len(match[1])
            continue
        stripped = line.strip()
        # Markdown permits an omitted leading/trailing pipe. Require a pipe
        # separator so prose mentioning an ID cannot supply a checklist row.
        if "|" not in stripped:
            continue
        cells = stripped.split("|")
        if stripped.startswith("|"):
            cells = cells[1:]
        if stripped.endswith("|"):
            cells = cells[:-1]
        first = cells[0].strip()
        if not first or not GRANT_LIKE.match(first):
            continue
        # An ID alone is not a register entry: each row must retain both its
        # actual state and remaining-acceptance columns.
        if len(cells) < 3 or not cells[1].strip() or not cells[2].strip():
            malformed += 1
            continue
        token = first.split(None, 1)[0]
        if not IDENTIFIER.fullmatch(token):
            malformed += 1
        elif token not in EXPECTED_IDS:
            unknown += 1
        else:
            seen[token] += 1
    missing = len(EXPECTED_IDS.difference(seen))
    duplicates = sum(count - 1 for count in seen.values())
    accepted = not (missing or duplicates or unknown or malformed)
    return {
        "status": "PASS" if accepted else "FAIL",
        "expected_unique_rows": len(EXPECTED_IDS),
        "observed_valid_rows": sum(seen.values()),
        "observed_unique_rows": len(seen),
        "missing_rows": missing,
        "duplicate_rows": duplicates,
        "unknown_rows": unknown,
        "malformed_rows": malformed,
    }


def main(argv=None):
    parser = AggregateArgumentParser(
        description="Verify exact 37-ID grant-register coverage without editing it."
    )
    parser.add_argument("register", help="Markdown register to verify")
    try:
        args = parser.parse_args(argv)
        with Path(args.register).open("rb") as source:
            raw = source.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise ValueError("bounded input exceeded")
        result = analyze_register(raw.decode("utf-8", errors="strict"))
    except (OSError, UnicodeError, ValueError):
        # Never echo the supplied path, document body or exception text.
        print(json.dumps({"status": "ERROR", "reason": "input_not_accepted"}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
