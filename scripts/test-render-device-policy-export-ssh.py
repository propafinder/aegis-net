#!/usr/bin/env python3
"""Inert core contracts; the production CLI never offers a test-owner override."""

import hashlib
import importlib.util
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
TOOL = HERE / "render-device-policy-export-ssh.py"
spec = importlib.util.spec_from_file_location("render_export", TOOL)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
COMMIT = subprocess.check_output(["git", "-C", str(HERE.parent), "rev-parse", "HEAD"], text=True, timeout=5).strip()
PRIOR = "cf6fbada5b832ca8c53c9b886326e871d1ac292d"
assert re.fullmatch(r"[0-9a-f]{40}", PRIOR)
OLD = (
    f"/opt/aegis/{PRIOR}/bin/aegis-server device-policy export "
    "--registry /var/lib/aegis-device-authority/registry.json --forced-ssh"
).encode()
NEW = (
    f"{module.source_binary(COMMIT)} device-policy export "
    "--registry /var/lib/aegis-device-authority/registry.json --forced-ssh"
).encode()
REAL_SOURCE_BINARY = module.source_binary


def rewrite_keys(*args, **kwargs):
    # actions/checkout fetches only HEAD. Keep the historical command fixture
    # without weakening the production renderer's Git-object validation.
    def pinned_prior(commit, *, must_be_head=True):
        if commit == PRIOR and not must_be_head:
            return f"/opt/aegis/{PRIOR}/bin/aegis-server"
        return REAL_SOURCE_BINARY(commit, must_be_head=must_be_head)

    with mock.patch.object(module, "source_binary", side_effect=pinned_prior):
        return module.rewrite_keys(*args, **kwargs)


def refuses(callback, *args, **kwargs) -> None:
    try:
        callback(*args, **kwargs)
    except (OSError, ValueError):
        return
    raise AssertionError("unsafe candidate was accepted")


with tempfile.TemporaryDirectory(prefix="aegis-exporter-render-") as tmp:
    root = Path(tmp)
    binary = root / "aegis-server"
    binary.write_bytes(b"synthetic candidate binary\n")
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    module.verify_binary(binary, digest)
    files = module.expected(COMMIT)
    prefix = files[module.PREFIX].rstrip(b"\n")
    assert NEW in files[module.SNIPPET] and NEW in prefix
    assert files[module.SNIPPET].endswith(b"Match all\n")
    assert f"AuthorizedKeysFile {module.versioned_roster_path(COMMIT)}".encode() in files[module.SNIPPET]
    assert b"AuthorizedKeysFile /etc/ssh/aegis-policy-authorized-keys\n" not in files[module.SNIPPET]
    assert b"/usr/local/bin" not in files[module.SNIPPET]

    roster = root / "authorized-keys"
    old_prefix = b'restrict,command="' + OLD + b'"'
    old_roster = old_prefix + b" ssh-ed25519 QUJDRA== synthetic-comment\n"
    roster.write_bytes(old_roster)
    roster.chmod(0o644)
    staged_keys, count = rewrite_keys(roster, PRIOR, prefix, owner=os.geteuid())
    assert count == 1
    assert staged_keys == old_roster.replace(OLD, NEW)
    files[module.ROSTER] = staged_keys
    staged = root / "staged"
    module.stage(staged, files)
    assert (staged.stat().st_mode & 0o777) == 0o700
    for name, body in files.items():
        assert module.read_regular(staged / name, owner=os.geteuid(), mode=0o600) == body
    refuses(module.stage, staged, files)

    reordered = b'command="' + OLD + b'",from="192.0.2.1,192.0.2.2",restrict,no-pty ssh-ed25519 QUJDRA== synthetic-comment\n'
    roster.write_bytes(reordered)
    rewritten, count = rewrite_keys(roster, PRIOR, prefix, owner=os.geteuid())
    assert count == 1 and rewritten == reordered.replace(OLD, NEW)

    roster.write_bytes(b"".join(old_prefix + b" ssh-ed25519 " + ("QUJDRA%02d" % index).encode() + b"= synthetic\n" for index in range(4)))
    rewritten, count = rewrite_keys(roster, PRIOR, prefix, owner=os.geteuid())
    assert count == 4 and rewritten.count(NEW) == 4 and b"QUJDRA" in rewritten

    for bad in (
        b"ssh-ed25519 QUJDRA== missing-options\n",
        old_prefix.replace(b"restrict,", b"") + b" ssh-ed25519 QUJDRA==\n",
        old_prefix.replace(b"--forced-ssh", b"--wrong") + b" ssh-ed25519 QUJDRA==\n",
        old_prefix + b',command="extra" ssh-ed25519 QUJDRA==\n',
        old_prefix + b" ssh-dss QUJDRA==\n",
        old_prefix + b" ssh-ed25519 invalid*\n",
        b"# empty roster\n",
    ):
        roster.write_bytes(bad)
        refuses(rewrite_keys, roster, PRIOR, prefix, owner=os.geteuid())
    roster.write_bytes(old_roster)

    alias = root / "alias"
    os.link(roster, alias)
    refuses(rewrite_keys, roster, PRIOR, prefix, owner=os.geteuid())
    alias.unlink()
    roster.chmod(0o666)
    refuses(rewrite_keys, roster, PRIOR, prefix, owner=os.geteuid())
    roster.chmod(0o644)
    assert rewrite_keys(roster, PRIOR, prefix, owner=os.geteuid())[1] == 1

    snippet = staged / module.SNIPPET
    snippet.write_bytes(snippet.read_bytes().replace(COMMIT.encode(), b"4d0a8fd2"))
    assert module.read_regular(snippet, owner=os.geteuid(), mode=0o600) != files[module.SNIPPET]
    snippet.unlink()
    snippet.symlink_to(staged / module.PREFIX)
    refuses(module.read_regular, snippet, owner=os.geteuid(), mode=0o600)
    snippet.unlink()
    snippet.write_bytes(files[module.SNIPPET])
    snippet.chmod(0o600)

    refuses(module.versioned_roster_path, "not-a-commit")
    refuses(module.source_binary, PRIOR)
    refuses(module.source_binary, "0" * 40)
    binary.write_bytes(b"changed synthetic binary\n")
    refuses(module.verify_binary, binary, digest)

    issuer_spec = importlib.util.spec_from_file_location("render_issuer", HERE / "render-enrollment-authority-units.py")
    issuer = importlib.util.module_from_spec(issuer_spec)
    issuer_spec.loader.exec_module(issuer)
    for rendered in issuer.expected_units(HERE.parent / "packaging/systemd", COMMIT).values():
        assert issuer.release_binary(COMMIT) in rendered

    command = [
        sys.executable, str(TOOL), "--source-commit", COMMIT,
        "--prior-source-commit", PRIOR, "--binary-sha256", digest,
        "--binary-file", str(binary), "--authorized-keys", str(roster),
        "--output-dir", str(root / "cli-stage"),
    ]
    assert subprocess.run(command + ["--keys-owner-uid", str(os.geteuid())], capture_output=True, timeout=5).returncode != 0
    if os.geteuid() != 0:
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        assert result.returncode != 0 and "requires root" in result.stderr
        assert "QUJDRA" not in result.stdout + result.stderr

print("PASS: root-only public CLI, direct inert renderer contracts, key preservation, four-key and refusal cases")
