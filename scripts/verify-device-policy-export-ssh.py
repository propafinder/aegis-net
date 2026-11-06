#!/usr/bin/env python3
"""Read-only, fail-closed installed SSH exporter policy verifier.

This checks bytes and effective sshd settings after a guarded, single-snippet switch.
It does not deploy, reload sshd, authenticate a relay, or prove a live ACK.
"""

import argparse
import glob
import importlib.util
import os
import re
import shlex
import stat
import subprocess
from pathlib import Path


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("export_renderer", HERE / "render-device-policy-export-ssh.py")
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)

CONFIG = Path("/etc/ssh/sshd_config")
INSTALLED_SNIPPET = Path("/etc/ssh/sshd_config.d/90-aegis-policy-export.conf")
RELAY_SOURCES = ("198.51.100.229", "198.51.100.77", "198.51.100.205")
FIELDS = {
    "authorizedkeyscommand": "none",
    "authorizedkeyscommanduser": "none",
    "trustedusercakeys": "none",
    "authorizedprincipalsfile": "none",
    "authorizedprincipalscommand": "none",
    "authorizedprincipalscommanduser": "none",
    "pubkeyauthentication": "yes",
    "authenticationmethods": "publickey",
    "passwordauthentication": "no",
    "kbdinteractiveauthentication": "no",
    "disableforwarding": "yes",
    "permittty": "no",
    "permituserrc": "no",
    "permittunnel": "no",
    "maxsessions": "1",
    "permituserenvironment": "no",
}


def protected_file(path: Path, mode: int, owner: int = 0) -> bytes:
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != owner or parent.st_mode & 0o022:
        raise ValueError(f"untrusted parent: {path.name}")
    return renderer.read_regular(path, owner=owner, mode=mode)


def protected_config_file(path: Path, owner: int = 0) -> bytes:
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != owner or parent.st_mode & 0o022:
        raise ValueError(f"untrusted sshd config parent: {path.name}")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != owner:
            raise ValueError("untrusted sshd config file")
        if stat.S_IMODE(before.st_mode) not in (0o600, 0o644) or before.st_size > renderer.MAX_BYTES:
            raise ValueError("unexpected sshd config mode or size")
        data = handle.read(renderer.MAX_BYTES + 1)
        after = os.fstat(handle.fileno())
    if len(data) != before.st_size or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError("sshd config changed while reading")
    return data


def versioned_binary(source: str) -> Path:
    if re.fullmatch(r"[0-9a-f]{40}", source) is None:
        raise ValueError("source commit must be a full lowercase SHA-1")
    return Path(f"/opt/aegis/{source}/bin/aegis-server")


def expected_without_git(source: str) -> dict[str, bytes]:
    """Mirror the renderer's exact template for use on a host without Git."""
    command = (
        f"{versioned_binary(source)} device-policy export "
        "--registry /var/lib/aegis-device-authority/registry.json --forced-ssh"
    )
    snippet = (
        "# Generated for one independently attested server binary.\n"
        "Match User aegis-policy-export\n"
        f"    AuthorizedKeysFile {renderer.versioned_roster_path(source)}\n"
        f"    ForceCommand {command}\n"
        "    AuthenticationMethods publickey\n"
        "    PasswordAuthentication no\n"
        "    KbdInteractiveAuthentication no\n"
        "    DisableForwarding yes\n"
        "    PermitTTY no\n"
        "    PermitUserRC no\n"
        "    PermitTunnel no\n"
        "    MaxSessions 1\n"
        "Match all\n"
    ).encode("ascii")
    return {
        renderer.SNIPPET: snippet,
        renderer.PREFIX: f'restrict,command="{command}"\n'.encode("ascii"),
    }


def verify_roster(data: bytes, forced_command: bytes, expected_count: int) -> None:
    count = 0
    for line in data.splitlines():
        if not line.strip() or line.lstrip().startswith(b"#"):
            continue
        # Reuse the renderer's restrictive parser. Identity replacement here
        # proves every key carries exactly this forced command and no other.
        if renderer.rewrite_key_line(line, forced_command, forced_command) != line:
            raise ValueError("authorized-key line differs after identity rewrite")
        count += 1
    if count != expected_count:
        raise ValueError("unexpected authorized-key entry count")


def parse_effective(output: bytes) -> dict[str, str]:
    if len(output) > 65536:
        raise ValueError("unbounded sshd effective output")
    settings = {}
    for line in output.decode("ascii").splitlines():
        key, sep, value = line.partition(" ")
        if not sep or not key or key in settings:
            raise ValueError("malformed or repeated sshd effective setting")
        settings[key] = value.strip()
    return settings


def scan_match_scope(config: Path, snippet: Path, *, owner: int = 0) -> None:
    """Reject every SSH Match stanza except the byte-checked exporter stanza.

    The effective probes use a fixed host/laddr/lport. They are sound for this
    source boundary only when no other Match predicate can select a different
    policy. Follow all absolute Include files, including glob expansion, and
    refuse unexamined or changing config trees.
    """
    visited: set[Path] = set()
    found_exporter = 0
    found_reset = 0

    def visit(path: Path, depth: int) -> None:
        nonlocal found_exporter, found_reset
        if depth > 4 or len(visited) >= 32 or not path.is_absolute() or path in visited:
            raise ValueError("unbounded or repeated sshd Include")
        visited.add(path)
        data = protected_config_file(path, owner)
        for raw in data.decode("ascii").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "\\" in line:
                raise ValueError("unreviewed sshd line continuation or escape")
            try:
                tokens = shlex.split(line, comments=True, posix=True)
            except ValueError as exc:
                raise ValueError("malformed sshd config line") from exc
            if not tokens:
                continue
            directive = tokens[0].lower()
            if directive == "match":
                if path != snippet:
                    raise ValueError("unreviewed sshd Match predicate")
                if tokens == ["Match", "User", "aegis-policy-export"]:
                    found_exporter += 1
                elif tokens == ["Match", "all"] and found_exporter == 1 and found_reset == 0:
                    found_reset += 1
                else:
                    raise ValueError("unreviewed sshd Match predicate")
            elif directive == "include":
                if len(tokens) < 2:
                    raise ValueError("empty sshd Include")
                for pattern in tokens[1:]:
                    candidate = Path(pattern)
                    if not candidate.is_absolute() or any(char in str(candidate.parent) for char in "*?["):
                        raise ValueError("unreviewed sshd Include path")
                    parent = candidate.parent.lstat()
                    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != owner or parent.st_mode & 0o022:
                        raise ValueError("untrusted sshd Include parent")
                    matches = []
                    for name in glob.iglob(pattern):
                        matches.append(Path(name))
                        if len(matches) > 32:
                            raise ValueError("sshd Include expands too many files")
                    matches.sort()
                    if not matches:
                        raise ValueError("sshd Include matched no files")
                    for included in matches:
                        visit(included, depth + 1)

    visit(config, 0)
    if found_exporter != 1 or found_reset != 1 or snippet not in visited:
        raise ValueError("source-checked exporter Match and reset were not included exactly once")


def run_sshd(sshd: Path, config: Path, *, user: str | None = None, addr: str | None = None) -> dict[str, str] | None:
    command = [str(sshd), "-T" if user else "-t", "-f", str(config)]
    if user:
        command += ["-C", f"user={user},host=localhost,addr={addr}"]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=False)
    if result.returncode != 0:
        raise ValueError("sshd configuration check refused")
    return parse_effective(result.stdout) if user else None


def verify_effective(settings: dict[str, str], command: str, *, export_user: bool,
                     roster_path: str) -> None:
    if settings.get("permituserenvironment") != "no":
        raise ValueError("effective PermitUserEnvironment is not no")
    if not export_user:
        return
    if settings.get("authorizedkeysfile") != roster_path:
        raise ValueError("unexpected effective AuthorizedKeysFile")
    for key, value in FIELDS.items():
        if settings.get(key) != value:
            raise ValueError(f"unexpected effective setting: {key}")
    if settings.get("forcecommand") != command:
        raise ValueError("effective ForceCommand differs from source render")


def verify(source: str, binary_digest: str, binary: Path, staged: Path, addresses: list[str],
           *, sshd: Path = Path("/usr/sbin/sshd"), config: Path = CONFIG,
           snippet: Path = INSTALLED_SNIPPET, roster: Path | None = None,
           owner: int = 0, count: int = 4) -> None:
    if tuple(addresses) != RELAY_SOURCES:
        raise ValueError("relay source addresses differ from the reviewed fleet roster")
    if re.fullmatch(r"[0-9a-f]{64}", binary_digest) is None:
        raise ValueError("binary SHA-256 must be full lowercase hex")
    expected = expected_without_git(source)
    renderer.verify_binary(binary, binary_digest)
    versioned = versioned_binary(source)
    if roster is None:
        roster = renderer.versioned_roster_path(source)
    if binary != versioned:
        raise ValueError("binary path differs from versioned source path")
    staged_meta = staged.lstat()
    if not stat.S_ISDIR(staged_meta.st_mode) or staged_meta.st_uid != owner or stat.S_IMODE(staged_meta.st_mode) != 0o700:
        raise ValueError("staging directory must be private and owner-controlled")
    for name in (renderer.SNIPPET, renderer.PREFIX, renderer.ROSTER):
        protected_file(staged / name, 0o600, owner)
    if protected_file(staged / renderer.SNIPPET, 0o600, owner) != expected[renderer.SNIPPET]:
        raise ValueError("staged snippet differs from source")
    if protected_file(staged / renderer.PREFIX, 0o600, owner) != expected[renderer.PREFIX]:
        raise ValueError("staged command prefix differs from source")
    proposed_roster = protected_file(staged / renderer.ROSTER, 0o600, owner)
    command = expected[renderer.PREFIX].removeprefix(b'restrict,command="').removesuffix(b'"\n')
    verify_roster(proposed_roster, command, count)
    if protected_file(snippet, 0o644, owner) != expected[renderer.SNIPPET]:
        raise ValueError("installed snippet differs from source")
    if protected_file(roster, 0o644, owner) != proposed_roster:
        raise ValueError("installed roster differs from staged bytes")
    scan_match_scope(config, snippet, owner=owner)
    run_sshd(sshd, config)
    for addr in addresses:
        verify_effective(run_sshd(sshd, config, user="aegis-policy-export", addr=addr),
                         command.decode("ascii"), export_user=True,
                         roster_path=str(roster))
        verify_effective(run_sshd(sshd, config, user="aegis-policy-global-check", addr=addr),
                         command.decode("ascii"), export_user=False,
                         roster_path=str(roster))
    # Detect an ordinary concurrent replacement during the bounded sshd probe.
    # The maintenance owner still has to hold the independent change window.
    if protected_file(snippet, 0o644, owner) != expected[renderer.SNIPPET] or \
       protected_file(roster, 0o644, owner) != proposed_roster:
        raise ValueError("installed policy changed during effective check")
    scan_match_scope(config, snippet, owner=owner)
    renderer.verify_binary(binary, binary_digest)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--staged-dir", type=Path, required=True)
    parser.add_argument("--relay-source-address", action="append", required=True)
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise ValueError("installed policy verifier requires root")
        binary = versioned_binary(args.source_commit)
        verify(args.source_commit, args.binary_sha256, binary, args.staged_dir,
               args.relay_source_address)
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired) as exc:
        parser.exit(1, f"REFUSE: {exc}\n")
    print("PASS: installed bytes and three-source effective sshd policy match; live pulls/ACKs untested")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
