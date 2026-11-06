#!/usr/bin/env python3
"""Inert source-contract tests for the read-only installed verifier."""

import hashlib
import importlib.util
import os
import tempfile
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("verify_export", HERE / "verify-device-policy-export-ssh.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def refuses(func, *args, **kwargs):
    try:
        func(*args, **kwargs)
    except (OSError, ValueError):
        return
    raise AssertionError("unsafe state accepted")


with tempfile.TemporaryDirectory(prefix="aegis-verify-export-") as tmp:
    root = Path(tmp)
    staging = root / "staging"
    installed = root / "installed"
    staging.mkdir(mode=0o700)
    installed.mkdir(mode=0o700)
    binary = root / "aegis-server"
    binary.write_bytes(b"synthetic versioned exporter\n")
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    commit = "a" * 40
    command = (
        f"{binary} device-policy export --registry "
        "/var/lib/aegis-device-authority/registry.json --forced-ssh"
    ).encode()
    settings = {**module.FIELDS, "authorizedkeysfile": str(installed / module.renderer.ROSTER),
                "forcecommand": command.decode()}
    settings_root = {"permituserenvironment": "no"}
    calls = []

    def fake_sshd(sshd, config, *, user=None, addr=None):
        calls.append((user, addr))
        return None if user is None else settings if user == "aegis-policy-export" else settings_root

    with mock.patch.object(module, "versioned_binary", return_value=binary), \
         mock.patch.object(module.renderer, "source_binary", return_value=str(binary)), \
         mock.patch.object(module, "run_sshd", side_effect=fake_sshd):
        rendered = module.renderer.expected(commit)
        assert module.expected_without_git(commit) == rendered
        roster = b"".join(
            b'restrict,command="' + command + b'" ssh-ed25519 QUJDRA== synthetic-%d\n' % i
            for i in range(4)
        )
        bodies = {**rendered, module.renderer.ROSTER: roster}
        for name, body in bodies.items():
            (staging / name).write_bytes(body)
            (staging / name).chmod(0o600)
        snippet = installed / module.renderer.SNIPPET
        keys = installed / module.renderer.ROSTER
        config = root / "sshd_config"
        config.write_text(f"Include {snippet}\n")
        config.chmod(0o644)
        snippet.write_bytes(rendered[module.renderer.SNIPPET])
        keys.write_bytes(roster)
        snippet.chmod(0o644)
        keys.chmod(0o644)
        kwargs = dict(sshd=Path("/usr/sbin/sshd"), config=config,
                      snippet=snippet, roster=keys, owner=os.geteuid())
        args = (commit, digest, binary, staging, list(module.RELAY_SOURCES))
        module.verify(*args, **kwargs)
        assert calls == [(None, None)] + [
            (user, address) for address in module.RELAY_SOURCES
            for user in ("aegis-policy-export", "aegis-policy-global-check")
        ]

        refuses(module.verify, commit, digest, binary, staging, list(reversed(module.RELAY_SOURCES)), **kwargs)
        keys.write_bytes(roster.replace(b"synthetic-0", b"changed-0"))
        refuses(module.verify, *args, **kwargs)
        keys.write_bytes(roster)
        bad = roster.replace(b"--forced-ssh", b"--bad-ssh", 1)
        (staging / module.renderer.ROSTER).write_bytes(bad)
        refuses(module.verify, *args, **kwargs)
        (staging / module.renderer.ROSTER).write_bytes(roster)
        snippet.write_bytes(rendered[module.renderer.SNIPPET].replace(b"MaxSessions 1", b"MaxSessions 2"))
        refuses(module.verify, *args, **kwargs)
        snippet.write_bytes(rendered[module.renderer.SNIPPET])
        snippet.chmod(0o666)
        refuses(module.verify, *args, **kwargs)
        snippet.chmod(0o644)
        alias = installed / "alias"
        os.link(keys, alias)
        refuses(module.verify, *args, **kwargs)
        alias.unlink()
        binary.write_bytes(b"changed binary\n")
        refuses(module.verify, *args, **kwargs)

        binary.write_bytes(b"synthetic versioned exporter\n")
        for predicate in ("Host localhost", "Address 198.51.100.229", "LocalAddress 127.0.0.1", "LocalPort 22", "All"):
            extra = installed / "91-other.conf"
            extra.write_text(f"Match {predicate}\nPasswordAuthentication yes\n")
            extra.chmod(0o644)
            config.write_text(f"Include {installed}/*.conf\n")
            refuses(module.verify, *args, **kwargs)
            extra.unlink()
        config.write_text("# exporter omitted\n")
        refuses(module.verify, *args, **kwargs)
        config.write_text(f"Include {snippet}\n")
        module.verify(*args, **kwargs)
        cloud = installed / "50-cloud-init.conf"
        cloud.write_text("PasswordAuthentication yes\n")
        cloud.chmod(0o600)
        config.write_text(f"Include {installed}/*.conf\n")
        module.verify(*args, **kwargs)
        cloud.chmod(0o666)
        refuses(module.verify, *args, **kwargs)
        cloud.unlink()

    effective = {**module.FIELDS, "authorizedkeysfile": str(installed / module.renderer.ROSTER),
                 "forcecommand": command.decode()}
    module.verify_effective(effective, command.decode(), export_user=True,
                            roster_path=str(installed / module.renderer.ROSTER))
    refuses(module.verify_effective, {**effective, "authorizedkeysfile": "/etc/ssh/old"},
            command.decode(), export_user=True, roster_path=str(installed / module.renderer.ROSTER))
    for key in module.FIELDS:
        bad = {**effective, key: "no" if module.FIELDS[key] != "no" else "yes"}
        refuses(module.verify_effective, bad, command.decode(), export_user=True,
                roster_path=str(installed / module.renderer.ROSTER))
    refuses(module.verify_effective, {**effective, "forcecommand": "wrong"}, command.decode(),
            export_user=True, roster_path=str(installed / module.renderer.ROSTER))
    refuses(module.verify_effective, {"permituserenvironment": "yes"}, command.decode(),
            export_user=False, roster_path=str(installed / module.renderer.ROSTER))
    refuses(module.parse_effective, b"permittty no\npermittty yes\n")
    refuses(module.parse_effective, b"garbage\n")

print("PASS: installed byte custody, four-key roster, three-source effective policy, and refusal cases")
