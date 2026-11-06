#!/usr/bin/env python3
"""Render one inert, source-bound HTTPS bridge pilot for the free jump host.

This writes private config/unit templates only. It never creates credentials,
contacts the host, changes DNS/firewall/routes, or starts a listener.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

os.umask(0o077)
HOST_IP = "198.51.100.171"
AUTHORITY = "bridge.example.com"
TRAFFIC_PATH = "/private/stream"
ENROLLMENT_PATH = "/private/enroll"
ROOT = Path("/var/lib/aegis-ownbridge-pilot")
KEY_PINS = (
    "relay_outer_key", "relay_inner_key", "relay_admission",
    "authority_outer_key", "authority_inner_key", "authority_admission",
    "issuer_ca_key",
)


def need(ok, label):
    if not ok:
        raise ValueError(label)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def hex_digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def private_file(path):
    need(path.is_absolute() and path.parent.resolve(strict=True) == path.parent,
         "private_pin_file_required")
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent = os.fstat(parent_fd)
        need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid() and
             not parent.st_mode & 0o077, "private_pin_file_required")
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=parent_fd)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                 and before.st_nlink == 1 and not before.st_mode & 0o077
                 and before.st_size <= 4096, "private_pin_file_required")
            raw = stream.read(4097)
            after = os.fstat(stream.fileno())
            need(len(raw) == before.st_size and
                 (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                  before.st_ctime_ns) ==
                 (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                  after.st_ctime_ns),
                 "private_pin_file_changed")
            return raw
    finally:
        os.close(parent_fd)


def source_commit_exists(source):
    repo = Path(__file__).resolve().parents[1]
    def git(*args):
        return subprocess.run(["git", *args], cwd=repo, capture_output=True,
                              timeout=15, check=False)
    kind = git("cat-file", "-t", source)
    head = git("rev-parse", "HEAD")
    status = git("status", "--porcelain", "--untracked-files=all")
    blob = git("show", source + ":scripts/render-own-https-bridge-pilot.py")
    need(kind.returncode == head.returncode == status.returncode == blob.returncode == 0
         and kind.stdout == b"commit\n" and head.stdout.strip() == source.encode()
         and not status.stdout and blob.stdout == Path(__file__).read_bytes(),
         "source_checkout_or_renderer_not_exact")


def render(source, binary_sha, profile_sha, nonce, pins):
    need(re.fullmatch(r"[0-9a-f]{40}", source) is not None and
         hex_digest(binary_sha) and hex_digest(profile_sha) and
         re.fullmatch(r"[0-9a-f]{32}", nonce) is not None,
         "source_artifact_profile_or_nonce_shape")
    need(type(pins) is dict and set(pins) == set(KEY_PINS) and
         all(hex_digest(value) for value in pins.values()) and
         pins["relay_admission"] == pins["authority_admission"] and
         len(set(pins.values())) == len(KEY_PINS) - 1,
         "bridge_key_pin_relationship_required")
    source_commit_exists(source)
    stage = ROOT / (source[:12] + "-" + nonce)
    stem = "aegis-ownbridge-" + nonce
    relay_unit = stem + "-relay.service"
    authority_unit = stem + "-authority.service"
    rollback_unit = stem + "-rollback.service"
    rollback_timer = stem + "-rollback.timer"
    server = stage / "bin" / "aegis-server"
    relay = stage / "private" / "relay"
    authority = stage / "private" / "authority"
    state = stage / "state"
    registry = state / "device-registry.json"
    rconfig = stage / "relay.toml"
    aconfig = stage / "authority.toml"
    relay_toml = f'''listen = "{HOST_IP}:443"
cert = "{relay / 'outer-cert.pem'}"
key = "{relay / 'outer-key.pem'}"
auth_token = ""
fallback = "close"

[logging]
include_sensitive_context = false

[rate_limit]
trusted_proxy_cidrs = []

[target_policy]
profile = "public_internet"

[transport]
quic_required = false

[transport.inner_tls]
cert = "{relay / 'inner-cert.pem'}"
key = "{relay / 'inner-key.pem'}"
client_ca = "{state / 'device-ca.pem'}"
device_registry = "{registry}"

[transport.https_bridge]
site_html = "<!doctype html><html lang='en'><title>Status</title><p>Service available.</p></html>"

[transport.https_bridge.carrier]
authority = "{AUTHORITY}"
path = "{TRAFFIC_PATH}"
enrollment_path = "{ENROLLMENT_PATH}"
credential_file = "{relay / 'admission.hex'}"
'''
    authority_toml = f'''listen = "{HOST_IP}:8443"
outer_cert = "{authority / 'outer-cert.pem'}"
outer_key = "{authority / 'outer-key.pem'}"

[inner_tls]
cert = "{authority / 'inner-cert.pem'}"
key = "{authority / 'inner-key.pem'}"

[issuer]
registry = "{registry}"
ca_cert = "{authority / 'issuer-ca-cert.pem'}"
ca_key = "{authority / 'issuer-ca-key.pem'}"
profile_sha256 = "{profile_sha}"
lifetime_secs = 86400
max_receipts = 16
max_receipt_bytes_total = 1048576
receipt_grace_secs = 60

[https_bridge]
site_html = "<!doctype html><html lang='en'><title>Status</title><p>Service available.</p></html>"

[https_bridge.carrier]
authority = "{AUTHORITY}"
path = "{TRAFFIC_PATH}"
enrollment_path = "{ENROLLMENT_PATH}"
credential_file = "{authority / 'admission.hex'}"
'''
    common = f'''Type=simple
User=root
Group=root
UMask=0077
Restart=no
RuntimeMaxSec=7200s
TimeoutStopSec=25s
KillMode=control-group
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectControlGroups=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
'''
    relay_service = f'''[Unit]
Description=Aegis own HTTPS bridge pilot relay {nonce}
After=network.target {authority_unit}
Requires={authority_unit}

[Service]
{common}InaccessiblePaths={authority}
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart={server} --config {rconfig}
'''
    authority_service = f'''[Unit]
Description=Aegis own HTTPS bridge pilot authority {nonce}
After=network.target

[Service]
{common}InaccessiblePaths={relay}
ReadWritePaths={state}
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart={server} enrollment serve --config {aconfig}
'''
    rollback = f'''#!/bin/sh
set -eu
for unit in {relay_unit} {authority_unit}; do
  fragment="$(/usr/bin/systemctl show "$unit" -p FragmentPath --value)"
  [ "$fragment" = "/etc/systemd/system/$unit" ] || exit 1
  /usr/bin/systemctl stop "$unit"
  [ "$(/usr/bin/systemctl show "$unit" -p MainPID --value)" = 0 ] || exit 1
  [ "$(/usr/bin/systemctl show "$unit" -p ControlPID --value)" = 0 ] || exit 1
done
'''
    rollback_service = f'''[Unit]
Description=Stop only Aegis own HTTPS bridge pilot {nonce}

[Service]
Type=oneshot
ExecStart=/bin/sh {stage / 'rollback.sh'}
TimeoutStartSec=90s
'''
    rollback_timer_body = f'''[Unit]
Description=Independent expiry of Aegis own HTTPS bridge pilot {nonce}

[Timer]
OnActiveSec=6900s
AccuracySec=1s
Persistent=false
Unit={rollback_unit}
'''
    files = {
        "relay.toml": relay_toml,
        "authority.toml": authority_toml,
        relay_unit: relay_service,
        authority_unit: authority_service,
        rollback_unit: rollback_service,
        rollback_timer: rollback_timer_body,
        "rollback.sh": rollback,
    }
    intent = {
        "schema": "aegis_own_https_bridge_pilot_render_v1",
        "source_commit": source, "binary_sha256_expected_unverified": binary_sha,
        "profile_sha256_expected_unverified": profile_sha,
        "host": HOST_IP, "tls_name": AUTHORITY,
        "relay_endpoint": f"{HOST_IP}:443", "authority_endpoint": f"{HOST_IP}:8443",
        "relay_unit": relay_unit, "authority_unit": authority_unit,
        "rollback_unit": rollback_unit, "rollback_timer": rollback_timer,
        "remote_stage": str(stage), "private_material_sha256_expected_unverified": pins,
        "credential_bytes_present": False, "binary_verified": False,
        "config_check_executed": False, "host_mutation": False,
        "rendered_sha256": {name: sha(body.encode()) for name, body in files.items()},
    }
    files["intent.json"] = json.dumps(intent, sort_keys=True, indent=2) + "\n"
    return files


def write(output, files):
    need(output.is_absolute() and output.parent.resolve(strict=True) == output.parent
         and output.name not in ("", ".", ".."), "private_new_output_required")
    need(not output.exists() and not output.is_symlink(), "private_new_output_required")
    parent_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent = os.fstat(parent_fd)
        need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid() and
             not parent.st_mode & 0o077, "private_new_output_required")
        os.mkdir(output.name, mode=0o700, dir_fd=parent_fd)
        output_fd = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=parent_fd)
        try:
            created = os.fstat(output_fd)
            need(stat.S_ISDIR(created.st_mode) and created.st_uid == os.geteuid()
                 and stat.S_IMODE(created.st_mode) == 0o700,
                 "new_output_identity_changed")
            for name, body in files.items():
                need(name not in ("", ".", "..") and "/" not in name,
                     "rendered_filename_invalid")
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=output_fd)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(body.encode())
                    stream.flush()
                    os.fsync(stream.fileno())
            after = os.fstat(output_fd)
            need((after.st_dev, after.st_ino, stat.S_IMODE(after.st_mode)) ==
                 (created.st_dev, created.st_ino, 0o700),
                 "new_output_identity_changed")
            os.fsync(output_fd)
            named_fd = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                               dir_fd=parent_fd)
            try:
                named = os.fstat(named_fd)
                need((named.st_dev, named.st_ino, stat.S_IMODE(named.st_mode)) ==
                     (created.st_dev, created.st_ino, 0o700),
                     "new_output_identity_changed")
            finally:
                os.close(named_fd)
            os.fsync(parent_fd)
        finally:
            os.close(output_fd)
    finally:
        os.close(parent_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--profile-sha256", required=True)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--material-pins", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        pins = json.loads(private_file(args.material_pins))
        files = render(args.source_commit, args.binary_sha256,
                       args.profile_sha256, args.nonce, pins)
        write(args.output_dir, files)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        parser.exit(1, "REFUSE: pilot render rejected\n")
    print("PASS: private pilot templates rendered; binary, keys, config and host unverified")


if __name__ == "__main__":
    main()
