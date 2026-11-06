#!/usr/bin/env python3
"""Inert same-443 SNI routing controls; no host or network effects."""

import importlib.util
import os
import stat
import tempfile
from pathlib import Path


TOOL = Path(__file__).with_name("render-carrier-443-sni.py")
spec = importlib.util.spec_from_file_location("carrier_443", TOOL)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def candidate(**changes: str) -> dict[str, str]:
    values = dict(public_bind="192.0.2.10:443", relay_name="relay.example.com",
                  relay_local="127.0.0.1:14443", enrollment_name="enroll.example.com",
                  enrollment_local="127.0.0.1:19445")
    values.update(changes)
    return values


body = module.render(**candidate())
assert b"bind 192.0.2.10:443\n" in body
assert b"use_backend aegis_relay if { req.ssl_sni -i relay.example.com }" in body
assert b"use_backend aegis_enrollment if { req.ssl_sni -i enroll.example.com }" in body
assert b"default_backend aegis_reject\n" in body
assert b"send-proxy" not in body and b"ssl crt" not in body
assert body.split(b"\nbackend aegis_reject\n", 1)[1].count(b"server ") == 0
for changes in (
    {"relay_name": "enroll.example.com"},
    {"relay_name": "relay.example.com;\nserver bad 0.0.0.0:1"},
    {"relay_name": "192.0.2.10"},
    {"enrollment_local": "0.0.0.0:19445"},
    {"enrollment_local": "127.0.0.1:14443"},
    {"relay_local": "127.0.0.1:443"},
    {"public_bind": "127.0.0.1:443"},
    {"public_bind": "192.0.2.10:9445"},
):
    try:
        module.render(**candidate(**changes))
    except ValueError:
        pass
    else:
        raise AssertionError(f"unsafe carrier front was accepted: {list(changes)}")

with tempfile.TemporaryDirectory() as private:
    parent = Path(private)
    os.chmod(parent, 0o700)
    output = parent / "carrier.cfg"
    module.write_new(output, body)
    assert output.read_bytes() == body
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    try:
        module.write_new(output, body)
    except FileExistsError:
        pass
    else:
        raise AssertionError("existing candidate was overwritten")
    os.chmod(parent, 0o755)
    try:
        module.write_new(parent / "unsafe.cfg", body)
    except ValueError:
        pass
    else:
        raise AssertionError("public output directory was accepted")

print("PASS: same-443 relay/enrollment SNI source controls")
