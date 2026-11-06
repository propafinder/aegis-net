#!/usr/bin/env python3
"""Render an inert TLS-passthrough 443 front for separate relay/issuer roles.

The front never terminates TLS or reads private keys. Installing and accepting
the generated configuration is a separate operator/deployment transaction.
"""

import argparse
import ipaddress
import os
import re
import stat
from pathlib import Path


NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")


def dns_name(value: str) -> str:
    if len(value) > 253 or not NAME.fullmatch(value) or value.endswith(".invalid"):
        raise ValueError("SNI must be a bounded lowercase DNS name")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError("SNI cannot be an IP literal")
    return value


def socket(value: str, *, public: bool) -> str:
    if value.startswith("["):
        host, sep, port_text = value[1:].partition("]:")
        if not sep:
            raise ValueError("socket requires an IPv6 address and port")
    else:
        host, sep, port_text = value.rpartition(":")
        if not sep:
            raise ValueError("socket requires address and port")
    try:
        address = ipaddress.ip_address(host)
        port = int(port_text)
    except ValueError as exc:
        raise ValueError("socket must use a numeric IP and port") from exc
    if not 1 <= port <= 65535 or (public and port != 443) or (not public and port == 443):
        raise ValueError("public port must be 443; private ports must differ")
    if public:
        if address.is_loopback or address.is_multicast or address.is_unspecified:
            raise ValueError("public bind address is not externally routable")
    elif not address.is_loopback:
        raise ValueError("backend must bind loopback only")
    return f"[{address}]:{port}" if address.version == 6 else f"{address}:{port}"


def render(public_bind: str, relay_name: str, relay_local: str,
           enrollment_name: str, enrollment_local: str) -> bytes:
    bind = socket(public_bind, public=True)
    relay = socket(relay_local, public=False)
    enrollment = socket(enrollment_local, public=False)
    relay_name = dns_name(relay_name)
    enrollment_name = dns_name(enrollment_name)
    if relay_name == enrollment_name or relay == enrollment:
        raise ValueError("relay and enrollment roles require distinct SNI and loopback sockets")
    return f"""# Aegis separate-role TLS passthrough; no PROXY protocol or TLS termination.
global
    daemon
defaults
    mode tcp
    timeout connect 5s
    timeout client 45s
    timeout server 45s
frontend aegis_public_443
    bind {bind}
    mode tcp
    tcp-request inspect-delay 5s
    tcp-request content accept if {{ req.ssl_hello_type 1 }}
    use_backend aegis_relay if {{ req.ssl_sni -i {relay_name} }}
    use_backend aegis_enrollment if {{ req.ssl_sni -i {enrollment_name} }}
    default_backend aegis_reject
backend aegis_relay
    server relay {relay} check
backend aegis_enrollment
    server enrollment {enrollment} check
backend aegis_reject
    # No server: unrecognized or absent SNI closes without reaching either role.
""".encode("ascii")


def write_new(output: Path, body: bytes) -> None:
    if not output.is_absolute() or output.is_symlink():
        raise ValueError("output must be a new absolute regular path")
    parent = output.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
        raise ValueError("output parent must be a private owned directory")
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as result:
        result.write(body)
        result.flush()
        os.fsync(result.fileno())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-bind", required=True)
    parser.add_argument("--relay-name", required=True)
    parser.add_argument("--relay-local", required=True)
    parser.add_argument("--enrollment-name", required=True)
    parser.add_argument("--enrollment-local", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        body = render(args.public_bind, args.relay_name, args.relay_local,
                      args.enrollment_name, args.enrollment_local)
        write_new(args.output, body)
    except (OSError, ValueError):
        parser.exit(1, "carrier 443 render refused\n")
    print("carrier 443 source configuration staged; deployment and acceptance pending")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
