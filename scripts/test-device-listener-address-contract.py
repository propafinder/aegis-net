#!/usr/bin/env python3
"""Exercise the real full-wide listener parser with Linux ss address forms."""

import ipaddress
from pathlib import Path


source = (Path(__file__).resolve().parent.parent / "install.sh").read_text()
body = source.split("def listener_address(local):\n", 1)[1].split("\nports=set()", 1)[0]
namespace = {
    "ipaddress": ipaddress,
    "need": lambda ok, message: None if ok else (_ for _ in ()).throw(ValueError(message)),
}
exec(compile("def listener_address(local):\n" + body, "install.sh listener_address", "exec"), namespace)
parse = namespace["listener_address"]

assert parse("[fe80::5055:55ff:fe5d:ed09]%lima0:546") == (
    "fe80::5055:55ff:fe5d:ed09", "546")
assert parse("[::]:22") == ("::", "22")
assert parse("127.0.0.53%lo:53") == ("127.0.0.53", "53")
assert parse("192.168.64.6%lima0:68") == ("192.168.64.6", "68")
for malformed in ("[fe80::1%lima0:546", "[fe80::1]%lima0:notaport",
                  "[fe80::1]%lima0:0", "[invalid]%lima0:546"):
    try:
        parse(malformed)
    except ValueError:
        continue
    raise AssertionError(f"accepted malformed listener {malformed!r}")

print("PASS: real full-wide listener parser accepts scoped ss IPv4/IPv6 and refuses malformed forms")
