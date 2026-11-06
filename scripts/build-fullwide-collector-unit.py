#!/usr/bin/env python3
"""Render an inert, independently owned B-03 packet collector systemd unit.

The output is a proposed unit file. This command does not install or start it.
The operator must independently pin the guest tcpdump digest, loaded command,
capture file and process identity before installed acceptance.
"""

import argparse
import re
import sys


def render(run_id: str, uplink: str, executable: str) -> str:
    if not re.fullmatch(r"[a-z0-9]{1,12}", run_id):
        raise ValueError("run ID must be one to twelve lowercase letters or digits")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", uplink) or uplink[0] == "-" or uplink in (".", ".."):
        raise ValueError("invalid literal Linux uplink")
    if executable not in ("/usr/bin/tcpdump", "/usr/sbin/tcpdump"):
        raise ValueError("unsupported fixed tcpdump location")
    output = f"/var/lib/aegis-fullwide-capture/{run_id}.pcap"
    return (
        "[Unit]\n"
        "Description=Independent B-03 full-wide packet collector\n"
        f"ConditionPathExists=!{output}\n"
        "\n"
        "[Service]\n"
        "Type=exec\n"
        "User=root\n"
        "Group=root\n"
        "UMask=0077\n"
        "StateDirectory=aegis-fullwide-capture\n"
        "StateDirectoryMode=0700\n"
        "ProtectSystem=strict\n"
        "ReadWritePaths=/var/lib/aegis-fullwide-capture\n"
        "NoNewPrivileges=yes\n"
        "PrivateTmp=yes\n"
        "Restart=no\n"
        "KillMode=control-group\n"
        "TimeoutStopSec=10\n"
        f"ExecStart={executable} -i {uplink} -s 0 -U -Z root -w {output}\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--uplink", required=True)
    parser.add_argument("--tcpdump", required=True)
    args = parser.parse_args()
    try:
        sys.stdout.write(render(args.run_id, args.uplink, args.tcpdump))
    except ValueError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
