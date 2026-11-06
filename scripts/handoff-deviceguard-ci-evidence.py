#!/usr/bin/env python3
"""Transfer only the bounded, flat, current CI driver's private evidence files."""
import argparse
import os
from pathlib import Path
import re
import stat


def require(condition):
    if not condition:
        raise ValueError("CI evidence custody refused")


def handoff(workspace, run, attempt, uid, gid, expected_owner=0):
    require(re.fullmatch(r"[1-9][0-9]{0,19}", run) is not None)
    require(re.fullmatch(r"[1-9][0-9]{0,9}", attempt) is not None)
    require(type(uid) is int and type(gid) is int and 0 < uid < 2**31 and 0 < gid < 2**31)
    base = Path(workspace)
    require(base.is_absolute() and ".." not in base.parts)
    parts = list(base.parts[1:]) + ["ci-output", "device-guard", "audit17-native-" + run + "-" + attempt]
    parents = [os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]
    try:
        for index, part in enumerate(parts):
            try:
                descriptor = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parents[-1])
            except FileNotFoundError:
                if index == len(parts) - 1:
                    for opened in reversed(parents):
                        os.close(opened)
                    return False
                raise
            parents.append(descriptor)
    except BaseException:
        for descriptor in reversed(parents):
            os.close(descriptor)
        raise
    if len(parents) != len(parts) + 1:
        for descriptor in reversed(parents):
            os.close(descriptor)
        return False
    directory = parents[-1]
    files = []
    try:
        directory_stat = os.fstat(directory)
        require(directory_stat.st_uid == expected_owner and stat.S_IMODE(directory_stat.st_mode) == 0o700)
        names = sorted(os.listdir(directory))
        require(1 <= len(names) <= 1024)
        literal = {"input-r1.json", "started-r1.json", "receipt-r1.json", "inside-receipt-r1.json",
                   "outer.log", "render-block.sh", "render-dhcp.sh", "block.nft", "dhcp.nft",
                   "export-complete-r1.json", "export-failure-r1.json"}
        total = 0
        for name in names:
            require(name in literal or re.fullmatch(r"command-[0-9]{3}\.(?:intent\.json|receipt\.json|stdout|stderr)", name))
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            files.append(descriptor)
            value = os.fstat(descriptor)
            require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and value.st_uid == expected_owner)
            require(stat.S_IMODE(value.st_mode) in (0o600, 0o644))
            require(0 <= value.st_size <= 1024 * 1024)
            total += value.st_size
            require(total <= 16 * 1024 * 1024)
            named = os.stat(name, dir_fd=directory, follow_symlinks=False)
            require((named.st_dev, named.st_ino) == (value.st_dev, value.st_ino))
        require(sorted(os.listdir(directory)) == names)
        # All entries are admitted before any mutation; use the opened handles,
        # never recursive chown or paths supplied by archived evidence.
        for descriptor in files:
            os.fchmod(descriptor, 0o600)
            os.fchown(descriptor, uid, gid)
        os.fchmod(directory, 0o700)
        os.fchown(directory, uid, gid)
        return True
    finally:
        for descriptor in files:
            os.close(descriptor)
        for descriptor in reversed(parents):
            os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--attempt", required=True)
    parser.add_argument("--uid", required=True, type=int)
    parser.add_argument("--gid", required=True, type=int)
    args = parser.parse_args()
    try:
        require(os.geteuid() == 0)
        transferred = handoff(args.workspace, args.run, args.attempt, args.uid, args.gid)
    except (OSError, ValueError):
        raise SystemExit("CI evidence handoff refused; private files retained")
    print("Current CI evidence transferred" if transferred else "No current CI evidence exists; native acceptance not established")


if __name__ == "__main__":
    main()
