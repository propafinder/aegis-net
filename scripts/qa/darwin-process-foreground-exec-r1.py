#!/usr/bin/env python3
"""Normalize only this Darwin process's inherited background policy before exec."""

import ctypes
import json
import os
import sys

PRIO_PROCESS = 0
PRIO_DARWIN_PROCESS = 4


def priority(libc, which):
    ctypes.set_errno(0)
    value = libc.getpriority(which, 0)
    if ctypes.get_errno():
        raise RuntimeError("getpriority_refused")
    return value


def run(argv, platform=sys.platform, library=None, execute=os.execvp, emit=None):
    if platform != "darwin" or len(argv) < 2 or argv[0] != "--" or not argv[1]:
        raise RuntimeError("platform_or_argv_refused")
    libc = library or ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    libc.getpriority.argtypes = (ctypes.c_int, ctypes.c_int)
    libc.getpriority.restype = ctypes.c_int
    libc.setpriority.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_int)
    libc.setpriority.restype = ctypes.c_int
    before_policy = priority(libc, PRIO_DARWIN_PROCESS)
    before_nice = priority(libc, PRIO_PROCESS)
    ctypes.set_errno(0)
    if libc.setpriority(PRIO_DARWIN_PROCESS, 0, 0) != 0:
        raise RuntimeError("setpriority_refused")
    after_policy = priority(libc, PRIO_DARWIN_PROCESS)
    after_nice = priority(libc, PRIO_PROCESS)
    if after_policy != 0 or after_nice != before_nice:
        raise RuntimeError("priority_readback_refused")
    record = {"inherited_policy": before_policy, "policy": after_policy,
              "inherited_nice": before_nice, "nice": after_nice}
    (emit or (lambda value: print(json.dumps(value, sort_keys=True), file=sys.stderr, flush=True)))(record)
    execute(argv[1], argv[1:])


if __name__ == "__main__":
    try:
        run(sys.argv[1:])
    except (OSError, RuntimeError):
        print("darwin_process_policy_refused", file=sys.stderr)
        raise SystemExit(73) from None
