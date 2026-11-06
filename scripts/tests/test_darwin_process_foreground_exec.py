"""Inert admission tests for the Darwin self-process CI launcher."""

import ctypes
import importlib.util
from pathlib import Path
import unittest


MODULE = Path(__file__).resolve().parents[1] / "qa/darwin-process-foreground-exec-r1.py"
SPEC = importlib.util.spec_from_file_location("darwin_foreground", MODULE)
LAUNCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER)


class Call:
    def __init__(self, func):
        self.func = func

    def __call__(self, *args):
        return self.func(*args)


class Lib:
    def __init__(self, *, policy=1, nice=0, set_error=False, stuck=False, nice_change=False,
                 read_error=False):
        self.policy = policy
        self.nice = nice
        self.set_error = set_error
        self.stuck = stuck
        self.nice_change = nice_change
        self.read_error = read_error
        self.getpriority = Call(self.get)
        self.setpriority = Call(self.set)

    def get(self, which, pid):
        assert pid == 0
        if self.read_error:
            ctypes.set_errno(1)
            return -1
        return self.policy if which == LAUNCHER.PRIO_DARWIN_PROCESS else self.nice

    def set(self, which, pid, value):
        assert (which, pid, value) == (LAUNCHER.PRIO_DARWIN_PROCESS, 0, 0)
        if self.set_error:
            ctypes.set_errno(1)
            return -1
        if not self.stuck:
            self.policy = 0
        if self.nice_change:
            self.nice = 5
        return 0


class LauncherTests(unittest.TestCase):
    def invoke(self, lib, platform="darwin", argv=("--", "probe", "observed")):
        executed, emitted = [], []
        def execute(*args):
            executed.append(args)
        try:
            LAUNCHER.run(list(argv), platform=platform, library=lib, execute=execute,
                         emit=emitted.append)
        except RuntimeError:
            self.assertEqual(executed, [])
            return None
        self.assertEqual(executed, [("probe", ["probe", "observed"])])
        self.assertEqual(len(emitted), 1)
        return emitted[0]

    def test_inherited_background_execs_with_normal_own_policy_and_same_nice(self):
        self.assertEqual(self.invoke(Lib(policy=1, nice=4)),
                         {"inherited_policy": 1, "policy": 0,
                          "inherited_nice": 4, "nice": 4})

    def test_refusals_never_exec(self):
        for lib in (Lib(set_error=True), Lib(stuck=True), Lib(nice_change=True),
                    Lib(read_error=True)):
            with self.subTest(lib=vars(lib)):
                self.assertIsNone(self.invoke(lib))
        self.assertIsNone(self.invoke(Lib(), platform="linux"))
        self.assertIsNone(self.invoke(Lib(), argv=("probe",)))


if __name__ == "__main__":
    unittest.main()
