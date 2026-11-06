"""Exercise the installed guard helper's inherited Linux flock admission."""

import fcntl
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HELPER = Path(__file__).resolve().parents[1] / "aegis-device-egress-guard.sh"


class InheritedGuardLockTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0,
                         "requires Linux root and actual /proc fdinfo")
    def test_original_flock_duplicate_and_unlocked_countercases(self):
        source = HELPER.read_text(encoding="utf-8")
        script = (source.split("<<'PY_AUTO_LOCK'", 1)[1]
                 .split("\n", 1)[1]
                 .split("\nPY_AUTO_LOCK", 1)[0])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "guard.lock"
            fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                duplicate = os.dup(fd)
                try:
                    def admitted(candidate):
                        result = subprocess.run(
                            [sys.executable, "-c", script, str(candidate), str(path)],
                            pass_fds=(candidate,), capture_output=True, timeout=3,
                            check=False)
                        return result.returncode == 0

                    self.assertTrue(admitted(duplicate))
                    separate = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
                    try:
                        self.assertFalse(admitted(separate))
                    finally:
                        os.close(separate)
                    fcntl.flock(fd, fcntl.LOCK_UN)
                    self.assertFalse(admitted(duplicate))
                finally:
                    os.close(duplicate)
            finally:
                os.close(fd)


if __name__ == "__main__":
    unittest.main()
