"""Stop/restart regression for the actual witness listener and signal path."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'lib/aegis_auto_witness_topology.py'
CHILD = r'''
import importlib.util,os,pathlib,socket,sys
spec=importlib.util.spec_from_file_location('witness',sys.argv[1]);m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
m.RUNTIME=pathlib.Path(sys.argv[2]);m.AUTHORITY=m.RUNTIME/'authority.sock'
m._safe_runtime=lambda:None
m.os.geteuid=lambda:0
m._notify=lambda value:(m.RUNTIME/'ready').touch() if value=='READY=1' else None
m.serve()
'''


@unittest.skipUnless(sys.platform == 'linux', 'Linux /proc and UNIX SEQPACKET actor')
class WitnessShutdownTests(unittest.TestCase):
    def test_real_sigterm_releases_listener_and_allows_second_start(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for _ in range(2):
                ready = root / 'ready'
                if ready.exists():
                    ready.unlink()
                process = subprocess.Popen([sys.executable, '-I', '-B', '-c', CHILD,
                                            str(SOURCE), str(root)],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    end = time.monotonic() + 5
                    while not ready.exists() and process.poll() is None and time.monotonic() < end:
                        time.sleep(0.01)
                    self.assertTrue(ready.exists())
                    self.assertTrue((root / 'authority.sock').is_socket())
                    process.send_signal(signal.SIGTERM)
                    out, err = process.communicate(timeout=5)
                    self.assertEqual((process.returncode, out, err), (0, b'', b''))
                    self.assertFalse((root / 'authority.sock').exists())
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.communicate(timeout=5)


if __name__ == '__main__':
    unittest.main()
