"""The last possible OUTPUT hook decides cgroup authority after route chains."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import auto_guard_render_harness as harness


class OutputHookOrdering(unittest.TestCase):
    def test_guard_uses_last_output_priority(self):
        rc, text, error = harness.render(profile='full-wide-tun', uplink='up0',
            management_ports='', client=None, scoped=None)
        self.assertEqual(rc, 0, error)
        self.assertIn('hook output priority 2147483647; policy drop;', text)


if __name__=='__main__':unittest.main()
