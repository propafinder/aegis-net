#!/usr/bin/env python3
"""Bounded source contract for the inert B-03 collector unit renderer."""

import importlib.util
from pathlib import Path
import shlex
import subprocess
import sys
import unittest


SOURCE = Path(__file__).with_name("build-fullwide-collector-unit.py")
SPEC = importlib.util.spec_from_file_location("build_fullwide_collector_unit", SOURCE)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class CollectorUnitContract(unittest.TestCase):
    def test_exact_command_and_private_state(self):
        for path in ("/usr/bin/tcpdump", "/usr/sbin/tcpdump"):
            with self.subTest(path=path):
                unit = module.render("b03r1", "eth0", path)
                lines = unit.splitlines()
                commands = [line.split("=", 1)[1] for line in lines if line.startswith("ExecStart=")]
                self.assertEqual(len(commands), 1)
                self.assertEqual(shlex.split(commands[0]), [path, "-i", "eth0", "-s", "0", "-U", "-Z", "root", "-w", "/var/lib/aegis-fullwide-capture/b03r1.pcap"])
                self.assertIn("UMask=0077", lines)
                self.assertIn("StateDirectoryMode=0700", lines)
                self.assertIn("ConditionPathExists=!/var/lib/aegis-fullwide-capture/b03r1.pcap", lines)
                self.assertIn("Restart=no", lines)
                self.assertNotIn("[Install]", lines)

    def test_bad_inputs_never_render_a_unit(self):
        invalid = [
            ("B03", "eth0", "/usr/bin/tcpdump"),
            ("b03;id", "eth0", "/usr/bin/tcpdump"),
            ("b03", "-i", "/usr/bin/tcpdump"),
            ("b03", "eth0\nExecStart=/bin/sh", "/usr/bin/tcpdump"),
            ("b03", "a" * 16, "/usr/bin/tcpdump"),
            ("b03", "eth0", "/bin/sh"),
        ]
        for args in invalid:
            with self.subTest(args=args), self.assertRaises(ValueError):
                module.render(*args)

    def test_cli_refusal_emits_no_unit(self):
        result = subprocess.run([sys.executable, str(SOURCE), "--run-id", "bad;id", "--uplink", "eth0", "--tcpdump", "/usr/bin/tcpdump"], capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
