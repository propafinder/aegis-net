"""Real Linux nft packet check for a bound guard after capture-link reuse.

Run in a disposable network-none container with CAP_NET_ADMIN. No host rules
or external network are used. The first dummy stands for a departed capture
device; a second dummy borrows its name but receives a different ifindex.
"""
import json
import errno
import socket
import subprocess
import unittest


TABLE = "aegis_codex_tun_index_test"
NAME = "aegis-tun0"


def call(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


class NativeTunIndex(unittest.TestCase):
    def setUp(self):
        if subprocess.run(["id", "-u"], capture_output=True, text=True).stdout.strip() != "0":
            self.skipTest("Linux root network namespace required")
        if subprocess.run(["ip", "link", "add", NAME, "type", "dummy"],
                          capture_output=True).returncode:
            self.skipTest("CAP_NET_ADMIN unavailable")
        self.addCleanup(lambda: subprocess.run(["ip", "link", "del", NAME],
                                               capture_output=True))
        self.old_index = socket.if_nametoindex(NAME)
        call("ip", "link", "del", NAME)
        call("ip", "link", "add", NAME, "type", "dummy")
        self.new_index = socket.if_nametoindex(NAME)
        self.assertNotEqual(self.old_index, self.new_index)
        call("ip", "link", "set", NAME, "up")
        call("ip", "route", "add", "198.18.0.2/32", "dev", NAME)
        self.addCleanup(lambda: subprocess.run(["nft", "delete", "table", "inet", TABLE],
                                               capture_output=True))

    def install(self, selector):
        subprocess.run(["nft", "delete", "table", "inet", TABLE],
                       capture_output=True)
        script = (f"add table inet {TABLE}\n"
                  f"add chain inet {TABLE} output {{ type filter hook output priority 2147483647; policy drop; }}\n"
                  f"add chain inet {TABLE} postroute {{ type filter hook postrouting priority 110; policy drop; }}\n"
                  f"add rule inet {TABLE} output {selector} counter accept\n"
                  f"add rule inet {TABLE} output counter drop\n"
                  f"add rule inet {TABLE} postroute {selector} counter accept\n"
                  f"add rule inet {TABLE} postroute counter drop\n")
        subprocess.run(["nft", "-f", "-"], input=script, text=True,
                       check=True, capture_output=True)

    def packets(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for _ in range(3):
                try:
                    sock.sendto(b"capture-name-reuse", ("198.18.0.2", 5300))
                except OSError as error:
                    if error.errno not in (errno.EPERM, errno.EACCES):
                        raise
        finally:
            sock.close()
        rows = json.loads(call("nft", "-j", "list", "table", "inet", TABLE))["nftables"]
        return [(row["rule"]["chain"], row["rule"]["expr"])
                for row in rows if "rule" in row]

    def test_old_numeric_identity_refuses_reused_name(self):
        self.install(f"meta oif {self.old_index}")
        listed = call("nft", "-a", "list", "table", "inet", TABLE)
        self.assertRegex(listed, rf'(?m)^\s+(?:meta )?oif {self.old_index} '
                         r'counter packets [0-9]+ bytes [0-9]+ accept # handle [1-9][0-9]*$')
        rows = self.packets()
        accepts = [expr for chain, expr in rows if chain == "output" and
                   any("accept" in item for item in expr)]
        self.assertEqual(len(accepts), 1)
        self.assertEqual(next(item["counter"]["packets"] for item in accepts[0]
                              if "counter" in item), 0)
        drops = [expr for chain, expr in rows if chain == "output" and
                 any("drop" in item for item in expr)]
        self.assertGreater(next(item["counter"]["packets"] for item in drops[0]
                                if "counter" in item), 0)
        self.install(f'oifname "{NAME}"')
        rows = self.packets()
        accepts = [expr for chain, expr in rows if chain == "output" and
                   any("accept" in item for item in expr)]
        self.assertGreater(next(item["counter"]["packets"] for item in accepts[0]
                                if "counter" in item), 0)


if __name__ == "__main__":
    unittest.main()
