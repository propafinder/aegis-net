"""Critic V4: a 14-row merged witness cannot run before the successor
foreign-policy monitor is up.

An old monitor process binds the 8-row-only trace predicate when it starts
(its module import), so a new guardian's 14-row witness seen by an old
monitor would be drift and a sticky revocation. The merged witness runs only
inside the installed guardian. The installer's first arm and rotation start
the successor monitor unconditionally after the guard and before the
watchdog, the guardian and the guardian readiness wait. These fixtures
require exactly that order and that only the guardian runs the witness.
"""
import ast
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
sys.path.insert(0, str(ROOT / "lib"))


def shell_function(text: str, name: str) -> list[str]:
    start = text.index("\n" + name + "() (\n") + 1
    end = text.index("\n)\n", start)
    return text[start:end].splitlines()


class MonitorSuccession(unittest.TestCase):
    def setUp(self):
        self.lines = shell_function((REPO / "install.sh").read_text(encoding="utf-8"),
                                    "auto_v2_first_arm")

    def index(self, line: str) -> int:
        found = [number for number, value in enumerate(self.lines) if value.strip() == line]
        self.assertEqual(len(found), 1, line)
        return found[0]

    def test_successor_monitor_starts_after_the_guard_and_before_any_guardian(self):
        guard = self.index("systemctl start aegis-device-egress-guard.service || return 1")
        monitor = self.index("systemctl start aegis-foreign-policy-monitor.service || return 1")
        manager = self.index('systemctl restart "$manager" || return 1')
        watchdog = self.index("systemctl start aegis-auto-guardian-watchdog.service || return 1")
        guardian = self.index("systemctl start aegis-auto-guardian.service || return 1")
        self.assertLess(guard, monitor)
        self.assertLess(monitor, manager)
        self.assertLess(manager, watchdog)
        self.assertLess(watchdog, guardian)
        ready = [number for number, value in enumerate(self.lines)
                 if "wait_guardian_ready(" in value]
        self.assertEqual(len(ready), 1)
        self.assertGreater(ready[0], guardian)
        # Nothing before the successor monitor can start or serve a guardian.
        for value in self.lines[:monitor]:
            self.assertNotRegex(value, r"systemctl (re)?start .*aegis-auto-guardian\.service")
            self.assertNotRegex(value, r"aegis_auto_guardian\.py\"? serve\b")

    def test_successor_monitor_start_is_unconditional(self):
        monitor = self.index("systemctl start aegis-foreign-policy-monitor.service || return 1")
        depth, heredoc = 0, None
        for value in self.lines[:monitor]:
            stripped = value.strip()
            if heredoc is not None:
                heredoc = None if value == heredoc else heredoc
                continue
            tag = re.search(r"<<'([A-Z0-9_]+)'", value)
            if tag:
                heredoc = tag.group(1)
            if stripped.startswith("#"):
                continue
            if re.match(r"(el)?if ", stripped) and stripped.endswith("then"):
                depth += 0 if stripped.startswith("elif") else 1
            elif stripped == "fi":
                depth -= 1
        self.assertIsNone(heredoc)
        self.assertEqual(depth, 0, "the monitor start must not sit inside a branch")
        # Self-check of the scan: a branch-wrapped start would be refused.
        wrapped = ['if [[ "$transition" == stopped-successor ]]; then',
                   "  systemctl start aegis-foreign-policy-monitor.service || return 1", "fi"]
        self.assertTrue(re.match(r"(el)?if ", wrapped[0].strip()) and
                        wrapped[0].strip().endswith("then"))

    def test_only_the_guardian_runs_the_merged_witness(self):
        callers = {}
        for path in sorted([*(ROOT / "lib").glob("*.py"), *ROOT.glob("*.sh"),
                            REPO / "install.sh"]):
            text = path.read_text(encoding="utf-8")
            count = len(re.findall(r"(?<!def )prove_deny_dual\(", text))
            if count:
                callers[path.name] = count
        self.assertEqual(callers, {"aegis_auto_guardian.py": 1})

    def test_the_monitor_binds_its_trace_predicate_when_it_starts(self):
        tree = ast.parse((ROOT / "lib" / "aegis_auto_foreign_monitor.py").read_text(encoding="utf-8"))
        top = [node for node in tree.body if isinstance(node, ast.ImportFrom) and
               node.module == "aegis_auto_foreign_policy"]
        self.assertEqual(len(top), 1)
        self.assertIn("assess_foreign_policy", {alias.name for alias in top[0].names})
        # No later re-import or reload can swap the predicate of a live monitor.
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "reload":
                self.fail("monitor reloads a module")
            if isinstance(node, (ast.Import, ast.ImportFrom)) and node not in tree.body:
                names = [node.module] if isinstance(node, ast.ImportFrom) else [
                    alias.name for alias in node.names]
                self.assertNotIn("aegis_auto_foreign_policy", names)

    def test_the_successor_predicate_admits_the_batch_the_guardian_installs(self):
        import aegis_auto_foreign_policy as foreign
        import aegis_auto_native_witness as witness
        actor = bytes(range(32))
        c4 = witness.Challenge("aegisaw0", "198.18.77.2", 48001, 47001, actor)
        c6 = witness.Challenge("aegisaw0", "2001:db8:ae61:77::2", 48002, 47002,
                               witness.ipv6_challenge_nonce(actor))
        _raw, expected = witness._dual_batch(c4, c6)
        rows = [{"table": {"family": "inet", "name": "aegis_auto_witness", "handle": 40}},
                {"chain": {"family": "inet", "table": "aegis_auto_witness", "name": "trace_out",
                           "handle": 1, "type": "filter", "hook": "output", "prio": -200,
                           "policy": "accept"}}]
        for index, rule in enumerate(expected["rules"]):
            def match(left, right):
                return {"match": {"op": "==", "left": left, "right": right}}
            rows.append({"rule": {"family": "inet", "table": "aegis_auto_witness",
                                  "chain": "trace_out", "handle": index + 2, "expr": [
                match({"meta": {"key": "oifname"}}, rule["oifname"]),
                match({"payload": {"protocol": rule["family"], "field": "daddr"}}, rule["daddr"]),
                match({"payload": {"protocol": "udp", "field": "sport"}}, rule["sport"]),
                match({"payload": {"protocol": "udp", "field": "dport"}}, rule["dport"]),
                match({"payload": {"base": "th", "offset": 64, "len": 96}}, hex(rule["prefix"])),
                {"mangle": {"key": {"meta": {"key": "nftrace"}}, "value": 1}}]}})
        # The successor monitor's shape-only mode admits the merged batch.
        foreign.verify_active_trace_table({"nftables": rows})


if __name__ == "__main__":
    unittest.main()
