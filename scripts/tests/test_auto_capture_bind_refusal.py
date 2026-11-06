"""A late numeric TUN grant cannot survive a refused foreign admission."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/aegis-device-egress-guard.sh"


class CaptureBindRefusal(unittest.TestCase):
    def test_foreign_assessment_refusal_reblocks_numeric_and_client_grants(self):
        source = HELPER.read_text()
        body = "apply_rules() {" + source.split("\napply_rules() {", 1)[1].split(
            "\n}\n\nguard_table_shape_present() {", 1)[0] + "\n}\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy = root / "kernel-policy"
            state = root / "device-guard.conf"
            capture = root / "device-guard.conf.capture-binding"
            client = root / "device-guard.conf.client-binding"
            capture.write_text("owned capture\n")
            client.write_text("owned client\n")
            script = r'''
set -eu
nft() {
  if [[ "$1" == --check ]]; then cat >/dev/null; return 0; fi
  if [[ "$1" == --file ]]; then cat > "$POLICY_FILE"; return 0; fi
  if [[ "$1" == --json ]]; then
    printf '%s\n' '{"nftables":[{"chain":{"family":"inet","table":"aegis_device_guard","name":"output","hook":"output","prio":2147483647,"policy":"drop"}},{"chain":{"family":"inet","table":"aegis_device_guard","name":"forward","hook":"forward","prio":10,"policy":"drop"}},{"chain":{"family":"inet","table":"aegis_device_guard","name":"postroute","hook":"postrouting","prio":2147483647,"policy":"drop"}}]}'
    return 0
  fi
  return 1
}
selected_relay_prepare() { selected_relay_script=''; }
selected_relay_finish() { return 0; }
guard_table_shape_present() { return 0; }
verify_v2_bindings() { return 0; }
kernel_binding_present() { return 0; }
foreign_assessment() { printf 'called\n' >> "$FOREIGN_CALLED"; return 1; }
aegis_root_remove() { rm -f "$1"; }
render() { printf 'DENY\n'; }
auto_seal_policy() { return 0; }
fail() { printf '%s\n' "$1" >&2; exit 91; }
schema=aegis_device_guard_v2
TABLE=aegis_device_guard
ACTION=capture-bind
STATE="$STATE_FILE"
client_path=system.slice/aegis-auto-test.service
client_inode=42
client_invocation=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
manager_path=''
cgroup_path=''
selected_relay_script=''
selected_relay_stop_after_block=0
'''
            script += body + '\napply_rules "meta oif 9 counter accept; client accept"\n'
            result = subprocess.run(
                ["/bin/bash", "--noprofile", "--norc", "-c", script],
                env={**os.environ, "POLICY_FILE": str(policy),
                     "FOREIGN_CALLED": str(root / "foreign-called"),
                     "STATE_FILE": str(state)},
                capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 91, result.stderr)
            self.assertIn("foreign policy admission refused", result.stderr)
            self.assertEqual((root / "foreign-called").read_text(), "called\n")
            self.assertEqual(policy.read_text(), "DENY\n")
            self.assertFalse(capture.exists())
            self.assertFalse(client.exists())


if __name__ == "__main__":
    unittest.main()
