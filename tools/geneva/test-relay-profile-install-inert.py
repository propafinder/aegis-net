#!/usr/bin/env python3
"""Execute the real selected installer in inert temporary paths.

Only root-state/client/systemctl/guard dependencies are fixture programs. This
exercises partial orchestration failure, not Rust trust gates or kernel/service
acceptance. It never uses installed paths, identity, sockets, NFT, or a VM.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class InstallerTerminalTests(unittest.TestCase):
    def invoke(self, failure=None):
        with tempfile.TemporaryDirectory(prefix="aegis-selected-install-inert-") as tmp:
            p = Path(tmp)
            checkout = p / "checkout"
            (checkout / "tools/geneva").mkdir(parents=True)
            (checkout / "scripts").mkdir()
            (checkout / "packaging/systemd").mkdir(parents=True)
            lib = p / "lib"
            (lib / "lib").mkdir(parents=True)
            (lib / "lib/root-state.sh").write_text(
                'aegis_root_state_init() { :; }\n'
                'aegis_root_trusted_executable() { [[ -x "$1" ]]; }\n'
                'aegis_root_read() { cat -- "$1"; }\n'
            )
            log = p / "calls"
            client = p / "client"
            client.write_text('''#!/usr/bin/env python3
import os,sys,pathlib,json
p=pathlib.Path(os.environ['FIXTURE']); a=sys.argv[1:]
if a[:2]==['profile','metadata']:
 step='dropin' if '25-relay' in a[a.index('--path')+1] else 'helper'
else: step=a[2]
with (p/'calls').open('a') as f: f.write(step+'\\n')
if step==os.environ.get('FAIL_STEP'): sys.exit(17)
if step=='prepare-install': (p/'intent').write_text('FIXTURE_ONLY_NOT_ACCEPTANCE')
if step in ['dropin','helper']:
 assert '--exclusive' in a
 with open(a[a.index('--path')+1],'x') as f: f.write(sys.stdin.read())
if step=='stage': (p/'profile').write_text('FIXTURE_ONLY_NOT_ACCEPTANCE')
''')
            client.chmod(0o700)
            sysctl = p / "systemctl"
            sysctl.write_text('''#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == show ]]; then
 printf '%s\\n' LoadState=loaded ActiveState=inactive SubState=dead MainPID=0 ControlPID=0
else
 printf '%s\\n' reload >>"$FIXTURE/calls"
 [[ "${FAIL_STEP:-}" != reload ]]
fi
''')
            sysctl.chmod(0o700)
            guard = lib / "aegis-device-egress-guard.sh"
            guard.write_text('''#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == block ]]
printf '%s\\n' block >>"$FIXTURE/calls"
[[ "${FAIL_STEP:-}" != block ]]
''')
            dropin = p / "25-relay-geneva-profile.conf"
            manifest = p / "manifest"
            manifest.write_text("PUBLIC_INERT_FIXTURE")
            for rel in ["scripts/aegis-relay-geneva-profile.sh", "packaging/systemd/25-relay-geneva-profile.conf"]:
                (checkout / rel).write_bytes((ROOT / rel).read_bytes())
            text = (ROOT / "tools/geneva/install-relay-profile.sh").read_text()
            # Explicit test-only substitutions, no alternative product entrypoint.
            for old, new in [
                ("$EUID", "0"),
                ("/usr/local/lib/aegis", str(lib)),
                ("/usr/local/bin/aegis-client", str(client)),
                ("/etc/systemd/system/aegis-client.service.d/25-relay-geneva-profile.conf", str(dropin)),
                ("/var/lib/aegis-install/client/relay-geneva-profile.json", str(p / "profile")),
                ("/usr/bin/timeout --signal=KILL 5s /usr/bin/systemctl", str(sysctl)),
                ("/usr/bin/systemctl daemon-reload", str(sysctl) + " daemon-reload"),
            ]:
                self.assertIn(old, text)
                text = text.replace(old, new)
            script = checkout / "tools/geneva/install-relay-profile.sh"
            script.write_text(text)
            env = {**os.environ, "FIXTURE": str(p), "FAIL_STEP": failure or ""}
            result = subprocess.run(["/bin/bash", str(script), "--manifest", str(manifest)],
                                    env=env, capture_output=True, timeout=5)
            calls = log.read_text().splitlines() if log.exists() else []
            return result, calls, dropin.exists(), (lib / "aegis-relay-geneva-profile.sh").exists(), (p / "intent").exists()

    def test_success_stages_blocked_and_never_starts_service(self):
        r, calls, *_ = self.invoke()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(calls, ['prepare-install', 'dropin', 'reload', 'helper', 'stage', 'block'])
        self.assertNotIn(b'PASS', r.stdout)
        self.assertIn(b'explicit service start and runtime validation remain required', r.stdout)

    def test_each_partial_failure_stops_without_erasing_previous_created_bytes(self):
        sequence = ['prepare-install', 'dropin', 'reload', 'helper', 'stage', 'block']
        for step in sequence:
            with self.subTest(step=step):
                r, calls, dropin, helper, intent = self.invoke(step)
                self.assertNotEqual(r.returncode, 0)
                self.assertEqual(calls, sequence[:sequence.index(step)+1])
                self.assertNotIn(b'staged blocked', r.stdout)
                self.assertEqual(intent, step != 'prepare-install')
                self.assertEqual(dropin, sequence.index(step) > sequence.index('dropin'))
                self.assertEqual(helper, sequence.index(step) > sequence.index('helper'))

    def test_recovery_hook_precedes_original_bind_and_keeps_default_hardening(self):
        selected = ROOT / 'packaging/systemd/25-relay-geneva-profile.conf'
        default = (ROOT / 'install.sh').read_text()
        self.assertLess(selected.name, '30-device-egress-guard.conf')
        self.assertIn('ExecStartPre=/bin/bash /usr/local/lib/aegis/aegis-relay-geneva-profile.sh recover', selected.read_text())
        self.assertIn('ExecStartPre=/bin/bash ${helper} bind', default)
        self.assertNotIn('ProtectKernelTunables=', selected.read_text())
        self.assertNotIn('ExecStart=', selected.read_text())


if __name__ == '__main__':
    unittest.main()
