"""Source contract for ordinary full-wide TUN admission after READY."""

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class LegacyTunGrantContract(unittest.TestCase):
    def test_installer_runs_late_numeric_grant_before_successful_start(self):
        source = (ROOT / "install.sh").read_text()
        self.assertTrue(
            'ExecStartPost=/bin/bash ${helper} capture-bind-legacy\n' in source,
            'ordinary service lacks post-ready numeric grant')
        self.assertTrue('ExecStopPost=/bin/bash ${helper} block\n' in source,
                        'ordinary service lacks stop-time revoke')

    def test_helper_refuses_name_grant_and_owns_legacy_receipt(self):
        source = (ROOT / "scripts/aegis-device-egress-guard.sh").read_text()
        self.assertFalse('output oifname "%s" counter accept' in source,
                         'name-based TUN grant returned')
        self.assertTrue('capture-bind-legacy)' in source,
                        'ordinary post-ready action missing')
        self.assertTrue('capture_binding_index_legacy' in source,
                        'ordinary owner revalidation missing')
        legacy = source.split('  capture-bind-legacy)', 1)[1].split('\n  block|', 1)[0]
        self.assertTrue('foreign-policy-drift.json' in legacy,
                        'sticky foreign refusal must block late ordinary grant')

    def test_owner_program_parses_and_rechecks_pid1_and_tun_fd(self):
        source = (ROOT / "scripts/aegis-device-egress-guard.sh").read_text()
        program = source.split("<<'PY_LEGACY_CAPTURE'\n", 1)[1].split(
            '\nPY_LEGACY_CAPTURE', 1)[0]
        compile(program, '<legacy-capture>', 'exec')
        for fact in ('MainPID', 'ControlPID', 'InvocationID', 'ControlGroup',
                     '/proc/{pid}/fdinfo', '/proc/{pid}/ns/net',
                     'socket.if_nametoindex', "'ifindex'"):
            self.assertTrue(fact in program, fact)
        self.assertRegex(source, re.compile(
            r'capture-bind-legacy\).*?capture_binding_index_legacy mint.*?'
            r'capture_binding_index_legacy verify.*?apply_rules', re.S))

    def test_pipeline_mint_binds_the_systemd_control_pid_and_boot(self):
        source = (ROOT / "scripts/aegis-device-egress-guard.sh").read_text()
        self.assertTrue('"$1" "$$" <<\'PY_LEGACY_CAPTURE\'' in source,
                        'pipeline child must receive the original hook PID')
        self.assertTrue("facts['ControlPID']==hook_pid" in source,
                        'mint must match the PID1 control process')
        self.assertTrue('"$(cat /proc/sys/kernel/random/boot_id)"' in source,
                        'v1 and v2 receipts must bind the current boot')

    def test_v1_implicit_fulltun_remains_eligible(self):
        source = (ROOT / "scripts/aegis-device-egress-guard.sh").read_text()
        self.assertTrue('capture_profile=full-wide-tun\npython3 - "$management_ipv4"' in source,
                        'v1 has no capture_profile state field and must infer FullTun')

    def test_monitor_can_revoke_v1_under_original_guard_flock(self):
        source = (ROOT / "scripts/aegis-device-egress-guard.sh").read_text()
        self.assertTrue('"$schema" == aegis_device_guard_v1 && "$ACTION" == block' in source,
                        'v1 monitor must pass its original lock to restrictive block')


if __name__ == "__main__":
    unittest.main()
