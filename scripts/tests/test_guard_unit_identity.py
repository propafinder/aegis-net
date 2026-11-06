"""Run production shell resolvers against coherent PID1/proc fixture bytes."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

HELPER = Path(__file__).resolve().parents[1] / 'aegis-device-egress-guard.sh'


def function(name):
    return re.search(r'^' + name + r'\(\) \{\n.*?^\}', HELPER.read_text(), re.M | re.S)[0]


class UnitIdentity(unittest.TestCase):
    def test_auto_binding_avoids_unrelated_pid1_query_and_retains_both_fallbacks(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for installed,valid,expected in (
                    (True,'AUTO_FROM_RECEIPT',['AUTO_FROM_RECEIPT']),
                    (True,'aegis-client.service',['AUTO_FROM_RECEIPT','aegis-client.service']),
                    (False,'aegis-client.service',['aegis-client.service']),
                    (False,'AUTO_FROM_RECEIPT',['aegis-client.service','AUTO_FROM_RECEIPT']),
                    (True,'alien',['AUTO_FROM_RECEIPT','aegis-client.service'])):
                calls=root/'calls';calls.unlink(missing_ok=True)
                install=root/'install';install.unlink(missing_ok=True)
                if installed:install.touch()
                code='''set -eu
read_binding() {
 [[ "$1" == client ]] || return 1
 printf '%s\\n' "$2" >> "$CALLS"
 [[ "$2" == "$VALID" ]] || return 1
 resolved_path=verified; resolved_inode=123; resolved_invocation=owned
}
networkmanager_check() { return 0; }
'''+function('collect_v2_bindings')+'''
service=aegis-client.service; manager=systemd-networkd.service; client_path=''
collect_v2_bindings
if [[ "$VALID" == alien ]]; then [[ -z "$client_path" ]]; else [[ "$client_path" == verified ]]; fi
'''
                result=subprocess.run(['bash','-c',code],capture_output=True,timeout=5,
                    env=dict(os.environ,AUTO_INSTALL=str(install),CALLS=str(calls),VALID=valid))
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(calls.read_text().splitlines(),expected)

    def run_resolver(self, facts, *, caller='1', operation='resolve_unit_cgroup', twice=False):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'sys/system.slice/test.service').mkdir(parents=True)
            (root / 'proc').mkdir()
            (root / 'proc/cgroup').write_text('0::/system.slice/test.service\n')
            body = '\n'.join(function(n) for n in
                             ('read_unit_identity', 'resolve_unit_cgroup', 'resolve_bind_cgroup'))
            body = body.replace('/proc/$$/cgroup', str(root / 'proc/cgroup'))
            body = body.replace('/sys/fs/cgroup', str(root / 'sys'))
            prelude = '''set -eu
fail() { exit 92; }
systemctl() {
 [[ "$*" == 'show test.service -p ActiveState -p ControlGroup -p InvocationID -p ControlPID --no-pager' ]] || return 93
 printf 'query\n' >> "$CALLS"
 printf '%s\n' "${FACTS//@PID@/$$}"
}
stat() { if [[ "$1" == -f ]]; then echo cgroup2fs; else echo 123; fi; }
'''
            command = (operation + ' test.service ' + caller if operation == 'resolve_unit_cgroup'
                       else 'service=test.service; resolve_bind_cgroup')
            if twice:
                command += '\nFACTS="${FACTS/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb}"\n' + command
                command += '\n[[ "$resolved_invocation" == bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ]]'
            result = subprocess.run(['bash', '-c', prelude + body + '\n' + command],
                                    env=dict(os.environ, FACTS=facts, CALLS=str(root / 'calls')),
                                    capture_output=True, timeout=5)
            calls = (root / 'calls').read_text().splitlines()
            return result.returncode, len(calls)

    def test_closed_timing_write_failure_cannot_abort_bind(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'uptime';path.write_text('123.45 234.56\n')
            body=function('private_bind_step').replace('/proc/uptime',str(path))
            code='set -eu\nprintf() { return 74; }\n'+body+'\nprivate_bind_step rules_begin\n'
            result=subprocess.run(['bash','-c',code],capture_output=True,timeout=5,
                                  env=dict(os.environ,ACTION='bind',AUTO_PRIVATE_UNIT='test.service'))
            self.assertEqual(result.returncode,0)

    @staticmethod
    def facts():
        return ('ActiveState=activating\nControlGroup=/system.slice/test.service\n'
                'InvocationID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nControlPID=@PID@')

    def test_one_coherent_query_per_checkpoint_and_no_cached_invocation(self):
        self.assertEqual(self.run_resolver(self.facts()), (0, 1))
        self.assertEqual(self.run_resolver(self.facts(), twice=True), (0, 2))
        self.assertEqual(self.run_resolver(self.facts(), operation='resolve_bind_cgroup'), (0, 1))

    def test_duplicate_missing_extra_or_malformed_fields_refuse(self):
        good = self.facts()
        for bad in (good + '\nActiveState=active', good + '\nExtra=private',
                    good.replace('ActiveState=activating\n', ''),
                    good.replace('ControlPID=@PID@', 'ControlPID=01'),
                    good.replace('InvocationID=' + 'a' * 32, 'InvocationID=bad'),
                    good.replace('ActiveState=activating', 'ActiveState=deactivating'),
                    good + '\n' + 'x' * 4097):
            with self.subTest(facts=bad):
                rc, calls = self.run_resolver(bad)
                self.assertNotEqual(rc, 0)
                self.assertEqual(calls, 1)

    def test_wrong_control_pid_or_foreign_cgroup_refuses(self):
        for bad in (self.facts().replace('ControlPID=@PID@', 'ControlPID=1'),
                    self.facts().replace('/system.slice/test.service', '/system.slice/other.service')):
            self.assertNotEqual(self.run_resolver(bad)[0], 0)
        # Manager receipt lookups can have no ControlPID; a bind caller cannot.
        idle = self.facts().replace('ControlPID=@PID@', 'ControlPID=0')
        self.assertEqual(self.run_resolver(idle, caller='0'), (0, 1))
        self.assertNotEqual(self.run_resolver(idle)[0], 0)


if __name__ == '__main__':
    unittest.main()
