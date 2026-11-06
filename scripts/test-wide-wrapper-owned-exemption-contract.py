#!/usr/bin/env python3
"""Execute the actual wrapper exemption block with inert command recorders only.
By default tests the repository wrapper; optional source override supports private controls.
No native conntrack semantics or service ownership acceptance is claimed.
"""
import json
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
import unittest

class WrapperExemption(unittest.TestCase):
    def run_block(self, ssh="192.0.2.7 45678 198.51.100.8 22", fail=""):
        source = Path(os.environ.get("AEGIS_WIDE_WRAPPER_SOURCE", str(Path(__file__).with_name("aegis-wide-enable.sh")))).read_text()
        begin = source.index("# 1. ")
        end = source.index("# 2. Call underlying helper", begin)
        body = source[begin:end]
        if 'aegis_wide_redirect_preview_activate' in body:
            functions_begin = source.index('aegis_wide_config_applied=0\n')
            functions_end = source.index('# ---------- apply ----------', functions_begin)
            body = source[functions_begin:functions_end] + body
        with tempfile.TemporaryDirectory(prefix="aegis-wrapper-owned-") as name:
            work = Path(name)
            log = work / "commands.jsonl"
            bin_dir = work / "bin"
            bin_dir.mkdir()
            iptables = bin_dir / "iptables"
            iptables.write_text("#!/usr/bin/env python3\nimport json,os,sys\nwith open(os.environ['COMMAND_LOG'],'a') as out: out.write(json.dumps(['iptables',sys.argv[1:]])+'\\n')\nsys.exit(1 if '-C' in sys.argv else 0)\n")
            iptables.chmod(0o700)
            helper = work / "setup-wide-linux-redirect.sh"
            helper.write_text(r"""#!/usr/bin/env python3
import json,os,sys
with open(os.environ['COMMAND_LOG'],'a') as out:
    out.write(json.dumps(['helper',sys.argv[1:],os.environ.get('AEGIS_WIDE_REQUIRE_CGROUP'),os.environ.get('AEGIS_WIDE_EXEMPT_SERVICE'),os.environ.get('AEGIS_WIDE_EXEMPT_CGROUP')])+'\n')
if os.environ.get('HELPER_FAIL') == 'identity': sys.exit(9)
if os.environ.get('HELPER_FAIL') == 'preflight' and sys.argv[1:] == ['preflight']: sys.exit(10)
if sys.argv[1:] == ['cgroup-path']: print('system.slice/aegis-client.service')
""")
            helper.chmod(0o700)
            env = dict(os.environ, PATH=str(bin_dir)+os.pathsep+os.environ['PATH'],
                       COMMAND_LOG=str(log), HELPER_FAIL=fail, SSH_CONNECTION=ssh,
                       AEGIS_WIDE_EXEMPT_CGROUP="untrusted/caller.service")
            script = """set -euo pipefail
mode=redirect
dns_choice=off
SCRIPT_DIR="$1"
WIDE_PORT=15080
INTERFACE=fixture0
AEGIS_UID=0
ssh_safe_ports=22,2222
SSH_SRC_IP=192.0.2.7
RELAY_ENDPOINTS_RAW=203.0.113.9:443
""" + body
            bash = os.environ.get('AEGIS_TEST_BASH_BINARY') or shutil.which('bash')
            if not bash or not Path(bash).is_absolute():
                raise AssertionError('An absolute Bash executable is required')
            result = subprocess.run([bash, '-c', script, 'fixture', str(work)], env=env,
                                    capture_output=True, timeout=5)
            self.last_output = result.stdout + result.stderr
            commands = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            return result.returncode, commands

    def test_root_caller_uses_only_verified_service_identity(self):
        rc, commands = self.run_block()
        self.assertEqual(rc, 0)
        helpers = [c for c in commands if c[0] == 'helper']
        self.assertEqual([c[1] for c in helpers], [['cgroup-path'], ['preflight']])
        self.assertEqual(helpers[0][2:], ['1', 'aegis-client.service', None])
        self.assertEqual(helpers[1][2:], ['1', 'aegis-client.service', 'system.slice/aegis-client.service'])

    def test_ssh_accept_is_exact_established_reply_tuple(self):
        rc, commands = self.run_block()
        self.assertEqual(rc, 0)
        accepts = [c[1] for c in commands if c[0] == 'iptables' and '-j' in c[1] and c[1][-1] == 'ACCEPT']
        self.assertEqual(accepts, [['-t','nat','-A','AEGIS_WIDE_SSH_EXEMPT','-p','tcp',
            '-s','198.51.100.8','--sport','22','-d','192.0.2.7','--dport','45678',
            '-m','conntrack','--ctstate','ESTABLISHED','--ctdir','REPLY',
            '--ctorigsrc','192.0.2.7','--ctorigsrcport','45678',
            '--ctorigdst','198.51.100.8','--ctorigdstport','22','-j','ACCEPT']])

    def test_no_all_process_relay_or_generic_ssh_port_bypass(self):
        rc, commands = self.run_block()
        self.assertEqual(rc, 0)
        arguments = [item for c in commands if c[0] == 'iptables' for item in c[1]]
        self.assertNotIn('203.0.113.9', arguments)
        self.assertNotIn('--uid-owner', arguments)
        self.assertNotIn('2222', arguments)
        self.assertEqual(arguments.count('ACCEPT'), 1)

    def test_empty_session_has_no_ssh_accept(self):
        rc, commands = self.run_block(ssh='')
        self.assertEqual(rc, 0)
        self.assertFalse(any(c[0] == 'iptables' and 'ACCEPT' in c[1] for c in commands))

    def test_bad_or_ipv6_tuple_refuses_before_any_wrapper_mutation(self):
        for ssh in ['2001:db8::7 45678 2001:db8::8 22', '192.0.2.7 0 198.51.100.8 22',
                    '192.0.2.999 45678 198.51.100.8 22', '192.0.2.7 45678 198.51.100.8 22 extra']:
            with self.subTest(ssh=ssh):
                rc, commands = self.run_block(ssh=ssh)
                self.assertNotEqual(rc, 0)
                self.assertFalse(any(c[0] == 'iptables' for c in commands))

    def test_unready_service_refuses_before_any_wrapper_mutation(self):
        rc, commands = self.run_block(fail='identity')
        self.assertNotEqual(rc, 0)
        self.assertFalse(any(c[0] == 'iptables' for c in commands))

    def test_multiline_first_valid_tuple_refuses_before_hooks(self):
        valid = '192.0.2.7 45678 198.51.100.8 22'
        for ssh in [valid+'\nignored', valid+'\n'+valid, valid+'\rignored']:
            with self.subTest(separator=repr(ssh[len(valid):])):
                rc, commands = self.run_block(ssh=ssh)
                self.assertNotEqual(rc, 0)
                self.assertFalse(any(c[0] == 'iptables' for c in commands))
                self.assertNotIn(b'192.0.2.7', self.last_output)
                self.assertNotIn(b'198.51.100.8', self.last_output)

    def test_identity_success_preflight_failure_has_no_hooks_or_tuple_output(self):
        rc, commands = self.run_block(fail='preflight')
        self.assertNotEqual(rc, 0)
        helpers = [c for c in commands if c[0] == 'helper']
        self.assertEqual([c[1] for c in helpers], [['cgroup-path'], ['preflight']])
        self.assertEqual(helpers[1][2:], ['1', 'aegis-client.service', 'system.slice/aegis-client.service'])
        self.assertFalse(any(c[0] == 'iptables' for c in commands))
        for value in [b'192.0.2.7', b'198.51.100.8', b'45678', b'203.0.113.9']:
            self.assertNotIn(value, self.last_output)

if __name__ == '__main__': unittest.main()
