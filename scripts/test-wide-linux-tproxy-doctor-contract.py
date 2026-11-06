#!/usr/bin/env python3
"""Actual helper doctor with inert OS commands and real Rust client readback.

One apply refusal runs before OS mutation. No firewall, route, service, Cargo or
network mutation executes. The fixture rejects mutation arguments and requires
real client/measure binaries for its positive and parser-policy controls.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/setup-wide-linux-tproxy.sh"
COMPLETE = """mode = 'relay'
[ingress]
primary = 'wide'
[ingress.wide]
enabled = true
platform_backend = 'linux_tproxy'
rollout_profile = 'transparent_privileged'
prerouting_interface = 'fixture0'
listen = '0.0.0.0:15080'
capture_dns = false
udp_capture_contract = 'preview_allowlist_only'
default_mark = 1
"""
RECORDER = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).name
args = sys.argv[1:]
mutation = (any(a in {'-N','-F','-X','-A','-I','-D','add','del','delete','flush','set','replace'} for a in args)
            or name in {'cargo','systemctl','sudo'})
with open(os.environ['AEGIS_DOCTOR_COMMAND_LOG'], 'a', encoding='utf-8') as stream:
    stream.write(json.dumps({'name':name,'args':args,'mutation':mutation})+'\n')
if mutation: sys.exit(97)
if name in {'firewall-cmd','nft','cargo','systemctl','sudo'}: sys.exit(1)
if name == 'ip':
    if args == ['route','show','default']: print('default via 192.0.2.1 dev uplink0')
    elif args == ['rule','show']: print('100: from all fwmark 1 lookup 100')
    elif args == ['route','show','table','100']: print('local 0.0.0.0/0 dev lo scope host')
    elif args[:3] == ['link','show','dev']: print('1: fixture0: <UP>')
    else: sys.exit(98)
    sys.exit(0)
if name in {'iptables','ip6tables'}:
    if '-S' in args or '-C' in args: sys.exit(0)
    sys.exit(98)
sys.exit(98)
'''


class ConfiguredDoctor(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-doctor-config-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name).resolve()
        self.directory.chmod(0o700)
        self.bin = self.directory / 'bin'
        self.bin.mkdir(mode=0o700)
        self.commands = self.directory / 'commands.jsonl'
        self.config = self.directory / 'client.toml'
        self.config.write_text(COMPLETE, encoding='utf-8')
        self.config.chmod(0o600)
        for name in ['ip','iptables','ip6tables','firewall-cmd','nft','cargo','systemctl','sudo']:
            p = self.bin / name
            p.write_text(RECORDER, encoding='utf-8')
            p.chmod(0o700)

    def measure(self):
        binary = Path(os.environ.get('AEGIS_TEST_MEASURE_BINARY') or
                      os.environ.get('AEGIS_MEASURE_BIN') or ROOT / 'target/debug/aegis-measure').resolve()
        self.assertTrue(binary.is_file() and os.access(binary, os.X_OK),
                        'fixture requires the actual reviewed Rust measure binary')
        return binary

    def measure_fields(self):
        result = subprocess.run([str(self.measure()), 'tproxy-client-contract',
                                 '--config', str(self.config)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=15, check=False, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def client(self):
        binary = Path(os.environ.get('AEGIS_TEST_CLIENT_BINARY') or
                      ROOT / 'target/debug/aegis-client').resolve()
        self.assertTrue(binary.is_file() and os.access(binary, os.X_OK),
                        'fixture requires the actual reviewed Rust client binary')
        return binary

    def invoke(self, parser=None, config=True, client=None, helper=HELPER,
               root_state_client=None, action='doctor'):
        env = os.environ.copy()
        # Remove unrelated ambient project policy rather than accidentally apply
        # a user's interface/mark/config. Supply every fixture policy explicitly.
        for key in list(env):
            if key.startswith('AEGIS_') and key not in {'AEGIS_TEST_CLIENT_BINARY'}:
                del env[key]
        env.update(PATH=str(self.bin)+os.pathsep+os.environ['PATH'],
                   AEGIS_DOCTOR_COMMAND_LOG=str(self.commands),
                   AEGIS_WIDE_FIREWALL_BACKEND='xtables', AEGIS_WIDE_IP_FAMILY='ipv4',
                   AEGIS_WIDE_INTERFACE='fixture0', AEGIS_WIDE_ALLOW_ALL_INTERFACES='0',
                   AEGIS_WIDE_SSH_SAFE_PORTS='22', AEGIS_ENABLE_DNS_PREVIEW='0',
                   AEGIS_ENABLE_LOCAL_OUTPUT='0', AEGIS_UDP_CAPTURE_CONTRACT='preview_allowlist_only',
                   AEGIS_WIDE_PORT='15080', AEGIS_WIDE_FWMARK='1', AEGIS_WIDE_ROUTE_TABLE='100',
                   AEGIS_WIDE_IPV6_POLICY='out_of_scope', AEGIS_CLIENT_CONFIG=str(self.config) if config else '')
        if parser is not None: env['AEGIS_MEASURE_BIN'] = str(parser)
        if client is not None: env['AEGIS_CLIENT_BIN'] = str(client)
        if parser is not None and root_state_client is None:
            root_state_client = self.client()
        if root_state_client is not None: env['AEGIS_ROOT_STATE_CLIENT'] = str(root_state_client)
        result = subprocess.run(['bash', str(helper), action], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=15, check=False, text=True)
        records = ([json.loads(line) for line in self.commands.read_text().splitlines()]
                   if self.commands.exists() else [])
        self.assertFalse(any(item['mutation'] for item in records), 'doctor attempted OS mutation')
        if action == 'doctor':
            self.assertTrue(any(item['name']=='ip' for item in records), 'actual helper OS path not exercised')
        return result

    def refuse(self, result):
        self.assertNotEqual(result.returncode, 0, 'configured incomplete contract reported success')
        self.assertIn('client config contract could not be parsed completely', result.stdout)
        self.assertNotIn('Doctor result: host contract looks consistent', result.stdout)
        self.assertIn('failures=1', result.stdout, 'unrelated host failure could mask the intended assertion')

    def stub(self, body):
        parser = self.bin / 'fixture-measure'
        parser.write_text('#!/usr/bin/env bash\n'+body+'\n', encoding='utf-8')
        parser.chmod(0o700)
        return parser

    def test_real_parser_complete_config_positive(self):
        result = self.invoke(self.measure())
        self.assertEqual(result.returncode, 0, 'valid actual parser/client contract refused')
        self.assertIn('Doctor result: host contract looks consistent', result.stdout)
        self.assertIn('failures=0', result.stdout)

    def test_public_client_typed_contract_without_measure_positive(self):
        result = self.invoke(client=self.client())
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('Doctor result: host contract looks consistent', result.stdout)
        self.assertIn('failures=0', result.stdout)

    def public_helper(self):
        bundle = self.directory / 'public-bundle'
        (bundle / 'bin').mkdir(parents=True)
        (bundle / 'scripts/lib').mkdir(parents=True)
        shutil.copy2(self.client(), bundle / 'bin/aegis-client')
        shutil.copy2(HELPER, bundle / 'scripts/setup-wide-linux-tproxy.sh')
        shutil.copy2(ROOT / 'scripts/lib/root-state.sh', bundle / 'scripts/lib/root-state.sh')
        self.assertFalse((bundle / 'Cargo.toml').exists())
        self.assertFalse((bundle / 'bin/aegis-measure').exists())
        return bundle / 'scripts/setup-wide-linux-tproxy.sh'

    def test_public_archive_layout_uses_bundled_client_without_checkout(self):
        result = self.invoke(helper=self.public_helper())
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('Doctor result: host contract looks consistent', result.stdout)
        self.assertIn('failures=0', result.stdout)

    def test_divergent_execution_target_refuses_public_bundle_parser(self):
        helper = self.public_helper()
        divergent = self.stub('exit 73')
        result = self.invoke(helper=helper, root_state_client=divergent)
        self.refuse(result)
        self.assertNotIn('Doctor result: host contract looks consistent', result.stdout)

    def test_root_launch_keeps_parser_and_state_owner_identity(self):
        # Source contract only: native root/systemd custody remains an installed
        # acceptance gate. A command substitution must not lose this assignment.
        source = HELPER.read_text(encoding='utf-8')
        launch = source.split('resolve_client_exec_prefix() {', 1)[1].split('\n}\n', 1)[0]
        select = source.split('selected_client_binary() {', 1)[1].split('\n}\n', 1)[0]
        self.assertLess(launch.index('AEGIS_ROOT_STATE_CLIENT="${CLIENT_BIN_OVERRIDE}"'),
                        launch.index('aegis_root_state_init || exit 1'))
        self.assertLess(launch.index('aegis_root_state_init || exit 1'),
                        launch.index('CLIENT_EXEC_PREFIX=("${AEGIS_ROOT_STATE_CLIENT}")'))
        self.assertIn('client="${CLIENT_BIN_OVERRIDE:-${AEGIS_ROOT_STATE_CLIENT:-/usr/local/bin/aegis-client}}"', select)
        self.assertIn('aegis_root_trusted_executable "${client}"', select)
        early = source.split('if [[ "${ACTION}" == apply || "${ACTION}" == teardown || "${ACTION}" == run ]]; then', 1)[1]
        self.assertLess(early.index('AEGIS_ROOT_STATE_CLIENT="${CLIENT_BIN_OVERRIDE}"'),
                        early.index('aegis_root_state_init || exit 1'))

    def test_primary_socks5_refuses_with_or_without_explicit_measure(self):
        self.config.write_text(COMPLETE.replace("primary = 'wide'", "primary = 'socks5'"), encoding='utf-8')
        self.assertIn('CFG_INGRESS_PRIMARY\tsocks5', self.measure_fields())
        for parser, helper in [(self.measure(), HELPER), (None, self.public_helper())]:
            with self.subTest(route='measure' if parser else 'public-client'):
                result = self.invoke(parser=parser, helper=helper)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('client wide ingress is inactive (primary=socks5, enabled=1)', result.stdout)
                self.assertIn('failures=1', result.stdout)

    def test_disabled_wide_refuses_with_or_without_explicit_measure(self):
        self.config.write_text(COMPLETE.replace('enabled = true', 'enabled = false'), encoding='utf-8')
        self.assertIn('CFG_WIDE_ENABLED\t0', self.measure_fields())
        for parser, helper in [(self.measure(), HELPER), (None, self.public_helper())]:
            with self.subTest(route='measure' if parser else 'public-client'):
                result = self.invoke(parser=parser, helper=helper)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('client wide ingress is inactive (primary=wide, enabled=0)', result.stdout)
                self.assertIn('failures=1', result.stdout)

    def test_public_client_typed_contract_refuses_invalid_config_without_disclosure(self):
        secret_marker = 'fixture-private-never-print-this'
        self.config.write_text(COMPLETE + '\ninvalid = "' + secret_marker + '"\n', encoding='utf-8')
        result = self.invoke(client=self.client())
        self.refuse(result)
        self.assertNotIn(secret_marker, result.stdout + result.stderr)

    def test_unset_config_host_only_refuses_without_parser(self):
        self.assertFalse(Path('/etc/aegis/client/aegis.toml').is_file(),
                         'host-only fixture requires a disposable host without an installed config')
        result = self.invoke(self.directory/'absent-measure', config=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('client config is unavailable; host-only checks cannot establish a supported linux_tproxy run', result.stdout)
        self.assertIn('failures=1', result.stdout)
        self.assertNotIn('Doctor result: host contract looks consistent', result.stdout)

    def test_configured_missing_config_refuses(self):
        self.config.unlink()
        self.refuse(self.invoke(self.measure()))

    def test_actual_parser_malformed_config_refuses(self):
        self.config.write_text('[ingress.wide\ninvalid =', encoding='utf-8')
        self.refuse(self.invoke(self.measure()))

    def test_explicit_missing_measure_does_not_block_client_contract_doctor(self):
        result = self.invoke(self.directory/'absent-measure')
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('Doctor result: host contract looks consistent', result.stdout)

    def test_available_measure_cannot_hide_absent_selected_client(self):
        result = self.invoke(self.measure(), root_state_client=self.directory/'absent-client')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('selected client executable is unavailable for probe/run', result.stdout)
        self.assertIn('failures=2', result.stdout)
        self.assertNotIn('Doctor result: host contract looks consistent', result.stdout)

    def test_valid_measure_cannot_hide_incompatible_selected_client(self):
        self.assertIn('CFG_INGRESS_PRIMARY\twide', self.measure_fields())
        self.refuse(self.invoke(self.measure(), client=self.stub('exit 73')))

    def test_apply_refuses_selected_client_parse_failure_before_os_mutation(self):
        self.config.write_text('[ingress.wide\ninvalid =', encoding='utf-8')
        result = self.invoke(client=self.client(), action='apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('selected client rejected the config contract; refusing apply', result.stderr)

    def test_apply_and_run_refuse_empty_config_before_os_mutation(self):
        for action in ('apply', 'run'):
            with self.subTest(action=action):
                self.commands.unlink(missing_ok=True)
                result = self.invoke(client=self.client(), config=False, action=action)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f'AEGIS_CLIENT_CONFIG is required; refusing {action}', result.stderr)

    def test_apply_refuses_inactive_wide_before_os_mutation(self):
        self.config.write_text(COMPLETE.replace("primary = 'wide'", "primary = 'socks5'"), encoding='utf-8')
        result = self.invoke(client=self.client(), action='apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('selected client is not configured for active privileged Linux TPROXY; refusing apply', result.stderr)

    def test_configured_missing_listener_port_incomplete_client_refuses(self):
        # Preserve every other alignment field so the old helper has no
        # unrelated mismatch; its absent-port branch formerly skipped checking.
        fields = "\\n".join([
            "CFG_INGRESS_PRIMARY\\twide", "CFG_WIDE_ENABLED\\t1",
            "CFG_WIDE_BACKEND\\tlinux_tproxy", "CFG_WIDE_PROFILE\\ttransparent_privileged",
            "CFG_WIDE_INTERFACE\\tfixture0", "CFG_WIDE_LISTEN_FAMILY\\tipv4",
            "CFG_CAPTURE_DNS\\t0", "CFG_UDP_CAPTURE_CONTRACT\\tpreview_allowlist_only",
            "CFG_DEFAULT_MARK\\t1",
        ]) + "\\n"
        self.refuse(self.invoke(self.measure(), client=self.stub("printf '" + fields + "'")))


if __name__ == '__main__':
    unittest.main()
