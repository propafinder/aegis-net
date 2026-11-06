"""B-06 v45: make-invite.py against a local fake ssh (never the real relay).

Run: python3 -I -B -m unittest discover -s tools/macos/relay-ops -p 'test_*.py'
"""
import fcntl
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / 'make-invite.py'
FAKE_SSH = HERE / 'testdata' / 'fake-ssh'
TOKEN = '0123456789abcdef' * 4
PEM = '-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n'
PROFILE = {
    'schema': 'aegis_device_bundle_v4', 'product_mode': 'full-wide-tun', 'udp': True,
    'relay_server': '192.0.2.10:443', 'outer_server_name': 'relay.test',
    'inner_server_name': 'inner.test',
    'enrollment': {'protocol': 'aegis-enrollment-v1', 'authority_server': '192.0.2.10:9445',
                   'outer_server_name': 'relay.test', 'inner_server_name': 'issuer.test',
                   'automatic_renewal': True, 'renewal_policy': 'same-key-v1'},
}


class MakeInvite(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='make-invite-test-'))
        self.bin = self.tmp / 'bin'
        self.bin.mkdir()
        shutil.copy(FAKE_SSH, self.bin / 'ssh')
        (self.bin / 'ssh').chmod(0o755)
        self.bundle = self.tmp / 'bundle'
        self.bundle.mkdir()
        (self.bundle / 'bundle.json').write_text(json.dumps(PROFILE))
        for name in ('outer-ca.pem', 'inner-ca.pem', 'device-ca.pem'):
            (self.bundle / name).write_text(PEM)
        self.config = self.tmp / 'ssh-config'
        self.config.write_text('Host relay-a\n  HostName 192.0.2.10\n')
        self.config.chmod(0o600)
        self.log = self.tmp / 'ssh.log'
        self.lock = self.tmp / 'locks' / 'invite.lock'
        self.out = self.tmp / 'friend.aegis-invite'

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_script(self, *extra, mode='ok', device='macos-friend-1', out=None, token=TOKEN):
        env = {'PATH': f'{self.bin}:/usr/bin:/bin', 'HOME': str(self.tmp),
               'FAKE_SSH_LOG': str(self.log), 'FAKE_SSH_MODE': mode,
               'FAKE_SSH_TOKEN': token}
        argv = ['/usr/bin/python3', '-I', '-B', str(SCRIPT), '--device-id', device,
                '--bundle-dir', str(self.bundle), '--out', str(out or self.out),
                '--ssh-config', str(self.config), '--lock-file', str(self.lock), *extra]
        return subprocess.run(argv, env=env, capture_output=True, text=True, timeout=60)

    def calls(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_writes_a_private_canonical_package_without_showing_the_token(self):
        done = self.run_script()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertNotIn(TOKEN, done.stdout + done.stderr)
        info = self.out.lstat()
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        raw = self.out.read_bytes()
        value = json.loads(raw)
        self.assertEqual(sorted(value), ['bundle', 'device_id', 'invitation', 'schema'])
        self.assertEqual(value['schema'], 'aegis_device_invite_v1')
        self.assertEqual(value['device_id'], 'macos-friend-1')
        self.assertEqual(value['invitation'], TOKEN)
        self.assertEqual(value['bundle']['inner-ca.pem'], PEM)
        self.assertEqual(value['bundle']['bundle.json'],
                         (self.bundle / 'bundle.json').read_text())
        # The canonical form invite_package.rs admits: sorted, compact.
        self.assertEqual(raw, json.dumps(value, sort_keys=True, separators=(',', ':'),
                                         ensure_ascii=False).encode())
        self.assertTrue(raw.startswith(b'{"bundle":{"bundle.json":'))
        # One SSH call: the project config and alias, batch mode, root
        # python from stdin; the remote program names the exact invite.
        (call,) = self.calls()
        argv = call['argv']
        self.assertEqual(argv[argv.index('-F') + 1], str(self.config))
        self.assertIn('BatchMode=yes', argv)
        self.assertEqual(argv[-2:], ['relay-a', '/usr/bin/sudo -n /usr/bin/python3 -I -B -'])
        program = call['program']
        self.assertIn('"device_id": "macos-friend-1"', program)
        self.assertIn('"registry": "/opt/aegis-macos-test-20261021/registry.json"', program)
        self.assertIn('"server": "/opt/aegis-macos-test-20261021/aegis-server"', program)
        self.assertIn('"ttl_secs": 86400', program)
        self.assertIn("'--token-out'", program)
        self.assertIn("dir='/run'", program)
        self.assertNotIn(TOKEN, program)
        # The lock is gone again.
        self.assertFalse(self.lock.exists())

    def test_refuses_an_existing_output_before_contacting_the_relay(self):
        self.out.write_text('keep me')
        done = self.run_script()
        self.assertEqual(done.returncode, 3)
        self.assertEqual(self.out.read_text(), 'keep me')
        self.assertEqual(self.calls(), [])
        link = self.tmp / 'link.aegis-invite'
        link.symlink_to(self.tmp / 'nowhere')
        self.assertEqual(self.run_script(out=link).returncode, 3)
        self.assertEqual(self.run_script(out=self.tmp / 'friend.json').returncode, 3)
        self.assertEqual(self.calls(), [])

    def test_a_held_lock_refuses_and_contacts_nothing(self):
        self.lock.parent.mkdir()
        fd = os.open(self.lock, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            done = self.run_script()
        finally:
            os.close(fd)
        self.assertEqual(done.returncode, 4, done.stderr)
        self.assertIn('lock busy', done.stderr)
        self.assertEqual(self.calls(), [])
        self.assertFalse(self.out.exists())

    def test_relay_failures_write_nothing_and_never_echo_a_token_shape(self):
        for mode in ('refuse', 'malformed', 'fail', 'silent'):
            with self.subTest(mode=mode):
                done = self.run_script(mode=mode)
                self.assertEqual(done.returncode, 5, done.stderr)
                self.assertFalse(self.out.exists())
                for shape in ('b' * 64, 'c' * 64, TOKEN):
                    self.assertNotIn(shape, done.stdout + done.stderr)
                self.assertFalse(self.lock.exists())
        refused = self.run_script(mode='refuse')
        self.assertIn('permanently cancelled', refused.stderr)
        self.assertIn('<redacted>', refused.stderr)
        # A definite refusal minted nothing; an ssh failure may have.
        self.assertNotIn('may have minted', refused.stderr)
        self.assertIn('may have minted', self.run_script(mode='fail').stderr)
        # An uppercase or short token from the relay is refused too.
        self.assertEqual(self.run_script(token='A' * 64).returncode, 5)
        self.assertFalse(self.out.exists())

    def test_bundle_device_id_ttl_and_config_are_checked_first(self):
        cases = []
        (self.bundle / 'extra.txt').write_text('x')
        cases.append(('extra member', self.run_script()))
        (self.bundle / 'extra.txt').unlink()
        (self.bundle / 'inner-ca.pem').write_text(
            '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n')
        cases.append(('private key', self.run_script()))
        (self.bundle / 'inner-ca.pem').write_text(PEM)
        socks = dict(PROFILE, product_mode='socks-only')
        (self.bundle / 'bundle.json').write_text(json.dumps(socks))
        cases.append(('socks profile', self.run_script()))
        (self.bundle / 'bundle.json').write_text(json.dumps(PROFILE))
        cases.append(('device id', self.run_script(device='bad id/x')))
        cases.append(('leading dash', self.run_script('--device-id=-oProxyCommand')))
        cases.append(('ttl', self.run_script('--ttl-secs', '86401')))
        cases.append(('relay root', self.run_script('--relay-root', '/opt/../etc')))
        self.config.chmod(0o644)
        cases.append(('ssh config', self.run_script()))
        self.config.chmod(0o600)
        for label, done in cases:
            self.assertEqual(done.returncode, 3, f'{label}: {done.stderr}')
        self.assertEqual(self.calls(), [])
        self.assertFalse(self.out.exists())

    def test_dry_run_prints_the_plan_and_contacts_nothing(self):
        done = self.run_script('--dry-run')
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn('dry run', done.stdout)
        self.assertIn('--ttl-secs 86400', done.stdout)
        self.assertEqual(self.calls(), [])
        self.assertFalse(self.out.exists())


if __name__ == '__main__':
    unittest.main()
