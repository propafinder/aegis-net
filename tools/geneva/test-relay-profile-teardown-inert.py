#!/usr/bin/env python3
"""Actual generic teardown programs with temporary roots and inert dependencies.

Proves early refusal before any shared/client/server file mutation or guard
initialization when exact selected ownership exists. No real units/network run.
"""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SELECTED = [
    '/var/lib/aegis-install/client/relay-geneva-profile.json',
    '/var/lib/aegis-install/client/relay-geneva-install-intent.json',
    '/var/lib/aegis-install/client/relay-geneva-teardown.json',
    '/var/lib/aegis-install/client/relay-geneva-guard-state.json',
    '/var/lib/aegis-install/client/relay-geneva-guard-intent.json',
    '/usr/local/lib/aegis/aegis-relay-geneva-profile.sh',
    '/etc/systemd/system/aegis-client.service.d/25-relay-geneva-profile.conf',
    '/run/aegis-relay-geneva',
]


def ownership(path, dangling):
    path.parent.mkdir(parents=True, exist_ok=True)
    if dangling:
        path.symlink_to(path.parent / 'absent-untrusted-target')
    else:
        path.write_bytes(b'PUBLIC_INERT_OWNERSHIP_FIXTURE')


class TeardownBoundaryTests(unittest.TestCase):
    def test_explicit_uninstaller_only_forwards_supported_request_and_failure(self):
        for args, fail, expected in [([],False,0),(['--resume-token','a'*32],False,0),([],True,17),(['--force'],False,2),(['--resume-token','bad'],False,2)]:
            with self.subTest(args=args,fail=fail), tempfile.TemporaryDirectory() as tmp:
                p=Path(tmp); lib=p/'lib'; (lib/'lib').mkdir(parents=True)
                (lib/'lib/root-state.sh').write_text('aegis_root_state_init() { :; }\naegis_root_trusted_executable() { [[ -x "$1" ]]; }\n')
                client=p/'client'; client.write_text('#!/usr/bin/env python3\nimport os,sys,json\nfrom pathlib import Path\nPath(os.environ["CALLS"]).write_text(json.dumps(sys.argv[1:]))\nsys.exit(int(os.environ["EXIT"]))\n');client.chmod(0o700)
                text=(ROOT/'tools/geneva/uninstall-relay-profile.sh').read_text().replace('$EUID','0').replace('/usr/local/lib/aegis',str(lib)).replace('/usr/local/bin/aegis-client',str(client))
                script=p/'uninstall.sh';script.write_text(text)
                result=subprocess.run(['/bin/bash',str(script),*args],env={**os.environ,'CALLS':str(p/'calls'),'EXIT':'17' if fail else '0'},capture_output=True,timeout=5)
                self.assertEqual(result.returncode,expected,result.stderr)
                if expected==2:self.assertFalse((p/'calls').exists())
                else:
                    import json
                    self.assertEqual(json.loads((p/'calls').read_text()),['profile','relay-geneva','teardown',*args])
                self.assertNotIn(b'PASS',result.stdout)

    def test_ubuntu_uninstall_refuses_before_detection_apt_or_manual_purge(self):
        for selected in SELECTED:
            for dangling in [False, True]:
                with self.subTest(selected=selected, dangling=dangling), tempfile.TemporaryDirectory() as tmp:
                    p = Path(tmp)
                    fake = p / 'root'
                    fake.mkdir()
                    q = fake / selected.lstrip('/')
                    ownership(q, dangling)
                    witness = fake / 'var/lib/aegis-install/client/retained-history'
                    witness.parent.mkdir(parents=True, exist_ok=True)
                    witness.write_bytes(b'RETAINED_PUBLIC_HISTORY')
                    calls = p / 'calls'
                    bins = p / 'bin'
                    bins.mkdir()
                    for name in ['dpkg', 'apt-get', 'systemctl', 'nft', 'ip', 'iptables-save', 'ip6tables-save']:
                        tool = bins / name
                        tool.write_text('#!/bin/bash\nprintf "called\\n" >>"$FIXTURE_CALLS"\nexit 0\n')
                        tool.chmod(0o700)
                    result = subprocess.run(['/bin/bash', str(ROOT / 'scripts/aegis-ubuntu-uninstall.sh'), 'purge'],
                                            env={**os.environ, 'PATH': str(bins) + ':' + os.environ['PATH'],
                                                 'AEGIS_UNINSTALL_SKIP_ROOT_CHECK': '1',
                                                 'AEGIS_UNINSTALL_FAKE_ROOT': str(fake), 'FIXTURE_CALLS': str(calls)},
                                            capture_output=True, timeout=5)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(b'generic uninstall refused before mutation', result.stderr)
                    self.assertFalse(calls.exists())
                    self.assertEqual(witness.read_bytes(), b'RETAINED_PUBLIC_HISTORY')
                    self.assertTrue(q.is_symlink() if dangling else q.is_file())

    def test_client_and_all_purge_refuse_before_common_or_role_mutation(self):
        for role in ['client', 'all']:
            for selected in SELECTED:
                for dangling in [False, True]:
                    with self.subTest(role=role, selected=selected, dangling=dangling), tempfile.TemporaryDirectory() as tmp:
                        p = Path(tmp)
                        fake = p / 'root'
                        fake.mkdir()
                        ownership(fake / selected.lstrip('/'), dangling)
                        witnesses = []
                        for rel in ['/usr/local/bin/aegis-client', '/usr/local/bin/aegis-server',
                                    '/usr/lib/systemd/system-preset/90-aegis-client.preset',
                                    '/usr/lib/systemd/system-preset/90-aegis-server.preset',
                                    '/var/lib/aegis-install/client/keep-history']:
                            q = fake / rel.lstrip('/')
                            q.parent.mkdir(parents=True, exist_ok=True)
                            q.write_bytes(b'UNRELATED_FIXTURE_MUST_REMAIN')
                            witnesses.append(q)
                        before = {str(q): hashlib.sha256(q.read_bytes()).digest() for q in witnesses}
                        tool = p / 'inert-tool'
                        tool.write_text('#!/bin/bash\nprintf "called\\n" >>"$FIXTURE_CALLS"\nexit 0\n')
                        tool.chmod(0o700)
                        calls = p / 'calls'
                        env = {**os.environ, 'AEGIS_PURGE_ROOT': str(fake),
                               'AEGIS_PURGE_TMPDIR': str(p), 'FIXTURE_CALLS': str(calls)}
                        for option in ['SYSTEMCTL', 'IPTABLES', 'IP6TABLES', 'NFT', 'IP', 'PKILL', 'USERDEL', 'GROUPDEL']:
                            env['AEGIS_PURGE_' + option + '_BIN'] = str(tool)
                        result = subprocess.run(['/bin/bash', str(ROOT / 'scripts/purge-installed-aegis.sh'), role, '--force'],
                                                env=env, capture_output=True, timeout=5)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(b'generic purge refused before mutation', result.stderr)
                        self.assertFalse(calls.exists())
                        self.assertEqual(before, {str(q): hashlib.sha256(q.read_bytes()).digest() for q in witnesses})
                        q = fake / selected.lstrip('/')
                        self.assertTrue(q.is_symlink() if dangling else q.is_file())

    def test_guard_teardown_refuses_before_helper_initialization(self):
        source = (ROOT / 'scripts/aegis-device-egress-guard.sh').read_text()
        for action in ['recover', 'release', 'recover-nm-policy']:
            for selected in SELECTED:
                for dangling in [False, True]:
                    with self.subTest(action=action, selected=selected, dangling=dangling), tempfile.TemporaryDirectory() as tmp:
                        p = Path(tmp)
                        q = p / selected.lstrip('/')
                        ownership(q, dangling)
                        text = source
                        for exact in sorted(SELECTED, key=len, reverse=True):
                            text = text.replace(exact, str(p / exact.lstrip('/')))
                        script = p / 'guard.sh'
                        script.write_text(text)
                        (p / 'lib').mkdir()
                        calls = p / 'calls'
                        (p / 'lib/root-state.sh').write_text('aegis_root_state_init() { printf "called\\n" >>"$FIXTURE_CALLS"; return 91; }\n')
                        result = subprocess.run(['/bin/bash', str(script), action],
                                                env={**os.environ, 'FIXTURE_CALLS': str(calls)},
                                                capture_output=True, timeout=5)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(b'generic guard recovery/release refused', result.stderr)
                        self.assertFalse(calls.exists())
                        self.assertTrue(q.is_symlink() if dangling else q.is_file())

    def test_without_selected_ownership_guard_reaches_original_initializer(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            text = (ROOT / 'scripts/aegis-device-egress-guard.sh').read_text()
            for exact in sorted(SELECTED, key=len, reverse=True):
                text = text.replace(exact, str(p / exact.lstrip('/')))
            (p / 'guard.sh').write_text(text)
            (p / 'lib').mkdir()
            calls = p / 'calls'
            (p / 'lib/root-state.sh').write_text('aegis_root_state_init() { printf "original initializer\\n" >>"$FIXTURE_CALLS"; return 91; }\n')
            result = subprocess.run(['/bin/bash', str(p / 'guard.sh'), 'recover'],
                                    env={**os.environ, 'FIXTURE_CALLS': str(calls)},
                                    capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(calls.read_text(), 'original initializer\n')
            self.assertNotIn(b'generic guard recovery/release refused', result.stderr)


if __name__ == '__main__':
    unittest.main()
