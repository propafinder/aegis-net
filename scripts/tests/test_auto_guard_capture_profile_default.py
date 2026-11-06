"""Execute the production state parser before any lock/kernel/service operation."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE=Path(__file__).resolve().parents[1]/'aegis-device-egress-guard.sh'
BASE=('schema=aegis_device_guard_v2\narmed=1\nservice=aegis-client.service\nuplink=up0\n'
      'manager=systemd-networkd.service\ncapture_interface=aegis-tun0\n'
      'management_address_policy=current_local\nmanagement_ports=\ndhcp4=1\ndhcp6=0\ninitramfs_network=absent_verified\n')


class GuardCaptureProfileDefault(unittest.TestCase):
    def parse(self,raw,action='capture-bind'):
        source=SOURCE.read_text();start=source.index('# The state is administrator-owned and parsed as data')
        end=source.index('# Serialize guard transactions with a verified administrative lock file;',start)
        parser=source[start:end]
        with tempfile.TemporaryDirectory(prefix='aegis-profile-') as folder:
            path=Path(folder)/'state';path.write_text(raw)
            program=('set -euo pipefail\nSTATE="$STATE_FILE"\nACTION="$TEST_ACTION"\n'
                'aegis_root_read(){ cat "$1"; }\nfail(){ printf "%s\\n" "$1" >&2; exit 91; }\n'+parser+
                '\nprintf "PROFILE=%s\\n" "$capture_profile"\n')
            result=subprocess.run(['/bin/bash','--noprofile','--norc','-c',program],text=True,
                capture_output=True,timeout=5,env={**os.environ,'STATE_FILE':str(path),'TEST_ACTION':action})
            self.assertEqual(path.read_text(),raw,'normalization must not rewrite bound state bytes')
            return result

    def test_supported_omitted_v2_profile_is_fulltun_for_every_mutation(self):
        for action in ('capture-bind','bind','bind-manager','block','manager-ready','refresh-manager-lease'):
            with self.subTest(action=action):
                result=self.parse(BASE,action);self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(result.stdout,'PROFILE=full-wide-tun\n')

    def test_explicit_supported_profiles_are_preserved(self):
        for profile in ('full-wide-tun','wide-redirect-safe'):
            result=self.parse(BASE+'capture_profile='+profile+'\n')
            self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout,'PROFILE='+profile+'\n')

    def test_explicit_empty_unknown_or_duplicate_profile_cannot_become_a_default(self):
        for tail in ('capture_profile=\n','capture_profile=foreign\n',
                     'capture_profile=full-wide-tun\ncapture_profile=wide-redirect-safe\n'):
            with self.subTest(tail=tail):
                result=self.parse(BASE+tail);self.assertEqual(result.returncode,91,result.stderr)

    def test_v1_profile_policy_is_unchanged(self):
        raw=BASE.replace('schema=aegis_device_guard_v2','schema=aegis_device_guard_v1').replace(
            'manager=systemd-networkd.service','manager=networking.service').replace('management_address_policy=current_local\n','')
        result=self.parse(raw,'block');self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,'PROFILE=full-wide-tun\n')
        self.assertEqual(self.parse(raw+'capture_profile=full-wide-tun\n','block').returncode,91)


if __name__=='__main__':unittest.main()
