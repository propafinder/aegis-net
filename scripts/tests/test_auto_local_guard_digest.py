"""Local capture must preserve both literal policy and shell binding digests."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1] / 'lib'
sys.path.insert(0, str(ROOT))


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guardian = load('aegis_auto_guardian')
policy = load('aegis_auto_guard_policy')
BOOT = '11111111-2222-3333-4444-555555555555'
STATE = b'''schema=aegis_device_guard_v2
armed=1
service=aegis-client.service
uplink=eth0
manager=systemd-networkd.service
capture_interface=aegis-tun0
capture_profile=wide-redirect-safe
management_address_policy=current_local
management_ports=22
dhcp4=1
dhcp6=1
initramfs_network=absent_verified
'''


class LocalGuardDigest(unittest.TestCase):
    def derive(self, state=STATE, binding_sha=None, *, mode='wide-redirect-safe',
               owner_epoch=False, expected_current='f'*64,
               mutate_original=None, mutate_state=False):
        expected_state = STATE.replace(b'wide-redirect-safe', mode.encode())
        state = state.replace(b'wide-redirect-safe', mode.encode())
        current_state = [state]
        manager = dict(schema='aegis_device_guard_binding_v1', boot_id=BOOT,
                       state_sha256=binding_sha or hashlib.sha256(expected_state.rstrip(b'\n')).hexdigest(),
                       path='system.slice/systemd-networkd.service', inode='77', invocation='a'*32)
        lease = SimpleNamespace(revalidate=Mock(), close=Mock(), config_sha256='1'*64,
                                config_semantic_sha256='2'*64, listen_ipv4='127.0.0.1',
                                listen_port=980 if mode=='full-wide-tun' else 15080, dns_port=53, udp_port=1980)
        endpoint = SimpleNamespace(admit_local_redirect_config=Mock(return_value=lease),
                                   admit_local_fulltun_config=Mock(return_value=lease),
                                   _configured_relay_pool=lambda _relay: [('ordinary','192.0.2.1:443')])
        request = dict(mode=mode, transaction_nonce='b'*32,
                       planned_generation='c'*64, private_unit='aegis-auto@'+'d'*64+'.service',
                       boot_id=BOOT, netns_ino=3)
        real_stat = Path.stat
        def source_stat(path, *args, **kwargs):
            if str(path) == '/sys/fs/cgroup/' + manager['path']:
                return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_ino=77)
            return real_stat(path, *args, **kwargs)
        def regular(path, *_args):
            return json.dumps(manager).encode() if str(path).endswith('.manager-binding') else current_state[0]
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryFile() as config:
            config_raw=b'[relay]\nserver = "192.0.2.1:443"\n';config.write(config_raw);config.flush()
            lease.config=SimpleNamespace(fd=config.fileno(),identity=(0,0,0,len(config_raw)))
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with patch.object(guardian, 'verified_module', side_effect=lambda path, _name:
                                  policy if path == guardian.POLICY_SOURCE else endpoint), \
                     patch.object(guardian, 'regular', side_effect=regular), \
                     patch.object(guardian, 'record', return_value={
                         'state_sha256': hashlib.sha256(expected_state).hexdigest(), 'policy_sha256': 'e'*64}) as saved, \
                     patch.object(Path, 'stat', source_stat), \
                     patch.object(Path, 'exists', return_value=True), \
                     patch.object(Path, 'is_symlink', return_value=False), \
                     patch.object(guardian, '_fulltun_first_arm', return_value=('3'*64,['192.0.2.1:443'])), \
                     patch.object(policy, '_scoped_read') as intent:
                    original=guardian._local_config_binding(fd, request, 'e'*64)
                    if not owner_epoch:return original
                    saved.return_value={'state_sha256':hashlib.sha256(expected_state).hexdigest(),
                                        'policy_sha256':'f'*64}
                    if mutate_original:original.update(mutate_original)
                    if mutate_state:current_state[0]=state.rstrip(b'\n')
                    intent.return_value={'binding':original}
                    return guardian._local_owner_binding(fd,request,'e'*64,
                        current_policy_sha256=expected_current)
            finally:
                os.close(fd)

    def test_dnat_ports_require_same_sealed_owner_and_remain_loopback_only(self):
        for mode in ('wide-redirect-safe','full-wide-tun'):
            state=STATE.replace(b'wide-redirect-safe',mode.encode())
            binding=self.derive(state=state,mode=mode)
            client={'schema':'aegis_device_guard_binding_v1','boot_id':BOOT,
                    'state_sha256':binding['guard_state_sha256'],
                    'path':'system.slice/'+binding['private_unit'],
                    'inode':'12345','invocation':'a'*32}
            def ports(intent=None,actual_client=None,raw=state):
                with patch.object(Path,'exists',return_value=True), \
                     patch.object(Path,'stat',return_value=SimpleNamespace(st_mode=stat.S_IFDIR,st_ino=12345)), \
                     patch.object(policy,'_scoped_read',return_value=intent or policy._local_intent(binding)), \
                     patch.object(policy,'_local_binding',side_effect=lambda value:value):
                    return policy.local_guard_dnat_ports(raw,actual_client or client,BOOT)
            expected=(('udp',53),) if mode=='wide-redirect-safe' else (('udp',53),('tcp',980),('udp',binding['udp_port']))
            self.assertEqual(ports(),expected)
            for change in ({'private_unit':'aegis-auto@'+'9'*64+'.service'},
                           {'guard_state_sha256':'9'*64},{'boot_id':'99999999-2222-3333-4444-555555555555'},
                           {'profile':'output_only_safe' if mode=='full-wide-tun'else 'full_wide_tun'}):
                with self.assertRaises(policy.PolicyRefused):
                    ports(policy._local_intent(dict(binding,**change)))
            with self.assertRaises(policy.PolicyRefused):
                ports(actual_client=dict(client,inode='12346'))
            self.assertEqual(policy.local_guard_dnat_ports(state,None,BOOT),())
            parsed=policy.parse_state(state)
            rows=policy._expected(parsed,client,None,local_dnat_ports=expected)
            for chain in ('output','postroute'):
                for protocol,port in expected:
                    match=next(row for row in rows[chain] if
                        {'match':{'op':'==','left':{'payload':{'protocol':protocol,'field':'dport'}},'right':port}} in row['expr'])
                    self.assertIn({'match':{'op':'==','left':{'payload':{'protocol':'ip','field':'daddr'}},'right':'127.0.0.1'}},match['expr'])
                    self.assertIn({'match':{'op':'in','left':{'ct':{'key':'status'}},'right':'dnat'}},match['expr'])

    def test_shell_binding_with_terminal_lf_survives_local_capture_validation(self):
        binding = self.derive()
        self.assertEqual(binding['guard_state_sha256'], hashlib.sha256(STATE.rstrip(b'\n')).hexdigest())
        self.assertEqual(policy._local_binding(binding, check_host=False), binding)

    def test_literal_policy_pin_and_binding_pin_remain_distinct_gates(self):
        with self.assertRaises(guardian.Refused):
            self.derive(state=STATE.rstrip(b'\n'))
        with self.assertRaises(policy.PolicyRefused):
            self.derive(binding_sha=hashlib.sha256(STATE).hexdigest())


    def test_current_policy_epoch_preserves_original_local_owner_for_both_modes(self):
        for mode in ('wide-redirect-safe','full-wide-tun'):
            with self.subTest(mode=mode):
                binding=self.derive(mode=mode,owner_epoch=True)
                self.assertEqual(binding['guard_policy_sha256'],'e'*64)
                self.assertEqual(policy._local_binding(binding,check_host=False),binding)

    def test_stale_current_policy_or_changed_original_owner_still_refuses(self):
        for mode in ('wide-redirect-safe','full-wide-tun'):
            for kwargs in ({'expected_current':'e'*64}, {'expected_current':None},
                           {'mutate_original':{'guard_policy_sha256':'f'*64}},
                           {'mutate_original':{'stage_ino':999}},
                           {'mutate_state':True}):
                with self.subTest(mode=mode,case=kwargs),self.assertRaises(guardian.Refused):
                    self.derive(mode=mode,owner_epoch=True,**kwargs)


if __name__ == '__main__':
    unittest.main()
