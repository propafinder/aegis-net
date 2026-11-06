#!/usr/bin/env python3
"""Whole actual wrapper + independent disable with real metadata and inert OS seams.
No route/service/conntrack/cgroup acceptance. Requires a reviewed local client binary.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import signal
import sys
import tempfile
import unittest

ROOT = Path(os.environ.get("AEGIS_TEST_PROJECT_ROOT", Path(__file__).resolve().parents[1]))
SOURCE = Path(os.environ.get('AEGIS_WIDE_WRAPPER_SOURCE', ROOT/'scripts/aegis-wide-enable.sh'))
spec = importlib.util.spec_from_file_location('wide_config_fixture', ROOT/'scripts/test-wide-config-staging-contract.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)

MOCK = r"""#!__PYTHON__
import json,os,pathlib,subprocess,sys,signal
root=pathlib.Path(os.environ['AEGIS_TEST_ROOT'])
name=pathlib.Path(sys.argv[0]).name
args=sys.argv[1:]
state=root/'generation'
generation=int(state.read_text()) if state.exists() else 0
failure=os.environ.get('WRAPPER_FAILURE','')
with (root/'whole-calls.jsonl').open('a') as out:
    out.write(json.dumps([name,args,generation,os.environ.get('AEGIS_WIDE_EXEMPT_CGROUP')])+'\n')
if name == 'timeout':
    sys.exit(subprocess.run(args[1:],timeout=int(args[0])+1).returncode)
if name == 'systemctl':
    if args[:1] == ['show']:
        key=args[args.index('-p')+1]
        print({'Group':'0','User':'root','ActiveState':'active','MainPID':str(321+generation),'ControlGroup':'/system.slice/aegis-client.service'}.get(key,''))
    elif args == ['restart','aegis-client']:
        if failure == 'restart' and generation == 0: sys.exit(71)
        state.write_text(str(generation+1))
    elif args[:1] in (['is-active'],['is-enabled']): sys.exit(1)
    sys.exit(0)
if name == 'stat':
    if args[:2] == ['-c','%i'] and len(args)==3 and str(root) in args[2] and '/sys/fs/cgroup' in args[2]:
        print(777+generation);sys.exit(0)
    # Trusted metadata/executable ownership checks retain actual native stat.
    real_stat=os.environ['AEGIS_TEST_REAL_STAT']
    assert pathlib.Path(real_stat).is_absolute() and real_stat != sys.argv[0]
    sys.exit(subprocess.run([real_stat,*args]).returncode)
if name == 'ss':
    if failure == 'readiness': sys.exit(72)
    if '-ltnp' in args: print('LISTEN 0 128 127.0.0.1:15080 0.0.0.0:* users:(("fixture",pid='+str(321+generation)+',fd=4))')
    elif '-lunp' in args: print('UNCONN 0 0 127.0.0.1:53 0.0.0.0:* users:(("fixture",pid='+str(321+generation)+',fd=5))')
    else: sys.exit(98)
    sys.exit(0)
if name.startswith('setup-wide-linux-'):
    if args == ['cgroup-path'] and generation > 0 and failure == 'rollover':
        state.write_text(str(generation+1));generation+=1
    if args != ['teardown'] and os.environ.get('AEGIS_WIDE_EXPECTED_SERVICE_PID'):
        assert os.environ.get('AEGIS_WIDE_EXPECTED_CGROUP_INODE')
        if os.environ['AEGIS_WIDE_EXPECTED_SERVICE_PID'] != str(321+generation) or os.environ['AEGIS_WIDE_EXPECTED_CGROUP_INODE'] != str(777+generation):
            sys.exit(76)
    if args == ['preflight'] and generation > 0 and failure == 'signal' and not (root/'owned-signal-delivered').exists():
        owned_pid=int((root/'owned-wrapper.pid').read_text())
        assert owned_pid == os.getppid(), 'signal seam parent was not owned wrapper'
        # Arm one-shot delivery before signaling. Independent rollback's own
        # helper preflight must retain normal behavior and cannot reinject.
        with (root/'owned-signal-delivered').open('x') as receipt:
            receipt.write(str(owned_pid))
        os.kill(owned_pid,signal.SIGTERM)
    if args != ['teardown']:
        assert os.environ.get('AEGIS_WIDE_REQUIRE_CGROUP') == '1'
        assert os.environ.get('AEGIS_WIDE_EXEMPT_SERVICE') == 'aegis-client.service'
    if args == ['cgroup-path']:
        assert os.environ.get('AEGIS_WIDE_EXEMPT_CGROUP') is None or (os.environ.get('AEGIS_WIDE_EXPECTED_SERVICE_PID') and os.environ.get('AEGIS_WIDE_EXEMPT_CGROUP') == 'system.slice/aegis-client.service')
        if failure == 'late-identity' and generation > 0: sys.exit(73)
        print('system.slice/aegis-client.service')
    elif args == ['preflight']:
        assert os.environ.get('AEGIS_WIDE_EXEMPT_CGROUP') == 'system.slice/aegis-client.service'
        if failure == 'late-preflight' and generation > 0: sys.exit(74)
    elif args == ['apply']:
        if failure == 'apply': sys.exit(75)
    elif args != ['teardown']: sys.exit(98)
    sys.exit(0)
if name in ('iptables','ip6tables'):
    sys.exit(1 if '-C' in args else 0)
if name == 'ip':
    # This fixture creates no native TUN. Actual independent-disable terminal
    # readback must see absence, not a false positive from generic mock success.
    if args == ['link','show','aegis-tun0']: sys.exit(1)
    if args[:4] == ['-4','route','show','default']: print('default via 192.0.2.1 dev fixture0')
    sys.exit(0)
if name in ('nft','firewall-cmd'): sys.exit(1)
if name in ('sysctl','logger','journalctl','networkctl','resolvectl','janitor-wide-linux-tproxy.sh'): sys.exit(0)
if name in ('setsid','sudo'): sys.exit(99)
# All unsupported native operations refuse rather than falling through.
sys.exit(97)
"""

class WholeWrapper(unittest.TestCase):
    def run_wrapper(self, failure='', dns='preview'):
        client=Path(os.environ.get('AEGIS_TEST_CLIENT_BINARY', ROOT/'target/debug/aegis-client')).resolve()
        self.assertTrue(client.is_file() and os.access(client,os.X_OK),'reviewed local client binary required; no build fallback')
        temp=tempfile.TemporaryDirectory(prefix='aegis-wrapper-transaction-')
        self.addCleanup(temp.cleanup)
        directory=Path(temp.name).resolve()/'fixture'
        f=fixture.Fixture(directory,SOURCE,ROOT/'scripts/aegis-wide-disable.sh',ROOT/'scripts/aegis-wide-disable.sh',ROOT/'scripts/lib/root-state.sh',client,False)
        (f.root/'host/run').mkdir(parents=True,exist_ok=True)
        fixture.put(f.root/'host/etc/resolv.conf',b'nameserver 192.0.2.53\n')
        fixture.put(f.cfg,fixture.CONFIG+b'[relay]\nserver="203.0.113.9:443"\n')
        text=SOURCE.read_text()
        for prefix in ('/etc/','/var/lib/','/run/','/sys/fs/cgroup'):
            text=text.replace(prefix,str(f.root/'host')+prefix)
        wrapper=f.lib/'aegis-wide-enable.sh'
        fixture.executable(wrapper,text)
        for name in ('timeout','systemctl','ss','stat','iptables','ip6tables','ip','nft','firewall-cmd','sysctl','logger','journalctl','networkctl','resolvectl','setsid','sudo'):
            fixture.executable(f.bin/name,MOCK.replace('__PYTHON__',sys.executable))
        for name in ('setup-wide-linux-redirect.sh','setup-wide-linux-tproxy.sh','janitor-wide-linux-tproxy.sh'):
            fixture.executable(f.lib/name,MOCK.replace('__PYTHON__',sys.executable))
        # Real sleep bounds readiness; actual independent disable remains in f.lib.
        real_stat=shutil.which('stat')
        self.assertTrue(real_stat and Path(real_stat).is_absolute())
        f.env['AEGIS_TEST_REAL_STAT']=real_stat
        f.env.update(AEGIS_EXEMPT_UID='0',WRAPPER_FAILURE=failure,
                     SSH_CONNECTION='192.0.2.7 45678 198.51.100.8 22')
        if failure == 'rollback':
            f.env['WRAPPER_FAILURE']='late-preflight'
            f.env['AEGIS_TEST_ROLLBACK_PREFLIGHT_FAIL']='1'
        original=f.cfg.read_bytes()
        if failure == 'unexpected-exit':
            seam=f.root/'owned-exit-seam.sh'
            fixture.executable(seam,'''trap 'if [[ "${aegis_wide_config_applied:-0}" == 1 && "$BASH_COMMAND" == "unset AEGIS_WIDE_EXEMPT_CGROUP" ]]; then exit 77; fi' DEBUG\n''')
            f.env['BASH_ENV']=str(seam)
        child=subprocess.Popen([f.bash,str(wrapper),'--yes','--no-rollback','--mode=redirect','--interface=fixture0','--dns='+dns,'--ipv6=block'],env=f.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        (f.root/'owned-wrapper.pid').write_text(str(child.pid))
        try:
            stdout,stderr=child.communicate(timeout=55)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid,signal.SIGKILL)
            child.communicate(timeout=3)
            raise
        result=subprocess.CompletedProcess(child.args,child.returncode,stdout,stderr)
        rows=[json.loads(line) for line in (f.root/'whole-calls.jsonl').read_text().splitlines()]
        return f,result,rows,original

    def check_rollback(self,f,result,rows,original):
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(f.backup.read_bytes(),original)
        stages=list(f.cfg.parent.glob('.aegis-wide-config.*'))
        self.assertEqual(len(stages),1)
        self.assertEqual(sorted(path.name for path in stages[0].iterdir()),['backup.toml','original.toml','render.toml'])
        self.assertEqual((stages[0]/'original.toml').read_bytes(),original)
        self.assertEqual((stages[0]/'backup.toml').read_bytes(),original)
        # Actual disable restores the retained original and explicitly disables
        # wide ingress; it must not leave preview listener configuration live.
        self.assertNotIn(b'dns_preview_listen = "127.0.0.1:53"',f.cfg.read_bytes())
        self.assertEqual((f.root/'host/etc/resolv.conf').read_bytes(),b'nameserver 192.0.2.53\n')
        self.assertTrue(any(r[0]=='setup-wide-linux-redirect.sh' and r[1]==['teardown'] for r in rows))

    def test_success_rebinds_after_restart_and_owned_listener_readiness(self):
        f,result,rows,original=self.run_wrapper()
        self.assertEqual(result.returncode,0)
        restart=next(i for i,r in enumerate(rows) if r[0]=='systemctl' and r[1]==['restart','aegis-client'])
        ready=max(i for i,r in enumerate(rows) if r[0]=='ss')
        identities=[(i,r[2])for i,r in enumerate(rows)if r[0]=='setup-wide-linux-redirect.sh'and r[1]==['cgroup-path']]
        apply=next(i for i,r in enumerate(rows)if r[0]=='setup-wide-linux-redirect.sh'and r[1]==['apply'])
        self.assertEqual([g for _,g in identities],[0,1,1])
        self.assertLess(restart,ready);self.assertLess(ready,identities[1][0]);self.assertLess(identities[1][0],apply);self.assertLess(apply,identities[2][0])
        self.assertEqual(f.backup.read_bytes(),original)
        self.assertIn(b'dns_preview_listen = "127.0.0.1:53"',f.cfg.read_bytes())

    def test_dns_off_keeps_config_and_does_not_restart(self):
        f,result,rows,original=self.run_wrapper(dns='off')
        self.assertEqual(result.returncode,0);self.assertEqual(f.cfg.read_bytes(),original)
        self.assertFalse(any(r[0]=='ss'or(r[0]=='systemctl'and r[1]==['restart','aegis-client'])for r in rows))
        self.assertEqual([r[2]for r in rows if r[0]=='setup-wide-linux-redirect.sh'and r[1]==['cgroup-path']],[0])

    def test_restart_failure_independently_restores(self):
        self.check_rollback(*self.run_wrapper(failure='restart'))

    def test_owned_listener_readiness_failure_independently_restores(self):
        self.check_rollback(*self.run_wrapper(failure='readiness'))

    def test_final_identity_failure_independently_restores(self):
        self.check_rollback(*self.run_wrapper(failure='late-identity'))

    def test_final_preflight_failure_independently_restores(self):
        self.check_rollback(*self.run_wrapper(failure='late-preflight'))

    def test_apply_failure_independently_restores(self):
        self.check_rollback(*self.run_wrapper(failure='apply'))

    def test_unexpected_postcommit_exit_recovers_and_retains_all_records(self):
        self.check_rollback(*self.run_wrapper(failure='unexpected-exit'))

    def test_owned_postcommit_term_recovers_once_and_retains_records(self):
        f,result,rows,original=self.run_wrapper(failure='signal')
        self.check_rollback(f,result,rows,original)
        self.assertEqual(sum(r[0]=='systemctl' and r[1]==['disable','aegis-wide.service'] for r in rows),1)
        self.assertEqual((f.root/'owned-signal-delivered').read_text(),(f.root/'owned-wrapper.pid').read_text())

    def test_generation_rollover_after_listeners_refuses_before_capture(self):
        f,result,rows,original=self.run_wrapper(failure='rollover')
        self.check_rollback(f,result,rows,original)
        self.assertFalse(any(r[0]=='setup-wide-linux-redirect.sh' and r[1]==['apply'] for r in rows))

    def test_failed_independent_rollback_retains_verified_recovery(self):
        f,result,rows,original=self.run_wrapper(failure='rollback')
        self.assertNotEqual(result.returncode,0)
        backups=list(f.cfg.parent.glob('.aegis-wide-config.*/backup.toml'))
        self.assertEqual(len(backups),1);self.assertEqual(backups[0].read_bytes(),original)
        self.assertTrue(any(r[0]=='systemctl'and r[1]==['stop','aegis-client']for r in rows))
        self.assertIn(b'recovery records retained',result.stderr)
        self.assertEqual(sorted(path.name for path in backups[0].parent.iterdir()),['backup.toml','original.toml','render.toml'])

if __name__=='__main__':unittest.main()
