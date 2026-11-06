#!/usr/bin/env bash
# Exercise the actual trusted bootstrap supervisor in private local fixtures.
# No candidate binary, service, credential, network or system state is used.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$ROOT" <<'PY'
import copy, hashlib, json, os, signal, subprocess, sys, tempfile, time
from pathlib import Path

root=Path(sys.argv[1])
text=(root/'bootstrap-install.sh').read_text()
code=text.split("<<'PY_RELEASE_FLOOR'\n",1)[1].split('\nPY_RELEASE_FLOOR',1)[0]
scope='client-linux-x86_64'
authority='github:fixture/repository:.github/workflows/release.yml'
stdin_fd=os.open(os.devnull,os.O_RDONLY)
if stdin_fd != 3:
    os.dup2(stdin_fd,3);os.close(stdin_fd)

with tempfile.TemporaryDirectory(prefix='aegis-release-floor-') as tmp:
    work=Path(tmp);state=work/'administrator'/'releases';manifest=work/'verified.json';marker=work/'installer-ran'
    floor=state/(scope+'.json');pending=state/(scope+'.pending.json')
    normal=[sys.executable,'-c','from pathlib import Path; import sys; Path(sys.argv[1]).write_text("installed")',str(marker)]
    count=0
    def candidate(seq,**extra):
        now=int(time.time())
        value={'version':'1.2.3','channel':'rc','prerelease':True,'release_policy':{
            'schema':'aegis_release_policy_v1','authority':authority,'sequence':seq,'tag':'v1.2.3-rc.1',
            'issued_at_unix':now-60,'expires_at_unix':now+3600},**extra}
        # Stable fixture bytes for a reproducible retry of one release.
        value['release_policy']['issued_at_unix']=stamp-60
        value['release_policy']['expires_at_unix']=stamp+3600
        return value
    stamp=int(time.time())
    def set_manifest(value):
        manifest.write_text(json.dumps(value,sort_keys=True));return hashlib.sha256(manifest.read_bytes()).hexdigest()
    def args(action,digest='',command=None,at=None):
        return [sys.executable,'-c',code,action,str(at or state),scope,str(manifest),digest,*(command or [])]
    def run(action,digest='',command=None,good=True,at=None,reason=None):
        global count
        count+=1;result=subprocess.run(args(action,digest,command,at),capture_output=True,text=True,pass_fds=(3,),timeout=10)
        assert (result.returncode==0)==good,(action,result.stdout,result.stderr)
        if reason:assert reason in result.stderr,result.stderr
        return result
    value10=candidate(10);digest10=set_manifest(value10)
    run('check',digest10);assert not state.exists(), 'read-only first check created state'
    run('install',digest10,normal);assert marker.exists()
    assert json.loads(floor.read_text())['sequence']==10 and not pending.exists()
    assert floor.stat().st_mode & 0o777 == 0o600
    run('install',digest10,normal);assert not pending.exists()
    marker.unlink()
    run('install',set_manifest(candidate(9)),normal,False,reason='below the installed floor');assert not marker.exists()
    run('install',set_manifest(candidate(10,changed='different signed bytes')),normal,False,reason='different manifest bytes');assert not marker.exists()
    assert json.loads(floor.read_text())['manifest_sha256']==digest10
    historical=set_manifest({'historical':'signed and explicitly pinned upstream'})
    run('check',historical,good=False,reason='historical metadata cannot bypass')
    other=candidate(11);other['release_policy']['authority']='github:another/repo:.github/workflows/release.yml'
    run('check',set_manifest(other),good=False,reason='authority change')
    expired=candidate(11);expired['release_policy']['expires_at_unix']=stamp-1
    run('check',set_manifest(expired),good=False,reason='no longer valid')
    digest11=set_manifest(candidate(11))
    run('install',digest11,[sys.executable,'-c','raise SystemExit(9)'],False)
    assert json.loads(floor.read_text())['sequence']==10 and pending.exists()
    run('check',digest11,good=False,reason='interrupted installation')
    run('discard-failed')
    run('install','0'*64,normal,False,reason='manifest bytes changed');assert not marker.exists()

    # A second installer cannot execute between check and successful advance.
    release=work/'release-waiter';ready=work/'waiter-ready'
    waiter=[sys.executable,'-c',
        'import os,time,sys;from pathlib import Path;Path(sys.argv[1]).write_text(str(os.getpid()));end=time.monotonic()+15\n'
        'while not Path(sys.argv[2]).exists():\n if time.monotonic()>end:raise SystemExit(98)\n time.sleep(.02)\n',str(ready),str(release)]
    def wait_for(path):
        end=time.monotonic()+8
        while not path.exists():
            assert time.monotonic()<end,'fixture stage not reached';time.sleep(.02)
    with (work/'supervisor.log').open('w') as output:
        supervisor=subprocess.Popen(args('install',digest11,waiter),stdout=output,stderr=output,pass_fds=(3,))
        try:
            wait_for(ready)
            run('install',digest11,normal,False,reason='another installation transaction');assert not marker.exists()
            release.write_text('finish');assert supervisor.wait(timeout=8)==0
        finally:
            release.write_text('finish')
            if supervisor.poll() is None:supervisor.terminate();supervisor.wait(timeout=8)
    assert json.loads(floor.read_text())['sequence']==11 and not pending.exists()

    # SIGKILL releases the supervisor but the child retains the same flock.
    # Once the child exits, the journal remains for explicit bounded recovery.
    ready.unlink();release.unlink();digest12=set_manifest(candidate(12))
    with (work/'crash.log').open('w') as output:
        supervisor=subprocess.Popen(args('install',digest12,waiter),stdout=output,stderr=output,pass_fds=(3,))
        try:
            wait_for(ready);supervisor.kill();supervisor.wait(timeout=8)
            run('inspect',good=False,reason='another installation transaction')
            release.write_text('finish')
            end=time.monotonic()+8
            while True:
                result=subprocess.run(args('inspect'),capture_output=True,text=True,pass_fds=(3,),timeout=3)
                if result.returncode==0:break
                assert time.monotonic()<end,result.stderr;time.sleep(.02)
        finally:
            release.write_text('finish')
            if supervisor.poll() is None:supervisor.kill();supervisor.wait(timeout=8)
    snapshot=json.loads(result.stdout)
    assert snapshot['floor']['sequence']==11 and snapshot['pending']['sequence']==12
    run('check',digest12,good=False,reason='interrupted installation')
    run('confirm-installed');assert json.loads(floor.read_text())['sequence']==12 and not pending.exists()

    # Explicit failure recovery preserves the previous floor. Invalid journals
    # cannot authorize a lowering/authority change even through recovery.
    journal=json.loads(floor.read_text());journal['sequence']=13;journal['manifest_sha256']='c'*64
    pending.write_text(json.dumps(journal));pending.chmod(0o600)
    run('discard-failed');assert json.loads(floor.read_text())['sequence']==12 and not pending.exists()
    journal['sequence']=1;pending.write_text(json.dumps(journal));pending.chmod(0o600)
    run('confirm-installed',good=False,reason='below the installed floor');assert pending.exists()
    pending.unlink()
    # A crash after floor fsync but before journal unlink is unambiguous.
    pending.write_bytes(floor.read_bytes());pending.chmod(0o600)
    run('check',digest12);run('install',digest12,normal);assert not pending.exists()

    saved=floor.read_bytes();floor.chmod(0o644)
    run('check',digest12,good=False,reason='private regular files');floor.chmod(0o600)
    floor.unlink();floor.symlink_to(manifest)
    run('check',digest12,good=False);floor.unlink();floor.write_bytes(saved);floor.chmod(0o600)
    linked=work/'linked';linked.symlink_to(state)
    run('check',digest12,good=False,at=linked)
    missing=floor.with_name('saved.json');floor.rename(missing);floor.write_text('{invalid');floor.chmod(0o600)
    run('check',digest12,good=False);floor.unlink();missing.rename(floor)
    assert not pending.exists()
    print(f'PASS: {count} release-floor operations; monotonic digest binding, failed install, concurrent lock, SIGKILL journal, explicit recovery, strict paths')
os.close(3)
PY
