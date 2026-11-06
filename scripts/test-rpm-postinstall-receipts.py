#!/usr/bin/env python3
"""Exercise exact scratch RPM scriptlet strings with inert system tools."""
import os
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parent
builder = (root / 'build-rpm-packages.sh').read_text()
with tempfile.TemporaryDirectory(prefix='aegis-rpm-receipt-test-') as scratch:
    work = Path(scratch)
    bins = work / 'bin'; bins.mkdir()
    for name in ('systemd-sysusers', 'systemd-tmpfiles'):
        path = bins / name
        path.write_text('#!/bin/sh\n[ "${AEGIS_FAIL:-}" != "' + name + '" ]\n')
        path.chmod(0o755)
    stat_stub = bins / 'stat'
    stat_stub.write_text('#!/bin/sh\ncase "$2" in %u) printf "%s\\n" "' + str(os.getuid()) + '" ;; %a) printf "%s\\n" "${AEGIS_TEST_RUN_MODE:-700}" ;; %u:%a) printf "%s:700\\n" "' + str(os.getuid()) + '" ;; esac\n')
    stat_stub.chmod(0o755)
    for name, marker, nonce in (('SERVER_POST','aegis-server.ok','T1'),('CLIENT_POST','aegis-client.ok','T2')):
        match = re.search(rf"^{name}='(.*?)'\n", builder, re.M | re.S)
        assert match, name
        body = match.group(1)
        script = work / f'{name}.sh'; script.write_text('#!/bin/sh\n' + body.replace('/run/systemd/system',str(work/'absent-systemd')) + '\n')
        subprocess.run(['/bin/sh','-n',str(script)],check=True)
        receipt = work / f'aegis-rpm-postinstall.{nonce}'; receipt.mkdir(mode=0o700)
        script.write_text(script.read_text().replace('/run/aegis-rpm-postinstall.', str(work/'aegis-rpm-postinstall.')).replace('/run', str(work)).replace('0:700', f'{os.getuid()}:700').replace('= 0 ]', f'= {os.getuid()} ]'))
        env = os.environ | {'PATH': f'{bins}:/usr/bin:/bin', 'AEGIS_RPM_POSTINSTALL_NONCE':nonce}
        result = subprocess.run(['/bin/sh',str(script),'1'],env=env,capture_output=True,text=True)
        assert result.returncode == 0,(name,result.stderr)
        assert (receipt/marker).read_text() == f'{nonce}\n',name
        (receipt/marker).unlink()
        failed_tool = 'systemd-sysusers' if name == 'SERVER_POST' else 'systemd-tmpfiles'
        result = subprocess.run(['/bin/sh',str(script),'1'],env=env|{'AEGIS_FAIL':failed_tool},capture_output=True,text=True)
        assert result.returncode != 0,(name,result.stderr)
        assert not (receipt/marker).exists(),name
        result = subprocess.run(['/bin/sh',str(script),'1'],env=env|{'AEGIS_RPM_POSTINSTALL_NONCE':'../unsafe'},capture_output=True,text=True)
        assert result.returncode != 0 and not (receipt/marker).exists(),name
        result = subprocess.run(['/bin/sh',str(script),'1'],env=env|{'AEGIS_TEST_RUN_MODE':'777'},capture_output=True,text=True)
        assert result.returncode != 0 and not (receipt/marker).exists(),name
        print(f'PASS {name}: success receipt, failed %post/unsafe nonce/writable parent leave no receipt')
