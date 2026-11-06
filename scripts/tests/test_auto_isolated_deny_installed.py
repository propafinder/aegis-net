#!/usr/bin/env python3
"""Read-only installed Linux regression. Run only when the guard is denied."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path('/usr/local/lib/aegis/helpers/lib')
GUARDIAN=ROOT/'aegis_auto_guardian.py'
WATCHDOG=ROOT/'aegis_auto_guardian_watchdog.py'
POLICY=Path('/var/lib/aegis-install/client/auto-guardian-policy.json')
PYTHON='/usr/bin/python3'
ENV={'PATH':'/usr/sbin:/usr/bin','LANG':'C','LC_ALL':'C'}


def child(code):
    result=subprocess.run((PYTHON,'-I','-B','-c',code),capture_output=True,
                          timeout=12,check=False,env=ENV)
    assert result.returncode==0 and result.stdout==b'expected_refusal\n', (
        result.returncode,hashlib.sha256(result.stderr).hexdigest())


def test_installed_isolated_deny():
    assert os.geteuid()==0 and GUARDIAN.is_file() and WATCHDOG.is_file()
    expected=json.loads(POLICY.read_bytes())['policy_sha256']
    # Reproduce the historical in-process collision using the real installed
    # loader and its actual source manifest, without changing either.
    child("""import runpy,sys
sys.path.insert(0,'/usr/local/lib/aegis/helpers/lib')
import aegis_auto_foreign_policy
watchdog=runpy.run_path('/usr/local/lib/aegis/helpers/lib/aegis_auto_guardian_watchdog.py')
try: watchdog['_semantic_blocked']()
except Exception as error:
    if str(error)=='installed_module_identity_changed': print('expected_refusal')
    else: raise
else: raise AssertionError('foreign module collision accepted')
""")
    # The fixed child has a clean module table and must return the protected
    # semantic deny hash through the installed, read-only guardian CLI.
    result=subprocess.run((PYTHON,'-I','-B',str(GUARDIAN),'read-guard-policy'),
                          capture_output=True,timeout=12,check=False,env=ENV)
    assert result.returncode==0 and len(result.stdout)<=4096, (
        result.returncode,hashlib.sha256(result.stderr).hexdigest())
    assert json.loads(result.stdout)['policy_sha256']==expected
    # A wrong preloaded module still fails inside the isolated verifier.
    child("""import runpy,sys,types
sys.modules['aegis_auto_foreign_policy']=types.ModuleType('aegis_auto_foreign_policy')
guardian=runpy.run_path('/usr/local/lib/aegis/helpers/lib/aegis_auto_guardian.py')
try: guardian['read_guard_policy']()
except Exception as error:
    if str(error)=='installed_module_identity_changed': print('expected_refusal')
    else: raise
else: raise AssertionError('foreign module injection accepted')
""")
    # A copied source path is never an installed guardian identity.
    with tempfile.TemporaryDirectory() as directory:
        copy=Path(directory)/GUARDIAN.name
        copy.write_bytes(GUARDIAN.read_bytes())
        child("""import runpy
bad=runpy.run_path(%r)
try: bad['read_guard_policy']()
except Exception as error:
    if str(error)=='wrong_installed_source': print('expected_refusal')
    else: raise
else: raise AssertionError('wrong source accepted')
""" % str(copy))


if __name__=='__main__':
    test_installed_isolated_deny()
    print('installed_isolated_deny_pass')
