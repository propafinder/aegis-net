#!/usr/bin/env python3
"""Linux root filesystem/flock controls of the actual installer boot producers.

PID1 is inert in these controls. The supplied ELF is used only for its existing
version/protocol interface; this does not accept an installed lifecycle.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile


GATE = b'[Unit]\nConditionPathExists=!/\n'
MARKER = b'{"schema":"aegis_installer_auto_v2_enabled_v1"}\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', required=True, type=Path)
    parser.add_argument('--client-binary', required=True, type=Path)
    args = parser.parse_args()
    assert sys.platform == 'linux' and os.geteuid() == 0
    source = (args.source_root / 'install.sh').read_text()
    tags = ('PY_AUTO_RETAIN_PAYLOAD', 'PY_AUTO_BOOT_GATE', 'PY_AUTO_CANDIDATE')
    bodies = {}
    launch = {}
    for tag in tags:
        lines = [line for line in source.splitlines() if "<<'" + tag + "'" in line]
        assert len(lines) == 1
        bodies[tag] = source.split(lines[0] + '\n', 1)[1].split('\n' + tag + '\n', 1)[0]
        if tag == 'PY_AUTO_CANDIDATE':
            # The literal stays outside command substitution for Bash 3.2.
            # Bind the extracted body to its actual isolated interpreter and
            # unchanged candidate/root/InstallLock arguments.
            assert lines[0] == "  IFS= read -r -d '' candidate_program <<'PY_AUTO_CANDIDATE' || true"
            calls = re.findall(
                r'^  candidate="\$\(printf \'%s\' "\$candidate_program" \| '
                r'python3 (-I(?: -B)? -) "\$candidate" "\$ROOT" '
                r'"\$STAGE_AUTO_INSTALL_LOCK_FD"\)" \|\| return 1$', source, re.M)
            assert len(calls) == 1, 'exact candidate literal/interpreter handoff required'
            launch[tag] = calls[0].split()
            continue
        match = re.search(r'\bpython3 (-I(?: -B)? -) ', lines[0])
        assert match, (tag, lines[0])
        launch[tag] = match.group(1).split()
    assert launch['PY_AUTO_BOOT_GATE'] == ['-I', '-B', '-']
    assert launch['PY_AUTO_CANDIDATE'] == ['-I', '-B', '-']
    gate_file = Path('/etc/systemd/system/aegis-client.service.d/00-v2-boot-gate.conf')
    control = Path('/var/lib/aegis-auto/control')
    marker = control / 'v2-enabled'
    lock_path = Path('/run/aegis-auto-install.lock')
    assert not any(os.path.lexists(p) for p in (gate_file, control, lock_path))
    checks = []
    with tempfile.TemporaryDirectory(prefix='aegis-v2-boot-interlock-') as temporary:
        work = Path(temporary)
        fixture_client = work / 'aegis-client'
        shutil.copyfile(args.client_binary, fixture_client)
        fixture_client.chmod(0o755)
        systemctl = work / 'systemctl'
        calls = work / 'systemctl-calls'
        systemctl.write_text('''#!/usr/bin/python3
import os,pathlib,sys
args=sys.argv[1:]
with open(os.environ['AEGIS_BOOT_GATE_CALLS'],'a') as log: log.write(' '.join(args)+'\\n')
if args[0]=='show':
 print('Id=aegis-client.service\\nLoadState=loaded\\nActiveState=inactive\\nSubState=dead\\nMainPID=0\\nControlPID=0\\nControlGroup=\\nNFileDescriptorStore=0\\nNeedDaemonReload=no')
 print('DropInPaths='+('/etc/systemd/system/aegis-client.service.d/00-v2-boot-gate.conf' if pathlib.Path('/etc/systemd/system/aegis-client.service.d/00-v2-boot-gate.conf').exists() else ''))
elif args[0] not in ('list-jobs','daemon-reload'): raise SystemExit(9)
''')
        systemctl.chmod(0o755)
        gate_script = work / 'gate.py'
        gate_script.write_text(bodies['PY_AUTO_BOOT_GATE'].replace(
            "['/usr/bin/systemctl',*args]",
            '[' + repr(sys.executable) + ',' + repr(str(systemctl)) + ',*args]'))
        candidate_script = work / 'candidate.py'
        candidate_script.write_text(bodies['PY_AUTO_CANDIDATE'])
        def retain():
            result = subprocess.run([sys.executable, *launch['PY_AUTO_RETAIN_PAYLOAD'][:-1], '-c',
                                     bodies['PY_AUTO_RETAIN_PAYLOAD'], str(args.source_root), '1',
                                     str(fixture_client)], capture_output=True, text=True, timeout=60)
            assert result.returncode == 0, result.stderr
            return Path(result.stdout.strip())
        payload = retain()
        coordinator = payload / 'scripts/lib/aegis_installer_auto_v2.py'
        candidate = payload / 'bin/aegis-client'
        original_sha = hashlib.sha256(candidate.read_bytes()).hexdigest()
        lock = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.fchmod(lock, 0o600)
            env = dict(os.environ, AEGIS_BOOT_GATE_CALLS=str(calls))
            env.pop('PYTHONDONTWRITEBYTECODE', None)

            def invoke(script, tag, *words, success=True, reason=None):
                result = subprocess.run([sys.executable, *launch[tag][:-1], str(script), *map(str, words)],
                                        pass_fds=(lock,), env=env, capture_output=True, timeout=30)
                assert (result.returncode == 0) == success, result.stderr.decode(errors='replace')
                if reason is not None:
                    assert reason in result.stderr
                return result

            # Both real producers refuse an inherited descriptor without flock.
            invoke(gate_script, 'PY_AUTO_BOOT_GATE', lock, payload, success=False)
            invoke(candidate_script, 'PY_AUTO_CANDIDATE', candidate, payload, lock, success=False)
            assert not gate_file.exists() and not control.exists()
            checks.append('unheld_original_lock_refused_before_publication')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            invoke(gate_script, 'PY_AUTO_BOOT_GATE', lock, payload)
            assert retain() == payload
            assert not (coordinator.parent / '__pycache__').exists()
            assert gate_file.read_bytes() == GATE and stat.S_IMODE(gate_file.stat().st_mode) == 0o644
            assert 'daemon-reload\n' in calls.read_text()
            assert not marker.exists()
            checks.append('exact_gate_readback_and_reload_precede_marker')
            # The old marker-based condition was true here. The new condition
            # is already false, so a start after reload cannot slip through
            # before marker publication. PID1 remains inert in this harness;
            # the real systemd condition parser is checked separately.
            assert Path('/').exists() and gate_file.read_bytes() == GATE
            assert b'v2-enabled' not in GATE
            checks.append('fixed_start_fenced_independently_of_marker_presence')
            gate_before = gate_file.stat()
            invoke(gate_script, 'PY_AUTO_BOOT_GATE', lock, payload)
            assert gate_file.stat().st_ino == gate_before.st_ino
            assert not list(gate_file.parent.glob('.passive-tmp-*'))
            checks.append('gate_idempotence_preserves_inode')
            gate_file.write_bytes(b'[Unit]\nConditionPathExists=/foreign\n')
            invoke(gate_script, 'PY_AUTO_BOOT_GATE', lock, payload, success=False)
            assert gate_file.read_bytes().endswith(b'/foreign\n') and not marker.exists()
            checks.append('foreign_gate_not_overwritten')
            gate_file.write_bytes(GATE)
            invoke(candidate_script, 'PY_AUTO_CANDIDATE', candidate, payload, lock)
            assert retain() == payload
            assert not (coordinator.parent / '__pycache__').exists()
            assert marker.read_bytes() == MARKER and stat.S_IMODE(marker.stat().st_mode) == 0o600
            checks.append('durable_exact_marker_with_real_elf_protocol')
            inode = marker.stat().st_ino
            invoke(candidate_script, 'PY_AUTO_CANDIDATE', candidate, payload, lock)
            assert marker.stat().st_ino == inode
            assert not list(control.glob('.passive-tmp-*'))
            checks.append('marker_idempotence_preserves_inode')
            for defect in ('mode', 'bytes', 'empty', 'symlink', 'hardlink'):
                marker.unlink()
                victim = work / ('victim-' + defect)
                if defect == 'symlink':
                    victim.write_bytes(MARKER)
                    marker.symlink_to(victim)
                elif defect == 'hardlink':
                    marker.write_bytes(MARKER)
                    marker.chmod(0o600)
                    os.link(marker, control / 'marker-second-link')
                else:
                    marker.write_bytes(b'' if defect == 'empty' else b'foreign' if defect == 'bytes' else MARKER)
                    marker.chmod(0o644 if defect == 'mode' else 0o600)
                invoke(candidate_script, 'PY_AUTO_CANDIDATE', candidate, payload, lock, success=False)
                if defect == 'symlink':
                    assert victim.read_bytes() == MARKER
                if defect == 'hardlink':
                    (control / 'marker-second-link').unlink()
                checks.append('foreign_marker_' + defect + '_refused')
            marker.unlink()
            marker.write_bytes(MARKER)
            marker.chmod(0o600)
            assert hashlib.sha256(candidate.read_bytes()).hexdigest() == original_sha
        finally:
            os.close(lock)
    return {'status': 'pass_linux_root_filesystem_flock_inert_pid1', 'checks': checks,
            'check_count': len(checks), 'install_sha256': hashlib.sha256(source.encode()).hexdigest(),
            'client_sha256': original_sha, 'native_or_installed_acceptance': False}


if __name__ == '__main__':
    print(json.dumps(main(), sort_keys=True))
