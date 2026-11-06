#!/usr/bin/env python3
"""Real pip, owned local wheels, no install; optional actual PowerShell admission."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time
import zipfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def private_json(path, value):
    with path.open('x', encoding='utf-8') as out:
        json.dump(value, out, indent=2)
        out.write('\n')
    path.chmod(0o600)


def run_owned(argv, log, env, records, label):
    """Bound only the actual direct leader; escaped descendants are unconfirmed."""
    started = time.monotonic()
    kwargs = {'start_new_session': True} if os.name == 'posix' else {
        'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP}
    timed_out = False
    reaped = False
    cleanup_error = None
    wait_error = None
    code = None
    with log.open('xb') as out:
        log.chmod(0o600)
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out,
                                 stderr=subprocess.STDOUT, env=env, **kwargs)
        try:
            code = child.wait(timeout=20)
            reaped = True
        except subprocess.TimeoutExpired:
            timed_out = True
        except BaseException as exc:
            wait_error = type(exc).__name__
        finally:
            if not reaped:
                cleanup_end = time.monotonic() + 4
                # The direct leader has not been reaped, retaining PID custody.
                try:
                    if os.name == 'posix':
                        os.killpg(child.pid, signal.SIGKILL)
                    else:
                        child.kill()
                except OSError as exc:
                    cleanup_error = type(exc).__name__
                remaining = cleanup_end - time.monotonic()
                if remaining <= 0:
                    cleanup_error = 'cleanup_deadline_elapsed'
                else:
                    try:
                        code = child.wait(timeout=remaining)
                        reaped = True
                    except (subprocess.TimeoutExpired, OSError) as exc:
                        cleanup_error = type(exc).__name__
    records.append({'case': label, 'pid': child.pid, 'returncode': code,
                    'timed_out': timed_out, 'direct_leader_reaped': reaped,
                    'wait_error_type': wait_error, 'cleanup_error_type': cleanup_error,
                    'elapsed_seconds': time.monotonic() - started,
                    'raw_sha256': digest(log)})
    if timed_out or not reaped or cleanup_error or wait_error:
        raise RuntimeError('owned acquisition fixture process invalid')
    return code, log.read_text(encoding='utf-8', errors='replace')


def make_wheel(path, content):
    metadata = 'Metadata-Version: 2.1\nName: aegis-hash-fixture\nVersion: 1.0\nRequires-Python: >=3.8\n'
    wheel = 'Wheel-Version: 1.0\nGenerator: aegis-owned-hash-contract\nRoot-Is-Purelib: false\nTag: py3-none-win_amd64\n'
    with zipfile.ZipFile(path, 'x', compression=zipfile.ZIP_STORED) as out:
        for name, value in [('aegis_hash_fixture/__init__.py', content),
                            ('aegis_hash_fixture-1.0.dist-info/METADATA', metadata),
                            ('aegis_hash_fixture-1.0.dist-info/WHEEL', wheel),
                            ('aegis_hash_fixture-1.0.dist-info/RECORD', '')]:
            info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            info.external_attr = 0o600 << 16
            out.writestr(info, value)
    path.chmod(0o600)


def source_contract(root):
    owner = root / 'tools/windows/prepare-build.ps1'
    text = owner.read_text(encoding='utf-8').replace('\r\n', '\n')
    requirements = root / 'tools/windows/build-tools-win_amd64.requirements.txt'
    inventory = root / 'tools/windows/build-tools-wheel-inventory.json'
    value = json.loads(inventory.read_text(encoding='utf-8'))
    assert value['schema'] == 'aegis_windows_build_tool_wheels_v1'
    assert value['platform'] == 'win_amd64' and value['minimum_python'] == '3.8'
    expected = [('cmake', '3.31.6'), ('ninja', '1.11.1.4'), ('libclang', '18.1.1')]
    rows = value['rows']
    assert [(row['package'], row['version']) for row in rows] == expected
    lines = [line for line in requirements.read_text().splitlines()
             if line.strip() and not line.startswith('#')]
    assert len(lines) == 3
    for line, row in zip(lines, rows):
        assert re.fullmatch(r'[0-9a-f]{64}', row['sha256'])
        assert row['url'].startswith('https://files.pythonhosted.org/packages/')
        assert row['url'].endswith('/' + row['filename'])
        assert row['filename'].endswith('-win_amd64.whl')
        assert line == row['package'] + ' @ ' + row['url'] + ' --hash=sha256:' + row['sha256']
    selector = '    $requirements = Get-PinnedWindowsBuildToolsRequirements $identity $PSScriptRoot\n'
    install = '        & $python -I -m pip --isolated --disable-pip-version-check --no-input install --upgrade --target $localTools --require-hashes --only-binary=:all: --no-deps --no-index --no-cache-dir --requirement $requirements\n'
    assert text.count(selector) == 1 and text.count(install) == 1
    assert 'if ($Bootstrap -and ' not in text and text.count('if ($Bootstrap) {') == 2
    assert text.index(selector) < text.index(install)
    assert "[Environment]::SetEnvironmentVariable('PIP_CONFIG_FILE', 'nul', 'Process')" in text
    assert "[Environment]::SetEnvironmentVariable('PIP_CONFIG_FILE', $previousPipConfig, 'Process')" in text
    assert '$Identity.minor -lt 8' in text and "$Identity.platform -cne 'win_amd64'" in text
    return text, {'owner': digest(owner), 'requirements': digest(requirements), 'inventory': digest(inventory)}


def powershell_admission(executable, owner, requirements, evidence, env, records):
    start = owner.index('function Get-PinnedWindowsBuildToolsRequirements(')
    end = owner.index('\n$ninja = Find-LocalNinja\n', start)
    function = owner[start:end]
    # Complete actual production function; only its independent input objects vary.
    code, raw = run_owned([executable, '-NoLogo', '-NoProfile', '-NonInteractive',
                           '-Command', '$PSVersionTable.PSVersion.ToString()'],
                          evidence / 'powershell-version.log', env, records, 'actual_powershell_version')
    assert code == 0 and re.match(r'^(?:5\.1\.|7\.)[0-9.]+$', raw.strip())
    cases = [('valid', 'cpython', 'win_amd64', 64, 3, 8, False),
             ('python37', 'cpython', 'win_amd64', 64, 3, 7, True),
             ('arm64', 'cpython', 'win_arm64', 64, 3, 13, True),
             ('bits32', 'cpython', 'win_amd64', 32, 3, 13, True),
             ('other_implementation', 'pypy', 'win_amd64', 64, 3, 10, True),
             ('missing_identity', None, None, None, None, None, True),
             ('missing_requirements', 'cpython', 'win_amd64', 64, 3, 13, True)]
    for label, impl, platform, bits, major, minor, refused in cases:
        data = {'implementation': impl, 'platform': platform, 'pointer_bits': bits,
                'major': major, 'minor': minor}
        directory = evidence / ('ps-' + label)
        directory.mkdir(mode=0o700)
        if label != 'missing_requirements':
            (directory / requirements.name).write_bytes(requirements.read_bytes())
            (directory / requirements.name).chmod(0o600)
        private_json(directory / 'identity.json', data)
        script = directory / 'admission.ps1'
        body = '''param([string]$InputDirectory)
$ErrorActionPreference = 'Stop'
'''+function+'''
$identity = Get-Content -LiteralPath (Join-Path $InputDirectory 'identity.json') -Raw | ConvertFrom-Json
try {
    $selected = Get-PinnedWindowsBuildToolsRequirements $identity $InputDirectory
    if ($selected -cne [IO.Path]::GetFullPath((Join-Path $InputDirectory 'build-tools-win_amd64.requirements.txt'))) { exit 92 }
    Write-Output 'admission=accepted'; exit 0
} catch { Write-Output 'admission=refused'; exit 86 }
'''
        script.write_text(body, encoding='utf-8'); script.chmod(0o600)
        code, raw = run_owned([executable, '-NoLogo', '-NoProfile', '-NonInteractive',
                               '-File', str(script), '-InputDirectory', str(directory)],
                              directory / 'raw.log', env, records, 'ps_' + label)
        assert code == (86 if refused else 0)
        assert raw.strip() == ('admission=refused' if refused else 'admission=accepted')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--evidence-dir', type=Path)
    parser.add_argument('--powershell', help='Actual Windows PowerShell5.1 or PowerShell7 executable; never mocked')
    args = parser.parse_args()
    if sys.version_info < (3, 8):
        raise RuntimeError('actual fixture Python3.8+ required')
    evidence = args.evidence_dir or Path(tempfile.mkdtemp(prefix='aegis-build-tools-hashes-'))
    if args.evidence_dir:
        evidence.mkdir(mode=0o700)
    evidence.chmod(0o700)
    env = os.environ.copy(); env['PIP_CONFIG_FILE'] = os.devnull
    records = []
    accepted = False
    error_type = None
    pins = {}
    try:
        owner, pins = source_contract(args.repo)
        code, raw = run_owned([sys.executable, '-I', '-m', 'pip', '--isolated',
                               '--disable-pip-version-check', '--version'],
                              evidence / 'pip-version.log', env, records, 'actual_pip_version')
        assert code == 0 and re.search(r'\bpip [0-9]+\.[0-9]+', raw)
        good = evidence / 'good'; bad = evidence / 'altered'
        good.mkdir(mode=0o700); bad.mkdir(mode=0o700)
        filename = 'aegis_hash_fixture-1.0-py3-none-win_amd64.whl'
        make_wheel(good / filename, '# owned original data\n')
        make_wheel(bad / filename, '# owned altered data\n')
        expected = digest(good / filename)
        assert expected != digest(bad / filename)
        cases = [('matching_hash', good / filename, expected, True, 0),
                 ('unprotected_counterfactual_accepts_altered', bad / filename, None, False, 0),
                 ('altered_hash_refused', bad / filename, expected, True, 1),
                 ('missing_wheel_refused', evidence / 'missing' / filename, expected, True, 1),
                 ('missing_hash_refused', good / filename, None, True, 1)]
        for label, wheel, declared_hash, protected, expected_code in cases:
            destination = evidence / ('output-' + label); destination.mkdir(mode=0o700)
            lock = evidence / (label + '.txt')
            line = 'aegis-hash-fixture @ ' + wheel.as_uri()
            if declared_hash:
                line += ' --hash=sha256:' + declared_hash
            lock.write_text(line + '\n', encoding='utf-8'); lock.chmod(0o600)
            argv = [sys.executable, '-I', '-m', 'pip', '--isolated', '--disable-pip-version-check',
                    '--no-input', 'download', '--no-deps', '--no-index', '--no-cache-dir',
                    '--only-binary=:all:', '--platform', 'win_amd64', '--implementation', 'cp',
                    '--abi', 'none', '--dest', str(destination), '--requirement', str(lock)]
            if protected:
                argv.append('--require-hashes')
            if label == 'missing_wheel_refused':
                assert not wheel.exists()
            code, raw = run_owned(argv, evidence / (label + '.log'), env, records, label)
            if label == 'missing_wheel_refused':
                # pip versions classify this same missing local file as an
                # installation error (1) or uncaught file error (2).
                assert code in (1, 2) and '[Errno 2]' in raw and wheel.name in raw
                assert str(wheel) in raw or repr(str(wheel))[1:-1] in raw
                assert not wheel.exists()
            else:
                assert code == expected_code
            if expected_code == 0:
                assert sorted(p.name for p in destination.iterdir()) == [filename]
                assert digest(destination / filename) == digest(wheel)
            else:
                assert not list(destination.iterdir())
            if label == 'altered_hash_refused':
                assert 'DO NOT MATCH THE HASHES' in raw and expected in raw and digest(wheel) in raw
            if label == 'missing_hash_refused':
                assert 'Hashes are required in --require-hashes mode' in raw
        if args.powershell:
            powershell_admission(args.powershell, owner,
                                 args.repo / 'tools/windows/build-tools-win_amd64.requirements.txt',
                                 evidence, env, records)
        assert pins == source_contract(args.repo)[1]
        accepted = True
    except Exception as exc:
        error_type = type(exc).__name__
    finally:
        private_json(evidence / 'receipt-r1.json', {
            'schema': 'aegis_windows_build_tools_hash_contract_v1', 'accepted': accepted,
            'source_pins': pins, 'records': records, 'error_type': error_type,
            'planned_pip_acquisition_cases': 5,
            'completed_pip_acquisition_cases': sum(record['case'] in {
                'matching_hash', 'unprotected_counterfactual_accepts_altered',
                'altered_hash_refused', 'missing_wheel_refused', 'missing_hash_refused'}
                for record in records), 'pip_install_executed': False,
            'official_wheel_assets_downloaded': False,
            'powershell_admission_requested': bool(args.powershell),
            'completed_powershell_admission_cases': sum(record['case'].startswith('ps_') for record in records),
            'native_windows_bootstrap_acceptance': False,
            'custody_limit': 'direct leaders bounded and reaped; POSIX group kill attempted on failure; escaped descendants not proven and not claimed owned by root PG'})
    print('Windows build-tool hash contract: ' + ('PASS' if accepted else 'FAIL_OR_INVALID'))
    return 0 if accepted else 1


if __name__ == '__main__':
    raise SystemExit(main())
