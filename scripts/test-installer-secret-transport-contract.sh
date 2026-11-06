#!/usr/bin/env bash
# Actual Rust/private-input and mechanically extracted installer-owner fixtures.
# No Cargo, services, public network, Keychain, or installed host paths are used.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "${ROOT}" <<'PY'
import hashlib, json, os, re, shutil, signal, stat, subprocess, sys, tarfile, tempfile, time
from pathlib import Path

root = Path(sys.argv[1])
source = Path(os.environ.get('AEGIS_TEST_SECRET_SOURCE', root)).resolve()
role = os.environ.get('AEGIS_TEST_SECRET_ROLE', 'candidate')
assert role in ('baseline', 'candidate'), 'unknown fixture role'
client = Path(os.environ.get('AEGIS_TEST_SECRET_CLIENT', root / 'target/debug/aegis-client')).resolve()
server = Path(os.environ.get('AEGIS_TEST_SECRET_READER', root / 'target/debug/aegis-server')).resolve()
assert client.is_file() and os.access(client, os.X_OK), 'actual compiled client required'
assert server.is_file() and os.access(server, os.X_OK), 'actual compiled server required'
assert hasattr(os, 'waitid') and hasattr(os, 'WNOWAIT'), 'owned wait observation unavailable'
work = Path(tempfile.mkdtemp(prefix='aegis-installer-private-contract-')).resolve()
work.chmod(0o700)
original_client, original_server = client, server
compiled = work / 'compiled-inputs'; compiled.mkdir(); compiled.chmod(0o700)
for binary, name in [(client, 'aegis-client'), (server, 'aegis-server')]:
    before = hashlib.sha256(binary.read_bytes()).hexdigest()
    shutil.copyfile(binary, compiled / name); (compiled / name).chmod(0o700)
    assert hashlib.sha256((compiled / name).read_bytes()).hexdigest() == before == hashlib.sha256(binary.read_bytes()).hexdigest(), 'INVALID binary copy race'
client, server = compiled / 'aegis-client', compiled / 'aegis-server'
rows = []
base_env = {key: os.environ[key] for key in ('PATH', 'LANG', 'LC_ALL') if key in os.environ}
base_env['HOME'] = str(work / 'owned-home'); Path(base_env['HOME']).mkdir()
base_env['TMPDIR'] = str(work)
url = 'https://fixture.invalid/bundle?token=AUDIT78_SYNTHETIC_URL_SENTINEL'
token = '0123456789abcdef' * 4  # Synthetic accepted-format fixture, not production entropy.
password = 'AUDIT78_SYNTHETIC_SOCKS_SENTINEL'
real_python = Path(sys.executable).resolve()
real_bash = Path(shutil.which('bash')).resolve()

def private(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(data.encode() if isinstance(data, str) else data)
    path.chmod(0o600)

def executable(path, text):
    private(path, text)
    path.chmod(0o755)

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def run(name, argv, env=None, stdin=None, bound=30):
    # One real-wall observation bound and one independent four-second cleanup.
    # WNOWAIT retains the group leader until the LAST signal; no post-reap signal.
    case = work / name
    case.mkdir()
    out, err = case / 'stdout.log', case / 'stderr.log'
    with out.open('xb') as stdout, err.open('xb') as stderr:
        os.chmod(out, 0o600); os.chmod(err, 0o600)
        child = subprocess.Popen(argv, env=base_env if env is None else env, stdin=stdin or subprocess.DEVNULL,
                                 stdout=stdout, stderr=stderr, start_new_session=True)
        pid, deadline = child.pid, time.monotonic() + bound
        observed = False; problem = None; signals = []
        try:
            while time.monotonic() < deadline:
                if os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT):
                    observed = True; break
                time.sleep(0.005)
            if not observed:
                problem = 'command_deadline'
        except BaseException as failure:
            problem = type(failure).__name__
        finally:
            cleanup = time.monotonic() + 4
            # Stop the fresh owned group before reaping its reserved leader.
            for value in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(pid, value); signals.append(int(value))
                except ProcessLookupError:
                    pass
                except PermissionError:
                    # Darwin may refuse a confirmed exited singleton zombie.
                    # No process-group quiescence is inferred from this error.
                    if not observed:
                        problem = problem or 'group_signal_unconfirmed'
            status = None
            while time.monotonic() < cleanup:
                status = child.poll()
                if status is not None:
                    break
                time.sleep(0.005)
            record = dict(case=name, rc=status, observed_before_cleanup=observed,
                          owned_leader_reaped=status is not None, signal_attempts=signals,
                          problem=problem, stdout_sha256=digest(out), stderr_sha256=digest(err))
            private(case / 'execution.json', json.dumps(record, indent=2) + '\n')
    assert status is not None and problem is None, 'INVALID owned command observation/cleanup'
    return status, out.read_bytes(), err.read_bytes()

def shell_quote(value):
    return "'" + str(value).replace("'", "'\\''") + "'"

def actual_function(text, name, next_name):
    begin = text.index(name + '() {')
    end = text.index('\n' + next_name + '() {', begin)
    return text[begin:end]

def fixture(name, function):
    try:
        function()
        rows.append(dict(case=name, result='PASS'))
    except AssertionError as failure:
        rows.append(dict(case=name, result='INVALID' if str(failure).startswith('INVALID') else 'FAIL', assertion=str(failure)))
    except BaseException as failure:
        rows.append(dict(case=name, result='INVALID', kind=type(failure).__name__))

install = (source / 'install.sh').read_text()
builder = (source / 'scripts/build-macos-client-tarball.sh').read_text()
provenance = {str(p.relative_to(source)): digest(p) for p in
              (source / 'install.sh', source / 'scripts/render-client-bundle.sh',
               source / 'scripts/build-macos-client-tarball.sh')}
private(work / 'source-and-artifact-pins.json', json.dumps(dict(role=role,
        source_pins=provenance, client_original=str(original_client), server_original=str(original_server), client_snapshot=str(client), server_snapshot=str(server), client_sha256=digest(client), server_sha256=digest(server)), indent=2) + '\n')

def tools(case):
    directory = case / 'tools'; directory.mkdir()
    # The tools record actual argv/env and then perform inert local operations.
    # Downloader response is a fixed owned archive; no DNS or network is used.
    logger = '''import json, os, sys
from pathlib import Path
with open(os.environ['AEGIS_TEST_ARGV'], 'a') as stream:
    stream.write(json.dumps({'tool': Path(sys.argv[0]).name, 'argv': sys.argv[1:],
                            'environment': {key: os.environ[key] for key in ('AUTH_TOKEN', 'BUNDLE_URL', 'SOCKS_TOKEN') if key in os.environ}}) + '\\n')
'''
    executable(directory / 'python3', '#!' + str(real_python) + '\n' + logger +
               'os.execv(' + repr(str(real_python)) + ', [' + repr(str(real_python)) + '] + sys.argv[1:])\n')
    executable(directory / 'bash', '#!' + str(real_python) + '\n' + logger +
               'os.execv(' + repr(str(real_bash)) + ', [' + repr(str(real_bash)) + '] + sys.argv[1:])\n')
    executable(directory / 'curl', '#!' + str(real_python) + '\n' + logger + '''
import shutil, time, signal
args = sys.argv[1:]
if '--config' in args:
    # Regular-file stdin proves the encoded config is not a parent pipe write.
    import stat
    assert stat.S_ISREG(os.fstat(0).st_mode)
    data = sys.stdin.buffer.read()
    Path(os.environ['AEGIS_TEST_INPUT_WITNESS']).write_bytes(data)
if os.environ.get('AEGIS_TEST_DOWNLOADER_WAIT') == '1':
    Path(os.environ['AEGIS_TEST_STARTED']).write_text('actual downloader entered')
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    time.sleep(20)
target = args[args.index('-o') + 1]
shutil.copyfile(os.environ['AEGIS_TEST_PAYLOAD'], target)
raise SystemExit(int(os.environ.get('AEGIS_TEST_DOWNLOADER_RC', '0')))
''')
    log = case / 'argv.jsonl'; private(log, b'')
    env = dict(base_env, PATH=str(directory) + os.pathsep + os.environ['PATH'],
               AEGIS_TEST_ARGV=str(log), AEGIS_TEST_INPUT_WITNESS=str(case / 'input-witness'))
    return env, log

def download_argv():
    case = work / 'download-data'; case.mkdir()
    access = case / 'access'; private(access, url)
    payload = case / 'payload'; private(payload, b'actual-fixture-response')
    env, log = tools(case); env['AEGIS_TEST_PAYLOAD'] = str(payload)
    body = actual_function(install, 'download_url', 'resolve_downloaded_bundle')
    leaf = case / 'actual-download.sh'
    # The baseline-only admission adapter supplies the original URL argument to
    # the exact old function; it changes neither that body nor its child argv.
    argument = shell_quote(access) if role == 'candidate' else '"$(cat ' + shell_quote(access) + ')"'
    private(leaf, 'set -euo pipefail\nBUNDLE_CACERT_PIN=""; BUNDLE_INSECURE=0; BUNDLE_LOCAL_ONLY=0\n'
            + 'PREFLIGHT_CLIENT_BINARY=' + shell_quote(client) + '\n'
            + body + '\ndownload_url ' + argument + ' ' + shell_quote(case / 'result') + '\n')
    rc, stdout, stderr = run('download-command', [str(real_bash), str(leaf)], env)
    assert rc == 0 and (case / 'result').read_bytes() == payload.read_bytes(), 'INVALID actual transfer positive'
    assert url.encode() not in log.read_bytes(), 'private URL crossed actual child argv/environment'
    assert url.encode() not in stdout + stderr, 'private URL crossed download diagnostics'

def renderer_argv():
    case = work / 'renderer-data'; case.mkdir()
    access = case / 'auth'; private(access, token)
    ca = case / 'ca.pem'; private(ca, 'fixture-only CA\n')
    env, log = tools(case)
    output = case / 'bundle'
    script = source / 'scripts/render-client-bundle.sh'
    if role == 'baseline':
        # This QA adapter reads an owned synthetic fixture and invokes the real
        # original inline interface. It is not a replacement production reader.
        command = 'bash ' + shell_quote(script) + ' ' + shell_quote(output) + ' 192.0.2.9:443 fixture.example "$(cat ' + shell_quote(access) + ')" ' + shell_quote(ca)
    else:
        command = 'cat ' + shell_quote(access) + ' | bash ' + shell_quote(script) + ' ' + shell_quote(output) + ' 192.0.2.9:443 fixture.example --auth-token-stdin ' + shell_quote(ca) + ' ' + shell_quote(server)
    leaf = case / 'invoke.sh'; private(leaf, 'set -euo pipefail\n' + command + '\n')
    rc, stdout, stderr = run('renderer-command', [str(real_bash), str(leaf)], env)
    assert rc == 0, 'INVALID actual renderer positive'
    content = (output / 'aegis-client.toml').read_text()
    assert 'auth_token = \"' + token + '\"' in content and 'server = \"192.0.2.9:443\"' in content, 'INVALID rendered consumer value'
    assert stat.S_IMODE((output / 'aegis-client.toml').stat().st_mode) == 0o600, 'INVALID rendered custody'
    assert token.encode() not in log.read_bytes(), 'relay token crossed actual renderer argv/environment'
    assert token.encode() not in stdout + stderr, 'relay token crossed renderer stdout/stderr'

def summary_stdout():
    case = work / 'summary-data'; case.mkdir()
    config = case / 'aegis.toml'
    private(config, '[socks]\nlisten="127.0.0.1:1080"\nauth_user="fixture"\nauth_token="' + password + '"\n[relay]\nauth_token="' + token + '"\n')
    if role == 'baseline':
        begin = install.index('  # v0.3.0: extract SOCKS5 auth_token + listen')
    else:
        begin = install.rindex('  cat <<EOF\n\nAEGIS client installed')
    end = install.index('  print_product_summary "${bin_path}" "${config_path}"', begin)
    body = install[begin:end]
    variables = dict(bin_path=case / 'client', config_path=config, state_dir=case / 'state',
        install_manifest_path=case / 'manifest', runtime_events_path=case / 'events',
        helper_dir=case / 'helpers', privileged_dns_example_path=case / 'dns')
    prefix = 'set -euo pipefail\n' + '\n'.join(k + '=' + shell_quote(v) for k, v in variables.items())
    prefix += '\nprivileged_dns_profile_installed=0\nBUNDLE_URL=' + shell_quote(url) + '\n'
    leaf = case / 'summary.sh'; private(leaf, prefix + 'actual_summary() {\n' + body + '}\nactual_summary\n')
    rc, stdout, stderr = run('summary-command', [str(real_bash), str(leaf)])
    assert rc == 0 and b'AEGIS client installed' in stdout and str(config).encode() in stdout, 'INVALID actual summary positive'
    assert all(value.encode() not in stdout + stderr for value in (url, password, token)), 'actual post-install summary revealed private input'

def issuer_stdout():
    case = work / 'issuer-data'; case.mkdir()
    payload = case / 'bundle.tar.gz'; private(payload, b'fixture bundle bytes')
    config = case / 'server.toml'
    private(config, 'listen="127.0.0.1:8443"\ncert="unused"\nkey="unused"\nauth_token="' + token + '"\n[bundle_endpoint]\nenabled=true\ntoken_store_path="' + str(case / 'tokens.json') + '"\n')
    output = case / 'access-url.txt'
    args = [str(server), '--config', str(config), 'bundle-token', 'issue', '--bundle-path', str(payload), '--public-host', 'fixture.invalid', '--public-port', '8443']
    if role == 'candidate':
        args += ['--url-output', str(output)]
    rc, stdout, stderr = run('issuer-command', args)
    assert rc == 0 and (case / 'tokens.json').is_file(), 'INVALID actual token issuance positive'
    if role == 'baseline':
        match = re.search(rb'https://fixture\.invalid:8443/[^\s]+\?token=[^\s]+', stdout)
        assert match, 'INVALID original issued URL witness'
        private(output, match[0])  # QA-only adapter preserves original stdout.
    access = output.read_bytes()
    assert access.startswith(b'https://fixture.invalid:8443/') and b'?token=' in access, 'INVALID private issued consumer URL'
    assert stat.S_IMODE(output.stat().st_mode) == 0o600, 'INVALID issued custody'
    assert access not in stdout + stderr, 'actual issuer revealed plaintext URL on stdout/stderr'

def mac(case_name, fault):
    case = work / ('mac-data-' + case_name); case.mkdir()
    package = case / 'package'; (package / 'bin').mkdir(parents=True)
    template = re.search(r'^cat > "\$\{BUNDLE_DIR\}/install-macos-client.sh" <<\'EOF\'\n(.*?)^EOF$', builder, re.M | re.S)
    assert template, 'INVALID actual macOS template extraction'
    # Instantiate the builder's exact public-text hash bindings. Only the fixed
    # system daemon path is relocated; input, fetch, archive, purge, config and
    # original service-mode logic remain actual template code.
    installer = package / 'install-macos-client.sh'
    installer_text = template[1].replace('/Library/LaunchDaemons/dev.aegis.client.plist', str(case / 'owned-daemon.plist'))
    for leaf, placeholder in (
        ('LICENSE-MIT', '__AEGIS_PROJECT_LICENSE_MIT_SHA256__'),
        ('LICENSE-APACHE', '__AEGIS_PROJECT_LICENSE_APACHE_SHA256__'),
        ('NOTICE', '__AEGIS_PROJECT_NOTICE_SHA256__'),
    ):
        source_text = source / leaf
        target_text = package / leaf
        shutil.copyfile(source_text, target_text)
        target_text.chmod(0o644)
        installer_text = installer_text.replace(placeholder, digest(target_text))
    assert '__AEGIS_PROJECT_' not in installer_text, 'INVALID unbound builder public-text hash'
    private(installer, installer_text)
    shutil.copyfile(client, package / 'bin/aegis-client'); (package / 'bin/aegis-client').chmod(0o755)
    private(package / 'macos-client-bundle.manifest.json', json.dumps(dict(version='fixture', git_sha='fixture', build_timestamp='fixture', platform='macos', arch='aarch64', target_triple='aarch64-apple-darwin')))
    home = case / 'home'; home.mkdir(); home.chmod(0o700)
    old = {home / '.config/aegis/aegis.toml': b'old-private-config', home / '.local/bin/aegis-client': b'old-private-binary', home / '.local/state/aegis/retained': b'old-private-state'}
    for path, data in old.items(): private(path, data)
    bundle = case / 'client-bundle'; bundle.mkdir()
    private(bundle / 'aegis-client.toml', 'mode="relay"\n[socks]\nlisten="127.0.0.1:1080"\n[relay]\nserver="192.0.2.9:443"\nserver_name="fixture.example"\nca_cert="__CLIENT_CA_CERT_PATH__"\nauth_token="' + token + '"\n')
    private(bundle / 'ca.pem', 'fixture-only CA\n')
    archive = case / 'archive.tar.gz'
    with tarfile.open(archive, 'w:gz') as tar: tar.add(bundle, arcname='client-bundle')
    archive.chmod(0o600)
    if fault == 'archive': archive.write_bytes(b'not a gzip archive')
    access = case / 'access.txt'; private(access, 'file://' + str(archive if fault != 'fetch' else case / 'absent.tar.gz'))
    if fault == 'private': access.chmod(0o644)
    mocks = case / 'tools'; mocks.mkdir()
    executable(mocks / 'launchctl', '#!/bin/sh\nexit 93\n')
    executable(mocks / 'networksetup', '#!/bin/sh\nexit 94\n')
    env = dict(base_env, HOME=str(home), TMPDIR=str(case), AEGIS_INSTALL_TMPDIR_CANDIDATES=str(case), PATH=str(mocks) + os.pathsep + os.environ['PATH'])
    args = [str(real_bash), str(installer), '--service-mode', 'foreground', '--no-browser-proxy', '--user-home', str(home)]
    args += ['--bundle-url-file', str(access)] if role == 'candidate' else ['--bundle-url', access.read_text()]
    if fault != 'existing': args += ['--reinstall']
    rc, stdout, stderr = run('mac-command-' + case_name, args, env)
    assert b'project text' not in stderr, 'INVALID public-text fixture masked private-input case'
    if fault == 'private':
        assert b'reason=private_input_rejected' in stderr, 'INVALID private-input refusal was masked'
    elif fault == 'fetch':
        assert b'stage=transfer reason=failed' in stderr, 'INVALID fetch refusal was masked'
    elif fault == 'archive':
        assert b'tar:' in stderr, 'INVALID archive refusal was masked'
    elif fault == 'existing':
        assert b'existing install detected' in stderr, 'INVALID existing-install refusal was masked'
    if fault == 'valid':
        assert rc == 0, 'INVALID actual valid macOS admission/install positive'
        content = (home / '.config/aegis/aegis.toml').read_text()
        assert token in content and '192.0.2.9:443' in content, 'INVALID unchanged macOS relay consumer'
        assert stat.S_IMODE((home / '.config/aegis/aegis.toml').stat().st_mode) == 0o600, 'INVALID macOS installed custody'
    else:
        assert rc != 0, 'invalid acquisition did not refuse before reinstall'
        assert all(path.is_file() and path.read_bytes() == data and stat.S_IMODE(path.stat().st_mode) == 0o600 for path, data in old.items()), 'actual macOS purge preceded private-input/fetch/archive admission'
    assert token.encode() not in stdout + stderr, 'macOS output revealed relay credential'
    assert not list(case.glob('aegis-bundle.*')), 'actual owned archive staging was retained on ordinary completion'


def actual_controls():
    case = work / 'controls-data'; case.mkdir()
    access = case / 'access'; private(access, url)
    def fetch(name, path=access, extra=(), environment=None):
        output = case / (name + '-output')
        args = [str(client), 'profile', 'installer-secret', 'fetch', '--input', str(path),
                '--output', str(output), '--connect-seconds', '1', '--total-seconds', '1'] + list(extra)
        rc, stdout, stderr = run('control-' + name, args, environment)
        assert url.encode() not in stdout + stderr, 'actual Rust refusal reflected URL'
        return rc, output
    for name, data in [('url-control', b'https://fixture.invalid/\n\n'),
                       ('url-oversized', b'x' * 8193), ('url-invalid-utf8', b'\xff')]:
        path = case / name; private(path, data)
        rc, output = fetch(name, path)
        assert rc != 0 and not output.exists(), 'actual invalid URL input admitted'
    public = case / 'public'; private(public, url); public.chmod(0o644)
    linked = case / 'linked'; linked.symlink_to(access)
    hard = case / 'hard'; os.link(access, hard)
    for name, path in [('public', public), ('symlink', linked), ('hardlink', hard)]:
        before = access.read_bytes()
        rc, output = fetch(name, path)
        assert rc != 0 and not output.exists() and access.read_bytes() == before, 'actual private descriptor custody refusal changed sentinel'
    hard.unlink()
    rc, output = fetch('offline-http', extra=['--local-only'])
    assert rc != 0 and not output.exists(), 'actual Rust offline HTTP admission created output'
    # Run the actual installer acquisition owner as well, before any active
    # installation mutation. Only its fresh staging directory is admitted.
    actual = actual_function(install, 'download_url', 'resolve_downloaded_bundle')
    actual += '\n' + actual_function(install, 'resolve_downloaded_bundle', 'install_binary')
    actual += '\n' + actual_function(install, 'ensure_dir', 'install_atomic_write')
    leaf = case / 'offline-installer.sh'
    private(leaf, 'set -euo pipefail\nTEMP_PATHS=(); BUNDLE_LOCAL_ONLY=1; BUNDLE_CACERT_PIN=""; BUNDLE_INSECURE=0\n'
            + 'PREFLIGHT_CLIENT_BINARY=' + shell_quote(client) + '\nTMPDIR=' + shell_quote(case) + '\n'
            + actual + '\nresolved=""\nresolve_downloaded_bundle ' + shell_quote(access) + ' resolved\n')
    sentinel = case / 'active-install-sentinel'; private(sentinel, b'preserve existing installation')
    rc, stdout, stderr = run('control-offline-installer', [str(real_bash), str(leaf)])
    assert rc != 0 and sentinel.read_bytes() == b'preserve existing installation', 'actual installer offline HTTP admission did not fail before active mutation'
    assert b'stage=bundle_acquisition reason=transfer_failed' in stderr, 'INVALID actual installer refusal phase'
    assert url.encode() not in stdout + stderr, 'actual installer offline refusal reflected URL'
    # SIGCHLD ignore survives exec. This fresh process proves disposition
    # admission refuses before any transfer/output, without changing handlers.
    shim = 'import os,signal,sys;signal.signal(signal.SIGCHLD,signal.SIG_IGN);os.execv(sys.argv[1],sys.argv[1:])'
    output = case / 'ignored-sigchld-output'
    rc, stdout, stderr = run('control-ignored-sigchld', [str(real_python), '-c', shim, str(client),
        'profile', 'installer-secret', 'fetch', '--input', str(access), '--output', str(output),
        '--connect-seconds', '1', '--total-seconds', '1'])
    assert rc != 0 and not output.exists(), 'actual ignored SIGCHLD ownership was admitted'
    assert url.encode() not in stdout + stderr, 'actual signal-owner refusal reflected URL'
    # The real server-role owner must admit the selected old binary before
    # destructive apply even without an explicit auth file. Read-only choice
    # and mutation callbacks are fixture seams; binary resolution is actual.
    old_server = Path(os.environ['AEGIS_TEST_OLD_SERVER_READER']).resolve()
    assert old_server.is_file() and os.access(old_server, os.X_OK), 'INVALID actual old server binary required'
    old_copy = case / 'old-release/bin/aegis-server'; old_copy.parent.mkdir(parents=True)
    shutil.copyfile(old_server, old_copy); old_copy.chmod(0o700)
    assert digest(old_copy) == digest(old_server), 'INVALID old server binary copy race'
    private(case / 'old-release-binary.json', json.dumps(dict(source=str(old_server), snapshot=str(old_copy), sha256=digest(old_copy))) + '\n')
    begin = install.index('install_server_role() {')
    end = install.index('\ninstall_client_role() {', begin) if '\ninstall_client_role() {' in install[begin:] else None
    assert end, 'INVALID actual server owner boundary'
    owner = install[begin:end]
    # Keep only the actual function; additional definitions between role owners
    # are inert availability, not executed substitute logic.
    binary = actual_function(install, 'install_binary', 'install_manifest_path_for_role')
    asset = actual_function(install, 'require_asset', 'has_command')
    # require_asset's existing policy is independently exercised by binary
    # existence; preflight uses only the supplied fresh private actual binary.
    prefix = 'set -euo pipefail\nROOT=' + shell_quote(old_copy.parent.parent) + '\nSOURCE_LAYOUT=0\n'
    prefix += 'PREFIX=' + shell_quote(case / 'prefix') + '\nCONFIG_DIR=' + shell_quote(case / 'config') + '\nSTATE_DIR=' + shell_quote(case / 'state') + '\nSYSTEMD_DIR=' + shell_quote(case / 'systemd') + '\nENV_DIR=' + shell_quote(case / 'env') + '\nAUTH_TOKEN_FILE=""\nAUTH_TOKEN=""\n'
    prefix += asset + '\n'
    marker = case / 'apply-marker'
    prefix += 'resolve_existing_install_choice() { printf "%s" reinstall; }\napply_existing_install_choice() { printf changed > ' + shell_quote(marker) + '; }\n'
    leaf = case / 'old-release-owner.sh'; private(leaf, prefix + binary + '\n' + owner + '\ninstall_server_role\n')
    rc, stdout, stderr = run('control-old-server-owner', [str(real_bash), str(leaf)])
    assert rc != 0 and not marker.exists(), 'actual default-credential server owner applied old release before protocol refusal'
    assert b'Selected release lacks the private installer input protocol.' in stderr, 'INVALID actual old-release refusal phase'
    # A curl-config record above minimum pipe capacity is sent as a private
    # regular descriptor and has the original one-second transfer cutoff.
    large = case / 'large-access'; private(large, 'https://fixture.invalid/' + '"' * 8000)
    payload = case / 'payload'; private(payload, b'actual-large-config-response')
    env, log = tools(case); env['AEGIS_TEST_PAYLOAD'] = str(payload)
    rc, output = fetch('large-config', large, environment=env)
    assert rc == 0 and output.read_bytes() == payload.read_bytes(), 'INVALID actual large-config transfer positive'
    witness = (case / 'input-witness').read_bytes()
    assert len(witness) > 8192 and b'"' * 8000 not in log.read_bytes(), 'actual encoded secret input used argv or missing descriptor witness'
    env['AEGIS_TEST_DOWNLOADER_WAIT'] = '1'
    env['AEGIS_TEST_STARTED'] = str(case / 'deadline-child-started')
    rc, output = fetch('one-original-deadline', environment=env)
    assert (case / 'deadline-child-started').is_file(), 'INVALID actual downloader startup witness'
    assert rc == 124 and not output.exists(), 'actual original transfer cutoff did not refuse publication'
    assert url.encode() not in log.read_bytes(), 'deadline control leaked actual child URL argument'
    # The actual local-copy child supports encoded Linux file URI semantics.
    local = case / 'local source'; private(local, b'actual local copy bytes')
    local_access = case / 'local-access'; private(local_access, local.as_uri())
    rc, output = fetch('local-copy', local_access)
    assert rc == 0 and output.read_bytes() == local.read_bytes(), 'INVALID actual Linux local-copy consumer'
    before = output.read_bytes()
    rc, _, _ = run('control-exclusive-output', [str(client), 'profile', 'installer-secret', 'fetch',
        '--input', str(local_access), '--output', str(output), '--connect-seconds', '1', '--total-seconds', '1'])
    assert rc != 0 and output.read_bytes() == before, 'actual existing destination was overwritten'

if os.environ.get('AEGIS_TEST_SECRET_PHASE', 'paired') == 'controls':
    assert role == 'candidate', 'candidate controls require actual candidate CLI'
    fixture('actual_private_transfer_controls', actual_controls)
    assert len(rows) == 1, 'INVALID control selection'
else:
    fixture('download_argv', download_argv)
    fixture('renderer_argv', renderer_argv)
    fixture('summary_stdout', summary_stdout)
    fixture('issuer_stdout', issuer_stdout)
    for name in ('private', 'fetch', 'archive', 'existing', 'valid'):
        fixture('mac_' + name, lambda name=name: mac(name, name))
    assert len(rows) == 9, 'INVALID fixture selection'
private(work / 'fixture-results.json', json.dumps(dict(role=role, cases=rows, limitations=[
    'Synthetic fixture bytes only; no installed host, service, network or root-owner acceptance.',
    'Ordinary group signal attempts and leader reap do not prove escaped-descendant quiescence.',
    'Filesystem calls are not kernel-preemptible; no universal hard filesystem deadline.',
    'Baseline admission adapters are QA only; exact actual old function/CLI performs the behavior.',
    'Mac daemon path relocation and inert OS tools are explicitly a fixture, not native service proof.']), indent=2) + '\n')
print('Private fixture receipt directory:', work)
for row in rows: print(row['case'] + ': ' + row['result'])
raise SystemExit(0 if all(row['result'] == 'PASS' for row in rows) else 1)
PY
