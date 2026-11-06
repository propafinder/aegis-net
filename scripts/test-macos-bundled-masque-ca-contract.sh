#!/usr/bin/env bash
# Real packaged Rust helper and generated installer, confined to private fixtures.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 -I - "${ROOT}" <<'PYTEST'
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from pathlib import Path

root = Path(sys.argv[1]).resolve()
source = Path(os.environ.get('AEGIS_TEST_MACOS_BUILDER_SOURCE', root / 'scripts/build-macos-client-tarball.sh')).read_text()
match = re.search(r'^cat > "\$\{BUNDLE_DIR\}/install-macos-client.sh" <<\'EOF\'\n(.*?)^EOF$', source, re.M | re.S)
assert match, 'generated installer missing'
actual_client = Path(os.environ.get('AEGIS_TEST_SECRET_CLIENT', root / 'target/debug/aegis-client')).resolve()
assert actual_client.is_file() and os.access(actual_client, os.X_OK), 'actual compiled Rust client required'
actual_measure = Path(os.environ.get('AEGIS_TEST_MEASURE', root / 'target/debug/aegis-measure')).resolve()
assert actual_measure.is_file() and os.access(actual_measure, os.X_OK), 'actual compiled Rust manifest writer required'
measure_pin = os.environ.get('AEGIS_TEST_MEASURE_SHA256', '')
assert re.fullmatch(r'[0-9a-f]{64}', measure_pin), 'explicit root-reviewed measure binary SHA-256 required'
assert hashlib.sha256(actual_measure.read_bytes()).hexdigest() == measure_pin, 'actual manifest writer identity changed'
project_names = ('LICENSE-MIT', 'LICENSE-APACHE', 'NOTICE')
project_bytes = {name: (root / name).read_bytes() for name in project_names}
project_placeholders = dict(zip(project_names, ('__AEGIS_PROJECT_LICENSE_MIT_SHA256__', '__AEGIS_PROJECT_LICENSE_APACHE_SHA256__', '__AEGIS_PROJECT_NOTICE_SHA256__')))
assert os.geteuid() != 0, 'private contract requires a non-root runner'
real_openssl = shutil.which('openssl')
assert real_openssl, 'owned fixture PKI producer required'
# Only future root-supervised QA executes these bounded children; no network or Keychain.
def command(argv, cwd, env, seconds, input_bytes=None):
    child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        out, err = child.communicate(input=input_bytes, timeout=seconds)
    except subprocess.TimeoutExpired:
        # Kill while the owned leader is unreaped, then confirm the direct reap.
        os.killpg(child.pid, signal.SIGKILL)
        child.communicate(timeout=4)
        raise AssertionError('owned fixture operation deadline')
    return child.returncode, out, err

def check(value, name):
    if not value:
        raise AssertionError(name)

with tempfile.TemporaryDirectory(prefix='aegis-bundled-masque-ca-') as temporary:
    work = Path(temporary).resolve()
    work.chmod(0o700)
    # Run the actual builder in a synthetic checkout. Compilation and the
    # unexercised Keychain binary are inert; the packaged client and production
    # manifest writer are actual root-reviewed Rust executables, not JSON mocks.
    builder_root = work / 'builder-checkout'
    builder_tools = work / 'builder-tools'
    builder_output = work / 'builder-output'
    for directory in (builder_root, builder_tools, builder_output): directory.mkdir(mode=0o700)
    def builder_file(name, contents, mode=0o644):
        path = builder_root / name; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents if isinstance(contents, bytes) else contents.encode()); path.chmod(mode)
    builder_file('scripts/build-macos-client-tarball.sh', source, 0o755)
    for name in ('scripts/lib/release-toolchain.sh', 'rust-toolchain.toml', 'aegis-client/Cargo.toml', 'config.example.toml', 'packaging/launchd/dev.aegis.client.plist', 'packaging/launchd/dev.aegis.client.daemon.plist', *project_names):
        builder_file(name, (root / name).read_bytes())
    builder_file('tools/macos/proxy-keychain.rs', '// unexecuted compilation fixture\n')
    tool_source = r'''import os, pathlib, shutil, subprocess, sys
root = pathlib.Path(os.environ['AEGIS_TEST_BUILDER_ROOT'])
tools = pathlib.Path(os.environ['AEGIS_TEST_BUILDER_TOOLS'])
args = sys.argv[1:]; name = pathlib.Path(sys.argv[0]).name
if name == 'cargo':
    if args[0] == 'build':
        target = args[args.index('--target') + 1]
        output = root / 'target' / target / 'release/aegis-client'; output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(os.environ['AEGIS_TEST_SECRET_CLIENT'], output); output.chmod(0o755)
    else:
        assert args[0] == 'run' and '--' in args
        command = args[args.index('--') + 1:]
        assert command[0] in ('build-macos-client-tarball-manifest', 'write-archive-sha256')
        raise SystemExit(subprocess.run([os.environ['AEGIS_TEST_MEASURE'], *command], stdin=subprocess.DEVNULL, timeout=10, check=False).returncode)
elif name == 'rustup':
    if args[0] == 'which': print(tools / args[-1])
    else: assert args[:2] == ['target', 'add']
elif name == 'rustc':
    if args == ['--version']: print('rustc ' + os.environ['AEGIS_TEST_TOOLCHAIN_VERSION'] + ' (inert compiler fixture)')
    else:
        output = pathlib.Path(args[args.index('-o') + 1]); output.write_text('#!/bin/sh\nexit 95\n'); output.chmod(0o755)
elif name in ('rustdoc', 'cmake'): pass
else: raise SystemExit('unreviewed builder fixture tool')
'''
    for name in ('cargo', 'rustup', 'rustc', 'rustdoc', 'cmake'):
        path = builder_tools / name
        path.write_text('#!' + sys.executable + ' -I\n' + tool_source); path.chmod(0o755)
    version = tomllib.loads((root / 'rust-toolchain.toml').read_text())['toolchain']['channel']
    builder_env = dict(os.environ, AEGIS_TEST_BUILDER_ROOT=str(builder_root), AEGIS_TEST_BUILDER_TOOLS=str(builder_tools),
                       AEGIS_TEST_TOOLCHAIN_VERSION=version, AEGIS_TEST_SECRET_CLIENT=str(actual_client),
                       AEGIS_TEST_MEASURE=str(actual_measure), AEGIS_BUILD_GIT_SHA='a' * 40, AEGIS_BUILD_TIMESTAMP='2026-10-12T00:00:00Z',
                       PATH=str(builder_tools) + os.pathsep + '/usr/bin:/bin:/usr/sbin:/sbin', COPYFILE_DISABLE='1')
    # The builder prepends the user's Cargo path. Export fixed fixture functions
    # for tool resolution only; neither HOME nor CARGO_HOME is repurposed.
    functions = ' '.join(name + '() { "$AEGIS_TEST_BUILDER_TOOLS/' + name + '" "$@"; }; export -f ' + name + ';' for name in ('cargo', 'rustup', 'rustc', 'rustdoc', 'cmake'))
    rc, out, err = command(['/bin/bash', '-c', functions + ' exec /bin/bash "$1" "$2" aarch64-apple-darwin', 'fixture-builder', str(builder_root / 'scripts/build-macos-client-tarball.sh'), str(builder_output)], builder_root, builder_env, 35)
    check(rc == 0, 'actual macOS builder with real manifest writer')
    archives = list(builder_output.glob('*.tar.gz')); check(len(archives) == 1, 'one software archive produced')
    with tarfile.open(archives[0]) as tar:
        files = {member.name: member for member in tar.getmembers() if member.isfile()}
        manifest_name = next(name for name in files if name.endswith('/macos-client-bundle.manifest.json'))
        software_prefix = manifest_name[:-len('macos-client-bundle.manifest.json')]
        built_manifest = json.load(tar.extractfile(files[manifest_name]))
        # The actual Rust writer supplies entry hashes; inspect its serialized
        # structure without replacing it with a fixture inventory implementation.
        entries = built_manifest['entries']
        for name in project_names:
            member = files.get(software_prefix + name); check(member is not None, 'project text missing from software tar')
            check(tar.extractfile(member).read() == project_bytes[name] and member.mode & 0o777 == 0o644, 'exact tar project bytes and mode')
            matching = [entry for entry in entries if entry.get('path') == name]
            check(len(matching) == 1 and matching[0].get('sha256') == hashlib.sha256(project_bytes[name]).hexdigest(), 'actual Rust manifest binds project text')
    check(archives[0].with_name(archives[0].name + '.sha256').read_text().split()[0] == hashlib.sha256(archives[0].read_bytes()).hexdigest(), 'actual Rust archive digest')
    print('MAC_PROJECT_LICENSE software_archive status=PASS native_compiler=INERT manifest_writer=ACTUAL_RUST', flush=True)
    package = work / 'package'
    (package / 'bin').mkdir(parents=True)
    installer = package / 'install-macos-client.sh'
    installer_text = match[1]
    for name in project_names:
        (package / name).write_bytes(project_bytes[name])
        installer_text = installer_text.replace(project_placeholders[name], hashlib.sha256(project_bytes[name]).hexdigest())
    installer.write_text(installer_text)
    client = package / 'bin/aegis-client'
    shutil.copyfile(actual_client, client)
    client.chmod(0o755)
    check(hashlib.sha256(client.read_bytes()).digest() == hashlib.sha256(actual_client.read_bytes()).digest(), 'copied actual producer identity')
    rc, out, err = command([str(client), 'profile', 'bundle-ca', 'version'], package, os.environ, 10)
    check(rc == 0 and out.strip() == b'bundle-ca-v1', 'actual common helper protocol')
    (package / 'macos-client-bundle.manifest.json').write_text(json.dumps(dict(version='fixture', git_sha='fixture', build_timestamp='fixture', platform='macos', arch='aarch64', target_triple='aarch64-apple-darwin')))
    cert = work / 'owned-public-ca.pem'
    key = work / 'owned-fixture-key.pem'
    rc, out, err = command([real_openssl, 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=fixture.invalid', '-keyout', str(key), '-out', str(cert), '-days', '1'], work, os.environ, 10)
    check(rc == 0 and cert.is_file(), 'owned public CA generation')
    key.unlink()  # Never archive or display the test-owned private key.
    scoped_bytes = cert.read_bytes()
    general_bytes = b'original-general-public-anchor-fixture\n'
    token = '42' * 32  # Synthetic local credential only.
    mocks = work / 'mocks'
    mocks.mkdir()
    def executable(path, text):
        path.write_text(text)
        path.chmod(0o755)
    executable(mocks / 'openssl', '#!/bin/sh\n[ "$1 $2 $3" = "rand -hex 32" ] || exit 92\nprintf "%s\\n" "' + token + '"\n')
    executable(mocks / 'launchctl', '#!/bin/sh\nexit 93\n')
    executable(mocks / 'networksetup', '#!/bin/sh\nexit 94\n')
    # The six exact cases are identical for the original-script/common-helper and candidate roles.
    cases = [('relative_legacy', 'masque-ca.pem', None, 'valid'),
             ('relative_configured', './masque-ca.pem', 'configured_ca_only', 'valid'),
             ('missing_before_purge', 'masque-ca.pem', None, 'missing'),
             ('symlink_before_purge', 'masque-ca.pem', None, 'symlink'),
             ('external_preserved', '/operator/external-public-ca.pem', 'configured_ca_only', 'unrelated'),
             ('absent_preserved', None, None, 'unrelated')]
    failed = 0
    for name, reference, mode, asset in cases:
        case = work / name
        case.mkdir(mode=0o700)
        home = case / 'home'
        home.mkdir(mode=0o700)
        bundle = case / 'client-bundle'
        bundle.mkdir(mode=0o700)
        text = 'mode = "relay"\n[socks]\nlisten = "127.0.0.1:1080"\nauth_user = "fixture-user"\n[relay]\nauth_token = "synthetic-relay-fixture"\nserver = "192.0.2.9:443"\nserver_name = "fixture.invalid"\nca_cert = "__CLIENT_CA_CERT_PATH__"\n'
        if reference is not None: text += 'masque_ca_cert = ' + json.dumps(reference) + '\n'
        if mode is not None: text += 'masque_trust_mode = ' + json.dumps(mode) + '\n'
        (bundle / 'aegis-client.toml').write_text(text)
        (bundle / 'ca.pem').write_bytes(general_bytes)
        if asset == 'valid': (bundle / 'masque-ca.pem').write_bytes(scoped_bytes)
        if asset == 'unrelated': (bundle / 'masque-ca.pem').write_bytes(b'unrelated unusable public input\n')
        if asset == 'symlink':
            (bundle / 'different.pem').write_bytes(scoped_bytes)
            (bundle / 'masque-ca.pem').symlink_to('different.pem')
        archive = case / 'bundle.tar.gz'
        with tarfile.open(archive, 'w:gz', dereference=False) as tar:
            tar.add(bundle, arcname='client-bundle')
        access = case / 'access.txt'
        access.write_text('file://' + str(archive))
        access.chmod(0o600)
        config_dir = home / '.config/aegis'
        refusal = asset in ('missing', 'symlink')
        originals = {}
        if refusal:
            for path, contents in [(config_dir / 'aegis.toml', b'original private installation\n'),
                                   (home / '.local/bin/aegis-client', b'original installed binary\n'),
                                   (home / '.local/state/aegis/retained', b'original retained state\n')]:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(contents)
                path.chmod(0o600)
                originals[path] = contents
            config_dir.chmod(0o700)
        env = dict(os.environ, AEGIS_INSTALL_TMPDIR_CANDIDATES=str(case), PATH=str(mocks) + os.pathsep + os.environ['PATH'])
        argv = ['/bin/bash', str(installer), '--bundle-url-file', str(access), '--bundle-local-only', '--no-browser-proxy', '--service-mode', 'foreground', '--user-home', str(home)]
        if refusal: argv.append('--reinstall')
        cause = 'none'
        rc = -1
        try:
            rc, out, err = command(argv, package, env, 30)
            check(token.encode() not in out + err and scoped_bytes not in out + err, 'private material output')
            check(not list(case.glob('aegis-bundle.*')), 'private stage cleanup')
            if refusal:
                check(rc != 0, 'missing or aliased scoped CA accepted')
                check(all(path.is_file() and path.read_bytes() == contents for path, contents in originals.items()), 'pre-purge installation preservation')
                check(not (config_dir / 'masque-ca.pem').exists(), 'refused CA destination mutation')
            else:
                check(rc == 0, 'actual installation result')
                config = tomllib.loads((config_dir / 'aegis.toml').read_text())
                relay = config['relay']
                check(relay['ca_cert'] == str(config_dir / 'ca.pem') and (config_dir / 'ca.pem').read_bytes() == general_bytes, 'original general CA flow')
                check(config['socks']['auth_user'] == 'fixture-user' and config['socks']['auth_token'] == token, 'original local authentication flow')
                check(stat.S_IMODE((config_dir / 'aegis.toml').stat().st_mode) == 0o600, 'private config permissions')
                for project_name in project_names:
                    installed_text = home / '.local/share/doc/aegis' / project_name
                    check(installed_text.is_file() and not installed_text.is_symlink() and installed_text.read_bytes() == project_bytes[project_name], 'installed exact project text')
                    check(stat.S_IMODE(installed_text.stat().st_mode) == 0o644 and installed_text.stat().st_uid == os.getuid(), 'installed public project text mode and owner')
                check(relay.get('masque_trust_mode') == mode, 'explicit or absent trust mode preserved')
                if asset == 'valid':
                    target = config_dir / 'masque-ca.pem'
                    check(relay['masque_ca_cert'] == str(target), 'durable scoped CA config reference')
                    check(target.read_bytes() == scoped_bytes and target.stat().st_nlink == 1 and stat.S_IMODE(target.stat().st_mode) == 0o600, 'owned durable scoped CA bytes and permissions')
                else:
                    check(relay.get('masque_ca_cert') == reference and not (config_dir / 'masque-ca.pem').exists(), 'external or absent scoped CA preservation')
        except AssertionError as error:
            failed += 1
            cause = str(error)  # Only fixed local assertion labels, never producer stderr.
        print('MAC_BUNDLED_CA case=' + name + ' status=' + ('PASS' if cause == 'none' else 'FAIL') + ' exit=' + str(rc) + ' cause=' + cause, flush=True)
    check(failed == 0, 'bundled MASQUE CA contract cases failed')
    # Every required project text must fail before existing installation/purge,
    # even with a valid access record and CA. Preserve the original six CA cases.
    for project_name in project_names:
        for fault in ('missing', 'tampered'):
            case = work / ('project-' + project_name + '-' + fault); case.mkdir(mode=0o700)
            home = case / 'home'; home.mkdir(mode=0o700)
            originals = {}
            for relative, contents in [('.config/aegis/aegis.toml', b'preserved private config\n'),
                                       ('.local/bin/aegis-client', b'preserved binary\n'),
                                       ('.local/state/aegis/retained', b'preserved private state\n'),
                                       ('.local/share/doc/aegis/NOTICE', b'preserved installed notice\n')]:
                path = home / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(contents); originals[path] = contents
            (home / '.config/aegis').chmod(0o700)
            # Reuse the valid local input prepared by the earlier CA case; no
            # URL, network, installer helper or credential behavior is mocked.
            archive = work / 'relative_legacy/bundle.tar.gz'
            access = case / 'access.txt'; access.write_text('file://' + str(archive)); access.chmod(0o600)
            package_text = package / project_name
            if fault == 'missing': package_text.unlink()
            else: package_text.write_bytes(project_bytes[project_name] + b'changed')
            env = dict(os.environ, AEGIS_INSTALL_TMPDIR_CANDIDATES=str(case), PATH=str(mocks) + os.pathsep + os.environ['PATH'])
            rc, out, err = command(['/bin/bash', str(installer), '--bundle-url-file', str(access), '--bundle-local-only', '--no-browser-proxy', '--service-mode', 'foreground', '--user-home', str(home), '--reinstall'], package, env, 30)
            check(rc != 0 and project_name.encode() in err, 'missing or changed project text refused semantically')
            check(all(path.is_file() and path.read_bytes() == contents for path, contents in originals.items()), 'project refusal before installation/purge mutation')
            check(not list(case.glob('aegis-bundle.*')), 'project refusal private snapshot cleanup')
            package_text.write_bytes(project_bytes[project_name])
            print('MAC_PROJECT_LICENSE case=' + project_name + '_' + fault + ' status=PASS', flush=True)
    # Real generated installer rejects a hostile destination before its existing
    # --reinstall purge, using the actual typed Rust readonly admission action.
    case = work / 'project-destination-before-purge'; case.mkdir(mode=0o700)
    home = case / 'home'; home.mkdir(mode=0o700)
    original = home / '.config/aegis/aegis.toml'; original.parent.mkdir(parents=True); original.write_bytes(b'preserved configuration\n'); original.parent.chmod(0o700)
    outside = case / 'unrelated'; outside.mkdir(mode=0o700)
    victim = outside / 'NOTICE'; victim.write_bytes(b'preserved unrelated victim\n')
    (home / '.local').symlink_to(outside, target_is_directory=True)
    access = case / 'access.txt'; access.write_text('file://' + str(work / 'relative_legacy/bundle.tar.gz')); access.chmod(0o600)
    env = dict(os.environ, AEGIS_INSTALL_TMPDIR_CANDIDATES=str(case), PATH=str(mocks) + os.pathsep + os.environ['PATH'])
    rc, out, err = command(['/bin/bash', str(installer), '--bundle-url-file', str(access), '--bundle-local-only', '--no-browser-proxy', '--service-mode', 'foreground', '--user-home', str(home), '--reinstall'], package, env, 30)
    diagnostic = dict(rc=rc,
                      static_error_stderr=b'[install-macos] public project text check refused' in err,
                      static_error_stdout=b'[install-macos] public project text check refused' in out,
                      config_same=original.is_file() and original.read_bytes() == b'preserved configuration\n',
                      victim_same=victim.is_file() and victim.read_bytes() == b'preserved unrelated victim\n',
                      cleanup=not list(case.glob('aegis-bundle.*')),
                      static_temp_refusal=b'no existing temporary base outside reinstall roots' in err,
                      static_protocol_refusal=b'packaged client lacks public project-text protocol' in err)
    print('MAC_PROJECT_LICENSE destination_admission_diagnostic ' + json.dumps(diagnostic, sort_keys=True), flush=True)
    check(rc != 0 and b'[install-macos] public project text check refused' in err and original.read_bytes() == b'preserved configuration\n' and victim.read_bytes() == b'preserved unrelated victim\n', 'actual installer destination refusal before purge')
    check(not list(case.glob('aegis-bundle.*')), 'destination refusal snapshot cleanup')
    # Exercise the actual Rust CLI over bounded public stdin. No sudo/root/VM.
    control = work / 'project-fd-controls'; control.mkdir(mode=0o700)
    home = control / 'home'; home.mkdir(mode=0o700)
    outside = control / 'outside'; outside.mkdir(mode=0o700)
    victim = outside / 'NOTICE'; victim.write_bytes(b'preserved private victim\n')
    def license_cli(action, owner=os.getuid(), digest=None, contents=None):
        return command([str(client), 'profile', 'project-license', action,
                        '--home', str(home), '--owner-uid', str(owner), '--owner-gid', str(os.getgid()),
                        '--leaf', 'NOTICE', '--expected-sha256', digest or hashlib.sha256(project_bytes['NOTICE']).hexdigest()],
                       package, os.environ, 10, project_bytes['NOTICE'] if contents is None else contents)
    rc, out, err = license_cli('check'); check(rc == 0 and not (home / '.local').exists(), 'readonly descriptor preflight')
    rc, out, err = license_cli('install'); check(rc == 0, 'actual public text descriptor install')
    leaf = home / '.local/share/doc/aegis/NOTICE'
    check(leaf.read_bytes() == project_bytes['NOTICE'] and leaf.stat().st_uid == os.getuid(), 'actual descriptor install exact bytes owner')
    before = leaf.stat().st_ino
    rc, out, err = license_cli('install'); check(rc == 0 and leaf.stat().st_ino != before, 'actual atomic inode replacement')
    for uid in (0, os.getuid() + 1):
        rc, out, err = license_cli('install', owner=uid)
        check(rc != 0 and leaf.read_bytes() == project_bytes['NOTICE'], 'unprivileged owner mismatch refusal')
    for contents, digest in ((b'changed', None), (b'x' * 65537, '0' * 64), (b'', '0' * 64)):
        rc, out, err = license_cli('install', digest=digest, contents=contents)
        check(rc != 0 and leaf.read_bytes() == project_bytes['NOTICE'], 'public stdin hash and size refusal')
    leaf.unlink(); leaf.symlink_to(victim)
    rc, out, err = license_cli('install'); check(rc != 0 and victim.read_bytes() == b'preserved private victim\n', 'leaf symlink victim unchanged')
    leaf.unlink(); os.link(victim, leaf)
    rc, out, err = license_cli('install'); check(rc != 0 and victim.read_bytes() == b'preserved private victim\n', 'hardlink victim unchanged')
    leaf.unlink()
    doc = home / '.local/share/doc/aegis'; doc.rename(control / 'retained'); doc.symlink_to(outside, target_is_directory=True)
    rc, out, err = license_cli('check'); check(rc != 0 and victim.read_bytes() == b'preserved private victim\n', 'suffix symlink refused by descriptor preflight')
    print('MAC_PROJECT_LICENSE actual_fd_cli_controls status=PASS root_UID0_native=NOT_EXECUTED', flush=True)
print('PASS: actual software archive/Rust manifest, six generated-installer CA cases and six project-text refusals and actual Rust descriptor CLI controls; local fixture only')
PYTEST
