#!/usr/bin/env python3
"""B-06 S09 product packaging checks used by build-sign-notarize.sh.

Subcommands are read-only checks except `receipt`, which writes one JSON
receipt in the caller-chosen (gitignored) artifacts directory, and
`disarm-weak-host`, which removes one kept copy's host executable. Nothing here
signs, uploads, staples, installs or changes trust/keychain state.

- check-version: CFBundleVersion must be strictly greater than every receipt,
  every entry of the worktree-independent version ledger and the installed app.
- ledger-reserve: record a reserved version in the ledger (exclusive create).
- check-committed: committed entitlement files equal the reviewed role set.
- check-profile: decoded Developer ID profile fields for one role.
- diff-signed: signed claims equal the committed file and every profile-gated
  claim is explicitly authorized by the decoded profile.
- check-signature: `codesign -dvv` display shows Developer ID, Team, runtime
  and a secure timestamp.
- check-modes: bundle or ZIP entries carry 0755 directories and 0644/0755
  files (no owner-only modes in the distributable artifact).
- receipt: create/update the run receipt; --stage-status is order aware.
- compare-version: an install replacement needs a strictly greater
  CFBundleVersion than the installed app (same grammar and order).
- activation-outcome: map an `aegis-ne-host --request-activation` exit code
  (src/host_lifecycle.rs) to the install outcome and receipt stage status;
  a host-reported code counts only with the host's matching
  `activation_result=` line (else host-unknown-exit).
- deactivation-outcome: the same for `aegis-ne-host --deactivate` (S21),
  against its own `deactivation_result=` line and exit-code table.
- filter-outcome: the same for the S20b filter verbs (`--enable-filter`,
  `--remove-filter`, `--filter-status`) against their `filter_result=` line.
- latest-uninstalled: the most recently moved AEGIS.app.uninstalled-<version>-
  <utc>[.N] copy of a directory, by its UTC stamp and retry suffix (never
  by a text sort of the name, where version 10 sorts before 9).
- disarm-weak-host: a kept (replaced or uninstalled) AEGIS.app whose host
  has the S20b filter verbs but not the v30 password-only leak-guard right
  (FILTER_MIN_PRIOR < CFBundleVersion < LEAK_GUARD_PASSWORD_MIN: v25 has no
  prompt, v26 to v29 one that offers Touch ID) loses its host executable,
  its SHA-256 recorded beside it; any other copy is unchanged.
- forget-reply / ping-identity: parse the host's one-line JSON reply of
  `--forget-identity` / `--ping` (exact shape, schema and verb) into the
  booleans uninstall-app.sh gates on; any other shape is refused.
"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import plistlib
import re
import stat
import subprocess
import sys
import tempfile
import zipfile

TEAM = 'TEAMID0000'
APP_ID = 'dev.aegis.macos'
PROVIDER_ID = APP_ID + '.PacketTunnel'
GROUP = 'group.' + TEAM + '.' + APP_ID
NE_KEY = 'com.apple.developer.networking.networkextension'
NE_VALUE = 'packet-tunnel-provider-systemextension'
# S20b: the packet filter (NEFilterPacketProvider) in the same system
# extension. Both roles carry both values, in this order: the host needs it
# for NEFilterManager, the provider for the filter-packet provider class.
NE_FILTER_VALUE = 'content-filter-provider-systemextension'
NE_VALUES = [NE_FILTER_VALUE, NE_VALUE]
# Historical B-06 assemblies (all receipts before S09) hard-coded
# CFBundleVersion 1, so a product version must exceed it.
HISTORICAL_BASELINE = '1'
# S20b: every host above this CFBundleVersion has --disable-filter and
# --remove-filter (uninstall-app.sh FILTER_MIN_PRIOR, a test binds both).
FILTER_MIN_PRIOR = '24'
# v26: the first host whose filter-weakening verbs ask for an administrator.
WEAKEN_PROMPT_MIN = '26'
# v30 review: the first host whose filter-weakening verbs ask for the
# password-only right dev.aegis.macos.leak-guard-change. v26 to v29 ask for
# dev.aegis.macos.leak-guard-weaken, registered with Touch ID allowed (one
# resting touch approved two v29 prompts), and the host alone changes
# NEFilterManager, so a kept copy of them is as weak as the leak guard gets.
LEAK_GUARD_PASSWORD_MIN = '30'
HOST_EXECUTABLE = 'aegis-ne-host'
# Sandbox claims are not provisioning-profile gated; every other claim is.
UNRESTRICTED = frozenset({
    'com.apple.security.app-sandbox',
    'com.apple.security.network.client',
    'com.apple.security.network.server',
})
FORBIDDEN = ('get-task-allow', 'com.apple.security.get-task-allow',
             'keychain-access-groups')
FORBIDDEN_PREFIXES = ('com.apple.security.cs.',)
# Stage order of build-sign-notarize.sh. A stage result is current only
# while no earlier stage has a later real (non-dry-run) entry.
STAGE_ORDER = ('build', 'assemble', 'sign', 'verify', 'zip', 'notarize',
               'staple', 'assess')
VERSION_RE = re.compile(r'[1-9][0-9]{0,8}(\.(0|[1-9][0-9]{0,8})){0,2}')


class Refusal(Exception):
    pass


def version_key(text):
    if not isinstance(text, str) or not VERSION_RE.fullmatch(text):
        raise Refusal(f'invalid CFBundleVersion {text!r}')
    parts = [int(x) for x in text.split('.')]
    return tuple(parts + [0] * (3 - len(parts)))


# `aegis-ne-host --request-activation` exit codes, mirrored from the
# EXIT_ACTIVATION_* constants in src/host_lifecycle.rs (a test binds both).
# The host bounds itself at 120 s; the install script's outer watchdog kills
# it with SIGALRM (exit 142) only if that bound were broken.
ACTIVATION_EXITS = {
    0: ('completed', 'ok'),
    2: ('host-usage', 'failed'),
    10: ('will-complete-after-reboot', 'pending-reboot'),
    11: ('failed', 'failed'),
    12: ('cancelled', 'failed'),
    13: ('replacement-declined', 'failed'),
    14: ('timeout-awaiting-approval', 'failed'),
    75: ('timeout', 'failed'),
    142: ('host-unbounded', 'failed'),
}
# Exits the host does not report on an `activation_result=` line: a usage
# refusal and the install script's SIGALRM watchdog.
UNREPORTED_EXITS = frozenset({2, 142})
UNKNOWN_EXIT = ('host-unknown-exit', 'failed')
# `aegis-ne-host` filter verb exit codes (S20b), mirrored from the
# EXIT_FILTER_* constants and FilterOutcome in src/host_lifecycle.rs (a test
# binds both). 69 is the host's provider-unavailable XPC code; 67 (v26) is
# its EXIT_AUTHORIZATION_REFUSED: no administrator approved --disable-filter
# or --remove-filter.
FILTER_EXITS = {
    0: ('ok', 'ok'),
    2: ('host-usage', 'failed'),
    30: ('not-configured', 'failed'),
    31: ('disabled', 'failed'),
    32: ('field-mismatch', 'failed'),
    33: ('not-attached', 'failed'),
    34: ('failed', 'failed'),
    35: ('permission-denied', 'failed'),
    36: ('timeout', 'failed'),
    37: ('removal-incomplete', 'failed'),
    67: ('authorization-refused', 'failed'),
    69: ('provider-unavailable', 'failed'),
    142: ('host-unbounded', 'failed'),
}
# `aegis-ne-host --deactivate` exit codes, mirrored from the
# EXIT_DEACTIVATION_* constants in src/host_lifecycle.rs (a test binds both).
# Only 0 deactivated the extension; not-found is never read as deactivated.
DEACTIVATION_EXITS = {
    0: ('completed', 'ok'),
    2: ('host-usage', 'failed'),
    20: ('will-complete-after-reboot', 'pending-reboot'),
    21: ('failed', 'failed'),
    22: ('cancelled', 'failed'),
    23: ('not-found', 'failed'),
    24: ('timeout-awaiting-approval', 'failed'),
    25: ('timeout', 'failed'),
    142: ('host-unbounded', 'failed'),
}
XPC_SCHEMA = 'aegis-ne-xpc-v1'


def expected_entitlements(role, team=TEAM, app_id=APP_ID,
                          provider_id=PROVIDER_ID, group=GROUP):
    ident = app_id if role == 'host' else provider_id
    claims = {
        'com.apple.application-identifier': team + '.' + ident,
        'com.apple.developer.team-identifier': team,
        NE_KEY: list(NE_VALUES),
        'com.apple.security.application-groups': [group],
    }
    if role == 'host':
        claims['com.apple.developer.system-extension.install'] = True
    else:
        # The provider must stay sandboxed (NE system extension); client for
        # the relay, server for the per-flow 127.0.0.1 bridge listener in
        # aegis-client/src/packet_engine/engine.rs (stream_pair).
        for key in sorted(UNRESTRICTED):
            claims[key] = True
    return claims


def load_plist(path):
    data = pathlib.Path(path).read_bytes()
    if not data.strip():
        return {}
    value = plistlib.loads(data)
    if not isinstance(value, dict):
        raise Refusal(f'{path}: plist root is not a dictionary')
    return value


def decoded_profile(args):
    if args.decoded_profile:
        return load_plist(args.decoded_profile)
    raw = pathlib.Path(args.profile)
    result = subprocess.run(['security', 'cms', '-D', '-i', str(raw)],
                            check=False, capture_output=True, timeout=60)
    if result.returncode != 0:
        raise Refusal(f'security cms -D failed for {raw.name}')
    return plistlib.loads(result.stdout)


def signed_claims(args):
    if args.signed_xml:
        return load_plist(args.signed_xml)
    result = subprocess.run(
        ['codesign', '-d', '--entitlements', '-', '--xml', args.bundle],
        check=False, capture_output=True, timeout=60)
    if result.returncode != 0:
        raise Refusal('codesign -d --entitlements failed: '
                      + result.stderr.decode(errors='replace').strip())
    return plistlib.loads(result.stdout) if result.stdout.strip() else {}


def render(value):
    return json.dumps(value, sort_keys=True)


def dict_diff(expected, actual):
    lines = []
    for key in sorted(set(expected) | set(actual)):
        if key not in actual:
            lines.append(f'- {key} = {render(expected[key])}')
        elif key not in expected:
            lines.append(f'+ {key} = {render(actual[key])}')
        elif expected[key] != actual[key]:
            lines.append(f'- {key} = {render(expected[key])}')
            lines.append(f'+ {key} = {render(actual[key])}')
    return lines


def profile_authorization_diff(claims, allowed):
    """Profile-gated claims that the decoded profile does not authorize.

    Lists must be explicit members of the profile list (a profile wildcard
    such as TEAM.* is not accepted as authorization); scalars must be equal.
    """
    lines = []
    for key in sorted(claims):
        if key in UNRESTRICTED:
            continue
        value = claims[key]
        if key not in allowed:
            lines.append(f'! {key} = {render(value)} (absent from profile)')
            continue
        permit = allowed[key]
        if isinstance(value, list):
            missing = [v for v in value if not isinstance(permit, list) or v not in permit]
            if missing or not value:
                lines.append(f'! {key} = {render(missing or value)} (not authorized by profile)')
        elif value != permit:
            lines.append(f'! {key} = {render(value)} (profile has {render(permit)})')
    return lines


def forbidden_claims(claims):
    return [f'! {k} (forbidden in product signature)' for k in sorted(claims)
            if k in FORBIDDEN or k.startswith(FORBIDDEN_PREFIXES)]


def recorded_versions(args):
    """(key, text, source) for every receipt, ledger entry and installed app."""
    found = [(version_key(HISTORICAL_BASELINE), HISTORICAL_BASELINE, 'historical baseline')]
    for directory in [args.receipts_dir] + list(args.ledger_dir or []):
        root = pathlib.Path(directory)
        if not root.exists():
            continue
        for path in sorted(root.glob('*.json')):
            try:
                previous = json.loads(path.read_text())['bundle_version']
            except (OSError, ValueError, KeyError, TypeError) as error:
                raise Refusal(f'unreadable receipt {path.name}: {error}') from error
            found.append((version_key(previous), previous, path.name))
    if args.installed_app:
        info = pathlib.Path(args.installed_app) / 'Contents' / 'Info.plist'
        if pathlib.Path(args.installed_app).exists():
            try:
                previous = plistlib.loads(info.read_bytes())['CFBundleVersion']
            except (OSError, ValueError, KeyError, plistlib.InvalidFileException) as error:
                raise Refusal(f'unreadable installed app version {info}: {error}') from error
            found.append((version_key(previous), previous, 'installed ' + str(args.installed_app)))
    return found


def highest(args):
    best = None
    for entry in recorded_versions(args):
        if best is None or entry[0] >= best[0]:
            best = entry
    return best


def cmd_check_version(args):
    candidate = version_key(args.version)
    _, best_text, source = best = highest(args)
    if candidate <= best[0]:
        raise Refusal(f'CFBundleVersion {args.version} is not greater than '
                      f'{best_text} ({source})')
    print(f'version: {args.version} > {best_text} ({source})')


def cmd_compare_version(args):
    new, installed = version_key(args.new), version_key(args.installed)
    if new <= installed:
        raise Refusal(f'CFBundleVersion {args.new} is not greater than installed {args.installed}')
    print(f'version: {args.new} > installed {args.installed}')


def request_outcome(table, key, exit_code, result_line):
    try:
        code = int(exit_code, 10)
    except ValueError as error:
        raise Refusal(f'invalid exit code {exit_code!r}') from error
    outcome, status = table.get(code, UNKNOWN_EXIT)
    if code in table and code not in UNREPORTED_EXITS:
        # The exit code alone is not the host's word: a failed exec (perl
        # exits with errno) or another process can produce the same number.
        # The last result line must name this outcome and this exit code.
        expected = re.compile(key + r'=' + re.escape(outcome.replace('-', '_'))
                              + r' exit_code=' + str(code) + r'(?: .*)?')
        if not expected.fullmatch(result_line):
            outcome, status = UNKNOWN_EXIT
    return outcome, status


def cmd_activation_outcome(args):
    outcome, status = request_outcome(ACTIVATION_EXITS, 'activation_result',
                                      args.exit_code, args.result_line)
    print(f'{outcome} {status}')


def cmd_filter_outcome(args):
    outcome, status = request_outcome(FILTER_EXITS, 'filter_result',
                                      args.exit_code, args.result_line)
    print(f'{outcome} {status}')


def cmd_deactivation_outcome(args):
    outcome, status = request_outcome(DEACTIVATION_EXITS, 'deactivation_result',
                                      args.exit_code, args.result_line)
    print(f'{outcome} {status}')


def xpc_report(line, verb, keys):
    """The `report` object of one host XPC reply line: exactly
    {schema, verb, report}, this schema and verb, and at least `keys`."""
    try:
        value = json.loads(line)
    except ValueError as error:
        raise Refusal(f'{verb} reply is not one JSON line') from error
    if (not isinstance(value, dict) or set(value) != {'schema', 'verb', 'report'}
            or value['schema'] != XPC_SCHEMA or value['verb'] != verb
            or not isinstance(value['report'], dict)):
        raise Refusal(f'not a {verb} reply')
    report = value['report']
    if not set(keys) <= set(report):
        raise Refusal(f'{verb} reply lacks {sorted(set(keys) - set(report))}')
    return report


def flag(report, key, verb):
    if not isinstance(report[key], bool):
        raise Refusal(f'{verb} {key} is not a boolean')
    return 'true' if report[key] else 'false'


def cmd_forget_reply(args):
    keys = ('identity_was_present', 'key_material_removed')
    report = xpc_report(args.line, 'forget-identity', keys)
    if set(report) != set(keys):
        raise Refusal('forget-identity reply has unexpected fields')
    print(' '.join(f'{key}={flag(report, key, "forget-identity")}' for key in keys))


def cmd_ping_identity(args):
    report = xpc_report(args.line, 'ping', ('identity_present', 'container_open'))
    present = flag(report, 'identity_present', 'ping')
    opened = report['container_open']
    # Absence counts only below an admitted container anchor: with no
    # resolved container the provider reports identity_present=false too.
    admitted = isinstance(opened, dict) and opened.get('admitted') is True
    print(f'identity_present={present} container_admitted={"true" if admitted else "false"}')


UNINSTALLED_COPY_RE = re.compile(r'AEGIS\.app\.uninstalled-(?:' + VERSION_RE.pattern
                                 + r')-(?P<utc>\d{8}T\d{6}Z)(?:\.(?P<n>[1-9][0-9]{0,8}))?')


def cmd_latest_uninstalled(args):
    """Print the newest uninstall copy (uninstall-app.sh `fresh` names):
    ordered by UTC stamp, then by the numeric retry suffix. Names of any
    other shape are ignored; an absent directory prints nothing."""
    directory = pathlib.Path(args.dir)
    best = None
    try:
        names = sorted(entry.name for entry in os.scandir(directory))
    except (FileNotFoundError, NotADirectoryError):
        names = []
    for name in names:
        match = UNINSTALLED_COPY_RE.fullmatch(name)
        if match:
            key = (match['utc'], int(match['n'] or 0))
            if best is None or key > best[0]:
                best = (key, name)
    if best is not None:
        print(directory / best[1])


def weak_host_version(version):
    """True for a host with the filter verbs and without their password-only
    prompt: none (v25) or one that offers Touch ID (v26 to v29)."""
    return version_key(FILTER_MIN_PRIOR) < version_key(version) < version_key(LEAK_GUARD_PASSWORD_MIN)


def weak_host_reason(version):
    """Why a weak host's filter verbs are weak, for its removal note."""
    if version_key(version) < version_key(WEAKEN_PROMPT_MIN):
        return 'predate the v26 administrator prompt'
    return ('ask for an administrator at a prompt that offers Touch ID (dev.aegis.macos.leak-guard-weaken), '
            'before the v30 password-only right')


def cmd_disarm_weak_host(args):
    """A kept copy of a weak host (`weak_host_version`) is still signed and
    executable by any process of the console user, which could disable or
    remove the leak-guard filter with no prompt (v25) or with one resting
    Touch ID touch (v26 to v29). Its host executable is
    removed (the stapled ZIP keeps the build) and its SHA-256 written to
    Contents/MacOS/aegis-ne-host.removed. Prints one `weak_host=` line:
    no, disarmed or disarmed-earlier; an unreadable copy is refused."""
    app = pathlib.Path(args.app)
    if app.is_symlink() or not app.is_dir():
        raise Refusal(f'not an app directory: {app}')
    try:
        info = load_plist(app / 'Contents' / 'Info.plist')
        version = info['CFBundleVersion']
        weak = weak_host_version(version)
    except (OSError, KeyError, TypeError, ValueError, plistlib.InvalidFileException, Refusal) as error:
        raise Refusal(f'unreadable CFBundleVersion of {app}: {error}') from error
    if not weak:
        print(f'weak_host=no version={version}')
        return
    macos = app / 'Contents' / 'MacOS'
    host = macos / HOST_EXECUTABLE
    note = macos / (HOST_EXECUTABLE + '.removed')
    if host.is_symlink() or (host.exists() and not host.is_file()):
        raise Refusal(f'{host} is not a regular file')
    if not host.exists():
        print(f'weak_host=disarmed-earlier version={version}')
        return
    digest = hashlib.sha256(host.read_bytes()).hexdigest()
    # macOS App Management protects a signed bundle's contents (EPERM even
    # for its owner, v26 installed run): the copy is then left unchanged
    # and refused with the owner's remedy, never a traceback.
    try:
        note.write_text(f'removed {HOST_EXECUTABLE} of CFBundleVersion {version}: its '
                        f'--disable-filter and --remove-filter {weak_host_reason(version)}'
                        f'\nsha256={digest}\n')
    except OSError as error:
        raise Refusal(f'weak host of CFBundleVersion {version} in {app} could not be '
                      f'disarmed ({error.strerror}); it was left unchanged. Move {app.name} '
                      'to the Trash in Finder (macOS protects signed app bundles from '
                      'other processes); while the tunnel is up the provider fails closed '
                      'if the filter is stopped') from error
    try:
        host.unlink()
    except OSError as error:
        note.unlink(missing_ok=True)
        raise Refusal(f'weak host of CFBundleVersion {version} in {app} could not be '
                      f'removed ({error.strerror}); it was left in place. Move {app.name} '
                      'to the Trash in Finder') from error
    print(f'weak_host=disarmed version={version} host_sha256={digest}')


def cmd_ledger_reserve(args):
    """Reserve one version in the ledger; the comparison is repeated here."""
    cmd_check_version(args)
    ledger = pathlib.Path(args.ledger_dir[0])
    ledger.mkdir(mode=0o700, parents=True, exist_ok=True)
    entry = ledger / f'v{args.version}-{args.run_id}.json'
    record = {'bundle_version': args.version, 'run_id': args.run_id,
              'commit': args.commit, 'receipt': args.receipt,
              'utc': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}
    try:
        fd = os.open(entry, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise Refusal(f'ledger entry {entry.name} already exists') from error
    with os.fdopen(fd, 'w') as handle:
        handle.write(json.dumps(record, sort_keys=True, indent=2) + '\n')
    print(f'ledger: reserved {args.version} in {entry}')


def cmd_check_committed(args):
    actual = load_plist(args.entitlements)
    expected = expected_entitlements(args.role)
    lines = dict_diff(expected, actual)
    if lines:
        raise Refusal(f'{args.role}: committed entitlements differ from the reviewed set\n'
                      + '\n'.join(lines))
    print(f'{args.role}: committed entitlements match the reviewed set')


def cmd_check_profile(args):
    profile = decoded_profile(args)
    ident = APP_ID if args.role == 'host' else PROVIDER_ID
    allowed = profile.get('Entitlements') or {}
    problems = []
    if profile.get('TeamIdentifier') != [TEAM]:
        problems.append('TeamIdentifier')
    if 'OSX' not in (profile.get('Platform') or []):
        problems.append('Platform')
    if profile.get('ProvisionsAllDevices') is not True or 'ProvisionedDevices' in profile:
        problems.append('not a Developer ID (all-devices) profile')
    expires = profile.get('ExpirationDate')
    now = (datetime.datetime.fromisoformat(args.now) if args.now
           else datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None))
    if not isinstance(expires, datetime.datetime) or expires <= now:
        problems.append('expired or missing ExpirationDate')
    if allowed.get('com.apple.application-identifier') != TEAM + '.' + ident:
        problems.append('application-identifier')
    if allowed.get('com.apple.developer.team-identifier') != TEAM:
        problems.append('team-identifier')
    if allowed.get('get-task-allow') or allowed.get('com.apple.security.get-task-allow'):
        problems.append('get-task-allow')
    if args.signer_sha1:
        digests = {hashlib.sha1(bytes(c)).hexdigest().upper()
                   for c in profile.get('DeveloperCertificates') or []}
        if args.signer_sha1.upper() not in digests:
            problems.append('signing certificate not in profile')
    problems += [line[2:] for line in
                 profile_authorization_diff(expected_entitlements(args.role), allowed)]
    if problems:
        raise Refusal(f'{args.role}: profile refused: ' + '; '.join(problems))
    print(json.dumps({'role': args.role, 'uuid': profile.get('UUID'),
                      'name': profile.get('Name'),
                      'expires': expires.isoformat()}, sort_keys=True))


def cmd_diff_signed(args):
    committed = load_plist(args.entitlements)
    claims = signed_claims(args)
    allowed = decoded_profile(args).get('Entitlements') or {}
    against_committed = dict_diff(committed, claims)
    against_profile = profile_authorization_diff(claims, allowed)
    forbidden = forbidden_claims(claims)
    install = 'com.apple.developer.system-extension.install' in claims
    misplaced = [] if install == (args.role == 'host') else [
        '! com.apple.developer.system-extension.install (wrong role)']
    lines = against_committed + against_profile + forbidden + misplaced
    result = {'role': args.role, 'empty': not lines, 'diff': lines,
              'signed_claims': claims}
    if args.out:
        pathlib.Path(args.out).write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    if lines:
        raise Refusal(f'{args.role}: entitlement diff is not empty\n' + '\n'.join(lines))
    print(f'{args.role}: entitlement diff empty (signed == committed; '
          f'{len([k for k in claims if k not in UNRESTRICTED])} profile-gated claims authorized)')


def cmd_check_signature(args):
    if args.display_text:
        text = pathlib.Path(args.display_text).read_text()
    else:
        result = subprocess.run(['codesign', '-dvv', args.bundle], check=False,
                                capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            raise Refusal('codesign -dvv failed: ' + result.stderr.strip())
        text = result.stdout + result.stderr
    fields = {}
    authorities = []
    for line in text.splitlines():
        key, sep, value = line.partition('=')
        if not sep:
            continue
        if key == 'Authority':
            authorities.append(value)
        else:
            fields.setdefault(key, value)
    problems = []
    if not authorities or not re.fullmatch(
            r'Developer ID Application: .+ \(' + TEAM + r'\)', authorities[0]):
        problems.append(f'Authority={authorities[0] if authorities else None}')
    if authorities[1:3] != ['Developer ID Certification Authority', 'Apple Root CA']:
        problems.append('certificate chain')
    if fields.get('TeamIdentifier') != TEAM:
        problems.append('TeamIdentifier')
    if fields.get('Identifier') != args.identifier:
        problems.append('Identifier')
    flags = fields.get('CodeDirectory v', '')
    if not re.search(r'flags=0x[0-9a-f]+\([^)]*runtime[^)]*\)', flags):
        problems.append('hardened runtime flag')
    if 'Timestamp' not in fields:
        problems.append('secure timestamp')
    if problems:
        raise Refusal(f'{args.identifier}: signature refused: ' + '; '.join(problems))
    print(f'{args.identifier}: Authority={authorities[0]}; runtime; Timestamp={fields["Timestamp"]}')


def mode_problem(name, mode):
    perms = stat.S_IMODE(mode)
    if stat.S_ISLNK(mode):
        return None
    if stat.S_ISDIR(mode):
        return None if perms == 0o755 else f'{name}: directory mode {perms:04o} (want 0755)'
    if stat.S_ISREG(mode):
        return None if perms in (0o644, 0o755) else f'{name}: file mode {perms:04o} (want 0644/0755)'
    return f'{name}: unexpected file type'


def cmd_check_modes(args):
    problems = []
    if args.bundle:
        root = pathlib.Path(args.bundle)
        problems.append(mode_problem(root.name, os.lstat(root).st_mode))
        for directory, dirs, files in os.walk(root):
            for name in dirs + files:
                path = pathlib.Path(directory) / name
                problems.append(mode_problem(str(path.relative_to(root.parent)),
                                             os.lstat(path).st_mode))
        label = root.name
    else:
        with zipfile.ZipFile(args.zip) as archive:
            for info in archive.infolist():
                # --sequesterRsrc AppleDouble sidecars become extended
                # attributes on extraction, never files of the bundle.
                if info.filename.startswith('__MACOSX/'):
                    continue
                mode = info.external_attr >> 16
                if not mode:
                    problems.append(f'{info.filename}: no stored mode')
                    continue
                problems.append(mode_problem(info.filename, mode))
        label = pathlib.Path(args.zip).name
    problems = [p for p in problems if p]
    if problems:
        raise Refusal(f'{label}: non-distributable modes\n' + '\n'.join(problems[:20]))
    print(f'{label}: modes 0755 directories, 0644/0755 files')


def stage_status(stages, name):
    """Latest real status of `name`; 'stale' when an earlier stage reran.

    Dry-run entries never count, so printing commands again cannot block or
    satisfy a gate.
    """
    real = [(i, s) for i, s in enumerate(stages) if s.get('status') != 'dry-run']
    mine = [(i, s) for i, s in real if s['stage'] == name]
    if not mine:
        return ''
    index, latest = mine[-1]
    if latest['status'] != 'ok' or name not in STAGE_ORDER:
        return latest['status']
    earlier = STAGE_ORDER[:STAGE_ORDER.index(name)]
    if any(i > index and s['stage'] in earlier for i, s in real):
        return 'stale'
    return 'ok'


def write_atomic(path, data):
    path = pathlib.Path(path)
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix='.' + path.name + '.')
    try:
        with os.fdopen(fd, 'w') as handle:
            handle.write(json.dumps(data, sort_keys=True, indent=2) + '\n')
        os.replace(temp, path)
    except BaseException:
        os.unlink(temp)
        raise


def cmd_receipt(args):
    path = pathlib.Path(args.receipt)
    if args.create:
        if path.exists():
            raise Refusal(f'receipt {path.name} already exists; retries need a new run id')
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {'schema': 1}
    else:
        data = json.loads(path.read_text())
    for item in args.set or []:
        key, sep, value = item.partition('=')
        if not sep:
            raise Refusal('--set requires KEY=VALUE')
        data[key] = value
    for item in args.set_json or []:
        key, sep, value = item.partition('=')
        if not sep:
            raise Refusal('--set-json requires KEY=JSON')
        data[key] = json.loads(value)
    for item in args.append_json or []:
        key, sep, value = item.partition('=')
        if not sep:
            raise Refusal('--append-json requires KEY=JSON')
        existing = data.setdefault(key, [])
        if not isinstance(existing, list):
            raise Refusal(f'{key} is not a list')
        existing.append(json.loads(value))
    if args.stage:
        data.setdefault('stages', []).append({
            'stage': args.stage, 'status': args.status, 'detail': args.detail,
            'utc': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        })
    if args.get:
        print(data.get(args.get, ''))
        return
    if args.stage_status:
        print(stage_status(data.get('stages', []), args.stage_status))
        return
    write_atomic(path, data)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest='command', required=True)
    for name, func in (('check-version', cmd_check_version),
                       ('ledger-reserve', cmd_ledger_reserve)):
        p = sub.add_parser(name)
        p.add_argument('--receipts-dir', required=True)
        p.add_argument('--ledger-dir', action='append', required=name == 'ledger-reserve')
        p.add_argument('--installed-app')
        p.add_argument('--version', required=True)
        p.set_defaults(func=func)
        if name == 'ledger-reserve':
            p.add_argument('--run-id', required=True)
            p.add_argument('--commit', required=True)
            p.add_argument('--receipt', required=True)
    p = sub.add_parser('compare-version')
    p.add_argument('--new', required=True)
    p.add_argument('--installed', required=True)
    p.set_defaults(func=cmd_compare_version)
    p = sub.add_parser('activation-outcome')
    p.add_argument('--exit-code', required=True)
    p.add_argument('--result-line', required=True,
                   help="the host's last activation_result= line (may be empty)")
    p.set_defaults(func=cmd_activation_outcome)
    p = sub.add_parser('deactivation-outcome')
    p.add_argument('--exit-code', required=True)
    p.add_argument('--result-line', required=True,
                   help="the host's last deactivation_result= line (may be empty)")
    p.set_defaults(func=cmd_deactivation_outcome)
    p = sub.add_parser('filter-outcome')
    p.add_argument('--exit-code', required=True)
    p.add_argument('--result-line', required=True,
                   help="the host's last filter_result= line (may be empty)")
    p.set_defaults(func=cmd_filter_outcome)
    p = sub.add_parser('disarm-weak-host')
    p.add_argument('--app', required=True)
    p.set_defaults(func=cmd_disarm_weak_host)
    p = sub.add_parser('latest-uninstalled')
    p.add_argument('--dir', required=True)
    p.set_defaults(func=cmd_latest_uninstalled)
    for name, func in (('forget-reply', cmd_forget_reply), ('ping-identity', cmd_ping_identity)):
        p = sub.add_parser(name)
        p.add_argument('--line', required=True, help="the host's one JSON stdout line")
        p.set_defaults(func=func)
    p = sub.add_parser('check-modes')
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument('--bundle')
    source.add_argument('--zip')
    p.set_defaults(func=cmd_check_modes)
    p = sub.add_parser('check-committed')
    p.add_argument('--role', choices=('host', 'provider'), required=True)
    p.add_argument('--entitlements', required=True)
    p.set_defaults(func=cmd_check_committed)
    for name, func in (('check-profile', cmd_check_profile), ('diff-signed', cmd_diff_signed)):
        p = sub.add_parser(name)
        p.add_argument('--role', choices=('host', 'provider'), required=True)
        source = p.add_mutually_exclusive_group(required=True)
        source.add_argument('--profile')
        source.add_argument('--decoded-profile')
        p.set_defaults(func=func)
        if name == 'check-profile':
            p.add_argument('--signer-sha1')
            p.add_argument('--now')
        else:
            p.add_argument('--entitlements', required=True)
            signed = p.add_mutually_exclusive_group(required=True)
            signed.add_argument('--bundle')
            signed.add_argument('--signed-xml')
            p.add_argument('--out')
    p = sub.add_parser('check-signature')
    p.add_argument('--identifier', required=True)
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument('--bundle')
    source.add_argument('--display-text')
    p.set_defaults(func=cmd_check_signature)
    p = sub.add_parser('receipt')
    p.add_argument('--receipt', required=True)
    p.add_argument('--create', action='store_true')
    p.add_argument('--set', action='append')
    p.add_argument('--set-json', action='append')
    p.add_argument('--append-json', action='append')
    p.add_argument('--stage')
    p.add_argument('--status', default='ok')
    p.add_argument('--detail', default='')
    p.add_argument('--get')
    p.add_argument('--stage-status')
    p.set_defaults(func=cmd_receipt)
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except Refusal as error:
        print(f'refused: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
