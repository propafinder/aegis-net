#!/usr/bin/env python3
"""Finite Noble classic image verifier; no installed/boot admission here."""
import hashlib
import os
from pathlib import Path
import posixpath
import re
import shutil
import stat
import subprocess
import tempfile

import aegis_initrd_policy as policy


BUILD_HOOK = Path('/etc/initramfs-tools/hooks/zz-aegis-classic-network-policy')
SOURCE_STAMP = Path('/var/lib/aegis-install/initrd-classic-source.json')
BOOT = Path('/boot')
CONFIG_ROOT = Path('/etc/initramfs-tools')
HELPER_LIB = Path('/usr/local/lib/aegis/helpers/lib')
BUILD_HOOK_BYTES = b'''#!/bin/sh
set -eu
case "${1:-}" in prereqs) printf '%s\\n' 'bcache btrfs cloud-initramfs-dyn-netconf console_setup copymods cryptgnupg cryptgnupg-sc cryptkeyctl cryptopensc cryptpassdev cryptroot cryptroot-unlock dhcpcd dmsetup fixrtc flash_kernel_set_root framebuffer fsck fuse iscsi kbd klibc-utils kmod lvm2 mdadm ntfs_3g overlayroot plymouth resume sg3-utils thermal thin-provisioning-tools udev xfs zz-busybox-initramfs'; exit 0;; esac
exec /usr/bin/python3 -I -B /usr/local/lib/aegis/helpers/lib/aegis_initrd_policy.py classic-build "${DESTDIR:?}" "${version:?}"
'''


# The exact local override is independently qualified from the authenticated
# Ubuntu 20260705 image, not from a failed candidate or mutable host digest.
OVERLAY_LOCAL = Path('/etc/overlayroot.local.conf')
OVERLAY_PREPARATION = Path('/var/lib/aegis-install/classic-overlay-preparation.json')
OVERLAY_BACKUP = Path('/var/lib/aegis-install/classic-overlay-before.conf')
OVERLAY_FACTORY = (b'# CLOUD_IMG: This file was created/modified by the Cloud Image build process\n'
                   b'overlayroot_cfgdisk=LABEL=OROOTCFG\n')
OVERLAY_DISABLED = b'overlayroot_cfgdisk="disabled"\noverlayroot=""\n'


def overlay_file(path, mode):
    for parent in (path.parent, *path.parent.parents):
        meta = parent.lstat()
        policy.need(stat.S_ISDIR(meta.st_mode) and meta.st_uid == meta.st_gid == 0 and
            not meta.st_mode & 0o022, 'untrusted classic overlay preparation directory')
    meta = path.lstat()
    policy.need(stat.S_ISREG(meta.st_mode) and meta.st_uid == meta.st_gid == 0 and
        meta.st_nlink == 1 and stat.S_IMODE(meta.st_mode) == mode and meta.st_size <= 4096,
        'untrusted classic overlay preparation file')
    raw = policy.trusted_read(path, 4096)
    after = path.lstat()
    def facts(value):
        return [value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns]
    policy.need(facts(meta) == facts(after), 'classic overlay preparation file changed')
    return raw, facts(meta)


def overlay_journal():
    if not OVERLAY_PREPARATION.exists() and not OVERLAY_PREPARATION.is_symlink():
        return None
    raw, _ = overlay_file(OVERLAY_PREPARATION, 0o600)
    value = policy.decode(raw)
    policy.need(set(value) == {'schema', 'path', 'backup', 'before_sha256', 'after_sha256', 'before', 'phase'} and
        value['schema'] == 'aegis_classic_overlay_preparation_v1' and
        value['path'] == '/etc/overlayroot.local.conf' and
        value['backup'] == '/var/lib/aegis-install/classic-overlay-before.conf' and
        value['before_sha256'] == hashlib.sha256(OVERLAY_FACTORY).hexdigest() and
        value['after_sha256'] == hashlib.sha256(OVERLAY_DISABLED).hexdigest() and
        value['phase'] in ('preparing', 'prepared', 'restoring', 'restored') and
        type(value['before']) is list and len(value['before']) == 5 and
        all(type(item) is int and item >= 0 for item in value['before']),
        'unknown classic overlay preparation journal')
    backup, _ = overlay_file(OVERLAY_BACKUP, 0o600)
    policy.need(backup == OVERLAY_FACTORY, 'classic overlay backup changed')
    return value


def save_overlay_journal(value):
    policy.atomic(OVERLAY_PREPARATION, (policy.json.dumps(value, sort_keys=True) + '\n').encode(), 0o600)


def ordinary_overlay_boundary():
    # A phase word alone cannot authorize re-enabling an external cfgdisk.
    policy.need(all(not path.exists() and not path.is_symlink() for path in owned_policy_files()),
                'classic overlay preparation requires complete boot policy teardown')
    manifest = policy.decode(policy.trusted_read(policy.MANIFEST)) if policy.MANIFEST.exists() else None
    if manifest is not None:
        policy.need(policy.owner_profile(manifest) == policy.CLASSIC_PROFILE and
            manifest.get('phase') in ('rolled_back', 'removed'), 'classic overlay inverse is incomplete')
    kernels = sorted(path.name.removeprefix('vmlinuz-') for path in BOOT.glob('vmlinuz-*'))
    policy.need(kernels and len(kernels) <= 32 and all(policy.KERNEL.fullmatch(k) for k in kernels),
                'classic ordinary kernel inventory unproved')
    for kernel in kernels:
        image = BOOT / ('initrd.img-' + kernel)
        if manifest is not None:
            expected = (manifest.get('uninstall_images', {}).get(kernel) if manifest['phase'] == 'removed'
                else manifest.get('backups', {}).get(kernel, {}).get('sha256'))
            policy.need(type(expected) is str and re.fullmatch('[a-f0-9]{64}', expected) and
                policy.sha_file(image) == expected, 'classic ordinary inverse image differs')
        entries = policy.archive_entries(image, metadata_payloads=frozenset((
            'usr/lib/dracut/modules.txt', 'etc/aegis-initrd-id')))
        policy.need(not any(name in entries for name in ('etc/aegis-initrd-id',
            policy.CLASSIC_GATE_HELPER[1:], policy.CLASSIC_CMDLINE_HELPER[1:])),
            'classic overlay restoration retains a networkless policy image')


def restore_overlay_value(value):
    raw, _ = overlay_file(OVERLAY_LOCAL, 0o644)
    policy.need(raw in (OVERLAY_FACTORY, OVERLAY_DISABLED), 'classic overlay preparation target changed')
    value['phase'] = 'restoring'; save_overlay_journal(value)
    if raw != OVERLAY_FACTORY:
        policy.atomic(OVERLAY_LOCAL, OVERLAY_FACTORY, 0o644)
    policy.need(overlay_file(OVERLAY_LOCAL, 0o644)[0] == OVERLAY_FACTORY, 'classic overlay restoration differs')
    value['phase'] = 'restored'; save_overlay_journal(value)


def prepare_overlay(*, opt_in):
    policy.need(os.geteuid() == 0 and opt_in, 'explicit root --opt-in required for classic preparation')
    policy._cloud_preparation_quiet(Path('/'), policy.command)
    policy.need(policy.detect_local_root()['class'] == 'local_provable', 'classic preparation requires local root')
    ordinary_overlay_boundary()
    value = overlay_journal()
    if not OVERLAY_LOCAL.exists() and not OVERLAY_LOCAL.is_symlink():
        policy.need(value is None, 'classic prepared overlay target disappeared')
        overlay_snapshot(); return dict(phase='not_needed', changed=False)
    raw, generation = overlay_file(OVERLAY_LOCAL, 0o644)
    if value is not None and value['phase'] == 'prepared':
        policy.need(raw == OVERLAY_DISABLED, 'classic prepared overlay target changed')
        overlay_snapshot(); return dict(phase='prepared', changed=False)
    if value is not None and value['phase'] == 'restoring':
        restore_overlay_value(value)
        raw, generation = overlay_file(OVERLAY_LOCAL, 0o644)
    if value is None or value['phase'] == 'restored':
        if raw != OVERLAY_FACTORY:
            policy.need(value is None, 'classic restored overlay target changed')
            overlay_snapshot(); return dict(phase='not_needed', changed=False)
        if value is not None:
            policy.atomic(OVERLAY_PREPARATION.with_name('classic-overlay-history-' + os.urandom(12).hex() + '.json'),
                (policy.json.dumps(value, sort_keys=True) + '\n').encode(), 0o600)
        if OVERLAY_BACKUP.exists() or OVERLAY_BACKUP.is_symlink():
            policy.need(overlay_file(OVERLAY_BACKUP, 0o600)[0] == OVERLAY_FACTORY, 'classic overlay backup changed')
        else:
            policy.atomic(OVERLAY_BACKUP, raw, 0o600)
        value = dict(schema='aegis_classic_overlay_preparation_v1', path='/etc/overlayroot.local.conf',
            backup='/var/lib/aegis-install/classic-overlay-before.conf', before_sha256=hashlib.sha256(raw).hexdigest(),
            after_sha256=hashlib.sha256(OVERLAY_DISABLED).hexdigest(), before=generation, phase='preparing')
        save_overlay_journal(value)
    policy.need(value['phase'] == 'preparing' and raw in (OVERLAY_FACTORY, OVERLAY_DISABLED) and
        (raw == OVERLAY_DISABLED or generation == value['before']), 'classic preparation generation differs')
    try:
        if raw == OVERLAY_FACTORY:
            policy.need(overlay_file(OVERLAY_LOCAL, 0o644) == (raw, generation), 'classic overlay changed before write')
            policy.atomic(OVERLAY_LOCAL, OVERLAY_DISABLED, 0o644)
        overlay_snapshot()
        value['phase'] = 'prepared'; save_overlay_journal(value)
        return dict(phase='prepared', changed=True)
    except BaseException:
        restore_overlay_value(value)
        raise


def restore_overlay(*, opt_in):
    policy.need(os.geteuid() == 0 and opt_in, 'explicit root --opt-in required for classic restoration')
    policy._cloud_preparation_quiet(Path('/'), policy.command)
    ordinary_overlay_boundary()
    value = overlay_journal()
    if value is None:
        return dict(phase='absent', changed=False)
    if value['phase'] == 'restored':
        policy.need(overlay_file(OVERLAY_LOCAL, 0o644)[0] == OVERLAY_FACTORY, 'classic restored overlay target changed')
        return dict(phase='restored', changed=False)
    restore_overlay_value(value)
    return dict(phase='restored', changed=True)


def owned_policy_files():
    # This stamp selects a source-owned generation for migration/removal. It
    # never substitutes for archive, nonce, changed-boot or admission checks.
    source = {'schema': 'aegis_initrd_classic_source_v1', 'profile': policy.CLASSIC_PROFILE,
        'policy_sha256': hashlib.sha256(Path(policy.__file__).read_bytes()).hexdigest(),
        'classic_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    return {BUILD_HOOK: BUILD_HOOK_BYTES,
        SOURCE_STAMP: (policy.json.dumps(source, sort_keys=True) + '\n').encode(),
        policy.HOOK: policy.HOOK_BYTES,
        policy.PREHOOK: policy.HOOK_BYTES.replace(b'kernel-hook', b'kernel-preflight')}


def ensure_helpers():
    """Bootstrap only missing passive source; never overwrite another version."""
    names = ('aegis_initrd_policy.py', 'aegis_initrd_classic.py',
             'aegis_auto_foreign_policy.py', 'aegis_auto_ufw_pins.json')
    sources = {name: policy.trusted_read(policy.HERE / name) for name in names}
    missing = []
    for name, raw in sources.items():
        target = HELPER_LIB / name
        if target.exists() or target.is_symlink():
            try:
                with policy._cloud_parent(Path('/'), str(target)):
                    policy.need(not target.is_symlink() and policy.trusted_read(target) == raw,
                                'classic helpers differ; install the matching client helpers first')
            except OSError as error:
                raise ValueError('untrusted classic helper namespace') from error
        else:
            missing.append(name)
    if missing:
        policy._cloud_preparation_quiet(Path('/'), policy.command)
        for name in missing:
            target = HELPER_LIB / name
            with policy._cloud_parent(Path('/'), str(target), create=True):
                policy.need(not target.exists() and not target.is_symlink(), 'classic helper destination changed')
                policy.atomic(target, sources[name], 0o500)


def build_candidate(kernel, *, nonce):
    policy.need(policy.KERNEL.fullmatch(kernel) and re.fullmatch('[a-f0-9]{64}', nonce),
                'invalid classic candidate identity')
    policy.need(hashlib.sha256(policy.trusted_read('/usr/sbin/mkinitramfs')).hexdigest() ==
        '209dbb330f57bf5f3c60d9dec060d098c751af464077127cd5e69103a4aeb649',
        'unreviewed classic builder source')
    candidate = BOOT / ('.aegis-classic-candidate-' + kernel + '-' + os.urandom(8).hex())
    policy.need(not candidate.exists() and not candidate.is_symlink(), 'classic candidate already exists')
    verify_build_sources()
    build_input_snapshot()
    return run_builder(candidate, kernel, nonce=nonce)


def run_builder(candidate, kernel, *, nonce=None, extra_args=()):
    """Keep ordinary inverse builds as private and diagnosable as apply."""
    # The pinned builder resets its umask to022 before touching the output.
    # Precreate exclusively with0600 so even a refused unverified candidate
    # never becomes readable to other users on the mounted boot filesystem.
    fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    policy.fsync_dir(BOOT)
    logs = Path(tempfile.mkdtemp(prefix='classic-build-', dir=policy.BACKUP))
    policy.fsync_dir(policy.BACKUP)
    # Builder output may contain host configuration. Keep the complete streams
    # private on the guest; only the receipt/path can leave this transaction.
    outcome = {'status': 'interrupted', 'candidate': str(candidate)}
    try:
        with (logs / 'stdout').open('xb') as out, (logs / 'stderr').open('xb') as err:
            try:
                environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
                if nonce is not None:
                    environment['aegis_build_nonce'] = nonce
                result = subprocess.run(['/usr/bin/nice', '-n', '10', '/usr/sbin/mkinitramfs',
                    *extra_args, '-o', str(candidate), kernel],
                    env=environment,
                    stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=300, umask=0o077)
                outcome.update(status='finished', returncode=result.returncode)
            finally:
                out.flush(); os.fsync(out.fileno()); err.flush(); os.fsync(err.fileno())
        policy.need(result.returncode == 0, 'classic build refused; private diagnostics ' + str(logs))
    finally:
        # A forced outer Stop must not erase the diagnostic candidate direntry.
        if candidate.exists() or candidate.is_symlink():
            meta = candidate.lstat()
            policy.need(stat.S_ISREG(meta.st_mode) and meta.st_uid == meta.st_gid == 0 and
                meta.st_nlink == 1 and not meta.st_mode & 0o077 and meta.st_size <= policy.MAX_IMAGE,
                'untrusted classic build candidate')
            with candidate.open('rb') as stream:
                os.fsync(stream.fileno())
            policy.fsync_dir(BOOT)
        policy.atomic(logs / 'result.json', (policy.json.dumps(outcome, sort_keys=True) + '\n').encode(), 0o600)
        policy.fsync_dir(logs)

    return candidate


def boot_snapshot():
    value = policy.boot_snapshot()
    value['classic_overlay_inputs'] = policy.digest(overlay_snapshot())
    value['classic_builder_sources'] = policy.digest(verify_build_sources())
    value['classic_builder_inputs'] = policy.digest(build_input_snapshot())
    files = [path for path in CONFIG_ROOT.rglob('*') if path.is_file()]
    policy.need(len(files) <= 4096, 'classic build policy inventory bound')
    owned = owned_policy_files()
    for path in files:
        if path not in owned:
            value[str(path)] = hashlib.sha256(policy.trusted_read(path)).hexdigest()
    return value


def local_module_baseline(entries, kernel):
    prefix = 'usr/lib/modules/' + kernel + '/'
    modules = {name for name, item in entries.items() if name.startswith(prefix) and
        re.search(r'\.ko(?:\.(?:xz|gz|zst))?$', name) and stat.S_ISREG(item['mode']) and
        not policy.classic_remote_module(name)}
    policy.need(modules and all(policy.classic_local_module(name) for name in modules),
                'classic ordinary local module requires review')
    return modules


def apply(*, opt_in):
    """Durable all-kernel classic transaction; does not authorize this boot."""
    need = policy.need
    need(opt_in and os.geteuid() == 0, 'root and explicit --opt-in required')
    manifest = policy.decode(policy.trusted_read(policy.MANIFEST)) if policy.MANIFEST.exists() else None
    if manifest is not None:
        need(policy.owner_profile(manifest) == policy.CLASSIC_PROFILE, 'another initrd backend owns this host')
    detector = policy.detect_local_root()
    need(policy.command('dpkg-query', '-W', '-f=${Version}', 'initramfs-tools-core').decode().strip() ==
         policy.CLASSIC_REVIEWED_CORE, 'unreviewed classic framework')
    kernels = sorted(path.name.removeprefix('vmlinuz-') for path in BOOT.glob('vmlinuz-*'))
    need(kernels and len(kernels) <= 32 and all(policy.KERNEL.fullmatch(kernel) for kernel in kernels),
         'unsupported classic kernel inventory')
    for kernel in kernels:
        meta = (BOOT / ('initrd.img-' + kernel)).lstat()
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid == meta.st_gid == 0 and
            not meta.st_mode & 0o022 and meta.st_nlink == 1 and meta.st_size <= policy.MAX_IMAGE,
            'untrusted classic original image')
    verify_build_sources()
    build_input_snapshot()
    overlay_snapshot()
    files = owned_policy_files()
    policy._cloud_preparation_quiet(Path('/'), policy.command)
    if manifest is not None and manifest.get('phase') in ('removed', 'rolled_back'):
        policy.verify_ownership(manifest, partial=True)
        need(all(not path.exists() and not path.is_symlink() for path in files),
             'inactive classic history has policy residue')
        history = policy.BACKUP.with_name(policy.BACKUP.name + '-classic-' + manifest['phase'] + '-' + os.urandom(12).hex())
        os.rename(policy.BACKUP, history)
        policy.fsync_dir(policy.BACKUP.parent)
        manifest = None
    if manifest is None:
        need(all(not path.exists() and not path.is_symlink() for path in files),
             'foreign classic policy destination exists')
        need(not policy.BACKUP.exists() or not any(policy.BACKUP.iterdir()), 'orphan classic backup directory')
    else:
        need(manifest.get('phase') in ('building', 'awaiting_reboot', 'active'),
             'classic inverse must finish before another apply')
        policy.verify_ownership(manifest, partial=manifest['phase'] == 'building')
    ensure_helpers()
    policy.BACKUP.mkdir(mode=0o700, parents=True, exist_ok=True)
    meta = policy.BACKUP.lstat()
    need(stat.S_ISDIR(meta.st_mode) and meta.st_uid == meta.st_gid == 0 and
         stat.S_IMODE(meta.st_mode) == 0o700, 'untrusted classic backup directory')
    if manifest is None:
        manifest = dict(schema='aegis_initrd_policy_owner_v1', boot_profile=policy.CLASSIC_PROFILE,
            phase='building', applied_boot_id=policy.current_boot(), detector=detector,
            before=boot_snapshot(), owned=policy.policy_hashes(files), backups={}, images={})
        policy.save_manifest(manifest)
    for path, raw in files.items():
        if not path.exists():
            policy.atomic(path, raw, 0o600 if path == SOURCE_STAMP else 0o755)
    policy.verify_ownership(manifest)
    for kernel in kernels:
        image = BOOT / ('initrd.img-' + kernel)
        record = manifest['images'].get(kernel)
        if record and policy.sha_file(image) == record['sha256']:
            verify_archive(kernel, image, nonce=record['nonce'])
            continue
        original = policy.archive_entries(image, metadata_payloads=frozenset((
            'usr/lib/dracut/modules.txt', 'etc/aegis-initrd-id')))
        prefix = 'usr/lib/modules/' + kernel + '/'
        required = local_module_baseline(original, kernel)
        need(required, 'empty classic non-network module baseline')
        policy.backup_image(image, kernel, manifest)
        nonce = os.urandom(32).hex()
        candidate = build_candidate(kernel, nonce=nonce)
        proof = verify_archive(kernel, candidate, nonce=nonce)
        need(set(proof['kernel_modules']) == required, 'classic candidate loses non-network modules')
        manifest['images'][kernel] = dict(nonce=nonce, sha256=proof['initrd_sha256'],
            original_sha256=manifest['backups'][kernel]['sha256'],
            archive_projection_sha256=proof['archive_projection_sha256'])
        policy.save_manifest(manifest)
        policy.replace_image(candidate, image, proof['initrd_sha256'])
    need(boot_snapshot() == manifest['before'], 'classic build changed unrelated boot policy')
    manifest['phase'] = 'awaiting_reboot'
    policy.save_manifest(manifest)
    return dict(status='reboot_required', boot_profile=policy.CLASSIC_PROFILE,
                kernels=len(kernels), network_in_initrd=False)


def remove_policy(manifest):
    policy.verify_ownership(manifest, partial=True)
    files = owned_policy_files()
    for path in (policy.HOOK, policy.PREHOOK, BUILD_HOOK, SOURCE_STAMP):
        if path.exists() or path.is_symlink():
            policy.need(policy.trusted_read(path) == files[path], 'foreign classic inverse policy')
            path.unlink()
            policy.fsync_dir(path.parent)


def _copy_image(source, destination):
    """Private execution backup, with bounded buffers and durable dirty pages."""
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(source_fd)
        policy.need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and
            before.st_nlink == 1 and not before.st_mode & 0o022 and before.st_size <= policy.MAX_IMAGE,
            'untrusted classic inverse image')
        out_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(out_fd, 'wb') as out:
            pending = total = 0
            while chunk := os.read(source_fd, 1 << 20):
                total += len(chunk)
                policy.need(total <= before.st_size, 'classic inverse source grew')
                out.write(chunk)
                pending += len(chunk)
                if pending >= 32 << 20:
                    out.flush(); os.fsync(out.fileno()); pending = 0
            out.flush(); os.fsync(out.fileno())
        policy.need(total == before.st_size, 'classic inverse source shortened')
        after = os.fstat(source_fd)
        policy.need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                    'classic inverse source changed')
        policy.need(policy.sha_file(source) == policy.sha_file(destination), 'classic inverse copy differs')
        policy.fsync_dir(destination.parent)
    finally:
        os.close(source_fd)


def _inverse_owner(phases):
    manifest = policy.decode(policy.trusted_read(policy.MANIFEST))
    policy.need(policy.owner_profile(manifest) == policy.CLASSIC_PROFILE and
        manifest.get('phase') in phases, 'classic inverse owner or phase unproved')
    policy.verify_ownership(manifest, partial=manifest['phase'] in
        ('building', 'rolling_back', 'uninstalling', 'removed', 'rolled_back'))
    policy._cloud_preparation_quiet(Path('/'), policy.command)
    meta = BOOT.lstat()
    policy.need(stat.S_ISDIR(meta.st_mode) and meta.st_uid == meta.st_gid == 0 and
                not meta.st_mode & 0o022, 'untrusted classic inverse boot directory')
    return manifest


def _restore_grub(manifest):
    changed = False
    if policy.GRUB_REFUSAL.exists():
        policy.need(policy.trusted_read(policy.GRUB_REFUSAL) ==
            b'# AEGIS refused initrd fallback\nGRUB_DEFAULT=saved\n', 'foreign classic fallback policy')
        policy.GRUB_REFUSAL.unlink(); policy.fsync_dir(policy.GRUB_REFUSAL.parent); changed = True
    if manifest.get('grubenv_backup_sha256'):
        raw = policy.trusted_read(policy.BACKUP / 'grubenv.before-refusal')
        policy.need(hashlib.sha256(raw).hexdigest() == manifest['grubenv_backup_sha256'],
                    'classic fallback environment backup differs')
        policy.atomic(BOOT / 'grub/grubenv', raw, 0o600); changed = True
    if changed:
        policy.command('update-grub', timeout=60)


def rollback():
    manifest = _inverse_owner(('building', 'awaiting_reboot', 'active', 'rolling_back', 'rolled_back'))
    backups = manifest.get('backups')
    policy.need(type(backups) is dict and backups and set(manifest.get('images', {})) <= set(backups),
                'classic rollback lacks an original; use complete uninstall regeneration')
    # Authenticate every source before changing the first destination. Journal
    # paths are data: only the fixed per-kernel backup filename may be read.
    for kernel, record in backups.items():
        policy.need(policy.KERNEL.fullmatch(kernel) and type(record) is dict and
            record.get('path') == str(policy.BACKUP / (kernel + '.initrd')) and
            re.fullmatch('[a-f0-9]{64}', record.get('sha256', '')),
            'unknown classic rollback backup')
        path = policy.BACKUP / (kernel + '.initrd')
        meta = path.lstat()
        policy.need(stat.S_ISREG(meta.st_mode) and meta.st_uid == meta.st_gid == 0 and
            meta.st_nlink == 1 and stat.S_IMODE(meta.st_mode) == 0o600 and
            policy.sha_file(path) == record['sha256'], 'classic original backup changed')
    manifest['phase'] = 'rolling_back'; policy.save_manifest(manifest)
    for kernel, record in backups.items():
        candidate = BOOT / ('.aegis-classic-rollback-' + kernel + '-' + os.urandom(8).hex())
        _copy_image(policy.BACKUP / (kernel + '.initrd'), candidate)
        policy.replace_image(candidate, BOOT / ('initrd.img-' + kernel), record['sha256'])
    remove_policy(manifest)
    _restore_grub(manifest)
    manifest['phase'] = 'rolled_back'; policy.save_manifest(manifest)
    return dict(status='rolled_back', network_in_initrd_restored=True, private_backups_retained=True)


def build_normal(kernel, *, isolated=False):
    policy.need(policy.KERNEL.fullmatch(kernel), 'invalid classic normal kernel')
    candidate = BOOT / ('.aegis-classic-normal-' + kernel + '-' + os.urandom(8).hex())
    verify_build_sources()
    build_input_snapshot()
    with tempfile.TemporaryDirectory(prefix='classic-normal-', dir=policy.BACKUP) as temporary:
        extra_args = []
        if isolated:
            config = Path(temporary) / 'conf'
            shutil.copytree(CONFIG_ROOT, config, symlinks=True)
            own_hook = config / BUILD_HOOK.relative_to(CONFIG_ROOT)
            policy.need(not own_hook.is_symlink() and policy.trusted_read(own_hook) == BUILD_HOOK_BYTES,
                        'classic baseline hook ownership differs')
            own_hook.unlink()
            extra_args += ['-d', str(config)]
        return run_builder(candidate, kernel, extra_args=extra_args)



def uninstall():
    if not policy.MANIFEST.exists():
        policy.need(all(not path.exists() and not path.is_symlink() for path in owned_policy_files()),
                    'orphan classic policy; retain guard')
        return dict(status='removed', private_backups_retained=True)
    manifest = _inverse_owner(('building', 'awaiting_reboot', 'active', 'uninstalling', 'removed', 'rolled_back'))
    if manifest['phase'] == 'removed':
        policy.need(all(not path.exists() and not path.is_symlink() for path in owned_policy_files()),
                    'removed classic owner has policy residue')
        return dict(status='removed', network_in_initrd_restored=True, private_backups_retained=True)
    kernels = sorted(path.name.removeprefix('vmlinuz-') for path in BOOT.glob('vmlinuz-*'))
    policy.need(kernels and len(kernels) <= 32 and all(policy.KERNEL.fullmatch(kernel) for kernel in kernels),
                'unsupported classic uninstall kernel inventory')
    manifest['phase'] = 'uninstalling'; policy.save_manifest(manifest)
    remove_policy(manifest)
    restored = manifest.setdefault('uninstall_images', {})
    for kernel in kernels:
        image = BOOT / ('initrd.img-' + kernel)
        if kernel in restored and image.exists() and policy.sha_file(image) == restored[kernel]:
            continue
        current = image if image.exists() else Path(str(image) + '.aegis-refused')
        original = policy.archive_entries(current, metadata_payloads=frozenset((
            'usr/lib/dracut/modules.txt', 'etc/aegis-initrd-id')))
        prefix = 'usr/lib/modules/' + kernel + '/'
        required = local_module_baseline(original, kernel)
        policy.need(required, 'classic uninstall has no non-network module baseline')
        retained = policy.BACKUP / (kernel + '.before-uninstall-' + os.urandom(8).hex())
        _copy_image(current, retained)
        candidate = build_normal(kernel)
        entries = policy.archive_entries(candidate, metadata_payloads=frozenset((
            'usr/lib/dracut/modules.txt', 'etc/aegis-initrd-id')))
        policy.need(not any(name in entries for name in ('etc/aegis-initrd-id',
            policy.CLASSIC_GATE_HELPER[1:], policy.CLASSIC_CMDLINE_HELPER[1:])) and required <= set(entries),
            'ordinary classic regeneration retained owned policy or lost modules')
        restored[kernel] = policy.sha_file(candidate); policy.save_manifest(manifest)
        policy.replace_image(candidate, image, restored[kernel])
        refused = Path(str(image) + '.aegis-refused')
        if refused.exists():
            os.replace(refused, policy.BACKUP / (kernel + '.refused-' + os.urandom(8).hex()))
            policy.fsync_dir(policy.BACKUP)
    _restore_grub(manifest)
    manifest['phase'] = 'removed'; policy.save_manifest(manifest)
    return dict(status='removed', network_in_initrd_restored=True, private_backups_retained=True)


def kernel_preflight(kernel):
    need = policy.need
    need(type(kernel) is str and policy.KERNEL.fullmatch(kernel), 'invalid classic preflight kernel')
    manifest = policy.decode(policy.trusted_read(policy.MANIFEST))
    need(policy.owner_profile(manifest) == policy.CLASSIC_PROFILE and
        manifest.get('phase') in ('awaiting_reboot', 'active'), 'classic transaction is not ready for kernel updates')
    policy.verify_ownership(manifest)
    fallback = []
    for other, record in manifest['images'].items():
        if other != kernel and (BOOT / ('vmlinuz-' + other)).exists() and (BOOT / ('initrd.img-' + other)).exists() and (
                policy.sha_file(BOOT / ('initrd.img-' + other)) == record['sha256']):
            verify_archive(other, BOOT / ('initrd.img-' + other), nonce=record['nonce'])
            fallback.append(other)
    need(fallback, 'classic kernel update requires a verified different-kernel fallback')
    fs = os.statvfs(BOOT)
    need(fs.f_bavail * fs.f_frsize >= 512 << 20, 'classic kernel update lacks boot space')
    detector = policy.detect_local_root()
    overlay_snapshot()
    normal = build_normal(kernel, isolated=True)
    entries = policy.archive_entries(normal, metadata_payloads=frozenset((
        'usr/lib/dracut/modules.txt', 'etc/aegis-initrd-id')))
    prefix = 'usr/lib/modules/' + kernel + '/'
    required = sorted(local_module_baseline(entries, kernel))
    need(required and 'etc/aegis-initrd-id' not in entries, 'ordinary classic kernel baseline unproved')
    if kernel not in manifest['backups']:
        policy.backup_image(normal, kernel, manifest)
    retained = policy.BACKUP / (kernel + '.baseline-' + os.urandom(8).hex() + '.initrd')
    _copy_image(normal, retained)
    manifest.setdefault('kernel_preflight', {})[kernel] = dict(path=str(retained), sha256=policy.sha_file(retained),
        modules=required, fallback=sorted(fallback)[-1])
    manifest['detector'] = detector
    policy.save_manifest(manifest)
    if normal.parent == BOOT and normal.name.startswith('.aegis-classic-normal-'):
        normal.unlink(); policy.fsync_dir(BOOT)
    return dict(status='classic_kernel_preflight_verified', kernel=kernel)


def kernel_hook(kernel):
    need = policy.need
    need(type(kernel) is str and policy.KERNEL.fullmatch(kernel), 'invalid classic kernel hook')
    manifest = policy.decode(policy.trusted_read(policy.MANIFEST))
    need(policy.owner_profile(manifest) == policy.CLASSIC_PROFILE, 'classic kernel owner differs')
    policy.verify_ownership(manifest)
    try:
        need(manifest.get('phase') in ('awaiting_reboot', 'active') and
             type(manifest.get('images')) is dict and type(manifest.get('backups')) is dict and
             type(manifest.get('kernel_preflight', {})) is dict,
             'classic kernel transaction shape or phase differs')
        pending = manifest.get('kernel_preflight', {}).get(kernel)
        image = BOOT / ('initrd.img-' + kernel)
        if pending is None:
            # Package callbacks may be retried after the publication journal
            # was committed. Only the exact fully reverified image is a retry.
            record = manifest['images'].get(kernel)
            need(not manifest.get('deny_reason') and type(record) is dict and
                 type(record.get('sha256')) is str and type(record.get('nonce')) is str and
                 policy.sha_file(image) == record['sha256'],
                 'classic kernel publication has no verified preflight')
            proof = verify_archive(kernel, image, nonce=record['nonce'])
            need(proof['initrd_sha256'] == record['sha256'] and
                 proof['archive_projection_sha256'] == record['archive_projection_sha256'],
                 'classic kernel retry differs from committed projection')
            return dict(status='classic_kernel_verified', kernel=kernel)
        need(type(pending) is dict and set(pending) == {'path', 'sha256', 'modules', 'fallback'},
             'classic kernel publication has no verified preflight')
        prefix = 'usr/lib/modules/' + kernel + '/kernel/'
        need(type(pending['path']) is str and type(pending['sha256']) is str and
             re.fullmatch('[a-f0-9]{64}', pending['sha256']) and
             type(pending['fallback']) is str and policy.KERNEL.fullmatch(pending['fallback']) and
             type(pending['modules']) is list and 0 < len(pending['modules']) <= 65536 and
             all(type(name) is str and name.startswith(prefix) and '..' not in Path(name).parts and
                 re.fullmatch(r'[A-Za-z0-9_/+.-]+\.ko(?:\.(?:xz|gz|zst))?', name)
                 for name in pending['modules']) and
             len(set(pending['modules'])) == len(pending['modules']),
             'classic kernel preflight fields differ')
        baseline = Path(pending['path'])
        need(baseline.parent == policy.BACKUP and re.fullmatch(re.escape(kernel) +
            r'\.baseline-[a-f0-9]{16}\.initrd', baseline.name) and policy.sha_file(baseline) == pending['sha256'],
            'classic kernel baseline changed')
        fallback = pending['fallback']
        need(fallback != kernel and fallback in manifest['images'] and
            (BOOT / ('vmlinuz-' + fallback)).exists() and
            policy.sha_file(BOOT / ('initrd.img-' + fallback)) == manifest['images'][fallback]['sha256'],
            'classic kernel fallback changed')
        policy.detect_local_root()
        metadata = policy.archive_entries(image, metadata_payloads=frozenset((
            'usr/lib/dracut/modules.txt', 'etc/aegis-initrd-id')))
        nonce = metadata.get('etc/aegis-initrd-id', {}).get('data', b'').decode('ascii').strip()
        need(re.fullmatch('[a-f0-9]{64}', nonce), 'classic kernel has no source nonce')
        proof = verify_archive(kernel, image, nonce=nonce)
        need(type(pending['modules']) is list and pending['modules'] and
            set(proof['kernel_modules']) == set(pending['modules']), 'classic kernel loses non-network modules')
        manifest['images'][kernel] = dict(nonce=nonce, sha256=proof['initrd_sha256'],
            original_sha256=manifest['backups'][kernel]['sha256'],
            archive_projection_sha256=proof['archive_projection_sha256'])
        del manifest['kernel_preflight'][kernel]
        manifest.pop('deny_reason', None)
        policy.save_manifest(manifest)
        return dict(status='classic_kernel_verified', kernel=kernel)
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        manifest['deny_reason'] = 'kernel_initrd_unverified'
        policy.save_manifest(manifest)
        policy.quarantine(kernel, manifest)
        return dict(status='classic_kernel_quarantined', kernel=kernel)
# Finite stock Noble roles. Pins were extracted from signature-verified APT
# current (50 archives) and official 20260705 snapshot (19 archives), not from
# the failed R37 candidate. Generated image inputs are qualified separately.
STOCK_ROLES = {
    'etc/console-setup/Uni2-Fixed16.psf.gz': ('/usr/share/consolefonts/Uni2-Fixed16.psf.gz', '7413efb11856a7e1ce437ca9752d3f03000889a93264eca2e2dec2923cbb977e', 4292, 420),
    'etc/lvm/lvm.conf': ('/etc/lvm/lvm.conf', 'ef4955e4c81761bdd6cb37c73c54b80b3a6ce04288baccb2238c05f016d6c91b', 111692, 420),
    'etc/lvm/lvmlocal.conf': ('/etc/lvm/lvmlocal.conf', '6034be4f1d62cadb9fec2e7c5f1a7592f44ef21b2bebc70585eac940f0da6f88', 2299, 420),
    'etc/lvm/profile/cache-mq.profile': ('/etc/lvm/profile/cache-mq.profile', 'd3f840a4d985f67b4d7c98c5ce0639cb775eb93c1810cc17c947c3d924def19a', 531, 420),
    'etc/lvm/profile/cache-smq.profile': ('/etc/lvm/profile/cache-smq.profile', 'e0a300ab3b467c229fe46552ca1e6d3d41eaf198c1d143ff418af27af65af798', 339, 420),
    'etc/lvm/profile/command_profile_template.profile': ('/etc/lvm/profile/command_profile_template.profile', '0e9a8757ceab5b853841b022598b0b26c075aadfbc7e8bb9ba6b5ac696944256', 3020, 420),
    'etc/lvm/profile/lvmdbusd.profile': ('/etc/lvm/profile/lvmdbusd.profile', '3305ee7b92b0cc05e97147cd653719532686036d83d0631100147bec52fe8ba0', 2309, 420),
    'etc/lvm/profile/metadata_profile_template.profile': ('/etc/lvm/profile/metadata_profile_template.profile', '122570662c0cd25c346fffd790278051d5519e5100a879dc92b05e452cba601a', 828, 420),
    'etc/lvm/profile/thin-generic.profile': ('/etc/lvm/profile/thin-generic.profile', '72ce438bf8c5413099187edd317761df1e64b444f76eb6a28df89a0160308fac', 76, 420),
    'etc/lvm/profile/thin-performance.profile': ('/etc/lvm/profile/thin-performance.profile', 'bac3bfcde4b7036dd9b2fe31506f12005871552791fccfdb3b94d3b5156ad2b9', 80, 420),
    'etc/lvm/profile/vdo-small.profile': ('/etc/lvm/profile/vdo-small.profile', '6a1511d72c80b4c8cb86f384c0f60ea0d1a4a74936a591b08068332a4cd8b9da', 563, 420),
    'etc/modprobe.d/mdadm.conf': ('/etc/modprobe.d/mdadm.conf', 'f1e2f3f7d12a9401012b9acb8324f949eb623a58f786536845fd5c70888107be', 379, 420),
    'etc/os-release': ('/usr/lib/os-release', '01af466feb100306498c86aa6bad1815e33036019aa34d4362c20f374ea5c829', 400, 420),
    'scripts/init-bottom/copymods': ('/usr/share/initramfs-tools/scripts/init-bottom/copymods', 'c6990aa8150f0f78f1d421c81e347ce42f01bc88bac1223391b7087908f5e20a', 2069, 493),
    'scripts/init-bottom/lvm2': ('/usr/share/initramfs-tools/scripts/init-bottom/lvm2', '22d0d965834eaadcad8e7c94c3c438cad62c36673e996bdefaeb1e32a1d1cd0f', 370, 493),
    'scripts/init-bottom/plymouth': ('/usr/share/initramfs-tools/scripts/init-bottom/plymouth', '546ee4815ee712aae32b8cd51abee941e6e7946b73d3dc9a124837f22669216f', 190, 493),
    'scripts/init-premount/plymouth': ('/usr/share/initramfs-tools/scripts/init-premount/plymouth', '97fd03b2f1abeb0475367bf0d65004cfa8a1a113cce87795356882aaf4eac18a', 492, 493),
    'scripts/init-top/00_mount_efivarfs': ('/usr/share/initramfs-tools/scripts/init-top/00_mount_efivarfs', '67a9174870da67d416f922e94aca813a54cb5ba0c7c9e1b901b280ecaf9348c4', 281, 493),
    'scripts/init-top/console_setup': ('/usr/share/initramfs-tools/scripts/init-top/console_setup', '891ca7be4f0cafa825a9bef2986641d8e5ab79e274dd7acb151b17376dfd65c2', 3424, 493),
    'scripts/init-top/framebuffer': ('/usr/share/initramfs-tools/scripts/init-top/framebuffer', '97e354dc7b56ef24db5c0227098e1af69e52f941f2870c3f70762a7161aedfe4', 3289, 493),
    'scripts/local-block/cryptroot': ('/usr/share/initramfs-tools/scripts/local-block/cryptroot', 'a0fbd833a8420a18dc0d87ae41325842f1be50604b8bfb1f29abf12ae25b8306', 246, 493),
    'scripts/local-block/mdadm': ('/usr/share/initramfs-tools/scripts/local-block/mdadm', '16d6b28179722b2d68a011d3ea533cd09c90ce562d9ef1592d0aabedfbaa9459', 1206, 493),
    'scripts/local-bottom/cryptgnupg-sc': ('/usr/share/initramfs-tools/scripts/local-bottom/cryptgnupg-sc', '4af31bf99d709441e447bb878160582775f952712725f2024f17de9eca3f13ff', 253, 493),
    'scripts/local-bottom/cryptopensc': ('/usr/share/initramfs-tools/scripts/local-bottom/cryptopensc', 'a797ac8a0eebd5e3a0441ceb63c275b5619dfabedff3839d791a0f72e22629ff', 449, 493),
    'scripts/local-bottom/cryptroot': ('/usr/share/initramfs-tools/scripts/local-bottom/cryptroot', 'bb5859e98734587f7ecde5f6b15b31764de26e2144521c8ecd3390e1f5153ce0', 307, 493),
    'scripts/local-bottom/mdadm': ('/usr/share/initramfs-tools/scripts/local-bottom/mdadm', 'b869c815c88f44df40f61b32f3f61c2aefe8139d354cfe8cb59ba9e95aae84f9', 46, 493),
    'scripts/local-bottom/ntfs_3g': ('/usr/share/initramfs-tools/scripts/local-bottom/ntfs_3g', 'a9fc8e10ba7af2a21513b88f2443c0bfeae129f370e02592776ff31f246b7227', 345, 493),
    'scripts/local-premount/btrfs': ('/usr/share/initramfs-tools/scripts/local-premount/btrfs', '642807af4437aa1c88a764933169a3907b90e8bff4714191b65d56b6a517f49d', 274, 493),
    'scripts/local-premount/ntfs_3g': ('/usr/share/initramfs-tools/scripts/local-premount/ntfs_3g', '1d5253aa05e2fc6ca4cb887296a1b1324b403b27fda74e368995c701336f1c25', 226, 493),
    'scripts/local-top/cryptopensc': ('/usr/share/initramfs-tools/scripts/local-top/cryptopensc', '48387c4868e05dc729d57988b58f195de78906b3e15ad94c5bd2233de7fb01c6', 757, 493),
    'scripts/local-top/cryptroot': ('/usr/share/initramfs-tools/scripts/local-top/cryptroot', '3f1d8179a5543e5f72d1e655598eec101dcf37001798f1f1cb867e9e60216e95', 8011, 493),
    'scripts/panic/console_setup': ('/usr/share/initramfs-tools/scripts/panic/console_setup', '0712fdc62ef261ad646467bc9604dc85c33e514023a84e6af83dc13048353f51', 3405, 493),
    'scripts/panic/plymouth': ('/usr/share/initramfs-tools/scripts/panic/plymouth', '1e0641b5e8d8eebaf74c4da430435f7fce678d3d571da41fab571abfdcdc5400', 174, 493),
    'usr/bin/btrfs': ('/bin/btrfs', '9b1d6997fcab8008d038a6827db68f5688da5cd531b95de10b0f1e91afb99faf', 1060784, 493),
    'usr/bin/cryptroot-unlock': ('/usr/share/cryptsetup/initramfs/bin/cryptroot-unlock', '4a4f0072ca43afeaa14179b6f485e6dacb73db6b83e34c5c262f21f696b06991', 5770, 493),
    'usr/bin/head': ('/usr/bin/head', '0684f563fa5972986eb7ce9dd3af9948ace350e7d1630a0c9d69d27c8e8a042e', 67952, 493),
    'usr/bin/kbd_mode': ('/usr/bin/kbd_mode', '775def8dc12a3abd26f8d3b1ddab6f630a796d7a1e0a83d8ec6c2105331eec25', 68024, 493),
    'usr/bin/loadkeys': ('/usr/bin/loadkeys', '13baa4953fdf90f8a20767848e4ce27bc53c84b714951b3e144ebce74336841b', 265112, 493),
    'usr/bin/ntfs-3g': ('/bin/ntfs-3g', 'ed255009c338c094b8928ad4d4561975d47b10dda7dfe4d7301e6fd3a9f796a1', 199464, 493),
    'usr/bin/plymouth': ('/usr/bin/plymouth', 'd476fa3fbcb6461fbbe8e078ec5d0cea5a70bc7a97693bf069ba3ad0f191dc97', 67672, 493),
    'usr/bin/setfont': ('/usr/bin/setfont', '9f556d8ff6b815e674d72969b0a34cca282b22aad4386161ebedb719b96f8055', 67816, 493),
    'usr/bin/sg_inq': ('/usr/bin/sg_inq', '07baff841f5c891739a42118c9a0020b2f287f665c50b01cd0b666256068dbf8', 142720, 493),
    'usr/bin/sha512sum': ('/usr/bin/sha512sum', '4693b71d9a247957f150adabaa158bd78a3d5b9f919db1609ed29ddfc03b3ec5', 67896, 493),
    'usr/lib/aarch64-linux-gnu/libaio.so.1t64.0.2': ('/usr/lib/aarch64-linux-gnu/libaio.so.1t64.0.2', '34a7d0e9f59834c5d2dfe195e00fa2851f6a4d9873406e6427f85c7f70f60e6f', 67360, 420),
    'usr/lib/aarch64-linux-gnu/libargon2.so.1': ('/usr/lib/aarch64-linux-gnu/libargon2.so.1', '6930483a3efc502e503f95ff7c39182cf32028ed237b4bfe534ed2cb53d35b00', 67352, 420),
    'usr/lib/aarch64-linux-gnu/libbsd.so.0.12.1': ('/usr/lib/aarch64-linux-gnu/libbsd.so.0.12.1', '6c5348ee0e1777f13e148b7492fa311b6f65adb0dc21a001a67ebc18948e6b3e', 133944, 420),
    'usr/lib/aarch64-linux-gnu/libcryptsetup.so.12.10.0': ('/lib/aarch64-linux-gnu/libcryptsetup.so.12.10.0', '3fa65cf0dc477a492b00b1c8a282b6fe00cbdd6f15a2b21c6644254251a07200', 603312, 420),
    'usr/lib/aarch64-linux-gnu/libdevmapper-event.so.1.02.1': ('/usr/lib/aarch64-linux-gnu/libdevmapper-event.so.1.02.1', 'b39f79090e501f37e6a3e73011eb85810dcdff4f33333dbefaf105ef91ad325b', 67464, 420),
    'usr/lib/aarch64-linux-gnu/libdevmapper.so.1.02.1': ('/usr/lib/aarch64-linux-gnu/libdevmapper.so.1.02.1', 'cefc3ee497db3d24bc5f3d79e9ab179512d2102af92e4ac4755dd1feb1a8d01e', 471280, 420),
    'usr/lib/aarch64-linux-gnu/libdrm.so.2.125.0': ('/usr/lib/aarch64-linux-gnu/libdrm.so.2.125.0', 'efa8992c21c657acb37e3fa63653161b53a9d73a0828851c9b725fa5e35cadf3', 133616, 420),
    'usr/lib/aarch64-linux-gnu/libedit.so.2.0.72': ('/usr/lib/aarch64-linux-gnu/libedit.so.2.0.72', '75eadb6987cba7386d6b3c41e29155aea0a94f35bc5b01293b8bdaabbe3b81f8', 265352, 420),
    'usr/lib/aarch64-linux-gnu/libevdev.so.2.3.0': ('/usr/lib/aarch64-linux-gnu/libevdev.so.2.3.0', '3e84086841ce470bdcdfc13d273aa6ee5e9ec0610b2d0934a6e5d1f84c72dc04', 133080, 420),
    'usr/lib/aarch64-linux-gnu/libexpat.so.1.9.1': ('/usr/lib/aarch64-linux-gnu/libexpat.so.1.9.1', 'f53b44564070acc56dcae4af78869a7c1338a9a818b1a71015afd388f23c66bd', 198712, 420),
    'usr/lib/aarch64-linux-gnu/libfuse3.so.3.14.0': ('/lib/aarch64-linux-gnu/libfuse3.so.3.14.0', 'da6a2acb7de4dfaf3cf09d4772311e5c9f4d3a76b7415d1a2346b0f3903086c6', 264248, 420),
    'usr/lib/aarch64-linux-gnu/libgcrypt.so.20.4.3': ('/usr/lib/aarch64-linux-gnu/libgcrypt.so.20.4.3', 'fab6cc79218fb1af1327af5bb25d41d165b7a2185cc3852c8682805816182ed4', 1000536, 420),
    'usr/lib/aarch64-linux-gnu/libgpg-error.so.0.34.0': ('/usr/lib/aarch64-linux-gnu/libgpg-error.so.0.34.0', 'ff2dccba4993ef97775b70c1ed1144f70dfe8581ee48c1eb25c76878c6cdfdf7', 198648, 420),
    'usr/lib/aarch64-linux-gnu/libjson-c.so.5.3.0': ('/usr/lib/aarch64-linux-gnu/libjson-c.so.5.3.0', '773990495f98a200f449dc915a14709007ce4b09f41d08c8e46c8d04082df35b', 133288, 420),
    'usr/lib/aarch64-linux-gnu/liblz4.so.1.9.4': ('/usr/lib/aarch64-linux-gnu/liblz4.so.1.9.4', 'd1482a2f74152881d8b83708fedae7bca039f5608024f1178dc21a17df9887a7', 133136, 420),
    'usr/lib/aarch64-linux-gnu/liblzo2.so.2.0.0': ('/lib/aarch64-linux-gnu/liblzo2.so.2.0.0', '57646708f4c971e6745821eaca7b83d336c3702b2d704ab484957b4f2655538a', 132968, 420),
    'usr/lib/aarch64-linux-gnu/libm.so.6': ('/usr/lib/aarch64-linux-gnu/libm.so.6', 'd5b262e559d38769e4959f036a1cc2c4009fa60b4ec836a7a19ca8554aebf5a5', 591800, 420),
    'usr/lib/aarch64-linux-gnu/libmd.so.0.1.0': ('/usr/lib/aarch64-linux-gnu/libmd.so.0.1.0', '30d117046ce9405745e0d0d4722cff121f532913180bbb9425b38d076319ac08', 67584, 420),
    'usr/lib/aarch64-linux-gnu/libmount.so.1.1.0': ('/usr/lib/aarch64-linux-gnu/libmount.so.1.1.0', '507b07264482e5e29171d9bf202abcac55ce85d0eb5d8b7100f07f1081578a63', 330272, 420),
    'usr/lib/aarch64-linux-gnu/libntfs-3g.so.89.0.0': ('/lib/aarch64-linux-gnu/libntfs-3g.so.89.0.0', 'b6aff1396db4f12230b40a32077851860ccff25c1fec67a1a1d0d94193120af5', 395728, 420),
    'usr/lib/aarch64-linux-gnu/libply-splash-core.so.5.0.0': ('/usr/lib/aarch64-linux-gnu/libply-splash-core.so.5.0.0', '8ef5fb6bdfca4161e80f22e4e5737c6842844cb36a78748dbd078d312b92ab9b', 200704, 420),
    'usr/lib/aarch64-linux-gnu/libply.so.5.0.0': ('/usr/lib/aarch64-linux-gnu/libply.so.5.0.0', 'fdfe712d784e1ab42d850eb14dd6a1020802dd5ad970edfe4ec2982aa2437860', 133824, 420),
    'usr/lib/aarch64-linux-gnu/libpopt.so.0.0.2': ('/usr/lib/aarch64-linux-gnu/libpopt.so.0.0.2', '3161e2e8b4fae8d4752757260ffc106a1124dee4c8548e967bec0dd0acb7996c', 67952, 420),
    'usr/lib/aarch64-linux-gnu/libsgutils2-1.46.so.2.0.0': ('/usr/lib/aarch64-linux-gnu/libsgutils2-1.46.so.2.0.0', '0fbf6fc0fd47a2f1bc66b69b325444e8aac5b7a6c3f55035397a1b4db563d517', 288792, 420),
    'usr/lib/aarch64-linux-gnu/libsmartcols.so.1.1.0': ('/usr/lib/aarch64-linux-gnu/libsmartcols.so.1.1.0', '85807f726a16e9afac0e35efdf3b6263ff9101658618ca3df1d8f85f221707cc', 133048, 420),
    'usr/lib/aarch64-linux-gnu/libstdc++.so.6.0.33': ('/usr/lib/aarch64-linux-gnu/libstdc++.so.6.0.33', '6e3112d35cfc86db7ee85b27e1746f67408e2837ff8628b46386c3eabd5682a4', 2633224, 420),
    'usr/lib/aarch64-linux-gnu/libsystemd.so.0.38.0': ('/usr/lib/aarch64-linux-gnu/libsystemd.so.0.38.0', '2c6bab36774ce8a23c3dc87680198364534557c134b625ec3e114fa7266e0b10', 989464, 420),
    'usr/lib/aarch64-linux-gnu/libuuid.so.1.3.0': ('/usr/lib/aarch64-linux-gnu/libuuid.so.1.3.0', '4ae9357729a51e478bdb3c94f89466073c6250c00815c7b713f790b24011b252', 67576, 420),
    'usr/lib/aarch64-linux-gnu/libxkbcommon.so.0.0.0': ('/usr/lib/aarch64-linux-gnu/libxkbcommon.so.0.0.0', '1dc9466c1328e7bf5dc2f46cc454e68800b950325572f48a81902af8d5c25aa0', 330088, 420),
    'usr/lib/aarch64-linux-gnu/libz.so.1.3': ('/usr/lib/aarch64-linux-gnu/libz.so.1.3', '170380b4e7ab28ec86eb090b48df90f84089392cb72fecd5067e5b7a4dc5239f', 133272, 420),
    'usr/lib/aarch64-linux-gnu/plymouth/details.so': ('/usr/lib/aarch64-linux-gnu/plymouth/details.so', '41a7bd4f8ba57e02a5baa0a195c307c0479aa42e83d5b41c10db89eba9cfb8af', 68048, 420),
    'usr/lib/aarch64-linux-gnu/plymouth/renderers/drm.so': ('/usr/lib/aarch64-linux-gnu/plymouth/renderers/drm.so', 'bf6e501b70f3b8bb1f0bd3907cb8d11e22989731f0b71cfedfb913c35cdb1c40', 68680, 420),
    'usr/lib/aarch64-linux-gnu/plymouth/renderers/frame-buffer.so': ('/usr/lib/aarch64-linux-gnu/plymouth/renderers/frame-buffer.so', '28197938d3bb5862591dbb55bbf844d88adc60a328ba01e51f7b72848a361501', 68440, 420),
    'usr/lib/aarch64-linux-gnu/plymouth/text.so': ('/usr/lib/aarch64-linux-gnu/plymouth/text.so', 'f54178d4b8e2d81d75d34b5050a69a5c98de48dcb729046c5f733389c6c37866', 68184, 420),
    'usr/lib/aarch64-linux-gnu/plymouth/ubuntu-text.so': ('/usr/lib/aarch64-linux-gnu/plymouth/ubuntu-text.so', 'eaaec6217d9c73c6b38c7728d5c2749be002e5546b07f94e2c1443861ff9dbfb', 68016, 420),
    'usr/lib/cryptsetup/askpass': ('/lib/cryptsetup/askpass', 'c5dc94728f9f453e56660283d0e7726f9ea102f676863154ea38f3564017c6e6', 67832, 493),
    'usr/lib/cryptsetup/functions': ('/lib/cryptsetup/functions', '6e249a509309933089fc39fc8ddbcd95c50abe8fdb09f210a4eb3f0b9afcfdde', 27319, 420),
    'usr/lib/udev/bcache-export-cached': ('/usr/lib/udev/bcache-export-cached', 'fdfbe26c548f150ab186587c0ab814b29a8163a17fe4261ce5f2b490ecaf6099', 1155, 493),
    'usr/lib/udev/bcache-register': ('/usr/lib/udev/bcache-register', 'ce0a4fa622529aef363841b0df7074e2d917cf813b514ccf232b8bf5a1ec5958', 67672, 493),
    'usr/lib/udev/probe-bcache': ('/usr/lib/udev/probe-bcache', '2e760d9fdec99f18ae21f6daa303ba8d7c91b3bbd9e326e4241a4607afeeedeb', 67672, 493),
    'usr/lib/udev/rules.d/55-dm.rules': ('/usr/lib/udev/rules.d/55-dm.rules', 'c3fd84a8b465ffdcb9768ff8297ba308ae240cf812640f78162fb55b6854dccd', 7282, 420),
    'usr/lib/udev/rules.d/55-scsi-sg3_id.rules': ('/usr/lib/udev/rules.d/55-scsi-sg3_id.rules', '92e699f8c8240023cbe3b992c288e26af3e784db1777dc98ac0754329aa3475e', 6664, 420),
    'usr/lib/udev/rules.d/56-lvm.rules': ('/usr/lib/udev/rules.d/56-lvm.rules', '4107716d0cb0b46a62091a21e2f10443f4347d6a71935d2f2deaf75e81826ab9', 2424, 420),
    'usr/lib/udev/rules.d/58-scsi-sg3_symlink.rules': ('/usr/lib/udev/rules.d/58-scsi-sg3_symlink.rules', 'e657c4eb3b51f83231115f2b8ee0a0a2e3a6503cda7a31e21b63417643a585ca', 2863, 420),
    'usr/lib/udev/rules.d/60-persistent-storage-dm.rules': ('/usr/lib/udev/rules.d/60-persistent-storage-dm.rules', '31a088ec6e41872ad4ab3d6781bb419ea2aa270826475e9055229ac85d6ecdf0', 1964, 420),
    'usr/lib/udev/rules.d/63-md-raid-arrays.rules': ('/lib/udev/rules.d/63-md-raid-arrays.rules', 'dac8eaa0f059e71c1c19d9c1e62f7209cdccb3d53233b0f0abca5d62ba7c2627', 2611, 420),
    'usr/lib/udev/rules.d/64-btrfs-dm.rules': ('/usr/lib/udev/rules.d/64-btrfs-dm.rules', 'ba9da67a41dce05c3b9606dac86fd514e41635b0280371df1f46046a3ae485ee', 387, 420),
    'usr/lib/udev/rules.d/64-btrfs.rules': ('/usr/lib/udev/rules.d/64-btrfs.rules', 'a4bc67740cd0988415907b0fdb5e9cd955be2626b5095b55c7eed4aa4e99bb53', 616, 420),
    'usr/lib/udev/rules.d/64-md-raid-assembly.rules': ('/lib/udev/rules.d/64-md-raid-assembly.rules', 'aa38af1505f51abf054c92ed9497a5c72d53b9c14288900db26d0dd47d8577ab', 1851, 420),
    'usr/lib/udev/rules.d/69-bcache.rules': ('/usr/lib/udev/rules.d/69-bcache.rules', '74a317af45465004b4f7d0abb313f85c3b3fc7bb67bae16a3c11b8718891fcd3', 1044, 420),
    'usr/lib/udev/rules.d/69-lvm.rules': ('/usr/lib/udev/rules.d/69-lvm.rules', '0ec4b37fce745eccb21e58de1cc342ba953bd61f13a7b18c6ea3d12b484c0517', 3571, 420),
    'usr/lib/udev/rules.d/95-dm-notify.rules': ('/usr/lib/udev/rules.d/95-dm-notify.rules', '2bbb8e2eded56b6fc80d7f0d8235c17a352d84301b0a81a21370d8a04b01a59e', 479, 420),
    'usr/libexec/plymouth/plymouthd-fd-escrow': ('/usr/libexec/plymouth/plymouthd-fd-escrow', '068aa1c58caaf03d1e7293e47b53c15d7880ee27ba8a064768ffaef10527b869', 67672, 493),
    'usr/sbin/cryptsetup': ('/sbin/cryptsetup', '9adb1337a36f2fb2c7f3d7301f6a367d26d7b34829da5a84a2ba27dc12097ff2', 288360, 493),
    'usr/sbin/dmsetup': ('/usr/sbin/dmsetup', 'f357fb001a933990640c0fc7ff99653c8ed5b430a31d268e1709b8baffc21252', 203448, 493),
    'usr/sbin/e2fsck': ('/usr/sbin/e2fsck', 'e08e5d3c172369356a92c5f20f28260bba5b7ae35726144e5bdf83383dee026a', 413720, 493),
    'usr/sbin/fsck': ('/usr/sbin/fsck', '2f364d51c8cdff55192f7874d5f879a44267d9e9d79fce35a17fdee0acba356a', 67792, 493),
    'usr/sbin/logsave': ('/usr/sbin/logsave', '9e2ad3589bdfb508165203d88b635de0717732d26e5fc281d70996ecd66f000e', 67520, 493),
    'usr/sbin/lvm': ('/usr/sbin/lvm', '987de8fca36168ca8c95361b4517112e9e3cd265bd732d299ec848fcdcfb2d9f', 3196312, 493),
    'usr/sbin/mdadm': ('/sbin/mdadm', '9c21a041d17b07896c95468f1f7607e0a1e4e9f534d6bc4b1de2e98ecd142583', 620320, 493),
    'usr/sbin/mdmon': ('/sbin/mdmon', 'b9066e95ec179f34d78b036517bd1a87cc8d530316d7e00b19a97db1a817bd35', 268784, 493),
    'usr/sbin/mke2fs': ('/usr/sbin/mke2fs', '84419f91298e173cf1569b3a9c957c9f3e26a28852a6025800ed9e0cd9227ea2', 133512, 493),
    'usr/sbin/mount.fuse3': ('/sbin/mount.fuse3', '0a1d2be490552188d81a4f0ff385278e2c8522820345e7208a96395dfec741ae', 67736, 493),
    'usr/sbin/pdata_tools': ('/usr/sbin/pdata_tools', '07503cf5f8dc5f872c751ef50b458db6b1ac911264ee80b94267a1892b419871', 1448800, 493),
    'usr/sbin/plymouthd': ('/usr/sbin/plymouthd', 'faff5159451bf0af9fa3a5d60da357bdc3276aeae365a98b6eda6ddf5abb5f88', 199056, 493),
    'usr/sbin/wipefs': ('/usr/sbin/wipefs', '994010c8a300255bdad9c942d0beba933f9a65de2ab0b2d7eb56e6e04a81db3e', 67744, 493),
    'usr/share/plymouth/themes/details/details.plymouth': ('/usr/share/plymouth/themes/details/details.plymouth', 'cbaa2bd034af419ffa9db2baaaceab76a0b858c34e38a157d20a56bd8f938502', 84, 420),
    'usr/share/plymouth/themes/text/text.plymouth': ('/usr/share/plymouth/themes/text/text.plymouth', 'f4dab831263ad4447449891918b98289c888612ed24185ef3129d05ba658046d', 94, 420),
    'usr/share/plymouth/themes/ubuntu-text/ubuntu-text.plymouth.in': ('/usr/share/plymouth/themes/ubuntu-text/ubuntu-text.plymouth.in', 'cad48268f9d8b89d3c26d432c8462c0054d7b44ed2b62f778dbe7ad452ee1155', 209, 420),
}

STOCK_ALIASES = {
    'usr/lib/aarch64-linux-gnu/libaio.so.1t64': ('/usr/lib/aarch64-linux-gnu/libaio.so.1t64', 'libaio.so.1t64.0.2'),
    'usr/lib/aarch64-linux-gnu/libbsd.so.0': ('/usr/lib/aarch64-linux-gnu/libbsd.so.0', 'libbsd.so.0.12.1'),
    'usr/lib/aarch64-linux-gnu/libcryptsetup.so.12': ('/lib/aarch64-linux-gnu/libcryptsetup.so.12', 'libcryptsetup.so.12.10.0'),
    'usr/lib/aarch64-linux-gnu/libdrm.so.2': ('/usr/lib/aarch64-linux-gnu/libdrm.so.2', 'libdrm.so.2.125.0'),
    'usr/lib/aarch64-linux-gnu/libedit.so.2': ('/usr/lib/aarch64-linux-gnu/libedit.so.2', 'libedit.so.2.0.72'),
    'usr/lib/aarch64-linux-gnu/libevdev.so.2': ('/usr/lib/aarch64-linux-gnu/libevdev.so.2', 'libevdev.so.2.3.0'),
    'usr/lib/aarch64-linux-gnu/libexpat.so.1': ('/usr/lib/aarch64-linux-gnu/libexpat.so.1', 'libexpat.so.1.9.1'),
    'usr/lib/aarch64-linux-gnu/libfuse3.so.3': ('/lib/aarch64-linux-gnu/libfuse3.so.3', 'libfuse3.so.3.14.0'),
    'usr/lib/aarch64-linux-gnu/libgcrypt.so.20': ('/usr/lib/aarch64-linux-gnu/libgcrypt.so.20', 'libgcrypt.so.20.4.3'),
    'usr/lib/aarch64-linux-gnu/libgpg-error.so.0': ('/usr/lib/aarch64-linux-gnu/libgpg-error.so.0', 'libgpg-error.so.0.34.0'),
    'usr/lib/aarch64-linux-gnu/libjson-c.so.5': ('/usr/lib/aarch64-linux-gnu/libjson-c.so.5', 'libjson-c.so.5.3.0'),
    'usr/lib/aarch64-linux-gnu/liblz4.so.1': ('/usr/lib/aarch64-linux-gnu/liblz4.so.1', 'liblz4.so.1.9.4'),
    'usr/lib/aarch64-linux-gnu/liblzo2.so.2': ('/lib/aarch64-linux-gnu/liblzo2.so.2', 'liblzo2.so.2.0.0'),
    'usr/lib/aarch64-linux-gnu/libmd.so.0': ('/usr/lib/aarch64-linux-gnu/libmd.so.0', 'libmd.so.0.1.0'),
    'usr/lib/aarch64-linux-gnu/libmount.so.1': ('/usr/lib/aarch64-linux-gnu/libmount.so.1', 'libmount.so.1.1.0'),
    'usr/lib/aarch64-linux-gnu/libntfs-3g.so.89': ('/lib/aarch64-linux-gnu/libntfs-3g.so.89', 'libntfs-3g.so.89.0.0'),
    'usr/lib/aarch64-linux-gnu/libply-splash-core.so.5': ('/usr/lib/aarch64-linux-gnu/libply-splash-core.so.5', 'libply-splash-core.so.5.0.0'),
    'usr/lib/aarch64-linux-gnu/libply.so.5': ('/usr/lib/aarch64-linux-gnu/libply.so.5', 'libply.so.5.0.0'),
    'usr/lib/aarch64-linux-gnu/libpopt.so.0': ('/usr/lib/aarch64-linux-gnu/libpopt.so.0', 'libpopt.so.0.0.2'),
    'usr/lib/aarch64-linux-gnu/libsgutils2-1.46.so.2': ('/usr/lib/aarch64-linux-gnu/libsgutils2-1.46.so.2', 'libsgutils2-1.46.so.2.0.0'),
    'usr/lib/aarch64-linux-gnu/libsmartcols.so.1': ('/usr/lib/aarch64-linux-gnu/libsmartcols.so.1', 'libsmartcols.so.1.1.0'),
    'usr/lib/aarch64-linux-gnu/libstdc++.so.6': ('/usr/lib/aarch64-linux-gnu/libstdc++.so.6', 'libstdc++.so.6.0.33'),
    'usr/lib/aarch64-linux-gnu/libsystemd.so.0': ('/usr/lib/aarch64-linux-gnu/libsystemd.so.0', 'libsystemd.so.0.38.0'),
    'usr/lib/aarch64-linux-gnu/libuuid.so.1': ('/usr/lib/aarch64-linux-gnu/libuuid.so.1', 'libuuid.so.1.3.0'),
    'usr/lib/aarch64-linux-gnu/libxkbcommon.so.0': ('/usr/lib/aarch64-linux-gnu/libxkbcommon.so.0', 'libxkbcommon.so.0.0.0'),
    'usr/lib/aarch64-linux-gnu/libz.so.1': ('/usr/lib/aarch64-linux-gnu/libz.so.1', 'libz.so.1.3'),
    'usr/sbin/cache_check': ('/usr/sbin/cache_check', 'pdata_tools'),
    'usr/sbin/fsck.ext4': ('/usr/sbin/fsck.ext4', 'e2fsck'),
    'usr/sbin/mount.ntfs': ('/sbin/mount.ntfs', 'mount.ntfs-3g'),
    'usr/sbin/mount.ntfs-3g': ('/sbin/mount.ntfs-3g', '/bin/ntfs-3g'),
    'usr/sbin/thin_check': ('/usr/sbin/thin_check', 'pdata_tools'),
    'usr/sbin/vgchange': ('/usr/sbin/vgchange', 'lvm'),
}

STOCK_BUILD_SOURCES = {
    '/etc/cryptsetup-initramfs/conf-hook': ('cryptsetup-initramfs:all=2:2.7.0-1ubuntu4.2', 'ae5eeebdd2c309fe9f82140fcd72efbf1113a09010ee236fda87fa0c72662c3f', 1644, 420),
    '/etc/initramfs-tools/initramfs.conf': ('initramfs-tools-core:all=0.142ubuntu25.8', 'e8dd8ab00c5c23384e388bcfe98c37fc3b5ee4beaf13f1194ac8545e7695243a', 1502, 420),
    '/lib/cryptsetup/functions': ('cryptsetup:arm64=2:2.7.0-1ubuntu4.2', '6e249a509309933089fc39fc8ddbcd95c50abe8fdb09f210a4eb3f0b9afcfdde', 27319, 420),
    '/usr/sbin/mkinitramfs': ('initramfs-tools-core:all=0.142ubuntu25.8', '209dbb330f57bf5f3c60d9dec060d098c751af464077127cd5e69103a4aeb649', 15762, 493),
    '/usr/share/flash-kernel/db/all.db': ('flash-kernel:arm64=3.107ubuntu13~24.04.6', '5a1f68cd23f859563622401e46fb10bbd253521fb20adc67cbd96793e7100256', 74929, 420),
    '/usr/share/flash-kernel/functions': ('flash-kernel:arm64=3.107ubuntu13~24.04.6', 'd248173b6f599d9b565b3f486928acaa9ed8c54a5cfab2310cb8b94021673206', 41553, 420),
    '/usr/share/initramfs-tools/conf-hooks.d/busybox-initramfs': ('busybox-initramfs:arm64=1:1.36.1-6ubuntu3.1', '1b0e7766679ffc515cd82fc4bd7cebb940fac6aa7c4f71cfa53cf7410d343cb5', 40, 420),
    '/usr/share/initramfs-tools/conf-hooks.d/cryptsetup': ('cryptsetup-initramfs:all=2:2.7.0-1ubuntu4.2', '52278458942c4e152127b687dba7bf1ca96b03d8fa692fa4f479a4ff0d87bdb1', 221, 420),
    '/usr/share/initramfs-tools/conf-hooks.d/overlayroot': ('overlayroot:all=0.49~24.04.1', '61632c098169f51028d2bc87e3e1f0ee946fad5bdec769fea18ab71326cb0b33', 20, 420),
    '/usr/share/initramfs-tools/conf-hooks.d/plymouth': ('plymouth:arm64=24.004.60-1ubuntu7.1', '66f8286e2a9623a417c8263d26db337e2ef8305ae70d64f0316a3f364ed8ef4b', 117, 420),
    '/usr/share/initramfs-tools/hook-functions': ('initramfs-tools-core:all=0.142ubuntu25.8', '500c8dea2feb1f393c60121a819bae5a0584bc8a824c6e29a3e388a22d231ea8', 28935, 420),
    '/usr/share/initramfs-tools/hooks/bcache': ('bcache-tools:arm64=1.0.8-5build1', '03e0bf51d5df0a507d7347ec816e917ab5f074a6a1da3ae2789303581de76ec4', 543, 493),
    '/usr/share/initramfs-tools/hooks/btrfs': ('btrfs-progs:arm64=6.6.3-1.1build2', '695a9e48c9af29c0e3802ce0defaab3e20fb5b36a561397174cf215ffafc60f5', 701, 493),
    '/usr/share/initramfs-tools/hooks/cloud-initramfs-dyn-netconf': ('cloud-initramfs-dyn-netconf:all=0.49~24.04.1', '9335570d051143281b5dcc4360d56a3c585bb8bf88a4be7025b4c9e380846417', 118, 493),
    '/usr/share/initramfs-tools/hooks/console_setup': ('keyboard-configuration:all=1.226ubuntu1', 'a225e852daa52d67e7b5bda47db4f76b92338f66f109338efa1f4052ec309cd8', 3142, 493),
    '/usr/share/initramfs-tools/hooks/copymods': ('cloud-initramfs-copymods:all=0.49~24.04.1', 'db3451057603c1a98b4e714aaa079b4d9d91caa529e16f83c6b066698618c073', 280, 493),
    '/usr/share/initramfs-tools/hooks/cryptgnupg': ('cryptsetup-initramfs:all=2:2.7.0-1ubuntu4.2', 'b7fc3319a66b7bcbeff25f0f4c9ece17a1d88a4318f8409f5a5385a6e02a2a3d', 958, 493),
    '/usr/share/initramfs-tools/hooks/cryptgnupg-sc': ('cryptsetup-initramfs:all=2:2.7.0-1ubuntu4.2', '0c60482edf85586d476dfa4b0cb00e6caa7c5589f7e2c289ae73339fe43953c2', 2462, 493),
    '/usr/share/initramfs-tools/hooks/cryptkeyctl': ('cryptsetup-initramfs:all=2:2.7.0-1ubuntu4.2', 'ca4a9fddfaabe4135abb8b4789b0ba6cbd49012e6e86c4613d9d95160acb7d4d', 457, 493),
    '/usr/share/initramfs-tools/hooks/cryptopensc': ('cryptsetup-initramfs:all=2:2.7.0-1ubuntu4.2', 'e7d05a9aaf543ca1202f4f4ce95f67ee2dcc3173c7d802251662e37810565ed0', 1518, 493),
    '/usr/share/initramfs-tools/hooks/cryptpassdev': ('cryptsetup-initramfs:all=2:2.7.0-1ubuntu4.2', 'c69ced3819ceef774cbbcb2796c6cf894b2d149be6334d2052a93f4eb233e84a', 888, 493),
    '/usr/share/initramfs-tools/hooks/cryptroot': ('cryptsetup-initramfs:all=2:2.7.0-1ubuntu4.2', '0e2c34368dc23dd453ecf697103da729112e040fd5c4ca40723b0dac4ab15dec', 16009, 493),
    '/usr/share/initramfs-tools/hooks/cryptroot-unlock': ('cryptsetup-initramfs:all=2:2.7.0-1ubuntu4.2', '83db78067337c58499ace67499a1fccb13aaf2be217c89df547f951f83c74674', 1010, 493),
    '/usr/share/initramfs-tools/hooks/dhcpcd': ('initramfs-tools-core:all=0.142ubuntu25.8', 'e5a9536fae14baf1d3a470a21774d54121a77c6dbfc9fb81d53905b9fec32317', 1335, 493),
    '/usr/share/initramfs-tools/hooks/dmsetup': ('dmsetup:arm64=2:1.02.185-3ubuntu3.2', '8c9a691182d41332370761de382d26e8f71944c2e6cf17b929b699fc264341e7', 506, 493),
    '/usr/share/initramfs-tools/hooks/fixrtc': ('initramfs-tools-core:all=0.142ubuntu25.8', 'e8b27bb8211ad1d9dfd5fa51093d03acdeae519e87ba2a7ba805fdfce09afe4d', 436, 493),
    '/usr/share/initramfs-tools/hooks/flash_kernel_set_root': ('flash-kernel:arm64=3.107ubuntu13~24.04.6', 'bc2edf903bbbd2ddcc6f06abd1e89e42df641fd9d6120261a328da29300f3868', 4441, 493),
    '/usr/share/initramfs-tools/hooks/framebuffer': ('initramfs-tools-core:all=0.142ubuntu25.8', 'bee0e54ca4da4a5c45ce7583ed025e3e00bde3c17d797f0dd5a1894ba9d96b2e', 386, 493),
    '/usr/share/initramfs-tools/hooks/fsck': ('initramfs-tools-core:all=0.142ubuntu25.8', '58469e9dd515852f083ee460e80c2b238454cba87b19121b9720aadb5b24e799', 2109, 493),
    '/usr/share/initramfs-tools/hooks/fuse': ('fuse3:arm64=3.14.0-5build1', 'c0477da2af956f172e5d37a1d08021961a2ad667bec726392842a26f50ce82db', 231, 493),
    '/usr/share/initramfs-tools/hooks/iscsi': ('open-iscsi:arm64=2.1.9-3ubuntu5.4', '7948af63634d4ce94a35f5b127f3f23250bc16d630f6449082cb36331359139e', 672, 493),
    '/usr/share/initramfs-tools/hooks/kbd': ('kbd:arm64=2.6.4-2ubuntu2', '69a2302e5823ca1349862927091facfbe8efc49c4d13e61920e3a9e1e71896f2', 301, 493),
    '/usr/share/initramfs-tools/hooks/klibc-utils': ('klibc-utils:arm64=2.0.13-4ubuntu0.2', '56e06e437c8b05f066d3f86f9af7b49425b27949164aaf83890dbe154ebe42ba', 694, 493),
    '/usr/share/initramfs-tools/hooks/kmod': ('kmod:arm64=31+20240202-2ubuntu7.2', '04cd88e587771418535e48800f16524ab59e9bc6e9f8bc31c262966b81bda6b7', 468, 493),
    '/usr/share/initramfs-tools/hooks/lvm2': ('lvm2:arm64=2.03.16-3ubuntu3.2', 'a0214fccdfff9993c220a82e573b520bb0564ef9efa63e669e0b0f6792ac02ba', 661, 493),
    '/usr/share/initramfs-tools/hooks/mdadm': ('mdadm:arm64=4.3-1ubuntu2.1', 'c503a4581c0832ff0040464a3f32e493d98a4ea6b53e432c966e675fc1048f8f', 3215, 493),
    '/usr/share/initramfs-tools/hooks/ntfs_3g': ('ntfs-3g:arm64=1:2022.10.3-1.2ubuntu3.1', '4eadf545d99bfdc5a274b7a37fbbd4f238ffb9dc48b18a460271582de7c03009', 304, 493),
    '/usr/share/initramfs-tools/hooks/overlayroot': ('overlayroot:all=0.49~24.04.1', 'e2d8f6eedefb8b1eed75d36a76ac2e31d6d593b1796b9beb9f6b5dda07cfdf83', 688, 493),
    '/usr/share/initramfs-tools/hooks/plymouth': ('plymouth:arm64=24.004.60-1ubuntu7.1', '77881bda1c90e29840c5e4696ee489456f8f54631c101fc20cab791d2d2182ee', 6188, 493),
    '/usr/share/initramfs-tools/hooks/resume': ('initramfs-tools-core:all=0.142ubuntu25.8', '49ffe6e2b5baa882923fc0276a11f87fafa78cf6c4d42843060272bd8859e39d', 3267, 493),
    '/usr/share/initramfs-tools/hooks/sg3-utils': ('sg3-utils-udev:all=1.46-3ubuntu4', '55e900e557ecf816fdf3d21d5635e1b9c38b722b6633fc8b38005b77af08baca', 485, 493),
    '/usr/share/initramfs-tools/hooks/thermal': ('initramfs-tools-core:all=0.142ubuntu25.8', '8000b165e2c6ef915fc8d7d6bf2af07942d461cb240e0590c5d1f99a56d8b14f', 1172, 493),
    '/usr/share/initramfs-tools/hooks/thin-provisioning-tools': ('thin-provisioning-tools:arm64=0.9.0-2ubuntu5.1', 'c9ce0862b0ffe9576ea38898b809403ee31ff97e1c5c2c27d4240d4e8638d614', 331, 493),
    '/usr/share/initramfs-tools/hooks/udev': ('udev:arm64=255.4-1ubuntu8.16', '102b94df29abac0b32ad7b7e254436dfc6ac508981978a97e2c40629d05aa918', 2650, 493),
    '/usr/share/initramfs-tools/hooks/xfs': ('xfsprogs:arm64=6.6.0-1ubuntu2.1', '965fd88a9cf3d2042f127e6afa18a1fae321008cd255dd6463746c28db67a347', 850, 493),
    '/usr/share/initramfs-tools/hooks/zz-busybox-initramfs': ('busybox-initramfs:arm64=1:1.36.1-6ubuntu3.1', '94c2a734c7c6e05d6cc5fbe3892e83960e7321d81e8c9e109bcf5432b9f7f828', 2233, 493),
    '/usr/share/initramfs-tools/scripts/functions': ('initramfs-tools-core:all=0.142ubuntu25.8', '6358cb0bc4784bb8dc13d5c9beaf65d5e88f51c9a459daeed0f1311bfc07aa96', 22861, 420),
    '/usr/share/mdadm/mkconf': ('mdadm:arm64=4.3-1ubuntu2.1', '5abc5d2e3083dd2a172d6735e3dd11c29ebd0f30c7b2935a2ac4f626bf87efa0', 2789, 493),
}

SCRIPT_PINS = {
    'scripts/functions': '6358cb0bc4784bb8dc13d5c9beaf65d5e88f51c9a459daeed0f1311bfc07aa96',
    'scripts/local': '9a839a12d83a6ee4b9a8d527bfabd6d4f16792377d9336009943d3ebd82f197e',
    'scripts/init-top/blacklist': '50d990344cb18e8fad0d77992e68ca2c504283d578abb358ffbd90342a03ebf2',
    'scripts/init-top/all_generic_ide': '59697cff80663c30132578d3fc6128692ff15826b4e32df3468e85db03ba3b93',
    'scripts/local-premount/fixrtc': '4b0c4e40fcacc4475eda40ff2d9220ee50b6335b6d0853cb7718f8c4dff7b29b',
    'scripts/local-premount/resume': 'aa479ccf70963ee410736a457eb2a38625d33223162f611f37659410eea8bb26',
    'scripts/init-top/udev': '5893d2c4c9426b2d6166586cb5bd1852be8fa22ba2984b9e1b2ca15f8b9cca5f',
    'scripts/init-bottom/udev': 'ef4a20c970512185e6372566e48fc4b6755f9098c841efe5ce6f1f22827f2326',
}
STAGES = {'init-top': ('all_generic_ide', 'blacklist', 'udev'),
          'init-bottom': ('udev',), 'local-premount': ('fixrtc', 'resume')}
UDEV_RULES = frozenset(('50-firmware.rules', '50-udev-default.rules', '60-block.rules',
    '60-persistent-storage.rules', '61-persistent-storage-android.rules', '71-seat.rules', '80-drivers.rules'))
MODPROBE_FILES = frozenset(('etc/modprobe.d/blacklist-ath_pci.conf',
    'etc/modprobe.d/blacklist-firewire.conf', 'etc/modprobe.d/blacklist-framebuffer.conf',
    'etc/modprobe.d/blacklist-rare-network.conf', 'etc/modprobe.d/blacklist.conf',
    'etc/modprobe.d/disable-algif_aead.conf', 'usr/lib/modprobe.d/aliases.conf',
    'usr/lib/modprobe.d/fbdev-blacklist.conf', 'usr/lib/modprobe.d/systemd.conf'))
PUBLIC_DATA = frozenset(('etc/ld.so.conf', 'etc/ld.so.conf.d/aarch64-linux-gnu.conf',
    'etc/ld.so.conf.d/libc.conf', 'etc/udev/udev.conf'))
LIBRARIES = frozenset(('libacl', 'libblkid', 'libc', 'libcap', 'libcom_err', 'libcrypto',
    'libe2p', 'libext2fs', 'libgcc_s', 'libkmod', 'liblzma', 'libnss_dns',
    'libnss_files', 'libpcre2-8', 'libpthread', 'libresolv', 'libselinux', 'libtinfo',
    'libudev', 'libzstd'))
EXTRA_EXECUTABLES = frozenset(('usr/bin/bash', 'usr/bin/kmod', 'usr/bin/udevadm',
    'usr/lib/initramfs-tools/bin/gcc_s1-stub', 'usr/lib/udev/ata_id',
    'usr/lib/udev/scsi_id', 'usr/sbin/blkid', 'usr/sbin/dumpe2fs'))
KL_INITRAMFS = {'usr/sbin/wait-for-root': '/usr/lib/initramfs-tools/bin/wait-for-root'}
LOCAL_BINARIES = frozenset('[ [[ acpid arch ascii ash awk base32 basename blockdev busybox cat chmod chroot chvt clear cmp cp cpio crc32 cut date dd deallocvt deluser devmem df dirname dmesg du dumpkmap echo egrep env expr false fbset fgrep find fold fstrim fstype grep gunzip gzip halt hostname hwclock i2ctransfer insmod kill ln loadfont loadkmap losetup ls lzop minips mkdir mkfifo mknod mkswap mktemp modinfo more mount mv nuke openvt pidof pivot_root poweroff printf ps pwd readlink reboot reset resume rm rmdir run-init sed seq setkeycodes sh sleep sort stat static-sh stty switch_root sync tail tee test touch tr true ts tty umount uname uniq wc which yes'.split())
SOURCE_HARDLINK_GROUPS = tuple(tuple('/usr/lib/klibc/bin/' + name for name in group)
    for group in (('gunzip', 'gzip', 'zcat'), ('halt', 'poweroff', 'reboot')))


# Generated factory inputs belong to Ubuntu's exact published 20260705 image
# 7df0201546f75b8bcc1044594c806c35749421ad3c9bc1be2a3ab806cfae39cc.
# They are not DEB payloads and do not grant arbitrary local configuration.
FACTORY_IMAGE_INPUTS = {'etc/default/keyboard': ('9d2d64b5b738ef55ecc80e236cd00caba19d3afe1921c74fa7d73c9477ebe6eb', 150, 420), 'etc/default/console-setup': ('e8601d8158edf57a2aa1aedb57d4a4d9e8856a52e4bdae4347f6afcb1ae975c6', 284, 420), 'etc/console-setup/cached_UTF-8_del.kmap.gz': ('916b4203c5f2a000896c8269e1a0836ec1d4ea07a3d0aa113b157256f93b0d48', 5085, 420)}
STAGE_DEPENDENCIES = {
    'init-top': (('udev', 'framebuffer'), ('framebuffer', 'console_setup')),
    'init-bottom': (('udev', 'plymouth'),),
}
REQUESTED_LOCAL_MODULES = frozenset(('linear', 'multipath', 'raid0', 'raid1',
    'raid456', 'raid5', 'raid6', 'raid10', 'efivarfs'))


def verify_stage_order(name, raw, entries):
    stage = name.split('/')[1]
    policy.need(stage in ('init-top', 'init-premount', 'init-bottom', 'local-top',
        'local-premount', 'local-block', 'local-bottom', 'panic'), 'unknown classic stage ' + name)
    names = [item.rsplit('/', 1)[1] for item in entries if item.startswith('scripts/' + stage + '/')
             and item != name and not stat.S_ISDIR(entries[item]['mode'])]
    policy.need(all('scripts/' + stage + '/' + leaf in SCRIPT_PINS or
        'scripts/' + stage + '/' + leaf in STOCK_ROLES for leaf in names), 'unreviewed classic stage callback')
    lines = raw.decode('ascii').splitlines(keepends=True)
    policy.need(len(lines) == len(names) * 2, 'classic stage callback count differs')
    ordered = []
    for index in range(0, len(lines), 2):
        match = re.fullmatch(re.escape('/scripts/' + stage + '/') + r'([A-Za-z0-9_-]+) "\$@"\n', lines[index])
        policy.need(match is not None and lines[index + 1] ==
            '[ -e /conf/param.conf ] && . /conf/param.conf\n', 'classic stage contains unreviewed code')
        ordered.append(match[1])
    policy.need(len(set(ordered)) == len(ordered) and set(ordered) == set(names), 'classic stage differs from callbacks')
    for before, after in STAGE_DEPENDENCIES.get(stage, ()):
        if before in ordered and after in ordered:
            policy.need(ordered.index(before) < ordered.index(after), 'classic stage prerequisite inverted')


def verify_mdadm_data(raw):
    policy.need(len(raw) <= 65536, 'classic mdadm configuration bound')
    for line in raw.decode('ascii').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        policy.need(line in ('HOMEHOST <system>', 'MAILADDR root') or re.fullmatch(
            r'ARRAY /dev/md[A-Za-z0-9_/-]* (?:metadata=[0-9.]+ )?UUID=[a-fA-F0-9:]{16,80}(?: name=[A-Za-z0-9_.:-]{1,128})?', line),
            'classic mdadm active configuration unreviewed')
    return raw


def verify_crypttab_data(raw):
    policy.need(len(raw) <= 16384, 'classic crypttab bound')
    host = policy.trusted_read('/etc/crypttab', 16384) if Path('/etc/crypttab').exists() else b''
    host_rows = {tuple(line.split()) for line in host.decode('ascii').splitlines()
                 if line.strip() and not line.lstrip().startswith('#')}
    for line in raw.decode('ascii').splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        row = tuple(line.split())
        policy.need(len(row) in (3, 4) and row in host_rows and
            re.fullmatch(r'[A-Za-z0-9_+-]{1,128}', row[0]) and
            re.fullmatch(r'UUID=[a-fA-F0-9-]{16,64}', row[1]) and row[2] in ('none', '-') and
            (len(row) == 3 or all(option in ('luks', 'discard', 'initramfs') or
                re.fullmatch(r'tries=[1-9][0-9]?', option) for option in row[3].split(','))),
            'classic crypttab needs reviewed local UUID/passphrase configuration')
    return raw


def parse_fstab(raw):
    policy.need(len(raw) <= 65536 and all(value in (9, 10) or 32 <= value <= 126 for value in raw),
                'classic fstab is not bounded ASCII data')
    rows = []
    for line in raw.decode('ascii').splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        fields = line.split()
        policy.need(len(fields) == 6 and all(re.fullmatch(r'[A-Za-z0-9_./,:=+@%~-]{1,1024}', item)
            for item in fields), 'classic fstab contains executable or unreviewed fields')
        source, target, filesystem, options, dump, check = fields
        policy.need(dump in ('0', '1') and check in ('0', '1', '2') and
            filesystem in (*policy.CLOUD_LOCAL_ROOT_FS, 'vfat', 'swap', 'tmpfs', 'proc', 'sysfs', 'devtmpfs', 'devpts', 'cgroup2') and
            '_netdev' not in options and '..' not in Path(source).parts and '..' not in Path(target).parts,
            'classic fstab requires local inert mount data')
        policy.need(target not in ('/', '/usr') or filesystem in policy.CLOUD_LOCAL_ROOT_FS,
                    'classic root filesystem policy unreviewed')
        policy.need(source.startswith('/') or re.fullmatch(r'(?:UUID|LABEL|PARTUUID|PARTLABEL)=[A-Za-z0-9_.+-]{1,128}', source) or
            source in ('none', 'tmpfs', 'proc', 'sysfs', 'devtmpfs', 'devpts', 'cgroup2'),
            'classic fstab mount source unreviewed')
        policy.need(target.startswith('/') or filesystem == 'swap' and target in ('none', 'swap'),
                    'classic fstab mount target unreviewed')
        rows.append(fields)
    policy.need(len(rows) <= 256 and sum(row[1] == '/' for row in rows) == 1,
                'classic fstab root is missing or ambiguous')
    return rows


def verify_root_device(value):
    mounts = policy.decode(policy.command('findmnt', '-J', '-o', 'SOURCE', '/'))['filesystems']
    policy.need(type(mounts) is list and len(mounts) == 1 and type(mounts[0]) is dict and
        type(mounts[0].get('source')) is str, 'classic running root identity unproved')
    source = mounts[0]['source'].split('[', 1)[0]
    policy.need(source.startswith('/dev/') and '..' not in Path(source).parts,
                'classic running root is not a local device')
    def facts(meta):
        return (meta.st_dev, meta.st_ino, meta.st_mode, meta.st_uid, meta.st_gid,
                meta.st_rdev, meta.st_mtime_ns, meta.st_ctime_ns)
    expected, running = Path(value).stat(), Path(source).stat()
    policy.need(all(stat.S_ISBLK(meta.st_mode) and meta.st_uid == 0 for meta in (expected, running)) and
        expected.st_rdev == running.st_rdev and facts(Path(value).stat()) == facts(expected) and
        facts(Path(source).stat()) == facts(running), 'classic fstab root differs from running root device')


def inert_config(path, patterns=None):
    path = Path(path)
    if not path.exists() and not path.is_symlink():
        return 'absent'
    policy.need(not path.is_symlink(), 'classic mutable build input symlink')
    raw = policy.trusted_read(path, 16384)
    policy.need(all(value in (9, 10) or 32 <= value <= 126 for value in raw),
                'classic mutable build input is not inert ASCII')
    for line in raw.decode('ascii').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        policy.need(patterns is not None, 'classic local build override unreviewed')
        match = re.fullmatch(r'([A-Z_]+)=(.*)', line)
        policy.need(match is not None and match[1] in patterns, 'classic build assignment unreviewed')
        value = match[2]
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        policy.need(re.fullmatch(patterns[match[1]], value) is not None,
                    'classic build assignment contains executable data')
        if match[1].startswith('LINUX_KERNEL_CMDLINE'):
            policy.inspect_cmdline(value)
    return __import__('hashlib').sha256(raw).hexdigest()


def build_input_snapshot():
    # Run before helpers or mkinitramfs: vendor fsck evals fstab fields and
    # vendor cryptsetup/mkconf source configuration during the build itself.
    raw = policy.trusted_read('/etc/fstab', 65536)
    parse_fstab(raw)
    default_root_data()
    directory = Path('/etc/fstab.d')
    if directory.exists() or directory.is_symlink():
        meta = directory.lstat()
        policy.need(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0 and not meta.st_mode & 0o022 and
            not list(directory.iterdir()), 'classic foreign fstab.d roster')
    values = {'fstab': hashlib.sha256(raw).hexdigest(), 'fstab.d': 'empty_or_absent'}
    for name in ('/etc/flash-kernel/db', '/etc/flash-kernel/machine'):
        values[name] = inert_config(name)
    values['/etc/default/mdadm'] = inert_config('/etc/default/mdadm', {
        'AUTOCHECK': r'(?:true|false)', 'AUTOSCAN': r'(?:true|false)',
        'START_DAEMON': r'(?:true|false)', 'VERBOSE': r'(?:true|false)',
        'DAEMON_OPTIONS': r'[A-Za-z0-9_ ./=:+-]{0,512}'})
    values['/etc/default/flash-kernel'] = inert_config('/etc/default/flash-kernel', {
        'LINUX_KERNEL_CMDLINE': r'[A-Za-z0-9_ ./=:+-]{0,512}',
        'LINUX_KERNEL_CMDLINE_DEFAULTS': r'[A-Za-z0-9_ ./=:+-]{0,512}'})
    crypt = Path('/etc/crypttab')
    if crypt.exists() or crypt.is_symlink():
        policy.need(not crypt.is_symlink(), 'classic crypttab source symlink')
        raw = policy.trusted_read(crypt, 16384)
        verify_crypttab_data(raw)
        values['crypttab'] = hashlib.sha256(raw).hexdigest()
    md = Path('/etc/mdadm/mdadm.conf')
    if md.exists() or md.is_symlink():
        policy.need(not md.is_symlink(), 'classic mdadm source symlink')
        # The publisher's default source comments/identities are inert. Active
        # ARRAY data must meet the same grammar before any generator runs.
        raw = policy.trusted_read(md, 65536); verify_mdadm_data(raw)
        values['mdadm'] = hashlib.sha256(raw).hexdigest()
    return values


def default_root_data():
    # Reproduce the pinned flash-kernel producer with typed, non-evaluated data.
    rows = parse_fstab(policy.trusted_read('/etc/fstab', 65536))
    roots = [row[0] for row in rows if row[1] == '/']
    value = roots[0]
    token = re.fullmatch(r'(LABEL|UUID|PARTUUID|PARTLABEL)=([A-Za-z0-9_.+-]{1,128})', value)
    if token:
        value = '/dev/disk/by-' + token[1].lower() + '/' + token[2]
    policy.need(re.fullmatch(r'/dev/(?:disk/by-(?:label|uuid|partuuid|partlabel)/[A-Za-z0-9_.+-]+|'
        r'(?:vd|sd|hd)[a-z]+[0-9]*|nvme[0-9]+n[0-9]+(?:p[0-9]+)?|mapper/[A-Za-z0-9_+.-]+|md[0-9]+)', value),
        'classic default root is not a reviewed local device')
    verify_root_device(value)
    return ('ROOT="' + value + '"\n').encode()


BUILD_CORE_SOURCES = ('/usr/sbin/mkinitramfs', '/usr/share/initramfs-tools/hook-functions',
                      '/etc/initramfs-tools/initramfs.conf', '/usr/share/initramfs-tools/scripts/functions')
BUILD_SOURCE_TREES = (
    '/usr/share/initramfs-tools/hooks', '/etc/initramfs-tools/hooks',
    '/usr/share/initramfs-tools/conf-hooks.d', '/usr/share/initramfs-tools/conf.d',
    '/etc/initramfs-tools/conf.d', '/etc/initramfs-tools/modules.d',
    '/usr/share/flash-kernel/db',
)
OVERLAY_INPUTS = ('/etc/overlayroot.conf', '/etc/overlayroot.local.conf',
                  '/etc/initramfs-tools/conf.d/overlayroot')


def overlay_snapshot():
    """Never evaluate overlayroot configuration; only disabled literals exist."""
    result = {}
    for name in OVERLAY_INPUTS:
        path = Path(name)
        if not path.exists() and not path.is_symlink():
            result[name] = 'absent'
            continue
        policy.need(not path.is_symlink(), 'classic overlay config symlink')
        raw = policy.trusted_read(path, 16384)
        policy.need(not raw or raw.endswith(b'\n'), 'classic overlay config incomplete line')
        policy.need(all(value == 10 or 32 <= value <= 126 for value in raw),
                    'classic overlay config contains nonliteral bytes')
        for line in raw.decode('ascii').splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            policy.need(re.fullmatch(r"(?:overlayroot|overlayroot_cfgdisk)=(?:''|\"\"|'disabled'|\"disabled\"|disabled)", line),
                        'classic overlay config must be literally disabled')
        result[name] = hashlib.sha256(raw).hexdigest()
    return result


def classic_gnu_sources(*, installed=None):
    """Bind one complete publisher-qualified package and all three real files."""
    if installed is None:
        raw = policy.command('dpkg-query', '-W',
            '-f=${db:Status-Abbrev} ${Package}:${Architecture}=${Version}\n', 'coreutils').decode('ascii')
        policy.need(len(raw) <= 4096, 'classic GNU package inventory bound')
        installed = {line[4:] for line in raw.splitlines() if line.startswith('ii  ')}
    packages = set(installed) & set(policy.CLASSIC_GNU_TOOL_PROFILES)
    policy.need(len(packages) == 1, 'unreviewed classic GNU package version')
    package = next(iter(packages)); tools = policy.CLASSIC_GNU_TOOL_PROFILES[package]
    observed, generations = {}, {}
    for name in tools:
        path = Path(name); meta = path.lstat()
        policy.need(stat.S_ISREG(meta.st_mode) and meta.st_uid == meta.st_gid == 0 and
            meta.st_nlink == 1 and stat.S_IMODE(meta.st_mode) == 0o755 and
            0 < meta.st_size <= policy.MAX_MEMORY_ENTRY, 'untrusted classic GNU source ' + name)
        generations[name] = alias_generation(meta)
        observed[name] = hashlib.sha256(policy.trusted_read(path, policy.MAX_MEMORY_ENTRY)).hexdigest()
    policy.need(all(alias_generation(Path(name).lstat()) == generation
        for name, generation in generations.items()), 'classic GNU source changed during qualification')
    return policy.classic_gnu_tool_profile(package, observed)


def classic_system_sources(installed):
    """Qualify the documented complete Noble package base before mutations.

    The private three-tool callback factory alone does not qualify all stock
    coreutils roles (head/sha512sum), or the large OpenSSL payload.
    """
    required = {'coreutils:arm64=9.4-3ubuntu6.3',
                'libssl3t64:arm64=3.0.13-0ubuntu3.16',
                'openssl:arm64=3.0.13-0ubuntu3.16'}
    policy.need(required <= installed,
        'classic package prerequisites required: coreutils 9.4-3ubuntu6.3, libssl3t64/openssl 3.0.13-0ubuntu3.16')
    hashes, cache, generations = {}, {}, {}
    for role in ('usr/bin/head', 'usr/bin/sha512sum'):
        source, sha, size, mode = STOCK_ROLES[role]
        path = Path(source); meta = path.lstat()
        policy.need(stat.S_ISREG(meta.st_mode) and meta.st_uid == meta.st_gid == 0 and
            meta.st_nlink == 1 and meta.st_size == size and stat.S_IMODE(meta.st_mode) == mode,
            'classic coreutils stock prerequisite metadata ' + source)
        generations[source] = alias_generation(meta)
        raw = policy.trusted_read(path, policy.MAX_MEMORY_ENTRY)
        policy.need(len(raw) == size and hashlib.sha256(raw).hexdigest() == sha,
            'classic coreutils stock prerequisite factory ' + source)
        hashes[source] = sha
    baseline = policy.package_baseline(os.uname().release, profile=policy.CLASSIC_PROFILE)
    for name, (package, sha, size, mode) in policy.CLASSIC_LARGE_PUBLIC_FILES.items():
        path = Path(name)
        packages = {value for value in installed if value.startswith(package + ':')}
        if not packages and not path.exists() and not path.is_symlink():
            continue
        policy.need(len(packages) == 1, 'classic large source package missing or ambiguous ' + package)
        meta = path.lstat()
        policy.need(stat.S_ISREG(meta.st_mode) and meta.st_uid == meta.st_gid == 0 and
            meta.st_nlink == 1 and meta.st_size == size and stat.S_IMODE(meta.st_mode) == mode,
            'classic large source prerequisite metadata ' + name)
        generations[name] = alias_generation(meta)
        body = policy.large_public_source(name, meta.st_mode, baseline, cache,
            profile=policy.CLASSIC_PROFILE)
        policy.need(body.sha256 == sha, 'classic large source prerequisite factory ' + name)
        hashes[name] = body.sha256
    policy.need(all(alias_generation(Path(name).lstat()) == value
        for name, value in generations.items()), 'classic large sources changed during qualification')
    return hashes


def verify_build_sources():
    """Authenticate both prereqs and normal hook execution before mkinitramfs."""
    present = set()
    for name, (sha, size, mode) in FACTORY_IMAGE_INPUTS.items():
        if not name.startswith('etc/default/'):
            continue
        path = Path('/' + name)
        if Path('/usr/share/initramfs-tools/hooks/console_setup').exists() or path.exists() or path.is_symlink():
            meta = path.lstat()
            policy.need(stat.S_ISREG(meta.st_mode) and meta.st_uid == meta.st_gid == 0 and
                meta.st_nlink == 1 and meta.st_size == size and stat.S_IMODE(meta.st_mode) == mode and
                hashlib.sha256(policy.trusted_read(path)).hexdigest() == sha,
                'classic factory keyboard configuration changed')
    for directory in BUILD_SOURCE_TREES:
        path = Path(directory)
        if not path.exists() and not path.is_symlink():
            continue
        meta = path.lstat()
        policy.need(stat.S_ISDIR(meta.st_mode) and meta.st_uid == meta.st_gid == 0 and
            not meta.st_mode & 0o022, 'untrusted classic builder source directory')
        children = list(path.iterdir())
        policy.need(len(children) <= 256, 'classic builder source inventory bound')
        for child in children:
            if child == BUILD_HOOK:
                policy.need(not child.is_symlink() and policy.trusted_read(child) == BUILD_HOOK_BYTES and
                    stat.S_IMODE(child.lstat().st_mode) == 0o755, 'classic owned builder hook changed')
            else:
                policy.need(str(child) in STOCK_BUILD_SOURCES, 'unknown classic builder source ' + str(child))
                present.add(str(child))
    raw_packages = policy.command('dpkg-query', '-W',
        '-f=${db:Status-Abbrev} ${Package}:${Architecture}=${Version}\n').decode('ascii').splitlines()
    policy.need(len(raw_packages) <= 8192, 'classic installed package inventory bound')
    installed = {line[4:] for line in raw_packages if line.startswith('ii  ')}
    gnu_tools = classic_gnu_sources(installed=installed)
    system_hashes = classic_system_sources(installed)
    expected = {name for name, pin in STOCK_BUILD_SOURCES.items() if pin[0] in installed}
    expected_tree = {name for name in expected if any(name.startswith(tree + '/') for tree in BUILD_SOURCE_TREES)}
    policy.need(present == expected_tree, 'classic installed builder source roster differs')
    present.update(expected - expected_tree)
    present.update(BUILD_CORE_SOURCES)

    packages, hashes = set(), {}
    for name in sorted(present):
        package, sha, size, mode = STOCK_BUILD_SOURCES[name]
        path = Path(name); meta = path.lstat()
        policy.need(stat.S_ISREG(meta.st_mode) and meta.st_uid == meta.st_gid == 0 and
            meta.st_nlink == 1 and stat.S_IMODE(meta.st_mode) == mode and meta.st_size == size and
            hashlib.sha256(policy.trusted_read(path)).hexdigest() == sha,
            'modified classic builder source ' + name)
        packages.add(package); hashes[name] = sha
    policy.need(packages <= installed, 'classic builder package versions changed')

    hashes.update({name: value[1] for name, value in gnu_tools.items()})
    hashes.update(system_hashes)
    return hashes


def stock_source(name, public):
    source, sha, size, mode = STOCK_ROLES[name]
    raw = public(source)
    meta = Path(source).stat()
    policy.need(len(raw) == size and hashlib.sha256(raw).hexdigest() == sha and
                stat.S_IMODE(meta.st_mode) == mode, 'classic stock publisher role changed ' + name)
    return raw


def alias_generation(meta):
    # readlink/resolve may update atime. All source identity and mutation
    # coordinates still participate, including the complete link count.
    return (meta.st_dev, meta.st_ino, meta.st_mode, meta.st_uid, meta.st_gid,
            meta.st_nlink, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns)


def pinned_builder_source(path):
    """Authenticate a producer before using one of its generated file roles."""
    path = Path(path)
    _package, expected_sha, size, mode = STOCK_BUILD_SOURCES[str(path)]
    before = path.lstat()
    policy.need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and
        before.st_nlink == 1 and before.st_size == size and stat.S_IMODE(before.st_mode) == mode,
        'classic generated-role producer metadata changed')
    raw = policy.trusted_read(path)
    policy.need(hashlib.sha256(raw).hexdigest() == expected_sha and
        alias_generation(path.lstat()) == alias_generation(before), 'classic generated-role producer changed')
    return raw


def stock_archive_alias(name, source_hashes):
    target = STOCK_ALIASES[name][1]
    if name == 'usr/sbin/mount.ntfs':
        # Unlike the package's intermediate source link, the exact published
        # ntfs_3g hook explicitly ln-s /bin/ntfs-3g at both archive aliases.
        path = '/usr/share/initramfs-tools/hooks/ntfs_3g'
        raw = pinned_builder_source(path)
        source_hashes[path] = hashlib.sha256(raw).hexdigest()
        policy.need(target == 'mount.ntfs-3g' and
            STOCK_ALIASES['usr/sbin/mount.ntfs-3g'][1] == '/bin/ntfs-3g', 'classic NTFS source recipe changed')
        return STOCK_ALIASES['usr/sbin/mount.ntfs-3g'][1]
    return target


STOCK_EMPTY_MODULE_PARENTS = frozenset((
    'drivers/block', 'drivers/firmware', 'drivers/scsi/lpfc', 'drivers/scsi/qla2xxx'))


def factory_empty_directory(name, item, entries, kernel, source_hashes):
    prefix = 'usr/lib/modules/' + kernel + '/kernel/'
    relative = name[len(prefix):] if name.startswith(prefix) else None
    if name == 'etc/plymouth':
        # The signed plymouth hook unconditionally mkdir-p this directory;
        # it remains empty when there is no optional plymouthd.conf source.
        path = '/usr/share/initramfs-tools/hooks/plymouth'
        raw = pinned_builder_source(path)
        source_hashes[path] = hashlib.sha256(raw).hexdigest()
    elif relative in STOCK_EMPTY_MODULE_PARENTS:
        # Independent pristine image7df02015/initrd7f3eb443 contains only
        # frozen remote leaves under these four exact directories. Removing
        # those leaves retains the inert publisher-created parent metadata.
        policy.need(any(posixpath.dirname(leaf) == relative for leaf in policy.CLASSIC_REMOTE_MODULE_LEAVES),
                    'classic empty module parent has no qualified subtraction')
    else:
        return False
    policy.need(item['mode'] == stat.S_IFDIR | 0o755 and item['nlink'] == 2 and item['data'] == b'' and
        not any(child.startswith(name + '/') for child in entries), 'classic factory directory is not exactly empty')
    return True


def source_read(path):
    """Keep generic policy reading single-link; narrowly prove klibc aliases."""
    group = next((group for group in SOURCE_HARDLINK_GROUPS if path in group), None)
    if group is None:
        return policy.trusted_read(path, policy.MAX_MEMORY_ENTRY)
    def facts(meta):
        return (meta.st_dev, meta.st_ino, meta.st_mode, meta.st_uid, meta.st_gid,
                meta.st_nlink, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns)
    before = Path(path).lstat()
    policy.need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and
        not before.st_mode & 0o022 and before.st_nlink == len(group) and
        before.st_size <= policy.MAX_MEMORY_ENTRY, 'untrusted classic hardlink source')
    for member in group:
        leaf = Path(member)
        policy.need(facts(leaf.lstat()) == facts(before), 'incomplete classic source hardlink group')
        for parent in leaf.parents:
            meta = parent.lstat()
            policy.need(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0 and not meta.st_mode & 0o022,
                        'untrusted classic hardlink ancestry')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        policy.need(facts(os.fstat(stream.fileno())) == facts(before), 'classic source open raced')
        raw = stream.read(policy.MAX_MEMORY_ENTRY + 1)
        policy.need(len(raw) == before.st_size and facts(os.fstat(stream.fileno())) == facts(before),
                    'classic hardlink source changed')
    policy.need(all(facts(Path(member).lstat()) == facts(before) for member in group),
                'classic source group changed')
    return raw


def verify_hardlink_groups(entries):
    groups = {}
    for name, item in entries.items():
        if not stat.S_ISREG(item['mode']):
            continue
        links = item['nlink']
        policy.need(type(links) is int and 1 <= links <= 256, 'classic archive hardlink bound')
        if links > 1:
            policy.need(name.startswith('usr/bin/') and name[8:] in LOCAL_BINARIES and
                item['mode'] == stat.S_IFREG | 0o755, 'unknown classic hardlink role')
            groups.setdefault(item['inode'], []).append(item)
    for members in groups.values():
        first = members[0]
        policy.need(len(members) == first['nlink'] and all(item['nlink'] == first['nlink'] and
            item['mode'] == first['mode'] and item['data'] == first['data'] for item in members),
            'incomplete or inconsistent classic archive hardlink group')


def populate_build(root, kernel, *, nonce=None):
    """Populate only a root-private stock mkinitramfs workspace, never /boot."""
    need = policy.need
    need(os.geteuid() == 0 and os.uname().machine == 'aarch64' and type(root) is str and re.fullmatch(
        r'/(?:var/tmp|tmp)/mkinitramfs_[A-Za-z0-9_-]{6,32}', root),
        'classic callback requires a private mkinitramfs root')
    need(type(kernel) is str and policy.KERNEL.fullmatch(kernel), 'invalid classic build kernel')
    nonce = os.urandom(32).hex() if nonce is None else nonce
    need(type(nonce) is str and re.fullmatch('[a-f0-9]{64}', nonce), 'invalid classic build nonce')
    path = Path(root)
    for parent in path.parents:
        meta = parent.lstat()
        need(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0 and (
            not meta.st_mode & 0o022 or str(parent) in ('/tmp', '/var/tmp') and
            stat.S_IMODE(meta.st_mode) == 0o1777), 'untrusted classic build ancestry')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent_fd = os.open(path.parent, flags)
    try:
        fd = os.open(path.name, flags, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        def identity(meta):
            return meta.st_dev, meta.st_ino, meta.st_mode, meta.st_uid, meta.st_gid
        before = os.fstat(fd)
        need(stat.S_ISDIR(before.st_mode) and before.st_uid == before.st_gid == 0 and
            stat.S_IMODE(before.st_mode) in (0o700, 0o755) and identity(path.lstat()) == identity(before),
            'untrusted classic build root')
        gnu_tools = classic_gnu_sources()
        # The pinned vendor builder chmods its mktemp directory0755. Seal the
        # already authenticated descriptor before any payload or alias write.
        os.fchmod(fd, 0o700)
        before = os.fstat(fd)
        need(stat.S_IMODE(before.st_mode) == 0o700 and identity(path.lstat()) == identity(before),
             'classic private root sealing failed')
        # Authenticate every possible write ancestor before copy_exec or rm.
        # The fixed /bin,/lib,/sbin image aliases are never write destinations.
        directories = ('etc', 'scripts', 'usr', 'usr/bin', 'usr/lib',
            'usr/lib/aarch64-linux-gnu', 'usr/lib/aegis', 'usr/lib/udev',
            'usr/lib/udev/rules.d', 'usr/lib/systemd', 'usr/lib/modules',
            'usr/lib/modules/' + kernel, 'usr/lib/modules/' + kernel + '/kernel',
            'usr/lib/modules/' + kernel + '/kernel/drivers', 'var', 'var/lib')
        paths = list(policy.CLASSIC_REMOVE_FILES) + list(policy.CLASSIC_REMOVE_TREES)
        paths += ['usr/lib/modules/' + kernel + '/kernel/' + item for item in
            (*policy.CLASSIC_REMOTE_MODULE_TREES, *policy.CLASSIC_REMOTE_MODULE_LEAVES)]
        directories += tuple(sorted({str(parent) for item in paths for parent in Path(item).parents
                                     if str(parent) != '.'}))
        for logical in directories:
            current = os.dup(fd)
            try:
                for part in Path(logical).parts:
                    try:
                        child = os.open(part, flags, dir_fd=current)
                    except FileNotFoundError:
                        break
                    except OSError as error:
                        raise ValueError('untrusted classic write directory ' + logical) from error
                    os.close(current)
                    current = child
                    meta = os.fstat(current)
                    need(meta.st_uid == meta.st_gid == 0 and not meta.st_mode & 0o022,
                         'untrusted classic write ancestry ' + logical)
            finally:
                os.close(current)
        init = policy.trusted_read('/usr/share/initramfs-tools/init')
        functions = policy.trusted_read('/usr/share/initramfs-tools/scripts/functions')
        hook = policy.classic_build_hook(nonce, init, functions, gnu_tools=gnu_tools)
        env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
            'DESTDIR': root, 'version': kernel, 'verbose': 'n', 'DPKG_ARCH': 'arm64'}
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            result = subprocess.run(['/bin/sh', '-e'], input=hook, env=env, cwd='/',
                stdout=output, stderr=errors, timeout=90)
            need(output.tell() <= 4 << 20 and errors.tell() <= 4 << 20, 'classic callback output bound')
            if result.returncode:
                errors.seek(0)
                os.write(2, errors.read(65536))
            need(result.returncode == 0, 'classic callback refused; partial build retained')
        need(identity(os.fstat(fd)) == identity(before) == identity(path.lstat()),
             'classic build root changed')
        return dict(build_nonce=nonce, hook_sha256=hashlib.sha256(hook).hexdigest(),
                    installed_acceptance=False)
    finally:
        os.close(fd)


@policy.bounded_assessment
def verify_archive(kernel, image, *, nonce):
    """Check every image leaf and its role/provenance, without boot claims."""
    need = policy.need
    need(type(kernel) is str and policy.KERNEL.fullmatch(kernel) and
         type(nonce) is str and re.fullmatch('[a-f0-9]{64}', nonce),
         'invalid classic image identity')
    need(os.uname().machine == 'aarch64', 'unsupported classic image architecture')
    before = policy.sha_file(image)
    entries = policy.archive_entries(image, profile=policy.CLASSIC_PROFILE)
    verify_hardlink_groups(entries)
    baseline = policy.package_baseline(kernel, profile=policy.CLASSIC_PROFILE)
    source_hashes, large_cache, files = {}, {}, {}

    def public(path):
        choices = (path, '/usr' + path if path.startswith(('/lib/', '/bin/', '/sbin/')) else
                   path[4:] if path.startswith(('/usr/lib/', '/usr/bin/', '/usr/sbin/')) else path)
        source = next((item for item in choices if item in baseline), None)
        need(source is not None, 'unpackaged classic source ' + path)
        try:
            raw = source_read(path)
        except ValueError as error:
            raise ValueError('classic public source refused ' + path + ': ' + str(error)) from error
        need(hashlib.md5(raw).hexdigest() == baseline[source], 'modified classic source ' + path)
        source_hashes[path] = hashlib.sha256(raw).hexdigest()
        return raw

    init, functions = public('/usr/share/initramfs-tools/init'), public('/usr/share/initramfs-tools/scripts/functions')
    payloads = policy.classic_build_payloads(nonce, init, functions)
    builtin = public('/usr/lib/initramfs-tools/bin/busybox')
    module_prefix = 'usr/lib/modules/' + kernel + '/'
    module_indices = frozenset(('modules.alias', 'modules.alias.bin', 'modules.dep', 'modules.dep.bin',
        'modules.softdep', 'modules.symbols', 'modules.symbols.bin', 'modules.devname',
        'modules.builtin.bin', 'modules.builtin.alias.bin'))
    root_links = {'bin': b'usr/bin', 'lib': b'usr/lib', 'sbin': b'usr/sbin',
        'lib.usr-is-merged': b'usr/lib.usr-is-merged', 'etc/mtab': b'/proc/mounts',
        'usr/sbin/modprobe': b'../bin/kmod', 'usr/sbin/rmmod': b'../bin/kmod',
        'usr/lib/systemd/systemd-udevd': b'../../bin/udevadm'}
    gnu_tools = None
    for name, item in entries.items():
        mode, body = item['mode'], item['data']
        need(not policy.classic_remote_module(name), 'classic network module ' + name)
        need(not any(name == excluded or name.startswith(excluded + '/') for excluded in
            (*policy.CLASSIC_REMOVE_FILES, *policy.CLASSIC_REMOVE_TREES)), 'classic forbidden role ' + name)
        if stat.S_ISDIR(mode):
            continue
        if name in root_links:
            need(stat.S_ISLNK(mode) and body == root_links[name], 'classic fixed symlink changed ' + name)
        elif name == 'usr/share/plymouth/themes/text.plymouth':
            need(mode == stat.S_IFLNK | 0o777 and item['nlink'] == 1 and
                body == b'/usr/share/plymouth/themes/ubuntu-text/ubuntu-text.plymouth' and
                body.decode()[1:] in entries, 'classic Plymouth generated alias changed')
        elif stat.S_ISLNK(mode) and name in STOCK_ALIASES:
            source, target = STOCK_ALIASES[name]
            archive_target = stock_archive_alias(name, source_hashes)
            need(body == archive_target.encode('ascii') and item['nlink'] == 1 and
                 mode == stat.S_IFLNK | 0o777, 'classic publisher alias changed ' + name)
            target_name = posixpath.normpath(archive_target.lstrip('/') if archive_target.startswith('/') else
                posixpath.join(posixpath.dirname(name), archive_target))
            if target_name.startswith(('bin/', 'sbin/', 'lib/')):
                target_name = 'usr/' + target_name
            need(target_name in entries and target_name != name, 'classic publisher alias unresolved ' + name)
            alias = Path(source); before_alias = alias.lstat()
            need(stat.S_ISLNK(before_alias.st_mode) and before_alias.st_uid == before_alias.st_gid == 0 and
                before_alias.st_nlink == 1 and
                os.readlink(alias) == target, 'classic source alias changed ' + name)
            companion = None
            if name == 'usr/sbin/mount.ntfs':
                companion_source, companion_target = STOCK_ALIASES['usr/sbin/mount.ntfs-3g']
                companion = Path(companion_source); companion_before = companion.lstat()
                need(stat.S_ISLNK(companion_before.st_mode) and
                    companion_before.st_uid == companion_before.st_gid == 0 and companion_before.st_nlink == 1 and
                    os.readlink(companion) == companion_target and
                    entries.get('usr/sbin/mount.ntfs-3g', {}).get('data') == companion_target.encode('ascii'),
                    'classic NTFS companion source changed')
            resolved = str(alias.resolve(strict=True))
            if companion is not None:
                need(resolved == '/' + target_name and stat.S_ISREG(entries[target_name]['mode']),
                     'classic NTFS terminal is not the qualified regular file')
            if resolved in policy.CLASSIC_LARGE_PUBLIC_FILES:
                target_body = policy.large_public_source(resolved, entries[target_name]['mode'], baseline,
                    large_cache, profile=policy.CLASSIC_PROFILE)
                source_hashes[resolved] = target_body.sha256
            else:
                public(resolved)
            if companion is not None:
                need(os.readlink(companion) == companion_target and
                    alias_generation(companion.lstat()) == alias_generation(companion_before),
                    'classic NTFS companion source raced')
            need(os.readlink(alias) == target and alias_generation(alias.lstat()) == alias_generation(before_alias),
                 'classic source alias raced ' + name)
        elif stat.S_ISLNK(mode):
            need(name.startswith('usr/lib/aarch64-linux-gnu/') or name == 'usr/lib/ld-linux-aarch64.so.1',
                 'unknown classic symlink ' + name)
            target = posixpath.normpath(posixpath.join(posixpath.dirname(name), body.decode('ascii')))
            need(target.startswith('usr/lib/aarch64-linux-gnu/') and target in entries,
                 'classic library alias escapes ' + name)
            alias = Path('/' + name)
            alias_before = alias.lstat()
            need(stat.S_ISLNK(alias_before.st_mode) and alias_before.st_uid == alias_before.st_gid == 0 and
                alias_before.st_nlink == 1 and
                os.fsencode(os.readlink(alias)) == body, 'classic library alias differs from source ' + name)
            public(str(alias.resolve(strict=True)))
            need(os.fsencode(os.readlink(alias)) == body and alias_generation(alias.lstat()) == alias_generation(alias_before),
                 'classic library alias changed ' + name)
        else:
            need(stat.S_ISREG(mode) and not mode & 0o7000, 'unknown classic device or special mode ' + name)
            expected = None
            if name in payloads:
                expected, expected_mode = payloads[name]
                need(mode == stat.S_IFREG | expected_mode and item['nlink'] == 1, 'classic barrier metadata ' + name)
            elif name in SCRIPT_PINS:
                expected = public('/usr/share/initramfs-tools/' + name)
                need(hashlib.sha256(expected).hexdigest() == SCRIPT_PINS[name], 'classic script revision ' + name)
                need(item['nlink'] == 1 and mode == stat.S_IFREG | (0o644 if name in
                    ('scripts/functions', 'scripts/local') else 0o755), 'classic script metadata ' + name)
            elif name.startswith('scripts/') and name.endswith('/ORDER'):
                verify_stage_order(name, body, entries)
                need(mode == stat.S_IFREG | 0o644 and item['nlink'] == 1, 'classic stage order metadata')
            elif name == 'conf/arch.conf':
                expected = b'DPKG_ARCH=arm64\n'
            elif name == 'conf/initramfs.conf':
                expected = public('/etc/initramfs-tools/initramfs.conf')
                need(hashlib.sha256(expected).hexdigest() == 'e8dd8ab00c5c23384e388bcfe98c37fc3b5ee4beaf13f1194ac8545e7695243a',
                     'classic build configuration changed')
            elif name in FACTORY_IMAGE_INPUTS:
                sha, size, factory_mode = FACTORY_IMAGE_INPUTS[name]
                expected = policy.trusted_read('/' + name, policy.MAX_MEMORY_ENTRY)
                need(len(expected) == size and hashlib.sha256(expected).hexdigest() == sha and
                    mode == stat.S_IFREG | factory_mode and item['nlink'] == 1,
                    'classic generated factory input differs ' + name)
            elif name == 'conf/conf.d/default_root':
                expected = default_root_data()
            elif name == 'conf/modules':
                names = body.decode('ascii').splitlines()
                need(len(names) <= len(REQUESTED_LOCAL_MODULES) and len(names) == len(set(names)) and
                    set(names) <= REQUESTED_LOCAL_MODULES and body == ''.join(n + '\n' for n in names).encode(),
                    'classic forced module configuration unreviewed')
                expected = body
            elif name == 'cryptroot/crypttab':
                expected = verify_crypttab_data(body)
            elif name == 'etc/mdadm/mdadm.conf':
                expected = verify_mdadm_data(body)
            elif name == 'etc/motd':
                expected = b'To unlock root partition, and maybe others like swap, run `cryptroot-unlock`.\n'
            elif name == 'usr/share/plymouth/themes/ubuntu-text/ubuntu-text.plymouth':
                template_name = name + '.in'
                template = stock_source(template_name, public)
                release = stock_source('etc/os-release', public)
                version = re.findall(rb'^VERSION_ID="([0-9.]+)"$', release, re.M)
                need(len(version) == 1 and template.count(b'title=Ubuntu ') == 1,
                    'classic Plymouth producer input changed')
                expected = re.sub(rb'^title=Ubuntu .*$', b'title=Ubuntu ' + version[0], template, flags=re.M)
            elif name == 'etc/fstab':
                expected = b''
            elif name == 'etc/ld.so.cache':
                pass  # Checked against every admitted ELF below.
            elif name.startswith(module_prefix) and name[len(module_prefix):] in module_indices:
                pass  # Complete text and binary oracle check below.
            elif name.startswith(module_prefix):
                relative = name[len(module_prefix):]
                need(relative in ('modules.order', 'modules.builtin', 'modules.builtin.modinfo') or
                     re.fullmatch(r'kernel/[A-Za-z0-9_/+.-]+\.ko(?:\.(?:xz|gz|zst))?', relative),
                     'unknown classic kernel leaf ' + name)
                if '.ko' in relative:
                    need(policy.classic_local_module(name), 'unreviewed classic local module ' + name)
                expected = public('/' + name)
            elif '/' + name in policy.CLASSIC_LARGE_PUBLIC_FILES:
                need(isinstance(body, policy.StreamedBody), 'classic large body not streamed')
                source = policy.large_public_source('/' + name, mode, baseline, large_cache,
                    profile=policy.CLASSIC_PROFILE)
                need((body.size, body.sha256) == (source.size, source.sha256), 'classic large source differs')
                item['data'] = body = source
                source_hashes['/' + name] = body.sha256
            elif name in STOCK_ROLES:
                expected = stock_source(name, public)
                need(mode == stat.S_IFREG | STOCK_ROLES[name][3] and item['nlink'] == 1,
                     'classic stock role metadata ' + name)
            elif name.startswith('usr/bin/') and name[8:] in LOCAL_BINARIES:
                expected = builtin if body == builtin else public('/usr/lib/klibc/bin/' + name[8:])
                need(mode == stat.S_IFREG | 0o755, 'classic executable mode changed ' + name)
            elif name in EXTRA_EXECUTABLES or name in KL_INITRAMFS:
                expected = public(KL_INITRAMFS.get(name, '/' + name))
                need(mode == stat.S_IFREG | 0o755 and item['nlink'] == 1, 'classic executable metadata ' + name)
            elif '/' + name in {target for target, _ in policy.CLASSIC_GNU_TOOLS.values()}:
                if gnu_tools is None:
                    gnu_tools = classic_gnu_sources()
                source_name, (_, sha) = next((source, target) for source, target in gnu_tools.items() if target[0] == '/' + name)
                expected = public(source_name)
                need(hashlib.sha256(expected).hexdigest() == sha and mode == stat.S_IFREG | 0o755 and item['nlink'] == 1,
                     'classic GNU alias changed ' + name)
            elif name in PUBLIC_DATA or name in MODPROBE_FILES or name == 'usr/lib/modprobe.d/blacklist_linux_' + kernel + '.conf' or (
                    name.startswith('usr/lib/udev/rules.d/') and name.rsplit('/', 1)[1] in UDEV_RULES):
                expected = public('/' + name)
                if '/modprobe.d/' in name:
                    for line in expected.decode().splitlines():
                        if re.match(r'\s*(install|remove|softdep)\b', line):
                            need(line.strip() in ('install algif_aead /bin/false',
                                'softdep uhci-hcd pre: ehci-hcd',
                                'softdep ohci-hcd pre: ehci-hcd'), 'classic module action unreviewed')
            elif name.startswith('usr/lib/aarch64-linux-gnu/') and (
                    name.rsplit('/', 1)[1].split('.so')[0] in LIBRARIES or name.endswith('/ld-linux-aarch64.so.1')) or re.fullmatch(r'usr/lib/klibc-[A-Za-z0-9_-]+\.so', name):
                expected = public('/' + name)
            else:
                need(False, 'unknown classic image leaf ' + name)
            if name in ('conf/conf.d/default_root', 'conf/modules', 'cryptroot/crypttab',
                    'etc/mdadm/mdadm.conf', 'etc/motd',
                    'usr/share/plymouth/themes/ubuntu-text/ubuntu-text.plymouth'):
                need(mode == stat.S_IFREG | 0o644 and item['nlink'] == 1, 'classic generated role metadata')
            if expected is not None:
                need(body == expected, 'classic archive differs from source ' + name)
        files[name] = body.sha256 if isinstance(body, policy.StreamedBody) else hashlib.sha256(body).hexdigest()
    for name in (*payloads, *SCRIPT_PINS, 'etc/ld.so.cache', 'scripts/init-top/ORDER',
                 'scripts/init-bottom/ORDER', 'scripts/local-premount/ORDER',
                 'usr/bin/bash', 'usr/bin/busybox', 'usr/bin/sh', 'usr/bin/sleep',
                 *(target[1:] for target, _ in policy.CLASSIC_GNU_TOOLS.values())):
        need(name in entries, 'missing classic required leaf ' + name)
    # Vendor empty search/runtime directories grant no children or callbacks;
    # every non-directory leaf was independently classified above.
    parents = {'', '.', 'dev', 'proc', 'sys', 'run', 'tmp', 'var', 'root',
               'conf/conf.d', 'usr/lib.usr-is-merged', 'var/lib'}
    for name in files:
        parents.update(str(parent) for parent in Path(name).parents)
    for name, item in entries.items():
        need(not stat.S_ISDIR(item['mode']) or name in parents or
            factory_empty_directory(name, item, entries, kernel, source_hashes),
            'unknown classic empty directory ' + name)
    policy.verify_loader_cache(entries, profile=policy.CLASSIC_PROFILE)
    policy.verify_kernel_indices(entries, kernel, public, profile=policy.CLASSIC_PROFILE)
    need(policy.sha_file(image) == before, 'classic image changed during assessment')
    return dict(image_profile_verified=True, boot_profile=policy.CLASSIC_PROFILE,
        kernel=kernel, initrd_sha256=before, build_nonce=nonce, checked_policy_files=len(files),
        archive_projection_sha256=policy.digest(files), public_source_sha256=policy.digest(source_hashes),
        kernel_modules=sorted(name for name in entries if name.startswith(module_prefix) and
            re.search(r'\.ko(?:\.(?:xz|gz|zst))?$', name)),
        installed_acceptance=False, boot_acceptance=False)
