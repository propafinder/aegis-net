#!/usr/bin/env python3
"""Installed AUTO terminal BOOT carrier. Publication alone grants no network."""

import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess


SCHEMA = 'aegis_auto_terminal_boot_store_v1'
MARKER_SCHEMA = 'aegis_auto_terminal_boot_v1'
TRIAL_SCHEMA = 'aegis_auto_terminal_carrier_v1'
CONFIG_KEYS = frozenset(('schema', 'root_uuid', 'root_dev', 'root_source',
                         'boot_uuid', 'boot_dev', 'boot_source',
                         'run_mount_dir', 'boot_store_dir', 'hook_path',
                         'hook_sha256', 'helper_sha256'))
ROOT_PATH = '/'
HOOK_DIR = '/usr/lib/systemd/system-shutdown'
BOOT_STORE_DIR = 'aegis-auto-terminal'
STOCK_HOOKS = {
    'fwupd.shutdown': 'a04f3c8bfdc238da337de9a8875ab36aed3d2673af51cee65a62fa57e800001e',
    'mdadm.shutdown': '762a29b328b28172c95f6a1e202e0453410d0ccf3449fb17d0d5770852965ed5',
}
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
UUID = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z')
DEV = re.compile(r'[0-9]+:[0-9]+\Z')
TOKEN = re.compile(r'[0-9a-f]{32}\Z')
MS_REC, MS_PRIVATE, CLONE_NEWNS = 16384, 1 << 18, 0x00020000


class Refusal(RuntimeError):
    pass


def need(ok, reason):
    if not ok:
        raise Refusal(reason)


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def file_sha(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        a = os.fstat(fd)
        need(stat.S_ISREG(a.st_mode) and a.st_uid == 0 and a.st_nlink == 1 and
             a.st_size <= (1 << 22) and not a.st_mode & 0o022, 'source_metadata')
        h = hashlib.sha256()
        while True:
            data = os.read(fd, 65536)
            if not data:
                break
            h.update(data)
        b = os.fstat(fd)
        need((a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns) ==
             (b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns, b.st_ctime_ns),
             'source_changed')
        return h.hexdigest()
    finally:
        os.close(fd)


def parse_mountinfo(data):
    mounts = []
    for line in data.splitlines():
        left, sep, right = line.partition(' - ')
        need(bool(sep), 'mountinfo_format')
        a, b = left.split(), right.split()
        need(len(a) >= 6 and len(b) >= 3, 'mountinfo_fields')
        mounts.append(dict(dev=a[2], target=a[4], options=frozenset(a[5].split(',')),
                           fstype=b[0], source=b[1], super=frozenset(b[2].split(','))))
    return mounts


def mounts():
    return parse_mountinfo(Path('/proc/self/mountinfo').read_text())


def one_mount(rows, target):
    found = [r for r in rows if r['target'] == target]
    need(len(found) == 1, 'mount_not_unique')
    return found[0]


def dev_number(path):
    s = os.stat(path)
    need(stat.S_ISBLK(s.st_mode), 'source_not_block')
    return str(os.major(s.st_rdev)) + ':' + str(os.minor(s.st_rdev))


def blkid_uuid(source):
    p = subprocess.run(('/usr/sbin/blkid', '-o', 'value', '-s', 'UUID', source),
                       capture_output=True, timeout=3, check=False)
    need(p.returncode == 0 and not p.stderr and len(p.stdout) <= 64, 'blkid_failed')
    return p.stdout.decode('ascii', 'strict').strip().lower()


def check_config(c):
    need(type(c) is dict and set(c) == CONFIG_KEYS and c['schema'] == SCHEMA,
         'boot_config_schema')
    for key in ('root_uuid', 'boot_uuid'):
        need(type(c[key]) is str and UUID.fullmatch(c[key]) is not None,
             'boot_config_uuid')
    for key in ('root_dev', 'boot_dev'):
        need(type(c[key]) is str and DEV.fullmatch(c[key]) is not None,
             'boot_config_dev')
    for key in ('root_source', 'boot_source'):
        need(type(c[key]) is str and c[key].startswith('/dev/') and
             '\x00' not in c[key], 'boot_config_source')
    need(c['root_dev'] != c['boot_dev'] and c['root_uuid'].lower() != c['boot_uuid'].lower(),
         'boot_same_as_root')
    need(c['run_mount_dir'] == '/run/aegis-auto-terminal-boot-store' and
         c['boot_store_dir'] == BOOT_STORE_DIR and
         c['hook_path'] == HOOK_DIR + '/aegis-auto-terminal-hook', 'boot_config_paths')
    for key in ('hook_sha256', 'helper_sha256'):
        need(type(c[key]) is str and HEX64.fullmatch(c[key]) is not None,
             'boot_config_hash')


def validate_record(record):
    keys = {'schema', 'boot', 'nonce', 'action', 'final_job', 'final_job_type',
            'b_sha256', 'pid1_tick', 'ancestor_depth', 'witness_sha256',
            'a_record', 'clean_record', 'b_record', 'intent_sha256'}
    need(type(record) is dict and set(record) == keys and
         record.get('schema') == TRIAL_SCHEMA and
         record.get('final_job_type') == 'start' and
         record.get('action') in ('reboot', 'poweroff') and
         type(record.get('final_job')) is int and 0 < record['final_job'] < (1 << 32) and
         type(record.get('pid1_tick')) is int and 0 <= record['pid1_tick'] < (1 << 64) and
         type(record.get('ancestor_depth')) is int and 1 <= record['ancestor_depth'] <= 4 and
         type(record.get('boot')) is str and UUID.fullmatch(record['boot']) is not None and
         type(record.get('nonce')) is str and TOKEN.fullmatch(record['nonce']) is not None,
         'trial_record_schema')
    need(all(type(record[k]) is str and HEX64.fullmatch(record[k]) is not None
             for k in ('b_sha256', 'witness_sha256')) and
         all(type(record[k]) is dict for k in ('a_record', 'clean_record', 'b_record')) and
         type(record['intent_sha256']) is str and HEX64.fullmatch(record['intent_sha256']),
         'trial_record_fields')
    need(all(type(record['a_record'].get(key)) is str and
             HEX64.fullmatch(record['a_record'][key]) for key in
             ('active_generation_sha256','active_report_sha256',
              'boot_snapshot_sha256')),
         'terminal_lineage_invalid')
    need(len(canonical(record)) <= 6144, 'trial_record_oversize')
    # The guardian's clean-stop receipt is newline terminated; A and B are
    # compact JSON without a terminator. Preserve each exact byte hash.
    need(record['b_record'].get('clean_stop_sha256') ==
         hashlib.sha256(canonical(record['clean_record']) + b'\n').hexdigest() and
         record['b_record'].get('a_sha256') ==
         hashlib.sha256(canonical(record['a_record'])).hexdigest() and
         record['b_sha256'] ==
         hashlib.sha256(canonical(record['b_record'])).hexdigest(),
         'trial_record_byte_chain_changed')


def mdstat_idle(raw, block_names):
    need(type(raw) is bytes and 0 < len(raw) <= 4096, 'mdstat_bound')
    lines = raw.decode('ascii', 'strict').splitlines()
    need(2 <= len(lines) <= 32 and re.fullmatch(r'Personalities :(?: \[[A-Za-z0-9_-]+\])* *', lines[0]) is not None and
         lines[-1] == 'unused devices: <none>' and
         all(not line.strip() for line in lines[1:-1]) and
         type(block_names) is list and len(block_names) <= 4096 and
         all(type(name) is str and not name.startswith('md') for name in block_names),
         'md_arrays_present_or_mdstat_untrusted')


def stock_inert(c):
    # The fwupd hook exits before invoking fwupdtool when pending.db is absent.
    # Every parent must be an owned directory on the same ROOT filesystem.
    root_dev = os.stat('/').st_dev
    for name in ('/var', '/var/lib'):
        s = Path(name).lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == s.st_gid == 0 and
             not s.st_mode & 0o022 and s.st_dev == root_dev,
             'fwupd_parent_untrusted')
    fwupd_dir = Path('/var/lib/fwupd')
    try:
        s = fwupd_dir.lstat()
    except FileNotFoundError:
        s = None
    if s is not None:
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == s.st_gid == 0 and
             not s.st_mode & 0o022 and s.st_dev == root_dev,
             'fwupd_dir_untrusted')
        try:
            fwupd_dir.joinpath('pending.db').lstat()
        except FileNotFoundError:
            pass
        else:
            raise Refusal('fwupd_pending_exists')
    rows = mounts()
    need(one_mount(rows, '/proc')['fstype'] == 'proc' and
         one_mount(rows, '/sys')['fstype'] == 'sysfs', 'md_views_untrusted')
    try:
        fd = os.open('/proc/mdstat', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as exc:
        raise Refusal('mdstat_unavailable') from exc
    try:
        raw = os.read(fd, 4097)
    finally:
        os.close(fd)
    mdstat_idle(raw, [p.name for p in Path('/sys/class/block').iterdir()])


def preflight_sources(c):
    """Read-only stock admission before the first terminal site publication."""
    need(file_sha(__file__) == c['helper_sha256'], 'helper_hash_changed')
    d = Path(HOOK_DIR)
    ds = d.lstat()
    need(stat.S_ISDIR(ds.st_mode) and ds.st_uid == ds.st_gid == 0 and
         not ds.st_mode & 0o022, 'hook_dir_metadata')
    own_name = Path(c['hook_path']).name
    names = sorted(p.name for p in d.iterdir())
    stock_names = sorted(STOCK_HOOKS)
    need(names == stock_names or names == sorted([own_name, *stock_names]),
         'foreign_shutdown_hook')
    for name, expected in STOCK_HOOKS.items():
        path = d / name
        s = path.lstat()
        need(stat.S_ISREG(s.st_mode) and s.st_uid == s.st_gid == 0 and
             stat.S_IMODE(s.st_mode) == 0o755 and s.st_nlink == 1 and
             file_sha(path) == expected, 'stock_hook_changed')
    if own_name in names:
        own = Path(c['hook_path']).lstat()
        need(stat.S_ISREG(own.st_mode) and own.st_uid == own.st_gid == 0 and
             stat.S_IMODE(own.st_mode) == 0o755 and own.st_nlink == 1 and
             file_sha(c['hook_path']) == c['hook_sha256'], 'hook_changed')
    stock_inert(c)


def check_sources(c):
    need(file_sha(__file__) == c['helper_sha256'], 'helper_hash_changed')
    d = Path(HOOK_DIR)
    ds = d.lstat()
    need(stat.S_ISDIR(ds.st_mode) and ds.st_uid == ds.st_gid == 0 and
         not ds.st_mode & 0o022, 'hook_dir_metadata')
    names = sorted(p.name for p in d.iterdir())
    need(names == sorted([Path(c['hook_path']).name, *STOCK_HOOKS]),
         'foreign_shutdown_hook')
    for name, expected in STOCK_HOOKS.items():
        path = d / name
        s = path.lstat()
        need(stat.S_ISREG(s.st_mode) and s.st_uid == s.st_gid == 0 and
             stat.S_IMODE(s.st_mode) == 0o755 and s.st_nlink == 1 and
             file_sha(path) == expected, 'stock_hook_changed')
    own = Path(c['hook_path']).lstat()
    need(stat.S_ISREG(own.st_mode) and own.st_uid == own.st_gid == 0 and
         stat.S_IMODE(own.st_mode) == 0o755 and own.st_nlink == 1 and
         file_sha(c['hook_path']) == c['hook_sha256'], 'hook_changed')
    stock_inert(c)


def check_run():
    run = Path('/run')
    s = run.lstat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022,
         'run_untrusted')
    m = one_mount(mounts(), '/run')
    need(m['fstype'] == 'tmpfs' and 'rw' in m['options'] and 'rw' in m['super'],
         'run_not_rw_tmpfs')


def root_ro(c):
    row = one_mount(mounts(), ROOT_PATH)
    need(row['fstype'] == 'ext4' and row['dev'] == c['root_dev'] and
         row['source'] == c['root_source'] and
         dev_number(c['root_source']) == c['root_dev'] and
         blkid_uuid(c['root_source']) == c['root_uuid'].lower(), 'root_identity')
    need('ro' in row['options'] and 'rw' not in row['options'] and
         'ro' in row['super'] and 'rw' not in row['super'], 'root_not_ro')
    return row


def boot_unmounted(c):
    need(dev_number(c['boot_source']) == c['boot_dev'] and
         blkid_uuid(c['boot_source']) == c['boot_uuid'].lower(), 'boot_identity')
    need(all(r['dev'] != c['boot_dev'] for r in mounts()), 'boot_already_mounted')


def enter_private_mount_namespace():
    libc = ctypes.CDLL(None, use_errno=True)
    need(libc.unshare(CLONE_NEWNS) == 0, 'mount_namespace_unshare')
    need(libc.mount(None, b'/', None, MS_REC | MS_PRIVATE, None) == 0,
         'mount_namespace_private')


def secure_dir(path, expected_dev):
    s = path.lstat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid == s.st_gid == 0 and
         stat.S_IMODE(s.st_mode) == 0o700 and s.st_dev == expected_dev,
         'store_dir_metadata')


def publish_file(directory, filename, body):
    """Final name appears only after complete file fsync; dir fsync follows."""
    dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    final_created = False
    tmp = filename + '.tmp'
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=dfd)
        try:
            need(os.write(fd, body) == len(body), 'marker_short_write')
            os.fsync(fd)
        finally:
            os.close(fd)
        os.link(tmp, filename, src_dir_fd=dfd, dst_dir_fd=dfd, follow_symlinks=False)
        final_created = True
        os.unlink(tmp, dir_fd=dfd)
        os.fsync(dfd)
        fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
        try:
            s = os.fstat(fd)
            need(stat.S_ISREG(s.st_mode) and s.st_uid == s.st_gid == 0 and
                 stat.S_IMODE(s.st_mode) == 0o600 and s.st_nlink == 1 and
                 s.st_size == len(body), 'marker_metadata')
            need(hashlib.sha256(os.read(fd, 4097)).digest() == hashlib.sha256(body).digest(),
                 'marker_readback')
        finally:
            os.close(fd)
        return hashlib.sha256(body).hexdigest()
    except BaseException:
        if final_created:
            try:
                os.unlink(filename, dir_fd=dfd)
                os.fsync(dfd)
            except OSError:
                pass  # Caller must treat refusal as indeterminate; no grant.
        try:
            os.unlink(tmp, dir_fd=dfd)
        except OSError:
            pass
        raise
    finally:
        os.close(dfd)


def unpublish_file(directory, filename):
    dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.unlink(filename, dir_fd=dfd)
        os.fsync(dfd)
    finally:
        os.close(dfd)


def publish_terminal(config, record):
    """Publish an inert post-root-RO marker on this image's separate BOOT ext4.

    Caller must already have verified exact PID1/job/nonce/source chain. This
    function never edits AUTO state, EFI, bootloader, kernel, or initrd files.
    """
    c = dict(config)
    check_config(c)
    validate_record(record)
    need(os.geteuid() == 0, 'not_root')
    # Stock hooks run concurrently. If systemd left ROOT RW before hooks,
    # their prior behavior cannot be certified by a later remedial remount.
    check_run()
    root_ro(c)
    check_sources(c)
    boot_unmounted(c)
    enter_private_mount_namespace()
    check_run()
    root_ro(c)
    boot_unmounted(c)
    target = Path(c['run_mount_dir'])
    target.mkdir(mode=0o700)
    secure_dir(target, os.stat('/run').st_dev)
    mounted = False
    try:
        p = subprocess.run(('/usr/bin/mount', '-t', 'ext4', '-o', 'rw,nosuid,nodev,noexec',
                            c['boot_source'], str(target)), capture_output=True,
                           timeout=6, check=False)
        need(p.returncode == 0 and len(p.stdout) + len(p.stderr) <= 2048,
             'boot_mount_failed')
        mounted = True
        row = one_mount(mounts(), str(target))
        need(row['dev'] == c['boot_dev'] and row['fstype'] == 'ext4' and
             'rw' in row['options'] and 'rw' in row['super'] and
             dev_number(c['boot_source']) == c['boot_dev'] and
             blkid_uuid(c['boot_source']) == c['boot_uuid'].lower(),
             'boot_mount_identity')
        boot_dev = os.stat(target).st_dev
        store = target / c['boot_store_dir']
        secure_dir(store, boot_dev)
        # Every authority-relevant check precedes publication. The exact
        # marker remains inert until the fresh-boot transition consumes it.
        before = root_ro(c)
        check_sources(c)  # Recheck stock bytes and inert predicates after ROOT RO.
        need(root_ro(c) == before, 'root_changed_before_publication')
        marker = dict(schema=MARKER_SCHEMA, root_uuid=c['root_uuid'].lower(),
                      boot_uuid=c['boot_uuid'].lower(), root_dev=c['root_dev'],
                      boot_dev=c['boot_dev'], hook_sha256=c['hook_sha256'],
                      helper_sha256=c['helper_sha256'],
                      old_boot_id=record['boot'], nonce=record['nonce'],
                      action=record['action'], final_job=record['final_job'],
                      final_job_type=record['final_job_type'],
                      pid1_tick=record['pid1_tick'],
                      source_sha256=record['a_record']['source_sha256'],
                      intent_sha256=record['intent_sha256'],
                      a_sha256=hashlib.sha256(json.dumps(record['a_record'], sort_keys=True, separators=(',', ':')).encode('ascii')).hexdigest(),
                      clean_stop_sha256=record['b_record']['clean_stop_sha256'],
                      b_sha256=record['b_sha256'],
                      active_generation_sha256=record['a_record']['active_generation_sha256'],
                      active_report_sha256=record['a_record']['active_report_sha256'],
                      boot_snapshot_sha256=record['a_record']['boot_snapshot_sha256'],
                      policy_sha256=record['clean_record']['policy_sha256'])
        body = canonical(marker)
        need(len(body) <= 4096, 'marker_oversize')
        filename = 'terminal-' + record['boot'] + '-' + record['nonce'] + '.json'
        digest = publish_file(store, filename, body)
        try:
            after = root_ro(c)
            need(after == before, 'root_changed_after_publication')
        except BaseException:
            # This rollback is best effort if power fails at exactly this
            # point. Source-pinned exclusion of competing shutdown hooks is
            # therefore part of the qualified-host trust assumption.
            unpublish_file(store, filename)
            raise
        return digest
    finally:
        if mounted:
            # Hygiene only. Marker visibility/validity cannot depend on this
            # later operation without reintroducing a post-commit gap.
            try:
                subprocess.run(('/usr/bin/umount', str(target)), capture_output=True,
                               timeout=6, check=False)
            except (OSError, subprocess.TimeoutExpired):
                pass
