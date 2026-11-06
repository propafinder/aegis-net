#!/usr/bin/env python3
"""Bind a macOS app payload inventory to an exact reviewed stapled ZIP.

Pure held-file Mach-O parsing avoids invoking a mutable external reader.
This records shipped bytes and dynamic load commands, not static-link SBOM
completeness, active-extension identity, or independent notarization acceptance.
"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import stat
import struct
import subprocess
import zipfile

FILE_CAP = 64 << 20
TREE_CAP = 128 << 20
APPLEDOUBLE_CAP = 1 << 20
MACH_MAGICS = {b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xce\xfa\xed\xfe',
               b'\xfe\xed\xfa\xce', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca',
               b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca'}
DYLIB_COMMANDS = {0xc, 0x80000018, 0x8000001f, 0x20, 0x80000023}
FKEYS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
         'st_size', 'st_mtime_ns', 'st_ctime_ns')


def need(value, why):
    if not value:
        raise ValueError(why)


def facts(st):
    return tuple(getattr(st, k) for k in FKEYS)


def sha_fd(fd):
    n = os.fstat(fd).st_size
    need(0 <= n <= TREE_CAP, 'held_file_size_bound')
    h = hashlib.sha256()
    for offset in range(0, n, 1 << 20):
        chunk = os.pread(fd, min(1 << 20, n - offset), offset)
        need(len(chunk) == min(1 << 20, n - offset), 'held_file_shortened')
        h.update(chunk)
    need(not os.pread(fd, 1, n), 'held_file_grew')
    return h.hexdigest()


def opened_file(path, stack, cap=FILE_CAP, dir_fd=None):
    before = os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
         before.st_uid in (0, os.getuid()) and not before.st_mode & 0o022 and
         before.st_size <= cap, 'untrusted_file_custody')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    stack.callback(os.close, fd)
    need(facts(os.fstat(fd)) == facts(before), 'file_changed_during_open')
    return fd, facts(before)


def command_name(raw, offset, minimum):
    need(minimum <= offset < len(raw), 'native_name_offset')
    end = raw.find(b'\0', offset)
    need(end >= offset, 'native_name_unterminated')
    name = raw[offset:end].decode('ascii')
    need(0 < len(name) <= 4096 and all(32 <= ord(c) <= 126 for c in name), 'native_name_invalid')
    return name


def parse_macho(raw):
    need(len(raw) >= 32 and raw[:4] == b'\xcf\xfa\xed\xfe', 'only_thin_little_endian_macho64_supported')
    _, cpu, subtype, kind, count, size, flags, reserved = struct.unpack('<IiiIIIII', raw[:32])
    need(cpu == 0x100000c and kind in (2, 6, 8) and reserved == 0,
         'native_architecture_or_kind_refused')
    need(count <= 4096 and size <= 1 << 20 and 32 + size <= len(raw), 'native_command_bounds')
    pos, libraries, rpaths = 32, [], []
    for _ in range(count):
        need(pos + 8 <= 32 + size, 'native_command_header_short')
        command, length = struct.unpack('<II', raw[pos:pos + 8])
        need(length >= 8 and length % 8 == 0 and pos + length <= 32 + size,
             'native_command_length')
        data = raw[pos:pos + length]
        if command in DYLIB_COMMANDS:
            need(length >= 24, 'native_dylib_header_short')
            offset, timestamp, current, compat = struct.unpack('<IIII', data[8:24])
            libraries.append({'name': command_name(data, offset, 24), 'load_command': command,
                              'current_version': current, 'compatibility_version': compat})
        elif command == 0x8000001c:
            need(length >= 16, 'native_rpath_header_short')
            rpaths.append(command_name(data, struct.unpack('<I', data[8:12])[0], 12))
        pos += length
    need(pos == 32 + size, 'native_command_roster_incomplete')
    return {'architecture': 'aarch64-apple-darwin', 'cpu_subtype': subtype, 'file_type': kind,
            'dynamic_libraries': libraries, 'rpaths': rpaths}


def held_tree(bundle, stack):
    need(bundle.resolve() == bundle and bundle.suffix == '.app', 'bundle_path_alias')
    checks, files, directories, total = [], {}, {}, 0

    def walk(path, fd, rel):
        nonlocal total
        before = facts(os.fstat(fd))
        need(stat.S_ISDIR(before[2]) and before[3] in (0, os.getuid()) and
             not before[2] & 0o022, 'untrusted_bundle_directory')
        directories['' if rel == PurePosixPath('.') else rel.as_posix()] = stat.S_IMODE(before[2])
        names = sorted(os.listdir(fd))
        need(len(names) <= 4096, 'directory_member_bound')
        checks.append((path, fd, before, names))
        for name in names:
            need(name not in ('.', '..') and '/' not in name, 'bundle_member_name')
            child = path / name
            relative = (rel / name).as_posix()
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                cfd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                stack.callback(os.close, cfd)
                need(facts(os.fstat(cfd)) == facts(st), 'bundle_directory_changed')
                walk(child, cfd, rel / name)
            else:
                cfd, gen = opened_file(name, stack, dir_fd=fd)
                total += gen[6]
                need(total <= TREE_CAP and len(files) < 4096, 'bundle_size_bound')
                data = os.pread(cfd, gen[6], 0)
                need(len(data) == gen[6], 'bundle_file_short')
                files[relative] = {'fd': cfd, 'facts': gen, 'parent_fd': fd, 'name': name,
                                   'size': gen[6], 'mode': stat.S_IMODE(gen[2]),
                                   'sha256': hashlib.sha256(data).hexdigest()}
                if data[:4] in MACH_MAGICS:
                    files[relative]['native'] = parse_macho(data)
    fd = os.open(bundle, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    stack.callback(os.close, fd)
    walk(bundle, fd, PurePosixPath('.'))

    def recheck():
        for path, fd, gen, names in checks:
            need(facts(os.fstat(fd)) == gen and facts(path.lstat()) == gen and
                 sorted(os.listdir(fd)) == names, 'bundle_directory_generation_changed')
        for row in files.values():
            need(facts(os.fstat(row['fd'])) == row['facts'] and
                 facts(os.stat(row['name'], dir_fd=row['parent_fd'], follow_symlinks=False)) == row['facts'] and
                 sha_fd(row['fd']) == row['sha256'], 'bundle_file_generation_changed')
    return files, directories, recheck


def apple_double(raw):
    """Admit the AppleDouble shape ditto writes, while retaining its whole hash.

    Entry 9 carries FinderInfo and extended attributes. Entry 2 is the empty
    resource fork in the reviewed product ZIP. A nonempty fork or another ID
    needs a separate review before it can be treated as package metadata.
    """
    need(50 <= len(raw) <= APPLEDOUBLE_CAP and raw[:4] == bytes.fromhex('00051607')
         and raw[4:8] == bytes.fromhex('00020000')
         and raw[8:24] == b'Mac OS X        ', 'appledouble_header')
    count = struct.unpack_from('>H', raw, 24)[0]
    need(count == 2 and 26 + count * 12 == 50, 'appledouble_entry_count')
    first = struct.unpack_from('>III', raw, 26)
    second = struct.unpack_from('>III', raw, 38)
    need(first[0] == 9 and first[1] == 50 and 32 <= first[2] <= APPLEDOUBLE_CAP - 50
         and second == (2, 50 + first[2], 0)
         and 50 + first[2] == len(raw), 'appledouble_entry_table')
    return [{'id': first[0], 'offset': first[1], 'length': first[2]},
            {'id': second[0], 'offset': second[1], 'length': second[2]}]


def zip_inventory(archive, bundle_name):
    files, metadata, directories, total = {}, {}, {}, 0
    entries = archive.infolist()
    need(len(entries) <= 4096, 'zip_member_bound')
    seen, normalized = set(), set()
    product_dirs = {}
    metadata_pairs = []
    for entry in entries:
        p = PurePosixPath(entry.filename)
        need(not p.is_absolute() and '..' not in p.parts and p.parts and
             str(p) == entry.filename.rstrip('/') and entry.filename not in seen and
             str(p) not in normalized,
             'zip_path_or_duplicate_refused')
        seen.add(entry.filename)
        normalized.add(str(p))
        need(p.parts[0] in (bundle_name, '__MACOSX'), 'unexpected_zip_root')
        is_meta = p.parts[0] == '__MACOSX'
        if is_meta:
            need(len(p.parts) >= 2 and p.parts[1] == bundle_name or
                 entry.filename == '__MACOSX/', 'appledouble_root')
        mode = entry.external_attr >> 16
        if entry.is_dir():
            need(stat.S_ISDIR(mode) and entry.file_size == 0 and not archive.read(entry),
                 'untrusted_zip_directory')
            if not is_meta:
                product_dirs[str(p)] = stat.S_IMODE(mode)
                paired = str(p)
            else:
                paired = PurePosixPath(*p.parts[1:]).as_posix() if len(p.parts) > 1 else ''
                metadata_pairs.append((entry.filename, paired))
            directories[entry.filename] = {'size': 0, 'mode': stat.S_IMODE(mode),
                                           'paired_with': paired}
            continue
        need(stat.S_ISREG(mode) and not mode & 0o022 and
             entry.file_size <= (APPLEDOUBLE_CAP if is_meta else FILE_CAP),
             'untrusted_zip_file')
        total += entry.file_size
        need(total <= TREE_CAP, 'zip_expansion_bound')
        data = archive.read(entry)
        need(len(data) == entry.file_size, 'zip_payload_short')
        digest = hashlib.sha256(data).hexdigest()
        if is_meta:
            need(len(p.parts) >= 3 and p.parts[-1].startswith('._') and
                 len(p.parts[-1]) > 2, 'appledouble_path')
            paired = PurePosixPath(*p.parts[1:-1], p.parts[-1][2:]).as_posix()
            metadata_pairs.append((entry.filename, paired))
            metadata[entry.filename] = {'kind': 'appledouble', 'size': len(data),
                                        'mode': stat.S_IMODE(mode), 'sha256': digest,
                                        'paired_with': paired, 'entries': apple_double(data)}
        else:
            rel = PurePosixPath(*p.parts[1:]).as_posix()
            need(rel not in files, 'duplicate_zip_payload')
            files[rel] = {'size': len(data), 'mode': stat.S_IMODE(mode), 'sha256': digest}
    for name, paired in metadata_pairs:
        need(not paired or paired in product_dirs or
             (paired.startswith(bundle_name + '/') and
              paired[len(bundle_name) + 1:] in files),
             'appledouble_unpaired')
    return files, metadata, directories, product_dirs


def executable_roster(files, version):
    expected = {}
    for contents, identifier, kind in (
        ('Contents', 'dev.aegis.macos', 'APPL'),
        ('Contents/Library/SystemExtensions/dev.aegis.macos.PacketTunnel.systemextension/Contents',
         'dev.aegis.macos.PacketTunnel', 'SYSX'),
    ):
        row = files[contents + '/Info.plist']
        info = plistlib.loads(os.pread(row['fd'], row['size'], 0))
        executable = info.get('CFBundleExecutable')
        need(isinstance(executable, str) and re.fullmatch(r'[A-Za-z0-9_-][A-Za-z0-9_.-]*', executable),
             'bundle_executable_name_invalid')
        need(info.get('CFBundleIdentifier') == identifier and info.get('CFBundlePackageType') == kind
             and info.get('CFBundleVersion') == version, 'bundle_executable_metadata_differs')
        path = contents + '/MacOS/' + executable
        need(path in files and files[path].get('native', {}).get('file_type') == 2
             and files[path]['mode'] & 0o111, 'declared_bundle_executable_missing_or_not_native')
        expected[path] = files[path]['native']
    need(set(expected) == {name for name, row in files.items() if 'native' in row},
         'unclassified_native_payload')
    return expected


def inspect(bundle, archive_path, archive_pin, receipt_path, receipt_pin, source,
            phase='installed'):
    need(re.fullmatch('[0-9a-f]{64}', archive_pin) and re.fullmatch('[0-9a-f]{64}', receipt_pin)
         and re.fullmatch('[0-9a-f]{40}', source), 'explicit_pins_required')
    need(phase in ('installed', 'staged-preinstall'), 'inventory_phase')
    with ExitStack() as stack:
        rfd, rgen = opened_file(receipt_path, stack, cap=1 << 20)
        need(sha_fd(rfd) == receipt_pin, 'build_receipt_pin_mismatch')
        receipt = json.loads(os.pread(rfd, rgen[6], 0))
        need(receipt['commit'] == source and receipt['source_dirty'] is False and
             receipt['binaries_source'] == 'build-stage' and
             receipt['stapled_zip_sha256'] == archive_pin and
             receipt['notary_status'] == 'Accepted', 'build_receipt_admission')
        previous = -1
        for stage in ('build', 'assemble', 'sign', 'verify', 'zip', 'notarize', 'staple', 'assess'):
            rows = [(i, s) for i, s in enumerate(receipt['stages']) if s['stage'] == stage]
            need(rows and rows[-1][1]['status'] == 'ok' and rows[-1][0] > previous,
                 'build_stage_not_ok_or_stale')
            previous = rows[-1][0]
        if phase == 'staged-preinstall':
            run = Path(receipt['run_dir'])
            need(run.is_absolute() and run.parent == receipt_path.parent.parent / 'runs' and
                 run.name.startswith('v44-') and run.name.endswith('-' + source[:12]) and
                 receipt_path == receipt_path.parent / (run.name + '.json') and
                 bundle == run / 'bundle' / 'AEGIS.app' and
                 archive_path == Path(receipt['stapled_zip']) and
                 receipt.get('installed') is False,
                 'staged_preinstall_receipt_and_bundle_path')
        else:
            need(receipt.get('installed') is True and
                 bundle == Path(receipt.get('installed_path', '')) and
                 bundle == Path('/Applications/AEGIS.app') and
                 archive_path == Path(receipt['stapled_zip']) and
                 receipt.get('installed_zip_sha256') == archive_pin,
                 'installed_bundle_receipt_and_path')
        afd, agen = opened_file(archive_path, stack, cap=TREE_CAP)
        need(sha_fd(afd) == archive_pin, 'stapled_zip_pin_mismatch')
        files, installed_dirs, recheck = held_tree(bundle, stack)
        with os.fdopen(os.dup(afd), 'rb') as stream, zipfile.ZipFile(stream) as archive:
            declared, archive_metadata, archive_directories, product_dirs = zip_inventory(archive, bundle.name)
        need(set(files) == set(declared), 'installed_zip_file_roster_differs')
        zip_dirs = {name[len(bundle.name):].lstrip('/'): mode for name, mode in product_dirs.items()}
        need(zip_dirs == installed_dirs, 'installed_zip_directory_roster_differs')
        for name, expected in declared.items():
            need(all(files[name][k] == v for k, v in expected.items()), 'installed_zip_file_differs')
        info = plistlib.loads(os.pread(files['Contents/Info.plist']['fd'], files['Contents/Info.plist']['size'], 0))
        need(info['CFBundleVersion'] == receipt['bundle_version'], 'installed_bundle_version_differs')
        natives = executable_roster(files, receipt['bundle_version'])
        for name, native in natives.items():
            for lib in native['dynamic_libraries']:
                lib['scope'] = ('apple_system_runtime' if lib['name'].startswith(('/usr/lib/', '/System/Library/Frameworks/'))
                                else 'unresolved_native_dependency')
                need(lib['scope'] != 'unresolved_native_dependency', 'native_dependency_requires_explicit_payload_resolution')
        recheck()
        need(facts(os.fstat(afd)) == agen and facts(archive_path.lstat()) == agen and sha_fd(afd) == archive_pin,
             'archive_generation_changed')
        need(facts(os.fstat(rfd)) == rgen and facts(receipt_path.lstat()) == rgen and sha_fd(rfd) == receipt_pin,
             'receipt_generation_changed')
        result = {'schema': 'aegis_macos_shipped_payload_inventory_v1', 'source_commit': source,
                'bundle_version': info['CFBundleVersion'], 'stapled_zip_sha256': archive_pin,
                'build_receipt_sha256': receipt_pin, 'installed_bundle_matches_zip': True,
                'files': {n: {k: r[k] for k in ('size', 'mode', 'sha256')} for n, r in files.items()},
                'archive_metadata': archive_metadata,
                'archive_directories': archive_directories,
                'archive_counts': {'total_members': len(declared) + len(archive_metadata) + len(archive_directories),
                                   'files': len(declared), 'metadata_files': len(archive_metadata),
                                   'directories': len(archive_directories)},
                'native_payloads': natives, 'static_native_and_rust_sbom_complete': False,
                'independent_notarization_verified': False, 'active_extension_verified': False,
                'runtime_or_release_acceptance': False}
        if phase == 'staged-preinstall':
            del result['installed_bundle_matches_zip']
            result['schema'] = 'aegis_macos_staged_payload_inventory_v1'
            result['staged_bundle_matches_zip'] = True
            result['staged_bundle_path'] = str(bundle)
            result['installed_acceptance'] = False
        return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bundle', type=Path, required=True)
    p.add_argument('--stapled-zip', type=Path, required=True)
    p.add_argument('--zip-sha256', required=True)
    p.add_argument('--build-receipt', type=Path, required=True)
    p.add_argument('--receipt-sha256', required=True)
    p.add_argument('--source-commit', required=True)
    p.add_argument('--phase', choices=('installed', 'staged-preinstall'), default='installed')
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    result = inspect(args.bundle, args.stapled_zip, args.zip_sha256, args.build_receipt,
                     args.receipt_sha256, args.source_commit, args.phase)
    repo = Path(__file__).resolve().parents[2]
    result['inventory_operator_commit'] = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True, timeout=10).strip()
    need(not subprocess.check_output(['git', '-C', str(repo), 'status', '--porcelain'], timeout=15), 'operator_source_dirty')
    with args.output.open('x') as f:
        os.chmod(args.output, 0o600)
        json.dump(result, f, sort_keys=True, indent=2)
        f.write('\n')
    print(json.dumps({'files': len(result['files']), 'native_payloads': len(result['native_payloads']),
                      'phase': args.phase, 'bundle_matches_zip': True,
                      'full_sbom_acceptance': False}))
