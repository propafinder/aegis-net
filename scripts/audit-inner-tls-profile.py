#!/usr/bin/env python3
"""Read-only comparison of explicitly selected deployment roles with Git files."""
import argparse
import hashlib
import json
import pathlib
import stat
import sys

ROLES = {
    'relay': ['aegis-device-policy-sync.timer.d/onboarding.conf', 'aegis-server-v3.service.d/recovery.conf'],
    'authority': ['aegis-enrollment-policy-stage.timer.d/onboarding.conf'],
    'ingress': ['aegis-v3-online.target', 'aegis-front-v3.service.d/ingress-recovery.conf', 'aegis-v3-dispatch.service.d/ingress-recovery.conf'],
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role', choices=ROLES, action='append', required=True)
    parser.add_argument('--systemd-dir', type=pathlib.Path, default=pathlib.Path('/etc/systemd/system'))
    args = parser.parse_args()
    source = pathlib.Path(__file__).resolve().parent.parent / 'packaging/systemd/profiles/inner-tls'
    records = []
    for name in sorted({name for role in args.role for name in ROLES[role]}):
        expected = (source / name).read_bytes()
        target = args.systemd_dir / name
        row = {'path': name, 'source_sha256': hashlib.sha256(expected).hexdigest()}
        try:
            # Refuse symlinks, including a linked drop-in directory. Never follow
            # an unexpected path and accidentally read unrelated private state.
            for part in (target, *target.parents):
                if part == args.systemd_dir:
                    break
                if part.is_symlink():
                    raise ValueError('symlink')
            metadata = target.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 65536:
                raise ValueError('not a bounded regular unit file')
            actual = target.read_bytes()
            row.update(deployed_sha256=hashlib.sha256(actual).hexdigest(),
                       status='MATCH' if actual == expected else 'DIFF',
                       uid=metadata.st_uid, mode=oct(stat.S_IMODE(metadata.st_mode)))
        except FileNotFoundError:
            row['status'] = 'MISSING'
        except (OSError, ValueError) as error:
            row.update(status='UNREADABLE', error_type=type(error).__name__)
        records.append(row)
    ok = all(row['status'] == 'MATCH' for row in records)
    print(json.dumps({'schema': 'aegis_deployment_profile_audit_v1',
                      'status': 'MATCH' if ok else 'DRIFT', 'roles': sorted(set(args.role)),
                      'writes_performed': False, 'files': records}, indent=2))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
