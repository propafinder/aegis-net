#!/usr/bin/env python3
"""Explicit local-root initrd policy, strict archive profile and reversible owner.

No image or embedded key is exported. Backups remain root-private outside /boot.
An applied policy cannot authorize this boot: the nonce and boot transition must
both be proved by the ordinary boot assessment after a normal reboot.
"""
from __future__ import annotations
import argparse
import contextlib
import errno
from dataclasses import dataclass
import fcntl
import hashlib
import gzip
import io
import json
import os
from pathlib import Path
import posixpath
import re
import shlex
import signal
import stat
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aegis_auto_foreign_policy import trusted_read, need, decode, digest

PROFILE = 'dracut-110-deb-local-v1'
REVIEWED_DRACUT = '110-11ubuntu0.1'
BACKUP = Path('/var/lib/aegis-install/boot-backup')
MANIFEST = BACKUP / 'manifest.json'
DROPIN = Path('/etc/dracut.conf.d/99-aegis-no-initrd-network.conf')
GATE = Path('/usr/lib/dracut/modules.d/99aegis-initrd-gate')
HOOK = Path('/etc/kernel/postinst.d/zy-aegis-initrd-assess')
PREHOOK = Path('/etc/kernel/postinst.d/00-aegis-initrd-space')
GRUB_REFUSAL = Path('/etc/default/grub.d/99-aegis-initrd-refusal.cfg')
HERE = Path(__file__).resolve().parent
OMIT = frozenset(('network', 'network-legacy', 'network-manager', 'connman',
    'systemd-networkd', 'systemd-network-management', 'systemd-resolved',
    'dyn-netconf', 'dyn-netconfd', 'net-lib', 'url-lib', 'livenet', 'iscsi', 'nfs',
    'nbd', 'nvmf', 'cifs', 'fcoe', 'fcoe-uefi', 'ssh-client', 'qemu-net',
    'kernel-network-modules'))
LOCAL_MODULES = frozenset(('console-setup', 'dash', 'bash', 'systemd',
    'systemd-ask-password', 'systemd-battery-check', 'systemd-initrd',
    'systemd-journald', 'systemd-modules-load', 'systemd-pcrextend',
    'systemd-sysctl', 'systemd-tmpfiles', 'systemd-udevd', 'i18n', 'plymouth',
    'simpledrm', 'copymods', 'overlayroot', 'fs-lib', 'kernel-modules',
    'kernel-modules-export', 'kernel-modules-extra', 'overlayfs', 'qemu',
    'overlayfs-crypt', 'rootfs-block', 'terminfo', 'udev-rules', 'virtfs',
    'virtiofs', 'dracut-systemd', 'initqueue', 'usrmount', 'systemd-sysusers',
    'base', 'shell-interpreter', 'shutdown', 'aegis-initrd-gate', 'dm', 'lvm',
    'mdraid', 'crypt', 'resume', 'btrfs', 'kernel-modules-storage', 'fips'))
NETWORK_KEYS = frozenset(('ip', 'ip6', 'nfsroot', 'BOOTIF', 'BOOTIF_DEFAULT',
    'vlan', 'rd.neednet', 'rd.iscsi.initiator', 'ISCSI_AUTO', 'ISCSI_INITIATOR',
    'iscsi', 'fetch', 'url', 'overlayroot', 'overlayroot_cfgdisk', 'netroot', 'rd.znet', 'ifname',
    'bond', 'bridge', 'rd.peerdns', 'rd.server', 'netconsole', 'modules_load',
    'rd.modules_load', 'rd.driver.pre', 'rd.driver.post', 'kgdboe'))
# Unknown undotted KEY=value arguments become PID1 environment entries.
# Reject the complete LD_ namespace, including options added by a future libc.
BOOT_ENVIRONMENT_KEYS = frozenset(('GLIBC_TUNABLES', 'GCONV_PATH', 'LOCPATH',
    'NLSPATH', 'BASH_ENV', 'ENV', 'CDPATH', 'GLOBIGNORE', 'SHELLOPTS', 'BASHOPTS'))
BOOT_ESCAPE_KEYS = frozenset(('break', 'debug', 'rd.break', 'rd.shell', 'rd.debug', 'rdinit'))
# The parent is the signed /bin/sh, not Bash. Clear known loader inputs with
# its builtins before executing another ELF; a child-side unset is too late.
# Remaining LD_* names are refused by the early gate before root is mounted.
CLASSIC_LOADER_ENVIRONMENT = tuple(sorted(BOOT_ENVIRONMENT_KEYS)) + (
    'LD_ASSUME_KERNEL', 'LD_AUDIT', 'LD_BIND_NOT', 'LD_BIND_NOW', 'LD_CONFIG_FILE',
    'LD_DEBUG', 'LD_DEBUG_OUTPUT', 'LD_DYNAMIC_WEAK', 'LD_HWCAP_MASK',
    'LD_LIBRARY_PATH', 'LD_ORIGIN_PATH', 'LD_POINTER_GUARD', 'LD_PREFER_MAP_32BIT_EXEC',
    'LD_PRELOAD', 'LD_PROFILE', 'LD_PROFILE_OUTPUT', 'LD_SHOW_AUXV',
    'LD_TRACE_LOADED_OBJECTS', 'LD_USE_LOAD_BIAS', 'LD_VERBOSE', 'LD_WARN')
KERNEL = re.compile(r'[A-Za-z0-9_.+-]{1,128}\Z')
REVIEWED_DRACUT_CONFIG = {
    '/usr/lib/dracut/dracut.conf.d/01-debian.conf':
        '2b420d300a1755135d44bcf7fb1e19fd7e1236d725eb8c0bf2db004751bc9a98',
    '/usr/lib/dracut/dracut.conf.d/50-snapd.conf':
        'f7d4b0833f34b248497465876eece8e4bda4eb8ce25b275aeb99e23a5746326c',
}
# The complete Ubuntu 26.04 cloud-init 26.2-0ubuntu1~26.04.1 unit set. Its
# cloud-init-main.service runs every stage (DefaultDependencies=no), so a
# partial pin set could not prove the marker profile.
CLOUD_DISABLED_PINS = {
    '/usr/lib/systemd/system/cloud-init-main.service':
        'd27b6d41b68370bbc8572f9bd5c311803fa8a3c1491a4297fd48f2fa4fc929d0',
    '/usr/lib/systemd/system/cloud-init-local.service':
        '36130771749618b30dac345ad344b20e7ba58ce8ca924e2c4829e8d6e652096d',
    '/usr/lib/systemd/system/cloud-init-network.service':
        'b7fd53cb5e503397266f24fc64a68c107f87160892587101e2ce37200120d6bb',
    '/usr/lib/systemd/system/cloud-config.service':
        '6cd84a65fdf53697f552fae5527b38f10863372aa58bfcbf9aa15b87ebc20e43',
    '/usr/lib/systemd/system/cloud-final.service':
        '3c2de66f60b26e3482d441f1580068fd2019ee2623fe648ca9a4f5d8e406ce14',
    '/usr/lib/systemd/system/cloud-init-hotplugd.service':
        '256c9f14673a5a642da2036e36914a45c34e7ad8a944f2f55fbd1b7beb8e6f62',
    '/usr/lib/systemd/system/cloud-init-hotplugd.socket':
        '1810b1c81f31103442b594cd117fe65bbe72730d89e1d5150954cc948d794fa8',
    '/usr/lib/systemd/system/cloud-init.target':
        'd9fdbc55f79e76333ce010f530e70fbc1f6d80370fc17e2021656fc709bc54a5',
    '/usr/lib/systemd/system/cloud-config.target':
        '6d6d9d13579f3714344cc236b02f4d952df14de63832b204836ca34cc91477d1',
    '/usr/lib/systemd/system-generators/cloud-init-generator':
        'cfc54cf84dbd88c112c297edd656261e344af96f1a3edc39353c70be72a339e9',
}
CLOUD_DISABLED_NOBLE_PINS = {
    '/usr/lib/systemd/system/cloud-init-local.service':
        '8c6f5b441d1ae1a9d181fd3c607914174da2c404fac22e98b7573b24ad722b42',
    '/usr/lib/systemd/system/cloud-init.service':
        'e13dd95a7bfac6407ea1ce45ed6683c0f4e84c791840d305c937d38ae77d9456',
    '/usr/lib/systemd/system/cloud-config.service':
        '70c670f46eea29fb91a44dddf0af86db149bd7da065b8c98410102c07c086649',
    '/usr/lib/systemd/system/cloud-final.service':
        '96b9a7b8a74af189954aa04dc589b0e4fbf9e0d725f3f0fa7ca5ab05e6204a24',
    '/usr/lib/systemd/system/cloud-init-hotplugd.service':
        '256c9f14673a5a642da2036e36914a45c34e7ad8a944f2f55fbd1b7beb8e6f62',
    '/usr/lib/systemd/system/cloud-init-hotplugd.socket':
        '1810b1c81f31103442b594cd117fe65bbe72730d89e1d5150954cc948d794fa8',
    '/usr/lib/systemd/system/cloud-init.target':
        'd9fdbc55f79e76333ce010f530e70fbc1f6d80370fc17e2021656fc709bc54a5',
    '/usr/lib/systemd/system/cloud-config.target':
        '690af815242250b1b46764d8f03e0b1b3b416b8d6b39d39e0f43a46df28a3780',
    '/usr/lib/systemd/system-generators/cloud-init-generator':
        'cfc54cf84dbd88c112c297edd656261e344af96f1a3edc39353c70be72a339e9',
}
CLOUD_INDICATORS = (
    '/usr/bin/cloud-init', '/bin/cloud-init', '/usr/local/bin/cloud-init',
    '/usr/lib/systemd/system/cloud-init-main.service',
    '/usr/lib/systemd/system/cloud-init-local.service',
    '/usr/lib/systemd/system/cloud-init-network.service',
    '/usr/lib/systemd/system/cloud-init.service',
    '/usr/lib/systemd/system/cloud-config.service',
    '/usr/lib/systemd/system/cloud-final.service',
    '/usr/lib/systemd/system/cloud-init-hotplugd.service',
    '/usr/lib/systemd/system/cloud-init-hotplugd.socket',
    '/usr/lib/systemd/system/cloud-init.target',
    '/usr/lib/systemd/system/cloud-config.target',
    '/lib/systemd/system/cloud-init-local.service',
    '/lib/systemd/system/cloud-init-network.service',
    '/etc/systemd/system/cloud-init-local.service',
    '/etc/systemd/system/cloud-init-network.service',
    '/usr/lib/systemd/system-generators/cloud-init-generator',
    '/lib/systemd/system-generators/cloud-init-generator',
)
# Every systemd unit and generator search path. /usr/lib precedes /lib so a
# merged-/usr alias is reported once under its canonical name.
CLOUD_UNIT_DIRS = (
    '/etc/systemd/system.control', '/run/systemd/system.control',
    '/run/systemd/transient', '/run/systemd/generator.early', '/etc/systemd/system',
    '/run/systemd/system', '/run/systemd/generator', '/usr/local/lib/systemd/system',
    '/usr/lib/systemd/system', '/lib/systemd/system', '/run/systemd/generator.late',
)
CLOUD_GENERATOR_DIRS = (
    '/run/systemd/system-generators', '/etc/systemd/system-generators',
    '/usr/local/lib/systemd/system-generators', '/usr/lib/systemd/system-generators',
    '/lib/systemd/system-generators',
)
CLOUD_UNIT_PREFIXES = ('cloud-init', 'cloud-config', 'cloud-final')
CLOUD_UNIT_PATTERNS = ('cloud-init*', 'cloud-config*', 'cloud-final*')
CLOUD_MARKER = '/etc/cloud/cloud-init.disabled'
CLOUD_CONDITION = b'ConditionPathExists=!/etc/cloud/cloud-init.disabled\n'
CLOUD_LOCAL_ROOT_FS = ('ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'f2fs')
CLOUD_BOOTSTRAP_EDGE = '/etc/systemd/system/cloud-final.service.wants/snapd.seeded.service'
CLOUD_BOOTSTRAP_TARGET = '/usr/lib/systemd/system/snapd.seeded.service'
CLOUD_BOOTSTRAP_JOURNAL = '/var/lib/aegis-install/cloud-bootstrap-detachment.json'
# Frozen Noble source control flow, not an admission of a new boot backend.
# Image production, vendor provenance and installed classic validation are
# required separately before this factory can authorize a profile.
CLASSIC_REVIEWED_CORE = '0.142ubuntu25.8'
CLASSIC_PROFILE = 'initramfs-tools-0.142ubuntu25.8-arm64-local-v1'
# Ubuntu noble-updates libssl3t64 3.0.13-0ubuntu3.16 arm64, downloaded
# through signature-verified APT. Factory DEB SHA256
# 8b2dff5ee02f3e1eaaf8106ff372c5ba61b88ee57b7658e163a2de0b90b4956e.
# Separate from the dracut profile: neither path set nor digest is inherited.
CLASSIC_LARGE_PUBLIC_FILES = {
    '/usr/lib/aarch64-linux-gnu/libcrypto.so.3': ('libssl3t64',
        'b27a2396652ee28629c94d59d667c417dbffdf2dee84e5bf140bd17d3eedb7d9',
        4663464, 0o644),
    # libstdc++6 14.2.0-4ubuntu2~24.04.1 arm64, signed APT DEB
    # f84a05ac45a6884109b6527e911081a38263b89e042fc94a338cf975f61a330c.
    '/usr/lib/aarch64-linux-gnu/libstdc++.so.6.0.33': ('libstdc++6',
        '6e3112d35cfc86db7ee85b27e1746f67408e2837ff8628b46386c3eabd5682a4',
        2633224, 0o644),
    '/usr/sbin/lvm': ('lvm2',
        '987de8fca36168ca8c95361b4517112e9e3cd265bd732d299ec848fcdcfb2d9f', 3196312, 0o755),
}
CLASSIC_BOOT_SOURCE_PINS = {
    'init': '26f5f5a706dd766158c01c7a9f4c75814a77519e9a4f7489a3cf8cf6312e8aef',
    'scripts/functions': '6358cb0bc4784bb8dc13d5c9beaf65d5e88f51c9a459daeed0f1311bfc07aa96',
}
CLASSIC_GATE_HELPER = '/usr/lib/aegis/initrd-cloud-classic.sh'
CLASSIC_CMDLINE_HELPER = '/usr/lib/aegis/initrd-cmdline-classic.sh'
CLASSIC_CMDLINE_SOURCE = '/proc/cmdline'
# Noble-updates coreutils 9.4-3ubuntu6.3 arm64, signature-verified APT
# payload SHA256 1a0b163febf032934ecc3c7a71769c90a9b68cdbdd8c3afa7f3ef985b4c962da.
CLASSIC_GNU_TOOLS = {
    '/usr/bin/stat': ('/usr/bin/gnustat',
        'cb620f40df0a87f49ffa0b2e3f587f26a0f7040c42d2e4955a32952196389ae1'),
    '/usr/bin/readlink': ('/usr/bin/gnureadlink',
        'ca85270bfc923c930577f93d5123ce9d09193df7d8ed040c80b5ab8ff99d2fc5'),
    '/usr/bin/sha256sum': ('/usr/bin/gnusha256sum',
        'a077f232a92c082920430659ec57b49a388b3564c4f4f512698d9cbd6e7512a9'),
}
# Snapshot 20260705 noble-updates: signed InRelease -> Packages -> coreutils
# 9.4-3ubuntu6.2 arm64 DEB 68f2a7cc1e164d669df3f8b5c1903947e1a74844d24843cf770bc63691753f16.
# These three helpers are a single factory, never independently mixed hashes.
CLASSIC_GNU_TOOL_PROFILES = {
    'coreutils:arm64=9.4-3ubuntu6.3': CLASSIC_GNU_TOOLS,
    'coreutils:arm64=9.4-3ubuntu6.2': {
        '/usr/bin/stat': ('/usr/bin/gnustat',
            '86b89355842f54a49698069b345eabb94c2f26d2f33b5734ec91c68de8fe6f7a'),
        '/usr/bin/readlink': ('/usr/bin/gnureadlink',
            '068bf5e7b3cfa43ae02ccf7b854f13863adb05d75d011a2de9e89adafd1a524b'),
        '/usr/bin/sha256sum': ('/usr/bin/gnusha256sum',
            'f3d040161f5c29e4c7cd4e3d6bb513ce9a43b9d1bd06f456a6aab3d34d0f1e33'),
    },
}


def classic_gnu_tool_profile(package, observed):
    need(package in CLASSIC_GNU_TOOL_PROFILES, 'unreviewed classic GNU package version')
    tools = CLASSIC_GNU_TOOL_PROFILES[package]
    need(type(observed) is dict and observed == {name: value[1] for name, value in tools.items()},
         'classic GNU tool factory differs; install a complete reviewed vendor package')
    return dict(tools)


CLASSIC_HOOK_FUNCTIONS_SHA = '500c8dea2feb1f393c60121a819bae5a0584bc8a824c6e29a3e388a22d231ea8'
CLASSIC_REMOVE_FILES = (
    '.random-seed', 'etc/initiatorname.iscsi',
    'scripts/init-premount/cloud-initramfs-dyn-netconf',
    'scripts/init-bottom/cloud-initramfs-dyn-netconf',
    'scripts/local-top/iscsi', 'scripts/local-bottom/iscsi',
    'scripts/init-bottom/overlayroot', 'usr/sbin/iscsistart',
    'usr/lib/aarch64-linux-gnu/libopeniscsiusr.so.0.2.0',
    'etc/dhcpcd.conf', 'scripts/nfs', 'usr/bin/ipconfig', 'usr/sbin/dhcpcd',
    'usr/bin/ip', 'usr/bin/ifconfig', 'usr/bin/wget', 'usr/bin/nfsmount',
    'etc/modprobe.d/iwlwifi.conf',
    'usr/lib/udev/hwdb.bin',
    'usr/lib/udev/rules.d/73-special-net-names.rules',
    'usr/lib/udev/rules.d/75-net-description.rules',
    'usr/lib/udev/rules.d/80-net-setup-link.rules',
)
CLASSIC_REMOVE_TREES = (
    'usr/lib/dhcpcd', 'usr/lib/aarch64-linux-gnu/dhcpcd', 'var/lib/dhcpcd',
    'usr/lib/systemd/network',
)
# One typed refusal for the detector and the installed gate (exit 78). The
# detail carries a fixed reason, a datasource class token or a file name;
# never a seed URL, address or path from cloud-init's own state files.
CLOUD_INIT_ACTIVE = 'cloud_init_early_network_unverified'
CLOUD_INIT_UNPROVED = 'cloud_init_disabled_profile_unproved'
CLOUD_INIT_SWITCH_ROOT = 'cloud_init_switch_root_unverified'
CLOUD_INIT_REFUSALS = {
    CLOUD_INIT_ACTIVE: (
        'use_reviewed_local_boot_image_or_cloud_init_marker',
        'cloud-init is active on this host and can start networking before AEGIS '
        'guards it, so full-wide is refused. Use a reviewed local-root image '
        'without cloud-init and with a verified networkless initrd, or disable '
        'cloud-init with the reviewed marker procedure in '
        'docs/users/linux/install.md (independent console access required), '
        'reboot normally and retry. Keep the current host network configuration '
        'until an independent access path is ready.'),
    CLOUD_INIT_UNPROVED: (
        'restore_reviewed_cloud_init_marker_profile',
        'A cloud-init disable marker exists, but this boot does not prove the '
        'reviewed disabled profile, so full-wide is refused. Follow the marker '
        'procedure in docs/users/linux/install.md exactly: a regular root-owned '
        'marker on the root filesystem, the stock cloud-init units without '
        'edits, masks or drop-ins, and one normal reboot before installing. Do '
        'not edit units or the marker to make this check pass.'),
    CLOUD_INIT_SWITCH_ROOT: (
        'apply_networkless_initrd_and_reboot',
        'The disabled cloud-init profile needs a source-owned networkless '
        'initrd that rechecks it before every switch-root. Follow the explicit '
        'initrd-policy apply and normal reboot steps in '
        'docs/users/linux/install.md, then retry. An install-time marker check '
        'alone does not prove protection at the next boot.'),
}


class CloudInitRefusal(ValueError):
    """A typed cloud-init boot refusal; str() is its bounded detail."""

    def __init__(self, code, detail):
        if code not in CLOUD_INIT_REFUSALS:
            raise ValueError('unknown cloud-init refusal code')
        super().__init__(detail)
        self.code = code
        self.detail = detail


def cloud_init_refusal_json(error):
    action, message = CLOUD_INIT_REFUSALS[error.code]
    return json.dumps({'schema': 'aegis_install_refusal_v1', 'code': error.code,
                       'action': action, 'detail': error.detail, 'message': message},
                      sort_keys=True, separators=(',', ':'))



def journal_cloud_init_refusal(error, *, socket_path=Path('/run/systemd/journal/socket')):
    """Best-effort closed rc78 coordinate, independent of a discarded stderr.

    The default is the local native journald socket. No seed, file name,
    exception detail or message is sent. Diagnostics never alter admission.
    The nonblocking single datagram neither waits nor retries.
    """
    import socket
    try:
        if type(error) is not CloudInitRefusal or error.code not in CLOUD_INIT_REFUSALS:
            return False
        record = {'schema':'aegis_boot_host_refusal_v1', 'code':error.code,
                  'action':CLOUD_INIT_REFUSALS[error.code][0]}
        message = json.dumps(record, sort_keys=True, separators=(',', ':')).encode()
        payload = (b'PRIORITY=3\nSYSLOG_IDENTIFIER=aegis-initrd-policy\n'
                   b'AEGIS_REFUSAL_CODE='+error.code.encode('ascii')+b'\nMESSAGE='+message+b'\n')
        if len(payload) > 4096:
            return False
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as peer:
            peer.setblocking(False)
            peer.connect(str(socket_path))
            return peer.send(payload) == len(payload)
    except (OSError, TypeError, ValueError):
        return False


def cloud_lstat(path):
    return os.lstat(path)


MAX_IMAGE = 256 << 20
MAX_ENTRY = 64 << 20
MAX_MEMORY_ENTRY = 2 << 20
STREAM_CHUNK = 1 << 20
# Finite, SHA-256-pinned additions for the reviewed Ubuntu 26.04 packages.
# Package MD5 provenance is still checked; it is not misrepresented as a
# SHA-256 database. A vendor update needs a new reviewed profile pin.
RUST_COREUTILS = frozenset(('cat', 'chmod', 'chown', 'echo', 'ln', 'ls', 'mkdir',
    'mkfifo', 'mknod', 'mktemp', 'readlink', 'sha512sum', 'sleep', 'stat', 'stty',
    'timeout', 'tr', 'uname'))
LARGE_PUBLIC_FILES = {
    '/usr/lib/cargo/bin/coreutils/' + name: ('rust-coreutils',
        '48893b0fb21436b54619db80486e83ef39dfccaf1aefe83dfa00c02d6146e8c0', 128)
    for name in RUST_COREUTILS}
# Ubuntu resolute-updates rust-coreutils 0.10.0-1ubuntu2~26.04.1,
# apt payload SHA256 963dbc5efa92141e7056a9e9f3431ec7f352f2a7c762f2b3242443df39be9115.
# Independently extracted payloads match every named applet. Keep the original
# reviewed revision, the finite path set and the separate dpkg provenance check.
LARGE_PUBLIC_REVISIONS = {
    '/usr/lib/cargo/bin/coreutils/' + name: frozenset((
        'f84e76ea4da1e0c4e92254bd0d7dccdabe2c8b3098e734f27997dae3ee5d8e02',))
    for name in RUST_COREUTILS}
LARGE_PUBLIC_FILES.update({
    '/usr/lib/x86_64-linux-gnu/libcrypto.so.3': ('libssl3t64',
        '5385f0436ac2e284ba8c5fb1488874057c29c04be72dea32add832694f381e28', 1),
    '/usr/lib/x86_64-linux-gnu/libc.so.6': ('libc6',
        '85e64f97e348786a8fb4d9f3d52fec289e2fb86bba20f0731dfe61990525e0f7', 1),
    '/usr/lib/x86_64-linux-gnu/systemd/libsystemd-core-259.so': ('libsystemd-shared',
        '8fcb08373177707996567006be35737e408d9ede3b0a2ca08fdd130182012754', 1),
    '/usr/lib/x86_64-linux-gnu/systemd/libsystemd-shared-259.so': ('libsystemd-shared',
        'c733810400659bf34b5d46f77b801507a384ebc36392c5fe48fedc72388bae3e', 1),
})
DEVICES = {'dev/console': (5, 1), 'dev/null': (1, 3), 'dev/kmsg': (1, 11),
           'dev/random': (1, 8), 'dev/urandom': (1, 9)}
SYSTEMD_PATH_RECIPE = (b'systemdutildir="/usr/lib/systemd"\n'
    b'systemdsystemunitdir="/usr/lib/systemd/system"\n'
    b'systemdsystemconfdir="/etc/systemd/system"\n')
LOCAL_NSS = b''.join((kind + ': files\n').encode() for kind in
    ('passwd','group','shadow','gshadow','hosts','networks','protocols','services','ethers','rpc'))
LOCAL_UDEV = (b'SUBSYSTEM=="block", GROUP="disk"\n'
    b'SUBSYSTEM=="tty", KERNEL=="tty[0-9]*|hvc[0-9]*|console", MODE="0600"\n')
CONSOLE_KEYMAP = 'etc/console-setup/cached_UTF-8_del.kmap'
CONSOLE_KEYMAP_SHA = 'd35418f79bcc8eb2bc9e9c1b6a7d640bbd00bfb7272dc3b6eecfeb124ff44906'
CONSOLE_CACHE_SHA = '916b4203c5f2a000896c8269e1a0836ec1d4ea07a3d0aa113b157256f93b0d48'
CONSOLE_SETUP = (b'#!/bin/sh\n# A micro-version of setupcon with static configuration.\n'
    b"kbd_mode '-u' \nloadkeys '/etc/console-setup/cached_UTF-8_del.kmap' > '/dev/null' \n"
    b'mkdir /run/console-setup\n>/run/console-setup/keymap_loaded\nexit 0\n')
# Reviewed factory compatibility leaves for the dracut110 Ubuntu26.04 profile.
# No directory/package wildcard is granted by these pins. Each source must
# also match its dpkg factory digest; activation roles remain independently gated.
PUBLIC_FILE_PINS = {
    # Ubuntu26 gnu-coreutils9.7-3ubuntu2.1, checked against signed-APT factory DEB
    # d9a6724f507759ac06d8b0214e4d31d67a4e6647be4d770a70a1d43041be5fa3.
    '/usr/bin/gnustat': ('gnu-coreutils', '8fed3e2a9bb62e1b97355fca8d9df97547e0c4d731032395264b409b1507e43e', 0o755),
    '/usr/bin/gnusha256sum': ('gnu-coreutils', 'd8ed629ca1c81da690bf2ee300a7f549deb0af20c861bda15ebdc1314fb93681', 0o755),
    '/usr/bin/gnureadlink': ('gnu-coreutils', '761cde2194495631c5408de0740c54b2660dc55050f514361d0be094be1af1a2', 0o755),
    '/usr/bin/gnucp': ('gnu-coreutils', '8fcdb2485ebc68f00392d647b3d3d9130f0d4bb9f72c69ee258086dd63e1c122', 0o755),
    '/usr/bin/gnumv': ('gnu-coreutils', '540c8712b7ad853aa2e7c3613a391917040b5baed35cffc5e4980bfcb59282d3', 0o755),
    '/usr/bin/gnurm': ('gnu-coreutils', '0362781f855d9de6396b71af947662758970ed09946c4a0a78ff740b20f5e6a6', 0o755),
    '/usr/bin/gnutrue': ('gnu-coreutils', '913a39cd38f353497086bcf317b12f91f93c23b51869cea763b8340b4f84cfd3', 0o755),
    '/usr/bin/gzip': ('gzip', '2ba6fd35db5f0b5561e56b97124a08b067464b795e8e08278367f23dc539d549', 0o755),
    '/usr/bin/kbd_mode': ('kbd', 'b3c2936471a18ddf4ca877529cadf9a0c80154c0febef88ae36ac6bb38d4b013', 0o755),
    '/usr/bin/less': ('less', '20b94c140eed52bf747b3b9e74290756a6597009719a0e4c5b4fb2f1eceec954', 0o755),
    '/usr/bin/loadkeys': ('kbd', 'fff2c05bfb2f7398b698f0248bc9b4d76d63353748d00ac913cd7d76cf345802', 0o755),
    '/usr/bin/sed': ('sed', 'e42dd92d4848435b6357af4c4a22691062e8f74869ca6c9f3900b4760d604a2f', 0o755),
    '/usr/bin/sg_inq': ('sg3-utils', '269520a45fce0591f66143fb2bc2ed708acd539a7d67f5a3f4fee5a3f47377be', 0o755),
    '/usr/lib/firmware/HP/ish/ish_lnlm_12128606_f9751b71.bin.zst': ('linux-firmware-intel-misc', 'a4a51f6dc6c2f2cc2a7f8444fcdf7d59c839ec3dddf6842d88a4c52776b3fa26', 0o644),
    '/usr/lib/firmware/LENOVO/ish/ish_lnlm_lenovo_X1_2025_5.8.4.7720.bin.zst': ('linux-firmware-intel-misc', '2437a69cdc90540846252529336b3aef8ca3bfff95347725e27cacb60cf2928e', 0o644),
    '/usr/lib/firmware/LENOVO/ish/ish_lnlm_lenovo_X9-14_2025_5.8.36.09092.bin.zst': ('linux-firmware-intel-misc', '448e2b8cc381ece3e6ee5456979722f17698220ae1a3d876dc1a47af1629f1ea', 0o644),
    '/usr/lib/firmware/LENOVO/ish/ish_lnlm_lenovo_x9-15_2025_5.8.0.7720.bin.zst': ('linux-firmware-intel-misc', 'c89d9a22e6f6bec78d975fb9d39eec05d042053d06a9c461e239450e1cf1b3f1', 0o644),
    '/usr/lib/firmware/LENOVO/ish/ish_ptl_lenovo_X1_2026_5.8.1.7782.bin.zst': ('linux-firmware-intel-misc', 'ee401c7063ee3a9537831818ff69b2a4258f46f8746583beda48a39ebc5d300d', 0o644),
    '/usr/lib/firmware/cavium/cnn55xx_se.fw.zst': ('linux-firmware-misc', '83d8dfdf85a481b125595d3b34e11dfccbdea9308af3626aef8855b4ae3781d5', 0o644),
    '/usr/lib/firmware/cis/3CCFEM556.cis.zst': ('linux-firmware-misc', '387e609875646207d804a63794881606018574d7d275cf42c8c417c117375828', 0o644),
    '/usr/lib/firmware/cis/3CXEM556.cis.zst': ('linux-firmware-misc', '2b30369366d1ac24039f7099f376db67f64d34ad194b426ca3d759dd6ce77b58', 0o644),
    '/usr/lib/firmware/cis/COMpad2.cis.zst': ('linux-firmware-misc', '7289dd015fa54f84e098eea9decd1e6a926560509aabd43bd126136fc1f88a2f', 0o644),
    '/usr/lib/firmware/cis/COMpad4.cis.zst': ('linux-firmware-misc', '4fe478f7c3fd0b692b031235a901528a49880939f0b67df338726e72cace1979', 0o644),
    '/usr/lib/firmware/cis/DP83903.cis.zst': ('linux-firmware-misc', '5860008a4cd8dabf6f8fd75bed2f097a09485c1faca33245c9f1cbc4f46ceef5', 0o644),
    '/usr/lib/firmware/cis/MT5634ZLX.cis.zst': ('linux-firmware-misc', '2c2dc4bf19c9ea74a379ddacad8951bd8eed03501e3b63a4e40db5cbade7f93d', 0o644),
    '/usr/lib/firmware/cis/PCMLM28.cis.zst': ('linux-firmware-misc', '925ce8c375f8c433f9e1033bb9f2842bddbf7fea8b66d62664bf7317cb7da76c', 0o644),
    '/usr/lib/firmware/cis/RS-COM-2P.cis.zst': ('linux-firmware-misc', 'f3b55a6f86662bfa2c0b5e356ac43b288585afee2409c9bdc09198e84e257a61', 0o644),
    '/usr/lib/firmware/cis/SW_555_SER.cis.zst': ('linux-firmware-misc', '812cafba856cb3587279ee52c02b91300d3c71b5bfc0875760f55e6b290b1bf9', 0o644),
    '/usr/lib/firmware/cis/SW_7xx_SER.cis.zst': ('linux-firmware-misc', 'c9174083a9bbde30720bd6a3e8386b2f71bfe71226152c4318149de22ca1ee86', 0o644),
    '/usr/lib/firmware/cis/SW_8xx_SER.cis.zst': ('linux-firmware-misc', '617fe5a621de6261ddbf04c3da7833e7a9d64d1b4dac5706af23d64cafb1abbd', 0o644),
    '/usr/lib/firmware/cxgb4/t4fw-1.27.5.0.bin.zst': ('linux-firmware-misc', 'cd20980dbd58361c4c2b3fa676928139b6f7f7c640220a9863513c8de1e6c034', 0o644),
    '/usr/lib/firmware/cxgb4/t5fw-1.27.5.0.bin.zst': ('linux-firmware-misc', 'b815bd64cb894f2506692245cd47182da9cf3d02ee60f93b087b7100dfb96519', 0o644),
    '/usr/lib/firmware/cxgb4/t6fw-1.27.5.0.bin.zst': ('linux-firmware-misc', '550b1cb8cafb497055f7adb6ea35b89ff8995c9288177b7989425936a30302d0', 0o644),
    '/usr/lib/firmware/dell/ish/ish_lnlm_39ceeaf8_58.7727.0.bin.zst': ('linux-firmware-intel-misc', '5c3b595e9c3eb46dd748e58d3abdf071ef9e1ee13bb209fdf604777ddae5b44a', 0o644),
    '/usr/lib/firmware/dell/ish/ish_ptl_39ceeaf8_581.7779.0.bin.zst': ('linux-firmware-intel-misc', '02c4cfde39eb685ddedac38309c34bf0bb8916f2b738f63b66b5afc26d930c19', 0o644),
    '/usr/lib/firmware/ene-ub6250/ms_init.bin.zst': ('linux-firmware-misc', '435a55c3c288487f5b10e93af8703ba1e727567b0bea69c9d7df2c99a7240f28', 0o644),
    '/usr/lib/firmware/ene-ub6250/ms_rdwr.bin.zst': ('linux-firmware-misc', '9d517344f9eacfd4435ab5301950048989d72bc871e2b2db3fe66e9f1152d526', 0o644),
    '/usr/lib/firmware/ene-ub6250/msp_rdwr.bin.zst': ('linux-firmware-misc', '863cbe8fa6047a69a7142d7d3f2c3158cb9d9dd6d00a5b23b1cbc929d9c9658c', 0o644),
    '/usr/lib/firmware/ene-ub6250/sd_init1.bin.zst': ('linux-firmware-misc', 'd1b5e1f0ac09ef1fe6888a16a28d87092f0180b799e4d690b7f102eee7abcc4f', 0o644),
    '/usr/lib/firmware/ene-ub6250/sd_init2.bin.zst': ('linux-firmware-misc', 'b2c6066ee7bb18d260a7d1e69e221fc8435a87b29a3e9d6193d92861f3ec3430', 0o644),
    '/usr/lib/firmware/ene-ub6250/sd_rdwr.bin.zst': ('linux-firmware-misc', '65eabaf1d6d586373cdc0af2f206fd7dc6f0d45bef0641cdf8589b22371ed88a', 0o644),
    '/usr/lib/firmware/inside-secure/eip197_minifw/ifpp.bin.zst': ('linux-firmware-misc', '8efab864792c04f192e7932d7cd7ef5ffda15ba114093d8eddc01cf87453413b', 0o644),
    '/usr/lib/firmware/inside-secure/eip197_minifw/ipue.bin.zst': ('linux-firmware-misc', '7acadfdaa81e5f30f82accc205c68fd40ff3f08f2c7786468c9cd45d98d0243d', 0o644),
    '/usr/lib/firmware/intel/ish/ish_lnlm.bin.zst': ('linux-firmware-intel-misc', 'a7c362e53cac41d32f6df7f5af0be7a5ecbcee879742cd4742b6dfe6dabeebe2', 0o644),
    '/usr/lib/firmware/intel/ish/ish_ptl.bin.zst': ('linux-firmware-intel-misc', '2a72705f6ac631e29eeea8a53b4b7f13615ff0f8d7ecb68430de9789aecc1112', 0o644),
    '/usr/lib/firmware/intel/ish/ish_wcl.bin.zst': ('linux-firmware-intel-misc', '674bd2345ea34cc4a7f36ad26f0e2768bce6b7d57141415b4e9eee8efbad60cd', 0o644),
    '/usr/lib/firmware/intel/qat/qat_402xx.bin.zst': ('linux-firmware-intel-misc', '8c14593d42416e4068945fa91c8ddc2bb16c33b40948ce8bee615f8fc1d54771', 0o644),
    '/usr/lib/firmware/intel/qat/qat_402xx_mmp.bin.zst': ('linux-firmware-intel-misc', 'c1be89090acd91f39d16b32a9764f2378bf1699e9531f5eb0aa639a03220f00c', 0o644),
    '/usr/lib/firmware/intel/qat/qat_420xx.bin.zst': ('linux-firmware-intel-misc', '045255137a843c29b08132866d3e3d9fd4a2a888b6c653162a445ba2449b26d0', 0o644),
    '/usr/lib/firmware/intel/qat/qat_420xx_mmp.bin.zst': ('linux-firmware-intel-misc', '0cf32f656d773b446e6b7cf5e7e2ca3105fa55c169983f9d24c6ef50c8d09f37', 0o644),
    '/usr/lib/firmware/intel/qat/qat_4xxx.bin.zst': ('linux-firmware-intel-misc', '241458395d9e5b0b8f32ae8b5f7727520dc2b760e1adbd6b6065725709badee1', 0o644),
    '/usr/lib/firmware/intel/qat/qat_4xxx_mmp.bin.zst': ('linux-firmware-intel-misc', '215fb477dcd405429c9378985bed0507cd3b9b9b4b3f3062f6267efcf0c191ef', 0o644),
    '/usr/lib/firmware/intel/qat/qat_895xcc.bin.zst': ('linux-firmware-intel-misc', 'd5fd70cfe869535268aa2d4400f3a237f50973fae745350c056df8d4e4f1dbed', 0o644),
    '/usr/lib/firmware/intel/qat/qat_895xcc_mmp.bin.zst': ('linux-firmware-intel-misc', 'e3f5cb29b6f29ac4ad7057cba8a38792ec1cd8b36b7205d6f73c74d2e08ca9f0', 0o644),
    '/usr/lib/firmware/intel/qat/qat_c3xxx.bin.zst': ('linux-firmware-intel-misc', '0f31e1a7e8fa4ee15f003be295cf4be5ecf46dc43f69d30fdbbcf5ae2b702bad', 0o644),
    '/usr/lib/firmware/intel/qat/qat_c3xxx_mmp.bin.zst': ('linux-firmware-intel-misc', 'e4df034540575b5ccedf43a975b8b7deced438ccc5aba23003c1a857bd2e6af8', 0o644),
    '/usr/lib/firmware/intel/qat/qat_c62x.bin.zst': ('linux-firmware-intel-misc', '29bcd87f72d80cf8bbeb222a1c49f25214e5c18ad2850c47005f8e4c0772bb17', 0o644),
    '/usr/lib/firmware/intel/qat/qat_c62x_mmp.bin.zst': ('linux-firmware-intel-misc', '74fbd47bd6834c5da10cc1ebff150a1e0f4db6112fa48bd2e73dbc45e64cb392', 0o644),
    '/usr/lib/firmware/rp2.fw.zst': ('linux-firmware-misc', '59357ae356869068213d7eeed28e20f41a855f6493ea7a08618b71dd3176f4e3', 0o644),
    '/usr/lib/modprobe.d/blacklist_linux_7.0.0-38-generic.conf': ('linux-modules-7.0.0-38-generic', '7d18958976289a74d670d263b888e931ac8be7aad879cd6052c3ea9cc2ee1d51', 0o644),
    '/usr/lib/modules-load.d/fwupd-i2c.conf': ('fwupd', '273f592d7f3e73ed36ae7ddfd08423304951370d844cabfe66895bca806201d4', 0o644),
    '/usr/lib/modules-load.d/fwupd-msr.conf': ('fwupd', '0ddfd6290cf2263f5e6be277a9d45e42cbbe1d2f1298fb0f352b7f07c36dd545', 0o644),
    '/usr/lib/sysctl.d/10-apparmor.conf': ('apparmor', '4981b04165da4990d6b5c5c3be4f97688e1eca03f09a71790b9f73df4f2f1147', 0o644),
    '/usr/lib/sysctl.d/50-default.conf': ('linux-sysctl-defaults', '43d317773a1fd90cc6b751f9020b89e37ca5bd46394d5436fc82017b293c1f96', 0o644),
    '/usr/lib/sysctl.d/55-bufferbloat.conf': ('procps', '763c2e237645fb7c3fecf16a54479e49c39aab229c2a646a42f16c83b9dd2974', 0o644),
    '/usr/lib/sysctl.d/55-console-messages.conf': ('procps', '14524a83a266454d517b7cdbfb2141dbc4b884570543da5f65e3f08da0b814c0', 0o644),
    '/usr/lib/sysctl.d/55-ipv6-privacy.conf': ('procps', 'e07c86211944a534c6418fe0eb5896926e09a13b56162d8cb642866f37e83b04', 0o644),
    '/usr/lib/sysctl.d/55-kernel-hardening.conf': ('procps', '2bbc2c5684414517eba9da8d2fbff0a678026d944eb8fcfd6287281e11282e2f', 0o644),
    '/usr/lib/sysctl.d/55-magic-sysrq.conf': ('procps', 'f9107778c619246fb2a5a7e2a05c9419951752238ede04c771173832dd296128', 0o644),
    '/usr/lib/sysctl.d/55-map-count.conf': ('procps', '867f4371a9cc5a79cab3b350aee03d067857b69e3cbf556a4a19aed057f9e954', 0o644),
    '/usr/lib/sysctl.d/55-network-security.conf': ('procps', '258805ec72eada3c24a923de1c5bd8ed0fd11fe21f3673628ec78f221c31e934', 0o644),
    '/usr/lib/sysctl.d/55-ptrace.conf': ('procps', '4add0d9ecbcc91e4018ed08e8dc66c69d4d9d142f9e31461178dcd7da0fd73c2', 0o644),
    '/usr/lib/sysctl.d/55-zeropage.conf': ('procps', '5c745f62d086d9b9cf2ec23e4164f510cdba206c7aa6f11d2256f3f9be64c950', 0o644),
    '/usr/lib/udev/rules.d/55-scsi-sg3_id.rules': ('sg3-utils-udev', '7760154cd1392427d5fdeb2c7666acde79d0a4c1695a19c2829b3a88ae752049', 0o644),
    '/usr/lib/udev/rules.d/58-scsi-sg3_symlink.rules': ('sg3-utils-udev', 'fcc5b9fe1e9b4b3118b26fbc0f2c0e46c820085ca2e66c1065618eb8a9bfe7d3', 0o644),
    '/usr/lib/x86_64-linux-gnu/libbpf.so.1.6.3': ('libbpf1', 'fe891e11e8c485fc01592e4894d35bd37b046f2fadb47141787ae842ea8656ef', 0o644),
    '/usr/lib/x86_64-linux-gnu/libbsd.so.0.12.2': ('libbsd0', 'c71b8a0d7e94c5e34f6c328c5dd1ba7f325d3300c97a54a7c69ef9a6c2caa8b3', 0o644),
    '/usr/lib/x86_64-linux-gnu/libc.so': ('libc6-dev', '649e1aa91af2551216685f45effca270fcc09ef39e28acd4b22745f0ae77e7f2', 0o644),
    '/usr/lib/x86_64-linux-gnu/libcom_err.so.2.1': ('libcom-err2', '6fb3115b11fe7e14c26f3e086c4dc1fb41061130869a66c976e0ea69fdb912d6', 0o644),
    '/usr/lib/x86_64-linux-gnu/libe2p.so.2.3': ('libext2fs2t64', '78b962737fc0df9fdd6b77ed284958065ff4c3ee0776251967f434b764204377', 0o644),
    '/usr/lib/x86_64-linux-gnu/libedit.so.2.0.76': ('libedit2', '438090e1cd463d9f89c9259ce9e99f229eae56c857b5e525d581e338f61aa1ce', 0o644),
    '/usr/lib/x86_64-linux-gnu/libelf-0.194.so': ('libelf1t64', 'f77db7b4cfa02c98aa5918caf1f02b6cf37a5998e2e5cc8e43e664dbb72c87fa', 0o644),
    '/usr/lib/x86_64-linux-gnu/libevdev.so.2.3.0': ('libevdev2', '03548725991442dc1c2b7a14a07abd91c35f984b959c1fff9ea9fc4f38ea4a5e', 0o644),
    '/usr/lib/x86_64-linux-gnu/libext2fs.so.2.4': ('libext2fs2t64', '2207429cf209fa895c8cd604a2737862b61442e290f0b2a451f25c42e8c6a070', 0o644),
    '/usr/lib/x86_64-linux-gnu/liblzo2.so.2.0.0': ('liblzo2-2', '1728af970f1689da66c2314c328aef8fd21a7c42332469177914367f5082c086', 0o644),
    '/usr/lib/x86_64-linux-gnu/libm.so': ('libc6-dev', '0789aa234121bb6b77f060e40577027323ae1e7531a430fe208d29e57a697e4a', 0o644),
    '/usr/lib/x86_64-linux-gnu/libmd.so.0.1.0': ('libmd0', 'f115fa619f586e47ddfbec21bfd50069fbe5d21f388f8d9a07a984cb075d7efa', 0o644),
    '/usr/lib/x86_64-linux-gnu/libnss_systemd.so.2': ('libnss-systemd', 'a456a729898df8b1b67e9cf5c6b220cf7772a814099884bf54a79a14e203288a', 0o644),
    '/usr/lib/x86_64-linux-gnu/libply-splash-core.so.5.0.0': ('libplymouth5', '2d57377529e6c0e635ee954fc6766d91f6f73660172c5a3c7ab8867b9cdcc0e1', 0o644),
    '/usr/lib/x86_64-linux-gnu/libply.so.5.0.0': ('libplymouth5', 'df56b303aec94713580e5f0ffbaa65672808dbe1af32c7a49bb88e6fac791f31', 0o644),
    '/usr/lib/x86_64-linux-gnu/libpopt.so.0.0.2': ('libpopt0', '8296d0cdfaa47f42029dcef99377396c7212e7368a8213edba8297e3d950dba8', 0o644),
    '/usr/lib/x86_64-linux-gnu/libsgutils2-1.48.so.2.0.0': ('libsgutils2-1.48', '74a64d3f262b5f36e755df6146da7e43ec0bfaa5d369c79366e74ef8eeaf5c38', 0o644),
    '/usr/lib/x86_64-linux-gnu/liburcu.so.8.1.0': ('liburcu8t64', '96191caf8b43a0f6e081613f6711b6367398e2b2e09b42389a5e3867619f1b95', 0o644),
    '/usr/lib/x86_64-linux-gnu/libxkbcommon.so.0.13.1': ('libxkbcommon0', '8b7d244ea1df8b1c073069344f8c705bab90d6b6bcafb96f1c2eccc2312f4946', 0o644),
    '/usr/lib/x86_64-linux-gnu/libxxhash.so.0.8.3': ('libxxhash0', 'eae56344ba81fd5d25c6976028b33a53d3303848c382b04f3d5746549fb25228', 0o644),
    '/usr/lib/x86_64-linux-gnu/plymouth/ubuntu-text.so': ('plymouth-theme-ubuntu-text', '3b752dd5c33c9db506a2eb6b81e05998f9d5ff89d4be132a2fb96973c6bb0aa7', 0o644),
    '/usr/sbin/fsck.cramfs': ('util-linux-extra', '82ccbc99540cc47c751cfb1fe4a0d77ebc97ffbc1324a2b5effb19f84970869e', 0o755),
    '/usr/sbin/fsck.exfat': ('exfatprogs', 'b4bce7f1a97966667e5777578099790875c809142d56f8050dcbf35ae1f7a01e', 0o755),
    '/usr/sbin/fsck.fat': ('dosfstools', '4e2aa9699ac6a103b8d27e1c0bceb8f8e6a817ff067f97cb240918e5aa75ae5c', 0o755),
    '/usr/sbin/fsck.minix': ('util-linux-extra', '59914e8fd6f2ec9631690f20be3a30fc9b2c9754b0e7edd9ad155c4283c9ee8e', 0o755),
    '/usr/sbin/kexec': ('kexec-tools', '4d042bac2a519f942d98b445ed3e39a3b8a5c6925b6b8465a1c04cfb6c5deffe', 0o755),
    '/usr/sbin/nologin': ('login', '1968a3d6bd4b6e6eee79a6c657394da4be26b9c3522dc4254470650fe555f9c6', 0o755),
    '/usr/sbin/sysctl': ('procps', '990418c1540c9f759b0225fb2ffdc77251c1c0551e74e77151d39621ccb4096c', 0o755),
    '/usr/share/X11/locale/am_ET.UTF-8/Compose': ('libx11-data', '44b0d7ed76f2fd0856762e0e2194f90ecb1094470310f95817911381c759d2dc', 0o644),
    '/usr/share/X11/locale/am_ET.UTF-8/XI18N_OBJS': ('libx11-data', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 0o644),
    '/usr/share/X11/locale/am_ET.UTF-8/XLC_LOCALE': ('libx11-data', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 0o644),
    '/usr/share/X11/locale/compose.dir': ('libx11-data', '1b842b950d38753e01c639e364c44bf7dec2300a444845bb3707049262616a0f', 0o644),
    '/usr/share/X11/locale/cs_CZ.UTF-8/Compose': ('libx11-data', '2498c21f61aa88237d149b182c888ebdcdc0877ec158e5d6a9fef234310dde64', 0o644),
    '/usr/share/X11/locale/cs_CZ.UTF-8/XI18N_OBJS': ('libx11-data', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 0o644),
    '/usr/share/X11/locale/cs_CZ.UTF-8/XLC_LOCALE': ('libx11-data', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 0o644),
    '/usr/share/X11/locale/el_GR.UTF-8/Compose': ('libx11-data', 'cd39eff9261eeb8580d3256b647917a21a7833194ac4d9652753c8f1726ef380', 0o644),
    '/usr/share/X11/locale/el_GR.UTF-8/XI18N_OBJS': ('libx11-data', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 0o644),
    '/usr/share/X11/locale/el_GR.UTF-8/XLC_LOCALE': ('libx11-data', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 0o644),
    '/usr/share/X11/locale/en_US.UTF-8/Compose': ('libx11-data', 'a3077ce7fdae43776b9a485d8a9689c0bfeb0cd17348a87b7a06818e59554ea1', 0o644),
    '/usr/share/X11/locale/en_US.UTF-8/XI18N_OBJS': ('libx11-data', 'ced92075d6db441663139fa39079da39bca242ec651459038b693faee91d1e29', 0o644),
    '/usr/share/X11/locale/en_US.UTF-8/XLC_LOCALE': ('libx11-data', '0067217168fa6507dde39089676e65e16a44f8f28d1cdf0aa65ddfe6cfd06cac', 0o644),
    '/usr/share/X11/locale/fi_FI.UTF-8/Compose': ('libx11-data', '55d31f9b815add4ee2c23d0c585baa69d3b5a4609c9ab025e26d8cba29da6906', 0o644),
    '/usr/share/X11/locale/fi_FI.UTF-8/XI18N_OBJS': ('libx11-data', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 0o644),
    '/usr/share/X11/locale/fi_FI.UTF-8/XLC_LOCALE': ('libx11-data', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 0o644),
    '/usr/share/X11/locale/ja_JP.UTF-8/Compose': ('libx11-data', '2d04ecb0181c56837f5b266d57fce339356d80212bde313c9a656d65cb751d59', 0o644),
    '/usr/share/X11/locale/ja_JP.UTF-8/XI18N_OBJS': ('libx11-data', '85023cec5e57823e91c22fd0cc8e0562e1b357dea2fb46e3978ebf01ed960d83', 0o644),
    '/usr/share/X11/locale/ja_JP.UTF-8/XLC_LOCALE': ('libx11-data', 'f2f928ca9d068e634bfdaca9dede542f2b3eb825a1480b96e45940369a23fe63', 0o644),
    '/usr/share/X11/locale/km_KH.UTF-8/Compose': ('libx11-data', '2d04ecb0181c56837f5b266d57fce339356d80212bde313c9a656d65cb751d59', 0o644),
    '/usr/share/X11/locale/km_KH.UTF-8/XI18N_OBJS': ('libx11-data', 'df4a3bcf39efef842ef9b8b855f9ec29da85613eb5133b0d764da535f0c32f1a', 0o644),
    '/usr/share/X11/locale/km_KH.UTF-8/XLC_LOCALE': ('libx11-data', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 0o644),
    '/usr/share/X11/locale/ko_KR.UTF-8/Compose': ('libx11-data', '2d04ecb0181c56837f5b266d57fce339356d80212bde313c9a656d65cb751d59', 0o644),
    '/usr/share/X11/locale/ko_KR.UTF-8/XI18N_OBJS': ('libx11-data', 'd5ac844df91eb872b5a9d06960dfdc727b9d910a0c36cd303c9595447616a2ec', 0o644),
    '/usr/share/X11/locale/ko_KR.UTF-8/XLC_LOCALE': ('libx11-data', '346554a5f535b6cd76df1b5be3a73b9a88c0868efcc4f63466d9ff95c0886142', 0o644),
    '/usr/share/X11/locale/locale.alias': ('libx11-data', '2f6b48ed21a700f9e6dbb26c54e7d980c672fcae0810af61c537db9066ae9fe0', 0o644),
    '/usr/share/X11/locale/locale.dir': ('libx11-data', '72e5b15f87c6a375d428b39edc4236e331614e2ef733a32ef59d6f099ffe4397', 0o644),
    '/usr/share/X11/locale/pt_BR.UTF-8/Compose': ('libx11-data', 'df150cfafe06fa49607d463b44b298776334cba2df7cc2615839dc5ddb192993', 0o644),
    '/usr/share/X11/locale/pt_BR.UTF-8/XI18N_OBJS': ('libx11-data', '084a4789668816bf0c9154fe3bd9d4d1bb303d355611d14e29f02d6e1d4cbb10', 0o644),
    '/usr/share/X11/locale/pt_BR.UTF-8/XLC_LOCALE': ('libx11-data', '52f44bc94b9ce3584a20e02137845ed041eb097b9e89e16ff718cb9bf460e0b6', 0o644),
    '/usr/share/X11/locale/pt_PT.UTF-8/Compose': ('libx11-data', '7937f12b516deee3699e80bce3fb1f34d5bfde3f596ca3ae1b17765d7d2b2e08', 0o644),
    '/usr/share/X11/locale/pt_PT.UTF-8/XI18N_OBJS': ('libx11-data', '1b7661866efdf754de97baa070e1079a233f1abb11f91721528e0d268bac41c8', 0o644),
    '/usr/share/X11/locale/pt_PT.UTF-8/XLC_LOCALE': ('libx11-data', '9c4cf5795c6bdaf2ee333526bdbadec64d2a5ecb9701b8bf2962c428d724f7a9', 0o644),
    '/usr/share/X11/locale/ru_RU.UTF-8/Compose': ('libx11-data', '2d04ecb0181c56837f5b266d57fce339356d80212bde313c9a656d65cb751d59', 0o644),
    '/usr/share/X11/locale/ru_RU.UTF-8/XI18N_OBJS': ('libx11-data', 'c7f2ddfe768b88bd83527aa17bfc359be01cf5e77a46731ea7f1031917669ade', 0o644),
    '/usr/share/X11/locale/ru_RU.UTF-8/XLC_LOCALE': ('libx11-data', '9c79a5307f23b94392455fd29e1d38b9fb1fed98d650377f346e2ff75ee055a8', 0o644),
    '/usr/share/X11/locale/sr_RS.UTF-8/Compose': ('libx11-data', '28f12f426f04d708bfcf84b15fe657e0939c82f19848e134aec569a4e6730c17', 0o644),
    '/usr/share/X11/locale/sr_RS.UTF-8/XI18N_OBJS': ('libx11-data', 'df4a3bcf39efef842ef9b8b855f9ec29da85613eb5133b0d764da535f0c32f1a', 0o644),
    '/usr/share/X11/locale/sr_RS.UTF-8/XLC_LOCALE': ('libx11-data', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 0o644),
    '/usr/share/X11/locale/th_TH.UTF-8/Compose': ('libx11-data', '2d04ecb0181c56837f5b266d57fce339356d80212bde313c9a656d65cb751d59', 0o644),
    '/usr/share/X11/locale/th_TH.UTF-8/XI18N_OBJS': ('libx11-data', '2c125f8e32f5a1fafd00b88320d74c66ffec12dd267fa2fcac5baec5e14e3e3f', 0o644),
    '/usr/share/X11/locale/th_TH.UTF-8/XLC_LOCALE': ('libx11-data', 'ccd9e45ecaa71057fc6b000378e4f5bd039fa65b8a521a2215ae0ed5e2f0018f', 0o644),
    '/usr/share/X11/locale/zh_CN.UTF-8/Compose': ('libx11-data', '2d04ecb0181c56837f5b266d57fce339356d80212bde313c9a656d65cb751d59', 0o644),
    '/usr/share/X11/locale/zh_CN.UTF-8/XI18N_OBJS': ('libx11-data', '16f3baef683a4a2cbbd48574eb4e25537bdce2348ce6913b3e13e3bf7459ca97', 0o644),
    '/usr/share/X11/locale/zh_CN.UTF-8/XLC_LOCALE': ('libx11-data', '20c82018a878b372b198d2b1edb1fcf51721ec16f55ed47413a166ff7cbec71a', 0o644),
    '/usr/share/X11/locale/zh_HK.UTF-8/Compose': ('libx11-data', '2d04ecb0181c56837f5b266d57fce339356d80212bde313c9a656d65cb751d59', 0o644),
    '/usr/share/X11/locale/zh_HK.UTF-8/XI18N_OBJS': ('libx11-data', '95fcb72dd3ae5e8d34183f3a068a7042434a82ac23801cadb22dfbf8ace8a432', 0o644),
    '/usr/share/X11/locale/zh_HK.UTF-8/XLC_LOCALE': ('libx11-data', '0ec0532f7cc08027abd8cf65f9e63ffb2e444c40ff4482940e629a6a5cbf8bb0', 0o644),
    '/usr/share/X11/locale/zh_TW.UTF-8/Compose': ('libx11-data', '2d04ecb0181c56837f5b266d57fce339356d80212bde313c9a656d65cb751d59', 0o644),
    '/usr/share/X11/locale/zh_TW.UTF-8/XI18N_OBJS': ('libx11-data', 'e67615cebce31ef62695e4b4f3603ee88c099c4ce66c2320fc3ee14eb9bd5910', 0o644),
    '/usr/share/X11/locale/zh_TW.UTF-8/XLC_LOCALE': ('libx11-data', 'c73e42057a8b2ea920119ac3d3148a22ea7b61ec79ed9c1729f2f8ad61948a4a', 0o644),
    '/usr/share/xkeyboard-config-2/compat/accessx': ('xkb-data', 'e7f0630dbf09f3bb3adf3bb8e8d2464afbd6e616fe0075dbef29b7e82bd2a50d', 0o644),
    '/usr/share/xkeyboard-config-2/compat/basic': ('xkb-data', '381cdef43f910f7f4ddb476b2ff258afe3af6881051f9c71efa5554108c30b4a', 0o644),
    '/usr/share/xkeyboard-config-2/compat/caps': ('xkb-data', '26f9917f6d36d13d23b5d303e8554e3e4d57ec02576ff47b0d34bc1fed90e5c4', 0o644),
    '/usr/share/xkeyboard-config-2/compat/complete': ('xkb-data', '11d1fd1f5364ef778eb0edc36b4f1955ca165c1900703f163c1406aa8ae767cd', 0o644),
    '/usr/share/xkeyboard-config-2/compat/iso9995': ('xkb-data', 'bfb9feee868fde37f9f5f4ba43924f2b70f621ebe058e1d4c7cef6f7aa4278ca', 0o644),
    '/usr/share/xkeyboard-config-2/compat/ledcaps': ('xkb-data', '7d3882ccecb24b1621975fde25fc7e90e5c1c00197cf67820622458f35bb34ae', 0o644),
    '/usr/share/xkeyboard-config-2/compat/lednum': ('xkb-data', '811b0afbcfe43d891cc53de9d275ba8787363f99c7f601ce2d3e316e58481f78', 0o644),
    '/usr/share/xkeyboard-config-2/compat/ledscroll': ('xkb-data', '736397f179253795f116607fa5588a4bc88dc620f87af4c38bbd9bdc20a17db5', 0o644),
    '/usr/share/xkeyboard-config-2/compat/level5': ('xkb-data', 'e07406a8982fa3fc94c9bbedbd6a3e3a0159d3e7426960e3b60d7f5bcb8bba1a', 0o644),
    '/usr/share/xkeyboard-config-2/compat/misc': ('xkb-data', 'aff8f280e2ce71e7752b75c8b2893c628cfa33f279ba25d918fae4ed43705f5d', 0o644),
    '/usr/share/xkeyboard-config-2/compat/mousekeys': ('xkb-data', 'b4de6898f10617c8172f9a35aae362def187793e1d995f5bb646e0c220b31255', 0o644),
    '/usr/share/xkeyboard-config-2/compat/xfree86': ('xkb-data', 'ade96d0e9fa4427c48e50ec708407bbd94c1bf4560fd05581391647e5f9ee9bb', 0o644),
    '/usr/share/xkeyboard-config-2/keycodes/aliases': ('xkb-data', '85f774170fc1526e8a909a1e2952423dae3891b721abc293a27dc450818dcc6d', 0o644),
    '/usr/share/xkeyboard-config-2/keycodes/evdev': ('xkb-data', 'fde3e1370f99498dee8f880c2b263fd5562b2a5d85eac2248be6085a14950a06', 0o644),
    '/usr/share/xkeyboard-config-2/rules/evdev': ('xkb-data', 'cfd6c2812926889222b58c01274b68888b53268453127d006427cc8673655fa8', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/af': ('xkb-data', '5b831de719d172c851b7c91da630e96d6520870a90690226d695d8501850c74d', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/al': ('xkb-data', 'b2c689f19123dd19d2097fbfe1b260cf1ec90b7caba8f0094089863f7bd99bd0', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/altwin': ('xkb-data', '085c134b47e092b955722f2165246eaae9bd5420d36b304175ae482012250601', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/am': ('xkb-data', '3f3db7a60e794f6d137b0a9a021d266cc254d4c137dbd6df7d70f8f77eab85b3', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/ancient': ('xkb-data', 'a157f3ec085d3642f88018ac22ee33dcc7f338587837e324a83acdba0233a429', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/apl': ('xkb-data', '6a33ab642e28e629d107a207a177a22b3a2f38208dea4733f9c145a5aecb0e81', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/ara': ('xkb-data', '2a5ebf2411230ab729d03bc4ef7105b82b63a2939af8ad3edf57ac28eadca5eb', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/at': ('xkb-data', 'e878e22e81bc7e0dd1f04aabbc7981e6605eee94f64150822f209eb1f31017fc', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/au': ('xkb-data', '6d54de90977bd0e50751a9413247b338a237e16bd91ac7d588c9340aae60604e', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/az': ('xkb-data', '244f3748072dd88d1ff2e597b21f7d3e896b551ffcb003432960ee0ca9c29a2d', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/ba': ('xkb-data', 'fde993c5a87ca245efd331948d4a1212805107aeebe720b1233c855c045c42d3', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/bd': ('xkb-data', 'fc21d55bac4ef2fdb96f92f52aa9f3633653ebcadf907f785d0ab3c6d49a7b12', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/be': ('xkb-data', '031df1bab5fd60145e54b3c1b581629e9860756a9f635656d86e6405b7ab6c8a', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/bg': ('xkb-data', '95f97e580ab1537c4eb4a30e20a4b83f0b5bcb2cee351731864c000290392687', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/bqn': ('xkb-data', 'd22cb1cd606d450430f07f4b485aaed40a033782c731c09ff38454300268c76e', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/br': ('xkb-data', 'cc6b6d7f18f5da2a3ffc62ef452e52e207624eebad7a4775839e9b9f0f9fa0fb', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/brai': ('xkb-data', '175912eab851524570710884176eb890c778b3204f4eb3e3bbc648a9660a6385', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/bt': ('xkb-data', 'a14842315c52340a6f8273a610b255bfe3af765bdf669117c94d4e9f227652d7', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/bw': ('xkb-data', 'd038072be9eee7b2ce64079f9bcc95bbc0b91009e3d1c8ed9049e65e5a35da21', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/by': ('xkb-data', '20e4241858341092487714aa0ca6aa789647fbc06f7b95a42f4a3f3c3fa810aa', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/ca': ('xkb-data', '3c7a55a158984dcb9b24103b8ad9af343532cc55a283c1039f5dbfc7595b714b', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/capslock': ('xkb-data', '1181722e79a4c46319dea21d6f4eb723de49e798ec2e91f8929e4dfb528882cd', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/cd': ('xkb-data', '803a5f118daef69c590e9243dfb27051abe8dd40b61b42d9028c629a5cc74e15', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/ch': ('xkb-data', '71b2bab94965f21dd656a149432518bbce8148a969463965604ae2a3dd5f7e80', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/cm': ('xkb-data', '07c90370b6fa96f69b8c9645788032892bed7e7936c41379f0e77aa6d8f4c265', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/cn': ('xkb-data', 'd533595453978274ab2837cc54a5f847c00121281221296e7e79a455131ed58e', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/compose': ('xkb-data', '10947142db6939e7adf1004b5cde6b190d577706ff4b7c0f0ca0a0ddb57262d9', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/ctrl': ('xkb-data', '8365f54106e3101f67281e6b92bfe2afbc23618f6646e71362b10e468652d41e', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/cz': ('xkb-data', 'e4fae163e9652d293e749b6be066d5de99823d4793cc1d299d83ce7a50d5cf52', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/de': ('xkb-data', 'dc4c7b2ef09efe6b6f927bcf3276295b4b85c549e56edbdfdb0fe80cde743e05', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/dk': ('xkb-data', 'fcefecdcbc25406de793791957e035ef57a8ab4988960ccbe6031235ec3f04bb', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/dz': ('xkb-data', '2cee960f73ca520c90142105bdb90796e1084d733711938e6b533d565aca08b2', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/ee': ('xkb-data', 'f7adbb45038afd86df55ddae6ac580c1fe7e4946cdf9175d1283db706bf309d9', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/eg': ('xkb-data', 'a91c117ff0507c529cb21b52276480316ebd242278c6e4c5c2b00da100f046be', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/empty': ('xkb-data', '887e05c9d27f1269ee87908c81bccef237b34e22f5db7e30ff8c3381691c6ac8', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/epo': ('xkb-data', 'e8978a60f6f5bf13aace45098f0f0530c0487f10b1ab200b46171e5963d90078', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/es': ('xkb-data', '20fec559a8027cd34926318da82ceb2c0f45404cea6cb40ec55bd966b852c14e', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/et': ('xkb-data', 'b38196b423ffaee0c4f1737c559ca848943378a806aee16bdd1660993ecd8e05', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/eu': ('xkb-data', '9080d6de013f2d61e1d34fd64bbc8715c7ee217ebc95e2d681b15bc2b50bb343', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/eurosign': ('xkb-data', '8563e64d139d1fe4df789e760822c42d20f5036a0d4b109bf8353db968eca666', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/fi': ('xkb-data', '7cc55979949a158f01585706c2ead364188498d651370215d2f1e92562638c1b', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/fkeys': ('xkb-data', '5e52e79433881737f067094387913a56f70a589d82262fbd0e788d81b51811f8', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/fo': ('xkb-data', 'd5709657f18d40e542b93b3cdc56afc75bbe7806f669a5608e11306ff7561d6d', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/fr': ('xkb-data', '67352dec5e7bc5742d012bdc7dc62c5c329d849e0c325d15b6280d170fd75896', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/gb': ('xkb-data', '4d0c3e74a0c15e7b85314bf6f174ba4473d2489e8b0aa8d0498bf3c1227fa124', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/ge': ('xkb-data', 'c373d734fe34bdea78569ae8dee654cabbcbc84803f57344a10d8e11db473bf0', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/gh': ('xkb-data', '843c5769823dbbc74335ac7cbddf521d92069a9201636df4716d0dcd03a3cad5', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/gn': ('xkb-data', '7aed3035f7298571a2ce93029d2fcd7f515be9cf0daca97ccb0e81b0b23893a9', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/gr': ('xkb-data', '4465a3bf7a8a759ea7f0fc1808eed4ac4fcde8c449aee498bb134f49d8b92f20', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/grab': ('xkb-data', '0a0697a38cd31952f45a5828a95a97cbaf535076fd464fda79a5f88ac05408c3', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/group': ('xkb-data', 'd962772859c00eb77223056cf3ec22e12c11b31ae8204760ca94e1c31f220000', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/hr': ('xkb-data', '0891f79bed0f754db251fa6a381ac05b96b060e91206c9612c49e3614e49ee11', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/hu': ('xkb-data', 'c499c00940ff1a447d61bf9bcb51662d686c673195a635b2b10cb23fdc63924d', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/hyper': ('xkb-data', '19fd70bfe2e8811669b531718964c7fa0bdf899b158cae6267b9c241abceeb85', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/id': ('xkb-data', 'e863d4174eed1172524a168b54b90c72849c658d3212b43910cea99042c384ea', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/ie': ('xkb-data', 'e841894f01c499f3598c3fbb09f930b6b0cca703b65bbc984ea7a8dcbe5408b9', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/il': ('xkb-data', 'f42072a57f056b3bfe05c781f24d913d9cf18a604f5a7e53008e3416fe270aff', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/in': ('xkb-data', 'a7593d6e4fa664f18c96a0a418a4796f39a306f78ff5fb7b01668388b39afb8a', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/inet': ('xkb-data', 'b4c56aea0527b72d7589b8e7067df28616c0a511e0aba5139a52aa8744a4ae82', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/iq': ('xkb-data', 'a1252c14090c5003fa6e60fa9778c29ea00af6e3dcfad86bf64159dee9f64640', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/ir': ('xkb-data', '38a4ebd89cd0e02d1eeba2aa28d6f8575417e87830ddfeda872b05add5d5b8e0', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/is': ('xkb-data', 'c7ac379e288142cab096db9a0c93d4e37255c7a9b3cf1ecd5b1cd43646fdb10e', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/it': ('xkb-data', '027a99d3d660d6cff46e6ee9364ace8dc23b3c2af617bc3b58090f1dd097d399', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/jp': ('xkb-data', '4f4ff9dbec37a4cf4631a22df74f0db7a4ec9d4ce75a40cce685419b5cb1f9d5', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/ke': ('xkb-data', '1436f69081864e1807242029f44b144d4d631e52e8a58c6767602b33b0b52d1b', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/keypad': ('xkb-data', 'c4044b7ae212b78f9bfa31dbe0deb2d25123d8e8f40b7f241f2b5508cfcf482f', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/kg': ('xkb-data', '2612789b3aeb9cfec78ad7ae330fa15216a1165ca7f1f23cd7cf3af95c0b7e13', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/kh': ('xkb-data', 'e49599f6871af00a457f60206621ef2f1916415756a08cabe44750778c13c0a6', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/kpdl': ('xkb-data', 'b81ef8aa7cfa4b3272986272150fd445b8effeff986c2097cd88fba880fed1bb', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/kr': ('xkb-data', '303d93a6d16950ec7f0d8f8efb11b6ee17dd7c664d0acb5b8dadb1ab9b80acb6', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/kz': ('xkb-data', '5bedd1321907880e83f8ab5a1146bf50dfa5e5a45cb2d62189a2a069b8a0ca0b', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/la': ('xkb-data', '3f0adb95edd2b8bb03204f6896781820fbd9c3fdba1c50cca389007b136d6de8', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/latam': ('xkb-data', '5040c4684ae4a5e0d45acdd58a8c96ce4aa3ebf5888feb7f60d0314934c9a6a9', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/latin': ('xkb-data', '442253255e7aade71aab3caf325041cd2242d248ce856252e7eb364fef30b91b', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/level2': ('xkb-data', 'ab1f791d69969eb8444f9661138cf5e28b38420dbd14bcac1adb1cda70742180', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/level3': ('xkb-data', 'cdeddada22f8593f89cb8693d728dc02a24abef92d62cf0ce61c4f947b6d47d0', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/level5': ('xkb-data', '8009418071d2bc55d0f5d38522fc9552a910af4e930945b261a7cdfc2ea7e750', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/lk': ('xkb-data', '881d6d40a3964c766af10874618ca342c610656e7a1bba598f8c1cbefeca98af', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/lt': ('xkb-data', 'd78d7fae4fbf70b9061067c8a5cf35c565a398585bb2e4eae6877b888a7c9e7d', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/lv': ('xkb-data', '3c4405f48f2db1ae22b07086cf058a1919e7d4756c58c6562b87db2215320449', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/ma': ('xkb-data', '3d8e3875fe3881bfdaac645a7d72062d9c8efd0638464ff5c73e0bcf4406732c', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/md': ('xkb-data', '27585ef75113257fc6436a92f90c50c955a2ecc27f8415dbd6fbdf70bc2db8da', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/me': ('xkb-data', '691b7050e5b415d95d59ff60d7a1ceb173f48cc677f00bbfe6872fe6dcea0907', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/mk': ('xkb-data', '6d3a9e38a8e04fbf7b6054a1408399f75ac17f1612362a1985866279e7a3f88f', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/ml': ('xkb-data', 'f437f0f5dd3c3f5217358b342528cc34d748b2c8cdb8c3574a7091b2949c0a28', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/mm': ('xkb-data', 'e6d26776976ddf29e08f7f661302aa78f9c7a98e961967c7989ce2eae9ac8d92', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/mn': ('xkb-data', 'e4cd56da6ba817e6ef50ceb431c3d6be07e10a24358011634849452acb353c27', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/mt': ('xkb-data', '7f783ac5138aa04990552b2e82d0cf513c1adf6e986a3c0ef7a3c5e1cb94e9c4', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/mv': ('xkb-data', '812bd0d66f8c88dcaae408eac78a078dabaf2151df53a620b571337c86c4ec1c', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/my': ('xkb-data', '4f8971b7a72d64457cfbe075403d3cd33cd255ef55dc282518f426d6ed9a3db9', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/nbsp': ('xkb-data', 'fcdebe89f88e385ca2ba178274cd3b04c0e7066afa10395e8c30671997baa441', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/ng': ('xkb-data', 'a44bb469226af83ab9dc344f31e38395c3957d51179c5a1d7b77bfeafb487a8b', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/nl': ('xkb-data', 'a61e97302f6a73a56553417db6852f5a31bc2bd392de8d0f9060770890ce4211', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/no': ('xkb-data', '44d18ee35fb817bb7d265027b613b6035af595a455049fd489f778b057850faf', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/np': ('xkb-data', '3bdc658d1739df8a5e8ed0649d02ab73e59b2006c78f4fee2a85992b7f5cd5d6', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/nz': ('xkb-data', '7874d1ad55d3b80246bba95c85a437310587581e900c7f735e73b5c9590403a6', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/olpc': ('xkb-data', '5dd585565e873ed7ea2d264e186ab6c90bda7528a9de05180efd8a21ca8f0151', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/parens': ('xkb-data', '67295705ae19cf0bc047a4f1e975dce4535329cf62319b5401534a60e3a2ec33', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/pc': ('xkb-data', 'e2e1c1501d8eedf2ba41ca153e244edf29ff8d7d83f9fa1a20d07d4729421794', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/ph': ('xkb-data', '831eb3897c208f9449561dcd3da49e8db39c6f107df80379424f136ba6cb699f', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/pk': ('xkb-data', 'de24cb85203c49568649e16c273419fa15ba361ed2e7326395690ea2b664a183', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/pl': ('xkb-data', 'b8a923200e2b3dcd618506154eb2db4d63caa60b538e7cf695a8d9bce79751d7', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/pt': ('xkb-data', 'e38d648c2dd89093ee881c238d88749459091aa740d93b52bfcd5d9bb002c765', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/ro': ('xkb-data', 'ddb2b5b024924e5205b014fb784e5a9b3cc77ecc7f4085fb0de3d836ff75bd51', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/rs': ('xkb-data', 'f9cd6947f3eb509a7e3776d7f2b7143cf8e7d92b1cfb165f04552cbe6e6732cb', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/ru': ('xkb-data', '50407d7fb56598f200f348ed5fa8b060cc29c9c49653a239e14c46e2c25e7dde', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/rupeesign': ('xkb-data', '24dde1d4fca8228394270b3b2cf71ab029466f8353a0345f8129ad4e56c59c93', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/scrolllock': ('xkb-data', '3e729b0a579df9fec1e1cf4d03b1ac1cb0eb2ccc1f25465f82fb77c2a63d908b', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/se': ('xkb-data', '6e72e4cfd16c5ebc621b471bfa49eb6a21dfb6a94a7033f6851486f5005f9db5', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/shift': ('xkb-data', 'f78597c70f29261bf49c2254e36e9d11718cc0c3665fb47bf0218d9761ed1605', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/si': ('xkb-data', '8ea12df796d51f64e688ef876ca50b0f77eee77daf2eb36d7b6797da7962cdae', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/sk': ('xkb-data', '2241508923aeef0c880b049dbecebe8bd8e983237cd4465dba251c52e47b975c', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/sn': ('xkb-data', '08e1ad5524f54a9ef776a8dbf60c33228cccb5dced3873f0573ceb6020f236c6', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/srvr_ctrl': ('xkb-data', '652d16838143dbeb218aff2997cc603f9e9731e1e55e2300dee910d167e25d85', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/srvrkeys': ('xkb-data', '026f03dd024e5bd630ab85cb98e772bdd0a7c431ea17346651c33c74ee0a645f', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/sy': ('xkb-data', 'e7e1843e8b9b28b438a79109ac622f7814860ef8ca744afafe7bcf6d0771aede', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/terminate': ('xkb-data', '0bf67addb6f096da3de29be0c8fd2ca7546e9164a4d0e874202d95c34d745598', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/tg': ('xkb-data', '230a4b89e9dbb7a0c71dabfb9082ebcf0febedf3ab1720f2a5eb68ce4685cc25', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/th': ('xkb-data', '4b2567f6f0afc04119697cdba8a7e7f40d8b97c7716a772e03dd25b4617cd0a4', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/tj': ('xkb-data', '86998ddb19288374722a120ae597d25d381f81027fa0a9a4143942f4a5138521', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/tm': ('xkb-data', '6d909052fdb7b4eb19c18ffecf9a78162d7432a2f2cc9011d1efe5dd069d5be5', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/tr': ('xkb-data', '2d0fd93105fcd948fe1df940cf10f6925848690161007de948b0d23893abfe11', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/trans': ('xkb-data', '471d549573a8a2c4fb720c9134d23dda1e29df2b4164d003d01b41332e65c15c', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/tw': ('xkb-data', '9021512e53f36526c57b07481d47dd63711f690e8ffe616efff4921856eb265c', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/typo': ('xkb-data', '3020278bd1a50e05d6596d770990b50a6186d2228c282a86376831d2a2ba36bd', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/tz': ('xkb-data', '5f8a7b2a0408fc0cd9e6e2e25e181df047b8ac5024ec0f68f10a55d39be94363', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/ua': ('xkb-data', '081a68b851ff0dc51b4a770b8a9e1549bbe396e0bbcb52e483ae117e64e7678d', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/us': ('xkb-data', 'cd38b88f81c4d37505fd4908d2bf37eedb26eb8dd80897b3120d987a97079b22', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/uz': ('xkb-data', '7fe72abc792fd38e7b17dd0636aab83c603d5d4af093e3fd9c0ac896469f782e', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/vn': ('xkb-data', '4ef686847cbde54e030af22e50d37e7d91f0524c1178b2943769061220933907', 0o644),
    '/usr/share/xkeyboard-config-2/symbols/za': ('xkb-data', '1e765c9f7f5391e369cdbe64e4020c292478022f9da24f3ace11ce2d96d46527', 0o644),
    '/usr/share/xkeyboard-config-2/types/basic': ('xkb-data', '4c18eb87250a3ba92b9d9881a4f07316bcda47d186c5f4e9c76e6d4fcbfbf948', 0o644),
    '/usr/share/xkeyboard-config-2/types/complete': ('xkb-data', '038d66c8861dbc797b7d2226bc9135698e62adf3d6d9f99f1be60b768f591aee', 0o644),
    '/usr/share/xkeyboard-config-2/types/extra': ('xkb-data', 'bd1f1f82f29473836e802a9c525be0113595c52b9216d19d66060eacaf9cf7c6', 0o644),
    '/usr/share/xkeyboard-config-2/types/iso9995': ('xkb-data', '37dc0a4905d8eae972fb8e4eb87a2f5b3050a86aa2fcbe217630647163aea975', 0o644),
    '/usr/share/xkeyboard-config-2/types/level5': ('xkb-data', '61850daaae74dd5603c7820a5c99c86f68e312a6d1f1d3cff271b421b6993861', 0o644),
    '/usr/share/xkeyboard-config-2/types/mousekeys': ('xkb-data', '8cd68606f38aa725915ea7a0de775f322a27b5b79bcd871569ac72b31b93585f', 0o644),
    '/usr/share/xkeyboard-config-2/types/numpad': ('xkb-data', 'ecc734b72b703b776acafa326f49e9b7420069ee04c9e6d5defe7afff4ac347f', 0o644),
    '/usr/share/xkeyboard-config-2/types/pc': ('xkb-data', '2aaa757827e81adb5dcae3db1f07fc98d5eee7955bd25064ad5f12dae7a9dddf', 0o644),
}
PUBLIC_FILE_PINS.update({
    '/usr/lib/modprobe.d/blacklist_linux_7.0.0-31-generic.conf': ('linux-modules-7.0.0-31-generic',
        '53e953a808419435792d17ec8a2368ef5b8f773987d1f129abb5a91916f9c1e9', 0o644),
    '/usr/bin/grep': ('grep',
        '4874cbc734792ae29aa38cd7978aedf1e646563af9e8ee0d5dab59ecb6406417', 0o755),
    '/usr/libexec/plymouth/plymouthd-fd-escrow': ('plymouth',
        'e26937c9b3636823e339efd8af210bd6a0a1fce874bd35e65257091b17879dd3', 0o755),
    '/usr/share/pixmaps/ubuntu-logo-text-dark.png': ('base-files',
        '63c599f9b4ad9938161f996b9eac4be3634e9af26f25f32c4be8bcff2ac45f1e', 0o644),
})
DATA_RELOCATE = {
    'usr/share/X11/xkb/compat/accessx': '/usr/share/xkeyboard-config-2/compat/accessx',
    'usr/share/X11/xkb/compat/basic': '/usr/share/xkeyboard-config-2/compat/basic',
    'usr/share/X11/xkb/compat/caps': '/usr/share/xkeyboard-config-2/compat/caps',
    'usr/share/X11/xkb/compat/complete': '/usr/share/xkeyboard-config-2/compat/complete',
    'usr/share/X11/xkb/compat/iso9995': '/usr/share/xkeyboard-config-2/compat/iso9995',
    'usr/share/X11/xkb/compat/ledcaps': '/usr/share/xkeyboard-config-2/compat/ledcaps',
    'usr/share/X11/xkb/compat/lednum': '/usr/share/xkeyboard-config-2/compat/lednum',
    'usr/share/X11/xkb/compat/ledscroll': '/usr/share/xkeyboard-config-2/compat/ledscroll',
    'usr/share/X11/xkb/compat/level5': '/usr/share/xkeyboard-config-2/compat/level5',
    'usr/share/X11/xkb/compat/misc': '/usr/share/xkeyboard-config-2/compat/misc',
    'usr/share/X11/xkb/compat/mousekeys': '/usr/share/xkeyboard-config-2/compat/mousekeys',
    'usr/share/X11/xkb/compat/xfree86': '/usr/share/xkeyboard-config-2/compat/xfree86',
    'usr/share/X11/xkb/keycodes/aliases': '/usr/share/xkeyboard-config-2/keycodes/aliases',
    'usr/share/X11/xkb/keycodes/evdev': '/usr/share/xkeyboard-config-2/keycodes/evdev',
    'usr/share/X11/xkb/rules/evdev': '/usr/share/xkeyboard-config-2/rules/evdev',
    'usr/share/X11/xkb/symbols/af': '/usr/share/xkeyboard-config-2/symbols/af',
    'usr/share/X11/xkb/symbols/al': '/usr/share/xkeyboard-config-2/symbols/al',
    'usr/share/X11/xkb/symbols/altwin': '/usr/share/xkeyboard-config-2/symbols/altwin',
    'usr/share/X11/xkb/symbols/am': '/usr/share/xkeyboard-config-2/symbols/am',
    'usr/share/X11/xkb/symbols/ancient': '/usr/share/xkeyboard-config-2/symbols/ancient',
    'usr/share/X11/xkb/symbols/apl': '/usr/share/xkeyboard-config-2/symbols/apl',
    'usr/share/X11/xkb/symbols/ara': '/usr/share/xkeyboard-config-2/symbols/ara',
    'usr/share/X11/xkb/symbols/at': '/usr/share/xkeyboard-config-2/symbols/at',
    'usr/share/X11/xkb/symbols/au': '/usr/share/xkeyboard-config-2/symbols/au',
    'usr/share/X11/xkb/symbols/az': '/usr/share/xkeyboard-config-2/symbols/az',
    'usr/share/X11/xkb/symbols/ba': '/usr/share/xkeyboard-config-2/symbols/ba',
    'usr/share/X11/xkb/symbols/bd': '/usr/share/xkeyboard-config-2/symbols/bd',
    'usr/share/X11/xkb/symbols/be': '/usr/share/xkeyboard-config-2/symbols/be',
    'usr/share/X11/xkb/symbols/bg': '/usr/share/xkeyboard-config-2/symbols/bg',
    'usr/share/X11/xkb/symbols/bqn': '/usr/share/xkeyboard-config-2/symbols/bqn',
    'usr/share/X11/xkb/symbols/br': '/usr/share/xkeyboard-config-2/symbols/br',
    'usr/share/X11/xkb/symbols/brai': '/usr/share/xkeyboard-config-2/symbols/brai',
    'usr/share/X11/xkb/symbols/bt': '/usr/share/xkeyboard-config-2/symbols/bt',
    'usr/share/X11/xkb/symbols/bw': '/usr/share/xkeyboard-config-2/symbols/bw',
    'usr/share/X11/xkb/symbols/by': '/usr/share/xkeyboard-config-2/symbols/by',
    'usr/share/X11/xkb/symbols/ca': '/usr/share/xkeyboard-config-2/symbols/ca',
    'usr/share/X11/xkb/symbols/capslock': '/usr/share/xkeyboard-config-2/symbols/capslock',
    'usr/share/X11/xkb/symbols/cd': '/usr/share/xkeyboard-config-2/symbols/cd',
    'usr/share/X11/xkb/symbols/ch': '/usr/share/xkeyboard-config-2/symbols/ch',
    'usr/share/X11/xkb/symbols/cm': '/usr/share/xkeyboard-config-2/symbols/cm',
    'usr/share/X11/xkb/symbols/cn': '/usr/share/xkeyboard-config-2/symbols/cn',
    'usr/share/X11/xkb/symbols/compose': '/usr/share/xkeyboard-config-2/symbols/compose',
    'usr/share/X11/xkb/symbols/ctrl': '/usr/share/xkeyboard-config-2/symbols/ctrl',
    'usr/share/X11/xkb/symbols/cz': '/usr/share/xkeyboard-config-2/symbols/cz',
    'usr/share/X11/xkb/symbols/de': '/usr/share/xkeyboard-config-2/symbols/de',
    'usr/share/X11/xkb/symbols/dk': '/usr/share/xkeyboard-config-2/symbols/dk',
    'usr/share/X11/xkb/symbols/dz': '/usr/share/xkeyboard-config-2/symbols/dz',
    'usr/share/X11/xkb/symbols/ee': '/usr/share/xkeyboard-config-2/symbols/ee',
    'usr/share/X11/xkb/symbols/eg': '/usr/share/xkeyboard-config-2/symbols/eg',
    'usr/share/X11/xkb/symbols/empty': '/usr/share/xkeyboard-config-2/symbols/empty',
    'usr/share/X11/xkb/symbols/epo': '/usr/share/xkeyboard-config-2/symbols/epo',
    'usr/share/X11/xkb/symbols/es': '/usr/share/xkeyboard-config-2/symbols/es',
    'usr/share/X11/xkb/symbols/et': '/usr/share/xkeyboard-config-2/symbols/et',
    'usr/share/X11/xkb/symbols/eu': '/usr/share/xkeyboard-config-2/symbols/eu',
    'usr/share/X11/xkb/symbols/eurosign': '/usr/share/xkeyboard-config-2/symbols/eurosign',
    'usr/share/X11/xkb/symbols/fi': '/usr/share/xkeyboard-config-2/symbols/fi',
    'usr/share/X11/xkb/symbols/fkeys': '/usr/share/xkeyboard-config-2/symbols/fkeys',
    'usr/share/X11/xkb/symbols/fo': '/usr/share/xkeyboard-config-2/symbols/fo',
    'usr/share/X11/xkb/symbols/fr': '/usr/share/xkeyboard-config-2/symbols/fr',
    'usr/share/X11/xkb/symbols/gb': '/usr/share/xkeyboard-config-2/symbols/gb',
    'usr/share/X11/xkb/symbols/ge': '/usr/share/xkeyboard-config-2/symbols/ge',
    'usr/share/X11/xkb/symbols/gh': '/usr/share/xkeyboard-config-2/symbols/gh',
    'usr/share/X11/xkb/symbols/gn': '/usr/share/xkeyboard-config-2/symbols/gn',
    'usr/share/X11/xkb/symbols/gr': '/usr/share/xkeyboard-config-2/symbols/gr',
    'usr/share/X11/xkb/symbols/grab': '/usr/share/xkeyboard-config-2/symbols/grab',
    'usr/share/X11/xkb/symbols/group': '/usr/share/xkeyboard-config-2/symbols/group',
    'usr/share/X11/xkb/symbols/hr': '/usr/share/xkeyboard-config-2/symbols/hr',
    'usr/share/X11/xkb/symbols/hu': '/usr/share/xkeyboard-config-2/symbols/hu',
    'usr/share/X11/xkb/symbols/hyper': '/usr/share/xkeyboard-config-2/symbols/hyper',
    'usr/share/X11/xkb/symbols/id': '/usr/share/xkeyboard-config-2/symbols/id',
    'usr/share/X11/xkb/symbols/ie': '/usr/share/xkeyboard-config-2/symbols/ie',
    'usr/share/X11/xkb/symbols/il': '/usr/share/xkeyboard-config-2/symbols/il',
    'usr/share/X11/xkb/symbols/in': '/usr/share/xkeyboard-config-2/symbols/in',
    'usr/share/X11/xkb/symbols/inet': '/usr/share/xkeyboard-config-2/symbols/inet',
    'usr/share/X11/xkb/symbols/iq': '/usr/share/xkeyboard-config-2/symbols/iq',
    'usr/share/X11/xkb/symbols/ir': '/usr/share/xkeyboard-config-2/symbols/ir',
    'usr/share/X11/xkb/symbols/is': '/usr/share/xkeyboard-config-2/symbols/is',
    'usr/share/X11/xkb/symbols/it': '/usr/share/xkeyboard-config-2/symbols/it',
    'usr/share/X11/xkb/symbols/jp': '/usr/share/xkeyboard-config-2/symbols/jp',
    'usr/share/X11/xkb/symbols/ke': '/usr/share/xkeyboard-config-2/symbols/ke',
    'usr/share/X11/xkb/symbols/keypad': '/usr/share/xkeyboard-config-2/symbols/keypad',
    'usr/share/X11/xkb/symbols/kg': '/usr/share/xkeyboard-config-2/symbols/kg',
    'usr/share/X11/xkb/symbols/kh': '/usr/share/xkeyboard-config-2/symbols/kh',
    'usr/share/X11/xkb/symbols/kpdl': '/usr/share/xkeyboard-config-2/symbols/kpdl',
    'usr/share/X11/xkb/symbols/kr': '/usr/share/xkeyboard-config-2/symbols/kr',
    'usr/share/X11/xkb/symbols/kz': '/usr/share/xkeyboard-config-2/symbols/kz',
    'usr/share/X11/xkb/symbols/la': '/usr/share/xkeyboard-config-2/symbols/la',
    'usr/share/X11/xkb/symbols/latam': '/usr/share/xkeyboard-config-2/symbols/latam',
    'usr/share/X11/xkb/symbols/latin': '/usr/share/xkeyboard-config-2/symbols/latin',
    'usr/share/X11/xkb/symbols/level2': '/usr/share/xkeyboard-config-2/symbols/level2',
    'usr/share/X11/xkb/symbols/level3': '/usr/share/xkeyboard-config-2/symbols/level3',
    'usr/share/X11/xkb/symbols/level5': '/usr/share/xkeyboard-config-2/symbols/level5',
    'usr/share/X11/xkb/symbols/lk': '/usr/share/xkeyboard-config-2/symbols/lk',
    'usr/share/X11/xkb/symbols/lt': '/usr/share/xkeyboard-config-2/symbols/lt',
    'usr/share/X11/xkb/symbols/lv': '/usr/share/xkeyboard-config-2/symbols/lv',
    'usr/share/X11/xkb/symbols/ma': '/usr/share/xkeyboard-config-2/symbols/ma',
    'usr/share/X11/xkb/symbols/md': '/usr/share/xkeyboard-config-2/symbols/md',
    'usr/share/X11/xkb/symbols/me': '/usr/share/xkeyboard-config-2/symbols/me',
    'usr/share/X11/xkb/symbols/mk': '/usr/share/xkeyboard-config-2/symbols/mk',
    'usr/share/X11/xkb/symbols/ml': '/usr/share/xkeyboard-config-2/symbols/ml',
    'usr/share/X11/xkb/symbols/mm': '/usr/share/xkeyboard-config-2/symbols/mm',
    'usr/share/X11/xkb/symbols/mn': '/usr/share/xkeyboard-config-2/symbols/mn',
    'usr/share/X11/xkb/symbols/mt': '/usr/share/xkeyboard-config-2/symbols/mt',
    'usr/share/X11/xkb/symbols/mv': '/usr/share/xkeyboard-config-2/symbols/mv',
    'usr/share/X11/xkb/symbols/my': '/usr/share/xkeyboard-config-2/symbols/my',
    'usr/share/X11/xkb/symbols/nbsp': '/usr/share/xkeyboard-config-2/symbols/nbsp',
    'usr/share/X11/xkb/symbols/ng': '/usr/share/xkeyboard-config-2/symbols/ng',
    'usr/share/X11/xkb/symbols/nl': '/usr/share/xkeyboard-config-2/symbols/nl',
    'usr/share/X11/xkb/symbols/no': '/usr/share/xkeyboard-config-2/symbols/no',
    'usr/share/X11/xkb/symbols/np': '/usr/share/xkeyboard-config-2/symbols/np',
    'usr/share/X11/xkb/symbols/nz': '/usr/share/xkeyboard-config-2/symbols/nz',
    'usr/share/X11/xkb/symbols/olpc': '/usr/share/xkeyboard-config-2/symbols/olpc',
    'usr/share/X11/xkb/symbols/parens': '/usr/share/xkeyboard-config-2/symbols/parens',
    'usr/share/X11/xkb/symbols/pc': '/usr/share/xkeyboard-config-2/symbols/pc',
    'usr/share/X11/xkb/symbols/ph': '/usr/share/xkeyboard-config-2/symbols/ph',
    'usr/share/X11/xkb/symbols/pk': '/usr/share/xkeyboard-config-2/symbols/pk',
    'usr/share/X11/xkb/symbols/pl': '/usr/share/xkeyboard-config-2/symbols/pl',
    'usr/share/X11/xkb/symbols/pt': '/usr/share/xkeyboard-config-2/symbols/pt',
    'usr/share/X11/xkb/symbols/ro': '/usr/share/xkeyboard-config-2/symbols/ro',
    'usr/share/X11/xkb/symbols/rs': '/usr/share/xkeyboard-config-2/symbols/rs',
    'usr/share/X11/xkb/symbols/ru': '/usr/share/xkeyboard-config-2/symbols/ru',
    'usr/share/X11/xkb/symbols/rupeesign': '/usr/share/xkeyboard-config-2/symbols/rupeesign',
    'usr/share/X11/xkb/symbols/scrolllock': '/usr/share/xkeyboard-config-2/symbols/scrolllock',
    'usr/share/X11/xkb/symbols/se': '/usr/share/xkeyboard-config-2/symbols/se',
    'usr/share/X11/xkb/symbols/shift': '/usr/share/xkeyboard-config-2/symbols/shift',
    'usr/share/X11/xkb/symbols/si': '/usr/share/xkeyboard-config-2/symbols/si',
    'usr/share/X11/xkb/symbols/sk': '/usr/share/xkeyboard-config-2/symbols/sk',
    'usr/share/X11/xkb/symbols/sn': '/usr/share/xkeyboard-config-2/symbols/sn',
    'usr/share/X11/xkb/symbols/srvr_ctrl': '/usr/share/xkeyboard-config-2/symbols/srvr_ctrl',
    'usr/share/X11/xkb/symbols/srvrkeys': '/usr/share/xkeyboard-config-2/symbols/srvrkeys',
    'usr/share/X11/xkb/symbols/sy': '/usr/share/xkeyboard-config-2/symbols/sy',
    'usr/share/X11/xkb/symbols/terminate': '/usr/share/xkeyboard-config-2/symbols/terminate',
    'usr/share/X11/xkb/symbols/tg': '/usr/share/xkeyboard-config-2/symbols/tg',
    'usr/share/X11/xkb/symbols/th': '/usr/share/xkeyboard-config-2/symbols/th',
    'usr/share/X11/xkb/symbols/tj': '/usr/share/xkeyboard-config-2/symbols/tj',
    'usr/share/X11/xkb/symbols/tm': '/usr/share/xkeyboard-config-2/symbols/tm',
    'usr/share/X11/xkb/symbols/tr': '/usr/share/xkeyboard-config-2/symbols/tr',
    'usr/share/X11/xkb/symbols/trans': '/usr/share/xkeyboard-config-2/symbols/trans',
    'usr/share/X11/xkb/symbols/tw': '/usr/share/xkeyboard-config-2/symbols/tw',
    'usr/share/X11/xkb/symbols/typo': '/usr/share/xkeyboard-config-2/symbols/typo',
    'usr/share/X11/xkb/symbols/tz': '/usr/share/xkeyboard-config-2/symbols/tz',
    'usr/share/X11/xkb/symbols/ua': '/usr/share/xkeyboard-config-2/symbols/ua',
    'usr/share/X11/xkb/symbols/us': '/usr/share/xkeyboard-config-2/symbols/us',
    'usr/share/X11/xkb/symbols/uz': '/usr/share/xkeyboard-config-2/symbols/uz',
    'usr/share/X11/xkb/symbols/vn': '/usr/share/xkeyboard-config-2/symbols/vn',
    'usr/share/X11/xkb/symbols/za': '/usr/share/xkeyboard-config-2/symbols/za',
    'usr/share/X11/xkb/types/basic': '/usr/share/xkeyboard-config-2/types/basic',
    'usr/share/X11/xkb/types/complete': '/usr/share/xkeyboard-config-2/types/complete',
    'usr/share/X11/xkb/types/extra': '/usr/share/xkeyboard-config-2/types/extra',
    'usr/share/X11/xkb/types/iso9995': '/usr/share/xkeyboard-config-2/types/iso9995',
    'usr/share/X11/xkb/types/level5': '/usr/share/xkeyboard-config-2/types/level5',
    'usr/share/X11/xkb/types/mousekeys': '/usr/share/xkeyboard-config-2/types/mousekeys',
    'usr/share/X11/xkb/types/numpad': '/usr/share/xkeyboard-config-2/types/numpad',
    'usr/share/X11/xkb/types/pc': '/usr/share/xkeyboard-config-2/types/pc',
}


@dataclass(frozen=True)
class StreamedBody:
    size: int
    sha256: str
    identity: tuple | None = None


def command(*args, timeout=3, maximum=4 << 20):
    import tempfile
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        p = subprocess.run(args, stdout=out, stderr=err, stdin=subprocess.DEVNULL,
                           timeout=timeout, env={**os.environ, 'LC_ALL': 'C'})
        need(p.returncode == 0, 'initrd command failed: ' + args[0])
        need(out.tell() <= maximum and err.tell() <= maximum, 'initrd output bound')
        out.seek(0)
        return out.read(maximum + 1)


def sha_file(path):
    h = hashlib.sha256()
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        before = os.fstat(f.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and
             not before.st_mode & 0o022 and before.st_size <= MAX_IMAGE, 'untrusted image')
        while raw := f.read(1 << 20):
            h.update(raw)
        after = os.fstat(f.fileno())
        need((before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == \
             (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'image raced')
    return h.hexdigest()


def read_config(path):
    return trusted_read(path, 2 << 20).decode('utf-8')


def inspect_cmdline(text):
    # A kernel '#' token does not start a comment. shlex removes the whole-key
    # double quote accepted by next_arg(), without evaluating any shell input.
    for token in shlex.split(text, comments=False):
        key, _, value = token.partition('=')
        need(not key.startswith('LD_') and key not in BOOT_ENVIRONMENT_KEYS,
             'unknown: unsafe init environment')
        need(key not in BOOT_ESCAPE_KEYS, 'unknown: alternate init or debug shell')
        if key == 'init':
            need(value in ('/sbin/init', '/lib/systemd/systemd', '/usr/lib/systemd/systemd'),
                 'unknown: alternate init or debug shell')
        need(key not in NETWORK_KEYS and not key.startswith(
            ('rd.net.', 'rd.iscsi.', 'iscsi_', 'rd.nvmf.')), 'network_required: early network option')
        need(not (key == 'root' and (value.startswith(('nfs:', 'iscsi:', 'nbd:', 'dhcp')) or
              value == '/dev/nfs')), 'network_required: network root')
        if key == 'boot':
            need(value == 'local', 'network_required: nonlocal boot')
        if key == 'rootfstype':
            need(value in ('ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'f2fs'),
                 'network_required: filesystem')


def config_paths():
    paths = [Path('/etc/default/grub'), Path('/etc/grub.d/40_custom'),
             Path('/boot/grub/grub.cfg'), Path('/boot/grub/grubenv'), Path('/etc/dracut.conf')]
    for root, pattern in (('/etc/default/grub.d', '*.cfg'),
        ('/etc/dracut.conf.d', '*.conf'), ('/usr/lib/dracut/dracut.conf.d', '*.conf'),
        ('/usr/lib/dracut.conf.d', '*.conf'), ('/etc/modules-load.d', '*.conf'),
        ('/usr/lib/modules-load.d', '*.conf'), ('/etc/modprobe.d', '*.conf'),
        ('/usr/lib/modprobe.d', '*.conf')):
        paths.extend(sorted(Path(root).glob(pattern)))
    return [p for p in paths if p.exists() or p.is_symlink()]


def _cloud_token(text, pattern, limit):
    return text if type(text) is str and re.fullmatch(pattern, text) and len(text) <= limit else 'unknown'


def _cloud_datasource_token(host, read):
    """The class token only; the refusal never depends on this parse."""
    try:
        data = decode(read(host('/run/cloud-init/status.json'), 1 << 20))
        datasource = data['v1']['datasource']
        token = datasource.split(' ', 1)[0] if type(datasource) is str else ''
    except Exception:  # noqa: BLE001 - every failure is the same refusal
        token = ''
    return _cloud_token(token, r'[A-Za-z]{1,64}', 64)


def _cloud_items(host, dirs):
    seen, items = set(), set()
    for name in dirs:
        try:
            info = os.stat(host(name))
        except FileNotFoundError:
            continue
        need(stat.S_ISDIR(info.st_mode), 'unknown: cloud-init unit path is not a directory')
        if (info.st_dev, info.st_ino) in seen:
            continue
        seen.add((info.st_dev, info.st_ino))
        entries = os.listdir(host(name))
        need(len(entries) <= 65536, 'unknown: cloud-init unit path bound')
        for entry in entries:
            # Dependency directories are validated separately: systemd may
            # queue their jobs even when this unit's condition skips its start.
            if entry.startswith(CLOUD_UNIT_PREFIXES) and not entry.endswith(
                    ('.wants', '.requires', '.upholds')):
                items.add(name + '/' + entry)
    return items


def _cloud_graph_directory(host, logical):
    # Match the initrd's physical merged-/usr alias rule; no other symlink
    # ancestry can inject units or dependency links after this assessment.
    if logical.startswith('/lib/') and os.path.islink(host('/lib')):
        meta = cloud_lstat(host('/lib'))
        need(meta.st_uid == 0 and os.readlink(host('/lib')) in ('usr/lib', '/usr/lib'),
             'unknown: cloud-init search alias unproved')
        logical = '/usr' + logical
    current = host('/')
    for part in Path(logical).parts[1:]:
        current /= part
        try: meta = cloud_lstat(current)
        except FileNotFoundError: return None
        need(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0 and not meta.st_mode & 0o022,
             'unknown: cloud-init search ancestry untrusted')
    return logical, current, meta


def _cloud_graph_inventory(host):
    dependencies, overrides, signature, seen = [], [], [], set()
    for original in CLOUD_UNIT_DIRS:
        found = _cloud_graph_directory(host, original)
        if found is None:
            signature.append((original, 'missing')); continue
        logical, parent, meta = found
        key = (meta.st_dev, meta.st_ino)
        if key in seen: continue
        seen.add(key)
        signature.append((logical, meta.st_dev, meta.st_ino, meta.st_uid, meta.st_mode))
        entries = os.listdir(parent)
        need(len(entries) <= 65536, 'unknown: cloud-init graph directory bound')
        for leaf in sorted(entries):
            if not leaf.startswith(CLOUD_UNIT_PREFIXES) or not leaf.endswith(('.wants', '.requires', '.upholds')):
                continue
            need(re.fullmatch(r'[A-Za-z0-9_.@+-]{1,128}', leaf), 'unknown: cloud-init dependency name unproved')
            item = _cloud_graph_directory(host, logical + '/' + leaf)
            need(item is not None, 'unknown: cloud-init dependency directory disappeared')
            children = os.listdir(item[1])
            need(len(children) <= 4096, 'unknown: cloud-init dependency bound')
            signature.append((logical + '/' + leaf, item[2].st_dev, item[2].st_ino, item[2].st_mode))
            for child in sorted(children):
                need(re.fullmatch(r'[A-Za-z0-9_.@+-]{1,128}', child), 'unknown: cloud-init dependency name unproved')
                path = item[1] / child; before = cloud_lstat(path)
                need(stat.S_ISLNK(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1,
                     'unknown: cloud-init dependency is not an owned symlink')
                target = os.readlink(path); after = cloud_lstat(path)
                facts = lambda entry: (entry.st_dev, entry.st_ino, entry.st_uid, entry.st_mode, entry.st_nlink, entry.st_ctime_ns)
                need(facts(before) == facts(after), 'unknown: cloud-init dependency changed')
                dependencies.append((logical, leaf, child, target, facts(before)))
        for prefix in ('service.d', 'socket.d', 'target.d', 'cloud-.service.d', 'cloud-.socket.d', 'cloud-.target.d'):
            item = _cloud_graph_directory(host, logical + '/' + prefix)
            if item is None: continue
            signature.append((logical + '/' + prefix, item[2].st_dev, item[2].st_ino, item[2].st_mode))
            children = os.listdir(item[1]); need(len(children) <= 4096, 'unknown: generic cloud override bound')
            overrides.extend(logical + '/' + prefix + '/' + child for child in sorted(children) if child.endswith('.conf'))
    return dependencies, overrides, signature


def _cloud_validate_graph(host, snapshots, pins):
    graph = _cloud_graph_inventory(host)
    need(not graph[1], 'unknown: generic cloud-init condition override unproved')
    units = {path.rsplit('/', 1)[1] for path in pins if '/system/' in path}
    for base, parent, leaf, target, facts in graph[0]:
        need(leaf in units, 'unknown: cloud-init dependency can start unreviewed code')
        allowed = {'/usr/lib/systemd/system/' + leaf}
        if _cloud_graph_directory(host, '/lib/systemd/system') and os.stat(host('/lib/systemd/system')).st_ino == os.stat(host('/usr/lib/systemd/system')).st_ino and os.stat(host('/lib/systemd/system')).st_dev == os.stat(host('/usr/lib/systemd/system')).st_dev:
            allowed.add('/lib/systemd/system/' + leaf)
        if base == '/usr/lib/systemd/system': allowed.add('../' + leaf)
        need(target in allowed, 'unknown: cloud-init dependency target unproved')
    snapshots['cloud_dependency_graph'] = digest(graph)
    return graph


def _cloud_pid1_units(run):
    rows = run('systemctl', 'list-units', '--all', '--no-legend', '--no-pager',
               '--plain', *CLOUD_UNIT_PATTERNS).decode('utf-8', 'strict').splitlines()
    need(len(rows) <= 4096, 'unknown: cloud-init unit list bound')
    names = set()
    for row in rows:
        tokens = row.split()
        if tokens and tokens[0] in ('\u25cf', '*'):
            tokens = tokens[1:]
        # A unit only referenced by another unit's dependency is listed as
        # not-found; it has no fragment and cannot run.
        if not tokens or len(tokens) > 1 and tokens[1] == 'not-found':
            continue
        names.add(tokens[0])
    return names


def _cloud_marker(host, snapshots):
    """Early boot reads the marker from the root mount before local-fs.target."""
    root_meta = cloud_lstat(host('/'))
    for name in ('/etc', '/etc/cloud'):
        meta = cloud_lstat(host(name))
        need(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0 and
             not meta.st_mode & 0o022 and meta.st_dev == root_meta.st_dev,
             'unknown: cloud-init marker directory is not a root-owned root-filesystem directory')
    with open(host('/proc/self/mountinfo'), 'rb') as stream:
        mountinfo = stream.read(4 << 20).decode('utf-8', 'surrogateescape')
    root_fs = None
    for line in mountinfo.splitlines():
        fields = line.split(' ')
        need(len(fields) >= 10 and ' - ' in line, 'unknown: mount table unreadable')
        point = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), fields[4])
        need(point not in ('/etc', '/etc/cloud', CLOUD_MARKER),
             'unknown: cloud-init marker path is a separate mount')
        if point == '/':
            root_fs = line.split(' - ', 1)[1].split(' ', 1)[0]
    need(root_fs in CLOUD_LOCAL_ROOT_FS, 'unknown: cloud-init marker is not on a local root filesystem')
    marker = host(CLOUD_MARKER)
    meta = cloud_lstat(marker)
    need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_nlink == 1 and
         not meta.st_mode & 0o022 and meta.st_dev == root_meta.st_dev and
         meta.st_size <= 4096,
         'unknown: cloud-init marker is not one regular root-owned file on the root filesystem')
    fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        need((opened.st_dev, opened.st_ino) == (meta.st_dev, meta.st_ino),
             'unknown: cloud-init marker changed while checked')
        raw = os.read(fd, 4097)
    finally:
        os.close(fd)
    snapshots[str(marker)] = hashlib.sha256(raw).hexdigest()
    # The marker inode must predate this boot: zero unit timestamps alone do
    # not prove cloud-init never ran, because an unreferenced stopped unit is
    # garbage-collected and reloaded with zero timestamps.
    with open(host('/proc/stat'), 'rb') as stream:
        btime = re.search(rb'^btime ([0-9]{1,12})$', stream.read(1 << 20), re.M)
    need(btime is not None and meta.st_ctime_ns < int(btime.group(1)) * 10**9,
         'unknown: cloud-init marker was created after this boot started')


def _cloud_disabled_profile(host, snapshots, read, run, items, generators, pid1):
    profiles = (CLOUD_DISABLED_NOBLE_PINS, CLOUD_DISABLED_PINS)
    units = {path.rsplit('/', 1)[1] for path in items}
    need(all(path.startswith('/usr/lib/systemd/system/') for path in items) and
         generators == {'/usr/lib/systemd/system-generators/cloud-init-generator'},
         'unknown: cloud-init unit outside the reviewed package paths')
    chosen = [pins for pins in profiles if units == {path.rsplit('/', 1)[1] for path in pins
                                                     if '/system/' in path}]
    need(len(chosen) == 1, 'unknown: unreviewed cloud-init unit layout')
    pins = chosen[0]
    graph = _cloud_validate_graph(host, snapshots, pins)
    need(pid1 <= units, 'unknown: unreviewed cloud-init unit known to PID1')
    for name in ('/run/cloud-init/status.json', '/run/cloud-init/instance-data.json'):
        need(not os.path.lexists(host(name)), 'unknown: cloud-init ran in this boot')
    for path, sha in pins.items():
        raw = read(host(path))
        need(hashlib.sha256(raw).hexdigest() == sha, 'unknown: modified disabled cloud-init code')
        snapshots[str(host(path))] = sha
        if '/system-generators/' in path:
            continue
        unit = path.rsplit('/', 1)[1]
        if unit != 'cloud-config.target':
            need(CLOUD_CONDITION in raw, 'unknown: cloud-init disable condition missing')
        fields = ['FragmentPath', 'DropInPaths', 'NeedDaemonReload', 'ActiveState',
                  'LoadState', 'UnitFileState', 'InactiveExitTimestampMonotonic']
        if unit.endswith('.service'):
            fields.append('ExecMainStartTimestampMonotonic')
        argv = ['systemctl', 'show', unit]
        for field in fields:
            argv += ['-p', field]
        props = dict(line.split('=', 1) for line in run(*argv).decode().splitlines())
        expected = {'FragmentPath': str(host(path)), 'DropInPaths': '',
                    'NeedDaemonReload': 'no', 'ActiveState': 'inactive',
                    'LoadState': 'loaded', 'InactiveExitTimestampMonotonic': '0'}
        if unit.endswith('.service'):
            expected['ExecMainStartTimestampMonotonic'] = '0'
        state = props.pop('UnitFileState', None)
        need(props == expected and state in ('enabled', 'static', 'disabled', 'indirect'),
             'unknown: disabled cloud-init unit override or activity in this boot')
    need(_cloud_graph_inventory(host) == graph, 'unknown: cloud-init dependency graph changed')


def verify_cloud_init_boot(snapshots, root=None, read=None, run=None):
    """Return 'absent' or 'disabled_proved'; refuse every active cloud-init.

    Files under /run describe only the current boot and an active cloud-init
    runs seed-supplied root code before the AEGIS guard, so no datasource is
    admitted. The optional root/read/run are for isolated synthetic tests.
    """
    root = Path('/') if root is None else root
    read = trusted_read if read is None else read
    run = command if run is None else run
    def host(path):
        return root / path.lstrip('/')
    marker = os.path.lexists(host(CLOUD_MARKER))
    try:
        items = _cloud_items(host, CLOUD_UNIT_DIRS)
        generators = _cloud_items(host, CLOUD_GENERATOR_DIRS)
        pid1 = _cloud_pid1_units(run)
        graph = _cloud_graph_inventory(host)
        present = bool(items or generators or pid1 or graph[0] or any(
            os.path.lexists(host(name)) for name in CLOUD_INDICATORS))
        if present and not marker:
            raise CloudInitRefusal(CLOUD_INIT_ACTIVE, 'network_required: cloud-init active: '
                                   'datasource ' + _cloud_datasource_token(host, read))
        if present:
            _cloud_marker(host, snapshots)
            _cloud_disabled_profile(host, snapshots, read, run, items, generators, pid1)
    except CloudInitRefusal:
        raise
    except TimeoutError:
        raise
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        detail = str(error) if str(error).startswith('unknown: ') and len(str(error)) <= 160 \
            else 'unknown: cloud-init boot state unproved'
        raise CloudInitRefusal(CLOUD_INIT_UNPROVED if marker else CLOUD_INIT_ACTIVE,
                               detail) from error
    for rootdir in ('/etc/cloud/cloud.cfg.d', '/run/cloud-init'):
        for path in sorted(set(host(rootdir).glob('*.yaml')) |
                           set(host(rootdir).glob('*.cfg'))):
            try:
                text = read(path, 2 << 20).decode('utf-8')
            except (OSError, ValueError) as error:
                raise CloudInitRefusal(CLOUD_INIT_ACTIVE,
                    'unknown: cloud-init configuration unreadable') from error
            if re.search(r'ephemeral_dhcp|activate_by_schema|dhcp4:\s*true', text):
                raise CloudInitRefusal(CLOUD_INIT_ACTIVE,
                    'network_required: cloud-init ephemeral DHCP in ' +
                    _cloud_token(path.name, r'[A-Za-z0-9_.-]{1,128}', 128))
    return 'disabled_proved' if present else 'absent'


@contextlib.contextmanager
def _cloud_parent(root, logical, *, create=False):
    """Pin each root-owned ancestor, never follow an administration symlink."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(root, flags)
    try:
        for part in ('', *Path(logical).parts[1:-1]):
            if part:
                if create:
                    try: os.mkdir(part, 0o700, dir_fd=fd)
                    except FileExistsError: pass
                    else: os.fsync(fd)
                child = os.open(part, flags, dir_fd=fd)
                os.close(fd); fd = child
            meta = os.fstat(fd)
            need(meta.st_uid == meta.st_gid == 0 and not meta.st_mode & 0o022,
                 'untrusted cloud preparation directory')
        yield fd, Path(logical).name
    finally:
        os.close(fd)


def _cloud_edge(fd, leaf):
    try: meta = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError: return None
    need(stat.S_ISLNK(meta.st_mode) and meta.st_uid == meta.st_gid == 0 and
         meta.st_nlink == 1 and os.readlink(leaf, dir_fd=fd) == CLOUD_BOOTSTRAP_TARGET,
         'foreign cloud bootstrap dependency')
    return (meta.st_dev, meta.st_ino, meta.st_ctime_ns)


def _cloud_preparation_quiet(root, run):
    for name in ('/var/lib/aegis-install/client/auto-guardian-install.json',
                 '/var/lib/aegis-auto/control', '/var/lib/aegis-install/client/device-guard.conf'):
        need(not os.path.lexists(root / name.lstrip('/')),
             'cloud preparation requires complete AUTO teardown')
    for unit in ('aegis-client.service', 'aegis-auto-guardian.service',
                 'aegis-auto-guardian-watchdog.service', 'aegis-device-egress-guard.service',
                 'aegis-foreign-policy-monitor.service', 'aegis-auto-capture-topology.service',
                 'aegis-device-dhcp-refresh.service'):
        props = dict(line.split('=', 1) for line in run('systemctl', 'show', unit,
            '-p', 'ActiveState', '-p', 'MainPID', '-p', 'ControlPID', timeout=5).decode().splitlines())
        need(props in ({'ActiveState': 'inactive', 'MainPID': '0', 'ControlPID': '0'},
                       {'ActiveState': 'failed', 'MainPID': '0', 'ControlPID': '0'}),
             'cloud preparation requires inactive AEGIS actors')


def _cloud_preparation_read(fd, leaf):
    try: stream = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    except FileNotFoundError: return None
    try:
        meta = os.fstat(stream)
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid == meta.st_gid == 0 and
             stat.S_IMODE(meta.st_mode) == 0o600 and meta.st_nlink == 1 and meta.st_size <= 4096,
             'untrusted cloud preparation journal')
        raw = os.read(stream, 4097)
        value = decode(raw)
        need(set(value) == {'schema', 'edge', 'target', 'phase', 'before'} and
             value['schema'] == 'aegis_cloud_dependency_preparation_v1' and
             value['edge'] == CLOUD_BOOTSTRAP_EDGE and value['target'] == CLOUD_BOOTSTRAP_TARGET and
             value['phase'] in ('detaching', 'prepared', 'restoring', 'restored') and
             type(value['before']) is list and len(value['before']) == 3 and
             all(type(n) is int and n >= 0 for n in value['before']),
             'unproved cloud preparation journal')
        return value
    finally:
        os.close(stream)


def _cloud_preparation_save(fd, leaf, value, *, exclusive=False):
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    temp = '.cloud-preparation-' + os.urandom(16).hex()
    out = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        with os.fdopen(out, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        if exclusive:
            os.link(temp, leaf, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
        else:
            os.rename(temp, leaf, src_dir_fd=fd, dst_dir_fd=fd)
    finally:
        try: os.unlink(temp, dir_fd=fd)
        except FileNotFoundError: pass  # A successful rename consumed the temporary name.
        os.fsync(fd)


def _cloud_restore_edge(edge_fd, edge_leaf, journal_fd, journal_leaf, value, run):
    value = {**value, 'phase': 'restoring'}
    _cloud_preparation_save(journal_fd, journal_leaf, value)
    if _cloud_edge(edge_fd, edge_leaf) is None:
        os.symlink(CLOUD_BOOTSTRAP_TARGET, edge_leaf, dir_fd=edge_fd)
        os.fsync(edge_fd)
    _cloud_edge(edge_fd, edge_leaf)  # Refuse to replace a foreign file or target.
    run('systemctl', 'daemon-reload', timeout=30)
    value['phase'] = 'restored'
    _cloud_preparation_save(journal_fd, journal_leaf, value)


def prepare_cloud_dependencies(*, opt_in=False, root=None, read=None, run=None):
    """Detach one stock bootstrap edge before installation, with a durable inverse.

    This never admits snapd to the cloud profile. A recreated dependency still
    refuses in both the read-only preflight and the switch-root barrier.
    """
    need(os.geteuid() == 0 and opt_in, 'explicit root --opt-in required for cloud preparation')
    root = Path('/') if root is None else Path(root)
    read = trusted_read if read is None else read
    run = command if run is None else run
    _cloud_marker(lambda name: root / name.lstrip('/'), {})
    _cloud_preparation_quiet(root, run)
    if not os.path.lexists(root / CLOUD_BOOTSTRAP_EDGE.lstrip('/')) and not os.path.lexists(
            root / CLOUD_BOOTSTRAP_JOURNAL.lstrip('/')):
        need(verify_cloud_init_boot({}, root, read, run) == 'disabled_proved',
             'cloud preparation profile unproved')
        return {'phase': 'not_needed', 'changed': False}
    with _cloud_parent(root, CLOUD_BOOTSTRAP_EDGE) as (edge_fd, edge_leaf), \
         _cloud_parent(root, CLOUD_BOOTSTRAP_JOURNAL, create=True) as (journal_fd, journal_leaf):
        before = _cloud_edge(edge_fd, edge_leaf)
        value = _cloud_preparation_read(journal_fd, journal_leaf)
        if value is not None and value['phase'] == 'prepared' and before is None:
            need(verify_cloud_init_boot({}, root, read, run) == 'disabled_proved',
                 'cloud preparation profile unproved')
            return {'phase': 'prepared', 'changed': False}
        if before is None:
            need(value is not None and value['phase'] == 'detaching',
                 'stock cloud bootstrap dependency absent without preparation ownership')
        elif value is None or value['phase'] == 'restored':
            if value is not None:
                _cloud_preparation_save(journal_fd, 'cloud-bootstrap-history-' + os.urandom(16).hex() + '.json',
                                        value, exclusive=True)
            value = {'schema': 'aegis_cloud_dependency_preparation_v1',
                     'edge': CLOUD_BOOTSTRAP_EDGE, 'target': CLOUD_BOOTSTRAP_TARGET,
                     'phase': 'detaching', 'before': list(before)}
            _cloud_preparation_save(journal_fd, journal_leaf, value)
        else:
            need(value['phase'] == 'detaching' and list(before) == value['before'],
                 'cloud preparation interrupted by another dependency generation')
        try:
            if before is not None:
                need(_cloud_edge(edge_fd, edge_leaf) == before, 'cloud bootstrap dependency changed')
                os.unlink(edge_leaf, dir_fd=edge_fd); os.fsync(edge_fd)
            run('systemctl', 'daemon-reload', timeout=30)
            need(verify_cloud_init_boot({}, root, read, run) == 'disabled_proved',
                 'cloud preparation profile unproved')
            value['phase'] = 'prepared'
            _cloud_preparation_save(journal_fd, journal_leaf, value)
            return {'phase': 'prepared', 'changed': True}
        except BaseException:
            _cloud_restore_edge(edge_fd, edge_leaf, journal_fd, journal_leaf, value, run)
            raise


def restore_cloud_dependencies(*, opt_in=False, root=None, read=None, run=None):
    need(os.geteuid() == 0 and opt_in, 'explicit root --opt-in required for cloud restoration')
    root = Path('/') if root is None else Path(root)
    run = command if run is None else run
    if not os.path.lexists(root / CLOUD_BOOTSTRAP_JOURNAL.lstrip('/')):
        return {'phase': 'absent', 'changed': False}
    _cloud_preparation_quiet(root, run)
    with _cloud_parent(root, CLOUD_BOOTSTRAP_EDGE) as (edge_fd, edge_leaf), \
         _cloud_parent(root, CLOUD_BOOTSTRAP_JOURNAL) as (journal_fd, journal_leaf):
        value = _cloud_preparation_read(journal_fd, journal_leaf)
        need(value is not None, 'cloud preparation journal disappeared')
        if value['phase'] == 'restored':
            need(_cloud_edge(edge_fd, edge_leaf) is not None, 'restored cloud dependency disappeared')
            return {'phase': 'restored', 'changed': False}
        _cloud_restore_edge(edge_fd, edge_leaf, journal_fd, journal_leaf, value, run)
        return {'phase': 'restored', 'changed': True}


def detect_local_root():
    """No mutation. Returns only local_provable; errors retain a precise class."""
    need(os.geteuid() == 0, 'unknown: root required')
    cmdline = Path('/proc/cmdline').read_text()
    inspect_cmdline(cmdline)
    need(any(x.startswith('root=') for x in cmdline.split()), 'unknown: implicit root')
    snapshots = {}
    for path in config_paths():
        if path == DROPIN:
            continue
        raw = trusted_read(path)
        snapshots[str(path)] = hashlib.sha256(raw).hexdigest()
        if str(path) in REVIEWED_DRACUT_CONFIG:
            need(hashlib.sha256(raw).hexdigest()==REVIEWED_DRACUT_CONFIG[str(path)],
                 'unknown: modified vendor dracut configuration')
            continue
        text = raw.decode('utf-8', errors='strict')
        # Scan keys in every configured next-boot line, including quoted GRUB
        # assignments and dracut kernel_cmdline; never evaluate shell content.
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            need(not re.search(r'(?<![A-Za-z_])(?:' + '|'.join(re.escape(k) for k in
                NETWORK_KEYS) + r'|rd\.nvmf\.[A-Za-z0-9_.-]+)\s*=', line),
                'network_required: configured early networking')
            need(not re.search(r'(?<![A-Za-z0-9_])(?:LD_[A-Za-z0-9_]+|' +
                 '|'.join(re.escape(k) for k in sorted(BOOT_ENVIRONMENT_KEYS)) + r')\s*=', line),
                 'unknown: configured unsafe init environment')
            need(not re.search(r'(?<![A-Za-z0-9_])rdinit\s*=', line),
                 'unknown: configured alternate init')
            need(not re.search(r'\b(?:netconsole|kgdboe|clevis|tang)\b', line),
                 'network_required: early module or unlock service')
            need(not re.search(r'root=(?:nfs:|iscsi:|nbd:|dhcp|/dev/nfs)', line),
                 'network_required: configured network root')
            if 'dracut' in str(path):
                key, sep, value = line.partition('=')
                key = key.strip().rstrip('+').strip()
                need(sep and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key), 'unknown: dracut shell action')
                need(key not in ('dracutmodules', 'install_items', 'install_optional_items',
                    'fstab_lines', 'add_fstab', 'include_src', 'include_target', 'add_device'),
                    'unknown: custom dracut payload')
                literal=value.strip()
                if len(literal)>=2 and literal[0]==literal[-1] and literal[0] in ('\"',"'"):
                    literal=literal[1:-1]
                need(re.fullmatch(r'[A-Za-z0-9_./ ,:+@=*-]*',literal) is not None,
                     'unknown: executable dracut configuration')
                if key in ('add_dracutmodules', 'force_add_dracutmodules'):
                    need(not (set(shlex.split(value.replace('"', '').replace("'", ''))) & OMIT),
                         'network_required: forced dracut network module')
                if path.parent == DROPIN.parent:
                    need(path.name < DROPIN.name, 'unknown: dracut policy after AEGIS')
    for path in ('/sys/firmware/ibft', '/sys/firmware/acpi/tables/NBFT',
                 '/sys/module/netconsole', '/sys/kernel/config/netconsole'):
        need(not Path(path).exists(), 'network_required: firmware or netconsole')
    iscsi = Path('/sys/class/iscsi_session')
    need(not iscsi.exists() or not list(iscsi.iterdir()), 'network_required: iSCSI session')
    root = decode(command('findmnt', '-J', '-o', 'SOURCE,FSTYPE,TARGET', '/'))['filesystems']
    need(len(root) == 1 and root[0]['fstype'] in ('ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'f2fs'),
         'unknown: unsupported root filesystem')
    source = root[0]['source'].split('[', 1)[0]
    need(source.startswith('/dev/'), 'unknown: non-device root')
    tree = decode(command('lsblk', '-J', '-s', '-p', '-o', 'NAME,TYPE,TRAN,FSTYPE', source))
    def block(node):
        name, typ, transport = node.get('name', ''), node.get('type'), node.get('tran')
        need(not re.search(r'/(?:nbd|rbd|loop)', name) and
             transport not in ('iscsi', 'fc') and typ not in ('loop', 'rom'),
             'network_required: root device transport')
        if 'nvme' in name:
            controller = re.search(r'(nvme\d+)', name)
            need(controller is not None and Path('/sys/class/nvme/' + controller[1] +
                '/transport').read_text().strip() == 'pcie', 'unknown: NVMe transport')
        if node.get('fstype') == 'crypto_LUKS':
            tokens = command('cryptsetup', 'luksDump', '--dump-json-metadata',
                             name, timeout=3)
            metadata = decode(tokens)
            need(not metadata.get('tokens'), 'unknown: token-bound encrypted root')
        children = node.get('children', [])
        need(type(children) is list and len(children) <= 128, 'unknown: root topology bound')
        for child in children:
            block(child)
    for node in tree['blockdevices']:
        block(node)
    for path in ('/etc/fstab', '/etc/crypttab'):
        if Path(path).exists():
            for line in read_config(path).splitlines():
                if not line.strip() or line.lstrip().startswith('#'):
                    continue
                need(not re.search(r'_netdev|\b(?:nfs|nfs4|cifs|ceph|glusterfs|9p)\b|keyscript=|clevis|tang', line),
                     'network_required: mount or unlock policy')
                need(not re.search(r'tpm2-device=|fido2-device=|pkcs11-uri=', line),
                     'unknown: hardware-bound encrypted root')
    for rootdir in ('/etc/clevis', '/etc/tang', '/run/credentials/systemd-stub', '/sys/firmware/efi/efivars'):
        p = Path(rootdir)
        if rootdir.endswith('efivars'):
            need(not p.exists() or not list(p.glob('StubInfo-*')), 'unknown: UKI boot')
        else:
            need(not p.exists(), 'unknown: network unlock or UKI')
    verify_cloud_init_boot(snapshots)
    for kernel_path in sorted(Path('/boot').glob('vmlinuz-*')):
        kernel = kernel_path.name.removeprefix('vmlinuz-')
        need(KERNEL.fullmatch(kernel), 'unknown: kernel name')
        config = read_config('/boot/config-' + kernel)
        need(not re.search(r'^CONFIG_(?:IP_PNP|NETCONSOLE)=y$', config, re.M),
             'network_required: built-in early network support')
    boot = decode(command('findmnt', '-J', '-T', '/boot', '-o', 'FSTYPE'))['filesystems']
    need(len(boot) == 1 and boot[0]['fstype'] not in ('vfat', 'msdos', 'fat', 'efivarfs'),
         'unknown: ESP-backed boot directory')
    for p in ('/boot', '/var'):
        fs = os.statvfs(p)
        need(fs.f_bavail * fs.f_frsize >= (512 << 20), 'unknown: insufficient free ' + p)
    return {'class': 'local_provable', 'config_sha256': digest(snapshots),
            'root_source_sha256': hashlib.sha256(source.encode()).hexdigest()}


def classic_identity_fragment(nonce):
    """Use the checked initrd root FD7; publish identity only once per boot."""
    need(type(nonce) is str and re.fullmatch('[0-9a-f]{64}', nonce), 'invalid classic build identity')
    expected = hashlib.sha256((nonce + '\n').encode()).hexdigest()
    return ('''# AEGIS classic initrd identity: image input is checked before publication.
classic_saved_base=$BASE
BASE=/proc/self/fd/7
file_generation /etc/aegis-initrd-id ''' + expected + ''' 128
safe_dir /run || refuse
[[ ! -e $BASE/run/aegis-initrd-id && ! -L $BASE/run/aegis-initrd-id ]] || refuse
(umask 077; set -o noclobber; printf '%s\\n' ''' + shlex.quote(nonce) + ''' > "$BASE/run/aegis-initrd-id") || refuse
file_generation /run/aegis-initrd-id ''' + expected + ''' 128
BASE=$classic_saved_base
''').encode()


def classic_overlay_recheck_fragment():
    return r'''# Never source rootfs overlay configuration under the trusted initrd.
classic_overlay_check() {
    local LC_ALL=C
    local logical=$1 line before hash consumed=0 size mode uid perm links dev ino mt ct tail
    local ascii_re='^[ -~]*$'
    local disabled_re="^[[:space:]]*(overlayroot|overlayroot_cfgdisk)=(\\\"\\\"|''|\\\"disabled\\\"|'disabled'|disabled)[[:space:]]*$"
    if ! safe_dir "${logical%/*}"; then return 0; fi
    if [[ ! -e $BASE$logical && ! -L $BASE$logical ]]; then return 0; fi
    file_generation "$logical" '*' 16384
    before=${GOT%|*}; hash=${GOT##*|}
    IFS='|' read -r mode uid perm links size dev ino mt ct tail <<< "$before"
    exec 8<"$BASE$logical" || refuse
    [[ $(/usr/bin/gnustat -Lc "$FILEFMT" -- /proc/self/fd/8) == "$before" ]] || refuse
    while IFS= read -r line; do
        (( consumed+=${#line}+1 ))
        [[ $line =~ $ascii_re ]] || refuse
        [[ $line =~ ^[[:space:]]*(#.*)?$ || $line =~ $disabled_re ]] || refuse
    done < /proc/self/fd/8
    (( consumed == size )) || refuse
    [[ $(/usr/bin/gnustat -Lc "$FILEFMT" -- /proc/self/fd/8) == "$before" ]] || refuse
    exec 8<&-
    file_generation "$logical" "$hash" 16384
    [[ ${GOT%|*} == "$before" ]] || refuse
}
classic_overlay_check /etc/overlayroot.conf
classic_overlay_check /etc/overlayroot.local.conf
classic_overlay_check /etc/initramfs-tools/conf.d/overlayroot
'''


def classic_late_recheck_script(nonce):
    fragment = classic_identity_fragment(nonce).decode()
    script = cloud_init_recheck_script(root_mount='/root').decode()
    passed = "printf '%s\\n' '{\"schema\":\"aegis_initrd_cloud_gate_v1\",\"status\":\"passed\"}'\n"
    need(script.count(passed) == 1, 'classic cloud handoff source changed')
    final_check = '''verify_root_mount
[[ $(/usr/bin/gnustat -c "$DIRFMT" -- /root) == "$ROOT_BEFORE" &&
   $(/usr/bin/gnustat -Lc "$DIRFMT" -- /proc/self/fd/9) == "$ROOT_BEFORE" ]] || refuse
'''
    return script.replace(passed, fragment + classic_overlay_recheck_fragment() + final_check + passed).encode()


def classic_cmdline_recheck_script():
    """Trusted Bash-only check, before classic /init parses early networking."""
    script = r'''#!/usr/bin/bash -p
set -Eeuo pipefail
PATH=/usr/bin:/bin
LC_ALL=C
export PATH LC_ALL
unset BASH_ENV ENV CDPATH GLOBIGNORE
refuse() {
    printf '%s\n' '{"schema":"aegis_initrd_cmdline_gate_v1","status":"refused","code":"initrd_early_network_unverified","action":"use_reviewed_local_boot_image"}' >&2
    exit 78
}
line=
IFS= read -r -n 1048577 line < @CMDLINE@ || [[ -n $line ]] || refuse
[[ ${#line} -le 1048576 ]] || refuse
read -r -a words <<< "$line"
saw_root=0
for token in "${words[@]}"; do
    # Linux next_arg() strips one leading whole-token double quote. read -a
    # retains it, so normalize before testing keys; values are never executed.
    token=${token#\"}
    key=${token%%=*}
    value=${token#*=}
    case "$key" in
        LD_*|@ENVIRONMENT_KEYS@) refuse;;
        @NETWORK_KEYS@|rd.net.*|rd.iscsi.*|iscsi_*|rd.nvmf.*) refuse;;
        break|debug|rd.break|rd.shell|rd.debug|rdinit) refuse;;
        init) case "$value" in /sbin/init|/lib/systemd/systemd|/usr/lib/systemd/systemd) ;; *) refuse;; esac;;
        root)
            [[ $saw_root == 0 && $token == *=* && -n $value ]] || refuse
            case "$value" in /dev/nfs|/dev/nbd*) refuse;; esac
            case "$value" in /dev/?*|UUID=?*|LABEL=?*|PARTUUID=?*|PARTLABEL=?*) ;; *) refuse;; esac
            saw_root=1;;
        copymods) [[ $token == copymods=force ]] || refuse;;
        boot) [[ $token == boot=local ]] || refuse;;
        rootfstype) case "$value" in @LOCAL_FS@) ;; *) refuse;; esac;;
    esac
done
[[ $saw_root == 1 ]] || refuse
'''
    return script.replace('@CMDLINE@', shlex.quote(CLASSIC_CMDLINE_SOURCE)).replace(
        '@NETWORK_KEYS@', '|'.join(shlex.quote(name) for name in sorted(NETWORK_KEYS))).replace(
        '@ENVIRONMENT_KEYS@', '|'.join(sorted(BOOT_ENVIRONMENT_KEYS))).replace(
        '@LOCAL_FS@', '|'.join(CLOUD_LOCAL_ROOT_FS)).encode()


def classic_switch_root_init(init_raw, functions_raw):
    """Put the refusal in the stock parent, after cleanup and before /run moves.

    A failing init-bottom child is not a hard dependency in initramfs-tools.
    This source factory therefore holds PID1 itself and exposes no debug shell.
    It never changes an image or selects the classic profile on its own.
    """
    for name, raw in (('init', init_raw), ('scripts/functions', functions_raw)):
        need(type(raw) is bytes and len(raw) <= 1 << 20 and
             hashlib.sha256(raw).hexdigest() == CLASSIC_BOOT_SOURCE_PINS[name],
             'unreviewed classic init control flow')
    boundary = b'\nrun_scripts /scripts/init-bottom\n'
    early_boundary = b'\nmount -t proc -o nodev,noexec,nosuid proc /proc\n'
    nfs_source = b'\n. /scripts/nfs\n'
    nfs_cleanup = b'\nnfs_bottom\n'
    need(init_raw.count(boundary) == init_raw.count(early_boundary) ==
         init_raw.count(nfs_source) == init_raw.count(nfs_cleanup) == 1 and
         init_raw.index(early_boundary) < init_raw.index(boundary), 'ambiguous classic init handoff')
    local_only = b'''
# AEGIS: the stock parent sources NFS even for local roots. Its implementation
# is absent from this image; any remote /usr dispatch must hold, not fall back.
aegis_classic_refuse_network() {
    printf '%s\\n' '{"schema":"aegis_initrd_cmdline_gate_v1","status":"refused","code":"initrd_early_network_unverified","action":"use_reviewed_local_boot_image"}' >&2
    while :; do /bin/sleep 3600 || :; done
}
nfs_mount_root() { aegis_classic_refuse_network; }
nfs_mount_fs() { aegis_classic_refuse_network; }
[ "${BOOT}" = local ] || aegis_classic_refuse_network
'''
    sanitize = ('unset ' + ' '.join(CLASSIC_LOADER_ENVIRONMENT) + ' || exit 78\n').encode()
    early = sanitize + ('''# AEGIS: inspect kernel input before any stock parser or boot hook.
if ! /usr/bin/bash -p ''' + shlex.quote(CLASSIC_CMDLINE_HELPER) + '''; then
    printf '%s\\n' '{"schema":"aegis_initrd_cmdline_gate_v1","status":"refused","code":"initrd_early_network_unverified","action":"use_reviewed_local_boot_image"}' >&2
    while :; do /bin/sleep 3600 || :; done
fi
''').encode()
    # The fixed helper path is source, never a rootfs/environment argument.
    barrier = sanitize + ('''# AEGIS: PID1 holds a refused transition; run_scripts may ignore child status.
if [ "${rootmnt}" != /root ] || ! /usr/bin/bash -p ''' + shlex.quote(CLASSIC_GATE_HELPER) + '''; then
    printf '%s\\n' '{"schema":"aegis_initrd_cloud_gate_v1","status":"refused","code":"cloud_init_disabled_profile_unproved","action":"restore_reviewed_cloud_init_marker_profile","source_line":0}' >&2
    while :; do /bin/sleep 3600 || :; done
fi
''').encode()
    return init_raw.replace(early_boundary, early_boundary + early).replace(
        nfs_source, local_only).replace(nfs_cleanup, b'\n').replace(boundary, boundary + barrier)


def classic_build_payloads(nonce, init_raw, functions_raw):
    """Pure source factory; production/admission of a whole image is separate."""
    need(type(nonce) is str and re.fullmatch('[a-f0-9]{64}', nonce), 'invalid classic build identity')
    return {
        'init': (classic_switch_root_init(init_raw, functions_raw), 0o755),
        'etc/aegis-initrd-id': ((nonce + '\n').encode(), 0o644),
        'etc/passwd': (b'root:!:0:0:root:/root:/bin/sh\n', 0o644),
        'etc/group': (b'root:x:0:\ndisk:x:6:\ntty:x:5:\n', 0o644),
        'etc/nsswitch.conf': (LOCAL_NSS, 0o644),
        CLASSIC_GATE_HELPER[1:]: (classic_late_recheck_script(nonce), 0o644),
        CLASSIC_CMDLINE_HELPER[1:]: (classic_cmdline_recheck_script(), 0o644),
    }


CLASSIC_REMOTE_MODULE_TREES = ('net', 'drivers/net', 'drivers/infiniband',
    'drivers/nvme/target', 'fs/nfs', 'fs/nfs_common', 'fs/lockd', 'fs/netfs',
    'fs/cifs', 'fs/smb', 'fs/ceph')
CLASSIC_REMOTE_MODULE_LEAVES = ('drivers/block/nbd', 'drivers/block/rbd',
    'drivers/firmware/iscsi_ibft', 'drivers/scsi/iscsi_boot_sysfs',
    'drivers/scsi/iscsi_tcp', 'drivers/scsi/libiscsi', 'drivers/scsi/libiscsi_tcp',
    'drivers/scsi/scsi_transport_iscsi', 'drivers/scsi/libfc', 'drivers/scsi/libfcoe',
    'drivers/scsi/fcoe', 'drivers/scsi/scsi_transport_fc',
    'drivers/scsi/lpfc/lpfc', 'drivers/scsi/qla2xxx/qla2xxx',
    'drivers/message/fusion/mptfc', 'drivers/nvme/host/nvme-fabrics', 'drivers/nvme/host/nvme-fc',
    'drivers/nvme/host/nvme-rdma', 'drivers/nvme/host/nvme-tcp')


# Pristine published image7df02015, kernel6.8.0-134-generic.
CLASSIC_LOCAL_MODULE_ROLES = frozenset((
    'drivers/md/dm-mod',
    'arch/arm64/crypto/aes-arm64',
    'arch/arm64/crypto/aes-ce-blk',
    'arch/arm64/crypto/aes-ce-ccm',
    'arch/arm64/crypto/aes-ce-cipher',
    'arch/arm64/crypto/aes-neon-blk',
    'arch/arm64/crypto/aes-neon-bs',
    'arch/arm64/crypto/chacha-neon',
    'arch/arm64/crypto/crct10dif-ce',
    'arch/arm64/crypto/ghash-ce',
    'arch/arm64/crypto/nhpoly1305-neon',
    'arch/arm64/crypto/poly1305-neon',
    'arch/arm64/crypto/polyval-ce',
    'arch/arm64/crypto/sha1-ce',
    'arch/arm64/crypto/sha2-ce',
    'arch/arm64/crypto/sha256-arm64',
    'arch/arm64/crypto/sha3-ce',
    'arch/arm64/crypto/sm3-ce',
    'arch/arm64/crypto/sm3-neon',
    'arch/arm64/crypto/sm4-ce',
    'arch/arm64/crypto/sm4-ce-ccm',
    'arch/arm64/crypto/sm4-ce-cipher',
    'arch/arm64/crypto/sm4-ce-gcm',
    'arch/arm64/crypto/sm4-neon',
    'arch/arm64/lib/xor-neon',
    'crypto/842',
    'crypto/adiantum',
    'crypto/aegis128',
    'crypto/aes_ti',
    'crypto/af_alg',
    'crypto/algif_aead',
    'crypto/algif_hash',
    'crypto/algif_rng',
    'crypto/algif_skcipher',
    'crypto/ansi_cprng',
    'crypto/aria_generic',
    'crypto/asymmetric_keys/pkcs7_test_key',
    'crypto/asymmetric_keys/pkcs8_key_parser',
    'crypto/async_tx/async_memcpy',
    'crypto/async_tx/async_pq',
    'crypto/async_tx/async_raid6_recov',
    'crypto/async_tx/async_tx',
    'crypto/async_tx/async_xor',
    'crypto/authenc',
    'crypto/authencesn',
    'crypto/blake2b_generic',
    'crypto/blowfish_common',
    'crypto/blowfish_generic',
    'crypto/camellia_generic',
    'crypto/cast5_generic',
    'crypto/cast6_generic',
    'crypto/cast_common',
    'crypto/ccm',
    'crypto/chacha20poly1305',
    'crypto/chacha_generic',
    'crypto/cmac',
    'crypto/crc32_generic',
    'crypto/cryptd',
    'crypto/crypto_engine',
    'crypto/crypto_user',
    'crypto/curve25519-generic',
    'crypto/des_generic',
    'crypto/ecc',
    'crypto/ecdh_generic',
    'crypto/ecdsa_generic',
    'crypto/echainiv',
    'crypto/ecrdsa_generic',
    'crypto/essiv',
    'crypto/fcrypt',
    'crypto/hctr2',
    'crypto/keywrap',
    'crypto/lrw',
    'crypto/lz4',
    'crypto/lz4hc',
    'crypto/md4',
    'crypto/michael_mic',
    'crypto/nhpoly1305',
    'crypto/pcbc',
    'crypto/pcrypt',
    'crypto/poly1305_generic',
    'crypto/polyval-generic',
    'crypto/rmd160',
    'crypto/serpent_generic',
    'crypto/sm2_generic',
    'crypto/sm3',
    'crypto/sm3_generic',
    'crypto/sm4',
    'crypto/sm4_generic',
    'crypto/streebog_generic',
    'crypto/tcrypt',
    'crypto/twofish_common',
    'crypto/twofish_generic',
    'crypto/vmac',
    'crypto/wp512',
    'crypto/xcbc',
    'crypto/xctr',
    'crypto/xor',
    'crypto/xxhash_generic',
    'crypto/zstd',
    'drivers/acpi/nfit/nfit',
    'drivers/ata/acard-ahci',
    'drivers/ata/ahci',
    'drivers/ata/ahci_platform',
    'drivers/ata/ahci_tegra',
    'drivers/ata/ata_generic',
    'drivers/bcma/bcma',
    'drivers/block/virtio_blk',
    'drivers/bus/mhi/host/mhi',
    'drivers/bus/tegra-aconnect',
    'drivers/char/hw_random/virtio-rng',
    'drivers/clk/clk-max77686',
    'drivers/gpio/gpio-max77620',
    'drivers/gpu/drm/virtio/virtio-gpu',
    'drivers/hid/hid',
    'drivers/hid/hid-generic',
    'drivers/hid/hid-hyperv',
    'drivers/hid/usbhid/usbhid',
    'drivers/hv/hv_utils',
    'drivers/hv/hv_vmbus',
    'drivers/i2c/algos/i2c-algo-bit',
    'drivers/i2c/busses/i2c-tegra',
    'drivers/i2c/busses/i2c-tegra-bpmp',
    'drivers/input/keyboard/gpio_keys',
    'drivers/input/mouse/psmouse',
    'drivers/input/serio/hyperv-keyboard',
    'drivers/md/bcache/bcache',
    'drivers/md/dm-bio-prison',
    'drivers/md/dm-bufio',
    'drivers/md/dm-cache',
    'drivers/md/dm-cache-smq',
    'drivers/md/dm-crypt',
    'drivers/md/dm-log',
    'drivers/md/dm-mirror',
    'drivers/md/dm-raid',
    'drivers/md/dm-region-hash',
    'drivers/md/dm-snapshot',
    'drivers/md/dm-thin-pool',
    'drivers/md/persistent-data/dm-persistent-data',
    'drivers/md/raid0',
    'drivers/md/raid1',
    'drivers/md/raid10',
    'drivers/md/raid456',
    'drivers/message/fusion/mptbase',
    'drivers/message/fusion/mptsas',
    'drivers/message/fusion/mptscsih',
    'drivers/message/fusion/mptspi',
    'drivers/mfd/sm501',
    'drivers/mmc/host/cqhci',
    'drivers/mmc/host/sdhci',
    'drivers/mmc/host/sdhci-pltfm',
    'drivers/mmc/host/sdhci-tegra',
    'drivers/nvme/common/nvme-auth',
    'drivers/nvme/common/nvme-keyring',
    'drivers/nvme/host/nvme',
    'drivers/nvme/host/nvme-core',
    'drivers/pci/controller/dwc/pcie-tegra194',
    'drivers/pci/controller/pci-hyperv-intf',
    'drivers/phy/tegra/phy-tegra-xusb',
    'drivers/phy/tegra/phy-tegra194-p2u',
    'drivers/pinctrl/pinctrl-max77620',
    'drivers/regulator/fixed',
    'drivers/regulator/max77620-regulator',
    'drivers/rtc/rtc-max77686',
    'drivers/rtc/rtc-tegra',
    'drivers/scsi/BusLogic',
    'drivers/scsi/aacraid/aacraid',
    'drivers/scsi/device_handler/scsi_dh_alua',
    'drivers/scsi/device_handler/scsi_dh_emc',
    'drivers/scsi/device_handler/scsi_dh_rdac',
    'drivers/scsi/hv_storvsc',
    'drivers/scsi/ipr',
    'drivers/scsi/megaraid/megaraid_mbox',
    'drivers/scsi/megaraid/megaraid_mm',
    'drivers/scsi/megaraid/megaraid_sas',
    'drivers/scsi/mpt3sas/mpt3sas',
    'drivers/scsi/qla1280',
    'drivers/scsi/raid_class',
    'drivers/scsi/scsi_transport_sas',
    'drivers/spi/spi-tegra114',
    'drivers/ssb/ssb',
    'drivers/tty/serial/jsm/jsm',
    'drivers/tty/serial/serial-tegra',
    'drivers/usb/gadget/udc/rzv2m_usb3drd',
    'drivers/usb/host/bcma-hcd',
    'drivers/usb/host/ehci-fsl',
    'drivers/usb/host/ehci-npcm7xx',
    'drivers/usb/host/ehci-platform',
    'drivers/usb/host/fsl-mph-dr-of',
    'drivers/usb/host/isp116x-hcd',
    'drivers/usb/host/max3421-hcd',
    'drivers/usb/host/ohci-platform',
    'drivers/usb/host/oxu210hp-hcd',
    'drivers/usb/host/r8a66597-hcd',
    'drivers/usb/host/ssb-hcd',
    'drivers/usb/host/xen-hcd',
    'drivers/usb/host/xhci-histb',
    'drivers/usb/host/xhci-mtk-hcd',
    'drivers/usb/host/xhci-pci',
    'drivers/usb/host/xhci-pci-renesas',
    'drivers/usb/host/xhci-plat-hcd',
    'drivers/usb/host/xhci-rcar-hcd',
    'drivers/usb/host/xhci-tegra',
    'drivers/usb/storage/uas',
    'drivers/usb/storage/usb-storage',
    'drivers/virtio/virtio_dma_buf',
    'fs/btrfs/btrfs',
    'fs/isofs/isofs',
    'fs/nls/nls_iso8859-1',
    'fs/overlayfs/overlay',
    'fs/udf/udf',
    'fs/xfs/xfs',
    'lib/842/842_compress',
    'lib/842/842_decompress',
    'lib/crc-itu-t',
    'lib/crypto/libchacha',
    'lib/crypto/libcurve25519-generic',
    'lib/crypto/libdes',
    'lib/crypto/libpoly1305',
    'lib/libcrc32c',
    'lib/lz4/lz4_compress',
    'lib/lz4/lz4hc_compress',
    'lib/objagg',
    'lib/parman',
    'lib/raid6/raid6_pq',
))


def classic_remote_module(name):
    if '/kernel/' not in name:
        return False
    relative = name.split('/kernel/', 1)[1]
    return any(relative == tree or relative.startswith(tree + '/') for tree in
        CLASSIC_REMOTE_MODULE_TREES) or any(re.fullmatch(re.escape(leaf) +
            r'\.ko(?:\.(?:xz|gz|zst))?', relative) for leaf in CLASSIC_REMOTE_MODULE_LEAVES)


def classic_local_module(name):
    if '/kernel/' not in name:
        return False
    relative = name.split('/kernel/', 1)[1]
    match = re.fullmatch(r'([A-Za-z0-9_/+.-]+)\.ko(?:\.(?:xz|gz|zst))?', relative)
    return match is not None and match[1] in CLASSIC_LOCAL_MODULE_ROLES and not classic_remote_module(name)


def classic_build_hook(nonce, init_raw, functions_raw, *, gnu_tools=None):
    """One mkinitramfs hook for both persistent and isolated production.

    The caller must verify the vendor builder and assess the final archive;
    this hook alone never confers admission. Every new leaf is no-clobber.
    """
    files = classic_build_payloads(nonce, init_raw, functions_raw)
    tools = CLASSIC_GNU_TOOLS if gnu_tools is None else gnu_tools
    need(any(tools == factory for factory in CLASSIC_GNU_TOOL_PROFILES.values()),
         'unreviewed classic GNU tool mapping')
    lines = ['#!/bin/sh', 'set -eu', 'umask 022',
        'PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH',
        'case "${1:-}" in prereqs) exit 0;; esac',
        '[ "$(id -u)" = 0 ]',
        'case "${DESTDIR:-}" in /*) ;; *) exit 1;; esac',
        '[ -d "$DESTDIR" ] && [ ! -L "$DESTDIR" ]',
        'check_file() {',
        '    [ -f "$1" ] && [ ! -L "$1" ] || return 1',
        '    [ "$(sha256sum -- "$1" | cut -d " " -f 1)" = "$2" ]',
        '}',
        'check_file /usr/share/initramfs-tools/hook-functions ' + CLASSIC_HOOK_FUNCTIONS_SHA,
        'check_file "$DESTDIR/init" ' + CLASSIC_BOOT_SOURCE_PINS['init'],
        'check_file "$DESTDIR/scripts/functions" ' + CLASSIC_BOOT_SOURCE_PINS['scripts/functions'],
        '. /usr/share/initramfs-tools/hook-functions']
    # Check every source before copy_exec can copy any of it. The private
    # aliases remain byte-for-byte equal to the signed GNU factory payloads.
    for source, (_, sha) in tools.items():
        lines.append('check_file ' + source + ' ' + sha)
    for source, (target, sha) in tools.items():
        lines += ['[ ! -e "$DESTDIR' + target + '" ] && [ ! -L "$DESTDIR' + target + '" ]',
                  'copy_exec ' + source + ' ' + target,
                  'check_file "$DESTDIR' + target + '" ' + sha]
    lines += ['copy_exec /usr/bin/bash /usr/bin/bash',
        'for dir in etc usr usr/lib usr/lib/aegis; do',
        '    [ ! -L "$DESTDIR/$dir" ]',
        '    if [ ! -d "$DESTDIR/$dir" ]; then mkdir -m 0755 "$DESTDIR/$dir"; fi',
        'done']
    for index, (name, (raw, mode)) in enumerate(files.items()):
        delimiter = 'AEGIS_CLASSIC_PAYLOAD_' + str(index)
        text = raw.decode('utf-8')
        need(text.endswith('\n') and delimiter not in text, 'unsafe classic payload delimiter')
        if name == 'init':
            lines.append('check_file "$DESTDIR/init" ' + CLASSIC_BOOT_SOURCE_PINS['init'])
        else:
            if name in ('etc/passwd', 'etc/group', 'etc/nsswitch.conf'):
                lines += ['[ ! -L "$DESTDIR/' + name + '" ]',
                    'if [ -e "$DESTDIR/' + name + '" ]; then',
                    '    [ -f "$DESTDIR/' + name + '" ]',
                    '    rm -f -- "$DESTDIR/' + name + '"', 'fi']
            lines += ['[ ! -e "$DESTDIR/' + name + '" ] && [ ! -L "$DESTDIR/' + name + '" ]',
                      '(','set -C']
        lines += ['cat > "$DESTDIR/' + name + '" <<\'' + delimiter + "'", text.rstrip('\n'), delimiter]
        if name != 'init':
            lines.append(')')
        lines += ['chmod ' + format(mode, '04o') + ' "$DESTDIR/' + name + '"',
                  'check_file "$DESTDIR/' + name + '" ' + hashlib.sha256(raw).hexdigest()]
    # Subtraction is not admission: the whole-image verifier must still reject
    # unknown network/configuration roles and prove all non-network modules.
    for name in CLASSIC_REMOVE_FILES:
        lines.append('rm -f -- "$DESTDIR/' + name + '"')
    for name in CLASSIC_REMOVE_TREES:
        lines.append('rm -rf -- "$DESTDIR/' + name + '"')
    lines += ['case "${version:-}" in ""|*[!A-Za-z0-9_.+-]*) exit 1;; esac',
        '[ -d "$DESTDIR/usr/lib/modules/$version" ]',
        '[ ! -L "$DESTDIR/usr/lib/modules/$version" ]',
        '[ ! -L "$DESTDIR/usr/lib/modules/$version/kernel" ]']
    for tree in CLASSIC_REMOTE_MODULE_TREES:
        lines.append('rm -rf -- "$DESTDIR/usr/lib/modules/$version/kernel/' + tree + '"')
    for leaf in CLASSIC_REMOTE_MODULE_LEAVES:
        for suffix in ('.ko', '.ko.xz', '.ko.gz', '.ko.zst'):
            lines.append('rm -f -- "$DESTDIR/usr/lib/modules/$version/kernel/' + leaf + suffix + '"')
    return ('\n'.join(lines) + '\n').encode()


def cloud_init_recheck_script(*, root_mount='/sysroot'):
    need(root_mount in ('/sysroot', '/root'), 'unsupported trusted initrd root mount')
    """Frozen initrd Bash; no interpreter or code is read from /sysroot."""
    data = []
    for name, paths in (('UNIT_DIRS', CLOUD_UNIT_DIRS), ('GEN_DIRS', CLOUD_GENERATOR_DIRS),
                        ('INDICATORS', CLOUD_INDICATORS)):
        data.append(name + '=(' + ' '.join(shlex.quote(path) for path in paths) + ')')
    choices = []
    for pins in (CLOUD_DISABLED_NOBLE_PINS, CLOUD_DISABLED_PINS):
        count = sum('/system/' in path for path in pins)
        values = ' '.join(shlex.quote(path + '|' + value) for path, value in sorted(pins.items()))
        choices.append(str(count) + ') PINS=(' + values + ');;')
    select = 'case "${#UNITS[@]}" in\n' + '\n'.join(choices) + '\n*) refuse;;\nesac'
    template = r'''#!/usr/bin/bash -p
# Trusted initrd code only. Never execute or source a file from /sysroot.
set -Eeuo pipefail
PATH=/usr/bin:/bin
LC_ALL=C
export PATH LC_ALL
unset BASH_ENV ENV CDPATH GLOBIGNORE
CODE=cloud_init_disabled_profile_unproved
refuse() {
    trap - ERR
    local action=restore_reviewed_cloud_init_marker_profile
    if [[ $CODE == cloud_init_early_network_unverified ]]; then action=use_reviewed_local_boot_image_or_cloud_init_marker; fi
    # This is a source coordinate, never data read from the mounted root.
    local source_line=${BASH_LINENO[0]:-0}
    [[ $source_line =~ ^[0-9]{1,6}$ ]] || source_line=0
    printf '{"schema":"aegis_initrd_cloud_gate_v1","status":"refused","code":"%s","action":"%s","source_line":%s}\n' "$CODE" "$action" "$source_line" >&2
    exit 78
}
trap refuse ERR
@DATA@
DIRFMT='%d|%i|%u|%a|%f'
FILEFMT='%f|%u|%a|%h|%s|%d|%i|%Y|%Z|%y|%z'
safe_dir() {
    local logical=$1 rest=${1#/} current=$BASE part meta dev ino uid perm kind
    CHAIN=
    while [[ -n $rest ]]; do
        part=${rest%%/*}
        if [[ $rest == */* ]]; then rest=${rest#*/}; else rest=; fi
        current+=/$part
        if [[ ! -e $current && ! -L $current ]]; then CHAIN+="|missing:$part"; return 1; fi
        [[ ! -L $current && -d $current ]] || refuse
        meta=$(/usr/bin/gnustat -c "$DIRFMT" -- "$current") || refuse
        IFS='|' read -r dev ino uid perm kind <<< "$meta"
        [[ $uid == 0 && $perm =~ ^[0-7]{3,4}$ ]] || refuse
        (( (8#$perm & 0022) == 0 )) || refuse
        CHAIN+="|$part:$meta"
    done
}
merge_aliases() {
    LIB_MERGED=0 BIN_MERGED=0
    local pair name target got owner
    for pair in lib:usr/lib bin:usr/bin; do
        name=${pair%%:*}; target=${pair#*:}
        if [[ -L $BASE/$name ]]; then
            got=$(/usr/bin/gnureadlink -- "$BASE/$name") || refuse
            owner=$(/usr/bin/gnustat -c '%u' -- "$BASE/$name") || refuse
            [[ $owner == 0 && ( $got == "$target" || $got == "/$target" ) ]] || refuse
            if [[ $name == lib ]]; then LIB_MERGED=1; else BIN_MERGED=1; fi
        fi
    done
}
inventory() {
    UNITS=() GENERATORS=() DEPENDENCIES=() OVERRIDES=() DIR_SIGNATURE= CLOUD_PRESENT=0
    local role dir original entry leaf key seen='|'
    merge_aliases
    shopt -s nullglob
    for role in units generators; do
        local -a directories
        if [[ $role == units ]]; then directories=("${UNIT_DIRS[@]}"); else directories=("${GEN_DIRS[@]}"); fi
        for original in "${directories[@]}"; do
            dir=$original
            if (( LIB_MERGED )) && [[ $dir == /lib/* ]]; then dir=/usr$dir; fi
            if ! safe_dir "$dir"; then DIR_SIGNATURE+="|$dir:missing:$CHAIN"; continue; fi
            key=$(/usr/bin/gnustat -Lc '%d:%i' -- "$BASE$dir") || refuse
            if [[ $seen == *"|$key|"* ]]; then continue; fi
            seen+="$key|"
            DIR_SIGNATURE+="|$dir:$CHAIN"
            local count=0
            for entry in "$BASE$dir"/cloud-init* "$BASE$dir"/cloud-config* "$BASE$dir"/cloud-final*; do
                ((count+=1)); (( count <= 4096 )) || refuse
                leaf=${entry##*/}
                [[ $leaf =~ ^[A-Za-z0-9_.@+-]{1,128}$ ]] || refuse
                if [[ $role == units && ( $leaf == *.wants || $leaf == *.requires || $leaf == *.upholds ) ]]; then
                    safe_dir "$dir/$leaf" || refuse
                    DIR_SIGNATURE+="|$dir/$leaf:$CHAIN"
                    local child child_leaf target dependency_count=0
                    for child in "$entry"/* "$entry"/.[!.]* "$entry"/..?*; do
                        ((dependency_count+=1)); (( dependency_count <= 4096 )) || refuse
                        child_leaf=${child##*/}
                        [[ $child_leaf =~ ^[A-Za-z0-9_.@+-]{1,128}$ && -L $child ]] || refuse
                        target=$(/usr/bin/gnureadlink -- "$child") || refuse
                        [[ $target =~ ^[A-Za-z0-9_./@+-]{1,512}$ ]] || refuse
                        [[ $(/usr/bin/gnustat -c '%u' -- "$child") == 0 ]] || refuse
                        CLOUD_PRESENT=1
                        DEPENDENCIES+=("$dir/$leaf/$child_leaf|$target")
                    done
                    continue
                fi
                CLOUD_PRESENT=1
                if [[ $role == units ]]; then UNITS+=("$dir/$leaf"); else GENERATORS+=("$dir/$leaf"); fi
            done
        done
    done
    # Type-wide and dash-prefix drop-ins can reset the stock marker condition.
    for original in "${UNIT_DIRS[@]}"; do
        dir=$original
        if (( LIB_MERGED )) && [[ $dir == /lib/* ]]; then dir=/usr$dir; fi
        for leaf in service.d socket.d target.d cloud-.service.d cloud-.socket.d cloud-.target.d; do
            if safe_dir "$dir/$leaf"; then
                DIR_SIGNATURE+="|$dir/$leaf:$CHAIN"
                for entry in "$BASE$dir/$leaf"/*.conf; do
                    [[ ${entry##*/} =~ ^[A-Za-z0-9_.@+-]{1,128}$ ]] || refuse
                    OVERRIDES+=("$dir/$leaf/${entry##*/}")
                done
            fi
        done
    done
    for original in "${INDICATORS[@]}"; do
        dir=$original
        if (( LIB_MERGED )) && [[ $dir == /lib/* ]]; then dir=/usr$dir; fi
        if (( BIN_MERGED )) && [[ $dir == /bin/* ]]; then dir=/usr$dir; fi
        if safe_dir "${dir%/*}"; then
            if [[ -e $BASE$dir || -L $BASE$dir ]]; then CLOUD_PRESENT=1; fi
        fi
    done
}
file_generation() {
    local logical=$1 expected=$2 maximum=$3 parent_before before opened after mode uid perm links size dev ino mt ct tail hashline hash
    safe_dir "${logical%/*}" || refuse
    parent_before=$CHAIN
    [[ ! -L $BASE$logical && -f $BASE$logical ]] || refuse
    before=$(/usr/bin/gnustat -c "$FILEFMT" -- "$BASE$logical") || refuse
    IFS='|' read -r mode uid perm links size dev ino mt ct tail <<< "$before"
    [[ $uid == 0 && $links == 1 && $perm =~ ^[0-7]{3,4}$ && $size =~ ^[0-9]{1,12}$ ]] || refuse
    (( (8#$perm & 0022) == 0 && size <= maximum )) || refuse
    exec 8<"$BASE$logical" || refuse
    opened=$(/usr/bin/gnustat -Lc "$FILEFMT" -- /proc/self/fd/8) || refuse
    [[ $opened == "$before" && -f /proc/self/fd/8 ]] || refuse
    if [[ $logical == /usr/lib/systemd/system/* && $logical != */cloud-config.target ]]; then
        local condition=0 line
        while IFS= read -r line; do
            if [[ $line == 'ConditionPathExists=!/etc/cloud/cloud-init.disabled' ]]; then condition=1; fi
        done < /proc/self/fd/8
        (( condition == 1 )) || refuse
    fi
    hashline=$(/usr/bin/gnusha256sum -- /proc/self/fd/8) || refuse
    hash=${hashline%% *}
    [[ $hash =~ ^[0-9a-f]{64}$ && ( $expected == '*' || $hash == "$expected" ) ]] || refuse
    opened=$(/usr/bin/gnustat -Lc "$FILEFMT" -- /proc/self/fd/8) || refuse
    exec 8<&-
    after=$(/usr/bin/gnustat -c "$FILEFMT" -- "$BASE$logical") || refuse
    [[ $opened == "$before" && $after == "$before" && ! -L $BASE$logical ]] || refuse
    safe_dir "${logical%/*}" || refuse
    [[ $CHAIN == "$parent_before" ]] || refuse
    GOT="$before|$hash"
    GOT_DEVICE=$dev GOT_CTIME=$ct
}
verify_root_mount() {
    local ROOT_FS= ROOT_MOUNTS=0 line mid parent dev mount_root point rest
    while IFS= read -r line; do
        read -r mid parent dev mount_root point rest <<< "$line"
        case "$point" in /sysroot/etc|/sysroot/etc/cloud|/sysroot/etc/cloud/cloud-init.disabled) refuse;; esac
        if [[ $point == /sysroot/* ]]; then
            rest=${line#* - }; rest=${rest%% *}
            case "$rest" in ext2|ext3|ext4|xfs|btrfs|f2fs|tmpfs|ramfs|devtmpfs|proc|sysfs|cgroup2|devpts|vfat) ;; *) refuse;; esac
        fi
        if [[ $point == /sysroot ]]; then
            ((ROOT_MOUNTS+=1)); rest=${line#* - }; ROOT_FS=${rest%% *}
        fi
    done < /proc/self/mountinfo
    (( ROOT_MOUNTS == 1 )) || refuse
    case "$ROOT_FS" in ext2|ext3|ext4|xfs|btrfs|f2fs) ;; *) refuse;; esac
}
verify_root_mount
[[ -d /sysroot && ! -L /sysroot ]] || refuse
ROOT_BEFORE=$(/usr/bin/gnustat -c "$DIRFMT" -- /sysroot) || refuse
IFS='|' read -r ROOT_DEVICE root_ino root_uid root_mode root_kind <<< "$ROOT_BEFORE"
[[ $root_uid == 0 && $root_mode =~ ^[0-7]{3,4}$ ]] || refuse
(( (8#$root_mode & 0022) == 0 )) || refuse
exec 9</sysroot
exec 7</
[[ $(/usr/bin/gnustat -Lc "$DIRFMT" -- /proc/self/fd/9) == "$ROOT_BEFORE" ]] || refuse
# The root manager has not started yet. Cloud units in the initrd itself refuse.
BASE=/proc/self/fd/7
inventory
(( CLOUD_PRESENT == 0 )) || refuse
if safe_dir /run/cloud-init; then
    for path in /run/cloud-init/status.json /run/cloud-init/instance-data.json; do
        [[ ! -e $BASE$path && ! -L $BASE$path ]] || refuse
    done
fi
BASE=/proc/self/fd/9
inventory
UNITS_BEFORE=("${UNITS[@]}") GENERATORS_BEFORE=("${GENERATORS[@]}")
DEPENDENCIES_BEFORE=("${DEPENDENCIES[@]}") OVERRIDES_BEFORE=("${OVERRIDES[@]}")
DIRECTORIES_BEFORE=$DIR_SIGNATURE
PRESENT_BEFORE=$CLOUD_PRESENT
MARKER_PRESENT=0
if safe_dir /etc/cloud; then
    if [[ -e $BASE/etc/cloud/cloud-init.disabled || -L $BASE/etc/cloud/cloud-init.disabled ]]; then MARKER_PRESENT=1; fi
fi
if (( MARKER_PRESENT )); then
    CODE=cloud_init_disabled_profile_unproved
    # The marker must live on the root filesystem and predate this boot.
    for dir in /etc /etc/cloud; do
        safe_dir "$dir" || refuse
        [[ $(/usr/bin/gnustat -Lc '%d' -- "$BASE$dir") == "$ROOT_DEVICE" ]] || refuse
    done
    BTIME=
    while read -r key value rest; do if [[ $key == btime && $value =~ ^[0-9]{1,12}$ ]]; then BTIME=$value; break; fi; done < /proc/stat
    [[ -n $BTIME ]] || refuse
    file_generation /etc/cloud/cloud-init.disabled '*' 4096
    MARKER_GENERATION=$GOT
    [[ $GOT_DEVICE == "$ROOT_DEVICE" && $GOT_CTIME =~ ^[0-9]{1,12}$ ]] || refuse
    (( GOT_CTIME < BTIME )) || refuse
    (( ${#GENERATORS[@]} == 1 )) || refuse
    [[ ${GENERATORS[0]} == /usr/lib/systemd/system-generators/cloud-init-generator ]] || refuse
    @SELECT_PROFILE@
    (( ${#OVERRIDES[@]} == 0 )) || refuse
    for dependency in "${DEPENDENCIES[@]}"; do
        path=${dependency%%|*}; target=${dependency#*|}; leaf=${path##*/}; found=0
        for pair in "${PINS[@]}"; do if [[ ${pair%%|*} == "/usr/lib/systemd/system/$leaf" ]]; then found=1; fi; done
        (( found == 1 )) || refuse
        case "$target" in
            "/usr/lib/systemd/system/$leaf") ;;
            "/lib/systemd/system/$leaf")
                if (( ! LIB_MERGED )); then
                    safe_dir /lib/systemd/system || refuse
                    [[ $(/usr/bin/gnustat -Lc '%d:%i' -- "$BASE/lib/systemd/system") == \
                       $(/usr/bin/gnustat -Lc '%d:%i' -- "$BASE/usr/lib/systemd/system") ]] || refuse
                fi;;
            "../$leaf") [[ $path == /usr/lib/systemd/system/* ]] || refuse;;
            *) refuse;;
        esac
    done
    for actual in "${UNITS[@]}"; do
        found=0
        for pair in "${PINS[@]}"; do if [[ ${pair%%|*} == "$actual" ]]; then found=1; fi; done
        (( found == 1 )) || refuse
    done
    declare -A FILE_GENERATIONS=()
    for pair in "${PINS[@]}"; do
        path=${pair%%|*}; pin=${pair#*|}
        file_generation "$path" "$pin" 262144
        FILE_GENERATIONS["$path"]=$GOT
    done
else
    CODE=cloud_init_early_network_unverified
    (( CLOUD_PRESENT == 0 )) || refuse
fi
# Recheck namespace, every opened file generation and the marker before return.
inventory
[[ ${UNITS[*]} == "${UNITS_BEFORE[*]}" && ${GENERATORS[*]} == "${GENERATORS_BEFORE[*]}" &&
   ${DEPENDENCIES[*]} == "${DEPENDENCIES_BEFORE[*]}" && ${OVERRIDES[*]} == "${OVERRIDES_BEFORE[*]}" &&
   $DIR_SIGNATURE == "$DIRECTORIES_BEFORE" && $CLOUD_PRESENT == "$PRESENT_BEFORE" ]] || refuse
if (( MARKER_PRESENT )); then
    file_generation /etc/cloud/cloud-init.disabled '*' 4096
    [[ $GOT == "$MARKER_GENERATION" ]] || refuse
    for pair in "${PINS[@]}"; do
        path=${pair%%|*}; pin=${pair#*|}
        file_generation "$path" "$pin" 262144
        [[ $GOT == "${FILE_GENERATIONS[$path]}" ]] || refuse
    done
else
    if safe_dir /etc/cloud; then [[ ! -e $BASE/etc/cloud/cloud-init.disabled && ! -L $BASE/etc/cloud/cloud-init.disabled ]] || refuse; fi
fi
verify_root_mount
[[ $(/usr/bin/gnustat -c "$DIRFMT" -- /sysroot) == "$ROOT_BEFORE" &&
   $(/usr/bin/gnustat -Lc "$DIRFMT" -- /proc/self/fd/9) == "$ROOT_BEFORE" ]] || refuse
printf '%s\n' '{"schema":"aegis_initrd_cloud_gate_v1","status":"passed"}'
'''
    return template.replace('@DATA@', '\n'.join(data)).replace('@SELECT_PROFILE@', select).replace(
        '/sysroot', root_mount).encode()


# The gate is deliberately a real numeric dracut module (99 prefix). dracut
# only discovers [0-9][0-9]*; the design's placeholder 9x would not be loaded.
GATE_SETUP = r'''#!/bin/bash
check() { return 0; }
depends() { echo systemd-initrd; }
install() {
    local module
    for module in $modules_loaded $mods_to_load; do
        case " $aegis_omit_network " in *" $module "*)
            dfatal "AEGIS: selected network module $module"; exit 1;; esac
    done
    if [[ -z "$aegis_build_nonce" ]]; then
        local first second
        read -r first < /proc/sys/kernel/random/uuid
        read -r second < /proc/sys/kernel/random/uuid
        aegis_build_nonce="${first//-/}${second//-/}"
    fi
    [[ "$aegis_build_nonce" =~ ^[a-f0-9]{64}$ ]] || { dfatal 'AEGIS: build nonce missing'; exit 1; }
    printf '%s\n' "$aegis_build_nonce" > "$initdir/etc/aegis-initrd-id"
    inst_simple "$moddir/aegis-initrd-id.service" "$systemdsystemunitdir/aegis-initrd-id.service"
    $SYSTEMCTL -q --root "$initdir" add-wants initrd.target aegis-initrd-id.service
    # The normal kernel command line already supplies root=. Embedded command
    # lines are prohibited by this profile, including host-only root snippets.
    rm -rf -- "$initdir/etc/cmdline.d"
}
'''
LEGACY_GATE_SETUP = GATE_SETUP
GATE_SETUP = GATE_SETUP.replace('depends() { echo systemd-initrd; }',
                               'depends() { echo systemd-initrd initqueue; }')
GATE_SETUP = GATE_SETUP.removesuffix("}\n") + r'''
    # Build-time subtraction only; the verifier still refuses these roles.
    # Never copy host password material into an early-boot image.
    local account password uid gid gecos home login members
    : > "$initdir/etc/passwd.aegis"
    : > "$initdir/etc/shadow"
    while IFS=: read -r account password uid gid gecos home login; do
        [[ "$account" == root ]] || login=/usr/sbin/nologin
        printf '%s:x:%s:%s:%s:%s:%s\n' "$account" "$uid" "$gid" "$gecos" "$home" "$login" >> "$initdir/etc/passwd.aegis"
        printf '%s:!:1::::::\n' "$account" >> "$initdir/etc/shadow"
    done < "$initdir/etc/passwd"
    mv -f -- "$initdir/etc/passwd.aegis" "$initdir/etc/passwd"
    : > "$initdir/etc/group.aegis"
    : > "$initdir/etc/gshadow"
    while IFS=: read -r account password gid members; do
        printf '%s:x:%s:%s\n' "$account" "$gid" "$members" >> "$initdir/etc/group.aegis"
        printf '%s:!::\n' "$account" >> "$initdir/etc/gshadow"
    done < "$initdir/etc/group"
    mv -f -- "$initdir/etc/group.aegis" "$initdir/etc/group"
    chmod 0600 "$initdir/etc/passwd" "$initdir/etc/group" "$initdir/etc/shadow" "$initdir/etc/gshadow"
    printf '%s\n' 'passwd: files' 'group: files' 'shadow: files' 'gshadow: files' 'hosts: files' 'networks: files' 'protocols: files' 'services: files' 'ethers: files' 'rpc: files' > "$initdir/etc/nsswitch.conf"
    chmod 0644 "$initdir/etc/nsswitch.conf"
    printf '%s\n' 'SUBSYSTEM=="block", GROUP="disk"' 'SUBSYSTEM=="tty", KERNEL=="tty[0-9]*|hvc[0-9]*|console", MODE="0600"' > "$initdir/usr/lib/udev/rules.d/50-udev-default.rules"
    chmod 0644 "$initdir/usr/lib/udev/rules.d/50-udev-default.rules"
    mkdir -p "$initdir/run/lock"
    chmod 0755 "$initdir/run/lock"
    rm -f -- "$initdir/usr/lib/systemd/system-generators/systemd-debug-generator"
    rm -f -- "$initdir/usr/lib/systemd/system/breakpoint-pre-basic.service"
    rm -f -- "$initdir/usr/lib/systemd/system/breakpoint-pre-mount.service"
    rm -f -- "$initdir/usr/lib/systemd/system/breakpoint-pre-switch-root.service"
    rm -f -- "$initdir/usr/lib/systemd/system/breakpoint-pre-udev.service"
    rm -f -- "$initdir/usr/lib/systemd/system/debug-shell.service"
    rm -f -- "$initdir/usr/lib/systemd/system/network-online.target"
    rm -f -- "$initdir/usr/lib/systemd/system/network-pre.target"
    rm -f -- "$initdir/usr/lib/systemd/system/network.target"
    rm -f -- "$initdir/usr/lib/systemd/system/nss-lookup.target"
    rm -f -- "$initdir/usr/lib/systemd/system/nss-user-lookup.target"
    rm -f -- "$initdir/usr/lib/systemd/system/remote-fs-pre.target"
    rm -f -- "$initdir/usr/lib/systemd/system/remote-fs.target"
    rm -f -- "$initdir/usr/lib/systemd/system/rpcbind.target"
    rm -f -- "$initdir/usr/lib/systemd/system/sigpwr.target"
    rm -f -- "$initdir/usr/lib/systemd/system/systemd-journal-catalog-update.service"
    rm -f -- "$initdir/usr/lib/systemd/system/systemd-journald-varlink@.socket"
    rm -f -- "$initdir/usr/lib/systemd/system/systemd-journald@.service"
    rm -f -- "$initdir/usr/lib/systemd/system/systemd-journald@.socket"
    rm -f -- "$initdir/usr/lib/systemd/system/systemd-tmpfiles-clean.service"
    rm -f -- "$initdir/usr/lib/systemd/system/systemd-udevd.service.d/syscall-architecture.conf"
    rm -f -- "$initdir/usr/lib/systemd/system/systemd-validatefs@.service"
    rm -f -- "$initdir/usr/lib/udev/rules.d/60-autosuspend.rules"
    rm -f -- "$initdir/usr/lib/udev/rules.d/60-drm.rules"
    rm -f -- "$initdir/usr/lib/udev/rules.d/60-evdev.rules"
    rm -f -- "$initdir/usr/lib/udev/rules.d/60-fido-id.rules"
    rm -f -- "$initdir/usr/lib/udev/rules.d/60-input-id.rules"
    rm -f -- "$initdir/usr/lib/udev/rules.d/60-persistent-alsa.rules"
    rm -f -- "$initdir/usr/lib/udev/rules.d/60-sensor.rules"
    rm -f -- "$initdir/usr/lib/udev/rules.d/70-joystick.rules"
    rm -f -- "$initdir/usr/lib/udev/rules.d/70-memory.rules"
    rm -f -- "$initdir/usr/lib/udev/rules.d/70-mouse.rules"
    rm -f -- "$initdir/usr/lib/udev/rules.d/70-touchpad.rules"
    rm -f -- "$initdir/usr/lib/udev/rules.d/75-probe_mtd.rules"
    rm -f -- "$initdir/usr/lib/udev/rules.d/78-sound-card.rules"
    rm -f -- "$initdir/usr/lib/udev/rules.d/90-image-dissect.rules"
    rm -f -- "$initdir/etc/tmpfiles.d/screen-cleanup.conf"
    rm -f -- "$initdir/etc/passwd-"
    rm -f -- "$initdir/etc/group-"
    rm -f -- "$initdir/etc/shadow-"
    rm -f -- "$initdir/etc/gshadow-"
    rmdir -- "$initdir/usr/lib/systemd/system/systemd-udevd.service.d" 2>/dev/null || :
    rmdir -- "$initdir/etc/tmpfiles.d" 2>/dev/null || :
    rmdir -- "$initdir/usr/share/plymouth/themes/none" 2>/dev/null || :
    rmdir -- "$initdir/var/lib/dracut/hooks/pre-shutdown" 2>/dev/null || :
    rmdir -- "$initdir/var/lib/dracut/hooks/shutdown-emergency" 2>/dev/null || :
    if [[ -f "$initdir/usr/lib/dracut/hostonly-files" ]]; then
        sed -i '\|^/etc/tmpfiles.d/screen-cleanup.conf$|d' "$initdir/usr/lib/dracut/hostonly-files"
    fi
}
'''
PRE_CLOUD_GATE_SETUP = GATE_SETUP
GATE_UNIT = b'''[Unit]
Description=AEGIS boot image identity
DefaultDependencies=no
Before=initrd-switch-root.target initrd-switch-root.service
After=initrd-root-fs.target initrd-usr-fs.target initrd-fs.target initrd-cleanup.service
[Service]
Type=oneshot
TimeoutStartSec=30
SyslogIdentifier=aegis-initrd-policy
StandardOutput=journal+console
StandardError=journal+console
ExecStartPre=/usr/bin/bash -p /usr/lib/aegis/initrd-cloud-check.sh
ExecStart=/usr/bin/cp /etc/aegis-initrd-id /run/aegis-initrd-id
RemainAfterExit=yes
'''
PRE_CLOUD_GATE_UNIT = b'[Unit]\nDescription=AEGIS boot image identity\nDefaultDependencies=no\nBefore=initrd-switch-root.target\n[Service]\nType=oneshot\nExecStart=/usr/bin/cp /etc/aegis-initrd-id /run/aegis-initrd-id\nRemainAfterExit=yes\n'
SWITCH_ROOT_REQUIRES = b'[Unit]\nRequires=aegis-initrd-id.service\nAfter=aegis-initrd-id.service\n'
# Distinct literal comments prevent dracut's archive deduplicator from
# hardlinking the two security-bearing graph leaves. Both remain single-link.
SWITCH_ROOT_TARGET_REQUIRES = b'# AEGIS switch-root target barrier\n' + SWITCH_ROOT_REQUIRES
SWITCH_ROOT_SERVICE_REQUIRES = b'# AEGIS switch-root service barrier\n' + SWITCH_ROOT_REQUIRES
GATE_SETUP = GATE_SETUP.replace(
    '    $SYSTEMCTL -q --root "$initdir" add-wants initrd.target aegis-initrd-id.service\n', '')
GATE_SETUP = GATE_SETUP.removesuffix("}\n") + r'''    inst_multiple /usr/bin/bash /usr/bin/gnustat /usr/bin/gnusha256sum /usr/bin/gnureadlink
    inst_simple "$moddir/initrd-cloud-check.sh" "/usr/lib/aegis/initrd-cloud-check.sh"
    inst_simple "$moddir/switch-root-target.conf" "$systemdsystemunitdir/initrd-switch-root.target.d/10-aegis-cloud.conf"
    inst_simple "$moddir/switch-root-service.conf" "$systemdsystemunitdir/initrd-switch-root.service.d/10-aegis-cloud.conf"
    # dracut-install honors the enclosing private umask; set these inert
    # source-owned leaves explicitly, without relaxing strict image admission.
    chmod 0644 "$initdir/usr/lib/aegis/initrd-cloud-check.sh" \
        "$initdir$systemdsystemunitdir/aegis-initrd-id.service" \
        "$initdir$systemdsystemunitdir/initrd-switch-root.target.d/10-aegis-cloud.conf" \
        "$initdir$systemdsystemunitdir/initrd-switch-root.service.d/10-aegis-cloud.conf"
}
'''
HOOK_BYTES = b'''#!/bin/sh
# AEGIS kernel policy assessor; dracut's gate enforces build-time exclusion.
exec /usr/bin/python3 -I -B /usr/local/lib/aegis/helpers/lib/aegis_initrd_policy.py kernel-hook "$1"
'''


def policy_files(*, legacy=False, pre_cloud=False, profile=PROFILE):
    need(profile in (PROFILE, CLASSIC_PROFILE), 'unknown owned initrd profile')
    if profile == CLASSIC_PROFILE:
        need(not legacy and not pre_cloud, 'classic profile has no dracut predecessor')
        from aegis_initrd_classic import owned_policy_files
        return owned_policy_files()
    drop = ('# AEGIS explicit local-root initrd policy\nomit_dracutmodules+=" ' +
        ' '.join(sorted(OMIT)) + ' "\nadd_dracutmodules+=" aegis-initrd-gate "\n' +
        'hostonly_cmdline="no"\naegis_omit_network=" ' + ' '.join(sorted(OMIT)) + ' "\n').encode()
    if not legacy:
        drop += (b'umask 077\n'
            b'aegis_net_omit="$(/usr/bin/python3 -I -B '
            b'/usr/local/lib/aegis/helpers/lib/aegis_initrd_policy.py network-drivers)" || exit 1\n'
            b'omit_drivers+=" $aegis_net_omit "\nunset aegis_net_omit\n')
        drop += (b'DRACUT_LDCONFIG="/usr/bin/python3 -I -B '
            b'/usr/local/lib/aegis/helpers/lib/aegis_initrd_policy.py ldconfig-build"\n')
    files = {DROPIN: drop, GATE / 'module-setup.sh': (
                LEGACY_GATE_SETUP if legacy else PRE_CLOUD_GATE_SETUP if pre_cloud else GATE_SETUP).encode(),
             GATE / 'aegis-initrd-id.service': PRE_CLOUD_GATE_UNIT if legacy or pre_cloud else GATE_UNIT,
             HOOK: HOOK_BYTES, PREHOOK: HOOK_BYTES.replace(b'kernel-hook', b'kernel-preflight')}
    if not legacy and not pre_cloud:
        files[GATE / 'initrd-cloud-check.sh'] = cloud_init_recheck_script()
        files[GATE / 'switch-root-target.conf'] = SWITCH_ROOT_TARGET_REQUIRES
        files[GATE / 'switch-root-service.conf'] = SWITCH_ROOT_SERVICE_REQUIRES
    return files


def cloud_barrier_files():
    return {
        'usr/lib/systemd/system/aegis-initrd-id.service': GATE_UNIT,
        'usr/lib/aegis/initrd-cloud-check.sh': cloud_init_recheck_script(),
        'usr/lib/systemd/system/initrd-switch-root.target.d/10-aegis-cloud.conf': SWITCH_ROOT_TARGET_REQUIRES,
        'usr/lib/systemd/system/initrd-switch-root.service.d/10-aegis-cloud.conf': SWITCH_ROOT_SERVICE_REQUIRES}


def network_driver_names():
    """Exclusion only: all installed kernels, including a newly unpacked one.

    Do not depend on dracut's option/config evaluation order. The finite names
    come from the two kernel trees that strict image admission always denies.
    No file content or command is supplied by these names.
    """
    names = set()
    for version in Path('/usr/lib/modules').iterdir():
        need(KERNEL.fullmatch(version.name) and version.is_dir() and
             not version.is_symlink(), 'unreviewed kernel module directory')
        for relative in ('kernel/drivers/net', 'kernel/net'):
            root = version / relative
            if not root.exists():
                continue
            need(root.resolve().is_relative_to(version.resolve()), 'network driver directory escapes')
            for item in root.rglob('*'):
                if item.is_dir():
                    continue
                match = re.fullmatch(r'([A-Za-z0-9_-]+)\.ko(?:\.(?:xz|gz|zst))?', item.name)
                need(match is not None, 'unknown network driver filename')
                names.add(match[1].replace('-', '_'))
                need(len(names) <= 4096, 'network driver inventory bound')
    need(sum(len(n) + 1 for n in names) <= 65536, 'network driver argument bound')
    return sorted(names)


def prepare_ldconfig(root):
    """Remove five development aliases in dracut's private build tree only.

    Dracut resolves shared libraries lazily after module installation. Its
    native ldconfig callback is the first point after that resolution. Keep
    runtime SONAME admission exact instead of accepting cache alias remaps.
    """
    need(os.geteuid() == 0, 'root required')
    need(re.fullmatch(r'/(?:var/tmp|tmp)/dracut\.[A-Za-z0-9_-]{6,32}/initramfs', root),
         'nonprivate dracut cache root')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    with contextlib.ExitStack() as stack:
        parent = os.open(str(Path(root).parent), flags); stack.callback(os.close, parent)
        meta = os.fstat(parent)
        need(meta.st_uid == 0 and stat.S_IMODE(meta.st_mode) == 0o700,
             'untrusted dracut temporary parent')
        fd = parent
        for part in ('initramfs',):
            fd = os.open(part, flags, dir_fd=fd); stack.callback(os.close, fd)
            meta = os.fstat(fd)
            need(meta.st_uid == 0 and not meta.st_mode & 0o022,
                 'untrusted dracut library directory')
        remove_build_host_data(fd)
        for part in ('usr', 'lib', 'x86_64-linux-gnu'):
            fd = os.open(part, flags, dir_fd=fd); stack.callback(os.close, fd)
            meta = os.fstat(fd)
            need(meta.st_uid == 0 and not meta.st_mode & 0o022,
                 'untrusted dracut library directory')
        for name in ('libresolv.so','libnss_hesiod.so','libnss_compat.so',
                     'libcrypto.so','libcrypt.so'):
            try:
                meta = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            need(stat.S_ISREG(meta.st_mode) or stat.S_ISLNK(meta.st_mode),
                 'unexpected development alias type')
            os.unlink(name, dir_fd=fd)


def remove_build_host_data(root_fd):
    """Subtract host provisioning data only inside the fenced build tree.

    A local-root, networkless initrd needs neither host-specific name mappings
    nor the cloud image's generated IPv6 settings.
    The archive whitelist remains unchanged, including its hosts refusals.
    The real /etc/hosts and the original initrd are never modified here.
    """
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    def child(parent, name):
        fd = os.open(name, flags, dir_fd=parent)
        meta = os.fstat(fd)
        if not (meta.st_uid == 0 and not meta.st_mode & 0o022):
            os.close(fd)
            need(False, 'untrusted dracut hosts directory')
        return fd
    with contextlib.ExitStack() as stack:
        try:
            etc = child(root_fd, 'etc'); stack.callback(os.close, etc)
        except FileNotFoundError:
            return
        for components in (('hosts',), ('sysctl.d', '99-cloudimg-ipv6.conf')):
            parent = etc
            try:
                for name in components[:-1]:
                    parent = child(parent, name); stack.callback(os.close, parent)
                meta = os.stat(components[-1], dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                continue
            need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and
                 meta.st_nlink == 1 and not meta.st_mode & 0o133 and
                 meta.st_size <= MAX_MEMORY_ENTRY, 'untrusted generated host data')
            os.unlink(components[-1], dir_fd=parent)
            if len(components) == 2:
                try:
                    os.rmdir(components[0], dir_fd=etc)
                except OSError as error:
                    if error.errno != errno.ENOTEMPTY:
                        raise
        index_parent = root_fd
        try:
            for name in ('usr', 'lib', 'dracut'):
                index_parent = child(index_parent, name)
                stack.callback(os.close, index_parent)
            index = os.open('hostonly-files', os.O_RDWR | os.O_NOFOLLOW |
                            os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=index_parent)
        except FileNotFoundError:
            return
        stack.callback(os.close, index)
        meta = os.fstat(index)
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_nlink == 1 and
             not meta.st_mode & 0o133 and meta.st_size <= MAX_MEMORY_ENTRY,
             'untrusted dracut hostonly index')
        raw = os.read(index, MAX_MEMORY_ENTRY + 1)
        need(len(raw) == meta.st_size, 'dracut hostonly index changed')
        removed = (b'/etc/hosts', b'etc/hosts', b'/etc/sysctl.d/99-cloudimg-ipv6.conf',
                   b'etc/sysctl.d/99-cloudimg-ipv6.conf')
        filtered = b''.join(line for line in raw.splitlines(keepends=True)
                            if line.rstrip(b'\r\n') not in removed)
        os.lseek(index, 0, os.SEEK_SET)
        view = memoryview(filtered)
        while view:
            count = os.write(index, view)
            need(count > 0, 'dracut hostonly index short write')
            view = view[count:]
        os.ftruncate(index, len(filtered))
        os.fsync(index)


def ldconfig_build(args):
    need(os.geteuid() == 0, 'root required')
    if args not in (['-p'], ['-pN']):
        need(len(args) == 4 and args[0] == '-r' and args[2:] == ['-f','/etc/ld.so.conf'],
             'unreviewed dracut ldconfig invocation')
        prepare_ldconfig(args[1])
    # Preserve the native cache writer and its actual exit status. No archive
    # is patched, and the completed candidate must still pass every check.
    result = subprocess.run(['/usr/sbin/ldconfig', *args], timeout=30,
                            stdin=subprocess.DEVNULL)
    need(result.returncode == 0, 'native dracut ldconfig failed')


def atomic(path, raw, mode):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    for parent in (path.parent, *path.parent.parents):
        st = parent.lstat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,
             'untrusted policy destination')
    tmp = path.with_name('.aegis-tmp-' + os.urandom(16).hex())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(raw)
            # The caller requests an exact policy mode. A restrictive parent
            # umask must not turn a0755 builder hook into an unreviewed0700.
            os.fchmod(f.fileno(), mode)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        fsync_dir(path.parent)
    finally:
        tmp.unlink(missing_ok=True)


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save_manifest(value):
    atomic(MANIFEST, (json.dumps(value, sort_keys=True, indent=2) + '\n').encode(), 0o600)


def assessment_seconds(image):
    size = Path(image).stat().st_size
    need(0 <= size <= MAX_IMAGE, 'boot archive exceeds bound')
    # Fixed setup allowance plus one second per compressed MiB; the 256MiB
    # image cap also bounds this allowance to 301s. Nested calls cannot extend
    # an existing deadline, and expanded bytes remain capped independently.
    return 45 + (size + STREAM_CHUNK - 1) // STREAM_CHUNK


def bounded_assessment(function):
    def checked(*args,**kwargs):
        image = kwargs['image'] if 'image' in kwargs else args[1] if function.__name__ in ('verify_profile', 'verify_archive') else args[0]
        seconds = assessment_seconds(image)
        previous=signal.getitimer(signal.ITIMER_REAL)
        handler=signal.getsignal(signal.SIGALRM)
        start=time.monotonic()
        def expired(*_):raise TimeoutError('strict initrd assessment exceeded volume budget')
        signal.signal(signal.SIGALRM,expired)
        signal.setitimer(signal.ITIMER_REAL,min(seconds,previous[0]) if previous[0]>0 else seconds)
        try:
            return function(*args,**kwargs)
        finally:
            signal.setitimer(signal.ITIMER_REAL,0)
            signal.signal(signal.SIGALRM,handler)
            if previous[0]>0:
                signal.setitimer(signal.ITIMER_REAL,max(0.000001,previous[0]-(time.monotonic()-start)),previous[1])
    return checked


@bounded_assessment
def archive_entries(image, *, metadata_payloads=None, profile=PROFILE):
    """Bounded newc reader; retain <=2MiB, stream pinned bodies up to64MiB.

    metadata_payloads is for ORIGINAL module-loss comparison and ordinary
    uninstall readback only. Unselected bodies stream through <=1MiB chunks;
    this mode can never qualify a candidate or return executable payloads.
    """
    need(profile in (PROFILE, CLASSIC_PROFILE), 'unknown initrd archive profile')
    need(profile == PROFILE or metadata_payloads is None, 'classic metadata-only mode unavailable')
    large_public = LARGE_PUBLIC_FILES if profile == PROFILE else CLASSIC_LARGE_PUBLIC_FILES
    if metadata_payloads is not None:
        need(metadata_payloads==frozenset(('usr/lib/dracut/modules.txt',
             'etc/aegis-initrd-id')), 'invalid metadata-only selection')
    need(Path(image).stat().st_size <= MAX_IMAGE, 'boot archive exceeds bound')
    entries = {}
    total = 0
    def exact(f, n):
        nonlocal total
        need(0 <= n <= MAX_MEMORY_ENTRY, 'initrd read exceeds 2MiB memory bound')
        total += n
        need(total <= MAX_IMAGE, 'expanded initrd exceeds 256MiB bound')
        raw = f.read(n)
        need(len(raw) == n, 'truncated initrd')
        return raw
    def parse(f):
        for _ in range(100000):
            header = exact(f, 110)
            need(header[:6] in (b'070701', b'070702'), 'unsupported cpio')
            fields = [int(header[i:i + 8], 16) for i in range(6, 110, 8)]
            mode, size, namesize = fields[1], fields[6], fields[11]
            need(0 < namesize <= 4096, 'cpio path bound')
            raw = exact(f, namesize)
            need(raw.endswith(b'\0'), 'cpio path terminator')
            name = raw[:-1].decode('utf-8').removeprefix('./')
            need(0 <= size <= MAX_ENTRY, 'initrd entry exceeds 64MiB bound')
            exact(f, (-110 - namesize) % 4)
            if metadata_payloads is None and size > MAX_MEMORY_ENTRY:
                need(stat.S_ISREG(mode) and '/' + name in large_public,
                     'unreviewed large initrd entry ' + name)
                if profile == CLASSIC_PROFILE:
                    _, pin_sha, pin_size, pin_mode = large_public['/' + name]
                    need(size == pin_size and mode == stat.S_IFREG | pin_mode and fields[4] == 1,
                         'classic large initrd metadata mismatch ' + name)
                h = hashlib.sha256()
                remaining = size
                while remaining:
                    chunk = min(remaining, STREAM_CHUNK)
                    h.update(exact(f, chunk))
                    remaining -= chunk
                data = StreamedBody(size, h.hexdigest())
                if profile == CLASSIC_PROFILE:
                    need(data.sha256 == pin_sha, 'classic large initrd factory mismatch ' + name)
            elif metadata_payloads is None or name in metadata_payloads:
                data = exact(f, size)
            else:
                remaining=size
                while remaining:
                    chunk=min(remaining,1<<20)
                    exact(f,chunk)
                    remaining-=chunk
                data=b''
            exact(f, (-size) % 4)
            if name == 'TRAILER!!!':
                return
            need(name in ('.', '') or name == posixpath.normpath(name) and
                 not name.startswith('/') and '..' not in name.split('/'), 'unsafe cpio path')
            need(fields[2:4] == [0, 0] and
                 (not mode & 0o022 or stat.S_ISLNK(mode) or
                  stat.S_ISDIR(mode) and name in ('tmp', 'var/tmp') and mode & stat.S_ISVTX),
                 'untrusted cpio metadata')
            need(name not in entries or stat.S_ISDIR(mode) and stat.S_ISDIR(entries[name]['mode']),
                 'duplicate cpio path')
            entries[name] = {'mode': mode, 'data': data,
                'inode': (fields[7], fields[8], fields[0]), 'nlink': fields[4],
                'rdev': (fields[9], fields[10])}
        need(False, 'cpio inventory bound')
    with open(image, 'rb', buffering=0) as raw:
        while True:
            marker = raw.read(6)
            if not marker:
                break
            if marker[0] == 0:
                raw.seek(-5, 1)
                continue
            raw.seek(-len(marker), 1)
            if marker in (b'070701', b'070702'):
                parse(raw)
                continue
            decoders = ((b'\x28\xb5\x2f\xfd', ('zstd', '-q', '-d', '-c')),
                        (b'\x1f\x8b', ('gzip', '-d', '-c')),
                        (b'\xfd7zXZ\x00', ('xz', '-d', '-c')),
                        (b'\x04\x22\x4d\x18', ('lz4', '-d', '-c')))
            args = next((args for prefix, args in decoders if marker.startswith(prefix)), None)
            need(args is not None, 'unsupported initrd compression')
            p = subprocess.Popen(args, stdin=raw, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL)
            try:
                parse(p.stdout)
                tail_total=total
                while chunk:=p.stdout.read(65536):
                    tail_total+=len(chunk)
                    need(tail_total<=MAX_IMAGE and not chunk.strip(b'\0'),'unexpected or oversized initrd tail')
                need(p.wait(timeout=20) == 0, 'initrd decompression failed')
            finally:
                if p.poll() is None:
                    p.kill()
                    p.wait()
                p.stdout.close()
            break
    links = {}
    for e in entries.values():
        if stat.S_ISREG(e['mode']) and e['nlink'] > 1 and e['data']:
            need(e['inode'] not in links, 'competing hardlink data')
            links[e['inode']] = e['data']
    for e in entries.values():
        if stat.S_ISREG(e['mode']) and e['nlink'] > 1 and not e['data']:
            e['data'] = links.get(e['inode'], b'')
    return entries

# Package membership is a secondary provenance check, not a path wildcard.
# Activation paths (units, udev, generators, hooks) have separate finite lists.
PACKAGES = frozenset(('dracut-core', 'dracut', 'dracut-install', 'systemd',
    'systemd-sysv', 'systemd-cryptsetup', 'systemd-resolved', 'libsystemd-shared',
    'libsystemd0', 'udev', 'libudev1', 'kmod', 'libkmod2', 'dash', 'bash',
    'coreutils', 'libc-bin', 'base-files', 'util-linux', 'mount', 'e2fsprogs', 'libc6', 'libgcc-s1',
    'libstdc++6', 'libcap2', 'libacl1', 'libattr1', 'libblkid1', 'libmount1',
    'libuuid1', 'libsmartcols1', 'libtinfo6', 'libncursesw6', 'libselinux1',
    'libsepol2', 'libpcre2-8-0', 'libzstd1', 'liblz4-1', 'liblzma5', 'zlib1g',
    'libssl3t64', 'libgcrypt20', 'libgpg-error0', 'libcrypt1', 'libdevmapper1.02.1',
    'libjson-c5', 'libkeyutils1', 'libaudit1', 'libapparmor1', 'libpam0g',
    'libpam-modules', 'libpam-runtime', 'libcap-ng0', 'libseccomp2', 'libaio1t64',
    'libcryptsetup12', 'cryptsetup', 'cryptsetup-bin', 'dmsetup', 'lvm2', 'mdadm',
    'btrfs-progs', 'xfsprogs', 'plymouth', 'plymouth-label', 'console-setup-linux',
    'keyboard-configuration', 'console-setup', 'ncurses-base', 'ncurses-term',
    'init-system-helpers', 'initramfs-tools-core', 'cloud-initramfs-copymods',
    'overlayroot', 'gawk', 'libsigsegv2', 'intel-microcode', 'amd64-microcode'))
UNITS = frozenset(('basic.target', 'ctrl-alt-del.target', 'default.target',
    'emergency.service', 'emergency.target', 'rescue.service', 'rescue.target',
    'final.target', 'halt.target', 'kexec.target', 'reboot.target', 'poweroff.target',
    'exit.target', 'umount.target', 'local-fs-pre.target', 'local-fs.target', 'multi-user.target',
    'shutdown.target', 'swap.target', 'sysinit.target', 'sockets.target',
    'slices.target', 'paths.target', 'timers.target', 'getty.target',
    'cryptsetup.target', 'systemd-cryptsetup@.service', 'systemd-cryptsetup-pre.target',
    'systemd-ask-password-console.path', 'systemd-ask-password-console.service',
    'systemd-ask-password-plymouth.path', 'systemd-ask-password-plymouth.service',
    'systemd-battery-check.service', 'systemd-fsck@.service', 'systemd-fsck-root.service',
    'systemd-fsck-usr.service', 'systemd-hibernate-resume.service',
    'systemd-hibernate-resume@.service', 'systemd-journald.service',
    'systemd-journald.socket', 'systemd-journald-dev-log.socket',
    'systemd-journald-audit.socket', 'systemd-modules-load.service',
    'systemd-pcrphase-initrd.service', 'systemd-pcrextend.socket',
    'systemd-pcrextend.service', 'systemd-pcrphase.service',
    'systemd-pcrphase-sysinit.service', 'systemd-random-seed.service',
    'systemd-remount-fs.service', 'systemd-sysctl.service', 'systemd-sysusers.service',
    'systemd-tmpfiles-setup-dev-early.service', 'systemd-tmpfiles-setup-dev.service',
    'systemd-tmpfiles-setup.service', 'systemd-udevd.service',
    'systemd-udevd-control.socket', 'systemd-udevd-kernel.socket',
    'systemd-udev-trigger.service', 'systemd-udev-settle.service',
    'systemd-udev-load-credentials.service', 'systemd-vconsole-setup.service',
    'systemd-reboot.service', 'systemd-poweroff.service', 'systemd-halt.service',
    'systemd-kexec.service', 'systemd-exit.service', 'systemd-soft-reboot.service',
    'systemd-pstore.service', 'kmod-static-nodes.service', 'modprobe@.service',
    'sys-kernel-config.mount', 'syslog.socket', 'tmp.mount', 'system.slice',
    'systemd-volatile-root.service', 'plymouth-start.service', 'plymouth-quit.service',
    'plymouth-quit-wait.service', 'plymouth-switch-root.service',
    'plymouth-read-write.service', 'aegis-initrd-id.service',
    'initrd-cleanup.service', 'initrd-fs.target', 'initrd-parse-etc.service',
    'initrd-root-device.target', 'initrd-root-fs.target', 'initrd-switch-root.service',
    'initrd-switch-root.target', 'initrd.target', 'initrd-udevadm-cleanup-db.service',
    'initrd-usr-fs.target', 'initrd-usr-fs.target', 'initrd-switch-root.target')) | frozenset(
        'dracut-' + s + '.service' for s in ('cmdline', 'cmdline-ask', 'emergency',
        'initqueue', 'mount', 'pre-mount', 'pre-pivot', 'pre-trigger', 'pre-udev'))
GENERATORS = frozenset(('dracut-rootfs-generator', 'systemd-fstab-generator',
    'systemd-gpt-auto-generator', 'systemd-cryptsetup-generator',
    'systemd-hibernate-resume-generator'))
UDEV = frozenset(('10-console.rules', '10-dm.rules', '11-dm.rules', '11-dm-lvm.rules',
    '13-dm-disk.rules', '55-scsi-sg3_id.rules', '58-scsi-sg3_symlink.rules', '59-persistent-storage.rules', '60-block.rules',
    '60-cdrom_id.rules', '60-persistent-storage.rules', '60-persistent-storage-dm.rules',
    '60-persistent-storage-tape.rules', '60-persistent-input.rules', '60-persistent-v4l.rules',
    '60-serial.rules', '61-persistent-storage.rules', '63-md-raid-arrays.rules',
    '64-btrfs.rules', '69-dm-lvm.rules', '70-uaccess.rules', '71-seat.rules',
    '73-seat-late.rules', '75-net-description.rules', '80-drivers.rules',
    '90-console-setup.rules', '95-dm-notify.rules',
    '50-udev-default.rules', '99-systemd.rules'))
DRACUT_RELOCATE = {'etc/udev/rules.d/10-console.rules': '09console-setup/10-console.rules',
    'etc/udev/rules.d/59-persistent-storage.rules': '74rootfs-block/59-persistent-storage.rules',
    'etc/udev/rules.d/61-persistent-storage.rules': '74rootfs-block/61-persistent-storage.rules',
    'shutdown': '86shutdown/shutdown.sh',
    'usr/bin/dracut-cmdline': '77dracut-systemd/dracut-cmdline.sh',
    'usr/bin/dracut-cmdline-ask': '77dracut-systemd/dracut-cmdline-ask.sh',
    'usr/bin/dracut-emergency': '77dracut-systemd/dracut-emergency.sh',
    'usr/bin/dracut-initqueue': '77initqueue/dracut-initqueue.sh',
    'usr/bin/dracut-mount': '77dracut-systemd/dracut-mount.sh',
    'usr/bin/dracut-pre-mount': '77dracut-systemd/dracut-pre-mount.sh',
    'usr/bin/dracut-pre-pivot': '77dracut-systemd/dracut-pre-pivot.sh',
    'usr/bin/dracut-pre-trigger': '77dracut-systemd/dracut-pre-trigger.sh',
    'usr/bin/dracut-pre-udev': '77dracut-systemd/dracut-pre-udev.sh',
    'usr/lib/dracut-crypt-lib.sh': '70crypt/crypt-lib.sh',
    'usr/lib/dracut-dev-lib.sh': '80base/dracut-dev-lib.sh',
    'usr/lib/dracut-lib.sh': '80base/dracut-lib.sh',
    'usr/lib/fs-lib.sh': '70fs-lib/fs-lib.sh',
    'usr/lib/overlayfs-crypt-lib.sh': '71overlayfs-crypt/overlayfs-crypt-lib.sh',
    'usr/lib/overlayfs-lib.sh': '70overlayfs/overlayfs-lib.sh',
    'usr/lib/systemd/journald.conf.d/initrd.conf': '11systemd-journald/initrd.conf',
    'usr/lib/systemd/system-generators/dracut-rootfs-generator': '77dracut-systemd/rootfs-generator.sh',
    'usr/lib/systemd/system/dracut-cmdline-ask.service': '77dracut-systemd/dracut-cmdline-ask.service',
    'usr/lib/systemd/system/dracut-cmdline.service': '77dracut-systemd/dracut-cmdline.service',
    'usr/lib/systemd/system/dracut-emergency.service': '77dracut-systemd/dracut-emergency.service',
    'usr/lib/systemd/system/dracut-initqueue.service': '77initqueue/dracut-initqueue.service',
    'usr/lib/systemd/system/dracut-mount.service': '77dracut-systemd/dracut-mount.service',
    'usr/lib/systemd/system/dracut-pre-mount.service': '77dracut-systemd/dracut-pre-mount.service',
    'usr/lib/systemd/system/dracut-pre-pivot.service': '77dracut-systemd/dracut-pre-pivot.service',
    'usr/lib/systemd/system/dracut-pre-trigger.service': '77dracut-systemd/dracut-pre-trigger.service',
    'usr/lib/systemd/system/dracut-pre-udev.service': '77dracut-systemd/dracut-pre-udev.service',
    'usr/lib/systemd/system/emergency.service': '77dracut-systemd/emergency.service',
    'usr/lib/systemd/system/rescue.service': '77dracut-systemd/emergency.service',
    'usr/lib/tmpfiles.d/dracut-tmpfiles.conf': '77dracut-systemd/dracut-tmpfiles.conf',
    'usr/lib/udev/console-setup': '09console-setup/console-setup.sh',
    'usr/sbin/initqueue': '77initqueue/initqueue.sh',
    'usr/sbin/insmodpost.sh': '80base/insmodpost.sh',
    'usr/sbin/loginit': '80base/loginit.sh',
    'usr/sbin/rdsosreport': '80base/rdsosreport.sh',
    'var/lib/dracut/hooks/cmdline/00-parse-root.sh': '77dracut-systemd/parse-root.sh',
    'var/lib/dracut/hooks/cmdline/50-parse-copymods.sh': '50copymods/parse-copymods.sh',
    'var/lib/dracut/hooks/cmdline/50-parse-overlayroot.sh': '50overlayroot/parse-overlayroot.sh',
    'var/lib/dracut/hooks/cmdline/95-parse-virtfs.sh': '74virtfs/parse-virtfs.sh',
    'var/lib/dracut/hooks/cmdline/95-parse-virtiofs.sh': '74virtiofs/parse-virtiofs.sh',
    'var/lib/dracut/hooks/emergency/50-plymouth-emergency.sh': '45plymouth/plymouth-emergency.sh',
    'var/lib/dracut/hooks/mount/01-mount-overlayfs.sh': '70overlayfs/mount-overlayfs.sh',
    'var/lib/dracut/hooks/mount/99-mount-virtfs.sh': '74virtfs/mount-virtfs.sh',
    'var/lib/dracut/hooks/pre-mount/01-prepare-overlayfs.sh': '70overlayfs/prepare-overlayfs.sh',
    'var/lib/dracut/hooks/pre-mount/02-prepare-overlayfs-crypt.sh': '71overlayfs-crypt/prepare-overlayfs-crypt.sh',
    'var/lib/dracut/hooks/pre-mount/99-mount-virtiofs.sh': '74virtiofs/mount-virtiofs.sh',
    'var/lib/dracut/hooks/pre-pivot/00-prepare-overlayfs.sh': '70overlayfs/prepare-overlayfs.sh',
    'var/lib/dracut/hooks/pre-pivot/01-prepare-overlayfs-crypt.sh': '71overlayfs-crypt/prepare-overlayfs-crypt.sh',
    'var/lib/dracut/hooks/pre-pivot/10-mount-overlayfs.sh': '70overlayfs/mount-overlayfs.sh',
    'var/lib/dracut/hooks/pre-pivot/50-overlayroot-compat-symlink.sh': '50overlayroot/overlayroot-compat-symlink.sh',
    'var/lib/dracut/hooks/pre-pivot/90-modules-export.sh': '70kernel-modules-export/modules-export.sh'}


def elf_identity(data=None, *, read_at=None, size=None):
    if isinstance(data, StreamedBody):
        return data.identity
    if read_at is None:
        size = len(data)
        read_at = lambda offset, length: data[offset:offset + length]
    def read(offset, length):
        need(0 <= offset <= size and 0 <= length <= MAX_MEMORY_ENTRY and
             offset + length <= size, 'ELF read bound')
        raw = read_at(offset, length)
        need(len(raw) == length, 'truncated ELF read')
        return raw
    if size < 6 or read(0,6)!=b'\x7fELF\x02\x01': return None
    need(size>=64,'truncated ELF header')
    fields=struct.unpack('<HHIQQQIHHHHHH',read(16,48))
    typ,machine,version,entry,phoff,shoff,flags,ehsize,phsize,phnum,_,_,_=fields
    if typ!=3: return None
    need(version==1 and ehsize==64 and phsize==56 and 0<phnum<=128 and phoff+phsize*phnum<=size,'unsupported ELF program headers')
    loads=[];dynamic=None;os_abi=None
    for i in range(phnum):
        kind,_,off,addr,_,segment_size,_,alignment=struct.unpack('<IIQQQQQQ',read(phoff+i*phsize,phsize))
        need(off+segment_size<=size,'ELF segment outside file')
        if kind==1: loads.append((addr,off,segment_size))
        if kind==4:
            need(segment_size<=65536 and alignment in (4,8),'ELF note segment bound or alignment');pos=off
            while pos<off+segment_size:
                need(pos+12<=off+segment_size,'truncated ELF note header')
                note_start=pos;namesz,descsz,note_type=struct.unpack('<III',read(pos,12));pos+=12
                name_end=pos+namesz;descriptor=note_start+((12+namesz+alignment-1)&~(alignment-1));end=descriptor+descsz;next_note=note_start+((end-note_start+alignment-1)&~(alignment-1))
                need(name_end<=off+segment_size and next_note<=off+segment_size,'truncated ELF note body')
                if read(pos,namesz)==b'GNU\0' and note_type==1:
                    need(namesz==4 and descsz==16 and os_abi is None,'duplicate or invalid ELF GNU ABI tag')
                    system,major,minor,patch=struct.unpack('<IIII',read(descriptor,16))
                    need(system==0 and max(major,minor,patch)<=255,'unreviewed ELF OS ABI requirement')
                    os_abi=(major<<16)|(minor<<8)|patch
                pos=next_note
        if kind==2:
            need(dynamic is None and segment_size<=65536 and segment_size%16==0,'ambiguous ELF dynamic segment');dynamic=(off,segment_size)
    if dynamic is None: return None
    values={};terminated=False
    for pos in range(dynamic[0],sum(dynamic),16):
        tag,value=struct.unpack('<qQ',read(pos,16))
        if tag==0: terminated=True;break
        if tag in (5,10,14): need(tag not in values,'duplicate ELF dynamic identity');values[tag]=value
    need(terminated,'unterminated ELF dynamic segment')
    if 14 not in values: return None
    need(5 in values and 10 in values and 0<values[10]<=2*1024*1024 and values[14]<values[10],'invalid ELF SONAME table')
    offsets=[off+values[5]-addr for addr,off,size in loads if addr<=values[5] and values[5]+values[10]<=addr+size]
    need(len(offsets)==1,'ambiguous ELF string table mapping')
    begin=offsets[0]+values[14]
    name=read(begin,min(256,offsets[0]+values[10]-begin));end=name.find(b'\0')
    need(0<=end<=255,'unterminated ELF SONAME')
    soname=name[:end].decode('ascii');need(re.fullmatch(r'[A-Za-z0-9_.+\-]+',soname),'invalid ELF SONAME')
    return (soname,machine,typ,os_abi or 0)


def package_baseline(kernel, *, profile=PROFILE):
    need(profile in (PROFILE, CLASSIC_PROFILE), 'unknown package provenance profile')
    families = PACKAGES if profile == PROFILE else PACKAGES | frozenset((
        'klibc-utils', 'libklibc', 'busybox-initramfs', 'initramfs-tools-bin', 'linux-base',
        'libcom-err2', 'libext2fs2t64',
        'base-files', 'bcache-tools', 'btrfs-progs', 'cloud-initramfs-copymods', 'cloud-initramfs-dyn-netconf', 'coreutils', 'cryptsetup', 'cryptsetup-bin', 'cryptsetup-initramfs', 'dmsetup', 'e2fsprogs', 'fuse3', 'initramfs-tools-core', 'kbd', 'keyboard-configuration', 'libaio1t64', 'libargon2-1', 'libbsd0', 'libc6', 'libcryptsetup12', 'libdevmapper-event1.02.1', 'libdevmapper1.02.1', 'libdrm2', 'libedit2', 'libevdev2', 'libexpat1', 'libfuse3-3', 'libgcrypt20', 'libgpg-error0', 'libjson-c5', 'liblz4-1', 'liblzo2-2', 'libmd0', 'libmount1', 'libntfs-3g89t64', 'libplymouth5', 'libpopt0', 'libsgutils2-1.46-2', 'libsmartcols1', 'libstdc++6', 'libsystemd0', 'libuuid1', 'libxkbcommon0', 'logsave', 'lvm2', 'mdadm', 'ntfs-3g', 'open-iscsi', 'overlayroot', 'plymouth', 'plymouth-theme-ubuntu-text', 'sg3-utils', 'sg3-utils-udev', 'thin-provisioning-tools', 'udev', 'util-linux', 'zlib1g'))
    pins = {**LARGE_PUBLIC_FILES, **PUBLIC_FILE_PINS} if profile == PROFILE else CLASSIC_LARGE_PUBLIC_FILES
    baseline = {}
    packages = set()
    def admitted(package, name):
        pin = pins.get(name)
        if pin is not None:
            need(package == pin[0], 'competing package for pinned boot file')
            return True
        return package in families or package.startswith(('linux-image-' + kernel,
            'linux-modules-' + kernel, 'linux-modules-extra-' + kernel))
    def add(package, name, h):
        need(re.fullmatch('[a-f0-9]{32}', h) and name.startswith('/') and
             name == posixpath.normpath(name) and '\x00' not in name,
             'invalid dpkg boot baseline')
        if not admitted(package, name):
            return
        need(name not in baseline or baseline[name] == h, 'competing dpkg boot baseline')
        baseline[name] = h
    for path in Path('/var/lib/dpkg/info').glob('*.md5sums'):
        package = path.name.removesuffix('.md5sums').split(':', 1)[0]
        if package not in families and package not in {v[0] for v in pins.values()} and not package.startswith(('linux-image-' + kernel,
                'linux-modules-' + kernel, 'linux-modules-extra-' + kernel)):
            continue
        packages.add(path.name.removesuffix('.md5sums'))
        for line in trusted_read(path).decode('utf-8').splitlines():
            h, sep, name = line.partition('  ')
            need(sep and re.fullmatch('[a-f0-9]{32}', h) and not name.startswith('/') and
                 '..' not in name.split('/'), 'invalid dpkg boot baseline')
            add(package, '/' + name, h)
    # md5sums deliberately omits conffiles. Use dpkg's separate factory digest,
    # never the current file's digest, and never an obsolete conffile grant.
    need(0 < len(packages) <= 512, 'dpkg profile package inventory bound')
    raw = command('dpkg-query', '-W', '-f=${binary:Package}\n${Conffiles}\n', *sorted(packages))
    package = None
    for line in raw.decode('utf-8').splitlines():
        if not line:
            continue
        if not line.startswith(' '):
            need(line in packages, 'unexpected dpkg conffile owner')
            package = line.split(':', 1)[0]
            continue
        # dpkg marks a never-installed, scheduled-for-removal conffile with
        # this non-digest sentinel. It grants no path or current-file trust.
        if re.fullmatch(r' /[^\s]+ newconffile remove-on-upgrade', line):
            need(package is not None, 'ownerless removed conffile')
            continue
        match = re.fullmatch(r' (/[^\s]+) ([a-f0-9]{32})( obsolete)?', line)
        need(package is not None and match is not None, 'invalid dpkg conffile metadata')
        if match[3] is None:
            add(package, match[1], match[2])
    return baseline


def large_public_source(path, mode, baseline, cache, *, profile=PROFILE):
    need(profile in (PROFILE, CLASSIC_PROFILE), 'unknown large source profile')
    files = LARGE_PUBLIC_FILES if profile == PROFILE else CLASSIC_LARGE_PUBLIC_FILES
    need(path in files and path in baseline, 'unpackaged large boot source ' + path)
    if profile == PROFILE:
        _, pin, max_links = files[path]
        pins = {pin} | LARGE_PUBLIC_REVISIONS.get(path, frozenset())
    else:
        _, pin, pin_size, pin_mode = files[path]
        need(stat.S_IMODE(mode) == pin_mode, 'classic large source mode mismatch')
        max_links, pins = 1, {pin}
    resolved = Path(path).resolve(strict=True)
    for item in (resolved, *resolved.parents):
        s = item.lstat()
        need(s.st_uid == 0 and not s.st_mode & 0o022 and not stat.S_ISLNK(s.st_mode),
             'untrusted large boot source ancestry')
    fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        before = os.fstat(source.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and
             not before.st_mode & 0o022 and 1 <= before.st_nlink <= max_links and
             MAX_MEMORY_ENTRY < before.st_size <= MAX_ENTRY and
             stat.S_IMODE(before.st_mode) == stat.S_IMODE(mode), 'untrusted large boot source')
        if profile == CLASSIC_PROFILE:
            need(before.st_size == pin_size, 'classic large source size mismatch')
        def facts(s):
            return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns,
                    s.st_mode, s.st_uid, s.st_gid, s.st_nlink)
        key = facts(before)
        if key not in cache:
            sha, md5 = hashlib.sha256(), hashlib.md5()
            count = 0
            while raw := source.read(STREAM_CHUNK):
                count += len(raw)
                need(count <= MAX_ENTRY, 'large boot source grew')
                sha.update(raw); md5.update(raw)
            need(count == before.st_size and md5.hexdigest() == baseline[path] and
                 sha.hexdigest() in pins, 'modified pinned large boot source ' + path)
            def read_at(offset, length):
                source.seek(offset)
                return source.read(length)
            identity = elf_identity(read_at=read_at, size=count)
            cache[key] = (md5.hexdigest(), StreamedBody(count, sha.hexdigest(), identity))
        md5, body = cache[key]
        need(md5 == baseline[path] and body.sha256 in pins, 'large boot source provenance mismatch')
        after = os.fstat(source.fileno())
        need(facts(before) == facts(after) == facts(resolved.lstat()), 'large boot source raced')
    return body




@bounded_assessment
def verify_profile(kernel, image, *, boot=False, nonce=None, profile=PROFILE):
    need(KERNEL.fullmatch(kernel), 'invalid kernel')
    need(profile in (PROFILE, CLASSIC_PROFILE), 'unknown archive verifier profile')
    if profile == CLASSIC_PROFILE:
        from aegis_initrd_classic import verify_archive
        if nonce is None:
            metadata = archive_entries(image, metadata_payloads=frozenset((
                'usr/lib/dracut/modules.txt', 'etc/aegis-initrd-id')))
            nonce = metadata.get('etc/aegis-initrd-id', {}).get('data', b'').decode('ascii').strip()
        need(type(nonce) is str and re.fullmatch('[a-f0-9]{64}', nonce), 'classic image nonce missing')
        result = verify_archive(kernel, image, nonce=nonce)
        result.update(initramfs_network='absent_verified', network_manager='absent')
        if boot:
            verify_boot_identity(kernel, result['initrd_sha256'], result['build_nonce'], profile=CLASSIC_PROFILE)
            result['boot_identity_verified'] = True
        return result
    version = command('dpkg-query', '-W', '-f=${Version}', 'dracut-core').decode().strip()
    need(version == REVIEWED_DRACUT, 'unreviewed dracut version: deny-only')
    image_before=sha_file(image)
    entries = archive_entries(image)
    def payload(name):
        e = entries.get(name)
        need(e is not None and stat.S_ISREG(e['mode']), 'missing initrd file ' + name)
        return e['data']
    need(entries.get('init', {}).get('data') == b'usr/lib/systemd/systemd' and
         stat.S_ISLNK(entries['init']['mode']), 'unsupported Debian dracut init entry')
    modules = payload('usr/lib/dracut/modules.txt').decode('ascii').split()
    need(len(modules) == len(set(modules)) and set(modules) <= LOCAL_MODULES and
         not set(modules) & OMIT and {'systemd', 'dracut-systemd', 'base',
         'rootfs-block', 'aegis-initrd-gate'} <= set(modules), 'unreviewed dracut module closure')
    marker = payload('etc/aegis-initrd-id').decode('ascii').strip()
    need(re.fullmatch('[a-f0-9]{64}', marker) and (nonce is None or marker == nonce),
         'missing or mismatched AEGIS build identity')
    barrier = cloud_barrier_files()
    for name, raw in barrier.items():
        entry = entries.get(name, {})
        need(stat.S_ISREG(entry.get('mode', 0)) and
             stat.S_IMODE(entry['mode']) == 0o644 and entry.get('nlink', 1) == 1 and
             entry.get('data') == raw, 'missing or changed switch-root barrier ' + name)
    # Running the oneshot early would cache success before /sysroot exists.
    # Only the two hard switch-root dependencies pull this unit into a boot.
    need(not any('/systemd/system/' in name and name.endswith('/aegis-initrd-id.service') and
                 name != 'usr/lib/systemd/system/aegis-initrd-id.service' for name in entries),
         'early or foreign initrd gate activation')
    baseline = package_baseline(kernel)
    source_hashes = {}
    large_cache = {}
    def public_source(path):
        choices = (path, '/usr' + path if path.startswith(('/lib/', '/bin/', '/sbin/')) else
                   path[4:] if path.startswith(('/usr/lib/', '/usr/bin/', '/usr/sbin/')) else path)
        source = next((p for p in choices if p in baseline), None)
        need(source is not None, 'unpackaged boot source ' + path)
        raw = trusted_read(path, MAX_MEMORY_ENTRY)
        need(hashlib.md5(raw).hexdigest() == baseline[source], 'modified boot source ' + path)
        if path in PUBLIC_FILE_PINS:
            need(hashlib.sha256(raw).hexdigest() == PUBLIC_FILE_PINS[path][1],
                 'unreviewed factory source revision ' + path)
        source_hashes[path] = hashlib.sha256(raw).hexdigest()
        return raw
    files = {}
    roots = {'', '.', 'dev', 'proc', 'sys', 'run', 'tmp', 'var', 'var/tmp', 'sysroot',
             'root', 'run/lock', 'kernel', 'kernel/x86', 'kernel/x86/microcode'}
    indices = set()
    console_checked = False
    def console_provenance():
        nonlocal console_checked
        if console_checked:
            return
        for path, pin in (
            ('/usr/bin/setupcon', '9cbb365d8a88b33ac0c129e09ab59fffcddd359224e357ce9f40729684cf0eb9'),
            ('/usr/lib/dracut/modules.d/09console-setup/module-setup.sh',
             'd1537234dabbb62c870688d11d49ce7f59975634325b68ee180aabb49a754e81')):
            need(hashlib.sha256(public_source(path)).hexdigest() == pin,
                 'changed console data producer')
        console_checked = True
    for name, e in entries.items():
        mode, raw = e['mode'], e['data']
        # dracut creates empty runtime hook stages unconditionally. This exact
        # empty directory has no callback; any child still hits the network
        # footprint refusal below. No network hook file is authorized.
        if name == 'var/lib/dracut/hooks/netroot' and stat.S_ISDIR(mode):
            need(stat.S_IMODE(mode) == 0o755 and not any(
                path.startswith(name + '/') for path in entries), 'nonempty network hook stage')
            continue
        need(not re.search(r'(?i)(?:networkd|network-generator|wait-online|resolved|dhcp|netroot|\.network(?:$|/)|(?:^|/)cmdline\.d(?:/|$))', name),
             'forbidden initrd network footprint ' + name)
        need(not name.startswith(('etc/crypttab','etc/cryptroot','etc/cryptsetup-keys.d/',
             'usr/lib/cryptsetup-keys.d/','run/cryptsetup-keys.d/','usr/lib/modules/keys/',
             'lib/modules/keys/')),
             'embedded cryptsetup key requires separate review')
        if stat.S_ISDIR(mode):
            continue
        need(stat.S_ISREG(mode) or stat.S_ISLNK(mode) or
             stat.S_ISCHR(mode) and name in DEVICES,
             'unsupported initrd entry type ' + name)
        if stat.S_ISCHR(mode):
            need(e['rdev'] == DEVICES[name] and stat.S_IMODE(mode) == 0o600 and raw == b'',
                 'unexpected initrd device ' + name)
            files[name] = hashlib.sha256(raw).hexdigest()
            continue
        need(not ('/kernel/net/' in name or '/kernel/drivers/net/' in name),
             'kernel network driver in initrd')
        unitpart = None
        if '/systemd/system/' in name and name not in barrier:
            unitpart = name.split('/systemd/system/', 1)[1]
            leaf = unitpart.rsplit('/', 1)[-1]
            need(leaf in UNITS and (len(unitpart.split('/')) == 1 or
                 len(unitpart.split('/')) == 2 and unitpart.split('/')[0].removesuffix(
                 '.wants').removesuffix('.requires') in UNITS), 'unknown initrd unit activation ' + name)
        if '/system-generators/' in name:
            need(name.rsplit('/', 1)[-1] in GENERATORS, 'unknown initrd generator')
        if '/udev/rules.d/' in name:
            need(name.rsplit('/', 1)[-1] in UDEV, 'unknown initrd udev rule')
        if '/dracut/hooks/' in name:
            need(name in DRACUT_RELOCATE, 'unknown initrd hook ' + name)
        if isinstance(raw, StreamedBody):
            need(stat.S_ISREG(mode) and e['nlink'] <= 128, 'invalid large initrd hardlink')
            body = large_public_source('/' + name, mode, baseline, large_cache)
            need(raw.size == body.size and raw.sha256 == body.sha256,
                 'archive differs from pinned large source ' + name)
            # The loader identity is from the still-open authenticated host FD,
            # after its SHA-256 matched these streamed archive bytes and pin.
            e['data'] = body
            source_hashes['/' + name] = body.sha256
            files[name] = body.sha256
            continue
        pin = PUBLIC_FILE_PINS.get(DATA_RELOCATE.get(name, '/' + name))
        if pin is not None:
            need(stat.S_ISREG(mode) and stat.S_IMODE(mode) == pin[2],
                 'unreviewed factory file mode ' + name)
        if stat.S_ISLNK(mode):
            target = raw.decode('utf-8')
            resolved = posixpath.normpath(target.lstrip('/') if target.startswith('/') else
                                         posixpath.join(posixpath.dirname(name), target))
            need(not resolved.startswith('../') and resolved in entries or
                 (name == 'etc/mtab' and target == '/proc/self/mounts'), 'unresolved initrd symlink')
            fixed = {'init': 'usr/lib/systemd/systemd', 'bin': 'usr/bin', 'sbin': 'usr/sbin',
                'lib': 'usr/lib', 'lib64': 'usr/lib64', 'etc/initrd-release': '../usr/lib/initrd-release',
                'etc/os-release': 'initrd-release', 'usr/lib/os-release': 'initrd-release',
                'etc/mtab': '/proc/self/mounts', 'var/run': '../run', 'var/lock': '../run/lock',
                'usr/bin/dracut-getarg': 'dracut-util', 'usr/bin/dracut-getargs': 'dracut-util',
                'usr/bin/loginctl': 'gnutrue', 'etc/modules-load.d/modules.conf': '../modules', 'usr/lib/systemd/system/default.target': 'initrd.target'}
            if name in fixed:
                need(target == fixed[name], 'changed initrd alias')
            elif unitpart and '.wants/' in unitpart:
                need(resolved.rsplit('/', 1)[-1] == unitpart.rsplit('/', 1)[-1],
                     'changed initrd unit dependency target')
            else:
                path = Path('/' + name)
                need(path.is_symlink() and os.readlink(path) == target and
                     ('/' + name in baseline or str(path.resolve()) in baseline),
                     'unreviewed initrd symlink ' + name)
        elif name in ('etc/hostname','etc/machine-id'):
            need(not mode&0o111 and len(raw)<=256 and
                 (re.fullmatch(rb'[a-f0-9]{32}\n?',raw) if name.endswith('machine-id') else
                  re.fullmatch(rb'[A-Za-z0-9][A-Za-z0-9.-]{0,253}\n?',raw)),
                 'invalid inert host identity')
        elif name == 'early_cpio':
            need(raw==b'1\n' and not mode&0o111,'unreviewed early CPIO marker')
        elif name.startswith('kernel/x86/microcode/'):
            need(name in ('kernel/x86/microcode/GenuineIntel.bin',
                          'kernel/x86/microcode/AuthenticAMD.bin'),'unreviewed microcode path')
            candidates=[p for p in baseline if '/firmware/' in p and
                        ('intel-ucode/' in p or 'amd-ucode/' in p)]
            need(0<len(candidates)<=512,'microcode baseline bound')
            need(any(raw==public_source(path) for path in candidates),
                 'early microcode differs from packaged firmware')
        elif name in ('usr/lib/dracut/need-initqueue',):
            need(raw==b'' and not mode&0o111,'unreviewed generated dracut flag')
        elif name.startswith('usr/lib/dracut/dracut-'):
            need(name=='usr/lib/dracut/dracut-'+REVIEWED_DRACUT and
                 raw==('dracut-'+REVIEWED_DRACUT+'\n').encode() and not mode&0o111,
                 'unreviewed dracut version marker')
        elif name == 'usr/lib/dracut/build-parameter.txt':
            need(raw == ("--kver '" + kernel + "'\n").encode() and not mode&0o111,
                 'unreviewed dracut build parameters')
        elif name == 'usr/lib/dracut/hostonly-files':
            need(not mode&0o111, 'executable hostonly metadata')
            for line in raw.decode('ascii').splitlines():
                normalized = posixpath.normpath(line)
                need(line.startswith('/') and normalized.lstrip('/') in entries and
                     (line == normalized or line == '/etc/modules-load.d/../modules'),
                     'unreviewed hostonly metadata reference')
        elif name in ('usr/lib/dracut/modules.txt', 'etc/aegis-initrd-id'):
            pass
        elif name in barrier:
            need(raw == barrier[name], 'modified AEGIS switch-root barrier')
        elif name.startswith('usr/lib/modules/' + kernel + '/') and name.rsplit('/', 1)[-1] in (
                'modules.dep', 'modules.dep.bin', 'modules.alias', 'modules.alias.bin',
                'modules.softdep', 'modules.symbols', 'modules.symbols.bin',
                'modules.builtin.bin', 'modules.devname', 'modules.weakdep', 'modules.builtin.alias.bin'):
            indices.add(name)
        elif name in ('etc/fstab', 'etc/fstab.empty', 'etc/crypttab'):
            need(not any(l.strip() and not l.lstrip().startswith(b'#') for l in raw.splitlines()),
                 'nonempty initrd mount/unlock policy')
        elif name in ('etc/passwd', 'etc/group', 'etc/shadow', 'etc/gshadow',
                      'etc/passwd-', 'etc/group-', 'etc/gshadow-', 'etc/shadow-'):
            need(all(len(l) <= 2048 and b'\x00' not in l for l in raw.splitlines()),
                 'invalid initrd account data')
            if 'shadow' in name:
                need(all(len(l.split(b':')) > 1 and l.split(b':')[1] in (b'*', b'!', b'!!', b'!*', b'')
                         for l in raw.splitlines()), 'embedded account credential')
            else:
                need(all(len(l.split(b':')) > 1 and l.split(b':')[1] in
                     (b'x', b'*', b'!', b'!!', b'!*') for l in raw.splitlines()),
                     'embedded account credential')
                need(all(b'/' not in l.split(b':')[-1] or l.split(b':')[-1] in
                     (b'/bin/sh', b'/bin/bash', b'/usr/bin/bash', b'/sbin/nologin', b'/usr/sbin/nologin', b'/bin/false')
                     for l in raw.splitlines()), 'custom initrd login shell')
        elif name == 'etc/ld.so.cache':
            pass  # Parsed below after every mapped library has passed provenance.
        elif name == 'etc/.pwd.lock':
            need(raw == b'', 'nonempty account lock')
        elif name in ('etc/nsswitch.conf', 'usr/lib/udev/rules.d/50-udev-default.rules'):
            need(raw == (LOCAL_NSS if name == 'etc/nsswitch.conf' else LOCAL_UDEV) and
                 stat.S_IMODE(mode) == 0o644, 'changed local-only lookup/device policy')
        elif name == CONSOLE_KEYMAP:
            console_provenance()
            cached = trusted_read('/' + CONSOLE_KEYMAP + '.gz', MAX_MEMORY_ENTRY)
            need(hashlib.sha256(cached).hexdigest() == CONSOLE_CACHE_SHA,
                 'unreviewed console keymap cache')
            with gzip.GzipFile(fileobj=io.BytesIO(cached)) as stream:
                expanded = stream.read(MAX_MEMORY_ENTRY + 1)
            need(not mode&0o111 and len(expanded) <= MAX_MEMORY_ENTRY and raw == expanded and
                 hashlib.sha256(raw).hexdigest() == CONSOLE_KEYMAP_SHA,
                 'modified generated console keymap')
        elif name == 'usr/bin/setupcon':
            console_provenance()
            need(raw == CONSOLE_SETUP and stat.S_IMODE(mode) == 0o700,
                 'changed generated console setup recipe')
        elif name in ('etc/default/keyboard', 'etc/modules'):
            pin = {'etc/default/keyboard': '9d2d64b5b738ef55ecc80e236cd00caba19d3afe1921c74fa7d73c9477ebe6eb',
                   'etc/modules': 'c0d37c5c430cb5c978a4ea00e42ddc4551b04f76352d149d6be5d5b65346df65'}[name]
            need(not mode&0o111 and raw == trusted_read('/' + name, MAX_MEMORY_ENTRY) and
                 hashlib.sha256(raw).hexdigest() == pin, 'unreviewed generated local boot data')
        elif name == 'etc/hosts':
            need(not mode&0o111 and raw == trusted_read('/etc/hosts', MAX_MEMORY_ENTRY),
                 'changed inert hosts data')
            for line in raw.decode('ascii').splitlines():
                fields = line.partition('#')[0].split()
                if not fields:
                    continue
                need(len(fields) >= 2 and fields[0] in ('127.0.0.1','127.0.1.1','::1',
                     'fe00::0','ff00::0','ff02::1','ff02::2') and all(
                     re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,253}', x) for x in fields[1:]),
                     'nonlocal hosts data')
        elif name == 'usr/bin/dracut-util':
            need(raw == public_source('/usr/lib/dracut/dracut-util'),
                 'changed relocated dracut utility')
        elif name in DRACUT_RELOCATE:
            need(raw == public_source('/usr/lib/dracut/modules.d/' + DRACUT_RELOCATE[name]),
                 'changed relocated dracut code ' + name)
        elif name == 'etc/conf.d/systemd.conf':
            # dracut110 emits this inert directory variable even when every
            # network module/unit/configuration has been omitted. Neither
            # recipe authorizes any network footprint or executable shell.
            need(raw in (SYSTEMD_PATH_RECIPE, SYSTEMD_PATH_RECIPE +
                 b'systemdnetworkconfdir="/etc/systemd/network"\n'),
                 'changed systemd path recipe')
        elif name == 'usr/lib/initrd-release':
            original=public_source('/usr/lib/os-release').decode('utf-8')
            output=[];values={}
            for line in original.splitlines():
                if line.startswith(('VERSION=','PRETTY_NAME=')):
                    key,value=line.split('=',1);tokens=shlex.split(value)
                    need(len(tokens)==1 and not any(c in tokens[0] for c in '\\"$`'),
                         'nonliteral public OS release')
                    values[key]=tokens[0]
                else:
                    output.append(line)
            for key,suffix in (('VERSION','dracut-'+REVIEWED_DRACUT),
                 ('PRETTY_NAME','dracut-'+REVIEWED_DRACUT+' (Initramfs)')):
                output.append(key+'="'+(values[key]+' ' if values.get(key) else '')+suffix+'"')
            output.append('DRACUT_VERSION="'+REVIEWED_DRACUT+'"')
            need(raw==('\n'.join(output)+'\n').encode(),'modified generated initrd release')

        else:
            need(name.startswith(('usr/bin/', 'usr/sbin/', 'usr/lib/', 'usr/lib64/',
                'usr/share/terminfo/', 'usr/share/plymouth/', 'etc/')) or
                name in DATA_RELOCATE or '/' + name in PUBLIC_FILE_PINS, 'unknown initrd path ' + name)
            need(not name.startswith(('etc/systemd/', 'etc/udev/', 'etc/modprobe.d/')) or
                 '/' + name in baseline or name in DRACUT_RELOCATE,
                 'unpackaged initrd policy ' + name)
            need(raw == public_source(DATA_RELOCATE.get(name, '/' + name)),
                 'archive differs from packaged source ' + name)
        files[name] = hashlib.sha256(raw).hexdigest()
    # Directories are admitted only as parents of independently admitted leaves
    # or the fixed runtime mount points. Empty activation directories are unknown.
    parents = set(roots) | {prefix+stage for prefix in
        ('usr/lib/dracut/hooks/','var/lib/dracut/hooks/') for stage in
        ('cmdline','cmdline-ask','emergency','initqueue','initqueue/finished',
         'initqueue/online','initqueue/settled','initqueue/timeout','mount',
         'pre-mount','pre-pivot','pre-trigger','pre-udev','shutdown','cleanup')}
    parents.add('var/lib/dracut/hooks/netroot')
    parents.update(str(p) for name in tuple(parents) for p in Path(name).parents)
    for name in files:
        parents.update(str(p) for p in Path(name).parents)
    for name, e in entries.items():
        need(not stat.S_ISDIR(e['mode']) or name in parents,
             'unknown empty initrd directory ' + name)
    if 'etc/ld.so.cache' in entries:
        verify_loader_cache(entries)
    if indices:
        verify_kernel_indices(entries, kernel, public_source)
    need(sha_file(image)==image_before,'initrd changed during strict assessment')
    result = {'initramfs_network': 'absent_verified', 'initrd_sha256': sha_file(image),
        'kernel': kernel, 'checked_policy_files': len(files), 'boot_profile': PROFILE,
        'network_manager': 'absent', 'build_nonce': marker,
        'archive_projection_sha256': digest(files), 'public_source_sha256': digest(source_hashes),
        'modules': sorted(modules)}
    if boot:
        verify_boot_identity(kernel, result['initrd_sha256'], marker)
    return result


def kernel_alias_key(value):
    out = []; bracket = False
    for c in value:
        if c == '[':
            need(not bracket, 'nested kernel alias range'); bracket = True
        elif c == ']':
            need(bracket, 'unmatched kernel alias range'); bracket = False
        out.append('_' if c == '-' and not bracket else c)
    need(not bracket, 'unterminated kernel alias range')
    return ''.join(out)


def builtin_alias_projection(data):
    """kmod34 built-in alias lookup, from authenticated kernel modinfo only.

    Equal-priority insertions precede existing values, including duplicates.
    This ordering matters for aliases shared by multiple built-in modules.
    """
    need(len(data) <= MAX_MEMORY_ENTRY and (not data or data.endswith(b'\0')),
         'builtin modinfo bound or terminator')
    result = {}; count = 0
    for record in data.split(b'\0'):
        if not record:
            continue
        module, dot, field = record.partition(b'.')
        key, equals, value = field.partition(b'=')
        need(dot and equals and re.fullmatch(rb'[A-Za-z0-9_-]+', module),
             'noncanonical builtin modinfo record')
        if key != b'alias':
            continue
        need(0 < len(value) <= 4096 and all(32 <= c < 127 for c in value),
             'builtin alias bound or encoding')
        alias = kernel_alias_key(value.decode('ascii'))
        result.setdefault(alias, []).insert(0, (0, module.decode('ascii').replace('-', '_')))
        count += 1
        need(count <= 100000, 'builtin alias count bound')
    return result


def builtin_module_projection(data):
    """kmod index_insert preserves repeated basenames, even identical values.

    Both upstream v31/v34 tools/depmod.c output_builtin_bin use this recipe;
    ARM has real arm_cci/clk_pll basename collisions in different directories.
    """
    need(len(data) <= MAX_MEMORY_ENTRY and (not data or data.endswith(b'\n')),
         'builtin module list bound or terminator')
    result = {}
    for count, line in enumerate(data.decode('ascii').splitlines(), 1):
        need(count <= 65536, 'builtin module inventory bound')
        if not line:
            continue
        need(re.fullmatch(r'kernel/[A-Za-z0-9_/+.-]+\.ko(?:\.(?:xz|gz|zst))?', line) and
             '..' not in line.split('/'), 'noncanonical builtin module path')
        name = posixpath.basename(line).split('.')[0].replace('-', '_')
        result.setdefault(name, []).append((0, ''))
    return result


def kernel_index_family(present, *, profile=PROFILE):
    need(profile in (PROFILE, CLASSIC_PROFILE), 'unknown kernel index profile')
    base = {'modules.dep', 'modules.dep.bin', 'modules.alias', 'modules.alias.bin',
        'modules.softdep', 'modules.symbols', 'modules.symbols.bin', 'modules.builtin.bin', 'modules.devname'}
    extended = {'modules.weakdep', 'modules.builtin.alias.bin'}
    expected = (base | {'modules.builtin.alias.bin'} if profile == CLASSIC_PROFILE else
                base | extended if set(present) & extended else base)
    need(set(present) == expected, 'unsupported or incomplete kernel index family')
    return expected


def decode_module_index(data):
    need(12<=len(data)<=8*1024*1024,'kernel index size bound')
    magic,version,root=struct.unpack_from('>III',data)
    need(magic==0xb007f457 and version==0x20001,'unsupported kernel index format')
    nodes=set();spans=[(0,12)];result={};stack=[(root,'',0)];nvalues=0
    while stack:
        offset,key,depth=stack.pop()
        if offset==0: continue
        base=offset&0xfffffff
        need(not offset&0x10000000 and 12<=base<len(data) and base not in nodes and depth<=256,'kernel index offset cycle or depth')
        nodes.add(base);need(len(nodes)<=100000,'kernel index node bound');pos=base
        def number():
            nonlocal pos
            need(pos+4<=len(data),'truncated kernel index number')
            value=struct.unpack_from('>I',data,pos)[0];pos+=4;return value
        def string():
            nonlocal pos
            end=data.find(b'\0',pos,min(len(data),pos+4097))
            need(end>=pos and all(32<=c<127 for c in data[pos:end]),'invalid kernel index string')
            value=data[pos:end].decode('ascii');pos=end+1;return value
        if offset&0x80000000: key+=string()
        need(len(key)<=4096,'kernel index key bound')
        children=[]
        if offset&0x20000000:
            need(pos+2<=len(data),'truncated kernel index children')
            first,last=data[pos:pos+2];pos+=2
            need(0<=first<=last<128,'invalid kernel index child range')
            children=[(number(),key+chr(c),depth+1) for c in range(first,last+1)]
        if offset&0x40000000:
            count=number();nvalues+=count
            need(0<count<=10000 and nvalues<=100000 and key not in result,'kernel index value bound or duplicate key')
            values=[(number(),string()) for _ in range(count)]
            need(values==sorted(values,key=lambda v:v[0]),'kernel index priority order')
            result[key]=values
        spans.append((base,pos));stack.extend(children)
    cursor=0
    for begin,end in sorted(spans):
        need(begin==cursor and end>begin,'overlapping or unaccounted kernel index bytes');cursor=end
    need(cursor==len(data),'kernel index suffix');return result

def verify_kernel_indices(entries, kernel, public_source, *, profile=PROFILE):
    checked = 0
    trusted = lambda p: Path(p).resolve(strict=True)
    payload = lambda p: entries[p]['data']
    def module_name(path):
        leaf=posixpath.basename(path)
        need(re.fullmatch(r'[A-Za-z0-9_\-]+\.ko(?:\.(?:xz|gz|zst))?',leaf),'noncanonical kernel module filename')
        return leaf.split('.')[0].replace('-','_')
    module_prefix='usr/lib/modules/'+kernel+'/'
    index_names={'modules.dep','modules.dep.bin','modules.alias','modules.alias.bin','modules.softdep','modules.symbols','modules.symbols.bin','modules.builtin.bin','modules.devname'}
    extended_indexes={'modules.weakdep','modules.builtin.alias.bin'}
    present_indexes={name[len(module_prefix):] for name in entries if name.startswith(module_prefix) and name[len(module_prefix):] in index_names | extended_indexes}
    if present_indexes:
        index_names = kernel_index_family(present_indexes, profile=profile)
        modules_in_image=[name for name,e in entries.items() if name.startswith(module_prefix) and re.search(r'\.ko(?:\.(?:xz|gz|zst))?$',name) and stat.S_ISREG(e['mode'])]
        need(0<len(modules_in_image)<=2048,'kernel module oracle input bound')
        args=[];names=set()
        for name in sorted(modules_in_image):
            relative=name[len(module_prefix):];mod=module_name(relative)
            need(mod not in names,'competing packaged kernel module names');names.add(mod)
            path='/lib/modules/'+kernel+'/'+relative
            data=public_source(path)
            need(hashlib.sha256(data).hexdigest()==hashlib.sha256(entries[name]['data']).hexdigest(),'host module differs from assessed archive')
            args.append(path)
        for leaf in ('modules.order','modules.builtin','modules.builtin.modinfo'):
            data=public_source('/lib/modules/'+kernel+'/'+leaf)
            need(module_prefix+leaf in entries and hashlib.sha256(entries[module_prefix+leaf]['data']).hexdigest()==hashlib.sha256(data).hexdigest(),'host kernel metadata differs from archive')
        tool='/usr/sbin/depmod';backing=str(trusted(tool))
        need(backing==str(trusted('/usr/bin/kmod')),'unexpected depmod executable binding')
        public_source('/usr/bin/kmod')
        need(sum(len(x)+1 for x in args)<=192*1024,'kernel oracle argument bound')
        # Explicit-file mode skips cfg_load/discovery. -n sets stdout;
        # output callbacks do not open or create any destination file in it.
        child=subprocess.Popen([tool,'-n','-C','/dev/null',kernel,*args],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'})
        try:
            output=child.stdout.read(16*1024*1024+1)
            need(len(output)<=16*1024*1024,'kernel oracle output bound')
            need(child.wait(timeout=15)==0,'verified depmod dry-run failed')
        finally:
            if child.poll() is None: child.kill();child.wait()
        groups={'modules.dep':[],'modules.alias':[],'modules.softdep':[],'modules.symbols':[],'modules.devname':[]}
        if 'modules.weakdep' in index_names:
            groups['modules.weakdep']=[]
        for line in output.decode('ascii').splitlines():
            if not line or line.startswith('#'): continue
            if line.startswith('alias '): group='modules.symbols' if line.startswith('alias symbol:') else 'modules.alias'
            elif line.startswith('softdep '): group='modules.softdep'
            elif line.startswith('weakdep '):
                need('modules.weakdep' in groups, 'unexpected weak dependency oracle')
                group='modules.weakdep'
            elif re.fullmatch(r'[A-Za-z0-9_]+ [A-Za-z0-9_/.-]+ [bc][0-9]+:[0-9]+',line): group='modules.devname'
            else: group='modules.dep'
            groups[group].append(line)
        ranks={};expected={name:{} for name in ('modules.dep.bin','modules.alias.bin','modules.symbols.bin','modules.builtin.bin')}
        for rank,line in enumerate(groups['modules.dep']):
            path,sep,dependencies=line.partition(':')
            need(sep and module_prefix+path in modules_in_image and all(module_prefix+x in modules_in_image for x in dependencies.split()),'noncanonical module dependency oracle')
            mod=module_name(path);need(mod not in ranks,'duplicate module dependency oracle');ranks[mod]=rank
            expected['modules.dep.bin'][mod]=[(rank,line)]
        need(set(ranks)==names,'incomplete kernel dependency oracle')
        for group in ('modules.alias','modules.symbols'):
            for line in groups[group]:
                fields=line.split();need(len(fields)==3 and fields[0]=='alias' and fields[2] in ranks,'invalid alias oracle')
                key=kernel_alias_key(fields[1])
                expected[group+'.bin'].setdefault(key,[]).append((ranks[fields[2]],fields[2]))
            for values in expected[group+'.bin'].values(): values.sort(key=lambda v:v[0])
        expected['modules.builtin.bin'] = builtin_module_projection(
            public_source('/lib/modules/'+kernel+'/modules.builtin'))
        if 'modules.builtin.alias.bin' in index_names:
            expected['modules.builtin.alias.bin']=builtin_alias_projection(
                public_source('/lib/modules/'+kernel+'/modules.builtin.modinfo'))
        for name,lines in groups.items():
            actual=[line for line in payload(module_prefix+name).decode('ascii').splitlines() if line and not line.startswith('#')]
            # Symbol hash-table iteration order has no lookup semantics;
            # aliases/dependencies retain exact canonical ordering below.
            need((sorted(actual)==sorted(lines) if name=='modules.symbols' else actual==lines),'kernel text index differs from canonical oracle '+name)
        for name,mapping in expected.items():
            need(decode_module_index(payload(module_prefix+name))==mapping,'kernel binary index differs from canonical oracle '+name)
        checked+=len(index_names)



def verify_loader_cache(entries, *, profile=PROFILE):
    need(profile in (PROFILE, CLASSIC_PROFILE), 'unknown loader cache profile')
    machine, elf_machine, cache_flags, library_dirs = (
        ('x86_64', 62, 0x303, r'lib(?:64|/x86_64-linux-gnu)?') if profile == PROFILE else
        ('aarch64', 183, 0xa03, r'lib(?:/aarch64-linux-gnu)?'))
    cache=entries['etc/ld.so.cache']['data']
    need(os.uname().machine==machine and len(cache)>=48 and
         cache[:20]==b'glibc-ld.so.cache1.1','unreviewed loader cache ABI')
    count,size=struct.unpack_from('<II',cache,20)
    extension=struct.unpack_from('<I',cache,32)[0]
    strings=48+24*count;strings_end=strings+size
    need(count<=4096 and strings_end<=len(cache) and cache[28]==2 and
         not any(cache[29:32]+cache[36:48]),'invalid loader cache header')
    def cache_string(offset):
        need(strings<=offset<strings_end,'loader cache string offset')
        end=cache.find(b'\0',offset,strings_end)
        need(offset<=end<=offset+4096,'loader cache string bound')
        return cache[offset:end].decode('ascii')
    def resolve(path):
        current=path.lstrip('/')
        for _ in range(32):
            parts=current.split('/');changed=False
            for i in range(1,len(parts)+1):
                name='/'.join(parts[:i]);entry=entries.get(name)
                if entry and stat.S_ISLNK(entry['mode']):
                    target=entry['data'].decode('ascii')
                    base=target.lstrip('/') if target.startswith('/') else posixpath.join(posixpath.dirname(name),target)
                    current=posixpath.normpath(posixpath.join(base,*parts[i:]))
                    need(not current.startswith('../'),'loader symlink escapes')
                    changed=True;break
            if not changed:
                need(current in entries and stat.S_ISREG(entries[current]['mode']),
                     'loader cache missing library')
                return current,entries[current]
        need(False,'loader cache symlink cycle')
    cached={}
    for i in range(count):
        flags,key,value,osversion_unused,hwcap=struct.unpack_from('<iIIIQ',cache,48+i*24)
        # glibc file_entry_new names this field osversion_unused; ldconfig
        # emits zero. GNU ABI notes are parsed in the authenticated ELF, not
        # compared to this reserved cache word. Nonzero remains refused.
        need(flags==cache_flags and hwcap==0 and osversion_unused==0,
             'loader hardware, architecture or reserved-word override')
        soname=cache_string(key);path=cache_string(value)
        need(re.fullmatch(r'[A-Za-z0-9_.+\-]+',soname) and
             re.fullmatch(r'/(?:usr/)?'+library_dirs+r'/[A-Za-z0-9_.+\-]+',path),
             'noncanonical loader cache path')
        resolved,entry=resolve(path)
        identity=elf_identity(entry['data'])
        need(identity is not None and identity[:3]==(soname,elf_machine,3),
             'loader cache code/SONAME mismatch')
        if soname in cached:
            previous_path, previous_target = cached[soname]
            # Noble ldconfig records both fixed interpreter spellings. They
            # must resolve to exactly the same admitted file; no other SONAME,
            # path pair, duplicate count or competing target is permitted.
            need(profile == CLASSIC_PROFILE and soname == 'ld-linux-aarch64.so.1' and
                 previous_target == resolved == 'usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1' and
                 {previous_path, path} == {'/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1',
                                          '/lib/ld-linux-aarch64.so.1'},
                 'competing loader cache SONAME')
            cached[soname] = ('duplicate-already-checked', resolved)
        else:
            cached[soname] = (path, resolved)
    if extension:
        need(extension%4==0 and strings_end<=extension<=strings_end+3 and
             not any(cache[strings_end:extension]) and extension+24<=len(cache),
             'loader cache extension offset')
        magic,nsections=struct.unpack_from('<II',cache,extension)
        tag,flags,offset,size=struct.unpack_from('<IIII',cache,extension+8)
        need(magic==0xeaa42174 and nsections==1 and tag==0 and flags==0 and
             offset==extension+24 and 0<size<=256 and offset+size==len(cache) and
             all(32<=c<127 for c in cache[offset:]),'unknown loader cache extension')
    else:
        need(strings_end==len(cache),'loader cache suffix')


def current_boot():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def verify_boot_image_locator(kernel, values):
    need(KERNEL.fullmatch(kernel), 'unknown boot kernel name')
    if values == ['/boot/vmlinuz-' + kernel]:
        return
    need(values == ['/vmlinuz-' + kernel], 'running BOOT_IMAGE differs from assessed kernel')
    # GRUB paths are relative to its selected filesystem. A short path is an
    # alias for /boot only when /boot is a separate, local filesystem root.
    def mount():
        rows = decode(command('findmnt', '-J', '-T', '/boot', '-o',
                              'SOURCE,TARGET,FSTYPE,FSROOT'))['filesystems']
        need(type(rows) is list and len(rows) == 1, 'ambiguous boot mount')
        row = rows[0]
        need(row.get('target') == '/boot' and row.get('fsroot') == '/' and
             row.get('fstype') in ('ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'f2fs') and
             re.fullmatch(r'/dev/[A-Za-z0-9_./+\-]+', row.get('source', '')) and
             '..' not in row['source'].split('/') and
             not re.search(r'/(?:nbd|rbd|loop)', row['source']),
             'short BOOT_IMAGE requires a separate local boot filesystem')
        return row
    before = mount()
    tree = decode(command('lsblk', '-J', '-s', '-p', '-o',
                          'NAME,TYPE,TRAN', before['source']))['blockdevices']
    remaining = 128
    def local(nodes, depth=0):
        nonlocal remaining
        need(type(nodes) is list and nodes and depth <= 16, 'unknown boot device topology')
        for node in nodes:
            remaining -= 1
            name = node.get('name', '')
            need(remaining >= 0 and re.fullmatch(r'/dev/[A-Za-z0-9_./+\-]+', name) and
                 '..' not in name.split('/') and not re.search(r'/(?:nbd|rbd|loop)', name) and
                 node.get('type') in ('part', 'disk') and
                 node.get('tran') in (None, '', 'ata', 'sata', 'sas', 'scsi', 'usb', 'virtio', 'nvme'),
                 'unknown or network boot device transport')
            if 'nvme' in name:
                controller = re.search(r'(nvme\d+)', name)
                need(controller is not None and Path('/sys/class/nvme/' + controller[1] +
                     '/transport').read_text().strip() == 'pcie', 'unknown boot NVMe transport')
            if node.get('children'):
                local(node['children'], depth + 1)
    local(tree)
    need(len(tree) == 1 and tree[0].get('name') == before['source'], 'boot device differs from mount')
    root = Path('/').lstat()
    boot = Path('/boot').lstat()
    for entry in (root, boot):
        need(stat.S_ISDIR(entry.st_mode) and entry.st_uid == entry.st_gid == 0 and
             not entry.st_mode & 0o022, 'untrusted boot directory')
    need(boot.st_dev != root.st_dev, 'short BOOT_IMAGE requires a separate boot device')
    directory = os.open('/boot', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(directory)
        need((opened.st_dev, opened.st_ino) == (boot.st_dev, boot.st_ino), 'boot directory raced')
        fd = os.open('vmlinuz-' + kernel, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=directory)
        try:
            entry = os.fstat(fd)
            need(stat.S_ISREG(entry.st_mode) and entry.st_uid == entry.st_gid == 0 and
                 not entry.st_mode & 0o022 and entry.st_nlink == 1 and
                 0 < entry.st_size <= MAX_ENTRY and entry.st_dev == boot.st_dev,
                 'untrusted boot kernel')
            need(mount() == before and Path('/boot').lstat() == boot, 'boot mount raced')
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def verify_boot_identity(kernel, image_sha, nonce, *, profile=PROFILE):
    manifest = decode(trusted_read(MANIFEST))
    need(owner_profile(manifest) == profile, 'running initrd owner profile mismatch')
    need(not manifest.get('deny_reason'),'initrd policy remains deny-only')
    need(manifest.get('schema') == 'aegis_initrd_policy_owner_v1' and
         manifest.get('phase') in ('awaiting_reboot', 'active') and
         manifest.get('applied_boot_id') != current_boot(), 'initrd policy requires a new boot')
    verify_ownership(manifest)
    image = manifest.get('images', {}).get(kernel, {})
    need(image.get('sha256') == image_sha and image.get('nonce') == nonce,
         'boot image differs from policy manifest')
    need(trusted_read('/run/aegis-initrd-id', 128) == (nonce + '\n').encode(),
         'running initrd identity unavailable or changed')
    values = [t.partition('=')[2] for t in Path('/proc/cmdline').read_text().split()
              if t.startswith('BOOT_IMAGE=')]
    verify_boot_image_locator(kernel, values)


def policy_hashes(files):
    return {str(path): hashlib.sha256(raw).hexdigest() for path, raw in files.items()}


def previous_policy_files(*, profile=PROFILE):
    # Frozen source-known generations only. These bytes authorize migration
    # or removal; they never qualify an image for boot or a new activation.
    need(profile in (PROFILE, CLASSIC_PROFILE), 'unknown previous initrd profile')
    if profile == CLASSIC_PROFILE:
        return ()
    return (policy_files(pre_cloud=True), policy_files(legacy=True))


def owner_profile(manifest):
    need(type(manifest) is dict and manifest.get('schema') == 'aegis_initrd_policy_owner_v1',
         'unknown initrd owner')
    profile = manifest.get('boot_profile', PROFILE)
    need(profile in (PROFILE, CLASSIC_PROFILE), 'unknown initrd owner profile')
    return profile


def owned_policy_sources(manifest, *, allow_previous=False):
    profile = owner_profile(manifest)
    current = policy_files(profile=profile)
    previous = previous_policy_files(profile=profile)
    variants = (current, *previous) if allow_previous else (current,)
    selected = next((files for files in variants if manifest.get('owned') == policy_hashes(files)), None)
    need(selected is not None, 'initrd ownership manifest differs from source')
    allowed = {path: {raw} for path, raw in selected.items()}
    transition = manifest.get('policy_upgrade')
    if transition is not None:
        need(isinstance(transition, dict) and transition.get('schema') == 'aegis_initrd_policy_upgrade_v1' and
             manifest.get('owned') == policy_hashes(current) and
             transition.get('from_owned') in [policy_hashes(files) for files in previous],
             'unrecognized initrd policy upgrade')
        if allow_previous and manifest.get('phase') in ('building', 'uninstalling', 'rolled_back'):
            old = next(files for files in previous
                       if policy_hashes(files) == transition['from_owned'])
            for path, raw in old.items():
                allowed.setdefault(path, set()).add(raw)
    # A predecessor cannot silently inherit one of the new destinations.
    for path in current.keys() - allowed.keys():
        need(not path.exists() and not path.is_symlink(), 'foreign new initrd policy destination')
    return allowed


def verify_ownership(manifest, *, partial=False, allow_previous=False):
    for path, sources in owned_policy_sources(manifest, allow_previous=allow_previous).items():
        if partial and not path.exists() and not path.is_symlink():
            continue
        need(trusted_read(path) in sources, 'initrd policy ownership mismatch')


def start_policy_upgrade(manifest, detector):
    need(manifest.get('phase') in ('awaiting_reboot', 'active'),
         'previous unfinished policy requires rollback or uninstall')
    verify_ownership(manifest, allow_previous=True)
    need(isinstance(manifest.get('images'), dict) and manifest['images'],
         'previous policy has no verified images')
    for kernel, record in manifest['images'].items():
        need(KERNEL.fullmatch(kernel) and isinstance(record, dict) and
             sha_file(Path('/boot/initrd.img-' + kernel)) == record.get('sha256'),
             'previous policy image changed before upgrade')
    for kernel, record in manifest.get('backups', {}).items():
        need(KERNEL.fullmatch(kernel) and isinstance(record, dict) and
             record.get('path') == str(BACKUP / (kernel + '.initrd')) and
             sha_file(Path(record['path'])) == record.get('sha256'),
             'previous policy backup changed before upgrade')
    need(set(manifest['images']) <= set(manifest.get('backups', {})),
         'previous policy original backup missing')
    manifest['policy_upgrade'] = {
        'schema': 'aegis_initrd_policy_upgrade_v1', 'from_owned': manifest['owned'],
        'from_images': manifest['images'], 'from_applied_boot_id': manifest.get('applied_boot_id')}
    manifest['owned'] = policy_hashes(policy_files())
    manifest['images'] = {}
    manifest['phase'] = 'building'
    manifest['applied_boot_id'] = current_boot()
    manifest['detector'] = detector
    # Persist the only permitted mixed generation before the first replacement.
    save_manifest(manifest)


def remove_owned_policy(manifest):
    sources = owned_policy_sources(manifest, allow_previous=True)
    order = [HOOK, PREHOOK] + [path for path in sources if path not in (HOOK, PREHOOK, DROPIN)] + [DROPIN]
    for path in order:
        if path.exists() or path.is_symlink():
            need(trusted_read(path) in sources[path], 'initrd removal ownership mismatch')
            path.unlink()
            fsync_dir(path.parent)
    if GATE.exists():
        GATE.rmdir()


def boot_snapshot():
    paths = [Path('/etc/default/grub'), Path('/boot/grub/grubenv'), Path('/boot/grub/grub.cfg')]
    paths += list(Path('/etc/default/grub.d').glob('*'))
    paths += list(Path('/etc/kernel/postinst.d').glob('*'))
    paths += list(Path('/etc/dracut.conf.d').glob('*'))
    return {str(p): hashlib.sha256(trusted_read(p)).hexdigest() for p in paths
            if p.is_file() and p not in policy_files()}


def backup_image(image, kernel, manifest):
    key = kernel + '.initrd'
    dest = BACKUP / key
    if not dest.exists():
        # O_EXCL and root-private destination; no named image under /boot.
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'wb') as out, open(image, 'rb') as inp:
                while chunk := inp.read(1 << 20):
                    out.write(chunk)
                out.flush()
                os.fsync(out.fileno())
        except BaseException:
            # Preserve a partial backup under a unique name; never accept it.
            os.rename(dest, dest.with_name(key + '.incomplete-' + os.urandom(8).hex()))
            raise
        fsync_dir(BACKUP)
    need(sha_file(dest) == sha_file(image), 'initrd backup differs from original')
    manifest.setdefault('backups', {})[kernel] = {'path': str(dest), 'sha256': sha_file(dest)}
    save_manifest(manifest)


def replace_image(candidate, image, expected_sha):
    need(candidate.parent == image.parent and sha_file(candidate) == expected_sha,
         'candidate identity changed')
    fd = os.open(candidate, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(candidate, image)
    fsync_dir(image.parent)
    need(sha_file(image) == expected_sha, 'installed initrd readback differs')


def build_candidate(kernel, *, nonce):
    image = Path('/boot/initrd.img-' + kernel)
    candidate = image.with_name('.aegis-candidate-' + kernel + '-' + os.urandom(8).hex())
    need(not candidate.exists() and not candidate.is_symlink(), 'candidate already exists')
    # The same persistent drop-in is used by both explicit apply and later
    # kernel package hooks. No CLI --omit can mask a broken persistent policy.
    env = {**os.environ, 'LC_ALL': 'C', 'aegis_build_nonce': nonce}
    p = subprocess.run(['nice', '-n', '10', 'dracut', '--force', '--kver', kernel,
                        str(candidate)], env=env, timeout=300, umask=0o077, stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    need(p.returncode == 0, 'dracut build failed; retained candidate and original')
    return candidate


def apply(*, opt_in):
    need(opt_in, 'explicit --opt-in required: modifies all initrd images and requires reboot')
    need(os.geteuid() == 0, 'root required')
    detector = detect_local_root()
    need(command('dpkg-query', '-W', '-f=${Version}', 'dracut-core').decode().strip() == \
         REVIEWED_DRACUT, 'unreviewed dracut: deny-only')
    if MANIFEST.exists():
        previous=decode(trusted_read(MANIFEST))
        need(owner_profile(previous) == PROFILE, 'another initrd backend owns this host')
        if previous.get('phase') in ('removed','rolled_back'):
            need(all(not p.exists() and not p.is_symlink() for p in policy_files()),
                 'removed initrd owner has unexpected policy residue')
            known = [policy_hashes(files) for files in (policy_files(), *previous_policy_files())]
            need(previous.get('schema') == 'aegis_initrd_policy_owner_v1' and
                 previous.get('owned') in known, 'unrecognized inactive initrd history')
            # Retained backups are history, never overwritten by a new opt-in.
            archive=BACKUP.with_name(BACKUP.name+'-removed-'+os.urandom(12).hex())
            os.rename(BACKUP,archive)
            fsync_dir(BACKUP.parent)
    BACKUP.mkdir(mode=0o700, parents=True, exist_ok=True)
    need(BACKUP.stat().st_uid == 0 and stat.S_IMODE(BACKUP.stat().st_mode) == 0o700,
         'untrusted boot backup directory')
    if MANIFEST.exists():
        manifest = decode(trusted_read(MANIFEST))
        if manifest.get('owned') != policy_hashes(policy_files()):
            start_policy_upgrade(manifest, detector)
        verify_ownership(manifest, partial=manifest.get('phase') == 'building', allow_previous=True)
        for path, raw in policy_files().items():
            if not path.exists() or trusted_read(path) != raw:
                atomic(path, raw, 0o755 if path.name == 'module-setup.sh' or path in (HOOK, PREHOOK) else 0o644)
        verify_ownership(manifest)
        need(manifest['phase'] in ('building', 'awaiting_reboot', 'active'),
             'unfinished uninstall requires resume')
        if manifest['phase'] in ('awaiting_reboot', 'active'):
            print(json.dumps({'status': 'reboot_required', 'boot_profile': PROFILE}))
            return
    else:
        files = policy_files()
        need(all(not p.exists() and not p.is_symlink() for p in files),
             'foreign initrd policy destination exists')
        manifest = {'schema': 'aegis_initrd_policy_owner_v1', 'phase': 'building',
            'applied_boot_id': current_boot(), 'detector': detector,
            'before': boot_snapshot(), 'owned': {str(p): hashlib.sha256(raw).hexdigest()
                for p, raw in files.items()}, 'backups': {}, 'images': {}}
        save_manifest(manifest)
        for path, raw in files.items():
            atomic(path, raw, 0o755 if path.name == 'module-setup.sh' or path in (HOOK, PREHOOK) else 0o644)
    kernels = sorted(p.name.removeprefix('vmlinuz-') for p in Path('/boot').glob('vmlinuz-*'))
    need(kernels and len(kernels) <= 32 and all(KERNEL.fullmatch(k) for k in kernels),
         'unsupported installed kernel inventory')
    for kernel in kernels:
        image = Path('/boot/initrd.img-' + kernel)
        if kernel in manifest['images'] and sha_file(image) == manifest['images'][kernel]['sha256']:
            continue
        original = archive_entries(image,metadata_payloads=frozenset(('usr/lib/dracut/modules.txt','etc/aegis-initrd-id')))
        rawmodules = original.get('usr/lib/dracut/modules.txt', {}).get('data')
        need(rawmodules is not None, 'original dracut module inventory missing')
        modules = set(rawmodules.decode('ascii').split())
        # The original is used only for module-loss detection, never to admit
        # executable code or unknown candidate paths.
        if manifest.get('policy_upgrade') and kernel in manifest.get('backups', {}):
            backup = manifest['backups'][kernel]
            previous = manifest['policy_upgrade']['from_images'].get(kernel, {})
            need(backup.get('path') == str(BACKUP / (kernel + '.initrd')) and
                 sha_file(Path(backup['path'])) == backup.get('sha256') and
                 sha_file(image) in (previous.get('sha256'), backup.get('sha256')),
                 'upgrading initrd differs from previous image or retained original')
        else:
            backup_image(image, kernel, manifest)
        nonce = os.urandom(32).hex()
        candidate = build_candidate(kernel, nonce=nonce)
        proof = verify_profile(kernel, candidate, nonce=nonce)
        need(set(proof['modules']) - {'aegis-initrd-gate'} == modules - (OMIT | {'aegis-initrd-gate'}),
             'dracut candidate loses non-network modules; original retained')
        manifest['images'][kernel] = {'nonce': nonce, 'sha256': proof['initrd_sha256'],
            'original_sha256': manifest['backups'][kernel]['sha256'],
            'archive_projection_sha256': proof['archive_projection_sha256']}
        # Durable identity precedes the atomic rename; a crash can resume by
        # comparing either original or candidate hash, with backup retained.
        save_manifest(manifest)
        replace_image(candidate, image, proof['initrd_sha256'])
    need(boot_snapshot() == manifest['before'], 'unexpected GRUB/kernel policy mutation')
    manifest['phase'] = 'awaiting_reboot'
    save_manifest(manifest)
    print(json.dumps({'status': 'reboot_required', 'boot_profile': PROFILE,
                      'kernels': len(kernels), 'network_in_initrd': False}))


def uninstall():
    if not MANIFEST.exists():
        need(all(not p.exists() for p in policy_files()), 'orphan initrd policy; guard retained')
        return
    manifest = decode(trusted_read(MANIFEST))
    need(manifest.get('phase') in ('building','awaiting_reboot','active',
         'uninstalling','removed','rolled_back'), 'unknown initrd owner phase')
    # A crash can leave only part of the durable building footprint, and an
    # explicit rollback has already removed its policy files. Both still need
    # ordinary all-kernel regeneration/reverse checks before purge completes.
    verify_ownership(manifest, partial=manifest.get('phase') in
                     ('building','uninstalling','removed','rolled_back'), allow_previous=True)
    if manifest.get('phase')=='removed':
        need(all(not p.exists() and not p.is_symlink() for p in policy_files()),
             'removed initrd owner has unexpected policy residue')
        print(json.dumps({'status':'removed','network_in_initrd_restored':True,
                          'private_backups_retained':True}))
        return
    manifest['phase'] = 'uninstalling'
    save_manifest(manifest)
    # Remove hook first, then gate and drop-in. Keep every original image and
    # all refusal candidates in the private backup until reverse proof closes.
    remove_owned_policy(manifest)
    kernels = sorted(p.name.removeprefix('vmlinuz-') for p in Path('/boot').glob('vmlinuz-*'))
    for kernel in kernels:
        image = Path('/boot/initrd.img-' + kernel)
        candidate = image.with_name('.aegis-restored-' + kernel + '-' + os.urandom(8).hex())
        command('nice', '-n', '10', 'dracut', '--force', '--kver', kernel,
                str(candidate), timeout=300)
        entries = archive_entries(candidate,metadata_payloads=frozenset(('usr/lib/dracut/modules.txt','etc/aegis-initrd-id')))
        need('usr/lib/dracut/modules.txt' in entries and 'etc/aegis-initrd-id' not in entries,
             'normal initrd regeneration did not remove AEGIS policy')
        replace_image(candidate, image, sha_file(candidate))
        refused = Path(str(image) + '.aegis-refused')
        if refused.exists():
            # Retain quarantined images privately, never irreversibly delete.
            os.replace(refused, BACKUP / (kernel + '.refused-' + os.urandom(8).hex()))
    if GRUB_REFUSAL.exists():
        need(trusted_read(GRUB_REFUSAL)==b'# AEGIS refused initrd fallback\nGRUB_DEFAULT=saved\n','foreign fallback default')
        GRUB_REFUSAL.unlink();fsync_dir(GRUB_REFUSAL.parent)
    if manifest.get('grubenv_backup_sha256'):
        raw=trusted_read(BACKUP/'grubenv.before-refusal')
        need(hashlib.sha256(raw).hexdigest()==manifest['grubenv_backup_sha256'],'GRUB recovery backup mismatch')
        atomic('/boot/grub/grubenv',raw,0o600)
    command('update-grub', timeout=60)
    grub = read_config('/boot/grub/grub.cfg')
    need(all(('initrd.img-' + k) in grub for k in kernels), 'GRUB misses regenerated initrd')
    current = boot_snapshot()
    # Generated grub.cfg can change timestamps/order as kernels are installed.
    # Literal administrator defaults and pre-existing policy/hooks must match.
    for path, sha in manifest['before'].items():
        if path not in ('/boot/grub/grub.cfg', '/boot/grub/grubenv'):
            need(current.get(path) == sha, 'reverse boot policy check failed')
    need(all(not p.exists() for p in policy_files()), 'owned initrd policy remains')
    manifest['phase'] = 'removed'
    manifest['restored_boot_id'] = current_boot()
    save_manifest(manifest)
    print(json.dumps({'status': 'removed', 'network_in_initrd_restored': True,
                      'private_backups_retained': True}))


def kernel_preflight(kernel):
    need(KERNEL.fullmatch(kernel), 'invalid hook kernel')
    verify_ownership(decode(trusted_read(MANIFEST)))
    fs=os.statvfs('/boot')
    need(fs.f_bavail*fs.f_frsize>=512<<20,'insufficient boot space before dracut')
    try:
        detect_local_root()
    except (OSError,ValueError,subprocess.SubprocessError):
        manifest=decode(trusted_read(MANIFEST))
        manifest['deny_reason']='root_boot_policy_changed'
        save_manifest(manifest)
        print('AEGIS: local-root policy changed; access remains denied',file=sys.stderr)


def quarantine(kernel, manifest):
    image=Path('/boot/initrd.img-'+kernel)
    good=[]
    for k,record in manifest['images'].items():
        p=Path('/boot/initrd.img-'+k)
        if k!=kernel and p.exists() and Path('/boot/vmlinuz-'+k).exists() and sha_file(p)==record['sha256']:
            good.append(k)
    need(good,'no verified fallback kernel; keep guard and require console recovery')
    chosen=os.uname().release if os.uname().release in good else sorted(good)[-1]
    grub=read_config('/boot/grub/grub.cfg')
    ids=re.findall(r"menuentry [^\n]*['\"](gnulinux-"+re.escape(chosen)+r"-advanced-[A-Za-z0-9-]+)['\"]",grub)
    need(len(ids)==1,'verified fallback GRUB entry is ambiguous')
    suffix=ids[0].split('-advanced-',1)[1]
    submenu='gnulinux-advanced-'+suffix
    need(submenu in grub,'verified fallback submenu missing')
    literal=b'# AEGIS refused initrd fallback\nGRUB_DEFAULT=saved\n'
    if GRUB_REFUSAL.exists():
        need(trusted_read(GRUB_REFUSAL)==literal,'foreign fallback default')
    else:
        atomic(GRUB_REFUSAL,literal,0o644)
    for path in ('/boot/grub/grubenv',):
        backup=BACKUP/'grubenv.before-refusal'
        if not backup.exists():
            atomic(backup,trusted_read(path),0o600)
        manifest['grubenv_backup_sha256']=hashlib.sha256(trusted_read(backup)).hexdigest()
    # Pin the known bootable default before exposing any initrd-less entry.
    command('grub-set-default',submenu+'>'+ids[0])
    if image.exists():
        refused=Path(str(image)+'.aegis-refused')
        if refused.exists():
            os.replace(refused,BACKUP/(kernel+'.refused-'+os.urandom(8).hex()))
        os.replace(image,refused)
        fsync_dir(image.parent)
    manifest['quarantined']=sorted(set(manifest.get('quarantined',[]))|{kernel})
    save_manifest(manifest)
    command('update-grub',timeout=60)
    need(Path('/boot/initrd.img-'+chosen).exists(),'verified fallback image missing')


def kernel_hook(kernel):
    need(KERNEL.fullmatch(kernel), 'invalid hook kernel')
    manifest = decode(trusted_read(MANIFEST))
    verify_ownership(manifest)
    try:
        detector = detect_local_root()
        image = Path('/boot/initrd.img-' + kernel)
        proof = verify_profile(kernel, image)
        manifest['images'][kernel] = {'nonce': proof['build_nonce'],
            'sha256': proof['initrd_sha256'],
            'archive_projection_sha256': proof['archive_projection_sha256']}
        manifest['detector'] = detector
        manifest.pop('deny_reason', None)
        save_manifest(manifest)
    except (OSError, ValueError, subprocess.SubprocessError):
        manifest['deny_reason'] = 'kernel_initrd_unverified'
        save_manifest(manifest)
        # A refused image never remains the default. No unreviewed dracut
        # release can turn a deny-only period into a networked early boot.
        quarantine(kernel,manifest)
        print('AEGIS: kernel initrd quarantined; verified fallback selected; access denied', file=sys.stderr)


def rollback():
    manifest=decode(trusted_read(MANIFEST))
    verify_ownership(manifest,partial=manifest.get('phase') in ('building','uninstalling','rolled_back'),
                     allow_previous=True)
    for kernel,record in manifest['backups'].items():
        backup=Path(record['path'])
        need(backup.parent==BACKUP and sha_file(backup)==record['sha256'],
             'boot rollback backup changed')
        image=Path('/boot/initrd.img-'+kernel)
        candidate=image.with_name('.aegis-rollback-'+kernel+'-'+os.urandom(8).hex())
        fd=os.open(candidate,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as dst,backup.open('rb') as src:
            while chunk:=src.read(1<<20):dst.write(chunk)
            dst.flush();os.fsync(dst.fileno())
        replace_image(candidate,image,record['sha256'])
    remove_owned_policy(manifest)
    manifest['phase']='rolled_back'
    save_manifest(manifest)
    print(json.dumps({'status':'rolled_back','network_in_initrd_restored':True,'private_backups_retained':True}))


def main():
    if sys.argv[1:2] == ['classic-build']:
        need(len(sys.argv) == 4, 'invalid internal classic builder arguments')
        from aegis_initrd_classic import populate_build
        print(json.dumps(populate_build(sys.argv[2], sys.argv[3],
            nonce=os.environ.get('aegis_build_nonce'))))
        return
    if sys.argv[1:2] == ['ldconfig-build']:
        ldconfig_build(sys.argv[2:])
        return
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('detect', 'apply', 'verify', 'uninstall', 'rollback', 'kernel-hook', 'kernel-preflight', 'network-drivers', 'prepare-cloud', 'restore-cloud', 'prepare-classic', 'restore-classic'))
    p.add_argument('kernel', nargs='?')
    p.add_argument('image', nargs='?')
    p.add_argument('--opt-in', action='store_true')
    p.add_argument('--boot', action='store_true')
    p.add_argument('--backend', choices=('dracut', 'classic'))
    a = p.parse_args()
    need(os.geteuid() == 0, 'root required')
    profile_actions = ('apply', 'verify', 'uninstall', 'rollback', 'kernel-hook', 'kernel-preflight')
    need(a.backend is None or a.action in profile_actions, 'backend does not apply to this action')
    selected_profile = CLASSIC_PROFILE if a.backend == 'classic' else PROFILE
    if a.action in profile_actions and MANIFEST.exists():
        selected_owner = owner_profile(decode(trusted_read(MANIFEST)))
        need(a.backend is None or selected_profile == selected_owner, 'explicit backend differs from owner')
        selected_profile = selected_owner
    if a.action in ('detect','verify','network-drivers'):
        # The public detector and boot verifier are strictly read-only, even
        # before any installation directory or transaction lock exists.
        signal.signal(signal.SIGALRM,lambda *_: (_ for _ in ()).throw(TimeoutError('initrd deadline')))
        signal.alarm(45)
        if a.action=='network-drivers':
            print(' '.join(network_driver_names()))
        elif a.action=='detect':
            print(json.dumps(detect_local_root()))
        else:
            image = a.image or '/boot/initrd.img-'+os.uname().release
            signal.alarm(assessment_seconds(image))
            print(json.dumps(verify_profile(a.kernel or os.uname().release,
                image,boot=a.boot,profile=selected_profile)))
        return
    if a.action in ('prepare-cloud', 'restore-cloud'):
        need(a.opt_in, 'explicit --opt-in required: changes the cloud bootstrap dependency')
    if a.action=='apply':
        need(a.opt_in,'explicit --opt-in required: modifies initrd images and requires reboot')
    # Independent of the guard lock: install/uninstall already own InstallLock;
    # kernel package hooks must not concurrently mutate this same boot policy.
    BACKUP.parent.mkdir(parents=True, exist_ok=True)
    for parent in (BACKUP.parent,*BACKUP.parent.parents):
        meta=parent.lstat()
        need(stat.S_ISDIR(meta.st_mode) and meta.st_uid==0 and not meta.st_mode&0o022,
             'untrusted initrd transaction directory')
    fd = os.open(BACKUP.parent / 'initrd-policy.lock',
                 os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'r+b'):
        meta=os.fstat(fd)
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid==0 and meta.st_nlink==1 and
             stat.S_IMODE(meta.st_mode)==0o600,'untrusted initrd transaction lock')
        deadline=time.monotonic()+30
        while True:
            try:
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);break
            except BlockingIOError:
                need(time.monotonic()<deadline,'initrd transaction lock deadline')
                time.sleep(0.05)
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError('initrd deadline')))
        if a.action in ('prepare-classic', 'restore-classic'):
            import aegis_initrd_classic as classic
            signal.alarm(90)
            result = (classic.prepare_overlay(opt_in=a.opt_in) if a.action == 'prepare-classic'
                else classic.restore_overlay(opt_in=a.opt_in))
            print(json.dumps(result))
            return
        if selected_profile == CLASSIC_PROFILE and a.action in profile_actions:
            import aegis_initrd_classic as classic
            if a.action == 'apply':
                result = classic.apply(opt_in=a.opt_in)
            elif a.action == 'uninstall':
                result = classic.uninstall()
            elif a.action == 'rollback':
                result = classic.rollback()
            elif a.action == 'kernel-hook':
                result = classic.kernel_hook(a.kernel)
            else:
                result = classic.kernel_preflight(a.kernel)
            print(json.dumps(result))
            return
        if a.action == 'apply':
            apply(opt_in=a.opt_in)
        elif a.action == 'uninstall':
            uninstall()
        elif a.action == 'kernel-hook':
            kernel_hook(a.kernel)
        elif a.action == 'kernel-preflight':
            kernel_preflight(a.kernel)
        elif a.action == 'rollback':
            rollback()
        elif a.action == 'prepare-cloud':
            signal.alarm(90)
            print(json.dumps(prepare_cloud_dependencies(opt_in=a.opt_in)))
        elif a.action == 'restore-cloud':
            signal.alarm(90)
            print(json.dumps(restore_cloud_dependencies(opt_in=a.opt_in)))



if __name__ == '__main__':
    try:
        main()
    except CloudInitRefusal as error:
        journal_cloud_init_refusal(error)
        print(cloud_init_refusal_json(error), file=sys.stderr)
        raise SystemExit(78)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit('AEGIS initrd policy refused: ' + str(error))
