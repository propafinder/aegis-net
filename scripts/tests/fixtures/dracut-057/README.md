# Public dracut057 test inputs

These are unmodified public RPM-matching network activation guard files from AlmaLinux dracut-network-057-110.git20260130.el9. They are test data only and are never sourced/executed by the contracts or included in the public client runtime payload. The production parser compares their reviewed SHA256 values in addition to local RPM integrity.

Upstream: https://github.com/dracutdevs/dracut/tree/057/modules.d/35network-manager
Distribution: https://git.almalinux.org/rpms/dracut
Public package evidence: evidence-archive/security/2026-09-11/dracut-boot-assessment/alma-public-network-sources.json.

The included COPYING and lgpl-2.1.txt retain the package's licensing notices. The shell files carry their original license markers.

Generic-cloud hooks and device-mapper rule fixtures in 03modsign, 90crypt, 90dm,
95lunmask and 95virtfs are unmodified public dracut-057-117.git20260625.el9_8
files collected from the isolated AlmaLinux 9.8 image. SHA256 values of the
initial eight hooks match the guest package source collection. They are never executed
by tests. The production profile excludes crypttab, LUKS command-line activation,
module-signing key payloads and ndctl TPM inputs; encrypted-root support is not
claimed. The upstream cryptsetup generator review used systemd v252
(src/cryptsetup/cryptsetup-generator.c): its inputs are crypttab and the kernel
command line, both bounded by the production parser.

crypt-run-generator and the two FC/SAS scan helpers are also included as
public fixtures and pinned in production. The local-root profile blocks their
custom activation inputs.
