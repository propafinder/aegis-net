# Linux offline intake verifier (not a signing lane)

`verify-linux-offline-release-intake.py` is a read-only policy/digest admission
step for a purpose-built, unsigned ZIP handoff. It cannot sign or publish, has no
GitHub transport, never builds or runs candidate files, and emits `INTAKE_ONLY`.
It does not change the hosted gate. Repository-level credentials and independent
custody remain owner dependencies; a successful inert test does not accept a
real release, reviewer consent, isolated key custody or an installed outcome.

## Independent installation and pins

An independent reviewer must freeze all `BUNDLE_FILES` from reviewed source into
a dedicated directory outside any Git checkout, with each file read-only. The
bundle includes the actual hosted workflow, existing source CI checker, existing
bounded public/operator archive verifier, its inventory dependency, bootstrap
anchor source, and intake script. The verifier executes only the hashed in-memory
helper bytes and the exact hashed hosted policy fragment in an isolated child.
It refuses mutable bundles, checkout execution and independently pinned bundle
mismatch. Run using `python3 -I /installed/path/scripts/verify-linux-offline-release-intake.py`.
Read-only modes are an additional guard, not a custody boundary against the host
owner. Installation, review and pin delivery must occur independently of the
producer and candidate.

The bundle hash uses sorted relative file names, and an unsigned 8-byte big-endian
length before each name and each payload, concatenated into SHA256. Obtain this
hash independently from the installed reviewed bundle; never accept a hash
provided inside the handoff or automatically trust current HEAD. The inert test
calls `frozen_bundle` and demonstrates the exact format.

All arguments are required:

- `--transport`: one bounded single-link regular ZIP, at most 8 GiB.
- `--record`, `--approval`, `--ledger`: separate bounded regular JSON records,
  provided by their external custodians, with duplicate/unknown schema keys refused.
- `--expected-record-sha256`, `--expected-approval-sha256`,
  `--expected-ledger-sha256`: independent hashes of those exact bytes.
- `--expected-verifier-sha256`: independently accepted installed bundle hash.
- `--trust-anchor`: independently held public PEM, exact bytes matching the
  reviewed bootstrap Ed25519 anchor. No private key argument is supported.
- `--output`: a new, exclusive private receipt directory; retries need new names.

The trusted record includes the complete bounded CI run listing for exact main
source, latest-attempt jobs, and reread current run. Existing CI admission selects
the latest qualifying run and requires all five successful jobs. The record
also pins exact successful main release builder ID/attempt, tag, source, created
time, client schema/features, transport digest, file digests, author/last pusher
and capture time. The approval binds those record bytes, verifier, ledger, public
anchor and every final file digest. Reviewer identity must differ from author
and last pusher. Captures and approvals expire within one hour. This is a check
of externally pinned evidence, not authentication of GitHub captures or human
identities; custody must establish their authenticity before any real use.

## Supported handoff and boundary

The ZIP is exactly 13 regular leaf files: four final canonical policy-bearing
Linux manifests, x86_64/aarch64 public client and private operator bundles, each
architecture's private research archive and detached research manifest, and
`bootstrap-install.sh`. Detached research manifest names are
`aegis-research-VERSION-linux-ARCH.manifest.json`; they bind to the existing nested
`research.manifest.json` digest without executing or extracting research code.
The producer can package these exact final policy-bearing bytes from one flat
staging directory with `python3 -I scripts/build-linux-offline-intake-transport.py
--source-dir /path/to/final-files --tag vX.Y.Z-rc.N --output
/path/to/new-transport.zip`. The exporter requires one matching source and
policy across all four manifests, checks each referenced bundle, bootstrap and
research digest, refuses links and existing output, and prints a `PRODUCER_ONLY`
hash inventory. Its output is only a candidate transport; a separate custodian
must obtain and pin the bytes independently, authenticate the external records,
and issue approval. The current hosted workflow does not automatically create
this final unsigned handoff. A real hosted producer run, independent custody and
approval-preparation procedure are still missing.

A bounded snapshot is taken once, verified against the independently approved
hashes, and retained without executable mode. The exact existing hosted source,
role, architecture and 30-day freshness policy validator must reproduce identical
manifest bytes. A rerun cannot refresh creation time or change policy bytes at
its existing sequence. The existing archive verifier checks nested source,
binaries/checksums and the public client allowlist; source/operator leakage in
the public archive refuses admission. Bootstrap and research digests are bound.
Current public v3 shipping inventory and its producer bindings are required;
legacy v1/v2 schema downgrade refuses admission. Operator client path and hash
must match its actual file, and public/operator client bytes and device guard
must agree separately on each architecture. ZIP central directory metadata is
bounded before parsing, including consistent ZIP64/legacy end records.
Before any `tarfile` consumer, every nested bundle/research archive also passes
a raw structural preflight: exactly one gzip member, only regular/directory
USTAR or basic GNU headers, at most 4096 total headers including directories,
512 MiB per regular file, 2 GiB total decompressed bytes including headers and
padding, unique canonical paths under the expected root, checked header sums,
zero body padding and a two-block terminator with at most 10 KiB zero padding.
PAX local/global, GNU longname/longlink/sparse, links, base-256 numbers,
concatenated gzip streams and nonzero/truncated/ambiguous trailers are refused.
These intentional parser restrictions can refuse otherwise valid producer
archives. The private Linux operator/research producer in
`scripts/build-release-bundle.sh` now requests USTAR explicitly for both
archives, because its default GNU tar dialect can emit LongLink records that
this intake must refuse. The current staged operator and research paths fit
USTAR; future path additions must retain that property or fail packaging.
This source correction and inert archive tests do not replace a real Linux
producer compatibility run before acceptance. The public client producer has
a separate Rust archive builder. It now checks every staged path against
USTAR before creating output and writes those prevalidated headers without a
GNU LongLink fallback. Seventeen local delivery tests passed on Darwin arm64,
including an overlong-path refusal; actual Linux producer output remains
unverified.
This first intake does **not** admit all additional operator deb/package-root
artifacts, inspect private research archive contents, prove compiler features,
perform an OPSEC sweep of arbitrary payload contents, or replace private research,
Windows/macOS and installed/endurance acceptance.

The independent ledger supplies authority, positive sequence floor and prior
four-manifest hashes. Lower sequence and same-sequence different manifest bytes
are refused. The intake never advances that ledger or proves it is append-only.
A signing custodian must independently enforce durable sequence admission before
signing. A receipt does not authorize signing or publication, and must not be
connected to the hosted credential step as an approval bypass.

The total verifier budget is 120 seconds, with 30 seconds for the frozen hosted
policy check. Post-snapshot failures retain a sanitized `failure.json` and bytes;
preflight refusal emits a sanitized error and creates no output directory.
No approval contents or secret values are printed. Examples of the complete
record/approval/ledger JSON schemas are in the inert regression test. Run it with
`python3 -I scripts/test-linux-offline-release-intake.py`; it uses no network,
signing keys, signatures or executable candidates.
