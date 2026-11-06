# Strict P3 exact-candidate soak harness v3

This is a local, undeployed template for a new node-local P3 attempt. It does
not make fleet changes and does not accept the failed `2cb081bf` r2 interval.

The monitor is append-only. `init` requires a new, absent attempt directory;
each sample has a UUID and is created with `O_EXCL`; `finalize` refuses to
replace `final.json`. A failed or interrupted attempt remains as evidence and a
retry must use a different directory. The final receipt includes a SHA-256 and
byte count for the config, baseline journal cursors, final journal probes, and
every sample file. `sample-chain.jsonl` is an fsynced, hash-linked ledger that
must name every sample exactly once; missing, extra, reordered, noncanonical,
or digest-mismatched samples fail finalization. Finalization also validates each
sample schema, UUID, filename, monotonic interval, complete probe record,
command/timeout contract, stdout/stderr digest and byte count, then recomputes
the assessment instead of trusting the stored result.

Each ledger entry must also have a canonical Ed25519 receipt from an external,
stateful append-only anchor. The anchor maintains the sequence and previous
receipt hash, refuses forks, replays, and backdating, and supplies its own UTC
time. Its private key must be inaccessible to the monitor host and attempt
writer; its retained state and receipts must live in independently administered
WORM or equivalent append-only storage. A local wrapper around a readable
private key is not an acceptable production anchor. Every invocation pins the
independently distributed public key by SHA-256. Finalization verifies every
signature and receipt link and applies the duration and maximum-gap gates to
both host monotonic time and the anchor's trusted time.

Every command probe records its argv, exact stdout and stderr bytes (base64),
their hashes and lengths, exact return code (or `null` on timeout), timeout
state, UTC start and monotonic elapsed nanoseconds. The assessment fails closed
on missing, timed-out, nonzero, malformed, or semantically wrong required
probes.

Acceptance requires all of the following on each declared node:

* at least 86,400 seconds on one boot and at least 1,400 samples;
* no inter-sample gap above the configured ceiling (180 seconds in the example);
* exact candidate path, binary SHA-256, and full Git SHA in `--version` at every sample;
* all declared units active with `NRestarts=0` at every sample;
* unchanged nonzero PIDs for every unit marked `immutable_pid`;
* required TCP and UDP listeners owned by the candidate PID at every sample;
* every configured semantic probe successful with its JSON assertions true;
* zero warning-through-emergency journal entries after the per-unit baseline cursors.

Copy `config.example.json`, replace every placeholder with the final signed
candidate values, and adapt public versus authority units explicitly. For the
authority node, replace the public front/dispatch units and journal list with
`aegis-enrollment-authority.service` as appropriate. Add every live supported
protocol, registry-refresh, resource, or session-health command needed by the
accepted fleet contract as a `semantic_probes` entry. Assertions may use
`json_equals`, exact `stdout_equals`, or a list of `stdout_contains` strings; a
command returning zero without its declared semantic result does not pass.
Empty assertion objects, strings, and lists are rejected during initialization.

Example node-local lifecycle (shown for review only):

```text
monitor.py init --config /root/exact-candidate.json --attempt-dir /var/lib/aegis-v3-soak/ATTEMPT-ID --anchor-command /usr/local/libexec/aegis-p3-anchor --trusted-anchor-public-key /etc/aegis/p3-anchor.pub --trusted-anchor-public-key-sha256 EXACT_SHA256
monitor.py sample --attempt-dir /var/lib/aegis-v3-soak/ATTEMPT-ID --anchor-command /usr/local/libexec/aegis-p3-anchor --trusted-anchor-public-key /etc/aegis/p3-anchor.pub --trusted-anchor-public-key-sha256 EXACT_SHA256
monitor.py finalize --attempt-dir /var/lib/aegis-v3-soak/ATTEMPT-ID --anchor-command /usr/local/libexec/aegis-p3-anchor --trusted-anchor-public-key /etc/aegis/p3-anchor.pub --trusted-anchor-public-key-sha256 EXACT_SHA256
```

Schedule `sample` once per minute and `finalize` only after the 24-hour window
has elapsed. A fleet receipt must subsequently copy and checksum every node's
complete attempt directory and require every node `final.json` to be `PASS`.
