# R75 XPC custody diagnostic target

Run `make check` on macOS. This target compiles one copy of the dormant R66
signed-peer gate and R67 physical-reap owner against the real SDK, then runs a
bounded, inert child fixture with a scratch file lock. The absent XPC service's
peer EUID is mocked only in the direct-call test translation unit; the two
standalone objects use the real XPC API. All temporary files are unique and
removed by `run.sh`.

The gate has **no public dictionary-taking terminal function**. The only
diagnostic terminal call asks the same helper-owned child object for its
one-shot dictionary after exact `waitpid`, then checks R66's connection,
EUID, epoch, digest and nonces. Stop request, timeout, `ESRCH`, peer loss and
synthetic dictionaries cannot substitute for a physical reap. This target
has no runtime or Apple callback caller, FACTORY, Store, H2/ACK, packet flow,
signed installed helper/child, entitlement proof or notarization claim.

The test child path is caller supplied **only in this diagnostic target**.
Product code must resolve a fixed signed bundle executable and separately
verify its own App Group claim before any actual Store use. The public Ready
parser is protocol consistency only; the inert ready fixture is never a
product grant. B-06 remains NO-GO.
