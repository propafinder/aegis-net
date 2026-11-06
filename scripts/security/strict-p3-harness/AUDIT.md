# Audit of the retained r2 attempt

The retained evidence does **not** pass strict P3 and must not be reused for a
new candidate. The reconciliation receipt reports:

| node | duration (s) | samples | failed samples | max gap (s) | PID final=baseline | warning/error rows |
|---|---:|---:|---:|---:|---|---:|
| origin | 86712.424697 | 1429 | 4 | 61.482974 | yes | 0 |
| r77 | 86703.828045 | 1428 | 5 | 61.404008 | yes | 0 |
| relay-c | 86704.123330 | 1428 | 0 | 61.380838 | yes | 0 |
| extra | 143103.388713 | 2366 | 28 | 61.874853 | yes | 0 |

Every retained failed row is labelled only `policy_read`. The bounded
2026-10-03 diagnostic provides stronger failure evidence: `extra` returned
exit code 1 with normalized stderr `Error: device_policy_registry_unavailable`
in 2 of 60 probes (indices 0 and 45).
Origin, r77, and relay-c had zero failures in that bounded window. That diagnostic
is useful causal evidence, but its own scope explicitly says it is not 24-hour
acceptance and it cannot repair the historical failed samples.

The old r2 monitor did enforce the main numeric and runtime checks: 86,400
seconds, 1,400 samples, 180-second maximum gap, exact executable path and hash,
live policy source, `NRestarts=0`, candidate-owned TCP and UDP listeners,
baseline/final PID equality, and an empty warning-through-emergency journal
query. Its fail result is therefore authoritative.

The following evidence weaknesses motivated v3:

* the command helper returned stripped stdout only; return code, exact stderr,
  elapsed time, timeout details, and malformed output were reduced to generic
  labels such as `policy_read`;
* `samples.jsonl` was appended without an inter-process lock or one-file
  atomicity, while `final.json` used replacing writes;
* duration and journal boundaries depended on wall-clock timestamps instead of
  a same-boot monotonic interval and journal cursors;
* only baseline and final PIDs were compared, rather than proving every sampled
  PID remained the same;
* journal output was truncated to 500 characters per line and a failed journal
  command could be indistinguishable from an empty result;
* no manifest bound every sample and journal artifact into the final receipt;
* supported protocol, session/resource, and registry-refresh semantics were
  not configurable acceptance probes.

The v3 template addresses those recording and evaluation weaknesses. It is
intentionally undeployed and contains no claim that the current checkout,
`2cb081bf`, or any later source is the final signed candidate.
