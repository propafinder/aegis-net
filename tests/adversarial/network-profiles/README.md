# Declared adversarial network conditions

`clean-fiber.sh`, `congested-wifi.sh`, `corporate-middlebox.sh` and `mobile-lossy.sh` print profile labels and declared latency/loss/reordering/bandwidth parameters. They currently contain no `tc`, netem, firewall or interface mutation. Their names are fixture categories, not measured descriptions of a live network.

These executable text fixtures can be invoked with Bash to inspect their declaration, but that output does not apply the stated impairment. The actual gateway/controller must establish and observe any live conditions before a result is classified as such. Do not convert printed parameters directly into proof that a test ran under loss or congestion.

The [parent testbed](../README.md) explains dry-run versus live-command behavior. Match profile labels with the selected scenario and retain actual gateway setup/cleanup evidence. This directory supplies no provider credentials, device identity, target-network availability or DPI-resistance guarantee.
