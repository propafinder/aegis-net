# Real cloud-init outputs for the cloud-init boot gate

These files are copied from disposable, network-isolated cloud-init runs made
on 29 October 2026 for the r21 cloud-init design (custody
`r21/design-cloudinit-probes-r1`, manifest `SHA256SUMS` SHA-256
`93d1537941466b1bb1cef52dfdc00993e99530c999da3eb8852d001aa31161b1`).

- `noble-*`: the cached Lima Ubuntu 24.04 `release-20260705` image (image
  digest `7df02015…`), cloud-init `26.1-0ubuntu1~24.04.1`, mounted read-only.
- `resolute-*`: Ubuntu 26.04.1 with cloud-init `26.2-0ubuntu1~26.04.1`.
- `*-disabled-by-marker/status-long.json`: `cloud-init status --long --format
  json` under a real systemd PID 1 after the marker was created as a regular,
  root-owned file. `noble-disabled-by-marker/cloud-init-generator.log` is the
  generator log with the marker present.

`status.json` is `/run/cloud-init/status.json` (the class string lives in its
`v1.datasource`), `instance-data.json` is `/run/cloud-init/instance-data.json`
(it has no `v1.datasource`) and `status-long.json` is the `cloud-init status
--long --format json` output.

The only edit: in the `s3b`/`s4b` NoCloudNet scenarios the loopback seed
address was replaced by `seed.invalid`, so the files keep the `http://` and
`ftp://` seed shapes without a literal IP address. Every other byte is the
probe output.
