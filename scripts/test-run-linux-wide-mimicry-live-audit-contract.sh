#!/usr/bin/env bash
# Contract for the Linux wide mimicry live audit helper.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/run-linux-wide-mimicry-live-audit.sh"
MANIFEST_HELPER="${ROOT}/scripts/build-linux-wide-live-audit-manifest.sh"
STATUS_SCRIPT="${ROOT}/scripts/linux-wide-live-audit-handoff-status.sh"
tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/aegis-live-audit-contract.XXXXXX")"
trap 'rm -rf "${tmpdir}"' EXIT

# Independent fixture expectation is selected before reported artifacts.
cat > "${tmpdir}/expected-topology.json" <<'TOPOLOGY'
{"schema":"aegis_linux_live_expected_topology_v1","server_host":"192.0.2.10","client_host":"192.0.2.20","relay_address":"192.0.2.10:8443"}
TOPOLOGY
chmod 600 "${tmpdir}/expected-topology.json"

client_audit_script="${tmpdir}/client-audit.sh"
server_audit_script="${tmpdir}/server-audit.sh"
output_path="${tmpdir}/stdout.txt"
output_dir="${tmpdir}/artifacts"
server_key="${tmpdir}/server.key"
client_key="${tmpdir}/client.key"
phase_b_baseline_json="${tmpdir}/phase-b-baseline-review.json"

: > "${server_key}"
: > "${client_key}"
cat > "${phase_b_baseline_json}" <<'EOF'
{
  "artifact_schema": "phase_b_baseline_review_v1",
  "status": "BASELINE_READY",
  "phase_b_entry_status": "ENTRY_READY",
  "phase_b_exit_status": "EXIT_NOT_CLAIMED",
  "checks": []
}
EOF

cat > "${client_audit_script}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "client audit"
EOF

cat > "${server_audit_script}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "server audit"
EOF

/bin/bash "${SCRIPT}" \
  --server-host 192.0.2.10 \
  --client-host 192.0.2.20 \
  --ssh-user root \
  --server-name 192.0.2.10 \
  --relay-address 192.0.2.10:8443 \
  --output-dir "${output_dir}" \
  --server-private-key-path "${server_key}" \
  --client-private-key-path "${client_key}" \
  --server-audit-script "${server_audit_script}" \
  --client-audit-script "${client_audit_script}" \
  --remote-client-pcap /tmp/live-audit/wire.pcapng \
  --phase-b-baseline-json "${phase_b_baseline_json}" \
  --phase-b-runtime-evidence-strict \
  --dry-run > "${output_path}"

for expected in \
  "Redeploy server and client from a clean purge" \
  "Two-VPS redeploy flow completed" \
  "Run server live audit script" \
  "Run client live audit script" \
  "Collect client runtime and service artifacts" \
  "Harvest transient relay wire runtime" \
  "Download remote witness capture" \
  "Build local witness summary from downloaded pcap" \
  "Compose wire helper runtime matrix input" \
  "Materialize local wire acceptance summary" \
  "Materialize local stealth live acceptance bundle" \
  "Materialize Phase B runtime evidence bundle" \
  "Write local audit manifest" \
  "ssh -i " \
  "scp -i " \
  "runtime-events.jsonl" \
  "transient-relay-wire-runtime-events.jsonl" \
  "wire-helper-runtime-events.jsonl" \
  "wire-witness-summary.json" \
  "wire-host-helper.stdout.json" \
  "manifest will summarize wire acceptance" \
  "wire-host-acceptance-summary.json" \
  "live-audit-summary.md" \
  "live-audit-handoff-status.json" \
  "manifest will link markdown summary" \
  "rerun command:" \
  "manifest will publish blocker-aware next action commands" \
  "manifest will publish next action artifact paths" \
  "manifest will publish unified next_action object" \
  "manifest will publish compact next_action context" \
  "manifest will publish canonical operator handoff object" \
  "scripts/run-linux-wide-mimicry-live-audit.sh" \
  "stealth-live-acceptance-bundle.json" \
  "stealth-live-acceptance.manifest.json" \
  "manifest will summarize stealth bundle" \
  "phase-b-runtime-evidence.manifest.json" \
  "phase-b-master-plan-status.json" \
  "phase-b master plan status will be written" \
  "live-audit.manifest.json" \
  "$(realpath "${output_dir}")/live-audit.manifest.json"; do
  grep -Fq "${expected}" "${output_path}"
done

expected_rerun_command="bash scripts/run-linux-wide-mimicry-live-audit.sh --server-host 192.0.2.10 --client-host 192.0.2.20 --ssh-user root --server-name 192.0.2.10 --relay-address 192.0.2.10:8443 --output-dir ${output_dir} --server-private-key-path ${server_key} --client-private-key-path ${client_key} --bootstrap-url https://github.com/propafinder/aegis-release/releases/latest/download/bootstrap-install.sh --client-audit-script ${client_audit_script} --server-audit-script ${server_audit_script} --remote-client-pcap /tmp/live-audit/wire.pcapng --remote-runtime-events /var/log/aegis-client/runtime-events.jsonl --relay-transport-priority https_ws\\,grpc_stream\\,legacy_tls\\,masque_derived --phase-b-baseline-json ${phase_b_baseline_json} --phase-b-runtime-evidence-strict"
grep -Fq "[dry-run] rerun command: ${expected_rerun_command}" "${output_path}"

expected_review_summary_command="sed -n 1\\,160p $(realpath "${output_dir}")/live-audit-summary.md"
expected_review_manifest_command="cargo run -q --manifest-path ${ROOT}/Cargo.toml -p aegis-measure -- pretty-json --input $(realpath "${output_dir}")/live-audit.manifest.json"
expected_review_handoff_status_command="cargo run -q --manifest-path ${ROOT}/Cargo.toml -p aegis-measure -- pretty-json --input $(realpath "${output_dir}")/live-audit-handoff-status.json"
grep -Fq "[dry-run] review summary command: ${expected_review_summary_command}" "${output_path}"
grep -Fq "[dry-run] review manifest command: ${expected_review_manifest_command}" "${output_path}"
grep -Fq "[dry-run] review handoff status command: ${expected_review_handoff_status_command}" "${output_path}"

cat > "${tmpdir}/wire-green.json" <<'EOF'
{
  "artifact_schema": "wire_mimicry_host_acceptance_v1",
  "product_verdict": "green",
  "acceptance_status": "passed",
  "hostile_path_support_ready": true,
  "independent_witness_correlation_status": "matched"
}
EOF

cat > "${tmpdir}/wire-blocked.json" <<'EOF'
{
  "artifact_schema": "wire_mimicry_host_acceptance_v1",
  "product_verdict": "yellow",
  "acceptance_status": "needs_witness",
  "hostile_path_support_ready": false,
  "independent_witness_correlation_status": "missing"
}
EOF

cat > "${tmpdir}/stealth-green.json" <<'EOF'
{
  "artifact_schema": "stealth_live_acceptance_bundle_v1",
  "bundle_verdict": "green",
  "bundle_status": "acceptance_green",
  "next_action": "collect_next_live_validation_slice",
  "primary_blocker": null,
  "active_blockers": []
}
EOF

cat > "${tmpdir}/stealth-blocked.json" <<'EOF'
{
  "artifact_schema": "stealth_live_acceptance_bundle_v1",
  "bundle_verdict": "yellow",
  "bundle_status": "blocked_on_runtime_relay_surface_evidence",
  "next_action": "inspect_runtime_relay_surface_evidence",
  "primary_blocker": {
    "id": "runtime_relay_surface_evidence"
  },
  "active_blockers": [
    {
      "id": "runtime_relay_surface_evidence"
    }
  ]
}
EOF

cat > "${tmpdir}/preflight.json" <<'EOF'
{
  "artifact_schema": "client_preflight_v1",
  "verdict": "ok",
  "listen_addr": "127.0.0.1:0"
}
EOF

cat > "${tmpdir}/startup.json" <<'EOF'
{
  "artifact_schema": "client_startup_probe_v1",
  "status": "started",
  "relay_address": "192.0.2.10:8443"
}
EOF

cat > "${tmpdir}/wire-helper.stdout.json" <<'EOF'
{
  "artifact_schema": "wire_helper_stdout_v1",
  "verdict": "green",
  "helper": "validate-mimicry-wire-host"
}
EOF

cat > "${tmpdir}/wire-witness-summary.json" <<'EOF'
{
  "artifact_schema": "wire_witness_summary_v1",
  "capture_status": "matched",
  "packets_observed": 12
}
EOF

cat > "${tmpdir}/stealth-live-acceptance.manifest.json" <<'EOF'
{
  "artifact_schema": "stealth_live_acceptance_manifest_v1",
  "bundle_json": "/tmp/stealth-live-acceptance-bundle.json",
  "status": "materialized"
}
EOF

cat > "${tmpdir}/runtime-events.jsonl" <<'EOF'
{"event":"client_started","relay_address":"192.0.2.10:8443"}
{"event":"surface_profile_selected","profile":"browser_balanced"}
EOF

cat > "${tmpdir}/transient-runtime-events.jsonl" <<'EOF'
{"event":"transient_wire_probe","stage":"connect"}
{"event":"transient_wire_probe","stage":"settled"}
EOF

cat > "${tmpdir}/wire-helper-runtime-events.jsonl" <<'EOF'
{"event":"wire_helper_started","helper":"validate-mimicry-wire-host"}
{"event":"wire_helper_finished","verdict":"green"}
EOF

touch "${tmpdir}/wire.pcapng"

dryrun_rerun_command="bash scripts/run-linux-wide-mimicry-live-audit.sh --server-host 192.0.2.10 --client-host 192.0.2.20 --ssh-user root --server-name 192.0.2.10 --relay-address 192.0.2.10:8443 --output-dir ${output_dir} --server-private-key-path ${server_key} --client-private-key-path ${client_key} --bootstrap-url https://github.com/propafinder/aegis-release/releases/latest/download/bootstrap-install.sh --client-audit-script ${client_audit_script} --server-audit-script ${server_audit_script} --remote-client-pcap /tmp/live-audit/wire.pcapng --remote-runtime-events /var/log/aegis-client/runtime-events.jsonl --relay-transport-priority https_ws\\,grpc_stream\\,legacy_tls\\,masque_derived --phase-b-baseline-json ${phase_b_baseline_json} --phase-b-runtime-evidence-strict"
stealth_rerun_command="bash scripts/run-linux-wide-mimicry-live-audit.sh --server-host 192.0.2.10 --client-host 192.0.2.20 --ssh-user root --server-name 192.0.2.10 --relay-address 192.0.2.10:8443 --output-dir ${tmpdir}/stealth --server-private-key-path ${server_key} --client-private-key-path ${client_key} --server-audit-script ${server_audit_script} --client-audit-script ${client_audit_script} --remote-client-pcap /tmp/live-audit/wire.pcapng"
wire_rerun_command="bash scripts/run-linux-wide-mimicry-live-audit.sh --server-host 192.0.2.10 --client-host 192.0.2.20 --ssh-user root --server-name 192.0.2.10 --relay-address 192.0.2.10:8443 --output-dir ${tmpdir}/wire --server-private-key-path ${server_key} --client-private-key-path ${client_key} --server-audit-script ${server_audit_script} --client-audit-script ${client_audit_script}"
green_rerun_command="bash scripts/run-linux-wide-mimicry-live-audit.sh --server-host 192.0.2.10 --client-host 192.0.2.20 --ssh-user root --server-name 192.0.2.10 --relay-address 192.0.2.10:8443 --output-dir ${tmpdir}/green --server-private-key-path ${server_key} --client-private-key-path ${client_key} --server-audit-script ${server_audit_script} --client-audit-script ${client_audit_script}"

bash "${MANIFEST_HELPER}" \
  --manifest "${tmpdir}/stealth/live-audit.manifest.json" \
  --output-dir "${tmpdir}/stealth" \
  --server-host 192.0.2.10 \
  --client-host 192.0.2.20 \
  --relay-address 192.0.2.10:8443 \
  --runtime-events "${tmpdir}/runtime-events.jsonl" \
  --preflight "${tmpdir}/preflight.json" \
  --startup-probe "${tmpdir}/startup.json" \
  --wire-helper-stdout "${tmpdir}/wire-helper.stdout.json" \
  --witness-summary "${tmpdir}/wire-witness-summary.json" \
  --witness-pcap "${tmpdir}/wire.pcapng" \
  --transient-runtime-events "${tmpdir}/transient-runtime-events.jsonl" \
  --wire-helper-runtime-events "${tmpdir}/wire-helper-runtime-events.jsonl" \
  --wire-acceptance-summary "${tmpdir}/wire-green.json" \
  --stealth-live-acceptance-bundle "${tmpdir}/stealth-blocked.json" \
  --stealth-live-acceptance-manifest "${tmpdir}/stealth-live-acceptance.manifest.json" \
  --rerun-command "${stealth_rerun_command}" \
  --review-summary-command "sed -n '1,160p' ${tmpdir}/stealth/live-audit-summary.md" \
  --review-manifest-command "cargo run -q --manifest-path ${ROOT}/Cargo.toml -p aegis-measure -- pretty-json --input ${tmpdir}/stealth/live-audit.manifest.json"
bash "${STATUS_SCRIPT}" \
  --manifest "${tmpdir}/stealth/live-audit.manifest.json" \
  --output "${tmpdir}/stealth/live-audit-handoff-status.json"

bash "${MANIFEST_HELPER}" \
  --manifest "${tmpdir}/wire/live-audit.manifest.json" \
  --output-dir "${tmpdir}/wire" \
  --server-host 192.0.2.10 \
  --client-host 192.0.2.20 \
  --relay-address 192.0.2.10:8443 \
  --runtime-events "${tmpdir}/runtime-events.jsonl" \
  --preflight "${tmpdir}/preflight.json" \
  --startup-probe "${tmpdir}/startup.json" \
  --wire-helper-stdout "${tmpdir}/wire-helper.stdout.json" \
  --witness-summary "" \
  --witness-pcap "" \
  --transient-runtime-events "${tmpdir}/transient-runtime-events.jsonl" \
  --wire-helper-runtime-events "${tmpdir}/wire-helper-runtime-events.jsonl" \
  --wire-acceptance-summary "${tmpdir}/wire-blocked.json" \
  --stealth-live-acceptance-bundle "${tmpdir}/stealth-green.json" \
  --stealth-live-acceptance-manifest "${tmpdir}/stealth-live-acceptance.manifest.json" \
  --rerun-command "${wire_rerun_command}" \
  --review-summary-command "sed -n '1,160p' ${tmpdir}/wire/live-audit-summary.md" \
  --review-manifest-command "cargo run -q --manifest-path ${ROOT}/Cargo.toml -p aegis-measure -- pretty-json --input ${tmpdir}/wire/live-audit.manifest.json"
bash "${STATUS_SCRIPT}" \
  --manifest "${tmpdir}/wire/live-audit.manifest.json" \
  --output "${tmpdir}/wire/live-audit-handoff-status.json"

bash "${MANIFEST_HELPER}" \
  --manifest "${tmpdir}/green/live-audit.manifest.json" \
  --output-dir "${tmpdir}/green" \
  --server-host 192.0.2.10 \
  --client-host 192.0.2.20 \
  --relay-address 192.0.2.10:8443 \
  --runtime-events "${tmpdir}/runtime-events.jsonl" \
  --preflight "${tmpdir}/preflight.json" \
  --startup-probe "${tmpdir}/startup.json" \
  --wire-helper-stdout "${tmpdir}/wire-helper.stdout.json" \
  --witness-summary "" \
  --witness-pcap "" \
  --transient-runtime-events "${tmpdir}/transient-runtime-events.jsonl" \
  --wire-helper-runtime-events "${tmpdir}/wire-helper-runtime-events.jsonl" \
  --wire-acceptance-summary "${tmpdir}/wire-green.json" \
  --stealth-live-acceptance-bundle "${tmpdir}/stealth-green.json" \
  --stealth-live-acceptance-manifest "${tmpdir}/stealth-live-acceptance.manifest.json" \
  --rerun-command "${green_rerun_command}" \
  --review-summary-command "sed -n '1,160p' ${tmpdir}/green/live-audit-summary.md" \
  --review-manifest-command "cargo run -q --manifest-path ${ROOT}/Cargo.toml -p aegis-measure -- pretty-json --input ${tmpdir}/green/live-audit.manifest.json"
bash "${STATUS_SCRIPT}" \
  --manifest "${tmpdir}/green/live-audit.manifest.json" \
  --output "${tmpdir}/green/live-audit-handoff-status.json"

mkdir -p "${output_dir}/client" "${output_dir}/stealth-live-acceptance"
cp "${tmpdir}/runtime-events.jsonl" "${output_dir}/client/runtime-events.jsonl"
cp "${tmpdir}/preflight.json" "${output_dir}/client/preflight.json"
cp "${tmpdir}/startup.json" "${output_dir}/client/startup-probe.json"
cp "${tmpdir}/wire-helper.stdout.json" "${output_dir}/client/wire-host-helper.stdout.json"
cp "${tmpdir}/wire-witness-summary.json" "${output_dir}/client/wire-witness-summary.json"
cp "${tmpdir}/wire.pcapng" "${output_dir}/client/wire-witness-capture.pcapng"
cp "${tmpdir}/transient-runtime-events.jsonl" "${output_dir}/client/transient-relay-wire-runtime-events.jsonl"
cp "${tmpdir}/wire-helper-runtime-events.jsonl" "${output_dir}/client/wire-helper-runtime-events.jsonl"
cp "${tmpdir}/wire-green.json" "${output_dir}/client/wire-host-acceptance-summary.json"
cp "${tmpdir}/stealth-green.json" "${output_dir}/stealth-live-acceptance/stealth-live-acceptance-bundle.json"
cp "${tmpdir}/stealth-live-acceptance.manifest.json" "${output_dir}/stealth-live-acceptance/stealth-live-acceptance.manifest.json"

bash "${MANIFEST_HELPER}" \
  --manifest "${output_dir}/live-audit.manifest.json" \
  --output-dir "${output_dir}" \
  --server-host 192.0.2.10 \
  --client-host 192.0.2.20 \
  --relay-address 192.0.2.10:8443 \
  --runtime-events "${output_dir}/client/runtime-events.jsonl" \
  --preflight "${output_dir}/client/preflight.json" \
  --startup-probe "${output_dir}/client/startup-probe.json" \
  --wire-helper-stdout "${output_dir}/client/wire-host-helper.stdout.json" \
  --witness-summary "${output_dir}/client/wire-witness-summary.json" \
  --witness-pcap "${output_dir}/client/wire-witness-capture.pcapng" \
  --transient-runtime-events "${output_dir}/client/transient-relay-wire-runtime-events.jsonl" \
  --wire-helper-runtime-events "${output_dir}/client/wire-helper-runtime-events.jsonl" \
  --wire-acceptance-summary "${output_dir}/client/wire-host-acceptance-summary.json" \
  --stealth-live-acceptance-bundle "${output_dir}/stealth-live-acceptance/stealth-live-acceptance-bundle.json" \
  --stealth-live-acceptance-manifest "${output_dir}/stealth-live-acceptance/stealth-live-acceptance.manifest.json" \
  --rerun-command "${dryrun_rerun_command}" \
  --review-summary-command "sed -n '1,160p' ${output_dir}/live-audit-summary.md" \
  --review-manifest-command "cargo run -q --manifest-path ${ROOT}/Cargo.toml -p aegis-measure -- pretty-json --input ${output_dir}/live-audit.manifest.json"
bash "${STATUS_SCRIPT}" \
  --manifest "${output_dir}/live-audit.manifest.json" \
  --output "${output_dir}/live-audit-handoff-status.json"

cargo run -q -p aegis-measure -- linux-wide-live-audit-manifest-contract-check \
  --manifest "${tmpdir}/stealth/live-audit.manifest.json" \
  --manifest "${tmpdir}/wire/live-audit.manifest.json" \
  --manifest "${tmpdir}/green/live-audit.manifest.json" \
  --manifest "${output_dir}/live-audit.manifest.json"

cargo run -q -p aegis-measure -- linux-wide-live-audit-materialized-contract-check \
  --expected-topology-file "${tmpdir}/expected-topology.json" \
  --dry-run-output "${output_path}" \
  --stealth-manifest "${tmpdir}/stealth/live-audit.manifest.json" \
  --wire-manifest "${tmpdir}/wire/live-audit.manifest.json" \
  --green-manifest "${tmpdir}/green/live-audit.manifest.json" \
  --dry-run-manifest "${output_dir}/live-audit.manifest.json"

echo "PASS: Linux wide mimicry live audit helper contract"
