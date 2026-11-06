#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${ROOT}/scripts/windows/run-windows-wide-service-reboot-proof.ps1"
WINCTL="${ROOT}/tools/windows/aegis-winctl/src/main.rs"

grep -q "aegis-winctl" "${SCRIPT}"
grep -q "proof service-reboot" "${SCRIPT}"

grep -q "BLOCKED_BY_NON_ELEVATED_TERMINAL" "${WINCTL}"
grep -q "BLOCKED_BY_REBOOT_NOT_PERFORMED" "${WINCTL}"
grep -q "service_started_after_reboot" "${WINCTL}"
grep -q "runtime_events_restarted" "${WINCTL}"
grep -q "wfp_reconfigured_after_reboot" "${WINCTL}"
grep -q "controlled_tcp_wfp_proof_after_reboot" "${WINCTL}"
grep -q "relay_egress_after_reboot" "${WINCTL}"
grep -q "broad_capture_claim" "${WINCTL}"
grep -q "dns_capture_claim" "${WINCTL}"
grep -q "udp_capture_claim" "${WINCTL}"
grep -q "ipv6_capture_claim" "${WINCTL}"
grep -q "No reboot is performed automatically" "${WINCTL}"

echo "ok"
