#!/usr/bin/env bash
# Shared stable exit codes for smoke helpers.
# Keep these values stable so shell automation can branch on them without
# parsing human-readable error text.

EXIT_PREFLIGHT_LISTENER_CONFLICT=20
EXIT_PREFLIGHT_LISTENER_BUSY=21
EXIT_PREFLIGHT_UNSUPPORTED_ADAPTER=22
EXIT_PREFLIGHT_NEEDS_CAP_NET_ADMIN=23
EXIT_PREFLIGHT_SOCKS_BIND_FAILED=24
EXIT_PREFLIGHT_ROLLOUT_PREREQUISITES=25

# Post-start/runtime failures begin at 30 to keep them separate from
# preflight remediation exits and easier to classify in automation.
EXIT_RUNTIME_CLIENT_EXITED_EARLY=30
EXIT_RUNTIME_WIDE_BACKEND_NOT_READY=31
EXIT_RUNTIME_SMOKE_REQUEST_FAILED=32
