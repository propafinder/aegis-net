#!/usr/bin/env bash
# Offline actual provenance consumers with inert payloads; no native acceptance.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
exec python3 -I "$ROOT/scripts/test_shipping_client_inventory_consumers.py"
