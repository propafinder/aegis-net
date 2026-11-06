#!/usr/bin/env bash
# Test-only staging for explicitly selected, locally built smoke executables.
# Production root-state validation and installed-client selection are unchanged.
AEGIS_SMOKE_ROOT_STATE_DIRECTORY=""
AEGIS_SMOKE_ROOT_STATE_IDENTITY=""
AEGIS_SMOKE_MEASURE_DIRECTORY=""
AEGIS_SMOKE_MEASURE_IDENTITY=""
AEGIS_SMOKE_HELPER_STARTED=0

aegis_smoke_cargo_target_directory() {
  (
    set -o pipefail
    cd "${ROOT}" || exit 1
    "${CARGO_BIN:-cargo}" metadata --manifest-path "${ROOT}/Cargo.toml" \
      --no-deps --offline --format-version 1 |
      python3 -c 'import json, os, sys
path = json.load(sys.stdin).get("target_directory")
if not isinstance(path, str) or not os.path.isabs(path) or any(c in path for c in "\x00\r\n"):
    raise SystemExit("cargo metadata did not return an absolute target_directory")
print(path)'
  )
}

_aegis_smoke_stage_binary() {
  local source="$1" name="$2" digest receipt directory identity
  [[ "$source" == /* && -f "$source" && -x "$source" && ! -L "$source" ]] || {
    echo 'smoke metadata source must be an absolute regular executable' >&2; return 1;
  }
  digest="$(sha256sum -- "$source")" || return 1
  digest="${digest%% *}"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  receipt="$(sudo -n /usr/bin/python3 "${ROOT}/scripts/lib/smoke-root-state-client.py" \
    stage --source "$source" --sha256 "$digest" --binary-name "$name")" || return 1
  read -r directory identity <<< "$receipt"
  [[ "$directory" == /run/aegis-smoke-metadata.* && "$identity" =~ ^[0-9]+:[0-9]+$ ]] || {
    echo 'invalid owned smoke metadata staging receipt' >&2; return 1;
  }
  printf '%s %s %s\n' "$directory" "$identity" "$digest"
}

aegis_smoke_stage_root_state_client() {
  local receipt digest
  receipt="$(_aegis_smoke_stage_binary "$1" aegis-client)" || return 1
  read -r AEGIS_SMOKE_ROOT_STATE_DIRECTORY AEGIS_SMOKE_ROOT_STATE_IDENTITY digest <<< "$receipt"
  export AEGIS_ROOT_STATE_CLIENT="$AEGIS_SMOKE_ROOT_STATE_DIRECTORY/aegis-client"
  # Root helper launch deliberately prefers AEGIS_CLIENT_BIN. Bind both names
  # so doctor/probe/launch cannot revert to a runner-owned build checkout.
  export AEGIS_CLIENT_BIN="$AEGIS_ROOT_STATE_CLIENT"
  sudo -n env AEGIS_ROOT_STATE_CLIENT="$AEGIS_ROOT_STATE_CLIENT" \
    bash -c '. "$1"; aegis_root_state_init' aegis-smoke "${ROOT}/scripts/lib/root-state.sh" || return 1
  printf 'Smoke metadata client staged: sha256=%s directory=%s\n' "$digest" "$AEGIS_SMOKE_ROOT_STATE_DIRECTORY"
  if [[ -n "${2:-}" ]]; then
    receipt="$(_aegis_smoke_stage_binary "$2" aegis-measure)" || return 1
    read -r AEGIS_SMOKE_MEASURE_DIRECTORY AEGIS_SMOKE_MEASURE_IDENTITY digest <<< "$receipt"
    export AEGIS_MEASURE_BIN="$AEGIS_SMOKE_MEASURE_DIRECTORY/aegis-measure"
    export AEGIS_MEASURE_RUN_BIN="$AEGIS_MEASURE_BIN"
    sudo -n bash -c '. "$1"; aegis_root_trusted_executable "$2"' \
      aegis-smoke "${ROOT}/scripts/lib/root-state.sh" "$AEGIS_MEASURE_BIN" || return 1
    printf 'Smoke metadata measure staged: sha256=%s directory=%s\n' "$digest" "$AEGIS_SMOKE_MEASURE_DIRECTORY"
  fi
}

aegis_smoke_cleanup_root_state_client() {
  if [[ -n "${AEGIS_SMOKE_MEASURE_DIRECTORY:-}" ]]; then
    sudo -n /usr/bin/python3 "${ROOT}/scripts/lib/smoke-root-state-client.py" cleanup \
      --directory "$AEGIS_SMOKE_MEASURE_DIRECTORY" --identity "$AEGIS_SMOKE_MEASURE_IDENTITY" || return 1
    AEGIS_SMOKE_MEASURE_DIRECTORY=""
    AEGIS_SMOKE_MEASURE_IDENTITY=""
  fi
  [[ -n "${AEGIS_SMOKE_ROOT_STATE_DIRECTORY:-}" ]] || return 0
  sudo -n /usr/bin/python3 "${ROOT}/scripts/lib/smoke-root-state-client.py" cleanup \
    --directory "$AEGIS_SMOKE_ROOT_STATE_DIRECTORY" --identity "$AEGIS_SMOKE_ROOT_STATE_IDENTITY" || return 1
  AEGIS_SMOKE_ROOT_STATE_DIRECTORY=""
  AEGIS_SMOKE_ROOT_STATE_IDENTITY=""
}
