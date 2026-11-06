#!/usr/bin/env bash
# Administrative state is separate from the daemon's writable runtime state.
# This library executes only a verified, administrator-owned installed client.
aegis_root_trusted_executable() {
  local path="$1" executable="$1" owner mode current="$(id -u)"
  [[ "$path" == /* && "$path" != *'/../'* && "$path" != */.. ]] || return 1
  [[ -f "$path" && -x "$path" && ! -L "$path" ]] || {
    echo 'ERROR: update the verified installed Aegis client before changing network state.' >&2; return 1;
  }
  while [[ "$path" != / ]]; do
    [[ ! -L "$path" ]] || return 1
    if [[ "${OSTYPE:-}" == darwin* ]]; then
      owner="$(stat -f %u "$path")"; mode="$(stat -f %Op "$path")"
    else
      owner="$(stat -c %u "$path")"; mode="$(stat -c %a "$path")"
    fi
    [[ "$owner" == 0 || "$owner" == "$current" ]] || return 1
    if (( (8#$mode & 022) != 0 )); then
      [[ "$owner" == 0 && "$path" != "$executable" ]] && (( (8#$mode & 01000) != 0 )) || return 1
    fi
    path="$(dirname "$path")"
  done
}
aegis_root_state_init() {
  AEGIS_ROOT_STATE_CLIENT="${AEGIS_ROOT_STATE_CLIENT:-/usr/local/bin/aegis-client}"
  aegis_root_trusted_executable "$AEGIS_ROOT_STATE_CLIENT" || return 1
  "${AEGIS_ROOT_STATE_CLIENT}" profile metadata --help >/dev/null || {
    echo 'ERROR: installed client lacks safe rollback metadata support; upgrade it first.' >&2; return 1;
  }
}
aegis_root_state() { "${AEGIS_ROOT_STATE_CLIENT}" profile metadata "$@"; }
aegis_root_validate() { aegis_root_state validate --path "$1"; }
aegis_root_read() { aegis_root_state read --path "$1"; }
aegis_root_write() { aegis_root_state write --path "$1" --mode "${2:-0600}"; }
aegis_root_remove() { aegis_root_state remove --path "$1"; }

aegis_root_sysctl_check() {
  local text key value count=0 seen="|"
  text="$(aegis_root_read "$1")" || return 1
  while IFS='=' read -r key value; do
    [[ -z "$key" || "$key" == \#* ]] && continue
    [[ "$value" == 0 || "$value" == 1 ]] || return 1
    case "$key" in
      net.ipv4.ip_forward|net.ipv4.conf.all.route_localnet) ;;
      *) [[ "$key" =~ ^net\.ipv4\.conf\.[A-Za-z0-9][A-Za-z0-9_@.-]{0,14}\.route_localnet$ ]] || return 1 ;;
    esac
    [[ "$seen" != *"|$key|"* ]] || return 1
    seen+="$key|"
    count=$((count + 1)); (( count <= 3 )) || return 1
  done <<< "$text"
  (( count == 3 )) && [[ "$seen" == *"|net.ipv4.ip_forward|"* && "$seen" == *"|net.ipv4.conf.all.route_localnet|"* ]]
}

aegis_root_network_preflight() {
  aegis_root_state_init || return 1
  AEGIS_WIDE_SYSCTL_FILE="${AEGIS_WIDE_SYSCTL_FILE:-/etc/sysctl.d/99-aegis-wide.conf}"
  AEGIS_WIDE_SYSCTL_SNAPSHOT="${AEGIS_WIDE_SYSCTL_SNAPSHOT:-/var/lib/aegis-install/client/wide-sysctl-original.txt}"
  AEGIS_WIDE_RESOLVER_SNAPSHOT="${AEGIS_WIDE_RESOLVER_SNAPSHOT:-/var/lib/aegis-install/client/resolver-original.json}"
  config_file="${AEGIS_CONFIG_FILE:-/etc/aegis/client/aegis.toml}"
  local path legacy=/var/lib/aegis/wide-sysctl-original.txt
  for path in "$AEGIS_WIDE_SYSCTL_FILE" "$AEGIS_WIDE_SYSCTL_SNAPSHOT" "$config_file" "$config_file.aegis-wide-bak" "$config_file.tmp"; do
    aegis_root_validate "$path" || {
      echo 'ERROR: untrusted administrative state; run the verified installer migration first.' >&2; return 1;
    }
  done
  if [[ -e "$legacy" || -L "$legacy" ]]; then
    # Only a fully trusted old snapshot may migrate. Runtime-owned state fails
    # closed; neither a current service nor a pathname link can supply sysctls.
    aegis_root_sysctl_check "$legacy" || return 1
    if [[ ! -e "$AEGIS_WIDE_SYSCTL_SNAPSHOT" ]]; then
      aegis_root_read "$legacy" | aegis_root_write "$AEGIS_WIDE_SYSCTL_SNAPSHOT" || return 1
    fi
    aegis_root_remove "$legacy" || return 1
  fi
  if [[ -e "$AEGIS_WIDE_SYSCTL_SNAPSHOT" ]]; then
    aegis_root_sysctl_check "$AEGIS_WIDE_SYSCTL_SNAPSHOT" || return 1
  fi
  aegis_root_resolver_preflight
}

aegis_root_resolver_preflight() {
  AEGIS_WIDE_RESOLVER_SNAPSHOT="${AEGIS_WIDE_RESOLVER_SNAPSHOT:-/var/lib/aegis-install/client/resolver-original.json}"
  local legacy=/etc/resolv.conf.aegis-wide-bak
  if [[ -e "$legacy" || -L "$legacy" ]]; then
    # Convert only an administrator-owned regular file or a known resolver
    # manager link in trusted /etc into an authenticated regular JSON record.
    aegis_root_state resolver-save --path "$legacy" --snapshot "$AEGIS_WIDE_RESOLVER_SNAPSHOT" || return 1
    rm -f -- "$legacy" || return 1
  fi
  aegis_root_state resolver-check --path /etc/resolv.conf --snapshot "$AEGIS_WIDE_RESOLVER_SNAPSHOT"
}
aegis_root_resolver_save() {
  aegis_root_state resolver-save --path /etc/resolv.conf --snapshot "$AEGIS_WIDE_RESOLVER_SNAPSHOT"
}
aegis_root_resolver_restore() {
  aegis_root_state resolver-restore --path /etc/resolv.conf --snapshot "$AEGIS_WIDE_RESOLVER_SNAPSHOT"
}
