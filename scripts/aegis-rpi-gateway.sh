#!/usr/bin/env bash
# Turnkey AEGIS gateway for RPi / OpenWrt-class routers.
# Makes the box a transparent tunneling gateway: every device whose traffic is
# ROUTED THROUGH this host (WiFi AP clients, wired LAN behind it) is captured and
# carried over the AEGIS relay — zero config on the device.
#
# This is the "glue" the client installer intentionally does NOT do (it can't
# guess your interfaces): the forwarding sysctls + NAT + the product TPROXY
# capture on the downstream interface. hostapd (turning --lan into a WiFi AP)
# and a DHCP server are separate, hardware-specific operator steps — see the
# runbook printed at the end of `apply`.
#
# Usage (interfaces are AUTO-DETECTED — no per-device config needed):
#   sudo aegis-rpi-gateway.sh apply                 # plumbing only (you run hostapd/DHCP)
#   sudo aegis-rpi-gateway.sh apply --setup-ap      # FULL turnkey: also brings up the
#                                                   # WiFi AP (hostapd+dnsmasq, auto SSID/pass)
#   sudo aegis-rpi-gateway.sh teardown [--setup-ap] # reverse everything
# Auto-detect: uplink = the iface with the internet default route; LAN/AP = a
# wireless iface that isn't the uplink and supports AP mode. Override only if the
# guess is wrong:
#   sudo aegis-rpi-gateway.sh apply --uplink wlan0 --lan wlan1 [--wide-port 15080]
#
# Requires: root, iproute2, a TPROXY-capable kernel (nft_tproxy+nft_socket on a
# pure-nft host, or xt_TPROXY+xt_socket via iptables), and the AEGIS client
# already installed & running in gateway-tproxy mode (listen 0.0.0.0:<wide-port>).
set -euo pipefail

ACTION="${1:-}"; shift || true
UPLINK=""; LAN=""; WIDE_PORT="15080"; FWMARK="1"; ROUTE_TABLE="100"
SETUP_AP=0; AP_SSID=""; AP_PASS=""; AP_SUBNET="10.99.1"
HELPER="$(cd "$(dirname "$0")" && pwd)/setup-wide-linux-tproxy.sh"
# shellcheck source=scripts/lib/root-state.sh
. "$(dirname "$HELPER")/lib/root-state.sh"
HOSTAPD_CONF="/run/aegis-gateway/hostapd.conf"; DNSMASQ_CONF="/run/aegis-gateway/dnsmasq.conf"
DNSMASQ_PID="/run/aegis-gateway/dnsmasq.pid"
# Persist the pre-apply sysctl values so teardown restores the box's original
# forwarding/routing posture instead of silently leaving it a router.
SYSCTL_BAK="${AEGIS_GW_SYSCTL_BAK:-/var/lib/aegis-install/client/gateway-sysctl-original.txt}"
NFT_TABLE="aegis_gw_nat"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --uplink) UPLINK="$2"; shift 2;;
    --lan) LAN="$2"; shift 2;;
    --wide-port) WIDE_PORT="$2"; shift 2;;
    --fwmark) FWMARK="$2"; shift 2;;
    --table) ROUTE_TABLE="$2"; shift 2;;
    --setup-ap) SETUP_AP=1; shift;;
    --ssid) AP_SSID="$2"; shift 2;;
    --pass) AP_PASS="$2"; shift 2;;
    --ap-subnet) AP_SUBNET="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[[ "$ACTION" == "apply" || "$ACTION" == "teardown" ]] || { echo "action must be apply|teardown" >&2; exit 2; }
[[ "$(id -u)" == "0" ]] || { echo "must run as root" >&2; exit 2; }

# Auto-detect interfaces so the operator does not have to name them per device.
# --uplink/--lan remain as manual overrides but are optional.
#   uplink = the interface that actually carries the default internet route.
#   lan    = a wireless interface that is NOT the uplink AND supports AP mode
#            (the natural access-point radio); if none, the single other
#            non-loopback interface that is up.
autodetect_uplink() {
  # Prefer the resolved route to a public IP; fall back to the default route.
  ip route get 1.1.1.1 2>/dev/null | grep -oE 'dev [^ ]+' | awk '{print $2; exit}' && return 0
  ip route show default 2>/dev/null | awk '/default/{print $5; exit}'
}
iface_supports_ap() {
  local phy; phy="$(cat "/sys/class/net/$1/phy80211/name" 2>/dev/null)" || return 1
  [[ -n "$phy" ]] || return 1
  iw phy "$phy" info 2>/dev/null | grep -A20 'Supported interface modes' | grep -qE '^[[:space:]]*\* AP$'
}
autodetect_lan() {
  local up="$1" i
  # 1) a wireless radio that isn't the uplink and can be an AP
  for i in $(ls /sys/class/net 2>/dev/null | grep -E '^wl'); do
    [[ "$i" == "$up" ]] && continue
    iface_supports_ap "$i" && { echo "$i"; return 0; }
  done
  # 2) fallback: any single non-loopback iface that isn't the uplink
  for i in $(ls /sys/class/net 2>/dev/null); do
    [[ "$i" == "lo" || "$i" == "$up" ]] && continue
    [[ -e "/sys/class/net/$i" ]] || continue
    echo "$i"; return 0
  done
  return 1
}

if [[ -z "$UPLINK" ]]; then
  UPLINK="$(autodetect_uplink)"
  [[ -n "$UPLINK" ]] && echo "auto-detected uplink: $UPLINK (has the internet default route)" >&2
fi
if [[ -z "$LAN" ]]; then
  LAN="$(autodetect_lan "$UPLINK")"
  [[ -n "$LAN" ]] && echo "auto-detected LAN/AP interface: $LAN$(iface_supports_ap "$LAN" && echo ' (AP-capable)')" >&2
fi
if [[ -z "$UPLINK" || -z "$LAN" ]]; then
  echo "could not auto-detect interfaces (uplink='${UPLINK:-?}' lan='${LAN:-?}')." >&2
  echo "pass them explicitly: --uplink <internet-iface> --lan <AP-iface>" >&2
  exit 2
fi
if [[ "$UPLINK" == "$LAN" ]]; then
  echo "uplink and LAN resolved to the same interface ($UPLINK) — need two paths." >&2
  echo "a single radio cannot be both uplink and AP; add a second radio/cable or pass --uplink/--lan." >&2
  exit 2
fi

for iface in "$UPLINK" "$LAN"; do
  [[ "$iface" =~ ^[A-Za-z0-9][A-Za-z0-9_@.-]{0,14}$ ]] || { echo 'invalid interface name' >&2; exit 2; }
done
[[ "$WIDE_PORT" =~ ^[0-9]{1,5}$ ]] && (( 10#$WIDE_PORT > 0 && 10#$WIDE_PORT <= 65535 )) || exit 2
[[ "$FWMARK" =~ ^[0-9]{1,9}$ && "$ROUTE_TABLE" =~ ^[0-9]{1,9}$ ]] || exit 2
[[ "$AP_SUBNET" =~ ^10\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || { echo 'AP subnet must be a private 10.x.y prefix' >&2; exit 2; }
IFS=. read -r _ ap_octet2 ap_octet3 <<< "$AP_SUBNET"
(( 10#$ap_octet2 <= 255 && 10#$ap_octet3 <= 255 )) || exit 2
[[ -z "$AP_SSID" || ( ${#AP_SSID} -le 32 && "$AP_SSID" != *$'\n'* && "$AP_SSID" != *$'\r'* ) ]] || exit 2
[[ -z "$AP_PASS" || ( ${#AP_PASS} -ge 8 && ${#AP_PASS} -le 63 && "$AP_PASS" != *$'\n'* && "$AP_PASS" != *$'\r'* ) ]] || exit 2
# Establish trusted destinations before stopping services or changing networking.
aegis_root_state_init
for destination in "$SYSCTL_BAK" "$HOSTAPD_CONF" "$DNSMASQ_CONF" "$DNSMASQ_PID"; do
  aegis_root_validate "$destination"
done

# Prefer iptables when the real binary is present; otherwise use native nft. On a
# pure-nft RPi (no iptables at all) the iptables-only MASQUERADE would silently
# never be installed — so NAT must have an nft path too.
have_iptables() { command -v iptables >/dev/null 2>&1; }

nat_apply() {
  if have_iptables; then
    iptables -t nat -C POSTROUTING -o "$UPLINK" -j MASQUERADE 2>/dev/null || \
      iptables -t nat -A POSTROUTING -o "$UPLINK" -j MASQUERADE
  else
    nft add table ip "${NFT_TABLE}" 2>/dev/null || true
    nft "add chain ip ${NFT_TABLE} postrouting { type nat hook postrouting priority srcnat ; }" 2>/dev/null || true
    # idempotent: only add if an equivalent rule is not already present
    nft list chain ip "${NFT_TABLE}" postrouting 2>/dev/null | grep -q "oifname \"${UPLINK}\" masquerade" || \
      nft add rule ip "${NFT_TABLE}" postrouting oifname "${UPLINK}" masquerade
  fi
}

nat_teardown() {
  if have_iptables; then
    iptables -t nat -C POSTROUTING -o "$UPLINK" -j MASQUERADE 2>/dev/null && \
      iptables -t nat -D POSTROUTING -o "$UPLINK" -j MASQUERADE || true
  else
    nft delete table ip "${NFT_TABLE}" 2>/dev/null || true
  fi
}

rand_hex() { head -c "$1" /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n'; }

# --setup-ap: bring $LAN up as a WiFi access point (hostapd + dnsmasq DHCP) with
# a static IP, so the operator does not hand-configure anything. Touches ONLY the
# AP interface; the uplink is never modified. Credentials are auto-generated and
# printed. NOTE: hostapd's radio bring-up is validated on real hardware.
setup_ap() {
  local lan="$1"
  [[ -n "${AP_SSID}" ]] || AP_SSID="AEGIS-$(rand_hex 2)"
  [[ -n "${AP_PASS}" ]] || AP_PASS="$(rand_hex 6)"
  # deps
  local missing=""
  command -v hostapd >/dev/null 2>&1 || missing+=" hostapd"
  command -v dnsmasq >/dev/null 2>&1 || missing+=" dnsmasq"
  if [[ -n "${missing}" ]]; then
    echo "installing:${missing}" >&2
    apt-get update -qq 2>/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ${missing} 2>/dev/null || {
      echo "could not auto-install${missing}; install them and re-run --setup-ap" >&2; return 1; }
  fi
  local cc; cc="$(iw reg get 2>/dev/null | grep -oE 'country [A-Z]{2}' | awk '{print $2; exit}')"
  aegis_root_write "${HOSTAPD_CONF}" <<H || return 1
interface=$lan
driver=nl80211
ssid=${AP_SSID}
hw_mode=g
channel=6
wmm_enabled=1
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=${AP_PASS}
$([[ -n "$cc" ]] && printf 'country_code=%s\nieee80211d=1\n' "$cc")
H
  aegis_root_write "${DNSMASQ_CONF}" <<D || return 1
interface=$lan
bind-interfaces
except-interface=lo
dhcp-range=${AP_SUBNET}.50,${AP_SUBNET}.200,255.255.255.0,12h
dhcp-option=3,${AP_SUBNET}.1
dhcp-option=6,1.1.1.1,8.8.8.8
D
  # Write both protected configs before changing the radio or its services.
  command -v nmcli >/dev/null 2>&1 && nmcli device set "$lan" managed no 2>/dev/null || true
  systemctl stop hostapd dnsmasq 2>/dev/null || true
  ip addr flush dev "$lan" 2>/dev/null || true
  ip addr add "${AP_SUBNET}.1/24" dev "$lan" || return 1
  ip link set "$lan" up || return 1
  pkill -F "${DNSMASQ_PID}" 2>/dev/null || true
  pkill -f "hostapd ${HOSTAPD_CONF}" 2>/dev/null || true
  dnsmasq -C "${DNSMASQ_CONF}" --pid-file="${DNSMASQ_PID}" 2>/dev/null || { echo "dnsmasq failed to start (check :53 collision)" >&2; return 1; }
  hostapd -B "${HOSTAPD_CONF}" 2>/dev/null || { echo "hostapd failed to start on $lan (check the radio supports AP + regulatory)" >&2; return 1; }
  cat <<M
== WiFi access point up on $lan ==
   SSID:     ${AP_SSID}
   Password: ${AP_PASS}
   Gateway:  ${AP_SUBNET}.1  (DHCP ${AP_SUBNET}.50-200)
   Connect a phone to this SSID — its traffic (TCP) is tunnelled.
M
}

teardown_ap() {
  local lan="$1"
  pkill -f "hostapd ${HOSTAPD_CONF}" 2>/dev/null || true
  [[ -f "${DNSMASQ_PID}" ]] && pkill -F "${DNSMASQ_PID}" 2>/dev/null || true
  aegis_root_remove "${HOSTAPD_CONF}"
  aegis_root_remove "${DNSMASQ_CONF}"
  aegis_root_remove "${DNSMASQ_PID}"
  ip addr flush dev "$lan" 2>/dev/null || true
  command -v nmcli >/dev/null 2>&1 && nmcli device set "$lan" managed yes 2>/dev/null || true
}

# route_localnet + loose rp_filter are MANDATORY for the forwarded TPROXY path:
# a routed (downstream) packet whose dst is a real public IP is delivered `local
# … dev lo` to the transparent listener via the fwmark policy route. Without
# route_localnet=1 on the ingress iface the kernel drops it at the policy-route
# step (AEGIS's own 2026-05-19 gateway drill caught exactly this), and strict
# rp_filter (=1) can drop the loopback-delivered forwarded packet. The client-
# host wide path (aegis-wide-enable.sh) already sets these; the standalone
# gateway wrapper must too. Snapshot originals first so teardown can restore.
SYSCTLS=(
  "net.ipv4.ip_forward"
  "net.ipv4.conf.all.route_localnet"
  "net.ipv4.conf.${LAN}.route_localnet"
  "net.ipv4.conf.all.rp_filter"
  "net.ipv4.conf.${LAN}.rp_filter"
)

sysctl_snapshot() {
  local k v text=""
  for k in "${SYSCTLS[@]}"; do
    v="$(sysctl -n "$k")" || return 1
    case "$k" in
      *.rp_filter) [[ "$v" =~ ^[012]$ ]] || return 1 ;;
      *) [[ "$v" =~ ^[01]$ ]] || return 1 ;;
    esac
    text+="${k}=${v}"$'\n'
  done
  printf '%s' "$text" | aegis_root_write "$SYSCTL_BAK"
}

sysctl_checked_snapshot() {
  local text key value index=0
  text="$(aegis_root_read "${1:-$SYSCTL_BAK}")" || return 1
  while IFS='=' read -r key value; do
    (( index < ${#SYSCTLS[@]} )) && [[ "$key" == "${SYSCTLS[$index]}" ]] || return 1
    case "$key" in
      *.rp_filter) [[ "$value" =~ ^[012]$ ]] || return 1 ;;
      *) [[ "$value" =~ ^[01]$ ]] || return 1 ;;
    esac
    index=$((index + 1))
  done <<< "$text"
  (( index == ${#SYSCTLS[@]} )) || return 1
  printf '%s\n' "$text"
}

snapshot=""
if [[ -e "$SYSCTL_BAK" ]]; then
  snapshot="$(sysctl_checked_snapshot)" || { echo 'invalid gateway rollback snapshot' >&2; exit 1; }
fi
if [[ -e /run/aegis-gw-sysctl.bak || -L /run/aegis-gw-sysctl.bak ]]; then
  legacy_snapshot="$(sysctl_checked_snapshot /run/aegis-gw-sysctl.bak)" || {
    echo 'legacy gateway snapshot is untrusted or does not match these interfaces' >&2; exit 1;
  }
  [[ -z "$snapshot" || "$snapshot" == "$legacy_snapshot" ]] || {
    echo 'conflicting gateway rollback snapshots' >&2; exit 1;
  }
  if [[ -z "$snapshot" ]]; then
    printf '%s\n' "$legacy_snapshot" | aegis_root_write "$SYSCTL_BAK"
    snapshot="$legacy_snapshot"
  fi
  aegis_root_remove /run/aegis-gw-sysctl.bak
fi

if [[ "$ACTION" == "apply" ]]; then
  echo "== AEGIS gateway apply: LAN=$LAN -> tunnel, uplink=$UPLINK =="
  # 0) optionally stand up the WiFi AP on $LAN first (hostapd + dnsmasq), so the
  #    interface is up with its subnet before capture is scoped to it.
  if [[ "${SETUP_AP}" == "1" ]]; then
    setup_ap "$LAN" || { echo "AP setup failed; not arming capture." >&2; exit 1; }
  fi
  # 1) snapshot + forwarding/routing sysctls (idempotent; only snapshot once)
  [[ -n "$snapshot" ]] || sysctl_snapshot
  sysctl -wq net.ipv4.ip_forward=1
  sysctl -wq net.ipv4.conf.all.route_localnet=1
  sysctl -wq "net.ipv4.conf.${LAN}.route_localnet=1"
  sysctl -wq net.ipv4.conf.all.rp_filter=2 2>/dev/null || true
  sysctl -wq "net.ipv4.conf.${LAN}.rp_filter=2" 2>/dev/null || true
  # 2) NAT the uplink so LAN traffic that goes DIRECT (DNS/UDP fallback, return
  #    path) can egress. Tunnelled TCP egresses at the relay anyway.
  nat_apply
  # 3) product TPROXY capture on the downstream (LAN) interface only — the box's
  #    own relay uplink on $UPLINK is never matched, so no self-loop.
  AEGIS_WIDE_INTERFACE="$LAN" AEGIS_WIDE_PORT="$WIDE_PORT" \
  AEGIS_WIDE_FWMARK="$FWMARK" AEGIS_WIDE_ROUTE_TABLE="$ROUTE_TABLE" \
    bash "$HELPER" apply
  cat <<EOF
== gateway up. Devices routed via $LAN are now tunnelled (TCP). ==

Operator steps AEGIS does NOT do (hardware/topology-specific):
  1. hostapd on $LAN  — turn it into a WiFi access point (SSID + WPA2).
  2. A DHCP server on $LAN (e.g. dnsmasq) handing out IP + gateway (this host's
     $LAN address) + DNS. Bind it to $LAN only (interface=$LAN, bind-interfaces)
     so it does NOT collide with a wide dns=preview listener on 127.0.0.1:53.
  3. If NetworkManager manages $LAN, unmanage it first:  nmcli device set $LAN managed no
     (otherwise NM fights hostapd for the radio).
Note: only downstream TCP is tunnelled; AP-client DNS/UDP egress DIRECTLY via
$UPLINK MASQUERADE (plaintext) — expected with capture_dns=false.
EOF
else
  echo "== AEGIS gateway teardown =="
  AEGIS_WIDE_INTERFACE="$LAN" AEGIS_WIDE_PORT="$WIDE_PORT" \
  AEGIS_WIDE_FWMARK="$FWMARK" AEGIS_WIDE_ROUTE_TABLE="$ROUTE_TABLE" \
    bash "$HELPER" teardown || true
  nat_teardown
  # Restore the box's original forwarding/routing posture (don't leave it a router).
  if [[ -n "$snapshot" ]]; then
    while IFS='=' read -r k v; do
      sysctl -wq "${k}=${v}"
    done <<< "$snapshot"
    aegis_root_remove "$SYSCTL_BAK"
  fi
  # Tear the AP down too if we ever brought it up (flag OR leftover conf).
  if [[ "${SETUP_AP}" == "1" || -f "${HOSTAPD_CONF}" ]]; then
    teardown_ap "$LAN"
  fi
  echo "== torn down =="
fi
