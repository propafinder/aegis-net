#!/usr/bin/env bash
# aegis-gre-gateway-setup.sh — GRE tunnel recipe for AEGIS TPROXY gateway
# topologies on cloud VPS where the L2 fabric enforces source-IP egress
# filtering (anti-spoofing).
#
# Background: a TPROXY transparent proxy on a gateway VM replies with
# src=ORIGINAL_DST (e.g. src=1.0.0.1:443). Most cloud providers drop
# packets whose src_IP is not in the VM's assigned IP list at the
# hypervisor or top-of-rack switch — see
# evidence-archive/live/2026-05-19/tproxy-forwarded-kernel-investigation/ for
# tcpdump evidence (VPS_A sends 7 SYN-ACK, VPS_B receives 0).
#
# Fix: encapsulate the gateway↔downstream traffic in a GRE tunnel. The
# outer GRE header carries the gateway's REAL IP, so the cloud fabric
# is happy. The inner packet preserves the TPROXY-spoofed src all the
# way to the downstream's GRE endpoint, where the kernel decapsulates
# and delivers it normally.
#
# Topology:
#
#     +-------------+   eth0    +-----------+   eth0    +-------------+
#     | downstream  |<--------->|  cloud L2 |<--------->|  gateway    |
#     |  VPS_B      | gre0/peer | / wire    | gre0/peer |  VPS_A      |
#     | 10.255.0.2  |<--GRE---->|           |<--GRE---->| 10.255.0.1  |
#     +-------------+           +-----------+           +-------------+
#                                                              |
#                                                              v
#                                                      aegis-client wide listener
#                                                              |
#                                                              v
#                                                          AEGIS relay
#
# Operator usage:
#
#   On GATEWAY (VPS_A):
#     sudo ./aegis-gre-gateway-setup.sh apply --role=gateway \
#         --peer-ip=<VPS_B_public_IP> \
#         --local-tip=10.255.0.1/30 \
#         --peer-tip=10.255.0.2
#
#   On DOWNSTREAM (VPS_B):
#     sudo ./aegis-gre-gateway-setup.sh apply --role=downstream \
#         --peer-ip=<VPS_A_public_IP> \
#         --local-tip=10.255.0.2/30 \
#         --peer-tip=10.255.0.1
#
# Then enable AEGIS wide mode on the gateway with the tunnel as ingress
# interface:
#
#     sudo AEGIS_WIDE_INTERFACE=aegis-gre0 ./aegis-wide-enable.sh -y \
#         --mode=tproxy --ssh-safe-ports=22 --dns=off --ipv6=block
#
# Route the test target on downstream into the tunnel:
#
#     sudo ip route add <target>/32 via 10.255.0.1 dev aegis-gre0
#
# Teardown (BOTH sides, after disabling AEGIS wide mode):
#
#     sudo ./aegis-gre-gateway-setup.sh teardown
#
# Safety: this helper only manipulates the GRE tunnel device + a /32
# route to the peer's PUBLIC IP so the tunnel endpoint stays reachable
# during the tunnel's lifetime. It does NOT alter the default route
# and does NOT modify iptables/nftables (that's aegis-wide-enable.sh's
# job).

set -uo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "FATAL: must run under sudo/root" >&2
    exit 2
fi

# ---- defaults ----
TUNNEL_NAME="aegis-gre0"
ROLE=""
PEER_IP=""
LOCAL_TIP=""        # tunnel-internal IP/CIDR on this host (e.g. 10.255.0.1/30)
PEER_TIP=""         # tunnel-internal IP on peer (e.g. 10.255.0.2)
TTL=64

usage() {
    cat <<USAGE
Usage:
  $0 apply --role=gateway|downstream --peer-ip=IP [--tunnel-name=NAME] \\
           --local-tip=IP/CIDR --peer-tip=IP

  $0 teardown [--tunnel-name=NAME]

Required for apply:
  --role           gateway   = the VM running AEGIS wide TPROXY
                   downstream = the client VM routing through the gateway
  --peer-ip        public IP of the OTHER end (used as GRE remote)
  --local-tip      tunnel-internal IP/CIDR on THIS host (e.g. 10.255.0.1/30)
  --peer-tip       tunnel-internal IP on the PEER (e.g. 10.255.0.2)

Optional:
  --tunnel-name    default aegis-gre0

Notes:
  * Use RFC 6890 reserved address space for --local-tip / --peer-tip
    (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). Default suggestion:
    10.255.0.0/30 — pick a subnet that does NOT overlap your LAN.
  * GRE protocol must be permitted between the two VMs by any cloud
    firewall in the path. Most providers allow GRE outbound by default;
    some require an explicit allow rule.
  * The tunnel endpoint's PUBLIC IP gets a /32 route via the underlying
    gateway so the tunnel itself stays reachable while the tunnel
    interface is up. We restore the routing on teardown.
USAGE
}

# ---- arg parsing ----
COMMAND="${1:-}"
shift || true
while [[ $# -gt 0 ]]; do
    case "$1" in
        --role=*) ROLE="${1#*=}" ;;
        --peer-ip=*) PEER_IP="${1#*=}" ;;
        --tunnel-name=*) TUNNEL_NAME="${1#*=}" ;;
        --local-tip=*) LOCAL_TIP="${1#*=}" ;;
        --peer-tip=*) PEER_TIP="${1#*=}" ;;
        -h|--help) usage; exit 0 ;;
        *) echo "FATAL: unknown arg: $1" >&2; usage; exit 2 ;;
    esac
    shift
done

# Sanity: tunnel-name should not be eth0/lo/etc
case "${TUNNEL_NAME}" in
    eth*|lo|wlan*|docker*|tun*)
        echo "FATAL: refusing to use ${TUNNEL_NAME} as tunnel name — pick something distinct (e.g. aegis-gre0)" >&2
        exit 2
        ;;
esac

state_file="/run/aegis-gre-${TUNNEL_NAME}.state"

apply_gateway() {
    local fwmark="0x2"
    local route_table="${ROUTE_TABLE:-202}"
    # Compute the underlay-src BEFORE we touch routes so we capture the
    # real eth0 IP, not the tunnel-internal IP.
    local underlay_src
    underlay_src="$(local_underlay_ip)"

    # Create the tunnel
    if ip link show "${TUNNEL_NAME}" >/dev/null 2>&1; then
        echo "INFO: ${TUNNEL_NAME} already exists; removing first" >&2
        ip link set "${TUNNEL_NAME}" down 2>/dev/null || true
        ip tunnel del "${TUNNEL_NAME}" 2>/dev/null || true
    fi
    ip tunnel add "${TUNNEL_NAME}" mode gre local "${underlay_src}" remote "${PEER_IP}" ttl "${TTL}" || {
        echo "FATAL: ip tunnel add failed" >&2; exit 3;
    }
    ip link set "${TUNNEL_NAME}" up
    ip addr add "${LOCAL_TIP}" dev "${TUNNEL_NAME}" 2>/dev/null || true

    # Route THIS host's traffic toward PEER_TIP via the tunnel
    ip route add "${PEER_TIP}/32" dev "${TUNNEL_NAME}" scope link 2>/dev/null || true

    # Symmetric routing for TPROXY-spoofed-src reply packets:
    #
    # When aegis-client accepts a TPROXY-redirected forwarded connection,
    # its reply socket has the original-dst as local addr (e.g. 1.0.0.1:443).
    # Reply packets go out with src=1.0.0.1, dst=<downstream-peer>:port. If
    # they leave via eth0, the cloud fabric's anti-spoofing filter drops
    # them. We need those packets to egress via the GRE tunnel instead so
    # the outer header carries this VM's REAL IP.
    #
    # We mark the conntrack on inbound forwarded SYNs (which arrive on the
    # tunnel device), then restore that mark on the reply path's first
    # packet via mangle OUTPUT, then policy-route marked packets to a
    # dedicated table whose default points into the tunnel. This is the
    # standard symmetric-TPROXY-routing pattern.
    #
    # Conntrack mark + ip rule:
    iptables -t mangle -A PREROUTING -i "${TUNNEL_NAME}" -j CONNMARK \
        --set-mark "${fwmark}/${fwmark}" 2>/dev/null || true
    iptables -t mangle -A OUTPUT -j CONNMARK --restore-mark --mask "${fwmark}" \
        2>/dev/null || true
    # Policy route: any packet with the spoofed-reply mark uses table 202
    # which routes default into the tunnel.
    ip rule add fwmark "${fwmark}/${fwmark}" lookup "${route_table}" 2>/dev/null || true
    ip route add default dev "${TUNNEL_NAME}" table "${route_table}" 2>/dev/null || true

    {
        echo "TUNNEL_NAME=${TUNNEL_NAME}"
        echo "ROLE=gateway"
        echo "PEER_IP=${PEER_IP}"
        echo "LOCAL_TIP=${LOCAL_TIP}"
        echo "PEER_TIP=${PEER_TIP}"
        echo "UNDERLAY_SRC=${underlay_src}"
        echo "FWMARK=${fwmark}"
        echo "ROUTE_TABLE=${route_table}"
    } > "${state_file}"

    cat <<DONE
============================================================
AEGIS GRE GATEWAY APPLIED
------------------------------------------------------------
tunnel:        ${TUNNEL_NAME}
local public:  $(local_underlay_ip)
peer public:   ${PEER_IP}
local tip:     ${LOCAL_TIP}
peer tip:      ${PEER_TIP}
state file:    ${state_file}

Next step on this gateway:
  sudo AEGIS_WIDE_INTERFACE=${TUNNEL_NAME} ./aegis-wide-enable.sh -y \\
      --mode=tproxy --ssh-safe-ports=22 --dns=off --ipv6=block

On the downstream peer:
  sudo ./aegis-gre-gateway-setup.sh apply --role=downstream \\
      --peer-ip=$(local_underlay_ip) \\
      --local-tip=${PEER_TIP}/30 \\
      --peer-tip=${LOCAL_TIP%%/*}
  sudo ip route add <target>/32 via ${LOCAL_TIP%%/*} dev ${TUNNEL_NAME}
============================================================
DONE
}

apply_downstream() {
    # Save current /32 route to peer if any, for restore
    ip -4 route show "${PEER_IP}/32" > "${state_file}.peer-route-orig" 2>/dev/null || true

    if ip link show "${TUNNEL_NAME}" >/dev/null 2>&1; then
        echo "INFO: ${TUNNEL_NAME} already exists; removing first" >&2
        ip link set "${TUNNEL_NAME}" down 2>/dev/null || true
        ip tunnel del "${TUNNEL_NAME}" 2>/dev/null || true
    fi
    ip tunnel add "${TUNNEL_NAME}" mode gre local "$(local_underlay_ip)" remote "${PEER_IP}" ttl "${TTL}" || {
        echo "FATAL: ip tunnel add failed" >&2; exit 3;
    }
    ip link set "${TUNNEL_NAME}" up
    ip addr add "${LOCAL_TIP}" dev "${TUNNEL_NAME}" 2>/dev/null || true

    # Route to peer's tunnel-internal IP via this tunnel
    ip route add "${PEER_TIP}/32" dev "${TUNNEL_NAME}" scope link 2>/dev/null || true

    {
        echo "TUNNEL_NAME=${TUNNEL_NAME}"
        echo "ROLE=downstream"
        echo "PEER_IP=${PEER_IP}"
        echo "LOCAL_TIP=${LOCAL_TIP}"
        echo "PEER_TIP=${PEER_TIP}"
    } > "${state_file}"

    cat <<DONE
============================================================
AEGIS GRE DOWNSTREAM APPLIED
------------------------------------------------------------
tunnel:       ${TUNNEL_NAME}
local public: $(local_underlay_ip)
peer public:  ${PEER_IP}
local tip:    ${LOCAL_TIP}
peer tip:     ${PEER_TIP}
state file:   ${state_file}

Use the tunnel for selected test targets:
  sudo ip route add <target>/32 via ${PEER_TIP} dev ${TUNNEL_NAME}
  curl https://<target>/
  sudo ip route del <target>/32 via ${PEER_TIP} dev ${TUNNEL_NAME}

Or for full default-route gateway:
  sudo ip route replace default via ${PEER_TIP} dev ${TUNNEL_NAME}
  # ... DANGEROUS — your SSH session may drop if not pinned via the
  # original underlay gateway. Only do this from console access.
============================================================
DONE
}

teardown() {
    local fwmark="${FWMARK:-0x2}"
    local route_table="${ROUTE_TABLE:-202}"
    if [[ ! -f "${state_file}" ]]; then
        echo "INFO: no state file at ${state_file}; best-effort teardown" >&2
    else
        # shellcheck source=/dev/null
        source "${state_file}"
    fi
    # Drop policy routing for spoofed-src reply path (gateway role only;
    # downstream role didn't install these, but the deletes are idempotent)
    while ip rule del fwmark "${fwmark}/${fwmark}" lookup "${route_table}" 2>/dev/null; do :; done
    ip -4 route flush table "${route_table}" 2>/dev/null || true
    iptables -t mangle -D PREROUTING -i "${TUNNEL_NAME}" -j CONNMARK \
        --set-mark "${fwmark}/${fwmark}" 2>/dev/null || true
    iptables -t mangle -D OUTPUT -j CONNMARK --restore-mark --mask "${fwmark}" \
        2>/dev/null || true

    if [[ -n "${PEER_TIP:-}" ]]; then
        ip route del "${PEER_TIP}/32" dev "${TUNNEL_NAME}" scope link 2>/dev/null || true
    fi
    ip link set "${TUNNEL_NAME}" down 2>/dev/null || true
    ip tunnel del "${TUNNEL_NAME}" 2>/dev/null || true
    rm -f "${state_file}" "${state_file}.peer-route-orig"
    echo "AEGIS GRE tunnel ${TUNNEL_NAME} torn down."
}

# Helper: return the IPv4 address that the kernel would use as src when
# sending to the peer (i.e. the underlay-facing local address).
local_underlay_ip() {
    local ip=""
    ip="$(ip -4 route get "${PEER_IP}" 2>/dev/null | awk 'NR==1 {for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}')"
    if [[ -z "${ip}" ]]; then
        # Fallback: first non-loopback IPv4
        ip="$(ip -4 -o addr show scope global | awk '{print $4}' | head -1 | cut -d/ -f1)"
    fi
    echo "${ip}"
}

case "${COMMAND}" in
    apply)
        if [[ -z "${ROLE}" || -z "${PEER_IP}" || -z "${LOCAL_TIP}" || -z "${PEER_TIP}" ]]; then
            usage; exit 2
        fi
        case "${ROLE}" in
            gateway) apply_gateway ;;
            downstream) apply_downstream ;;
            *) echo "FATAL: role must be gateway or downstream" >&2; exit 2 ;;
        esac
        ;;
    teardown) teardown ;;
    -h|--help|"") usage ; [[ -z "${COMMAND}" ]] && exit 2 || exit 0 ;;
    *) echo "FATAL: unknown command: ${COMMAND}" >&2; usage; exit 2 ;;
esac
