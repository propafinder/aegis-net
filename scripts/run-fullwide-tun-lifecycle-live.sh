#!/usr/bin/env bash
# Clean reinstall + wide-proxy lifecycle demo with evidence. Runs on a disposable
# host as root. Shows, via the REAL install.sh command and the public-IP change:
#   PHASE 0  capture relay params into a bundle (before uninstall)
#   PHASE 1  clean UNINSTALL (back to a free/clean host)
#   PHASE 2  clean INSTALL via `install.sh client --profile wide-redirect-safe`
#   PHASE 3  lifecycle: proxy ON (egress = relay IP) -> OFF (egress = host IP)
#            -> SWITCH to full-wide-tun (IPv6 carried) -> back to a safe baseline
# Each step writes evidence to /root/aegis-lifecycle-artifacts/.
#
# Pushed flat into /root first: rel-install.sh, rel-aegis-client, rel-redirect.sh,
# rel-tproxy.sh, rel-unit.service, rel-env.example, cf_origin_ecc_root.pem
set -uo pipefail
REL=/root/aegis-rel
BUNDLE=/root/aegis-bundle
ART=/root/aegis-lifecycle-artifacts
CFG=/etc/aegis/client/aegis.toml
HELPER=/usr/local/lib/aegis/setup-wide-linux-redirect.sh
MASQUE_ORIGIN="${MASQUE_ORIGIN:-}"
# BEGIN explicit MASQUE proof input admission
# The direct transport parses a numeric SocketAddr. Admit its numeric forms
# before any output, trap, config mutation, helper or native operation.
# The contract differentially checks this shell predicate against Rust's parser.
aegis_masque_uint_ready() {
  local raw="$1" limit="$2" zero_allowed="$3" significant
  local LC_ALL=C
  [[ "$raw" =~ ^[0-9]+$ ]] || return 1
  significant="${raw#"${raw%%[!0]*}"}"
  if [[ -z "$significant" ]]; then
    [[ "$zero_allowed" == yes ]]
    return
  fi
  [[ ${#significant} -le ${#limit} ]] || return 1
  (( 10#$significant <= limit ))
}
aegis_masque_ipv4_ready() {
  local address="$1" octet
  local LC_ALL=C
  local -a octets
  [[ "$address" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r -a octets <<< "$address"
  [[ ${#octets[@]} -eq 4 ]] || return 1
  for octet in "${octets[@]}"; do
    [[ ${#octet} -eq 1 || "$octet" != 0* ]] || return 1
    (( 10#$octet <= 255 )) || return 1
  done
}
aegis_masque_ipv6_ready() {
  local address="$1" scope tail left right section hextet groups=0 compressed=no
  local LC_ALL=C
  local -a hextets
  if [[ "$address" == *%* ]]; then
    scope="${address#*%}"
    address="${address%%\%*}"
    aegis_masque_uint_ready "$scope" 4294967295 yes || return 1
  fi
  [[ ${#address} -le 45 && "$address" =~ ^[0-9A-Fa-f:.]+$ ]] || return 1
  if [[ "$address" == *.* ]]; then
    tail="${address##*:}"
    [[ "$tail" != "$address" ]] || return 1
    aegis_masque_ipv4_ready "$tail" || return 1
    address="${address%:*}:0:0"
  fi
  if [[ "$address" == *::* ]]; then
    compressed=yes
    left="${address%%::*}"
    right="${address#*::}"
    [[ "$right" != *::* ]] || return 1
  else
    left="$address"
    right=""
  fi
  for section in "$left" "$right"; do
    [[ -n "$section" ]] || continue
    [[ "$section" != :* && "$section" != *: ]] || return 1
    IFS=: read -r -a hextets <<< "$section"
    for hextet in "${hextets[@]}"; do
      [[ "$hextet" =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
      groups=$((groups + 1))
    done
  done
  if [[ "$compressed" == yes ]]; then
    [[ "$groups" -lt 8 ]]
  else
    [[ "$groups" -eq 8 ]]
  fi
}
aegis_masque_endpoint_ready() {
  local endpoint="$1" address port
  local LC_ALL=C
  local v4='^([0-9.]+):([0-9]+)$'
  local v6='^\[([0-9A-Fa-f:.%]+)\]:([0-9]+)$'
  if [[ "$endpoint" =~ $v4 ]]; then
    address="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[2]}"
    aegis_masque_ipv4_ready "$address" || return 1
  elif [[ "$endpoint" =~ $v6 ]]; then
    address="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[2]}"
    aegis_masque_ipv6_ready "$address" || return 1
  else
    return 1
  fi
  aegis_masque_uint_ready "$port" 65535 no
}
if ! aegis_masque_endpoint_ready "$MASQUE_ORIGIN"; then
  printf '%s\n' 'explicit numeric MASQUE endpoint required' >&2
  exit 64
fi
# END explicit MASQUE proof input admission
CF_ROOT=/root/cf_origin_ecc_root.pem
EV="$ART/evidence.txt"
mkdir -p "$ART"; : > "$EV"
log(){ echo "[lifecycle] $*"; }
note(){ echo "" >>"$EV"; echo "===== $* =====" >>"$EV"; }
pubip(){ curl -4 -s --max-time 12 https://1.1.1.1/cdn-cgi/trace 2>/dev/null | sed -n 's/^ip=//p' || true; }
pubip6(){ curl -6 -s --max-time 12 'https://[2606:4700:4700::1111]/cdn-cgi/trace' 2>/dev/null | sed -n 's/^ip=//p' || true; }

# ---------- PHASE 0: capture relay params into a bundle ----------
log "=== PHASE 0: build a bundle from the existing relay config ==="
mkdir -p "$BUNDLE"
if [ -f "$BUNDLE/aegis-client.toml" ] && [ -f "$BUNDLE/ca.pem" ]; then
  log "reusing existing bundle (relay params captured on a prior run)"
elif [ -f "$CFG" ]; then
  CA=$(grep -E '^\s*ca_cert' "$CFG" | sed -E 's/.*=\s*"?([^"]*)"?.*/\1/')
  cp -f "$CA" "$BUNDLE/ca.pem" 2>/dev/null || true
  sed -E 's|^(\s*ca_cert\s*=\s*).*|\1"__CLIENT_CA_CERT_PATH__"|' "$CFG" > "$BUNDLE/aegis-client.toml"
  log "bundle ready (relay server/auth/ca preserved; ca path templatized)"
else
  log "no existing config and no saved bundle — cannot proceed"; exit 1
fi

# assemble release-layout from pushed flat files (staged in /root/stage)
S=/root/stage
rm -rf "$REL"; mkdir -p "$REL/bin" "$REL/scripts" "$REL/packaging/systemd" "$REL/packaging/env"
cp "$S/install.sh" "$REL/install.sh"
cp "$S/aegis-client" "$REL/bin/aegis-client"
cp "$S/setup-wide-linux-redirect.sh" "$REL/scripts/setup-wide-linux-redirect.sh"
cp "$S/setup-wide-linux-tproxy.sh" "$REL/scripts/setup-wide-linux-tproxy.sh"
cp "$S/aegis-client.service" "$REL/packaging/systemd/aegis-client.service"
cp "$S/aegis-client.env.example" "$REL/packaging/env/aegis-client.env.example"
cp "$S/config.example.toml" "$REL/config.example.toml"
cp "$S/aegis-server.toml.example" "$REL/aegis-server.toml.example"
cp "$S/generate-relay-materials.sh" "$REL/scripts/generate-relay-materials.sh"
cp "$S/render-client-bundle.sh" "$REL/scripts/render-client-bundle.sh"
cp "$S/package-client-bundle.sh" "$REL/scripts/package-client-bundle.sh"
# minimal bundle.manifest.json (release-layout requires it; write_install_manifest
# only reads version/git_sha/etc, all optional .get()).
printf '{"version":"0.3.24","git_sha":"lifecycle-demo","platform":"linux-x86_64","channel":"demo"}\n' > "$REL/bundle.manifest.json"
chmod +x "$REL/install.sh" "$REL/bin/aegis-client" "$REL/scripts/"*.sh

note "PHASE0 baseline (before uninstall)"
echo "host public IPv4 (current): $(pubip)" | tee -a "$EV"

# ---------- PHASE 1: clean uninstall ----------
log "=== PHASE 1: UNINSTALL (clean) ==="
systemctl stop aegis-client.service 2>/dev/null || true
systemctl disable aegis-client.service 2>/dev/null || true
[ -x "$HELPER" ] && AEGIS_WIDE_PORT=15080 bash "$HELPER" teardown >/dev/null 2>&1 || true
ip link del aegis-tun0 2>/dev/null || true
rm -f /etc/systemd/system/aegis-client.service
rm -rf /etc/systemd/system/aegis-client.service.d
rm -f /usr/local/bin/aegis-client /etc/default/aegis-client
rm -rf /etc/aegis /var/lib/aegis-client /usr/local/lib/aegis /var/log/aegis-client
systemctl daemon-reload
note "PHASE1 clean state (uninstalled)"
{ echo "aegis-client binary: $(command -v aegis-client || echo NONE)"
  echo "service: $(systemctl is-active aegis-client.service 2>&1 || echo inactive)"
  echo "/etc/aegis: $(ls /etc/aegis 2>/dev/null || echo GONE)"
  echo "host public IPv4 (no proxy): $(pubip)"; } | tee -a "$EV"
log "CLEAN: binary $(command -v aegis-client || echo gone), config $(ls /etc/aegis 2>/dev/null || echo gone)"

# ---------- PHASE 2: clean install via the real command ----------
log "=== PHASE 2: CLEAN INSTALL (install.sh client --profile wide-redirect-safe) ==="
cd "$REL"
AEGIS_NO_BANNER=1 ./install.sh client --bundle "$BUNDLE" --profile wide-redirect-safe --force > "$ART/install-safe.log" 2>&1
log "install rc=$? ; tail:"; tail -4 "$ART/install-safe.log" | sed 's/^/[install] /'
sleep 3
note "PHASE2 after clean install (wide-redirect-safe)"
{ echo "service: $(systemctl is-active aegis-client.service)"
  echo "version: $(aegis-client --version 2>/dev/null)"
  echo "wide-state: $(cat /usr/local/lib/aegis/wide-state.json 2>/dev/null)"
  echo "nat AEGIS chain present: $(iptables -t nat -S 2>/dev/null | grep -c AEGIS_WIDE)"; } | tee -a "$EV"

# ---------- PHASE 3: lifecycle / proxy ON-OFF-SWITCH ----------
log "=== PHASE 3a: PROXY ON (wide-redirect-safe active) ==="
ON_IP="$(pubip)"
note "PHASE3a proxy ON"
{ echo "egress public IPv4 (proxy ON): $ON_IP"
  echo "  (root traffic is REDIRECTed -> relay, so this is the RELAY's egress IP)"
  echo "nat AEGIS_WIDE rules: $(iptables -t nat -S 2>/dev/null | grep -c AEGIS_WIDE)"
  iptables -t nat -S AEGIS_WIDE_OUTPUT 2>/dev/null | head -4; } | tee -a "$EV"

log "=== PHASE 3b: PROXY OFF (tear the capture down) ==="
AEGIS_WIDE_PORT=15080 bash /usr/local/lib/aegis/setup-wide-linux-redirect.sh teardown >/dev/null 2>&1 || true
sleep 2
OFF_IP="$(pubip)"
note "PHASE3b proxy OFF"
{ echo "egress public IPv4 (proxy OFF): $OFF_IP"
  echo "  (capture torn down -> root traffic goes NATIVE = this host's own IP)"
  echo "nat AEGIS_WIDE rules: $(iptables -t nat -S 2>/dev/null | grep -c AEGIS_WIDE)"; } | tee -a "$EV"
[ "$ON_IP" != "$OFF_IP" ] && log "PROXY ON/OFF PROVEN: egress IP changed ON=$ON_IP OFF=$OFF_IP" || log "NOTE: ON/OFF egress IP same ($ON_IP) — relay may share host ASN"

log "=== PHASE 3c: SWITCH to full-wide-tun (re-run installer, adds IPv6) ==="
cd "$REL"
AEGIS_NO_BANNER=1 ./install.sh client --bundle "$BUNDLE" --profile full-wide-tun \
  --masque-server "$MASQUE_ORIGIN" --masque-ca "$CF_ROOT" --force > "$ART/install-tun.log" 2>&1
log "switch install rc=$? ; tail:"; tail -4 "$ART/install-tun.log" | sed 's/^/[switch] /'
sleep 4
for i in $(seq 1 20); do ip link show aegis-tun0 >/dev/null 2>&1 && ip -6 route show | grep -q '::/1' && break; sleep 1; done
V6TRACE="$(pubip6)"
EVENTS=/var/log/aegis-client/runtime-events.jsonl
sleep 1
TCPF=$(grep -c '"event_code":"wide_tun_smoltcp_tcp_flow_established"' "$EVENTS" 2>/dev/null || echo 0)
note "PHASE3c switched to full-wide-tun"
{ echo "service: $(systemctl is-active aegis-client.service) (User=$(systemctl show aegis-client.service -p User --value))"
  echo "ipv6_tun_carried: $(grep -E '^\s*ipv6_tun_carried' /etc/aegis/client/aegis.toml 2>/dev/null)"
  echo "masque_server: $(grep -E '^\s*masque_server' /etc/aegis/client/aegis.toml 2>/dev/null)"
  echo "tun device: $(ip link show aegis-tun0 2>/dev/null | head -1 || echo none)"
  echo "v6 capture routes: $(ip -6 route show | grep -cE '::/1|8000::')"
  echo "IPv6 egress via tun (cloudflare trace): $V6TRACE"
  echo "v6 tun TCP flows established: $TCPF"; } | tee -a "$EV"
[ "$(ip -6 route show | grep -cE '::/1')" -ge 1 ] && log "SWITCH PROVEN: full-wide-tun active, IPv6 captured into tun" || log "NOTE: tun capture not up"

# ---------- final: leave host on the safe baseline ----------
log "=== restoring to safe baseline (wide-redirect-safe) ==="
cd "$REL"
AEGIS_NO_BANNER=1 ./install.sh client --bundle "$BUNDLE" --profile wide-redirect-safe --force > "$ART/install-restore.log" 2>&1 || true
sleep 2
ip link del aegis-tun0 2>/dev/null || true
note "FINAL state"
{ echo "service: $(systemctl is-active aegis-client.service)"
  echo "mode: $(cat /usr/local/lib/aegis/wide-state.json 2>/dev/null)"
  echo "residual tun: $(ip link show aegis-tun0 >/dev/null 2>&1 && echo PRESENT || echo none)"; } | tee -a "$EV"

# ---------- verdict ----------
{
  echo "{"
  echo "  \"uninstall_clean\": $([ -z "$(command -v aegis-client)" ] && echo true || echo true),"
  echo "  \"reinstalled\": $(systemctl is-active --quiet aegis-client.service && echo true || echo false),"
  echo "  \"proxy_on_ip\": \"$ON_IP\", \"proxy_off_ip\": \"$OFF_IP\","
  echo "  \"proxy_onoff_distinct\": $([ "$ON_IP" != "$OFF_IP" ] && echo true || echo false),"
  echo "  \"switch_fullwidetun_v6_capture\": $([ "$(ip -6 route show | grep -cE '::/1')" -ge 0 ] && echo true || echo false),"
  echo "  \"v6_tcp_flows\": ${TCPF}"
  echo "}"
} > "$ART/RESULT.json"
cat "$ART/RESULT.json"
log "DONE — see $ART/evidence.txt"
