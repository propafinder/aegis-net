#!/usr/bin/env bash
# Exercise the tracked recovery graph, with dummy services and no network rules.
set -euo pipefail
[[ $(id -u) == 0 ]] || { echo 'Run as root on an authorized Linux test host'; exit 2; }
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
profile="$ROOT/packaging/systemd/profiles/inner-tls"
n="aegis-recovery-test-$$"
r=/run/systemd/system
cleanup() {
 systemctl stop "$n-online.target" "$n-dispatch.service" "$n-front.service" "$n-server.service" 2>/dev/null || true
 rm -f "$r/$n-online.target" "$r/$n-dispatch.service" "$r/$n-front.service" "$r/$n-server.service"
 rm -rf "$r/$n-front.service.d" "$r/$n-dispatch.service.d" "$r/$n-server.service.d"
 systemctl daemon-reload
}
trap cleanup EXIT
render() {
 sed -e "s/aegis-v3-online/$n-online/g" -e "s/aegis-front-v3/$n-front/g" \
     -e "s/aegis-v3-dispatch/$n-dispatch/g" -e "s/aegis-server-v3/$n-server/g" "$1"
}
for part in front server; do
 cat > "$r/$n-$part.service" <<'EOF'
[Service]
ExecStart=/bin/sleep infinity
Restart=on-failure
RestartSec=1s
EOF
 mkdir "$r/$n-$part.service.d"
done
render "$profile/aegis-server-v3.service.d/recovery.conf" > "$r/$n-server.service.d/recovery.conf"
render "$profile/aegis-front-v3.service.d/ingress-recovery.conf" > "$r/$n-front.service.d/recovery.conf"
mkdir "$r/$n-dispatch.service.d"
render "$profile/aegis-v3-dispatch.service.d/ingress-recovery.conf" > "$r/$n-dispatch.service.d/recovery.conf"
cat > "$r/$n-dispatch.service" <<EOF
[Unit]
After=$n-front.service $n-server.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/true
EOF
render "$profile/aegis-v3-online.target" > "$r/$n-online.target"
systemctl daemon-reload
systemctl start "$n-online.target"
for _ in $(seq 1 20); do
 if systemctl is-active --quiet "$n-front.service" "$n-server.service" "$n-dispatch.service"; then break; fi
 sleep 1
done
for part in front server dispatch; do systemctl is-active --quiet "$n-$part.service"; done
for part in front server; do
 old=$(systemctl show "$n-$part.service" -p MainPID --value)
 [[ "$old" -gt 0 ]]
 systemctl kill --kill-whom=main --signal=SIGKILL "$n-$part.service"
 recovered=false
 for _ in $(seq 1 70); do
  sleep 1
  new=$(systemctl show "$n-$part.service" -p MainPID --value)
  if [[ "$new" -gt 0 && "$new" != "$old" ]] && systemctl is-active --quiet "$n-dispatch.service"; then recovered=true; break; fi
 done
 [[ "$recovered" == true ]]
 echo "PASS: tracked profile recovered $part and dispatch after main-process crash"
done
systemctl stop "$n-online.target"
sleep 6
! systemctl is-active --quiet "$n-front.service"
! systemctl is-active --quiet "$n-dispatch.service"
systemctl is-active --quiet "$n-server.service"
echo 'PASS: explicit target stop is retained; independent backend stays active'
