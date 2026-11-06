#!/usr/bin/env bash
# Native systemd regression: clearing OnUnitActiveSec also clears OnBootSec.
set -euo pipefail
[[ $(id -u) == 0 ]] || { echo 'Run as root on a disposable Linux test host'; exit 2; }
name="aegis-policy-timer-test-$$"
base="/run/systemd/system/$name"
cleanup() {
 systemctl stop "$name.timer" "$name.service" 2>/dev/null || true
 rm -f "$base.timer" "$base.service"
 rm -rf "$base.timer.d"
 systemctl daemon-reload
}
trap cleanup EXIT
mkdir "$base.timer.d"
cat > "$base.service" <<'EOF'
[Service]
Type=oneshot
ExecStart=/bin/sleep 3
EOF
cat > "$base.timer" <<EOF
[Timer]
OnBootSec=1s
OnUnitActiveSec=60s
AccuracySec=100ms
Unit=$name.service
EOF
cat > "$base.timer.d/override.conf" <<'EOF'
[Timer]
OnUnitActiveSec=
OnUnitActiveSec=2s
EOF
systemctl daemon-reload
systemctl start "$name.timer"
sleep 1
[[ -z $(systemctl show "$name.timer" -p LastTriggerUSec --value) ]]
echo 'PASS: original override loses boot trigger and never fires'
systemctl stop "$name.timer"
cat > "$base.timer.d/override.conf" <<'EOF'
[Timer]
OnUnitActiveSec=
OnActiveSec=1s
OnUnitInactiveSec=2s
EOF
systemctl daemon-reload
systemctl start "$name.timer"
sleep 2
first=$(systemctl show "$name.timer" -p LastTriggerUSecMonotonic --value)
[[ -n "$first" && "$first" != 0 ]]
sleep 6
second=$(systemctl show "$name.timer" -p LastTriggerUSecMonotonic --value)
[[ -n "$second" && "$second" != "$first" ]]
echo 'PASS: repaired timer fires on activation and repeats after a slow service'
