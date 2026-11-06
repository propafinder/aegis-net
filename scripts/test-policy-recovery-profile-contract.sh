#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
python3 - "$ROOT" <<'PY'
import pathlib,sys
root=pathlib.Path(sys.argv[1])/'packaging/systemd'
# Model systemd's empty assignment resetting ALL monotonic triggers, then verify
# effective base+deployed override semantics. A reset-only repeat regresses boot.
keys={'OnActiveSec','OnBootSec','OnStartupSec','OnUnitActiveSec','OnUnitInactiveSec'}
def effective(files):
    timers={}
    for file in files:
        for line in file.read_text().splitlines():
            key,sep,value=line.partition('=')
            if sep and key in keys:
                if value:timers[key]=value
                else:timers.clear()
    return timers
for name,interval in [('aegis-device-policy-sync','10s'),('aegis-enrollment-policy-stage','15s')]:
    base=root/(name+'.timer');override=root/'profiles/inner-tls'/(name+'.timer.d/onboarding.conf')
    for files in ([base],[base,override]):
        timers=effective(files)
        assert timers.get('OnActiveSec')=='2s' and 'OnUnitInactiveSec' in timers and 'OnUnitActiveSec' not in timers,(name,timers)
    assert effective([base,override])['OnUnitInactiveSec']==interval
assert effective([root/'aegis-device-policy-refresh.timer'])=={'OnActiveSec':'2s','OnUnitInactiveSec':'120s'}
print('PASS: base and onboarding timers retain activation and completion-based repeat')
PY
