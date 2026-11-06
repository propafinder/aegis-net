#!/usr/bin/env bash
# Actual helper + unit function, inert commands and fixture-only proc/sys paths.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
export AEGIS_TEST_CLIENT_BINARY="${AEGIS_TEST_CLIENT_BINARY:-$ROOT/target/debug/aegis-client}"
python3 - "$ROOT" <<'PY'
import hashlib,json,os,pathlib,re,shutil,subprocess,sys,tempfile
root=pathlib.Path(sys.argv[1])
with tempfile.TemporaryDirectory(prefix='aegis-device-guard-') as tmp:
 t=pathlib.Path(tmp).resolve();b=t/'bin';b.mkdir();(t/'lib').mkdir()
 source=(root/'scripts/aegis-device-egress-guard.sh').read_text()
 # Only the source-proof boundary is inert in this transaction fixture.
 # Match its exact production argv/held lock FD and retain a refusal control;
 # native PID1 cohorts execute the real boot-transition/source verifier.
 terminal=t/'lib/aegis_auto_boot_transition.py'
 terminal.write_text("import os,pathlib,sys\nassert sys.argv[1:]==['verify-consumed-under-guard','9']\nt=pathlib.Path(os.environ['FIXTURE'])\na=os.fstat(9);b=(t/'global.lock').stat()\nassert (a.st_dev,a.st_ino)==(b.st_dev,b.st_ino)\nwith (t/'terminal-proof-calls').open('a') as f:f.write('verify\\n')\nassert os.environ.get('FAIL_TERMINAL_PROOF')!='1'\n")
 boundary='/usr/local/lib/aegis/helpers/lib/aegis_auto_boot_transition.py'
 assert source.count(boundary)==1
 source=source.replace(boundary,str(terminal))
 source=re.sub(r'(?<![A-Za-z0-9_/])/(?:sys|proc|etc/systemd/system|etc/ufw)(?=/)',lambda m:str(t)+m.group(),source)
 # Stable fixture PID; production continues using the actual shell PID.
 source=source.replace('/var/lib/aegis-install/client/device-guard.conf.lock',str(t/'global.lock'))
 source=source.replace('/var/lib/aegis-install/client/foreign-policy-drift.json',str(t/'foreign-policy-drift.json'))
 source=source.replace('/var/lib/aegis-install/client/auto-clean-shutdown-once.json',str(t/'auto-clean-shutdown-once.json'))
 source=source.replace('/proc/$$/cgroup','/proc/321/cgroup')
 # This inert transaction fixture has no live eth0 or networkd D-Bus. The
 # lease reader boundary is fixed to the fixture's one uplink and no lease;
 # real manager metadata and DHCP renewal execute in native PID1 QA.
 lease=re.compile(r'^lease_servers\(\) \{\n.*?^\}',re.M|re.S)
 assert len(lease.findall(source))==1
 source=lease.sub('lease_servers() {\n  [[ "$uplink" == eth0 && "$STATE" == "$FIXTURE/state.conf" ]] || return 93\n  printf "3\\tnone\\tnone\\n"\n}',source,count=1)
 helper=t/'guard.sh';helper.write_text(source);helper.chmod(0o755)
 shutil.copy(root/'scripts/lib/root-state.sh',t/'lib/root-state.sh')
 for name,text in [('sys/fs/cgroup/system.slice/aegis-client.service/cgroup.procs','321\n'),('proc/321/cgroup','0::/system.slice/aegis-client.service\n'),('proc/sys/net/ipv4/ip_forward','0\n'),('proc/sys/net/ipv6/conf/all/forwarding','0\n'),('proc/sys/kernel/random/boot_id','11111111-2222-3333-4444-555555555555\n'),('proc/cmdline','root=UUID=fixture ro\n')]:
  f=t/name;f.parent.mkdir(parents=True,exist_ok=True);f.write_text(text)
 (t/'sys/class/net/eth0').mkdir(parents=True)
 (t/'sys/class/net/eth0/ifindex').write_text('3\n')
 def exe(name,body):
  p=b/name;p.write_text('#!/usr/bin/env bash\nset -eu\n'+body+'\n');p.chmod(0o755)
 realstat=shutil.which('stat')
 exe('stat','''if [[ "$*" == "-f -c %T "* ]]; then echo cgroup2fs; exit; fi
if [[ "$*" == "-c %i "* ]]; then echo 111; exit; fi
exec '''+repr(realstat)+''' "$@"''')
 exe('flock',': # inert fixture only')
 exe('ip','''if [[ "$*" == '-j address show dev eth0' ]]; then echo '[{"addr_info":[{"local":"192.0.2.1"}]}]'; exit; fi
if [[ "$*" == '-o link show' ]]; then echo '1: lo: <LOOPBACK>'; exit; fi
exit 91''')
 exe('systemctl','''echo "$*" >> "$FIXTURE/systemd.log"
case "$*" in
'show aegis-device-egress-guard.service -p ActiveState --value') if [[ -e "$FIXTURE/guard-active" ]]; then echo active; else echo inactive; fi;;
'show aegis-foreign-policy-monitor.service -p MainPID --value') echo 0;;
'show aegis-client.service -p ActiveState -p ControlGroup -p InvocationID -p ControlPID --no-pager') printf 'ActiveState=activating\\nControlGroup=/system.slice/aegis-client.service\\nInvocationID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\nControlPID=0\\n';;
*'-p ActiveState'*) echo activating;;
*'-p ControlGroup'*) echo /system.slice/aegis-client.service;;
'is-active --quiet aegis-device-egress-guard.service') [[ -e "$FIXTURE/guard-active" ]];;
'is-active --quiet aegis-device-dhcp-refresh.timer') [[ -e "$FIXTURE/dhcp-timer-active" ]];;
'start aegis-device-egress-guard.service') touch "$FIXTURE/guard-active";;
'start aegis-device-dhcp-refresh.timer') touch "$FIXTURE/dhcp-timer-active";;
'stop aegis-device-dhcp-refresh.timer aegis-device-dhcp-refresh.service') rm -f "$FIXTURE/dhcp-timer-active";;
'disable --now aegis-device-egress-guard.service') :;; # old Requires/socket race cancels stop
'disable aegis-device-egress-guard.service aegis-foreign-policy-monitor.service') grep -q '^armed=0$' "$AEGIS_DEVICE_GUARD_STATE"; [[ "${FAIL_DISABLE:-0}" == 0 ]];;
'stop aegis-device-egress-guard.service')
 [[ ! -e "$FIXTURE/etc/systemd/system/systemd-networkd.service.d/30-aegis-device-guard.conf" ]]
 [[ "${FAIL_STOP:-0}" == 0 ]] || exit 1
 rm -f "$FIXTURE/guard-active";;
'is-active --quiet systemd-networkd.service') [[ "${BAD_MANAGER:-0}" == 0 ]];;
'is-active --quiet '*) exit 1;;
'is-enabled --quiet '*) [[ "${ENABLED_OTHER:-0}" == 1 ]];;
'list-unit-files'*) :;;
*) [[ "${FAIL_SYSTEMD:-0}" == 0 ]];; esac''')
 # nft fixture preserves old table on check/apply failure and records exact bytes.
 exe('nft','''case "$*" in
'--check --file -') cat > "$FIXTURE/checked.nft"; [[ "${FAIL_CHECK:-0}" == 0 ]];;
'--file -') cat > "$FIXTURE/submitted.nft"; [[ "${FAIL_APPLY:-0}" == 0 ]] || exit 1; cmp "$FIXTURE/checked.nft" "$FIXTURE/submitted.nft"; cp "$FIXTURE/submitted.nft" "$FIXTURE/table.nft";;
'--json list table inet aegis_device_guard') python3 - "$FIXTURE/table.nft" <<'EOF_JSON'
import json,pathlib,re,sys
rows=[{"table":{"name":"aegis_device_guard","family":"inet"}}]
for name,hook,prio,policy in (("incoming","prerouting",-190,"accept"),("output","output",2147483647,"drop"),("forward","forward",10,"drop"),("postroute","postrouting",2147483647,"drop")):
 rows.append({"chain":{"name":name,"family":"inet","table":"aegis_device_guard","hook":hook,"prio":prio,"policy":policy}})
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
 found=re.match(r'add rule inet aegis_device_guard (incoming|output|forward|postroute) ',line)
 if not found:continue
 expr=[{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"lo"}},{"accept":None}] if ' counter accept' in line else [{"drop":None}] if ' counter drop' in line else [{"mangle":{"key":"ct mark","value":"0xa3610002"}}]
 rows.append({"rule":{"family":"inet","table":"aegis_device_guard","chain":found[1],"expr":expr}})
print(json.dumps({"nftables":rows}))
EOF_JSON
;;
'list table inet aegis_device_guard') [[ -e "$FIXTURE/table.nft" ]];;
'list tables') [[ "${FAIL_LIST:-0}" == 0 ]] || exit 1; if [[ -e "$FIXTURE/table.nft" ]]; then echo 'table inet aegis_device_guard'; fi;;
'delete table inet aegis_device_guard')
 grep -q '^armed=0$' "$AEGIS_DEVICE_GUARD_STATE"
 [[ ! -e "$FIXTURE/guard-active" && ! -e "$FIXTURE/etc/systemd/system/aegis-device-egress-guard.service" ]]
 [[ "${FAIL_DELETE:-0}" == 0 ]] || exit 1; rm "$FIXTURE/table.nft";;
*) exit 92;; esac''')
 for cmd in ['iptables-save','ip6tables-save']:exe(cmd,':')
 recovery=t/'aegis-wide-disable.sh';recovery.write_text('#!/usr/bin/env bash\nexit "${FAIL_RECOVERY:-0}"\n');recovery.chmod(0o755)
 state=t/'state.conf'
 state_text='''schema=aegis_device_guard_v1
armed=1
service=aegis-client.service
uplink=eth0
manager=systemd-networkd.service
capture_interface=aegis-tun0
management_ipv4=192.0.2.1
management_ipv6=
management_ports=22,2222
dhcp4=0
dhcp6=0
initramfs_network=absent_verified
'''
 state.write_text(state_text);state.chmod(0o600)
 env=dict(os.environ,PATH=str(b)+os.pathsep+os.environ['PATH'],FIXTURE=str(t),AEGIS_ROOT_STATE_CLIENT=os.environ['AEGIS_TEST_CLIENT_BINARY'],AEGIS_DEVICE_GUARD_STATE=str(state))
 def run(action,extra=None,success=True):
  p=subprocess.run(['bash',str(helper),action],env=env|dict(extra or {}),capture_output=True,text=True)
  assert (p.returncode==0)==success,(action,p.returncode,p.stdout,p.stderr)
  return p
 run('preflight');assert not (t/'table.nft').exists()
 run('block');blocked=(t/'table.nft').read_text()
 assert blocked.count('policy drop;')==3 and 'flush ruleset' not in blocked
 assert 'hook output priority 2147483647;' in blocked and 'socket cgroupv2' not in blocked
 assert 'ct direction reply ct mark' in blocked and 'iifname "eth0" ip daddr 192.0.2.1 tcp dport 22' in blocked
 assert 'ct original ip daddr 192.0.2.1 ct original proto-dst 22 tcp sport 22' in blocked
 assert 'udp sport 68' not in blocked and 'udp sport 546' not in blocked
 state.write_text(state_text.replace('dhcp4=0','dhcp4=1').replace('dhcp6=0','dhcp6=1'))
 run('block');bootstrap=(t/'table.nft').read_text()
 assert 'oifname "eth0" ip daddr 255.255.255.255 udp sport 68 udp dport 67' in bootstrap
 assert 'oifname "eth0" ip6 saddr fe80::/10 ip6 daddr ff02::1:2 udp sport 546 udp dport 547' in bootstrap
 state.write_text(state_text)
 run('bind');bound=(t/'table.nft').read_text();assert 'socket cgroupv2 level 2 "system.slice/aegis-client.service"' in bound
 for knob in ['FAIL_CHECK','FAIL_APPLY']:
  run('block',{knob:'1'},False);assert (t/'table.nft').read_text()==bound
 for old,new in [('capture_interface=aegis-tun0','capture_interface=user0'),('initramfs_network=absent_verified','initramfs_network=unknown'),('management_ports=22,2222','management_ports=22;accept'),('uplink=eth0','uplink=eth0 x'),('management_ipv6=','management_ipv6=fe80::1%eth0; accept')]:
  state.write_text(state_text.replace(old,new));run('block',success=False);assert (t/'table.nft').read_text()==bound
 state.write_text(state_text)
 run('preflight',{'BAD_MANAGER':'1'},False)
 run('preflight',{'ENABLED_OTHER':'1'},False)
 (t/'proc/sys/net/ipv4/ip_forward').write_text('1\n');run('preflight',success=False);(t/'proc/sys/net/ipv4/ip_forward').write_text('0\n')
 (t/'sys/class/net/docker0').mkdir();run('preflight',success=False);(t/'sys/class/net/docker0').rmdir()
 (t/'proc/cmdline').write_text('root=fixture ip=dhcp\n');run('preflight',success=False);(t/'proc/cmdline').write_text('root=fixture\n')
 run('release',success=False)
 run('recover',{'FAIL_RECOVERY':'1'},False);assert (t/'table.nft').exists() and 'armed=1' in state.read_text()
 # Executed unit renderer with inert installation/systemd, exact helper preflight.
 install=(root/'install.sh').read_text();fn=re.search(r'^install_device_egress_guard_units\(\) \{\n.*?^\}',install,re.M|re.S).group()
 fn=fn.replace('/var/lib/aegis-install/client/device-guard.conf',str(state)).replace('/etc/systemd/system',str(t/'etc/systemd/system')).replace('/usr/local/lib/aegis/helpers',str(t/'installed')).replace('/var/lib/aegis-install/client/ufw-before-guard.json',str(t/'ufw-before-guard.json'))
 inspector=t/'inspector';inspector.write_text('#!/usr/bin/env bash\n[[ "${BAD_PROFILE:-0}" == 0 ]] || exit 1\nif [[ "$*" == "device bundle-inspect --bundle-dir fixture-public-v2 --json" ]]; then\n'+  '''cat <<'EOF'
{"schema":"aegis_device_bundle_v2","product_mode":"full-wide-tun","udp":true,"resolved":{"capture_scope":"local_host","tcp_transport":"grpc_stream","udp_transport":"grpc_datagram","inner_tls":true,"native_fallback":false,"requires_privileged_capture":true,"dns_policy":"preview","ipv6_policy":"tun_carried"}}
EOF
else
exec '''+repr(os.environ['AEGIS_TEST_CLIENT_BINARY'])+' "$@"\nfi\n');inspector.chmod(0o755)
 ir=t/'install-root';(ir/'scripts/lib').mkdir(parents=True);shutil.copy(helper,ir/'scripts/aegis-device-egress-guard.sh');shutil.copy(root/'scripts/lib/root-state.sh',ir/'scripts/lib/root-state.sh')
 units=t/'etc/systemd/system';units.mkdir(parents=True)
 sh=t/'units.sh';sh.write_text('set -eu\n'+fn+'\ninstall_copy_file() { cp "$1" "$2"; chmod "$3" "$2"; }\ninstall_atomic_write() { cat > "$1"; }\ninstall_device_egress_guard_units "$AEGIS_DEVICE_GUARD_STATE" systemd-networkd.service fixture-public-v2\n')
 unit_env=env|{'ROOT':str(ir),'AEGIS_WIDE_LIB_DIR':str(t/'installed'),'SYSTEMD_DIR':str(units),'AEGIS_ROOT_STATE_CLIENT':str(inspector)}
 p=subprocess.run(['bash',str(sh)],env=unit_env|{'BAD_PROFILE':'1'},capture_output=True,text=True)
 assert p.returncode!=0 and not (t/'installed').exists() and not list(units.iterdir()),(p.returncode,p.stderr)
 # This lifecycle fixture keeps the foreign snapshot command inert, as it does
 # nft/systemd. Actual foreign/UFW semantics execute in their own root cohort.
 # Admit only the literal private fixture output, and prove its refusal stops
 # unit publication before the successful lifecycle/recovery cases below.
 foreign=t/'installed/lib/aegis_auto_foreign_policy.py';foreign.parent.mkdir(parents=True)
 foreign.write_text("import os,pathlib,sys\nassert sys.argv[1:]==['--snapshot',"+repr(str(t/'ufw-before-guard.json'))+"]\nassert os.environ.get('FAIL_FOREIGN_SNAPSHOT')!='1'\npathlib.Path(sys.argv[2]).write_text('fixture-only\\n')\n")
 p=subprocess.run(['bash',str(sh)],env=unit_env|{'FAIL_FOREIGN_SNAPSHOT':'1'},capture_output=True,text=True)
 assert p.returncode!=0 and not list(units.iterdir()),(p.returncode,p.stderr)
 p=subprocess.run(['bash']+(['-x'] if os.environ.get('AEGIS_TEST_TRACE')=='1' else [])+[str(sh)],env=unit_env,capture_output=True,text=True);assert p.returncode==0,(p.returncode,p.stderr)
 assert (t/'ufw-before-guard.json').read_text()=='fixture-only\n'
 unit=(units/'aegis-device-egress-guard.service').read_text();assert 'Before=network-pre.target' in unit and 'Wants=network-pre.target' in unit and 'DefaultDependencies=no' in unit
 assert not any(x.startswith('ExecStop=') or x.startswith('PartOf=') for x in unit.splitlines())
 manager=(units/'systemd-networkd.service.d/30-aegis-device-guard.conf').read_text();assert 'Requires=aegis-device-egress-guard.service' in manager and 'After=aegis-device-egress-guard.service' in manager
 client=(units/'aegis-client.service.d/30-device-egress-guard.conf').read_text();assert 'ExecStartPre=' in client and ' bind\n' in client and 'ExecStopPost=' in client and ' block\n' in client
 assert 'ExecStartPost=/bin/bash '+str(t/'installed/aegis-device-egress-guard.sh')+' capture-bind-legacy\n' in client
 # Durable release precedes boot-ownership removal. Failure leaves the table
 # and a retryable armed=0 record, including when all old units still exist.
 run('recover',{'FAIL_DISABLE':'1'},False)
 assert 'armed=0' in state.read_text() and (t/'table.nft').exists()
 assert (units/'aegis-device-egress-guard.service').exists() and (t/'guard-active').exists()
 # Detach dependencies before stop, so a manager's socket activation cannot
 # cancel the stop. A failed detached stop also remains safely retryable.
 run('recover',{'FAIL_STOP':'1'},False)
 assert 'armed=0' in state.read_text() and (t/'table.nft').exists() and (t/'guard-active').exists()
 assert not (units/'systemd-networkd.service.d/30-aegis-device-guard.conf').exists()
 run('recover',{'FAIL_DELETE':'1'},False);assert 'armed=0' in state.read_text() and (t/'table.nft').exists()
 assert not (t/'guard-active').exists()
 assert not (units/'aegis-device-egress-guard.service').exists() and not (units/'systemd-networkd.service.d/30-aegis-device-guard.conf').exists()
 run('recover');assert not (t/'table.nft').exists();run('recover')
 assert 'disable --now aegis-device-egress-guard.service' not in (t/'systemd.log').read_text()
 # v2 adds a single fixed privileged pre-start hook to the selected manager;
 # the original v1 unit and lifecycle cases above remain unchanged.
 v2=state_text.replace('schema=aegis_device_guard_v1','schema=aegis_device_guard_v2').replace('management_ipv4=192.0.2.1\nmanagement_ipv6=','management_address_policy=current_local')
 state.write_text(v2)
 result=run('preflight',{'FAIL_TERMINAL_PROOF':'1'},False)
 assert 'AUTO terminal current-boot source proof refused' in result.stderr and not (t/'table.nft').exists()
 boot=t/'proc/sys/kernel/random/boot_id';boot.parent.mkdir(parents=True,exist_ok=True);boot.write_text('11111111-2222-3333-4444-555555555555\n')
 p=subprocess.run(['bash']+(['-x'] if os.environ.get('AEGIS_TEST_TRACE')=='1' else [])+[str(sh)],env=unit_env,capture_output=True,text=True);assert p.returncode==0,(p.returncode,p.stderr)
 manager=(units/'systemd-networkd.service.d/30-aegis-device-guard.conf').read_text()
 assert 'Requires=aegis-device-egress-guard.service' in manager
 assert 'ExecStartPre=+/usr/bin/nsenter --mount=/proc/1/ns/mnt --root=/proc/1/root -- /bin/bash '+str(t/'installed/aegis-device-egress-guard.sh')+' bind-manager' in manager
 assert 'ExecStartPost=+/usr/bin/nsenter --mount=/proc/1/ns/mnt --root=/proc/1/root -- /bin/bash '+str(t/'installed/aegis-device-egress-guard.sh')+' manager-ready' in manager and 'TimeoutStartSec=90' in manager
 assert 'User=root' not in manager and 'ExecStart=\n' not in manager and 'ExecStartPre=\n' not in manager
 p=subprocess.run(['bash',str(sh)],env=unit_env|{'DEVICE_ONLINE':'1'},capture_output=True,text=True);assert p.returncode==0,(p.returncode,p.stderr)
 assert 'TimeoutStartSec=180' in (units/'aegis-client.service.d/30-device-egress-guard.conf').read_text()
 # NM unit staging and cleanup use the actual renderer/lifecycle, with only
 # NM command/storage boundaries inert (storage crash behavior tested separately).
 for path in units.rglob('*'):
  if path.is_file():path.unlink()
 (t/'guard-active').unlink(missing_ok=True)
 nm_state=v2.replace('systemd-networkd.service','NetworkManager.service')+'manager_connection_uuid=11111111-2222-3333-4444-555555555555\nmanager_ipv4_method=manual\nmanager_ipv6_method=disabled\n'
 state.write_text(nm_state)
 nm_stubs='networkmanager_policy() {\n  printf \'policy %s\\n\' "$*" >> "$FIXTURE/nm-stage.log"\n  if [[ "$1" == remove ]]; then grep -q \'^armed=0$\' "$AEGIS_DEVICE_GUARD_STATE" && [[ -e "$FIXTURE/table.nft" ]] || return 98; fi\n  [[ "${FAIL_NM_POLICY:-}" != "$1" ]]\n}\nnetworkmanager_validate() { :; }\n'
 nm_source=source.replace('# The pre-enrollment assessor',nm_stubs+'# The pre-enrollment assessor',1)
 (ir/'scripts/aegis-device-egress-guard.sh').write_text(nm_source)
 systemctl=b/'systemctl';systemctl.write_text(systemctl.read_text().replace('systemd-networkd.service','NetworkManager.service'))
 nm_sh=t/'nm-units.sh';nm_sh.write_text(sh.read_text().replace('"$AEGIS_DEVICE_GUARD_STATE" systemd-networkd.service fixture-public-v2','"$AEGIS_DEVICE_GUARD_STATE" NetworkManager.service fixture-public-v2').replace('install_atomic_write() { cat > "$1"; }','install_atomic_write() { printf "unit %s\\n" "$1" >> "$FIXTURE/nm-stage.log"; cat > "$1"; }'))
 p=subprocess.run(['bash',str(nm_sh)],env=unit_env|{'DEVICE_ONLINE':'1','FAIL_NM_POLICY':'prepare'},capture_output=True,text=True)
 assert p.returncode!=0 and not list(units.rglob('*.conf')) and not (units/'aegis-device-egress-guard.service').exists(),p.stderr
 p=subprocess.run(['bash',str(nm_sh)],env=unit_env|{'DEVICE_ONLINE':'1'},capture_output=True,text=True);assert p.returncode==0,p.stderr
 nm_unit=(units/'NetworkManager.service.d/30-aegis-device-guard.conf').read_text()
 assert 'ExecStartPre=+/usr/bin/nsenter --mount=/proc/1/ns/mnt --root=/proc/1/root -- /bin/bash '+str(t/'installed/aegis-device-egress-guard.sh')+' bind-manager' in nm_unit
 assert 'ExecStartPost=+/usr/bin/nsenter --mount=/proc/1/ns/mnt --root=/proc/1/root -- /bin/bash '+str(t/'installed/aegis-device-egress-guard.sh')+' manager-ready' in nm_unit and 'TimeoutStartSec=90' in nm_unit
 events=(t/'nm-stage.log').read_text();assert events.index('policy prepare')<events.index('unit ')
 helper.write_text(nm_source)
 run('block')
 run('recover',{'FAIL_NM_POLICY':'remove'},False)
 assert 'armed=0' in state.read_text() and (t/'table.nft').exists() and (units/'NetworkManager.service.d/30-aegis-device-guard.conf').exists()
 run('recover');assert not (t/'table.nft').exists() and not (units/'NetworkManager.service.d/30-aegis-device-guard.conf').exists()
 print('PASS: nft atomic bytes/old-table retention, strict typed state, first-arm forwarding/manager/initramfs rejection, narrow SSH tuple, actual unit dependencies, recovery-last failure/retry/idempotency')
PY
