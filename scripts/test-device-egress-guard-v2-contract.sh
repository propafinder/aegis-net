#!/usr/bin/env bash
# Execute the production guard with inert commands and fixture-only /proc /sys.
# These are state/transaction contracts, not a claim of native packet behavior.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
export AEGIS_TEST_CLIENT_BINARY="${AEGIS_TEST_CLIENT_BINARY:-$ROOT/target/debug/aegis-client}"
managers=(systemd-networkd.service NetworkManager.service)
if [[ $# -ne 0 ]]; then
  if [[ $# -ne 2 || "${1-}" != --manager ]]; then
    printf '%s\n' 'usage: test-device-egress-guard-v2-contract.sh [--manager systemd-networkd.service|NetworkManager.service]' >&2
    exit 2
  fi
  case "$2" in
    systemd-networkd.service|NetworkManager.service) managers=("$2");;
    *) printf '%s\n' 'unknown fixture manager' >&2; exit 2;;
  esac
fi
for AEGIS_GUARD_TEST_MANAGER in "${managers[@]}"; do
export AEGIS_GUARD_TEST_MANAGER
python3 - "$ROOT" <<'PY'
import json,os,pathlib,re,shutil,subprocess,sys,tempfile
root=pathlib.Path(sys.argv[1]);count=0
manager_unit=os.environ["AEGIS_GUARD_TEST_MANAGER"];nm=manager_unit=="NetworkManager.service"
with tempfile.TemporaryDirectory(prefix='aegis-device-guard-v2-') as tmp:
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
 source=source.replace('/var/lib/aegis-install/client/device-guard.conf.lock',str(t/'global.lock'))
 source=source.replace('/var/lib/aegis-install/client/foreign-policy-drift.json',str(t/'foreign-policy-drift.json'))
 source=source.replace('/proc/$$/cgroup','/proc/321/cgroup').replace('"$control_pid" == "$$"','"$control_pid" == "321"')
 source=source.replace('selected_relay_prepare() {\n',
     'selected_relay_prepare() {\n  if [[ "${FAIL_SELECTED_PREPARE_AFTER_BAD_LEVEL:-0}" == 1 && -e "$FIXTURE/bad-level-observed" ]]; then exit 99; fi\n',1)
 source=source.replace('selected_relay_finish() {\n',
     'selected_relay_finish() {\n  printf "finish\\n" >> "$FIXTURE/selected-finish-calls"\n',1)
 # Host-side NM commands remain inert here; the separate policy contract runs
 # both actual embedded Python bodies, including filesystem crash cut points.
 if nm:
  boundary='# The pre-enrollment assessor'
  stubs='networkmanager_policy() { printf \'policy %s\\n\' "$*" >> "$FIXTURE/nm-calls"; [[ "${FAIL_NM_POLICY:-}" != "$1" ]]; }\nnetworkmanager_validate() { printf \'validate %s\\n\' "$*" >> "$FIXTURE/nm-calls"; [[ "${FAIL_NM_VALIDATE:-}" != "$1" ]]; }\n'
  assert source.count(boundary)==1;source=source.replace(boundary,stubs+boundary,1)
 # This inert transaction fixture has no live networkd/NM D-Bus or physical
 # eth0. Keep only its metadata boundary fixed to one lease/ifindex; genuine
 # acquisition, renewal and route behavior are covered by native PID1 QA.
 lease=re.compile(r'^lease_servers\(\) \{\n.*?^\}',re.M|re.S)
 assert len(lease.findall(source))==1
 source=lease.sub('lease_servers() {\n  [[ "$STATE" == "$FIXTURE/state.conf" && "$uplink" == eth0 ]] || return 93\n  [[ "${FAIL_LEASE_METADATA:-0}" == 0 ]] || return 1\n  printf "3\\t10.77.0.1\\tnone\\n"\n}',source,count=1)
 # This transaction fixture keeps nft/systemd and foreign admission inert.
 # The separate root/native foreign-policy cohorts execute the real assessor.
 # Keep this boundary closed to the one fixture state/uplink, and exercise
 # refusal below so an unassessed transient grant cannot publish a receipt.
 foreign=re.compile(r'^foreign_assessment\(\) \{\n.*?^\}',re.M|re.S)
 assert len(foreign.findall(source))==1
 stub='''foreign_assessment() {
  [[ "$STATE" == "$FIXTURE/state.conf" && "${1:-${uplink:-}}" == eth0 ]] || return 93
  printf '%s\\n' "$ACTION" >> "$FIXTURE/foreign-calls"
  [[ "${FAIL_FOREIGN_ADMISSION:-0}" == 0 ]] || return 1
  printf '%s\\n' '{"schema":"aegis_foreign_policy_v1","class":"filter_only","backend":"nf_tables"}'
}'''
 source=foreign.sub(lambda _:stub,source,count=1)
 helper=t/'guard.sh';helper.write_text(source);helper.chmod(0o755)
 shutil.copy(root/'scripts/lib/root-state.sh',t/'lib/root-state.sh')
 client='system.slice/aegis-client.service';manager='system.slice/'+manager_unit
 for group in [client,manager]:(t/'sys/fs/cgroup'/group).mkdir(parents=True)
 def put(path,text):
  p=t/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
 put('proc/321/cgroup','0::/'+client+'\n')
 put('proc/sys/kernel/random/boot_id','11111111-2222-3333-4444-555555555555\n')
 put('proc/sys/net/ipv4/ip_forward','0\n');put('proc/sys/net/ipv6/conf/all/forwarding','0\n');put('proc/cmdline','root=UUID=fixture ro\n')
 (t/'sys/class/net/eth0').mkdir(parents=True)
 (t/'sys/class/net/eth0/ifindex').write_text('3\n')
 def exe(name,body):
  p=b/name;body=body.replace('systemd-networkd.service',manager_unit);p.write_text('#!/usr/bin/env bash\nset -eu\n'+body+'\n');p.chmod(0o755)
 exe('flock','echo "$*" >> "$FIXTURE/locks"; [[ "${FAIL_LOCK:-0}" == 0 ]]')
 realstat=shutil.which('stat')
 exe('stat','''if [[ "$*" == '-f -c %T '* ]]; then echo cgroup2fs
elif [[ "$*" == '-c %i '*systemd-networkd.service ]]; then if [[ -e "$FIXTURE/post-apply-changed" ]]; then echo 333; else echo "${MANAGER_INODE:-222}"; fi
elif [[ "$*" == '-c %i '*aegis-client.service ]]; then echo "${CLIENT_INODE:-111}"
else exec '''+repr(realstat)+''' "$@"; fi''')
 exe('ip','exit 93 # v2 never reads a stale persisted address list')
 exe('systemctl','''case "$*" in
 'show aegis-client.service -p ActiveState -p ControlGroup -p InvocationID -p ControlPID --no-pager')
 printf 'ActiveState=%s\\nControlGroup=/system.slice/aegis-client.service\\nInvocationID=%s\\nControlPID=%s\\n' "${CLIENT_STATE:-active}" "${CLIENT_INVOCATION:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}" "${CONTROL_PID:-321}";;
 'show systemd-networkd.service -p ActiveState -p ControlGroup -p InvocationID -p ControlPID --no-pager')
 printf 'ActiveState=%s\\nControlGroup=/system.slice/systemd-networkd.service\\nInvocationID=%s\\nControlPID=%s\\n' "${MANAGER_STATE:-active}" "${MANAGER_INVOCATION:-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb}" "${CONTROL_PID:-321}";;
'show aegis-client.service -p ControlPID --value'|'show systemd-networkd.service -p ControlPID --value') echo "${CONTROL_PID:-321}";;
'show aegis-client.service -p ActiveState --value') echo "${CLIENT_STATE:-active}";;
'show systemd-networkd.service -p ActiveState --value') echo "${MANAGER_STATE:-active}";;
'show aegis-client.service -p ControlGroup --value') echo /system.slice/aegis-client.service;;
'show systemd-networkd.service -p ControlGroup --value') echo /system.slice/systemd-networkd.service;;
'show aegis-client.service -p InvocationID --value') echo "${CLIENT_INVOCATION:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}";;
'show systemd-networkd.service -p InvocationID --value') echo "${MANAGER_INVOCATION:-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb}";;
'is-active --quiet systemd-networkd.service') exit 0;;
'is-active --quiet '*|'is-enabled --quiet '*) exit 1;;
*) exit 93;; esac''')
 exe('nft','''case "$*" in
'--check --file -') cat > "$FIXTURE/checked.nft"; [[ "${FAIL_CHECK:-0}" == 0 ]];;
'--file -') cat > "$FIXTURE/submitted.nft"; [[ "${FAIL_APPLY:-0}" == 0 ]] || exit 1; cmp "$FIXTURE/checked.nft" "$FIXTURE/submitted.nft"; cp "$FIXTURE/submitted.nft" "$FIXTURE/table.nft"; if [[ "${CHANGE_AFTER_APPLY:-0}" == 1 ]]; then touch "$FIXTURE/post-apply-changed"; fi; if [[ "${BAD_READBACK_AFTER_APPLY:-0}" != 0 ]]; then echo "$BAD_READBACK_AFTER_APPLY" > "$FIXTURE/readback-bad"; fi;;
'--json list table inet aegis_device_guard') if [[ -e "$FIXTURE/readback-bad" ]]; then
 if [[ "$(cat "$FIXTURE/readback-bad")" == failed ]]; then exit 1; fi
 echo '{malformed'; exit 0
fi
python3 - "$FIXTURE/table.nft" <<'EOF_JSON'
import json,pathlib,re,sys
rows=[{"table":{"name":"aegis_device_guard","family":"inet"}}]
for name,hook,prio,policy in (("incoming","prerouting",-190,"accept"),("output","output",2147483647,"drop"),("forward","forward",10,"drop"),("postroute","postrouting",2147483647,"drop")):
 rows.append({"chain":{"name":name,"family":"inet","table":"aegis_device_guard","hook":hook,"prio":prio,"policy":policy}})
path=pathlib.Path(sys.argv[1])
for line in path.read_text().splitlines() if path.exists() else []:
 found=re.match(r'add rule inet aegis_device_guard (incoming|output|forward|postroute) ',line)
 if not found: continue
 chain=found[1]
 marker=re.search(r'accept comment "(aegis-v2-[a-f0-9]{64})"',line)
 if marker:
  socket=re.search(r'socket cgroupv2 level ([0-9]+) "([^"]+)"',line)
  assert socket
  expr=[]
  if 'meta nfproto' in line:
   iface=re.search(r'oifname "([^"]+)"',line);oif=re.search(r'meta oif ([1-9][0-9]*)',line)
   daddr=re.search(r'(ip|ip6) daddr (\\{[^}]+\\}|[0-9a-fA-F:.]+)',line)
   sport=re.search(r'udp sport ([0-9]+)',line);dport=re.search(r'udp dport ([0-9]+)',line)
   assert iface and oif and daddr and sport and dport
   destination=daddr[2]
   if destination.startswith('{'):
    values=[part.strip() for part in destination[1:-1].split(',')]
    assert len(values)==2 and len(set(values))==2
    destination={'set':sorted(values)}
   expr.extend([{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":iface[1]}},
                {"match":{"op":"==","left":{"meta":{"key":"oif"}},"right":iface[1]}},
                {"match":{"op":"==","left":{"payload":{"protocol":daddr[1],"field":"daddr"}},"right":destination}},
                {"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"sport"}},"right":int(sport[1])}},
                {"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":int(dport[1])}}])
  tag=int(re.search(r"meta mark set (0x[0-9a-f]+)",line)[1],0)
  expr.extend([{"match":{"op":"==","left":{"socket":{"key":"cgroupv2"}},"right":socket[2]}},{"mangle":{"key":{"meta":{"key":"mark"}},"value":tag}},{"counter":{"packets":0,"bytes":0}},{"accept":None}])
 else:
  expr=[{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"lo"}},{"accept":None}] if ' counter accept' in line else [{"drop":None}] if ' counter drop' in line else [{"mangle":{"key":"ct mark","value":"0xa3610002"}}]
 rows.append({"rule":{"family":"inet","table":"aegis_device_guard","chain":chain,"comment":marker[1] if marker else None,"handle":len(rows)+1,"expr":expr}})
print(json.dumps({"nftables":rows}))
EOF_JSON
;;
'-a list table inet aegis_device_guard') python3 - "$FIXTURE/table.nft" <<'EOF_TEXT'
import os,pathlib,re,sys
print('table inet aegis_device_guard {\\n\\tchain output {')
path=pathlib.Path(sys.argv[1]);handle=6
for line in path.read_text().splitlines() if path.exists() else []:
 if not line.startswith('add rule inet aegis_device_guard '): continue
 if re.search(r'accept comment "aegis-v2-[a-f0-9]{64}"',line):
  body=line.partition(' output ')[2]
  assert body and ' counter accept comment ' in body
  body=body.replace(' counter accept comment ',' counter packets 0 bytes 0 accept comment ')
  if os.environ.get('BAD_LEVEL_READBACK_AFTER_APPLY')=='1':
   pathlib.Path(os.environ['FIXTURE'],'bad-level-observed').touch()
   body=body.replace('socket cgroupv2 level 2 ','socket cgroupv2 level 1 ',1)
  print('\\t'+body+' # handle '+str(handle))
 handle+=1
print('\\t}\\n}')
EOF_TEXT
;;
'list table inet aegis_device_guard') [[ -e "$FIXTURE/table.nft" ]];;
*) exit 93;; esac''')
 state=t/'state.conf'
 state_text='''schema=aegis_device_guard_v2
armed=1
service=aegis-client.service
uplink=eth0
manager=systemd-networkd.service
capture_interface=aegis-tun0
management_address_policy=current_local
management_ports=22,2222
dhcp4=1
dhcp6=1
initramfs_network=absent_verified
'''
 if nm:state_text=state_text.replace('systemd-networkd.service',manager_unit)+'manager_connection_uuid=11111111-2222-3333-4444-555555555555\nmanager_ipv4_method=auto\nmanager_ipv6_method=auto\n'
 state.write_text(state_text);state.chmod(0o600)
 exe('fixture-client','''if [[ "$*" == 'profile metadata remove --path '*client-binding || "$*" == 'profile metadata remove --path '*manager-binding ]]; then
 [[ "${FAIL_REMOVE:-0}" == 0 ]] || exit 1
fi
exec '''+repr(os.environ['AEGIS_TEST_CLIENT_BINARY'])+''' "$@"''')
 env=dict(os.environ,PATH=str(b)+os.pathsep+os.environ['PATH'],FIXTURE=str(t),AEGIS_ROOT_STATE_CLIENT=str(b/'fixture-client'),AEGIS_DEVICE_GUARD_STATE=str(state))
 def run(action,extra=None,success=True):
  p=subprocess.run(['bash',str(helper),action],env=env|dict(extra or {}),capture_output=True,text=True)
  assert (p.returncode==0)==success,(action,p.returncode,p.stdout,p.stderr)
  return p
 def rules():return (t/'table.nft').read_text()
 def caller(group):put('proc/321/cgroup','0::/'+group+'\n')
 def passed():
  global count;count+=1
 run('preflight');assert not (t/'table.nft').exists();assert (t/'locks').read_text().strip()=='-w 30 -x 9';passed()
 result=run('preflight',{'FAIL_TERMINAL_PROOF':'1'},False)
 assert 'AUTO terminal current-boot source proof refused' in result.stderr and not (t/'table.nft').exists();passed()
 assert (t/'locks').read_text().splitlines()==['-w 30 -x 9','-w 30 -x 9']
 run('preflight',{'FAIL_CHECK':'1'},False);assert not (t/'table.nft').exists();passed()
 run('block');initial=rules()
 assert 'fib daddr type local tcp dport 22 ct direction original' in initial
 assert 'ct direction reply ct mark 0xa3610002 ct original proto-dst 22 tcp sport 22' in initial
 assert 'ct state { new, established } counter accept' not in initial
 assert 'socket cgroupv2' not in initial and 'udp sport 68' not in initial and 'udp sport 546' not in initial
 assert 'ct status dnat' not in initial
 assert 'flush ruleset' not in initial and initial.count('policy drop;')==3;passed()
 run('block',{'FAIL_FOREIGN_ADMISSION':'1'});assert rules()==initial
 assert 'socket cgroupv2' not in rules();passed()
 # A client caller cannot give its own cgroup the network manager permission.
 run('bind-manager',success=False);assert rules()==initial;passed()
 caller(manager);run('bind-manager',{'CONTROL_PID':'999'},False);assert rules()==initial;passed()
 prior_finishes=(t/'selected-finish-calls').read_text().count('finish')
 result=run('bind-manager',{'BAD_LEVEL_READBACK_AFTER_APPLY':'1'},False)
 assert 'manager binding readback failed' in result.stderr and rules()==initial
 assert not pathlib.Path(str(state)+'.manager-binding').exists()
 assert (t/'selected-finish-calls').read_text().count('finish')==prior_finishes+1;passed()
 (t/'bad-level-observed').unlink()
 prior_finishes=(t/'selected-finish-calls').read_text().count('finish')
 run('bind-manager',{'BAD_LEVEL_READBACK_AFTER_APPLY':'1','FAIL_SELECTED_PREPARE_AFTER_BAD_LEVEL':'1'},False)
 assert rules()==initial and not pathlib.Path(str(state)+'.manager-binding').exists()
 assert (t/'selected-finish-calls').read_text().count('finish')==prior_finishes;passed()
 (t/'bad-level-observed').unlink()
 result=run('bind-manager',{'FAIL_FOREIGN_ADMISSION':'1'},False)
 assert 'foreign policy admission refused' in result.stderr and rules()==initial
 assert not pathlib.Path(str(state)+'.manager-binding').exists()
 assert not pathlib.Path(str(state)+'.client-binding').exists();passed()
 run('bind-manager');run('manager-ready');run('manager-status');managed=rules()
 # A status reader must not take the mutation OFD away from the independent
 # monitor. A real mutation still refuses when exclusive locking fails.
 before=rules();run('manager-status',{'FAIL_LOCK':'1'})
 run('block',{'FAIL_LOCK':'1'},False);assert rules()==before;passed()
 assert f'meta oif 3 meta nfproto ipv4 ip daddr {{ 255.255.255.255, 10.77.0.1 }} udp sport 68 udp dport 67 socket cgroupv2 level 2 "{manager}" meta mark set 0xa361c002 counter accept' in managed
 assert f'meta oif 3 meta nfproto ipv6 ip6 daddr ff02::1:2 udp sport 546 udp dport 547 socket cgroupv2 level 2 "{manager}" meta mark set 0xa361c002 counter accept' in managed
 assert f'output socket cgroupv2 level 2 "{manager}"' not in managed and client not in managed
 assert 'ct status dnat' not in managed
 receipt=json.loads(pathlib.Path(str(state)+'.manager-binding').read_text());assert receipt['invocation']=='b'*32 and receipt['inode']=='222' and receipt['ifindex']==3 and receipt['dhcp4_server']=='10.77.0.1' and receipt['dhcp6_server'] is None;passed()
 caller(client);run('bind');both=rules();assert client in both and manager in both;passed()
 assert 'ip daddr 127.0.0.1 ct status dnat tcp dport 15080 counter accept' in both
 assert 'ip daddr 127.0.0.1 ct status dnat udp dport 15081 counter accept' in both
 assert both.count('ct status dnat')==4;passed()
 result=run('bind',{'FAIL_FOREIGN_ADMISSION':'1'},False)
 assert 'foreign policy admission refused' in result.stderr and 'socket cgroupv2' not in rules()
 assert not pathlib.Path(str(state)+'.manager-binding').exists()
 assert not pathlib.Path(str(state)+'.client-binding').exists();passed()
 caller(manager);run('bind-manager');caller(client);run('bind')
 # Block revokes client while retaining only the separately bound manager DHCP.
 before=rules();run('block',{'FAIL_REMOVE':'1'},False);assert rules()==before and pathlib.Path(str(state)+'.client-binding').exists();passed()
 saved_client=pathlib.Path(str(state)+'.client-binding').read_bytes()
 run('block');assert client not in rules() and manager in rules()
 assert 'ct status dnat' not in rules()
 assert not pathlib.Path(str(state)+'.client-binding').exists();passed()
 # Simulate an old receipt surviving a crashed/failed cleanup after kernel block.
 pathlib.Path(str(state)+'.client-binding').write_bytes(saved_client)
 caller(manager);run('bind-manager');assert client not in rules();passed()
 # A restart at the same path cannot inherit a deleted inode or old invocation.
 caller(client);run('bind',{'MANAGER_INODE':'223'});assert manager not in rules();passed()
 run('bind',{'MANAGER_INVOCATION':'c'*32});assert manager not in rules();passed()
 caller(manager);run('bind-manager',{'CLIENT_INVOCATION':'d'*32});assert client not in rules();passed()
 # Own restart can explicitly rebind its new incarnation without granting client.
 run('bind-manager',{'CLIENT_INVOCATION':'d'*32,'MANAGER_INODE':'223','MANAGER_INVOCATION':'e'*32})
 receipt=json.loads(pathlib.Path(str(state)+'.manager-binding').read_text());assert receipt['inode']=='223' and receipt['invocation']=='e'*32;passed()
 # Missing/inactive/tampered receipts are fail-closed and never auto-enrolled.
 caller(client);run('bind',{'MANAGER_STATE':'inactive'});assert manager not in rules();passed()
 binding=pathlib.Path(str(state)+'.manager-binding');binding.write_text('{"schema":"untrusted"}');binding.chmod(0o600)
 run('bind');assert manager not in rules();passed()
 caller(manager);run('bind-manager');caller(client)
 put('proc/sys/kernel/random/boot_id','66666666-2222-3333-4444-555555555555\n');run('bind');assert manager not in rules();passed()
 put('proc/sys/kernel/random/boot_id','11111111-2222-3333-4444-555555555555\n')
 caller(manager);run('bind-manager');caller(client)
 state.write_text(state_text.replace('management_ports=22,2222','management_ports=22'));run('bind');assert manager not in rules();passed()
 state.write_text(state_text)
 # Kill/failure prefix after durable revoke but before new rules cannot be reused.
 caller(client);run('bind');run('block',{'FAIL_APPLY':'1'},False)
 assert not pathlib.Path(str(state)+'.client-binding').exists()
 caller(manager);run('bind-manager');assert client not in rules();passed()
 caller(client);run('bind');caller(manager)
 # Recreated inode during nft apply is caught after readback, even if receipt
 # deletion fails; an old persisted receipt must not resurrect kernel authority.
 run('bind-manager',{'CHANGE_AFTER_APPLY':'1','FAIL_REMOVE':'1'},False)
 assert 'socket cgroupv2' not in rules();passed()
 run('bind-manager');assert manager in rules() and client not in rules();passed()
 (t/'post-apply-changed').unlink()
 for readback in ('failed','malformed'):
  caller(client);run('bind');caller(manager)
  result=run('bind-manager',{'BAD_READBACK_AFTER_APPLY':readback,'FAIL_REMOVE':'1'},False)
  assert 'guard JSON readback failed' in result.stderr and 'socket cgroupv2' not in rules();passed()
  (t/'readback-bad').unlink()
  run('bind-manager');assert manager in rules() and client not in rules();passed()
 before=rules();run('block',{'FAIL_LOCK':'1'},False);assert rules()==before;passed()
 for knob in ['FAIL_CHECK','FAIL_APPLY']:
  before=rules();run('block',{knob:'1'},False);assert rules()==before;passed()
 if nm:
  caller(manager);run('bind-manager');run('manager-ready');passed()
  before=rules();run('bind-manager',{'FAIL_NM_POLICY':'verify'},False);assert rules()==before;passed()
  before=rules();run('bind-manager',{'FAIL_NM_VALIDATE':'disk'},False);assert rules()==before;passed()
  run('manager-status',{'FAIL_NM_VALIDATE':'live'},False);passed()
  caller(client);run('bind');caller(manager)
  run('manager-ready',{'FAIL_NM_VALIDATE':'ready'},False)
  assert 'socket cgroupv2' not in rules() and not pathlib.Path(str(state)+'.manager-binding').exists() and not pathlib.Path(str(state)+'.client-binding').exists();passed()
  run('bind-manager');before=rules()
  run('prepare-nm-policy',{'FAIL_NM_POLICY':'prepare'},False);assert rules()==before;passed()
  run('prepare-nm-policy');assert rules()==before;passed()
  calls=(t/'nm-calls').read_text();assert 'validate ready eth0' in calls and 'policy prepare' in calls
 for changed in [state_text+'management_ipv4=192.0.2.1\n',state_text.replace('current_local','static'),state_text.replace(manager_unit,'networking.service'),state_text.replace('management_ports=22,2222\n',''),state_text.replace('management_ports=22,2222','management_ports=22;accept'),state_text+'dhcp4=1\n']:
  state.write_text(changed);before=rules();run('block',success=False);assert rules()==before;passed()
 print(f'PASS: {manager_unit}: {count} v2 state/transaction cases; dynamic-local reply qualification, DHCP-only manager binding, no caller substitution, block preservation, invocation/inode/boot/state invalidation, atomic failure retention')
PY
done
