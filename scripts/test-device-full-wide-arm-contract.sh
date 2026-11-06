#!/usr/bin/env bash
# Executes the actual arm transaction with inert service/firewall/probe tools.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
python3 - "$ROOT" <<'PY'
import hashlib,os,pathlib,re,subprocess,sys,tempfile
root=pathlib.Path(sys.argv[1]);text=(root/'install.sh').read_text()
lock_source=re.search(r'^device_guard_assessment_lock_ensure\(\) \{\n.*?^\}',text,re.M|re.S).group()
device_source=re.search(r'^activate_device_full_wide_capture\(\) \{\n.*?^\}',text,re.M|re.S).group()
first_arm=text[text.index('auto_v2_first_arm() ('):text.index('\n)\n',text.index('auto_v2_first_arm() ('))]
assert device_source.count('device_guard_assessment_lock_ensure || return 1')==1
assert first_arm.count('device_guard_assessment_lock_ensure || return 1')==1
assert device_source.index('install_device_egress_guard_units ')<device_source.index('device_guard_assessment_lock_ensure || return 1')<device_source.index('bash "$guard" block')<device_source.index('systemctl start aegis-device-egress-guard.service')
assert first_arm.index('install_device_egress_guard_units ')<first_arm.index('device_guard_assessment_lock_ensure || return 1')<first_arm.index('auto_guard block')<first_arm.index('systemctl start aegis-device-egress-guard.service')
functions='\n'.join(re.search(r'^'+name+(r'\(\) \{\n.*?^PY\n\}' if name=='inject_client_service_state_path' else r'\(\) \{\n.*?^\}'),text,re.M|re.S).group() for name in ['inject_client_service_state_path','device_validate_config','device_bundle_render','device_relay_geneva_absent','device_relay_geneva_verify_snapshot','device_relay_geneva_install_selected','device_full_wide_arm_failure','activate_device_full_wide_capture'])
with tempfile.TemporaryDirectory(prefix='aegis-arm-contract-') as tmp:
 t=pathlib.Path(tmp).resolve()
 for scenario in ['', 'identity','validate-stage','preflight','first-block','commit','copy-final','validate-final','readiness','capture','probes','persist','v2-success','assessment-lock-symlink','assessment-lock-nonempty','assessment-lock-mode','manager-restart','manager-readback','nm-success','nm-manager-restart','nm-manager-readback','selected-success','selected-stage','selected-readiness','selected-capture']:
  nm=scenario.startswith('nm-');manager='NetworkManager.service' if nm else 'systemd-networkd.service'
  selected=scenario.startswith('selected-')
  guard_v2=selected or nm or scenario in ('v2-success','assessment-lock-symlink','assessment-lock-nonempty','assessment-lock-mode','manager-restart','manager-readback')
  fail_at='' if scenario in ('v2-success','nm-success','selected-success') else scenario.removeprefix('nm-').removeprefix('selected-')
  case=t/(scenario or 'success');case.mkdir();(case/'state').mkdir();(case/'config').mkdir();(case/'lib').mkdir();(case/'root/scripts').mkdir(parents=True);(case/'bundle').mkdir();(case/'identity').mkdir()
  lock=case/'state/device-guard.conf.assessment.lock'
  if scenario=='assessment-lock-symlink':
   target=case/'foreign-lock-target';target.write_bytes(b'foreign\n');lock.symlink_to(target)
  elif scenario=='assessment-lock-nonempty':
   lock.write_bytes(b'foreign\n');lock.chmod(0o600)
  elif scenario=='assessment-lock-mode':
   lock.touch();lock.chmod(0o644)
  for filename in ['outer-ca.pem','inner-ca.pem']:(case/'bundle'/filename).write_text('fixture public certificate\n')
  assessment=case/'assessment.conf';assessment.write_text(('schema=aegis_device_guard_v'+('2' if guard_v2 else '1')+'\narmed=1\nmanager=systemd-networkd.service\n').replace('systemd-networkd.service',manager))
  client=case/'client';client.write_text('''#!/usr/bin/env python3
import json,os,pathlib,sys
args=sys.argv[1:];root=pathlib.Path(os.environ['FIXTURE']);fail=os.environ.get('FAIL_AT','')
with (root/'calls').open('a') as f:f.write('cli '+ ' '.join(args)+'\\n')
def arg(k):return args[args.index(k)+1]
if args[:2]==['device','bundle-inspect']:print(json.dumps({'schema':'aegis_device_bundle_v2'}))
elif args[:2]==['device','status']:
 if fail=='identity':sys.exit(1)
 print(json.dumps({'phase':'ready'}))
elif args[:2]==['device','bundle-render']:
 if os.environ.get('SELECTED')=='1':
  for flag,key in [('--relay-geneva-request','DEVICE_RELAY_GENEVA_REQUEST'),('--relay-geneva-request-sha256','DEVICE_RELAY_GENEVA_REQUEST_SHA256'),('--relay-geneva-profile-manifest','DEVICE_RELAY_GENEVA_MANIFEST'),('--relay-geneva-profile-sha256','DEVICE_RELAY_GENEVA_MANIFEST_SHA256')]:assert arg(flag)==os.environ[key]
 else:assert not any('relay-geneva-' in part for part in args)
 pathlib.Path(arg('--output')).write_text('fixture_config_inner_tls_grpc\\nconfig_dir='+arg('--config-dir')+'\\n')
elif args[:3]==['profile','metadata','validate']:pass
elif args[:3]==['profile','metadata','read']:print(pathlib.Path(arg('--path')).read_text(),end='')
elif '--validate-config' in args:
 is_stage=arg('--config').endswith('/check.toml')
 if fail==('validate-stage' if is_stage else 'validate-final'):sys.exit(1)
 assert 'fixture_config_inner_tls_grpc' in pathlib.Path(arg('--config')).read_text()
 assert 'state_path = '+chr(34)+str(root/'runtime/state.json')+chr(34) in pathlib.Path(arg('--config')).read_text()
else:raise AssertionError(args)
''');client.chmod(0o755)
  helper='''#!/usr/bin/env bash
set -eu
printf '%s %s\\n' "$(basename "$0")" "$*" >> "$FIXTURE/calls"
case "$(basename "$0"):$*" in
setup-wide-linux-redirect.sh:cgroup-path) echo system.slice/aegis-client.service;;
setup-wide-linux-redirect.sh:apply) [[ "${FAIL_AT:-}" != capture ]] || exit 1
 [[ "$AEGIS_WIDE_REQUIRE_CGROUP" == 1 && "$AEGIS_WIDE_EXEMPT_SERVICE" == aegis-client.service && "$AEGIS_WIDE_EXEMPT_CGROUP" == system.slice/aegis-client.service ]]
 [[ -z "$AEGIS_WIDE_RELAY_EXCLUDE_IPS$AEGIS_EXEMPT_UID$AEGIS_DIRECT_SOCKET_MARK" ]]
 [[ "$AEGIS_WIDE_UDP_REDIRECT_PORT" == 15081 && "$AEGIS_WIDE_IPV6_TUN_DEV" == aegis-tun0 ]];;
aegis-device-egress-guard.sh:manager-status) [[ "${FAIL_AT:-}" != manager-readback ]];;
aegis-device-egress-guard.sh:block) [[ -e "$AEGIS_DEVICE_GUARD_STATE" ]]; [[ "${FAIL_AT:-}" != first-block ]] || exit 1; touch "$FIXTURE/table-blocked";;
*:recover|*:release|*:teardown) echo ILLEGAL_NATIVE_ROLLBACK >> "$FIXTURE/calls"; exit 99;;
esac
'''
  for name in ['aegis-device-egress-guard.sh','setup-wide-linux-redirect.sh','aegis-wide-disable.sh','aegis-wide-persist-install.sh','aegis-wide-enable.sh','janitor-wide-linux-tproxy.sh']:
   p=case/'root/scripts'/name;p.write_text(helper);p.chmod(0o755)
  # Execute the real lock helper on a disposable current-user fixture. Only
  # its fixed root path and expected owner are adapted; O_EXCL/O_NOFOLLOW,
  # mode, zero length, inode readback and fsync remain the source code.
  lock_fixture=lock_source.replace('device_guard_assessment_lock_ensure() {','source_device_guard_assessment_lock_ensure() {',1)
  lock_fixture=lock_fixture.replace('/var/lib/aegis-install/client',str(case/'state'))
  # macOS system Python predates pathlib's follow_symlinks parameter; lstat
  # has the same no-follow semantics for this isolated fixture.
  lock_fixture=lock_fixture.replace('path.parent.stat(follow_symlinks=False)','path.parent.lstat()')
  lock_fixture=lock_fixture.replace('path.stat(follow_symlinks=False)','path.lstat()')
  lock_fixture=lock_fixture.replace('parent.st_uid==parent.st_gid==0','parent.st_uid==os.getuid() and parent.st_gid==os.getgid()')
  lock_fixture=lock_fixture.replace('item.st_uid==item.st_gid==0','item.st_uid==os.getuid() and item.st_gid==os.getgid()')
  assert "device-guard.conf.assessment.lock" in lock_fixture and '==0' not in lock_fixture.split('parent=',1)[1].split('created=',1)[0]
  body=lock_fixture+'\n'+functions.replace('/var/lib/aegis-install/client',str(case/'state')).replace('/etc/aegis/client/aegis.toml',str(case/'config/aegis.toml')).replace('/var/lib/aegis-client',str(case/'runtime')).replace('/usr/local/lib/aegis',str(case/'selected-lib')).replace('/etc/systemd/system',str(case/'systemd')).replace('/run/aegis-relay-geneva',str(case/'selected-native'))
  (case/'root/scripts/lib').mkdir();(case/'root/scripts/lib/root-state.sh').write_text('# synthetic prerequisite\n')
  (case/'root/tools/geneva').mkdir(parents=True)
  (case/'root/tools/geneva/install-relay-profile.sh').write_text('''#!/bin/bash
set -eu
[[ "$1" == --manifest && "$2" == "$DEVICE_RELAY_GENEVA_MANIFEST" ]]
[[ -s "$FIXTURE/config/aegis.toml" && -s "$FIXTURE/state/device-guard.conf" && -e "$FIXTURE/table-blocked" ]]
[[ -f "$FIXTURE/selected-lib/lib/root-state.sh" && -f "$FIXTURE/selected-lib/aegis-device-egress-guard.sh" ]]
printf 'selected-stopped-stage\\n' >> "$FIXTURE/calls"
touch "$FIXTURE/refusing-selected-gate"
[[ "${FAIL_AT:-}" != stage ]]
''')
  stubs='''
TEMP_PATHS=()
log() { printf '%s\\n' "$*" >> "$FIXTURE/calls"; }
ensure_dir() { [[ "$1" == "$FIXTURE/"* ]] || return 97; mkdir -p "$1"; }
install_copy_file() {
 [[ "$2" == "$FIXTURE/"* ]] || return 97
 log "copy $2"
 [[ "${FAIL_AT:-}" != copy-final || "$2" != "$FIXTURE/config/aegis.toml" ]] || return 1
 cp "$1" "$2"; chmod "$3" "$2"
}
install_atomic_write() {
 [[ "$1" == "$FIXTURE/"* ]] || return 97
 log "write $1"
 [[ "${FAIL_AT:-}" != commit || "$1" != "$FIXTURE/state/device-guard.conf" ]] || return 1
 cat > "$1"
}
install_device_egress_guard_units() {
 log 'stage-dependencies'
 [[ "$5" == stage && -s "$4" ]] || return 96
 [[ "${FAIL_AT:-}" != preflight ]] || return 1
 cp "$ROOT/scripts/aegis-device-egress-guard.sh" "$AEGIS_WIDE_LIB_DIR/"
}
device_guard_assessment_lock_ensure() {
 log assessment-lock
 source_device_guard_assessment_lock_ensure
}
systemctl() {
 log "systemctl $*"
 if [[ "$GUARD_V2" == 1 && "$*" == 'start aegis-device-egress-guard.service' ]]; then
  [[ -f "$FIXTURE/state/device-guard.conf.assessment.lock" ]] || return 98
 fi
 [[ "$*" != 'restart systemd-networkd.service' || "${FAIL_AT:-}" != manager-restart ]]
}
install_client_ipv6_tun_dropin() { log capability-dropin; [[ "$PRODUCT_MODE" == full-wide-tun ]]; }
restart_systemd_unit_checked() { log notify-readiness; [[ "${FAIL_AT:-}" != readiness ]]; }
device_full_wide_probes() { log secure-probes; [[ "${FAIL_AT:-}" != probes ]]; }
install_wide_tun_boot_unit() { log capture-persistence; [[ "${FAIL_AT:-}" != persist ]]; }
activate_wide_capture() { log ILLEGAL_LEGACY_MUTATOR; return 99; }
inject_client_default_primary_socks5() { log ILLEGAL_SOCKS_FALLBACK; return 99; }
activate_device_full_wide_capture "$FIXTURE/bundle" "$FIXTURE/identity" "$FIXTURE/config/aegis.toml" "$FIXTURE/assessment.conf"
'''
  script=case/'run.sh';script.write_text('set -euo pipefail\n'+body+stubs.replace('systemd-networkd.service',manager))
  env=dict(os.environ,FIXTURE=str(case),FAIL_AT=fail_at,AEGIS_ROOT_STATE_CLIENT=str(client),AEGIS_WIDE_LIB_DIR=str(case/'lib'),ROOT=str(case/'root'),SELECTED=str(int(selected)),GUARD_V2=str(int(guard_v2)))
  if selected:
   for name,field in [('request','REQUEST'),('profile','MANIFEST')]:
    p=case/(name+'.json');p.write_bytes(b'synthetic bounded pinned metadata\n');p.chmod(0o600)
    env['DEVICE_RELAY_GENEVA_'+field]=str(p);env['DEVICE_RELAY_GENEVA_'+field+'_SHA256']=hashlib.sha256(p.read_bytes()).hexdigest()
  p=subprocess.run(['bash',str(script)],env=env,capture_output=True,text=True)
  assert (p.returncode==0)==(not fail_at),(fail_at,p.returncode,p.stdout,p.stderr)
  calls=(case/'calls').read_text();assert 'ILLEGAL_' not in calls,(fail_at,calls)
  armed=(case/'state/device-guard.conf').exists()
  assert armed==(fail_at not in ['identity','validate-stage','preflight','assessment-lock-symlink','assessment-lock-nonempty','assessment-lock-mode','first-block','commit']),(fail_at,calls)
  blocked=(case/'table-blocked').exists()
  assert blocked==(fail_at not in ['identity','validate-stage','preflight','assessment-lock-symlink','assessment-lock-nonempty','assessment-lock-mode','first-block']),(fail_at,calls)
  if scenario.startswith('assessment-lock-'):
   assert 'assessment-lock' in calls and 'aegis-device-egress-guard.sh block' not in calls
   assert 'systemctl start aegis-device-egress-guard.service' not in calls
   if scenario=='assessment-lock-symlink':assert lock.is_symlink() and (case/'foreign-lock-target').read_bytes()==b'foreign\n'
   if scenario=='assessment-lock-nonempty':assert lock.read_bytes()==b'foreign\n'
   if scenario=='assessment-lock-mode':assert lock.stat().st_mode&0o777==0o644
  elif guard_v2 and fail_at not in ('identity','validate-stage','preflight'):
   info=lock.lstat();assert info.st_size==0 and info.st_mode&0o777==0o600 and not lock.is_symlink()
   assert calls.index('stage-dependencies')<calls.index('assessment-lock')<calls.index('aegis-device-egress-guard.sh block')
   if not fail_at:
    assert calls.index('assessment-lock')<calls.index('systemctl start aegis-device-egress-guard.service')
   # Retry must retain the same inode and contents, not replace the lock.
   retry=case/'retry-lock.sh';retry.write_text('set -euo pipefail\n'+lock_fixture+'\nsource_device_guard_assessment_lock_ensure\n')
   rerun=subprocess.run(['bash',str(retry)],env=env,capture_output=True,text=True)
   assert rerun.returncode==0,(scenario,rerun.stderr)
   assert lock.stat().st_ino==info.st_ino and lock.stat().st_size==0
  if fail_at=='commit':
   assert 'systemctl stop aegis-client.service' in calls and list((case/'state').glob('.device-arm.*/guard.conf'))
  if armed:
   assert 'armed=1' in (case/'state/device-guard.conf').read_text()
   assert calls.index('stage-dependencies')<calls.index('aegis-device-egress-guard.sh block')<calls.index('write '+str(case/'state/device-guard.conf'))
   if fail_at:
    assert 'systemctl stop aegis-client.service' in calls and 'persistent block and recovery state were retained' in p.stderr
   else:
    assert calls.index('notify-readiness')<calls.index('setup-wide-linux-redirect.sh apply')<calls.index('secure-probes')<calls.index('capture-persistence')
    assert 'fixture_config_inner_tls_grpc' in (case/'config/aegis.toml').read_text()
  if guard_v2 and not scenario.startswith('assessment-lock-'):
   assert calls.index('write '+str(case/'state/device-guard.conf'))<calls.index('systemctl restart '+manager)
   if not fail_at:assert calls.index('aegis-device-egress-guard.sh manager-status')<calls.index('notify-readiness')
  else:assert 'systemctl restart '+manager not in calls
  if selected:
   assert calls.index('capability-dropin')<calls.index('selected-stopped-stage')
   assert calls.index('write '+str(case/'state/device-guard.conf'))<calls.index('selected-stopped-stage')
   if fail_at=='stage':assert 'notify-readiness' not in calls
   else:assert calls.index('selected-stopped-stage')<calls.index('notify-readiness')
   assert (case/'refusing-selected-gate').exists() and blocked
  print('PASS arm case:',scenario or 'success')
print('PASS: staged validation/dependencies before armed commit, notify before strict capture, secure probes before persistence, v1 and v2 manager failure prefixes preserve the intended pre-arm/armed boundary and never call native rollback')
PY
