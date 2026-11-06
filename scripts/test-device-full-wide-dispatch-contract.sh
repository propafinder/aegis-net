#!/usr/bin/env bash
# Real dispatcher, inert host/service/capture boundaries, all paths confined to
# one temporary tree. This does not claim native installation acceptance.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
python3 - "$ROOT" <<'PY'
import os,pathlib,re,subprocess,sys,tempfile
root=pathlib.Path(sys.argv[1]);source=(root/'install.sh').read_text()
state_injector=re.search(r'^inject_client_service_state_path\(\) \{\n.*?^PY\n\}',source,re.M|re.S)[0]
validator=re.search(r'^device_validate_config\(\) \{\n.*?^\}',source,re.M|re.S)[0]
renderer=re.search(r'^device_bundle_render\(\) \{\n.*?^\}',source,re.M|re.S)[0]
absence=re.search(r'^device_relay_geneva_absent\(\) \{\n.*?^\}',source,re.M|re.S)[0]
function=re.search(r'^install_device_full_wide_role\(\) \{\n.*?^\}',source,re.M|re.S)[0]
with tempfile.TemporaryDirectory(prefix='aegis-device-dispatch-') as raw:
 for failure in ('','assessment','config-validation','preflight','old-block','copy-binary','activation'):
  for protected in (False,True):
   t=pathlib.Path(raw).resolve()/(failure or 'success')/str(protected);t.mkdir(parents=True)
   for part in ('metadata','config','runtime','logs','prefix/bin','prefix/lib/aegis/helpers','systemd','env','root/scripts','bundle','identity'):(t/part).mkdir(parents=True,exist_ok=True)
   state=t/'metadata/device-guard.conf'
   if protected:state.write_text('schema=aegis_device_guard_v1\narmed=1\nmanager=systemd-networkd.service\n')
   key=t/'identity/device.key';key.write_bytes(b'SYNTHETIC DEVICE KEY RETAINED');inode=key.stat().st_ino
   for name in ('outer-ca.pem','inner-ca.pem'):(t/'bundle'/name).write_text('synthetic public certificate')
   cli=t/'candidate';cli.write_text('''#!/usr/bin/env python3
import os,pathlib,sys
args=sys.argv[1:];root=pathlib.Path(os.environ['FIXTURE']);failure=os.environ['FAILURE']
with (root/'calls').open('a') as f:f.write('cli '+' '.join(args)+'\\n')
if args[:3]==['profile','metadata','read']: print(pathlib.Path(args[args.index('--path')+1]).read_text(),end='')
elif args[:2]==['device','bundle-render']: pathlib.Path(args[args.index('--output')+1]).write_text('validated inner TLS fixture')
elif '--validate-config' in args:
 assert 'state_path = '+chr(34)+str(root/'runtime/state.json')+chr(34) in pathlib.Path(args[args.index('--config')+1]).read_text()
 if failure=='config-validation':sys.exit(1)
''');cli.chmod(0o755)
   helper='''#!/bin/bash
set -eu
printf 'guard %s\\n' "$1" >> "$FIXTURE/calls"
case "$1" in
preflight) [[ "$FAILURE" != preflight ]];;
block) [[ "$FAILURE" != old-block ]] || exit 1; touch "$FIXTURE/blocked";;
*) exit 94;;
esac
'''
   for path in (t/'root/scripts/aegis-device-egress-guard.sh',t/'prefix/lib/aegis/helpers/aegis-device-egress-guard.sh'):path.write_text(helper);path.chmod(0o755)
   paths={'/var/lib/aegis-install/client':str(t/'metadata'),'/usr/local/lib/aegis/helpers':str(t/'prefix/lib/aegis/helpers'),'/usr/local/bin/aegis-client':str(t/'prefix/bin/aegis-client'),'/usr/local':str(t/'prefix'),'/etc/aegis/client':str(t/'config'),'/var/lib/aegis-client':str(t/'runtime'),'/var/log/aegis-client':str(t/'logs'),'/etc/systemd/system':str(t/'systemd'),'/etc/default':str(t/'env')}
   body=function
   for old,new in paths.items():body=body.replace(old,new)
   body=body.replace('${EUID} -eq 0','${EUID} -eq '+str(os.getuid()))
   stubs='''
TEMP_PATHS=()
FORCE=1
DEVICE_PUBLIC_BUNDLE="$FIXTURE/bundle"
DEVICE_IDENTITY_DIR="$FIXTURE/identity"
PREFLIGHT_CLIENT_BINARY="$FIXTURE/candidate"
SYSTEMD_DIR="$FIXTURE/systemd"
ENV_DIR="$FIXTURE/env"
ROOT="$FIXTURE/root"
log() { printf '%s\\n' "$*" >> "$FIXTURE/calls"; }
detect_os_kind() { printf linux; }
systemd_activation_requested() { return 0; }
device_assess_full_wide_host() { log assess; [[ "$FAILURE" != assessment ]] || return 1; printf 'schema=aegis_device_guard_v1\\narmed=1\\nuplink=eth0\\nmanager=systemd-networkd.service\\n'; }
install_atomic_write() { [[ "$1" == "$FIXTURE/"* ]] || return 97; log "write $1"; [[ "${4:-}" != validate ]] || return 0; cat > "$1"; }
install_copy_file() { [[ "$2" == "$FIXTURE/"* ]] || return 97; log "copy $2"; [[ "$FAILURE" != copy-binary || "$2" != "$FIXTURE/prefix/bin/aegis-client" ]] || return 1; cp "$1" "$2"; chmod "$3" "$2"; }
prepare_client_config_boundary() { log config-boundary; }
ensure_dir() { [[ "$1" == "$FIXTURE/"* ]] || return 97; mkdir -p "$1"; }
install_client_wide_helpers() { log helpers; }
install_client_service_assets() { log service-assets; }
systemctl() { log "systemctl $*"; [[ "$1" != is-active ]]; }
activate_device_full_wide_capture() {
 log activate; [[ "$1" == "$FIXTURE/bundle" && "$2" == "$FIXTURE/identity" && "$3" == "$FIXTURE/config/aegis.toml" && "$4" == "$FIXTURE/metadata/device-assessment.conf" ]] || return 93
 touch "$FIXTURE/blocked"; printf 'schema=aegis_device_guard_v1\\narmed=1\\n' > "$FIXTURE/metadata/device-guard.conf"
 [[ "$FAILURE" != activation ]]
}
record_product_mode() { log mode-record; }
write_install_manifest() { log manifest; }
apply_existing_install_choice() { log ILLEGAL_LEGACY_PURGE; return 99; }
deactivate_existing_wide_boot_units() { log ILLEGAL_NATIVE_TEARDOWN; return 99; }
inject_client_socks_auth_token() { log ILLEGAL_TOKEN; return 99; }
resolve_auto_profile() { log ILLEGAL_LEGACY_PLANNER; return 99; }
install_device_full_wide_role "$FIXTURE/prefix" "$FIXTURE/config" "$FIXTURE/runtime" "$FIXTURE/logs" /dev/null reinstall
'''
   script=t/'run.sh';script.write_text('set -euo pipefail\n'+state_injector+'\n'+validator+'\n'+renderer+'\n'+absence.replace('/var/lib/aegis-install/client',str(t/'metadata')).replace('/usr/local/lib/aegis',str(t/'prefix/lib/aegis')).replace('/etc/systemd/system',str(t/'systemd')).replace('/run/aegis-relay-geneva',str(t/'native-selected'))+'\n'+body+stubs)
   r=subprocess.run(['bash',script],env=dict(os.environ,FIXTURE=str(t),FAILURE=failure),text=True,capture_output=True)
   expected=not failure or failure=='old-block' and not protected
   assert (r.returncode==0)==expected,(failure,protected,r.returncode,r.stdout,r.stderr)
   calls=(t/'calls').read_text();assert 'ILLEGAL_' not in calls
   assert key.stat().st_ino==inode and key.read_bytes()==b'SYNTHETIC DEVICE KEY RETAINED'
   assert not any(p.name=='device.key' for p in t.rglob('*') if p!=key)
   if 'copy '+str(t/'prefix/bin/aegis-client') in calls:
    assert calls.index('guard preflight')<calls.index('config-boundary')<calls.index('copy '+str(t/'prefix/bin/aegis-client'))
    if protected:assert calls.index('guard block')<calls.index('systemctl stop aegis-client.service')<calls.index('config-boundary')
   if expected:assert calls.index('activate')<calls.index('mode-record')<calls.index('manifest')
   if protected:assert 'armed=1' in state.read_text()
   if failure=='activation':assert (t/'blocked').exists() and 'manifest' not in calls
   print('PASS dispatcher:',failure or 'success','armed-upgrade' if protected else 'fresh')
print('PASS: 14 isolated dispatcher cases; validated mode, preflight ordering, key retention and armed upgrade failure boundaries')
PY
