#!/usr/bin/env bash
# Real v3/v4 public-profile/identity CLI, inert enrollment and service boundaries.
# No network, host configuration or production key is accessed by this fixture.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
CLIENT="${AEGIS_DEVICE_CLIENT:-${ROOT}/target/debug/aegis-client}"
if [[ -z "${AEGIS_TEST_DEVICE_PROFILE_SCHEMA:-}" ]]; then
  for schema in aegis_device_bundle_v3 aegis_device_bundle_v4; do
    AEGIS_TEST_DEVICE_PROFILE_SCHEMA="$schema" bash "$0"
  done
  exit 0
fi
python3 - "$ROOT" "$CLIENT" <<'PY'
import hashlib,json,os,pathlib,re,shlex,shutil,subprocess,sys,tempfile
root=pathlib.Path(sys.argv[1]);client=pathlib.Path(sys.argv[2]);source=(root/'install.sh').read_text()
def function(name):return re.search(r'^'+name+r'\(\) \{\n.*?^\}',source,re.M|re.S)[0]
def run(args,**kwargs):
 if pathlib.Path(args[0])==client:args=[args[0],'--diagnostic-logs',*args[1:]]
 p=subprocess.run(list(map(str,args)),capture_output=True,text=True,**kwargs)
 assert p.returncode==0,(args,p.returncode,p.stdout,p.stderr)
 return p
names=['device_online_identity_path','device_preflight_online_public_bundle','device_recover_online_local','device_bundle_render','device_relay_geneva_absent','device_relay_geneva_preflight','resolve_device_bundle_policy','prepare_device_bundle','device_install_online_public_bundle','device_validate_config','install_client_systemd_asset']
functions=function('install_atomic_write').replace('install_atomic_write() {','fixture_atomic_write() {',1)+'\n'+'\n'.join(function(name) for name in names)
# Exercise the exact production policy before rebasing mutation fixtures.
for path in ['/etc/device','/usr/local/device','/var/lib','/var/lib/aegis-install/client/device','/var/lib/aegis-install','/var/lib/aegis/device','/var/lib/aegis-server/device','/var/lib/aegis-identity/client','/var/lib/custom/device']:
 checked=subprocess.run(['bash','-c',function('device_online_identity_path')+'\ndevice_online_identity_path "$1"','fixture',path],capture_output=True,text=True)
 assert (checked.returncode==0)==(path in ('/var/lib/aegis-identity/client','/var/lib/custom/device')),(path,checked.stderr)
with tempfile.TemporaryDirectory(prefix='aegis-online-installer-',dir='/tmp') as raw:
 t=pathlib.Path(raw).resolve();ca=t/'issuer.pem';key=t/'issuer.key'
 run(['openssl','req','-new','-x509','-newkey','ed25519','-nodes','-keyout',key,'-out',ca,'-days','2','-subj','/CN=Synthetic online fixture','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign']);key.chmod(0o600)
 profile={'schema':'aegis_device_bundle_v3','product_mode':'full-wide-tun','relay_server':'198.51.100.4:443','outer_server_name':'relay.test','inner_server_name':'origin.test','udp':True,'enrollment':{'protocol':'aegis-enrollment-v1','authority_server':'198.51.100.5:443','outer_server_name':'authority.test','inner_server_name':'issuer.test','automatic_renewal':True,'renewal_policy':'same-key-v1'}}
 profile['schema']=os.environ.get('AEGIS_TEST_DEVICE_PROFILE_SCHEMA','aegis_device_bundle_v3')
 assert profile['schema'] in ('aegis_device_bundle_v3','aegis_device_bundle_v4')
 if profile['schema']=='aegis_device_bundle_v4':profile['relay_endpoints']=[{'server':profile['relay_server'],'server_name':profile['outer_server_name']},{'server':'198.51.100.6:443','server_name':'backup.test'}]
 public=t/'profile.json';public.write_text(json.dumps(profile));bundle=t/'public-v3'
 run([client,'device','bundle-create','--bundle-dir',bundle,'--profile',public,'--outer-ca',ca,'--inner-ca',ca,'--device-ca',ca])
 inspected=json.loads(run([client,'device','bundle-inspect','--bundle-dir',bundle,'--json']).stdout)
 assert inspected['schema']==profile['schema'] and inspected['resolved']['native_fallback'] is False
 for scenario in ['initial','resume','ready-armed','prepared-armed','certificate-conflict','invitation-v2','mode-conflict','custom-prefix','existing-no-force','redeem-failure','public-copy-failure','unit-env-failure','socks-reinstall','identity-etc','identity-usr','identity-metadata','custom-persistent','public-conflict','public-unknown','public-symlink','public-hardlink','public-member-symlink','public-parent-writable','public-identical-partial','runtime-recovery','recovered-ready','local-recovery-failure','early-host-refusal']:
  case=t/scenario;case.mkdir()
  for name in ['config','runtime','systemd','env','metadata','prefix/bin','public','issuer']:(case/name).mkdir(parents=True)
  shutil.copytree(bundle,case/'public',dirs_exist_ok=True)
  if scenario=='socks-reinstall':
   value=profile.copy();value['product_mode']='socks-only';value['udp']=False;(case/'public/bundle.json').write_text(json.dumps(value))
  if scenario=='invitation-v2':
   value=profile.copy();value['schema']='aegis_device_bundle_v2';value.pop('enrollment');value.pop('relay_endpoints',None);(case/'public/bundle.json').write_text(json.dumps(value))
  identity=case/'persistent/identity'
  if scenario=='custom-persistent':identity=case/'persistent/custom/device'
  if scenario=='identity-etc':identity=case/'etc/identity'
  if scenario=='identity-usr':identity=case/'usr/identity'
  if scenario=='identity-metadata':identity=case/'metadata/identity'
  if scenario.startswith('public-') and scenario!='public-copy-failure':
   installed=case/'config/device-bundle'
   if scenario=='public-symlink':installed.symlink_to(case/'public',target_is_directory=True)
   else:
    installed.mkdir()
    member=installed/'bundle.json';shutil.copy2(case/'public/bundle.json',member)
    if scenario=='public-parent-writable':(case/'config').chmod(0o1777)
    if scenario=='public-conflict':member.write_text('{}')
    if scenario=='public-unknown':(installed/'unknown.pem').write_text('unknown public member')
    if scenario=='public-hardlink':os.link(member,case/'other-public-copy')
    if scenario=='public-member-symlink':member.unlink();member.symlink_to(case/'public/bundle.json')
  invitation=case/'invitation';invitation.write_text('SYNTHETIC PROTECTED INVITATION CONTENT');invitation.chmod(0o600)
  if scenario=='resume':(case/'pending').touch()
  if scenario in ('ready-armed','runtime-recovery','recovered-ready','local-recovery-failure'):
   run([client,'device','prepare','--device-id','fixture-online','--identity-dir',identity,'--device-ca',case/'public/device-ca.pem'])
   run([client,'device','bundle-inspect','--bundle-dir',case/'public','--identity-dir',identity,'--json'])
   (case/'ready').touch()
  if scenario in ('ready-armed','prepared-armed'):(case/'metadata/device-guard.conf').write_text('schema=aegis_device_guard_v2\narmed=1\n')
  if scenario=='existing-no-force':(case/'config/aegis.toml').write_text('existing config retained')
  cli=case/'client';cli.write_text('''#!/usr/bin/env python3
import json,os,pathlib,subprocess,sys
root=pathlib.Path(os.environ['FIXTURE']);a=sys.argv[1:]
with (root/'calls').open('a') as f:f.write(' '.join(a)+'\\n')
if a[:2]==['device','redeem']:
 if os.environ['SCENARIO']=='redeem-failure':sys.exit(1)
 assert '--invitation-file' in a or (root/'pending').exists()
 if '--invitation-file' in a:assert pathlib.Path(a[a.index('--invitation-file')+1])==root/'invitation'
 (root/'ready').touch();print('{"state":"issued_pending_distribution"}')
elif a[:2]==['device','bundle-render']:
 assert os.environ['SCENARIO']=='socks-reinstall'
 pathlib.Path(a[a.index('--output')+1]).write_text('inert shell fixture config')
elif a[:2]==['device','recover-local'] and (root/'ready').exists():
 if os.environ['SCENARIO']=='local-recovery-failure':sys.exit(1)
 phase='runtime_recovery_required' if os.environ['SCENARIO']=='runtime-recovery' else 'ready'
 print(json.dumps({'schema':'aegis_device_local_recovery_v1','phase':phase,'repaired':os.environ['SCENARIO']=='recovered-ready','pending_request':phase=='runtime_recovery_required'}))
elif a[:3]==['profile','metadata','validate']:pass
elif a[:3]==['profile','metadata','read']:print(pathlib.Path(a[a.index('--path')+1]).read_text(),end='')
elif '--validate-config' in a:
 assert a[a.index('--device-online-bundle')+1]==str(root/'config/device-bundle')
else:sys.exit(subprocess.run([os.environ['REAL_CLIENT'],*a]).returncode)
''');cli.chmod(0o755)
  paths={'/var/lib/aegis-install/client':str(case/'metadata'),'/usr/local/bin/aegis-client':str(case/'prefix/bin/aegis-client'),'/usr/local':str(case/'prefix'),'/etc/aegis/client':str(case/'config'),'/var/lib/aegis-client':str(case/'runtime'),'/etc/systemd/system':str(case/'systemd'),'/etc/default':str(case/'env')}
  body=functions
  for old,new in paths.items():body=body.replace(old,new)
  body=body.replace('${EUID} -eq 0','${EUID} -eq '+str(os.getuid()))
  # Rebase the production read-only directory walk onto this temporary root;
  # all member checks, nofollow opens and exact comparisons remain production.
  body=body.replace("anchor='/'",'anchor='+repr(str(case)))
  body=body.replace('pathlib.PurePath(path).parts[1:]','(pathlib.PurePath(path).parts[1:] if public_source else pathlib.PurePath(path).relative_to(anchor).parts)')
  body=body.replace('fd=os.open(anchor,',"fd=os.open('/' if public_source else anchor,")
  body=body.replace('value.st_uid==0','value.st_uid in (0,'+str(os.getuid())+')')
  body=body.replace('/var/lib/*',str(case)+'/persistent/*')
  setup='''
PREFLIGHT_CLIENT_BINARY="$FIXTURE/client"
AEGIS_ROOT_STATE_CLIENT="$FIXTURE/client"
BUNDLE_PATH="$FIXTURE/public"
DEVICE_ID=fixture-online
DEVICE_CERTIFICATE=""
DEVICE_INVITATION_FILE="$FIXTURE/invitation"
DEVICE_IDENTITY_DIR="$FIXTURE_IDENTITY"
BUNDLE_INSECURE=0
PRODUCT_MODE=auto OPERATOR_MODE="" MASQUE_SERVER="" MASQUE_CA="" GENEVA_STRATEGY_FILE="" OPERATOR_TRANSPORT="" FRONTED_AUTHORITY=""
WIDE_UDP_POLICY="" WIDE_DNS_POLICY="" WIDE_IPV6_POLICY="" UDP_CARRY=0
PREFIX="$FIXTURE/prefix" SYSTEMD_DIR="$FIXTURE/systemd" ENV_DIR="$FIXTURE/env" FORCE=1
TEMP_PATHS=()
ROOT="$REAL_ROOT"
device_absolute_path() { printf '%s\\n' "$1"; }
device_service_identity_path() { [[ "$1" == "$FIXTURE/"* ]]; }
detect_os_kind() { echo linux; }
case "$SCENARIO" in
resume|ready-armed) DEVICE_INVITATION_FILE="";;
certificate-conflict) DEVICE_CERTIFICATE="$FIXTURE/certificate";;
mode-conflict) PRODUCT_MODE=socks-only;;
custom-prefix) PREFIX="$FIXTURE/custom";;
existing-no-force) FORCE=0;;
esac
install_atomic_write() { [[ "$1" == "$FIXTURE/"* ]] || return 98; fixture_atomic_write "$@"; }
device_assess_full_wide_host() { printf 'host-assess\n' >> "$FIXTURE/calls"; [[ "${SCENARIO}" != early-host-refusal ]]; }
prepare_device_bundle "$FIXTURE/config" "$FIXTURE/runtime" upgrade
[[ "$DEVICE_INSTALL_READY" == 1 && "$DEVICE_ONLINE" == 1 ]]
if [[ "$SCENARIO" == socks-reinstall ]]; then
 [[ "$PRODUCT_MODE" == socks-only && "$UDP_CARRY" == 0 && "$DEVICE_PUBLIC_BUNDLE" == "$FIXTURE_IDENTITY/"* ]]
 # Simulate the existing generic SOCKS purge removing its original public input.
 rm -r "$FIXTURE/public"
else
 [[ "$PRODUCT_MODE" == full-wide-tun && "$UDP_CARRY" == 1 ]]
fi
ensure_dir() { [[ "$1" == "$FIXTURE/"* ]] || return 98; mkdir -p "$1"; }
require_asset() { [[ -f "$1" ]]; }
install_atomic_write() {
 [[ "$1" == "$FIXTURE/"* ]] || return 98
 [[ "$SCENARIO" != public-copy-failure || "$1" != "$FIXTURE/config/device-bundle/inner-ca.pem" || "${4:-}" == validate ]] || return 1
 fixture_atomic_write "$@"
}
install_copy_file() {
 [[ "$2" == "$FIXTURE/"* ]] || return 98
 [[ "$SCENARIO" != public-copy-failure || "$2" != "$FIXTURE/config/device-bundle/inner-ca.pem" ]] || return 1
 [[ "$SCENARIO" != unit-env-failure || "$2" != "$FIXTURE/env/aegis-client" ]] || return 1
 cp "$1" "$2"; chmod "$3" "$2"
}
install_text_file() { [[ "$1" == "$FIXTURE/"* ]] || return 98; printf '%s\\n' "$3" > "$1"; }
render_template() {
 python3 - "$@" <<'PY_RENDER'
import pathlib,sys
text=pathlib.Path(sys.argv[1]).read_text()
for a,b in zip(sys.argv[2::2],sys.argv[3::2]):text=text.replace(a,b)
print(text,end='')
PY_RENDER
}
install_client_systemd_asset "$FIXTURE/prefix/bin/aegis-client" "$FIXTURE/config/aegis.toml" "$FIXTURE/runtime" /dev/null
device_validate_config "$FIXTURE/client" "$FIXTURE/config/aegis.toml"
'''
  script=case/'fixture.sh';script.write_text('set -euo pipefail\n'+body+setup)
  env=dict(os.environ,FIXTURE=str(case),SCENARIO=scenario,REAL_CLIENT=str(client),REAL_ROOT=str(root),FIXTURE_IDENTITY=str(identity))
  p=subprocess.run(['bash',str(script)],env=env,capture_output=True,text=True)
  success=scenario in ('initial','resume','ready-armed','socks-reinstall','custom-persistent','public-identical-partial','runtime-recovery','recovered-ready');assert (p.returncode==0)==success,(scenario,p.returncode,p.stdout,p.stderr)
  calls=(case/'calls').read_text();assert 'online-status' not in calls and 'device renew' not in calls and 'device complete' not in calls and 'device status' not in calls
  assert 'SYNTHETIC PROTECTED INVITATION CONTENT' not in calls
  should_prepare=scenario not in ('certificate-conflict','invitation-v2','mode-conflict','custom-prefix','existing-no-force','identity-etc','identity-usr','identity-metadata','public-conflict','public-unknown','public-symlink','public-hardlink','public-member-symlink','public-parent-writable','early-host-refusal')
  assert (identity/'device.key').exists()==should_prepare,(scenario,calls)
  if scenario in ('ready-armed','prepared-armed','runtime-recovery','recovered-ready','local-recovery-failure'):assert 'device redeem ' not in calls
  if not should_prepare:assert 'device prepare ' not in calls and 'device recover-local ' not in calls and 'device redeem ' not in calls and '--identity-dir' not in calls
  if scenario in ('runtime-recovery','recovered-ready','local-recovery-failure'):assert 'device prepare ' not in calls
  if scenario=='resume':assert 'device redeem ' in calls and '--invitation-file' not in calls
  unit=case/'systemd/aegis-client.service'
  assert unit.exists()==success,(scenario,calls)
  if success:
   if scenario=='public-identical-partial':
    # The production source walk runs on the real root-owned sticky temp
    # ancestry, not its rebased destination walk, both now and on reinstall.
    assert any(p.stat().st_uid==0 and p.stat().st_mode&0o1000 for p in (case/'public').parents)
   text=unit.read_text();assert '--device-online-bundle '+str(case/'config/device-bundle') in text
   assert 'Type=notify' in text and 'NotifyAccess=main' in text and 'TimeoutStartSec=180' in text and 'Restart=on-failure' in text and 'RestartSec=30' in text
   installed=case/'config/device-bundle';assert {p.name for p in installed.iterdir()}=={'bundle.json','outer-ca.pem','inner-ca.pem','device-ca.pem'}
   assert not any('PRIVATE KEY' in p.read_text() or 'INVITATION' in p.read_text() for p in installed.iterdir())
   assert len(list(case.rglob('device.key')))==1
   assert bool(list(case.rglob('.install-render.*')))==(scenario=='socks-reinstall')
   original_key=identity/'device.key';old=(original_key.stat().st_ino,hashlib.sha256(original_key.read_bytes()).hexdigest());count=calls.count('device redeem ')
   if scenario=='socks-reinstall':
    print('PASS online installer:',scenario);continue
   again=subprocess.run(['bash',str(script)],env=env,capture_output=True,text=True);assert again.returncode==0,(scenario,again.stderr)
   assert (original_key.stat().st_ino,hashlib.sha256(original_key.read_bytes()).hexdigest())==old
   assert (case/'calls').read_text().count('device redeem ')==count and {p.name for p in installed.iterdir()}=={'bundle.json','outer-ca.pem','inner-ca.pem','device-ca.pem'}
  if scenario=='public-copy-failure':
   assert not unit.exists() and len(list((case/'config/device-bundle').iterdir()))<4
   old=(identity/'device.key').stat().st_ino
   again=subprocess.run(['bash',str(script)],env=env|{'SCENARIO':'initial'},capture_output=True,text=True);assert again.returncode==0,again.stderr
   assert (identity/'device.key').stat().st_ino==old and unit.exists()
  print('PASS online installer:',scenario)
 print('PASS: 28 '+profile['schema']+' installer cases; actual public-profile/key CLI, synthetic inert redeem, exact public persistence and notify/worker wiring, no network/host mutation')
PY
