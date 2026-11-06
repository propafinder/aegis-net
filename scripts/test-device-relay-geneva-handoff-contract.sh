#!/usr/bin/env bash
# Enter the real prepare_device_bundle through inert CLI/host boundaries.
# The first device prepare is a marker-only refusal; never continue installation.
# Every path is rebased into one temporary tree; this is not installed evidence.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
python3 - "$ROOT" <<'PY'
import hashlib,os,pathlib,re,subprocess,sys,tempfile
root=pathlib.Path(sys.argv[1]);source=(root/'install.sh').read_text()
names=['device_bundle_render','device_relay_geneva_absent','device_relay_geneva_verify_snapshot','device_relay_geneva_existing_installation_eligible','device_relay_geneva_preflight','prepare_device_bundle']
functions='\n'.join(re.search(r'^'+name+r'\(\) \{\n.*?^\}',source,re.M|re.S)[0] for name in names)
with tempfile.TemporaryDirectory(prefix='aegis-selected-handoff-') as raw:
 for case in ['success','no-selection','request-validation','manifest-validation','request-drift','manifest-drift','guard-v1','selected-file','selected-dangling-link','legacy-config','legacy-dangling-unit','interrupted-recovery','wrong-mode']:
  t=pathlib.Path(raw).resolve()/case;t.mkdir()
  for part in ['metadata','config','runtime','systemd','env','prefix','bundle','identity']:(t/part).mkdir()
  request=t/'request.json';manifest=t/'profile.json'
  request.write_bytes(b'{"synthetic":"private request"}\n');manifest.write_bytes(b'{"synthetic":"public profile"}\n')
  request.chmod(0o600);manifest.chmod(0o600)
  request_hash=hashlib.sha256(request.read_bytes()).hexdigest();manifest_hash=hashlib.sha256(manifest.read_bytes()).hexdigest()
  if case=='selected-file':(t/'metadata/relay-geneva-install-intent.json').write_text('retained selected intent')
  if case=='selected-dangling-link':(t/'metadata/relay-geneva-profile.json').symlink_to(t/'missing')
  if case=='legacy-config':(t/'config/aegis.toml').write_text('legacy installation retained')
  if case=='legacy-dangling-unit':(t/'systemd/aegis-client.service').symlink_to(t/'missing')
  if case=='interrupted-recovery':
   (t/'metadata/device-guard.conf').write_text('schema=aegis_device_guard_v2\narmed=0\n')
   (t/'systemd/aegis-device-egress-guard.service').write_text('retained recovery unit')
  cli=t/'cli';cli.write_text('''#!/usr/bin/env python3
import hashlib,os,pathlib,sys
args=sys.argv[1:];t=pathlib.Path(os.environ['FIXTURE']);case=os.environ['CASE']
def arg(name):return args[args.index(name)+1]
with (t/'calls').open('a') as out:out.write('cli '+' '.join(args)+'\\n')
if args[:3]==['profile','metadata','validate']:pass
elif args[:3]==['profile','metadata','read']:
 path=pathlib.Path(arg('--path'));assert path.is_relative_to(t)
 raw=path.read_bytes()
 if case=='request-drift' and path==t/'request.json':raw+=b'changed'
 if case=='manifest-drift' and path==t/'profile.json':raw+=b'changed'
 sys.stdout.buffer.write(raw)
elif args[:3]==['profile','metadata','write']:
 path=pathlib.Path(arg('--path'));assert path.is_relative_to(t) and '--exclusive' in args
 with path.open('xb') as out:out.write(sys.stdin.buffer.read(65537))
 path.chmod(0o600)
elif args[:2]==['device','prepare']:
 assert arg('--device-id')=='fixture-selected-handoff'
 assert arg('--identity-dir')==str(t/'identity')
 assert arg('--device-ca')==str(t/'bundle/device-ca.pem')
 (t/'enrollment').write_text('inert device prepare refused with exit 73\\n')
 sys.exit(73)
elif args[:2]==['device','bundle-render']:
 assert '--validate-only' in args and not (t/'enrollment').exists()
 for flag,path,expected in [('--relay-geneva-request',t/'request.json',os.environ['REQUEST_HASH']),('--relay-geneva-profile-manifest',t/'profile.json',os.environ['MANIFEST_HASH'])]:
  assert arg(flag)==str(path)
  assert hashlib.sha256(path.read_bytes()).hexdigest()==expected
 assert arg('--relay-geneva-request-sha256')==os.environ['REQUEST_HASH']
 assert arg('--relay-geneva-profile-sha256')==os.environ['MANIFEST_HASH']
 assert arg('--output')==str(t/'config/aegis.toml')
 if case in ['request-validation','manifest-validation']:sys.exit(1)
else:raise AssertionError(args)
''');cli.chmod(0o700)
  replacements={'/var/lib/aegis-install/client':str(t/'metadata'),'/var/lib/aegis-client':str(t/'runtime'),'/usr/local/lib/aegis':str(t/'prefix/lib/aegis'),'/usr/local':str(t/'prefix'),'/etc/aegis/client':str(t/'config'),'/etc/systemd/system':str(t/'systemd'),'/etc/default':str(t/'env'),'/run/aegis-relay-geneva':str(t/'native-selected')}
  body=functions
  for old,new in sorted(replacements.items(),key=lambda item:-len(item[0])):body=body.replace(old,new)
  body=body.replace('"$EUID" == 0','"$EUID" == '+str(os.getuid()))
  body=body.replace('[[ ${EUID} -eq 0 ]]','[[ ${EUID} -eq '+str(os.getuid())+' ]]')
  stubs='''
PREFLIGHT_CLIENT_BINARY="$FIXTURE/cli"
DEVICE_ID=fixture-selected-handoff
DEVICE_IDENTITY_DIR="$FIXTURE/identity"
BUNDLE_PATH="$FIXTURE/bundle"
BUNDLE_INSECURE=0
DEVICE_ONLINE=0
DEVICE_PRODUCT_MODE=full-wide-tun
[[ "$CASE" != wrong-mode ]] || DEVICE_PRODUCT_MODE=socks-only
DEVICE_RELAY_GENEVA_REQUEST="$FIXTURE/request.json"
DEVICE_RELAY_GENEVA_REQUEST_SHA256="$REQUEST_HASH"
DEVICE_RELAY_GENEVA_MANIFEST="$FIXTURE/profile.json"
DEVICE_RELAY_GENEVA_MANIFEST_SHA256="$MANIFEST_HASH"
[[ "$CASE" != no-selection ]] || DEVICE_RELAY_GENEVA_REQUEST=''
PREFIX="$FIXTURE/prefix" SYSTEMD_DIR="$FIXTURE/systemd" ENV_DIR="$FIXTURE/env"
detect_os_kind() { printf linux; }
systemd_activation_requested() { return 0; }
device_absolute_path() { [[ "$1" == "$FIXTURE/"* ]] || return 97; printf '%s' "$1"; }
device_service_identity_path() { [[ "$1" == "$FIXTURE/"* ]]; }
resolve_device_bundle_policy() { [[ "$1" == "$FIXTURE/bundle" ]]; }
ensure_dir() { [[ "$1" == "$FIXTURE/"* ]] || return 97; mkdir -p "$1"; }
device_assess_full_wide_host() { [[ "$CASE" != guard-v1 ]] && printf 'schema=aegis_device_guard_v2\\n' || printf 'schema=aegis_device_guard_v1\\n'; }
status=0
prepare_device_bundle "$FIXTURE/config" "$FIXTURE/runtime" || status=$?
if [[ -e "$FIXTURE/enrollment" && "$CASE" != no-selection ]]; then
 [[ "$DEVICE_RELAY_GENEVA_REQUEST" == "$FIXTURE/metadata/.relay-geneva-handoff."*/request.json ]]
 [[ "$DEVICE_RELAY_GENEVA_MANIFEST" == "$FIXTURE/metadata/.relay-geneva-handoff."*/profile.json ]]
fi
exit "$status"
'''
  script=t/'run.sh';script.write_text('set -euo pipefail\n'+body+stubs)
  result=subprocess.run(['bash',script],env=dict(os.environ,FIXTURE=str(t),CASE=case,REQUEST_HASH=request_hash,MANIFEST_HASH=manifest_hash),capture_output=True,text=True)
  reaches_prepare=case in ['success','no-selection']
  # The real function maps the mocked device prepare's exit 73 to return 1.
  # Positive handoff is therefore proven by the marker/calls, not exit zero.
  assert result.returncode==1,(case,result.returncode,result.stdout,result.stderr)
  assert (t/'enrollment').exists()==reaches_prepare,(case,result.stderr)
  calls=(t/'calls').read_text() if (t/'calls').exists() else ''
  lines=calls.splitlines()
  prepares=[i for i,line in enumerate(lines) if line.startswith('cli device prepare ')]
  assert len(prepares)==int(reaches_prepare),(case,calls,result.stderr)
  if reaches_prepare:assert prepares[0]==len(lines)-1,(case,calls)
  if reaches_prepare and case!='no-selection':
   retained=list((t/'metadata').glob('.relay-geneva-handoff.*/request.json'));assert len(retained)==1
   assert retained[0].read_bytes()==request.read_bytes()
   assert retained[0].with_name('profile.json').read_bytes()==manifest.read_bytes()
   rendered=[i for i,line in enumerate(lines) if line.startswith('cli device bundle-render ')]
   assert len(rendered)==1,(case,calls)
   request_checked=lines.index('cli profile metadata read --path '+str(retained[0]))
   manifest_checked=lines.index('cli profile metadata read --path '+str(retained[0].with_name('profile.json')))
   assert rendered[0]<request_checked<manifest_checked<prepares[0],(case,calls)
  if case=='no-selection':assert 'bundle-render' not in calls and not list((t/'metadata').glob('.relay-geneva-handoff.*'))
  if case in ['selected-file','selected-dangling-link','legacy-config','legacy-dangling-unit','interrupted-recovery','wrong-mode','guard-v1']:assert 'bundle-render' not in calls
  assert not (t/'identity/bundle-profile.sha256').exists()
  assert not (t/'config/aegis.toml').exists() or case=='legacy-config'
  print('PASS selected pre-enrollment handoff:',case)
print('PASS: 13 real prepare_device_bundle handoff cases; only success/no-selection reach marker-only device prepare exit 73, inputs freeze before it, failures never reach enrollment')
PY
