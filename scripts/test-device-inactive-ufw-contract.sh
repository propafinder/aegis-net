#!/usr/bin/env bash
# Exercise the production parser against inert policy files; no firewall mutation.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
python3 - "$ROOT" <<'PY'
import contextlib,hashlib,io,json,os,pathlib,shutil,sys,tempfile
source=(pathlib.Path(sys.argv[1])/'scripts/aegis-device-egress-guard.sh').read_text()
program=source.split("<<'PY_INACTIVE_UFW'\n",1)[1].split('\nPY_INACTIVE_UFW',1)[0]
count=0
with tempfile.TemporaryDirectory(prefix='aegis-inactive-ufw-') as tmp:
 root=pathlib.Path(tmp).resolve()
 unit='usr/lib/systemd/system/ufw.service';init='usr/lib/ufw/ufw-init';conf='etc/ufw/ufw.conf'
 initial={unit:b'INERT REVIEWED UNIT\n',init:b'INERT REVIEWED INIT\n',conf:b'# fixture\nENABLED=no\nLOGLEVEL=low\n'}
 ns={'__name__':'fixture'};exec(compile(program,'production-inactive-ufw','exec'),ns)
 ns['ROOT']=root;ns['OWNER_UID']=os.getuid();ns['DIGESTS']={k:hashlib.sha256(initial[k]).hexdigest() for k in (unit,init)}
 original_which=shutil.which;shutil.which=lambda _: '/fixture/command'
 def check(label,mutate=lambda:None,ok=False,properties=None,legacy='',nft=None,change=False):
  global count
  for name,data in initial.items():
   p=root/name;p.parent.mkdir(parents=True,exist_ok=True)
   if p.exists() or p.is_symlink():p.unlink()
   p.write_bytes(data);p.chmod(0o600)
  props={'FragmentPath':'/usr/lib/systemd/system/ufw.service','DropInPaths':'','NeedDaemonReload':'no'}
  props.update(properties or {})
  def run(*args):
   if change:(root/conf).write_text('ENABLED=yes\n')
   if args[0]=='systemctl':return '\n'.join(k+'='+v for k,v in props.items())
   if args[0]=='nft':return json.dumps({'nftables':[]} if nft is None else nft)
   if args[0] in ('iptables-save','ip6tables-save','iptables-legacy-save','ip6tables-legacy-save'):return legacy
   raise AssertionError('unexpected command '+repr(args))
  ns['run']=run;mutate();before={str(p.relative_to(root)) for p in root.rglob('*')}
  output=io.StringIO()
  try:
   with contextlib.redirect_stdout(output):ns['main']()
   passed=True
  except (ValueError,OSError):passed=False
  assert passed==ok,(label,output.getvalue())
  if ok:assert json.loads(output.getvalue())=={'schema':'aegis_inactive_ufw_v1','enabled':False,'service_mutated':False,'rules_mutated':False}
  assert before=={str(p.relative_to(root)) for p in root.rglob('*')},label+' created files'
  count+=1;print('PASS: '+label)
 check('reviewed disabled boot no-op',ok=True)
 check('enabled policy',lambda:(root/conf).write_text('ENABLED=yes\n'))
 check('duplicate assignments',lambda:(root/conf).write_text('ENABLED=no\nENABLED=no\n'))
 check('shell substitution',lambda:(root/conf).write_text('ENABLED=$(true)\n'))
 check('extra shell command',lambda:(root/conf).write_text('ENABLED=no\necho unexpected\n'))
 check('carriage return differs from shell semantics',lambda:(root/conf).write_bytes(b'ENABLED=no\r\n'))
 check('unknown config key',lambda:(root/conf).write_text('ENABLED=no\nCUSTOM=x\n'))
 check('changed init',lambda:(root/init).write_text('modified'))
 check('changed unit',lambda:(root/unit).write_text('modified'))
 check('writable config',lambda:(root/conf).chmod(0o666))
 def symlink():
  (root/conf).unlink();(root/conf).symlink_to(root/init)
 check('config symlink',symlink)
 check('custom unit fragment',properties={'FragmentPath':'/etc/systemd/system/ufw.service'})
 check('unit drop-in',properties={'DropInPaths':'/etc/systemd/system/ufw.service.d/custom.conf'})
 check('stale loaded unit',properties={'NeedDaemonReload':'yes'})
 check('residual xtables policy',legacy=':ufw-before-input - [0:0]')
 check('residual nft policy',nft={'nftables':[{'chain':{'name':'ufw-before-input'}}]})
 check('residual IPv6 xtables policy',legacy=':ufw6-before-input - [0:0]')
 check('residual IPv6 nft chain',nft={'nftables':[{'chain':{'name':'ufw6-before-input'}}]})
 check('residual IPv6 nft jump',nft={'nftables':[{'rule':{'expr':[{'jump':{'target':'ufw6-before-input'}}]}}]})
 check('invalid nft state',nft={})
 check('config changes during inspection',change=True)
 shutil.which=original_which
 print('PASS:',count,'inactive UFW scenarios; no services/rules changed')
PY
