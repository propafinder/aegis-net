#!/usr/bin/env bash
# Actual installer functions, units and helper; every administrative/kernel path
# is rebased and every network command is inert. This is not native nft/systemd
# acceptance. The interpreter evaluates the submitted rules, not a restatement
# of guard policy, and rejects unsupported syntax.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
python3 - "$ROOT" <<'PY'
import ipaddress, json, os, pathlib, re, shlex, shutil, subprocess, sys, tempfile

root = pathlib.Path(sys.argv[1])
evidence = os.environ.get('AEGIS_LEGACY_GUARD_EVIDENCE_DIR')
if evidence:
    fixture = pathlib.Path(evidence).resolve()
    fixture.mkdir(parents=True, exist_ok=False)
    temporary = None
else:
    temporary = tempfile.TemporaryDirectory(prefix='aegis-legacy-tun-guard-')
    fixture = pathlib.Path(temporary.name).resolve()
b = fixture / 'bin'; b.mkdir()
lib = fixture / 'helpers'; (lib / 'lib').mkdir(parents=True)
units = fixture / 'etc/systemd/system'; units.mkdir(parents=True)
state = fixture / 'var/lib/aegis-install/client/legacy-tun-guard.conf'
state.parent.mkdir(parents=True)
cg = fixture / 'sys/fs/cgroup/system.slice/aegis-client.service'; cg.mkdir(parents=True)
(cg / 'cgroup.procs').write_text('321\n')
member = fixture / 'proc/321/cgroup'; member.parent.mkdir(parents=True)
member.write_text('0::/system.slice/aegis-client.service\n')
port_floor = fixture / 'proc/sys/net/ipv4/ip_unprivileged_port_start'
port_floor.parent.mkdir(parents=True); port_floor.write_text('1024\n')
(fixture / 'inode').write_text('111')
(fixture / 'client-active').touch()

def rebase(text):
    text=text.replace('/usr/local/lib/aegis/helpers',str(lib))
    return re.sub(r'(?<![A-Za-z0-9_/])/(?:etc|var/lib|run|sys|proc)/',
                  lambda match: str(fixture) + match.group(), text)

helper = lib / 'setup-wide-linux-redirect.sh'
text = rebase((root / 'scripts/setup-wide-linux-redirect.sh').read_text())
text = text.replace('[[ "$EUID" == 0 ]]', ': # fixture takes root-only branch')
text = text.replace('"$pid" == "$$"', '"$pid" == 321')
helper.write_text(text); helper.chmod(0o755)
# Administrative metadata boundary is separately tested by the real Rust CLI.
# This fixture delegates only trusted metadata I/O to a bounded path stub.
(lib / 'lib/root-state.sh').write_text('''aegis_root_state_init() { :; }
aegis_root_validate() { [[ "$1" == "$FIXTURE/"* && "$1" != *'/../'* ]]; }
aegis_root_read() { aegis_root_validate "$1" && cat "$1"; }
aegis_root_write() { aegis_root_validate "$1" && cat > "$1"; }
aegis_root_remove() { aegis_root_validate "$1" && rm -f "$1"; }
aegis_root_resolver_preflight() { :; }
aegis_root_resolver_save() { :; }
aegis_root_resolver_restore() { :; }
''')

# A fail-closed interpreter of the exact nft batch. Unsupported grammar raises,
# and nft apply is atomic in this fixture. Native parsing is a later CI gate.
model = fixture / 'model.py'
model.write_text(r'''
import ipaddress, json, pathlib, shlex
TABLE='aegis_legacy_tun_guard'
def parse(text, inode):
    data={'policies':{},'rules':{'incoming':[],'output':[],'forward':[]}}
    for line in text.splitlines():
        t=shlex.split(line)
        if t[:2] in (['add','table'],['flush','table']):
            assert t[2:]==['inet',TABLE], line
        elif t[:2]==['add','chain']:
            assert t[2:4]==['inet',TABLE] and t[4] in data['rules'],line
            assert 'hook' in t and 'policy' in t,line
            data['policies'][t[4]]=t[t.index('policy')+1].rstrip(';')
        elif t[:2]==['add','rule']:
            assert t[2:4]==['inet',TABLE] and t[4] in data['rules'],line
            terms=[]; i=5
            while i<len(t):
                if t[i]=='counter': i+=1; continue
                if t[i] in ('accept','drop'):
                    assert i==len(t)-1,line
                    terms.append(('verdict',t[i]));i+=1;continue
                if t[i:i+2]==['ct','mark'] and t[i+2]=='set':
                    terms.append(('setmark',int(t[i+3],0)));i+=4;continue
                if t[i:i+3]==['fib','daddr','type']:
                    assert t[i+3]=='local';terms.append(('local',True));i+=4;continue
                if t[i:i+2]==['socket','cgroupv2']:
                    assert t[i+2]=='level' and int(t[i+3])==len(t[i+4].split('/'))
                    terms.append(('cgroup',(t[i+4],inode)));i+=5;continue
                if t[i:i+3]==['ct','original','proto-dst']:
                    terms.append(('original_dport',int(t[i+3])));i+=4;continue
                if t[i]=='oifname': terms.append(('oif',t[i+1]));i+=2;continue
                pair=tuple(t[i:i+2])
                fields={('meta','nfproto'):'family',('meta','l4proto'):'proto',
                  ('ct','direction'):'direction',('ct','mark'):'mark',('ct','status'):'status',
                  ('ct','state'):'state',('ip','daddr'):'daddr4',('ip6','daddr'):'daddr6',
                  ('ip6','saddr'):'saddr6',('ip6','hoplimit'):'hoplimit',('icmpv6','type'):'icmp_type',
                  ('tcp','dport'):'tcp_dport',('tcp','sport'):'tcp_sport',
                  ('udp','dport'):'udp_dport',('udp','sport'):'udp_sport'}
                assert pair in fields, (line,t[i:])
                key=fields[pair];i+=2
                if t[i]=='{':
                    end=t.index('}',i);value=[x.rstrip(',') for x in t[i+1:end]];i=end+1
                else:value=[t[i]];i+=1
                terms.append((key,value))
            data['rules'][t[4]].append(terms)
        else:raise AssertionError(('unsupported nft grammar',line))
    assert data['policies']=={'incoming':'accept','output':'drop','forward':'drop'}
    return data
def decision(data,packet,chain='output'):
    p=dict(packet)
    if data is None:return 'accept'
    for terms in data['rules'][chain]:
        matched=True;verdict=None;mark=None
        for key,values in terms:
            if key=='verdict':verdict=values;continue
            if key=='setmark':mark=values;continue
            if key=='cgroup': ok=(p.get('cgroup'),p.get('inode'))==tuple(values)
            elif key in ('local','oif','original_dport'):ok=p.get(key)==values
            elif key.startswith('tcp_') or key.startswith('udp_'):
                proto,field=key.split('_');ok=p.get('proto')==proto and str(p.get(field)) in values
            elif key in ('daddr4','daddr6','saddr6'):
                family=4 if key.endswith('4') else 6
                addr=p.get(key[:-1]);ok=False
                if addr:
                    addr=ipaddress.ip_address(addr)
                    ok=addr.version==family and any(addr in ipaddress.ip_network(x,strict=False) for x in values)
            elif key=='mark':ok=str(p.get(key)) in values or (p.get(key) is not None and p[key] in [int(x,0) for x in values])
            else:ok=str(p.get(key)) in values
            if not ok:matched=False;break
        if matched:
            if mark is not None:p['mark']=mark
            if verdict:return verdict
    if chain=='incoming':return p
    return data['policies'][chain]
''')
sys.path.insert(0, str(fixture)); from model import parse, decision

def executable(name, body, python=False):
    p=b/name
    p.write_text(('#!'+sys.executable+'\n' if python else '#!/usr/bin/env bash\nset -eu\n')+body+'\n')
    p.chmod(0o755)

executable('nft', '''import json, os, pathlib, sys
sys.path.insert(0,os.environ['FIXTURE']);from model import parse
f=pathlib.Path(os.environ['FIXTURE']);args=sys.argv[1:];table=f/'table.json'
with (f/'calls.log').open('a') as log:log.write('nft '+ ' '.join(args)+'\\n')
if args in (['--check','--file','-'],['--file','-']):
    raw=sys.stdin.read();kind='checked' if args[0]=='--check' else 'submitted'
    (f/(kind+'.nft')).write_text(raw)
    batches=f/'nft-batches';batches.mkdir(exist_ok=True);sequence=f/'nft-batch-sequence'
    number=int(sequence.read_text()) if sequence.exists() else 0
    if kind=='checked':number+=1;sequence.write_text(str(number))
    (batches/(str(number).zfill(3)+'-'+kind+'.nft')).write_text(raw)
    parsed=parse(raw,int((f/'inode').read_text()))
    if os.environ.get('FAIL_'+kind.upper())=='1':sys.exit(41)
    if kind=='submitted':
        assert raw==(f/'checked.nft').read_text()
        table.write_text(json.dumps(parsed));(f/'last-applied.nft').write_text(raw)
        if os.environ.get('CGROUP_RACE')=='1' and 'socket cgroupv2' in raw:(f/'inode').write_text('222')
elif args==['list','tables']:
    if os.environ.get('FAIL_LIST')=='1':sys.exit(42)
    if table.exists():print('table inet aegis_legacy_tun_guard')
elif args==['delete','table','inet','aegis_legacy_tun_guard']:
    assert 'armed=0' in pathlib.Path(os.environ['AEGIS_LEGACY_TUN_GUARD_STATE']).read_text()
    assert not (f/'etc/systemd/system/aegis-legacy-tun-guard.service').exists()
    assert not (f/'guard-active').exists()
    assert not (f/'etc/systemd/system/aegis-client.service.d/29-legacy-tun-guard.conf').exists()
    if os.environ.get('FAIL_DELETE')=='1':sys.exit(43)
    table.unlink()
else:raise AssertionError(args)
''', True)
executable('systemctl', '''import os,pathlib,shlex,shutil,subprocess,sys
f=pathlib.Path(os.environ['FIXTURE']);a=sys.argv[1:]
with (f/'calls.log').open('a') as log:log.write('systemctl '+ ' '.join(a)+'\\n')
def unit_start(name):
    text=(f/'etc/systemd/system'/name).read_text();env=dict(os.environ)
    for line in text.splitlines():
        if line.startswith('Environment='):
            for item in shlex.split(line.split('=',1)[1]):
                k,v=item.split('=',1);env[k]=v
    line=next(x for x in text.splitlines() if x.startswith('ExecStart='))
    argv=shlex.split(line.split('=',1)[1])
    if argv[0]=='/bin/bash':argv[0]=shutil.which('bash')
    result=subprocess.run(argv,env=env,timeout=15)
    if result.returncode:sys.exit(result.returncode)
    if name=='aegis-legacy-tun-guard.service':(f/'guard-active').touch()
    if name=='aegis-wide-tun-firewall.service':(f/'capture-active').touch()
if a[0]=='show':
    print({'ControlGroup':'/system.slice/aegis-client.service','MainPID':'321','ControlPID':'321','ActiveState':'active'}[a[a.index('-p')+1]])
elif a[0]=='enable' and '--now' in a:unit_start(a[-1])
elif a[0]=='is-active':
    name=a[-1]
    flags={'aegis-client.service':'client-active','aegis-legacy-tun-guard.service':'guard-active','aegis-wide-tun-firewall.service':'capture-active'}
    if name not in flags:sys.exit(3)
    flag=flags[name]
    sys.exit(0 if (f/flag).exists() else 3)
elif a[0]=='stop' and a[-1]=='aegis-legacy-tun-guard.service':
    assert not (f/'etc/systemd/system/aegis-client.service.d/29-legacy-tun-guard.conf').exists()
    if os.environ.get('FAIL_STOP')=='1':sys.exit(44)
    (f/'guard-active').unlink(missing_ok=True)
elif a[0]=='disable' and os.environ.get('FAIL_DISABLE')=='1':sys.exit(45)
elif a[0]=='stop' and a[-1]=='aegis-wide-tun-firewall.service':(f/'capture-active').unlink(missing_ok=True)
elif a[0] in ('disable','stop','daemon-reload','reset-failed','start','restart','reload'):pass
else:raise AssertionError(a)
''', True)
executable('stat', '''if [[ "$*" == '-f -c %T '* ]]; then echo cgroup2fs; exit; fi
if [[ "$*" == '-c %i '* ]]; then cat "$FIXTURE/inode"; exit; fi
exit 93''')
executable('flock', ': # independent process lock is inert in this serial fixture')
for command in ('iptables','ip6tables'):
    executable(command, '''echo "$(basename "$0") $*" >> "$FIXTURE/calls.log"
if [[ " $* " == *' -C '* ]]; then exit 1; fi
if [[ " $* " == *' -S '* || " $* " == *' -L '* ]]; then exit; fi''')
for command in ('ip','sysctl'):
    executable(command, '''echo "$(basename "$0") $*" >> "$FIXTURE/calls.log"
if [[ "$(basename "$0") $*" == 'ip link show aegis-tun0' ]]; then exit 1; fi''')
for command in ('iptables-save','ip6tables-save'):
    executable(command, '''if [[ "${CAPTURE_RESIDUE:-0}" == 1 ]]; then echo ':AEGIS_WIDE_OUTPUT - [0:0]'; fi''')
env=dict(os.environ, PATH=str(b)+os.pathsep+os.environ['PATH'],FIXTURE=str(fixture),
    AEGIS_LEGACY_TUN_GUARD_STATE=str(state))
install=(root/'install.sh').read_text()
def function(name):
    return rebase(re.search(r'^'+name+r'\(\) \{\n.*?^\}',install,re.M|re.S).group())
functions='\n'.join(function(x) for x in ('install_legacy_tun_guard_unit','install_wide_tun_boot_unit'))
runner=fixture/'install-fixture.sh'
runner.write_text('set -eu\n'+functions+'''
ensure_dir() { [[ "$1" == "$FIXTURE/"* ]] || exit 90; mkdir -p "$1"; }
install_atomic_write() { [[ "$1" == "$FIXTURE/"* && "$1" != *'/../'* ]] || exit 91; cat > "$1"; }
SYSTEMD_DIR="$FIXTURE/etc/systemd/system"
install_legacy_tun_guard_unit "$FIXTURE/helpers/setup-wide-linux-redirect.sh" 980 981
install_wide_tun_boot_unit "$FIXTURE/helpers/setup-wide-linux-redirect.sh" 980 0 0 0 1 0 aegis-tun0 981 '' 1 '' 1 aegis-client.service system.slice/aegis-client.service
''')
def run(command, extra=None, success=True, receipt='command'):
    p=subprocess.run(command,env=env|dict(extra or {}),text=True,capture_output=True,timeout=20)
    with (fixture/'receipts.log').open('a') as f:
        f.write(receipt+' rc='+str(p.returncode)+'\n'+p.stdout+p.stderr)
    assert (p.returncode==0)==success,(receipt,p.returncode,p.stdout,p.stderr)
    return p
def guard(action,extra=None,success=True):return run(['bash',str(helper),action],extra,success,action)
run(['bash',str(runner)],receipt='render-and-arm-real-installer-functions')
assert 'systemctl stop aegis-client\n' not in (fixture/'calls.log').read_text()
assert 'systemctl start\n' not in (fixture/'calls.log').read_text()
guard_unit=(units/'aegis-legacy-tun-guard.service').read_text()
client=(units/'aegis-client.service.d/29-legacy-tun-guard.conf').read_text()
capture=(units/'aegis-wide-tun-firewall.service').read_text()
assert 'Before=network-pre.target' in guard_unit and 'DefaultDependencies=no' in guard_unit
assert not any(x.startswith(('ExecStop=','PartOf=','Requires=aegis-client')) for x in guard_unit.splitlines())
for manager in ('NetworkManager','systemd-networkd','networking'):
    m=(units/(manager+'.service.d/29-aegis-legacy-tun-guard.conf')).read_text()
    assert 'Requires=aegis-legacy-tun-guard.service' in m and 'After=aegis-legacy-tun-guard.service' in m
assert 'Requires=aegis-legacy-tun-guard.service' in client
assert 'AEGIS_WIDE_PORT=980' in capture and 'AEGIS_WIDE_UDP_REDIRECT_PORT=981' in capture
def exec_field(text,key,extra=None,success=True):
    e=dict(extra or {})
    for line in text.splitlines():
        if line.startswith('Environment='):
            for item in shlex.split(line.split('=',1)[1]):
                k,v=item.split('=',1);e[k]=v
    line=next(x for x in text.splitlines() if x.startswith(key+'='))
    argv=shlex.split(line.split('=',1)[1])
    # The production target is Linux Bash. macOS /bin/bash 3.2 has a known
    # empty-array nounset incompatibility in the unchanged capture helper.
    # Keep the rendered unit bytes exact; select the runner's Bash executable.
    if argv[0]=='/bin/bash':argv[0]=shutil.which('bash')
    return run(argv,e,success,key)
def table():return json.loads((fixture/'table.json').read_text()) if (fixture/'table.json').exists() else None
def packets_blocked():
    for family,destination in [('ipv4','198.51.100.9'),('ipv6','2001:db8::9')]:
        for proto,port in [('tcp',443),('tcp',53),('udp',53),('udp',443)]:
            p=dict(family=family,daddr=destination,oif='eth0',proto=proto,sport=40000,dport=port,direction='original',state='established')
            assert decision(table(),p)=='drop',p
            assert decision(table(),p,'forward')=='drop',p
    assert decision(table(),dict(oif='lo'))=='accept'
    assert decision(table(),dict(family='ipv6',oif='aegis-tun0'))=='accept'
    incoming=decision(table(),dict(local=True,proto='tcp',dport=22,direction='original',state='new'),'incoming')
    p=dict(proto='tcp',sport=22,original_dport=22,direction='reply',mark=incoming['mark'])
    assert decision(table(),p)=='accept'
    for mutation in ({'direction':'original'},{'sport':443},{'original_dport':443},{'mark':0}):
        assert decision(table(),p|mutation)=='drop',mutation
    for p in (dict(daddr='255.255.255.255',proto='udp',sport=68,dport=67),
              dict(saddr='fe80::1',daddr='ff02::1:2',proto='udp',sport=546,dport=547),
              dict(daddr='ff02::1',hoplimit=255,icmp_type='nd-neighbor-advert')):
        assert decision(table(),p)=='accept',p
        assert decision(table(),p|{'daddr':'2001:db8::9'})=='drop',p

# Boot: kernel table starts empty. The generated guard runs before a dependent
# manager/client; a failed guard dependency never authorizes their startup.
(fixture/'table.json').unlink()
exec_field(guard_unit,'ExecStart',{'FAIL_CHECKED':'1'},False)
assert table() is None
exec_field(guard_unit,'ExecStart');packets_blocked()
blocked=(fixture/'table.json').read_bytes()
exec_field(client,'ExecStartPre',{'FAIL_CHECKED':'1'},False)
assert (fixture/'table.json').read_bytes()==blocked
exec_field(client,'ExecStartPre');bound=(fixture/'table.json').read_bytes();packets_blocked()
assert decision(table(),dict(cgroup='system.slice/aegis-client.service',inode=111))=='accept'
assert decision(table(),dict(cgroup='system.slice/aegis-client.service',inode=222))=='drop'
for proto,port in [('tcp',980),('udp',981)]:
    assert decision(table(),dict(proto=proto,dport=port,daddr='127.0.0.1',status='dnat'))=='accept'
    assert decision(table(),dict(proto=proto,dport=port,daddr='198.51.100.9',status='dnat'))=='drop'
    assert decision(table(),dict(proto=proto,dport=port,daddr='127.0.0.1'))=='drop'

# Execute real capture teardown from the generated unit. Independent nft table
# remains until the client stop hook blocks its old cgroup; no stop deletes it.
exec_field(capture,'ExecStop');assert (fixture/'table.json').read_bytes()==bound
run([str(b/'systemctl'),'stop','aegis-wide-tun-firewall.service'],receipt='capture-stop-complete')
exec_field(client,'ExecStopPost');packets_blocked()
assert 'socket cgroupv2' not in (fixture/'last-applied.nft').read_text()
# Crash-loop/start-limit terminal state: repeated real pre/stop hooks leave the
# table installed, without a cgroup or local DNAT permission after final stop.
for inode in (333,444,555):
    (fixture/'inode').write_text(str(inode));exec_field(client,'ExecStartPre');exec_field(client,'ExecStopPost');packets_blocked()
assert 'delete table' not in (fixture/'calls.log').read_text()
for knob in ('FAIL_CHECKED','FAIL_SUBMITTED'):
    old=(fixture/'table.json').read_bytes();guard('guard-block',{knob:'1'},False)
    assert (fixture/'table.json').read_bytes()==old
guard('guard-bind',{'CGROUP_RACE':'1'},False);packets_blocked()
assert 'socket cgroupv2' not in (fixture/'last-applied.nft').read_text()
port_floor.write_text('0\n');guard('guard-preflight',success=False);port_floor.write_text('1024\n')
original=state.read_text()
for change in ('management_ports=22;accept','tcp_port=15080','service=user.service'):
    key=change.split('=',1)[0];state.write_text(re.sub(r'^'+key+r'=.*$',change,original,flags=re.M))
    guard('guard-block',success=False);packets_blocked()
state.write_text(original)

# Release: every storage/systemd failure preserves the deny table. Durable
# armed=0 state precedes dependency removal, stopping and nft deletion.
guard('guard-release',{'CAPTURE_RESIDUE':'1'},False);assert 'armed=1' in state.read_text();packets_blocked()
guard('guard-release',{'FAIL_DISABLE':'1'},False);assert 'armed=0' in state.read_text();packets_blocked()
guard('guard-block');packets_blocked() # crash after durable disarm never deletes
guard('guard-release',{'FAIL_STOP':'1'},False);packets_blocked()
guard('guard-release',{'FAIL_DELETE':'1'},False);packets_blocked()
guard('guard-release');assert table() is None and 'armed=0' in state.read_text()

# Caller mapping uses the actual activation function and actual config writer;
# device rendering is a separate fixed-port path and never invokes this guard.
activation=function('activate_wide_capture')
assert '[[ "${PRODUCT_MODE:-}" != full-wide-tun ]] || port=980' in activation
assert activation.index('set_client_dns_preview') < activation.index('install_legacy_tun_guard_unit') < activation.index('restart_systemd_unit_checked')
assert 'install_wide_tun_boot_unit "$capture" 15080' in install
assert 'AEGIS_WIDE_UDP_REDIRECT_PORT=15081' in install
writer=fixture/'config-writer.sh'
writer.write_text('set -eu\n'+function('set_client_config_wide')+'''\nset_client_config_wide "$FIXTURE/client.toml" linux_redirect 980\n''')
(fixture/'client.toml').write_text('[ingress]\nprimary = "socks5"\n')
run(['bash',str(writer)],receipt='actual-config-port-writer')
assert 'listen = "127.0.0.1:980"' in (fixture/'client.toml').read_text()
# Exercise the caller, config mutators, guard installer and capture helper in a
# single inert activation. This catches mismatches between 980/981 and generated
# configuration, capture environment, persistence unit and guard DNAT tuples.
source=fixture/'source/scripts';(source/'lib').mkdir(parents=True)
shutil.copy(helper,source/'setup-wide-linux-redirect.sh')
shutil.copy(lib/'lib/root-state.sh',source/'lib/root-state.sh')
activation_runner=fixture/'activation-fixture.sh'
mutators='\n'.join(function(x) for x in ('set_client_config_wide','set_client_config_udp_contract',
    'set_client_config_ipv6_tun','set_client_config_udp_relay_plan','set_client_dns_preview'))
activation_runner.write_text('set -eu\n'+functions+'\n'+mutators+'\n'+
    function('preflight_wide_capture')+'\n'+activation+'''
ensure_dir() { [[ "$1" == "$FIXTURE/"* ]] || exit 90; mkdir -p "$1"; }
install_atomic_write() { [[ "$1" == "$FIXTURE/"* && "$1" != *'/../'* ]] || exit 91; cat > "$1"; }
install_copy_file() { [[ "$2" == "$FIXTURE/"* ]] || exit 92; cp "$1" "$2"; }
client_service_uid() { echo 0; }
id() { echo 0; }
sleep() { :; }
curl() { echo 301; }
getent() { echo '192.0.2.1 example.test'; }
pin_relay_server_to_resolved_ipv4() { :; }
restart_systemd_unit_checked() {
  bash "$FIXTURE/helpers/setup-wide-linux-redirect.sh" guard-block &&
  bash "$FIXTURE/helpers/setup-wide-linux-redirect.sh" guard-bind
}
ROOT="$FIXTURE/source"
SYSTEMD_DIR="$FIXTURE/etc/systemd/system"
AEGIS_WIDE_LIB_DIR="$FIXTURE/helpers"
PRODUCT_MODE=full-wide-tun
UDP_CARRY=1
MASQUE_SERVER=''
MASQUE_CA=''
WIDE_INTERFACE=''
RES_UDP_POLICY=masque_direct
RES_DNS_POLICY=preview
RES_IPV6_POLICY=tun_carried
RES_LEAK_RISK=low
activate_wide_capture "$FIXTURE/client.toml" client-ipv6-tun-smoltcp
''')
(fixture/'client.toml').write_text('[relay]\nserver = "203.0.113.7:443"\n[ingress]\nprimary = "socks5"\n')
saved_helper=(source/'setup-wide-linux-redirect.sh').read_text()
(source/'setup-wide-linux-redirect.sh').write_text('#!/usr/bin/env bash\nexit 2\n')
unchanged_config=(fixture/'client.toml').read_bytes()
run(['bash',str(activation_runner)],success=False,receipt='old-signed-helper-rejected-before-wide-config-start')
assert (fixture/'client.toml').read_bytes()==unchanged_config
(source/'setup-wide-linux-redirect.sh').write_text(saved_helper)
run(['bash',str(activation_runner)],receipt='actual-legacy-activation')
assert 'listen = "127.0.0.1:980"' in (fixture/'client.toml').read_text()
assert 'tcp_port=980\nudp_port=981' in state.read_text()
capture=(units/'aegis-wide-tun-firewall.service').read_text()
assert 'AEGIS_WIDE_PORT=980' in capture and 'AEGIS_WIDE_UDP_REDIRECT_PORT=981' in capture
calls=(fixture/'calls.log').read_text()
assert 'iptables -t nat -A AEGIS_WIDE_OUTPUT -p tcp -j REDIRECT --to-ports 980' in calls
assert 'iptables -t nat -A AEGIS_WIDE_OUTPUT -p udp -j REDIRECT --to-ports 981' in calls
packets_blocked()
# Explicit disable release is placed after all config/capture residue checks.
disable=(root/'scripts/aegis-wide-disable.sh').read_text()
assert disable.index('if [[ ${disable_residue} -ne 0 ]]') < disable.index('guard-release; then')
assert 'AEGIS_WIDE_DISABLE_FROM_UNIT:-0' in disable and 'AEGIS_WIDE_DISABLE_KEEP_LEGACY_GUARD:-0' in disable
assert 'AEGIS_WIDE_DISABLE_KEEP_LEGACY_GUARD=1 bash' in install
# Execute the real outer disconnect, including a failed residue check and the
# upgrade keep-guard path. Policy deletion is observable only after success.
with (lib/'lib/root-state.sh').open('a') as f:
    f.write('''aegis_root_network_preflight() {
  AEGIS_WIDE_SYSCTL_FILE="$FIXTURE/sysctl.conf"
  AEGIS_WIDE_SYSCTL_SNAPSHOT="$FIXTURE/sysctl.snapshot"
  AEGIS_WIDE_RESOLVER_SNAPSHOT="$FIXTURE/resolver.snapshot"
}
''')
outer=lib/'aegis-wide-disable.sh';outer.write_text(rebase(disable));outer.chmod(0o755)
run(['bash',str(outer)],{'AEGIS_WIDE_SKIP_ROOT_CHECK':'1','AEGIS_CONFIG_FILE':str(fixture/'client.toml'),
    'CAPTURE_RESIDUE':'1'},False,receipt='explicit-disconnect-residue-rejected')
packets_blocked();assert 'armed=1' in state.read_text()
run(['bash',str(outer)],{'AEGIS_WIDE_SKIP_ROOT_CHECK':'1','AEGIS_CONFIG_FILE':str(fixture/'client.toml'),
    'AEGIS_WIDE_DISABLE_KEEP_LEGACY_GUARD':'1'},receipt='upgrade-capture-cleanup-retains-guard')
packets_blocked();assert 'armed=1' in state.read_text()
run(['bash',str(outer)],{'AEGIS_WIDE_SKIP_ROOT_CHECK':'1','AEGIS_CONFIG_FILE':str(fixture/'client.toml')},receipt='explicit-disconnect-release-last')
assert table() is None and 'armed=0' in state.read_text()
assert 'primary = "socks5"' in (fixture/'client.toml').read_text()
print('PASS: generated legacy guard/capture units; actual pre/stop/boot hooks and nft batches; IPv4/IPv6 TCP/UDP/DNS/forward denial, scoped SSH, fresh cgroups, terminal crash loop; failed checks/apply/disarm/delete retain policy; legacy 980/981 and device mapping retained. Fixture only: native nft/systemd/boot acceptance unmeasured.')
if temporary:temporary.cleanup()
PY
