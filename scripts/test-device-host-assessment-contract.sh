#!/usr/bin/env bash
# Feed recorded-shape host observations to the production assessment policy.
# All filesystem observations are fixture-local; no host commands are executed.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
python3 -I - "$ROOT" <<'PY'
import ast,copy,json,os,pathlib,re,subprocess,sys,tempfile
source=(pathlib.Path(sys.argv[1])/'install.sh').read_text();count=0
function=re.search(r'^device_assess_guard_host\(\) \{\n.*?^\}',source,re.M|re.S)[0]
program=function.split("python3 -I -c '\n",1)[1].rsplit("\n' ",1)[0]
with tempfile.TemporaryDirectory(prefix='aegis-host-assess-',dir='/tmp') as raw:
 root=pathlib.Path(raw).resolve()
 for path in ('run/systemd/system','sys/class/net/eth0','sys/class/net/lo','dev/net','proc/net','proc/sys/net/ipv4','proc/sys/net/ipv6/conf/all','run/systemd/network'):(root/path).mkdir(parents=True,exist_ok=True)
 (root/'dev/net/tun').touch();(root/'proc/net/if_inet6').touch()
 config=root/'run/systemd/network/eth0.network';config.write_text('[Network]\nDHCP=ipv4\n')
 adapted=program.replace('p=json.load(sys.stdin)','fixture=json.loads(os.environ["FIXTURE_DATA"]);p=json.load(sys.stdin)')
 run_node=next(node for node in ast.parse(adapted).body if isinstance(node,ast.FunctionDef) and node.name=='run')
 lines=adapted.splitlines();lines[run_node.lineno-1:run_node.end_lineno]=['def run(*args):',' value=fixture["commands"][" ".join(args)];return value.pop(0) if isinstance(value,list) else value'];adapted='\n'.join(lines)
 adapted=re.sub(r'def active\(unit\):.*', 'def active(unit): return unit in fixture["active"]',adapted)
 adapted=re.sub(r'def enabled\(unit\):.*', 'def enabled(unit): return unit in fixture["enabled"]',adapted)
 adapted=adapted.replace('shutil.which(command)','command not in fixture["missing"]')
 adapted=adapted.replace('os.geteuid()==0 and sys.platform.startswith("linux")','os.geteuid()=='+str(os.getuid()))
 adapted=adapted.replace('.is_char_device()','.is_file()').replace('metadata.st_uid==0','metadata.st_uid=='+str(os.getuid()))
 adapted=adapted.replace('st.st_uid==0',f'st.st_uid in (0,{os.getuid()})').replace('not st.st_mode&0o022','(not st.st_mode&0o022 or str(item) in ("/tmp","/private/tmp"))')
 for old in ('/etc/ufw/ufw.conf','/etc/systemd/network','/run/systemd/network','/usr/local/lib/systemd/network','/usr/lib/systemd/network','/lib/systemd/network','/run/systemd/system','/sys/class/net','/dev/net/tun','/proc/net/if_inet6','/proc/sys/net/ipv4/ip_forward','/proc/sys/net/ipv6/conf/all/forwarding','/var/lib/aegis-install/client/device-guard.conf','/usr/local/bin/aegis-client','/usr/lib/systemd/systemd-resolved','/usr/lib/systemd/systemd-timesyncd','/proc/sys/net/ipv4/ip_local_port_range','/proc'):
  adapted=adapted.replace('"'+old+'"','"'+str(root/old[1:])+'"')
 base={'active':['systemd-networkd.service'],'enabled':['systemd-networkd.service'],'missing':[], 'commands':{
 'bash /fixture/guard.sh assess-foreign-policy eth0':json.dumps({'schema':'aegis_foreign_policy_v1','class':'filter_only','backend':'nf_tables','ufw_integrity_sha256':'0'*64}),
 'stat -f -c %T /sys/fs/cgroup':'cgroup2fs',
 'ip -j route get 198.51.100.4':json.dumps([{'dev':'eth0','prefsrc':'192.0.2.7'}]),
 'ip -j address show dev eth0':json.dumps([{'addr_info':[{'family':'inet','scope':'global','local':'192.0.2.7','dynamic':True}]}]),
 'networkctl status eth0 --no-pager':'Network File: '+str(config),
 'ss -H -ltnpe':'LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=1))\nLISTEN 0 4096 127.0.0.53:53 0.0.0.0:* users:(("resolver",pid=2,fd=1))',
 'ss -H -lunpe':'UNCONN 0 0 0.0.0.0:68 0.0.0.0:* users:(("systemd-network",pid=3,fd=1))'}}
 def check(name,change=lambda x:None,ok=False,forward='0',interface='',boot='absent_verified'):
  global count
  f=copy.deepcopy(base);change(f)
  (root/'proc/sys/net/ipv4/ip_forward').write_text(forward);(root/'proc/sys/net/ipv6/conf/all/forwarding').write_text('0')
  r=subprocess.run([sys.executable,'-I','-c',adapted,interface,json.dumps({'initramfs_network':boot,'initrd_sha256':'synthetic-verified-boot'}),'/fixture/guard.sh','device-full-wide-tun'],input=json.dumps({'relay_server':'198.51.100.4:443'}),env=dict(os.environ,FIXTURE_DATA=json.dumps(f)),text=True,capture_output=True,timeout=5)
  assert (r.returncode==0)==ok,(name,r.returncode,r.stdout,r.stderr)
  if ok:
   state=dict(line.split('=',1) for line in r.stdout.splitlines());assert state['uplink']=='eth0' and state['dhcp4']=='1' and state['management_ports']=='22' and state['schema']=='aegis_device_guard_v2' and state['management_address_policy']=='current_local' and 'management_ipv4' not in state and 'management_ipv6' not in state
   if state['manager']=='NetworkManager.service':
    assert state['manager_connection_uuid']=='11111111-2222-3333-4444-555555555555' and state['manager_ipv4_method']=='auto' and state['manager_ipv6_method']=='disabled'
   assert state['foreign_policy']=='filter_only' and state['ufw_integrity_sha256']=='0'*64
  count+=1
  print('PASS host:',name)
 check('observed single networkd uplink',ok=True)
 def nm(f,**changes):
  f['active']=f['enabled']=['NetworkManager.service']
  policy=dict(schema='aegis_networkmanager_assessment_v1',manager_connection_uuid='11111111-2222-3333-4444-555555555555',manager_ipv4_method='auto',manager_ipv6_method='disabled',dhcp4=True,dhcp6=False,explicit_internal=True)
  policy.update(changes)
  f['commands']['bash /fixture/guard.sh assess-networkmanager eth0']=json.dumps(policy)
  f['commands']['ss -H -lunpe']='UNCONN 0 0 0.0.0.0:68 0.0.0.0:* users:(("NetworkManager",pid=3,fd=1))'
 check('NM typed v2 state preserves assessed connection',nm,ok=True)
 check('NM wrong assessment schema',lambda f:nm(f,schema='unknown'))
 check('NM invalid connection UUID',lambda f:nm(f,manager_connection_uuid='unknown'))
 check('NM invalid IP method',lambda f:nm(f,manager_ipv4_method='shared'))
 check('NM dynamic address contradicts assessed policy',lambda f:nm(f,dhcp4=False,manager_ipv4_method='manual'))
 check('NM nonboolean DHCP policy',lambda f:nm(f,dhcp4=1))
 config.write_text('[Network]\n DHCP = ipv4 \n');check('section-aware spaced DHCP',ok=True)
 config.write_text('[DHCPv4]\nDHCP=ipv4\n');check('wrong-section DHCP cannot enable lease')
 config.write_text('[Network]\nDHCP=unknown\n');check('unknown DHCP value')
 config.write_text('[Network]\nDHCP=ipv4\nDHCP=no\n');check('ambiguous DHCP settings')
 config.write_text('[Network]\nDHCP=ipv4'+chr(92)+'\n');check('unknown continuation')
 config.write_text('[Network]\nDHCP=ipv4\n')
 dropin=config.parent/'eth0.network.d';dropin.mkdir();check('runtime drop-in refuses before arm');dropin.rmdir()
 vendor=root/'usr/lib/systemd/network/other.network.d';vendor.mkdir(parents=True);check('vendor drop-in refuses before arm');vendor.rmdir()
 check('reported drop-in refuses before arm',lambda f:f['commands'].__setitem__('networkctl status eth0 --no-pager','Network File: '+str(config)+'\n Drop-In: /etc/systemd/network/eth0.network.d'))
 check('missing nft' ,lambda f:f['missing'].append('nft'))
 check('cgroup v1',lambda f:f['commands'].__setitem__('stat -f -c %T /sys/fs/cgroup','tmpfs'))
 check('forwarding enabled',forward='1')
 def ufw(f,proof=None):
  f['enabled'].append('ufw.service');f['active'].append('ufw.service')
  if proof is not None:f['commands']['bash /fixture/guard.sh assess-foreign-policy eth0']=json.dumps(proof)
 # UFW unit presence is allowed only with the same semantic foreign-policy
 # assessment used without UFW. Real UFW rules are tested in the root cohort.
 check('semantically assessed active UFW',ufw,ok=True)
 ufw_file=root/'etc/ufw/ufw.conf';ufw_file.parent.mkdir(parents=True);ufw_file.write_text('ENABLED=no\n')
 def disabled_ufw(f):
  ufw(f);f['enabled'].remove('ufw.service');f['active'].remove('ufw.service')
 check('disabled unit still assesses remaining UFW policy',disabled_ufw,ok=True)
 check('disabled unit cannot skip missing semantic assessment',lambda f:f['commands'].pop('bash /fixture/guard.sh assess-foreign-policy eth0'))
 ufw_file.unlink()
 check('incomplete foreign proof rejected',lambda f:ufw(f,{}))
 check('legacy foreign backend rejected',lambda f:ufw(f,{'schema':'aegis_foreign_policy_v1','class':'filter_only','backend':'legacy','ufw_integrity_sha256':'0'*64}))
 check('unhandled foreign policy rejected',lambda f:ufw(f,{'schema':'aegis_foreign_policy_v1','class':'unhandled','backend':'nf_tables','ufw_integrity_sha256':'0'*64}))
 check('unknown foreign proof schema rejected',lambda f:ufw(f,{'schema':'unknown','class':'filter_only','backend':'nf_tables','ufw_integrity_sha256':'0'*64}))
 check('malformed foreign reply rejected',lambda f:f['commands'].__setitem__('bash /fixture/guard.sh assess-foreign-policy eth0','{'))
 check('multiple managers',lambda f:f['active'].append('NetworkManager.service'))
 check('explicit interface conflict',interface='eth1')
 check('ambiguous relay route',lambda f:f['commands'].__setitem__('ip -j route get 198.51.100.4','[]'))
 check('foreign public TCP service',lambda f:f['commands'].__setitem__('ss -H -ltnpe','LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:(("httpd",pid=4,fd=1))'))
 check('foreign public UDP service',lambda f:f['commands'].__setitem__('ss -H -lunpe','UNCONN 0 0 0.0.0.0:9999 0.0.0.0:* users:(("app",pid=4,fd=1))'))
 resolver_exe=root/'usr/lib/systemd/systemd-resolved';resolver_exe.parent.mkdir(parents=True,exist_ok=True);resolver_exe.write_text('resolver fixture');resolver_exe.chmod(0o755)
 resolver_proc=root/'proc/5050';(resolver_proc/'fd').mkdir(parents=True);(resolver_proc/'exe').symlink_to(resolver_exe)
 (resolver_proc/'stat').write_text('5050 (resolver fixture) S '+'0 '*18+'9')
 (resolver_proc/'cgroup').write_text('0::/system.slice/systemd-resolved.service\n');(resolver_proc/'fd/12').symlink_to('socket:[12345]')
 def resolver(f):
  f['active'].append('systemd-resolved.service')
  f['commands']['systemctl show systemd-resolved.service -p MainPID --value']='5050'
  f['commands']['ss -H -ltnpe']+='\nLISTEN 0 4096 0.0.0.0:5355 0.0.0.0:* users:(("arbitrary-name",pid=5050,fd=12)) ino:12345 sk:4'
  f['commands']['ss -H -lunpe']+='\nUNCONN 0 0 [::]:5355 [::]:* users:(("arbitrary-name",pid=5050,fd=12)) ino:12345 sk:4'
 check('attested resolver LLMNR is not a management exemption',resolver,ok=True)
 def bad_resolver(f,key,old,new):
  resolver(f);f['commands'][key]=f['commands'][key].replace(old,new)
 check('resolver name cannot impersonate PID',lambda f:bad_resolver(f,'ss -H -ltnpe','pid=5050','pid=5051'))
 check('resolver socket inode mismatch',lambda f:bad_resolver(f,'ss -H -ltnpe','ino:12345','ino:12346'))
 check('resolver public DNS server remains unsupported',lambda f:bad_resolver(f,'ss -H -ltnpe',':5355',':53'))
 (resolver_proc/'cgroup').write_text('0::/system.slice/unrelated.service\n');check('resolver wrong cgroup',resolver)
 (resolver_proc/'cgroup').write_text('0::/system.slice/systemd-resolved.service\n')
 def changed_resolver(f):
  resolver(f);f['commands']['systemctl show systemd-resolved.service -p MainPID --value']=['5050','5050','5051']
 check('resolver changes before assessment completion',changed_resolver)
 other_resolver=root/'other-resolver';other_resolver.write_text('other');(resolver_proc/'exe').unlink();(resolver_proc/'exe').symlink_to(other_resolver)
 check('resolver executable mismatch',resolver)
 (resolver_proc/'exe').unlink();(resolver_proc/'exe').symlink_to(resolver_exe)
 ntp_exe=root/'usr/lib/systemd/systemd-timesyncd';ntp_exe.write_text('timesync fixture');ntp_exe.chmod(0o755)
 ntp_proc=root/'proc/6060';(ntp_proc/'fd').mkdir(parents=True);(ntp_proc/'exe').symlink_to(ntp_exe)
 (ntp_proc/'stat').write_text('6060 (timesync fixture) S '+'0 '*18+'11')
 (ntp_proc/'cgroup').write_text('0::/system.slice/systemd-timesyncd.service\n');(ntp_proc/'fd/17').symlink_to('socket:[9648]')
 port_range=root/'proc/sys/net/ipv4/ip_local_port_range';port_range.write_text('32768 60999\n')
 def timesync(f):
  f['active'].append('systemd-timesyncd.service')
  f['commands']['systemctl show systemd-timesyncd.service -p MainPID --value']='6060'
  f['commands']['ss -H -lunpe']+='\nUNCONN 0 0 0.0.0.0:53658 0.0.0.0:* users:(("systemd-timesyn",pid=6060,fd=17)) ino:9648 sk:8'
 check('attested timesyncd client does not add management port',timesync,ok=True)
 def changed_timesync(f,old,new):
  timesync(f);f['commands']['ss -H -lunpe']=f['commands']['ss -H -lunpe'].replace(old,new)
 check('attested IPv6 timesyncd client',lambda f:changed_timesync(f,'0.0.0.0:53658','[::]:53658'),ok=True)
 check('timesyncd name cannot impersonate PID',lambda f:changed_timesync(f,'pid=6060','pid=6061'))
 check('timesyncd socket mismatch',lambda f:changed_timesync(f,'ino:9648','ino:9649'))
 check('timesyncd NTP server port refused',lambda f:changed_timesync(f,':53658',':123'))
 check('timesyncd outside ephemeral range refused',lambda f:changed_timesync(f,':53658',':32000'))
 check('timesyncd missing socket owner refused',lambda f:changed_timesync(f,'pid=6060,fd=17','unknown'))
 def restarted_timesync(f):
  timesync(f);f['commands']['systemctl show systemd-timesyncd.service -p MainPID --value']=['6060','6061']
 check('timesyncd restart before assessment completion refused',restarted_timesync)
 (ntp_proc/'cgroup').write_text('0::/system.slice/other.service\n');check('timesyncd cgroup mismatch',timesync)
 (ntp_proc/'cgroup').write_text('0::/system.slice/systemd-timesyncd.service\n')
 (ntp_proc/'exe').unlink();(ntp_proc/'exe').symlink_to(other_resolver);check('timesyncd executable mismatch',timesync)
 (ntp_proc/'exe').unlink();(ntp_proc/'exe').symlink_to(ntp_exe)
 port_range.write_text('0 65535');check('unsafe ephemeral range refused',timesync);port_range.write_text('32768 60999')
 def tcp_timesync(f):
  timesync(f);f['commands']['ss -H -ltnpe']+='\nLISTEN 0 0 0.0.0.0:53658 0.0.0.0:* users:(("systemd-timesyn",pid=6060,fd=17)) ino:9648'
 check('timesyncd TCP socket never exempted',tcp_timesync)
 check('missing boot proof',boot='unknown')
 (root/'sys/class/net/veth-test').mkdir();check('container interface');(root/'sys/class/net/veth-test').rmdir()
 (root/'dev/net/tun').unlink();check('missing TUN device')
 (root/'dev/net/tun').touch()
 state=root/'var/lib/aegis-install/client/device-guard.conf';state.parent.mkdir(parents=True);state.write_text('schema=aegis_device_guard_v1\narmed=1\nservice=aegis-client.service\n')
 exe=root/'usr/local/bin/aegis-client';exe.parent.mkdir(parents=True);exe.write_text('fixture executable');exe.chmod(0o755)
 proc=root/'proc/4242';(proc/'fd').mkdir(parents=True);(proc/'exe').symlink_to(exe)
 (proc/'stat').write_text('4242 (fixture client) S '+'0 '*18+'7')
 (proc/'cgroup').write_text('0::/system.slice/aegis-client.service\n');(proc/'fd/18').symlink_to('socket:[98765]')
 def managed(f):
  f['active'].append('aegis-client.service')
  f['commands']['systemctl show aegis-client.service -p MainPID --value']='4242'
  f['commands']['systemctl show aegis-client.service -p ControlGroup --value']='/system.slice/aegis-client.service'
  f['commands']['ss -H -lunpe']='UNCONN 0 0 0.0.0.0:15081 0.0.0.0:* users:(("arbitrary-name",pid=4242,fd=18)) ino:98765 sk:1'
 check('attested managed UDP listener',managed,ok=True)
 def wrong_pid(f):
  managed(f);f['commands']['ss -H -lunpe']=f['commands']['ss -H -lunpe'].replace('pid=4242','pid=4243')
 check('same port different PID',wrong_pid)
 def changed_pid(f):
  managed(f);f['commands']['systemctl show aegis-client.service -p MainPID --value']=['4242','4243']
 check('service changed during assessment',changed_pid)
 def wrong_inode(f):
  managed(f);f['commands']['ss -H -lunpe']=f['commands']['ss -H -lunpe'].replace('ino:98765','ino:98766')
 check('same PID different socket inode',wrong_inode)
 def wrong_port(f):
  managed(f);f['commands']['ss -H -lunpe']=f['commands']['ss -H -lunpe'].replace(':15081',':9999')
 check('owned but unexpected public port',wrong_port)
 (proc/'cgroup').write_text('0::/system.slice/other.service\n');check('managed cgroup mismatch',managed)
 (proc/'cgroup').write_text('0::/system.slice/aegis-client.service\n')
 other=root/'other-exe';other.write_text('other');(proc/'exe').unlink();(proc/'exe').symlink_to(other)
 check('managed executable mismatch',managed)
 print(f'PASS: {count} host policy cases; semantic foreign/UFW admission, exact managed PID/cgroup/executable/socket and NM state checks; no actual host commands')
PY
