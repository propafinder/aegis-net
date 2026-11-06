"""Linux-only opt-in isolated native emitted-batch QA; exact CI proof is separate.
No self-escalation, named netns, host nft/ip mutation, VM or client installation.
"""
import argparse, hashlib, json, os, pathlib, re, select, selectors, shutil
import signal, socket, stat, subprocess, sys, threading, time, types

HELPER_SHA = '8386706cbe1cd9f195e73caceacd300e3dcd8425ec8fc20750346709d70c248b'
CONTRACT_SHA = 'ce950b8fe7bca11846a16c23e98e89ced59f5935e4b46362cbe46645ec3a4840'
STAGE_SHA = '5c5053fc84543a8ad1e144d254c58d2cb5c9b850dc80abe1ec86e6bfbf1ad4ae'
NS = ('user', 'net', 'pid', 'mnt')
V4, V6 = '198.18.0.1', 'fd00:17::1'
P4, P6 = '198.18.0.2', 'fd00:17::2'
PROBE = r'''import json,socket,sys
family=socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET
udp=sys.argv[2]=='dns'; token=sys.argv[3].encode()
data=(b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'+bytes([len(token)])+token+b'\x07invalid\x00\x00\x01\x00\x01') if udp else token
s=socket.socket(family,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM);s.settimeout(.6)
try:
 s.connect((sys.argv[1],53 if udp else 8443));s.sendall(data);reply=s.recv(4096)
 if reply!=data: raise ValueError('oracle payload mismatch')
 print(json.dumps({'roundtrip':True}));sys.exit(0)
except (OSError,ValueError): print(json.dumps({'roundtrip':False}));sys.exit(23)
finally: s.close()
'''

def need(value, reason):
    if not value:
        raise AssertionError(reason)

def sha(path):
    need(stat.S_ISREG(path.lstat().st_mode) and not path.is_symlink(), 'Regular immutable input required')
    need(not any('grpc' in p.casefold() for p in path.parts + path.resolve().parts), 'Excluded component refused before bytes')
    need(all(not parent.is_symlink() for parent in path.parents), 'Input parent alias refused before bytes')
    return hashlib.sha256(path.read_bytes()).hexdigest()

def write(path, value):
    data = value if isinstance(value, bytes) else json.dumps(value, sort_keys=True, indent=2).encode() + b'\n'
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(data); out.flush(); os.fsync(out.fileno())

def identities():
    return {name: os.readlink('/proc/self/ns/' + name) for name in NS}

def park():
    print(json.dumps({'pid': os.getpid(), 'net': os.readlink('/proc/self/ns/net')}), flush=True)
    need(sys.stdin.readline().strip() == 'exit', 'Owned park request invalid')

def inside(config_path):
    c = json.loads(config_path.read_bytes()); out = config_path.parent
    own = identities()
    need(os.getpid() == 1 and os.geteuid() == 0 and all(own[n] != c['host_namespaces'][n] for n in NS), 'Fresh user/net/PID/mount namespaces required before native operations')
    cutoff = time.monotonic() + 105
    clean_env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'}
    sequence, results, received = [], [], []
    child = None; selector = selectors.DefaultSelector(); stop = threading.Event(); worker = None
    def command(argv, *, data=None, expected=0):
        need(time.monotonic() < cutoff, 'Original105s inner cutoff')
        label = 'command-%03d' % len(sequence)
        bound=min(4,cutoff-time.monotonic())
        write(out/(label+'.intent.json'),{'argv':argv,'effective_bound_seconds':bound,'input_sha256':None if data is None else hashlib.sha256(data).hexdigest(),'expected_exit':expected})
        try:
            r = subprocess.run(argv, input=data, capture_output=True, timeout=bound, env=clean_env)
        except subprocess.TimeoutExpired as error:
            write(out/(label+'.stdout'),error.stdout or b'');write(out/(label+'.stderr'),error.stderr or b'')
            write(out/(label+'.receipt.json'),{'argv':argv,'timed_out':True,'accepted':False})
            raise
        write(out / (label + '.stdout'), r.stdout); write(out / (label + '.stderr'), r.stderr)
        row={'argv':argv,'exit_code':r.returncode,'effective_bound_seconds':bound,'timed_out':False,'stdout_sha256':hashlib.sha256(r.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(r.stderr).hexdigest()}
        sequence.append(row);write(out/(label+'.receipt.json'),row)
        need(r.returncode == expected if expected is not None else r.returncode != 0, 'Native command unexpected status')
        return r.stdout
    tools = c['tools']; ip, nft, nsenter = tools['ip']['path'], tools['nft']['path'], tools['nsenter']['path']
    def peer(argv, **kw):
        need(child is not None and child.poll() is None, 'Owned namespace keeper unavailable')
        need(os.readlink('/proc/%d/ns/net' % peer_pid) == peer_ns and peer_ns != own['net'], 'Owned peer namespace changed')
        return command([nsenter, '--target', str(peer_pid), '--net', '--'] + argv, **kw)
    def oracle():
        try:
            while not stop.is_set():
                for key, _ in selector.select(.05):
                    s, udp = key.fileobj, key.data
                    if udp:
                        data, address = s.recvfrom(4096); received.append(data); s.sendto(data, address)
                    else:
                        accepted, _ = s.accept()
                        with accepted:
                            accepted.settimeout(.6); data = accepted.recv(4096)
                            received.append(data); accepted.sendall(data)
        except BaseException as error:
            results.append({'oracle_error': type(error).__name__}); stop.set()
    def projection(payload):
        # Retention comparison preserves every policy field/handle/order. Only
        # metainfo and mutable packet/byte totals are outside this projection.
        if isinstance(payload, dict):
            if set(payload) == {'metainfo'}: return None
            if set(payload) == {'counter'} and isinstance(payload['counter'], dict):
                need(set(payload['counter']) == {'packets','bytes'}, 'Unknown counter schema')
                return {'counter': {'packets': '<dynamic>', 'bytes': '<dynamic>'}}
            return {k: projection(v) for k,v in payload.items()}
        if isinstance(payload, list): return [projection(v) for v in payload if not (isinstance(v,dict) and set(v)=={'metainfo'})]
        return payload
    def table():
        value = json.loads(peer([nft, '--json', 'list', 'table', 'inet', 'aegis_device_guard']))
        chains = {x['chain']['name']:x['chain'] for x in value['nftables'] if 'chain' in x}
        need(set(chains)=={'incoming','output','forward','postroute'}, 'Native four-chain inventory mismatch')
        for name,hook,priority in (('output','output',2147483647),('forward','forward',10),('postroute','postrouting',2147483647)):
            need(chains[name]['family']=='inet' and chains[name]['table']=='aegis_device_guard' and chains[name]['hook']==hook and chains[name]['prio']==priority and chains[name]['policy']=='drop', 'Native drop-policy readback mismatch')
        return value
    def dropped(payload):
        total=0
        for item in payload['nftables']:
            r=item.get('rule',{})
            if r.get('chain')!='output' or not any(isinstance(e,dict) and 'drop' in e for e in r.get('expr',[])): continue
            counters=[e['counter'] for e in r['expr'] if isinstance(e,dict) and 'counter' in e]
            need(len(counters)==1 and type(counters[0].get('packets')) is int and counters[0]['packets']>=0,'Native output drop-counter witness absent')
            total+=counters[0]['packets']
        return total
    def probes(phase, allowed):
        for address in (V4,V6):
            for kind in ('dns','data'):
                token = '%s_%s_%s' % (phase, 'v6' if ':' in address else 'v4', kind)
                before = sum(token.encode() in v for v in received)
                peer([tools['python']['path'], '-I', '-c', PROBE, address, kind, token], expected=0 if allowed else 23)
                after = sum(token.encode() in v for v in received)
                need(after-before == (1 if allowed else 0), 'Independent local oracle disagrees')
                results.append({'phase':phase,'family':'ipv6' if ':' in address else 'ipv4','kind':kind,'roundtrip_expected':allowed,'oracle_payload_count':after-before})
        need(not stop.is_set(), 'Oracle worker stopped unexpectedly')
    try:
        child = subprocess.Popen([tools['unshare']['path'], '--net', '--fork', '--kill-child=KILL', tools['python']['path'], '-I', c['driver'], '--park'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=clean_env)
        need(select.select([child.stdout], [], [], 4)[0], 'Peer READY deadline')
        opened = json.loads(child.stdout.readline(4097)); peer_pid, peer_ns = opened['pid'], opened['net']
        need(type(peer_pid) is int and peer_pid > 1 and peer_ns != own['net'] and child.poll() is None, 'Peer READY identity invalid')
        need(os.readlink('/proc/%d/ns/user' % peer_pid) == own['user'] and os.readlink('/proc/%d/ns/pid' % peer_pid) == own['pid'], 'Peer left owned user/PID custody')
        command([ip,'link','set','lo','up']); peer([ip,'link','set','lo','up'])
        command([ip,'link','add','peer0','type','veth','peer','name','eth0'])
        command([ip,'link','set','eth0','netns',str(peer_pid)])
        for address in (V4+'/30', V6+'/64'):
            command([ip,'address','add',address,'dev','peer0','nodad'] if ':' in address else [ip,'address','add',address,'dev','peer0'])
        for address in (P4+'/30', P6+'/64'):
            peer([ip,'address','add',address,'dev','eth0','nodad'] if ':' in address else [ip,'address','add',address,'dev','eth0'])
        command([ip,'link','set','peer0','up']); peer([ip,'link','set','eth0','up'])
        for family,address in ((socket.AF_INET,V4),(socket.AF_INET6,V6)):
            for udp,port in ((True,53),(False,8443)):
                s=socket.socket(family,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
                if family==socket.AF_INET6: s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
                s.bind((address,port))
                if not udp: s.listen(8)
                selector.register(s,selectors.EVENT_READ,udp)
        worker=threading.Thread(target=oracle,daemon=True);worker.start()
        probes('before',True)
        source_path=pathlib.Path(c['helper']);need(sha(source_path)==HELPER_SHA,'Emitted source path drift')
        source=source_path.read_bytes(); need(hashlib.sha256(source).hexdigest()==HELPER_SHA, 'Emitted source drift')
        matches=re.findall(rb'^render\(\) \{\n.*?^\}\n',source,re.M|re.S);need(len(matches)==1,'Unique exact render function required')
        emitted=[]
        execution=pathlib.Path(c['staging_root'])/'execution';execution.mkdir(mode=0o700)
        for role,dhcp in (('block',0),('dhcp',1)):
            prefix=('set -eu\nTABLE=aegis_device_guard\nschema=aegis_device_guard_v1\ncapture_interface=aegis-tun0\ncapture_profile=full-wide-tun\nuplink=eth0\nmanagement_ipv4='+P4+'\nmanagement_ipv6='+P6+'\nmanagement_ports=22,2222\ndhcp4='+str(dhcp)+'\ndhcp6='+str(dhcp)+'\n').encode()
            render=execution/('render-'+role+'.sh');write(render,prefix+matches[0]+b'render\n')
            batch=peer([tools['bash']['path'],str(render)])
            write(out/(role+'.nft'),batch);emitted.append({'role':role,'sha256':hashlib.sha256(batch).hexdigest(),'execution_script_sha256':sha(render)})
        block=(out/'block.nft').read_bytes(); dhcp=(out/'dhcp.nft').read_bytes()
        for phase,batch in (('block',block),('dhcp_blocked',dhcp),('reblock',block)):
            peer([nft,'--check','--file','-'],data=batch);peer([nft,'--file','-'],data=batch)
            before=table();probes(phase,False);after=table()
            need(projection(before)==projection(after),'Probes changed policy structure')
            need(dropped(after)>dropped(before),'Denied probes lack native output drop-counter increase')
        retained=projection(table()); invalid=block+b'add rule inet aegis_device_guard output definitely_invalid_token\n'
        peer([nft,'--check','--file','-'],data=invalid,expected=None)
        need(projection(table())==retained,'Failed check changed armed policy')
        peer([nft,'--file','-'],data=invalid,expected=None)
        need(projection(table())==retained,'Failed atomic apply changed armed policy')
        peer([nft,'delete','table','inet','aegis_device_guard']);probes('after',True)
        child.stdin.write('exit\n');child.stdin.flush();need(child.wait(timeout=4)==0,'Owned peer keeper failed cleanup')
        stop.set();worker.join(timeout=2);need(not worker.is_alive(),'Oracle worker failed cleanup')
        write(out/'inside-receipt-r1.json',{'native_emitted_batch_smoke':True,'namespace_identities':own,'peer_namespace':peer_ns,'peer_pid':peer_pid,'emitted':emitted,'results':results,'commands':sequence,'peer_reaped':True,'oracle_joined':True,'systemd_boot_cgroup_bind_proven':False,'target_network_or_installed_client':False,'row17_closed':False,'beta_exit':False})
    finally:
        stop.set()
        for key in list(selector.get_map().values()): key.fileobj.close()
        selector.close()
        # Failure cleanup is deliberately the independent outer PID-namespace
        # teardown, never host namespace recovery or guessed PID signalling.

def main():
    p=argparse.ArgumentParser();p.add_argument('--inside');p.add_argument('--park',action='store_true')
    p.add_argument('--repo-root');p.add_argument('--output-name');p.add_argument('--reviewed-driver-sha')
    p.add_argument('--root-reviewed-source-and-tools',action='store_true');p.add_argument('--sole-root-lease',action='store_true')
    a=p.parse_args()
    if a.park: park();return
    if a.inside: inside(pathlib.Path(a.inside));return
    need(sys.platform=='linux' and a.root_reviewed_source_and_tools and a.sole_root_lease,'Explicit Linux root review/readiness required; no automatic capability fallback')
    need(a.repo_root and re.fullmatch(r'audit17-native-[A-Za-z0-9_-]{1,50}',a.output_name or '') and re.fullmatch(r'[a-f0-9]{64}',a.reviewed_driver_sha or ''),'Exact root/fresh name/driver pin required')
    need(os.geteuid()==0,'Explicit reviewed root staging required; no privilege fallback')
    root=pathlib.Path(a.repo_root).resolve();script=pathlib.Path(__file__).resolve()
    need(sha(script)==a.reviewed_driver_sha,'Reviewed driver changed')
    helper=root/'scripts/aegis-device-egress-guard.sh';contract=root/'scripts/test-device-egress-guard-contract.sh'
    need(sha(helper)==HELPER_SHA and sha(contract)==CONTRACT_SHA,'Reviewed B-03-FINAL guard source/contract changed; explicit repin required')
    tools={}
    for name in ('unshare','ip','nft','nsenter','bash','timeout'):
        target=shutil.which(name);need(target,'Required native tool unavailable')
        path=pathlib.Path(target).resolve();tools[name]={'path':str(path),'sha256':sha(path)}
    python=pathlib.Path(sys.executable).resolve();tools['python']={'path':str(python),'sha256':sha(python)}
    out=root/'ci-output/device-guard'/a.output_name
    need(out.parent.is_dir() and not out.exists() and not out.is_symlink(),'Fresh existing artifact parent required')
    need(all(parent.is_dir() and not parent.is_symlink() for parent in out.parents),'Artifact parent alias/special object refused')
    out.mkdir(mode=0o700)
    host=identities();routes={name:hashlib.sha256(pathlib.Path('/proc/net/'+name).read_bytes()).hexdigest() for name in ('route','ipv6_route')}
    staging_source=root/'scripts/deviceguard-native-private-stage.py'
    need(sha(staging_source)==STAGE_SHA,'Reviewed private staging source changed')
    staging_bytes=staging_source.read_bytes();need(hashlib.sha256(staging_bytes).hexdigest()==STAGE_SHA,'Private staging bytes changed before compilation')
    staging=types.ModuleType('deviceguard_private_stage')
    exec(compile(staging_bytes,'<reviewed-private-stage>','exec'),staging.__dict__)
    for tool in tools.values():
        need(not pathlib.Path(tool['path']).is_relative_to(root),'Original workspace tool path refused')
        staging.namespace_accessible(pathlib.Path(tool['path']))
    stage=staging.prepare('/tmp',a.output_name,{script.name:(script,a.reviewed_driver_sha),helper.name:(helper,HELPER_SHA),contract.name:(contract,CONTRACT_SHA)})
    evidence=pathlib.Path(stage['evidence'])
    staged_driver=pathlib.Path(stage['root'])/'scripts'/script.name
    staged_helper=pathlib.Path(stage['root'])/'scripts'/helper.name
    config={'host_namespaces':host,'helper':str(staged_helper),'driver':str(staged_driver),'tools':tools,'staging_root':stage['root'],'staging_output_name':a.output_name}
    write(evidence/'input-r1.json',config)
    argv=[tools['timeout']['path'],'--kill-after=5s','120s',tools['unshare']['path'],'--user','--map-root-user','--net','--mount','--pid','--fork','--mount-proc','--kill-child=KILL',tools['python']['path'],'-I',str(staged_driver),'--inside',str(evidence/'input-r1.json')]
    child=None;record={'argv':argv,'host_namespaces':host,'host_route_projection_before':routes,'command_bound_seconds':120,'independent_parent_bound_seconds':135,'cleanup_seconds':5,'success':False,'row17_closed':False,'beta_exit':False}
    log_fd=os.open(evidence/'outer.log',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(log_fd,'wb') as log:
        try:
            child=subprocess.Popen(argv,cwd=stage['root'],stdout=log,stderr=subprocess.STDOUT,start_new_session=True,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'})
            record.update(pid=child.pid,owned_process_group=child.pid);write(evidence/'started-r1.json',record)
            cutoff=time.monotonic()+135;terminal=None
            while time.monotonic()<cutoff:
                terminal=os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
                if terminal: break
                time.sleep(.02)
            need(os.getpgid(child.pid)==child.pid,'Owned unreaped leader group changed')
            os.killpg(child.pid,signal.SIGKILL);record['owned_group_signalled']=True;code=child.wait(timeout=5)
            record.update(exit_code=code,terminal=None if terminal is None else {'pid':terminal.si_pid,'code':terminal.si_code,'status':terminal.si_status},parent_reaped=True)
            need(terminal is not None and terminal.si_pid==child.pid and terminal.si_code==os.CLD_EXITED and terminal.si_status==code==0,'Native timeout/failure is retained, never PASS')
            need(identities()==host,'Host namespace identity changed')
            need(routes=={name:hashlib.sha256(pathlib.Path('/proc/net/'+name).read_bytes()).hexdigest() for name in routes},'Host route projection changed; no restoration authorized')
            need(sha(helper)==HELPER_SHA and sha(contract)==CONTRACT_SHA and sha(script)==a.reviewed_driver_sha,'Source identity drift')
            for tool in tools.values(): need(sha(pathlib.Path(tool['path']))==tool['sha256'],'Native tool bytes changed')
            sha(evidence/'inside-receipt-r1.json')  # Admit regular type/parents/excluded scope before the first content read.
            inner=json.loads((evidence/'inside-receipt-r1.json').read_bytes())
            need(inner['native_emitted_batch_smoke'] is True and inner['peer_reaped'] is True and inner['oracle_joined'] is True,'Native inner closure absent')
            record['success']=True;record['inside_receipt_sha256']=sha(evidence/'inside-receipt-r1.json')
        except BaseException as error:
            record['failure_type']=type(error).__name__
            if child is not None and 'parent_reaped' not in record:
                try:
                    need(os.getpgid(child.pid)==child.pid,'Unknown leader/group retained')
                    os.killpg(child.pid,signal.SIGKILL);record['owned_group_signalled']=True;record['exit_code']=child.wait(timeout=5);record['parent_reaped']=True
                except BaseException as cleanup: record['cleanup_error_type']=type(cleanup).__name__
        finally: write(evidence/'receipt-r1.json',record)
    try:
        need(child is None or (record.get('parent_reaped') is True and record.get('owned_group_signalled') is True and 'cleanup_error_type' not in record),'Unclosed owned child prevents evidence export')
        copied=staging.export(stage,out)
        write(out/'export-complete-r1.json',{'evidence_export_complete':True,'native_success':record['success'],'copied_sha256':copied,'private_stage_retained':True,'row17_closed':False,'beta_exit':False})
    except BaseException as error:
        record.update(success=False,evidence_export_complete=False,export_failure_type=type(error).__name__,private_stage_retained=True)
        write(out/'export-failure-r1.json',record)
        print('Private stage export refused; failed evidence retained',file=sys.stderr)
    raise SystemExit(0 if record['success'] else 1)

if __name__=='__main__': main()
