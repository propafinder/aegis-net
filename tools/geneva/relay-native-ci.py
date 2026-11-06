#!/usr/bin/env python3
"""Controlled relay-only native CI. Never touches production or host network rules.

Fresh unnamed net/mount namespaces; independent host guard ready before links,
root-owned /run tmpfs; only bounded metadata exported (no PKI, frames or source).
"""
import ctypes
import functools
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time

SELF=Path(__file__).resolve()
COMMON=SELF.parents[2]/'scripts/test-geneva-live-netns.py'
OBSERVER=SELF.parent/'relay_capture_observer.py'
DIAGNOSTICS=SELF.parent/'relay_native_diagnostics.py'
diagnostic_spec=importlib.util.spec_from_file_location('geneva_native_diagnostics',DIAGNOSTICS)
d=importlib.util.module_from_spec(diagnostic_spec);diagnostic_spec.loader.exec_module(d)
observer_spec=importlib.util.spec_from_file_location('geneva_native_capture_observer',OBSERVER)
observer_module=importlib.util.module_from_spec(observer_spec);observer_spec.loader.exec_module(observer_module)
CaptureObserver=observer_module.CaptureObserver
spec=importlib.util.spec_from_file_location('geneva_native_common',COMMON)
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
c.SELF=SELF
MARKER=b'AEGIS_ENCRYPTED_TARGET_ONLY_TEST_8d38'
require=c.require

def link_snapshot():
    # Read only this process's fresh, unnamed network namespace.
    value=d.parse(c.command(['ip','-j','-d','link','show']))
    require(type(value) is list and len(value)<=3,'owned namespace link inventory bound')
    return value

def link_identity(row):
    require(type(row) is dict and type(row.get('ifindex')) is int and row['ifindex']>0
            and type(row.get('ifname')) is str and type(row.get('address')) is str,
            'owned link identity types')
    kind=row.get('linkinfo',{}).get('info_kind')
    if row['ifname']=='lo':
        require(row.get('link_type')=='loopback' and row['address']=='00:00:00:00:00:00'
                and kind is None,'fresh loopback identity')
        return {'ifindex':row['ifindex'],'ifname':'lo','address':row['address'],'link_type':'loopback'}
    require(row['ifname'] in ('client0','relay0') and row.get('link_type')=='ether'
            and kind=='veth' and type(row.get('link_index')) is int and row['link_index']>0,
            'exact owned veth identity required')
    return {'ifindex':row['ifindex'],'ifname':row['ifname'],'address':row['address'],
            'link_type':'ether','kind':'veth','link_index':row['link_index']}

def topology_identity(links, names):
    require(type(links) is list and len(links)==len(names),'unexpected owned namespace topology')
    identities=[link_identity(row) for row in links]
    require({row['ifname'] for row in identities}==set(names)
            and len({row['ifindex'] for row in identities})==len(identities),
            'renamed, duplicate or foreign owned namespace link')
    return {row['ifname']:row for row in identities}

def owned_pair_identity(local, peer, local_lo, peer_lo):
    left=topology_identity(local,('lo','client0'));right=topology_identity(peer,('lo','relay0'))
    require(left['lo']==local_lo and right['lo']==peer_lo,'original fresh loopback replaced')
    client=left['client0'];relay=right['relay0']
    require(client['address']=='02:00:00:00:00:02' and relay['address']=='02:00:00:00:00:03'
            and client['link_index']==relay['ifindex'] and relay['link_index']==client['ifindex'],
            'original controlled veth pair differs')
    return left,right

def cleanup_peer_topology(namespace, local, peer, birth, peer_namespace, terminal,
                          endpoint, stdout, stderr):
    # Missing client0 is expected only after the exact child has acknowledged
    # its clean terminal state AND communicate() has waited/reaped that child.
    require(os.readlink('/proc/self/ns/net')==namespace and namespace!=peer_namespace
            and re.fullmatch(r'net:\[[0-9]+\]',namespace)
            and re.fullmatch(r'net:\[[0-9]+\]',peer_namespace),'owned namespace cleanup binding')
    require(type(birth.get('pid')) is int and birth['pid']==endpoint.pid
            and type(endpoint.returncode) is int and endpoint.returncode==0
            and endpoint.poll()==0 and stdout==b'' and stderr==b'',
            'exact peer successful exit and reap required')
    require(terminal.get('ok') is True and type(terminal.get('pid')) is int
            and terminal['pid']==birth['pid'] and terminal.get('namespace')==peer_namespace
            and terminal.get('errors')==[] and terminal.get('tls_worker_joined') is True
            and terminal.get('physical_capture_closed') is True
            and topology_identity(terminal.get('links'),('lo','relay0'))==peer,
            'exact peer clean terminal topology required')
    links=link_snapshot()
    if len(links)==1:
        require(topology_identity(links,('lo',))=={'lo':local['lo']},
                'missing peer link without original fresh topology')
    else:
        require(topology_identity(links,('lo','client0'))==local,
                'remaining client link no longer exact owned veth')
        # Never swallow a delete failure, including a raced ENODEV.
        c.command(['ip','link','delete','client0'])
    require(topology_identity(link_snapshot(),('lo',))=={'lo':local['lo']},
            'owned namespace topology removal readback')

def completed_scenario_diagnostics(rows):
    require(type(rows) is list and len(rows)<=3,'completed scenario diagnostic bound')
    completed=[]
    for index,row in enumerate(rows):
        require(row['mode']==('tls','tls-transfer','drop')[index]
                and type(row['terminal']) is dict
                and type(row['physical_packets']) is int and row['physical_packets']>=0
                and type(row['tun_packets']) is int and row['tun_packets']>=0,
                'actual completed scenario diagnostic shape')
        completed.append({key:row[key] for key in ('mode','terminal','physical_packets','tun_packets')})
    return {'completed_scenarios':completed,'runtime_acceptance':False,
            'scope':'actual completed loop rows retained after failure; captures and overall cleanup not accepted'}

def packet_metadata(frame, ethernet=True):
    packet=frame[14:] if ethernet else frame
    if len(packet)<40 or packet[0]>>4!=4 or packet[9]!=6:return None
    ihl=(packet[0]&15)*4
    require(20<=ihl<=60 and len(packet)>=ihl+20,'observed IPv4/TCP bounds')
    return {'src':socket.inet_ntoa(packet[12:16]),'dst':socket.inet_ntoa(packet[16:20]),
            'sport':int.from_bytes(packet[ihl:ihl+2],'big'),'dport':int.from_bytes(packet[ihl+2:ihl+4],'big'),
            'seq':int.from_bytes(packet[ihl+4:ihl+8],'big'),'flags':packet[ihl+13],
            'ttl':packet[8],'sha256':hashlib.sha256(frame).hexdigest(),
            'clear_marker_present':MARKER in frame}

def drain(sock,ethernet=True):
    rows=[]
    while select.select([sock],[],[],0)[0]:
        frame=sock.recv(65550);row=packet_metadata(frame,ethernet)
        if row is not None:rows.append(row)
        require(len(rows)<=512,'native observation packet bound')
    return rows

def start_capture(interface,ethernet=True,incoming_only=False):
    sock=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800))
    try:
        if incoming_only:sock.setsockopt(263,23,1)
        sock.bind((interface,0))
        observer=CaptureObserver(sock,lambda frame:packet_metadata(frame,ethernet)).start()
        require(observer.failure is None,'bounded capture readiness failed')
        return observer
    except BaseException:
        sock.close()
        raise

def stop_capture(observer,label):
    result=observer.stop()
    require(result['clean'] and result['kernel_counter_matches_received'] and
            result['thread_terminal_confirmed'] and result['owned_fd_closed'],label+' capture did not close cleanly')
    return result

def encrypted_payload(size):
    require(type(size) is int and size in (len(MARKER),65536),'bounded encrypted transfer size')
    return (MARKER*((size+len(MARKER)-1)//len(MARKER)))[:size]

def peer():
    require(len(sys.argv)==3 and c.digest(OBSERVER)==sys.argv[2],'peer capture source pin drift')
    require(ctypes.CDLL(None,use_errno=True).unshare(c.CLONE_NEWNET)==0,'peer netns unshare')
    c.command(['sysctl','-qw','net.ipv6.conf.all.disable_ipv6=1','net.ipv6.conf.default.disable_ipv6=1'])
    print(json.dumps({'ok':True,'pid':os.getpid(),'namespace':os.readlink('/proc/self/ns/net'),'links':link_snapshot()}),flush=True)
    listener=None;capture=None;worker=None;stop=threading.Event();answers=[];errors=[]
    for line in sys.stdin:
        request=json.loads(line);op=request['op']
        if op=='open':
            c.command(['ip','addr','add','192.0.2.3/24','dev','relay0']);c.command(['ip','link','set','relay0','up'])
            c.command(['ip','neigh','replace','192.0.2.2','lladdr','02:00:00:00:00:02','nud','permanent','dev','relay0'])
            c.command(['ethtool','-K','relay0','tx','off','rx','off','tso','off','gso','off','gro','off'])
            capture=start_capture('relay0',incoming_only=True)
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_3
            context.load_cert_chain(request['certificate'],request['key'])
            listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind(('192.0.2.3',24443));listener.listen(2);listener.settimeout(0.2)
            def serve():
                while not stop.is_set():
                    try:stream,_=listener.accept()
                    except socket.timeout:continue
                    except OSError:
                        if not stop.is_set():errors.append('listener_error')
                        return
                    try:
                        stream.settimeout(8)
                        with context.wrap_socket(stream,server_side=True) as tls:
                            until=time.monotonic()+8
                            def exact(count):
                                data=b''
                                while len(data)<count:
                                    remaining=until-time.monotonic()
                                    require(remaining>0,'encrypted application transfer deadline')
                                    tls.settimeout(remaining)
                                    part=tls.recv(count-len(data));require(part,'TLS client closed early');data+=part
                                return data
                            size=int.from_bytes(exact(4),'big');expected=encrypted_payload(size)
                            started=time.monotonic_ns();data=exact(size)
                            require(data==expected,'controlled encrypted application bytes differ');tls.sendall(data)
                            answers.append({'actual_TLS13_application_echo':True,'bytes':len(data),
                                            'server_elapsed_microseconds':(time.monotonic_ns()-started)//1000})
                    except Exception as error:errors.append(type(error).__name__)
            worker=threading.Thread(target=serve,daemon=True);worker.start();reply={'ok':True,'links':link_snapshot()}
        elif op=='observe':
            observed=stop_capture(capture,'physical');capture=None
            capture=start_capture('relay0',incoming_only=True)
            reply={'ok':True,'packets':observed['records'],'capture':observed,'TLS_echoes':list(answers),'errors':list(errors)}
        elif op=='exit':
            stop.set()
            if listener is not None:listener.close()
            if worker is not None:worker.join(timeout=2);require(not worker.is_alive(),'peer TLS worker remains')
            final_capture=stop_capture(capture,'final physical') if capture is not None else None;capture=None
            print(json.dumps({'ok':True,'pid':os.getpid(),'namespace':os.readlink('/proc/self/ns/net'),
                              'links':link_snapshot(),'tls_worker_joined':worker is None or not worker.is_alive(),
                              'physical_capture_closed':True,'TLS_echoes':answers,'errors':errors,'final_capture':final_capture}),flush=True);break
        else:raise RuntimeError('unsupported peer operation')
        print(json.dumps(reply),flush=True)

def pki(root):
    folder=root/'private-test-pki';folder.mkdir(mode=0o700)
    c.command(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(folder/'ca.key'),'-out',str(folder/'ca.pem'),'-days','1','-subj','/CN=Aegis isolated native CI CA','-addext','basicConstraints=critical,CA:TRUE'],timeout=10)
    c.command(['openssl','req','-newkey','rsa:2048','-nodes','-keyout',str(folder/'leaf.key'),'-out',str(folder/'leaf.csr'),'-subj','/CN=relay-geneva.test'],timeout=10)
    (folder/'extensions').write_text('subjectAltName=DNS:relay-geneva.test\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
    c.command(['openssl','x509','-req','-in',str(folder/'leaf.csr'),'-CA',str(folder/'ca.pem'),'-CAkey',str(folder/'ca.key'),'-set_serial','7','-out',str(folder/'leaf.pem'),'-days','1','-extfile',str(folder/'extensions')],timeout=10)
    c.command(['openssl','x509','-in',str(folder/'ca.pem'),'-outform','DER','-out',str(folder/'ca.der')])
    for path in folder.iterdir():path.chmod(0o600)
    return folder

def remove_test_pki(folder):
    if not folder.exists():return
    require(folder.is_dir() and not folder.is_symlink() and folder.stat().st_uid==os.geteuid() and folder.stat().st_mode&0o777==0o700,'test PKI directory ownership')
    names={'ca.key','ca.pem','leaf.key','leaf.csr','extensions','leaf.pem','ca.der'}
    require(all(path.name in names and path.is_file() and not path.is_symlink() and path.stat().st_uid==os.geteuid() for path in folder.iterdir()),'unexpected/unowned PKI member')
    for path in folder.iterdir():path.unlink()
    folder.rmdir()

def inner(stage):
    root=Path(stage)
    try:return inner_body(stage)
    except BaseException as error:
        if not(root/'inner-failure.json').exists():
            c.exclusive(root/'inner-failure.json',{'status':'FAIL_NATIVE_RELAY_EARLY_OR_BODY_ATTEMPT_RETAINED','error_type':type(error).__name__,'scope':'fresh owned namespaces only; independent host guard remains responsible for session cleanup'})
        raise

def inner_body(stage):
    root=Path(stage);cfg=json.loads((root/'input.json').read_text());c.FAILURE_ROOT=root
    require(c.digest(SELF)==cfg['tool_sha256'] and c.digest(COMMON)==cfg['common_sha256'] and c.digest(OBSERVER)==cfg['observer_sha256'] and c.digest(DIAGNOSTICS)==cfg['diagnostics_sha256'],'controller source pin drift')
    inner_netns=os.readlink('/proc/self/ns/net');inner_mntns=os.readlink('/proc/self/ns/mnt')
    require(inner_netns!=cfg['host_netns'] and inner_mntns!=cfg['host_mntns'],'fresh isolated namespaces required')
    c.exclusive(root/'inner-start.json',{'child':c.identity(os.getpid()),'tool_sha256':c.digest(SELF)})
    until=time.monotonic()+8
    while not(root/'watchdog-ready.json').exists():require(time.monotonic()<until,'guard readiness deadline');time.sleep(0.02)
    ready=json.loads((root/'watchdog-ready.json').read_text());require(ready['child']==c.identity(os.getpid()) and ready['tool_sha256']==c.digest(SELF) and c.same_process(ready['watchdog']) and ready['deadline']-time.monotonic()>100,'independent live guard binding')
    c.command(['mount','--make-rprivate','/']);c.command(['mount','-t','tmpfs','-o','nosuid,nodev,noexec','tmpfs','/run'])
    c.command(['sysctl','-qw','net.ipv6.conf.all.disable_ipv6=1','net.ipv6.conf.default.disable_ipv6=1','net.ipv4.ip_forward=0','net.ipv4.conf.all.rp_filter=1','net.ipv4.conf.default.rp_filter=1','net.ipv4.ip_default_ttl=64'])
    endpoint=None;probe=None;probe_index=None;probe_diagnostic_saved=False;peer_diagnostic_saved=False;observation=None;rows=[];clean=False
    try:
        local_lo=topology_identity(link_snapshot(),('lo',))['lo']
        endpoint=subprocess.Popen([sys.executable,str(SELF),'peer',cfg['observer_sha256']],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,preexec_fn=functools.partial(c.die_with_parent,os.getpid()))
        peer_info=json.loads(c.read_line(endpoint,time.monotonic()+5));require(peer_info.get('ok') is True and type(peer_info['pid']) is int and peer_info['pid']==endpoint.pid and peer_info['namespace']!=inner_netns,'actual peer namespace binding')
        peer_birth=c.identity(endpoint.pid);require(c.same_process(peer_birth) and os.readlink(f'/proc/{endpoint.pid}/ns/net')==peer_info['namespace'],'actual peer process birth and namespace binding')
        peer_lo=topology_identity(peer_info['links'],('lo',))['lo']
        c.command(['ip','link','add','client0','address','02:00:00:00:00:02','type','veth','peer','name','relay0','address','02:00:00:00:00:03'])
        c.command(['ip','link','set','relay0','netns',str(endpoint.pid)]);c.command(['ip','addr','add','192.0.2.2/24','dev','client0']);c.command(['ip','link','set','client0','up'])
        c.command(['ip','neigh','replace','192.0.2.3','lladdr','02:00:00:00:00:03','nud','permanent','dev','client0']);c.command(['ethtool','-K','client0','tx','off','rx','off','tso','off','gso','off','gro','off'])
        folder=Path(cfg['pki']);opened=c.rpc(endpoint,{'op':'open','certificate':str(folder/'leaf.pem'),'key':str(folder/'leaf.key')})
        local_topology,peer_topology=owned_pair_identity(link_snapshot(),opened['links'],local_lo,peer_lo)
        # The peer has finished its own isolated sysctl setup. Only this private
        # mount namespace now makes /proc/sys read-only, as the installed service
        # requires. Strict global RPF remains 1; the driver must configure its
        # exact new TUN through rtnetlink, with checked loose-mode readback.
        rpf_paths=[Path('/proc/sys/net/ipv4/conf')/name/'rp_filter' for name in ('all','default')]
        rpf_before=[path.read_bytes() for path in rpf_paths]
        require(rpf_before==[b'1\n',b'1\n'],'controlled strict global RPF baseline absent')
        c.command(['mount','--bind','/proc/sys','/proc/sys'])
        c.command(['mount','-o','remount,bind,ro','/proc/sys'])
        require(os.statvfs('/proc/sys').f_flag & os.ST_RDONLY,'owned /proc/sys read-only mount absent')
        for index,(mode,strategy) in enumerate([('tls','[TCP:flags:S]-duplicate(,tamper{IP:ttl:replace:63}())-| \\/ [TCP:flags:SA]-duplicate(tamper{IP:ttl:replace:63}(),)-|'),('tls-transfer','[TCP:flags:S]-duplicate(,tamper{IP:ttl:replace:63}())-| \\/ [TCP:flags:SA]-duplicate(tamper{IP:ttl:replace:63}(),)-|'),('drop','[IP:ttl:64]-drop-|')]):
            probe_index=index
            probe_diagnostic_saved=False
            request={'strategy':strategy,'interface':'client0','local_address':'192.0.2.2','local_mac':[2,0,0,0,0,2],'next_hop_mac':[2,0,0,0,0,3],'outbound_queue':431,'inbound_queue':432,'socket_mark':0x5a71,'max_duration_secs':24}
            path=root/f'request-{index}.json';c.exclusive(path,request);require(c.digest(cfg['binary'])==cfg['binary_sha256'],'probe binary changed')
            probe=subprocess.Popen([cfg['binary'],str(path),'192.0.2.3:24443',str(folder/'ca.der'),mode],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,preexec_fn=functools.partial(c.die_with_parent,os.getpid()))
            started=json.loads(c.read_line(probe,time.monotonic()+8));require(started['phase']=='ready' and started['source']==cfg['source'] and started['fallback_dials']==0,'native runtime readiness/source differs')
            links=json.loads(c.command(['ip','-j','link','show']));tuns=[x['ifname'] for x in links if x['ifname'].startswith('agv')];require(len(tuns)==1,'exact single owned TUN missing')
            observation=start_capture(tuns[0],False)
            probe.stdin.write(b'continue\n');probe.stdin.flush()
            transfer_complete=json.loads(c.read_line(probe,time.monotonic()+12))
            require(transfer_complete=={'phase':'transfer_complete','tun_still_owned':True},'native pre-quiesce capture barrier absent')
            tun_capture=stop_capture(observation,'live TUN');observation=None
            received=c.rpc(endpoint,{'op':'observe'});packets=received['packets']
            require(not received['errors'],'peer TLS error')
            probe.stdin.write(b'capture_closed\n');probe.stdin.flush()
            terminal=json.loads(c.read_line(probe,time.monotonic()+12))
            stdout,stderr=probe.communicate(timeout=3)
            if probe.returncode!=0 or stdout or stderr:
                d.retain_completed_stderr(root,f'probe-{probe_index}',stderr,probe.returncode);probe_diagnostic_saved=True
            require(probe.returncode==0 and not stdout and not stderr,'controlled native probe failed');probe=None
            require(terminal['phase']=='terminal' and terminal['owned_runtime_quiesced'] is True and terminal['operation']['fallback_dials']==0 and terminal['operation']['worker_healthy_before_quiesce'] is True,'probe terminal acceptance absent')
            inbound=tun_capture['records']
            if mode in ('tls','tls-transfer'):
                size=len(MARKER) if mode=='tls' else 65536
                require(terminal['operation']['strict_local_CA_name_TLS13_echo'] is True and terminal['operation']['encrypted_echo_bytes']==size and len(received['TLS_echoes'])==index+1 and received['TLS_echoes'][-1]['bytes']==size,'actual strict TLS echo missing')
                outgoing=[p for p in packets if p['src']=='192.0.2.2' and p['dst']=='192.0.2.3' and p['dport']==24443 and p['flags']&0x12==2]
                returning=[p for p in inbound if p['src']=='192.0.2.3' and p['dst']=='192.0.2.2' and p['sport']==24443 and p['flags']&0x12==0x12]
                require(len(outgoing)>=2 and [p['ttl'] for p in outgoing[:2]]==[64,63] and outgoing[0]['seq']==outgoing[1]['seq'],'physical outbound duplicate/tamper not observed')
                require(len(returning)>=2 and [p['ttl'] for p in returning[:2]]==[63,64] and returning[0]['seq']==returning[1]['seq'],'actual TUN inbound duplicate/tamper not observed')
                require(packets and all(not p['clear_marker_present'] for p in packets+inbound),'application marker leaked in physical packet capture')
            else:
                counters=terminal['operation']['native_packet_counters']
                require(terminal['operation']['selected_connection_refused'] is True and terminal['operation']['actual_program_drop_acknowledged'] is True and counters['outbound_empty_batches']>0 and counters['outbound_batches']==counters['outbound_empty_batches'] and counters['outbound_emitted_frames']==0 and counters['inbound_emitted_frames']==0 and not any(p['src']=='192.0.2.2' and p['dport']==24443 and p['flags']&0x12==2 for p in packets),'drop was not an actual acknowledged empty output or reached peer/fallback')
            require(not any(x['ifname'].startswith('agv') for x in json.loads(c.command(['ip','-j','link','show']))),'owned TUN remains')
            tables=json.loads(c.command(['nft','-j','list','ruleset']));require(not any(row.get('table',{}).get('name','').startswith('aegis_rg_') for row in tables['nftables']),'owned relay table remains')
            require([path.read_bytes() for path in rpf_paths]==rpf_before and os.statvfs('/proc/sys').f_flag & os.ST_RDONLY,'global RPF/read-only sysctl policy drift')
            rows.append({'mode':mode,'terminal':terminal,'physical_packets':len(packets),'tun_packets':len(inbound),'TUN_capture':tun_capture,'physical_capture':received['capture'],'capture_closed_before_TUN_teardown':True,'capture_does_not_cover_runtime_teardown':True,'controlled_packet_observation_not_independent_capture':True})
        require(c.same_process(peer_birth) and os.readlink(f'/proc/{endpoint.pid}/ns/net')==peer_info['namespace'],'original peer remains before terminal request')
        peer_terminal=c.rpc(endpoint,{'op':'exit'});peer_stdout,errors=endpoint.communicate(timeout=3)
        if endpoint.returncode!=0 or errors:
            d.retain_completed_stderr(root,'peer',errors,endpoint.returncode);peer_diagnostic_saved=True
        require(endpoint.returncode==0 and not peer_stdout and not errors,'peer terminal failed')
        journal=Path('/run/aegis-relay-geneva');entries=[]
        for folder in sorted(journal.iterdir()):
            for path in sorted(folder.iterdir()):
                require(path.is_file() and not path.is_symlink() and path.stat().st_size<=65536,'native journal frame bound')
                entries.append({'instance':folder.name,'name':path.name,'value':json.loads(path.read_bytes()),'sha256':c.digest(path)})
        require(not any(row['name'].endswith(('_runtime_fault.json','_worker_failed.json')) or row['value'].get('runtime_fault') is True for row in entries),'native journal contains a real worker fault')
        require(len(entries)<=2048,'native journal export bound');c.exclusive(root/'native-journals.json',{'entries':entries})
        cleanup_peer_topology(inner_netns,local_topology,peer_topology,peer_birth,peer_info['namespace'],peer_terminal,endpoint,peer_stdout,errors);endpoint=None;clean=True
        c.exclusive(root/'inner-result.json',{'status':'PASS_CONTROLLED_RELAY_GENEVA_TLS_DUPLICATION_DROP_AND_CLEANUP','rows':rows,'peer_terminal':peer_terminal,'owned_namespace_topology_removed':True,'strict_global_rpf_unchanged':True,'proc_sys_read_only':True,'target_network':False,'independent_capture':False,'final_signed_client':False})
    finally:
        diagnostic_errors=[]
        if not clean:
            # The attempt is already failed; retain actual owned-inner NFT JSON
            # before stopping consumers or destroying the private namespace.
            # This observation is diagnostic only and never changes acceptance.
            try:d.retain_failed_inner_ruleset(root,cfg['host_netns'],cfg['host_mntns'],inner_netns,inner_mntns)
            except BaseException as error:diagnostic_errors.append({'phase':'inner_nft_failure_retention','type':type(error).__name__})
        if observation is not None:
            try:
                failed_capture=observation.stop()
                c.exclusive(root/'capture-failure.json',{'scope':'attempt failed; no clean capture acceptance','capture':failed_capture})
            except BaseException as error:diagnostic_errors.append({'phase':'capture_cleanup_or_diagnostic','type':type(error).__name__})
        for process in (probe,endpoint):
            if process is not None:
                try:
                    if process.poll() is None:process.kill()
                    process.wait(timeout=3)
                    saved=probe_diagnostic_saved if process is probe else peer_diagnostic_saved
                    if not clean and not saved:d.retain_process_stderr(root,process,f'probe-{probe_index}' if process is probe else 'peer')
                except BaseException as error:diagnostic_errors.append({'phase':'consumer_cleanup_or_diagnostic','type':type(error).__name__})
        if not clean:
            try:d.write_json(root,'native-journals-failure.json',d.journal_snapshot('/run/aegis-relay-geneva'))
            except BaseException as error:diagnostic_errors.append({'phase':'native_journal_retention','type':type(error).__name__})
            d.write_json(root,'inner-failure.json',{'status':'FAIL_NATIVE_RELAY_ATTEMPT_RETAINED','error_type':None if sys.exc_info()[0] is None else sys.exc_info()[0].__name__,'remaining_rules_live_only_in_owned_namespace':True,'diagnostic_errors':diagnostic_errors,'completed_loop_diagnostics':completed_scenario_diagnostics(rows)})

def outer(binary,stage):
    require(sys.platform=='linux' and os.geteuid()==0,'Linux root required')
    root=Path(stage);require(root.is_absolute() and not root.exists(),'new absolute stage required');root.mkdir(mode=0o700);c.FAILURE_ROOT=root
    binary=Path(binary)
    child=None;guard=None;birth=None;row=None;folder=None;errors=[];status='FAIL_CONTROLLED_RELAY_PREPARATION'
    hostns=None;hostmnt=None;baseline=None;hostrules=None;binary_pin=None;host_configuration=None;host_configuration_pin=None;host_namespace_observations={'before':None,'after':None}
    try:
        require(binary.is_absolute() and binary.is_file() and not binary.is_symlink(),'regular absolute probe required')
        hostns=os.readlink('/proc/self/ns/net');hostmnt=os.readlink('/proc/self/ns/mnt')
        host_namespace_observations['before']={'net':hostns,'mount':hostmnt}
        baseline=c.command(['ip','-j','link','show']);hostrules=c.command(['nft','-j','list','ruleset']);binary_pin=c.digest(binary)
        d.public_host_snapshot(root,'before',baseline,hostrules)
        d.host_configuration_comparison(baseline,hostrules,baseline,hostrules,{'before':{'net':hostns,'mount':hostmnt},'after':{'net':hostns,'mount':hostmnt}})
        folder=root/'private-test-pki';pki(root);source=c.command(['git','-C',str(SELF.parents[2]),'rev-parse','HEAD']).decode().strip()
        c.exclusive(root/'input.json',{'tool_sha256':c.digest(SELF),'common_sha256':c.digest(COMMON),'observer_sha256':c.digest(OBSERVER),'diagnostics_sha256':c.digest(DIAGNOSTICS),'binary':str(binary),'binary_sha256':binary_pin,'source':source,'pki':str(folder),'host_netns':hostns,'host_mntns':hostmnt})
        with (root/'inner.stdout').open('xb') as stdout,(root/'inner.stderr').open('xb') as stderr:
            child=subprocess.Popen(['unshare','--net','--mount',sys.executable,str(SELF),'inner',str(root)],stdout=stdout,stderr=stderr,start_new_session=True);birth=c.identity(child.pid)
            until=time.monotonic()+6
            while not(root/'inner-start.json').exists():require(child.poll() is None and time.monotonic()<until,'inner startup');time.sleep(0.02)
            row=c.identity(child.pid);started=json.loads((root/'inner-start.json').read_text());require(row==started['child'] and row['start']==birth['start'] and row['group']==child.pid,'exact isolated session binding')
            c.exclusive(root/'watchdog-input.json',{'tool_sha256':c.digest(SELF),'child':row,'deadline':time.monotonic()+120})
            guard=subprocess.Popen([sys.executable,str(SELF),'watchdog',str(root)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,start_new_session=True)
            status='FAIL_CONTROLLED_RELAY_RUNTIME';require(child.wait(timeout=110)==0,'native relay operation failed');require((root/'inner-result.json').is_file(),'native relay result absent');status='PASS_CONTROLLED_RELAY_NATIVE_ONLY'
    except BaseException as error:errors.append({'phase':'body','type':type(error).__name__})
    finally:
        cleanup={'owned_session_absent':False,'watchdog_terminal':False,'host_network_rules_unchanged':False,'test_PKI_removed':False}
        try:
            if child is not None and child.poll() is None:
                now=c.identity(child.pid);require(birth and now['start']==birth['start'] and now['group']==child.pid and (row is None or now==row),'cleanup exact session ownership');os.killpg(child.pid,signal.SIGKILL)
            if child is not None:child.wait(timeout=5)
            until=time.monotonic()+3
            while child is not None and not c.session_absent(child.pid) and time.monotonic()<until:time.sleep(0.02)
            cleanup['owned_session_absent']=child is None or c.session_absent(child.pid);require(cleanup['owned_session_absent'],'owned descendants remain')
            if guard is not None:
                c.exclusive(root/'disarm.json',{'owned_session_absent':True});_,stderr=guard.communicate(timeout=8);require(guard.returncode==0 and not stderr,'independent guard terminal refused')
            cleanup['watchdog_terminal']=True
        except BaseException as error:errors.append({'phase':'session_cleanup','type':type(error).__name__})
        try:
            require(baseline is not None and hostrules is not None,'host baseline not observed; do not invent unchanged-network proof')
            after_ip=c.command(['ip','-j','link','show']);after_nft=c.command(['nft','-j','list','ruleset'])
            d.public_host_snapshot(root,'after',after_ip,after_nft)
            d.write_json(root,'host-difference.json',d.host_difference(baseline,hostrules,after_ip,after_nft))
            host_namespace_observations['after']={'net':os.readlink('/proc/self/ns/net'),'mount':os.readlink('/proc/self/ns/mnt')}
            namespaces=host_namespace_observations
            host_configuration=d.host_configuration_comparison(baseline,hostrules,after_ip,after_nft,namespaces)
            host_configuration_pin=d.write_json(root,'host-config-comparison.json',host_configuration)
            d.verify_host_configuration_record(host_configuration,baseline,hostrules,after_ip,after_nft,namespaces)
            cleanup['host_network_rules_unchanged']=host_configuration['configuration_unchanged']
            require(cleanup['host_network_rules_unchanged'],'host network/rules configuration drift')
        except BaseException as error:errors.append({'phase':'host_readback','type':type(error).__name__})
        try:
            require(cleanup['owned_session_absent'],'PKI cleanup requires all owned consumers absent')
            if folder is not None:remove_test_pki(folder)
            cleanup['test_PKI_removed']=True
        except BaseException as error:errors.append({'phase':'test_pki_cleanup','type':type(error).__name__})
        if errors or not all(cleanup.values()):status='FAIL_CONTROLLED_RELAY_RUNTIME_OR_CLEANUP'
        c.exclusive(root/'receipt.json',{'status':status,'tool_sha256':c.digest(SELF),'binary_sha256':binary_pin,'host_baselines_observed':baseline is not None and hostrules is not None,'owned_child_started':child is not None,'independent_guard_started':guard is not None,'cleanup':cleanup,'errors':errors,'host_namespace_observations':host_namespace_observations,'host_configuration_comparison':None if host_configuration_pin is None else {'schema':host_configuration['schema'],'sha256':host_configuration_pin['sha256'],'exact_raw_ip_equal':host_configuration['exact_raw_ip_equal'],'exact_raw_nft_equal':host_configuration['exact_raw_nft_equal'],'configuration_unchanged':host_configuration['configuration_unchanged']},'production_or_target_network_or_independent_capture_or_signed_release_acceptance':False})
    require(status=='PASS_CONTROLLED_RELAY_NATIVE_ONLY','controlled relay did not pass; preserve attempt')

def export(stage,output):
    root=Path(stage);out=Path(output);require(out.is_absolute() and not out.exists(),'fresh evidence export');out.mkdir(mode=0o755)
    # The root controller deliberately uses umask 077. mkdir's requested mode
    # alone therefore leaves this metadata-only directory unreadable to the
    # unprivileged artifact uploader. Only this newly created export is public.
    out.chmod(0o755)
    names=['receipt.json','inner-result.json','inner-start.json','watchdog-ready.json','watchdog-terminal.json','inner.stdout','inner.stderr','inner-failure.json','native-journals.json','capture-failure.json','native-journals-failure.json','host-ip-before.json','host-nft-before.json','host-ip-after.json','host-nft-after.json','host-difference.json','host-config-comparison.json','peer.stderr','peer-diagnostic.json','inner-nft-failure.json']
    names += [f'probe-{index}{suffix}' for index in range(3) for suffix in ('.stderr','-diagnostic.json')]
    for path in root.glob('command-failure-*.json'):
        require(re.fullmatch(r'command-failure-[0-9]+-[0-9]+\.json',path.name),'unexpected diagnostic export name')
        names.append(path.name)
    require(len(names)<=64,'diagnostic export inventory bound')
    retained=[];total=0
    for name in names:
        path=root/name
        require(not path.is_symlink(),'diagnostic export symlink refused')
        if not path.exists():continue
        require(path.is_file() and not path.is_symlink() and path.stat().st_uid==0 and path.stat().st_size<=1048576,'bounded regular owned evidence')
        body=d.read_owned(path,1048576)
        total+=len(body);require(total<=8388608,'diagnostic export total bound');retained.append((name,body))
    for name,body in retained:
        with (out/name).open('xb') as stream:stream.write(body)
        (out/name).chmod(0o644)

if __name__=='__main__':
    os.umask(0o077)
    if len(sys.argv)==3 and sys.argv[1]=='peer':peer()
    elif len(sys.argv)==3 and sys.argv[1]=='watchdog':c.watchdog(sys.argv[2])
    elif len(sys.argv)==3 and sys.argv[1]=='inner':inner(sys.argv[2])
    elif len(sys.argv)==4 and sys.argv[1]=='run':outer(sys.argv[2],sys.argv[3])
    elif len(sys.argv)==4 and sys.argv[1]=='export':export(sys.argv[2],sys.argv[3])
    else:raise SystemExit('run /absolute/probe /absolute/fresh-stage | export /absolute/stage /absolute/fresh-output')
