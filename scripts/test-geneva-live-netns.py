#!/usr/bin/env python3
"""Owned unshare-only controlled Geneva runtime. Never edits the host network.
All veth devices exist in a fresh unnamed namespace; no named netns survives.
A separate host watchdog is armed before topology creation and kills only the
new session/process group after validating its exact PID/start time/argv.
"""
import ctypes
import hashlib
import functools
import json
import os
import pathlib
import select
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

SELF = pathlib.Path(__file__).resolve()
CLONE_NEWNET = 0x40000000
FAILURE_ROOT = None
COMMAND_INDEX = 0

def require(value, message):
    if not value:
        raise RuntimeError(message)

def digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def exclusive(path, value):
    data = json.dumps(value, sort_keys=True).encode() + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())

def command(argv, timeout=10):
    global COMMAND_INDEX
    try:
        r = subprocess.run(argv, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        if FAILURE_ROOT is not None:
            COMMAND_INDEX+=1
            exclusive(FAILURE_ROOT/f"command-failure-{os.getpid()}-{COMMAND_INDEX}.json",{"program":argv[0],"timeout":True,"stdout_hex":(error.stdout or b"").hex(),"stderr_hex":(error.stderr or b"").hex()})
        raise
    if r.returncode != 0 and FAILURE_ROOT is not None:
        COMMAND_INDEX+=1
        exclusive(FAILURE_ROOT/f"command-failure-{os.getpid()}-{COMMAND_INDEX}.json",{"program":argv[0],"exit_code":r.returncode,"stdout_hex":r.stdout.hex(),"stderr_hex":r.stderr.hex()})
    require(r.returncode == 0, "controlled command failed: " + argv[0])
    return r.stdout

def identity(pid):
    text = pathlib.Path(f"/proc/{pid}/stat").read_text()
    fields = text[text.rfind(")") + 2:].split()
    return {"pid": pid, "start": fields[19], "group": int(fields[2]),
            "argv": pathlib.Path(f"/proc/{pid}/cmdline").read_bytes().hex(),
            "exe": os.readlink(f"/proc/{pid}/exe")}

def same_process(row):
    try:
        return identity(row["pid"]) == row
    except FileNotFoundError:
        return False

def session_absent(group):
    for path in pathlib.Path("/proc").iterdir():
        if not path.name.isdigit():continue
        try:
            text=(path/"stat").read_text();fields=text[text.rfind(")")+2:].split()
            if int(fields[2])==group:return False
        except FileNotFoundError:continue
    return True

def kill_owned(row):
    if same_process(row):
        require(row["group"] == row["pid"], "child session ownership mismatch")
        os.killpg(row["pid"], signal.SIGKILL)

def die_with_parent(parent):
    require(ctypes.CDLL(None,use_errno=True).prctl(1,signal.SIGKILL,0,0,0)==0,"parent-death guard failed")
    require(os.getppid()==parent,"parent exited before death guard")

def read_line(process, deadline):
    require(select.select([process.stdout], [], [], max(0, deadline-time.monotonic()))[0], "child response deadline")
    line = process.stdout.readline()
    require(line, "child exited before response")
    return line

def rpc(process, request, timeout=4):
    process.stdin.write(json.dumps(request).encode()+b"\n")
    process.stdin.flush()
    result = json.loads(read_line(process,time.monotonic()+timeout))
    require(result.get("ok") is True,"endpoint operation failed")
    return result

def checksum(data):
    if len(data)%2:
        data+=b"\x00"
    total=sum(struct.unpack("!"+"H"*(len(data)//2),data))
    while total>>16:
        total=(total&65535)+(total>>16)
    return (~total)&65535

def frame():
    data=b"abcdefghijklmnop"
    source=socket.inet_aton("192.0.2.1"); destination=socket.inet_aton("192.0.2.2")
    tcp=bytearray(struct.pack("!HHIIBBHHH",1234,443,0xfffffffd,10,0x50,0x18,4096,0,0)+data)
    tcp[16:18]=struct.pack("!H",checksum(source+destination+struct.pack("!BBH",0,6,len(tcp))+tcp))
    ip=bytearray(struct.pack("!BBHHHBBH",0x45,0,20+len(tcp),42,0,64,6,0)+source+destination)
    ip[10:12]=struct.pack("!H",checksum(ip))
    return bytes.fromhex("0200000000020200000000010800")+ip+tcp

def endpoint():
    require(ctypes.CDLL(None,use_errno=True).unshare(CLONE_NEWNET)==0,"endpoint unshare failed")
    command(["sysctl","-qw","net.ipv6.conf.all.disable_ipv6=1","net.ipv6.conf.default.disable_ipv6=1"])
    print(json.dumps({"ok":True,"pid":os.getpid(),"namespace":os.readlink("/proc/self/ns/net")}),flush=True)
    sock=None
    for line in sys.stdin.buffer:
        request=json.loads(line)
        if request["op"]=="open":
            command(["ip","link","set","dev","port0","up"])
            sock=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3))
            sock.setsockopt(263,23,1)
            sock.bind(("port0",0));sock.setblocking(False)
            result={"ok":True}
        elif request["op"]=="send":
            packet=bytes.fromhex(request["frame"])
            require(len(packet)<=65549,"fixture frame too large")
            require(sock.send(packet)==len(packet),"endpoint send truncated")
            result={"ok":True}
        elif request["op"]=="receive":
            deadline=time.monotonic()+min(float(request["seconds"]),3)
            packets=[]
            while time.monotonic()<deadline:
                if select.select([sock],[],[],max(0,deadline-time.monotonic()))[0]:
                    packets.append(sock.recv(65550).hex())
                    require(len(packets)<=64,"endpoint receive budget")
            result={"ok":True,"frames":packets}
        elif request["op"]=="exit":
            print(json.dumps({"ok":True}),flush=True);break
        else:
            raise RuntimeError("unknown endpoint operation")
        print(json.dumps(result),flush=True)

def watchdog(stage):
    root=pathlib.Path(stage)
    state=json.loads((root/"watchdog-input.json").read_text())
    require(digest(SELF)==state["tool_sha256"],"watchdog source changed")
    require(same_process(state["child"]),"watchdog child no longer owned")
    require(state["child"]["group"]==state["child"]["pid"],"watchdog session mismatch")
    require(0 < state["deadline"]-time.monotonic() <= 120,"watchdog deadline outside owned finite bound")
    exclusive(root/"watchdog-ready.json",{"tool_sha256":state["tool_sha256"],"child":state["child"],"deadline":state["deadline"],"watchdog":identity(os.getpid())})
    while time.monotonic()<state["deadline"]:
        if (root/"disarm.json").exists():
            # Disarm is accepted only after the exact owned session leader exited.
            require(not same_process(state["child"]) and session_absent(state["child"]["group"]),"premature watchdog disarm")
            exclusive(root/"watchdog-terminal.json",{"owned_child_absent":True,"deadline_fired":False})
            return
        time.sleep(0.05)
    kill_owned(state["child"])
    exclusive(root/"watchdog-terminal.json",{"deadline_fired":True})

def inner(stage):
    global FAILURE_ROOT
    FAILURE_ROOT=pathlib.Path(stage)
    root=pathlib.Path(stage);cfg=json.loads((root/"input.json").read_text())
    require(cfg["tool_sha256"]==digest(SELF),"inner tool differs from preparation")
    require(os.readlink("/proc/self/ns/net")!=cfg["host_netns"],"not isolated from host")
    require(os.readlink("/proc/self/ns/mnt")!=cfg["host_mntns"],"mount namespace not isolated from host")
    exclusive(root/"inner-start.json",{"child":identity(os.getpid()),"tool_sha256":digest(SELF)})
    deadline=time.monotonic()+8
    while not(root/"watchdog-ready.json").exists():
        require(time.monotonic()<deadline,"watchdog readiness timeout");time.sleep(0.02)
    ready=json.loads((root/"watchdog-ready.json").read_text())
    require(ready["child"]==identity(os.getpid()) and ready["tool_sha256"]==digest(SELF),"watchdog readiness binding")
    require(same_process(ready["watchdog"]) and ready["deadline"]-time.monotonic()>100,"watchdog not live/bounded before topology")
    # These mounts/sysctls belong only to this new mount/network namespace.
    command(["mount","--make-rprivate","/"])
    command(["mount","-t","sysfs","-o","ro,nosuid,nodev,noexec","sysfs","/sys"])
    command(["sysctl","-qw","net.ipv6.conf.all.disable_ipv6=1","net.ipv6.conf.default.disable_ipv6=1","net.ipv4.ip_forward=0","net.ipv6.conf.all.forwarding=0"])
    endpoints=[];bridge=None;results=[]
    try:
        for index,port in enumerate(["out0","in0"]):
            child=subprocess.Popen([sys.executable,str(SELF),"endpoint"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,preexec_fn=functools.partial(die_with_parent,os.getpid()))
            endpoints.append(child)
            info=json.loads(read_line(child,time.monotonic()+8))
            require(info["pid"]==child.pid and info["namespace"]!=os.readlink("/proc/self/ns/net"),"endpoint namespace binding")
            command(["ip","link","add",port,"type","veth","peer","name",f"peer{index}"])
            command(["ip","link","set",f"peer{index}","netns",str(child.pid)])
            command(["nsenter","-t",str(child.pid),"-n","ip","link","set",f"peer{index}","name","port0"])
            command(["ip","link","set",port,"up"])
            rpc(child,{"op":"open"})
        binary=cfg["binary"]
        require(digest(binary)==cfg["binary_sha256"],"binary changed before runtime")
        # This also tests the packaged/source installed entrypoint, not a model.
        native=frame()
        cases=[
            ("midpoint-overlap","[TCP:flags:PA]-fragment{TCP:-1:True:2}(,)-|",2),
            ("ip-transport-cut","[IP:ttl:64]-fragment{IP:1:False}(,)-|",2),
            ("all-matching","[IP:ttl:64]-duplicate(,)-| [TCP:flags:PA]--|",3),
            ("encoded-payload","[TCP:load:abcd*]-tamper{TCP:load:replace:hello%20/%3A}()-|",1),
            ("tcp-option","[TCP:options-mss:]-tamper{TCP:options-mss:replace:1460}()-|",1),
            ("gas-drop","[TCP:flags:PA:1]-drop-|",0),
            ("inbound-two-interface","\\/ [TCP:flags:PA]-duplicate(tamper{IP:ttl:replace:63}(),)-|",2),
        ]
        for index,(name,strategy,count) in enumerate(cases):
            path=root/f"strategy-{index}.dsl";fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,"w")as stream:stream.write(strategy)
            bridge=subprocess.Popen([binary,"out0","in0",str(path),"2","10"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,preexec_fn=functools.partial(die_with_parent,os.getpid()))
            require(read_line(bridge,time.monotonic()+5)==b"bounded bridge ready\n","bridge startup failed")
            origin,sink=(1,0) if name=="inbound-two-interface" else (0,1)
            rpc(endpoints[origin],{"op":"send","frame":native.hex()})
            packets=[bytes.fromhex(v)for v in rpc(endpoints[sink],{"op":"receive","seconds":0.8})["frames"]]
            require(len(packets)==count,"actual forwarded frame count mismatch: "+name)
            if name=="inbound-two-interface":require([p[22]for p in packets]==[63,64],"actual inbound forest/socket direction mismatch")
            elif name=="midpoint-overlap":
                require([p[54:]for p in packets]==[b"abcdefghij",b"ijklmnop"],"actual TCP midpoint/overlap mismatch")
                require(struct.unpack("!I",packets[1][38:42])[0]==5,"actual wrapped sequence mismatch")
            elif name=="ip-transport-cut":
                require(struct.unpack("!H",packets[0][20:22])[0]&8191==1 and packets[0][34:]+packets[1][34:]==native[34:][8:]+native[34:][:8],"actual IP cut/order mismatch")
            elif name=="encoded-payload":require(packets[0][54:]==b"hello /:","actual decoded payload mismatch")
            elif name=="tcp-option":require(packets[0][54:58]==bytes.fromhex("020405b4"),"actual MSS option mismatch")
            if name=="gas-drop":
                rpc(endpoints[0],{"op":"send","frame":native.hex()})
                require(rpc(endpoints[1],{"op":"receive","seconds":0.5})["frames"]==[native.hex()],"actual gas exhaustion mismatch")
            stdout,stderr=bridge.communicate(timeout=5)
            exclusive(root/f"bridge-{index}-output.json",{"stdout_hex":stdout.hex(),"stderr_hex":stderr.hex(),"exit_code":bridge.returncode})
            require(bridge.returncode==0 and not stderr,"bridge runtime failed or kernel capture loss")
            results.append({"case":name,"emitted":len(packets),"stdout_sha256":hashlib.sha256(stdout).hexdigest(),"frame_sha256":[hashlib.sha256(p).hexdigest()for p in packets]})
            bridge=None
        # Every bridge is exited; the now-disconnected ports cannot forward.
        require(rpc(endpoints[1],{"op":"receive","seconds":0.1})["frames"]==[],"unexpected queued traffic")
        rpc(endpoints[0],{"op":"send","frame":native.hex()})
        require(rpc(endpoints[1],{"op":"receive","seconds":0.3})["frames"]==[],"forwarding survived bridge exit")
        exclusive(root/"inner-result.json",{"scope":"controlled Ethernet/IPv4 only","cases":results,"no_forwarding_after_process_exit":True,"binary_sha256":cfg["binary_sha256"]})
    finally:
        if bridge is not None:
            bridge.kill();stdout,stderr=bridge.communicate(timeout=5)
            exclusive(root/"bridge-aborted-output.json",{"stdout_hex":stdout.hex(),"stderr_hex":stderr.hex(),"exit_code":bridge.returncode})
        for index,child in enumerate(endpoints):
            if child.poll()is None:child.kill()
            stdout,stderr=child.communicate(timeout=5)
            exclusive(root/f"endpoint-{index}-terminal.json",{"stderr_hex":stderr.hex(),"exit_code":child.returncode})
        # No namespace path or persistent interface was ever installed on host.

def prepare_installed(root,binary):
    source=SELF.parent.parent
    require(command(["git","-C",str(source),"diff","--name-only","HEAD"])==b"","source checkout is dirty")
    commit=command(["git","-C",str(source),"rev-parse","HEAD"]).decode().strip()
    require(len(commit)==40 and all(c in "0123456789abcdef"for c in commit),"exact source commit unavailable")
    version=command([binary,"--version"],timeout=5).decode().strip()
    require("source "+commit+" live-linux"in version,"binary exact-source stamp differs from checkout")
    fixture=root/"operator-fixture";fixture.mkdir(mode=0o700);(fixture/"bin").mkdir();(fixture/"tools").mkdir();(fixture/"tools/geneva").mkdir()
    files={"install.sh":source/"install.sh","tools/geneva/install-bridge.sh":source/"tools/geneva/install-bridge.sh","bin/aegis-geneva-bridge":pathlib.Path(binary)}
    pins={}
    for relative,path in files.items():
        target=fixture/relative;shutil.copyfile(path,target);os.chmod(target,0o755);pins[relative]=digest(target)
    (fixture/"SHA256SUMS").write_text(pins["bin/aegis-geneva-bridge"]+"  bin/aegis-geneva-bridge\n");os.chmod(fixture/"SHA256SUMS",0o600)
    prefix=root/"installed"
    command(["bash",str(fixture/"install.sh"),"geneva-bridge","--prefix",str(prefix)],timeout=10)
    installed=prefix/"bin/aegis-geneva-bridge";metadata=installed.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid==0 and stat.S_IMODE(metadata.st_mode)==0o755,"installed copy ownership/mode failed")
    require(digest(installed)==pins["bin/aegis-geneva-bridge"],"installed copy differs from built binary")
    require(command([str(installed),"--version"],timeout=5).decode().strip()==version,"installed executable readback differs")
    proof={"source":commit,"installer_sha256":pins["install.sh"],"helper_sha256":pins["tools/geneva/install-bridge.sh"],"installed_sha256":digest(installed),"inode":metadata.st_ino,"device":metadata.st_dev,"path":str(installed),"scope":"actual unsigned prebuilt operator fixture installation"}
    exclusive(root/"installation.json",proof)
    return str(installed),proof

def cleanup_installed(proof):
    path=pathlib.Path(proof["path"]);metadata=path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid==0 and metadata.st_ino==proof["inode"] and metadata.st_dev==proof["device"] and digest(path)==proof["installed_sha256"],"installed file cleanup ownership mismatch")
    require(not path.parent.is_symlink() and not path.parent.parent.is_symlink(),"installed cleanup parent symlink")
    require(sorted(p.name for p in path.parent.iterdir())==["aegis-geneva-bridge"] and sorted(p.name for p in path.parent.parent.iterdir())==["bin"],"installed prefix contains foreign entries")
    path.unlink();path.parent.rmdir();path.parent.parent.rmdir()
    return not path.parent.parent.exists()

def outer(binary,output):
    global FAILURE_ROOT
    require(sys.platform=="linux" and os.geteuid()==0,"native controlled runtime needs Linux root")
    require(os.path.realpath(binary)==binary and pathlib.Path(binary).is_file(),"binary must be absolute regular path")
    root=pathlib.Path(output);root.mkdir(mode=0o700)
    FAILURE_ROOT=root
    installation=None;child=None;row=None;birth=None;guard=None
    host_ns=os.readlink("/proc/self/ns/net");host_mnt=os.readlink("/proc/self/ns/mnt")
    baseline=command(["ip","-j","link","show"])
    status="FAIL_CONTROLLED_PREPARATION";errors=[];guard_exited=False;group_absent=False;installed_cleanup=False;host_same=False
    try:
        binary,installation=prepare_installed(root,binary)
        exclusive(root/"input.json",{"tool_sha256":digest(SELF),"binary":binary,"binary_sha256":digest(binary),"host_netns":host_ns,"host_mntns":host_mnt,"installation":installation})
        with (root/"inner.stdout").open("xb")as stdout,(root/"inner.stderr").open("xb")as stderr:
            os.chmod(root/"inner.stdout",0o600);os.chmod(root/"inner.stderr",0o600)
            child=subprocess.Popen(["unshare","--net","--mount",sys.executable,str(SELF),"inner",str(root)],stdout=stdout,stderr=stderr,start_new_session=True)
            birth=identity(child.pid)
            ready_deadline=time.monotonic()+6
            while not(root/"inner-start.json").exists():
                require(child.poll()is None and time.monotonic()<ready_deadline,"isolated worker startup failed")
                time.sleep(0.02)
            started=json.loads((root/"inner-start.json").read_text())
            row=identity(child.pid)
            require(row==started["child"] and row["start"]==birth["start"] and row["group"]==child.pid and started["tool_sha256"]==digest(SELF),"isolated worker process binding")
            exclusive(root/"watchdog-input.json",{"tool_sha256":digest(SELF),"child":row,"deadline":time.monotonic()+120})
            guard=subprocess.Popen([sys.executable,str(SELF),"watchdog",str(root)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,start_new_session=True)
            status="FAIL_CONTROLLED_RUNTIME"
            require(child.wait(timeout=110)==0,"controlled runtime failed")
            require((root/"inner-result.json").exists(),"actual runtime result missing")
            status="PASS_CONTROLLED_NATIVE_GENEVA"
    except BaseException as error:
        errors.append({"phase":"body","type":type(error).__name__})
    finally:
        # Before guard readiness the worker has only fresh empty namespaces.
        # Bind PID/start/session, while allowing unshare to exec Python during startup.
        try:
            if child is not None and child.poll()is None:
                current=identity(child.pid)
                require(birth is not None and current["pid"]==birth["pid"] and current["start"]==birth["start"] and current["group"]==child.pid,"worker cleanup birth binding")
                if row is not None:require(current==row,"worker cleanup exact identity")
                os.killpg(child.pid,signal.SIGKILL)
            if child is not None:child.wait(timeout=5)
            absent_deadline=time.monotonic()+2
            while child is not None and not session_absent(child.pid) and time.monotonic()<absent_deadline:time.sleep(0.02)
            group_absent=child is None or session_absent(child.pid)
            require(group_absent,"owned descendant session remains")
        except BaseException as error:errors.append({"phase":"worker_cleanup","type":type(error).__name__})
        try:
            if guard is not None and group_absent:
                exclusive(root/"disarm.json",{"owned_session_absent":True})
                _,guard_stderr=guard.communicate(timeout=8)
                if guard_stderr:exclusive(root/"watchdog-failure-output.json",{"stderr_hex":guard_stderr.hex()})
                require(guard.returncode==0 and not guard_stderr,"watchdog terminal failure")
                guard_exited=True
            elif guard is None:guard_exited=True
        except BaseException as error:errors.append({"phase":"watchdog_terminal","type":type(error).__name__})
        try:
            host_same=command(["ip","-j","link","show"])==baseline and os.readlink("/proc/self/ns/net")==host_ns and os.readlink("/proc/self/ns/mnt")==host_mnt
            require(host_same,"host namespace/network changed")
        except BaseException as error:errors.append({"phase":"host_readback","type":type(error).__name__})
        if installation is not None and group_absent and guard_exited and host_same:
            try:installed_cleanup=cleanup_installed(installation)
            except BaseException as error:errors.append({"phase":"installed_cleanup","type":type(error).__name__})
        cleanup_ok=group_absent and guard_exited and host_same and installed_cleanup
        if not cleanup_ok:status="FAIL_CONTROLLED_CLEANUP"
        if errors and status=="PASS_CONTROLLED_NATIVE_GENEVA":status="FAIL_CONTROLLED_RUNTIME"
        exclusive(root/"receipt.json",{"status":status,"tool_sha256":digest(SELF),"binary_sha256":None if installation is None else installation["installed_sha256"],"host_network_unchanged":host_same,"owned_session_absent":group_absent,"watchdog_exited":guard_exited,"watchdog_alive":guard is not None and guard.poll()is None,"cleanup_checked":cleanup_ok,"installed_prefix_removed":installed_cleanup,"partial_installation_retained":installation is None and (root/"installed").exists(),"installation":installation,"errors":errors,"independent_review":False,"target_network":False,"commercial_dpi":False})
    require(status=="PASS_CONTROLLED_NATIVE_GENEVA","controlled runtime did not pass")

def export_evidence(stage,output):
    # Only explicit metadata/log files; never ship operator fixtures, binaries or source.
    root=pathlib.Path(stage);target=pathlib.Path(output);target.mkdir(mode=0o755)
    names=["receipt.json","installation.json","inner-result.json","inner-start.json","watchdog-ready.json","watchdog-terminal.json","inner.stdout","inner.stderr","watchdog-failure-output.json"]
    names += sorted(p.name for pattern in ["command-failure-*.json","bridge-*-output.json","endpoint-*-terminal.json"] for p in root.glob(pattern))
    for name in names:
        path=root/name
        if not path.exists():continue
        metadata=path.lstat();require(stat.S_ISREG(metadata.st_mode)and metadata.st_uid==0 and metadata.st_size<=1048576,"evidence export ownership/size")
        data=path.read_bytes();fd=os.open(target/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
        with os.fdopen(fd,"wb")as stream:stream.write(data)

if __name__=="__main__":
    if sys.argv[1]=="endpoint":endpoint()
    elif sys.argv[1]=="watchdog":watchdog(sys.argv[2])
    elif sys.argv[1]=="inner":inner(sys.argv[2])
    elif sys.argv[1]=="run" and len(sys.argv)==4:outer(sys.argv[2],sys.argv[3])
    elif sys.argv[1]=="export" and len(sys.argv)==4:export_evidence(sys.argv[2],sys.argv[3])
    else:raise SystemExit("usage: test-geneva-live-netns.py run /absolute/installed-binary /absolute/new-output")
