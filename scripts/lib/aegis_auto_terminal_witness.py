#!/usr/bin/env python3
"""Installed source-bound AUTO terminal witness.

This never clears stop intent or grants networking.
"""
import ctypes as C
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import select
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import uuid

RUN=Path('/run/aegis-auto-terminal')
SOCK=RUN/'observer.sock'
READY=RUN/'ready.json'
PROC_EVENT_EXEC=2
CN_IDX_PROC=CN_VAL_PROC=1
NETLINK_CONNECTOR=11
SOL_NETLINK=270
NETLINK_ADD_MEMBERSHIP=1
SYSTEMD_SHUTDOWN='/usr/lib/systemd/systemd-shutdown'
HEX64=re.compile(r'[0-9a-f]{64}\Z')
UNIT={'reboot':'systemd-reboot.service','poweroff':'systemd-poweroff.service'}
FIXED_REASONS=frozenset((
 'bind_a_private_mismatch', 'bind_argv', 'bind_job_changed', 'bind_schema',
 'bind_state', 'boot_id', 'bus_address', 'bus_callback',
 'bus_fd', 'bus_kernel_bytes_unconsumed', 'bus_match', 'bus_new',
 'bus_open_state', 'bus_peer_not_pid1', 'bus_ready_query', 'bus_start',
 'bus_unexpected_error', 'connector_ack', 'connector_gap', 'connector_header',
 'fifo_not_active', 'fifo_requires_two_cpus', 'final_unit_fragment_changed', 'final_unit_pid1_show',
 'final_unit_properties', 'final_unit_semantics', 'initial_pid1', 'job_event_bound',
 'job_path', 'job_removed_read', 'json_length', 'json_schema',
 'kernel_timestamp', 'late_args', 'late_caller', 'late_foreign_parent',
 'late_parent_cycle', 'late_parent_missing', 'late_pid1_exe_action', 'late_runtime_chain_invalid',
 'late_schema', 'late_witness_refused', 'linux_only', 'mark_a_args',
 'mark_private_args', 'netlink_credentials', 'netlink_frame', 'netlink_header',
 'netlink_sender', 'observer_bind_refused', 'observer_deadline', 'operation',
 'parent_stat_short', 'pending_final_job_not_unique', 'pid1_cmdline', 'pid1_exec_before_bound_proof',
 'pid1_exec_identity', 'pid1_job_path', 'pid1_job_rendering', 'pid1_shutdown_action',
 'pid1_stat_short', 'pidfd_unavailable', 'private_job_changed', 'private_main_not_success',
 'private_no_a', 'private_terminal_not_success', 'proof_readback', 'proof_short_write',
 'proof_size', 'ready_pid1_changed', 'ready_short_write', 'remount_flags_changed',
 'remount_mode', 'request', 'request_length', 'response_length',
 'root_dev_changed', 'root_mount_flags', 'root_mount_unique', 'root_not_pid1',
 'root_not_pinned_ext4', 'root_read_only', 'root_ro_flags_not_restored', 'root_uuid_changed',
 'run_path_preexists', 'runtime_metadata', 'runtime_name', 'runtime_short',
 'runtime_short_write', 'runtime_size', 'socket_peer', 'source_changed',
 'source_config_metadata', 'source_config_schema', 'source_config_short', 'source_elf_changed',
 'source_metadata', 'store_config_metadata', 'store_config_schema', 'store_config_short',
 'store_directory', 'usage',
))
FIXED_REASONS=FIXED_REASONS|frozenset(('observer_pid1_unavailable', 'observer_pid1_invalid', 'observer_pid1_changed', 'observer_process_changed', 'observer_process_generation', 'ready_observer_identity_changed','retire_state_unqualified',
 'retire_pending_changed','retire_private_not_stopped', 'final_job_replaced', 'private_stop_job_replaced', 'private_unit_pin_missing', 'pin_args', 'pin_bus_parent', 'pin_bus_source', 'pin_bus_new', 'pin_bus_start', 'pin_bus_fd', 'pin_bus_peer', 'pin_bus_replaced', 'pin_bus_peer_exited', 'pin_owner_query', 'pin_owner_uint', 'pin_owner_not_pid1', 'pin_method', 'pin_method_reply', 'pin_unit_path', 'pin_unit_id', 'pin_invocation', 'pin_invocation_property', 'pin_invocation_read', 'pin_unit_property', 'pin_unit_read', 'pin_result_property', 'pin_result_read', 'pin_unit_changed', 'pin_active_changed', 'pin_terminal_not_success', 'blkid_failed', 'boot_already_mounted', 'boot_config_dev', 'boot_config_hash', 'boot_config_paths', 'boot_config_schema', 'boot_config_source', 'boot_config_uuid', 'boot_helper_metadata', 'boot_helper_size', 'boot_helper_source_changed', 'boot_identity', 'boot_mount_failed', 'boot_mount_identity', 'boot_same_as_root', 'boot_store_source_pins', 'bus_method_timeout', 'foreign_shutdown_hook', 'fwupd_dir_untrusted', 'fwupd_parent_untrusted', 'fwupd_pending_exists', 'helper_hash_changed', 'hook_changed', 'hook_dir_metadata', 'hook_hash_changed', 'job_get', 'job_get_path', 'job_identity_or_type', 'job_property_Id', 'job_property_JobType', 'job_property_Unit', 'job_property_read_Id', 'job_property_read_JobType', 'job_property_read_Unit', 'job_query_args', 'marker_metadata', 'marker_oversize', 'marker_readback', 'marker_short_write', 'md_arrays_present_or_mdstat_untrusted', 'md_views_untrusted', 'mdstat_bound', 'mdstat_unavailable', 'mount_namespace_private', 'mount_namespace_unshare', 'mount_not_unique', 'mountinfo_fields', 'mountinfo_format', 'not_root', 'root_changed_after_publication', 'root_changed_before_publication', 'root_identity', 'root_not_ro', 'root_remount_ro_failed', 'run_not_rw_tmpfs', 'run_untrusted', 'source_changed', 'source_metadata', 'source_not_block', 'stock_hook_changed', 'store_dir_metadata', 'trial_record_fields', 'trial_record_oversize', 'trial_record_schema'))
PRODUCT_SOURCES={
 'a_unit_sha256':'/etc/systemd/system/aegis-auto-terminal-a@.service',
 'b_unit_sha256':'/etc/systemd/system/aegis-auto-terminal-b@.service',
 'observer_unit_sha256':'/etc/systemd/system/aegis-auto-terminal-observer.service',
 'transition_unit_sha256':'/etc/systemd/system/aegis-auto-terminal-transition.service',
 'hook_sha256':'/usr/lib/systemd/system-shutdown/aegis-auto-terminal-hook',
 'boot_helper_sha256':'/usr/local/lib/aegis/helpers/lib/aegis_auto_terminal_boot_store.py'}
PRIVATE_UNIT=re.compile(r'aegis-auto@[0-9a-f]{64}\.service\Z')
STOP_INTENT=Path('/var/lib/aegis-install/client/auto-stop-intent.json')

STORE_CONFIG=Path('/etc/aegis-auto-terminal-store.json')
SOURCE_CONFIG=Path('/etc/aegis-auto-terminal-source.json')

def need(ok,reason):
 if not ok:raise RuntimeError(reason)

def failure_code(prefix,exc):
 need(prefix in ('bus','connector','socket','ready','command'),'failure_prefix')
 cls=type(exc).__name__
 if cls not in ('RuntimeError','OSError','ValueError','KeyError',
              'FileNotFoundError','PermissionError','TimeoutError',
              'JSONDecodeError','BrokenPipeError','Refusal'):
  cls='Other'
 reason=str(exc)
 if reason not in FIXED_REASONS:reason='unclassified'
 return prefix+':'+cls+':'+reason

def first_failure(state,prefix,exc):
 if state['refusal'] is not None:return
 state['refusal']=failure_code(prefix,exc)
 try:
  print(json.dumps({'schema':'aegis_auto_terminal_first_failure_v1',
                    'refusal':state['refusal']},sort_keys=True),
        file=sys.stderr,flush=True)
 except OSError:pass

def callback_failure_reason(exc):
 # The callback runs across a C boundary, so its exception cannot propagate.
 # Retain only an existing fixed refusal token; never log arbitrary message
 # content from a D-Bus frame or an unexpected exception.
 if type(exc) is RuntimeError and str(exc) in FIXED_REASONS:
  return str(exc)
 return 'bus_callback'

def exact_json(raw,keys):
 need(len(raw)<=4096,'json_length')
 value=json.loads(raw)
 need(type(value)is dict and set(value)==set(keys),'json_schema')
 return value

def unique_pairs(pairs):
 row={}
 for key,value in pairs:
  need(key not in row,'duplicate_json_key')
  row[key]=value
 return row

def sha(path):
 h=hashlib.sha256()
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_uid==0 and a.st_nlink==1 and a.st_size<=1<<22,'source_metadata')
  while True:
   part=os.read(fd,65536)
   if not part:break
   h.update(part)
  b=os.fstat(fd);need((a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns),'source_changed')
  return h.hexdigest()
 finally:os.close(fd)

def pid1_facts(require_action=False):
 raw=Path('/proc/1/stat').read_text()
 fields=raw[raw.rfind(')')+2:].split()
 need(len(fields)>20,'pid1_stat_short')
 tick=int(fields[19]) # field 22 after pid+comm
 # PID1 may start within the first clock tick. Zero is a real generation
 # value; its boot ID and held pidfd still bind it to this kernel instance.
 need(0<=tick<1<<64,'initial_pid1')
 exe=os.readlink('/proc/1/exe')
 cmd=Path('/proc/1/cmdline').read_bytes().split(b'\0')
 need(len(cmd)>=1 and 0<len(cmd[0])<=512 and all(len(x)<=512 for x in cmd[:4]),'pid1_cmdline')
 if require_action:need(len(cmd)>=2 and cmd[1] in (b'reboot',b'poweroff'),'pid1_shutdown_action')
 return dict(start_tick=tick,exe=exe,argv0=cmd[0].decode('utf-8','strict'),
             action=cmd[1].decode('ascii' if require_action else 'utf-8','strict') if len(cmd)>1 else '')

def boot_id():
 value=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 need(re.fullmatch(r'[0-9a-f-]{36}',value) is not None,'boot_id')
 return value

def proc_parent(pid):
 raw=Path('/proc/'+str(pid)+'/stat').read_text()
 fields=raw[raw.rfind(')')+2:].split()
 need(len(fields)>20,'parent_stat_short')
 return int(fields[1]),int(fields[19])

def late_ancestor_chain():
 pid=os.getppid();rows=[]
 for _ in range(4):
  need(pid>0,'late_parent_missing')
  exe=os.readlink('/proc/'+str(pid)+'/exe')
  next_pid,tick=proc_parent(pid)
  need(exe==SYSTEMD_SHUTDOWN and (0<=tick<1<<64 if pid==1 else 0<tick<1<<64),
       'late_foreign_parent')
  rows.append(dict(pid=pid,start_tick=tick))
  if pid==1:return rows
  need(next_pid!=pid,'late_parent_cycle')
  pid=next_pid
 raise RuntimeError('late_parent_depth')

def mount_root():
 raw=Path('/proc/self/mountinfo').read_text()
 rows=[]
 for line in raw.splitlines():
  left,sep,right=line.partition(' - ')
  if not sep:continue
  a=left.split();b=right.split()
  if len(a)>=6 and a[4]=='/' and len(b)>=3:
   rows.append(dict(dev=a[2],options=tuple(sorted(a[5].split(','))),fstype=b[0],
                    source=b[1],super=tuple(sorted(b[2].split(',')))))
 need(len(rows)==1,'root_mount_unique')
 return rows[0]

def store_config():
 fd=os.open(STORE_CONFIG,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  st=os.fstat(fd);need(stat.S_ISREG(st.st_mode)and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600 and
                       st.st_nlink==1 and 0<st.st_size<=2048,'store_config_metadata')
  data=os.read(fd,2049);need(len(data)==st.st_size,'store_config_short')
  keys=('schema','root_uuid','root_dev','root_source','boot_uuid','boot_dev','boot_source',
        'run_mount_dir','boot_store_dir','hook_path','hook_sha256','helper_sha256')
  return exact_json(data,keys)
 finally:os.close(fd)

def source_config():
 fd=os.open(SOURCE_CONFIG,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  st=os.fstat(fd);need(stat.S_ISREG(st.st_mode)and st.st_uid==0 and
                       stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1 and 0<st.st_size<=2048,
                       'source_config_metadata')
  data=os.read(fd,2049);need(len(data)==st.st_size,'source_config_short')
  row=exact_json(data,('schema','selected_manager',
                       'manager_transition_dropin_sha256',
                       'guardian_transition_dropin_sha256',
                       'witness_sha256','shutdown_sha256','reboot_unit_sha256',
                       'poweroff_unit_sha256','register_sha256',
                       'transition_sha256',*PRODUCT_SOURCES))
  need(row['schema']=='aegis_auto_terminal_source_v1' and
       row['selected_manager'] in ('NetworkManager.service','systemd-networkd.service') and
       all(type(value)is str and HEX64.fullmatch(value)for key,value in row.items()
           if key not in('schema','selected_manager')),
       'source_config_schema')
  need(sha(Path(__file__))==row['witness_sha256'] and
       sha(SYSTEMD_SHUTDOWN)==row['shutdown_sha256'],'source_elf_changed')
  for field,path in PRODUCT_SOURCES.items():need(sha(path)==row[field],'product_source_changed_'+field)
  return row
 finally:os.close(fd)

def final_unit(action,config):
 unit=UNIT[action]
 q=subprocess.run(['/usr/bin/systemctl','show',unit,'-p','FragmentPath','-p','DropInPaths',
                   '-p','SuccessAction','-p','Requires','-p','After','-p','Job'],
                  capture_output=True,timeout=5)
 need(q.returncode==0 and not q.stderr and len(q.stdout)<=4096,'final_unit_pid1_show')
 facts={}
 for line in q.stdout.decode('utf-8','strict').splitlines():
  key,sep,value=line.partition('=')
  need(sep and key not in facts and key in {'FragmentPath','DropInPaths','SuccessAction','Requires','After','Job'},
       'final_unit_properties')
  facts[key]=value
 need(set(facts)=={'FragmentPath','DropInPaths','SuccessAction','Requires','After','Job'} and
      facts['DropInPaths']=='' and facts['SuccessAction']==action+'-force' and
      {'shutdown.target','umount.target','final.target'}<=set(facts['Requires'].split()) and
      {'shutdown.target','umount.target','final.target'}<=set(facts['After'].split()),
      'final_unit_semantics')
 fragment=Path(facts['FragmentPath'])
 need(str(fragment)=='/usr/lib/systemd/system/'+unit and
      sha(fragment)==config[action+'_unit_sha256'],'final_unit_fragment_changed')
 return facts

def load_boot_helper(expected):
 path=Path(PRODUCT_SOURCES['boot_helper_sha256'])
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  before=os.fstat(fd)
  need(stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_nlink==1 and
       not before.st_mode&0o022 and 0<before.st_size<=32768,'boot_helper_metadata')
  chunks=[];count=0
  while True:
   data=os.read(fd,min(65536,32769-count))
   if not data:break
   chunks.append(data);count+=len(data);need(count<=32768,'boot_helper_size')
  after=os.fstat(fd);named=path.lstat()
  keys=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
  raw=b''.join(chunks)
  need(len(raw)==before.st_size and
       all(getattr(before,k)==getattr(after,k)==getattr(named,k)for k in keys) and
       hashlib.sha256(raw).hexdigest()==expected,'boot_helper_source_changed')
 finally:os.close(fd)
 namespace={'__file__':str(path),'__name__':'aegis_qa_newboot_store'}
 exec(compile(raw,str(path),'exec'),namespace)
 return namespace

def durable_store(row):
 source=source_config();config=store_config()
 need(config['helper_sha256']==source['boot_helper_sha256'] and
      config['hook_sha256']==source['hook_sha256'],'boot_store_source_pins')
 helper=load_boot_helper(source['boot_helper_sha256'])
 return helper['publish_terminal'](config,row)

def check_nl_packet(raw,addr,ancillary,truncated):
 need(not truncated and len(raw)>=16+20+40 and len(raw)<=8192,'netlink_frame')
 need(addr[0]==0,'netlink_sender')
 creds=[struct.unpack('=iii',data[:12])for level,typ,data in ancillary
        if level==socket.SOL_SOCKET and typ==socket.SCM_CREDENTIALS and len(data)>=12]
 need(creds==[(0,0,0)],'netlink_credentials')
 nl_len,nl_type,nl_flags,nl_seq,nl_pid=struct.unpack_from('=IHHII',raw)
 need(nl_len==len(raw)and nl_pid==0 and nl_type==3,'netlink_header')
 idx,val,seq,ack,body_len,flags=struct.unpack_from('=IIIIHH',raw,16)
 need((idx,val,flags)==(1,1,0)and body_len==40 and len(raw)==16+20+40,'connector_header')
 what,cpu,stamp=struct.unpack_from('=IIQ',raw,36)
 need(stamp>0,'kernel_timestamp')
 return dict(seq=seq,ack=ack,what=what,cpu=cpu,
             payload=raw[52:76],nl_seq=nl_seq)

def connector():
 s=socket.socket(socket.AF_NETLINK,socket.SOCK_DGRAM|socket.SOCK_CLOEXEC,NETLINK_CONNECTOR)
 s.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
 s.bind((os.getpid(),0))
 s.setsockopt(SOL_NETLINK,NETLINK_ADD_MEMBERSHIP,struct.pack('=I',1))
 s.setblocking(False)
 seq=int.from_bytes(os.urandom(4),'little')
 ack_seed=int.from_bytes(os.urandom(4),'little')
 # Subscribe to all events: the per-CPU sequence advances even for events
 # excluded by a connector filter, so filtered EXEC cannot prove no loss.
 data=struct.pack('=I',1)
 cn=struct.pack('=IIIIHH',1,1,seq,ack_seed,len(data),0)+data
 msg=struct.pack('=IHHII',16+len(cn),3,0,seq,os.getpid())+cn
 s.sendto(msg,(0,0))
 return s,(ack_seed+1)&0xffffffff

def netlink_truncated(flags):
 return bool(flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))

def connector_ack_admitted(row, expected_ack, already_ack):
 # cn_proc_ack first writes cpu=-1, but send_msg overwrites it with the
 # actual per-CPU sender ID and overwrites cn_msg.seq before serialization.
 return (not already_ack and row['what']==0 and row['ack']==expected_ack and
         row['cpu']!=0xffffffff and row['nl_seq']==row['seq'] and
         struct.unpack_from('=I',row['payload'])[0]==0)

def record_connector_wire(state,row,expected_ack):
 # Every emitted message, including our ACK and pre-ACK events, consumes a
 # per-CPU sequence number. A hole after the first observed number refuses.
 prev=state['seen_by_cpu'].get(row['cpu'])
 if prev is not None:need(row['seq']==(prev+1)&0xffffffff,'connector_gap')
 state['seen_by_cpu'][row['cpu']]=row['seq']
 if row['what']==0:
  need(connector_ack_admitted(row,expected_ack,state['ack']),'connector_ack')
  state['ack']=True
  return False
 if row['what']==PROC_EVENT_EXEC:
  pid,tgid=struct.unpack_from('=ii',row['payload'])
  if pid==tgid==1:
   need(state['ack'] and state['ready_published'] and state['b'] is not None,
        'pid1_exec_before_bound_proof')
   return True
 return False

def positive_job_done(events,expected):
 matching=[row for row in events if row[0]==expected[0] or row[1]==expected[1]]
 return matching==[expected]

def ready_witness(state,bus):
 return (state['ack'] and state['refusal'] is None and state['exec'] is None and
         not state['bus_eof'] and bus.peercred==(1,0,0) and
         bus.match_registered and bus.ready())

def exact_stream_eof(held_socket):
 # sd_bus_is_open()==0 is a libsystemd state, not proof that the original
 # PID1-authenticated socket was drained to kernel EOF. A duplicate retains
 # that exact connection even if libsystemd closes its descriptor.
 try:raw=held_socket.recv(1,socket.MSG_PEEK|socket.MSG_DONTWAIT)
 except BlockingIOError as exc:raise RuntimeError('bus_no_kernel_eof')from exc
 except OSError as exc:raise RuntimeError('bus_eof_read_error')from exc
 need(raw==b'','bus_kernel_bytes_unconsumed')

def admitted_job(job,path,unit,actual_id,actual_unit,unit_path,actual_type,expected_type):
 need(actual_id==job and actual_unit==unit.encode('ascii') and
      unit_path==b'/org/freedesktop/systemd1/unit/'+''.join(
       c if c.isascii() and c.isalnum() else '_'+format(ord(c),'02x') for c in unit).encode('ascii') and
      actual_type==expected_type.encode('ascii') and
      path=='/org/freedesktop/systemd1/job/'+str(job),'job_identity_or_type')
 return expected_type

class DirectBus:
 def __init__(self,record):
  self.lib=C.CDLL('libsystemd.so.0',use_errno=True)
  L=self.lib
  def bind(name,args,result=C.c_int):
   fn=getattr(L,name);fn.argtypes=args;fn.restype=result;return fn
  self.new=bind('sd_bus_new',[C.POINTER(C.c_void_p)])
  self.address=bind('sd_bus_set_address',[C.c_void_p,C.c_char_p])
  self.start=bind('sd_bus_start',[C.c_void_p])
  self.fd=bind('sd_bus_get_fd',[C.c_void_p])
  self.process=bind('sd_bus_process',[C.c_void_p,C.POINTER(C.c_void_p)])
  self.is_open=bind('sd_bus_is_open',[C.c_void_p])
  self.is_ready=bind('sd_bus_is_ready',[C.c_void_p])
  self.match=bind('sd_bus_add_match',[C.c_void_p,C.POINTER(C.c_void_p),C.c_char_p,C.c_void_p,C.c_void_p])
  self.read=bind('sd_bus_message_read',[C.c_void_p,C.c_char_p])
  self.call=bind('sd_bus_call_method',[C.c_void_p,C.c_char_p,C.c_char_p,C.c_char_p,C.c_char_p,C.c_void_p,C.POINTER(C.c_void_p),C.c_char_p])
  self.property=bind('sd_bus_get_property',[C.c_void_p,C.c_char_p,C.c_char_p,C.c_char_p,C.c_char_p,C.c_void_p,C.POINTER(C.c_void_p),C.c_char_p])
  self.message_unref=bind('sd_bus_message_unref',[C.c_void_p],C.c_void_p)
  self.method_timeout=bind('sd_bus_set_method_call_timeout',[C.c_void_p,C.c_uint64])
  self.close=bind('sd_bus_close_unref',[C.c_void_p],C.c_void_p)
  self.bus=C.c_void_p();self.slot=C.c_void_p();self.record=record
  need(self.new(C.byref(self.bus))>=0,'bus_new')
  need(self.address(self.bus,b'unix:path=/run/systemd/private')>=0,'bus_address')
  need(self.start(self.bus)>=0,'bus_start')
  need(self.method_timeout(self.bus,300_000)>=0,'bus_method_timeout')
  self.socket_fd=self.fd(self.bus);need(self.socket_fd>=0,'bus_fd')
  self.peer_socket=socket.socket(fileno=os.dup(self.socket_fd))
  pid,uid,gid=struct.unpack('=iii',self.peer_socket.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
  need((pid,uid,gid)==(1,0,0),'bus_peer_not_pid1')
  self.peercred=(pid,uid,gid)
  CALLBACK=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_void_p,C.c_void_p)
  @CALLBACK
  def callback(message,userdata,error):
   try:
    job=C.c_uint32();path=C.c_char_p();unit=C.c_char_p();result=C.c_char_p()
    r=self.read(message,b'uoss',C.byref(job),C.byref(path),C.byref(unit),C.byref(result))
    need(r>0,'job_removed_read')
    self.record(job.value,path.value.decode(),unit.value.decode(),result.value.decode())
   except BaseException as exc:self.failed=callback_failure_reason(exc)
   return 0
  self.callback=callback;self.failed=None
  pattern=b"type='signal',path='/org/freedesktop/systemd1',interface='org.freedesktop.systemd1.Manager',member='JobRemoved'"
  need(self.match(self.bus,C.byref(self.slot),pattern,C.cast(callback,C.c_void_p),None)>=0,'bus_match')
  self.match_registered=True
 def ready(self):
  value=self.is_ready(self.bus)
  need(value>=0,'bus_ready_query')
  return value>0
 def exact_job(self,job,path,unit,expected_type='start'):
  need(type(job)is int and 0<job<2**32 and
       path=='/org/freedesktop/systemd1/job/'+str(job) and
       type(unit)is str and
       ((expected_type=='stop' and PRIVATE_UNIT.fullmatch(unit)) or
        (expected_type=='start' and unit in UNIT.values())),
       'job_query_args')
  dest=b'org.freedesktop.systemd1';manager=b'/org/freedesktop/systemd1'
  reply=C.c_void_p()
  try:
   need(self.call(self.bus,dest,manager,b'org.freedesktop.systemd1.Manager',
                  b'GetJob',None,C.byref(reply),b'u',C.c_uint32(job))>=0,'job_get')
   actual=C.c_char_p()
   need(self.read(reply,b'o',C.byref(actual))>0 and
        actual.value.decode('ascii','strict')==path,'job_get_path')
  finally:
   if reply:self.message_unref(reply)
  iface=b'org.freedesktop.systemd1.Job'
  def prop(name,signature,*targets):
   message=C.c_void_p()
   try:
    need(self.property(self.bus,dest,path.encode('ascii'),iface,name,None,
                       C.byref(message),signature)>=0,'job_property_'+name.decode())
    need(self.read(message,signature,*(C.byref(v) for v in targets))>0,
         'job_property_read_'+name.decode())
    return tuple(v.value if isinstance(v,C.c_uint32) else bytes(v.value or b'') for v in targets)
   finally:
    if message:self.message_unref(message)
  (actual_id,)=prop(b'Id',b'u',C.c_uint32())
  actual_unit,unit_path=prop(b'Unit',b'(so)',C.c_char_p(),C.c_char_p())
  (actual_type,)=prop(b'JobType',b's',C.c_char_p())
  return admitted_job(job,path,unit,actual_id,actual_unit,unit_path,actual_type,expected_type)
 def drain(self):
  for _ in range(128):
   r=self.process(self.bus,None)
   need(self.failed is None,self.failed or 'bus_callback')
   opened=self.is_open(self.bus)
   need(opened>=0,'bus_open_state')
   if r<0:
    need(opened==0 and -r in (errno.ENOTCONN,errno.ECONNRESET,errno.EPIPE),
         'bus_unexpected_error')
    exact_stream_eof(self.peer_socket)
    return True,False
   if r==0:
    if opened==0:exact_stream_eof(self.peer_socket)
    return opened==0,False
  # A bounded chunk may leave messages buffered in libsystemd while the
  # underlying socket is no longer readable. It is not EOF or a refusal.
  return False,True
 def destroy(self):
  if hasattr(self,'peer_socket'):self.peer_socket.close()
  if self.bus:self.close(self.bus);self.bus=None

class SystemUnitPin:
 """Held system-bus sender reference for one authenticated private Unit object.

 This connection grants no Stop/Start authority. The direct PID1 socket remains
 the sole JobRemoved/GetJob witness; PID1 ownership of this mediated sender is
 rechecked before and after reading the retained Unit result.
 """
 def __init__(self,unit,invocation):
  need(PRIVATE_UNIT.fullmatch(unit) and
       re.fullmatch(r'[0-9a-f]{32}',invocation),'pin_args')
  self.unit=unit;self.invocation=invocation;self.bus=C.c_void_p()
  self.lib=C.CDLL('libsystemd.so.0',use_errno=True)
  L=self.lib
  def bind(name,args,result=C.c_int):
   fn=getattr(L,name);fn.argtypes=args;fn.restype=result;return fn
  self.new=bind('sd_bus_new',[C.POINTER(C.c_void_p)])
  self.address=bind('sd_bus_set_address',[C.c_void_p,C.c_char_p])
  self.client=bind('sd_bus_set_bus_client',[C.c_void_p,C.c_int])
  self.start=bind('sd_bus_start',[C.c_void_p])
  self.fd=bind('sd_bus_get_fd',[C.c_void_p])
  self.timeout=bind('sd_bus_set_method_call_timeout',[C.c_void_p,C.c_uint64])
  self.call=bind('sd_bus_call_method',[C.c_void_p,C.c_char_p,C.c_char_p,C.c_char_p,C.c_char_p,C.c_void_p,C.POINTER(C.c_void_p),C.c_char_p])
  self.property=bind('sd_bus_get_property',[C.c_void_p,C.c_char_p,C.c_char_p,C.c_char_p,C.c_char_p,C.c_void_p,C.POINTER(C.c_void_p),C.c_char_p])
  self.read=bind('sd_bus_message_read',[C.c_void_p,C.c_char_p])
  self.array=bind('sd_bus_message_read_array',[C.c_void_p,C.c_char,C.POINTER(C.c_void_p),C.POINTER(C.c_size_t)])
  self.unref=bind('sd_bus_message_unref',[C.c_void_p],C.c_void_p)
  self.close=bind('sd_bus_close_unref',[C.c_void_p],C.c_void_p)
  socket_path=Path('/run/dbus/system_bus_socket')
  for parent in reversed(socket_path.parents):
   if parent==Path('/'):continue
   st=parent.lstat();need(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and
                         not st.st_mode&0o022,'pin_bus_parent')
  before=socket_path.lstat()
  need(stat.S_ISSOCK(before.st_mode) and before.st_uid==0,'pin_bus_source')
  need(self.new(C.byref(self.bus))>=0,'pin_bus_new')
  try:
   need(self.address(self.bus,b'unix:path=/run/dbus/system_bus_socket')>=0 and
        self.client(self.bus,1)>=0 and self.start(self.bus)>=0 and
        self.timeout(self.bus,300_000)>=0,'pin_bus_start')
   fd=self.fd(self.bus);need(fd>=0,'pin_bus_fd')
   self.socket=socket.socket(fileno=os.dup(fd))
   peer=struct.unpack('=iii',self.socket.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
   need(peer[0]>0 and peer[1]==0,'pin_bus_peer')
   self.peerfd=os.pidfd_open(peer[0],0)
   again=socket_path.lstat()
   keys=('st_dev','st_ino','st_mode','st_uid','st_gid','st_mtime_ns','st_ctime_ns')
   need(all(getattr(before,k)==getattr(again,k)for k in keys),'pin_bus_replaced')
   self.owner=self.pid1_owner()
   self.path=self.call_string(self.owner,b'GetUnit',unit.encode(),b'o')
   need(self.path==b'/org/freedesktop/systemd1/unit/'+''.join(
        c if c.isascii() and c.isalnum() else '_'+format(ord(c),'02x')
        for c in unit).encode(),'pin_unit_path')
   need(self.unit_field(b'Id',b's')==unit.encode(),'pin_unit_id')
   need(self.unit_invocation()==invocation,'pin_invocation')
   self.call_string(self.owner,b'RefUnit',unit.encode(),None)
   self.revalidate(active=True)
  except BaseException:
   self.destroy();raise
 def method(self,dest,path,interface,member,arg,signature):
  reply=C.c_void_p()
  try:
   need(self.call(self.bus,dest,path,interface,member,None,C.byref(reply),
                  b's',C.c_char_p(arg))>=0,'pin_method')
   if signature is None:return None
   need(reply.value is not None,'pin_method_reply')
   value=C.c_char_p()
   need(self.read(reply,signature,C.byref(value))>0 and value.value is not None,
        'pin_method_reply')
   return bytes(value.value)
  finally:
   if reply:self.unref(reply)
 def call_string(self,dest,member,arg,signature):
  return self.method(dest,b'/org/freedesktop/systemd1',
                     b'org.freedesktop.systemd1.Manager',member,arg,signature)
 def daemon(self,member,arg,signature):
  return self.method(b'org.freedesktop.DBus',b'/org/freedesktop/DBus',
                     b'org.freedesktop.DBus',member,arg,signature)
 def daemon_uint(self,member,arg):
  reply=C.c_void_p()
  try:
   need(self.call(self.bus,b'org.freedesktop.DBus',b'/org/freedesktop/DBus',
                  b'org.freedesktop.DBus',member,None,C.byref(reply),
                  b's',C.c_char_p(arg))>=0,'pin_owner_query')
   need(reply.value is not None,'pin_owner_uint')
   value=C.c_uint32()
   need(self.read(reply,b'u',C.byref(value))>0,'pin_owner_uint')
   return value.value
  finally:
   if reply:self.unref(reply)
 def pid1_owner(self):
  owner=self.daemon(b'GetNameOwner',b'org.freedesktop.systemd1',b's')
  need(re.fullmatch(rb':[0-9]+\.[0-9]+',owner) and len(owner)<=128 and
       self.daemon_uint(b'GetConnectionUnixProcessID',owner)==1 and
       self.daemon_uint(b'GetConnectionUnixUser',owner)==0,'pin_owner_not_pid1')
  return owner
 def unit_field(self,name,signature):
  reply=C.c_void_p()
  try:
   need(self.property(self.bus,self.owner,self.path,
                      b'org.freedesktop.systemd1.Unit',name,None,
                      C.byref(reply),signature)>=0,'pin_unit_property')
   need(reply.value is not None,'pin_unit_read')
   value=C.c_char_p()
   need(self.read(reply,signature,C.byref(value))>0 and value.value is not None,
        'pin_unit_read')
   return bytes(value.value)
  finally:
   if reply:self.unref(reply)
 def service_result(self):
  reply=C.c_void_p()
  try:
   need(self.property(self.bus,self.owner,self.path,
                      b'org.freedesktop.systemd1.Service',b'Result',None,
                      C.byref(reply),b's')>=0,'pin_result_property')
   need(reply.value is not None,'pin_result_read')
   value=C.c_char_p()
   need(self.read(reply,b's',C.byref(value))>0 and value.value is not None,
        'pin_result_read')
   return bytes(value.value)
  finally:
   if reply:self.unref(reply)
 def unit_invocation(self):
  reply=C.c_void_p()
  try:
   need(self.property(self.bus,self.owner,self.path,
                      b'org.freedesktop.systemd1.Unit',b'InvocationID',None,
                      C.byref(reply),b'ay')>=0,'pin_invocation_property')
   need(reply.value is not None,'pin_invocation_read')
   data=C.c_void_p();size=C.c_size_t()
   need(self.array(reply,b'y',C.byref(data),C.byref(size))>=0 and
        size.value==16 and data.value,'pin_invocation_read')
   return C.string_at(data,size.value).hex()
  finally:
   if reply:self.unref(reply)
 def revalidate(self,*,active):
  probe=select.poll();probe.register(self.peerfd,select.POLLIN)
  need(not probe.poll(0),'pin_bus_peer_exited')
  need(self.pid1_owner()==self.owner and
       self.call_string(self.owner,b'GetUnit',self.unit.encode(),b'o')==self.path and
       self.unit_field(b'Id',b's')==self.unit.encode() and
       self.unit_field(b'LoadState',b's')==b'loaded',
       'pin_unit_changed')
  if active:
   need(self.unit_invocation()==self.invocation and
        self.unit_field(b'ActiveState',b's') in (b'active',b'deactivating'),
        'pin_active_changed')
  else:
   need(self.unit_field(b'ActiveState',b's')==b'inactive' and
        self.service_result()==b'success','pin_terminal_not_success')
 def destroy(self):
  if hasattr(self,'socket'):self.socket.close()
  if hasattr(self,'peerfd'):os.close(self.peerfd)
  if self.bus:self.close(self.bus);self.bus=None

def private_socket():
 need(os.geteuid()==0 and not RUN.exists(),'run_path_preexists')
 RUN.mkdir(mode=0o700)
 s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET|socket.SOCK_CLOEXEC)
 s.bind(str(SOCK));os.chmod(SOCK,0o600);s.listen(4);s.setblocking(False)
 return s

def send_request(value,deadline=3):
 data=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
 need(len(data)<=4096,'request_length')
 s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET|socket.SOCK_CLOEXEC)
 s.settimeout(deadline)
 try:
  s.connect(str(SOCK));s.sendall(data);raw=s.recv(4097)
  need(0<len(raw)<=4096,'response_length')
  return json.loads(raw)
 finally:s.close()


def source_regular(path,maximum):
 for parent in reversed(path.parents):
  if parent==Path('/'):continue
  ps=parent.lstat()
  need(stat.S_ISDIR(ps.st_mode) and ps.st_uid==ps.st_gid==0 and
       not ps.st_mode&0o022,'source_parent_untrusted')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);named=path.lstat()
  need(stat.S_ISREG(a.st_mode) and a.st_uid==a.st_gid==0 and
       stat.S_IMODE(a.st_mode)==0o600 and a.st_nlink==1 and
       0<a.st_size<=maximum and
       (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==
       (named.st_dev,named.st_ino,named.st_size,named.st_mtime_ns,named.st_ctime_ns),
       'source_record_metadata')
  raw=os.read(fd,maximum+1);b=os.fstat(fd)
  need(len(raw)==a.st_size and
       (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==
       (b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns),
       'source_record_changed')
  return raw
 finally:os.close(fd)

def runtime_write(name,row):
 need(name in('a.json','b.json'),'runtime_name')
 body=json.dumps(row,sort_keys=True,separators=(',',':')).encode()
 need(len(body)<=2048,'runtime_size')
 fd=os.open(RUN/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:need(os.write(fd,body)==len(body),'runtime_short_write');os.fsync(fd)
 finally:os.close(fd)
 dfd=os.open(RUN,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(dfd)
 finally:os.close(dfd)
 return hashlib.sha256(body).hexdigest()


def runtime_read(name,keys):
 fd=os.open(RUN/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);need(stat.S_ISREG(st.st_mode)and st.st_uid==st.st_gid==0 and
                       stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1 and 0<st.st_size<=2048,
                       'runtime_metadata')
  raw=os.read(fd,2049);need(len(raw)==st.st_size,'runtime_short')
  return exact_json(raw,keys),hashlib.sha256(raw).hexdigest()
 finally:os.close(fd)

def pending_final(config, *, optional=False):
 active=[]
 for action in UNIT:
  facts=final_unit(action,config)
  raw=facts['Job'].strip()
  match=re.fullmatch(r'([1-9][0-9]*)(?:\s+(/org/freedesktop/systemd1/job/([1-9][0-9]*)))?',raw)
  if match:
   need(match[3] is None or match[1]==match[3],'pid1_job_path')
   active.append((action,int(match[1])))
  else:need(raw in('','0'),'pid1_job_rendering')
 if not active and optional:return None
 need(len(active)==1,'pending_final_job_not_unique')
 return active[0]


def activation(config, unit):
 need(PRIVATE_UNIT.fullmatch(unit),'activation_unit')
 raw=source_regular(RUN/('activation-'+unit[11:75]+'.json'),4096)
 value=exact_json(raw,('schema','boot_id','unit','nonce','stage_path',
  'stage_dev','stage_ino','terminal_sha256','installed_generation_sha256',
  'installed_manifest_sha256','active_generation_sha256',
  'active_report_sha256','boot_snapshot_sha256','source_sha256'))
 need(value['schema']=='aegis_auto_terminal_activation_v1' and
      value['boot_id']==boot_id() and value['unit']==unit and
      type(value['nonce']) is str and re.fullmatch(r'[0-9a-f]{32}',value['nonce']) and
      value['source_sha256']==sha(SOURCE_CONFIG) and
      type(value['stage_path']) is str and
      Path(value['stage_path']).parent==Path('/run/aegis-installer-config-snapshots') and
      '..' not in Path(value['stage_path']).parts and
      type(value['stage_dev']) is int and value['stage_dev']>0 and
      type(value['stage_ino']) is int and value['stage_ino']>0 and
      all(type(value[k]) is str and HEX64.fullmatch(value[k])for k in
          ('terminal_sha256','installed_generation_sha256',
           'installed_manifest_sha256','active_generation_sha256',
           'active_report_sha256','boot_snapshot_sha256')),
      'activation_invalid')
 stage=Path(value['stage_path']);st=stage.lstat()
 need(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and
      (st.st_dev,st.st_ino)==(value['stage_dev'],value['stage_ino']) and
      sha(stage/'receipts/activation-owner/terminal.json')==value['terminal_sha256'],
      'activation_stage_changed')
 active_raw=source_regular(Path('/var/lib/aegis-auto/control/generation.json'),139264)
 need(hashlib.sha256(active_raw).hexdigest()==value['active_generation_sha256'],
      'activation_generation_changed')
 active=json.loads(active_raw,object_pairs_hook=unique_pairs)
 need(type(active) is dict and active['schema']=='aegis_auto_v2_generation_v1' and
      active['report_sha256']==value['active_report_sha256'] and
      active['boot_snapshot_sha256']==value['boot_snapshot_sha256'] and
      active['report']['terminal']['start_terminal_sha256']==value['terminal_sha256'] and
      active['report']['terminal']['private_unit']==unit,
      'activation_generation_mismatch')
 snapshot=Path('/var/lib/aegis-auto/control/boot-snapshots')/(
  'snapshot-'+value['boot_snapshot_sha256']+'.json')
 need(sha(snapshot)==value['boot_snapshot_sha256'],'activation_snapshot_changed')
 return value,hashlib.sha256(raw).hexdigest()

def mark_a():
 need(os.geteuid()==0 and len(sys.argv)==3 and
      re.fullmatch(r'[0-9a-f]{64}',sys.argv[2]) is not None,'mark_a_args')
 config=source_config();unit='aegis-auto@'+sys.argv[2]+'.service'
 act,act_sha=activation(config,unit)
 pending=pending_final(config,optional=True)
 if pending is None:
  need(not any((RUN/name).exists() or (RUN/name).is_symlink()
               for name in ('a.json','clean-stop.json','b.json')),
       'administrative_stop_stale_terminal')
  return
 action,job=pending
 q=subprocess.run(['/usr/bin/systemctl','show',unit,'-p','ActiveState',
                   '-p','MainPID','-p','ControlPID','-p','InvocationID',
                   '-p','ControlGroup'],capture_output=True,timeout=3)
 need(q.returncode==0 and not q.stderr and len(q.stdout)<=4096,
      'private_unit_facts_unavailable')
 facts={}
 for line in q.stdout.decode('ascii','strict').splitlines():
  key,sep,value=line.partition('=');need(sep and key not in facts,'private_unit_facts_invalid');facts[key]=value
 need(set(facts)=={'ActiveState','MainPID','ControlPID','InvocationID','ControlGroup'} and
      facts['ActiveState']=='active' and facts['ControlPID']=='0' and
      facts['ControlGroup']=='/system.slice/'+unit and
      re.fullmatch(r'[0-9a-f]{32}',facts['InvocationID']) and
      facts['MainPID'].isdigit() and int(facts['MainPID'])>1,
      'private_unit_not_active')
 value=dict(schema='aegis_auto_terminal_a_v1',boot_id=boot_id(),
            unit=unit,invocation_id=facts['InvocationID'],nonce=act['nonce'],
            action=action,final_job=job,pid1_tick=pid1_facts()['start_tick'],
            source_sha256=sha(SOURCE_CONFIG),activation_sha256=act_sha,
            stage_dev=act['stage_dev'],stage_ino=act['stage_ino'],
            terminal_sha256=act['terminal_sha256'],
            installed_generation_sha256=act['installed_generation_sha256'],
            installed_manifest_sha256=act['installed_manifest_sha256'],
            active_generation_sha256=act['active_generation_sha256'],
            active_report_sha256=act['active_report_sha256'],
            boot_snapshot_sha256=act['boot_snapshot_sha256'])
 digest=runtime_write('a.json',value)
 need(sha(SOURCE_CONFIG)==value['source_sha256'],'source_changed')
 print(json.dumps(dict(a_sha256=digest,action=action,final_job=job),sort_keys=True))


def mark_private():
 # The installed guardian alone publishes clean-stop.json from ExecStop.
 # This command is not exposed by any installed unit.
 raise RuntimeError('private_stop_must_be_guardian_authenticated')


def live_observer_facts():
 unit='aegis-auto-terminal-observer.service'
 q=subprocess.run(['/usr/bin/systemctl','show',unit,'--no-pager',
                   '-p','Id','-p','LoadState','-p','UnitFileState',
                   '-p','FragmentPath','-p','DropInPaths',
                   '-p','NeedDaemonReload','-p','ActiveState','-p','SubState',
                   '-p','MainPID','-p','ControlPID','-p','ControlGroup',
                   '-p','InvocationID'],capture_output=True,timeout=3,
                  check=False,env={'PATH':'/usr/sbin:/usr/bin','LANG':'C','LC_ALL':'C'})
 need(q.returncode==0 and not q.stderr and len(q.stdout)<=4096,
      'observer_pid1_unavailable')
 rows={}
 for line in q.stdout.decode('ascii','strict').splitlines():
  key,sep,value=line.partition('=')
  need(sep and key not in rows,'observer_pid1_invalid')
  rows[key]=value
 pid_text=rows.get('MainPID','')
 need(set(rows)=={'Id','LoadState','UnitFileState','FragmentPath',
                  'DropInPaths','NeedDaemonReload',
                  'ActiveState','SubState','MainPID','ControlPID','ControlGroup',
                  'InvocationID'} and
      rows['Id']==unit and rows['LoadState']=='loaded' and
      rows['UnitFileState']=='disabled' and
      rows['FragmentPath']=='/etc/systemd/system/'+unit and
      rows['DropInPaths']=='' and rows['NeedDaemonReload']=='no' and
      rows['ActiveState']=='active' and rows['SubState']=='running' and
      pid_text.isascii() and pid_text.isdecimal() and int(pid_text)>1 and
      rows['ControlPID']=='0' and
      rows['ControlGroup']=='/system.slice/'+unit and
      type(rows['InvocationID'])is str and
      re.fullmatch(r'[0-9a-f]{32}',rows['InvocationID']),
      'observer_pid1_changed')
 pid=int(pid_text);proc=Path('/proc')/pid_text
 need((proc/'cgroup').read_text(encoding='ascii')==
      '0::/system.slice/'+unit+'\n' and
      (proc/'cmdline').read_bytes()==
      b'/usr/bin/python3\0-I\0-B\0'+
      b'/usr/local/lib/aegis/helpers/lib/aegis_auto_terminal_witness.py\0observer\0' and
      os.path.samefile(proc/'exe','/usr/bin/python3') and
      any(line.split()==['Uid:','0','0','0','0']
          for line in (proc/'status').read_text(encoding='ascii').splitlines()),
      'observer_process_changed')
 start_tick=proc_parent(pid)[1]
 need(0<start_tick<1<<64,'observer_process_generation')
 return dict(observer_pid=pid,observer_start_tick=start_tick,
             observer_invocation_id=rows['InvocationID'],
             observer_source_sha256=sha(Path(__file__)),
             source_config_sha256=sha(SOURCE_CONFIG))


def observer():
 need(os.geteuid()==0 and os.getpid()!=1,'root_not_pid1')
 signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGTERM})
 if os.environ.get('AEGIS_QA_FIFO')=='1':
  cpus=sorted(os.sched_getaffinity(0));need(len(cpus)>=2,'fifo_requires_two_cpus')
  os.sched_setaffinity(0,set(cpus[:2]))
  os.sched_setscheduler(0,os.SCHED_FIFO,os.sched_param(90))
  need(os.sched_getscheduler(0)==os.SCHED_FIFO and
       os.sched_getparam(0).sched_priority==90,'fifo_not_active')
 need(hasattr(os,'pidfd_open')and hasattr(signal,'pidfd_send_signal'),'pidfd_unavailable')
 pidfd=os.pidfd_open(1,0)
 signal.pidfd_send_signal(pidfd,0,None,0)
 source=source_config()
 original=pid1_facts()
 boot=boot_id();listen=private_socket();nl,expected_ack=connector()
 state=dict(boot=boot,pid1_tick=original['start_tick'],ack=False,b=None,private_stop=None,pin=None,
            done=[],exec=None,refusal=None,seen_by_cpu={},bus_eof=False,
            ready_published=False,retiring=False)
 def record(job,path,unit,result):
  need(re.fullmatch(r'/org/freedesktop/systemd1/job/[0-9]+',path) is not None,'job_path')
  private=state['private_stop'];final=state['b']
  relevant_private=(private is not None and
    (job==private['job'] or path==private['path'] or unit==private['unit']))
  relevant_final=(final is not None and
    (job==final['final_job'] or path==final['final_path'] or
     unit==UNIT[final['action']]))
  if not relevant_private and not relevant_final:return
  if relevant_private:
   need((job,path,unit)==(private['job'],private['path'],private['unit']),
        'private_stop_job_replaced')
  if relevant_final:
   need((job,path,unit)==(final['final_job'],final['final_path'],
                         UNIT[final['action']]),'final_job_replaced')
  need(len(state['done'])<8,'job_event_bound')
  state['done'].append((job,path,unit,result))
 bus=DirectBus(record)
 def publish_ready():
  if state['ready_published'] or not ready_witness(state,bus):return
  signal.pidfd_send_signal(pidfd,0,None,0)
  current=pid1_facts()
  need(current['start_tick']==original['start_tick'] and
       current['exe']==original['exe'],'ready_pid1_changed')
  own=live_observer_facts()
  need(own['observer_pid']==os.getpid() and
       own['observer_source_sha256']==source['witness_sha256'],
       'ready_observer_identity_changed')
  body=dict(schema='aegis_auto_terminal_witness_ready_v2',boot=boot,
            pid1_tick=original['start_tick'],pid1_private_bus_peer=1,
            pid1_private_bus_ready=True,job_removed_match_registered=True,
            kernel_connector_ack=True,**own)
  raw=json.dumps(body,sort_keys=True,separators=(',',':')).encode()
  temporary=RUN/'ready.json.tmp'
  fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
  try:need(os.write(fd,raw)==len(raw),'ready_short_write');os.fsync(fd)
  finally:os.close(fd)
  dfd=os.open(RUN,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   rename=C.CDLL(None,use_errno=True).renameat2
   rename.argtypes=[C.c_int,C.c_char_p,C.c_int,C.c_char_p,C.c_uint]
   rename.restype=C.c_int
   need(rename(dfd,b'ready.json.tmp',dfd,b'ready.json',1)==0,
        'ready_publication_collision')
   os.fsync(dfd)
  finally:os.close(dfd)
  state['ready_published']=True
 sel=selectors.DefaultSelector();sel.register(nl,selectors.EVENT_READ,'nl')
 sel.register(bus.socket_fd,selectors.EVENT_READ,'bus');sel.register(listen,selectors.EVENT_READ,'sock')
 bus_pending=False
 def drain_bus():
  nonlocal bus_pending
  if state['bus_eof']:return
  try:
   eof,bus_pending=bus.drain()
   if eof:
    state['bus_eof']=True
    sel.unregister(bus.socket_fd)
  except BaseException as exc:
   bus_pending=False
   first_failure(state,'bus',exc)
 try:
  while True:
   selected=sel.select(.01 if bus_pending else 1)
   bus_polled=False
   for key,_ in selected:
    if key.data=='bus':
     drain_bus();bus_polled=True
    elif key.data=='nl':
     try:
      raw,anc,flags,addr=nl.recvmsg(8192,256)
      row=check_nl_packet(raw,addr,anc,netlink_truncated(flags))
      if record_connector_wire(state,row,expected_ack):
       signal.pidfd_send_signal(pidfd,0,None,0)
       facts=pid1_facts(require_action=True)
       need(facts['start_tick']==state['pid1_tick'] and facts['exe']==SYSTEMD_SHUTDOWN and
            facts['action']in UNIT and state['exec'] is None,'pid1_exec_identity')
       state['exec']=dict(action=facts['action'],seq=row['seq'],cpu=row['cpu'])
     except BaseException as exc:first_failure(state,'connector',exc)
    elif key.data=='sock':
     connection,_=listen.accept();connection.settimeout(2)
     try:
      pid,uid,gid=struct.unpack('=iii',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
      need(uid==0 and gid==0 and pid>1,'socket_peer')
      request=json.loads(connection.recv(4097));need(type(request)is dict and len(json.dumps(request))<=4096,'request')
      if request.get('op')=='bind-private':
       need(state['ready_published'] and state['b'] is None and
            state['private_stop'] is None and state['exec'] is None and
            set(request)=={'op','boot','unit','nonce','job','path','invocation_id'} and
            request['boot']==boot and type(request['unit']) is str and
            PRIVATE_UNIT.fullmatch(request['unit']) and
            type(request['nonce']) is str and re.fullmatch('[0-9a-f]{32}',request['nonce']) and
            type(request['invocation_id']) is str and re.fullmatch('[0-9a-f]{32}',request['invocation_id']) and
            type(request['job']) is int and 0<request['job']<2**32 and
            request['path']=='/org/freedesktop/systemd1/job/'+str(request['job']),
            'private_stop_job_request_invalid')
       need(bus.exact_job(request['job'],request['path'],request['unit'],'stop')=='stop',
            'private_stop_job_type_changed')
       pin=SystemUnitPin(request['unit'],request['invocation_id'])
       state['pin']=pin;state['private_stop']=request
       answer={'bound_private':True}
      elif request.get('op')=='bind':
       need(state['ready_published'] and state['b'] is None and state['exec'] is None,'bind_state')
       final_unit(request['action'],source)
       need(set(request)=={'op','boot','action','final_job','final_path','b_sha256','nonce','private_unit','private_stop_job'} and
            request['boot']==boot and request['action']in UNIT and
            type(request['final_job'])is int and 0<request['final_job']<2**32 and
            request['final_path']=='/org/freedesktop/systemd1/job/'+str(request['final_job']) and
            type(request['b_sha256'])is str and HEX64.fullmatch(request['b_sha256']) and
            type(request['nonce'])is str and re.fullmatch('[0-9a-f]{32}',request['nonce']),'bind_schema')
       job_type=bus.exact_job(request['final_job'],request['final_path'],UNIT[request['action']])
       private=state['private_stop']
       need(private is not None and private['boot']==boot and
            private['nonce']==request['nonce'] and
            private['unit']==request['private_unit'] and
            private['job']==request['private_stop_job'] and
            positive_job_done(state['done'],
              (private['job'],private['path'],private['unit'],'done')),
            'private_stop_job_not_done')
       pin=state['pin'];need(pin is not None,'private_unit_pin_missing')
       pin.revalidate(active=False)
       state['b']=request;state['final_job_type']=job_type
       answer={'bound':True,'private_result':'success','unit_path':pin.path.decode('ascii')}
      elif request.get('op')=='retire':
       # Source-qualified same-boot package rotation asks the infrastructure
       # witness to exit normally. No terminal proof or network grant follows.
       need(set(request)=={'op','boot','unit','pending_sha256','old_source_sha256'} and
            request['boot']==boot and type(request['unit'])is str and
            PRIVATE_UNIT.fullmatch(request['unit']) and
            type(request['pending_sha256'])is str and
            HEX64.fullmatch(request['pending_sha256']) and
            request['old_source_sha256']==sha(SOURCE_CONFIG) and
            state['ready_published'] and state['refusal'] is None and
            state['private_stop'] is None and state['b'] is None and
            state['exec'] is None and state['pin'] is None and
            pending_final(source,optional=True) is None,
            'retire_state_unqualified')
       pending_path=Path('/var/lib/aegis-install/client/terminal-migrations/pending.json')
       pending_raw=source_regular(pending_path,4096)
       pending=json.loads(pending_raw,object_pairs_hook=unique_pairs)
       need(hashlib.sha256(pending_raw).hexdigest()==request['pending_sha256'] and
            pending.get('schema')=='aegis_auto_terminal_migration_pending_v1' and
            pending.get('unit')==request['unit'] and
            pending.get('old_source_sha256')==request['old_source_sha256'] and
            pending.get('boot_id')==boot,
            'retire_pending_changed')
       q=subprocess.run(['/usr/bin/systemctl','show',request['unit'],
                         '-p','ActiveState','-p','SubState','-p','MainPID',
                         '-p','ControlPID','--no-pager'],capture_output=True,
                         timeout=3,check=False)
       need(q.returncode==0 and not q.stderr and len(q.stdout)<=4096 and
            set(q.stdout.decode('ascii','strict').splitlines())==
            {'ActiveState=inactive','SubState=dead','MainPID=0','ControlPID=0'},
            'retire_private_not_stopped')
       answer={'retiring':True,'pending_sha256':request['pending_sha256']}
       state['retiring']=True
      elif request.get('op')=='late':
       need(set(request)=={'op','boot','action','nonce'} and state['b'] is not None and
            request['boot']==boot and request['action']==state['b']['action'] and
            request['nonce']==state['b']['nonce'],'late_schema')
       b=state['b'];expected=(b['final_job'],b['final_path'],UNIT[b['action']],'done')
       signal.pidfd_send_signal(pidfd,0,None,0)
       passed=(state['refusal'] is None and state['ready_published'] and state['bus_eof'] and state['exec'] is not None and
               state['exec']['action']==b['action'] and positive_job_done(state['done'],expected))
       answer=dict(proven=bool(passed),boot=boot,action=b['action'],b_sha256=b['b_sha256'],
                   final_job=b['final_job'],final_job_type=state['final_job_type'],
                   positive_done_count=state['done'].count(expected),
                   pid1_exec=state['exec'] is not None,refusal=state['refusal'])
      else:raise RuntimeError('operation')
      connection.sendall(json.dumps(answer,sort_keys=True).encode())
     except BaseException as exc:
      first_failure(state,'socket',exc)
      try:connection.sendall(b'{"proven":false}')
      except OSError:pass
     finally:connection.close()
   if state['retiring']:
    break
   if bus_pending and not bus_polled:drain_bus()
   try:publish_ready()
   except BaseException as exc:first_failure(state,'ready',exc)
 finally:
  if state['pin'] is not None:state['pin'].destroy()
  bus.destroy();nl.close();listen.close();os.close(pidfd)

def bind():
 need(os.geteuid()==0 and len(sys.argv)==3 and
      re.fullmatch(r'[0-9a-f]{64}',sys.argv[2]) is not None,'bind_argv')
 config=source_config();unit='aegis-auto@'+sys.argv[2]+'.service'
 pending=pending_final(config,optional=True)
 if pending is None:
  need(not any((RUN/name).exists() or (RUN/name).is_symlink()
               for name in ('a.json','clean-stop.json','b.json')),
       'administrative_stop_stale_terminal')
  return
 a,a_sha=runtime_read('a.json',('schema','boot_id','unit','invocation_id','nonce',
                                'action','final_job','pid1_tick','source_sha256','activation_sha256',
                                'stage_dev','stage_ino','terminal_sha256',
                                'installed_generation_sha256','installed_manifest_sha256',
                                'active_generation_sha256','active_report_sha256',
                                'boot_snapshot_sha256'))
 clean,clean_sha=runtime_read('clean-stop.json',
  ('schema','boot_id','unit','invocation_id','nonce','action','final_job',
   'a_sha256','intent_sha256','policy_sha256','private_stop_job','private_stop_path',
   'activation_sha256','terminal_sha256','stage_dev','stage_ino',
   'installed_generation_sha256','installed_manifest_sha256'))
 need(a['schema']=='aegis_auto_terminal_a_v1' and
      clean['schema']=='aegis_auto_terminal_clean_stop_v1' and
      a['boot_id']==clean['boot_id']==boot_id() and
      a['unit']==clean['unit']==unit and
      a['invocation_id']==clean['invocation_id'] and
      a['nonce']==clean['nonce']==activation(config,unit)[0]['nonce'] and
      a['action']==clean['action'] and a['final_job']==clean['final_job'] and
      clean['a_sha256']==a_sha and a['pid1_tick']==pid1_facts()['start_tick'] and
      a['source_sha256']==sha(SOURCE_CONFIG) and
      a['activation_sha256']==activation(config,unit)[1] and
      clean['activation_sha256']==a['activation_sha256'] and
      clean['terminal_sha256']==a['terminal_sha256'] and
      clean['stage_dev']==a['stage_dev'] and clean['stage_ino']==a['stage_ino'] and
      clean['installed_generation_sha256']==a['installed_generation_sha256'] and
      clean['installed_manifest_sha256']==a['installed_manifest_sha256'],
      'bind_a_clean_mismatch')
 intent_raw=source_regular(STOP_INTENT,4096)
 need(hashlib.sha256(intent_raw).hexdigest()==clean['intent_sha256'] and
      exact_json(intent_raw,('schema','boot_id','invocation_id','service','phase'))==
      {'schema':'aegis_auto_stop_intent_v1','boot_id':boot_id(),
       'invocation_id':a['invocation_id'],'service':unit,'phase':'deny_proven'},
      'bind_stop_intent_changed')
 action,job=pending
 need((action,job)==(a['action'],a['final_job']),'bind_job_changed')
 row=dict(schema='aegis_auto_terminal_b_v1',boot_id=a['boot_id'],
          unit=unit,invocation_id=a['invocation_id'],nonce=a['nonce'],
          action=action,final_job=job,a_sha256=a_sha,
          clean_stop_sha256=clean_sha,intent_sha256=clean['intent_sha256'],
          policy_sha256=clean['policy_sha256'],
          private_stop_job=clean['private_stop_job'])
 b_sha=runtime_write('b.json',row)
 answer=send_request(dict(op='bind',boot=boot_id(),action=action,nonce=a['nonce'],
                          b_sha256=b_sha,final_job=job,private_unit=unit,
                          private_stop_job=clean['private_stop_job'],final_path='/org/freedesktop/systemd1/job/'+str(job)))
 expected_unit_path='/org/freedesktop/systemd1/unit/'+''.join(
  c if c.isascii() and c.isalnum() else '_'+format(ord(c),'02x') for c in unit)
 need(answer=={'bound':True,'private_result':'success',
               'unit_path':expected_unit_path},'observer_bind_refused')
 print(json.dumps(dict(bound=True,final_job=job,boot=a['boot_id'],b_sha256=b_sha),sort_keys=True))


def late():
 need(os.geteuid()==0 and len(sys.argv)==3,'late_caller')
 _,_,action=sys.argv
 config=source_config()
 need(action in UNIT,'late_args')
 chain=late_ancestor_chain()
 facts=pid1_facts(require_action=True)
 need(facts['exe']==SYSTEMD_SHUTDOWN and facts['action']==action,'late_pid1_exe_action')
 a,a_sha=runtime_read('a.json',('schema','boot_id','unit','invocation_id','nonce',
                                'action','final_job','pid1_tick','source_sha256','activation_sha256',
                                'stage_dev','stage_ino','terminal_sha256',
                                'installed_generation_sha256','installed_manifest_sha256',
                                'active_generation_sha256','active_report_sha256',
                                'boot_snapshot_sha256'))
 clean,clean_sha=runtime_read('clean-stop.json',
  ('schema','boot_id','unit','invocation_id','nonce','action','final_job',
   'a_sha256','intent_sha256','policy_sha256','private_stop_job','private_stop_path',
   'activation_sha256','terminal_sha256','stage_dev','stage_ino',
   'installed_generation_sha256','installed_manifest_sha256'))
 b,b_sha=runtime_read('b.json',('schema','boot_id','unit','invocation_id','nonce',
  'action','final_job','a_sha256','clean_stop_sha256','intent_sha256','policy_sha256','private_stop_job'))
 need(a['schema']=='aegis_auto_terminal_a_v1' and
      clean['schema']=='aegis_auto_terminal_clean_stop_v1' and
      b['schema']=='aegis_auto_terminal_b_v1' and
      a['boot_id']==clean['boot_id']==b['boot_id']==boot_id() and
      a['unit']==clean['unit']==b['unit'] and PRIVATE_UNIT.fullmatch(a['unit']) and
      a['invocation_id']==clean['invocation_id']==b['invocation_id'] and
      a['nonce']==clean['nonce']==b['nonce']==activation(config,a['unit'])[0]['nonce'] and
      a['action']==clean['action']==b['action']==action and
      a['final_job']==clean['final_job']==b['final_job'] and
      a['pid1_tick']==facts['start_tick'] and
      clean['a_sha256']==b['a_sha256']==a_sha and
      b['clean_stop_sha256']==clean_sha and
      b['intent_sha256']==clean['intent_sha256'] and
      b['policy_sha256']==clean['policy_sha256'] and
      b['private_stop_job']==clean['private_stop_job'],
      'late_runtime_chain_invalid')
 intent_raw=source_regular(STOP_INTENT,4096)
 need(hashlib.sha256(intent_raw).hexdigest()==clean['intent_sha256'],
      'late_stop_intent_changed')
 answer=send_request(dict(op='late',boot=boot_id(),action=action,nonce=a['nonce']),deadline=5)
 need(set(answer)=={'proven','boot','action','b_sha256','final_job',
      'final_job_type','positive_done_count','pid1_exec','refusal'} and
      answer['proven'] is True and answer['boot']==boot_id() and
      answer['action']==action and answer['b_sha256']==b_sha and
      answer['final_job']==b['final_job'] and answer['final_job_type']=='start' and
      answer['positive_done_count']==1 and answer['pid1_exec'] is True and
      answer['refusal'] is None,'late_witness_refused')
 record=dict(schema='aegis_auto_terminal_carrier_v1',boot=answer['boot'],
             nonce=a['nonce'],action=action,final_job=answer['final_job'],
             final_job_type=answer['final_job_type'],b_sha256=answer['b_sha256'],
             pid1_tick=facts['start_tick'],ancestor_depth=len(chain),
             witness_sha256=sha(Path(__file__)),a_record=a,
             clean_record=clean,b_record=b,intent_sha256=clean['intent_sha256'])
 digest=durable_store(record)
 print(json.dumps(dict(qualified=True,boot=answer['boot'],action=action,
                       marker_sha256=digest),sort_keys=True))


if __name__=='__main__':
 try:
  need(sys.platform.startswith('linux'),'linux_only')
  if len(sys.argv)==2 and sys.argv[1]=='observer':observer()
  elif len(sys.argv)==3 and sys.argv[1]=='mark-a':mark_a()
  elif len(sys.argv)==3 and sys.argv[1]=='bind':bind()
  elif len(sys.argv)>=2 and sys.argv[1]=='late':late()
  else:raise RuntimeError('usage')
 except BaseException as exc:
  print(json.dumps(dict(qualified=False,refusal=failure_code('command',exc)),sort_keys=True),file=sys.stderr)
  raise SystemExit(2)
