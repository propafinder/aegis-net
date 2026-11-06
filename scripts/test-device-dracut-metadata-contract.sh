#!/usr/bin/env bash
# Executes the exact embedded parser functions and cache validation AST with
# synthetic public ELF/index metadata. No tools, boot files or network run.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
python3 - "$ROOT" <<'PY'
import ast,copy,hashlib,pathlib,re,stat,struct,sys,types
s=(pathlib.Path(sys.argv[1])/'install.sh').read_text()
f=re.search(r'^device_verify_initramfs\(\) \{\n.*?^\}',s,re.M|re.S)[0]
program=f.split("<<'PY'\n",1)[1].rsplit('\nPY',1)[0];tree=ast.parse(program)
names={'need','kbd_source','openssl_activation','elf_identity','decode_index','module_name','alias_key','resolve_archive','canonical','resolved_link','payload','baseline'}
functions=[node for node in ast.walk(tree) if isinstance(node,ast.FunctionDef) and node.name in names]
assert {x.name for x in functions}==names
cache=next(node for node in ast.walk(tree) if isinstance(node,ast.If) and ast.unparse(node.test)=="'etc/ld.so.cache' in entries")
# This is the production binary-to-canonical-oracle equality, not a copy.
comparison=next(node for node in ast.walk(tree) if isinstance(node,ast.For) and ast.unparse(node.iter)=='expected.items()' and any(isinstance(x,ast.Name) and x.id=='decode_index' for x in ast.walk(node)))
ns={'struct':struct,'re':re,'stat':stat,'hashlib':hashlib,'posixpath':__import__('posixpath'),'os':types.SimpleNamespace(uname=lambda:types.SimpleNamespace(machine='x86_64'))}
exec(compile(ast.fix_missing_locations(ast.Module(body=functions,type_ignores=[])),'<production functions>','exec'),ns)
cache_code=compile(ast.fix_missing_locations(ast.Module(body=[cache],type_ignores=[])),'<production cache validation>','exec')
comparison_code=compile(ast.fix_missing_locations(ast.Module(body=[comparison],type_ignores=[])),'<production canonical index equality>','exec')
REG=stat.S_IFREG|0o644;EXE=stat.S_IFREG|0o755;LINK=stat.S_IFLNK|0o777

def elf(soname,machine=62):
    strings=b'\0'+soname.encode()+b'\0';end=240+len(strings)
    ident=b'\x7fELF\x02\x01\x01'+b'\0'*9
    header=struct.pack('<16sHHIQQQIHHHHHH',ident,3,machine,1,0,64,0,0,64,56,2,0,0,0)
    load=struct.pack('<IIQQQQQQ',1,4,0,0,0,end,end,8)
    dynamic=struct.pack('<IIQQQQQQ',2,4,176,176,176,64,64,8)
    values=b''.join(struct.pack('<qQ',tag,value) for tag,value in [(5,240),(10,len(strings)),(14,1),(0,0)])
    return header+load+dynamic+values+strings

def index(mapping):
    root={'children':{},'values':[]}
    for key,values in mapping.items():
        node=root
        for c in key:node=node['children'].setdefault(c,{'children':{},'values':[]})
        node['values']=values
    out=bytearray(struct.pack('>III',0xb007f457,0x20001,0))
    def write(node):
        children={ord(c):write(n) for c,n in node['children'].items()};offset=len(out);flags=0
        if children:
            flags|=0x20000000;first,last=min(children),max(children);out.extend(bytes((first,last)))
            out.extend(b''.join(struct.pack('>I',children.get(c,0)) for c in range(first,last+1)))
        if node['values']:
            flags|=0x40000000;out.extend(struct.pack('>I',len(node['values'])))
            for priority,value in node['values']:out.extend(struct.pack('>I',priority)+value.encode()+b'\0')
        # Empty index uses a zero root, matching kmod's null pointer encoding.
        if not flags:return 0
        return offset|flags
    ptr=write(root);struct.pack_into('>I',out,8,ptr);return bytes(out)

def loader(rows,extension=False):
    strings=bytearray();encoded=[];start=48+24*len(rows)
    for soname,path in rows:
        key=start+len(strings);strings.extend(soname.encode()+b'\0')
        value=start+len(strings);strings.extend(path.encode()+b'\0')
        encoded.append(struct.pack('<iIIIQ',0x303,key,value,0,0))
    header=b'glibc-ld.so.cache1.1'+struct.pack('<IIB3xI3I',len(rows),len(strings),2,0,0,0,0)
    out=bytearray(header+b''.join(encoded)+strings)
    if extension:
        out.extend(b'\0'*((-len(out))%4));offset=len(out);struct.pack_into('<I',out,32,offset)
        message=b'ldconfig (Synthetic glibc 2.34)'
        out.extend(struct.pack('<6I',0xeaa42174,1,0,0,offset+24,len(message))+message)
    return bytes(out)

def record(data,mode=EXE):
    return {'mode':mode,'data':data,'digest':hashlib.sha256(data).hexdigest(),'elf':ns['elf_identity'](data) if data.startswith(b'\x7fELF') else None}
base={
 'usr/lib64/libalpha.so.1.0':record(elf('libalpha.so.1')),
 'usr/lib64/libbeta.so.1.0':record(elf('libbeta.so.1')),
 'usr/lib64/libalpha-alt.so.1.0':record(elf('libalpha.so.1')+b'DIFFERENT VERIFIED CODE'),
 'usr/lib64/libalpha.so.1':record(b'libalpha.so.1.0',LINK),
 'usr/lib64/libbeta.so.1':record(b'libbeta.so.1.0',LINK),
}
count=0

def check(label,fn,ok=False):
    global count
    try:fn()
    except (SystemExit,ValueError,UnicodeError,struct.error):
        assert not ok,label+' unexpectedly refused'
    else:assert ok,label+' unexpectedly accepted'
    count+=1;print('PASS: '+label)

def cache_case(data,changes=None,versions=None):
    entries=copy.deepcopy(base);entries.update(changes or {});entries['etc/ld.so.cache']=record(data,REG)
    ns.update(entries=entries,source_map={},package_versions=versions or {'glibc':{'2.34'}},checked=0,
      rpm_files={'/'+n:(e['digest'],e['mode'],'','glibc') for n,e in entries.items() if stat.S_ISREG(e['mode'])})
    exec(cache_code,ns)

check('canonical cache maps ELF SONAME and alias',lambda:cache_case(loader([('libalpha.so.1','/lib64/libalpha.so.1')])),True)
check('canonical cache accepts metadata-only producer extension',lambda:cache_case(loader([('libalpha.so.1','/usr/lib64/libalpha.so.1')],True)),True)
check('same packaged ELF cannot serve another SONAME',lambda:cache_case(loader([('libbeta.so.1','/lib64/libalpha.so.1')])) )
check('same SONAME cannot redirect canonical alias to alternative packaged code',lambda:cache_case(loader([('libalpha.so.1','/usr/lib64/libalpha-alt.so.1.0')])) )
check('competing cache key refused',lambda:cache_case(loader([('libalpha.so.1','/lib64/libalpha.so.1')]*2)))
check('noncanonical library path refused',lambda:cache_case(loader([('libalpha.so.1','/lib64/../lib64/libalpha.so.1')])))
check('unknown glibc cache policy refused',lambda:cache_case(loader([]),versions={'glibc':{'2.35'}}))
check('cyclic library aliases refused',lambda:cache_case(loader([('libalpha.so.1','/lib64/libalpha.so.1')]),{'usr/lib64/libalpha.so.1':record(b'libalpha.so.1',LINK)}))
check('wrong ELF architecture refused',lambda:cache_case(loader([('libalpha.so.1','/lib64/libalpha.so.1')]),{'usr/lib64/libalpha.so.1.0':record(elf('libalpha.so.1',183))}))
for label,offset,fmt,value in [('wrong cache flags',48,'<I',3),('cache key offset in header',52,'<I',0),('cache value outside file',56,'<I',0xffffffff),('hardware override',64,'<Q',1),('extension offset overlaps table',32,'<I',48)]:
    data=bytearray(loader([('libalpha.so.1','/lib64/libalpha.so.1')]));struct.pack_into(fmt,data,offset,value)
    check(label,lambda data=data:cache_case(bytes(data)))
check('cache trailing data refused',lambda:cache_case(loader([])+b'x'))
check('ELF SONAME parsed from bounded mapped dynamic table',lambda:ns['elf_identity'](elf('libalpha.so.1')),True)
for label,offset,fmt,value in [('ELF program table overflow',32,'<Q',0xffffffffffffffff),('ELF string table unmapped',184,'<Q',0xffffffffffffffff),('ELF duplicate identity entry',208,'<q',5),('ELF dynamic terminator absent',224,'<q',11)]:
    data=bytearray(elf('libalpha.so.1'));struct.pack_into(fmt,data,offset,value)
    check(label,lambda data=data:ns['elf_identity'](bytes(data)))
expected={'a':[(0,'kernel/a.ko:')],'ab':[(1,'kernel/b.ko: kernel/a.ko')]}
check('bounded index reconstructs exact keys and priorities',lambda:ns['need'](ns['decode_index'](index(expected))==expected,'mapping'),True)
check('empty canonical index',lambda:ns['need'](ns['decode_index'](index({}))=={},'empty'),True)
check('unsorted priorities refused',lambda:ns['decode_index'](index({'alias':[(2,'second'),(1,'first')]})))
check('index key depth bounded',lambda:ns['decode_index'](index({'x'*258:[(0,'module')]})))
check('index trailing bytes refused',lambda:ns['decode_index'](index(expected)+b'junk'))
check('truncated index refused',lambda:ns['decode_index'](index(expected)[:-1]))
data=bytearray(index(expected));ptr=struct.unpack_from('>I',data,8)[0];baseoff=ptr&0xfffffff
cycle=bytearray(data);struct.pack_into('>I',cycle,baseoff+2,ptr)
check('index offset cycle refused',lambda:ns['decode_index'](bytes(cycle)))
for label,value in [('index root points into header',0x60000008),('unknown index node flag',ptr|0x10000000),('index root out of range',0x6fffffff)]:
    bad=bytearray(data);struct.pack_into('>I',bad,8,value)
    check(label,lambda bad=bad:ns['decode_index'](bytes(bad)))

def compare(actual,wanted):
    ns.update(module_prefix='usr/lib/modules/fixture/',expected={'modules.alias.bin':wanted},entries={'usr/lib/modules/fixture/modules.alias.bin':record(index(actual),REG)})
    exec(comparison_code,ns)
canonical={'pci:*':[(0,'alpha'),(1,'beta')],'pci:1234*':[(1,'beta')]}
check('binary mapping equals independent canonical oracle',lambda:compare(canonical,canonical),True)
check('different packaged module alias rejected',lambda:compare({'pci:*':[(0,'beta'),(1,'alpha')],'pci:1234*':[(1,'beta')]},canonical))
check('cross-pattern provider priority change rejected',lambda:compare({'pci:*':[(0,'alpha'),(1,'beta')],'pci:1234*':[(0,'beta')]},canonical))
check('extra alias rejected',lambda:compare(dict(canonical,extra=[(0,'alpha')]),canonical))
check('missing alias rejected',lambda:compare({'pci:*':canonical['pci:*']},canonical))
check('kmod alias normalization preserves character range',lambda:ns['need'](ns['alias_key']('test-key[0-9]')=='test_key[0-9]','normalize'),True)
check('unmatched alias bracket refused',lambda:ns['alias_key']('test[0-9'))
main=b'''openssl_conf = openssl_init
[openssl_init]
providers = provider_sect
ssl_conf = ssl_module
alg_section = evp_properties
[provider_sect]
default = default_sect
[default_sect]
activate = 1
.include /etc/pki/tls/openssl.d
[evp_properties]
[ssl_module]
system_default = crypto_policy
[crypto_policy]
.include = /etc/crypto-policies/back-ends/opensslcnf.config
'''
backend=b''.join((key+' = public-fixture-value\n').encode() for key in ('CipherString','Ciphersuites','TLS.MinProtocol','TLS.MaxProtocol','DTLS.MinProtocol','DTLS.MaxProtocol','SignatureAlgorithms','Groups'))
check('OpenSSL activation only builtin default provider and public policy',lambda:ns['openssl_activation'](main,backend),True)
for label,changed in [('custom engine module',main.replace(b'providers =',b'engines = engine_sect\nproviders =')),('custom provider',main.replace(b'default = default_sect',b'custom = default_sect')),('external DSO provider path',main.replace(b'activate = 1',b'activate = 1\nmodule = /custom.so')),('alternate include path',main.replace(b'/etc/pki/tls/openssl.d',b'/tmp/custom')),('duplicate initialization section',main+b'[openssl_init]\n'),('SSL key-loading configuration',main.replace(b'[crypto_policy]',b'[crypto_policy]\nPrivateKey = /secret'))]:
    check(label,lambda changed=changed:ns['openssl_activation'](changed,backend))
check('backend environment expansion rejected',lambda:ns['openssl_activation'](main,backend.replace(b'public-fixture-value',b'$ENV::HOME',1)))
check('backend nested include rejected',lambda:ns['openssl_activation'](main,backend+b'.include = /custom\n'))
def keyboard_case(rows,path='/usr/lib/kbd/keymaps/alias.map'):
    ns['rpm_files']=rows;return ns['kbd_source'](path)
kbdroot='/usr/lib/kbd/keymaps/';kbdfile=('public-digest',REG,'','kbd-legacy');kbdsym=('',LINK,'real.map','kbd-legacy')
check('keyboard alias resolves exact packaged data',lambda:ns['need'](keyboard_case({kbdroot+'alias.map':kbdsym,kbdroot+'real.map':kbdfile})==kbdroot+'real.map','target'),True)
check('keyboard prefix directory alias resolved',lambda:keyboard_case({kbdroot+'old':('',LINK,'new','kbd-legacy'),kbdroot+'new/file.map':kbdfile},kbdroot+'old/file.map'),True)
check('keyboard alias cannot leave data subtree',lambda:keyboard_case({kbdroot+'alias.map':('',LINK,'/usr/bin/public','kbd-legacy'),'/usr/bin/public':kbdfile}))
check('keyboard alias cannot change package authority',lambda:keyboard_case({kbdroot+'alias.map':kbdsym,kbdroot+'real.map':('public-digest',REG,'','other')}))
check('keyboard alias cycle refused',lambda:keyboard_case({kbdroot+'alias.map':('',LINK,'alias.map','kbd-legacy')}))
check('keyboard alias cannot become executable',lambda:keyboard_case({kbdroot+'alias.map':kbdsym,kbdroot+'real.map':('public-digest',EXE,'','kbd-legacy')}))
chain={kbdroot+str(i):('',LINK,str(i+1),'kbd-legacy') for i in range(17)};chain[kbdroot+'17']=kbdfile
check('keyboard alias traversal bounded',lambda:keyboard_case(chain,kbdroot+'0'))
def elf_notes(abi=(0,3,2,0),duplicate=False,truncated=False):
    strings=b'\0libalpha.so.1\0';note=struct.pack('<III',4,16,1)+b'GNU\0'+struct.pack('<IIII',*abi)
    if duplicate:note+=note
    if truncated:note=note[:-1]
    stringoff=296;noteoff=(stringoff+len(strings)+3)&~3;end=noteoff+len(note)
    ident=b'\x7fELF\x02\x01\x01'+b'\0'*9
    header=struct.pack('<16sHHIQQQIHHHHHH',ident,3,62,1,0,64,0,0,64,56,3,0,0,0)
    load=struct.pack('<IIQQQQQQ',1,4,0,0,0,end,end,8)
    dynamic=struct.pack('<IIQQQQQQ',2,4,232,232,232,64,64,8)
    notes=struct.pack('<IIQQQQQQ',4,4,noteoff,noteoff,noteoff,len(note),len(note),4)
    values=b''.join(struct.pack('<qQ',tag,value) for tag,value in [(5,stringoff),(10,len(strings)),(14,1),(0,0)])
    return header+load+dynamic+notes+values+strings+b'\0'*(noteoff-stringoff-len(strings))+note

def abi_cache(version,library):
    data=bytearray(loader([('libalpha.so.1','/lib64/libalpha.so.1')]));struct.pack_into('<I',data,60,version)
    cache_case(data,{'usr/lib64/libalpha.so.1.0':record(library)})
check('cache OS minimum bound to exact ELF GNU ABI tag',lambda:abi_cache(0x30200,elf_notes()),True)
check('cache cannot invent absent ELF ABI tag',lambda:abi_cache(0x30200,elf('libalpha.so.1')))
check('cache cannot omit ELF ABI requirement',lambda:abi_cache(0,elf_notes()))
check('duplicate GNU ABI tags refused',lambda:ns['elf_identity'](elf_notes(duplicate=True)))
check('conflicting foreign OS ABI refused',lambda:ns['elf_identity'](elf_notes(abi=(1,3,2,0))))
check('truncated GNU ABI descriptor refused',lambda:ns['elf_identity'](elf_notes(truncated=True)))
check('ABI components cannot overflow encoded minimum',lambda:ns['elf_identity'](elf_notes(abi=(0,256,2,0))))
print(f'PASS: {count} generated-metadata parser cases; no host files or subprocesses')
PY
