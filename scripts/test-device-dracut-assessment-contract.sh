#!/usr/bin/env bash
# Real production parser; synthetic cpio + an inert RPM metadata query only.
# No initrd extraction, host package DB, boot operation, or network access.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
python3 - "$ROOT" <<'PY'
from pathlib import Path
import gzip,hashlib,json,os,re,stat,subprocess,sys,tempfile
root=Path(sys.argv[1]);source=(root/'install.sh').read_text()
function=re.search(r'^device_verify_initramfs\(\) \{\n.*?^\}',source,re.M|re.S)[0]
program=function.split("<<'PY'\n",1)[1].rsplit('\nPY',1)[0]
REG=stat.S_IFREG|0o644;EXE=stat.S_IFREG|0o755;LINK=stat.S_IFLNK|0o777

def archive(entries,rdev=None,hardlinks=None):
    out=bytearray()
    for i,(name,data,mode) in enumerate(entries+[('TRAILER!!!',b'',REG)]):
        major,minor=(rdev or {}).get(name,(0,0));inode,nlink=(hardlinks or {}).get(name,(i+1,1))
        name=name.encode()+b'\0';fields=[inode,mode,0,0,nlink,0,len(data),0,0,major,minor,len(name),0]
        out+=b'070701'+b''.join(f'{x:08x}'.encode() for x in fields)+name
        out+=b'\0'*((-len(out))%4);out+=data;out+=b'\0'*((-len(out))%4)
    return bytes(out)

with tempfile.TemporaryDirectory(prefix='aegis-dracut-contract-',dir='/tmp') as raw:
    work=Path(raw).resolve();boot=work/'boot';boot.mkdir();db=work/'rpm-db';db.mkdir()
    rpm=work/'rpm';metadata=work/'metadata';calls=work/'calls'
    # Only the external RPM query is represented by a fixture; all package
    # digest, source mapping, activation and archive validators remain real.
    rpm.write_text('#!'+sys.executable+'\nimport pathlib,sys\nassert sys.argv[1:]==["--noplugins","--dbpath",'+repr(str(db))+',"-qa","--qf",'+repr('PACKAGE\t%{NAME}\t%{VERSION}\t%{FILEDIGESTALGO}\n[%{FILENAMES}\t%{FILEDIGESTS}\t%{FILEMODES}\t%{FILELINKTOS}\n]')+']\nprint(pathlib.Path('+repr(str(metadata))+').read_text(),end="")\n')
    rpm.chmod(0o755);cmdline=work/'cmdline';image=boot/'initramfs-fixture.img'
    adapted=re.sub(r'^kernel=.*$',"kernel='fixture'",program,count=1,flags=re.M)
    for old,new in [('/boot/initrd.img-',str(boot)+'/initrd.img-'),('/boot/initramfs-',str(boot)+'/initramfs-'),('/boot/initrd.img',str(work/'missing-default-initrd')),('/initrd.img',str(work/'missing-root-initrd')),('/proc/cmdline',str(cmdline)),('/sys/firmware/ibft',str(work/'missing-ibft')),('/sys/firmware/acpi/tables/NBFT',str(work/'missing-nbft')),('/usr/bin/rpm',str(rpm)),('/usr/lib/sysimage/rpm',str(db)),('/var/lib/rpm',str(work/'missing-rpm-db'))]:
        adapted=adapted.replace("'"+old,"'"+new)
    adapted=adapted.replace('s.st_uid==0',f's.st_uid in (0,{os.getuid()})')
    adapted=adapted.replace('not s.st_mode&0o022',"(not s.st_mode&0o022 or item==pathlib.Path('/private/tmp') or item==pathlib.Path('/tmp'))")
    # Keep the synthetic RPM archive independent of the CI runner's cloud-init
    # and of the runner's PID1 unit list.
    cloud_root=work/'cloud-root';cloud_root.mkdir()
    assert adapted.count('verify_cloud_init_boot({})')==1
    adapted=adapted.replace('verify_cloud_init_boot({})',
        "verify_cloud_init_boot({},root=pathlib.Path("+repr(str(cloud_root))+
        "),read=lambda path,limit=2097152: path.read_bytes(),run=lambda *args: b'')",1)
    files={
      'usr/lib/systemd/systemd':b'SYNTHETIC SYSTEMD EXECUTABLE, NEVER EXECUTED\n',
      'usr/lib/systemd/system/initrd.target':b'[Unit]\nDescription=Synthetic local initrd\n',
      'usr/lib/systemd/system-generators/systemd-fstab-generator':b'SYNTHETIC GENERATOR, NEVER EXECUTED\n',
      'usr/lib/dracut-lib.sh':b'# synthetic packaged dracut library, never executed\n',
    }
    sources={'usr/lib/dracut-lib.sh':'/usr/lib/dracut/modules.d/99base/dracut-lib.sh'}
    entries=[(n,d,REG if n.endswith('.target') else EXE) for n,d in files.items()]+[
      ('init',b'usr/lib/systemd/systemd',LINK),('lib',b'usr/lib',LINK),
      ('etc/systemd/system/default.target',b'/usr/lib/systemd/system/initrd.target',LINK),
      ('usr/lib/dracut/modules.txt',b'bash\nsystemd\nsystemd-initrd\ndr acut\n'.replace(b'dr acut',b'dracut-systemd')+b'base\nrootfs-block\n',REG),
      ('etc/cmdline.d/95root-dev.conf',b'root=UUID=fixture ro\n',REG),
    ]
    def rpm_rows(extra=None,algorithm='8',version='057'):
        rows=['PACKAGE\tdracut\t'+version+'\t'+algorithm]
        for name,data in dict(files,**(extra or {})).items():
            path=sources.get(name,'/'+name)
            rows.append(path+'\t'+hashlib.sha256(data).hexdigest()+'\t'+str(REG if name.endswith(('.target','.service','.conf')) else EXE)+'\t')
        return '\n'.join(rows)+'\n'
    count=0
    def check(label,items=None,ok=False,cmd='root=UUID=fixture ro',meta=None,blob=None,expected=None):
        global count
        image.write_bytes(blob if blob is not None else archive(entries if items is None else items));cmdline.write_text(cmd)
        metadata.write_text(rpm_rows() if meta is None else meta)
        before={str(p.relative_to(work)) for p in work.rglob('*')}
        r=subprocess.run([sys.executable,'-c',adapted,'','',str(root/'scripts/lib')],text=True,capture_output=True,timeout=10)
        assert (r.returncode==0)==ok,(label,r.returncode,r.stdout,r.stderr)
        if expected: assert expected in r.stderr,(label,r.stderr)
        if ok:
            got=json.loads(r.stdout);assert got['boot_profile']=='dracut-057-rpm-local-v1' and got['initramfs_network']=='absent_verified'
            assert got['initrd_sha256']==hashlib.sha256(image.read_bytes()).hexdigest()
            assert 'SYNTHETIC' not in r.stdout
        assert before=={str(p.relative_to(work)) for p in work.rglob('*')},label+' extracted or created a file'
        count+=1;print('PASS: '+label)
    check('RPM local-root profile',ok=True)
    check('gzip local-root profile',blob=gzip.compress(archive(entries)),ok=True)
    check('stock GRUB BOOT_IMAGE is literal data',cmd='BOOT_IMAGE=(hd0,gpt3)/vmlinuz-fixture root=UUID=fixture ro',ok=True)
    check('stock Alma APIC timer flag',cmd='root=UUID=fixture ro no_timer_check',ok=True)
    check('timer flag cannot carry a value',cmd='root=UUID=fixture ro no_timer_check=1')
    check('timer flag cannot admit networking',cmd='root=UUID=fixture ro no_timer_check ip=dhcp')
    check('GRUB syntax cannot extend other parameters',cmd='root=UUID=(fixture) ro')
    device_entries=entries+[('dev/console',b'',stat.S_IFCHR|0o644)]
    check('fixed stock console device',blob=archive(device_entries,{'dev/console':(5,1)}),ok=True)
    check('console different device number',blob=archive(device_entries,{'dev/console':(1,3)}))
    check('unknown early device node',blob=archive(entries+[('dev/custom',b'',stat.S_IFCHR|0o644)],{'dev/custom':(5,1)}))
    empty_index=entries+[('usr/lib/modules/fixture/modules.builtin.alias.bin',b'',REG)]
    kmod_meta=rpm_rows()+'PACKAGE\tkmod\t28\t8\n'
    check('stock empty kmod28 built-in alias result',empty_index,meta=kmod_meta,ok=True)
    check('nonempty built-in alias index refused',entries+[('usr/lib/modules/fixture/modules.builtin.alias.bin',b'not-empty',REG)],meta=kmod_meta)
    check('executable built-in alias index refused',entries+[('usr/lib/modules/fixture/modules.builtin.alias.bin',b'',EXE)],meta=kmod_meta)
    check('linked built-in alias index refused',entries+[('usr/lib/modules/fixture/modules.builtin.alias.bin',b'../../dracut/modules.txt',LINK)],meta=kmod_meta)
    generator='usr/lib/systemd/system-generators/systemd-debug-generator';data=b'PUBLIC STOCK GENERATOR FIXTURE NEVER EXECUTED\n'
    debug_meta=rpm_rows()+'PACKAGE\tsystemd\t252\t8\n/'+generator+'\t'+hashlib.sha256(data).hexdigest()+'\t'+str(EXE)+'\t\n'
    check('stock systemd252 dormant debug generator',entries+[(generator,data,EXE)],meta=debug_meta,ok=True)
    check('debug generator cannot enable early unit',entries+[(generator,data,EXE)],meta=debug_meta,cmd='root=UUID=fixture systemd.wants=custom.service')
    shared=b'PUBLIC LIBRARY FIXTURE NEVER LOADED\n';lib='usr/lib64/libfixture.so.1.0'
    libmeta=rpm_rows()+'/'+lib+'\t'+hashlib.sha256(shared).hexdigest()+'\t'+str(EXE)+'\t\n/usr/lib64/libfixture.so.1\t\t'+str(LINK)+'\tlibfixture.so.1.0\n'
    libentries=entries+[(lib,shared,EXE),('usr/lib64/libfixture.so.1',b'../../lib64/libfixture.so.1.0',LINK)]
    check('usrmerge symlink has same exact RPM endpoint',libentries,meta=libmeta,ok=True)
    check('usrmerge symlink cannot select other packaged endpoint',entries+[(lib,shared,EXE),('usr/lib64/libfixture.so.1',b'../../lib64/libwrong.so.1.0',LINK)],meta=libmeta)
    check('stock generated var lock alias',entries+[('var/lock',b'../run/lock',LINK)],ok=True)
    check('var lock cannot redirect to foreign path',entries+[('var/lock',b'../etc',LINK)])
    check('four fixed stock keyboard aliases',entries+[('usr/share/'+x,('/usr/lib/kbd/'+x).encode(),LINK) for x in ('consolefonts','consoletrans','keymaps','unimaps')],ok=True)
    check('keyboard alias cannot select other directory',entries+[('usr/share/keymaps',b'/usr/lib/kbd/consolefonts',LINK)])
    hook='usr/lib/dracut/hooks/pre-udev/01-fips-load-crypto.sh';hookdata=b'# PUBLIC FIPS HOOK FIXTURE NEVER EXECUTED\n'
    hookmeta=rpm_rows()+'/usr/lib/dracut/modules.d/01fips/fips-load-crypto.sh\t'+hashlib.sha256(hookdata).hexdigest()+'\t'+str(REG)+'\t\n'
    check('inst_hook preserves exact source plus owner executable',entries+[(hook,hookdata,REG|0o100)],meta=hookmeta,ok=True)
    check('inst_hook cannot add group executable',entries+[(hook,hookdata,REG|0o110)],meta=hookmeta)
    os_source=work/'public-os-release';os_source.write_bytes(b'NAME=Fixture\nVERSION="1.0"\nPRETTY_NAME="Fixture 1.0"\nID=fixture\n')
    dracut_source=work/'public-dracut-version';dracut_source.write_bytes(b'DRACUT_VERSION=057-fixture\n')
    adapted=adapted.replace("'/usr/lib/os-release'",repr(str(os_source))).replace("'/usr/lib/dracut/dracut-version.sh'",repr(str(dracut_source)))
    source_meta=rpm_rows()+''.join(str(path)+'\t'+hashlib.sha256(path.read_bytes()).hexdigest()+'\t'+str(REG)+'\t\n' for path in (os_source,dracut_source))
    release=b'NAME=Fixture\nID=fixture\nVERSION="1.0 dracut-057-fixture"\nPRETTY_NAME="Fixture 1.0 dracut-057-fixture (Initramfs)"\nDRACUT_VERSION="057-fixture"\n'
    check('public initrd-release is captured and exact recipe validated',entries+[('usr/lib/initrd-release',release,REG)],meta=source_meta,ok=True)
    check('public initrd-release recipe tampering refused',entries+[('usr/lib/initrd-release',release+b'CUSTOM=1\n',REG)],meta=source_meta)
    emergency='usr/lib/systemd/system/emergency.service';rescue='usr/lib/systemd/system/rescue.service';unitdata=b'[Unit]\nDescription=Public dracut emergency fixture\n'
    unitmeta=rpm_rows()+'/usr/lib/dracut/modules.d/98dracut-systemd/emergency.service\t'+hashlib.sha256(unitdata).hexdigest()+'\t'+str(REG)+'\t\n'
    pair={emergency:(9000,2),rescue:(9000,2)}
    check('stock emergency and rescue hardlinks share checked source',blob=archive(entries+[(emergency,b'',REG),(rescue,unitdata,REG)],hardlinks=pair),meta=unitmeta,ok=True)
    check('conflicting cpio hardlink payloads refused',blob=archive(entries+[(emergency,b'changed',REG),(rescue,unitdata,REG)],hardlinks=pair),meta=unitmeta)
    check('unresolved cpio hardlink refused',blob=archive(entries+[(emergency,b'',REG)],hardlinks=pair),meta=unitmeta)
    actual_link='/usr/lib/modules/fixture/modules.builtin.alias.bin\t\t'+str(LINK)+'\t../../dracut/modules.txt\n'
    check('even packaged index symlink refused',entries+[('usr/lib/modules/fixture/modules.builtin.alias.bin',b'../../dracut/modules.txt',LINK)],meta=kmod_meta+actual_link)
    legacy_libmeta=libmeta.replace('/usr/lib64/','/lib64/')
    check('legacy RPM lib64 canonical path',libentries,meta=legacy_libmeta,ok=True)
    check('unknown dracut version',meta=rpm_rows(version='058'))
    check('non-SHA256 RPM baseline',meta=rpm_rows(algorithm='1'))
    check('changed package bytes',[(n,b'changed' if n=='usr/lib/systemd/systemd' else d,m) for n,d,m in entries])
    check('unknown executable',entries+[('usr/bin/custom',b'private fixture never extracted',EXE)])
    check('custom hook with legitimate copied digest',entries+[('usr/lib/dracut/hooks/pre-udev/01-custom.sh',files['usr/lib/dracut-lib.sh'],EXE)])
    check('modified init symlink',[(n,b'/usr/bin/sh' if n=='init' else d,m) for n,d,m in entries])
    check('unknown unit activation',entries+[('etc/systemd/system/initrd.target.wants/custom.service',b'/usr/lib/systemd/system/custom.service',LINK)])
    check('custom drop-in',entries+[('etc/systemd/system/nm-initrd.service.d/override.conf',b'[Unit]\nConditionPathExists=\n',REG)])
    check('prepopulated neednet sentinel',entries+[('run/NetworkManager/initrd/neednet',b'',REG)])
    check('embedded neednet option',entries+[('etc/cmdline.d/10-network.conf',b'rd.neednet=1\n',REG)])
    check('embedded netroot option',entries+[('etc/cmdline.d/10-network.conf',b'netroot=dhcp\n',REG)])
    check('live bond option',cmd='root=UUID=fixture bond=bond0:eth0')
    check('live unit injection',cmd='root=UUID=fixture systemd.wants=NetworkManager.service')
    check('firmware neednet option',cmd='root=UUID=fixture rd.net.dhcp.retry=3')
    check('custom kernel command syntax',cmd='root=UUID=fixture rootflags=$(command)')
    check('host NetworkManager keyfile',entries+[('etc/NetworkManager/system-connections/host.nmconnection',b'[connection]\nid=SYNTHETIC\n',REG)])
    check('host ifcfg profile',entries+[('etc/sysconfig/network-scripts/ifcfg-eth0',b'BOOTPROTO=dhcp\n',REG)])
    check('usr NetworkManager keyfile',entries+[('usr/lib/NetworkManager/system-connections/default.nmconnection',b'[connection]\n',REG)])
    check('host cryptographic unlock policy',entries+[('etc/crypttab',b'SYNTHETIC SECRET NEVER EXTRACTED',REG)])
    check('unreviewed generated executable policy',entries+[('etc/conf.d/custom.conf',b'custom=1\n',REG)])
    nss={'passwd':['sss','files','systemd'],'shadow':['files'],'group':['sss','files','systemd'],'hosts':['files','dns','myhostname'],'services':['files','sss'],'netgroup':['sss'],'automount':['files','sss'],'aliases':['files'],'ethers':['files'],'gshadow':['files'],'networks':['files','dns'],'protocols':['files'],'publickey':['files'],'rpc':['files']}
    nss_data=b'# Stock generated public policy\n'+b''.join((key+': '+ ' '.join(values)+'\n').encode() for key,values in nss.items())
    check('reviewed NSS provider mapping',entries+[('etc/nsswitch.conf',nss_data,REG)],ok=True)
    check('unreviewed NSS provider',entries+[('etc/nsswitch.conf',nss_data.replace(b'files dns myhostname',b'files custom'),REG)])
    check('duplicate NSS database',entries+[('etc/nsswitch.conf',nss_data+b'hosts: files\n',REG)])
    check('NSS action expression not assumed safe',entries+[('etc/nsswitch.conf',nss_data.replace(b'sss files systemd',b'sss [SUCCESS=return] files systemd'),REG)])
    check('SSSD daemon blocks dormant NSS profile',entries+[('etc/nsswitch.conf',nss_data,REG),('usr/sbin/sssd',b'public fixture',EXE)])
    check('generated NSS cannot become executable',entries+[('etc/nsswitch.conf',nss_data,EXE)])
    check('literal generated locale and console',entries+[('etc/locale.conf',b'LANG="C.UTF-8"\n',REG),('etc/vconsole.conf',b'KEYMAP=us\nFONT="eurlatgr"\n',REG)],ok=True)
    check('generated locale cannot inject environment',entries+[('etc/locale.conf',b'LD_PRELOAD=/usr/lib/evil.so\n',REG)])
    check('generated console shell expression refused',entries+[('etc/vconsole.conf',b'FONT=$(command)\n',REG)])
    check('generated console duplicate assignment refused',entries+[('etc/vconsole.conf',b'FONT=a\nFONT=b\n',REG)])
    check('changed archive executable permission',[(n,d,REG if n=='usr/lib/systemd/systemd' else m) for n,d,m in entries])
    check('writable archive entry',entries+[('etc/hostname',b'fixture\n',stat.S_IFREG|0o666)])
    for label,name,target in [
        ('packaged symlink cannot bypass generator allowlist','usr/lib/systemd/system-generators/custom','../systemd'),
        ('packaged symlink cannot bypass unit allowlist','usr/lib/systemd/system/custom.service','initrd.target'),
        ('packaged symlink cannot bypass network policy','usr/lib/systemd/network/custom.network','../system/initrd.target'),
        ('packaged symlink cannot bypass tmpfiles policy','usr/lib/tmpfiles.d/custom.conf','../systemd/system/initrd.target'),
        ('packaged symlink cannot bypass embedded cmdline parsing','etc/cmdline','../usr/lib/dracut/modules.txt'),
    ]:
        row='/'+name+'\t\t'+str(LINK)+'\t'+target+'\n'
        check(label,entries+[(name,target.encode(),LINK)],meta=rpm_rows()+row)
    check('unknown tmpfiles cannot use even packaged policy',entries+[('usr/lib/tmpfiles.d/custom.conf',b'f /run/NetworkManager/initrd/neednet 0644 root root -\n',REG)],meta=rpm_rows(extra={'usr/lib/tmpfiles.d/custom.conf':b'f /run/NetworkManager/initrd/neednet 0644 root root -\n'}))
    check('duplicate policy',entries+[entries[0]])
    check('truncated cpio',blob=archive(entries)[:-70])
    check('second compressed archive',blob=gzip.compress(archive(entries)+archive([('hidden',b'data',REG)])))
    fixture=root/'scripts/tests/fixtures/dracut-057'
    destinations={'nm-config.sh':'usr/lib/dracut/hooks/cmdline/99-nm-config.sh','nm-run.sh':'usr/lib/dracut/hooks/initqueue/settled/99-nm-run.sh','nm-lib.sh':'usr/lib/nm-lib.sh','nm-initrd.service':'usr/lib/systemd/system/nm-initrd.service','nm-wait-online-initrd.service':'usr/lib/systemd/system/nm-wait-online-initrd.service','initrd-no-auto-default.conf':'usr/lib/NetworkManager/conf.d/initrd-no-auto-default.conf'}
    for leaf,name in destinations.items():
        files[name]=(fixture/leaf).read_bytes();sources[name]='/usr/lib/dracut/modules.d/35network-manager/'+leaf
    nm_entries=[(n,d+b'network-manager\nnetwork\nifcfg\n' if n=='usr/lib/dracut/modules.txt' else d,m) for n,d,m in entries]
    nm_entries += [(name,files[name],EXE if name.endswith('.sh') else REG) for name in destinations.values()]
    nm_entries += [('etc/systemd/system/initrd.target.wants/'+leaf,('/usr/lib/systemd/system/'+leaf).encode(),LINK) for leaf in ('nm-initrd.service','nm-wait-online-initrd.service')]
    check('packaged dormant NM with exact activation guards',nm_entries,ok=True)
    check('dormant NM refuses neednet',nm_entries,cmd='root=UUID=fixture rd.neednet=1')
    check('dormant NM refuses embedded profile',nm_entries+[('etc/NetworkManager/system-connections/keyfile',b'[connection]\n',REG)])
    check('dormant NM refuses archived sentinel',nm_entries+[('run/NetworkManager/initrd/neednet',b'',REG)])
    DIR=stat.S_IFDIR|0o755
    check('stock empty runtime roots remain structural',nm_entries+[(name,b'',DIR) for name in ('run','tmp','var','var/tmp')],ok=True)
    check('directory neednet sentinel refused',nm_entries+[('run/NetworkManager/initrd/neednet',b'',DIR)])
    check('directory connection glob refused',nm_entries+[('run/NetworkManager/system-connections/placeholder',b'',DIR)])
    check('directory sentinel plus connection glob refused',nm_entries+[('run/NetworkManager/initrd/neednet',b'',DIR),('run/NetworkManager/system-connections/placeholder',b'',DIR)])
    check('directory net interfaces sentinel refused',nm_entries+[('tmp/net.ifaces',b'',DIR)])
    check('directory packaged connection glob refused',nm_entries+[('usr/lib/NetworkManager/system-connections/placeholder',b'',DIR)])
    check('directory ifcfg glob refused',nm_entries+[('etc/sysconfig/network-scripts/ifcfg-placeholder',b'',DIR)])
    check('directory var tmp activation state refused',nm_entries+[('var/tmp/net.ifaces',b'',DIR)])
    changed=dict(files);changed[destinations['nm-initrd.service']]+=b'ExecStartPre=/usr/bin/custom\n'
    check('even changed RPM baseline cannot remove semantic guard',[(n,changed[n] if n in changed else d,m) for n,d,m in nm_entries],meta=rpm_rows(extra=changed))
    hidden_modules=[(n,d.replace(b'network-manager\n',b'').replace(b'network\n',b'').replace(b'ifcfg\n',b'') if n=='usr/lib/dracut/modules.txt' else d,m) for n,d,m in nm_entries]
    check('NM footprint refuses omitted module declaration',hidden_modules)
    check('omitted modules cannot bypass edited RPM activation guard',[(n,changed[n] if n in changed else d,m) for n,d,m in hidden_modules],meta=rpm_rows(extra=changed))
    check('missing NM no-auto-default guard',[(n,d,m) for n,d,m in nm_entries if n!=destinations['initrd-no-auto-default.conf']])
    # Public generic-cloud hooks are data, never sourced or executed.
    cloud_paths={
      'usr/lib/udev/sas_transport_scan_lun.sh':'95lunmask/sas_transport_scan_lun.sh',
      'usr/lib/udev/fc_transport_scan_lun.sh':'95lunmask/fc_transport_scan_lun.sh',
      'usr/sbin/crypt-run-generator':'90crypt/crypt-run-generator.sh',
      'usr/lib/dracut/hooks/pre-trigger/01-load-modsign-keys.sh':'03modsign/load-modsign-keys.sh',
      'usr/lib/dracut-crypt-lib.sh':'90crypt/crypt-lib.sh',
      'usr/lib/dracut/hooks/cmdline/30-parse-crypt.sh':'90crypt/parse-crypt.sh',
      'usr/lib/dracut/hooks/pre-udev/30-dm-pre-udev.sh':'90dm/dm-pre-udev.sh',
      'usr/lib/dracut/hooks/shutdown/25-dm-shutdown.sh':'90dm/dm-shutdown.sh',
      'usr/lib/dracut/hooks/cmdline/30-parse-lunmask.sh':'95lunmask/parse-lunmask.sh',
      'usr/lib/dracut/hooks/cmdline/95-parse-virtfs.sh':'95virtfs/parse-virtfs.sh',
      'usr/lib/dracut/hooks/mount/99-mount-virtfs.sh':'95virtfs/mount-virtfs.sh',
    }
    cloud_data={n:(fixture/src).read_bytes() for n,src in cloud_paths.items()}
    cloud_meta=rpm_rows()+''.join('/usr/lib/dracut/modules.d/'+cloud_paths[n]+'\t'+hashlib.sha256(d).hexdigest()+'\t'+str(EXE)+'\t\n' for n,d in cloud_data.items())
    # Base entries are captured before the NetworkManager fixtures mutate files.
    cloud_entries=[(n,d+b'modsign\ncrypt\ndm\nnvdimm\nlunmask\nvirtfs\n' if n=='usr/lib/dracut/modules.txt' else d,m) for n,d,m in entries]
    cloud_entries += [(n,d,EXE) for n,d in cloud_data.items()]
    cloud_entries += [('usr/lib/modules/keys',b'',stat.S_IFDIR|0o755)]
    check('generic-cloud reviewed hooks and empty key directory',cloud_entries,meta=cloud_meta,ok=True)
    for key in ['rd.lunmask=fc,1,2','rd.luks.key=/etc/secret','rd.luks.uuid=00000000-0000-0000-0000-000000000000','rd.luks.name=00000000-0000-0000-0000-000000000000=secret','root=virtfs:share','rootfstype=9p']:
        check('generic-cloud forbids activation '+key,cloud_entries,meta=cloud_meta,cmd='root=UUID=fixture ro '+key)
    for n in ['usr/lib/modules/keys/custom.der','etc/ndctl/keys/tpm.handle','etc/cryptsetup-keys.d/root.key','usr/lib/cryptsetup-keys.d/root.key']:
        check('generic-cloud forbids key payload '+n,cloud_entries+[(n,b'public synthetic key fixture',REG)],meta=cloud_meta,expected='unreviewed early key or TPM payload')
    key_alias=[(n,b'../../etc' if n=='usr/lib/modules/keys' else d,LINK if n=='usr/lib/modules/keys' else m) for n,d,m in cloud_entries]
    check('generic-cloud rejects linked module keys',key_alias,meta=cloud_meta,expected='linked early module key directory')
    for name in cloud_data:
        altered=[(n,d+b'# changed public hook\n' if n==name else d,m) for n,d,m in cloud_entries]
        check('changed generic-cloud hook '+name,altered,meta=cloud_meta,expected='unreviewed generic-cloud boot hook')
    gen='usr/lib/systemd/system-generators/systemd-cryptsetup-generator';gen_data=b'SYNTHETIC GENERATOR NEVER EXECUTED\n'
    gen_meta=cloud_meta+'PACKAGE\tsystemd\t252\t8\n/'+gen+'\t'+hashlib.sha256(gen_data).hexdigest()+'\t'+str(EXE)+'\t\n'
    check('generic-cloud reviewed generator version',cloud_entries+[(gen,gen_data,EXE)],meta=gen_meta,ok=True)
    check('generic-cloud generator version must be reviewed',cloud_entries+[(gen,gen_data,EXE)],meta=gen_meta.replace('PACKAGE\tsystemd\t252\t8','PACKAGE\tsystemd\t253\t8'),expected='unreviewed systemd generator version')
    check('cryptsetup generator cannot hide its module',entries+[(gen,gen_data,EXE)],meta=gen_meta,expected='cryptsetup payload without reviewed crypt module')
    tmp='usr/lib/tmpfiles.d/cryptsetup.conf';tmp_data=b'd /run/cryptsetup 0700 root root -\n'
    tmp_meta=cloud_meta+'PACKAGE\tcryptsetup-libs\t2.8.1\t8\n/'+tmp+'\t'+hashlib.sha256(tmp_data).hexdigest()+'\t'+str(REG)+'\t\n'
    check('cryptsetup tmpfiles exact local runtime directory',cloud_entries+[(tmp,tmp_data,REG)],meta=tmp_meta,ok=True)
    check('cryptsetup tmpfiles cannot add an action',cloud_entries+[(tmp,tmp_data+b'L /run/custom - - - - /etc\n',REG)],meta=tmp_meta,expected='modified cryptsetup tmpfiles policy')
    check('cryptsetup tmpfiles linked input refused',cloud_entries+[(tmp,b'/etc/secret',LINK)],meta=tmp_meta)
    for leaf in ['11-dm.rules','59-persistent-storage-dm.rules']:
        name='etc/udev/rules.d/'+leaf;src='/usr/lib/dracut/modules.d/90dm/'+leaf;data=(fixture/'90dm'/leaf).read_bytes()
        meta=cloud_meta+src+'\t'+hashlib.sha256(data).hexdigest()+'\t'+str(REG)+'\t\n'
        source_file=work/leaf;source_file.write_bytes(data)
        old_adapted=adapted
        if leaf.startswith('59-'):
            # Production recipe reads the installed public RPM source only.
            adapted=adapted.replace("'/usr/lib/dracut/modules.d/'+module+'/'+posixpath.basename(name)",repr(str(source_file)))
            meta += str(source_file)+'\t'+hashlib.sha256(data).hexdigest()+'\t'+str(REG)+'\t\n'
            data=data.replace(b'IMPORT BLKID',b'IMPORT{builtin}="blkid"')
        check('reviewed local device mapper rule '+leaf,cloud_entries+[(name,data,REG)],meta=meta,ok=True)
        check('device mapper rule cannot add execution '+leaf,cloud_entries+[(name,data+b'RUN+="custom"\n',REG)],meta=meta)
        adapted=old_adapted
    journal=b'[Journal]\nStorage=volatile\nRateLimitInterval=0\nRateLimitBurst=0\n'
    check('generic-cloud literal volatile journal recipe',cloud_entries+[('etc/systemd/journald.conf',journal,REG)],meta=cloud_meta,ok=True)
    check('generic-cloud journal cannot enable forwarding',cloud_entries+[('etc/systemd/journald.conf',journal+b'ForwardToSyslog=yes\n',REG)],meta=cloud_meta)
    print(f'PASS: {count} dracut assessment scenarios; no extraction or host effects')
PY
