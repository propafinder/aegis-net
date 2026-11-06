#!/usr/bin/env bash
# Execute the production read-only parser over synthetic cpio archives; no host
# boot inputs, service commands, initrd extraction, or network calls are used.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
python3 -I -B - "$ROOT" <<'PY'
from pathlib import Path
import ast,contextlib,gzip,hashlib,io,json,os,re,shutil,stat,subprocess,sys,tempfile,textwrap,types
source=(Path(sys.argv[1])/'install.sh').read_text()
function=re.search(r'^device_verify_initramfs\(\) \{\n.*?^\}',source,re.M|re.S)[0]
program=function.split("<<'PY'\n",1)[1].rsplit('\nPY',1)[0]
assert source.count('boot_proof="$(device_verify_initramfs)" || return $?')==3
assert 'auto_v2_first_arm "$candidate" "$planning_config" "$selected_mode" "$helper_dir" || return $?' in source
assert 'auto_v2_first_arm "$candidate" /etc/aegis/client/aegis.toml "$selected_mode" "$helper_dir" stopped-successor || return $?' in source
# Exercise the production module-root gate without the fixture's /tmp or
# runner-UID trust exceptions. Stop exactly where the existing /boot checks
# begin: the no-cloud case must reach them, even for a public v3 bundle with
# no AUTO policy helpers or for a user-owned source tree.
gate=program.split("need(not pathlib.Path('/sys/firmware/ibft')",1)[0]
policy=ast.parse((Path(sys.argv[1])/'scripts/lib/aegis_initrd_policy.py').read_text())
gate_tree=ast.parse(gate)
def indicators(tree):
    return next(ast.literal_eval(node.value) for node in tree.body
                if isinstance(node,ast.Assign) and
                any(isinstance(target,ast.Name) and target.id=='CLOUD_INDICATORS'
                    for target in node.targets))
assert indicators(gate_tree)==indicators(policy),'inline cloud indicators drifted from the policy'
with tempfile.TemporaryDirectory(prefix='aegis-public-boot-gate-',dir='/tmp') as raw:
    fixture=Path(raw)
    public=fixture/'public-v3/scripts/lib';public.mkdir(parents=True)
    untrusted=fixture/'user-tree/scripts/lib';untrusted.mkdir(parents=True)
    for name in ('aegis_initrd_policy.py','aegis_auto_foreign_policy.py'):
        (untrusted/name).write_bytes((Path(sys.argv[1])/'scripts/lib'/name).read_bytes())
    (fixture/'user-tree').chmod(0o777)
    indicator=fixture/'cloud-init-indicator'
    fakebin=fixture/'bin';fakebin.mkdir()
    (fakebin/'systemctl').write_text('#!/bin/sh\nexit 0\n');(fakebin/'systemctl').chmod(0o700)
    fixture_env=dict(os.environ,PATH=str(fakebin)+os.pathsep+os.environ['PATH'])
    chosen=re.sub(r'CLOUD_INDICATORS = \(.*?\)\n',
                  'CLOUD_INDICATORS = ('+repr(str(indicator))+',)\n',gate,flags=re.S)
    for key in ('CLOUD_UNIT_DIRS','CLOUD_GENERATOR_DIRS'):
        chosen=re.sub(key+r' = \(.*?\)\n',key+' = ()\n',chosen,flags=re.S)
    chosen+='\nprint("boot_checks_reached")\n'
    trusted_missing=Path('/usr/lib')
    assert trusted_missing.is_dir() and not any((trusted_missing/name).exists() for name in
        ('aegis_initrd_policy.py','aegis_auto_foreign_policy.py'))
    for root,label in ((public,'public bundle without AUTO helpers'),
                       (trusted_missing,'trusted module root without AUTO helpers'),
                       (untrusted,'untrusted source ancestor')):
        for present in (False,True):
            if present: indicator.touch()
            else: indicator.unlink(missing_ok=True)
            result=subprocess.run([sys.executable,'-I','-B','-c',chosen,'','',str(root)],
                                  text=True,capture_output=True,timeout=10,env=fixture_env)
            if present:
                assert result.returncode==78,(label,result.returncode,result.stderr)
                assert json.loads(result.stderr)['code']=='cloud_init_early_network_unverified',(label,result.stderr)
            else:
                assert result.returncode==0 and result.stdout.strip()=='boot_checks_reached',(
                    label,result.returncode,result.stdout,result.stderr)
            print('PASS: '+label+(' with cloud indicator' if present else ' without cloud indicator'))
def archive(entries):
    out=bytearray()
    for index,(name,data,mode) in enumerate(entries+[('TRAILER!!!',b'',stat.S_IFREG|0o600)]):
        name=name.encode()+b'\0'
        fields=[index+1,mode,0,0,1,0,len(data),0,0,0,0,len(name),0]
        out+=b'070701'+b''.join(f'{x:08x}'.encode() for x in fields)
        out+=name;out+=b'\0'*((-len(out))%4);out+=data;out+=b'\0'*((-len(out))%4)
    return bytes(out)
with tempfile.TemporaryDirectory(prefix='aegis-boot-assessment-',dir='/tmp') as raw:
    work=Path(raw).resolve();boot=work/'boot';boot.mkdir();pkg=work/'pkg';pkg.mkdir();share=work/'share';share.mkdir()
    init=b'#!/bin/sh\n# Synthetic stock local-boot fixture. Never executed.\n'
    hooks={'init':init,'scripts/functions':b'# stock functions\n','scripts/init-top/local-fixture':b'#!/bin/sh\nexit 0\n'}
    md5=[]
    for name,data in hooks.items():
        p=share/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
        md5.append(hashlib.md5(data).hexdigest()+'  '+str(p)[1:])
    (pkg/'initramfs-tools-core.md5sums').write_text('\n'.join(md5)+'\n')
    cmdline=work/'cmdline';cmdline.write_text('root=LABEL=fixture ro')
    image=boot/'initrd.img-fixture'
    adapted=re.sub(r'^kernel=.*$',"kernel='fixture'",program,count=1,flags=re.M)
    for old,new in [('/boot/initrd.img-',str(boot)+'/initrd.img-'),('/boot/initrd.img',str(work/'missing-default-initrd')),('/initrd.img',str(work/'missing-root-initrd')),('/proc/cmdline',str(cmdline)),('/sys/firmware/ibft',str(work/'missing-ibft')),('/usr/share/initramfs-tools',str(share)),('/var/lib/dpkg/info',str(pkg)),('/var/lib/dpkg/status',str(pkg/'status'))]:
        # Prefix replacement must not rewrite earlier fixture paths.
        adapted=adapted.replace("'"+old,"'"+new)
    adapted=adapted.replace('s.st_uid==0',f's.st_uid in (0,{os.getuid()})')
    # Never let this synthetic archive test inspect the runner's cloud-init.
    cloud_root=work/'cloud-root';cloud_root.mkdir()
    cloud_binary=cloud_root/'usr/bin/cloud-init';cloud_binary.parent.mkdir(parents=True)
    assert adapted.count('verify_cloud_init_boot({})')==1
    # PID1 is the runner's own; the synthetic contract answers list-units
    # with no cloud-init row.
    adapted=adapted.replace('verify_cloud_init_boot({})',
        "verify_cloud_init_boot({},root=pathlib.Path("+repr(str(cloud_root))+
        "),read=lambda path,limit=2097152: path.read_bytes(),run=lambda *args: b'')",1)
    # Model root ownership only inside this synthetic cloud-init tree. The
    # production ancestry/mode/symlink checks remain byte-for-byte intact.
    fixture_lstat = '''\nimport aegis_initrd_policy as _fixture_policy\nimport types as _fixture_types\n_original_cloud_lstat = _fixture_policy.cloud_lstat\ndef _fixture_cloud_lstat(path):\n    info = _original_cloud_lstat(path)\n    if pathlib.Path(path).is_relative_to(pathlib.Path(FIXTURE_CLOUD_ROOT)):\n        return _fixture_types.SimpleNamespace(**{key: (0 if key == 'st_uid' else getattr(info, key)) for key in dir(info) if key.startswith('st_')})\n    return info\n_fixture_policy.cloud_lstat = _fixture_cloud_lstat\n'''.replace('FIXTURE_CLOUD_ROOT',repr(str(cloud_root)))
    cloud_import='from aegis_initrd_policy import verify_cloud_init_boot,CloudInitRefusal,cloud_init_refusal_json,journal_cloud_init_refusal'
    assert adapted.count(cloud_import)==1
    adapted=adapted.replace(cloud_import,cloud_import+textwrap.indent(fixture_lstat,'        '),1)
    # The synthetic temp ancestor has sticky semantics on macOS/Linux; only
    # this test path may use the current fixture UID. Product policy stays strict.
    adapted=adapted.replace('not s.st_mode&0o022',"(not s.st_mode&0o022 or item==pathlib.Path('/private/tmp') or item==pathlib.Path('/tmp'))")
    entries=[(name,data,stat.S_IFREG|0o755) for name,data in hooks.items()]+[
      ('conf/initramfs.conf',b'MODULES=most\nBUSYBOX=auto\nDEVICE=\nNFSROOT=auto\n',stat.S_IFREG|0o644),
      ('conf/conf.d/default_root',b'BOOT=local\n',stat.S_IFREG|0o644),
      ('scripts/init-top/ORDER',b'/scripts/init-top/local-fixture "$@"\n',stat.S_IFREG|0o755),
      ('etc/dropbear/fixture.key',b'SYNTHETIC PRIVATE FIXTURE NEVER EXTRACTED',stat.S_IFREG|0o600)]
    count=0
    def check(label,items=None,ok=False,blob=None,cmd='root=LABEL=fixture ro',reason=None,code=None,early_network=None,refusal_code=None):
        global count
        image.write_bytes(blob if blob is not None else archive(items if items is not None else entries));cmdline.write_text(cmd)
        before={str(p.relative_to(work)) for p in work.rglob('*')}
        r=subprocess.run([sys.executable,'-c',adapted,'','',str(Path(sys.argv[1])/'scripts/lib')],text=True,capture_output=True,timeout=10)
        assert (r.returncode==0)==ok,(label,r.returncode,r.stdout,r.stderr)
        if code is not None: assert r.returncode==code,(label,r.returncode,r.stderr)
        if code==75:
            diagnostic=json.loads(r.stderr.strip())
            assert diagnostic=={'schema':'aegis_install_refusal_v1',
                'code':'reboot_required_kernel_changed','action':'reboot_computer',
                'message':'A newer kernel is selected for the next boot. Reboot the computer, then retry installation.'},(label,diagnostic)
        if code==78:
            diagnostic=json.loads(r.stderr.strip())
            assert diagnostic['schema']=='aegis_install_refusal_v1', (label,diagnostic)
            assert diagnostic['code']==(refusal_code or 'debian_dracut_boot_profile_unreviewed'), (label,diagnostic)
            if early_network is not None:
                assert diagnostic['early_network_services_present'] is early_network, (label,diagnostic)
        if reason is not None: assert reason in r.stderr,(label,r.stderr)
        if ok:
            data=json.loads(r.stdout);assert data['initramfs_network']=='absent_verified' and data['initrd_sha256']==hashlib.sha256(image.read_bytes()).hexdigest()
        assert before=={str(p.relative_to(work)) for p in work.rglob('*')},label+' created/extracted a file'
        count+=1;print('PASS: '+label)
    check('stock uncompressed archive',ok=True)
    cloud_binary.write_text('#!/bin/sh\nexit 0\n')
    check('present cloud-init fails closed',code=78,refusal_code='cloud_init_early_network_unverified')
    datasource=cloud_root/'run/cloud-init/instance-data.json';datasource.parent.mkdir(parents=True)
    # 45bb6522 admitted this invented key as an offline datasource. Real
    # cloud-init never writes it, and every active cloud-init is refused.
    datasource.write_text(json.dumps({'v1':{'datasource':'DataSourceNoCloud [seed=/dev/sr0]'}}))
    check('offline cloud-init datasource refused',code=78,refusal_code='cloud_init_early_network_unverified')
    datasource.write_text(json.dumps({'v1':{'datasource':'DataSourceEc2 [metadata]'}}))
    check('network cloud-init datasource refused',code=78,refusal_code='cloud_init_early_network_unverified')
    sys.path.insert(0,str(Path(sys.argv[1])/'scripts/lib'))
    import aegis_initrd_policy as policy
    # The detector is executed from source in a separate namespace. Give it
    # the same synthetic-root ownership view as the installed parser.
    def fixture_owned_lstat(path):
        info=os.lstat(path)
        if Path(path).is_relative_to(cloud_root):
            return types.SimpleNamespace(**{key:(0 if key=='st_uid' else getattr(info,key))
                                           for key in dir(info) if key.startswith('st_')})
        return info
    policy.cloud_lstat=fixture_owned_lstat
    fixtures=Path(sys.argv[1])/'scripts/tests/fixtures/cloud-init-r21'
    read=lambda path,limit=2097152:path.read_bytes()
    def detector_stderr(run):
        """The detector's own __main__ typing around the same proof."""
        source=(Path(sys.argv[1])/'scripts/lib/aegis_initrd_policy.py').read_text()
        head,tail=source.split("\nif __name__ == '__main__':\n",1)
        namespace={'__file__':str(Path(sys.argv[1])/'scripts/lib/aegis_initrd_policy.py')}
        exec(compile(head,namespace['__file__'],'exec'),namespace)
        namespace['cloud_lstat']=fixture_owned_lstat
        namespace['main']=lambda:namespace['verify_cloud_init_boot']({},root=cloud_root,read=read,run=run)
        namespace['__name__']='__main__'
        stderr=io.StringIO()
        with contextlib.redirect_stderr(stderr):
            try: exec(compile("if __name__ == '__main__':\n"+tail,namespace['__file__'],'exec'),namespace)
            except SystemExit as stop: assert stop.code==78,stop.code
            else: raise AssertionError('detector admitted')
        return stderr.getvalue()
    # F7(f)/R12: the installed gate and the detector print byte-identical
    # typed JSON for each refusal, from real cloud-init status samples.
    for scenario,token in (('noble-s1-nocloud-seeddir','DataSourceNoCloud'),
            ('noble-s4b-nocloudnet-ftp-syscfg','DataSourceNoCloudNet'),
            ('resolute-s5-configdrive-seeddir','DataSourceConfigDrive'),
            ('resolute-s6-none','DataSourceNone')):
        for name in ('status.json','instance-data.json'):
            (cloud_root/'run/cloud-init'/name).write_bytes((fixtures/scenario/name).read_bytes())
        image.write_bytes(archive(entries))
        installed=subprocess.run([sys.executable,'-c',adapted,'','',str(Path(sys.argv[1])/'scripts/lib')],text=True,capture_output=True,timeout=10)
        assert installed.returncode==78,(scenario,installed.returncode,installed.stderr)
        detector=detector_stderr(lambda *args:b'')
        assert installed.stderr==detector,(scenario,installed.stderr,detector)
        refusal=json.loads(detector)
        assert refusal['code']=='cloud_init_early_network_unverified' and refusal['detail']=='network_required: cloud-init active: datasource '+token,refusal
        assert 'seed' not in refusal['detail'] and '://' not in detector,refusal
        print('PASS: byte-identical typed refusal for real '+scenario)
    (cloud_root/'run/cloud-init/status.json').unlink()
    datasource.unlink()
    cloud_binary.unlink()
    original_pins=policy.CLOUD_DISABLED_PINS
    original_lstat=policy.cloud_lstat
    try:
        unit_data=b'[Unit]\nConditionPathExists=!/etc/cloud/cloud-init.disabled\n'
        paths={}
        for name in original_pins:
            target=cloud_root/name.lstrip('/');target.parent.mkdir(parents=True,exist_ok=True)
            data=(b'#!/bin/sh\n# synthetic generator\n' if 'generators' in name else
                  b'[Unit]\n# synthetic target\n' if name.endswith('/cloud-config.target') else
                  unit_data+name.encode()+b'\n')
            target.write_bytes(data);paths[name]=hashlib.sha256(data).hexdigest()
        policy.CLOUD_DISABLED_PINS=paths
        marker=cloud_root/'etc/cloud/cloud-init.disabled';marker.parent.mkdir(parents=True)
        marker.write_bytes(b'')
        proc=cloud_root/'proc';(proc/'self').mkdir(parents=True)
        (proc/'self/mountinfo').write_text('22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw\n')
        (proc/'stat').write_text('cpu  1 2 3 4\nbtime %d\n'%(int(__import__('time').time())+60))
        def root_owned(path):
            info=os.lstat(path)
            return types.SimpleNamespace(st_mode=info.st_mode,st_uid=0,st_gid=0,st_nlink=info.st_nlink,
                st_dev=info.st_dev,st_ino=info.st_ino,st_size=info.st_size,st_ctime_ns=info.st_ctime_ns)
        policy.cloud_lstat=root_owned
        state={}
        def fake_run(*args):
            if args[:2]==('systemctl','list-units'):return b''
            unit=args[2];target=cloud_root/'usr/lib/systemd/system'/unit
            props={'FragmentPath':str(target),'DropInPaths':'','NeedDaemonReload':'no','ActiveState':'inactive',
                   'LoadState':'loaded','UnitFileState':'static','InactiveExitTimestampMonotonic':'0',
                   'ExecMainStartTimestampMonotonic':'0'}
            props.update(state.get(unit,{}))
            wanted=[args[i+1] for i,arg in enumerate(args) if arg=='-p']
            return ''.join(k+'='+props[k]+'\n' for k in wanted if k in props).encode()
        def refused(code,run=fake_run):
            try: policy.verify_cloud_init_boot({},root=cloud_root,read=read,run=run)
            except policy.CloudInitRefusal as error:
                assert error.code==code,(error.code,str(error));return error
            raise AssertionError('cloud-init profile admitted')
        assert policy.verify_cloud_init_boot({},root=cloud_root,read=read,run=fake_run)=='disabled_proved'
        print('PASS: disabled marker with the complete pinned inactive 26.04 profile, even without binary')
        # A complete install-time marker proof cannot replace a switch-root
        # barrier in the actual running image. Exercise the entire production
        # parser in-process so the declared cloud fixture remains isolated from
        # this test runner's PID1 and vendor unit bytes.
        image.write_bytes(archive(entries));cmdline.write_text('root=LABEL=fixture ro')
        barrier_program=adapted.replace("run=lambda *args: b''",'run=fixture_run').replace(
            '/var/lib/aegis-install/boot-backup/manifest.json',str(work/'no-owned-boot-policy'))
        stdout,stderr=io.StringIO(),io.StringIO();old_argv=sys.argv
        try:
            sys.argv=['boot-assessment','','',str(Path(old_argv[1])/'scripts/lib')]
            with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
                try:exec(compile(barrier_program,'production-boot-parser','exec'),{'fixture_run':fake_run})
                except SystemExit as stop:status=stop.code
                else:status=0
        finally:sys.argv=old_argv
        assert status==78,('disabled profile admitted without a running barrier',status,stdout.getvalue(),stderr.getvalue())
        assert json.loads(stderr.getvalue())['code']=='cloud_init_switch_root_unverified',stderr.getvalue()
        print('PASS: disabled cloud profile without owned running switch-root barrier refuses before install')
        unit=cloud_root/'usr/lib/systemd/system/cloud-init-local.service'
        original=unit.read_bytes();unit.write_bytes(original+b'# modified\n')
        assert 'modified disabled cloud-init code' in str(refused('cloud_init_disabled_profile_unproved'))
        unit.write_bytes(original)
        for name,props in (('cloud-init-local.service',{'ActiveState':'active'}),
                           ('cloud-init-main.service',{'DropInPaths':'/etc/systemd/system/cloud-init-main.service.d/z.conf'}),
                           ('cloud-init-main.service',{'InactiveExitTimestampMonotonic':'7'})):
            state={name:props}
            refused('cloud_init_disabled_profile_unproved')
        state={}
        print('PASS: modified, active, drop-in or started disabled-cloud unit refused')
        marker.unlink();(cloud_root/'run/marker').write_bytes(b'');marker.symlink_to(cloud_root/'run/marker')
        refused('cloud_init_disabled_profile_unproved')
        # Both paths load the module afresh (real lstat, reviewed pins), so the
        # unproved-profile refusal must also be byte-identical.
        detector=detector_stderr(fake_run)
        image.write_bytes(archive(entries))
        installed=subprocess.run([sys.executable,'-c',adapted,'','',str(Path(sys.argv[1])/'scripts/lib')],text=True,capture_output=True,timeout=10)
        assert installed.returncode==78 and installed.stderr==detector,(installed.returncode,installed.stderr,detector)
        assert json.loads(detector)['code']=='cloud_init_disabled_profile_unproved',detector
        print('PASS: symlinked marker refused with the typed unproved-profile code')
        marker.unlink()
        refused('cloud_init_early_network_unverified')
        print('PASS: unit-only cloud-init without the marker refused')
    finally:
        policy.CLOUD_DISABLED_PINS=original_pins
        policy.cloud_lstat=original_lstat
        shutil.rmtree(cloud_root)
    # A package update may move the default initrd to a newer kernel while
    # this process still runs the previous one. The guard must remain off,
    # with a typed reboot action. After the reboot the same archive qualifies.
    next_image=boot/'initrd.img-fixture-next';next_image.write_bytes(archive(entries))
    default_alias=work/'missing-default-initrd';default_alias.symlink_to(next_image)
    check('new kernel awaiting reboot',reason='reboot_required_kernel_changed',code=75)
    original_image,original_program=image,adapted
    image=next_image;adapted=adapted.replace("kernel='fixture'","kernel='fixture-next'",1)
    check('new kernel after reboot',ok=True)
    image,adapted=original_image,original_program
    default_alias.unlink()
    arbitrary=work/'not-an-initrd';arbitrary.write_bytes(b'arbitrary')
    default_alias.symlink_to(arbitrary)
    check('arbitrary default mismatch remains generic refusal',reason='default initrd differs from running kernel',code=1)
    default_alias.unlink()
    check('gzip main archive',blob=gzip.compress(archive(entries)),ok=True)
    check('early archive plus compressed main',blob=archive([('early',b'data',stat.S_IFREG|0o600)])+gzip.compress(archive(entries)),ok=True)
    check('network command line',cmd='root=LABEL=fixture ip=dhcp')
    check('iSCSI command line',cmd='root=LABEL=fixture iscsi_auto')
    check('custom init command line',cmd='root=LABEL=fixture init=/bin/custom')
    check('custom boot hook',entries+[('scripts/init-top/custom',b'#!/bin/sh\n',stat.S_IFREG|0o755)])
    check('modified packaged hook',[(n,b'changed' if n=='init' else d,m) for n,d,m in entries])
    growname='scripts/local-bottom/growroot'
    growdata=b'#!/bin/sh\n# Synthetic packaged local disk resize hook. Never executed.\n'
    growpath=share/growname;growpath.parent.mkdir(parents=True,exist_ok=True);growpath.write_bytes(growdata)
    growmeta=pkg/'cloud-initramfs-growroot.md5sums'
    growmeta.write_text(hashlib.md5(growdata).hexdigest()+'  '+str(growpath)[1:]+'\n')
    check('packaged local growroot hook',entries+[(growname,growdata,stat.S_IFREG|0o755)],ok=True)
    check('modified growroot archive hook',entries+[(growname,b'changed',stat.S_IFREG|0o755)])
    growpath.write_bytes(b'changed')
    check('modified installed growroot hook',entries+[(growname,growdata,stat.S_IFREG|0o755)])
    growmeta.unlink()
    check('growroot without package baseline',entries+[(growname,growdata,stat.S_IFREG|0o755)])
    check('network config',entries+[('conf/conf.d/network',b'IP=dhcp\n',stat.S_IFREG|0o644)])
    for value in ('none','UUID=01234567-89ab-cdef-0123-456789abcdef'):
        check('literal local resume policy '+value,entries+[('conf/conf.d/resume',('RESUME='+value+'\n').encode(),stat.S_IFREG|0o644)],ok=True)
    for value in ('auto','/dev/nfs','dhcp','https://fixture.invalid/resume','UUID=../custom'):
        check('unsupported resume policy '+value,entries+[('conf/conf.d/resume',('RESUME='+value+'\n').encode(),stat.S_IFREG|0o644)],reason='unsupported early resume device')
    for value in ('y','n'):
        check('literal keyboard policy '+value,entries+[('conf/conf.d/keymap',('KEYMAP='+value+'\n').encode(),stat.S_IFREG|0o644)],ok=True)
    check('nonboolean keyboard policy',entries+[('conf/conf.d/keymap',b'KEYMAP=/unreviewed\n',stat.S_IFREG|0o644)])
    check('literal no-op modprobe blacklist',entries+[('etc/modprobe.d/blacklist.conf',b'install fixture /bin/false\n',stat.S_IFREG|0o644)],ok=True)
    check('custom executable modprobe command',entries+[('etc/modprobe.d/custom.conf',b'install fixture /bin/custom\n',stat.S_IFREG|0o644)])
    check('custom PATH boot config',entries+[('conf/conf.d/path',b'PATH=/unreviewed\n',stat.S_IFREG|0o644)])
    check('shell expression boot config',entries+[('conf/conf.d/expression',b'BOOT=$(true)\n',stat.S_IFREG|0o644)])
    check('symlinked boot hook',entries+[('scripts/init-top/link',b'/bin/unreviewed',stat.S_IFLNK|0o777)])
    # Ubuntu 26.04 uses the Debian filename with dracut, not initramfs-tools.
    # Neither the stock-looking systemd init alias nor the local root argument
    # proves that early networking is dormant. Do not turn a format fix into
    # an admission bypass for the networkd profile.
    dracut=[('init',b'usr/lib/systemd/systemd',stat.S_IFLNK|0o777),
            ('usr/lib/dracut/modules.txt',b'systemd\nsystemd-networkd\nbase\n',stat.S_IFREG|0o644)]
    check('Debian-named dracut with networkd refused',dracut,
          code=78,early_network=True)
    check('compressed Debian dracut with networkd refused',blob=gzip.compress(archive(dracut)),
          code=78,early_network=True)
    enabled='etc/systemd/system/multi-user.target.wants/systemd-networkd.service'
    hidden=[(n,d.replace(b'systemd-networkd\n',b'') if n.endswith('/modules.txt') else d,m) for n,d,m in dracut]
    check('networkd activation detected independently of module list',hidden+[
          (enabled,b'/usr/lib/systemd/system/systemd-networkd.service',stat.S_IFLNK|0o777)],
          code=78,early_network=True)
    check('Debian dracut cannot borrow RPM admission',hidden,
          code=78,early_network=False)
    check('custom Debian dracut init refused',[(n,b'bin/custom' if n=='init' else d,m) for n,d,m in hidden],
          reason='unsupported Debian dracut init entry')
    check('plain linked init still refused',[(n,b'usr/lib/systemd/systemd' if n=='init' else d,stat.S_IFLNK|0o777 if n=='init' else m) for n,d,m in entries],
          reason='symlinked boot policy entry init')
    check('duplicate Debian dracut marker refused',dracut+[dracut[1]],
          reason='duplicate boot format marker')
    check('duplicate policy entry',entries+[entries[0]])
    check('ORDER traversal',[(n,b'/scripts/../bin/sh "$@"\n' if n.endswith('/ORDER') else d,m) for n,d,m in entries])
    check('truncated archive',blob=archive(entries)[:-90])
    check('unknown compression',blob=b'unsupported image')
    check('large zero padding followed by second archive',blob=gzip.compress(archive(entries)+b'\0'*(1024*1024+1024)+archive([('second',b'not padding',stat.S_IFREG|0o644)])))
    check('large legal zero padding',blob=gzip.compress(archive(entries)+b'\0'*(1024*1024+1024)),ok=True)
    print(f'PASS: {count} boot assessment scenarios; no extraction or host effects')
policy=(Path(sys.argv[1])/'scripts/lib/aegis_initrd_policy.py').read_text()
head,tail=policy.split("\nif __name__ == '__main__':\n",1)
tail="if __name__ == '__main__':\n"+tail
for kind,message,typed in [
    ('cloud_init_early_network_unverified','network_required: cloud-init active: datasource DataSourceNone',True),
    ('cloud_init_disabled_profile_unproved','unknown: unreviewed cloud-init unit layout',True),
    (ValueError,'network_required: cloud-init may use ephemeral DHCP',False),
    (ValueError,'unknown: cloud-init datasource not established',False),
    (ValueError,'network_required: mount or unlock policy',False),
    (OSError,'unknown: modified disabled cloud-init code',False),
]:
    namespace={'__file__':str(Path(sys.argv[1])/'scripts/lib/aegis_initrd_policy.py')}
    exec(compile(head,namespace['__file__'],'exec'),namespace)
    def fail(kind=kind,message=message):
        if isinstance(kind,str): raise namespace['CloudInitRefusal'](kind,message)
        raise kind(message)
    namespace['main']=fail
    namespace['__name__']='__main__'
    stderr=io.StringIO()
    with contextlib.redirect_stderr(stderr):
        try: exec(compile(tail,namespace['__file__'],'exec'),namespace)
        except SystemExit as stop: result=stop.code
    if typed:
        refusal=json.loads(stderr.getvalue())
        assert result==78 and refusal['code']==kind and refusal['detail']==message,(message,result,stderr.getvalue())
        assert stderr.getvalue().strip()==namespace['cloud_init_refusal_json'](namespace['CloudInitRefusal'](kind,message))
    else:
        # Only the typed CloudInitRefusal is typed; plain strings never are.
        assert isinstance(result,str) and result.startswith('AEGIS initrd policy refused: '),(message,result)
print('PASS: 6 initrd-policy typed/generic error routes')
PY
