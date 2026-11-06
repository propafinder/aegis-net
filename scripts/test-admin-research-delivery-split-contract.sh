#!/usr/bin/env bash
# Real retained Linux builder output only. No build/help stand-in or producer fallback.
set -euo pipefail
if [[ $# -ne 2 || "$1" != --builder-output ]]; then
  echo 'usage: test-admin-research-delivery-split-contract.sh --builder-output DIRECTORY' >&2
  exit 2
fi
python3 -I - "$2" <<'PY_SPLIT'
import hashlib, json, os, pathlib, shutil, signal, stat, subprocess, tarfile, tempfile, time
base=pathlib.Path(__import__('sys').argv[1]).resolve(strict=True)
def require(value, message):
    if not value: raise AssertionError(message)
EXPECTED_HELPER_SCRIPTS = (
    'scripts/lib/root-state.sh',
    'scripts/lib/aegis_installer_auto_v2.py',
    'scripts/lib/aegis_auto_uninstall_journal.py',
    'scripts/lib/aegis_auto_capture.py',
    'scripts/lib/aegis_auto_capture_topology.py',
    'scripts/lib/aegis_auto_endpoint.py',
    'scripts/lib/aegis_auto_guard_policy.py', 'scripts/lib/aegis_auto_foreign_policy.py', 'scripts/lib/aegis_auto_foreign_monitor.py', 'scripts/lib/aegis_auto_ufw_pins.json', 'scripts/lib/aegis_initrd_policy.py', 'scripts/lib/aegis_initrd_classic.py',
    'scripts/lib/aegis_auto_guardian.py',
    'scripts/lib/aegis_auto_guardian_watchdog.py',
    'scripts/lib/aegis_auto_terminal_witness.py',
    'scripts/lib/aegis_auto_terminal_boot_store.py',
    'scripts/lib/aegis_auto_terminal_register.py',
    'scripts/lib/aegis_auto_boot_transition.py',
    'scripts/lib/aegis_auto_launch.py',
    'scripts/lib/aegis_auto_native_witness.py',
    'scripts/lib/aegis_auto_sink.py',
    'scripts/lib/aegis_auto_trace_rollback.py',
    'scripts/lib/aegis_auto_witness_topology.py',
    'scripts/aegis-device-egress-guard.sh',
    'scripts/aegis-relay-geneva-profile.sh',
    'scripts/bootstrap-wide-linux-validation-host.sh',
    'scripts/generate-relay-materials.sh',
    'scripts/render-client-bundle.sh',
    'scripts/package-client-bundle.sh',
    'scripts/issue-fronted-bundle.sh',
    'scripts/purge-installed-aegis.sh',
    'scripts/aegis-ubuntu-uninstall.sh',
    'scripts/aegis-origin-guard.sh',
    'scripts/aegis-wide-enable.sh',
    'scripts/aegis-wide-disable.sh',
    'scripts/aegis-wide-persist-install.sh',
    'scripts/janitor-wide-linux-tproxy.sh',
    'scripts/setup-wide-linux-redirect.sh',
    'scripts/setup-wide-linux-tproxy.sh',
    'scripts/setup-wide-linux-nfqueue.sh',
    'scripts/aegis-rpi-gateway.sh',
    'scripts/validate-debian-package-host.sh',
    'scripts/build-ubuntu-controlled-pilot-playbook.sh',
    'scripts/build-ubuntu-operator-reapply-canary.sh',
    'scripts/build-ubuntu-controlled-pilot-bundle.sh',
    'scripts/build-ubuntu-release-review.sh',
    'scripts/build-ubuntu-controlled-pilot-review-bundle.sh',
    'scripts/ubuntu-release-wave-status.sh',
    'scripts/build-ubuntu-release-wave-bundle.sh',
    'scripts/build-ubuntu-field-pilot-remote-bundle.sh',
    'scripts/build-post-release-stealth-wave-summary.sh',
    'scripts/mimicry-wire-validation-contract.sh',
    'scripts/build-mimicry-wire-witness-summary.sh',
    'scripts/validate-mimicry-wire-host.sh',
    'scripts/build-ubuntu-mimicry-next-contour.sh',
)
EXPECTED_SYSTEMD_TEMPLATES = (
    'packaging/systemd/aegis-server.service',
    'packaging/systemd/aegis-client.service',
    'packaging/systemd/aegis-auto-config.service',
    'packaging/systemd/aegis-auto-capture-topology.service',
    'packaging/systemd/aegis-auto-guardian-watchdog.service',
    'packaging/systemd/aegis-auto-guardian.service',
    'packaging/systemd/aegis-auto-terminal-a@.service',
    'packaging/systemd/aegis-auto-terminal-b@.service',
    'packaging/systemd/aegis-auto-terminal-observer.service',
    'packaging/systemd/aegis-auto-terminal-transition.service',
    'packaging/systemd/aegis-auto-trace-rollback-actor.service',
    'packaging/systemd/aegis-auto-trace-rollback.service',
    'packaging/systemd/aegis-auto-trace-rollback.timer',
    'packaging/systemd/aegis-auto-witness-topology.service',
    'packaging/systemd/aegis-foreign-policy-monitor.service',
    'packaging/systemd/aegis-auto-clean-shutdown.service',
    'packaging/systemd/aegis-device-dhcp-refresh.service',
    'packaging/systemd/aegis-device-dhcp-refresh.timer',
    'packaging/systemd/25-relay-geneva-profile.conf',
)
def validate_helper_inventory(value):
    # Closed independently reviewed identities, not a count-only producer claim.
    require(type(value) is list and all(type(name) is str for name in value)
            and len(value) == len(EXPECTED_HELPER_SCRIPTS)
            and len(set(value)) == len(value)
            and tuple(value) == EXPECTED_HELPER_SCRIPTS,
            'exact approved55 helper inventory required')
def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(65536),b''):h.update(block)
    return h.hexdigest()
def regular(path, cap):
    m=path.lstat();require(stat.S_ISREG(m.st_mode) and not path.is_symlink() and 0<m.st_size<=cap,'actual regular producer/input required')
    return path
admin_dirs=list(base.glob('aegis-*-linux-*'))
admin_dirs=[p for p in admin_dirs if p.is_dir() and not p.name.startswith(('aegis-client-','aegis-research-','aegis-package-root-'))]
require(len(admin_dirs)==1,'exact original administrative builder directory required')
admin=admin_dirs[0];manifest=json.loads(regular(admin/'bundle.manifest.json',1048576).read_bytes())
require(admin.name==f"aegis-{manifest['version']}-linux-{manifest['arch']}",'exact original administrative directory identity required')
require(manifest.get('distribution')=='private_administrative_operator','administrative role missing')
research=base/f"aegis-research-{manifest['version']}-linux-{manifest['arch']}"
rm=json.loads(regular(research/'research.manifest.json',65536).read_bytes())
require(rm['distribution']=='private_research_only' and rm['signed_release'] is False,'separate research role required')
require(not (admin/'research').exists() and not (admin/'bin/aegis-transport-lab').exists(),'administrative/research role mixture')
validate_helper_inventory(manifest.get('helper_scripts'))
for name in manifest['helper_scripts']:regular(admin/name,8388608)
require(tuple(manifest.get('systemd_templates', ())) == EXPECTED_SYSTEMD_TEMPLATES,
        'exact AUTO systemd template inventory required')
for name in EXPECTED_SYSTEMD_TEMPLATES:
    unit = regular(admin/name, 65536)
    require(name in manifest['files'] and any(line == f'{sha(unit)}  {name}'
            for line in (admin/'SHA256SUMS').read_text().splitlines()),
            'source-bound AUTO systemd template checksum required')
full=regular(admin/'bin/aegis-measure',536870912)
require(sha(full)==manifest['binaries']['aegis-measure']['sha256'],'administrative manifest identity drift')
with full.open('rb') as producer:require(producer.read(4)==b'\x7fELF','real Linux producer required')
measure=regular(research/'bin/aegis-measure',536870912);lab=regular(research/'bin/aegis-transport-lab',536870912)
require(sha(full)!=sha(measure),'full tool cannot substitute restricted producer')
passed=['administrative-role-and55helpers']
with tempfile.TemporaryDirectory(prefix='aegis-admin-research-contract-') as temp:
    work=pathlib.Path(temp).resolve();os.chmod(work,0o700)
    # Capture private outputs to files, not pipes. The outer CI/QA supervisor owns
    # the complete process group; these pure selectors additionally reap direct children.
    sequence=0
    def run(exe,args,success=True):
        global sequence
        sequence+=1;o=work/f'{sequence}.stdout';e=work/f'{sequence}.stderr'
        with o.open('xb') as out,e.open('xb') as err:
            os.chmod(o,0o600);os.chmod(e,0o600)
            p=subprocess.Popen([str(exe),*map(str,args)],stdin=subprocess.DEVNULL,stdout=out,stderr=err)
            try:rc=p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
                try:p.wait(timeout=2)
                except subprocess.TimeoutExpired:raise AssertionError('direct child cleanup unconfirmed') from None
                raise AssertionError('original10s command cutoff') from None
        require(o.stat().st_size<=65536 and e.stat().st_size<=65536,'bounded output required')
        require((rc==0)==success,'actual selector result disagrees')
        if success:require(e.stat().st_size==0,'successful selector emitted stderr')
        return o.read_bytes()
    stdout=work/'probe.json';stderr=work/'probe.stderr'
    stdout.write_text(json.dumps({'status':'PASS','startup':{'code':'fixture_ready','started_backend':'fixture'}}));stderr.write_text('')
    require(run(full,['tproxy-startup-probe-fields','--stdout',stdout,'--stderr',stderr])==b'PROBE_STATUS\tPASS\nPROBE_CODE\tfixture_ready\nPROBE_STARTED_BACKEND\tfixture\n','actual startup fields changed')
    passed.append('actual-administrative-startup-fields')
    events=work/'events.jsonl';events.write_text(json.dumps({'event_code':'ingress_backend_started','level':'info','message':'fixture','fields':{'backend':'fixture'}})+'\n')
    fields=run(full,['tproxy-runtime-events-summary','--runtime-events-jsonl',events,'--limit','16']).decode().splitlines()
    require('EVENTS_TOTAL\t1' in fields and 'EVENTS_BACKEND\tfixture' in fields,'actual events fields changed');passed.append('actual-administrative-events')
    output=work/'evidence.json'
    run(full,['write-tproxy-operator-evidence','--output',output,'--runtime-events-jsonl',events,'--events-total','1','--startup-health','fixture','--runtime-status','fixture','--product-verdict','fixture','--runtime-degradation-count','0','--failover-count','0','--terminal-failure-count','0'])
    evidence=json.loads(output.read_bytes());require(evidence['artifact_schema']=='wide_linux_operator_evidence_v1' and evidence['records_scanned']==1 and evidence['canonical_operator_loop']==['doctor','probe','launch_or_run','events','evidence'],'actual evidence contract changed');passed.append('actual-administrative-evidence')
    expected_caps={'aegis-measure':['private-control','poisson-control','poisson-insertion','privacy-pcap-export','privacy-study-assemble','privacy-frontier','brain-outcome-replay'],'aegis-transport-lab':['dependencies','topology','awgn','poisson-channel','privacy-channel','bittraps-channel']}
    for name,exe,arg in [('aegis-measure',measure,'research-build-info'),('aegis-transport-lab',lab,'--build-info')]:
        info=json.loads(run(exe,[arg]));captured=json.loads((research/f'research/{name}.build-info.json').read_bytes())
        require(info==captured and info['capabilities']==expected_caps[name] and info['binary_sha256']==sha(exe),'actual restricted identity mismatch')
    help_text=run(measure,['--help']).decode()
    require(all(command in help_text for command in expected_caps['aegis-measure']) and all(command not in help_text for command in ['run-with-timeout','tproxy-startup-probe-fields','write-tproxy-operator-evidence']),'compiled restricted inventory mismatch')
    passed.append('actual-restricted-pair')
    expected=dict(rm['files']);expected['research.manifest.json']=sha(research/'research.manifest.json');expected['SHA256SUMS']=sha(research/'SHA256SUMS')
    actual={str(p.relative_to(research)) for p in research.rglob('*') if p.is_file()};require(actual==set(expected),'whole research tree mismatch')
    archive=regular(base/(research.name+'.tar.gz'),2147483648);seen=set();entries=0
    with tarfile.open(archive,'r:gz') as tar:
        for member in tar:
            entries+=1;require(entries<=len(expected)+3 and member.mode & 0o7000==0,'bounded archive header inventory required')
            if member.isdir():require(member.name.rstrip('/') in {research.name,research.name+'/bin',research.name+'/research'},'unknown archive directory');continue
            require(member.isfile() and member.name.startswith(research.name+'/'),'archive special/foreign leaf')
            leaf=member.name[len(research.name)+1:];require(leaf in expected and leaf not in seen,'extra/duplicate archive leaf');seen.add(leaf)
            cap=536870912 if leaf.startswith('bin/') else 8192 if leaf.endswith('.build-info.json') else 65536 if leaf=='research.manifest.json' else 16384 if leaf=='SHA256SUMS' else 8388608
            require(0<member.size<=cap,'archive member size refused');h=hashlib.sha256();count=0
            with tar.extractfile(member) as f:
                for block in iter(lambda:f.read(65536),b''):
                    count+=len(block);require(count<=cap,'archive expansion refused');h.update(block)
            require(count==member.size,'archive length mismatch')
            require(h.hexdigest()==expected[leaf],'archive member hash drift')
    require(seen==set(expected),'missing archive leaf');require((base/(research.name+'.tar.gz.sha256')).read_text()==sha(archive)+'  '+archive.name+'\n','archive sidecar drift');passed.append('entire-real-archive')
    common=['--version',rm['version'],'--arch',rm['arch'],'--target-triple',rm['target_triple'],'--git-sha',rm['source_commit'],'--cargo-lock-sha256',rm['cargo_lock_sha256']]
    for index,extra in enumerate([None,'bin/full-administrative-tool','helper.sh']):
        copy=work/f'copy-{index}';shutil.copytree(research,copy,symlinks=True)
        (copy/'research.manifest.json').unlink();(copy/'SHA256SUMS').unlink()
        if extra:shutil.copyfile(full,copy/extra)
        run(full,['build-private-research-manifest','--bundle-dir',copy,*common],success=extra is None)
        if extra:require(not (copy/'research.manifest.json').exists() and not (copy/'SHA256SUMS').exists(),'refusal wrote role output')
        passed.append('canonical-role-rebuild' if extra is None else 'extra-'+str(index)+'-refusal')
require(len(passed)==9,'nonzero exact9 contract cases required')
print('PASS admin/research delivery split:9 actual cases')
PY_SPLIT
