#!/usr/bin/env python3
"""Assemble unsigned app/systemextension from independently built binaries.
Does not compile, sign, install, inspect profiles, alter trust or request approval.
--product assembles only the two product roles (host app + PacketTunnel
system extension) with an explicit CFBundleVersion; diagnostic helper/child
staging is refused there. Signing inputs for product mode are the committed
packaging/entitlements files, so no review entitlement files are written.
"""
import argparse, pathlib, plistlib, re, hashlib, json
LEGAL_PINS = {
    'THIRD-PARTY-NOTICES': 'd2bfa7f7fe9fb79cf1d66df2ce3e6f6131df46ef4d39fdd70c1ceb4839e0f05c',
    'NOTICE': '18bb6bc0341670e47be1456822ffffce67e230be1c773f4a162a68d537d62a6e',
    'LICENSE-MIT': 'bdb914c4ba714c6509046bf116dddb9b2ec0073db5b1db68ef1588baf7a3294b',
    'LICENSE-APACHE': 'a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2',
    'LICENSE-LIBVPX': '8267348d5af1262c11d1a08de2f5afc77457755f1ac658627dd9acf71011d615',
}
p=argparse.ArgumentParser()
for n in ('output','host_binary','provider_binary','app_id','provider_id','app_group','team_id'):
    p.add_argument('--'+n.replace('_','-'),required=True)
p.add_argument('--helper-binary')
p.add_argument('--child-binary')
p.add_argument('--product',action='store_true')
p.add_argument('--bundle-version')
p.add_argument('--short-version')
a=p.parse_args()
if a.product and (a.helper_binary or a.child_binary):
    raise SystemExit('product mode packages host and provider only; diagnostic helper/child are excluded')
if a.product and not (a.bundle_version and a.short_version):
    raise SystemExit('product mode requires explicit --bundle-version and --short-version')
bundle_version=a.bundle_version or '1'
short_version=a.short_version or '0.1.0'
# CFBundleVersion: one to three period-separated non-negative integers.
if not re.fullmatch(r'[1-9][0-9]{0,8}(\.(0|[1-9][0-9]{0,8})){0,2}',bundle_version):
    raise SystemExit('invalid CFBundleVersion')
if not re.fullmatch(r'(0|[1-9][0-9]{0,8})(\.(0|[1-9][0-9]{0,8})){0,2}',short_version):
    raise SystemExit('invalid CFBundleShortVersionString')
staged=bool(a.helper_binary or a.child_binary)
if staged and not (a.helper_binary and a.child_binary):
    raise SystemExit('helper and child binaries must be staged together')
helper_id='dev.aegis.macos.ObserveHelper'
child_id='dev.aegis.macos.ObserveChild'
if (staged or a.product) and (a.app_id!='dev.aegis.macos' or
        a.provider_id!='dev.aegis.macos.PacketTunnel' or
        a.app_group!='group.TEAMID0000.dev.aegis.macos' or
        a.team_id!='TEAMID0000'):
    raise SystemExit('staged helper/child and product mode require exact reviewed Aegis identities')
for ident in (a.app_id,a.provider_id,a.app_group):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{2,180}',ident):raise SystemExit('invalid bundle/group identifier')
if not re.fullmatch(r'[A-Z0-9]{10}',a.team_id):raise SystemExit('invalid team identifier')
if a.app_id==a.provider_id or not a.provider_id.startswith(a.app_id+'.'):raise SystemExit('provider must be distinct child bundle ID')
# Apple Developer prefixes App Group identifiers with "group.". Keep the
# namespace bound to the exact supplied signing team for the Mach service.
if not a.app_group.startswith('group.'+a.team_id+'.'):raise SystemExit('macOS systemextension app group must use group.<team-id>. prefix')
inputs=[]
for name in (a.host_binary,a.provider_binary,*(([a.helper_binary,a.child_binary]) if staged else [])):
    f=pathlib.Path(name)
    if not f.is_absolute() or f.is_symlink() or not f.is_file():raise SystemExit('absolute regular built binary required')
    if f.stat().st_size > 200*1024*1024:raise SystemExit('binary too large')
    raw=f.read_bytes()
    if len(raw) > 200*1024*1024:raise SystemExit('binary too large')
    if raw[:4] not in (b'\xcf\xfa\xed\xfe',b'\xfe\xed\xfa\xcf',b'\xca\xfe\xba\xbe',b'\xbe\xba\xfe\xca'):
        raise SystemExit('native Mach-O binary required')
    # Hash and copy the same captured bytes; never reopen a path after check.
    inputs.append((hashlib.sha256(raw).hexdigest(),raw))
# Read the exact committed legal source bytes before opening the output. The
# notices are a reviewed Cargo graph superset, not a complete native SBOM.
# The pinned libvpx text covers the optional native VP8 dependency; it does
# not prove the native archive was linked into a particular provider binary.
root=pathlib.Path(__file__).resolve().parents[3]
legal=[]
if a.product:
    for name,want in LEGAL_PINS.items():
        source=(pathlib.Path(__file__).resolve().parent/'legal/LICENSE-LIBVPX'
                if name=='LICENSE-LIBVPX' else root/name)
        if source.is_symlink() or not source.is_file():
            raise SystemExit('pinned legal source missing or linked')
        raw=source.read_bytes()
        if len(raw)>2*1024*1024 or hashlib.sha256(raw).hexdigest()!=want:
            raise SystemExit('pinned legal source differs from reviewed bytes')
        legal.append((name,want,raw))
out=pathlib.Path(a.output)
if not out.is_absolute():raise SystemExit('absolute fresh output required')
out.mkdir(mode=0o700,exist_ok=False)
app=out/'AEGIS.app';ext=app/'Contents/Library/SystemExtensions'/f'{a.provider_id}.systemextension'
for bundle,binary,exe,ident,kind in ((app,inputs[0][1],'aegis-ne-host',a.app_id,'APPL'),(ext,inputs[1][1],'aegis-ne-provider',a.provider_id,'SYSX')):
    (bundle/'Contents/MacOS').mkdir(parents=True,exist_ok=False)
    target=bundle/'Contents/MacOS'/exe;target.write_bytes(binary);target.chmod(0o755)
    info={'CFBundleExecutable':exe,'CFBundleIdentifier':ident,'CFBundleName':'AEGIS','CFBundleVersion':bundle_version,'CFBundleShortVersionString':short_version,'CFBundlePackageType':kind,'LSMinimumSystemVersion':'14.4'}
    # S20b: the same system extension also serves the packet filter (one
    # process for both providers; NEFilterManager names this bundle id).
    if kind=='SYSX':info['NetworkExtension']={'NEMachServiceName':a.app_group+'.packet-tunnel','NEProviderClasses':{
        'com.apple.networkextension.packet-tunnel':'AegisPacketTunnelProvider',
        'com.apple.networkextension.filter-packet':'AegisFilterPacketProvider'}}
    # sysextd refuses a network_extension-category system extension without it.
    if kind=='SYSX':info['NSSystemExtensionUsageDescription']='AEGIS uses this network extension to send your traffic through your AEGIS relay and, while the tunnel runs, to stop traffic from leaving outside it.'
    # v39: the containing app opened from Finder is a menu-bar app (no Dock
    # icon, no app menu); its CLI verbs are unchanged.
    if kind=='APPL':info['LSUIElement']=True
    # v45: the menu is English (base) or Russian, chosen in code from the
    # system language; declaring both lets macOS show its own panels (the
    # invitation file picker, alert buttons it adds) in Russian as well.
    if kind=='APPL':info['CFBundleDevelopmentRegion']='en';info['CFBundleLocalizations']=['en','ru']
    (bundle/'Contents/Info.plist').write_bytes(plistlib.dumps(info,sort_keys=True))
if a.product:
    legal_dir=app/'Contents/Resources/Legal'
    legal_dir.mkdir(parents=True,exist_ok=False)
    for name,want,raw in legal:
        target=legal_dir/name
        target.write_bytes(raw)
        if hashlib.sha256(target.read_bytes()).hexdigest()!=want:
            raise SystemExit('legal resource readback differs')
if staged:
    helpers=app/'Contents/Library/Helpers'
    for ident,binary,exe in ((helper_id,inputs[2][1],'aegis-ne-observe-helper'),
                             (child_id,inputs[3][1],'aegis-ne-observe-child')):
        bundle=helpers/f'{ident}.app'
        (bundle/'Contents/MacOS').mkdir(parents=True,exist_ok=False)
        target=bundle/'Contents/MacOS'/exe
        target.write_bytes(binary);target.chmod(0o755)
        info={'CFBundleExecutable':exe,'CFBundleIdentifier':ident,
              'CFBundleName':ident.rsplit('.',1)[-1],
              'CFBundleVersion':'1','CFBundleShortVersionString':'0.1.0',
              'CFBundlePackageType':'APPL','LSMinimumSystemVersion':'14.4',
              'LSBackgroundOnly':True}
        (bundle/'Contents/Info.plist').write_bytes(plistlib.dumps(info,sort_keys=True))
# Review inputs only: these are not applied entitlements or signed profiles.
for name,host in (() if a.product else (('host.entitlements',True),('provider.entitlements',False))):
    ident=a.app_id if host else a.provider_id
    d={'com.apple.application-identifier':a.team_id+'.'+ident,
       'com.apple.developer.team-identifier':a.team_id,
       'com.apple.developer.networking.networkextension':['content-filter-provider-systemextension','packet-tunnel-provider-systemextension'],
       'com.apple.security.application-groups':[a.app_group]}
    if host:d['com.apple.developer.system-extension.install']=True
    (out/name).write_bytes(plistlib.dumps(d,sort_keys=True))
if staged:
    for ident,name in ((helper_id,'helper.entitlements'),(child_id,'child.entitlements')):
        d={'com.apple.application-identifier':a.team_id+'.'+ident,
           'com.apple.developer.team-identifier':a.team_id,
           'com.apple.security.application-groups':[a.app_group]}
        (out/name).write_bytes(plistlib.dumps(d,sort_keys=True))
    profile_paths={
        a.app_id:'AEGIS.app/Contents/embedded.provisionprofile',
        a.provider_id:f'AEGIS.app/Contents/Library/SystemExtensions/{a.provider_id}.systemextension/Contents/embedded.provisionprofile',
        helper_id:f'AEGIS.app/Contents/Library/Helpers/{helper_id}.app/Contents/embedded.provisionprofile',
        child_id:f'AEGIS.app/Contents/Library/Helpers/{child_id}.app/Contents/embedded.provisionprofile',
    }
    (out/'profiles-expected.json').write_text(json.dumps({
        'schema':1,'profiles_included':False,'expected_embedded_paths':profile_paths,
    },sort_keys=True,indent=2)+'\n')
manifest={'schema':1,'signed':False,'installed':False,'native_acceptance':False,
          'runtime_observed':False,'inputs_sha256':[h for h,_ in inputs]}
if a.product:
    manifest.update({'product_mode':True,'roles':[a.app_id,a.provider_id],
                     'bundle_version':bundle_version,'short_version':short_version,
                     'profiles_included':False,'entitlements':'committed packaging/entitlements',
                     'legal_resources':{name:sha for name,sha,_ in legal},
                     'legal_scope':'reviewed Cargo graph superset; native/system completeness pending'})
if staged:
    manifest.update({'helper_child_staged':True,'profiles_included':False,
                     'xpc_service_registered':False,'child_ready':False})
# No factory claim: the assembler only checks Mach-O magic and hashes inputs,
# so it cannot state whether a provider registers FACTORY (S07+ source does).
(out/'assembly.json').write_text(json.dumps(manifest,indent=2)+'\n')
