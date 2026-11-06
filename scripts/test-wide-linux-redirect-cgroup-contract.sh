#!/usr/bin/env bash
# Inert fixture: exact production helper, with only /proc,/sys,/etc,/var/lib
# redirected to temporary files and firewall/systemd commands replaced.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
export AEGIS_TEST_CLIENT_BINARY="${AEGIS_TEST_CLIENT_BINARY:-$ROOT/target/debug/aegis-client}"
python3 - "$ROOT" <<'PY'
import os, pathlib, re, shutil, subprocess, sys, tempfile
root = pathlib.Path(sys.argv[1])
with tempfile.TemporaryDirectory(prefix="aegis-cgroup-contract-") as tmp:
    t = pathlib.Path(tmp).resolve()
    bin = t / 'bin'; bin.mkdir()
    (t/'lib').mkdir(); shutil.copy(root/'scripts/lib/root-state.sh', t/'lib/root-state.sh')
    source = pathlib.Path(os.environ.get('AEGIS_REDIRECT_HELPER_SOURCE',root/'scripts/setup-wide-linux-redirect.sh')).read_text()
    for prefix in ('/sys/fs/cgroup','/proc','/etc','/var/lib'):
        source = source.replace(prefix, str(t) + prefix)
    helper = t/'helper.sh'; helper.write_text(source)
    helper.chmod(0o755)
    cgroup = t/'sys/fs/cgroup/system.slice/aegis-client.service'; cgroup.mkdir(parents=True)
    (cgroup/'cgroup.procs').write_text('321\n')
    member = t/'proc/321/cgroup'; member.parent.mkdir(parents=True); member.write_text('0::/system.slice/aegis-client.service\n')
    def exe(name, body):
        p = bin/name; p.write_text('#!/usr/bin/env bash\nset -eu\n'+body+'\n'); p.chmod(0o755)
    for command in ('iptables','ip6tables'):
        exe(command, '''printf '%s %s\\n' "$(basename "$0")" "$*" >> "$FIXTURE/log"
if [[ "${3:-}" == -C ]]; then exit 1; fi
if [[ "${FAIL_MATCH:-0}" == 1 && " $* " == *" -m cgroup "* ]]; then exit 1; fi
''')
    realstat = shutil.which('stat')
    exe('stat', '''if [[ "$*" == "-f -c %T "* ]]; then printf '%s\\n' "${FS_TYPE:-cgroup2fs}"; exit; fi
if [[ "$*" == "-c %i "* ]]; then printf '%s\\n' "${CGROUP_INODE_FIXTURE:-777}"; exit; fi
exec '''+repr(realstat)+''' "$@"''')
    exe('systemctl', '''case "$*" in
*"-p ActiveState"*) echo "${ACTIVE_STATE:-active}";;
*"-p MainPID"*) echo 321;;
*"-p ControlGroup"*) echo "${CONTROL_GROUP:-/system.slice/aegis-client.service}";;
*) exit 91;; esac''')
    env = dict(os.environ, PATH=str(bin)+os.pathsep+os.environ['PATH'], FIXTURE=str(t),
        AEGIS_ROOT_STATE_CLIENT=os.environ['AEGIS_TEST_CLIENT_BINARY'],
        AEGIS_WIDE_RESOLVER_SNAPSHOT=str(t/'snapshot.json'), AEGIS_WIDE_REQUIRE_CGROUP='1',
        AEGIS_WIDE_EXEMPT_SERVICE='aegis-client.service', AEGIS_WIDE_EXEMPT_CGROUP='',
        AEGIS_ENABLE_PREROUTING='1', AEGIS_WIDE_INTERFACE='fixture0',
        AEGIS_WIDE_RELAY_EXCLUDE_IPS='198.51.100.10', AEGIS_EXEMPT_UID='0',
        AEGIS_DIRECT_SOCKET_MARK='44641', AEGIS_WIDE_UDP_REDIRECT_PORT='15081',
        AEGIS_WIDE_MANAGE_RESOLV='0')
    def run(action='apply', extra=None, success=True):
        (t/'log').write_text('')
        result = subprocess.run(['bash',str(helper),action],env=env|dict(extra or {}),text=True,capture_output=True)
        assert (result.returncode == 0) == success, (action, extra, result.stdout, result.stderr)
        return (t/'log').read_text(), result.stdout
    log,_ = run()
    for command, table, chain in [('iptables','nat','AEGIS_WIDE_OUTPUT'),('iptables','filter','AEGIS_WIDE_FILTER'),('ip6tables','filter','AEGIS_WIDE_V6')]:
        assert f'{command} -t {table} -A {chain} -m cgroup --path system.slice/aegis-client.service -j RETURN' in log
    assert '--uid-owner' not in log and '-m mark' not in log and '-d 198.51.100.10' not in log
    assert not any('PREROUTING' in line and 'cgroup' in line for line in log.splitlines())
    assert log.index('-N AEGIS_CG_') < log.index('-N AEGIS_WIDE_OUTPUT')
    for action in ('preflight','apply'):
        log,_=run(action, {'FAIL_MATCH':'1'}, False)
        assert 'AEGIS_WIDE_' not in log, log
    for extra in ({'ACTIVE_STATE':'inactive'}, {'FS_TYPE':'tmpfs'},
            {'AEGIS_WIDE_EXEMPT_CGROUP':'other.service'}, {'CONTROL_GROUP':'/'},
            {'CONTROL_GROUP':'/system.slice/../aegis-client.service'},
            {'AEGIS_WIDE_EXEMPT_SERVICE':'aegis-client.service --help'},
            {'AEGIS_WIDE_EXEMPT_SERVICE':'','AEGIS_WIDE_EXEMPT_CGROUP':''},
            {'AEGIS_WIDE_EXEMPT_SERVICE':'','AEGIS_WIDE_EXEMPT_CGROUP':'/'}):
        log,_=run('apply', extra, False); assert not log, (extra,log)
    member.write_text('0::/system.slice/other.service\n')
    log,_=run('apply', success=False); assert not log
    member.write_text('0::/system.slice/aegis-client.service\n')
    # Actual helper generation admission, not a canned validator port.
    pins={'AEGIS_WIDE_EXPECTED_SERVICE_PID':'321','AEGIS_WIDE_EXPECTED_CGROUP_INODE':'777'}
    pinned_log,_=run('apply',pins)
    assert '-m cgroup --path system.slice/aegis-client.service -j RETURN' in pinned_log
    for extra in (
        {'AEGIS_WIDE_EXPECTED_SERVICE_PID':'321'},
        {'AEGIS_WIDE_EXPECTED_CGROUP_INODE':'777'},
        pins|{'AEGIS_WIDE_EXPECTED_SERVICE_PID':'0321'},
        pins|{'AEGIS_WIDE_EXPECTED_CGROUP_INODE':'0'},
        pins|{'AEGIS_WIDE_EXEMPT_SERVICE':''},
        pins|{'AEGIS_WIDE_EXPECTED_SERVICE_PID':'322'},
        pins|{'CGROUP_INODE_FIXTURE':'778'},
    ):
        refused,_=run('apply',extra,False)
        assert not refused, 'generation refusal touched firewall/probe chains'
    # Cleanup admission is independent of captured generation, including an
    # interrupted caller's half-pair and an already stopped/replaced service.
    for extra in (
        {'AEGIS_WIDE_EXPECTED_SERVICE_PID':'321'},
        {'AEGIS_WIDE_EXPECTED_CGROUP_INODE':'777'},
        {'AEGIS_WIDE_EXPECTED_SERVICE_PID':'bad','AEGIS_WIDE_EXPECTED_CGROUP_INODE':'0'},
        pins|{'AEGIS_WIDE_EXPECTED_SERVICE_PID':'322','ACTIVE_STATE':'inactive'},
        pins|{'CGROUP_INODE_FIXTURE':'778','ACTIVE_STATE':'inactive'},
    ):
        cleanup,_=run('teardown',extra)
        assert '-D OUTPUT -p tcp -j AEGIS_WIDE_OUTPUT' in cleanup
        assert '-D OUTPUT -p udp -j AEGIS_WIDE_OUTPUT' in cleanup
        assert '-F AEGIS_WIDE_OUTPUT' in cleanup
        assert '-X AEGIS_WIDE_OUTPUT' in cleanup
    log,output=run('cgroup-path'); assert not log and output.strip()=='system.slice/aegis-client.service'
    # Stopped service may never prevent explicit teardown of the owned rules.
    run('teardown',{'ACTIVE_STATE':'inactive','AEGIS_WIDE_EXEMPT_CGROUP':'missing.service'})
    # Render the actual boot function in an isolated path, never call host systemd.
    install = (root/'install.sh').read_text()
    fn = re.search(r'^install_wide_tun_boot_unit\(\) \{\n.*?^\}', install, re.M|re.S).group()
    fn=fn.replace('/etc/systemd/system/aegis-wide-tun-firewall.service',str(t/'boot.service'))
    fixture=t/'boot.sh';fixture.write_text('set -eu\n'+fn+'\nsystemctl() { :; }\ninstall_wide_tun_boot_unit /owned/helper 15080 0 0 1 1 1 aegis-tun0 15081 "" 1 "" 1 aegis-client.service system.slice/aegis-client.service\n')
    subprocess.run(['bash',str(fixture)],check=True,capture_output=True)
    unit=(t/'boot.service').read_text()
    for line in ('Environment=AEGIS_WIDE_REQUIRE_CGROUP=1','Environment=AEGIS_WIDE_EXEMPT_SERVICE=aegis-client.service','Environment=AEGIS_WIDE_EXEMPT_CGROUP=system.slice/aegis-client.service','PartOf=aegis-client.service','WantedBy=multi-user.target aegis-client.service','ExecStart=/bin/bash /owned/helper apply'):
        assert line in unit
    preflight = re.search(r'^preflight_wide_capture\(\) \{\n.*?^\}', install, re.M|re.S).group()
    fn = re.search(r'^activate_wide_capture\(\) \{\n.*?^\}', install, re.M|re.S).group()
    assert fn.index('bash "$persisted" preflight') < fn.index('set_client_config_wide')
    assert fn.index('restart_systemd_unit_checked') < fn.index('bash "$persisted" cgroup-path') < fn.index('bash "$persisted" apply')
    assert 'if [[ "$require_cgroup" == 1 ]]; then\n    echo "loop-avoidance:' in fn
    assert fn.index('else\n    # Compatibility profiles retain') < fn.index('-I AEGIS_WIDE_OUTPUT 1 -d')
    assert '"$require_cgroup" "$exempt_service" "$exempt_cgroup"; then' in fn
    # Execute the real activation function with unsupported kernel matching.
    # Config writers are sentinels; only fixture helper installation is allowed.
    install_root=t/'install-root';(install_root/'scripts/lib').mkdir(parents=True)
    shutil.copy(helper,install_root/'scripts/setup-wide-linux-redirect.sh')
    shutil.copy(root/'scripts/lib/root-state.sh',install_root/'scripts/lib/root-state.sh')
    cfg=t/'client.toml';cfg.write_text('fixture_config_unchanged\n')
    activation=t/'activation.sh'
    activation.write_text('set -eu\n'+preflight+'\n'+fn+\
        '\nid() { echo 0; }\ninstall_copy_file() { cp "$1" "$2"; }\n'+\
        'client_service_uid() { echo unexpected >> "$FIXTURE/config-mutated"; echo 0; }\n'+\
        'set_client_config_wide() { echo unexpected >> "$FIXTURE/config-mutated"; return 99; }\n'+\
        'activate_wide_capture "$FIXTURE/client.toml" client-ipv6-tun-smoltcp\n')
    (t/'log').write_text('')
    result=subprocess.run(['bash',str(activation)],env=env|{'ROOT':str(install_root),
        'AEGIS_WIDE_LIB_DIR':str(t/'installed'),'FAIL_MATCH':'1'},capture_output=True,text=True)
    assert result.returncode==1 and 'wide config was not changed' in result.stderr,(result.returncode,result.stderr)
    assert not (t/'config-mutated').exists() and cfg.read_text()=='fixture_config_unchanged\n'
    assert 'AEGIS_WIDE_' not in (t/'log').read_text()
    print('PASS: strict IPv4/IPv6 service cgroup rules, no IP/UID/mark or PREROUTING bypass; unsupported match preserves active chains; 9 identity negatives; service readback, teardown and stop/start persistence')
PY
