#!/usr/bin/env python3
"""Behavioural admission cases with the real Ubuntu 26.04 stock UFW shape."""
import copy
import contextlib
import hashlib
import io
import importlib.util
import json
from pathlib import Path
import sys
import subprocess
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/lib'))
import aegis_auto_foreign_policy as p


_READ_TEXT = Path.read_text


def legacy_tables(path, *args, **kwargs):
    """Hermetic /proc/net/*_tables_names (unreadable to an unprivileged runner)."""
    if str(path).startswith('/proc/net/') and str(path).endswith('_tables_names'):
        return 'filter nat\n'
    return _READ_TEXT(path, *args, **kwargs)


def no_prefetch(*argvs):
    """For tests that replace run(): dispatch stays by argv, no real readers."""
    return contextlib.nullcontext()


class FakeProc:
    """Popen stand-in on the fallback (no pidfd) wait path."""
    def __init__(self,rc,timeouts,now,advance=0.0,hang=False,events=None,argv=None):
        self.rc,self.timeouts,self.now,self.advance,self.hang=rc,timeouts,now,advance,hang
        self.events,self.argv,self.returncode,self.killed=events,argv,None,False
    def wait(self,timeout=None):
        if self.returncode is not None:return self.returncode
        if timeout is not None:self.timeouts.append(timeout)
        if self.hang and not self.killed:
            self.now[0]+=timeout
            raise subprocess.TimeoutExpired('fixture',timeout)
        self.now[0]+=self.advance
        self.returncode=-9 if self.killed else self.rc
        if self.events is not None:self.events.append(('reap',self.argv))
        return self.returncode
    def poll(self):return self.returncode
    def kill(self):
        self.killed=True
        if self.events is not None:self.events.append(('kill',self.argv))


class ForeignPolicy(unittest.TestCase):
    def test_only_pid1_reads_retry_within_original_budget_and_never_log_stderr(self):
        results=[1,0];timeouts=[];now=[0.0]
        def spawn(argv,output,errors):
            rc=results.pop(0)
            (errors if rc else output).write(b'Failed to connect to bus: PRIVATE_SENTINEL'if rc else b'fresh-readback')
            return FakeProc(rc,timeouts,now,advance=1.0),None
        with mock.patch.object(p,'_spawn',side_effect=spawn), \
             mock.patch.object(p.time,'monotonic',side_effect=lambda:now[0]), \
             mock.patch.object(p.time,'sleep')as pause,contextlib.redirect_stderr(io.StringIO())as errors:
            self.assertEqual(p.run('systemctl','show','fixture.service'),b'fresh-readback')
            self.assertEqual(timeouts,[3,2]);self.assertNotIn('PRIVATE_SENTINEL',errors.getvalue())
            pause.assert_called_once_with(0.025)
        for argv in (('nft','--json','list','ruleset'),('systemctl','stop','fixture.service')):
            results[:]=[1];timeouts.clear()
            with mock.patch.object(p,'_spawn',side_effect=spawn)as query:
                with self.assertRaises(p.PolicyInputUnavailable):p.run(*argv)
                query.assert_called_once()

    def test_pid1_read_retries_only_transient_within_original_deadline(self):
        now=[0.0]
        for stderr in (b'Permission denied', b'Unit not found', b'PRIVATE_SENTINEL'):
            def failed(argv,output,errors):
                errors.write(stderr)
                return FakeProc(1,[],now),None
            with self.subTest(stderr=stderr), mock.patch.object(p,'_spawn',side_effect=failed)as query, \
                 mock.patch.object(p.time,'sleep')as pause,contextlib.redirect_stderr(io.StringIO())as errors:
                with self.assertRaises(p.PolicyInputUnavailable):
                    p.run('systemctl','show','fixture.service')
                query.assert_called_once();pause.assert_not_called()
                self.assertNotIn('PRIVATE_SENTINEL',errors.getvalue())
        def busy(argv,output,errors):
            errors.write(b'Failed to connect to bus')
            return FakeProc(1,[],now,advance=3.1),None
        now[0]=0.0
        with mock.patch.object(p,'_spawn',side_effect=busy)as query, \
             mock.patch.object(p.time,'monotonic',side_effect=lambda:now[0]), \
             mock.patch.object(p.time,'sleep')as pause,contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(p.PolicyInputUnavailable):
                p.run('systemctl','show','fixture.service')
            query.assert_called_once();pause.assert_not_called()

    def test_lazy_stop_candidate_reads_revoked_receipts_then_checks_complete_snapshot(self):
        from test_auto_guard_policy import STATE, BOOT_ID, kernel_rows, kernel_text, encoded
        client={'schema':'aegis_device_guard_binding_v1','boot_id':BOOT_ID,
                'state_sha256':hashlib.sha256(STATE.rstrip(b'\n')).hexdigest(),
                'path':'system.slice/aegis-auto@'+'a'*64+'.service',
                'inode':'77','invocation':'b'*32}
        table=kernel_rows(STATE,client);reads=[];observed=mock.Mock()
        def read(path,*args):
            if str(path).endswith('-binding'):
                reads.append('receipt');raise FileNotFoundError()
            return STATE
        def candidates():
            self.assertEqual(reads[-2:],['receipt','receipt'])
            return [{'client':client,'manager':None}]
        def nft(*args):return encoded(table)if '--json'in args else kernel_text(table)
        with mock.patch.object(p,'trusted_read',side_effect=read),mock.patch.object(p,'run',side_effect=nft), \
             mock.patch.object(p,'prefetch',side_effect=no_prefetch), \
             mock.patch.object(Path,'read_text',return_value=BOOT_ID):
            self.assertEqual(p.verified_owned_tables(table,Path('/fixture/state'),
                binding_candidate_provider=candidates,binding_observer=observed,
                expected_state_sha256=hashlib.sha256(STATE.rstrip(b'\n')).hexdigest()),
                {('inet','aegis_device_guard')})
            observed.assert_called_once_with({'client':client,'manager':None});observed.reset_mock()
            unused=mock.Mock(side_effect=AssertionError('valid receipt must not query PID1 again'))
            self.assertEqual(p.verified_owned_tables(table,Path('/fixture/state'),
                binding_overrides={'client':client,'manager':None},
                binding_candidate_provider=unused),{('inet','aegis_device_guard')})
            unused.assert_not_called()
            unsafe=copy.deepcopy(table['nftables'][-1]);unsafe['rule']['handle']=999
            unsafe['rule']['expr']=[{'counter':{'packets':0,'bytes':0}},{'accept':None}]
            unsafe['rule'].pop('comment',None);table['nftables'].append(unsafe)
            with self.assertRaisesRegex(p.ForeignPolicyRefused,'persistent guard differs'):
                p.verified_owned_tables(table,Path('/fixture/state'),binding_candidate_provider=candidates,binding_observer=observed)
            observed.assert_not_called()

    def test_preapply_state_change_refused_before_kernel_readback(self):
        table={'nftables':[{'table':{'family':'inet','name':'aegis_device_guard'}}]}
        with mock.patch.object(p,'trusted_read',return_value=b'schema=changed\n'), \
             mock.patch.object(p,'prefetch',side_effect=AssertionError('kernel readback must not start')):
            with self.assertRaisesRegex(p.ForeignPolicyRefused,'preapply guard state changed'):
                p.verified_owned_tables(table,Path('/fixture/state'),
                    expected_state_sha256='0'*64)

    def setUp(self):
        self.fixture=json.loads((Path(__file__).parent/'fixtures/ufw-0.36.2-nft-filter.json').read_bytes())
        self.rules=self.fixture['nft']
        self.saves={k:self.fixture[k].encode() for k in ('ip','ip6')}
        self.legacy=[self.fixture[k].encode() for k in ('legacy4','legacy6')]

    def admit(self):
        return p.assess_rules(self.rules,self.saves,self.legacy)

    def test_stock_enabled_both_families(self):
        self.assertTrue(self.admit())

    def test_disabled_residual_rules_same_admission(self):
        # The enabled bit is a separate code/config integrity check. Residual
        # stock filter rules retain exactly the same safe packet semantics.
        self.assertTrue(self.admit())

    def test_empty_never_enabled(self):
        self.assertEqual(p.assess_rules({'nftables':[]},{'ip':b'','ip6':b''},[b'',b'']),[])

    def test_every_mutating_statement_both_families(self):
        mutations=[{'mangle':{'key':{'meta':{'key':'mark'}},'value':1}},
            {'queue':{'num':0}}, {'dup':{'addr':'192.0.2.1'}}, {'fwd':{'dev':'lo'}},
            {'snat':{'addr':'192.0.2.1'}}, {'dnat':{'addr':'192.0.2.1'}},
            {'masquerade':None}, {'redirect':{'port':7}}, {'tproxy':{'port':7}},
            {'notrack':None}, {'synproxy':{}}, {'flow':{'op':'add','flowtable':'f'}},
            {'set':{'op':'update','set':'a','elem':1}}, {'log':{'group':1}},
            {'secmark':{'value':1}}, {'unknown':None}]
        for family in ('ip','ip6'):
            row=next(x['rule'] for x in self.rules['nftables'] if 'rule' in x and x['rule']['family']==family)
            original=copy.deepcopy(row['expr'])
            for mutation in mutations:
                with self.subTest(family=family,mutation=mutation):
                    row['expr']=[mutation]
                    with self.assertRaises(p.ForeignPolicyRefused):self.admit()
            row['expr']=original

    def test_xt_targets_and_unknown_names(self):
        for name in ('NFQUEUE','TEE','MARK','CONNMARK','CT','NOTRACK','TPROXY','NFLOG','UNKNOWN'):
            with self.subTest(name=name):
                with self.assertRaises(p.ForeignPolicyRefused):
                    p.statement({'xt':{'type':'target','name':name}},set())
        with self.assertRaises(p.ForeignPolicyRefused):
            p.statement({'xt':{'type':'match','name':'bpf'}},set())

    def test_route_nat_any_priority(self):
        for typ in ('route','nat'):
            for prio in (-500,0,20,100,2**31-1):
                rules=copy.deepcopy(self.rules)
                chain=next(x['chain'] for x in rules['nftables'] if 'chain' in x and 'hook' in x['chain'])
                chain.update(type=typ,prio=prio)
                with self.subTest(typ=typ,priority=prio):
                    with self.assertRaises(p.ForeignPolicyRefused):
                        p.assess_rules(rules,self.saves,self.legacy)

    def test_final_output_priority_is_reserved_for_owned_guard(self):
        for priority in (2147483646, 2147483647):
            rules=copy.deepcopy(self.rules)
            rules['nftables'] += [
                {'table':{'family':'inet','name':'late_filter'}},
                {'chain':{'family':'inet','table':'late_filter','name':'out',
                          'type':'filter','hook':'output','prio':priority,'policy':'accept'}}]
            if priority == 2147483647:
                with self.assertRaisesRegex(p.ForeignPolicyRefused,'final guard priority'):
                    p.assess_rules(rules,self.saves,self.legacy)
            else:
                p.assess_rules(rules,self.saves,self.legacy)

    def test_stateful_objects_unknown_fields_and_families(self):
        for obj in ({'flowtable':{'family':'ip','table':'filter','name':'f'}},
            {'counter':{'family':'ip','table':'filter','name':'c'}},
            {'table':{'family':'bridge','name':'filter'}},
            {'table':{'family':'inet','name':'another','flags':['owner']}}):
            self.rules['nftables'].append(obj)
            with self.assertRaises(p.ForeignPolicyRefused):self.admit()
            self.rules['nftables'].pop()

    def test_unverified_aegis_names(self):
        for name in (*p.OWNED,'aegis_other'):
            self.rules['nftables'].append({'table':{'family':'inet','name':name}})
            with self.assertRaises(p.ForeignPolicyRefused):self.admit()
            self.rules['nftables'].pop()

    def test_save_chain_disagreement(self):
        self.saves['ip']=self.saves['ip'].replace(b':ufw-user-input - [0:0]\n',b'')
        with self.assertRaises(p.ForeignPolicyRefused):self.admit()

    def test_valid_save_with_extra_safe_chain_still_requires_json_agreement(self):
        for family in ('ip','ip6'):
            original=self.saves[family]
            changed=original.replace(b'COMMIT\n',b':ufw-extra-safe-chain - [0:0]\nCOMMIT\n')
            # Each representation is independently safe. Only their mismatch
            # must cause refusal; a malformed jump cannot mask this check.
            p.parse_save(changed)
            self.saves[family]=changed
            with self.subTest(family=family),self.assertRaises(p.ForeignPolicyRefused):self.admit()
            self.saves[family]=original

    def test_save_extension_disagreement(self):
        self.saves['ip']=self.saves['ip'].replace(b'-m conntrack',b'-m state')
        with self.assertRaises(p.ForeignPolicyRefused):self.admit()

    def test_legacy_rules_and_custom_chains(self):
        for raw in (b'*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -j ACCEPT\nCOMMIT\n',
                    b'*filter\n:x - [0:0]\nCOMMIT\n'):
            self.legacy[0]=raw
            with self.assertRaises(p.ForeignPolicyRefused):self.admit()

    def test_duplicate_json_and_size_bounds(self):
        for raw in (b'{"nftables":[],"nftables":[]}',b'{"x":NaN}',b' '*(p.MAX_INPUT+1)):
            with self.assertRaises(ValueError):p.decode(raw)

    def test_unknown_nested_read_and_write(self):
        for v in ({'meta':{'key':'mark'}},{'ct':{'key':'helper'}},
                  {'payload':{'protocol':'tcp','field':'dport','set':1}}):
            with self.assertRaises(p.ForeignPolicyRefused):p.readonly(v)

    def test_normalization_keeps_semantic_order(self):
        first=[{'rule':{'expr':[{'accept':None}],'handle':1}},
               {'rule':{'expr':[{'drop':None}],'handle':2}}]
        self.assertNotEqual(p.digest(p.normalize(first)),p.digest(p.normalize(first[::-1])))
        changed=copy.deepcopy(self.rules)
        for item in changed['nftables']:
            obj=next(iter(item.values()))
            if isinstance(obj,dict):obj.pop('handle',None)
            for e in obj.get('expr',[]):
                if 'counter' in e:e['counter']={'packets':123,'bytes':456}
        self.assertEqual(p.normalize(self.rules),p.normalize(changed))

    def test_snapshot_mismatch_fingerprints_never_retain_private_rule_values(self):
        first={'nftables':[{'rule':{'expr':[{'drop':None}]}}]}
        second={'nftables':[{'rule':{'comment':'PRIVATE_SENTINEL',
                                  'expr':[{'accept':None}]}}]}
        error=p.PolicySnapshotChanged(p.normalize(first),p.normalize(second))
        self.assertIsInstance(error,p.ForeignPolicyRefused)
        self.assertEqual((error.changed_index,error.first_kind,error.second_kind),(0,'rule','rule'))
        self.assertEqual(error.first_sha256,p.digest(p.normalize(first)))
        self.assertNotEqual(error.first_sha256,error.second_sha256)
        self.assertNotIn('PRIVATE_SENTINEL',str(vars(error))+str(error))
        owned_first={'nftables':[{'rule':{'family':'inet','table':'aegis_device_guard',
                                        'expr':[{'drop':None}]}}]}
        owned_second=copy.deepcopy(owned_first)
        owned_second['nftables'][0]['rule']['comment']='PRIVATE_SENTINEL'
        changed=p.PolicySnapshotChanged(owned_first,owned_second)
        self.assertFalse(changed.foreign_changed)
        self.assertEqual(changed.owned_changes[0]['table'],'aegis_device_guard')
        self.assertNotIn('PRIVATE_SENTINEL',str(vars(changed)))
        for malformed in ([],None,{'PRIVATE_SENTINEL':'secret'},{'nftables':None},
                          {'nftables':[{'rule':{'family':[], 'table':{}}}]},
                          {'nftables':[{'PRIVATE_SENTINEL':'secret'}]}):
            with self.subTest(value=type(malformed).__name__):
                error=p.PolicySnapshotChanged(first,malformed)
                self.assertIn(error.second_kind,('unknown','absent','rule'))
                self.assertNotIn('PRIVATE_SENTINEL',str(vars(error))+str(error))

    def test_bpf_query_uses_full_output_union_and_refuses_programs(self):
        from unittest import mock
        import ctypes,errno,struct
        for outcome in ('empty','attached','unavailable','not_netkit','missing_interface','denied_netkit'):
            sizes=[]
            def syscall(number,command,buffer,size):
                self.assertEqual(number.value,321);sizes.append(size.value)
                self.assertEqual(size.value,256)
                if command.value==31:
                    ctypes.set_errno(errno.ENOENT);return -1
                self.assertEqual(command.value,16)
                attach=struct.unpack_from('I',ctypes.string_at(buffer,256),4)[0]
                if outcome=='unavailable':
                    ctypes.set_errno(errno.EPERM);return -1
                if outcome in ('not_netkit','missing_interface','denied_netkit') and attach in (54,55):
                    ctypes.set_errno({'not_netkit':errno.ENXIO,'missing_interface':errno.ENODEV,'denied_netkit':errno.EACCES}[outcome]);return -1
                # Emulate the kernel's modern tail output, not merely prog_cnt.
                ctypes.memmove(ctypes.cast(buffer,ctypes.c_void_p).value+64,
                               struct.pack('Q',123),8)
                ctypes.memmove(ctypes.cast(buffer,ctypes.c_void_p).value+24,
                               struct.pack('I',int(outcome=='attached')),4)
                return 0
            fake=mock.Mock(syscall=syscall)
            with mock.patch.object(p.ctypes,'CDLL',return_value=fake), \
                 mock.patch.object(p.platform,'machine',return_value='x86_64'), \
                 mock.patch.object(p.socket,'if_nametoindex',return_value=1):
                if outcome in ('empty','not_netkit'):p.bpf_bindings(['lo'])
                else:
                    with self.assertRaises(ValueError):p.bpf_bindings(['lo'])
            self.assertTrue(sizes)

    def test_every_prohibited_bpf_link_type_refuses_and_closes_owned_fd(self):
        from unittest import mock
        import ctypes,errno,struct
        for kind in (6,10,11,13):
            def syscall(number,command,buffer,size):
                self.assertEqual(size.value,256)
                address=ctypes.cast(buffer,ctypes.c_void_p).value
                if command.value==31:
                    ctypes.memmove(address+4,struct.pack('I',1),4);return 0
                if command.value==30:return 77
                self.assertEqual(command.value,15)
                _,_,info=struct.unpack_from('IIQ',ctypes.string_at(buffer,16))
                ctypes.memmove(info,struct.pack('I',kind),4);return 0
            with self.subTest(link_type=kind), \
                 mock.patch.object(p.ctypes,'CDLL',return_value=mock.Mock(syscall=syscall)), \
                 mock.patch.object(p.platform,'machine',return_value='x86_64'), \
                 mock.patch.object(p.os,'close') as close:
                with self.assertRaisesRegex(ValueError,'BPF link'):p.bpf_bindings(['lo'])
                close.assert_called_once_with(77)

    def active_trace(self):
        rows=[{'table':{'family':'inet','name':'aegis_auto_witness','handle':1}},
            {'chain':{'family':'inet','table':'aegis_auto_witness','name':'trace_out','type':'filter','hook':'output','prio':-200,'policy':'accept','handle':1}}]
        for nonce in range(6):
            def match(left,right):return {'match':{'op':'==','left':left,'right':right}}
            expr=[match({'meta':{'key':'oifname'}},'witness0'),
                match({'payload':{'protocol':'ip6','field':'daddr'}},'2001:db8::2'),
                match({'payload':{'protocol':'udp','field':'sport'}},40001),
                match({'payload':{'protocol':'udp','field':'dport'}},40002),
                match({'payload':{'base':'th','offset':64,'len':96}},hex(nonce)),
                {'mangle':{'key':{'meta':{'key':'nftrace'}},'value':1}}]
            rows.append({'rule':{'family':'inet','table':'aegis_auto_witness','chain':'trace_out','expr':expr,'handle':nonce+2}})
        return {'nftables':rows}

    def test_active_trace_requires_exact_read_only_tuple_and_six_distinct_nonces(self):
        value=self.active_trace();p.verify_active_trace_table(value)
        for mutation in ('mark','queue','accept','extra','missing','priority','chain','duplicate_nonce','tuple','foreign_peer'):
            changed=copy.deepcopy(value)
            if mutation in ('mark','queue','accept'):
                changed['nftables'][2]['rule']['expr'][-1]={'mark':{'mangle':{'key':{'meta':{'key':'mark'}},'value':1}},'queue':{'queue':{'num':1}},'accept':{'accept':None}}[mutation]
            elif mutation=='extra':changed['nftables'].append(copy.deepcopy(changed['nftables'][-1]))
            elif mutation=='missing':changed['nftables'].pop()
            elif mutation=='priority':changed['nftables'][1]['chain']['prio']=20
            elif mutation=='chain':changed['nftables'][1]['chain']['policy']='drop'
            elif mutation=='duplicate_nonce':changed['nftables'][3]['rule']['expr'][4]['match']['right']='0x0'
            elif mutation=='tuple':changed['nftables'][3]['rule']['expr'][2]['match']['right']=41000
            elif mutation=='foreign_peer':changed['nftables'][2]['rule']['expr'][1]['match']['right']='2001:4860::1'
            with self.subTest(mutation=mutation),self.assertRaises((ValueError,TypeError)):p.verify_active_trace_table(changed)

    def test_missing_guard_is_refused_only_after_arm(self):
        from unittest import mock
        import tempfile
        def command(*args):
            if args==('iptables','-V'):return b'iptables v1.8.11 (nf_tables)'
            if args[0]=='nft':return b'{"nftables":[]}'
            return b''
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(p.os,'geteuid',return_value=0), \
             mock.patch.object(p,'ufw_integrity',return_value={'class':'absent','sha256':'a'*64,'enabled':False}), \
             mock.patch.object(p,'check_links'),mock.patch.object(p,'run',side_effect=command), \
             mock.patch.object(Path,'read_text',autospec=True,side_effect=legacy_tables), \
             mock.patch.object(p,'prefetch',side_effect=no_prefetch):
            state=Path(tmp)/'not-published'
            self.assertEqual(p.assess_foreign_policy('eth0',state_path=state)['class'],'filter_only')
            with self.assertRaisesRegex(p.ForeignPolicyRefused,'guard table missing'):
                p.assess_foreign_policy('eth0',state_path=state,require_guard=True)

    def test_cached_code_matches_pinned_source_semantics(self):
        import importlib.util,marshal
        source=b"def nested(x):\n    return x+1\n"
        name='/usr/lib/python3/dist-packages/ufw/fixture.py'
        def cache(code):return importlib.util.MAGIC_NUMBER+b"\0"*12+marshal.dumps(code)
        raw=cache(compile(source,name,'exec',dont_inherit=True))
        p.verify_bytecode(raw,source,name)
        mutated=cache(compile(b"raise RuntimeError('never executed')",name,'exec'))
        with self.assertRaises(p.ForeignPolicyRefused):p.verify_bytecode(mutated,source,name)
        for invalid in (raw+b'foreign',b'xxxx'+raw[4:],raw[:4]+(7).to_bytes(4,'little')+raw[8:]):
            with self.assertRaises(ValueError):p.verify_bytecode(invalid,source,name)

    def test_filter_jump_log_reject_limit_and_sets(self):
        for expr in ({'jump':{'target':'f2b-sshd'}},{'goto':{'target':'f2b-sshd'}},
                     {'log':{'prefix':'ban','level':'warn'}},
                     {'reject':{'type':'tcp reset'}},
                     {'limit':{'rate':3,'per':'minute','burst':10}},
                     {'match':{'op':'in','left':{'payload':{'protocol':'ip','field':'saddr'}},'right':'@bans'}}):
            p.statement(expr,{'f2b-sshd'})

class ConcurrentPolicyReads(unittest.TestCase):
    """Independent readers start together; results keep the original order."""

    def host(self,outputs,hang=()):
        events=[];now=[0.0];counts={}
        def spawn(argv,output,errors):
            events.append(('spawn',argv))
            index=counts.get(argv,0);counts[argv]=index+1
            value=outputs.get(argv,(0,b''))
            if type(value) is list:value=value[index]
            rc,data=value
            (errors if rc else output).write(data)
            return FakeProc(rc,[],now,hang=argv in hang,events=events,argv=argv),None
        return events,now,spawn

    def test_link_reads_start_together_and_refuse_in_original_order(self):
        links=json.dumps([{'ifname':'lo'},{'ifname':'eth0'},{'ifname':'other'}]).encode()
        reads=[('tc','-j','qdisc','show','dev',n) for n in ('lo','eth0')]
        outputs={p.LINK_INVENTORY:(0,links),
                 ('tc','-j','qdisc','show','dev','lo'):(0,b'[]'),
                 ('tc','-j','qdisc','show','dev','eth0'):(0,b'[]')}
        for name in ('lo','eth0'):
            for direction in ('ingress','egress'):
                outputs[('tc','-j','filter','show','dev',name,direction)]=(0,b'[]')
        events,_now,spawn=self.host(outputs)
        with mock.patch.object(p,'_spawn',side_effect=spawn), \
             mock.patch.object(p,'bpf_bindings') as bpf, \
             mock.patch.object(Path,'read_text',return_value='0\n'):
            self.assertEqual(p.check_links('eth0'),['lo','eth0'])
        bpf.assert_called_once_with(['lo','eth0'])
        tc=[e for e in events if e[1][0]=='tc']
        self.assertEqual([e[0] for e in tc[:6]],['spawn']*6)
        self.assertEqual({e[1] for e in tc if e[0]=='spawn'},
                         {a for a in outputs if a[0]=='tc'})
        # A later link's failed read never hides an earlier link's refusal.
        outputs[('tc','-j','qdisc','show','dev','lo')]=(0,b'[{"kind":"clsact"}]')
        outputs[('tc','-j','filter','show','dev','eth0','egress')]=(1,b'Cannot find device')
        events,_now,spawn=self.host(outputs)
        with mock.patch.object(p,'_spawn',side_effect=spawn),mock.patch.object(p,'bpf_bindings'):
            with self.assertRaisesRegex(p.ForeignPolicyRefused,'clsact'):p.check_links('eth0')
        spawned={e[1] for e in events if e[0]=='spawn'}
        finished={e[1] for e in events if e[0]=='reap'}
        self.assertEqual(spawned,finished)
        self.assertEqual(p._registry(),{})

    def assess(self,outputs,hang=(),legacy=True):
        events,now,spawn=self.host(outputs,hang)
        import tempfile
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(p,'_spawn',side_effect=spawn), \
             mock.patch.object(p.os,'geteuid',return_value=0), \
             mock.patch.object(p,'ufw_integrity',return_value={'class':'absent','sha256':'a'*64,'enabled':False}), \
             mock.patch.object(p,'check_links'), \
             mock.patch.object(p,'verified_owned_tables',return_value=set()), \
             mock.patch.object(p,'assess_rules',return_value=[]), \
             mock.patch.object(p.time,'monotonic',side_effect=lambda:now[0]), \
             mock.patch.object(Path,'read_text',autospec=True,side_effect=legacy_tables), \
             mock.patch.object(p.shutil,'which',side_effect=lambda c:('/usr/sbin/'+c) if legacy else None):
            try:
                return events,p.assess_foreign_policy('eth0',state_path=Path(tmp)/'absent')
            finally:
                self.assertEqual(p._registry(),{})

    SAVES=[('iptables-save',),('ip6tables-save',),('iptables-legacy-save',),('ip6tables-legacy-save',)]

    def outputs(self,second=None):
        first={'nftables':[{'metainfo':{'version':'1'}}]}
        return {p.IPTABLES_VERSION:(0,b'iptables v1.8.10 (nf_tables)'),
                p.RULESET:[(0,json.dumps(first).encode()),
                           (0,json.dumps(first if second is None else second).encode())]}

    def test_saves_run_together_and_snapshot_two_waits_for_every_save(self):
        events,result=self.assess(self.outputs())
        self.assertEqual(result['class'],'filter_only')
        spawns=[i for i,e in enumerate(events) if e==('spawn',p.RULESET)]
        self.assertEqual(len(spawns),2)
        saves=[i for i,e in enumerate(events) if e[1] in self.SAVES]
        self.assertEqual([events[i][0] for i in saves[:4]],['spawn']*4)
        reaped=[i for i,e in enumerate(events) if e[0]=='reap' and e[1] in self.SAVES]
        self.assertEqual(len(reaped),4)
        self.assertGreater(spawns[1],max(reaped))
        self.assertLess(spawns[0],min(saves))
        # The early group is complete before snapshot one starts.
        early=[i for i,e in enumerate(events) if e[1] in (p.IPTABLES_VERSION,p.LINK_INVENTORY)]
        self.assertLess(max(early),spawns[0])

    def test_ruleset_change_during_concurrent_saves_is_refused(self):
        changed={'nftables':[{'metainfo':{'version':'1'}},{'table':{'family':'ip','name':'filter'}}]}
        with self.assertRaises(p.PolicySnapshotChanged):self.assess(self.outputs(changed))

    def test_one_save_timeout_kills_and_reaps_siblings_before_snapshot_two(self):
        # Every save is killed or reaped, and the second ruleset snapshot is
        # never started after the timeout.
        recorded=[]
        original=self.host
        def host(outputs,hang=()):
            value=original(outputs,hang);recorded.append(value[0]);return value
        with mock.patch.object(self,'host',side_effect=host):
            with self.assertRaises(subprocess.TimeoutExpired):
                self.assess(self.outputs(),hang={('ip6tables-save',)})
        events=recorded[0]
        self.assertEqual(sum(1 for e in events if e==('spawn',p.RULESET)),1)
        for argv in self.SAVES:
            self.assertIn(('spawn',argv),events)
            self.assertTrue(('reap',argv) in events or ('kill',argv) in events,argv)

    def test_failed_save_refuses_in_original_order(self):
        outputs=self.outputs()
        outputs[('ip6tables-save',)]=(1,b'Permission denied')
        outputs[('iptables-legacy-save',)]=(1,b'No such file or directory')
        with self.assertRaises(p.PolicyInputUnavailable) as caught:self.assess(outputs)
        self.assertEqual(caught.exception.command_tag,'ip6tables_save')

    def test_legacy_absent_reads_nothing(self):
        events,result=self.assess(self.outputs(),legacy=False)
        self.assertEqual(result['class'],'filter_only')
        self.assertNotIn(('spawn',('iptables-legacy-save',)),events)

    def test_signature_memo_rechecks_every_input(self):
        import importlib.util,marshal
        source=b"def nested(x):\n    return x+2\n"
        name='/usr/lib/python3/dist-packages/ufw/memo_fixture.py'
        def cache(code):return importlib.util.MAGIC_NUMBER+b"\0"*12+marshal.dumps(code)
        raw=cache(compile(source,name,'exec',dont_inherit=True))
        compiled=[]
        real=compile
        def counting(*args,**kw):
            compiled.append(args[1]);return real(*args,**kw)
        with mock.patch('builtins.compile',side_effect=counting):
            p.verify_bytecode(raw,source,name)
            p.verify_bytecode(raw,source,name)
        self.assertEqual(compiled,[name])
        # A cached success never admits a changed source or a changed cache.
        with self.assertRaises(p.ForeignPolicyRefused):
            p.verify_bytecode(raw,source.replace(b'+2',b'+3'),name)
        with self.assertRaises(p.ForeignPolicyRefused):
            p.verify_bytecode(cache(compile(b"x=1\n",name,'exec')),source,name)
        with self.assertRaises(p.ForeignPolicyRefused):
            p.verify_bytecode(raw,source,name.replace('memo_fixture','other'))
        with self.assertRaises(ValueError):p.verify_bytecode(raw+b'x',source,name)
        keys=[k for k in p._SIGNATURES if k[0]=='source' and k[2]==name]
        self.assertTrue(keys)
        for key in keys:
            self.assertEqual(key[-2:],(sys.implementation.cache_tag,bytes(importlib.util.MAGIC_NUMBER)))
            self.assertIn(key[3],(0,1,2))
        for index in range(40):
            p.verify_bytecode(cache(compile(b"y=%d\n"%index,name,'exec',dont_inherit=True)),
                              b"y=%d\n"%index,name)
        self.assertLessEqual(len(p._SIGNATURES),p.SIGNATURE_MEMO_ENTRIES)


@unittest.skipUnless(Path('/bin/sh').exists(),'POSIX shell required')
class RealReaderWaits(unittest.TestCase):
    """Timing-independent: the event-driven wait reaps every real child."""

    def test_output_and_failure(self):
        self.assertEqual(p.run('/bin/sh','-c','printf ok'),b'ok')
        with self.assertRaises(p.PolicyInputUnavailable):p.run('/bin/sh','-c','exit 3')

    def test_timeout_kills_and_reaps(self):
        procs=[]
        real=p._spawn
        def spawn(*args):
            value=real(*args);procs.append(value[0]);return value
        with mock.patch.object(p,'READ_SECONDS',0.2),mock.patch.object(p,'_spawn',side_effect=spawn):
            with self.assertRaises(subprocess.TimeoutExpired):p.run('/bin/sh','-c','exec sleep 30')
        self.assertEqual(len(procs),1);self.assertIsNotNone(procs[0].returncode)

    def test_unconsumed_prefetch_is_killed_and_reaped(self):
        argv=('/bin/sh','-c','exec sleep 30')
        with p.prefetch(argv,('/bin/sh','-c','printf two')):
            proc=p._registry()[argv].proc
            self.assertEqual(p.run('/bin/sh','-c','printf two'),b'two')
        self.assertEqual(proc.returncode,-9);self.assertEqual(p._registry(),{})
        with self.assertRaisesRegex(p.ForeignPolicyRefused,'duplicate prefetched'):
            with p.prefetch(argv,argv):pass
        self.assertEqual(p._registry(),{})

    def test_missing_program_refuses_at_consumption(self):
        with p.prefetch(('/nonexistent/aegis-reader',)):
            with self.assertRaises(OSError):p.run('/nonexistent/aegis-reader')


class LocalCgroupSpellingTransition(unittest.TestCase):
    """Only the authenticated stopped owner's one nft display atom may change."""

    def setUp(self):
        self.path='system.slice/aegis-auto@'+'a'*64+'.service'
        self.inode='734892'
        self.marker='aegis-owned-marker'
        match=lambda value:{'match':{'op':'==','left':{'socket':{'key':'cgroupv2'}},'right':value}}
        row=lambda value:{'rule':{'family':'ip','table':'aegis_auto_local_redirect',
                                  'chain':'output','comment':self.marker,
                                  'expr':[match(value),{'counter':None},{'return':None}]}}
        self.first={'nftables':[{'table':{'family':'ip','name':'aegis_auto_local_redirect'}},
                                {'chain':{'family':'ip','table':'aegis_auto_local_redirect',
                                          'name':'output'}},row(self.path)]}
        self.second=copy.deepcopy(self.first)
        self.second['nftables'][2]=row(self.inode)
        self.binding={'private_unit':self.path.rsplit('/',1)[1],
                      'config_semantic_sha256':'b'*64}
        self.bound={'cgroup_path':self.path,'cgroup_inode':int(self.inode),
                    'invocation_id':'c'*32}

    def check(self, first=None, second=None, *, stopped=True, current=None):
        import aegis_auto_guard_policy as policy
        first=copy.deepcopy(self.first if first is None else first)
        second=copy.deepcopy(self.second if second is None else second)
        current=second if current is None else current
        receipt=lambda path: ({'binding':self.binding} if path==policy.LOCAL_INTENT
                              else {'invocation_id':self.bound['invocation_id']})
        with mock.patch.object(policy,'_scoped_read',side_effect=receipt), \
             mock.patch.object(policy,'_local_binding',return_value=self.binding), \
             mock.patch.object(policy,'_local_bound',return_value=self.bound), \
             mock.patch.object(policy,'_local_intent',return_value={'owner_marker':self.marker}), \
             mock.patch.object(policy,'local_verify_stopping',side_effect=(None if stopped else
                 policy.PolicyRefused('exact owner/deny refused'))) as verify_stop, \
             mock.patch.object(p,'run',return_value=json.dumps(current).encode()):
            result=p.exact_stopped_local_cgroup_spelling(
                first,second,{('ip','aegis_auto_local_redirect')})
        if result:
            verify_stop.assert_called_once_with(self.binding,self.bound['invocation_id'],
                config_semantic_sha256=self.binding['config_semantic_sha256'])
        return result

    def test_exact_named_to_numeric_after_stopped_owner_proof(self):
        self.assertTrue(self.check())
        self.assertFalse(p.exact_stopped_local_cgroup_spelling(
            self.first,self.second,set()))

    def test_wrong_inode_and_nonlocal_changes_never_admit(self):
        wrong=copy.deepcopy(self.second)
        wrong['nftables'][2]['rule']['expr'][0]['match']['right']='734893'
        self.assertFalse(self.check(second=wrong))
        foreign=copy.deepcopy(self.second)
        foreign['nftables'].append({'rule':{'family':'ip','table':'foreign',
                                           'chain':'output','expr':[{'accept':None}]}})
        self.assertFalse(self.check(second=foreign))
        altered=copy.deepcopy(self.second)
        altered['nftables'][2]['rule']['expr'][2]={'accept':None}
        self.assertFalse(self.check(second=altered))

    def test_only_original_rule_position_and_path(self):
        moved=copy.deepcopy(self.second)
        moved['nftables'][2]['rule']['expr'].reverse()
        self.assertFalse(self.check(second=moved))
        replaced=copy.deepcopy(self.first)
        replaced['nftables'][2]['rule']['expr'][0]['match']['right']='system.slice/other.service'
        self.assertFalse(self.check(first=replaced))

    def test_stopped_deny_or_fresh_ruleset_failure_refuses(self):
        import aegis_auto_guard_policy as policy
        with self.assertRaises(policy.PolicyRefused):self.check(stopped=False)
        changed=copy.deepcopy(self.second)
        changed['nftables'][2]['rule']['expr'][2]={'accept':None}
        self.assertFalse(self.check(current=changed))

    def test_complete_assessment_requires_monitor_gate_guard_and_redirect_mode(self):
        import tempfile
        first=copy.deepcopy(self.first)
        first['nftables'].insert(0,{'table':{'family':'inet','name':'aegis_device_guard'}})
        second=copy.deepcopy(self.second)
        second['nftables'].insert(0,{'table':{'family':'inet','name':'aegis_device_guard'}})
        for enabled,guard,mode,accepted in ((False,True,'wide-redirect-safe',False),
                                             (True,False,'wide-redirect-safe',False),
                                             (True,True,'full-wide-tun',False),
                                             (True,True,'wide-redirect-safe',True)):
            nft_reads=iter((first,second))
            def command(*args):
                if args==('iptables','-V'):return b'iptables v1.8 (nf_tables)'
                if args[:2]==('nft','--json'):return json.dumps(next(nft_reads)).encode()
                return b''
            with self.subTest(enabled=enabled,guard=guard,mode=mode), \
                 tempfile.TemporaryDirectory() as tmp, \
                 mock.patch.object(p.os,'geteuid',return_value=0), \
                 mock.patch.object(p,'ufw_integrity',return_value={'class':'absent','sha256':'a'*64,'enabled':False}), \
                 mock.patch.object(p,'check_links'), \
                 mock.patch.object(p,'run',side_effect=command), \
                 mock.patch.object(p,'prefetch',side_effect=no_prefetch), \
                 mock.patch.object(Path,'read_text',autospec=True,side_effect=legacy_tables), \
                 mock.patch.object(p.shutil,'which',return_value=None), \
                 mock.patch.object(p,'verified_owned_tables',return_value={('ip','aegis_auto_local_redirect')}), \
                 mock.patch.object(p,'assess_rules',return_value={}), \
                 mock.patch.object(p,'exact_stopped_local_cgroup_spelling',return_value=True) as exact:
                args={'mode':mode,'state_path':Path(tmp)/'not-published',
                      'require_guard':guard,
                      'allow_stopped_local_display_transition':enabled}
                if accepted:
                    self.assertEqual(p.assess_foreign_policy('eth0',**args)['class'],'filter_only')
                    exact.assert_called_once()
                else:
                    with self.assertRaises(p.PolicySnapshotChanged):
                        p.assess_foreign_policy('eth0',**args)
                    exact.assert_not_called()



if __name__=='__main__':unittest.main()
