"""Fixed watchdog inventory RPC; no BPF load or service change in these tests."""
import array,errno,json,os,pathlib,socket,sys,types,unittest
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'lib'))
import aegis_auto_foreign_policy as foreign
import aegis_auto_guardian_watchdog as actor

class Delegation(unittest.TestCase):
    def test_only_explicit_source_loader_hook_can_delegate_permission_refusal(self):
        with mock.patch.object(foreign,'_local_bpf_bindings',side_effect=OSError(errno.EPERM,'denied')), \
             mock.patch.object(foreign,'_privileged_bpf_query',None):
            with self.assertRaises(OSError):foreign.bpf_bindings(['lo'])
        delegate=mock.Mock(return_value=None)
        with mock.patch.object(foreign,'_local_bpf_bindings',side_effect=OSError(errno.EPERM,'denied')), \
             mock.patch.object(foreign,'_privileged_bpf_query',delegate):
            foreign.bpf_bindings(['lo']);delegate.assert_called_once_with(['lo'])
        delegate.reset_mock()
        with mock.patch.object(foreign,'_local_bpf_bindings',side_effect=OSError(errno.EIO,'input failed')), \
             mock.patch.object(foreign,'_privileged_bpf_query',delegate):
            with self.assertRaises(OSError):foreign.bpf_bindings(['lo'])
            delegate.assert_not_called()
        for interfaces in ([],['lo']*4,['lo','lo'],['bad name'],[{}]):
            with self.subTest(interfaces=interfaces),self.assertRaises(ValueError):foreign.bpf_bindings(interfaces)

@unittest.skipUnless(sys.platform=='linux','Linux SEQPACKET/SCM_RIGHTS wire controls')
class Wire(unittest.TestCase):
    def pair(self):
        a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        a.settimeout(.5);b.settimeout(.5);self.addCleanup(a.close);self.addCleanup(b.close);return a,b

    def test_registration_peek_preserves_original_rights_and_never_queries_bpf(self):
        a,b=self.pair();fd=os.open('/dev/null',os.O_RDONLY);self.addCleanup(os.close,fd)
        raw=json.dumps({'op':'REGISTER','boot_id':'fixture'}).encode()
        a.sendmsg([raw],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))])
        with mock.patch.object(actor,'_guardian_peer') as peer:
            self.assertFalse(actor._serve_bpf_query(b));peer.assert_not_called()
        body,anc,flags,_=b.recvmsg(8192,socket.CMSG_SPACE(4))
        self.assertEqual(body,raw);self.assertEqual(flags,0)
        received=array.array('i');received.frombytes(anc[0][2]);self.assertEqual(len(received),1)
        try:self.assertEqual(os.fstat(received[0]).st_rdev,os.fstat(fd).st_rdev)
        finally:os.close(received[0])

    def serve(self,request,*,failure=None,foreign_peer=False):
        a,b=self.pair();a.send(json.dumps(request).encode());fd=os.open('/dev/null',os.O_RDONLY)
        local=mock.Mock(side_effect=failure);loader=mock.Mock(return_value=types.SimpleNamespace(_local_bpf_bindings=local))
        module=types.SimpleNamespace(FOREIGN_SOURCE=pathlib.Path('/source'),verified_module=loader)
        with mock.patch.object(actor,'_guardian_peer',side_effect=actor.Refused('foreign') if foreign_peer else None,return_value=(123,fd)) as auth, \
             mock.patch.object(actor,'_own_source') as own, \
             mock.patch.object(actor,'_guardian_module',return_value=module), \
             mock.patch.object(actor,'_boot',return_value='fixture-boot'), \
             mock.patch.object(actor,'_alive',return_value=True):
            try:
                result=actor._serve_bpf_query(b)
                self.assertTrue(result);reply=json.loads(a.recv(8192));self.assertEqual(reply,{'state':'BPF_EMPTY','boot_id':'fixture-boot','interfaces':['lo','eth0'],'guardian_pid':123})
                auth.assert_called_once();own.assert_called_once();local.assert_called_once_with(['lo','eth0'])
            finally:
                if foreign_peer:os.close(fd) # Auth failure returned no owned PIDFD.
        return local

    def test_read_only_rpc_authenticates_and_returns_exact_fixed_proof(self):
        self.serve({'op':'BPF_READ','boot_id':'fixture-boot','interfaces':['lo','eth0']})

    def test_foreign_peer_dangerous_input_and_unavailable_inventory_never_ack(self):
        good={'op':'BPF_READ','boot_id':'fixture-boot','interfaces':['lo','eth0']}
        with self.assertRaises(actor.Refused):self.serve(good,foreign_peer=True)
        for changes in ({'interfaces':['lo','lo']},{'interfaces':[{}]},{'boot_id':'stale'},{'injected':'write'}):
            with self.subTest(changes=changes),self.assertRaises(actor.Refused):self.serve({**good,**changes})
        with self.assertRaises(foreign.ForeignPolicyRefused):self.serve(good,failure=foreign.ForeignPolicyRefused('attached'))

    def test_active_lease_poll_services_inventory_and_preserves_lease_packet(self):
        import select,tempfile
        with tempfile.TemporaryDirectory() as d:
            with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as listener, \
                 socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as query:
                listener.bind(str(pathlib.Path(d)/'actor.sock'));listener.listen(1)
                lease,registered=self.pair();lease.send(b'{"op":"LIVE"}')
                query.settimeout(.5);query.connect(listener.getsockname())
                query.send(json.dumps({'op':'BPF_READ','boot_id':'fixture-boot','interfaces':['lo']}).encode())
                watcher=select.poll();watcher.register(listener,select.POLLIN);watcher.register(registered,select.POLLIN)
                local=mock.Mock();module=types.SimpleNamespace(FOREIGN_SOURCE=pathlib.Path('/source'),verified_module=lambda *args:types.SimpleNamespace(_local_bpf_bindings=local))
                with mock.patch.object(actor,'_guardian_peer',side_effect=lambda p:(123,os.open('/dev/null',os.O_RDONLY))), \
                     mock.patch.object(actor,'_own_source'),mock.patch.object(actor,'_guardian_module',return_value=module), \
                     mock.patch.object(actor,'_boot',return_value='fixture-boot'),mock.patch.object(actor,'_alive',return_value=True):
                    events=list(actor._lease_events(watcher,listener))
                self.assertEqual(events,[(registered.fileno(),select.POLLIN)])
                self.assertEqual(registered.recv(8192),b'{"op":"LIVE"}')
                self.assertEqual(json.loads(query.recv(8192))['state'],'BPF_EMPTY')
                local.assert_called_once_with(['lo'])

    def test_second_registration_is_refused_without_consuming_active_lease(self):
        import select,tempfile
        with tempfile.TemporaryDirectory() as d:
            with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as listener, \
                 socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as query:
                listener.bind(str(pathlib.Path(d)/'actor.sock'));listener.listen(1)
                lease,registered=self.pair();lease.send(b'{"op":"LIVE"}')
                query.settimeout(.5);query.connect(listener.getsockname());query.send(b'{"op":"REGISTER"}')
                watcher=select.poll();watcher.register(listener,select.POLLIN);watcher.register(registered,select.POLLIN)
                with mock.patch.object(actor,'_register') as register, mock.patch.object(actor,'_guardian_peer') as authenticate:
                    events=list(actor._lease_events(watcher,listener))
                register.assert_not_called();authenticate.assert_not_called()
                self.assertEqual(events,[(registered.fileno(),select.POLLIN)])
                self.assertEqual(registered.recv(8192),b'{"op":"LIVE"}')
                # The unread REGISTER (including any rights) is not consumed.
                # Linux may reset this refused SEQPACKET on close even when
                # the bounded refusal reply was sent before closing.
                try:reply=json.loads(query.recv(8192))
                except ConnectionResetError:reply={'state':'REFUSED'}
                self.assertEqual(reply['state'],'REFUSED')
