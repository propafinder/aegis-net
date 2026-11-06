"""B14-11: scoped capture may never convert an uplink into relay ingress."""
import json
import contextlib
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import aegis_auto_guardian as guardian


class ScopedRouteRefusal(unittest.TestCase):
    def check(self, capture, uplink, default_dev, relay_dev, refusal):
        state = f'schema=v2\nuplink={uplink}\n'.encode()
        def ip(args, **_kwargs):
            dev = default_dev if 'default' in args else relay_dev
            return SimpleNamespace(returncode=0, stdout=json.dumps([{'dev': dev}]).encode(),
                                   stderr=b'')
        with patch.object(guardian, '_semantic_policy_readback', return_value=(state, b'')), \
             patch.object(guardian.subprocess, 'run', side_effect=ip):
            action = lambda: guardian._scoped_route_refusal(
                capture, guardian.digest(state),
                (('ordinary', '203.0.113.7:443', 'relay.example'),))
            if refusal:
                with self.assertRaisesRegex(guardian.Refused, refusal):
                    action()
            else:
                action()

    def test_guard_uplink_default_and_relay_route_are_all_refused(self):
        self.check('eth0', 'eth0', 'wan0', 'wan0', 'scoped_ingress_is_guard_uplink')
        self.check('eth0', 'wan0', 'eth0', 'wan0', 'scoped_ingress_is_egress_route')
        self.check('eth0', 'wan0', 'wan0', 'eth0', 'scoped_ingress_is_egress_route')
        self.check('lan0', 'wan0', 'wan0', 'wan0', None)

    def test_capture_effect_refuses_bad_routes_before_scoped_activation(self):
        class Activated(Exception):
            pass

        state = b'schema=v2\nuplink=wan0\n'
        projection = b'guard-projection'
        runtime = SimpleNamespace(
            redirect_rollout_profile='prerouting_scoped',
            redirect_ingress_ifname='lan0',
            configured_relay_pool=(('ordinary', '203.0.113.7:443', 'relay.example'),))
        original = {'mode': 'wide-redirect-safe', 'private_unit': 'aegis-auto@test.service',
                    'boot_id': 'boot', 'netns_ino': 1, 'transaction_nonce': 'nonce',
                    'planned_generation': 'generation'}
        effect = {'command': 'CAPTURE_READY', 'pid1_invocation_id': 'invocation'}
        binding = {'interface': 'lan0', 'config_semantic_sha256': 'a' * 64}
        for case, uplink, default_dev, relay_dev, warning, empty_relay in (
                ('guard_uplink', 'lan0', 'wan0', 'wan0', False, False),
                ('default_route', 'wan0', 'lan0', 'wan0', False, False),
                ('relay_route', 'wan0', 'wan0', 'lan0', False, False),
                ('route_warning', 'wan0', 'wan0', 'wan0', True, False),
                ('empty_relay', 'wan0', 'wan0', 'wan0', False, True),
                ('multipath_default', 'wan0', 'wan0', 'wan0', False, False),
                ('nexthops_relay', 'wan0', 'wan0', 'wan0', False, False),
                ('nhid_relay', 'wan0', 'wan0', 'wan0', False, False),
                ('safe', 'wan0', 'wan0', 'wan0', False, False)):
            with self.subTest(case=case), contextlib.ExitStack() as stack:
                rendered_state = state.replace(b'wan0', uplink.encode())
                def ip(args, **_kwargs):
                    is_default = 'default' in args
                    rows = [] if empty_relay and not is_default else [
                        {'dev': default_dev if is_default else relay_dev}]
                    if rows and case == 'multipath_default' and is_default:
                        rows[0]['multipath'] = [{'dev': 'lan0'}]
                    if rows and case == 'nexthops_relay' and not is_default:
                        rows[0]['nexthops'] = [{'dev': 'lan0'}]
                    if rows and case == 'nhid_relay' and not is_default:
                        rows[0]['nhid'] = 7
                    return SimpleNamespace(returncode=0, stdout=json.dumps(rows).encode(),
                                           stderr=b'warning' if warning else b'')
                mocks = {
                    '_capture_request_shape': Mock(), '_held_lock': Mock(return_value=(1, 2)),
                    '_claimed_private_unit': Mock(), '_policy': Mock(return_value={
                        'state_sha256': guardian.digest(rendered_state),
                        'policy_sha256': guardian.digest(projection)}),
                    '_stage_leaf': Mock(return_value=b'{"commitments":{}}'),
                    '_installed_main_digest': Mock(return_value='b' * 64),
                    '_private_unit_main_pid': Mock(return_value=123),
                    '_capture_step': Mock(), '_scoped_owner_binding': Mock(return_value=binding),
                    '_semantic_policy_readback': Mock(return_value=(rendered_state, b'')),
                    '_CaptureHeldLease': Mock(side_effect=lambda *_: contextlib.nullcontext()),
                    'STOP_INTENT': SimpleNamespace(exists=lambda: False,
                                                   is_symlink=lambda: False),
                }
                for name, replacement in mocks.items():
                    stack.enter_context(patch.object(guardian, name, replacement))
                redirect = SimpleNamespace(scoped_activate=Mock(side_effect=Activated),
                                           scoped_verify=Mock(side_effect=Activated))
                modules = {
                    'aegis_auto_native_witness': SimpleNamespace(
                        snapshot_policy=lambda *_: (projection, {'output': 1}, {})),
                    'aegis_auto_capture': SimpleNamespace(),
                    'aegis_auto_endpoint': SimpleNamespace(
                        qa_relay_receipt_present=lambda: False,
                        admit_runtime_endpoint=lambda **_: runtime),
                    'aegis_auto_guard_policy': redirect,
                }
                stack.enter_context(patch.object(
                    guardian, 'verified_module', side_effect=lambda _path, name: modules[name]))
                stack.enter_context(patch.object(guardian.subprocess, 'run', side_effect=ip))
                expected = Activated if case == 'safe' else guardian.Refused
                with self.assertRaises(expected):
                    guardian._capture_effect(effect, original,
                                             {'policy_sha256': 'c' * 64}, 1, 2, {}, None)
                if case == 'safe':
                    redirect.scoped_activate.assert_called_once()
                else:
                    redirect.scoped_activate.assert_not_called()
                    redirect.scoped_verify.assert_not_called()


if __name__ == '__main__':
    unittest.main()
