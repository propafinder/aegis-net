"""Route inverse tolerates elapsed RA lifetime and rejects routing changes."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

MODULES = []
for name in ('aegis_auto_witness_topology', 'aegis_auto_capture_topology'):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parents[1] / 'lib' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    MODULES.append(module)


spec = importlib.util.spec_from_file_location('route_policy', Path(__file__).resolve().parents[1] / 'lib/aegis_auto_foreign_policy.py')
POLICY = importlib.util.module_from_spec(spec)
spec.loader.exec_module(POLICY)


class RouteExpiryInverse(unittest.TestCase):
    def setUp(self):
        for module in MODULES:
            loader = patch.object(module, '_route_policy', return_value=POLICY)
            loader.start(); self.addCleanup(loader.stop)
        self.before = [{'dst': 'default', 'gateway': 'fe80::2', 'dev': 'enp0s1',
                        'protocol': 'ra', 'metric': 100, 'expires': 1800,
                        'nhid': 7, 'flags': [], 'pref': 'medium'}]
        self.after = copy.deepcopy(self.before)
        self.after[0]['expires'] = 1790
        self.times = (10**9, 1100000000, 11 * 10**9, 11100000000)

    def test_elapsed_expiry_preserves_original_hashed_snapshot(self):
        for module in MODULES:
            with self.subTest(module=module.__name__):
                self.assertEqual(module._restore_route_expiry(self.before, self.after, *self.times), self.before)
                self.assertEqual(self.after[0]['expires'], 1790)

    def test_static_routes_stay_exact(self):
        for module in MODULES:
            self.assertEqual(module._restore_route_expiry([{'dst': '10.0.2.0/24'}], [{'dst': '10.0.2.0/24'}], *self.times), [{'dst': '10.0.2.0/24'}])

    def test_route_changes_missing_routes_and_invalid_expiry_refuse(self):
        changes = []
        for key, value in (('gateway', 'fe80::3'), ('dev', 'eth9'), ('metric', 101),
                           ('nhid', 8), ('protocol', 'static'), ('pref', 'high'),
                           ('flags', ['linkdown']), ('dst', 'fd00::/64'),
                           ('expires', 9001),
                           ('expires', 0), ('expires', True), ('expires', 1790.0)):
            row = copy.deepcopy(self.after); row[0][key] = value; changes.append(row)
        row = copy.deepcopy(self.after); del row[0]['expires']; changes.append(row)
        row = copy.deepcopy(self.after); row[0]['unexpected'] = 1; changes.append(row)
        changes.extend(([], self.after * 2))
        for module in MODULES:
            for changed in changes:
                with self.subTest(module=module.__name__, changed=changed), self.assertRaises(module.Refused):
                    module._restore_route_expiry(self.before, changed, *self.times)

    def test_ra_renewal_is_bounded_but_non_ra_countdown_remains_exact(self):
        for module in MODULES:
            for expiry in (1700, 1800, 1801, 9000):
                refreshed = copy.deepcopy(self.after); refreshed[0]['expires'] = expiry
                self.assertEqual(module._restore_route_expiry(self.before, refreshed, *self.times), self.before)
            prefix = [{'dst':'2001:db8:1::/64','dev':'eth0','protocol':'ra','expires':120,'metric':100,'flags':[]}]
            self.assertEqual(module._restore_route_expiry(prefix, copy.deepcopy(prefix), *self.times), prefix)
            for lifetime in (121,9000,2**32-1):
                changed = copy.deepcopy(prefix); changed[0]['expires'] = lifetime
                self.assertEqual(module._restore_route_expiry(prefix,changed,*self.times),prefix)
            for key,value in (('expires',2**32),('expires',0),('expires',True),
                              ('dev','other0'),('dst','2001:db8:2::/64'),
                              ('protocol','static'),('flags',['linkdown'])):
                changed=copy.deepcopy(prefix);changed[0][key]=value
                with self.assertRaises(module.Refused):module._restore_route_expiry(prefix,changed,*self.times)
            static = copy.deepcopy(self.before); static[0]['protocol'] = 'dhcp'
            changed = copy.deepcopy(static)
            with self.assertRaises(module.Refused):
                module._restore_route_expiry(static, changed, *self.times)
            changed[0]['expires'] = 1790
            self.assertEqual(module._restore_route_expiry(static, changed, *self.times), static)

    def test_invalid_or_overlong_monotonic_windows_refuse(self):
        for module in MODULES:
            for times in ((0, 1, 2, 3), (2, 1, 3, 4), (1, 3, 2, 4),
                          (1, 2, 4, 3), (True, 2, 3, 4), (1, 2, 3, 901 * 10**9)):
                with self.subTest(module=module.__name__, times=times), self.assertRaises(module.Refused):
                    module._restore_route_expiry(self.before, self.after, *times)


if __name__ == '__main__':
    unittest.main()
