"""Retain both native witness receipts without admitting a repeated challenge."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('dual_witness_topology', ROOT / 'scripts/lib/aegis_auto_witness_topology.py')
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)

class ReachedRouteRead(Exception):
    pass

class DualFamily(unittest.TestCase):
    def test_retained_other_family_allows_next_proof_and_same_family_refuses(self):
        for first, second in ((4, 6), (6, 4)):
            with self.subTest(first=first), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); nonce = b'a' * 32
                receipt = root / ('sink-receipt-' + str(first) + '-' + nonce.hex() + '.json')
                receipt.write_bytes(b'retained-result')
                with patch.object(m, 'RUNTIME', root), patch.object(m, 'STATE', root/'state'), \
                     patch.object(m, 'SINK_SOCKET', root/'socket'), patch.object(m, '_watchdog_ready'), \
                     patch.object(m, '_link', return_value=None), patch.object(m, '_namespace_present', return_value=False), \
                     patch.object(m, '_route_snapshot', side_effect=ReachedRouteRead) as routes:
                    with self.assertRaises(ReachedRouteRead):m._prepare(nonce, second)
                    routes.assert_called_once()
                    routes.reset_mock()
                    with self.assertRaisesRegex(m.Refused, 'existing_witness_topology'):m._prepare(nonce, first)
                    routes.assert_not_called()
                    self.assertEqual(receipt.read_bytes(), b'retained-result')

    def test_legacy_receipt_or_dangling_receipt_fences_both_families(self):
        for legacy, dangling in ((True, False), (True, True), (False, True)):
            for family in (4, 6):
                with self.subTest(legacy=legacy, dangling=dangling, family=family), tempfile.TemporaryDirectory() as directory:
                    root=Path(directory);nonce=b'b'*32
                    name='sink-receipt-'+(''if legacy else str(family)+'-')+nonce.hex()+'.json'
                    receipt=root/name
                    if dangling:receipt.symlink_to(root/'missing')
                    else:receipt.write_bytes(b'retained-legacy')
                    with patch.object(m, 'RUNTIME', root), patch.object(m, 'STATE', root/'state'), \
                         patch.object(m, 'SINK_SOCKET', root/'socket'), patch.object(m, '_watchdog_ready'), \
                         patch.object(m, '_link', return_value=None), patch.object(m, '_namespace_present', return_value=False), \
                         patch.object(m, '_route_snapshot') as routes:
                        with self.assertRaisesRegex(m.Refused, 'existing_witness_topology'):m._prepare(nonce, family)
                        routes.assert_not_called()

    def test_pinned_actor_permits_exact_dual_stack_socket_families(self):
        source=(ROOT/'packaging/systemd/aegis-auto-witness-topology.service').read_text()
        values=[line.split('=',1)[1]for line in source.splitlines()if line.startswith('RestrictAddressFamilies=')]
        self.assertEqual(len(values),1)
        self.assertEqual(set(values[0].split()),{'AF_UNIX','AF_INET','AF_INET6','AF_NETLINK','AF_PACKET'})
        self.assertIn('NoNewPrivileges=yes',source)

if __name__ == '__main__':unittest.main()
