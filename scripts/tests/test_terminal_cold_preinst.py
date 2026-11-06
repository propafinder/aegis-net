"""Evaluate the actual generated preinst's native proof admission predicate."""
import ast
import hashlib
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'build-split-deb-packages.sh'
text = SOURCE.read_text()
start = text.index("cat > \"$path\" <<'PY'", text.index('write_client_preinst()'))
start = text.index('\n', start) + 1
end = text.index('\nPY\n', start)
module = ast.parse(text[start:end])
function = next(node for node in module.body if isinstance(node, ast.FunctionDef)
                and node.name == 'cold_package_admit')
predicate = next(node.args[0] for node in function.body
                 if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                 for node in [node.value] if isinstance(node.func, ast.Name)
                 and node.func.id == 'need' and isinstance(node.args[0], ast.BoolOp)
                 and any(isinstance(sub, ast.Constant)
                         and sub.value == 'aegis_auto_v2_cold_retired_successor_v2'
                         for sub in ast.walk(node.args[0])))
code = compile(ast.Expression(predicate), '<generated-cold-preinst-proof>', 'eval')

class ColdPreinstProofTests(unittest.TestCase):
    def accepted(self, migration, site, package, rows='r', context=None, cold_context=None):
        boot = 'b'; root = '/var/lib/aegis-auto/releases/' + 'a'*16
        intent_raw = b'intent\n'; phase_raw = b'phase\n'
        phase = {'deny_policy_sha256':'d','quiesce_monotonic_tick':123,
                 'post_quiesce_infrastructure_sha256':'r'}
        intent = {'new_candidate_sha256':'c','successor_intent_sha256':'s'}
        proof = {'schema':'aegis_auto_v2_cold_retired_successor_v2',
                 'current_boot_id':boot,'retained_root':root,
                 'new_candidate_sha256':'c','successor_intent_sha256':'s',
                 'cold_intent_sha256':hashlib.sha256(intent_raw).hexdigest(),
                 'deny_policy_sha256':'d','quiesce_state':'post',
                 'quiesce_receipt_sha256':hashlib.sha256(phase_raw).hexdigest(),
                 'quiesce_monotonic_tick':123,'infrastructure_quiescent':True,
                 'infrastructure_rows_sha256':rows,'package_state':package,
                 'migration_state':migration,'site_state':site,
                 'observer_state':'absent','infrastructure_qualified':True,
                 'client_actors_absent':True,'jobs_absent':True,
                 'cgroups_empty':True,'stop_intent_absent':True,
                 'context_state':context or ('present_exact' if migration == 'pending_prefix'
                                             else 'absent_not_prepared'),
                 'cold_context_state':cold_context or ('present_exact' if migration == 'preparation_absent'
                                                       else 'absent_not_prepared')}
        namespace = dict(hashlib=hashlib, proof=proof, intent=intent,
                         phase=phase, intent_raw=intent_raw, phase_raw=phase_raw,
                         boot=boot, root=root)
        return eval(code, namespace)

    def test_pending_partial_package_accepts_authenticated_prefix_and_changed_rows(self):
        for site in ('a_exact','a_retiring_prefix','absent','b_prefix'):
            with self.subTest(site=site):
                self.assertTrue(self.accepted('pending_prefix',site,'known_interrupted','changed'))

    def test_old_exact_still_requires_exact_quiesce_rows(self):
        self.assertFalse(self.accepted('pending_prefix','a_retiring_prefix','old_exact','changed'))
        self.assertTrue(self.accepted('pending_prefix','a_retiring_prefix','old_exact','r'))

    def test_preparation_absent_requires_a_site_and_cold_context(self):
        self.assertTrue(self.accepted('preparation_absent','a_exact','old_exact'))
        self.assertFalse(self.accepted('preparation_absent','absent','old_exact'))
        self.assertFalse(self.accepted('preparation_absent','a_exact','old_exact',
                                       cold_context='absent_not_prepared'))

    def test_pending_requires_ordinary_context_and_rejects_completed_edge(self):
        self.assertFalse(self.accepted('pending_prefix','b_prefix','known_interrupted',
                                       context='missing_reconstructible'))
        self.assertFalse(self.accepted('completed_edge','b_prefix','known_interrupted'))

if __name__ == '__main__':
    unittest.main()
