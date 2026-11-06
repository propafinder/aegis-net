#!/usr/bin/env python3
"""Exercise actual finite site prefix classifier from the product draft."""
import ast
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'lib/aegis_auto_terminal_register.py'
TREE = ast.parse(SOURCE.read_text(encoding='utf-8'), filename=str(SOURCE))
NODE = next(node for node in TREE.body if isinstance(node, ast.FunctionDef)
            and node.name == '_cold_site_classify')


class Refused(RuntimeError):
    pass


def need(value, reason):
    if not value:
        raise Refused(reason)


NS = {'need':need, 'Refused':Refused}
exec(compile(ast.Module(body=[NODE], type_ignores=[]), str(SOURCE), 'exec'), NS)
classify = NS['_cold_site_classify']


class SitePrefixTests(unittest.TestCase):
    def setUp(self):
        self.old_order = ['a','b','c','d','e','f','g']
        self.new_order = ['g','f','e','d','c','b','a']
        self.old = {key:('old-'+key).encode() for key in self.old_order}
        self.new = {key:('new-'+key).encode() for key in self.old_order}

    def classify(self, current):
        return classify(current,self.old,self.new,self.old_order,self.new_order)

    def test_all_valid_a_and_b_prefixes(self):
        self.assertEqual(self.classify(self.old),'a_exact')
        self.assertEqual(self.classify(self.new),'b_complete')
        self.assertEqual(self.classify({key:None for key in self.old}),'absent')
        for cut in range(1,7):
            old={key:(None if i<cut else self.old[key])
                 for i,key in enumerate(self.old_order)}
            new={key:(self.new[key] if i<cut else None)
                 for i,key in enumerate(self.new_order)}
            with self.subTest(cut=cut):
                self.assertEqual(self.classify(old),'a_retiring_prefix')
                self.assertEqual(self.classify(new),'b_prefix')

    def test_foreign_mixed_and_out_of_order_refuse(self):
        cases=[]
        foreign=dict(self.old);foreign['d']=b'foreign';cases.append(foreign)
        mixed=dict(self.old);mixed['a']=self.new['a'];cases.append(mixed)
        gap={key:None for key in self.old};gap['a']=self.old['a'];cases.append(gap)
        late={key:None for key in self.new};late['a']=self.new['a'];cases.append(late)
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(Refused): self.classify(case)

    def test_missing_roster_refuses(self):
        with self.assertRaises(Refused):
            self.classify({'a':self.old['a']})


if __name__ == '__main__':
    unittest.main()
