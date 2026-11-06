#!/usr/bin/env python3
"""Source-level controls for the fixed cold infrastructure StopUnit roster."""
import ast
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'lib/aegis_installer_auto_v2.py'


def operator():
    tree=ast.parse(SOURCE.read_text(encoding='utf-8'))
    roster=next(node for node in tree.body if isinstance(node,ast.Assign)
                and any(isinstance(target,ast.Name) and
                        target.id=='_COLD_INFRASTRUCTURE_UNITS'
                        for target in node.targets))
    func=next(node for node in tree.body if isinstance(node,ast.FunctionDef)
              and node.name=='_cold_stop_old_infrastructure')
    scope={}
    exec(compile(ast.Module(body=[roster,func],type_ignores=[]),str(SOURCE),'exec'),scope)
    return scope


class ColdQuiesce(unittest.TestCase):
    def test_exact_six_source_units_and_bounded_stop(self):
        scope=operator(); calls=[]
        scope['call_output']=lambda argv,maximum,timeout:calls.append(
            (argv,maximum,timeout))
        scope['_cold_stop_old_infrastructure']()
        self.assertEqual([item[0][-1] for item in calls],list(scope['_COLD_INFRASTRUCTURE_UNITS']))
        self.assertEqual(len(set(scope['_COLD_INFRASTRUCTURE_UNITS'])),6)
        self.assertEqual({tuple(item[0][:2]) for item in calls},
                         {('/usr/bin/systemctl','stop')})
        self.assertEqual({(item[1],item[2]) for item in calls},{(1024,20)})
        self.assertNotIn('aegis-device-egress-guard.service',scope['_COLD_INFRASTRUCTURE_UNITS'])

    def test_first_failed_stop_prevents_later_progress(self):
        scope=operator(); calls=[]
        def refuse(argv,maximum,timeout):
            calls.append(argv[-1])
            if len(calls)==2: raise RuntimeError('stop_refused')
        scope['call_output']=refuse
        with self.assertRaisesRegex(RuntimeError,'stop_refused'):
            scope['_cold_stop_old_infrastructure']()
        self.assertEqual(len(calls),2)


if __name__=='__main__':unittest.main()
