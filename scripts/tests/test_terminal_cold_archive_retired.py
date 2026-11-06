"""Retained B PID1 readback reports missing units for native package joining."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import time
import unittest
from unittest import mock


SOURCE=Path(__file__).resolve().parents[1]/'lib/aegis_auto_guardian.py'
spec=importlib.util.spec_from_file_location('guardian_cold_archive_test',SOURCE)
guardian=importlib.util.module_from_spec(spec)
spec.loader.exec_module(guardian)


class ColdArchiveRetiredUnits(unittest.TestCase):
    def facts(self, missing=(), corrupt=()):
        rows={}
        for unit,_source,path in guardian.ROTATION_ACTORS:
            absent=unit in missing
            rows[unit]={'Id':unit,'LoadState':'not-found' if absent else 'loaded',
                'FragmentPath':'' if absent else str(path),
                'ActiveState':'inactive','SubState':'dead','InvocationID':'',
                'MainPID':'0','ControlPID':'0','ControlGroup':'',
                'NFileDescriptorStore':'0'}
        for unit,_relative in guardian.ROTATION_STATIC_UNITS:
            absent=unit in missing
            row={'Id':unit,'LoadState':'not-found' if absent else 'loaded',
                 'FragmentPath':'' if absent else '/etc/systemd/system/'+unit,
                 'ActiveState':'inactive','SubState':'dead','InvocationID':'',
                 'UnitFileState':'not-found' if absent else 'static',
                 'Triggers':'' if absent else (
                     'aegis-auto-trace-rollback.service' if unit.endswith('.timer') else ''),
                 'TriggeredBy':''}
            if unit.endswith('.timer'):
                row.update(NextElapseUSecRealtime='n/a',
                           NextElapseUSecMonotonic='infinity')
            else:
                row.update(MainPID='0',ControlPID='0',ControlGroup='',
                           NFileDescriptorStore='0')
            rows[unit]=row
        for unit,field,value in corrupt:
            rows[unit][field]=value
        return rows

    def observe(self, rows, *, fail_cgroup=None):
        def run(command,**_kwargs):
            unit=command[2]
            value=''.join(key+'='+item+'\n' for key,item in rows[unit].items())
            return SimpleNamespace(returncode=0,stdout=value.encode(),stderr=b'')
        def receipt(path,*_args,**_kwargs):
            self.assertEqual(path,guardian.ROTATION_ACTOR_INTENT)
            return {'static_units':[
                {'unit':unit,'unit_file_state':'static'}
                for unit,_relative in guardian.ROTATION_STATIC_UNITS]}
        def fixed_group(unit):
            if unit==fail_cgroup:
                raise guardian.Refused('fixed_named_cgroup_populated')
        with (mock.patch.object(guardian.subprocess,'run',side_effect=run),
              mock.patch.object(guardian,'record',side_effect=receipt) as records,
              mock.patch.object(guardian,'_rotation_actor_facts',
                                side_effect=lambda unit,**_kw:rows[unit]),
              mock.patch.object(guardian,'_rotation_static_facts',
                                side_effect=lambda unit,**_kw:rows[unit]),
              mock.patch.object(guardian,'_cold_archive_fixed_cgroup_empty',
                                side_effect=fixed_group) as cgroups,
              mock.patch.object(guardian,'_rotation_actor_jobs')):
            result=guardian._cold_archive_rotation_units_absent(
                time.monotonic()+30)
            records.assert_called_once_with(guardian.ROTATION_ACTOR_INTENT)
            self.assertEqual(cgroups.call_count,16)
            return result

    def test_exact_missing_actor_is_exposed_for_native_roster_join(self):
        unit='aegis-auto-guardian.service'
        self.assertEqual(self.observe(self.facts(missing=(unit,))),[unit])

    def test_missing_unit_with_fragment_path_refuses(self):
        unit='aegis-auto-guardian.service'
        rows=self.facts(missing=(unit,),corrupt=((unit,'FragmentPath','/tmp/foreign'),))
        with self.assertRaises(guardian.Refused):
            self.observe(rows)

    def test_loaded_actor_with_live_pid_refuses(self):
        unit='aegis-auto-guardian.service'
        rows=self.facts(corrupt=((unit,'MainPID','123'),))
        with self.assertRaises(guardian.Refused):
            self.observe(rows)

    def test_fixed_named_cgroup_refuses_even_with_empty_pid1_controlgroup(self):
        unit='aegis-auto-guardian.service'
        rows=self.facts()
        self.assertEqual(rows[unit]['ControlGroup'],'')
        with self.assertRaises(guardian.Refused):
            self.observe(rows,fail_cgroup=unit)


if __name__=='__main__':
    unittest.main()
