"""Source-bound pre-package anchors and durable observer retirement records.

This fixture never starts PID 1 units or touches installed paths. Live PID 1
retirement still needs the protected Linux VM admission before product GO.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / 'lib/aegis_auto_terminal_register.py'
spec = importlib.util.spec_from_file_location('terminal_registrar_source_under_test', SOURCE)
registrar = importlib.util.module_from_spec(spec)
spec.loader.exec_module(registrar)


def raw(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


class CustodyTests(unittest.TestCase):
    def test_old_ready_cannot_be_reused_for_new_observer(self):
        boot = '00000000-0000-0000-0000-000000000000'
        live = {'observer_pid':222,'observer_start_tick':333,
                'observer_invocation_id':'a'*32,
                'observer_source_sha256':'b'*64,
                'source_config_sha256':'c'*64}
        row = {'schema':'aegis_auto_terminal_witness_ready_v2',
               'boot':boot,'pid1_tick':0,'pid1_private_bus_peer':1,
               'pid1_private_bus_ready':True,
               'job_removed_match_registered':True,
               'kernel_connector_ack':True,**live}
        registrar._observer_ready_match(row,live,
                                        {'witness_sha256':'b'*64},'c'*64,boot,0)
        changed = {**live,'observer_pid':223,'observer_start_tick':334,
                   'observer_invocation_id':'d'*32}
        with self.assertRaisesRegex(registrar.Refused,'terminal_observer_not_ready'):
            registrar._observer_ready_match(row,changed,
                                            {'witness_sha256':'b'*64},'c'*64,boot,0)
        with self.assertRaisesRegex(registrar.Refused,'terminal_observer_not_ready'):
            registrar._observer_ready_match(row,live,
                                            {'witness_sha256':'e'*64},'c'*64,boot,0)

    def test_native_anchor_binds_every_terminal_helper_before_package_effect(self):
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary)
            names = (
                'scripts/lib/aegis_auto_terminal_register.py',
                'scripts/lib/aegis_auto_terminal_witness.py',
                'scripts/lib/aegis_auto_terminal_boot_store.py',
                'scripts/lib/aegis_auto_boot_transition.py',
                'scripts/lib/aegis_auto_guardian.py',
                'scripts/lib/aegis_installer_auto_v2.py',
                'packaging/systemd/aegis-auto-terminal-a@.service',
                'packaging/systemd/aegis-auto-terminal-b@.service',
                'packaging/systemd/aegis-auto-terminal-observer.service',
                'packaging/systemd/aegis-auto-terminal-transition.service',
                'packaging/systemd/system-shutdown/aegis-auto-terminal-hook',
            )
            files = {name: (name+'\n').encode() for name in names}
            manifest = raw({'schema':'aegis_release_bundle_manifest_v2',
                            'files':['SHA256SUMS',*names]})
            sums = ''.join(sha(data)+'  '+name+'\n'
                           for name,data in files.items()).encode()
            files['bundle.manifest.json'] = manifest
            files['SHA256SUMS'] = sums
            successor = {'kind':'upgrade','next_public_payload_root':str(release),
                         'next_candidate_binary':str(release/'bin/aegis-client'),
                         'next_candidate_sha256':'a'*64,
                         'next_bundle_manifest_sha256':sha(manifest),
                         'next_sums_sha256':sha(sums)}
            guardian = type('Guardian',(),{'_rotation_intent':lambda self,fd:
                {'old_install_sha256':'b'*64,'successor':successor}})()
            def held(path,maximum,mode):
                return files[str(Path(path).relative_to(release))]
            with mock.patch.object(registrar,'held',side_effect=held):
                self.assertEqual(registrar._migration_rotation_bound(
                    guardian,10,release,'a'*64,'b'*64),
                    (sha(manifest),sha(sums)))
                files['scripts/lib/aegis_auto_terminal_witness.py'] = b'changed\n'
                with self.assertRaisesRegex(registrar.Refused,
                                            'migration_next_helper_changed'):
                    registrar._migration_rotation_bound(
                        guardian,10,release,'a'*64,'b'*64)
                files['scripts/lib/aegis_auto_terminal_witness.py'] = (
                    'scripts/lib/aegis_auto_terminal_witness.py\n').encode()
                files['SHA256SUMS'] = sums+b'0'*64+b'  forged\n'
                with self.assertRaisesRegex(registrar.Refused,
                                            'migration_next_bundle_anchor_changed'):
                    registrar._migration_rotation_bound(
                        guardian,10,release,'a'*64,'b'*64)
                files['SHA256SUMS'] = sums
                saved = successor.pop('next_sums_sha256')
                with self.assertRaisesRegex(registrar.Refused,
                                            'migration_rotation_mismatch'):
                    registrar._migration_rotation_bound(
                        guardian,10,release,'a'*64,'b'*64)
                successor['next_sums_sha256'] = saved

    def test_edge_publication_pins_orphan_roster(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent=Path(temporary);intent='a'*64
            edge={'schema':'aegis_auto_terminal_migration_edge_v1',
                  'intent_sha256':intent,
                  'old_source_sha256':'b'*64,
                  'new_source_sha256':'c'*64,
                  'old_context_sha256':'d'*64,
                  'prior_head_sha256':None,
                  'candidate_sha256':'e'*64,
                  'package_sha256':'f'*64,
                  'next_bundle_manifest_sha256':'1'*64,
                  'next_sums_sha256':'2'*64,
                  'observer_runtime_sha256':'3'*64,
                  'new_install_sha256':'4'*64,
                  'new_observer_orphan_sha256s':['5'*64]}
            content=raw(edge);path=parent/('edge-'+sha(content)+'.json')
            path.write_bytes(content)
            with (mock.patch.object(registrar,'MIGRATION',parent),
                  mock.patch.object(registrar,'held',side_effect=lambda name,maxi,mode:
                                    Path(name).read_bytes())):
                self.assertEqual(registrar._migration_existing_edge_for_pending(intent),edge)
                self.assertIsNone(registrar._migration_existing_edge_for_pending('c'*64))
                second=parent/('edge-'+sha(raw({**edge,'candidate_sha256':'6'*64}))+'.json')
                second.write_bytes(raw({**edge,'candidate_sha256':'6'*64}))
                with self.assertRaisesRegex(registrar.Refused,'migration_edge_fork'):
                    registrar._migration_existing_edge_for_pending(intent)

    def test_new_orphan_socket_must_have_no_live_kernel_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);network=root/'unix';run=root/'run';run.mkdir()
            original=Path
            def redirected(value,*args):
                if value=='/proc/net/unix':return network
                return original(value,*args)
            header='Num RefCount Protocol Flags Type St Inode Path\n'
            network.write_text(header)
            with (mock.patch.object(registrar,'Path',side_effect=redirected),
                  mock.patch.object(registrar,'RUN',run)):
                registrar._migration_orphan_socket_unbound()
                network.write_text(header+
                    '00000000: 00000002 00000000 00010000 0005 01 12345 '+
                    str(run/'observer.sock')+'\n')
                with self.assertRaisesRegex(registrar.Refused,
                                            'migration_new_orphan_socket_live'):
                    registrar._migration_orphan_socket_unbound()

    def test_final_orphan_ready_needs_complete_pid1_and_peer_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);proc=root/'proc';proc.mkdir()
            stat_file=root/'stat'
            stat_file.write_text('1 (systemd) '+' '.join(
                ['S']+['0']*18+['7']+['0']*5)+'\n')
            original=Path
            def redirected(value,*args):
                if value=='/proc/1/stat':return stat_file
                if value=='/proc':return proc
                return original(value,*args)
            boot='00000000-0000-0000-0000-000000000000'
            row={'schema':'aegis_auto_terminal_witness_ready_v2',
                 'boot':boot,'pid1_tick':7,'pid1_private_bus_peer':1,
                 'pid1_private_bus_ready':True,
                 'job_removed_match_registered':True,
                 'kernel_connector_ack':True,
                 'observer_pid':123,'observer_start_tick':456,
                 'observer_invocation_id':'a'*32,
                 'observer_source_sha256':'b'*64,
                 'source_config_sha256':'c'*64}
            with mock.patch.object(registrar,'Path',side_effect=redirected):
                self.assertEqual(registrar._migration_orphan_ready(
                    raw(row),'c'*64,'b'*64,boot),row)
                for changed in ({**row,'pid1_private_bus_peer':0},
                                {**row,'kernel_connector_ack':False},
                                {key:value for key,value in row.items()
                                 if key!='job_removed_match_registered'}):
                    with self.assertRaises(registrar.Refused):
                        registrar._migration_orphan_ready(
                            raw(changed),'c'*64,'b'*64,boot)

    def test_new_orphan_archive_is_bound_to_pending_and_b_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent=Path(temporary)
            pending='a'*64;source='b'*64;witness='c'*64
            row={'schema':'aegis_auto_terminal_new_observer_orphan_v1',
                 'pending_sha256':pending,'new_source_sha256':source,
                 'new_witness_sha256':witness,
                 'boot_id':'00000000-0000-0000-0000-000000000000',
                 'run_dev':1,'run_ino':2,'unit_state':'failed','members':{}}
            content=raw(row);digest=sha(content)
            path=parent/('observer-new-orphan-'+pending+'-'+digest+'.json')
            path.write_bytes(content)
            with (mock.patch.object(registrar,'held',side_effect=lambda name,maxi,mode:
                                    Path(name).read_bytes()),
                  mock.patch.object(Path,'read_text',autospec=True,
                                    side_effect=lambda path,*args,**kwargs:
                                    '00000000-0000-0000-0000-000000000000'
                                    if str(path).endswith('/boot_id') else
                                    Path.open(path).read())):
                self.assertEqual(registrar._migration_new_orphan_record(
                    path,pending,source,witness)[0],row)
                with self.assertRaisesRegex(registrar.Refused,
                                            'migration_new_orphan_archive_changed'):
                    registrar._migration_new_orphan_record(
                        path,pending,'d'*64,witness)

    def test_archived_old_ready_requires_exact_pending_and_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            location = Path(temporary)
            pending = raw({'unit':'aegis-auto@'+'c'*64+'.service'})
            pending_sha = sha(pending)
            ready = {'schema':'aegis_auto_terminal_witness_ready_v2',
                     'boot':'00000000-0000-0000-0000-000000000000',
                     'pid1_tick':0,'pid1_private_bus_peer':1,
                     'pid1_private_bus_ready':True,
                     'job_removed_match_registered':True,
                     'kernel_connector_ack':True,
                     'observer_pid':123,'observer_start_tick':456,
                     'observer_invocation_id':'a'*32,
                     'observer_source_sha256':'d'*64,
                     'source_config_sha256':'e'*64}
            ready_raw = raw(ready)
            record = {'schema':'aegis_auto_terminal_observer_runtime_v1',
                      'pending_sha256':pending_sha,
                      'old_source_sha256':'e'*64,
                      'boot_id':'00000000-0000-0000-0000-000000000000',
                      'ready_hex':ready_raw.hex(),'ready_sha256':sha(ready_raw),
                      **{key:ready[key] for key in
                         ('observer_pid','observer_start_tick',
                          'observer_invocation_id','observer_source_sha256',
                          'source_config_sha256')},
                      'run_dev':1,'run_ino':2,
                      'members':{'ready.json':{'stat':[1]*9,'hex':ready_raw.hex()},
                                 'observer.sock':{'stat':[1]*9,'hex':None}}}
            archive = location/('observer-runtime-'+pending_sha+'.json')
            archive.write_bytes(raw(record))
            with (mock.patch.object(registrar,'MIGRATION',location),
                  mock.patch.object(registrar,'held',side_effect=lambda path,maxi,mode:
                                    Path(path).read_bytes()),
                  mock.patch.object(Path,'read_text',autospec=True,
                                    side_effect=lambda path,*args,**kwargs:
                                    '00000000-0000-0000-0000-000000000000'
                                    if str(path).endswith('/boot_id') else
                                    Path.open(path).read())):
                row,_ = registrar._migration_runtime_archive(pending,'e'*64)
                self.assertEqual(row['ready_sha256'],sha(ready_raw))
                with self.assertRaisesRegex(registrar.Refused,
                                            'migration_observer_archive_changed'):
                    registrar._migration_runtime_archive(pending,'f'*64)


if __name__ == '__main__':
    unittest.main()
