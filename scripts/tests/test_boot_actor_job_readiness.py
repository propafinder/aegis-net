"""Boot-only pending-job readiness with unchanged final actor authority."""
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/lib'))
F2_EXCERPTS = r'''def _rotation_actor_jobs(deadline: float) -> None:
    remaining = deadline - time.monotonic()
    need(remaining > 0, "rotation_actor_deadline_elapsed")
    result = subprocess.run(
        ["/usr/bin/systemctl", "list-jobs", "--no-legend", "--no-pager",
         "--plain"], stdin=subprocess.DEVNULL, capture_output=True,
        timeout=min(3.0, remaining), check=False,
        env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C", "LC_ALL": "C"})
    need(result.returncode == 0 and len(result.stdout) <= 1 << 16 and
         len(result.stderr) <= 4096 and
         not any("aegis-" in line for line in
                 result.stdout.decode("ascii").splitlines()),
         "rotation_actor_job_pending")

def _boot_actor_observation(deadline: float) -> list[dict[str, object]]:
    observations: list[dict[str, object]] = []
    for unit, source, _path in ROTATION_ACTORS:
        facts = _rotation_actor_facts(unit, deadline=deadline)
        pid = int(facts["MainPID"])
        need(facts["ControlPID"] == "0" and
             facts["NFileDescriptorStore"] == "0" and
             (pid == 0 and facts["ActiveState"] == "inactive" and
              facts["SubState"] == "dead" or
              pid > 1 and facts["ActiveState"] == "active" and
              facts["SubState"] == "running" and
              HEX32.fullmatch(facts["InvocationID"]) is not None),
             "boot_actor_state_invalid")
        if pid > 1:
            need(facts["ControlGroup"] == "/system.slice/" + unit and
                 Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii") ==
                 "0::" + facts["ControlGroup"] + "\n" and
                 Path(f"/proc/{pid}/cmdline").read_bytes() ==
                 _rotation_actor_command(unit, source),
                 "boot_actor_identity_changed")
            handle = os.pidfd_open(pid, 0)
            try:
                need(_pid_alive(handle), "boot_actor_identity_changed")
            finally:
                os.close(handle)
        observations.append({"unit": unit, "active": pid > 1,
                             "main_pid": pid,
                             "invocation_id": facts["InvocationID"] if pid else None})
    _rotation_static_stopped(deadline)
    _rotation_actor_jobs(deadline)
    return observations
'''
assert hashlib.sha256(F2_EXCERPTS.encode()).hexdigest() == '6141569d66dcd03f3730bdbfbde5f557b46056abc411256f8833c9f0e8ac4a33'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


new = load('aegis_guardian_r22_readiness', ROOT / 'scripts/lib/aegis_auto_guardian.py')
old = ModuleType('aegis_guardian_f2_readiness')
old.__dict__.update(new.__dict__)
exec(compile(F2_EXCERPTS, 'F2 guardian job and boot observation excerpts', 'exec'), old.__dict__)

PENDING = b'1084 aegis-device-dhcp-refresh.service start running\n'
MALFORMED = b'not-a-job aegis-device-dhcp-refresh.service start running\n'


def result(stdout=b'', returncode=0, stderr=b''):
    return SimpleNamespace(stdout=stdout, returncode=returncode, stderr=stderr)


def inactive(_unit, **_kwargs):
    return {'MainPID': '0', 'ControlPID': '0', 'NFileDescriptorStore': '0',
            'ActiveState': 'inactive', 'SubState': 'dead',
            'InvocationID': '', 'ControlGroup': ''}


class BootActorJobReadinessTests(unittest.TestCase):
    def observe(self, module, responses, *, facts=inactive, static=None, deadline=2):
        calls = []
        def read_jobs(*_args, **_kwargs):
            calls.append('job')
            return responses.pop(0)
        with patch.object(module, '_rotation_actor_facts', side_effect=facts), \
             patch.object(module, '_rotation_static_stopped', side_effect=static), \
             patch.object(module.subprocess, 'run', side_effect=read_jobs):
            value = module._boot_actor_observation(time.monotonic() + deadline)
        return value, calls

    def test_f2_refuses_transient_job_r22_restarts_full_roster_and_settles(self):
        with self.assertRaisesRegex(old.Refused, "rotation_actor_job_pending"):
            self.observe(old, [result(PENDING)])
        visited = []
        def facts(unit, **_kwargs):
            visited.append(unit)
            return inactive(unit)
        static_calls = []
        def static(_deadline):
            static_calls.append('static')
        observed, calls = self.observe(new, [result(PENDING), result()],
                                       facts=facts, static=static)
        roster = [unit for unit, _source, _path in new.ROTATION_ACTORS]
        self.assertEqual(visited, roster + roster)
        self.assertEqual(static_calls, ['static', 'static'])
        self.assertEqual(calls, ['job', 'job'])
        self.assertEqual([row['unit'] for row in observed], roster)
        self.assertTrue(all(row['active'] is False for row in observed))

    def test_pending_from_static_check_restarts_full_roster(self):
        visited = []
        def facts(unit, **_kwargs):
            visited.append(unit)
            return inactive(unit)
        static = [new.RotationActorJobPending('rotation_actor_job_pending'), None]
        with patch.object(new, '_rotation_actor_facts', side_effect=facts), \
             patch.object(new, '_rotation_static_stopped', side_effect=static), \
             patch.object(new, '_rotation_actor_jobs') as jobs:
            observed = new._boot_actor_observation(time.monotonic() + 2)
        self.assertEqual(len(visited), 2 * len(new.ROTATION_ACTORS))
        self.assertEqual(len(observed), len(new.ROTATION_ACTORS))
        jobs.assert_called_once()

    def test_persistent_job_exhausts_original_deadline(self):
        seen = []
        def facts(unit, **_kwargs):
            seen.append(unit)
            return inactive(unit)
        with patch.object(new, '_rotation_actor_facts', side_effect=facts), \
             patch.object(new, '_rotation_static_stopped'), \
             patch.object(new.subprocess, 'run', return_value=result(PENDING)) as jobs:
            start = time.monotonic()
            with self.assertRaisesRegex(new.Refused, 'rotation_actor_deadline_elapsed'):
                new._boot_actor_observation(start + 0.14)
        self.assertLess(time.monotonic() - start, 1)
        self.assertGreaterEqual(jobs.call_count, 2)
        self.assertIn(len(seen), (jobs.call_count * len(new.ROTATION_ACTORS),
                                  (jobs.call_count + 1) * len(new.ROTATION_ACTORS)))

    def test_actor_cgroup_drift_after_wait_still_refuses(self):
        visited = []
        def drift(unit, **_kwargs):
            visited.append(unit)
            if len(visited) > len(new.ROTATION_ACTORS):
                return {'MainPID': '2345', 'ControlPID': '0',
                        'NFileDescriptorStore': '0', 'ActiveState': 'active',
                        'SubState': 'running', 'InvocationID': 'a' * 32,
                        'ControlGroup': '/system.slice/' + unit}
            return inactive(unit)
        with patch.object(new, '_rotation_actor_facts', side_effect=drift), \
             patch.object(new, '_rotation_static_stopped'), \
             patch.object(new.Path, 'read_text',
                          return_value='0::/system.slice/foreign.service\n'), \
             patch.object(new.subprocess, 'run', return_value=result(PENDING)) as jobs:
            with self.assertRaisesRegex(new.Refused, 'boot_actor_identity_changed'):
                new._boot_actor_observation(time.monotonic() + 2)
        jobs.assert_called_once()
        self.assertEqual(len(visited), len(new.ROTATION_ACTORS) + 1)

    def test_actor_and_source_drift_after_wait_still_refuse(self):
        visited = []
        def drift(unit, **_kwargs):
            visited.append(unit)
            if len(visited) > len(new.ROTATION_ACTORS):
                raise new.Refused('installed_source_changed')
            return inactive(unit)
        with patch.object(new, '_rotation_actor_facts', side_effect=drift), \
             patch.object(new, '_rotation_static_stopped'), \
             patch.object(new.subprocess, 'run', return_value=result(PENDING)) as jobs:
            with self.assertRaisesRegex(new.Refused, 'installed_source_changed'):
                new._boot_actor_observation(time.monotonic() + 2)
        jobs.assert_called_once()
        self.assertEqual(len(visited), len(new.ROTATION_ACTORS) + 1)

    def test_policy_drift_after_settle_still_refuses(self):
        first = {'state_sha256': 'a' * 64, 'policy_sha256': 'b' * 64,
                 'manager_binding_sha256': 'c' * 64}
        second = dict(first, policy_sha256='d' * 64)
        with patch.object(new, 'own_source'), \
             patch.object(new, '_held_lock', return_value=(11, 12)), \
             patch.object(new, 'record', return_value={'worker_sha256': 'e' * 64}), \
             patch.object(new, 'read_guard_policy', side_effect=[first, second]), \
             patch.object(new, 'digest', return_value='a' * 64), \
             patch.object(new, 'regular', return_value=b'fixed'), \
             patch.object(new, '_boot_pending_absent'), \
             patch.object(new, '_boot_fixed_client_stopped'), \
             patch.object(new, '_boot_private_owners_absent'), \
             patch.object(new, '_rotation_actor_facts', side_effect=inactive), \
             patch.object(new, '_rotation_static_stopped'), \
             patch.object(new.subprocess, 'run', side_effect=[result(PENDING), result()]) as jobs:
            with self.assertRaisesRegex(new.Refused, 'boot_deny_changed'):
                new.boot_denied_readback(11, 12)
        self.assertEqual(jobs.call_count, 2)

    def test_malformed_or_failed_job_readback_does_not_retry(self):
        for response in (result(MALFORMED), result(PENDING, stderr=b'warning'),
                         result(PENDING, returncode=1), result(b'1084 aegis-? start running\n')):
            with self.subTest(response=response):
                with patch.object(new, '_rotation_actor_facts', side_effect=inactive), \
                     patch.object(new, '_rotation_static_stopped'), \
                     patch.object(new.subprocess, 'run', return_value=response) as jobs:
                    with self.assertRaises(new.Refused) as refused:
                        new._boot_actor_observation(time.monotonic() + 2)
                self.assertIs(type(refused.exception), new.Refused)
                jobs.assert_called_once()

    def test_foreign_job_refuses_without_boot_retry(self):
        for unit in ('aegis-foreign-job.service', 'aegis-auto-guardian.service',
                     'aegis-device-dhcp-refresh-other.service'):
            with self.subTest(unit=unit):
                pending = f'1084 {unit} start running\n'.encode()
                with patch.object(new, '_rotation_actor_facts', side_effect=inactive), \
                     patch.object(new, '_rotation_static_stopped'), \
                     patch.object(new.subprocess, 'run', return_value=result(pending)) as jobs:
                    with self.assertRaises(new.Refused) as refused:
                        new._boot_actor_observation(time.monotonic() + 2)
                self.assertIs(type(refused.exception), new.Refused)
                jobs.assert_called_once()

    def test_own_refresh_non_start_job_refuses_without_boot_retry(self):
        for kind in ('stop', 'restart', 'reload'):
            pending = f'1084 aegis-device-dhcp-refresh.service {kind} running\n'.encode()
            with self.subTest(kind=kind), \
                 patch.object(new, '_rotation_actor_facts', side_effect=inactive), \
                 patch.object(new, '_rotation_static_stopped'), \
                 patch.object(new.subprocess, 'run', return_value=result(pending)) as jobs:
                with self.assertRaises(new.Refused) as refused:
                    new._boot_actor_observation(time.monotonic() + 2)
                self.assertIs(type(refused.exception), new.Refused)
                jobs.assert_called_once()

    def test_mixed_own_and_foreign_jobs_refuse_without_boot_retry(self):
        pending = PENDING + b'1085 aegis-foreign-job.service start waiting\n'
        with patch.object(new, '_rotation_actor_facts', side_effect=inactive), \
             patch.object(new, '_rotation_static_stopped'), \
             patch.object(new.subprocess, 'run', return_value=result(pending)) as jobs:
            with self.assertRaises(new.Refused) as refused:
                new._boot_actor_observation(time.monotonic() + 2)
        self.assertIs(type(refused.exception), new.Refused)
        jobs.assert_called_once()

    def test_global_rotation_job_check_still_refuses(self):
        with patch.object(new.subprocess, 'run', return_value=result(PENDING)) as jobs:
            with self.assertRaises(new.Refused):
                new._rotation_actor_jobs(time.monotonic() + 2)
        jobs.assert_called_once()


if __name__ == '__main__':
    unittest.main()
