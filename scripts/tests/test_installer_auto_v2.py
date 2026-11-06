"""Local coordinator fault controls; no PID 1 or native admission claim."""

import importlib.util
import hashlib
import json
import os
import stat
from pathlib import Path
import tempfile
import unittest
import subprocess
import sys
import io
import re
import time
from contextlib import ExitStack
from types import SimpleNamespace
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1] / "lib" / "aegis_installer_auto_v2.py"
SPEC = importlib.util.spec_from_file_location("aegis_installer_auto_v2_test", SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
GUARDIAN_SOURCE = SOURCE.with_name("aegis_auto_guardian.py")
GUARDIAN_SPEC = importlib.util.spec_from_file_location("aegis_auto_guardian_passive_test",
                                                       GUARDIAN_SOURCE)
GUARDIAN = importlib.util.module_from_spec(GUARDIAN_SPEC)
GUARDIAN_SPEC.loader.exec_module(GUARDIAN)


class CoordinatorFaults(unittest.TestCase):
    def test_reapplied_package_does_not_take_completed_abort_recovery_path(self):
        with tempfile.TemporaryDirectory() as raw:
            archives = Path(raw) / 'archives'
            archives.mkdir()
            helper = Path('/usr/local/lib/aegis/helpers/lib/fixture.py')
            original_exists = Path.exists
            with mock.patch.object(MODULE, 'PASSIVE_ABORT_ARCHIVES', archives), \
                 mock.patch.object(MODULE, 'FRESH_CLIENT_HELPERS', ('lib/fixture.py',)), \
                 mock.patch.object(MODULE.Path, 'exists', autospec=True,
                     side_effect=lambda path: path == helper or original_exists(path)), \
                 mock.patch.object(MODULE, '_abort_completed_plan') as completed:
                self.assertFalse(MODULE._aborted_package_requires_reapply(9))
                completed.assert_not_called()

    def test_completed_fresh_abort_requires_typed_package_reapply_before_dpkg_verify(self):
        import contextlib
        root = Path('/var/lib/aegis-auto/releases/fixture-aborted-package')
        with tempfile.TemporaryDirectory() as raw:
            archives = Path(raw) / 'archives'
            archives.mkdir()
            commands = []
            def output(argv, **_kwargs):
                commands.append(tuple(argv))
                if argv[:2] == ['/usr/bin/dpkg-deb', '--field']:
                    return {'Version': b'0.3.50-19\n',
                            'Architecture': b'arm64\n'}[argv[-1]]
                if argv[0] == '/usr/bin/dpkg-query':
                    return b'install ok installed\n0.3.50-19\narm64\n'
                raise AssertionError('dpkg verification must not precede typed abort recovery')
            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch.object(MODULE.sys, 'platform', 'linux'), \
                 mock.patch.object(MODULE.os, 'geteuid', return_value=0), \
                 mock.patch.object(MODULE, 'uninstall_intent_present', return_value=False), \
                 mock.patch.object(MODULE, 'PASSIVE_ABORT_ARCHIVES', archives), \
                 mock.patch.object(MODULE, 'FRESH_CLIENT_HELPERS', ('lib/fixture.py',)), \
                 mock.patch.object(MODULE, 'fresh_package_lock'), \
                 mock.patch.object(MODULE, 'signed_client_package',
                                   return_value=(root / 'client.deb', 'a' * 64)), \
                 mock.patch.object(MODULE, '_abort_completed_plan',
                                   return_value=(archives / 'abort-fixture', {'run_id': 'a' * 32})), \
                 mock.patch.object(MODULE, 'call_output', side_effect=output), \
                 contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(MODULE.main(['admit-fresh-package',
                    '--public-payload-root', str(root), '--install-fd', '9']), 1)
            self.assertEqual(json.loads(stdout.getvalue()), {
                'status': 'refused', 'class': 'fresh_passive_aborted_reapply_required'})
            self.assertIn('class=fresh_passive_aborted_reapply_required', stderr.getvalue())
            self.assertIn('Reapply the exact client package', stderr.getvalue())
            self.assertFalse(any(argv[0] == '/usr/bin/dpkg' for argv in commands))

    @unittest.skipUnless(os.geteuid() == 0, "root-owned installed source fixture")
    def test_guarded_readiness_never_accepts_sticky_or_dangling_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "guardian.py"
            source.write_bytes(b"# pinned fixture\n")
            source.chmod(0o500)
            candidate = root / "candidate"
            candidate.write_bytes(b"candidate")
            incident = root / "foreign-policy-drift.json"
            installation = {"worker_sha256": hashlib.sha256(b"candidate").hexdigest(),
                            "guard_unit_sha256": "a" * 64}
            reached = RuntimeError("semantic readback reached")
            fake = SimpleNamespace(
                INSTALL=root / "install.json", STOP_INTENT=root / "stop.json",
                POLICY=root / "policy.json", own_source=lambda: None,
                record=lambda _path: installation,
                _semantic_policy_readback=mock.Mock(side_effect=reached))
            with mock.patch.object(MODULE, "passive_actor_status", return_value=([], [])), \
                 mock.patch.object(MODULE, "installed_guardian", return_value=fake):
                # With no alarm the actual readiness path reaches semantics.
                with self.assertRaisesRegex(RuntimeError, "semantic readback reached"):
                    MODULE.guardian_ready(candidate, "guarded")
                fake._semantic_policy_readback.reset_mock()
                for kind in ("record", "dangling"):
                    if kind == "record":
                        incident.write_bytes(b"sticky incident")
                    else:
                        incident.symlink_to(root / "absent")
                    with self.subTest(kind=kind), self.assertRaises(MODULE.Refused):
                        MODULE.guardian_ready(candidate, "guarded")
                    fake._semantic_policy_readback.assert_not_called()
                    incident.unlink()

    def test_admission_refusals_emit_one_fixed_phase_line_without_error_contents(self):
        import contextlib
        import io
        root = Path("/var/lib/aegis-auto/releases/diagnostic-source-1234")
        argv = ["admit-fresh-package", "--public-payload-root", str(root), "--install-fd", "9"]
        for target, kind in [("abort_pending", "refused"), ("lock", "refused"),
                             ("signed_package", "os_error"), ("signed_package", "unexpected"),
                             ("dpkg_status", "refused"), ("dpkg_verify", "timeout"),
                             ("absent_path:0", "refused")]:
            with self.subTest(phase=target, kind=kind):
                def lock(_fd):
                    if target == "lock":
                        raise MODULE.Refused("PRIVATE_SENTINEL")
                def package(_root):
                    if target == "signed_package":
                        if kind == "os_error":
                            raise OSError(5, "PRIVATE_SENTINEL")
                        raise ValueError("PRIVATE_SENTINEL")
                    return root / "client.deb", "a" * 64
                def output(args, **kwargs):
                    if args[0] == "/usr/bin/dpkg-deb":
                        return {"Version": b"1.2.3\n", "Architecture": b"amd64\n"}[args[-1]]
                    if args[0] == "/usr/bin/dpkg-query":
                        return (b"install ok unpacked\n1.2.3\namd64\n" if target == "dpkg_status"
                                else b"install ok installed\n1.2.3\namd64\n")
                    if target == "dpkg_verify":
                        raise subprocess.TimeoutExpired("PRIVATE_SENTINEL", 1)
                    return b""
                stdout, stderr = io.StringIO(), io.StringIO()
                with contextlib.ExitStack() as stack:
                    for obj, name, kwargs in [
                        (MODULE.sys, "platform", {"new": "linux"}),
                        (MODULE.os, "geteuid", {"return_value": 0}),
                        (MODULE.Path, "exists", {"side_effect": lambda: MODULE._PHASE == target
                                                 and target in ("abort_pending", "absent_path:0")}),
                        (MODULE.Path, "is_symlink", {"return_value": False}),
                        (MODULE, "fresh_package_lock", {"side_effect": lock}),
                        (MODULE, "signed_client_package", {"side_effect": package}),
                        (MODULE, "call_output", {"side_effect": output}),
                    ]:
                        stack.enter_context(mock.patch.object(obj, name, **kwargs))
                    stack.enter_context(contextlib.redirect_stdout(stdout))
                    stack.enter_context(contextlib.redirect_stderr(stderr))
                    self.assertEqual(MODULE.main(argv), 1)
                self.assertEqual(stdout.getvalue(), '{"status":"refused"}\n')
                self.assertRegex(stderr.getvalue(), r"\AAUTO_V2_HELPER_REFUSED operation=admit-fresh-package phase="
                                 + re.escape(target) + " class=" + kind + r" line=[0-9]+\n\Z")
                self.assertNotIn("PRIVATE_SENTINEL", stderr.getvalue())
                line = int(stderr.getvalue().split("line=")[1])
                self.assertNotIn(line, (MODULE.need.__code__.co_firstlineno + 1,
                                        MODULE.need.__code__.co_firstlineno + 2))

    def test_terminal_start_tick_accepts_kernel_bytes_and_parentheses_in_comm(self):
        # Fields 3..21 precede starttime (22); later fields must not affect it.
        stat_line = (b"1234 (aegis worker) name)) S 1 2 3 4 5 6 7 8 9 10 11 "
                     b"12 13 14 15 16 17 18 361782593 8192 2 3\n")
        self.assertEqual(MODULE._terminal_start_tick(stat_line), 361782593)

    def test_terminal_start_tick_rejects_truncation_and_non_ascii_numbers(self):
        prefix = b"1234 (aegis-client) S " + b"1 " * 18
        for value in (b"", b"0", b"-1", b"+1", b"1x", b"\xc2\xb2"):
            with self.subTest(value=value), self.assertRaises(MODULE.Refused):
                MODULE._terminal_start_tick(prefix + value)
        for raw in (b"", b"1234 no closing comm", b"1234 (aegis-client) S 1",
                    b"1234 (" + b"x" * 4096 + b") S 1"):
            with self.subTest(raw=raw[:32]), self.assertRaises(MODULE.Refused):
                MODULE._terminal_start_tick(raw)

    def test_passive_package_requires_fully_configured_exact_deb(self):
        package = Path("/var/lib/aegis-auto/releases/exact/package.deb")

        def query(argv, **_kwargs):
            if argv[0] == "/usr/bin/dpkg-deb":
                return {"Version": b"1.2.3\n", "Architecture": b"arm64\n"}[argv[-1]]
            return b"install ok unpacked|1.2.3|arm64"

        with mock.patch.object(MODULE, "call_output", side_effect=query):
            self.assertFalse(MODULE._passive_package_complete(package))
        with mock.patch.object(MODULE, "call_output", side_effect=lambda argv, **kw:
                               b"install ok installed|1.2.3|arm64" if argv[0] ==
                               "/usr/bin/dpkg-query" else query(argv, **kw)):
            self.assertTrue(MODULE._passive_package_complete(package))

    def test_passive_package_half_configured_is_never_complete(self):
        package = Path("/var/lib/aegis-auto/releases/exact/package.deb")
        def query(argv, **_kwargs):
            if argv[0] == "/usr/bin/dpkg-deb":
                return {"Version": b"1.2.3\n", "Architecture": b"arm64\n"}[argv[-1]]
            return b"install ok half-configured|1.2.3|arm64"
        with mock.patch.object(MODULE, "call_output", side_effect=query):
            self.assertEqual(MODULE._passive_package_state(package), "half-configured")
            self.assertFalse(MODULE._passive_package_complete(package))
        def foreign(argv, **_kwargs):
            if argv[0] == "/usr/bin/dpkg-deb":
                return {"Version": b"1.2.3\n", "Architecture": b"arm64\n"}[argv[-1]]
            return b"install ok installed|1.2.4|arm64"
        with mock.patch.object(MODULE, "call_output", side_effect=foreign):
            self.assertIsNone(MODULE._passive_package_state(package))

    def test_passive_compensated_retry_closes_lock_and_reauthenticates(self):
        root = Path("/var/lib/aegis-auto/releases/next-release-identity")
        package = root / "packages/client.deb"
        candidate = root / "bin/aegis-client"
        status = {"phase": "package-installed", "old_candidate_sha256": "a" * 64,
                  "candidate_sha256": "b" * 64, "preinst_sha256": "c" * 64,
                  "successor_intent_sha256": "d" * 64}
        calls = []
        def resume(*_args):
            calls.append("resume")
            return "current_pending"
        def certificate(*_args):
            calls.append("certificate")
        def status_read(*_args):
            calls.append("status")
            return dict(status, phase="pending-old") if calls.count("status") > 1 else status
        def close(fd):
            calls.append(("close", fd))
        with mock.patch.object(MODULE, "_open_original_lock", side_effect=[9, 9]), \
             mock.patch.object(MODULE, "_passive_transition_status", side_effect=status_read), \
             mock.patch.object(MODULE, "_passive_resume_package", side_effect=resume), \
             mock.patch.object(MODULE, "recover_current", return_value="recovered"), \
             mock.patch.object(MODULE, "_passive_compensated_readback", side_effect=certificate), \
             mock.patch.object(MODULE, "_passive_package_source"), \
             mock.patch.object(MODULE, "_passive_package_state", return_value="installed"), \
             mock.patch.object(MODULE, "_passive_finish_prepare", return_value="terminal_active"), \
             mock.patch.object(MODULE.os, "close", side_effect=close):
            self.assertEqual(MODULE._passive_continue(root, package, candidate,
                             "b" * 64, "socks-only", {}), "terminal_active")
        self.assertEqual(calls, ["status", "resume", ("close", 9), "certificate",
                                 "status", ("close", 9)])

    def test_unsealed_finalized_retry_uses_distinct_stopped_certificate(self):
        root = Path("/var/lib/aegis-auto/releases/next-release-identity")
        candidate = root / "bin/aegis-client"
        status = {"phase": "package-installed", "old_candidate_sha256": "a" * 64,
                  "candidate_sha256": "b" * 64, "preinst_sha256": "c" * 64,
                  "successor_intent_sha256": "d" * 64}
        with mock.patch.object(MODULE, "_open_original_lock", side_effect=[9, 9]), \
             mock.patch.object(MODULE, "_passive_transition_status", return_value=status), \
             mock.patch.object(MODULE, "_passive_resume_package",
                               return_value="current_pending"), \
             mock.patch.object(MODULE, "recover_current", return_value="recovered_stopped"), \
             mock.patch.object(MODULE, "_passive_compensated_readback") as rollback, \
             mock.patch.object(MODULE, "_passive_unsealed_stopped_readback") as stopped, \
             mock.patch.object(MODULE, "_passive_resume_unsealed"), \
             mock.patch.object(MODULE, "_passive_package_source") as source, \
             mock.patch.object(MODULE, "_passive_package_state", return_value="installed"), \
             mock.patch.object(MODULE, "_passive_finish_prepare",
                               return_value="terminal_active"), \
             mock.patch.object(MODULE.os, "close"):
            self.assertEqual(MODULE._passive_continue(root, root / "package.deb",
                             candidate, "b" * 64, "socks-only", {}), "terminal_active")
        rollback.assert_not_called()
        stopped.assert_called_once()
        self.assertEqual(source.call_args.kwargs["installed_sha"], "b" * 64)

    def test_unsealed_journal_retry_reopens_status_before_package_effect(self):
        root = Path("/var/lib/aegis-auto/releases/next-release-identity")
        status = {"phase": "package-installed", "successor_intent_sha256": "a" * 64}
        order = []
        def read_status(*_args):
            order.append("status")
            return status
        def resume(*_args):
            order.append("resume")
        def package(*_args):
            order.append("package")
            return "terminal_active"
        def close(_fd):
            order.append("close")
        with mock.patch.object(MODULE, "_open_original_lock", side_effect=[9, 9]), \
             mock.patch.object(MODULE, "_passive_transition_status", side_effect=read_status), \
             mock.patch.object(MODULE, "_passive_unsealed_certificate_present", return_value=True), \
             mock.patch.object(MODULE, "_passive_resume_unsealed", side_effect=resume), \
             mock.patch.object(MODULE, "_passive_resume_package", side_effect=package), \
             mock.patch.object(MODULE, "_passive_completed_active",
                               return_value="terminal_active"), \
             mock.patch.object(MODULE.os, "close", side_effect=close):
            self.assertEqual(MODULE._passive_continue(root, root / "package.deb",
                             root / "bin/aegis-client", "b" * 64,
                             "socks-only", {}), "terminal_active")
        self.assertEqual(order, ["status", "close", "resume", "status",
                                 "package", "close"])

    def test_sealed_active_retry_does_not_replay_stopped_resume(self):
        root = Path("/var/lib/aegis-auto/releases/next-release-identity")
        status = {"phase": "new-active", "successor_intent_sha256": "a" * 64}
        order = []
        with mock.patch.object(MODULE, "_open_original_lock", return_value=9), \
             mock.patch.object(MODULE, "_passive_transition_status",
                               return_value=status), \
             mock.patch.object(MODULE, "_passive_unsealed_certificate_present",
                               side_effect=lambda *_: order.append("certificate")), \
             mock.patch.object(MODULE, "_passive_resume_unsealed",
                               side_effect=lambda *_: order.append("resume")), \
             mock.patch.object(MODULE, "_passive_resume_package",
                               return_value="terminal_active") as package, \
             mock.patch.object(MODULE, "_passive_completed_active",
                               return_value="terminal_active") as active, \
             mock.patch.object(MODULE.os, "close"):
            self.assertEqual(MODULE._passive_continue(root, root / "package.deb",
                             root / "bin/aegis-client", "b" * 64,
                             "socks-only", {}), "terminal_active")
        self.assertEqual(order, [])
        package.assert_called_once()
        active.assert_called_once_with(root, "b" * 64, advance=True)

    def test_passive_completed_requires_live_exact_source_before_archive(self):
        root = Path("/var/lib/aegis-auto/releases/next-release-identity")
        active = {"schema": "aegis_auto_v2_current_socks_active_v1",
                  "stage": "/var/lib/aegis-auto/stage/exact",
                  "public_payload_root": str(root),
                  "candidate_sha256": "a" * 64}
        commands = []
        def output(argv, **_kwargs):
            commands.append(argv[1])
            return json.dumps(active).encode()
        with mock.patch.object(MODULE, "call_output", side_effect=output), \
             mock.patch.object(MODULE, "control_directory", return_value=9), \
             mock.patch.object(MODULE, "current_pointer", return_value=None), \
             mock.patch.object(MODULE.os, "close"):
            with self.assertRaises(MODULE.Refused):
                MODULE._passive_completed_active(root, "b" * 64, advance=True)
        self.assertEqual(commands, ["auto-verify-current-socks"])

    def test_passive_completed_rejects_foreign_pointer_after_live_inspector(self):
        root = Path("/var/lib/aegis-auto/releases/next-release-identity")
        active = {"schema": "aegis_auto_v2_current_socks_active_v1",
                  "stage": "/run/aegis-installer-config-snapshots/active",
                  "public_payload_root": str(root),
                  "candidate_sha256": "a" * 64}
        calls = []
        def output(argv, **_kwargs):
            calls.append(argv[1])
            return json.dumps(active).encode()
        with mock.patch.object(MODULE, "control_directory", return_value=9), \
             mock.patch.object(MODULE, "current_pointer", return_value=(
                 {"stage": "/run/aegis-installer-config-snapshots/foreign",
                  "candidate_sha256": "a" * 64, "boot_id": "boot"}, b"", None)), \
             mock.patch.object(MODULE.os, "close"), \
             mock.patch.object(MODULE, "call_output", side_effect=output):
            with self.assertRaises(MODULE.Refused):
                MODULE._passive_completed_active(root, "a" * 64, advance=True)
        self.assertEqual(calls, ["auto-verify-current-socks"])

    def test_passive_completed_accepts_matching_active_pointer(self):
        root = Path("/var/lib/aegis-auto/releases/next-release-identity")
        stage = "/run/aegis-installer-config-snapshots/active"
        active = {"schema": "aegis_auto_v2_current_socks_active_v1",
                  "stage": stage, "public_payload_root": str(root),
                  "candidate_sha256": "a" * 64}
        boot = "00000000-0000-0000-0000-000000000001"
        with mock.patch.object(MODULE, "control_directory", return_value=9), \
             mock.patch.object(MODULE, "current_pointer", return_value=(
                 {"stage": stage, "candidate_sha256": "a" * 64,
                  "boot_id": boot}, b"", None)), \
             mock.patch.object(MODULE, "current_boot", return_value=boot), \
             mock.patch.object(MODULE, "call_output",
                               return_value=json.dumps(active).encode()) as called, \
             mock.patch.object(MODULE.os, "close"):
            self.assertEqual(MODULE._passive_completed_active(
                root, "a" * 64, advance=False), "terminal_active")
        self.assertEqual(called.call_count, 1)

    def test_guarded_same_package_keeps_typed_stop_path(self):
        root = Path("/var/lib/aegis-auto/releases/next-release-identity")
        candidate_sha = hashlib.sha256(b"same-binary").hexdigest()
        reached_stop = RuntimeError("typed stop reached")
        with tempfile.TemporaryDirectory() as control, \
             mock.patch.object(MODULE, "CONTROL", Path(control)), \
             mock.patch.object(MODULE, "signed_client_package",
                               return_value=(root / "client.deb", "a" * 64)), \
             mock.patch.object(MODULE, "held_root_file", return_value=99), \
             mock.patch.object(MODULE, "bounded_digest", return_value=(11, candidate_sha)), \
             mock.patch.object(MODULE, "bounded_root_bytes",
                               return_value=b"same-binary"), \
             mock.patch.object(MODULE, "_incoming_upgrade_coordinator"), \
             mock.patch.object(MODULE, "_passive_package_state",
                               return_value="installed"), \
             mock.patch.object(MODULE, "_current_mode_hint",
                               return_value="full-wide-tun"), \
             mock.patch.object(MODULE, "_passive_package_source") as passive_source, \
             mock.patch.object(MODULE, "_passive_completed_active") as passive_done, \
             mock.patch.object(MODULE, "stop_current",
                               side_effect=reached_stop) as stop, \
             mock.patch.object(MODULE.os, "close"), \
             mock.patch.object(MODULE.sys, "platform", "linux"), \
             mock.patch.object(MODULE.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(RuntimeError, "typed stop reached"):
                MODULE.upgrade_package(str(root))
        stop.assert_called_once_with(None)
        passive_source.assert_not_called()
        passive_done.assert_not_called()

    def test_passive_actor_progress_refuses_reused_old_invocation(self):
        unit = GUARDIAN.PASSIVE_SUCCESSOR_ACTORS[0][0]
        old_id = "a" * 32
        old = {"MainPID": "4242", "InvocationID": old_id}
        intent = {"actors": {row[0]: old for row in
                             GUARDIAN.PASSIVE_SUCCESSOR_ACTORS},
                  "actor_start_ticks": {row[0]: 17 for row in
                                        GUARDIAN.PASSIVE_SUCCESSOR_ACTORS}}
        facts = {"Id": unit, "ActiveState": "active", "SubState": "running",
                 "MainPID": "4243", "ControlPID": "0", "NFileDescriptorStore": "0",
                 "ControlGroup": "/system.slice/" + unit, "InvocationID": old_id}
        with mock.patch.object(GUARDIAN, "own_source"), \
             mock.patch.object(GUARDIAN, "_passive_successor_admission",
                               return_value=({"candidate_sha256": "b" * 64}, b"new")), \
             mock.patch.object(GUARDIAN, "regular", return_value=b"new"), \
             mock.patch.object(GUARDIAN, "record", return_value=intent), \
             mock.patch.object(GUARDIAN, "_boot_fixed_client_stopped"), \
             mock.patch.object(GUARDIAN, "_boot_private_owners_absent"), \
             mock.patch.object(GUARDIAN, "_rotation_static_stopped"), \
             mock.patch.object(GUARDIAN, "_rotation_actor_facts", return_value=facts), \
             mock.patch("builtins.open", mock.mock_open(
                 read_data=b"4243 (a) b)) S " + b"1 " * 18 + b"18 0\n")), \
             mock.patch.object(GUARDIAN.os, "pidfd_open", create=True) as opened:
            with self.assertRaises(GUARDIAN.Refused):
                GUARDIAN.passive_successor_progress_readback(9)
        opened.assert_not_called()

    def test_guardian_actor_tick_reads_kernel_bytes_with_parentheses(self):
        raw = b"4243 (a) b)) S " + b"1 " * 18 + b"987654 0\n"
        with mock.patch("builtins.open", mock.mock_open(read_data=raw)):
            self.assertEqual(GUARDIAN._passive_actor_tick(4243), 987654)

    def test_guardian_unix_table_short_reads_find_late_row_and_oversize_is_terminal(self):
        from types import SimpleNamespace
        path = "/run/aegis-auto-topology/authority.sock"
        raw = b"Num RefCount Protocol Flags Type St Inode Path\n" + b"padding\n" * 600
        raw += b"000: 00000002 00000000 00010000 0001 01 987 " + path.encode() + b"\n"
        class ShortRead(io.BytesIO):
            def read(self, maximum=-1):
                return super().read(min(maximum, 4017))
        parent = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_gid=0)
        sock = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_uid=0)
        with mock.patch("builtins.open", return_value=ShortRead(raw)), \
             mock.patch.object(GUARDIAN.Path, "stat", side_effect=[parent, sock]), \
             mock.patch.object(GUARDIAN.Path, "iterdir", return_value=iter([Path("/proc/42/fd/7")])), \
             mock.patch.object(GUARDIAN.os, "readlink", return_value="socket:[987]"):
            GUARDIAN._passive_actor_socket(path, 42)
        with mock.patch("builtins.open", return_value=ShortRead(b"x" * ((1 << 20) + 1))):
            with self.assertRaisesRegex(GUARDIAN.Refused, "actor_unix_table_oversized"):
                GUARDIAN._passive_actor_unix_table()
        with mock.patch.object(GUARDIAN, "passive_successor_progress_readback",
                               side_effect=GUARDIAN.Refused("passive_successor_actor_unix_table_oversized")), \
             mock.patch.object(GUARDIAN.time, "sleep") as pause:
            with self.assertRaisesRegex(GUARDIAN.Refused, "actor_unix_table_oversized"):
                GUARDIAN.passive_successor_progress_wait(9)
            pause.assert_not_called()

    def test_rotation_witness_real_source_dataclasses_leave_no_module_registration(self):
        import dataclasses
        import types
        raw = SOURCE.with_name("aegis_auto_native_witness.py").read_bytes()
        intent = {"next_sources": {"witness_sha256": hashlib.sha256(raw).hexdigest()}}
        name = "aegis_auto_rotation_witness"
        missing = object()
        old = sys.modules.pop(name, missing)
        try:
            with mock.patch.object(GUARDIAN, "regular", return_value=raw):
                for _ in range(2):
                    loaded = GUARDIAN._rotation_verified_witness(intent)
                    self.assertTrue(dataclasses.is_dataclass(loaded.Challenge))
                    self.assertNotIn(name, sys.modules)
                previous = types.ModuleType(name)
                sys.modules[name] = previous
                loaded = GUARDIAN._rotation_verified_witness(intent)
                self.assertTrue(dataclasses.is_dataclass(loaded.DenyWitness))
                self.assertIs(sys.modules[name], previous)
        finally:
            sys.modules.pop(name, None)
            if old is not missing:
                sys.modules[name] = old

    def test_passive_actor_socket_readiness_uses_one_bounded_wait(self):
        clock = [100.0]
        calls = []
        def observed(_fd, *, deadline):
            calls.append(deadline)
            if len(calls) == 1:
                raise GUARDIAN.Refused("passive_successor_actor_socket_changed")
            return {"missing": [], "active": ["aegis-auto-guardian.service"]}
        def pause(duration):
            clock[0] += duration
        with mock.patch.object(GUARDIAN.time, "monotonic",
                               side_effect=lambda: clock[0]), \
             mock.patch.object(GUARDIAN.time, "sleep", side_effect=pause), \
             mock.patch.object(GUARDIAN, "passive_successor_progress_readback",
                               side_effect=observed):
            self.assertEqual(GUARDIAN.passive_successor_progress_wait(9)["missing"], [])
        self.assertEqual(calls, [140.0, 140.0])

    def test_passive_actor_wait_does_not_retry_foreign_identity(self):
        with mock.patch.object(GUARDIAN, "passive_successor_progress_readback",
                               side_effect=GUARDIAN.Refused(
                                   "passive_successor_old_actor_still_live")) as proof:
            with self.assertRaises(GUARDIAN.Refused):
                GUARDIAN.passive_successor_progress_wait(9)
        proof.assert_called_once()

    def test_staged_readback_uses_handoff_before_install_rotation(self):
        old = b"old-install\n"
        with mock.patch.object(GUARDIAN, "own_source") as source, \
             mock.patch.object(GUARDIAN, "_passive_successor_admission",
                               return_value=({"old_install_sha256": hashlib.sha256(old).hexdigest(),
                                              "candidate_sha256": "a" * 64}, b"new-install\n")), \
             mock.patch.object(GUARDIAN, "regular", return_value=old), \
             mock.patch.object(GUARDIAN, "_held_lock"), \
             mock.patch.object(GUARDIAN, "host_anchor", return_value={"boot_id": "boot"}):
            observed = GUARDIAN.passive_successor_staged_readback(9)
        self.assertTrue(observed["no_live_actors"])
        source.assert_not_called()

    def test_partial_retirement_retry_uses_archived_proof_before_stop(self):
        root = Path("/var/lib/aegis-auto/releases/next-release-identity")
        commands = []
        report = {"stopped": {"stage": {"mode": "socks-only"}},
                  "successor": {"intent_sha256": "a" * 64}}
        def output(argv, **_kwargs):
            commands.append(argv)
            return b"{}"
        with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryFile() as held:
            control = Path(temp)
            (control / MODULE.PASSIVE_SUCCESSOR_INTENT).write_text("{}")
            with mock.patch.object(MODULE, "CONTROL", control), \
                 mock.patch.object(MODULE.sys, "platform", "linux"), \
                 mock.patch.object(MODULE.os, "geteuid", return_value=0), \
                 mock.patch.object(MODULE, "signed_client_package",
                                   return_value=(root / "packages/client.deb", "f" * 64)), \
                 mock.patch.object(MODULE, "held_root_file", return_value=held.fileno()), \
                 mock.patch.object(MODULE, "bounded_digest", return_value=(1, "b" * 64)), \
                 mock.patch.object(MODULE, "_incoming_upgrade_coordinator"), \
                 mock.patch.object(MODULE, "_open_original_lock", return_value=9), \
                 mock.patch.object(MODULE, "_passive_control", return_value=9), \
                 mock.patch.object(MODULE, "_passive_record", return_value={}), \
                 mock.patch.object(MODULE, "_ensure_passive_old_stopped_report"), \
                 mock.patch.object(MODULE, "_authenticate_passive_retirement_before_stop"), \
                 mock.patch.object(MODULE, "_successor_report", return_value=report), \
                 mock.patch.object(MODULE, "retire_passive_successor",
                                   side_effect=MODULE.Refused()), \
                 mock.patch.object(MODULE, "call_output", side_effect=output), \
                 mock.patch.object(MODULE, "record_failure"), \
                 mock.patch.object(MODULE.os, "close"):
                with self.assertRaises(MODULE.Refused):
                    MODULE.upgrade_package(str(root))
        self.assertTrue(any("verify-passive-retirement-intent" in argv
                            for argv in commands))
        self.assertFalse(any("begin-stopped-successor" in argv for argv in commands))

    def test_completed_same_package_retry_reads_live_b_without_stop(self):
        root = Path("/var/lib/aegis-auto/releases/next-release-identity")
        sha = hashlib.sha256(b"B").hexdigest()
        with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryFile() as held:
            with mock.patch.object(MODULE, "CONTROL", Path(temp)), \
                 mock.patch.object(MODULE.sys, "platform", "linux"), \
                 mock.patch.object(MODULE.os, "geteuid", return_value=0), \
                 mock.patch.object(MODULE, "signed_client_package",
                                   return_value=(root / "package.deb", "f" * 64)), \
                 mock.patch.object(MODULE, "held_root_file", return_value=held.fileno()), \
                 mock.patch.object(MODULE, "bounded_digest", return_value=(1, sha)), \
                 mock.patch.object(MODULE, "bounded_root_bytes", return_value=b"B"), \
                 mock.patch.object(MODULE, "_incoming_upgrade_coordinator"), \
                 mock.patch.object(MODULE, "_passive_package_state", return_value="installed"), \
                 mock.patch.object(MODULE, "_current_mode_hint",
                                   return_value="socks-only"), \
                 mock.patch.object(MODULE, "_passive_package_source"), \
                 mock.patch.object(MODULE, "_passive_completed_active",
                                   return_value="terminal_active") as active, \
                 mock.patch.object(MODULE, "stop_current") as stop, \
                 mock.patch.object(MODULE.os, "close"):
                self.assertEqual(MODULE.upgrade_package(str(root)), "terminal_active")
        active.assert_called_once_with(root, sha, advance=False)
        stop.assert_not_called()

    def test_missing_package_db_with_mixed_old_source_never_replays_preinst(self):
        root = Path("/var/lib/aegis-auto/releases/next-release-identity")
        status = {"phase": "pending-old", "old_public_payload_root": str(root.parent / "prior"),
                  "old_candidate_sha256": "a" * 64, "old_install_sha256": "b" * 64}
        with mock.patch.object(MODULE, "_passive_package_state", return_value=None), \
             mock.patch.object(MODULE, "_passive_package_source",
                               side_effect=MODULE.Refused()) as source, \
             mock.patch.object(MODULE, "call_output") as effect:
            with self.assertRaises(MODULE.Refused):
                MODULE._passive_resume_package(root, root / "package.deb",
                    root / "bin/aegis-client", "c" * 64, 9, status, {})
        source.assert_called_once_with(status["old_public_payload_root"],
                                       status["old_candidate_sha256"])
        effect.assert_not_called()

    def test_half_configured_b_only_configures_after_staged_proof(self):
        root = Path("/var/lib/aegis-auto/releases/next-release-identity")
        old = b"old-install\n"
        status = {"phase": "package-installed", "old_install_sha256":
                  hashlib.sha256(old).hexdigest(), "preinst_sha256": "a" * 64,
                  "candidate_sha256": "b" * 64}
        order = []
        def staged(*_args):
            order.append("staged")
            return {"old_install_sha256": status["old_install_sha256"],
                    "no_live_actors": True}
        def effect(argv, **_kwargs):
            order.append("configure" if argv[:2] == ["/usr/bin/dpkg", "--configure"]
                         else "other")
            if argv[:2] != ["/usr/bin/dpkg", "--configure"]:
                raise MODULE.Refused()
            return b""
        with mock.patch.object(MODULE, "_passive_package_state",
                               side_effect=["half-configured", "installed"]), \
             mock.patch.object(MODULE, "_passive_package_source"), \
             mock.patch.object(MODULE, "_passive_guardian_report", side_effect=staged), \
             mock.patch.object(MODULE, "call_output", side_effect=effect), \
             mock.patch.object(MODULE, "control_directory", return_value=9), \
             mock.patch.object(MODULE, "current_pointer", return_value=None), \
             mock.patch.object(MODULE, "bounded_root_bytes", return_value=old), \
             mock.patch.object(MODULE.os, "close"):
            with self.assertRaises(MODULE.Refused):
                MODULE._passive_resume_package(root, root / "package.deb",
                    root / "bin/aegis-client", "b" * 64, 9, status, {})
        self.assertEqual(order[:2], ["staged", "configure"])

    def test_passive_readback_child_timeout_reaps_process(self):
        spawned = []
        real_popen = subprocess.Popen

        def record(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            spawned.append(child)
            return child

        began = time.monotonic()
        with mock.patch.object(MODULE.subprocess, "Popen", side_effect=record):
            with self.assertRaises(MODULE.Refused):
                MODULE.call_output([sys.executable, "-c", "import time;time.sleep(2)"],
                                   timeout=0.05)
        self.assertEqual(len(spawned), 1)
        self.assertIsNotNone(spawned[0].poll())
        self.assertLess(time.monotonic() - began, 1.0)

    def test_passive_retirement_refuses_active_capture_before_actor_stop(self):
        guardian = SimpleNamespace(
            own_source=mock.Mock(),
            _rotation_actor_facts=mock.Mock(return_value={
                "ActiveState": "active", "SubState": "running", "MainPID": "42",
                "ControlPID": "0", "NFileDescriptorStore": "0",
                "ControlGroup": "/system.slice/aegis-auto-capture-topology.service"}),
            _rotation_static_stopped=mock.Mock(),
            _rotation_actors_stopped=mock.Mock())
        spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda _module: None))
        with mock.patch.object(MODULE.importlib.util, "spec_from_file_location",
                               return_value=spec), \
             mock.patch.object(MODULE.importlib.util, "module_from_spec",
                               return_value=guardian):
            with self.assertRaises(MODULE.Refused):
                MODULE._passive_non_actor_stopped(before_retirement=True)
        guardian._rotation_static_stopped.assert_not_called()
        guardian._rotation_actors_stopped.assert_not_called()

    def test_partial_passive_retry_refuses_foreign_archived_successor_before_stop(self):
        stopped = b'{}\n'
        successor = b'{"schema":"aegis_auto_v2_stopped_successor_v1","kind":"upgrade","old_boot_id":"boot"}'
        actors = {unit: {"Id": unit} for unit, _, _ in MODULE.PASSIVE_ACTORS}
        intent = {"schema": "aegis_auto_v2_passive_successor_retirement_intent_v1",
                  "boot_id": "boot", "successor_sha256": "f" * 64,
                  "successor_intent_sha256": hashlib.sha256(successor).hexdigest(),
                  "stopped_sha256": hashlib.sha256(stopped[:-1]).hexdigest(),
                  "source_sha256": "c" * 64, "actors": actors,
                  "actor_start_ticks": {unit: 1 for unit in actors}}
        def old_leaf(path, *_args):
            return successor if path.name == "generation-successor-current.json" else stopped
        with mock.patch.object(MODULE, "current_boot", return_value="boot"), \
             mock.patch.object(MODULE, "bounded_root_bytes", side_effect=old_leaf), \
             mock.patch.object(MODULE, "call_output", return_value=b'{}') as archive, \
             mock.patch.object(MODULE, "_passive_successor_source") as source, \
             mock.patch.object(MODULE, "_retired_passive_actor_status") as stop:
            with self.assertRaises(MODULE.Refused):
                MODULE._authenticate_passive_retirement_before_stop(intent, 9)
            archive.assert_called_once()
            source.assert_not_called()
            stop.assert_not_called()

    def test_partial_passive_retry_accepts_exact_archived_chain_without_live_guardian(self):
        stopped_value = {"stage": {"mode": "socks-only"}}
        stopped = (json.dumps(stopped_value, sort_keys=True,
                              separators=(",", ":")) + "\n").encode()
        successor = b'{"kind":"upgrade","old_boot_id":"boot","schema":"aegis_auto_v2_stopped_successor_v1"}'
        successor_sha = hashlib.sha256(successor).hexdigest()
        verified = json.dumps({"schema": "aegis_auto_v2_stopped_successor_verification_v1",
                               "stopped": stopped_value,
                               "successor": {"intent_sha256": successor_sha}},
                              sort_keys=True, separators=(",", ":")).encode()
        actors = {unit: {"Id": unit, "ActiveState": "active",
                         "SubState": "running", "ControlGroup": "/system.slice/" + unit}
                  for unit, _, _ in MODULE.PASSIVE_ACTORS}
        intent = {"schema": "aegis_auto_v2_passive_successor_retirement_intent_v1",
                  "boot_id": "boot",
                  "successor_sha256": hashlib.sha256(verified).hexdigest(),
                  "successor_intent_sha256": successor_sha,
                  "stopped_sha256": hashlib.sha256(stopped[:-1]).hexdigest(),
                  "source_sha256": "c" * 64, "actors": actors,
                  "actor_start_ticks": {unit: 1 for unit in actors}}
        with mock.patch.object(MODULE, "current_boot", return_value="boot"), \
             mock.patch.object(MODULE, "bounded_root_bytes",
                               side_effect=lambda path, *_: successor if path.name ==
                               "generation-successor-current.json" else stopped), \
             mock.patch.object(MODULE, "call_output", return_value=verified) as archive, \
             mock.patch.object(MODULE, "_passive_successor_source", return_value="c" * 64):
            MODULE._authenticate_passive_retirement_before_stop(intent, 9)
            self.assertIn("verify-passive-retirement-intent", archive.call_args.args[0])

    def test_passive_guardian_install_rotation_retries_only_exact_new_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            installed = Path(temporary) / "guardian-install.json"
            old = b'{"old":true}\n'
            new = b'{"new":true}\n'
            installed.write_bytes(old)
            preinst = {"old_install_sha256": hashlib.sha256(old).hexdigest()}
            with mock.patch.object(GUARDIAN, "INSTALL", installed), \
                 mock.patch.object(GUARDIAN, "_passive_successor_admission",
                                   return_value=(preinst, new)), \
                 mock.patch.object(GUARDIAN, "regular", side_effect=lambda path, *_: path.read_bytes()), \
                 mock.patch.object(GUARDIAN, "_rotation_archive") as archive, \
                 mock.patch.object(GUARDIAN, "_held_lock"), \
                 mock.patch.object(GUARDIAN, "own_source"):
                self.assertEqual(GUARDIAN.admit_passive_successor(9),
                                 hashlib.sha256(new).hexdigest())
                self.assertEqual(installed.read_bytes(), new)
                self.assertEqual(GUARDIAN.admit_passive_successor(9),
                                 hashlib.sha256(new).hexdigest())
                archive.assert_called_once()
                installed.write_bytes(b'{"foreign":true}\n')
                with self.assertRaises(GUARDIAN.Refused):
                    GUARDIAN.admit_passive_successor(9)

    def test_interrupted_passive_intent_never_recreates_report_after_actor_stop(self):
        intent = {"stopped_sha256": "a" * 64,
                  "successor_sha256": "b" * 64,
                  "source_sha256": "c" * 64}
        with mock.patch.object(MODULE, "_retired_passive_actor_status",
                               return_value=([], ["aegis-auto-guardian.service"])), \
             mock.patch.object(MODULE, "call_output") as verify, \
             mock.patch.object(MODULE, "atomic_exclusive_bytes") as write:
            with self.assertRaises(MODULE.Refused):
                MODULE._ensure_passive_old_stopped_report(intent, 9)
            verify.assert_not_called()
            write.assert_not_called()

    def test_passive_retired_readback_requires_original_process_cgroup(self):
        unit = "aegis-auto-guardian.service"
        facts = {"Id": unit, "LoadState": "loaded", "ActiveState": "active",
                 "SubState": "running", "MainPID": "411", "ControlPID": "0",
                 "ControlGroup": "/system.slice/" + unit,
                 "InvocationID": "a" * 32, "NeedDaemonReload": "no",
                 "NFileDescriptorStore": "0"}
        intent = {"actors": {unit: facts}, "actor_start_ticks": {unit: 73}}
        def show(_argv, **_kwargs):
            return "".join(f"{key}={value}\n" for key, value in facts.items()).encode()
        with mock.patch.object(MODULE, "PASSIVE_ACTORS", ((unit, "/run/unused", "unused.py"),)), \
             mock.patch.object(MODULE, "no_private_jobs_or_units"), \
             mock.patch.object(MODULE, "call_output", side_effect=show), \
             mock.patch.object(MODULE, "_passive_actor_start_tick", return_value=73), \
             mock.patch.object(MODULE.Path, "read_text", return_value="0::/system.slice/foreign.service\n"):
            with self.assertRaises(MODULE.Refused):
                MODULE._retired_passive_actor_status(intent)

    def test_passive_retired_readback_exhausted_budget_sends_no_pid1_query(self):
        with mock.patch.object(MODULE, "no_private_jobs_or_units",
                               side_effect=lambda deadline: MODULE._remaining(deadline, 5)), \
             mock.patch.object(MODULE, "call_output") as query:
            with self.assertRaises(MODULE.Refused):
                MODULE._retired_passive_actor_status({}, MODULE.time.monotonic() - 1)
            query.assert_not_called()

    def test_upgrade_socks_refuses_before_unpack_without_retired_receipt(self):
        root = Path("/var/lib/aegis-auto/releases/next-release-identity")
        sha = "a" * 64
        successor = {"kind": "upgrade", "intent_sha256": "b" * 64,
                     "old_active_sha256": "c" * 64, "old_stopped_sha256": "d" * 64,
                     "next_public_payload_root": str(root),
                     "next_candidate_binary": str(root / "bin/aegis-client"),
                     "next_candidate_sha256": sha,
                     "next_installer_sha256": hashlib.sha256(b"installer").hexdigest(),
                     "next_bundle_manifest_sha256": hashlib.sha256(b"installer").hexdigest(),
                     "next_sums_sha256": hashlib.sha256(b"installer").hexdigest(),
                     "prior_successor_intent_sha256": None}
        begin = {"schema": "aegis_auto_v2_stopped_successor_verification_v1",
                 "stopped": {"stage": {"mode": "socks-only"}},
                 "successor": successor}
        commands = []
        def output(argv, **_kwargs):
            commands.append(argv)
            if "begin-stopped-successor" in argv or "verify-stopped-successor" in argv:
                return json.dumps(begin).encode()
            raise MODULE.Refused()
        with tempfile.TemporaryFile() as held, \
             mock.patch.object(MODULE.sys, "platform", "linux"), \
             mock.patch.object(MODULE.os, "geteuid", return_value=0), \
             mock.patch.object(MODULE, "signed_client_package",
                               return_value=(root / "packages/client.deb", "e" * 64)), \
             mock.patch.object(MODULE, "held_root_file", return_value=held.fileno()), \
             mock.patch.object(MODULE, "bounded_digest", return_value=(1, sha)), \
             mock.patch.object(MODULE, "bounded_root_bytes", return_value=b"installer"), \
             mock.patch.object(MODULE, "_incoming_upgrade_coordinator"), \
             mock.patch.object(MODULE, "_passive_package_state", return_value=None), \
             mock.patch.object(MODULE, "stop_current", return_value="stopped"), \
             mock.patch.object(MODULE, "_open_original_lock", return_value=9), \
             mock.patch.object(MODULE, "retire_passive_successor", side_effect=MODULE.Refused()), \
             mock.patch.object(MODULE, "call_output", side_effect=output), \
             mock.patch.object(MODULE, "record_failure"), \
             mock.patch.object(MODULE.os, "close"):
            with self.assertRaises(MODULE.Refused):
                MODULE.upgrade_package(str(root))
        self.assertFalse(any(argv[:2] == ["/usr/bin/dpkg", "--force-confold"]
                             for argv in commands))
        self.assertFalse(any("prepare-guard-rotation" in argv for argv in commands))

    def test_retired_guardian_invocation_is_first_arm_only(self):
        guardian = "aegis-auto-guardian.service"
        witness = "aegis-auto-witness-topology.service"
        old = "a" * 32
        fields = {
            "Id": guardian, "LoadState": "loaded", "ActiveState": "inactive",
            "SubState": "dead", "MainPID": "0", "ControlPID": "0",
            "ControlGroup": "", "InvocationID": old,
            "NeedDaemonReload": "no", "NFileDescriptorStore": "0",
        }

        def show(_argv, **_kwargs):
            return "".join(f"{key}={value}\n" for key, value in fields.items()).encode()

        with mock.patch.object(MODULE, "PASSIVE_ACTORS", ((guardian, "/run/unused", "unused.py"),)), \
             mock.patch.object(MODULE, "no_private_jobs_or_units"), \
             mock.patch.object(MODULE, "call_output", side_effect=show):
            with self.assertRaises(MODULE.Refused):
                MODULE.passive_actor_status()
            self.assertEqual(MODULE.passive_actor_status(
                retired_guardian_invocation=old), ([], [guardian]))
            for invalid in ("b" * 32, "A" * 32, "a" * 31, "0" * 32, 42):
                with self.subTest(invalid=invalid), self.assertRaises(MODULE.Refused):
                    MODULE.passive_actor_status(retired_guardian_invocation=invalid)
            for key, value in (("LoadState", "not-found"),
                               ("ActiveState", "active"),
                               ("SubState", "failed"),
                               ("MainPID", "3"),
                               ("ControlPID", "3"),
                               ("ControlGroup", "/system.slice/foreign.service"),
                               ("NFileDescriptorStore", "1")):
                with self.subTest(key=key):
                    original = fields[key]
                    fields[key] = value
                    with self.assertRaises(MODULE.Refused):
                        MODULE.passive_actor_status(retired_guardian_invocation=old)
                    fields[key] = original
            fields["Id"] = witness
            with mock.patch.object(MODULE, "PASSIVE_ACTORS", ((witness, "/run/unused", "unused.py"),)):
                with self.assertRaises(MODULE.Refused):
                    MODULE.passive_actor_status(retired_guardian_invocation=old)

    @unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0,
                         "requires isolated root-owned Linux publication")
    def test_passive_gate_accepts_only_exact_interrupted_atomic_prefix(self):
        body = b"[Unit]\nConditionPathExists=!/\n"
        with tempfile.TemporaryDirectory(dir="/var/lib") as temporary:
            dropins = Path(temporary) / "service.d"
            dropins.mkdir(mode=0o700)
            marker = dropins / (".passive-tmp-" + "a" * 24)
            marker.write_bytes(body[:11])
            os.chmod(marker, 0o600)
            MODULE._passive_gate_dropins(dropins)
            marker.write_bytes(b"foreign")
            with self.assertRaises(MODULE.Refused):
                MODULE._passive_gate_dropins(dropins)
            marker.write_bytes(body)
            foreign = dropins / "50-foreign.conf"
            foreign.write_bytes(b"[Service]\n")
            with self.assertRaises(MODULE.Refused):
                MODULE._passive_gate_dropins(dropins)
            foreign.unlink()
            marker.unlink()
            gate = dropins / "00-v2-boot-gate.conf"
            gate.write_bytes(body)
            os.chmod(gate, 0o644)
            MODULE._passive_gate_dropins(dropins)

    def test_passive_prepared_reference_manifest_matches_and_refuses_drift(self):
        control = Path("/var/lib/aegis-auto/control")
        snapshot = control / MODULE.PASSIVE_INPUT
        options = dict.fromkeys(MODULE.PASSIVE_OPTIONS)
        cert = b"inner-ca"
        digest = hashlib.sha256(cert).hexdigest()
        intent = {"schema": "aegis_auto_v2_fresh_passive_intent_v1",
                  "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
                  "source": {"public_payload_root": "/var/lib/aegis-auto/releases/release-id",
                             "fresh_origin": "packaged", "package_sha256": "a" * 64,
                             "source_tree_sha256": "b" * 64,
                             "candidate_sha256": "c" * 64, "installer_sha256": "d" * 64},
                  "original_bundle": "/var/lib/ordinary-bundle",
                  "bundle_files": {"aegis-client.toml": {"size": 1, "sha256": "e" * 64},
                                   "ca.pem": {"size": 1, "sha256": "f" * 64},
                                   "aegis-client-privileged-dns.toml": None,
                                   "masque-ca.pem": None},
                  "options_sha256": MODULE._passive_optional(options),
                  "external_refs": [{"path": "/var/lib/ordinary-bundle/inner/ca.pem",
                                     "snapshot_relative": "inner/ca.pem",
                                     "size": len(cert), "sha256": digest}],
                  "fresh_origin": "packaged"}
        leaf = "input/references/0000/bytes"
        manifest = {"logical_bundle": str(snapshot), "references": [{"stage_bytes": leaf,
                                      "generation_leaf": "input/references/0000/metadata.json",
                                      "original_path": str(snapshot / "inner/ca.pem"),
                                      "final_path": "/etc/aegis/client/inner/ca.pem",
                                      "expected_uid": 0}]}
        manifest_raw = json.dumps(manifest).encode()
        header = {"leaves": {"input/authority.json": hashlib.sha256(manifest_raw).hexdigest(),
                             leaf: digest}}
        content = {"header.json": json.dumps(header).encode(),
                   "input/authority.json": manifest_raw, leaf: cert}
        def read(_fd, name, _maximum):
            return content[name]
        def intent_bytes(path, _maximum, _modes):
            self.assertEqual(path, control / MODULE.PASSIVE_INTENT)
            return json.dumps(intent).encode()
        with mock.patch.object(MODULE, "CONTROL", control), \
             mock.patch.object(MODULE, "directory", return_value=33), \
             mock.patch.object(MODULE.os, "close"), \
             mock.patch.object(MODULE, "read_private", side_effect=read), \
             mock.patch.object(MODULE, "bounded_root_bytes", side_effect=intent_bytes), \
             mock.patch.object(MODULE, "current_boot", return_value=intent["boot_id"]):
            paths = {"bundle-dir": snapshot,
                     "public-payload-root": Path(intent["source"]["public_payload_root"])}
            args = SimpleNamespace(**options)
            MODULE.passive_prepared_reference_match(Path("/var/lib/stage"), paths, args)
            content[leaf] = b"changed"
            with self.assertRaises(MODULE.Refused):
                MODULE.passive_prepared_reference_match(Path("/var/lib/stage"), paths, args)
            content[leaf] = cert
            manifest["references"][0]["original_path"] = "/var/lib/foreign/ca.pem"
            content["input/authority.json"] = json.dumps(manifest).encode()
            header["leaves"]["input/authority.json"] = hashlib.sha256(
                content["input/authority.json"]).hexdigest()
            content["header.json"] = json.dumps(header).encode()
            with self.assertRaises(MODULE.Refused):
                MODULE.passive_prepared_reference_match(Path("/var/lib/stage"), paths, args)

    def test_passive_reference_roster_binds_absolute_and_relative_credentials(self):
        bundle = Path("/var/lib/operator-bundle")
        config = (b'mode="relay"\n[relay]\nca_cert="ca.pem"\n'
                  b'ech_config_list="extras/ech.bin"\n'
                  b'[relay.inner_tls]\nserver_ca="/var/lib/identity/ca.pem"\n'
                  b'cert="/var/lib/identity/device.pem"\n'
                  b'key="/var/lib/identity/device.key"\n'
                  b'[relay.https_bridge]\ncredential_file="/var/lib/identity/bridge.key"\n')
        contents = {str(bundle / "aegis-client.toml"): config,
                    str(bundle / "ca.pem"): b"ca",
                    str(bundle / "extras/ech.bin"): b"ech",
                    "/var/lib/identity/ca.pem": b"ca",
                    "/var/lib/identity/device.pem": b"cert",
                    "/var/lib/identity/device.key": b"secret-key",
                    "/var/lib/identity/bridge.key": b"bridge-key"}
        options = dict.fromkeys(MODULE.PASSIVE_OPTIONS)
        def read(path, _maximum):
            try:
                return contents[str(path)]
            except KeyError:
                raise FileNotFoundError(str(path)) from None
        with mock.patch.object(MODULE, "_passive_input_bytes",
                               side_effect=read):
            refs = MODULE._passive_external_refs(bundle, options)
        self.assertEqual({item["path"] for item in refs},
                         set(contents) - {str(bundle / "aegis-client.toml")})
        self.assertEqual(next(item for item in refs if item["path"].endswith("ech.bin"))[
                         "snapshot_relative"], "extras/ech.bin")
        self.assertIsNone(next(item for item in refs if item["path"].endswith("device.key"))[
                          "snapshot_relative"])
        self.assertEqual(next(item for item in refs if item["path"].endswith("device.key"))[
                         "sha256"], hashlib.sha256(b"secret-key").hexdigest())
        contents[str(bundle / "aegis-client.toml")] = config.replace(
            b'extras/ech.bin', b'../foreign.bin')
        with mock.patch.object(MODULE, "_passive_input_bytes",
                               side_effect=read):
            with self.assertRaises(MODULE.Refused):
                MODULE._passive_external_refs(bundle, options)

    def test_passive_cli_contract_and_strict_record_shape(self):
        args = MODULE.parser().parse_args([
            "passive-intent", "--install-fd", "9", "--public-payload-root",
            "/var/lib/aegis-auto/releases/release-identity", "--bundle-dir",
            "/var/lib/ordinary-bundle", "--fresh-origin", "packaged"])
        self.assertEqual(args.operation, "passive-intent")
        self.assertEqual(args.fresh_origin, "packaged")
        with self.assertRaises(SystemExit):
            MODULE.parser().parse_args([
                "passive-ready", "--install-fd", "9", "--public-payload-root",
                "/var/lib/aegis-auto/releases/release-identity", "--bundle-dir",
                "/var/lib/ordinary-bundle"])
        record = {"schema": "aegis_auto_v2_fresh_passive_intent_v1",
                  "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
                  "source": {"public_payload_root": "/var/lib/aegis-auto/releases/release-identity",
                             "fresh_origin": "packaged", "package_sha256": "a" * 64,
                             "source_tree_sha256": "b" * 64,
                             "candidate_sha256": "c" * 64,
                             "installer_sha256": "d" * 64},
                  "original_bundle": "/var/lib/ordinary-bundle",
                  "bundle_files": {"aegis-client.toml": {"size": 4, "sha256": "e" * 64},
                                   "ca.pem": {"size": 4, "sha256": "f" * 64},
                                   "aegis-client-privileged-dns.toml": None,
                                   "masque-ca.pem": None},
                  "options_sha256": "1" * 64, "external_refs": [],
                  "fresh_origin": "packaged"}
        MODULE._passive_intent_shape(record)
        for key, value in (("fresh_origin", "foreign"),
                           ("options_sha256", "A" * 64)):
            wrong = json.loads(json.dumps(record))
            wrong[key] = value
            with self.assertRaises(MODULE.Refused):
                MODULE._passive_intent_shape(wrong)

    @unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0,
                         "requires isolated root-owned Linux publication")
    def test_passive_intent_atomic_snapshot_retry_and_tamper_refusal(self):
        with tempfile.TemporaryDirectory(dir="/var/lib") as temporary:
            root = Path(temporary)
            control = root / "control"
            control.mkdir(mode=0o700)
            bundle = root / "bundle"
            bundle.mkdir(mode=0o700)
            (bundle / "aegis-client.toml").write_bytes(
                b'mode="relay"\n[relay]\nca_cert="ca.pem"\n'
                b'ech_config_list="extras/ech.bin"\n')
            (bundle / "ca.pem").write_bytes(b"ca")
            (bundle / "extras").mkdir(mode=0o700)
            (bundle / "extras/ech.bin").write_bytes(b"ech")
            for path in bundle.rglob("*"):
                if path.is_file():
                    os.chmod(path, 0o600)
            options = dict.fromkeys(MODULE.PASSIVE_OPTIONS)
            source = {"public_payload_root": "/var/lib/aegis-auto/releases/release-id",
                      "fresh_origin": "packaged", "package_sha256": "a" * 64,
                      "source_tree_sha256": "b" * 64,
                      "candidate_sha256": "c" * 64,
                      "installer_sha256": "d" * 64}
            with mock.patch.object(MODULE, "CONTROL", control), \
                 mock.patch.object(MODULE, "_passive_control",
                                   side_effect=lambda create=False: os.open(
                                       control, os.O_RDONLY | os.O_DIRECTORY)), \
                 mock.patch.object(MODULE, "fresh_package_lock"), \
                 mock.patch.object(MODULE, "fresh_installed_package"), \
                 mock.patch.object(MODULE, "_passive_installed_origin"), \
                 mock.patch.object(MODULE, "_passive_identity", return_value=source), \
                 mock.patch.object(MODULE, "_passive_prefix"), \
                 mock.patch.object(MODULE, "current_boot",
                                   return_value="01234567-89ab-cdef-0123-456789abcdef"):
                MODULE.passive_intent_admit(source["public_payload_root"], bundle,
                                            9, options, "packaged", create=True)
                intent = control / MODULE.PASSIVE_INTENT
                self.assertEqual(intent.stat().st_mode & 0o777, 0o600)
                self.assertEqual((control / MODULE.PASSIVE_INPUT / "extras/ech.bin").read_bytes(),
                                 b"ech")
                for path in bundle.rglob("*"):
                    if path.is_file():
                        path.unlink()
                MODULE.passive_intent_admit(source["public_payload_root"],
                                            control / MODULE.PASSIVE_INPUT,
                                            9, options, "packaged")
                (control / MODULE.PASSIVE_INPUT / "ca.pem").write_bytes(b"foreign")
                with self.assertRaises(MODULE.Refused):
                    MODULE.passive_intent_admit(source["public_payload_root"],
                                                control / MODULE.PASSIVE_INPUT,
                                                9, options, "packaged")

    def test_proc_unix_short_reads_preserve_late_actor_and_strict_inode(self):
        path = Path("/run/aegis-auto-guard/authority.sock")
        header = b"Num RefCount Protocol Flags Type St Inode Path\n"
        foreign = (b"00000000: 00000002 00000000 00010000 0001 01 7 "
                   b"/run/foreign.sock\n")
        actor = (b"00000000: 00000002 00000000 00010000 0005 01 12345 " +
                 str(path).encode() + b"\n")
        raw = header + foreign * 70 + actor
        self.assertGreater(len(raw), 4096)

        class ShortRaw:
            def __init__(self, data):
                self.data = io.BytesIO(data)

            def read(self, size):
                return self.data.read(min(size, 4096))

        self.assertEqual(MODULE.unix_table_socket_inodes(
            MODULE.read_unix_table(ShortRaw(raw)), path), ["12345"])
        self.assertEqual(MODULE.unix_table_socket_inodes(raw[:4096], path), [])
        self.assertEqual(MODULE.unix_table_socket_inodes(raw + actor, path),
                         ["12345", "12345"])
        with self.assertRaises(MODULE.Refused):
            MODULE.read_unix_table(ShortRaw(b"x" * (1024 * 1024 + 1)))

    def test_fresh_package_pid1_timer_has_distinct_strict_inactive_shape(self):
        timer = "aegis-auto-trace-rollback.timer"
        valid = (f"Id={timer}\nLoadState=loaded\nActiveState=inactive\n"
                 "SubState=dead\n").encode()
        MODULE.fresh_pid1_unit(timer, valid, True)
        for bad in (valid.replace(b"inactive", b"active"),
                    valid.replace(b"LoadState=loaded", b"LoadState=not-found"),
                    valid + b"MainPID=0\n", valid + b"Id=foreign.timer\n"):
            with self.assertRaises(MODULE.Refused):
                MODULE.fresh_pid1_unit(timer, bad, True)
        service = (b"Id=aegis-client.service\nLoadState=loaded\n"
                   b"ActiveState=inactive\nSubState=dead\nMainPID=0\n"
                   b"ControlPID=0\nControlGroup=\nNFileDescriptorStore=0\n")
        MODULE.fresh_pid1_unit("aegis-client.service", service)
        with self.assertRaises(MODULE.Refused):
            MODULE.fresh_pid1_unit("aegis-client.service",
                                   service.replace(b"NFileDescriptorStore=0",
                                                   b"NFileDescriptorStore=1"))

    def test_fresh_package_roster_matches_builder_and_refuses_foreign_dpkg_state(self):
        builder = (SOURCE.parents[2] / "scripts/build-split-deb-packages.sh").read_text()
        def roster(name):
            match = re.search(r"(?ms)^" + name + r"=\(\n(.*?)^\)", builder)
            self.assertIsNotNone(match)
            return tuple(re.findall(r'^\s+"([A-Za-z0-9_./@-]+)"$',
                                    match[1], re.MULTILINE))
        self.assertEqual(tuple("usr/local/lib/aegis/helpers/" + value
                               for value in MODULE.FRESH_CLIENT_HELPERS),
                         roster("CLIENT_PROTECTED_HELPER_PATHS"))
        self.assertEqual(tuple("etc/systemd/system/" + value
                               for value in MODULE.FRESH_CLIENT_UNITS),
                         roster("CLIENT_AUTO_UNIT_PATHS"))
        root_builder = (SOURCE.parents[2] / "scripts/build-package-root.sh").read_text()
        root_match = re.search(r"(?ms)^AUTO_SYSTEMD_UNITS=\(\n(.*?)^\)",
                               root_builder)
        self.assertIsNotNone(root_match)
        self.assertEqual(MODULE.FRESH_CLIENT_UNITS,
                         tuple(re.findall(r'^\s+"([A-Za-z0-9_.@-]+)"$',
                                          root_match[1], re.MULTILINE)))
        self.assertEqual((len(MODULE.FRESH_CLIENT_HELPERS),
                          len(MODULE.FRESH_CLIENT_UNITS)), (34, 16))
        root = "/var/lib/aegis-auto/releases/next-release-identity"
        package = Path(root) / "packages/aegis-client_1.2.3-2_arm64.deb"
        def fields(argv, **_kwargs):
            if argv[:2] == ["/usr/bin/dpkg-deb", "--field"]:
                return {"Version": b"1.2.3-2\n", "Architecture": b"arm64\n"}[argv[-1]]
            if argv[0] == "/usr/bin/dpkg-query":
                return b"deinstall ok config-files\n1.2.3-2\narm64\n"
            raise AssertionError("unexpected command after foreign package status")
        with mock.patch.object(MODULE.sys, "platform", "linux"), \
             mock.patch.object(MODULE.os, "geteuid", return_value=0), \
             mock.patch.object(MODULE, "fresh_package_lock"), \
             mock.patch.object(MODULE, "signed_client_package",
                               return_value=(package, "a" * 64)), \
             mock.patch.object(MODULE, "call_output", side_effect=fields), \
             mock.patch.object(MODULE, "held_root_file") as opened:
            with self.assertRaises(MODULE.Refused):
                MODULE.fresh_installed_package(root, 9)
            opened.assert_not_called()

    def test_successor_lineage_is_exact_and_nullable_only_for_first_generation(self):
        root = Path("/var/lib/aegis-auto/releases/next-release-identity")
        successor = {
            "kind": "upgrade", "intent_sha256": "a" * 64,
            "old_active_sha256": "b" * 64, "old_stopped_sha256": "c" * 64,
            "next_public_payload_root": str(root),
            "next_candidate_binary": str(root / "bin/aegis-client"),
            "next_candidate_sha256": "d" * 64,
            "next_installer_sha256": hashlib.sha256(b"installer").hexdigest(),
                     "next_bundle_manifest_sha256": hashlib.sha256(b"installer").hexdigest(),
                     "next_sums_sha256": hashlib.sha256(b"installer").hexdigest(),
            "prior_successor_intent_sha256": None,
        }
        report = {"schema": "aegis_auto_v2_stopped_successor_verification_v1",
                  "stopped": {"stage": {"mode": "wide-redirect-safe"}},
                  "successor": successor}
        with mock.patch.object(MODULE, "bounded_root_bytes", return_value=b"installer"):
            for prior in (None, "e" * 64):
                successor["prior_successor_intent_sha256"] = prior
                raw = json.dumps(report).encode()
                self.assertEqual(MODULE._successor_report(raw, root, "d" * 64), report)
            for foreign in ("E" * 64, "not-a-sha", 0):
                successor["prior_successor_intent_sha256"] = foreign
                with self.assertRaises(MODULE.Refused):
                    MODULE._successor_report(json.dumps(report).encode(), root, "d" * 64)
            del successor["prior_successor_intent_sha256"]
            with self.assertRaises(MODULE.Refused):
                MODULE._successor_report(json.dumps(report).encode(), root, "d" * 64)

    def test_retained_client_package_is_selected_from_manifest_and_external_must_match(self):
        root = Path("/var/lib/aegis-auto/releases/next-release-identity")
        name = "aegis-client_1.2.3_arm64.deb"
        package = root / "packages" / name
        marker = json.dumps({"version": "1.2.3", "deb_arch": "arm64",
                             "packages": {"aegis-client": {"deb_file": name},
                                          "aegis-server": {"deb_file":
                                                           "aegis-server_1.2.3_arm64.deb"}}}).encode()
        body = b"bounded inert package body"
        package_sha = hashlib.sha256(body).hexdigest()
        sidecar = f"{package_sha}  {name}\n".encode()
        candidate = b"bounded inert candidate body"
        installer = b"bounded inert installer body"
        entries = {"bin/aegis-client": candidate, "install.sh": installer,
                   "packages/split-deb-packages.manifest.json": marker,
                   "packages/" + name: body,
                   "packages/" + name + ".sha256": sidecar,
                   "packaging/systemd/aegis-auto-terminal-a@.service":
                       b"[Service]\nType=oneshot\n"}
        sums = "".join(f"{hashlib.sha256(value).hexdigest()}  {key}\n"
                       for key, value in entries.items()).encode()
        manifest = json.dumps({"schema": "aegis_release_bundle_manifest_v2",
                               "distribution": "private_administrative_operator",
                               "binaries": {"aegis-client": {
                                   "path": "bin/aegis-client",
                                   "sha256": hashlib.sha256(candidate).hexdigest()}},
                               "files": [*entries, "SHA256SUMS"]}).encode()
        reads = {str(root / key): value for key, value in entries.items()}
        reads[str(root / "SHA256SUMS")] = sums
        reads[str(root / "bundle.manifest.json")] = manifest
        with tempfile.TemporaryFile() as retained, tempfile.TemporaryFile() as foreign:
            retained.write(body)
            foreign.write(b"different package")
            retained.flush()
            foreign.flush()
            def held(path, *_args):
                source = retained if Path(path) == package else foreign
                os.lseek(source.fileno(), 0, os.SEEK_SET)
                return os.dup(source.fileno())
            def field(argv, **_kwargs):
                return {"Package": b"aegis-client\n", "Architecture": b"arm64\n",
                        "Version": b"1.2.3\n"}[argv[-1]]
            with mock.patch.object(MODULE, "directory",
                                   side_effect=lambda *_args: os.dup(retained.fileno())), \
                 mock.patch.object(MODULE, "bounded_root_bytes",
                                   side_effect=lambda path, *_args: reads[str(path)]), \
                 mock.patch.object(MODULE, "held_root_file", side_effect=held), \
                 mock.patch.object(MODULE, "call_output", side_effect=field):
                self.assertEqual(MODULE.signed_client_package(root), (package, package_sha))
                with self.assertRaises(MODULE.Refused):
                    MODULE.signed_client_package(root, "/tmp/foreign.deb")

    def test_upgrade_package_refuses_before_stop_without_signed_package(self):
        with mock.patch.object(MODULE.sys, "platform", "linux"), \
             mock.patch.object(MODULE.os, "geteuid", return_value=0), \
             mock.patch.object(MODULE, "signed_client_package",
                               side_effect=MODULE.Refused()), \
             mock.patch.object(MODULE, "stop_current") as stopped, \
             mock.patch.object(MODULE, "record_failure"):
            with self.assertRaises(MODULE.Refused):
                MODULE.upgrade_package("/var/lib/aegis-auto/releases/next-release-identity")
            stopped.assert_not_called()

    def test_upgrade_package_never_unpacks_before_retired_proof(self):
        root = Path("/var/lib/aegis-auto/releases/next-release-identity")
        candidate = root / "bin/aegis-client"
        sha = "a" * 64
        successor = {"kind": "upgrade", "intent_sha256": "b" * 64,
                     "old_active_sha256": "c" * 64,
                     "old_stopped_sha256": "d" * 64,
                     "next_public_payload_root": str(root),
                     "next_candidate_binary": str(candidate),
                     "next_candidate_sha256": sha,
                     "next_installer_sha256": hashlib.sha256(b"installer").hexdigest(),
                     "next_bundle_manifest_sha256": hashlib.sha256(b"installer").hexdigest(),
                     "next_sums_sha256": hashlib.sha256(b"installer").hexdigest(),
                     "prior_successor_intent_sha256": None}
        stopped_report = {"stage": {"mode": "wide-redirect-safe"},
                          "terminal": {"boot_id": "boot"}}
        begin = {"schema": "aegis_auto_v2_stopped_successor_verification_v1",
                 "stopped": stopped_report, "successor": successor}
        prepared = {"schema": "aegis_auto_guard_rotation_intent_v1",
                    "successor": successor}
        commands = []
        def output(argv, **_kwargs):
            commands.append(argv)
            if "begin-stopped-successor" in argv or "verify-stopped-successor" in argv:
                return json.dumps(begin).encode()
            if "prepare-guard-rotation" in argv:
                return json.dumps(prepared).encode()
            if "retire-rotation-actors" in argv:
                return b'{"schema":"aegis_auto_guard_rotation_retired_v1"}'
            if "verify-retired-successor" in argv:
                raise MODULE.Refused()
            return b""
        original_close = os.close
        with tempfile.TemporaryFile() as held, \
             mock.patch.object(MODULE.sys, "platform", "linux"), \
             mock.patch.object(MODULE.os, "geteuid", return_value=0), \
             mock.patch.object(MODULE, "signed_client_package",
                               return_value=(root / "packages/client.deb", "e" * 64)), \
             mock.patch.object(MODULE, "held_root_file", return_value=held.fileno()), \
             mock.patch.object(MODULE, "bounded_digest", return_value=(1, sha)), \
             mock.patch.object(MODULE, "bounded_root_bytes", return_value=b"installer"), \
             mock.patch.object(MODULE, "_incoming_upgrade_coordinator"), \
             mock.patch.object(MODULE, "_passive_package_state", return_value=None), \
             mock.patch.object(MODULE, "stop_current", return_value="stopped"), \
             mock.patch.object(MODULE, "_open_original_lock", side_effect=[9, 10]), \
             mock.patch.object(MODULE, "call_output", side_effect=output), \
             mock.patch.object(MODULE, "record_failure"), \
             mock.patch.object(MODULE.os, "close", side_effect=lambda fd: None if fd in (9, 10, held.fileno()) else original_close(fd)):
            with self.assertRaises(MODULE.Refused):
                MODULE.upgrade_package(str(root))
        self.assertTrue(any("verify-retired-successor" in argv for argv in commands))
        self.assertFalse(any(argv[:2] == ["/usr/bin/dpkg", "--install"] for argv in commands))

    def test_events_directory_accepts_only_fixed_external_path_or_dev_null(self):
        MODULE.ensure_runtime_events_directory(Path("/dev/null"), "root")
        with self.assertRaises(MODULE.Refused):
            MODULE.ensure_runtime_events_directory(
                Path("/var/lib/aegis-client/runtime-events.jsonl"), "root")
        with tempfile.TemporaryDirectory() as temporary:
            Path(temporary, "aegis-client").symlink_to("foreign")
            with mock.patch.object(MODULE, "directory", side_effect=lambda _path: os.open(
                    temporary, os.O_RDONLY | os.O_DIRECTORY)):
                with self.assertRaises(OSError):
                    MODULE.ensure_runtime_events_directory(
                        Path("/var/log/aegis-client/runtime/runtime-events.jsonl"), "root")

    @unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0,
                         "requires isolated Linux root")
    def test_events_tmpfiles_parent_and_foreign_runtime_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "aegis-client"
            parent.mkdir(mode=0o755)
            parent.chmod(0o755)
            fixed = Path("/var/log/aegis-client/runtime/runtime-events.jsonl")
            with mock.patch.object(MODULE, "directory", side_effect=lambda _path: os.open(
                    temporary, os.O_RDONLY | os.O_DIRECTORY)):
                MODULE.ensure_runtime_events_directory(fixed, "root")
                self.assertEqual((parent / "runtime").stat().st_mode & 0o777, 0o700)
                (parent / "runtime").rmdir()
                (parent / "runtime").symlink_to("foreign")
                with self.assertRaises(OSError):
                    MODULE.ensure_runtime_events_directory(fixed, "root")

    def test_private_failure_breadcrumb_is_fixed_and_does_not_expose_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            held = lambda: os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            progress = {"phase": "guardian_mode", "worker": None,
                        "worker_started": MODULE.time.monotonic()}
            with mock.patch.object(MODULE, "control_directory", side_effect=held):
                MODULE.record_failure(progress, MODULE.Refused("private-key-value"))
            files = list(Path(temporary).glob("failure-*.json"))
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)
            raw = files[0].read_bytes()
            self.assertNotIn(b"private-key-value", raw)
            self.assertEqual(set(json.loads(raw)), {"schema", "phase", "reason",
                                                     "worker_exit", "remaining_ms"})
            self.assertEqual(json.loads(raw)["reason"], "refused")

    def test_dedicated_account_uses_fixed_creation_and_rechecks_identity(self):
        MODULE.local_account_nss(b"passwd: files\ngroup: files\ninitgroups: files\n")
        MODULE.local_account_nss(b"passwd: files systemd\ngroup: files systemd\n"
                              b"initgroups: files systemd\n")
        for bad in (b"passwd: systemd files\ngroup: files\n",
                    b"passwd: files sss\ngroup: files\n",
                    b"passwd: files [SUCCESS=return] systemd\ngroup: files\n",
                    b"passwd: files systemd systemd\ngroup: files\n",
                    b"passwd: files\npasswd: files systemd\ngroup: files\n",
                    b"passwd: files\npasswd : sss\ngroup: files\n",
                    b"passwd: files\ngroup: files\ngroup : systemd\n",
                    b"passwd: files\ngroup: files\ninitgroups : files\n",
                    b"passwd: files\ngroup: files\ninitgroups: files ldap\n",
                    b"passwd: files\\\n systemd\ngroup: files\n",
                    b"passwd: files#comment\ngroup: files\n",
                    b"passwd: files systemd#comment\ngroup: files\n",
                    b"passwd: files\ngroup: files\x00\n",
                    b"passwd: files\ngroup: files\x1b\n",
                    b"passwd: files\ngroup: files\ninitgroups: files syst\xc3\xa9md\n"):
            with self.subTest(bad=bad), self.assertRaises((MODULE.Refused, UnicodeError)):
                MODULE.local_account_nss(bad)
        local = {
            "/etc/passwd": (b"root:x:0:0:r\xc3\xb6ot:/root:/bin/sh\n"
                            b"aegis-svc:x:997:998::/var/lib/aegis-client:/usr/sbin/nologin\n"),
            "/etc/group": b"root:x:0:\naegis-svc:x:998:\n",
        }
        record = {"status": "present", "name": "aegis-svc", "uid": 997, "gid": 998,
                  "home": "/var/lib/aegis-client", "shell": "/usr/sbin/nologin",
                  "group_name": "aegis-svc", "group_gid": 998, "members": [],
                  "reverse_user": "aegis-svc", "reverse_group": "aegis-svc", "groups": [998]}
        def local_bytes(path, _maximum, _modes=None):
            return local[str(path)]
        with mock.patch.object(MODULE, "bounded_root_bytes", side_effect=local_bytes):
            MODULE.local_runtime_account(record, Path("/var/lib/aegis-client"))
            for change in ({"uid": 996}, {"gid": 997}, {"group_gid": 997},
                           {"reverse_user": "foreign"}, {"reverse_group": "foreign"},
                           {"groups": [998, 27]}, {"members": ["foreign"]}):
                with self.subTest(change=change), self.assertRaises(MODULE.Refused):
                    MODULE.local_runtime_account({**record, **change},
                                                 Path("/var/lib/aegis-client"))
            local["/etc/passwd"] += b"foreign:x:996:998::/none:/bin/false\n"
            with self.assertRaises(MODULE.Refused):
                MODULE.local_runtime_account(record, Path("/var/lib/aegis-client"))
            local["/etc/passwd"] = local["/etc/passwd"].split(b"foreign:")[0]
            local["/etc/passwd"] += b"foreign:x:0997:27::/none:/bin/false\n"
            with self.assertRaises(MODULE.Refused):
                MODULE.local_runtime_account(record, Path("/var/lib/aegis-client"))
            local["/etc/passwd"] = local["/etc/passwd"].split(b"foreign:")[0]
            local["/etc/passwd"] += b"foreign:x:996:0998::/none:/bin/false\n"
            with self.assertRaises(MODULE.Refused):
                MODULE.local_runtime_account(record, Path("/var/lib/aegis-client"))
            local["/etc/passwd"] = local["/etc/passwd"].split(b"foreign:")[0]
            local["/etc/group"] += b"foreign:x:0998:\n"
            with self.assertRaises(MODULE.Refused):
                MODULE.local_runtime_account(record, Path("/var/lib/aegis-client"))
            local["/etc/group"] = b"root:x:0:\naegis-svc:x:998:\n"
            local["/etc/group"] += b"foreign:x:27:aegis-svc\n"
            with self.assertRaises(MODULE.Refused):
                MODULE.local_runtime_account(record, Path("/var/lib/aegis-client"))
            local["/etc/group"] = b"root:x:0:\naegis-svc:x:998:\n"
        with mock.patch.object(MODULE, "runtime_account_preflight", return_value=False), \
             mock.patch.object(MODULE, "runtime_nss_record", return_value=record), \
             mock.patch.object(MODULE, "bounded_root_bytes", side_effect=lambda path, *_:
                               b"passwd: files systemd\ngroup: files systemd\n"
                               if str(path) == "/etc/nsswitch.conf" else local[str(path)]), \
             mock.patch.object(MODULE, "call_output", return_value=b"") as create:
            MODULE.ensure_runtime_account(Path("/var/lib/aegis-client"))
            create.assert_called_once_with(
                ["/usr/sbin/useradd", "--system", "--user-group", "--no-create-home", "--home-dir",
                 "/var/lib/aegis-client", "--shell", "/usr/sbin/nologin", "aegis-svc"],
                maximum=1024, timeout=15)

    def test_runtime_nss_child_is_bounded_and_shape_checked(self):
        raw = b'{"status":"absent"}'
        with mock.patch.object(MODULE, "bounded_root_bytes", return_value=
                               b"passwd: files systemd\ngroup: files systemd\n"), \
             mock.patch.object(MODULE, "call_output", return_value=raw) as child:
            self.assertEqual(MODULE.runtime_nss_record(), {"status": "absent"})
            args, kwargs = child.call_args
            self.assertEqual(args[0][:4], ["/usr/bin/python3", "-I", "-B", "-c"])
            self.assertEqual(kwargs, {"maximum": 2048, "timeout": 3,
                                      "env": {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                                              "LANG": "C", "LC_ALL": "C"}})
        for raw in (b'{"status":"present"}', b'{"status":"absent","uid":7}',
                    b'{"status":"absent","status":"present"}', b'[]'):
            with self.subTest(raw=raw), \
                 mock.patch.object(MODULE, "bounded_root_bytes", return_value=
                                   b"passwd: files systemd\ngroup: files systemd\n"), \
                 mock.patch.object(MODULE, "call_output", return_value=raw), \
                 self.assertRaises(MODULE.Refused):
                MODULE.runtime_nss_record()
        with mock.patch.object(MODULE, "bounded_root_bytes", side_effect=[
                b"passwd: files systemd\ngroup: files systemd\n",
                b"passwd: files\ngroup: files\n"]), \
             mock.patch.object(MODULE, "call_output", return_value=b'{"status":"absent"}'), \
             self.assertRaises(MODULE.Refused):
            MODULE.runtime_nss_record()

    def test_dedicated_process_authority_refuses_extra_groups_and_capabilities(self):
        status = (b"Groups:\t998\nNoNewPrivs:\t1\nCapInh:\t0000000000000000\n"
                  b"CapPrm:\t0000000000000000\nCapEff:\t0000000000000000\n"
                  b"CapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\n")
        MODULE.dedicated_process_authority(status, 998, "dedicated_none")
        bind = status.replace(b"0000000000000000", b"0000000000000400")
        MODULE.dedicated_process_authority(bind, 998, "dedicated_bind")
        for changed, policy in (
                (status.replace(b"Groups:\t998", b"Groups:\t998 27"), "dedicated_none"),
                (status.replace(b"NoNewPrivs:\t1", b"NoNewPrivs:\t0"), "dedicated_none"),
                (status.replace(b"CapEff:\t0000000000000000",
                                b"CapEff:\t0000000000000400"), "dedicated_none"),
                (status.replace(b"CapBnd:\t0000000000000000",
                                b"CapBnd:\t0000000000000001"), "dedicated_bind")):
            with self.subTest(policy=policy, changed=changed), \
                 self.assertRaises(MODULE.Refused):
                MODULE.dedicated_process_authority(changed, 998, policy)
        with self.assertRaises(MODULE.Refused):
            MODULE.dedicated_process_authority(
                status.replace(b"CapAmb:\t0000000000000000", b"CapAmb:\t0"),
                998, "dedicated_none")

    def test_missing_common_guardian_blocks_before_prepare(self):
        argv = ["install", "--config-root", "/etc/aegis", "--state-dir", "/var/lib/aegis",
                "--metadata-dir", "/var/lib/aegis-admin", "--staging-parent",
                "/run/aegis-installer-config-snapshots", "--public-payload-root", "/opt/public",
                "--candidate-binary", "/opt/candidate/aegis-client", "--installed-binary",
                "/usr/local/bin/aegis-client", "--runtime-events", "/var/log/aegis/events",
                "--existing-choice", "none", "--bundle-dir", "/opt/private-bundle"]
        args = MODULE.parser().parse_args(argv)
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(MODULE.sys, "platform", "linux"), \
                 mock.patch.object(MODULE.os, "geteuid", return_value=0), \
                 mock.patch.object(MODULE, "control_directory",
                                   side_effect=lambda: os.open(temporary, os.O_RDONLY)), \
                 mock.patch.object(MODULE, "current_pointer", return_value=None), \
                 mock.patch.object(MODULE, "pid1_fixed_state", return_value="root"), \
                 mock.patch.object(MODULE, "guardian_ready", side_effect=MODULE.Refused), \
                 mock.patch.object(MODULE, "call_line") as prepare:
                with self.assertRaises(MODULE.Refused):
                    MODULE.run(args)
                prepare.assert_not_called()

    @mock.patch.object(MODULE, "fresh_package_lock", return_value=None)
    @mock.patch.object(MODULE, "_open_original_lock", side_effect=lambda *_: os.open(os.devnull, os.O_RDONLY))
    def test_wide_guard_absence_blocks_before_candidate_publication(self, _lock, _held):
        argv = ["install", "--config-root", "/etc/aegis", "--state-dir", "/var/lib/aegis",
                "--metadata-dir", "/var/lib/aegis-admin", "--staging-parent",
                "/run/aegis-installer-config-snapshots", "--public-payload-root", "/opt/public",
                "--candidate-binary", "/opt/candidate/aegis-client", "--installed-binary",
                "/usr/local/bin/aegis-client", "--runtime-events", "/var/log/aegis/events",
                "--existing-choice", "none", "--bundle-dir", "/opt/private-bundle"]
        args = MODULE.parser().parse_args(argv)
        worker = mock.Mock()
        worker.poll.return_value = None
        worker.stdin = io.BytesIO()
        worker.stdout = io.BytesIO()
        stage = b"/run/aegis-installer-config-snapshots/stage"
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate"
            candidate.write_bytes(b"candidate executable bytes")
            candidate.chmod(0o555)
            args.candidate_binary = str(candidate)
            with mock.patch.object(MODULE.sys, "platform", "linux"), \
                 mock.patch.object(MODULE.os, "geteuid", return_value=0), \
                 mock.patch.object(MODULE, "control_directory",
                                   side_effect=lambda: os.open(temporary, os.O_RDONLY)), \
                 mock.patch.object(MODULE, "current_pointer", return_value=None), \
                 mock.patch.object(MODULE, "pid1_fixed_state", return_value="root"), \
                 mock.patch.object(MODULE, "guardian_ready", side_effect=["passive", MODULE.Refused]), \
                 mock.patch.object(MODULE, "call_line", side_effect=[MODULE.PROTOCOL.encode(), stage]), \
                 mock.patch.object(MODULE, "admitted_prepare_handoff", return_value=(b"i", b"c")), \
                 mock.patch.object(MODULE, "verify_handoff_candidate"), \
                 mock.patch.object(MODULE, "archive_prepare_handoff"), \
                 mock.patch.object(MODULE.subprocess, "Popen", return_value=worker), \
                 mock.patch.object(MODULE, "fixed_lines", return_value=b'{"status":"ready"}'), \
                 mock.patch.object(MODULE, "worker_phase", side_effect=["wide-redirect-safe", "dedicated-bind"]), \
                 mock.patch.object(MODULE, "record_stage") as pointer, \
                 mock.patch.object(MODULE, "install_candidate") as publication:
                with self.assertRaises(MODULE.Refused):
                    MODULE.run(args)
                pointer.assert_called_once()
                publication.assert_not_called()

    @mock.patch.object(MODULE, "fresh_package_lock", return_value=None)
    @mock.patch.object(MODULE, "_open_original_lock", side_effect=lambda *_: os.open(os.devnull, os.O_RDONLY))
    def test_malformed_prepare_handoff_blocks_before_pointer_or_worker(self, _lock, _held):
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate"
            candidate.write_bytes(b"candidate")
            args = MODULE.parser().parse_args([
                "install", "--config-root", "/etc/aegis", "--state-dir", "/var/lib/aegis",
                "--metadata-dir", "/var/lib/aegis-admin", "--staging-parent",
                "/run/aegis-installer-config-snapshots", "--public-payload-root", "/opt/public",
                "--candidate-binary", str(candidate), "--installed-binary",
                "/usr/local/bin/aegis-client", "--runtime-events", "/dev/null",
                "--existing-choice", "none", "--bundle-dir", "/opt/private-bundle",
            ])
            with mock.patch.object(MODULE.sys, "platform", "linux"), \
                 mock.patch.object(MODULE.os, "geteuid", return_value=0), \
                 mock.patch.object(MODULE, "control_directory",
                                   side_effect=lambda: os.open(temporary, os.O_RDONLY)), \
                 mock.patch.object(MODULE, "current_pointer", return_value=None), \
                 mock.patch.object(MODULE, "pid1_fixed_state", return_value="root"), \
                 mock.patch.object(MODULE, "guardian_ready"), \
                 mock.patch.object(MODULE, "call_line", side_effect=[MODULE.PROTOCOL.encode(),
                     b"/run/aegis-installer-config-snapshots/stage"]), \
                 mock.patch.object(MODULE, "admitted_prepare_handoff", side_effect=MODULE.Refused), \
                 mock.patch.object(MODULE, "record_stage") as pointer, \
                 mock.patch.object(MODULE.subprocess, "Popen") as worker:
                with self.assertRaises(MODULE.Refused):
                    MODULE.run(args)
                pointer.assert_not_called()
                worker.assert_not_called()

    @mock.patch.object(MODULE, "fresh_package_lock", return_value=None)
    @mock.patch.object(MODULE, "_open_original_lock", side_effect=lambda *_: os.open(os.devnull, os.O_RDONLY))
    def test_phase_failures_retain_pointer_without_success(self, _lock, _held):
        for failing in ("bind-runtime-service", "commit-config", "finalize"):
            with self.subTest(failing=failing), tempfile.TemporaryDirectory() as temporary:
                candidate = Path(temporary) / "candidate"
                candidate.write_bytes(b"candidate executable bytes")
                candidate.chmod(0o555)
                argv = ["install", "--config-root", "/etc/aegis", "--state-dir", "/var/lib/aegis",
                        "--metadata-dir", "/var/lib/aegis-admin", "--staging-parent",
                        "/run/aegis-installer-config-snapshots", "--public-payload-root", "/opt/public",
                        "--candidate-binary", str(candidate), "--installed-binary",
                        "/usr/local/bin/aegis-client", "--runtime-events", "/var/log/aegis/events",
                        "--existing-choice", "none", "--bundle-dir", "/opt/private-bundle"]
                args = MODULE.parser().parse_args(argv)
                worker = mock.Mock()
                worker.poll.return_value = None
                worker.stdin = io.BytesIO()
                worker.stdout = io.BytesIO()
                sent = []
                def phase(_worker, words, _started, *, phase=None):
                    sent.append(words[0])
                    if words[0] == failing:
                        raise MODULE.Refused()
                    if words[:2] == ["inspect", "--field"]:
                        return "socks-only" if words[-1] == "product-mode" else "root"
                    return None
                pointer = Path(temporary) / "pointer"
                def record(*_unused):
                    pointer.write_bytes(b"retained pending stage")
                with ExitStack() as stack:
                    for target, attribute, kwargs in (
                        (MODULE.sys, "platform", {"new": "linux"}),
                        (MODULE.os, "geteuid", {"return_value": 0}),
                        (MODULE, "control_directory", {"side_effect": lambda: os.open(
                            temporary, os.O_RDONLY)}),
                        (MODULE, "current_pointer", {"return_value": None}),
                        (MODULE, "pid1_fixed_state", {"return_value": "root"}),
                        (MODULE, "guardian_ready", {"return_value": "passive"}),
                        (MODULE, "call_line", {"side_effect": [MODULE.PROTOCOL.encode(),
                            b"/run/aegis-installer-config-snapshots/stage"]}),
                        (MODULE, "admitted_prepare_handoff", {"return_value": (b"i", b"c")}),
                        (MODULE, "verify_handoff_candidate", {}),
                        (MODULE, "archive_prepare_handoff", {}),
                        (MODULE, "ensure_runtime_events_directory", {}),
                        (MODULE.subprocess, "Popen", {"return_value": worker}),
                        (MODULE, "fixed_lines", {"return_value": b'{"status":"ready"}'}),
                        (MODULE, "worker_phase", {"side_effect": phase}),
                        (MODULE, "record_stage", {"side_effect": record}),
                    ):
                        stack.enter_context(mock.patch.object(target, attribute, **kwargs))
                    publication = stack.enter_context(mock.patch.object(
                        MODULE, "install_candidate"))
                    active = stack.enter_context(mock.patch.object(
                        MODULE, "active_after_terminal"))
                    with self.assertRaises(MODULE.Refused):
                        MODULE.run(args)
                    self.assertEqual(pointer.read_bytes(), b"retained pending stage")
                    active.assert_not_called()
                    self.assertEqual(sent[-1], failing)
                    if failing == "bind-runtime-service":
                        publication.assert_not_called()
                    self.assertGreaterEqual(worker.wait.call_args.kwargs["timeout"], 35.0)

    @mock.patch.object(MODULE, "fresh_package_lock", return_value=None)
    @mock.patch.object(MODULE, "_open_original_lock", side_effect=lambda *_: os.open(os.devnull, os.O_RDONLY))
    def test_generation_seal_refusal_keeps_recovery_pointer_after_finalized_worker(self, _lock, _held):
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate"
            candidate.write_bytes(b"candidate executable bytes")
            candidate.chmod(0o555)
            args = MODULE.parser().parse_args([
                "install", "--config-root", "/etc/aegis", "--state-dir", "/var/lib/aegis",
                "--metadata-dir", "/var/lib/aegis-admin", "--staging-parent",
                "/run/aegis-installer-config-snapshots", "--public-payload-root", "/opt/public",
                "--candidate-binary", str(candidate), "--installed-binary",
                "/usr/local/bin/aegis-client", "--runtime-events", "/dev/null",
                "--existing-choice", "none", "--bundle-dir", "/opt/private-bundle",
            ])
            worker = mock.Mock()
            worker.poll.return_value = None
            worker.wait.return_value = 0
            worker.stdin = io.BytesIO()
            worker.stdout = io.BytesIO()
            pointer = Path(temporary) / "pointer"
            real_open = os.open
            def held_open(path, flags, *positional, **keywords):
                if path == Path("/usr/local/bin/aegis-client"):
                    path = candidate
                return real_open(path, flags, *positional, **keywords)
            def phase(_worker, words, _started, *, phase=None):
                if words[:2] == ["inspect", "--field"]:
                    return "socks-only" if words[-1] == "product-mode" else "root"
                return None
            with ExitStack() as stack:
                for target, attribute, kwargs in (
                    (MODULE.sys, "platform", {"new": "linux"}),
                    (MODULE.os, "geteuid", {"return_value": 0}),
                    (MODULE.os, "open", {"side_effect": held_open}),
                    (MODULE, "control_directory", {"side_effect": lambda: real_open(
                        temporary, os.O_RDONLY)}),
                    (MODULE, "current_pointer", {"return_value": None}),
                    (MODULE, "pid1_fixed_state", {"return_value": "root"}),
                    (MODULE, "guardian_ready", {"return_value": "passive"}),
                    (MODULE, "call_line", {"side_effect": [MODULE.PROTOCOL.encode(),
                        b"/run/aegis-installer-config-snapshots/stage"]}),
                    (MODULE, "admitted_prepare_handoff", {"return_value": (b"i", b"c")}),
                    (MODULE, "verify_handoff_candidate", {}),
                    (MODULE, "archive_prepare_handoff", {}),
                    (MODULE, "record_stage", {"side_effect": lambda *_: pointer.write_bytes(
                        b"retained")}),
                    (MODULE, "worker_phase", {"side_effect": phase}),
                    (MODULE, "ensure_runtime_events_directory", {}),
                    (MODULE, "install_candidate", {}),
                    (MODULE, "active_after_terminal", {}),
                    (MODULE, "fixed_lines", {"return_value": b'{"status":"ready"}'}),
                    (MODULE.subprocess, "Popen", {"return_value": worker}),
                ):
                    stack.enter_context(mock.patch.object(target, attribute, **kwargs))
                seal = stack.enter_context(mock.patch.object(
                    MODULE, "call_output", side_effect=MODULE.Refused))
                with self.assertRaises(MODULE.Refused):
                    MODULE.run(args)
                self.assertEqual(pointer.read_bytes(), b"retained")
                self.assertEqual(seal.call_args.args[0][1:], [
                    "auto-seal-generation", "/run/aegis-installer-config-snapshots/stage"])
                self.assertIs(seal.call_args.kwargs.get("diagnostic_stderr"), True)

    @mock.patch.object(MODULE, "fresh_package_lock", return_value=None)
    @mock.patch.object(MODULE, "_open_original_lock", side_effect=lambda *_: os.open(os.devnull, os.O_RDONLY))
    def test_dedicated_nss_refusal_retains_pointer_before_binary_replacement(self, _lock, _held):
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate"
            candidate.write_bytes(b"candidate executable bytes")
            candidate.chmod(0o555)
            args = MODULE.parser().parse_args([
                "install", "--config-root", "/etc/aegis", "--state-dir",
                "/var/lib/aegis-client", "--metadata-dir", "/var/lib/aegis-admin",
                "--staging-parent", "/run/aegis-installer-config-snapshots",
                "--public-payload-root", "/opt/public", "--candidate-binary",
                str(candidate), "--installed-binary", "/usr/local/bin/aegis-client",
                "--runtime-events", "/var/lib/aegis-client/runtime-events.jsonl",
                "--existing-choice", "none", "--bundle-dir", "/opt/private-bundle",
            ])
            worker = mock.Mock()
            worker.poll.return_value = None
            worker.stdin = io.BytesIO()
            worker.stdout = io.BytesIO()
            def phase(_worker, words, _started, *, phase=None):
                if words[:2] == ["inspect", "--field"]:
                    return "socks-only" if words[-1] == "product-mode" else "dedicated-bind"
                return None
            with mock.patch.object(MODULE.sys, "platform", "linux"), \
                 mock.patch.object(MODULE.os, "geteuid", return_value=0), \
                 mock.patch.object(MODULE, "control_directory",
                                   side_effect=lambda: os.open(temporary, os.O_RDONLY)), \
                 mock.patch.object(MODULE, "current_pointer", return_value=None), \
                 mock.patch.object(MODULE, "pid1_fixed_state", return_value="root"), \
                 mock.patch.object(MODULE, "guardian_ready"), \
                 mock.patch.object(MODULE, "call_line",
                                   side_effect=[MODULE.PROTOCOL.encode(),
                                                b"/run/aegis-installer-config-snapshots/stage"]), \
                 mock.patch.object(MODULE, "admitted_prepare_handoff", return_value=(b"i", b"c")), \
                 mock.patch.object(MODULE, "verify_handoff_candidate"), \
                 mock.patch.object(MODULE, "archive_prepare_handoff"), \
                 mock.patch.object(MODULE.subprocess, "Popen", return_value=worker), \
                 mock.patch.object(MODULE, "fixed_lines", return_value=b'{"status":"ready"}'), \
                 mock.patch.object(MODULE, "worker_phase", side_effect=phase), \
                 mock.patch.object(MODULE, "runtime_account_preflight",
                                   side_effect=MODULE.Refused), \
                 mock.patch.object(MODULE, "record_stage") as pointer, \
                 mock.patch.object(MODULE, "install_candidate") as publication:
                with self.assertRaises(MODULE.Refused):
                    MODULE.run(args)
                pointer.assert_called_once()
                publication.assert_not_called()

    @mock.patch.object(MODULE, "recover_prepare_handoff")
    def test_recover_current_uses_one_real_rollback_worker_before_locked_restore(self, _prepare_replay):
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate"
            candidate.write_bytes(b"candidate")
            pointer = {"boot_id": "01234567-89ab-cdef-0123-456789abcdef",
                       "stage": "/run/aegis-installer-config-snapshots/stage",
                       "candidate_sha256": "a" * 64}
            worker = mock.Mock()
            worker.poll.return_value = 0
            worker.wait.return_value = 0
            worker.stdin = io.BytesIO()
            worker.stdout = io.BytesIO()
            admitted_file = SimpleNamespace(st_mode=MODULE.stat.S_IFREG | 0o555,
                                            st_uid=0, st_gid=0, st_nlink=1)
            with mock.patch.object(MODULE.sys, "platform", "linux"), \
                 mock.patch.object(MODULE.os, "geteuid", return_value=0), \
                 mock.patch.object(MODULE, "control_directory",
                                   side_effect=lambda: os.open(temporary, os.O_RDONLY)), \
                 mock.patch.object(MODULE, "current_pointer", return_value=(pointer, b"", None)), \
                 mock.patch.object(MODULE, "current_boot", return_value=pointer["boot_id"]), \
                 mock.patch.object(MODULE.os, "fstat", return_value=admitted_file), \
                 mock.patch.object(MODULE, "file_sha", return_value=(9, "a" * 64)), \
                 mock.patch.object(MODULE, "complete_terminal_seal_cut", return_value=False), \
                 mock.patch.object(MODULE, "call_output",
                                   side_effect=[MODULE.Refused(), MODULE.Refused(), b""]) as gate, \
                 mock.patch.object(MODULE.subprocess, "Popen", return_value=worker), \
                 mock.patch.object(MODULE, "fixed_lines", return_value=b'{"status":"ready"}'), \
                 mock.patch.object(MODULE, "worker_phase", return_value=None) as phase:
                self.assertEqual(MODULE.recover_current(str(candidate)), "recovered")
                phase.assert_called_once()
                self.assertEqual(phase.call_args.args[1], ["rollback", "--capture-started", "0"])
                self.assertEqual(gate.call_count, 3)

    @mock.patch.object(MODULE, "recover_prepare_handoff")
    def test_recover_current_refused_worker_preserves_pending_pointer(self, _prepare_replay):
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate"
            candidate.write_bytes(b"candidate")
            pointer = {"boot_id": "01234567-89ab-cdef-0123-456789abcdef",
                       "stage": "/run/aegis-installer-config-snapshots/stage",
                       "candidate_sha256": "a" * 64}
            pending = Path(temporary) / "current.json"
            pending.write_bytes(b"pending")
            worker = mock.Mock()
            worker.poll.return_value = 0
            worker.wait.return_value = 0
            worker.stdin = io.BytesIO()
            worker.stdout = io.BytesIO()
            admitted_file = SimpleNamespace(st_mode=MODULE.stat.S_IFREG | 0o555,
                                            st_uid=0, st_gid=0, st_nlink=1)
            with mock.patch.object(MODULE.sys, "platform", "linux"), \
                 mock.patch.object(MODULE.os, "geteuid", return_value=0), \
                 mock.patch.object(MODULE, "control_directory",
                                   side_effect=lambda: os.open(temporary, os.O_RDONLY)), \
                 mock.patch.object(MODULE, "current_pointer", return_value=(pointer, b"", None)), \
                 mock.patch.object(MODULE, "current_boot", return_value=pointer["boot_id"]), \
                 mock.patch.object(MODULE.os, "fstat", return_value=admitted_file), \
                 mock.patch.object(MODULE, "file_sha", return_value=(9, "a" * 64)), \
                 mock.patch.object(MODULE, "call_output", side_effect=MODULE.Refused()), \
                 mock.patch.object(MODULE.subprocess, "Popen", return_value=worker), \
                 mock.patch.object(MODULE, "fixed_lines", return_value=b'{"status":"ready"}'), \
                 mock.patch.object(MODULE, "worker_phase", side_effect=MODULE.Refused):
                with self.assertRaises(MODULE.Refused):
                    MODULE.recover_current(str(candidate))
                self.assertEqual(pending.read_bytes(), b"pending")

    @mock.patch.object(MODULE, "recover_prepare_handoff")
    def test_recover_current_completed_rollback_does_not_start_second_worker(self, _prepare_replay):
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate"
            candidate.write_bytes(b"candidate")
            pointer = {"boot_id": "01234567-89ab-cdef-0123-456789abcdef",
                       "stage": "/run/aegis-installer-config-snapshots/stage",
                       "candidate_sha256": "a" * 64}
            admitted_file = SimpleNamespace(st_mode=MODULE.stat.S_IFREG | 0o555,
                                            st_uid=0, st_gid=0, st_nlink=1)
            with mock.patch.object(MODULE.sys, "platform", "linux"), \
                 mock.patch.object(MODULE.os, "geteuid", return_value=0), \
                 mock.patch.object(MODULE, "control_directory",
                                   side_effect=lambda: os.open(temporary, os.O_RDONLY)), \
                 mock.patch.object(MODULE, "current_pointer", return_value=(pointer, b"", None)), \
                 mock.patch.object(MODULE, "current_boot", return_value=pointer["boot_id"]), \
                 mock.patch.object(MODULE.os, "fstat", return_value=admitted_file), \
                 mock.patch.object(MODULE, "file_sha", return_value=(9, "a" * 64)), \
                 mock.patch.object(MODULE, "complete_terminal_seal_cut", return_value=False), \
                 mock.patch.object(MODULE, "call_output",
                                   side_effect=[MODULE.Refused(), b""]) as restore, \
                 mock.patch.object(MODULE.subprocess, "Popen") as worker:
                self.assertEqual(MODULE.recover_current(str(candidate)), "recovered")
                self.assertEqual(restore.call_count, 2)
                worker.assert_not_called()

    @mock.patch.object(MODULE, "recover_prepare_handoff")
    def test_unsealed_finalized_recovery_uses_distinct_locked_command(self, _prepare_replay):
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate"
            candidate.write_bytes(b"candidate")
            pointer = {"boot_id": "01234567-89ab-cdef-0123-456789abcdef",
                       "stage": "/run/aegis-installer-config-snapshots/stage",
                       "candidate_sha256": "a" * 64}
            admitted = SimpleNamespace(st_mode=MODULE.stat.S_IFREG | 0o555,
                                       st_uid=0, st_gid=0, st_nlink=1)
            with ExitStack() as stack:
                for target, attribute, kwargs in (
                    (MODULE.sys, "platform", {"new": "linux"}),
                    (MODULE.os, "geteuid", {"return_value": 0}),
                    (MODULE, "control_directory", {"side_effect": lambda: os.open(
                        temporary, os.O_RDONLY)}),
                    (MODULE, "current_pointer", {"return_value": (pointer, b"pending", None)}),
                    (MODULE, "current_boot", {"return_value": pointer["boot_id"]}),
                    (MODULE.os, "fstat", {"return_value": admitted}),
                    (MODULE, "file_sha", {"return_value": (9, "a" * 64)}),
                    (MODULE, "complete_terminal_seal_cut", {"return_value": False}),
                ):
                    stack.enter_context(mock.patch.object(target, attribute, **kwargs))
                call = stack.enter_context(mock.patch.object(
                    MODULE, "call_output", return_value=b""))
                worker = stack.enter_context(mock.patch.object(MODULE.subprocess, "Popen"))
                self.assertEqual(MODULE.recover_current(str(candidate)), "recovered_stopped")
                call.assert_called_once_with(
                    [str(candidate), "auto-recover-unsealed-finalized", pointer["stage"]],
                    maximum=1024, timeout=120)
                worker.assert_not_called()

    @mock.patch.object(MODULE, "recover_prepare_handoff")
    def test_unsealed_certificate_refusal_never_starts_rollback_worker(self, _prepare_replay):
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate"
            candidate.write_bytes(b"candidate")
            pointer = {"boot_id": "01234567-89ab-cdef-0123-456789abcdef",
                       "stage": "/run/aegis-installer-config-snapshots/stage",
                       "candidate_sha256": "a" * 64}
            admitted = SimpleNamespace(st_mode=MODULE.stat.S_IFREG | 0o555,
                                       st_uid=0, st_gid=0, st_nlink=1)
            with ExitStack() as stack:
                for target, attribute, kwargs in (
                    (MODULE.sys, "platform", {"new": "linux"}),
                    (MODULE.os, "geteuid", {"return_value": 0}),
                    (MODULE, "control_directory", {"side_effect": lambda: os.open(
                        temporary, os.O_RDONLY)}),
                    (MODULE, "current_pointer", {"return_value": (pointer, b"pending", None)}),
                    (MODULE, "current_boot", {"return_value": pointer["boot_id"]}),
                    (MODULE.os, "fstat", {"return_value": admitted}),
                    (MODULE, "file_sha", {"return_value": (9, "a" * 64)}),
                    (MODULE, "complete_terminal_seal_cut", {"return_value": False}),
                    (MODULE, "unsealed_recovery_present", {"return_value": True}),
                ):
                    stack.enter_context(mock.patch.object(target, attribute, **kwargs))
                command = stack.enter_context(mock.patch.object(
                    MODULE, "call_output", side_effect=MODULE.Refused))
                worker = stack.enter_context(mock.patch.object(MODULE.subprocess, "Popen"))
                with self.assertRaises(MODULE.Refused):
                    MODULE.recover_current(str(candidate))
                command.assert_called_once()
                worker.assert_not_called()

    def test_unsealed_stop_keeps_pointer_until_distinct_recovery(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            pointer = root / "current.json"
            pointer.write_bytes(b"retained pending stage")
            info = pointer.stat()
            admitted = ({"stage": "/run/aegis-installer-config-snapshots/stage"},
                        pointer.read_bytes(), info)
            with mock.patch.object(MODULE.sys, "platform", "linux"), \
                 mock.patch.object(MODULE.os, "geteuid", return_value=0), \
                 mock.patch.object(MODULE, "control_directory",
                                   side_effect=lambda: os.open(root, os.O_RDONLY)), \
                 mock.patch.object(MODULE, "current_pointer", return_value=admitted), \
                 mock.patch.object(MODULE, "verified_stop",
                                   return_value=("recovery_required", {})) as verified:
                self.assertEqual(MODULE.stop_current(), "recovery_required")
                verified.assert_called_once()
                self.assertEqual(pointer.read_bytes(), b"retained pending stage")
                self.assertEqual(list(root.glob("archived-*.json")), [])

    @unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0,
                         "requires root-owned Linux directory identities")
    def test_real_control_chain_requires_existing_root_private_leaf(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            (root / "var/lib/aegis-auto").mkdir(parents=True)
            with self.assertRaises(FileNotFoundError):
                MODULE.control_directory(str(root))
            control = root / "var/lib/aegis-auto/control"
            control.mkdir(mode=0o700)
            fd = MODULE.control_directory(str(root))
            os.close(fd)
            control.rmdir()
            control.symlink_to(root)
            with self.assertRaises(OSError):
                MODULE.control_directory(str(root))

    @unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0,
                         "requires root-owned Linux executable identities")
    def test_real_old_binary_backup_binds_bytes_before_replace(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            control = root / "control"
            binary_dir = root / "bin"
            control.mkdir(mode=0o700)
            binary_dir.mkdir(mode=0o700)
            installed = binary_dir / "aegis-client"
            installed.write_bytes(b"original executable generation")
            os.chmod(installed, 0o755)
            fd = os.open(control, os.O_RDONLY | os.O_DIRECTORY)
            try:
                previous = MODULE.snapshot_old_binary(fd, installed)
                backup = control / previous["name"]
                self.assertEqual((previous["device"], previous["inode"]),
                                 (installed.stat().st_dev, installed.stat().st_ino))
                self.assertEqual((previous["backup_device"], previous["backup_inode"]),
                                 (backup.stat().st_dev, backup.stat().st_ino))
                self.assertNotEqual((previous["device"], previous["inode"]),
                                    (previous["backup_device"], previous["backup_inode"]))
                self.assertEqual(backup.read_bytes(),
                                 b"original executable generation")
                self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
                pointer = {"schema": "aegis_installer_auto_v2_stage_v2",
                           "stage": "/run/aegis-installer-config-snapshots/stage",
                           "status": "pending", "boot_id": "a" * 36,
                           "candidate_sha256": "b" * 64,
                           "installed_binary": "/usr/local/bin/aegis-client",
                           "previous_binary": previous}
                (control / "current.json").write_bytes(json.dumps(pointer).encode())
                os.chmod(control / "current.json", 0o600)
                self.assertEqual(MODULE.current_pointer(fd)[0], pointer)
                v3 = json.loads(json.dumps(pointer))
                v3["schema"] = "aegis_installer_auto_v2_boot_stage_v3"
                v3["boot_intent_sha256"] = "c" * 64
                v3["prepare_intent_sha256"] = "d" * 64
                v3["prepare_completed_sha256"] = "e" * 64
                (control / "current.json").write_bytes(json.dumps(v3).encode())
                self.assertEqual(MODULE.current_pointer(fd)[0], v3)
                for changed in (
                    {**v3, "prepare_completed_sha256": None},
                    {key: value for key, value in v3.items()
                     if key != "prepare_intent_sha256"},
                    {**v3, "boot_intent_sha256": "A" * 64},
                    {**v3, "schema": "aegis_installer_auto_v2_stage_v2"},
                ):
                    (control / "current.json").write_bytes(json.dumps(changed).encode())
                    with self.assertRaises(MODULE.Refused):
                        MODULE.current_pointer(fd)
                (control / "current.json").write_bytes(json.dumps(pointer).encode())
                replacement = control / "replacement"
                replacement.write_bytes(backup.read_bytes())
                os.chmod(replacement, 0o600)
                os.replace(replacement, backup)
                with self.assertRaises(MODULE.Refused):
                    MODULE.current_pointer(fd)
                pointer["previous_binary"]["backup_inode"] = backup.stat().st_ino
                (control / "current.json").write_bytes(json.dumps(pointer).encode())
                self.assertEqual(MODULE.current_pointer(fd)[0], pointer)
                os.chmod(backup, 0o644)
                with self.assertRaises(MODULE.Refused):
                    MODULE.current_pointer(fd)
                os.chmod(backup, 0o600)
                backup.write_bytes(b"changed executable generation!")
                with self.assertRaises(MODULE.Refused):
                    MODULE.current_pointer(fd)
                backup.write_bytes(b"original executable generation")
                missing = json.loads(json.dumps(pointer))
                del missing["previous_binary"]["backup_inode"]
                (control / "current.json").write_bytes(json.dumps(missing).encode())
                with self.assertRaises(MODULE.Refused):
                    MODULE.current_pointer(fd)
                legacy_mixed = json.loads(json.dumps(pointer))
                legacy_mixed["schema"] = "aegis_installer_auto_v2_stage_v1"
                (control / "current.json").write_bytes(json.dumps(legacy_mixed).encode())
                with self.assertRaises(MODULE.Refused):
                    MODULE.current_pointer(fd)
                legacy = json.loads(json.dumps(legacy_mixed))
                del legacy["previous_binary"]["backup_device"]
                del legacy["previous_binary"]["backup_inode"]
                (control / "current.json").write_bytes(json.dumps(legacy).encode())
                self.assertEqual(MODULE.current_pointer(fd)[0], legacy)
                (control / "current.json").unlink()
                installed.write_bytes(b"changed executable generation")
                candidate = root / "candidate"
                candidate.write_bytes(b"next executable generation")
                os.chmod(candidate, 0o555)
                with self.assertRaises(MODULE.Refused):
                    MODULE.install_candidate(candidate, installed, previous)
                self.assertEqual(installed.read_bytes(), b"changed executable generation")
            finally:
                os.close(fd)

    def test_stop_inspection_requires_actual_finalized_stop_and_live_absence(self):
        unit = "aegis-auto@" + "a" * 64 + ".service"
        record = {"schema": "aegis_auto_v2_stopped_stage_inspection_v1",
                  "stage": {"path": "/run/aegis-installer-config-snapshots/stage"},
                  "published_paths": {"current_verified": True},
                  "terminal": {"outcome": "finalized-stopped",
                               "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
                               "stop_terminal_sha256": "b" * 64,
                               "private_unit": unit},
                  "main": {"stopped_verified": True, "no_live_lease_verified": True,
                           "fdstore_empty_verified": True},
                  "guardian": {"deny_verified": True, "fdstore_empty_verified": True}}
        with mock.patch.object(MODULE, "call_output", return_value=json.dumps(record).encode()) as call, \
             mock.patch.object(MODULE, "active_properties", side_effect=AssertionError("typed Stop already checked collected units")) as stopped:
            MODULE.inspect_after_stop("/usr/local/bin/aegis-client",
                                      "/run/aegis-installer-config-snapshots/stage",
                                      record["terminal"]["boot_id"])
            stopped.assert_not_called()
            self.assertEqual(call.call_args.args[0],
                             ["/usr/local/bin/aegis-client", "auto-seal-stopped-generation",
                              record["stage"]["path"]])
            record["terminal"]["outcome"] = "finalized"
            with mock.patch.object(MODULE, "call_output", return_value=json.dumps(record).encode()):
                with self.assertRaises(MODULE.Refused):
                    MODULE.inspect_after_stop("/usr/local/bin/aegis-client",
                                              record["stage"]["path"],
                                              record["terminal"]["boot_id"])
            record["terminal"]["outcome"] = "finalized-stopped"
            for group, field in (("main", "stopped_verified"), ("main", "no_live_lease_verified"),
                                 ("main", "fdstore_empty_verified"),
                                 ("guardian", "deny_verified"), ("guardian", "fdstore_empty_verified")):
                record[group][field] = False
                with mock.patch.object(MODULE, "call_output", return_value=json.dumps(record).encode()):
                    with self.assertRaises(MODULE.Refused):
                        MODULE.inspect_after_stop("/usr/local/bin/aegis-client", record["stage"]["path"],
                                                  record["terminal"]["boot_id"])
                record[group][field] = True
            stopped.reset_mock()
            with mock.patch.object(MODULE, "call_output", return_value=json.dumps(record).encode()):
                MODULE.inspect_after_stop("/usr/local/bin/aegis-client", record["stage"]["path"],
                                          record["terminal"]["boot_id"])
            stopped.assert_not_called()

    def test_actual_cli_subcommands_parse_and_non_linux_refuses(self):
        parsed = MODULE.parser().parse_args(["stop-current"])
        self.assertEqual(parsed.operation, "stop-current")
        parsed = MODULE.parser().parse_args(["preflight-passive", "--candidate-binary",
                                              "/opt/candidate/aegis-client"])
        self.assertEqual(parsed.operation, "preflight-passive")
        argv = ["install", "--config-root", "/etc/aegis", "--state-dir", "/var/lib/aegis",
                "--metadata-dir", "/var/lib/aegis-admin", "--staging-parent",
                "/run/aegis-installer-config-snapshots", "--public-payload-root", "/opt/public",
                "--candidate-binary", "/opt/candidate/aegis-client", "--installed-binary",
                "/usr/local/bin/aegis-client", "--runtime-events", "/var/log/aegis/events",
                "--existing-choice", "none", "--bundle-dir", "/opt/private-bundle"]
        self.assertEqual(MODULE.parser().parse_args(argv).operation, "install")
        completed = subprocess.run([sys.executable, "-I", "-B", str(SOURCE), "stop-current"],
                                   capture_output=True, timeout=5, check=False)
        if sys.platform != "linux":
            self.assertEqual(completed.returncode, 1)
            self.assertEqual(completed.stdout, b'{"status":"refused"}\n')

    def test_one_real_pipe_worker_enforces_phase_order_and_eof(self):
        child_source = r'''
import json,sys
print('{"status":"ready"}', flush=True)
expected = [["inspect","--field","product-mode"],
            ["verify","--phase","before-custody"]]
for command in expected:
    line = sys.stdin.buffer.readline()
    if not line or json.loads(line)["command"] != command:
        print('{"status":"error","reason":"phase_refused"}', flush=True)
        sys.exit(2)
    print('{"status":"ok","value":null}', flush=True)
if sys.stdin.buffer.readline():
    sys.exit(3)
'''
        proc = subprocess.Popen([sys.executable, "-I", "-B", "-u", "-c", child_source],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)
        try:
            started = MODULE.time.monotonic()
            MODULE.response(MODULE.fixed_lines(proc, MODULE.MAX_REPLY, started + 5), "ready")
            self.assertIsNone(MODULE.worker_phase(
                proc, ["inspect", "--field", "product-mode"], started))
            self.assertIsNone(MODULE.worker_phase(
                proc, ["verify", "--phase", "before-custody"], started))
            proc.stdin.close()
            self.assertEqual(proc.wait(timeout=5), 0)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
            proc.stdout.close()

    def test_real_pipe_worker_disconnect_refuses(self):
        proc = subprocess.Popen([sys.executable, "-I", "-B", "-u", "-c",
                                 "print('{\"status\":\"ready\"}', flush=True)"],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)
        try:
            started = MODULE.time.monotonic()
            MODULE.response(MODULE.fixed_lines(proc, MODULE.MAX_REPLY, started + 5), "ready")
            proc.wait(timeout=5)
            with self.assertRaises((BrokenPipeError, MODULE.Refused)):
                MODULE.worker_phase(proc, ["finalize"], started)
        finally:
            proc.stdin.close()
            proc.stdout.close()

    def test_protocol_rejects_duplicate_and_extra_fields(self):
        with self.assertRaises(MODULE.Refused):
            MODULE.response(b'{"status":"ok","status":"ok","value":null}', "ok")
        with self.assertRaises(MODULE.Refused):
            MODULE.response(b'{"status":"ok","value":null,"extra":1}', "ok")
        with self.assertRaises(MODULE.Refused):
            MODULE.response(b'{"status":"error","reason":"phase_refused"}', "ok")
        self.assertIsNone(MODULE.response(b'{"status":"ok","value":null}', "ok"))

    def test_worker_phase_error_preserves_refusal(self):
        proc = mock.Mock()
        proc.poll.return_value = None
        with mock.patch.object(MODULE, "fixed_lines", return_value=b'{"status":"error","reason":"phase_refused"}'):
            with self.assertRaises(MODULE.Refused):
                MODULE.worker_phase(proc, ["finalize"], MODULE.time.monotonic())

    def test_pointer_is_unique_and_private_and_retained_on_stop_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            def held():
                return os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            with mock.patch.object(MODULE.sys, "platform", "linux"), \
                 mock.patch.object(MODULE.os, "geteuid", return_value=0), \
                 mock.patch.object(MODULE, "control_directory", side_effect=held), \
                 mock.patch.object(MODULE, "snapshot_old_binary", return_value=None), \
                 mock.patch.object(MODULE, "current_boot", return_value="01234567-89ab-cdef-0123-456789abcdef"):
                MODULE.record_stage(Path("/run/aegis-installer-config-snapshots/stage"),
                                    "a" * 64, Path("/usr/local/bin/aegis-client"))
                self.assertEqual((root / "current.json").stat().st_mode & 0o777, 0o600)
                raw = (root / "current.json").read_bytes()
                existing = (json.loads(raw), raw, (root / "current.json").stat())
                with mock.patch.object(MODULE, "current_pointer", return_value=existing):
                    with self.assertRaises(MODULE.Refused):
                        MODULE.record_stage(Path("/run/aegis-installer-config-snapshots/stage"),
                                            "a" * 64, Path("/usr/local/bin/aegis-client"))
                with mock.patch.object(MODULE, "current_pointer", return_value=existing), \
                     mock.patch.object(MODULE, "verified_stop", side_effect=MODULE.Refused):
                    with self.assertRaises(MODULE.Refused):
                        MODULE.stop_current()
                self.assertTrue((root / "current.json").exists())
                self.assertEqual(list(root.glob("archived-*.json")), [])

    def test_stopped_pointer_archive_is_delegated_to_locked_rust_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            def held():
                return os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            with mock.patch.object(MODULE.sys, "platform", "linux"), \
                 mock.patch.object(MODULE.os, "geteuid", return_value=0), \
                 mock.patch.object(MODULE, "control_directory", side_effect=held), \
                 mock.patch.object(MODULE, "snapshot_old_binary", return_value=None), \
                 mock.patch.object(MODULE, "current_boot", return_value="01234567-89ab-cdef-0123-456789abcdef"):
                self.assertEqual(MODULE.stop_current(), "noop")
                MODULE.record_stage(Path("/run/aegis-installer-config-snapshots/stage"),
                                    "b" * 64, Path("/usr/local/bin/aegis-client"))
                before = (root / "current.json").read_bytes()
                details = (root / "current.json").stat()
                retained = (json.loads(before), before, details)
                with mock.patch.object(MODULE, "current_pointer", return_value=retained), \
                     mock.patch.object(MODULE, "verified_stop", return_value=("stopped", {})) as verifier, \
                     mock.patch.object(MODULE, "call_output", return_value=b"") as archive:
                    self.assertEqual(MODULE.stop_current(), "stopped")
                    verifier.assert_called_once()
                    archive.assert_called_once_with(
                        ["/usr/local/bin/aegis-client", "auto-archive-stopped-generation",
                         retained[0]["stage"]], maximum=1024, timeout=120)
                # The Python caller has no authority to unlink either the old
                # pointer or a successor that appeared after its Stop readback.
                self.assertEqual((root / "current.json").read_bytes(), before)
                self.assertEqual(list(root.glob("archived-*.json")), [])
                with mock.patch.object(MODULE, "current_pointer", return_value=retained), \
                     mock.patch.object(MODULE, "verified_stop", return_value=("stopped", {})), \
                     mock.patch.object(MODULE, "call_output", side_effect=MODULE.Refused):
                    with self.assertRaises(MODULE.Refused):
                        MODULE.stop_current()
                self.assertEqual((root / "current.json").read_bytes(), before)

    def test_requested_socks_refuses_stopped_wide_before_pointer_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            def held():
                return os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            with mock.patch.object(MODULE.sys, "platform", "linux"), \
                 mock.patch.object(MODULE.os, "geteuid", return_value=0), \
                 mock.patch.object(MODULE, "control_directory", side_effect=held), \
                 mock.patch.object(MODULE, "snapshot_old_binary", return_value=None), \
                 mock.patch.object(MODULE, "current_boot", return_value="01234567-89ab-cdef-0123-456789abcdef"):
                MODULE.record_stage(Path("/run/aegis-installer-config-snapshots/stage"),
                                    "b" * 64, Path("/usr/local/bin/aegis-client"))
                with mock.patch.object(MODULE, "verified_stop", return_value=(
                        "stopped", {"stage": {"mode": "full-wide-tun"}})), \
                     mock.patch.object(MODULE, "call_output") as archive:
                    with self.assertRaises(MODULE.Refused):
                        MODULE.stop_current("socks-only")
                    archive.assert_not_called()

    def test_requested_socks_uses_installed_mode_checked_stop(self):
        pointer = {"installed_binary": "/usr/local/bin/aegis-client",
                   "stage": "/run/aegis-installer-config-snapshots/stage",
                   "candidate_sha256": "a" * 64,
                   "boot_id": "01234567-89ab-cdef-0123-456789abcdef"}
        with tempfile.TemporaryFile() as held, \
             mock.patch.object(MODULE.os, "open", return_value=held.fileno()), \
             mock.patch.object(MODULE.os, "fstat", return_value=SimpleNamespace(
                 st_mode=stat.S_IFREG | 0o755, st_uid=0, st_nlink=1)), \
             mock.patch.object(MODULE, "file_sha", return_value=(1, "a" * 64)), \
             mock.patch.object(MODULE, "current_boot", return_value=pointer["boot_id"]), \
             mock.patch.object(MODULE, "inspect_after_stop", side_effect=[MODULE.Refused(),
                 {"stage": {"mode": "socks-only"}}]), \
             mock.patch.object(MODULE, "inspect_unsealed_after_stop", side_effect=MODULE.Refused()), \
             mock.patch.object(MODULE, "call_output", return_value=b"") as command, \
             mock.patch.object(MODULE.os, "close"):
            status, _ = MODULE.verified_stop(pointer, "socks-only")
            self.assertEqual(status, "stopped")
            command.assert_called_once_with(
                [pointer["installed_binary"], "auto-stop-finalized-socks", pointer["stage"]],
                maximum=4096, timeout=45, diagnostic_stderr=True)

    def test_pointer_tampering_refuses_before_stop(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            (root / "current.json").write_text(json.dumps({"schema": "bad"}))
            os.chmod(root / "current.json", 0o600)
            def held():
                return os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            with mock.patch.object(MODULE.sys, "platform", "linux"), \
                 mock.patch.object(MODULE.os, "geteuid", return_value=0), \
                 mock.patch.object(MODULE, "control_directory", side_effect=held), \
                 mock.patch.object(MODULE, "verified_stop") as verifier:
                with self.assertRaises(MODULE.Refused):
                    MODULE.stop_current()
                verifier.assert_not_called()


if __name__ == "__main__":
    unittest.main()
