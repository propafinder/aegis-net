"""An ordinary Stop ends the launch watch with a closed event, not a refusal.

The evaluation order (inactive read, watchdog.begin_stop(probe=True), second
inactive read, then fail_closed or _stop_lost_launch) is unchanged; only the
two buffered launch_transition_refused records wait for the outcome.
"""
import contextlib
import importlib.util
import io
import json
import tempfile
from pathlib import Path
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "lib/aegis_auto_guardian.py"
SPEC = importlib.util.spec_from_file_location("aegis_auto_guardian_watch_label", SOURCE)
guardian = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guardian)
UNIT = "aegis-auto@" + "a" * 64 + ".service"


class LaunchWatchLabel(unittest.TestCase):
    def watch(self, *, inactive, normal_stop, watchdog=True):
        calls = []
        actor = guardian.Guardian()
        held = mock.Mock()
        held.revalidate.side_effect = guardian.Refused("launch_actor_launch_process_exited")
        held.close.side_effect = lambda: calls.append("close")
        actor.main_digests[UNIT] = "b" * 64
        actor.launches[UNIT] = held
        monitor = mock.Mock()
        monitor.begin_stop.side_effect = lambda probe: (calls.append(("begin_stop", probe)),
                                                        object() if normal_stop else None)[1]
        monitor.fail_closed.side_effect = lambda reason: calls.append(("fail_closed", reason))
        if watchdog:
            actor.watchdogs[UNIT] = monitor
        reads = iter(inactive)
        def inactive_read(unit):
            calls.append("inactive")
            return next(reads)
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(guardian, "INSTALL", Path(directory) / "install.json"), \
             mock.patch.object(guardian, "_pending_owned_stop",
                               side_effect=guardian.Refused("pending_stop_process_exited")), \
             mock.patch.object(guardian, "_private_unit_inactive", side_effect=inactive_read), \
             mock.patch.object(guardian, "_stop_lost_launch",
                               side_effect=lambda unit: calls.append(("stop_lost", unit))), \
             contextlib.redirect_stderr(output):
            actor._watch_launch(UNIT, held)
        events = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertNotIn(UNIT, actor.launches)
        return calls, events

    def test_inactive_unit_ends_with_one_closed_event(self):
        calls, events = self.watch(inactive=[True], normal_stop=False)
        self.assertEqual(calls, ["inactive", "close"])
        self.assertEqual([(e["event"], e["phase"]) for e in events],
                         [("launch_watch_ended", "inactive")])
        self.assertEqual(set(events[0]), {"event", "phase", "monotonic_ns"})

    def test_normal_stopping_ends_with_one_closed_event(self):
        calls, events = self.watch(inactive=[False], normal_stop=True)
        self.assertEqual(calls, ["inactive", ("begin_stop", True), "close"])
        self.assertEqual([(e["event"], e["phase"]) for e in events],
                         [("launch_watch_ended", "normal_stopping")])

    def test_second_inactive_read_after_begin_stop_is_still_an_ordinary_end(self):
        calls, events = self.watch(inactive=[False, True], normal_stop=False)
        self.assertEqual(calls, ["inactive", ("begin_stop", True), "inactive", "close"])
        self.assertEqual([(e["event"], e["phase"]) for e in events],
                         [("launch_watch_ended", "inactive")])

    def test_lost_channel_prints_both_refusals_then_fails_closed(self):
        calls, events = self.watch(inactive=[False, False], normal_stop=False)
        self.assertEqual(calls, ["inactive", ("begin_stop", True), "inactive",
                                 ("fail_closed", "launch_channel_lost"), "close"])
        self.assertEqual([(e["event"], e["phase"]) for e in events],
                         [("launch_transition_refused", "launch"),
                          ("launch_transition_refused", "pending_stop")])

    def test_lost_channel_without_watchdog_stops_the_lost_launch(self):
        calls, events = self.watch(inactive=[False, False], normal_stop=False, watchdog=False)
        self.assertEqual(calls, ["inactive", "inactive", ("stop_lost", UNIT), "close"])
        self.assertEqual([e["event"] for e in events],
                         ["launch_transition_refused", "launch_transition_refused"])


if __name__ == "__main__":
    unittest.main()
