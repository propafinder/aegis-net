#!/usr/bin/env python3
"""Callback failures stay fixed, actionable, and fail closed across ctypes."""
import unittest

from scripts.lib import aegis_auto_terminal_witness as witness


class CallbackRefusal(unittest.TestCase):
    def test_known_callback_refusal_survives_c_boundary(self):
        for reason in ('job_removed_read', 'job_path',
                       'private_stop_job_replaced', 'final_job_replaced',
                       'job_event_bound'):
            self.assertEqual(witness.callback_failure_reason(RuntimeError(reason)),
                             reason)
            bus = object.__new__(witness.DirectBus)
            bus.bus = None
            bus.failed = reason
            bus.process = lambda *_: 1
            with self.assertRaisesRegex(RuntimeError, '^' + reason + '$'):
                bus.drain()

    def test_untrusted_callback_text_is_never_reported(self):
        self.assertEqual(witness.callback_failure_reason(
            RuntimeError('outside fixed refusal grammar')), 'bus_callback')
        self.assertEqual(witness.callback_failure_reason(
            ValueError('arbitrary D-Bus payload')), 'bus_callback')


if __name__ == '__main__':
    unittest.main()
