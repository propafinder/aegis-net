"""A protected first arm survives multiple authenticated cold successors."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import aegis_auto_guardian as guardian


class FirstArmSuccessorLineage(unittest.TestCase):
    def test_three_boots_require_each_direct_consumed_producer(self):
        boots = [f"00000000-0000-0000-0000-{value:012x}" for value in (1, 2, 3)]
        candidate = "a" * 64
        policy = "e" * 64
        old_unit = "aegis-auto@" + "b" * 64 + ".service"
        successor_units = ["aegis-auto@" + token * 64 + ".service"
                           for token in ("c", "d")]
        receipt = {"boot_id": boots[0], "candidate_sha256": candidate,
                   "policy_sha256": "d" * 64}
        request = {"boot_id": boots[0], "private_unit": old_unit}

        self.assertTrue(guardian._first_arm_boot_owned(receipt, request, None))
        self.assertTrue(guardian._first_arm_guard_owned(
            receipt, request, "d" * 64, None))
        self.assertFalse(guardian._first_arm_guard_owned(
            receipt, request, policy, None))
        for prior, current, current_unit in zip(
                boots, boots[1:], successor_units):
            request["boot_id"] = current
            request["private_unit"] = current_unit
            self.assertFalse(guardian._first_arm_boot_owned(receipt, request, None))
            lineage = {"current_boot_id": current,
                       "predecessor_boot_id": prior,
                       "candidate_sha256": candidate,
                       "private_unit": old_unit,
                       "source_config_sha256": "9" * 64,
                       "current_policy_sha256": policy}
            self.assertTrue(guardian._first_arm_boot_owned(receipt, request,
                                                            lineage))
            self.assertTrue(guardian._first_arm_guard_owned(
                receipt, request, policy, lineage))
            request["private_unit"] = "malformed-fresh-service"
            self.assertFalse(guardian._first_arm_boot_owned(
                receipt, request, lineage))
            request["private_unit"] = old_unit
            self.assertFalse(guardian._first_arm_boot_owned(
                receipt, request, lineage))
            request["private_unit"] = current_unit
            self.assertFalse(guardian._first_arm_guard_owned(
                receipt, request, "f" * 64, lineage))
            for field, bad in (("candidate_sha256", "c" * 64),
                               ("source_config_sha256", "not-a-sha"),
                               ("private_unit", current_unit),
                               ("current_boot_id", prior),
                               ("predecessor_boot_id", current)):
                self.assertFalse(guardian._first_arm_boot_owned(
                    receipt, request, {**lineage, field: bad}), field)
            self.assertFalse(guardian._first_arm_boot_owned(
                receipt, request, {**lineage, "unauthenticated": True}))
            self.assertFalse(guardian._first_arm_boot_owned(
                receipt, request,
                {**lineage, "private_unit": "malformed-old-service"}))
            self.assertFalse(guardian._first_arm_guard_owned(
                receipt, request, policy,
                {**lineage, "current_policy_sha256": "f" * 64}))
            old_unit = current_unit
        self.assertFalse(guardian._first_arm_boot_owned(
            {**receipt, "boot_id": "not-a-boot"}, request, lineage))


if __name__ == "__main__":
    unittest.main()
