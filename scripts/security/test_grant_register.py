"""Synthetic contracts for grant-register coverage, without repository edits."""

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "grant_register_checker", Path(__file__).with_name("check-grant-register.py")
)
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)

# Independent explicit oracle; it must not be generated from checker constants.
IDS = (
    "P0.1 P0.2 P0.3 P0.4 P0.5 P0.6 P0.7 P0.8 P0.9 P0.10 "
    "P1.1 P1.2 P1.3 P1.4 P1.5 P1.6 P1.7 P1.8 P1.9 P1.10 "
    "P2.1 P2.2 P2.3 P2.4 P2.5 P2.6 P2.7 P2.8 P2.9 "
    "P3.1 P3.2 P3.3 P3.4 P3.5 P3.6 P3.7 P3.8"
).split()


def document(ids=IDS):
    return "\n".join(
        ["# Register", "| ID | State and actual work | Remaining acceptance |",
         "|---|---|---|"]
        + [f"| {item} Description | Partial | Evidence remains |" for item in ids]
    )


class GrantRegisterTests(unittest.TestCase):
    def test_current_table_format_and_exact_coverage(self):
        result = CHECKER.analyze_register(document())
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["observed_unique_rows"], 37)

    def test_deleted_public_names_and_naming_rows_are_missing(self):
        result = CHECKER.analyze_register(
            document([item for item in IDS if item not in {"P3.6", "P3.8"}])
        )
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["missing_rows"], 2)

    def test_count_37_with_duplicate_does_not_replace_missing_id(self):
        changed = [item if item != "P3.8" else "P3.7" for item in IDS]
        result = CHECKER.analyze_register(document(changed))
        self.assertEqual(result["observed_valid_rows"], 37)
        self.assertEqual(result["missing_rows"], 1)
        self.assertEqual(result["duplicate_rows"], 1)
        self.assertEqual(result["status"], "FAIL")

    def test_tenth_id_is_not_prefix_match_for_first(self):
        result = CHECKER.analyze_register(document([i for i in IDS if i != "P0.1"]))
        self.assertEqual(result["missing_rows"], 1)
        self.assertEqual(result["duplicate_rows"], 0)

    def test_unknown_and_malformed_rows_fail_complete_register(self):
        for row, field in (
            ("P3.9", "unknown_rows"), ("P0.11", "unknown_rows"),
            ("P4.1", "malformed_rows"), ("P0x1", "malformed_rows"),
            ("P0.1suffix", "malformed_rows"), ("P0.01", "malformed_rows"),
        ):
            with self.subTest(row=row):
                result = CHECKER.analyze_register(document() + f"\n| {row} | open | open |")
                self.assertEqual(result[field], 1)
                self.assertEqual(result["status"], "FAIL")

    def test_id_row_requires_state_and_remaining_acceptance_cells(self):
        for replacement in (
            "| P0.1 Description |",
            "| P0.1 Description | Partial |",
            "| P0.1 Description | | Evidence remains |",
            "| P0.1 Description | Partial | |",
        ):
            with self.subTest(replacement=replacement):
                changed = document().replace(
                    "| P0.1 Description | Partial | Evidence remains |", replacement
                )
                result = CHECKER.analyze_register(changed)
                self.assertEqual(result["status"], "FAIL")
                self.assertEqual(result["missing_rows"], 1)
                self.assertEqual(result["malformed_rows"], 1)

    def test_prose_summary_and_second_cell_are_not_coverage(self):
        result = CHECKER.analyze_register(
            "All original IDs: " + " ".join(IDS) + "\n"
            + "\n".join(f"| Summary | {item} | Open |" for item in IDS)
        )
        self.assertEqual(result["observed_unique_rows"], 0)
        self.assertEqual(result["missing_rows"], 37)

    def test_backtick_and_tilde_code_examples_do_not_count(self):
        result = CHECKER.analyze_register(
            "```markdown\n" + document() + "\n```\n~~~\n" + document() + "\n~~~"
        )
        self.assertEqual(result["observed_valid_rows"], 0)
        self.assertEqual(result["status"], "FAIL")

    def test_fenced_duplicates_do_not_break_actual_complete_table(self):
        result = CHECKER.analyze_register(
            document() + "\n````markdown\n" + document() + "\n```\n````"
        )
        self.assertEqual(result["status"], "PASS")

    def test_optional_outer_pipes_and_whitespace(self):
        text = "\n".join(f"  {i} Description | Partial | Remaining  " for i in IDS)
        self.assertEqual(CHECKER.analyze_register(text)["status"], "PASS")

    def test_input_error_diagnostics_do_not_disclose_path(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "PRIVATE_SENTINEL_DO_NOT_ECHO"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = CHECKER.main([str(missing)])
            self.assertEqual(code, 2)
            self.assertNotIn("PRIVATE_SENTINEL", output.getvalue())
            self.assertEqual(json.loads(output.getvalue())["status"], "ERROR")

    def test_argument_error_does_not_echo_untrusted_arguments(self):
        marker = "PRIVATE_ARGUMENT_SENTINEL_729c"
        for arguments in ([], [marker, "--" + marker], [marker, marker]):
            with self.subTest(argument_count=len(arguments)):
                output, errors = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    code = CHECKER.main(arguments)
                self.assertEqual(code, 2)
                self.assertNotIn(marker, output.getvalue())
                self.assertNotIn(marker, errors.getvalue())
                self.assertEqual(errors.getvalue(), "")
                self.assertEqual(
                    json.loads(output.getvalue()),
                    {"status": "ERROR", "reason": "input_not_accepted"},
                )

    def test_cli_is_read_only_and_has_aggregate_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "register.md"
            original = document().encode("utf-8")
            path.write_bytes(original)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = CHECKER.main([str(path)])
            self.assertEqual(code, 0)
            self.assertEqual(path.read_bytes(), original)
            self.assertNotIn(str(path), output.getvalue())
            self.assertNotIn("Description", output.getvalue())

    def test_oversized_and_non_utf8_inputs_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "register.md"
            for value in (b"\xff", b"a" * (CHECKER.MAX_INPUT_BYTES + 1)):
                with self.subTest(size=len(value)):
                    path.write_bytes(value)
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        code = CHECKER.main([str(path)])
                    self.assertEqual(code, 2)
                    self.assertEqual(json.loads(output.getvalue())["status"], "ERROR")


if __name__ == "__main__":
    unittest.main()
