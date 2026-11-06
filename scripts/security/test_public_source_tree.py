#!/usr/bin/env python3
"""Inert temporary fixtures only; never inspect the working source tree."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "public_source_tree", Path(__file__).with_name("check-public-source-tree.py")
)
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)
INVALID_PRIVATE_VALUE = "INVALID_PRIVATE_EXACT_MARKER_1"


class PublicSourceTreeTests(unittest.TestCase):
    def setUp(self):
        # macOS /tmp can be a symlink: fixture parents themselves must be real.
        self.temp = tempfile.TemporaryDirectory(
            prefix="aegis-public-tree-inert-", dir=os.path.realpath(tempfile.gettempdir())
        )
        self.base = Path(self.temp.name)
        self.tree = self.base / "candidate"
        self.tree.mkdir()
        self.manifest = self.base / "manifest.json"
        self.denylist = self.base / "private-denylist.json"
        self.controls()

    def tearDown(self):
        self.temp.cleanup()

    def controls(self, manifest=None, denylist=None):
        self.manifest.write_text(json.dumps(
            ["README.md"] if manifest is None else manifest
        ), encoding="utf-8")
        self.denylist.write_text(json.dumps(
            [INVALID_PRIVATE_VALUE] if denylist is None else denylist
        ), encoding="utf-8")

    def write(self, relative="README.md", text="Approved inert example.\n"):
        path = self.tree / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            path.write_bytes(text)
        else:
            path.write_text(text, encoding="utf-8")
        return path

    def run_gate(self, tree=None, manifest=None, denylist=None):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = GATE.main([
                "--tree", str(self.tree if tree is None else tree),
                "--manifest-file", str(self.manifest if manifest is None else manifest),
                "--denylist-file", str(self.denylist if denylist is None else denylist),
            ])
        return code, json.loads(output.getvalue()), output.getvalue()

    def classes(self, result):
        return {item["class"] for item in result["findings"]}

    def assert_failure(self, category, **kwargs):
        code, result, output = self.run_gate(**kwargs)
        self.assertNotEqual(code, 0)
        self.assertEqual(result["status"], "FAIL")
        self.assertIn(category, self.classes(result))
        return result, output

    def test_exact_nested_manifest_passes_utf8_text_and_empty_files(self):
        self.controls(["README.md", "src/example.rs", "empty.txt"])
        self.write(text="Approved café example.\nhttps://example.invalid/docs\n")
        self.write("src/example.rs", "// Inert example.\n")
        self.write("empty.txt", "")
        code, result, output = self.run_gate()
        self.assertEqual(code, 0)
        self.assertEqual(result, {"status": "PASS", "checked_files": 3, "findings": []})
        self.assertNotIn(str(self.base), output)

    def test_manifest_file_must_be_present(self):
        self.assert_failure("missing-manifest-file")

    def test_unknown_file_rejected_without_reading_it(self):
        self.write()
        self.write("unknown.txt", INVALID_PRIVATE_VALUE)
        result, output = self.assert_failure("unlisted-file")
        self.assertNotIn("denylist-content-match", self.classes(result))
        self.assertEqual(result["checked_files"], 1)
        self.assertNotIn(INVALID_PRIVATE_VALUE, output)

    def test_unknown_directory_rejected_without_descent(self):
        self.write()
        self.write("unknown/hidden.txt", INVALID_PRIVATE_VALUE)
        result, output = self.assert_failure("unlisted-directory")
        self.assertNotIn("denylist-content-match", self.classes(result))
        self.assertNotIn("hidden.txt", output)

    def test_empty_unknown_directory_also_rejected(self):
        self.write()
        (self.tree / "unknown").mkdir()
        self.assert_failure("unlisted-directory")

    def test_control_arrays_must_be_nonempty_unique_strings(self):
        self.write()
        invalid_arrays = [[], {}, "INVALID_EXAMPLE", [""], ["  "], [17], [["README.md"]], ["\ud800"], ["README.md", "README.md"]]
        for category, control in [("manifest", self.manifest), ("denylist", self.denylist)]:
            for invalid in invalid_arrays:
                with self.subTest(category=category, invalid=invalid):
                    self.controls()
                    control.write_text(json.dumps(invalid), encoding="utf-8")
                    result, output = self.assert_failure("invalid-" + category)
                    self.assertEqual(result["checked_files"], 0)
                    self.assertNotIn(str(control), output)

    def test_malformed_private_json_never_echoes_its_content(self):
        self.write()
        self.denylist.write_text('["' + INVALID_PRIVATE_VALUE, encoding="utf-8")
        _, output = self.assert_failure("invalid-denylist")
        self.assertNotIn(INVALID_PRIVATE_VALUE, output)

    def test_missing_control_is_an_input_failure(self):
        self.write()
        self.denylist.unlink()
        code, result, output = self.run_gate()
        self.assertEqual(code, 2)
        self.assertIn("invalid-denylist", self.classes(result))
        self.assertNotIn(str(self.denylist), output)

    def test_control_input_reads_are_size_bounded(self):
        self.write()
        with patch.object(GATE, "MAX_INPUT_BYTES", 8):
            self.assert_failure("invalid-denylist")

    def test_unsafe_manifest_paths_rejected_before_tree_scan(self):
        self.write()
        for value in ["/README.md", "../README.md", "x/../README.md", "./README.md", "x//file", "README.md/", "*.rs", "file?.rs", "[ab].rs", "x\\file", ".git/HEAD", "x/.hg/file", "bad\nfile", "bad\x00file"]:
            with self.subTest(value=value):
                self.controls([value])
                result, _ = self.assert_failure("invalid-manifest-path")
                self.assertEqual(result["checked_files"], 0)

    def test_controls_must_be_outside_candidate(self):
        self.write()
        inside = self.tree / "private.json"
        inside.write_text(json.dumps([INVALID_PRIVATE_VALUE]), encoding="utf-8")
        result, output = self.assert_failure("control-input-inside-tree", denylist=inside)
        self.assertEqual(result["checked_files"], 0)
        self.assertNotIn(INVALID_PRIVATE_VALUE, output)

    def test_same_control_path_rejected(self):
        self.assert_failure("unsafe-control-inputs", denylist=self.manifest)

    def test_blank_and_root_inputs_rejected(self):
        self.assert_failure("unsafe-input-path", tree=" ")
        self.assert_failure("unsafe-input-path", tree="INVALID_\x7f_PATH")
        self.assert_failure("unsafe-control-inputs", tree=os.sep)

    def test_missing_safe_filesystem_api_fails_closed(self):
        self.write()
        with patch.object(GATE.os, "supports_fd", set()):
            result, _ = self.assert_failure("unsupported-safe-filesystem-api")
        self.assertEqual(result["checked_files"], 0)

    def test_symlink_control_file_rejected(self):
        self.write()
        alias = self.base / "denylist-link.json"
        alias.symlink_to(self.denylist)
        result, _ = self.assert_failure("invalid-denylist", denylist=alias)
        self.assertEqual(result["checked_files"], 0)

    def test_symlink_control_parent_rejected(self):
        self.write()
        directory = self.base / "controls"
        directory.mkdir()
        control = directory / "denylist.json"
        control.write_text(json.dumps([INVALID_PRIVATE_VALUE]), encoding="utf-8")
        alias = self.base / "control-parent-link"
        alias.symlink_to(directory, target_is_directory=True)
        self.assert_failure("invalid-denylist", denylist=alias / "denylist.json")

    def test_symlink_candidate_root_rejected(self):
        self.write()
        alias = self.base / "candidate-link"
        alias.symlink_to(self.tree, target_is_directory=True)
        result, _ = self.assert_failure("symlink", tree=alias)
        self.assertEqual(result["checked_files"], 0)

    def test_symlink_candidate_parent_rejected(self):
        self.write()
        alias = self.base / "parent-link"
        alias.symlink_to(self.base, target_is_directory=True)
        self.assert_failure("symlink", tree=alias / "candidate")

    def test_symlink_parent_dotdot_inputs_rejected_before_normalization(self):
        self.write()
        other = self.base / "other"
        nested = other / "nested"
        nested.mkdir(parents=True)
        (other / "candidate").mkdir()
        (other / "candidate" / "README.md").write_text(
            INVALID_PRIVATE_VALUE, encoding="utf-8"
        )
        (other / "manifest.json").write_text(
            json.dumps(["INVALID_UNAPPROVED_FILE.txt"]), encoding="utf-8"
        )
        (other / "private-denylist.json").write_text(
            json.dumps(["Approved"]), encoding="utf-8"
        )
        alias = self.base / "symlink-parent"
        alias.symlink_to(nested, target_is_directory=True)
        for argument, leaf in [
            ("tree", "candidate"),
            ("manifest", "manifest.json"),
            ("denylist", "private-denylist.json"),
        ]:
            with self.subTest(argument=argument):
                code, result, output = self.run_gate(
                    **{argument: alias / ".." / leaf}
                )
                self.assertEqual(code, 2)
                self.assertEqual(result, {
                    "status": "FAIL", "checked_files": 0,
                    "findings": [{"class": "unsafe-input-path"}],
                })
                self.assertNotIn(INVALID_PRIVATE_VALUE, output)
                self.assertNotIn(str(self.base), output)

    def test_symlink_file_not_followed(self):
        outside = self.base / "outside.txt"
        outside.write_text(INVALID_PRIVATE_VALUE, encoding="utf-8")
        (self.tree / "README.md").symlink_to(outside)
        result, output = self.assert_failure("symlink")
        self.assertEqual(result["checked_files"], 0)
        self.assertNotIn("denylist-content-match", self.classes(result))
        self.assertNotIn(INVALID_PRIVATE_VALUE, output)

    def test_symlink_directory_not_followed(self):
        self.controls(["src/example.rs"])
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "example.rs").write_text(INVALID_PRIVATE_VALUE, encoding="utf-8")
        (self.tree / "src").symlink_to(outside, target_is_directory=True)
        result, _ = self.assert_failure("symlink")
        self.assertEqual(result["checked_files"], 0)
        self.assertNotIn("denylist-content-match", self.classes(result))

    def test_file_replaced_by_symlink_at_open_cannot_escape(self):
        candidate = self.write()
        outside = self.base / "outside.txt"
        outside.write_text(INVALID_PRIVATE_VALUE, encoding="utf-8")
        original_open = os.open
        changed = False

        def changing_open(name, flags, *args, **kwargs):
            nonlocal changed
            if name == "README.md" and not changed:
                candidate.unlink()
                candidate.symlink_to(outside)
                changed = True
            return original_open(name, flags, *args, **kwargs)

        with patch.object(GATE.os, "open", side_effect=changing_open):
            # Platform capability membership depends on the original function.
            with patch.object(GATE, "_require_platform"):
                result, _ = self.assert_failure("unreadable")
        self.assertTrue(changed)
        self.assertEqual(result["checked_files"], 0)
        self.assertNotIn("denylist-content-match", self.classes(result))

    def test_vcs_metadata_rejected_without_descent(self):
        self.write()
        self.write(".git/HEAD", INVALID_PRIVATE_VALUE)
        result, output = self.assert_failure("version-control-metadata")
        self.assertNotIn("denylist-content-match", self.classes(result))
        self.assertNotIn("HEAD", output)

    def test_nonregular_fifo_rejected_without_blocking(self):
        os.mkfifo(self.tree / "README.md")
        self.assert_failure("non-regular-file")

    def test_unreadable_text_rejected(self):
        candidate = self.write()
        candidate.chmod(0)
        try:
            result, _ = self.assert_failure("unreadable")
            self.assertEqual(result["checked_files"], 0)
        finally:
            candidate.chmod(0o600)

    def test_binary_and_unsupported_encodings_rejected(self):
        for value in [b"a\x00b", b"\xff", b"escape\x1b", "inert".encode("utf-16")]:
            with self.subTest(value=value):
                self.write(text=value)
                result, _ = self.assert_failure("binary-or-unsupported-text")
                self.assertEqual(result["checked_files"], 0)

    def test_oversize_text_rejected(self):
        self.write(text="123456789")
        with patch.object(GATE, "MAX_FILE_BYTES", 8):
            self.assert_failure("too-large")

    def test_growing_file_read_remains_bounded(self):
        candidate = self.write(text="tiny")
        inode = candidate.stat().st_ino
        original_read = os.read
        sizes = []
        changed = False

        def growing_read(fd, size):
            nonlocal changed
            if os.fstat(fd).st_ino == inode:
                sizes.append(size)
                if not changed:
                    with candidate.open("a", encoding="utf-8") as target:
                        target.write("INVALID_GROWTH_EXAMPLE")
                    changed = True
            return original_read(fd, size)

        with patch.object(GATE, "MAX_FILE_BYTES", 8), patch.object(GATE.os, "read", side_effect=growing_read):
            self.assert_failure("too-large")
        self.assertTrue(changed)
        self.assertLessEqual(sum(sizes), 9)

    def test_total_text_budget_rejected(self):
        self.controls(["README.md", "second.txt"])
        self.write(text="123456")
        self.write("second.txt", "123456")
        with patch.object(GATE, "MAX_TOTAL_BYTES", 10):
            self.assert_failure("too-large")

    def test_entry_budget_rejected(self):
        self.controls(["README.md", "second.txt"])
        self.write()
        self.write("second.txt")
        with patch.object(GATE, "MAX_TREE_ENTRIES", 1):
            self.assert_failure("tree-entry-limit")

    def test_hardlinked_control_file_rejected(self):
        os.link(self.denylist, self.tree / "README.md")
        result, output = self.assert_failure("control-file-in-tree")
        self.assertEqual(result["checked_files"], 0)
        self.assertNotIn(INVALID_PRIVATE_VALUE, output)

    def test_exact_string_match_is_case_sensitive_substring(self):
        self.write(text="before " + INVALID_PRIVATE_VALUE + " after")
        _, output = self.assert_failure("denylist-content-match")
        self.assertNotIn(INVALID_PRIVATE_VALUE, output)
        self.write(text=INVALID_PRIVATE_VALUE.lower())
        self.assertEqual(self.run_gate()[0], 0)

    def test_multiline_and_unicode_denylist_match_without_echo(self):
        denied = "INVALID_multiline_é\nexample"
        self.controls(denylist=[denied])
        self.write(text="before " + denied + " after")
        _, output = self.assert_failure("denylist-content-match")
        self.assertNotIn("INVALID_multiline", output)
        self.assertNotIn("example", output)

    def test_denied_filename_is_withheld_in_every_finding(self):
        self.write()
        self.write(INVALID_PRIVATE_VALUE + ".txt", "Inert example")
        result, output = self.assert_failure("denylist-path-match")
        self.assertIn("unlisted-file", self.classes(result))
        self.assertNotIn(INVALID_PRIVATE_VALUE, output)
        self.assertTrue(all("path" not in item for item in result["findings"]))
        self.assertNotIn("sha256", output)

    def test_missing_denied_manifest_path_is_withheld(self):
        self.controls([INVALID_PRIVATE_VALUE + ".txt"])
        _, output = self.assert_failure("missing-manifest-file")
        self.assertNotIn(INVALID_PRIVATE_VALUE, output)

    def test_private_key_forms_are_supplementary_to_denylist(self):
        for kind in ["", "RSA ", "EC ", "DSA ", "OPENSSH ", "ENCRYPTED "]:
            with self.subTest(kind=kind):
                header = "-----BEGIN " + kind + "PRIVATE KEY-----"
                self.write(text=header + "\nINVALID_NOT_A_KEY\n")
                _, output = self.assert_failure("private-key-form")
                self.assertNotIn(header, output)

    def test_private_pgp_block_is_rejected_without_echo(self):
        marker = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
        self.write(text=marker + "\nINVALID_NOT_A_KEY\n")
        _, output = self.assert_failure("private-key-form")
        self.assertNotIn(marker, output)

    def test_public_ipv4_rejected_and_not_printed(self):
        # A lexical fixture only: no network request is ever made.
        value = "8.8.8.8"
        self.write(text="endpoint = " + value)
        _, output = self.assert_failure("public-ipv4-form")
        self.assertNotIn(value, output)

    def test_reserved_and_private_ipv4_are_not_global_findings(self):
        self.write(text="127.0.0.1 192.0.2.1 198.51.100.2 203.0.113.3 10.0.0.1")
        self.assertEqual(self.run_gate()[0], 0)

    def test_nonreserved_domain_requires_external_exact_approval(self):
        self.write(text="https://documentation.python.org/fixture")
        _, output = self.assert_failure("unapproved-domain-form")
        self.assertNotIn("documentation.python.org", output)
        approved = self.base / "approved-domains.json"
        approved.write_text(json.dumps(["documentation.python.org"]), encoding="utf-8")
        result, code = GATE.check_tree(str(self.tree), str(self.manifest), str(self.denylist), str(approved))
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "PASS")

    def test_domain_approval_cannot_override_private_denylist(self):
        domain = "documentation.python.org"
        self.controls(denylist=[domain])
        self.write(text="https://" + domain)
        approved = self.base / "approved-domains.json"
        approved.write_text(json.dumps([domain]), encoding="utf-8")
        result, code = GATE.check_tree(str(self.tree), str(self.manifest), str(self.denylist), str(approved))
        self.assertEqual(code, 1)
        self.assertIn("denylist-content-match", self.classes(result))

    def test_domain_control_reuses_safe_external_file_contract(self):
        self.write()
        control = self.tree / "approved-domains.json"
        control.write_text('["documentation.python.org"]', encoding="utf-8")
        result, code = GATE.check_tree(str(self.tree), str(self.manifest), str(self.denylist), str(control))
        self.assertEqual(code, 2)
        self.assertIn("control-input-inside-tree", self.classes(result))

    def test_domain_control_rejects_globs_uppercase_and_missing_input(self):
        self.write()
        control = self.base / "approved-domains.json"
        for values in [[], ["*.python.org"], ["PYTHON.ORG"], ["python.org/path"]]:
            with self.subTest(values=values):
                control.write_text(json.dumps(values), encoding="utf-8")
                result, code = GATE.check_tree(str(self.tree), str(self.manifest), str(self.denylist), str(control))
                self.assertEqual(code, 2)
                self.assertIn("invalid-approved-domains", self.classes(result))
        control.unlink()
        result, code = GATE.check_tree(str(self.tree), str(self.manifest), str(self.denylist), str(control))
        self.assertEqual(code, 2)
        self.assertIn("invalid-approved-domains", self.classes(result))

    def test_domain_control_rejects_symlink(self):
        self.write()
        control = self.base / "approved-domains.json"
        control.write_text('["documentation.python.org"]', encoding="utf-8")
        alias = self.base / "approved-alias.json"
        alias.symlink_to(control)
        result, code = GATE.check_tree(str(self.tree), str(self.manifest), str(self.denylist), str(alias))
        self.assertEqual(code, 2)
        self.assertIn("invalid-approved-domains", self.classes(result))

    def test_oversized_malformed_domain_candidate_is_bounded(self):
        self.write(text="a." * 10000 + "!")
        self.assertEqual(self.run_gate()[0], 0)

    def test_every_diagnostic_path_is_opaque_not_a_hash(self):
        self.write()
        self.write("unreviewed-personal-identity.txt")
        result, output = self.assert_failure("unlisted-file")
        self.assertNotIn("unreviewed-personal-identity", output)
        self.assertNotIn("sha256", output)
        self.assertTrue(all("path" not in item for item in result["findings"]))

    def test_token_forms_are_supplementary_to_denylist(self):
        for token in ["ghp_" + "INVALID" * 4, "github_pat_" + "INVALID_" * 4, "AKIA" + "INVALID0" * 2, "xoxb-" + "INVALID-" * 4, "sk-" + "INVALID_" * 4]:
            with self.subTest(token=token):
                self.write(text=token)
                _, output = self.assert_failure("token-form")
                self.assertNotIn(token, output)

    def test_credential_url_forms_are_supplementary_to_denylist(self):
        for url in ["https://INVALID_USER:INVALID_PASSWORD@example.invalid/", "https://example.invalid/?token=INVALID_TOKEN", "https://example.invalid/?%61ccess_token=INVALID_TOKEN", "https://example.invalid/?X-Amz-Signature=INVALID_SIGNATURE"]:
            with self.subTest(url=url):
                self.write(text=url)
                _, output = self.assert_failure("credential-url-form")
                self.assertNotIn(url, output)

    def test_malformed_url_is_not_silently_admitted(self):
        self.write(text="https://[INVALID_EXAMPLE/")
        self.assert_failure("malformed-url-form")

    def test_token_filename_is_withheld_even_when_not_in_denylist(self):
        self.write()
        token = "ghp_" + "INVALID" * 4
        self.write(token, "Inert example")
        _, output = self.assert_failure("token-form")
        self.assertNotIn(token, output)

    def test_diagnostic_count_is_bounded_and_still_fails(self):
        self.write()
        for index in range(4):
            self.write("unknown-" + str(index))
        with patch.object(GATE, "MAX_FINDINGS", 2):
            result, _ = self.assert_failure("unlisted-file")
        self.assertEqual(len(result["findings"]), 2)
        self.assertEqual(result["omitted_findings"], 2)

    def test_omitted_findings_count_survives_an_early_verification_failure(self):
        self.write()
        self.write("unknown-one")
        self.write("unknown-two")
        with patch.object(GATE, "MAX_FINDINGS", 1), patch.object(GATE, "MAX_TREE_ENTRIES", 2):
            code, result, _ = self.run_gate()
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(len(result["findings"]), 1)
        self.assertGreaterEqual(result["omitted_findings"], 1)

    def test_cli_required_inputs_and_unrecognized_arguments_do_not_echo(self):
        for argv in [[], ["--tree", str(self.tree)], ["--INVALID_" + INVALID_PRIVATE_VALUE]]:
            with self.subTest(argv=argv):
                output = io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                    with self.assertRaises(SystemExit) as exit_value:
                        GATE.main(argv)
                self.assertEqual(exit_value.exception.code, 2)
                self.assertEqual(json.loads(output.getvalue())["findings"], [{"class": "invalid-cli"}])
                self.assertNotIn(INVALID_PRIVATE_VALUE, output.getvalue())


if __name__ == "__main__":
    unittest.main()
