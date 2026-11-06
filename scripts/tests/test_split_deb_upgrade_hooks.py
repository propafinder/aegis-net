"""Generated client package hooks bind the incoming protected file roster."""

import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
BUILDER = ROOT / "scripts/build-split-deb-packages.sh"


def function(source, name):
    start = re.search(r"^" + re.escape(name) + r"\(\) \{\n", source, re.MULTILINE)
    assert start is not None, name
    successor = {"write_client_removal_hook": "write_client_upgrade_roster",
                 "write_client_upgrade_roster": "write_client_preinst",
                 "write_client_preinst": "write_postinst",
                 "write_postinst": "write_prerm", "write_prerm": "write_postrm",
                 "write_postrm": "write_md5sums"}[name]
    finish = re.search(r"^" + re.escape(successor) + r"\(\) \{\n",
                       source[start.end():], re.MULTILINE)
    assert finish is not None, name
    body = source[start.start():start.end() + finish.start()]
    # Explanatory comments before the next shell function are not executable
    # generator source, including the removal hook's custody explanation.
    body = body[:body.rfind("\n}") + 2]
    assert body.rstrip().endswith("}")
    return body


def roster(source, name):
    match = re.search(r"^" + re.escape(name) + r"=\(\n(.*?)^\)", source,
                      re.MULTILINE | re.DOTALL)
    assert match is not None, name
    return re.findall(r'^\s+"([A-Za-z0-9_./@-]+)"$', match.group(1), re.MULTILINE)


def installer_retained_mode(name, source_mode):
    """Evaluate the installed retainer's actual closed mode assignments."""
    installer = (ROOT / 'install.sh').read_text()
    program = installer.split("<<'PY_AUTO_RETAIN_PAYLOAD'\n", 1)[1].split('\nPY_AUTO_RETAIN_PAYLOAD', 1)[0]
    nodes = list(ast.walk(ast.parse(program)))
    policy = [n for n in nodes if isinstance(n, ast.Assign) and any(
        isinstance(t, ast.Name) and t.id == 'policy_data' for t in n.targets)]
    mode = [n for n in nodes if isinstance(n, ast.Assign) and isinstance(n.value, ast.IfExp)
            and isinstance(n.value.test, ast.Name) and n.value.test.id == 'policy_data'
            and any(isinstance(t, ast.Name) and t.id == 'mode' for t in n.targets)]
    assert len(policy) == len(mode) == 1
    namespace = {'name': name, 'before': SimpleNamespace(st_mode=source_mode)}
    exec(compile(ast.Module(body=[policy[0], mode[0]], type_ignores=[]),
                 '<actual installer retention modes>', 'exec'), namespace)
    return namespace['mode']


class SplitDebUpgradeHooks(unittest.TestCase):
    def test_preinst_successor_anchors_are_closed_and_generation_checked(self):
        generated = function(BUILDER.read_text(), 'write_client_preinst')
        program = re.search(r"<<'PY'\n(.*?)\nPY", generated, re.DOTALL).group(1)
        tree = ast.parse(program)
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == 'main')
        keysets = [set(value.value for value in node.elts)
                   for node in ast.walk(main) if isinstance(node, ast.Set)
                   and all(isinstance(value, ast.Constant) and
                           isinstance(value.value, str) for value in node.elts)]
        successor = [keys for keys in keysets if 'prior_successor_intent_sha256' in keys]
        self.assertEqual(len(successor), 1)
        self.assertIn('next_bundle_manifest_sha256', successor[0])
        self.assertIn('next_sums_sha256', successor[0])
        calls = [node for node in ast.walk(main) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == 'anchored_digest']
        self.assertEqual(len(calls), 2)
        self.assertEqual({ast.unparse(call.args[0]) for call in calls},
                         {"root + '/bundle.manifest.json'", "root + '/SHA256SUMS'"})

    def test_preinst_held_anchor_refuses_replacement_during_read(self):
        generated = function(BUILDER.read_text(), 'write_client_preinst')
        program = re.search(r"<<'PY'\n(.*?)\nPY", generated, re.DOTALL).group(1)
        tree = ast.parse(program)
        selected = ast.Module(body=[node for node in tree.body
                                    if isinstance(node, ast.FunctionDef)
                                    and node.name in ('need','digest','anchored_digest')],
                              type_ignores=[])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'SHA256SUMS'
            path.write_bytes(b'pinned\n')
            namespace = {'os': os, 'hashlib': hashlib, 'stat': stat,
                         'held': lambda name, mode: os.open(name, os.O_RDONLY)}
            exec(compile(selected, '<actual generated client preinst>', 'exec'), namespace)
            self.assertEqual(namespace['anchored_digest'](str(path)),
                             hashlib.sha256(b'pinned\n').hexdigest())
            original = namespace['digest']
            def replace(fd):
                result = original(fd)
                replacement = path.with_name('replacement')
                replacement.write_bytes(b'other\n')
                os.replace(replacement, path)
                return result
            namespace['digest'] = replace
            with self.assertRaises(ValueError):
                namespace['anchored_digest'](str(path))
            namespace['digest'] = original
            with path.open('wb') as large:
                large.truncate(4 * 1024 * 1024 + 1)
            with self.assertRaises(ValueError):
                namespace['anchored_digest'](str(path))

    def test_archive_exec_bits_follow_the_actual_installer_retention_rule(self):
        generated = function(BUILDER.read_text(), 'write_client_upgrade_roster')
        program = re.search(r"<<'PY'\n(.*?)\nPY", generated, re.DOTALL).group(1)
        nodes = list(ast.walk(ast.parse(program)))
        policy = [n for n in nodes if isinstance(n, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == 'policy_data' for t in n.targets)]
        record = [n for n in nodes if isinstance(n, ast.Assign) and any(
            isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name)
            and t.value.id == 'manifest' for t in n.targets)]
        self.assertLessEqual(len(policy), 1); self.assertEqual(len(record), 1)
        body = ast.Module(body=policy + record, type_ignores=[])
        for name in ('scripts/lib/aegis_installer_auto_v2.py',
                     'scripts/lib/aegis_initrd_policy.py',
                     'scripts/lib/aegis_auto_ufw_pins.json', 'scripts/lib/root-state.sh'):
            relative = 'usr/local/lib/aegis/helpers/' + name.removeprefix('scripts/')
            for source_mode in (0o755, 0o555, 0o644):
                with self.subTest(name=name, source_mode=oct(source_mode)):
                    namespace = {'relative': relative, 'manifest': {}, 'hashlib': hashlib, 'stat': stat,
                        'file': SimpleNamespace(read_bytes=lambda: b'pinned bytes',
                            stat=lambda: SimpleNamespace(st_mode=stat.S_IFREG | 0o500)),
                        'original': SimpleNamespace(stat=lambda: SimpleNamespace(
                            st_mode=stat.S_IFREG | source_mode))}
                    exec(compile(body, '<actual generated roster expressions>', 'exec'), namespace)
                    self.assertEqual(namespace['manifest'][relative]['retained_mode'],
                                     installer_retained_mode(name, stat.S_IFREG | source_mode))

    def test_abort_journal_blocks_preinst_even_after_control_is_archived(self):
        generated = function(BUILDER.read_text(), "write_client_preinst")
        body = re.search(r"<<'PY'\n(.*?)\nPY", generated, re.DOTALL).group(1)
        tree = ast.parse(body)
        selected = ast.Module(body=[node for node in tree.body
                                    if isinstance(node, ast.FunctionDef)
                                    and node.name in ("need", "main")], type_ignores=[])
        with tempfile.TemporaryDirectory() as temporary:
            pending = Path(temporary) / "pending"
            uninstall = Path(temporary) / "uninstall"
            def exists(path):
                if path in (
                    "/var/lib/aegis-install/client/terminal-migrations/cold-recovery/intent.json",
                    "/var/lib/aegis-install/client/terminal-migrations/cold-recovery/transition-ready.json",
                ):
                    return False
                self.assertIn(path, (
                    "/var/lib/aegis-auto/fresh-passive-abort-current.json",
                    "/var/lib/aegis-auto-uninstall"))
                return os.path.lexists(pending if path.endswith(".json") else uninstall)
            # Execute the actual generated main; an absent CONTROL must never
            # bypass a pending journal, including a broken link or wrong type.
            control = mock.Mock(return_value=False)
            namespace = {"os": SimpleNamespace(geteuid=lambda: 0,
                                               path=SimpleNamespace(lexists=exists)),
                         "sys": SimpleNamespace(platform="linux"),
                         "control_present": control,
                         "cold_current_head": lambda: None}
            exec(compile(selected, "<generated client preinst>", "exec"), namespace)
            namespace["main"]()
            control.assert_called_once_with()
            control.reset_mock()
            for kind in ("regular", "broken-link", "directory"):
                if kind == "regular":
                    pending.write_bytes(b"unsealed journal")
                elif kind == "broken-link":
                    pending.symlink_to(Path(temporary) / "missing")
                else:
                    pending.mkdir()
                with self.subTest(kind=kind), self.assertRaises(ValueError):
                    namespace["main"]()
                control.assert_not_called()
                pending.rmdir() if pending.is_dir() else pending.unlink()
            uninstall.mkdir()
            with self.assertRaises(ValueError):
                namespace["main"]()
            control.assert_not_called()

    def test_abort_cli_rejects_source_checkout_before_cargo_or_effects(self):
        for role, arguments in (("client", []), ("server", []),
                                ("client", ["--force"])):
            result = subprocess.run(["bash", str(ROOT / "install.sh"), role,
                                     "--abort-fresh-passive", *arguments],
                                    cwd=ROOT, capture_output=True, timeout=5,
                                    env={"PATH": "/usr/bin:/bin", "AEGIS_NO_BANNER": "1"})
            self.assertEqual(result.returncode, 2, result.stderr.decode()[:1000])
            self.assertIn(b"requires Linux root and an administrative release bundle", result.stderr)

    def test_release_inventory_accepts_revisioned_split_pair_and_rejects_mismatch(self):
        source = ROOT / "scripts/verify-release-deb-inventory.py"
        spec = importlib.util.spec_from_file_location("release_deb_revision_test", source)
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        digest = lambda data: hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source_sha, upstream, split_version = "a" * 40, "0.3.50", "0.3.50-2"
            manifests = {}
            for arch, deb_arch, suffix in (("x86_64", "amd64", ""),
                                           ("aarch64", "arm64", "-aarch64")):
                marker = f"split-deb-packages{suffix}.manifest.json"
                marker_bytes = b"{}\n"
                (base / marker).write_bytes(marker_bytes)
                records = {}
                for role in ("server", "client", "combined"):
                    package = "aegis" if role == "combined" else f"aegis-{role}"
                    package_version = upstream if role == "combined" else split_version
                    name = f"{package}_{package_version}_{deb_arch}.deb"
                    body = f"isolated {name}".encode()
                    (base / name).write_bytes(body)
                    (base / f"{name}.sha256").write_text(f"{digest(body)}  {name}\n")
                    records[role] = {"path": name, "sha256_path": f"{name}.sha256",
                                     "sha256": digest(body)}
                manifest_name = f"release.manifest{suffix}.json"
                manifests[manifest_name] = {"schema": "aegis_linux_release_manifest_v1",
                                            "git_sha": source_sha, "arch": arch,
                                            "version": upstream,
                                            "artifacts": {"deb": {
                                                "status": "ready", "split_version": split_version,
                                                "manifest_path": marker,
                                                "manifest_sha256": digest(marker_bytes),
                                                "split": {key: records[key] for key in ("server", "client")},
                                                "combined": records["combined"]}}}
            indexed = {path.name: digest(path.read_bytes()) for path in base.iterdir()}
            index_bytes = (json.dumps({"schema": "aegis_operator_payload_index_v1",
                                       "source_sha": source_sha, "version": upstream,
                                       "files": indexed}, sort_keys=True, indent=2) + "\n").encode()
            (base / verifier.INDEX_NAME).write_bytes(index_bytes)
            for name, manifest in manifests.items():
                manifest["artifacts"]["delivery_inventory"] = {
                    "path": verifier.INDEX_NAME, "sha256": digest(index_bytes)}
                (base / name).write_text(json.dumps(manifest))
            with mock.patch.object(verifier.subprocess, "run",
                                   return_value=mock.Mock(returncode=0, stderr="")) as runner:
                verifier.verify(base, source_sha, base / "split-checker", base / "owner-checker",
                                time.monotonic() + 30)
                split_calls = [call.args[0] for call in runner.call_args_list
                               if "--release-manifest" in call.args[0]]
                self.assertEqual(len(split_calls), 2)
                self.assertTrue(all(call[call.index("--version") + 1] == split_version
                                    for call in split_calls))
                mismatched = manifests["release.manifest-aarch64.json"]
                mismatched["artifacts"]["deb"]["split_version"] = "0.3.50-3"
                (base / "release.manifest-aarch64.json").write_text(json.dumps(mismatched))
                with self.assertRaises(verifier.Refused):
                    verifier.verify(base, source_sha, base / "split-checker", base / "owner-checker",
                                    time.monotonic() + 30)

    def test_revisioned_pair_is_bound_to_upstream_release_manifest(self):
        source = ROOT / "scripts/verify-split-deb-package-set.py"
        spec = importlib.util.spec_from_file_location("split_deb_revision_test", source)
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            version, arch = "0.3.50-2", "arm64"
            packages, release_pair = {}, {}
            for role in ("server", "client"):
                name = f"aegis-{role}_{version}_{arch}.deb"
                body = f"isolated {role} archive boundary".encode()
                digest = hashlib.sha256(body).hexdigest()
                (base / name).write_bytes(body)
                (base / f"{name}.sha256").write_text(f"{digest}  {name}\n")
                packages[f"aegis-{role}"] = {"deb_file": name}
                release_pair[role] = {"path": name, "sha256_path": f"{name}.sha256",
                                      "sha256": digest}
            (base / "split-deb-packages.manifest.json").write_text(json.dumps({
                "version": version, "deb_arch": arch, "packages": packages}))
            manifest = base / "release.manifest.json"
            release = {"schema": "aegis_linux_release_manifest_v1",
                       "version": "0.3.50", "arch": "aarch64", "git_sha": "a" * 40,
                       "artifacts": {"deb": {"status": "ready",
                                               "split_version": version,
                                               "manifest_path": "split-deb-packages.manifest.json",
                                               "split": release_pair}}}
            manifest.write_text(json.dumps(release))
            with mock.patch.object(verifier.subprocess, "run",
                                   return_value=mock.Mock(returncode=0, stderr="")):
                verifier.verify(base, arch, version, manifest, "a" * 40)
                release["artifacts"]["deb"]["split_version"] = "0.3.50-3"
                manifest.write_text(json.dumps(release))
                with self.assertRaises(verifier.Refused):
                    verifier.verify(base, arch, version, manifest, "a" * 40)

    def test_auto_units_upgrade_as_protected_payload_while_admin_env_stays_conffile(self):
        source = BUILDER.read_text()
        match = re.search(r'cat > "\$\{debian_dir\}/conffiles" <<\'EOF\'\n'
                          r'(/etc/default/aegis-client\n.*?)EOF', source, re.DOTALL)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1).splitlines(), ["/etc/default/aegis-client"])
        units = roster(source, "CLIENT_AUTO_UNIT_PATHS")
        self.assertEqual(len(units), 16)
        self.assertIn("etc/systemd/system/aegis-auto-terminal-a@.service", units)
        self.assertIn("etc/systemd/system/aegis-auto-terminal-b@.service", units)
        self.assertIn("etc/systemd/system/aegis-auto-clean-shutdown.service", units)
        self.assertIn("etc/systemd/system/aegis-device-dhcp-refresh.service", units)
        self.assertIn("etc/systemd/system/aegis-device-dhcp-refresh.timer", units)
        self.assertIn("old_root + '/packaging/systemd/' + name", source)
        self.assertIn("need(digest(prior) == digest(installed))", source)
        coordinator = (ROOT / "scripts/lib/aegis_installer_auto_v2.py").read_text()
        self.assertIn('"/usr/bin/dpkg", "--force-confold", "--install"', coordinator)

    def test_delivery_seals_the_built_client_deb_and_boot_unit(self):
        delivery = (ROOT / "scripts/build-release-delivery.sh").read_text()
        bundle = (ROOT / "scripts/build-release-bundle.sh").read_text()
        self.assertLess(delivery.index('"${ROOT}/scripts/build-split-deb-packages.sh"'),
                        delivery.index('"${ROOT}/scripts/build-release-bundle.sh"'))
        self.assertIn('--client-deb "${OUTPUT_DIR}/aegis-client_', delivery)
        self.assertIn('--split-deb-manifest "${OUTPUT_DIR}/split-deb-packages.manifest.json"',
                      delivery)
        self.assertIn('for original in (deb,sidecar,marker):', bundle)
        self.assertIn('"etc/systemd/system/aegis-auto-config.service"', BUILDER.read_text())

    def test_generated_hooks_bind_all_exact_incoming_assets(self):
        source = BUILDER.read_text()
        helpers = roster(source, "CLIENT_PROTECTED_HELPER_PATHS")
        units = roster(source, "CLIENT_AUTO_UNIT_PATHS")
        expected = ["usr/local/bin/aegis-client", *helpers, *units]
        self.assertEqual(len(expected), len(set(expected)))
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            staged, debian = base / "stage", base / "DEBIAN"
            staged.mkdir()
            debian.mkdir()
            for relative in expected:
                if relative == "usr/local/bin/aegis-client":
                    # Only the generated hook contract is under test; a real
                    # package build later binds its actual ELF bytes.
                    content, mode = b"actual incoming ELF fixture", 0o555
                elif relative.startswith("usr/local/lib/aegis/helpers/"):
                    name = relative.removeprefix("usr/local/lib/aegis/helpers/")
                    if name == "lib/aegis-auto-terminal-hook":
                        content = (ROOT / "packaging/systemd/system-shutdown/aegis-auto-terminal-hook").read_bytes()
                    else:
                        content = (ROOT / "scripts" / name).read_bytes()
                    mode = 0o500 if name.startswith("lib/aegis_auto_") or name in ("lib/aegis_installer_auto_v2.py", "lib/aegis_initrd_policy.py", "lib/aegis_initrd_classic.py", "lib/aegis-auto-terminal-hook") else 0o755
                else:
                    name = relative.removeprefix("etc/systemd/system/")
                    content = (ROOT / "packaging/systemd" / name).read_bytes()
                    mode = 0o644
                path = staged / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
                path.chmod(mode)
            script = "\n".join(function(source, name) for name in
                               ("write_client_removal_hook", "write_client_preinst", "write_postinst",
                                "write_prerm", "write_postrm",
                                "write_client_upgrade_roster"))
            command = (script + "\nwrite_client_preinst " + shlex.quote(str(debian / "preinst")) +
                       "\nwrite_postinst " + shlex.quote(str(debian / "postinst")) +
                       " aegis-client\nwrite_prerm " + shlex.quote(str(debian / "prerm")) +
                       " aegis-client\nwrite_postrm " + shlex.quote(str(debian / "postrm")) +
                       " aegis-client\nwrite_client_upgrade_roster " +
                       shlex.quote(str(staged)) + " " + shlex.quote(str(debian)) + "\n")
            generated = subprocess.run(["bash", "-eu", "-c", command], cwd=ROOT,
                                       capture_output=True, timeout=10,
                                       env={"PATH": "/usr/bin:/bin", "ROOT": str(ROOT), "VERSION": "0.3.50-100"})
            self.assertEqual(generated.returncode, 0, generated.stderr.decode()[:1000])
            preinst = (debian / "preinst").read_text()
            postinst = (debian / "postinst").read_text()
            compile(preinst, str(debian / "preinst"), "exec")
            subprocess.run(["bash", "-n", str(debian / "postinst")],
                           check=True, capture_output=True, timeout=5)
            self.assertEqual(stat.S_IMODE((debian / "preinst").stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE((debian / "postinst").stat().st_mode), 0o755)
            embedded = []
            for body in (preinst, postinst):
                encoded = re.search(r"json\.loads\((['\"].*['\"])\)", body)
                self.assertIsNotNone(encoded)
                embedded.append(json.loads(ast.literal_eval(encoded.group(1))))
            self.assertEqual(embedded[0], embedded[1])
            for hook in ("prerm", "postrm"):
                body = (debian / hook).read_text()
                compile(body, str(debian / hook), "exec")
                encoded = re.search(r"json\.loads\((['\"].*['\"])\)", body)
                removal = json.loads(ast.literal_eval(encoded.group(1)))
                self.assertEqual(removal, {**embedded[0], "package_version": "0.3.50-100"})
                self.assertIn("source_bytes", body)
            self.assertEqual(set(embedded[0]["files"]), set(expected))
            self.assertEqual(embedded[0]["install_sha256"],
                             hashlib.sha256((ROOT / "install.sh").read_bytes()).hexdigest())
            for relative, record in embedded[0]["files"].items():
                path = staged / relative
                if relative == "usr/local/bin/aegis-client":
                    original = path
                elif relative == "usr/local/lib/aegis/helpers/lib/aegis-auto-terminal-hook":
                    original = ROOT / "packaging/systemd/system-shutdown/aegis-auto-terminal-hook"
                elif relative.startswith("usr/local/lib/aegis/helpers/"):
                    original = ROOT / "scripts" / relative.removeprefix("usr/local/lib/aegis/helpers/")
                else:
                    original = ROOT / "packaging/systemd" / relative.removeprefix("etc/systemd/system/")
                self.assertEqual(record, {
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "mode": stat.S_IMODE(path.stat().st_mode),
                    "retained_mode": installer_retained_mode(
                        'bin/aegis-client' if relative == 'usr/local/bin/aegis-client'
                        else str(original.relative_to(ROOT)), original.stat().st_mode)})
            self.assertIn("verify-retired-successor", preinst)
            self.assertIn("verify-retired-passive-successor", preinst)
            self.assertIn("b'passive-package-preinst.json', 1", preinst)
            self.assertIn("rename = libc.renameat2", preinst)
            self.assertIn("pass_fds=(9, 10)", preinst)
            self.assertIn("/run/aegis-auto-install.lock", preinst)
            self.assertIn("/var/lib/aegis-install/client/device-guard.conf.lock", preinst)
            self.assertIn("PY_AUTO_PACKAGE_READBACK", postinst)


if __name__ == "__main__":
    unittest.main()
