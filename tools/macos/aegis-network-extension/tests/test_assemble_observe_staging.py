"""Unsigned layout contract plus S09 packaging-pipeline refusals.

Mock Mach-O headers and decoded-profile fixtures are not executable or
signing proof; real signing is exercised only by build-sign-notarize.sh.
"""
import datetime
import hashlib
import ipaddress
import json
import os
import pathlib
import plistlib
import re
import shlex
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from shutil import which as shutil_which


PACKAGE = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = PACKAGE / "assemble-unsigned.py"
PIPELINE = PACKAGE / "packaging" / "pipeline.py"
PIPELINE_SH = PACKAGE / "packaging" / "build-sign-notarize.sh"
INSTALL_SH = PACKAGE / "packaging" / "install-app.sh"
UNINSTALL_SH = PACKAGE / "packaging" / "uninstall-app.sh"
TEAM = "TEAMID0000"
APP = "dev.aegis.macos"
PROVIDER = APP + ".PacketTunnel"
HELPER = APP + ".ObserveHelper"
CHILD = APP + ".ObserveChild"
GROUP = "group." + TEAM + ".dev.aegis.macos"


class AssemblerFixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-r76-layout-")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.inputs = []
        for index in range(4):
            path = self.root / f"mock-{index}"
            path.write_bytes(b"\xcf\xfa\xed\xfe" + bytes([index]) * 16)
            self.inputs.append(path)

    def command(self, output, *, staged=True, team=TEAM, helper=None, child=None):
        command = [sys.executable, str(SCRIPT), "--output", str(output),
                   "--host-binary", str(self.inputs[0]),
                   "--provider-binary", str(self.inputs[1]),
                   "--app-id", APP, "--provider-id", PROVIDER,
                   "--app-group", GROUP, "--team-id", team]
        if staged:
            command += ["--helper-binary", str(helper or self.inputs[2]),
                        "--child-binary", str(child or self.inputs[3])]
        return command

    def run_assembler(self, output, **kwargs):
        return subprocess.run(self.command(output, **kwargs),
                              check=False, capture_output=True, text=True)


class ObserveStagingTests(AssemblerFixture, unittest.TestCase):
    def test_exact_unsigned_layout_profiles_absent_and_deterministic_bytes(self):
        outputs = [self.root / "out-one", self.root / "out-two"]
        for output in outputs:
            result = self.run_assembler(output)
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((output / "assembly.json").read_text())
            self.assertEqual(manifest["inputs_sha256"],
                             [hashlib.sha256(path.read_bytes()).hexdigest()
                              for path in self.inputs])
            packaged = [
                output / "AEGIS.app/Contents/MacOS/aegis-ne-host",
                output / f"AEGIS.app/Contents/Library/SystemExtensions/{PROVIDER}.systemextension/Contents/MacOS/aegis-ne-provider",
                output / f"AEGIS.app/Contents/Library/Helpers/{HELPER}.app/Contents/MacOS/aegis-ne-observe-helper",
                output / f"AEGIS.app/Contents/Library/Helpers/{CHILD}.app/Contents/MacOS/aegis-ne-observe-child",
            ]
            self.assertEqual([hashlib.sha256(path.read_bytes()).hexdigest()
                              for path in packaged], manifest["inputs_sha256"])
            for flag in ("signed", "installed", "native_acceptance",
                         "runtime_observed", "profiles_included",
                         "xpc_service_registered", "child_ready"):
                self.assertFalse(manifest[flag])
            # The assembler cannot observe factory registration in the
            # provider bytes, so it makes no claim about it.
            self.assertNotIn("factory_registered", manifest)
            self.assertTrue(manifest["helper_child_staged"])
            profile_map = json.loads((output / "profiles-expected.json").read_text())
            self.assertEqual(set(profile_map["expected_embedded_paths"]),
                             {APP, PROVIDER, HELPER, CHILD})
            for relative in profile_map["expected_embedded_paths"].values():
                self.assertFalse((output / relative).exists())
            for ident, entitlement_file, binary_name in (
                (HELPER, "helper.entitlements", "aegis-ne-observe-helper"),
                (CHILD, "child.entitlements", "aegis-ne-observe-child"),
            ):
                bundle = output / "AEGIS.app/Contents/Library/Helpers" / f"{ident}.app"
                info = plistlib.loads((bundle / "Contents/Info.plist").read_bytes())
                self.assertEqual(info["CFBundleIdentifier"], ident)
                self.assertEqual(info["CFBundleExecutable"], binary_name)
                entitlements = plistlib.loads((output / entitlement_file).read_bytes())
                self.assertEqual(entitlements["com.apple.application-identifier"], TEAM + "." + ident)
                self.assertEqual(entitlements["com.apple.security.application-groups"], [GROUP])
                self.assertNotIn("com.apple.developer.networking.networkextension", entitlements)
                self.assertFalse((bundle / "Contents/embedded.provisionprofile").exists())
        for relative in ("assembly.json", "profiles-expected.json",
                         "helper.entitlements", "child.entitlements"):
            self.assertEqual((outputs[0] / relative).read_bytes(),
                             (outputs[1] / relative).read_bytes())

    def test_missing_pair_wrong_team_and_symlink_leave_no_output(self):
        missing = self.root / "missing"
        command = self.command(missing, staged=False) + [
            "--helper-binary", str(self.inputs[2])]
        self.assertNotEqual(subprocess.run(command, check=False, capture_output=True).returncode, 0)
        self.assertFalse(missing.exists())
        wrong = self.root / "wrong"
        self.assertNotEqual(self.run_assembler(wrong, team="ABCDEFGHIJ").returncode, 0)
        self.assertFalse(wrong.exists())
        link = self.root / "linked-helper"
        link.symlink_to(self.inputs[2])
        linked = self.root / "linked"
        self.assertNotEqual(self.run_assembler(linked, helper=link).returncode, 0)
        self.assertFalse(linked.exists())

    def test_legacy_two_binary_layout_stays_available(self):
        output = self.root / "legacy"
        self.assertEqual(self.run_assembler(output, staged=False).returncode, 0)
        self.assertFalse((output / "profiles-expected.json").exists())
        self.assertFalse((output / "AEGIS.app/Contents/Library/Helpers").exists())
        manifest = json.loads((output / "assembly.json").read_text())
        self.assertEqual(len(manifest["inputs_sha256"]), 2)
        self.assertNotIn("helper_child_staged", manifest)
        # S20b: the review entitlements name the filter beside the tunnel.
        for name in ("host.entitlements", "provider.entitlements"):
            review = plistlib.loads((output / name).read_bytes())
            self.assertEqual(review["com.apple.developer.networking.networkextension"],
                             NE_VALUES, name)


def pipeline(*args):
    return subprocess.run([sys.executable, "-I", "-B", str(PIPELINE), *map(str, args)],
                          check=False, capture_output=True, text=True)


def isolated_env(root):
    """Test ledger and installed-app overrides; never the owner's real ledger."""
    env = dict(os.environ)
    env["AEGIS_PACKAGING_LEDGER"] = str(pathlib.Path(root) / "ledger")
    env["AEGIS_INSTALLED_APP"] = str(pathlib.Path(root) / "Applications" / "AEGIS.app")
    for key in ("AEGIS_SIGN_IDENTITY", "AEGIS_PACKAGING_ARTIFACTS", "AEGIS_CAPTURE_WINDOW"):
        env.pop(key, None)
    return env


def run_script(root, *args, script=PIPELINE_SH):
    return subprocess.run(["/bin/bash", str(script), *map(str, args)], check=False,
                          capture_output=True, text=True, env=isolated_env(root))


def sha256_file(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


# S20b: both roles carry both NetworkExtension values, in this order.
NE_VALUES = ["content-filter-provider-systemextension", "packet-tunnel-provider-systemextension"]


def committed(role):
    return plistlib.loads((PACKAGE / "packaging" / "entitlements" /
                           f"{role}.entitlements").read_bytes())


class ProductAssemblyTests(AssemblerFixture, unittest.TestCase):
    def product(self, output, *extra, version="7", short="0.2.0"):
        command = self.command(output, staged=False) + ["--product"]
        if version:
            command += ["--bundle-version", version]
        if short:
            command += ["--short-version", short]
        return subprocess.run(command + list(extra), check=False,
                              capture_output=True, text=True)

    def test_product_mode_two_roles_explicit_version(self):
        output = self.root / "product"
        result = self.product(output)
        self.assertEqual(result.returncode, 0, result.stderr)
        app = output / "AEGIS.app"
        ext = app / f"Contents/Library/SystemExtensions/{PROVIDER}.systemextension"
        for bundle, ident in ((app, APP), (ext, PROVIDER)):
            info = plistlib.loads((bundle / "Contents/Info.plist").read_bytes())
            self.assertEqual(info["CFBundleIdentifier"], ident)
            self.assertEqual(info["CFBundleVersion"], "7")
            self.assertEqual(info["CFBundleShortVersionString"], "0.2.0")
        # sysextd's network_extension category check refuses the extension
        # without a usage description (OSSystemExtensionError 9 on v6).
        ext_info = plistlib.loads((ext / "Contents/Info.plist").read_bytes())
        self.assertTrue(ext_info["NSSystemExtensionUsageDescription"].strip())
        self.assertEqual(ext_info["CFBundlePackageType"], "SYSX")
        # S20b: the packet filter is served by the same system extension.
        self.assertEqual(
            ext_info["NetworkExtension"]["NEProviderClasses"],
            {"com.apple.networkextension.packet-tunnel": "AegisPacketTunnelProvider",
             "com.apple.networkextension.filter-packet": "AegisFilterPacketProvider"},
        )
        self.assertIn("stop traffic from leaving outside it",
                      ext_info["NSSystemExtensionUsageDescription"])
        # v39: the app is a menu-bar (agent) app; the extension is not.
        app_info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
        self.assertIs(app_info["LSUIElement"], True)
        self.assertNotIn("LSUIElement", ext_info)
        # v45: English base, Russian declared for macOS's own panels.
        self.assertEqual(app_info["CFBundleDevelopmentRegion"], "en")
        self.assertEqual(app_info["CFBundleLocalizations"], ["en", "ru"])
        self.assertNotIn("CFBundleLocalizations", ext_info)
        self.assertFalse((app / "Contents/Library/Helpers").exists())
        for name in ("host.entitlements", "provider.entitlements",
                     "profiles-expected.json"):
            self.assertFalse((output / name).exists())
        manifest = json.loads((output / "assembly.json").read_text())
        self.assertTrue(manifest["product_mode"])
        self.assertEqual(manifest["roles"], [APP, PROVIDER])
        self.assertEqual(manifest["bundle_version"], "7")
        self.assertFalse(manifest["signed"])
        self.assertEqual(len(manifest["inputs_sha256"]), 2)

    def test_product_mode_refusals_leave_no_output(self):
        helper = ("--helper-binary", str(self.inputs[2]),
                  "--child-binary", str(self.inputs[3]))
        cases = {  # name: (extra arguments, CFBundleVersion, short version)
            "diagnostic helper/child": (helper, "7", "0.2.0"),
            "missing version": ((), None, "0.2.0"),
            "missing short version": ((), "7", None),
            "four components": ((), "1.2.3.4", "0.2.0"),
            "zero": ((), "0", "0.2.0"),
            "leading zero": ((), "07", "0.2.0"),
        }
        for name, (extra, version, short) in cases.items():
            output = self.root / ("refused-" + name.replace(" ", "-").replace("/", "-"))
            result = self.product(output, *extra, version=version, short=short)
            self.assertNotEqual(result.returncode, 0, name)
            self.assertFalse(output.exists(), name)
        wrong = self.root / "refused-team"
        command = self.command(wrong, staged=False, team="ABCDEFGHIJ")
        command = [c.replace(TEAM, "ABCDEFGHIJ") if c == GROUP else c for c in command]
        result = subprocess.run(command + ["--product", "--bundle-version", "7",
                                           "--short-version", "0.2.0"],
                                check=False, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(wrong.exists())


class VersionMustIncreaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-s09-version-")
        self.addCleanup(self.temp.cleanup)
        self.receipts = pathlib.Path(self.temp.name) / "receipts"

    def check(self, version):
        return pipeline("check-version", "--receipts-dir", self.receipts,
                        "--version", version)

    def test_historical_baseline_without_receipts(self):
        self.assertNotEqual(self.check("1").returncode, 0)
        self.assertNotEqual(self.check("1.0").returncode, 0)
        self.assertEqual(self.check("2").returncode, 0)
        self.assertEqual(self.check("1.0.1").returncode, 0)

    def test_version_must_exceed_every_receipt_including_failed(self):
        self.receipts.mkdir()
        (self.receipts / "v5-a.json").write_text(json.dumps(
            {"bundle_version": "5", "stages": [{"stage": "sign", "status": "failed"}]}))
        (self.receipts / "v3-b.json").write_text(json.dumps({"bundle_version": "3"}))
        for refused in ("5", "5.0", "5.0.0", "4.9", "3", "1"):
            result = self.check(refused)
            self.assertNotEqual(result.returncode, 0, refused)
            self.assertIn("not greater than 5", result.stderr)
        for accepted in ("5.0.1", "5.1", "6", "10"):
            self.assertEqual(self.check(accepted).returncode, 0, accepted)

    def test_invalid_versions_and_corrupt_receipts_fail_closed(self):
        for invalid in ("02", "1.2.3.4", "a", "", "1..2", "-3"):
            self.assertNotEqual(self.check(invalid).returncode, 0, invalid)
        self.receipts.mkdir()
        (self.receipts / "broken.json").write_text("{")
        self.assertNotEqual(self.check("99").returncode, 0)
        (self.receipts / "broken.json").write_text(json.dumps({"bundle_version": "x"}))
        self.assertNotEqual(self.check("99").returncode, 0)

    def test_pipeline_script_refuses_before_creating_a_run(self):
        root = pathlib.Path(self.temp.name)
        artifacts = root / "artifacts"
        (artifacts / "receipts").mkdir(parents=True)
        (artifacts / "receipts" / "v4-old.json").write_text(json.dumps({"bundle_version": "4"}))
        binaries = []
        for index in range(2):
            path = root / f"bin-{index}"
            path.write_bytes(b"\xcf\xfa\xed\xfe" + bytes([index]) * 16)
            binaries.append(path)
        command = ["/bin/bash", str(PIPELINE_SH), "--stages", "assemble", "--version", "4",
                   "--artifacts-dir", str(artifacts),
                   "--host-profile", str(root / "host.provisionprofile"),
                   "--provider-profile", str(root / "provider.provisionprofile"),
                   "--host-binary", str(binaries[0]), "--provider-binary", str(binaries[1])]
        env = isolated_env(root)
        result = subprocess.run(command, check=False, capture_output=True, text=True, env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not greater than 4", result.stderr)
        self.assertFalse((artifacts / "runs").exists())
        self.assertEqual(sorted(p.name for p in (artifacts / "receipts").iterdir()),
                         ["v4-old.json"])
        dry = subprocess.run(command[:3] + ["build", "--dry-run", "--artifacts-dir",
                                             str(artifacts)],
                             check=False, capture_output=True, text=True, env=env)
        self.assertEqual(dry.returncode, 0, dry.stderr)
        self.assertIn("nice -n 10 rustup run 1.97.1 cargo build --locked --release -j 4", dry.stdout)
        self.assertIn("--bin aegis-ne-host --bin aegis-ne-provider", dry.stdout)
        self.assertNotIn("observe", dry.stdout)
        self.assertIn("--target-dir " + str(PACKAGE / "target"), dry.stdout)
        self.assertIn("env -u CARGO_TARGET_DIR", dry.stdout)
        both = subprocess.run(command[:3] + ["build,assemble"] + command[4:],
                              check=False, capture_output=True, text=True, env=env)
        self.assertNotEqual(both.returncode, 0)
        self.assertIn("mutually exclusive", both.stderr)


class EntitlementDiffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-s09-entitlements-")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)

    def profile(self, role, **changes):
        ident = APP if role == "host" else PROVIDER
        entitlements = {
            "com.apple.application-identifier": TEAM + "." + ident,
            "com.apple.developer.team-identifier": TEAM,
            "com.apple.developer.networking.networkextension": [
                "packet-tunnel-provider-systemextension",
                "content-filter-provider-systemextension",
                "app-proxy-provider-systemextension"],
            "com.apple.security.application-groups": [GROUP, TEAM + ".*"],
            "keychain-access-groups": [TEAM + ".*"],
        }
        if role == "host":
            entitlements["com.apple.developer.system-extension.install"] = True
        entitlements.update(changes.pop("entitlements", {}))
        for key in changes.pop("drop", ()):
            entitlements.pop(key)
        data = {"Entitlements": entitlements, "TeamIdentifier": [TEAM],
                "Platform": ["OSX"], "ProvisionsAllDevices": True,
                "UUID": "00000000-0000-0000-0000-000000000000", "Name": "fixture",
                "ExpirationDate": datetime.datetime(2044, 1, 1),
                "DeveloperCertificates": [b"fixture-certificate"]}
        data.update(changes)
        path = self.root / f"{role}-{len(list(self.root.iterdir()))}.plist"
        path.write_bytes(plistlib.dumps(data))
        return path

    def signed(self, claims):
        path = self.root / f"signed-{len(list(self.root.iterdir()))}.plist"
        path.write_bytes(plistlib.dumps(claims))
        return path

    def diff(self, role, claims, profile=None):
        return pipeline("diff-signed", "--role", role,
                        "--decoded-profile", profile or self.profile(role),
                        "--entitlements", PACKAGE / "packaging" / "entitlements" / f"{role}.entitlements",
                        "--signed-xml", self.signed(claims))

    def test_committed_entitlements_are_the_reviewed_two_role_set(self):
        host, provider = committed("host"), committed("provider")
        self.assertTrue(host["com.apple.developer.system-extension.install"])
        self.assertNotIn("com.apple.security.app-sandbox", host)
        for key in ("com.apple.security.app-sandbox", "com.apple.security.network.client",
                    "com.apple.security.network.server"):
            self.assertIs(provider[key], True)
        self.assertNotIn("com.apple.developer.system-extension.install", provider)
        for role, claims in (("host", host), ("provider", provider)):
            self.assertEqual(claims["com.apple.security.application-groups"], [GROUP])
            self.assertEqual(claims["com.apple.developer.networking.networkextension"],
                             NE_VALUES)
            ok = pipeline("check-committed", "--role", role, "--entitlements",
                          PACKAGE / "packaging" / "entitlements" / f"{role}.entitlements")
            self.assertEqual(ok.returncode, 0, ok.stderr)
        swapped = pipeline("check-committed", "--role", "host", "--entitlements",
                           PACKAGE / "packaging" / "entitlements" / "provider.entitlements")
        self.assertNotEqual(swapped.returncode, 0)

    def test_exact_signed_claims_produce_an_empty_diff(self):
        for role in ("host", "provider"):
            result = self.diff(role, committed(role))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("entitlement diff empty", result.stdout)

    def test_any_entitlement_difference_is_refused(self):
        provider = committed("provider")
        host = committed("host")
        cases = {
            "extra get-task-allow": ("provider", {**provider, "com.apple.security.get-task-allow": True}),
            "extra keychain group": ("provider", {**provider, "keychain-access-groups": [TEAM + ".*"]}),
            "missing network.server": ("provider", {k: v for k, v in provider.items()
                                                     if k != "com.apple.security.network.server"}),
            "missing sandbox": ("provider", {k: v for k, v in provider.items()
                                              if k != "com.apple.security.app-sandbox"}),
            "changed group": ("provider", {**provider, "com.apple.security.application-groups":
                                           ["group." + TEAM + ".other"]}),
            "wrong NE value": ("host", {**host, "com.apple.developer.networking.networkextension":
                                        ["packet-tunnel-provider"]}),
            # S20b: a missing or extra NE value, or the two out of order.
            "missing content filter": ("provider", {**provider,
                "com.apple.developer.networking.networkextension":
                    ["packet-tunnel-provider-systemextension"]}),
            "missing packet tunnel": ("host", {**host,
                "com.apple.developer.networking.networkextension":
                    ["content-filter-provider-systemextension"]}),
            "extra NE value": ("provider", {**provider,
                "com.apple.developer.networking.networkextension":
                    NE_VALUES + ["app-proxy-provider-systemextension"]}),
            "NE values reordered": ("host", {**host,
                "com.apple.developer.networking.networkextension": list(reversed(NE_VALUES))}),
            "install on provider": ("provider", {**provider,
                                                 "com.apple.developer.system-extension.install": True}),
            "disable library validation": ("host", {**host,
                "com.apple.security.cs.disable-library-validation": True}),
            "unsigned": ("host", {}),
        }
        for name, (role, claims) in cases.items():
            result = self.diff(role, claims)
            self.assertNotEqual(result.returncode, 0, name)
            self.assertIn("entitlement diff is not empty", result.stderr, name)

    def test_claims_not_authorized_by_the_profile_are_refused(self):
        cases = {
            "group only via wildcard": ("provider", self.profile(
                "provider", entitlements={"com.apple.security.application-groups": [TEAM + ".*"]})),
            "NE value absent": ("host", self.profile(
                "host", entitlements={"com.apple.developer.networking.networkextension":
                                      ["app-proxy-provider-systemextension"]})),
            # S20b: a profile (like the pre-r2 ones) without the content filter.
            "content filter not provisioned for the provider": ("provider", self.profile(
                "provider", entitlements={"com.apple.developer.networking.networkextension":
                                          ["packet-tunnel-provider-systemextension"]})),
            "content filter not provisioned for the host": ("host", self.profile(
                "host", entitlements={"com.apple.developer.networking.networkextension":
                                      ["packet-tunnel-provider-systemextension"]})),
            "install not provisioned": ("host", self.profile(
                "host", drop=("com.apple.developer.system-extension.install",))),
            "other app id": ("provider", self.profile(
                "provider", entitlements={"com.apple.application-identifier": TEAM + "." + APP})),
        }
        for name, (role, profile) in cases.items():
            result = self.diff(role, committed(role), profile)
            self.assertNotEqual(result.returncode, 0, name)
            self.assertIn("profile", result.stderr, name)

    def test_profile_field_checks(self):
        signer = hashlib.sha1(b"fixture-certificate").hexdigest().upper()
        ok = pipeline("check-profile", "--role", "provider", "--decoded-profile",
                      self.profile("provider"), "--signer-sha1", signer,
                      "--now", "2026-10-20T00:00:00")
        self.assertEqual(ok.returncode, 0, ok.stderr)
        refusals = {
            "wrong signer": (self.profile("provider"), "0" * 40),
            "expired": (self.profile("provider", ExpirationDate=datetime.datetime(2026, 1, 1)), signer),
            "development devices": (self.profile("provider", ProvisionsAllDevices=False,
                                                 ProvisionedDevices=["x"]), signer),
            "debug": (self.profile("provider", entitlements={"get-task-allow": True}), signer),
            "other team": (self.profile("provider", TeamIdentifier=["ABCDEFGHIJ"]), signer),
            "host profile for provider": (self.profile("host"), signer),
        }
        for name, (profile, sha1) in refusals.items():
            result = pipeline("check-profile", "--role", "provider", "--decoded-profile",
                              profile, "--signer-sha1", sha1, "--now", "2026-10-20T00:00:00")
            self.assertNotEqual(result.returncode, 0, name)

    def test_signature_display_requires_developer_id_runtime_and_timestamp(self):
        good = "\n".join([
            "Executable=/x/AEGIS.app/Contents/MacOS/aegis-ne-host",
            "Identifier=dev.aegis.macos",
            "CodeDirectory v=20500 size=5723 flags=0x10000(runtime) hashes=168+7 location=embedded",
            "Authority=Developer ID Application: Example Person (" + TEAM + ")",
            "Authority=Developer ID Certification Authority",
            "Authority=Apple Root CA",
            "Timestamp=20 Oct 2026 at 21:00:00",
            "TeamIdentifier=" + TEAM,
        ])
        variants = {
            "good": good,
            "adhoc": good.replace("flags=0x10000(runtime)", "flags=0x20002(adhoc,linker-signed)"),
            "development": good.replace("Developer ID Application", "Apple Development"),
            "no timestamp": good.replace("Timestamp=", "Signed Time="),
            "other team": good.replace("TeamIdentifier=" + TEAM, "TeamIdentifier=ABCDEFGHIJ"),
        }
        for name, text in variants.items():
            path = pathlib.Path(self.temp.name) / f"display-{name}.txt"
            path.write_text(text + "\n")
            result = pipeline("check-signature", "--identifier", APP, "--display-text", path)
            if name == "good":
                self.assertEqual(result.returncode, 0, result.stderr)
            else:
                self.assertNotEqual(result.returncode, 0, name)


class VersionLedgerTests(unittest.TestCase):
    """The must-increase rule spans a ledger outside any worktree and the installed app."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-s09-ledger-")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.receipts = self.root / "worktree-receipts"
        self.ledger = self.root / "ledger"

    def check(self, version, *extra):
        return pipeline("check-version", "--receipts-dir", self.receipts,
                        "--ledger-dir", self.ledger, "--version", version, *extra)

    def reserve(self, version, run_id):
        return pipeline("ledger-reserve", "--receipts-dir", self.receipts,
                        "--ledger-dir", self.ledger, "--version", version,
                        "--run-id", run_id, "--commit", "0" * 40,
                        "--receipt", self.root / f"{run_id}.json")

    def test_reservation_in_another_worktree_still_counts(self):
        ok = self.reserve("6", "v6-other-worktree")
        self.assertEqual(ok.returncode, 0, ok.stderr)
        entry = json.loads((self.ledger / "v6-v6-other-worktree.json").read_text())
        self.assertEqual(entry["bundle_version"], "6")
        # An empty worktree-local receipts directory does not reset the rule.
        for refused in ("6", "5", "2"):
            result = self.check(refused)
            self.assertNotEqual(result.returncode, 0, refused)
            self.assertIn("not greater than 6", result.stderr)
        self.assertEqual(self.check("7").returncode, 0)
        again = self.reserve("6", "v6-second")
        self.assertNotEqual(again.returncode, 0)
        self.assertFalse((self.ledger / "v6-v6-second.json").exists())
        same = self.reserve("7", "v6-other-worktree-x")
        self.assertEqual(same.returncode, 0, same.stderr)
        duplicate = self.reserve("8", "v6-other-worktree-x")
        self.assertEqual(duplicate.returncode, 0, duplicate.stderr)

    def test_installed_app_version_counts(self):
        app = self.root / "Applications" / "AEGIS.app"
        (app / "Contents").mkdir(parents=True)
        (app / "Contents" / "Info.plist").write_bytes(plistlib.dumps({"CFBundleVersion": "9"}))
        result = self.check("9", "--installed-app", app)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("installed", result.stderr)
        self.assertEqual(self.check("10", "--installed-app", app).returncode, 0)
        self.assertEqual(self.check("2", "--installed-app", self.root / "absent.app").returncode, 0)
        (app / "Contents" / "Info.plist").write_bytes(b"not a plist")
        self.assertNotEqual(self.check("99", "--installed-app", app).returncode, 0)


class ReceiptGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-s09-gates-")
        self.addCleanup(self.temp.cleanup)
        self.receipt = pathlib.Path(self.temp.name) / "r.json"
        self.receipt.write_text(json.dumps({"schema": 1}))

    def add(self, stage, status="ok"):
        result = pipeline("receipt", "--receipt", self.receipt, "--stage", stage, "--status", status)
        self.assertEqual(result.returncode, 0, result.stderr)

    def status(self, stage):
        return pipeline("receipt", "--receipt", self.receipt, "--stage-status", stage).stdout.strip()

    def test_rerunning_an_earlier_stage_makes_later_results_stale(self):
        for stage in ("assemble", "sign", "verify", "zip"):
            self.add(stage)
        self.assertEqual(self.status("verify"), "ok")
        self.add("sign")
        self.assertEqual(self.status("sign"), "ok")
        self.assertEqual(self.status("verify"), "stale")
        self.assertEqual(self.status("zip"), "stale")
        self.add("sign", "failed")
        self.assertEqual(self.status("sign"), "failed")
        self.assertEqual(self.status("verify"), "stale")
        self.add("sign")
        self.add("verify")
        self.assertEqual(self.status("verify"), "ok")
        self.assertEqual(self.status("zip"), "stale")
        self.assertEqual(self.status("notarize"), "")

    def test_dry_run_entries_neither_block_nor_satisfy_a_gate(self):
        for stage in ("assemble", "sign", "verify", "zip", "notarize"):
            self.add(stage)
        self.add("notarize", "dry-run")
        self.add("zip", "dry-run")
        self.assertEqual(self.status("notarize"), "ok")
        self.add("staple", "dry-run")
        self.assertEqual(self.status("staple"), "")

    def test_append_json_keeps_every_attempt(self):
        for attempt, state in ((1, "In Progress"), (2, "Accepted")):
            result = pipeline("receipt", "--receipt", self.receipt, "--append-json",
                              "notary_submissions=" + json.dumps({"attempt": attempt, "status": state}))
            self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(self.receipt.read_text())
        self.assertEqual([s["status"] for s in data["notary_submissions"]],
                         ["In Progress", "Accepted"])


class DistributableModeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-s09-modes-")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)

    def bundle(self, umask):
        old = os.umask(umask)
        try:
            app = self.root / f"u{umask:03o}" / "AEGIS.app"
            (app / "Contents" / "MacOS").mkdir(parents=True)
            (app / "Contents" / "Info.plist").write_bytes(b"x")
            exe = app / "Contents" / "MacOS" / "aegis-ne-host"
            exe.write_bytes(b"x")
            exe.chmod(0o755)
        finally:
            os.umask(old)
        return app

    def test_owner_only_bundle_and_zip_are_refused(self):
        private = self.bundle(0o077)
        refused = pipeline("check-modes", "--bundle", private)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("0700", refused.stderr)
        public = self.bundle(0o022)
        ok = pipeline("check-modes", "--bundle", public)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        for app, expect in ((private, 1), (public, 0)):
            archive = self.root / f"{app.parent.name}.zip"
            made = subprocess.run(["ditto", "-c", "-k", "--sequesterRsrc", "--keepParent",
                                   str(app), str(archive)], capture_output=True, text=True)
            self.assertEqual(made.returncode, 0, made.stderr)
            result = pipeline("check-modes", "--zip", archive)
            self.assertEqual(result.returncode, expect, result.stderr)

    def test_product_assembly_under_pipeline_umask_is_distributable(self):
        source = self.root / "bins"
        source.mkdir()
        binaries = []
        for index in range(2):
            path = source / f"bin-{index}"
            path.write_bytes(b"\xcf\xfa\xed\xfe" + bytes([index]) * 16)
            binaries.append(path)
        out = self.root / "product"
        script = ("umask 077; (umask 022; exec python3 -I -B \"$0\" --product --output \"$1\" "
                  "--host-binary \"$2\" --provider-binary \"$3\" --app-id dev.aegis.macos "
                  "--provider-id dev.aegis.macos.PacketTunnel "
                  "--app-group group.TEAMID0000.dev.aegis.macos --team-id TEAMID0000 "
                  "--bundle-version 7 --short-version 0.2.0)")
        made = subprocess.run(["/bin/bash", "-c", script, str(SCRIPT), str(out),
                               str(binaries[0]), str(binaries[1])], capture_output=True, text=True)
        self.assertEqual(made.returncode, 0, made.stderr)
        result = pipeline("check-modes", "--bundle", out / "AEGIS.app")
        self.assertEqual(result.returncode, 0, result.stderr)


class PipelineScriptGateTests(unittest.TestCase):
    """build-sign-notarize.sh refusals that need no keychain, cargo or Apple."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-s09-script-")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.artifacts = self.root / "artifacts"
        self.run_id = "v9-20261020T000000Z-test"
        self.run_dir = self.artifacts / "runs" / self.run_id
        (self.run_dir / "logs").mkdir(parents=True)
        (self.artifacts / "receipts").mkdir()
        self.receipt = self.artifacts / "receipts" / f"{self.run_id}.json"
        head = subprocess.run(["git", "-C", str(PACKAGE), "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
        ent = PACKAGE / "packaging" / "entitlements"
        self.data = {
            "schema": 1, "run_id": self.run_id, "commit": head, "source_dirty": True,
            "bundle_version": "9", "profile_signer_sha1": "A" * 40,
            "host_entitlements_sha256": sha256_file(ent / "host.entitlements"),
            "provider_entitlements_sha256": sha256_file(ent / "provider.entitlements"),
            "pipeline_sha256": sha256_file(PIPELINE),
            "script_sha256": sha256_file(PIPELINE_SH),
            "assembler_sha256": sha256_file(SCRIPT),
            "stages": [{"stage": "assemble", "status": "ok", "detail": "", "utc": "x"}],
        }
        self.write()

    def write(self):
        self.receipt.write_text(json.dumps(self.data))

    def script(self, *args):
        return run_script(self.root, *args)

    def test_stage_list_is_parsed_once(self):
        for stages, message in (("sign, verify", "without spaces"), ("sign verify", "without spaces"),
                                ("sign,,verify", "empty entry"), ("sign,", "empty entry"),
                                ("sign,sign", "duplicate"), ("sign,Verify", "without spaces"),
                                ("sign,verfy", "unknown stage")):
            result = self.script("--stages", stages, "--run-dir", self.run_dir)
            self.assertNotEqual(result.returncode, 0, stages)
            self.assertIn(message, result.stderr, stages)

    def test_build_alone_is_refused_outside_dry_run(self):
        result = self.script("--stages", "build")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("only together with assemble", result.stderr)

    def test_exact_sfu_feature_profiles_require_verified_native_vp8(self):
        for features in ("apple,sfu-media-vp8", "apple,sfu-media-vp8,enrolled-quic"):
            missing = self.script("--stages", "build,assemble", "--dry-run",
                                  "--features", features)
            self.assertNotEqual(missing.returncode, 0, features)
            self.assertIn("native VP8 requires absolute receipt and prefix paths",
                          missing.stderr, features)
            invalid = self.script("--stages", "build,assemble", "--dry-run",
                                  "--features", features,
                                  "--native-vp8-receipt", self.root / "missing-receipt.json",
                                  "--native-vp8-prefix", self.root / "missing-prefix")
            self.assertNotEqual(invalid.returncode, 0, features)
            self.assertIn("native VP8 receipt/prefix verification failed",
                          invalid.stderr, features)
        for features in ("apple,enrolled-quic", "apple,sfu-media-vp8,enrolled-quic,other",
                         "apple,enrolled-quic,sfu-media-vp8"):
            invalid = self.script("--stages", "build,assemble", "--dry-run",
                                  "--features", features)
            self.assertNotEqual(invalid.returncode, 0, features)
            self.assertIn("unsupported build feature set", invalid.stderr, features)
        source = PIPELINE_SH.read_text()
        # The same exact SFU predicate must protect clean source, native build
        # environment, and after-build proof; a future feature cannot skip one.
        self.assertEqual(source.count("if native_vp8_enabled"), 4)
        self.assertNotIn('[ "$BUILD_FEATURES" = apple,sfu-media-vp8 ]', source)

    def test_sign_refuses_an_identity_other_than_the_pinned_one(self):
        result = self.script("--stages", "sign", "--run-dir", self.run_dir, "--identity", "b" * 40)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("differs from " + "A" * 40, result.stderr)
        stages = json.loads(self.receipt.read_text())["stages"]
        self.assertEqual(stages[-1]["stage"], "sign")
        self.assertEqual(stages[-1]["status"], "failed")

    def test_sign_refuses_entitlements_changed_since_assembly(self):
        self.data["provider_entitlements_sha256"] = "0" * 64
        self.write()
        result = self.script("--stages", "sign", "--run-dir", self.run_dir, "--identity", "A" * 40)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("provider entitlements changed since assembly", result.stderr)
        self.data["provider_entitlements_sha256"] = sha256_file(
            PACKAGE / "packaging" / "entitlements" / "provider.entitlements")
        self.data["commit"] = "0" * 40
        self.write()
        result = self.script("--stages", "sign", "--run-dir", self.run_dir, "--identity", "A" * 40)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HEAD differs", result.stderr)

    def test_zip_refuses_a_verify_superseded_by_a_later_sign(self):
        self.data["stages"] += [{"stage": s, "status": "ok", "detail": "", "utc": "x"}
                                for s in ("sign", "verify", "sign")]
        self.write()
        result = self.script("--stages", "zip", "--run-dir", self.run_dir)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stage verify must be current", result.stderr)
        self.assertIn("stale", result.stderr)
        self.assertFalse(list(self.run_dir.glob("*.zip")))

    def test_staple_after_a_notarize_dry_run_still_sees_the_accepted_result(self):
        self.data["stages"] += [{"stage": s, "status": st, "detail": "", "utc": "x"}
                                for s, st in (("sign", "ok"), ("verify", "ok"), ("zip", "ok"),
                                              ("notarize", "ok"), ("notarize", "dry-run"))]
        self.write()
        status = pipeline("receipt", "--receipt", self.receipt, "--stage-status", "notarize")
        self.assertEqual(status.stdout.strip(), "ok")
        dry = self.script("--stages", "notarize", "--run-dir", self.run_dir, "--dry-run")
        self.assertEqual(dry.returncode, 0, dry.stderr)
        self.assertIn("notary-submit-1.json", dry.stdout)
        refused = self.script("--stages", "notarize", "--run-dir", self.run_dir,
                              "--approve-zip-sha256", "0" * 64)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("already notarized", refused.stderr)


class InstallReceiptBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-s09-install-")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.zip = self.root / "AEGIS-9-stapled.zip"
        self.zip.write_bytes(b"not really a zip")
        self.sha = sha256_file(self.zip)

    def install(self, *extra):
        return run_script(self.root, "--stapled-zip", self.zip, "--approve-sha256", self.sha,
                          "--dest", self.root / "Applications", "--state-dir", self.root / "state",
                          "--dry-run", *extra, script=INSTALL_SH)

    def test_receipt_of_another_zip_is_refused_before_extraction(self):
        receipt = self.root / "other.json"
        receipt.write_text(json.dumps({"stapled_zip_sha256": "f" * 64, "bundle_version": "9",
                                       "stages": [{"stage": "staple", "status": "ok"},
                                                  {"stage": "assess", "status": "ok"}]}))
        result = self.install("--receipt", receipt)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("different stapled ZIP", result.stderr)
        receipt.write_text(json.dumps({"stapled_zip_sha256": self.sha, "bundle_version": "9",
                                       "stages": [{"stage": "staple", "status": "ok"},
                                                  {"stage": "assess", "status": "failed"}]}))
        result = self.install("--receipt", receipt)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("assess is not current ok", result.stderr)
        self.assertNotIn("installed", json.loads(receipt.read_text()))

    def test_replace_with_activate_reaches_extraction_after_s11(self):
        # S11: the host replaces an active extension only with a numerically
        # newer CFBundleVersion, so the combination is no longer refused
        # up front; this fake ZIP then fails at extraction.
        result = self.install("--replace", "--activate")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("host cancels replacement", result.stderr)
        self.assertNotIn("unsupported", result.stderr)
        self.assertIn("stapled zip sha256: " + self.sha, result.stdout)

    def test_removed_activation_timeout_option_is_refused(self):
        result = self.install("--activation-timeout", "600")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unknown argument: --activation-timeout", result.stderr)

    def test_script_uses_host_exit_codes_and_strict_version_order(self):
        text = INSTALL_SH.read_text()
        # No log polling for delegate text and no lenient inline comparator.
        self.assertNotIn("Activation request finished", text)
        self.assertNotIn("kill -0", text)
        self.assertNotIn("python3 -I -c", text)
        self.assertIn('pipeline compare-version --new "$new_version" --installed "$old_version"', text)
        self.assertIn('pipeline activation-outcome --exit-code "$host_exit" --result-line "$result_line"',
                      text)
        self.assertIn('bounded "$ACTIVATION_WATCHDOG" "${activation_cmd[@]}"', text)


HOST_LIFECYCLE_RS = PACKAGE / "src" / "host_lifecycle.rs"


class ActivationOutcomeTests(unittest.TestCase):
    """The install script's outcome table is bound to the host's exit codes."""

    def outcome(self, code, line=None):
        if line is None:
            name = ACTIVATION_RESULT_NAMES.get(int(code), "x")
            line = f"activation_result={name} exit_code={code} replacement_decision=none"
        result = pipeline("activation-outcome", "--exit-code", code, "--result-line", line)
        self.assertEqual(result.returncode, 0, result.stderr)
        return tuple(result.stdout.split())

    def rust_codes(self):
        import re
        found = dict((name, int(value)) for name, value in re.findall(
            r"pub const EXIT_ACTIVATION_([A-Z_]+): i32 = (\d+);", HOST_LIFECYCLE_RS.read_text()))
        self.assertEqual(set(found), {"COMPLETED", "WILL_COMPLETE_AFTER_REBOOT", "FAILED",
                                      "CANCELLED", "REPLACEMENT_DECLINED",
                                      "TIMEOUT_AWAITING_APPROVAL", "TIMEOUT"})
        return found

    def test_every_host_activation_exit_code_has_its_named_outcome(self):
        codes = self.rust_codes()
        self.assertEqual(len(set(codes.values())), len(codes))
        for name, code in codes.items():
            outcome, status = self.outcome(code)
            self.assertEqual(outcome, name.lower().replace("_", "-"), name)
            self.assertEqual(status, {"COMPLETED": "ok",
                                      "WILL_COMPLETE_AFTER_REBOOT": "pending-reboot"}.get(name, "failed"))
        self.assertIn("ACTIVATION_TIMEOUT_SECS: u64 = 120;", HOST_LIFECYCLE_RS.read_text())

    def test_only_completed_is_ok_and_unknown_exits_fail_closed(self):
        self.assertEqual(self.outcome(2, ""), ("host-usage", "failed"))
        self.assertEqual(self.outcome(142, ""), ("host-unbounded", "failed"))
        for code in (1, 3, 9, 15, 65, 69, 76, 127, 255):
            self.assertEqual(self.outcome(code), ("host-unknown-exit", "failed"), code)
        for bad in ("", "x", "1.5"):
            self.assertNotEqual(pipeline("activation-outcome", "--exit-code", bad,
                                         "--result-line", "").returncode, 0)
        # The result line is required, so a caller cannot map an exit alone.
        self.assertNotEqual(pipeline("activation-outcome", "--exit-code", "0").returncode, 0)

    def test_a_host_exit_counts_only_with_the_hosts_own_result_line(self):
        # A failed exec (perl exits with errno: EACCES 13, ENOENT 2, ENOMEM 12)
        # or another process can return a host code without the host's line.
        for code in (0, 10, 11, 12, 13, 14, 75):
            self.assertEqual(self.outcome(code, ""), ("host-unknown-exit", "failed"), code)
        self.assertEqual(self.outcome(13, "exec: Permission denied"), ("host-unknown-exit", "failed"))
        # The line must name this outcome and this exit code, as a whole token.
        self.assertEqual(self.outcome(0, "activation_result=completed exit_code=13"),
                         ("host-unknown-exit", "failed"))
        self.assertEqual(self.outcome(13, "activation_result=completed exit_code=13"),
                         ("host-unknown-exit", "failed"))
        self.assertEqual(self.outcome(1, "activation_result=completed exit_code=10"),
                         ("host-unknown-exit", "failed"))
        self.assertEqual(self.outcome(10, "activation_result=will_complete_after_reboot exit_code=100"),
                         ("host-unknown-exit", "failed"))
        self.assertEqual(self.outcome(0, " activation_result=completed exit_code=0"),
                         ("host-unknown-exit", "failed"))
        self.assertEqual(self.outcome(0, "activation_result=completed exit_code=0"), ("completed", "ok"))
        self.assertEqual(self.outcome(13, "activation_result=replacement_declined exit_code=13 "
                                          "replacement_decision=cancel reason=x"),
                         ("replacement-declined", "failed"))


# `filter_result=` names printed by the host for each S20b exit code.
FILTER_RESULT_NAMES = {0: "ok", 30: "not_configured", 31: "disabled", 32: "field_mismatch",
                       33: "not_attached", 34: "failed", 35: "permission_denied", 36: "timeout",
                       37: "removal_incomplete", 67: "authorization_refused",
                       69: "provider_unavailable"}


class FilterOutcomeTests(unittest.TestCase):
    """S20b: the filter verbs' outcome table is bound to the host's codes."""

    def outcome(self, code, line=None):
        if line is None:
            line = f"filter_result={FILTER_RESULT_NAMES.get(int(code), 'x')} exit_code={code} configured=true"
        result = pipeline("filter-outcome", "--exit-code", code, "--result-line", line)
        self.assertEqual(result.returncode, 0, result.stderr)
        return tuple(result.stdout.split())

    def test_every_host_filter_exit_code_has_its_named_outcome(self):
        import re
        text = HOST_LIFECYCLE_RS.read_text()
        found = dict((name, int(value)) for name, value in re.findall(
            r"pub const EXIT_FILTER_([A-Z_]+): i32 = (\d+);", text))
        self.assertEqual(set(found), {"NOT_CONFIGURED", "DISABLED", "FIELD_MISMATCH", "NOT_ATTACHED",
                                      "FAILED", "PERMISSION_DENIED", "TIMEOUT", "REMOVAL_INCOMPLETE"})
        self.assertEqual(len(set(found.values())), len(found))
        for name, code in found.items():
            self.assertEqual(self.outcome(code), (name.lower().replace("_", "-"), "failed"), name)
            # The host prints the same name for this outcome.
            self.assertEqual(FILTER_RESULT_NAMES[code], name.lower())
        names = dict(re.findall(r'FilterOutcome::(\w+)(?:\(_\))? => "([a-z_]+)"', text))
        self.assertEqual(sorted(names.values()), sorted(FILTER_RESULT_NAMES.values()))
        self.assertEqual(self.outcome(0), ("ok", "ok"))
        self.assertEqual(self.outcome(69), ("provider-unavailable", "failed"))
        self.assertIn("FilterOutcome::ProviderUnavailable => EXIT_XPC_UNAVAILABLE", text)
        # v26: a refused administrator approval keeps the identity verbs' 67.
        self.assertEqual(self.outcome(67), ("authorization-refused", "failed"))
        self.assertIn("FilterOutcome::AuthorizationRefused(_) => EXIT_AUTHORIZATION_REFUSED", text)
        self.assertIn("pub const EXIT_AUTHORIZATION_REFUSED: i32 = 67;", text)
        self.assertEqual(self.outcome(67, "filter_result=ok exit_code=67"), ("host-unknown-exit", "failed"))

    def test_a_filter_exit_counts_only_with_the_hosts_own_line(self):
        self.assertEqual(self.outcome(2, ""), ("host-usage", "failed"))
        self.assertEqual(self.outcome(142, ""), ("host-unbounded", "failed"))
        for code in (0, 30, 35, 36):
            self.assertEqual(self.outcome(code, ""), ("host-unknown-exit", "failed"), code)
        self.assertEqual(self.outcome(0, "filter_result=ok exit_code=35"), ("host-unknown-exit", "failed"))
        self.assertEqual(self.outcome(35, "filter_result=ok exit_code=35"), ("host-unknown-exit", "failed"))
        self.assertEqual(self.outcome(0, "activation_result=ok exit_code=0"), ("host-unknown-exit", "failed"))
        for code in (1, 10, 25, 38, 65, 75, 127):
            self.assertEqual(self.outcome(code), ("host-unknown-exit", "failed"), code)
        self.assertEqual(self.outcome(0, "filter_result=ok exit_code=0"), ("ok", "ok"))


class CompareVersionTests(unittest.TestCase):
    def compare(self, new, installed):
        return pipeline("compare-version", "--new", new, "--installed", installed).returncode

    def test_replacement_needs_a_numerically_newer_bundle_version(self):
        for new, installed in (("8", "7"), ("7.0.1", "7"), ("10", "9"), ("1.10", "1.9")):
            self.assertEqual(self.compare(new, installed), 0, (new, installed))
        for new, installed in (("7", "7"), ("7", "7.0"), ("7.0.0", "7"), ("9", "10"), ("1.9", "1.10")):
            self.assertNotEqual(self.compare(new, installed), 0, (new, installed))
        for new, installed in (("08", "7"), ("8", "07"), ("8", "1.2.3.4"), ("8", ""), ("8a", "7")):
            self.assertNotEqual(self.compare(new, installed), 0, (new, installed))


# `activation_result=` names printed by the host for each exit code.
ACTIVATION_RESULT_NAMES = {0: "completed", 10: "will_complete_after_reboot", 11: "failed",
                           12: "cancelled", 13: "replacement_declined",
                           14: "timeout_awaiting_approval", 75: "timeout"}

FAKE_TOOLS = {
    # The extracted "ZIP" is a prepared AEGIS.app; a plain copy may be tampered.
    "ditto": """#!/bin/sh
if [ "$1" = -x ]; then cp -R "$FAKE_APP_TEMPLATE" "$4/AEGIS.app"; exit 0; fi
cp -R "$1" "$2"
case "${FAKE_DITTO_TAMPER:-}" in
    host) echo tampered >> "$2/Contents/MacOS/aegis-ne-host" ;;
    provider) p=dev.aegis.macos.PacketTunnel
        echo tampered >> "$2/Contents/Library/SystemExtensions/$p.systemextension/Contents/MacOS/$p" ;;
esac
""",
    # A CDHash stands in for the bundle's own main executable bytes.
    "codesign": """#!/bin/sh
if [ "$1" = -d ]; then
    for p; do :; done
    h=$(find "$p/Contents/MacOS" -type f -exec cat {} + | shasum -a 256 | cut -c1-40)
    echo "Executable=$p" >&2
    echo "CDHash=$h" >&2
fi
exit 0
""",
    "xcrun": "#!/bin/sh\nexit 0\n",
    "spctl": """#!/bin/sh
for p; do :; done
echo "$p: accepted"
echo "source=${FAKE_SPCTL_SOURCE:-Notarized Developer ID}"
echo "origin=Developer ID Application: Test (TEAMID0000)"
""",
}

FAKE_HOST = """#!/bin/sh
echo "$@" >> "$FAKE_HOST_ARGS"
if [ "$1" = --enable-filter ]; then
    echo "${FAKE_FILTER_LINE-filter_result=ok exit_code=0 configured=true enabled=true filter_packets=true filter_sockets=false packet_bundle_id=match grade=firewall}"
    exit "${FAKE_FILTER_EXIT:-0}"
fi
if [ -n "${FAKE_HOST_LINE:-}" ]; then echo "$FAKE_HOST_LINE"; fi
exit "${FAKE_HOST_EXIT:-0}"
"""


def write_mode(path, data, mode):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    os.chmod(path, mode)


def make_app(root, version, host_mode=0o755):
    """A product-shaped AEGIS.app with a fake host; no real binary or signature."""
    app = pathlib.Path(root) / "AEGIS.app"
    write_mode(app / "Contents" / "Info.plist", plistlib.dumps(
        {"CFBundleIdentifier": APP, "CFBundleVersion": version}), 0o644)
    write_mode(app / "Contents" / "MacOS" / "aegis-ne-host", FAKE_HOST, host_mode)
    ext = app / "Contents" / "Library" / "SystemExtensions" / (PROVIDER + ".systemextension")
    write_mode(ext / "Contents" / "Info.plist", plistlib.dumps(
        {"CFBundleIdentifier": PROVIDER, "CFBundleVersion": version}), 0o644)
    write_mode(ext / "Contents" / "MacOS" / PROVIDER, b"provider " + version.encode(), 0o755)
    for directory, _, _ in os.walk(app):
        os.chmod(directory, 0o755)
    return app


class InstallActivationBehaviorTests(unittest.TestCase):
    """Runs install-app.sh for real (not --dry-run) against fake Apple tools
    and a fake host executable that exits with a chosen code. Proves only the
    script's handling of host results, never an Apple activation."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-s11-install-")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name).resolve()
        self.bin = self.root / "bin"
        for name, body in FAKE_TOOLS.items():
            write_mode(self.bin / name, body, 0o755)
        self.dest = self.root / "Applications"
        self.dest.mkdir()
        self.state = self.root / "state"
        self.host_args = self.root / "host-args"
        self.runs = 0

    def zip_for(self, version, host_mode=0o755):
        """Prepare one 'stapled ZIP' (template app + placeholder ZIP + receipt)."""
        self.runs += 1
        work = self.root / f"build-{self.runs}"
        app = make_app(work, version, host_mode)
        zipfile_ = work / f"AEGIS-{version}-stapled.zip"
        zipfile_.write_bytes(b"placeholder zip " + version.encode() + bytes([self.runs]))
        sha = sha256_file(zipfile_)
        receipt = work / "receipt.json"
        receipt.write_text(json.dumps({"schema": 1, "stapled_zip_sha256": sha, "bundle_version": version,
                                       "stages": [{"stage": "staple", "status": "ok"},
                                                  {"stage": "assess", "status": "ok"}]}))
        return app, zipfile_, sha, receipt

    def run_install(self, args, template=None, host_exit=0, host_line=None, **env_extra):
        return self.run_exact([str(INSTALL_SH), *map(str, args), "--dest", self.dest,
                               "--state-dir", self.state], template, host_exit, host_line,
                              **env_extra)

    def run_exact(self, argv, template=None, host_exit=0, host_line=None, **env_extra):
        """install-app.sh with exactly `argv` (argv[0] the script)."""
        env = {"PATH": f"{self.bin}:{pathlib.Path(sys.executable).parent}:/usr/bin:/bin:/usr/sbin:/sbin",
               "HOME": str(self.root), "TMPDIR": str(self.root),
               "FAKE_HOST_ARGS": str(self.host_args), "FAKE_HOST_EXIT": str(host_exit),
               "FAKE_HOST_LINE": (f"activation_result={ACTIVATION_RESULT_NAMES.get(host_exit, 'x')} "
                                  f"exit_code={host_exit} replacement_decision=none tunnel_ready=unknown"
                                  if host_line is None else host_line)}
        if template is not None:
            env["FAKE_APP_TEMPLATE"] = str(template)
        env.update(env_extra)
        return subprocess.run(["/bin/bash", *map(str, argv)],
                              check=False, capture_output=True, text=True, env=env)

    def install(self, version, *extra, host_mode=0o755, **kwargs):
        app, zipfile_, sha, receipt = self.zip_for(version, host_mode)
        result = self.run_install(["--stapled-zip", zipfile_, "--approve-sha256", sha,
                                   "--receipt", receipt, *extra], template=app, **kwargs)
        return result, receipt

    @staticmethod
    def stages(receipt, name):
        return [s["status"] for s in json.loads(receipt.read_text())["stages"] if s["stage"] == name]

    def test_enable_filter_follows_a_completed_activation_and_is_recorded(self):
        result, receipt = self.install("9", "--activate", "--enable-filter")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.host_args.read_text().splitlines(),
                         ["--request-activation " + PROVIDER, "--enable-filter"])
        self.assertIn("leak-guard packet filter enabled", result.stdout)
        data = json.loads(receipt.read_text())
        self.assertEqual(self.stages(receipt, "enable-filter"), ["ok"])
        self.assertEqual(data["filter_outcome"], "ok")
        self.assertEqual(data["filter_exit_code"], 0)
        self.assertTrue(data["filter_result"].startswith("filter_result=ok exit_code=0 "))
        self.assertTrue(pathlib.Path(data["filter_log"]).is_file())

    def test_enable_filter_failures_are_recorded_and_refused(self):
        cases = [
            (35, None, "click Allow", "permission-denied"),
            (31, None, "enable-filter disabled (host exit 31", "disabled"),
            (36, None, "enable-filter timeout (host exit 36", "timeout"),
            (34, "", "enable-filter host-unknown-exit (host exit 34", "host-unknown-exit"),
            (0, "filter_result=ok exit_code=35", "host-unknown-exit", "host-unknown-exit"),
        ]
        for code, line, message, outcome in cases:
            with self.subTest(code=code, line=line):
                for child in self.dest.iterdir():
                    subprocess.run(["rm", "-rf", str(child)], check=True)
                self.host_args.unlink(missing_ok=True)
                filter_line = (f"filter_result={FILTER_RESULT_NAMES[code]} exit_code={code} configured=true"
                               if line is None else line)
                result, receipt = self.install("9", "--activate", "--enable-filter",
                                               FAKE_FILTER_EXIT=str(code), FAKE_FILTER_LINE=filter_line)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn(message, result.stderr)
                self.assertEqual(self.stages(receipt, "enable-filter"), ["failed"])
                self.assertEqual(json.loads(receipt.read_text())["filter_outcome"], outcome)
        # A failed activation never reaches the filter.
        for child in self.dest.iterdir():
            subprocess.run(["rm", "-rf", str(child)], check=True)
        self.host_args.unlink(missing_ok=True)
        result, receipt = self.install("9", "--activate", "--enable-filter", host_exit=11)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.host_args.read_text().splitlines(), ["--request-activation " + PROVIDER])
        self.assertEqual(self.stages(receipt, "enable-filter"), [])

    def test_enable_filter_needs_an_activation_and_its_dry_run_prints_the_bounded_command(self):
        app, zipfile_, sha, receipt = self.zip_for("9")
        result = self.run_install(["--stapled-zip", zipfile_, "--approve-sha256", sha,
                                   "--receipt", receipt, "--enable-filter"], template=app)
        self.assertEqual(result.returncode, 1)
        self.assertIn("--enable-filter follows an activation", result.stderr)
        self.assertFalse(self.host_args.exists())
        result = self.run_install(["--stapled-zip", zipfile_, "--approve-sha256", sha,
                                   "--receipt", receipt, "--activate", "--enable-filter", "--dry-run"],
                                  template=app)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"\+ bounded 150 \S*aegis-ne-host --enable-filter > ")
        self.assertIn("host stops after 120s", result.stdout)
        self.assertFalse(self.host_args.exists())

    def test_each_host_exit_is_recorded_and_handled_by_its_outcome(self):
        cases = [
            # code, line override, script exit, outcome, stage status, message
            (0, None, 0, "completed", "ok", "activation request completed"),
            (10, None, 1, "will-complete-after-reboot", "pending-reboot", "completes after a reboot"),
            (11, None, 1, "failed", "failed", "activation failed (host exit 11"),
            (12, None, 1, "cancelled", "failed", "activation cancelled (host exit 12"),
            (13, None, 1, "replacement-declined", "failed", "CFBundleVersion 9 is not newer"),
            (14, None, 1, "timeout-awaiting-approval", "failed", "approval still pending after 120s"),
            (75, None, 1, "timeout", "failed", "activation timeout (host exit 75"),
            (3, "activation_result=x exit_code=3", 1, "host-unknown-exit", "failed", "host exit 3"),
            (13, "", 1, "host-unknown-exit", "failed", "host exit 13"),
            (13, "activation_result=completed exit_code=0", 1, "host-unknown-exit", "failed",
             "host exit 13"),
        ]
        for code, line, rc, outcome, status, message in cases:
            with self.subTest(code=code, line=line):
                for child in self.dest.iterdir():
                    subprocess.run(["rm", "-rf", str(child)], check=True)
                result, receipt = self.install("9", "--activate", host_exit=code, host_line=line)
                self.assertEqual(result.returncode, rc, result.stderr)
                self.assertIn(message, result.stdout + result.stderr)
                data = json.loads(receipt.read_text())
                self.assertIs(data["installed"], True)
                self.assertEqual(data["installed_path"], str(self.dest / "AEGIS.app"))
                self.assertRegex(data["installed_host_cdhash"], r"^[0-9a-f]{40}$")
                self.assertRegex(data["installed_provider_cdhash"], r"^[0-9a-f]{40}$")
                self.assertEqual(data["activation_outcome"], outcome)
                self.assertEqual(data["activation_exit_code"], code)
                self.assertEqual(data["stages"][-1]["stage"], "activate")
                self.assertEqual(data["stages"][-1]["status"], status)
                self.assertEqual(self.stages(receipt, "install"), ["ok"])
                self.assertTrue(pathlib.Path(data["activation_log"]).is_file())
                self.assertEqual(self.host_args.read_text().splitlines()[-1],
                                 "--request-activation " + PROVIDER)
                if outcome in ("will-complete-after-reboot", "timeout-awaiting-approval"):
                    # The follow-up re-records against this receipt.
                    self.assertIn("--activate-installed --receipt " + str(receipt), result.stderr)

    def test_a_host_that_cannot_be_executed_is_not_a_host_outcome(self):
        # check-modes accepts a 0644 file; perl's die would exit EACCES (13),
        # the host's "replacement declined" code.
        result, receipt = self.install("9", "--activate", host_mode=0o644, host_exit=13)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("exec: Permission denied", result.stdout)
        self.assertNotIn("not newer", result.stderr)
        data = json.loads(receipt.read_text())
        self.assertEqual(data["activation_exit_code"], 127)
        self.assertEqual(data["activation_outcome"], "host-unknown-exit")
        self.assertEqual(data["activation_result"], "")
        self.assertFalse(self.host_args.exists())

    def test_activation_after_reboot_is_recorded_against_the_same_zip(self):
        result, receipt = self.install("9", "--activate", host_exit=10)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.stages(receipt, "activate"), ["pending-reboot"])
        again = self.run_install(["--activate-installed", "--receipt", receipt], host_exit=0)
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertIn("installed app 9 matches receipt", again.stdout)
        self.assertIn("activation request completed", again.stdout)
        data = json.loads(receipt.read_text())
        self.assertEqual(self.stages(receipt, "activate"), ["pending-reboot", "ok"])
        self.assertEqual(data["activation_outcome"], "completed")
        self.assertEqual(data["activation_exit_code"], 0)
        self.assertEqual(self.stages(receipt, "install"), ["ok"])
        # Both attempts keep their own log, even within one second.
        logs = sorted(self.state.glob("activation-9-*.log"))
        self.assertEqual(len(logs), 2)
        self.assertEqual(sorted(p.read_text() for p in logs),
                         sorted(["activation_result=will_complete_after_reboot exit_code=10 "
                                 "replacement_decision=none tunnel_ready=unknown\n",
                                 "activation_result=completed exit_code=0 "
                                 "replacement_decision=none tunnel_ready=unknown\n"]))

    def printed_followup(self, stderr):
        """The shell command a pending activation tells the owner to run."""
        match = re.search(r"then run (.+?)(?: to confirm \(log |\n|$)", stderr)
        self.assertIsNotNone(match, stderr)
        return match.group(1)

    def test_a_pending_activation_prints_a_followup_that_keeps_enable_filter(self):
        for code in (10, 14):
            with self.subTest(code=code):
                self.setUp()
                result, receipt = self.install("9", "--activate", "--enable-filter", host_exit=code)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(self.stages(receipt, "enable-filter"), [])
                argv = shlex.split(self.printed_followup(result.stderr))
                self.assertEqual(argv[0], str(INSTALL_SH))
                self.assertEqual(argv[1:], ["--activate-installed", "--receipt", str(receipt),
                                            "--dest", str(self.dest), "--state-dir", str(self.state),
                                            "--enable-filter"])
                # Running exactly the printed command enables the filter.
                self.host_args.unlink()
                again = self.run_exact(argv, host_exit=0)
                self.assertEqual(again.returncode, 0, again.stderr)
                self.assertEqual(self.host_args.read_text().splitlines(),
                                 ["--request-activation " + PROVIDER, "--enable-filter"])
                self.assertEqual(self.stages(receipt, "enable-filter"), ["ok"])
        # Without --enable-filter the follow-up does not add it.
        self.setUp()
        result, _ = self.install("9", "--activate", host_exit=10)
        self.assertNotIn("--enable-filter", self.printed_followup(result.stderr))
        # Without a receipt the host's --enable-filter is the named second step.
        self.setUp()
        app, zipfile_, sha, _ = self.zip_for("9", 0o755)
        result = self.run_install(["--stapled-zip", zipfile_, "--approve-sha256", sha,
                                   "--activate", "--enable-filter"], template=app, host_exit=10)
        self.assertEqual(result.returncode, 1, result.stderr)
        host = self.dest / "AEGIS.app" / "Contents" / "MacOS" / "aegis-ne-host"
        self.assertEqual(self.printed_followup(result.stderr),
                         f"{host} --request-activation {PROVIDER}, then {host} --enable-filter")

    def test_a_late_activation_of_the_installed_app_also_enables_the_filter(self):
        result, receipt = self.install("9", "--activate", "--enable-filter", host_exit=10)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.stages(receipt, "enable-filter"), [])
        self.host_args.unlink()
        again = self.run_install(["--activate-installed", "--enable-filter", "--receipt", receipt],
                                 host_exit=0)
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual(self.host_args.read_text().splitlines(),
                         ["--request-activation " + PROVIDER, "--enable-filter"])
        self.assertEqual(self.stages(receipt, "activate"), ["pending-reboot", "ok"])
        self.assertEqual(self.stages(receipt, "enable-filter"), ["ok"])

    def test_activate_installed_refuses_any_app_other_than_the_receipts(self):
        result, receipt = self.install("9")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--activate-installed --receipt", result.stdout)
        host = self.dest / "AEGIS.app" / "Contents" / "MacOS" / "aegis-ne-host"
        provider = (self.dest / "AEGIS.app" / "Contents" / "Library" / "SystemExtensions" /
                    (PROVIDER + ".systemextension") / "Contents" / "MacOS" / PROVIDER)
        before = receipt.read_text()

        def refused(message, *extra, args=None):
            out = self.run_install(args or ["--activate-installed", "--receipt", receipt, *extra])
            self.assertNotEqual(out.returncode, 0, out.stdout)
            self.assertIn(message, out.stderr)
            self.assertEqual(receipt.read_text(), before)
            self.assertFalse(self.host_args.exists())

        original = host.read_bytes()
        host.write_bytes(original + b"\n# swapped\n")
        refused("installed host CDHash differs from the receipt")
        host.write_bytes(original)
        original_provider = provider.read_bytes()
        provider.write_bytes(b"other provider")
        refused("installed provider CDHash differs from the receipt")
        provider.write_bytes(original_provider)
        info = self.dest / "AEGIS.app" / "Contents" / "Info.plist"
        original_info = info.read_bytes()
        info.write_bytes(plistlib.dumps({"CFBundleIdentifier": APP, "CFBundleVersion": "10"}))
        refused("installed CFBundleVersion 10 differs from the receipt")
        info.write_bytes(original_info)
        out = self.run_install(["--activate-installed", "--receipt", receipt],
                               FAKE_SPCTL_SOURCE="Unnotarized Developer ID")
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("installed app is not accepted as Notarized Developer ID", out.stderr)
        self.assertEqual(receipt.read_text(), before)
        for extra in (["--activate"], ["--replace"], ["--stapled-zip", "/x.zip"]):
            refused("--activate-installed takes only", *extra)
        # A receipt that never installed, or installed elsewhere.
        _, _, _, fresh = self.zip_for("9")
        out = self.run_install(["--activate-installed", "--receipt", fresh])
        self.assertIn("no current ok install stage", out.stderr)
        moved = json.loads(before)
        moved["installed_path"] = str(self.root / "elsewhere" / "AEGIS.app")
        receipt.write_text(json.dumps(moved))
        before = receipt.read_text()
        refused("receipt did not install")
        # Unchanged: activation runs and is recorded.
        receipt.write_text(json.dumps(json.loads(before) | {"installed_path": str(self.dest / "AEGIS.app")}))
        ok = self.run_install(["--activate-installed", "--receipt", receipt], host_exit=0)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertEqual(self.stages(receipt, "activate"), ["ok"])

    def test_tampered_install_copy_is_moved_aside_and_not_recorded(self):
        for count, part in enumerate(("host", "provider"), 1):
            with self.subTest(part=part):
                result, receipt = self.install("9", "--activate", FAKE_DITTO_TAMPER=part)
                self.assertEqual(result.returncode, 1)
                self.assertIn("differs from the verified extracted app (CDHash)", result.stderr)
                self.assertFalse((self.dest / "AEGIS.app").exists())
                # Each failed copy keeps its own name, even within one second.
                failed = sorted((self.state / "failed").iterdir())
                self.assertEqual(len(failed), count)
                self.assertTrue(all((f / "Contents" / "Info.plist").is_file() for f in failed))
                self.assertEqual(self.stages(receipt, "install"), ["failed"])
                self.assertNotIn("installed", json.loads(receipt.read_text()))
                self.assertFalse(self.host_args.exists())

    def test_attempts_in_the_same_second_never_reuse_an_earlier_path(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        stamps = [(now + datetime.timedelta(seconds=d)).strftime("%Y%m%dT%H%M%SZ")
                  for d in range(-1, 30)]
        earlier = {}
        for stamp in stamps:
            for path in (self.state / "failed" / f"AEGIS.app.failed-9-{stamp}" / "earlier",
                         self.state / f"activation-9-{stamp}.log",
                         self.state / f"activation-9-{stamp}.1.log"):
                write_mode(path, "earlier attempt\n", 0o644)
                earlier[path] = path.read_text()
        result, receipt = self.install("9", "--activate", FAKE_DITTO_TAMPER="host")
        self.assertEqual(result.returncode, 1)
        result, receipt = self.install("9", "--activate", host_exit=0)
        self.assertEqual(result.returncode, 0, result.stderr)
        for path, text in earlier.items():
            self.assertEqual(path.read_text(), text, path)
        for directory in (self.state / "failed").iterdir():
            self.assertNotIn("AEGIS.app", [c.name for c in directory.iterdir()], directory)
        failed = json.loads((self.root / "build-1" / "receipt.json").read_text())["install_failed_copy"]
        self.assertRegex(failed, r"AEGIS\.app\.failed-9-\d{8}T\d{6}Z\.1$")
        self.assertTrue((pathlib.Path(failed) / "Contents" / "Info.plist").is_file())
        log = json.loads(receipt.read_text())["activation_log"]
        self.assertRegex(log, r"activation-9-\d{8}T\d{6}Z\.2\.log$")
        self.assertIn("activation_result=completed", pathlib.Path(log).read_text())

    def test_replace_records_an_app_only_rollback_and_the_provider_skew(self):
        first, _ = self.install("8")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertNotIn("restores only the app", first.stderr)
        now = datetime.datetime.now(datetime.timezone.utc)
        markers = [self.state / "backups" / ("AEGIS.app.replaced-8-" + (now + datetime.timedelta(
            seconds=d)).strftime("%Y%m%dT%H%M%SZ")) / "earlier" for d in range(-1, 30)]
        for marker in markers:
            write_mode(marker, "earlier backup\n", 0o644)
        result, receipt = self.install("9", "--replace", "--activate", host_exit=13)
        for marker in markers:
            self.assertEqual(sorted(c.name for c in marker.parent.iterdir()), ["earlier"])
        self.assertEqual(result.returncode, 1)
        self.assertIn("app-only rollback", result.stdout)
        self.assertIn("the backup restores only the app", result.stderr)
        self.assertIn("previously active provider stays active", result.stderr)
        data = json.loads(receipt.read_text())
        self.assertIn("does not change the active system extension", data["rollback_note"])
        backup = pathlib.Path(data["installed_backup"])
        self.assertRegex(backup.name, r"^AEGIS\.app\.replaced-8-\d{8}T\d{6}Z\.1$")
        self.assertTrue(backup.is_dir())
        self.assertEqual(plistlib.loads((backup / "Contents" / "Info.plist").read_bytes())
                         ["CFBundleVersion"], "8")
        # Plain --replace (activation later) gets the same note and warning.
        plain, receipt10 = self.install("10", "--replace")
        self.assertEqual(plain.returncode, 0, plain.stderr)
        self.assertIn("the backup restores only the app", plain.stderr)
        self.assertIn("previously active provider stays active", plain.stderr)
        self.assertIn("restores only the app", json.loads(receipt10.read_text())["rollback_note"])
        # A fresh install records no rollback note.
        self.assertEqual(json.loads((self.root / "build-1" / "receipt.json").read_text())
                         ["rollback_note"], "")
        # Equal and lower versions are refused before anything moves.
        for version in ("10", "9"):
            refused, _ = self.install(version, "--replace")
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn("is not greater than installed 10", refused.stderr)
        self.assertEqual(plistlib.loads((self.dest / "AEGIS.app" / "Contents" / "Info.plist")
                                        .read_bytes())["CFBundleVersion"], "10")


    def test_a_host_without_the_leak_guard_prompt_is_never_installed_or_kept_runnable(self):
        # v26 review: the administrator gate on --disable-filter and
        # --remove-filter lives in the host, so a kept signed v25 host (the
        # filter verbs without the prompt) must not stay executable. v30
        # review: nor a kept v26 to v29 host, whose prompt offers Touch ID
        # (one resting touch approved two v29 prompts); only v30 asks for
        # the password-only right.
        for version, reason in (
                ("25", "has --disable-filter and --remove-filter without the administrator prompt (v26)"),
                ("25.1", "has --disable-filter and --remove-filter without the administrator prompt (v26)"),
                ("26", "asks for --disable-filter and --remove-filter at a prompt that offers Touch ID (before v30"),
                ("29", "asks for --disable-filter and --remove-filter at a prompt that offers Touch ID (before v30"),
                ("29.9", "asks for --disable-filter and --remove-filter at a prompt that offers Touch ID (before v30")):
            with self.subTest(version=version):
                result, receipt = self.install(version)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn(f"CFBundleVersion {version} {reason}", result.stderr)
                self.assertIn("install v30 or later", result.stderr)
                self.assertFalse((self.dest / "AEGIS.app").exists())
                self.assertEqual(self.stages(receipt, "install"), [])
        # v29 installed earlier (by an older install-app.sh), kept copies of
        # v24 to v30 beside it, as the v25 to v29 upgrades left them.
        installed = make_app(self.dest, "29")
        weak_host = installed / "Contents" / "MacOS" / "aegis-ne-host"
        weak_sha = sha256_file(weak_host)
        kept = {}
        for name, version in (("backups/AEGIS.app.replaced-24-20261020T000000Z", "24"),
                              ("uninstalled/AEGIS.app.uninstalled-25-20261021T000000Z", "25"),
                              ("backups/AEGIS.app.replaced-26-20261022T000000Z", "26"),
                              ("uninstalled/AEGIS.app.uninstalled-28-20261023T000000Z", "28"),
                              ("uninstalled/AEGIS.app.uninstalled-30-20261024T000000Z", "30")):
            kept[version] = make_app(self.state / name, version).parent
            os.rename(kept[version] / "AEGIS.app", self.root / "moved")
            kept[version].rmdir()
            os.rename(self.root / "moved", kept[version])
        # A failed install restores v29 with its host: the replaced app is
        # the rollback, disarmed only after a verified install.
        failed, _ = self.install("30", "--replace", FAKE_DITTO_TAMPER="host")
        self.assertEqual(failed.returncode, 1)
        self.assertEqual(sha256_file(weak_host), weak_sha)
        for version in ("25", "26", "28"):
            self.assertTrue((kept[version] / "Contents" / "MacOS" / "aegis-ne-host").is_file(), version)
        result, receipt = self.install("30", "--replace")
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(receipt.read_text())
        backup = pathlib.Path(data["installed_backup"])
        self.assertRegex(backup.name, r"^AEGIS\.app\.replaced-29-\d{8}T\d{6}Z$")
        reasons = {"25": "predate the v26 administrator prompt",
                   "26": "offers Touch ID (dev.aegis.macos.leak-guard-weaken), before the v30 password-only right"}
        for copy, version in ((backup, "29"), (kept["25"], "25"), (kept["26"], "26"), (kept["28"], "28")):
            self.assertFalse((copy / "Contents" / "MacOS" / "aegis-ne-host").exists(), copy)
            note = (copy / "Contents" / "MacOS" / "aegis-ne-host.removed").read_text()
            self.assertIn(reasons.get(version, reasons["26"]), note)
            # Every fake host is the same file, so one digest for all.
            self.assertIn(f"sha256={weak_sha}\n", note)
            self.assertIn(f"kept app {copy}: weak_host=disarmed version={version} host_sha256={weak_sha}",
                          result.stdout)
            self.assertIn(f"{copy} weak_host=disarmed version={version}", data["weak_hosts_disarmed"])
            # The rest of the copy is kept.
            self.assertTrue((copy / "Contents" / "Info.plist").is_file())
        self.assertIn("predates the v30 password-only leak-guard prompt", result.stdout)
        for version in ("24", "30"):
            self.assertTrue((kept[version] / "Contents" / "MacOS" / "aegis-ne-host").is_file(), version)
            self.assertNotIn(str(kept[version]), data["weak_hosts_disarmed"])
        self.assertTrue((self.dest / "AEGIS.app" / "Contents" / "MacOS" / "aegis-ne-host").is_file())
        # Idempotent: a later install finds nothing more to disarm, and the
        # replaced v30 keeps its host.
        again, receipt31 = self.install("31", "--replace")
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual(json.loads(receipt31.read_text())["weak_hosts_disarmed"], "")
        backup30 = pathlib.Path(json.loads(receipt31.read_text())["installed_backup"])
        self.assertTrue((backup30 / "Contents" / "MacOS" / "aegis-ne-host").is_file())
        self.assertIn("FILTER_MIN_PRIOR=24 WEAKEN_PROMPT_MIN=26 LEAK_GUARD_PASSWORD_MIN=30\n",
                      INSTALL_SH.read_text())



# `deactivation_result=` names printed by the host for each exit code (S21).
DEACTIVATION_RESULT_NAMES = {0: "completed", 20: "will_complete_after_reboot", 21: "failed",
                             22: "cancelled", 23: "not_found",
                             24: "timeout_awaiting_approval", 25: "timeout"}
XPC_SCHEMA = "aegis-ne-xpc-v1"


def forget_line(was_present=True, removed=True, **extra):
    return json.dumps({"schema": XPC_SCHEMA, "verb": "forget-identity",
                       "report": {"identity_was_present": was_present,
                                  "key_material_removed": removed, **extra}})


def ping_line(identity=False, admitted=True):
    return json.dumps({"schema": XPC_SCHEMA, "verb": "ping", "report": {
        "euid": 0, "sandboxed": True, "session_phase": "none", "identity_present": identity,
        "container_open": None if admitted is None else {
            "errno": 0, "getpath_errno": 0, "path_matched": True, "admitted": admitted}}})


class DeactivationOutcomeTests(unittest.TestCase):
    """uninstall-app.sh's deactivation table is bound to the host's exit codes."""

    def outcome(self, code, line=None):
        if line is None:
            name = DEACTIVATION_RESULT_NAMES.get(int(code), "x")
            line = f"deactivation_result={name} exit_code={code} needs_user_approval=false"
        result = pipeline("deactivation-outcome", "--exit-code", code, "--result-line", line)
        self.assertEqual(result.returncode, 0, result.stderr)
        return tuple(result.stdout.split())

    def test_every_host_deactivation_exit_code_has_its_named_outcome(self):
        import re
        text = HOST_LIFECYCLE_RS.read_text()
        codes = dict((name, int(value)) for name, value in re.findall(
            r"pub const EXIT_DEACTIVATION_([A-Z_]+): i32 = (\d+);", text))
        self.assertEqual(set(codes), {"COMPLETED", "WILL_COMPLETE_AFTER_REBOOT", "FAILED",
                                      "CANCELLED", "NOT_FOUND", "TIMEOUT_AWAITING_APPROVAL",
                                      "TIMEOUT"})
        self.assertEqual(len(set(codes.values())), len(codes))
        activation = set(int(v) for v in re.findall(r"pub const EXIT_ACTIVATION_[A-Z_]+: i32 = (\d+);", text))
        # Only the completed code is shared with activation.
        self.assertEqual(set(codes.values()) & activation, {0})
        self.assertEqual({DEACTIVATION_RESULT_NAMES[c] for c in codes.values()},
                         {name.lower() for name in codes})
        for name, code in codes.items():
            outcome, status = self.outcome(code)
            self.assertEqual(outcome, name.lower().replace("_", "-"), name)
            self.assertEqual(status, {"COMPLETED": "ok",
                                      "WILL_COMPLETE_AFTER_REBOOT": "pending-reboot"}.get(name, "failed"))
        self.assertIn("DEACTIVATION_TIMEOUT_SECS: u64 = 120;", text)

    def test_a_host_exit_counts_only_with_the_hosts_own_deactivation_line(self):
        for code in (0, 20, 21, 22, 23, 24, 25):
            self.assertEqual(self.outcome(code, ""), ("host-unknown-exit", "failed"), code)
        # An activation line is not a deactivation result.
        self.assertEqual(self.outcome(0, "activation_result=completed exit_code=0"),
                         ("host-unknown-exit", "failed"))
        self.assertEqual(self.outcome(0, "deactivation_result=completed exit_code=20"),
                         ("host-unknown-exit", "failed"))
        self.assertEqual(self.outcome(23, "deactivation_result=completed exit_code=23"),
                         ("host-unknown-exit", "failed"))
        self.assertEqual(self.outcome(0, "deactivation_result=completed exit_code=0"), ("completed", "ok"))
        for code in (1, 10, 11, 13, 14, 65, 69, 75, 127):
            self.assertEqual(self.outcome(code), ("host-unknown-exit", "failed"), code)
        self.assertEqual(self.outcome(2, ""), ("host-usage", "failed"))
        self.assertEqual(self.outcome(142, ""), ("host-unbounded", "failed"))
        self.assertNotEqual(pipeline("deactivation-outcome", "--exit-code", "0").returncode, 0)


class HostReplyParseTests(unittest.TestCase):
    """The forget and ping gates read only an exact host reply shape."""

    def parse(self, command, line):
        result = pipeline(command, "--line", line)
        return result.returncode, result.stdout.strip()

    def test_forget_reply_needs_the_exact_shape(self):
        self.assertEqual(self.parse("forget-reply", forget_line()),
                         (0, "identity_was_present=true key_material_removed=true"))
        self.assertEqual(self.parse("forget-reply", forget_line(False, False)),
                         (0, "identity_was_present=false key_material_removed=false"))
        for bad in (forget_line(removed="true"), forget_line(removed=1), forget_line(extra=True),
                    forget_line().replace("forget-identity", "ping"),
                    forget_line().replace(XPC_SCHEMA, "aegis-ne-xpc-v0"),
                    json.dumps({"schema": XPC_SCHEMA, "refused": "session_live"}),
                    json.dumps({"schema": XPC_SCHEMA, "verb": "forget-identity",
                                "report": {"identity_was_present": True}}),
                    json.dumps({**json.loads(forget_line()), "extra": 1}),
                    "", "not json", "[]"):
            code, _ = self.parse("forget-reply", bad)
            self.assertNotEqual(code, 0, bad)

    def test_ping_identity_counts_absence_only_below_an_admitted_container(self):
        self.assertEqual(self.parse("ping-identity", ping_line()),
                         (0, "identity_present=false container_admitted=true"))
        self.assertEqual(self.parse("ping-identity", ping_line(identity=True)),
                         (0, "identity_present=true container_admitted=true"))
        for admitted in (False, None, "true", 1):
            self.assertEqual(self.parse("ping-identity", ping_line(admitted=admitted)),
                             (0, "identity_present=false container_admitted=false"), admitted)
        for bad in (ping_line(identity="false"), ping_line(identity=0),
                    ping_line().replace('"ping"', '"status"'),
                    ping_line().replace(XPC_SCHEMA, "x"),
                    json.dumps({"schema": XPC_SCHEMA, "verb": "ping", "report": {"identity_present": False}}),
                    forget_line(), "", "{}"):
            code, _ = self.parse("ping-identity", bad)
            self.assertNotEqual(code, 0, bad)


FAKE_UNINSTALL_HOST = """#!/bin/sh
echo "$*" >> "$FAKE_HOST_ARGS"
case "$1" in
--emergency-stop)
    if [ -n "${FAKE_STOP_FAIL:-}" ]; then echo emergency_stop_requested=unknown; echo operation_expired >&2; exit 2; fi
    echo "stop_requested index=0 owner_generation=G native_vpn_status_before=3 on_demand_enabled=false"
    echo "emergency_stop_requested=1 disconnected=unknown"
    exit "${FAKE_STOP_EXIT:-0}" ;;
--remove-profile)
    echo "${FAKE_REMOVE_LINE:-profiles_found=1 profiles_removed=1 removal_failed=0 profiles_remaining=0}"
    exit "${FAKE_REMOVE_EXIT:-0}" ;;
--forget-identity)
    n=$(cat "$FAKE_STATE/forget-count" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$FAKE_STATE/forget-count"
    # The real host writes this banner first on every identity verb, before
    # any refusal or XPC code (authorize_or_exit in src/bin/host.rs).
    echo "administrator approval required for this identity change; answer the system prompt (at most 120s)" >&2
    if [ "$n" -le "${FAKE_FORGET_LIVE:-0}" ]; then echo "provider_refused session_live" >&2; exit 65; fi
    if [ -n "${FAKE_FORGET_UNAVAILABLE:-}" ]; then echo xpc_connection_invalid >&2; exit 69; fi
    if [ -n "${FAKE_FORGET_AUTH_REFUSED:-}" ]; then echo "$FAKE_FORGET_AUTH_REFUSED" >&2; exit 67; fi
    if [ -n "${FAKE_FORGET_REFUSED:-}" ]; then echo "provider_refused $FAKE_FORGET_REFUSED" >&2; exit 65; fi
    echo "$FAKE_FORGET_LINE"
    exit "${FAKE_FORGET_EXIT:-0}" ;;
--identity-gate)
    # v30: the read-only identity gate; an older host has no such verb.
    if [ -n "${FAKE_GATE_UNKNOWN:-}" ]; then
        printf 'unknown_command\nusage: aegis-ne-host --ping | --forget-identity\n' >&2; exit 2
    fi
    if [ -n "${FAKE_GATE_UNAVAILABLE:-}" ]; then echo xpc_connection_invalid >&2; exit 69; fi
    if [ -n "${FAKE_GATE_REFUSED:-}" ]; then echo "provider_refused $FAKE_GATE_REFUSED" >&2; exit 65; fi
    if [ -n "${FAKE_GATE_CLOSED:-}" ]; then
        echo "identity_gate=closed peer=admitted identity_rule=admitted proof_rule=admitted proof_probe=denied"
        echo "identity_gate_closed $FAKE_GATE_CLOSED" >&2; exit 65
    fi
    echo '{"schema":"aegis-ne-xpc-v1","verb":"identity-gate","report":{}}'
    echo "identity_gate=open peer=admitted identity_rule=unregistered proof_rule=admitted proof_probe=allowed" ;;
--ping)
    if [ -n "${FAKE_IMPORT_DURING_RUN:-}" ]; then echo "import_attempt unix_ns=9 pid=1" >> "$FAKE_IMPORT_DURING_RUN"; fi
    if [ -n "${FAKE_PING_UNAVAILABLE:-}" ]; then echo xpc_connection_invalid >&2; exit 69; fi
    echo "$FAKE_PING_LINE" ;;
--remove-filter)
    if [ -n "${2:-}" ]; then
        if [ -n "${FAKE_NO_FILTER:-}" ]; then
            printf 'unknown_command\nusage: aegis-ne-host --ping | --deactivate [PROVIDER_ID]\n' >&2; exit 2
        fi
        if [ -n "${FAKE_FILTER_PROBE_ACCEPTS:-}" ]; then exit 0; fi
        printf '%s\nusage: aegis-ne-host --filter-status | --remove-filter | --deactivate [PROVIDER_ID]\n' \
            "${FAKE_FILTER_PROBE_REFUSAL:-filter_operand_refused}" >&2
        exit "${FAKE_FILTER_PROBE_EXIT:-2}"
    fi
    # v26: the real host writes this banner first, after its parser
    # (approve_filter_or_exit in src/bin/host.rs).
    echo "administrator approval required for this leak-guard change; answer the system prompt (at most 120s)" >&2
    if [ -n "${FAKE_REMOVE_FILTER_AUTH_REFUSED:-}" ]; then
        echo "filter_result=authorization_refused exit_code=67 filter_changed=false"
        echo "$FAKE_REMOVE_FILTER_AUTH_REFUSED" >&2; exit 67
    fi
    echo "${FAKE_REMOVE_FILTER_LINE:-filter_result=ok exit_code=0 filter_found=1 filter_remaining=0}"
    exit "${FAKE_REMOVE_FILTER_EXIT:-0}" ;;
--filter-status)
    echo "${FAKE_FILTER_STATUS_LINE:-filter_result=not_configured exit_code=30 configured=false enabled=false filter_packets=false filter_sockets=false packet_bundle_id=none grade=firewall attached=unknown}"
    exit "${FAKE_FILTER_STATUS_EXIT:-30}" ;;
--deactivate)
    if [ -n "${FAKE_NO_DEACTIVATE:-}" ]; then
        printf 'unknown_command\nusage: aegis-ne-host --ping | --forget-identity | --request-activation PROVIDER_ID\n' >&2
        exit 2
    fi
    if [ "${2:-}" != dev.aegis.macos.PacketTunnel ]; then
        if [ -n "${FAKE_PROBE_ACCEPTS:-}" ]; then exit 0; fi
        printf '%s\n%s\n' "${FAKE_PROBE_REFUSAL:-provider_id_mismatch}" \
            "${FAKE_PROBE_USAGE:-usage: aegis-ne-host --ping | --deactivate [PROVIDER_ID] | --forget-identity}" >&2
        exit "${FAKE_PROBE_EXIT:-2}"
    fi
    if [ -n "${FAKE_DEACT_APPROVAL:-}" ]; then echo "System Settings approval required; no automatic approval." >&2; fi
    echo "Deactivation request finished." >&2
    if [ -n "$FAKE_DEACT_LINE" ]; then echo "$FAKE_DEACT_LINE"; fi
    exit "${FAKE_DEACT_EXIT:-0}" ;;
*) exit 2 ;;
esac
"""

# uninstall-app.sh's parse-only capability probe; calls() leaves it out.
CAPABILITY_PROBE = "--deactivate capability-probe"
# v30: the read-only identity gate after the probe; calls() leaves it out.
IDENTITY_GATE = "--identity-gate"
PREFLIGHT = [CAPABILITY_PROBE, IDENTITY_GATE]
# S20b: the filter probe, removal and verification after --remove-profile;
# calls() leaves them out too, the filter tests read raw_calls().
FILTER_PROBE = "--remove-filter capability-probe"
FILTER_CALLS = [FILTER_PROBE, "--remove-filter", "--filter-status"]
UNINSTALL_ORDER = ["--emergency-stop", "--remove-profile", "--forget-identity", "--ping",
                   "--deactivate " + PROVIDER]
UNINSTALL_STAGES = ["verify", "identity-gate", "emergency-stop", "remove-profile", "remove-filter",
                    "verify-filter-absent", "forget-identity",
                    "verify-identity-absent", "deactivate", "move-app", "report-container"]


class UninstallBehaviorTests(unittest.TestCase):
    """Runs uninstall-app.sh for real against fake codesign/spctl and a fake
    host answering each verb. Proves only the script's ordering, gates and
    records, never an Apple deactivation or a provider forget."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-s21-uninstall-")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name).resolve()
        self.bin = self.root / "bin"
        for name, body in FAKE_TOOLS.items():
            write_mode(self.bin / name, body, 0o755)
        self.dest = self.root / "Applications"
        self.state = self.root / "state"
        self.artifacts = self.root / "artifacts"
        self.fake_state = self.root / "fake"
        self.fake_state.mkdir()
        self.host_args = self.root / "host-args"
        self.app = make_app(self.dest, "9")
        write_mode(self.app / "Contents" / "MacOS" / "aegis-ne-host", FAKE_UNINSTALL_HOST, 0o755)
        self.container = self.root / "Library" / "Group Containers" / GROUP
        write_mode(self.container / "Library" / "kept", "owner data\n", 0o600)

    def run_uninstall(self, *args, deact_exit=0, deact_line=None, **env_extra):
        name = DEACTIVATION_RESULT_NAMES.get(deact_exit, "x")
        env = {"PATH": f"{self.bin}:{pathlib.Path(sys.executable).parent}:/usr/bin:/bin:/usr/sbin:/sbin",
               "HOME": str(self.root), "TMPDIR": str(self.root),
               "FAKE_HOST_ARGS": str(self.host_args), "FAKE_STATE": str(self.fake_state),
               "FAKE_FORGET_LINE": forget_line(), "FAKE_PING_LINE": ping_line(),
               "FAKE_DEACT_EXIT": str(deact_exit),
               "FAKE_DEACT_LINE": (f"deactivation_result={name} exit_code={deact_exit} "
                                   "will_complete_after_reboot=false needs_user_approval=false"
                                   if deact_line is None else deact_line)}
        env.update({k: str(v) for k, v in env_extra.items()})
        return subprocess.run(["/bin/bash", str(UNINSTALL_SH), "--dest", self.dest,
                               "--state-dir", self.state, "--artifacts-dir", self.artifacts,
                               *map(str, args)],
                              check=False, capture_output=True, text=True, env=env)

    def raw_calls(self):
        return self.host_args.read_text().splitlines() if self.host_args.exists() else []

    def calls(self):
        """Host verbs after verify; each run begins with the probe."""
        raw = self.raw_calls()
        return [call for call in raw if call not in PREFLIGHT and call not in FILTER_CALLS]

    def receipts(self):
        directory = self.artifacts / "uninstall" / "receipts"
        # Run order: names of runs within one second do not sort by run.
        paths = sorted(directory.glob("*.json"), key=lambda p: p.stat().st_mtime_ns) \
            if directory.exists() else []
        return [json.loads(p.read_text()) for p in paths]

    def uninstalled(self):
        directory = self.state / "uninstalled"
        return sorted(directory.iterdir()) if directory.exists() else []

    def assert_app_in_place(self):
        self.assertTrue((self.dest / "AEGIS.app" / "Contents" / "Info.plist").is_file())
        self.assertEqual(self.uninstalled(), [])

    def assert_container_kept(self):
        self.assertEqual((self.container / "Library" / "kept").read_text(), "owner data\n")

    def test_steps_run_in_order_and_the_app_is_moved_not_deleted(self):
        result = self.run_uninstall()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.raw_calls(), PREFLIGHT + UNINSTALL_ORDER[:2] + FILTER_CALLS
                         + UNINSTALL_ORDER[2:])
        self.assertFalse((self.dest / "AEGIS.app").exists())
        [backup] = self.uninstalled()
        self.assertRegex(backup.name, r"^AEGIS\.app\.uninstalled-9-\d{8}T\d{6}Z$")
        self.assertEqual(plistlib.loads((backup / "Contents" / "Info.plist").read_bytes())
                         ["CFBundleVersion"], "9")
        self.assert_container_kept()
        self.assertIn(f"app group container left in place (the owner decides whether to remove it): "
                      f"{self.container} (present=true)", result.stdout)
        [receipt] = self.receipts()
        self.assertEqual([s["stage"] for s in receipt["stages"]], UNINSTALL_STAGES)
        self.assertEqual({s["status"] for s in receipt["stages"]}, {"ok"})
        self.assertEqual(receipt["uninstall_result"], "uninstalled")
        self.assertEqual(receipt["uninstalled_app_path"], str(backup))
        self.assertEqual(receipt["app_group_container_path"], str(self.container))
        self.assertIs(receipt["app_group_container_present"], True)
        self.assertEqual(receipt["forget_report"], "identity_was_present=true key_material_removed=true")
        self.assertEqual(receipt["ping_identity"], "identity_present=false container_admitted=true")
        self.assertEqual(receipt["deactivation_outcome"], "completed")
        self.assertEqual(receipt["deactivation_exit_code"], 0)
        self.assertEqual(receipt["identity_absence"], "verified")
        self.assertIs(receipt["identity_unverified_allowed"], False)
        self.assertNotIn("deactivation_accepted_as", receipt)
        self.assertEqual(receipt["remove_profile_line"],
                         "profiles_found=1 profiles_removed=1 removal_failed=0 profiles_remaining=0")
        self.assertEqual(receipt["filter_removal"], "removed")
        self.assertEqual(receipt["remove_filter_line"],
                         "filter_result=ok exit_code=0 filter_found=1 filter_remaining=0")
        self.assertTrue(receipt["filter_status_line"].startswith(
            "filter_result=not_configured exit_code=30 configured=false "))
        self.assertRegex(receipt["host_cdhash"], r"^[0-9a-f]{40}$")
        # The marker of this run was consumed by its own move.
        self.assertFalse((self.state / "uninstall" / "deactivated.txt").exists())
        self.assertTrue(receipt["consumed_marker"])
        self.assertFalse((self.state / "uninstall" / "identity-absent.txt").exists())
        consumed = pathlib.Path(receipt["consumed_identity_marker"])
        self.assertIn("phase=identity-absent", consumed.read_text())
        self.assertFalse((self.state / "uninstall" / ".lock").exists())
        # Receipts, logs and the moved app's parent are owner-only.
        self.assertEqual(os.stat(self.artifacts / "uninstall" / "receipts").st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(self.state / "uninstalled").st_mode & 0o777, 0o700)

    def test_the_filter_is_removed_and_verified_absent_before_the_forget(self):
        ordered = PREFLIGHT + UNINSTALL_ORDER[:2] + FILTER_CALLS
        cases = [
            # removal failed, or the line is not the exact success line
            ({"FAKE_REMOVE_FILTER_EXIT": 34,
              "FAKE_REMOVE_FILTER_LINE": "filter_result=failed exit_code=34 filter_removed=unknown"},
             "remove-filter", "host exit 34: filter_result=failed", ordered[:6]),
            ({"FAKE_REMOVE_FILTER_LINE": "filter_result=ok exit_code=0 filter_found=1 filter_remaining=1"},
             "remove-filter", "host exit 0", ordered[:6]),
            # still configured after the removal (or a status that is not absence)
            ({"FAKE_FILTER_STATUS_EXIT": 0, "FAKE_FILTER_STATUS_LINE":
              "filter_result=ok exit_code=0 configured=true enabled=true"},
             "verify-filter-absent", "packet filter still configured", ordered),
            ({"FAKE_FILTER_STATUS_EXIT": 31, "FAKE_FILTER_STATUS_LINE":
              "filter_result=disabled exit_code=31 configured=true enabled=false"},
             "verify-filter-absent", "host exit 31", ordered),
            ({"FAKE_FILTER_STATUS_EXIT": 34, "FAKE_FILTER_STATUS_LINE":
              "filter_result=failed exit_code=34 configured=unknown"},
             "verify-filter-absent", "host exit 34", ordered),
            ({"FAKE_REMOVE_FILTER_EXIT": 37},
             "remove-filter", "host exit 37", ordered[:6]),
            # v26: no administrator approved the removal; the code, never
            # the banner, is reported
            ({"FAKE_REMOVE_FILTER_AUTH_REFUSED": "filter_authorization_cancelled"},
             "remove-filter",
             "administrator approval not given (host exit 67: filter_authorization_cancelled); "
             "the packet filter was not removed", ordered[:6]),
            ({"FAKE_FILTER_STATUS_EXIT": 30, "FAKE_FILTER_STATUS_LINE":
              "filter_result=disabled exit_code=31 configured=true enabled=false"},
             "verify-filter-absent", "host exit 30", ordered),
            ({"FAKE_FILTER_STATUS_EXIT": 0, "FAKE_FILTER_STATUS_LINE":
              "filter_result=not_configured exit_code=30 configured=false enabled=false"},
             "verify-filter-absent", "host exit 0", ordered),
            # a probe answer that is neither the S20b parser nor an older host
            ({"FAKE_FILTER_PROBE_ACCEPTS": 1}, "remove-filter", "filter probe with exit 0", ordered[:5]),
            ({"FAKE_FILTER_PROBE_EXIT": 0}, "remove-filter", "filter probe with exit 0", ordered[:5]),
            ({"FAKE_FILTER_PROBE_REFUSAL": "provider_id_mismatch"}, "remove-filter",
             "filter probe with exit 2: provider_id_mismatch", ordered[:5]),
        ]
        for env, failed, message, calls in cases:
            with self.subTest(env=env):
                self.host_args.unlink(missing_ok=True)
                before = len(self.receipts())
                result = self.run_uninstall(**env)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn(message, result.stderr)
                # Nothing is forgotten or deactivated after a filter failure.
                self.assertEqual(self.raw_calls(), calls)
                self.assert_app_in_place()
                receipt = self.receipts()[before]
                self.assertEqual(receipt["uninstall_result"], "failed-at-" + failed)
                self.assertEqual(receipt["stages"][-1]["stage"], failed)
                self.assertNotIn("forget_report", receipt)

    def test_an_exit_67_names_the_remedy_its_refusal_code_needs(self):
        # v26 review: only a prompt that was shown is fixed by a rerun.
        rerun = "Run this script again and approve the prompt"
        weak = "running this script again will not help"
        # v30: the password-only rights under their new names.
        filter_right, identity_right = "dev.aegis.macos.leak-guard-change", "dev.aegis.macos.identity-change"
        cases = []
        for prefix, variable, right, failed in (
                ("filter", "FAKE_REMOVE_FILTER_AUTH_REFUSED", filter_right, "remove-filter"),
                ("identity", "FAKE_FORGET_AUTH_REFUSED", identity_right, "forget-identity")):
            for code in ("cancelled", "denied", "timeout"):
                cases.append((variable, f"{prefix}_authorization_{code}", failed, [rerun], [weak]))
            cases.append((variable, f"{prefix}_authorization_right_inadmissible", failed,
                          [weak, f"sudo security authorizationdb remove {right}"], [rerun]))
            for code in ("right_unregistered", "unavailable"):
                cases.append((variable, f"{prefix}_authorization_{code}", failed,
                              [weak, f"security authorizationdb read {right}"], [rerun, "remove " + right]))
            cases.append((variable, f"{prefix}_authorization_other", failed,
                          ["troubleshooting.md (exit 67)"], [rerun]))
        for variable, code, failed, present, absent in cases:
            with self.subTest(code=code):
                self.host_args.unlink(missing_ok=True)
                (self.fake_state / "forget-count").unlink(missing_ok=True)
                before = len(self.receipts())
                result = self.run_uninstall(**{variable: code})
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn(f"administrator approval not given (host exit 67: {code})", result.stderr)
                for text in present:
                    self.assertIn(text, result.stderr)
                for text in absent:
                    self.assertNotIn(text, result.stderr)
                self.assert_app_in_place()
                self.assertEqual(self.receipts()[before]["uninstall_result"], "failed-at-" + failed)
                self.assertNotIn("deactivation_outcome", self.receipts()[before])

    def test_an_uninstalled_v25_copy_loses_its_host_and_other_copies_keep_theirs(self):
        result = self.run_uninstall()
        self.assertEqual(result.returncode, 0, result.stderr)
        [kept] = self.uninstalled()
        self.assertTrue((kept / "Contents" / "MacOS" / "aegis-ne-host").is_file())
        self.assertEqual(self.receipts()[-1]["uninstalled_host_disarm"], "weak_host=no version=9")
        # v25: the filter verbs without the administrator prompt.
        make_app(self.dest, "25")
        host = self.dest / "AEGIS.app" / "Contents" / "MacOS" / "aegis-ne-host"
        write_mode(host, FAKE_UNINSTALL_HOST, 0o755)
        digest = sha256_file(host)
        (self.fake_state / "forget-count").unlink(missing_ok=True)
        result = self.run_uninstall()
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = self.receipts()[-1]
        backup = pathlib.Path(receipt["uninstalled_app_path"])
        self.assertRegex(backup.name, r"^AEGIS\.app\.uninstalled-25-")
        self.assertFalse((backup / "Contents" / "MacOS" / "aegis-ne-host").exists())
        self.assertIn(f"sha256={digest}\n",
                      (backup / "Contents" / "MacOS" / "aegis-ne-host.removed").read_text())
        self.assertEqual(receipt["uninstalled_host_disarm"],
                         f"weak_host=disarmed version=25 host_sha256={digest}")
        self.assertIn(f"uninstalled copy {backup}: weak_host=disarmed", result.stdout)
        self.assertEqual(receipt["uninstall_result"], "uninstalled")
        self.assertTrue((kept / "Contents" / "MacOS" / "aegis-ne-host").is_file())

    def test_a_host_older_than_the_filter_verbs_is_recorded_as_unsupported(self):
        result = self.run_uninstall(FAKE_NO_FILTER=1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.raw_calls(), PREFLIGHT + UNINSTALL_ORDER[:2] + [FILTER_PROBE]
                         + UNINSTALL_ORDER[2:])
        [receipt] = self.receipts()
        self.assertEqual(receipt["filter_removal"], "unsupported_by_host")
        statuses = {s["stage"]: s["status"] for s in receipt["stages"]}
        self.assertEqual(statuses["remove-filter"], "skipped")
        self.assertEqual(statuses["verify-filter-absent"], "skipped")
        self.assertEqual(receipt["uninstall_result"], "uninstalled")
        # A v25 host must have the filter verbs: the same answer fails there.
        self.app = make_app(self.root / "v25", "25")
        subprocess.run(["rm", "-rf", str(self.dest / "AEGIS.app")], check=True)
        subprocess.run(["mv", str(self.app), str(self.dest / "AEGIS.app")], check=True)
        write_mode(self.dest / "AEGIS.app" / "Contents" / "MacOS" / "aegis-ne-host", FAKE_UNINSTALL_HOST, 0o755)
        self.host_args.unlink(missing_ok=True)
        result = self.run_uninstall(FAKE_NO_FILTER=1)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("answered the filter probe with exit 2: unknown_command", result.stderr)
        self.assertEqual(self.raw_calls(), PREFLIGHT + UNINSTALL_ORDER[:2] + [FILTER_PROBE])
        self.assertTrue((self.dest / "AEGIS.app").is_dir())
        self.assertEqual(self.receipts()[-1]["uninstall_result"], "failed-at-remove-filter")
        # The host parser and the script agree on the probe's refusal code.
        self.assertIn('pub const FILTER_OPERAND_REFUSED: &str = "filter_operand_refused";',
                      HOST_LIFECYCLE_RS.read_text())
        self.assertIn("filter_operand_refused", UNINSTALL_SH.read_text())
        self.assertIn("FILTER_MIN_PRIOR=24\n", UNINSTALL_SH.read_text())

    def test_identity_still_present_after_forget_refuses_before_deactivation(self):
        cases = [
            ({"FAKE_PING_LINE": ping_line(identity=True)}, "identity still present after --forget-identity",
             "verify-identity-absent", UNINSTALL_ORDER[:4]),
            ({"FAKE_PING_LINE": ping_line(admitted=False)}, "identity absence not verified",
             "verify-identity-absent", UNINSTALL_ORDER[:4]),
            ({"FAKE_PING_LINE": ping_line(admitted=None)}, "identity absence not verified",
             "verify-identity-absent", UNINSTALL_ORDER[:4]),
            ({"FAKE_PING_LINE": forget_line()}, "unparsed ping reply",
             "verify-identity-absent", UNINSTALL_ORDER[:4]),
            ({"FAKE_FORGET_LINE": forget_line(removed=False), "FAKE_FORGET_EXIT": 74},
             "could not remove its key material", "forget-identity", UNINSTALL_ORDER[:3]),
            # A zero exit never overrides the reply's own removal flag.
            ({"FAKE_FORGET_LINE": forget_line(removed=False)}, "key material not removed",
             "forget-identity", UNINSTALL_ORDER[:3]),
            ({"FAKE_FORGET_UNAVAILABLE": 1}, "identity absence cannot be verified",
             "forget-identity", UNINSTALL_ORDER[:3]),
            # The approval banner is never reported in place of the code.
            ({"FAKE_FORGET_UNAVAILABLE": 1}, "provider unavailable (host exit 69: xpc_connection_invalid)",
             "forget-identity", UNINSTALL_ORDER[:3]),
            # No administrator approval (cancelled prompt): nothing was
            # sent, never retried, nothing deactivated.
            ({"FAKE_FORGET_AUTH_REFUSED": "identity_authorization_cancelled"},
             "administrator approval not given (host exit 67: identity_authorization_cancelled)",
             "forget-identity", UNINSTALL_ORDER[:3]),
            # Only a live session is retried; any other refusal stops at once.
            ({"FAKE_FORGET_REFUSED": "identity_verbs_unavailable"},
             "host exit 65 after 1 attempt(s): provider_refused identity_verbs_unavailable",
             "forget-identity", UNINSTALL_ORDER[:3]),
        ]
        for env, message, failed, calls in cases:
            with self.subTest(message=message, env=env):
                self.host_args.unlink(missing_ok=True)
                (self.fake_state / "forget-count").unlink(missing_ok=True)
                before = len(self.receipts())
                result = self.run_uninstall(**env)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn(message, result.stderr)
                self.assertEqual(self.calls(), calls)
                self.assert_app_in_place()
                self.assert_container_kept()
                receipt = self.receipts()[before]
                self.assertEqual(receipt["stages"][-1], receipt["stages"][-1] | {"stage": failed, "status": "failed"})
                self.assertEqual(receipt["uninstall_result"], "failed-at-" + failed)
                self.assertNotIn("deactivation_outcome", receipt)
                self.assertFalse((self.state / "uninstall" / "deactivated.txt").exists())
                # No verified forget, no marker that would skip the next one.
                self.assertFalse((self.state / "uninstall" / "identity-absent.txt").exists())

    def test_a_second_run_is_idempotent(self):
        first = self.run_uninstall()
        self.assertEqual(first.returncode, 0, first.stderr)
        [backup] = self.uninstalled()
        calls = self.calls()
        second = self.run_uninstall()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("is absent: nothing to stop, forget, deactivate or move", second.stdout)
        self.assertIn(f"latest uninstalled copy: {backup}", second.stdout)
        self.assertEqual(self.calls(), calls)
        self.assertEqual(self.uninstalled(), [backup])
        self.assertTrue((backup / "Contents" / "Info.plist").is_file())
        self.assert_container_kept()
        first_receipt, second_receipt = self.receipts()
        self.assertEqual(first_receipt["uninstall_result"], "uninstalled")
        self.assertEqual(second_receipt["uninstall_result"], "already-absent")
        self.assertEqual([s["stage"] for s in second_receipt["stages"]], UNINSTALL_STAGES)
        self.assertEqual({s["status"] for s in second_receipt["stages"][:-1]}, {"skipped"})
        self.assertNotEqual(first_receipt["run_id"], second_receipt["run_id"])

    def test_dry_run_performs_nothing(self):
        result = self.run_uninstall("--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), [])
        self.assert_app_in_place()
        self.assert_container_kept()
        self.assertFalse(self.state.exists())
        self.assertFalse(self.artifacts.exists())
        printed = [line for line in result.stdout.splitlines() if line.startswith("+ ")]
        host = str(self.app / "Contents" / "MacOS" / "aegis-ne-host")
        verbs = [line.split(host, 1)[1].split("  #")[0].strip() for line in printed if host in line]
        self.assertEqual(verbs, ["--deactivate capability-probe", "--identity-gate", "--emergency-stop", "--remove-profile",
                                 FILTER_PROBE, "--remove-filter", "--filter-status",
                                 "--forget-identity", "--ping", "--deactivate " + PROVIDER])
        self.assertIn("codesign --verify --deep --strict", result.stdout)
        self.assertRegex(printed[-1], r"^\+ bounded 120 mv .*AEGIS\.app .*AEGIS\.app\.uninstalled-9-")
        self.assertIn("dry run complete: nothing was executed or written", result.stdout)
        # Absent app: dry run also writes nothing.
        empty = self.root / "empty"
        empty.mkdir()
        result = self.run_uninstall("--dry-run", "--dest", empty)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.state.exists())
        self.assertFalse(self.artifacts.exists())

    def test_each_non_completed_deactivation_keeps_the_app(self):
        cases = [
            (20, None, "completes after a reboot", "will-complete-after-reboot", "pending-reboot"),
            (21, None, "deactivation failed (host exit 21)", "failed", "failed"),
            (22, None, "deactivation cancelled (host exit 22)", "cancelled", "failed"),
            (23, None, "Apple reports no such extension", "not-found", "failed"),
            (24, None, "approval still pending after 120s", "timeout-awaiting-approval", "failed"),
            (25, None, "deactivation timeout (host exit 25)", "timeout", "failed"),
            (3, "deactivation_result=x exit_code=3", "host-unknown-exit", "host-unknown-exit", "failed"),
            (0, "", "host-unknown-exit", "host-unknown-exit", "failed"),
            (0, "activation_result=completed exit_code=0", "host-unknown-exit", "host-unknown-exit", "failed"),
        ]
        for code, line, message, outcome, status in cases:
            with self.subTest(code=code, line=line):
                self.host_args.unlink(missing_ok=True)
                before = len(self.receipts())
                result = self.run_uninstall(deact_exit=code, deact_line=line)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn(message, result.stderr)
                self.assertEqual(self.calls(), UNINSTALL_ORDER)
                self.assert_app_in_place()
                receipt = self.receipts()[before]
                self.assertEqual(receipt["deactivation_outcome"], outcome)
                self.assertEqual(receipt["deactivation_exit_code"], code)
                self.assertEqual(receipt["stages"][-1]["stage"], "deactivate")
                self.assertEqual(receipt["stages"][-1]["status"], status)
                marker = self.state / "uninstall" / "deactivated.txt"
                self.assertEqual(marker.exists(), outcome == "will-complete-after-reboot", outcome)
                marker.unlink(missing_ok=True)
                # The verified forget is recorded before every outcome.
                absent = self.state / "uninstall" / "identity-absent.txt"
                self.assertTrue(absent.is_file(), outcome)
                absent.unlink()
        # Approval then completion records that approval was needed.
        result = self.run_uninstall(FAKE_DEACT_APPROVAL=1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIs(self.receipts()[-1]["deactivation_needed_approval"], True)

    def test_a_live_session_retries_the_forget_a_bounded_number_of_times(self):
        result = self.run_uninstall(FAKE_FORGET_LIVE=1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), UNINSTALL_ORDER[:2] + ["--forget-identity"] + UNINSTALL_ORDER[2:])
        self.assertEqual(self.receipts()[-1]["forget_attempts"], 2)
        # A session that never ends stops after five attempts, before ping.
        self.app = make_app(self.dest, "9")
        write_mode(self.app / "Contents" / "MacOS" / "aegis-ne-host", FAKE_UNINSTALL_HOST, 0o755)
        self.host_args.unlink()
        (self.fake_state / "forget-count").unlink()
        result = self.run_uninstall(FAKE_FORGET_LIVE=99)
        self.assertEqual(result.returncode, 1)
        self.assertIn("host exit 65 after 5 attempt(s): provider_refused session_live", result.stderr)
        self.assertEqual(self.calls(), UNINSTALL_ORDER[:2] + ["--forget-identity"] * 5)
        self.assertTrue((self.dest / "AEGIS.app").is_dir())

    def test_earlier_step_failures_stop_every_later_step(self):
        for env, message, calls in (
                ({"FAKE_STOP_FAIL": 1}, "emergency-stop: host exit 2: operation_expired", 1),
                # A result line with a non-zero exit is still refused.
                ({"FAKE_STOP_EXIT": 2}, "emergency-stop: host exit 2", 1),
                ({"FAKE_REMOVE_LINE": "profiles_found=2 profiles_removed=1 removal_failed=1 profiles_remaining=1",
                  "FAKE_REMOVE_EXIT": 2}, "remove-profile: host exit 2", 2),
                # A zero exit with profiles remaining is still refused.
                ({"FAKE_REMOVE_LINE": "profiles_found=1 profiles_removed=0 removal_failed=0 profiles_remaining=1"},
                 "remove-profile: host exit 0", 2)):
            with self.subTest(message=message):
                self.host_args.unlink(missing_ok=True)
                result = self.run_uninstall(**env)
                self.assertEqual(result.returncode, 1)
                self.assertIn(message, result.stderr)
                self.assertEqual(self.calls(), UNINSTALL_ORDER[:calls])
                self.assert_app_in_place()

    def test_an_unverified_or_linked_app_runs_no_host_verb(self):
        result = self.run_uninstall(FAKE_SPCTL_SOURCE="Unnotarized Developer ID")
        self.assertEqual(result.returncode, 1)
        self.assertIn("verify: installed app is not accepted as Notarized Developer ID", result.stderr)
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.receipts()[-1]["uninstall_result"], "failed-at-verify")
        info = self.app / "Contents" / "Info.plist"
        original = info.read_bytes()
        info.write_bytes(plistlib.dumps({"CFBundleIdentifier": APP + ".Other", "CFBundleVersion": "9"}))
        result = self.run_uninstall()
        self.assertIn("unexpected host bundle identifier", result.stderr)
        info.write_bytes(original)
        real = self.root / "elsewhere" / "AEGIS.app"
        real.parent.mkdir()
        os.rename(self.app, real)
        os.symlink(real, self.dest / "AEGIS.app")
        result = self.run_uninstall()
        self.assertEqual(result.returncode, 1)
        self.assertIn("is not an app directory", result.stderr)
        self.assertEqual(self.calls(), [])
        self.assertTrue((self.dest / "AEGIS.app").is_symlink())
        self.assertTrue(real.is_dir())

    def test_a_rerun_after_a_failed_move_skips_only_while_the_provider_is_gone(self):
        # The move fails (the uninstalled directory cannot be created).
        write_mode(self.state / "uninstalled", "not a directory\n", 0o600)
        result = self.run_uninstall()
        self.assertEqual(result.returncode, 1)
        self.assertIn("move-app: cannot create", result.stderr)
        marker = self.state / "uninstall" / "deactivated.txt"
        absent = self.state / "uninstall" / "identity-absent.txt"
        self.assertTrue(marker.is_file())
        self.assertIn("outcome=completed", marker.read_text())
        self.assertIn("phase=identity-absent", absent.read_text())
        (self.state / "uninstalled").unlink()
        self.assertTrue((self.dest / "AEGIS.app").is_dir())

        # Markers of other CDHashes are not this app's: the forget is needed
        # and an unreachable provider refuses.
        original, original_absent = marker.read_text(), absent.read_text()
        for tampered in ("host_cdhash=", "provider_cdhash="):
            with self.subTest(tampered=tampered):
                marker.write_text(original.replace(tampered, tampered + "0"))
                absent.write_text(original_absent.replace(tampered, tampered + "0"))
                self.host_args.unlink()
                result = self.run_uninstall(FAKE_PING_UNAVAILABLE=1, FAKE_FORGET_UNAVAILABLE=1)
                self.assertEqual(result.returncode, 1)
                self.assertIn("identity absence cannot be verified", result.stderr)
                self.assertEqual(self.calls(), UNINSTALL_ORDER[:3])
                # The foreign markers were retired, not deleted.
                self.assertFalse(marker.exists())
                self.assertFalse(absent.exists())
        retired = sorted(p.name for p in (self.state / "uninstall").glob("*-stale-*.txt"))
        self.assertEqual(len(retired), 4, retired)
        # A linked marker is never honoured (either kind).
        for linked, other in ((marker, absent), (absent, marker)):
            with self.subTest(linked=linked.name):
                elsewhere = self.root / ("elsewhere-" + linked.name)
                elsewhere.write_text(original if linked == marker else original_absent)
                os.symlink(elsewhere, linked)
                self.host_args.unlink()
                result = self.run_uninstall(FAKE_PING_UNAVAILABLE=1, FAKE_FORGET_UNAVAILABLE=1)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(self.calls(), UNINSTALL_ORDER[:3])
                self.assertTrue((self.dest / "AEGIS.app").is_dir())
                self.assertTrue(elsewhere.is_file())
                linked.unlink(missing_ok=True)
                self.assertFalse(other.exists())
        marker.write_text(original)
        absent.write_text(original_absent)

        # This app's marker while the provider still answers: everything again.
        self.host_args.unlink()
        (self.fake_state / "forget-count").unlink(missing_ok=True)
        write_mode(self.state / "uninstalled", "not a directory\n", 0o600)
        result = self.run_uninstall()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.calls(), UNINSTALL_ORDER[:2] + ["--ping"] + UNINSTALL_ORDER[2:])
        (self.state / "uninstalled").unlink()

        # This app's marker and an unavailable provider: forget, ping and
        # deactivation are not repeated; stop, removal and the move are.
        self.host_args.unlink()
        result = self.run_uninstall(FAKE_PING_UNAVAILABLE=1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), UNINSTALL_ORDER[:2] + ["--ping"])
        self.assertFalse((self.dest / "AEGIS.app").exists())
        receipt = self.receipts()[-1]
        self.assertEqual([s["status"] for s in receipt["stages"]],
                         ["ok", "ok", "ok", "ok", "ok", "ok", "done-earlier", "done-earlier", "done-earlier", "ok",
                          "ok"])
        self.assertEqual(receipt["uninstall_result"], "uninstalled")
        self.assertEqual(receipt["identity_absence"], "verified-earlier")
        self.assertFalse(marker.exists())
        self.assertFalse(absent.exists())
        self.assertTrue(pathlib.Path(receipt["consumed_marker"]).is_file())
        self.assertTrue(pathlib.Path(receipt["consumed_identity_marker"]).is_file())

    def reset_app(self):
        """A fresh copy of the same app (same CDHashes) at the destination."""
        self.app = make_app(self.dest, "9")
        write_mode(self.app / "Contents" / "MacOS" / "aegis-ne-host", FAKE_UNINSTALL_HOST, 0o755)
        self.host_args.unlink(missing_ok=True)
        (self.fake_state / "forget-count").unlink(missing_ok=True)

    def install_version(self, version):
        """The installed app replaced by one of CFBundleVersion `version`."""
        subprocess.run(["rm", "-rf", str(self.dest / "AEGIS.app")], check=True)
        self.app = make_app(self.dest, version)
        write_mode(self.app / "Contents" / "MacOS" / "aegis-ne-host", FAKE_UNINSTALL_HOST, 0o755)
        self.host_args.unlink(missing_ok=True)
        (self.fake_state / "forget-count").unlink(missing_ok=True)

    def test_a_closed_identity_gate_stops_before_anything_changes(self):
        # v30: the v29 run stopped at the forget after the profile and the
        # filter were gone; a gate that would refuse the forget now stops
        # the run before any verb with an effect.
        nothing = "nothing was stopped, removed or forgotten"
        cases = [
            ({"FAKE_GATE_CLOSED": "proof_probe_denied"}, "30",
             "identity gate closed (host exit 65: identity_gate_closed proof_probe_denied)",
             "provider's sandbox did not let it check an administrator approval"),
            # v30 review: an authd error in the provider's own check is no
            # sandbox answer; the provider probes again on the next request.
            ({"FAKE_GATE_CLOSED": "proof_probe_failed"}, "30", "identity_gate_closed proof_probe_failed",
             "(an Authorization Services error, not a sandbox refusal); it checks again on the next request: "
             "run this script again"),
            ({"FAKE_GATE_CLOSED": "proof_probe_unavailable"}, "30", "identity_gate_closed proof_probe_unavailable",
             "it checks again on the next request: run this script again"),
            ({"FAKE_GATE_CLOSED": "identity_rule_inadmissible"}, "30", "identity_rule_inadmissible",
             "sudo security authorizationdb remove dev.aegis.macos.identity-change"),
            ({"FAKE_GATE_CLOSED": "peer_not_admin"}, "30", "peer_not_admin", "an administrator outside Setup Assistant"),
            ({"FAKE_GATE_CLOSED": "proof_rule_unexpected"}, "30", "proof_rule_unexpected",
             "security authorizationdb read system.services.systemconfiguration.network"),
            # A v30 host whose active provider is older.
            ({"FAKE_GATE_REFUSED": "unknown_verb"}, "30", "host exit 65: provider_refused unknown_verb",
             "The active provider predates v30"),
            # A v30 host must answer the gate.
            ({"FAKE_GATE_UNKNOWN": 1}, "30", "identity gate closed (host exit 2: unknown_command)", "troubleshooting.md"),
        ]
        for env, version, message, advice in cases:
            with self.subTest(env=env):
                self.install_version(version)
                result = self.run_uninstall(**env)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn(message, result.stderr)
                self.assertIn(advice, result.stderr)
                if env.get("FAKE_GATE_CLOSED", "").startswith("proof_probe_") \
                        and env["FAKE_GATE_CLOSED"] != "proof_probe_denied":
                    self.assertNotIn("sandbox did not let it check", result.stderr)
                self.assertIn(nothing, result.stderr)
                self.assertEqual(self.raw_calls(), PREFLIGHT)
                self.assert_app_in_place()
                receipt = self.receipts()[-1]
                self.assertEqual(receipt["uninstall_result"], "failed-at-identity-gate")
                self.assertEqual([s["stage"] for s in receipt["stages"]], ["verify", "identity-gate"])
        # v26 to v29: no gate verb, and a provider that answers can never
        # approve the forget: refused before anything changes.
        for version in ("26", "29"):
            with self.subTest(version=version):
                self.install_version(version)
                result = self.run_uninstall(FAKE_GATE_UNKNOWN=1)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn(f"installed host {version} (v26 to v29) cannot forget its identity while its "
                              "provider answers", result.stderr)
                self.assertIn("Install v30 or later", result.stderr)
                self.assertIn(nothing, result.stderr)
                self.assertEqual(self.raw_calls(), PREFLIGHT + ["--ping"])
                self.assert_app_in_place()
                self.assertEqual(self.receipts()[-1]["uninstall_result"], "failed-at-identity-gate")
        # ... unless that provider is gone: the forget step decides (here
        # with --identity-unverified, as for any unavailable provider).
        gone = {"FAKE_FORGET_UNAVAILABLE": 1, "FAKE_PING_UNAVAILABLE": 1}
        self.install_version("29")
        result = self.run_uninstall("--identity-unverified", deact_exit=23, FAKE_GATE_UNKNOWN=1, **gone)
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = self.receipts()[-1]
        gate = [st for st in receipt["stages"] if st["stage"] == "identity-gate"]
        self.assertEqual(gate[0]["status"], "skipped")
        self.assertEqual(receipt["identity_gate"], "unsupported-provider-unavailable")
        self.assertEqual(receipt["identity_absence"], "unverified")
        # v30 review: its prompt offers Touch ID, so the uninstalled v29
        # copy loses its host like a v25 one.
        moved = pathlib.Path(receipt["uninstalled_app_path"])
        self.assertTrue(receipt["uninstalled_host_disarm"].startswith("weak_host=disarmed version=29 host_sha256="),
                        receipt["uninstalled_host_disarm"])
        self.assertFalse((moved / "Contents" / "MacOS" / "aegis-ne-host").exists())
        self.assertIn("ask for an administrator at a prompt that offers Touch ID",
                      (moved / "Contents" / "MacOS" / "aegis-ne-host.removed").read_text())
        self.assertIn("predates the v30 password-only leak-guard prompt", result.stdout)
        # Before v26 the forget has no administrator gate: nothing to pass.
        self.install_version("25")
        result = self.run_uninstall(FAKE_GATE_UNKNOWN=1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.raw_calls(), PREFLIGHT + UNINSTALL_ORDER[:2] + FILTER_CALLS + UNINSTALL_ORDER[2:])
        self.assertEqual(self.receipts()[-1]["identity_gate"], "predates-audit")
        # A provider unavailable to the gate: the forget step decides.
        self.install_version("30")
        result = self.run_uninstall("--identity-unverified", deact_exit=23, FAKE_GATE_UNAVAILABLE=1, **gone)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.receipts()[-1]["identity_gate"], "provider-unavailable")
        # An open gate is recorded with its line.
        self.install_version("30")
        result = self.run_uninstall()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.receipts()[-1]["identity_gate"],
                         "identity_gate=open peer=admitted identity_rule=unregistered proof_rule=admitted "
                         "proof_probe=allowed")
        text = UNINSTALL_SH.read_text()
        self.assertIn("IDENTITY_GATE_MIN=30 AUDIT_GATE_MIN=26\n", text)
        self.assertIn('"--identity-gate"', HOST_LIFECYCLE_RS.read_text() + (PACKAGE / "src" / "provider_xpc.rs").read_text())

    def test_a_provider_refusing_the_approval_names_the_way_out(self):
        for code, advice in (
                ("identity_authorization_denied", "install and activate v30 or later first"),
                ("identity_authorization_host_outdated", "refuses this v9 host's approval"),
                ("identity_authorization_proof_rule_unexpected", "troubleshooting.md (exit 65)")):
            with self.subTest(code=code):
                self.reset_app()
                result = self.run_uninstall(FAKE_FORGET_REFUSED=code)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn(f"host exit 65 after 1 attempt(s): provider_refused {code}", result.stderr)
                self.assertIn(advice, result.stderr)
                self.assert_app_in_place()
                self.assertEqual(self.receipts()[-1]["uninstall_result"], "failed-at-forget-identity")

    def test_a_host_without_deactivate_runs_no_verb_with_an_effect(self):
        cases = [
            # The installed pre-S21 hosts: unknown_command for --deactivate.
            ({"FAKE_NO_DEACTIVATE": 1}, "probe exit 2: unknown_command"),
            # A host that accepts a foreign provider id is not this parser.
            ({"FAKE_PROBE_ACCEPTS": 1}, "probe exit 0"),
            # Exit 2 needs provider_id_mismatch, and that code needs exit 2.
            ({"FAKE_PROBE_REFUSAL": "unknown_command"}, "probe exit 2: unknown_command"),
            ({"FAKE_PROBE_EXIT": 1}, "probe exit 1: provider_id_mismatch"),
            ({"FAKE_PROBE_USAGE": "usage: aegis-ne-host --ping | --deactivate PROVIDER_ID"},
             "probe exit 2: provider_id_mismatch"),
        ]
        for env, message in cases:
            with self.subTest(env=env):
                self.host_args.unlink(missing_ok=True)
                result = self.run_uninstall(**env)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn("does not support --deactivate", result.stderr)
                self.assertIn(message, result.stderr)
                self.assertIn("nothing was stopped, removed or forgotten", result.stderr)
                self.assertEqual(self.raw_calls(), [CAPABILITY_PROBE])
                self.assert_app_in_place()
                receipt = self.receipts()[-1]
                self.assertEqual(receipt["uninstall_result"], "failed-at-verify")
                self.assertEqual([s["stage"] for s in receipt["stages"]], ["verify"])
        # The usage text must name the verb too (the probe id is not enough).
        self.assertIn("'--deactivate [PROVIDER_ID]'", UNINSTALL_SH.read_text())
        self.assertIn("--deactivate [PROVIDER_ID]", HOST_LIFECYCLE_RS.read_text())
        self.assertIn("CAPABILITY_PROBE=capability-probe\n", UNINSTALL_SH.read_text())
        self.assertRegex(HOST_LIFECYCLE_RS.read_text(),
                         r'"--deactivate", "capability-probe"\],\s*"provider_id_mismatch"')

    def test_the_scripts_skip_exactly_the_banner_the_real_host_writes(self):
        host_rs = (PACKAGE / "src" / "bin" / "host.rs").read_text()
        # The identity verbs' banner and (v26) the leak-guard verbs' one.
        banners = re.findall(r'eprintln!\(\s*"(administrator approval required[^"]*)"', host_rs)
        self.assertEqual(len(banners), 2, banners)
        self.assertEqual(len({b.split(";")[0] for b in banners}), 2, banners)
        secs = re.search(r"pub const PROMPT_TIMEOUT_SECS: u64 = ([0-9]+);",
                         (PACKAGE / "src" / "identity_authorization.rs").read_text())
        self.assertIsNotNone(secs)
        for script in (UNINSTALL_SH, UNINSTALL_REINSTALL):
            with self.subTest(script=script.name):
                text = script.read_text()
                pattern = re.search(r"^APPROVAL_BANNER='(\^[^']*)'$", text, re.M)
                self.assertIsNotNone(pattern)
                for banner in banners:
                    # grep -E reads the pattern as Python's re does here.
                    self.assertTrue(re.match(pattern.group(1), banner), banner)
                    self.assertTrue(re.match(pattern.group(1), banner.replace(
                        "{PROMPT_TIMEOUT_SECS}", secs.group(1))), banner)
                self.assertFalse(re.match(pattern.group(1), "provider_refused session_live"))
                self.assertFalse(re.match(pattern.group(1), "filter_authorization_cancelled"))
                self.assertIn('grep -Ev "$APPROVAL_BANNER"', text)
                self.assertNotIn('grep -v "$APPROVAL_BANNER"', text)
        for banner in banners:
            self.assertIn(banner.replace("{PROMPT_TIMEOUT_SECS}", secs.group(1)), FAKE_UNINSTALL_HOST)
        # v26: the leak-guard prompt runs before the filter verb's bound.
        self.assertRegex(host_rs, r"if aegis_network_extension::host_lifecycle::filter_requires_authorization"
                                  r"\(&command\) \{\s*approve_filter_or_exit\(\);\s*\}\s*let budget =")

    def test_an_inactive_extension_without_a_marker_needs_the_explicit_flag(self):
        gone = {"FAKE_FORGET_UNAVAILABLE": 1, "FAKE_PING_UNAVAILABLE": 1}
        # Never activated or deactivated elsewhere: refused, with the way out.
        result = self.run_uninstall(deact_exit=23, **gone)
        self.assertEqual(result.returncode, 1)
        self.assertIn("its extension is not active", result.stderr)
        self.assertIn("deactivation was not requested", result.stderr)
        self.assertIn("--identity-unverified", result.stderr)
        self.assertIn("install-app.sh --activate", result.stderr)
        self.assertNotIn("so the extension is not deactivated", result.stderr)
        self.assertEqual(self.calls(), UNINSTALL_ORDER[:3])
        self.assert_app_in_place()

        # With the flag: deactivation is requested and not-found accepted.
        self.host_args.unlink()
        result = self.run_uninstall("--identity-unverified", deact_exit=23, **gone)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("identity absence is NOT verified", result.stderr)
        self.assertEqual(self.calls(), UNINSTALL_ORDER[:3] + UNINSTALL_ORDER[4:])
        self.assertFalse((self.dest / "AEGIS.app").exists())
        self.assert_container_kept()
        receipt = self.receipts()[-1]
        self.assertEqual([s["status"] for s in receipt["stages"]],
                         ["ok", "ok", "ok", "ok", "ok", "ok", "unverified", "unverified", "ok", "ok", "ok"])
        self.assertEqual(receipt["identity_absence"], "unverified")
        self.assertIs(receipt["identity_unverified_allowed"], True)
        self.assertEqual(receipt["deactivation_outcome"], "not-found")
        self.assertEqual(receipt["deactivation_accepted_as"], "already-inactive")
        # By name: the S20b filter stages come before the forget.
        forget = [st for st in receipt["stages"] if st["stage"] == "forget-identity"]
        self.assertEqual(len(forget), 1, receipt["stages"])
        self.assertIn("host exit 69: xpc_connection_invalid", forget[0]["detail"])
        self.assertNotIn("forget_report", receipt)
        self.assertEqual(receipt["consumed_marker"], "")
        self.assertEqual(receipt["consumed_identity_marker"], "")

        # With the flag and a completed deactivation: moved, and no marker
        # that a later run would read as a verified forget.
        self.reset_app()
        os.rename(self.state / "uninstalled", self.state / "uninstalled-kept")
        write_mode(self.state / "uninstalled", "not a directory\n", 0o600)
        result = self.run_uninstall("--identity-unverified", **gone)
        self.assertEqual(result.returncode, 1)
        self.assertIn("move-app: cannot create", result.stderr)
        self.assertEqual(self.receipts()[-1]["deactivation_outcome"], "completed")
        self.assertFalse((self.state / "uninstall" / "deactivated.txt").exists())
        self.assertFalse((self.state / "uninstall" / "identity-absent.txt").exists())
        (self.state / "uninstalled").unlink()
        os.rename(self.state / "uninstalled-kept", self.state / "uninstalled")

        # With the flag, any other outcome keeps the app and names the flag.
        for code, message in ((21, "deactivation failed (host exit 21)"),
                              (24, "approval still pending after 120s"),
                              (25, "deactivation timeout (host exit 25)")):
            with self.subTest(code=code):
                self.host_args.unlink(missing_ok=True)
                result = self.run_uninstall("--identity-unverified", deact_exit=code, **gone)
                self.assertEqual(result.returncode, 1)
                self.assertIn(message, result.stderr)
                self.assertIn("again with --identity-unverified", result.stderr)
                self.assertTrue((self.dest / "AEGIS.app").is_dir())

        # The flag never skips the forget of a reachable provider.
        self.reset_app()
        result = self.run_uninstall("--identity-unverified", deact_exit=23)
        self.assertEqual(result.returncode, 1)
        self.assertIn("although its provider answered", result.stderr)
        self.assertEqual(self.calls(), UNINSTALL_ORDER)
        self.host_args.unlink()
        result = self.run_uninstall("--identity-unverified")
        self.assertEqual(result.returncode, 0, result.stderr)
        # The verified forget of the run before is probed, found reachable
        # and repeated.
        self.assertEqual(self.calls(), UNINSTALL_ORDER[:2] + ["--ping"] + UNINSTALL_ORDER[2:])
        receipt = self.receipts()[-1]
        self.assertEqual(receipt["identity_absence"], "verified")
        self.assertEqual({s["status"] for s in receipt["stages"]}, {"ok"})
        # Nor does it overrule a provider that refuses or cannot remove.
        self.reset_app()
        result = self.run_uninstall("--identity-unverified", FAKE_FORGET_LINE=forget_line(removed=False),
                                    FAKE_FORGET_EXIT=74)
        self.assertEqual(result.returncode, 1)
        self.assertIn("could not remove its key material", result.stderr)
        self.assertEqual(self.calls(), UNINSTALL_ORDER[:3])

    def test_a_rerun_after_a_pending_deactivation_resumes_from_the_verified_forget(self):
        # Run 1: forget verified, then approval is still pending at 120 s.
        result = self.run_uninstall(deact_exit=24, FAKE_DEACT_APPROVAL=1)
        self.assertEqual(result.returncode, 1)
        self.assertIn("approve in System Settings, then run", result.stderr)
        self.assertNotIn("--identity-unverified", result.stderr)
        absent = self.state / "uninstall" / "identity-absent.txt"
        self.assertIn("phase=identity-absent", absent.read_text())
        self.assertFalse((self.state / "uninstall" / "deactivated.txt").exists())
        first = self.receipts()[-1]
        self.assertIn(f"receipt={self.artifacts}/uninstall/receipts/{first['run_id']}.json", absent.read_text())

        # Apple finished it after that host exited: the provider is gone.
        # A failed deactivation still keeps the app and the marker.
        self.host_args.unlink()
        result = self.run_uninstall(deact_exit=21, FAKE_PING_UNAVAILABLE=1, FAKE_FORGET_UNAVAILABLE=1)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.calls(), UNINSTALL_ORDER[:2] + ["--ping", UNINSTALL_ORDER[4]])
        self.assertTrue((self.dest / "AEGIS.app").is_dir())
        self.assertTrue(absent.is_file())

        # Not found now means already inactive: no forget, no identity ping.
        self.host_args.unlink()
        result = self.run_uninstall(deact_exit=23, FAKE_PING_UNAVAILABLE=1, FAKE_FORGET_UNAVAILABLE=1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), UNINSTALL_ORDER[:2] + ["--ping", UNINSTALL_ORDER[4]])
        self.assertFalse((self.dest / "AEGIS.app").exists())
        receipt = self.receipts()[-1]
        self.assertEqual([s["status"] for s in receipt["stages"]],
                         ["ok", "ok", "ok", "ok", "ok", "ok", "done-earlier", "done-earlier", "ok", "ok", "ok"])
        self.assertEqual(receipt["identity_absence"], "verified-earlier")
        self.assertEqual(receipt["earlier_receipt"],
                         f"{self.artifacts}/uninstall/receipts/{first['run_id']}.json")
        self.assertEqual(receipt["deactivation_accepted_as"], "already-inactive")
        self.assertFalse(absent.exists())
        self.assertIn("phase=identity-absent",
                      pathlib.Path(receipt["consumed_identity_marker"]).read_text())

        # Same resume with a completed deactivation.
        self.reset_app()
        self.run_uninstall(deact_exit=24)
        self.host_args.unlink()
        result = self.run_uninstall(FAKE_PING_UNAVAILABLE=1, FAKE_FORGET_UNAVAILABLE=1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), UNINSTALL_ORDER[:2] + ["--ping", UNINSTALL_ORDER[4]])
        self.assertEqual(self.receipts()[-1]["deactivation_outcome"], "completed")

        # The marker while the provider still answers: everything again, and
        # a not-found then is refused as before.
        self.reset_app()
        self.run_uninstall(deact_exit=24)
        self.host_args.unlink()
        result = self.run_uninstall(deact_exit=23)
        self.assertEqual(result.returncode, 1)
        self.assertIn("although its provider answered", result.stderr)
        self.assertEqual(self.calls(), UNINSTALL_ORDER[:2] + ["--ping"] + UNINSTALL_ORDER[2:])
        self.assertTrue((self.dest / "AEGIS.app").is_dir())

    def import_journal(self):
        return self.root / "Library" / "Application Support" / "dev.aegis.macos" / \
            "identity-import-journal"

    def host_import(self, n):
        """What a host --import does before sending: one more journal line."""
        journal = self.import_journal()
        journal.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with open(journal, "a") as handle:
            handle.write(f"import_attempt unix_ns={n} pid=1\n")
        journal.chmod(0o600)

    def test_a_marker_written_before_a_later_import_is_never_honoured(self):
        unavailable = {"FAKE_PING_UNAVAILABLE": 1, "FAKE_FORGET_UNAVAILABLE": 1}
        for first_exit, marker in ((24, "identity-absent.txt"), (20, "deactivated.txt")):
            with self.subTest(marker=marker):
                self.reset_app()
                # An earlier import, then run 1 verifies the forget and stops
                # with the app in place and a marker of this app.
                self.host_import(1)
                line = None if first_exit == 24 else (
                    "deactivation_result=will_complete_after_reboot exit_code=20 "
                    "will_complete_after_reboot=true needs_user_approval=false")
                result = self.run_uninstall(deact_exit=first_exit, deact_line=line)
                self.assertEqual(result.returncode, 1, result.stderr)
                path = self.state / "uninstall" / marker
                self.assertIn("import_journal=", path.read_text())
                # The owner imports again while the provider still answers,
                # and the provider then becomes unavailable.
                self.host_import(2)
                self.host_args.unlink()
                moved = self.uninstalled()
                result = self.run_uninstall(deact_exit=23, **unavailable)
                self.assertEqual(result.returncode, 1)
                self.assertIn("no earlier run of this app verified the forget", result.stderr)
                self.assertEqual(self.calls(), UNINSTALL_ORDER[:3])
                self.assertTrue((self.dest / "AEGIS.app").is_dir())
                self.assertEqual(self.uninstalled(), moved)
                receipt = self.receipts()[-1]
                self.assertNotEqual(receipt.get("identity_absence"), "verified-earlier")
                self.assertEqual(receipt["uninstall_result"], "failed-at-forget-identity")
                # The marker no longer binds this app's identity state: retired.
                self.assertFalse(path.exists())
                stale = marker.replace(".txt", "-stale-")
                self.assertTrue(list((self.state / "uninstall").glob(stale + "*.txt")))
                # Without a later import the same marker still resumes.
                self.reset_app()
                self.run_uninstall(deact_exit=first_exit, deact_line=line)
                self.host_args.unlink()
                result = self.run_uninstall(deact_exit=23, **unavailable)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.receipts()[-1]["identity_absence"], "verified-earlier")
                # A journal that is not the owner's plain file never matches.
                self.reset_app()
                self.run_uninstall(deact_exit=first_exit, deact_line=line)
                journal = self.import_journal()
                kept = journal.with_name("kept")
                journal.rename(kept)
                journal.symlink_to(kept)
                self.host_args.unlink()
                moved = self.uninstalled()
                result = self.run_uninstall(deact_exit=23, **unavailable)
                self.assertEqual(result.returncode, 1)
                self.assertTrue((self.dest / "AEGIS.app").is_dir())
                self.assertEqual(self.uninstalled(), moved)
                journal.unlink()
                kept.rename(journal)
                # An import while run 1 runs (after its forget) also stands:
                # the marker binds the journal as it was before the forget.
                self.reset_app()
                self.run_uninstall(deact_exit=first_exit, deact_line=line,
                                   FAKE_IMPORT_DURING_RUN=journal)
                self.assertTrue(path.is_file())
                self.host_args.unlink()
                moved = self.uninstalled()
                result = self.run_uninstall(deact_exit=23, **unavailable)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(self.uninstalled(), moved)
                for leftover in (self.state / "uninstall").glob("*.txt"):
                    leftover.unlink()

    def test_the_latest_uninstalled_copy_is_the_newest_by_time_not_by_name(self):
        directory = self.state / "uninstalled"
        names = ["AEGIS.app.uninstalled-9-20261001T000000Z",
                 "AEGIS.app.uninstalled-10-20261002T000000Z",
                 "AEGIS.app.uninstalled-10-20261002T000000Z.2",
                 "AEGIS.app.uninstalled-10-20261002T000000Z.10",
                 "AEGIS.app.uninstalled-1.9-20261001T120000Z",
                 # Not the script's names: ignored.
                 "AEGIS.app.uninstalled-99-20261003T00000Z",
                 "AEGIS.app.uninstalled-zz-20261009T000000Z",
                 "AEGIS.app.uninstalled-99-20261009T000000Z.0"]
        for name in names:
            (directory / name).mkdir(parents=True)
        newest = directory / "AEGIS.app.uninstalled-10-20261002T000000Z.10"
        result = pipeline("latest-uninstalled", "--dir", directory)
        self.assertEqual((result.returncode, result.stdout), (0, f"{newest}\n"), result.stderr)
        self.assertEqual(pipeline("latest-uninstalled", "--dir", self.root / "none").stdout, "")
        # The already-absent run reports it.
        os.rename(self.app, self.root / "moved-elsewhere")
        result = self.run_uninstall()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"latest uninstalled copy: {newest}", result.stdout)
        self.assertEqual(self.receipts()[-1]["latest_uninstalled_copy"], str(newest))
        self.assertEqual(self.raw_calls(), [])



REAL_RELAY_WINDOW = PACKAGE / "harness" / "real-relay-window.sh"


class RealRelayWindowBurstTests(unittest.TestCase):
    """The S16g/S16h flow bursts of harness/real-relay-window.sh, run alone
    against a fake curl beside a long-lived child of the same shell, as the
    detached rollback is: a burst must wait for its own curls only, never for
    the rollback's timer. Nothing here dials anything or touches a tunnel."""

    def burst_function(self):
        lines = REAL_RELAY_WINDOW.read_text().splitlines()
        start = next(i for i, line in enumerate(lines) if line.lstrip().startswith("burst() {"))
        end = next(i for i in range(start, len(lines)) if lines[i].strip() == "}")
        return "\n".join(lines[start:end + 1])

    def run_bursts(self, calls, curl_body="echo 200"):
        with tempfile.TemporaryDirectory(prefix="aegis-s16h-burst-") as temp:
            root = pathlib.Path(temp)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            curl = bin_dir / "curl"
            curl.write_text(f"#!/bin/sh\n{curl_body}\n")
            curl.chmod(0o755)
            out = root / "out"
            out.mkdir()
            pid_file = root / "rollback.pid"
            script = ("set -u\n"
                      # Stands in for the rollback: an async child of this shell.
                      "sleep 30 >/dev/null 2>&1 &\n"
                      f"echo $! > '{pid_file}'\n"
                      "result() { printf '%s\\t%s\\t%s\\n' \"$1\" \"$2\" \"$3\"; }\n"
                      f"{self.burst_function()}\n"
                      f"{calls}\n"
                      "echo burst_done\n")
            env = {"PATH": f"{bin_dir}:/usr/bin:/bin:/opt/homebrew/bin", "OUT": str(out),
                   "WHOAMI": "http://198.51.100.1/"}
            try:
                result = subprocess.run(["/bin/bash", "-c", script], capture_output=True,
                                        text=True, env=env, timeout=20)
            except subprocess.TimeoutExpired:
                self.fail("a burst waited for the rollback child")
            finally:
                if pid_file.exists():
                    try:
                        os.kill(int(pid_file.read_text()), 9)
                    except (OSError, ValueError):
                        pass
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("burst_done", result.stdout)
            self.assertEqual(sorted(out.glob("burst.*")), [])
            return [line.split("\t") for line in result.stdout.splitlines() if "\t" in line]

    def test_the_bursts_wait_for_their_curls_and_not_for_the_rollback(self):
        rows = self.run_bursts("burst 24 22\nburst 90 88")
        self.assertEqual([r[:2] for r in rows], [["flow_burst_24", "pass"], ["flow_burst_90", "pass"]])
        self.assertTrue(rows[0][2].startswith("24/24 "), rows)
        self.assertTrue(rows[1][2].startswith("90/90 "), rows)
        self.assertRegex(rows[1][2], r" [0-9]+\.[0-9]{2}s$")

    def test_a_burst_below_its_threshold_fails(self):
        rows = self.run_bursts("burst 24 22", curl_body='case "$$" in *[02468]) echo 200;; *) echo 000;; esac')
        ok = int(rows[0][2].split("/")[0])
        self.assertEqual(rows[0][1], "pass" if ok >= 22 else "fail", rows)
        rows = self.run_bursts("burst 24 22", curl_body="echo 000")
        self.assertEqual(rows[0][:2], ["flow_burst_24", "fail"])
        self.assertTrue(rows[0][2].startswith("0/24 "), rows)



# ---------------------------------------------------------------- S20 leak proof

LEAK_REVIEW = PACKAGE / "harness" / "leak_review.py"
RELAY_IP = "203.0.113.7"
LOCAL_IP = "192.168.1.50"
T_CONNECT = 1_800_000_000.25
T_DISCONNECT = T_CONNECT + 20.0
IN = T_CONNECT + 5.0  # well inside the guarded interval


def ip4(text):
    return bytes(int(part) for part in text.split("."))


def ip6(text):
    import ipaddress
    return ipaddress.IPv6Address(text).packed


def tcp_seg(sport, dport, flags=0x02):
    return struct.pack(">HHIIBBHHH", sport, dport, 1, 0, 0x50, flags, 65535, 0, 0)


def udp_dgram(sport, dport, data=b"\x00" * 12):
    return struct.pack(">HHHH", sport, dport, 8 + len(data), 0) + data


def ipv4_pkt(src, dst, proto, l4):
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0x4000, 64, proto, 0,
                       ip4(src), ip4(dst)) + l4


def ipv6_pkt(src, dst, nxt, l4, hop_by_hop=False):
    if hop_by_hop:  # router alert option, as MLD carries
        l4 = bytes([nxt, 0, 5, 2, 0, 0, 1, 0]) + l4
        nxt = 0
    return struct.pack(">IHBB16s16s", 0x60000000, len(l4), nxt, 255, ip6(src), ip6(dst)) + l4


def icmpv6(kind):
    return bytes([kind, 0, 0, 0]) + b"\x00" * 20


def tcp_full(sport, dport, flags, seq=1, ack=0, data=b""):
    return struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 65535, 0, 0) + data


def icmp_echo(kind, ident, v6=True):
    return bytes([kind, 0, 0, 0]) + struct.pack(">HH", ident, 1) + b"\x00" * 16


def icmp_error(kind, code, quoted):
    return bytes([kind, code, 0, 0]) + b"\x00" * 4 + quoted


LOCAL_IP6 = "2001:db8::50"
PEER6 = "2001:db8:ffff::5"
GATEWAY_MAC = b"\x02\x00\x00\x00\x00\x01"   # ether()'s default destination


def e4_in(src, dst, proto, l4):
    """A frame the gateway delivers to the Mac."""
    return MAC_BYTES + GATEWAY_MAC + struct.pack(">H", 0x0800) + ipv4_pkt(src, dst, proto, l4)


def e6_in(src, dst, nxt, l4):
    return MAC_BYTES + GATEWAY_MAC + struct.pack(">H", 0x86DD) + ipv6_pkt(src, dst, nxt, l4)


MAC_BYTES = b"\x02\xab\xcd\xef\x00\x02"  # the Mac: source of ether() frames


def ether(payload, ethertype, mac=b"\x02\x00\x00\x00\x00\x01"):
    return mac + MAC_BYTES + struct.pack(">H", ethertype) + payload


def e4(src, dst, proto, l4, **kw):
    return ether(ipv4_pkt(src, dst, proto, l4), 0x0800, **kw)


def e6(src, dst, nxt, l4, **kw):
    return ether(ipv6_pkt(src, dst, nxt, l4, **kw), 0x86DD)


def arp_frame():
    return ether(struct.pack(">HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, b"\x02" * 6, ip4(LOCAL_IP),
                             b"\x00" * 6, ip4("192.168.1.1")), 0x0806, mac=b"\xff" * 6)


def relay_out(ts):
    return ts, e4(LOCAL_IP, RELAY_IP, 6, tcp_seg(50000, 443, 0x18))


def relay_in(ts):
    return ts, e4(RELAY_IP, LOCAL_IP, 6, tcp_seg(443, 50000, 0x10))


def clean_records():
    return [relay_out(T_CONNECT + 2 + i) for i in range(10)] + [relay_in(T_CONNECT + 2.5 + i) for i in range(10)]


def pcap_bytes(records, linktype=1, order="<", nanos=False, keep_order=False):
    magic = 0xA1B23C4D if nanos else 0xA1B2C3D4
    out = struct.pack(order + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype)
    for ts, frame in (records if keep_order else sorted(records, key=lambda r: r[0])):
        sec = int(ts)
        frac = round((ts - sec) * (1e9 if nanos else 1e6))
        out += struct.pack(order + "IIII", sec, frac, len(frame), len(frame)) + frame
    return out


def pcapng_bytes(records, linktype=1, order="<", tsresol=None):
    def block(btype, body):
        body += b"\x00" * (-len(body) % 4)
        length = 12 + len(body)
        return struct.pack(order + "II", btype, length) + body + struct.pack(order + "I", length)
    out = block(0x0A0D0D0A, struct.pack(order + "IHHq", 0x1A2B3C4D, 1, 0, -1))
    options = b""
    if tsresol is not None:
        options = struct.pack(order + "HH", 9, 1) + bytes([tsresol]) + b"\x00" * 3
        options += struct.pack(order + "HH", 0, 0)
    out += block(1, struct.pack(order + "HHI", linktype, 0, 65535) + options)
    units = 10 ** (tsresol or 6)
    for ts, frame in sorted(records, key=lambda r: r[0]):
        tick = round(ts * units)
        out += block(6, struct.pack(order + "IIIII", 0, tick >> 32, tick & 0xFFFFFFFF,
                                    len(frame), len(frame)) + frame)
    return out


def _untimed_block(frame, order="<"):
    """A pcapng simple packet block: no timestamp, interface 0."""
    body = struct.pack(order + "I", len(frame)) + frame
    body += b"\x00" * (-len(body) % 4)
    return struct.pack(order + "II", 3, 12 + len(body)) + body + struct.pack(order + "I", 12 + len(body))


class LeakReviewTests(unittest.TestCase):
    """harness/leak_review.py on synthetic captures written with struct."""

    def review(self, data, connected=T_CONNECT, disconnect=T_DISCONNECT, extra=()):
        with tempfile.TemporaryDirectory(prefix="aegis-s20-leak-") as temp:
            root = pathlib.Path(temp)
            pcap = root / "physical.pcap"
            pcap.write_bytes(data)
            out = root / "leak-review.json"
            args = [sys.executable, "-I", str(LEAK_REVIEW), "--pcap", str(pcap), "--relay-ip", RELAY_IP,
                    "--relay-port", "443", "--out", str(out), "--local-addr", LOCAL_IP, *extra]
            if connected is not None:
                args += ["--connected-at", repr(connected), "--disconnect-at", repr(disconnect)]
            result = subprocess.run(args, capture_output=True, text=True, timeout=30)
            report = json.loads(out.read_text())
            self.assertEqual(result.returncode, 0 if report["pass"] else (2 if "Error" in report.get("error", "") else 1),
                             result.stdout + result.stderr)
            self.assertTrue(result.stdout.startswith(f"leak_review pass={str(report['pass']).lower()} "), result.stdout)
            if "leak_origins" in report:
                # S20a: the origins partition the leaks; they never pass one.
                origins = report["leak_origins"]
                self.assertEqual(sum(origins.values()), report["leak_count"], report)
                self.assertEqual(sum(v for k, v in origins.items() if k.startswith("host_")),
                                 report["leak_classes"].get("host", 0), report)
                for klass, count in report["leak_classes"].items():
                    if klass != "host":
                        self.assertEqual(origins.get(klass), count, report)
                if report["leak_count"]:
                    self.assertFalse(report["pass"], report)
                self.assertEqual(report["new_outbound_flows"], report["leak_flows"].get("new_outbound", 0))
                for leak in report["leaks"]:
                    self.assertEqual("origin" in leak, leak["class"] == "host", leak)
                self.assertIn(f" new_outbound_flows={report['new_outbound_flows']} ", result.stdout)
                self.assertIn(f" foreign={report['leak_classes'].get('foreign', 0)}", result.stdout)
                pre = origins.get("host_preexisting", 0) + origins.get("host_preexisting_inferred", 0)
                self.assertIn(f" preexisting={pre} ", result.stdout)
            return report

    def assert_leak(self, report, **fields):
        self.assertFalse(report["pass"], report)
        self.assertGreaterEqual(report["leak_count"], 1, report)
        for leak in report["leaks"]:
            if all(leak.get(k) == v for k, v in fields.items()):
                return leak
        self.fail(f"no leak with {fields}: {report['leaks']}")

    def test_a_clean_capture_passes(self):
        report = self.review(pcap_bytes(clean_records()))
        self.assertTrue(report["pass"], report)
        self.assertEqual(report["relay_packets"], 20)
        self.assertEqual(report["leaks"], [])
        self.assertEqual(report["total_packets"], 20)
        self.assertEqual(report["excluded_control"], {"total": 0})
        self.assertEqual(report["connected_interval"]["connected_at"], T_CONNECT)
        self.assertEqual(report["connected_interval"]["disconnect_at"], T_DISCONNECT)

    def test_one_tcp_syn_to_another_ip_during_connected_fails(self):
        syn = (IN, e4(LOCAL_IP, "198.51.100.9", 6, tcp_seg(51515, 443)))
        report = self.review(pcap_bytes(clean_records() + [syn]))
        leak = self.assert_leak(report, dst="198.51.100.9", proto="tcp", dport=443, tcp_flags=0x02)
        self.assertEqual(leak["direction"], "outbound")
        self.assertEqual(report["leak_count"], 1)
        self.assertEqual(report["relay_packets"], 20)

    def test_the_same_syn_before_connect_or_after_disconnect_passes(self):
        for ts in (T_CONNECT - 3, T_CONNECT - 0.001, T_DISCONNECT + 0.001, T_DISCONNECT + 9):
            syn = (ts, e4(LOCAL_IP, "198.51.100.9", 6, tcp_seg(51515, 443)))
            report = self.review(pcap_bytes(clean_records() + [syn]))
            self.assertTrue(report["pass"], (ts, report))
            self.assertEqual(report["total_packets"], 21)
            self.assertEqual((report["outside_packets"], report["guard_packets"]), (1, 0))

    def test_the_guard_excludes_one_second_after_connect_and_before_disconnect_only(self):
        for ts in (T_CONNECT + 0.5, T_DISCONNECT - 0.5):
            syn = (ts, e4(LOCAL_IP, "198.51.100.9", 6, tcp_seg(51515, 443)))
            report = self.review(pcap_bytes(clean_records() + [syn]))
            self.assertTrue(report["pass"], (ts, report))
            self.assertEqual((report["outside_packets"], report["guard_packets"]), (0, 1))
        for ts in (T_CONNECT + 1.1, T_DISCONNECT - 1.1):
            syn = (ts, e4(LOCAL_IP, "198.51.100.9", 6, tcp_seg(51515, 443)))
            self.assert_leak(self.review(pcap_bytes(clean_records() + [syn])), dst="198.51.100.9")

    def test_dns_to_a_public_resolver_during_connected_fails(self):
        dns = (IN, e4(LOCAL_IP, "8.8.8.8", 17, udp_dgram(53000, 53)))
        self.assert_leak(self.review(pcap_bytes(clean_records() + [dns])),
                         dst="8.8.8.8", proto="udp", dport=53)

    def test_link_local_control_is_excluded_and_counted_by_kind(self):
        control = [
            (IN, arp_frame()),
            (IN, e4("0.0.0.0", "255.255.255.255", 17, udp_dgram(68, 67), mac=b"\xff" * 6)),
            (IN, e4(LOCAL_IP, "192.168.1.1", 17, udp_dgram(68, 67))),   # unicast renewal
            (IN, e6("fe80::1", "ff02::2", 58, icmpv6(133))),            # RS
            (IN, e6("fe80::2", "ff02::1", 58, icmpv6(134))),            # RA
            (IN, e6("fe80::1", "ff02::1:ff00:2", 58, icmpv6(135))),     # NS
            (IN, e6("fe80::2", "fe80::1", 58, icmpv6(136))),            # NA
            (IN, e6("fe80::1", "ff02::16", 58, icmpv6(143), hop_by_hop=True)),  # MLDv2
            (IN, e4(LOCAL_IP, "224.0.0.251", 17, udp_dgram(5353, 5353))),
            (IN, e6("fe80::1", "ff02::fb", 17, udp_dgram(5353, 5353))),
            (IN, e4("192.168.1.9", "192.168.1.255", 17, udp_dgram(137, 137))),
            (IN, e4("192.168.1.9", "255.255.255.255", 17, udp_dgram(9, 9), mac=b"\xff" * 6)),
        ]
        report = self.review(pcap_bytes(clean_records() + control), extra=["--broadcast", "192.168.1.255"])
        self.assertTrue(report["pass"], report)
        self.assertEqual(report["excluded_control"], {"total": 12, "arp": 1, "dhcp": 2, "nd": 4,
                                                      "mld": 1, "mdns": 2, "broadcast": 2})
        # Neighbours of the control classes stay leaks.
        for frame, dst in ((e4(LOCAL_IP, "239.255.255.250", 17, udp_dgram(5353, 1900)), "239.255.255.250"),
                           (e4(LOCAL_IP, "224.0.0.251", 6, tcp_seg(5353, 5353)), "224.0.0.251"),
                           (e4(LOCAL_IP, "198.51.100.9", 17, udp_dgram(5353, 5353)), "198.51.100.9"),
                           (e4(LOCAL_IP, "198.51.100.9", 17, udp_dgram(40000, 67)), "198.51.100.9"),
                           (e6("2001:db8::50", "2001:db8:ffff::5", 17, udp_dgram(40000, 547)), "2001:db8:ffff::5"),
                           (e4("192.168.1.9", "192.168.1.255", 17, udp_dgram(137, 137)), "192.168.1.255")):
            self.assert_leak(self.review(pcap_bytes(clean_records() + [(IN, frame)])), dst=dst)

    def test_ipv6_leaks_are_detected(self):
        for frame, fields in (
                (e6("2001:db8::50", "2001:db8:ffff::5", 6, tcp_seg(50001, 443)), {"proto": "tcp", "dport": 443}),
                (e6("2001:db8::50", "2001:4860:4860::8888", 17, udp_dgram(53001, 53)), {"proto": "udp", "dport": 53}),
                (e6("2001:db8::50", "2001:db8:ffff::5", 58, icmpv6(128)), {"proto": "icmpv6", "icmp_type": 128}),
                (e6("fe80::1", "fe80::99", 17, udp_dgram(40000, 40000), hop_by_hop=True), {"proto": "udp"})):
            report = self.review(pcap_bytes(clean_records() + [(IN, frame)]))
            self.assert_leak(report, **fields)

    def test_leaks_are_counted_by_ip_family(self):
        report = self.review(pcap_bytes(clean_records()))
        self.assertEqual(report["leak_families"], {"ipv4": 0, "ipv6": 0, "other": 0})
        leaks = [(IN, e6("2001:db8::50", "2001:db8:ffff::5", 6, tcp_seg(50001, 443))),
                 (IN + 0.1, e6("2001:db8::50", "2001:4860:4860::8888", 17, udp_dgram(53001, 53))),
                 (IN + 0.2, e4(LOCAL_IP, "198.51.100.9", 6, tcp_seg(51515, 443))),
                 (IN + 0.3, ether(b"\x02\x07" + b"\x00" * 20, 0x88CC)),
                 (IN + 0.4, b"\x02\x00\x00"),
                 # IPv6 control stays control, outside the family counts.
                 (IN + 0.5, e6("fe80::1", "ff02::2", 58, icmpv6(133)))]
        report = self.review(pcap_bytes(clean_records() + leaks))
        self.assertEqual(report["leak_families"], {"ipv4": 1, "ipv6": 2, "other": 2})
        self.assertEqual(sum(report["leak_families"].values()), report["leak_count"])
        self.assertEqual(report["excluded_control"], {"total": 1, "nd": 1})

    def test_pcapng_is_parsed_in_either_byte_order_and_resolution(self):
        syn = (IN, e4(LOCAL_IP, "198.51.100.9", 6, tcp_seg(51515, 443)))
        for order, resol in (("<", None), (">", 9)):
            report = self.review(pcapng_bytes(clean_records(), order=order, tsresol=resol))
            self.assertTrue(report["pass"], report)
            self.assertEqual((report["format"], report["relay_packets"]), ("pcapng", 20))
            report = self.review(pcapng_bytes(clean_records() + [syn], order=order, tsresol=resol))
            self.assert_leak(report, dst="198.51.100.9")
            early = (T_CONNECT - 2, syn[1])
            self.assertTrue(self.review(pcapng_bytes(clean_records() + [early], order=order, tsresol=resol))["pass"])

    def test_classic_pcap_variants_and_link_types(self):
        leak4 = ipv4_pkt(LOCAL_IP, "198.51.100.9", 6, tcp_seg(51515, 443))
        leak6 = ipv6_pkt("2001:db8::50", "2001:db8:ffff::5", 6, tcp_seg(50001, 443))
        relay = ipv4_pkt(LOCAL_IP, RELAY_IP, 6, tcp_seg(50000, 443))
        for linktype, wrap in ((0, lambda p: struct.pack("<I", 2 if p[0] >> 4 == 4 else 30) + p),
                               (108, lambda p: struct.pack(">I", 2 if p[0] >> 4 == 4 else 30) + p),
                               (101, lambda p: p), (12, lambda p: p), (228, lambda p: p)):
            for order, nanos in (("<", False), (">", True)):
                records = [(T_CONNECT + 2 + i, wrap(relay)) for i in range(5)]
                ok = self.review(pcap_bytes(records, linktype, order, nanos))
                self.assertTrue(ok["pass"], (linktype, ok))
                bad = self.review(pcap_bytes(records + [(IN, wrap(leak4))], linktype, order, nanos))
                self.assert_leak(bad, dst="198.51.100.9")
                if linktype != 228:
                    bad = self.review(pcap_bytes(records + [(IN, wrap(leak6))], linktype, order, nanos))
                    self.assert_leak(bad, dst="2001:db8:ffff::5")

    def test_non_ip_frames_and_truncated_records_fail_closed(self):
        lldp = (IN, ether(b"\x02\x07" + b"\x00" * 20, 0x88CC))
        self.assert_leak(self.review(pcap_bytes(clean_records() + [lldp])), kind="non_ip")
        short = (IN, b"\x02\x00\x00")
        self.assert_leak(self.review(pcap_bytes(clean_records() + [short])), kind="unparsed")
        truncated = pcap_bytes(clean_records())[:-10]
        self.assert_leak(self.review(truncated), kind="unparsed")

    def test_no_relay_packet_during_connected_fails(self):
        before = [relay_out(T_CONNECT - 2), relay_in(T_DISCONNECT + 2), relay_out(T_CONNECT + 0.3)]
        control = [(IN, arp_frame()), (IN, e6("fe80::1", "ff02::2", 58, icmpv6(133)))]
        report = self.review(pcap_bytes(before + control))
        self.assertFalse(report["pass"], report)
        self.assertEqual((report["relay_packets"], report["leak_count"]), (0, 0))
        self.assertEqual(report["excluded_control"]["total"], 2)
        self.assertFalse(self.review(pcap_bytes([]))["pass"])

    def test_flows_to_the_relay_host_off_the_relay_port_are_leaks(self):
        # The window's echo, whoami and burst flows target the relay host:
        # sent around the tunnel they are leaks, not relay packets.
        for frame, fields in (
                (e4(LOCAL_IP, RELAY_IP, 6, tcp_seg(50100, 7)), {"proto": "tcp", "dport": 7}),
                (e4(LOCAL_IP, RELAY_IP, 17, udp_dgram(50101, 7)), {"proto": "udp", "dport": 7}),
                (e4(LOCAL_IP, RELAY_IP, 6, tcp_seg(50102, 8080)), {"proto": "tcp", "dport": 8080}),
                (e4(RELAY_IP, LOCAL_IP, 6, tcp_seg(8080, 50102, 0x12)), {"proto": "tcp", "sport": 8080}),
                (e4(LOCAL_IP, RELAY_IP, 6, tcp_seg(443, 50103)), {"proto": "tcp", "sport": 443, "dport": 50103}),
                (e4(LOCAL_IP, RELAY_IP, 1, bytes([8, 0, 0, 0]) + b"\x00" * 4), {"proto": "icmp", "icmp_type": 8})):
            report = self.review(pcap_bytes(clean_records() + [(IN, frame)]))
            leak = self.assert_leak(report, **fields)
            self.assertTrue(leak["relay_host"], leak)
            self.assertEqual((report["leak_count"], report["relay_packets"]), (1, 20))
        self.assertEqual((report["relay_port"], report["relay_protocols"]), (443, ["tcp", "udp"]))
        # UDP to the relay port is relay transport unless only TCP is declared.
        quic = (IN, e4(LOCAL_IP, RELAY_IP, 17, udp_dgram(50104, 443)))
        report = self.review(pcap_bytes(clean_records() + [quic]))
        self.assertTrue(report["pass"], report)
        self.assertEqual(report["relay_packets"], 21)
        report = self.review(pcap_bytes(clean_records() + [quic]), extra=["--relay-proto", "tcp"])
        self.assert_leak(report, proto="udp", dport=443, relay_host=True)

    def test_only_off_port_traffic_to_the_relay_ip_has_no_relay_packet(self):
        records = [(T_CONNECT + 2 + i, e4(LOCAL_IP, RELAY_IP, 6, tcp_seg(50100 + i, 8080))) for i in range(5)]
        report = self.review(pcap_bytes(records))
        self.assertFalse(report["pass"], report)
        self.assertEqual((report["relay_packets"], report["leak_count"]), (0, 5))
        self.assertIn("no relay packet", report["error"])

    def test_the_relay_port_and_protocols_are_required_and_checked(self):
        with tempfile.TemporaryDirectory(prefix="aegis-s20-args-") as temp:
            pcap = pathlib.Path(temp) / "physical.pcap"
            pcap.write_bytes(pcap_bytes(clean_records()))
            out = pathlib.Path(temp) / "leak-review.json"
            base = [sys.executable, "-I", str(LEAK_REVIEW), "--pcap", str(pcap), "--relay-ip", RELAY_IP,
                    "--out", str(out), "--connected-at", repr(T_CONNECT), "--disconnect-at", repr(T_DISCONNECT)]
            result = subprocess.run(base, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 2)
            self.assertIn("--relay-port", result.stderr)
            self.assertFalse(out.exists())
            for extra in (["--relay-port", "0"], ["--relay-port", "443", "--relay-proto", "icmp"],
                          ["--relay-port", "443", "--relay-proto", ""]):
                result = subprocess.run(base + extra, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 2, (extra, result.stdout))
                self.assertFalse(json.loads(out.read_text())["pass"])

    def test_leaks_carry_a_diagnostic_class_that_never_passes_them(self):
        mac = MAC_BYTES.hex(":")
        other = b"\x02\x00\x00\x00\x00\x09"
        def from_other(payload, ethertype, dst=b"\x01\x00\x5e\x7f\xff\xfa"):
            return dst + other + struct.pack(">H", ethertype) + payload
        cases = (
            (ether(b"\x01\x03\x00\x5f" + b"\x00" * 95, 0x888E), "link_control"),          # EAPOL key
            (ether(b"\x02\x07\x04" + b"\x00" * 20, 0x88CC), "link_control"),               # LLDP
            (ether(b"\x42\x42\x03" + b"\x00" * 35, 38), "link_control"),                   # STP over LLC
            (e4(LOCAL_IP, "224.0.0.22", 2, bytes([0x22, 0, 0, 0]) + b"\x00" * 4), "igmp"),  # IGMPv3 report
            (from_other(ipv4_pkt("192.168.1.9", "239.255.255.250", 17, udp_dgram(1900, 1900)), 0x0800), "foreign"),
            (from_other(ipv4_pkt("192.168.1.9", "192.168.1.10", 6, tcp_seg(40000, 22)), 0x0800,
                        dst=b"\x02\x00\x00\x00\x00\x0a"), "foreign"),
            # Sourced by the Mac or from the tunnel address: never foreign.
            (e4(LOCAL_IP, "239.255.255.250", 17, udp_dgram(1900, 1900)), "host"),
            (from_other(ipv4_pkt("198.19.255.1", "198.51.100.9", 6, tcp_seg(40000, 443)), 0x0800,
                        dst=b"\x02\x00\x00\x00\x00\x0a"), "host"),
            (from_other(ipv4_pkt("192.168.1.9", LOCAL_IP, 6, tcp_seg(40000, 22)), 0x0800,
                        dst=b"\x02\x00\x00\x00\x00\x0a"), "host"),
            (from_other(ipv4_pkt("192.168.1.9", "198.51.100.9", 6, tcp_seg(40000, 22)), 0x0800,
                        dst=MAC_BYTES), "host"),   # to the Mac's MAC
        )
        for frame, klass in cases:
            report = self.review(pcap_bytes(clean_records() + [(IN, frame)]), extra=["--local-mac", mac.upper()])
            leak = self.assert_leak(report, **{"class": klass})
            self.assertEqual((report["leak_count"], report["leak_classes"]), (1, {klass: 1}), leak)
        # Without the Mac's address nothing is called foreign.
        report = self.review(pcap_bytes(clean_records() + [(IN, cases[4][0])]))
        self.assertEqual(report["leak_classes"], {"host": 1})
        self.assertEqual(self.review(pcap_bytes(clean_records()[:-1] + [(IN, b"\x02")]))["leak_classes"],
                         {"unparsed": 1})

    # ------------------------------------------------ S20a flow origins

    def review6(self, records, extra=()):
        return self.review(pcap_bytes(clean_records() + records),
                           extra=["--local-addr", LOCAL_IP6, "--local-mac", MAC_BYTES.hex(":"), *extra])

    def test_a_flow_opened_before_connected_is_preexisting_and_still_fails(self):
        records = [(T_CONNECT - 3, e6(LOCAL_IP6, PEER6, 6, tcp_full(61730, 443, 0x02, seq=100))),
                   (T_CONNECT - 2.9, e6_in(PEER6, LOCAL_IP6, 6, tcp_full(443, 61730, 0x12, seq=7, ack=101))),
                   (IN, e6_in(PEER6, LOCAL_IP6, 6, tcp_full(443, 61730, 0x18, seq=8, ack=101, data=b"\x17" * 31)))]
        report = self.review6(records)
        leak = self.assert_leak(report, proto="tcp", sport=443, dport=61730)
        self.assertEqual((leak["origin"], leak["direction"], leak["payload_len"]), ("preexisting", "inbound", 31))
        self.assertEqual(report["leak_origins"], {"host_preexisting": 1})
        self.assertEqual((report["leak_flows"], report["new_outbound_flows"]), ({"preexisting": 1}, 0))
        self.assertEqual(report["host_outbound"], {})
        # Any earlier packet of the flow makes it preexisting, a SYN or not.
        report = self.review6(records[2:] + [(T_CONNECT - 0.2, records[2][1])])
        self.assertEqual(report["leak_origins"], {"host_preexisting": 1})

    def test_a_syn_at_or_after_connected_is_a_new_outbound_flow(self):
        syn = e6(LOCAL_IP6, PEER6, 6, tcp_full(62000, 443, 0x02))
        report = self.review6([(IN, syn)])
        leak = self.assert_leak(report, proto="tcp", dport=443, tcp_flags=0x02)
        self.assertEqual(leak["origin"], "new_outbound")
        self.assertEqual((report["new_outbound_flows"], report["host_outbound"]), (1, {"tcp_syn": 1}))
        self.assertEqual(report["leak_origins"], {"host_new_outbound": 1})
        # A handshake inside the guard still makes the flow's later packets new.
        later = e6_in(PEER6, LOCAL_IP6, 6, tcp_full(443, 62000, 0x10, ack=2))
        report = self.review6([(T_CONNECT + 0.5, syn), (IN, later)])
        self.assertEqual((report["leak_origins"], report["guard_packets"]), ({"host_new_outbound": 1}, 1))
        # A 5-tuple seen before connect but reused by a new SYN is new.
        old = e6(LOCAL_IP6, PEER6, 6, tcp_full(62000, 443, 0x10))
        report = self.review6([(T_CONNECT - 2, old), (IN, syn), (IN + 1, old)])
        self.assertEqual(report["leak_origins"], {"host_new_outbound": 2})
        self.assertEqual(report["new_outbound_flows"], 1)
        # Before that SYN, the same flow is preexisting.
        report = self.review6([(T_CONNECT - 2, old), (IN, old), (IN + 1, syn)])
        self.assertEqual(report["leak_origins"], {"host_preexisting": 1, "host_new_outbound": 1})
        # A SYN-ACK with no SYN seen answers the Mac's own handshake: new outbound.
        report = self.review6([(IN, e6_in(PEER6, LOCAL_IP6, 6, tcp_full(443, 62001, 0x12)))])
        self.assertEqual((report["leak_origins"], report["new_outbound_flows"]), ({"host_new_outbound": 1}, 1))
        # A peer's SYN is a new inbound flow, and the Mac's answer joins it.
        report = self.review6([(IN, e6_in(PEER6, LOCAL_IP6, 6, tcp_full(40000, 22, 0x02))),
                               (IN + 0.1, e6(LOCAL_IP6, PEER6, 6, tcp_full(22, 40000, 0x12)))])
        self.assertEqual((report["leak_origins"], report["new_outbound_flows"]), ({"host_new_inbound": 2}, 0))
        self.assertEqual(report["host_outbound"], {"tcp_syn": 1})
        # The same SYN one tick before connected_at is preexisting; at it, new.
        report = self.review6([(T_CONNECT - 0.001, syn), (IN, later)])
        self.assertEqual(report["leak_origins"], {"host_preexisting": 1})
        report = self.review6([(T_CONNECT, syn), (IN, later)])
        self.assertEqual(report["leak_origins"], {"host_new_outbound": 1})
        # A capture written out of time order: the earliest packet decides.
        records = clean_records() + [(IN, later), (T_CONNECT - 2, old)]
        report = self.review(pcap_bytes(records, keep_order=True), extra=["--local-addr", LOCAL_IP6])
        self.assertEqual(report["leak_origins"], {"host_preexisting": 1})

    def test_a_mid_stream_flow_without_a_handshake_is_inferred_preexisting(self):
        records = [(IN, e6_in(PEER6, LOCAL_IP6, 6, tcp_full(443, 61685, 0x18, seq=5, ack=9, data=b"\x01" * 73))),
                   (IN + 1, e6_in(PEER6, LOCAL_IP6, 6, tcp_full(443, 61685, 0x18, seq=5, ack=9, data=b"\x01" * 73)))]
        report = self.review6(records)
        self.assertEqual(report["leak_origins"], {"host_preexisting_inferred": 2})
        self.assertEqual((report["leak_flows"], report["new_outbound_flows"]), ({"preexisting_inferred": 1}, 0))
        self.assertFalse(report["pass"])

    def test_outbound_tcp_is_split_into_data_keepalive_and_control(self):
        probe = e6(LOCAL_IP6, PEER6, 6, tcp_full(61679, 443, 0x10, seq=1000, ack=50))
        answer = e6_in(PEER6, LOCAL_IP6, 6, tcp_full(443, 61679, 0x10, seq=50, ack=1001))
        report = self.review6([(T_CONNECT - 2, probe), (IN, probe), (IN + 0.03, answer)])
        self.assertEqual(report["host_outbound"], {"tcp_keepalive": 1})
        self.assertEqual(report["leak_origins"], {"host_preexisting": 2})
        # Not the probe's seq + 1, or acknowledged only before the probe: control.
        wrong = e6_in(PEER6, LOCAL_IP6, 6, tcp_full(443, 61679, 0x10, seq=50, ack=1002))
        self.assertEqual(self.review6([(IN, probe), (IN + 0.03, wrong)])["host_outbound"], {"tcp_control": 1})
        self.assertEqual(self.review6([(IN - 0.03, answer), (IN, probe)])["host_outbound"], {"tcp_control": 1})
        # Only the peer's acknowledgement counts, never the Mac's own ack field.
        selfack = e6(LOCAL_IP6, PEER6, 6, tcp_full(61679, 443, 0x10, seq=1000, ack=1001))
        self.assertEqual(self.review6([(IN, selfack)])["host_outbound"], {"tcp_control": 1})
        # seq + 1 wraps at 2**32.
        wrap = e6(LOCAL_IP6, PEER6, 6, tcp_full(61679, 443, 0x10, seq=0xFFFFFFFF))
        zero = e6_in(PEER6, LOCAL_IP6, 6, tcp_full(443, 61679, 0x10, ack=0))
        self.assertEqual(self.review6([(IN, wrap), (IN + 0.03, zero)])["host_outbound"], {"tcp_keepalive": 1})
        # A FIN or RST is control even when acknowledged with seq + 1.
        fin = e6(LOCAL_IP6, PEER6, 6, tcp_full(61679, 443, 0x11, seq=1000))
        self.assertEqual(self.review6([(IN, fin), (IN + 0.03, answer)])["host_outbound"], {"tcp_control": 1})
        # Any payload is data, keepalive answer or not.
        data = e6(LOCAL_IP6, PEER6, 6, tcp_full(61679, 443, 0x10, seq=1000, data=b"\x00"))
        report = self.review6([(IN, data), (IN + 0.03, answer)])
        self.assertEqual(report["host_outbound"], {"tcp_data": 1})
        self.assertEqual(report["leaks"][0]["payload_len"], 1)
        # An IPv4 total length of 0 (a TSO capture) is an unknown length: data.
        tso = bytearray(e4(LOCAL_IP, "198.51.100.9", 6, tcp_full(61700, 443, 0x10, seq=1000)))
        tso[16:18] = b"\x00\x00"
        answer4 = e4_in("198.51.100.9", LOCAL_IP, 6, tcp_full(443, 61700, 0x10, ack=1001))
        report = self.review6([(IN, bytes(tso)), (IN + 0.03, answer4)])
        self.assertEqual(report["host_outbound"], {"tcp_data": 1})
        self.assertNotIn("payload_len", [l for l in report["leaks"] if l["direction"] == "outbound"][0])

    def test_udp_flows_are_attributed_by_their_first_packet(self):
        out = e6(LOCAL_IP6, PEER6, 17, udp_dgram(50341, 443))
        back = e6_in(PEER6, LOCAL_IP6, 17, udp_dgram(443, 50341))
        report = self.review6([(T_CONNECT - 2.2, out), (IN, back)])
        self.assertEqual((report["leak_origins"], report["host_outbound"]), ({"host_preexisting": 1}, {}))
        report = self.review6([(IN, out), (IN + 0.1, back)])
        self.assertEqual(report["leak_origins"], {"host_new_outbound": 2})
        self.assertEqual([l["payload_len"] for l in report["leaks"] if l["class"] == "host"], [12, 12])
        self.assertEqual((report["new_outbound_flows"], report["host_outbound"]), (1, {"udp": 1}))
        # A first packet exactly at connected_at began after Connected.
        report = self.review6([(T_CONNECT, out), (IN, back)])
        self.assertEqual(report["leak_origins"], {"host_new_outbound": 1})
        report = self.review6([(IN, back), (IN + 0.1, out)])
        self.assertEqual((report["leak_origins"], report["new_outbound_flows"]), ({"host_new_inbound": 2}, 0))
        dns = e4(LOCAL_IP, "8.8.8.8", 17, udp_dgram(53000, 53))
        report = self.review6([(IN, dns)])
        self.assertEqual((report["host_outbound"], report["new_outbound_flows"]), ({"dns": 1}, 1))

    def test_an_icmp_error_takes_the_origin_of_the_flow_it_quotes(self):
        back = ipv6_pkt(PEER6, LOCAL_IP6, 17, udp_dgram(443, 50341))
        unreachable = e6(LOCAL_IP6, PEER6, 58, icmp_error(1, 4, back))
        records = [(T_CONNECT - 2.2, e6(LOCAL_IP6, PEER6, 17, udp_dgram(50341, 443))),
                   (IN, ether(back, 0x86DD)), (IN + 0.0001, unreachable)]
        report = self.review6(records)
        self.assertEqual(report["leak_origins"], {"host_preexisting": 2})
        self.assertEqual(report["host_outbound"], {"icmp_error": 1})
        self.assertEqual(report["leak_flows"], {"preexisting": 1})
        # Quoting a flow first seen after connect, the error is new as well.
        report = self.review6(records[1:])
        self.assertEqual(report["leak_origins"], {"host_new_inbound": 2})
        # ICMPv4 errors are read the same way.
        quoted4 = ipv4_pkt("198.51.100.9", LOCAL_IP, 17, udp_dgram(443, 50342))
        report = self.review6([(T_CONNECT - 1, e4(LOCAL_IP, "198.51.100.9", 17, udp_dgram(50342, 443))),
                               (IN, e4(LOCAL_IP, "198.51.100.9", 1, icmp_error(3, 3, quoted4)))])
        self.assertEqual((report["leak_origins"], report["host_outbound"]),
                         ({"host_preexisting": 1}, {"icmp_error": 1}))
        # An unreadable quote, or one naming no captured flow, is unattributed.
        for quoted in (b"\x60\x00", ipv6_pkt(PEER6, LOCAL_IP6, 17, udp_dgram(443, 59999))):
            report = self.review6([(IN, e6(LOCAL_IP6, PEER6, 58, icmp_error(1, 4, quoted)))])
            self.assertEqual(report["leak_origins"], {"host_unattributed": 1}, quoted)
            self.assertEqual(report["host_outbound"], {"icmp_error": 1})

    def test_echo_started_by_the_gateway_is_new_inbound_never_new_outbound(self):
        records = [(IN, e4_in("192.168.1.1", LOCAL_IP, 1, icmp_echo(8, 7))),
                   (IN, e6_in("fe80::1", "fe80::50", 58, icmp_echo(128, 8))),
                   (IN + 0.0005, e6("fe80::50", "fe80::1", 58, icmp_echo(129, 8))),
                   (IN, e6_in("2001:db8::1", LOCAL_IP6, 58, icmp_echo(128, 9))),
                   (IN + 0.0005, e6(LOCAL_IP6, "2001:db8::1", 58, icmp_echo(129, 9)))]
        report = self.review6(records, extra=["--local-addr", "fe80::50"])
        self.assertEqual(report["leak_origins"], {"host_new_inbound": 5})
        self.assertEqual((report["leak_flows"], report["new_outbound_flows"]), ({"new_inbound": 3}, 0))
        self.assertEqual(report["host_outbound"], {"icmp_echo_reply": 2})
        self.assertFalse(report["pass"])
        # The Mac's own echo request is a new outbound flow.
        report = self.review6([(IN, e6(LOCAL_IP6, PEER6, 58, icmp_echo(128, 3))),
                               (IN + 0.01, e6_in(PEER6, LOCAL_IP6, 58, icmp_echo(129, 3)))])
        self.assertEqual((report["leak_origins"], report["new_outbound_flows"]), ({"host_new_outbound": 2}, 1))
        self.assertEqual(report["host_outbound"], {"icmp_echo_request": 1})
        # Echo ids keep two pings apart.
        report = self.review6([(T_CONNECT - 1, e6(LOCAL_IP6, PEER6, 58, icmp_echo(128, 3))),
                               (IN, e6(LOCAL_IP6, PEER6, 58, icmp_echo(128, 4)))])
        self.assertEqual(report["leak_origins"], {"host_new_outbound": 1})

    def test_the_mac_is_found_by_its_ethernet_address_without_a_local_address(self):
        # A packet with the tunnel source, or from the Mac's MAC, is the Mac's own.
        tun = e4("198.19.255.1", "198.51.100.9", 6, tcp_full(40000, 443, 0x02))
        report = self.review(pcap_bytes(clean_records() + [(IN, tun)]))
        self.assertEqual((report["host_outbound"], report["leaks"][0]["direction"]), ({"tcp_syn": 1}, "outbound"))
        stray_in = e6_in(PEER6, "2001:db8::77", 17, udp_dgram(443, 40002))
        report = self.review(pcap_bytes(clean_records() + [(IN, stray_in)]), extra=["--local-mac", MAC_BYTES.hex(":")])
        self.assertEqual((report["leak_origins"], report["leaks"][0]["direction"]), ({"host_new_inbound": 1}, "inbound"))
        # ICMPv6 inside IPv4 is read for its type only: no echo flow.
        odd = e4(LOCAL_IP, "198.51.100.9", 58, icmp_echo(128, 5))
        report = self.review(pcap_bytes(clean_records() + [(IN, odd)]))
        self.assertEqual((report["leak_origins"], report["leaks"][0]["icmp_type"]), ({"host_unattributed": 1}, 128))
        stray = e6("2001:db8::77", PEER6, 17, udp_dgram(40001, 443))
        report = self.review(pcap_bytes(clean_records() + [(IN, stray)]), extra=["--local-mac", MAC_BYTES.hex(":")])
        self.assertEqual((report["host_outbound"], report["new_outbound_flows"]), ({"udp": 1}, 1))
        report = self.review(pcap_bytes(clean_records() + [(IN, stray)]))
        self.assertEqual((report["host_outbound"], report["leak_origins"]), ({}, {"host_new_outbound": 1}))

    def test_other_leaks_keep_their_class_and_no_payload_byte_is_written(self):
        marker = b"AEGIS-S20A-PAYLOAD-MARKER"
        other = b"\x02\x00\x00\x00\x00\x09"
        foreign = b"\x01\x00\x5e\x7f\xff\xfa" + other + struct.pack(">H", 0x0800) + ipv4_pkt(
            "192.168.1.9", "239.255.255.250", 17, udp_dgram(1900, 1900, marker))
        records = [(IN, foreign), (IN, e4(LOCAL_IP, "224.0.0.22", 2, bytes([0x22, 0, 0, 0]) + b"\x00" * 4)),
                   (IN, ether(b"\x02\x07" + b"\x00" * 20, 0x88CC)), (IN, b"\x02"),
                   (IN, e4(LOCAL_IP, "198.51.100.9", 6, tcp_full(61000, 443, 0x18, data=marker))),
                   (IN, e4(LOCAL_IP, "198.51.100.9", 50, marker)),             # ESP: no flow identity
                   (None, e4(LOCAL_IP, "198.51.100.9", 17, udp_dgram(61001, 443, marker)))]
        with tempfile.TemporaryDirectory(prefix="aegis-s20a-") as temp:
            pcap = pathlib.Path(temp) / "physical.pcap"
            pcap.write_bytes(pcapng_bytes(clean_records() + [r for r in records if r[0] is not None])
                             + _untimed_block(records[-1][1]))
            out = pathlib.Path(temp) / "leak-review.json"
            subprocess.run([sys.executable, "-I", str(LEAK_REVIEW), "--pcap", str(pcap), "--relay-ip", RELAY_IP,
                            "--relay-port", "443", "--out", str(out), "--local-addr", LOCAL_IP,
                            "--local-mac", MAC_BYTES.hex(":"), "--connected-at", repr(T_CONNECT),
                            "--disconnect-at", repr(T_DISCONNECT)], capture_output=True, timeout=30)
            text = out.read_text()
        report = json.loads(text)
        self.assertNotIn(marker.decode(), text)
        self.assertNotIn(marker.hex(), text)
        self.assertFalse(report["pass"])
        self.assertEqual(report["leak_origins"], {"foreign": 1, "igmp": 1, "link_control": 1, "unparsed": 1,
                                                  "host_preexisting_inferred": 1, "host_unattributed": 2})
        # The Mac's own mid-stream data still shows as data, never as residue.
        self.assertEqual(report["leak_count"], 7)
        self.assertEqual(report["host_outbound"], {"tcp_data": 1, "other": 1, "udp": 1})
        self.assertEqual([l["payload_len"] for l in report["leaks"] if l.get("proto") == "tcp"], [len(marker)])

    def test_no_connected_interval_or_an_unreadable_file_fails(self):
        report = self.review(pcap_bytes(clean_records()), connected=None)
        self.assertFalse(report["pass"])
        self.assertIsNone(report["connected_interval"])
        report = self.review(pcap_bytes(clean_records()), connected=T_CONNECT, disconnect=T_CONNECT + 1.5)
        self.assertFalse(report["pass"])
        report = self.review(b"not a capture at all")
        self.assertFalse(report["pass"])
        self.assertIn("CaptureError", report["error"])

    # ------------------------------------------------ S20d Mac-sent criterion

    def mac_review(self, records=(), extra=(), mac=True, data=None, connected=T_CONNECT, disconnect=T_DISCONNECT):
        """leak_review.py with the Mac's MAC (unless mac=False) and both local
        addresses; returns the report and the summary line."""
        with tempfile.TemporaryDirectory(prefix="aegis-s20d-") as temp:
            pcap = pathlib.Path(temp) / "physical.pcap"
            pcap.write_bytes(data if data is not None else pcap_bytes(clean_records() + list(records)))
            out = pathlib.Path(temp) / "leak-review.json"
            args = [sys.executable, "-I", str(LEAK_REVIEW), "--pcap", str(pcap), "--relay-ip", RELAY_IP,
                    "--relay-port", "443", "--out", str(out), "--local-addr", LOCAL_IP, "--local-addr", LOCAL_IP6,
                    *extra]
            if connected is not None:
                args += ["--connected-at", repr(connected), "--disconnect-at", repr(disconnect)]
            if mac:
                args += ["--local-mac", MAC_BYTES.hex(":")]
            result = subprocess.run(args, capture_output=True, text=True, timeout=30)
            report = json.loads(out.read_text())
        # The Mac-sent criterion never changes the exit code.
        self.assertEqual(result.returncode, 0 if report["pass"] else 1, result.stdout + result.stderr)
        line = result.stdout.rstrip("\n")
        self.assertEqual(result.stdout.count("\n"), 1, result.stdout)
        self.assertTrue(line.endswith(f" mac_sent_leaks={report['mac_sent_leaks']} "
                                      f"mac_sent_pass={str(report['mac_sent_pass']).lower()}"), line)
        self.assertEqual(report["mac_sent_leaks"], sum(report["mac_sent_classes"].values()), report)
        self.assertEqual(report["mac_sent_leaks"], sum(report["mac_sent_origins"].values()), report)
        self.assertEqual(report["mac_sent_pass"], report["mac_sent_leaks"] == 0 and "mac_sent_error" not in report)
        self.assertEqual(len(report["mac_sent_frames"]), min(report["mac_sent_leaks"], 1000))
        return report, line

    def test_a_mac_sent_keepalive_on_an_old_socket_fails_the_mac_sent_criterion(self):
        probe = e6(LOCAL_IP6, PEER6, 6, tcp_full(61679, 443, 0x10, seq=1000, ack=50))
        answer = e6_in(PEER6, LOCAL_IP6, 6, tcp_full(443, 61679, 0x10, seq=50, ack=1001))
        report, line = self.mac_review([(T_CONNECT - 2, probe), (IN, probe), (IN + 0.03, answer)])
        self.assertFalse(report["pass"])
        self.assertEqual(report["host_outbound"], {"tcp_keepalive": 1})
        self.assertEqual((report["mac_sent_leaks"], report["mac_sent_classes"], report["mac_sent_origins"]),
                         (1, {"tcp_keepalive": 1}, {"preexisting": 1}))
        self.assertFalse(report["mac_sent_pass"])
        self.assertNotIn("mac_sent_error", report)
        frame = report["mac_sent_frames"][0]
        self.assertEqual((frame["class"], frame["origin"], frame["direction"]), ("tcp_keepalive", "preexisting", "outbound"))
        self.assertTrue(line.startswith("leak_review pass=false leaks=2 relay=20 "), line)
        self.assertTrue(line.endswith(" foreign=0 mac_sent_leaks=1 mac_sent_pass=false"), line)
        # The Mac's Ethernet source alone makes a frame its own, as does the
        # tunnel address; neither needs a local address.
        for frame, klass in ((e6("2001:db8::77", PEER6, 17, udp_dgram(40001, 443)), "udp"),
                             (e4("198.19.255.1", "198.51.100.9", 6, tcp_full(40000, 443, 0x02)), "tcp_syn")):
            report, line = self.mac_review([(IN, frame)])
            self.assertEqual(report["mac_sent_classes"], {klass: 1}, report)
        tun = from_device(ipv4_pkt("198.19.255.1", "198.51.100.9", 6, tcp_seg(40000, 443)), 0x0800, dst=GATEWAY_MAC)
        report, line = self.mac_review([(IN, tun)])
        self.assertEqual(report["mac_sent_classes"], {"tcp_syn": 1})
        # A local source address from another MAC is still the Mac's.
        spoof = from_device(ipv4_pkt(LOCAL_IP, "198.51.100.9", 17, udp_dgram(40002, 53)), 0x0800, dst=GATEWAY_MAC)
        report, line = self.mac_review([(IN, spoof)])
        self.assertEqual(report["mac_sent_classes"], {"dns": 1})

    def test_inbound_and_foreign_frames_pass_the_mac_sent_criterion_while_pass_stays_false(self):
        records = [
            (T_CONNECT - 2, e6(LOCAL_IP6, PEER6, 6, tcp_full(61730, 443, 0x02, seq=100))),
            (T_CONNECT - 1.9, e6_in(PEER6, LOCAL_IP6, 6, tcp_full(443, 61730, 0x12, seq=7, ack=101))),
            # Arrivals: data on an old socket, a new UDP flow, the gateway's ping.
            (IN, e6_in(PEER6, LOCAL_IP6, 6, tcp_full(443, 61730, 0x18, seq=8, ack=101, data=b"\x17" * 31))),
            (IN + 0.1, e6_in(PEER6, LOCAL_IP6, 17, udp_dgram(443, 50341))),
            (IN + 0.2, e4_in("192.168.1.1", LOCAL_IP, 1, icmp_echo(8, 7))),
            # Other devices' frames.
            (IN + 0.3, from_device(ipv4_pkt("192.168.1.9", "239.255.255.250", 17, udp_dgram(1900, 1900)), 0x0800)),
            (IN + 0.4, from_device(ipv4_pkt("192.168.1.9", "192.168.1.10", 6, tcp_seg(40000, 22)), 0x0800,
                                   dst=b"\x02\x00\x00\x00\x00\x0a")),
            (IN + 0.5, from_device(ipv4_pkt("192.168.1.9", "224.0.0.22", 2, bytes([0x22, 0, 0, 0]) + b"\x00" * 4),
                                   0x0800)),
            (IN + 0.6, from_device(b"\x02\x07" + b"\x00" * 20, 0x88CC, dst=b"\x01\x80\xc2\x00\x00\x0e")),
            (IN + 0.7, from_device(ipv4_pkt("192.168.1.9", "224.0.0.251", 17, udp_dgram(5353, 5353)), 0x0800)),
            (IN + 0.8, from_device(ipv4_pkt("192.168.1.9", "255.255.255.255", 17, udp_dgram(68, 67)), 0x0800,
                                   dst=b"\xff" * 6)),
        ]
        report, line = self.mac_review(records)
        self.assertFalse(report["pass"])
        self.assertEqual(report["leak_count"], 7)
        self.assertEqual(report["leak_classes"], {"host": 3, "foreign": 2, "igmp": 1, "link_control": 1})
        self.assertEqual(report["host_outbound"], {})
        self.assertEqual((report["mac_sent_leaks"], report["mac_sent_classes"], report["mac_sent_guard"]), (0, {}, 0))
        self.assertTrue(report["mac_sent_pass"], report)
        self.assertTrue(line.startswith("leak_review pass=false leaks=7 "), line)
        self.assertTrue(line.endswith(" mac_sent_leaks=0 mac_sent_pass=true"), line)
        # The Mac's own answer to the ping is its own frame.
        report, line = self.mac_review(records + [(IN + 0.2005, e4(LOCAL_IP, "192.168.1.1", 1, icmp_echo(0, 7)))])
        self.assertEqual((report["mac_sent_classes"], report["mac_sent_origins"]),
                         ({"icmp_echo_reply": 1}, {"new_inbound": 1}))

    def test_mac_sent_mdns_broadcast_and_igmp_fail_the_mac_sent_criterion(self):
        cases = (
            (e4(LOCAL_IP, "224.0.0.251", 17, udp_dgram(5353, 5353)), "mdns", True),
            (e6("fe80::50", "ff02::fb", 17, udp_dgram(5353, 5353)), "mdns", True),
            (e4(LOCAL_IP, "192.168.1.255", 17, udp_dgram(137, 137)), "broadcast", True),
            (e4(LOCAL_IP, "255.255.255.255", 17, udp_dgram(9, 9), mac=b"\xff" * 6), "broadcast", True),
            (e4(LOCAL_IP, "224.0.0.22", 2, bytes([0x22, 0, 0, 0]) + b"\x00" * 4), "igmp", False),
            (e4(LOCAL_IP, "239.255.255.250", 17, udp_dgram(5353, 1900)), "udp", False),
            (e4(LOCAL_IP, "198.51.100.9", 1, icmp_echo(8, 3)), "icmp_echo_request", False),
            (e6(LOCAL_IP6, PEER6, 58, icmp_error(1, 4, ipv6_pkt(PEER6, LOCAL_IP6, 17, udp_dgram(443, 50341)))),
             "icmp_error", False),
            (e6(LOCAL_IP6, PEER6, 58, icmpv6(140)), "icmp_other", False),
            (e4(LOCAL_IP, "198.51.100.9", 6, tcp_full(61000, 443, 0x18, data=b"\x00" * 5)), "tcp_data", False),
            (e4(LOCAL_IP, "198.51.100.9", 6, tcp_full(61000, 443, 0x14)), "tcp_control", False),
            (e4(LOCAL_IP, "198.51.100.9", 50, b"\x00" * 8), "other", False),
        )
        for frame, klass, strict_pass in cases:
            with self.subTest(klass=klass):
                report, line = self.mac_review([(IN, frame)], extra=["--broadcast", "192.168.1.255"])
                # pass excludes mDNS and LAN broadcast; the Mac-sent criterion does not.
                self.assertEqual(report["pass"], strict_pass, report)
                self.assertEqual((report["mac_sent_leaks"], report["mac_sent_classes"]), (1, {klass: 1}), report)
                self.assertFalse(report["mac_sent_pass"])
                self.assertTrue(line.endswith(" mac_sent_leaks=1 mac_sent_pass=false"), line)

    def test_an_unparsed_frame_counts_unless_another_device_sent_it(self):
        other = b"\x02\x00\x00\x00\x00\x09"
        cut = b"\x08\x00\x45\x00"   # an IPv4 frame cut short after its Ethernet header
        for frame, counted in ((b"\x02\x00\x00", True),            # no Ethernet source at all
                               (GATEWAY_MAC + MAC_BYTES + cut, True),  # the Mac's
                               (GATEWAY_MAC + other + cut, False)):    # another device's
            with self.subTest(frame=frame.hex()):
                report, line = self.mac_review([(IN, frame)])
                self.assertEqual((report["pass"], report["leak_classes"]), (False, {"unparsed": 1}))
                self.assertEqual(report["mac_sent_classes"], {"unparsed": 1} if counted else {})
                self.assertEqual(report["mac_sent_origins"], {"unattributed": 1} if counted else {})
                self.assertEqual(report["mac_sent_pass"], not counted)
        # Without the Mac's MAC no Ethernet source can clear it.
        report, line = self.mac_review([(IN, GATEWAY_MAC + other + cut)], mac=False)
        self.assertEqual((report["mac_sent_leaks"], report["mac_sent_pass"]), (1, False))
        # A truncated last record has no frame at all.
        report, line = self.mac_review(data=pcap_bytes(clean_records())[:-10])
        self.assertEqual(report["mac_sent_classes"], {"unparsed": 1})
        # Untimed frames: the Mac's, or one whose sender is unknown, count.
        foreign = from_device(ipv4_pkt("192.168.1.9", "239.255.255.250", 17, udp_dgram(1900, 1900)), 0x0800)
        mine = e4(LOCAL_IP, "198.51.100.9", 17, udp_dgram(61001, 443))
        arrival = e4_in("198.51.100.9", LOCAL_IP, 17, udp_dgram(443, 61001))
        for frame, counted in ((foreign, 0), (mine, 1), (arrival, 0)):
            data = pcapng_bytes(clean_records()) + _untimed_block(frame)
            report, line = self.mac_review(data=data)
            self.assertEqual(report["mac_sent_leaks"], counted, report)
            self.assertEqual(report["mac_sent_guard"], 0)
        self.assertEqual((report["mac_sent_frames"], report["leak_count"]), ([], 1))
        report, line = self.mac_review(data=pcapng_bytes(clean_records()) + _untimed_block(mine))
        self.assertEqual((report["mac_sent_frames"][0]["reason"], report["mac_sent_origins"]),
                         ("no timestamp", {"unattributed": 1}))
        # Raw IP has no Ethernet source: an untimed arrival counts, a timed one does not.
        relay = [(T_CONNECT + 2 + i, ipv4_pkt(LOCAL_IP, RELAY_IP, 6, tcp_seg(50000, 443))) for i in range(3)]
        raw_in = ipv4_pkt("198.51.100.9", LOCAL_IP, 17, udp_dgram(443, 61001))
        report, line = self.mac_review(data=pcapng_bytes(relay + [(IN, raw_in)], linktype=101))
        self.assertEqual((report["mac_sent_leaks"], report["mac_sent_pass"]), (0, True))
        report, line = self.mac_review(data=pcapng_bytes(relay, linktype=101) + _untimed_block(raw_in))
        self.assertEqual((report["mac_sent_leaks"], report["mac_sent_pass"]), (1, False))

    def test_without_local_mac_or_a_relay_packet_mac_sent_pass_is_false_and_says_why(self):
        report, line = self.mac_review(mac=False)
        self.assertTrue(report["pass"])
        self.assertEqual((report["mac_sent_leaks"], report["mac_sent_pass"]), (0, False))
        self.assertIn("no --local-mac", report["mac_sent_error"])
        self.assertTrue(line.startswith("leak_review pass=true leaks=0 relay=20 "), line)
        self.assertTrue(line.endswith(" mac_sent_leaks=0 mac_sent_pass=false"), line)
        report, line = self.mac_review()
        self.assertTrue(report["mac_sent_pass"])
        self.assertEqual((report["mac_sent_relay_required"], report["mac_sent_frames"]), (True, []))
        # No relay packet: neither passes; --relay-optional (an interface that
        # carries no relay traffic) drops only that term, and only from mac_sent_pass.
        quiet = [(IN, arp_frame())]
        report, line = self.mac_review(data=pcap_bytes(quiet))
        self.assertEqual((report["pass"], report["mac_sent_pass"]), (False, False))
        self.assertEqual(report["mac_sent_error"], "no relay packet inside the Connected interval")
        report, line = self.mac_review(data=pcap_bytes(quiet), extra=["--relay-optional"])
        self.assertEqual((report["pass"], report["mac_sent_pass"], report["mac_sent_relay_required"]), (False, True, False))
        self.assertIn("no relay packet", report["error"])
        self.assertTrue(line.startswith("leak_review pass=false leaks=0 relay=0 "), line)
        report, line = self.mac_review(data=pcap_bytes(quiet + [(IN + 1, e4(LOCAL_IP, "198.51.100.9", 6, tcp_seg(51515, 443)))]),
                                       extra=["--relay-optional"])
        self.assertEqual((report["mac_sent_leaks"], report["mac_sent_pass"]), (1, False))
        report, line = self.mac_review(data=pcap_bytes(quiet), extra=["--relay-optional"], mac=False)
        self.assertEqual(report["mac_sent_pass"], False)
        # No Connected interval: never a pass.
        report, line = self.mac_review(connected=None, extra=["--relay-optional"])
        self.assertEqual((report["pass"], report["mac_sent_pass"]), (False, False))
        self.assertIn("no Connected interval", report["mac_sent_error"])
        # An unreadable file: exit 2, and the line still ends with the criterion.
        with tempfile.TemporaryDirectory(prefix="aegis-s20d-bad-") as temp:
            bad = pathlib.Path(temp) / "physical.pcap"
            bad.write_bytes(b"not a capture at all")
            out = pathlib.Path(temp) / "leak-review.json"
            result = subprocess.run([sys.executable, "-I", str(LEAK_REVIEW), "--pcap", str(bad), "--relay-ip", RELAY_IP,
                                     "--relay-port", "443", "--out", str(out), "--local-mac", MAC_BYTES.hex(":"),
                                     "--connected-at", repr(T_CONNECT), "--disconnect-at", repr(T_DISCONNECT)],
                                    capture_output=True, text=True, timeout=30)
            report = json.loads(out.read_text())
        self.assertEqual(result.returncode, 2)
        self.assertEqual((report["mac_sent_pass"], report["mac_sent_error"]), (False, report["error"]))
        self.assertTrue(result.stdout.startswith("leak_review pass=false leaks=0 "), result.stdout)
        self.assertTrue(result.stdout.endswith(" mac_sent_leaks=0 mac_sent_pass=false\n"), result.stdout)

    def test_eapol_arp_dhcp_nd_mld_and_relay_from_the_mac_never_fail_the_mac_sent_criterion(self):
        frames = [ether(b"\x01\x03\x00\x5f" + b"\x00" * 95, 0x888E),                    # EAPOL key
                  arp_frame(),
                  e4("0.0.0.0", "255.255.255.255", 17, udp_dgram(68, 67), mac=b"\xff" * 6),
                  e4(LOCAL_IP, "192.168.1.1", 17, udp_dgram(68, 67)),
                  e6("fe80::50", "ff02::1:2", 17, udp_dgram(546, 547)),                   # DHCPv6
                  e6("fe80::50", "ff02::2", 58, icmpv6(133)),                             # RS
                  e6("fe80::50", "ff02::1:ff00:1", 58, icmpv6(135)),                      # NS
                  e6("fe80::50", "fe80::1", 58, icmpv6(136)),                             # NA
                  e6("fe80::50", "ff02::16", 58, icmpv6(143), hop_by_hop=True),           # MLDv2
                  e4(LOCAL_IP, RELAY_IP, 17, udp_dgram(50104, 443))]                      # relay UDP
        report, line = self.mac_review([(IN + i * 0.01, f) for i, f in enumerate(frames)])
        self.assertEqual((report["mac_sent_leaks"], report["mac_sent_pass"]), (0, True), report)
        # pass still counts the EAPOL frame: the only frame it counts and this does not.
        self.assertEqual((report["pass"], report["leak_classes"]), (False, {"link_control": 1}))
        # Other link-layer frames the Mac sends count; so does a flow to the relay host off its port.
        for frame, klass in ((ether(b"\x02\x07" + b"\x00" * 20, 0x88CC), "link_control"),
                             (ether(b"\x42\x42\x03" + b"\x00" * 35, 38), "link_control"),
                             (ether(b"\x00" * 10, 0x9999), "other"),
                             (e4(LOCAL_IP, RELAY_IP, 6, tcp_seg(50100, 7)), "tcp_syn")):
            report, line = self.mac_review([(IN, frame)])
            self.assertEqual(report["mac_sent_classes"], {klass: 1}, report)

    def test_the_guard_counts_mac_sent_frames_without_failing_them(self):
        syn = e4(LOCAL_IP, "198.51.100.9", 6, tcp_seg(51515, 443))
        records = [(T_CONNECT + 0.5, syn), (T_DISCONNECT - 0.5, syn), (T_CONNECT - 3, syn), (T_DISCONNECT + 2, syn),
                   (T_CONNECT + 0.6, arp_frame()), (T_CONNECT + 0.7, e4_in("198.51.100.9", LOCAL_IP, 6, tcp_seg(443, 51515, 0x12)))]
        report, line = self.mac_review(records)
        self.assertEqual((report["pass"], report["guard_packets"]), (True, 4))
        self.assertEqual((report["mac_sent_guard"], report["mac_sent_leaks"], report["mac_sent_pass"]), (2, 0, True))
        report, line = self.mac_review([(T_CONNECT + 1.1, syn), (T_DISCONNECT - 1.1, syn)])
        self.assertEqual((report["mac_sent_guard"], report["mac_sent_leaks"]), (0, 2))
        self.assertEqual(report["mac_sent_origins"], {"new_outbound": 2})

    def test_mac_sent_identities_count_the_macs_own_frames_from_before_a_rejoin_and_never_change_pass(self):
        # S20e: --local-mac and --local-addr are read after the window; the
        # Mac sent these under its MAC and address from before a rejoin.
        old_mac, old_ip = b"\x02\xab\xcd\xef\x00\x99", "192.168.1.61"
        cut = b"\x08\x00\x45\x00"
        records = [
            (IN, GATEWAY_MAC + old_mac + b"\x08\x00" + ipv4_pkt("198.51.100.77", "198.51.100.9", 6, tcp_seg(40000, 443))),
            (IN + 0.1, from_device(ipv4_pkt(old_ip, "198.51.100.9", 17, udp_dgram(40003, 443)), 0x0800, dst=GATEWAY_MAC)),
            (IN + 0.2, GATEWAY_MAC + old_mac + cut),
            # Another device's frames stay another device's.
            (IN + 0.3, from_device(ipv4_pkt("192.168.1.9", "198.51.100.9", 6, tcp_seg(40001, 443)), 0x0800,
                                   dst=GATEWAY_MAC)),
        ]
        ids = ["--mac-sent-mac", "02:AB:CD:EF:00:99", "--mac-sent-addr", old_ip, "--mac-sent-addr", "fe80::99%en0"]
        strict = lambda r: {k: v for k, v in r.items() if not k.startswith("mac_sent_")}
        base, base_line = self.mac_review(records)
        self.assertEqual((base["mac_sent_leaks"], base["mac_sent_pass"]), (0, True), base)
        self.assertEqual(base["mac_sent_identity"], {"macs": 1, "addrs": 2})
        more, line = self.mac_review(records, extra=ids)
        self.assertEqual((more["mac_sent_leaks"], more["mac_sent_pass"]), (3, False), more)
        self.assertEqual(more["mac_sent_classes"], {"tcp_syn": 1, "udp": 1, "unparsed": 1})
        self.assertEqual(more["mac_sent_identity"], {"macs": 2, "addrs": 4})
        self.assertEqual([f["direction"] for f in more["mac_sent_frames"] if f["kind"] == "ip"], ["unknown", "outbound"])
        self.assertNotIn("mac_sent_error", more)
        # pass and every strict field, and the summary up to its suffix, ignore them.
        self.assertEqual(strict(more), strict(base))
        suffix = re.compile(r" mac_sent_leaks=[0-9]+ mac_sent_pass=(true|false)$")
        self.assertEqual(suffix.sub("", line), suffix.sub("", base_line))
        # An unreadable identity fails only the Mac-sent criterion.
        bad, bad_line = self.mac_review(extra=["--mac-sent-addr", "not-an-address"])
        self.assertEqual((bad["pass"], bad["mac_sent_leaks"], bad["mac_sent_pass"]), (True, 0, False))
        self.assertEqual(bad["mac_sent_error"], "unreadable --mac-sent-addr: 1 value(s)")
        self.assertEqual(strict(bad), strict(self.mac_review()[0]))
        # Only --local-mac decides no_local_mac; without it an unparsed frame
        # from a known MAC still counts, and so does one from any other.
        nomac, _ = self.mac_review(records, extra=ids, mac=False)
        self.assertIn("no --local-mac", nomac["mac_sent_error"])
        self.assertEqual((nomac["mac_sent_leaks"], nomac["mac_sent_pass"]), (3, False))
        nomac, _ = self.mac_review([(IN, GATEWAY_MAC + b"\x02\x00\x00\x00\x00\x09" + cut)], extra=ids, mac=False)
        self.assertEqual(nomac["mac_sent_classes"], {"unparsed": 1})


def from_device(payload, ethertype, dst=b"\x01\x00\x5e\x7f\xff\xfa"):
    """A frame another device on the LAN sent."""
    return dst + b"\x02\x00\x00\x00\x00\x09" + struct.pack(">H", ethertype) + payload


class LeakReviewInvariantTests(LeakReviewTests):
    """S20d: every LeakReviewTests fixture again, each also reviewed with
    --relay-optional: pass, leak_count, the classes, origins and families,
    every other field that existed before S20d, the exit code and the summary
    line up to its mac_sent_* suffix never move. On the Mac's own frames the
    Mac-sent count covers every listed leak but EAPOL. S20e: the same holds
    with --mac-sent-mac/--mac-sent-addr identities (here other devices' MACs
    and addresses, so they change the Mac-sent count), which only ever add
    Mac-sent frames."""

    MAC_SENT_IDS = ("--mac-sent-mac", "02:00:00:00:00:09", "--mac-sent-mac", "02:00:00:00:00:01",
                    "--mac-sent-addr", "192.168.1.9", "--mac-sent-addr", "198.51.100.9", "--mac-sent-addr", PEER6)

    def run_raw(self, data, connected, disconnect, extra):
        with tempfile.TemporaryDirectory(prefix="aegis-s20d-inv-") as temp:
            pcap = pathlib.Path(temp) / "physical.pcap"
            pcap.write_bytes(data)
            out = pathlib.Path(temp) / "leak-review.json"
            args = [sys.executable, "-I", str(LEAK_REVIEW), "--pcap", str(pcap), "--relay-ip", RELAY_IP,
                    "--relay-port", "443", "--out", str(out), "--local-addr", LOCAL_IP, *extra]
            if connected is not None:
                args += ["--connected-at", repr(connected), "--disconnect-at", repr(disconnect)]
            result = subprocess.run(args, capture_output=True, text=True, timeout=30)
            return result.returncode, result.stdout, json.loads(out.read_text())

    def review(self, data, connected=T_CONNECT, disconnect=T_DISCONNECT, extra=()):
        report = super().review(data, connected, disconnect, extra)
        code, line, plain = self.run_raw(data, connected, disconnect, list(extra))
        code2, line2, optional = self.run_raw(data, connected, disconnect, list(extra) + ["--relay-optional"])
        strict = lambda r: {k: v for k, v in r.items() if not k.startswith("mac_sent_")}
        self.assertEqual(strict(plain), strict(report))
        self.assertEqual((code2, strict(optional)), (code, strict(plain)))
        suffix = re.compile(r" mac_sent_leaks=[0-9]+ mac_sent_pass=(true|false)\n$")
        self.assertRegex(line, suffix)
        self.assertEqual(suffix.sub("", line), suffix.sub("", line2))
        code3, line3, more = self.run_raw(data, connected, disconnect, list(extra) + list(self.MAC_SENT_IDS))
        self.assertEqual((code3, strict(more)), (code, strict(plain)))
        self.assertEqual(suffix.sub("", line3), suffix.sub("", line))
        self.assertGreaterEqual(more.get("mac_sent_leaks", 0), plain.get("mac_sent_leaks", 0), (more, plain))
        if "leaks" in report and len(report["leaks"]) == report["leak_count"]:
            mac = next((extra[i + 1].lower() for i, a in enumerate(extra) if a == "--local-mac"), None)
            local = {LOCAL_IP} | {extra[i + 1] for i, a in enumerate(extra) if a == "--local-addr"}
            own = 0
            for leak in report["leaks"]:
                if leak["kind"] == "unparsed" or "0x888e" in leak.get("reason", ""):
                    continue   # unparsed: decided from raw bytes; EAPOL: excluded
                if (mac and leak.get("eth_src") == mac) or leak.get("src") in local or leak.get("src") == "198.19.255.1":
                    own += 1
                elif leak["time"] is None and not (mac and leak.get("eth_src") and leak["eth_src"] != mac):
                    own += 1
            self.assertGreaterEqual(plain.get("mac_sent_leaks", 0), own, plain)
        return report


WINDOW_FAKE_TCPDUMP = r"""
import os, signal, struct, sys, time
args = sys.argv[1:]
log = open(os.environ["CALLS"], "a", buffering=1)
open(os.environ["FAKE_PIDS"], "a").write(f"tcpdump {os.getpid()}\n")
die_after = float(os.environ.get("FAKE_DIE_AFTER", "0"))
bound = float(args[args.index("-G") + 1]) if "-G" in args and "-W" in args else 0
started = time.time()
if os.environ.get("FAKE_HIDE_ARGS") == "1" and "--hidden" not in args:
    # re-exec under the same pid without the -w file on its command line
    os.environ["FAKE_W"] = args[args.index("-w") + 1]
    os.environ["FAKE_I"] = args[args.index("-i") + 1]
    os.execv(sys.executable, [sys.executable, "-I", __file__, "--hidden"])
iface = args[args.index("-i") + 1] if "-i" in args else os.environ.get("FAKE_I", "en0")
# S20e: which pid captures which interface, beside FAKE_PIDS.
open(os.environ["FAKE_PIDS"] + ".if", "a").write(f"{iface} {os.getpid()}\n")
# FAKE_QUIET_IF: a link that never sees a packet, so like the real tcpdump
# its -G bound (checked only when a packet arrives) never fires there.
quiet = os.environ.get("FAKE_QUIET_IF") == iface
if os.environ.get("FAKE_DIE_IF", iface) != iface:
    die_after = 0   # S20d: FAKE_DIE_IF ends only that interface's capture early
if os.environ.get("FAKE_TCPDUMP_FAIL") == "1" or os.environ.get("FAKE_TCPDUMP_FAIL_IF") == iface:
    sys.stderr.write("tcpdump: %s: You don't have permission to capture on that device\n" % iface)
    sys.exit(1)
out = os.environ["FAKE_W"] if "--hidden" in args else args[args.index("-w") + 1]
state = os.environ["STATE"]
def ip(t): return bytes(int(x) for x in t.split("."))
def frame6(src, dst):
    import ipaddress
    l4 = struct.pack(">HHIIBBHHH", 50001, 443, 1, 0, 0x50, 0x02, 65535, 0, 0)
    pkt = struct.pack(">IHBB16s16s", 0x60000000, len(l4), 6, 64, ipaddress.IPv6Address(src).packed,
                      ipaddress.IPv6Address(dst).packed) + l4
    return b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x86\xdd" + pkt
def frame(src, dst, dport=443, proto=6, eth_src=None):
    if proto == 6:
        l4 = struct.pack(">HHIIBBHHH", 50000, dport, 1, 0, 0x50, 0x02, 65535, 0, 0)
    else:
        l4 = struct.pack(">HHHH", 50000, dport, 12, 0) + b"pong"
    pkt = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0x4000, 64, proto, 0, ip(src), ip(dst)) + l4
    macs = b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02"
    if eth_src:   # S20e: FAKE_LEAK_ETH_SRC, the leak's Ethernet source
        macs = b"\x02\x00\x00\x00\x00\x02" + bytes.fromhex(eth_src.replace(":", ""))
    return macs + b"\x08\x00" + pkt
f = open(out, "wb", buffering=0)
f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
def write(fr):
    ts = time.time(); sec = int(ts)
    f.write(struct.pack("<IIII", sec, int((ts - sec) * 1e6), len(fr), len(fr)) + fr)
stop = []
# v30 review: FAKE_INT_DELAY_S: a capture that takes that long to stop
# after its SIGINT (a slow EXIT trap).
int_delay = float(os.environ.get("FAKE_INT_DELAY_S", "0"))
signal.signal(signal.SIGINT, lambda *a: stop.append(time.time() + int_delay))
sys.stderr.write("tcpdump: listening on %s, link-type EN10MB (Ethernet), snapshot length 160 bytes\n" % iface)
sys.stderr.flush()
# FAKE_LEAK_IF: the injected leaks go out on that interface only.
leak_here = os.environ.get("FAKE_LEAK_IF", iface) == iface
# S20d: FAKE_NO_RELAY_IF: that interface carries no relay traffic (ARP only);
# FAKE_LEAK_SRC: the injected leak's source; FAKE_INBOUND=1: a peer's SYN to
# the Mac instead of a leak; FAKE_DROPS_IF: the kernel drops on that one only.
relay_here = os.environ.get("FAKE_NO_RELAY_IF") != iface
leak_src = os.environ.get("FAKE_LEAK_SRC", "192.168.1.50")
arp = b"\xff" * 6 + b"\x02\x00\x00\x00\x00\x02\x08\x06" + struct.pack(">HHBBH", 1, 0x0800, 6, 4, 1) + b"\x00" * 20
if os.environ.get("FAKE_SIGINFO_STATS") == "1":
    # Ctrl-T in the owner's terminal: tcpdump prints its counters and runs on
    sys.stderr.write("3 packets captured\n3 packets received by filter\n0 packets dropped by kernel\n")
    sys.stderr.flush()
log.write("tcpdump started " + " ".join(args) + "\n")
seen = None; leaked = False
# S20e: FAKE_LEAK_DST/DPORT/PROTO shape the injected leak (224.0.0.251 5353 17: mDNS).
leak_to = (os.environ.get("FAKE_LEAK_DST", "198.51.100.9"), int(os.environ.get("FAKE_LEAK_DPORT", "443")),
           int(os.environ.get("FAKE_LEAK_PROTO", "6")))
while not stop or time.time() < stop[0]:
    if quiet:
        time.sleep(0.1); continue
    if bound and time.time() - started >= bound:
        sys.stderr.write("Maximum file limit reached: 1\n"); break
    write(frame("192.168.1.50", os.environ["RELAY_IP"]) if relay_here else arp)
    if open(state).read().strip() == "Connected":
        seen = seen or time.time()
        if os.environ.get("FAKE_LEAK") == "1" and leak_here and not leaked and time.time() - seen > 2.0:
            write(frame(leak_src, *leak_to, eth_src=os.environ.get("FAKE_LEAK_ETH_SRC"))); leaked = True
        if os.environ.get("FAKE_INBOUND") == "1" and leak_here and not leaked and time.time() - seen > 2.0:
            write(frame("198.51.100.9", "192.168.1.50")); leaked = True
        if os.environ.get("FAKE_LEAK6") == "1" and not leaked and time.time() - seen > 2.0:
            write(frame6("2001:db8:1:2::50", "2001:db8:ffff::9")); leaked = True
        if os.environ.get("FAKE_BYPASS") == "1" and not leaked and time.time() - seen > 2.0:
            # echo TCP 7, echo UDP 7 and whoami 8080 sent around the tunnel
            for dport, proto in ((7, 6), (7, 17), (8080, 6)):
                write(frame("192.168.1.50", os.environ["RELAY_IP"], dport, proto))
            leaked = True
        if die_after and time.time() - seen > die_after:
            break  # the capture ends inside the window, with clean stats
    time.sleep(0.1)
log.write("tcpdump stopped\n")
log.write("tcpdump stopped if=%s\n" % iface)
drops = os.environ.get("FAKE_DROPS", "0")
if os.environ.get("FAKE_DROPS_IF", iface) != iface:
    drops = "0"
sys.stderr.write("100 packets captured\n100 packets received by filter\n%s packets dropped by kernel\n" % drops)
"""

WINDOW_FAKE_COMMANDS = {
    "sudo": r"""#!/bin/sh
echo "sudo $*" >> "$CALLS"
[ "$1" = -n ] || { echo "fake sudo: called without -n" >&2; exit 64; }
shift
case "$1" in
  -l) case "$2" in
        /usr/sbin/tcpdump) ok=${FAKE_SUDO_OK:-1};;
        /bin/kill) ok=${FAKE_SUDO_KILL_LIST:-${FAKE_SUDO_OK:-1}};;
        /usr/bin/pmset) ok=${FAKE_SUDO_PMSET:-0}
          # v30: refuse only a caller whose parent launchd adopted (the
          # detached sleep guard), as a per-terminal credential would.
          if [ "${FAKE_SUDO_DETACHED_REFUSES:-0}" = 1 ] && [ "$(ps -o ppid= -p "$PPID" | tr -d ' ')" = 1 ]; then ok=0; fi;;
        /usr/bin/perl) ok=${FAKE_SUDO_PERL:-${FAKE_SUDO_OK:-1}};;
        *) ok=0;;
      esac
      [ "$ok" = 1 ] && exit 0; echo "sudo: a password is required" >&2; exit 1;;
  /usr/sbin/tcpdump) shift
      # parent: like sudo 1.9 with use_pty, sudo and its monitor stay the
      # parents of tcpdump and ignore every signal from the caller.
      [ "${FAKE_SUDO_MODE:-exec}" = parent ] && exec python3 -I "$FAKE_SUDO_PARENT" sudo "$@"
      exec python3 -I "$FAKE_TCPDUMP" "$@";;
  /bin/kill) shift; [ "${FAKE_KILL_OK:-1}" = 1 ] || { echo "sudo: a password is required" >&2; exit 1; }
      exec /bin/kill "$@";;
  /usr/bin/pmset) shift; [ "${FAKE_SUDO_PMSET:-0}" = 1 ] || { echo "sudo: a password is required" >&2; exit 1; }
      # v30 review: FAKE_SUDO_PMSET_CHILD=1: like sudo with use_pty, the
      # root pmset is sudo's child, which a kill of sudo does not reach.
      if [ "${FAKE_SUDO_PMSET_CHILD:-0}" = 1 ] && [ "$1" = sleepnow ]; then
        "$FAKE_PMSET" "$@" </dev/null >/dev/null 2>&1 & wait $!; exit $?
      fi
      exec "$FAKE_PMSET" "$@";;
  /usr/bin/perl) shift
      # The captures' root alarm: the real perl runs the window's own alarm
      # code, with the fake tcpdump in place of /usr/sbin/tcpdump.
      # FAKE_ALARM_S shortens the alarm for a test that waits for it.
      [ "$1" = -e ] && [ "$4" = /usr/sbin/tcpdump ] || { echo "fake sudo: unexpected perl $*" >&2; exit 1; }
      code=$2 bound=${FAKE_ALARM_S:-$3}; shift 4
      exec /usr/bin/perl -e "$code" "$bound" python3 -I "$FAKE_TCPDUMP" "$@";;
esac
exit 1
""",
    "scutil": r"""#!/bin/sh
case "$1 $2" in
  "--nc status") cat "$STATE"; echo "Extended Status <dictionary> {";;
  "--nc stop") echo "scutil $*" >> "$CALLS"; echo Disconnected > "$STATE";;
  "--dns "*) printf 'DNS configuration\n\nresolver #1\n  nameserver[0] : 198.19.255.2\n  nameserver[1] : fd00:ae61::2\n';;
esac
""",
    "route": r"""#!/bin/sh
# FAKE_PHYS_DEF6: the IPv6 default interface while Disconnected, when it is not en0.
if [ "$(cat "$STATE")" = Connected ]; then echo "  interface: utun9"
else case "$*" in *-inet6*) echo "  interface: ${FAKE_PHYS_DEF6:-en0}";; *) echo "  interface: en0";; esac; fi
""",
    "ifconfig": r"""#!/bin/sh
# en0 carries one global IPv6 address that must never reach results or logs.
# S20e: FAKE_EN0_ROTATE=1: after the window (Disconnected once Connected)
# en0 has rejoined with a new private MAC and a new IPv4 lease; connect:
# from the connect on (a rejoin early in the window), so only the reading
# before connect knows the old ones.
if [ -z "$1" ] || [ "$1" = en0 ]; then
  mac=02:00:00:00:00:01 v4=192.168.1.50
  if { [ "${FAKE_EN0_ROTATE:-0}" = 1 ] && [ -e "$STATE.was-connected" ] && [ "$(cat "$STATE")" != Connected ]; } \
     || { [ "${FAKE_EN0_ROTATE:-0}" = connect ] && [ -e "$STATE.was-connected" ]; }; then
    mac=02:00:00:00:00:21 v4=192.168.1.77
  fi
  printf 'en0: flags=8863<UP> mtu 1500\n\tether %s\n\tinet6 fe80::1c%%en0 prefixlen 64 scopeid 0x6\n\tinet6 2001:db8:1:2::50 prefixlen 64 autoconf secured\n\tinet %s netmask 0xffffff00 broadcast 192.168.1.255\n' "$mac" "$v4"
fi
# FAKE_EN1_V6: a second, IPv6-only service on en1 with its own global address.
if [ -n "${FAKE_EN1_V6:-}" ] && { [ -z "$1" ] || [ "$1" = en1 ]; }; then
  printf 'en1: flags=8863<UP> mtu 1500\n\tether 02:00:00:00:00:02\n\tinet6 fe80::2%%en1 prefixlen 64 scopeid 0x7\n\tinet6 %s prefixlen 64 autoconf secured\n' "$FAKE_EN1_V6"
fi
if [ -z "$1" ]; then
  printf 'lo0: flags=8049<UP,LOOPBACK> mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000\n\tinet6 ::1 prefixlen 128\n\tinet6 fe80::1%%lo0 prefixlen 64 scopeid 0x1\n'
fi
if { [ -z "$1" ] || [ "$1" = utun9 ]; } && [ "$(cat "$STATE")" = Connected ]; then
  printf 'utun9: flags=8051<UP> mtu 1400\n\tinet 198.19.255.1 --> 198.19.255.1 netmask 0xffffffff\n\tinet6 fe80::9%%utun9 prefixlen 64 scopeid 0x13\n\tinet6 fd00:ae61::1 prefixlen 120\n'
fi
# S20d: FAKE_EN5=active (or late: active only while Connected) is a second
# active interface; FAKE_EN5_NO_ETHER=1 hides its MAC. S20e: appear: en5
# exists, active, only while Connected (an adapter plugged in mid-window).
want() { [ -z "$ARG" ] || [ "$ARG" = "$1" ]; }
ARG=${1:-}
if [ -n "${FAKE_EN5:-}" ] && want en5 && { [ "$FAKE_EN5" != appear ] || [ "$(cat "$STATE")" = Connected ]; }; then
  printf 'en5: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n'
  [ "${FAKE_EN5_NO_ETHER:-0}" = 1 ] || printf '\tether 02:00:00:00:00:05\n'
  if [ "$FAKE_EN5" = active ] || [ "$FAKE_EN5" = appear ] || { [ "$FAKE_EN5" = late ] && [ "$(cat "$STATE")" = Connected ]; }; then
    printf '\tinet6 fe80::5%%en5 prefixlen 64 scopeid 0x9\n\tinet 10.0.5.50 netmask 0xffffff00 broadcast 10.0.5.255\n\tstatus: active\n'
  else
    printf '\tstatus: inactive\n'
  fi
fi
# FAKE_IGNORED_IFS=1: awdl0 (active, link-local only), which is captured, and
# interfaces that S20d skipped and S20e captures (llw0 and en8 without a link,
# en6 link-local only, bridge0, ap1, anpi0) or still skips (down, tunnel, VM).
if [ "${FAKE_IGNORED_IFS:-0}" = 1 ]; then
  want awdl0 && printf 'awdl0: flags=8943<UP,BROADCAST,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1500\n\tether 02:00:00:00:00:0a\n\tinet6 fe80::a%%awdl0 prefixlen 64 scopeid 0xb\n\tstatus: active\n'
  want llw0 && printf 'llw0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n\tether 02:00:00:00:00:0b\n\tinet6 fe80::b%%llw0 prefixlen 64 scopeid 0xc\n\tstatus: inactive\n'
  want bridge0 && printf 'bridge0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n\tether 02:00:00:00:00:1b\n\tinet 10.0.9.1 netmask 0xffffff00 broadcast 10.0.9.255\n\tstatus: active\n'
  want ap1 && printf 'ap1: flags=8843<UP,BROADCAST,RUNNING> mtu 1500\n\tether 02:00:00:00:00:1c\n\tinet 10.0.10.1 netmask 0xffffff00\n\tstatus: active\n'
  want anpi0 && printf 'anpi0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n\tether 02:00:00:00:00:1d\n\tinet6 2001:db8:a::1 prefixlen 64\n\tstatus: active\n'
  want gif0 && printf 'gif0: flags=8010<POINTOPOINT,MULTICAST> mtu 1280\n'
  want stf0 && printf 'stf0: flags=0<> mtu 1280\n'
  want en6 && printf 'en6: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n\tether 02:00:00:00:00:06\n\tinet6 fe80::6%%en6 prefixlen 64 scopeid 0xd\n\tstatus: active\n'
  want en8 && printf 'en8: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n\tether 02:00:00:00:00:08\n\tinet 10.0.8.50 netmask 0xffffff00\n\tstatus: inactive\n'
  want en9 && printf 'en9: flags=8822<BROADCAST,SMART,SIMPLEX,MULTICAST> mtu 1500\n\tether 02:00:00:00:00:09\n\tinet 10.0.11.50 netmask 0xffffff00\n\tstatus: active\n'
  want utun3 && printf 'utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380\n\tinet 10.0.12.1 --> 10.0.12.1 netmask 0xffffffff\n\tstatus: active\n'
  # S20e: a VM's host-side port and its NAT bridge, whose only member it is.
  want vmenet0 && printf 'vmenet0: flags=8963<UP,BROADCAST,SMART,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1500\n\tether 02:00:00:00:00:0e\n\tstatus: active\n'
  want bridge100 && printf 'bridge100: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tether 02:00:00:00:00:0f\n\tinet 192.168.64.1 netmask 0xffffff00 broadcast 192.168.64.255\n\tmember: vmenet0 flags=3<LEARNING,DISCOVER>\n\t        ifmaxaddr 0 port 20 priority 0 path cost 0\n\tstatus: active\n'
fi
# S20e: FAKE_TB_BRIDGE=1: a Thunderbolt Bridge cable to another Mac. bridge0
# holds the only (link-local) address; its member en1 is active without an
# address of its own, en2 has no link.
if [ "${FAKE_TB_BRIDGE:-0}" = 1 ]; then
  want bridge0 && printf 'bridge0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tether 02:00:00:00:00:0b\n\tinet 169.254.7.7 netmask 0xffff0000 broadcast 169.254.255.255\n\tmember: en1 flags=3<LEARNING,DISCOVER>\n\t        ifmaxaddr 0 port 9 priority 0 path cost 0\n\tmember: en2 flags=3<LEARNING,DISCOVER>\n\tstatus: active\n'
  want en1 && printf 'en1: flags=8963<UP,BROADCAST,SMART,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1500\n\tether 02:00:00:00:00:0c\n\tstatus: active\n'
  want en2 && printf 'en2: flags=8963<UP,BROADCAST,SMART,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1500\n\tether 02:00:00:00:00:0d\n\tstatus: inactive\n'
fi
exit 0
""",
    "netstat": "#!/bin/sh\nprintf 'Internet6:\\ndefault fe80::%%utun9 UGcIg utun9\\nfd00:ae61::/120 fd00:ae61::1 UC utun9\\n'\n",
    "nc": "#!/bin/sh\ncat\n",
    "dig": "#!/bin/sh\ncase \"$*\" in *TXT*) echo '\"v=fake\"';; *AAAA*) echo 2001:db8:5::1;; *) echo 198.18.0.9;; esac\n",
    "curl": "#!/bin/sh\ncase \"$*\" in *-w*) printf '200\\n';; *\"-6 \"*) printf '%s' \"${FAKE_WHOAMI6_BODY-}\";;"
            " *) echo \"ip=$RELAY_IP\";; esac\n",
    # Stands in for /usr/bin/python3 running harness/net_probe.py: the
    # window tests never dial the handoff's targets.
    "probe_py": r"""#!/bin/sh
echo "probe $3 $4" >> "$CALLS"
case "$3" in
  tcp) case "$4" in hc) echo 4/7/eof;; *) echo 4/7/full;; esac;;
  source6) echo "${FAKE_SRC6:-fd00:ae61::1}";;
  aaaa) echo 2001:db8:5::1;;
  scan64) exec "$SYSTEM_PY" "$@";;
  *) exit 2;;
esac
""",
}

WINDOW_FAKE_SUDO_PARENT = r"""
import os, signal, subprocess, sys
for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
    signal.signal(s, signal.SIG_IGN)
role, args = sys.argv[1], sys.argv[2:]
open(os.environ["FAKE_PIDS"], "a").write(f"{role} {os.getpid()}\n")
if role == "sudo":
    child = [sys.executable, "-I", __file__, "monitor", *args]
else:
    child = [sys.executable, "-I", os.environ["FAKE_TCPDUMP"], *args]
sys.exit(subprocess.Popen(child).wait())
"""

WINDOW_FAKE_HOST = r"""#!/bin/sh
case "$1" in
  --filter-status) echo "${FAKE_FILTER_LINE:-filter_result=ok exit_code=0 configured=true enabled=true filter_packets=true filter_sockets=false packet_bundle_id=match grade=firewall attached=true pid_match=true mode=open armed_token=none dropped=0 allowed=0}"
     echo '{"schema":"aegis-ne-xpc-v1","verb":"filter-status","report":{}}'
     exit "${FAKE_FILTER_EXIT:-0}";;
  --list) echo "profile index=0 owner_generation=0A1B2C3D-0000-4000-8000-000000000001 scutil_service_id=1111AAAA-2222-3333-4444-555566667777 intent_valid=true on_demand_enabled=false";;
  --connect) echo "host $*" >> "$CALLS"; echo Connected > "$STATE"; : > "$STATE.was-connected";;
  --emergency-stop) echo "host $*" >> "$CALLS"; echo Disconnected > "$STATE";;
esac
"""


class RealRelayWindowLeakCaptureTests(unittest.TestCase):
    """LEAK_CAPTURE=1 of harness/real-relay-window.sh against fake system
    commands on PATH, a fake app under APP, a temporary HOME and a fake
    tcpdump behind a fake sudo. Nothing here dials, captures or tunnels."""

    def run_window(self, kill_when_connected=False, handoff_extra=None, **env_extra):
        temp = tempfile.TemporaryDirectory(prefix="aegis-s20-window-")
        self.addCleanup(temp.cleanup)
        root = pathlib.Path(temp.name)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        for name, body in WINDOW_FAKE_COMMANDS.items():
            (bin_dir / name).write_text(body)
            (bin_dir / name).chmod(0o755)
        host = root / "AEGIS.app" / "Contents" / "MacOS" / "aegis-ne-host"
        host.parent.mkdir(parents=True)
        host.write_text(WINDOW_FAKE_HOST)
        host.chmod(0o755)
        (root / "fake_tcpdump.py").write_text(WINDOW_FAKE_TCPDUMP)
        (root / "fake_sudo_parent.py").write_text(WINDOW_FAKE_SUDO_PARENT)
        pids = root / "fake.pids"
        pids.write_text("")
        self.addCleanup(self.kill_fakes, pids)
        (root / "home" / ".aegis-local" / "locks").mkdir(parents=True)
        handoff = root / "handoff.json"
        handoff.write_text(json.dumps({"relay": f"{RELAY_IP}:443", "echo_tcp": f"{RELAY_IP}:7",
                                       "echo_udp": f"{RELAY_IP}:7", "whoami": f"http://{RELAY_IP}/ip",
                                       **(handoff_extra or {})}))
        state = root / "state"
        state.write_text("Disconnected\n")
        calls = root / "calls.log"
        calls.write_text("")
        out = root / "out"
        env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(root / "home"), "APP": str(root / "AEGIS.app"),
               "HANDOFF": str(handoff), "OUT": str(out), "ROLLBACK_S": "25", "STATE": str(state),
               "CALLS": str(calls), "FAKE_TCPDUMP": str(root / "fake_tcpdump.py"), "RELAY_IP": RELAY_IP,
               "FAKE_SUDO_PARENT": str(root / "fake_sudo_parent.py"), "FAKE_PIDS": str(pids),
               "LEAK_CAPTURE": "1", "PROBE_PY": str(bin_dir / "probe_py"), "SYSTEM_PY": SYSTEM_PY,
               **env_extra}
        self.addCleanup(self.cancel_rollback, out)
        if kill_when_connected:
            window = subprocess.Popen(["/bin/bash", str(REAL_RELAY_WINDOW)], env=env,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.monotonic() + 30
            while state.read_text().strip() != "Connected" and time.monotonic() < deadline:
                time.sleep(0.05)
            window.kill()  # SIGKILL: no EXIT trap runs
            window.wait(timeout=10)
            result = subprocess.CompletedProcess(window.args, window.returncode, "", "")
        else:
            result = subprocess.run(["/bin/bash", str(REAL_RELAY_WINDOW)], capture_output=True, text=True,
                                    env=env, timeout=90)
        rows = {}
        if (out / "results.tsv").exists():
            for line in (out / "results.tsv").read_text().splitlines():
                name, verdict, detail, status, _start, _end = line.split("\t")  # v31: UTC start, end
                rows[name] = (verdict, detail, status)
        return result, rows, calls.read_text().splitlines(), out, root

    @staticmethod
    def fake_pids(root):
        return {role: int(pid) for role, pid in
                (line.split() for line in (root / "fake.pids").read_text().splitlines())}

    @staticmethod
    def kill_fakes(pids):
        # The fake sudo, monitor and tcpdump are ours; end any left running.
        try:
            lines = pids.read_text().splitlines()
        except OSError:
            return
        for line in lines:
            try:
                os.kill(int(line.split()[1]), 9)
            except (OSError, ValueError, IndexError):
                pass

    def cancel_rollback(self, out):
        # A failing run leaves its fake-only rollback armed: end it by pid.
        try:
            log = (out / "rollback.log").read_text()
        except OSError:
            return
        if "rollback_cancelled" in log or "rollback_done" in log:
            return
        for line in log.splitlines():
            if line.startswith("armed pid="):
                try:
                    os.kill(int(line.split()[1].split("=")[1]), 9)
                except (OSError, ValueError):
                    pass

    def test_sudo_without_n_refuses_before_connect(self):
        result, rows, calls, out, root = self.run_window(FAKE_SUDO_OK="0")
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("refused: LEAK_CAPTURE=1 needs sudo -n for /usr/sbin/tcpdump", result.stdout)
        self.assertEqual(calls, ["sudo -n -l /usr/sbin/tcpdump"])
        self.assertFalse((out / "physical.pcap").exists())
        self.assertFalse((out / "rollback.log").exists())
        self.assertFalse((root / "home" / ".aegis-local" / "locks" / "timing-self").exists())
        self.assertEqual(rows, {})

    def test_a_capture_without_an_identifiable_tcpdump_pid_refuses_before_connect(self):
        result, rows, calls, out, root = self.run_window(FAKE_HIDE_ARGS="1")
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("refused: tcpdump on en0 did not start", result.stdout)
        self.assertTrue((out / "physical.pcap").stat().st_size > 0)
        self.assertFalse(any(c.startswith("host ") for c in calls), calls)
        self.assertFalse((out / "rollback.log").exists())
        self.assertIn("tcpdump stopped", calls)

    def test_sudo_that_allows_tcpdump_but_not_kill_refuses_before_capture(self):
        result, rows, calls, out, root = self.run_window(FAKE_SUDO_KILL_LIST="0")
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("refused: LEAK_CAPTURE=1 needs sudo -n for /bin/kill", result.stdout)
        self.assertEqual(calls, ["sudo -n -l /usr/sbin/tcpdump", "sudo -n -l /bin/kill"])
        self.assertFalse((out / "physical.pcap").exists())
        self.assertFalse((out / "rollback.log").exists())
        self.assertEqual(rows, {})

    def test_a_tcpdump_that_does_not_start_refuses_before_connect(self):
        result, rows, calls, out, root = self.run_window(FAKE_TCPDUMP_FAIL="1")
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("refused: tcpdump on en0 did not start: tcpdump: en0: You don't have permission", result.stdout)
        self.assertFalse(any(c.startswith("host ") for c in calls), calls)
        self.assertFalse((out / "rollback.log").exists())
        self.assertFalse((root / "home" / ".aegis-local" / "locks" / "timing-self").exists())

    def test_the_filter_preflight_and_its_counters_after_the_window_are_recorded(self):
        result, rows, calls, out, root = self.run_window()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["filter_preflight"][0], "pass")
        self.assertTrue(rows["filter_preflight"][1].startswith("exit=0 required=1 filter_result=ok exit_code=0 "))
        self.assertEqual(rows["filter_preflight"][2], "Disconnected")
        self.assertEqual(rows["filter_counters_after"][0], "info")
        self.assertIn("mode=open", rows["filter_counters_after"][1])
        for name in ("before", "after"):
            kept = (out / f"filter-status-{name}.txt").read_text()
            self.assertIn('"verb":"filter-status"', kept)
        # The filter rows never name an address.
        self.assertNotIn(RELAY_IP, rows["filter_preflight"][1] + rows["filter_counters_after"][1])

    def test_a_leak_window_without_an_attached_filter_refuses_before_capture_or_connect(self):
        for code, name in ((33, "not_attached"), (31, "disabled"), (30, "not_configured"), (69, "provider_unavailable")):
            with self.subTest(code=code):
                result, rows, calls, out, root = self.run_window(
                    FAKE_FILTER_EXIT=str(code), FAKE_FILTER_LINE=f"filter_result={name} exit_code={code}")
                self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
                self.assertIn("refused: FILTER_REQUIRED=1 needs the leak-guard filter", result.stdout)
                self.assertIn(f"host --filter-status exit {code}", result.stdout)
                self.assertEqual(calls, [])
                self.assertEqual(rows, {})
                self.assertFalse((out / "physical.pcap").exists())
                self.assertFalse((root / "home" / ".aegis-local" / "locks" / "timing-self").exists())
        # An explicit FILTER_REQUIRED=0 runs the window and records the failing row.
        result, rows, calls, out, root = self.run_window(
            FILTER_REQUIRED="0", FAKE_FILTER_EXIT="33", FAKE_FILTER_LINE="filter_result=not_attached exit_code=33")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["filter_preflight"][:2],
                         ("fail", "exit=33 required=0 filter_result=not_attached exit_code=33"))
        self.assertEqual(rows["connected"][0], "1")

    def test_a_clean_window_records_its_interval_and_passes_the_leak_proof(self):
        result, rows, calls, out, root = self.run_window()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(all(c.startswith("sudo -n ") for c in calls if c.startswith("sudo")), calls)
        self.assertEqual(calls[:2], ["sudo -n -l /usr/sbin/tcpdump", "sudo -n -l /bin/kill"])
        # Headers only, not promiscuous, and bounded by itself: ROLLBACK_S 25 + 60.
        start = calls.index(f"sudo -n /usr/sbin/tcpdump -i en0 -p -s 160 -B 4096 -G 85 -W 1 -U -w {out}/physical.pcap")
        connect = next(i for i, c in enumerate(calls) if c.startswith("host --connect"))
        stop = next(i for i, c in enumerate(calls) if c.startswith("scutil --nc stop"))
        stopped = calls.index("tcpdump stopped")
        self.assertLess(start, connect)
        self.assertLess(stop, stopped)
        self.assertEqual(rows["capture_started"][0], "pass")
        tcpdump = self.fake_pids(root)["tcpdump"]
        self.assertIn(f"tcpdump={tcpdump} ", rows["capture_started"][1])
        self.assertIn(f"sudo -n /bin/kill -INT {tcpdump}", calls)
        self.assertEqual(rows["capture_stopped"][0], "pass")
        connected_at = float(rows["leak_window_connected_at"][0])
        disconnect_at = float(rows["leak_window_disconnect_at"][0])
        self.assertEqual(rows["leak_window_disconnect_at"][1], "capture_alive=1")
        self.assertGreater(disconnect_at - connected_at, 4)
        self.assertEqual(rows["disconnect_verified"][0], "pass")
        self.assertEqual(rows["leak_proof"][0], "pass", rows["leak_proof"])
        self.assertIn("kernel_drops=0", rows["leak_proof"][1])
        report = json.loads((out / "leak-review.json").read_text())
        self.assertTrue(report["pass"])
        self.assertEqual(report["connected_interval"]["connected_at"], connected_at)
        self.assertEqual(report["connected_interval"]["disconnect_at"], disconnect_at)
        self.assertGreater(report["relay_packets"], 20)
        self.assertEqual((report["relay_ip"], report["relay_port"], report["relay_protocols"]),
                         (RELAY_IP, 443, ["tcp", "udp"]))
        self.assertEqual(report["local_mac"], "02:00:00:00:00:01")
        self.assertIn("capture_stopped=1 ", rows["leak_proof"][1])
        digest = hashlib.sha256((out / "physical.pcap").read_bytes()).hexdigest()
        self.assertEqual(rows["leak_capture_sha256"][0], digest)
        self.assertFalse((root / "home" / ".aegis-local" / "locks" / "timing-self").exists())

    def test_a_clean_window_runs_the_timed_probes_and_ipv6_rows_without_naming_physical_addresses(self):
        result, rows, calls, out, root = self.run_window()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        probes = [c for c in calls if c.startswith("probe ")]
        # The timed half-close probe is the first user flow; warm ones follow the bursts.
        self.assertEqual(probes[:2], ["probe tcp hc", "probe tcp nohc"])
        self.assertEqual(probes[2:4], ["probe tcp hc", "probe tcp nohc"])
        self.assertEqual(rows["tcp_echo_v4"][:2], ("pass", "4/7/eof"))
        self.assertEqual(rows["tcp_echo_v4_nohc"][:2], ("pass", "4/7/full"))
        self.assertEqual(rows["tcp_echo_v4_nc"][:2], ("pass", "ping"))
        self.assertEqual(rows["tcp_echo_v4_warm"][:2], ("pass", "4/7/eof"))
        self.assertEqual(rows["tcp_echo_v4_warm_nohc"][:2], ("pass", "4/7/full"))
        names = list(rows)
        self.assertLess(names.index("flow_burst_90"), names.index("tcp_echo_v4_warm"))
        self.assertEqual(rows["physical_v6_baseline"][:2], ("info", "default=en0 global=1"))
        for name in ("utun_addr_v6", "default_route_v6", "route_v6_anchor", "source_v6_tunnel", "system_resolver_v6",
                     "dns_udp6_anchor", "dns_tcp6_anchor", "dns_aaaa_via_relay", "dns_aaaa_v6_anchor"):
            self.assertEqual(rows[name][0], "pass", (name, rows[name]))
            self.assertEqual(rows[name][2], "Connected", (name, rows[name]))
        self.assertEqual(rows["utun_addr_v6"][1], "fd00:ae61::1/120")
        self.assertEqual(rows["utun_routes_v6"][:2], ("info", "default:UGcIg,fd00:ae61::/120:UC other=0"))
        self.assertEqual(rows["scoped_phys_v6_default"][0], "info")
        self.assertEqual(rows["http6_by_name"][0], "info_fail")
        for name, field in (("udp_echo_v6", "echo_udp6"), ("tcp_echo_v6", "echo_tcp6"), ("whoami6_egress", "whoami6")):
            self.assertEqual(rows[name][:2], ("skip", f"no {field}"))
        self.assertEqual(rows["disconnect_v6_route"][:2], ("pass", "en0 baseline=en0"))
        self.assertEqual(rows["disconnect_v6_addr"][:2], ("pass", "count=0"))
        self.assertEqual(rows["no_v6_leak_physical"][0], "pass", rows["no_v6_leak_physical"])
        self.assertTrue(rows["no_v6_leak_physical"][1].startswith("ipv6_leaks=0 capture_alive=1 capture_stopped=1 "))
        names = list(rows)
        self.assertLess(names.index("disconnect_verified"), names.index("disconnect_v6_route"))
        for text in ((out / "results.tsv").read_text(), (out / "window.log").read_text()):
            self.assertNotIn("2001:db8:1:2", text)
        self.assertIn("physical_v6_default=en0 host_global_v6=1", (out / "window.log").read_text())

    def test_an_ipv6_packet_on_the_physical_interface_fails_no_v6_leak_physical(self):
        result, rows, calls, out, root = self.run_window(FAKE_LEAK6="1")
        self.assertEqual(rows["leak_proof"][0], "fail", rows)
        self.assertEqual(rows["no_v6_leak_physical"][0], "fail", rows)
        self.assertTrue(rows["no_v6_leak_physical"][1].startswith("ipv6_leaks=1 "), rows["no_v6_leak_physical"])
        self.assertNotIn("2001:db8:1:2", (out / "results.tsv").read_text())
        # An IPv4 leak alone leaves the IPv6 row passing.
        result, rows, calls, out, root = self.run_window(FAKE_LEAK="1")
        self.assertEqual(rows["leak_proof"][0], "fail", rows)
        self.assertEqual(rows["no_v6_leak_physical"][0], "pass", rows)

    def test_without_leak_capture_no_v6_leak_physical_is_unavailable_and_no_sudo_runs(self):
        result, rows, calls, out, root = self.run_window(LEAK_CAPTURE="0")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse([c for c in calls if c.startswith("sudo")], calls)
        self.assertEqual(rows["no_v6_leak_physical"][:2], ("unavailable", "LEAK_CAPTURE=0: no physical capture"))
        self.assertEqual(rows["disconnect_verified"][0], "pass")
        self.assertEqual(rows["disconnect_v6_addr"][:2], ("pass", "count=0"))

    def test_an_ipv6_default_on_another_interface_is_never_a_v6_leak_pass_and_its_address_stays_unnamed(self):
        # IPv4 default en0 (captured), IPv6 default en1 (not captured): the
        # capture cannot see an IPv6 leak, and en1's address is the Mac's own.
        en1 = "2001:db8:7:8::60"
        result, rows, calls, out, root = self.run_window(
            FAKE_PHYS_DEF6="en1", FAKE_EN1_V6=en1, FAKE_WHOAMI6_BODY=f"ip={en1}", FAKE_SRC6=en1,
            handoff_extra={"whoami6": "http://[2001:db8:ffff::7]:8080/", "relay_ipv6": "2001:db8:ffff::7"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"sudo -n /usr/sbin/tcpdump -i en0 -p -s 160 -B 4096 -G 85 -W 1 -U -w {out}/physical.pcap", calls)
        self.assertEqual(rows["physical_v6_baseline"][:2], ("info", "default=en1 global=2"))
        self.assertEqual(rows["no_v6_leak_physical"][:2],
                         ("unavailable", "v6_default_interface_differs capture=en0 v6_default=en1"))
        self.assertEqual(rows["leak_proof"][0], "pass", rows["leak_proof"])
        self.assertEqual(rows["whoami6_egress"][:2], ("fail", "physical_prefix_seen"))
        self.assertEqual(rows["source_v6_tunnel"][:2], ("fail", "physical_address"))
        self.assertEqual(rows["disconnect_v6_route"][:2], ("pass", "en1 baseline=en1"))
        log = (out / "window.log").read_text()
        self.assertIn("physical_v6_default=en1 host_global_v6=2", log)
        for text in ((out / "results.tsv").read_text(), log):
            self.assertNotIn("2001:db8:7:8", text)
            self.assertNotIn("2001:db8:1:2", text)
        # The same IPv6 default as the capture keeps the verdict from the capture.
        result, rows, calls, out, root = self.run_window(FAKE_EN1_V6=en1)
        self.assertEqual(rows["no_v6_leak_physical"][0], "pass", rows["no_v6_leak_physical"])
        self.assertEqual(rows["physical_v6_baseline"][:2], ("info", "default=en0 global=2"))

    def test_test_flows_to_the_relay_host_around_the_tunnel_fail_the_leak_proof(self):
        result, rows, calls, out, root = self.run_window(FAKE_BYPASS="1")
        self.assertEqual(rows["leak_proof"][0], "fail", rows)
        self.assertIn("leaks=3 ", rows["leak_proof"][1])
        report = json.loads((out / "leak-review.json").read_text())
        self.assertEqual(sorted((l["proto"], l["dport"]) for l in report["leaks"]),
                         [("tcp", 7), ("tcp", 8080), ("udp", 7)])
        self.assertTrue(all(l["dst"] == RELAY_IP and l["relay_host"] for l in report["leaks"]), report["leaks"])
        self.assertGreater(report["relay_packets"], 20)

    def test_a_parent_sudo_that_ignores_signals_is_stopped_through_the_real_tcpdump_pid(self):
        result, rows, calls, out, root = self.run_window(FAKE_SUDO_MODE="parent")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        pids = self.fake_pids(root)
        self.assertEqual(set(pids), {"sudo", "monitor", "tcpdump"})
        self.assertIn(f"tcpdump={pids['tcpdump']} ", rows["capture_started"][1])
        self.assertEqual(rows["capture_stopped"], (f"pass", f"pid={pids['sudo']} tcpdump={pids['tcpdump']}",
                                                   "Disconnected"))
        self.assertIn(f"sudo -n /bin/kill -INT {pids['tcpdump']}", calls)
        self.assertEqual(rows["leak_proof"][0], "pass", rows["leak_proof"])

    def test_a_refused_kill_at_stop_fails_the_leak_proof_and_names_the_tcpdump(self):
        result, rows, calls, out, root = self.run_window(FAKE_SUDO_MODE="parent", FAKE_KILL_OK="0",
                                                         FAKE_SIGINFO_STATS="1")
        pids = self.fake_pids(root)
        self.assertEqual(rows["capture_stopped"][0], "fail", rows)
        self.assertEqual(rows["capture_stopped"][1], f"pid={pids['sudo']} tcpdump={pids['tcpdump']} still running")
        self.assertIn(f"exits by itself at the first packet after 85s; stop it now with: sudo kill -INT {pids['tcpdump']}",
                      result.stdout)
        self.assertEqual(rows["leak_proof"][0], "fail", rows)
        self.assertIn("capture_stopped=0 kernel_drops=0", rows["leak_proof"][1])

    def test_the_detached_rollback_stops_the_capture_when_the_window_is_killed(self):
        result, rows, calls, out, root = self.run_window(kill_when_connected=True, FAKE_SUDO_MODE="parent",
                                                         ROLLBACK_S="6")
        self.assertEqual(result.returncode, -9)
        log = out / "rollback.log"
        deadline = time.monotonic() + 30
        while "rollback_done" not in (log.read_text() if log.exists() else "") and time.monotonic() < deadline:
            time.sleep(0.2)
        pids = self.fake_pids(root)
        self.assertIn(f"capture_stop_requested pid={pids['tcpdump']} rc=0", log.read_text())
        calls_log = root / "calls.log"
        while "tcpdump stopped" not in calls_log.read_text() and time.monotonic() < deadline:
            time.sleep(0.2)
        self.assertIn("tcpdump stopped", calls_log.read_text().splitlines())
        self.assertIn(f"sudo -n /bin/kill -INT {pids['tcpdump']}", calls_log.read_text().splitlines())
        self.assertIn("-G 66 -W 1", calls_log.read_text())

    def test_the_detached_rollback_leaves_an_ended_capture_alone(self):
        result, rows, calls, out, root = self.run_window(kill_when_connected=True, FAKE_SUDO_MODE="parent",
                                                         ROLLBACK_S="6", FAKE_DIE_AFTER="0.5")
        log = out / "rollback.log"
        deadline = time.monotonic() + 30
        while "rollback_done" not in (log.read_text() if log.exists() else "") and time.monotonic() < deadline:
            time.sleep(0.2)
        pids = self.fake_pids(root)
        self.assertIn(f"capture_already_stopped pid={pids['tcpdump']}", log.read_text())
        self.assertNotIn("sudo -n /bin/kill", (root / "calls.log").read_text())

    def test_a_leak_a_kernel_drop_or_a_capture_that_ends_early_fails_the_leak_proof(self):
        result, rows, calls, out, root = self.run_window(FAKE_LEAK="1")
        self.assertEqual(rows["leak_proof"][0], "fail", rows)
        self.assertIn("leaks=1 ", rows["leak_proof"][1])
        report = json.loads((out / "leak-review.json").read_text())
        self.assertEqual([l["dst"] for l in report["leaks"]], ["198.51.100.9"])
        result, rows, calls, out, root = self.run_window(FAKE_DROPS="3")
        self.assertEqual(rows["leak_proof"][0], "fail", rows)
        self.assertIn("leak_review pass=true ", rows["leak_proof"][1])
        self.assertIn("kernel_drops=3", rows["leak_proof"][1])
        result, rows, calls, out, root = self.run_window(FAKE_DIE_AFTER="2")
        self.assertEqual(rows["leak_window_disconnect_at"][1], "capture_alive=0")
        self.assertEqual(rows["leak_proof"][0], "fail", rows)
        self.assertIn("leak_review pass=true ", rows["leak_proof"][1])
        # A capture that already ended is never signalled through sudo by pid.
        self.assertFalse([c for c in calls if c.startswith("sudo -n /bin/kill")], calls)

    # ------------------------------------------- S20d every active interface

    @staticmethod
    def tcpdump_pids(root):
        return [int(l.split()[1]) for l in (root / "fake.pids").read_text().splitlines() if l.startswith("tcpdump ")]

    def test_every_active_interface_is_captured_and_reviewed_with_its_own_mac(self):
        # en5 is up but carries no relay traffic, as Wi-Fi did beside en7 in v26.
        result, rows, calls, out, root = self.run_window(FAKE_EN5="active", FAKE_NO_RELAY_IF="en5",
                                                         FAKE_SUDO_MODE="parent")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        first = calls.index(f"sudo -n /usr/sbin/tcpdump -i en0 -p -s 160 -B 4096 -G 85 -W 1 -U -w {out}/physical.pcap")
        # S20e: the other interface under the root alarm, 30 s past its -G bound.
        second = calls.index(f"sudo -n /usr/bin/perl -e {owner_alarm_code()} 115 /usr/sbin/tcpdump -i en5 -p -s 160 "
                             f"-B 4096 -G 85 -W 1 -U -w {out}/physical-en5.pcap")
        self.assertLess(calls.index("sudo -n -l /usr/bin/perl"), first)
        connect = next(i for i, c in enumerate(calls) if c.startswith("host --connect"))
        self.assertLess(first, second)
        self.assertLess(second, connect)
        self.assertEqual(len([c for c in calls if "/usr/sbin/tcpdump -i " in c]), 2, calls)
        tcpdumps = self.tcpdump_pids(root)
        self.assertEqual(len(tcpdumps), 2)
        for pid in tcpdumps:
            self.assertIn(f"sudo -n /bin/kill -INT {pid}", calls)
        names = list(rows)
        self.assertEqual(rows["leak_capture_ifaces"][:2], ("info", "en0,en5"))
        self.assertLess(names.index("capture_started_en5"), names.index("leak_capture_ifaces"))
        self.assertLess(names.index("leak_capture_ifaces"), names.index("connected"))
        self.assertEqual(rows["capture_started_en5"][0], "pass")
        self.assertIn(f"tcpdump={tcpdumps[1]} if=en5 file=physical-en5.pcap bound=85s alarm=115s",
                      rows["capture_started_en5"][1])
        self.assertEqual(rows["capture_stopped_en5"][0], "pass")
        # The rows of S20 read exactly as before.
        self.assertEqual(rows["leak_proof"][0], "pass", rows["leak_proof"])
        self.assertTrue(rows["leak_proof"][1].startswith("leak_review pass=true leaks=0 "), rows["leak_proof"])
        self.assertTrue(rows["leak_proof"][1].endswith(" foreign=0 capture_alive=1 capture_stopped=1 kernel_drops=0"),
                        rows["leak_proof"])
        self.assertEqual(rows["no_v6_leak_physical"][0], "pass")
        phys = json.loads((out / "leak-review.json").read_text())
        self.assertEqual((phys["local_mac"], phys["mac_sent_relay_required"], phys["mac_sent_pass"]),
                         ("02:00:00:00:00:01", True, True))
        report = json.loads((out / "leak-review-en5.json").read_text())
        self.assertEqual((report["local_mac"], report["relay_packets"], report["pass"]), ("02:00:00:00:00:05", 0, False))
        self.assertEqual((report["mac_sent_relay_required"], report["mac_sent_leaks"], report["mac_sent_pass"]),
                         (False, 0, True))
        self.assertTrue(rows["leak_review_en5"][1].startswith("if=en5 leak_review pass=false leaks=0 relay=0 "),
                        rows["leak_review_en5"])
        self.assertTrue(rows["leak_review_en5"][1].endswith(
            " mac_sent_leaks=0 mac_sent_pass=true capture_alive=1 capture_stopped=1 kernel_drops=0"), rows["leak_review_en5"])
        self.assertEqual(rows["leak_capture_sha256_en5"][0],
                         hashlib.sha256((out / "physical-en5.pcap").read_bytes()).hexdigest())
        # pass's rule needs a relay packet on every capture; en5 has none.
        self.assertEqual(rows["leak_proof_all_ifaces"][0], "fail", rows["leak_proof_all_ifaces"])
        self.assertIn(" en5:pass=false,relay=0,alive=1,stopped=1,drops=0 ", rows["leak_proof_all_ifaces"][1])
        self.assertEqual(rows["no_mac_sent_leak_physical"][:2], (
            "pass", "ifaces=en0,en5 en0:mac_sent_leaks=0,mac_sent_pass=true,alive=1,stopped=1,drops=0 "
                    "en5:mac_sent_leaks=0,mac_sent_pass=true,alive=1,stopped=1,drops=0 uncaptured=none"))
        self.assertLess(names.index("no_v6_leak_physical"), names.index("no_mac_sent_leak_physical"))
        for text in ((out / "results.tsv").read_text(), (out / "window.log").read_text()):
            for address in ("10.0.5.50", "192.168.1.50", "2001:db8:1:2", "02:00:00:00:00:05", "02:00:00:00:00:01"):
                self.assertNotIn(address, text)
        # Both carrying relay traffic and clean: pass's rule holds on both.
        result, rows, calls, out, root = self.run_window(FAKE_EN5="active")
        self.assertEqual(rows["leak_proof_all_ifaces"][0], "pass", rows["leak_proof_all_ifaces"])
        self.assertTrue(rows["leak_proof_all_ifaces"][1].startswith("ifaces=en0,en5 en0:pass=true,relay="))
        self.assertEqual(rows["no_mac_sent_leak_physical"][0], "pass", rows["no_mac_sent_leak_physical"])

    def test_an_interface_whose_capture_does_not_start_refuses_the_window(self):
        result, rows, calls, out, root = self.run_window(FAKE_EN5="active", FAKE_TCPDUMP_FAIL_IF="en5")
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("refused: tcpdump on en5 did not start: tcpdump: en5: You don't have permission", result.stdout)
        self.assertFalse(any(c.startswith("host ") for c in calls), calls)
        self.assertFalse((out / "rollback.log").exists())
        self.assertFalse((root / "home" / ".aegis-local" / "locks" / "timing-self").exists())
        self.assertIn("tcpdump stopped if=en0", calls)
        self.assertEqual(rows["capture_started"][0], "pass")
        self.assertEqual(rows["capture_stopped"][0], "pass")
        self.assertNotIn("leak_capture_ifaces", rows)
        self.assertNotIn("connected", rows)

    def test_a_mac_sent_leak_on_another_interface_fails_only_the_all_interface_rows(self):
        result, rows, calls, out, root = self.run_window(FAKE_EN5="active", FAKE_LEAK="1", FAKE_LEAK_IF="en5",
                                                         FAKE_LEAK_SRC="10.0.5.50")
        self.assertEqual(rows["leak_proof"][0], "pass", rows["leak_proof"])
        self.assertEqual(rows["no_v6_leak_physical"][0], "pass")
        self.assertEqual(rows["leak_proof_all_ifaces"][0], "fail")
        self.assertIn(" en5:pass=false,", rows["leak_proof_all_ifaces"][1])
        self.assertEqual(rows["no_mac_sent_leak_physical"][0], "fail", rows["no_mac_sent_leak_physical"])
        self.assertIn(" en5:mac_sent_leaks=1,mac_sent_pass=false,", rows["no_mac_sent_leak_physical"][1])
        self.assertTrue(rows["no_mac_sent_leak_physical"][1].endswith(" reason=en5:mac_sent_leaks=1"))
        report = json.loads((out / "leak-review-en5.json").read_text())
        self.assertEqual(report["mac_sent_classes"], {"tcp_syn": 1})
        self.assertNotIn("10.0.5.50", (out / "results.tsv").read_text())

    def test_arrivals_fail_leak_proof_but_never_the_mac_sent_row(self):
        result, rows, calls, out, root = self.run_window(FAKE_INBOUND="1")
        self.assertEqual(rows["leak_proof"][0], "fail", rows["leak_proof"])
        self.assertIn("leaks=1 ", rows["leak_proof"][1])
        self.assertEqual(rows["leak_capture_ifaces"][:2], ("info", "en0"))
        self.assertEqual(rows["leak_proof_all_ifaces"][0], "fail")
        self.assertEqual(rows["no_mac_sent_leak_physical"][:2],
                         ("pass", "ifaces=en0 en0:mac_sent_leaks=0,mac_sent_pass=true,alive=1,stopped=1,drops=0 "
                                  "uncaptured=none"))
        report = json.loads((out / "leak-review.json").read_text())
        self.assertEqual((report["leak_classes"], report["mac_sent_leaks"]), ({"host": 1}, 0))

    def test_a_port_whose_link_comes_up_during_the_window_is_captured_from_the_start(self):
        # S20e: en5 has no link before connect, so S20d left it uncaptured. It
        # is an Ethernet port, so it is captured from the start; what the Mac
        # sends once its link is up counts, by the address it holds only then
        # (read right before the disconnect).
        result, rows, calls, out, root = self.run_window(FAKE_EN5="late", FAKE_LEAK="1", FAKE_LEAK_IF="en5",
                                                         FAKE_LEAK_SRC="10.0.5.50")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["leak_capture_ifaces"][:2], ("info", "en0,en5"))
        self.assertEqual(len(self.tcpdump_pids(root)), 2)
        self.assertEqual(rows["leak_proof"][0], "pass", rows["leak_proof"])
        self.assertEqual(rows["no_mac_sent_leak_physical"][0], "fail", rows["no_mac_sent_leak_physical"])
        self.assertTrue(rows["no_mac_sent_leak_physical"][1].endswith(" uncaptured=none reason=en5:mac_sent_leaks=1"),
                        rows["no_mac_sent_leak_physical"])
        report = json.loads((out / "leak-review-en5.json").read_text())
        self.assertEqual((report["leak_classes"], report["mac_sent_classes"]), ({"foreign": 1}, {"tcp_syn": 1}))
        self.assertNotIn("10.0.5.50", (out / "results.tsv").read_text() + (out / "window.log").read_text())
        result, rows, calls, out, root = self.run_window(FAKE_EN5="late")
        self.assertEqual(rows["no_mac_sent_leak_physical"][0], "pass", rows["no_mac_sent_leak_physical"])
        self.assertTrue(rows["no_mac_sent_leak_physical"][1].endswith(" uncaptured=none"))

    def test_an_interface_that_appears_during_the_window_is_uncaptured_and_fails(self):
        # An adapter plugged in mid-window was not there to be captured.
        result, rows, calls, out, root = self.run_window(FAKE_EN5="appear")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["leak_capture_ifaces"][:2], ("info", "en0"))
        self.assertEqual(len(self.tcpdump_pids(root)), 1)
        self.assertEqual(rows["leak_proof"][0], "pass", rows["leak_proof"])
        self.assertEqual(rows["leak_proof_all_ifaces"][0], "fail")
        self.assertTrue(rows["leak_proof_all_ifaces"][1].endswith(" uncaptured=en5"))
        self.assertEqual(rows["no_mac_sent_leak_physical"][0], "fail")
        self.assertTrue(rows["no_mac_sent_leak_physical"][1].endswith(
            " uncaptured=en5 reason=uncaptured=en5"), rows["no_mac_sent_leak_physical"])

    def test_a_drop_a_missing_mac_or_an_early_end_on_another_interface_fails_the_mac_sent_row(self):
        for extra, reason in (({"FAKE_DROPS": "2", "FAKE_DROPS_IF": "en5"}, "en5:kernel_drops=2"),
                              ({"FAKE_EN5_NO_ETHER": "1"}, "en5:no_local_mac"),
                              ({"FAKE_DIE_AFTER": "2", "FAKE_DIE_IF": "en5"}, "en5:capture_alive=0")):
            with self.subTest(reason=reason):
                result, rows, calls, out, root = self.run_window(FAKE_EN5="active", **extra)
                self.assertEqual(rows["leak_proof"][0], "pass", rows["leak_proof"])
                self.assertIn("kernel_drops=0", rows["leak_proof"][1])
                self.assertEqual(rows["no_mac_sent_leak_physical"][0], "fail", rows["no_mac_sent_leak_physical"])
                self.assertTrue(rows["no_mac_sent_leak_physical"][1].endswith(f" reason={reason}"),
                                rows["no_mac_sent_leak_physical"])
                self.assertEqual(rows["leak_proof_all_ifaces"][0], "fail" if "NO_ETHER" not in str(extra) else "pass")

    def test_every_port_the_mac_could_send_on_is_captured_whatever_its_address(self):
        # S20e: an active or Ethernet port counts without an address of its
        # own (en6 link-local only, llw0 and en8 without a link), and bridge0,
        # ap1 and anpi0 are no longer skipped by name. Down ports, tunnels,
        # loopback, a VM's host-side port and its VM-only bridge are.
        result, rows, calls, out, root = self.run_window(FAKE_IGNORED_IFS="1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        started = [c.split(" -i ")[1].split()[0] for c in calls if "/usr/sbin/tcpdump -i " in c]
        captured = ["en0", "awdl0", "llw0", "bridge0", "ap1", "anpi0", "en6", "en8"]
        self.assertEqual(started, captured)
        alarm = f"sudo -n /usr/bin/perl -e {owner_alarm_code()} 115 "
        for dev in captured[1:]:
            self.assertIn(f"{alarm}/usr/sbin/tcpdump -i {dev} -p -s 160 -B 4096 -G 85 -W 1 -U -w {out}/physical-{dev}.pcap",
                          calls)
            self.assertEqual(rows[f"capture_started_{dev}"][0], "pass")
        self.assertEqual(rows["leak_capture_ifaces"][:2], ("info", ",".join(captured)))
        self.assertEqual(rows["no_mac_sent_leak_physical"][0], "pass", rows["no_mac_sent_leak_physical"])
        self.assertTrue(rows["no_mac_sent_leak_physical"][1].startswith(f"ifaces={','.join(captured)} "))
        self.assertTrue(rows["no_mac_sent_leak_physical"][1].endswith(" uncaptured=none"))
        self.assertEqual(json.loads((out / "leak-review-awdl0.json").read_text())["local_mac"], "02:00:00:00:00:0a")
        self.assertEqual(json.loads((out / "leak-review-en6.json").read_text())["local_mac"], "02:00:00:00:00:06")

    def test_a_bridge_member_without_an_address_is_captured_and_the_bridge_identity_counts_on_it(self):
        # S20e: a Thunderbolt Bridge. The member en1 has no address; the Mac's
        # mDNS leaves through it from bridge0's address. Both, and the member
        # without a link, are captured, and every review knows every
        # interface's MACs and addresses for the Mac-sent criterion.
        result, rows, calls, out, root = self.run_window(
            FAKE_TB_BRIDGE="1", FAKE_LEAK="1", FAKE_LEAK_IF="en1", FAKE_LEAK_SRC="169.254.7.7",
            FAKE_LEAK_DST="224.0.0.251", FAKE_LEAK_DPORT="5353", FAKE_LEAK_PROTO="17")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["leak_capture_ifaces"][:2], ("info", "en0,bridge0,en1,en2"))
        self.assertEqual(rows["leak_proof"][0], "pass", rows["leak_proof"])
        report = json.loads((out / "leak-review-en1.json").read_text())
        # pass excludes mDNS; the Mac-sent criterion counts it, by bridge0's address.
        self.assertEqual((report["pass"], report["leak_count"], report["local_mac"]), (True, 0, "02:00:00:00:00:0c"))
        self.assertEqual((report["mac_sent_leaks"], report["mac_sent_classes"]), (1, {"mdns": 1}))
        self.assertEqual(report["mac_sent_identity"], {"macs": 4, "addrs": 4})
        self.assertEqual(rows["no_mac_sent_leak_physical"][0], "fail", rows["no_mac_sent_leak_physical"])
        self.assertTrue(rows["no_mac_sent_leak_physical"][1].endswith(" uncaptured=none reason=en1:mac_sent_leaks=1"),
                        rows["no_mac_sent_leak_physical"])
        for text in ((out / "results.tsv").read_text(), (out / "window.log").read_text()):
            for address in ("169.254.7.7", "02:00:00:00:00:0b", "02:00:00:00:00:0c", "02:00:00:00:00:0d"):
                self.assertNotIn(address, text)
        result, rows, calls, out, root = self.run_window(FAKE_TB_BRIDGE="1")
        self.assertEqual(rows["no_mac_sent_leak_physical"][0], "pass", rows["no_mac_sent_leak_physical"])
        self.assertTrue(rows["no_mac_sent_leak_physical"][1].startswith("ifaces=en0,bridge0,en1,en2 "))

    def test_frames_sent_under_the_mac_or_address_from_before_a_rejoin_count_for_the_mac_sent_row(self):
        # S20e: en0 rejoins with a new private MAC and a new lease, after the
        # window or right at the connect. The strict review reads them after
        # the window, as before; the Mac-sent criterion also knows the ones
        # from before connect (for connect, only that reading has them).
        for rotate in ("1", "connect"):
            for extra in ({"FAKE_LEAK_SRC": "192.168.1.50"},
                          {"FAKE_LEAK_SRC": "198.51.100.77", "FAKE_LEAK_ETH_SRC": "02:00:00:00:00:01"}):
                with self.subTest(rotate=rotate, **extra):
                    result, rows, calls, out, root = self.run_window(FAKE_EN0_ROTATE=rotate, FAKE_LEAK="1", **extra)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    report = json.loads((out / "leak-review.json").read_text())
                    self.assertEqual((report["local_mac"], report["leak_count"]), ("02:00:00:00:00:21", 1))
                    self.assertEqual((report["mac_sent_leaks"], report["mac_sent_classes"]), (1, {"tcp_syn": 1}))
                    self.assertEqual(rows["leak_proof"][0], "fail", rows["leak_proof"])
                    self.assertTrue(rows["leak_proof"][1].startswith("leak_review pass=false leaks=1 "),
                                    rows["leak_proof"])
                    self.assertNotIn("mac_sent", rows["leak_proof"][1])
                    self.assertEqual(rows["no_mac_sent_leak_physical"][0], "fail", rows["no_mac_sent_leak_physical"])
                    self.assertTrue(rows["no_mac_sent_leak_physical"][1].endswith(
                        " uncaptured=none reason=en0:mac_sent_leaks=1"), rows["no_mac_sent_leak_physical"])
                    for text in ((out / "results.tsv").read_text(), (out / "window.log").read_text()):
                        for address in ("02:00:00:00:00:21", "02:00:00:00:00:01", "192.168.1.77", "192.168.1.50"):
                            self.assertNotIn(address, text)

    def test_leak_capture_refuses_without_sudo_for_the_capture_alarm(self):
        # S20e: every other interface's capture needs the root alarm, with or
        # without IFSWITCH=1, so perl through sudo -n is part of the preflight.
        result, rows, calls, out, root = self.run_window(FAKE_SUDO_PERL="0", FAKE_EN5="active")
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("refused: LEAK_CAPTURE=1 needs sudo -n for /usr/bin/perl (the other captures' wall-clock bound; "
                      "run sudo -v first); nothing connected", result.stdout)
        self.assertEqual(calls, ["sudo -n -l /usr/sbin/tcpdump", "sudo -n -l /bin/kill", "sudo -n -l /usr/bin/perl"])
        self.assertFalse((out / "physical.pcap").exists())
        self.assertFalse((out / "rollback.log").exists())
        self.assertFalse((root / "home" / ".aegis-local" / "locks" / "timing-self").exists())
        self.assertEqual(rows, {})

    @staticmethod
    def iface_pids(root):
        return {line.split()[0]: int(line.split()[1])
                for line in (root / "fake.pids.if").read_text().splitlines() if line.strip()}

    @staticmethod
    def gone(pid):
        stat = subprocess.run(["/bin/ps", "-p", str(pid), "-o", "stat="], capture_output=True, text=True).stdout.strip()
        return not stat or stat.startswith("Z")

    def test_a_quiet_interface_capture_ends_by_its_root_alarm_after_a_killed_window(self):
        # S20e: en5 never sees a packet, so its -G bound never fires; the
        # window is SIGKILLed (no EXIT trap) and the rollback's sudo kill is
        # refused, as in its own session. Only the root alarm is left to end
        # it (the fake shortens it to 12 s; the window asks for 66 + 30).
        result, rows, calls, out, root = self.run_window(kill_when_connected=True, ROLLBACK_S="6", FAKE_EN5="active",
                                                         FAKE_QUIET_IF="en5", FAKE_KILL_OK="0", FAKE_ALARM_S="12")
        self.assertEqual(result.returncode, -9)
        log = out / "rollback.log"
        deadline = time.monotonic() + 30
        while "rollback_done" not in (log.read_text() if log.exists() else "") and time.monotonic() < deadline:
            time.sleep(0.2)
        en5 = self.iface_pids(root)["en5"]
        self.assertIn(f"capture_stop_requested pid={en5} rc=1", log.read_text())
        deadline = time.monotonic() + 30
        while not self.gone(en5) and time.monotonic() < deadline:
            time.sleep(0.2)
        self.assertTrue(self.gone(en5), "the quiet capture outlived the killed window and the refused kill")
        # It ended by the alarm (SIGALRM), not by a signal or its -G bound.
        self.assertNotIn("tcpdump stopped if=en5", (root / "calls.log").read_text())
        calls = (root / "calls.log").read_text().splitlines()
        self.assertIn(f"sudo -n /usr/bin/perl -e {owner_alarm_code()} 96 /usr/sbin/tcpdump -i en5 -p -s 160 -B 4096 "
                      f"-G 66 -W 1 -U -w {out}/physical-en5.pcap", calls)

    def test_the_detached_rollback_stops_every_capture_when_the_window_is_killed(self):
        result, rows, calls, out, root = self.run_window(kill_when_connected=True, FAKE_SUDO_MODE="parent",
                                                         ROLLBACK_S="6", FAKE_EN5="active")
        self.assertEqual(result.returncode, -9)
        log = out / "rollback.log"
        deadline = time.monotonic() + 30
        while "rollback_done" not in (log.read_text() if log.exists() else "") and time.monotonic() < deadline:
            time.sleep(0.2)
        tcpdumps = self.tcpdump_pids(root)
        self.assertEqual(len(tcpdumps), 2)
        for pid in tcpdumps:
            self.assertIn(f"capture_stop_requested pid={pid} rc=0", log.read_text())
        calls_log = root / "calls.log"
        while "tcpdump stopped if=en5" not in calls_log.read_text() and time.monotonic() < deadline:
            time.sleep(0.2)
        self.assertIn("tcpdump stopped if=en5", calls_log.read_text().splitlines())


# ------------------------------------------------- S16i-3 probes and IPv6 rows

NET_PROBE = PACKAGE / "harness" / "net_probe.py"
# The window runs the probes under the system python3 (3.9); so do these tests.
SYSTEM_PY = "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else sys.executable


def shell_function(name):
    """One function of harness/real-relay-window.sh, from `name() {` to the
    first bare closing brace (or the same line for a one-liner)."""
    lines = REAL_RELAY_WINDOW.read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line.lstrip().startswith(f"{name}() {{"))
    if lines[start].split("  # ")[0].rstrip().endswith("}"):
        return lines[start]
    end = next(i for i in range(start, len(lines)) if lines[i].strip() == "}")
    return "\n".join(lines[start:end + 1])


class LoopbackServer:
    """A one-behaviour TCP server on loopback for the probe tests."""

    def __init__(self, behaviour, family=None, delay=0.0):
        import socket
        import threading
        family = family or socket.AF_INET
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.bind(("::1" if family == socket.AF_INET6 else "127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.behaviour, self.delay = behaviour, delay
        self.done = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        import socket
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        with conn:
            try:
                if self.delay:
                    time.sleep(self.delay)
                if self.behaviour == "echo":  # echo each recv, close on EOF
                    while True:
                        data = conn.recv(4096)
                        if not data:
                            break
                        conn.sendall(data)
                elif self.behaviour == "wrong":
                    while conn.recv(4096):
                        pass
                    conn.sendall(b"pong")
                elif self.behaviour == "echo_hold":  # echo once, never close
                    conn.sendall(conn.recv(4096))
                    self.done.wait(15)
                elif self.behaviour == "silent":
                    conn.recv(4096)
                    self.done.wait(15)
                elif self.behaviour == "reset":
                    conn.recv(4096)
                    time.sleep(0.2)
                    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            except OSError:
                pass

    def close(self):
        self.done.set()
        self.sock.close()
        self.thread.join(5)


class NetProbeTests(unittest.TestCase):
    """harness/net_probe.py under the system python3 against loopback only."""

    def serve(self, behaviour, **kw):
        server = LoopbackServer(behaviour, **kw)
        self.addCleanup(server.close)
        return server

    def probe(self, mode, port, host="127.0.0.1", payload="ping", limit="10"):
        result = subprocess.run([SYSTEM_PY, "-I", str(NET_PROBE), "tcp", mode, host, str(port), payload, limit],
                                capture_output=True, text=True, timeout=30)
        count, ms, outcome = result.stdout.strip().split("/")
        return result.returncode, int(count), int(ms), outcome

    def test_the_system_python_is_the_one_the_window_uses(self):
        import ast
        ast.parse(NET_PROBE.read_text(), feature_version=(3, 9))
        text = REAL_RELAY_WINDOW.read_text()
        self.assertIn("PROBE_PY=${PROBE_PY:-/usr/bin/python3}\n", text)
        if SYSTEM_PY == "/usr/bin/python3":
            version = subprocess.run([SYSTEM_PY, "-I", "-c", "import sys; print(sys.version_info[:2])"],
                                     capture_output=True, text=True, timeout=30).stdout
            self.assertRegex(version, r"^\(3, (9|[1-9][0-9])\)")

    def test_a_half_close_echo_reads_its_bytes_then_eof(self):
        rc, count, ms, outcome = self.probe("hc", self.serve("echo").port)
        self.assertEqual((rc, count, outcome), (0, 4, "eof"))
        self.assertLess(ms, 3000)

    def test_the_no_half_close_control_reads_its_bytes_and_closes(self):
        rc, count, ms, outcome = self.probe("nohc", self.serve("echo_hold").port)
        self.assertEqual((rc, count, outcome), (0, 4, "full"))
        # The same server never sends EOF: the half-close probe times out with its bytes.
        rc, count, ms, outcome = self.probe("hc", self.serve("echo_hold").port, limit="1.5")
        self.assertEqual((rc, count, outcome), (1, 4, "timeout"))
        self.assertGreaterEqual(ms, 1400)

    def test_a_reset_is_recorded_as_reset(self):
        rc, count, ms, outcome = self.probe("hc", self.serve("reset").port)
        self.assertEqual((rc, count, outcome), (1, 0, "reset"))
        rc, count, ms, outcome = self.probe("nohc", self.serve("reset").port)
        self.assertEqual((rc, count, outcome), (1, 0, "reset"))
        import socket
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        port = closed.getsockname()[1]
        closed.close()
        rc, count, ms, outcome = self.probe("hc", port)
        self.assertEqual((rc, count, outcome), (1, 0, "reset"))

    def test_silence_is_a_timeout_bounded_by_the_limit(self):
        rc, count, ms, outcome = self.probe("hc", self.serve("silent").port, limit="1.5")
        self.assertEqual((rc, count, outcome), (1, 0, "timeout"))
        self.assertGreaterEqual(ms, 1400)
        self.assertLess(ms, 5000)

    def test_a_slow_first_flow_passes_past_nc_three_seconds_and_records_its_time(self):
        rc, count, ms, outcome = self.probe("hc", self.serve("echo", delay=3.3).port)
        self.assertEqual((rc, count, outcome), (0, 4, "eof"))
        self.assertGreaterEqual(ms, 3300)
        self.assertLess(ms, 10000)

    def test_a_wrong_echo_fails_with_its_byte_count(self):
        rc, count, ms, outcome = self.probe("hc", self.serve("wrong").port)
        self.assertEqual((rc, count, outcome), (1, 4, "eof"))

    def test_ipv6_loopback_and_bad_arguments(self):
        import socket
        rc, count, ms, outcome = self.probe("hc", self.serve("echo", family=socket.AF_INET6).port, host="::1",
                                            payload="ping6")
        self.assertEqual((rc, count, outcome), (0, 5, "eof"))
        for args in (["tcp", "both", "127.0.0.1", "7", "ping"], ["tcp", "hc", "127.0.0.1", "0", "ping"],
                     ["tcp", "hc", "127.0.0.1", "7", "ping", "0"], ["tcp", "hc"], ["nope"]):
            result = subprocess.run([SYSTEM_PY, "-I", str(NET_PROBE), *args], capture_output=True, text=True,
                                    timeout=30)
            self.assertEqual(result.returncode, 2, args)
            self.assertEqual(result.stdout, "", args)

    def test_source6_names_the_kernel_choice_without_sending(self):
        result = subprocess.run([SYSTEM_PY, "-I", str(NET_PROBE), "source6", "::1"], capture_output=True,
                                text=True, timeout=30)
        self.assertEqual((result.returncode, result.stdout), (0, "::1\n"))

    def test_scan64_finds_a_physical_prefix_and_prints_nothing(self):
        phys = ["2001:db8:1:2::50", "2001:db8:1:3:a::9"]

        def scan(body, addrs=phys):
            result = subprocess.run([SYSTEM_PY, "-I", str(NET_PROBE), "scan64", *addrs], input=body,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.stdout, "")
            return result.returncode

        self.assertEqual(scan("ip=2001:db8:ffff::7\n"), 0)
        self.assertEqual(scan("ip=2001:db8:1:2:dead::1\n"), 1)
        self.assertEqual(scan('{"ip":"2001:0DB8:0001:0003:0:0:0:77"}'), 1)
        self.assertEqual(scan("seen 2001:db8:1:2::50."), 1)
        self.assertEqual(scan("ip=192.0.2.1 time=12:30:01"), 0)
        self.assertEqual(scan("ip=2001:db8:1:2::5", addrs=[]), 0)
        self.assertEqual(scan("x", addrs=["not-an-address"]), 2)


class RealRelayWindowProbeTests(unittest.TestCase):
    """The window's tcp_probe() rows and the order of its TCP echo checks."""

    def run_probe(self, calls, limit="10"):
        script = ("set -u\n"
                  "result() { printf '%s\\t%s\\t%s\\n' \"$1\" \"$2\" \"$3\"; }\n"
                  f"{shell_function('tcp_probe')}\n{calls}\n")
        env = {"PATH": "/usr/bin:/bin", "PROBE_PY": SYSTEM_PY, "PROBE_LIMIT_S": limit,
               "HARNESS_DIR": str(NET_PROBE.parent)}
        result = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return [line.split("\t") for line in result.stdout.splitlines()]

    def test_rows_record_bytes_ms_and_outcome(self):
        echo = LoopbackServer("echo")
        self.addCleanup(echo.close)
        silent = LoopbackServer("silent")
        self.addCleanup(silent.close)
        rows = self.run_probe(f"tcp_probe tcp_echo_v4 hc 127.0.0.1 {echo.port} ping\n"
                              f"tcp_probe tcp_echo_v4_warm hc 127.0.0.1 {silent.port} ping", limit="1")
        self.assertEqual(rows[0][:2], ["tcp_echo_v4", "pass"])
        self.assertRegex(rows[0][2], r"^4/[0-9]+/eof$")
        self.assertEqual(rows[1][:2], ["tcp_echo_v4_warm", "fail"])
        self.assertRegex(rows[1][2], r"^0/[0-9]+/timeout$")

    def test_the_cold_probe_is_the_first_flow_and_the_old_nc_line_is_kept(self):
        text = REAL_RELAY_WINDOW.read_text()
        cold = text.index('tcp_probe tcp_echo_v4 hc "${ECHO_TCP%:*}" "${ECHO_TCP#*:}" ping\n')
        nohc = text.index('tcp_probe tcp_echo_v4_nohc nohc ')
        nc = text.index('t=$(printf ping | nc -w 3 "${ECHO_TCP%:*}" "${ECHO_TCP#*:}" 2>&1 | head -c 20)')
        self.assertIn('result tcp_echo_v4_nc "$([ "$t" = ping ] && echo pass || echo fail)" "$t"', text)
        udp = text.index("nc -u -w 3")
        whoami = text.index('w=$(curl -s -m 5 "$WHOAMI"')
        route = text.index("result default_route ")
        self.assertLess(route, cold)
        self.assertEqual(sorted([cold, nohc, nc, udp, whoami]), [cold, nohc, nc, udp, whoami])
        burst = text.index("    burst 90 88\n")
        warm = text.index('tcp_probe tcp_echo_v4_warm hc ')
        self.assertLess(burst, warm)
        self.assertIn("tcp_probe tcp_echo_v4_warm_nohc nohc ", text)
        self.assertEqual(text.count("result tcp_echo_v4 "), 0)  # the bare nc row name is gone


FAKE_V6 = {
    "ifconfig": r"""#!/bin/sh
[ "$1" = utun9 ] || exit 1
printf 'utun9: flags=8051<UP> mtu 1280\n\tinet 198.19.255.1 --> 198.19.255.1 netmask 0xffffffff\n'
printf '\tinet6 fe80::9%%utun9 prefixlen 64 scopeid 0x13\n'
printf '\tinet6 %s prefixlen %s\n' "${FAKE_UTUN6:-fd00:ae61::1}" "${FAKE_UTUN6_PREFIX:-120}"
""",
    # S16j-2: the anchor, the scoped physical default and the unscoped default
    # are looked up separately; an empty value prints no interface line.
    "route": r"""#!/bin/sh
echo "route $*" >> "$CALLS"
case "$*" in
  *-ifscope*) i=${FAKE_SCOPED6-en0};;
  *fd00:ae61::2*) i=${FAKE_ANCHOR6-utun9};;
  *) i=${FAKE_DEF6-utun9};;
esac
[ -n "$i" ] && echo "  interface: $i"
exit 0
""",
    # The physical /64 and a host route into it must never reach a row.
    "netstat": r"""#!/bin/sh
echo "netstat $*" >> "$CALLS"
printf 'Routing tables\n\nInternet6:\nDestination                             Gateway                                 Flags               Netif Expire\n'
[ -n "${FAKE_NETSTAT_EMPTY:-}" ] && exit 0
printf 'default                                 fe80::%%utun9                            UGcIg               utun9\n'
printf 'default                                 fe80::1%%en0                             UGcIg                 en0\n'
printf '2001:db8:1:2::/64                       link#6                                  UCI                   en0\n'
printf 'fd00:ae61::/120                         fd00:ae61::1                            UC                  utun9\n'
printf 'fe80::%%utun9/64                         fe80::9%%utun9                           UcI                 utun9\n'
printf 'fe80::9%%utun9                           link#19                                 UHLI                  lo0\n'
printf 'fe80::4c2a:77ff:fe01:2%%utun9            link#19                                 UHLWI               utun9\n'
printf 'ff00::/8                                ::1                                     UmCI                utun9\n'
printf '2001:db8:1:2::77                        fd00:ae61::1                            UGHWI               utun9\n'
""",
    "scutil": r"""#!/bin/sh
printf 'DNS configuration\n\nresolver #1\n  nameserver[0] : 198.19.255.2\n  nameserver[1] : %s\n' "${FAKE_NS1:-fd00:ae61::2}"
""",
    "dig": r"""#!/bin/sh
echo "dig $*" >> "$CALLS"
case " $* " in
  *" -6 "*AAAA*) printf '%b' "${FAKE_AAAA6-2606:2800:21f:cb07::1\n}";;
  *AAAA*) printf '%b' "${FAKE_AAAA4-www.example.com.\n2606:2800:21f:cb07::1\n}";;
  *) echo 198.18.0.9;;
esac
""",
    "curl": r"""#!/bin/sh
echo "curl $*" >> "$CALLS"
case "$*" in
  *-w*) printf '%s' "${FAKE_HTTP6-200 2606:2800:21f:cb07::1}";;
  *) printf '%s' "${FAKE_WHOAMI6_BODY-ip=2001:db8:ffff::7}";;
esac
""",
    "nc": "#!/bin/sh\necho \"nc $*\" >> \"$CALLS\"\ncat\n",
    # net_probe.py's source6 and aaaa are faked; tcp and scan64 run for real.
    "probe_py": r"""#!/bin/sh
case "$3" in
  source6) echo "${FAKE_SRC6:-fd00:ae61::1}";;
  aaaa) echo "${FAKE_SYS_AAAA:-2606:2800:21f:cb07::1}";;
  *) exec "$SYSTEM_PY" "$@";;
esac
""",
}

HOST_V6_FAKE = "2001:db8:1:2::50\n2001:db8:1:2:a::9"


class RealRelayWindowIpv6Tests(unittest.TestCase):
    """v6_checks() of harness/real-relay-window.sh with fake system commands on
    PATH and a loopback ::1 echo for tcp_echo_v6. Nothing here leaves the Mac."""

    # v34: whoami6_egress masks its passing body (egress_detail); v34 review:
    # and judges it by the relay's whole address (egress_is_relay, whose awk
    # body has bare braces: extracted by window_functions).
    FUNCTIONS = ("hostpart", "portpart", "tcp_probe", "v6_source_class", "aaaa_row", "v6_checks", "mask_addrs",
                 "egress_detail")

    def run_v6(self, handoff=True, host_v6=HOST_V6_FAKE, fields_extra=None, **env_extra):
        temp = tempfile.TemporaryDirectory(prefix="aegis-s16i3-v6-")
        self.addCleanup(temp.cleanup)
        root = pathlib.Path(temp.name)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        for name, body in FAKE_V6.items():
            (bin_dir / name).write_text(body)
            (bin_dir / name).chmod(0o755)
        calls = root / "calls.log"
        calls.write_text("")
        import socket
        echo = LoopbackServer("echo", family=socket.AF_INET6)
        self.addCleanup(echo.close)
        fields = {"ECHO_TCP6": f"[::1]:{echo.port}", "ECHO_UDP6": "[2001:db8:ffff::7]:7",
                  "WHOAMI6": "http://[2001:db8:ffff::7]:8080/", "RELAY_V6": "2001:db8:ffff::7"}
        if not handoff:
            fields = {k: "" for k in fields}
        fields.update(fields_extra or {})
        assigns = "".join(f"{k}='{v}'\n" for k, v in fields.items())
        functions = "\n".join(shell_function(name) for name in self.FUNCTIONS)
        functions += "\n" + window_functions("egress_is_relay")
        script = ("set -u\n"
                  "result() { printf '%s\\t%s\\t%s\\n' \"$1\" \"$2\" \"$3\"; }\n"
                  f"{functions}\n{assigns}"
                  "UTUN=${FAKE_UTUN-utun9}\n"
                  "PHYS=${FAKE_PHYS-en0}\n"
                  f"HOST_V6='{host_v6}'\n"
                  "v6_checks\n")
        env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "PROBE_PY": str(bin_dir / "probe_py"), "SYSTEM_PY": SYSTEM_PY,
               "PROBE_LIMIT_S": "5", "HARNESS_DIR": str(NET_PROBE.parent), "CALLS": str(calls), **env_extra}
        result = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = {}
        for line in result.stdout.splitlines():
            name, verdict, detail = line.split("\t")
            rows[name] = (verdict, detail)
        self.assertNotIn("2001:db8:1:2", result.stdout)
        return rows, calls.read_text().splitlines()

    def test_every_row_passes_on_the_expected_outputs(self):
        rows, calls = self.run_v6()
        expected = ["utun_addr_v6", "default_route_v6", "route_v6_anchor", "scoped_phys_v6_default",
                    "utun_routes_v6", "source_v6_tunnel", "system_resolver_v6", "dns_udp6_anchor",
                    "dns_tcp6_anchor", "dns_aaaa_via_relay", "dns_aaaa_v6_anchor", "system_aaaa_observed",
                    "http6_by_name", "udp_echo_v6", "tcp_echo_v6", "whoami6_egress"]
        self.assertEqual(list(rows), expected)
        info = ("scoped_phys_v6_default", "utun_routes_v6", "system_aaaa_observed")
        for name in expected:
            self.assertEqual(rows[name][0], "info" if name in info else "pass", (name, rows[name]))
        self.assertEqual(rows["utun_addr_v6"][1], "fd00:ae61::1/120")
        self.assertEqual(rows["default_route_v6"][1], "utun9")
        self.assertEqual(rows["route_v6_anchor"][1], "utun9")
        self.assertEqual(rows["scoped_phys_v6_default"][1], "en0:present")
        self.assertEqual(rows["utun_routes_v6"][1],
                         "default:UGcIg,fd00:ae61::/120:UC,fe80::/64:UcI,ff00::/8:UmCI other=2")
        self.assertIn("route -n get -inet6 fd00:ae61::2", calls)
        self.assertIn("route -n get -inet6 -ifscope en0 default", calls)
        self.assertIn("netstat -rn -f inet6", calls)
        self.assertEqual(rows["source_v6_tunnel"][1], "fd00:ae61::1")
        self.assertEqual(rows["dns_aaaa_via_relay"][1], "2606:2800:21f:cb07::1")
        self.assertEqual(rows["http6_by_name"][1], "200 2606:2800:21f:cb07::1")
        self.assertEqual(rows["udp_echo_v6"][1], "pong6")
        self.assertRegex(rows["tcp_echo_v6"][1], r"^5/[0-9]+/eof$")
        # v34: the passing body is recorded masked; the relay is relay_addr.
        self.assertEqual(rows["whoami6_egress"][1], "ip=relay_addr")
        self.assertIn("route -n get -inet6 default", calls)
        self.assertIn("dig -6 +short +time=3 +tries=1 @fd00:ae61::2 example.com A", calls)
        self.assertIn("dig -6 +tcp +short +time=3 +tries=1 @fd00:ae61::2 example.com A", calls)
        self.assertIn("dig @198.19.255.2 +short +time=3 +tries=1 example.com AAAA", calls)
        self.assertIn("dig -6 @fd00:ae61::2 +short +time=3 +tries=1 example.com AAAA", calls)
        self.assertIn("nc -6 -u -w 3 2001:db8:ffff::7 7", calls)
        self.assertIn("curl -6 -s -m 5 http://[2001:db8:ffff::7]:8080/", calls)

    def test_the_utun_address_route_and_resolver_must_be_the_tunnel_ones(self):
        rows, _ = self.run_v6(FAKE_UTUN6_PREFIX="64")
        self.assertEqual(rows["utun_addr_v6"], ("fail", "fd00:ae61::1/64"))
        rows, _ = self.run_v6(FAKE_UTUN6_PREFIX="128")
        self.assertEqual(rows["utun_addr_v6"], ("fail", "fd00:ae61::1/128"))
        rows, _ = self.run_v6(FAKE_ANCHOR6="en0")
        self.assertEqual(rows["route_v6_anchor"], ("fail", "en0"))
        rows, _ = self.run_v6(FAKE_ANCHOR6="")
        self.assertEqual(rows["route_v6_anchor"], ("fail", "none"))
        rows, _ = self.run_v6(FAKE_UTUN6="fd00:ae61::9")
        self.assertEqual(rows["utun_addr_v6"], ("fail", "none"))
        rows, _ = self.run_v6(FAKE_DEF6="en0")
        self.assertEqual(rows["default_route_v6"], ("fail", "en0"))
        rows, calls = self.run_v6(FAKE_UTUN="")
        self.assertEqual(rows["utun_addr_v6"], ("fail", "none"))
        self.assertEqual(rows["default_route_v6"][0], "fail")
        self.assertEqual(rows["route_v6_anchor"][0], "fail")
        self.assertEqual(rows["utun_routes_v6"], ("info", "none other=0"))
        self.assertFalse([c for c in calls if c.startswith("netstat")], calls)
        # No utun and no route at all: an empty interface never equals "no utun".
        rows, _ = self.run_v6(FAKE_UTUN="", FAKE_ANCHOR6="", FAKE_DEF6="")
        self.assertEqual(rows["route_v6_anchor"], ("fail", "none"))
        self.assertEqual(rows["default_route_v6"], ("fail", "none"))
        rows, _ = self.run_v6(FAKE_NS1="192.168.1.1")
        self.assertEqual(rows["system_resolver_v6"], ("fail", "192.168.1.1"))

    def test_the_v21_window_without_any_ipv6_route_still_fails(self):
        # v21: fd00:ae61::1/128, no unscoped IPv6 default anywhere, no route to
        # the anchor, and the source lookup failed.
        rows, _ = self.run_v6(FAKE_UTUN6_PREFIX="128", FAKE_DEF6="", FAKE_ANCHOR6="", FAKE_SRC6="error:OSError")
        self.assertEqual(rows["utun_addr_v6"], ("fail", "fd00:ae61::1/128"))
        self.assertEqual(rows["default_route_v6"], ("fail", "none"))
        self.assertEqual(rows["route_v6_anchor"], ("fail", "none"))
        self.assertEqual(rows["source_v6_tunnel"], ("fail", "error:OSError"))
        self.assertEqual(rows["scoped_phys_v6_default"], ("info", "en0:present"))

    def test_the_scoped_physical_default_and_utun_routes_are_info_without_addresses(self):
        rows, _ = self.run_v6(FAKE_SCOPED6="")
        self.assertEqual(rows["scoped_phys_v6_default"], ("info", "en0:absent"))
        rows, calls = self.run_v6(FAKE_PHYS="")
        self.assertEqual(rows["scoped_phys_v6_default"], ("info", "no_physical"))
        self.assertFalse([c for c in calls if "-ifscope" in c], calls)
        rows, _ = self.run_v6(FAKE_NETSTAT_EMPTY="1")
        self.assertEqual(rows["utun_routes_v6"], ("info", "none other=0"))
        # The fake table carries the Mac's /64 on en0, a host route into it on
        # utun9 and a link-local host route on utun9; run_v6 already refuses
        # any 2001:db8:1:2 in the rows, and only fe80::/64 itself is named.
        rows, _ = self.run_v6()
        self.assertTrue(rows["utun_routes_v6"][1].endswith(" other=2"), rows["utun_routes_v6"])
        self.assertNotIn("en0", rows["utun_routes_v6"][1])
        self.assertNotIn("4c2a", rows["utun_routes_v6"][1])

    def test_a_physical_source_address_fails_and_is_never_recorded(self):
        rows, _ = self.run_v6(FAKE_SRC6="2001:db8:1:2::50")
        self.assertEqual(rows["source_v6_tunnel"], ("fail", "physical_address"))
        rows, _ = self.run_v6(FAKE_SRC6="2a02:db8:77::3")
        self.assertEqual(rows["source_v6_tunnel"], ("fail", "other_address"))
        rows, _ = self.run_v6(FAKE_SRC6="fe80::1c")
        self.assertEqual(rows["source_v6_tunnel"], ("fail", "link_local"))
        rows, _ = self.run_v6(FAKE_SRC6="error:OSError")
        self.assertEqual(rows["source_v6_tunnel"], ("fail", "error:OSError"))
        rows, _ = self.run_v6(FAKE_SRC6="error:2001:db8:1:2::50")
        self.assertEqual(rows["source_v6_tunnel"], ("fail", "error:"))

    def test_aaaa_rows_fail_on_empty_tunnel_or_timed_out_answers(self):
        for answer, detail in (("", "empty"), ("fd00:ae61::5\n", "fd00:ae61::5"),
                               (";; connection timed out; no servers could be reached\n",
                                ";; connection timed out; no servers could be reached"),
                               ("2606:2800:21f:cb07::1\n::ffff:198.18.0.9\n", "::ffff:198.18.0.9"),
                               ("fe80::1\n", "fe80::1"), ("200::1\n", "200::1")):
            rows, _ = self.run_v6(FAKE_AAAA4=answer, FAKE_AAAA6=answer)
            for name in ("dns_aaaa_via_relay", "dns_aaaa_v6_anchor"):
                self.assertEqual(rows[name], ("fail", detail), (answer, name))
        rows, _ = self.run_v6(FAKE_AAAA6="")
        self.assertEqual(rows["dns_aaaa_via_relay"][0], "pass")
        self.assertEqual(rows["dns_aaaa_v6_anchor"], ("fail", "empty"))

    def test_http6_is_info_without_relay_ipv6_and_relay_rows_skip_without_fields(self):
        rows, calls = self.run_v6(handoff=False)
        self.assertEqual(rows["http6_by_name"], ("info_pass", "200 2606:2800:21f:cb07::1"))
        for name, field in (("udp_echo_v6", "echo_udp6"), ("tcp_echo_v6", "echo_tcp6"), ("whoami6_egress", "whoami6")):
            self.assertEqual(rows[name], ("skip", f"no {field}"))
        self.assertFalse([c for c in calls if c.startswith("nc ")], calls)
        self.assertEqual([c for c in calls if c.startswith("curl ")],
                         ["curl -6 -s -m 8 -o /dev/null -w %{http_code} %{remote_ip} http://example.com/"])
        rows, _ = self.run_v6(handoff=False, FAKE_HTTP6="000 ")
        self.assertEqual(rows["http6_by_name"], ("info_fail", "000 "))
        rows, _ = self.run_v6(FAKE_HTTP6="000 ")
        self.assertEqual(rows["http6_by_name"], ("fail", "000 "))
        rows, _ = self.run_v6(FAKE_HTTP6="200 198.18.0.9")
        self.assertEqual(rows["http6_by_name"][0], "fail")

    def test_whoami6_with_a_physical_prefix_fails_without_naming_it(self):
        rows, _ = self.run_v6(FAKE_WHOAMI6_BODY="ip=2001:db8:1:2:dead::1")
        self.assertEqual(rows["whoami6_egress"], ("fail", "physical_prefix_seen"))
        long_body = "x" * 120 + " ip=2001:db8:1:2::50"  # past the recorded 80 bytes
        rows, _ = self.run_v6(FAKE_WHOAMI6_BODY=long_body)
        self.assertEqual(rows["whoami6_egress"], ("fail", "physical_prefix_seen"))
        rows, _ = self.run_v6(FAKE_WHOAMI6_BODY="ip=2001:db8:eeee::1")
        self.assertEqual(rows["whoami6_egress"], ("fail", "not_relay_address"))

    def test_a_failing_whoami6_body_is_recorded_only_as_a_class(self):
        # The Mac's own address from a prefix scan64 never saw (another
        # interface, NAT66, renumbering) must not reach the row.
        rows, _ = self.run_v6(host_v6="", FAKE_WHOAMI6_BODY="ip=2001:db8:1:2::50")
        self.assertEqual(rows["whoami6_egress"], ("fail", "not_relay_address"))
        rows, _ = self.run_v6(FAKE_WHOAMI6_BODY="")
        self.assertEqual(rows["whoami6_egress"], ("fail", "empty"))
        rows, _ = self.run_v6(fields_extra={"RELAY_V6": ""}, FAKE_WHOAMI6_BODY="ip=2001:db8:eeee::1")
        self.assertEqual(rows["whoami6_egress"], ("fail", "no_relay_ipv6"))
        # A pass still records the body, which names the relay; v34: masked,
        # the relay as relay_addr and any other address as its class.
        rows, _ = self.run_v6(FAKE_WHOAMI6_BODY="ip=2001:db8:ffff::7")
        self.assertEqual(rows["whoami6_egress"], ("pass", "ip=relay_addr"))
        rows, _ = self.run_v6(FAKE_WHOAMI6_BODY="via 2001:db8:eeee::1 ip=2001:db8:ffff::7")
        self.assertEqual(rows["whoami6_egress"], ("pass", "via ip6_global ip=relay_addr"))
        # v34 review: the relay's whole address, as the IPv4 rows judge it,
        # case and brackets ignored; a longer address that merely contains it
        # fails (it passed a substring match before).
        rows, _ = self.run_v6(FAKE_WHOAMI6_BODY="ip=[2001:DB8:FFFF::7]")
        self.assertEqual(rows["whoami6_egress"], ("pass", "ip=[relay_addr]"))
        for body in ("ip=2001:db8:ffff::70", "ip=2001:db8:ffff::7:1", "ip=12001:db8:ffff::7"):
            rows, _ = self.run_v6(FAKE_WHOAMI6_BODY=body)
            self.assertEqual(rows["whoami6_egress"], ("fail", "not_relay_address"), body)

    def test_a_tcp_echo_v6_failure_records_its_outcome(self):
        import socket
        silent = LoopbackServer("silent", family=socket.AF_INET6)
        self.addCleanup(silent.close)
        env = {"PATH": "/usr/bin:/bin", "PROBE_PY": SYSTEM_PY, "PROBE_LIMIT_S": "1",
               "HARNESS_DIR": str(NET_PROBE.parent)}
        script = ("set -u\nresult() { printf '%s\\t%s\\t%s\\n' \"$1\" \"$2\" \"$3\"; }\n"
                  + "\n".join(shell_function(n) for n in ("hostpart", "portpart", "tcp_probe"))
                  + f"\nE='[::1]:{silent.port}'\n"
                  "tcp_probe tcp_echo_v6 hc \"$(hostpart \"$E\")\" \"$(portpart \"$E\")\" ping6\n")
        result = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, env=env, timeout=30)
        script_rows = [line.split("\t") for line in result.stdout.splitlines()]
        self.assertEqual(script_rows[0][:2], ["tcp_echo_v6", "fail"])
        self.assertRegex(script_rows[0][2], r"^0/[0-9]+/timeout$")


ROLLBACK_CANCEL_GATE = """scutil --nc stop "$SID"
down=0
for _ in $(seq 1 20); do
    if [ "$(scutil --nc status "$SID" | head -1)" = "Disconnected" ] && [ "$(route -n get default | awk '/interface:/{print $2}')" = "$PHYS" ]; then
        down=$((down+1)); [ "$down" -ge 2 ] && break
    else
        down=0
    fi
    sleep 0.5
done
if [ "$down" -ge 2 ]; then
    echo "$TOKEN" > "$OUT/rollback.cancel"
    rm -f "$LOCK"
    result disconnect_verified pass "$PHYS"
else
    "$HOST_BIN" --emergency-stop
    result disconnect_verified fail "rollback stays armed"
fi
"""


class RealRelayWindowStaticTests(unittest.TestCase):
    """Static S16i-3 properties of harness/real-relay-window.sh."""

    def test_the_rollback_cancel_gate_is_unchanged_and_the_v6_rows_follow_it(self):
        text = REAL_RELAY_WINDOW.read_text()
        self.assertEqual(text.count(ROLLBACK_CANCEL_GATE), 1)
        self.assertEqual(hashlib.sha256(ROLLBACK_CANCEL_GATE.encode()).hexdigest(),
                         "349ffdb2b8bf2d31fa417010946ab277c09c372385298d72d9e93ea6ce6ec2b6")
        gate_end = text.index(ROLLBACK_CANCEL_GATE) + len(ROLLBACK_CANCEL_GATE)
        self.assertGreater(text.index("result disconnect_v6_route "), gate_end)
        # v31 review: disconnect_v6_addr starts where disconnect_v6_route does.
        self.assertGreater(text.index('result_since "$V6_FROM" disconnect_v6_addr '), gate_end)
        self.assertGreater(text.index('V6_FROM=$RESULT_FROM'), gate_end)
        # The cancel token is written in exactly one place: the gate.
        self.assertEqual(text.count('> "$OUT/rollback.cancel"'), 1)

    def test_rollback_default_covers_the_longer_window(self):
        text = REAL_RELAY_WINDOW.read_text()
        import re
        default = int(re.search(r"^ROLLBACK_S=\$\{ROLLBACK_S:-([0-9]+)\}$", text, re.M).group(1))
        self.assertGreaterEqual(default, 150)
        self.assertIn("CAPTURE_BOUND_S=$((ROLLBACK_S + 60))", text)

    def test_ofield_reads_absent_or_null_as_empty_and_field_still_fails(self):
        with tempfile.TemporaryDirectory(prefix="aegis-s16i3-ofield-") as temp:
            handoff = pathlib.Path(temp) / "handoff.json"
            handoff.write_text(json.dumps({"relay": "203.0.113.7:443", "relay_ipv6": None,
                                           "echo_tcp6": "[2001:db8::7]:7"}))
            script = (f"{shell_function('field')}\n{shell_function('ofield')}\n"
                      f"{shell_function('hostpart')}\n{shell_function('portpart')}\n"
                      "printf '<%s>' \"$(ofield whoami6)\" \"$(ofield relay_ipv6)\" \"$(ofield echo_tcp6)\"\n"
                      "printf '<%s>' \"$(hostpart \"$(ofield echo_tcp6)\")\" \"$(portpart \"$(ofield echo_tcp6)\")\"\n"
                      "printf '<%s>' \"$(field relay)\"\n"
                      "field whoami6 >/dev/null 2>&1; echo \" field_rc=$?\"\n")
            result = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True,
                                    env={"PATH": "/usr/bin:/bin", "HANDOFF": str(handoff)}, timeout=30)
        self.assertEqual(result.stdout,
                         "<><><[2001:db8::7]:7><2001:db8::7><7><203.0.113.7:443> field_rc=1\n", result.stderr)


# ------------------------------------------------ S21i NETLOSS window mode

NETLOSS_SH = PACKAGE / "harness" / "netloss.sh"
PHYS_V6 = "2001:db8:1:2::50"
RELAY6 = "2001:db8:5::7"

NETLOSS_FAKE_COMMANDS = dict(WINDOW_FAKE_COMMANDS)
NETLOSS_FAKE_COMMANDS.update({
    # NS_WIFI holds On/Off, NS_V6 Automatic/Off. Turning Wi-Fi off makes a
    # Connected tunnel Reasserting; turning it on lets it recover unless
    # FAKE_NO_RECOVER=1. FAKE_ON_FAILS=N fails the first N on requests.
    "networksetup": r"""#!/bin/sh
echo "networksetup $*" >> "$CALLS"
case "$1" in
  -listallhardwareports)
    printf '\nHardware Port: %s\nDevice: en0\nEthernet Address: 02:00:00:00:00:01\n' "${FAKE_PORT:-Wi-Fi}"
    if [ "${FAKE_EN5:-0}" = 1 ]; then printf '\nHardware Port: Thunderbolt Ethernet\nDevice: en5\nEthernet Address: 02:00:00:00:00:05\n'; fi
    printf '\nVLAN Configurations\n===================\n';;
  -listnetworkserviceorder)
    printf 'An asterisk (*) denotes that a network service is disabled.\n'
    if [ -n "${FAKE_SERVICE_ORDER+x}" ]; then printf '%b' "$FAKE_SERVICE_ORDER"; exit 0; fi
    printf '(1) %s\n(Hardware Port: %s, Device: en0)\n\n' "${FAKE_PORT:-Wi-Fi}" "${FAKE_PORT:-Wi-Fi}";;
  -getairportpower) [ "$2" = en0 ] || exit 1; echo "Wi-Fi Power (en0): $(cat "$NS_WIFI")";;
  -setairportpower)
    [ "$2" = en0 ] || exit 1
    if [ "$3" = off ]; then
      echo Off > "$NS_WIFI"
      st=$(cat "$STATE"); [ "$st" = Connected ] && echo Reasserting > "$STATE"
    else
      n=$(cat "$NS_ON_COUNT" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$NS_ON_COUNT"
      if [ "$n" -le "${FAKE_ON_FAILS:-0}" ]; then echo "fake: power on refused" >&2; exit 1; fi
      echo On > "$NS_WIFI"
      if [ "${FAKE_NO_RECOVER:-0}" != 1 ] && [ "$(cat "$STATE")" = Reasserting ]; then echo Connected > "$STATE"; fi
    fi;;
  -getinfo) printf 'DHCP Configuration\nIP address: 192.168.1.50\nIPv6: %s\n' "$(cat "$NS_V6")";;
  -setv6off)
    if [ "${FAKE_V6_DENIED:-0}" = 1 ]; then echo "** Error: requires admin" >&2; exit 14; fi
    echo Off > "$NS_V6";;
  -setv6automatic) echo Automatic > "$NS_V6";;
  *) exit 1;;
esac
""",
    "scutil": r"""#!/bin/sh
case "$1 $2" in
  "--nc status") cat "$STATE"; echo "Extended Status <dictionary> {";;
  "--nc stop") echo "scutil $*" >> "$CALLS"; echo Disconnected > "$STATE";;
  "--dns "*) printf 'DNS configuration\n\nresolver #1\n  nameserver[0] : 198.19.255.2\n  nameserver[1] : fd00:ae61::2\n';;
esac
""",
    "route": r"""#!/bin/sh
case "$(cat "$STATE")" in Connected|Reasserting) echo "  interface: utun9"; exit 0;; esac
echo "  interface: en0"
""",
    "ifconfig": r"""#!/bin/sh
if [ -z "$1" ] || [ "$1" = en0 ]; then
  printf 'en0: flags=8863<UP> mtu 1500\n\tether 02:00:00:00:00:01\n'
  if [ "$(cat "$NS_WIFI")" = On ]; then
    printf '\tinet6 fe80::1c%%en0 prefixlen 64 scopeid 0x6\n'
    [ "$(cat "$NS_V6")" = Automatic ] && printf '\tinet6 2001:db8:1:2::50 prefixlen 64 autoconf secured\n'
    printf '\tinet 192.168.1.50 netmask 0xffffff00 broadcast 192.168.1.255\n\tstatus: active\n'
  else
    printf '\tstatus: inactive\n'
  fi
fi
if [ "${FAKE_EN5:-0}" = 1 ] && { [ -z "$1" ] || [ "$1" = en5 ]; }; then
  printf 'en5: flags=8863<UP> mtu 1500\n\tinet 10.0.0.5 netmask 0xffffff00 broadcast 10.0.0.255\n\tstatus: active\n'
fi
case "$(cat "$STATE")" in Connected|Reasserting)
  if [ -z "$1" ] || [ "$1" = utun9 ]; then
    printf 'utun9: flags=8051<UP> mtu 1400\n\tinet 198.19.255.1 --> 198.19.255.1 netmask 0xffffffff\n\tinet6 fe80::9%%utun9 prefixlen 64 scopeid 0x13\n\tinet6 fd00:ae61::1 prefixlen 120\n'
  fi;;
esac
exit 0
""",
    # Traffic answers only while the fake tunnel is Connected.
    "nc": "#!/bin/sh\n[ \"$(cat \"$STATE\")\" = Connected ] && exec cat\ncat >/dev/null; exit 1\n",
    "curl": "#!/bin/sh\ncase \"$*\" in *-w*) printf '200\\n';; *\"-6 \"*) printf '';;"
            " *) [ \"$(cat \"$STATE\")\" = Connected ] && echo \"ip=$RELAY_IP\";; esac\n",
    "probe_py": r"""#!/bin/sh
echo "probe $3 $4" >> "$CALLS"
case "$3" in
  tcp) [ "$(cat "$STATE")" = Connected ] || { echo 0/5000/timeout; exit 1; }
       case "$4" in hc) echo 4/7/eof;; *) echo 4/7/full;; esac;;
  source6) echo fd00:ae61::1;;
  aaaa) echo 2001:db8:5::1;;
  scan64) exec "$SYSTEM_PY" "$@";;
  *) exit 2;;
esac
""",
    # Stands in for /usr/bin/log: the provider's codes of one netloss cycle.
    "fake_log": r"""#!/bin/sh
echo "log $1" >> "$CALLS"
[ "$1" = show ] || exit 1
printf 'Timestamp               Ty Process[PID:TID]\n'
if [ -n "${FAKE_PROVIDER_LOG+x}" ]; then printf '%b' "$FAKE_PROVIDER_LOG"; exit 0; fi
for l in "path_change unsatisfied" "reasserting on" "session_lost relay_path_changed" "path_change name:en0" \
         "relay_interface_repinned name:en0" "session_rebuilt attempt:1" "reasserting off"; do
  echo "2026-10-23 06:00:00.000 Df PacketTunnel[42:1] [dev.aegis.macos.PacketTunnel] aegis-ne $l"
done
""",
})


class RealRelayWindowNetlossTests(unittest.TestCase):
    """NETLOSS=1 of harness/real-relay-window.sh (harness/netloss.sh) with
    fake networksetup, scutil, route, ifconfig, log and traffic commands on
    PATH and a temporary HOME. Nothing here changes a real interface."""

    def setup_world(self, wifi="On", v6="Automatic", relay=f"{RELAY_IP}:443"):
        temp = tempfile.TemporaryDirectory(prefix="aegis-s21i-netloss-")
        self.addCleanup(temp.cleanup)
        root = pathlib.Path(temp.name)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        for name, body in NETLOSS_FAKE_COMMANDS.items():
            (bin_dir / name).write_text(body)
            (bin_dir / name).chmod(0o755)
        host = root / "AEGIS.app" / "Contents" / "MacOS" / "aegis-ne-host"
        host.parent.mkdir(parents=True)
        host.write_text(WINDOW_FAKE_HOST)
        host.chmod(0o755)
        (root / "home" / ".aegis-local" / "locks").mkdir(parents=True)
        handoff = root / "handoff.json"
        handoff.write_text(json.dumps({"relay": relay, "echo_tcp": f"{RELAY_IP}:7",
                                       "echo_udp": f"{RELAY_IP}:7", "whoami": f"http://{RELAY_IP}/ip"}))
        for name, text in (("state", "Disconnected"), ("wifi", wifi), ("v6", v6), ("calls.log", "")):
            (root / name).write_text(text + ("\n" if text else ""))
        env = {"PATH": f"{bin_dir}:/usr/bin:/bin:/usr/sbin", "HOME": str(root / "home"),
               "APP": str(root / "AEGIS.app"), "HANDOFF": str(handoff), "OUT": str(root / "out"),
               "ROLLBACK_S": "60", "STATE": str(root / "state"), "CALLS": str(root / "calls.log"),
               "RELAY_IP": RELAY_IP, "PROBE_PY": str(bin_dir / "probe_py"), "SYSTEM_PY": SYSTEM_PY,
               "LOG_BIN": str(bin_dir / "fake_log"), "NS_WIFI": str(root / "wifi"), "NS_V6": str(root / "v6"),
               "NS_ON_COUNT": str(root / "on.count"), "NETLOSS": "1", "NETLOSS_OFF_S": "2",
               "NETLOSS_GRACE_S": "3", "NETLOSS_RECOVER_S": "5", "NETLOSS_ADDR_OFF_S": "2",
               "NETLOSS_RESTORE_WAIT_S": "1"}
        self.addCleanup(self.end_rollbacks, root / "out")
        return root, env

    @staticmethod
    def end_rollbacks(out):
        # A failing run may leave a fake-only rollback armed: end it by pid.
        for log in sorted(out.glob("*rollback.log")) if out.exists() else []:
            text = log.read_text()
            if "rollback_cancelled" in text or "rollback_done" in text:
                continue
            for line in text.splitlines():
                if line.startswith("armed pid="):
                    try:
                        os.kill(int(line.split()[1].split("=")[1]), 9)
                    except (OSError, ValueError):
                        pass

    @staticmethod
    def rows_of(out):
        rows = {}
        if (out / "results.tsv").exists():
            for line in (out / "results.tsv").read_text().splitlines():
                name, verdict, detail, status, _start, _end = line.split("\t")  # v31: UTC start, end
                rows[name] = (verdict, detail, status)
        return rows

    def run_window(self, wifi="On", v6="Automatic", relay=f"{RELAY_IP}:443", **extra):
        root, env = self.setup_world(wifi, v6, relay)
        env.update(extra)
        result = subprocess.run(["/bin/bash", str(REAL_RELAY_WINDOW)], capture_output=True, text=True,
                                env=env, timeout=150)
        return result, self.rows_of(root / "out"), (root / "calls.log").read_text().splitlines(), root

    def assert_refused_untouched(self, result, rows, calls, root, reason):
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn(f"refused: NETLOSS=1: {reason}", result.stdout)
        self.assertFalse([c for c in calls if c.startswith(("host --connect", "networksetup -set"))], calls)
        self.assertFalse((root / "home" / ".aegis-local" / "locks" / "timing-self").exists())
        self.assertFalse(list((root / "out").glob("*rollback.log")))
        self.assertEqual(rows, {})
        self.assertEqual((root / "wifi").read_text().strip(), "On" if "reads 'Off'" not in reason else "Off")

    def test_a_clean_cycle_turns_wifi_off_and_on_under_a_rollback_and_the_tunnel_recovers(self):
        result, rows, calls, root = self.run_window()
        out = root / "out"
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        connect = next(i for i, c in enumerate(calls) if c.startswith("host --connect"))
        off = calls.index("networksetup -setairportpower en0 off")
        on = calls.index("networksetup -setairportpower en0 on")
        stop = next(i for i, c in enumerate(calls) if c.startswith("scutil --nc stop"))
        self.assertLess(connect, off)
        self.assertLess(off, on)
        self.assertLess(on, stop)
        self.assertEqual(rows["netloss_preflight"][:2],
                         ("info", "port=Wi-Fi device=en0 only_route=true off=2s recover_bound=5s"))
        self.assertIn("netloss: device=en0 port=Wi-Fi only_route=true rollback_s=60", result.stdout)
        names = list(rows)
        order = ["netloss_rollback_armed", "netloss_off", "netloss_status_during_off", "netloss_restored",
                 "netloss_rollback_ended", "netloss_recovered", "netloss_whoami_egress", "netloss_udp_echo_v4",
                 "netloss_tcp_echo_v4", "netloss_log_path_change", "netloss_rebuild_settled"]
        self.assertEqual([names.index(n) for n in order], sorted(names.index(n) for n in order))
        self.assertLess(names.index("dns_aaaa_v6_anchor"), names.index("netloss_preflight"))
        self.assertLess(names.index("netloss_rebuild_settled"), names.index("disconnect_verified"))
        self.assertEqual(rows["netloss_off"][:2], ("pass", "rc=0 state=Off"))
        self.assertEqual(rows["netloss_off"][2], "Reasserting")
        self.assertIn("statuses=Reasserting", rows["netloss_status_during_off"][1])
        self.assertEqual(rows["netloss_restored"][:2], ("pass", "attempts=1 state=On"))
        self.assertEqual(rows["netloss_rollback_ended"][1], "rollback_cancelled restored_verified")
        self.assertEqual(rows["netloss_recovered"][0], "pass", rows["netloss_recovered"])
        for name in ("netloss_whoami_egress", "netloss_udp_echo_v4", "netloss_tcp_echo_v4"):
            self.assertEqual(rows[name][0], "pass", (name, rows[name]))
            self.assertEqual(rows[name][2], "Connected", (name, rows[name]))
        self.assertEqual(rows["netloss_log_path_change"][:2], ("info", "count=2 seq=unsatisfied,name:en0"))
        self.assertEqual(rows["netloss_log_relay_interface_repinned"][1], "count=1 seq=name:en0")
        self.assertEqual(rows["netloss_log_session_rebuilt"][1], "count=1 seq=attempt:1")
        self.assertEqual(rows["netloss_log_reasserting"][1], "count=2 seq=on,off")
        self.assertEqual(rows["netloss_rebuild_settled"][:2], ("pass", "reasserting_off"))
        self.assertEqual(rows["disconnect_verified"][0], "pass")
        self.assertEqual((root / "wifi").read_text().strip(), "On")
        log = (out / "netloss-wifi-rollback.log").read_text()
        pid = int(log.split("armed pid=")[1].split()[0])
        self.assertIn(f"pid={pid} fires_after=5s", rows["netloss_rollback_armed"][1])
        self.assertNotIn("rollback_fired", log)
        self.assertFalse((root / "home" / ".aegis-local" / "locks" / "timing-self").exists())
        # No address phase unless asked for, and no physical address recorded.
        self.assertFalse([n for n in rows if n.startswith("netloss_addr_")])
        self.assertFalse([c for c in calls if "-setv6" in c])
        for text in ((out / "results.tsv").read_text(), (out / "window.log").read_text()):
            self.assertNotIn(PHYS_V6, text)

    def test_the_default_rollback_grows_with_the_netloss_cycle_and_a_given_one_does_not(self):
        root, env = self.setup_world()
        script = (f". '{NETLOSS_SH}'\nPHYS=en0 LEAK_CAPTURE=0\n"
                  "netloss_preflight || { echo \"refused $NL_REFUSAL\"; exit 3; }\necho \"extra=$NL_EXTRA_S\"\n")
        env.update(NETLOSS_OFF_S="10", NETLOSS_RECOVER_S="60", NETLOSS_RESTORE_WAIT_S="10")
        out = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(out.stdout.strip(), "extra=170", out.stderr)
        env.update(NETLOSS_ADDR="1")
        out = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, env=env, timeout=30)
        # The address phase has its own off time (NETLOSS_ADDR_OFF_S=2 here).
        self.assertEqual(out.stdout.strip(), "extra=332", out.stderr)
        text = REAL_RELAY_WINDOW.read_text()
        self.assertIn('[ -n "$ROLLBACK_S_GIVEN" ] || ROLLBACK_S=$((ROLLBACK_S + NL_EXTRA_S))', text)
        self.assertLess(text.index("ROLLBACK_S_GIVEN=${ROLLBACK_S:-}"), text.index("ROLLBACK_S=${ROLLBACK_S:-180}"))
        # The window logs the rollback it armed with: grown only without ROLLBACK_S
        # (180 + 2 off + 5 recovery + 3 x 1 restore wait + 70).
        del env["ROLLBACK_S"]
        env.update(NETLOSS_ADDR="0", NETLOSS_OFF_S="2", NETLOSS_RECOVER_S="5", NETLOSS_RESTORE_WAIT_S="1")
        res = subprocess.run(["/bin/bash", str(REAL_RELAY_WINDOW)], capture_output=True, text=True, env=env, timeout=150)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("netloss: device=en0 port=Wi-Fi only_route=true rollback_s=260", res.stdout)
        deadline = time.monotonic() + 10
        while "rollback_cancelled" not in (root / "out" / "rollback.log").read_text() and time.monotonic() < deadline:
            time.sleep(0.1)
        self.assertIn("rollback_cancelled", (root / "out" / "rollback.log").read_text())
        result, rows, calls, root = self.run_window(NETLOSS="0")
        self.assertNotIn("netloss_preflight", rows)
        self.assertFalse([c for c in calls if c.startswith("networksetup")], calls)
        self.assertEqual(rows["disconnect_verified"][0], "pass")

    def test_refusals_happen_before_the_lock_the_rollback_and_any_connect(self):
        result, rows, calls, root = self.run_window(FAKE_PORT="Ethernet")
        self.assert_refused_untouched(result, rows, calls, root, "physical interface en0 is Ethernet, not Wi-Fi")
        result, rows, calls, root = self.run_window(wifi="Off")
        self.assert_refused_untouched(result, rows, calls, root, "Wi-Fi power of en0 reads 'Off', not On")
        result, rows, calls, root = self.run_window(NL_PY="/nonexistent/python3")
        self.assert_refused_untouched(result, rows, calls, root,
                                      "no rollback can restore en0 (/nonexistent/python3 missing, only_route=true)")
        result, rows, calls, root = self.run_window(NL_PY="/nonexistent/python3", FAKE_EN5="1")
        self.assert_refused_untouched(result, rows, calls, root,
                                      "no rollback can restore en0 (/nonexistent/python3 missing, only_route=false)")
        result, rows, calls, root = self.run_window(NETLOSS_OFF_S="61")
        self.assert_refused_untouched(result, rows, calls, root, "NETLOSS_OFF_S=61 is outside 1..60")
        result, rows, calls, root = self.run_window(NETLOSS_RECOVER_S="x")
        self.assert_refused_untouched(result, rows, calls, root, "NETLOSS_RECOVER_S=x is outside 5..180")
        result, rows, calls, root = self.run_window(LEAK_CAPTURE="1")
        self.assert_refused_untouched(result, rows, calls, root, "not with LEAK_CAPTURE=1")
        result, rows, calls, root = self.run_window(NETWORKSETUP="no-such-networksetup")
        self.assert_refused_untouched(result, rows, calls, root, "networksetup not found")
        self.assertFalse([c for c in calls if c.startswith("sudo")], calls)

    def test_a_rollback_that_does_not_arm_turns_nothing_off(self):
        result, rows, calls, root = self.run_window(NL_PY="/usr/bin/true")
        self.assertEqual(rows["netloss_rollback_armed"][:2], ("fail", "pid=none; nothing was turned off"))
        self.assertFalse([c for c in calls if c.startswith("networksetup -set")], calls)
        self.assertNotIn("netloss_off", rows)
        self.assertEqual(rows["disconnect_verified"][0], "pass")
        self.assertEqual((root / "wifi").read_text().strip(), "On")

    def test_a_second_active_interface_is_recorded_as_not_the_only_route(self):
        result, rows, calls, root = self.run_window(FAKE_EN5="1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("only_route=false", rows["netloss_preflight"][1])
        self.assertEqual(rows["netloss_recovered"][0], "pass")

    def test_the_rollback_restores_wifi_after_the_window_and_its_group_are_killed(self):
        root, env = self.setup_world()
        env.update(NETLOSS_OFF_S="20", NETLOSS_GRACE_S="2")
        window = subprocess.Popen(["/bin/bash", str(REAL_RELAY_WINDOW)], env=env, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, start_new_session=True)
        deadline = time.monotonic() + 60
        while (root / "wifi").read_text().strip() != "Off" and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual((root / "wifi").read_text().strip(), "Off")
        log = root / "out" / "netloss-wifi-rollback.log"
        pid = int(log.read_text().split("armed pid=")[1].split()[0])
        os.killpg(window.pid, signal.SIGKILL)  # the window, its tee and every child left in its group
        window.wait(timeout=10)
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT):
            os.kill(pid, sig)
        while "rollback_done" not in log.read_text() and time.monotonic() < deadline:
            time.sleep(0.2)
        text = log.read_text()
        self.assertIn("rollback_fired", text)
        self.assertIn("restored attempt=1", text)
        self.assertEqual((root / "wifi").read_text().strip(), "On")
        self.assertIn("networksetup -setairportpower en0 on", (root / "calls.log").read_text().splitlines())
        self.assertFalse((root / "out" / "netloss-wifi-rollback.cancel").exists())

    def test_the_rollback_survives_a_sigkill_of_every_descendant_of_the_window(self):
        # A supervisor or tool timeout that walks the window's process tree
        # by ppid (as tree-kill does) must not reach the rollback.
        root, env = self.setup_world()
        env.update(NETLOSS_OFF_S="20", NETLOSS_GRACE_S="2")
        window = subprocess.Popen(["/bin/bash", str(REAL_RELAY_WINDOW)], env=env, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, start_new_session=True)
        deadline = time.monotonic() + 60
        while (root / "wifi").read_text().strip() != "Off" and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual((root / "wifi").read_text().strip(), "Off")
        log = root / "out" / "netloss-wifi-rollback.log"
        pid = int(log.read_text().split("armed pid=")[1].split()[0])
        info = subprocess.run(["/bin/ps", "-o", "ppid=", "-o", "pgid=", "-p", str(pid)], capture_output=True,
                              text=True).stdout.split()
        self.assertEqual(info, ["1", str(pid)])
        tree, frontier = [], [window.pid]
        while frontier:
            parent = frontier.pop()
            tree.append(parent)
            kids = subprocess.run(["/usr/bin/pgrep", "-P", str(parent)], capture_output=True, text=True).stdout.split()
            frontier.extend(int(k) for k in kids)
        self.assertNotIn(pid, tree)
        for member in tree:
            try:
                os.kill(member, signal.SIGKILL)
            except ProcessLookupError:
                pass
        window.wait(timeout=10)
        while "rollback_done" not in log.read_text() and time.monotonic() < deadline:
            time.sleep(0.2)
        self.assertIn("rollback_fired", log.read_text())
        self.assertIn("restored attempt=1", log.read_text())
        self.assertEqual((root / "wifi").read_text().strip(), "On")

    def test_a_rollback_not_adopted_by_launchd_turns_nothing_off(self):
        root, env = self.setup_world()
        fake_ps = root / "bin" / "ps"
        # Reports every process with ppid and pgid as a child of 4242.
        fake_ps.write_text("#!/bin/sh\ncase \"$*\" in *ppid=*) p=$(echo \"$*\" | sed -n 's/.*-p \\([0-9]*\\).*/\\1/p'); "
                           "echo \"4242 $p\";; *) exec /bin/ps \"$@\";; esac\n")
        fake_ps.chmod(0o755)
        result = subprocess.run(["/bin/bash", str(REAL_RELAY_WINDOW)], capture_output=True, text=True,
                                env=env, timeout=150)
        rows = self.rows_of(root / "out")
        calls = (root / "calls.log").read_text().splitlines()
        self.assertEqual(rows["netloss_rollback_armed"][0], "fail", rows)
        self.assertFalse([c for c in calls if c.startswith("networksetup -setairportpower en0 off")], calls)
        self.assertNotIn("netloss_off", rows)
        self.assertEqual((root / "wifi").read_text().strip(), "On")
        self.assertEqual(rows["disconnect_verified"][0], "pass", result.stdout)

    def test_a_restore_the_window_cannot_verify_leaves_the_rollback_armed_and_it_restores(self):
        # Keep the independent fake rollback after all three one-second
        # window attempts. With the five-second fixture deadline it can
        # consume a shared FAKE_ON_FAILS slot during the third attempt,
        # making the window succeed instead of exercising failed restoration.
        # Production defaults/deadlines and the rollback assertions stay intact.
        result, rows, calls, root = self.run_window(FAKE_ON_FAILS="3", NETLOSS_GRACE_S="10")
        out = root / "out"
        self.assertEqual(rows["netloss_restored"][0], "fail", rows)
        self.assertIn("rollback stays armed", rows["netloss_restored"][1])
        self.assertNotIn("netloss_recovered", rows)
        self.assertFalse((out / "netloss-wifi-rollback.cancel").exists())
        log = out / "netloss-wifi-rollback.log"
        deadline = time.monotonic() + 30
        while "rollback_done" not in log.read_text() and time.monotonic() < deadline:
            time.sleep(0.2)
        self.assertIn("rollback_fired", log.read_text())
        self.assertIn("restored attempt=1", log.read_text())
        self.assertEqual((root / "wifi").read_text().strip(), "On")
        # Three from the window, then the rollback's first, which works.
        # The rollback completes after run_window captured its initial calls.
        calls = (root / "calls.log").read_text().splitlines()
        self.assertEqual(calls.count("networksetup -setairportpower en0 on"), 4)
        # NETLOSS_ADDR is not attempted after an unverified Wi-Fi restore.
        result, rows, calls, root = self.run_window(FAKE_ON_FAILS="3", NETLOSS_ADDR="1", NETLOSS_GRACE_S="10")
        self.assertEqual(rows["netloss_addr_change"][:2], ("skip", "Wi-Fi not restored"))
        self.assertFalse([c for c in calls if "-setv6" in c])

    def test_the_rollback_refuses_a_cancel_while_the_switch_is_still_off(self):
        root, env = self.setup_world(wifi="Off")
        out = root / "out"
        out.mkdir()
        script = (f". '{NETLOSS_SH}'\nPHYS=en0 NETWORKSETUP=networksetup\n"
                  "alive() { kill -0 \"$1\" 2>/dev/null; }\n"
                  "nl_arm wifi 20 || { echo arm_failed; exit 1; }\n"
                  "echo \"$NL_TOKEN\" > \"$NL_CANCEL\"\necho armed\n")
        res = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, env=env, timeout=30)
        self.assertIn("armed", res.stdout, res.stderr)
        log = out / "netloss-wifi-rollback.log"
        deadline = time.monotonic() + 20
        while "rollback_done" not in log.read_text() and time.monotonic() < deadline:
            time.sleep(0.1)
        text = log.read_text()
        self.assertIn("cancel_refused state_not_restored", text)
        self.assertIn("rollback_fired", text)
        self.assertIn("restored attempt=1", text)
        self.assertEqual((root / "wifi").read_text().strip(), "On")
        # A wrong token is never a cancel.
        (root / "wifi").write_text("On\n")
        script = script.replace('echo "$NL_TOKEN"', "echo wrong-token").replace("nl_arm wifi 20", "nl_arm wifi 2")
        log.unlink()
        res = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, env=env, timeout=30)
        deadline = time.monotonic() + 20
        while "rollback_done" not in log.read_text() and time.monotonic() < deadline:
            time.sleep(0.1)
        self.assertIn("rollback_fired", log.read_text())
        self.assertNotIn("rollback_cancelled", log.read_text())

    def test_a_tunnel_that_does_not_recover_fails_recovery_and_traffic_but_wifi_is_restored(self):
        result, rows, calls, root = self.run_window(FAKE_NO_RECOVER="1")
        self.assertEqual(rows["netloss_restored"][0], "pass")
        self.assertEqual(rows["netloss_rollback_ended"][1], "rollback_cancelled restored_verified")
        self.assertEqual(rows["netloss_recovered"][0], "fail", rows["netloss_recovered"])
        self.assertIn("not within 5s status=Reasserting", rows["netloss_recovered"][1])
        for name in ("netloss_whoami_egress", "netloss_udp_echo_v4", "netloss_tcp_echo_v4"):
            self.assertEqual(rows[name][0], "fail", (name, rows[name]))
        self.assertEqual((root / "wifi").read_text().strip(), "On")
        self.assertEqual(rows["disconnect_verified"][0], "pass")

    def test_provider_log_rows_record_an_unsettled_or_absent_reassertion(self):
        line = "2026-10-23 06:00:00.000 Df PacketTunnel[42:1] aegis-ne %s\\n"
        result, rows, calls, root = self.run_window(
            FAKE_PROVIDER_LOG=line % "path_change unsatisfied" + line % "reasserting on")
        self.assertEqual(rows["netloss_rebuild_settled"][:2], ("fail", "last_reasserting=on"))
        self.assertEqual(rows["netloss_log_session_rebuilt"][1], "count=0 seq=none")
        result, rows, calls, root = self.run_window(FAKE_PROVIDER_LOG=line % "path_change name:en0")
        self.assertEqual(rows["netloss_rebuild_settled"][:2], ("pass", "no_reassert"))
        result, rows, calls, root = self.run_window(FAKE_PROVIDER_LOG="")
        self.assertEqual(rows["netloss_rebuild_settled"][0], "unavailable")

    def test_the_address_phase_is_skipped_for_an_ipv4_relay_and_changes_nothing(self):
        # The provider watches only relay-family addresses: an IPv6-only
        # change could re-pin or rebuild nothing for an IPv4 relay.
        result, rows, calls, root = self.run_window(NETLOSS_ADDR="1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["netloss_addr_change"][:2], ("skip", "the relay is not IPv6: an IPv6-only change "
                                                           "leaves the relay family's egress addresses unchanged"))
        self.assertFalse([c for c in calls if "-setv6" in c or "-listnetworkserviceorder" in c], calls)
        self.assertFalse([n for n in rows if n.startswith("netloss_addr_") and n != "netloss_addr_change"], rows)
        self.assertEqual(rows["netloss_recovered"][0], "pass")

    def test_the_address_phase_turns_ipv6_off_and_back_to_automatic_and_counts_only(self):
        result, rows, calls, root = self.run_window(relay=f"[{RELAY6}]:443", NETLOSS_ADDR="1")
        out = root / "out"
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        v6off = calls.index("networksetup -setv6off Wi-Fi")
        v6on = calls.index("networksetup -setv6automatic Wi-Fi")
        self.assertLess(calls.index("networksetup -setairportpower en0 on"), v6off)
        self.assertLess(v6off, v6on)
        self.assertEqual(rows["netloss_addr_rollback_armed"][0], "pass")
        self.assertEqual(rows["netloss_addr_off"][:2], ("pass", "rc=0 state=Off"))
        self.assertEqual(rows["netloss_addr_restored"][:2], ("pass", "attempts=1 state=On"))
        self.assertEqual(rows["netloss_addr_rollback_ended"][1], "rollback_cancelled restored_verified")
        self.assertEqual(rows["netloss_addr_v6_count"][:2], ("info", "before=1 during=0 after=1"))
        self.assertEqual(rows["netloss_addr_recovered"][0], "pass")
        self.assertEqual(rows["netloss_addr_whoami_egress"][0], "pass")
        self.assertEqual(rows["netloss_addr_relay_path_exercised"][:2],
                         ("pass", "path_change=2 repinned=1 rebuilt=1"))
        self.assertEqual((root / "v6").read_text().strip(), "Automatic")
        for text in ((out / "results.tsv").read_text(), (out / "window.log").read_text()):
            self.assertNotIn(PHYS_V6, text)
        # v31 review: its `before` count was taken before the off row.
        fields = row_fields(out)
        assert_rows_chain(self, fields)
        times = row_times(fields)
        self.assertEqual(times["netloss_addr_v6_count"][0], times["netloss_addr_off"][0])

    def test_an_address_change_the_provider_never_saw_fails_its_exercised_row(self):
        line = "2026-10-23 06:00:00.000 Df PacketTunnel[42:1] aegis-ne %s\\n"
        cases = [(line % "reasserting off", "path_change=0 repinned=0 rebuilt=0"),
                 (line % "path_change name:en0", "path_change=1 repinned=0 rebuilt=0"),
                 (line % "relay_interface_repinned name:en0" + line % "session_rebuilt attempt:1",
                  "path_change=0 repinned=1 rebuilt=1")]
        for log, detail in cases:
            with self.subTest(detail=detail):
                result, rows, calls, root = self.run_window(relay=f"[{RELAY6}]:443", NETLOSS_ADDR="1",
                                                            FAKE_PROVIDER_LOG=log)
                self.assertEqual(rows["netloss_addr_relay_path_exercised"][0], "fail", rows)
                self.assertTrue(rows["netloss_addr_relay_path_exercised"][1].startswith(detail + ":"),
                                rows["netloss_addr_relay_path_exercised"])
                self.assertEqual(rows["netloss_addr_restored"][0], "pass")
        # A path change with only a rebuild is enough.
        result, rows, calls, root = self.run_window(
            relay=f"[{RELAY6}]:443", NETLOSS_ADDR="1",
            FAKE_PROVIDER_LOG=line % "path_change unsatisfied" + line % "session_rebuilt attempt:1")
        self.assertEqual(rows["netloss_addr_relay_path_exercised"][:2], ("pass", "path_change=1 repinned=0 rebuilt=1"))

    def test_the_address_service_is_the_one_enabled_wifi_service_of_the_device(self):
        root, env = self.setup_world()
        script = (f". '{NETLOSS_SH}'\nPHYS=en0 LEAK_CAPTURE=0 RELAY_IP='[{RELAY6}]' NETLOSS_ADDR=1\n"
                  "netloss_preflight || { echo \"refused $NL_REFUSAL\"; exit 3; }\n"
                  "echo \"service=<$NL_SERVICE> skip=<$NL_ADDR_SKIP>\"\n")
        cases = [
            # A disabled duplicate on en0 before the enabled one, after another device's service.
            ("(1) Thunderbolt Bridge\\n(Hardware Port: Thunderbolt Bridge, Device: bridge0)\\n\\n"
             "(*) Wi-Fi 2\\n(Hardware Port: Wi-Fi, Device: en0)\\n\\n(2) Wi-Fi\\n(Hardware Port: Wi-Fi, Device: en0)\\n\\n",
             "service=<Wi-Fi> skip=<>"),
            # The disabled entry first of all.
            ("(*) Old Wi-Fi\\n(Hardware Port: Wi-Fi, Device: en0)\\n\\n(1) Home Wi-Fi\\n(Hardware Port: Wi-Fi, Device: en0)\\n\\n",
             "service=<Home Wi-Fi> skip=<>"),
            ("(*) Old Wi-Fi\\n(Hardware Port: Wi-Fi, Device: en0)\\n\\n(1) USB LAN\\n(Hardware Port: USB LAN, Device: en7)\\n\\n",
             "service=<> skip=<0 enabled network services on en0, not exactly one>"),
            ("(1) Wi-Fi\\n(Hardware Port: Wi-Fi, Device: en0)\\n\\n(2) Wi-Fi 2\\n(Hardware Port: Wi-Fi, Device: en0)\\n\\n",
             "service=<> skip=<2 enabled network services on en0, not exactly one>"),
            ("(1) Odd\\n(Hardware Port: Ethernet, Device: en0)\\n\\n",
             "service=<Odd> skip=<service 'Odd' is on hardware port 'Ethernet', not Wi-Fi>"),
            # A device name that only ends like en0 is another device.
            ("(1) Other\\n(Hardware Port: Wi-Fi, Device: xen0)\\n\\n",
             "service=<> skip=<0 enabled network services on en0, not exactly one>"),
        ]
        for order, want in cases:
            with self.subTest(want=want):
                res = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True,
                                     env=dict(env, FAKE_SERVICE_ORDER=order), timeout=30)
                self.assertEqual(res.stdout.strip(), want, res.stderr)
        # An IPv4 relay is skipped before the service order is read.
        before = (root / "calls.log").read_text().splitlines()
        res = subprocess.run(["/bin/bash", "-c", script.replace(f"RELAY_IP='[{RELAY6}]'", f"RELAY_IP={RELAY_IP}")],
                             capture_output=True, text=True, env=env, timeout=30)
        self.assertIn("service=<> skip=<the relay is not IPv6", res.stdout, res.stderr)
        added = (root / "calls.log").read_text().splitlines()[len(before):]
        self.assertFalse([c for c in added if "-listnetworkserviceorder" in c], added)

    def test_an_address_change_that_needs_admin_is_unavailable_and_still_restored(self):
        result, rows, calls, root = self.run_window(relay=f"[{RELAY6}]:443", NETLOSS_ADDR="1", FAKE_V6_DENIED="1")
        self.assertEqual(rows["netloss_addr_off"][:2], ("unavailable", "rc=14 state=On"))
        self.assertIn("networksetup -setv6automatic Wi-Fi", calls)
        self.assertEqual(rows["netloss_addr_rollback_ended"][1], "rollback_cancelled restored_verified")
        self.assertNotIn("netloss_addr_recovered", rows)
        # IPv6 not Automatic beforehand: the phase is skipped, never forced.
        result, rows, calls, root = self.run_window(v6="Off", relay=f"[{RELAY6}]:443", NETLOSS_ADDR="1")
        self.assertEqual(rows["netloss_addr_change"][:2], ("skip", "IPv6 of 'Wi-Fi' is not Automatic"))
        self.assertFalse([c for c in calls if "-setv6" in c])
        self.assertEqual(rows["netloss_recovered"][0], "pass")


# ------------------------------------- S21i installed uninstall/reinstall

class DisarmWeakHostTests(unittest.TestCase):
    """pipeline.py disarm-weak-host on prepared copies (v26 review)."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="aegis-v26-disarm-")
        self.addCleanup(temp.cleanup)
        self.root = pathlib.Path(temp.name)

    def copy(self, version):
        return make_app(self.root / version, version)

    def test_only_hosts_with_the_filter_verbs_and_without_the_prompt_are_disarmed(self):
        # v30 review: v26 to v29 ask at a prompt that offers Touch ID.
        for version, weak in (("24", False), ("24.9", True), ("25", True), ("25.0.1", True),
                              ("25.99", True), ("26", True), ("27", True), ("29", True), ("29.99.1", True),
                              ("30", False), ("30.0.1", False), ("100", False), ("9", False)):
            with self.subTest(version=version):
                app = self.copy(version)
                host = app / "Contents" / "MacOS" / "aegis-ne-host"
                digest = sha256_file(host)
                result = pipeline("disarm-weak-host", "--app", app)
                self.assertEqual(result.returncode, 0, result.stderr)
                if weak:
                    self.assertEqual(result.stdout, f"weak_host=disarmed version={version} "
                                                    f"host_sha256={digest}\n")
                    self.assertFalse(host.exists())
                    note = (app / "Contents" / "MacOS" / "aegis-ne-host.removed").read_text()
                    self.assertTrue(note.endswith(f"\nsha256={digest}\n"), note)
                    again = pipeline("disarm-weak-host", "--app", app)
                    self.assertEqual(again.stdout, f"weak_host=disarmed-earlier version={version}\n")
                else:
                    self.assertEqual(result.stdout, f"weak_host=no version={version}\n")
                    self.assertEqual(sha256_file(host), digest)

    def test_an_unreadable_or_linked_copy_is_refused_and_left_alone(self):
        app = self.copy("25")
        host = app / "Contents" / "MacOS" / "aegis-ne-host"
        os.rename(host, self.root / "real-host")
        host.symlink_to(self.root / "real-host")
        result = pipeline("disarm-weak-host", "--app", app)
        self.assertEqual(result.returncode, 1)
        self.assertIn("is not a regular file", result.stderr)
        self.assertTrue((self.root / "real-host").is_file())
        bad = self.copy("31")
        (bad / "Contents" / "Info.plist").write_bytes(plistlib.dumps({"CFBundleVersion": "025"}))
        result = pipeline("disarm-weak-host", "--app", bad)
        self.assertEqual(result.returncode, 1)
        self.assertIn("unreadable CFBundleVersion", result.stderr)
        self.assertTrue((bad / "Contents" / "MacOS" / "aegis-ne-host").is_file())
        link = self.root / "link.app"
        link.symlink_to(bad)
        self.assertIn("not an app directory", pipeline("disarm-weak-host", "--app", link).stderr)

    def test_a_protected_copy_is_refused_with_the_remedy_and_left_unchanged(self):
        # v26 installed: App Management made the note write fail with EPERM
        # and the step died with a traceback. A read-only MacOS directory
        # stands in for that protection here.
        app = self.copy("25")
        macos = app / "Contents" / "MacOS"
        host = macos / "aegis-ne-host"
        digest = sha256_file(host)
        macos.chmod(0o555)
        self.addCleanup(macos.chmod, 0o755)
        result = pipeline("disarm-weak-host", "--app", app)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("refused: weak host of CFBundleVersion 25", result.stderr)
        self.assertIn("left unchanged", result.stderr)
        self.assertIn("to the Trash in Finder", result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(sha256_file(host), digest)
        self.assertFalse((macos / "aegis-ne-host.removed").exists())

    def test_the_bounds_match_the_packaging_scripts(self):
        text = PIPELINE.read_text()
        self.assertIn("FILTER_MIN_PRIOR = '24'\n", text)
        self.assertIn("WEAKEN_PROMPT_MIN = '26'\n", text)
        # v30 review: the first host with the password-only leak-guard right,
        # the same version as the identity gate's floor.
        self.assertIn("LEAK_GUARD_PASSWORD_MIN = '30'\n", text)
        self.assertIn("FILTER_MIN_PRIOR=24\n", UNINSTALL_SH.read_text())
        self.assertIn("IDENTITY_GATE_MIN=30 ", UNINSTALL_SH.read_text())
        self.assertIn("FILTER_MIN_PRIOR=24 WEAKEN_PROMPT_MIN=26 LEAK_GUARD_PASSWORD_MIN=30\n", INSTALL_SH.read_text())
        rust = (PACKAGE / "src" / "identity_authorization.rs").read_text()
        self.assertIn('FILTER_RIGHT: &CStr = c"dev.aegis.macos.leak-guard-change"', rust)
        self.assertNotIn("never asked for again", rust)


UNINSTALL_REINSTALL = PACKAGE / "harness" / "uninstall-reinstall-window.sh"
URW_SID = "1111AAAA-2222-3333-4444-555566667777"

URW_FAKE_HOST = r"""#!/bin/sh
echo "host $*" >> "$CALLS"
case "$1" in
  --list)
    if [ "$(cat "$WORLD/profile")" = present ]; then
      echo "profiles=1 native_acceptance=false"
      echo "profile index=0 owner_generation=0A1B2C3D-0000-4000-8000-000000000001 scutil_service_id=$URW_SID intent_valid=${FAKE_INTENT:-true} enabled=true on_demand_enabled=false native_vpn_status=1"
    else
      echo "profiles=0 native_acceptance=false"
    fi;;
  --ping)
    # The provider answers only while its extension is activated enabled.
    [ "$(cat "$WORLD/sysext")" = "activated enabled" ] || { echo "provider_unavailable" >&2; exit 69; }
    printf '{"schema":1,"verb":"ping","report":{"identity_present":%s,"container_open":{"admitted":true},"session_phase":"idle"}}\n' "$(cat "$WORLD/identity")";;
  --import)
    echo "administrator approval required for this identity change; answer the system prompt (at most 120s)" >&2
    [ "${FAKE_IMPORT:-ok}" = ok ] || { echo "import_result=refused manifest_match=false source=kept"; echo "provider_refused identity_import_refused" >&2; exit 65; }
    [ "${FAKE_IMPORT_TOUCHES_SOURCE:-0}" = 1 ] && echo changed >> "$2/bundle"
    echo true > "$WORLD/identity"
    echo "import_result=committed manifest_match=true committed_files=3 retired_removed=true remove_source=false source=kept";;
  --save-profile)
    echo present > "$WORLD/profile"
    echo "owner_generation=0A1B2C3D-0000-4000-8000-000000000002 saved=true profile_sha256=ab native_vpn_status=1 native_acceptance=false";;
  --filter-status)
    case "$(cat "$WORLD/filter" 2>/dev/null)" in
      enabled) echo "filter_result=ok exit_code=0 configured=true enabled=true attached=true pid_match=true"; exit 0;;
      unattached) echo "filter_result=not_attached exit_code=33 configured=true enabled=true attached=false"; exit 33;;
      attaching) n=$(cat "$WORLD/attach-reads" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$WORLD/attach-reads"
        if [ "$n" -gt "${FAKE_ATTACH_AFTER_READS:-0}" ]; then echo enabled > "$WORLD/filter"
          echo "filter_result=ok exit_code=0 configured=true enabled=true attached=true pid_match=true"; exit 0; fi
        echo "filter_result=not_attached exit_code=33 configured=true enabled=true attached=false"; exit 33;;
      disabled) echo "filter_result=disabled exit_code=31 configured=true enabled=false"; exit 31;;
      *) echo "filter_result=not_configured exit_code=30 configured=false enabled=false attached=unknown"; exit 30;;
    esac;;
  --enable-filter)
    [ "${FAKE_ENABLE_FILTER:-ok}" = ok ] || { echo "filter_result=permission_denied exit_code=35 configured=false"; exit 35; }
    # FAKE_ATTACH_AFTER_READS=n: enabled at once, attached only after n
    # status reads (the v30 installed run attached seconds after the enable).
    if [ -n "${FAKE_ATTACH_AFTER_READS:-}" ]; then echo attaching > "$WORLD/filter"; else echo enabled > "$WORLD/filter"; fi
    echo "filter_result=ok exit_code=0 configured=true enabled=true";;
  *) exit 2;;
esac
"""

URW_FAKE_UNINSTALL = r"""
import datetime, json, os, pathlib, shutil, sys
args = sys.argv[1:]
opt = {args[i]: args[i + 1] for i in range(0, len(args) - 1, 2) if args[i].startswith("--")}
world = pathlib.Path(os.environ["WORLD"])
open(os.environ["CALLS"], "a").write("uninstall " + " ".join(args) + "\n")
app = pathlib.Path(opt["--dest"]) / "AEGIS.app"
state = pathlib.Path(opt["--state-dir"])
receipts = pathlib.Path(opt["--artifacts-dir"]) / "uninstall" / "receipts"
receipts.mkdir(parents=True, exist_ok=True)
stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
receipt = {"schema": 1, "kind": "uninstall"}
mode = os.environ.get("FAKE_UNINSTALL", "ok")
def done(code):
    (receipts / f"uninstall-{stamp}.json").write_text(json.dumps(receipt))
    sys.exit(code)
uninstalled = state / "uninstalled"
if not app.exists():
    copies = sorted(uninstalled.glob("AEGIS.app.uninstalled-*")) if uninstalled.exists() else []
    receipt.update(uninstall_result="already-absent", latest_uninstalled_copy=str(copies[-1]) if copies else "")
    done(0)
if mode == "fail":
    receipt.update(uninstall_result="failed-at-forget-identity")
    done(1)
marker = state / "uninstall" / "deactivated.txt"
provider_gone = (world / "sysext").read_text().strip() != "activated enabled"
(world / "profile").write_text("absent\n")
(world / "filter").write_text("absent\n")  # remove-filter, verified absent
receipt["remove_profile_line"] = "profiles_found=1 profiles_removed=1 removal_failed=0 profiles_remaining=0"
if marker.exists() and provider_gone:
    receipt.update(identity_absence="verified-earlier", deactivation_outcome="done-earlier")
    open(os.environ["CALLS"], "a").write("uninstall resumed from deactivated.txt\n")
elif provider_gone:
    receipt.update(uninstall_result="failed-at-forget-identity")  # exit 69 without a marker
    done(1)
elif os.environ.get("FAKE_KEEP_IDENTITY") != "1":
    (world / "identity").write_text("false\n")
    receipt.update(identity_absence="verified", ping_identity="identity_present=false container_admitted=true")
else:
    receipt.update(identity_absence="verified", ping_identity="identity_present=true container_admitted=true")
if mode == "pending-reboot":
    receipt.update(uninstall_result="pending-reboot", deactivation_outcome="will-complete-after-reboot",
                   deactivation_result="deactivation_result=will_complete_after_reboot")
    (world / "sysext").write_text("activated waiting for user\n")
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("host_cdhash=aa\nprovider_cdhash=bb\nbundle_version=23\noutcome=will-complete-after-reboot\n")
    done(1)
receipt.setdefault("deactivation_outcome", "completed")
(world / "sysext").write_text(os.environ.get("FAKE_SYSEXT_AFTER", "terminated waiting to uninstall on reboot") + "\n")
(world / "sysext_list").write_text(os.environ.get("FAKE_SYSEXT_LIST_AFTER", "") + "\n")
if os.environ.get("FAKE_UTUN_LEFT") == "1":
    (world / "utun").write_text("1\n")
if os.environ.get("FAKE_UTUN_ADDR_LEFT") == "1":
    (world / "utun_addr").write_text("1\n")  # the address without the route
version = (app / "Contents" / "version").read_text().strip()
uninstalled.mkdir(parents=True, exist_ok=True)
backup = uninstalled / f"AEGIS.app.uninstalled-{version}-{stamp}"
n = 1
while backup.exists():
    backup = uninstalled / f"AEGIS.app.uninstalled-{version}-{stamp}.{n}"; n += 1
if os.environ.get("FAKE_UNINSTALL_DELETES") == "1":
    shutil.rmtree(app)  # the defect the window must catch
else:
    os.rename(app, backup)
if marker.exists():
    os.rename(marker, marker.with_name(f"deactivated-consumed-{stamp}.txt"))
receipt.update(uninstall_result="uninstalled", uninstalled_app_path=str(backup))
done(0)
"""

URW_FAKE_INSTALL = r"""
import hashlib, os, pathlib, shutil, sys
args = sys.argv[1:]
open(os.environ["CALLS"], "a").write("install " + " ".join(args) + "\n")
world = pathlib.Path(os.environ["WORLD"])
opt = {args[i]: args[i + 1] for i in range(len(args) - 1) if args[i] in ("--stapled-zip", "--approve-sha256", "--dest", "--state-dir")}
PENDING = {"pending-approval": "activation_result=timeout_awaiting_approval exit_code=14 will_complete_after_reboot=false",
           "pending-reboot": "activation_result=will_complete_after_reboot exit_code=10 will_complete_after_reboot=true",
           "activation-failed": "activation_result=failed exit_code=11 will_complete_after_reboot=false"}
def activate(mode):
    if mode in PENDING:
        (world / "sysext").write_text("activated waiting for user\n")
        print(PENDING[mode])
        print("install-app: activation did not complete", file=sys.stderr)
        sys.exit(1)
    (world / "sysext").write_text("activated enabled\n")
    (world / "sysext_list").write_text("\n")
    print("activation_result=completed exit_code=0 will_complete_after_reboot=false")
    sys.exit(0)
if "--activate-installed" in args:
    if not (pathlib.Path(opt["--dest"]) / "AEGIS.app").is_dir() or "--receipt" not in args:
        sys.exit(1)
    activate(os.environ.get("FAKE_ACTIVATE_INSTALLED", "ok"))
if os.environ.get("FAKE_INSTALL") == "fail":
    print("activation_result=failed"); sys.exit(1)
digest = hashlib.sha256(pathlib.Path(opt["--stapled-zip"]).read_bytes()).hexdigest()
if digest != opt["--approve-sha256"]:
    print("approved SHA-256 does not match", file=sys.stderr); sys.exit(1)
target = pathlib.Path(opt["--dest"]) / "AEGIS.app"
if target.exists():
    if "--replace" not in args:
        sys.exit(1)
    backups = pathlib.Path(opt["--state-dir"]) / "backups"
    backups.mkdir(parents=True, exist_ok=True)
    os.rename(target, backups / f"AEGIS.app.replaced-{len(list(backups.iterdir()))}")
shutil.copytree(os.environ["FAKE_APP_TEMPLATE"], target, symlinks=True)
lock = pathlib.Path(os.environ["HOME"]) / ".aegis-local" / "locks" / "timing-self"
(world / "lock_seen").write_text(lock.read_text() if lock.exists() else "absent\n")
if "--activate" in args:
    activate(os.environ.get("FAKE_INSTALL", "ok"))
"""

URW_FAKE_COMMANDS = {
    "systemextensionsctl": r"""#!/bin/sh
echo "systemextensionsctl $*" >> "$CALLS"
[ "$1" = list ] || exit 1
case "$(cat "$WORLD/sysext_list" 2>/dev/null)" in
  fail) echo "systemextensionsctl: XPC error" >&2; exit 1;;
  empty) exit 0;;
  noheader) printf 'enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n'; exit 0;;
esac
printf '1 extension(s)\n--- com.apple.system_extension.network_extension\nenabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n'
s=$(cat "$WORLD/sysext")
[ "$s" = none ] || printf '*\t*\tTEAMID0000\tdev.aegis.macos.PacketTunnel (1.0/23)\tAEGIS PacketTunnel\t[%s]\n' "$s"
""",
    "scutil": r"""#!/bin/sh
case "$1 $2" in
  "--nc list")
    echo "Available network connection services in the current set (*=enabled):"
    [ "${FAKE_NC_LIST_HIDES:-0}" = 1 ] && exit 0
    [ "$(cat "$WORLD/profile")" = present ] && printf '* (%s)   %s VPN (dev.aegis.macos) "AEGIS"  [VPN/dev.aegis.macos]\n' "$(cat "$WORLD/tunnel")" "$URW_SID";;
  "--nc status") cat "$WORLD/tunnel";;
  "--dns ") printf 'DNS configuration\n\nresolver #1\n  nameserver[0] : %s\n' "$([ "$(cat "$WORLD/tunnel")" = Connected ] && echo 198.19.255.2 || echo 192.168.1.1)";;
esac
""",
    "route": r"""#!/bin/sh
if [ "$(cat "$WORLD/tunnel")" = Connected ] || [ -s "$WORLD/utun" ]; then echo "  interface: utun9"; else echo "  interface: en0"; fi
""",
    "ifconfig": r"""#!/bin/sh
printf 'en0: flags=8863<UP> mtu 1500\n\tinet 192.168.1.50 netmask 0xffffff00 broadcast 192.168.1.255\n'
if [ "$(cat "$WORLD/tunnel")" = Connected ] || [ -s "$WORLD/utun" ] || [ -s "$WORLD/utun_addr" ]; then
  printf 'utun9: flags=8051<UP> mtu 1400\n\tinet 198.19.255.1 --> 198.19.255.1 netmask 0xffffffff\n\tinet6 fd00:ae61::1 prefixlen 120\n'
fi
""",
}


class UninstallReinstallWindowTests(unittest.TestCase):
    """harness/uninstall-reinstall-window.sh against fake packaging scripts,
    a fake host inside a fake AEGIS.app, fake systemextensionsctl, scutil,
    route and ifconfig, and a temporary HOME. Nothing here touches the
    installed app, an extension or a real identity."""

    def setup_world(self, zip_version="23", receipt=None, **world):
        temp = tempfile.TemporaryDirectory(prefix="aegis-s21i-urw-")
        self.addCleanup(temp.cleanup)
        root = pathlib.Path(temp.name)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        for name, body in URW_FAKE_COMMANDS.items():
            (bin_dir / name).write_text(body)
            (bin_dir / name).chmod(0o755)
        template = root / "template" / "AEGIS.app"
        (template / "Contents" / "MacOS").mkdir(parents=True)
        with open(template / "Contents" / "Info.plist", "wb") as f:
            plistlib.dump({"CFBundleIdentifier": APP, "CFBundleVersion": "23"}, f)
        (template / "Contents" / "version").write_text("23\n")
        host = template / "Contents" / "MacOS" / "aegis-ne-host"
        host.write_text(URW_FAKE_HOST)
        host.chmod(0o755)
        dest = root / "Applications"
        dest.mkdir()
        subprocess.run(["/bin/cp", "-Rp", str(template), str(dest / "AEGIS.app")], check=True)
        packaging = root / "packaging"
        packaging.mkdir()
        for name, body in (("uninstall", URW_FAKE_UNINSTALL), ("install", URW_FAKE_INSTALL)):
            (packaging / f"fake_{name}.py").write_text(body)
            (packaging / f"{name}-app.sh").write_text(
                f"#!/bin/bash\nexec python3 -I '{packaging}/fake_{name}.py' \"$@\"\n")
        zip_path = root / "AEGIS-23-stapled.zip"
        with zipfile.ZipFile(zip_path, "w") as archive:
            archive.writestr("AEGIS.app/Contents/Info.plist",
                             plistlib.dumps({"CFBundleIdentifier": APP, "CFBundleVersion": zip_version}))
            archive.writestr("AEGIS.app/Contents/MacOS/aegis-ne-host", "fake")
        install_receipt = root / "receipts" / "run-23.json"
        install_receipt.parent.mkdir()
        install_receipt.write_text(json.dumps({
            "schema": 1, "stapled_zip_sha256": sha256_file(zip_path), "bundle_version": zip_version,
            "stages": [{"stage": "staple", "status": "ok"}, {"stage": "assess", "status": "ok"},
                       {"stage": "install", "status": "ok"}], **(receipt or {})}))
        source = root / "identity-src"
        source.mkdir(mode=0o700)
        source.chmod(0o700)
        for name, data in (("bundle", "fake-bundle"), ("enrollment.json", "{}"), ("note", "x")):
            (source / name).write_text(data)
        world_dir = root / "world"
        world_dir.mkdir()
        for name, value in {"sysext": "activated enabled", "profile": "present", "identity": "true",
                            "tunnel": "Disconnected", **world}.items():
            (world_dir / name).write_text(value + "\n")
        (root / "calls.log").write_text("")
        (root / "home" / ".aegis-local" / "locks").mkdir(parents=True)
        env = {"PATH": f"{bin_dir}:/usr/bin:/bin:/usr/sbin", "HOME": str(root / "home"),
               "APP": str(dest / "AEGIS.app"), "ZIP": str(zip_path), "ZIP_SHA256": sha256_file(zip_path),
               "IDENTITY_SRC": str(source), "RELAY_IP": "203.0.113.7", "WORLD": str(world_dir),
               "CALLS": str(root / "calls.log"), "URW_SID": URW_SID, "FAKE_APP_TEMPLATE": str(template),
               "UNINSTALL_SH": str(packaging / "uninstall-app.sh"), "INSTALL_SH": str(packaging / "install-app.sh"),
               "INSTALL_RECEIPT": str(install_receipt)}
        return root, env

    def run_cycle(self, root, env, out="out", **extra):
        env = dict(env, OUT=str(root / out), **extra)
        result = subprocess.run(["/bin/bash", str(UNINSTALL_REINSTALL)], capture_output=True, text=True,
                                env=env, timeout=120)
        rows = {}
        if (root / out / "results.tsv").exists():
            for line in (root / out / "results.tsv").read_text().splitlines():
                name, verdict, detail, utc = line.split("\t")
                rows[name] = (verdict, detail)
        return result, rows

    @staticmethod
    def calls(root):
        return (root / "calls.log").read_text().splitlines()

    @staticmethod
    def contents(root):
        """Every file's bytes outside the run's own outputs and fake state."""
        found = {}
        for path in root.rglob("*"):
            rel = path.relative_to(root)
            if rel.parts[0] in ("world", "home", "calls.log") or rel.parts[0].startswith("out") or not path.is_file():
                continue
            found.setdefault(hashlib.sha256(path.read_bytes()).hexdigest(), []).append(str(rel))
        return found

    def assert_nothing_deleted(self, before, root):
        after = self.contents(root)
        lost = {digest: paths for digest, paths in before.items() if digest not in after}
        self.assertEqual(lost, {})

    def test_a_clean_cycle_uninstalls_reinstalls_and_restores_identity_and_profile(self):
        root, env = self.setup_world()
        before = self.contents(root)
        source_before = {p.name: p.read_bytes() for p in (root / "identity-src").iterdir()}
        result, rows = self.run_cycle(root, env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = [c for c in self.calls(root) if not c.startswith("systemextensionsctl")]
        dest, state = root / "Applications", root / "home" / "Library" / "Application Support" / "aegis-packaging" / "install"
        artifacts = root / "out" / "packaging-artifacts"
        self.assertEqual(calls, [
            "host --list", "host --ping", "host --filter-status",
            f"uninstall --dest {dest} --state-dir {state} --artifacts-dir {artifacts}",
            f"install --stapled-zip {env['ZIP']} --approve-sha256 {env['ZIP_SHA256']} --dest {dest} "
            f"--state-dir {state} --replace --activate --receipt {env['INSTALL_RECEIPT']}",
            f"host --import {env['IDENTITY_SRC']}",
            "host --save-profile dev.aegis.macos.PacketTunnel 203.0.113.7 --replace-existing",
            "host --list", "host --ping"])
        order = ["preflight", "baseline_app", "baseline_extension", "baseline_profile", "baseline_identity",
                 "baseline_filter", "baseline_network", "uninstall", "app_moved", "profile_gone", "identity_absent",
                 "extension_deactivated", "no_tunnel_left", "network_baseline", "install", "reinstalled_version",
                 "extension_activated", "identity_import", "identity_source_kept", "profile_saved",
                 "intent_valid", "identity_present", "filter_restored", "network_after_reinstall", "outcome"]
        self.assertEqual(list(rows), order)
        for name in order:
            self.assertIn(rows[name][0], ("pass", "info"), (name, rows[name]))
        self.assertEqual(rows["outcome"][0], "pass")
        self.assertIn("version=23 mode=cycle ", rows["preflight"][1])
        self.assertEqual(rows["reinstalled_version"], ("pass", "installed=23 zip=23 before=23"))
        marker = state / "uninstall-reinstall-window" / "reinstall.txt"
        self.assertTrue(marker.read_text().startswith("phase=completed\n"), marker.read_text())
        self.assertEqual(rows["baseline_app"][1], "present=true version=23")
        self.assertEqual(rows["baseline_extension"][1], "[activated enabled]")
        self.assertIn(f"sid={URW_SID} intent_valid=true", rows["baseline_profile"][1])
        self.assertEqual(rows["baseline_identity"][1], "rc=0 identity_present=true container_admitted=true")
        self.assertIn("states=[terminated waiting to uninstall on reboot]", rows["extension_deactivated"][1])
        self.assertEqual(rows["extension_activated"][1], "states=[activated enabled]")
        self.assertEqual(rows["identity_present"][1], "rc=0 identity_present=true container_admitted=true")
        self.assertEqual(rows["identity_source_kept"][1], "files=3 unchanged=true")
        backups = sorted((state / "uninstalled").iterdir())
        self.assertEqual(len(backups), 1)
        self.assertIn(f"backup={backups[0]}", rows["app_moved"][1])
        self.assertTrue((backups[0] / "Contents" / "MacOS" / "aegis-ne-host").is_file())
        self.assertTrue((dest / "AEGIS.app" / "Contents" / "MacOS" / "aegis-ne-host").is_file())
        self.assertEqual({p.name: p.read_bytes() for p in (root / "identity-src").iterdir()}, source_before)
        self.assert_nothing_deleted(before, root)
        self.assertFalse((root / "home" / ".aegis-local" / "locks" / "timing-self").exists())
        self.assertRegex((root / "world" / "lock_seen").read_text(),
                         r"^start=[0-9]{8}T[0-9]{6}Z purpose=b06-uninstall-reinstall-window\ntoken=[0-9A-F-]{36}\n$")
        for text in ((root / "out" / "results.tsv").read_text(), (root / "out" / "window.log").read_text()):
            self.assertNotIn("fake-bundle", text)
        self.assertEqual(oct((root / "out").stat().st_mode & 0o777), "0o700")

    def test_a_leak_guard_filter_enabled_at_the_baseline_is_restored_or_the_cycle_fails(self):
        # v26 review: uninstall-app.sh removes the filter; the cycle puts
        # back what the owner had, and never passes without it.
        for filter_state in ("enabled", "unattached"):
            with self.subTest(filter=filter_state):
                root, env = self.setup_world(filter=filter_state)
                result, rows = self.run_cycle(root, env)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                calls = [c for c in self.calls(root) if not c.startswith("systemextensionsctl")]
                self.assertEqual(calls[-4:], ["host --list", "host --ping", "host --enable-filter",
                                              "host --filter-status"])
                self.assertTrue(rows["baseline_filter"][1].startswith(
                    f"rc={0 if filter_state == 'enabled' else 33} restore=true source=baseline "), rows)
                self.assertEqual(rows["filter_enable"][0], "pass")
                self.assertEqual(rows["filter_restored"][0], "pass")
                self.assertIn("rc=0 source=baseline filter_result=ok", rows["filter_restored"][1])
                self.assertEqual(rows["outcome"], ("pass", "uninstalled, reinstalled, identity, profile "
                                                           "and leak-guard filter restored"))
                state = root / "home" / "Library" / "Application Support" / "aegis-packaging" / "install"
                marker = state / "uninstall-reinstall-window" / "filter.txt"
                self.assertTrue(marker.read_text().startswith("phase=restored\n"))
        # Not enabled at the baseline: nothing enabled, an info row.
        for filter_state in ("absent", "disabled"):
            with self.subTest(filter=filter_state):
                root, env = self.setup_world(filter=filter_state)
                result, rows = self.run_cycle(root, env)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse([c for c in self.calls(root) if c == "host --enable-filter"])
                self.assertEqual(rows["filter_restored"][0], "info")
                self.assertNotIn("filter_enable", rows)
                self.assertEqual(rows["outcome"], ("pass", "uninstalled, reinstalled, identity and profile restored"))
        # v30 installed run: the filter attached a few seconds after the
        # enable. A not_attached answer is read again; attached later passes.
        root, env = self.setup_world(filter="enabled")
        result, rows = self.run_cycle(root, env, FAKE_ATTACH_AFTER_READS="2")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["filter_restored"][0], "pass", rows["filter_restored"])
        self.assertIn("rc=0 source=baseline filter_result=ok", rows["filter_restored"][1])
        self.assertIn(" waited=4s", rows["filter_restored"][1])
        # Never attached within the bound: still a fail, after the bound.
        root, env = self.setup_world(filter="enabled")
        result, rows = self.run_cycle(root, env, FAKE_ATTACH_AFTER_READS="99", FILTER_ATTACH_WAIT_S="4")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(rows["filter_restored"][0], "fail")
        self.assertIn("rc=33 ", rows["filter_restored"][1])
        self.assertIn(" waited=4s", rows["filter_restored"][1])
        # The Allow is not given: the cycle fails and says so.
        root, env = self.setup_world(filter="enabled")
        result, rows = self.run_cycle(root, env, FAKE_ENABLE_FILTER="denied")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(rows["filter_enable"][0], "fail")
        self.assertEqual(rows["filter_restored"][0], "fail")
        self.assertIn("rc=30 ", rows["filter_restored"][1])
        self.assertEqual(rows["outcome"], ("fail", "a reinstall check failed"))
        # A re-run (the uninstall already removed the filter) still restores
        # it from the record taken before that uninstall.
        result, rows = self.run_cycle(root, env, out="out2")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(rows["baseline_filter"][1].startswith("rc=30 restore=true source=earlier-run "),
                        rows["baseline_filter"])
        self.assertEqual(rows["filter_restored"][0], "pass")
        self.assertEqual(rows["outcome"][0], "pass")
        # Once restored, the record no longer forces a restore.
        (root / "world" / "filter").write_text("absent\n")
        result, rows = self.run_cycle(root, env, out="out3")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["filter_restored"][0], "info")

    def test_a_rerun_after_a_completed_cycle_or_an_interrupted_one_is_safe(self):
        root, env = self.setup_world()
        result, rows = self.run_cycle(root, env, out="out1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        before = self.contents(root)
        result, rows = self.run_cycle(root, env, out="out2")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        state = root / "home" / "Library" / "Application Support" / "aegis-packaging" / "install"
        self.assertEqual(len(list((state / "uninstalled").iterdir())), 2)
        self.assert_nothing_deleted(before, root)
        # Interrupted after the uninstall: the app is already absent.
        os.rename(root / "Applications" / "AEGIS.app", state / "uninstalled" / "AEGIS.app.uninstalled-23-20261023T000000Z")
        for name, value in (("profile", "absent"), ("identity", "false"), ("sysext", "none")):
            (root / "world" / name).write_text(value + "\n")
        before = self.contents(root)
        result, rows = self.run_cycle(root, env, out="out3")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["baseline_app"], ("info", "present=false version=none"))
        self.assertIn("result=already-absent", rows["uninstall"][1])
        self.assertEqual(rows["app_moved"][0], "pass", rows["app_moved"])
        self.assertEqual(rows["profile_gone"][0], "info")
        self.assertEqual(rows["reinstalled_version"], ("pass", "installed=23 zip=23 before=23"))
        self.assertEqual(rows["outcome"][0], "pass")
        self.assert_nothing_deleted(before, root)
        # An existing OUT is never reused.
        result, rows = self.run_cycle(root, env, out="out3")
        self.assertEqual(result.returncode, 2)
        self.assertFalse([c for c in self.calls(root)[-3:] if c.startswith("uninstall")])

    def test_refusals_run_nothing_and_change_nothing(self):
        locks = None
        cases = [
            ({"lock": "timing-peer"}, 4, "timing-peer lock held"),
            ({"lock": "timing-self"}, 3, "timing-self lock held"),
            ({"world": {"tunnel": "Connected"}}, 3, "1 AEGIS service(s) not Disconnected"),
            ({"world": {"tunnel": "Connecting"}}, 3, "1 AEGIS service(s) not Disconnected"),
            ({"world": {"tunnel": "Connected"}, "env": {"FAKE_NC_LIST_HIDES": "1"}}, 3,
             f"service {URW_SID} is Connected, not Disconnected"),
            ({"world": {"utun": "1"}}, 3, "an interface holds the tunnel address"),
            ({"env": {"ZIP_SHA256": "0" * 64}}, 3, "ZIP_SHA256 does not match the stapled ZIP"),
            ({"env": {"ZIP": "relative.zip"}}, 3, "ZIP must be an absolute stapled ZIP path"),
            ({"env": {"RELAY_IP": "relay.example"}}, 3, "no numeric relay IP"),
            ({"mode": 0o755}, 3, "identity source must be 0700"),
            ({"env": {"IDENTITY_SRC": "/nonexistent/aegis-src"}}, 3, "identity source is not a directory"),
            ({"env": {"INSTALL_RECEIPT": ""}}, 3, "INSTALL_RECEIPT must be the absolute run receipt"),
            ({"env": {"INSTALL_RECEIPT": "receipts/run-23.json"}}, 3, "INSTALL_RECEIPT must be the absolute run receipt"),
            ({"env": {"INSTALL_RECEIPT": "/nonexistent/run.json"}}, 3, "install receipt not found"),
            ({"receipt": {"stapled_zip_sha256": "1" * 64}}, 3, "install receipt belongs to a different stapled ZIP"),
            ({"receipt": {"stages": [{"stage": "staple", "status": "failed"}, {"stage": "assess", "status": "ok"}]}},
             3, "install receipt stage staple is not current ok"),
            ({"receipt": {"stages": [{"stage": "staple", "status": "ok"}, {"stage": "assess", "status": "ok"},
                                     {"stage": "notarize", "status": "ok"}]}},
             3, "install receipt stage staple is not current ok"),
            ({"receipt": {"stages": [{"stage": "staple", "status": "ok"}]}}, 3, "install receipt stage assess is not current ok"),
            ({"receipt": {"bundle_version": "22"}}, 3, "install receipt bundle_version differs from the ZIP's 23"),
            ({"zip_version": "24"}, 3, "installed AEGIS.app is 23, the stapled ZIP is 24"),
            ({"incoming": True}, 3, "stale"),
            ({"world": {"sysext": "activated waiting for user"}}, 3,
             "installed AEGIS.app 23: host --ping exit 69 (malformed), no uninstall-app.sh resume marker"),
            ({"world": {"identity": "false"}}, 3,
             "installed AEGIS.app 23: host --ping exit 0 (identity_present=false container_admitted=true)"),
            ({"world": {"sysext": "none"}, "marker": "bundle_version=22\n"}, 3, "installed AEGIS.app 23: host --ping exit 69"),
        ]
        for case, code, reason in cases:
            with self.subTest(reason=reason):
                root, env = self.setup_world(zip_version=case.get("zip_version", "23"), receipt=case.get("receipt"),
                                             **case.get("world", {}))
                env.update(case.get("env", {}))
                if case.get("incoming"):
                    (root / "Applications" / ".AEGIS.app.incoming-23").mkdir()
                if "marker" in case:
                    marker = (root / "home" / "Library" / "Application Support" / "aegis-packaging" / "install"
                              / "uninstall" / "deactivated.txt")
                    marker.parent.mkdir(parents=True)
                    marker.write_text(case["marker"])
                if "mode" in case:
                    (root / "identity-src").chmod(case["mode"])
                locks = root / "home" / ".aegis-local" / "locks"
                if "lock" in case:
                    (locks / case["lock"]).write_text("start=x purpose=other\n")
                before = self.contents(root)
                result, rows = self.run_cycle(root, env)
                self.assertEqual(result.returncode, code, result.stdout + result.stderr)
                self.assertIn(f"refused: {reason}", result.stdout)
                calls = self.calls(root)
                self.assertFalse([c for c in calls if c.split()[0] in ("uninstall", "install")
                                  or c.startswith(("host --import", "host --save"))], calls)
                self.assertEqual([r[0] for r in rows.values()], ["refused"])
                self.assertTrue((root / "Applications" / "AEGIS.app" / "Contents" / "MacOS" / "aegis-ne-host").is_file())
                self.assertEqual((root / "world" / "profile").read_text(), "present\n")
                self.assert_nothing_deleted(before, root)
                if "lock" in case:
                    self.assertEqual((locks / case["lock"]).read_text(), "start=x purpose=other\n")
                else:
                    self.assertFalse((locks / "timing-self").exists())

    def test_a_deactivation_pending_reboot_stops_before_the_reinstall_and_a_rerun_completes(self):
        root, env = self.setup_world()
        result, rows = self.run_cycle(root, env, FAKE_UNINSTALL="pending-reboot")
        self.assertEqual(result.returncode, 7, result.stdout + result.stderr)
        self.assertEqual(rows["extension_deactivated"][0], "pending-reboot")
        self.assertEqual(rows["outcome"][0], "pending_reboot")
        self.assertFalse([c for c in self.calls(root) if c.startswith(("install", "host --import"))])
        self.assertTrue((root / "Applications" / "AEGIS.app").is_dir())
        self.assertFalse((root / "home" / ".aegis-local" / "locks" / "timing-self").exists())
        # After the reboot the provider is gone; the same command, with a new
        # OUT, resumes from uninstall-app.sh's marker and completes.
        (root / "world" / "sysext").write_text("none\n")
        result, rows = self.run_cycle(root, env, out="out-after-reboot")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["outcome"][0], "pass")
        self.assertIn("uninstall resumed from deactivated.txt", self.calls(root))
        self.assertEqual(rows["baseline_identity"][1], "rc=69 malformed")
        self.assertIn("identity_absence=verified-earlier", rows["identity_absent"][1])

    def test_each_failed_uninstall_check_stops_before_the_reinstall(self):
        cases = [
            ({"FAKE_UNINSTALL_DELETES": "1"}, "app_moved"),
            ({"FAKE_KEEP_IDENTITY": "1"}, "identity_absent"),
            ({"FAKE_SYSEXT_AFTER": "activated enabled"}, "extension_deactivated"),
            ({"FAKE_SYSEXT_AFTER": "activated waiting for user"}, "extension_deactivated"),
            ({"FAKE_SYSEXT_AFTER": "activated disabled"}, "extension_deactivated"),
            ({"FAKE_SYSEXT_AFTER": "none", "FAKE_SYSEXT_LIST_AFTER": "fail"}, "extension_deactivated"),
            ({"FAKE_SYSEXT_AFTER": "none", "FAKE_SYSEXT_LIST_AFTER": "empty"}, "extension_deactivated"),
            ({"FAKE_SYSEXT_AFTER": "none", "FAKE_SYSEXT_LIST_AFTER": "noheader"}, "extension_deactivated"),
            ({"FAKE_UTUN_LEFT": "1"}, "no_tunnel_left"),
            ({"FAKE_UTUN_ADDR_LEFT": "1"}, "no_tunnel_left"),
            ({"FAKE_UNINSTALL": "fail"}, "uninstall"),
        ]
        for extra, row in cases:
            with self.subTest(row=row):
                root, env = self.setup_world()
                result, rows = self.run_cycle(root, env, **extra)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual(rows[row][0], "fail", rows)
                self.assertEqual(rows["outcome"][0], "fail")
                self.assertFalse([c for c in self.calls(root) if c.startswith(("install", "host --import"))])
        root, env = self.setup_world()
        result, rows = self.run_cycle(root, env, FAKE_UTUN_LEFT="1")
        self.assertEqual(rows["network_baseline"][0], "fail")
        # An unreadable listing is named, never read as no extension; a valid
        # listing without the provider passes.
        root, env = self.setup_world()
        result, rows = self.run_cycle(root, env, FAKE_SYSEXT_AFTER="none", FAKE_SYSEXT_LIST_AFTER="fail")
        self.assertEqual(rows["extension_deactivated"], ("fail", "outcome=completed states=unreadable rc=1"))
        root, env = self.setup_world()
        result, rows = self.run_cycle(root, env, FAKE_SYSEXT_AFTER="none")
        self.assertEqual(rows["extension_deactivated"], ("pass", "outcome=completed states=none"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # A failed uninstall-app.sh stops at once: no later check runs on its leftovers.
        root, env = self.setup_world()
        result, rows = self.run_cycle(root, env, FAKE_UNINSTALL="fail")
        self.assertEqual(list(rows)[-2:], ["uninstall", "outcome"])
        self.assertEqual(rows["outcome"], ("fail", "uninstall-app.sh failed; nothing was reinstalled"))

    def test_each_failed_reinstall_check_fails_the_outcome(self):
        cases = [
            ({"FAKE_INSTALL": "fail"}, "install"),
            ({"FAKE_IMPORT": "refused"}, "identity_import"),
            ({"FAKE_IMPORT_TOUCHES_SOURCE": "1"}, "identity_source_kept"),
            ({"FAKE_INTENT": "false"}, "intent_valid"),
        ]
        for extra, row in cases:
            with self.subTest(row=row):
                root, env = self.setup_world()
                result, rows = self.run_cycle(root, env, **extra)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual(rows[row][0], "fail", rows)
                self.assertEqual(rows["outcome"][0], "fail")
                self.assertTrue((root / "identity-src").is_dir())
        root, env = self.setup_world()
        result, rows = self.run_cycle(root, env, FAKE_IMPORT="refused")
        self.assertEqual(rows["identity_present"][0], "fail")
        # A failed install-app.sh stops at once: no import or profile follows.
        root, env = self.setup_world()
        result, rows = self.run_cycle(root, env, FAKE_INSTALL="fail")
        self.assertEqual(list(rows)[-2:], ["install", "outcome"])
        self.assertFalse([c for c in self.calls(root) if c.startswith(("host --import", "host --save"))])

    def test_a_pending_activation_exits_8_and_a_rerun_resumes_without_uninstalling_again(self):
        root, env = self.setup_world()
        state = root / "home" / "Library" / "Application Support" / "aegis-packaging" / "install"
        marker = state / "uninstall-reinstall-window" / "reinstall.txt"
        for mode in ("pending-approval", "pending-reboot"):
            with self.subTest(mode=mode):
                root, env = self.setup_world()
                state = root / "home" / "Library" / "Application Support" / "aegis-packaging" / "install"
                marker = state / "uninstall-reinstall-window" / "reinstall.txt"
                result, rows = self.run_cycle(root, env, FAKE_INSTALL=mode)
                self.assertEqual(result.returncode, 8, result.stdout + result.stderr)
                self.assertEqual(rows["install"][0], "pending", rows["install"])
                self.assertEqual(rows["outcome"][0], "activation_pending")
                self.assertIn("--activate-installed", rows["outcome"][1])
                self.assertFalse([c for c in self.calls(root) if c.startswith(("host --import", "host --save"))])
                text = marker.read_text()
                self.assertTrue(text.startswith(f"phase=reinstall-pending\nzip_sha256={env['ZIP_SHA256']}\n"
                                                "bundle_version=23\n"), text)
                self.assertFalse((root / "home" / ".aegis-local" / "locks" / "timing-self").exists())
        # Still pending on the re-run: only the activation is repeated.
        dest = root / "Applications"
        result, rows = self.run_cycle(root, env, out="out2", FAKE_ACTIVATE_INSTALLED="pending-approval")
        self.assertEqual(result.returncode, 8, result.stdout + result.stderr)
        self.assertIn("mode=resume", rows["preflight"][1])
        self.assertTrue(rows["uninstall"][1].startswith("resumed: "), rows["uninstall"])
        # Approved: the re-run activates, imports and saves the profile; it never uninstalls again.
        before_calls = len(self.calls(root))
        result, rows = self.run_cycle(root, env, out="out3")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = [c for c in self.calls(root)[before_calls:] if not c.startswith("systemextensionsctl")]
        self.assertEqual(calls, [
            "host --list", "host --ping", "host --filter-status",
            f"install --activate-installed --receipt {env['INSTALL_RECEIPT']} --dest {dest} --state-dir {state}",
            f"host --import {env['IDENTITY_SRC']}",
            "host --save-profile dev.aegis.macos.PacketTunnel 203.0.113.7 --replace-existing",
            "host --list", "host --ping"])
        self.assertEqual(rows["install"][0], "pass")
        self.assertEqual(rows["extension_activated"][0], "pass")
        self.assertEqual(rows["reinstalled_version"], ("pass", "installed=23 zip=23 before=23"))
        self.assertEqual(rows["outcome"], ("pass", "resumed: reinstalled, identity and profile restored"))
        self.assertTrue(marker.read_text().startswith("phase=completed\n"))
        # A completed marker is never resumed: the next run is a full cycle.
        result, rows = self.run_cycle(root, env, out="out4")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("mode=cycle", rows["preflight"][1])
        self.assertTrue([c for c in self.calls(root) if c.startswith("uninstall --dest")])

    def test_a_failed_import_resumes_with_the_import_and_never_repeats_the_activation(self):
        root, env = self.setup_world()
        result, rows = self.run_cycle(root, env, FAKE_IMPORT="refused")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(rows["identity_import"][0], "fail")
        # The refusal code, not the approval banner the host writes first.
        self.assertIn("provider_refused identity_import_refused", rows["identity_import"][1])
        self.assertNotIn("administrator approval", rows["identity_import"][1])
        # The provider answers with no identity: a full cycle would be refused,
        # the pending reinstall of this ZIP resumes.
        before_calls = len(self.calls(root))
        result, rows = self.run_cycle(root, env, out="out2")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls(root)[before_calls:]
        self.assertFalse([c for c in calls if c.split()[0] in ("uninstall", "install")], calls)
        self.assertEqual(rows["install"][0], "info")
        self.assertIn("activation not repeated", rows["install"][1])
        self.assertEqual(rows["identity_import"][0], "pass")
        self.assertEqual(rows["outcome"][0], "pass")
        # A pending reinstall of another ZIP is not resumed.
        root, env = self.setup_world()
        result, rows = self.run_cycle(root, env, FAKE_IMPORT="refused")
        marker = (root / "home" / "Library" / "Application Support" / "aegis-packaging" / "install"
                  / "uninstall-reinstall-window" / "reinstall.txt")
        marker.write_text(marker.read_text().replace(env["ZIP_SHA256"], "2" * 64))
        result, rows = self.run_cycle(root, env, out="out2")
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("no pending reinstall of this ZIP", result.stdout)

    def test_the_script_never_deletes_uses_sudo_or_changes_an_extension(self):
        text = UNINSTALL_REINSTALL.read_text()
        code = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
        import re
        self.assertEqual([line for line in code if re.search(r"\brm\b", line)], ['    [ -n "$TOKEN" ] && grep -qx "token=$TOKEN" "$LOCK" 2>/dev/null && rm -f "$LOCK"'])
        # The host verbs with an effect run only inside uninstall-app.sh.
        for word in ("sudo", "--remove-source", "--dry-run", "rmdir", "unlink", "--deactivate", "--forget-identity",
                     "--remove-profile", "--emergency-stop", "networksetup", "mv "):
            self.assertFalse([line for line in code if word in line], word)
        self.assertEqual([line.strip() for line in code if "systemextensionsctl" in line and "list" not in line], [])


# ------------------------------------- owner-attended SLEEP=1 and IFSWITCH=1

SLEEP_GUARD = PACKAGE / "harness" / "sleep_guard.py"
OWNER_MODES_SH = PACKAGE / "harness" / "owner-modes.sh"


def owner_alarm_code():
    """The perl alarm code of owner-modes.sh, as the window passes it."""
    import re
    return re.search(r"^OM_ALARM_PL='([^']*)'$", OWNER_MODES_SH.read_text(), re.M).group(1)


def provider_lines(*codes):
    return "".join(f"2026-10-23 06:00:00.000 Df PacketTunnel[42:1] [dev.aegis.macos.PacketTunnel] aegis-ne {c}\\n"
                   for c in codes)


# v33: fake_timeline's provider lines (seconds after the owner's action).
# v33 review: the plug and the unplug as v33 should log them (the unplug as
# window-v32-ifswitch-r2 and r4 did): re-pinned to the new primary at the
# path change, the session sealed with relay_path_changed and rebuilt on
# it. NO_LOSS_TO_EN7 is a re-pin that sealed no session.
REPIN_TO_EN7 = ("+0.3 path_change name:en7;+0.3 relay_interface_repinned name:en7;"
                "+0.3 session_lost relay_path_changed;+0.3 reasserting on;+0.8 relay_interface name:en7;"
                "+1.5 session_rebuilt attempt:1;+1.5 reasserting off")
REBUILT_ON_EN0 = ("+0.3 path_change name:en0;+0.3 relay_interface_repinned name:en0;"
                  "+0.3 session_lost relay_path_changed;+0.3 reasserting on;+0.7 relay_interface name:en0;"
                  "+1.0 session_rebuilt attempt:1;+1.0 reasserting off")
NO_LOSS_TO_EN7 = "+0.3 path_change name:en7;+0.3 relay_interface_repinned name:en7"


OWNER_FAKE_COMMANDS = dict(WINDOW_FAKE_COMMANDS)
OWNER_FAKE_COMMANDS.update({
    # Wi-Fi en0, the Thunderbolt Bridge and a USB Ethernet adapter en7.
    "networksetup": r"""#!/bin/sh
echo "networksetup $*" >> "$CALLS"
case "$1" in
  -listallhardwareports)
    printf '\nHardware Port: Wi-Fi\nDevice: en0\nEthernet Address: 02:00:00:00:00:01\n'
    printf '\nHardware Port: Thunderbolt Bridge\nDevice: bridge0\nEthernet Address: 02:00:00:00:00:0b\n'
    # v30: $W/en7.unlisted: the adapter is not registered (yet).
    [ "${FAKE_NO_EN7:-0}" = 1 ] || [ -e "$W/en7.unlisted" ] \
      || printf '\nHardware Port: USB 10/100/1000 LAN\nDevice: en7\nEthernet Address: 02:00:00:00:00:07\n'
    { [ "${FAKE_EN8:-0}" = 1 ] || [ -e "$W/en8.port" ]; } \
      && printf '\nHardware Port: Thunderbolt Ethernet Slot 1\nDevice: en8\nEthernet Address: 02:00:00:00:00:08\n'
    printf '\nVLAN Configurations\n===================\n';;
  -getairportpower) echo "Wi-Fi Power (en0): On";;
  # FAKE_SERVICE_ORDER: en7_first (default), wifi_first or en7_disabled.
  -listnetworkserviceorder)
    echo "An asterisk (*) denotes that a network service is disabled."
    case "${FAKE_SERVICE_ORDER:-en7_first}" in
      en7_first) printf '(1) USB 10/100/1000 LAN\n(Hardware Port: USB 10/100/1000 LAN, Device: en7)\n\n(2) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n\n';;
      wifi_first) printf '(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n\n(2) USB 10/100/1000 LAN\n(Hardware Port: USB 10/100/1000 LAN, Device: en7)\n\n';;
      en7_disabled) printf '(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n\n(*) USB 10/100/1000 LAN\n(Hardware Port: USB 10/100/1000 LAN, Device: en7)\n\n';;
    esac
    printf '(3) Thunderbolt Bridge\n(Hardware Port: Thunderbolt Bridge, Device: bridge0)\n';;
  *) exit 1;;
esac
""",
    # $W/en0 and $W/en7 hold active or inactive ($W/en7 absent: no adapter).
    "ifconfig": r"""#!/bin/sh
show() { [ -z "$1" ] || [ "$1" = "$2" ]; }
if show "$1" en0; then
  printf 'en0: flags=8863<UP> mtu 1500\n\tether 02:00:00:00:00:01\n'
  if [ "$(cat "$W/en0")" = active ]; then
    printf '\tinet6 fe80::1c%%en0 prefixlen 64 scopeid 0x6\n'
    # FAKE_EN0_NO_V6=1: a Wi-Fi network without global IPv6.
    [ "${FAKE_EN0_NO_V6:-0}" = 1 ] || printf '\tinet6 2001:db8:1:2::50 prefixlen 64 autoconf secured\n'
    printf '\tinet 192.168.1.50 netmask 0xffffff00 broadcast 192.168.1.255\n\tstatus: active\n'
  else
    printf '\tstatus: inactive\n'
  fi
fi
if [ -e "$W/en7" ] && show "$1" en7; then
  printf 'en7: flags=8863<UP> mtu 1500\n\tether 02:00:00:00:00:07\n'
  if [ "$(cat "$W/en7")" = active ]; then
    printf '\tinet 10.0.7.50 netmask 0xffffff00 broadcast 10.0.7.255\n\tstatus: active\n'
  elif [ "$(cat "$W/en7")" = link ]; then
    # v30: a link (cable in) before DHCP gave it an address.
    printf '\tstatus: active\n'
  else
    printf '\tstatus: inactive\n'
  fi
elif [ "$1" = en7 ]; then
  echo "ifconfig: interface en7 does not exist" >&2; exit 1
fi
if [ -z "$1" ]; then
  printf 'lo0: flags=8049<UP,LOOPBACK> mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000\n\tinet6 ::1 prefixlen 128\n'
fi
if show "$1" utun9 && [ "$(cat "$STATE")" = Connected ]; then
  printf 'utun9: flags=8051<UP> mtu 1400\n\tinet 198.19.255.1 --> 198.19.255.1 netmask 0xffffffff\n\tinet6 fe80::9%%utun9 prefixlen 64 scopeid 0x13\n\tinet6 fd00:ae61::1 prefixlen 120\n'
fi
exit 0
""",
    "route": r"""#!/bin/sh
if [ "$(cat "$STATE")" = Connected ]; then echo "  interface: utun9"; exit 0; fi
p=$(cat "$W/primary")
case "$*" in *-inet6*) [ "$p" = en0 ] && [ "${FAKE_EN0_NO_V6:-0}" = 1 ] && exit 0;; esac
echo "  interface: $p"
""",
    # --nwi: the utun first while Connected, then the physical primary and
    # any other active interface; the IPv6 list names en0 too.
    "scutil": r"""#!/bin/sh
case "$1 $2" in
  "--nc status") cat "$STATE"; echo "Extended Status <dictionary> {";;
  "--nc stop") echo "scutil $*" >> "$CALLS"; echo Disconnected > "$STATE";;
  "--dns "*) printf 'DNS configuration\n\nresolver #1\n  nameserver[0] : 198.19.255.2\n  nameserver[1] : fd00:ae61::2\n';;
  "--nwi ")
    up=$(cat "$STATE"); p=$(cat "$W/primary")
    printf 'Network information\n\nIPv4 network interface information\n'
    [ "$up" = Connected ] && printf '     utun9 : flags      : 0x5 (IPv4,DNS)\n           address    : 198.19.255.1\n'
    if [ "$up" != Connected ] || [ "${FAKE_NWI_HIDES_PHYS:-0}" != 1 ]; then
      printf '       %s : flags      : 0x7 (IPv4,IPv6,DNS)\n           address    : 192.0.2.1\n' "$p"
      for d in en0 en7; do
        [ "$d" != "$p" ] && [ -e "$W/$d" ] && [ "$(cat "$W/$d")" = active ] && printf '       %s : flags      : 0x7 (IPv4,DNS)\n' "$d"
      done
    fi
    printf '\n   REACH : flags 0x00000002 (Reachable)\n\nIPv6 network interface information\n       en0 : flags      : 0x6 (IPv6,DNS)\n\nNetwork interfaces: utun9 %s\n' "$p";;
esac
""",
    "sysctl": r"""#!/bin/sh
[ "$1" = -n ] || exit 1
case "$2" in
  kern.waketime) [ "${FAKE_NO_WAKETIME:-0}" = 1 ] && exit 1
    printf '{ sec = %s, usec = 0 } Thu Oct 23 06:00:00 2026\n' "$(cat "$W/waketime")";;
  kern.sleeptime) printf '{ sec = %s, usec = 0 } Thu Oct 23 05:59:00 2026\n' "$(cat "$W/sleeptime")";;
  *) exit 1;;
esac
""",
    # Unprivileged for -g sched, behind the fake sudo for everything else.
    # sleepnow "sleeps" FAKE_SLEEP_S seconds in the background, then
    # records kern.sleeptime and kern.waketime (unless FAKE_NO_WAKE=1).
    "pmset": r"""#!/bin/sh
echo "pmset $*" >> "$CALLS"
case "$1" in
  -g) if [ -z "${2:-}" ]; then
      # v30: the system-wide block; $W/sleep_disabled or FAKE_SLEEP_DISABLED.
      [ "${FAKE_PMSET_G_FAIL:-0}" = 1 ] && exit 1
      printf 'System-wide power settings:\n SleepDisabled\t\t%s\nCurrently in use:\n standby              0\n' \
        "$(cat "$W/sleep_disabled" 2>/dev/null || echo "${FAKE_SLEEP_DISABLED:-0}")"
      exit 0
    fi
    [ "$2" = sched ] || exit 1
    n=$(cat "$W/sched.reads" 2>/dev/null || echo 0); echo $((n + 1)) > "$W/sched.reads"
    echo "Scheduled power events:"
    if [ "${FAKE_SCHED_VANISH:-0}" = 1 ] && [ "$n" -ge 1 ]; then exit 0; fi
    cat "$W/sched" 2>/dev/null; exit 0;;
  relative|schedule) [ "$1 $2" = "schedule cancel" ] || {
      grep -q '^armed ' "$OUT/sleep-guard.log" 2>/dev/null && echo "pmset_guard=armed" >> "$CALLS" \
        || echo "pmset_guard=none" >> "$CALLS"; } ;;
esac
case "$1" in
  relative) [ "$2" = wake ] && [ "${FAKE_PMSET_FAIL:-0}" != 1 ] || exit 1
    case "${FAKE_SCHED_STYLE:-at}" in
      at) echo " [0]  wake at $(date -r $(( $(date +%s) + $3 )) '+%m/%d/%Y %H:%M:%S') by 'pmset'" > "$W/sched";;
      relative) echo " [0]  relative wake in $3 seconds" > "$W/sched";;
    esac;;
  schedule)
    if [ "$2" = cancel ]; then : > "$W/sched"
    elif [ "${FAKE_PMSET_FAIL:-0}" = 1 ]; then exit 1
    elif [ "${FAKE_SCHED_STYLE:-at}" != none ]; then echo " [0]  wake at $3 by '$4'" > "$W/sched"; fi;;
  sleepnow) t=$(date +%s)
    # v30 review: FAKE_SLEEPNOW_HOLD_S: a request that takes that long to
    # return (powerd busy), then sleeps as usual.
    if [ -n "${FAKE_SLEEPNOW_HOLD_S:-}" ]; then
      sleep "$FAKE_SLEEPNOW_HOLD_S"; echo "pmset sleepnow returned" >> "$CALLS"; t=$(date +%s)
    fi
    # v30: pmset's own failures (stdout, as the real one writes them).
    if [ -n "${FAKE_SLEEPNOW_RC:-}" ]; then
      printf '%b' "${FAKE_SLEEPNOW_OUT-}"; printf '%b' "${FAKE_SLEEPNOW_ERR-}" >&2; exit "$FAKE_SLEEPNOW_RC"
    fi
    ( sleep "${FAKE_SLEEP_S:-2}"
      echo "${FAKE_SLEPT_AT:-$t}" > "$W/sleeptime"
      [ "${FAKE_NO_WAKE:-0}" = 1 ] && exit 0
      date +%s > "$W/waketime"
      if [ "${FAKE_WAKE_REASSERT:-0}" = 1 ]; then echo Reasserting > "$STATE"; sleep 1.5; echo Connected > "$STATE"; fi
    ) >/dev/null 2>&1 &;;
  *) exit 1;;
esac
""",
    # v33: the settle gate's reads ask log show for the provider process
    # only (`log show settle_read`). The first FAKE_SETTLE_FAIL_READS of them
    # fail; with FAKE_SETTLE_HANG=1 each hangs until its alarm ends it. Every
    # read prints FAKE_PROVIDER_LOG and, with a timeline, fake_timeline's
    # lines that are due (v33 review: told whether it is a settle read).
    "fake_log": r"""#!/bin/sh
echo "log $1" >> "$CALLS"
[ "$1" = show ] || exit 1
settle=0
case "$*" in
  *'process == "aegis-ne-provider"'*)
    settle=1
    echo "log show settle_read" >> "$CALLS"
    n=$(cat "$W/settle.reads" 2>/dev/null || echo 0); echo $((n + 1)) > "$W/settle.reads"
    if [ "$n" -lt "${FAKE_SETTLE_FAIL_READS:-0}" ]; then echo "log: fake failure" >&2; exit 1; fi
    [ "${FAKE_SETTLE_HANG:-0}" = 1 ] && exec /bin/sleep 100;;
esac
printf 'Timestamp               Ty Process[PID:TID]\n'
printf '%b' "${FAKE_PROVIDER_LOG-}"
[ -z "${FAKE_PROVIDER_TIMELINE-}${FAKE_FOREIGN_TIMELINE-}" ] \
  || FAKE_SETTLE_READ=$settle exec "$SYSTEM_PY" -I "$(dirname "$0")/fake_timeline"
""",
    # v33: the provider's lines relative to the owner's action ($W/route_at,
    # written by the plug and unplug hooks), in local time as log show
    # prints them: FAKE_PROVIDER_TIMELINE="+<s> <code> [value];..." from
    # aegis-ne-provider, FAKE_FOREIGN_TIMELINE the same from a cargo test
    # binary of this crate, and a reack_valid_ms line every 0.5 s from 1 s
    # before the action (none after FAKE_PROVIDER_SILENT_AFTER seconds).
    # Only lines already due are printed, in time order. v33 review: every
    # settle read records its time in $W/settle_at, and
    # FAKE_AFTER_SETTLE_TIMELINE's provider lines are relative to the last
    # one: logged right after that read, so no settle read ever holds them.
    "fake_timeline": r"""import os, time
now = time.time()
try:
    with open(os.path.join(os.environ["W"], "route_at")) as f:
        route = float(f.read())
except (OSError, ValueError):
    raise SystemExit(0)
settle_at = os.path.join(os.environ["W"], "settle_at")
if os.environ.get("FAKE_SETTLE_READ") == "1":
    with open(settle_at, "w") as f:
        f.write("%.6f\n" % now)
try:
    with open(settle_at) as f:
        last_settle = float(f.read())
except (OSError, ValueError):
    last_settle = None
lines = []
for var, proc, base in (("FAKE_PROVIDER_TIMELINE", "aegis-ne-provider[4242:2c03685]", route),
                        ("FAKE_FOREIGN_TIMELINE", "aegis_network_extension-0a1b2c3d4e5f6a7b[999:1]", route),
                        ("FAKE_AFTER_SETTLE_TIMELINE", "aegis-ne-provider[4242:2c03685]", last_settle)):
    for entry in os.environ.get(var, "").split(";") if base is not None else ():
        entry = entry.strip()
        if entry:
            offset, code = entry.split(" ", 1)
            if base + float(offset) <= now:
                lines.append((base + float(offset), proc, code))
silent = os.environ.get("FAKE_PROVIDER_SILENT_AFTER")
end = now if silent is None else min(now, route + float(silent))
at = route - 1.0
while at <= end:
    lines.append((at, "aegis-ne-provider[4242:2c109d6]", "reack_valid_ms ms:2500"))
    at += 0.5
for at, proc, code in sorted(lines, key=lambda line: line[0]):
    print("%s.%03d Df %s aegis-ne %s" % (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(at)),
                                         int(at * 1000) % 1000, proc, code))
""",
})


# v31 review: a results.tsv row that reports a check made before an earlier
# row was written starts where the row before that check ended (result_since
# in harness/real-relay-window.sh); every other row starts where the row
# before it ended.
EARLIER_CHECK_ROWS = {"physical_v6_baseline", "filter_preflight", "leak_capture_ifaces", "leak_window_connected_at",
                      "disconnect_v6_addr", "ifswitch_leak_window_disconnect_at", "ifswitch_route_changed",
                      "netloss_addr_v6_count"}
EARLIER_CHECK_PREFIXES = ("probe_failed_", "filter_drop_delta_", "bound_fresh_", "bpf_order_")
ROW_UTC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{3}Z$")


def row_utc(text):
    return datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=datetime.timezone.utc)


def file_utc(path):
    """When the harness wrote PATH (a --filter-status read's output)."""
    return datetime.datetime.fromtimestamp(path.stat().st_mtime, datetime.timezone.utc)


def row_fields(out):
    return [line.split("\t") for line in (out / "results.tsv").read_text().splitlines()]


def row_times(fields):
    return {row[0]: (row_utc(row[4]), row_utc(row[5])) for row in fields}


def reports_an_earlier_check(name):
    for prefix in ("positive_control_", "negative_control_"):
        if name.startswith(prefix):
            name = name[len(prefix):]
    return name in EARLIER_CHECK_ROWS or name.startswith(EARLIER_CHECK_PREFIXES)


def assert_rows_chain(test, fields):
    """Six columns, ISO UTC times, start at most end; each row starts where
    the row before it ended, or, for a row that reports an earlier check,
    where an earlier row ended (or at the window's start)."""
    test.assertTrue(fields)
    ends, previous = [fields[0][4]], None
    for row in fields:
        test.assertEqual(len(row), 6, row)
        start, end = row[4], row[5]
        test.assertRegex(start, ROW_UTC, row[0])
        test.assertRegex(end, ROW_UTC, row[0])
        test.assertLessEqual(row_utc(start), row_utc(end), row[0])
        if previous is not None:
            if reports_an_earlier_check(row[0]):
                test.assertIn(start, ends, row[0])
            else:
                # Each row starts where the one before it ended.
                test.assertEqual(start, previous, row[0])
        previous = end
        ends.append(end)


SETTLE_JUDGE = PACKAGE / "harness" / "settle_judge.py"
# v33: excerpts (codes and interface names only) of the installed v32
# provider logs: window-v32-ifswitch-r3 (the plug: lost by lease expiry
# after ifswitch_recovered had passed) and window-v32-ifswitch-r4 (the
# unplug: re-pinned and rebuilt at the path change). Local time (UTC+1).
SETTLE_R3 = """\
2026-10-27 11:40:30.023 Df aegis-ne-provider[13190:2c109d6] aegis-ne reack_valid_ms ms:2047
2026-10-27 11:40:30.631 Df aegis-ne-provider[13190:2c109d6] aegis-ne reack_valid_ms ms:2556
2026-10-27 11:40:30.950 Df aegis-ne-provider[13190:2c03685] aegis-ne path_change name:en7
2026-10-27 11:40:32.420 Df aegis-ne-provider[13190:2c03685] aegis-ne session_lost capture_lease_expired
2026-10-27 11:40:32.420 Df aegis-ne-provider[13190:2c03685] aegis-ne reasserting on
2026-10-27 11:40:32.445 Df aegis-ne-provider[13190:2c11ad8] aegis-ne session_rebuild attempt:1 backoff_ms:381
2026-10-27 11:40:32.909 Df aegis-ne-provider[13190:2c11ae6] aegis-ne relay_interface name:en0
2026-10-27 11:40:34.212 Df aegis-ne-provider[13190:2c11ae6] aegis-ne ack_valid_ms ms:3356
2026-10-27 11:40:34.243 Df aegis-ne-provider[13190:2c03685] aegis-ne session_rebuilt attempt:1
2026-10-27 11:40:34.243 Df aegis-ne-provider[13190:2c03685] aegis-ne reasserting off
2026-10-27 11:40:34.890 Df aegis-ne-provider[13190:2c11ae6] aegis-ne reack_valid_ms ms:2128
2026-10-27 11:40:36.193 Df aegis-ne-provider[13190:2c11ae6] aegis-ne reack_valid_ms ms:2679
2026-10-27 11:40:38.185 Df aegis-ne-provider[13190:2c11ae6] aegis-ne reack_valid_ms ms:2682
2026-10-27 11:40:39.204 Df aegis-ne-provider[13190:2c11ae6] aegis-ne reack_valid_ms ms:2678
2026-10-27 11:40:39.847 Df aegis-ne-provider[13190:2c11ae6] aegis-ne reack_valid_ms ms:2172
"""
SETTLE_R4 = """\
2026-10-27 11:42:06.021 Df aegis-ne-provider[13190:2c03685] aegis-ne path_change name:en0
2026-10-27 11:42:06.021 Df aegis-ne-provider[13190:2c03685] aegis-ne relay_interface_repinned name:en0
2026-10-27 11:42:06.021 Df aegis-ne-provider[13190:2c03685] aegis-ne session_lost relay_path_changed
2026-10-27 11:42:06.021 Df aegis-ne-provider[13190:2c03685] aegis-ne reasserting on
2026-10-27 11:42:06.033 Df aegis-ne-provider[13190:2c13cd0] aegis-ne session_rebuild attempt:1 backoff_ms:319
2026-10-27 11:42:06.452 Df aegis-ne-provider[13190:2c13cf2] aegis-ne relay_interface name:en0
2026-10-27 11:42:07.853 Df aegis-ne-provider[13190:2c03685] aegis-ne session_rebuilt attempt:1
2026-10-27 11:42:07.853 Df aegis-ne-provider[13190:2c03685] aegis-ne reasserting off
2026-10-27 11:42:10.846 Df aegis-ne-provider[13190:2c13cf2] aegis-ne reack_valid_ms ms:2169
2026-10-27 11:42:13.357 Df aegis-ne-provider[13190:2c13cf2] aegis-ne reack_valid_ms ms:2660
"""


class SettleJudgeTests(unittest.TestCase):
    """harness/settle_judge.py, the v33 IFSWITCH=1 settle gate's judge, on
    excerpts of the installed v32 provider logs and made-up lines."""

    @staticmethod
    def local_ms(text):
        day, millis = text.rsplit(".", 1)
        return int(time.mktime(time.strptime(day, "%Y-%m-%d %H:%M:%S"))) * 1000 + int(millis)

    def judge(self, text, ask, route, quiet=5000, env=None, name=None):
        with tempfile.TemporaryDirectory(prefix="aegis-settle-judge-") as temp:
            log = pathlib.Path(temp) / "settle.log"
            log.write_text("Timestamp               Ty Process[PID:TID]\n" + text)
            args = [str(log), str(ask), str(route), str(quiet)] + ([] if name is None else [name])
            r = subprocess.run([SYSTEM_PY, "-I", str(SETTLE_JUDGE), *args],
                               capture_output=True, text=True, timeout=30, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.count("\n"), 1, r.stdout)
        return dict(pair.split("=", 1) for pair in r.stdout.split())

    @staticmethod
    def until(text, stamp):
        return "".join(line + "\n" for line in text.splitlines() if line[:23] <= stamp)

    def test_the_v32_plug_settles_only_after_its_late_loss_was_rebuilt_and_the_quiet_period(self):
        ask, route = self.local_ms("2026-10-27 11:40:00.650"), self.local_ms("2026-10-27 11:40:30.450")
        full = self.judge(SETTLE_R3, ask, route)
        self.assertEqual(full, {
            "settled": "1", "failed": "none", "pending": "0", "path_change": "1",
            "lost": "1:capture_lease_expired", "rebuilt": "1", "refused": "0", "lines": "15",
            "path_change_after": "0.500", "rebuilt_after": "3.793", "settled_after": "8.793",
            "covered_after": "9.397", "failed_after": "none",
            "covered_ms": str(self.local_ms("2026-10-27 11:40:39.847")), "repinned": "0"})
        # Read by read, as the gate did: quiet but too short after the path
        # change (where ifswitch_recovered had passed), the loss pending, the
        # rebuild without its quiet period, one line short of it, settled.
        for stamp, settled, pending, covered in (
                ("2026-10-27 11:40:31.000", "0", "0", "0.500"),
                ("2026-10-27 11:40:33.000", "0", "1", "2.459"),
                ("2026-10-27 11:40:36.500", "0", "0", "5.743"),
                ("2026-10-27 11:40:39.204", "0", "0", "8.754"),
                ("2026-10-27 11:40:39.847", "1", "0", "9.397")):
            with self.subTest(stamp):
                got = self.judge(self.until(SETTLE_R3, stamp), ask, route)
                self.assertEqual((got["settled"], got["pending"], got["covered_after"]), (settled, pending, covered))
        # The v32 unplug: re-pinned and lost at the path change.
        ask, route = self.local_ms("2026-10-27 11:41:47.630"), self.local_ms("2026-10-27 11:42:05.552")
        got = self.judge(SETTLE_R4, ask, route)
        self.assertEqual((got["settled"], got["lost"], got["rebuilt_after"], got["settled_after"]),
                         ("1", "1:relay_path_changed", "2.301", "7.301"))
        self.assertEqual(self.judge(SETTLE_R4, ask, route, quiet=8000)["settled"], "0")

    def test_a_name_counts_the_provider_s_re_pins_to_it_since_the_prompt_and_covered_ms_is_its_newest_line(self):
        # v33 review: the switch rows read the re-pin to the new interface
        # and the after-settle row's start from the judge.
        ask, route = self.local_ms("2026-10-27 11:41:47.630"), self.local_ms("2026-10-27 11:42:05.552")
        got = self.judge(SETTLE_R4, ask, route, quiet=1, name="en0")
        self.assertEqual((got["repinned"], got["lost"], got["path_change"]), ("1", "1:relay_path_changed", "1"))
        self.assertEqual(got["covered_ms"], str(self.local_ms("2026-10-27 11:42:13.357")))
        for name in ("en7", "en"):
            self.assertEqual(self.judge(SETTLE_R4, ask, route, quiet=1, name=name)["repinned"], "0", name)
        # Without a name nothing is counted; the r3 plug never re-pinned.
        self.assertEqual(self.judge(SETTLE_R4, ask, route, quiet=1)["repinned"], "0")
        r3_ask, r3_route = self.local_ms("2026-10-27 11:40:00.650"), self.local_ms("2026-10-27 11:40:30.450")
        self.assertEqual(self.judge(SETTLE_R3, r3_ask, r3_route, quiet=1, name="en7")["repinned"], "0")
        # Another process's re-pin, a re-pin before the prompt and another
        # process's later line count for neither.
        foreign = ("2026-10-27 11:42:06.500 Df aegis_network_extension-0a1b2c3d4e5f6a7b[999:1] aegis-ne "
                   "relay_interface_repinned name:en7\n"
                   "2026-10-27 11:42:20.000 Df aegis_network_extension-0a1b2c3d4e5f6a7b[999:1] aegis-ne "
                   "reack_valid_ms ms:2500\n")
        early = "2026-10-27 11:41:40.000 Df aegis-ne-provider[13190:2c03685] aegis-ne relay_interface_repinned name:en7\n"
        got = self.judge(early + SETTLE_R4 + foreign, ask, route, quiet=1, name="en7")
        self.assertEqual((got["repinned"], got["covered_ms"]), ("0", str(self.local_ms("2026-10-27 11:42:13.357"))))
        # No provider line: no covered_ms. A name that is no interface token
        # is refused.
        self.assertEqual(self.judge(foreign, ask, route, name="en7")["covered_ms"], "none")
        for name in ("en 7", "name:en7", "", "en7;x"):
            r = subprocess.run([SYSTEM_PY, "-I", str(SETTLE_JUDGE), "/nonexistent/settle.log", "1", "2", "3", name],
                               capture_output=True, text=True, timeout=30)
            self.assertEqual((r.returncode, r.stdout), (2, "settled=0 error=arguments\n"), name)

    def test_only_the_provider_process_and_lines_since_the_prompt_count(self):
        ask, route = self.local_ms("2026-10-27 11:40:00.650"), self.local_ms("2026-10-27 11:40:30.450")
        pending = self.until(SETTLE_R3, "2026-10-27 11:40:33.000")
        foreign = "".join(f"2026-10-27 11:40:{sec}.000 Df aegis_network_extension-0a1b2c3d4e5f6a7b[999:1] aegis-ne {c}\n"
                          for sec, c in (("33", "session_rebuilt attempt:1"), ("33", "reasserting off"),
                                         ("45", "reack_valid_ms ms:2500")))
        got = self.judge(pending + foreign, ask, route)
        self.assertEqual((got["settled"], got["pending"], got["rebuilt"], got["lines"], got["covered_after"]),
                         ("0", "1", "0", "7", "2.459"))
        # A path change before the prompt is no path change of this switch.
        late = self.local_ms("2026-10-27 11:40:31.000")
        got = self.judge(SETTLE_R3, late, late)
        self.assertEqual((got["settled"], got["path_change"], got["lost"]), ("0", "0", "1:capture_lease_expired"))
        # The fakes' subsystem column is read the same way.
        bracketed = SETTLE_R3.replace("] aegis-ne ", "] [dev.aegis.macos.PacketTunnel] aegis-ne ")
        self.assertEqual(self.judge(bracketed, ask, route)["settled"], "1")
        # No path change at all never settles, however quiet.
        quiet = "".join(line + "\n" for line in SETTLE_R3.splitlines() if "path_change" not in line)
        self.assertEqual(self.judge(quiet, ask, route)["settled"], "0")

    def test_a_session_failure_an_empty_read_and_bad_input_never_settle(self):
        ask, route = self.local_ms("2026-10-27 11:40:00.650"), self.local_ms("2026-10-27 11:40:30.450")
        failed = SETTLE_R3 + "2026-10-27 11:40:39.900 Df aegis-ne-provider[13190:2c03685] aegis-ne session_failed identity_tampered\n"
        got = self.judge(failed, ask, route)
        self.assertEqual((got["settled"], got["failed"], got["failed_after"]), ("0", "identity_tampered", "9.450"))
        got = self.judge("", ask, route)
        self.assertEqual((got["settled"], got["lines"], got["covered_after"], got["settled_after"]),
                         ("0", "0", "none", "5.000"))
        refused = self.until(SETTLE_R3, "2026-10-27 11:40:33.000") + (
            "2026-10-27 11:40:33.500 Df aegis-ne-provider[13190:2c11ad8] aegis-ne session_rebuild_refused "
            "session_spawn_failed\n")
        got = self.judge(refused, ask, route)
        self.assertEqual((got["settled"], got["pending"], got["refused"]), ("0", "1", "1"))
        for args, why in ((["/nonexistent/settle.log", "1", "2", "3"], "error=unreadable"),
                          (["x", "1", "2"], "error=usage"), (["x", "a", "2", "3"], "error=arguments"),
                          (["x", "5", "2", "3"], "error=arguments"), (["x", "1", "2", "0"], "error=arguments")):
            r = subprocess.run([SYSTEM_PY, "-I", str(SETTLE_JUDGE), *args], capture_output=True, text=True, timeout=30)
            self.assertEqual((r.returncode, r.stdout), (2, f"settled=0 {why}\n"), args)

    def test_the_local_timestamps_follow_the_zone_of_the_mac(self):
        from zoneinfo import ZoneInfo
        route = int(time.time()) * 1000 - 60_000
        events = ((0.4, "path_change name:en7"), (1.2, "session_lost capture_lease_expired"), (2.5, "session_rebuilt attempt:1"),
                  (8.0, "reack_valid_ms ms:2500"))
        outputs = set()
        for zone in ("UTC", "Asia/Tokyo", "America/New_York", "Europe/Berlin"):
            lines = ""
            for offset, code in events:
                at = datetime.datetime.fromtimestamp(route / 1000 + offset, ZoneInfo(zone))
                lines += f"{at:%Y-%m-%d %H:%M:%S}.{at.microsecond // 1000:03d} Df aegis-ne-provider[1:2] aegis-ne {code}\n"
            got = self.judge(lines, route - 10_000, route, env=dict(os.environ, TZ=zone))
            outputs.add(tuple(sorted(got.items())))
            self.assertEqual((got["settled"], got["rebuilt_after"], got["settled_after"]), ("1", "2.500", "7.500"), zone)
        self.assertEqual(len(outputs), 1)


class RealRelayWindowOwnerModeTests(unittest.TestCase):
    """SLEEP=1 and IFSWITCH=1 of harness/real-relay-window.sh
    (harness/owner-modes.sh, harness/sleep_guard.py) against fake pmset,
    sysctl, scutil, route, ifconfig, networksetup, log, sudo and tcpdump on
    PATH and a temporary HOME. Nothing here sleeps the Mac, touches an
    interface, captures or tunnels: the owner's cable is a file."""

    def setup_world(self, primary="en0", en0="active", en7="inactive"):
        temp = tempfile.TemporaryDirectory(prefix="aegis-owner-modes-")
        self.addCleanup(temp.cleanup)
        root = pathlib.Path(temp.name)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        for name, body in OWNER_FAKE_COMMANDS.items():
            (bin_dir / name).write_text(body)
            (bin_dir / name).chmod(0o755)
        host = root / "AEGIS.app" / "Contents" / "MacOS" / "aegis-ne-host"
        host.parent.mkdir(parents=True)
        host.write_text(WINDOW_FAKE_HOST)
        host.chmod(0o755)
        (root / "fake_tcpdump.py").write_text(WINDOW_FAKE_TCPDUMP)
        (root / "fake_sudo_parent.py").write_text(WINDOW_FAKE_SUDO_PARENT)
        pids = root / "fake.pids"
        pids.write_text("")
        self.addCleanup(RealRelayWindowLeakCaptureTests.kill_fakes, pids)
        (root / "home" / ".aegis-local" / "locks").mkdir(parents=True)
        handoff = root / "handoff.json"
        handoff.write_text(json.dumps({"relay": f"{RELAY_IP}:443", "echo_tcp": f"{RELAY_IP}:7",
                                       "echo_udp": f"{RELAY_IP}:7", "whoami": f"http://{RELAY_IP}/ip"}))
        world = root / "world"
        world.mkdir()
        now = int(time.time())
        for name, text in (("primary", primary), ("en0", en0), ("en7", en7), ("waketime", str(now - 3600)),
                           ("sleeptime", str(now - 3700))):
            if text is not None:
                (world / name).write_text(text + "\n")
        (root / "state").write_text("Disconnected\n")
        (root / "calls.log").write_text("")
        out = root / "out"
        env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(root / "home"), "APP": str(root / "AEGIS.app"),
               "HANDOFF": str(handoff), "OUT": str(out), "ROLLBACK_S": "40", "STATE": str(root / "state"),
               "CALLS": str(root / "calls.log"), "FAKE_TCPDUMP": str(root / "fake_tcpdump.py"),
               "RELAY_IP": RELAY_IP, "FAKE_SUDO_PARENT": str(root / "fake_sudo_parent.py"), "FAKE_PIDS": str(pids),
               "LEAK_CAPTURE": "0", "PROBE_PY": str(bin_dir / "probe_py"), "SYSTEM_PY": SYSTEM_PY, "W": str(world),
               "LOG_BIN": str(bin_dir / "fake_log"), "PMSET": str(bin_dir / "pmset"),
               "FAKE_PMSET": str(bin_dir / "pmset"), "SYSCTL": str(bin_dir / "sysctl"), "FAKE_SUDO_PMSET": "1"}
        self.addCleanup(RealRelayWindowLeakCaptureTests.cancel_rollback, None, out)
        self.addCleanup(self.end_guard, out)
        return root, env

    @staticmethod
    def end_guard(out):
        try:
            text = (out / "sleep-guard.log").read_text()
        except OSError:
            return
        if "sleep_refused" in text or "sleep_requested" in text:
            return
        (out / "sleep-guard.log.cancel").write_text("")

    @staticmethod
    def rows_of(out):
        rows, names = {}, []
        if (out / "results.tsv").exists():
            for line in (out / "results.tsv").read_text().splitlines():
                name, verdict, detail, status, _start, _end = line.split("\t")  # v31: UTC start, end
                rows[name] = (verdict, detail, status)
                names.append(name)
        return rows, names

    def run_window(self, when=None, world=None, **extra):
        """Runs the window; `when` is (file under OUT, text, action(root, proc)),
        or a list of them, each run once as soon as that file holds that
        text."""
        root, env = self.setup_world(**(world or {}))
        env.update(extra)
        log = open(root / "stdout.txt", "w")
        self.addCleanup(log.close)
        proc = subprocess.Popen(["/bin/bash", str(REAL_RELAY_WINDOW)], env=env, stdout=log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 150
        hooks = [] if when is None else (list(when) if isinstance(when, list) else [when])
        while proc.poll() is None and time.monotonic() < deadline:
            for hook in list(hooks):
                path = root / "out" / hook[0]
                if path.exists() and hook[1] in path.read_text():
                    hook[2](root, proc)
                    hooks.remove(hook)
            time.sleep(0.05)
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
            self.fail("window did not finish within 150 s")
        rows, names = self.rows_of(root / "out")
        stdout = (root / "stdout.txt").read_text()
        return proc.returncode, stdout, rows, names, (root / "calls.log").read_text().splitlines(), root

    def assert_refused_untouched(self, rc, stdout, rows, calls, root, mode, reason):
        self.assertEqual(rc, 3, stdout)
        self.assertIn(f"refused: {mode}: {reason}; nothing connected", stdout)
        # v30: the unprivileged `pmset -g` read is the only pmset call.
        self.assertFalse([c for c in calls if c.startswith(("host --connect", "pmset", "sudo -n /usr", "tcpdump"))
                          and c != "pmset -g"], calls)
        self.assertFalse((root / "home" / ".aegis-local" / "locks" / "timing-self").exists())
        self.assertFalse((root / "out" / "rollback.log").exists())
        self.assertFalse((root / "out" / "sleep-guard.log").exists())
        self.assertEqual(rows, {})

    @staticmethod
    def wait_for(path, text, timeout=60):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.exists() and text in path.read_text():
                return True
            time.sleep(0.1)
        return False

    # ------------------------------------- v31: row times and the window summary

    ROW_TIME = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{3}Z$")

    @staticmethod
    def utc(text):
        return datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=datetime.timezone.utc)

    def test_every_row_carries_its_utc_start_and_end_and_the_rows_chain(self):
        before = datetime.datetime.now(datetime.timezone.utc)
        rc, stdout, rows, names, calls, root = self.run_window(
            FAKE_PROVIDER_LOG=provider_lines("session_lost capture_lease_expired", "session_rebuilt attempt:1"))
        after = datetime.datetime.now(datetime.timezone.utc)
        self.assertEqual(rc, 0, stdout)
        fields = [line.split("\t") for line in (root / "out" / "results.tsv").read_text().splitlines()]
        self.assertGreater(len(fields), 30)
        # v31 review: each row starts where the one before it ended, unless
        # it reports a check made before an earlier row was written.
        assert_rows_chain(self, fields)
        earlier = [row[0] for ahead, row in zip(fields, fields[1:]) if row[4] != ahead[5]]
        self.assertEqual(earlier, ["filter_preflight", "disconnect_v6_addr"])
        slack = datetime.timedelta(seconds=2)
        self.assertGreaterEqual(self.utc(fields[0][4]), before - slack)
        self.assertLessEqual(self.utc(fields[-1][5]), after + slack)
        # The status column is still the fourth, unchanged.
        self.assertEqual(rows["connected"], ("1", "Connected", "Connected"))
        # A probe's row spans the probe: the connect waits for Connected.
        connected = next(row for row in fields if row[0] == "connected")
        self.assertGreater(self.utc(connected[5]), self.utc(connected[4]))

    def test_the_window_wide_session_summary_counts_every_loss_and_renewal_line(self):
        log = provider_lines(
            "session_lost capture_lease_expired", "reasserting on", "session_rebuilt attempt:1", "reasserting off",
            "session_lost relay_path_changed", "reasserting on", "session_rebuilt attempt:2",
            "identity_renewal state:deferred:guarded attempt:0 remaining_s:142049",
            "identity_renewal state:held:transport attempt:1",
            "identity_renewal state:start attempt:2 connects:1", "session_lost identity_renewal_due",
            "session_lost capture_lease_expired")
        rc, stdout, rows, names, calls, root = self.run_window(FAKE_PROVIDER_LOG=log)
        self.assertEqual(rc, 0, stdout)
        self.assertEqual(rows["window_session_summary"][:2], (
            "info", "session_lost=4 causes=capture_lease_expired:2,identity_renewal_due:1,relay_path_changed:1 "
                    "session_rebuilt=2 reasserting_on=2 renewal_attempts=1 renewal_deferred=1 renewal_held=1"))
        self.assertLess(names.index("disconnect_verified"), names.index("window_session_summary"))
        self.assertLess(names.index("window_session_summary"), names.index("disconnect_v6_addr"))
        # Address-free: tokens and counts only.
        self.assertNotIn(RELAY_IP, rows["window_session_summary"][1])
        # A quiet window, and no provider log at all.
        rc, stdout, rows, names, calls, root = self.run_window(FAKE_PROVIDER_LOG=provider_lines("start tunnel_running"))
        self.assertEqual(rows["window_session_summary"][:2], (
            "info", "session_lost=0 causes=none session_rebuilt=0 reasserting_on=0 renewal_attempts=0 "
                    "renewal_deferred=0 renewal_held=0"))
        rc, stdout, rows, names, calls, root = self.run_window(FAKE_PROVIDER_LOG="")
        self.assertEqual(rows["window_session_summary"][:2], ("unavailable", "no provider log lines"))

    def test_a_row_that_reports_an_earlier_check_still_contains_it(self):
        # v31 review: the baseline and the filter's preflight read come
        # before any row; disconnect_v6_addr is checked in the loop of
        # disconnect_v6_route but written after the provider-log reviews.
        rc, stdout, rows, names, calls, root = self.run_window(
            FAKE_PROVIDER_LOG=provider_lines("session_lost capture_lease_expired", "session_rebuilt attempt:1"))
        self.assertEqual(rc, 0, stdout)
        out = root / "out"
        fields = row_fields(out)
        assert_rows_chain(self, fields)
        times = row_times(fields)
        before = file_utc(out / "filter-status-before.txt")
        for name in ("physical_v6_baseline", "filter_preflight"):
            self.assertLessEqual(times[name][0], before, name)
        self.assertLessEqual(before, times["filter_preflight"][1])
        self.assertEqual(times["filter_preflight"][0], row_utc(fields[0][4]), "the window's start")
        self.assertEqual(times["disconnect_v6_addr"][0], times["disconnect_v6_route"][0])
        self.assertGreater(times["disconnect_v6_addr"][1], times["window_session_summary"][1])
        self.assertLess(names.index("window_session_summary"), names.index("disconnect_v6_addr"))
        # A row written right after its own read contains it as before.
        after = file_utc(out / "filter-status-after.txt")
        self.assertLessEqual(times["filter_counters_after"][0], after)
        self.assertLessEqual(after, times["filter_counters_after"][1])
        self.assertEqual(times["filter_counters_after"][0], times["disconnect_v6_route"][1])

    # ---------------------------------------------------------------- SLEEP=1

    def test_sleep_refusals_happen_before_the_lock_the_rollback_and_any_connect(self):
        for extra, reason in (
                ({"FAKE_SUDO_PMSET": "0"}, "needs sudo -n for /usr/bin/pmset (run sudo -v in this terminal first)"),
                ({"IFSWITCH": "1"}, "not with IFSWITCH=1: one owner-attended disruption per window"),
                ({"NETLOSS": "1"}, "not with NETLOSS=1: one owner-attended disruption per window"),
                ({"SLEEP_WAKE_S": "19"}, "SLEEP_WAKE_S=19 is outside 20..600"),
                ({"SLEEP_WAKE_SLACK_S": "x"}, "SLEEP_WAKE_SLACK_S=x is outside 10..300"),
                ({"SLEEP_RECOVER_S": "301"}, "SLEEP_RECOVER_S=301 is outside 5..300"),
                ({"SLEEP_WAKE_KIND": "sometime"}, "SLEEP_WAKE_KIND=sometime is not relative or absolute"),
                # The default dated wake keeps 20 s ahead of the guard's settle.
                ({"SLEEP_WAKE_S": "21"}, "SLEEP_WAKE_S=21 leaves under 20s between the guard's settle (2s) and "
                                         "the dated wake: use at least 22"),
                ({"SLEEP_WAKE_S": "25", "SLEEP_GUARD_SETTLE_S": "6"},
                 "SLEEP_WAKE_S=25 leaves under 20s between the guard's settle (6s) and the dated wake: use at least 26"),
                ({"FAKE_NO_WAKETIME": "1"}, "kern.waketime is unreadable: no wake could be observed"),
                ({"OM_PY": "/nonexistent/python3"}, "no sleep guard interpreter (/nonexistent/python3 missing)"),
                ({"FAKE_SUDO_PMSET": "0", "LEAK_CAPTURE": "1"},
                 "needs sudo -n for /usr/bin/pmset (run sudo -v in this terminal first)"),
                # v30: a disabled sleep (window-v29-sleep-r3) or an unreadable one.
                ({"FAKE_SLEEP_DISABLED": "1"},
                 "SleepDisabled=1 (pmset disablesleep) refuses every pmset sleepnow (kPMUserDisabledAllSleep): "
                 "the owner clears it before the window (sudo pmset disablesleep 0) and decides whether to set it "
                 "again afterwards"),
                ({"FAKE_PMSET_G_FAIL": "1"},
                 "pmset -g is unreadable: SleepDisabled unknown, so no sleep could be relied on"),
                ({"SLEEP_GUARD_CALL_S": "61"}, "SLEEP_GUARD_CALL_S=61 is outside 1..60")):
            with self.subTest(extra=extra):
                rc, stdout, rows, names, calls, root = self.run_window(SLEEP="1", **extra)
                self.assert_refused_untouched(rc, stdout, rows, calls, root, "SLEEP=1", reason)
                if extra.get("FAKE_SUDO_PMSET") == "0":
                    # Asked without a prompt, and before any capture is started.
                    self.assertEqual(calls, ["sudo -n -l /usr/bin/pmset"])

    def test_a_sleep_cycle_spans_the_capture_rebuilds_and_recovers_in_order(self):
        log = provider_lines("sleep count:1", "wake rebuild", "reasserting on", "session_lost capture_lease_expired",
                             "session_rebuild attempt:1 backoff_ms:0", "session_rebuilt attempt:1", "reasserting off")
        rc, stdout, rows, names, calls, root = self.run_window(
            SLEEP="1", LEAK_CAPTURE="1", ROLLBACK_S="25", FAKE_WAKE_REASSERT="1", FAKE_PROVIDER_LOG=log)
        out = root / "out"
        self.assertEqual(rc, 0, stdout)
        self.assertEqual(calls[:4], ["sudo -n -l /usr/bin/pmset", "pmset -g", "sudo -n -l /usr/sbin/tcpdump",
                                     "sudo -n -l /bin/kill"])
        # The capture's own bound covers the sleep: 25 + 60 + wake 40 + slack 60.
        self.assertIn("SLEEP=1: wake=absolute:40s rollback_s=25 capture_bound_s=185", stdout)
        start = calls.index(f"sudo -n /usr/sbin/tcpdump -i en0 -p -s 160 -B 4096 -G 185 -W 1 -U -w {out}/physical.pcap")
        connect = next(i for i, c in enumerate(calls) if c.startswith("host --connect"))
        schedule = next(i for i, c in enumerate(calls) if c.startswith("sudo -n /usr/bin/pmset schedule wake "))
        self.assertFalse([c for c in calls if "pmset relative" in c], calls)
        # The guard is armed before the wake is scheduled.
        self.assertEqual(calls[schedule + 2], "pmset_guard=armed")
        self.assertNotIn("pmset_guard=none", calls)
        reads = [i for i, c in enumerate(calls) if c == "pmset -g sched"]
        sleepnow = calls.index("sudo -n /usr/bin/pmset sleepnow")
        stop = next(i for i, c in enumerate(calls) if c.startswith("scutil --nc stop"))
        self.assertEqual(len(reads), 2)  # the window's check, then the guard's own
        self.assertLess(start, connect)
        self.assertLess(connect, schedule)
        self.assertLess(schedule, reads[0])
        self.assertLess(reads[1], sleepnow)
        self.assertLess(sleepnow, stop)
        self.assertLess(sleepnow, calls.index("tcpdump stopped"))
        order = ["sleep_preflight", "sleep_guard_armed", "sleep_wake_scheduled", "sleep_guard", "sleep_woke",
                 "sleep_capture_alive_after_wake", "sleep_recovered", "sleep_whoami_egress", "sleep_udp_echo_v4",
                 "sleep_tcp_echo_v4", "sleep_log_sleep", "sleep_log_wake", "sleep_log_reack", "sleep_log_session_lost",
                 "sleep_log_session_rebuild", "sleep_log_session_rebuilt", "sleep_log_reasserting",
                 "sleep_log_path_change", "sleep_rebuild_settled", "sleep_provider_cycle"]
        # The fake wakes early: a dated wake still ahead is cancelled at exit.
        self.assertEqual([n for n in names if n.startswith("sleep_") and n != "sleep_wake_cancelled"], order)
        # v33: the IFSWITCH=1 settle gate never runs here.
        self.assertFalse([n for n in names if "settle" in n and n != "sleep_rebuild_settled"], names)
        self.assertNotIn("log show settle_read", calls)
        self.assertFalse(list(out.glob("*settle.*")))
        if "sleep_wake_cancelled" in rows:
            self.assertEqual(rows["sleep_wake_cancelled"][:2], ("info", "rc=0 at_exit"))
            self.assertEqual(names[-1], "sleep_wake_cancelled")
        self.assertLess(names.index("dns_aaaa_v6_anchor"), names.index("sleep_preflight"))
        self.assertLess(names.index("sleep_provider_cycle"), names.index("disconnect_verified"))
        self.assertEqual(rows["sleep_wake_scheduled"][:2], ("pass", "kind=absolute rc=0 listed=at"))
        self.assertEqual(rows["sleep_guard"][0], "pass")
        self.assertRegex(rows["sleep_guard"][1], r"^sleep_requested rc=0 at=[0-9]+ wake=at cause=ok out=\[\] err=\[\]$")
        self.assertTrue(rows["sleep_preflight"][1].endswith(" sleep_disabled=0"), rows["sleep_preflight"])
        self.assertEqual(rows["sleep_woke"][0], "pass", rows["sleep_woke"])
        self.assertRegex(rows["sleep_woke"][1], r"^slept=[0-9]+s woke_after=[0-9]+s bound=100s$")
        self.assertEqual(rows["sleep_capture_alive_after_wake"][0], "pass")
        self.assertEqual(rows["sleep_recovered"][0], "pass", rows["sleep_recovered"])
        self.assertEqual(rows["sleep_recovered"][2], "Connected")
        for name in ("sleep_whoami_egress", "sleep_udp_echo_v4", "sleep_tcp_echo_v4"):
            self.assertEqual(rows[name][0], "pass", (name, rows[name]))
        self.assertEqual(rows["sleep_log_wake"][:2], ("info", "count=1 seq=rebuild"))
        self.assertEqual(rows["sleep_rebuild_settled"][:2], ("pass", "reasserting_off"))
        self.assertEqual(rows["sleep_provider_cycle"][:2],
                         ("pass", "sleep=1 wake=1 last_wake=rebuild reack=0 rebuilt=1"))
        # The guard is detached from the window's group and adopted by launchd.
        guard = (out / "sleep-guard.log").read_text()
        self.assertRegex(guard, r"^armed pid=[0-9]+ ppid=[0-9]+ settle=2\ncredential sudo=ok sleep_disabled=0\n")
        self.assertIn(f"pid={guard.split('armed pid=')[1].split()[0]} settle=2s", rows["sleep_guard_armed"][1])
        self.assertEqual(rows["disconnect_verified"][:2], ("pass", "en0"))
        self.assertEqual(rows["leak_proof"][0], "pass", rows["leak_proof"])
        self.assertEqual(rows["leak_window_disconnect_at"][1], "capture_alive=1")
        self.assertFalse((root / "home" / ".aegis-local" / "locks" / "timing-self").exists())

    def test_an_absolute_wake_and_a_forced_reack_pass_and_a_missing_reack_fails(self):
        log = provider_lines("sleep count:1", "wake reack", "reack forced")
        rc, stdout, rows, names, calls, root = self.run_window(SLEEP="1", SLEEP_WAKE_KIND="absolute",
                                                               SLEEP_WAKE_S="120", FAKE_PROVIDER_LOG=log)
        self.assertEqual(rc, 0, stdout)
        import re
        sched = [c for c in calls if c.startswith("sudo -n /usr/bin/pmset schedule wake ")]
        self.assertEqual(len(sched), 1, calls)
        self.assertRegex(sched[0], r"^sudo -n /usr/bin/pmset schedule wake [0-9]{2}/[0-9]{2}/[0-9]{2} "
                                   r"[0-9]{2}:[0-9]{2}:[0-9]{2} aegis-b06$")
        when = re.search(r"wake (\S+ \S+) aegis", sched[0]).group(1)
        delta = time.mktime(time.strptime(when, "%m/%d/%y %H:%M:%S")) - time.time()
        self.assertTrue(-60 < delta < 120, delta)
        self.assertIn("sleeps in 2s and wakes by itself about 118s later", stdout)
        self.assertEqual(rows["sleep_wake_scheduled"][:2], ("pass", "kind=absolute rc=0 listed=at"))
        self.assertEqual(rows["sleep_woke"][0], "pass", rows["sleep_woke"])
        self.assertEqual(rows["sleep_provider_cycle"][:2], ("pass", "sleep=1 wake=1 last_wake=reack reack=1 rebuilt=0"))
        self.assertEqual(rows["sleep_rebuild_settled"][:2], ("pass", "no_reassert"))
        self.assertNotIn("sleep_capture_alive_after_wake", rows)
        # The fake woke long before the dated wake: the exit cancels it, once.
        self.assertEqual([c for c in calls if c.startswith("sudo") and "schedule cancel" in c],
                         [f"sudo -n /usr/bin/pmset schedule cancel wake {when} aegis-b06"])
        self.assertEqual(rows["sleep_wake_cancelled"][:2], ("info", "rc=0 at_exit"))
        self.assertGreater(names.index("sleep_wake_cancelled"), names.index("disconnect_verified"))
        # A wake that names reack without the provider's forced re-ACK fails,
        # and so does a kern.sleeptime from before the request.
        rc, stdout, rows, names, calls, root = self.run_window(
            SLEEP="1", FAKE_SLEPT_AT="1000", FAKE_PROVIDER_LOG=provider_lines("sleep count:1", "wake reack"))
        self.assertEqual(rows["sleep_provider_cycle"][:2], ("fail", "sleep=1 wake=1 last_wake=reack reack=0 rebuilt=0"))
        self.assertEqual(rows["sleep_woke"][0], "fail", rows["sleep_woke"])
        self.assertTrue(rows["sleep_woke"][1].startswith("a wake without a sleep after the request"), rows["sleep_woke"])
        self.assertEqual(rows["sleep_recovered"][0], "pass")
        self.assertEqual(rows["disconnect_verified"][0], "pass")
        # No provider line at all is unavailable, never a pass.
        rc, stdout, rows, names, calls, root = self.run_window(SLEEP="1", FAKE_PROVIDER_LOG="")
        self.assertEqual(rows["sleep_provider_cycle"][:2], ("unavailable", "no provider log lines"))
        self.assertEqual(rows["sleep_woke"][0], "pass")

    def test_without_a_listed_wake_nothing_sleeps_and_the_window_disconnects(self):
        # The default dated wake that is not read back is cancelled by its
        # date and owner, and the armed guard is told to stand down.
        rc, stdout, rows, names, calls, root = self.run_window(SLEEP="1", FAKE_SCHED_STYLE="none")
        self.assertEqual(rc, 0, stdout)
        self.assertEqual(rows["sleep_wake_scheduled"][:2], ("fail", "kind=absolute rc=0 listed=none; nothing slept"))
        self.assertFalse([c for c in calls if "pmset relative" in c], calls)
        when = [c for c in calls if c.startswith("pmset schedule wake ")][0].split("wake ", 1)[1].rsplit(" ", 1)[0]
        self.assertEqual([c for c in calls if c.startswith("sudo") and "schedule cancel" in c],
                         [f"sudo -n /usr/bin/pmset schedule cancel wake {when} aegis-b06"])
        self.assertEqual(rows["sleep_wake_cancelled"][:2], ("info", "rc=0"))
        self.assertTrue(self.wait_for(root / "out" / "sleep-guard.log", "sleep_refused cancelled", 20))
        self.assertNotIn("cannot be cancelled", stdout)
        self.assertNotIn("pmset sleepnow", calls)
        self.assertNotIn("sleep_woke", rows)
        self.assertEqual(rows["disconnect_verified"][:2], ("pass", "en0"))
        # A relative wake only on request, said to be irreversible before it is
        # scheduled; when it is not read back nothing sleeps.
        rc, stdout, rows, names, calls, root = self.run_window(SLEEP="1", SLEEP_WAKE_KIND="relative",
                                                               FAKE_SCHED_STYLE="none")
        self.assertEqual(rc, 0, stdout)
        warning = "sleep: SLEEP_WAKE_KIND=relative: this wake cannot be cancelled or undone"
        self.assertIn(warning, stdout)
        self.assertLess(stdout.index(warning), stdout.index("sleep_wake_scheduled\tfail"))
        self.assertEqual(rows["sleep_wake_scheduled"][:2], ("fail", "kind=relative rc=0 listed=none; nothing slept"))
        self.assertEqual(rows["sleep_wake_cancelled"][:2],
                         ("info", "relative wake cannot be cancelled: it applies to the next sleep"))
        self.assertTrue(self.wait_for(root / "out" / "sleep-guard.log", "sleep_refused cancelled", 20))
        self.assertEqual(calls.count("pmset -g sched"), 1)
        self.assertNotIn("pmset sleepnow", calls)
        self.assertNotIn("sleep_woke", rows)
        self.assertEqual(rows["disconnect_verified"][:2], ("pass", "en0"))
        # The guard's read-back right before sleeping finds it gone: it
        # refuses, and the absolute wake is cancelled by its date and owner.
        rc, stdout, rows, names, calls, root = self.run_window(SLEEP="1", SLEEP_WAKE_KIND="absolute",
                                                               FAKE_SCHED_VANISH="1")
        self.assertEqual(rc, 0, stdout)
        self.assertEqual(rows["sleep_wake_scheduled"][0], "pass")
        self.assertEqual(rows["sleep_guard_armed"][0], "pass")
        self.assertEqual(rows["sleep_guard"][:2], ("fail", "sleep_refused no_scheduled_wake lines=1; nothing slept"))
        self.assertEqual(calls.count("pmset -g sched"), 2)
        self.assertNotIn("pmset sleepnow", calls)
        when = [c for c in calls if c.startswith("pmset schedule wake ")][0].split("wake ", 1)[1].rsplit(" ", 1)[0]
        self.assertIn(f"sudo -n /usr/bin/pmset schedule cancel wake {when} aegis-b06", calls)
        self.assertEqual(rows["sleep_wake_cancelled"][:2], ("info", "rc=0"))
        self.assertNotIn("sleep_woke", rows)
        self.assertEqual(rows["disconnect_verified"][:2], ("pass", "en0"))
        # A refused pmset is a failed schedule too, whatever is listed.
        rc, stdout, rows, names, calls, root = self.run_window(SLEEP="1", FAKE_PMSET_FAIL="1")
        self.assertEqual(rows["sleep_wake_scheduled"][:2], ("fail", "kind=absolute rc=1 listed=none; nothing slept"))
        self.assertNotIn("pmset sleepnow", calls)
        rc, stdout, rows, names, calls, root = self.run_window(SLEEP="1", SLEEP_WAKE_KIND="relative", FAKE_PMSET_FAIL="1")
        self.assertEqual(rows["sleep_wake_scheduled"][:2], ("fail", "kind=relative rc=1 listed=none; nothing slept"))

    def test_a_wake_that_never_comes_fails_within_its_bound(self):
        rc, stdout, rows, names, calls, root = self.run_window(
            SLEEP="1", SLEEP_WAKE_S="22", SLEEP_WAKE_SLACK_S="10", FAKE_NO_WAKE="1",
            FAKE_PROVIDER_LOG=provider_lines("sleep count:1"))
        self.assertEqual(rows["sleep_woke"][:2], ("fail", "no wake within 32s of the request"))
        self.assertEqual(rows["sleep_provider_cycle"][0], "fail")
        self.assertEqual(rows["disconnect_verified"][0], "pass")

    def test_a_window_killed_before_the_guard_sleeps_keeps_the_mac_awake_and_the_rollback_ends_the_tunnel(self):
        seen = {}

        def kill(root, proc):
            guard = root / "out" / "sleep-guard.log"
            pid = int(guard.read_text().split("armed pid=")[1].split()[0])
            info = subprocess.run(["/bin/ps", "-o", "ppid=", "-o", "pgid=", "-p", str(pid)], capture_output=True,
                                  text=True).stdout.split()
            seen["guard"] = (pid, info)
            proc.kill()  # SIGKILL: no EXIT trap runs

        rc, stdout, rows, names, calls, root = self.run_window(
            when=("sleep-guard.log", "armed pid=", kill), SLEEP="1", LEAK_CAPTURE="1", ROLLBACK_S="30",
            SLEEP_GUARD_SETTLE_S="3")
        self.assertEqual(rc, -9)
        pid, info = seen["guard"]
        self.assertEqual(info, ["1", str(pid)])
        out = root / "out"
        self.assertTrue(self.wait_for(out / "sleep-guard.log", "sleep_refused window_gone", 20),
                        (out / "sleep-guard.log").read_text())
        self.assertTrue(self.wait_for(out / "rollback.log", "rollback_done", 60))
        calls = (root / "calls.log").read_text().splitlines()
        self.assertNotIn("pmset sleepnow", calls)
        self.assertIn("host --emergency-stop", calls)
        tcpdump = RealRelayWindowLeakCaptureTests.fake_pids(root)["tcpdump"]
        self.assertIn(f"capture_stop_requested pid={tcpdump} rc=0", (out / "rollback.log").read_text())
        self.assertTrue(self.wait_for(root / "calls.log", "tcpdump stopped if=en0", 20))
        self.assertEqual((root / "state").read_text().strip(), "Disconnected")

    def test_a_guard_not_adopted_by_launchd_is_cancelled_and_nothing_sleeps(self):
        root, env = self.setup_world()
        fake_ps = root / "bin" / "ps"
        fake_ps.write_text("#!/bin/sh\ncase \"$*\" in *ppid=*) p=$(echo \"$*\" | sed -n 's/.*-p \\([0-9]*\\).*/\\1/p'); "
                           "echo \"4242 $p\";; *) exec /bin/ps \"$@\";; esac\n")
        fake_ps.chmod(0o755)
        env.update(SLEEP="1")
        result = subprocess.run(["/bin/bash", str(REAL_RELAY_WINDOW)], capture_output=True, text=True, env=env,
                                timeout=150)
        rows, names = self.rows_of(root / "out")
        self.assertEqual(rows["sleep_guard_armed"][0], "fail", result.stdout)
        self.assertIn("cancelled, no wake scheduled, nothing slept", rows["sleep_guard_armed"][1])
        self.assertTrue(self.wait_for(root / "out" / "sleep-guard.log", "sleep_refused cancelled", 20))
        calls = (root / "calls.log").read_text().splitlines()
        self.assertNotIn("pmset sleepnow", calls)
        # A guard that cannot be confirmed leaves no wake behind.
        self.assertFalse([c for c in calls if c.startswith(("pmset schedule", "pmset relative"))], calls)
        self.assertNotIn("sleep_wake_scheduled", rows)
        self.assertEqual(rows["disconnect_verified"][0], "pass")

    def test_the_wake_check_reads_only_wakes_that_fire_by_the_bound(self):
        with tempfile.TemporaryDirectory(prefix="aegis-sleep-guard-") as temp:
            fake = pathlib.Path(temp) / "pmset"
            fake.write_text("#!/bin/sh\n[ \"$1 $2\" = \"-g sched\" ] || exit 1\nprintf '%b' \"$SCHED\"\n")
            fake.chmod(0o755)
            now = int(time.time())

            def at(offset, fmt="%m/%d/%Y %H:%M:%S", word="wake"):
                return f" [0]  {word} at {time.strftime(fmt, time.localtime(now + offset))} by 'pmset'\\n"

            def check(sched, hi=now + 60):
                r = subprocess.run([SYSTEM_PY, "-I", str(SLEEP_GUARD), "check", str(fake), str(hi)],
                                   capture_output=True, text=True, env={"SCHED": "Scheduled power events:\\n" + sched},
                                   timeout=30)
                return r.returncode, r.stdout.strip()

            self.assertEqual(check(at(30)), (0, "at"))
            # Too close to be asleep before it fires.
            self.assertEqual(check(at(10)), (1, ""))
            self.assertEqual(check(at(10) + at(25)), (0, "at"))
            self.assertEqual(check(at(30, "%m/%d/%y %H:%M:%S")), (0, "at"))
            self.assertEqual(check(at(30, word="wakeorpoweron")), (0, "at"))
            self.assertEqual(check(at(-30)), (1, ""))          # already past
            self.assertEqual(check(at(120)), (1, ""))          # after the bound
            self.assertEqual(check(at(30, word="sleep")), (1, ""))
            self.assertEqual(check(at(30, word="shutdown")), (1, ""))
            self.assertEqual(check(at(120) + at(30)), (0, "at"))
            self.assertEqual(check(" [0]  relative wake in 40 seconds\\n"), (0, "relative"))
            self.assertEqual(check(" [0]  relative wake in 40 seconds\\n", now + 30), (1, ""))
            self.assertEqual(check(" Relative wake scheduled\\n"), (0, "relative"))
            self.assertEqual(check(" [0]  relative poweron in 40 seconds\\n"), (1, ""))
            self.assertEqual(check(""), (1, ""))
            self.assertEqual(check(at(30), "not-a-number")[0], 2)
            r = subprocess.run([SYSTEM_PY, "-I", str(SLEEP_GUARD), "check", "/nonexistent/pmset", str(now + 60)],
                               capture_output=True, text=True, timeout=30)
            self.assertEqual((r.returncode, r.stdout), (1, ""))

    def test_the_guard_waits_for_its_go_and_refuses_without_a_valid_one(self):
        with tempfile.TemporaryDirectory(prefix="aegis-sleep-guard-") as temp:
            temp = pathlib.Path(temp)
            # Any sudo the guard could reach is a recording fake that lists
            # its pmset right (-l) and refuses everything else.
            fake_bin = temp / "bin"
            fake_bin.mkdir()
            (fake_bin / "sudo").write_text("#!/bin/sh\necho \"sudo $*\" >> \"$CALLS\"\n"
                                           "[ \"$1 $2\" = \"-n -l\" ] && exit 0\nexit 1\n")
            (fake_bin / "sudo").chmod(0o755)
            fake_pmset = fake_bin / "pmset"
            fake_pmset.write_text("#!/bin/sh\necho \"pmset $*\" >> \"$CALLS\"\n"
                                  "[ -z \"$2\" ] && printf 'System-wide power settings:\\nCurrently in use:\\n'\nexit 0\n")
            fake_pmset.chmod(0o755)
            env = {"PATH": f"{fake_bin}:/usr/bin:/bin", "CALLS": str(temp / "calls.log")}
            window = subprocess.Popen(["/bin/sleep", "60"])
            self.addCleanup(window.wait)
            self.addCleanup(window.kill)

            def guard(name, before=None, window_pid=window.pid):
                logp = temp / f"{name}.log"
                if before:
                    before(logp)
                subprocess.run([SYSTEM_PY, "-I", str(SLEEP_GUARD), "guard", str(fake_pmset), str(logp),
                                str(window_pid), "0"], env=env, timeout=30, check=True)
                self.assertTrue(self.wait_for(logp, "sleep_refused", 20), logp.read_text())
                lines = logp.read_text().splitlines()
                self.assertEqual(lines[1], "credential sudo=ok sleep_disabled=0")
                return lines[2:]

            self.assertEqual(guard("bad", lambda l: pathlib.Path(f"{l}.go").write_text("hi=soon\n")),
                             ["sleep_refused bad_go"])
            self.assertEqual(guard("cancel", lambda l: pathlib.Path(f"{l}.cancel").write_text("")),
                             ["sleep_refused cancelled"])
            # A window that is gone before its go (a zombie counts as gone).
            gone = subprocess.Popen(["/usr/bin/true"])
            time.sleep(0.5)
            self.assertEqual(guard("gone", window_pid=gone.pid), ["sleep_refused window_gone"])
            gone.wait()
            # A go whose bound no listed wake fits: no sleep is asked for.
            self.assertEqual(guard("nowake", lambda l: pathlib.Path(f"{l}.go").write_text(f"hi={int(time.time()) + 90}\n")),
                             ["sleep_refused no_scheduled_wake lines=0"])
            calls = (temp / "calls.log").read_text().splitlines() if (temp / "calls.log").exists() else []
            # Each guard asks sudo -l and reads -g at its arm; the last one
            # reads -g and the schedule again before it would sleep.
            arm = ["sudo -n -l /usr/bin/pmset", "pmset -g"]
            self.assertEqual(calls, arm * 4 + ["pmset -g", "pmset -g sched"])

    # ---------------------------------------------------- SLEEP=1 v30 evidence

    @staticmethod
    def sleep_guard_module():
        import importlib.util
        spec = importlib.util.spec_from_file_location("aegis_sleep_guard", SLEEP_GUARD)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_a_sleep_disabled_after_the_go_is_refused_without_a_privileged_call(self):
        def disable(root, proc):
            (root / "world" / "sleep_disabled").write_text("1\n")

        rc, stdout, rows, names, calls, root = self.run_window(
            when=("window.log", "sleep: this Mac sleeps in", disable), SLEEP="1", SLEEP_GUARD_SETTLE_S="2")
        self.assertEqual(rc, 0, stdout)
        self.assertEqual(rows["sleep_guard_armed"][0], "pass")
        self.assertEqual(rows["sleep_guard"][:2], ("fail", "sleep_refused sleep_disabled; nothing slept"))
        self.assertNotIn("pmset sleepnow", calls)
        self.assertFalse([c for c in calls if c.endswith("pmset sleepnow")], calls)
        self.assertEqual(rows["sleep_wake_cancelled"][:2], ("info", "rc=0"))
        self.assertNotIn("sleep_woke", rows)
        self.assertEqual(rows["disconnect_verified"][:2], ("pass", "en0"))

    def test_a_refused_sleep_request_records_its_cause_and_output(self):
        for rc_text, out, cause in (
                ("71", "Unable to sleep system: error 0xe00002e2\\n",
                 "cause=pmset_not_permitted error=0xe00002e2 out=[Unable to sleep system: error 0xe00002e2] err=[]"),
                ("77", "Sleep error 0xe00002c1; You must run this as root.\\n",
                 "cause=pmset_not_root error=0xe00002c1 out=[Sleep error 0xe00002c1; You must run this as root.] "
                 "err=[]")):
            with self.subTest(rc=rc_text):
                rc, stdout, rows, names, calls, root = self.run_window(
                    SLEEP="1", FAKE_SLEEPNOW_RC=rc_text, FAKE_SLEEPNOW_OUT=out)
                self.assertEqual(rc, 0, stdout)
                verdict, detail = rows["sleep_guard"][:2]
                self.assertEqual(verdict, "fail")
                self.assertRegex(detail, rf"^sleep_requested rc={rc_text} at=[0-9]+ wake=at ")
                self.assertTrue(detail.endswith(f" {cause}; nothing slept"), detail)
                # Asked once, never retried; the dated wake is cancelled.
                self.assertEqual(calls.count("sudo -n /usr/bin/pmset sleepnow"), 1)
                self.assertEqual(rows["sleep_wake_cancelled"][:2], ("info", "rc=0"))
                self.assertNotIn("sleep_woke", rows)
                self.assertEqual(rows["disconnect_verified"][:2], ("pass", "en0"))

    def test_a_guard_that_cannot_use_the_credential_schedules_no_wake(self):
        # The window's own sudo -l passes; the detached guard's is refused.
        rc, stdout, rows, names, calls, root = self.run_window(SLEEP="1", FAKE_SUDO_DETACHED_REFUSES="1")
        self.assertEqual(rc, 0, stdout)
        self.assertEqual(rows["sleep_guard_armed"][0], "fail", rows)
        detail = rows["sleep_guard_armed"][1]
        self.assertIn("credential sudo=no_credential sleep_disabled=0 rc=1 err=[sudo: a password is required]", detail)
        self.assertIn("cancelled, no wake scheduled, nothing slept", detail)
        self.assertEqual(calls.count("sudo -n -l /usr/bin/pmset"), 2)
        self.assertFalse([c for c in calls if "pmset schedule" in c or "pmset relative" in c], calls)
        self.assertNotIn("sleep_wake_scheduled", rows)
        guard = (root / "out" / "sleep-guard.log").read_text()
        self.assertIn("sleep_refused no_credential", guard)
        self.assertEqual(rows["disconnect_verified"][0], "pass")

    def test_the_guard_bounds_and_masks_a_hanging_request(self):
        with tempfile.TemporaryDirectory(prefix="aegis-sleep-guard-") as temp:
            temp = pathlib.Path(temp)
            fake_bin = temp / "bin"
            fake_bin.mkdir()
            (fake_bin / "sudo").write_text(
                "#!/bin/sh\necho \"sudo $*\" >> \"$CALLS\"\n[ \"$1 $2\" = \"-n -l\" ] && exit 0\n"
                "[ \"$2 $3\" = \"/usr/bin/pmset sleepnow\" ] || exit 1\n"
                "printf 'partial 192.0.2.7 fe80::1%%en0 02:00:00:00:00:07\\n'\nexec /bin/sleep 30\n")
            (fake_bin / "sudo").chmod(0o755)
            fake_pmset = fake_bin / "pmset"
            fake_pmset.write_text(
                "#!/bin/sh\necho \"pmset $*\" >> \"$CALLS\"\n"
                "if [ -z \"$2\" ]; then printf 'System-wide power settings:\\n SleepDisabled\\t\\t0\\n'; exit 0; fi\n"
                "echo \" [0]  wake at $(date -r $(( $(date +%s) + 40 )) '+%m/%d/%Y %H:%M:%S') by 'pmset'\"\n")
            fake_pmset.chmod(0o755)
            env = {"PATH": f"{fake_bin}:/usr/bin:/bin", "CALLS": str(temp / "calls.log")}
            window = subprocess.Popen(["/bin/sleep", "60"])
            self.addCleanup(window.wait)
            self.addCleanup(window.kill)
            logp = temp / "guard.log"
            pathlib.Path(f"{logp}.go").write_text(f"hi={int(time.time()) + 90}\n")
            started = time.monotonic()
            subprocess.run([SYSTEM_PY, "-I", str(SLEEP_GUARD), "guard", str(fake_pmset), str(logp),
                            str(window.pid), "0", "1"], env=env, timeout=30, check=True)
            self.assertTrue(self.wait_for(logp, "sleep_requested", 20), logp.read_text())
            self.assertLess(time.monotonic() - started, 15)
            line = logp.read_text().splitlines()[-1]
            self.assertRegex(line, r"^sleep_requested rc=timeout at=[0-9]+ wake=at cause=timeout "
                                   r"out=\[partial <ipv4> <ipv6> <mac>\] err=\[\]$")
            for address in ("192.0.2.7", "fe80::1", "02:00:00:00:00:07"):
                self.assertNotIn(address, logp.read_text())
            calls = (temp / "calls.log").read_text().splitlines()
            self.assertEqual(calls.count("sudo -n /usr/bin/pmset sleepnow"), 1)
            # A bound outside 1..60 is a usage error, before any fork.
            r = subprocess.run([SYSTEM_PY, "-I", str(SLEEP_GUARD), "guard", str(fake_pmset), str(logp),
                                str(window.pid), "0", "61"], env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 2)

    # ------------------------------------------- SLEEP=1 v30 review findings

    def test_a_slow_request_within_its_bound_is_waited_for_and_its_wake_kept(self):
        # v30 review: SLEEP_GUARD_CALL_S may be 60, but the window gave up
        # after about SETTLE + 40 s and cancelled the wake while the
        # request still ran. It now waits as long as the guard's bounds.
        rc, stdout, rows, names, calls, root = self.run_window(
            SLEEP="1", ROLLBACK_S="", SLEEP_WAKE_S="120", SLEEP_GUARD_SETTLE_S="0", SLEEP_GUARD_CALL_S="60",
            FAKE_SLEEPNOW_HOLD_S="43", FAKE_PROVIDER_LOG=provider_lines("sleep count:1", "wake reack", "reack forced"))
        self.assertEqual(rc, 0, stdout)
        # The rollback also covers the whole verdict wait: 180 + 120 + 60 + 60
        # + (0 + 50 + 60 + 10) + 60.
        self.assertIn("SLEEP=1: wake=absolute:120s rollback_s=600 capture_bound_s=840", stdout)
        self.assertEqual(rows["sleep_guard"][0], "pass", rows["sleep_guard"])
        self.assertRegex(rows["sleep_guard"][1], r"^sleep_requested rc=0 at=[0-9]+ wake=at cause=ok ")
        self.assertEqual(rows["sleep_woke"][0], "pass", rows["sleep_woke"])
        self.assertNotIn("sleep_wake_kept", rows)
        returned = calls.index("pmset sleepnow returned")
        cancels = [i for i, c in enumerate(calls) if "schedule cancel" in c]
        # Only the exit cancels the wake, after the request returned and the
        # Mac woke early.
        self.assertTrue(all(i > returned for i in cancels), calls)
        self.assertEqual(rows["sleep_wake_cancelled"][:2], ("info", "rc=0 at_exit"))
        self.assertEqual((root / "out" / "sleep-guard.log.claim").read_text().split()[0], "guard")
        self.assertEqual(rows["disconnect_verified"][:2], ("pass", "en0"))

    def test_a_timed_out_request_keeps_the_wake_and_never_says_nothing_slept(self):
        # v30 review: the bound kills only the user's sudo; with use_pty the
        # root pmset is its child and may still ask for the sleep.
        rc, stdout, rows, names, calls, root = self.run_window(
            SLEEP="1", SLEEP_GUARD_CALL_S="1", FAKE_SLEEPNOW_HOLD_S="4", FAKE_SUDO_PMSET_CHILD="1",
            FAKE_PROVIDER_LOG=provider_lines("sleep count:1"))
        self.assertEqual(rc, 0, stdout)
        verdict, detail = rows["sleep_guard"][:2]
        self.assertEqual(verdict, "fail")
        self.assertRegex(detail, r"^sleep_requested rc=timeout at=[0-9]+ wake=at cause=timeout ")
        self.assertTrue(detail.endswith("; outcome unknown (only sudo was stopped, the root pmset may still ask "
                                        "for the sleep): slept_since_request=no"), detail)
        self.assertNotIn("nothing slept", detail)
        self.assertEqual(rows["sleep_wake_kept"][0], "info")
        self.assertIn("request outcome unknown: the dated wake ", rows["sleep_wake_kept"][1])
        self.assertIn("sudo pmset schedule cancel wake '", rows["sleep_wake_kept"][1])
        # Never cancelled: not after the verdict, not at exit.
        self.assertFalse([c for c in calls if "schedule cancel" in c], calls)
        self.assertNotIn("sleep_wake_cancelled", rows)
        # The orphaned pmset did sleep after the window recorded its verdict.
        self.assertTrue(self.wait_for(root / "calls.log", "pmset sleepnow returned", 20))
        self.assertEqual(rows["disconnect_verified"][:2], ("pass", "en0"))

    def test_a_window_stopped_after_the_go_stands_the_guard_down_before_its_captures(self):
        # v30 review: the EXIT trap stopped the captures first and never told
        # the guard; the guard found the window still alive and slept the
        # Mac, and the trap then cancelled the only wake.
        def term(root, proc):
            proc.send_signal(signal.SIGTERM)

        rc, stdout, rows, names, calls, root = self.run_window(
            when=("window.log", "sleep: this Mac sleeps in", term), SLEEP="1", LEAK_CAPTURE="1", ROLLBACK_S="30",
            SLEEP_GUARD_SETTLE_S="2", FAKE_INT_DELAY_S="3")
        self.assertNotEqual(rc, 0, stdout)
        out = root / "out"
        self.assertTrue(self.wait_for(out / "sleep-guard.log", "sleep_refused cancelled", 30),
                        (out / "sleep-guard.log").read_text())
        self.assertEqual((out / "sleep-guard.log.claim").read_text().split()[0], "window")
        calls = (root / "calls.log").read_text().splitlines()
        self.assertNotIn("pmset sleepnow", calls)
        self.assertFalse([c for c in calls if c.endswith("pmset sleepnow")], calls)
        # Nothing can sleep any more: the dated wake goes at exit.
        rows, names = self.rows_of(out)
        self.assertEqual(rows["sleep_wake_cancelled"][:2], ("info", "rc=0 at_exit"))
        self.assertNotIn("sleep_wake_kept", rows)

    def test_a_window_stopped_during_the_request_keeps_the_dated_wake(self):
        # v30 review: once the guard holds the claim its request may run, so
        # a stopped window keeps the wake instead of cancelling it.
        def term(root, proc):
            proc.send_signal(signal.SIGTERM)

        rc, stdout, rows, names, calls, root = self.run_window(
            when=("../calls.log", "sudo -n /usr/bin/pmset sleepnow", term), SLEEP="1", SLEEP_GUARD_SETTLE_S="0",
            FAKE_SLEEPNOW_HOLD_S="6")
        self.assertNotEqual(rc, 0, stdout)
        out = root / "out"
        self.assertTrue((out / "sleep-guard.log.claim").read_text().startswith("guard pid="))
        self.assertEqual(rows["sleep_wake_kept"][0], "info", rows)
        self.assertTrue(rows["sleep_wake_kept"][1].startswith(
            "at_exit: the guard's sleep request may still run (guard pid="), rows["sleep_wake_kept"])
        self.assertNotIn("sleep_wake_cancelled", rows)
        self.assertTrue(self.wait_for(out / "sleep-guard.log", "sleep_requested rc=0", 30))
        calls = (root / "calls.log").read_text().splitlines()
        self.assertFalse([c for c in calls if "schedule cancel" in c], calls)

    def test_the_guard_takes_the_claim_only_when_the_window_has_not(self):
        with tempfile.TemporaryDirectory(prefix="aegis-sleep-guard-") as temp:
            temp = pathlib.Path(temp)
            fake_bin = temp / "bin"
            fake_bin.mkdir()
            (fake_bin / "sudo").write_text("#!/bin/sh\necho \"sudo $*\" >> \"$CALLS\"\n"
                                           "[ \"$1 $2\" = \"-n -l\" ] && exit 0\nexit 0\n")
            (fake_bin / "sudo").chmod(0o755)
            fake_pmset = fake_bin / "pmset"
            fake_pmset.write_text(
                "#!/bin/sh\necho \"pmset $*\" >> \"$CALLS\"\n"
                "if [ -z \"$2\" ]; then printf 'System-wide power settings:\\n SleepDisabled\\t\\t0\\n'; exit 0; fi\n"
                "echo \" [0]  wake at $(date -r $(( $(date +%s) + 40 )) '+%m/%d/%Y %H:%M:%S') by 'pmset'\"\n")
            fake_pmset.chmod(0o755)
            env = {"PATH": f"{fake_bin}:/usr/bin:/bin", "CALLS": str(temp / "calls.log")}
            window = subprocess.Popen(["/bin/sleep", "60"])
            self.addCleanup(window.wait)
            self.addCleanup(window.kill)

            def guard(name, claim=None):
                logp = temp / f"{name}.log"
                pathlib.Path(f"{logp}.go").write_text(f"hi={int(time.time()) + 90}\n")
                if claim:
                    pathlib.Path(f"{logp}.claim").write_text(claim)
                subprocess.run([SYSTEM_PY, "-I", str(SLEEP_GUARD), "guard", str(fake_pmset), str(logp),
                                str(window.pid), "0"], env=env, timeout=30, check=True)
                self.assertTrue(self.wait_for(logp, "\nsleep_re", 20), logp.read_text())
                return logp.read_text().splitlines()[-1], pathlib.Path(f"{logp}.claim").read_text()

            # The window stood down first: no request, the claim untouched.
            line, claim = guard("stood-down", "window pid=1 at=1\n")
            self.assertEqual((line, claim), ("sleep_refused cancelled", "window pid=1 at=1\n"))
            calls = (temp / "calls.log").read_text()
            self.assertNotIn("pmset sleepnow", calls)
            # Otherwise the guard holds it, by pid, right before its request.
            line, claim = guard("requested")
            self.assertRegex(line, r"^sleep_requested rc=0 at=[0-9]+ wake=at cause=ok ")
            self.assertRegex(claim, r"^guard pid=[0-9]+ at=[0-9]+\n$")
            self.assertEqual((temp / "calls.log").read_text().count("sudo -n /usr/bin/pmset sleepnow"), 1)

    def test_the_guard_helpers_classify_parse_and_bound_output(self):
        guard = self.sleep_guard_module()
        self.assertEqual(guard.classify(0, "Sleeping now...", ""), ("ok", ""))
        self.assertEqual(guard.classify(1, "", "sudo: a password is required\n"), ("sudo_no_credential", ""))
        self.assertEqual(guard.classify(1, "", "other"), ("other", ""))
        self.assertEqual(guard.classify(71, "Unable to sleep system: error 0xE00002E2\n", ""),
                         ("pmset_not_permitted", "0xe00002e2"))
        self.assertEqual(guard.classify(77, "Sleep error 0xe00002c1; You must run this as root.", ""),
                         ("pmset_not_root", "0xe00002c1"))
        self.assertEqual(guard.classify("timeout", "", ""), ("timeout", ""))
        self.assertEqual(guard.classify("error", "", "x"), ("other", ""))
        # 64 KiB of output, control characters and addresses: one bounded line.
        noisy = ("x" * 70000 + "\n").encode()
        self.assertEqual(guard.bounded(noisy), "x" * 200)
        line = guard.bounded(b"a\x01b\tc\nnext [bracket] 10.0.0.1 2001:db8::5 aa-bb-cc-dd-ee-ff 11:13:54 \xff")
        self.assertEqual(line, "a?b?c | next (bracket) <ipv4> <ipv6> <mac> 11:13:54 ?")
        # v30 review: the shapes the docstring promises but the v30 patterns
        # missed, and a time of day that stays.
        for text, masked in (
                ("from 192.0.2.7.", "from <ipv4>."),
                ("addr 192.0.2.7.5353 >", "addr <ipv4>.5353 >"),
                ("x 10.0.0.1:443", "x <ipv4>:443"),
                ("mapped ::ffff:192.0.2.7", "mapped <ipv6>:<ipv4>"),
                ("nat64 64:ff9b::192.0.2.33 ok", "nat64 <ipv6><ipv4> ok"),
                ("full 2001:db8:1:2:3:4:5:6: refused", "full <ipv6>: refused"),
                ("full 2001:db8:1:2:3:4:5:6", "full <ipv6>"),
                ("zone fe80::1%en0, ok", "zone <ipv6>, ok"),
                ("dot 2001:db8::1.", "dot <ipv6>."),
                ("in addr.fe80::1", "in addr.<ipv6>"),
                ("bracket [fe80::1]:5353", "bracket (<ipv6>):5353"),
                ("mac 02:00:00:00:00:07: x", "mac <mac>: x"),
                ("mac 02:00:00:00:00:07.", "mac <mac>."),
                ("dash x-aa-bb-cc-dd-ee-ff", "dash x-<mac>"),
                ("at 11:13:54: done", "at 11:13:54: done"),
                ("Unable to sleep system: error 0xe00002e2", "Unable to sleep system: error 0xe00002e2")):
            with self.subTest(text=text):
                self.assertEqual(guard.bounded(text), masked)
        for address in ("192.0.2.7", "192.0.2", "0.2.7", "2001:db8", "fe80::1", "02:00:00:00:00:07"):
            self.assertNotIn(address, guard.bounded("a 192.0.2.7. b ::ffff:192.0.2.7 c 2001:db8:1:2:3:4:5:6: "
                                                    "d fe80::1%en0 e 02:00:00:00:00:07:"))
        self.assertTrue(all(" " <= c <= "~" for c in line))
        self.assertLessEqual(len(guard.bounded("y" * 500, 50)), 50)
        self.assertEqual(guard.bounded(None), "")
        # SleepDisabled from `pmset -g` (the live one too, read-only).
        with tempfile.TemporaryDirectory(prefix="aegis-sleep-guard-") as temp:
            fake = pathlib.Path(temp) / "pmset"
            fake.write_text("#!/bin/sh\nprintf '%b' \"$OUT\"\nexit \"${RC:-0}\"\n")
            fake.chmod(0o755)

            def disabled(out, rc="0"):
                r = subprocess.run([SYSTEM_PY, "-I", str(SLEEP_GUARD), "disabled", str(fake)],
                                   capture_output=True, text=True, env={"OUT": out, "RC": rc}, timeout=30)
                return r.stdout.strip()

            block = "System-wide power settings:\\n SleepDisabled\\t\\t%s\\nCurrently in use:\\n sleep 0\\n"
            self.assertEqual(disabled(block % "1"), "1")
            self.assertEqual(disabled(block % "0"), "0")
            self.assertEqual(disabled(block % "yes"), "unknown")
            self.assertEqual(disabled("System-wide power settings:\\nCurrently in use:\\n SleepDisabled 1\\n"), "0")
            self.assertEqual(disabled("Currently in use:\\n sleep 0\\n"), "unknown")
            self.assertEqual(disabled(block % "0", rc="1"), "unknown")
        live = subprocess.run([SYSTEM_PY, "-I", str(SLEEP_GUARD), "disabled", "/usr/bin/pmset"],
                              capture_output=True, text=True, timeout=30)
        self.assertIn(live.stdout.strip(), ("0", "1"))
        r = subprocess.run([SYSTEM_PY, "-I", str(SLEEP_GUARD), "text"], input=b"rc 1\n10.1.2.3\n",
                           capture_output=True, timeout=30)
        self.assertEqual(r.stdout, b"rc 1 | <ipv4>\n")

    # ------------------------------------------------------------- IFSWITCH=1

    @staticmethod
    def plug(root, proc):
        # v33: the moment of the owner's action, for fake_timeline.
        (root / "world" / "route_at").write_text(f"{time.time():.3f}\n")
        (root / "world" / "en7").write_text("active\n")
        (root / "world" / "primary").write_text("en7\n")

    @staticmethod
    def unplug(root, proc):
        (root / "world" / "route_at").write_text(f"{time.time():.3f}\n")
        (root / "world" / "en7").write_text("inactive\n")
        (root / "world" / "primary").write_text("en0\n")

    def test_ifswitch_refusals_happen_before_the_lock_the_captures_and_any_connect(self):
        for world, extra, reason in (
                ({}, {"FAKE_NO_EN7": "1"}, "0 interfaces to switch to from en0 (Wi-Fi), not one: set IFSWITCH_TO"),
                ({}, {"FAKE_EN8": "1"}, "2 interfaces to switch to from en0 (Wi-Fi), not one: set IFSWITCH_TO"),
                ({"en7": "active"}, {}, "en7 (USB 10/100/1000 LAN) is already active but not the primary: "
                                        "unplug its cable before the window"),
                ({}, {"IFSWITCH_TO": "en0"}, "IFSWITCH_TO=en0 is the physical default interface"),
                ({}, {"IFSWITCH_TO": "en9", "IFSWITCH_ATTACH_WAIT_S": "0"}, "IFSWITCH_TO=en9 is no hardware port"),
                ({}, {"IFSWITCH_ATTACH_WAIT_S": "181"}, "IFSWITCH_ATTACH_WAIT_S=181 is outside 0..180"),
                ({}, {"IFSWITCH_ATTACH_SETTLE_S": "1"}, "IFSWITCH_ATTACH_SETTLE_S=1 is outside 2..30"),
                # v30: a link without an address yet (the cable already in).
                ({"en7": "link"}, {}, "en7 (USB 10/100/1000 LAN) has a link already (status: active): take the "
                                      "cable out of the adapter before the window"),
                ({"en7": None}, {}, "en7 is not present (attach the adapter first)"),
                ({"primary": "en7", "en7": "active", "en0": "inactive"}, {},
                 "en0 (Wi-Fi) has no active IPv4 address: unplugging en7 would leave no route"),
                ({}, {"IFSWITCH_BOUND_S": "4"}, "IFSWITCH_BOUND_S=4 is outside 5..600"),
                ({}, {"IFSWITCH_RECOVER_S": "301"}, "IFSWITCH_RECOVER_S=301 is outside 5..300"),
                # v33: the settle gate's quiet period, below the bound it shares.
                ({}, {"IFSWITCH_SETTLE_QUIET_S": "1"}, "IFSWITCH_SETTLE_QUIET_S=1 is outside 2..30"),
                ({}, {"IFSWITCH_SETTLE_QUIET_S": "31"}, "IFSWITCH_SETTLE_QUIET_S=31 is outside 2..30"),
                # v33 review: and at least 6 s below it, or a switch that
                # rebuilds could never settle (5 of 8 accepted before).
                ({}, {"IFSWITCH_SETTLE_QUIET_S": "10", "IFSWITCH_RECOVER_S": "10"},
                 "IFSWITCH_SETTLE_QUIET_S=10 leaves under 6s of IFSWITCH_RECOVER_S=10, which the settle gate shares "
                 "(no read in its last second, about one a second, a rebuild up to 4s after the route change): use "
                 "IFSWITCH_RECOVER_S of at least 16"),
                ({}, {"IFSWITCH_SETTLE_QUIET_S": "5", "IFSWITCH_RECOVER_S": "8"},
                 "IFSWITCH_SETTLE_QUIET_S=5 leaves under 6s of IFSWITCH_RECOVER_S=8, which the settle gate shares "
                 "(no read in its last second, about one a second, a rebuild up to 4s after the route change): use "
                 "IFSWITCH_RECOVER_S of at least 11"),
                ({}, {"IFSWITCH_SETTLE_QUIET_S": "2", "IFSWITCH_RECOVER_S": "7"},
                 "IFSWITCH_SETTLE_QUIET_S=2 leaves under 6s of IFSWITCH_RECOVER_S=7, which the settle gate shares "
                 "(no read in its last second, about one a second, a rebuild up to 4s after the route change): use "
                 "IFSWITCH_RECOVER_S of at least 8"),
                ({}, {"OM_PY": "/nonexistent/python3"},
                 "no settle judge (/nonexistent/python3 or harness/settle_judge.py missing)"),
                ({}, {"NETWORKSETUP": "no-such-networksetup"}, "networksetup not found"),
                # Plugging in moves the primary only from a lower-ranked service.
                ({}, {"FAKE_SERVICE_ORDER": "wifi_first"},
                 "the en7 service (order 2) ranks below the en0 service (order 1) in networksetup "
                 "-listnetworkserviceorder: plugging in would not move the primary; move it above first"),
                ({}, {"FAKE_SERVICE_ORDER": "en7_disabled"},
                 "en7 (USB 10/100/1000 LAN) has no enabled network service in networksetup -listnetworkserviceorder"),
                # The captures' root alarm needs perl through sudo -n.
                ({}, {"LEAK_CAPTURE": "1", "FAKE_SUDO_PERL": "0"},
                 "LEAK_CAPTURE=1 needs sudo -n for /usr/bin/perl (the captures' wall-clock bound; run sudo -v first)")):
            with self.subTest(world=world, extra=extra):
                rc, stdout, rows, names, calls, root = self.run_window(world=world, IFSWITCH="1", **extra)
                self.assert_refused_untouched(rc, stdout, rows, calls, root, "IFSWITCH=1", reason)
        # A second capture that does not start refuses before connect and
        # stops the first one.
        rc, stdout, rows, names, calls, root = self.run_window(IFSWITCH="1", LEAK_CAPTURE="1",
                                                               FAKE_TCPDUMP_FAIL_IF="en7")
        self.assertEqual(rc, 3, stdout)
        self.assertIn("refused: tcpdump on en7 did not start: tcpdump: en7: You don't have permission", stdout)
        self.assertFalse([c for c in calls if c.startswith("host ")], calls)
        self.assertFalse((root / "out" / "rollback.log").exists())
        self.assertFalse((root / "home" / ".aegis-local" / "locks" / "timing-self").exists())
        self.assertIn("tcpdump stopped if=en0", calls)
        self.assertEqual(rows["capture_stopped"][0], "pass")
        self.assertNotIn("ifswitch_capture_started", rows)

    def test_a_plug_switch_recovers_and_both_captures_are_reviewed(self):
        rc, stdout, rows, names, calls, root = self.run_window(
            when=("window.log", "OWNER ACTION", self.plug), IFSWITCH="1", LEAK_CAPTURE="1", IFSWITCH_BOUND_S="60",
            IFSWITCH_RECOVER_S="10", IFSWITCH_SETTLE_QUIET_S="2", FAKE_PROVIDER_TIMELINE=REPIN_TO_EN7)
        out = root / "out"
        self.assertEqual(rc, 0, stdout)
        self.assertIn("IFSWITCH=1: from=en0 to=en7 direction=plug rollback_s=40 capture_bound_s=100", stdout)
        # Both captures start under the root alarm, 30 s past their -G bound.
        alarm = f"sudo -n /usr/bin/perl -e {owner_alarm_code()} 130 "
        first = calls.index(f"{alarm}/usr/sbin/tcpdump -i en0 -p -s 160 -B 4096 -G 100 -W 1 -U -w {out}/physical.pcap")
        second = calls.index(f"{alarm}/usr/sbin/tcpdump -i en7 -p -s 160 -B 4096 -G 100 -W 1 -U -w "
                             f"{out}/physical-en7.pcap")
        self.assertFalse([c for c in calls if c.startswith("sudo -n /usr/sbin/tcpdump")], calls)
        self.assertLess(calls.index("sudo -n -l /usr/bin/perl"), first)
        connect = next(i for i, c in enumerate(calls) if c.startswith("host --connect"))
        stop = next(i for i, c in enumerate(calls) if c.startswith("scutil --nc stop"))
        self.assertLess(first, second)
        self.assertLess(second, connect)
        self.assertLess(stop, calls.index("tcpdump stopped if=en0"))
        self.assertLess(stop, calls.index("tcpdump stopped if=en7"))
        self.assertIn("OWNER ACTION: plug the Ethernet cable into en7 (USB 10/100/1000 LAN) now", stdout)
        # v33: the settle gate between the recovery and the probes, and the
        # losses after it next to the provider's codes.
        order = ["ifswitch_capture_started", "ifswitch_preflight", "ifswitch_primary_before",
                 "ifswitch_status_during_switch", "ifswitch_route_changed", "ifswitch_recovered",
                 "ifswitch_settled_before_probes",
                 "ifswitch_whoami_egress", "ifswitch_udp_echo_v4", "ifswitch_tcp_echo_v4", "ifswitch_log_path_change",
                 "ifswitch_log_relay_interface_repinned", "ifswitch_log_relay_interface_repin_refused",
                 "ifswitch_log_session_lost", "ifswitch_log_session_rebuilt", "ifswitch_log_reasserting",
                 "ifswitch_rebuild_settled", "ifswitch_relay_path_exercised", "ifswitch_session_lost_by_repin",
                 "ifswitch_session_lost_after_settle", "ifswitch_leak_window_disconnect_at",
                 "ifswitch_capture_stopped", "ifswitch_leak_proof", "ifswitch_leak_capture_sha256"]
        self.assertEqual([n for n in names if n.startswith("ifswitch_")], order)
        self.assertEqual(rows["ifswitch_settled_before_probes"][0], "pass", rows["ifswitch_settled_before_probes"])
        self.assertRegex(rows["ifswitch_settled_before_probes"][1],
                         r"^settled_after=[0-9.]+s rebuilt_after=[0-9.]+s path_change_after=-?[0-9.]+s quiet=2s "
                         r"lost=1:relay_path_changed rebuilt=1 reads=[0-9]+ probes_after=[0-9.]+s bound=10s$")
        # v33 review: the plug as v33 should log it passes the switch rows.
        self.assertEqual(rows["ifswitch_session_lost_by_repin"][0], "pass", rows["ifswitch_session_lost_by_repin"])
        self.assertRegex(rows["ifswitch_session_lost_by_repin"][1],
                         r"^count=1 codes=relay_path_changed rebuilt_after=[0-9.]+s$")
        self.assertEqual(rows["ifswitch_session_lost_after_settle"][:2], ("info", "count=0 codes=none"))
        self.assertLess(names.index("ifswitch_relay_path_exercised"), names.index("disconnect_verified"))
        self.assertEqual(rows["ifswitch_preflight"][:2],
                         ("info", "from=en0(Wi-Fi) to=en7(USB 10/100/1000 LAN) direction=plug bound=60s recover_bound=10s"))
        self.assertEqual(rows["ifswitch_primary_before"][:2], ("pass", "en0"))
        self.assertEqual(rows["ifswitch_route_changed"][0], "pass", rows["ifswitch_route_changed"])
        self.assertRegex(rows["ifswitch_route_changed"][1], r"^en0->en7 after [0-9]+s expected=en7$")
        self.assertEqual(rows["ifswitch_recovered"][0], "pass", rows["ifswitch_recovered"])
        self.assertTrue(rows["ifswitch_recovered"][1].endswith(" if=en7"))
        for name in ("ifswitch_whoami_egress", "ifswitch_udp_echo_v4", "ifswitch_tcp_echo_v4"):
            self.assertEqual(rows[name][0], "pass", (name, rows[name]))
        self.assertEqual(rows["ifswitch_relay_path_exercised"][:2],
                         ("pass", "path_change=1 repinned_to_en7=1 rebuilt=1"))
        self.assertEqual(rows["ifswitch_rebuild_settled"][:2], ("pass", "reasserting_off"))
        # The disconnect gate follows the route to its new interface.
        self.assertEqual(rows["disconnect_verified"][:2], ("pass", "en7"))
        self.assertEqual(rows["disconnect_v6_route"][:2], ("pass", "en7 baseline=en0 or_switched=en7"))
        self.assertIn("rollback_cancelled", (out / "rollback.log").read_text())
        tcpdumps = [int(l.split()[1]) for l in (root / "fake.pids").read_text().splitlines() if l.startswith("tcpdump ")]
        self.assertEqual(len(tcpdumps), 2)
        self.assertIn(f"tcpdump={tcpdumps[1]} if=en7 file=physical-en7.pcap bound=100s alarm=130s",
                      rows["ifswitch_capture_started"][1])
        for pid in tcpdumps:
            self.assertIn(f"sudo -n /bin/kill -INT {pid}", calls)
        self.assertEqual(rows["capture_stopped"][0], "pass")
        self.assertEqual(rows["ifswitch_capture_stopped"][0], "pass")
        self.assertEqual(rows["ifswitch_leak_window_disconnect_at"][1], "capture_alive=1")
        self.assertEqual(rows["leak_proof"][0], "pass", rows["leak_proof"])
        self.assertEqual(rows["ifswitch_leak_proof"][0], "pass", rows["ifswitch_leak_proof"])
        self.assertTrue(rows["ifswitch_leak_proof"][1].startswith("if=en7 leak_review pass=true "))
        self.assertIn("capture_alive=1 capture_stopped=1 kernel_drops=0", rows["ifswitch_leak_proof"][1])
        report = json.loads((out / "leak-review-en7.json").read_text())
        self.assertTrue(report["pass"])
        self.assertEqual(report["local_mac"], "02:00:00:00:00:07")
        self.assertEqual(rows["ifswitch_leak_capture_sha256"][0],
                         hashlib.sha256((out / "physical-en7.pcap").read_bytes()).hexdigest())
        for text in ((out / "results.tsv").read_text(), (out / "window.log").read_text()):
            for address in ("10.0.7.50", "192.0.2.1", "2001:db8:1:2", "192.168.1.50"):
                self.assertNotIn(address, text)
        self.assertFalse((root / "home" / ".aegis-local" / "locks" / "timing-self").exists())
        # v31 review: rows that report a check made before an earlier row
        # start where the row before that check ended.
        fields = row_fields(out)
        assert_rows_chain(self, fields)
        times = row_times(fields)
        for name, shares in (("ifswitch_route_changed", "ifswitch_status_during_switch"),
                             ("leak_window_connected_at", "connected"),
                             ("leak_capture_ifaces", "capture_started"),
                             ("ifswitch_leak_window_disconnect_at", "leak_window_disconnect_at")):
            self.assertEqual(times[name][0], times[shares][0], name)
            self.assertLess(names.index(shares), names.index(name), name)

    def test_a_leak_on_the_switched_to_interface_fails_only_its_leak_proof(self):
        rc, stdout, rows, names, calls, root = self.run_window(
            when=("window.log", "OWNER ACTION", self.plug), IFSWITCH="1", LEAK_CAPTURE="1", IFSWITCH_RECOVER_S="10",
            FAKE_LEAK="1", FAKE_LEAK_IF="en7", IFSWITCH_SETTLE_QUIET_S="2",
            FAKE_PROVIDER_TIMELINE="+0.3 path_change name:en7")
        self.assertEqual(rows["ifswitch_leak_proof"][0], "fail", rows["ifswitch_leak_proof"])
        self.assertIn(" leaks=1 ", rows["ifswitch_leak_proof"][1])
        self.assertEqual(rows["leak_proof"][0], "pass", rows["leak_proof"])
        # A path change without a re-pin to en7 is not exercised, and (v33
        # review) without a session sealed by a re-pin the losses row fails.
        self.assertEqual(rows["ifswitch_relay_path_exercised"][0], "fail")
        self.assertIn("path_change=1 repinned_to_en7=0 rebuilt=0", rows["ifswitch_relay_path_exercised"][1])
        self.assertEqual(rows["ifswitch_session_lost_by_repin"][:2], (
            "fail", "count=0 codes=none rebuilt_after=none: no session_lost relay_path_changed, so no session was "
                    "sealed by a re-pin"))

    def test_an_unplug_switch_moves_back_to_wifi_and_the_gate_follows_it(self):
        log = ("+0.3 path_change name:en0;+0.3 relay_interface_repinned name:en7;+0.3 session_lost relay_path_changed;"
               "+1.2 session_rebuilt attempt:1")
        rc, stdout, rows, names, calls, root = self.run_window(
            when=("window.log", "OWNER ACTION", self.unplug), world={"primary": "en7", "en7": "active"},
            IFSWITCH="1", IFSWITCH_RECOVER_S="10", IFSWITCH_SETTLE_QUIET_S="2", FAKE_PROVIDER_TIMELINE=log)
        self.assertEqual(rc, 0, stdout)
        self.assertIn("OWNER ACTION: unplug the Ethernet cable from en7 (USB 10/100/1000 LAN) now "
                      "(the cable, not the adapter)", stdout)
        self.assertEqual(rows["ifswitch_preflight"][1].split(" bound=")[0],
                         "from=en7(USB 10/100/1000 LAN) to=en0(Wi-Fi) direction=unplug")
        self.assertRegex(rows["ifswitch_route_changed"][1], r"^en7->en0 after ")
        self.assertEqual(rows["ifswitch_route_changed"][0], "pass")
        self.assertTrue(rows["ifswitch_recovered"][1].endswith(" if=en0"), rows["ifswitch_recovered"])
        # A re-pin to the old interface is not counted, and (v33 review) a
        # rebuild without a re-pin to en0 no longer passes; the loss itself
        # was the re-pin's seal.
        self.assertEqual(rows["ifswitch_relay_path_exercised"][:2], (
            "fail", "path_change=1 repinned_to_en0=0 rebuilt=1: the provider recorded no path change or no re-pin to en0"))
        self.assertEqual(rows["ifswitch_session_lost_by_repin"][0], "pass", rows["ifswitch_session_lost_by_repin"])
        # v33: the probes waited for the rebuild and the quiet period after it.
        self.assertEqual(rows["ifswitch_settled_before_probes"][0], "pass", rows["ifswitch_settled_before_probes"])
        self.assertIn(" lost=1:relay_path_changed rebuilt=1 ", rows["ifswitch_settled_before_probes"][1])
        self.assertEqual(rows["disconnect_verified"][:2], ("pass", "en0"))
        # Wi-Fi has global IPv6: its IPv6 default is required, none is not enough.
        self.assertEqual(rows["disconnect_v6_route"][:2], ("pass", "en0 baseline=en7 or_switched=en0"))
        self.assertFalse([c for c in calls if c.startswith("sudo")], calls)
        # The unplug direction never reads the service order, and (v30)
        # never waits for an attach: the ports are listed once.
        self.assertNotIn("networksetup -listnetworkserviceorder", calls)
        self.assertEqual(calls.count("networksetup -listallhardwareports"), 1)

    def test_an_unplug_with_leak_capture_captures_the_target_once_and_reviews_every_interface(self):
        rc, stdout, rows, names, calls, root = self.run_window(
            when=("window.log", "OWNER ACTION", self.unplug), world={"primary": "en7", "en7": "active"},
            IFSWITCH="1", LEAK_CAPTURE="1", IFSWITCH_RECOVER_S="10", IFSWITCH_SETTLE_QUIET_S="2",
            FAKE_PROVIDER_TIMELINE=REBUILT_ON_EN0)
        out = root / "out"
        self.assertEqual(rc, 0, stdout)
        alarm = f"sudo -n /usr/bin/perl -e {owner_alarm_code()} "
        caps = [c.split(" -w ")[1] for c in calls if c.startswith(alarm) and " /usr/sbin/tcpdump -i " in c]
        # en0 is the switch's target and active before connect: one capture of it.
        self.assertEqual(caps, [f"{out}/physical.pcap", f"{out}/physical-en0.pcap"])
        self.assertNotIn("capture_started_en0", rows)
        self.assertEqual(rows["leak_capture_ifaces"][:2], ("info", "en7,en0"))
        self.assertEqual(rows["leak_proof"][0], "pass", rows["leak_proof"])
        self.assertEqual(rows["ifswitch_leak_proof"][0], "pass", rows["ifswitch_leak_proof"])
        self.assertNotIn("mac_sent", rows["ifswitch_leak_proof"][1] + rows["leak_proof"][1])
        self.assertEqual(rows["leak_proof_all_ifaces"][0], "pass", rows["leak_proof_all_ifaces"])
        self.assertEqual(rows["no_mac_sent_leak_physical"][:2], (
            "pass", "ifaces=en7,en0 en7:mac_sent_leaks=0,mac_sent_pass=true,alive=1,stopped=1,drops=0 "
                    "en0:mac_sent_leaks=0,mac_sent_pass=true,alive=1,stopped=1,drops=0 uncaptured=none"))
        self.assertTrue(json.loads((out / "leak-review-en0.json").read_text())["mac_sent_relay_required"])
        # v33 review: the unplug as window-v32-ifswitch-r4 logged it passes
        # the switch rows.
        self.assertEqual(rows["ifswitch_relay_path_exercised"][:2], ("pass", "path_change=1 repinned_to_en0=1 rebuilt=1"))
        self.assertEqual(rows["ifswitch_session_lost_by_repin"][0], "pass", rows["ifswitch_session_lost_by_repin"])
        self.assertRegex(rows["ifswitch_session_lost_by_repin"][1], r"^count=1 codes=relay_path_changed rebuilt_after=")

    def test_a_mac_sent_leak_on_the_switched_to_interface_fails_the_mac_sent_row(self):
        rc, stdout, rows, names, calls, root = self.run_window(
            when=("window.log", "OWNER ACTION", self.plug), IFSWITCH="1", LEAK_CAPTURE="1", IFSWITCH_RECOVER_S="10",
            FAKE_LEAK="1", FAKE_LEAK_IF="en7", FAKE_LEAK_SRC="10.0.7.50", IFSWITCH_SETTLE_QUIET_S="2",
            FAKE_PROVIDER_TIMELINE=REPIN_TO_EN7)
        self.assertEqual(rows["leak_capture_ifaces"][:2], ("info", "en0,en7"))
        self.assertEqual(rows["leak_proof"][0], "pass", rows["leak_proof"])
        self.assertEqual(rows["ifswitch_leak_proof"][0], "fail", rows["ifswitch_leak_proof"])
        self.assertEqual(rows["leak_proof_all_ifaces"][0], "fail")
        self.assertEqual(rows["no_mac_sent_leak_physical"][0], "fail", rows["no_mac_sent_leak_physical"])
        self.assertTrue(rows["no_mac_sent_leak_physical"][1].endswith(" uncaptured=none reason=en7:mac_sent_leaks=1"),
                        rows["no_mac_sent_leak_physical"])

    def test_an_unplug_onto_a_wifi_without_ipv6_expects_no_ipv6_default(self):
        rc, stdout, rows, names, calls, root = self.run_window(
            when=("window.log", "OWNER ACTION", self.unplug), world={"primary": "en7", "en7": "active"},
            IFSWITCH="1", IFSWITCH_RECOVER_S="10", FAKE_EN0_NO_V6="1", IFSWITCH_SETTLE_QUIET_S="2",
            FAKE_PROVIDER_TIMELINE=REBUILT_ON_EN0)
        self.assertEqual(rc, 0, stdout)
        self.assertEqual(rows["physical_v6_baseline"][1].split()[0], "default=en7")
        self.assertEqual(rows["disconnect_verified"][:2], ("pass", "en0"))
        self.assertEqual(rows["disconnect_v6_route"][:2], ("pass", "none baseline=en7 or_switched=en0 or_none"))

    def test_no_route_change_within_the_bound_fails_and_disconnects_on_the_old_route(self):
        rc, stdout, rows, names, calls, root = self.run_window(IFSWITCH="1", IFSWITCH_BOUND_S="5")
        self.assertEqual(rc, 0, stdout)
        self.assertEqual(rows["ifswitch_route_changed"][:2], ("fail", "no change from en0 within 5s"))
        self.assertEqual(rows["ifswitch_recovered"][:2], ("skip", "no route change"))
        self.assertEqual(rows["ifswitch_status_during_switch"][:2], ("info", "statuses=Connected primary=en0"))
        self.assertNotIn("ifswitch_relay_path_exercised", rows)
        # v33: no route change, no settle gate and no read of it.
        self.assertNotIn("ifswitch_settled_before_probes", rows)
        self.assertNotIn("log show settle_read", calls)
        self.assertEqual(rows["disconnect_verified"][:2], ("pass", "en0"))
        self.assertEqual(rows["disconnect_v6_route"][:2], ("pass", "en0 baseline=en0"))
        # When scutil --nwi does not name the physical primary while
        # Connected, the switch could not be observed: no owner action.
        rc, stdout, rows, names, calls, root = self.run_window(IFSWITCH="1", FAKE_NWI_HIDES_PHYS="1")
        self.assertEqual(rows["ifswitch_primary_before"][0], "fail")
        self.assertNotIn("OWNER ACTION", stdout)
        self.assertNotIn("ifswitch_route_changed", rows)
        self.assertEqual(rows["disconnect_verified"][:2], ("pass", "en0"))

    def test_a_window_killed_while_waiting_for_the_owner_leaves_both_captures_under_their_alarm(self):
        rc, stdout, rows, names, calls, root = self.run_window(
            when=("window.log", "OWNER ACTION", lambda root, proc: proc.kill()), IFSWITCH="1", LEAK_CAPTURE="1",
            ROLLBACK_S="30")
        self.assertEqual(rc, -9)
        out = root / "out"
        # The rollback's kill is best effort; the alarm bounds both anyway.
        alarm = f"sudo -n /usr/bin/perl -e {owner_alarm_code()} "
        self.assertEqual(len([c for c in calls if c.startswith(alarm) and " /usr/sbin/tcpdump -i " in c]), 2, calls)
        self.assertTrue(self.wait_for(out / "rollback.log", "rollback_done", 60))
        tcpdumps = [int(l.split()[1]) for l in (root / "fake.pids").read_text().splitlines() if l.startswith("tcpdump ")]
        self.assertEqual(len(tcpdumps), 2)
        log = (out / "rollback.log").read_text()
        for pid in tcpdumps:
            self.assertIn(f"capture_stop_requested pid={pid} rc=0", log)
        for iface in ("en0", "en7"):
            self.assertTrue(self.wait_for(root / "calls.log", f"tcpdump stopped if={iface}", 20), iface)
        self.assertEqual((root / "state").read_text().strip(), "Disconnected")

    def test_the_capture_alarm_ends_a_program_that_never_exits_by_itself(self):
        # The window's own alarm code, kept across exec as on a link that
        # never sees a packet.
        started = time.monotonic()
        r = subprocess.run(["/usr/bin/perl", "-e", owner_alarm_code(), "1", "/bin/sleep", "30"], timeout=20)
        self.assertEqual(r.returncode, -signal.SIGALRM)
        self.assertLess(time.monotonic() - started, 10)
        r = subprocess.run(["/usr/bin/perl", "-e", owner_alarm_code(), "5", "/usr/bin/true"], timeout=20)
        self.assertEqual(r.returncode, 0)
        r = subprocess.run(["/usr/bin/perl", "-e", owner_alarm_code(), "5", "/nonexistent/tcpdump"], timeout=20)
        self.assertEqual(r.returncode, 127)

    # ------------------------------------------- IFSWITCH=1 v33 settle gate

    SETTLE_ROW = "ifswitch_settled_before_probes"
    # window-v32-ifswitch-r3 replayed, after the owner's plug: the path
    # change at +0.5 s, the session lost by lease expiry at +1.97 s (after
    # ifswitch_recovered had passed there) and rebuilt at +3.79 s.
    R3_TIMELINE = ("+0.5 path_change name:en7;+1.97 session_lost capture_lease_expired;+1.97 reasserting on;"
                   "+2.0 session_rebuild attempt:1 backoff_ms:381;+2.46 relay_interface name:en0;"
                   "+3.79 session_rebuilt attempt:1;+3.79 reasserting off")

    def settle_window(self, timeline, recover="20", **extra):
        return self.run_window(when=("window.log", "OWNER ACTION", self.plug), IFSWITCH="1",
                               IFSWITCH_RECOVER_S=recover, FAKE_PROVIDER_TIMELINE=timeline, **extra)

    @staticmethod
    def settle_numbers(detail):
        return {k: float(v) for k, v in re.findall(r"([a-z_]+_after)=(-?[0-9.]+)s", detail)}

    @staticmethod
    def route_at(root):
        return datetime.datetime.fromtimestamp(float((root / "world" / "route_at").read_text()),
                                               datetime.timezone.utc)

    def assert_gate_then_probes(self, rows, names, root):
        """The gate's row comes right after the recovery and right before the
        probes, which start where it ended and still run and are judged."""
        i = names.index(self.SETTLE_ROW)
        self.assertEqual(names[i - 1:i + 4], ["ifswitch_recovered", self.SETTLE_ROW, "ifswitch_whoami_egress",
                                              "ifswitch_udp_echo_v4", "ifswitch_tcp_echo_v4"])
        times = row_times(row_fields(root / "out"))
        self.assertEqual(times["ifswitch_whoami_egress"][0], times[self.SETTLE_ROW][1])
        for name in ("ifswitch_whoami_egress", "ifswitch_udp_echo_v4", "ifswitch_tcp_echo_v4"):
            self.assertEqual(rows[name][0], "pass", (name, rows[name]))
        return times

    def test_the_settle_gate_holds_the_probes_until_a_late_loss_is_rebuilt_and_quiet(self):
        rc, stdout, rows, names, calls, root = self.settle_window(self.R3_TIMELINE)
        out = root / "out"
        self.assertEqual(rc, 0, stdout)
        verdict, detail, _status = rows[self.SETTLE_ROW]
        self.assertEqual(verdict, "pass", detail)
        self.assertRegex(detail, r"^settled_after=[0-9.]+s rebuilt_after=[0-9.]+s path_change_after=-?[0-9.]+s quiet=5s "
                                 r"lost=1:capture_lease_expired rebuilt=1 reads=[0-9]+ probes_after=[0-9.]+s bound=20s$")
        n = self.settle_numbers(detail)
        # The default quiet period after the rebuild; the window saw the
        # route move at most a poll or so after the hook's action.
        self.assertAlmostEqual(n["settled_after"], n["rebuilt_after"] + 5, delta=0.002)
        self.assertLessEqual(n["rebuilt_after"], 3.791)
        self.assertGreater(n["rebuilt_after"], 3.79 - 1.5)
        self.assertGreaterEqual(n["probes_after"], n["settled_after"] - 0.05)
        times = self.assert_gate_then_probes(rows, names, root)
        route_at = self.route_at(root)
        # ifswitch_recovered passed before the rebuild; the probes waited
        # for it and the quiet period after it.
        self.assertEqual(rows["ifswitch_recovered"][0], "pass")
        self.assertLess(times["ifswitch_recovered"][1], route_at + datetime.timedelta(seconds=3.79))
        self.assertGreaterEqual(times["ifswitch_whoami_egress"][0], route_at + datetime.timedelta(seconds=3.79 + 5))
        self.assertEqual(rows["ifswitch_session_lost_after_settle"][:2], ("info", "count=0 codes=none"))
        # v33 review: the probes passing after the gate do not pass the
        # switch. The stale en0 pin (no re-pin to en7) and the loss by lease
        # expiry each fail a row, as whoami alone did on v32.
        self.assertEqual(rows["ifswitch_relay_path_exercised"][:2], (
            "fail", "path_change=1 repinned_to_en7=0 rebuilt=1: the provider recorded no path change or no re-pin to en7"))
        self.assertEqual(rows["ifswitch_session_lost_by_repin"][0], "fail", rows["ifswitch_session_lost_by_repin"])
        self.assertRegex(rows["ifswitch_session_lost_by_repin"][1],
                         r"^count=1 codes=capture_lease_expired rebuilt_after=[0-9]\.[0-9]{3}s: a session_lost other than the "
                         r"re-pin's relay_path_changed$")
        self.assertEqual(rows["ifswitch_rebuild_settled"][:2], ("pass", "reasserting_off"))
        # Every read asked for the provider process only and is traced; the
        # last one settled and is kept.
        reads = calls.count("log show settle_read")
        self.assertIn(f" reads={reads} ", detail)
        self.assertGreaterEqual(reads, 3)
        trace = (out / "ifswitch_settle.trace").read_text().splitlines()
        self.assertEqual(len(trace), reads)
        self.assertTrue(all(re.match(r"^at_ms=[0-9]+ rc=0 read_ms=[0-9]+ settled=[01] ", line) for line in trace), trace)
        self.assertEqual([" settled=1 " in line for line in trace], [False] * (reads - 1) + [True])
        self.assertIn("] aegis-ne session_rebuilt attempt:1", (out / "ifswitch_settle.log").read_text())
        for text in ((out / "results.tsv").read_text(), (out / "window.log").read_text()):
            for address in ("10.0.7.50", "192.0.2.1", "2001:db8:1:2", "192.168.1.50"):
                self.assertNotIn(address, text)

    def test_a_switch_without_a_loss_settles_after_the_quiet_period_and_the_bounds_are_unchanged(self):
        # ROLLBACK_S unset: the rollback and the capture bound grow exactly
        # as on v32 (window-v32-ifswitch-r3: bound=520s); the gate shares
        # IFSWITCH_RECOVER_S.
        rc, stdout, rows, names, calls, root = self.settle_window(
            NO_LOSS_TO_EN7, recover="60", IFSWITCH_SETTLE_QUIET_S="2", ROLLBACK_S="")
        self.assertEqual(rc, 0, stdout)
        self.assertIn("IFSWITCH=1: from=en0 to=en7 direction=plug rollback_s=460 capture_bound_s=520", stdout)
        verdict, detail, _status = rows[self.SETTLE_ROW]
        self.assertEqual(verdict, "pass", detail)
        self.assertRegex(detail, r"^settled_after=[0-9.]+s no_loss path_change_after=-?[0-9.]+s quiet=2s lost=0:none "
                                 r"rebuilt=0 reads=[0-9]+ probes_after=[0-9.]+s bound=60s$")
        n = self.settle_numbers(detail)
        # Two seconds after the route change (or the later path change).
        self.assertGreaterEqual(n["settled_after"], 2.0)
        self.assertLessEqual(n["settled_after"], 2.301)
        self.assert_gate_then_probes(rows, names, root)
        self.assertEqual(rows["ifswitch_relay_path_exercised"][:2], ("pass", "path_change=1 repinned_to_en7=1 rebuilt=0"))
        # v33 review: a re-pin that sealed no session is not what a running
        # v33 epoch does.
        self.assertEqual(rows["ifswitch_session_lost_by_repin"][0], "fail", rows["ifswitch_session_lost_by_repin"])
        self.assertIn("rollback_cancelled", (root / "out" / "rollback.log").read_text())

    def test_a_plug_whose_follow_did_not_happen_fails_the_switch_rows_while_every_probe_passes(self):
        """v33 review: the gate waits out any rebuilt loss before the probes,
        so they pass after an r3-like outage. The switch rows must not: a
        refused re-pin and the r3 lease expiry, a re-pin that came only
        after the lease ran out, and a lease expiry after a good re-pin."""
        repin_refused = ("+0.5 path_change name:en7;+0.5 relay_interface_repin_refused relay_interface_unresolved;"
                         "+1.97 session_lost capture_lease_expired;+1.97 reasserting on;+2.46 relay_interface name:en0;"
                         "+3.79 session_rebuilt attempt:1;+3.79 reasserting off")
        late_repin = ("+0.5 path_change name:en7;+1.0 session_lost capture_lease_expired;+1.0 reasserting on;"
                      "+1.2 relay_interface_repinned name:en7;+1.6 relay_interface name:en7;"
                      "+2.5 session_rebuilt attempt:1;+2.5 reasserting off")
        lost_again = REPIN_TO_EN7 + (";+2.0 session_lost capture_lease_expired;+2.0 reasserting on;"
                                     "+3.0 session_rebuilt attempt:1;+3.0 reasserting off")
        for name, timeline, exercised, lost in (
                ("repin_refused", repin_refused,
                 ("fail", "path_change=1 repinned_to_en7=0 rebuilt=1: the provider recorded no path change or no "
                          "re-pin to en7"),
                 r"^count=1 codes=capture_lease_expired rebuilt_after=[0-9]\.[0-9]{3}s: a session_lost other than the "
                 r"re-pin's relay_path_changed$"),
                ("late_repin", late_repin, ("pass", "path_change=1 repinned_to_en7=1 rebuilt=1"),
                 r"^count=1 codes=capture_lease_expired rebuilt_after=[0-9.]+s: a session_lost other than "),
                ("lost_again", lost_again, ("pass", "path_change=1 repinned_to_en7=1 rebuilt=2"),
                 r"^count=2 codes=relay_path_changed,capture_lease_expired rebuilt_after=[0-9.]+s: a session_lost "
                 r"other than ")):
            with self.subTest(name):
                rc, stdout, rows, names, calls, root = self.settle_window(
                    timeline, recover="10", IFSWITCH_SETTLE_QUIET_S="2")
                self.assertEqual(rc, 0, stdout)
                self.assertEqual(rows[self.SETTLE_ROW][0], "pass", rows[self.SETTLE_ROW])
                self.assert_gate_then_probes(rows, names, root)
                self.assertEqual(rows["ifswitch_rebuild_settled"][:2], ("pass", "reasserting_off"))
                self.assertEqual(rows["ifswitch_relay_path_exercised"][:2], exercised)
                self.assertEqual(rows["ifswitch_session_lost_by_repin"][0], "fail", rows["ifswitch_session_lost_by_repin"])
                self.assertRegex(rows["ifswitch_session_lost_by_repin"][1], lost)
                # Every loss came before the release: none after it.
                self.assertEqual(rows["ifswitch_session_lost_after_settle"][:2], ("info", "count=0 codes=none"))

    def test_a_loss_logged_after_the_releasing_read_but_before_the_release_counts_after_the_settle(self):
        """v33 review: the after-settle row starts at the newest line the
        releasing read held, not at OM_SETTLED_MS: a loss logged while the
        judge and om_up ran, which neither the gate nor the old row saw, is
        shown next to the probes, and it fails the losses row."""
        late = ("+0.005 session_lost capture_lease_expired;+0.005 reasserting on;"
                "+1.5 session_rebuilt attempt:1;+1.5 reasserting off")
        rc, stdout, rows, names, calls, root = self.settle_window(
            REPIN_TO_EN7, recover="10", IFSWITCH_SETTLE_QUIET_S="2", FAKE_AFTER_SETTLE_TIMELINE=late)
        out = root / "out"
        self.assertEqual(rc, 0, stdout)
        verdict, detail, _status = rows[self.SETTLE_ROW]
        self.assertEqual(verdict, "pass", detail)
        self.assertIn(" lost=1:relay_path_changed rebuilt=1 ", detail)
        self.assertEqual(rows["ifswitch_session_lost_after_settle"][:2], ("info", "count=1 codes=capture_lease_expired"))
        self.assertEqual(rows["ifswitch_session_lost_by_repin"][0], "fail", rows["ifswitch_session_lost_by_repin"])
        self.assertTrue(rows["ifswitch_session_lost_by_repin"][1].startswith(
            "count=2 codes=relay_path_changed,capture_lease_expired "), rows["ifswitch_session_lost_by_repin"])
        # The loss is stamped after the newest line of the releasing read
        # and before the probes started: inside the gap the old row missed.
        last = (out / "ifswitch_settle.trace").read_text().splitlines()[-1]
        self.assertIn(" settled=1 ", last)
        covered = int(re.search(r" covered_ms=([0-9]+)", last).group(1))
        line = next(l for l in (out / "ifswitch_provider.log").read_text().splitlines()
                    if "aegis-ne session_lost capture_lease_expired" in l)
        lost_ms = SettleJudgeTests.local_ms(line[:23])
        self.assertGreater(lost_ms, covered)
        self.assertNotIn("capture_lease_expired", (out / "ifswitch_settle.log").read_text())
        times = row_times(row_fields(out))
        self.assertLess(lost_ms, times["ifswitch_whoami_egress"][0].timestamp() * 1000)

    def test_a_rebuild_that_never_settles_fails_the_gate_at_its_bound_and_the_window_still_disconnects(self):
        lost = "+0.3 path_change name:en7;+0.6 session_lost capture_lease_expired;+0.6 reasserting on"
        flapping = lost + "".join(f";+{t:.1f} session_rebuilt attempt:1;+{t:.1f} reasserting off;"
                                  f"+{t + 0.6:.1f} session_lost relay_path_changed;+{t + 0.6:.1f} reasserting on"
                                  for t in (1.5, 3.0, 4.5, 6.0, 7.5, 9.0, 10.5, 12.0))
        for name, timeline, extra, want in (
                # Lost and never rebuilt, beside another process's rebuild
                # lines (a cargo test binary of this crate): still pending.
                ("pending", lost, {"FAKE_FOREIGN_TIMELINE": "+1.0 session_rebuilt attempt:1;+1.0 reasserting off"},
                 r"pending=1 lost=1:capture_lease_expired rebuilt=0 path_change=1 settled_after=[0-9.]+s "),
                # Rebuilt and lost again every 1.5 s: never 2 s of quiet.
                ("flapping", flapping, {}, r"lost=[4-9]:capture_lease_expired,relay_path_changed rebuilt=[3-9] "
                                           r"path_change=1 ")):
            with self.subTest(name):
                rc, stdout, rows, names, calls, root = self.settle_window(
                    timeline, recover="8", IFSWITCH_SETTLE_QUIET_S="2", **extra)
                self.assertEqual(rc, 0, stdout)
                verdict, detail, _status = rows[self.SETTLE_ROW]
                self.assertEqual(verdict, "fail", detail)
                self.assertRegex(detail, r"^not settled within 8s of the route change: pending=[01] ")
                self.assertRegex(detail, want)
                self.assertRegex(detail, r" reads=([2-9]|[1-9][0-9]) failed_reads=0 up=1 status=Connected waited=[0-9]+s$")
                # The probes still run after the row, the window disconnects
                # and nothing is left behind.
                times = row_times(row_fields(root / "out"))
                self.assertEqual(names[names.index(self.SETTLE_ROW) + 1], "ifswitch_whoami_egress")
                route_at = self.route_at(root)
                self.assertGreaterEqual(times[self.SETTLE_ROW][1], route_at + datetime.timedelta(seconds=7))
                self.assertLessEqual(times[self.SETTLE_ROW][1], route_at + datetime.timedelta(seconds=8 + 3))
                self.assertNotIn("ifswitch_session_lost_after_settle", rows)
                self.assertEqual(rows["disconnect_verified"][:2], ("pass", "en7"))
                self.assertIn("rollback_cancelled", (root / "out" / "rollback.log").read_text())
                self.assertFalse((root / "home" / ".aegis-local" / "locks" / "timing-self").exists())
                # (ifswitch_rebuild_settled, read after the probes, still
                # takes every process's lines: the foreign `reasserting off`
                # passes it there, which the gate does not accept.)

    def test_a_silent_provider_failed_or_hung_reads_and_a_session_failure_never_settle(self):
        # v33 review: 8 s, the shortest bound a 2 s quiet period is accepted
        # with (6 s before).
        for name, timeline, extra, want in (
                # The provider logs nothing after +0.5 s: nothing shows the
                # quiet period was not missed.
                ("silent", "+0.3 path_change name:en7", {"FAKE_PROVIDER_SILENT_AFTER": "1.5"},
                 r"^not settled within 8s of the route change: pending=0 lost=0:none rebuilt=0 path_change=1 "
                 r"settled_after=2\.[0-9]+s covered_after=[01]\.[0-9]+s reads=[2-9] failed_reads=0 "),
                # Every read fails: a failed read never settles.
                ("failed_reads", REPIN_TO_EN7, {"FAKE_SETTLE_FAIL_READS": "1000"},
                 r"^not settled within 8s of the route change: .* reads=([2-9]) failed_reads=\1 "),
                # Every read hangs: each is bounded by the time left (at most
                # 10 s), and none starts with under 1 s left.
                ("hung_reads", REPIN_TO_EN7, {"FAKE_SETTLE_HANG": "1"},
                 r"^not settled within 8s of the route change: pending=0 lost=0:none rebuilt=0 path_change=0 "
                 r"settled_after=2\.000s covered_after=none reads=1 failed_reads=1 "),
                # A terminal failure fails the gate at once.
                ("session_failed", "+0.3 path_change name:en7;+1.0 session_failed identity_tampered", {},
                 r"^session_failed:identity_tampered after [0-9.]+s reads=[1-9]$")):
            with self.subTest(name):
                recover = "20" if name == "session_failed" else "8"
                rc, stdout, rows, names, calls, root = self.settle_window(
                    timeline, recover=recover, IFSWITCH_SETTLE_QUIET_S="2", **extra)
                self.assertEqual(rc, 0, stdout)
                verdict, detail, _status = rows[self.SETTLE_ROW]
                self.assertEqual(verdict, "fail", detail)
                self.assertRegex(detail, want)
                self.assertEqual(names[names.index(self.SETTLE_ROW) + 1], "ifswitch_whoami_egress")
                times = row_times(row_fields(root / "out"))
                route_at = self.route_at(root)
                bound = 1.0 + 3 if name == "session_failed" else 8 + 2.5
                self.assertLessEqual(times[self.SETTLE_ROW][1], route_at + datetime.timedelta(seconds=bound))
                self.assertEqual(rows["disconnect_verified"][:2], ("pass", "en7"))
                if name == "hung_reads":
                    # Its alarm ended it (rc 142); the trace says so.
                    self.assertRegex((root / "out" / "ifswitch_settle.trace").read_text(), r"^at_ms=[0-9]+ rc=142 ")

    def run_settle(self, recovered="1", left_ms=None, **env):
        """om_settle alone (owner-modes.sh sourced after netloss.sh, a stub
        result), Connected on en7, with LEFT_MS of IFSWITCH_RECOVER_S=10
        left since the route change."""
        root, base = self.setup_world(primary="en7", en7="active")
        (root / "state").write_text("Connected\n")
        base.update(env, IFSWITCH_RECOVER_S="10")
        harness = PACKAGE / "harness"
        script = (f". '{NETLOSS_SH}'\n. '{OWNER_MODES_SH}'\nHARNESS_DIR='{harness}' SID=fake\nmkdir -p \"$OUT\"\n"
                  "result() { printf '%s\\t%s\\t%s\\n' \"$1\" \"$2\" \"$3\"; }\n"
                  f"now=$(om_ms)\nOM_ASK_MS=$((now - 3000)) OM_ROUTE_MS=$((now - 10000 + {left_ms}))\n"
                  f"OM_RECOVERED={recovered}\nom_settle ifswitch_ '2026-10-27 00:00:00' en7\n")
        started = time.monotonic()
        res = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, env=base, timeout=60)
        calls = (root / "calls.log").read_text().splitlines()
        return res, time.monotonic() - started, calls, root

    def test_the_settle_gate_starts_no_read_without_a_second_left_and_bounds_each_by_what_is_left(self):
        # Not recovered: skipped, nothing read.
        res, took, calls, root = self.run_settle(recovered="0", left_ms=9000)
        self.assertEqual(res.stdout, "ifswitch_settled_before_probes\tskip\tnot recovered\n", res.stderr)
        self.assertNotIn("log show settle_read", calls)
        # The recovery used the bound up: under 1 s left, no read starts.
        res, took, calls, root = self.run_settle(left_ms=600)
        self.assertRegex(res.stdout, r"^ifswitch_settled_before_probes\tfail\tnot settled within 10s of the route "
                                     r"change: .* reads=0 failed_reads=0 up=1 status=Connected waited=0s\n$")
        self.assertNotIn("log show settle_read", calls)
        self.assertLess(took, 3)
        # 3.5 s left and a read that hangs: bounded at 3 s, not 10, then no
        # second read with under 1 s left.
        res, took, calls, root = self.run_settle(left_ms=3500, FAKE_SETTLE_HANG="1")
        self.assertRegex(res.stdout, r"\tfail\tnot settled within 10s of the route change: .* reads=1 failed_reads=1 ")
        self.assertEqual(calls.count("log show settle_read"), 1)
        # v33 review: the read's own time from the trace (its alarm ended
        # it, rc 142), and room for a loaded Mac around it (this run took
        # 7.2 s once in a full suite): a 10 s bound would take longer.
        trace = (root / "out" / "ifswitch_settle.trace").read_text().splitlines()
        self.assertEqual(len(trace), 1, trace)
        read_ms = int(re.match(r"^at_ms=[0-9]+ rc=142 read_ms=([0-9]+) ", trace[0]).group(1))
        self.assertGreaterEqual(read_ms, 2900)
        self.assertLess(read_ms, 9000)
        self.assertGreater(took, 2.5)
        self.assertLess(took, 9.5)

    def test_the_settle_gate_reads_the_provider_process_only_and_runs_only_in_the_switch(self):
        text = OWNER_MODES_SH.read_text()
        el = (PACKAGE / "harness" / "endurance-load.sh").read_text()
        pred = re.search(r"^OM_SETTLE_PREDICATE='([^']*)'$", text, re.M).group(1)
        exe = re.search(r"^EL_PROVIDER_EXE=(\S+)$", el, re.M).group(1)
        self.assertEqual(pred, f'process == "{exe}" AND eventMessage BEGINSWITH "aegis-ne"')
        self.assertIn('EL_LOG_PREDICATE="process == \\"$EL_PROVIDER_EXE\\" AND eventMessage BEGINSWITH \\"aegis-ne\\""',
                      el)
        self.assertEqual(re.findall(r"^\s+om_settle .*$", text, re.M), ['    om_settle ifswitch_ "$start" "$new"'])
        window = text[text.index("om_ifswitch_window() {"):text.index("\nom_window() {")]
        self.assertIn('    om_recover ifswitch_ "$IFSWITCH_RECOVER_S" "$new"\n    om_settle ifswitch_ "$start" "$new"\n'
                      '    nl_traffic ifswitch_\n', window)
        # SLEEP=1 and NETLOSS=1 are unchanged: recovery, then the probes.
        self.assertIn('    om_recover sleep_ "$SLEEP_RECOVER_S" "$PHYS"\n    nl_traffic sleep_\n', text)
        self.assertIn('    nl_recover "$p"\n', (PACKAGE / "harness" / "netloss.sh").read_text())
        self.assertNotIn("om_settle", (PACKAGE / "harness" / "netloss.sh").read_text())
        # The bounds the window grows by are unchanged.
        self.assertIn("    OM_EXTRA_S=$((IFSWITCH_BOUND_S + IFSWITCH_RECOVER_S + 100))\n", text)

    def test_a_window_without_ifswitch_has_no_settle_gate(self):
        rc, stdout, rows, names, calls, root = self.run_window(
            FAKE_PROVIDER_LOG=provider_lines("session_lost capture_lease_expired", "session_rebuilt attempt:1"))
        self.assertEqual(rc, 0, stdout)
        self.assertFalse([n for n in names if n.startswith("ifswitch_") or "settle" in n], names)
        self.assertNotIn("log show settle_read", calls)
        self.assertFalse(list((root / "out").glob("*settle*")))
        self.assertFalse((root / "world" / "settle.reads").exists())

    # -------------------------------------------- IFSWITCH=1 v30 attach wait

    @staticmethod
    def attach(root, port=True, interface=True, state="inactive"):
        if port:
            (root / "world" / "en7.unlisted").unlink(missing_ok=True)
        if interface:
            (root / "world" / "en7").write_text(state + "\n")

    @staticmethod
    def detach(root):
        (root / "world" / "en7.unlisted").write_text("")
        (root / "world" / "en7").unlink(missing_ok=True)

    def unattached(self):
        """en7 neither listed nor present: the adapter plugged in just now."""
        return {"en7": None}

    def run_unattached(self, hooks, **extra):
        # The world's en7.unlisted marker must exist before the window starts.
        original = self.setup_world

        def setup_world(**world):
            root, env = original(**world)
            (root / "world" / "en7.unlisted").write_text("")
            return root, env

        self.setup_world = setup_world
        try:
            return self.run_window(when=hooks, world=self.unattached(), IFSWITCH="1", IFSWITCH_TO="en7", **extra)
        finally:
            self.setup_world = original

    def test_a_just_attached_adapter_is_waited_for_and_the_switch_passes(self):
        seen = {}

        def during_wait(root, proc):
            calls = (root / "calls.log").read_text()
            seen["untouched"] = (not (root / "home" / ".aegis-local" / "locks" / "timing-self").exists()
                                 and not (root / "out" / "rollback.log").exists()
                                 and "host --connect" not in calls and "tcpdump" not in calls)
            threading.Timer(1.0, self.attach, (root,)).start()

        rc, stdout, rows, names, calls, root = self.run_unattached(
            [("window.log", "waiting up to 20s for en7 to attach", during_wait),
             ("window.log", "OWNER ACTION", self.plug)],
            IFSWITCH_ATTACH_WAIT_S="20", IFSWITCH_ATTACH_SETTLE_S="2", IFSWITCH_RECOVER_S="10",
            IFSWITCH_SETTLE_QUIET_S="2", FAKE_PROVIDER_TIMELINE=REPIN_TO_EN7)
        self.assertEqual(rc, 0, stdout)
        self.assertTrue(seen["untouched"])
        self.assertIn("ifswitch: waiting up to 20s for en7 to attach (adapter in, cable out)", stdout)
        self.assertRegex(rows["ifswitch_preflight"][1], r" attach_after=[0-9]+s settle=2s$")
        # The refreshed hardware ports let the primary check see en7.
        self.assertEqual(rows["ifswitch_route_changed"][0], "pass", rows["ifswitch_route_changed"])
        self.assertGreater(calls.count("networksetup -listallhardwareports"), 2)
        self.assertEqual(rows["ifswitch_relay_path_exercised"][0], "pass")

    def test_the_wait_needs_the_port_and_the_interface_for_the_whole_settle(self):
        # The port first, the interface three seconds later: the settle
        # starts only once both are there.
        def port_then_interface(root, proc):
            self.attach(root, interface=False)
            threading.Timer(3.0, self.attach, (root,), {"port": False}).start()

        rc, stdout, rows, names, calls, root = self.run_unattached(
            [("window.log", "waiting up to", port_then_interface), ("window.log", "OWNER ACTION", self.plug)],
            IFSWITCH_ATTACH_WAIT_S="20", IFSWITCH_ATTACH_SETTLE_S="2", IFSWITCH_RECOVER_S="10",
            IFSWITCH_SETTLE_QUIET_S="2", FAKE_PROVIDER_TIMELINE=REPIN_TO_EN7)
        self.assertEqual(rc, 0, stdout)
        after = int(re.search(r"attach_after=([0-9]+)s", rows["ifswitch_preflight"][1]).group(1))
        self.assertGreaterEqual(after, 3)
        # Attached, then gone again within the settle: the settle restarts,
        # and gone for good refuses with the usual text and the bound.
        def flap(root, proc):
            self.attach(root)
            threading.Timer(1.0, self.detach, (root,)).start()

        started = time.monotonic()
        rc, stdout, rows, names, calls, root = self.run_unattached(
            [("window.log", "waiting up to", flap)], IFSWITCH_ATTACH_WAIT_S="4", IFSWITCH_ATTACH_SETTLE_S="3")
        self.assert_refused_untouched(rc, stdout, rows, calls, root, "IFSWITCH=1",
                                      "IFSWITCH_TO=en7 is no hardware port (not attached within 4s)")
        self.assertLess(time.monotonic() - started, 4 + 3 + 30)

        # Attached, gone for 2.5 s, back: the settle counts from the return.
        def flap_back(root, proc):
            self.attach(root)
            threading.Timer(1.0, self.detach, (root,)).start()
            threading.Timer(3.5, self.attach, (root,)).start()

        rc, stdout, rows, names, calls, root = self.run_unattached(
            [("window.log", "waiting up to", flap_back)], IFSWITCH_ATTACH_WAIT_S="20",
            IFSWITCH_ATTACH_SETTLE_S="3", IFSWITCH_BOUND_S="5")
        self.assertEqual(rc, 0, stdout)
        after = int(re.search(r"attach_after=([0-9]+)s", rows["ifswitch_preflight"][1]).group(1))
        self.assertGreaterEqual(after, 3, rows["ifswitch_preflight"])

    def test_a_target_that_attaches_with_a_link_or_moves_the_primary_is_refused(self):
        rc, stdout, rows, names, calls, root = self.run_unattached(
            [("window.log", "waiting up to", lambda root, proc: self.attach(root, state="link"))],
            IFSWITCH_ATTACH_WAIT_S="10", IFSWITCH_ATTACH_SETTLE_S="2")
        self.assert_refused_untouched(rc, stdout, rows, calls, root, "IFSWITCH=1",
                                      "en7 (USB 10/100/1000 LAN) has a link already (status: active): take the "
                                      "cable out of the adapter before the window")
        rc, stdout, rows, names, calls, root = self.run_unattached(
            [("window.log", "waiting up to", lambda root, proc: self.attach(root, state="active"))],
            IFSWITCH_ATTACH_WAIT_S="10", IFSWITCH_ATTACH_SETTLE_S="2")
        self.assert_refused_untouched(rc, stdout, rows, calls, root, "IFSWITCH=1",
                                      "en7 (USB 10/100/1000 LAN) is already active but not the primary: unplug "
                                      "its cable before the window")

        def primary_moves(root, proc):
            self.attach(root, state="active")
            (root / "world" / "primary").write_text("en7\n")

        rc, stdout, rows, names, calls, root = self.run_unattached(
            [("window.log", "waiting up to", primary_moves)], IFSWITCH_ATTACH_WAIT_S="10", IFSWITCH_ATTACH_SETTLE_S="2")
        self.assert_refused_untouched(rc, stdout, rows, calls, root, "IFSWITCH=1",
                                      "scutil --nwi names en7 as the IPv4 primary after en7 attached, not en0")

    def test_no_attach_within_the_bound_refuses_with_the_usual_text(self):
        def new_port(root, proc):
            (root / "world" / "en8.port").write_text("")

        started = time.monotonic()
        rc, stdout, rows, names, calls, root = self.run_unattached(
            [("window.log", "waiting up to", new_port)], IFSWITCH_ATTACH_WAIT_S="2", IFSWITCH_ATTACH_SETTLE_S="2")
        self.assert_refused_untouched(rc, stdout, rows, calls, root, "IFSWITCH=1",
                                      "IFSWITCH_TO=en7 is no hardware port (not attached within 2s; new hardware "
                                      "ports: en8)")
        self.assertLess(time.monotonic() - started, 2 + 2 + 30)
        # Without the wait (0): today's immediate refusal, one port listing.
        rc, stdout, rows, names, calls, root = self.run_unattached([], IFSWITCH_ATTACH_WAIT_S="0")
        self.assert_refused_untouched(rc, stdout, rows, calls, root, "IFSWITCH=1", "IFSWITCH_TO=en7 is no hardware port")
        self.assertNotIn("waiting up to", stdout)
        self.assertEqual(calls.count("networksetup -listallhardwareports"), 1)

    def test_the_codex_lock_or_a_signal_during_the_wait_leaves_nothing_behind(self):
        def lock(root, proc):
            self.attach(root)
            (root / "home" / ".aegis-local" / "locks" / "timing-peer").write_text("start=x purpose=test\n")

        rc, stdout, rows, names, calls, root = self.run_unattached(
            [("window.log", "waiting up to", lock)], IFSWITCH_ATTACH_WAIT_S="10", IFSWITCH_ATTACH_SETTLE_S="2")
        self.assertEqual(rc, 4, stdout)
        self.assertIn("refused: IFSWITCH=1: timing-peer lock taken while waiting for en7; nothing connected", stdout)
        self.assertFalse([c for c in calls if c.startswith(("host --connect", "sudo -n /usr", "tcpdump"))], calls)
        self.assertFalse((root / "home" / ".aegis-local" / "locks" / "timing-self").exists())
        self.assertFalse((root / "out" / "rollback.log").exists())
        rc, stdout, rows, names, calls, root = self.run_unattached(
            [("window.log", "waiting up to", lambda root, proc: proc.terminate())],
            IFSWITCH_ATTACH_WAIT_S="20", IFSWITCH_ATTACH_SETTLE_S="2")
        self.assertIn(rc, (-signal.SIGTERM, 128 + signal.SIGTERM), stdout)
        self.assertFalse((root / "home" / ".aegis-local" / "locks" / "timing-self").exists())
        for name in ("rollback.log", "results.tsv", "physical.pcap"):
            self.assertFalse((root / "out" / name).exists(), name)
        self.assertFalse([c for c in calls if c.startswith(("host --connect", "sudo -n /usr", "tcpdump"))], calls)


# ------------------------------------------------ S20f observability batch

PC_GW0 = "192.0.2.1"       # en0's LAN gateway (documentation range)
PC_GW5 = "198.51.100.1"    # en5's LAN gateway
PC_LOCAL0 = "192.0.2.50"
PC_LOCAL5 = "198.51.100.50"

# A fake tcpdump for the S20f windows: relay traffic on en0 only, ARP
# elsewhere; FAKE_PRECONNECT_LEAK=<if>: one Mac-sent SYN after the arm and
# before Connected; a probe marker in PROBE_DIR (written by the fake probe
# for FAKE_BPF_PRE interfaces) puts the marked SYNs into that capture.
# S20h review: FAKE_TCPDUMP_DROPS=<if>:<n> reports n packets dropped by the
# kernel on that interface at the stop; FAKE_TCPDUMP_QUIET_AT_DISARM=<if>
# records nothing more on it once the filter disarmed (a capture that
# stopped recording before the armed span ended).
CTL_FAKE_TCPDUMP = r"""
import os, signal, struct, sys, time
args = sys.argv[1:]
log = open(os.environ["CALLS"], "a", buffering=1)
open(os.environ["FAKE_PIDS"], "a").write(f"tcpdump {os.getpid()}\n")
bound = float(args[args.index("-G") + 1]) if "-G" in args else 0
iface = args[args.index("-i") + 1]
out = args[args.index("-w") + 1]
if os.environ.get("FAKE_TCPDUMP_FAIL_IF") == iface:
    sys.stderr.write("tcpdump: %s: You don't have permission to capture on that device\n" % iface)
    sys.exit(1)
state, probe_dir = os.environ["STATE"], os.environ["PROBE_DIR"]
local = {"en0": "192.0.2.50", "en5": "198.51.100.50"}.get(iface)
mac = {"en0": "020000000001", "en5": "020000000005", "awdl0": "02000000000a"}.get(iface, "020000000009")
started = time.time()
def ip(t): return bytes(int(x) for x in t.split("."))
def tcp(src, dst, sport, dport, flags=0x02, data=b""):
    l4 = struct.pack(">HHIIBBHHH", sport, dport, 1, 0, 0x50, flags, 65535, 0, 0) + data
    pkt = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0x4000, 64, 6, 0, ip(src), ip(dst)) + l4
    return b"\x02\x00\x00\x00\x00\xff" + bytes.fromhex(mac) + b"\x08\x00" + pkt
arp = b"\xff" * 6 + b"\x02\x00\x00\x00\x00\x02\x08\x06" + struct.pack(">HHBBH", 1, 0x0800, 6, 4, 1) + b"\x00" * 20
f = open(out, "wb", buffering=0)
f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
def write(fr, ts=None):
    ts = time.time() if ts is None else ts; sec = int(ts)
    f.write(struct.pack("<IIII", sec, int((ts - sec) * 1e6), len(fr), len(fr)) + fr)
stop = []
signal.signal(signal.SIGINT, lambda *a: stop.append(1))
sys.stderr.write("tcpdump: listening on %s, link-type EN10MB (Ethernet), snapshot length 160 bytes\n" % iface)
sys.stderr.flush()
log.write("tcpdump started " + " ".join(args) + "\n")
leaked = False
quiet = os.environ.get("FAKE_TCPDUMP_QUIET_AT_DISARM") == iface
while not stop:
    if bound and time.time() - started >= bound:
        break
    if quiet and os.path.exists(state + ".disarmed"):
        time.sleep(0.1)
        continue
    write(tcp(local, os.environ["RELAY_IP"], 50000, 443, 0x18) if iface == "en0" else arp)
    armed = os.path.exists(state + ".armed")
    if (os.environ.get("FAKE_PRECONNECT_LEAK") == iface and armed and not leaked
            and not os.path.exists(state + ".was-connected")):
        write(tcp(local, "198.51.100.9", 50001, 443)); leaked = True
    marker = os.path.join(probe_dir, iface)
    if os.path.exists(marker):
        gw, port, base, n = open(marker).read().split()
        for k in range(int(n)):
            write(tcp(local, gw, int(base) + k, int(port)))
        os.unlink(marker)
    # S20g: the pre-existing sockets' written segments (`gw port lport`
    # lines from the presock shim), one data frame each. S20h: `gw port
    # lport ack T` is a keepalive (a bare ACK) stamped at its time T.
    marker = os.path.join(probe_dir, "presock-" + iface)
    if os.path.exists(marker):
        taken = marker + ".taken"
        os.rename(marker, taken)
        lines = open(taken).read().split("\n")
        os.unlink(taken)
        for line in lines:
            if line.strip():
                parts = line.split()
                gw, port, lport = parts[:3]
                if len(parts) > 3 and parts[3] == "ack":
                    write(tcp(local, gw, int(lport), int(port), 0x10), float(parts[4]))
                else:
                    write(tcp(local, gw, int(lport), int(port), 0x18, b"aegis-s20g-presock-0\n"))
    time.sleep(0.1)
log.write("tcpdump stopped if=%s\n" % iface)
lost = dict(x.split(":") for x in os.environ.get("FAKE_TCPDUMP_DROPS", "").split() if ":" in x).get(iface, "0")
sys.stderr.write("100 packets captured\n100 packets received by filter\n%s packets dropped by kernel\n" % lost)
"""

# A fake host with a filter that can be disabled and enabled, whose
# filter-status carries observability (out drops per class from DROPS, the
# arm from DROPS/arm_seq, the drop ring from DROPS/ring: one record per
# line, `iface dir family proto tcp reason [wall [m]]`, the last 64
# reported; S20h: the v29 outbound part from the ring's outbound records,
# by class and kind, marked when the line ends in m, the marker range
# FAKE_MARK_FIRST (47000) and 32 ports, none with FAKE_NO_OUTBOUND=1;
# S20g: a record's ms since the arm comes from its wall time, else 5, and
# armed_for_ms from the arm's wall time while guarding) and
# whose connect and stop leave the provider's armed span (FAKE_SPAN: ok,
# none, early (disarmed while Connected), rearm, or restart: a new
# provider process arms seq:1 again while Connected and logs the disarm).
# FAKE_DISABLED_EXIT: the status exit while disabled (31);
# FAKE_ENABLE_DELAY_S: an enable that waits (for the owner's Allow).
CTL_FAKE_HOST = r"""#!/bin/sh
now() { python3 -I -c 'import time; print("%.6f" % time.time())'; }
# The time is taken first and the file appears whole, so a fake tcpdump
# that sees the arm marker never writes a frame stamped before it (a plain
# `now > file` creates the file before python starts).
stamp() { t=$(now); printf '%s\n' "$t" > "$1.tmp" && mv "$1.tmp" "$1"; }
case "$1" in
  --filter-status)
    if [ "$(cat "$FILTER_STATE")" = disabled ]; then
      echo "filter_result=disabled exit_code=31 configured=true exact=true enabled=false"; exit "${FAKE_DISABLED_EXIT:-31}"
    fi
    mode=open; [ "$(cat "$STATE")" = Connected ] && mode=guarding
    p=$(cat "$DROPS/primary" 2>/dev/null || echo 0); o=$(cat "$DROPS/en_other" 2>/dev/null || echo 0)
    echo "${FAKE_FILTER_LINE:-filter_result=ok exit_code=0 configured=true enabled=true attached=true pid_match=true mode=$mode armed_token=1 dropped=$((p + o)) allowed=0}"
    if [ "${FAKE_NO_OBS:-0}" = 1 ]; then
      printf '{"schema":"aegis-ne-xpc-v1","verb":"filter-status","report":{"mode":"%s"}}\n' "$mode"
    else
      python3 -I -c '
import json, os, sys, time
d, mode, state = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    armed_at = float(open(state + ".armed").read())
except (OSError, ValueError):
    armed_at = None
def ms(wall):
    return int((wall - armed_at) * 1000) if armed_at is not None else 5
def num(name, default=0):
    try:
        return int(open(os.path.join(d, name)).read().strip())
    except (OSError, ValueError):
        return default
try:
    ring = [line.split() for line in open(os.path.join(d, "ring")) if line.strip()]
except OSError:
    ring = []
arm = num("arm_seq", 1)
entries = [{"index": i, "arm_seq": arm, "ms": ms(float(r[6])) if len(r) > 6 else 5,
            "class": "primary" if r[0] == "en0" else "en_other",
            "iface": r[0], "dir": r[1], "family": r[2], "proto": int(r[3]), "tcp": r[4], "reason": r[5]}
           for i, r in enumerate(ring)][-64:]
drops = {c: {"in": 0, "out": num(c), "any": 0} for c in ("primary", "en_other", "awdl_llw", "bridge_ap_anpi", "other")}
obs = {"arm_seq": arm, "disarms": 0, "armed_ms_total": 5,
       "armed_for_ms": (ms(time.time()) if armed_at is not None else 5) if mode == "guarding" else None,
       "open_while_applied": 0, "applied_epochs": 0, "primary_iface": "en0", "drops": drops,
       "ring": {"next": len(ring), "skipped": 0, "torn": 0, "entries": entries}}
KINDS = ("syn", "syn_ack", "ack_only", "data", "fin", "rst", "other", "non_tcp")
CLASSES = ("primary", "en_other", "awdl_llw", "bridge_ap_anpi", "other")
outs = [r for r in ring if r[1] == "out"]
def cls(r):
    return "primary" if r[0] == "en0" else "en_other"
def kind(r):
    return "non_tcp" if r[3] != "6" else (r[4] if r[4] in KINDS else "other")
def marked(r):
    return len(r) > 7 and r[7] == "m"
def table(pick):
    return {c: {k: sum(1 for r in outs if cls(r) == c and kind(r) == k and pick(r)) for k in KINDS} for c in CLASSES}
out_entries = [{"index": i, "arm_seq": arm, "ms": ms(float(r[6])) if len(r) > 6 else 5, "class": cls(r),
                "iface": r[0], "dir": r[1], "family": r[2], "proto": int(r[3]), "tcp": r[4], "reason": r[5],
                "marked": marked(r)} for i, r in enumerate(outs)][-64:]
if os.environ.get("FAKE_NO_OUTBOUND") != "1":
    obs["outbound"] = {"mark_sport_first": int(os.environ.get("FAKE_MARK_FIRST", "47000")), "mark_sport_count": 32,
                       "kinds": table(lambda r: True), "marked": table(marked),
                       "ring": {"next": len(outs), "skipped": 0, "torn": 0, "entries": out_entries}}
print(json.dumps({"schema": "aegis-ne-xpc-v1", "verb": "filter-status", "report": {"mode": mode, "observability": obs}},
                 separators=(",", ":")))' "$DROPS" "$mode" "$STATE"
    fi
    exit "${FAKE_FILTER_EXIT:-0}";;
  --disable-filter)
    echo "host --disable-filter" >> "$CALLS"
    [ -e "$HOME/.aegis-local/negative-control-filter-disabled" ] && echo "marker_at_disable" >> "$CALLS"
    if [ "${FAKE_DISABLE_EXIT:-0}" != 0 ]; then
      echo "filter_result=authorization_refused exit_code=67 filter_changed=false"; exit "$FAKE_DISABLE_EXIT"
    fi
    # FAKE_DISABLE_NOOP=1: exit 0, yet the filter stays enabled.
    [ "${FAKE_DISABLE_NOOP:-0}" = 1 ] || echo disabled > "$FILTER_STATE"
    echo "filter_result=ok exit_code=0 configured=true enabled=false";;
  --enable-filter)
    echo "host --enable-filter" >> "$CALLS"
    sleep "${FAKE_ENABLE_DELAY_S:-0}"
    n=$(cat "$FILTER_STATE.enables" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$FILTER_STATE.enables"
    if [ "$n" -le "${FAKE_ENABLE_FAILS:-0}" ]; then echo "filter_result=failed exit_code=34"; exit 34; fi
    echo enabled > "$FILTER_STATE"; echo "filter_result=ok exit_code=0 configured=true enabled=true";;
  --list) echo "profile index=0 owner_generation=0A1B2C3D-0000-4000-8000-000000000001 scutil_service_id=1111AAAA-2222-3333-4444-555566667777 intent_valid=true on_demand_enabled=false";;
  --connect)
    echo "host $*" >> "$CALLS"
    # S20h: FAKE_NO_CONNECT=1, a tunnel that never connects (nor arms).
    [ "${FAKE_NO_CONNECT:-0}" = 1 ] && exit 0
    [ "${FAKE_SPAN:-ok}" = none ] || stamp "$STATE.armed"
    sleep "${FAKE_ARM_LEAD_S:-0}"
    echo Connected > "$STATE"; : > "$STATE.was-connected"
    # Two seconds into the Connected window: a disarm, or a second arm.
    if [ "${FAKE_SPAN:-ok}" = early ]; then ( sleep 2; stamp "$STATE.disarmed" ) </dev/null >/dev/null 2>&1 & fi
    if [ "${FAKE_SPAN:-ok}" = rearm ]; then ( sleep 2; stamp "$STATE.rearmed" ) </dev/null >/dev/null 2>&1 & fi
    if [ "${FAKE_SPAN:-ok}" = restart ]; then ( sleep 2; stamp "$STATE.restarted" ) </dev/null >/dev/null 2>&1 & fi;;
  --emergency-stop) echo "host $*" >> "$CALLS"; echo Disconnected > "$STATE";;
esac
"""

CTL_FAKE_COMMANDS = dict(WINDOW_FAKE_COMMANDS)
CTL_FAKE_COMMANDS.update({
    "scutil": r"""#!/bin/sh
case "$1 $2" in
  "--nc status") cat "$STATE"; echo "Extended Status <dictionary> {";;
  "--nc stop") echo "scutil $*" >> "$CALLS"; echo Disconnected > "$STATE"
     if [ -s "$STATE.armed" ] && [ ! -e "$STATE.disarmed" ]; then
       python3 -I -c 'import time; print("%.6f" % time.time())' > "$STATE.disarmed"
     fi;;
  "--dns "*) printf 'DNS configuration\n\nresolver #1\n  nameserver[0] : 198.19.255.2\n  nameserver[1] : fd00:ae61::2\n';;
esac
""",
    # The scoped default routes name each interface's LAN gateway;
    # FAKE_GW_EN5 replaces en5's (an off-link one is never probed).
    "route": r"""#!/bin/sh
case "$*" in
  *-inet6*) if [ "$(cat "$STATE")" = Connected ]; then echo "  interface: utun9"; else echo "  interface: en0"; fi;;
  *"-ifscope en0 "*) [ "${FAKE_NO_GW:-0}" = 1 ] && exit 1; printf '    gateway: 192.0.2.1\n  interface: en0\n';;
  *"-ifscope en5 "*) [ "${FAKE_EN5:-0}" = 1 ] && printf '    gateway: %s\n  interface: en5\n' "${FAKE_GW_EN5:-198.51.100.1}";;
  *-ifscope*) exit 1;;
  *) if [ "$(cat "$STATE")" = Connected ]; then echo "  interface: utun9"; else echo "  interface: en0"; fi;;
esac
""",
    "ifconfig": r"""#!/bin/sh
ARG=${1:-}
want() { [ -z "$ARG" ] || [ "$ARG" = "$1" ]; }
want en0 && printf 'en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n\tether 02:00:00:00:00:01\n\tinet6 fe80::1c%%en0 prefixlen 64 scopeid 0x6\n\tinet 192.0.2.50 netmask 0xffffff00 broadcast 192.0.2.255\n\tstatus: active\n'
[ "${FAKE_EN5:-0}" = 1 ] && want en5 && printf 'en5: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n\tether 02:00:00:00:00:05\n\tinet 198.51.100.50 netmask 0xffffff00 broadcast 198.51.100.255\n\tstatus: active\n'
[ "${FAKE_AWDL:-0}" = 1 ] && want awdl0 && printf 'awdl0: flags=8943<UP,BROADCAST,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1500\n\tether 02:00:00:00:00:0a\n\tinet6 fe80::a%%awdl0 prefixlen 64 scopeid 0xb\n\tstatus: active\n'
[ -z "$ARG" ] && printf 'lo0: flags=8049<UP,LOOPBACK> mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000\n'
if want utun9 && [ "$(cat "$STATE")" = Connected ]; then
  printf 'utun9: flags=8051<UP> mtu 1400\n\tinet 198.19.255.1 --> 198.19.255.1 netmask 0xffffffff\n\tinet6 fe80::9%%utun9 prefixlen 64 scopeid 0x13\n\tinet6 fd00:ae61::1 prefixlen 120\n'
fi
exit 0
""",
    # Provider process 42; with FAKE_SPAN=restart, process 43 arms seq:1
    # again and logs the disarm. FAKE_LOG_NOPID=1: lines without [pid:tid].
    # FAKE_LOG_NOSPAN=1: no leak_guard_span line (the filter still arms).
    "fake_log": r"""#!/bin/sh
echo "log $1" >> "$CALLS"
[ "$1" = show ] || exit 1
printf 'Timestamp               Ty Process[PID:TID]\n'
p() {
  if [ "${FAKE_LOG_NOPID:-0}" = 1 ]; then echo '2026-10-24 06:00:00.000 Df PacketTunnel [dev.aegis.macos.PacketTunnel] aegis-ne'
  else echo "2026-10-24 06:00:00.000 Df PacketTunnel[$1:1] [dev.aegis.macos.PacketTunnel] aegis-ne"; fi
}
d=42; [ -s "$STATE.restarted" ] && d=43
if [ "${FAKE_LOG_NOSPAN:-0}" != 1 ]; then
  [ -s "$STATE.armed" ] && echo "$(p 42) leak_guard_span armed seq:1 wall:$(cat "$STATE.armed")"
  [ -s "$STATE.rearmed" ] && echo "$(p 42) leak_guard_span armed seq:2 wall:$(cat "$STATE.rearmed")"
  [ -s "$STATE.restarted" ] && echo "$(p 43) leak_guard_span armed seq:1 wall:$(cat "$STATE.restarted")"
  [ -s "$STATE.disarmed" ] && echo "$(p $d) leak_guard_span disarmed seq:1 wall:$(cat "$STATE.disarmed")"
fi
# S20g: a v28 engine's answers to the probes (`wall n` per line).
if [ -s "$STATE.engine" ]; then
  while read -r w k; do echo "$(p 42) engine_flow_open class:discard n:$k wall:$w"; done < "$STATE.engine"
fi
exit 0
""",
    # net_probe.py stand-in: boundsyn counts the probes' drops into the
    # fake provider (twice each: a SYN and its retransmission, each a ring
    # record of an outbound SYN on that interface) while the filter is
    # enabled and the tunnel Connected, unless FAKE_FILTER_BLIND names the
    # interface; FAKE_PROBE_CONNECTS names one whose probe connects;
    # FAKE_PROBE_INCONCLUSIVE one whose probes never leave (eaddrinuse,
    # exit 3); FAKE_BPF_PRE names those whose capture sees the SYNs.
    # FAKE_NOISE_IF=<if>: during its probes FAKE_NOISE_N (6) other drops of
    # its class, mDNS and SYNs alternately, on another interface (en6, or
    # inbound on en0); FAKE_PROBE_REARM=<if>: the filter re-arms meanwhile.
    # S20g: FAKE_PROBE_TUNNEL=<if>: the system routes its probes into the
    # tunnel: each connects, no drop, and the engine logs a discard open at
    # that moment (shifted by FAKE_ENGINE_SKEW_S; none with
    # FAKE_ENGINE_LOG=0). presock runs the real net_probe.py helper through
    # PRESOCK_SHIM on loopback (exit 2 without one).
    "probe_py": r"""#!/bin/sh
echo "probe $3 $4" >> "$CALLS"
if [ "$3" = presock ]; then
  echo "probe presock $4 $5 $6 $7 $9 ${10} ${11}" >> "$CALLS"
  [ -n "${PRESOCK_SHIM:-}" ] || exit 2
  np=$2; shift 2
  exec "$SYSTEM_PY" -I "$PRESOCK_SHIM" "$np" "$@"
fi
drop() {
  c=$(cat "$DROPS/$cls" 2>/dev/null || echo 0); echo $((c + 1)) > "$DROPS/$cls"
  echo "$*" >> "$DROPS/ring"
}
case "$3" in
  tcp) case "$4" in hc) echo 4/7/eof;; *) echo 4/7/full;; esac;;
  source6) echo fd00:ae61::1;;
  aaaa) echo 2001:db8:5::1;;
  scan64) exec "$SYSTEM_PY" "$@";;
  boundsyn)
    dev=$4 gw=$5 port=$6 n=$7 base=$8
    echo "probe boundsyn $dev $gw $port $n $base $9" >> "$CALLS"
    cls=en_other; [ "$dev" = en0 ] && cls=primary
    if [ "${FAKE_PROBE_INCONCLUSIVE:-}" != "$dev" ]; then
      if [ "$(cat "$FILTER_STATE")" = enabled ] && [ "$(cat "$STATE")" = Connected ] && [ "${FAKE_FILTER_BLIND:-}" != "$dev" ] \
          && [ "${FAKE_PROBE_TUNNEL:-}" != "$dev" ]; then
        k=0; while [ "$k" -lt $((2 * n)) ]; do drop "$dev out v4 6 syn drop_tcp_out"; k=$((k + 1)); done
      fi
      case " ${FAKE_BPF_PRE:-} " in *" $dev "*) echo "$gw $port $base $n" > "$PROBE_DIR/$dev";; esac
    fi
    if [ "${FAKE_NOISE_IF:-}" = "$dev" ]; then
      k=0; while [ "$k" -lt "${FAKE_NOISE_N:-6}" ]; do
        if [ "$cls" = primary ]; then
          if [ $((k % 2)) = 0 ]; then drop "en0 out v4 17 none drop_mdns"; else drop "en0 in v4 6 syn drop_tcp_in"; fi
        else
          if [ $((k % 2)) = 0 ]; then drop "en6 out v4 17 none drop_mdns"; else drop "en6 out v4 6 syn drop_tcp_out"; fi
        fi
        k=$((k + 1))
      done
    fi
    [ "${FAKE_PROBE_REARM:-}" = "$dev" ] && echo 2 > "$DROPS/arm_seq"
    if [ "${FAKE_PROBE_TUNNEL:-}" = "$dev" ]; then
      k=1; while [ "$k" -le "$n" ]; do
        [ "${FAKE_ENGINE_LOG:-1}" = 0 ] || python3 -I -c 'import sys, time; print("%.6f %s" % (time.time() + float(sys.argv[1]), sys.argv[2]))' \
          "${FAKE_ENGINE_SKEW_S:-0}" "$k" >> "$STATE.engine"
        k=$((k + 1))
      done
      echo "probes=$n failed=0 kinds=connected:$n ms=7"; exit 1
    fi
    if [ "${FAKE_PROBE_CONNECTS:-}" = "$dev" ]; then
      echo "probes=$n failed=$((n - 1)) kinds=connected:1,timeout:$((n - 1)) ms=12"; exit 1
    fi
    if [ "${FAKE_PROBE_INCONCLUSIVE:-}" = "$dev" ]; then
      echo "probes=$n failed=$n kinds=eaddrinuse:$n ms=3"; exit 3
    fi
    echo "probes=$n failed=$n kinds=timeout:$n ms=$((n * 2000))"; exit 0;;
  *) exit 2;;
esac
""",
})


# S20g: the presock shim the probe stand-in execs: the real net_probe.py
# helper (port selection, sockets, commands, state file) on loopback, with
# the interface and gateway mapped to lo0 and FakeGateway (a window port in
# FAKE_GW_OPEN, or FAKE_GW_OPEN_<if>, maps to the gateway's port, any other
# to a closed one), and a stand-in for the filter while it is enabled and
# armed (S20h: within the fake provider's armed span, judged at the time of
# each segment): what is written stays unacknowledged (TCP_CONNECTION_INFO's
# snd_sbbytes keeps the bytes, and its txpackets and txretransmitpackets
# count FAKE_PRESOCK_RETX (1) retransmissions a written socket besides the
# segment) and the provider counts FAKE_PRESOCK_DROPS (2) outbound drops
# per write (the segment and its retransmission), ring records of
# FAKE_PRESOCK_RING (data; ack_only; early: timed 2 s before the write;
# none: no record), marked as the provider marks them (S20h review: the
# socket's source port in the marker range; XNU keeps a connection's ports
# on every segment and keepalive, never its IP_TTL) unless
# FAKE_PRESOCK_UNMARKED=1. FAKE_PRESOCK_DATA_LEAK=<if>: the filter counts
# those drops, yet one copy of each written segment leaves (its frame in
# the capture), as a segment the filter missed would. A FAKE_BPF_PRE
# capture holds every segment the filter dropped (the retransmission too).
# FAKE_FILTER_BLIND=<if>: the filter misses that
# interface, so loopback acknowledges the bytes. FAKE_FILTER_OUT_BLIND=<if>:
# the filter lets that interface's segments out (no drop, the frame in the
# capture) and drops the gateway's answers inbound, so the bytes stay
# unacknowledged. FAKE_PRESOCK_HOLD=1: the bytes stay unacknowledged with
# the filter off too. The frames reach the fake capture with the filter
# off, or with it on for FAKE_BPF_PRE and FAKE_FILTER_OUT_BLIND interfaces.
# S20h: FAKE_PRESOCK_KA=1 adds each socket's keepalives, due every intvl
# from idle after its connect (the helper's keepalive): while armed each is
# a bare-ACK drop (marked by its source port as above; also in the
# capture for FAKE_BPF_PRE, only in the capture for FAKE_FILTER_BLIND and
# FAKE_FILTER_OUT_BLIND), otherwise a bare ACK in the capture stamped at
# its time; FAKE_PRESOCK_KA_BLIND=1: the system holds them before the
# filter too (neither a drop nor a frame).
# The state file also records test_window_port, the window's port that
# matched.
PRESOCK_SHIM_PY = r"""
import os, sys, threading, time
sys.path.insert(0, os.path.dirname(sys.argv[1]))
import net_probe

dev, gw, ports, n, path, limit, wait, lifetime = net_probe.presock_args(sys.argv[3:])
keepalive = net_probe.presock_keepalive(sys.argv[3:])
env = os.environ
open_ports = env.get("FAKE_GW_OPEN_" + dev, env.get("FAKE_GW_OPEN", "")).split()
mapped = [int(env["FAKE_GW_PORT"]) if str(p) in open_ports else int(env["FAKE_GW_CLOSED"]) for p in ports]
lock = threading.Lock()
cls = "primary" if dev == "en0" else "en_other"


def mark(lport):
    # The provider's rule: a TCP source port of the marker range. The
    # segment's TTL never counts (XNU keepalives carry ip_defttl).
    first, count = net_probe.PRESOCK_MARK_SPORT_FIRST, net_probe.PRESOCK_MARK_SPORT_COUNT
    return " m" if first <= lport < first + count and env.get("FAKE_PRESOCK_UNMARKED") != "1" else ""


def listed(name):
    return dev in env.get(name, "").split()


def drop(line):
    with lock:
        path = os.path.join(env["DROPS"], cls)
        try:
            count = int(open(path).read().strip())
        except (OSError, ValueError):
            count = 0
        open(path, "w").write("%d\n" % (count + 1))
        open(os.path.join(env["DROPS"], "ring"), "a").write(line + "\n")


def wire(line):
    with lock:
        open(os.path.join(env["PROBE_DIR"], "presock-" + dev), "a").write(line + "\n")


def stamp(name):
    try:
        return float(open(env["STATE"] + name).read())
    except (OSError, ValueError):
        return None


def armed(at):
    # The fake provider's armed span: its arm stamp at or before `at` and
    # no disarm stamp at or before it, with the filter enabled.
    try:
        enabled = open(env["FILTER_STATE"]).read().strip() == "enabled"
    except OSError:
        return False
    start, end = stamp(".armed"), stamp(".disarmed")
    return enabled and start is not None and start <= at and (end is None or at < end)


class Shim(net_probe.Presock):
    def __init__(self):
        super().__init__("lo0", "127.0.0.1", mapped, n, path, limit, wait, lifetime, keepalive=keepalive)
        self.held = {}

    def open(self):
        ok = super().open()
        if "port" in self.doc:
            self.doc["test_window_port"] = ports[mapped.index(self.doc["port"])]
            self.save()
        if ok and env.get("FAKE_PRESOCK_KA") == "1":
            threading.Thread(target=self.keepalives, daemon=True).start()
        return ok

    def filtering(self, at=None):
        return armed(time.time() if at is None else at)

    def keepalives(self):
        idle, intvl, cnt = self.keepalive
        due = [(s["t_connected"] + idle, s["lport"]) for s in self.doc.get("sockets", []) if "t_connected" in s]
        sent = [0] * len(due)
        while True:
            now = time.time()
            for j, (first, lport) in enumerate(due):
                while sent[j] < cnt and first + sent[j] * intvl <= now:
                    self.keepalive_at(first + sent[j] * intvl, lport)
                    sent[j] += 1
            time.sleep(0.02)

    def keepalive_at(self, at, lport):
        if env.get("FAKE_PRESOCK_KA_BLIND") == "1":
            return
        filtering = self.filtering(at) and not listed("FAKE_FILTER_BLIND")
        out_blind = filtering and listed("FAKE_FILTER_OUT_BLIND")
        if filtering and not out_blind:
            drop("%s out v4 6 ack_only drop_tcp_out %.6f%s" % (dev, at, mark(lport)))
        if not filtering or out_blind or listed("FAKE_BPF_PRE"):
            wire("%s %d %d ack %.6f" % (gw, self.doc["port"], lport, at))

    def send(self, sock, data):
        sent = super().send(sock, data)
        filtering = self.filtering() and not listed("FAKE_FILTER_BLIND")
        out_blind = filtering and listed("FAKE_FILTER_OUT_BLIND")
        if filtering or env.get("FAKE_PRESOCK_HOLD") == "1":
            self.held[id(sock)] = sent
        lport = sock.getsockname()[1]
        dropped = 0
        if filtering and not out_blind:
            ring = env.get("FAKE_PRESOCK_RING", "data")
            if ring != "none":
                wall = time.time() - (2.0 if ring == "early" else 0.0)
                kind = "ack_only" if ring == "ack_only" else "data"
                for _ in range(int(env.get("FAKE_PRESOCK_DROPS", "2"))):
                    drop("%s out v4 6 %s drop_tcp_out %.6f%s" % (dev, kind, wall, mark(lport)))
                    dropped += 1
        if not filtering or out_blind or (filtering and listed("FAKE_PRESOCK_DATA_LEAK")):
            wire("%s %d %d" % (gw, self.doc["port"], lport))
        elif listed("FAKE_BPF_PRE"):
            # S20h review: a tap before the filter records every segment
            # the filter drops, the retransmission too.
            for _ in range(max(dropped, 1)):
                wire("%s %d %d" % (gw, self.doc["port"], lport))
        return sent

    def info(self, sock):
        info = super().info(sock)
        if id(sock) in self.held:
            retx = int(env.get("FAKE_PRESOCK_RETX", "1"))
            info = dict(info, snd_sbbytes=info["snd_sbbytes"] + self.held[id(sock)],
                        txpackets=info["txpackets"] + retx, txretransmitpackets=info["txretransmitpackets"] + retx)
        return info


sys.exit(Shim().run())
"""


class FakeGateway:
    """S20g: a LAN gateway stand-in on loopback that accepts and holds every
    connection (the kernel acknowledges what is written to it, nothing
    reads it), with a closed loopback port beside it. reset_on_accept
    resets each connection right after it is accepted."""

    def __init__(self, reset_on_accept=False):
        import socket
        import threading
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        self.closed = closed.getsockname()[1]
        closed.close()
        self.reset_on_accept = reset_on_accept
        self.conns, self.accepted = [], 0
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        import socket
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.accepted += 1
            if self.reset_on_accept:
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                conn.close()
            else:
                self.conns.append(conn)

    def close(self):
        self.stop.set()
        self.thread.join(5)
        self.sock.close()
        for conn in self.conns:
            conn.close()


class RealRelayWindowControlTests(unittest.TestCase):
    """S20f: POSITIVE_CONTROL=1, NEGATIVE_CONTROL=1 and the armed-span review
    of harness/real-relay-window.sh (harness/controls.sh) against fake system
    commands, a fake host whose filter can be disabled, a fake provider log
    and a fake tcpdump. Documentation addresses only; nothing dials,
    captures or changes a filter."""

    def run_window(self, kill_when_connected=False, handoff_extra=None, prepare=None, **env_extra):
        temp = tempfile.TemporaryDirectory(prefix="aegis-s20f-window-")
        self.addCleanup(temp.cleanup)
        root = pathlib.Path(temp.name)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        for name, body in CTL_FAKE_COMMANDS.items():
            (bin_dir / name).write_text(body)
            (bin_dir / name).chmod(0o755)
        host = root / "AEGIS.app" / "Contents" / "MacOS" / "aegis-ne-host"
        host.parent.mkdir(parents=True)
        host.write_text(CTL_FAKE_HOST)
        host.chmod(0o755)
        (root / "fake_tcpdump.py").write_text(CTL_FAKE_TCPDUMP)
        (root / "fake_sudo_parent.py").write_text(WINDOW_FAKE_SUDO_PARENT)
        pids = root / "fake.pids"
        pids.write_text("")
        self.addCleanup(RealRelayWindowLeakCaptureTests.kill_fakes, pids)
        (root / "home" / ".aegis-local" / "locks").mkdir(parents=True)
        for name in ("drops", "probes"):
            (root / name).mkdir()
        handoff = root / "handoff.json"
        handoff.write_text(json.dumps({"relay": f"{RELAY_IP}:443", "echo_tcp": f"{RELAY_IP}:7",
                                       "echo_udp": f"{RELAY_IP}:7", "whoami": f"http://{RELAY_IP}/ip",
                                       **(handoff_extra or {})}))
        state = root / "state"
        state.write_text("Disconnected\n")
        (root / "filter").write_text("enabled\n")
        calls = root / "calls.log"
        calls.write_text("")
        out = root / "out"
        env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(root / "home"), "APP": str(root / "AEGIS.app"),
               "HANDOFF": str(handoff), "OUT": str(out), "ROLLBACK_S": "25", "STATE": str(state),
               "CALLS": str(calls), "FAKE_TCPDUMP": str(root / "fake_tcpdump.py"), "RELAY_IP": RELAY_IP,
               "FAKE_SUDO_PARENT": str(root / "fake_sudo_parent.py"), "FAKE_PIDS": str(pids),
               "LEAK_CAPTURE": "1", "PROBE_PY": str(bin_dir / "probe_py"), "SYSTEM_PY": SYSTEM_PY,
               "LOG_BIN": str(bin_dir / "fake_log"), "FILTER_STATE": str(root / "filter"),
               "DROPS": str(root / "drops"), "PROBE_DIR": str(root / "probes"), "NC_PY": SYSTEM_PY,
               "PRESOCK_WAIT_S": "1", **env_extra}
        self.addCleanup(self.end_rollbacks, out)
        if prepare is not None:
            prepare(root)
        if kill_when_connected:
            window = subprocess.Popen(["/bin/bash", str(REAL_RELAY_WINDOW)], env=env,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.monotonic() + 40
            while state.read_text().strip() != "Connected" and time.monotonic() < deadline:
                time.sleep(0.05)
            window.kill()  # SIGKILL: no EXIT trap runs
            window.wait(timeout=10)
            result = subprocess.CompletedProcess(window.args, window.returncode, "", "")
        else:
            result = subprocess.run(["/bin/bash", str(REAL_RELAY_WINDOW)], capture_output=True, text=True,
                                    env=env, timeout=150)
        rows = {}
        if (out / "results.tsv").exists():
            for line in (out / "results.tsv").read_text().splitlines():
                name, verdict, detail, status, _start, _end = line.split("\t")  # v31: UTC start, end
                rows[name] = (verdict, detail, status)
        return result, rows, calls.read_text().splitlines(), out, root

    @staticmethod
    def end_rollbacks(out):
        # A run that ends before its rollbacks finish leaves fake-only
        # rollbacks behind: end them by pid.
        for name in ("rollback.log", "filter-rollback.log"):
            try:
                log = (out / name).read_text()
            except OSError:
                continue
            if "rollback_cancelled" in log or "rollback_done" in log:
                continue
            for line in log.splitlines():
                if line.startswith("armed pid="):
                    try:
                        os.kill(int(line.split()[1].split("=")[1]), 9)
                    except (OSError, ValueError):
                        pass

    @staticmethod
    def wait_for(path, text, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if path.exists() and text in path.read_text():
                return True
            time.sleep(0.2)
        return False

    def assert_no_address(self, out):
        for text in ((out / "results.tsv").read_text(), (out / "window.log").read_text()):
            for address in (PC_GW0, PC_GW5, PC_LOCAL0, PC_LOCAL5, "198.51.100.9", "02:00:00:00:00:01",
                            "02:00:00:00:00:05"):
                self.assertNotIn(address, text)

    # ----------------------------------------------------- positive control

    def test_positive_control_probes_two_interfaces_and_classifies_the_bpf_order(self):
        result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", FAKE_EN5="1", FAKE_AWDL="1",
                                                         FAKE_BPF_PRE="en5")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("POSITIVE_CONTROL=1: probes=3 port=9 timeout=2s presock=2 wait=1s rollback_s=25", result.stdout)
        names = list(rows)
        self.assertEqual(names[0], "evidence_scope")
        self.assertEqual(rows["evidence_scope"][:2], (
            "info", "positive_control: owner-attended control with marked probes; its rows are never S20 evidence"))
        self.assertEqual(rows["positive_control_ifaces"][:2],
                         ("info", "probe=en0,en5 skipped=awdl0:no_ipv4 probes=3 port=9"))
        # The marked probes go only to each interface's LAN gateway, port 9,
        # while Connected, from their own source ports.
        probes = [c for c in calls if c.startswith("probe boundsyn ") and len(c.split()) > 3]
        self.assertEqual(probes, [f"probe boundsyn en0 {PC_GW0} 9 3 47100 2", f"probe boundsyn en5 {PC_GW5} 9 3 47103 2"])
        for dev in ("en0", "en5"):
            self.assertEqual(rows[f"probe_failed_{dev}"][:2], ("pass", "probes=3 failed=3 kinds=timeout:3 ms=6000 rc=0 port=9"))
            self.assertEqual(rows[f"probe_failed_{dev}"][2], "Connected")
            self.assertLess(names.index("connected"), names.index(f"probe_failed_{dev}"))
            self.assertLess(names.index(f"filter_drop_delta_{dev}"), names.index("disconnect_verified"))
        self.assertEqual(rows["filter_drop_delta_en0"][:2],
                         ("pass", "class=primary out_before=0 out_after=6 delta=6 syn_drops=6 ring_lost=0 need=3"))
        self.assertEqual(rows["filter_drop_delta_en5"][:2],
                         ("pass", "class=en_other out_before=0 out_after=6 delta=6 syn_drops=6 ring_lost=0 need=3"))
        self.assertEqual(rows["bpf_order_en0"][:2],
                         ("info", "post_filter syns=0 probes=3 capture=physical.pcap filter_drop_delta=pass"))
        self.assertEqual(rows["bpf_order_en5"][:2],
                         ("info", "pre_filter syns=3 probes=3 capture=physical-en5.pcap filter_drop_delta=pass"))
        # Its leak rows are its own, never the S20 rows.
        for name in ("leak_proof", "no_v6_leak_physical", "leak_proof_all_ifaces", "no_mac_sent_leak_physical",
                     "leak_capture_ifaces", "leak_window_connected_at", "filter_armed_span"):
            self.assertNotIn(name, rows)
            self.assertIn("positive_control_" + name, rows)
        self.assertEqual(rows["positive_control_leak_proof"][0], "pass", rows["positive_control_leak_proof"])
        self.assertEqual(rows["positive_control_filter_armed_span"][0], "pass")
        # The probes the capture saw are Mac-sent frames there. The last
        # interface's may fall in the guard second before the disconnect;
        # the armed span, which has no guard, counts all three.
        mac = rows["positive_control_no_mac_sent_leak_physical"]
        self.assertEqual(mac[0], "fail", mac)
        self.assertRegex(mac[1], r" en5:mac_sent_leaks=[0-9]+,mac_sent_pass=(true|false),alive=1,stopped=1,drops=0,"
                                 r"armed_leaks=3 ")
        self.assertIn(" armed_span=reviewed uncaptured=none reason=", mac[1])
        self.assertTrue(mac[1].endswith("en5:mac_sent_armed_leaks=3"), mac)
        report = json.loads((out / "leak-review-en5.json").read_text())
        self.assertEqual(report["mac_sent_leaks"] + report["mac_sent_guard"], 3)
        self.assertEqual((report["mac_sent_armed_leaks"], report["mac_sent_armed_classes"]), (3, {"tcp_syn": 3}))
        self.assert_no_address(out)

    def test_positive_control_fails_its_rows_when_the_filter_misses_a_probe_or_one_connects(self):
        result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", FAKE_EN5="1",
                                                         FAKE_FILTER_BLIND="en0", FAKE_PROBE_CONNECTS="en5")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["filter_drop_delta_en0"][:2],
                         ("fail", "class=primary out_before=0 out_after=0 delta=0 syn_drops=0 ring_lost=0 need=3"))
        self.assertEqual(rows["bpf_order_en0"][:2], (
            "info", "unknown syns=0 probes=3 capture=physical.pcap filter_drop_delta=fail: the filter did not count the probes"))
        self.assertEqual(rows["probe_failed_en5"][:2],
                         ("fail", "probes=3 failed=2 kinds=connected:1,timeout:2 ms=12 rc=1 port=9"))
        self.assertEqual(rows["filter_drop_delta_en5"][0], "pass")
        # A probe that was answered went out unfiltered: no BPF order from it.
        self.assertEqual(rows["bpf_order_en5"][:2], (
            "info", "unknown syns=0 probes=3 capture=physical-en5.pcap probe_failed=fail: not every probe went unanswered"))
        # Without observability in --filter-status the delta cannot pass.
        result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", FAKE_NO_OBS="1")
        self.assertEqual(rows["filter_drop_delta_en0"][:2],
                         ("fail", "unavailable: no observability in --filter-status need=3"))

    def test_bpf_order_needs_probes_the_filter_counted_never_syns_it_let_out(self):
        # An interface the filter does not see: the probes leave unfiltered,
        # the capture holds the marked SYNs, and the filter counted none.
        # That says nothing about where the BPF tap sits (it was pre_filter).
        result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", FAKE_EN5="1",
                                                         FAKE_FILTER_BLIND="en5", FAKE_BPF_PRE="en5")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["bpf_order_en5"][:2], (
            "info", "unknown syns=3 probes=3 capture=physical-en5.pcap filter_drop_delta=fail: the filter did not count the probes"))
        self.assertEqual(rows["probe_failed_en5"][0], "pass")
        self.assertEqual(rows["filter_drop_delta_en5"][:2],
                         ("fail", "class=en_other out_before=0 out_after=0 delta=0 syn_drops=0 ring_lost=0 need=3"))
        self.assertEqual(rows["bpf_order_en0"][:2],
                         ("info", "post_filter syns=0 probes=3 capture=physical.pcap filter_drop_delta=pass"))
        self.assert_no_address(out)

    def test_the_drop_delta_counts_only_the_probes_own_syn_drops_on_that_interface(self):
        # Other drops of the class while the filter misses the probes (mDNS
        # and another interface's SYNs) grow the class counter past the
        # probe count; they never count as the probes (it was post_filter).
        result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", FAKE_EN5="1",
                                                         FAKE_FILTER_BLIND="en5", FAKE_NOISE_IF="en5")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["filter_drop_delta_en5"][:2],
                         ("fail", "class=en_other out_before=0 out_after=6 delta=6 syn_drops=0 ring_lost=0 need=3"))
        self.assertEqual(rows["bpf_order_en5"][:2], (
            "info", "unknown syns=0 probes=3 capture=physical-en5.pcap filter_drop_delta=fail: the filter did not count the probes"))
        self.assertEqual(rows["filter_drop_delta_en0"][0], "pass")
        # Probes that never left (eaddrinuse) say nothing: unavailable, and
        # the class noise does not make them post_filter.
        result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", FAKE_EN5="1",
                                                         FAKE_PROBE_INCONCLUSIVE="en5", FAKE_NOISE_IF="en5")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["probe_failed_en5"][:2],
                         ("unavailable", "probes=3 failed=3 kinds=eaddrinuse:3 ms=3 rc=3 port=9"))
        self.assertEqual(rows["filter_drop_delta_en5"][:2],
                         ("fail", "class=en_other out_before=0 out_after=6 delta=6 syn_drops=0 ring_lost=0 need=3"))
        self.assertEqual(rows["bpf_order_en5"][1].split(" ")[0], "unknown")
        # The probes' records pushed out of the 64-entry ring by later drops
        # cannot be tied to the probes: fail, with the lost records named.
        result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", FAKE_EN5="1",
                                                         FAKE_NOISE_IF="en5", FAKE_NOISE_N="70")
        self.assertEqual(rows["filter_drop_delta_en5"][:2],
                         ("fail", "class=en_other out_before=0 out_after=76 delta=76 syn_drops=0 ring_lost=12 need=3"))
        self.assertEqual(rows["bpf_order_en5"][1].split(" ")[0], "unknown")
        # A re-arm between the two readings: not one arm through the probes.
        result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", FAKE_EN5="1", FAKE_PROBE_REARM="en5")
        self.assertEqual(rows["filter_drop_delta_en5"][:2], (
            "fail", "rearmed: mode_after=guarding arm_seq=1->2 disarms=0->0: not one arm through the probes "
                    "class=en_other need=3"))
        self.assertEqual(rows["probe_failed_en5"][0], "pass")

    def test_positive_control_never_probes_an_off_link_gateway(self):
        result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", FAKE_EN5="1", FAKE_GW_EN5="203.0.113.99")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["positive_control_ifaces"][:2],
                         ("info", "probe=en0 skipped=en5:no_lan_gateway probes=3 port=9"))
        self.assertEqual([c.split()[2] for c in calls if c.startswith("probe boundsyn ") and len(c.split()) > 3],
                         ["en0"])
        self.assertNotIn("probe_failed_en5", rows)
        self.assertNotIn("203.0.113.99", (out / "results.tsv").read_text())

    def test_positive_control_refuses_before_any_connect(self):
        cases = (
            ({"NEGATIVE_CONTROL": "1"}, "not with NEGATIVE_CONTROL=1: one control per window"),
            ({"LEAK_CAPTURE": "0"}, "needs LEAK_CAPTURE=1"),
            ({"FILTER_REQUIRED": "0", "FAKE_FILTER_EXIT": "33",
              "FAKE_FILTER_LINE": "filter_result=not_attached exit_code=33"},
             "needs the leak-guard filter configured, enabled and attached before the window (host --filter-status exit 33)"),
            ({"PC_PROBES": "11"}, "PC_PROBES=11 is outside 1..10"),
            # S20h review: a fresh probe's source port in the marker range
            # would count as a pre-existing socket's marked drop.
            ({"PC_SPORT_BASE": "46998"}, "PC_SPORT_BASE=46998 puts a probe's source port in the pre-existing "
                                         "sockets' marker range"),
            ({"PC_SPORT_BASE": "47031"}, "PC_SPORT_BASE=47031 puts a probe's source port in the pre-existing "
                                         "sockets' marker range"),
            # The second interface's probes start PC_PROBES ports later
            # (46999..47001): its last ones reach into the range.
            ({"PC_SPORT_BASE": "46996", "FAKE_EN5": "1"}, "PC_SPORT_BASE=46996 puts a probe's source port in the "
                                                          "pre-existing sockets' marker range"),
        )
        for extra, why in cases:
            with self.subTest(why=why):
                result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", **extra)
                self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
                self.assertIn(f"refused: POSITIVE_CONTROL=1: {why}", result.stdout)
                self.assertFalse(any(c.startswith(("host --connect", "sudo -n /usr/sbin/tcpdump", "probe boundsyn"))
                                     for c in calls), calls)
                self.assertFalse((root / "home" / ".aegis-local" / "locks" / "timing-self").exists())
        result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1",
                                                         handoff_extra={"relay": f"{RELAY_IP}:9"})
        self.assertEqual(result.returncode, 3)
        self.assertIn("never probe the relay port", result.stdout)
        # No interface to probe: refused after the captures, which are
        # stopped, before the lock, the rollback or any connect.
        result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", FAKE_NO_GW="1")
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("refused: POSITIVE_CONTROL=1: no captured interface has an IPv4 address and an on-link "
                      "default gateway to probe", result.stdout)
        self.assertEqual(rows["positive_control_ifaces"][:2],
                         ("info", "probe=none skipped=en0:no_lan_gateway probes=3 port=9"))
        self.assertIn("tcpdump stopped if=en0", calls)
        self.assertFalse(any(c.startswith(("host --connect", "probe boundsyn")) for c in calls), calls)
        self.assertFalse((out / "rollback.log").exists())
        self.assertFalse((root / "home" / ".aegis-local" / "locks" / "timing-self").exists())

    # ----------------------------------------------------- negative control

    def test_negative_control_disables_the_filter_for_the_window_and_restores_it(self):
        result, rows, calls, out, root = self.run_window(NEGATIVE_CONTROL="1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("OWNER ACTION: approve the administrator prompt that turns the AEGIS leak guard off", result.stdout)
        self.assertEqual(rows["evidence_scope"][:2], (
            "info", "negative_control: the leak-guard filter is disabled for this window; its rows are never S20 evidence"))
        self.assertEqual(rows["negative_control_rollback_armed"][0], "pass")
        self.assertEqual(rows["negative_control_filter_disabled"][:2], ("pass", "rc=0 status_exit=31"))
        disable = calls.index("host --disable-filter")
        capture = next(i for i, c in enumerate(calls) if c.startswith("sudo -n /usr/sbin/tcpdump"))
        connect = next(i for i, c in enumerate(calls) if c.startswith("host --connect"))
        stop = next(i for i, c in enumerate(calls) if c.startswith("scutil --nc stop"))
        enable = calls.index("host --enable-filter")
        self.assertLess(disable, capture)
        self.assertLess(capture, connect)
        self.assertLess(stop, enable)
        self.assertEqual(rows["filter_preflight"][0], "pass")
        self.assertTrue(rows["filter_counters_after"][1].startswith("exit=31 filter_result=disabled "))
        self.assertEqual(rows["negative_control_filter_restored"][0], "pass")
        self.assertTrue(rows["negative_control_filter_restored"][1].startswith("enable_rc=0 status_exit=0 "))
        self.assertEqual(rows["negative_control_rollback_ended"][:2], ("info", "rollback_cancelled restored_verified"))
        self.assertEqual((root / "filter").read_text().strip(), "enabled")
        for name in ("leak_proof", "no_mac_sent_leak_physical", "no_v6_leak_physical", "filter_armed_span"):
            self.assertNotIn(name, rows)
            self.assertIn("negative_control_" + name, rows)
        names = list(rows)
        self.assertLess(names.index("negative_control_filter_restored"), names.index("negative_control_leak_proof"))
        self.assertIn("done", result.stdout)
        # The interrupted-control marker existed while the filter was off
        # and is gone once the restore was verified.
        self.assertIn("marker_at_disable", calls)
        self.assertFalse((root / "home" / ".aegis-local" / "negative-control-filter-disabled").exists())
        self.assert_no_address(out)

    def test_negative_control_refuses_and_restores_when_the_filter_is_not_disabled(self):
        result, rows, calls, out, root = self.run_window(NEGATIVE_CONTROL="1", FAKE_DISABLE_EXIT="67")
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("refused: NEGATIVE_CONTROL=1: the filter was not disabled (host exit 67, --filter-status exit 0); "
                      "nothing connected", result.stdout)
        self.assertEqual(rows["negative_control_filter_disabled"][0], "fail")
        self.assertEqual(rows["negative_control_filter_restored"][0], "pass")
        self.assertFalse(any(c.startswith(("host --connect", "sudo -n /usr/sbin/tcpdump")) for c in calls), calls)
        self.assertIn("rollback_cancelled restored_verified", (out / "filter-rollback.log").read_text())
        self.assertEqual((root / "filter").read_text().strip(), "enabled")
        self.assertFalse((root / "home" / ".aegis-local" / "locks" / "timing-self").exists())
        # A disable that reports success while the filter still reads
        # enabled is no disable either.
        result, rows, calls, out, root = self.run_window(NEGATIVE_CONTROL="1", FAKE_DISABLE_NOOP="1")
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("the filter was not disabled (host exit 0, --filter-status exit 0)", result.stdout)
        self.assertFalse(any(c.startswith("host --connect") for c in calls), calls)

    def test_a_negative_control_whose_filter_is_not_restored_fails_the_window(self):
        # The window's restore and its EXIT trap's retry fail; the rollback,
        # left armed, restores the filter once the window is gone.
        result, rows, calls, out, root = self.run_window(NEGATIVE_CONTROL="1", FAKE_ENABLE_FAILS="2",
                                                         NC_ATTACH_WAIT_S="5")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("FAILED: negative control: the leak-guard filter is not restored (enable rc=34, "
                      "--filter-status exit 31)", result.stdout)
        self.assertNotIn(" done\n", result.stdout)
        self.assertEqual(rows["negative_control_filter_restored"][0], "fail")
        log = out / "filter-rollback.log"
        self.assertTrue(self.wait_for(log, "rollback_done", 60), log.read_text())
        text = log.read_text()
        self.assertNotIn("rollback_cancelled", text)
        self.assertIn("window_gone", text)
        self.assertIn("restored attempt=1", text)
        self.assertEqual((root / "filter").read_text().strip(), "enabled")

    def test_the_filter_rollback_restores_the_filter_after_a_killed_window(self):
        result, rows, calls, out, root = self.run_window(kill_when_connected=True, NEGATIVE_CONTROL="1")
        self.assertEqual(result.returncode, -9)
        self.assertEqual((root / "filter").read_text().strip(), "disabled")
        log = out / "filter-rollback.log"
        self.assertTrue(self.wait_for(log, "rollback_done", 60), log.read_text() if log.exists() else "")
        self.assertIn("window_gone", log.read_text())
        self.assertIn("restored attempt=1", log.read_text())
        self.assertEqual((root / "filter").read_text().strip(), "enabled")
        # Only after its verified restore does the rollback remove the marker.
        self.assertIn("marker_removed", log.read_text())
        self.assertFalse((root / "home" / ".aegis-local" / "negative-control-filter-disabled").exists())

    def test_a_refusal_after_the_disable_exits_1_while_the_filter_stays_off(self):
        # The disable read back 36, not 31, and neither the window's restore
        # nor its EXIT trap's retry brings the filter back: exit 1, never
        # the refusal's 3 ("nothing connected").
        result, rows, calls, out, root = self.run_window(NEGATIVE_CONTROL="1", FAKE_DISABLED_EXIT="36",
                                                         FAKE_ENABLE_FAILS="2", NC_ATTACH_WAIT_S="5")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("refused: NEGATIVE_CONTROL=1: the filter was not disabled (host exit 0, --filter-status exit 36)",
                      result.stdout)
        self.assertIn("FAILED: negative control: the leak-guard filter is not restored (enable rc=34, "
                      "--filter-status exit 36)", result.stdout)
        self.assertEqual(rows["negative_control_filter_restored"][0], "fail")
        self.assertFalse(any(c.startswith(("host --connect", "sudo -n /usr/sbin/tcpdump")) for c in calls), calls)
        log = out / "filter-rollback.log"
        self.assertTrue(self.wait_for(log, "rollback_done", 60), log.read_text())
        self.assertIn("restored attempt=1", log.read_text())
        self.assertEqual((root / "filter").read_text().strip(), "enabled")
        # The disable took, then the capture did not start (exit 3): the EXIT
        # trap's restore fails, so the window exits 1.
        result, rows, calls, out, root = self.run_window(NEGATIVE_CONTROL="1", FAKE_TCPDUMP_FAIL_IF="en0",
                                                         FAKE_ENABLE_FAILS="1", NC_ATTACH_WAIT_S="5")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("refused: tcpdump on en0 did not start", result.stdout)
        self.assertIn("FAILED: negative control: the leak-guard filter is not restored (enable rc=34, "
                      "--filter-status exit 31)", result.stdout)
        self.assertFalse(any(c.startswith("host --connect") for c in calls), calls)
        log = out / "filter-rollback.log"
        self.assertTrue(self.wait_for(log, "rollback_done", 60), log.read_text())
        self.assertEqual((root / "filter").read_text().strip(), "enabled")
        # The same refusal with a restore that works stays a refusal (exit 3).
        result, rows, calls, out, root = self.run_window(NEGATIVE_CONTROL="1", FAKE_TCPDUMP_FAIL_IF="en0")
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertNotIn("FAILED", result.stdout)
        self.assertIn("rollback_cancelled restored_verified", (out / "filter-rollback.log").read_text())
        self.assertEqual((root / "filter").read_text().strip(), "enabled")

    def test_the_restore_reads_the_filter_after_an_enable_slower_than_the_attach_wait(self):
        # The enable waits 7 s (the owner's Allow) and NC_ATTACH_WAIT_S is 5:
        # the attach wait starts when the enable returns, so the filter,
        # attached at once, is read and the restore passes.
        result, rows, calls, out, root = self.run_window(NEGATIVE_CONTROL="1", FAKE_ENABLE_DELAY_S="7",
                                                         NC_ATTACH_WAIT_S="5")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("FAILED", result.stdout)
        self.assertEqual(rows["negative_control_filter_restored"][0], "pass", rows["negative_control_filter_restored"])
        self.assertRegex(rows["negative_control_filter_restored"][1], r"^enable_rc=0 status_exit=0 waited=[0-9]+s$")
        self.assertEqual(rows["negative_control_rollback_ended"][:2], ("info", "rollback_cancelled restored_verified"))

    def test_an_interrupted_negative_control_marker_refuses_windows_until_the_filter_is_back(self):
        marker_of = lambda root: root / "home" / ".aegis-local" / "negative-control-filter-disabled"
        gone = subprocess.Popen(["/usr/bin/true"])
        gone.wait()

        def interrupted(filter_state, pid):
            def prepare(root):
                marker_of(root).write_text(f"start=20261024T060000Z pid={pid} out=/nonexistent/out\n")
                (root / "filter").write_text(filter_state + "\n")
            return prepare

        # A reboot cut off a negative control: its EXIT trap and its rollback
        # never ran, the filter stayed disabled. A plain window (no capture,
        # FILTER_REQUIRED=0) refuses before connecting.
        result, rows, calls, out, root = self.run_window(LEAK_CAPTURE="0", prepare=interrupted("disabled", gone.pid))
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("refused: an interrupted NEGATIVE_CONTROL window left the leak-guard filter disabled (", result.stdout)
        self.assertIn("host --filter-status exit 31): run ", result.stdout)
        self.assertIn(" --enable-filter until --filter-status exits 0; nothing connected", result.stdout)
        self.assertFalse(any(c.startswith("host --connect") for c in calls), calls)
        self.assertTrue(marker_of(root).exists())
        # A capture window too, before its own FILTER_REQUIRED refusal.
        result, rows, calls, out, root = self.run_window(prepare=interrupted("disabled", gone.pid))
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("refused: an interrupted NEGATIVE_CONTROL window", result.stdout)
        self.assertFalse(any(c.startswith(("host --connect", "sudo -n /usr/sbin/tcpdump")) for c in calls), calls)
        # Once the filter is attached again the next window removes the
        # marker of a window that is gone, and runs.
        result, rows, calls, out, root = self.run_window(LEAK_CAPTURE="0", prepare=interrupted("enabled", gone.pid))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("negative_control_marker: removed, the leak-guard filter is attached again", result.stdout)
        self.assertFalse(marker_of(root).exists())
        self.assertTrue(any(c.startswith("host --connect") for c in calls), calls)
        # A marker whose window still runs is kept.
        result, rows, calls, out, root = self.run_window(LEAK_CAPTURE="0", prepare=interrupted("enabled", os.getpid()))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"negative_control_marker: kept, its window (pid {os.getpid()}) is still running", result.stdout)
        self.assertTrue(marker_of(root).exists())


    # ------------------------------------------- S20g pre-existing sockets

    def presock(self, reset_on_accept=False, **extra):
        """A FakeGateway and the presock shim, as window environment: the
        gateway accepts the window's ports 53 and 8080, not 80."""
        gateway = FakeGateway(reset_on_accept=reset_on_accept)
        self.addCleanup(gateway.close)
        temp = tempfile.TemporaryDirectory(prefix="aegis-s20g-shim-")
        self.addCleanup(temp.cleanup)
        shim = pathlib.Path(temp.name) / "presock_shim.py"
        shim.write_text(PRESOCK_SHIM_PY)
        env = {"PRESOCK_SHIM": str(shim), "FAKE_GW_PORT": str(gateway.port), "FAKE_GW_CLOSED": str(gateway.closed),
               "FAKE_GW_OPEN": "53 8080"}
        env.update(extra)
        return gateway, env

    def presock_ka(self, **extra):
        """S20h: presock with the shim's keepalives, every second from one
        second after each connect (PRESOCK_KEEPALIVE=1/1/60)."""
        return self.presock(FAKE_PRESOCK_KA="1", PRESOCK_KEEPALIVE="1/1/60", **extra)

    def assert_no_port(self, out, rows, gateway):
        """No row or log names the gateway's port, a closed one, or a local
        port of the helpers; the private state files hold them, mode 0600."""
        ports = {gateway.port, gateway.closed}
        states = list(out.glob("presock-*.json"))
        self.assertTrue(states)
        for state in states:
            self.assertEqual(state.stat().st_mode & 0o777, 0o600, state)
            doc = json.loads(state.read_text())
            ports.update(entry["lport"] for entry in doc.get("sockets", []) if "lport" in entry)
            self.assertNotIn("192.0.2", state.read_text())
            self.assertNotIn("198.51.100", state.read_text())
        for name, (verdict, detail, status) in rows.items():
            if "presock" in name or "bound_fresh" in name or "verdict" in name:
                for port in ports:
                    self.assertNotRegex(detail, rf"\b{port}\b", name)
        text = (out / "results.tsv").read_text() + (out / "window.log").read_text()
        for port in ports:
            self.assertNotRegex(text, rf"[=:]{port}\b")

    # S20h: the keepalive criterion's row, its counted row and the frames.
    KA_PASS = (r"^class={cls} sockets=2 expected=(?P<e>[0-9]+) per_socket=[0-9]+,[0-9]+ counted=(?P<c>[0-9]+) "
               r"matched=(?P=e) unmarked=0 inferred=0 ring_lost=0 data_counted={data} tx={tx} rx=helper "
               r"keepalive=1/1 tol_ms=500 span_ms=[0-9]+$")

    def assert_keepalives_pass(self, rows, dev, cls, data=4, tx=4):
        verdict, detail, status = rows[f"positive_control_presock_keepalive_drops_{dev}"]
        self.assertEqual((verdict, status), ("pass", "Disconnected"), detail)
        m = re.match(self.KA_PASS.format(cls=cls, data=data, tx=tx), detail)
        self.assertIsNotNone(m, detail)
        # At least two due keepalives a socket, each counted as marked.
        self.assertGreaterEqual(int(m.group("e")), 4, detail)
        self.assertGreaterEqual(int(m.group("c")), int(m.group("e")), detail)
        return int(m.group("e"))

    def test_positive_control_counted_keepalives_and_unacked_bytes_pass_the_verdict(self):
        gateway, env = self.presock_ka()
        result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", FAKE_EN5="1", **env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # Each interface's LAN gateway only, its fixed ports in order without
        # the fake relay's port, before the connect.
        presocks = [c for c in calls if c.startswith("probe presock ") and len(c.split()) > 3]
        self.assertEqual(presocks, [f"probe presock en0 {PC_GW0} 80,53,8080 2 2 1 325",
                                    f"probe presock en5 {PC_GW5} 80,53,8080 2 2 1 325"])
        connect = next(i for i, c in enumerate(calls) if c.startswith("host --connect"))
        self.assertLess(calls.index(presocks[-1]), connect)
        self.assertEqual(gateway.accepted, 6)
        names = list(rows)
        self.assertEqual(rows["positive_control_presock_ifaces"][:2], ("info", "ifaces=en0,en5 skipped=none n=2 wait=1s"))
        for dev, cls, file in (("en0", "primary", "physical.pcap"), ("en5", "en_other", "physical-en5.pcap")):
            state = json.loads((out / f"presock-{dev}.json").read_text())
            # 80 refused, 53 accepted: the first accepting port, in order.
            self.assertEqual((state["test_window_port"], state["select_kinds"]), (53, {"connected": 1, "refused": 1}))
            self.assertEqual((state["phase"], state["mark_sport"], state["keepalive"]),
                             ("closed", [47000, 32], [1, 1, 60]))
            self.assertTrue(all(isinstance(s["t_connected"], float) for s in state["sockets"]))
            # S20h review: every kept socket bound in the provider's marker
            # range, which is how its keepalives are marked.
            self.assertTrue(all(47000 <= s["lport"] < 47032 for s in state["sockets"]), state["sockets"])
            self.assertEqual(rows[f"positive_control_presock_open_{dev}"],
                             ("pass", "open opened=2 need=2 kinds=connected:2 keepalive=1/1/60", "Disconnected"))
            self.assertLess(names.index(f"positive_control_presock_open_{dev}"), names.index("connected"))
            verdict, detail, status = rows[f"positive_control_presock_unacked_{dev}"]
            self.assertEqual((verdict, status), ("pass", "Connected"))
            self.assertRegex(detail, r"^written=2 acked=0 unacked=2 reset=0 rx=0 timed_out=0 closed=0 not_written=0 "
                                     r"answered=0 tx=4 retx=2 rx_packets=0 wait=1s$")
            self.assertLess(names.index(f"positive_control_presock_unacked_{dev}"), names.index(f"probe_failed_{dev}"))
            self.assertNotIn(f"positive_control_presock_drop_delta_{dev}", rows)
            # Judged after the captures and the provider log.
            self.assertLess(names.index("disconnect_verified"), names.index(f"positive_control_presock_keepalive_drops_{dev}"))
            expected = self.assert_keepalives_pass(rows, dev, cls)
            self.assertRegex(rows[f"positive_control_presock_counted_{dev}"][1],
                             rf"^tx=4 data_counted=4 blocked_before_filter=0 keepalive_expected={expected} "
                             rf"keepalive_counted=[0-9]+ class={cls}$")
            self.assertEqual(rows[f"positive_control_presock_counted_{dev}"][0], "info")
            self.assertRegex(rows[f"positive_control_presock_bpf_order_{dev}"][1],
                             rf"^post_filter frames=0 data=0 ack_only=0 other=0 uncounted=0 total=[0-9]+ "
                             rf"after_disarm=[1-9][0-9]* tap_evidence=post_filter capture={file} "
                             r"presock_keepalive_drops=pass span=armed$")
            self.assertNotIn(f"presock_keepalive_drops_{dev}", rows)
        # The two reads around each write are at least 2 * intvl + 2 s apart.
        for dev in ("en0", "en5"):
            self.assertTrue((out / f"filter-status-presock-{dev}-before.txt").exists())
            self.assertTrue((out / f"filter-status-presock-{dev}-after.txt").exists())
        self.assertEqual(rows["positive_control_presock_closed"][:2], ("info", "en0:closed en5:closed"))
        self.assertEqual(rows["positive_control_verdict"][:2], (
            "pass", "primary=en0 presock_open=pass presock_unacked=pass presock_keepalive_drops=pass "
                    "frames_while_armed=0 frames_checked=en0,en5 captures=complete"))
        self.assertEqual(names[-1], "positive_control_verdict")
        # The fresh probes still time out at the filter here.
        self.assertEqual(rows["positive_control_bound_fresh_en0"][:2],
                         ("info", "unanswered probe_failed=pass engine_opens=none"))
        self.assert_no_address(out)
        self.assert_no_port(out, rows, gateway)

    def test_positive_control_passes_when_the_written_segments_never_reach_the_filter(self):
        # includeAllNetworks holds a pre-existing socket's own output before
        # the filter (v28): no data drop is counted, nothing leaves, and the
        # counted keepalives still show the filter dropping the sockets'
        # kernel traffic. The write is reported, never required.
        gateway, env = self.presock_ka(FAKE_PRESOCK_DROPS="0")
        result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", **env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["positive_control_presock_unacked_en0"][0], "pass")
        expected = self.assert_keepalives_pass(rows, "en0", "primary", data=0)
        self.assertRegex(rows["positive_control_presock_counted_en0"][1],
                         rf"^tx=4 data_counted=0 blocked_before_filter=4 keepalive_expected={expected} "
                         r"keepalive_counted=[0-9]+ class=primary$")
        self.assertEqual(rows["positive_control_verdict"][:2], (
            "pass", "primary=en0 presock_open=pass presock_unacked=pass presock_keepalive_drops=pass "
                    "frames_while_armed=0 frames_checked=en0 captures=complete"))
        self.assert_no_port(out, rows, gateway)

    def test_written_bytes_acknowledged_while_armed_fail_the_positive_verdict(self):
        # The filter misses en5: its pre-existing sockets' bytes reach the
        # gateway and come back acknowledged while armed, a real leak, even
        # with the primary interface's sockets passing.
        gateway, env = self.presock_ka(FAKE_FILTER_BLIND="en5")
        result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", FAKE_EN5="1", **env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        verdict, detail, status = rows["positive_control_presock_unacked_en5"]
        self.assertEqual(verdict, "fail", detail)
        self.assertRegex(detail, r"^written=2 acked=2 unacked=0 reset=0 rx=0 timed_out=0 closed=0 not_written=0 "
                                 r"answered=2 ")
        self.assertEqual(rows["positive_control_presock_keepalive_drops_en5"][0], "unavailable")
        self.assertRegex(rows["positive_control_presock_keepalive_drops_en5"][1],
                         r"^unattributed: no marked bare ACK was counted class=en_other .* counted=0 matched=0 ")
        self.assertRegex(rows["positive_control_presock_bpf_order_en5"][1],
                         r"^unknown frames=([0-9]+) data=2 ack_only=[1-9][0-9]* other=0 uncounted=\1 total=[0-9]+ "
                         r"after_disarm=[1-9][0-9]* tap_evidence=none capture=physical-en5.pcap "
                         r"presock_keepalive_drops=unavailable: ")
        self.assertEqual(rows["positive_control_presock_unacked_en0"][0], "pass")
        self.assert_keepalives_pass(rows, "en0", "primary")
        self.assertEqual(rows["positive_control_verdict"][:2], (
            "fail", "answered_while_armed=en5 uncounted_frames=en5 primary=en0: written bytes of a pre-existing "
                    "socket were answered while the filter was armed; that interface's capture holds more of the "
                    "helper's frames while armed than the filter counted marked drops of their kind: they left the Mac"))
        self.assert_no_address(out)
        self.assert_no_port(out, rows, gateway)

    def test_keepalives_the_filter_did_not_count_or_attribute_leave_the_verdict_unavailable(self):
        # Never a pass without the helper's own keepalives counted as marked
        # drops, and never a fail when nothing left the Mac.
        cases = (
            # The system holds the keepalives before the filter too.
            ({"FAKE_PRESOCK_KA_BLIND": "1"}, r"^unattributed: no marked bare ACK was counted class=primary sockets=2 "
                                             r"expected=[0-9]+ per_socket=[0-9]+,[0-9]+ counted=0 matched=0 unmarked=0 "
                                             r"inferred=0 ring_lost=0 data_counted=4 tx=4 "),
            # Dropped, but not marked: timing alone is pass_inferred at best.
            ({"FAKE_PRESOCK_UNMARKED": "1"}, r"^unattributed: no marked bare ACK was counted \(pass_inferred: "
                                             r"unmarked ones fit every due keepalive\) class=primary sockets=2 "
                                             r"expected=([0-9]+) per_socket=[0-9]+,[0-9]+ counted=0 matched=0 "
                                             r"unmarked=[0-9]+ inferred=\1 ring_lost=0 data_counted=0 tx=4 "),
            # A provider before v29 has no outbound counts.
            ({"FAKE_NO_OUTBOUND": "1"}, r"^no_outbound: a provider before v29 class=primary tx=4$"),
            # A provider whose marker range is not the helper's.
            ({"FAKE_MARK_FIRST": "47100"}, r"^mark_mismatch: the provider's marker range is not the helper's "
                                           r"class=primary$"),
        )
        for extra, detail in cases:
            with self.subTest(extra=extra):
                gateway, env = self.presock_ka(**extra)
                result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", **env)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(rows["positive_control_presock_unacked_en0"][0], "pass")
                verdict, text, _ = rows["positive_control_presock_keepalive_drops_en0"]
                self.assertEqual(verdict, "unavailable", text)
                self.assertRegex(text, detail)
                if "FAKE_PRESOCK_KA_BLIND" in extra:
                    # S20h review: the four marked data drops are not in
                    # the capture, so its tap comes after the filter; with
                    # no helper frame in it that says nothing more.
                    self.assertRegex(rows["positive_control_presock_bpf_order_en0"][1],
                                     r"^post_filter frames=0 data=0 ack_only=0 other=0 uncounted=0 total=[0-9]+ "
                                     r"after_disarm=[1-9][0-9]* tap_evidence=post_filter capture=physical.pcap "
                                     r"presock_keepalive_drops=unavailable span=armed$")
                else:
                    self.assertRegex(rows["positive_control_presock_bpf_order_en0"][1],
                                     r"^unknown frames=0 data=0 ack_only=0 other=0 uncounted=0 .* "
                                     r"presock_keepalive_drops=unavailable: ")
                self.assertEqual(rows["positive_control_verdict"][:2], (
                    "unavailable", "primary=en0 presock_open=pass presock_unacked=pass "
                                   "presock_keepalive_drops=unavailable frames_seen=none frames_unchecked=none"))

    def test_marked_data_drops_must_cover_every_segment_the_sockets_sent(self):
        # Marked data drops appear (the written segments do reach the filter
        # here): then they must cover every data segment the sockets sent,
        # retransmissions included (tx=10: five a socket). Four do not;
        # ten do; none at all is the v28 case, the segments held before the
        # filter (blocked_before_filter=10), and still passes.
        for drops, verdict, counted in (
                ("2", "unavailable", "tx=10 data_counted=4 blocked_before_filter=6"),
                ("5", "pass", "tx=10 data_counted=10 blocked_before_filter=0"),
                ("0", "pass", "tx=10 data_counted=0 blocked_before_filter=10")):
            with self.subTest(drops=drops):
                gateway, env = self.presock_ka(FAKE_PRESOCK_RETX="4", FAKE_PRESOCK_DROPS=drops)
                result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", **env)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertRegex(rows["positive_control_presock_unacked_en0"][1], r" tx=10 retx=8 ")
                row = rows["positive_control_presock_keepalive_drops_en0"]
                self.assertEqual(row[0], verdict, row)
                if verdict == "unavailable":
                    self.assertRegex(row[1], r"^data_partial: the filter counted some of the written segments but "
                                             r"not every one the sockets sent class=primary .* data_counted=4 tx=10 ")
                self.assertTrue(rows["positive_control_presock_counted_en0"][1].startswith(counted + " "),
                                rows["positive_control_presock_counted_en0"])
                self.assertEqual(rows["positive_control_verdict"][0], verdict, rows["positive_control_verdict"])
                self.assert_no_port(out, rows, gateway)

    def test_the_helpers_frames_sent_uncounted_while_armed_fail_the_positive_verdict(self):
        # The filter lets the interface's pre-existing-socket segments and
        # keepalives out (they are in its capture, no drop is counted) and
        # drops the gateway's answers inbound, so the bytes stay
        # unacknowledged: presock_unacked passes and says nothing about the
        # outbound bytes. The verdict fails on the frames, on another
        # interface as on the primary one, whatever the primary interface's
        # rows show.
        for dev, extra, file, primary in (("en5", {"FAKE_EN5": "1"}, "physical-en5.pcap", "pass"),
                                          ("en0", {}, "physical.pcap", "unavailable")):
            with self.subTest(dev=dev):
                gateway, env = self.presock_ka(FAKE_FILTER_OUT_BLIND=dev)
                result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", **extra, **env)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(rows[f"positive_control_presock_unacked_{dev}"][0], "pass")
                self.assertRegex(rows[f"positive_control_presock_unacked_{dev}"][1], r" answered=0 ")
                self.assertEqual(rows[f"positive_control_presock_keepalive_drops_{dev}"][0], "unavailable")
                self.assertRegex(rows[f"positive_control_presock_keepalive_drops_{dev}"][1], r" counted=0 ")
                self.assertRegex(rows[f"positive_control_presock_bpf_order_{dev}"][1],
                                 rf"^unknown frames=([0-9]+) data=2 ack_only=[1-9][0-9]* other=0 uncounted=\1 "
                                 rf"total=[0-9]+ after_disarm=[1-9][0-9]* tap_evidence=none capture={file} "
                                 rf"presock_keepalive_drops=unavailable: ")
                self.assertEqual(rows["positive_control_presock_keepalive_drops_en0"][0], primary)
                self.assertEqual(rows["positive_control_verdict"][:2], (
                    "fail", f"uncounted_frames={dev} primary=en0: that interface's capture holds more of the helper's "
                            "frames while armed than the filter counted marked drops of their kind: they left the Mac"))
                self.assert_no_address(out)
                self.assert_no_port(out, rows, gateway)

    def test_helper_frames_in_a_capture_while_armed_are_never_pre_filter_nor_a_pass(self):
        # The filter counts the helper's segments and keepalives as marked
        # drops and the interface's capture holds them too: dropped after a
        # tap that sits before the filter, or sent while others were
        # dropped. The window cannot tell, so the order stays unknown and
        # the verdict is never pass, on the primary interface or another.
        # The fresh probes' pre_filter (en0) does not settle it either.
        for dev, extra, file in (("en0", {}, "physical.pcap"), ("en5", {"FAKE_EN5": "1"}, "physical-en5.pcap")):
            with self.subTest(dev=dev):
                gateway, env = self.presock_ka(FAKE_BPF_PRE=dev)
                result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", **extra, **env)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                for name in ("open", "unacked", "keepalive_drops"):
                    self.assertEqual(rows[f"positive_control_presock_{name}_{dev}"][0], "pass", name)
                    self.assertEqual(rows[f"positive_control_presock_{name}_en0"][0], "pass", name)
                # Every segment and keepalive the filter dropped is in the
                # capture (each socket's segment and its retransmission), so
                # nothing shows a tap after the filter.
                self.assertRegex(rows[f"positive_control_presock_bpf_order_{dev}"][1],
                                 rf"^unknown frames=[0-9]+ data=4 ack_only=[1-9][0-9]* other=0 uncounted=0 "
                                 rf"total=[0-9]+ after_disarm=[1-9][0-9]* tap_evidence=none capture={file} "
                                 rf"presock_keepalive_drops=pass span=armed: the helper's "
                                 r"frames are in the capture while armed; they may be frames the filter dropped "
                                 r"after the tap or frames that left$")
                for name, row in rows.items():
                    if "presock_bpf_order" in name:
                        self.assertFalse(row[1].startswith("pre_filter"), (name, row))
                if dev == "en0":
                    self.assertEqual(rows["bpf_order_en0"][1].split()[0], "pre_filter")
                self.assertEqual(rows["positive_control_verdict"][:2], (
                    "unavailable", f"primary=en0 presock_open=pass presock_unacked=pass presock_keepalive_drops=pass "
                                   f"frames_seen={dev} frames_unchecked=none: the helper's frames are in a capture "
                                   "while armed; they may be frames the filter dropped after the tap or frames that "
                                   "left the Mac"))
                self.assert_no_address(out)
                self.assert_no_port(out, rows, gateway)

    def test_helper_frames_in_a_capture_whose_tap_follows_the_filter_fail_the_positive_verdict(self):
        # S20h review: the filter counts the written segments' marked data
        # drops, yet one copy of each leaves (its frame in the capture).
        # Those drops outnumber the frames, so the frames are not
        # uncounted. But the filter dropped more of the marker's segments on
        # that interface between the reads than its complete capture holds
        # (none of the dropped keepalives, half the data segments): a tap
        # before the filter would hold every one, so the tap comes after it
        # and every helper frame in it while armed left the Mac.
        left = (r"presock_keepalive_drops=[a-z]+ span=armed: the filter dropped more of the marker's segments on "
                r"this interface than its capture holds, so its tap comes after the filter and the helper's frames "
                r"in it while armed left the Mac$")
        verdict = lambda dev: (
            "fail", f"frames_left={dev} primary=en0: that interface's complete capture holds the helper's frames "
                    "while armed but fewer of the marker's frames than the filter dropped on it, so its tap comes "
                    "after the filter: they left the Mac")
        for dev, cls, extra, file in (("en0", "primary", {}, "physical.pcap"),
                                      ("en5", "en_other", {"FAKE_EN5": "1"}, "physical-en5.pcap")):
            with self.subTest(dev=dev):
                gateway, env = self.presock_ka(FAKE_PRESOCK_DATA_LEAK=dev)
                result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", **extra, **env)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(rows[f"positive_control_presock_unacked_{dev}"][0], "pass")
                self.assert_keepalives_pass(rows, dev, cls)
                self.assertRegex(rows[f"positive_control_presock_bpf_order_{dev}"][1],
                                 rf"^post_filter frames=2 data=2 ack_only=0 other=0 uncounted=0 total=[0-9]+ "
                                 rf"after_disarm=[1-9][0-9]* tap_evidence=post_filter capture={file} " + left)
                self.assertEqual(rows["positive_control_verdict"][:2], verdict(dev))
                self.assert_no_address(out)
                self.assert_no_port(out, rows, gateway)
        # The review's case: six data segments sent (tx=6), four counted as
        # marked drops, two left. v28 failed it on the delta; the keepalive
        # row reads data_partial, so only the tap evidence keeps the fail.
        # And with the keepalives held before the filter too (no keepalive
        # drop and no keepalive frame), the data drops alone show the order.
        for extra, row in (({"FAKE_PRESOCK_RETX": "2"}, r"^data_partial: .* data_counted=4 tx=6 "),
                           ({"FAKE_PRESOCK_KA_BLIND": "1"}, r"^unattributed: no marked bare ACK was counted .* "
                                                            r"data_counted=4 tx=4 ")):
            with self.subTest(extra=extra):
                gateway, env = self.presock_ka(FAKE_PRESOCK_DATA_LEAK="en0", **extra)
                result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", **env)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(rows["positive_control_presock_keepalive_drops_en0"][0], "unavailable")
                self.assertRegex(rows["positive_control_presock_keepalive_drops_en0"][1], row)
                self.assertRegex(rows["positive_control_presock_bpf_order_en0"][1],
                                 r"^post_filter frames=2 data=2 ack_only=0 other=0 uncounted=0 total=[0-9]+ "
                                 r"after_disarm=[1-9][0-9]* tap_evidence=post_filter capture=physical.pcap " + left)
                self.assertEqual(rows["positive_control_verdict"][:2], verdict("en0"))
                self.assert_no_port(out, rows, gateway)
        # Under a failing filter_armed_span (a re-arm) the reads are not tied
        # to the reviewed span, so the evidence is not used: frames_seen,
        # never frames_left and never a pass.
        gateway, env = self.presock_ka(FAKE_PRESOCK_DATA_LEAK="en0")
        result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", FAKE_SPAN="rearm", **env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["positive_control_filter_armed_span"][0], "fail")
        self.assertRegex(rows["positive_control_presock_bpf_order_en0"][1],
                         r"^unknown frames=2 data=2 ack_only=0 other=0 uncounted=0 total=[0-9]+ after_disarm=[1-9][0-9]* "
                         r"tap_evidence=post_filter capture=physical.pcap ")
        self.assertEqual(rows["positive_control_verdict"][0], "unavailable")
        self.assertIn(" frames_seen=en0 ", rows["positive_control_verdict"][1])
        # The same frames in a capture that lost frames show no tap order:
        # unavailable, never a pass.
        gateway, env = self.presock_ka(FAKE_PRESOCK_DATA_LEAK="en0")
        result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", FAKE_TCPDUMP_DROPS="en0:2", **env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["positive_control_verdict"][:2], (
            "unavailable", "primary=en0 presock_open=pass presock_unacked=pass presock_keepalive_drops=pass "
                           "frames_seen=en0 frames_unchecked=none captures_incomplete=en0:kernel_drops=2: the "
                           "helper's frames are in a capture while armed; they may be frames the filter dropped "
                           "after the tap or frames that left the Mac; a capture that lost frames or did not run "
                           "through the armed span cannot show that nothing left"))

    def test_a_capture_that_lost_frames_or_stopped_early_never_passes_the_positive_verdict(self):
        # S20h review: a pass rests on no helper frame in any capture while
        # armed. A capture whose kernel dropped frames, or that recorded
        # nothing after the disarm, cannot show that, whatever the filter
        # counted; everything else would pass here.
        for extra, dev, reason in (({"FAKE_TCPDUMP_DROPS": "en0:3"}, "en0", "en0:kernel_drops=3"),
                                   ({"FAKE_EN5": "1", "FAKE_TCPDUMP_DROPS": "en5:1"}, "en5", "en5:kernel_drops=1"),
                                   ({"FAKE_TCPDUMP_QUIET_AT_DISARM": "en0"}, "en0", "en0:after_disarm=0")):
            with self.subTest(extra=extra):
                gateway, env = self.presock_ka()
                result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", **extra, **env)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                for name in ("open", "unacked"):
                    self.assertEqual(rows[f"positive_control_presock_{name}_en0"][0], "pass", name)
                self.assert_keepalives_pass(rows, "en0", "primary")
                file = "physical.pcap" if dev == "en0" else "physical-en5.pcap"
                self.assertRegex(rows[f"positive_control_presock_bpf_order_{dev}"][1],
                                 rf"^unknown frames=0 data=0 ack_only=0 other=0 uncounted=0 total=[0-9]+ "
                                 rf"after_disarm=[0-9]+ tap_evidence=post_filter capture={file} "
                                 rf"capture_incomplete={reason}: the capture did not cover the armed span whole$")
                self.assertEqual(rows["positive_control_verdict"][:2], (
                    "unavailable", "primary=en0 presock_open=pass presock_unacked=pass presock_keepalive_drops=pass "
                                   f"frames_seen=none frames_unchecked=none captures_incomplete={reason}: a capture "
                                   "that lost frames or did not run through the armed span cannot show that nothing "
                                   "left"))
                self.assert_no_port(out, rows, gateway)

    def test_helper_frames_not_counted_never_pass_the_positive_verdict(self):
        # Without the provider's armed span neither the keepalives' times
        # nor the helper's frames can be placed, so nothing shows that the
        # filter dropped them or that they stayed on the Mac: the verdict is
        # unavailable even with every pre-existing socket row passing.
        gateway, env = self.presock_ka()
        result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", FAKE_LOG_NOSPAN="1", **env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["positive_control_filter_armed_span"][:2], ("unavailable", "no_span_lines"))
        for name in ("open", "unacked"):
            self.assertEqual(rows[f"positive_control_presock_{name}_en0"][0], "pass", name)
        self.assertEqual(rows["positive_control_presock_keepalive_drops_en0"][:2],
                         ("unavailable", "no_armed_span class=primary tx=4 data_counted=4"))
        self.assertEqual(rows["positive_control_presock_bpf_order_en0"][:2],
                         ("info", "unknown no_armed_span capture=physical.pcap"))
        self.assertEqual(rows["positive_control_verdict"][:2], (
            "unavailable", "primary=en0 presock_open=pass presock_unacked=pass presock_keepalive_drops=unavailable "
                           "frames_seen=none frames_unchecked=en0"))

    def test_presock_open_is_unavailable_when_the_gateway_accepts_none_of_the_ports(self):
        gateway, env = self.presock(FAKE_GW_OPEN="")
        result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", **env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["positive_control_presock_open_en0"][:2],
                         ("unavailable", "unavailable opened=0 need=2 select=refused:3"))
        self.assertEqual(rows["positive_control_presock_unacked_en0"][:2],
                         ("unavailable", "not_open presock_open=unavailable"))
        self.assertEqual(rows["positive_control_presock_keepalive_drops_en0"][:2],
                         ("unavailable", "no_sockets presock_open=unavailable"))
        self.assertEqual(rows["positive_control_presock_counted_en0"][:2], ("info", "unknown no_sockets"))
        self.assertNotIn("positive_control_presock_drop_delta_en0", rows)
        self.assertEqual(rows["positive_control_verdict"][:2], (
            "unavailable", "primary=en0 presock_open=unavailable presock_unacked=unavailable "
                           "presock_keepalive_drops=unavailable frames_seen=none frames_unchecked=none"))
        self.assertEqual(gateway.accepted, 0)
        self.assertEqual(json.loads((out / "presock-en0.json").read_text())["phase"], "unavailable")

    def test_negative_control_presock_bytes_are_acknowledged_with_the_filter_off(self):
        gateway, env = self.presock()
        result, rows, calls, out, root = self.run_window(NEGATIVE_CONTROL="1", **env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(" presock=2 wait=1s rollback_s=25", result.stdout)
        self.assertEqual(rows["negative_control_presock_open_en0"][:2],
                         ("pass", "open opened=2 need=2 kinds=connected:2 keepalive=4/4/60"))
        verdict, detail, status = rows["negative_control_presock_acked_en0"]
        self.assertEqual((verdict, status), ("pass", "Connected"), detail)
        self.assertRegex(detail, r"^written=2 acked=2 unacked=0 reset=0 rx=0 timed_out=0 closed=0 not_written=0 answered=2 ")
        self.assertRegex(rows["negative_control_presock_frames_en0"][1],
                         r"^frames=2 data=2 ack_only=0 other=0 total=[0-9]+ ack_only_marked=0 capture=physical.pcap "
                         r"span=write\+1s presock_acked=pass$")
        for name in rows:
            self.assertFalse(name.startswith("presock_") or name.startswith("positive_control_"), name)
        self.assertNotIn("negative_control_presock_drop_delta_en0", rows)
        self.assertEqual(rows["negative_control_filter_restored"][0], "pass")
        self.assert_no_address(out)
        self.assert_no_port(out, rows, gateway)
        # Bytes that stay unacknowledged with the filter off: the probe's
        # send path is not shown.
        gateway, env = self.presock(FAKE_PRESOCK_HOLD="1")
        result, rows, calls, out, root = self.run_window(NEGATIVE_CONTROL="1", **env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["negative_control_presock_acked_en0"][0], "fail")
        self.assertRegex(rows["negative_control_presock_acked_en0"][1], r"^written=2 acked=0 unacked=2 ")

    def test_negative_control_writes_right_after_connected_and_shows_its_frames_on_the_wire(self):
        # S20h: the write comes right after Connected, before any standard
        # check, never after a --filter-status read or the arm; a gateway
        # that resets idle connections about 15 s after their last packet
        # can no longer close them first. With the filter off the helper's
        # keepalives are on the wire beside its data.
        gateway, env = self.presock_ka()
        result, rows, calls, out, root = self.run_window(NEGATIVE_CONTROL="1", **env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        names = list(rows)
        verdict, detail, status = rows["negative_control_presock_acked_en0"]
        self.assertEqual((verdict, status), ("pass", "Connected"), detail)
        self.assertRegex(detail, r"^written=2 acked=2 unacked=0 reset=0 rx=0 timed_out=0 closed=0 not_written=0 answered=2 ")
        self.assertLess(names.index("connected"), names.index("negative_control_presock_acked_en0"))
        self.assertLess(names.index("negative_control_presock_acked_en0"), names.index("utun_addr"))
        self.assertLess(names.index("negative_control_presock_acked_en0"), names.index("flow_burst_24"))
        self.assertEqual(list(out.glob("filter-status-presock-*")), [])
        self.assertRegex(rows["negative_control_presock_frames_en0"][1],
                         r"^frames=[0-9]+ data=2 ack_only=[0-9]+ other=0 total=[0-9]+ ack_only_marked=[0-9]+ "
                         r"capture=physical.pcap span=write\+1s presock_acked=pass$")
        wire = rows["negative_control_presock_wire_en0"]
        self.assertEqual(wire[0], "info")
        # S20h review: every bare ACK of the helper on the wire with the
        # filter off carries the provider's marker (its source port).
        m = re.match(r"^frames=([0-9]+) data=2 ack_only=([0-9]+) other=0 total=[0-9]+ ack_only_marked=\2 "
                     r"capture=physical.pcap span=connected: the helper's frames with the filter off, its keepalives "
                     r"expected among them, ack_only_marked those carrying the provider's marker$", wire[1])
        self.assertIsNotNone(m, wire)
        self.assertGreaterEqual(int(m.group(2)), 4, wire)
        for name in rows:
            self.assertFalse(name.startswith("presock_") or name.startswith("positive_control_"), name)
        self.assertEqual(rows["negative_control_filter_restored"][0], "pass")
        self.assert_no_address(out)
        self.assert_no_port(out, rows, gateway)

    def test_negative_control_names_why_nothing_was_written(self):
        # The gateway resets every connection right after accepting it: the
        # sockets are closed by the write, which names the cause instead of
        # a bare not_written, and the frame count after the write is
        # unknown rather than a misleading frames=0.
        gateway, env = self.presock(reset_on_accept=True)
        result, rows, calls, out, root = self.run_window(NEGATIVE_CONTROL="1", **env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["negative_control_presock_acked_en0"][:2], (
            "unavailable", "written=0 acked=0 unacked=0 reset=0 rx=0 timed_out=0 closed=0 not_written=2 answered=0 "
                           "tx=0 retx=0 rx_packets=0 wait=1s not_written_causes=reset:2"))
        self.assertEqual(rows["negative_control_presock_frames_en0"][:2], (
            "info", "unknown nothing_written capture=physical.pcap presock_acked=unavailable"))
        self.assertTrue(rows["negative_control_presock_wire_en0"][1].startswith("frames=0 "))
        self.assert_no_port(out, rows, gateway)

    def test_a_control_window_that_never_connects_says_so_in_its_presock_rows(self):
        # The tunnel never reaches Connected: no write, no read, and the rows
        # say not_connected instead of being absent.
        for mode, row in (("POSITIVE_CONTROL", "positive_control_presock_unacked_en0"),
                          ("NEGATIVE_CONTROL", "negative_control_presock_acked_en0")):
            with self.subTest(mode=mode):
                gateway, env = self.presock_ka()
                result, rows, calls, out, root = self.run_window(FAKE_NO_CONNECT="1", **{mode: "1"}, **env)
                self.assertEqual(rows["connected"][0], "0", rows["connected"])
                self.assertEqual(rows[row][:2], ("unavailable", "not_connected presock_open=pass"))
                if mode == "POSITIVE_CONTROL":
                    self.assertEqual(rows["positive_control_presock_keepalive_drops_en0"][:2],
                                     ("unavailable", "not_written presock_open=pass"))
                    # The fresh probes never ran either: never an answer.
                    self.assertNotIn("probe_failed_en0", rows)
                    self.assertEqual(rows["positive_control_bound_fresh_en0"][:2], (
                        "info", "not_run probe_failed=not_run: the window never probed (not Connected)"))
                    self.assertEqual(rows["positive_control_verdict"][:2], (
                        "unavailable", "primary=en0 presock_open=pass presock_unacked=unavailable "
                                       "presock_keepalive_drops=unavailable frames_seen=none frames_unchecked=en0"))
                else:
                    self.assertEqual(rows["negative_control_presock_wire_en0"][:2],
                                     ("info", "unknown not_connected capture=physical.pcap"))

    def test_an_answered_fresh_probe_fails_the_positive_verdict(self):
        # A fresh SYN bound to en0 reached the gateway and its answer came
        # back while armed (probe_failed fail): a real leak, even with every
        # pre-existing socket row passing on that interface.
        gateway, env = self.presock_ka(FAKE_PROBE_CONNECTS="en0")
        result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", **env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["probe_failed_en0"][:2],
                         ("fail", "probes=3 failed=2 kinds=connected:1,timeout:2 ms=12 rc=1 port=9"))
        for name in ("open", "unacked", "keepalive_drops"):
            self.assertEqual(rows[f"positive_control_presock_{name}_en0"][0], "pass", name)
        self.assertEqual(rows["positive_control_verdict"][:2], (
            "fail", "fresh_probe_answered=en0 primary=en0: a fresh probe bound to that interface was answered while the "
                    "filter was armed (probe_failed fail)"))
        self.assert_no_address(out)
        self.assert_no_port(out, rows, gateway)
        # A probe that never left says nothing (unavailable): the verdict
        # rests on the pre-existing sockets.
        gateway, env = self.presock_ka(FAKE_PROBE_INCONCLUSIVE="en0")
        result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", **env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["probe_failed_en0"][0], "unavailable")
        self.assertEqual(rows["positive_control_verdict"][0], "pass", rows["positive_control_verdict"])

    def test_fresh_bound_probes_routed_into_the_tunnel_read_tunnel_enforced(self):
        gateway, env = self.presock_ka(FAKE_PROBE_TUNNEL="en0")
        result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", **env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        names = list(rows)
        self.assertEqual(rows["probe_failed_en0"][:2],
                         ("info", "tunnel_enforced probes=3 failed=0 kinds=connected:3 ms=7 rc=1 port=9 at=Connected"))
        # S20h: the helper's keepalives are dropped on en0 meanwhile; no SYN.
        self.assertEqual(rows["filter_drop_delta_en0"][0], "info")
        self.assertRegex(rows["filter_drop_delta_en0"][1],
                         r"^tunnel_enforced class=primary out_before=[0-9]+ out_after=[0-9]+ delta=[0-9]+ syn_drops=0 "
                         r"ring_lost=0 need=3$")
        self.assertEqual(rows["positive_control_bound_fresh_en0"][:2], (
            "info", "tunnel_enforced connected=3 engine_opens=3 marked_syns_in_captures=0: the system routed sockets "
                    "bound to en0 into the tunnel"))
        self.assertEqual(rows["bpf_order_en0"][:2], (
            "info", "unknown syns=0 probes=3 capture=physical.pcap bound_fresh=tunnel_enforced: the probes never reached en0"))
        # Decided after the captures and the provider log.
        self.assertLess(names.index("disconnect_verified"), names.index("probe_failed_en0"))
        # The pre-existing sockets still exercise the filter.
        self.assertEqual(rows["positive_control_verdict"][0], "pass", rows["positive_control_verdict"])
        self.assert_no_address(out)
        # Probes that all connected and keep their fail (no engine lines: a
        # provider before v28) fail the verdict, as any answered probe does.
        gateway, env = self.presock_ka(FAKE_PROBE_TUNNEL="en0", FAKE_ENGINE_LOG="0")
        result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", **env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["probe_failed_en0"][0], "fail")
        self.assertEqual(rows["positive_control_presock_keepalive_drops_en0"][0], "pass")
        self.assertEqual(rows["positive_control_verdict"][:2], (
            "fail", "fresh_probe_answered=en0 primary=en0: a fresh probe bound to that interface was answered while the "
                    "filter was armed (probe_failed fail)"))
        # Without the engine's lines (a provider before v28), with the marked
        # SYNs in a capture, or with the engine's opens outside the probes'
        # time, the probes that connected fail as before.
        for extra, opens, syns in (({"FAKE_ENGINE_LOG": "0"}, "none", 0), ({"FAKE_BPF_PRE": "en0"}, "3", 3),
                                   ({"FAKE_ENGINE_SKEW_S": "-100"}, "0", 0)):
            with self.subTest(extra=extra):
                result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", FAKE_PROBE_TUNNEL="en0", **extra)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(rows["probe_failed_en0"][:2],
                                 ("fail", "probes=3 failed=0 kinds=connected:3 ms=7 rc=1 port=9 at=Connected"))
                self.assertEqual(rows["filter_drop_delta_en0"][0], "fail")
                self.assertEqual(rows["positive_control_bound_fresh_en0"][:2], (
                    "info", f"answered connected=3 engine_opens={opens} marked_syns_in_captures={syns}"))
                self.assertTrue(rows["bpf_order_en0"][1].startswith("unknown "), rows["bpf_order_en0"])

    def test_positive_control_rows_start_before_their_probes_and_filter_reads(self):
        # v31 review: every per-interface row reports that interface's
        # probes and the two --filter-status reads around them, whether it is
        # written right after them (probes timed out) or, every probe
        # connected, only after the disconnect: it starts before the first.
        for extra, deferred in (({}, False), ({"FAKE_PROBE_TUNNEL": "en0"}, True)):
            with self.subTest(deferred=deferred):
                result, rows, calls, out, root = self.run_window(POSITIVE_CONTROL="1", **extra)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                fields = row_fields(out)
                assert_rows_chain(self, fields)
                times = row_times(fields)
                names = [row[0] for row in fields]
                self.assertEqual(names.index("disconnect_verified") < names.index("probe_failed_en0"), deferred)
                before = file_utc(out / "filter-status-pc-en0-before.txt")
                after = file_utc(out / "filter-status-pc-en0-after.txt")
                self.assertLess(before, after)
                for name in ("probe_failed_en0", "filter_drop_delta_en0", "positive_control_bound_fresh_en0",
                             "bpf_order_en0"):
                    self.assertLessEqual(times[name][0], before, name)
                    self.assertLessEqual(times[name][0], times[name][1], name)
                for name in ("filter_drop_delta_en0", "positive_control_bound_fresh_en0", "bpf_order_en0"):
                    self.assertLessEqual(after, times[name][1], name)
                # The Connected interval's rows, and the captured interfaces.
                for name, shares in (("positive_control_leak_window_connected_at", "connected"),
                                     ("positive_control_leak_capture_ifaces", "capture_started")):
                    self.assertEqual(times[name][0], times[shares][0], name)


    # ------------------------------------------------------- armed span

    def test_a_mac_sent_frame_in_the_armed_span_fails_the_mac_sent_row(self):
        # The Mac sends one SYN after the arm and before Connected: outside
        # the reviewed Connected interval, inside the armed span.
        result, rows, calls, out, root = self.run_window(FAKE_ARM_LEAD_S="1.5", FAKE_PRECONNECT_LEAK="en0")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["filter_armed_span"][0], "pass", rows["filter_armed_span"])
        self.assertRegex(rows["filter_armed_span"][1],
                         r"^seq=1 armed_before_connect=[0-9.]+s disarmed_after_disconnect=[0-9.]+s rearms=0$")
        self.assertEqual(rows["leak_proof"][0], "pass", rows["leak_proof"])
        report = json.loads((out / "leak-review.json").read_text())
        self.assertEqual((report["mac_sent_leaks"], report["mac_sent_pass"]), (0, True))
        self.assertEqual((report["mac_sent_armed_leaks"], report["mac_sent_armed_classes"]), (1, {"tcp_syn": 1}))
        self.assertLess(report["mac_sent_armed_span"]["armed_at"], report["connected_interval"]["connected_at"])
        mac = rows["no_mac_sent_leak_physical"]
        self.assertEqual(mac[0], "fail", mac)
        self.assertEqual(mac[1], "ifaces=en0 en0:mac_sent_leaks=0,mac_sent_pass=true,alive=1,stopped=1,drops=0,"
                                 "armed_leaks=1 armed_span=reviewed uncaptured=none reason=en0:mac_sent_armed_leaks=1")
        self.assert_no_address(out)
        # Without the frame both spans are clean.
        result, rows, calls, out, root = self.run_window(FAKE_ARM_LEAD_S="1.5")
        self.assertEqual(rows["no_mac_sent_leak_physical"][:2], (
            "pass", "ifaces=en0 en0:mac_sent_leaks=0,mac_sent_pass=true,alive=1,stopped=1,drops=0,armed_leaks=0 "
                    "armed_span=reviewed uncaptured=none"))

    def test_the_armed_span_row_fails_a_transient_disarm_or_rearm_and_is_unavailable_without_lines(self):
        result, rows, calls, out, root = self.run_window(FAKE_SPAN="early")
        self.assertEqual(rows["filter_armed_span"][0], "fail")
        self.assertTrue(rows["filter_armed_span"][1].endswith(" rearms=0 reason=disarmed_before_disconnect"),
                        rows["filter_armed_span"])
        result, rows, calls, out, root = self.run_window(FAKE_SPAN="rearm")
        self.assertEqual(rows["filter_armed_span"][0], "fail")
        self.assertTrue(rows["filter_armed_span"][1].endswith(" rearms=1 reason=rearms"), rows["filter_armed_span"])
        # A v26 provider logs no span: unavailable, and the Mac-sent row reads
        # exactly as before S20f.
        result, rows, calls, out, root = self.run_window(FAKE_SPAN="none")
        self.assertEqual(rows["filter_armed_span"][:2], ("unavailable", "no_span_lines"))
        self.assertEqual(rows["no_mac_sent_leak_physical"][:2], (
            "pass", "ifaces=en0 en0:mac_sent_leaks=0,mac_sent_pass=true,alive=1,stopped=1,drops=0 uncaptured=none"))
        report = json.loads((out / "leak-review.json").read_text())
        self.assertIsNone(report["mac_sent_armed_span"])

    def test_a_provider_restart_that_repeats_the_arm_seq_fails_the_armed_span(self):
        # The provider process dies while Connected and a new one arms seq:1
        # again, then logs the disarm after the disconnect. Its seq matches
        # the window's first arm, yet it is a re-arm (it passed as rearms=0),
        # and its disarm is not the first arm's.
        result, rows, calls, out, root = self.run_window(FAKE_SPAN="restart")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["filter_armed_span"][0], "fail", rows["filter_armed_span"])
        self.assertRegex(rows["filter_armed_span"][1],
                         r"^seq=1 armed_before_connect=[0-9.]+s disarmed=none rearms=1 reason=no_disarm,rearms$")
        # Without a [pid:tid] in the lines the disarm pairs by seq alone and
        # the repeated seq still counts as a re-arm.
        result, rows, calls, out, root = self.run_window(FAKE_SPAN="restart", FAKE_LOG_NOPID="1")
        self.assertEqual(rows["filter_armed_span"][0], "fail", rows["filter_armed_span"])
        self.assertTrue(rows["filter_armed_span"][1].endswith(" rearms=1 reason=rearms"), rows["filter_armed_span"])
        # One process's own span, logged without pids, still passes.
        result, rows, calls, out, root = self.run_window(FAKE_LOG_NOPID="1")
        self.assertEqual(rows["filter_armed_span"][0], "pass", rows["filter_armed_span"])


def armed_review(test, records, armed_at, disarmed_at, extra=()):
    with tempfile.TemporaryDirectory(prefix="aegis-s20f-leak-") as temp:
        pcap = pathlib.Path(temp) / "physical.pcap"
        pcap.write_bytes(pcap_bytes(records) if isinstance(records, list) else records)
        out = pathlib.Path(temp) / "leak-review.json"
        args = [sys.executable, "-I", str(LEAK_REVIEW), "--pcap", str(pcap), "--relay-ip", RELAY_IP,
                "--relay-port", "443", "--out", str(out), "--local-addr", LOCAL_IP,
                "--local-mac", MAC_BYTES.hex(":"), "--connected-at", repr(T_CONNECT),
                "--disconnect-at", repr(T_DISCONNECT), *extra]
        if armed_at is not None:
            args += ["--armed-at", repr(armed_at)]
        if disarmed_at is not None:
            args += ["--disarmed-at", repr(disarmed_at)]
        result = subprocess.run(args, capture_output=True, text=True, timeout=30)
        return result.returncode, result.stdout, json.loads(out.read_text())


class LeakReviewArmedSpanTests(unittest.TestCase):
    """S20f: leak_review.py's armed-span Mac-sent pass and probe-syns, on
    synthetic captures. Strict fields, mac_sent_* fields, the summary line
    and the exit code never move."""

    ARMED, DISARMED = T_CONNECT - 3.0, T_DISCONNECT + 2.0

    def test_a_mac_sent_frame_between_the_arm_and_the_connect_counts_only_in_the_armed_span(self):
        own = e4(LOCAL_IP, "198.51.100.9", 6, tcp_seg(50001, 443))
        records = clean_records() + [(self.ARMED + 0.2, own), (T_CONNECT - 1.0, own), (T_CONNECT + 0.5, own),
                                     (T_DISCONNECT + 1.0, own), (self.DISARMED - 0.2, own),
                                     (self.ARMED - 0.2, own), (self.DISARMED + 1.0, own)]
        code0, line0, plain = armed_review(self, records, None, None)
        code, line, report = armed_review(self, records, self.ARMED, self.DISARMED)
        self.assertEqual((code, line), (code0, line0))
        strict = {k: v for k, v in plain.items() if not k.startswith("mac_sent_armed")}
        self.assertEqual({k: v for k, v in report.items() if not k.startswith("mac_sent_armed")}, strict)
        self.assertEqual((report["pass"], report["mac_sent_leaks"], report["mac_sent_guard"]), (True, 0, 1))
        # Right after the arm, before the connect, in the guard, after the
        # disconnect and right before the disarm: five, with no guard of
        # its own; before the arm and after the disarm: none.
        self.assertEqual((report["mac_sent_armed_leaks"], report["mac_sent_armed_classes"]), (5, {"tcp_syn": 5}))
        self.assertEqual(report["mac_sent_armed_span"], {"armed_at": self.ARMED, "disarmed_at": self.DISARMED})
        self.assertEqual(len(report["mac_sent_armed_frames"]), 5)
        self.assertEqual((plain["mac_sent_armed_span"], plain["mac_sent_armed_leaks"]), (None, 0))

    def test_arrivals_foreign_frames_and_excluded_control_never_count_in_the_armed_span(self):
        records = clean_records() + [
            (T_CONNECT - 1.0, e4_in("198.51.100.9", LOCAL_IP, 6, tcp_seg(443, 50001))),
            (T_CONNECT - 1.0, arp_frame()),
            (T_CONNECT - 1.0, e4(LOCAL_IP, "255.255.255.255", 17, udp_dgram(68, 67))),
            (T_CONNECT - 1.0, e4(LOCAL_IP, RELAY_IP, 6, tcp_seg(50000, 443, 0x18))),
            (T_CONNECT - 1.0, b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x08\x08\x00"
             + ipv4_pkt("198.51.100.7", "198.51.100.8", 6, tcp_seg(1, 2))),
        ]
        code, line, report = armed_review(self, records, self.ARMED, self.DISARMED)
        self.assertEqual(report["mac_sent_armed_leaks"], 0, report["mac_sent_armed_frames"])
        # An untimed frame cannot be placed: it counts, fail closed.
        untimed = pcap_bytes(clean_records()) + struct.pack("<IIII", 0, 0, 0, 0)[:8]
        code, line, report = armed_review(self, untimed, self.ARMED, self.DISARMED)
        self.assertEqual(report["mac_sent_armed_leaks"], report["mac_sent_leaks"])
        self.assertGreaterEqual(report["mac_sent_armed_leaks"], 1)

    def test_an_incomplete_or_inverted_span_or_an_unreadable_capture_is_an_armed_error(self):
        for armed_at, disarmed_at, why in ((self.ARMED, None, "armed span incomplete"),
                                           (None, self.DISARMED, "armed span incomplete"),
                                           (self.DISARMED, self.ARMED, "armed span inverted")):
            with self.subTest(why=why):
                code, line, report = armed_review(self, clean_records(), armed_at, disarmed_at)
                self.assertTrue(report["mac_sent_armed_error"].startswith(why), report)
                self.assertIsNone(report["mac_sent_armed_span"])
                self.assertEqual((code, report["pass"], report["mac_sent_pass"]), (0, True, True))
        code, line, report = armed_review(self, b"not a capture", self.ARMED, self.DISARMED)
        self.assertEqual(code, 2)
        self.assertIn("mac_sent_armed_error", report)
        self.assertEqual(report["mac_sent_armed_leaks"], 0)

    def test_probe_syns_counts_only_the_marked_syns_and_prints_no_address(self):
        gw = "192.0.2.1"
        records = clean_records() + [
            (IN, e4(LOCAL_IP, gw, 6, tcp_seg(47100, 9))),
            (IN + 1, e4(LOCAL_IP, gw, 6, tcp_seg(47101, 9))),
            (IN + 2, e4(LOCAL_IP, gw, 6, tcp_seg(47101, 9))),        # a retransmission
            (IN, e4(LOCAL_IP, gw, 6, tcp_seg(47100, 9, 0x12))),      # SYN-ACK: no
            (IN, e4(LOCAL_IP, gw, 6, tcp_seg(47199, 9))),            # another port: no
            (IN, e4(LOCAL_IP, gw, 6, tcp_seg(47100, 10))),           # another service: no
            (IN, e4(LOCAL_IP, "192.0.2.2", 6, tcp_seg(47100, 9))),   # another host: no
        ]
        with tempfile.TemporaryDirectory(prefix="aegis-s20f-syns-") as temp:
            pcap = pathlib.Path(temp) / "p.pcap"
            pcap.write_bytes(pcap_bytes(records))
            run = lambda *extra: subprocess.run(
                [sys.executable, "-I", str(LEAK_REVIEW), "probe-syns", "--pcap", str(pcap), "--dst", gw,
                 "--dport", "9", "--sport-min", "47100", "--sport-max", "47102", *extra],
                capture_output=True, text=True, timeout=30)
            result = run()
            self.assertEqual((result.returncode, result.stdout), (0, f"probe_syns=3 total={len(records)}\n"))
            pcap.write_bytes(b"junk")
            result = run()
            self.assertEqual((result.returncode, result.stdout), (2, "probe_syns=unreadable\n"))


class NetProbeBoundSynTests(unittest.TestCase):
    """S20f: net_probe.py boundsyn under the system python3, on loopback only."""

    def boundsyn(self, *args):
        result = subprocess.run([SYSTEM_PY, "-I", str(NET_PROBE), "boundsyn", *args], capture_output=True,
                                text=True, timeout=30)
        return result.returncode, result.stdout

    def test_a_refused_or_connected_probe_is_counted_and_no_address_is_printed(self):
        import socket
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        port = closed.getsockname()[1]
        closed.close()
        # A refused connect needs the SYN out and the RST back: answered, so
        # never what a dropping filter gives (it exited 0).
        rc, out = self.boundsyn("lo0", "127.0.0.1", str(port), "3", "47200", "1")
        self.assertEqual(rc, 1, out)
        self.assertRegex(out, r"^probes=3 failed=3 kinds=refused:3 ms=[0-9]+\n$")
        server = LoopbackServer("silent")
        self.addCleanup(server.close)
        rc, out = self.boundsyn("lo0", "127.0.0.1", str(server.port), "2", "47210", "1")
        self.assertEqual(rc, 1, out)
        self.assertRegex(out, r"^probes=2 failed=0 kinds=connected:2 ms=[0-9]+\n$")
        self.assertNotIn("127.0.0.1", out)

    def test_a_probe_that_never_left_is_inconclusive(self):
        import socket
        # The marked source port is taken: bind fails, no SYN is sent.
        holder = socket.socket()
        self.addCleanup(holder.close)
        holder.bind(("0.0.0.0", 0))
        rc, out = self.boundsyn("lo0", "127.0.0.1", "9", "1", str(holder.getsockname()[1]), "1")
        self.assertEqual(rc, 3, out)
        self.assertRegex(out, r"^probes=1 failed=1 kinds=eaddrinuse:1 ms=[0-9]+\n$")

    def test_only_probes_that_all_timed_out_read_as_blocked(self):
        import errno
        import importlib.util
        import io
        import socket
        spec = importlib.util.spec_from_file_location("aegis_net_probe_under_test", NET_PROBE)
        probe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(probe)

        def outcome(kinds):
            todo = list(kinds)

            class FakeSocket:
                def __init__(self, *args):
                    pass

                def setsockopt(self, *args):
                    pass

                def bind(self, address):
                    if todo[0] == "eaddrinuse":
                        todo.pop(0)
                        raise OSError(errno.EADDRINUSE, "in use")

                def settimeout(self, limit):
                    pass

                def connect(self, address):
                    kind = todo.pop(0)
                    if kind == "connected":
                        return
                    raise {"timeout": socket.timeout("timed out"),
                           "etimedout": OSError(errno.ETIMEDOUT, "timed out"),
                           "refused": ConnectionRefusedError(errno.ECONNREFUSED, "refused"),
                           "reset": ConnectionResetError(errno.ECONNRESET, "reset"),
                           "ehostunreach": OSError(errno.EHOSTUNREACH, "unreachable")}[kind]

                def close(self):
                    pass

            saved = (probe.socket.socket, probe.socket.if_nametoindex, sys.stdout)
            probe.socket.socket, probe.socket.if_nametoindex, sys.stdout = FakeSocket, lambda name: 1, io.StringIO()
            try:
                rc = probe.boundsyn("en0", "192.0.2.1", 9, len(kinds), 47100, 1.0)
                printed = sys.stdout.getvalue()
            finally:
                probe.socket.socket, probe.socket.if_nametoindex, sys.stdout = saved
            return rc, printed.split(" ")[2]

        self.assertEqual(outcome(["timeout", "timeout", "timeout"]), (0, "kinds=timeout:3"))
        self.assertEqual(outcome(["timeout", "etimedout"]), (0, "kinds=timeout:2"))
        self.assertEqual(outcome(["timeout", "refused"]), (1, "kinds=refused:1,timeout:1"))
        self.assertEqual(outcome(["reset", "timeout"]), (1, "kinds=reset:1,timeout:1"))
        self.assertEqual(outcome(["connected", "eaddrinuse"]), (1, "kinds=connected:1,eaddrinuse:1"))
        self.assertEqual(outcome(["timeout", "ehostunreach"]), (3, "kinds=ehostunreach:1,timeout:1"))
        self.assertEqual(outcome(["eaddrinuse", "eaddrinuse"]), (3, "kinds=eaddrinuse:2"))

    def test_bad_arguments_and_an_unknown_interface_refuse_without_output(self):
        for args in (("lo0", "::1", "9", "1", "47200", "1"), ("lo0", "127.0.0.1", "0", "1", "47200", "1"),
                     ("lo0", "127.0.0.1", "9", "11", "47200", "1"), ("lo0", "127.0.0.1", "9", "1", "80", "1"),
                     ("lo0", "127.0.0.1", "9", "1", "47200", "11"), ("lo0", "127.0.0.1", "9"),
                     ("nosuch9", "127.0.0.1", "9", "1", "47200", "1"),
                     ("lo0", "127.0.0.1", "9", "1", "47200", "1", "extra")):
            with self.subTest(args=args):
                rc, out = self.boundsyn(*args)
                self.assertEqual((rc, out), (2, ""))


def load_net_probe():
    import importlib.util
    spec = importlib.util.spec_from_file_location("aegis_net_probe_presock_under_test", NET_PROBE)
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    return probe


class NetProbePresockTests(unittest.TestCase):
    """S20g: net_probe.py presock and presock-read under the system python3
    against loopback gateways, and its TCP_CONNECTION_INFO parsing."""

    def temp(self):
        temp = tempfile.TemporaryDirectory(prefix="aegis-s20g-presock-")
        self.addCleanup(temp.cleanup)
        return pathlib.Path(temp.name)

    def gateway(self, **kw):
        gateway = FakeGateway(**kw)
        self.addCleanup(gateway.close)
        return gateway

    def read(self, state, mode):
        result = subprocess.run([SYSTEM_PY, "-I", str(NET_PROBE), "presock-read", str(state), mode],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.rstrip("\n")

    def start(self, state, ports, n=2, wait=1, lifetime=60, iface="lo0", dst="127.0.0.1"):
        helper = subprocess.Popen([SYSTEM_PY, "-I", str(NET_PROBE), "presock", iface, dst,
                                   ",".join(str(p) for p in ports), str(n), str(state), "1", str(wait), str(lifetime)],
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

        def end():
            if helper.poll() is None:
                helper.kill()
                helper.wait(5)
            helper.stdout.close()
        self.addCleanup(end)
        return helper

    def wait_phase(self, state, phases, seconds=15):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            phase = self.read(state, "phase")
            if phase in phases:
                return phase
            time.sleep(0.1)
        self.fail(f"{state}: phase {self.read(state, 'phase')} never in {phases}")

    def command(self, state, text):
        tmp = pathlib.Path(str(state) + ".cmd.tmp")
        tmp.write_text(text + "\n")
        os.replace(tmp, str(state) + ".cmd")

    # ------------------------------------------------ TCP_CONNECTION_INFO

    def test_connection_info_is_parsed_with_the_sdk_struct_layout(self):
        probe = load_net_probe()
        self.assertEqual(probe.CONNECTION_INFO.size, 112)
        self.assertEqual((probe.TCP_CONNECTION_INFO, probe.TCP_KEEPALIVE, probe.TCP_KEEPINTVL, probe.TCP_KEEPCNT),
                         (0x106, 0x10, 0x101, 0x102))
        # Each field at its offset in struct tcp_connection_info.
        raw = bytearray(112)
        raw[0] = 5                                      # tcpi_state: CLOSE_WAIT
        raw[1], raw[2] = 6, 7                           # window scales
        struct.pack_into("<I", raw, 4, 0x3)             # tcpi_options
        struct.pack_into("<I", raw, 12, 230)            # tcpi_rto
        struct.pack_into("<I", raw, 32, 22)             # tcpi_snd_sbbytes
        struct.pack_into("<I", raw, 44, 9)              # tcpi_srtt
        struct.pack_into("<Q", raw, 56, 11)             # tcpi_txpackets
        struct.pack_into("<Q", raw, 64, 1234)           # tcpi_txbytes
        struct.pack_into("<Q", raw, 80, 3)              # tcpi_rxpackets
        struct.pack_into("<Q", raw, 104, 4)             # tcpi_txretransmitpackets
        info = probe.parse_connection_info(bytes(raw) + b"\xff" * 8)
        self.assertEqual((info["state"], info["snd_wscale"], info["rcv_wscale"], info["options"], info["rto"],
                          info["snd_sbbytes"], info["srtt"], info["txpackets"], info["txbytes"], info["rxpackets"],
                          info["txretransmitpackets"], info["rxbytes"]),
                         (5, 6, 7, 3, 230, 22, 9, 11, 1234, 3, 4, 0))
        self.assertEqual(len(info), len(probe.CONNECTION_INFO_FIELDS))
        with self.assertRaises(ValueError):
            probe.parse_connection_info(bytes(111))
        self.assertEqual([probe.tcp_state_name(k) for k in (0, 4, 5, 10, 11)],
                         ["closed", "established", "close_wait", "time_wait", "state_11"])

    @unittest.skipUnless(shutil_which("clang") and shutil_which("xcrun"), "needs the macOS SDK")
    def test_the_layout_matches_the_sdk_header(self):
        probe = load_net_probe()
        root = self.temp()
        source = root / "layout.c"
        source.write_text("""#include <stdio.h>
#include <stddef.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#define O(f) printf("%s %zu\\n", #f, offsetof(struct tcp_connection_info, tcpi_##f))
int main(void) {
  printf("size %zu\\n", sizeof(struct tcp_connection_info));
  O(state); O(options); O(rto); O(snd_sbbytes); O(rcv_wnd); O(rttvar); O(txpackets); O(txbytes);
  O(rxpackets); O(rxbytes); O(txretransmitpackets);
  printf("TCP_CONNECTION_INFO %d\\nTCP_KEEPALIVE %d\\nTCP_KEEPINTVL %d\\nTCP_KEEPCNT %d\\n", TCP_CONNECTION_INFO,
         TCP_KEEPALIVE, TCP_KEEPINTVL, TCP_KEEPCNT);
  printf("TCPS_ESTABLISHED %d\\nTCPS_CLOSE_WAIT %d\\nTCPS_TIME_WAIT %d\\n", TCPS_ESTABLISHED, TCPS_CLOSE_WAIT, TCPS_TIME_WAIT);
  return 0;
}
""")
        built = subprocess.run(["clang", "-o", str(root / "layout"), str(source)], capture_output=True, text=True,
                               timeout=120)
        if built.returncode != 0:
            self.skipTest("clang could not build against the SDK: " + built.stderr[-200:])
        got = dict(line.split() for line in subprocess.run([str(root / "layout")], capture_output=True, text=True,
                                                            timeout=30).stdout.splitlines())
        got = {k: int(v) for k, v in got.items()}
        offsets = {}
        position = 0
        for name, code in zip(probe.CONNECTION_INFO_FIELDS, "BBB" + "I" * 13 + "Q" * 7):
            if name == "options":
                position = 4  # past __pad1
            offsets[name] = position
            position += struct.calcsize("<" + code)
        self.assertEqual(got["size"], probe.CONNECTION_INFO.size)
        for name in ("state", "options", "rto", "snd_sbbytes", "rcv_wnd", "rttvar", "txpackets", "txbytes",
                     "rxpackets", "rxbytes", "txretransmitpackets"):
            self.assertEqual(got[name], offsets[name], name)
        self.assertEqual((got["TCP_CONNECTION_INFO"], got["TCP_KEEPALIVE"], got["TCP_KEEPINTVL"], got["TCP_KEEPCNT"]),
                         (probe.TCP_CONNECTION_INFO, probe.TCP_KEEPALIVE, probe.TCP_KEEPINTVL, probe.TCP_KEEPCNT))
        self.assertEqual(probe.WRITABLE, (got["TCPS_ESTABLISHED"], got["TCPS_CLOSE_WAIT"]))
        self.assertEqual(probe.TCP_STATES[got["TCPS_TIME_WAIT"]], "time_wait")

    def test_connection_info_reads_a_live_loopback_socket(self):
        import socket
        probe = load_net_probe()
        gateway = self.gateway()
        helper = probe.Presock("lo0", "127.0.0.1", [gateway.port], 1, str(self.temp() / "s.json"), 1.0, 1.0, 30)
        sock, kind = helper.connect(gateway.port, True)
        self.assertEqual(kind, "connected")
        self.addCleanup(sock.close)
        self.assertEqual(sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) != 0, True)
        self.assertEqual([sock.getsockopt(socket.IPPROTO_TCP, o) for o in (0x10, 0x101, 0x102)],
                         list(probe.PRESOCK_KEEPALIVE))
        before = helper.info(sock)
        self.assertEqual((before["state"], before["snd_sbbytes"]), (4, 0))
        self.assertEqual(helper.send(sock, probe.presock_marker(0)), len(probe.presock_marker(0)))
        deadline = time.monotonic() + 5
        while helper.info(sock)["snd_sbbytes"] and time.monotonic() < deadline:
            time.sleep(0.05)
        after = helper.info(sock)
        self.assertEqual(after["snd_sbbytes"], 0)
        self.assertGreaterEqual(after["txbytes"] - before["txbytes"], len(probe.presock_marker(0)))
        self.assertGreaterEqual(after["txpackets"] - before["txpackets"], 1)

    # ------------------------------------------------------ the helper

    def test_the_helper_takes_the_first_port_the_gateway_accepts_in_order(self):
        first, second = self.gateway(), self.gateway()
        for ports, chosen, kinds in (([first.closed, first.port, second.port], first, {"connected": 1, "refused": 1}),
                                     ([second.port, first.port], second, {"connected": 1})):
            with self.subTest(ports=ports):
                state = self.temp() / "presock-lo0.json"
                accepted = (first.accepted, second.accepted)
                helper = self.start(state, ports)
                self.assertEqual(self.wait_phase(state, ("open", "failed", "unavailable")), "open")
                doc = json.loads(state.read_text())
                self.assertEqual((doc["port"], doc["select_kinds"], doc["opened"]), (chosen.port, kinds, 2))
                # The probe connect and the two kept sockets, all to the chosen port.
                other = second if chosen is first else first
                deadline = time.monotonic() + 5
                while chosen.accepted - accepted[0 if chosen is first else 1] < 3 and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertEqual(chosen.accepted - accepted[0 if chosen is first else 1], 3)
                self.assertEqual(other.accepted, accepted[1 if chosen is first else 0])
                self.command(state, "close")
                self.assertEqual(helper.wait(10), 0)
                self.assertEqual(helper.stdout.read(), "")

    def test_the_helper_is_unavailable_when_the_gateway_accepts_none_of_the_ports(self):
        gateway = self.gateway()
        closed = []
        import socket
        for _ in range(2):
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            closed.append(s.getsockname()[1])
            s.close()
        state = self.temp() / "presock-lo0.json"
        helper = self.start(state, [gateway.closed] + closed)
        self.assertEqual(helper.wait(15), 3)
        self.assertEqual(self.read(state, "open"), "unavailable opened=0 need=2 select=refused:3")
        self.assertEqual(self.read(state, "ports"), "")
        self.assertEqual(self.read(state, "write"), "none")
        self.assertEqual(gateway.accepted, 0)

    def test_the_helper_writes_on_command_and_loopback_acknowledges_every_byte(self):
        gateway = self.gateway()
        state = self.temp() / "presock-lo0.json"
        helper = self.start(state, [gateway.port], n=2, wait=1)
        self.assertEqual(self.wait_phase(state, ("open", "failed", "unavailable")), "open")
        self.assertEqual(state.stat().st_mode & 0o777, 0o600)
        opened = self.read(state, "open")
        self.assertEqual(opened, "open opened=2 need=2 kinds=connected:2 keepalive=4/4/60")
        ports = [int(p) for p in self.read(state, "ports").split()]
        self.assertEqual(ports[0], gateway.port)
        self.assertEqual(len(ports), 3)
        self.assertNotIn("127.0.0.1", state.read_text())
        self.command(state, "write")
        self.assertEqual(self.wait_phase(state, ("written",)), "written")
        line = self.read(state, "write")
        self.assertRegex(line, r"^written=2 acked=2 unacked=0 reset=0 rx=0 timed_out=0 closed=0 not_written=0 "
                               r"answered=2 tx=[0-9]+ retx=0 rx_packets=0 wait=1s$")
        times = self.read(state, "times")
        t_write, t_done = (float(t) for t in times.split())
        self.assertLessEqual(t_write, t_done)
        # The state keeps the raw float; presock-read prints it with six
        # decimals, which a raw time.time() seldom survives exactly.
        raw = json.loads(state.read_text())["write"]
        self.assertEqual(times, f"{raw['t_write']:.6f} {raw['t_done']:.6f}")
        for text in (opened, line):
            for port in ports:
                self.assertNotRegex(text, rf"\b{port}\b")
        # A second write command is ignored: one write per window.
        self.command(state, "write")
        time.sleep(0.3)
        self.assertEqual(json.loads(state.read_text())["write"], raw)
        self.assertEqual(self.read(state, "times"), times)
        self.command(state, "close")
        self.assertEqual(helper.wait(10), 0)
        self.assertEqual(self.read(state, "phase"), "closed")
        self.assertEqual(helper.stdout.read(), "")

    def test_written_bytes_are_classified_by_their_connection_info(self):
        import errno as errno_module
        probe = load_net_probe()
        root = self.temp()

        def outcome(scenarios, wait=0.3):
            """Each scenario: (state before, send result or exception, the
            readings after the write as (state, sbbytes, rxpackets) tuples,
            the last one repeated, SO_ERROR)."""

            class Fake(probe.Presock):
                def __init__(self):
                    super().__init__("lo0", "127.0.0.1", [9], len(scenarios), str(root / "s.json"), 1.0, wait, 30)
                    self.socks = list(range(len(scenarios)))
                    self.lports = [40000 + k for k in self.socks]
                    self.reads = {k: 0 for k in self.socks}
                    self.doc.update(phase="open", port=9)

                def info(self, k):
                    first, _, readings, _ = scenarios[k]
                    n = self.reads[k]
                    self.reads[k] += 1
                    if n == 0:
                        state, sb, rx = first, 0, 0
                    else:
                        state, sb, rx = readings[min(n - 1, len(readings) - 1)]
                    return dict.fromkeys(probe.CONNECTION_INFO_FIELDS, 0) | {
                        "state": state, "snd_sbbytes": sb, "rxpackets": rx, "txpackets": n, "txretransmitpackets": n}

                def send(self, k, data):
                    sent = scenarios[k][1]
                    if isinstance(sent, BaseException):
                        raise sent
                    return sent

                def so_error(self, k):
                    return scenarios[k][3]

            helper = Fake()
            started = time.monotonic()
            helper.write()
            helper.save()
            write = helper.doc["write"]
            return ([s["outcome"] for s in write["sockets"]], write["written"], time.monotonic() - started,
                    probe.presock_read(str(root / "s.json"), "write"))

        est, cw = 4, 5
        # Unacknowledged for the whole wait, then; an ACK of any of the
        # written bytes (even part) is acked at once.
        got, written, took, line = outcome([(est, 22, [(est, 22, 0)], 0), (est, 22, [(est, 21, 0)], 0)])
        self.assertEqual((got, written), (["unacked", "acked"], 2))
        self.assertGreaterEqual(took, 0.3)
        self.assertTrue(line.startswith("written=2 acked=1 unacked=1 reset=0 rx=0 timed_out=0 closed=0 "
                                        "not_written=0 answered=1 "), line)
        got, written, took, line = outcome([(est, 22, [(est, 0, 0)], 0)], wait=5)
        self.assertEqual(got, ["acked"])
        self.assertLess(took, 2)
        # A closed socket: reset by the gateway, timed out, or closed.
        got, _, _, line = outcome([(est, 22, [(0, 0, 0)], errno_module.ECONNRESET),
                                   (est, 22, [(0, 0, 0)], errno_module.ETIMEDOUT), (est, 22, [(0, 0, 0)], 0)])
        self.assertEqual(got, ["reset", "timed_out", "closed"])
        self.assertIn(" reset=1 rx=0 timed_out=1 closed=1 not_written=0 answered=1 ", line)
        # Data from the gateway while the bytes stay unacked is an answer.
        got, _, _, line = outcome([(est, 22, [(est, 22, 1)], 0)])
        self.assertEqual(got, ["rx"])
        self.assertIn(" answered=1 ", line)
        # CLOSE_WAIT is still written on; FIN_WAIT_1, CLOSED and a send that
        # fails are not.
        got, written, _, line = outcome([(cw, 22, [(cw, 22, 0)], 0), (6, 22, [(6, 0, 0)], 0), (0, 22, [(0, 0, 0)], 0),
                                         (est, BrokenPipeError(errno_module.EPIPE, "broken"), [(est, 0, 0)], 0)])
        self.assertEqual((got, written), (["unacked", "not_written", "not_written", "not_written"], 1))
        self.assertIn("written=1 acked=0 unacked=1 ", line)
        self.assertIn(" not_written=3 answered=0 ", line)

    def test_the_helper_closes_its_sockets_once_its_parent_is_gone(self):
        gateway = self.gateway()
        state = self.temp() / "presock-lo0.json"
        # The parent shell starts the helper and exits a second later.
        subprocess.run(["/bin/sh", "-c", '"$0" -I "$1" presock lo0 127.0.0.1 "$2" 1 "$3" 1 1 60 >/dev/null 2>&1 & '
                        'sleep 1', SYSTEM_PY, str(NET_PROBE), str(gateway.port), str(state)], timeout=30)
        self.assertEqual(self.wait_phase(state, ("orphaned", "expired", "closed")), "orphaned")
        # Its lifetime ends it too.
        state = self.temp() / "presock-lo0.json"
        helper = self.start(state, [gateway.port], n=1, lifetime=5)
        self.assertEqual(helper.wait(20), 0)
        self.assertEqual(self.read(state, "phase"), "expired")

    def test_bad_presock_arguments_refuse_without_output_or_state(self):
        root = self.temp()
        state = root / "presock-lo0.json"
        good = ["lo0", "127.0.0.1", "80,443", "2", str(state), "1", "1", "60"]
        cases = [
            {2: "80,80"}, {2: "0"}, {2: "80,443,53,8080,22"}, {2: "70000"}, {3: "0"}, {3: "5"}, {4: ""},
            {5: "0.05"}, {5: "11"}, {6: "0.1"}, {6: "31"}, {7: "1"}, {7: "8000"}, {1: "::1"}, {1: "gateway"},
            {0: "nosuch9"},
        ]
        for change in cases + [None]:
            args = list(good)
            if change is None:
                args = args[:-1]
            else:
                for k, v in change.items():
                    args[k] = v
            with self.subTest(args=args):
                result = subprocess.run([SYSTEM_PY, "-I", str(NET_PROBE), "presock", *args], capture_output=True,
                                        text=True, timeout=30)
                self.assertEqual((result.returncode, result.stdout), (2, ""))
                self.assertFalse(state.exists())
        for args in (["presock-read", str(state)], ["presock-read", str(state), "nope"]):
            result = subprocess.run([SYSTEM_PY, "-I", str(NET_PROBE), *args], capture_output=True, text=True,
                                    timeout=30)
            self.assertEqual((result.returncode, result.stdout), (2, ""))
        # A missing or foreign state file reads as none.
        self.assertEqual([self.read(state, m) for m in ("phase", "open", "write", "times", "ports")],
                         ["none", "none", "none", "none", ""])
        state.write_text(json.dumps({"schema": "other", "phase": "open"}))
        self.assertEqual(self.read(state, "phase"), "none")

    # ------------------------------------------------------------ S20h

    def test_the_helper_marks_its_sockets_and_records_their_connect_times(self):
        import socket
        probe = load_net_probe()
        # S20h review: the marker is the source port. XNU's keepalives carry
        # the connection's ports and the system's default TTL, never the
        # socket's IP_TTL.
        self.assertEqual((probe.PRESOCK_MARK_SPORT_FIRST, probe.PRESOCK_MARK_SPORT_COUNT), (47000, 32))
        marker = range(47000, 47032)
        gateway = self.gateway()
        helper = probe.Presock("lo0", "127.0.0.1", [gateway.port], 1, str(self.temp() / "s.json"), 1.0, 1.0, 30,
                               keepalive=(1, 2, 5))
        sock, kind = helper.connect(gateway.port, True)
        self.assertEqual(kind, "connected")
        self.addCleanup(sock.close)
        self.assertIn(sock.getsockname()[1], marker)
        self.assertEqual(struct.unpack("ii", sock.getsockopt(socket.SOL_SOCKET, socket.SO_LINGER, 8)), (1, 0))
        self.assertEqual([sock.getsockopt(socket.IPPROTO_TCP, o) for o in (0x10, 0x101, 0x102)], [1, 2, 5])
        # The port probe stays on an ephemeral port, outside the range.
        probe_sock, kind = helper.connect(gateway.port, False)
        self.assertEqual(kind, "connected")
        self.addCleanup(probe_sock.close)
        self.assertNotIn(probe_sock.getsockname()[1], marker)
        # A port of the range in use is skipped; none free is eaddrinuse.
        held = []
        for port in marker:
            s = socket.socket()
            try:
                s.bind(("0.0.0.0", port))
            except OSError:
                s.close()
                continue
            held.append(s)
        self.addCleanup(lambda: [s.close() for s in held])
        self.assertEqual(helper.connect(gateway.port, True), (None, "eaddrinuse"))
        free = held.pop()
        port = free.getsockname()[1]
        free.close()
        other, kind = helper.connect(gateway.port, True)
        self.assertEqual(kind, "connected")
        self.assertEqual(other.getsockname()[1], port)
        for s in held + [other, sock, probe_sock]:
            s.close()
        held.clear()
        # The window's helper, with its keepalive as the ninth argument.
        state = self.temp() / "presock-lo0.json"
        started = time.time()
        helper = subprocess.Popen([SYSTEM_PY, "-I", str(NET_PROBE), "presock", "lo0", "127.0.0.1", str(gateway.port),
                                   "2", str(state), "1", "1", "60", "1/2/5"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: helper.poll() is None and (helper.kill(), helper.wait(5)))
        self.assertEqual(self.wait_phase(state, ("open", "failed", "unavailable")), "open")
        self.assertEqual(self.read(state, "open"), "open opened=2 need=2 kinds=connected:2 keepalive=1/2/5")
        doc = json.loads(state.read_text())
        self.assertEqual((doc["mark_sport"], doc["keepalive"]), ([47000, 32], [1, 2, 5]))
        lports = [entry["lport"] for entry in doc["sockets"]]
        self.assertEqual(len(set(lports)), 2)
        self.assertTrue(all(p in marker for p in lports), lports)
        for entry in doc["sockets"]:
            self.assertGreaterEqual(entry["t_connected"], started)
            self.assertLessEqual(entry["t_connected"], doc["t_open"])
        self.command(state, "close")
        self.assertEqual(helper.wait(10), 0)

    def test_a_bad_keepalive_argument_refuses(self):
        probe = load_net_probe()
        self.assertEqual(probe.keepalive_arg("4/4/60"), (4, 4, 60))
        self.assertEqual(probe.keepalive_arg("10/10/120"), (10, 10, 120))
        self.assertEqual(probe.presock_keepalive(["x"] * 8), probe.PRESOCK_KEEPALIVE)
        state = self.temp() / "presock-lo0.json"
        for bad in ("0/4/60", "4/11/60", "11/4/60", "4/4/1", "4/4/121", "4/4", "4/4/60/1", "a/4/60", "04/4/60",
                    "4//60", ""):
            with self.subTest(keepalive=bad):
                with self.assertRaises(ValueError):
                    probe.keepalive_arg(bad)
                result = subprocess.run([SYSTEM_PY, "-I", str(NET_PROBE), "presock", "lo0", "127.0.0.1", "80", "2",
                                         str(state), "1", "1", "60", bad], capture_output=True, text=True, timeout=30)
                self.assertEqual((result.returncode, result.stdout), (2, ""))
                self.assertFalse(state.exists())

    def test_a_socket_closed_before_the_write_names_why(self):
        import errno as errno_module
        probe = load_net_probe()
        root = self.temp()
        errors = {0: errno_module.ECONNRESET, 1: errno_module.ETIMEDOUT, 2: 0}

        class Fake(probe.Presock):
            def __init__(self):
                super().__init__("lo0", "127.0.0.1", [9], 4, str(root / "s.json"), 1.0, 0.2, 30)
                self.socks = [0, 1, 2, 3]
                self.lports = [40000 + k for k in self.socks]
                self.doc.update(phase="open", port=9)

            def info(self, k):
                if k == 3:
                    raise ConnectionResetError(errno_module.ECONNRESET, "reset")
                return dict.fromkeys(probe.CONNECTION_INFO_FIELDS, 0)  # TCPS_CLOSED

            def so_error(self, k):
                return errors[k]

        helper = Fake()
        helper.write()
        helper.save()
        sockets = helper.doc["write"]["sockets"]
        self.assertEqual([s["outcome"] for s in sockets], ["not_written"] * 4)
        self.assertEqual([s.get("cause") for s in sockets], ["reset", "timed_out", None, "reset"])
        line = probe.presock_read(str(root / "s.json"), "write")
        self.assertTrue(line.startswith("written=0 acked=0 unacked=0 reset=0 rx=0 timed_out=0 closed=0 not_written=4 "
                                        "answered=0 "), line)
        self.assertTrue(line.endswith(" wait=0.2s not_written_causes=reset:2,timed_out:1"), line)


class LeakReviewPresockFramesTests(unittest.TestCase):
    """S20g: leak_review.py presock-frames on synthetic captures."""

    GW = "192.0.2.1"
    LOCAL = "192.0.2.50"

    def frames(self, records, *extra):
        with tempfile.TemporaryDirectory(prefix="aegis-s20g-frames-") as temp:
            pcap = pathlib.Path(temp) / "physical.pcap"
            pcap.write_bytes(pcap_bytes(records))
            result = subprocess.run([sys.executable, "-I", str(LEAK_REVIEW), "presock-frames", "--pcap", str(pcap),
                                     "--dst", self.GW, "--dport", "8080", "--sport", "50001", "--sport", "50002",
                                     *extra], capture_output=True, text=True, timeout=30)
            return result.returncode, result.stdout

    def test_only_the_helpers_frames_to_the_gateway_port_count_by_kind_and_time(self):
        out = lambda sport, flags=0x10, data=b"", dst=None, dport=8080: e4(self.LOCAL, dst or self.GW, 6,
                                                                            tcp_full(sport, dport, flags, data=data))
        records = [
            (IN, out(50001, 0x18, b"aegis-s20g-presock-0\n")),     # data
            (IN + 0.1, out(50002, 0x10)),                          # bare ACK (keepalive)
            (IN + 0.2, out(50002, 0x11)),                          # FIN
            (IN + 0.3, out(50003, 0x18, b"x")),                    # another source port
            (IN + 0.4, out(50001, 0x18, b"x", dport=80)),          # another port
            (IN + 0.5, out(50001, 0x18, b"x", dst="192.0.2.9")),   # another host
            (IN + 0.6, e4(self.GW, self.LOCAL, 6, tcp_full(8080, 50001, 0x10))),  # the gateway's ACK
            (IN + 5.0, out(50001, 0x18, b"late")),
            (IN - 5.0, out(50002, 0x10)),
        ]
        rc, text = self.frames(records)
        self.assertEqual((rc, text), (0, "presock_frames=5 data=2 ack_only=2 other=1 total=9 ack_only_marked=0\n"))
        rc, text = self.frames(records, "--since", repr(IN - 1), "--until", repr(IN + 1))
        self.assertEqual((rc, text), (0, "presock_frames=3 data=1 ack_only=1 other=1 total=9 ack_only_marked=0\n"))
        for address in (self.GW, self.LOCAL, "8080", "50001"):
            self.assertNotIn(address, text)

    def test_the_bare_acks_from_the_marker_range_are_counted_as_marked(self):
        # S20h review: the filter marks the helper's keepalives by their
        # source port; a filter-off capture shows that marker on the wire.
        out = lambda sport, flags=0x10, data=b"": e4(self.LOCAL, self.GW, 6, tcp_full(sport, 8080, flags, data=data))
        records = [
            (IN, out(47000)),                    # a keepalive from the range's first port
            (IN + 0.1, out(47031)),              # and from its last
            (IN + 0.2, out(47031, 0x18, b"x")),  # data from the range: not a bare ACK
            (IN + 0.3, out(47001, 0x11)),        # FIN from the range: not a bare ACK
            (IN + 0.4, out(47032)),              # past the range
            (IN + 0.5, out(46999)),              # before it
        ]
        with tempfile.TemporaryDirectory(prefix="aegis-s20h-frames-") as temp:
            pcap = pathlib.Path(temp) / "physical.pcap"
            pcap.write_bytes(pcap_bytes(records))
            ports = [a for p in (47000, 47001, 47031, 47032, 46999) for a in ("--sport", str(p))]
            result = subprocess.run([sys.executable, "-I", str(LEAK_REVIEW), "presock-frames", "--pcap", str(pcap),
                                     "--dst", self.GW, "--dport", "8080", *ports], capture_output=True, text=True,
                                    timeout=30)
        self.assertEqual((result.returncode, result.stdout),
                         (0, "presock_frames=6 data=1 ack_only=4 other=1 total=6 ack_only_marked=2\n"))

    def test_an_unreadable_capture_is_unreadable(self):
        with tempfile.TemporaryDirectory(prefix="aegis-s20g-frames-") as temp:
            bad = pathlib.Path(temp) / "bad.pcap"
            bad.write_bytes(b"nope")
            result = subprocess.run([sys.executable, "-I", str(LEAK_REVIEW), "presock-frames", "--pcap", str(bad),
                                     "--dst", self.GW, "--dport", "8080", "--sport", "50001"],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual((result.returncode, result.stdout), (2, "presock_frames=unreadable\n"))


class LeakReviewPresockReviewTests(unittest.TestCase):
    """S20h: leak_review.py presock-review, the positive control's keepalive
    criterion, on synthetic captures, helper states and --filter-status
    outputs. Documentation addresses only."""

    GW = "192.0.2.1"
    LOCAL = "192.0.2.50"
    PORT = 8080
    # S20h review: the helper binds its sockets in the provider's marker
    # range (47000, 32 ports).
    LPORTS = (47000, 47001)
    ARMED = 1_800_000_100.0
    DISARMED = ARMED + 60.0
    # Each socket's last receive (its SYN-ACK) 3 s and 3.007 s before the
    # arm: with keepalive 4/4 they are due 1 s (0.993 s) after the arm and
    # every 4 s, so 41000/40993, 45000/44993 and 49000/48993 ms fall inside
    # the reads at 40000 and 50000 ms with 500 ms of tolerance.
    RX = (ARMED - 3.0, ARMED - 3.007)
    TICKS = (40993, 41000, 44993, 45000, 48993, 49000)
    KINDS = ("syn", "syn_ack", "ack_only", "data", "fin", "rst", "other", "non_tcp")

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="aegis-s20h-review-")
        self.addCleanup(temp.cleanup)
        self.root = pathlib.Path(temp.name)

    def state(self, tx=4, mark=(47000, 32), keepalive=(4, 4, 60), t_connected=None, lports=None):
        lports = lports or self.LPORTS
        doc = {"schema": "aegis-presock-v1", "phase": "closed", "port": self.PORT, "mark_sport": list(mark),
               "keepalive": list(keepalive),
               "sockets": [{"kind": "connected", "lport": p, "t_connected": (t_connected or self.RX)[k]}
                           for k, p in enumerate(lports)],
               "write": {"t_write": self.ARMED + 40.1, "t_done": self.ARMED + 41.1, "written": 2,
                         "sockets": [{"lport": p, "tx_packets": tx // 2} for p in lports]}}
        path = self.root / "presock-en0.json"
        path.write_text(json.dumps(doc))
        return path

    def status(self, name, mode="guarding", arm_seq=1, armed_for_ms=40000, marked=None, kinds=None, ring_next=0,
               entries=(), mark=(47000, 32), outbound=True):
        def table(cells):
            rows = {c: dict.fromkeys(self.KINDS, 0) for c in ("primary", "en_other", "awdl_llw", "bridge_ap_anpi",
                                                              "other")}
            rows["primary"].update(cells or {})
            return rows
        obs = {"arm_seq": arm_seq, "disarms": 0, "armed_ms_total": armed_for_ms, "armed_for_ms": armed_for_ms,
               "open_while_applied": 0, "applied_epochs": 0, "primary_iface": "en0",
               "drops": {c: {"in": 0, "out": 0, "any": 0} for c in ("primary", "en_other", "awdl_llw",
                                                                     "bridge_ap_anpi", "other")},
               "ring": {"next": 0, "skipped": 0, "torn": 0, "entries": []}}
        if outbound:
            obs["outbound"] = {"mark_sport_first": mark[0], "mark_sport_count": mark[1], "kinds": table(kinds),
                               "marked": table(marked),
                               "ring": {"next": ring_next, "skipped": 0, "torn": 0, "entries": list(entries)}}
        path = self.root / f"filter-status-{name}.txt"
        path.write_text("filter_result=ok exit_code=0\n" + json.dumps(
            {"schema": "aegis-ne-xpc-v1", "verb": "filter-status", "report": {"mode": mode, "observability": obs}})
            + "\n")
        return path

    @staticmethod
    def entry(index, ms, marked=True, tcp="ack_only", iface="en0"):
        return {"index": index, "arm_seq": 1, "ms": ms, "class": "primary", "iface": iface, "dir": "out",
                "family": "v4", "proto": 6, "tcp": tcp, "reason": "drop_tcp_out", "marked": marked}

    def capture(self, extra=(), rx=True):
        records = list(extra)
        if rx:
            for t, p in zip(self.RX, self.LPORTS):
                records.append((t, e4(self.GW, self.LOCAL, 6, tcp_full(self.PORT, p, 0x12))))
            # The gateway's probe after the arm: dropped inbound, never a
            # receive of the socket.
            records.append((self.ARMED + 2.0, e4(self.GW, self.LOCAL, 6, tcp_full(self.PORT, self.LPORTS[0], 0x10))))
        path = self.root / "physical.pcap"
        path.write_bytes(pcap_bytes(records))
        return path

    def review(self, before, after, *extra, state=None, pcap=None, armed=True):
        args = ["presock-review", "--pcap", str(pcap or self.capture()), "--state", str(state or self.state()),
                "--dst", self.GW, "--dev", "en0", "--before", str(before), "--after", str(after), *extra]
        if armed:
            args += ["--armed-at", repr(self.ARMED), "--disarmed-at", repr(self.DISARMED)]
        result = subprocess.run([SYSTEM_PY, "-I", str(LEAK_REVIEW), *args], capture_output=True, text=True,
                                timeout=60)
        lines = result.stdout.splitlines()
        for text in lines:
            for secret in (self.GW, self.LOCAL, str(self.PORT), *map(str, self.LPORTS)):
                self.assertNotIn(secret, text)
        return result.returncode, lines

    def passing(self, **after):
        before = self.status("before", marked={"ack_only": 10}, kinds={"ack_only": 30}, ring_next=20)
        entries = [self.entry(20 + k, ms) for k, ms in enumerate(self.TICKS)]
        entries += [self.entry(26 + k, ms, marked=False) for k, ms in enumerate((42500, 43500, 46500, 47500))]
        values = dict(armed_for_ms=50000, marked={"ack_only": 16}, kinds={"ack_only": 40}, ring_next=30,
                      entries=entries)
        values.update(after)
        return before, self.status("after", **values)

    def test_the_helpers_marked_keepalives_on_every_due_time_pass(self):
        rc, lines = self.review(*self.passing())
        self.assertEqual(rc, 0)
        self.assertEqual(lines, [
            "pass class=primary sockets=2 expected=6 per_socket=3,3 counted=6 matched=6 unmarked=4 inferred=0 "
            "ring_lost=0 data_counted=0 tx=4 rx=capture keepalive=4/4 tol_ms=500 span_ms=10000",
            "tx=4 data_counted=0 blocked_before_filter=4 keepalive_expected=6 keepalive_counted=6 class=primary",
            "frames=0 data=0 ack_only=0 other=0 uncounted=0 total=3 after_disarm=0 tap_evidence=post_filter"])
        # Without the gateway's frames the helper's connect times stand in.
        rc, lines = self.review(*self.passing(), pcap=self.capture(rx=False))
        self.assertTrue(lines[0].startswith("pass ") and lines[0].endswith(" rx=helper keepalive=4/4 tol_ms=500 "
                                                                           "span_ms=10000"), lines[0])
        # A receive just before the arm moves every due time: the same
        # drops then no longer fall on them.
        late = [(self.ARMED - 1.0, e4(self.GW, self.LOCAL, 6, tcp_full(self.PORT, p, 0x10))) for p in self.LPORTS]
        rc, lines = self.review(*self.passing(), pcap=self.capture(extra=late))
        self.assertTrue(lines[0].startswith("unavailable ticks: "), lines[0])

    def test_too_few_due_keepalives_uncounted_lost_or_misplaced_ones_are_unavailable(self):
        before, _ = self.passing()
        cases = (
            # Reads 4 s apart: one keepalive a socket between them.
            (dict(armed_for_ms=44000), "unavailable wait_short: fewer than two keepalives per socket were due "
                                       "between the reads class=primary sockets=2 expected=2 per_socket=1,1 "),
            # Five marked bare ACKs for six due keepalives.
            (dict(marked={"ack_only": 15}), "unavailable uncounted: fewer marked bare ACKs than due keepalives "
                                            "class=primary sockets=2 expected=6 per_socket=3,3 counted=5 "),
            # The ring lost five records between the reads.
            (dict(ring_next=35), "unavailable ring_lost: the outbound ring lost records between the reads "),
            # The marked records two seconds off every due time.
            (dict(ring_next=26, entries=[self.entry(20 + k, ms + 2000) for k, ms in enumerate(self.TICKS)]),
             "unavailable ticks: the marked bare ACKs do not fall on every due keepalive class=primary sockets=2 "
             "expected=6 per_socket=3,3 counted=6 matched=0 "),
            # The marked records on another interface.
            (dict(ring_next=26, entries=[self.entry(20 + k, ms, iface="en5") for k, ms in enumerate(self.TICKS)]),
             "unavailable ticks: "),
        )
        for after, prefix in cases:
            with self.subTest(after=after):
                _, after_path = self.passing(**after)
                rc, lines = self.review(before, after_path)
                self.assertEqual(rc, 0)
                self.assertTrue(lines[0].startswith(prefix), lines[0])

    def test_unmarked_drops_on_the_due_times_are_pass_inferred_at_best(self):
        before = self.status("before", ring_next=20)
        entries = [self.entry(20 + k, ms, marked=False) for k, ms in enumerate(self.TICKS)]
        after = self.status("after", armed_for_ms=50000, kinds={"ack_only": 6}, ring_next=26, entries=entries)
        rc, lines = self.review(before, after)
        self.assertEqual(lines[0], "unavailable unattributed: no marked bare ACK was counted (pass_inferred: unmarked "
                                   "ones fit every due keepalive) class=primary sockets=2 expected=6 per_socket=3,3 "
                                   "counted=0 matched=0 unmarked=6 inferred=6 ring_lost=0 data_counted=0 tx=4 "
                                   "rx=capture keepalive=4/4 tol_ms=500 span_ms=10000")
        after = self.status("after", armed_for_ms=50000, ring_next=20)
        rc, lines = self.review(before, after)
        self.assertTrue(lines[0].startswith("unavailable unattributed: no marked bare ACK was counted class="), lines[0])

    def test_marked_data_drops_must_cover_every_data_segment_sent(self):
        before, _ = self.passing()
        for data, tx, verdict in ((2, 4, "unavailable data_partial: "), (4, 4, "pass "), (6, 4, "pass "),
                                  (0, 4, "pass ")):
            with self.subTest(data=data, tx=tx):
                _, after = self.passing(marked={"ack_only": 16, "data": data})
                rc, lines = self.review(before, after, state=self.state(tx=tx))
                self.assertTrue(lines[0].startswith(verdict), lines[0])
                self.assertEqual(lines[1], f"tx={tx} data_counted={data} blocked_before_filter={max(tx - data, 0)} "
                                           f"keepalive_expected=6 keepalive_counted=6 class=primary")

    def test_reads_not_armed_rearmed_unreadable_or_before_v29_are_never_a_pass(self):
        _, after = self.passing()
        good = self.status("good", marked={"ack_only": 10}, kinds={"ack_only": 30}, ring_next=20)
        cases = (
            (self.status("open", mode="open", armed_for_ms=None), after, "fail mode=open: the filter was not armed"),
            (good, self.status("rearmed", arm_seq=2, armed_for_ms=50000), "fail rearmed: mode_after=guarding "
                                                                          "arm_seq=1->2 disarms=0->0"),
            (self.root / "missing.txt", after, "fail unreadable: --filter-status not parsed"),
            (self.status("v28", outbound=False), after, "unavailable no_outbound: a provider before v29 "
                                                        "class=primary tx=4"),
            (self.status("mark", mark=(47100, 32), ring_next=20), after,
             "unavailable mark_mismatch: the provider's marker range is not the helper's class=primary"),
            (self.status("count", mark=(47000, 16), ring_next=20), after, "unavailable mark_mismatch: the provider's "),
            (self.status("none", mark=(47000, 0), ring_next=20), after, "unavailable mark_mismatch: the provider's "),
        )
        for before, after_path, prefix in cases:
            with self.subTest(prefix=prefix):
                rc, lines = self.review(before, after_path)
                self.assertTrue(lines[0].startswith(prefix), lines[0])
        # The helper's range differs, or one of its sockets is outside it
        # (no marked drop can be its own): never a pass.
        rc, lines = self.review(good, after, state=self.state(mark=(47100, 32)))
        self.assertEqual(lines[0], "unavailable mark_mismatch: the provider's marker range is not the helper's "
                                   "class=primary")
        rc, lines = self.review(good, after, state=self.state(lports=(47000, 50002)))
        self.assertEqual(lines[0], "unavailable mark_mismatch: 1 of the sockets are outside the marker range "
                                   "class=primary")
        # The reads disagree on the range.
        rc, lines = self.review(self.status("other", mark=(47100, 32), marked={"ack_only": 10}, kinds={"ack_only": 30},
                                            ring_next=20), after)
        self.assertTrue(lines[0].startswith("unavailable mark_mismatch: the provider's "), lines[0])
        # Without the provider's armed span nothing can be placed.
        rc, lines = self.review(good, after, armed=False)
        self.assertEqual(lines[0], "unavailable no_armed_span class=primary tx=4 data_counted=0")
        self.assertEqual(lines[2], "frames=unknown no_armed_span")

    def test_the_helpers_frames_while_armed_beyond_their_marked_drops_are_uncounted(self):
        out = lambda sport, flags=0x10, data=b"": e4(self.LOCAL, self.GW, 6, tcp_full(sport, self.PORT, flags, data=data))
        first, second = self.LPORTS
        frames = [(self.ARMED + 10.0, out(first, 0x18, b"x")), (self.ARMED + 11.0, out(first)),
                  (self.ARMED + 15.0, out(second)), (self.ARMED - 10.0, out(second)),  # before the arm
                  (self.ARMED + 12.0, out(50003))]                                    # another source port
        pcap = self.capture(extra=frames)
        # (The ring's six marked keepalive drops outnumber the capture's two
        # bare ACKs from the marker's ports: tap_evidence post_filter.)
        before, after = self.passing()
        span_before = self.status("span-before", mode="open", armed_for_ms=None)
        span_after = self.status("span-after", mode="open", armed_for_ms=None, marked={"ack_only": 1, "data": 1})
        rc, lines = self.review(before, after, "--span-before", str(span_before), "--span-after", str(span_after),
                                pcap=pcap)
        self.assertEqual(lines[2], "frames=3 data=1 ack_only=2 other=0 uncounted=1 total=8 after_disarm=0 "
                                   "tap_evidence=post_filter")
        # Without v29 counts nothing covers them.
        v28 = self.status("span-v28", mode="open", armed_for_ms=None, outbound=False)
        rc, lines = self.review(before, after, "--span-before", str(v28), "--span-after", str(v28), pcap=pcap)
        self.assertEqual(lines[2], "frames=3 data=1 ack_only=2 other=0 uncounted=3 total=8 after_disarm=0 "
                                   "tap_evidence=post_filter")
        # Enough marked drops of each kind: counted, none uncounted.
        span_after = self.status("span-more", mode="open", armed_for_ms=None, marked={"ack_only": 2, "data": 1})
        rc, lines = self.review(before, after, "--span-before", str(span_before), "--span-after", str(span_after),
                                pcap=pcap)
        self.assertEqual(lines[2], "frames=3 data=1 ack_only=2 other=0 uncounted=0 total=8 after_disarm=0 "
                                   "tap_evidence=post_filter")

    def test_more_marked_drops_than_marker_frames_in_the_capture_are_tap_evidence(self):
        # S20h review: a tap before the filter records every frame the
        # filter drops. When the outbound ring holds more marked drops of
        # one kind on en0 between the reads than the capture holds frames
        # of that kind from a port of the marker range while armed, the tap
        # comes after the filter, so the helper's frames in it left the Mac,
        # however many marked data drops the filter counted.
        out = lambda sport, flags=0x10, data=b"", dst=None: e4(self.LOCAL, dst or self.GW, 6,
                                                               tcp_full(sport, self.PORT, flags, data=data))
        first, second = self.LPORTS
        span_before = self.status("span-before", mode="open", armed_for_ms=None)
        span_after = self.status("span-after", mode="open", armed_for_ms=None, marked={"ack_only": 6, "data": 4})
        before, after = self.passing()
        spans = ("--span-before", str(span_before), "--span-after", str(span_after))
        left = [(self.ARMED + 40.2, out(first, 0x18, b"x"))]
        later = [(self.DISARMED + 1.0, out(first)),
                 (self.DISARMED + 2.0, e4(self.GW, self.LOCAL, 6, tcp_full(self.PORT, first, 0x10)))]
        # Six marked keepalive drops, none of them in the capture.
        rc, lines = self.review(before, after, *spans, pcap=self.capture(extra=left + later))
        self.assertTrue(lines[0].startswith("pass "), lines[0])
        self.assertEqual(lines[2], "frames=1 data=1 ack_only=0 other=0 uncounted=0 total=6 after_disarm=2 "
                                   "tap_evidence=post_filter")
        # A frame for every marked drop, at its time (one at the disarm, the
        # span's edge, and one from another port of the range to another
        # host, which the helper's counts leave out): no evidence.
        acks = [(self.ARMED + ms / 1000.0, out(first if k % 2 else second)) for k, ms in enumerate(self.TICKS)]
        acks[-1] = (self.DISARMED, acks[-1][1])
        acks[0] = (acks[0][0], out(47031, dst="192.0.2.77"))
        rc, lines = self.review(before, after, *spans, pcap=self.capture(extra=left + acks + later))
        self.assertEqual(lines[2], "frames=6 data=1 ack_only=5 other=0 uncounted=0 total=12 after_disarm=2 "
                                   "tap_evidence=none")
        # One of them missing: post_filter. So is a frame from a port
        # outside the range in its place.
        rc, lines = self.review(before, after, *spans, pcap=self.capture(extra=left + acks[1:] + later))
        self.assertTrue(lines[2].endswith(" tap_evidence=post_filter"), lines[2])
        outside = [(acks[0][0], out(46999, dst="192.0.2.77"))]
        rc, lines = self.review(before, after, *spans, pcap=self.capture(extra=left + outside + acks[1:] + later))
        self.assertTrue(lines[2].endswith(" tap_evidence=post_filter"), lines[2])
        # Data drops alone: two marked data drops on en0 between the reads,
        # one data frame in the capture (the keepalives not dropped here).
        data = self.status("data", armed_for_ms=50000, marked={"ack_only": 10, "data": 2}, kinds={"ack_only": 30},
                           ring_next=22, entries=[self.entry(20 + k, 40200, tcp="data") for k in range(2)])
        rc, lines = self.review(before, data, *spans, pcap=self.capture(extra=left))
        self.assertTrue(lines[0].startswith("unavailable data_partial: "), lines[0])
        self.assertEqual(lines[2], "frames=1 data=1 ack_only=0 other=0 uncounted=0 total=4 after_disarm=0 "
                                   "tap_evidence=post_filter")
        # Both data drops in the capture: no evidence.
        both = left + [(self.ARMED + 40.3, out(second, 0x18, b"x"))]
        rc, lines = self.review(before, data, *spans, pcap=self.capture(extra=both))
        self.assertEqual(lines[2], "frames=2 data=2 ack_only=0 other=0 uncounted=0 total=5 after_disarm=0 "
                                   "tap_evidence=none")
        # No marked drop on en0 between the reads (unmarked ones only, or
        # marked ones on another interface): no evidence.
        unmarked = self.status("unmarked", armed_for_ms=50000, kinds={"ack_only": 6}, ring_next=26,
                               entries=[self.entry(20 + k, ms, marked=False) for k, ms in enumerate(self.TICKS)])
        rc, lines = self.review(self.status("before-u", ring_next=20), unmarked, *spans,
                                pcap=self.capture(extra=left))
        self.assertTrue(lines[0].startswith("unavailable unattributed: "), lines[0])
        self.assertEqual(lines[2], "frames=1 data=1 ack_only=0 other=0 uncounted=0 total=4 after_disarm=0 "
                                   "tap_evidence=none")
        elsewhere = self.status("elsewhere", armed_for_ms=50000, marked={"ack_only": 16}, kinds={"ack_only": 40},
                                ring_next=26, entries=[self.entry(20 + k, ms, iface="en5")
                                                       for k, ms in enumerate(self.TICKS)])
        rc, lines = self.review(before, elsewhere, *spans, pcap=self.capture(extra=left))
        self.assertTrue(lines[2].endswith(" tap_evidence=none"), lines[2])
        # A provider whose marker range is not the helper's, or reads that
        # are not under one arm: the ring is never read, no evidence.
        for b, a in ((self.status("mark-b", mark=(47100, 32), marked={"ack_only": 10}, kinds={"ack_only": 30},
                                  ring_next=20), self.passing(mark=(47100, 32))[1]),
                     (before, self.passing(arm_seq=2)[1])):
            rc, lines = self.review(b, a, *spans, pcap=self.capture(extra=left))
            self.assertTrue(lines[2].endswith(" tap_evidence=none"), (lines[0], lines[2]))

    def test_no_state_or_an_unreadable_capture(self):
        before, after = self.passing()
        missing = self.root / "presock-none.json"
        rc, lines = self.review(before, after, state=missing)
        self.assertEqual((rc, lines), (0, ["unavailable no_sockets", "unknown no_sockets", "frames=unknown no_sockets"]))
        bad = self.root / "bad.pcap"
        bad.write_bytes(b"nope")
        rc, lines = self.review(before, after, pcap=bad)
        self.assertEqual((rc, lines), (2, ["unavailable capture_unreadable", "unknown capture_unreadable",
                                           "frames=unknown capture_unreadable"]))


# ------------------------------------------------ S24 ENDURANCE=1 and LOAD=1

ENDURANCE_LOAD_SH = PACKAGE / "harness" / "endurance-load.sh"
ENDURANCE_REVIEW = PACKAGE / "harness" / "endurance_review.py"
SESSION_REBUILD_RS = PACKAGE / "src" / "session_rebuild.rs"
LEAK_GUARD_RS = PACKAGE / "src" / "leak_guard.rs"
LOAD_URL_FAKE = "http://load.example/down?bytes=1048576"
ENDURANCE_TSV_COLUMNS = ["cycle", "slot_s", "start", "end", "verdict", "whoami", "tcp_echo", "udp_echo", "dns_txt", "http",
                         "probe_detail", "status_start", "status_end", "phase", "renewal", "provider_pid", "rss_kib",
                         "cpu_pct", "log_read", "session_lost", "lost_causes", "session_rebuilt", "session_failed",
                         "renewal_states", "rebuild_pending", "codex_lock", "run_ms"]
ENDURANCE_ROWS = ["endurance_cycles", "endurance_longest_gap", "endurance_connected_throughout",
                  "endurance_provider_stable", "endurance_rss_growth", "endurance_rebuilds", "endurance_renewal",
                  "endurance_real_time"]
# v34: load_provider_rss after the load's rows, and harness/load_review.py's
# info rows after the disconnect.
LOAD_REVIEW_ROWS = ["load_filter_series", "load_outbound_drops", "load_placement", "load_window", "load_latency",
                    "load_queue", "load_takes"]
LOAD_ROWS = ["load_flow_burst_24", "load_flow_burst_90", "load_tcp_echo_v4", "load_udp_echo_v4", "load_download",
             "load_throughput", "load_concurrent", "load_connected_throughout", "load_filter_counters",
             "load_provider_rss", *LOAD_REVIEW_ROWS]
LOAD_REVIEW = PACKAGE / "harness" / "load_review.py"
ADDR_MASK = PACKAGE / "harness" / "addr_mask.py"
# The S24 rows that report reads made before an earlier row was written
# (result_since): the modes' preflight reads, and the summary rows of the
# cycles or of the load, which start where the mode began.
EARLIER_CHECK_ROWS.update({"endurance_preflight", "load_preflight", "load_download", "load_throughput", "load_concurrent",
                           "load_connected_throughout", "load_filter_counters", "load_provider_rss", *ENDURANCE_ROWS})

# Every fake reads the cycle the window is in from its progress file
# (`cycle=K of=N`, absent outside the cycles, K = N after them);
# FAKE_FAIL_AT=<probe>:<K>,... fails that probe in cycle K. In each cycle of
# FAKE_HANG_AT every probe runs to its bound (pgrep after
# FAKE_HANG_PGREP_S=<K>:<s>,... answers, ps, --status and the second log
# read hang until their alarm); in each cycle of FAKE_SLOW_AT the TCP echo,
# whoami and HTTP answer after FAKE_SLOW_S (3.5) and the TXT query after
# FAKE_SLOW_DNS_S (2.5), or time out at their bound if that is shorter.
EL_FAKE_PRELUDE = r"""
cyc() { sed -n 's/^cycle=\([0-9]*\) .*/\1/p' "$OUT/endurance.progress" 2>/dev/null | head -1; }
failing() { c=$(cyc); [ -n "$c" ] || return 1; case ",${FAKE_FAIL_AT:-}," in *",$1:$c,"*) return 0;; esac; return 1; }
in_cycles() { c=$(cyc); [ -n "$c" ] || return 1; case ",$1," in *",$c,"*) return 0;; esac; return 1; }
hanging() { in_cycles "${FAKE_HANG_AT:-}"; }
slow() { in_cycles "${FAKE_SLOW_AT:-}"; }
answers() { if awk -v d="$1" -v b="$2" 'BEGIN {exit !(d < b)}'; then sleep "$1"; return 0; fi; sleep "$2"; return 1; }
bound_of() { printf '%s\n' "$2" | sed -n "s/.*$1\([0-9][0-9]*\).*/\1/p"; }
"""

EL_FAKE_COMMANDS = dict(WINDOW_FAKE_COMMANDS)
EL_FAKE_COMMANDS.update({
    # The load streams (-o -): FAKE_LOAD_SERVE bytes (default the URL's
    # bytes=, else twice the cap) after FAKE_LOAD_DELAY_S, a timeout at the
    # -m bound (never with FAKE_LOAD_IGNORE_M=1); a burst under load fails
    # with FAKE_BURST_FAIL_UNDER_LOAD=1, FAKE_LOAD_BURST_FAILS=<a>:<b> fails
    # the last a requests of the 24-burst and the last b of the 90-burst
    # under load, and with FAKE_BURST_AT_THRESHOLD=1 the bursts' 23rd and
    # 24th and the 90-burst's last two requests fail (each request claims
    # the next slot); the cycles' whoami (another address in each cycle of
    # FAKE_WHOAMI_OTHER_AT) and HTTP, which also ends FAKE_ROW_STATUS.
    "curl": "#!/bin/sh" + EL_FAKE_PRELUDE + r"""
m=$(bound_of '-m ' "$*")
case "$*" in
  *" -o - "*)
    echo "curl load m=$m" >> "$CALLS"
    u=$(printf '%s\n' "$*" | sed -n 's/.*[?&]bytes=\([0-9][0-9]*\).*/\1/p')
    echo "curl load bytes=${u:-none}" >> "$CALLS"
    echo "curl load url=$(printf '%s\n' "$*" | awk '{print $NF}')" >> "$CALLS"
    # v34: -D <file> gets the response's headers; the first stream to start
    # answers FAKE_LOAD_FIRST_STATUS (with FAKE_LOAD_FIRST_BODY) when set,
    # and with FAKE_LOAD_HANG_FIRST=1 hangs past every bound instead.
    hdr=$(printf '%s\n' "$*" | sed -n 's/.* -D \([^ ]*\) .*/\1/p')
    st=200 body=''
    if [ -n "${FAKE_LOAD_FIRST_STATUS:-}${FAKE_LOAD_HANG_FIRST:-}" ] && mkdir "$STATE.first" 2>/dev/null; then
      if [ "${FAKE_LOAD_HANG_FIRST:-0}" = 1 ]; then : > "$STATE.load.$$"; sleep 40; exit 0; fi
      st=$FAKE_LOAD_FIRST_STATUS body=${FAKE_LOAD_FIRST_BODY-}
    fi
    [ "${FAKE_LOAD_IGNORE_M:-0}" = 1 ] && m=100000
    : > "$STATE.load.$$"
    d=${FAKE_LOAD_DELAY_S:-6}
    if [ "$d" -gt "$m" ]; then
      sleep "$m"; rm -f "$STATE.load.$$"; echo "curl: (28) Operation timed out" >&2; echo "http=000" >&2; exit 28
    fi
    if [ "$st" != 200 ]; then
      [ -z "$hdr" ] || printf 'HTTP/2 %s\r\ncontent-type: text/plain\r\nserver: fake\r\nx-other: dropped\r\ncontent-length: %s\r\n\r\n' \
        "$st" "${#body}" > "$hdr"
      printf '%s' "$body"; rm -f "$STATE.load.$$"; echo "http=$st" >&2; exit 0
    fi
    [ -z "$hdr" ] || printf 'HTTP/2 200\r\ncontent-type: application/x-xz\r\ncontent-length: 140064536\r\nserver: fake\r\nx-other: dropped\r\n\r\n' > "$hdr"
    sleep "$d"
    head -c "${FAKE_LOAD_SERVE:-${u:-$((2 * LOAD_BYTES / LOAD_STREAMS))}}" /dev/zero
    rm -f "$STATE.load.$$"
    echo "http=200" >&2;;
  *-w*example.com*)
    if [ -e "$STATE.row-status" ] && [ -z "$(cyc)" ]; then rm -f "$STATE.row-status"; echo Connected > "$STATE"; fi
    [ -z "$(cyc)" ] || echo "cycle-curl http m=$m" >> "$CALLS"
    if hanging; then sleep "$m"; exit 28; fi
    if slow && ! answers "${FAKE_SLOW_S:-3.5}" "$m"; then exit 28; fi
    if failing http; then printf '000'; exit 28; fi; printf '200\n';;
  *-w*) if [ "${FAKE_BURST_AT_THRESHOLD:-0}" = 1 ]; then
          n=0; while ! mkdir "$STATE.slot.$n" 2>/dev/null; do n=$((n + 1)); done
          case $n in 22|23|112|113) printf '000\n'; exit 0;; esac
        fi
        if [ -n "${FAKE_LOAD_BURST_FAILS:-}" ] && ls "$STATE".load.* >/dev/null 2>&1; then
          n=0; while ! mkdir "$STATE.lslot.$n" 2>/dev/null; do n=$((n + 1)); done
          a=${FAKE_LOAD_BURST_FAILS%%:*} b=${FAKE_LOAD_BURST_FAILS#*:}
          if { [ "$n" -lt 24 ] && [ "$n" -ge $((24 - a)) ]; } || [ "$n" -ge $((114 - b)) ]; then printf '000\n'; exit 0; fi
        fi
        if [ "${FAKE_BURST_FAIL_UNDER_LOAD:-0}" = 1 ] && ls "$STATE".load.* >/dev/null 2>&1; then printf '000\n'
        else printf '200\n'; fi;;
  *"-6 "*) printf '%s' "${FAKE_WHOAMI6_BODY-}";;
  *) [ -z "$(cyc)" ] || echo "cycle-curl whoami m=$m" >> "$CALLS"
     if hanging; then sleep "$m"; exit 28; fi
     if slow && ! answers "${FAKE_SLOW_S:-3.5}" "$m"; then exit 28; fi
     if failing whoami; then exit 7; fi
     if in_cycles "${FAKE_WHOAMI_OTHER_AT:-}"; then echo "ip=192.0.2.99"; exit 0; fi
     # v34: FAKE_WHOAMI_BODY, when set, is every other whoami's body.
     if [ -n "${FAKE_WHOAMI_BODY:-}" ]; then printf '%s\n' "$FAKE_WHOAMI_BODY"; exit 0; fi
     echo "ip=$RELAY_IP";;
esac
""",
    # UDP: under load with FAKE_LOAD_BLIP=1 the tunnel reads Connecting until
    # the next --filter-status.
    "nc": "#!/bin/sh" + EL_FAKE_PRELUDE + r"""
case " $* " in *" -u "*)
  w=$(bound_of '-w ' "$*")
  [ -z "$(cyc)" ] || echo "cycle-nc w=$w" >> "$CALLS"
  if hanging; then cat >/dev/null; sleep "$w"; exit 1; fi
  if failing udp; then cat >/dev/null; exit 1; fi
  if [ "${FAKE_LOAD_BLIP:-0}" = 1 ] && ls "$STATE".load.* >/dev/null 2>&1; then echo Connecting > "$STATE"; : > "$STATE.blip"; fi;;
esac
cat
""",
    # The first A query before the cycles (dns_a_fakeip) sets the tunnel to
    # FAKE_ROW_STATUS until http_by_name's curl.
    "dig": "#!/bin/sh" + EL_FAKE_PRELUDE + r"""
case "$*" in
  *TXT*) t=$(bound_of '+time=' "$*")
         [ -z "$(cyc)" ] || echo "cycle-dig time=$t" >> "$CALLS"
         if hanging; then sleep "$t"; echo ';; connection timed out; no servers could be reached'; exit 9; fi
         if slow && ! answers "${FAKE_SLOW_DNS_S:-2.5}" "$t"; then echo ';; connection timed out; no servers could be reached'; exit 9; fi
         if failing dns; then echo ';; connection timed out; no servers could be reached'; else echo '"v=fake"'; fi;;
  *AAAA*) echo 2001:db8:5::1;;
  *) if [ -n "${FAKE_ROW_STATUS:-}" ] && [ -z "$(cyc)" ] && [ ! -e "$STATE.row-status-done" ]; then
       : > "$STATE.row-status-done"; : > "$STATE.row-status"; echo "$FAKE_ROW_STATUS" > "$STATE"
     fi
     echo 198.18.0.9;;
esac
""",
    "probe_py": "#!/bin/sh" + EL_FAKE_PRELUDE + r"""
echo "probe $3 $4" >> "$CALLS"
case "$3" in
  tcp) [ -z "$(cyc)" ] || echo "cycle-probe tcp limit=$8" >> "$CALLS"
       if hanging; then sleep "$8"; echo "0/${8}000/timeout"; exit 1; fi
       if slow && ! answers "${FAKE_SLOW_S:-3.5}" "$8"; then echo "0/${8}000/timeout"; exit 1; fi
       if failing tcp; then echo 0/3000/timeout; exit 1; fi
       case "$4" in hc) echo 4/7/eof;; *) echo 4/7/full;; esac;;
  source6) echo fd00:ae61::1;;
  aaaa) echo 2001:db8:5::1;;
  scan64) exec "$SYSTEM_PY" "$@";;
  *) exit 2;;
esac
""",
    # The provider process: FAKE_PROVIDER_PID, another one from
    # FAKE_PID_CHANGE_AT, none from FAKE_PROVIDER_GONE_AT. It also ends the
    # tunnel at FAKE_DISCONNECT_AT, jumps the clock by MS at
    # FAKE_JUMP_AT=K:MS (the Mac asleep), and records both locks.
    "pgrep": "#!/bin/sh" + EL_FAKE_PRELUDE + r"""
if [ "$1" = -x ] && [ "$2" = aegis-ne-provider ]; then
  c=$(cyc)
  echo "pgrep cycle=${c:-none} codex_lock=$([ -e "$HOME/.aegis-local/locks/timing-peer" ] && echo 1 || echo 0) claude_lock=$([ -e "$HOME/.aegis-local/locks/timing-self" ] && echo 1 || echo 0)" >> "$CALLS"
  [ "${c:-x}" = 0 ] && echo "lock=$(cat "$HOME/.aegis-local/locks/timing-self" 2>/dev/null)" >> "$CALLS"
  if hanging; then sleep "$(printf '%s\n' "${FAKE_HANG_PGREP_S:-}" | tr ',' '\n' | sed -n "s/^$c://p" | head -1)"; fi
  if [ -n "${FAKE_DISCONNECT_AT:-}" ] && [ "${c:--1}" -ge "$FAKE_DISCONNECT_AT" ]; then echo Disconnected > "$STATE"; fi
  if [ -n "${FAKE_JUMP_AT:-}" ] && [ "${c:--1}" = "${FAKE_JUMP_AT%%:*}" ] && [ ! -e "$FAKE_CLOCK_OFFSET.jumped" ]; then
    : > "$FAKE_CLOCK_OFFSET.jumped"
    "$FAKE_SLEEP_BIN" "$(( ${FAKE_JUMP_AT#*:} / 1000 ))"
  fi
  if [ -n "${FAKE_PROVIDER_GONE_AT:-}" ] && [ "${c:--1}" -ge "$FAKE_PROVIDER_GONE_AT" ]; then exit 1; fi
  if [ -n "${FAKE_PID_CHANGE_AT:-}" ] && [ "${c:--1}" -ge "$FAKE_PID_CHANGE_AT" ]; then echo 4343; else echo "${FAKE_PROVIDER_PID:-4242}"; fi
  exit 0
fi
exec /usr/bin/pgrep "$@"
""",
    # RSS grows by FAKE_RSS_STEP KiB a cycle, and (v34, LOAD=1) by
    # FAKE_RSS_PER_CALL KiB at each sample; every other ps is the real one.
    "ps": "#!/bin/sh" + EL_FAKE_PRELUDE + r"""
case "$*" in
  *rss=*) if hanging; then exec /bin/sleep 100; fi
    c=$(cyc); [ "${c:--1}" -ge 0 ] || c=0
    k=$(cat "$STATE.rss-calls" 2>/dev/null || echo 0); echo $((k + 1)) > "$STATE.rss-calls"
    echo "  $(( ${FAKE_RSS_BASE:-50000} + c * ${FAKE_RSS_STEP:-0} + k * ${FAKE_RSS_PER_CALL:-0} ))   1.5"; exit 0;;
esac
exec /bin/ps "$@"
""",
    "df": "#!/bin/sh\necho 'Filesystem 1024-blocks Used Available Capacity Mounted on'\n"
          "echo \"/dev/fake 999999999 1 ${FAKE_DF_AVAIL_KIB:-41943040} 1% /\"\n",
    # /usr/bin/log: one heartbeat line per cycle so far (unless
    # FAKE_LOG_NO_HEARTBEAT=1), FAKE_LOG_AT=<K>:<code> <value>;... from cycle
    # K on (K = the planned count: after the last cycle), FAKE_LOG_LATE the
    # same but in cycle K only from its second read on (logged late),
    # FAKE_LOG_LATER from its third, FAKE_PROVIDER_LOG always; a read fails
    # in each cycle of FAKE_LOG_FAIL_AT. FAKE_LOG_FOREIGN=1 adds another
    # process's `aegis-ne` lines (a cargo test binary of this crate) to every
    # read. With FAKE_LOG_ALARM_LOAD=N the load's read prints the first N
    # lines of FAKE_PROVIDER_LOG and is cut off by its alarm (rc 142).
    "fake_log": "#!/bin/sh" + EL_FAKE_PRELUDE + r"""
c=$(cyc)
echo "log $1 cycle=${c:-none}" >> "$CALLS"
[ "$1" = show ] || exit 1
if [ "${FAKE_LOG_ALARM_LOAD:-0}" != 0 ] && [ -e "$OUT/filter-status-load-after.txt" ] && [ ! -e "$STATE.log-alarmed" ]; then
  : > "$STATE.log-alarmed"
  printf 'Timestamp               Ty Process[PID:TID]\n'
  printf '%b' "${FAKE_PROVIDER_LOG-}" | head -n "$FAKE_LOG_ALARM_LOAD"
  kill -ALRM $$
fi
if [ -n "$c" ]; then case ",${FAKE_LOG_FAIL_AT:-}," in *",$c,"*) exit 1;; esac; else c=100000; fi
r=$(cat "$FAKE_CLOCK_OFFSET.reads.$c" 2>/dev/null || echo 0); echo $((r + 1)) > "$FAKE_CLOCK_OFFSET.reads.$c"
if hanging; then if [ "$r" = 0 ]; then sleep "${FAKE_HANG_LOG_S:-0}"; else exec /bin/sleep 100; fi; fi
printf 'Timestamp               Ty Process[PID:TID]\n'
printf '%b' "${FAKE_PROVIDER_LOG-}"
if [ "${FAKE_LOG_FOREIGN:-0}" = 1 ]; then
  printf '2026-10-27 09:00:00.000 Df aegis_network_extension-0a1b2c3d4e5f6a7b[999:1] aegis-ne identity_renewal state:due attempt:0\n'
  printf '2026-10-27 09:00:00.001 Df aegis_network_extension-0a1b2c3d4e5f6a7b[999:1] aegis-ne session_lost made_up_code\n'
fi
awk -v c="$c" -v r="$r" -v plan="${FAKE_LOG_AT:-}" -v late="${FAKE_LOG_LATE:-}" -v later="${FAKE_LOG_LATER:-}" -v hb="${FAKE_LOG_NO_HEARTBEAT:-0}" 'BEGIN {
    for (j = 0; hb != 1 && j <= c && j <= 400; j++)
        printf "2026-10-27 06:%02d:%02d.000 Df aegis-ne-provider[4242:1] [dev.aegis.macos.PacketTunnel] aegis-ne reack_ok link_ms:%d\n", int(j / 60) % 60, j % 60, j
    n = split(plan, e, ";")
    for (x = 1; x <= n; x++) {
        i = index(e[x], ":"); if (!i) continue
        k = substr(e[x], 1, i - 1) + 0; if (k > c) continue
        printf "2026-10-27 07:%02d:%02d.%03d Df aegis-ne-provider[4242:1] [dev.aegis.macos.PacketTunnel] aegis-ne %s\n", int(k / 60) % 60, k % 60, x, substr(e[x], i + 1)
    }
    n = split(late, e, ";")
    for (x = 1; x <= n; x++) {
        i = index(e[x], ":"); if (!i) continue
        k = substr(e[x], 1, i - 1) + 0; if (k > c || (k == c && r == 0)) continue
        printf "2026-10-27 08:%02d:%02d.%03d Df aegis-ne-provider[4242:1] [dev.aegis.macos.PacketTunnel] aegis-ne %s\n", int(k / 60) % 60, k % 60, x, substr(e[x], i + 1)
    }
    n = split(later, e, ";")
    for (x = 1; x <= n; x++) {
        i = index(e[x], ":"); if (!i) continue
        k = substr(e[x], 1, i - 1) + 0; if (k > c || (k == c && r < 2)) continue
        printf "2026-10-27 09:%02d:%02d.%03d Df aegis-ne-provider[4242:1] [dev.aegis.macos.PacketTunnel] aegis-ne %s\n", int(k / 60) % 60, k % 60, x, substr(e[x], i + 1)
    }
}'
# A summary, as log show may print one.
echo "Log      - Default:          $r, Info:                0, Debug:             0, Error:          0, Fault:          0"
""",
    # The schedule's clock and sleep: virtual milliseconds (the real time
    # plus an offset that each sleep advances at once). A sleep after cycle
    # FAKE_DISCONNECT_IN_WAIT ends the tunnel; after cycle
    # FAKE_REASSERT_IN_WAIT the first sleep turns it Connecting (a reassert,
    # as scutil prints it) and the next one Connected again; the first
    # sleep after cycle K of FAKE_WAIT_JUMP_AT=K:MS also jumps the clock by
    # MS (the Mac asleep, or the window stalled, while it waited).
    "fake_clock": "#!/bin/sh\nexec /usr/bin/perl -MTime::HiRes=time -e 'my $o = 0; if (open(my $f, \"<\", $ENV{FAKE_CLOCK_OFFSET}))"
                  " { $o = <$f> + 0 } printf \"%d\\n\", time * 1000 + $o'\n",
    "fake_sleep": "#!/bin/sh" + EL_FAKE_PRELUDE + r"""
c=$(cyc)
echo "$1" >> "$FAKE_CLOCK_OFFSET.sleeps"
if [ -n "${FAKE_DISCONNECT_IN_WAIT:-}" ] && [ "$c" = "$FAKE_DISCONNECT_IN_WAIT" ]; then echo Disconnected > "$STATE"; fi
if [ -n "${FAKE_REASSERT_IN_WAIT:-}" ] && [ "$c" = "$FAKE_REASSERT_IN_WAIT" ]; then
  if [ ! -e "$STATE.reassert" ]; then : > "$STATE.reassert"; echo Connecting > "$STATE"
  elif [ ! -e "$STATE.reassert-done" ]; then : > "$STATE.reassert-done"; echo Connected > "$STATE"; fi
fi
j=0
if [ -n "${FAKE_WAIT_JUMP_AT:-}" ] && [ "$c" = "${FAKE_WAIT_JUMP_AT%%:*}" ] && [ ! -e "$FAKE_CLOCK_OFFSET.wait-jumped" ]; then
  : > "$FAKE_CLOCK_OFFSET.wait-jumped"; j=${FAKE_WAIT_JUMP_AT#*:}
fi
exec /usr/bin/perl -e 'my $p = $ENV{FAKE_CLOCK_OFFSET}; my $o = 0; if (open(my $f, "<", $p)) { $o = <$f> + 0; close $f }
open(my $g, ">", $p) or die; print $g int($o + $ARGV[0] * 1000 + $ARGV[1]), "\n"; close $g; select(undef, undef, undef, 0.002)' "$1" "$j"
""",
    "caffeinate": "#!/bin/sh\necho \"caffeinate $*\" >> \"$CALLS\"\nwhile kill -0 \"$3\" 2>/dev/null; do sleep 0.2; done\n",
})

# --filter-status counts up with every read (mode guarding while Connected;
# it ends FAKE_LOAD_BLIP's Connecting); --status and --cert-status as the
# v31 host prints them (--status hangs in a cycle of FAKE_HANG_AT).
EL_FAKE_HOST = r"""#!/bin/sh
case "$1" in
  --filter-status)
    if [ -e "$STATE.blip" ]; then rm -f "$STATE.blip"; echo Connected > "$STATE"; fi
    n=$(cat "$STATE.filter" 2>/dev/null || echo 0); echo $((n + 1)) > "$STATE.filter"
    mode=open; [ "$(head -1 "$STATE")" = Connected ] && mode=guarding
    echo "filter_result=ok exit_code=0 configured=true enabled=true filter_packets=true filter_sockets=false packet_bundle_id=match grade=firewall attached=true pid_match=true mode=$mode armed_token=none dropped=$((n * 5)) allowed=$((n * 100))"
    printf '{"schema":"aegis-ne-xpc-v1","verb":"filter-status","report":{"observability":{"ring":{"next":%d,"skipped":0,"torn":0,"entries":[]}}}}\n' $((n * ${FAKE_RING_STEP:-10}))
    exit "${FAKE_FILTER_EXIT:-0}";;
  --status)
    c=$(sed -n 's/^cycle=\([0-9]*\) .*/\1/p' "$OUT/endurance.progress" 2>/dev/null | head -1)
    case ",${FAKE_HANG_AT:-}," in *",${c:-x},"*) exec /bin/sleep 100;; esac
    echo '{"schema":"aegis-ne-xpc-v1","verb":"status","report":{"session_phase":"ready","session_refusal":null}}'
    [ -z "${FAKE_RENEWAL_LINE:-}" ] || echo "$FAKE_RENEWAL_LINE" >&2
    exit 0;;
  --cert-status)
    echo "host --cert-status" >> "$CALLS"
    if [ "${FAKE_CERT_REFUSED:-0}" = 1 ]; then echo "provider_refused no_epoch" >&2; exit 65; fi
    printf '{"schema":"aegis-ne-xpc-v1","verb":"cert-status","report":{"state":"valid","not_before":1,"not_after":%d,"renew_at":2,"attempts":0,"last_attempt_at":null,"next_attempt_at":null,"last_failure":null}}\n' \
      $(( $(date +%s) + ${FAKE_NOT_AFTER_IN:-172800} ))
    exit 0;;
  --list) echo "profile index=0 owner_generation=0A1B2C3D-0000-4000-8000-000000000001 scutil_service_id=1111AAAA-2222-3333-4444-555566667777 intent_valid=true on_demand_enabled=false";;
  --connect) echo "host $*" >> "$CALLS"; [ "${FAKE_NO_CONNECT:-0}" = 1 ] && exit 0
    echo Connected > "$STATE"; : > "$STATE.was-connected";;
  --emergency-stop) echo "host $*" >> "$CALLS"; echo Disconnected > "$STATE";;
esac
"""


def el_lines(*codes):
    """Lines of the provider process as the S24 reads keep them."""
    return "".join(f"2026-10-27 06:30:00.000 Df aegis-ne-provider[4242:1] [dev.aegis.macos.PacketTunnel] aegis-ne {c}\\n"
                   for c in codes)


def iso_in(seconds):
    return (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=seconds)).strftime(
        "%Y-%m-%dT%H:%M:%S+00:00")


class EnduranceLoadWorld:
    """A fake world for ENDURANCE=1 and LOAD=1 of harness/real-relay-window.sh:
    the leak-capture world's commands, a counting filter, a provider process
    behind pgrep and ps, a disk behind df, a provider log that follows the
    cycles and a virtual clock for the cycle schedule. Nothing here dials,
    captures or tunnels, and no test waits the real period."""

    def setup_world(self, handoff_extra=None, capture=False):
        temp = tempfile.TemporaryDirectory(prefix="aegis-s24-")
        self.addCleanup(temp.cleanup)
        root = pathlib.Path(temp.name)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        for name, body in EL_FAKE_COMMANDS.items():
            (bin_dir / name).write_text(body)
            (bin_dir / name).chmod(0o755)
        host = root / "AEGIS.app" / "Contents" / "MacOS" / "aegis-ne-host"
        host.parent.mkdir(parents=True)
        host.write_text(EL_FAKE_HOST)
        host.chmod(0o755)
        (root / "fake_tcpdump.py").write_text(WINDOW_FAKE_TCPDUMP)
        (root / "fake_sudo_parent.py").write_text(WINDOW_FAKE_SUDO_PARENT)
        pids = root / "fake.pids"
        pids.write_text("")
        self.addCleanup(RealRelayWindowLeakCaptureTests.kill_fakes, pids)
        (root / "home" / ".aegis-local" / "locks").mkdir(parents=True)
        handoff = root / "handoff.json"
        fields = {"relay": f"{RELAY_IP}:443", "echo_tcp": f"{RELAY_IP}:7", "echo_udp": f"{RELAY_IP}:7",
                  "whoami": f"http://{RELAY_IP}/ip", "expires_utc": iso_in(2 * 86400)}
        fields.update(handoff_extra or {})
        handoff.write_text(json.dumps({k: v for k, v in fields.items() if v is not None}))
        (root / "state").write_text("Disconnected\n")
        (root / "calls.log").write_text("")
        (root / "clock.offset").write_text("0\n")
        out = root / "out"
        env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(root / "home"), "APP": str(root / "AEGIS.app"),
               "HANDOFF": str(handoff), "OUT": str(out), "STATE": str(root / "state"), "CALLS": str(root / "calls.log"),
               "FAKE_TCPDUMP": str(root / "fake_tcpdump.py"), "RELAY_IP": RELAY_IP,
               "FAKE_SUDO_PARENT": str(root / "fake_sudo_parent.py"), "FAKE_PIDS": str(pids),
               "LEAK_CAPTURE": "1" if capture else "0", "PROBE_PY": str(bin_dir / "probe_py"), "SYSTEM_PY": SYSTEM_PY,
               "LOG_BIN": str(bin_dir / "fake_log"), "EL_CLOCK": str(bin_dir / "fake_clock"),
               "EL_SLEEP": str(bin_dir / "fake_sleep"), "EL_CAFFEINATE": str(bin_dir / "caffeinate"),
               "FAKE_CLOCK_OFFSET": str(root / "clock.offset"), "FAKE_SLEEP_BIN": str(bin_dir / "fake_sleep")}
        self.addCleanup(RealRelayWindowLeakCaptureTests.cancel_rollback, None, out)
        return root, env

    @staticmethod
    def rows_of(out):
        rows, names = {}, []
        if (out / "results.tsv").exists():
            for line in (out / "results.tsv").read_text().splitlines():
                name, verdict, detail, status, _start, _end = line.split("\t")
                rows[name] = (verdict, detail, status)
                names.append(name)
        return rows, names

    @staticmethod
    def cycles_of(out):
        lines = (out / "endurance.tsv").read_text().splitlines()
        head = lines[0].split("\t")
        return head, [dict(zip(head, line.split("\t"))) for line in lines[1:]]

    def run_window(self, handoff_extra=None, capture=False, codex_lock=False, **extra):
        root, env = self.setup_world(handoff_extra, capture)
        env.update(extra)
        if codex_lock:
            (root / "home" / ".aegis-local" / "locks" / "timing-peer").write_text("start=x purpose=test\n")
        result = subprocess.run(["/bin/bash", str(REAL_RELAY_WINDOW)], capture_output=True, text=True, env=env,
                                timeout=400)
        rows, names = self.rows_of(root / "out")
        return result, rows, names, (root / "calls.log").read_text().splitlines(), root

    def assert_refused_untouched(self, result, rows, calls, root, mode, reason, code=3):
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        if mode:
            self.assertIn(f"refused: {mode}: {reason}", result.stdout)
        else:
            self.assertIn(f"refused: {reason}", result.stdout)
        self.assertFalse([c for c in calls if c.startswith(("host --connect", "sudo", "networksetup", "pmset",
                                                            "tcpdump", "curl load"))], calls)
        self.assertFalse((root / "home" / ".aegis-local" / "locks" / "timing-self").exists())
        self.assertFalse((root / "out" / "rollback.log").exists())
        self.assertEqual(rows, {})

    def preflight(self, *setup, **env_extra):
        """el_preflight alone (endurance-load.sh with netloss.sh), against the
        same fakes: prints the refusal or the extra seconds and bounds."""
        root, env = self.setup_world()
        env.update(env_extra)
        (root / "out").mkdir()
        script = (f". '{NETLOSS_SH}'\n. '{ENDURANCE_LOAD_SH}'\n"
                  f"HOST_BIN='{root}/AEGIS.app/Contents/MacOS/aegis-ne-host' RESULT_FROM=x SID=x\n"
                  "NETLOSS=${NETLOSS:-0} SLEEP=${SLEEP:-0} IFSWITCH=${IFSWITCH:-0} POSITIVE_CONTROL=${POSITIVE_CONTROL:-0}\n"
                  "NEGATIVE_CONTROL=${NEGATIVE_CONTROL:-0} FILTER_RC=${FILTER_RC:-0} PROVIDER_LOG_BOUND_S=60\n"
                  "ROLLBACK_S_GIVEN=${ROLLBACK_S:-} ROLLBACK_S=${ROLLBACK_S:-180}\n" + "\n".join(setup) +
                  "\nel_preflight || { echo \"refused $EL_MODE: $EL_REFUSAL\"; exit 3; }\n"
                  "echo \"mode=$EL_MODE extra=$EL_EXTRA_S log_bound=$PROVIDER_LOG_BOUND_S planned=$EL_PLANNED\"\n"
                  "echo \"info=$EL_PREFLIGHT_INFO\"\n")
        out = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, env=env, timeout=60)
        return out.returncode, out.stdout, root


class RealRelayWindowEnduranceTests(EnduranceLoadWorld, unittest.TestCase):
    """ENDURANCE=1 (harness/endurance-load.sh, harness/endurance_review.py)
    of harness/real-relay-window.sh in the fake world, on a virtual clock."""

    def endurance(self, seconds, period, **extra):
        return self.run_window(ENDURANCE="1", ENDURANCE_S=str(seconds), ENDURANCE_PERIOD_S=str(period), **extra)

    def assert_clean_end(self, result, rows, root):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["disconnect_verified"][0], "pass", rows["disconnect_verified"])
        self.assertFalse((root / "home" / ".aegis-local" / "locks" / "timing-self").exists())
        self.assertIn("rollback_cancelled", (root / "out" / "rollback.log").read_text())

    def test_an_endurance_window_cycles_until_its_duration_and_every_summary_row_passes(self):
        result, rows, names, calls, root = self.endurance(600, 60)
        out = root / "out"
        self.assert_clean_end(result, rows, root)
        # The rollback grows by the run: 180 + 600 + 60 + 44 (the cycle's
        # bound) + 2 x 31 (the final read, and again after the wait for a
        # loss still pending) + 120.
        self.assertIn("ENDURANCE=1: duration_s=600 period_s=60 cycles=11 cycle_bound_s=44 log_bound_s=15 probe_bound_s=10 "
                      "rollback_s=1066 capture_bound_s=1126 window_bound_s=1266", result.stdout)
        pre = rows["endurance_preflight"]
        self.assertEqual(pre[0], "info")
        self.assertRegex(pre[1], r"^duration_s=600 period_s=60 cycles=11 cycle_bound_s=44 log_bound_s=15 probe_bound_s=10 "
                                 r"not_after_margin_s=1[0-9]{5} "
                                 r"cert_state=valid relay_expires_margin_s=1[0-9]{5} free_gib=40 clock=override "
                                 r"sleep=override$")
        self.assertEqual(rows["endurance_cycles"][:2], ("pass", "passed=11/11 pct=100.00% failed=0 missed=0 not_run=0 "
                                                                "threshold=99%"))
        self.assertEqual(rows["endurance_longest_gap"][0], "pass")
        self.assertTrue(rows["endurance_longest_gap"][1].startswith("longest_failing_run=0 cycles period_s=60 "))
        self.assertTrue(rows["endurance_longest_gap"][1].endswith(" awake=yes"), rows["endurance_longest_gap"])
        self.assertEqual(rows["endurance_connected_throughout"][0], "pass", rows["endurance_connected_throughout"])
        self.assertIn("statuses=Connected:", rows["endurance_connected_throughout"][1])
        self.assertEqual(rows["endurance_provider_stable"][:2],
                         ("pass", "pid=4242 readings=11 changes=0 none=0 multi=0"))
        # A run of 600 s leaves no period after its tenth minute: the growth
        # is the last cycle's against the first's.
        self.assertTrue(rows["endurance_rss_growth"][1].startswith("growth_kib=0 growth_mib=0.0 limit_kib=65536 "
                                                                   "baseline_cycle=0 "), rows["endurance_rss_growth"])
        self.assertIn(" end_cycle=10 ", rows["endurance_rss_growth"][1])
        self.assertEqual(rows["endurance_rss_growth"][0], "pass")
        self.assertEqual(rows["endurance_rebuilds"][:2], (
            "info", "session_lost=0 causes=none session_rebuilt=0 session_failed=0 rebuild_pending_cycles=0 unjudged=0 "
                    "unread_logs=0 final=ok"))
        self.assertEqual(rows["endurance_renewal"][:2], ("info", "status_lines=none:11 log_states=none phases=ready:11"))
        # The tests' virtual clock is not real time: the run's real span
        # passes nothing.
        self.assertEqual(rows["endurance_real_time"][0], "unavailable")
        self.assertRegex(rows["endurance_real_time"][1],
                         r"^real_span_s=[0-9.]+ duration_s=600 need_s=540 clock=override$")
        # Order: the preflight row before the connect, the summary after
        # the IPv6 rows and before the disconnect, in the review's order.
        self.assertLess(names.index("filter_preflight"), names.index("endurance_preflight"))
        self.assertLess(names.index("endurance_preflight"), names.index("connected"))
        self.assertLess(names.index("dns_aaaa_v6_anchor"), names.index("endurance_cycles"))
        self.assertEqual(names[names.index("endurance_cycles"):names.index("endurance_cycles") + len(ENDURANCE_ROWS)],
                         ENDURANCE_ROWS)
        self.assertLess(names.index("endurance_real_time"), names.index("disconnect_verified"))
        fields = row_fields(out)
        assert_rows_chain(self, fields)
        times = row_times(fields)
        for name in ENDURANCE_ROWS:
            self.assertEqual(times[name][0], times["endurance_cycles"][0], name)
        # One endurance.tsv row per cycle, the last at the duration.
        head, cycles = self.cycles_of(out)
        self.assertEqual(head, ENDURANCE_TSV_COLUMNS)
        self.assertEqual([c["slot_s"] for c in cycles], [str(60 * k) for k in range(11)])
        for c in cycles:
            self.assertEqual([c[k] for k in ("verdict", "whoami", "tcp_echo", "udp_echo", "dns_txt", "http")],
                             ["pass"] * 6, c)
            self.assertRegex(c["start"], ROW_UTC)
            self.assertRegex(c["end"], ROW_UTC)
            self.assertLessEqual(row_utc(c["start"]), row_utc(c["end"]))
            self.assertEqual((c["status_start"], c["status_end"], c["phase"], c["provider_pid"], c["rss_kib"]),
                             ("Connected", "Connected", "ready", "4242", "50000"))
            self.assertEqual(c["probe_detail"], "tcp=4/7/eof http=200")
            self.assertEqual((c["log_read"], c["rebuild_pending"], c["codex_lock"]), ("ok", "0", "0"))
            # Each started within its period on the schedule's clock.
            self.assertGreaterEqual(int(c["run_ms"]), 1000 * int(c["slot_s"]))
            self.assertLess(int(c["run_ms"]), 1000 * int(c["slot_s"]) + 60000)
        # At 60 s every probe has the baseline row's own bound.
        for bound in ("cycle-curl whoami m=5", "cycle-curl http m=8", "cycle-probe tcp limit=10", "cycle-nc w=3",
                      "cycle-dig time=3"):
            self.assertEqual(calls.count(bound), 11, bound)
        text = (out / "endurance.tsv").read_text() + (out / "results.tsv").read_text().split("endurance_preflight")[1]
        self.assertNotIn(RELAY_IP, (out / "endurance.tsv").read_text())
        self.assertNotIn(PHYS_V6, text)
        # The Mac kept awake for the window's life, the lock held throughout.
        self.assertTrue([c for c in calls if re.match(r"^caffeinate -i -w [0-9]+$", c)], calls)
        held = [c for c in calls if c.startswith("pgrep cycle=")]
        self.assertEqual(len(held), 12)   # the provider at the start and every cycle
        self.assertTrue(all(c.endswith(" codex_lock=0 claude_lock=1") for c in held), held)
        lock = next(c for c in calls if c.startswith("lock="))
        self.assertRegex(lock, r"^lock=start=[0-9TZ]+ purpose=b06-real-relay-window mode=ENDURANCE "
                               r"ends_by=[0-9-]+T[0-9:]+Z$")
        # The cycles waited on the schedule's clock, never longer than a poll.
        sleeps = [float(s) for s in pathlib.Path(str(root / "clock.offset") + ".sleeps").read_text().split()]
        self.assertTrue(sleeps and max(sleeps) <= 5.0, sleeps)
        self.assertGreater(sum(sleeps), 500)
        # One provider-log read before each cycle's probes and one at the
        # end: nothing pending, no second read.
        reads = [c for c in calls if re.match(r"^log show cycle=[0-9]+$", c)]
        self.assertEqual(reads, [f"log show cycle={k}" for k in range(12)])

    def test_one_failing_cycle_in_a_hundred_stays_within_99_percent(self):
        result, rows, names, calls, root = self.endurance(1485, 15, FAKE_FAIL_AT="whoami:50")
        self.assert_clean_end(result, rows, root)
        self.assertEqual(rows["endurance_cycles"][:2], (
            "pass", "passed=99/100 pct=99.00% failed=1 missed=0 not_run=0 threshold=99% failing=50:whoami"))
        self.assertEqual(rows["endurance_longest_gap"][0], "pass")
        self.assertTrue(rows["endurance_longest_gap"][1].startswith("longest_failing_run=1 "))
        head, cycles = self.cycles_of(root / "out")
        self.assertEqual(len(cycles), 100)
        self.assertEqual((cycles[50]["verdict"], cycles[50]["whoami"], cycles[50]["tcp_echo"]), ("fail", "fail", "pass"))
        self.assertEqual([c["cycle"] for c in cycles if c["verdict"] != "pass"], ["50"])

    def test_one_failing_cycle_in_forty_one_is_below_99_percent(self):
        result, rows, names, calls, root = self.endurance(600, 15, FAKE_FAIL_AT="tcp:10")
        self.assert_clean_end(result, rows, root)
        self.assertEqual(rows["endurance_cycles"][:2], (
            "fail", "passed=40/41 pct=97.56% failed=1 missed=0 not_run=0 threshold=99% failing=10:tcp_echo"))
        self.assertEqual(rows["endurance_longest_gap"][0], "pass")
        head, cycles = self.cycles_of(root / "out")
        self.assertEqual((cycles[10]["tcp_echo"], cycles[10]["probe_detail"]), ("fail", "tcp=0/3000/timeout http=200"))

    def test_two_failing_cycles_in_a_row_fail_the_longest_gap(self):
        result, rows, names, calls, root = self.endurance(600, 60, FAKE_FAIL_AT="udp:4,dns:5,http:8")
        self.assert_clean_end(result, rows, root)
        self.assertEqual(rows["endurance_longest_gap"][0], "fail")
        self.assertRegex(rows["endurance_longest_gap"][1],
                         r"^longest_failing_run=2 cycles period_s=60 max_start_gap_s=[0-9.]+ max_pass_gap_s=18[0-9][.][0-9] "
                         r"pass_gap_limit_s=125 awake=yes from_cycle=4 pass_gap_after_cycle=3$")
        self.assertEqual(rows["endurance_cycles"][:2], (
            "fail", "passed=8/11 pct=72.73% failed=3 missed=0 not_run=0 threshold=99% "
                    "failing=4:udp_echo,5:dns_txt,8:http"))

    def test_slots_missed_while_the_clock_jumped_fail_like_failing_cycles(self):
        # The clock jumps 200 s during cycle 3 (the Mac asleep): the slots at
        # 240 s and 300 s are missed, cycle 6 runs late within its period.
        result, rows, names, calls, root = self.endurance(600, 60, FAKE_JUMP_AT="3:200000")
        self.assert_clean_end(result, rows, root)
        head, cycles = self.cycles_of(root / "out")
        self.assertEqual([c["verdict"] for c in cycles], ["pass"] * 4 + ["missed"] * 2 + ["pass"] * 5)
        self.assertEqual(rows["endurance_cycles"][:2], (
            "fail", "passed=9/11 pct=81.82% failed=0 missed=2 not_run=0 threshold=99%"))
        self.assertEqual(rows["endurance_longest_gap"][0], "fail")
        self.assertIn("longest_failing_run=2 ", rows["endurance_longest_gap"][1])
        self.assertTrue(rows["endurance_longest_gap"][1].endswith(" from_cycle=4 pass_gap_after_cycle=3"),
                        rows["endurance_longest_gap"])
        # A missed slot records no probe and no provider sample.
        self.assertEqual(rows["endurance_provider_stable"][:2], ("pass", "pid=4242 readings=9 changes=0 none=0 multi=0"))

    def test_a_provider_restart_or_crash_fails_provider_stable(self):
        result, rows, names, calls, root = self.endurance(600, 60, FAKE_PID_CHANGE_AT="5")
        self.assert_clean_end(result, rows, root)
        self.assertEqual(rows["endurance_provider_stable"][:2], (
            "fail", "pid=4242 readings=11 changes=6 none=0 multi=0 other_pids=4343"))
        self.assertEqual(rows["endurance_cycles"][0], "pass")
        # Its RSS from cycle 0 to cycle 10 spans two processes: no growth shown.
        self.assertEqual(rows["endurance_rss_growth"][0], "fail")
        self.assertIn(" baseline_cycle=0 ", rows["endurance_rss_growth"][1])
        self.assertTrue(rows["endurance_rss_growth"][1].endswith(" reason=pid_changed"), rows["endurance_rss_growth"])
        result, rows, names, calls, root = self.endurance(600, 60, FAKE_PROVIDER_GONE_AT="7")
        self.assert_clean_end(result, rows, root)
        self.assertEqual(rows["endurance_provider_stable"][:2], (
            "fail", "pid=4242 readings=11 changes=4 none=4 multi=0"))
        # Without the end reading no growth can be shown.
        self.assertEqual(rows["endurance_rss_growth"][:2], (
            "fail", "no_rss_reading baseline_cycle=0 baseline_kib=50000 end_cycle=10 end_kib=none limit_kib=65536"))

    def test_rss_growth_above_64_mib_fails_and_at_64_mib_passes(self):
        # Cycles at 0, 300, 600, 900 and 1200 s: the baseline is the cycle at
        # 600 s (10 minutes in), the end the last.
        result, rows, names, calls, root = self.endurance(1200, 300, FAKE_RSS_STEP="32768")
        self.assert_clean_end(result, rows, root)
        self.assertEqual(rows["endurance_rss_growth"][:2], (
            "pass", "growth_kib=65536 growth_mib=64.0 limit_kib=65536 baseline_cycle=2 baseline_kib=115536 end_cycle=4 "
                    "end_kib=181072 max_kib=181072 cpu_max=1.5"))
        result, rows, names, calls, root = self.endurance(1200, 300, FAKE_RSS_STEP="32769")
        self.assert_clean_end(result, rows, root)
        self.assertEqual(rows["endurance_rss_growth"][0], "fail")
        self.assertTrue(rows["endurance_rss_growth"][1].startswith("growth_kib=65538 "), rows["endurance_rss_growth"])
        self.assertEqual(rows["endurance_cycles"][0], "pass")

    def test_a_tunnel_disconnected_mid_run_stops_the_cycles_and_fails(self):
        result, rows, names, calls, root = self.endurance(600, 60, FAKE_DISCONNECT_AT="4")
        self.assert_clean_end(result, rows, root)
        head, cycles = self.cycles_of(root / "out")
        self.assertEqual([c["cycle"] for c in cycles], ["0", "1", "2", "3", "4"])
        self.assertEqual((cycles[4]["status_start"], cycles[4]["status_end"]), ("Connected", "Disconnected"))
        # No probe after the stop: cycle 4's are the last.
        self.assertEqual(max(int(c.split("=")[1].split()[0]) for c in calls if c.startswith("pgrep cycle=")
                             and not c.startswith("pgrep cycle=none")), 4)
        self.assertEqual(rows["endurance_connected_throughout"][0], "fail")
        self.assertIn("first_bad=Disconnected@4 stopped=Disconnected@cycle=4", rows["endurance_connected_throughout"][1])
        self.assertEqual(rows["endurance_cycles"][:2], (
            "fail", "passed=5/11 pct=45.45% failed=0 missed=0 not_run=6 threshold=99% stopped=Disconnected@cycle=4"))
        self.assertEqual(rows["endurance_longest_gap"][0], "fail")
        # The tunnel ends while the window waits for cycle 3: it never runs.
        result, rows, names, calls, root = self.endurance(600, 60, FAKE_DISCONNECT_IN_WAIT="2")
        self.assert_clean_end(result, rows, root)
        head, cycles = self.cycles_of(root / "out")
        self.assertEqual([c["cycle"] for c in cycles], ["0", "1", "2"])
        self.assertEqual(cycles[2]["status_end"], "Connected")
        # The first sample that is not Connected ends the wait at once.
        statuses = (root / "out" / "endurance-statuses.txt").read_text().splitlines()
        self.assertEqual([s for s in statuses if s.startswith("3 ")], ["3 Disconnected"])
        self.assertIn("not_run=8 threshold=99% stopped=Disconnected@cycle=3", rows["endurance_cycles"][1])
        self.assertEqual(rows["endurance_connected_throughout"][0], "fail")

    def test_a_window_that_never_connects_passes_nothing(self):
        result, rows, names, calls, root = self.endurance(600, 60, FAKE_NO_CONNECT="1")
        self.assertEqual(rows["connected"][0], "0")
        for name in ENDURANCE_ROWS + ["endurance_window"]:
            self.assertEqual(rows[name][:2], ("unavailable", "not_connected"), name)
        self.assertFalse((root / "out" / "endurance.tsv").exists())
        self.assertEqual(rows["disconnect_verified"][0], "pass")

    def test_the_stream_windows_budget_across_the_run_is_an_info_row(self):
        # v34 review (critic B4): after the disconnect, endurance_window from
        # the cycles' own provider-log reads; it never passes or fails.
        result, rows, names, calls, root = self.endurance(
            600, 60, FAKE_LOG_AT="2:pool_window grown:2 max_kib:512 budget_kib:768-7168 denied:1;"
                                "6:pool_window grown:0 max_kib:128 budget_kib:0-7168 denied:3")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["endurance_window"][:2], (
            "info", "lines=2 grown_max=2 grown_last=0 max_kib_max=512 budget_kib_max=768/7168 "
                    "budget_kib_last=0/7168 denied_last=3"))
        self.assertLess(names.index("disconnect_verified"), names.index("endurance_window"))
        self.assertEqual(rows["endurance_cycles"][0], "pass")
        # A build without the line: unavailable, the window unchanged.
        result, rows, names, calls, root = self.endurance(600, 60)
        self.assertEqual(rows["endurance_window"][:2], ("unavailable", "no_pool_window_lines"))
        self.assertEqual(rows["endurance_cycles"][0], "pass")

    def test_a_loss_rebuilt_before_the_next_probes_is_info_and_the_renewal_states_are_recorded(self):
        result, rows, names, calls, root = self.endurance(
            600, 300, FAKE_LOG_AT="1:session_lost capture_lease_expired;1:reasserting on;1:session_rebuilt attempt:1;"
                                  "1:reasserting off;2:identity_renewal state:deferred:guarded attempt:0 remaining_s:1000",
            FAKE_RENEWAL_LINE="renewal deferred:guarded (due since 2026-10-27T10:00:00Z; runs at the next connect), "
                              "expires at 2026-10-28T11:43:50Z, 0 attempts")
        self.assert_clean_end(result, rows, root)
        self.assertEqual(rows["endurance_rebuilds"][:2], (
            "info", "session_lost=1 causes=capture_lease_expired:1 session_rebuilt=1 session_failed=0 "
                    "rebuild_pending_cycles=0 unjudged=0 unread_logs=0 final=ok"))
        self.assertEqual(rows["endurance_renewal"][:2], (
            "info", "status_lines=deferred:guarded:3 log_states=deferred:guarded:1 phases=ready:3"))
        head, cycles = self.cycles_of(root / "out")
        self.assertEqual([(c["session_lost"], c["lost_causes"], c["session_rebuilt"], c["renewal_states"],
                           c["rebuild_pending"], c["renewal"]) for c in cycles], [
            ("0", "none", "0", "none", "0", "deferred:guarded"),
            ("1", "capture_lease_expired:1", "1", "none", "0", "deferred:guarded"),
            ("0", "none", "0", "deferred:guarded:1", "0", "deferred:guarded")])
        # Every provider line once, though the reads overlap, and nothing else.
        log = (root / "out" / "endurance-provider.log").read_text().splitlines()
        self.assertEqual(len(log), len(set(log)))
        self.assertTrue(log and all(" aegis-ne " in line for line in log), log)
        self.assertEqual(sum(1 for line in log if " session_lost " in line), 1)

    def test_a_rebuild_after_the_next_cycles_probes_fails(self):
        result, rows, names, calls, root = self.endurance(
            600, 300, FAKE_LOG_AT="1:session_lost capture_lease_expired;2:session_rebuilt attempt:1")
        self.assert_clean_end(result, rows, root)
        self.assertEqual(rows["endurance_rebuilds"][0], "fail")
        self.assertTrue(rows["endurance_rebuilds"][1].endswith(" final=ok reason=not_rebuilt_before_cycle=1"),
                        rows["endurance_rebuilds"])
        head, cycles = self.cycles_of(root / "out")
        self.assertEqual([c["rebuild_pending"] for c in cycles], ["0", "1", "0"])
        # A loss after the last cycle's probes, not rebuilt by the planned
        # disconnect.
        result, rows, names, calls, root = self.endurance(600, 300, FAKE_LOG_AT="3:session_lost capture_lease_expired")
        self.assertEqual(rows["endurance_rebuilds"][0], "fail")
        self.assertTrue(rows["endurance_rebuilds"][1].endswith(" final=pending reason=final=pending"),
                        rows["endurance_rebuilds"])
        # Read after the settle, again at the next slot and after its settle.
        self.assertEqual(calls.count("log show cycle=3"), 4)

    def test_a_rebuild_logged_just_before_the_read_is_seen_after_a_settle(self):
        # The rebuild is in the log only from the cycle's second read on: the
        # pending loss is read again after a second and is not counted.
        result, rows, names, calls, root = self.endurance(
            600, 300, FAKE_LOG_AT="1:session_lost capture_lease_expired", FAKE_LOG_LATE="1:session_rebuilt attempt:1")
        self.assert_clean_end(result, rows, root)
        head, cycles = self.cycles_of(root / "out")
        self.assertEqual([(c["session_lost"], c["session_rebuilt"], c["rebuild_pending"]) for c in cycles],
                         [("0", "0", "0"), ("1", "1", "0"), ("0", "0", "0")])
        self.assertEqual(rows["endurance_rebuilds"][0], "info", rows["endurance_rebuilds"])
        self.assertEqual(calls.count("log show cycle=1"), 2)
        self.assertEqual(calls.count("log show cycle=2"), 1)

    def test_a_loss_outside_the_recoverable_set_or_a_failed_session_fails(self):
        result, rows, names, calls, root = self.endurance(
            600, 300, FAKE_LOG_AT="1:session_lost made_up_code;1:session_rebuilt attempt:1")
        self.assert_clean_end(result, rows, root)
        self.assertEqual(rows["endurance_rebuilds"][0], "fail")
        self.assertIn("causes=made_up_code:1 ", rows["endurance_rebuilds"][1])
        self.assertTrue(rows["endurance_rebuilds"][1].endswith(" reason=outside_recoverable=made_up_code"),
                        rows["endurance_rebuilds"])
        result, rows, names, calls, root = self.endurance(600, 300, FAKE_LOG_AT="1:session_failed session_peer_refused")
        self.assertEqual(rows["endurance_rebuilds"][0], "fail")
        self.assertTrue(rows["endurance_rebuilds"][1].endswith(" reason=session_failed=session_peer_refused:1"),
                        rows["endurance_rebuilds"])

    def test_a_loss_seen_after_an_unread_log_is_unjudged_and_fails(self):
        result, rows, names, calls, root = self.endurance(
            600, 300, FAKE_LOG_FAIL_AT="1", FAKE_LOG_AT="1:session_lost capture_lease_expired;1:session_rebuilt attempt:1")
        self.assert_clean_end(result, rows, root)
        head, cycles = self.cycles_of(root / "out")
        self.assertEqual([(c["log_read"], c["rebuild_pending"]) for c in cycles],
                         [("ok", "0"), ("failed", "-"), ("ok", "unknown")])
        self.assertEqual(rows["endurance_rebuilds"][0], "fail")
        self.assertIn(" unjudged=1 unread_logs=1 final=ok reason=unjudged_cycle=2", rows["endurance_rebuilds"][1])
        # An unread log without a loss judges nothing and fails nothing.
        result, rows, names, calls, root = self.endurance(600, 300, FAKE_LOG_FAIL_AT="1")
        self.assertEqual(rows["endurance_rebuilds"][0], "info", rows["endurance_rebuilds"])

    # -------------------------------------------------------- S24 review

    def test_a_reassert_reads_connecting_and_the_cycles_go_on(self):
        # scutil prints Connecting while the provider reasserts and never
        # Reasserting: a reassert between cycles 3 and 4 (its loss rebuilt)
        # and one on a baseline row are part of a run that stays connected.
        result, rows, names, calls, root = self.endurance(
            600, 60, FAKE_REASSERT_IN_WAIT="3", FAKE_ROW_STATUS="Connecting",
            FAKE_LOG_AT="4:session_lost capture_lease_expired;4:reasserting on;4:session_rebuilt attempt:5;"
                        "4:reasserting off")
        self.assert_clean_end(result, rows, root)
        self.assertEqual(rows["dns_a_fakeip"][::2], ("pass", "Connecting"))
        head, cycles = self.cycles_of(root / "out")
        self.assertEqual([c["verdict"] for c in cycles], ["pass"] * 11)
        statuses = (root / "out" / "endurance-statuses.txt").read_text().splitlines()
        self.assertEqual([s for s in statuses if not s.endswith(" Connected")], ["4 Connecting"])
        self.assertEqual(rows["endurance_cycles"][0], "pass")
        self.assertEqual(rows["endurance_longest_gap"][0], "pass")
        self.assertEqual(rows["endurance_connected_throughout"][0], "pass", rows["endurance_connected_throughout"])
        self.assertRegex(rows["endurance_connected_throughout"][1], r"^statuses=Connected:[0-9]+,Connecting:2 samples=[0-9]+$")
        self.assertEqual(rows["endurance_rebuilds"][:2], (
            "info", "session_lost=1 causes=capture_lease_expired:1 session_rebuilt=1 session_failed=0 "
                    "rebuild_pending_cycles=0 unjudged=0 unread_logs=0 final=ok"))
        # Any other status fails it, also one seen only in a baseline row's
        # status column.
        result, rows, names, calls, root = self.endurance(600, 60, FAKE_ROW_STATUS="Invalid")
        self.assert_clean_end(result, rows, root)
        self.assertEqual(rows["dns_a_fakeip"][2], "Invalid")
        self.assertEqual(rows["endurance_cycles"][0], "pass")
        self.assertEqual(rows["endurance_connected_throughout"][0], "fail")
        self.assertTrue(rows["endurance_connected_throughout"][1].endswith(" first_bad=Invalid@row:dns_a_fakeip"),
                        rows["endurance_connected_throughout"])

    def test_a_sleep_or_stall_while_waiting_misses_its_slot_and_fails_the_gap(self):
        # The clock jumps 130 s in the first sleep of the wait for slot 4
        # (240 s): the wake at about 315 s is past that slot's period, so it
        # is missed and cycle 5 runs at once. Nothing was probed between
        # cycle 3 (180 s) and cycle 5 (about 315 s), more than two periods.
        result, rows, names, calls, root = self.endurance(600, 60, FAKE_WAIT_JUMP_AT="3:130000")
        self.assert_clean_end(result, rows, root)
        head, cycles = self.cycles_of(root / "out")
        self.assertEqual([c["verdict"] for c in cycles], ["pass"] * 4 + ["missed"] + ["pass"] * 6)
        self.assertGreaterEqual(int(cycles[5]["run_ms"]) - int(cycles[3]["run_ms"]), 135000)
        self.assertEqual(rows["endurance_cycles"][:2], (
            "fail", "passed=10/11 pct=90.91% failed=0 missed=1 not_run=0 threshold=99%"))
        self.assertEqual(rows["endurance_longest_gap"][0], "fail")
        self.assertRegex(rows["endurance_longest_gap"][1],
                         r"^longest_failing_run=1 cycles period_s=60 max_start_gap_s=[0-9.]+ max_pass_gap_s=13[5-9][.][0-9] "
                         r"pass_gap_limit_s=125 awake=yes pass_gap_after_cycle=3$")
        # 180 s asleep while waiting misses two slots in a row.
        result, rows, names, calls, root = self.endurance(600, 60, FAKE_WAIT_JUMP_AT="3:180000")
        self.assert_clean_end(result, rows, root)
        head, cycles = self.cycles_of(root / "out")
        self.assertEqual([c["verdict"] for c in cycles], ["pass"] * 4 + ["missed"] * 2 + ["pass"] * 5)
        self.assertEqual(rows["endurance_longest_gap"][0], "fail")
        self.assertIn("longest_failing_run=2 ", rows["endurance_longest_gap"][1])

    def test_the_rss_growth_of_a_run_too_short_for_a_late_baseline_counts_from_its_first_cycle(self):
        # 600 s: the cycle at 600 s is the last one, which no baseline may
        # be. RSS grows 20 MiB a cycle, 200 MiB in all.
        result, rows, names, calls, root = self.endurance(600, 60, FAKE_RSS_STEP="20480")
        self.assert_clean_end(result, rows, root)
        self.assertEqual(rows["endurance_rss_growth"][:2], (
            "fail", "growth_kib=204800 growth_mib=200.0 limit_kib=65536 baseline_cycle=0 baseline_kib=50000 "
                    "end_cycle=10 end_kib=254800 max_kib=254800 cpu_max=1.5"))
        # 650 s: the cycle at 600 s is less than a period before the last.
        result, rows, names, calls, root = self.endurance(650, 60, FAKE_RSS_STEP="20480")
        self.assertEqual(rows["endurance_rss_growth"][0], "fail")
        self.assertIn(" baseline_cycle=0 baseline_kib=50000 end_cycle=11 ", rows["endurance_rss_growth"][1])
        # 660 s: it is a period before the last, and the baseline.
        result, rows, names, calls, root = self.endurance(660, 60, FAKE_RSS_STEP="20480")
        self.assertEqual(rows["endurance_rss_growth"][:2], (
            "pass", "growth_kib=20480 growth_mib=20.0 limit_kib=65536 baseline_cycle=10 baseline_kib=254800 "
                    "end_cycle=11 end_kib=275280 max_kib=275280 cpu_max=1.5"))
        # Cycles that ended after the first one: one reading, no growth shown.
        result, rows, names, calls, root = self.endurance(600, 60, FAKE_DISCONNECT_IN_WAIT="0")
        self.assertEqual(rows["endurance_rss_growth"][:2], (
            "fail", "no_growth_window baseline_cycle=0 end_cycle=0 readings=1 limit_kib=65536"))

    def test_every_command_of_a_cycle_at_its_bound_ends_within_the_period(self):
        # At 15 s the group is cut to 4 s (pgrep and ps 2 s each). In cycles
        # 2 and 5 every probe runs to its bound, --status and ps hang until
        # their alarm, pgrep answers after 4.7 s (cycle 2) or 1.7 s (cycle
        # 5), and a loss looks pending, so the provider log is read twice:
        # the first read takes 2.2 s, the second hangs until its alarm.
        result, rows, names, calls, root = self.endurance(
            600, 15, FAKE_HANG_AT="2,5", FAKE_HANG_PGREP_S="2:4.7,5:1.7", FAKE_HANG_LOG_S="2.2",
            FAKE_LOG_AT="2:session_lost capture_lease_expired;3:session_rebuilt attempt:1;"
                        "5:session_lost capture_lease_expired;6:session_rebuilt attempt:1")
        self.assert_clean_end(result, rows, root)
        self.assertIn(" cycle_bound_s=14 log_bound_s=3 probe_bound_s=4 ", rows["endurance_preflight"][1])
        head, cycles = self.cycles_of(root / "out")
        self.assertEqual(len(cycles), 41)
        self.assertEqual([c["cycle"] for c in cycles if c["verdict"] != "pass"], ["2", "5"])
        for k, pid in ((2, "none"), (5, "4242")):
            c = cycles[k]
            span = (row_utc(c["end"]) - row_utc(c["start"])).total_seconds()
            # Below the cycle's bound (14 s) and so the period; every
            # command did run to its bound.
            self.assertLess(span, 14.5, (k, span))
            self.assertGreater(span, 9.5, (k, span))
            self.assertEqual([c[p] for p in ("whoami", "tcp_echo", "udp_echo", "dns_txt", "http")], ["fail"] * 5)
            self.assertEqual((c["rebuild_pending"], c["provider_pid"], c["rss_kib"]), ("1", pid, "none"))
            self.assertTrue(c["phase"].startswith("unreadable:rc="), c["phase"])
            # The next cycle started on its own slot.
            self.assertLess(int(cycles[k + 1]["run_ms"]) - 15000 * (k + 1), 1000)
        for bound in ("cycle-curl whoami m=4", "cycle-curl http m=4", "cycle-probe tcp limit=4", "cycle-nc w=3",
                      "cycle-dig time=3"):
            self.assertEqual(calls.count(bound), 41, bound)

    def test_the_provider_sample_keeps_pgrep_and_ps_each_within_its_bound(self):
        # At 15 s pgrep and ps get 2 s each: a pgrep or a ps that hangs is
        # cut there, so the sample stays within twice that (the group's).
        with tempfile.TemporaryDirectory(prefix="aegis-s24-ps-") as temp:
            bin_dir = pathlib.Path(temp)
            for name, body in (("pgrep", 'if [ "${HANG:-}" = pgrep ]; then exec /bin/sleep 100; fi\necho 4242\n'),
                               ("ps", 'if [ "${HANG:-}" = ps ]; then exec /bin/sleep 100; fi\necho "  51200   1.5"\n')):
                (bin_dir / name).write_text("#!/bin/sh\n" + body)
                (bin_dir / name).chmod(0o755)
            script = (f". '{NETLOSS_SH}'\n. '{ENDURANCE_LOAD_SH}'\nel_cycle_bounds 15\n"
                      "echo \"ps_s=$EL_PS_S group_s=$EL_GROUP_S\"\nel_provider_sample\n")
            for hang, sample in (("", "4242 51200 1.5"), ("ps", "4242 none none"), ("pgrep", "none none none")):
                with self.subTest(hang=hang):
                    t0 = time.monotonic()
                    out = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, timeout=60,
                                         env={"PATH": f"{bin_dir}:/usr/bin:/bin", "HANG": hang})
                    took = time.monotonic() - t0
                    self.assertEqual(out.stdout.splitlines(), ["ps_s=2 group_s=4", sample], out.stderr)
                    self.assertLess(took, 3.2, took)   # one 2 s bound, never 5 s

    def test_probes_that_answer_after_three_seconds_pass_within_the_baseline_bounds(self):
        # A cold TCP echo, whoami and HTTP of 3.5 s and a TXT answer of
        # 2.5 s, as healthy installed windows saw them, in two cycles in a
        # row.
        result, rows, names, calls, root = self.endurance(600, 60, FAKE_SLOW_AT="2,3")
        self.assert_clean_end(result, rows, root)
        head, cycles = self.cycles_of(root / "out")
        self.assertEqual([c["verdict"] for c in cycles], ["pass"] * 11)
        self.assertEqual((rows["endurance_cycles"][0], rows["endurance_longest_gap"][0]), ("pass", "pass"))
        self.assertTrue(cycles[2]["probe_detail"].startswith("tcp=4/7/eof "), cycles[2])

    def test_a_loss_after_the_last_probes_rebuilt_before_the_next_slot_is_info(self):
        # The final read finds the loss pending, and so does its re-read
        # after the settle; the read at the next slot (900 s) finds the
        # rebuild, as a later cycle's read would have.
        result, rows, names, calls, root = self.endurance(
            600, 300, FAKE_LOG_AT="3:session_lost capture_lease_expired", FAKE_LOG_LATER="3:session_rebuilt attempt:2")
        self.assert_clean_end(result, rows, root)
        self.assertEqual(rows["endurance_rebuilds"][:2], (
            "info", "session_lost=1 causes=capture_lease_expired:1 session_rebuilt=1 session_failed=0 "
                    "rebuild_pending_cycles=0 unjudged=0 unread_logs=0 final=ok"))
        self.assertEqual(calls.count("log show cycle=3"), 3)
        # The wait sampled the tunnel and reached the next slot.
        statuses = (root / "out" / "endurance-statuses.txt").read_text().splitlines()
        self.assertGreater(statuses.count("final Connected"), 1)
        sleeps = [float(s) for s in pathlib.Path(str(root / "clock.offset") + ".sleeps").read_text().split()]
        self.assertGreater(sum(sleeps), 850)

    def test_other_processes_aegis_ne_lines_are_left_out(self):
        # This crate's cargo test binary logs `aegis-ne` lines of its own (a
        # renewal state, a loss of a code no provider has) during the run.
        result, rows, names, calls, root = self.endurance(600, 300, FAKE_LOG_FOREIGN="1")
        self.assert_clean_end(result, rows, root)
        self.assertEqual(rows["endurance_rebuilds"][:2], (
            "info", "session_lost=0 causes=none session_rebuilt=0 session_failed=0 rebuild_pending_cycles=0 "
                    "unjudged=0 unread_logs=0 final=ok"))
        self.assertEqual(rows["endurance_renewal"][:2], ("info", "status_lines=none:3 log_states=none phases=ready:3"))
        log = (root / "out" / "endurance-provider.log").read_text()
        self.assertIn(" aegis-ne-provider[4242:1] ", log)
        self.assertNotIn("aegis_network_extension-", log)
        head, cycles = self.cycles_of(root / "out")
        self.assertEqual({c["renewal_states"] for c in cycles}, {"none"})
        # Both S24 reads also ask log show for the provider process only.
        text = ENDURANCE_LOAD_SH.read_text()
        self.assertIn("EL_LOG_PREDICATE=\"process == \\\"$EL_PROVIDER_EXE\\\" AND eventMessage BEGINSWITH \\\"aegis-ne\\\"\"",
                      text)
        self.assertEqual(text.count('--predicate "$EL_LOG_PREDICATE"'), 2)

    def test_a_whoami_that_names_another_address_fails_its_cycle(self):
        result, rows, names, calls, root = self.endurance(600, 60, FAKE_WHOAMI_OTHER_AT="5")
        self.assert_clean_end(result, rows, root)
        head, cycles = self.cycles_of(root / "out")
        self.assertEqual([(c["cycle"], c["whoami"]) for c in cycles if c["verdict"] != "pass"], [("5", "fail")])
        self.assertTrue(rows["endurance_cycles"][1].endswith(" failing=5:whoami"), rows["endurance_cycles"])
        self.assertNotIn("192.0.2.99", (root / "out" / "endurance.tsv").read_text())

    def test_a_provider_never_found_fails_provider_stable(self):
        result, rows, names, calls, root = self.endurance(600, 60, FAKE_PROVIDER_GONE_AT="-1")
        self.assert_clean_end(result, rows, root)
        self.assertEqual(rows["endurance_provider_stable"][:2], (
            "fail", "pid=none readings=11 changes=0 none=11 multi=0 first_reading=none"))

    # ------------------------------------------------------------ refusals

    def test_endurance_refuses_beside_any_other_mode_before_anything_runs(self):
        for name in ("LEAK_CAPTURE", "NETLOSS", "SLEEP", "IFSWITCH", "LOAD", "POSITIVE_CONTROL", "NEGATIVE_CONTROL"):
            with self.subTest(name=name):
                result, rows, names, calls, root = self.endurance(600, 60, **{name: "1"})
                reason = (f"not with {name}=1: one disruption or capture per window, and hours of capture would "
                          "threaten the disk floor" if name == "LEAK_CAPTURE"
                          else f"not with {name}=1: one disruption, capture or load per window")
                self.assert_refused_untouched(result, rows, calls, root, "ENDURANCE=1", reason + "; nothing connected")
                self.assertEqual([c for c in calls if c.startswith("host --cert-status")], [])

    def test_endurance_bounds_refuse(self):
        for seconds, period, reason in ((599, 60, "ENDURANCE_S=599 is outside 600..86400"),
                                        (86401, 60, "ENDURANCE_S=86401 is outside 600..86400"),
                                        ("2h", 60, "ENDURANCE_S=2h is outside 600..86400"),
                                        (7200, 14, "ENDURANCE_PERIOD_S=14 is outside 15..600"),
                                        (7200, 601, "ENDURANCE_PERIOD_S=601 is outside 15..600")):
            with self.subTest(seconds=seconds, period=period):
                result, rows, names, calls, root = self.endurance(seconds, period)
                self.assert_refused_untouched(result, rows, calls, root, "ENDURANCE=1", reason)

    def test_a_certificate_that_expires_before_the_run_ends_refuses(self):
        # not_after 1700 s after the planned end: inside the 30 min margin.
        result, rows, names, calls, root = self.endurance(600, 60, FAKE_NOT_AFTER_IN=str(600 + 1700))
        self.assert_refused_untouched(result, rows, calls, root, "ENDURANCE=1", "the device certificate expires at ")
        self.assertRegex(result.stdout, r"\(not_after, state valid\), before the run's end \+ 30 min \([0-9-]+T[0-9:]+Z\): "
                                        r"a session past its due point defers renewal until reconnect; nothing connected")
        result, rows, names, calls, root = self.endurance(600, 60, FAKE_CERT_REFUSED="1")
        self.assert_refused_untouched(result, rows, calls, root, "ENDURANCE=1",
                                      "the device certificate's not_after is unreadable (host --cert-status: "
                                      "provider_refused no_epoch); a provider that has not run a session since it "
                                      "started answers no_epoch: run one ordinary window first; nothing connected")

    def test_a_relay_handoff_that_expires_before_the_run_ends_refuses(self):
        for value, reason in ((iso_in(600 + 800), "the relay handoff expires at "),
                              (None, "the relay handoff's expires_utc is absent or unreadable"),
                              ("tomorrow", "the relay handoff's expires_utc is absent or unreadable"),
                              ("2030-01-01T00:00:00", "the relay handoff's expires_utc is absent or unreadable")):
            with self.subTest(value=value):
                result, rows, names, calls, root = self.endurance(600, 60, handoff_extra={"expires_utc": value})
                self.assert_refused_untouched(result, rows, calls, root, "ENDURANCE=1", reason)
                if value and value.endswith("+00:00"):
                    self.assertRegex(result.stdout, r"\(expires_utc\), before the run's end \+ 15 min "
                                                    r"\([0-9-]+T[0-9:]+Z\); nothing connected")

    def test_free_space_below_the_floor_refuses(self):
        result, rows, names, calls, root = self.endurance(600, 60, FAKE_DF_AVAIL_KIB=str(31 * 1048576 - 1))
        self.assert_refused_untouched(result, rows, calls, root, "ENDURANCE=1",
                                      "30 GiB free on the volume holding OUT, below the 31 GiB floor; nothing connected")
        rc, out, root = self.preflight(ENDURANCE="1", ENDURANCE_S="600", FAKE_DF_AVAIL_KIB=str(31 * 1048576))
        self.assertEqual(rc, 0, out)

    def test_a_given_rollback_shorter_than_the_run_or_the_codex_lock_refuses(self):
        result, rows, names, calls, root = self.endurance(600, 60, ROLLBACK_S="1065")
        self.assert_refused_untouched(result, rows, calls, root, "ENDURANCE=1",
                                      "ROLLBACK_S=1065 is shorter than this window needs (1066 s): the rollback would "
                                      "stop the tunnel mid-run; nothing connected")
        rc, out, root = self.preflight(ENDURANCE="1", ENDURANCE_S="600", ROLLBACK_S="1066")
        self.assertEqual(rc, 0, out)
        result, rows, names, calls, root = self.endurance(600, 60, codex_lock=True)
        self.assert_refused_untouched(result, rows, calls, root, "", "timing-peer lock", code=4)

    def test_the_bounds_scale_with_the_run(self):
        rc, out, root = self.preflight(ENDURANCE="1")
        self.assertEqual(rc, 0, out)
        # The defaults: 7200 s every 60 s, 121 cycles (7200 + 60 + 44 + 2 x 31 + 120).
        self.assertIn("mode=ENDURANCE=1 extra=7486 log_bound=300 planned=121\n", out)
        rc, out, root = self.preflight(ENDURANCE="1", ENDURANCE_S="86400", ENDURANCE_PERIOD_S="600")
        self.assertEqual(rc, 0, out)
        self.assertIn("mode=ENDURANCE=1 extra=87316 log_bound=2940 planned=145\n", out)
        self.assertIn(" cycle_bound_s=74 log_bound_s=30 probe_bound_s=10 ", out)
        rc, out, root = self.preflight(ENDURANCE="1", ENDURANCE_S="650", ENDURANCE_PERIOD_S="60")
        self.assertIn(" planned=12\n", out)   # 0, 60, ... 600 and 650
        # A cycle's bound covers every member of its group (the ps sample is
        # pgrep, then ps) and stays below every period it may run at.
        script = (f". '{NETLOSS_SH}'\n. '{ENDURANCE_LOAD_SH}'\nfor p in $(seq 15 600); do el_cycle_bounds \"$p\"\n"
                  "[ \"$EL_CYCLE_BOUND_S\" -lt \"$p\" ] || echo \"bad $p $EL_CYCLE_BOUND_S\"\n"
                  "for b in $EL_TCP_S $EL_WHOAMI_S $EL_HTTP_S $EL_DNS_S $EL_UDP_S $EL_STATUS_S $((2 * EL_PS_S)); do\n"
                  "[ \"$b\" -le \"$EL_GROUP_S\" ] || echo \"bad group $p $b\"; done\n"
                  "[ \"$EL_CYCLE_BOUND_S\" = $((2 * EL_LOG_S + 1 + EL_GROUP_S + 3)) ] || echo \"bad sum $p\"; done\n"
                  "for p in 15 20 21 60 600; do el_cycle_bounds \"$p\"\n"
                  "echo \"$p:$EL_LOG_S:$EL_CYCLE_BOUND_S tcp=$EL_TCP_S whoami=$EL_WHOAMI_S http=$EL_HTTP_S dns=$EL_DNS_S \"\\\n"
                  "\"udp=$EL_UDP_S status=$EL_STATUS_S ps=$EL_PS_S group=$EL_GROUP_S\"; done\n")
        out = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, timeout=60).stdout
        self.assertEqual(out.splitlines(), [
            "15:3:14 tcp=4 whoami=4 http=4 dns=3 udp=3 status=4 ps=2 group=4",
            "20:3:19 tcp=9 whoami=5 http=8 dns=3 udp=3 status=4 ps=4 group=9",
            "21:3:20 tcp=10 whoami=5 http=8 dns=3 udp=3 status=4 ps=5 group=10",
            "60:15:44 tcp=10 whoami=5 http=8 dns=3 udp=3 status=4 ps=5 group=10",
            "600:30:74 tcp=10 whoami=5 http=8 dns=3 udp=3 status=4 ps=5 group=10"])
        # At full length they are the baseline rows' own bounds (v34: the
        # whoami body is read up to 4096 bytes and masked before its cut;
        # its verdict reads the first 80, its bound is still 5 s).
        text = REAL_RELAY_WINDOW.read_text()
        for line in ("PROBE_LIMIT_S=${PROBE_LIMIT_S:-10}\n", 'w=$(curl -s -m 5 "$WHOAMI" 2>&1 | head -c 4096)',
                     "h=$(curl -s -m 8 -o /dev/null -w '%{http_code}' http://example.com/ 2>&1)",
                     "x=$(dig +short +time=3 +tries=1 @198.19.255.2 example.com TXT 2>&1 | head -1)",
                     'u=$(printf pong | nc -u -w 3 "${ECHO_UDP%:*}" "${ECHO_UDP#*:}" 2>&1 | head -c 20)'):
            self.assertEqual(text.count(line), 1, line)

    def test_the_recoverable_codes_and_the_ring_are_the_providers(self):
        table = re.findall(r'^\s*\("([a-z_]+)", (Recoverable|Terminal)\),', SESSION_REBUILD_RS.read_text(), re.M)
        self.assertGreater(len(table), 30)
        script = f". '{NETLOSS_SH}'\n. '{ENDURANCE_LOAD_SH}'\necho $EL_RECOVERABLE\necho \"$EL_RING_SLOTS\"\n"
        out = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, timeout=30).stdout.splitlines()
        self.assertEqual(out[0].split(), [code for code, kind in table if kind == "Recoverable"])
        self.assertEqual(int(out[1]), int(re.search(r"^pub const RING_SLOTS: usize = ([0-9]+);$",
                                                    LEAK_GUARD_RS.read_text(), re.M).group(1)))
        self.assertIn("EL_BASE_ROLLBACK_S=180\n", ENDURANCE_LOAD_SH.read_text())
        self.assertIn("ROLLBACK_S=${ROLLBACK_S:-180}\n", REAL_RELAY_WINDOW.read_text())

    def test_the_review_alone_reads_a_short_or_empty_record(self):
        with tempfile.TemporaryDirectory(prefix="aegis-s24-review-") as temp:
            root = pathlib.Path(temp)
            (root / "e.tsv").write_text("\t".join(ENDURANCE_TSV_COLUMNS) + "\n")
            for name in ("results.tsv", "statuses.txt", "log.txt"):
                (root / name).write_text("")
            out = subprocess.run([SYSTEM_PY, "-I", str(ENDURANCE_REVIEW), "--tsv", str(root / "e.tsv"), "--results",
                                  str(root / "results.tsv"), "--statuses", str(root / "statuses.txt"), "--log",
                                  str(root / "log.txt"), "--planned", "11", "--period", "60", "--pid0", "none",
                                  "--final", "ok", "--recoverable", "capture_lease_expired", "--duration", "600"],
                                 capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        rows = [line.split("\t") for line in out.stdout.splitlines()]
        self.assertEqual([r[0] for r in rows], ENDURANCE_ROWS)
        # Nothing ran: every criterion fails, the two info rows stay info
        # (rebuilds fails without a provider log line), and a schedule
        # whose clock is not named the system's shows no real time.
        self.assertEqual([r[1] for r in rows], ["fail", "fail", "fail", "fail", "fail", "fail", "info", "unavailable"])
        self.assertTrue(rows[5][2].endswith("reason=no_provider_log_lines"), rows[5])


class RealRelayWindowLoadTests(EnduranceLoadWorld, unittest.TestCase):
    """LOAD=1 (harness/endurance-load.sh) of harness/real-relay-window.sh in
    the fake world: the downloads are a fake curl's zeros."""

    def load(self, **extra):
        env = {"LOAD": "1", "LOAD_URL": LOAD_URL_FAKE, "LOAD_STREAMS": "4", "LOAD_BYTES": "4194304",
               "LOAD_BOUND_S": "10", "FAKE_PROVIDER_LOG": el_lines("flow_open ok ms:le100")}
        env.update(extra)
        return self.run_window(**env)

    def test_a_load_window_downloads_every_stream_and_repeats_the_checks_under_it(self):
        result, rows, names, calls, root = self.load()
        out = root / "out"
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("LOAD=1: streams=4 bytes=4194304 per_stream=1048576 bound_s=10 url_host=load.example url=given "
                      "url_bytes=1048576 rollback_s=310 capture_bound_s=370 window_bound_s=490", result.stdout)
        self.assertEqual(rows["load_preflight"][:2], (
            "info", "streams=4 bytes=4194304 per_stream=1048576 bound_s=10 url_host=load.example url=given "
                    "url_bytes=1048576 capture=0 free_gib=40"))
        for name in ("flow_burst_24", "flow_burst_90", "load_flow_burst_24", "load_flow_burst_90"):
            self.assertEqual(rows[name][0], "pass", (name, rows[name]))
        self.assertTrue(rows["load_flow_burst_24"][1].startswith("24/24 "))
        self.assertTrue(rows["load_flow_burst_90"][1].startswith("90/90 "))
        self.assertEqual(rows["load_tcp_echo_v4"][:2], ("pass", "4/7/eof"))
        self.assertEqual(rows["load_udp_echo_v4"][:2], ("pass", "pong"))
        self.assertEqual(rows["load_download"][0], "pass", rows["load_download"])
        self.assertRegex(rows["load_download"][1], r"^ok=4/4 bytes=4194304/4194304 per_stream=1048576 "
                                                   r"elapsed_max=[0-9.]+s bound=10s http=200,200,200,200 "
                                                   r"target_status=2xx$")
        # v34: each stream's status line and a few headers (no other), no
        # body for a 2xx, and no unmasked capture left behind.
        for i in range(1, 5):
            self.assertEqual((out / f"load-target.{i}.head").read_text(),
                             "HTTP/2 200\ncontent-type: application/x-xz\ncontent-length: 140064536\nserver: fake\n")
            self.assertTrue((out / f"load-stream.{i}").read_text().rstrip().endswith(" http=200 status=200"))
        self.assertFalse(list(out.glob("load-target.*.body")) + list(out.glob("load-target.*.raw"))
                         + list(out.glob("load-target.*.first")))
        self.assertEqual(rows["load_provider_rss"][:2], (
            "info", "pid=4242 rss_kib_before=50000 rss_kib_max=50000 growth_kib=0 samples=6"))
        # The review's rows are info or unavailable, never a verdict.
        for name in LOAD_REVIEW_ROWS:
            self.assertIn(rows[name][0], ("info", "unavailable"), (name, rows[name]))
            self.assertLess(names.index("disconnect_verified"), names.index(name))
        self.assertEqual(rows["load_outbound_drops"][0], "unavailable")
        self.assertEqual(rows["load_placement"][:2], ("unavailable", "no_flow_bulk_lines"))
        self.assertTrue(rows["load_window"][1].startswith("no_pool_window_lines"), rows["load_window"])
        self.assertRegex(rows["load_latency"][1], r"^burst24_s=[0-9.]+->[0-9.]+ burst90_s=[0-9.]+->[0-9.]+ "
                                                  r"tcp_echo_ms=7->7 hs_p50_ms_max=na->na hs_p90_ms_max=na->na rtt=none$")
        self.assertEqual(rows["load_throughput"][0], "info")
        self.assertRegex(rows["load_throughput"][1], r"^total_mbit_s=[0-9.]+ per_stream_mbit_s=[0-9.]+(,[0-9.]+){3} "
                                                     r"bytes=4194304 span_s=[0-9.]+$")
        self.assertEqual(rows["load_concurrent"][:2], (
            "pass", "running_at_end: burst24=4 burst90=4 tcp=4 udp=4 streams=4"))
        self.assertEqual(rows["load_connected_throughout"][0], "pass", rows["load_connected_throughout"])
        self.assertTrue(rows["load_connected_throughout"][1].startswith("session_lost=0 statuses=Connected:"))
        self.assertEqual(rows["load_filter_counters"][:2], (
            "info", "exit=0/0 allowed_delta=100 dropped_delta=5 mode=guarding/guarding ring_next_delta=10 "
                    "ring_overflow=0 ring_skipped_delta=0"))
        self.assertEqual(rows["disconnect_verified"][0], "pass")
        self.assertEqual(len([c for c in calls if c == "curl load m=10"]), 4)
        # Order: after the baseline rows and the IPv6 rows, before the
        # disconnect; the existing burst rows are unchanged.
        load = [n for n in names if n.startswith("load_") and n != "load_preflight"]
        self.assertEqual(load, LOAD_ROWS)
        self.assertLess(names.index("flow_burst_90"), names.index("load_flow_burst_24"))
        self.assertLess(names.index("dns_aaaa_v6_anchor"), names.index("load_flow_burst_24"))
        self.assertLess(names.index("load_filter_counters"), names.index("disconnect_verified"))
        fields = row_fields(out)
        assert_rows_chain(self, fields)
        times = row_times(fields)
        for name in ("load_download", "load_throughput", "load_concurrent", "load_connected_throughout",
                     "load_filter_counters", "load_provider_rss"):
            self.assertEqual(times[name][0], times["load_flow_burst_24"][0], name)
        self.assertFalse(list(out.glob("load-stream.*.err")))
        self.assertNotIn(RELAY_IP, "".join(rows[n][1] for n in LOAD_ROWS + ["load_preflight"]))
        # The window's own filter reads are unchanged around the load's.
        self.assertTrue(rows["filter_counters_after"][1].startswith("exit=0 filter_result=ok "))

    def test_a_short_download_fails_and_the_ring_overflow_is_counted(self):
        result, rows, names, calls, root = self.load(FAKE_LOAD_SERVE="1000", FAKE_RING_STEP="100")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["load_download"][0], "fail")
        self.assertIn("ok=0/4 bytes=4000/4194304 ", rows["load_download"][1])
        self.assertRegex(rows["load_download"][1], r" short=1:1000/[0-9.]+s:rc=[0-9]+,2:1000/")
        self.assertEqual(rows["load_filter_counters"][1].split(" ring_next_delta=")[1],
                         "100 ring_overflow=36 ring_skipped_delta=0")

    def test_a_download_that_outlasts_its_bound_fails(self):
        result, rows, names, calls, root = self.load(FAKE_LOAD_DELAY_S="15")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["load_download"][0], "fail")
        self.assertIn("ok=0/4 bytes=0/4194304 ", rows["load_download"][1])
        self.assertIn("http=000,000,000,000", rows["load_download"][1])
        # Every byte, but after the bound (a transfer its bound did not stop).
        result, rows, names, calls, root = self.load(FAKE_LOAD_DELAY_S="12", FAKE_LOAD_IGNORE_M="1")
        self.assertEqual(rows["load_download"][0], "fail")
        self.assertIn("ok=0/4 bytes=4194304/4194304 ", rows["load_download"][1])
        self.assertRegex(rows["load_download"][1], r" short=1:1048576/1[2-9][.][0-9]s:rc=")

    def test_a_burst_failing_under_load_fails_its_load_row_only(self):
        result, rows, names, calls, root = self.load(FAKE_BURST_FAIL_UNDER_LOAD="1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["flow_burst_24"][0], "pass")
        self.assertEqual(rows["flow_burst_90"][0], "pass")
        self.assertEqual(rows["load_flow_burst_24"][0], "fail")
        self.assertTrue(rows["load_flow_burst_24"][1].startswith("0/24 "))
        self.assertEqual(rows["load_flow_burst_90"][0], "fail")
        self.assertEqual(rows["load_download"][0], "pass")

    def test_a_session_lost_during_the_load_fails_load_connected_throughout(self):
        result, rows, names, calls, root = self.load(
            FAKE_PROVIDER_LOG=el_lines("session_lost capture_lease_expired", "session_rebuilt attempt:1"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["load_connected_throughout"][0], "fail")
        self.assertTrue(rows["load_connected_throughout"][1].startswith(
            "session_lost=1 causes=capture_lease_expired statuses=Connected:"), rows["load_connected_throughout"])
        # Without any provider line nothing is shown either way.
        result, rows, names, calls, root = self.load(FAKE_PROVIDER_LOG="", FAKE_LOG_NO_HEARTBEAT="1")
        self.assertEqual(rows["load_connected_throughout"][0], "unavailable")

    def test_downloads_that_end_before_the_checks_fail_load_concurrent(self):
        result, rows, names, calls, root = self.load(FAKE_LOAD_DELAY_S="0")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["load_download"][0], "pass")
        self.assertEqual(rows["load_concurrent"][:2], (
            "fail", "running_at_end: burst24=0 burst90=0 tcp=0 udp=0 streams=4"))

    def test_load_with_a_capture_covers_the_load_and_reviews_it(self):
        result, rows, names, calls, root = self.load(capture=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # The capture's bound covers the rollback, which covers the load.
        self.assertIn("rollback_s=310 capture_bound_s=370", result.stdout)
        self.assertIn(" bound=370s", rows["capture_started"][1])
        self.assertEqual(rows["leak_proof"][0], "pass", rows["leak_proof"])
        self.assertEqual(rows["no_mac_sent_leak_physical"][0], "pass", rows["no_mac_sent_leak_physical"])
        self.assertEqual(rows["load_download"][0], "pass")
        self.assertIn(" capture=1 ", rows["load_preflight"][1])
        self.assertLess(names.index("capture_started"), names.index("load_preflight"))

    # -------------------------------------------------------- S24 review

    def test_the_default_url_is_the_kernel_tarball_and_serves_each_streams_cap(self):
        # v34: one stream of 64 MiB from the default URL, the immutable
        # kernel tarball (its 140064536 bytes pinned); the fake serves twice
        # the cap of a URL that names no bytes=.
        result, rows, names, calls, root = self.run_window(
            LOAD="1", LOAD_STREAMS="1", LOAD_BYTES="67108864", LOAD_BOUND_S="10",
            FAKE_PROVIDER_LOG=el_lines("flow_open ok ms:le100"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["load_preflight"][:2], (
            "info", "streams=1 bytes=67108864 per_stream=67108864 bound_s=10 url_host=cdn.kernel.org url=default "
                    "url_bytes=140064536 capture=0 free_gib=40"))
        self.assertEqual(calls.count("curl load url=https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.tar.xz"), 1)
        self.assertEqual(calls.count("curl load bytes=none"), 1)
        self.assertEqual(rows["load_download"][0], "pass", rows["load_download"])
        self.assertTrue(rows["load_download"][1].startswith("ok=1/1 bytes=67108864/67108864 "), rows["load_download"])
        # The gate's defaults are unchanged: 4 streams of 50 MiB in 180 s.
        rc, out, root = self.preflight(LOAD="1")
        self.assertEqual(rc, 0, out)
        self.assertIn("info=streams=4 bytes=209715200 per_stream=52428800 bound_s=180 url_host=cdn.kernel.org "
                      "url=default url_bytes=140064536 ", out)
        # The whole file as one stream's cap passes; a byte more is refused.
        rc, out, root = self.preflight(LOAD="1", LOAD_STREAMS="1", LOAD_BYTES="140064536")
        self.assertEqual(rc, 0, out)
        rc, out, root = self.preflight(LOAD="1", LOAD_STREAMS="1", LOAD_BYTES="140064537")
        self.assertEqual((rc, out.strip()), (3, "refused LOAD=1: each stream's cap of 140064537 (LOAD_BYTES / LOAD_STREAMS) "
                                                "is more than the default LOAD_URL serves (140064536 bytes): lower "
                                                "LOAD_BYTES or raise LOAD_STREAMS, or give a LOAD_URL that serves the cap"))
        result, rows, names, calls, root = self.run_window(LOAD="1", LOAD_STREAMS="2", LOAD_BYTES="285212672")
        self.assert_refused_untouched(result, rows, calls, root, "LOAD=1",
                                      "each stream's cap of 142606336 (LOAD_BYTES / LOAD_STREAMS) is more than the "
                                      "default LOAD_URL serves (140064536 bytes): lower LOAD_BYTES or raise "
                                      "LOAD_STREAMS, or give a LOAD_URL that serves the cap; nothing connected")
        # The speed-test host runs only as a given LOAD_URL, checked by its
        # bytes= as before.
        rc, out, root = self.preflight(LOAD="1", LOAD_URL="https://speed.cloudflare.com/__down?bytes=52428800")
        self.assertEqual(rc, 0, out)
        self.assertIn(" url_host=speed.cloudflare.com url=given url_bytes=52428800 ", out)
        self.assertNotIn("speed.cloudflare.com", ENDURANCE_LOAD_SH.read_text().split("el_load_preflight() {")[0]
                         .split("EL_LOAD_URL_DEFAULT=")[1].splitlines()[0])

    def test_a_url_that_serves_less_than_each_streams_cap_refuses(self):
        # 2 MiB a stream, from a URL that serves 1 MiB.
        result, rows, names, calls, root = self.load(LOAD_BYTES="8388608")
        self.assert_refused_untouched(result, rows, calls, root, "LOAD=1",
                                      "LOAD_URL serves bytes=1048576 per request, fewer than each stream's cap of "
                                      "2097152 (LOAD_BYTES / LOAD_STREAMS): raise its bytes= or lower LOAD_BYTES; "
                                      "nothing connected")
        for url in ("http://load.example/down?x=1&bytes=0002097152&y=2", "http://load.example/down?bytes=99999999999999999999"):
            rc, out, root = self.preflight(LOAD="1", LOAD_URL=url, LOAD_BYTES="8388608")
            self.assertEqual(rc, 0, out)
        # A URL that names no size is the operator's to choose.
        rc, out, root = self.preflight(LOAD="1", LOAD_URL="http://load.example/blob")
        self.assertEqual(rc, 0, out)
        self.assertIn(" url=given url_bytes=undeclared capture=0 ", out)
        # v34: or it declares one with LOAD_URL_BYTES, checked the same way.
        result, rows, names, calls, root = self.load(LOAD_URL="http://load.example/blob", LOAD_URL_BYTES="1048575")
        self.assert_refused_untouched(result, rows, calls, root, "LOAD=1",
                                      "LOAD_URL serves LOAD_URL_BYTES=1048575 bytes, fewer than each stream's cap of "
                                      "1048576 (LOAD_BYTES / LOAD_STREAMS): lower LOAD_BYTES or give a LOAD_URL that "
                                      "serves the cap; nothing connected")
        rc, out, root = self.preflight(LOAD="1", LOAD_URL="http://load.example/blob", LOAD_URL_BYTES="01048576",
                                       LOAD_BYTES="4194304")
        self.assertEqual(rc, 0, out)
        self.assertIn(" url=given url_bytes=1048576 capture=0 ", out)
        # With a bytes= as well, either one below the cap refuses, and the
        # smaller one is shown.
        rc, out, root = self.preflight(LOAD="1", LOAD_URL="http://load.example/down?bytes=2097152",
                                       LOAD_URL_BYTES="1048575", LOAD_BYTES="4194304")
        self.assertEqual(rc, 3, out)
        self.assertIn("LOAD_URL_BYTES=1048575 bytes, fewer than each stream's cap of 1048576", out)
        rc, out, root = self.preflight(LOAD="1", LOAD_URL="http://load.example/down?bytes=2097152",
                                       LOAD_URL_BYTES="1048576", LOAD_BYTES="4194304")
        self.assertEqual(rc, 0, out)
        self.assertIn(" url_bytes=1048576 capture=0 ", out)
        for extra, reason in (({"LOAD_URL_BYTES": "1048576"},
                               "LOAD_URL_BYTES declares the size of a given LOAD_URL; the default LOAD_URL's is "
                               "pinned (140064536 bytes)"),
                              ({"LOAD_URL": "http://load.example/blob", "LOAD_URL_BYTES": "1MiB"},
                               "LOAD_URL_BYTES=1MiB is outside 1..1099511627776"),
                              ({"LOAD_URL": "http://load.example/blob", "LOAD_URL_BYTES": "0"},
                               "LOAD_URL_BYTES=0 is outside 1..1099511627776")):
            with self.subTest(extra=extra):
                rc, out, root = self.preflight(LOAD="1", **extra)
                self.assertEqual((rc, out.strip()), (3, "refused LOAD=1: " + reason))

    def test_a_load_log_read_cut_off_at_its_bound_shows_nothing_either_way(self):
        lines = el_lines("flow_open ok ms:le100", "session_lost capture_lease_expired", "session_rebuilt attempt:1")
        # The read is cut off by its alarm after its first line: the loss
        # logged later in the load is never read.
        result, rows, names, calls, root = self.load(FAKE_PROVIDER_LOG=lines, FAKE_LOG_ALARM_LOAD="1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((root / "out" / "load-provider.log").read_text().count(" aegis-ne "), 1)
        self.assertEqual(rows["load_connected_throughout"][0], "unavailable", rows["load_connected_throughout"])
        self.assertTrue(rows["load_connected_throughout"][1].startswith("provider_log_read=failed:rc=142 statuses=Connected:"),
                        rows["load_connected_throughout"])
        # A loss among the lines read before the cut fails it all the same.
        result, rows, names, calls, root = self.load(FAKE_PROVIDER_LOG=lines, FAKE_LOG_ALARM_LOAD="2")
        self.assertEqual(rows["load_connected_throughout"][0], "fail")
        self.assertTrue(rows["load_connected_throughout"][1].startswith("session_lost=1 causes=capture_lease_expired "),
                        rows["load_connected_throughout"])

    def test_load_bursts_at_their_thresholds_pass_and_one_below_fails(self):
        result, rows, names, calls, root = self.load(FAKE_LOAD_BURST_FAILS="2:2")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((rows["load_flow_burst_24"][0], rows["load_flow_burst_24"][1].split()[0]), ("pass", "22/24"))
        self.assertEqual((rows["load_flow_burst_90"][0], rows["load_flow_burst_90"][1].split()[0]), ("pass", "88/90"))
        result, rows, names, calls, root = self.load(FAKE_LOAD_BURST_FAILS="3:3")
        self.assertEqual((rows["load_flow_burst_24"][0], rows["load_flow_burst_24"][1].split()[0]), ("fail", "21/24"))
        self.assertEqual((rows["load_flow_burst_90"][0], rows["load_flow_burst_90"][1].split()[0]), ("fail", "87/90"))
        self.assertEqual((rows["flow_burst_24"][1].split()[0], rows["flow_burst_90"][1].split()[0]), ("24/24", "90/90"))

    def test_a_status_other_than_connected_during_the_load_fails_without_a_loss(self):
        result, rows, names, calls, root = self.load(FAKE_LOAD_BLIP="1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["load_udp_echo_v4"][2], "Connecting")
        self.assertEqual(rows["load_connected_throughout"][0], "fail")
        self.assertRegex(rows["load_connected_throughout"][1],
                         r"^session_lost=0 causes=none statuses=Connected:[0-9]+,Connecting:[0-9]+$")
        self.assertEqual(rows["disconnect_verified"][0], "pass")

    def test_other_processes_aegis_ne_lines_are_left_out_of_the_load(self):
        result, rows, names, calls, root = self.load(FAKE_LOG_FOREIGN="1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["load_connected_throughout"][0], "pass", rows["load_connected_throughout"])
        log = (root / "out" / "load-provider.log").read_text()
        self.assertIn(" aegis-ne flow_open ", log)
        self.assertNotIn("aegis_network_extension-", log)

    # ------------------------------------------------------- v34 receipts

    def test_a_status_the_target_refuses_is_kept_masked_and_still_fails(self):
        # One stream gets a 403 whose body names addresses (as some CDN
        # error pages name the client's); the others download.
        body = "error code: 1020 your ip 203.0.113.7 via 192.0.2.99 " + "x" * 300
        result, rows, names, calls, root = self.load(FAKE_LOAD_FIRST_STATUS="403", FAKE_LOAD_FIRST_BODY=body)
        out = root / "out"
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["load_download"][0], "fail")
        m = re.search(r" target_status=([1-4]):403 short=([1-4]):[0-9]+/", rows["load_download"][1])
        self.assertTrue(m, rows["load_download"])
        i = int(m.group(1))
        self.assertEqual(m.group(2), str(i))
        self.assertIn("ok=3/4 ", rows["load_download"][1])
        self.assertEqual((out / f"load-target.{i}.head").read_text(),
                         "HTTP/2 403\ncontent-type: text/plain\nserver: fake\ncontent-length: %d\n" % len(body))
        expected = ("error code: 1020 your ip relay_addr via ip4_global " + "x" * 80)[:64]
        self.assertEqual((out / f"load-target.{i}.body").read_text(), expected + "\n")
        self.assertIn(f"load: stream {i} status 403: {expected}", (out / "window.log").read_text())
        for j in set(range(1, 5)) - {i}:
            self.assertTrue((out / f"load-target.{j}.head").read_text().startswith("HTTP/2 200\n"))
            self.assertFalse((out / f"load-target.{j}.body").exists())
        self.assertTrue((out / f"load-stream.{i}").read_text().rstrip().endswith(" http=403 status=403"))
        texts = "".join(p.read_text() for p in out.glob("load-target.*")) + (out / "results.tsv").read_text() \
            + (out / "window.log").read_text()
        for literal in (RELAY_IP, "192.0.2.99"):
            self.assertNotIn(literal, texts)
        self.assertFalse(list(out.glob("load-target.*.raw")) + list(out.glob("load-target.*.first")))

    def test_a_stream_stopped_at_the_deadline_is_missing_and_fails(self):
        # The first stream hangs past its -m bound and the window's deadline
        # stops it: its leftovers never count as its record.
        result, rows, names, calls, root = self.load(FAKE_LOAD_HANG_FIRST="1")
        out = root / "out"
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["load_download"][0], "fail")
        self.assertRegex(rows["load_download"][1], r"^ok=3/4 bytes=3145728/4194304 per_stream=1048576 "
                                                   r"elapsed_max=[0-9.]+s bound=10s http=[0-9,a-z]+ "
                                                   r"target_status=[1-4]:none short=[1-4]:missing$")
        self.assertFalse(list(out.glob("load-target.*.raw")) + list(out.glob("load-target.*.first")))

    def test_a_window_stopped_mid_load_leaves_no_unmasked_capture(self):
        # v34 review: curl -D's headers (load-target.<i>.raw) and the body's
        # first bytes (.first) are unmasked until a stream ends; a window
        # stopped mid-load (SIGTERM, as Ctrl-C or an error would) stops its
        # streams and removes them on its EXIT path.
        root, env = self.setup_world()
        env.update({"LOAD": "1", "LOAD_URL": LOAD_URL_FAKE, "LOAD_STREAMS": "4", "LOAD_BYTES": "4194304",
                    "LOAD_BOUND_S": "30", "FAKE_LOAD_DELAY_S": "20",
                    "FAKE_PROVIDER_LOG": el_lines("flow_open ok ms:le100")})
        out = root / "out"
        window = subprocess.Popen(["/bin/bash", str(REAL_RELAY_WINDOW)], env=env, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 120
            while len(list(out.glob("load-target.*.raw"))) < 4 and time.monotonic() < deadline:
                time.sleep(0.1)
            self.assertEqual(len(list(out.glob("load-target.*.raw"))), 4)
            window.send_signal(signal.SIGTERM)
            window.wait(timeout=120)
        finally:
            if window.poll() is None:
                window.kill()
                window.wait(timeout=30)
        # Nothing writes them later either: every stream was stopped.
        time.sleep(1)
        self.assertFalse(list(out.glob("load-target.*.raw")) + list(out.glob("load-target.*.first")))
        self.assertFalse(list(out.glob("load-stream.*.*")))

    def test_the_providers_rss_across_the_load_is_an_info_row(self):
        # Six samples: before the downloads, after each check, after them.
        result, rows, names, calls, root = self.load(FAKE_RSS_PER_CALL="1024")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["load_provider_rss"][:2], (
            "info", "pid=4242 rss_kib_before=50000 rss_kib_max=55120 growth_kib=5120 samples=6"))
        self.assertEqual([line.split()[0] for line in (root / "out" / "load-provider-rss.txt").read_text().splitlines()],
                         ["before", "burst24", "burst90", "tcp", "udp", "after"])
        self.assertEqual(rows["load_download"][0], "pass")

    # ------------------------------------------------------------ refusals

    def test_load_refuses_beside_another_mode_before_anything_runs(self):
        for name, mode, reason in (
                ("ENDURANCE", "ENDURANCE=1", "not with LOAD=1: one disruption, capture or load per window"),
                ("NETLOSS", "LOAD=1", "not with NETLOSS=1: one disruption, capture or load per window"),
                ("SLEEP", "LOAD=1", "not with SLEEP=1: one disruption, capture or load per window"),
                ("IFSWITCH", "LOAD=1", "not with IFSWITCH=1: one disruption, capture or load per window"),
                ("POSITIVE_CONTROL", "LOAD=1", "not with POSITIVE_CONTROL=1: one disruption, capture or load per window"),
                ("NEGATIVE_CONTROL", "LOAD=1", "not with NEGATIVE_CONTROL=1: one disruption, capture or load per window")):
            with self.subTest(name=name):
                result, rows, names, calls, root = self.load(**{name: "1"})
                self.assert_refused_untouched(result, rows, calls, root, mode, reason + "; nothing connected")

    def test_a_load_window_that_never_connects_passes_nothing(self):
        result, rows, names, calls, root = self.load(FAKE_NO_CONNECT="1")
        for name in ("load_download", "load_throughput", "load_concurrent", "load_connected_throughout",
                     "load_filter_counters", "load_provider_rss", *LOAD_REVIEW_ROWS):
            self.assertEqual(rows[name][:2], ("unavailable", "not_connected"), name)
        self.assertFalse([c for c in calls if c.startswith("curl load")])

    def test_load_bounds_url_and_filter_refuse(self):
        for extra, reason in (({"LOAD_STREAMS": "9"}, "LOAD_STREAMS=9 is outside 1..8"),
                              ({"LOAD_STREAMS": "0"}, "LOAD_STREAMS=0 is outside 1..8"),
                              ({"LOAD_BYTES": "1073741825"}, "LOAD_BYTES=1073741825 is outside 1048576..1073741824"),
                              ({"LOAD_BYTES": "1048575"}, "LOAD_BYTES=1048575 is outside 1048576..1073741824"),
                              ({"LOAD_BOUND_S": "9"}, "LOAD_BOUND_S=9 is outside 10..900"),
                              ({"LOAD_BOUND_S": "901"}, "LOAD_BOUND_S=901 is outside 10..900"),
                              ({"LOAD_URL": "ftp://load.example/x"}, "LOAD_URL is not a plain http(s) URL"),
                              ({"LOAD_URL": "http://load.example/a b"}, "LOAD_URL is not a plain http(s) URL"),
                              ({"LOAD_URL": "http://load.example/$(id)"}, "LOAD_URL is not a plain http(s) URL"),
                              ({"FAKE_FILTER_EXIT": "33"}, "needs the leak-guard filter configured, enabled and "
                                                           "attached (host --filter-status exit 33)")):
            with self.subTest(extra=extra):
                result, rows, names, calls, root = self.load(**extra)
                self.assert_refused_untouched(result, rows, calls, root, "LOAD=1", reason + "; nothing connected")

    def test_load_with_a_capture_refuses_when_its_pcap_would_cross_the_disk_floor(self):
        # 1 GiB of load and its 1 GiB margin out of 33 GiB less a KiB.
        free = str(33 * 1048576 - 1)
        result, rows, names, calls, root = self.load(capture=True, LOAD_BYTES="1073741824", FAKE_DF_AVAIL_KIB=free)
        self.assert_refused_untouched(result, rows, calls, root, "LOAD=1",
                                      "32 GiB free on the volume holding OUT less the captures' expected 2 GiB leaves "
                                      "less than the 31 GiB floor; nothing connected")
        # v34: from a URL that serves 256 MiB a stream (the default's file
        # is smaller), so only the floor is judged.
        big = "http://load.example/blob"
        rc, out, root = self.preflight(LOAD="1", LOAD_URL=big, LOAD_BYTES="1073741824", FAKE_DF_AVAIL_KIB=free)
        self.assertEqual(rc, 0, out)
        self.assertIn("mode=LOAD=1 extra=300 ", out)
        rc, out, root = self.preflight("LEAK_CAPTURE=1", LOAD="1", LOAD_URL=big, LOAD_BYTES="1073741824",
                                       FAKE_DF_AVAIL_KIB=str(33 * 1048576))
        self.assertEqual(rc, 0, out)
        rc, out, root = self.preflight(LOAD="1", FAKE_DF_AVAIL_KIB=str(31 * 1048576 - 1))
        self.assertEqual(rc, 3, out)


class RealRelayWindowPolicyTests(EnduranceLoadWorld, unittest.TestCase):
    """v35: WINDOW_POLICY and the window_policy row of
    harness/real-relay-window.sh in the fake world (H1, H2). v36 (outcome
    fixed): empty connects the product default and expects fixed; adaptive
    is a QA arm with its own flag."""

    def load(self, **extra):
        env = {"LOAD": "1", "LOAD_URL": LOAD_URL_FAKE, "LOAD_STREAMS": "4", "LOAD_BYTES": "4194304",
               "LOAD_BOUND_S": "10", "FAKE_PROVIDER_LOG": el_lines("flow_open ok ms:le100", "pool_policy mode:fixed")}
        env.update(extra)
        return self.run_window(**env)

    @staticmethod
    def connects(calls):
        return [c for c in calls if c.startswith("host --connect")]

    def test_a_set_policy_connects_with_its_flag_and_its_row_passes(self):
        # H1: WINDOW_POLICY=fixed or adaptive appends the flag with its value
        # to the connect's argv; H2: one pool_policy line naming it passes.
        for value in ("fixed", "adaptive"):
            result, rows, names, calls, root = self.load(
                WINDOW_POLICY=value, FAKE_PROVIDER_LOG=el_lines("flow_open ok ms:le100", "pool_policy mode:" + value))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            connects = self.connects(calls)
            self.assertEqual(len(connects), 1, calls)
            self.assertTrue(connects[0].endswith(" --window-policy " + value), connects)
            self.assertEqual(connects[0].split()[2:4], ["dev.aegis.macos.PacketTunnel",
                                                         "0A1B2C3D-0000-4000-8000-000000000001"])
            self.assertEqual(rows["window_policy"][:2], ("pass", "expected=%s seen=%s lines=1" % (value, value)))
            self.assertLess(names.index("disconnect_verified"), names.index("window_policy"))
            for name in LOAD_REVIEW_ROWS:
                self.assertIn(rows[name][0], ("info", "unavailable"), (name, rows[name]))

    def test_the_default_connects_without_the_flag_and_expects_the_fixed_window(self):
        result, rows, names, calls, root = self.load()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        connects = self.connects(calls)
        self.assertEqual(len(connects), 1, calls)
        self.assertNotIn("--window-policy", connects[0])
        self.assertEqual(len(connects[0].split()), 5, connects)
        self.assertEqual(rows["window_policy"][:2], ("pass", "expected=fixed seen=fixed lines=1"))
        # A session rebuilt in the window logs a second line of the same mode.
        result, rows, names, calls, root = self.load(FAKE_PROVIDER_LOG=el_lines(
            "pool_policy mode:fixed", "session_rebuilt attempt:1", "pool_policy mode:fixed"))
        self.assertEqual(rows["window_policy"][:2], ("pass", "expected=fixed seen=fixed lines=2"))
        # A build whose default is still the v35 window fails the row.
        result, rows, names, calls, root = self.load(FAKE_PROVIDER_LOG=el_lines("pool_policy mode:adaptive"))
        self.assertEqual(rows["window_policy"][:2], ("fail", "expected=fixed seen=adaptive lines=1"))

    def test_any_other_value_refuses_before_the_connect(self):
        # H1: FIXED, ADAPTIVE or anything else is refused before the lock,
        # the rollback or any connect, exit 2.
        for value in ("FIXED", "ADAPTIVE", "Adaptive", "fixedx", "v33-1"):
            result, rows, names, calls, root = self.load(WINDOW_POLICY=value)
            self.assert_refused_untouched(result, rows, calls, root, None,
                                          "WINDOW_POLICY must be empty, fixed or adaptive; nothing connected",
                                          code=2)
            # The refused value is not echoed.
            self.assertNotIn(value, result.stdout)

    def test_the_row_fails_on_a_mismatch_mixed_modes_or_no_line(self):
        # H2.
        result, rows, names, calls, root = self.load(WINDOW_POLICY="adaptive")
        self.assertEqual(rows["window_policy"][:2], ("fail", "expected=adaptive seen=fixed lines=1"))
        result, rows, names, calls, root = self.load(
            WINDOW_POLICY="fixed", FAKE_PROVIDER_LOG=el_lines("pool_policy mode:adaptive"))
        self.assertEqual(rows["window_policy"][:2], ("fail", "expected=fixed seen=adaptive lines=1"))
        result, rows, names, calls, root = self.load(FAKE_PROVIDER_LOG=el_lines(
            "pool_policy mode:fixed", "pool_policy mode:adaptive"))
        self.assertEqual(rows["window_policy"][:2], ("fail", "expected=fixed seen=adaptive,fixed lines=2"))
        result, rows, names, calls, root = self.load(FAKE_PROVIDER_LOG=el_lines("flow_open ok ms:le100"))
        self.assertEqual(rows["window_policy"][:2], ("fail", "expected=fixed seen=none lines=0"))
        result, rows, names, calls, root = self.load(FAKE_PROVIDER_LOG=el_lines("pool_policy mode:"))
        self.assertEqual(rows["window_policy"][0], "fail")

    def test_a_window_that_never_connected_has_no_policy_to_judge(self):
        result, rows, names, calls, root = self.load(FAKE_NO_CONNECT="1", ROLLBACK_S="400",
                                                     FAKE_PROVIDER_LOG="")
        self.assertEqual(rows["connected"][0], "0")
        self.assertEqual(rows["window_policy"][:2], ("unavailable", "expected=fixed seen=none lines=0 not_connected"))

    def test_outside_load_and_without_window_policy_there_is_no_row(self):
        result, rows, names, calls, root = self.run_window(FAKE_PROVIDER_LOG=el_lines("pool_policy mode:fixed"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("window_policy", rows)


class EnduranceReviewTests(unittest.TestCase):
    """harness/endurance_review.py alone on made-up records: the cycles'
    99% threshold and the real-time row (no window, no fake world)."""

    @staticmethod
    def cycle_rows(n, period=60, failing=(), real_s=None):
        base = datetime.datetime(2026, 10, 27, 8, 0, 0, tzinfo=datetime.timezone.utc)
        rows = []
        for k in range(n):
            start = base + datetime.timedelta(seconds=k * (period if real_s is None else real_s))
            v = "fail" if k in failing else "pass"
            stamp = lambda t: t.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (t.microsecond // 1000)
            rows.append({"cycle": str(k), "slot_s": str(k * period), "start": stamp(start),
                         "end": stamp(start + datetime.timedelta(seconds=1)), "verdict": v, "whoami": v,
                         "tcp_echo": "pass", "udp_echo": "pass", "dns_txt": "pass", "http": "pass",
                         "probe_detail": "tcp=4/7/eof http=200", "status_start": "Connected", "status_end": "Connected",
                         "phase": "ready", "renewal": "none", "provider_pid": "4242", "rss_kib": "50000",
                         "cpu_pct": "1.5", "log_read": "ok", "session_lost": "0", "lost_causes": "none",
                         "session_rebuilt": "0", "session_failed": "0", "renewal_states": "none",
                         "rebuild_pending": "0", "codex_lock": "0", "run_ms": str(k * period * 1000 + 100)})
        return rows

    def review(self, rows, planned, period=60, duration=None, clock="default"):
        with tempfile.TemporaryDirectory(prefix="aegis-s24-review-") as temp:
            root = pathlib.Path(temp)
            (root / "e.tsv").write_text("\n".join(["\t".join(ENDURANCE_TSV_COLUMNS)] +
                                                  ["\t".join(r[c] for c in ENDURANCE_TSV_COLUMNS) for r in rows]) + "\n")
            (root / "results.tsv").write_text("")
            (root / "statuses.txt").write_text("")
            (root / "log.txt").write_text(el_lines("reack_ok link_ms:1").replace("\\n", "\n"))
            out = subprocess.run([SYSTEM_PY, "-I", str(ENDURANCE_REVIEW), "--tsv", str(root / "e.tsv"), "--results",
                                  str(root / "results.tsv"), "--statuses", str(root / "statuses.txt"), "--log",
                                  str(root / "log.txt"), "--planned", str(planned), "--period", str(period), "--pid0",
                                  "4242", "--final", "ok", "--recoverable", "capture_lease_expired", "--duration",
                                  str(duration if duration is not None else (planned - 1) * period), "--clock", clock],
                                 capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        return {line.split("\t")[0]: tuple(line.split("\t")[1:]) for line in out.stdout.splitlines()}

    def test_at_least_99_percent_of_the_cycles_pass(self):
        # Of the default 121 cycles one may fail (99.17%) and two may not
        # (98.35%), whatever their place; of 100 one may.
        for n, failing, verdict in ((121, (60,), "pass"), (121, (30, 90), "fail"), (100, (50,), "pass"),
                                    (99, (50,), "fail")):
            with self.subTest(n=n, failing=failing):
                rows = self.review(self.cycle_rows(n, failing=failing), n)
                self.assertEqual(rows["endurance_cycles"][0], verdict, rows["endurance_cycles"])
                self.assertEqual(rows["endurance_longest_gap"][0], "pass", rows["endurance_longest_gap"])

    def test_the_cycles_must_span_the_run_in_real_time(self):
        # 11 cycles 60 s apart in real time span the 600 s run.
        rows = self.review(self.cycle_rows(11), 11, duration=600)
        self.assertEqual(rows["endurance_real_time"], ("pass", "real_span_s=600.0 duration_s=600 need_s=540 clock=default"))
        # A last slot missed leaves a period less, which is allowed.
        rows = self.review(self.cycle_rows(10), 11, duration=600)
        self.assertEqual(rows["endurance_real_time"][0], "pass")
        # A schedule that ran faster than real time (its clock not the
        # system's, or a clock of its own) does not span the run.
        rows = self.review(self.cycle_rows(11, real_s=5), 11, duration=600)
        self.assertEqual(rows["endurance_real_time"], ("fail", "real_span_s=50.0 duration_s=600 need_s=540 clock=default"))
        rows = self.review(self.cycle_rows(11), 11, duration=600, clock="override")
        self.assertEqual(rows["endurance_real_time"][0], "unavailable")


class RealRelayWindowArmedRollbackTests(EnduranceLoadWorld, unittest.TestCase):
    """S24 review: the detached tunnel rollback of a window that died stays
    armed for its whole rollback_s (hours with ENDURANCE=1). Every new window
    refuses beside it, the documented disarm ends it, and when it fires it
    releases timing-self only while that is still its window's lock."""

    def dead_window(self, root, env, rollback_s):
        """A window SIGKILLed once Connected (no EXIT trap): its rollback's pid."""
        window = subprocess.Popen(["/bin/bash", str(REAL_RELAY_WINDOW)], env=dict(env, ROLLBACK_S=str(rollback_s)),
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 60
        while (root / "state").read_text().strip() != "Connected" and time.monotonic() < deadline:
            time.sleep(0.05)
        window.kill()
        window.wait(timeout=10)
        return int(re.search(r"^armed pid=([0-9]+) ", (root / "out" / "rollback.log").read_text(), re.M).group(1))

    @staticmethod
    def alive(pid):
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True

    def wait_done(self, out, seconds=30):
        log = out / "rollback.log"
        deadline = time.monotonic() + seconds
        while "rollback_done" not in log.read_text() and time.monotonic() < deadline:
            time.sleep(0.2)
        return log.read_text()

    def test_a_new_window_refuses_beside_an_earlier_windows_armed_rollback(self):
        root, env = self.setup_world()
        pid = self.dead_window(root, env, 300)
        lock = root / "home" / ".aegis-local" / "locks" / "timing-self"
        self.assertTrue(lock.exists())
        # The tunnel stopped and the lock removed by hand; the rollback stays.
        (root / "state").write_text("Disconnected\n")
        lock.unlink()
        calls = lambda: (root / "calls.log").read_text().splitlines()
        connects = [c for c in calls() if c.startswith("host --connect")]
        self.assertEqual(len(connects), 1)
        for n, mode in enumerate(({}, {"ENDURANCE": "1", "ENDURANCE_S": "600", "ENDURANCE_PERIOD_S": "60"},
                                  {"LOAD": "1", "LOAD_URL": LOAD_URL_FAKE, "LOAD_BYTES": "4194304", "LOAD_BOUND_S": "10"})):
            with self.subTest(mode=mode):
                out = root / f"out-{n}"
                self.addCleanup(RealRelayWindowLeakCaptureTests.cancel_rollback, None, out)
                result = subprocess.run(["/bin/bash", str(REAL_RELAY_WINDOW)], capture_output=True, text=True,
                                        env=dict(env, OUT=str(out), **mode), timeout=120)
                self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
                self.assertIn(f"refused: a detached tunnel rollback of an earlier window is still armed (pid {pid}): "
                              "it would stop this window's tunnel; disarm it first (harness/README.md, a window that "
                              "dies)", result.stdout)
                self.assertFalse(lock.exists())
                self.assertFalse((out / "rollback.log").exists())
                self.assertFalse((out / "results.tsv").exists())
                self.assertEqual([c for c in calls() if c.startswith("host --connect")], connects)
        # The documented disarm: the pid on rollback.log's `armed pid=` line,
        # whose arguments name that window's rollback.cancel, ended with
        # SIGKILL (it ignores INT, TERM, HUP and QUIT).
        args = subprocess.run(["/bin/ps", "-o", "args=", "-p", str(pid)], capture_output=True, text=True).stdout
        self.assertIn(f"{root}/out/rollback.cancel ", args)
        os.kill(pid, signal.SIGTERM)
        time.sleep(1)
        self.assertTrue(self.alive(pid))
        os.kill(pid, signal.SIGKILL)
        deadline = time.monotonic() + 10
        while self.alive(pid) and time.monotonic() < deadline:
            time.sleep(0.1)
        self.assertFalse(self.alive(pid))
        out = root / "out-disarmed"
        self.addCleanup(RealRelayWindowLeakCaptureTests.cancel_rollback, None, out)
        result = subprocess.run(["/bin/bash", str(REAL_RELAY_WINDOW)], capture_output=True, text=True,
                                env=dict(env, OUT=str(out), ROLLBACK_S="40"), timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rows, names = self.rows_of(out)
        self.assertEqual((rows["connected"][0], rows["disconnect_verified"][0]), ("1", "pass"))
        self.assertFalse(lock.exists())

    def test_a_rollback_that_fires_releases_only_its_own_lock(self):
        # Taken since by another run: kept.
        root, env = self.setup_world()
        self.dead_window(root, env, 6)
        lock = root / "home" / ".aegis-local" / "locks" / "timing-self"
        self.assertTrue(lock.read_text().startswith("start="))
        lock.write_text("start=20261027T000000Z purpose=another-run\n")
        text = self.wait_done(root / "out")
        self.assertIn("rollback_fired\n", text)
        self.assertIn("lock_kept not_ours\n", text)
        self.assertEqual(lock.read_text(), "start=20261027T000000Z purpose=another-run\n")
        self.assertIn("host --emergency-stop", (root / "calls.log").read_text().splitlines())
        # Its own, untouched: released.
        root, env = self.setup_world()
        self.dead_window(root, env, 6)
        lock = root / "home" / ".aegis-local" / "locks" / "timing-self"
        text = self.wait_done(root / "out")
        self.assertIn("rollback_fired\n", text)
        self.assertIn("lock_released\n", text)
        self.assertFalse(lock.exists())

    def test_the_docs_say_how_to_disarm_a_dead_windows_rollback(self):
        repo = PACKAGE.parents[2]
        for path in (PACKAGE / "harness" / "README.md", repo / "docs" / "platforms" / "macos" / "known-limits.md",
                     repo / "docs" / "platforms" / "macos" / "operate.md"):
            text = " ".join(path.read_text().split())
            with self.subTest(path=path.name):
                for words in ("armed pid=", "rollback.cancel", "kill -KILL", "timing-self"):
                    self.assertIn(words, text)


# A window without the new modes, in the S24 fake world, row for row as the
# harness before S24 wrote it (generated from d0635ebb's harness with the
# same fakes): names, verdicts, statuses and details, with durations,
# process ids, digests and epochs masked. v34 (S24 review F): the only
# details that differ are the address literals the window now masks (the
# relay's in whoami_egress, the AAAA answers); every verdict is the same.
PRE_S24_ROWS = {
    False: [
        ('physical_v6_baseline', 'info', 'default=en0 global=1', 'Disconnected'),
        ('filter_preflight', 'pass', 'exit=0 required=0 filter_result=ok exit_code=0 configured=true enabled=true filter_packets=true filter_sockets=false packet_bundle_id=match grade=firewall attached=true pid_match=true mode=open armed_token=none dropped=0 allowed=0', 'Disconnected'),
        ('connected', '1', 'Connected', 'Connected'),
        ('utun_addr', 'pass', 'utun9', 'Connected'),
        ('default_route', 'pass', 'utun9', 'Connected'),
        ('tcp_echo_v4', 'pass', '4/7/eof', 'Connected'),
        ('tcp_echo_v4_nohc', 'pass', '4/7/full', 'Connected'),
        ('tcp_echo_v4_nc', 'pass', 'ping', 'Connected'),
        ('udp_echo_v4', 'pass', 'pong', 'Connected'),
        ('whoami_egress', 'pass', 'ip=relay_addr', 'Connected'),
        ('flow_burst_24', 'pass', '24/24 <s>', 'Connected'),
        ('flow_burst_90', 'pass', '90/90 <s>', 'Connected'),
        ('still_connected_after_reack', 'pass', '', 'Connected'),
        ('tcp_echo_v4_warm', 'pass', '4/7/eof', 'Connected'),
        ('tcp_echo_v4_warm_nohc', 'pass', '4/7/full', 'Connected'),
        ('dns_a_fakeip', 'pass', '198.18.0.9', 'Connected'),
        ('http_by_name', 'pass', '200', 'Connected'),
        ('dns_txt_via_relay', 'pass', '"v=fake"', 'Connected'),
        ('system_resolver', 'pass', '198.19.255.2', 'Connected'),
        ('utun_addr_v6', 'pass', 'fd00:ae61::1/120', 'Connected'),
        ('default_route_v6', 'pass', 'utun9', 'Connected'),
        ('route_v6_anchor', 'pass', 'utun9', 'Connected'),
        ('scoped_phys_v6_default', 'info', 'en0:present', 'Connected'),
        ('utun_routes_v6', 'info', 'default:UGcIg,fd00:ae61::/120:UC other=0', 'Connected'),
        ('source_v6_tunnel', 'pass', 'fd00:ae61::1', 'Connected'),
        ('system_resolver_v6', 'pass', 'fd00:ae61::2', 'Connected'),
        ('dns_udp6_anchor', 'pass', '198.18.0.9', 'Connected'),
        ('dns_tcp6_anchor', 'pass', '198.18.0.9', 'Connected'),
        ('dns_aaaa_via_relay', 'pass', 'ip6_global', 'Connected'),
        ('dns_aaaa_v6_anchor', 'pass', 'ip6_global', 'Connected'),
        ('system_aaaa_observed', 'info', 'ip6_global', 'Connected'),
        ('http6_by_name', 'info_fail', '200', 'Connected'),
        ('udp_echo_v6', 'skip', 'no echo_udp6', 'Connected'),
        ('tcp_echo_v6', 'skip', 'no echo_tcp6', 'Connected'),
        ('whoami6_egress', 'skip', 'no whoami6', 'Connected'),
        ('disconnect_verified', 'pass', 'en0', 'Disconnected'),
        ('disconnect_v6_route', 'pass', 'en0 baseline=en0', 'Disconnected'),
        ('filter_counters_after', 'info', 'exit=0 filter_result=ok exit_code=0 configured=true enabled=true filter_packets=true filter_sockets=false packet_bundle_id=match grade=firewall attached=true pid_match=true mode=open armed_token=none dropped=5 allowed=100', 'Disconnected'),
        ('filter_armed_span', 'unavailable', 'no_span_lines', 'Disconnected'),
        ('window_session_summary', 'info', 'session_lost=0 causes=none session_rebuilt=0 reasserting_on=0 renewal_attempts=0 renewal_deferred=0 renewal_held=0', 'Disconnected'),
        ('disconnect_v6_addr', 'pass', 'count=0', 'Disconnected'),
        ('no_v6_leak_physical', 'unavailable', 'LEAK_CAPTURE=0: no physical capture', 'Disconnected'),
    ],
    True: [
        ('capture_started', 'pass', 'pid=<n> tcpdump=<n> if=en0 file=physical.pcap bound=100s', 'Disconnected'),
        ('leak_capture_ifaces', 'info', 'en0', 'Disconnected'),
        ('physical_v6_baseline', 'info', 'default=en0 global=1', 'Disconnected'),
        ('filter_preflight', 'pass', 'exit=0 required=1 filter_result=ok exit_code=0 configured=true enabled=true filter_packets=true filter_sockets=false packet_bundle_id=match grade=firewall attached=true pid_match=true mode=open armed_token=none dropped=0 allowed=0', 'Disconnected'),
        ('connected', '1', 'Connected', 'Connected'),
        ('leak_window_connected_at', '<epoch>', '', 'Connected'),
        ('utun_addr', 'pass', 'utun9', 'Connected'),
        ('default_route', 'pass', 'utun9', 'Connected'),
        ('tcp_echo_v4', 'pass', '4/7/eof', 'Connected'),
        ('tcp_echo_v4_nohc', 'pass', '4/7/full', 'Connected'),
        ('tcp_echo_v4_nc', 'pass', 'ping', 'Connected'),
        ('udp_echo_v4', 'pass', 'pong', 'Connected'),
        ('whoami_egress', 'pass', 'ip=relay_addr', 'Connected'),
        ('flow_burst_24', 'pass', '24/24 <s>', 'Connected'),
        ('flow_burst_90', 'pass', '90/90 <s>', 'Connected'),
        ('still_connected_after_reack', 'pass', '', 'Connected'),
        ('tcp_echo_v4_warm', 'pass', '4/7/eof', 'Connected'),
        ('tcp_echo_v4_warm_nohc', 'pass', '4/7/full', 'Connected'),
        ('dns_a_fakeip', 'pass', '198.18.0.9', 'Connected'),
        ('http_by_name', 'pass', '200', 'Connected'),
        ('dns_txt_via_relay', 'pass', '"v=fake"', 'Connected'),
        ('system_resolver', 'pass', '198.19.255.2', 'Connected'),
        ('utun_addr_v6', 'pass', 'fd00:ae61::1/120', 'Connected'),
        ('default_route_v6', 'pass', 'utun9', 'Connected'),
        ('route_v6_anchor', 'pass', 'utun9', 'Connected'),
        ('scoped_phys_v6_default', 'info', 'en0:present', 'Connected'),
        ('utun_routes_v6', 'info', 'default:UGcIg,fd00:ae61::/120:UC other=0', 'Connected'),
        ('source_v6_tunnel', 'pass', 'fd00:ae61::1', 'Connected'),
        ('system_resolver_v6', 'pass', 'fd00:ae61::2', 'Connected'),
        ('dns_udp6_anchor', 'pass', '198.18.0.9', 'Connected'),
        ('dns_tcp6_anchor', 'pass', '198.18.0.9', 'Connected'),
        ('dns_aaaa_via_relay', 'pass', 'ip6_global', 'Connected'),
        ('dns_aaaa_v6_anchor', 'pass', 'ip6_global', 'Connected'),
        ('system_aaaa_observed', 'info', 'ip6_global', 'Connected'),
        ('http6_by_name', 'info_fail', '200', 'Connected'),
        ('udp_echo_v6', 'skip', 'no echo_udp6', 'Connected'),
        ('tcp_echo_v6', 'skip', 'no echo_tcp6', 'Connected'),
        ('whoami6_egress', 'skip', 'no whoami6', 'Connected'),
        ('leak_window_disconnect_at', '<epoch>', 'capture_alive=1', 'Connected'),
        ('disconnect_verified', 'pass', 'en0', 'Disconnected'),
        ('disconnect_v6_route', 'pass', 'en0 baseline=en0', 'Disconnected'),
        ('filter_counters_after', 'info', 'exit=0 filter_result=ok exit_code=0 configured=true enabled=true filter_packets=true filter_sockets=false packet_bundle_id=match grade=firewall attached=true pid_match=true mode=open armed_token=none dropped=5 allowed=100', 'Disconnected'),
        ('filter_armed_span', 'unavailable', 'no_span_lines', 'Disconnected'),
        ('window_session_summary', 'info', 'session_lost=0 causes=none session_rebuilt=0 reasserting_on=0 renewal_attempts=0 renewal_deferred=0 renewal_held=0', 'Disconnected'),
        ('disconnect_v6_addr', 'pass', 'count=0', 'Disconnected'),
        ('capture_stopped', 'pass', 'pid=<n> tcpdump=<n>', 'Disconnected'),
        ('leak_proof', 'pass', 'leak_review pass=true leaks=0 relay=<n> control=0 total=<n> new_outbound_flows=0 preexisting=0 foreign=0 capture_alive=1 capture_stopped=1 kernel_drops=0', 'Disconnected'),
        ('leak_capture_sha256', '<sha256>', 'physical.pcap not for retained evidence', 'Disconnected'),
        ('no_v6_leak_physical', 'pass', 'ipv6_leaks=0 capture_alive=1 capture_stopped=1 kernel_drops=0', 'Disconnected'),
        ('leak_proof_all_ifaces', 'pass', 'ifaces=en0 en0:pass=true,relay=<n>,alive=1,stopped=1,drops=0 uncaptured=none', 'Disconnected'),
        ('no_mac_sent_leak_physical', 'pass', 'ifaces=en0 en0:mac_sent_leaks=0,mac_sent_pass=true,alive=1,stopped=1,drops=0 uncaptured=none', 'Disconnected'),
    ],
}


def masked_rows(out):
    rows = []
    for name, verdict, detail, status, _start, _end in row_fields(out):
        detail = re.sub(r"\b[0-9]+\.[0-9]+s\b", "<s>", detail)
        detail = re.sub(r"\b(pid|tcpdump)=[0-9]+", r"\1=<n>", detail)
        detail = re.sub(r"\brelay=[0-9]+", "relay=<n>", detail)
        detail = re.sub(r"\btotal=[0-9]+", "total=<n>", detail)
        verdict = re.sub(r"^[0-9a-f]{64}$", "<sha256>", verdict)
        verdict = re.sub(r"^[0-9]{10}\.[0-9]+$", "<epoch>", verdict)
        rows.append((name, verdict, detail, status))
    return rows


class RealRelayWindowWithoutS24ModesTests(EnduranceLoadWorld, unittest.TestCase):
    """A window that asks for neither ENDURANCE=1 nor LOAD=1 writes every
    row exactly as the harness before S24 did."""

    def test_a_window_without_the_new_modes_keeps_every_row(self):
        for capture in (False, True):
            with self.subTest(capture=capture):
                result, rows, names, calls, root = self.run_window(
                    capture=capture, ROLLBACK_S="40", FAKE_PROVIDER_LOG=provider_lines("start tunnel_running"),
                    FAKE_LOG_NO_HEARTBEAT="1")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(masked_rows(root / "out"), PRE_S24_ROWS[capture])
                self.assertFalse(list((root / "out").glob("endurance*")) + list((root / "out").glob("load-*")))
                self.assertFalse([c for c in calls if c.startswith(("caffeinate", "pgrep", "curl load",
                                                                    "host --cert-status"))], calls)
        # Bursts exactly at their thresholds (22 of 24, 88 of 90) still pass,
        # as before S24: a changed threshold flips a verdict here.
        result, rows, names, calls, root = self.run_window(
            ROLLBACK_S="40", FAKE_PROVIDER_LOG=provider_lines("start tunnel_running"), FAKE_LOG_NO_HEARTBEAT="1",
            FAKE_BURST_AT_THRESHOLD="1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        expected = [(n, v, {"flow_burst_24": "22/24 <s>", "flow_burst_90": "88/90 <s>"}.get(n, d), s)
                    for n, v, d, s in PRE_S24_ROWS[False]]
        self.assertEqual(masked_rows(root / "out"), expected)


# ---------------------------------- v34 masking (S24 review F) and the load review

TUNNEL_RANGES = (ipaddress.ip_network("198.18.0.0/15"), ipaddress.ip_network("fd00:ae61::/32"))
ADDR_RUN = re.compile(r"[0-9A-Fa-f.:]*[.:][0-9A-Fa-f.:]*")
ADDR_QUAD = re.compile(r"(?<![0-9])[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?![0-9])")


def address_literals(text):
    """Every IPv4 and IPv6 literal of `text` (found independently of
    harness/addr_mask.py: any dotted quad, and any colon run that parses
    once a leading or trailing colon or dot is dropped)."""
    found = []
    for m in ADDR_QUAD.finditer(text):
        try:
            found.append(ipaddress.ip_address(m.group(0)))
        except ValueError:
            pass
    for m in ADDR_RUN.finditer(text):
        run = m.group(0)
        if run.count(":") < 2:
            continue
        for cand in (run, run.strip("."), run.lstrip(":"), run.rstrip(":."), run.strip(":.")):
            try:
                found.append(ipaddress.ip_address(cand))
                break
            except ValueError:
                continue
    return found


def window_functions(*names):
    """Shell functions of harness/real-relay-window.sh, extracted with the
    mask patterns they read, to run alone."""
    lines = REAL_RELAY_WINDOW.read_text().splitlines()
    out = [line for line in lines if line.startswith(("MASK_RE4=", "MASK_RE6="))]
    for name in names:
        i = next(k for k, line in enumerate(lines) if line.startswith(f"{name}() {{"))
        j = i if lines[i].rstrip().endswith("}") else lines.index("}", i)
        out.extend(lines[i:j + 1])
    return "\n".join(out) + "\n"


class RealRelayWindowMaskTests(EnduranceLoadWorld, unittest.TestCase):
    """v34 (S24 review F): every verdict from the raw value, then only
    masked details and log lines; the tunnel's own fixed addresses are the
    only literals left."""

    def assert_no_foreign_literal(self, *paths):
        text = "".join(p.read_text() for p in paths)
        foreign = [str(a) for a in address_literals(text) if not any(a in n for n in TUNNEL_RANGES)]
        self.assertEqual(foreign, [])
        self.assertNotIn(RELAY_IP, text)
        return text

    def test_no_address_literal_but_the_tunnels_own_reaches_the_rows_or_the_log(self):
        result, rows, names, calls, root = self.run_window(
            ROLLBACK_S="40", FAKE_PROVIDER_LOG=provider_lines("start tunnel_running"), FAKE_LOG_NO_HEARTBEAT="1")
        out = root / "out"
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        log = self.assert_no_foreign_literal(out / "results.tsv", out / "window.log")
        self.assertIn(" relay=relay_addr:443 sid=", log)
        self.assertEqual(rows["whoami_egress"][:2], ("pass", "ip=relay_addr"))
        # The tunnel's own addresses stay readable.
        self.assertEqual(rows["system_resolver"][1], "198.19.255.2")
        self.assertEqual(rows["utun_addr_v6"][1], "fd00:ae61::1/120")
        # A load window, one of whose streams the target refuses with a body
        # that names the relay.
        result, rows, names, calls, root = self.run_window(
            LOAD="1", LOAD_URL=LOAD_URL_FAKE, LOAD_STREAMS="4", LOAD_BYTES="4194304", LOAD_BOUND_S="10",
            FAKE_PROVIDER_LOG=el_lines("flow_open ok ms:le100"), FAKE_LOAD_FIRST_STATUS="429",
            FAKE_LOAD_FIRST_BODY=f"slow down {RELAY_IP} [2001:db8:ffff::7] fe80::1")
        out = root / "out"
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_no_foreign_literal(out / "results.tsv", out / "window.log", *out.glob("load-target.*"))
        self.assertIn(":429 ", rows["load_download"][1])

    def test_an_egress_other_than_the_relay_still_fails(self):
        result, rows, names, calls, root = self.run_window(
            ROLLBACK_S="40", FAKE_PROVIDER_LOG=provider_lines("start tunnel_running"), FAKE_LOG_NO_HEARTBEAT="1",
            FAKE_WHOAMI_BODY="ip=192.0.2.99")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(rows["whoami_egress"][:2], ("fail", "ip=ip4_global"))
        self.assert_no_foreign_literal(root / "out" / "results.tsv", root / "out" / "window.log")
        # The rest of the window is unchanged by it.
        self.assertEqual(rows["disconnect_verified"][0], "pass")

    def test_the_whoami_rule_needs_the_relays_whole_address(self):
        script = window_functions("egress_is_relay") + (
            'RELAY_IP=$1; shift\nfor b in "$@"; do egress_is_relay "$b" && echo pass || echo fail; done\n')
        cases = (("203.0.113.7", [("ip=203.0.113.7", "pass"), ("203.0.113.7\n", "pass"), ('{"ip":"203.0.113.7"}', "pass"),
                                  ("ip=::ffff:203.0.113.7", "pass"), ("ip=203.0.113.70", "fail"), ("ip=1203.0.113.7", "fail"),
                                  ("ip=203.0.113.7.5", "fail"), ("ip=203x0x113x7", "fail"), ("ip=192.0.2.99", "fail"),
                                  ("ip=2001:db8::203.0.113.7", "fail"), ("", "fail")]),
                 ("[2001:db8:ffff::7]", [("ip=2001:db8:ffff::7", "pass"), ("ip=2001:DB8:FFFF::7", "pass"),
                                         ("ip=2001:db8:ffff::70", "fail"), ("ip=12001:db8:ffff::7", "fail"),
                                         ("ip=2001:db8:ffff::7:1", "fail"), ("ip=203.0.113.7", "fail")]),
                 ("", [("ip=203.0.113.7", "fail")]))
        for relay, bodies in cases:
            with self.subTest(relay=relay):
                out = subprocess.run(["/bin/bash", "-c", script, "x", relay, *[b for b, _ in bodies]],
                                     capture_output=True, text=True, timeout=30)
                self.assertEqual(out.stdout.split(), [v for _, v in bodies], out.stderr)

    def test_the_mask_passes_plain_text_through_and_fails_closed(self):
        script = window_functions("mask_addrs", "egress_detail") + (
            'for t in "$@"; do printf "%s|" "$(mask_addrs "$t")"; done; echo; printf "%s\\n" "$(egress_detail "$1")"\n')
        env = dict(os.environ, HARNESS_DIR=str(PACKAGE / "harness"), RELAY_IP=RELAY_IP, RELAY_V6="2001:db8:ffff::7")
        texts = ("ip=203.0.113.7 " + "y" * 90, "24/24 1.94s", "relay=203.0.113.7:443", "ends 08:00:00 [4242:1]",
                 "2001:db8:ffff::7 and 2001:db8:5::1")
        out = subprocess.run(["/bin/bash", "-c", script, "x", *texts], capture_output=True, text=True, env=env, timeout=30)
        masked, detail = out.stdout.splitlines()
        self.assertEqual(masked.split("|")[:-1], ["ip=relay_addr " + "y" * 90, "24/24 1.94s", "relay=relay_addr:443",
                                                  "ends 08:00:00 [4242:1]", "relay_addr and ip6_global"])
        self.assertEqual(detail, ("ip=relay_addr " + "y" * 90)[:80])
        # Without a working masker every candidate is masked (fail closed);
        # plain text needs no python at all.
        env["HARNESS_DIR"] = "/nonexistent"
        out = subprocess.run(["/bin/bash", "-c", script, "x", *texts], capture_output=True, text=True, env=env, timeout=30)
        masked = out.stdout.splitlines()[0].split("|")[:-1]
        self.assertEqual(masked[1], "24/24 1.94s")
        for m in masked:
            self.assertEqual(address_literals(m), [], m)


class AddrMaskTests(unittest.TestCase):
    """harness/addr_mask.py alone."""

    def mask(self, text, *relays):
        args = [x for r in relays for x in ("--relay", r)]
        out = subprocess.run([SYSTEM_PY, "-I", str(ADDR_MASK), *args], input=text, capture_output=True, text=True,
                             timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        return out.stdout

    def test_each_class_and_the_tunnels_own_addresses(self):
        relays = (RELAY_IP, "2001:db8:ffff::7")
        for text, expected in (
                ("ip=203.0.113.7", "ip=relay_addr"), ("ip=192.0.2.99", "ip=ip4_global"),
                ("relay=203.0.113.7:443", "relay=relay_addr:443"), ("ip=2001:db8:ffff::7", "ip=relay_addr"),
                ("http://[2001:db8:ffff::7]:8080/", "http://[relay_addr]:8080/"), ("::ffff:203.0.113.7", "relay_addr"),
                ("200 2001:db8:5::1", "200 ip6_global"), ("fe80::1%en0", "ip6_link_local%en0"),
                ("fd12:3456::1", "ip6_ula"), ("ff02::fb", "ip6_multicast"), ("::1", "ip6_loopback"),
                ("10.0.5.50 192.168.1.1 172.16.0.1", "ip4_private ip4_private ip4_private"),
                ("100.64.1.2 127.0.0.1 169.254.1.1 224.0.0.251", "ip4_cgnat ip4_loopback ip4_link_local ip4_multicast"),
                ("ip:203.0.113.70", "ip:ip4_global"), ("x192.0.2.4y", "xip4_globaly"), ("192.0.2.4.", "ip4_global."),
                ("ip=2001:db8:ffff:12", "ip=ip6_fragment"), ("a4:83:e7:1c:2d:3f", "ip6_fragment"),
                ("::ffff:198.18.0.9", "::ffff:198.18.0.9"), ("198.19.255.2 198.18.0.9", "198.19.255.2 198.18.0.9"),
                ("fd00:ae61::1/120 default:UGcIg,fd00:ae61::/120:UC", "fd00:ae61::1/120 default:UGcIg,fd00:ae61::/120:UC"),
                ("2026-10-27T08:00:00Z 06:30:00.000 [4242:1] 4/1144/eof 1.94s 0.1.0/33 en7:v6:tcp_out:ack_only:8",
                 "2026-10-27T08:00:00Z 06:30:00.000 [4242:1] 4/1144/eof 1.94s 0.1.0/33 en7:v6:tcp_out:ack_only:8"),
                ("line 1 203.0.113.7\nline 2 192.0.2.1\n", "line 1 relay_addr\nline 2 ip4_global\n")):
            with self.subTest(text=text):
                self.assertEqual(self.mask(text, *relays), expected)
        # Without a relay every address is only its class; masking twice is
        # the same as once.
        self.assertEqual(self.mask("ip=203.0.113.7"), "ip=ip4_global")
        self.assertEqual(self.mask(self.mask("a 203.0.113.7 b 2001:db8::1", RELAY_IP), RELAY_IP),
                         "a relay_addr b ip6_global")
        out = subprocess.run([SYSTEM_PY, "-I", str(ADDR_MASK), "--bogus"], input="", capture_output=True, text=True,
                             timeout=30)
        self.assertEqual(out.returncode, 2)


def review_line(t, event, *fields, process="aegis-ne-provider[4242:1]"):
    return f"{t}.000 Df {process} [dev.aegis.macos.PacketTunnel] aegis-ne {event} {' '.join(fields)}".rstrip() + "\n"


def at(minute, second):
    return "2026-10-27 10:%02d:%02d" % (minute, second)


def filter_report(next_out, kinds, marked, entries=()):
    zero = {"ack_only": 0, "data": 0, "fin": 0, "non_tcp": 0, "other": 0, "rst": 0, "syn": 0, "syn_ack": 0}
    obs = {"ring": {"next": 0, "skipped": 0, "torn": 0, "entries": []},
           "outbound": {"kinds": {"primary": dict(zero, ack_only=kinds), "en_other": dict(zero)},
                        "marked": {"primary": dict(zero, ack_only=marked), "en_other": dict(zero)},
                        "ring": {"next": next_out, "skipped": 0, "torn": 0, "entries": list(entries)}}}
    return ("filter_result=ok exit_code=0 mode=guarding dropped=1 allowed=2\n"
            + json.dumps({"report": {"mode": "guarding", "observability": obs}, "schema": "aegis-ne-xpc-v1",
                          "verb": "filter-status"}) + "\n")


def out_entry(index, marked=False):
    return {"arm_seq": 3, "class": "primary", "dir": "out", "family": "v6", "iface": "en7", "index": index,
            "marked": marked, "ms": 1000 + index, "proto": 6, "reason": "drop_tcp_out", "tcp": "ack_only"}


class LoadReviewTests(unittest.TestCase):
    """harness/load_review.py alone on synthetic provider logs, filter reads
    and rows: the window from 10:00:00, the load from 10:01:00 to 10:03:00."""

    def review(self, log="", load_log="", before=None, after=None, results="", span=(at(0, 0), at(1, 0), at(3, 0))):
        with tempfile.TemporaryDirectory(prefix="aegis-load-review-") as temp:
            root = pathlib.Path(temp)
            for name, text in (("provider.log", log), ("load-provider.log", load_log), ("results.tsv", results)):
                (root / name).write_text(text)
            for name, text in (("before.txt", before), ("after.txt", after)):
                if text is not None:
                    (root / name).write_text(text)
            out = subprocess.run([SYSTEM_PY, "-I", str(LOAD_REVIEW), "--provider-log", str(root / "provider.log"),
                                  "--load-log", str(root / "load-provider.log"), "--window-from", span[0],
                                  "--load-from", span[1], "--load-to", span[2], "--filter-before",
                                  str(root / "before.txt"), "--filter-after", str(root / "after.txt"), "--results",
                                  str(root / "results.tsv")], capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        rows = [line.split("\t") for line in out.stdout.splitlines()]
        self.assertEqual([r[0] for r in rows], LOAD_REVIEW_ROWS)
        for r in rows:
            self.assertIn(r[1], ("info", "unavailable"), r)
        return {r[0]: (r[1], r[2]) for r in rows}

    def counters_log(self):
        """Guarding blocks every 10 s from 10:00:05 to 10:03:05 (an open one
        at 10:00:00): 1000 relay packets a block before the load and 20000
        under it, 15 non-IP drops a block throughout, one outbound TCP drop
        a block before the load only. Another process's lines are left out."""
        text = review_line(at(0, 0), "filter_counters_state", "mode:open", "attached:true")
        text += review_line(at(0, 0), "filter_counters", "allow_relay:5", "drop_non_ip:1")
        relay, non_ip, tcp_out = 1000, 100, 10
        for k in range(19):
            minute, second = divmod(5 + 10 * k, 60)
            t = at(minute, second)
            text += review_line(t, "filter_counters_state", "mode:guarding", "attached:true")
            text += review_line(t, "filter_counters", "allow_tunnel_iface:9", "allow_relay:%d" % relay,
                                "allow_nd:3", "drop_non_ip:%d" % non_ip)
            text += review_line(t, "filter_counters", "drop_tcp_out:%d" % tcp_out)
            text += review_line(t, "filter_counters", "allow_relay:1", "drop_non_ip:1",
                                process="aegis_network_extension-0a1b2c3d[999:1]")
            relay += 1000 if (5 + 10 * k) < 55 else 20000
            non_ip += 15
            tcp_out += 1 if (5 + 10 * k) < 55 else 0
        return text

    def test_the_filter_series_before_and_during_the_load(self):
        rows = self.review(log=self.counters_log())
        self.assertEqual(rows["load_filter_series"], (
            "info", "intervals=5/12 before_s=50.0 during_s=120.0 allow_relay_per_s=100.00->2000.00 "
                    "drops_per_s=1.60->1.50 corr_drops_vs_relay=-1.00 torn_malformed_fragment_during=0 "
                    "drop_non_ip=1.50->1.50 drop_tcp_out=0.10->0.00"))
        # The load's own read stands in when the window's has no load lines.
        rows = self.review(log="", load_log=self.counters_log())
        self.assertEqual(rows["load_filter_series"][0], "info")
        rows = self.review(log=review_line(at(1, 5), "pool_state", "conns:1-0-0", "streams:1", "waiting:1"))
        self.assertEqual(rows["load_filter_series"], ("unavailable", "no_filter_counters_blocks blocks=0"))

    def test_the_outbound_ring_records_of_the_load(self):
        before = filter_report(10, 10, 0)
        after = filter_report(18, 18, 1, [out_entry(i, marked=(i == 12)) for i in range(0, 18)])
        rows = self.review(before=before, after=after)
        self.assertEqual(rows["load_outbound_drops"], (
            "info", "new=8 recorded=8 overflow=0 records=en7:v6:tcp_out:ack_only:8 marked_records=1 "
                    "kinds=primary:ack_only:+8 marked=primary:ack_only:+1"))
        after = filter_report(90, 90, 0, [out_entry(i) for i in range(26, 90)])
        rows = self.review(before=before, after=after)
        self.assertTrue(rows["load_outbound_drops"][1].startswith("new=80 recorded=64 overflow=16 "),
                        rows["load_outbound_drops"])
        rows = self.review(before=before, after=None)
        self.assertEqual(rows["load_outbound_drops"], ("unavailable", "outbound_unexposed"))

    def test_the_bulk_flows_placement_and_the_collision_case(self):
        one_each = "".join(review_line(at(2, 50), "flow_bulk", "conn:%d" % c, "kib:51200", "ms:100000", "win_kib:1024")
                           for c in (1, 2, 3, 4))
        rows = self.review(log=one_each)
        self.assertEqual(rows["load_placement"], (
            "info", "bulk_flows=4 conns=4 per_conn=1:1,2:1,3:1,4:1 max_concurrent_per_conn=1 overlapping_pairs=0 "
                    "collision_case=not_exercised win_kib_max=1024 load_flows=unknown load_win_kib=unknown "
                    "flow_mbit_s=1:4.2,2:4.2,3:4.2,4:4.2"))
        # Two overlapping bulk flows on conn 1, two in turn on conn 2; one
        # before the load and one after its tail are left out.
        shared = (review_line(at(0, 30), "flow_bulk", "conn:7", "kib:2048", "ms:2000", "win_kib:128")
                  + review_line(at(2, 50), "flow_bulk", "conn:1", "kib:25600", "ms:100000", "win_kib:256")
                  + review_line(at(2, 55), "flow_bulk", "conn:1", "kib:25600", "ms:110000", "win_kib:512")
                  + review_line(at(1, 30), "flow_bulk", "conn:2", "kib:5120", "ms:20000", "win_kib:128")
                  + review_line(at(2, 50), "flow_bulk", "conn:2", "kib:20480", "ms:60000", "win_kib:128")
                  + review_line(at(3, 40), "flow_bulk", "conn:3", "kib:2048", "ms:1000", "win_kib:128"))
        rows = self.review(log=shared)
        self.assertEqual(rows["load_placement"], (
            "info", "bulk_flows=4 conns=2 per_conn=1:2,2:2 max_concurrent_per_conn=2 overlapping_pairs=1 "
                    "collision_case=exercised win_kib_max=512 load_flows=unknown load_win_kib=unknown "
                    "flow_mbit_s=1:2.1,1:1.9,2:2.1,2:2.8"))
        # v34 review: the load streams' own lines, the flows that moved at
        # least one stream's cap (load_download's per_stream=), in end order.
        download = "load_download\tpass\tok=2/2 bytes=52428800/52428800 per_stream=26214400 elapsed_max=99.0s\tC\tx\ty\n"
        rows = self.review(log=shared, results=download)
        self.assertIn(" win_kib_max=512 load_flows=2 load_win_kib=256,512 ", rows["load_placement"][1])
        download = download.replace("per_stream=26214400", "per_stream=52428800")
        rows = self.review(log=one_each + shared, results=download)
        self.assertIn(" load_flows=4 load_win_kib=1024,1024,1024,1024 ", rows["load_placement"][1])
        rows = self.review(log=shared, results=download)
        self.assertIn(" load_flows=0 load_win_kib=none ", rows["load_placement"][1])
        rows = self.review(log="")
        self.assertEqual(rows["load_placement"], ("unavailable", "no_flow_bulk_lines"))

    def test_the_stream_window_during_the_load(self):
        log = (review_line(at(0, 40), "pool_window", "grown:0", "max_kib:128", "budget_kib:0-7168", "denied:2")
               + review_line(at(1, 30), "pool_window", "grown:2", "max_kib:512", "budget_kib:768-7168", "denied:2")
               + review_line(at(2, 30), "pool_window", "grown:4", "max_kib:1024", "budget_kib:3584/7168", "denied:5")
               + review_line(at(5, 0), "pool_window", "grown:9", "max_kib:2048", "budget_kib:7168-7168", "denied:9"))
        rows = self.review(log=log)
        self.assertEqual(rows["load_window"], (
            "info", "lines=2 grown_max=4 max_kib_max=1024 above_initial=yes budget_kib_max=3584/7168 denied_last=5 "
                    "denied_in_load=3"))
        rows = self.review(log=review_line(at(1, 30), "pool_window", "grown:0", "max_kib:128", "budget_kib:0-7168",
                                           "denied:0"))
        self.assertIn(" above_initial=no ", rows["load_window"][1])
        rows = self.review(log=log.splitlines(keepends=True)[0])
        self.assertEqual(rows["load_window"], ("unavailable", "no_pool_window_lines before=1"))

    def test_the_latency_before_and_under_the_load(self):
        results = "".join("\t".join(r) + "\tConnected\tx\ty\n" for r in (
            ("flow_burst_24", "pass", "24/24 1.94s"), ("flow_burst_90", "pass", "90/90 4.32s"),
            ("tcp_echo_v4_warm", "pass", "4/1144/eof"), ("load_flow_burst_24", "pass", "24/24 2.29s"),
            ("load_flow_burst_90", "pass", "90/90 3.45s"), ("load_tcp_echo_v4", "pass", "4/722/eof")))
        log = (review_line(at(0, 20), "pool_detail", "oldest_ms:0", "sndq_kib:1", "hs_ms:500-700")
               + review_line(at(1, 10), "pool_detail", "oldest_ms:0", "sndq_kib:1", "hs_ms:480-650")
               + review_line(at(1, 11), "pool_detail", "oldest_ms:900", "sndq_kib:4", "hs_ms:520-760")
               + review_line(at(0, 30), "pool_rtt", "conn:1", "min_ms:180", "srtt_ms:185", "last_ms:190")
               + "".join(review_line(at(1, 20 + k), "pool_rtt", "conn:1", "min_ms:180", "srtt_ms:%d" % (190 + k),
                                     "last_ms:%d" % (200 + 10 * k)) for k in range(10))
               # A line without a sample since the one before: no last_ms.
               + review_line(at(1, 31), "pool_rtt", "conn:1", "min_ms:180", "srtt_ms:199")
               + review_line(at(1, 40), "pool_rtt", "conn:9", "min_ms:20", "srtt_ms:25", "last_ms:900")
               + review_line(at(2, 50), "flow_bulk", "conn:1", "kib:51200", "ms:100000", "win_kib:1024"))
        rows = self.review(log=log, results=results)
        self.assertEqual(rows["load_latency"], (
            "info", "burst24_s=1.94->2.29 burst90_s=4.32->3.45 tcp_echo_ms=1144->722 hs_p50_ms_max=500->520 "
                    "hs_p90_ms_max=700->760 rtt_lines=11 rtt_conns=bulk:1 min_ms_p50=180 min_ms_p90=180 "
                    "srtt_ms_p50=195 srtt_ms_p90=199 last_ms_p50=240 last_ms_p90=280 rtt_samples=10 "
                    "rtt_queue_ms_p50=60 rtt_queue_ms_p90=100 last_ms_before_p50=190"))
        rows = self.review()
        self.assertEqual(rows["load_latency"], ("unavailable", "no_latency_samples"))

    def test_an_unreadable_span_writes_every_row_unavailable(self):
        rows = self.review(log=self.counters_log(), span=("x", at(1, 0), at(3, 0)))
        self.assertEqual(set(rows.values()), {("unavailable", "load_span_unreadable")})

    def endurance(self, log):
        with tempfile.TemporaryDirectory(prefix="aegis-load-review-") as temp:
            path = pathlib.Path(temp) / "endurance-provider.log"
            path.write_text(log)
            out = subprocess.run([SYSTEM_PY, "-I", str(LOAD_REVIEW), "--endurance-log", str(path)],
                                 capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        rows = [line.split("\t") for line in out.stdout.splitlines()]
        self.assertEqual([r[0] for r in rows], ["endurance_window"])
        return tuple(rows[0][1:])

    def test_the_endurance_window_row_reads_the_budget_across_the_run(self):
        # v34 review (critic B4): long-lived flows across an ENDURANCE=1 run.
        log = (review_line(at(0, 40), "pool_window", "grown:1", "max_kib:512", "budget_kib:384-7168", "denied:0")
               + review_line(at(30, 0), "pool_window", "grown:3", "max_kib:1024", "budget_kib:2304-7168", "denied:2")
               + review_line(at(31, 0), "pool_window", "grown:1", "max_kib:256", "budget_kib:128-7168", "denied:2",
                             process="aegis_network_extension-0a1b2c3d[999:1]")
               + review_line(at(59, 0), "pool_window", "grown:0", "max_kib:128", "budget_kib:0/7168", "denied:4"))
        self.assertEqual(self.endurance(log), (
            "info", "lines=3 grown_max=3 grown_last=0 max_kib_max=1024 budget_kib_max=2304/7168 "
                    "budget_kib_last=0/7168 denied_last=4"))
        self.assertEqual(self.endurance(review_line(at(0, 40), "pool_state", "conns:1-0-0", "streams:1", "waiting:0")),
                         ("unavailable", "no_pool_window_lines"))
        # The load rows still need their arguments.
        out = subprocess.run([SYSTEM_PY, "-I", str(LOAD_REVIEW), "--provider-log", "x"], capture_output=True,
                             text=True, timeout=30)
        self.assertEqual((out.returncode, out.stdout), (2, ""))


    def test_the_connections_credit_loop_delay_and_the_load_streams_zones(self):
        # H3 (v35): load_queue per bulk connection from pool_queue and
        # pool_rtt lines of the load, and the load streams' flow_queue
        # lines (paired with the flow_bulk line right before each).
        log = (review_line(at(0, 30), "pool_queue", "conn:0", "q_ms:900", "held_kib:999", "extra_kib:9")
               + review_line(at(1, 10), "pool_rtt", "conn:0", "min_ms:190", "srtt_ms:300", "last_ms:400")
               + review_line(at(1, 10), "pool_queue", "conn:0", "q_ms:none", "held_kib:100", "extra_kib:0")
               + review_line(at(1, 20), "pool_rtt", "conn:0", "min_ms:180", "srtt_ms:300")
               + review_line(at(1, 20), "pool_queue", "conn:0", "q_ms:360", "held_kib:120", "extra_kib:0")
               + review_line(at(1, 30), "pool_queue", "conn:0", "q_ms:180", "held_kib:140", "extra_kib:64")
               + review_line(at(1, 40), "pool_queue", "conn:0", "q_ms:20", "held_kib:300", "extra_kib:200")
               + review_line(at(1, 20), "pool_rtt", "conn:1", "min_ms:200", "srtt_ms:210")
               + review_line(at(1, 20), "pool_queue", "conn:1", "q_ms:40", "held_kib:500", "extra_kib:384")
               + review_line(at(2, 50), "flow_bulk", "conn:0", "kib:51300", "ms:100000", "win_kib:300")
               + review_line(at(2, 50), "flow_queue", "conn:0", "q_bins:10-5-2", "grows:3", "resets:0-1")
               + review_line(at(2, 51), "flow_bulk", "conn:1", "kib:2048", "ms:1000", "win_kib:128")
               + review_line(at(2, 51), "flow_queue", "conn:1", "q_bins:1-0-0", "grows:0", "resets:0-0")
               + review_line(at(2, 52), "flow_bulk", "conn:1", "kib:51250", "ms:100000", "win_kib:500")
               + review_line(at(2, 52), "flow_queue", "conn:1", "q_bins:30-1-0", "grows:5", "resets:0-0"))
        rows = self.review(log=log)
        self.assertEqual(rows["load_queue"], (
            "info", "conns=2 0:q180/360:held120/300:x200:bdp2.0/3.0:sx33 1:q40/40:held500/500:x384:bdp1.2/1.2:sx0 "
                    "load_flows=0:10-5-2:g3:r0-1,1:1-0-0:g0:r0-0,1:30-1-0:g5:r0-0"))
        download = "load_download\tpass\tok=2/2 bytes=104857600/104857600 per_stream=52428800 elapsed_max=99.0s\tC\tx\ty\n"
        rows = self.review(log=log, results=download)
        self.assertTrue(rows["load_queue"][1].endswith(" load_flows=0:10-5-2:g3:r0-1,1:30-1-0:g5:r0-0"),
                        rows["load_queue"])
        rows = self.review(log="")
        self.assertEqual(rows["load_queue"], ("unavailable", "no_pool_queue_lines"))

    def test_the_takes_of_the_load(self):
        # H3 (v35): load_takes sums the pool_take lines of the load.
        log = (review_line(at(0, 30), "pool_take", "n:50", "queued:50", "conns_queued:4-4")
               + review_line(at(1, 5), "pool_take", "n:10", "queued:2", "conns_queued:1-4")
               + review_line(at(1, 6), "pool_take", "n:5", "queued:0", "conns_queued:2-3")
               + review_line(at(2, 0), "pool_take", "n:5", "queued:1", "conns_queued:0-4")
               + review_line(at(2, 1), "pool_take", "n:x", "queued:1", "conns_queued:0-4"))
        rows = self.review(log=log)
        self.assertEqual(rows["load_takes"], ("info", "lines=3 n=20 queued=3 share=0.15 conns_queued_max=2-3"))
        rows = self.review(log="")
        self.assertEqual(rows["load_takes"], ("unavailable", "no_pool_take_lines"))


if __name__ == "__main__":
    unittest.main()
