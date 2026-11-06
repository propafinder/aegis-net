#!/usr/bin/env python3
"""Execute guard-only publication and refusal boundaries with inert effects."""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "install.sh").read_text()


def function(source, name):
    signature = name + "() {" if name + "() {" in source else name + "() ("
    start = source.index(signature)
    after_signature = source.index("\n", start) + 1
    following = re.search(r"(?m)^[A-Za-z_][A-Za-z_0-9]*\(\) [({]", source[after_signature:])
    end = after_signature + following.start() if following else len(source)
    return source[start:end].rstrip()


def host_python(source, name):
    body = function(source, name)
    return body.split("python3 -I -c '", 1)[1].rsplit("' \"$WIDE_INTERFACE\"", 1)[0]


def syntax_shape(node):
    """Keep every syntax value; omit version-dependent empty AST fields.

    Python 3.13 changed ast.dump's empty-field display and newer Python adds
    empty type-parameter fields. Neither changes this host assessment body.
    """
    if isinstance(node, ast.AST):
        return [type(node).__name__, [[key, syntax_shape(value)]
                for key, value in ast.iter_fields(node)
                if value is not None and value != []]]
    if isinstance(node, list):
        return [syntax_shape(item) for item in node]
    return node


class FirstArmContract(unittest.TestCase):
    def test_shared_host_and_boot_checks_are_preserved(self):
        # Reviewed B-03-FINAL source bodies. The additive dracut branch,
        # shared cloud-init admission, semantic UFW admission and scoped-IPv6 ss listener parsing change
        # these bodies. r21: the cloud-init refusal is the policy module's one
        # typed CloudInitRefusal JSON (byte-identical to the detector's). The 41/123/60
        # behavioural archive cases independently retain the historical refusals;
        # this digest detects any later unreviewed extraction/shape change.
        host = json.dumps(syntax_shape(ast.parse(host_python(
            SOURCE, "device_assess_guard_host"))), separators=(",", ":"))
        self.assertEqual(hashlib.sha256(host.encode()).hexdigest(),
                         "17d57417d49266aecf3811bc0f47cd01cf1f031034aff63b2cf5187d0b9c1699")
        boot = function(SOURCE, "device_verify_initramfs")
        self.assertEqual(hashlib.sha256(boot.encode()).hexdigest(),
                         "1a3039f642de6a6009011d02205d01ea988a9417916bcef91aa0d950fc7fef25")
        self.assertLess(boot.index("verify_cloud_init_boot({})"),
                        boot.index("firmware iSCSI boot table requires separate review"))
        self.assertIn("    except CloudInitRefusal as error:\n        journal_cloud_init_refusal(error)\n        print(cloud_init_refusal_json(error),file=sys.stderr)\n        raise SystemExit(78)", boot)
        self.assertIn("if cloud_state=='disabled_proved':", boot)
        self.assertIn("CLOUD_INIT_SWITCH_ROOT", boot)
        # Owner24 adds only a strict owned-profile dispatch and its volume
        # deadline. Removing that exact addition must retain the reviewed
        # format, cmdline, typed default-image and semantic boot checks.
        # Restore only the exact reviewed r21 cloud prefix, then retain the
        # existing checksum of every legacy archive/cmdline/semantic check.
        cloud_start = boot.index("CLOUD_INDICATORS = (")
        cloud_end = boot.index("need(not pathlib.Path('/sys/firmware/ibft')")
        reviewed_cloud = "module_root=trusted(sys.argv[3])\ntrusted(module_root/'aegis_initrd_policy.py')\ntrusted(module_root/'aegis_auto_foreign_policy.py')\nsys.dont_write_bytecode=True\nsys.path.insert(0,str(module_root))\nfrom aegis_initrd_policy import verify_cloud_init_boot,CloudInitRefusal,cloud_init_refusal_json\n# The detector's cloud-init proof and its one typed refusal (byte-identical\n# JSON on both paths): every active cloud-init is refused; a marker admits\n# only the reviewed disabled profile proved by a normal reboot.\ntry:\n    verify_cloud_init_boot({})\nexcept CloudInitRefusal as error:\n    print(cloud_init_refusal_json(error),file=sys.stderr)\n    raise SystemExit(78)\n"
        boot = boot[:cloud_start] + reviewed_cloud + boot[cloud_end:]
        start = boot.index("# An owned Debian profile has its own complete streamed archive/provenance")
        end = boot.index("# Package metadata is an integrity baseline", start)
        old_boot = (boot[:start] + boot[end:]).replace(
            "subprocess,sys,time\n", "subprocess,sys\n", 1).replace(
            "assessment_start=time.monotonic()\n", "", 1)
        self.assertEqual(hashlib.sha256(old_boot.encode()).hexdigest(),
                         "82481cfd579122a55aa2f7d0f0794ec07191ad5d9a94cf9320db3b91887ef6ed")

    def test_owned_profile_dispatch_follows_original_cmdline_and_image_gates(self):
        boot = function(SOURCE, "device_verify_initramfs")
        dispatch = boot.index("from aegis_initrd_policy import verify_profile")
        for gate in ("firmware iSCSI boot table requires separate review",
                     "ambiguous initramfs family", "root device is not explicit",
                     "default initrd differs from running kernel"):
            self.assertLess(boot.index(gate), dispatch)
        self.assertIn("seconds-(time.monotonic()-assessment_start)", boot)
        self.assertIn("boot=not (len(sys.argv)>2 and sys.argv[2])", boot)

    def test_mode_bound_host_capture_prerequisites(self):
        tree = ast.parse(host_python(SOURCE, "device_assess_guard_host"))
        helper, = (node for node in tree.body if isinstance(node, ast.FunctionDef)
                   and node.name == "capture_prerequisites")
        settings = {"tun": False, "ipv6": False, "ipv4_forward": "0",
                    "ipv6_forward_present": False, "ipv6_forward": "0"}

        class FakePath:
            def __init__(self, name):
                self.name = name

            def is_char_device(self):
                self.assert_path("/dev/net/tun")
                return settings["tun"]

            def exists(self):
                if self.name == "/proc/net/if_inet6":
                    return settings["ipv6"]
                self.assert_path("/proc/sys/net/ipv6/conf/all/forwarding")
                return settings["ipv6_forward_present"]

            def read_text(self):
                if self.name == "/proc/sys/net/ipv4/ip_forward":
                    return settings["ipv4_forward"]
                self.assert_path("/proc/sys/net/ipv6/conf/all/forwarding")
                return settings["ipv6_forward"]

            def assert_path(self, expected):
                if self.name != expected:
                    raise AssertionError(self.name)

        namespace = {"pathlib": types.SimpleNamespace(Path=FakePath),
                     "need": lambda ok, reason: None if ok else
                     (_ for _ in ()).throw(ValueError(reason))}
        exec(compile(ast.Module(body=[helper], type_ignores=[]), "<actual-assessor>", "exec"), namespace)
        assess = namespace["capture_prerequisites"]
        assess("wide-redirect-safe")
        for mode in ("full-wide-tun", "device-full-wide-tun", "unknown"):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                assess(mode)
        settings["tun"] = True
        with self.assertRaises(ValueError):
            assess("full-wide-tun")
        settings["ipv6"] = True
        with self.assertRaises(ValueError):
            assess("full-wide-tun")
        settings["ipv6_forward_present"] = True
        assess("full-wide-tun")
        settings["ipv6_forward"] = "1"
        with self.assertRaises(ValueError):
            assess("wide-redirect-safe")
        settings["ipv6_forward_present"] = False
        with self.assertRaises(ValueError):
            assess("wide-redirect-safe")
        settings["ipv6"] = False
        settings["ipv4_forward"] = "1"
        with self.assertRaises(ValueError):
            assess("wide-redirect-safe")

    def test_v2_callers_bind_mode_and_device_default_stays_legacy(self):
        self.assertIn('| device_assess_guard_host "$boot_proof"',
                      function(SOURCE, "device_assess_full_wide_host"))
        self.assertIn('device_assess_guard_host "$boot_proof" "$mode" <',
                      function(SOURCE, "auto_v2_first_arm"))
        self.assertIn('device_assess_guard_host "$boot_proof" "$AUTO_V2_BOOT_MODE" <',
                      function(SOURCE, "auto_v2_verify_boot_host"))
        self.assertIn("'capture_profile':sys.argv[5]", function(SOURCE, "auto_v2_verify_boot_host"))

    def publication(self, *, admit=True, preflight=True, phase="v2-stage"):
        with tempfile.TemporaryDirectory(prefix="aegis-first-arm-contract-") as temporary:
            root = Path(temporary)
            systemd, helpers = root / "systemd", root / "helpers"
            helpers.mkdir()
            (helpers / "lib").mkdir()
            # Inert snapshot input adapter: this publication test exercises no
            # real host firewall or privileged path, and still records the call.
            (helpers / "lib/aegis_auto_foreign_policy.py").write_text(
                "import sys\nassert sys.argv[1:]==['--snapshot','/var/lib/aegis-install/client/ufw-before-guard.json']\n")
            (root / "scripts/lib").mkdir(parents=True)
            (root / "scripts/lib/root-state.sh").write_text("# inert source\n")
            guard = root / "scripts/aegis-device-egress-guard.sh"
            guard.write_text("#!/bin/bash\n[[ $1 != preflight ]] || exit " + ("0" if preflight else "1") + "\n")
            client = root / "candidate"
            client.write_text("#!/bin/bash\n[[ $1 == profile && $2 == metadata && $3 == read ]] || exit 9\ncat \"$5\"\n")
            client.chmod(0o755)
            assessment = root / "assessment.conf"
            assessment.write_text("schema=aegis_device_guard_v2\nmanager=systemd-networkd.service\n")
            state = root / "owned/device-guard.conf"
            body = function(SOURCE, "install_device_egress_guard_units")
            body = body.replace("/var/lib/aegis-install/client/device-guard.conf", str(state))
            body = body.replace("/etc/systemd/system", str(systemd))
            body = body.replace("/usr/local/lib/aegis/helpers", str(helpers))
            body = body.replace("/usr/bin/timeout", shutil.which("timeout") or "/usr/bin/timeout")
            harness = r'''
set -euo pipefail
ROOT=$1 SYSTEMD_DIR=$2 AEGIS_WIDE_LIB_DIR=$3 AEGIS_ROOT_STATE_CLIENT=$4
AUTO_PROFILE=1 AUTO_V2_FIRST_ARM_ADMITTED=$5
install_copy_file() { cp "$1" "$2"; chmod "$3" "$2"; }
install_atomic_write() { mkdir -p "$(dirname "$1")"; cat >"$1"; chmod "$2" "$1"; }
systemctl() { printf '%s\n' "$*" >>"$ROOT/systemctl.log"; }
'''
            script = root / "invoke.sh"
            script.write_text(harness + "\n" + body + "\ninstall_device_egress_guard_units \"$6\" systemd-networkd.service admitted-v2-settings \"$7\" \"$8\"\n")
            result = subprocess.run(["bash", str(script), str(root), str(systemd), str(helpers), str(client),
                                     "1" if admit else "0", str(state), str(assessment), phase],
                                    capture_output=True, timeout=10)
            files = {str(path.relative_to(systemd)): path.read_text()
                     for path in systemd.rglob("*") if path.is_file()}
            calls = (root / "systemctl.log").read_text().splitlines() if (root / "systemctl.log").exists() else []
            client_namespace = (systemd / "aegis-client.service.d").exists()
            return result.returncode, files, calls, client_namespace

    def test_guard_only_stage_never_creates_client_namespace_or_starts_guard(self):
        code, files, calls, namespace = self.publication()
        self.assertEqual(code, 0)
        self.assertEqual(set(files), {"aegis-device-egress-guard.service",
                                     "systemd-networkd.service.d/30-aegis-device-guard.conf"})
        self.assertFalse(namespace)
        # The installed guardian authenticates literal guard-unit bytes. Test
        # the real publisher against that separate consumer, normalizing only
        # the two disposable paths substituted by this harness.
        guardian = ast.parse((ROOT / "scripts/lib/aegis_auto_guardian.py").read_text())
        expected, = [ast.literal_eval(node.value) for node in guardian.body
                     if isinstance(node, ast.Assign) and
                     any(isinstance(target, ast.Name) and target.id == "EXPECTED_GUARD_UNIT"
                         for target in node.targets)]
        actual = files["aegis-device-egress-guard.service"]
        actual, count = re.subn(r"(?m)^Environment=AEGIS_DEVICE_GUARD_STATE=[^\n]+$",
                               "Environment=AEGIS_DEVICE_GUARD_STATE=/var/lib/aegis-install/client/device-guard.conf",
                               actual)
        self.assertEqual(count, 1)
        actual, count = re.subn(r"(?m)^ExecStart=/bin/bash [^\n]+ block$",
                               "ExecStart=/bin/bash /usr/local/lib/aegis/helpers/aegis-device-egress-guard.sh block",
                               actual)
        self.assertEqual(count, 1)
        self.assertEqual(actual.encode(), expected)
        self.assertIn("bind-manager", files["systemd-networkd.service.d/30-aegis-device-guard.conf"])
        self.assertIn("manager-ready", files["systemd-networkd.service.d/30-aegis-device-guard.conf"])
        self.assertEqual(calls, ["daemon-reload", "enable aegis-device-egress-guard.service aegis-foreign-policy-monitor.service aegis-auto-clean-shutdown.service aegis-device-dhcp-refresh.timer"])

    def test_missing_admission_and_failed_kernel_preflight_publish_nothing(self):
        for options in ({"admit": False}, {"preflight": False}, {"phase": "unknown"}):
            with self.subTest(options=options):
                code, files, calls, namespace = self.publication(**options)
                self.assertNotEqual(code, 0)
                self.assertEqual(files, {})
                self.assertEqual(calls, [])
                self.assertFalse(namespace)


if __name__ == "__main__":
    unittest.main()
