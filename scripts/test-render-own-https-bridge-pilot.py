#!/usr/bin/env python3
"""Inert source contracts for the jump-host HTTPS bridge pilot renderer."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("render-own-https-bridge-pilot.py")
SPEC = importlib.util.spec_from_file_location("ownbridge_pilot", SCRIPT)
PILOT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PILOT)
ROOT = Path(__file__).resolve().parents[1]
SOURCE = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                 text=True).strip()


def pins():
    result = {name: hashlib.sha256(name.encode()).hexdigest()
              for name in PILOT.KEY_PINS}
    result["authority_admission"] = result["relay_admission"]
    return result


def files(p=None):
    return PILOT.render(SOURCE, "a" * 64, "b" * 64, "c" * 32, pins() if p is None else p)


class PilotSourceContract(unittest.TestCase):
    def test_roles_endpoints_inner_tls_and_no_secret_bytes(self):
        rendered = files()
        relay = tomllib.loads(rendered["relay.toml"])
        authority = tomllib.loads(rendered["authority.toml"])
        intent = json.loads(rendered["intent.json"])
        self.assertEqual(relay["listen"], "198.51.100.171:443")
        self.assertEqual(authority["listen"], "198.51.100.171:8443")
        self.assertEqual(relay["auth_token"], "")
        self.assertEqual(relay["fallback"], "close")
        self.assertFalse(relay["transport"]["quic_required"])
        self.assertEqual(relay["transport"]["inner_tls"]["device_registry"],
                         authority["issuer"]["registry"])
        self.assertEqual(relay["transport"]["https_bridge"]["carrier"]["authority"],
                         authority["https_bridge"]["carrier"]["authority"])
        self.assertEqual(intent["tls_name"], "bridge.example.com")
        self.assertEqual(intent["relay_endpoint"], "198.51.100.171:443")
        self.assertEqual(intent["authority_endpoint"], "198.51.100.171:8443")
        self.assertNotEqual(relay["transport"]["https_bridge"]["carrier"]["credential_file"],
                            authority["https_bridge"]["carrier"]["credential_file"])
        self.assertEqual(intent["private_material_sha256_expected_unverified"]["relay_admission"],
                         intent["private_material_sha256_expected_unverified"]["authority_admission"])
        self.assertNotEqual(relay["key"], authority["outer_key"])
        self.assertNotEqual(relay["transport"]["inner_tls"]["key"], authority["inner_tls"]["key"])
        self.assertNotEqual(authority["issuer"]["ca_key"], authority["outer_key"])
        self.assertEqual(authority["issuer"]["profile_sha256"], "b" * 64)
        self.assertFalse(intent["binary_verified"])
        self.assertFalse(intent["config_check_executed"])
        self.assertFalse(intent["host_mutation"])
        self.assertEqual(set(intent["rendered_sha256"]), set(rendered) - {"intent.json"})

    def test_rollback_only_names_own_units_and_is_bounded(self):
        rendered = files()
        intent = json.loads(rendered["intent.json"])
        rollback = rendered["rollback.sh"]
        for unit in (intent["relay_unit"], intent["authority_unit"]):
            self.assertIn(unit, rollback)
        self.assertEqual(rollback.count("/usr/bin/systemctl stop"), 1)
        for forbidden in ("sshd", "reverse", "nft", "iptables", "ufw", "ip route",
                          "daemon-reload", "aegis-server.service", "aegis-client.service"):
            self.assertNotIn(forbidden, rollback)
        self.assertIn("OnActiveSec=6900s", rendered[intent["rollback_timer"]])
        self.assertIn("RuntimeMaxSec=7200s", rendered[intent["relay_unit"]])
        self.assertIn("RuntimeMaxSec=7200s", rendered[intent["authority_unit"]])
        self.assertIn("KillMode=control-group", rendered[intent["relay_unit"]])
        self.assertNotIn("[Install]", rendered[intent["relay_unit"]])

    def test_each_service_masks_the_other_private_role(self):
        rendered = files()
        intent = json.loads(rendered["intent.json"])
        stage = intent["remote_stage"]
        relay = rendered[intent["relay_unit"]]
        authority = rendered[intent["authority_unit"]]
        self.assertIn(f"InaccessiblePaths={stage}/private/authority\n", relay)
        self.assertIn(f"InaccessiblePaths={stage}/private/relay\n", authority)
        self.assertNotIn(f"InaccessiblePaths={stage}/state", relay)
        for service in (relay, authority):
            self.assertIn("NoNewPrivileges=yes\n", service)
            self.assertIn("CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n", service)
            self.assertIn("AmbientCapabilities=CAP_NET_BIND_SERVICE\n", service)

    def test_invalid_or_reused_key_pins_refuse(self):
        p = pins()
        p["authority_admission"] = hashlib.sha256(b"different-admission").hexdigest()
        with self.assertRaisesRegex(ValueError, "bridge_key_pin_relationship_required"):
            files(p)
        p = pins()
        p["relay_inner_key"] = p["relay_admission"]
        with self.assertRaisesRegex(ValueError, "bridge_key_pin_relationship_required"):
            files(p)
        p = pins()
        p.pop("issuer_ca_key")
        with self.assertRaisesRegex(ValueError, "bridge_key_pin_relationship_required"):
            files(p)
        with self.assertRaisesRegex(ValueError, "source_artifact_profile_or_nonce_shape"):
            PILOT.render(SOURCE, "a" * 63, "b" * 64, "c" * 32, pins())
        with self.assertRaisesRegex(ValueError, "source_artifact_profile_or_nonce_shape"):
            PILOT.render(SOURCE, "a" * 64, "b" * 64, "x" * 32, pins())
        with self.assertRaisesRegex(ValueError, "source_checkout_or_renderer_not_exact"):
            PILOT.render("0" * 40, "a" * 64, "b" * 64, "c" * 32, pins())
        with self.assertRaisesRegex(ValueError, "source_checkout_or_renderer_not_exact"):
            PILOT.render("5b477fe73b54bc711c59ffa611762569af005cd9",
                         "a" * 64, "b" * 64, "c" * 32, pins())

    def test_private_unique_output_and_pin_input(self):
        with tempfile.TemporaryDirectory(prefix="aegis-ownbridge-pilot-",
                                         dir="/private/tmp") as scratch:
            parent = Path(scratch)
            os.chmod(parent, 0o700)
            pinfile = parent / "pins.json"
            pinfile.write_text(json.dumps(pins()))
            pinfile.chmod(0o600)
            self.assertEqual(json.loads(PILOT.private_file(pinfile)), pins())
            output = parent / "rendered"
            PILOT.write(output, files())
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600
                                for path in output.iterdir()))
            with self.assertRaisesRegex(ValueError, "private_new_output_required"):
                PILOT.write(output, files())
            linked = parent / "linked"
            linked.symlink_to(output, target_is_directory=True)
            with self.assertRaises((OSError, ValueError)):
                PILOT.write(linked / "redirected", files())
            pinlink = parent / "pinlink.json"
            pinlink.symlink_to(pinfile)
            with self.assertRaises((OSError, ValueError)):
                PILOT.private_file(pinlink)
            pinfile.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "private_pin_file_required"):
                PILOT.private_file(pinfile)
            pinfile.chmod(0o600)
            parent.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "private_new_output_required"):
                PILOT.write(parent / "public", files())

    def test_output_path_replaced_after_held_directory_write_refuses(self):
        with tempfile.TemporaryDirectory(prefix="aegis-ownbridge-swap-",
                                         dir="/private/tmp") as scratch:
            parent = Path(scratch)
            output = parent / "rendered"
            original_fsync = os.fsync
            swapped = False

            def swap_after_output_sync(fd):
                nonlocal swapped
                original_fsync(fd)
                if stat.S_ISDIR(os.fstat(fd).st_mode) and not swapped:
                    swapped = True
                    output.rename(parent / "displaced")
                    output.mkdir(mode=0o700)

            with patch.object(PILOT.os, "fsync", side_effect=swap_after_output_sync):
                with self.assertRaisesRegex(ValueError, "new_output_identity_changed"):
                    PILOT.write(output, files())
            self.assertTrue(swapped)


if __name__ == "__main__":
    unittest.main()
