"""Offline tests for fronted_zone.py against an in-memory Cloudflare API.

No network, no real token, no real zone. Run:
  python3 -I -m unittest discover -s tools/cloudflare -p 'test_*.py'
"""
import contextlib
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import fronted_zone as fz  # noqa: E402

TOKEN = "T" * 40
KEY = "ab" * 32


class FakeCloudflare:
    def __init__(self, fail_on=None):
        self.zone = "zone-1"
        self.records = []
        self.settings = {name: "off" for name in list(fz.SETTINGS) + ["ech"]}
        self.settings.update({"ssl": "full", "min_tls_version": "1.0"})
        self.bot = {"fight_mode": False}
        self.rulesets = {fz.TRANSFORM_PHASE: {"id": "rs-t", "rules": [
            {"id": "keep-1", "description": "existing operator rule", "expression": "true",
             "action": "rewrite"}]}}
        self.certificates = {}
        self.calls = []
        self.fail_on = fail_on
        self.counter = 0

    def next_id(self, prefix):
        self.counter += 1
        return f"{prefix}-{self.counter}"

    def __call__(self, method, url, body, headers):
        assert headers["Authorization"] == "Bearer " + TOKEN
        path = url[len(fz.API):]
        payload = json.loads(body) if body else None
        self.calls.append((method, path.split("?")[0]))
        if self.fail_on and self.fail_on(method, path):
            return 403, json.dumps({"success": False, "errors": [{"code": 10000, "message": "denied"}]}).encode()
        result = self.route(method, path, payload)
        if result is FileNotFoundError:
            return 404, json.dumps({"success": False, "errors": []}).encode()
        return 200, json.dumps({"success": True, "result": result}).encode()

    def route(self, method, path, payload):
        z = f"/zones/{self.zone}"
        if method == "GET" and path.startswith("/zones?name="):
            return [{"id": self.zone}]
        if path.startswith(z + "/dns_records"):
            if method == "GET":
                name = path.split("name=")[1]
                return [r for r in self.records if r["name"] == name]
            if method == "POST":
                record = dict(payload, id=self.next_id("dns"))
                self.records.append(record)
                return record
            if method == "DELETE":
                rid = path.rsplit("/", 1)[1]
                self.records = [r for r in self.records if r["id"] != rid]
                return {"id": rid}
        if path.startswith(z + "/settings/"):
            name = path.rsplit("/", 1)[1]
            if method == "PATCH":
                self.settings[name] = payload["value"]
            return {"id": name, "value": self.settings[name]}
        if path == z + "/bot_management":
            if method == "PUT":
                self.bot.update(payload)
            return dict(self.bot)
        if path.startswith(z + "/rulesets/phases/"):
            phase = path.split("/")[5]
            if method == "GET":
                return self.rulesets.get(phase, FileNotFoundError)
            if method == "PUT":
                rules = [dict(r, id=self.next_id("rule")) for r in payload["rules"]]
                self.rulesets[phase] = {"id": self.next_id("rs"), "rules": rules}
                return self.rulesets[phase]
        if path.startswith(z + "/rulesets/"):
            parts = path.split("/")
            ruleset = parts[4]
            entry = next(v for v in self.rulesets.values() if v["id"] == ruleset)
            if method == "POST":
                entry["rules"].append(dict(payload, id=self.next_id("rule")))
                return entry
            if method == "DELETE":
                entry["rules"] = [r for r in entry["rules"] if r["id"] != parts[6]]
                return entry
        if path == "/certificates" and method == "POST":
            cid = self.next_id("cert")
            self.certificates[cid] = payload
            return {"id": cid, "certificate": "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n"}
        if path.startswith("/certificates/") and method == "DELETE":
            self.certificates.pop(path.rsplit("/", 1)[1])
            return {}
        raise AssertionError(f"unexpected {method} {path}")


class Args:
    zone = "example.test"
    host = "relay"


class FrontedZoneTests(unittest.TestCase):
    def roundtrip(self, fake, ech=True):
        client = fz.Client(TOKEN, fake)
        before = json.loads(json.dumps({"records": fake.records, "settings": fake.settings,
                                        "bot": fake.bot, "rulesets": fake.rulesets}))
        state = fz.snapshot(client, Args)
        saved = fz.plan(state, "203.0.113.10", fz.hashlib.sha256(KEY.encode()).hexdigest(), ech)
        record = {"created": [], "changed_settings": [], "changed_bot_management": False,
                  "completed_steps": 0}
        return client, before, state, saved, record

    def test_apply_verify_and_rollback_restore_exact_prior_state(self):
        fake = FakeCloudflare()
        client, before, state, saved, record = self.roundtrip(fake)
        fz.apply(client, saved, KEY, record)
        self.assertEqual(record["completed_steps"], len(saved["steps"]))
        self.assertEqual(fz.verify(client, saved), [])
        self.assertEqual(fake.settings["ssl"], "strict")
        self.assertEqual(fake.settings["ech"], "on")
        self.assertFalse(fake.bot["fight_mode"])
        transform = fake.rulesets[fz.TRANSFORM_PHASE]["rules"]
        self.assertEqual([r["id"] for r in transform][0], "keep-1", "existing rules preserved")
        injected = transform[-1]["action_parameters"]["headers"][fz.ORIGIN_KEY_HEADER]
        self.assertEqual(injected, {"operation": "set", "value": KEY})
        self.assertTrue(fake.records[0]["proxied"])
        self.assertEqual(fz.rollback(client, state, record), [])
        after = {"records": fake.records, "settings": fake.settings, "bot": fake.bot,
                 "rulesets": fake.rulesets}
        self.assertEqual(after["records"], before["records"])
        self.assertEqual(after["settings"], before["settings"])
        self.assertEqual(after["bot"], before["bot"])
        self.assertEqual(after["rulesets"][fz.TRANSFORM_PHASE]["rules"],
                         before["rulesets"][fz.TRANSFORM_PHASE]["rules"])
        self.assertEqual(after["rulesets"][fz.CONFIG_PHASE]["rules"], [])

    def test_failed_step_records_partial_state_and_rollback_undoes_it(self):
        fake = FakeCloudflare(fail_on=lambda m, p: m == "PATCH" and p.endswith("/settings/grpc"))
        client, before, state, saved, record = self.roundtrip(fake)
        with self.assertRaises(fz.ApiError) as error:
            fz.apply(client, saved, KEY, record)
        self.assertNotIn(KEY, str(error.exception))
        self.assertNotIn(TOKEN, str(error.exception))
        self.assertGreater(record["completed_steps"], 0)
        self.assertLess(record["completed_steps"], len(saved["steps"]))
        fake.fail_on = None
        self.assertEqual(fz.rollback(client, state, record), [])
        self.assertEqual(fake.records, before["records"])
        self.assertEqual(fake.settings, before["settings"])

    def test_plan_refuses_existing_records_and_never_contains_the_key(self):
        fake = FakeCloudflare()
        fake.records.append({"id": "old", "type": "A", "name": "relay.example.test",
                             "content": "198.51.100.1", "proxied": True})
        client = fz.Client(TOKEN, fake)
        state = fz.snapshot(client, Args)
        with self.assertRaises(SystemExit):
            fz.plan(state, "203.0.113.10", "00" * 32, False)
        fake.records.clear()
        saved = fz.plan(fz.snapshot(client, Args), "203.0.113.10", "00" * 32, False)
        self.assertNotIn(KEY, json.dumps(saved))
        self.assertFalse(any(s.get("name") == "ech" for s in saved["steps"]))
        # A plan bound to another key refuses to inject this one.
        record = {"created": [], "changed_settings": [], "changed_bot_management": False,
                  "completed_steps": 0}
        with self.assertRaises(SystemExit):
            fz.apply(client, saved, KEY, record)

    def test_private_inputs_require_owner_only_files_and_outputs_are_private(self):
        with tempfile.TemporaryDirectory() as directory:
            token = pathlib.Path(directory, "token.json")
            token.write_text(json.dumps({"api_token": TOKEN}))
            os.chmod(token, 0o644)
            with self.assertRaises(SystemExit):
                fz.load_token(token, "api_token")
            os.chmod(token, 0o600)
            self.assertEqual(fz.load_token(token, "api_token"), TOKEN)
            key = pathlib.Path(directory, "origin.key")
            key.write_text(KEY + "\n")
            os.chmod(key, 0o600)
            self.assertEqual(fz.load_origin_key(key), KEY)
            key.write_text("0" * 64)
            with self.assertRaises(SystemExit):
                fz.load_origin_key(key)
            path = fz.write_json(pathlib.Path(directory, "state"), "plan", {"a": 1})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_origin_certificate_accepts_only_a_public_csr_and_is_revocable(self):
        fake = FakeCloudflare()
        client = fz.Client(TOKEN, fake)
        record = {"created": []}
        with self.assertRaises(SystemExit):
            fz.origin_certificate(client, "relay.example.test",
                                  "-----BEGIN PRIVATE KEY-----\n", record)
        pem = fz.origin_certificate(
            client, "relay.example.test",
            "-----BEGIN CERTIFICATE REQUEST-----\nX\n-----END CERTIFICATE REQUEST-----\n", record)
        self.assertIn("BEGIN CERTIFICATE", pem)
        self.assertEqual(fake.certificates[record["created"][0]["id"]]["hostnames"],
                         ["relay.example.test"])
        state = {"zone_id": fake.zone, "settings": {}}
        self.assertEqual(fz.rollback(client, state, record), [])
        self.assertEqual(fake.certificates, {})

    def test_cli_apply_requires_explicit_owner_approval(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                fz.main(["apply", "--token-file", "/nonexistent", "--zone", "example.test",
                         "--host", "relay", "--state-dir", "/nonexistent", "--plan-file", "x"])

    def test_stronger_tls_minimum_survives_plan_apply_and_rollback(self):
        fake = FakeCloudflare()
        fake.settings["min_tls_version"] = "1.3"
        client, before, state, saved, record = self.roundtrip(fake)
        self.assertFalse(any(s.get("name") == "min_tls_version" for s in saved["steps"]))
        fz.apply(client, saved, KEY, record)
        self.assertEqual(fake.settings["min_tls_version"], "1.3")
        self.assertEqual(fz.rollback(client, state, record), [])
        self.assertEqual(fake.settings, before["settings"])

    def test_enabled_bot_protection_refuses_plan_without_any_write(self):
        fake = FakeCloudflare()
        fake.bot["fight_mode"] = True
        client = fz.Client(TOKEN, fake)
        state = fz.snapshot(client, Args)
        with self.assertRaises(SystemExit):
            fz.plan(state, "203.0.113.10", "00" * 32, True)
        self.assertTrue(all(method == "GET" for method, _ in fake.calls))
        self.assertTrue(fake.bot["fight_mode"])

    def test_incomplete_live_inventory_cannot_create_a_plan(self):
        fake = FakeCloudflare()
        client = fz.Client(TOKEN, fake)
        state = fz.snapshot(client, Args)
        state["settings"]["grpc"] = None
        state["read_failures"] = [{"endpoint": "grpc", "http_status": 400}]
        with self.assertRaises(SystemExit):
            fz.plan(state, "203.0.113.10", "00" * 32, True)
        self.assertTrue(all(method == "GET" for method, _ in fake.calls))

    def test_old_bot_disable_plan_is_refused_before_first_dns_write(self):
        fake = FakeCloudflare()
        client, _, _, saved, record = self.roundtrip(fake)
        saved["steps"].append({"op": "bot_fight_mode_off"})
        fake.calls.clear()
        with self.assertRaises(SystemExit):
            fz.apply(client, saved, KEY, record)
        self.assertEqual(fake.calls, [])
        self.assertEqual(record["completed_steps"], 0)

    def test_old_tls_downgrade_plan_is_refused_before_first_dns_write(self):
        fake = FakeCloudflare()
        client, _, _, saved, record = self.roundtrip(fake)
        saved["steps"].append({"op": "setting", "name": "min_tls_version",
                               "previous": "1.3", "value": "1.2"})
        fake.calls.clear()
        with self.assertRaises(SystemExit):
            fz.apply(client, saved, KEY, record)
        self.assertEqual(fake.calls, [])
        self.assertEqual(record["completed_steps"], 0)


if __name__ == "__main__":
    unittest.main()
