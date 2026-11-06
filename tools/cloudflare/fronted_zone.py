#!/usr/bin/env python3
"""Prepare, apply, verify and roll back the Cloudflare zone changes for one
CDN-fronted, device-enrolled AEGIS origin (carrier program D1/D2).

Prepared, not executed: every write requires an explicit owner-approval flag
and a fresh read-only snapshot taken by this tool. The API token is read from
a private JSON file and never printed, logged or passed in a process argument;
the origin key is read from its owner-only file and never printed.

Commands (all take --token-file, --zone, --host, --state-dir):
  snapshot                 read-only; saves current state for plan/rollback
  plan                     no API calls; prints and saves the intended writes
  apply                    executes a saved plan in order, records every
                           created object, stops at the first failure
  verify                   read-only; compares live state with the plan
  rollback                 restores settings/bot mode from the snapshot and
                           deletes exactly the objects recorded by apply
  origin-cert              issues a Cloudflare Origin CA certificate for the
                           host from a CSR made on the origin (key stays there)
  cloudflare-ips           unauthenticated GET /ips -> trusted proxy ranges

Standard library only. Run with `python3 -I`.
"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.request

API = "https://api.cloudflare.com/client/v4"
ORIGIN_KEY_HEADER = "x-aegis-origin-key"
TIMEOUT = 20
# Zone settings this deployment depends on; ECH only with --ech.
SETTINGS = {
    "ssl": "strict",            # Full (strict): origin certificate verified
    "min_tls_version": "1.2",
    "tls_1_3": "on",
    "0rtt": "off",              # no replayable early data to the origin
    "grpc": "on",               # gRPC proxying (all plans)
    "origin_max_http_version": "2",
}
ECH_SETTING = ("ech", "on")
TRANSFORM_PHASE = "http_request_late_transform"
CONFIG_PHASE = "http_config_settings"
TRANSFORM_DESCRIPTION = "aegis fronted origin key"
CONFIG_DESCRIPTION = "aegis fronted origin: no browser challenges"


class ApiError(Exception):
    pass


def utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def private_file(path):
    path = pathlib.Path(path)
    info = path.lstat()
    if not path.is_file() or path.is_symlink() or info.st_mode & 0o077:
        raise SystemExit(f"{path}: must be a regular owner-only (0600) file")
    return path.read_bytes()


def load_token(path, field):
    data = json.loads(private_file(path))
    token = data.get(field)
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_\-]{20,200}", token):
        raise SystemExit("token file has no usable token field")
    return token


def load_origin_key(path):
    raw = private_file(path)
    key = raw[:-1] if raw.endswith(b"\n") else raw
    if not re.fullmatch(rb"[0-9a-f]{64}", key) or set(key) == {ord("0")}:
        raise SystemExit("origin key must be 64 lowercase hex characters")
    return key.decode()


class Client:
    """Minimal Cloudflare v4 client; `transport` is injectable for tests."""

    def __init__(self, token, transport=None):
        self._token = token
        self._transport = transport or self._urllib

    def _urllib(self, method, url, body, headers):
        request = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()

    def call(self, method, path, payload=None, allow_404=False):
        body = None if payload is None else json.dumps(payload).encode()
        headers = {"Authorization": "Bearer " + self._token, "Content-Type": "application/json"}
        status, raw = self._transport(method, API + path, body, headers)
        if allow_404 and status == 404:
            return None
        try:
            data = json.loads(raw or b"{}")
        except ValueError:
            data = {}
        if status >= 300 or not data.get("success", False):
            codes = [(e.get("code"), e.get("message")) for e in data.get("errors", [])]
            # Never echo request bodies: they can contain the origin key.
            raise ApiError(f"{method} {path.split('?')[0]} -> HTTP {status} {codes}")
        return data.get("result")


def zone_id(client, zone):
    result = client.call("GET", f"/zones?name={zone}")
    if not result or len(result) != 1:
        raise SystemExit("zone not found or ambiguous")
    return result[0]["id"]


def fqdn(args):
    host = args.host.lower()
    if not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", host):
        raise SystemExit("--host must be one DNS label")
    return f"{host}.{args.zone.lower()}"


def phase_entrypoint(client, zid, phase):
    return client.call("GET", f"/zones/{zid}/rulesets/phases/{phase}/entrypoint", allow_404=True)


def snapshot(client, args):
    zid = zone_id(client, args.zone)
    name = fqdn(args)
    state = {
        "schema": "aegis_cf_fronted_snapshot_v1",
        "utc": utc(),
        "zone": args.zone,
        "zone_id": zid,
        "fqdn": name,
        "dns_records": client.call("GET", f"/zones/{zid}/dns_records?name={name}"),
        "settings": {},
        "bot_management": client.call("GET", f"/zones/{zid}/bot_management", allow_404=True),
        "rulesets": {},
    }
    for setting in list(SETTINGS) + [ECH_SETTING[0]]:
        result = client.call("GET", f"/zones/{zid}/settings/{setting}", allow_404=True)
        state["settings"][setting] = None if result is None else result.get("value")
    for phase in (TRANSFORM_PHASE, CONFIG_PHASE):
        entry = phase_entrypoint(client, zid, phase)
        # Keep rule metadata only: never persist header values from rules.
        state["rulesets"][phase] = None if entry is None else {
            "id": entry.get("id"),
            "rules": [
                {"id": r.get("id"), "description": r.get("description"), "expression": r.get("expression")}
                for r in entry.get("rules", [])
            ],
        }
    return state


def plan(state, origin_ipv4, origin_key_sha256, ech):
    if state.get("read_failures") or any(
            state.get("settings", {}).get(name) is None for name in SETTINGS):
        raise SystemExit("zone settings snapshot is incomplete; deployment remains refused")
    tls_versions = ("1.0", "1.1", "1.2", "1.3")
    current_minimum = state["settings"]["min_tls_version"]
    if current_minimum not in tls_versions:
        raise SystemExit("unknown minimum TLS version; deployment remains refused")
    if (state.get("bot_management") or {}).get("fight_mode"):
        raise SystemExit("zone-wide Bot Fight Mode must remain enabled; deployment remains refused")
    name = state["fqdn"]
    existing = state["dns_records"] or []
    if any(r.get("type") in ("A", "AAAA", "CNAME") for r in existing):
        raise SystemExit(f"{name} already has address records; refusing to overwrite")
    for phase in (TRANSFORM_PHASE, CONFIG_PHASE):
        rules = (state["rulesets"].get(phase) or {}).get("rules", [])
        if any(r.get("description") in (TRANSFORM_DESCRIPTION, CONFIG_DESCRIPTION) for r in rules):
            raise SystemExit(f"an aegis rule already exists in {phase}; roll back first")
    steps = [{"op": "dns_create", "name": name, "content": origin_ipv4}]
    wanted = dict(SETTINGS)
    # Preserve a stronger existing minimum instead of rewriting it to 1.2.
    wanted["min_tls_version"] = tls_versions[max(
        tls_versions.index(current_minimum), tls_versions.index("1.2"))]
    if ech:
        wanted[ECH_SETTING[0]] = ECH_SETTING[1]
    for setting, value in wanted.items():
        if state["settings"].get(setting) != value:
            steps.append({"op": "setting", "name": setting, "value": value,
                          "previous": state["settings"].get(setting)})
    expression = f'(http.host eq "{name}")'
    steps.append({"op": "rule", "phase": TRANSFORM_PHASE, "rule": {
        "action": "rewrite", "expression": expression, "description": TRANSFORM_DESCRIPTION,
        "enabled": True,
        "action_parameters": {"headers": {ORIGIN_KEY_HEADER: {"operation": "set", "value": "<ORIGIN_KEY>"}}},
    }, "origin_key_sha256": origin_key_sha256})
    steps.append({"op": "rule", "phase": CONFIG_PHASE, "rule": {
        "action": "set_config", "expression": expression, "description": CONFIG_DESCRIPTION,
        "enabled": True, "action_parameters": {"bic": False, "security_level": "essentially_off"},
    }})
    return {"schema": "aegis_cf_fronted_plan_v1", "utc": utc(), "zone_id": state["zone_id"],
            "fqdn": name, "snapshot_utc": state["utc"], "steps": steps}


def admit_security_steps(saved_plan):
    """Reject stale weakening plans before even their first DNS operation."""
    tls_versions = ("1.0", "1.1", "1.2", "1.3")
    for step in saved_plan["steps"]:
        if step.get("op") == "bot_fight_mode_off":
            raise SystemExit("refusing zone-wide Bot Fight Mode disablement")
        if step.get("op") != "setting":
            continue
        name, value = step.get("name"), step.get("value")
        if name == "min_tls_version":
            previous = step.get("previous")
            if (previous not in tls_versions or value not in tls_versions
                    or tls_versions.index(value) < max(2, tls_versions.index(previous))):
                raise SystemExit("refusing weaker or unbound minimum TLS version")
        elif (name not in SETTINGS and name != ECH_SETTING[0]) or value != (
                ECH_SETTING[1] if name == ECH_SETTING[0] else SETTINGS.get(name)):
            raise SystemExit("refusing unsupported zone security setting")


def apply(client, saved_plan, origin_key, record):
    admit_security_steps(saved_plan)
    zid = saved_plan["zone_id"]
    for step in saved_plan["steps"]:
        op = step["op"]
        if op == "dns_create":
            result = client.call("POST", f"/zones/{zid}/dns_records", {
                "type": "A", "name": step["name"], "content": step["content"],
                "proxied": True, "ttl": 1, "comment": "aegis fronted enrolled origin"})
            record["created"].append({"kind": "dns", "id": result["id"]})
        elif op == "setting":
            client.call("PATCH", f"/zones/{zid}/settings/{step['name']}", {"value": step["value"]})
            record["changed_settings"].append(step["name"])
        elif op == "bot_fight_mode_off":
            client.call("PUT", f"/zones/{zid}/bot_management", {"fight_mode": False})
            record["changed_bot_management"] = True
        elif op == "rule":
            rule = json.loads(json.dumps(step["rule"]))
            if step["phase"] == TRANSFORM_PHASE:
                if hashlib.sha256(origin_key.encode()).hexdigest() != step["origin_key_sha256"]:
                    raise SystemExit("origin key differs from the planned key")
                rule["action_parameters"]["headers"][ORIGIN_KEY_HEADER]["value"] = origin_key
            entry = phase_entrypoint(client, zid, step["phase"])
            if entry is None:
                result = client.call("PUT", f"/zones/{zid}/rulesets/phases/{step['phase']}/entrypoint",
                                     {"rules": [rule]})
            else:
                result = client.call("POST", f"/zones/{zid}/rulesets/{entry['id']}/rules", rule)
            ours = [r for r in result.get("rules", []) if r.get("description") == rule["description"]]
            if len(ours) != 1:
                raise ApiError("created rule not uniquely identifiable")
            record["created"].append({"kind": "rule", "ruleset": result["id"], "id": ours[0]["id"]})
        else:
            raise SystemExit(f"unknown plan step {op}")
        record["completed_steps"] += 1


def rollback(client, state, record):
    zid = state["zone_id"]
    failures = []
    for item in reversed(record.get("created", [])):
        try:
            if item["kind"] == "dns":
                client.call("DELETE", f"/zones/{zid}/dns_records/{item['id']}")
            elif item["kind"] == "rule":
                client.call("DELETE", f"/zones/{zid}/rulesets/{item['ruleset']}/rules/{item['id']}")
            elif item["kind"] == "origin_certificate":
                client.call("DELETE", f"/certificates/{item['id']}")
        except ApiError as error:
            failures.append(str(error))
    for setting in reversed(record.get("changed_settings", [])):
        previous = state["settings"].get(setting)
        if previous is None:
            failures.append(f"no snapshot value for {setting}")
            continue
        try:
            client.call("PATCH", f"/zones/{zid}/settings/{setting}", {"value": previous})
        except ApiError as error:
            failures.append(str(error))
    if record.get("changed_bot_management"):
        try:
            client.call("PUT", f"/zones/{zid}/bot_management", {"fight_mode": True})
        except ApiError as error:
            failures.append(str(error))
    return failures


def verify(client, saved_plan):
    zid = saved_plan["zone_id"]
    problems = []
    records = client.call("GET", f"/zones/{zid}/dns_records?name={saved_plan['fqdn']}") or []
    for step in saved_plan["steps"]:
        if step["op"] == "dns_create":
            if not any(r.get("type") == "A" and r.get("proxied") and r.get("content") == step["content"]
                       for r in records):
                problems.append("proxied A record missing")
        elif step["op"] == "setting":
            value = (client.call("GET", f"/zones/{zid}/settings/{step['name']}") or {}).get("value")
            if value != step["value"]:
                problems.append(f"setting {step['name']} is {value!r}")
        elif step["op"] == "rule":
            entry = phase_entrypoint(client, zid, step["phase"]) or {}
            if not any(r.get("description") == step["rule"]["description"] and r.get("enabled", True)
                       for r in entry.get("rules", [])):
                problems.append(f"rule missing in {step['phase']}")
    return problems


def origin_certificate(client, name, csr_pem, record):
    if "BEGIN CERTIFICATE REQUEST" not in csr_pem or "PRIVATE KEY" in csr_pem:
        raise SystemExit("--csr must be a public CSR, never a private key")
    result = client.call("POST", "/certificates", {
        "hostnames": [name], "requested_validity": 5475,
        "request_type": "origin-ecc", "csr": csr_pem})
    record["created"].append({"kind": "origin_certificate", "id": result["id"]})
    return result["certificate"]


def write_json(directory, prefix, data):
    directory = pathlib.Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / f"{prefix}-{utc()}.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as out:
        json.dump(data, out, indent=2, sort_keys=True)
        out.write("\n")
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=["snapshot", "plan", "apply", "verify", "rollback",
                                            "origin-cert", "cloudflare-ips"])
    parser.add_argument("--csr")
    parser.add_argument("--out")
    parser.add_argument("--token-file")
    parser.add_argument("--token-field", default="api_token")
    parser.add_argument("--zone")
    parser.add_argument("--host")
    parser.add_argument("--state-dir")
    parser.add_argument("--snapshot")
    parser.add_argument("--plan-file")
    parser.add_argument("--applied")
    parser.add_argument("--origin-ipv4")
    parser.add_argument("--origin-key-file")
    parser.add_argument("--ech", action="store_true")
    parser.add_argument("--i-have-owner-approval", action="store_true")
    args = parser.parse_args(argv)

    if args.command == "cloudflare-ips":
        with urllib.request.urlopen(API + "/ips", timeout=TIMEOUT) as response:
            data = json.loads(response.read())
        ranges = data["result"]["ipv4_cidrs"] + data["result"]["ipv6_cidrs"]
        print(json.dumps({"trusted_proxy_cidrs": ranges}, indent=2))
        return 0

    for required in ("token_file", "zone", "host", "state_dir"):
        if not getattr(args, required):
            raise SystemExit(f"--{required.replace('_', '-')} is required")
    if args.command == "plan":
        state = json.loads(pathlib.Path(args.snapshot).read_text())
        import ipaddress
        address = ipaddress.ip_address(args.origin_ipv4 or "")
        if address.version != 4 or not address.is_global:
            raise SystemExit("--origin-ipv4 must be a global IPv4 address")
        key = load_origin_key(args.origin_key_file)
        saved = plan(state, str(address), hashlib.sha256(key.encode()).hexdigest(), args.ech)
        path = write_json(args.state_dir, "plan", saved)
        for step in saved["steps"]:
            print(json.dumps({k: v for k, v in step.items() if k != "rule"} | (
                {"rule": step["rule"]["description"]} if "rule" in step else {})))
        print(f"plan saved: {path}")
        return 0

    if args.command in ("apply", "origin-cert") and not args.i_have_owner_approval:
        raise SystemExit(f"{args.command} requires --i-have-owner-approval (owner said yes)")
    client = Client(load_token(args.token_file, args.token_field))
    if args.command == "snapshot":
        print(f"snapshot saved: {write_json(args.state_dir, 'snapshot', snapshot(client, args))}")
    elif args.command == "apply":
        if not args.i_have_owner_approval:
            raise SystemExit("apply requires --i-have-owner-approval (owner said yes for this window)")
        saved = json.loads(pathlib.Path(args.plan_file).read_text())
        record = {"schema": "aegis_cf_fronted_applied_v1", "plan_utc": saved["utc"],
                  "created": [], "changed_settings": [], "changed_bot_management": False,
                  "completed_steps": 0}
        try:
            apply(client, saved, load_origin_key(args.origin_key_file), record)
        finally:
            # The record is written even after a failure: it drives rollback.
            print(f"applied record: {write_json(args.state_dir, 'applied', record)}")
        print(f"completed {record['completed_steps']}/{len(saved['steps'])} steps")
    elif args.command == "origin-cert":
        if not args.i_have_owner_approval:
            raise SystemExit("origin-cert requires --i-have-owner-approval")
        record = {"schema": "aegis_cf_fronted_applied_v1", "plan_utc": None, "created": [],
                  "changed_settings": [], "changed_bot_management": False, "completed_steps": 0}
        try:
            pem = origin_certificate(client, fqdn(args), pathlib.Path(args.csr).read_text(), record)
            fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            with os.fdopen(fd, "w") as out:
                out.write(pem)
        finally:
            print(f"certificate record: {write_json(args.state_dir, 'origin-cert', record)}")
    elif args.command == "verify":
        problems = verify(client, json.loads(pathlib.Path(args.plan_file).read_text()))
        print(json.dumps({"ok": not problems, "problems": problems}))
        return 0 if not problems else 1
    elif args.command == "rollback":
        state = json.loads(pathlib.Path(args.snapshot).read_text())
        record = json.loads(pathlib.Path(args.applied).read_text())
        failures = rollback(client, state, record)
        print(json.dumps({"rolled_back": not failures, "failures": failures}))
        return 0 if not failures else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
