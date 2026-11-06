"""B-06 v36: harness/ab_review.py with the v36 plan (docs/platforms/macos/
v36-ab-plan.json) on synthetic receipts: the renewal window, the W2 gate on
both arms and its retry, the relay condition, the interim that stops only on
REGRESSION, the deadline and the default-policy rule; and the relay review's
congestion-control field. Nothing here dials, tunnels or touches a relay.
System python 3.9."""
import datetime
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_v35_harness import (HARNESS, REPO, RELAY_SAMPLES, SYSTEM_PY, T0, ab_review,  # noqa: E402
                              make_window, ran_side)
import relay_ss_review  # noqa: E402

PLAN36 = REPO / "docs" / "platforms" / "macos" / "v36-ab-plan.json"
PLAN35 = REPO / "docs" / "platforms" / "macos" / "v35-ab-plan.json"
COND = "cc:bbr,default_qdisc:fq,root_qdisc:fq,notsent_lowat:131072"
W2 = ["window-v36-w2t1-r1", "window-v36-w2c1-r1", "window-v36-w2t2-r1", "window-v36-w2c2-r1"]


def window36(root, name, arm, start, run=None, w2_rows=True, **kw):
    """A v36 window: the relay condition in run.txt, and (W2) the L1/L3
    rows make_window leaves out."""
    tokens = {"relay_cond": COND}
    tokens.update(run or {})
    out = make_window(root, name, arm, start, run=tokens, **kw)
    if w2_rows:
        with open(out / "results.tsv", "a") as f:
            f.write("load_flow_burst_24\tpass\t24/24 1.90s\tConnected\ta\tb\n"
                    "tcp_echo_v4_warm\tpass\t4/900/eof\tConnected\ta\tb\n")
    return out


def pair36(root, plan, k, ratio, attempt=1, gap_s=600, echo_ratio=1.0, c_kw=None, t_kw=None):
    order = plan["pairs"][k - 1]
    start = T0 + datetime.timedelta(seconds=1800 * k + 400 * (attempt - 1))
    for i, arm in enumerate(order):
        kw = dict(c_kw or {}) if arm == "c" else dict(t_kw or {})
        kw.setdefault("rate", 400000.0 * (ratio if arm == "t" else 1.0))
        kw.setdefault("echo", int(900 * (echo_ratio if arm == "t" else 1.0)))
        window36(root, ab_review.window_name(plan, k, arm, attempt), arm, start + datetime.timedelta(seconds=gap_s * i),
                 **kw)


def cert(root, renew_at, state="valid"):
    path = root / ("cert-%d.json" % renew_at)
    path.write_text(json.dumps({"schema": "aegis-ne-xpc-v1", "verb": "cert-status",
                                "report": {"state": state, "renew_at": renew_at}}) + "\n")
    return str(path)


class V36PlanTests(unittest.TestCase):
    def test_both_declared_plans_and_only_them(self):
        plan = ab_review.load_plan(PLAN36)
        self.assertEqual(ab_review.check_plan(plan), [])
        self.assertEqual(ab_review.check_plan(ab_review.load_plan(PLAN35)), [])
        for key, value in (("n_max", 24), ("interim_stops", ["GAIN", "REGRESSION"]), ("relay_condition", "cc:cubic"),
                           ("deadline_utc", "2026-10-29T02:00:00Z"), ("default_rows", ["throughput"]),
                           ("w2_valid_min_per_arm", 1)):
            self.assertEqual(ab_review.check_plan(dict(plan, **{key: value})), ["value_not_declared:%s" % key])
        self.assertIn("pairs_not_declared_order", ab_review.check_plan(dict(plan, pairs=plan["pairs"][:16])))
        self.assertEqual(ab_review.check_plan(dict(plan, extra=1)), ["unknown:extra"])
        # Each arm goes first in 10 of the 20 pairs, and in 2 of every block of 4.
        self.assertEqual(sum(1 for o in plan["pairs"] if o == "tc"), 10)
        for b in range(0, 20, 4):
            self.assertEqual(sorted(plan["pairs"][b:b + 4]), ["ct", "ct", "tc", "tc"])
        out = subprocess.run([SYSTEM_PY, "-I", str(HARNESS / "ab_review.py"), "check-plan", "--plan", str(PLAN36)],
                             capture_output=True, text=True, timeout=30)
        self.assertEqual((out.returncode, out.stdout.strip()), (0, "plan_ok v36-ab-r1"))


class V36NextTests(unittest.TestCase):
    def setUp(self):
        self.plan = ab_review.load_plan(PLAN36)
        temp = tempfile.TemporaryDirectory(prefix="aegis-ab36-")
        self.addCleanup(temp.cleanup)
        self.root = pathlib.Path(temp.name)

    def next(self, now=None, cert_path=None):
        return ab_review.next_step(self.plan, str(self.root), now or T0, cert_path)

    def prelude(self, w2_runs=None):
        ran_side(self.root, "path-probe-v36-s1-r1")
        for i, name in enumerate(W2):
            window36(self.root, name, self.plan["prelude_arms"][name], T0 + datetime.timedelta(seconds=420 * i),
                     run=(w2_runs or {}).get(name))

    def test_the_renewal_window_then_the_declared_order(self):
        now = int(T0.timestamp())
        # Inside the margin, not yet due: wait.
        self.assertEqual(self.next(T0, cert(self.root, now + 600)), "refuse:renew_margin")
        # Due (renew_at plus the skew has passed): the renewal window, no load.
        due = cert(self.root, now - 60)
        self.assertEqual(self.next(T0, due), "next=window-v36-renew-r1 kind=renewal arm=none env=none")
        # Amendment: the provider reports `due` (or `failed:<class>`) once renew_at has passed.
        self.assertEqual(self.next(T0, cert(self.root, now - 61, "due")),
                         "next=window-v36-renew-r1 kind=renewal arm=none env=none")
        self.assertEqual(self.next(T0, cert(self.root, now - 30, "due")), "refuse:renew_margin")
        self.assertEqual(self.next(T0, cert(self.root, now - 62, "in_progress")), "refuse:cert_state")
        self.assertEqual(self.next(T0, cert(self.root, now - 63, "expired")), "refuse:cert_state")
        ran_side(self.root, "window-v36-renew-r1")
        self.assertEqual(self.next(T0, cert(self.root, now - 64, "failed:network")),
                         "next=window-v36-renew-r2 kind=renewal arm=none env=none")
        self.assertEqual(self.next(T0, due), "next=window-v36-renew-r2 kind=renewal arm=none env=none")
        ran_side(self.root, "window-v36-renew-r2")
        ran_side(self.root, "window-v36-renew-r3")
        self.assertEqual(self.next(T0, due), "refuse:renewal_failed")
        renewed = cert(self.root, now + 57600)
        self.assertEqual(self.next(T0, renewed), "next=path-probe-v36-s1-r1 kind=sentinel arm=none env=none")
        ran_side(self.root, "path-probe-v36-s1-r1")
        expect = [("window-v36-w2t1-r1", "t", "LOAD=1,WINDOW_POLICY="), ("window-v36-w2c1-r1", "c",
                                                                         "LOAD=1,WINDOW_POLICY=fixed"),
                  ("window-v36-w2t2-r1", "t", "LOAD=1,WINDOW_POLICY="), ("window-v36-w2c2-r1", "c",
                                                                         "LOAD=1,WINDOW_POLICY=fixed")]
        for name, arm, env in expect:
            self.assertEqual(self.next(T0, renewed), "next=%s kind=window arm=%s env=%s" % (name, arm, env))
            window36(self.root, name, arm, T0)
        self.assertEqual(self.next(T0, renewed), "next=window-v36-ab01-t-r1 kind=window arm=t env=LOAD=1,WINDOW_POLICY=")

    def test_a_w2_window_invalid_for_a_declared_reason_is_retried_after_the_prelude(self):
        self.prelude({"window-v36-w2c1-r1": {"host_free": "0"}})
        self.assertEqual(self.next(), "next=window-v36-w2c1-r2 kind=window arm=c env=LOAD=1,WINDOW_POLICY=fixed "
                                      "reason=w2_retry:host_free_breach")
        window36(self.root, "window-v36-w2c1-r2", "c", T0)
        self.assertTrue(self.next().startswith("next=window-v36-ab01-t-r1 "), self.next())
        gate = ab_review.w2_gate(self.plan, str(self.root))
        self.assertEqual((gate["c"]["verdict"], gate["t"]["verdict"]), ("PASS", "PASS"))
        self.assertEqual([w["counted"] for w in gate["c"]["windows"]], ["window-v36-w2c1-r2", "window-v36-w2c2-r1"])

    def test_the_relay_condition_invalidates_a_pair(self):
        self.prelude()
        pair36(self.root, self.plan, 1, 1.0, t_kw={"run": {"relay_cond": "cc:cubic,default_qdisc:fq_codel,"
                                                                         "root_qdisc:pfifo_fast,notsent_lowat:4294967295"}})
        self.assertEqual(self.next(), "next=window-v36-ab01-t-r2 kind=window arm=t env=LOAD=1,WINDOW_POLICY= "
                                      "reason=rerun:relay_condition")
        pair36(self.root, self.plan, 1, 1.0, attempt=2, c_kw={"run": {"relay_cond_after": "cc:cubic"}})
        self.assertEqual(self.next(), "next=window-v36-ab01-t-r3 kind=window arm=t env=LOAD=1,WINDOW_POLICY= "
                                      "reason=rerun:relay_condition")
        # A window without the condition at all is invalid too.
        rec = ab_review.window_record(self.plan, str(self.root), "window-v36-ab01-c-r1")
        rec["relay_cond"] = None
        self.assertIn("relay_condition", ab_review.window_invalid(self.plan, rec, "c"))

    def test_the_interim_stops_only_on_regression(self):
        self.prelude()
        for k, r in enumerate([1.5, 1.3, 1.6, 1.2, 1.45, 1.35, 1.55, 1.4], 1):
            pair36(self.root, self.plan, k, r)
        ran_side(self.root, "path-probe-v36-s2-r1")
        pairs, valid = ab_review.pair_table(self.plan, str(self.root))
        self.assertEqual(ab_review.decide(self.plan, valid, "interim")["verdict"], "GAIN")
        # GAIN at the interim: the series runs on.
        self.assertTrue(self.next().startswith("next=window-v36-ab09-c-r1 "), self.next())
        root = pathlib.Path(tempfile.mkdtemp(prefix="reg-", dir=self.root))
        self.root = root
        self.prelude()
        for k in range(1, 9):
            pair36(self.root, self.plan, k, 1.0, echo_ratio=2.5)
        ran_side(self.root, "path-probe-v36-s2-r1")
        pairs, valid = ab_review.pair_table(self.plan, str(self.root))
        interim = ab_review.decide(self.plan, valid, "interim")
        self.assertEqual((interim["verdict"], interim["rows"]["tcp_echo_ms"]), ("REGRESSION", "REGRESSION"))
        self.assertEqual(self.next(), "next=path-probe-v36-s5-r1 kind=sentinel arm=none env=none")

    def test_the_deadline_and_a_w2_control_that_never_connected(self):
        self.assertEqual(self.next(datetime.datetime(2026, 10, 29, 1, 10, tzinfo=datetime.timezone.utc)),
                         "refuse:deadline")
        ran_side(self.root, "path-probe-v36-s1-r1")
        window36(self.root, "window-v36-w2t1-r1", "t", T0)
        window36(self.root, "window-v36-w2c1-r1", "c", T0, tunnel="0")
        self.assertEqual(self.next(), "refuse:series_stopped:control_not_connected:window-v36-w2c1-r1")


class V36DefaultPolicyTests(unittest.TestCase):
    def setUp(self):
        self.plan = ab_review.load_plan(PLAN36)
        temp = tempfile.TemporaryDirectory(prefix="aegis-ab36-default-")
        self.addCleanup(temp.cleanup)
        self.root = pathlib.Path(temp.name)

    def series(self, n=20, echo_ratio=1.0, w2_runs=None, w2_kw=None):
        ran_side(self.root, "path-probe-v36-s1-r1")
        for i, name in enumerate(W2):
            window36(self.root, name, self.plan["prelude_arms"][name], T0, run=(w2_runs or {}).get(name),
                     **(w2_kw or {}).get(name, {}))
        for k in range(1, n + 1):
            pair36(self.root, self.plan, k, 1.02 if k % 2 else 0.98, echo_ratio=echo_ratio)
        if n < 20:
            (self.root / "series-end.txt").write_text("reason=deadline\n")
        return ab_review.analyze(self.plan, str(self.root))

    def test_adaptive_only_when_every_default_row_is_gain_or_non_inferior(self):
        out = self.series()
        d = out["default_policy"]
        self.assertEqual((out["result"]["look"], d["default"], d["why"]), ("final", "adaptive", []))
        self.assertEqual((d["rows"]["throughput"], d["rows"]["tcp_echo_ms"], d["rows"]["w2"]),
                         ("NON_INFERIOR", "NON_INFERIOR", "NON_INFERIOR"))
        proc = subprocess.run([SYSTEM_PY, "-I", str(HARNESS / "ab_review.py"), "analyze", "--plan", str(PLAN36),
                               "--receipts", str(self.root)], capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.stdout.splitlines()[-1], "verdict=NON_INFERIOR n=20 look=final default=adaptive")

    def test_a_cut_short_series_or_an_echo_regression_is_fixed(self):
        out = self.series(n=11)
        self.assertEqual(out["default_policy"]["default"], "fixed")
        self.assertIn("no_final_look:interim", out["default_policy"]["why"])
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="echo-", dir=self.root))
        out = self.series(echo_ratio=1.4)
        self.assertEqual(out["default_policy"]["default"], "fixed")
        self.assertIn("tcp_echo_ms:REGRESSION", out["default_policy"]["why"])

    def test_the_w2_gate_on_both_arms(self):
        # T fails W2 (a slow burst) where C passes: the w2 row is a REGRESSION.
        out = self.series(w2_kw={"window-v36-w2t2-r1": {"burst90": 7.0}})
        gate = out["w2_gate"]
        self.assertEqual((gate["t"]["verdict"], gate["c"]["verdict"]), ("FAIL", "PASS"))
        self.assertEqual(gate["t"]["failed_windows"], ["window-v36-w2t2-r1"])
        self.assertEqual(out["default_policy"]["rows"]["w2"], "REGRESSION")
        self.assertEqual(out["default_policy"]["default"], "fixed")
        # An arm with one valid W2 window and no failure is INCOMPLETE.
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="w2-", dir=self.root))
        out = self.series(w2_runs={"window-v36-w2c2-r1": {"invalid": "operator_abort"}})
        self.assertEqual(out["w2_gate"]["c"]["verdict"], "INCOMPLETE")
        self.assertEqual(out["default_policy"]["rows"]["w2"], "NON_INFERIOR")


class V36RelayReviewTests(unittest.TestCase):
    def test_the_congestion_control_of_each_socket(self):
        bbr = RELAY_SAMPLES.replace("\t cubic rtt:", "\t bbr wscale:7,7 bbr:(bw:20Mbps,mrtt:160) rtt:")
        r = relay_ss_review.relay_review(bbr.splitlines())
        self.assertEqual({s["port"]: s["cc"] for s in r["sockets"]}, {"5001": ["bbr"], "5002": ["bbr"]})
        r = relay_ss_review.relay_review(RELAY_SAMPLES.splitlines())
        self.assertEqual({s["port"]: s["cc"] for s in r["sockets"]}, {"5001": ["cubic"], "5002": ["cubic"]})


if __name__ == "__main__":
    unittest.main()
