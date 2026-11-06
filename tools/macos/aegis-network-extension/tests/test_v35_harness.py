"""B-06 v35: the A/B harness pieces alone, on fakes and synthetic receipts
(H4 to H7): harness/relay_ss_loop.sh and harness/mac_sockq_loop.sh against
fake commands on PATH, harness/relay_ss_review.py on synthetic masked
samples, and harness/ab_review.py's analyze and next on synthetic receipts.
Nothing here dials, tunnels or touches a relay. System python 3.9."""
import datetime
import json
import math
import os
import pathlib
import statistics
import subprocess
import sys
import tempfile
import unittest

PACKAGE = pathlib.Path(__file__).resolve().parents[1]
HARNESS = PACKAGE / "harness"
REPO = PACKAGE.parents[2]
PLAN = REPO / "docs" / "platforms" / "macos" / "v35-ab-plan.json"
SYSTEM_PY = "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else sys.executable
sys.path.insert(0, str(HARNESS))
import ab_review  # noqa: E402
import relay_ss_review  # noqa: E402

# Documentation ranges only (RFC 5737, RFC 3849).
RELAY = "192.0.2.10"
MAC = "198.51.100.20"
OTHER = "203.0.113.30"


# `ip tcp_metrics show` as the relay prints it: IPv4 and bare IPv6, with
# the relay's own `source` address.
TCP_METRICS = ("%s age 2.5sec cwnd 10 rtt 190ms rttvar 20ms source %s\n"
               "2001:db8:85a3::8a2e:370:7334 age 120.5sec cwnd 10 rtt 190ms source 2001:db8::1\n"
               "::ffff:%s age 1sec source ::ffff:%s\n"
               "fe80::1%%eth0 age 3sec source ::1\n" % (MAC, RELAY, MAC, RELAY))
TCP_METRICS_MASKED = ("198.51.x.x age 2.5sec cwnd 10 rtt 190ms rttvar 20ms source 192.0.x.x\n"
                      "v6.x age 120.5sec cwnd 10 rtt 190ms source v6.x\n"
                      "v6.x age 1sec source v6.x\n"
                      "v6.x%eth0 age 3sec source v6.x\n")


def fake_bin(root, scripts):
    d = root / "bin"
    d.mkdir()
    for name, body in scripts.items():
        (d / name).write_text("#!/bin/bash\n" + body)
        (d / name).chmod(0o755)
    return d


class RelaySsLoopTests(unittest.TestCase):
    """H4: the relay socket sampler and the Mac socket-queue sampler."""

    SS = ('printf "%%s\\n" "$*" >> "$LOG.ss"\n'
          'echo "0      9000   %s:443  %s:51234"\n'
          'echo "\t cubic rtt:180.5/2 cwnd:20 ssthresh:16 bytes_acked:1000 segs_out:30 notsent:4096 '
          'peer [2001:db8::5]:443 mapped [::ffff:%s]:8"\n' % (RELAY, MAC, OTHER))

    def run_loop(self, *args, scripts=None):
        with tempfile.TemporaryDirectory(prefix="aegis-ss-") as temp:
            root = pathlib.Path(temp)
            log = root / "log"
            scripts = scripts or {
                "ss": self.SS,
                "date": 'echo "date $*" >> "$LOG.calls"; echo 1793161670.5\n',
                "sleep": 'echo "sleep $*" >> "$LOG.calls"\n',
            }
            d = fake_bin(root, scripts)
            # Only the fakes and sed: any other command fails to run.
            os.symlink("/usr/bin/sed", d / "sed")
            out = subprocess.run([str(HARNESS / "relay_ss_loop.sh"), *args], capture_output=True, text=True,
                                 env={"PATH": str(d), "LOG": str(log)}, timeout=30)
            read = lambda suffix: (root / ("log" + suffix)).read_text() if (root / ("log" + suffix)).exists() else ""
            return out, read(".ss"), read(".calls")

    def test_the_loop_writes_n_masked_samples_of_the_relays_443_sockets(self):
        out, ss, calls = self.run_loop("run", "3")
        self.assertEqual(out.returncode, 0, out.stderr)
        lines = out.stdout.splitlines()
        self.assertEqual([l for l in lines if l.startswith("T ")], ["T 1793161670.5"] * 3)
        self.assertEqual(len(lines), 9)
        # Exactly the established :443 filter, once a sample.
        self.assertEqual(ss.splitlines(), ["-tinH state established ( sport = :443 )"] * 3)
        # ss, date and sleep (and sed) only; no sleep after the last sample.
        self.assertEqual(calls.splitlines(), ["date +%s.%N", "sleep 1", "date +%s.%N", "sleep 1", "date +%s.%N"])
        text = out.stdout
        for literal in (RELAY, MAC, OTHER, "2001:db8::5", "::ffff"):
            self.assertNotIn(literal, text)
        self.assertIn("192.0.x.x:443  198.51.x.x:51234", text)
        self.assertIn("[v6.x]:443", text)
        self.assertIn("mapped [v6.x]:8", text)
        self.assertIn("notsent:4096", text)

    def test_bad_arguments_refuse_and_run_nothing(self):
        for args in (("run",), ("run", "0"), ("run", "7201"), ("run", "x"), ("remote-start", "Bad_Name", "3", "10"),
                     ("remote-start", "w1", "10", "3"), ("remote-start", "w1", "3", "10", "relative/dir"),
                     ("remote-start", "w1", "3", "10", "/tmp/../etc"), ("remote-fetch",), ("remote-metrics", "x"),
                     ("nope",)):
            out, ss, calls = self.run_loop(*args)
            self.assertEqual(out.returncode, 2, args)
            self.assertEqual((ss, calls, out.stdout), ("", "", ""), args)

    def test_the_remote_commands_run_the_loop_inline_and_refuse_a_leftover(self):
        out, _ss, _calls = self.run_loop("remote-start", "window-v35-ab01-c-r1", "240", "300")
        cmd = out.stdout.strip()
        self.assertEqual(out.returncode, 0)
        self.assertTrue(cmd.startswith("umask 077; m=aegis-s; m=${m}s-; "), cmd)
        self.assertIn("setsid nohup timeout 300 bash -c ", cmd)
        self.assertIn(' "${m}window-v35-ab01-c-r1" 240 > /tmp/"${m}window-v35-ab01-c-r1.txt"', cmd)
        # No file is copied to the relay, and the marker never appears whole
        # in the remote shell's own command line.
        for word in ("scp", "cat >", "tee ", "aegis-ss-"):
            self.assertNotIn(word, cmd)
        clean, _s, _c = self.run_loop("remote-clean", "window-v35-ab01-c-r1")
        self.assertIn('rm -f /tmp/"${m}window-v35-ab01-c-r1.txt"', clean.stdout)
        self.assertIn("echo aegis_ss_left; exit 4", clean.stdout)
        metrics, _s, _c = self.run_loop("remote-metrics")
        self.assertIn("sysctl -n net.ipv4.tcp_no_metrics_save", metrics.stdout)
        self.assertIn("ip tcp_metrics show", metrics.stdout)
        for word in ("flush", "delete", "-w ", "sysctl net", "tc "):
            self.assertNotIn(word, metrics.stdout)
        # Run the start against fakes in a private directory: it writes the
        # masked samples, then refuses while that file is left over; the
        # clean removes it.
        with tempfile.TemporaryDirectory(prefix="aegis-ss-remote-") as temp:
            root = pathlib.Path(temp)
            d = fake_bin(root, {"ss": self.SS.replace('"$LOG.ss"', "/dev/null"), "sleep": ":\n",
                                "setsid": 'exec "$@"\n', "timeout": 'shift; exec "$@"\n'})
            files = root / "files"
            files.mkdir()
            env = {"PATH": f"{d}:/usr/bin:/bin"}
            start = subprocess.run([str(HARNESS / "relay_ss_loop.sh"), "remote-start", "w1", "2", "10", str(files)],
                                   capture_output=True, text=True, timeout=30).stdout
            first = subprocess.run(["/bin/bash", "-c", start], capture_output=True, text=True, env=env, timeout=30)
            self.assertEqual(first.stdout.strip(), "aegis_ss_started")
            sample = files / "aegis-ss-w1.txt"
            for _ in range(50):
                if sample.exists() and sample.read_text().count("\nT ") + sample.read_text().startswith("T ") >= 2 \
                        and sample.read_text().count("cubic") >= 2:
                    break
                subprocess.run(["/bin/sleep", "0.1"])
            text = sample.read_text()
            self.assertEqual(text.count("cubic"), 2, text)
            self.assertNotIn(RELAY, text)
            self.assertEqual(oct(sample.stat().st_mode & 0o777), "0o600")
            again = subprocess.run(["/bin/bash", "-c", start], capture_output=True, text=True, env=env, timeout=30)
            self.assertEqual((again.returncode, again.stdout.strip()), (4, "aegis_ss_leftover"))
            clean = subprocess.run([str(HARNESS / "relay_ss_loop.sh"), "remote-clean", "w1", str(files)],
                                   capture_output=True, text=True, timeout=30).stdout
            done = subprocess.run(["/bin/bash", "-c", clean], capture_output=True, text=True,
                                  env={"PATH": "/usr/bin:/bin"}, timeout=30)
            self.assertEqual((done.returncode, done.stdout.strip()), (0, "aegis_ss_clean"))
            self.assertFalse(sample.exists())

    def test_the_local_mask_refuses_a_literal_it_cannot_mask(self):
        ok = subprocess.run([str(HARNESS / "relay_ss_loop.sh"), "mask"], input=f"a {RELAY}:443 b\n",
                            capture_output=True, text=True, timeout=30)
        self.assertEqual((ok.returncode, ok.stdout), (0, "a 192.0.x.x:443 b\n"))
        # v35 review: `ip tcp_metrics show` prints IPv6 bare, the peer and the
        # relay's own source; ss's own fields stay.
        metrics = (TCP_METRICS + "\t cubic wscale:7,7 rto:204 rtt:180.5/2 bbr:(bw:1.2Mbps,mrtt:180) "
                   "cwnd:20 bytes_acked:1000\n")
        out = subprocess.run([str(HARNESS / "relay_ss_loop.sh"), "mask"], input=metrics, capture_output=True,
                             text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout, TCP_METRICS_MASKED + "\t cubic wscale:7,7 rto:204 rtt:180.5/2 "
                         "bbr:(bw:1.2Mbps,mrtt:180) cwnd:20 bytes_acked:1000\n")
        # A literal the masks cannot take (no boundary before it) is refused
        # whole: exit 3, nothing printed.
        for text in ("id_2001:db8::1 x\n", "a_::1 b\n"):
            bad = subprocess.run([str(HARNESS / "relay_ss_loop.sh"), "mask"], input=text, capture_output=True,
                                 text=True, timeout=30)
            self.assertEqual((bad.returncode, bad.stdout), (3, ""), text)

    def test_the_remote_metrics_command_masks_every_address(self):
        # The printed remote command, run against fakes of sysctl and ip that
        # print IPv4 and bare IPv6 entries: nothing unmasked comes out.
        with tempfile.TemporaryDirectory(prefix="aegis-ss-metrics-") as temp:
            root = pathlib.Path(temp)
            d = fake_bin(root, {"sysctl": 'echo 0\n',
                                "ip": 'cat <<"EOM"\n' + TCP_METRICS + "EOM\n"})
            cmd = subprocess.run([str(HARNESS / "relay_ss_loop.sh"), "remote-metrics"], capture_output=True,
                                 text=True, timeout=30).stdout
            out = subprocess.run(["/bin/bash", "-c", cmd], capture_output=True, text=True,
                                 env={"PATH": f"{d}:/usr/bin:/bin"}, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout, "tcp_no_metrics_save=0\n" + TCP_METRICS_MASKED)
        for literal in (RELAY, MAC, "2001:db8", "::ffff", "fe80::"):
            self.assertNotIn(literal, out.stdout)

    def test_the_mac_sampler_keeps_only_the_relays_443_sockets_masked(self):
        netstat = ('echo "Active Internet connections (including servers)"\n'
                   'echo "Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)"\n'
                   f'echo "tcp4  65536    120  {MAC}.52344      {RELAY}.443        ESTABLISHED"\n'
                   f'echo "tcp4      0      0  {MAC}.52345      {RELAY}.443        CLOSE_WAIT"\n'
                   f'echo "tcp4      7      0  {MAC}.52346      {OTHER}.443        ESTABLISHED"\n'
                   f'echo "tcp4      0      0  {MAC}.52347      {RELAY}.8443       ESTABLISHED"\n')
        with tempfile.TemporaryDirectory(prefix="aegis-sockq-") as temp:
            root = pathlib.Path(temp)
            d = fake_bin(root, {"netstat": netstat, "date": "echo 1793161670\n", "sleep": ":\n"})
            for tool in ("awk", "sed"):
                os.symlink(f"/usr/bin/{tool}", d / tool)
            out = subprocess.run([str(HARNESS / "mac_sockq_loop.sh"), "2", RELAY], capture_output=True, text=True,
                                 env={"PATH": str(d)}, timeout=30)
            bad = subprocess.run([str(HARNESS / "mac_sockq_loop.sh"), "2", "relay.example"], capture_output=True,
                                 text=True, env={"PATH": str(d)}, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.splitlines(), [
            "T 1793161670", "tcp4  65536    120  198.51.x.x.52344      192.0.x.x.443        ESTABLISHED",
            "T 1793161670", "tcp4  65536    120  198.51.x.x.52344      192.0.x.x.443        ESTABLISHED"])
        self.assertEqual((bad.returncode, bad.stdout), (2, ""))


RELAY_SAMPLES = """T 100.0
0      0      192.0.x.x:443  198.51.x.x:5001
\t cubic rtt:180.0/2 cwnd:100 ssthresh:80 bytes_acked:1000 segs_out:10 notsent:70000 busy:1000ms rwnd_limited:0ms delivery_rate 4000000bps
0      0      192.0.x.x:443  198.51.x.x:5002
\t cubic rtt:190.0/2 cwnd:50 bytes_acked:1000 segs_out:10 notsent:0 busy:1000ms rwnd_limited:500ms
T 101.0
0      0      192.0.x.x:443  198.51.x.x:5001
\t cubic rtt:200.0/2 cwnd:70 ssthresh:60 bytes_acked:1500000 segs_out:1010 notsent:90000 busy:2000ms rwnd_limited:0ms retrans:0/3 lost:1
0      0      192.0.x.x:443  198.51.x.x:5002
\t cubic rtt:190.0/2 cwnd:55 bytes_acked:3000000 segs_out:2010 notsent:1000 busy:3000ms rwnd_limited:600ms
T 102.0
0      0      192.0.x.x:443  198.51.x.x:5001
\t cubic rtt:210.0/2 cwnd:72 bytes_acked:2000000 segs_out:1510 notsent:80000 busy:3000ms rwnd_limited:0ms
"""

MAC_SAMPLES = """T 100
tcp4  1000   0  198.51.x.x.60001      192.0.x.x.443        ESTABLISHED
tcp4  50000  0  198.51.x.x.60002      192.0.x.x.443        ESTABLISHED
T 101
tcp4  2000   10 198.51.x.x.60001      192.0.x.x.443        ESTABLISHED
tcp4  60000  0  198.51.x.x.60002      192.0.x.x.443        ESTABLISHED
"""


# A provider log (timestamps, stable lines): the slowest bulk flow is on
# conn 2, which held 64 KiB of extra credit at one point.
PROVIDER_LOG = """2026-10-28 10:39:12.123456+0100 aegis-ne pool_queue conn:2 q_ms:300 held_kib:120 extra_kib:0
2026-10-28 10:39:13.123456+0100 aegis-ne pool_queue conn:2 q_ms:310 held_kib:150 extra_kib:64
2026-10-28 10:39:13.223456+0100 aegis-ne pool_queue conn:1 q_ms:20 held_kib:500 extra_kib:512
2026-10-28 10:40:12.123456+0100 aegis-ne flow_bulk conn:1 kib:51200 ms:60000 win_kib:640
2026-10-28 10:40:13.123456+0100 aegis-ne flow_bulk conn:2 kib:40000 ms:180000 win_kib:128
"""


class RelaySsReviewTests(unittest.TestCase):
    """H5: harness/relay_ss_review.py on synthetic masked samples."""

    def run_review(self, *args, files=None):
        with tempfile.TemporaryDirectory(prefix="aegis-ss-review-") as temp:
            root = pathlib.Path(temp)
            paths = {}
            for name, text in (files or {}).items():
                (root / name).write_text(text)
                paths[name] = str(root / name)
            argv = [a if a not in paths else paths[a] for a in args]
            out = subprocess.run([SYSTEM_PY, "-I", str(HARNESS / "relay_ss_review.py"), *argv],
                                 capture_output=True, text=True, timeout=30)
        return out

    def test_the_relay_review_reads_each_socket_and_counts_cwnd_cuts(self):
        out = self.run_review("relay", "r", files={"r": RELAY_SAMPLES})
        self.assertEqual(out.returncode, 0, out.stderr)
        r = json.loads(out.stdout)
        self.assertEqual(r["samples"], 3)
        socks = {s["port"]: s for s in r["sockets"]}
        a, b = socks["5001"], socks["5002"]
        # 100 -> 70 is a cut of 30%: one loss event; 70 -> 72 none.
        self.assertEqual(a["loss_events"], 1)
        self.assertEqual(b["loss_events"], 0)
        self.assertTrue(a["bulk"] and b["bulk"])
        self.assertEqual(a["bytes"], 1999000)
        self.assertAlmostEqual(a["loss_events_per_segment"], 1 / 1500)
        self.assertEqual((a["notsent_p50"], a["notsent_p90"]), (80000, 90000))
        self.assertEqual((a["rtt_ms_p50"], a["rtt_ms_p90"]), (200.0, 210.0))
        self.assertEqual(a["rwnd_limited_share"], 0.0)
        self.assertAlmostEqual(b["rwnd_limited_share"], 100 / 2000)
        self.assertEqual((a["ssthresh_last"], a["retrans_total"]), (None, None))
        self.assertEqual(a["delivery_bps_p50"], 4000000)
        # Below --min-bytes a socket is not bulk.
        out = self.run_review("relay", "r", "--min-bytes", "2500000", files={"r": RELAY_SAMPLES})
        socks = {s["port"]: s for s in json.loads(out.stdout)["sockets"]}
        self.assertEqual((socks["5001"]["bulk"], socks["5002"]["bulk"]), (False, True))

    def test_the_mac_review_and_the_attribution(self):
        out = self.run_review("mac", "m", files={"m": MAC_SAMPLES})
        m = json.loads(out.stdout)
        self.assertEqual(m["samples"], 2)
        self.assertEqual([(s["port"], s["recvq_p50"], s["recvq_p90"], s["sendq_max"]) for s in m["sockets"]],
                         [("60001", 1000, 2000, 10), ("60002", 50000, 60000, 0)])
        # The slowest bulk relay socket (5001) has notsent p50 80000 >= 64 KiB.
        # v35 review: that is the path's queue only when the slowest bulk
        # flow's connection held no extra credit; with extra credit (or no
        # provider log) the client's credit may have filled it.
        at_v33 = PROVIDER_LOG.replace("extra_kib:64", "extra_kib:0")
        out = self.run_review("attribute", "--relay", "r", "--mac", "m", "--provider-log", "p",
                              files={"r": RELAY_SAMPLES, "m": MAC_SAMPLES, "p": at_v33})
        a = json.loads(out.stdout)
        self.assertEqual((a["label"], a["reason"], a["slowest_port"]), ("path_bound", "relay_send_buffer", "5001"))
        self.assertEqual((a["slowest_flow_conn"], a["slowest_flow_extra_kib_max"]), ("2", 0))
        for files in ({"r": RELAY_SAMPLES, "m": MAC_SAMPLES, "p": PROVIDER_LOG},
                      {"r": RELAY_SAMPLES, "m": MAC_SAMPLES}):
            args = ["attribute", "--relay", "r", "--mac", "m"] + (["--provider-log", "p"] if "p" in files else [])
            a = json.loads(self.run_review(*args, files=files).stdout)
            self.assertEqual((a["label"], a["reason"]), ("credit_or_path", "relay_send_buffer"), files.keys())
        # No relay queue and a busy Mac receive queue: unattributed.
        quiet = RELAY_SAMPLES.replace("notsent:70000", "notsent:0").replace("notsent:90000", "notsent:0") \
            .replace("notsent:80000", "notsent:0")
        out = self.run_review("attribute", "--relay", "r", "--mac", "m", files={"r": quiet, "m": MAC_SAMPLES})
        self.assertEqual(json.loads(out.stdout)["label"], "unattributed")
        # No relay queue, an idle Mac queue and no rwnd limit: the relay's
        # congestion window.
        idle = MAC_SAMPLES.replace("50000", "100").replace("60000", "200")
        out = self.run_review("attribute", "--relay", "r", "--mac", "m", files={"r": quiet, "m": idle})
        a = json.loads(out.stdout)
        self.assertEqual((a["label"], a["reason"]), ("path_bound", "relay_congestion_window"))
        out = self.run_review("attribute", "--relay", "r", "--mac", "missing", files={"r": quiet})
        self.assertEqual(json.loads(out.stdout)["label"], "unavailable")

    def test_missing_fields_and_an_unmasked_literal(self):
        bare = "T 1.0\n0 0 192.0.x.x:443 198.51.x.x:7\n\t cubic\nT 2.0\n"
        out = self.run_review("relay", "r", files={"r": bare})
        r = json.loads(out.stdout)
        self.assertEqual((r["samples"], r["sockets"][0]["bytes"], r["sockets"][0]["bulk"]), (2, 0, False))
        for cmd, name in (("relay", "r"), ("mac", "m")):
            out = self.run_review(cmd, name, files={name: f"T 1\n0 0 {RELAY}:443 x:1\n"})
            self.assertEqual((out.returncode, out.stdout), (3, ""))
            # v35 review: a bare IPv6 literal too.
            out = self.run_review(cmd, name, files={name: "T 1\n0 0 2001:db8::1 x:1\n"})
            self.assertEqual((out.returncode, out.stdout), (3, ""))
        out = self.run_review("attribute", "--relay", "r", "--mac", "m",
                              files={"r": RELAY_SAMPLES, "m": MAC_SAMPLES + f"tcp4 1 1 {MAC}.1 x ESTABLISHED\n"})
        self.assertEqual((out.returncode, out.stdout), (3, ""))
        self.assertEqual(self.run_review("bogus").returncode, 2)


T0 = datetime.datetime(2026, 10, 28, 8, 0, 0, tzinfo=datetime.timezone.utc)
RENEW_AT = T0 + datetime.timedelta(hours=12)
MB = 52428800


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def make_window(root, name, arm, start, rate=400000.0, rates=None, s24b=True, burst90=4.0, echo=900, hs90=800,
                rq=(30, 80), samples=12, policy=("pass", None), run=None, connected=True, streams_override=None,
                expect=None, tunnel="1", provider_log=None, above_initial="yes"):
    """A synthetic window receipt: OUT (results.tsv, load-stream.i,
    provider.log) and OUT.side/run.txt. `rate` (bytes/s) for every stream
    unless `rates`. `connected`: the harness reached its connect (the row
    is written); `tunnel`: the row's value (1 connected, 0 never)."""
    out, side = root / name, root / (name + ".side")
    out.mkdir()
    side.mkdir()
    expect = expect or {"c": "fixed", "t": "adaptive"}.get(arm, "adaptive")
    rows = [("load_preflight", "info", "streams=4 bytes=209715200 per_stream=52428800 bound_s=180")]
    if connected:
        rows.append(("connected", tunnel, "Connected" if tunnel == "1" else "Disconnected"))
    if provider_log is not None:
        (out / "provider.log").write_text(provider_log)
    rows.append(("load_window", "info", "max_kib=900 above_initial=%s" % above_initial))
    rates = list(rates or [rate] * 4)
    for i, r in enumerate(rates, 1):
        if streams_override and i in streams_override:
            (out / ("load-stream.%d" % i)).write_text(streams_override[i])
            continue
        el = MB / r
        if el <= 180:
            line = "bytes=%d rc=0 t0=1000.000 t1=%.3f http=200 status=200\n" % (MB, 1000 + el)
        else:
            line = "bytes=%d rc=28 t0=1000.000 t1=1180.000 http=200 status=200\n" % int(r * 180)
        (out / ("load-stream.%d" % i)).write_text(line)
    verdict = "pass" if s24b else "fail"
    for row in ab_review.S24B_ROWS:
        rows.append((row, verdict if row == "load_download" else "pass", "x"))
    rows.append(("load_flow_burst_90", "pass", "90/90 %.2fs" % burst90))
    rows.append(("load_tcp_echo_v4", "pass", "4/%d/eof" % echo))
    rows.append(("load_provider_rss", "info", "pid=4242 rss_kib_before=1 rss_kib_max=2 growth_kib=1000 samples=6"))
    rows.append(("load_throughput", "info", "total_mbit_s=%.1f per_stream_mbit_s=1 bytes=1 span_s=1"
                 % (sum(rates) * 8 / 1e6)))
    rows.append(("load_latency", "info", "burst24_s=2->2 burst90_s=4->%s tcp_echo_ms=900->%d hs_p50_ms_max=500->600 "
                 "hs_p90_ms_max=700->%d rtt_lines=50 rtt_samples=%d rtt_queue_ms_p50=%s rtt_queue_ms_p90=%s"
                 % (burst90, echo, hs90, samples, rq[0], rq[1])))
    if policy is not None:
        verdict, seen = policy
        rows.append(("window_policy", verdict, "expected=%s seen=%s lines=1" % (expect, seen or expect)))
    rows.append(("window_session_summary", "info", "session_lost=0 renewal_attempts=0"))
    if connected or True:
        (out / "results.tsv").write_text("".join("%s\t%s\t%s\tConnected\ta\tb\n" % r for r in rows))
    tokens = {"window": name, "arm": arm or "none", "env": "LOAD=1" + (",WINDOW_POLICY=fixed" if arm == "c" else ""),
              "build": "35", "source": "abc", "owner_head": "abc", "start": iso(start), "host_free": "1",
              "idle_s": "200", "renew_at": iso(RENEW_AT), "provider_pid_before": "4242"}
    tokens.update(run or {})
    (side / "run.txt").write_text(" ".join("%s=%s" % kv for kv in tokens.items() if kv[1] is not None) + "\n")
    return out


def make_pair(root, plan, k, ratio, attempt=1, gap_s=600, latency_ratio=1.0, c_kw=None, t_kw=None):
    """Pair k, attempt `attempt`: C streams at 400 kB/s, T at `ratio` x."""
    order = plan["pairs"][k - 1]
    start = T0 + datetime.timedelta(seconds=1800 * k + 400 * (attempt - 1))
    for i, arm in enumerate(order):
        kw = dict(c_kw or {}) if arm == "c" else dict(t_kw or {})
        rate = 400000.0 * (ratio if arm == "t" else 1.0)
        burst = 4.0 * (latency_ratio if arm == "t" else 1.0)
        kw.setdefault("rate", rate)
        kw.setdefault("burst90", burst)
        make_window(root, ab_review.window_name(plan, k, arm, attempt), arm,
                    start + datetime.timedelta(seconds=gap_s * i), **kw)


def ran_side(root, name, start=T0):
    side = root / (name + ".side")
    side.mkdir()
    (side / "run.txt").write_text("name=%s start=%s\n" % (name, iso(start)))
    out = root / name
    out.mkdir(exist_ok=True)
    (out / "summary.txt").write_text("single1 bytes=1 s=1 mbit=12.5\nparallel_total bytes=1 span_s=1 mbit=40.0\n")


class AbReviewAnalyzeTests(unittest.TestCase):
    """H6: harness/ab_review.py analyze on synthetic receipts."""

    def setUp(self):
        self.plan = ab_review.load_plan(PLAN)
        temp = tempfile.TemporaryDirectory(prefix="aegis-ab-")
        self.addCleanup(temp.cleanup)
        self.root = pathlib.Path(temp.name)

    def analyze(self):
        return ab_review.analyze(self.plan, str(self.root))

    def test_the_plan_is_the_declared_one_and_a_changed_one_is_refused(self):
        self.assertEqual(ab_review.check_plan(self.plan), [])
        bad = dict(self.plan, pairs=["tc", "ct"] + self.plan["pairs"][2:])
        self.assertIn("pairs_not_declared_order", ab_review.check_plan(bad))
        bad = dict(self.plan, arms={"c": {"WINDOW_POLICY": "", "expect": "adaptive"},
                                    "t": {"WINDOW_POLICY": "", "expect": "adaptive"}})
        self.assertIn("arms_not_declared", ab_review.check_plan(bad))
        bad = {k: v for k, v in self.plan.items() if k != "latency_primary"}
        self.assertIn("missing:latency_primary", ab_review.check_plan(bad))
        # v35 review: every number is pinned; an edited plan is refused.
        for key, value in (("alpha", {"interim": 0.05, "final": 0.05}), ("gain_lower", {"interim": 1.15, "final": 1.0}),
                           ("latency_margin", 1.5), ("s24b_block_p", 0.2), ("final_n_min", 8),
                           ("aggregate_noninferior_lower", 0.8), ("floor_bytes_per_s", 1), ("stream_bound_s", 200),
                           ("sign_min_fraction", 0.5), ("noninferior_lower", 0.8)):
            self.assertEqual(ab_review.check_plan(dict(self.plan, **{key: value})), ["value_not_declared:%s" % key])
        self.assertEqual(ab_review.check_plan(dict(self.plan, extra=1)), ["unknown:extra"])
        out = subprocess.run([SYSTEM_PY, "-I", str(HARNESS / "ab_review.py"), "check-plan", "--plan", str(PLAN)],
                             capture_output=True, text=True, timeout=30)
        self.assertEqual((out.returncode, out.stdout.strip()), (0, "plan_ok v35-ab-r2"))

    def test_the_exact_ratio_and_interval_at_the_interim(self):
        ratios = [1.5, 1.3, 1.6, 1.2, 1.45, 1.35, 1.55, 1.4]
        for k, r in enumerate(ratios, 1):
            make_pair(self.root, self.plan, k, r)
        res = self.analyze()["result"]
        # From the receipts' own S values (bytes over each stream's t1 - t0).
        S = lambda k, arm: ab_review.window_record(self.plan, str(self.root),
                                                   ab_review.window_name(self.plan, k, arm, 1))["S"]
        d = [math.log(S(k, "t") / S(k, "c")) for k in range(1, 9)]
        for got, want in zip(d, ratios):
            self.assertAlmostEqual(got, math.log(want), places=4)
        mean, sd = statistics.mean(d), statistics.stdev(d)
        half = 3.499 * sd / math.sqrt(8)
        thr = res["throughput"]
        self.assertEqual((res["n"], res["look"], res["alpha"]), (8, "interim", 0.01))
        self.assertAlmostEqual(thr["ratio"], math.exp(mean), places=12)
        self.assertAlmostEqual(thr["lower"], math.exp(mean - half), places=12)
        self.assertAlmostEqual(thr["upper"], math.exp(mean + half), places=12)
        self.assertEqual((res["signs"], res["sign_min"]), (8, 6))
        # Every stream at one rate: the aggregate rate's ratio is S's.
        for got, want in zip(res["d_aggregate"], d):
            self.assertAlmostEqual(got, want, places=4)
        # Latency equal in both arms: the primary row's CI is exactly 1.
        self.assertEqual(res["latency"]["burst90_s"]["upper"], 1.0)
        self.assertEqual(res["verdict"], "GAIN")

    def test_a_stream_short_or_past_the_bound_counts_its_bytes_over_180_s(self):
        # One stream that delivered half its bytes and stopped after 10 s, one
        # with every byte after 200 s: both count bytes / 180 s.
        override = {1: "bytes=%d rc=56 t0=1000.0 t1=1010.0 http=200 status=200\n" % (MB // 2),
                    2: "bytes=%d rc=0 t0=1000.0 t1=1200.0 http=200 status=200\n" % MB,
                    3: "garbage\n"}
        make_window(self.root, "x", "t", T0, rate=MB / 100.0, streams_override=override)
        rec = ab_review.window_record(self.plan, str(self.root), "x")
        self.assertAlmostEqual(rec["S"], (MB / 2) / 180 + MB / 180 + 0 + MB / 100.0)
        self.assertAlmostEqual(rec["slowest"], 0.0)
        # The aggregate rate: any incomplete stream makes the makespan 180 s.
        self.assertAlmostEqual(rec["A"], (MB / 2 + MB + MB) / 180)
        # Every stream complete: the bytes over first t0 to last t1, as
        # load_throughput's total_mbit_s.
        make_window(self.root, "y", "t", T0, rates=[MB / 100.0, MB / 50.0, MB / 120.0, MB / 60.0])
        rec = ab_review.window_record(self.plan, str(self.root), "y")
        self.assertAlmostEqual(rec["A"], 4 * MB / 120.0)

    def test_pair_validity_lists_only_the_declared_reasons(self):
        make_pair(self.root, self.plan, 1, 1.2, gap_s=901)
        make_pair(self.root, self.plan, 2, 1.2, c_kw={"run": {"env": "LOAD=1"}})
        make_pair(self.root, self.plan, 3, 1.2, t_kw={"run": {"idle_s": "100", "host_free": "0"}})
        make_pair(self.root, self.plan, 4, 1.2, c_kw={"connected": False})
        # Pair 5: its first window only (incomplete).
        order = self.plan["pairs"][4]
        make_window(self.root, ab_review.window_name(self.plan, 5, order[0], 1), order[0], T0)
        # Pair 6: invalid (an operator abort), then valid as -r2.
        make_pair(self.root, self.plan, 6, 1.2, t_kw={"run": {"invalid": "operator_abort"}})
        make_pair(self.root, self.plan, 6, 1.3, attempt=2)
        # Pair 7: a provider crash after the connect is an observation: valid,
        # an S24b failure for T with the bytes it moved.
        make_pair(self.root, self.plan, 7, 0.5, t_kw={"s24b": False})
        pairs = {p["pair"]: p for p in self.analyze()["pairs"]}
        self.assertEqual(pairs[1]["attempts"][0]["reasons"], ["pair_gap"])
        self.assertEqual(pairs[2]["attempts"][0]["reasons"], ["build_or_env_mismatch"])
        self.assertEqual(sorted(pairs[3]["attempts"][0]["reasons"]), ["host_free_breach", "idle_short"])
        self.assertEqual(pairs[4]["attempts"][0]["reasons"], ["harness_fault_before_connect"])
        self.assertEqual((pairs[5]["status"], pairs[5]["attempts"][0]["status"]), ("pending", "incomplete"))
        self.assertEqual([a["status"] for a in pairs[6]["attempts"]], ["invalid", "valid"])
        self.assertEqual(pairs[6]["attempts"][0]["reasons"], ["operator_abort"])
        self.assertEqual(pairs[6]["windows"]["t"]["name"], "window-v35-ab06-t-r2")
        self.assertEqual(pairs[7]["status"], "valid")
        self.assertFalse(pairs[7]["windows"]["t"]["s24b"])
        res = self.analyze()["result"]
        self.assertEqual((res["verdict"], res["n"]), ("NO_CLAIM", 2))
        # A pair invalid three times is missing.
        for attempt in (1, 2, 3):
            make_pair(self.root, self.plan, 8, 1.2, attempt=attempt, gap_s=1000)
        self.assertEqual({p["pair"]: p for p in self.analyze()["pairs"]}[8]["status"], "missing")
        # A renewal between the windows invalidates the pair.
        make_pair(self.root, self.plan, 9, 1.2, t_kw={"run": {"renew_at": iso(RENEW_AT + datetime.timedelta(1))}})
        self.assertIn("identity_renewal", {p["pair"]: p for p in self.analyze()["pairs"]}[9]["attempts"][0]["reasons"])

    def test_each_verdict(self):
        # NO_CLAIM below 8 valid pairs.
        for k in range(1, 8):
            make_pair(self.root, self.plan, k, 1.5)
        self.assertEqual(self.analyze()["result"]["verdict"], "NO_CLAIM")
        # REGRESSION at the interim.
        root = self.root
        for k, r in enumerate([0.7, 0.75, 0.72, 0.8, 0.7, 0.77, 0.74, 0.71], 1):
            self.root = root / "reg"
            self.root.mkdir(exist_ok=True)
            make_pair(self.root, self.plan, k, r)
        self.assertEqual(self.analyze()["result"]["verdict"], "REGRESSION")
        # CONTINUE at the interim: no clear difference.
        self.root = root / "cont"
        self.root.mkdir()
        spread = [1.6, 0.6, 1.5, 0.65, 1.55, 0.7, 1.4, 0.75]
        for k, r in enumerate(spread, 1):
            make_pair(self.root, self.plan, k, r)
        self.assertEqual(self.analyze()["result"]["verdict"], "CONTINUE")
        # NO_RESOLVABLE_DIFFERENCE at the final.
        for k, r in enumerate(spread, 9):
            make_pair(self.root, self.plan, k, r)
        res = self.analyze()["result"]
        self.assertEqual((res["look"], res["verdict"]), ("final", "NO_RESOLVABLE_DIFFERENCE"))
        # NON_INFERIOR at the final: a small gain whose lower bound is above
        # 0.90 but not above 1.10.
        self.root = root / "ni"
        self.root.mkdir()
        for k, r in enumerate([1.05, 1.1, 1.0, 1.08, 1.12, 1.02, 1.06, 1.04] * 2, 1):
            make_pair(self.root, self.plan, k, r)
        res = self.analyze()["result"]
        self.assertEqual(res["verdict"], "NON_INFERIOR", res["throughput"])
        # A latency regression of the primary row turns a gain into REGRESSION.
        self.root = root / "lat"
        self.root.mkdir()
        for k, r in enumerate([1.5, 1.3, 1.6, 1.2, 1.45, 1.35, 1.55, 1.4], 1):
            make_pair(self.root, self.plan, k, r, latency_ratio=1.6 + 0.01 * k)
        self.assertEqual(self.analyze()["result"]["verdict"], "REGRESSION")
        # S24b (v35 review): the exact one-sided sign test on the discordant
        # pairs. Two T-only failures (p 0.25) neither regress nor block.
        gains = [1.5, 1.3, 1.6, 1.2, 1.45, 1.35, 1.55, 1.4]

        def s24b_case(name, t_fails, c_fails=()):
            self.root = root / name
            self.root.mkdir()
            for k, r in enumerate(gains, 1):
                make_pair(self.root, self.plan, k, r, t_kw={"s24b": k not in t_fails},
                          c_kw={"s24b": k not in c_fails})
            return self.analyze()["result"]
        res = s24b_case("s24b2", (1, 2))
        self.assertEqual((res["s24b_fail"], res["s24b"]["t_only"], res["s24b"]["p_t_worse"]), ({"c": 0, "t": 2}, 2, 0.25))
        self.assertEqual(res["verdict"], "GAIN")
        # Four T-only (p 1/16 = 0.0625 <= 0.10) block GAIN without a
        # regression (p > 0.01 at the interim).
        res = s24b_case("s24b4", (1, 2, 3, 4))
        self.assertEqual((res["s24b"]["p_t_worse"], res["s24b"]["blocks"], res["verdict"]), (0.0625, True, "CONTINUE"))
        # Seven T-only (p 1/128 <= 0.01): REGRESSION at the interim.
        res = s24b_case("s24b7", (1, 2, 3, 4, 5, 6, 7))
        self.assertEqual((res["s24b"]["regression"], res["verdict"]), (True, "REGRESSION"))
        # Discordant both ways (3 against 3, p 0.656): GAIN.
        res = s24b_case("s24b33", (1, 2, 3), (4, 5, 6))
        self.assertEqual((res["s24b"]["t_only"], res["s24b"]["c_only"], res["verdict"]), (3, 3, "GAIN"))
        self.assertAlmostEqual(res["s24b"]["p_t_worse"], 42 / 64)
        # Both failing in a pair is concordant: no evidence either way.
        res = s24b_case("s24b_both", (1, 2, 3, 4, 5, 6, 7), (1, 2, 3, 4, 5, 6, 7))
        self.assertEqual((res["s24b"]["t_only"], res["s24b"]["p_t_worse"], res["verdict"]), (0, 1.0, "GAIN"))

    def test_a_primary_row_missing_in_more_than_two_pairs_blocks_gain(self):
        for k, r in enumerate([1.5, 1.3, 1.6, 1.2, 1.45, 1.35, 1.55, 1.4], 1):
            make_pair(self.root, self.plan, k, r)
        # Three T windows whose burst row has no wall time (the row itself
        # still passes, so S24b is unchanged).
        for k in (1, 2, 3):
            out = self.root / ab_review.window_name(self.plan, k, "t", 1) / "results.tsv"
            out.write_text("".join(("load_flow_burst_90\tpass\t90/90 na\tConnected\ta\tb\n"
                                    if l.startswith("load_flow_burst_90\t") else l)
                                   for l in out.read_text().splitlines(keepends=True)))
        res = self.analyze()["result"]
        self.assertFalse(res["latency"]["burst90_s"]["available"])
        self.assertEqual(res["verdict"], "CONTINUE")
        # rtt_queue rows count only with enough samples; missing there is
        # only reported.
        self.assertTrue(res["latency"]["rtt_queue_p50_ms"]["available"])

    def test_a_window_policy_failure_stops_the_series(self):
        for k in range(1, 4):
            make_pair(self.root, self.plan, k, 1.3, t_kw={"policy": ("fail", "fixed")} if k == 2 else None)
        res = self.analyze()["result"]
        self.assertEqual((res["verdict"], res["stop_reason"]), ("STOPPED", "window_policy_fail"))
        self.assertEqual(res["stopped_at"], "window-v35-ab02-t-r1")
        out = subprocess.run([SYSTEM_PY, "-I", str(HARNESS / "ab_review.py"), "analyze", "--plan", str(PLAN),
                              "--receipts", str(self.root)], capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.splitlines()[-1], "verdict=STOPPED n=3 look=none")
        import hashlib
        self.assertEqual(json.loads(out.stdout.splitlines()[0])["plan_sha256"],
                         hashlib.sha256(PLAN.read_bytes()).hexdigest())

    def test_the_arm_label_and_the_control_mechanism_stop_the_series(self):
        # v35 review: a connected A/B window must pass window_policy with its
        # arm's expected mode; a control window that never connected, or a
        # start refused for its window-policy option, stops the series too.
        refused = "2026-10-28 10:00:00.0+0100 aegis-ne start_refused window_policy_refused\n"
        cases = [
            ("missing_row", {"c_kw": {"policy": None}}, "window_policy_missing", "c"),
            ("arm_mismatch", {"c_kw": {"expect": "adaptive"}}, "window_policy_arm_mismatch", "c"),
            ("c_not_connected", {"c_kw": {"tunnel": "0", "policy": ("unavailable", "none")}},
             "control_not_connected", "c"),
            ("c_refused", {"c_kw": {"tunnel": "0", "policy": ("unavailable", "none"), "provider_log": refused}},
             "control_start_refused", "c"),
            ("t_refused", {"t_kw": {"provider_log": refused}}, "control_start_refused", "t"),
        ]
        for name, kw, reason, arm in cases:
            self.root = pathlib.Path(tempfile.mkdtemp(prefix="aegis-ab-stop-", dir=self.root))
            make_pair(self.root, self.plan, 1, 1.2, **kw)
            res = self.analyze()["result"]
            self.assertEqual((res["verdict"], res["stop_reason"], res["stopped_at"]),
                             ("STOPPED", reason, "window-v35-ab01-%s-r1" % arm), name)
        # A treatment window that never connected is an observation: valid,
        # an S24b FAIL, no stop.
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="aegis-ab-stop-", dir=self.root))
        make_pair(self.root, self.plan, 1, 1.2, t_kw={"tunnel": "0", "policy": ("unavailable", "none"),
                                                     "s24b": False, "rate": 0.0001})
        out = self.analyze()
        self.assertEqual((out["result"]["verdict"], out["pairs"][0]["status"]), ("NO_CLAIM", "valid"))

    def test_a_window_that_moved_nothing_is_floored_and_listed(self):
        empty = {i: "bytes=0 rc=7 t0=1000.0 t1=1000.5 http=000 status=none\n" for i in (1, 2, 3, 4)}
        make_pair(self.root, self.plan, 1, 1.0, t_kw={"streams_override": empty, "s24b": False})
        out = self.analyze()
        t = out["pairs"][0]["windows"]["t"]
        self.assertEqual((t["S_mbit_s"], t["A_mbit_s"], t["floored"]), (1024 * 8 / 1e6, 1024 * 8 / 1e6, True))
        self.assertEqual(out["floored_windows"], ["window-v35-ab01-t-r1"])

    def test_the_aggregate_rate_is_a_co_primary(self):
        # T's three fast streams lift S by 1.7x while its slowest stream
        # finishes last at 0.75x C's rate: the aggregate (bytes over the
        # makespan) regressed, and that is a REGRESSION.
        for k in range(1, 9):
            slow = 300000.0 * (1 + 0.01 * k)
            make_pair(self.root, self.plan, k, 1.0, t_kw={"rates": [800000.0, 800000.0, 800000.0, slow]})
        res = self.analyze()["result"]
        self.assertGreater(res["throughput"]["lower"], 1.15)
        self.assertLess(res["aggregate"]["upper"], 1.0)
        self.assertEqual(res["verdict"], "REGRESSION")
        # An aggregate whose lower bound is under 0.90 (upper above 1.00)
        # blocks GAIN.
        self.root = self.root / "agg"
        self.root.mkdir()
        for k in range(1, 9):
            slow = 600000.0 if k % 2 else 350000.0
            make_pair(self.root, self.plan, k, 1.0, t_kw={"rates": [800000.0, 800000.0, 800000.0, slow]})
        res = self.analyze()["result"]
        self.assertGreater(res["throughput"]["lower"], 1.15)
        self.assertLess(res["aggregate"]["lower"], 0.90)
        self.assertGreater(res["aggregate"]["upper"], 1.0)
        self.assertEqual(res["verdict"], "CONTINUE")

    def test_the_interim_is_taken_once_and_the_final_at_the_series_end(self):
        spread = [1.6, 0.6, 1.5, 0.65, 1.55, 0.7, 1.4, 0.75]
        for k, r in enumerate(spread, 1):
            make_pair(self.root, self.plan, k, r)
        res = self.analyze()["result"]
        self.assertEqual((res["verdict"], res["look"], res["n"], res["pairs"]), ("CONTINUE", "interim", 8,
                                                                               list(range(1, 9))))
        # Two more pairs that would regress: no new look before the end.
        for k in (9, 10):
            make_pair(self.root, self.plan, k, 0.3)
        res = self.analyze()["result"]
        self.assertEqual((res["verdict"], res["n"], res["n_valid"], res["pairs"]), ("CONTINUE", 8, 10,
                                                                                    list(range(1, 9))))
        # Cut short at 10 (deadline): the interim stands, inconclusive.
        (self.root / "series-end.txt").write_text("reason=deadline at=2026-10-28T17:00:00Z\n")
        res = self.analyze()["result"]
        self.assertEqual((res["verdict"], res["look"], res["cut_short"], res["series_end"]),
                         ("CONTINUE", "interim", True, "deadline"))
        # Ended at 12 or more valid pairs: the final look over all of them,
        # alpha 0.05 with t(n - 1).
        for k in (11, 12):
            make_pair(self.root, self.plan, k, 1.0)
        res = self.analyze()["result"]
        self.assertEqual((res["look"], res["n"], res["alpha"], res["sign_min"]), ("final", 12, 0.05, 9))
        d = res["d"]
        half = 2.201 * statistics.stdev(d) / math.sqrt(12)
        self.assertAlmostEqual(res["throughput"]["lower"], math.exp(statistics.mean(d) - half), places=12)
        self.assertEqual(res["interim"]["verdict"], "CONTINUE")
        # Without a declared end and before every pair ran there is no
        # final look; an undeclared reason is not an end.
        (self.root / "series-end.txt").write_text("reason=bored\n")
        self.assertEqual(self.analyze()["result"]["look"], "interim")

    def test_the_w1_growth_evidence_and_the_renewal_strata(self):
        for k in range(1, 5):
            later = {"renew_at": iso(RENEW_AT + datetime.timedelta(hours=12))} if k > 2 else {}
            make_pair(self.root, self.plan, k, 1.2, c_kw={"run": later} if later else None,
                      t_kw={"above_initial": "yes" if k != 2 else "no", **({"run": later} if later else {})})
        out = self.analyze()
        self.assertEqual(out["w1_growth_evidence"], {"t_windows": 4, "above_initial_yes": 3, "half_or_more": True})
        self.assertEqual([(s["pairs"], s["n"]) for s in out["strata"]], [([1, 2], 2), ([3, 4], 2)])


class AbOcTests(unittest.TestCase):
    """The declared rule's operating characteristics (harness/ab_oc.py)."""

    def test_the_simulation_runs_the_declared_rule_and_the_sign_test_holds_its_alpha(self):
        out = subprocess.run([SYSTEM_PY, "-I", str(HARNESS / "ab_oc.py"), "--trials", "5", "--seed", "1"],
                             capture_output=True, text=True, timeout=120)
        self.assertEqual(out.returncode, 0, out.stderr)
        r = json.loads(out.stdout)
        self.assertEqual(len(r["cells"]), 24)
        for cell in r["cells"].values():
            self.assertAlmostEqual(sum(cell["verdicts"].values()), 1.0, places=2)
            self.assertTrue(set(cell["verdicts"]) <= {"GAIN", "NON_INFERIOR", "REGRESSION",
                                                      "NO_RESOLVABLE_DIFFERENCE", "CONTINUE"})
        # Exact, under the null: the sign test never regresses more often
        # than the look's alpha, nor blocks more often than 0.10.
        for f, looks in r["s24b_null_exact"].items():
            self.assertLessEqual(looks["interim_n8_alpha0.01"]["regression"], 0.01, f)
            self.assertLessEqual(looks["final_n16_alpha0.05"]["regression"], 0.05, f)
            for look in looks.values():
                self.assertLessEqual(look["blocks"], 0.10, f)
        plan = ab_review.load_plan(PLAN)
        self.assertEqual(ab_review.binom_upper(7, 7), 1 / 128)
        self.assertEqual(ab_review.binom_upper(0, 0), 1.0)
        self.assertAlmostEqual(ab_review.binom_upper(2, 2), 0.25)
        self.assertEqual(plan["s24b_block_p"], 0.10)


class AbReviewNextTests(unittest.TestCase):
    """H7: harness/ab_review.py next."""

    def setUp(self):
        self.plan = ab_review.load_plan(PLAN)
        temp = tempfile.TemporaryDirectory(prefix="aegis-ab-next-")
        self.addCleanup(temp.cleanup)
        self.root = pathlib.Path(temp.name)

    def next(self, now=None, cert=None):
        return ab_review.next_step(self.plan, str(self.root), now or T0, cert)

    def test_the_declared_order(self):
        self.assertEqual(self.next(), "next=path-probe-v35-s1-r1 kind=sentinel arm=none env=none")
        ran_side(self.root, "path-probe-v35-s1-r1")
        self.assertEqual(self.next(), "next=window-v35-w2-r1 kind=window arm=none env=LOAD=1")
        make_window(self.root, "window-v35-w2-r1", None, T0)
        self.assertEqual(self.next(),
                         "next=window-v35-w1-r1 kind=window arm=none env=LOAD=1,LOAD_BYTES=52428800,LOAD_STREAMS=1")
        make_window(self.root, "window-v35-w1-r1", None, T0)
        self.assertEqual(self.next(), "next=window-v35-ab01-c-r1 kind=window arm=c env=LOAD=1,WINDOW_POLICY=fixed")
        make_window(self.root, "window-v35-ab01-c-r1", "c", T0)
        self.assertEqual(self.next(T0 + datetime.timedelta(seconds=300)),
                         "next=window-v35-ab01-t-r1 kind=window arm=t env=LOAD=1,WINDOW_POLICY=")
        # Pair 02 is tc.
        make_window(self.root, "window-v35-ab01-t-r1", "t", T0 + datetime.timedelta(seconds=300))
        self.assertTrue(self.next(T0).startswith("next=window-v35-ab02-t-r1 kind=window arm=t "))
        for k in (2, 3, 4):
            make_pair(self.root, self.plan, k, 1.2)
        # The sentinel after pair 04 is due before pair 05.
        self.assertEqual(self.next(), "next=path-probe-v35-s2-r1 kind=sentinel arm=none env=none")
        ran_side(self.root, "path-probe-v35-s2-r1")
        self.assertTrue(self.next().startswith("next=window-v35-ab05-t-r1 "))

    def setup_through_prelude(self):
        ran_side(self.root, "path-probe-v35-s1-r1")
        make_window(self.root, "window-v35-w2-r1", None, T0)
        make_window(self.root, "window-v35-w1-r1", None, T0)

    def test_the_gap_and_an_invalid_pair_are_re_run_first(self):
        self.setup_through_prelude()
        make_window(self.root, "window-v35-ab01-c-r1", "c", T0)
        # Past 900 s from the first window's start the second cannot start:
        # the attempt is invalid and is re-run whole.
        self.assertEqual(self.next(T0 + datetime.timedelta(seconds=901)),
                         "next=window-v35-ab01-c-r2 kind=window arm=c env=LOAD=1,WINDOW_POLICY=fixed "
                         "reason=rerun:pair_gap")
        make_pair(self.root, self.plan, 1, 1.2, attempt=2, t_kw={"run": {"idle_s": "10"}})
        self.assertEqual(self.next(), "next=window-v35-ab01-c-r3 kind=window arm=c env=LOAD=1,WINDOW_POLICY=fixed "
                                      "reason=rerun:idle_short")
        make_pair(self.root, self.plan, 1, 1.2, attempt=3, gap_s=1000)
        # Invalid three times: pair 01 is missing and pair 02 is next.
        self.assertTrue(self.next().startswith("next=window-v35-ab02-t-r1 "), self.next())

    def test_the_renewal_margin_and_the_certificate_state(self):
        def cert(state, renew_at):
            path = self.root / "cert.json"
            path.write_text(json.dumps({"schema": "aegis-ne-xpc-v1", "verb": "cert-status",
                                        "report": {"state": state, "renew_at": renew_at}}) + "\n")
            return str(path)
        now = T0
        self.assertEqual(self.next(now, cert("valid", int(now.timestamp()) + 2699)), "refuse:renew_margin")
        self.assertTrue(self.next(now, cert("valid", int(now.timestamp()) + 2700)).startswith("next=path-probe"))
        self.assertEqual(self.next(now, cert("expired", int(now.timestamp()) + 99999)), "refuse:cert_state")
        self.assertEqual(self.next(now, str(self.root / "absent.json")), "refuse:cert_status_unreadable")

    def test_the_interim_stops_on_gain_and_only_the_coda_follows(self):
        self.setup_through_prelude()
        for k, r in enumerate([1.5, 1.3, 1.6, 1.2, 1.45, 1.35, 1.55, 1.4], 1):
            make_pair(self.root, self.plan, k, r)
            if k in (4,):
                ran_side(self.root, "path-probe-v35-s2-r1")
        self.assertEqual(self.next(), "next=path-probe-v35-s3-r1 kind=sentinel arm=none env=none")
        ran_side(self.root, "path-probe-v35-s3-r1")
        self.assertEqual(self.next(), "next=path-probe-v35-s5-r1 kind=sentinel arm=none env=none")
        ran_side(self.root, "path-probe-v35-s5-r1")
        self.assertEqual(self.next(), "next=window-v35-w3-r1 kind=window arm=none env=LOAD=1,LOAD_BYTES=209715200,"
                                      "LOAD_STREAMS=8")
        make_window(self.root, "window-v35-w3-r1", None, T0)
        self.assertEqual(self.next(), "refuse:series_complete")

    def test_a_window_policy_failure_stops_next(self):
        self.setup_through_prelude()
        make_pair(self.root, self.plan, 1, 1.2, c_kw={"policy": ("fail", "adaptive")})
        self.assertEqual(self.next(), "refuse:series_stopped:window_policy_fail:window-v35-ab01-c-r1")

    def test_the_interim_is_taken_once_and_the_series_runs_on(self):
        # v35 review: CONTINUE at the 8th valid pair, then pairs that would
        # be a REGRESSION at 10: `next` still offers pair 11.
        # The first 8 pairs' 99% CI reaches 1.05 (CONTINUE); with two more
        # at 0.8 it would end at 0.98 (a REGRESSION on 10 pairs).
        self.setup_through_prelude()
        for k, r in enumerate([0.75, 0.9, 0.7, 1.05, 0.72, 0.88, 0.78, 1.1], 1):
            make_pair(self.root, self.plan, k, r)
        for name in ("path-probe-v35-s2-r1", "path-probe-v35-s3-r1"):
            ran_side(self.root, name)
        self.assertTrue(self.next().startswith("next=window-v35-ab09-t-r1 "), self.next())
        for k in (9, 10):
            make_pair(self.root, self.plan, k, 0.8)
        pairs, valid = ab_review.pair_table(self.plan, str(self.root))
        self.assertEqual(ab_review.decide(self.plan, valid, "interim")["verdict"], "REGRESSION")
        self.assertTrue(self.next().startswith("next=window-v35-ab11-c-r1 "), self.next())

    def test_the_second_window_is_offered_only_while_it_can_start_in_time(self):
        self.setup_through_prelude()
        make_window(self.root, "window-v35-ab01-c-r1", "c", T0)
        # 720 s after the first start plus the 180 s idle is the 900 s gap.
        self.assertTrue(self.next(T0 + datetime.timedelta(seconds=720)).startswith("next=window-v35-ab01-t-r1 "))
        self.assertEqual(self.next(T0 + datetime.timedelta(seconds=721)),
                         "next=window-v35-ab01-c-r2 kind=window arm=c env=LOAD=1,WINDOW_POLICY=fixed "
                         "reason=rerun:pair_gap")

    def test_a_declared_w2_retry_follows_the_coda(self):
        def through_coda(w2_run):
            self.root = pathlib.Path(tempfile.mkdtemp(prefix="aegis-ab-w2-", dir=self.root))
            ran_side(self.root, "path-probe-v35-s1-r1")
            make_window(self.root, "window-v35-w2-r1", None, T0, run=w2_run)
            make_window(self.root, "window-v35-w1-r1", None, T0)
            (self.root / "series-end.txt").write_text("reason=operator_stop\n")
            ran_side(self.root, "path-probe-v35-s5-r1")
            make_window(self.root, "window-v35-w3-r1", None, T0)
        through_coda({"invalid": "harness_fault_before_connect"})
        self.assertEqual(self.next(), "next=path-probe-v35-w2r2-r1 kind=sentinel arm=none env=none "
                                      "reason=w2_retry:harness_fault_before_connect")
        ran_side(self.root, "path-probe-v35-w2r2-r1")
        self.assertEqual(self.next(), "next=window-v35-w2-r2 kind=window arm=none env=LOAD=1 "
                                      "reason=w2_retry:harness_fault_before_connect")
        make_window(self.root, "window-v35-w2-r2", None, T0)
        self.assertEqual(self.next(), "refuse:series_complete")
        # A valid W2-r1, or one marked for an undeclared reason: no retry.
        for run in (None, {"invalid": "path_was_bad"}):
            through_coda(run)
            self.assertEqual(self.next(), "refuse:series_complete")

    def test_a_declared_series_end_offers_only_the_coda(self):
        self.setup_through_prelude()
        make_pair(self.root, self.plan, 1, 1.2)
        (self.root / "series-end.txt").write_text("reason=host_not_free\n")
        self.assertEqual(self.next(), "next=path-probe-v35-s5-r1 kind=sentinel arm=none env=none")


if __name__ == "__main__":
    unittest.main()
