"""B-06 SLEEP=1 of harness/real-relay-window.sh: the scheduled-wake check
and the detached sleep guard. Runs under /usr/bin/python3 -I (3.9).

    sleep_guard.py check PMSET HI
        Prints the kind of wake that `PMSET -g sched` lists and that fires
        by HI (epoch seconds): `at` for a one-time wake (or wakeorpoweron)
        at least MIN_LEAD_S seconds after now and at or before HI (a wake
        closer than that may pass before the system is asleep), `relative`
        for a listed relative wake whose seconds, when the line names any,
        fit before HI. Exit 0 when one is listed, 1 when none is, 2 on bad
        arguments.

    sleep_guard.py disabled PMSET
        v30: prints SleepDisabled of the unprivileged `PMSET -g`, `0` or `1`
        (`pmset disablesleep`; a missing line is 0), or `unknown` when
        `pmset -g` fails or names no "System-wide power settings" block.
        While it is 1 the kernel refuses every demand sleep
        (kPMUserDisabledAllSleep) and `pmset sleepnow` exits 71. Exit 0.

    sleep_guard.py text
        v30: one bounded, printable line of standard input (BOUNDED_TEXT
        characters, addresses masked), for the window's rows.

    sleep_guard.py guard PMSET LOG WINDOW SETTLE [CALL_S]
        Forks and exits; the child is adopted by launchd, leads its own
        process group in the window's session (sudo's credential of this
        terminal is per session, so a new session could not use it) and
        ignores INT, TERM, HUP and QUIT. It is armed before any wake is
        scheduled: `armed pid=...`, then (v30) one `credential sudo=ok|...
        sleep_disabled=0|1|unknown` line from its own read-only
        `sudo -n -l /usr/bin/pmset` and `PMSET -g`, so the window refuses
        (no wake scheduled) unless this very process could ask for the
        sleep. It waits up to GO_WAIT_S for LOG.go (`hi=<epoch>`, the bound
        of the wake the window scheduled and read back) or LOG.cancel.
        After the go and SETTLE seconds it refuses when the window process
        WINDOW is gone, when LOG.cancel exists, when SleepDisabled is not 0
        or when no wake is listed by the go's hi. v30 review: it then
        creates LOG.claim exclusively (`guard pid=... at=...`); the window
        stands the guard down by writing LOG.cancel and creating the same
        file (`window`), so exactly one of them holds it. Without the claim
        it refuses (`cancelled`); with it, it checks LOG.cancel and the
        window once more and otherwise runs `sudo -n /usr/bin/pmset
        sleepnow` once (never a prompt, never a retry), bounded by CALL_S
        seconds (default CALL_S_DEFAULT). A window that does not hold the
        claim therefore keeps its dated wake: the request may have run.
        Every verdict is one line of LOG: `sleep_refused <reason>` or
        `sleep_requested rc=<rc> at=<epoch> wake=<kind> cause=<cause>
        [error=0x...] out=[...] err=[...]` with the command's own bounded
        stdout and stderr (pmset writes its errors to stdout). On a timeout
        only the user's sudo is killed; the root pmset it started may still
        ask for the sleep, so `rc=timeout` is no proof that nothing slept.

Nothing here reads or writes an address or key material; command output is
bounded and any address-shaped text in it is masked (an IPv4 address also
before a full stop or a port, an IPv6 address also with an embedded IPv4
tail or before a colon).
"""
import os
import re
import signal
import subprocess
import sys
import time

AT = re.compile(r"\bwake(?:orpoweron)? at (\d{1,2})/(\d{1,2})/(\d{2,4}) (\d{1,2}):(\d{2}):(\d{2})\b")
SECONDS = re.compile(r"\b(\d+)\b")
# An absolute wake must still be this far ahead when sleep is asked for.
MIN_LEAD_S = 15
# The window schedules and reads back its wake within this after arming.
GO_WAIT_S = 60
# v30: the privileged sleep request's bound, and the range a caller may set.
CALL_S_DEFAULT = 20
CALL_S_RANGE = (1, 60)
# v30: characters kept of any command output in the log.
BOUNDED_TEXT = 200
# v30 review: four dotted octets whatever follows them but a digit, so an
# address before a full stop or a port (tcpdump's 192.0.2.7.5353) is
# masked too; a longer dotted number loses four of its parts (over-masking
# is the safe side).
IPV4 = re.compile(r"(?<![0-9])\d{1,3}(?:\.\d{1,3}){3}(?![0-9])")
# Six groups, also before a colon or a full stop that ends a sentence.
MAC = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,2}[:-]){5}[0-9A-Fa-f]{1,2}(?![:-]?[0-9A-Fa-f])")
# v30 review: a colon-separated run of hex groups of any length, with an
# optional zone; `_ipv6` decides whether it is address-shaped. IPv4 is
# masked first, so an embedded IPv4 tail (::ffff:192.0.2.7) loses all four
# octets instead of the three IPV6 left behind.
IPV6 = re.compile(r"(?<![0-9A-Fa-f:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,}(?:%\w+)?")
PMSET_ERROR = re.compile(r"\berror (0x[0-9a-fA-F]{1,8})\b")


def _ipv6(match):
    """`<ipv6>` for a run with `::` or at least three colons, a lone
    trailing colon (punctuation) kept outside the mask; a time of day
    (11:13:54) stays."""
    text = match.group(0)
    core, tail = text, ""
    if core.endswith(":") and not core.endswith("::"):
        core, tail = core[:-1], ":"
    if "::" in core or core.count(":") >= 3:
        return "<ipv6>" + tail
    return text


def bounded(data, limit=BOUNDED_TEXT):
    """One printable ASCII line of at most `limit` characters: line breaks
    become ` | `, other control or non-ASCII characters `?`, brackets
    parentheses, and IPv4, IPv6 and MAC addresses `<ipv4>`, `<ipv6>` and
    `<mac>`."""
    if isinstance(data, bytes):
        data = data[:64 * 1024].decode("utf-8", "replace")
    else:
        data = (data or "")[:64 * 1024]
    text = " | ".join(part.strip() for part in data.splitlines() if part.strip())
    text = MAC.sub("<mac>", text)
    text = IPV4.sub("<ipv4>", text)
    text = IPV6.sub(_ipv6, text)
    text = "".join(c if " " <= c <= "~" else "?" for c in text)
    text = text.replace("[", "(").replace("]", ")")
    return text[:limit]


def classify(rc, out, err):
    """The cause of one `sudo -n /usr/bin/pmset sleepnow` result, and the
    pmset error code when its stdout names one."""
    code = PMSET_ERROR.search(out or "")
    code = code.group(1).lower() if code else ""
    if rc == "timeout":
        return "timeout", code
    if rc == 0:
        return "ok", code
    if rc == 1 and "password is required" in (err or ""):
        return "sudo_no_credential", code
    if rc == 71:
        return "pmset_not_permitted", code
    if rc == 77:
        return "pmset_not_root", code
    return "other", code


def text_of(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value


def run_bounded(argv, seconds):
    """rc (or `timeout`/`error`) and the stdout and stderr, partial output
    kept on a timeout."""
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=seconds)
        return result.returncode, text_of(result.stdout), text_of(result.stderr)
    except subprocess.TimeoutExpired as expired:
        return "timeout", text_of(expired.stdout), text_of(expired.stderr)
    except OSError as error:
        return "error", "", str(error)


def sleep_disabled(pmset):
    """`0`, `1` or `unknown`: SleepDisabled of `pmset -g`'s system-wide
    block."""
    try:
        result = subprocess.run([pmset, "-g"], capture_output=True, text=True, timeout=10,
                                stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    if result.returncode != 0:
        return "unknown"
    block = None
    for line in result.stdout.splitlines():
        if line.strip() == "System-wide power settings:":
            block = True
            continue
        if block is None:
            continue
        if not line[:1].isspace():
            break
        fields = line.split()
        if len(fields) >= 2 and fields[0] == "SleepDisabled":
            return {"0": "0", "1": "1"}.get(fields[1], "unknown")
    return "0" if block else "unknown"


def sched_lines(pmset):
    try:
        out = subprocess.run([pmset, "-g", "sched"], capture_output=True, text=True, timeout=10,
                             stdin=subprocess.DEVNULL).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    return out.splitlines()


def listed(lines, hi, now):
    """The kind of the first listed wake that fires at least MIN_LEAD_S
    after now and by hi."""
    for line in lines:
        low = line.lower()
        if "wake" not in low:
            continue
        if "relative" in low:
            numbers = [int(n) for n in SECONDS.findall(low)]
            # `[0]` style indices are not seconds; a relative wake names at most one count.
            numbers = [n for n in numbers if f"[{n}]" not in low]
            if not numbers or numbers[-1] <= hi - now:
                return "relative"
            continue
        m = AT.search(low)
        if not m:
            continue
        mo, day, year, hh, mm, ss = (int(g) for g in m.groups())
        if year < 100:
            year += 2000
        try:
            t = time.mktime((year, mo, day, hh, mm, ss, 0, 0, -1))
        except (OverflowError, ValueError):
            continue
        if now + MIN_LEAD_S <= t <= hi:
            return "at"
    return ""


def window_alive(pid):
    try:
        stat = subprocess.run(["/bin/ps", "-p", str(pid), "-o", "stat="], capture_output=True, text=True,
                              timeout=10, stdin=subprocess.DEVNULL).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return False
    return bool(stat) and not stat.startswith("Z")


def read_go(logp):
    """The hi of LOG.go, None while it is absent, -1 when it is malformed."""
    try:
        text = open(logp + ".go").read()
    except OSError:
        return None
    m = re.fullmatch(r"hi=(\d{1,12})\n?", text)
    return int(m.group(1)) if m else -1


def credential():
    """`ok`, or why this process's `sudo -n` could not run pmset, with the
    command's bounded stderr."""
    rc, _, err = run_bounded(["sudo", "-n", "-l", "/usr/bin/pmset"], 10)
    if rc == 0:
        return "ok", ""
    cause = "no_credential" if rc == 1 and "password is required" in err else "refused"
    return cause, f" rc={rc} err=[{bounded(err)}]"


def disabled_refusal(value):
    return "sleep_refused sleep_disabled\n" if value == "1" else "sleep_refused sleep_disabled_unknown\n"


def claim(logp, holder):
    """v30 review: create LOG.claim exclusively. True when this caller now
    holds it; False when the other side does (or it cannot be created)."""
    try:
        fd = os.open(logp + ".claim", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    except OSError:
        return False
    try:
        os.write(fd, holder.encode() + b"\n")
    finally:
        os.close(fd)
    return True


def guard(pmset, logp, window, settle, call_s=CALL_S_DEFAULT):
    if os.fork() > 0:
        os._exit(0)
    os.setpgid(0, 0)
    for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
        signal.signal(s, signal.SIG_IGN)
    log = open(logp, "a", buffering=1)
    log.write(f"armed pid={os.getpid()} ppid={os.getppid()} settle={settle}\n")
    # The one check that matters: this process, detached as it is when it
    # asks for the sleep, can use the terminal's sudo credential (-l only).
    sudo, detail = credential()
    disabled = sleep_disabled(pmset)
    log.write(f"credential sudo={sudo} sleep_disabled={disabled}{detail}\n")
    if sudo != "ok":
        log.write(f"sleep_refused {sudo}\n")
        return 0
    if disabled != "0":
        log.write(disabled_refusal(disabled))
        return 0
    end = time.monotonic() + GO_WAIT_S
    hi = None
    while True:
        if os.path.exists(logp + ".cancel"):
            log.write("sleep_refused cancelled\n")
            return 0
        hi = read_go(logp)
        if hi is not None:
            break
        if not window_alive(window):
            log.write("sleep_refused window_gone\n")
            return 0
        if time.monotonic() >= end:
            log.write("sleep_refused no_go\n")
            return 0
        time.sleep(0.25)
    if hi < 0:
        log.write("sleep_refused bad_go\n")
        return 0
    time.sleep(settle)
    if os.path.exists(logp + ".cancel"):
        log.write("sleep_refused cancelled\n")
        return 0
    if not window_alive(window):
        log.write("sleep_refused window_gone\n")
        return 0
    # Read again right before the request: a disabled sleep gets no
    # privileged call at all.
    disabled = sleep_disabled(pmset)
    if disabled != "0":
        log.write(disabled_refusal(disabled))
        return 0
    lines = sched_lines(pmset)
    kind = listed(lines, hi, time.time())
    if not kind:
        log.write(f"sleep_refused no_scheduled_wake lines={len(lines)}\n")
        return 0
    # v30 review: the request and the window's stand-down exclude each
    # other. Once this guard holds the claim the window keeps its wake.
    if not claim(logp, f"guard pid={os.getpid()} at={time.time():.0f}"):
        log.write("sleep_refused cancelled\n")
        return 0
    if os.path.exists(logp + ".cancel"):
        log.write("sleep_refused cancelled\n")
        return 0
    if not window_alive(window):
        log.write("sleep_refused window_gone\n")
        return 0
    at = time.time()
    rc, out, err = run_bounded(["sudo", "-n", "/usr/bin/pmset", "sleepnow"], call_s)
    cause, code = classify(rc, out, err)
    error = f" error={code}" if code else ""
    log.write(f"sleep_requested rc={rc} at={at:.0f} wake={kind} cause={cause}{error} "
              f"out=[{bounded(out)}] err=[{bounded(err)}]\n")
    return 0


def main(argv):
    try:
        if argv[:1] == ["check"] and len(argv) == 3:
            kind = listed(sched_lines(argv[1]), int(argv[2]), time.time())
            if kind:
                print(kind)
            return 0 if kind else 1
        if argv[:1] == ["disabled"] and len(argv) == 2:
            print(sleep_disabled(argv[1]))
            return 0
        if argv == ["text"]:
            print(bounded(sys.stdin.buffer.read(64 * 1024)))
            return 0
        if argv[:1] == ["guard"] and len(argv) in (5, 6):
            call_s = int(argv[5]) if len(argv) == 6 else CALL_S_DEFAULT
            if not CALL_S_RANGE[0] <= call_s <= CALL_S_RANGE[1]:
                raise ValueError(call_s)
            return guard(argv[1], argv[2], int(argv[3]), int(argv[4]), call_s)
    except ValueError:
        pass
    sys.stderr.write("usage: sleep_guard.py check PMSET HI | disabled PMSET | text"
                     " | guard PMSET LOG WINDOW SETTLE [CALL_S]\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
