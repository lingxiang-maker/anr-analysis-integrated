#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Smoke tests for anr-integrated-analysis scripts (stdlib only).

Run from anywhere:
  python3 -I .claude/skills/anr-integrated-analysis/tests/smoke_test.py

These lock in the bugs fixed in v2.1.0:
  * trace_parser: real ART '- waiting to lock/- locked' lines resolve holder
    chains and deadlock cycles (old prefix checks returned [] always)
  * trace_parser: multi-process sections, --pid selection, first-wins meta,
    stack no longer polluted with '| group=/| sysTid=/| schedstat=' lines
  * scan.build_time_pattern: 'HH:M' ten-minute windows expand correctly
    under grep -E; malformed windows raise instead of silently dropping hits
  * thermal_analyzer: throttling is baseline-relative (a 1.8GHz SoC running
    full speed is NOT 'throttled' below the old hardcoded 2GHz threshold)
  * ANR-type classification: 'service' keyword no longer leaks over
    broadcast/provider subjects
  * scan.py grep-facing patterns: no '\d' (literal 'd' under real GNU grep
    ERE) and no '[:\s]' bracket class (never matches a space — silently
    killed the bgreport temperature/battery lookups)
"""

import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

import scan                # noqa: E402
import trace_parser        # noqa: E402
from thermal_analyzer import ThermalAnalyzer, minute_regex  # noqa: E402

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + ("" if cond else f" — {detail}"))
    if not cond:
        FAILURES.append(name)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

ART_TRACE = """Subject: Input dispatching timed out (abc)
Reason: Input dispatching timed out

----- pid 1908 at 2026-11-05 19:40:12.345 -----
Cmd line: com.example.app
DALVIK THREADS (4)

"main" prio=5 tid=1 Blocked
  | group="main" sCount=1 dsCount=0 obj=0x12fc self=0x7d
  | sysTid=1908 nice=-10 cgrp=default handle=0x7e
  | state=D schedstat=( 1234 5678 90 ) utm=100 stm=23 core=2 HZ=300
  at android.os.BinderProxy.transactNative(Native method)
  at com.example.LockHolder.waitHere(LockHolder.java:42)
  - waiting to lock <0x09c3e702> (a java.lang.Object) held by thread 27
  - locked <0x0aaa1111> (a com.example.Foo)

"WorkerOne" prio=5 tid=10 Blocked
  at com.example.A.run(A.java:10)
  - waiting to lock <0x0bbb2222> (a java.lang.Object) held by thread 11
  - locked <0x0ccc3333> (a java.lang.Object)

"WorkerTwo" prio=5 tid=11 Blocked
  at com.example.B.run(B.java:20)
  - waiting to lock <0x0ccc3333> (a java.lang.Object) held by thread 10

"BinderThreadD" daemon prio=5 tid=27 Blocked
  at com.example.C.hold(C.java:30)
  - locked <0x09c3e702> (a java.lang.Object)
----- end 1908 -----

----- pid 3579 at 2026-11-05 19:40:12.555 -----
Cmd line: system_server
DALVIK THREADS (1)
"main" prio=5 tid=1 Runnable
  | state=R schedstat=( 1 2 3 )
  at zzz(zz.java:1)
----- end 3579 -----
"""


def write_thermal_file(path, hot=20, cool=20, cool_temp=30000, hot_temp=41000,
                      base_freq=1804800, hot_freq=1150000):
    lines = []
    for i in range(cool):
        lines.append(f"11-05 20:5{i % 10}:{i:02d}.000 D/SS-THERM: SS-CPU4 "
                     f"VIRTUAL-SENSOR {cool_temp} {{[cpu0 {base_freq}][cpu4 {base_freq}]}}")
    for i in range(hot):
        lines.append(f"11-05 20:5{i % 10}:{30 + i if 30 + i < 60 else 30 + i - 60:02d}.000 D/SS-THERM: SS-CPU4 "
                     f"VIRTUAL-SENSOR {hot_temp} {{[cpu0 {hot_freq}][cpu4 {hot_freq}]}}")
    Path(path).write_text("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# 1. trace_parser — ART lock lines / chains / cycles / stacks / sections
# ---------------------------------------------------------------------------

tp = trace_parser.TraceParser()
rep = tp.analyze(ART_TRACE)
check("trace: parse returns report", rep is not None)
if rep:
    check("trace: first-wins meta (target pid, not system_server)",
          rep.pid == 1908 and rep.package == "com.example.app",
          f"pid={rep.pid} pkg={rep.package}")
    check("trace: section pids detected", rep.section_pids == [1908, 3579], str(rep.section_pids))
    mt = rep.main_thread
    check("trace: main thread Blocked + kernel state D captured",
          mt.state == "Blocked" and mt.native_state == "D", repr(mt.native_state))
    check("trace: stack only contains frames (no '| group/sysTid/schedstat')",
          [f for f in mt.stack] == [
              "at android.os.BinderProxy.transactNative(Native method)",
              "at com.example.LockHolder.waitHere(LockHolder.java:42)"],
          str(mt.stack))
    chain_to_27 = [c for c in rep.lock_chains
                   if c.waiting_tid == 1 and c.target_lock == "0x09c3e702" and c.holder_tid == 27]
    check("trace: main 'waiting to lock ... held by thread 27' resolves holder",
          bool(chain_to_27), str([(c.waiting_tid, c.holder_tid) for c in rep.lock_chains]))
    cyc = [c for c in rep.deadlock_pairs if c.get("type") == "cycle"]
    check("trace: WorkerOne<->WorkerTwo circular wait detected",
          any(sorted(t["tid"] for t in c["threads"]) == [10, 11] for c in cyc),
          str(cyc))
    check("trace: ANR type from Subject", rep.anr_type == "input", rep.anr_type)
    d = tp.to_dict(rep)
    check("trace: to_dict exposes cycle + holder fields",
          d["deadlock_cycles"] and d["main_thread"]["waiting_lock"] == "0x09c3e702")

rep2 = trace_parser.TraceParser().analyze(ART_TRACE, target_pid=3579)
check("trace: --pid style section selection",
      rep2 is not None and rep2.pid == 3579 and rep2.package == "system_server")
check("trace: unknown target pid rejected loudly",
      trace_parser.TraceParser().parse(ART_TRACE, target_pid=9999) is False)

# ---------------------------------------------------------------------------
# 2. scan.build_time_pattern — window formats + loud failures
# ---------------------------------------------------------------------------

p_1940 = scan.build_time_pattern("19:4")
check("time: '19:4' expands to ten-minute window and matches 19:40:12.345",
      p_1940 and re.search(p_1940, "11-05 19:40:12.345") and not re.search(p_1940, "11-05 19:39:59.100"),
      p_1940)
p_hour = scan.build_time_pattern("19")
check("time: hour-only '19' matches any 19:xx:xx",
      p_hour and re.search(p_hour, "11-05 19:05:01.000"), p_hour)
p_exact = scan.build_time_pattern("19:40:12")
check("time: 'HH:MM:SS' accepted",
      p_exact and re.search(p_exact, "11-05 19:40:12.345"), p_exact)
check("time: empty window → None (no filter)", scan.build_time_pattern("") is None)
try:
    scan.build_time_pattern("abc")
    check("time: malformed window raises ValueError", False, "no exception")
except ValueError:
    check("time: malformed window raises ValueError", True)

# grep -E compatibility: [0-9] not \\d
with tempfile.TemporaryDirectory() as td:
    fp = Path(td) / "log.txt"
    fp.write_text("11-05 19:40:12.345 hit\n11-05 19:39:59.000 miss\n")
    res = subprocess.run(["grep", "-aEc", scan.build_time_pattern("19:4"), str(fp)],
                         capture_output=True, text=True)
    check("time: pattern works under real GNU grep -E", res.stdout.strip() == "1",
          f"stdout={res.stdout!r} stderr={res.stderr!r}")

# ---------------------------------------------------------------------------
# 3. thermal_analyzer — baseline-relative throttling
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as td:
    hot_f, norm_f, allhot_f = (str(Path(td) / n) for n in
                               ("hot.txt", "norm.txt", "allhot.txt"))
    write_thermal_file(hot_f)
    write_thermal_file(norm_f, hot=0, cool=20)
    write_thermal_file(allhot_f, hot=20, cool=0)

    ta = ThermalAnalyzer(hot_f)
    ta.parse()
    r = ta.analyze()
    check("thermal: 1.8GHz-SoC cool full-speed records NOT counted as throttled "
          "(old 2GHz rule said 40/40)", r.throttling_records == 20,
          f"throttled={r.throttling_records}/{r.total_records}")
    check("thermal: grade counts ≥38 / ≥40",
          r.high_temp_records == 20 and r.severe_temp_records == 20)
    v = ta.get_verdict(r)
    check("thermal: verdict 高温限频主导 / high / 严重",
          (v["category"], v["confidence"], v["severity"]) == ("高温限频主导", "high", "严重"),
          str(v))
    check("thermal: per-core baselines captured",
          r.baseline.get("cpu0") == 1804800 and r.baseline.get("cpu4") == 1804800,
          str(r.baseline))

    ta_n = ThermalAnalyzer(norm_f)
    ta_n.parse()
    r_n = ta_n.analyze()
    check("thermal: all-normal file → 0 throttled, 温度正常",
          r_n.throttling_records == 0 and ta_n.get_verdict(r_n)["category"] == "温度正常")

    ta_a = ThermalAnalyzer(allhot_f)
    ta_a.parse()
    r_a = ta_a.analyze()
    check("thermal: no cool records → baseline_missing flagged", r_a.baseline_missing is True)

    # time-window normalization + loud garbage
    ta_w = ThermalAnalyzer(hot_f)
    ta_w.parse(time_window="20:5")
    check("thermal: window '20:5' keeps whole ten-minute block", ta_w.records and len(ta_w.records) == 40,
          str(len(ta_w.records)))
    ta_w2 = ThermalAnalyzer(hot_f)
    ta_w2.parse(time_window="20:51")
    # i=1 and i=11 both land in minute 20:51 (2 cool + 2 hot)
    check("thermal: window '20:51' filters other minutes out", len(ta_w2.records) == 4,
          str(len(ta_w2.records)))
    try:
        minute_regex("not-a-time")
        check("thermal: bad window raises", False, "no exception")
    except ValueError:
        check("thermal: bad window raises", True)

# ---------------------------------------------------------------------------
# 4. ANR type classification — 'service' leakage fixed
# ---------------------------------------------------------------------------

check("classify: 'Timeout executing service …' → service",
      scan.classify_anr_type("Timeout executing service com.foo/.Bar") == "service")
check("classify: 'Broadcast of Intent {cmp=…Service}' → broadcast (not service)",
      scan.classify_anr_type("Broadcast of Intent { cmp=com.x/.MyService }") == "broadcast")
check("classify: provider subject → content_provider",
      scan.classify_anr_type("ContentProvider com.x/.P timed out") == "content_provider"
      and trace_parser.TraceParser._classify_anr_type("Waiting for content provider com.x/.P") == "content_provider")
check("classify: input subject consistent across scan/trace_parser",
      scan.classify_anr_type("Input dispatching timed out (x)")
      == trace_parser.TraceParser._classify_anr_type("Input dispatching timed out (x)") == "input")

# ---------------------------------------------------------------------------
# 5. grep-pattern portability guards (real GNU grep: '\d'/'[:\s]' = silent dead)
# ---------------------------------------------------------------------------

_scan_src = (SCRIPTS / "scan.py").read_text(encoding="utf-8")

check("pattern: 'Board Sensor Temperature: 41976' matches temp regex (space after colon)",
      re.search(r"[Tt]emperature[ :=]+([0-9]+\.?[0-9]*)", "Board Sensor Temperature: 41976") is not None)
check("pattern: 'level: 85' matches battery level regex",
      re.search(r"level[ :=]+([0-9]+)", "  level: 85%") is not None)
_bad_digit = [ln for ln in _scan_src.splitlines()
              if ("search_file(" in ln or "run_grep(" in ln or "search_file_section(" in ln)
              and r"\d" in ln]
check("scan.py: no grep-facing pattern uses \\d (ERE-incompatible)",
      not _bad_digit, f"offending: {_bad_digit[:2]}")
check("scan.py: no '[:\\s]' bracket class (never matches a space)",
      r"[:\s]" not in _scan_src)

# ---------------------------------------------------------------------------

print()
if FAILURES:
    print(f"SMOKE TEST FAILED — {len(FAILURES)} failing: {FAILURES}")
    sys.exit(1)
print("SMOKE TEST PASSED")
