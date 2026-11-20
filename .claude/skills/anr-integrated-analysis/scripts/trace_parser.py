#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ANR Trace Parser — enhanced from anr-analyzer-kui's anr_analyzer.py.

Enhancements:
- 12 blocking pattern types with severity levels (from anr-analysis-tian)
- Lock holder chain tracing (waiting to lock → holder → holder's stack)
- Kernel blocking point identification for state=D threads
- ANR type classification
- Deadlock detection via circular wait-for graph over ALL threads
- Multi-process dump support: pick a section with --pid

Usage:
  python trace_parser.py <trace_file>
  python trace_parser.py <trace_file> --json
  python trace_parser.py <trace_file> --pid 2002    # pick one section in multi-process dumps
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ThreadInfo:
    name: str
    tid: int
    state: str            # Java state: Native, Blocked, Waiting, etc.
    native_state: str = ""  # Kernel state: D, R, S, W (from | state=X line)
    stack: list = field(default_factory=list)          # only "at ..." / "#NN pc" frames
    locks_held: list = field(default_factory=list)      # raw "- locked <0x...>" lines
    locked_addresses: list = field(default_factory=list)  # "0x..." addresses held
    waiting_for: Optional[str] = None                   # raw waiting line (first one)
    waiting_lock: Optional[str] = None                  # lock address this thread waits on
    waiting_holder_tid: Optional[int] = None            # from "held by thread N"
    is_main: bool = False


@dataclass
class BlockingPattern:
    pattern_type: str     # e.g. "文件IO阻塞"
    severity: str         # 严重 / 高 / 警告
    matched_frame: str    # The stack frame that matched
    pattern_keyword: str  # Which keyword triggered


@dataclass
class LockChainLink:
    waiting_thread: str   # thread name
    waiting_tid: int
    target_lock: str      # lock address ("0x...")
    holder_thread: Optional[str] = None
    holder_tid: Optional[int] = None
    holder_stack: list = field(default_factory=list)


@dataclass
class AnrReport:
    timestamp: str = ""
    pid: int = 0
    package: str = ""
    activity: str = ""
    reason: str = ""
    anr_type: str = ""           # input / broadcast / service / content_provider / no_focus / waiting_previous_event
    waited_ms: int = 0
    main_thread: Optional[ThreadInfo] = None
    all_threads: list[ThreadInfo] = field(default_factory=list)
    blocking_patterns: list[BlockingPattern] = field(default_factory=list)
    lock_chains: list[LockChainLink] = field(default_factory=list)
    deadlock_pairs: list = field(default_factory=list)   # wait-for graph cycles
    temperature: Optional[float] = None
    psi: dict = field(default_factory=dict)
    rss_kb: int = 0
    swap_kb: int = 0
    dump_latency_ms: float = 0
    thread_count: int = 0
    section_pids: list = field(default_factory=list)  # all pids in a multi-process dump


# ---------------------------------------------------------------------------
# 12 Blocking Pattern Types (from anr-analysis-tian)
# ---------------------------------------------------------------------------

BLOCKING_PATTERNS = [
    # (pattern_type, severity, keywords)
    ("同步锁阻塞", "严重", ["synchronized", "ReentrantLock", "Object.wait", "Lock.lock", "futex_wait"]),
    ("文件IO阻塞", "高", ["FileInputStream.read", "FileOutputStream.write", "SharedPreferences", "readFile", "writeFile", "vfs_read", "vfs_write", "ext4_file_read_iter"]),
    ("网络IO阻塞", "高", ["SocketInputStream.read", "HttpURLConnection", "OkHttp", "Retrofit", "connect", "getResponseCode"]),
    ("线程池阻塞", "高", ["LinkedBlockingQueue", "ThreadPoolExecutor", "FutureTask"]),
    ("数据库操作", "高", ["SQLiteDatabase", "android.database.sqlite", "Room", "rawQuery"]),
    ("JSON解析", "高", ["Gson.fromJson", "org.json.JSON", "JsonReader"]),
    ("图片解码", "高", ["BitmapFactory.decode", "BitmapFactory", "Drawable.createFromStream"]),
    ("消息队列阻塞", "警告", ["Handler.sendMessage", "Handler.dispatchMessage", "MessageQueue.next"]),
    ("UI测量耗时", "警告", ["View.measure", "View.layout", "View.onMeasure"]),
    ("UI绘制耗时", "警告", ["View.draw", "View.onDraw", "Canvas.draw"]),
    ("线程休眠", "警告", ["Thread.sleep", "SystemClock.sleep", "Thread.wait"]),
    ("正则表达式", "警告", ["regex", "Pattern.compile", "Pattern.matches"]),
]

# Kernel blocking points for state=D threads (from android-anr-thermal-load-analysis)
KERNEL_BLOCKING_POINTS = {
    "__get_node_page": ("内存页面分配阻塞", "高"),
    "do_page_fault": ("缺页异常处理", "高"),
    "vfs_read": ("文件系统读阻塞", "高"),
    "vfs_write": ("文件系统写阻塞", "高"),
    "ext4_file_read_iter": ("EXT4文件读阻塞", "高"),
    "ext4_file_write_iter": ("EXT4文件写阻塞", "高"),
    "binder_ioctl": ("Binder通信阻塞", "高"),
    "binder_thread_read": ("Binder线程读阻塞", "高"),
    "binder_transaction": ("Binder事务阻塞", "高"),
    "futex_wait": ("锁竞争(futex)", "严重"),
    "__switch_to": ("内核调度切换", "警告"),
    "do_epoll_wait": ("Epoll等待", "警告"),
    "kswapd": ("内存回收(kswapd)", "高"),
    "f2fs_gc": ("F2FS垃圾回收", "高"),
    "zram": ("ZRAM压缩/解压", "高"),
}


# ---------------------------------------------------------------------------
# Lock parsing (real ART/dalvik trace formats)
# ---------------------------------------------------------------------------

# ART lines look like:
#   - waiting to lock <0x09c3e702> (a java.lang.Object) held by thread 27
#   - locked <0x09c3e702> (a java.lang.Object)
#   - waiting on <0x0a1b2c3d> (a java.lang.Class<...>)
WAIT_LOCK_RE = re.compile(r"waiting to lock\s+<(0x[0-9a-fA-F]+)>.*?held by thread\s+(\d+)")
WAIT_LOCK_NO_HOLDER_RE = re.compile(r"waiting to lock\s+<(0x[0-9a-fA-F]+)>")
LOCKED_RE = re.compile(r"^\s*-\s+locked\s+<(0x[0-9a-fA-F]+)>")

# Thread header: "main" prio=5 tid=1 Blocked / "X" daemon prio=5 tid=2 Waiting
THREAD_HEADER_RE = re.compile(r'"([^"]+)"\s+(?:daemon\s+)?prio=(\d+)\s+tid=(\d+)\s+(\w+)')
# Kernel state line inside a thread block: "| state=D schedstat=..."
NATIVE_STATE_RE = re.compile(r"\|\s*state=(\w)")
# Only these look like real stack frames
FRAME_RE = re.compile(r"(at |#\d+ )")
# Multi-process dump section header: "----- pid 2002 at ... ----- / ----- dumping pid: 3579 at ..."
SECTION_RE = re.compile(r"(?m)^----- (?:dumping )?pid:? (\d+) at .*$")


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class TraceParser:
    """Enhanced ANR trace file parser."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.timestamp = ""
        self.pid = 0
        self.package = ""
        self.activity = ""
        self.reason = ""
        self.anr_type = ""
        self.waited_ms = 0
        self.threads: list[ThreadInfo] = []
        self.temperature = None
        self.psi = {}
        self.rss_kb = 0
        self.swap_kb = 0
        self.dump_latency_ms = 0.0
        self.thread_count = 0
        self.section_pids: list[int] = []

    def parse(self, content: str, target_pid: Optional[int] = None) -> bool:
        """Parse ANR trace file content.

        Multi-process dumps (old-style traces.txt with several '----- pid'
        sections) are supported: threads/meta come from ONE section
        (target_pid if given, else the first). Metadata uses first-occurrence
        semantics instead of last-wins, so a later system_server section can
        no longer overwrite the target process's data.
        """
        self.reset()

        sections = list(SECTION_RE.finditer(content))
        self.section_pids = [int(m.group(1)) for m in sections]
        if sections:
            sel = 0
            if target_pid is not None:
                if target_pid not in self.section_pids:
                    return False
                sel = self.section_pids.index(target_pid)
            end = sections[sel + 1].start() if sel + 1 < len(sections) else len(content)
            # Header lines before the first section (Subject:/Reason:/global PSI)
            # are always kept; other sections' threads/meta are not.
            text = content[:sections[0].start()] + content[sections[sel].start():end]
        else:
            text = content

        lines = text.split("\n")
        if not lines:
            return False

        # Parse header / metadata — first match wins
        for line in lines:
            if self.pid == 0 and line.startswith("----- pid"):
                m = re.match(r"^----- (?:dumping )?pid:? (\d+) at (.*?)-*\s*$", line)
                if m:
                    self.pid = int(m.group(1))
                    self.timestamp = m.group(2).strip()

            if line.startswith("Cmd line:") and not self.package:
                self.package = line.split("Cmd line:", 1)[1].strip()

            elif line.startswith("ANR in") and not self.activity:
                m = re.search(r"ANR in (\S+)", line)
                if m:
                    self.activity = m.group(1)

            if "Reason:" in line and not self.reason:
                self.reason = line.split("Reason:", 1)[1].strip()

            if "Subject:" in line and not self.anr_type:
                subject = line.split("Subject:", 1)[1].strip()
                cat = self._classify_anr_type(subject)
                if cat and cat != "unknown":
                    self.anr_type = cat
                if not self.reason:
                    self.reason = subject

            # Waited time
            m = re.search(r"Waited\s+(\d+)ms", line)
            if m and not self.waited_ms:
                self.waited_ms = int(m.group(1))

            # Board temperature
            m = re.search(r"Board Sensor Temperature:\s*(\d+)", line)
            if m and self.temperature is None:
                self.temperature = int(m.group(1)) / 1000.0

            # PSI data
            if "cpu_avg10" not in self.psi:
                m = re.search(r"/proc/pressure/cpu.*?some avg10=([\d.]+)", line, re.DOTALL)
                if not m:
                    m = re.search(r"cpu.*?some avg10=([\d.]+)", line)
                if m:
                    self.psi["cpu_avg10"] = float(m.group(1))

            if "mem_avg10" not in self.psi:
                m = re.search(r"/proc/pressure/memory.*?some avg10=([\d.]+)", line, re.DOTALL)
                if not m:
                    m = re.search(r"memory.*?some avg10=([\d.]+)", line, re.DOTALL)
                if m:
                    self.psi["mem_avg10"] = float(m.group(1))

            if "mem_full_avg10" not in self.psi:
                m = re.search(r"/proc/pressure/memory.*?full avg10=([\d.]+)", line, re.DOTALL)
                if m:
                    self.psi["mem_full_avg10"] = float(m.group(1))

            if "io_avg10" not in self.psi:
                m = re.search(r"/proc/pressure/io.*?some avg10=([\d.]+)", line, re.DOTALL)
                if not m:
                    m = re.search(r"io.*?some avg10=([\d.]+)", line, re.DOTALL)
                if m:
                    self.psi["io_avg10"] = float(m.group(1))

            # Memory
            m = re.search(r"RssKb:\s*(\d+)", line)
            if m and not self.rss_kb:
                self.rss_kb = int(m.group(1))
            m = re.search(r"VmSwapKb:\s*(\d+)", line)
            if m and not self.swap_kb:
                self.swap_kb = int(m.group(1))

            # Dump latency
            m = re.search(r"DumpLatencyMs?:\s*([\d.]+)", line)
            if m and not self.dump_latency_ms:
                self.dump_latency_ms = float(m.group(1))

            # Thread count
            m = re.search(r"DALVIK THREADS\s*\((\d+)\)", line)
            if m and not self.thread_count:
                self.thread_count = int(m.group(1))

        # Parse threads
        current_thread = None

        for line in lines:
            thread_match = THREAD_HEADER_RE.match(line)
            if thread_match:
                if current_thread:
                    self.threads.append(current_thread)
                current_thread = ThreadInfo(
                    name=thread_match.group(1),
                    tid=int(thread_match.group(3)),
                    state=thread_match.group(4),
                )
                current_thread.is_main = (current_thread.name == "main")
                continue

            if not current_thread:
                continue

            stripped = line.strip()
            if not stripped:
                continue

            # Kernel state: "| state=D schedstat=..."
            m = NATIVE_STATE_RE.match(stripped)
            if m:
                current_thread.native_state = m.group(1)
                continue

            # Lock lines (real ART/dalvik format)
            if stripped.startswith("- locked"):
                m2 = LOCKED_RE.match(stripped)
                if m2:
                    current_thread.locked_addresses.append(m2.group(1))
                    current_thread.locks_held.append(stripped)
                continue

            if stripped.startswith("- waiting to lock") or stripped.startswith("- waiting on"):
                if current_thread.waiting_for is None:
                    current_thread.waiting_for = stripped
                m2 = WAIT_LOCK_RE.search(stripped)
                if m2:
                    if current_thread.waiting_lock is None:
                        current_thread.waiting_lock = m2.group(1)
                        current_thread.waiting_holder_tid = int(m2.group(2))
                else:
                    m3 = WAIT_LOCK_NO_HOLDER_RE.search(stripped)
                    if m3 and current_thread.waiting_lock is None:
                        current_thread.waiting_lock = m3.group(1)
                continue

            # Stack frames: only Java "at ..." and native "#NN pc ..." lines.
            # "| group=...", "| sysTid=...", "| schedstat=..." etc. are skipped.
            if FRAME_RE.match(stripped):
                current_thread.stack.append(stripped)

        if current_thread:
            self.threads.append(current_thread)

        return len(self.threads) > 0

    @staticmethod
    def _classify_anr_type(subject: str) -> Optional[str]:
        """Classify ANR type from Subject line."""
        if not subject:
            return None
        if "Input dispatching" in subject:
            return "input"
        if re.search(r"broadcast|Broadcast of", subject, re.IGNORECASE):
            return "broadcast"
        if re.search(r"content ?provider", subject, re.IGNORECASE):
            return "content_provider"
        if re.search(r"waiting previous|Waiting Previous Event", subject, re.IGNORECASE):
            return "waiting_previous_event"
        if "no focus" in subject.lower() or "No focused window" in subject:
            return "no_focus"
        # 'service' is checked last: the word leaks into broadcast/provider subjects
        if re.search(r"executing service|service", subject, re.IGNORECASE):
            return "service"
        return "unknown"

    def get_main_thread(self) -> Optional[ThreadInfo]:
        """Get the main thread."""
        for t in self.threads:
            if t.name == "main":
                return t
        return None

    def detect_blocking_patterns(self, thread: ThreadInfo) -> list[BlockingPattern]:
        """Identify all blocking patterns in thread stack (12 types)."""
        patterns = []
        all_frames = "\n".join(thread.stack)

        for pattern_type, severity, keywords in BLOCKING_PATTERNS:
            for kw in keywords:
                if kw in all_frames:
                    # Find the specific frame
                    matched_frame = ""
                    for frame in thread.stack:
                        if kw in frame:
                            matched_frame = frame
                            break
                    patterns.append(BlockingPattern(
                        pattern_type=pattern_type,
                        severity=severity,
                        matched_frame=matched_frame,
                        pattern_keyword=kw,
                    ))
                    break  # One match per pattern type

        # Also check for kernel blocking points (in native state)
        if thread.native_state == "D":
            for kw, (desc, severity) in KERNEL_BLOCKING_POINTS.items():
                if kw in all_frames:
                    matched_frame = ""
                    for frame in thread.stack:
                        if kw in frame:
                            matched_frame = frame
                            break
                    patterns.append(BlockingPattern(
                        pattern_type=f"内核:{desc}",
                        severity=severity,
                        matched_frame=matched_frame,
                        pattern_keyword=kw,
                    ))

        return patterns

    def _resolve_holders(self) -> tuple:
        """Shared resolution maps for chains/deadlock.

        Returns (by_tid, waits_on) where waits_on[tid] = (holder_tid, lock_addr)
        for every thread waiting on a resolvable holder. Holder is resolved via
        'held by thread N' first, then via the addr→locker map from '- locked' lines.
        """
        by_tid = {t.tid: t for t in self.threads}
        addr_owner: dict = {}
        for t in self.threads:
            for addr in t.locked_addresses:
                addr_owner.setdefault(addr, t)

        waits_on: dict = {}
        for t in self.threads:
            if not t.waiting_lock:
                continue
            holder = None
            if t.waiting_holder_tid is not None:
                holder = by_tid.get(t.waiting_holder_tid)
            if holder is None or holder.tid == t.tid:
                cand = addr_owner.get(t.waiting_lock)
                if cand is not None and cand.tid != t.tid:
                    holder = cand
            if holder is not None and holder.tid != t.tid:
                waits_on[t.tid] = (holder.tid, t.waiting_lock)
        return by_tid, waits_on

    def build_lock_chains(self, max_depth: int = 6) -> list[LockChainLink]:
        """Build lock-holder chains for EVERY waiting thread (not just main).

        Each link: 'thread X waits for lock <addr>, held by thread Y',
        followed transitively into Y's own wait (up to max_depth hops).
        """
        chains = []
        by_tid, waits_on = self._resolve_holders()
        if not waits_on:
            return chains

        for t in self.threads:
            if t.tid not in waits_on:
                continue
            seen = {t.tid}
            cur_tid = t.tid
            while cur_tid in waits_on and len(seen) <= max_depth:
                holder_tid, lock = waits_on[cur_tid]
                if holder_tid in seen:
                    break
                holder = by_tid.get(holder_tid)
                waiter = by_tid.get(cur_tid)
                if holder is None or waiter is None:
                    break
                chains.append(LockChainLink(
                    waiting_thread=waiter.name,
                    waiting_tid=waiter.tid,
                    target_lock=lock,
                    holder_thread=holder.name,
                    holder_tid=holder.tid,
                    holder_stack=holder.stack[:15],
                ))
                seen.add(holder_tid)
                cur_tid = holder_tid

        # De-duplicate identical (waiter→holder, lock) edges produced by
        # transitive walks overlapping between threads.
        uniq = []
        seen_edges = set()
        for c in chains:
            key = (c.waiting_tid, c.holder_tid, c.target_lock)
            if key not in seen_edges:
                seen_edges.add(key)
                uniq.append(c)
        return uniq

    def detect_deadlock(self) -> list:
        """Detect circular waits: cycles in the thread wait-for graph.

        Edge: A → B when A is 'waiting to lock <addr>' and B holds it.
        A cycle = true deadlock (every thread in it is blocked forever).
        """
        by_tid, waits_on = self._resolve_holders()
        cycles = []
        visited_in_cycle: set = set()

        for start in waits_on:
            if start in visited_in_cycle:
                continue
            path = []
            idx = {}
            cur = start
            while cur in waits_on and cur not in idx:
                idx[cur] = len(path)
                path.append(cur)
                cur = waits_on[cur][0]
            if cur in idx:
                cyc = path[idx[cur]:]
                visited_in_cycle.update(cyc)
                cycles.append({
                    "type": "cycle",
                    "length": len(cyc),
                    "threads": [
                        {
                            "name": by_tid[tid].name if tid in by_tid else f"tid-{tid}",
                            "tid": tid,
                            "waiting_for_lock": waits_on[tid][1],
                            "blocked_by_tid": waits_on[tid][0],
                        }
                        for tid in cyc
                    ],
                })
        return cycles

    def analyze(self, content: str, target_pid: Optional[int] = None) -> Optional[AnrReport]:
        """Perform complete ANR trace analysis."""
        if not self.parse(content, target_pid=target_pid):
            return None

        main_thread = self.get_main_thread()
        if not main_thread:
            return None

        blocking_patterns = self.detect_blocking_patterns(main_thread)
        lock_chains = self.build_lock_chains()
        deadlock_pairs = self.detect_deadlock()

        return AnrReport(
            timestamp=self.timestamp,
            pid=self.pid,
            package=self.package,
            activity=self.activity,
            reason=self.reason,
            anr_type=self.anr_type,
            waited_ms=self.waited_ms,
            main_thread=main_thread,
            all_threads=self.threads,
            blocking_patterns=blocking_patterns,
            lock_chains=lock_chains,
            deadlock_pairs=deadlock_pairs,
            temperature=self.temperature,
            psi=self.psi,
            rss_kb=self.rss_kb,
            swap_kb=self.swap_kb,
            dump_latency_ms=self.dump_latency_ms,
            thread_count=self.thread_count,
            section_pids=list(self.section_pids),
        )

    def format_report(self, report: AnrReport) -> str:
        """Format analysis report as human-readable text."""
        lines = []
        lines.append("=" * 60)
        lines.append("          ANR Trace分析报告")
        lines.append("=" * 60)
        lines.append("")

        lines.append("[基本信息]")
        lines.append(f"  包名: {report.package or '未知'}")
        lines.append(f"  PID: {report.pid or '未知'}")
        lines.append(f"  Activity: {report.activity or '未知'}")
        lines.append(f"  ANR类型: {report.anr_type or '未知'}")
        lines.append(f"  Reason: {report.reason or '未知'}")
        if report.waited_ms:
            lines.append(f"  超时时长: {report.waited_ms}ms")
        if report.temperature is not None:
            lines.append(f"  设备温度: {report.temperature:.1f}°C")
        if len(report.section_pids) > 1:
            lines.append(f"  多进程dump: 含 {len(report.section_pids)} 个进程段 {report.section_pids}"
                         f"（当前解析 pid={report.pid}，其余用 --pid 选择）")
        lines.append("")

        lines.append("[主线程状态]")
        mt = report.main_thread
        lines.append(f"  线程名: {mt.name}")
        lines.append(f"  TID: {mt.tid}")
        lines.append(f"  Java状态: {mt.state}")
        if mt.native_state:
            lines.append(f"  Native状态: {mt.native_state}")
        if mt.waiting_for:
            lines.append(f"  等待: {mt.waiting_for}")
        lines.append(f"  总线程数: {report.thread_count}")
        lines.append("")

        if report.blocking_patterns:
            lines.append("[阻塞模式检测]")
            for bp in report.blocking_patterns:
                lines.append(f"  [{bp.severity}] {bp.pattern_type}")
                lines.append(f"    匹配帧: {bp.matched_frame[:120]}")
            lines.append("")

        if report.lock_chains:
            lines.append("[锁持有者链]")
            for lc in report.lock_chains:
                lines.append(f"  {lc.waiting_thread} (TID={lc.waiting_tid}) "
                             f"等待锁 <{lc.target_lock}> → 持有者: {lc.holder_thread} (TID={lc.holder_tid})")
                if lc.holder_stack:
                    lines.append(f"    持有者栈顶: {lc.holder_stack[0][:120]}")
            lines.append("")

        if report.deadlock_pairs:
            lines.append("[死锁检测] ⚠️")
            for cyc in report.deadlock_pairs:
                ring = " -> ".join(f"{x['name']}(tid={x['tid']})" for x in cyc["threads"])
                lines.append(f"  环形等待 ({cyc['length']} 节点): {ring} -> {cyc['threads'][0]['name']}")
                for x in cyc["threads"]:
                    lines.append(f"    {x['name']} (tid={x['tid']}) 等待 <{x['waiting_for_lock']}> "
                                 f"由 tid={x['blocked_by_tid']} 持有")
            lines.append("")

        if report.psi:
            lines.append("[PSI压力]")
            if "cpu_avg10" in report.psi:
                lines.append(f"  CPU avg10: {report.psi['cpu_avg10']}%")
            if "mem_avg10" in report.psi:
                lines.append(f"  Memory avg10: {report.psi['mem_avg10']}%")
            if "io_avg10" in report.psi:
                lines.append(f"  IO avg10: {report.psi['io_avg10']}%")
            lines.append("")

        lines.append("[主线程堆栈 (前15帧)]")
        for i, frame in enumerate(mt.stack[:15]):
            lines.append(f"  {i+1}. {frame}")
        if len(mt.stack) > 15:
            lines.append(f"  ... 还有 {len(mt.stack) - 15} 帧")
        lines.append("")

        return "\n".join(lines)

    def to_dict(self, report: AnrReport) -> dict:
        """Convert report to JSON-serializable dict."""
        bp_list = []
        for bp in report.blocking_patterns:
            bp_list.append({
                "pattern_type": bp.pattern_type,
                "severity": bp.severity,
                "matched_frame": bp.matched_frame,
                "keyword": bp.pattern_keyword,
            })

        lc_list = []
        for lc in report.lock_chains:
            lc_list.append({
                "waiting_thread": lc.waiting_thread,
                "waiting_tid": lc.waiting_tid,
                "target_lock": lc.target_lock,
                "holder_thread": lc.holder_thread,
                "holder_tid": lc.holder_tid,
                "holder_stack_top": lc.holder_stack[:5] if lc.holder_stack else [],
            })

        mt = report.main_thread
        return {
            "timestamp": report.timestamp,
            "pid": report.pid,
            "all_pids_in_dump": report.section_pids,
            "package": report.package,
            "activity": report.activity,
            "reason": report.reason,
            "anr_type": report.anr_type,
            "waited_ms": report.waited_ms,
            "main_thread": {
                "name": mt.name,
                "tid": mt.tid,
                "state": mt.state,
                "native_state": mt.native_state,
                "waiting_for": mt.waiting_for,
                "waiting_lock": mt.waiting_lock,
                "locked_addresses": mt.locked_addresses,
                "stack": mt.stack[:20],
            },
            "thread_count": report.thread_count,
            "blocking_patterns": bp_list,
            "lock_chains": lc_list,
            "deadlock_cycles": report.deadlock_pairs,
            "temperature": report.temperature,
            "psi": report.psi,
            "rss_kb": report.rss_kb,
            "swap_kb": report.swap_kb,
            "dump_latency_ms": report.dump_latency_ms,
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="ANR Trace Parser (Enhanced)")
    parser.add_argument("file", help="Path to ANR trace file (.txt or .trace)")
    parser.add_argument("--pid", type=int, default=None,
                        help="Target pid when the dump contains several process sections")
    parser.add_argument("--json", action="store_true", help="Output JSON format")
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"Error: File not found: {args.file}")
        sys.exit(1)

    content = path.read_text(encoding="utf-8", errors="replace")

    tp = TraceParser()
    report = tp.analyze(content, target_pid=args.pid)

    if not report:
        if args.pid and tp.section_pids and args.pid not in tp.section_pids:
            print(f"Error: pid {args.pid} not found in dump. Available pids: {tp.section_pids}")
        else:
            print("Error: Unable to parse ANR trace file.")
        sys.exit(1)

    if args.json:
        print(json.dumps(tp.to_dict(report), indent=2, ensure_ascii=False, default=str))
    else:
        print(tp.format_report(report))


if __name__ == "__main__":
    main()
