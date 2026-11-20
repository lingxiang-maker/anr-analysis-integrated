#!/usr/bin/env python3
"""
ANR Scan Tool — enhanced CLI for anr-integrated-analysis skill.
Zero external dependencies. Python 3.9+.

Run all commands from a CONSISTENT working directory (recommended: project
root), using the full relative path to this script:
  python3 .claude/skills/anr-integrated-analysis/scripts/scan.py <command> ...
Session file .anr_session.json and reports/ live in the current directory.

Usage:
  scan.py init <zip_or_dir>                    Summarize ANR files (dirs used IN PLACE, no copy)
  scan.py blind <time_window> [extract_dir]    Blind sweep 11 dimensions
  scan.py why <keyword> [extract_dir]          Root cause追问
  scan.py bgreport [extract_dir]               Bugreport 14-item comprehensive check
  scan.py cleanup                              Delete temp extract directory + session file

Time window format (blind): "HH:MM" (exact minute, e.g. "19:40"),
"HH:M" (ten-minute prefix, e.g. "19:4" = 19:40-19:49), "HH" (whole hour),
or "HH:MM:SS". Invalid formats now fail loudly instead of silently
filtering every hit out.

Examples:
  scan.py init bugreport.zip
  scan.py blind "19:40"
  scan.py why binder_lock ./extracted
  scan.py bgreport ./extracted
  scan.py cleanup
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Optional


# Allow importing sibling modules (thermal_analyzer) regardless of cwd
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TIME_WINDOW_RE = re.compile(r"^\d{1,2}(:\d{1,2}){0,2}$")


def _minute_regex(time_window: str) -> str:
    """Normalize '19', '19:4' or '19:40' to a grep-EREG 'HH:MM' pattern.
    '19:4' -> '19:4[0-9]' (whole ten-minute), '19' -> '19:[0-9][0-9]'.
    Uses [0-9] (not \\d) so it works with plain grep -E too.
    """
    parts = time_window.strip().split(":")
    hour = re.escape(parts[0])
    if len(parts) == 1:
        return hour + r":[0-9][0-9]"
    minute = parts[1]
    if len(minute) == 1:
        return hour + ":" + re.escape(minute) + r"[0-9]"
    return hour + ":" + re.escape(minute)


def build_time_pattern(time_window: str) -> Optional[str]:
    """Build a timestamp regex from a window like '10:29', '19:4', or '19'.

    Returns None for empty input (no time filtering). Raises ValueError for
    malformed windows — a broken window must fail loudly, never silently
    filter every hit out.
    """
    if not time_window or not time_window.strip():
        return None
    w = time_window.strip()
    if not TIME_WINDOW_RE.match(w):
        raise ValueError(
            f"Invalid time window {time_window!r}. "
            "Use HH / HH:M / HH:MM (e.g. '19:40') or HH:MM:SS."
        )
    parts = w.split(":")
    if len(parts) >= 3:
        return _minute_regex(w) + ":" + re.escape(parts[2]) + r"[0-9]?\.?[0-9]*"
    return _minute_regex(w) + r":[0-9][0-9]\.?"


def run_grep(pattern: str, *paths: str, context: int = 0, max_count: int = 20, time_filter: str = None):
    """Run grep on given paths. Returns (results, warnings).

    warnings records timeouts / grep errors / out-of-window matches —
    'no hits' WITH a warning is not evidence of absence (Rule 1 discipline).
    """
    results = []
    warnings = []
    for p in paths:
        path = Path(p)
        if not path.exists():
            continue
        recursive = path.is_dir()
        if not path.is_file() and not recursive:
            continue
        label = "<dir>" if recursive else str(path)
        cmd = ["grep", "-aE"] + (["-rn"] if recursive else ["-n"]) + ["-m", str(max_count)]
        if context:
            cmd += ["-C", str(context)]
        cmd += [pattern, str(path)]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired:
            warnings.append(f"grep timeout (120s): {path} — 'no hits' here is UNRELIABLE, grep manually")
            continue
        except OSError as e:
            warnings.append(f"grep failed on {path}: {e}")
            continue
        if out.returncode not in (0, 1):
            warnings.append(f"grep error on {path} (rc={out.returncode})")
        if out.stdout.strip():
            raw = out.stdout.strip().split("\n")
            lines = raw
            if time_filter:
                lines = [l for l in raw if re.search(time_filter, l)]
                if raw and not lines:
                    warnings.append(f"{path}: {len(raw)} matches found but ALL outside time window")
            if lines:
                results.append({"file": label, "lines": lines[:max_count]})
    return results, warnings


def find_anr_files(extract_dir: Path) -> list:
    """Find ANR data by scanning file content, not file names."""
    anr_files = []
    markers = [b"Subject:", b"DALVIK THREADS", b"----- dumping pid"]

    known_anr_dirs = [
        extract_dir / "FS" / "data" / "anr",
        extract_dir / "data" / "anr",
        extract_dir / "anr",
    ]
    for d in extract_dir.rglob("bugreport*"):
        if d.is_dir():
            known_anr_dirs.append(d / "FS" / "data" / "anr")
            known_anr_dirs.append(d / "data" / "anr")
    for d in extract_dir.rglob("hyperBugreport*"):
        if d.is_dir():
            known_anr_dirs.append(d / "FS" / "data" / "anr")
            known_anr_dirs.append(d / "data" / "anr")

    for d in known_anr_dirs:
        if d.exists():
            for f in d.iterdir():
                if f.is_file() and not f.name.endswith(".zip"):
                    anr_files.append(f)

    if anr_files:
        seen = set()
        unique = []
        for f in sorted(anr_files, key=lambda x: x.name):
            if f not in seen:
                seen.add(f)
                unique.append(f)
        return unique

    for f in extract_dir.rglob("*"):
        if not f.is_file():
            continue
        size = f.stat().st_size
        if size > 500 * 1024 * 1024:
            continue
        if f.suffix in (".zip", ".dex", ".apk", ".png", ".jpg", ".jpeg", ".mp4", ".proto", ".dump"):
            continue
        try:
            with open(f, "rb") as fh:
                head = fh.read(8192)
                if any(m in head for m in markers):
                    anr_files.append(f)
                    continue
                if size > 100 * 1024:
                    fh.seek(size // 2)
                    mid = fh.read(8192)
                    if any(m in mid for m in markers):
                        anr_files.append(f)
        except (OSError, IOError):
            pass

    seen = set()
    unique = []
    for f in sorted(anr_files, key=lambda x: x.name):
        if f not in seen:
            seen.add(f)
            unique.append(f)
    return unique


def _is_bugreport_content(f: Path) -> bool:
    """Check if a file is a bugreport by reading its header (MQS compatibility)."""
    try:
        with open(f, "rb") as fh:
            head = fh.read(512)
            if b"== headline:" in head or b"== debuggable:" in head:
                return True
            if b"Build:" in head and b"Command line:" in head:
                return True
    except (OSError, IOError):
        pass
    return False


def find_log_files(extract_dir: Path) -> list:
    """Find log/text files, prioritizing bugreport and logcat files."""
    log_files = []
    priority_files = []

    for f in extract_dir.rglob("*"):
        if not f.is_file():
            continue
        if f.suffix not in (".txt", ".log", ""):
            continue
        if "appLog" in str(f):
            continue
        if f.stat().st_size > 200 * 1024 * 1024:
            continue
        name_lower = f.name.lower()
        if any(k in name_lower for k in ("bugreport", "main_log", "sys_log", "events_log")):
            priority_files.append(f)
        elif f.suffix == "" and f.stat().st_size > 1024 * 1024:
            if _is_bugreport_content(f):
                priority_files.append(f)
            else:
                log_files.append(f)
        else:
            log_files.append(f)

    return priority_files + log_files


def find_largest_bugreport(extract_dir: Path) -> Optional[str]:
    """Find the main bugreport text file for logcat searches."""
    preferred_txt = None
    largest_txt = None
    largest_size = 0
    large_bugreport = None

    for f in extract_dir.rglob("*"):
        if not f.is_file():
            continue
        if f.suffix not in (".txt", ".log", ""):
            if f.stat().st_size > 200 * 1024 * 1024 and _is_bugreport_content(f):
                large_bugreport = str(f)
            continue
        name_lower = f.name.lower()
        if f.stat().st_size > 200 * 1024 * 1024:
            if _is_bugreport_content(f):
                large_bugreport = str(f)
            continue
        if not preferred_txt and ("bugreport" in name_lower or "main_log" in name_lower or "sys_log" in name_lower):
            preferred_txt = str(f)
        if f.suffix == "" and not preferred_txt and f.stat().st_size > 1024 * 1024:
            if _is_bugreport_content(f):
                preferred_txt = str(f)
        if f.stat().st_size > largest_size:
            largest_size = f.stat().st_size
            largest_txt = str(f)

    if large_bugreport:
        preferred_txt = large_bugreport
    return preferred_txt or largest_txt


def find_dumpstate_file(extract_dir: Path) -> Optional[str]:
    """Find dumpstate_board.txt or thermal.dump."""
    for f in extract_dir.rglob("dumpstate_board.txt"):
        return str(f)
    for f in extract_dir.rglob("thermal.dump"):
        return str(f)
    return None


def find_sys_version_file(extract_dir: Path) -> Optional[str]:
    """Find sys_version.txt for device info."""
    for f in extract_dir.rglob("sys_version.txt"):
        return str(f)
    return None


def parse_anr_summary(anr_file: Path) -> dict:
    """Parse one ANR file for key fields."""
    text = anr_file.read_text(encoding="utf-8", errors="replace")
    result = {
        "file": str(anr_file),
        "subject": None,
        "pid": None,
        "process": None,
        "main_state": None,
        "psi_cpu_avg10": None,
        "psi_mem_avg10": None,
        "psi_io_avg10": None,
        "rss_kb": None,
        "swap_kb": None,
        "heap_free_pct": None,
        "dump_latency_ms": None,
        "thread_count": None,
    }

    m = re.search(r"Subject:\s*(.+)", text)
    if m:
        result["subject"] = m.group(1).strip()

    m = re.search(r"----- pid (\d+) at", text)
    if not m:
        m = re.search(r"dumping pid:\s*(\d+)", text)
    if m:
        result["pid"] = m.group(1)

    m = re.search(r"Cmd line:\s*(.+)", text)
    if m:
        result["process"] = m.group(1).strip()

    m = re.search(r'"main".*?state=([A-Z])\b', text)
    if not m:
        pid = result.get("pid")
        if pid:
            m = re.search(rf'sysTid={pid}\s+state=([A-Z])', text)
    if m:
        result["main_state"] = m.group(1)

    m = re.search(r"/proc/pressure/cpu.*?some avg10=([\d.]+)", text, re.DOTALL)
    if not m:
        m = re.search(r"cpu.*?some avg10=([\d.]+)", text)
    if m:
        result["psi_cpu_avg10"] = float(m.group(1))
    m = re.search(r"/proc/pressure/memory.*?some avg10=([\d.]+)", text, re.DOTALL)
    if not m:
        m = re.search(r"memory.*?some avg10=([\d.]+)", text, re.DOTALL)
    if m:
        result["psi_mem_avg10"] = float(m.group(1))
    m = re.search(r"/proc/pressure/io.*?some avg10=([\d.]+)", text, re.DOTALL)
    if not m:
        m = re.search(r"io.*?some avg10=([\d.]+)", text, re.DOTALL)
    if m:
        result["psi_io_avg10"] = float(m.group(1))

    m = re.search(r"RssKb:\s*(\d+)", text)
    if m:
        result["rss_kb"] = int(m.group(1))
    m = re.search(r"VmSwapKb:\s*(\d+)", text)
    if m:
        result["swap_kb"] = int(m.group(1))

    m = re.search(r"free_pct[:=]\s*([\d.]+)", text)
    if m:
        result["heap_free_pct"] = float(m.group(1))

    m = re.search(r"DumpLatencyMs?:\s*([\d.]+)", text)
    if m:
        result["dump_latency_ms"] = float(m.group(1))

    m = re.search(r"DALVIK THREADS\s*\((\d+)\)", text)
    if m:
        result["thread_count"] = int(m.group(1))

    # Extract ANR type classification (single shared implementation)
    result["anr_type"] = classify_anr_type(result["subject"])

    # Extract ANR reason duration
    m = re.search(r"Waited\s+(\d+)ms", text)
    if m:
        result["waited_ms"] = int(m.group(1))

    # Extract board temperature from ANR file
    m = re.search(r"Board Sensor Temperature:\s*(\d+)", text)
    if m:
        result["board_temp"] = int(m.group(1)) / 1000.0

    return result


# ---------------------------------------------------------------------------
# ANR Type Classification
# ---------------------------------------------------------------------------

# Order matters: more specific types first; "service" last because the word
# appears in many subjects of other types.
ANR_TYPE_PATTERNS = {
    "input": r"Input dispatching timed out",
    "broadcast": r"broadcast|Broadcast of",
    "content_provider": r"ContentProvider|content provider",
    "no_focus": r"no focus|No focused window",
    "waiting_previous_event": r"[Ww]aiting [Pp]revious [Ee]vent|waiting previous",
    "service": r"service|executing service",
}


def classify_anr_type(subject: str) -> Optional[str]:
    """Classify ANR type from Subject line."""
    if not subject:
        return None
    for anr_type, pattern in ANR_TYPE_PATTERNS.items():
        if re.search(pattern, subject, re.IGNORECASE):
            return anr_type
    return "unknown"


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_init(args):
    """Extract zip (or use dir in place) and show ANR summary."""
    artifact = Path(args.path)
    if not artifact.exists():
        print(json.dumps({"error": f"Path not found: {args.path}"}))
        sys.exit(1)

    extract_dir = None
    in_place = False
    if artifact.suffix.lower() == ".zip":
        if not zipfile.is_zipfile(artifact):
            print(json.dumps({"error": f"Not a valid zip file: {args.path}"}))
            sys.exit(1)
        extract_dir = Path(args.output) if args.output else Path(tempfile.mkdtemp(prefix="anr_scan_"))
        extract_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(artifact, "r") as zf:
            zf.extractall(extract_dir)
        if args.all_nested:
            for _ in range(3):
                nested_zips = list(extract_dir.rglob("*.zip"))
                if not nested_zips:
                    break
                for nested in nested_zips:
                    try:
                        with zipfile.ZipFile(nested, "r") as zf:
                            zf.extractall(extract_dir)
                    except Exception:
                        pass
        else:
            for nested in extract_dir.rglob("*.zip"):
                if nested.name.startswith("bugreport") or nested.name.startswith("hyperBugreport"):
                    try:
                        with zipfile.ZipFile(nested, "r") as zf:
                            zf.extractall(extract_dir / nested.stem)
                    except Exception:
                        pass
    elif artifact.is_dir():
        # Use the directory IN PLACE — never copy multi-GB bugreports.
        extract_dir = artifact.resolve()
        in_place = True
    else:
        print(json.dumps({"error": "Unsupported format. Use .zip or directory."}))
        sys.exit(1)

    anr_files = find_anr_files(extract_dir)

    output = {
        "extract_dir": str(extract_dir),
        "in_place": in_place,
        "anr_files": [str(f) for f in anr_files],
    }

    if anr_files:
        summaries = []
        for f in anr_files[:20]:
            try:
                s = parse_anr_summary(f)
                summaries.append({
                    "file": str(f),
                    "subject": s.get("subject"),
                    "pid": s.get("pid"),
                    "process": s.get("process"),
                    "anr_type": s.get("anr_type"),
                    "main_state": s.get("main_state"),
                    "waited_ms": s.get("waited_ms"),
                    "psi_cpu_avg10": s.get("psi_cpu_avg10"),
                    "psi_mem_avg10": s.get("psi_mem_avg10"),
                    "psi_io_avg10": s.get("psi_io_avg10"),
                    "rss_kb": s.get("rss_kb"),
                    "swap_kb": s.get("swap_kb"),
                    "board_temp": s.get("board_temp"),
                    "thread_count": s.get("thread_count"),
                })
            except Exception:
                pass
        output["anr_summaries"] = summaries
        output["anr_count"] = len(anr_files)
    else:
        output["warning"] = "No ANR data found by content scan. Directory extracted, use manual search."
        output["anr_count"] = 0

    print(json.dumps(output, indent=2, ensure_ascii=False, default=str))

    session_file = Path.cwd() / ".anr_session.json"
    session_data = {
        "extract_dir": str(extract_dir),
        "artifact": str(artifact),
        "anr_count": len(anr_files),
        "in_place": in_place,
        "created_ts": int(time.time()),
    }
    try:
        session_file.write_text(json.dumps(session_data, indent=2, ensure_ascii=False))
    except OSError:
        pass


def _resolve_dir(dir_arg: str) -> Path:
    """Resolve extract dir from arg or last session."""
    if dir_arg:
        return Path(dir_arg)
    session_file = Path.cwd() / ".anr_session.json"
    if session_file.exists():
        try:
            data = json.loads(session_file.read_text())
            d = Path(data.get("extract_dir", ""))
            if d.exists():
                return d
        except (json.JSONDecodeError, OSError):
            pass
    print(json.dumps({"error": "No dir provided and no .anr_session.json found. Run init first or pass dir explicitly."}))
    sys.exit(1)


def cmd_blind(args):
    """Blind sweep 11 dimensions (extended from original 7)."""
    extract_dir = _resolve_dir(args.dir)
    if not extract_dir.exists():
        print(json.dumps({"error": f"Directory not found: {args.dir}"}))
        sys.exit(1)

    anr_files = find_anr_files(extract_dir)
    target_files = [str(f) for f in anr_files]

    largest_txt = find_largest_bugreport(extract_dir)
    if largest_txt and largest_txt not in target_files:
        target_files.append(largest_txt)

    time_filter = None
    minute_prefix = None
    try:
        time_filter = build_time_pattern(args.time)
        if args.time and args.time.strip():
            minute_prefix = _minute_regex(args.time)
    except ValueError as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
    dumpstate_file = find_dumpstate_file(extract_dir)

    # Extended dimensions: 7 original + 4 new
    dimensions = [
        # === Original 7 dimensions ===
        ("am_anr", "am_anr", "同窗口其他 ANR", None, 50),
        ("system_server_gc", "system_server.*GC|system_server.*Pause|system_server.*concurrent", "system_server GC 暂停", None, 50),
        ("binder_starved", "IPCThreadState.*starved", "binder 线程池耗尽", None, 50),
        ("lmk_kill", "lmkd.*kill|[Ll]ow.{0,5}memory.{0,5}killer|Killing.*adj", "LMK 低内存杀进程", None, 50),
        ("dead_object", "DeadObjectException|binderDied", "binder 死亡通知", None, 50),
        ("background_procs", "SmartPower.*background|am_proc_start|am_proc_died|RecentTasks|mainTaskId.*baseIntent", "后台进程活动", "bugreport", 500),
        ("thermal", "SS-CPU|VIRTUAL-SENSOR", "温升限频", "dumpstate", 100),

        # === New dimension: Binder thread pool (MIUI specific) ===
        ("binder_thread_pool", r"binder thread pool|binder_alloc|BpBinder.*PerfMonitor binderTransact|LockPerfImpl.*Long locked method event|bindService exceeded max service|dvm_lock_sample.*system_server|Long monitor contention with owner binder",
         "Binder线程池耗尽 (MIUI关键字)", None, 100),

        # === New dimension: Binder lock contention ===
        ("binder_lock_contention", r"dvm_lock_sample.*Locked|LockPerfImpl.*duration=[0-9]{3,}|Long monitor contention|monitor contention with owner",
         "Binder锁竞争详情", None, 100),

        # === New dimension: MIUI-specific mechanisms ===
        ("miui_specific", r"MiuiEmbeddingWindow|app-switch-from-projection|MiuiProjection|isNotProjeciton|MiuiClone|AppCloner|DUALLAYER|GreezeManager|ActionExecute.*frozen|freezeApp|SubDisplay|VirtualDisplay|ChildDisplay",
         "MIUI特有机制 (投屏/双开/冻结/子窗口)", None, 50),

        # === New dimension: App blocking patterns ===
        ("app_blocking", r"FileInputStream\.read|SocketInputStream\.read|LinkedBlockingQueue|SQLiteDatabase|Gson\.fromJson|org\.json\.JSON|BitmapFactory\.decode|Thread\.sleep|synchronized|View\.measure|View\.draw|Handler\.sendMessage",
         "应用层阻塞模式匹配 (12类)", None, 100),
    ]

    results = {}
    any_hit = False

    for key, pattern, desc, scope, max_n in dimensions:
        if scope == "bugreport" and largest_txt:
            files_to_search = [largest_txt]
        elif scope == "bugreport" and not largest_txt:
            files_to_search = target_files
        elif scope == "dumpstate" and dumpstate_file:
            files_to_search = [dumpstate_file]
        elif scope == "dumpstate" and not dumpstate_file:
            results[key] = {"description": desc, "hits": [], "note": "已扫，无结果（dumpstate_board.txt 和 thermal.dump 均未找到）"}
            continue
        else:
            files_to_search = target_files

        log_dimensions = {"am_anr", "binder_starved", "lmk_kill", "dead_object", "background_procs", "binder_thread_pool", "binder_lock_contention", "miui_specific"}
        use_time_filter = time_filter and (key in log_dimensions)

        grep_pattern = pattern
        if use_time_filter and key == "background_procs":
            grep_pattern = f"{minute_prefix}:.*({pattern})" if minute_prefix else pattern
            hits, warns = run_grep(grep_pattern, *files_to_search, max_count=max_n, time_filter=time_filter)
        else:
            hits, warns = run_grep(pattern, *files_to_search, max_count=max_n, time_filter=time_filter if use_time_filter else None)
        if hits:
            any_hit = True
            results[key] = {"description": desc, "hits": hits}
        elif warns:
            results[key] = {"description": desc, "hits": [], "note": "搜索超时/出错或全部落在时间窗外 — 结果不可信，必须手动 grep 复核"}
        else:
            results[key] = {"description": desc, "hits": [], "note": "已扫，无结果"}
        if warns:
            results[key]["warnings"] = warns[:10]

    # PSI from ANR files
    psi_summary = {}
    for f in anr_files:
        text = f.read_text(encoding="utf-8", errors="replace")[:5000]
        psi = {}
        m = re.search(r"/proc/pressure/cpu.*?some avg10=([\d.]+)", text, re.DOTALL)
        if not m:
            m = re.search(r"cpu.*?some avg10=([\d.]+)", text)
        if m: psi["cpu"] = float(m.group(1))
        m = re.search(r"/proc/pressure/memory.*?some avg10=([\d.]+)", text, re.DOTALL)
        if not m:
            m = re.search(r"memory.*?some avg10=([\d.]+)", text, re.DOTALL)
        if m: psi["mem"] = float(m.group(1))
        m = re.search(r"/proc/pressure/io.*?some avg10=([\d.]+)", text, re.DOTALL)
        if not m:
            m = re.search(r"io.*?some avg10=([\d.]+)", text, re.DOTALL)
        if m: psi["io"] = float(m.group(1))
        if psi:
            psi_summary[f.name] = psi

    output = {
        "time_window": args.time,
        "time_filter": time_filter,
        "dimensions": results,
        "psi_from_anr_files": psi_summary,
        "any_hit": any_hit,
    }
    if time_filter is None:
        output["window_note"] = "无时间窗过滤（blind 需要 'HH:MM' 如 '19:40'，或 'HH:M'/'HH' 前缀）；日志维度结果为全文件命中，非仅 ANR 窗口"

    print(json.dumps(output, indent=2, ensure_ascii=False, default=str))


def cmd_why(args):
    """Root cause追问 — extended with thermal and binder_lock keywords."""
    extract_dir = _resolve_dir(args.dir)
    if not extract_dir.exists():
        print(json.dumps({"error": f"Directory not found: {args.dir}"}))
        sys.exit(1)

    keyword = args.keyword.lower()
    log_files = find_log_files(extract_dir)
    anr_files = find_anr_files(extract_dir)
    dumpstate_file = find_dumpstate_file(extract_dir)

    patterns = {
        "io": {
            "description": "IO 拥塞上游来源",
            "queries": {
                "ota_snapshot": r"update_engine|snapshot.*[Mm]erge|CleanupPreviousUpdate",
                "zram_swap": r"zram|swap.{0,10}wr|swap.{0,10}rd",
                "page_fault": r"page_fault|do_page_fault",
                "io_scheduler": r"iowait|blkio",
            },
        },
        "memory": {
            "description": "内存压力上游来源",
            "queries": {
                "lmk": r"lmkd.*kill|[Ll]ow.{0,5}memory",
                "gc_pause": r"GC.{0,20}[Pp]ause|concurrent.*GC|GcPause",
                "large_process": r"RssKb.*[0-9]{6,}|RssHwmKb.*[0-9]{6,}",
                "dex_oat": r"dex2oat|dexopt",
            },
        },
        "binder": {
            "description": "binder 超时上游来源",
            "queries": {
                "target_process": r"binder.*transact.*time=|BpBinder.*transact",
                "thread_pool": r"binder.*thread|IPCThreadState",
                "dead_object": r"DeadObjectException|binderDied",
                "provider_timeout": r"Timeout waiting for provider|ContentProvider",
            },
        },
        "cpu": {
            "description": "CPU 压力上游来源",
            "queries": {
                "cpu_hogs": r"[0-9]+%\s+[0-9]+/",
                "thermal": r"THERMAL|SS-CPU|MONITOR-GPU|MONITOR-BAT|mi_thermald",
                "gc": r"GC.{0,20}[Pp]ause|concurrent.*GC",
            },
        },
        # === New: thermal deep analysis ===
        "thermal": {
            "description": "温控限频深度分析",
            "queries": {
                "virtual_sensor": r"VIRTUAL-SENSOR\s+([0-9]+)",
                "cpu_freq": r"\[cpu([0-9]+)\s+([0-9]+)\]",
                "cpu_type": r"SS-CPU([0-9]+)",
                "backlight_battery_temp": r"backlight_therm|battery_temp",
                "mtk_power": r"MTKPOWER_HINT|setClusterFreq|mi_thermald",
            },
        },
        # === New: binder lock chain analysis ===
        "binder_lock": {
            "description": "Binder锁竞争链分析",
            "queries": {
                "thread_pool_status": r"binder.*thread pool.*total=[0-9]+",
                "dvm_lock_locked": r"dvm_lock_sample.*Locked",
                "dvm_lock_blocked": r"dvm_lock_sample.*Blocked",
                "lockperf_long": r"LockPerfImpl.*Long locked method event",
                "lockperf_duration": r"LockPerfImpl.*duration=[0-9]+",
                "bindservice_max": r"bindService exceeded max service",
                "binder_transact": r"PerfMonitor binderTransact|binder_transaction.*time=",
                "monitor_contention": r"Long monitor contention|monitor contention with owner binder",
            },
        },
    }

    if keyword not in patterns:
        print(json.dumps({
            "error": f"Unknown keyword: {keyword}",
            "available": list(patterns.keys()),
            "hint": "io | memory | binder | cpu | thermal | binder_lock",
        }))
        sys.exit(1)

    config = patterns[keyword]
    results = {"keyword": keyword, "description": config["description"], "queries": {}}
    all_warnings = []

    for qname, pattern in config["queries"].items():
        # thermal queries check dumpstate first, then ANR files
        if keyword == "thermal" and dumpstate_file:
            search_paths = [dumpstate_file] + [str(f) for f in anr_files]
        elif keyword == "binder_lock":
            search_paths = [str(f) for f in (log_files + anr_files)]
        else:
            search_paths = [str(f) for f in log_files]

        hits, warns = run_grep(pattern, *search_paths, max_count=20)
        all_warnings.extend(warns)
        results["queries"][qname] = {
            "pattern": pattern,
            "hits": hits if hits else [],
            "found": len(hits) > 0,
        }

    # For thermal keyword, reuse ThermalAnalyzer (baseline-relative throttling,
    # NOT the old hardcoded <2GHz absolute threshold that misjudges low-freq SoCs)
    if keyword == "thermal":
        thermal_stats = {"total_records": 0}
        if dumpstate_file:
            try:
                from thermal_analyzer import ThermalAnalyzer
                ta = ThermalAnalyzer(dumpstate_file)
                ta.parse()
                rep = ta.analyze()
                thermal_stats = {
                    "file": dumpstate_file,
                    "total_records": rep.total_records,
                    "max_temp": rep.max_temp,
                    "min_temp": rep.min_temp,
                    "high_temp_ge38": rep.high_temp_records,
                    "severe_temp_ge40": rep.severe_temp_records,
                    "throttled_count": rep.throttling_records,
                    "high_temp_and_throttled": rep.high_temp_and_throttle,
                    "baseline_missing": rep.baseline_missing,
                    "verdict": ta.get_verdict(rep),
                }
            except Exception as e:
                thermal_stats = {"error": f"thermal analysis failed: {e} — run thermal_analyzer.py manually"}
        results["thermal_statistics"] = thermal_stats

    # For binder_lock keyword, parse binder thread pool status
    if keyword == "binder_lock":
        binder_pool_info = []
        for f in anr_files + log_files:
            if not f.exists():
                continue
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
                for m in re.finditer(r"binder.*thread pool.*total=(\d+).*idle=(\d+).*pending=(\d+).*active=(\d+)", text):
                    binder_pool_info.append({
                        "total": int(m.group(1)),
                        "idle": int(m.group(2)),
                        "pending": int(m.group(3)),
                        "active": int(m.group(4)),
                        "exhausted": int(m.group(2)) == 0 and int(m.group(3)) > 0,
                    })
            except Exception:
                pass
        results["binder_pool_status"] = binder_pool_info[:10]

    if all_warnings:
        results["warnings"] = all_warnings[:20]

    print(json.dumps(results, indent=2, ensure_ascii=False, default=str))


def cmd_bgreport(args):
    """14-item bugreport comprehensive check (from anr-analyzer-kui)."""
    extract_dir = _resolve_dir(args.dir)
    if not extract_dir.exists():
        print(json.dumps({"error": f"Directory not found: {args.dir}"}))
        sys.exit(1)

    largest_txt = find_largest_bugreport(extract_dir)
    if not largest_txt:
        print(json.dumps({"error": "No bugreport text file found."}))
        sys.exit(1)

    sys_version_file = find_sys_version_file(extract_dir)

    def search_file(path, pattern, max_lines=5):
        """Search a single file for pattern. Timeouts/errors are recorded, not silent."""
        try:
            out = subprocess.run(
                ["grep", "-aE", "-n", "-m", str(max_lines), pattern, str(path)],
                capture_output=True, text=True, timeout=60
            )
            if out.returncode not in (0, 1):
                search_timeouts.append(pattern)
            if out.stdout.strip():
                return out.stdout.strip().split("\n")
        except subprocess.TimeoutExpired:
            search_timeouts.append(pattern)
        except Exception:
            search_timeouts.append(pattern)
        return []

    def search_file_section(path, start_pattern, max_lines=30):
        """Extract a section starting from pattern."""
        try:
            out = subprocess.run(
                ["grep", "-aE", "-n", "-m", "1", start_pattern, str(path)],
                capture_output=True, text=True, timeout=60
            )
            if not out.stdout.strip():
                return []
            line_num = int(out.stdout.strip().split(":")[0])
            # Use sed to extract from that line
            out2 = subprocess.run(
                ["sed", "-n", f"{line_num},{line_num + max_lines}p", str(path)],
                capture_output=True, text=True, timeout=30
            )
            return out2.stdout.strip().split("\n") if out2.stdout.strip() else []
        except Exception:
            pass
        return []

    check_items = []
    search_timeouts = []

    # Helper to add check item
    def add_item(category, name, keyword, found, value, status, detail=""):
        check_items.append({
            "category": category,
            "name": name,
            "keyword": keyword,
            "found": found,
            "value": value,
            "status": status,
            "detail": detail,
        })

    # 1. Android version
    hits = search_file(largest_txt, r"\[ro\.build\.version\.release\]:\s*\[(.+?)\]", 1)
    if hits:
        m = re.search(r"\[ro\.build\.version\.release\]:\s*\[(.+?)\]", hits[0])
        add_item("设备基本信息", "Android版本信息", "ro.build.version.release", True,
                 m.group(1) if m else hits[0], "正常")
    else:
        add_item("设备基本信息", "Android版本信息", "ro.build.version.release", False, "", "未找到")

    # 2. Dumpstate time
    if sys_version_file:
        sv_text = Path(sys_version_file).read_text(encoding="utf-8", errors="replace")[:2000]
        m = re.search(r"dumpstate:\s*(.+)", sv_text)
        if m:
            add_item("设备基本信息", "日志抓取时间", "dumpstate", True, m.group(1).strip(), "正常")
        else:
            add_item("设备基本信息", "日志抓取时间", "dumpstate", False, "", "未找到")
    else:
        hits = search_file(largest_txt, r"dumpstate:\s*([0-9]{4}-[0-9]{2}-[0-9]{2})", 1)
        if hits:
            m = re.search(r"dumpstate:\s*(\d{4}-\d{2}-\d{2}.*)", hits[0])
            add_item("设备基本信息", "日志抓取时间", "dumpstate", True,
                     m.group(1).strip() if m else hits[0], "正常")
        else:
            add_item("设备基本信息", "日志抓取时间", "dumpstate", False, "", "未找到")

    # 3. Uptime
    hits = search_file(largest_txt, r"Uptime:\s*up\s*(.+)", 3)
    if not hits:
        hits = search_file(largest_txt, r"System uptime:", 3)
    if hits:
        add_item("设备基本信息", "开机运行时间", "uptime", True, hits[0][:200], "正常")
    else:
        add_item("设备基本信息", "开机运行时间", "uptime", False, "", "未找到")

    # 4. OTA
    hits = search_file(largest_txt, r"Upgrading from", 3)
    if hits:
        add_item("设备基本信息", "OTA升级时间", "Upgrading from", True, hits[0][:200], "正常")
    else:
        add_item("设备基本信息", "OTA升级时间", "Upgrading from", True, "无OTA升级记录", "正常")

    # 5. MemTotal
    hits = search_file(largest_txt, r"MemTotal:\s*([0-9]+)\s*kB", 1)
    if hits:
        m = re.search(r"MemTotal:\s*([0-9]+)\s*kB", hits[0])
        kb = int(m.group(1))
        gb = kb / (1024 * 1024)
        detail = "低端机" if gb < 3 else ("中端机" if gb < 6 else "高端机")
        add_item("设备状态信息", "内存配置", "MemTotal", True,
                 f"{kb} kB ({gb:.1f} GB)", "正常", f"{detail}内存配置")
    else:
        add_item("设备状态信息", "内存配置", "MemTotal", False, "", "未找到")

    # 6. MemAvailable
    hits = search_file(largest_txt, r"MemAvailable:\s*([0-9]+)\s*kB", 1)
    if hits:
        m = re.search(r"MemAvailable:\s*([0-9]+)\s*kB", hits[0])
        kb = int(m.group(1))
        mb = kb / 1024
        # Get MemTotal for ratio
        memtotal_hit = search_file(largest_txt, r"MemTotal:\s*([0-9]+)\s*kB", 1)
        ratio = None
        if memtotal_hit:
            mt = re.search(r"MemTotal:\s*([0-9]+)\s*kB", memtotal_hit[0])
            if mt:
                ratio = kb / int(mt.group(1)) * 100
        detail = f"可用率: {ratio:.1f}%" if ratio else ""
        status = "正常"
        if ratio:
            if ratio < 10:
                status = "异常"
            elif ratio < 20:
                status = "警告"
        add_item("设备状态Check", "可用内存", "MemAvailable", True, f"{kb} kB ({mb:.0f} MB)", status, detail)
    else:
        add_item("设备状态Check", "可用内存", "MemAvailable", False, "", "未找到")

    # 7. Battery
    hits = search_file(largest_txt, r"level[ :=]+([0-9]+)", 5)
    found_battery = False
    for h in hits:
        m = re.search(r"level[ :=]+([0-9]+)", h, re.IGNORECASE)
        if m:
            level = int(m.group(1))
            if level <= 100:
                status = "异常" if level <= 10 else ("警告" if level <= 20 else "正常")
                add_item("设备状态Check", "电量", "PowerChecker_Service", True, f"{level}%", status)
                found_battery = True
                break
    if not found_battery:
        add_item("设备状态Check", "电量", "PowerChecker_Service", False, "未找到电量信息", "未找到")

    # 8. Temperature — raw values may be milli-°C (41976), tenths-°C (347) or °C (41)
    # Case-flexible: bugreport uses both 'Temperature: 38.9' and 'Board Sensor Temperature: 41976'
    hits = search_file(largest_txt, r"[Tt]emperature[ :=]+([0-9]+\.?[0-9]*)", 3)
    if hits:
        m = re.search(r"temperature[ :=]+([0-9]+\.?[0-9]*)", hits[0], re.IGNORECASE)
        if m:
            raw = float(m.group(1))
            if raw >= 10000:
                temp, unit_note = raw / 1000.0, "milli-°C"
            elif raw > 100:
                temp, unit_note = raw / 10.0, "tenths-°C"
            else:
                temp, unit_note = raw, "°C"
            # Thresholds aligned with thermal_analyzer / SKILL.md 专项模块 A:
            # >=40 严重(异常), 38-40 高温(警告), <38 正常
            status = "异常" if temp >= 40 else ("警告" if temp >= 38 else "正常")
            add_item("设备状态Check", "温度", "SENSOR", True, f"{temp:.1f}°C", status, f"raw={m.group(1)} ({unit_note})")
        else:
            add_item("设备状态Check", "温度", "SENSOR", True, hits[0][:100], "正常")
    else:
        add_item("设备状态Check", "温度", "SENSOR", False, "未找到温度信息", "未找到")

    # 9. Filesystem
    section = search_file_section(largest_txt, r"FILESYSTEMS & FREE SPACE", 60)
    found_fs = False
    for line in section:
        m = re.search(r"^\s*\S+\s+\d+\s+\d+\s+\d+\s+(\d+)%\s+/data\s*$", line)
        if m:
            usage = int(m.group(1))
            free_pct = 100 - usage
            parts = line.split()
            avail_gb = int(parts[3]) / (1024 * 1024) if len(parts) >= 5 else 0
            total_gb = int(parts[1]) / (1024 * 1024) if len(parts) >= 5 else 0
            status = "异常" if free_pct < 5 else ("警告" if free_pct < 10 else "正常")
            add_item("设备状态Check", "data剩余空间", "data", True,
                     f"{free_pct}% ({avail_gb:.1f} GB / {total_gb:.1f} GB)", status)
            found_fs = True
            break
    if not found_fs:
        add_item("设备状态Check", "data剩余空间", "data", False, "", "未找到")

    # 10. CPU usage
    hits = search_file(largest_txt, r"CPU usage", 3)
    if hits:
        # Extract TOTAL line
        section = search_file_section(largest_txt, r"CPU usage", 30)
        total_line = ""
        for line in section:
            if "TOTAL" in line:
                total_line = line.strip()[:200]
                break
        add_item("设备状态Check", "CPU使用信息", "CPU USAGE", True,
                 f"找到CPU使用信息", "正常", total_line)
    else:
        add_item("设备状态Check", "CPU使用信息", "CPU USAGE", False, "", "未找到")

    # 11. PSI
    cpu_psi = ""
    mem_psi = ""
    io_psi = ""
    for section_name, start_pat, var in [("cpu", r"PSI cpu", "cpu_psi"), ("memory", r"PSI memory", "mem_psi"), ("io", r"PSI io", "io_psi")]:
        sec = search_file_section(largest_txt, start_pat, 10)
        if var == "cpu_psi":
            cpu_psi = "\n".join(sec)
        elif var == "mem_psi":
            mem_psi = "\n".join(sec)
        else:
            io_psi = "\n".join(sec)

    if not cpu_psi and not mem_psi and not io_psi:
        # Fallback: single-line form '/proc/pressure/cpu: some avg10=75.00 avg60=...'
        hits = search_file(largest_txt, r"pressure/(cpu|memory|io).*some avg10=", 6)
        for h in hits:
            if "pressure/cpu" in h and not cpu_psi:
                cpu_psi = h
            elif "pressure/memory" in h and not mem_psi:
                mem_psi = h
            elif "pressure/io" in h and not io_psi:
                io_psi = h

    if cpu_psi:
        # Threshold per SKILL.md P7: 高负载 = some avg10 ≥ 70%，低于不算高负载
        # (full avg10 不参与判定)
        pressure_status = "正常"
        combined = cpu_psi + mem_psi + io_psi
        highs = []
        for m in re.finditer(r"some avg10=([\d.]+)", combined):
            avg10 = float(m.group(1))
            if avg10 >= 70:
                pressure_status = "异常"
                highs.append(avg10)
        add_item("设备状态Check", "内存/IO压力信息", "psi cpu", True, "PSI信息已提取", pressure_status,
                 f"cpu:{len(cpu_psi)}行 mem:{len(mem_psi)}行 io:{len(io_psi)}行; 阈值 some avg10≥70 (P7)"
                 + (f"; 超标值: {highs}" if highs else ""))
    else:
        add_item("设备状态Check", "内存/IO压力信息", "psi cpu", False, "", "未找到")

    # 12. Process PSS
    hits = search_file(largest_txt, r"total pss by", 5)
    if hits:
        add_item("设备状态Check", "进程占用信息", "total pss by", True, f"找到PSS信息({len(hits)}条)", "正常")
    else:
        add_item("设备状态Check", "进程占用信息", "total pss by", False, "", "未找到")

    # 13. ANR logs
    hits = search_file(largest_txt, r"am_anr", 30)
    if not hits:
        hits = search_file(largest_txt, r"ANR in", 30)
    if hits:
        status = "异常" if len(hits) > 10 else ("警告" if len(hits) > 3 else "正常")
        anr_pkgs = {}
        for h in hits:
            m = re.search(r"ANR in\s+(\S+)", h)
            if m:
                pkg = m.group(1)
                anr_pkgs[pkg] = anr_pkgs.get(pkg, 0) + 1
        detail = ", ".join(f"{k}:{v}" for k, v in sorted(anr_pkgs.items(), key=lambda x: -x[1])[:5])
        add_item("设备状态Check", "ANR日志", "am_anr", True, f"发现 {len(hits)} 条ANR记录", status, detail)
    else:
        add_item("设备状态Check", "ANR日志", "am_anr", True, "未发现ANR记录", "正常")

    # 14. Crash logs
    hits = search_file(largest_txt, r"am_crash", 20)
    if not hits:
        hits = search_file(largest_txt, r"Fatal signal", 10)
    if hits:
        status = "异常" if len(hits) > 5 else ("警告" if len(hits) > 2 else "正常")
        crash_pkgs = {}
        for h in hits:
            m = re.search(r"Process\s+(\S+)\s+\(pid\s+(\d+)\)", h)
            if m:
                pkg = m.group(1)
                crash_pkgs[pkg] = crash_pkgs.get(pkg, 0) + 1
        detail = ", ".join(f"{k}:{v}" for k, v in sorted(crash_pkgs.items(), key=lambda x: -x[1])[:5])
        add_item("设备状态Check", "CRASH日志", "am_crash", True, f"发现 {len(hits)} 条CRASH记录", status, detail)
    else:
        add_item("设备状态Check", "CRASH日志", "am_crash", True, "未发现CRASH记录", "正常")

    # Summary
    status_count = {"正常": 0, "警告": 0, "异常": 0, "未找到": 0}
    issues = []
    for item in check_items:
        status_count[item["status"]] = status_count.get(item["status"], 0) + 1
        if item["status"] in ("异常", "警告"):
            issues.append(f"[{item['status']}] [{item['category']}] {item['name']}: {item['value']}")

    output = {
        "file": largest_txt,
        "check_items": check_items,
        "status_summary": status_count,
        "issues": issues,
        "psi_raw": {"cpu": cpu_psi[:500] if cpu_psi else "", "memory": mem_psi[:500] if mem_psi else "", "io": io_psi[:500] if io_psi else ""},
    }
    if search_timeouts:
        output["warnings"] = [f"grep 超时/出错: {p} — 对应检查项的'未找到'可能是假阴性，需手动复核"
                              for p in sorted(set(search_timeouts))]

    print(json.dumps(output, indent=2, ensure_ascii=False, default=str))


def cmd_cleanup(args):
    """Delete temp extract directory and session file."""
    session_file = None
    d = Path.cwd()
    while d != d.parent:
        candidate = d / ".anr_session.json"
        if candidate.exists():
            session_file = candidate
            break
        d = d.parent
    extract_dir = None

    in_place = False

    if session_file:
        try:
            data = json.loads(session_file.read_text())
            extract_dir = data.get("extract_dir")
            in_place = bool(data.get("in_place"))
        except Exception:
            data = {}

    if args.dir:
        extract_dir = args.dir
        in_place = False
        data = {}

    if not extract_dir:
        print(json.dumps({"status": "nothing_to_cleanup", "reason": "No session or dir specified"}))
        return

    target = Path(extract_dir)
    if not target.exists():
        print(json.dumps({"status": "already_gone", "path": str(target)}))
        if session_file:
            session_file.unlink()
        return

    # In-place dirs are USER data — cleanup only removes the session file, never the dir.
    if in_place:
        if session_file:
            session_file.unlink()
        print(json.dumps({"status": "session_removed_only",
                          "reason": "init 使用了目录就地模式，该目录属于用户，不删除",
                          "path": str(target)}))
        return

    # Guard against stale sessions whose /tmp path was recycled by a fresh init:
    # only auto-delete if the dir was created AFTER (or near) the session timestamp.
    if str(target).startswith("/tmp/anr_scan_") and data.get("created_ts"):
        try:
            if target.stat().st_mtime < data["created_ts"] - 2:
                print(json.dumps({"status": "refused", "path": str(target),
                                  "reason": "session 记录早于该目录创建时间（疑似路径已被复用），请手动确认后用 --force"}))
                sys.exit(1)
        except OSError:
            pass

    # Defense in depth: only auto-delete init-created temp extractions.
    # Anything else (user dirs, legacy sessions missing in_place) needs --force.
    if not str(target).startswith("/tmp/anr_scan_") and not args.force:
        print(json.dumps({
            "status": "refused",
            "path": str(target),
            "reason": "只自动删除 init 创建的 /tmp/anr_scan_* 临时解压目录；其余目录请确认后使用 --force",
        }))
        sys.exit(1)

    import shutil
    shutil.rmtree(target)
    if session_file:
        session_file.unlink()

    print(json.dumps({"status": "cleaned", "path": str(target)}))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="ANR Scan Tool (Enhanced — anr-integrated-analysis)")
    sub = parser.add_subparsers(dest="command", required=True)

    # init
    p = sub.add_parser("init", help="Extract & summarize ANR files")
    p.add_argument("path", help="Path to bugreport .zip or extracted directory")
    p.add_argument("-o", "--output", help="Output directory (default: temp)")
    p.add_argument("--all-nested", action="store_true", dest="all_nested",
                   help="Extract all nested zips (default: only bugreport-*.zip)")

    # blind (extended to 11 dimensions)
    p = sub.add_parser("blind", help="Blind sweep 11 dimensions")
    p.add_argument("time", help="Time window pattern (e.g. '19:4' for 19:4x)")
    p.add_argument("dir", nargs="?", default="", help="Extracted bugreport directory (auto from session if omitted)")

    # why (extended keywords)
    p = sub.add_parser("why", help="Root cause 追问")
    p.add_argument("keyword", help="Intermediate cause: io | memory | binder | cpu | thermal | binder_lock")
    p.add_argument("dir", nargs="?", default="", help="Extracted bugreport directory (auto from session if omitted)")

    # bgreport (NEW)
    p = sub.add_parser("bgreport", help="Bugreport 14-item comprehensive check")
    p.add_argument("dir", nargs="?", default="", help="Extracted bugreport directory (auto from session if omitted)")

    # cleanup
    p = sub.add_parser("cleanup", help="Delete temp extract directory and session file")
    p.add_argument("dir", nargs="?", default="", help="Directory to delete (auto from session if omitted)")
    p.add_argument("--force", action="store_true", help="Allow deleting non-/tmp directories")

    args = parser.parse_args()

    if args.command == "init":
        cmd_init(args)
    elif args.command == "blind":
        cmd_blind(args)
    elif args.command == "why":
        cmd_why(args)
    elif args.command == "bgreport":
        cmd_bgreport(args)
    elif args.command == "cleanup":
        cmd_cleanup(args)


if __name__ == "__main__":
    main()
