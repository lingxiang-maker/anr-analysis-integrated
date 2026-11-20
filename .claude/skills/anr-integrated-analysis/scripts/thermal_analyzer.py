#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Temperature & CPU Throttling Analyzer for ANR root cause analysis.

Analyzes dumpstate_board.txt / thermal.dump to detect:
- High temperature events (VIRTUAL-SENSOR, values are milli-°C → /1000)
- CPU frequency throttling, measured RELATIVE to a per-core baseline
  (max freq seen while temp < 38°C). A drop ≥ 30% vs baseline = throttled.
  The old hardcoded "< 2GHz" absolute test misjudges low-frequency SoCs.
- Correlation between temperature and throttling

Temperature grades (shared with SKILL.md 专项模块 A / scan.py bgreport):
  < 35°C 正常 | 35-38°C 偏高 | ≥ 38°C 高温 | ≥ 40°C 严重

Usage:
  python thermal_analyzer.py <dumpstate_board.txt|thermal.dump> [--time-window "HH:MM"]
  python thermal_analyzer.py <dumpstate_board.txt> --json
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Threshold constants (single source of truth; keep SKILL.md / scan.py in sync)
# ---------------------------------------------------------------------------

TEMP_SLIGHT = 35.0        # ≥ 35°C: 偏高
TEMP_HIGH = 38.0          # ≥ 38°C: 高温 (throttling likely)
TEMP_SEVERE = 40.0        # ≥ 40°C: 严重 (root-cause grade)
THROTTLE_DROP_PCT = 0.30  # freq < baseline*(1-0.30) → throttled
FREQ_NORMAL_FALLBACK = 2_000_000  # used only when no cool (<38°C) record exists


def minute_regex(window: str) -> str:
    """Normalize a 'HH' / 'HH:MM' / 'HH:MM:SS' window into a line regex.

    '20:5'  -> '20:5[0-9]:[0-9]{2}'  (minute prefix)
    '20:51' -> '20:51:[0-9]{2}'
    '5:1'   -> '05:1[0-9]:[0-9]{2}'  (zero-padded)
    Raises ValueError on garbage so callers fail loudly instead of
    silently matching nothing.
    """
    if not window:
        raise ValueError("empty time window")
    m = re.match(r"^(\d{1,2}):(\d{1,2})(?::(\d{1,2}))?$", window.strip())
    if not m:
        raise ValueError(f"bad time window {window!r}; expected 'HH:MM' or 'HH:MM:SS'")
    h, mi, s = m.groups()
    hour = f"{int(h):02d}"
    if s is not None:
        return f"{hour}:{int(mi):02d}:{int(s):02d}"
    if len(mi) == 1:
        return f"{hour}:{mi}[0-9]:[0-9]{{2}}"
    return f"{hour}:{mi}:[0-9]{{2}}"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ThermalRecord:
    timestamp: str = ""
    temp: float = 0.0
    cpu_type: str = ""          # "小核" / "大核" / "unknown" (coarse, by core idx)
    cpu_index: int = 0
    freqs: dict = field(default_factory=dict)  # {"cpu0": 1708800, ...}
    line_raw: str = ""


@dataclass
class ThermalReport:
    file_path: str = ""
    total_records: int = 0
    high_temp_records: int = 0        # temp ≥ 38°C
    severe_temp_records: int = 0      # temp ≥ 40°C
    throttling_records: int = 0       # ≥1 core dropped ≥30% vs baseline
    high_temp_and_throttle: int = 0   # both (temp ≥ 38 且 throttled)
    max_temp: float = 0.0
    min_temp: float = 0.0
    avg_temp: float = 0.0
    baseline_missing: bool = False    # no cool(<38°C) record → baseline is a fallback
    baseline: dict = field(default_factory=dict)   # {"cpu0": 1804800, ...}
    records: list = field(default_factory=list)
    temp_timeline: list = field(default_factory=list)  # [(timestamp, temp, max_freq, min_freq)]


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class ThermalAnalyzer:
    """Analyze dumpstate_board.txt for temperature and CPU throttling."""

    # Class aliases kept for backwards-compat with any external import
    TEMP_NORMAL = TEMP_SLIGHT
    TEMP_ELEVATED = TEMP_HIGH

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.records: list[ThermalRecord] = []
        self.normal_max_freqs: dict[str, int] = {}   # per-core baseline {"cpu0": 1804800}
        self.baseline_missing = False

    def parse(self, time_window: str = None):
        """Parse dumpstate_board.txt or thermal.dump for temperature/freq data."""
        path = Path(self.file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {self.file_path}")

        ts_filter = minute_regex(time_window) if time_window else None

        # Patterns
        temp_pattern = re.compile(r"VIRTUAL-SENSOR\s+(\d+)")
        cpu_freq_pattern = re.compile(r"\[cpu(\d+)\s+(\d+)\]")  # 不强制 { 前缀：一行多核全部捕获
        cpu_type_pattern = re.compile(r"SS-CPU(\d+)")
        timestamp_pattern = re.compile(r"(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})")

        with open(self.file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                # Time filter (normalized: 'HH:MM' / 'HH:M' / 'HH:MM:SS' all work)
                if ts_filter and not re.search(ts_filter, line):
                    continue

                temp_match = temp_pattern.search(line)
                if not temp_match:
                    continue

                temp = int(temp_match.group(1)) / 1000.0

                cpu_type_match = cpu_type_pattern.search(line)
                if cpu_type_match:
                    cpu_idx = int(cpu_type_match.group(1))
                    cpu_type = "小核" if cpu_idx <= 3 else "大核"
                else:
                    cpu_type = "unknown"
                    cpu_idx = -1

                freqs = {f"cpu{c}": int(fv) for c, fv in cpu_freq_pattern.findall(line)}

                ts_match = timestamp_pattern.search(line)
                timestamp = ts_match.group(1) if ts_match else ""

                self.records.append(ThermalRecord(
                    timestamp=timestamp,
                    temp=temp,
                    cpu_type=cpu_type,
                    cpu_index=cpu_idx,
                    freqs=freqs,
                    line_raw=line.strip(),
                ))

        self._calc_normal_max_freqs()

    def _calc_normal_max_freqs(self):
        """Per-core baseline = max frequency seen while temp < 38°C (cool state).

        Keyed by core index (cpu0..cpuN), NOT by cluster label — mixing cores
        of a cluster hides per-core throttling. If the file has no cool record
        (device was hot the whole capture), fall back to the global per-core
        max and flag baseline_missing: throttling percentages are then a
        lower bound (throttling while supposedly 'cool' is invisible).
        """
        cool_freqs: dict[str, list[int]] = defaultdict(list)
        all_freqs: dict[str, list[int]] = defaultdict(list)
        for r in self.records:
            for cpu, fv in r.freqs.items():
                all_freqs[cpu].append(fv)
                if r.temp < TEMP_HIGH:
                    cool_freqs[cpu].append(fv)

        if not any(cool_freqs.values()):
            self.baseline_missing = True

        for cpu, fv in all_freqs.items():
            src = cool_freqs.get(cpu) or fv
            self.normal_max_freqs[cpu] = max(src) if src else FREQ_NORMAL_FALLBACK
        self.baseline_missing = self.baseline_missing or not self.normal_max_freqs

    def _record_throttled(self, r: ThermalRecord) -> bool:
        """True if any core in this record dropped ≥30% vs its baseline."""
        for cpu, fv in r.freqs.items():
            base = self.normal_max_freqs.get(cpu)
            if base and fv < base * (1 - THROTTLE_DROP_PCT):
                return True
        return False

    def analyze(self) -> ThermalReport:
        """Run full analysis."""
        if not self.records:
            return ThermalReport(
                file_path=self.file_path,
                baseline_missing=self.baseline_missing,
                baseline=dict(self.normal_max_freqs),
            )

        temps = [r.temp for r in self.records]
        high_temp = sum(1 for t in temps if t >= TEMP_HIGH)
        severe = sum(1 for t in temps if t >= TEMP_SEVERE)
        throttled_records = [r for r in self.records if self._record_throttled(r)]
        both = sum(1 for r in throttled_records if r.temp >= TEMP_HIGH)

        report = ThermalReport(
            file_path=self.file_path,
            total_records=len(self.records),
            high_temp_records=high_temp,
            severe_temp_records=severe,
            throttling_records=len(throttled_records),
            high_temp_and_throttle=both,
            max_temp=max(temps),
            min_temp=min(temps),
            avg_temp=sum(temps) / len(temps),
            baseline_missing=self.baseline_missing,
            baseline=dict(self.normal_max_freqs),
            records=self.records,
        )

        # Build temperature timeline
        prev_ts = None
        for r in self.records:
            if r.timestamp != prev_ts:
                max_freq = max(r.freqs.values()) if r.freqs else 0
                min_freq = min(r.freqs.values()) if r.freqs else 0
                report.temp_timeline.append((r.timestamp, r.temp, max_freq, min_freq))
                prev_ts = r.timestamp

        return report

    def get_cpu_throttle_summary(self) -> list[dict]:
        """Per-core (cpuN) throttling summary against its own baseline."""
        if not self.normal_max_freqs:
            return []

        def _core_order(cpu: str) -> int:
            m = re.search(r"\d+", cpu)
            return int(m.group()) if m else 999

        summaries = []
        for cpu, normal_max in sorted(self.normal_max_freqs.items(), key=lambda kv: _core_order(kv[0])):
            type_records = [r for r in self.records if cpu in r.freqs]
            if not type_records:
                continue

            throttled = []
            for r in type_records:
                fv = r.freqs[cpu]
                if normal_max > 0 and fv < normal_max * (1 - THROTTLE_DROP_PCT):
                    throttled.append({
                        "timestamp": r.timestamp,
                        "temp": r.temp,
                        "cpu": cpu,
                        "freq": fv,
                        "normal_max": normal_max,
                        "drop_pct": round((1 - fv / normal_max) * 100, 1),
                    })

            idx = _core_order(cpu)
            summaries.append({
                "cpu": cpu,
                "cluster": "小核" if idx <= 3 else "大核",   # coarse, by core index
                "normal_max_freq": normal_max,
                "normal_max_ghz": round(normal_max / 1_000_000, 2),
                "record_count": len(type_records),
                "throttled_count": len(throttled),
                "throttle_pct": round(len(throttled) / len(type_records) * 100, 1) if type_records else 0,
                "current_freq": type_records[-1].freqs.get(cpu, 0),
                "throttle_samples": throttled[:10],
            })

        return summaries

    def get_verdict(self, report: ThermalReport) -> dict:
        """Final verdict: is thermal throttling a dominant factor?"""
        high_temp_pct = report.high_temp_records / max(report.total_records, 1) * 100
        throttle_pct = report.throttling_records / max(report.total_records, 1) * 100

        # Classification aligned with SKILL.md 根因分类 / 专项模块 A
        if report.max_temp >= TEMP_SEVERE and throttle_pct >= 30:
            category = "高温限频主导"
            confidence = "low" if report.baseline_missing else "high"
        elif report.max_temp >= TEMP_HIGH and throttle_pct >= 30:
            category = "高温限频主导"
            confidence = "medium"
        elif report.max_temp >= TEMP_SEVERE and throttle_pct < 30:
            category = "高温（未显著限频）"
            confidence = "medium"
        elif report.max_temp < TEMP_HIGH and throttle_pct >= 30:
            category = "限频（非温度原因）"
            confidence = "low"
        else:
            category = "温度正常"
            confidence = "normal"

        if report.max_temp >= TEMP_SEVERE:
            severity = "严重"
        elif report.max_temp >= TEMP_HIGH:
            severity = "高温"
        elif report.max_temp >= TEMP_SLIGHT:
            severity = "偏高"
        else:
            severity = "正常"

        detail = (
            f"温度最高 {report.max_temp:.1f}°C (严重级别: {severity}), "
            f"高温≥38°C占比 {high_temp_pct:.1f}%, 降频占比 {throttle_pct:.1f}%, "
            f"高温+降频重叠 {report.high_temp_and_throttle}/{report.total_records}"
        )
        if report.baseline_missing:
            detail += "；⚠️ 无 <38°C 冷态记录，基线取自全程最大值 — 降频程度为下限，置信度已降级"

        return {
            "category": category,
            "confidence": confidence,
            "severity": severity,
            "max_temp": report.max_temp,
            "high_temp_pct": round(high_temp_pct, 1),
            "throttle_pct": round(throttle_pct, 1),
            "baseline_missing": report.baseline_missing,
            "verdict_detail": detail,
        }

    def format_report(self, report: ThermalReport) -> str:
        """Format analysis as human-readable text."""
        verdict = self.get_verdict(report)
        cpu_summaries = self.get_cpu_throttle_summary()

        lines = []
        lines.append("=" * 60)
        lines.append("  温度与CPU限频分析报告")
        lines.append("=" * 60)
        lines.append(f"文件: {report.file_path}")
        lines.append(f"总记录: {report.total_records}")
        lines.append("")

        lines.append("--- 温度统计 ---")
        lines.append(f"最高温度: {report.max_temp:.1f}°C")
        lines.append(f"最低温度: {report.min_temp:.1f}°C")
        lines.append(f"平均温度: {report.avg_temp:.1f}°C")
        lines.append(f"高温记录 (≥38°C): {report.high_temp_records} ({report.high_temp_records * 100 // max(report.total_records, 1)}%)")
        lines.append(f"严重高温 (≥40°C): {report.severe_temp_records} ({report.severe_temp_records * 100 // max(report.total_records, 1)}%)")
        lines.append("")

        lines.append("--- 限频统计 (相对基线降幅≥30%) ---")
        if report.baseline_missing:
            lines.append("⚠️ 基线缺失：文件中无 <38°C 冷态记录，基线取全程最大值，降幅为下限")
        else:
            base_str = ", ".join(f"{c}={f / 1_000_000:.2f}GHz" for c, f in sorted(report.baseline.items()))
            lines.append(f"基线(冷态最高): {base_str or '无'}")
        lines.append(f"降频记录: {report.throttling_records} ({report.throttling_records * 100 // max(report.total_records, 1)}%)")
        lines.append(f"高温 + 降频: {report.high_temp_and_throttle} ({report.high_temp_and_throttle * 100 // max(report.total_records, 1)}%)")
        lines.append("")

        for cs in cpu_summaries:
            lines.append(f"--- {cs['cpu']} ({cs['cluster']}) ---")
            lines.append(f"基线最高频率: {cs['normal_max_ghz']} GHz")
            lines.append(f"记录数: {cs['record_count']}，降频次数: {cs['throttled_count']} ({cs['throttle_pct']}%)")
            if cs["throttle_samples"]:
                lines.append("降频样本 (前5条):")
                for s in cs["throttle_samples"][:5]:
                    lines.append(f"  [{s['timestamp']}] {s['cpu']}: {s['freq'] / 1_000_000:.2f}GHz "
                                 f"(降幅 {s['drop_pct']}% vs 基线 {s['normal_max'] / 1_000_000:.2f}GHz) @ {s['temp']:.1f}°C")
            lines.append("")

        lines.append("--- 判定 ---")
        lines.append(f"分类: {verdict['category']}")
        lines.append(f"置信度: {verdict['confidence']}")
        lines.append(f"详情: {verdict['verdict_detail']}")

        if verdict["category"] == "高温限频主导":
            lines.append("")
            lines.append("⚠️  检测到高温导致的 CPU 降频，这可能是 ANR 的重要原因！")
            lines.append("建议:")
            lines.append("  1. 检查设备散热是否正常")
            lines.append("  2. 排查是否有长时间高负载场景")
            lines.append("  3. 考虑降低应用在高负载下的计算密集度")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON output helpers
# ---------------------------------------------------------------------------

def analyze_to_json(file_path: str, time_window: str = None) -> dict:
    """Analyze and return JSON-serializable dict."""
    analyzer = ThermalAnalyzer(file_path)
    analyzer.parse(time_window=time_window)
    report = analyzer.analyze()
    verdict = analyzer.get_verdict(report)
    cpu_summaries = analyzer.get_cpu_throttle_summary()

    return {
        "file": file_path,
        "time_window": time_window,
        "temperature": {
            "max": report.max_temp,
            "min": report.min_temp,
            "avg": round(report.avg_temp, 2),
            "total_records": report.total_records,
            "high_temp_count_ge38": report.high_temp_records,
            "high_temp_pct": round(report.high_temp_records / max(report.total_records, 1) * 100, 1),
            "severe_count_ge40": report.severe_temp_records,
            "severe_pct": round(report.severe_temp_records / max(report.total_records, 1) * 100, 1),
        },
        "throttling": {
            "criterion": f"freq < per-core baseline × (1 - {THROTTLE_DROP_PCT:.0%})",
            "baseline_ghz": {c: round(f / 1_000_000, 2) for c, f in sorted(report.baseline.items())},
            "baseline_missing": report.baseline_missing,
            "throttling_count": report.throttling_records,
            "throttling_pct": round(report.throttling_records / max(report.total_records, 1) * 100, 1),
            "high_temp_and_throttle": report.high_temp_and_throttle,
            "overlap_pct": round(report.high_temp_and_throttle / max(report.total_records, 1) * 100, 1),
        },
        "cpu_summary": cpu_summaries,
        "verdict": verdict,
        "timeline": [
            {"time": ts, "temp": t, "max_freq": mf, "min_freq": lf}
            for ts, t, mf, lf in report.temp_timeline[:200]
        ],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Temperature & CPU Throttling Analyzer")
    parser.add_argument("file", help="Path to dumpstate_board.txt or thermal.dump")
    parser.add_argument("--time-window", "-t",
                        help="Time window filter, 'HH:MM' / 'HH:M' / 'HH:MM:SS' (e.g. '20:51')")
    parser.add_argument("--json", action="store_true", help="Output JSON format")
    args = parser.parse_args()

    if args.time_window:
        try:
            minute_regex(args.time_window)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    if args.json:
        result = analyze_to_json(args.file, args.time_window)
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    else:
        analyzer = ThermalAnalyzer(args.file)
        analyzer.parse(time_window=args.time_window)
        report = analyzer.analyze()
        print(analyzer.format_report(report))


if __name__ == "__main__":
    main()
