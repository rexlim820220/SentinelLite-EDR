#!/usr/bin/env python3
"""
parse_events.py — SentinelLite-EDR 事件報告生成器

用途：
    讀取 ControllerEXE 輸出的原始 log，
    過濾並結構化成 JSON 報告，聚焦在 CRITICAL 與 WARNING 事件。

執行方式：
    # Step 1：把 ControllerEXE 的輸出重導向到檔案
    ControllerEXE.exe > events.log 2>&1

    # Step 2：執行此腳本
    python parse_events.py events.log

    # 輸出：summary.json（在同目錄下）

輸出格式範例：
    {
        "generated_at": "2026-06-07T15:30:00",
        "total_events": 3,
        "critical_count": 2,
        "warning_count": 0,
        "info_count": 1,
        "events": [
            {
                "severity": "CRITICAL",
                "pid": "7740",
                "api": "VirtualAllocEx",
                "process": "ControllerEXE.exe",
                "details": "RemotePID=7740, Size=4096, Protect=0x40",
                "raw": "[CRITICAL] PID=7740 ..."
            }
        ]
    }
"""

import sys
import re
import json
from datetime import datetime


# ── 正則表達式：對應 ControllerEXE 的輸出格式 ──────────────
# 格式：[SEVERITY] PID=XXXXXX  API=XXXXXXXXX  Process=XXXXXXXXX  | details
EVENT_PATTERN = re.compile(
    r'\[(?P<severity>CRITICAL|WARNING |INFO    )\]\s+'
    r'PID=(?P<pid>\d+)\s+'
    r'API=(?P<api>\S+)\s+'
    r'Process=(?P<process>\S+)\s+\|\s+'
    r'(?P<details>.+)'
)


def parse_log(filepath: str) -> list[dict]:
    """讀取 log 檔案，回傳所有成功解析的事件列表。"""
    events = []

    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            for line_num, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue

                match = EVENT_PATTERN.search(line)
                if not match:
                    continue  # 跳過非事件行（banner、debug 輸出等）

                event = {
                    "line":     line_num,
                    "severity": match.group('severity').strip(),
                    "pid":      match.group('pid'),
                    "api":      match.group('api').strip(),
                    "process":  match.group('process').strip(),
                    "details":  match.group('details').strip(),
                    "raw":      line
                }
                events.append(event)

    except FileNotFoundError:
        print(f"[ERROR] 找不到檔案：{filepath}")
        sys.exit(1)

    return events


def generate_report(events: list[dict]) -> dict:
    """把事件列表轉成結構化報告。"""

    critical = [e for e in events if e['severity'] == 'CRITICAL']
    warning  = [e for e in events if e['severity'] == 'WARNING']
    info     = [e for e in events if e['severity'] == 'INFO']

    # ── TTP 分析：偵測 Process Injection 特徵組合 ──────────
    # T1055 特徵：同一個 PID 在短時間內出現 VirtualAllocEx + CreateRemoteThread
    ttp_detections = []
    pids_with_valloc  = {e['pid'] for e in critical if e['api'] == 'VirtualAllocEx'}
    pids_with_crt     = {e['pid'] for e in critical if e['api'] == 'CreateRemoteThread'}
    injection_pids    = pids_with_valloc & pids_with_crt

    for pid in injection_pids:
        ttp_detections.append({
            "ttp_id":       "T1055",
            "ttp_name":     "Process Injection",
            "evidence_pid": pid,
            "description":  (
                f"PID {pid} triggered both VirtualAllocEx(PAGE_EXECUTE_READWRITE) "
                f"and CreateRemoteThread — classic Process Injection pattern."
            )
        })

    report = {
        "generated_at":   datetime.now().isoformat(timespec='seconds'),
        "source_log":     sys.argv[1] if len(sys.argv) > 1 else "unknown",
        "total_events":   len(events),
        "critical_count": len(critical),
        "warning_count":  len(warning),
        "info_count":     len(info),
        "ttp_detections": ttp_detections,
        "events":         events
    }

    return report


def print_summary(report: dict) -> None:
    """在 console 印出人類可讀的摘要。"""
    print("=" * 52)
    print(" SentinelLite-EDR — Event Analysis Report")
    print("=" * 52)
    print(f"  Generated : {report['generated_at']}")
    print(f"  Source    : {report['source_log']}")
    print(f"  Total     : {report['total_events']} events")
    print(f"  CRITICAL  : {report['critical_count']}")
    print(f"  WARNING   : {report['warning_count']}")
    print(f"  INFO      : {report['info_count']}")
    print()

    if report['ttp_detections']:
        print("── TTP Detections ──────────────────────────────────")
        for ttp in report['ttp_detections']:
            print(f"  [{ttp['ttp_id']}] {ttp['ttp_name']}")
            print(f"  {ttp['description']}")
        print()

    if report['critical_count'] > 0:
        print("── CRITICAL Events ─────────────────────────────────")
        for ev in report['events']:
            if ev['severity'] == 'CRITICAL':
                print(f"  PID={ev['pid']:6s} API={ev['api']:<22s} | {ev['details']}")
        print()

    if report['warning_count'] > 0:
        print("── WARNING Events ──────────────────────────────────")
        for ev in report['events']:
            if ev['severity'] == 'WARNING':
                print(f"  PID={ev['pid']:6s} API={ev['api']:<22s} | {ev['details']}")
        print()


def main():
    if len(sys.argv) < 2:
        print("Usage: python parse_events.py <events.log>")
        print()
        print("To generate events.log:")
        print("  ControllerEXE.exe > events.log 2>&1")
        sys.exit(1)

    log_path    = sys.argv[1]
    output_path = "summary.json"

    print(f"[*] Parsing: {log_path}")
    events = parse_log(log_path)
    print(f"[*] Found {len(events)} events")

    report = generate_report(events)

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"[*] Report saved: {output_path}\n")
    print_summary(report)


if __name__ == "__main__":
    main()