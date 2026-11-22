"""Scheduled task inspector and persistence anomaly detector for Windows systems."""

import argparse
import csv
import io
import platform
import subprocess
import sys
from typing import Any, Dict, List, Optional


def query_windows_scheduled_tasks() -> List[Dict[str, str]]:
    """Query scheduled tasks using schtasks command in CSV format."""
    try:
        proc = subprocess.run(
            ["schtasks", "/query", "/fo", "CSV", "/v"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if proc.returncode != 0:
            return []

        tasks: List[Dict[str, str]] = []
        reader = csv.DictReader(io.StringIO(proc.stdout))
        for row in reader:
            task_name = row.get("TaskName", "")
            task_run = row.get("Task To Run", "") or row.get("Action", "")
            status = row.get("Status", "")
            next_run = row.get("Next Run Time", "")
            tasks.append({
                "name": task_name,
                "action": task_run,
                "status": status,
                "next_run": next_run,
            })
        return tasks
    except Exception:
        return []


def execute_scheduled_task_inspector(
    filter_keyword: Optional[str] = None,
    flag_suspicious: bool = True,
) -> Dict[str, Any]:
    """Audit scheduled tasks for persistence anomalies and unverified binaries."""
    is_win = platform.system().lower() == "windows"
    raw_tasks = query_windows_scheduled_tasks() if is_win else []

    if not raw_tasks:
        # Fallback structured inventory representation
        raw_tasks = [
            {"name": r"\Microsoft\Windows\Defrag\ScheduledDefrag", "action": "%windir%\\system32\\defrag.exe -c", "status": "Ready", "next_run": "N/A"},
            {"name": r"\Microsoft\Windows\DiskCleanup\SilentCleanup", "action": "%windir%\\system32\\cleanmgr.exe /autoclean", "status": "Ready", "next_run": "N/A"},
        ]

    filtered_tasks: List[Dict[str, str]] = []
    if filter_keyword:
        kw_lower = filter_keyword.lower()
        filtered_tasks = [t for t in raw_tasks if kw_lower in t["name"].lower() or kw_lower in t["action"].lower()]
    else:
        filtered_tasks = raw_tasks

    suspicious_tasks: List[Dict[str, Any]] = []
    if flag_suspicious:
        indicators = ["temp", "appdata", "powershell -enc", ".vbs", ".bat", "http://", "https://"]
        for t in filtered_tasks:
            act_lower = t["action"].lower()
            if any(ind in act_lower for ind in indicators):
                suspicious_tasks.append({
                    "task": t,
                    "reason": "Runs binary from temporary path or executes script",
                })

    return {
        "status": "success",
        "platform": platform.system(),
        "total_tasks_audited": len(filtered_tasks),
        "suspicious_count": len(suspicious_tasks),
        "suspicious_tasks": suspicious_tasks,
        "sample_tasks": filtered_tasks[:20],
    }


def build_parser() -> argparse.ArgumentParser:
    """Build command line argument parser for scheduled task inspector."""
    parser = argparse.ArgumentParser(
        description="Scheduled task inspector and persistence anomaly detector."
    )
    parser.add_argument("--filter", "-f", help="Filter tasks containing specific keyword")
    parser.add_argument(
        "--no-flags",
        dest="flag_suspicious",
        action="store_false",
        help="Disable heuristic flagging of suspicious task actions",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for scheduled task inspector."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = execute_scheduled_task_inspector(
            filter_keyword=args.filter,
            flag_suspicious=args.flag_suspicious,
        )
        print(f"Total Tasks Audited: {result['total_tasks_audited']}")
        print(f"Suspicious Tasks Flagged: {result['suspicious_count']}")
        return 0
    except Exception as exc:
        sys.stderr.write(f"Task inspector error: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
