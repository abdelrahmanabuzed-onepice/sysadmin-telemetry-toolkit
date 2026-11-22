"""Unified Command Line Interface dispatcher for Sysadmin Telemetry Toolkit."""

import argparse
import os
import sys
from pathlib import Path
from typing import List, Optional

_src_dir = str(Path(__file__).resolve().parent.parent)
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

from sysadmin_telemetry.tools.service_watchdog import build_parser as parse_watchdog, main as main_watchdog
from sysadmin_telemetry.tools.disk_space_guard import build_parser as parse_disk, main as main_disk
from sysadmin_telemetry.tools.win_turbo_cleaner import build_parser as parse_cleaner, main as main_cleaner
from sysadmin_telemetry.tools.process_sentinel import build_parser as parse_process, main as main_process
from sysadmin_telemetry.tools.event_log_auditor import build_parser as parse_event, main as main_event
from sysadmin_telemetry.tools.system_telemetry_reporter import build_parser as parse_telemetry, main as main_telemetry
from sysadmin_telemetry.tools.autorun_persistence_guard import build_parser as parse_autorun, main as main_autorun
from sysadmin_telemetry.tools.env_diagnostic_collector import build_parser as parse_env, main as main_env
from sysadmin_telemetry.tools.ntfs_junction_manager import build_parser as parse_junction, main as main_junction
from sysadmin_telemetry.tools.scheduled_task_inspector import build_parser as parse_task, main as main_task


def build_parser() -> argparse.ArgumentParser:
    """Build unified multi-command argument parser."""
    parser = argparse.ArgumentParser(
        prog="sysadmin-cli",
        description="Sysadmin Telemetry Toolkit: Diagnostic monitoring and maintenance CLI suite.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available telemetry subcommands")

    subparsers.add_parser("watchdog", parents=[parse_watchdog()], add_help=False, help="Monitor and restart system services")
    subparsers.add_parser("disk-guard", parents=[parse_disk()], add_help=False, help="Analyze disk mounts and find duplicates")
    subparsers.add_parser("cleaner", parents=[parse_cleaner()], add_help=False, help="Clean temporary folders and caches")
    subparsers.add_parser("process", parents=[parse_process()], add_help=False, help="Audit memory hogs and suspicious tasks")
    subparsers.add_parser("event-log", parents=[parse_event()], add_help=False, help="Query Windows event logs for anomalies")
    subparsers.add_parser("telemetry", parents=[parse_telemetry()], add_help=False, help="Capture host hardware telemetry snapshot")
    subparsers.add_parser("autorun", parents=[parse_autorun()], add_help=False, help="Inspect registry Run keys and startup links")
    subparsers.add_parser("env-diag", parents=[parse_env()], add_help=False, help="Collect host environment parameters")
    subparsers.add_parser("junction", parents=[parse_junction()], add_help=False, help="Create, list, or verify NTFS junctions")
    subparsers.add_parser("tasks", parents=[parse_task()], add_help=False, help="Audit scheduled tasks for persistence")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Unified CLI dispatch routine."""
    if argv is None:
        argv = sys.argv[1:]

    parser = build_parser()
    if not argv or argv[0] in ("-h", "--help"):
        parser.print_help()
        return 0

    command_map = {
        "watchdog": main_watchdog,
        "disk-guard": main_disk,
        "cleaner": main_cleaner,
        "process": main_process,
        "event-log": main_event,
        "telemetry": main_telemetry,
        "autorun": main_autorun,
        "env-diag": main_env,
        "junction": main_junction,
        "tasks": main_task,
    }

    subcommand = argv[0]
    if subcommand in command_map:
        return command_map[subcommand](argv[1:])

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
