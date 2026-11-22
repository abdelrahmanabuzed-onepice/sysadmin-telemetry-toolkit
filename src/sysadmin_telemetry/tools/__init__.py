"""Export all 10 sysadmin telemetry tools."""

from sysadmin_telemetry.tools.service_watchdog import execute_service_watchdog
from sysadmin_telemetry.tools.disk_space_guard import execute_disk_space_guard
from sysadmin_telemetry.tools.win_turbo_cleaner import execute_win_turbo_cleaner
from sysadmin_telemetry.tools.process_sentinel import execute_process_sentinel
from sysadmin_telemetry.tools.event_log_auditor import execute_event_log_auditor
from sysadmin_telemetry.tools.system_telemetry_reporter import execute_system_telemetry_reporter
from sysadmin_telemetry.tools.autorun_persistence_guard import execute_autorun_persistence_guard
from sysadmin_telemetry.tools.env_diagnostic_collector import execute_env_diagnostic_collector
from sysadmin_telemetry.tools.ntfs_junction_manager import execute_ntfs_junction_manager
from sysadmin_telemetry.tools.scheduled_task_inspector import execute_scheduled_task_inspector

__all__ = [
    "execute_service_watchdog",
    "execute_disk_space_guard",
    "execute_win_turbo_cleaner",
    "execute_process_sentinel",
    "execute_event_log_auditor",
    "execute_system_telemetry_reporter",
    "execute_autorun_persistence_guard",
    "execute_env_diagnostic_collector",
    "execute_ntfs_junction_manager",
    "execute_scheduled_task_inspector",
]
