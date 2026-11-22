"""Unit tests for all 10 sysadmin telemetry tools."""

import os
import tempfile
import pytest

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


def test_service_watchdog():
    res = execute_service_watchdog(service_names=["EventLog", "Spooler"])
    assert "status" in res
    assert "services" in res
    assert isinstance(res["services"], list)


def test_disk_space_guard():
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "test.bin")
        with open(test_file, "wb") as f:
            f.write(b"0" * 2048)
        res = execute_disk_space_guard(target_path=tmpdir, size_threshold_mb=0.001)
        assert res["status"] == "success"
        assert "mount" in res
        assert res["large_files_count"] >= 1


def test_win_turbo_cleaner():
    with tempfile.TemporaryDirectory() as tmpdir:
        dummy_file = os.path.join(tmpdir, "sample.tmp")
        with open(dummy_file, "w") as f:
            f.write("temporary junk")
        res = execute_win_turbo_cleaner(dry_run=True, paths=[tmpdir])
        assert res["status"] == "success"
        assert res["dry_run"] is True
        assert res["actioned_items_count"] >= 1
        assert os.path.exists(dummy_file)


def test_process_sentinel():
    res = execute_process_sentinel(mem_mb_threshold=10.0)
    assert res["status"] == "success"
    assert "total_processes_scanned" in res
    assert "high_memory_processes" in res


def test_event_log_auditor():
    res = execute_event_log_auditor(log_name="System", max_events=5)
    assert res["status"] == "success"
    assert "events" in res


def test_system_telemetry_reporter():
    with tempfile.TemporaryDirectory() as tmpdir:
        out_json = os.path.join(tmpdir, "telemetry.json")
        res = execute_system_telemetry_reporter(output_format="json", output_path=out_json)
        assert res["status"] == "success"
        assert os.path.exists(out_json)
        assert "telemetry" in res
        assert "host" in res["telemetry"]


def test_autorun_persistence_guard():
    res = execute_autorun_persistence_guard(include_startup_folder=True)
    assert res["status"] == "success"
    assert "registry_run_keys_count" in res


def test_env_diagnostic_collector():
    res = execute_env_diagnostic_collector()
    assert res["status"] == "success"
    assert "diagnostics" in res
    assert "os" in res["diagnostics"]
    assert "python" in res["diagnostics"]


def test_ntfs_junction_manager():
    res = execute_ntfs_junction_manager(action="list", scan_dir=".")
    assert res["status"] == "success"
    assert "junctions_found" in res


def test_scheduled_task_inspector():
    res = execute_scheduled_task_inspector()
    assert res["status"] == "success"
    assert "total_tasks_audited" in res
