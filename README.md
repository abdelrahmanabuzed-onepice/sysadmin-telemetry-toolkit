# Sysadmin Telemetry Toolkit

A modular Python diagnostic and telemetry monitoring suite engineered for systems administration, resource profiling, persistence auditing, and maintenance on Windows hosts.

## Architecture

```text
[ Host OS Environment ]
  │   ├── Windows Service Subsystem (SC / Service Control Manager)
  │   ├── Windows Registry (Run / RunOnce Hives)
  │   ├── Task Scheduler Service (schtasks engine)
  │   └── Event Log Subsystem (wevtutil / Windows Event Provider)
  ▼
[ Telemetry & Sentinel Processing Core ]
  │   ├── Service Watchdog & Auto-Recovery
  │   ├── Process Memory & Anomaly Auditor
  │   ├── Storage & Mount Utilization Profiler
  │   ├── Cache & Temporary Space Reclaim Engine
  │   ├── NTFS Directory Junction Link Manager
  │   └── Host Hardware & Runtime Sanitizer
  ▼
[ Diagnostic Delivery Targets ]
  ├── Real-time Terminal Operator Telemetry
  ├── Structured JSON Diagnostics Snapshots
  └── Sanitized CSV Reporting Metrics
```

## Tool Inventory

| Tool | Module | Description |
|---|---|---|
| Service Watchdog | `service_watchdog.py` | Monitors service status and critical process health with auto-recovery logic |
| Disk Space Guard | `disk_space_guard.py` | Analyzes disk mount usage, flags large files, and discovers SHA-256 duplicates |
| Win Turbo Cleaner | `win_turbo_cleaner.py` | Scans and cleans temporary caches and system scratch directories |
| Process Sentinel | `process_sentinel.py` | Audits running tasks, flags excessive memory consumption, and flags anomalies |
| Event Log Auditor | `event_log_auditor.py` | Queries system and application event logs for error and warning diagnostics |
| System Telemetry Reporter | `system_telemetry_reporter.py` | Gathers CPU, disk, host parameters, and network state into JSON/CSV snapshots |
| Autorun Persistence Guard | `autorun_persistence_guard.py` | Audits registry Run keys and startup directories for configured persistence |
| Env Diagnostic Collector | `env_diagnostic_collector.py` | Captures OS, Python runtime, and sanitized environment variables |
| NTFS Junction Manager | `ntfs_junction_manager.py` | Creates, lists, and verifies directory junction points via mklink |
| Scheduled Task Inspector | `scheduled_task_inspector.py` | Queries and inspects Windows scheduled tasks for suspicious entries |

## Quickstart

### Installation

```bash
git clone https://github.com/abdelrahmanabuzed-onepice/sysadmin-telemetry-toolkit.git
cd sysadmin-telemetry-toolkit
pip install -e .
```

### Usage Examples

Run via unified CLI dispatcher:

```bash
# Display CLI help
sysadmin-cli --help

# Query service health
sysadmin-cli watchdog --services EventLog Spooler

# Analyze disk space and find duplicate files
sysadmin-cli disk-guard --path C:\ --threshold-mb 200

# Capture comprehensive telemetry snapshot
sysadmin-cli telemetry --format json --output telemetry_report.json
```

Or execute individual tool scripts directly:

```bash
python src/sysadmin_telemetry/tools/system_telemetry_reporter.py --format json
```

## Testing

Execute the unit test suite using pytest:

```bash
pytest tests/
```

## Author

Abdelrahman Abouzed  
GitHub: [abdelrahmanabuzed-onepice](https://github.com/abdelrahmanabuzed-onepice)
