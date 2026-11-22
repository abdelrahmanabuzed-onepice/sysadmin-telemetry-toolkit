"""Autorun persistence auditor for Windows registry run keys and startup directories."""

import argparse
import os
import platform
import sys
from typing import Any, Dict, List, Optional

try:
    import winreg
except ImportError:
    winreg = None  # type: ignore


def scan_registry_run_keys() -> List[Dict[str, str]]:
    """Scan standard Windows Run and RunOnce registry hives."""
    entries: List[Dict[str, str]] = []
    if winreg is None:
        return entries

    hives = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU_Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU_RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM_Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM_RunOnce"),
    ]

    for root_hive, subkey, label in hives:
        try:
            with winreg.OpenKey(root_hive, subkey, 0, winreg.KEY_READ) as key:
                num_values = winreg.QueryInfoKey(key)[1]
                for idx in range(num_values):
                    val_name, val_data, _ = winreg.EnumValue(key, idx)
                    entries.append({
                        "hive": label,
                        "name": str(val_name),
                        "command": str(val_data),
                    })
        except (OSError, PermissionError):
            continue

    return entries


def scan_startup_folders() -> List[Dict[str, str]]:
    """Scan user and system startup shortcut directories."""
    entries: List[Dict[str, str]] = []
    folders = [
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.expandvars(r"%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup"),
    ]

    for folder in folders:
        if os.path.isdir(folder):
            try:
                for fname in os.listdir(folder):
                    fpath = os.path.join(folder, fname)
                    if os.path.isfile(fpath):
                        entries.append({
                            "folder": folder,
                            "filename": fname,
                            "path": fpath,
                        })
            except (OSError, PermissionError):
                continue

    return entries


def execute_autorun_persistence_guard(
    include_startup_folder: bool = True,
    flag_temp_binaries: bool = True,
) -> Dict[str, Any]:
    """Audit system autoruns and persistence locations for potential anomalies."""
    is_win = platform.system().lower() == "windows"
    registry_items = scan_registry_run_keys() if is_win else []
    startup_items = scan_startup_folders() if (is_win and include_startup_folder) else []

    suspicious_entries: List[Dict[str, Any]] = []

    if flag_temp_binaries:
        temp_indicators = ["appdata\\local\\temp", "c:\\temp", "c:\\windows\\temp", ".bat", ".vbs", ".ps1"]
        for r in registry_items:
            cmd_lower = r["command"].lower()
            if any(ind in cmd_lower for ind in temp_indicators):
                suspicious_entries.append({"type": "registry", "entry": r, "reason": "Executes script or temp binary"})
        for s in startup_items:
            fname_lower = s["filename"].lower()
            if any(fname_lower.endswith(ext) for ext in [".bat", ".vbs", ".ps1", ".cmd"]):
                suspicious_entries.append({"type": "startup_folder", "entry": s, "reason": "Executable script in startup folder"})

    return {
        "status": "success",
        "platform": platform.system(),
        "registry_run_keys_count": len(registry_items),
        "registry_entries": registry_items,
        "startup_items_count": len(startup_items),
        "startup_entries": startup_items,
        "flagged_suspicious_count": len(suspicious_entries),
        "flagged_entries": suspicious_entries,
    }


def build_parser() -> argparse.ArgumentParser:
    """Build command line argument parser for autorun persistence guard."""
    parser = argparse.ArgumentParser(
        description="Autorun persistence auditor for Windows registry and startup folders."
    )
    parser.add_argument(
        "--no-startup-folder",
        dest="include_startup_folder",
        action="store_false",
        help="Skip inspection of startup directory shortcuts",
    )
    parser.add_argument(
        "--no-heuristic-flags",
        dest="flag_temp_binaries",
        action="store_false",
        help="Disable heuristic flagging for temp paths and scripts",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for autorun persistence guard."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = execute_autorun_persistence_guard(
            include_startup_folder=args.include_startup_folder,
            flag_temp_binaries=args.flag_temp_binaries,
        )
        print(f"Registry Persistence Entries: {result['registry_run_keys_count']}")
        print(f"Startup Folder Entries: {result['startup_items_count']}")
        print(f"Suspicious Indicators: {result['flagged_suspicious_count']}")
        return 0
    except Exception as exc:
        sys.stderr.write(f"Persistence guard error: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
