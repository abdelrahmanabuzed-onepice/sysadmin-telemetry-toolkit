"""System telemetry snapshot reporter for CPU, memory, disk, and network interfaces."""

import argparse
import csv
import json
import os
import platform
import shutil
import socket
import sys
import time
from typing import Any, Dict, List, Optional


def redact_ip_address(ip_str: str) -> str:
    """Mask non-private IP addresses to protect public network identity."""
    if not ip_str or ip_str in ("127.0.0.1", "::1", "localhost"):
        return ip_str
    # Check if private IPv4
    parts = ip_str.split(".")
    if len(parts) == 4:
        try:
            p0, p1 = int(parts[0]), int(parts[1])
            if p0 == 10 or (p0 == 172 and 16 <= p1 <= 31) or (p0 == 192 and p1 == 168):
                return ip_str
        except ValueError:
            pass
    return "[REDACTED-IP]"


def execute_system_telemetry_reporter(
    output_format: str = "json",
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Capture comprehensive telemetry snapshot including CPU, storage, and network state."""
    hostname = socket.gethostname()
    try:
        raw_ip = socket.gethostbyname(hostname)
        host_ip = redact_ip_address(raw_ip)
    except Exception:
        host_ip = "127.0.0.1"

    # Disk usage for current drive
    root_path = os.path.abspath(os.sep)
    total_b, used_b, free_b = shutil.disk_usage(root_path)

    snapshot = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": {
            "name": hostname,
            "ip": host_ip,
            "platform": platform.platform(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "cpu_cores": os.cpu_count() or 1,
            "python_version": platform.python_version(),
        },
        "storage": {
            "root_mount": root_path,
            "total_gb": round(total_b / (1024**3), 2),
            "used_gb": round(used_b / (1024**3), 2),
            "free_gb": round(free_b / (1024**3), 2),
            "utilization_percent": round((used_b / total_b) * 100, 2) if total_b else 0,
        },
    }

    if output_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        if output_format.lower() == "csv":
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Metric", "Value"])
                writer.writerow(["Timestamp", snapshot["timestamp"]])
                writer.writerow(["Hostname", hostname])
                writer.writerow(["Platform", snapshot["host"]["platform"]])
                writer.writerow(["CPU Cores", snapshot["host"]["cpu_cores"]])
                writer.writerow(["Root Total GB", snapshot["storage"]["total_gb"]])
                writer.writerow(["Root Free GB", snapshot["storage"]["free_gb"]])
        else:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, indent=2)

    return {
        "status": "success",
        "format": output_format,
        "output_path": output_path,
        "telemetry": snapshot,
    }


def build_parser() -> argparse.ArgumentParser:
    """Build command line argument parser for telemetry reporter."""
    parser = argparse.ArgumentParser(
        description="System telemetry snapshot reporter for CPU, storage, and host metrics."
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["json", "csv"],
        default="json",
        help="Export serialization format (default: json)",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Optional destination file path to save snapshot",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for telemetry reporter."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = execute_system_telemetry_reporter(
            output_format=args.format,
            output_path=args.output,
        )
        snap = result["telemetry"]
        print(f"Host: {snap['host']['name']} ({snap['host']['platform']})")
        print(f"Cores: {snap['host']['cpu_cores']} | Disk Utilization: {snap['storage']['utilization_percent']}%")
        if result["output_path"]:
            print(f"Report written to: {result['output_path']}")
        return 0
    except Exception as exc:
        sys.stderr.write(f"Telemetry reporter error: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
