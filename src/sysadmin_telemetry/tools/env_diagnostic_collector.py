"""Environment diagnostic collector for system parameters, runtime versions, and sanitized configs."""

import argparse
import json
import os
import platform
import socket
import sys
from typing import Any, Dict, List, Optional


def redact_sensitive_value(key: str, val: str) -> str:
    """Mask potential secrets and credentials in environment variables."""
    key_upper = key.upper()
    sensitive_tokens = ["PASS", "SECRET", "TOKEN", "KEY", "AUTH", "CREDENTIAL", "PRIVATE"]
    if any(tok in key_upper for tok in sensitive_tokens):
        return "********"
    return val


def execute_env_diagnostic_collector(
    output_file: Optional[str] = None,
    redact_secrets: bool = True,
) -> Dict[str, Any]:
    """Collect system runtime environment, hardware platform, and sanitized variables."""
    env_vars: Dict[str, str] = {}
    for k, v in os.environ.items():
        env_vars[k] = redact_sensitive_value(k, v) if redact_secrets else v

    diagnostic_payload = {
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "node": socket.gethostname(),
        },
        "python": {
            "version": platform.python_version(),
            "compiler": platform.python_compiler(),
            "build": platform.python_build(),
            "executable": sys.executable,
        },
        "environment_variables": env_vars,
        "variable_count": len(env_vars),
    }

    if output_file:
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(diagnostic_payload, f, indent=2)

    return {
        "status": "success",
        "output_file": output_file,
        "diagnostics": diagnostic_payload,
    }


def build_parser() -> argparse.ArgumentParser:
    """Build command line argument parser for environment collector."""
    parser = argparse.ArgumentParser(
        description="Environment diagnostic collector for OS, runtime, and sanitized variables."
    )
    parser.add_argument("--output", "-o", help="Optional output JSON path for the collected report")
    parser.add_argument(
        "--no-redact",
        dest="redact_secrets",
        action="store_false",
        help="Disable redaction of sensitive credentials",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for environment collector."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = execute_env_diagnostic_collector(
            output_file=args.output,
            redact_secrets=args.redact_secrets,
        )
        diag = result["diagnostics"]
        print(f"OS: {diag['os']['system']} {diag['os']['release']} ({diag['os']['machine']})")
        print(f"Python: {diag['python']['version']} | Env Variables Collected: {diag['variable_count']}")
        return 0
    except Exception as exc:
        sys.stderr.write(f"Diagnostic collector error: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
