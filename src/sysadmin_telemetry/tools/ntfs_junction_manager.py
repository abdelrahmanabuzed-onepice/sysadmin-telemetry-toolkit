"""NTFS directory junction point manager, verifier, and link analyzer."""

import argparse
import os
import platform
import subprocess
import sys
from typing import Any, Dict, List, Optional


def create_directory_junction(link_path: str, target_path: str) -> Dict[str, Any]:
    """Create an NTFS directory junction using Windows mklink /J command."""
    abs_link = os.path.abspath(link_path)
    abs_target = os.path.abspath(target_path)

    if not os.path.isdir(abs_target):
        return {
            "status": "error",
            "message": f"Target directory does not exist: {abs_target}",
        }

    is_win = platform.system().lower() == "windows"
    if is_win:
        cmd = f'cmd.exe /c mklink /J "{abs_link}" "{abs_target}"'
        try:
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            success = res.returncode == 0 and os.path.exists(abs_link)
            return {
                "status": "success" if success else "failed",
                "link": abs_link,
                "target": abs_target,
                "stdout": res.stdout.strip(),
                "stderr": res.stderr.strip(),
                "exit_code": res.returncode,
            }
        except Exception as exc:
            return {"status": "error", "message": str(exc)}
    else:
        # Cross-platform symlink fallback
        try:
            os.symlink(abs_target, abs_link, target_is_directory=True)
            return {
                "status": "success",
                "link": abs_link,
                "target": abs_target,
                "note": "Created directory symlink on POSIX platform",
            }
        except Exception as exc:
            return {"status": "error", "message": str(exc)}


def list_junctions_in_directory(root_dir: str) -> List[Dict[str, str]]:
    """Scan a folder to discover NTFS junctions or directory symlinks."""
    results: List[Dict[str, str]] = []
    abs_root = os.path.abspath(root_dir)

    try:
        for entry in os.scandir(abs_root):
            try:
                if entry.is_dir():
                    stat_info = entry.stat(follow_symlinks=False)
                    # Check reparse point flag on Windows if available (st_file_attributes)
                    is_junction = False
                    if hasattr(stat_info, "st_file_attributes"):
                        # FILE_ATTRIBUTE_REPARSE_POINT = 0x400
                        is_junction = bool(stat_info.st_file_attributes & 0x400)
                    elif entry.is_symlink():
                        is_junction = True

                    if is_junction:
                        target = ""
                        try:
                            target = os.readlink(entry.path)
                        except OSError:
                            pass
                        results.append({
                            "name": entry.name,
                            "path": entry.path,
                            "target": target,
                        })
            except (OSError, PermissionError):
                continue
    except (OSError, PermissionError):
        pass

    return results


def execute_ntfs_junction_manager(
    action: str = "list",
    link_path: Optional[str] = None,
    target_path: Optional[str] = None,
    scan_dir: str = ".",
) -> Dict[str, Any]:
    """Execute NTFS directory junction operations (create, list, verify)."""
    if action == "create":
        if not link_path or not target_path:
            return {"status": "error", "message": "Both link_path and target_path are required to create a junction"}
        return create_directory_junction(link_path, target_path)

    elif action == "verify":
        if not link_path:
            return {"status": "error", "message": "link_path is required for verification"}
        abs_link = os.path.abspath(link_path)
        exists = os.path.exists(abs_link)
        is_dir = os.path.isdir(abs_link)
        return {
            "status": "success",
            "path": abs_link,
            "exists": exists,
            "is_directory": is_dir,
        }

    else:
        # Default action: list
        junctions = list_junctions_in_directory(scan_dir)
        return {
            "status": "success",
            "scan_dir": os.path.abspath(scan_dir),
            "junctions_found": len(junctions),
            "junctions": junctions,
        }


def build_parser() -> argparse.ArgumentParser:
    """Build command line argument parser for junction manager."""
    parser = argparse.ArgumentParser(
        description="NTFS directory junction creator, inspector, and verifier."
    )
    parser.add_argument(
        "--action",
        "-a",
        choices=["list", "create", "verify"],
        default="list",
        help="Action to perform (default: list)",
    )
    parser.add_argument("--link", "-l", help="Junction link path (for create/verify)")
    parser.add_argument("--target", "-t", help="Target real directory (for create)")
    parser.add_argument("--dir", "-d", default=".", help="Directory to scan for junctions")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for NTFS junction manager."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = execute_ntfs_junction_manager(
            action=args.action,
            link_path=args.link,
            target_path=args.target,
            scan_dir=args.dir,
        )
        if args.action == "create":
            print(f"Junction creation: {result.get('status')} -> {result.get('link')}")
        elif args.action == "verify":
            print(f"Verified: {result.get('path')} (Exists: {result.get('exists')})")
        else:
            print(f"Scanned {result.get('scan_dir')}: Found {result.get('junctions_found')} junction(s)")
        return 0
    except Exception as exc:
        sys.stderr.write(f"Junction manager error: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
