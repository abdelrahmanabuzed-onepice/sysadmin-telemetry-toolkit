"""Temporary file, application cache cleaner, and storage recovery utility."""

import argparse
import os
import shutil
import sys
import tempfile
from typing import Any, Dict, List, Optional


def execute_win_turbo_cleaner(
    dry_run: bool = True,
    paths: Optional[List[str]] = None,
    older_than_days: int = 0,
) -> Dict[str, Any]:
    """Scan and clean temporary and cache directories, reporting reclaimed storage."""
    target_paths: List[str] = []
    if paths:
        target_paths = [os.path.abspath(p) for p in paths if os.path.isdir(p)]
    else:
        # Default standard temporary directories
        candidates = [
            tempfile.gettempdir(),
            os.path.expandvars(r"%LOCALAPPDATA%\Temp"),
            os.path.expandvars(r"%WINDIR%\Temp"),
        ]
        target_paths = list({os.path.abspath(c) for c in candidates if os.path.isdir(c)})

    total_scanned_files = 0
    total_reclaimed_bytes = 0
    deleted_items: List[str] = []
    skipped_items: List[Dict[str, str]] = []

    for base_dir in target_paths:
        try:
            entries = os.scandir(base_dir)
        except (PermissionError, OSError) as exc:
            skipped_items.append({"path": base_dir, "reason": str(exc)})
            continue

        for entry in entries:
            total_scanned_files += 1
            entry_path = entry.path
            try:
                stat = entry.stat(follow_symlinks=False)
                entry_size = stat.st_size
                if not dry_run:
                    if entry.is_file() or entry.is_symlink():
                        os.remove(entry_path)
                    elif entry.is_dir():
                        shutil.rmtree(entry_path, ignore_errors=True)
                total_reclaimed_bytes += entry_size
                deleted_items.append(entry_path)
            except (PermissionError, OSError) as exc:
                skipped_items.append({"path": entry_path, "reason": str(exc)})

    return {
        "status": "success",
        "dry_run": dry_run,
        "scanned_directories": target_paths,
        "total_scanned_items": total_scanned_files,
        "actioned_items_count": len(deleted_items),
        "reclaimed_bytes": total_reclaimed_bytes,
        "reclaimed_mb": round(total_reclaimed_bytes / (1024 * 1024), 2),
        "skipped_items_count": len(skipped_items),
        "sample_actioned": deleted_items[:20],
    }


def build_parser() -> argparse.ArgumentParser:
    """Build command line argument parser for temporary cleaner."""
    parser = argparse.ArgumentParser(
        description="Temporary file, application cache analyzer, and storage cleaner."
    )
    parser.add_argument(
        "--no-dry-run",
        dest="dry_run",
        action="store_false",
        help="Perform genuine file deletion (defaults to safe dry-run analysis)",
    )
    parser.add_argument(
        "--paths",
        "-p",
        nargs="+",
        help="Custom directories to clean",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for temporary cleaner."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = execute_win_turbo_cleaner(
            dry_run=args.dry_run,
            paths=args.paths,
        )
        mode = "DRY-RUN (Simulated)" if result["dry_run"] else "ACTIVE (Deleted)"
        print(f"Cleaner Mode: {mode}")
        print(f"Scanned Items: {result['total_scanned_items']} across {len(result['scanned_directories'])} directories")
        print(f"Storage Reclaimed: {result['reclaimed_mb']} MB ({result['actioned_items_count']} items)")
        return 0
    except Exception as exc:
        sys.stderr.write(f"Cleaner error: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
