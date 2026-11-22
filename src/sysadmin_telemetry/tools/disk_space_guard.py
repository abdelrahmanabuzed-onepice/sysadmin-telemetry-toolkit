"""Disk space utilization guard, large file identifier, and SHA-256 duplicate finder."""

import argparse
import hashlib
import os
import shutil
import sys
from typing import Any, Dict, List, Optional


def hash_file_sha256(path: str, chunk_size: int = 65536) -> Optional[str]:
    """Compute SHA-256 hash of a file efficiently in streaming chunks."""
    hasher = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (OSError, PermissionError):
        return None


def execute_disk_space_guard(
    target_path: str = ".",
    size_threshold_mb: float = 100.0,
    find_duplicates: bool = True,
    max_scan_depth: int = 5,
) -> Dict[str, Any]:
    """Scan disk mounts, detect high-capacity files exceeding threshold, and locate duplicates."""
    target_dir = os.path.abspath(target_path)
    threshold_bytes = int(size_threshold_mb * 1024 * 1024)

    total_b, used_b, free_b = shutil.disk_usage(target_dir)
    disk_metrics = {
        "mount_path": target_dir,
        "total_gb": round(total_b / (1024**3), 2),
        "used_gb": round(used_b / (1024**3), 2),
        "free_gb": round(free_b / (1024**3), 2),
        "used_percent": round((used_b / total_b) * 100, 2) if total_b else 0,
    }

    large_files: List[Dict[str, Any]] = []
    size_groups: Dict[int, List[str]] = {}

    target_depth = target_dir.rstrip(os.path.sep).count(os.path.sep)

    for root, _, files in os.walk(target_dir):
        current_depth = root.count(os.path.sep) - target_depth
        if current_depth > max_scan_depth:
            continue

        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                stat = os.stat(fpath)
                fsize = stat.st_size
                if fsize >= threshold_bytes:
                    large_files.append({
                        "path": fpath,
                        "size_bytes": fsize,
                        "size_mb": round(fsize / (1024 * 1024), 2),
                    })

                if find_duplicates and fsize > 1024:
                    size_groups.setdefault(fsize, []).append(fpath)
            except (OSError, PermissionError):
                continue

    duplicate_sets: List[Dict[str, Any]] = []
    if find_duplicates:
        for size, candidates in size_groups.items():
            if len(candidates) < 2:
                continue
            hashes: Dict[str, List[str]] = {}
            for cand in candidates:
                cand_hash = hash_file_sha256(cand)
                if cand_hash:
                    hashes.setdefault(cand_hash, []).append(cand)
            for hval, match_list in hashes.items():
                if len(match_list) > 1:
                    duplicate_sets.append({
                        "sha256": hval,
                        "size_bytes": size,
                        "files": match_list,
                        "wasted_bytes": size * (len(match_list) - 1),
                    })

    large_files.sort(key=lambda x: x["size_bytes"], reverse=True)

    return {
        "status": "success",
        "mount": disk_metrics,
        "large_files_count": len(large_files),
        "large_files": large_files[:50],
        "duplicate_sets_count": len(duplicate_sets),
        "duplicate_sets": duplicate_sets[:25],
    }


def build_parser() -> argparse.ArgumentParser:
    """Build command line argument parser for disk space guard."""
    parser = argparse.ArgumentParser(
        description="Disk space usage analyzer, large file detector, and duplicate finder."
    )
    parser.add_argument("--path", "-p", default=".", help="Root directory to scan (default: current directory)")
    parser.add_argument(
        "--threshold-mb",
        "-t",
        type=float,
        default=100.0,
        help="Size threshold in megabytes to flag files (default: 100.0 MB)",
    )
    parser.add_argument(
        "--no-duplicates",
        dest="find_duplicates",
        action="store_false",
        help="Skip SHA-256 duplicate scanning",
    )
    parser.add_argument(
        "--depth",
        "-d",
        type=int,
        default=5,
        help="Maximum folder traversal depth (default: 5)",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for disk space guard."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = execute_disk_space_guard(
            target_path=args.path,
            size_threshold_mb=args.threshold_mb,
            find_duplicates=args.find_duplicates,
            max_scan_depth=args.depth,
        )
        mount = result["mount"]
        print(f"Mount: {mount['mount_path']} | Used: {mount['used_gb']}GB ({mount['used_percent']}%) | Free: {mount['free_gb']}GB")
        print(f"Large files (> {args.threshold_mb}MB): {result['large_files_count']}")
        print(f"Duplicate file clusters detected: {result['duplicate_sets_count']}")
        return 0
    except Exception as exc:
        sys.stderr.write(f"Disk guard error: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
