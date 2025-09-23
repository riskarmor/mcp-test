#!/usr/bin/env python3
"""
Storage Manager
===============
Manages disk space, cleanup, and monitoring for repository storage.
"""

import os
import shutil
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import json

logger = logging.getLogger(__name__)


class StorageManager:
    """Manages storage operations and monitoring."""

    def __init__(self, base_path: str = "/mnt/prod/repos"):
        """
        Initialize storage manager.

        Args:
            base_path: Base directory for storage
        """
        self.base_path = Path(base_path)
        self.thresholds = {
            "warning_percent": 80,
            "critical_percent": 90,
            "archive_retention_days": 30,
            "cache_retention_days": 7,
            "report_retention_days": 30
        }

    def get_storage_usage(self) -> Dict[str, Any]:
        """
        Calculate storage usage for all categories.

        Returns:
            Dictionary with storage statistics
        """
        usage = {
            "timestamp": datetime.now().isoformat(),
            "categories": {},
            "total": {},
            "disk": {}
        }

        # Calculate usage by category
        total_bytes = 0
        for category in ['active', 'archive', 'cache', 'metadata']:
            path = self.base_path / category
            if path.exists():
                size = self._calculate_directory_size(path)
                usage["categories"][category] = {
                    "bytes": size,
                    "mb": round(size / (1024 * 1024), 2),
                    "gb": round(size / (1024 * 1024 * 1024), 2),
                    "percentage": 0  # Will calculate after total
                }
                total_bytes += size

        # Calculate total usage
        usage["total"] = {
            "bytes": total_bytes,
            "mb": round(total_bytes / (1024 * 1024), 2),
            "gb": round(total_bytes / (1024 * 1024 * 1024), 2)
        }

        # Calculate percentages
        if total_bytes > 0:
            for category in usage["categories"]:
                cat_bytes = usage["categories"][category]["bytes"]
                usage["categories"][category]["percentage"] = round(
                    (cat_bytes / total_bytes) * 100, 2
                )

        # Get disk usage
        if self.base_path.exists():
            stat = shutil.disk_usage(self.base_path)
            usage["disk"] = {
                "total_gb": round(stat.total / (1024 ** 3), 2),
                "used_gb": round(stat.used / (1024 ** 3), 2),
                "free_gb": round(stat.free / (1024 ** 3), 2),
                "percent_used": round((stat.used / stat.total) * 100, 2)
            }

        return usage

    def _calculate_directory_size(self, path: Path) -> int:
        """
        Calculate total size of a directory.

        Args:
            path: Directory path

        Returns:
            Total size in bytes
        """
        try:
            total = 0
            for entry in path.rglob('*'):
                if entry.is_file() and not entry.is_symlink():
                    total += entry.stat().st_size
            return total
        except Exception as e:
            logger.error(f"Error calculating directory size: {e}")
            return 0

    def cleanup_archives(self, days: Optional[int] = None) -> Dict[str, Any]:
        """
        Clean up old archived repositories.

        Args:
            days: Retention period in days

        Returns:
            Cleanup statistics
        """
        if days is None:
            days = self.thresholds["archive_retention_days"]

        archive_path = self.base_path / "archive"
        if not archive_path.exists():
            return {"removed_dirs": 0, "freed_bytes": 0}

        cutoff = datetime.now() - timedelta(days=days)
        removed_dirs = []
        freed_bytes = 0

        for month_dir in archive_path.iterdir():
            if month_dir.is_dir():
                try:
                    # Parse directory name (YYYY-MM format)
                    dir_date = datetime.strptime(month_dir.name, "%Y-%m")

                    if dir_date < cutoff:
                        # Calculate size before deletion
                        dir_size = self._calculate_directory_size(month_dir)

                        # Remove directory
                        shutil.rmtree(month_dir)

                        removed_dirs.append(month_dir.name)
                        freed_bytes += dir_size
                        logger.info(f"Removed archive: {month_dir}")

                except (ValueError, OSError) as e:
                    logger.error(f"Error processing archive {month_dir}: {e}")

        return {
            "removed_dirs": len(removed_dirs),
            "freed_bytes": freed_bytes,
            "freed_mb": round(freed_bytes / (1024 * 1024), 2),
            "directories": removed_dirs
        }

    def cleanup_cache(self, days: Optional[int] = None) -> Dict[str, Any]:
        """
        Clean up old cache files.

        Args:
            days: Retention period in days

        Returns:
            Cleanup statistics
        """
        if days is None:
            days = self.thresholds["cache_retention_days"]

        cache_path = self.base_path / "cache"
        if not cache_path.exists():
            return {"removed_files": 0, "freed_bytes": 0}

        cutoff = datetime.now() - timedelta(days=days)
        removed_files = 0
        freed_bytes = 0

        # Clean up each cache subdirectory
        for subdir in ['sboms', 'reports', 'rules']:
            subdir_path = cache_path / subdir
            if subdir_path.exists():
                for file_path in subdir_path.rglob('*'):
                    if file_path.is_file():
                        try:
                            # Check file age
                            file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime)

                            if file_mtime < cutoff:
                                file_size = file_path.stat().st_size
                                file_path.unlink()
                                removed_files += 1
                                freed_bytes += file_size

                        except Exception as e:
                            logger.error(f"Error removing cache file {file_path}: {e}")

        return {
            "removed_files": removed_files,
            "freed_bytes": freed_bytes,
            "freed_mb": round(freed_bytes / (1024 * 1024), 2)
        }

    def check_disk_space(self) -> Dict[str, Any]:
        """
        Check disk space and return alerts if needed.

        Returns:
            Disk space status and alerts
        """
        usage = self.get_storage_usage()
        disk = usage.get("disk", {})

        status = {
            "timestamp": datetime.now().isoformat(),
            "percent_used": disk.get("percent_used", 0),
            "free_gb": disk.get("free_gb", 0),
            "status": "ok",
            "alerts": []
        }

        percent_used = disk.get("percent_used", 0)

        if percent_used >= self.thresholds["critical_percent"]:
            status["status"] = "critical"
            status["alerts"].append({
                "level": "critical",
                "message": f"Disk space critical: {percent_used:.1f}% used",
                "action": "Immediate cleanup required"
            })

        elif percent_used >= self.thresholds["warning_percent"]:
            status["status"] = "warning"
            status["alerts"].append({
                "level": "warning",
                "message": f"Disk space warning: {percent_used:.1f}% used",
                "action": "Consider cleanup"
            })

        return status

    def emergency_cleanup(self) -> Dict[str, Any]:
        """
        Perform emergency cleanup when disk space is critical.

        Returns:
            Cleanup statistics
        """
        logger.warning("Performing emergency cleanup")
        results = {
            "timestamp": datetime.now().isoformat(),
            "actions": []
        }

        # 1. Clear old cache (1 day retention)
        cache_result = self.cleanup_cache(days=1)
        results["actions"].append({
            "type": "cache_cleanup",
            "result": cache_result
        })

        # 2. Remove old archives (7 day retention)
        archive_result = self.cleanup_archives(days=7)
        results["actions"].append({
            "type": "archive_cleanup",
            "result": archive_result
        })

        # 3. Clear temporary files
        temp_result = self._cleanup_temp_files()
        results["actions"].append({
            "type": "temp_cleanup",
            "result": temp_result
        })

        # Calculate total freed space
        total_freed = sum(
            action["result"].get("freed_bytes", 0)
            for action in results["actions"]
        )
        results["total_freed_mb"] = round(total_freed / (1024 * 1024), 2)

        return results

    def _cleanup_temp_files(self) -> Dict[str, Any]:
        """
        Clean up temporary files.

        Returns:
            Cleanup statistics
        """
        temp_patterns = ['*.tmp', '*.log', '.git/objects/pack/tmp_*']
        removed_files = 0
        freed_bytes = 0

        for pattern in temp_patterns:
            for temp_file in self.base_path.rglob(pattern):
                if temp_file.is_file():
                    try:
                        file_size = temp_file.stat().st_size
                        temp_file.unlink()
                        removed_files += 1
                        freed_bytes += file_size
                    except Exception as e:
                        logger.error(f"Error removing temp file {temp_file}: {e}")

        return {
            "removed_files": removed_files,
            "freed_bytes": freed_bytes,
            "freed_mb": round(freed_bytes / (1024 * 1024), 2)
        }

    def get_repository_sizes(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get sizes of repositories, sorted by size.

        Args:
            limit: Number of repositories to return

        Returns:
            List of repository size information
        """
        repo_sizes = []
        active_path = self.base_path / "active" / "by-owner"

        if active_path.exists():
            for owner_dir in active_path.iterdir():
                if owner_dir.is_dir():
                    for repo_dir in owner_dir.iterdir():
                        if repo_dir.is_dir() and not repo_dir.is_symlink():
                            size = self._calculate_directory_size(repo_dir)
                            repo_sizes.append({
                                "owner": owner_dir.name,
                                "name": repo_dir.name,
                                "path": str(repo_dir),
                                "size_bytes": size,
                                "size_mb": round(size / (1024 * 1024), 2)
                            })

        # Sort by size (largest first)
        repo_sizes.sort(key=lambda x: x["size_bytes"], reverse=True)

        return repo_sizes[:limit]

    def generate_storage_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive storage report.

        Returns:
            Storage report dictionary
        """
        report = {
            "timestamp": datetime.now().isoformat(),
            "usage": self.get_storage_usage(),
            "disk_status": self.check_disk_space(),
            "largest_repos": self.get_repository_sizes(10),
            "recommendations": []
        }

        # Add recommendations based on usage
        disk_percent = report["disk_status"]["percent_used"]

        if disk_percent > 90:
            report["recommendations"].append(
                "Critical: Immediate cleanup required. Run emergency_cleanup()"
            )
        elif disk_percent > 80:
            report["recommendations"].append(
                "Warning: Consider archiving inactive repositories"
            )

        # Check cache size
        cache_mb = report["usage"]["categories"].get("cache", {}).get("mb", 0)
        if cache_mb > 1000:  # 1GB
            report["recommendations"].append(
                f"Cache is large ({cache_mb}MB). Consider cleanup_cache()"
            )

        return report

    def save_report(self, report: Optional[Dict] = None) -> Path:
        """
        Save storage report to file.

        Args:
            report: Report to save (generates new if None)

        Returns:
            Path to saved report
        """
        if report is None:
            report = self.generate_storage_report()

        reports_dir = self.base_path / "metadata" / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = reports_dir / f"storage_report_{timestamp}.json"

        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        logger.info(f"Storage report saved: {report_file}")
        return report_file