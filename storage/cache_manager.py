#!/usr/bin/env python3
"""
Cache Manager
=============
Manages temporary cache files for scans and reports.
"""

import json
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
import hashlib

logger = logging.getLogger(__name__)


class CacheManager:
    """Manages cache storage for scan results and reports."""

    def __init__(self, base_path: str = "/mnt/prod/repos/cache"):
        """
        Initialize cache manager.

        Args:
            base_path: Base directory for cache storage
        """
        self.base_path = Path(base_path)
        self.sbom_path = self.base_path / "sboms"
        self.report_path = self.base_path / "reports"
        self.rules_path = self.base_path / "rules"

        # Ensure cache directories exist
        self._ensure_directories()

    def _ensure_directories(self) -> None:
        """Create required cache directories."""
        for path in [self.sbom_path, self.report_path, self.rules_path]:
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(0o755)  # Read access for web server

    def store_sbom(self, mcp_id: str, scan_id: str, sbom_data: Dict) -> Path:
        """
        Store SBOM in cache.

        Args:
            mcp_id: MCP identifier
            scan_id: Scan identifier
            sbom_data: SBOM data dictionary

        Returns:
            Path to stored SBOM file
        """
        filename = f"{scan_id}_sbom.json"
        file_path = self.sbom_path / filename

        try:
            with open(file_path, 'w') as f:
                json.dump(sbom_data, f, indent=2)

            # Store metadata
            self._store_metadata(file_path, {
                "mcp_id": mcp_id,
                "scan_id": scan_id,
                "type": "sbom",
                "created_at": datetime.now().isoformat(),
                "size_bytes": file_path.stat().st_size
            })

            logger.info(f"Stored SBOM: {file_path}")
            return file_path

        except Exception as e:
            logger.error(f"Failed to store SBOM: {e}")
            raise

    def get_sbom(self, scan_id: str) -> Optional[Dict]:
        """
        Retrieve SBOM from cache.

        Args:
            scan_id: Scan identifier

        Returns:
            SBOM data or None if not found
        """
        filename = f"{scan_id}_sbom.json"
        file_path = self.sbom_path / filename

        if file_path.exists():
            try:
                with open(file_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to read SBOM: {e}")

        return None

    def store_scan_report(self, mcp_id: str, scan_id: str,
                         report_data: Dict) -> Path:
        """
        Store scan report in cache.

        Args:
            mcp_id: MCP identifier
            scan_id: Scan identifier
            report_data: Report data dictionary

        Returns:
            Path to stored report file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{mcp_id}_{scan_id}_{timestamp}_report.json"
        file_path = self.report_path / filename

        try:
            with open(file_path, 'w') as f:
                json.dump(report_data, f, indent=2)

            # Store metadata
            self._store_metadata(file_path, {
                "mcp_id": mcp_id,
                "scan_id": scan_id,
                "type": "report",
                "created_at": datetime.now().isoformat(),
                "size_bytes": file_path.stat().st_size
            })

            logger.info(f"Stored report: {file_path}")
            return file_path

        except Exception as e:
            logger.error(f"Failed to store report: {e}")
            raise

    def store_detection_rules(self, mcp_id: str, rules: Dict[str, str]) -> Dict[str, Path]:
        """
        Store detection rules in cache.

        Args:
            mcp_id: MCP identifier
            rules: Dictionary of rule format to rule content

        Returns:
            Dictionary of format to file path
        """
        mcp_rules_dir = self.rules_path / mcp_id
        mcp_rules_dir.mkdir(parents=True, exist_ok=True)

        stored_files = {}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        for format_name, rule_content in rules.items():
            # Determine file extension
            extensions = {
                'snort': '.rules',
                'yara': '.yar',
                'sigma': '.yml',
                'zeek': '.zeek',
                'suricata': '.rules',
                'ossec': '.xml'
            }
            ext = extensions.get(format_name, '.txt')

            filename = f"{mcp_id}_{format_name}_{timestamp}{ext}"
            file_path = mcp_rules_dir / filename

            try:
                with open(file_path, 'w') as f:
                    f.write(rule_content)

                stored_files[format_name] = file_path
                logger.info(f"Stored {format_name} rules: {file_path}")

            except Exception as e:
                logger.error(f"Failed to store {format_name} rules: {e}")

        # Store metadata
        if stored_files:
            self._store_metadata(mcp_rules_dir / "metadata.json", {
                "mcp_id": mcp_id,
                "timestamp": timestamp,
                "formats": list(stored_files.keys()),
                "files": {k: str(v) for k, v in stored_files.items()}
            })

        return stored_files

    def get_latest_rules(self, mcp_id: str) -> Optional[Dict[str, Path]]:
        """
        Get latest detection rules for an MCP.

        Args:
            mcp_id: MCP identifier

        Returns:
            Dictionary of format to file path or None
        """
        mcp_rules_dir = self.rules_path / mcp_id
        metadata_file = mcp_rules_dir / "metadata.json"

        if metadata_file.exists():
            try:
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                    return {
                        format_name: Path(file_path)
                        for format_name, file_path in metadata.get("files", {}).items()
                    }
            except Exception as e:
                logger.error(f"Failed to read rules metadata: {e}")

        return None

    def store_temp_file(self, content: bytes, prefix: str = "temp",
                       suffix: str = ".dat") -> Path:
        """
        Store temporary file with auto-cleanup.

        Args:
            content: File content
            prefix: File prefix
            suffix: File suffix

        Returns:
            Path to temporary file
        """
        # Generate unique filename
        content_hash = hashlib.md5(content).hexdigest()[:8]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{prefix}_{timestamp}_{content_hash}{suffix}"

        temp_dir = self.base_path / "temp"
        temp_dir.mkdir(parents=True, exist_ok=True)

        file_path = temp_dir / filename

        try:
            with open(file_path, 'wb') as f:
                f.write(content)

            logger.debug(f"Created temp file: {file_path}")
            return file_path

        except Exception as e:
            logger.error(f"Failed to create temp file: {e}")
            raise

    def cleanup_old_files(self, days: int = 7) -> Dict[str, int]:
        """
        Clean up cache files older than specified days.

        Args:
            days: Age threshold in days

        Returns:
            Cleanup statistics
        """
        cutoff = datetime.now() - timedelta(days=days)
        stats = {
            "sboms": 0,
            "reports": 0,
            "rules": 0,
            "temp": 0,
            "total_bytes": 0
        }

        # Clean each cache directory
        for category, path in [
            ("sboms", self.sbom_path),
            ("reports", self.report_path),
            ("rules", self.rules_path),
            ("temp", self.base_path / "temp")
        ]:
            if path.exists():
                for file_path in path.rglob('*'):
                    if file_path.is_file() and not file_path.name.endswith('.json'):
                        try:
                            file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime)

                            if file_mtime < cutoff:
                                file_size = file_path.stat().st_size
                                file_path.unlink()
                                stats[category] += 1
                                stats["total_bytes"] += file_size

                        except Exception as e:
                            logger.error(f"Error cleaning up {file_path}: {e}")

        stats["total_mb"] = round(stats["total_bytes"] / (1024 * 1024), 2)
        logger.info(f"Cleaned up cache: {stats}")
        return stats

    def _store_metadata(self, file_path: Path, metadata: Dict) -> None:
        """
        Store metadata for a cache file.

        Args:
            file_path: File to store metadata for
            metadata: Metadata dictionary
        """
        try:
            metadata_file = file_path.parent / f".{file_path.name}.meta"
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f)
        except Exception as e:
            logger.debug(f"Failed to store metadata: {e}")

    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Cache statistics dictionary
        """
        stats = {
            "timestamp": datetime.now().isoformat(),
            "categories": {}
        }

        for category, path in [
            ("sboms", self.sbom_path),
            ("reports", self.report_path),
            ("rules", self.rules_path),
            ("temp", self.base_path / "temp")
        ]:
            if path.exists():
                files = list(path.rglob('*'))
                file_count = sum(1 for f in files if f.is_file())
                total_size = sum(f.stat().st_size for f in files if f.is_file())

                stats["categories"][category] = {
                    "file_count": file_count,
                    "total_bytes": total_size,
                    "total_mb": round(total_size / (1024 * 1024), 2)
                }

        return stats

    def get_recent_files(self, category: str = "all",
                        limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get recently cached files.

        Args:
            category: Category to filter (sboms, reports, rules, all)
            limit: Maximum number of files to return

        Returns:
            List of recent file information
        """
        files = []

        # Determine paths to check
        if category == "all":
            paths = [self.sbom_path, self.report_path, self.rules_path]
        else:
            path_map = {
                "sboms": self.sbom_path,
                "reports": self.report_path,
                "rules": self.rules_path
            }
            paths = [path_map.get(category, self.base_path)]

        # Collect file information
        for path in paths:
            if path.exists():
                for file_path in path.rglob('*'):
                    if file_path.is_file() and not file_path.name.startswith('.'):
                        try:
                            stat = file_path.stat()
                            files.append({
                                "path": str(file_path),
                                "name": file_path.name,
                                "category": path.name,
                                "size_bytes": stat.st_size,
                                "size_mb": round(stat.st_size / (1024 * 1024), 2),
                                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
                            })
                        except Exception as e:
                            logger.debug(f"Error getting file info: {e}")

        # Sort by modification time (newest first)
        files.sort(key=lambda x: x["modified"], reverse=True)

        return files[:limit]