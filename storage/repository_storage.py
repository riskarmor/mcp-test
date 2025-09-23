#!/usr/bin/env python3
"""
Repository Storage Manager
==========================
Handles cloning, updating, and organizing MCP repositories on disk.
"""

import os
import json
import subprocess
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, Tuple, Dict, Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class RepositoryStorage:
    """Manages repository storage and organization."""

    def __init__(self, base_path: str = "/mnt/prod/repos"):
        """
        Initialize repository storage manager.

        Args:
            base_path: Base directory for repository storage
        """
        self.base_path = Path(base_path)
        self.active_path = self.base_path / "active"
        self.archive_path = self.base_path / "archive"
        self.cache_path = self.base_path / "cache"
        self.metadata_path = self.base_path / "metadata"

        # Create required directories
        self._ensure_directories()

        # Load or create manifest
        self.manifest_file = self.metadata_path / "manifest.json"
        self.manifest = self._load_manifest()

    def _ensure_directories(self) -> None:
        """Create all required storage directories."""
        directories = [
            self.active_path / "by-owner",
            self.active_path / "by-id",
            self.archive_path,
            self.cache_path / "sboms",
            self.cache_path / "reports",
            self.cache_path / "rules",
            self.metadata_path
        ]

        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            # Set permissions (750 for most, 755 for cache)
            if 'cache' in str(directory):
                directory.chmod(0o755)
            else:
                directory.chmod(0o750)

    def _load_manifest(self) -> Dict[str, Any]:
        """Load or create repository manifest."""
        if self.manifest_file.exists():
            try:
                with open(self.manifest_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                logger.warning("Corrupt manifest file, creating new one")

        # Create new manifest
        manifest = {
            "version": "1.0",
            "created_at": datetime.now().isoformat(),
            "repositories": {},
            "statistics": {
                "total_repos": 0,
                "active_repos": 0,
                "archived_repos": 0,
                "total_size_mb": 0
            }
        }
        self._save_manifest(manifest)
        return manifest

    def _save_manifest(self, manifest: Optional[Dict] = None) -> None:
        """Save repository manifest to disk."""
        if manifest is None:
            manifest = self.manifest

        with open(self.manifest_file, 'w') as f:
            json.dump(manifest, f, indent=2, default=str)

    def parse_github_url(self, repo_url: str) -> Tuple[str, str]:
        """
        Parse GitHub URL to extract owner and repository name.

        Args:
            repo_url: GitHub repository URL

        Returns:
            Tuple of (owner, repo_name)
        """
        # Handle different GitHub URL formats
        repo_url = repo_url.rstrip('/')

        if 'github.com' in repo_url:
            # https://github.com/owner/repo or git@github.com:owner/repo
            parts = repo_url.replace('git@github.com:', '').replace('https://github.com/', '')
            parts = parts.replace('.git', '').split('/')

            if len(parts) >= 2:
                return parts[0], parts[1]

        raise ValueError(f"Invalid GitHub URL: {repo_url}")

    def get_repo_paths(self, mcp_id: str, repo_url: str) -> Tuple[Path, Path]:
        """
        Get storage paths for a repository.

        Args:
            mcp_id: Unique MCP identifier
            repo_url: GitHub repository URL

        Returns:
            Tuple of (repo_path, id_symlink_path)
        """
        owner, name = self.parse_github_url(repo_url)

        # Main storage path organized by owner
        repo_path = self.active_path / "by-owner" / owner / name

        # UUID symlink for fast lookup
        id_path = self.active_path / "by-id" / mcp_id

        return repo_path, id_path

    def clone_repository(self, mcp_id: str, repo_url: str,
                        branch: str = "main", depth: int = 1) -> Path:
        """
        Clone a new repository.

        Args:
            mcp_id: Unique MCP identifier
            repo_url: GitHub repository URL
            branch: Branch to clone
            depth: Clone depth (default 1 - minimal shallow clone)

        Returns:
            Path to cloned repository
        """
        repo_path, id_path = self.get_repo_paths(mcp_id, repo_url)

        if repo_path.exists():
            logger.info(f"Repository already exists: {repo_path}")
            return repo_path

        # Ensure parent directory exists
        repo_path.parent.mkdir(parents=True, exist_ok=True)

        # Clone with limited depth for efficiency
        cmd = [
            'git', 'clone',
            '--depth', str(depth),
            '--single-branch',
            '--branch', branch,
            repo_url,
            str(repo_path)
        ]

        try:
            logger.info(f"Cloning repository: {repo_url}")
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)

            # Create UUID symlink
            if not id_path.exists():
                id_path.symlink_to(repo_path)

            # Update manifest
            owner, name = self.parse_github_url(repo_url)
            self.manifest["repositories"][mcp_id] = {
                "id": mcp_id,
                "url": repo_url,
                "owner": owner,
                "name": name,
                "path": str(repo_path),
                "cloned_at": datetime.now().isoformat(),
                "last_updated": datetime.now().isoformat(),
                "branch": branch,
                "status": "active"
            }
            self.manifest["statistics"]["total_repos"] += 1
            self.manifest["statistics"]["active_repos"] += 1
            self._save_manifest()

            logger.info(f"Successfully cloned: {repo_path}")
            return repo_path

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to clone repository: {e.stderr}")
            raise

    def update_repository(self, mcp_id: str, repo_url: str) -> Tuple[bool, Optional[str]]:
        """
        Update an existing repository.

        Args:
            mcp_id: Unique MCP identifier
            repo_url: GitHub repository URL

        Returns:
            Tuple of (updated, commit_range)
        """
        repo_path, _ = self.get_repo_paths(mcp_id, repo_url)

        if not repo_path.exists():
            logger.warning(f"Repository not found, cloning: {repo_path}")
            self.clone_repository(mcp_id, repo_url)
            return True, None

        try:
            # Get current commit
            old_commit = subprocess.run(
                ['git', 'rev-parse', 'HEAD'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=True
            ).stdout.strip()

            # Fetch latest changes (minimal depth)
            subprocess.run(
                ['git', 'fetch', '--depth', '1'],
                cwd=repo_path,
                capture_output=True,
                check=True
            )

            # Get remote commit
            remote_commit = subprocess.run(
                ['git', 'rev-parse', 'origin/HEAD'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=True
            ).stdout.strip()

            if old_commit == remote_commit:
                logger.info(f"Repository up to date: {repo_path}")
                return False, None

            # Pull changes
            subprocess.run(
                ['git', 'pull', '--ff-only'],
                cwd=repo_path,
                capture_output=True,
                check=True
            )

            # Update manifest
            if mcp_id in self.manifest["repositories"]:
                self.manifest["repositories"][mcp_id]["last_updated"] = datetime.now().isoformat()
                self._save_manifest()

            commit_range = f"{old_commit[:8]}..{remote_commit[:8]}"
            logger.info(f"Updated repository: {repo_path} ({commit_range})")
            return True, commit_range

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to update repository: {e}")
            raise

    def get_repository_info(self, mcp_id: str, repo_url: str) -> Dict[str, Any]:
        """
        Get information about a repository.

        Args:
            mcp_id: Unique MCP identifier
            repo_url: GitHub repository URL

        Returns:
            Repository information dictionary
        """
        repo_path, id_path = self.get_repo_paths(mcp_id, repo_url)

        info = {
            "id": mcp_id,
            "url": repo_url,
            "exists": repo_path.exists(),
            "path": str(repo_path) if repo_path.exists() else None,
            "symlink_exists": id_path.exists()
        }

        if repo_path.exists():
            try:
                # Get current commit
                commit = subprocess.run(
                    ['git', 'rev-parse', 'HEAD'],
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    check=True
                ).stdout.strip()

                # Get branch
                branch = subprocess.run(
                    ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    check=True
                ).stdout.strip()

                # Get last commit date
                commit_date = subprocess.run(
                    ['git', 'log', '-1', '--format=%cd', '--date=iso'],
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    check=True
                ).stdout.strip()

                # Calculate size
                size_bytes = sum(f.stat().st_size for f in repo_path.rglob('*') if f.is_file())

                info.update({
                    "current_commit": commit,
                    "branch": branch,
                    "last_commit_date": commit_date,
                    "size_mb": round(size_bytes / (1024 * 1024), 2)
                })

            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to get repository info: {e}")

        return info

    def archive_repository(self, mcp_id: str, repo_url: str,
                          reason: str = "deprecated") -> bool:
        """
        Archive a repository.

        Args:
            mcp_id: Unique MCP identifier
            repo_url: GitHub repository URL
            reason: Reason for archival

        Returns:
            Success status
        """
        repo_path, id_path = self.get_repo_paths(mcp_id, repo_url)

        if not repo_path.exists():
            logger.warning(f"Repository not found for archival: {repo_path}")
            return False

        # Create archive directory for current month
        archive_month = datetime.now().strftime("%Y-%m")
        archive_dir = self.archive_path / archive_month
        archive_dir.mkdir(parents=True, exist_ok=True)

        # Move repository
        owner, name = self.parse_github_url(repo_url)
        archive_path = archive_dir / f"{owner}_{name}"

        try:
            import shutil
            shutil.move(str(repo_path), str(archive_path))

            # Remove symlink
            if id_path.exists():
                id_path.unlink()

            # Update manifest
            if mcp_id in self.manifest["repositories"]:
                self.manifest["repositories"][mcp_id]["status"] = "archived"
                self.manifest["repositories"][mcp_id]["archived_at"] = datetime.now().isoformat()
                self.manifest["repositories"][mcp_id]["archive_reason"] = reason
                self.manifest["repositories"][mcp_id]["archive_path"] = str(archive_path)
                self.manifest["statistics"]["active_repos"] -= 1
                self.manifest["statistics"]["archived_repos"] += 1
                self._save_manifest()

            logger.info(f"Archived repository: {repo_path} -> {archive_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to archive repository: {e}")
            return False

    def list_repositories(self, status: str = "active") -> Dict[str, Any]:
        """
        List all repositories.

        Args:
            status: Filter by status (active, archived, all)

        Returns:
            Dictionary of repositories
        """
        if status == "all":
            return self.manifest["repositories"]

        return {
            mcp_id: repo
            for mcp_id, repo in self.manifest["repositories"].items()
            if repo.get("status") == status
        }