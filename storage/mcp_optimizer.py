#!/usr/bin/env python3
"""
MCP Storage Optimizer
=====================
Optimizations specific to MCP repository characteristics.
"""

import os
import subprocess
import shutil
from pathlib import Path
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


class MCPStorageOptimizer:
    """Optimize storage for MCP repositories."""

    @staticmethod
    def calculate_mcp_size(repo_path: Path) -> Dict[str, Any]:
        """
        Calculate actual MCP repository size breakdown.

        Args:
            repo_path: Path to repository

        Returns:
            Size breakdown dictionary
        """
        if not repo_path.exists():
            return {}

        stats = {
            "source_code": 0,  # .ts, .js, .py files
            "config": 0,       # .json, .yml, .toml files
            "docs": 0,         # .md files
            "git": 0,          # .git directory
            "other": 0,
            "total": 0
        }

        # File extensions by category
        source_exts = {'.ts', '.js', '.py', '.tsx', '.jsx'}
        config_exts = {'.json', '.yml', '.yaml', '.toml'}
        doc_exts = {'.md', '.txt', '.rst'}

        for item in repo_path.rglob('*'):
            if item.is_file():
                size = item.stat().st_size

                # Skip node_modules if present
                if 'node_modules' in str(item):
                    continue

                if '.git' in str(item):
                    stats["git"] += size
                elif item.suffix in source_exts:
                    stats["source_code"] += size
                elif item.suffix in config_exts:
                    stats["config"] += size
                elif item.suffix in doc_exts:
                    stats["docs"] += size
                else:
                    stats["other"] += size

                stats["total"] += size

        # Convert to KB
        for key in stats:
            stats[f"{key}_kb"] = round(stats[key] / 1024, 2)

        return stats

    @staticmethod
    def optimize_clone(repo_url: str, target_path: Path) -> Dict[str, Any]:
        """
        Ultra-minimal clone for MCPs.

        Args:
            repo_url: GitHub repository URL
            target_path: Where to clone

        Returns:
            Clone statistics
        """
        # Clone with absolute minimum
        cmd = [
            'git', 'clone',
            '--depth', '1',           # Only latest commit
            '--single-branch',        # Only default branch
            '--no-tags',              # Skip tags
            '--filter=blob:none',     # Lazy-load blobs
            repo_url,
            str(target_path)
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)

            # Get size after clone
            size_stats = MCPStorageOptimizer.calculate_mcp_size(target_path)

            return {
                "success": True,
                "size_kb": size_stats.get("total_kb", 0),
                "breakdown": size_stats
            }

        except subprocess.CalledProcessError as e:
            logger.error(f"Clone failed: {e.stderr}")
            return {"success": False, "error": str(e)}

    @staticmethod
    def optimize_existing_repo(repo_path: Path) -> Dict[str, int]:
        """
        Optimize an already cloned repository.

        Args:
            repo_path: Path to repository

        Returns:
            Space saved statistics
        """
        if not repo_path.exists():
            return {"error": "Repository not found"}

        saved = 0

        # 1. Clean git objects
        try:
            subprocess.run(
                ['git', 'gc', '--aggressive', '--prune=now'],
                cwd=repo_path,
                capture_output=True,
                check=True
            )
            saved += 100  # Estimate
        except:
            pass

        # 2. Remove git hooks (not needed for scanning)
        hooks_path = repo_path / '.git' / 'hooks'
        if hooks_path.exists():
            for hook in hooks_path.glob('*'):
                if hook.is_file() and not hook.name.endswith('.sample'):
                    size = hook.stat().st_size
                    hook.unlink()
                    saved += size

        # 3. Remove unnecessary files
        unnecessary = [
            '.github',      # GitHub workflows
            'docs',         # Documentation (keep README)
            'examples',     # Example code
            'tests',        # Test files (unless analyzing)
            '.vscode',      # Editor config
            '.idea',        # IDE files
        ]

        for pattern in unnecessary:
            path = repo_path / pattern
            if path.exists() and path.is_dir():
                size = sum(f.stat().st_size for f in path.rglob('*') if f.is_file())
                shutil.rmtree(path)
                saved += size

        return {
            "saved_bytes": saved,
            "saved_kb": round(saved / 1024, 2)
        }

    @staticmethod
    def estimate_storage_needs(num_mcps: int) -> Dict[str, Any]:
        """
        Estimate storage needs for given number of MCPs.

        Args:
            num_mcps: Number of MCPs

        Returns:
            Storage estimate
        """
        # Based on real MCP characteristics
        size_distribution = {
            "minimal": 50,      # KB - Very simple MCP
            "small": 100,       # KB - Basic MCP
            "medium": 300,      # KB - Average MCP
            "large": 800,       # KB - Complex MCP
            "huge": 2000        # KB - MCP with many tools
        }

        # Assumed distribution
        distribution = {
            "minimal": 0.10,    # 10% are minimal
            "small": 0.40,      # 40% are small
            "medium": 0.35,     # 35% are medium
            "large": 0.13,      # 13% are large
            "huge": 0.02        # 2% are huge
        }

        # Calculate weighted average
        avg_size_kb = sum(
            size_distribution[cat] * distribution[cat]
            for cat in size_distribution
        )

        # Calculate totals
        total_kb = num_mcps * avg_size_kb

        # Add overhead
        cache_overhead = num_mcps * 10  # 10KB per MCP for cache
        metadata_overhead = num_mcps * 2  # 2KB per MCP for metadata

        return {
            "mcps": num_mcps,
            "avg_mcp_kb": round(avg_size_kb, 2),
            "repos_total_kb": round(total_kb, 2),
            "repos_total_mb": round(total_kb / 1024, 2),
            "cache_mb": round(cache_overhead / 1024, 2),
            "metadata_mb": round(metadata_overhead / 1024, 2),
            "total_mb": round((total_kb + cache_overhead + metadata_overhead) / 1024, 2),
            "breakdown": {
                "minimal_mcps": int(num_mcps * distribution["minimal"]),
                "small_mcps": int(num_mcps * distribution["small"]),
                "medium_mcps": int(num_mcps * distribution["medium"]),
                "large_mcps": int(num_mcps * distribution["large"]),
                "huge_mcps": int(num_mcps * distribution["huge"])
            }
        }

    @staticmethod
    def get_cleanup_candidates(base_path: Path, older_than_days: int = 7) -> list:
        """
        Find repositories that can be cleaned up.

        Args:
            base_path: Base repository path
            older_than_days: Age threshold

        Returns:
            List of cleanup candidates
        """
        import time
        from datetime import datetime, timedelta

        candidates = []
        cutoff = time.time() - (older_than_days * 24 * 60 * 60)

        active_path = base_path / "active" / "by-owner"
        if not active_path.exists():
            return candidates

        for owner_dir in active_path.iterdir():
            if owner_dir.is_dir():
                for repo_dir in owner_dir.iterdir():
                    if repo_dir.is_dir():
                        # Check last access time
                        stat = repo_dir.stat()
                        if stat.st_atime < cutoff:
                            size_kb = sum(
                                f.stat().st_size for f in repo_dir.rglob('*')
                                if f.is_file()
                            ) / 1024

                            candidates.append({
                                "path": repo_dir,
                                "owner": owner_dir.name,
                                "name": repo_dir.name,
                                "size_kb": round(size_kb, 2),
                                "last_accessed": datetime.fromtimestamp(stat.st_atime)
                            })

        # Sort by size (largest first)
        candidates.sort(key=lambda x: x["size_kb"], reverse=True)
        return candidates


def print_storage_estimates():
    """Print storage estimates for different scenarios."""
    optimizer = MCPStorageOptimizer()

    print("\n" + "="*60)
    print("MCP Storage Estimates (Realistic)")
    print("="*60)

    scenarios = [10, 50, 100, 500, 1000]

    print("\nStorage requirements by MCP count:")
    print(f"{'MCPs':<10} {'Repos (MB)':<12} {'Cache (MB)':<12} {'Total (MB)':<12}")
    print("-" * 46)

    for num_mcps in scenarios:
        estimate = optimizer.estimate_storage_needs(num_mcps)
        print(f"{num_mcps:<10} {estimate['repos_total_mb']:<12.1f} "
              f"{estimate['cache_mb']:<12.1f} {estimate['total_mb']:<12.1f}")

    print("\n100 MCPs breakdown:")
    estimate_100 = optimizer.estimate_storage_needs(100)
    print(f"  Average MCP size: {estimate_100['avg_mcp_kb']:.0f} KB")
    print(f"  Total repository storage: {estimate_100['repos_total_mb']:.1f} MB")
    print(f"  Cache overhead: {estimate_100['cache_mb']:.1f} MB")
    print(f"  Metadata: {estimate_100['metadata_mb']:.1f} MB")
    print(f"  TOTAL: {estimate_100['total_mb']:.1f} MB")

    print("\nDistribution for 100 MCPs:")
    for size_cat, count in estimate_100['breakdown'].items():
        print(f"  {size_cat}: {count} MCPs")


if __name__ == "__main__":
    print_storage_estimates()