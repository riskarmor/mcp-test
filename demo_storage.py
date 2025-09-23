#!/usr/bin/env python3
"""
Demo Storage System
===================
Demonstrate the storage system with a real MCP repository.
"""

import sys
import json
from pathlib import Path

# Add to Python path
sys.path.append('/mnt/prod/mcp')

from storage import RepositoryStorage, StorageManager, CacheManager


def demo_clone_repository():
    """Demo cloning a real MCP repository."""
    print("\n" + "="*60)
    print("Storage System Demo - Clone Real MCP")
    print("="*60)

    storage = RepositoryStorage("/mnt/prod/repos")

    # Example MCP repository (use a small one for demo)
    mcp_id = "demo-mcp-001"
    repo_url = "https://github.com/modelcontextprotocol/servers"  # Official MCP servers repo

    print(f"\nCloning MCP repository:")
    print(f"  ID: {mcp_id}")
    print(f"  URL: {repo_url}")

    try:
        # Clone the repository
        print("\nCloning repository (this may take a moment)...")
        repo_path = storage.clone_repository(mcp_id, repo_url, branch="main", depth=10)
        print(f"✓ Successfully cloned to: {repo_path}")

        # Get repository info
        print("\nRepository information:")
        info = storage.get_repository_info(mcp_id, repo_url)
        print(f"  Path: {info['path']}")
        print(f"  Current commit: {info.get('current_commit', 'N/A')[:8]}")
        print(f"  Branch: {info.get('branch', 'N/A')}")
        print(f"  Size: {info.get('size_mb', 0):.2f} MB")
        print(f"  Last commit: {info.get('last_commit_date', 'N/A')}")

        # Check storage usage
        manager = StorageManager("/mnt/prod/repos")
        usage = manager.get_storage_usage()
        print(f"\nStorage usage after clone:")
        print(f"  Total: {usage['total']['mb']:.2f} MB")
        print(f"  Active repos: {usage['categories']['active']['mb']:.2f} MB")

        # Create and store an SBOM (simulated)
        print("\nStoring scan results in cache:")
        cache = CacheManager("/mnt/prod/repos/cache")

        # Store simulated SBOM
        scan_id = "scan-demo-001"
        sbom_data = {
            "bomFormat": "CycloneDX",
            "version": 1,
            "serialNumber": f"urn:uuid:{mcp_id}",
            "metadata": {
                "timestamp": "2025-01-22T00:00:00Z",
                "component": {
                    "name": "mcp-servers",
                    "version": "1.0.0"
                }
            },
            "components": []
        }

        sbom_path = cache.store_sbom(mcp_id, scan_id, sbom_data)
        print(f"  ✓ SBOM stored: {sbom_path.name}")

        # Store detection rules
        rules = {
            "snort": f"alert tcp any any -> any any (msg:'MCP {mcp_id} detected'; sid:1001;)",
            "yara": f"rule mcp_{mcp_id.replace('-', '_')} {{ strings: $mcp = \"modelcontextprotocol\" condition: $mcp }}"
        }
        rule_files = cache.store_detection_rules(mcp_id, rules)
        print(f"  ✓ Detection rules stored: {len(rule_files)} formats")

        # List all repositories
        print("\nCurrent repositories in storage:")
        repos = storage.list_repositories("active")
        for repo_id, repo_info in repos.items():
            print(f"  - {repo_info['owner']}/{repo_info['name']} (ID: {repo_id})")

        return True

    except Exception as e:
        print(f"✗ Error: {e}")
        return False


def demo_update_repository():
    """Demo updating an existing repository."""
    print("\n" + "="*60)
    print("Storage System Demo - Update Repository")
    print("="*60)

    storage = RepositoryStorage("/mnt/prod/repos")

    mcp_id = "demo-mcp-001"
    repo_url = "https://github.com/modelcontextprotocol/servers"

    print(f"\nChecking for updates:")
    print(f"  Repository: {repo_url}")

    try:
        # Check if repo exists
        info = storage.get_repository_info(mcp_id, repo_url)

        if not info['exists']:
            print("  Repository not found. Clone it first.")
            return False

        print(f"  Current commit: {info.get('current_commit', 'N/A')[:8]}")

        # Try to update
        updated, commit_range = storage.update_repository(mcp_id, repo_url)

        if updated:
            print(f"  ✓ Repository updated: {commit_range}")
        else:
            print("  ✓ Repository is already up to date")

        return True

    except Exception as e:
        print(f"✗ Error: {e}")
        return False


def demo_storage_report():
    """Generate a comprehensive storage report."""
    print("\n" + "="*60)
    print("Storage System Report")
    print("="*60)

    manager = StorageManager("/mnt/prod/repos")
    cache = CacheManager("/mnt/prod/repos/cache")

    # Get storage usage
    usage = manager.get_storage_usage()

    print("\nDisk Usage:")
    print(f"  Total disk: {usage['disk']['total_gb']:.2f} GB")
    print(f"  Used: {usage['disk']['used_gb']:.2f} GB ({usage['disk']['percent_used']:.1f}%)")
    print(f"  Free: {usage['disk']['free_gb']:.2f} GB")

    print("\nStorage Categories:")
    for category, data in usage['categories'].items():
        if data['mb'] > 0:
            print(f"  {category:10s}: {data['mb']:8.2f} MB ({data['percentage']:5.1f}%)")

    # Get cache statistics
    cache_stats = cache.get_cache_stats()

    print("\nCache Statistics:")
    for category, data in cache_stats['categories'].items():
        if data['file_count'] > 0:
            print(f"  {category:10s}: {data['file_count']:3d} files, {data['total_mb']:8.2f} MB")

    # Get largest repositories
    largest = manager.get_repository_sizes(5)
    if largest:
        print("\nLargest Repositories:")
        for i, repo in enumerate(largest, 1):
            print(f"  {i}. {repo['owner']}/{repo['name']}: {repo['size_mb']:.2f} MB")

    # Get recent cache files
    recent = cache.get_recent_files(limit=5)
    if recent:
        print("\nRecent Cache Files:")
        for file_info in recent[:5]:
            print(f"  - {file_info['name']} ({file_info['category']})")

    # Save report
    report = manager.generate_storage_report()
    report_path = manager.save_report(report)
    print(f"\nFull report saved to: {report_path}")


def main():
    """Run storage system demo."""
    import argparse

    parser = argparse.ArgumentParser(description="Storage System Demo")
    parser.add_argument("--clone", action="store_true", help="Demo cloning a repository")
    parser.add_argument("--update", action="store_true", help="Demo updating a repository")
    parser.add_argument("--report", action="store_true", help="Generate storage report")
    parser.add_argument("--all", action="store_true", help="Run all demos")

    args = parser.parse_args()

    if args.all or args.clone:
        success = demo_clone_repository()
        if not success and not args.all:
            return

    if args.all or args.update:
        demo_update_repository()

    if args.all or args.report:
        demo_storage_report()

    if not any([args.clone, args.update, args.report, args.all]):
        print("Usage: python demo_storage.py [--clone] [--update] [--report] [--all]")
        print("\nRun with --all to see full demo")


if __name__ == "__main__":
    main()