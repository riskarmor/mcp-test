#!/usr/bin/env python3
"""
Test Storage System
===================
Test the repository storage implementation.
"""

import sys
import json
from pathlib import Path
from datetime import datetime

# Add to Python path
sys.path.append('/mnt/prod/mcp')

from storage import RepositoryStorage, StorageManager, CacheManager


def test_repository_storage():
    """Test repository storage functionality."""
    print("\n" + "="*60)
    print("Testing Repository Storage")
    print("="*60)

    storage = RepositoryStorage("/mnt/prod/repos")

    # Test 1: Parse GitHub URLs
    print("\n1. Testing GitHub URL parsing:")
    test_urls = [
        "https://github.com/anthropics/claude-mcp",
        "git@github.com:microsoft/vscode-mcp.git",
        "https://github.com/openai/chatgpt-mcp/"
    ]

    for url in test_urls:
        try:
            owner, name = storage.parse_github_url(url)
            print(f"   ✓ {url}")
            print(f"     Owner: {owner}, Name: {name}")
        except Exception as e:
            print(f"   ✗ {url}: {e}")

    # Test 2: Get repository paths
    print("\n2. Testing path generation:")
    test_mcp_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    test_url = "https://github.com/anthropics/claude-mcp"

    repo_path, id_path = storage.get_repo_paths(test_mcp_id, test_url)
    print(f"   Repository path: {repo_path}")
    print(f"   ID symlink path: {id_path}")

    # Test 3: Repository info
    print("\n3. Testing repository info:")
    info = storage.get_repository_info(test_mcp_id, test_url)
    print(f"   Repository exists: {info['exists']}")
    print(f"   Path: {info['path']}")

    # Test 4: List repositories
    print("\n4. Testing repository listing:")
    repos = storage.list_repositories("active")
    print(f"   Active repositories: {len(repos)}")

    # Test 5: Manifest
    print("\n5. Testing manifest:")
    print(f"   Manifest file: {storage.manifest_file}")
    print(f"   Total repos: {storage.manifest['statistics']['total_repos']}")
    print(f"   Active repos: {storage.manifest['statistics']['active_repos']}")


def test_storage_manager():
    """Test storage manager functionality."""
    print("\n" + "="*60)
    print("Testing Storage Manager")
    print("="*60)

    manager = StorageManager("/mnt/prod/repos")

    # Test 1: Storage usage
    print("\n1. Testing storage usage calculation:")
    usage = manager.get_storage_usage()

    print(f"   Total usage: {usage['total']['mb']:.2f} MB")
    print(f"   Disk usage: {usage['disk']['percent_used']:.1f}%")
    print(f"   Free space: {usage['disk']['free_gb']:.2f} GB")

    print("\n   Category breakdown:")
    for category, data in usage['categories'].items():
        print(f"   - {category}: {data['mb']:.2f} MB ({data['percentage']:.1f}%)")

    # Test 2: Disk space check
    print("\n2. Testing disk space check:")
    status = manager.check_disk_space()
    print(f"   Status: {status['status']}")
    print(f"   Percent used: {status['percent_used']:.1f}%")
    print(f"   Free GB: {status['free_gb']:.2f}")

    if status['alerts']:
        print("   Alerts:")
        for alert in status['alerts']:
            print(f"   - [{alert['level']}] {alert['message']}")

    # Test 3: Repository sizes
    print("\n3. Testing repository size calculation:")
    largest_repos = manager.get_repository_sizes(5)
    if largest_repos:
        print("   Largest repositories:")
        for repo in largest_repos:
            print(f"   - {repo['owner']}/{repo['name']}: {repo['size_mb']:.2f} MB")
    else:
        print("   No repositories found")

    # Test 4: Generate report
    print("\n4. Testing report generation:")
    report = manager.generate_storage_report()
    print(f"   Report timestamp: {report['timestamp']}")
    print(f"   Recommendations: {len(report['recommendations'])}")

    for rec in report['recommendations']:
        print(f"   - {rec}")


def test_cache_manager():
    """Test cache manager functionality."""
    print("\n" + "="*60)
    print("Testing Cache Manager")
    print("="*60)

    cache = CacheManager("/mnt/prod/repos/cache")

    # Test 1: Store and retrieve SBOM
    print("\n1. Testing SBOM storage:")
    test_mcp_id = "test-mcp-123"
    test_scan_id = "scan-456"
    test_sbom = {
        "bomFormat": "CycloneDX",
        "version": 1,
        "components": [
            {"name": "test-package", "version": "1.0.0"}
        ]
    }

    try:
        sbom_path = cache.store_sbom(test_mcp_id, test_scan_id, test_sbom)
        print(f"   ✓ Stored SBOM: {sbom_path}")

        retrieved_sbom = cache.get_sbom(test_scan_id)
        if retrieved_sbom:
            print(f"   ✓ Retrieved SBOM successfully")
        else:
            print(f"   ✗ Failed to retrieve SBOM")
    except Exception as e:
        print(f"   ✗ SBOM storage error: {e}")

    # Test 2: Store detection rules
    print("\n2. Testing detection rule storage:")
    test_rules = {
        "snort": "alert tcp any any -> any any (msg:'Test rule'; sid:1;)",
        "yara": "rule test_rule { condition: true }",
        "sigma": "title: Test Rule\ndetection:\n  selection:\n    EventID: 1"
    }

    try:
        rule_files = cache.store_detection_rules(test_mcp_id, test_rules)
        print(f"   ✓ Stored {len(rule_files)} rule formats")

        latest_rules = cache.get_latest_rules(test_mcp_id)
        if latest_rules:
            print(f"   ✓ Retrieved latest rules: {list(latest_rules.keys())}")
    except Exception as e:
        print(f"   ✗ Rule storage error: {e}")

    # Test 3: Cache statistics
    print("\n3. Testing cache statistics:")
    stats = cache.get_cache_stats()

    print("   Cache categories:")
    for category, data in stats['categories'].items():
        print(f"   - {category}: {data['file_count']} files, {data['total_mb']:.2f} MB")

    # Test 4: Recent files
    print("\n4. Testing recent files:")
    recent = cache.get_recent_files(limit=5)
    if recent:
        print(f"   Recent files ({len(recent)}):")
        for file_info in recent:
            print(f"   - {file_info['name']} ({file_info['size_mb']:.2f} MB)")
    else:
        print("   No recent files")


def test_directory_structure():
    """Test directory structure creation."""
    print("\n" + "="*60)
    print("Testing Directory Structure")
    print("="*60)

    base_path = Path("/mnt/prod/repos")

    required_dirs = [
        "active/by-owner",
        "active/by-id",
        "archive",
        "cache/sboms",
        "cache/reports",
        "cache/rules",
        "metadata"
    ]

    print("\nChecking required directories:")
    all_exist = True

    for dir_path in required_dirs:
        full_path = base_path / dir_path
        exists = full_path.exists()
        symbol = "✓" if exists else "✗"
        print(f"   {symbol} {dir_path}: {'exists' if exists else 'missing'}")

        if not exists:
            all_exist = False

    if all_exist:
        print("\n✓ All required directories exist")
    else:
        print("\n✗ Some directories are missing")

    # Check permissions
    print("\nChecking directory permissions:")
    for dir_path in ["active", "archive", "cache"]:
        full_path = base_path / dir_path
        if full_path.exists():
            mode = oct(full_path.stat().st_mode)[-3:]
            print(f"   {dir_path}: {mode}")


def main():
    """Run all tests."""
    print("\n" + "="*60)
    print("MCP Storage System Test Suite")
    print("="*60)

    tests = [
        ("Directory Structure", test_directory_structure),
        ("Repository Storage", test_repository_storage),
        ("Storage Manager", test_storage_manager),
        ("Cache Manager", test_cache_manager)
    ]

    results = []

    for test_name, test_func in tests:
        try:
            test_func()
            results.append((test_name, "PASSED"))
        except Exception as e:
            print(f"\n✗ Error in {test_name}: {e}")
            results.append((test_name, "FAILED"))

    # Summary
    print("\n" + "="*60)
    print("Test Summary")
    print("="*60)

    for test_name, status in results:
        symbol = "✓" if status == "PASSED" else "✗"
        print(f"   {symbol} {test_name}: {status}")

    passed = sum(1 for _, status in results if status == "PASSED")
    total = len(results)
    print(f"\n   Total: {passed}/{total} tests passed")


if __name__ == "__main__":
    main()