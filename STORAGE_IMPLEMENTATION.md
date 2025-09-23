# Storage System Implementation

## Overview

The MCP Repository Storage System has been fully implemented with the following components:

## Directory Structure

```
/mnt/prod/repos/
├── active/                 # Currently tracked MCPs
│   ├── by-owner/          # Organized by GitHub owner
│   └── by-id/             # UUID symlinks for fast lookup
├── archive/               # Removed/deprecated MCPs
├── cache/                 # Temporary scan outputs
│   ├── sboms/            # Generated SBOMs
│   ├── reports/          # Scan reports
│   └── rules/            # Detection rules
└── metadata/             # Repository metadata
    ├── manifest.json     # Repository index
    └── reports/          # Storage reports
```

## Implemented Modules

### 1. **RepositoryStorage** (`storage/repository_storage.py`)
- Clone and update Git repositories
- Parse GitHub URLs
- Manage repository paths and symlinks
- Archive old repositories
- Maintain manifest of all repositories

**Key Methods:**
- `clone_repository()` - Clone with shallow depth
- `update_repository()` - Pull latest changes
- `archive_repository()` - Move to archive
- `get_repository_info()` - Get repo details

### 2. **StorageManager** (`storage/storage_manager.py`)
- Monitor disk usage
- Cleanup old archives and cache
- Generate storage reports
- Emergency cleanup when disk critical

**Key Methods:**
- `get_storage_usage()` - Calculate usage by category
- `check_disk_space()` - Alert on thresholds
- `cleanup_archives()` - Remove old archives
- `emergency_cleanup()` - Free space urgently

### 3. **CacheManager** (`storage/cache_manager.py`)
- Store SBOMs before database insertion
- Cache detection rules
- Manage temporary scan reports
- Auto-cleanup old cache files

**Key Methods:**
- `store_sbom()` - Cache SBOM JSON
- `store_detection_rules()` - Save rule files
- `cleanup_old_files()` - Remove expired cache

### 4. **StorageMonitor** (`storage/monitor.py`)
- Continuous monitoring daemon
- Generate daily reports
- Trigger cleanup on thresholds
- Log alerts to database

**Key Methods:**
- `check_and_alert()` - Monitor and alert
- `generate_daily_report()` - Daily statistics
- `run_continuous()` - Daemon mode

## Usage Examples

### Clone a Repository
```python
from storage import RepositoryStorage

storage = RepositoryStorage()
repo_path = storage.clone_repository(
    mcp_id="abc-123",
    repo_url="https://github.com/owner/repo",
    branch="main",
    depth=100  # Shallow clone
)
```

### Check Storage Usage
```python
from storage import StorageManager

manager = StorageManager()
usage = manager.get_storage_usage()
print(f"Disk used: {usage['disk']['percent_used']:.1f}%")
```

### Store Scan Results
```python
from storage import CacheManager

cache = CacheManager()
sbom_path = cache.store_sbom(mcp_id, scan_id, sbom_data)
rules = cache.store_detection_rules(mcp_id, rule_dict)
```

### Monitor Storage (Daemon)
```bash
# Run continuous monitoring
python storage/monitor.py --monitor --interval 3600

# Generate report
python storage/monitor.py --report

# Cleanup
python storage/monitor.py --cleanup
```

## Configuration

### Thresholds
- **Warning**: 80% disk usage
- **Critical**: 90% disk usage
- **Archive retention**: 30 days
- **Cache retention**: 7 days

### Permissions
- `/mnt/prod/repos/active`: 750
- `/mnt/prod/repos/archive`: 750
- `/mnt/prod/repos/cache`: 755 (web server read)

## Testing

Run tests with:
```bash
source /mnt/prod/venv/bin/activate
python test_storage.py
```

Run demo with:
```bash
python demo_storage.py --all
```

## Integration with Daily Workflow

The storage system integrates with the daily scanning workflow:

1. **Version Check**: No storage needed
2. **Full Scan**: Clone/update repository
3. **SBOM Generation**: Store in cache, then database
4. **Security Scanning**:
   - Semgrep: Static code analysis
   - TruffleHog: Secret detection
   - OSV: Vulnerability scanning
5. **Score Calculation**:
   - Hygiene Score (25%): GitHub repository health
   - Tools Score (35%): Semgrep + TruffleHog findings
   - Vulnerability Score (40%): OSV with time decay
   - Final FICO Score: Weighted aggregate (300-850)
6. **Detection Rules**: Generate and cache
7. **Cleanup**: Remove old archives and cache

## Storage Estimates (Realistic)

MCPs are typically very small (just a few TypeScript/JavaScript files):
- **Minimal MCP**: 50 KB (simple single-tool MCP)
- **Average MCP**: 300 KB (typical MCP with few tools)
- **Large MCP**: 800 KB (complex multi-tool MCP)

For 100 MCPs:
- **Active repos**: ~30 MB (average 300KB per MCP with minimal clone)
- **Cache**: ~1 MB (SBOMs, reports, rules)
- **Archive**: ~5 MB (few deprecated MCPs)
- **Metadata**: ~0.2 MB (manifests and indexes)
- **Total**: **~30 MB for 100 MCPs**

Storage by scale:
- 10 MCPs: ~3 MB
- 50 MCPs: ~15 MB
- 100 MCPs: ~30 MB
- 500 MCPs: ~150 MB
- 1000 MCPs: ~300 MB

## Next Steps

1. Integrate with scanning pipeline
2. Set up cron job for monitoring
3. Configure database tables for metrics
4. Implement S3 backup (optional)
5. Add compression for archives