# OSV Scanner Component

## Component Overview

The OSV Scanner Component is a standalone tool for vulnerability detection that consumes Software Bill of Materials (SBOM) files and queries the OSV (Open Source Vulnerabilities) database to identify known security vulnerabilities with detailed metadata.

### Purpose
Scan SBOM files (CycloneDX or SPDX format) for known vulnerabilities using the OSV database, enriching findings with CVSS scores, age analysis, KEV status, and exploit availability information.

### Position in System Architecture
```
┌─────────────────────────────────────────────────┐
│          MCP Security Analysis System           │
├─────────────────────────────────────────────────┤
│                                                  │
│       Vulnerability Scoring Pipeline (30%)      │
│       ┌──────────────────────────────┐         │
│       │                              │         │
│       │     ┌─────────────┐         │         │
│       │     │    SBOM     │         │         │
│       │     │  Generator  │         │         │
│       │     └─────────────┘         │         │
│       │            │                 │         │
│       │            ▼                 │         │
│       │     ┌─────────────┐         │         │
│       │     │     OSV     │         │         │
│       │     │   Scanner   │ ◄── THIS          │
│       │     └─────────────┘         │         │
│       │            │                 │         │
│       │            ▼                 │         │
│       │     ┌─────────────┐         │         │
│       │     │ Time-Decay  │         │         │
│       │     │   Scorer    │         │         │
│       │     └─────────────┘         │         │
│       │                              │         │
│       └──────────────────────────────┘         │
└─────────────────────────────────────────────────┘
```

## Files Created

### 1. Core Scanner
- **File**: `/mnt/prod/mcp/osv_scanner.py` (500+ lines)
- **Purpose**: OSV vulnerability scanning with KEV integration
- **Key Features**:
  - SBOM consumption (CycloneDX/SPDX)
  - OSV database queries
  - CISA KEV catalog integration
  - Vulnerability age tracking
  - Exploit availability detection
  - Result caching (24-hour TTL)
  - Offline mode support

### 2. Key Classes

#### `OSVScanner`
Main scanner class with vulnerability detection:
```python
class OSVScanner:
    def __init__(self,
                 offline_mode: bool = False,
                 local_db_path: Optional[Path] = None,
                 check_kev: bool = True,
                 min_cvss: float = 0.0,
                 cache_dir: Optional[Path] = None,
                 cache_ttl_hours: int = 24)
```

#### `VulnerabilityFinding`
Individual vulnerability details:
```python
@dataclass
class VulnerabilityFinding:
    package_name: str
    current_version: str
    fixed_version: Optional[str]
    cve_id: str
    cvss_score: float
    severity: VulnerabilitySeverity
    published_date: datetime
    age_days: int
    is_kev: bool
    exploit_available: bool
```

#### `OSVScanResult`
Complete scan results:
```python
@dataclass
class OSVScanResult:
    sbom_path: str
    scan_date: datetime
    vulnerabilities: List[VulnerabilityFinding]
    total_packages: int
    vulnerable_packages: int
    severity_counts: Dict[str, int]
```

## Installation Guide

### Installing OSV Scanner

#### Option 1: Using Go (Recommended)
```bash
# Install via Go
go install github.com/google/osv-scanner/cmd/osv-scanner@latest

# Verify installation
osv-scanner --version
```

#### Option 2: Download Binary
```bash
# Download latest release from GitHub
# https://github.com/google/osv-scanner/releases

# Example for Linux x64
wget https://github.com/google/osv-scanner/releases/download/v1.4.3/osv-scanner_1.4.3_linux_amd64
chmod +x osv-scanner_1.4.3_linux_amd64
sudo mv osv-scanner_1.4.3_linux_amd64 /usr/local/bin/osv-scanner

# Verify
osv-scanner --version
```

#### Option 3: Using Docker
```bash
# Run with Docker
docker run --rm -v $(pwd):/src ghcr.io/google/osv-scanner:latest --sbom /src/sbom.json
```

## OSV Database Overview

### What is OSV?

OSV (Open Source Vulnerabilities) is a distributed vulnerability database that aggregates vulnerability information from multiple sources:

- **Coverage**: Most open source ecosystems
- **Sources**: GitHub Security Advisories, PyPA, RustSec, Go Vulnerability Database, npm audit, and more
- **Format**: Standardized OSV schema
- **API**: Free, rate-limited API access
- **Updates**: Real-time vulnerability updates

### Supported Ecosystems

| Ecosystem | Package Types | Database Source |
|-----------|--------------|-----------------|
| **npm** | JavaScript/TypeScript | GitHub Advisory Database |
| **PyPI** | Python packages | Python Packaging Advisory |
| **Go** | Go modules | Go Vulnerability Database |
| **Maven** | Java packages | GitHub Advisory Database |
| **RubyGems** | Ruby packages | GitHub Advisory Database |
| **Cargo** | Rust packages | RustSec Advisory Database |
| **Packagist** | PHP packages | GitHub Advisory Database |
| **NuGet** | .NET packages | GitHub Advisory Database |
| **Pub** | Dart packages | GitHub Advisory Database |
| **Hex** | Elixir packages | GitHub Advisory Database |
| **Linux** | OS packages | Ubuntu, Debian, Alpine, Rocky Linux |

## SBOM Input Requirements

### Supported Formats

#### CycloneDX (Recommended)
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {
      "type": "library",
      "name": "express",
      "version": "4.17.1",
      "purl": "pkg:npm/express@4.17.1"
    }
  ]
}
```

#### SPDX
```json
{
  "spdxVersion": "SPDX-2.3",
  "packages": [
    {
      "name": "express",
      "versionInfo": "4.17.1",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:npm/express@4.17.1"
        }
      ]
    }
  ]
}
```

### Package URL (PURL) Format

OSV Scanner relies on Package URLs for accurate matching:
```
pkg:ecosystem/namespace/name@version
```

Examples:
- `pkg:npm/express@4.17.1`
- `pkg:pypi/django@3.2.0`
- `pkg:golang/github.com/gin-gonic/gin@v1.7.0`

## Usage Examples

### Basic Vulnerability Scanning

```python
from osv_scanner import OSVScanner
import asyncio

async def scan_for_vulnerabilities():
    # Initialize scanner
    scanner = OSVScanner(
        check_kev=True,  # Check CISA KEV catalog
        min_cvss=4.0     # Only report medium+ severity
    )

    # Scan SBOM file
    result = await scanner.scan_sbom("sbom.json")

    # Process results
    print(f"Found {len(result.vulnerabilities)} vulnerabilities")
    for vuln in result.vulnerabilities:
        if vuln.is_kev:
            print(f"🚨 CRITICAL KEV: {vuln.cve_id} in {vuln.package_name}")

asyncio.run(scan_for_vulnerabilities())
```

### Offline Mode Scanning

```python
# For air-gapped environments
scanner = OSVScanner(
    offline_mode=True,
    local_db_path=Path("/opt/osv/database")
)

# Update database when connected
await scanner.update_local_database()

# Scan without network access
result = await scanner.scan_sbom("sbom.json")
```

### Filtering and Analysis

```python
# Advanced filtering
scanner = OSVScanner(
    min_cvss=7.0,  # High and Critical only
    check_kev=True
)

result = await scanner.scan_sbom("sbom.json")

# Analyze by age
old_criticals = [
    v for v in result.vulnerabilities
    if v.severity == VulnerabilitySeverity.CRITICAL
    and v.age_days > 30
]

# Find exploitable vulnerabilities
exploitable = [
    v for v in result.vulnerabilities
    if v.exploit_available or v.is_kev
]
```

### Command Line Usage

```bash
# Basic scan
python osv_scanner.py sbom.json

# With options (when CLI is extended)
python osv_scanner.py sbom.json --offline --min-cvss 7.0
```

## KEV Integration

### CISA Known Exploited Vulnerabilities

The scanner integrates with CISA's KEV catalog to identify actively exploited vulnerabilities:

- **Updated Daily**: Fresh KEV data downloaded every 24 hours
- **Cached Locally**: Stored in `.cache/osv/kev_catalog.json`
- **Priority Flag**: KEV vulnerabilities marked with `is_kev=True`
- **Risk Indicator**: KEV status indicates active exploitation in the wild

### KEV Impact on Scoring

Vulnerabilities in the KEV catalog receive special treatment:
- Double base deduction in FICO scoring
- Priority remediation flag
- Highlighted in reports
- Tracked separately in metrics

## Vulnerability Data Enrichment

### Information Collected

For each vulnerability, OSV Scanner provides:

1. **Basic Information**
   - CVE ID or OSV ID
   - Package name and version
   - Fixed version (if available)

2. **Severity Assessment**
   - CVSS score (v2 or v3)
   - Severity level (Critical/High/Medium/Low)
   - KEV status

3. **Timeline Data**
   - Published date
   - Age in days
   - Last modified date

4. **Exploit Information**
   - Known exploit availability
   - Exploit references
   - Attack vectors

5. **Remediation Guidance**
   - Fixed versions
   - Patch availability
   - Workarounds (if documented)

## Offline Mode Configuration

### Setting Up Local Database

```bash
# Download OSV database for offline use
osv-scanner --update-offline-database /opt/osv/db

# Database structure
/opt/osv/db/
├── npm/
├── pypi/
├── go/
├── maven/
└── ...
```

### Using Offline Mode

```python
# Configure for offline scanning
scanner = OSVScanner(
    offline_mode=True,
    local_db_path=Path("/opt/osv/db")
)

# Database is used automatically
result = await scanner.scan_sbom("sbom.json")
```

### Database Update Strategy

- Update weekly for production
- Update daily for high-security environments
- Automate updates with cron/scheduled tasks
- Keep backup of previous database

## Performance Characteristics

### Scanning Speed

| SBOM Size | Online Mode | Offline Mode | Cache Hit |
|-----------|------------|--------------|-----------|
| Small (<100 packages) | 5-10 seconds | 2-5 seconds | <1 second |
| Medium (100-500) | 15-30 seconds | 5-10 seconds | <1 second |
| Large (500-1000) | 30-60 seconds | 10-20 seconds | <1 second |
| Huge (1000+) | 60-120 seconds | 20-40 seconds | <1 second |

### Resource Usage

- **Memory**: 100-500MB depending on SBOM size
- **CPU**: Light usage, mostly I/O bound
- **Disk**: 10-50MB for cache, 1-5GB for offline DB
- **Network**: 1-10MB per scan (online mode)

### Optimization Tips

1. **Use Caching**: 24-hour cache eliminates redundant scans
2. **Batch Processing**: Group SBOM scans to reuse connections
3. **Offline Mode**: Eliminates network latency
4. **Filter Early**: Use `min_cvss` to reduce processing
5. **Parallel Scans**: Process multiple SBOMs concurrently

## API Rate Limits

### OSV API Limits

- **Rate Limit**: 1000 requests per minute
- **Batch Size**: 1000 packages per request
- **No Authentication**: Public API, no key required
- **Retry Logic**: Automatic exponential backoff

### Handling Rate Limits

```python
# Built-in retry logic handles rate limits
# No configuration needed for normal usage

# For high-volume scanning, use offline mode
scanner = OSVScanner(offline_mode=True)
```

## Troubleshooting

### Common Issues

#### 1. OSV Scanner Not Found
```
FileNotFoundError: osv-scanner is not installed
```
**Solution**: Install using the installation guide above

#### 2. Empty Vulnerability Results
**Possible causes:**
- SBOM missing PURL identifiers
- Packages not in OSV database
- Network connectivity issues

**Solution**: Verify SBOM format and check network

#### 3. KEV Catalog Download Failed
```
Warning: Could not load KEV catalog
```
**Solution**: Check internet connection or disable KEV checking:
```python
scanner = OSVScanner(check_kev=False)
```

#### 4. Timeout on Large SBOM
**Solution**: Increase timeout or use offline mode

#### 5. Cache Permission Errors
**Solution**: Ensure write permissions for `.cache/osv/` directory

## Best Practices

### 1. Always Check KEV
```python
# KEV indicates active exploitation
scanner = OSVScanner(check_kev=True)
```

### 2. Set Appropriate CVSS Threshold
```python
# For production: Focus on High/Critical
scanner = OSVScanner(min_cvss=7.0)

# For development: See all vulnerabilities
scanner = OSVScanner(min_cvss=0.0)
```

### 3. Regular Database Updates
```bash
# Daily update for offline database
0 2 * * * osv-scanner --update-offline-database /opt/osv/db
```

### 4. Monitor Scan Performance
```python
# Log scan duration
result = await scanner.scan_sbom("sbom.json")
logger.info(f"Scan took {result.scan_duration:.2f} seconds")
```

### 5. Prioritize Remediation
```python
# Focus on KEV and old criticals first
priority_vulns = sorted(
    result.vulnerabilities,
    key=lambda v: (v.is_kev, v.severity.value, v.age_days),
    reverse=True
)
```

## Integration with Scoring Pipeline

The OSV Scanner provides vulnerability data to the time-decay scorer:

```python
# Step 1: Generate SBOM
sbom_result = await sbom_generator.generate_sbom(repo_path)

# Step 2: Scan for vulnerabilities (THIS COMPONENT)
osv_scanner = OSVScanner()
scan_result = await osv_scanner.scan_sbom(sbom_result.sbom_path)

# Step 3: Apply time-decay scoring
from vulnerability_time_scorer import VulnerabilityTimeScorer
scorer = VulnerabilityTimeScorer()
fico_score = scorer.calculate_score(scan_result)
```

## API Reference

### OSVScanner Methods

#### `__init__(...)`
Initialize scanner with configuration options.

#### `scan_sbom(sbom_path: str) -> OSVScanResult`
Scan SBOM file for vulnerabilities.

#### `update_local_database() -> bool`
Update local OSV database for offline mode.

#### `check_kev_status(cve_id: str) -> bool`
Check if CVE is in CISA KEV catalog.

## Future Enhancements

1. **Advanced Features**
   - Call graph analysis for reachability
   - Transitive dependency mapping
   - License violation detection
   - SBOM comparison/diff

2. **Performance**
   - Streaming SBOM parsing
   - Distributed scanning
   - Incremental updates

3. **Integration**
   - GitHub Security Advisories
   - Snyk vulnerability DB
   - NVD direct integration
   - Container registry scanning

4. **Reporting**
   - SARIF format output
   - HTML vulnerability reports
   - Trend analysis

## Dependencies

### Python Requirements
```python
# Built-in modules only
import asyncio
import json
import logging
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set
from enum import Enum
```

### System Requirements
- Python 3.7+
- OSV Scanner CLI installed
- 500MB RAM minimum
- Internet connection (online mode)
- 5GB disk space (offline mode)

## Component Boundaries

### What This Component Does
- ✅ Scan SBOM files for vulnerabilities
- ✅ Query OSV database
- ✅ Check CISA KEV catalog
- ✅ Calculate vulnerability age
- ✅ Detect exploit availability
- ✅ Cache results

### What This Component Does NOT Do
- ❌ Generate SBOMs (SBOM Generator's job)
- ❌ Calculate FICO scores (Scorer's job)
- ❌ Fix vulnerabilities
- ❌ Create patches
- ❌ Modify dependencies

## Testing

### Unit Tests
```python
def test_cvss_to_severity():
    scanner = OSVScanner()
    assert scanner._cvss_to_severity(9.5) == VulnerabilitySeverity.CRITICAL
    assert scanner._cvss_to_severity(7.5) == VulnerabilitySeverity.HIGH
    assert scanner._cvss_to_severity(5.0) == VulnerabilitySeverity.MEDIUM
    assert scanner._cvss_to_severity(2.0) == VulnerabilitySeverity.LOW
```

### Integration Tests
- Test with sample SBOM files
- Verify KEV integration
- Check cache functionality
- Validate offline mode

## Maintenance

### Keeping OSV Scanner Updated
```bash
# Update to latest version
go install github.com/google/osv-scanner/cmd/osv-scanner@latest

# Or download latest binary
# Check: https://github.com/google/osv-scanner/releases
```

### Cache Cleanup
```python
# Clean old cache entries
from pathlib import Path
import time

cache_dir = Path(".cache/osv")
for cache_file in cache_dir.glob("*.json"):
    age_days = (time.time() - cache_file.stat().st_mtime) / 86400
    if age_days > 7:
        cache_file.unlink()
```

### KEV Catalog Refresh
The KEV catalog is automatically refreshed daily, but can be forced:
```python
scanner = OSVScanner()
scanner.kev_cves = set()  # Clear cache
scanner._load_kev_catalog()  # Force reload
```

---

*This component is part of the MCP Security Analysis System and provides vulnerability detection capabilities that feed into the time-decay scoring algorithm for comprehensive security assessment.*