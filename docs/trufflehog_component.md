# TruffleHog Secret Detection Component

## Component Overview

The TruffleHog Secret Detection Component is part of the **Risk Scoring Pillar** in the MCP Security Analysis System. It scans repositories for exposed secrets, API keys, and credentials in both current code and git history.

### Purpose
Detect exposed secrets in MCP repositories using entropy analysis and pattern matching, contributing to the overall security risk score with heavy penalties for credential exposure.

### Position in System Architecture
```
┌─────────────────────────────────────────────────┐
│          MCP Security Analysis System           │
├─────────────────────────────────────────────────┤
│                                                  │
│            Risk Scoring Component (40%)         │
│            ┌──────────────────────┐             │
│            │                      │             │
│            │   ┌─────────────┐   │             │
│            │   │   Semgrep   │   │             │
│            │   │   Scanner   │   │             │
│            │   └─────────────┘   │             │
│            │          +           │             │
│            │   ┌─────────────┐   │             │
│            │   │  TruffleHog │   │             │
│            │   │   Scanner   │   │ ◄── THIS    │
│            │   └─────────────┘   │             │
│            │                      │             │
│            └──────────────────────┘             │
└─────────────────────────────────────────────────┘
```

## Files Created

### 1. Core Scanner
- **File**: `/mnt/prod/mcp/trufflehog_integration.py` (900+ lines)
- **Purpose**: TruffleHog integration for secret detection
- **Key Features**:
  - 700+ secret detector types
  - Git history scanning
  - Filesystem scanning
  - Smart exclusions (100+ patterns)
  - False positive filtering
  - Ethical public repo scanning

### 2. Key Classes

#### `TruffleHogScanner`
Main scanner class with configuration options:
```python
class TruffleHogScanner:
    def __init__(self,
                 verify_secrets: bool = False,  # Ethical default
                 scan_history: bool = True,
                 custom_patterns: Optional[List[Dict]] = None,
                 exclude_paths: Optional[List[str]] = None,
                 include_paths: Optional[List[str]] = None)
```

#### `SecretFinding`
Individual secret detection result:
```python
@dataclass
class SecretFinding:
    detector_name: str      # AWS, GitHub, Generic, etc.
    severity: SecretSeverity
    file_path: str
    line_number: int
    verified: bool          # Is the secret active?
    redacted_secret: str    # Safe display version
```

#### `CombinedRiskScanner`
Combines Semgrep and TruffleHog results:
```python
class CombinedRiskScanner:
    def __init__(self,
                 semgrep_scanner=None,
                 trufflehog_scanner: Optional[TruffleHogScanner] = None)
```

## Secret Detection Capabilities

### 700+ Detector Types

| Category | Examples |
|----------|----------|
| **Cloud Providers** | AWS, GCP, Azure, DigitalOcean, Heroku |
| **Version Control** | GitHub, GitLab, Bitbucket tokens |
| **Payment Systems** | Stripe, PayPal, Square, Coinbase |
| **Communication** | Slack, Discord, Twilio, SendGrid |
| **Databases** | MongoDB, PostgreSQL, MySQL, Redis |
| **Package Managers** | NPM, PyPI, RubyGems, Docker Hub |
| **Monitoring** | DataDog, New Relic, PagerDuty |
| **AI/ML Services** | OpenAI, Anthropic, Hugging Face |
| **Custom Patterns** | MCP-specific, regex-based |

### Scanning Modes

1. **Git History Scanning**
   - Scans all commits, branches, and tags
   - Identifies when secrets were first exposed
   - Tracks secret lifetime in repository

2. **Filesystem Scanning**
   - Scans current state of files
   - Faster than history scanning
   - Good for initial assessments

## Smart Exclusions

### Excluded Directories (100+ patterns)

| Category | Examples | Rationale |
|----------|----------|-----------|
| **Dependencies** | node_modules/, vendor/, venv/ | Third-party code |
| **Build Artifacts** | build/, dist/, target/ | Generated files |
| **Version Control** | .git/, .svn/, .hg/ | VCS internals |
| **Package Locks** | package-lock.json, yarn.lock | Hashes, not secrets |
| **Binary Files** | *.dll, *.so, *.exe | Compiled code |
| **Test Data** | test/, examples/, fixtures/ | Sample data |
| **IDE Files** | .idea/, .vscode/ | Editor config |
| **ML Models** | *.h5, *.pkl, *.model | Binary data |
| **Minified Code** | *.min.js, *.min.css | Compressed files |

### Force-Included Files

Despite exclusions, these files are always scanned:
- `.env` and `.env.*` files
- `config.*` files (json, yaml, ini)
- `credentials.*`, `secrets.*`, `auth.*` files
- `docker-compose.yml`
- `mcp.json` and MCP config files

## False Positive Filtering

### Automated Filters

1. **Placeholder Detection**
   ```
   xxxxxxxx, changeme, TODO, your-key-here
   <INSERT_KEY>, {{variable}}, ${VARIABLE}
   ```

2. **Hash Value Detection**
   - SHA1 (40 hex characters)
   - SHA256 (64 hex characters)
   - Git commit hashes

3. **Test/Example Files**
   - Files in test/, example/, demo/ directories
   - Files containing "fixture", "mock", "sample"

4. **Development URLs**
   - localhost, 127.0.0.1, 0.0.0.0
   - host.docker.internal
   - example.com

## FICO Scoring Impact

### Secret Severity Weights

| Secret Type | Confidence | FICO Deduction | Notes |
|-------------|------------|----------------|-------|
| **Verified Active** | Confirmed | -200 points | Immediate danger |
| **Critical (Unverified)** | Very High | -180 points | AWS, Stripe keys |
| **High-Confidence** | High | -150 points | GitHub, API tokens |
| **Medium-Confidence** | Medium | -80 points | Generic patterns |
| **Low-Confidence** | Low | -30 points | Possible FP |

### Special Scoring Rules

- **Any verified secret**: Caps score at 579 (Poor)
- **Production files**: 1.5x penalty multiplier
- **Config files**: 1.3x penalty multiplier
- **Test files**: 0.5x penalty reduction

## Ethical Scanning Configuration

### For Public Repositories

```python
# Ethical configuration - NO VERIFICATION
scanner = TruffleHogScanner(
    verify_secrets=False,  # Never test credentials
    scan_history=True,     # Check exposure duration
    exclude_paths=[...],   # Smart exclusions
    include_paths=[...]    # Force includes
)
```

### Why No Verification?

1. **Legal**: Testing credentials could be unauthorized access
2. **Ethical**: We detect, not exploit
3. **Practical**: Avoids triggering security alerts
4. **Responsible**: Enables safe disclosure

## Integration Interfaces

### Input Interface
```python
async def scan_repository(self, repo_path: str) -> SecretScanResult
```

### Output Data Model
```python
@dataclass
class SecretScanResult:
    repository: str
    total_secrets: int
    verified_count: int  # Always 0 for ethical scanning
    findings: List[SecretFinding]
    scan_duration: float
    metadata: Dict[str, Any]
```

### Integration with Risk Scoring
```python
# Combined scanning with Semgrep
combined = CombinedRiskScanner(
    semgrep_scanner=semgrep_scanner,
    trufflehog_scanner=TruffleHogScanner(verify_secrets=False)
)
result = await combined.scan_repository(repo_path)
final_score = result['combined_score']['fico_score']
```

## Performance Characteristics

### Scanning Speed
- **Filesystem only**: ~10-30 seconds per repo
- **Git history**: ~30-120 seconds per repo
- **With exclusions**: 50-70% faster

### Resource Usage
- **Memory**: 100-500MB per scan
- **CPU**: Single core usage
- **Disk**: Minimal (temp files for exclusions)

### Optimization Strategies
1. Use aggressive exclusions
2. Disable history scanning for speed
3. Parallel processing with semaphore
4. Cache results for re-scans

## Usage Examples

### Basic Scanning
```python
scanner = TruffleHogScanner()
result = await scanner.scan_repository("/path/to/repo")
print(f"Found {result.total_secrets} secrets")
```

### Advanced Configuration
```python
scanner = TruffleHogScanner(
    verify_secrets=False,
    scan_history=True,
    exclude_paths=[r"archived/", r"legacy/"],
    custom_patterns=[{
        "pattern": r"mcp[_-]key[_-]([a-z0-9]{32,})",
        "name": "MCP_API_Key"
    }]
)
```

### Batch Processing
```python
async def scan_multiple_repos(repo_paths: List[str]):
    scanner = TruffleHogScanner(verify_secrets=False)
    results = []

    for repo in repo_paths:
        result = await scanner.scan_repository(repo)
        results.append(result)

    return results
```

## Error Handling

### Common Issues

1. **TruffleHog Not Installed**
   ```
   RuntimeError: TruffleHog is not available
   Install with: pip install truffleHog3 or brew install trufflehog
   ```

2. **Timeout on Large Repos**
   - Solution: Disable history scanning
   - Or: Increase timeout limit

3. **High False Positive Rate**
   - Solution: Add more exclusions
   - Enable aggressive filtering

## Dependencies

### Required
- TruffleHog CLI (`pip install truffleHog3` or `brew install trufflehog`)
- Python 3.7+
- Git (for history scanning)

### Python Packages
```python
import asyncio
import json
import subprocess
import tempfile
from pathlib import Path
from dataclasses import dataclass
from enum import Enum
```

## Component Boundaries

### What TruffleHog Does
- ✅ Detect secrets in code and history
- ✅ Filter false positives
- ✅ Score based on secret type
- ✅ Support custom patterns
- ✅ Exclude irrelevant files

### What TruffleHog Does NOT Do
- ❌ Fix or rotate secrets
- ❌ Verify secrets in public repos (ethical)
- ❌ Perform static code analysis (Semgrep's job)
- ❌ Check dependencies for CVEs (Vulnerability scanner's job)
- ❌ Make GitHub API calls (Hygiene scorer's job)

## Testing

### Unit Tests
```python
def test_secret_detection():
    scanner = TruffleHogScanner(verify_secrets=False)

    # Create temp file with fake secret
    with tempfile.NamedTemporaryFile(mode='w', suffix='.env') as f:
        f.write("API_KEY=sk_test_1234567890abcdef")
        f.flush()

        result = scanner.scan_repository(Path(f.name).parent)
        assert result.total_secrets > 0
```

### Integration Tests
- Test with sample MCP repositories
- Verify exclusions work correctly
- Check false positive filtering
- Validate FICO score impact

## Best Practices

1. **Always use `verify_secrets=False` for public repos**
2. **Configure comprehensive exclusions**
3. **Monitor false positive rate**
4. **Report responsibly without exposing secrets**
5. **Track remediation time**
6. **Use in combination with Semgrep**

## Maintenance

### Updating Exclusion Patterns
- Review false positives monthly
- Add new patterns as needed
- Test impact on scan time

### TruffleHog Updates
- Keep TruffleHog CLI updated
- New detectors added regularly
- Check release notes for changes

---

*This component is part of the MCP Security Analysis System and works in conjunction with Semgrep to provide comprehensive risk assessment of MCP repositories.*