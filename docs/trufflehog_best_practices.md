# TruffleHog Best Practices for MCP Repository Scanning

## Overview

This guide provides best practices for using TruffleHog to scan public MCP repositories for exposed secrets while maintaining ethical standards and maximizing accuracy.

---

## Ethical Scanning Guidelines

### 1. Never Verify Secrets in Public Repositories

```python
# ❌ WRONG - Don't verify secrets in public repos
scanner = TruffleHogScanner(verify_secrets=True)

# ✅ CORRECT - Detect without verification
scanner = TruffleHogScanner(verify_secrets=False)
```

**Why?**
- Verifying credentials is potentially illegal (unauthorized access)
- May trigger security alerts for the account owner
- We're security researchers, not attackers
- Detection is sufficient for risk assessment

### 2. Responsible Disclosure

When secrets are found:
- **Don't** expose the actual secret in reports
- **Don't** test if the credential works
- **Do** report the type and location
- **Do** notify repository maintainers if possible
- **Do** track remediation over time

---

## Exclusion Strategy

### Core Exclusions (Always Skip)

```python
ALWAYS_EXCLUDE = [
    r"node_modules/",      # NPM dependencies
    r"vendor/",            # Go/PHP dependencies
    r"\.git/",             # Git internals
    r"venv/", r"\.venv/",  # Python virtual environments
    r"build/", r"dist/",   # Build outputs
    r"\*\.min\.js",        # Minified JavaScript
    r"package-lock\.json", # Package locks (hashes, not secrets)
    r"\*\.dll", r"\*\.so", # Binary files
]
```

### MCP-Specific Exclusions

```python
MCP_EXCLUDE = [
    r"mcp-servers/",       # Multi-server directories
    r"examples/data/",     # Example data files
    r"test-data/",         # Test datasets
    r"mock-data/",         # Mock data
    r"sample-output/",     # Sample outputs
    r"\.ipynb_checkpoints/", # Jupyter checkpoints
]
```

### Force Includes (Always Scan)

```python
ALWAYS_SCAN = [
    r"\.env$",             # Environment files
    r"config\.(json|yml|yaml|ini)$",  # Config files
    r"credentials\.(json|yml|yaml)$", # Credential files
    r"mcp\.json$",         # MCP configuration
    r"docker-compose\.yml$", # Docker configs
]
```

---

## False Positive Reduction

### 1. Filter Test/Example Files

```python
def is_test_file(file_path: str) -> bool:
    test_indicators = [
        "test", "tests", "spec", "specs",
        "example", "examples", "sample",
        "demo", "fixture", "mock"
    ]
    return any(indicator in file_path.lower()
              for indicator in test_indicators)
```

### 2. Identify Placeholders

```python
PLACEHOLDER_PATTERNS = [
    "xxxxxxxx",           # Generic placeholder
    "changeme",           # Common placeholder
    "your-api-key-here",  # Instruction placeholder
    "<INSERT_KEY_HERE>",  # Template placeholder
    "{{api_key}}",        # Template variable
    "${API_KEY}",         # Environment variable reference
    "TODO",               # To-do marker
]
```

### 3. Exclude Hash Values

```python
def is_hash(value: str) -> bool:
    # SHA1 (40 hex chars) or SHA256 (64 hex chars)
    import re
    return bool(re.match(r'^[a-f0-9]{40}$|^[a-f0-9]{64}$', value))
```

### 4. Skip Development URLs

```python
DEV_URLS = [
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "host.docker.internal",
    "example.com",
    "test.local"
]
```

---

## Configuration Examples

### Basic Configuration

```python
scanner = TruffleHogScanner(
    verify_secrets=False,
    scan_history=True,
    exclude_paths=None,  # Use defaults
    include_paths=None   # Use defaults
)
```

### Advanced Configuration

```python
scanner = TruffleHogScanner(
    verify_secrets=False,
    scan_history=True,
    exclude_paths=[
        r"archived/",     # Custom exclusion
        r"legacy/",       # Custom exclusion
    ],
    include_paths=[
        r"prod\.env$",    # Force scan production env
    ],
    custom_patterns=[
        {
            "pattern": r"mcp[_-]key[_-]([a-zA-Z0-9]{32,})",
            "name": "MCP_API_Key"
        }
    ]
)
```

### Batch Processing Configuration

```python
async def scan_mcp_repositories(repos: List[str]):
    scanner = TruffleHogScanner(
        verify_secrets=False,  # Ethical scanning
        scan_history=False,    # Faster for batch processing
    )

    results = []
    for repo_url in repos:
        # Clone repository
        repo_path = await clone_repo(repo_url)

        # Scan for secrets
        result = await scanner.scan_repository(repo_path)

        # Clean up
        cleanup_repo(repo_path)

        results.append(result)

    return results
```

---

## Performance Optimization

### 1. Disable Git History for Speed

```python
# Faster but less thorough
scanner = TruffleHogScanner(scan_history=False)
```

### 2. Use Exclusions Aggressively

```python
# More exclusions = faster scanning
exclude_paths = ALWAYS_EXCLUDE + MCP_EXCLUDE + CUSTOM_EXCLUDE
```

### 3. Parallel Processing

```python
async def scan_parallel(repos: List[str], max_workers: int = 5):
    semaphore = asyncio.Semaphore(max_workers)

    async def scan_with_limit(repo):
        async with semaphore:
            return await scanner.scan_repository(repo)

    tasks = [scan_with_limit(repo) for repo in repos]
    return await asyncio.gather(*tasks)
```

---

## Scoring Guidelines

### Secret Severity Mapping

| Secret Type | Confidence | FICO Deduction | Action |
|-------------|------------|----------------|---------|
| AWS Key (prod) | Very High | -180 | Critical Alert |
| GitHub Token | High | -150 | Urgent Fix |
| Generic API Key | Medium | -80 | Investigation |
| Possible Secret | Low | -30 | Review |

### Context Matters

```python
def adjust_severity(finding: SecretFinding) -> int:
    base_deduction = finding.get_base_deduction()

    # Production files are worse
    if "prod" in finding.file_path.lower():
        base_deduction *= 1.5

    # Config files are critical
    if finding.file_path.endswith((".env", "config.json")):
        base_deduction *= 1.3

    # Test files are less critical
    if "test" in finding.file_path.lower():
        base_deduction *= 0.5

    return int(base_deduction)
```

---

## Common Pitfalls to Avoid

### 1. ❌ Scanning Everything

```python
# Bad - Scans unnecessary files
scanner.scan_repository("/")
```

### 2. ❌ Verifying Public Secrets

```python
# Bad - Unethical and potentially illegal
scanner = TruffleHogScanner(verify_secrets=True)
```

### 3. ❌ Exposing Found Secrets

```python
# Bad - Never log actual secrets
print(f"Found secret: {finding.raw_secret}")
```

### 4. ❌ Ignoring Context

```python
# Bad - Treating all findings equally
score -= 100  # Same penalty for everything
```

---

## Integration with MCP Security System

### Combined Risk Scoring

```python
from trufflehog_integration import TruffleHogScanner, CombinedRiskScanner
from mcp_security_scanner import MCPSecurityScanner

# Create combined scanner
combined = CombinedRiskScanner(
    semgrep_scanner=MCPSecurityScanner(),
    trufflehog_scanner=TruffleHogScanner(
        verify_secrets=False,
        scan_history=True
    )
)

# Scan repository
result = await combined.scan_repository(repo_path)

# Get unified FICO score
fico_score = result['combined_score']['fico_score']
```

### Report Generation

```python
def generate_secret_report(findings: List[SecretFinding]) -> str:
    report = []

    # Group by severity
    critical = [f for f in findings if f.severity == "critical"]
    high = [f for f in findings if f.severity == "high"]

    # Summarize without exposing secrets
    if critical:
        report.append(f"🚨 {len(critical)} CRITICAL secrets found")

    if high:
        report.append(f"⚠️ {len(high)} HIGH-risk secrets found")

    # Recommendations
    if critical or high:
        report.append("\n📋 IMMEDIATE ACTIONS REQUIRED:")
        report.append("1. Rotate ALL exposed credentials")
        report.append("2. Review git history for exposure duration")
        report.append("3. Enable secret scanning in CI/CD")
        report.append("4. Implement pre-commit hooks")

    return "\n".join(report)
```

---

## Monitoring and Metrics

### Key Metrics to Track

1. **False Positive Rate**
   ```python
   false_positive_rate = false_positives / total_findings
   ```

2. **Scan Coverage**
   ```python
   coverage = files_scanned / total_files
   ```

3. **Secret Types Distribution**
   ```python
   distribution = Counter(f.detector_name for f in findings)
   ```

4. **Time to Remediation**
   ```python
   remediation_time = date_fixed - date_found
   ```

### Continuous Improvement

```python
class ScanMetrics:
    def __init__(self):
        self.total_scans = 0
        self.total_secrets = 0
        self.false_positives = 0
        self.scan_times = []

    def record_scan(self, result: SecretScanResult):
        self.total_scans += 1
        self.total_secrets += result.total_secrets
        self.scan_times.append(result.scan_duration)

    def get_average_scan_time(self) -> float:
        return sum(self.scan_times) / len(self.scan_times)

    def get_false_positive_rate(self) -> float:
        total = self.total_secrets + self.false_positives
        return self.false_positives / total if total > 0 else 0
```

---

## Checklist for Production Deployment

- [ ] Set `verify_secrets=False` for public repos
- [ ] Configure comprehensive exclusions
- [ ] Implement false positive filtering
- [ ] Set up responsible disclosure process
- [ ] Enable rate limiting
- [ ] Add monitoring and metrics
- [ ] Test on sample repositories
- [ ] Document scanning policies
- [ ] Train team on ethical scanning
- [ ] Set up automated reporting

---

## Summary

TruffleHog is a powerful tool for detecting secrets in MCP repositories, but must be used responsibly:

1. **Never verify secrets** in public repositories
2. **Use smart exclusions** to reduce false positives
3. **Filter aggressively** for placeholders and test data
4. **Score contextually** based on file location and type
5. **Report responsibly** without exposing actual secrets
6. **Monitor continuously** to improve accuracy

By following these best practices, you can effectively identify security risks in MCP repositories while maintaining ethical standards and producing actionable results.

---

*Last Updated: 2024*
*Version: 1.0*
*Part of the MCP Security Analysis System*