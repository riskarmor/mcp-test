# Semgrep Security Scanning Component

## Component Overview

The Semgrep Security Scanning Component is part of the **Risk Scoring Pillar** in the MCP Security Analysis System. It performs static code analysis to detect security vulnerabilities and MCP protocol violations using pattern-based rules.

### Purpose
Analyze MCP repositories for security vulnerabilities using static code analysis with Semgrep, producing FICO-style security scores (300-850 range) based on the MCP Security Review document specifications.

### Position in System Architecture
```
┌─────────────────────────────────────────────────┐
│          MCP Security Analysis System           │
├─────────────────────────────────────────────────┤
│                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌────────┐│
│  │   Hygiene    │  │  Semgrep     │  │ Vuln   ││
│  │   Scorer     │  │  Security    │  │Scanner ││
│  │  (GitHub)    │◄─┤  Component   │►─┤ (CVE)  ││
│  └──────────────┘  └──────────────┘  └────────┘│
│         │                 │                │     │
│         ▼                 ▼                ▼     │
│  ┌──────────────────────────────────────────┐   │
│  │         Score Aggregator                 │   │
│  │    (Weighted Average → Final Score)      │   │
│  └──────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
```

## Files Created

### 1. Core Scanner
- **File**: `/mnt/prod/mcp/mcp_security_scanner.py` (607 lines)
- **Purpose**: Main orchestrator for Semgrep-based security scanning
- **Key Features**:
  - Deployment mode detection
  - FICO scoring implementation
  - Context-aware rule filtering
  - Caching support

### 2. Security Rules
- **Python Rules**: `/mnt/prod/mcp/rules/mcp_python_rules.yaml` (400+ lines)
- **JavaScript Rules**: `/mnt/prod/mcp/rules/mcp_javascript_rules.yaml` (380+ lines)
- **Heuristic Rules**: `/mnt/prod/mcp/rules/heuristic_python.yaml` (150+ lines)

### 3. Report Generator
- **File**: `/mnt/prod/mcp/report_generator.py` (750+ lines)
- **Purpose**: Generate multi-format security reports
- **Output Formats**: HTML, Markdown, JSON, CSV

## Security Rule Categories

### 11 Security Check Categories Implemented

| Category | Rule ID Pattern | Severity | MCP Weight |
|----------|----------------|----------|------------|
| 1. Authentication & Authorization | `mcp-*-missing-auth` | High | +40 |
| 2. Transport Layer Security | `mcp-*-insecure-transport` | High | +40 |
| 3. Sensitive Data Exposure | `mcp-*-sensitive-data-logging` | Critical | +40 |
| 4. Code Injection | `mcp-*-insecure-deserialization` | Critical | +40 |
| 5. Session Management | `mcp-*-insecure-session-id` | High | +40 |
| 6. Rate Limiting | `mcp-*-missing-rate-limit` | Medium | +20 |
| 7. Origin Validation | `mcp-*-missing-origin-validation` | High | +40 |
| 8. Network Binding | `mcp-*-insecure-binding` | High | +40 |
| 9. User Consent | `mcp-*-missing-user-consent` | Medium | +20 |
| 10. Supply Chain | `mcp-*-unpinned-dependencies` | Low | 0 |
| 11. MCP Protocol | `mcp-*-missing-sse-resumption` | Medium | +20 |

## FICO Scoring Algorithm

### Score Calculation Formula
```python
# Base score
score = 850

# For each finding:
deduction = base_weight + (mcp_weight if is_mcp_specific else 0)
score -= deduction

# Apply bounds
score = max(300, score)  # Floor at 300
if critical_high_count > 10:
    score = min(579, score)  # Cap at 579

# Bonus points
if mcp_findings == 0 and critical_high == 0:
    score = min(850, score + 15)
```

### Severity Weights
| Severity | Base Deduction | MCP-Specific Total |
|----------|---------------|-------------------|
| Critical | -120 points | -160 points |
| High | -80 points | -120 points |
| Medium | -40 points | -60 points |
| Low | -10 points | -10 points |
| Info | 0 points | 0 points |

### Score Interpretation
| FICO Range | Grade | Risk Level | Action Required |
|------------|-------|------------|-----------------|
| 800-850 | A | Excellent | Production-ready |
| 670-799 | B | Good | Minor fixes only |
| 580-669 | C | Fair | Targeted remediation |
| 300-579 | F | Poor | Major overhaul needed |

## Deployment Mode Detection

### Three Deployment Contexts

1. **`trusted-host-only`**
   - Local execution only
   - Uses stdio transport
   - No network exposure
   - **Suppressed checks**: auth, rate-limiting, origin validation

2. **`standalone`**
   - Network-accessible service
   - Requires full authentication
   - Public-facing deployment
   - **Suppressed checks**: None (all rules apply)

3. **`mixed-use`**
   - Supports both modes via configuration
   - Dynamic security requirements
   - **Suppressed checks**: None (all rules apply)

### Detection Methodology
```python
# Stage 1: Run heuristic Semgrep rules
heuristic_findings = semgrep(heuristic_rules)

# Stage 2: Analyze pattern matches
if has_pattern("MCP_MODE", "config.deployment"):
    return MIXED_USE
elif has_pattern("app.run(0.0.0.0)", "require_auth"):
    return STANDALONE
elif has_pattern("stdio", "sys.stdin"):
    return TRUSTED_HOST_ONLY
else:
    return UNKNOWN
```

## Integration Interfaces

### Input Interface
```python
async def scan_repository(
    repo_path: str,
    language: Optional[str] = None,
    use_cache: bool = True
) -> SecurityScore
```

### Output Data Model
```python
@dataclass
class SecurityScore:
    repository: str
    deployment_mode: DeploymentMode
    fico_score: int  # 300-850
    raw_deduction: int
    findings: List[SemgrepFinding]
    suppressed_findings: List[SemgrepFinding]
    severity_counts: Dict[str, int]
    mcp_finding_count: int
    scored_at: str
    metadata: Dict[str, Any]
```

### Integration with Aggregator
```python
# This component provides the risk_score to the aggregator
from mcp_security_scanner import MCPSecurityScanner

scanner = MCPSecurityScanner()
score = await scanner.scan_repository(repo_path)

# Aggregator uses this score
aggregator.aggregate(
    hygiene=hygiene_score,
    risk=score.fico_score,  # Our component's output
    vulnerability=vuln_score
)
```

## Semgrep Execution Flow

### 1. Language Detection
```python
def _detect_language(repo_path):
    # Count files by extension
    # Return: "python", "javascript", "go", or "unknown"
```

### 2. Deployment Mode Detection
```python
# Execute: semgrep --config heuristic_python.yaml
# Analyze findings to determine deployment mode
```

### 3. Security Scanning
```python
# Execute: semgrep --config mcp_python_rules.yaml
# Parse JSON output into SemgrepFinding objects
```

### 4. Context-Aware Filtering
```python
def _filter_findings_by_mode(findings, deployment_mode):
    # Suppress irrelevant findings based on deployment context
    # Return: (active_findings, suppressed_findings)
```

### 5. Score Calculation
```python
def _calculate_fico_score(findings):
    # Apply severity weights
    # Calculate deductions
    # Apply floor/cap rules
    # Return score and metadata
```

## Report Generation

### Supported Formats
1. **HTML**: Interactive web report with charts
2. **Markdown**: Documentation-friendly format
3. **JSON**: Machine-readable for automation
4. **CSV**: Spreadsheet-compatible findings list

### Report Sections
- Executive Summary
- FICO Score & Grade
- Deployment Context
- Security Metrics
- Findings Table (sortable by severity)
- Remediation Priorities
- Compliance Mapping (OWASP, CWE, MCP)

## Performance Optimizations

### Caching Strategy
- Cache key: MD5 hash of repository path
- Cache duration: 24 hours
- Location: `.cache/` directory

### Concurrent Processing
```python
async def score_multiple(repositories, max_concurrent=3):
    # Process multiple repos in parallel
    # Semaphore limits concurrent Semgrep processes
```

## Error Handling

### Graceful Degradation
- Missing Semgrep → RuntimeError with instructions
- Missing rules → Warning, continue with available
- Timeout → Return empty findings, log error
- Parse errors → Skip malformed findings

## Usage Example

```python
from mcp_security_scanner import MCPSecurityScanner
from report_generator import ReportGenerator
import asyncio

async def analyze_mcp_repo():
    # Initialize scanner
    scanner = MCPSecurityScanner(
        rules_dir=Path("./rules"),
        cache_dir=Path("./.cache")
    )

    # Scan repository
    score = await scanner.scan_repository(
        repo_path="/path/to/mcp/repo",
        language="python",  # or None for auto-detect
        use_cache=True
    )

    # Generate report
    generator = ReportGenerator(output_dir=Path("./reports"))
    report_path = generator.generate_report(
        score.to_dict(),
        format="html",
        include_suppressed=False
    )

    print(f"FICO Score: {score.fico_score}")
    print(f"Grade: {score.get_grade()}")
    print(f"Report: {report_path}")

asyncio.run(analyze_mcp_repo())
```

## Dependencies

### Required Python Packages
```python
# Built-in
import asyncio
import json
import subprocess
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

# No external dependencies required
# Semgrep must be installed separately: pip install semgrep
```

### System Requirements
- Python 3.7+
- Semgrep CLI installed (`pip install semgrep`)
- 1GB+ RAM for large repositories
- Write access for cache directory

## Component Boundaries

### What This Component Does
- ✅ Static code analysis via Semgrep
- ✅ Security vulnerability detection
- ✅ FICO scoring (300-850 range)
- ✅ Deployment mode detection
- ✅ Context-aware finding suppression
- ✅ Multi-format report generation

### What This Component Does NOT Do
- ❌ GitHub API calls (hygiene scorer's job)
- ❌ CVE database lookups (vulnerability scanner's job)
- ❌ Final score aggregation (aggregator's job)
- ❌ Repository cloning (orchestrator's job)
- ❌ Database storage (persistence layer's job)

## Testing Approach

### Unit Tests
```python
# Test scoring algorithm
def test_fico_calculation():
    findings = [
        SemgrepFinding(severity=Severity.CRITICAL, is_mcp_specific=True),
        SemgrepFinding(severity=Severity.HIGH, is_mcp_specific=False)
    ]
    score = calculate_score(findings)
    assert score == 570  # 850 - 160 - 80 = 610, capped at 579
```

### Integration Tests
- Test with sample repositories
- Verify Semgrep execution
- Validate report generation

## Future Enhancements

1. **Additional Language Support**
   - Go rules implementation
   - Rust rules
   - Swift for iOS MCP clients

2. **Advanced Features**
   - Incremental scanning (only changed files)
   - Parallel Semgrep execution
   - Custom rule injection
   - Fix suggestions with `--autofix`

3. **Integration Improvements**
   - Direct GitHub integration
   - CI/CD pipeline templates
   - IDE plugins

## Maintenance Notes

### Adding New Rules
1. Add rule to appropriate YAML file
2. Follow naming convention: `mcp-{lang}-{issue}`
3. Include metadata: category, cwe, mcp_specific
4. Test with sample vulnerable code

### Updating Severity Weights
- Modify `SEVERITY_WEIGHTS` in `mcp_security_scanner.py`
- Ensure consistency with document specifications
- Update documentation

### Debugging
- Enable verbose logging: `logging.basicConfig(level=logging.DEBUG)`
- Check Semgrep output: Add `--verbose` flag
- Inspect cache files in `.cache/` directory

---

*This component is part of the larger MCP Security Analysis System and integrates with the hygiene scorer and vulnerability scanner to provide comprehensive security assessment of MCP repositories.*