# MCP Security Analysis System
## Complete System Documentation

---

## Executive Summary

The MCP Security Analysis System is a comprehensive platform for evaluating the security posture of Model Context Protocol (MCP) repositories. It analyzes **13,016+ MCP repositories** using a three-pillar assessment framework, producing FICO-style security scores (300-850 range) that enable objective security evaluation across the entire MCP ecosystem.

### Key Capabilities
- **Automated Security Scoring**: FICO-style scores from 300-850
- **Three-Pillar Analysis**: Hygiene (30%), Risk (40%), Vulnerability (30%)
- **MCP-Specific Calibration**: Tailored for MCP protocol requirements
- **Deployment-Aware**: Context-sensitive security requirements
- **Scalable Processing**: Handles 13,000+ repositories
- **Multi-Format Reporting**: HTML, Markdown, JSON, CSV outputs

---

## System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                   MCP SECURITY ANALYSIS SYSTEM                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Data Source                   Processing Pipeline               │
│  ┌──────────┐                 ┌─────────────────────┐          │
│  │  13,016  │                 │   Repository        │          │
│  │   MCP    │ ───────────────▶│   Downloader/       │          │
│  │  Repos   │                 │   Manager           │          │
│  └──────────┘                 └─────────────────────┘          │
│       │                                 │                        │
│       │                                 ▼                        │
│       │                    ┌────────────────────────┐          │
│       │                    │  Three-Pillar Analysis │          │
│       │                    ├────────────────────────┤          │
│       │                    │                        │          │
│       │         ┌──────────┴──┐  ┌────────┴──┐  ┌─┴────────┐ │
│       └────────▶│   Hygiene    │  │   Risk     │  │  Vuln    │ │
│                 │   Scorer     │  │  Scanner   │  │ Scanner  │ │
│                 │   (GitHub)   │  │ (Semgrep)  │  │  (CVE)   │ │
│                 └──────────────┘  └────────────┘  └──────────┘ │
│                        │                │              │        │
│                        │     30%        │ 40%         │ 30%    │
│                        └────────────────┼──────────────┘        │
│                                         ▼                        │
│                              ┌───────────────────┐              │
│                              │  Score Aggregator │              │
│                              │   (FICO 300-850)  │              │
│                              └───────────────────┘              │
│                                         │                        │
│                                         ▼                        │
│                              ┌───────────────────┐              │
│                              │  Report Generator │              │
│                              │  HTML/MD/JSON/CSV │              │
│                              └───────────────────┘              │
│                                         │                        │
│                                         ▼                        │
│                              ┌───────────────────┐              │
│                              │    Data Storage   │              │
│                              │   (Results DB)    │              │
│                              └───────────────────┘              │
└─────────────────────────────────────────────────────────────────┘
```

### Directory Structure

```
/mnt/prod/mcp/
├── MCP Security Review with Semgrep Rules.md  # Source document
├── mcp_repositories.json                      # 13,016 MCP repos
├── mcp_security_scanner.py                    # Main Semgrep scanner
├── trufflehog_integration.py                  # TruffleHog secret scanner
├── sbom_generator.py                           # SBOM generation tool
├── osv_scanner.py                              # OSV vulnerability scanner
├── vulnerability_time_scorer.py                # Time-decay vulnerability scoring
├── report_generator.py                         # Report generation
├── rules/                                      # Semgrep rules
│   ├── mcp_python_rules.yaml
│   ├── mcp_javascript_rules.yaml
│   ├── heuristic_python.yaml
│   └── heuristic_javascript.yaml
├── risk_armor/                                 # Core system
│   ├── core/
│   │   └── aggregator.py                      # Score aggregation
│   ├── scoring/
│   │   ├── hygiene/
│   │   │   ├── hygiene_scorer.py              # GitHub metrics
│   │   │   └── hygiene_scorer_v1.py
│   │   ├── risk/
│   │   │   ├── semgrep_scorer.py              # Security scanning
│   │   │   ├── rules_generator.py
│   │   │   └── rules/                         # Additional rules
│   │   └── vulnerability/
│   │       ├── __init__.py
│   │       └── vulnerability_scorer.py        # Vulnerability orchestrator
│   ├── config/
│   │   └── hygiene_config.yaml
│   ├── tests/
│   ├── cache/                                 # API response cache
│   └── requirements.txt
└── docs/
    └── semgrep_component.md                   # Component docs
```

---

## Component Details

### 1. Hygiene Scoring Component (30% Weight)
**Location**: `/risk_armor/scoring/hygiene/`
**Status**: ✅ Fully Implemented (v2.0)

#### Purpose
Analyzes repository health and maintenance metrics using GitHub API to assess code quality practices.

#### Key Features
- **GitHub GraphQL Integration**: Single query for all metrics
- **Token Rotation**: Supports multiple GitHub tokens
- **Intelligent Caching**: 1-hour TTL with diskcache
- **MCP-Specific Detection**: Identifies `mcp.json` files
- **Stale Detection**: Based on last activity, not creation date

#### Scoring Factors (11 Components)
1. **Documentation** (10%): README quality and completeness
2. **License** (5%): Presence of OSS license
3. **Tests** (10%): Test file coverage
4. **CI/CD** (10%): GitHub Actions or CI configuration
5. **Issue Activity** (10%): Open/closed issue ratio
6. **PR Activity** (10%): PR velocity and merge rate
7. **Dependencies** (10%): package.json/requirements.txt freshness
8. **Security** (10%): Security policy and vulnerability disclosure
9. **Code Review** (5%): PR review requirements
10. **Release Management** (10%): Tagged releases and versioning
11. **Community** (10%): Stars, forks, contributors

#### MCP Calibration
- Lower activity thresholds (1 PR in 90 days = healthy)
- Young repository bonus (new tools aren't penalized)
- Tolerant stale detection (90 days PRs, 120 days issues)

---

### 2. Risk Scoring Component (40% Weight)
**Location**: `/mcp_security_scanner.py` + `/risk_armor/scoring/risk/` + `/trufflehog_integration.py`
**Status**: ✅ Fully Implemented
**Documentation**:
- Semgrep: `/docs/semgrep_component.md`
- TruffleHog: `/docs/trufflehog_component.md`
- Best Practices: `/docs/trufflehog_best_practices.md`

#### Purpose
Comprehensive security analysis combining:
- **Semgrep**: Static code analysis for vulnerabilities
- **TruffleHog**: Secret detection in code and git history

#### A. Semgrep Security Rules (11 Categories)
1. **Authentication & Authorization**: Missing/weak auth checks
2. **Transport Security**: TLS/HTTPS violations
3. **Data Exposure**: Logging secrets, credential leaks
4. **Code Injection**: eval(), exec(), unsafe deserialization
5. **Session Management**: Weak randomness, missing logout
6. **Rate Limiting**: Missing DoS protection
7. **Origin Validation**: DNS rebinding vulnerabilities
8. **Network Binding**: Insecure 0.0.0.0 binding
9. **User Consent**: Data access without permission
10. **Supply Chain**: Unpinned dependencies
11. **MCP Protocol**: SSE resumption, nonce generation

#### Deployment Mode Detection
Automatically detects and adjusts security requirements based on deployment context:

- **`trusted-host-only`**: Local execution, stdio transport
  - Suppresses: auth, rate-limiting, origin validation
- **`standalone`**: Network server with full security
  - All security rules apply
- **`mixed-use`**: Configurable deployment
  - All security rules apply

#### B. TruffleHog Secret Detection
**Full Documentation**: See `/docs/trufflehog_component.md` for complete details

**Detects 700+ Secret Types Including:**
- Cloud provider credentials (AWS, GCP, Azure)
- API keys (GitHub, GitLab, Slack, Stripe)
- Database credentials
- OAuth tokens and JWTs
- Private keys and certificates
- Webhook URLs
- Custom MCP-specific patterns

**Smart Exclusions to Reduce False Positives:**
- **Excludes**: node_modules/, .git/, build/, vendor/, *.min.js, package-lock.json
- **Excludes**: Test files, examples, demos, fixtures
- **Excludes**: Binary files, compiled code, ML models
- **Still Scans**: .env files, config files, credentials.*, mcp.json

**False Positive Filtering:**
- Filters placeholders (xxxxxxx, changeme, TODO)
- Ignores hash values (SHA1/SHA256)
- Excludes localhost/development URLs
- Detects template variables ({{var}}, ${var}})

**Ethical Public Repo Scanning:**
- **verify_secrets=False** by default (no credential testing)
- Detection without exploitation
- Responsible disclosure approach

**Secret Severity Scoring:**
- **Verified Active Secrets**: -200 points (critical)
- **High-Confidence Secrets**: -150 points
- **Medium-Confidence**: -80 points
- **Low-Confidence**: -30 points

#### Combined FICO Scoring Algorithm
```
Base Score: 850

Semgrep Deductions:
- Critical: -120 (MCP-specific: -160)
- High: -80 (MCP-specific: -120)
- Medium: -40 (MCP-specific: -60)
- Low: -10
- Info: 0

TruffleHog Deductions:
- Verified Secrets: -200 points each
- Unverified Critical: -180 points
- High-Confidence: -150 points
- Medium-Confidence: -80 points
- Low-Confidence: -30 points

Special Rules:
- Floor: 300 minimum
- Cap: 579 if verified secrets found
- Cap: 579 if >10 critical/high findings
- Bonus: +15 if no MCP findings and no secrets
```

---

### 3. Vulnerability Scoring Component (30% Weight)
**Location**: `/risk_armor/scoring/vulnerability/`
**Status**: ✅ Fully Implemented
**Documentation**:
- SBOM Generator: `/docs/sbom_generator.md`
- OSV Scanner: `/docs/osv_scanner.md`
- Scoring Model: `/docs/vulnerability_scoring.md`

#### Implemented Features
- **SBOM Generation**: Multi-language support via cdxgen/syft
- **OSV Database Integration**: Comprehensive CVE detection
- **Time-Decay Scoring**: Age-based vulnerability penalties
- **KEV Integration**: CISA Known Exploited Vulnerabilities
- **Remediation Priority**: Risk-based prioritization

---

### 4. Score Aggregator
**Location**: `/risk_armor/core/aggregator.py`
**Status**: ✅ Fully Implemented

#### Aggregation Formula
```python
# Normalize each pillar score (300-850) to 0-1
normalized = (score - 300) / 550

# Apply weights
final_normalized = (
    hygiene_norm * 0.30 +
    risk_norm * 0.40 +
    vulnerability_norm * 0.30
)

# Convert back to FICO scale
final_score = 300 + (final_normalized * 550)
```

#### Default Weights
- Hygiene: 30%
- Risk: 40%
- Vulnerability: 30%

*Note: Weights are configurable and automatically normalized to sum to 1.0*

---

## Data Flow

### 1. Repository Discovery
```
mcp_repositories.json (13,016 repos)
    ↓
Parse GitHub URLs
    ↓
Extract owner/repo pairs
```

### 2. Analysis Pipeline
```
For each repository:
    ↓
Clone/Download Repository
    ↓
Parallel Analysis:
    ├─→ Hygiene: GitHub API metrics
    ├─→ Risk: Semgrep security scan
    └─→ Vulnerability: CVE/dependency scan
    ↓
Aggregate Scores (weighted average)
    ↓
Generate FICO Score (300-850)
```

### 3. Report Generation
```
Security Score Results
    ↓
Report Generator
    ├─→ HTML: Interactive web report
    ├─→ Markdown: Documentation format
    ├─→ JSON: Machine-readable
    └─→ CSV: Spreadsheet analysis
```

---

## Scoring Interpretation

### FICO Score Ranges

| Score | Grade | Security Level | Description | Action Required |
|-------|-------|---------------|-------------|-----------------|
| 800-850 | A | Excellent | Well-maintained, secure repository | Production-ready |
| 740-799 | B+ | Very Good | Strong security practices | Minor improvements |
| 670-739 | B | Good | Adequate security measures | Some fixes needed |
| 580-669 | C | Fair | Moderate security concerns | Targeted remediation |
| 500-579 | D | Poor | Significant security issues | Major overhaul |
| 300-499 | F | Critical | Severe security problems | Immediate action |

### Score Components Example

```
Repository: example-mcp-server
═══════════════════════════════════════
Hygiene Score:      720 (B)  [25% weight]
Tools Score:        680 (B)  [35% weight]
Vulnerability:      750 (B+) [40% weight]
───────────────────────────────────────
FINAL SCORE:        712 (B - Good)
═══════════════════════════════════════
```

---

## Usage Examples

### Basic Usage

```python
import asyncio
from pathlib import Path

# Import components
from risk_armor.scoring.hygiene import MCPHygieneScorer
from mcp_security_scanner import MCPSecurityScanner
from risk_armor.core.aggregator import ScoreAggregator
from report_generator import ReportGenerator

async def analyze_mcp_repository(owner: str, repo: str):
    # Initialize components
    hygiene_scorer = MCPHygieneScorer()
    risk_scanner = MCPSecurityScanner()
    aggregator = ScoreAggregator()
    report_gen = ReportGenerator()

    # Step 1: Hygiene scoring (GitHub metrics)
    hygiene_result = await hygiene_scorer.score_repository(owner, repo)
    hygiene_score = hygiene_result['fico_score']

    # Step 2: Risk scoring (Semgrep + TruffleHog analysis)
    repo_path = f"/tmp/{repo}"  # Assuming cloned here

    # Option A: Separate scanning
    semgrep_result = await risk_scanner.scan_repository(repo_path)

    # Configure TruffleHog for ethical public repo scanning
    trufflehog_scanner = TruffleHogScanner(
        verify_secrets=False,  # Don't test credentials in public repos
        scan_history=True,     # Scan git history for exposure duration
        exclude_paths=[        # Additional exclusions if needed
            r"archived/",
            r"deprecated/"
        ]
    )
    secret_result = await trufflehog_scanner.scan_repository(repo_path)

    # Option B: Combined scanning
    from trufflehog_integration import CombinedRiskScanner
    combined_scanner = CombinedRiskScanner(
        semgrep_scanner=risk_scanner,
        trufflehog_scanner=TruffleHogScanner(
            verify_secrets=False,  # Ethical scanning
            scan_history=True
        )
    )
    risk_result = await combined_scanner.scan_repository(repo_path)
    risk_score = risk_result['combined_score']['fico_score']

    # Step 3: Vulnerability scoring (SBOM → OSV → Time-decay)
    from risk_armor.scoring.vulnerability.vulnerability_scorer import VulnerabilityScorer
    vuln_scorer = VulnerabilityScorer()
    vuln_result = await vuln_scorer.score_repository(repo_path)
    vuln_score = vuln_result.fico_score

    # Step 4: Aggregate scores
    final_result = aggregator.aggregate(
        hygiene=hygiene_score,
        risk=risk_score,
        vulnerability=vuln_score
    )

    # Step 5: Generate report
    report_data = {
        'repository': f"{owner}/{repo}",
        'hygiene_score': hygiene_score,
        'risk_score': risk_score,
        'vulnerability_score': vuln_score,
        'final_score': final_result.final_score,
        'scored_at': datetime.now().isoformat()
    }

    report_path = report_gen.generate_report(
        report_data,
        format='html'
    )

    return final_result

# Run analysis
result = asyncio.run(analyze_mcp_repository("modelcontextprotocol", "servers"))
print(f"Final FICO Score: {result.final_score}")
```

### Batch Processing

```python
async def analyze_all_mcp_repos():
    import json

    # Load repository list
    with open('mcp_repositories.json') as f:
        repos = json.load(f)

    # Process in batches
    batch_size = 10
    results = []

    for i in range(0, len(repos), batch_size):
        batch = repos[i:i+batch_size]

        # Process batch concurrently
        tasks = []
        for repo in batch:
            # Extract owner/repo from URL
            parts = repo['url'].split('/')
            owner = parts[-2]
            name = parts[-1]

            task = analyze_mcp_repository(owner, name)
            tasks.append(task)

        batch_results = await asyncio.gather(*tasks)
        results.extend(batch_results)

    return results
```

---

## Configuration

### Environment Variables

```bash
# Required
export GITHUB_TOKEN='ghp_xxxxxxxxxxxx'

# Optional: Token rotation
export GITHUB_TOKEN_2='ghp_yyyyyyyyyyyy'
export GITHUB_TOKEN_3='ghp_zzzzzzzzzzzz'

# Optional: Cache settings
export CACHE_DIR='/path/to/cache'
export CACHE_TTL='3600'  # seconds

# Optional: Semgrep settings
export SEMGREP_RULES_DIR='/path/to/rules'
export SEMGREP_TIMEOUT='300'  # seconds
```

### Configuration Files

#### `risk_armor/config/hygiene_config.yaml`
```yaml
# Score overrides for specific repos
score_overrides:
  "modelcontextprotocol/servers": 850
  "example/broken-repo": 300

# Component weights
component_weights:
  documentation: 0.10
  license: 0.05
  tests: 0.10
  ci_cd: 0.10
  issue_activity: 0.10
  pr_activity: 0.10
  dependencies: 0.10
  security: 0.10
  code_review: 0.05
  releases: 0.10
  community: 0.10

# MCP-specific thresholds
mcp_thresholds:
  healthy_pr_days: 90
  healthy_issue_days: 120
  min_stars: 5
  min_contributors: 1
```

---

## Deployment Guide

### Prerequisites

```bash
# System requirements
- Python 3.7+
- Git
- 4GB RAM minimum
- 10GB disk space for repo clones

# Install dependencies
pip install -r requirements.txt
pip install semgrep

# Install TruffleHog for secret detection
pip install truffleHog3
# OR
brew install trufflehog

# Install SBOM generators
npm install -g @cyclonedx/cdxgen  # For cdxgen
brew install syft                  # For syft

# Install OSV Scanner
go install github.com/google/osv-scanner/cmd/osv-scanner@latest
# OR download binary from GitHub releases
```

### Installation Steps

1. **Clone the repository**
```bash
git clone <repository>
cd mcp-security-system
```

2. **Install Python dependencies**
```bash
pip install -r risk_armor/requirements.txt
pip install semgrep aiohttp python-dotenv pyyaml diskcache
```

3. **Configure GitHub token**
```bash
export GITHUB_TOKEN='your-github-token'
```

4. **Verify Semgrep installation**
```bash
semgrep --version
```

5. **Run test suite**
```bash
python risk_armor/tests/test_hygiene_scorer.py
python -m pytest
```

### Production Deployment

#### Docker Container
```dockerfile
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y git

# Copy application
COPY . /app

# Install Python dependencies
RUN pip install -r risk_armor/requirements.txt
RUN pip install semgrep

# Set environment
ENV GITHUB_TOKEN=${GITHUB_TOKEN}
ENV PYTHONPATH=/app

CMD ["python", "main.py"]
```

#### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-security-scanner
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: scanner
        image: mcp-security:latest
        env:
        - name: GITHUB_TOKEN
          valueFrom:
            secretKeyRef:
              name: github-token
              key: token
        resources:
          requests:
            memory: "2Gi"
            cpu: "1"
          limits:
            memory: "4Gi"
            cpu: "2"
```

---

## API Endpoints (Planned)

### REST API Design

```
GET /api/v1/score/{owner}/{repo}
    → Returns current security score

POST /api/v1/scan
    Body: {"repository": "owner/repo"}
    → Triggers new scan

GET /api/v1/report/{scan_id}
    → Returns scan report

GET /api/v1/stats
    → Returns system statistics

GET /api/v1/leaderboard
    → Returns top scored repositories
```

---

## Performance Characteristics

### Scanning Performance
- **Single Repository**: ~30-60 seconds
- **Batch Processing**: 10 repos/minute with 3 workers
- **Full Dataset**: ~22 hours for 13,016 repos

### Resource Usage
- **Memory**: 500MB-2GB per scan
- **CPU**: 1-2 cores per concurrent scan
- **Disk**: 100MB-1GB per repository
- **Network**: ~10MB per GitHub API call

### Optimization Strategies
1. **Caching**: 1-hour TTL for GitHub data
2. **Token Rotation**: Avoid rate limits
3. **Parallel Processing**: Concurrent scanning
4. **Incremental Updates**: Only rescan changed repos
5. **Database Storage**: Store results for quick retrieval

---

## Monitoring & Observability

### Key Metrics
- Scan completion rate
- Average scan duration
- API rate limit usage
- Cache hit ratio
- Error rates by component

### Logging
```python
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('mcp_security.log'),
        logging.StreamHandler()
    ]
)
```

### Health Checks
```python
async def health_check():
    checks = {
        'github_api': check_github_connection(),
        'semgrep': check_semgrep_installation(),
        'disk_space': check_disk_space(),
        'memory': check_memory_usage()
    }
    return all(checks.values())
```

---

## Security Considerations

### Sensitive Data Handling
- GitHub tokens stored in environment variables
- No credentials in logs
- Sanitized error messages
- Secure API endpoints with authentication

### Ethical Scanning of Public Repositories
- **Never verify secrets**: Use `verify_secrets=False` for public repos
- **Responsible disclosure**: Report findings without exposing actual secrets
- **No exploitation**: Detection only, no testing of found credentials
- **Rate limiting respect**: Don't overwhelm repository hosting services
- **Legal compliance**: Ensure scanning complies with terms of service

### Exclusion Strategy for Accuracy
- **Smart filtering**: Exclude 100+ patterns (node_modules, .git, build artifacts)
- **Focus on source code**: Skip dependencies, compiled files, test data
- **Reduce false positives**: Filter placeholders, hashes, dev URLs
- **Still catch real issues**: Force-scan .env, config, credentials files

### Rate Limiting
- GitHub API: 5,000 requests/hour per token
- Token rotation for higher throughput
- Exponential backoff on rate limit errors
- TruffleHog: Respect repository size limits

### Access Control
- Read-only GitHub access
- Sandboxed Semgrep execution
- Limited file system access
- Container isolation in production
- No credential verification in public repos

---

## Troubleshooting

### Common Issues

1. **GitHub API Rate Limit**
   - Solution: Add more tokens for rotation
   - Check: `curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/rate_limit`

2. **Semgrep Timeout**
   - Solution: Increase timeout or reduce rule complexity
   - Check: Run with `--verbose` flag

3. **Memory Issues**
   - Solution: Reduce batch size or increase memory
   - Monitor: `htop` or `docker stats`

4. **Cache Corruption**
   - Solution: Clear cache directory
   - Command: `rm -rf risk_armor/cache/*`

---

## Future Enhancements

### Phase 1: Core Improvements
- [ ] Complete vulnerability scanner implementation
- [ ] Add PostgreSQL database storage
- [ ] Implement REST API
- [ ] Create web dashboard

### Phase 2: Advanced Features
- [ ] Machine learning for anomaly detection
- [ ] Trend analysis and predictions
- [ ] Integration with CI/CD pipelines
- [ ] Slack/Discord notifications

### Phase 3: Ecosystem Integration
- [ ] GitHub App marketplace listing
- [ ] VS Code extension
- [ ] Command-line tool distribution
- [ ] SaaS platform deployment

---

## Contributing

### Development Setup
```bash
# Clone repository
git clone <repo>
cd mcp-security-system

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
pytest
```

### Code Standards
- Type hints for all functions
- Comprehensive docstrings
- 80% test coverage minimum
- Black formatting
- Pylint score > 8.0

---

## License & Legal

**Proprietary Software - All Rights Reserved**

This system is proprietary software developed by Risk Armor. Unauthorized copying, modification, or distribution is prohibited.

### Third-Party Licenses
- Semgrep: LGPL-2.1
- GitHub API: Subject to GitHub Terms
- Python dependencies: Various OSS licenses

---

## Support

For technical support, bug reports, or feature requests:
- Email: support@riskarmor.dev
- GitHub Issues: [repository]/issues
- Documentation: [repository]/docs

---

## Appendix

### A. Data Schema

#### SecurityScore Object
```json
{
  "repository": "owner/repo",
  "hygiene_score": 720,
  "risk_score": 680,
  "vulnerability_score": 750,
  "final_score": 708,
  "deployment_mode": "standalone",
  "findings": [...],
  "metadata": {
    "scanned_at": "2024-01-20T10:30:00Z",
    "version": "2.0"
  }
}
```

### B. Semgrep Rule Example
```yaml
rules:
  - id: mcp-py-missing-auth
    message: "MCP endpoint lacks authentication"
    severity: high
    languages: [python]
    patterns:
      - pattern: |
          @app.route(...)
          def $FUNC(...):
              ...
      - pattern-not: |
          if request.headers.get("Authorization"):
              ...
    metadata:
      category: security
      mcp_specific: true
```

### C. Repository Statistics
- Total MCP Repositories: 13,016
- Languages: Python (40%), JavaScript (35%), Go (15%), Other (10%)
- Average Repository Age: 6 months
- Active Maintainers: ~2,000

---

## Related Documentation

### Component-Specific Documentation
- **Semgrep Component**: `/docs/semgrep_component.md` - Detailed documentation for the Semgrep security scanning component
- **TruffleHog Component**: `/docs/trufflehog_component.md` - Comprehensive documentation for the TruffleHog secret detection component
- **TruffleHog Best Practices**: `/docs/trufflehog_best_practices.md` - Guidelines for ethical and effective secret scanning

---

*Document Version: 2.1*
*Last Updated: 2024*
*System Status: Operational*