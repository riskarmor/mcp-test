# MCP Risk Assessment Scoring System

## Overview

The MCP Risk Assessment Tool implements a sophisticated three-component scoring system that produces FICO-style security scores (300-850) for Model Context Protocol repositories.

## Scoring Architecture

### FICO Score Range (300-850)
- **800-850**: Excellent - Very few security issues detected
- **740-799**: Very Good - Minor security issues present
- **670-739**: Good - Some security issues need attention
- **580-669**: Fair - Multiple security issues require remediation
- **500-579**: Poor - Significant security issues found
- **300-499**: Very Poor - Critical security issues require immediate action

## Three-Component System

### 1. Hygiene Score (25% weight)
**File**: `scoring/hygiene_scorer.py`
**Purpose**: Evaluates repository health and maintenance practices

#### Metrics Analyzed:
- **Commit Activity** (20%)
  - Frequency and recency of commits
  - Active development indicators
- **Documentation** (20%)
  - README presence and quality
  - Documentation completeness
- **Community Engagement** (20%)
  - Stars, forks, watchers
  - Contributor diversity
- **Issue Management** (15%)
  - Open vs closed issues ratio
  - Response times
- **Pull Request Activity** (15%)
  - PR merge rate
  - Review practices
- **Release Management** (10%)
  - Version tagging
  - Release frequency

#### Implementation Notes:
- Uses GitHub GraphQL API for efficient data fetching
- Requires async execution
- Caches results for 24 hours
- Returns full metrics breakdown

### 2. Tools Score (35% weight)
**File**: `scoring/tools_scorer.py`
**Purpose**: Combines security tool findings from static analysis and secret detection

#### Tool Integration:
- **Semgrep** (60% of tools score)
  - Static code analysis
  - Security pattern detection
  - Code quality issues
- **TruffleHog** (40% of tools score)
  - Secret detection
  - Credential scanning
  - Verified secrets get 2x penalty

#### Severity Deductions:
**Semgrep** (max 330 points):
- Critical: -80 points
- High: -50 points
- Medium: -20 points
- Low: -5 points
- Info: -1 point

**TruffleHog** (max 220 points):
- Verified Critical: -200 points
- Verified High: -180 points
- Verified Medium: -150 points
- Verified Low: -100 points
- Unverified reduced by ~50%

### 3. Vulnerability Score (40% weight)
**File**: `scoring/vulnerability_scorer.py`
**Purpose**: Time-decay scoring for known vulnerabilities

#### Features:
- **OSV Scanner Integration**
  - CVE detection in dependencies
  - SBOM-based analysis
- **CISA KEV Integration**
  - Known Exploited Vulnerabilities
  - 2x penalty multiplier
- **Time-Decay Penalties**
  - Older vulnerabilities score worse
  - Incentivizes quick patching

#### Decay Rates (per day):
- Critical: -2.0 points/day
- High: -1.0 points/day
- Medium: -0.5 points/day
- Low: -0.1 points/day
- Unknown: -0.3 points/day

#### Special Rules:
- Max age penalty at 90 days
- Ancient penalty: -50 for vulns > 365 days
- Critical > 30 days old caps score at 579

## Score Aggregation

**File**: `scoring/aggregator.py`
**Purpose**: Combines three component scores into final FICO score

### Calculation Process:
1. Normalize each score from FICO (300-850) to 0-1 range
2. Apply weights (25%, 35%, 40%)
3. Calculate weighted average
4. Convert back to FICO scale
5. Round to nearest integer

### Formula:
```python
normalized = (score - 300) / 550
weighted_avg = (hygiene * 0.25 + tools * 0.35 + vulnerability * 0.40)
final_score = round(300 + weighted_avg * 550)
```

## Implementation Details

### Data Flow:
1. **main.py** orchestrates the scoring process
2. Each scorer independently calculates its FICO score
3. Aggregator combines scores with weights
4. Final score returned with full breakdown

### Score Consistency:
- All components output FICO scores (300-850)
- No score bonuses (only deductions)
- Consistent interpretation across components
- Transparent weight distribution

### Error Handling:
- Failed scans return neutral scores (600-670)
- Missing data uses safe defaults
- All errors logged with context
- Graceful degradation

## Usage Example

```python
# In main.py
hygiene_score = await hygiene_scorer.score_repository(owner, repo)
tools_score = tools_scorer.calculate_score(semgrep_findings, trufflehog_findings)
vuln_score = vulnerability_scorer.calculate_score(osv_results, repo_url)

final_score = score_aggregator.aggregate_scores({
    'hygiene': hygiene_score['fico_score'],
    'tools': tools_score['fico_score'],
    'vulnerability': vuln_score.fico_score
})
```

## Score Interpretation Guide

### Score Ranges and Actions:
- **800+**: Minimal risk, maintain current practices
- **740-799**: Low risk, address minor issues
- **670-739**: Moderate risk, plan remediation
- **580-669**: Elevated risk, prioritize fixes
- **500-579**: High risk, immediate action needed
- **Below 500**: Critical risk, emergency response

### Component Analysis:
- Low hygiene: Poor maintenance, potential abandonment
- Low tools: Code quality issues, possible secrets
- Low vulnerability: Unpatched CVEs, security debt

## Configuration

### Weights (Database-Configurable):
```sql
-- Default weights in scoring_config table
INSERT INTO scoring_config (component, weight) VALUES
  ('hygiene', 0.25),
  ('tools', 0.35),
  ('vulnerability', 0.40);
```

### Customization:
- Weights can be adjusted per organization
- Tag-based policy application
- Custom thresholds for alerts
- Tenant-specific scoring rules

## Testing

### Verify Scoring:
```bash
python3 -c "
from scoring.aggregator import ScoreAggregator
agg = ScoreAggregator()
# Example scores
scores = {'hygiene': 750, 'tools': 650, 'vulnerability': 600}
final = agg.aggregate_scores(scores)
print(f'Final FICO Score: {final}')
"
```

### Expected Output:
- Clean repository: 800-850
- Average repository: 600-700
- Problematic repository: 400-500

## Performance Considerations

- Hygiene scorer requires GitHub API (rate limited)
- Tools scoring is CPU-intensive (Semgrep)
- Vulnerability scoring uses caching (24h TTL)
- Aggregation is instant (simple math)

## Future Enhancements

- Machine learning for score calibration
- Industry-specific weight profiles
- Peer comparison scoring
- Trend analysis and predictions
- Automated remediation suggestions

---

Last Updated: 2025-01-23
Version: 1.0