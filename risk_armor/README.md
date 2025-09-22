# Risk Armor Security Analysis Platform

**Author:** Risk Armor
**License:** Proprietary - All Rights Reserved

## Overview

Risk Armor is a comprehensive repository security scoring system that analyzes GitHub repositories across three critical pillars to produce FICO-style security scores (300-850 range).

## Three-Pillar Architecture

### 1. Hygiene Score (30% weight)
- **Module:** `scoring/hygiene/`
- **Components:** GitHub maintenance metrics, OpenSSF Scorecard
- **Status:** ✅ Implemented (v2.0)

### 2. Risk Score (40% weight)
- **Module:** `scoring/risk/`
- **Components:** Semgrep static analysis, TruffleHog secret scanning
- **Status:** 🚧 Planned

### 3. Vulnerability Score (30% weight)
- **Module:** `scoring/vulnerability/`
- **Components:** OSV vulnerability scan, License analysis
- **Status:** 🚧 Planned

## Directory Structure

```
risk_armor/
├── core/                   # Core components
│   ├── aggregator.py      # Score aggregation logic
│   └── __init__.py
├── scoring/               # Three-pillar scoring modules
│   ├── hygiene/          # Repository hygiene scoring
│   │   ├── hygiene_scorer.py
│   │   ├── hygiene_scorer_v1.py (legacy)
│   │   └── __init__.py
│   ├── risk/             # Security risk analysis
│   │   └── __init__.py
│   └── vulnerability/    # Vulnerability detection
│       └── __init__.py
├── api/                  # REST API endpoints
├── utils/                # Utility functions
├── config/               # Configuration files
│   └── hygiene_config.yaml
├── tests/                # Test suite
│   └── test_hygiene_scorer.py
├── cache/                # API response cache
├── data/                 # Data storage
├── docs/                 # Documentation
├── requirements.txt      # Python dependencies
└── __init__.py
```

## Features

### Hygiene Scoring (Implemented)
- **GraphQL API Optimization**: Single query for all metrics
- **Intelligent Caching**: Reduces API calls with 1-hour TTL
- **MCP-Specific Detection**: Identifies MCP configuration and server files
- **Stale Detection**: Uses last activity date, not creation date
- **Token Rotation**: Supports multiple GitHub tokens with smart rotation
- **Error Resilience**: Handles partial GraphQL responses gracefully
- **Weighted Components**: 11 scoring factors with MCP-calibrated thresholds

## Installation

```bash
# Install dependencies
pip install -r risk_armor/requirements.txt

# Set up environment
export GITHUB_TOKEN='your-github-token'
# Optional: Add more tokens for rotation
export GITHUB_TOKEN_2='backup-token'
export GITHUB_TOKEN_3='another-token'
```

## Usage

### Basic Hygiene Scoring

```python
from risk_armor.scoring.hygiene import MCPHygieneScorer

# Initialize scorer
scorer = MCPHygieneScorer(config_path="risk_armor/config/hygiene_config.yaml")

# Score a single repository
result = await scorer.score_repository("modelcontextprotocol", "servers")
print(f"FICO Score: {result['fico_score']}")

# Score multiple repositories
repos = [
    ("owner1", "repo1"),
    ("owner2", "repo2")
]
results = await scorer.score_multiple(repos)
```

### Score Aggregation

```python
from risk_armor.core.aggregator import ScoreAggregator

# Create aggregator with custom weights (optional)
aggregator = ScoreAggregator({
    'hygiene': 0.25,
    'risk': 0.50,
    'vulnerability': 0.25
})

# Aggregate scores
security_score = aggregator.aggregate(
    hygiene=750,
    risk=620,
    vulnerability=700
)
print(f"Final Security Score: {security_score.final_score}")
```

## Configuration

Edit `risk_armor/config/hygiene_config.yaml` to:
- Override scores for specific repositories
- Customize scoring thresholds
- Adjust component weights
- Configure cache settings
- Set rate limiting parameters

## MCP Calibration

The system is specifically calibrated for MCP (Model Context Protocol) repositories:
- Lower activity thresholds (1 PR in 90 days is healthy)
- MCP-specific file detection (mcp.json, server implementations)
- More tolerant stale detection (90 days for PRs, 120 for issues)
- Young repository bonus (new tools aren't penalized)

## Score Interpretation

| FICO Score | Rating | Description |
|------------|--------|-------------|
| 800-850 | Excellent | Well-maintained, secure repository |
| 740-799 | Very Good | Strong security practices |
| 670-739 | Good | Adequate security measures |
| 580-669 | Fair | Some security concerns |
| 500-579 | Poor | Significant security issues |
| 300-499 | Very Poor | Critical security problems |

## Testing

```bash
cd risk_armor
python tests/test_hygiene_scorer.py
```

## Future Development

- [ ] Implement Risk Scoring module (Semgrep + TruffleHog)
- [ ] Implement Vulnerability Scoring module (OSV + License)
- [ ] Add REST API endpoints
- [ ] Create web dashboard
- [ ] Add batch processing capabilities
- [ ] Implement webhook integrations
- [ ] Add OpenSSF Scorecard integration

## Support

For issues or questions, contact the Risk Armor development team.

---

© Risk Armor - Proprietary Software