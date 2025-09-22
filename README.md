# MCP Security Analysis System

A comprehensive security analysis system for scoring 13,016+ public GitHub repositories using multiple security tools and FICO-style scoring.

## Overview

The MCP Security Analysis System provides automated security assessment of public GitHub repositories through:

- **Multi-tool scanning**: Semgrep, TruffleHog, OSV Scanner
- **SBOM generation**: Comprehensive dependency analysis
- **FICO-style scoring**: 300-850 range based on three pillars
- **Time-decay penalties**: Incentivizes quick vulnerability patching
- **Defense-in-depth security**: Safe processing of untrusted repositories

## Project Structure

```
mcp/
├── main.py                 # Main orchestrator
├── scanners/              # Security scanning tools
│   ├── semgrep_scanner.py
│   ├── trufflehog_scanner.py
│   ├── osv_scanner.py
│   └── sbom_generator.py
├── scoring/               # Scoring modules
│   ├── hygiene_scorer.py
│   ├── risk_scorer.py
│   ├── vulnerability_scorer.py
│   └── aggregator.py
├── security/              # Security controls
│   ├── validators.py
│   ├── database.py
│   ├── storage.py
│   └── config.py
├── github/                # GitHub integration
│   └── fetcher.py
├── rules/                 # Scanning rules
│   └── semgrep/
├── docs/                  # Documentation
└── tests/                 # Test suite
```

## Quick Start

### Single Repository Analysis

```bash
python main.py analyze --repo https://github.com/owner/repo
```

### Batch Analysis

```bash
python main.py batch --repos-file repositories.txt --max-concurrent 10
```

### View Statistics

```bash
python main.py stats
```

## Scoring System

The system uses a three-pillar scoring model:

1. **Hygiene (30%)**: Secret detection and credential management
2. **Risk (40%)**: Code quality and security patterns
3. **Vulnerability (30%)**: Known vulnerabilities with time decay

Final scores range from 300-850 (FICO-style):

- **800-850**: Excellent security posture
- **740-799**: Very good security
- **670-739**: Good security
- **580-669**: Fair security
- **300-579**: Poor security

## Security Features

- **Input validation**: Prevents injection attacks
- **Repository isolation**: Each repo processed in isolation
- **Malware scanning**: Pre-storage malware detection
- **Quarantine system**: Automatic isolation of suspicious content
- **Rate limiting**: Respects GitHub API limits
- **Audit logging**: Complete activity tracking

## Configuration

Edit `config.yaml` to customize:

```yaml
security_level: HIGH
github_token: ${GITHUB_TOKEN}
storage_path: /opt/mcp/storage
max_repo_size_mb: 500
enable_malware_scan: true
```

## Documentation

- [Security Controls](docs/security_controls.md)
- [Component Documentation](docs/components/)
- [API Reference](docs/api/)

## License

Proprietary - MCP Security Team

## Contact

For security issues or questions, contact the MCP Security Team.