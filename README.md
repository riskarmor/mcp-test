# MCP Risk Assessment Tool

A comprehensive security scoring and detection system for Model Context Protocol (MCP) repositories. The system analyzes public GitHub repositories containing MCPs, generates FICO-style security scores (300-850), and creates network detection rules to identify MCPs on enterprise networks.

## Overview

The MCP Risk Assessment Tool provides:
- **Three-component security scoring** with FICO-style output (300-850)
- **Automated security scanning** using industry-standard tools (Semgrep, TruffleHog, OSV)
- **Time-decay vulnerability scoring** that penalizes older vulnerabilities
- **Multi-tenant architecture** with custom scoring policies
- **Detection rule generation** in multiple formats (Snort, YARA, Sigma, etc.)
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
│   ├── hygiene_scorer.py      # GitHub health metrics (25% weight)
│   ├── tools_scorer.py        # Semgrep + TruffleHog (35% weight)
│   ├── vulnerability_scorer.py # Time-decay scoring (40% weight)
│   └── aggregator.py          # Final score calculation
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