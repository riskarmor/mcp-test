# CLAUDE.md - MCP Risk Assessment Tool Project Guide

## Project Overview

This is the MCP Risk Assessment Tool - a comprehensive security scoring and detection system for Model Context Protocols (MCPs). The system analyzes public GitHub repositories containing MCPs, generates FICO-style security scores (300-850), and creates network detection rules to identify MCPs on enterprise networks.

## Critical Project Rules

### 1. Never Make Assumptions
- **ALWAYS** ask clarifying questions when requirements are unclear
- **NEVER** implement features without confirming with the user
- **ALWAYS** verify understanding before proceeding with code changes

### 2. Virtual Environment
- **ALL** Python code must run in `/mnt/prod/venv`
- **ALWAYS** activate with: `source /mnt/prod/venv/bin/activate`
- **NEVER** install packages globally

### 3. Database Configuration
- **NEVER** hardcode configuration values in code
- **ALL** configuration must be stored in PostgreSQL database
- **USE** `.env` file for database credentials only
- **Database**: `mcp_security`
- **User**: `postgres_user`
- **Password**: `r$quaZ`

### 4. Security First
- **NEVER** store secrets in code
- **NEVER** commit credentials to repository
- **ALWAYS** use parameterized queries (no SQL injection)
- **ALWAYS** validate all user inputs
- **ALWAYS** encrypt sensitive data

## Core System Architecture

### Scoring System
- **Range**: 300-850 (FICO-style)
- **Default Weights** (security-focused):
  - Hygiene Score: 25%
  - Tools Score: 35% (Semgrep + TruffleHog findings)
  - Vulnerability Score: 40%
- **Multi-tenant**: Organizations can create custom scoring policies
- **Tag-based**: AWS-style tags (key:value) for policy application
- **Dual Scoring**: Always show both base score and custom score

### Key Features
1. **MCP Analysis**:
   - Public GitHub repositories only
   - Daily lightweight version checks
   - Full rescan on changes
   - Track all version history

2. **Detection Rules**:
   - Multiple formats: Snort, YARA, Sigma, Zeek, Suricata, OSSEC
   - Per-MCP rule generation
   - All detection scopes (identity, behavior, vulnerability, anomaly, risk)

3. **Multi-tenant Architecture**:
   - Organization isolation
   - Master admin with role delegation
   - Tag-based policy management
   - Complete audit logging

4. **Storage Strategy**:
   - PostgreSQL for all data (no S3/cloud storage)
   - SBOMs as JSONB in database
   - Repository code stored locally
   - Reports stored locally with DB paths

## Technical Stack

### Backend
- **Language**: Python 3.9+
- **API**: RESTful (not GraphQL)
- **Database**: PostgreSQL 16
- **Queue**: Redis for async tasks
- **Framework**: FastAPI or Flask

### Frontend
- **Framework**: React or Vue.js
- **Visualization**: Charts.js or D3.js
- **Real-time**: WebSocket for updates

### Security Tools
- **SBOM**: Syft
- **Vulnerability**: Grype, OSV Scanner
- **Secrets**: TruffleHog, GitLeaks
- **SAST**: Semgrep, Bandit
- **Dependencies**: pip-audit, Safety

### Integrations
- **SIEM**: Splunk, QRadar, Sentinel, ElasticSearch
- **Ticketing**: ServiceNow, Jira, PagerDuty
- **Formats**: CEF, LEEF, Syslog

## Development Standards

### Code Quality
- **Style**: PEP 8 (enforced with Black)
- **Type Hints**: Required for all functions
- **Docstrings**: Google style for all public functions
- **Line Length**: 120 characters maximum
- **Tools**: Black, Pylint, mypy, isort

### Testing
- **Coverage**: 80% minimum overall
- **Critical Functions**: 100% coverage required
- **Framework**: pytest with pytest-cov
- **Types**: Unit, Integration, E2E, Performance, Security

### Documentation
- **Code**: Docstrings for all modules/functions
- **API**: OpenAPI 3.0 with Swagger UI
- **User**: Getting Started, Admin, Troubleshooting guides
- **Dev**: Architecture, Schema, Contributing guides

### CI/CD
- **Platform**: GitHub Actions
- **Triggers**: PRs and main branch commits
- **Quality Gates**: Tests, coverage, security, reviews
- **Environments**: Development, Staging, Production

## Project Structure

```
/mnt/prod/mcp/
├── .env                    # Database credentials (never commit)
├── CLAUDE.md              # This file - project guardrails
├── PROJECT_QUESTIONS.md  # Complete requirements documentation
├── README.md              # User-facing documentation
│
├── storage/               # Repository storage system
│   ├── repository_storage.py  # Git operations
│   ├── storage_manager.py     # Disk management
│   ├── cache_manager.py       # Cache handling
│   ├── mcp_optimizer.py       # MCP-specific optimizations
│   └── monitor.py             # Storage monitoring
│
├── api/                   # RESTful API implementation
│   ├── endpoints/         # API route handlers
│   ├── models/           # Pydantic models
│   └── middleware/       # Auth, logging, etc.
│
├── core/                 # Core business logic
│   ├── scoring/         # Scoring algorithms
│   ├── scanning/        # MCP scanning logic
│   └── detection/       # Rule generation
│
├── database/            # Database related
│   ├── init/           # Schema initialization
│   ├── migrations/     # Alembic migrations
│   └── models/         # SQLAlchemy models
│
├── services/           # External service integrations
│   ├── github/        # GitHub API client
│   ├── siem/          # SIEM integrations
│   └── ticketing/     # Ticketing integrations
│
├── tests/             # Test suite
│   ├── unit/         # Unit tests
│   ├── integration/  # Integration tests
│   └── fixtures/     # Test data
│
└── ui/               # Web interface
    ├── src/         # React/Vue source
    └── public/      # Static assets
```

## Database Schema Key Tables

- `repositories` - MCP repository information
- `scans` - Scan history and status
- `vulnerabilities` - CVE/vulnerability findings
- `secrets` - Encrypted secret findings
- `security_scores` - FICO scores per scan
- `score_history` - Historical score tracking
- `sboms` - Software bill of materials
- `dependencies` - Package dependencies
- `api_keys` - API authentication
- `audit.audit_log` - Complete audit trail

## Implementation Priorities

1. **Phase 1 - Core Functionality**:
   - Database schema setup
   - Basic MCP scanning
   - Three-component scoring
   - RESTful API

2. **Phase 2 - Multi-tenancy**:
   - Organization management
   - Tag-based policies
   - Custom scoring configs
   - Role-based access

3. **Phase 3 - Detection Rules**:
   - Rule generation engine
   - Multiple format support
   - Per-MCP rulesets

4. **Phase 4 - Integrations**:
   - SIEM connectors
   - Ticketing systems
   - Webhook support

5. **Phase 5 - UI & Visualization**:
   - Web dashboard
   - Score visualizations
   - Report generation

## Common Commands

```bash
# Activate virtual environment
source /mnt/prod/venv/bin/activate

# Test database connection
python verify_db_connection.py

# Run tests
pytest tests/ -v --cov=.

# Format code
black . --line-length 120

# Type checking
mypy .

# Start development server
python main.py

# Database migrations
alembic upgrade head
```

## Environment Variables (.env)

```
# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=mcp_security
DB_USER=postgres_user
DB_PASSWORD=r$quaZ

# GitHub
GITHUB_TOKEN=<your_token>

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=mcp_redis_password
```

## Important Notes

1. **GitHub API**: Always use token from .env, optimize calls to avoid rate limits
2. **Scoring**: Track all changes with timestamps and reasons
3. **Security**: Public MCPs only, no private repository access
4. **Performance**: Daily lightweight checks, full scan only on changes
5. **Compliance**: Built with future compliance in mind (SOC2, ISO 27001)
6. **Audit**: Log everything that could impact scoring or security

## When Working on This Project

1. **Read** `PROJECT_QUESTIONS.md` for complete requirements
2. **Check** existing code patterns before implementing new features
3. **Ask** for clarification on any unclear requirements
4. **Test** all changes with appropriate coverage
5. **Document** all new functionality
6. **Never** hardcode configuration values
7. **Always** consider multi-tenant implications
8. **Track** all work using the TodoWrite tool

## Support Contacts

- **Documentation Issues**: Create issue in project repository
- **Security Concerns**: Follow responsible disclosure process
- **Feature Requests**: Document in PROJECT_QUESTIONS.md first

---

*This document is the source of truth for project guardrails and must be consulted before making any architectural decisions or significant code changes.*