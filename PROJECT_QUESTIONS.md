# MCP Risk Assessment Tool - Project Clarification Questions

## Overview
This document tracks all clarifying questions for the MCP Risk Assessment Tool project. Each question will be marked as answered (✅) or pending (⬜), with responses documented below.

---

## 1. Scoring System Details

### ✅ 1.1 Score Range
**Question:** What should be the score range? (You mentioned FICO-like, so 300-850?)

**Answer:**
**300-850** (FICO standard range)
- Confirmed: Using FICO-like scoring range of 300-850
- This is already implemented in the hygiene scoring code
- Provides familiar risk categories: Poor (300-579), Fair (580-669), Good (670-739), Very Good (740-799), Excellent (800-850)

### ✅ 1.2 Component Weights
**Question:** For the three main components (Hygiene, Tools, Vulnerability), what default weights should they have? (e.g., 30%, 40%, 30%?)

**Answer:**
**Security-focused weights:**
- **Hygiene**: 25% (0.25) - Repository health and maintenance practices
- **Tools**: 35% (0.35) - Security tool findings (Semgrep code issues + TruffleHog secrets)
- **Vulnerability**: 40% (0.40) - Known CVEs and security vulnerabilities

This prioritizes vulnerability detection while maintaining strong emphasis on proactive security issue identification.

### ✅ 1.3 Sub-Component Weights
**Question:** Should sub-components also have configurable weights?

**Answer:**
**Yes - Database-driven configuration**
- Sub-components will have configurable weights stored in the database
- No hardcoded weights in code - all configuration comes from database
- Default weights loaded into database during initial setup
- Weights can be configured at multiple levels:
  - Global defaults
  - Tenant-specific overrides
  - Environment/tag-based overrides
- Automatic normalization if weights don't sum to 1.0
- Configuration changes tracked in audit log

This provides maximum flexibility while maintaining consistency and auditability.

### ✅ 1.4 Environment Thresholds
**Question:** Should there be a minimum score threshold for different environments?

**Answer:**
**No built-in thresholds - Organization managed via tags**
- System provides default scoring configuration only
- Organizations define their own scoring rules and thresholds
- Custom scores are applied via tags (e.g., env:prod, team:security, location:us-west)
- Organizations can:
  - Create custom scoring configurations
  - Assign configurations to specific tags/tag combinations
  - Manage their own thresholds and policies
  - Decide how to enforce scores (blocking, alerting, etc.)
- System is policy-agnostic - provides scores, organizations decide actions

This approach provides maximum flexibility for organizations to implement their own risk management policies.

---

## 2. MCP Source and Versioning

### ✅ 2.1 JSON Source Updates
**Question:** The JSON file with MCP names/URLs - is this a one-time import or regularly updated?

**Answer:**
**One-time import + API for additions**
- JSON file is a one-time import for initial MCP list
- API endpoint will be provided to add new MCPs
  - Required fields: name, GitHub URL
  - API will validate GitHub URL format
  - Duplicate URL detection
  - Returns MCP ID for tracking
- No automatic re-importing of JSON file
- All subsequent MCPs added via API

This provides controlled, auditable MCP additions while maintaining data integrity.

### ✅ 2.2 Version Detection
**Question:** How do we detect new versions? (GitHub releases, tags, commits?)

**Answer:**
**Lightweight daily version check with optimized API calls**
- Separate version check process (not during hygiene checks)
- Uses GitHub token from .env file for authentication
- Single optimized API call per repository using GitHub GraphQL API to fetch:
  - Default branch HEAD commit SHA
  - Latest release tag (if available)
  - Last push timestamp
- Compare with stored version in database
- When change detected:
  - Queue MCP for full asynchronous rescan
  - Download codebase and run full security scans
  - Update scores and version history
- Batch API calls where possible to minimize rate limit usage
- Cache responses to avoid redundant calls

This keeps version checks lightweight and scalable while respecting API limits.

### ✅ 2.3 Version Tracking Scope
**Question:** Should we track all versions or just major/minor releases?

**Answer:**
**Track all changes that can impact users**
- Track every version that could affect someone using the MCP
- This includes:
  - Any commit to the default branch
  - New releases/tags
  - Security patches
  - Dependency updates
  - Configuration changes
- Daily version check captures current state
- If HEAD commit SHA differs from last scan, trigger rescan
- Store each scanned version with:
  - Commit SHA
  - Scan timestamp
  - Score at that version
  - Changes that triggered rescan
- This ensures users always have current risk assessment

The goal is comprehensive tracking of any change that could introduce risk or vulnerabilities.

### ✅ 2.4 Historical Scores
**Question:** Should we store historical scores for each version?

**Answer:**
**Yes - Complete historical tracking at all levels**
- Store all score changes at every level:
  - Overall FICO score (300-850)
  - Component scores (Hygiene, Tools, Vulnerability)
  - Sub-component scores (each individual metric)
- For each score change, track:
  - Previous score
  - New score
  - Delta (+/-)
  - Reason for change (new vulnerabilities, fixed issues, etc.)
  - Specific items that caused change
  - Timestamp
  - Version/commit SHA
- Enable visualization:
  - Time-series graphs showing score trends
  - Drill-down capability to see why scores changed
  - Highlight significant events (major drops/improvements)
  - Compare any two versions
- No data expiration - keep all history for trending

This provides complete auditability and enables root cause analysis for score changes.

---

## 3. Multi-Tenancy

### ✅ 3.1 Tenant Hierarchy
**Question:** What's the tenant hierarchy? (Organization → Environment → Location?)

**Answer:**
**Organization-based with tag-driven policies**
- **Hierarchy**: Platform → Organizations (Tenants) → Users → MCPs
- Each organization is a separate tenant with full isolation
- Each organization has:
  - One master admin (initial user who creates the org)
  - Master admin can invite/manage other users
  - Master admin assigns roles to users
  - Predefined roles (viewer, analyst, admin, etc.)
- MCPs are tracked at organization level
- Each MCP can have multiple tags assigned
- Tags are used to apply scoring policies (not hierarchical structure)
- Example: An MCP tagged with "env:prod, team:payments, region:us" gets specific scoring rules

This provides flexible policy management without rigid hierarchy constraints.

### ✅ 3.2 Custom Rules Scope
**Question:** Can tenants modify sub-component weights only, or add new scoring criteria?

**Answer:**
**Weights only (for now)**
- Organizations can modify weights at all levels:
  - Main component weights (Hygiene, Tools, Vulnerability)
  - Sub-component weights within each category
  - Weights automatically normalized to sum to 1.0
- Cannot add new scoring criteria or components
- Cannot create custom rules

**Future Wishlist:**
- Add custom scoring criteria to existing components
- Create custom Semgrep rules that affect scoring
- Define organization-specific security requirements
- Add custom sub-components with their own metrics

This keeps initial implementation manageable while providing essential customization.

### ✅ 3.3 Deviation Limits
**Question:** Should there be limits on how much tenants can deviate from base scores?

**Answer:**
**No limits - Full flexibility with transparency**
- Organizations can set any weights they want (including 0% or 100%)
- System always calculates and stores both:
  - Base score (using platform defaults)
  - Custom score (using organization's weights)
- Both scores visible for comparison
- This makes extreme deviations obvious
- Organizations accountable for their weight choices
- Enables A/B comparison of scoring strategies

**Future enhancements:**
- Industry benchmark scores for comparison
- Peer organization comparisons (anonymized)
- Recommendations when scores deviate significantly
- Risk alerts if custom scoring masks critical issues

This approach provides maximum flexibility while maintaining transparency and accountability.

### ✅ 3.4 Tag System
**Question:** How should tags work? (e.g., env:prod, location:us-west, team:security)

**Answer:**
**AWS-style tags with priority-based scoring**
- **Tag format**: Key:value pairs following AWS tagging rules
  - Keys: Max 128 characters
  - Values: Max 256 characters
  - Allowed characters: letters, numbers, spaces, +, -, =, ., _, :, /, @
  - Case-sensitive
  - No wildcards supported
- **Tag application**:
  - MCPs can have multiple tags
  - Tags assigned when MCP is added or edited
  - No tag inheritance
- **Scoring policy priority**:
  - Each scoring configuration has a priority weight
  - When multiple configs match an MCP's tags, highest priority wins
  - Organization sets priority when creating scoring configs
  - Example: "env:prod" config (priority 100) overrides "team:any" config (priority 50)
- **Conflict resolution**:
  - Explicit priority values prevent ambiguity
  - Same priority = most recently created wins
  - Base score always calculated as fallback

This provides clear, predictable policy application with AWS-familiar tagging.

---

## 4. Change Tracking

### ✅ 4.1 Change Detail Level
**Question:** What level of detail for score change documentation? Individual sub-component changes? Threshold-based notifications (e.g., >10 point change)?

**Answer:**
**Complete granular tracking of all changes**
- Track every change at all levels:
  - Overall FICO score changes
  - Component score changes (Hygiene, Tools, Vulnerability)
  - Sub-component score changes
  - Individual findings (each vulnerability, secret, code issue)
- For each finding, capture:
  - Type (CVE, secret, code pattern)
  - Severity/criticality
  - Location (file, line number)
  - First detected timestamp
  - Resolution timestamp (if fixed)
  - Impact on score
- Enable drill-down from any level:
  - FICO dropped 50 points → Vulnerability score decreased →
  - New critical CVE-2024-1234 detected → Affects package X
- Store raw data for custom analysis and reporting
- No data aggregation that loses detail

This enables complete root cause analysis and trend visualization at any granularity.

### ✅ 4.2 Trigger Attribution
**Question:** Should we track who/what triggered the rescan?

**Answer:**
**Yes - Complete trigger attribution tracking**
- Track all scan triggers with full attribution:
  - **Automated triggers**:
    - Daily scheduled scan (timestamp, job ID)
    - Version change detected (old SHA, new SHA)
    - Dependency update (package, version change)
    - New CVE published (CVE ID, detection time)
  - **Manual triggers**:
    - User-initiated (user ID, name, role, timestamp)
    - API call (API key ID, client application)
    - Admin force refresh (admin ID, reason)
  - **System triggers**:
    - Configuration change (what changed, who changed it)
    - New scoring rule applied (rule ID, applier)
    - System upgrade/patch (version info)
- Store trigger info with each scan record
- Enable audit trail for compliance and debugging
- Show trigger source in scan history

This provides complete auditability and helps understand scan patterns and costs.

---

## 5. Network Detection Rules

### ✅ 5.1 Detection Rule Format
**Question:** What type of detection rules? (Snort, Suricata, YARA, Sigma?)

**Answer:**
**Multiple formats - Support various SIEM/detection tools**
- Generate rules in multiple formats for broad compatibility:
  - **Snort/Suricata** - Network IDS/IPS rules for traffic patterns
  - **YARA** - File and process pattern matching
  - **Sigma** - Generic SIEM rules for log correlation
  - **Zeek** - Network analysis and behavior detection
  - **Splunk** - SPL queries for Splunk deployments
  - **ElasticSearch** - KQL/EQL queries for Elastic Stack
- Each MCP gets rules in all applicable formats
- Rules packaged separately by format for easy deployment
- Include metadata:
  - MCP name and version
  - Risk score at rule generation time
  - Confidence level
  - False positive rate estimate
- Provide import scripts for common SIEMs

This ensures organizations can use rules regardless of their security stack.

### ✅ 5.2 Detection Scope
**Question:** Should rules detect:
- MCP communication patterns?
- Specific vulnerabilities/behaviors?
- Version-specific signatures?

**Answer:**
**All of the above - Comprehensive detection coverage**
- **Identity detection**:
  - Identify specific MCP by unique signatures
  - Determine exact version running
  - Detect MCP initialization/startup patterns
- **Behavior detection**:
  - Normal MCP communication patterns
  - API endpoints and protocols used
  - Data flow patterns
  - Unusual or suspicious API calls
- **Vulnerability detection**:
  - Known CVE exploitation attempts
  - Vulnerable version identification
  - Attack patterns targeting known weaknesses
- **Anomaly detection**:
  - Deviations from baseline behavior
  - Unusual network traffic patterns
  - Unexpected data volumes or destinations
- **Risk-based detection**:
  - High-risk MCP activities (based on score)
  - Critical vulnerability indicators
  - Secret/credential exposure patterns

This comprehensive approach enables both proactive threat hunting and reactive incident response.

### ✅ 5.3 Rule Grouping
**Question:** One rule per MCP or grouped by risk level?

**Answer:**
**Per MCP - Individual ruleset for each MCP**
- Each MCP gets its own dedicated ruleset
- Benefits:
  - Precise detection and identification
  - Easy to enable/disable specific MCP monitoring
  - Clear attribution when alerts fire
  - Version-specific rules possible
  - Customizable per MCP based on organization's usage
- Rule package structure:
  - MCP name and ID
  - Current version rules
  - Historical version detection (if needed)
  - Risk score at generation time
  - All format variants (Snort, YARA, etc.)
- Update strategy:
  - Regenerate rules when MCP version changes
  - Regenerate when score changes significantly
  - Include rule version/generation timestamp
- Performance optimization:
  - Provide rule enablement recommendations based on risk
  - Option to only deploy high-risk MCP rules

This approach provides maximum granularity and control for security teams.

---

## 6. Technical Architecture

### ✅ 6.1 API Style
**Question:** Should the API be RESTful or GraphQL?

**Answer:**
**RESTful API - Enterprise-ready architecture**
- RESTful API chosen for enterprise compatibility
- Key benefits for large enterprises:
  - Mature security patterns (OAuth2, JWT)
  - Universal tool/system compatibility
  - Well-understood by enterprise teams
  - Proven multi-tenant patterns
  - Better caching and scaling
  - Easier compliance auditing
- API structure:
  - Version prefix: `/api/v1/`
  - Resource-based endpoints
  - Standard HTTP methods (GET, POST, PUT, DELETE)
  - JSON request/response format
- Documentation:
  - OpenAPI 3.0 specification
  - Auto-generated API documentation
  - Interactive API explorer (Swagger UI)
- Example endpoints:
  - `GET /api/v1/mcps` - List MCPs
  - `GET /api/v1/mcps/{id}/scores` - Get scores
  - `POST /api/v1/scoring-configs` - Create scoring config
  - `GET /api/v1/mcps/{id}/history` - Score history

This provides a robust, scalable API that enterprises can easily adopt.

### ✅ 6.2 Database Choice
**Question:** Continue with PostgreSQL for everything?

**Answer:**
**PostgreSQL for everything - Cost-optimized approach**
- Use PostgreSQL as the single source of truth
- Storage strategy:
  - All configuration and scoring data in PostgreSQL
  - SBOMs stored as JSONB in database (efficient querying)
  - Repository code stored locally on filesystem
  - Large reports can be stored locally with paths in DB
- No S3/cloud storage (avoid read/write costs)
- PostgreSQL features to leverage:
  - JSONB for flexible document storage (SBOMs, configs)
  - Partitioning for time-series data (historical scores)
  - Row-level security for multi-tenancy
  - Built-in full-text search for queries
  - Table inheritance for tenant isolation
- Local filesystem for:
  - Cloned repository code
  - Generated detection rules
  - Large report files
  - Temporary scan artifacts
- Benefits:
  - No cloud storage costs
  - Simple backup strategy
  - Single database to manage
  - Fast local file access

This keeps infrastructure simple and costs predictable.

### ✅ 6.3 Scan Frequency
**Question:** How often should we rescan MCPs? (Daily, weekly, on-demand?)

**Answer:**
**Daily scanning schedule**
- **Daily lightweight version check** (all MCPs):
  - Check for repository changes via GitHub API
  - Compare commit SHA with last scan
  - Queue changed MCPs for full scan
- **Daily full rescan** (changed MCPs only):
  - Download updated code
  - Run all security scanners
  - Recalculate scores
  - Update detection rules if needed
- **Additional triggers**:
  - Manual rescan via API
  - New CVE affecting MCP dependencies
  - Configuration change requiring recalculation
- **Optimization**:
  - Stagger scans to avoid API rate limits
  - Priority queue (high-risk MCPs first)
  - Cache GitHub API responses
  - Parallel scanning where possible

This ensures scores are always current (max 24 hours old) while managing resources efficiently.

### ✅ 6.4 Security Scanners
**Question:** Any specific security scanners beyond Semgrep, TruffleHog, OSV?

**Answer:**
**No additional scanners - Current stack is comprehensive**
- Current scanner suite is sufficient:
  - **Semgrep** - Static code analysis (Tools component)
  - **TruffleHog** - Secret detection (Tools component)
  - **OSV Scanner** - Vulnerability scanning (Vulnerability component)
  - **SBOM Generators** (cdxgen/syft) - Dependency enumeration
- This covers:
  - Code quality and security patterns
  - Secret/credential exposure
  - Known vulnerabilities (CVEs)
  - Complete dependency tracking
  - Supply chain visibility
- Benefits of keeping current set:
  - Proven tools with good performance
  - Manageable complexity
  - Clear mapping to scoring components
  - Reasonable scan times
  - Lower maintenance overhead

Future consideration: Can add specialized scanners later if specific gaps identified.

---

## 7. Project Boundaries

### ✅ 7.1 MCP Scope
**Question:** Are we analyzing only public MCPs or private ones too?

**Answer:**
**Public MCPs only**
- System analyzes only publicly accessible GitHub repositories
- Benefits:
  - No complex authentication requirements
  - No access control issues
  - Simplified GitHub token management
  - Clear legal/ethical boundaries
  - Easier to scale
  - No customer credential management
- GitHub token usage:
  - Token from .env used only for API rate limits
  - Not for repository access (all repos public)
  - Single token sufficient for system
- Implications:
  - Cannot scan private organization MCPs
  - Focus on open-source MCP ecosystem
  - No need for per-tenant GitHub tokens
  - Simplified security model

This keeps the system simpler and avoids authentication complexity.

### ✅ 7.2 Compliance Requirements
**Question:** Any compliance requirements (SOC2, HIPAA, etc.)?

**Answer:**
**None initially - Add compliance later as needed**
- Start without formal compliance requirements
- Focus on building core functionality first
- Design with compliance in mind:
  - Comprehensive audit logging
  - Data encryption at rest and in transit
  - Role-based access control
  - Multi-tenant data isolation
  - Secure API authentication
  - Data retention policies
- Future compliance roadmap:
  - SOC2 Type II likely first (most enterprises require)
  - ISO 27001 as international alternative
  - GDPR compliance for EU customers
  - Industry-specific as needed
- Current approach:
  - Follow security best practices
  - Document all processes
  - Maintain audit trails
  - Implement standard security controls

This allows rapid initial development while keeping future compliance achievable.

### ✅ 7.3 User Interface
**Question:** Should the tool have a UI or API-only?

**Answer:**
**Full UI - Complete web interface**
- Comprehensive web-based user interface including:
  - **Dashboards**:
    - Organization overview with aggregate scores
    - MCP portfolio risk view
    - Trending and analytics
  - **MCP Management**:
    - Add/edit/delete MCPs
    - Tag management
    - Manual scan triggers
  - **Score Visualization**:
    - Time-series graphs showing score evolution
    - Drill-down to understand score changes
    - Component and sub-component breakdowns
    - Comparison views (base vs custom scores)
  - **Configuration**:
    - Scoring weight configuration
    - Policy management by tags
    - User and role management
  - **Reports**:
    - Executive summaries
    - Detailed security reports
    - Export capabilities (PDF, CSV)
  - **Detection Rules**:
    - View generated rules
    - Download rule packages
- Technology stack (suggested):
  - React/Vue.js for frontend
  - Charts.js or D3.js for visualizations
  - WebSocket for real-time updates

This provides a complete, user-friendly experience for enterprise customers.

### ✅ 7.4 External Integrations
**Question:** Any integration requirements (SIEM, ticketing systems)?

**Answer:**
**SIEM and Ticketing System integrations**
- **SIEM Integrations**:
  - Splunk (HEC API, saved searches)
  - QRadar (LEEF format, API)
  - Sentinel (Azure API, Logic Apps)
  - ElasticSearch (Beats, Logstash)
  - Generic syslog export
  - CEF/LEEF format support
  - Export capabilities:
    - Score changes/alerts
    - Detection rule updates
    - Scan results
    - Audit logs
- **Ticketing System Integrations**:
  - ServiceNow (REST API, automated ticket creation)
  - Jira (REST API, issue creation/updates)
  - PagerDuty (Events API for critical alerts)
  - Generic webhook support
  - Ticket triggers:
    - Score drops below threshold
    - Critical vulnerabilities detected
    - New high-risk MCPs added
    - Policy violations
- **Integration features**:
  - Configurable per organization
  - Field mapping customization
  - Filtering and routing rules
  - Retry logic for failures

This covers the main enterprise security and IT operations platforms.

---

## 8. Development Guidelines

### ✅ 8.1 Coding Standards
**Question:** Any specific coding standards or style guides?

**Answer:**
**Python PEP 8 with enterprise additions**
- **Python Standards**:
  - PEP 8 compliance (enforced with Black formatter)
  - Type hints for all functions (Python 3.9+)
  - Docstrings for all public functions (Google style)
  - Maximum line length: 120 characters
- **Code Quality Tools**:
  - Black for formatting
  - Pylint for linting
  - mypy for type checking
  - isort for import sorting
- **Security Standards**:
  - No hardcoded credentials (use .env and database)
  - Input validation on all API endpoints
  - SQL injection prevention (use parameterized queries)
  - XSS prevention in UI
- **Naming Conventions**:
  - Snake_case for variables and functions
  - PascalCase for classes
  - UPPER_CASE for constants
  - Descriptive names (no single letters except loops)
- **Error Handling**:
  - Explicit exception handling
  - Proper logging of errors
  - User-friendly error messages
  - Never expose internal details in API responses

### ✅ 8.2 Testing Requirements
**Question:** Testing requirements (unit test coverage percentage?)

**Answer:**
**80% minimum coverage with comprehensive testing**
- **Coverage Requirements**:
  - 80% minimum code coverage overall
  - 100% coverage for security-critical functions
  - 100% coverage for scoring algorithms
  - API endpoints: 100% coverage
- **Test Types**:
  - Unit tests for all functions
  - Integration tests for API endpoints
  - End-to-end tests for critical workflows
  - Performance tests for scoring operations
  - Security tests (OWASP Top 10)
- **Testing Tools**:
  - pytest for test framework
  - pytest-cov for coverage reporting
  - pytest-mock for mocking
  - pytest-asyncio for async tests
  - Faker for test data generation
- **Test Organization**:
  - Mirror source structure in tests/
  - Fixtures for common test data
  - Separate unit and integration tests
  - CI/CD runs all tests on commit
- **Special Requirements**:
  - Database tests use transactions (rollback after)
  - Mock external API calls (GitHub, etc.)
  - Test with multiple tenant configurations
  - Validate all scoring edge cases

### ✅ 8.3 Documentation Standards
**Question:** Documentation standards beyond the CLAUDE.md?

**Answer:**
**Comprehensive documentation at all levels**
- **Code Documentation**:
  - Docstrings for all modules, classes, and functions
  - Inline comments for complex logic only
  - Type hints throughout
  - Example usage in docstrings
- **API Documentation**:
  - OpenAPI 3.0 specification
  - Interactive Swagger UI
  - Request/response examples
  - Error code documentation
  - Rate limiting documentation
- **User Documentation**:
  - Getting Started guide
  - Administration guide
  - API integration guide
  - Troubleshooting guide
  - FAQ section
- **Developer Documentation**:
  - Architecture overview
  - Database schema documentation
  - Development setup guide
  - Contributing guidelines
  - Release notes
- **Operations Documentation**:
  - Deployment guide
  - Monitoring and alerting setup
  - Backup and recovery procedures
  - Performance tuning guide
  - Security hardening checklist
- **Documentation Tools**:
  - Sphinx for Python docs
  - MkDocs for user guides
  - PlantUML for diagrams
  - Automated API doc generation

### ✅ 8.4 CI/CD Pipeline
**Question:** CI/CD pipeline preferences?

**Answer:**
**GitHub Actions with comprehensive automation**
- **CI Pipeline**:
  - Trigger on all PRs and main branch commits
  - Python linting (Black, Pylint, mypy)
  - Run full test suite
  - Security scanning (Bandit, Safety)
  - Code coverage check (fail if <80%)
  - SBOM generation
  - Dependency vulnerability check
- **CD Pipeline**:
  - Automated deployment to staging
  - Manual approval for production
  - Database migration automation
  - Configuration validation
  - Health checks post-deployment
  - Rollback capability
- **Environments**:
  - Development (local)
  - Staging (pre-production)
  - Production
- **Quality Gates**:
  - All tests must pass
  - Coverage requirements met
  - No critical security issues
  - Code review approved
  - Documentation updated
- **Artifacts**:
  - Docker images
  - Python packages
  - Database migration scripts
  - Configuration files
  - Documentation
- **Monitoring**:
  - Build status badges
  - Slack/email notifications
  - Deployment tracking
  - Performance metrics

---

## Summary

**Total Questions:** 24
**Answered:** 24
**Pending:** 0

✅ **All questions have been answered!**

## Next Steps
1. Go through each question systematically
2. Document answers as provided
3. Use completed answers to create comprehensive CLAUDE.md file
4. Update this document as requirements evolve