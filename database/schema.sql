-- MCP Risk Assessment Tool Database Schema
-- =========================================
-- PostgreSQL 16+ Required
--
-- This schema provides comprehensive tracking of MCP repositories,
-- security scans, scoring history, and multi-tenant organization support.
-- Integrates with WorkOS for authentication and supports full audit logging.

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "btree_gist";

-- =====================================================
-- AUTHENTICATION & MULTI-TENANCY (WorkOS Integration)
-- =====================================================

-- Organizations (synced from WorkOS)
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workos_org_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) UNIQUE NOT NULL,
    domain VARCHAR(255),
    subscription_tier VARCHAR(50) DEFAULT 'free', -- free, pro, enterprise
    is_active BOOLEAN DEFAULT true,
    settings JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_organizations_workos_id ON organizations(workos_org_id);
CREATE INDEX idx_organizations_slug ON organizations(slug);
CREATE INDEX idx_organizations_active ON organizations(is_active) WHERE deleted_at IS NULL;

-- Users (synced from WorkOS)
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    workos_user_id VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    role VARCHAR(50) DEFAULT 'member', -- admin, member, viewer
    is_active BOOLEAN DEFAULT true,
    last_login_at TIMESTAMP WITH TIME ZONE,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(organization_id, email)
);

CREATE INDEX idx_users_workos_id ON users(workos_user_id);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_org_id ON users(organization_id);

-- API Keys for programmatic access
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) NOT NULL, -- bcrypt hash of actual key
    key_prefix VARCHAR(20) NOT NULL, -- First 8 chars for identification
    permissions JSONB DEFAULT '["read"]',
    last_used_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);
CREATE INDEX idx_api_keys_org_id ON api_keys(organization_id);
CREATE INDEX idx_api_keys_active ON api_keys(is_active) WHERE revoked_at IS NULL;

-- =====================================================
-- MCP REPOSITORY TRACKING
-- =====================================================

-- Master repository records
CREATE TABLE mcp_repositories (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    github_url VARCHAR(500) UNIQUE NOT NULL,
    github_owner VARCHAR(255) NOT NULL,
    github_name VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    description TEXT,
    primary_language VARCHAR(50),
    is_public BOOLEAN DEFAULT true,
    is_archived BOOLEAN DEFAULT false,
    is_active BOOLEAN DEFAULT true,
    tags JSONB DEFAULT '[]', -- AWS-style tags for policy application
    metadata JSONB DEFAULT '{}',
    first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_checked_at TIMESTAMP WITH TIME ZONE,
    last_modified_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_mcp_repos_github_url ON mcp_repositories(github_url);
CREATE INDEX idx_mcp_repos_owner_name ON mcp_repositories(github_owner, github_name);
CREATE INDEX idx_mcp_repos_active ON mcp_repositories(is_active) WHERE deleted_at IS NULL;
CREATE INDEX idx_mcp_repos_tags ON mcp_repositories USING gin(tags);

-- Version tracking for each repository
CREATE TABLE repository_versions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repository_id UUID NOT NULL REFERENCES mcp_repositories(id) ON DELETE CASCADE,
    version_type VARCHAR(50) NOT NULL, -- commit, tag, release
    version_identifier VARCHAR(255) NOT NULL, -- commit SHA, tag name, etc.
    commit_sha VARCHAR(64) NOT NULL,
    commit_message TEXT,
    commit_author VARCHAR(255),
    commit_date TIMESTAMP WITH TIME ZONE,
    release_tag VARCHAR(255),
    release_name VARCHAR(255),
    is_latest BOOLEAN DEFAULT false,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(repository_id, commit_sha)
);

CREATE INDEX idx_repo_versions_repo_id ON repository_versions(repository_id);
CREATE INDEX idx_repo_versions_latest ON repository_versions(repository_id, is_latest) WHERE is_latest = true;
CREATE INDEX idx_repo_versions_detected ON repository_versions(detected_at DESC);

-- GitHub metrics and metadata
CREATE TABLE repository_metadata (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repository_id UUID NOT NULL REFERENCES mcp_repositories(id) ON DELETE CASCADE,
    version_id UUID REFERENCES repository_versions(id) ON DELETE CASCADE,
    stars_count INTEGER DEFAULT 0,
    forks_count INTEGER DEFAULT 0,
    watchers_count INTEGER DEFAULT 0,
    open_issues_count INTEGER DEFAULT 0,
    open_pr_count INTEGER DEFAULT 0,
    contributors_count INTEGER DEFAULT 0,
    commits_count INTEGER DEFAULT 0,
    branches_count INTEGER DEFAULT 0,
    releases_count INTEGER DEFAULT 0,
    topics JSONB DEFAULT '[]',
    languages JSONB DEFAULT '{}', -- {"JavaScript": 60, "TypeScript": 40}
    license VARCHAR(100),
    default_branch VARCHAR(100) DEFAULT 'main',
    created_at_github TIMESTAMP WITH TIME ZONE,
    updated_at_github TIMESTAMP WITH TIME ZONE,
    pushed_at_github TIMESTAMP WITH TIME ZONE,
    size_kb INTEGER,
    has_wiki BOOLEAN DEFAULT false,
    has_issues BOOLEAN DEFAULT true,
    has_downloads BOOLEAN DEFAULT true,
    collected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_repo_metadata_repo_id ON repository_metadata(repository_id);
CREATE INDEX idx_repo_metadata_version_id ON repository_metadata(version_id);
CREATE INDEX idx_repo_metadata_collected ON repository_metadata(collected_at DESC);

-- =====================================================
-- SCANNING & SECURITY FINDINGS
-- =====================================================

-- Master scan records
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repository_id UUID NOT NULL REFERENCES mcp_repositories(id) ON DELETE CASCADE,
    version_id UUID NOT NULL REFERENCES repository_versions(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    triggered_by UUID REFERENCES users(id) ON DELETE SET NULL,
    scan_type VARCHAR(50) NOT NULL, -- full, incremental, scheduled, manual
    status VARCHAR(50) NOT NULL, -- pending, running, completed, failed
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    duration_seconds INTEGER,
    error_message TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_scans_repo_id ON scans(repository_id);
CREATE INDEX idx_scans_version_id ON scans(version_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created ON scans(created_at DESC);

-- Semgrep findings
CREATE TABLE scan_semgrep_findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    repository_id UUID NOT NULL REFERENCES mcp_repositories(id) ON DELETE CASCADE,
    rule_id VARCHAR(255) NOT NULL,
    severity VARCHAR(50) NOT NULL, -- critical, high, medium, low, info
    category VARCHAR(100),
    file_path TEXT NOT NULL,
    line_start INTEGER,
    line_end INTEGER,
    column_start INTEGER,
    column_end INTEGER,
    message TEXT,
    code_snippet TEXT,
    fix_suggestion TEXT,
    cwe_ids INTEGER[],
    owasp_ids VARCHAR(50)[],
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_semgrep_scan_id ON scan_semgrep_findings(scan_id);
CREATE INDEX idx_semgrep_severity ON scan_semgrep_findings(severity);
CREATE INDEX idx_semgrep_category ON scan_semgrep_findings(category);

-- TruffleHog secrets
CREATE TABLE scan_trufflehog_secrets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    repository_id UUID NOT NULL REFERENCES mcp_repositories(id) ON DELETE CASCADE,
    detector_name VARCHAR(100) NOT NULL,
    detector_type VARCHAR(50), -- api_key, password, token, etc.
    severity VARCHAR(50) NOT NULL,
    confidence VARCHAR(50),
    file_path TEXT NOT NULL,
    line_number INTEGER,
    commit_sha VARCHAR(64),
    commit_author VARCHAR(255),
    commit_date TIMESTAMP WITH TIME ZONE,
    secret_hash VARCHAR(64) NOT NULL, -- SHA256 of secret for deduplication
    is_verified BOOLEAN DEFAULT false,
    is_excluded BOOLEAN DEFAULT false,
    raw_secret_encrypted BYTEA, -- Encrypted with pgcrypto
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(repository_id, secret_hash)
);

CREATE INDEX idx_trufflehog_scan_id ON scan_trufflehog_secrets(scan_id);
CREATE INDEX idx_trufflehog_severity ON scan_trufflehog_secrets(severity);
CREATE INDEX idx_trufflehog_verified ON scan_trufflehog_secrets(is_verified) WHERE is_verified = true;
CREATE INDEX idx_trufflehog_hash ON scan_trufflehog_secrets(secret_hash);

-- OSV vulnerabilities
CREATE TABLE scan_osv_vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    repository_id UUID NOT NULL REFERENCES mcp_repositories(id) ON DELETE CASCADE,
    vulnerability_id VARCHAR(100) NOT NULL, -- CVE-2021-1234, GHSA-xxx
    package_name VARCHAR(255) NOT NULL,
    package_ecosystem VARCHAR(50), -- npm, pypi, maven, etc.
    current_version VARCHAR(100),
    fixed_version VARCHAR(100),
    severity VARCHAR(50) NOT NULL,
    cvss_score DECIMAL(3,1),
    cvss_vector VARCHAR(255),
    cwe_ids INTEGER[],
    published_date DATE,
    modified_date DATE,
    description TEXT,
    references JSONB DEFAULT '[]',
    is_kev BOOLEAN DEFAULT false, -- CISA Known Exploited Vulnerability
    has_exploit BOOLEAN DEFAULT false,
    age_days INTEGER,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_osv_scan_id ON scan_osv_vulnerabilities(scan_id);
CREATE INDEX idx_osv_severity ON scan_osv_vulnerabilities(severity);
CREATE INDEX idx_osv_cve_id ON scan_osv_vulnerabilities(vulnerability_id);
CREATE INDEX idx_osv_kev ON scan_osv_vulnerabilities(is_kev) WHERE is_kev = true;
CREATE INDEX idx_osv_cvss ON scan_osv_vulnerabilities(cvss_score DESC);

-- Software Bill of Materials
CREATE TABLE sboms (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    repository_id UUID NOT NULL REFERENCES mcp_repositories(id) ON DELETE CASCADE,
    format VARCHAR(50) NOT NULL, -- cyclonedx, spdx
    spec_version VARCHAR(20),
    serial_number VARCHAR(255),
    total_components INTEGER,
    direct_dependencies INTEGER,
    transitive_dependencies INTEGER,
    sbom_data JSONB NOT NULL, -- Full SBOM JSON
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sboms_scan_id ON sboms(scan_id);
CREATE INDEX idx_sboms_repo_id ON sboms(repository_id);

-- =====================================================
-- SCORING SYSTEM
-- =====================================================

-- Final aggregated scores
CREATE TABLE scores (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    repository_id UUID NOT NULL REFERENCES mcp_repositories(id) ON DELETE CASCADE,
    version_id UUID NOT NULL REFERENCES repository_versions(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    scoring_policy_id UUID REFERENCES scoring_policies(id) ON DELETE SET NULL,
    final_score INTEGER NOT NULL CHECK (final_score >= 300 AND final_score <= 850),
    grade VARCHAR(2), -- A+, A, B+, B, C, D, F
    risk_level VARCHAR(20), -- very_low, low, medium, high, critical
    percentile INTEGER, -- Percentile rank among all MCPs
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(scan_id)
);

CREATE INDEX idx_scores_scan_id ON scores(scan_id);
CREATE INDEX idx_scores_repo_id ON scores(repository_id);
CREATE INDEX idx_scores_final ON scores(final_score DESC);
CREATE INDEX idx_scores_created ON scores(created_at DESC);

-- Component scores breakdown
CREATE TABLE score_components (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    score_id UUID NOT NULL REFERENCES scores(id) ON DELETE CASCADE,
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    hygiene_score INTEGER NOT NULL CHECK (hygiene_score >= 300 AND hygiene_score <= 850),
    hygiene_weight DECIMAL(3,2) DEFAULT 0.25,
    hygiene_details JSONB DEFAULT '{}',
    tools_score INTEGER NOT NULL CHECK (tools_score >= 300 AND tools_score <= 850),
    tools_weight DECIMAL(3,2) DEFAULT 0.35,
    tools_details JSONB DEFAULT '{}',
    vulnerability_score INTEGER NOT NULL CHECK (vulnerability_score >= 300 AND vulnerability_score <= 850),
    vulnerability_weight DECIMAL(3,2) DEFAULT 0.40,
    vulnerability_details JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(score_id)
);

CREATE INDEX idx_score_components_score_id ON score_components(score_id);

-- Historical score tracking (time-series data)
CREATE TABLE score_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repository_id UUID NOT NULL REFERENCES mcp_repositories(id) ON DELETE CASCADE,
    score INTEGER NOT NULL CHECK (score >= 300 AND score <= 850),
    hygiene_score INTEGER,
    tools_score INTEGER,
    vulnerability_score INTEGER,
    recorded_at DATE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(repository_id, recorded_at)
) PARTITION BY RANGE (recorded_at);

-- Create monthly partitions for score history
CREATE TABLE score_history_2025_01 PARTITION OF score_history
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
CREATE TABLE score_history_2025_02 PARTITION OF score_history
    FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');
-- Add more partitions as needed

CREATE INDEX idx_score_history_repo_date ON score_history(repository_id, recorded_at DESC);

-- Custom scoring policies per organization
CREATE TABLE scoring_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    is_default BOOLEAN DEFAULT false,
    hygiene_weight DECIMAL(3,2) DEFAULT 0.25,
    tools_weight DECIMAL(3,2) DEFAULT 0.35,
    vulnerability_weight DECIMAL(3,2) DEFAULT 0.40,
    custom_rules JSONB DEFAULT '{}',
    tags JSONB DEFAULT '[]', -- Apply to repos with matching tags
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT weights_sum_to_one CHECK (
        ABS((hygiene_weight + tools_weight + vulnerability_weight) - 1.0) < 0.01
    )
);

CREATE INDEX idx_scoring_policies_org ON scoring_policies(organization_id);
CREATE INDEX idx_scoring_policies_default ON scoring_policies(is_default) WHERE is_default = true;

-- =====================================================
-- DETECTION RULES
-- =====================================================

CREATE TABLE detection_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repository_id UUID NOT NULL REFERENCES mcp_repositories(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    rule_type VARCHAR(50) NOT NULL, -- snort, yara, sigma, zeek, suricata, ossec
    rule_name VARCHAR(255) NOT NULL,
    rule_content TEXT NOT NULL,
    severity VARCHAR(50),
    confidence VARCHAR(50),
    description TEXT,
    tags JSONB DEFAULT '[]',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_detection_rules_repo ON detection_rules(repository_id);
CREATE INDEX idx_detection_rules_type ON detection_rules(rule_type);
CREATE INDEX idx_detection_rules_active ON detection_rules(is_active) WHERE is_active = true;

-- =====================================================
-- MONITORING & COMPLIANCE
-- =====================================================

-- Comprehensive audit logging
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    api_key_id UUID REFERENCES api_keys(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL, -- scan.initiated, score.calculated, rule.generated, etc.
    resource_type VARCHAR(50), -- repository, scan, score, etc.
    resource_id UUID,
    ip_address INET,
    user_agent TEXT,
    request_id UUID,
    changes JSONB, -- Before/after for updates
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
) PARTITION BY RANGE (created_at);

-- Create monthly partitions for audit logs
CREATE TABLE audit_logs_2025_01 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
CREATE TABLE audit_logs_2025_02 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');

CREATE INDEX idx_audit_logs_org ON audit_logs(organization_id);
CREATE INDEX idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created ON audit_logs(created_at DESC);

-- Alerts and notifications
CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    repository_id UUID REFERENCES mcp_repositories(id) ON DELETE CASCADE,
    alert_type VARCHAR(50) NOT NULL, -- score_drop, new_vulnerability, secret_found
    severity VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    details JSONB DEFAULT '{}',
    is_acknowledged BOOLEAN DEFAULT false,
    acknowledged_by UUID REFERENCES users(id),
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_alerts_org ON alerts(organization_id);
CREATE INDEX idx_alerts_repo ON alerts(repository_id);
CREATE INDEX idx_alerts_unack ON alerts(is_acknowledged) WHERE is_acknowledged = false;
CREATE INDEX idx_alerts_created ON alerts(created_at DESC);

-- =====================================================
-- FUNCTIONS AND TRIGGERS
-- =====================================================

-- Auto-update updated_at timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply updated_at trigger to relevant tables
CREATE TRIGGER update_organizations_updated_at BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_mcp_repositories_updated_at BEFORE UPDATE ON mcp_repositories
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_scoring_policies_updated_at BEFORE UPDATE ON scoring_policies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_detection_rules_updated_at BEFORE UPDATE ON detection_rules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to update latest version flag
CREATE OR REPLACE FUNCTION update_latest_version()
RETURNS TRIGGER AS $$
BEGIN
    -- Set all versions for this repo to not latest
    UPDATE repository_versions
    SET is_latest = false
    WHERE repository_id = NEW.repository_id;

    -- Set the new version as latest
    NEW.is_latest = true;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER set_latest_version BEFORE INSERT ON repository_versions
    FOR EACH ROW EXECUTE FUNCTION update_latest_version();

-- Function to calculate risk level from score
CREATE OR REPLACE FUNCTION calculate_risk_level(score INTEGER)
RETURNS VARCHAR AS $$
BEGIN
    RETURN CASE
        WHEN score >= 800 THEN 'very_low'
        WHEN score >= 740 THEN 'low'
        WHEN score >= 670 THEN 'medium'
        WHEN score >= 580 THEN 'high'
        ELSE 'critical'
    END;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Function to calculate grade from score
CREATE OR REPLACE FUNCTION calculate_grade(score INTEGER)
RETURNS VARCHAR AS $$
BEGIN
    RETURN CASE
        WHEN score >= 850 THEN 'A+'
        WHEN score >= 800 THEN 'A'
        WHEN score >= 740 THEN 'B+'
        WHEN score >= 670 THEN 'B'
        WHEN score >= 580 THEN 'C'
        WHEN score >= 500 THEN 'D'
        ELSE 'F'
    END;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- =====================================================
-- INDEXES FOR PERFORMANCE
-- =====================================================

-- Composite indexes for common queries
CREATE INDEX idx_scores_repo_created ON scores(repository_id, created_at DESC);
CREATE INDEX idx_scans_repo_status ON scans(repository_id, status);
CREATE INDEX idx_repo_versions_latest_commit ON repository_versions(repository_id, commit_sha) WHERE is_latest = true;

-- Partial indexes for active records
CREATE INDEX idx_active_repos ON mcp_repositories(id) WHERE is_active = true AND deleted_at IS NULL;
CREATE INDEX idx_active_users ON users(id) WHERE is_active = true AND deleted_at IS NULL;

-- =====================================================
-- PERMISSIONS
-- =====================================================

-- Create read-only role for reporting
CREATE ROLE mcp_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO mcp_reader;

-- Create application role with full access
CREATE ROLE mcp_app;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO mcp_app;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO mcp_app;

-- =====================================================
-- INITIAL DATA
-- =====================================================

-- Insert default scoring policy
INSERT INTO scoring_policies (name, description, is_default, hygiene_weight, tools_weight, vulnerability_weight)
VALUES ('Default Security-Focused', 'Standard scoring weights with security focus', true, 0.25, 0.35, 0.40);

-- =====================================================
-- COMMENTS FOR DOCUMENTATION
-- =====================================================

COMMENT ON TABLE mcp_repositories IS 'Master record for each MCP repository being tracked';
COMMENT ON TABLE repository_versions IS 'Version history for each repository, tracking all commits and releases';
COMMENT ON TABLE scores IS 'Final calculated FICO scores for each scan';
COMMENT ON TABLE score_history IS 'Time-series data for score trending and analysis';
COMMENT ON TABLE audit_logs IS 'Comprehensive audit trail for compliance and security';
COMMENT ON COLUMN scan_trufflehog_secrets.raw_secret_encrypted IS 'Secrets are encrypted using pgcrypto before storage';
COMMENT ON COLUMN scores.percentile IS 'Percentile rank compared to all other MCPs in the system';