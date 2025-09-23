-- MCP Security Analysis System Database Schema
-- =============================================

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create schemas
CREATE SCHEMA IF NOT EXISTS mcp_security;
CREATE SCHEMA IF NOT EXISTS audit;

-- Set default schema
SET search_path TO mcp_security, public;

-- =============================================
-- Core Tables
-- =============================================

-- Repositories table
CREATE TABLE repositories (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    url VARCHAR(2048) NOT NULL UNIQUE,
    owner VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    full_name VARCHAR(512) NOT NULL,
    description TEXT,
    language VARCHAR(100),
    size_kb INTEGER,
    stars INTEGER DEFAULT 0,
    forks INTEGER DEFAULT 0,
    is_private BOOLEAN DEFAULT FALSE,
    is_archived BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    last_scanned_at TIMESTAMP,
    scan_status VARCHAR(50) DEFAULT 'pending',
    scan_error TEXT,
    metadata JSONB,
    CONSTRAINT unique_owner_name UNIQUE (owner, name)
);

CREATE INDEX idx_repositories_url ON repositories(url);
CREATE INDEX idx_repositories_full_name ON repositories(full_name);
CREATE INDEX idx_repositories_last_scanned ON repositories(last_scanned_at);
CREATE INDEX idx_repositories_status ON repositories(scan_status);

-- Scans table
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    scan_type VARCHAR(50) NOT NULL, -- 'full', 'incremental', 'vulnerability'
    started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    status VARCHAR(50) NOT NULL DEFAULT 'running', -- 'running', 'completed', 'failed'
    error_message TEXT,
    duration_seconds INTEGER,
    metadata JSONB,
    created_by VARCHAR(255),
    CONSTRAINT chk_scan_type CHECK (scan_type IN ('full', 'incremental', 'vulnerability'))
);

CREATE INDEX idx_scans_repository ON scans(repository_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_started ON scans(started_at);

-- =============================================
-- Security Findings Tables
-- =============================================

-- Vulnerabilities table
CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    vulnerability_id VARCHAR(255) NOT NULL, -- CVE, GHSA, etc.
    severity VARCHAR(20) NOT NULL,
    cvss_score DECIMAL(3,1),
    title VARCHAR(500),
    description TEXT,
    affected_package VARCHAR(500),
    affected_version VARCHAR(100),
    fixed_version VARCHAR(100),
    published_date DATE,
    last_modified_date DATE,
    exploit_available BOOLEAN DEFAULT FALSE,
    in_kev BOOLEAN DEFAULT FALSE,
    references JSONB,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_severity CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'))
);

CREATE INDEX idx_vulnerabilities_scan ON vulnerabilities(scan_id);
CREATE INDEX idx_vulnerabilities_repo ON vulnerabilities(repository_id);
CREATE INDEX idx_vulnerabilities_id ON vulnerabilities(vulnerability_id);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulnerabilities_cvss ON vulnerabilities(cvss_score);

-- Secrets table (encrypted)
CREATE TABLE secrets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    detector_name VARCHAR(100) NOT NULL,
    detector_type VARCHAR(100),
    file_path TEXT ENCRYPTED USING (pgcrypto),
    line_number INTEGER,
    column_number INTEGER,
    secret_hash VARCHAR(64) NOT NULL, -- SHA-256 hash of the secret
    entropy DECIMAL(5,2),
    verified BOOLEAN DEFAULT FALSE,
    false_positive BOOLEAN DEFAULT FALSE,
    metadata JSONB ENCRYPTED USING (pgcrypto),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_secrets_scan ON secrets(scan_id);
CREATE INDEX idx_secrets_repo ON secrets(repository_id);
CREATE INDEX idx_secrets_hash ON secrets(secret_hash);

-- Code quality issues table
CREATE TABLE code_issues (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    rule_id VARCHAR(255) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    category VARCHAR(100),
    message TEXT,
    file_path TEXT,
    line_start INTEGER,
    line_end INTEGER,
    column_start INTEGER,
    column_end INTEGER,
    fix_suggestion TEXT,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_code_severity CHECK (severity IN ('ERROR', 'WARNING', 'INFO'))
);

CREATE INDEX idx_code_issues_scan ON code_issues(scan_id);
CREATE INDEX idx_code_issues_repo ON code_issues(repository_id);
CREATE INDEX idx_code_issues_severity ON code_issues(severity);
CREATE INDEX idx_code_issues_category ON code_issues(category);

-- =============================================
-- Scoring Tables
-- =============================================

-- Security scores table
CREATE TABLE security_scores (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    fico_score INTEGER NOT NULL CHECK (fico_score >= 300 AND fico_score <= 850),
    hygiene_score INTEGER NOT NULL CHECK (hygiene_score >= 0 AND hygiene_score <= 100),
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    vulnerability_score INTEGER NOT NULL CHECK (vulnerability_score >= 0 AND vulnerability_score <= 100),
    hygiene_weight DECIMAL(3,2) DEFAULT 0.30,
    risk_weight DECIMAL(3,2) DEFAULT 0.40,
    vulnerability_weight DECIMAL(3,2) DEFAULT 0.30,
    score_breakdown JSONB,
    calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_repo_scan_score UNIQUE (repository_id, scan_id)
);

CREATE INDEX idx_scores_repository ON security_scores(repository_id);
CREATE INDEX idx_scores_scan ON security_scores(scan_id);
CREATE INDEX idx_scores_fico ON security_scores(fico_score);
CREATE INDEX idx_scores_calculated ON security_scores(calculated_at);

-- Score history table
CREATE TABLE score_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    fico_score INTEGER NOT NULL,
    hygiene_score INTEGER NOT NULL,
    risk_score INTEGER NOT NULL,
    vulnerability_score INTEGER NOT NULL,
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_score_history_repo ON score_history(repository_id);
CREATE INDEX idx_score_history_recorded ON score_history(recorded_at);

-- =============================================
-- SBOM Tables
-- =============================================

-- SBOM table
CREATE TABLE sboms (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    format VARCHAR(50) NOT NULL, -- 'cyclonedx', 'spdx'
    version VARCHAR(20),
    generator VARCHAR(100),
    component_count INTEGER,
    sbom_content JSONB,
    file_path TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sboms_repository ON sboms(repository_id);
CREATE INDEX idx_sboms_scan ON sboms(scan_id);

-- Dependencies table
CREATE TABLE dependencies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sbom_id UUID NOT NULL REFERENCES sboms(id) ON DELETE CASCADE,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    package_name VARCHAR(500) NOT NULL,
    version VARCHAR(100),
    package_manager VARCHAR(50),
    license VARCHAR(100),
    is_direct BOOLEAN DEFAULT TRUE,
    is_dev BOOLEAN DEFAULT FALSE,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_dependencies_sbom ON dependencies(sbom_id);
CREATE INDEX idx_dependencies_repo ON dependencies(repository_id);
CREATE INDEX idx_dependencies_package ON dependencies(package_name);

-- =============================================
-- Audit Tables
-- =============================================

-- Audit log table
CREATE TABLE audit.audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(100) NOT NULL,
    event_timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_id VARCHAR(255),
    ip_address INET,
    resource_type VARCHAR(100),
    resource_id UUID,
    action VARCHAR(50),
    details JSONB,
    risk_score INTEGER,
    success BOOLEAN DEFAULT TRUE
);

CREATE INDEX idx_audit_timestamp ON audit.audit_log(event_timestamp);
CREATE INDEX idx_audit_user ON audit.audit_log(user_id);
CREATE INDEX idx_audit_type ON audit.audit_log(event_type);
CREATE INDEX idx_audit_resource ON audit.audit_log(resource_type, resource_id);

-- =============================================
-- Security Tables
-- =============================================

-- API keys table (encrypted)
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key_hash VARCHAR(64) NOT NULL UNIQUE,
    name VARCHAR(255),
    description TEXT,
    permissions JSONB,
    rate_limit INTEGER DEFAULT 1000,
    expires_at TIMESTAMP,
    last_used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE
);

CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_active ON api_keys(is_active);

-- Sessions table
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_token VARCHAR(255) NOT NULL UNIQUE,
    user_id VARCHAR(255) NOT NULL,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

CREATE INDEX idx_sessions_token ON sessions(session_token);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

-- =============================================
-- Views
-- =============================================

-- Current repository status view
CREATE VIEW v_repository_status AS
SELECT
    r.id,
    r.full_name,
    r.last_scanned_at,
    r.scan_status,
    ss.fico_score,
    ss.calculated_at,
    COUNT(DISTINCT v.vulnerability_id) as vulnerability_count,
    COUNT(DISTINCT s.id) as secret_count,
    COUNT(DISTINCT ci.id) as issue_count
FROM repositories r
LEFT JOIN security_scores ss ON r.id = ss.repository_id
LEFT JOIN vulnerabilities v ON r.id = v.repository_id
LEFT JOIN secrets s ON r.id = s.repository_id AND s.false_positive = FALSE
LEFT JOIN code_issues ci ON r.id = ci.repository_id
GROUP BY r.id, r.full_name, r.last_scanned_at, r.scan_status, ss.fico_score, ss.calculated_at;

-- =============================================
-- Functions & Triggers
-- =============================================

-- Update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_repositories_updated_at
    BEFORE UPDATE ON repositories
    FOR EACH ROW
    EXECUTE PROCEDURE update_updated_at_column();

-- =============================================
-- Row Level Security Policies
-- =============================================

-- Enable RLS on sensitive tables
ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;

-- =============================================
-- Permissions
-- =============================================

-- Create read-only role
CREATE ROLE mcp_readonly;
GRANT USAGE ON SCHEMA mcp_security TO mcp_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA mcp_security TO mcp_readonly;

-- Create read-write role
CREATE ROLE mcp_readwrite;
GRANT USAGE ON SCHEMA mcp_security TO mcp_readwrite;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA mcp_security TO mcp_readwrite;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA mcp_security TO mcp_readwrite;

-- Create admin role
CREATE ROLE mcp_admin;
GRANT ALL PRIVILEGES ON SCHEMA mcp_security TO mcp_admin;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA mcp_security TO mcp_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA mcp_security TO mcp_admin;