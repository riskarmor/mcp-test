"""
SQLAlchemy Database Models for MCP Risk Assessment Tool
========================================================
Provides ORM models for all database tables with relationships and validations.
Integrates with WorkOS for authentication and supports full historical tracking.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum as PyEnum
from decimal import Decimal
from uuid import uuid4

from sqlalchemy import (
    Column, String, Integer, Boolean, DateTime, Date, Text, Float,
    ForeignKey, UniqueConstraint, CheckConstraint, Index, JSON,
    ARRAY, LargeBinary, Numeric, Enum, Table
)
from sqlalchemy.dialects.postgresql import UUID, INET, JSONB
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref
from sqlalchemy.sql import func

Base = declarative_base()


# =====================================================
# ENUMS
# =====================================================

class SubscriptionTier(PyEnum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class UserRole(PyEnum):
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


class ScanType(PyEnum):
    FULL = "full"
    INCREMENTAL = "incremental"
    SCHEDULED = "scheduled"
    MANUAL = "manual"


class ScanStatus(PyEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(PyEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RiskLevel(PyEnum):
    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleType(PyEnum):
    SNORT = "snort"
    YARA = "yara"
    SIGMA = "sigma"
    ZEEK = "zeek"
    SURICATA = "suricata"
    OSSEC = "ossec"


# =====================================================
# AUTHENTICATION & MULTI-TENANCY MODELS
# =====================================================

class Organization(Base):
    """Organizations synced from WorkOS"""
    __tablename__ = 'organizations'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    workos_org_id = Column(String(255), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    slug = Column(String(255), unique=True, nullable=False, index=True)
    domain = Column(String(255))
    subscription_tier = Column(Enum(SubscriptionTier), default=SubscriptionTier.FREE)
    is_active = Column(Boolean, default=True)
    settings = Column(JSONB, default={})
    metadata = Column(JSONB, default={})
    created_at = Column(DateTime(timezone=True), default=func.current_timestamp())
    updated_at = Column(DateTime(timezone=True), default=func.current_timestamp(), onupdate=func.current_timestamp())
    deleted_at = Column(DateTime(timezone=True))

    # Relationships
    users = relationship("User", back_populates="organization", cascade="all, delete-orphan")
    api_keys = relationship("APIKey", back_populates="organization", cascade="all, delete-orphan")
    repositories = relationship("MCPRepository", back_populates="organization")
    scans = relationship("Scan", back_populates="organization")
    scoring_policies = relationship("ScoringPolicy", back_populates="organization", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="organization", cascade="all, delete-orphan")


class User(Base):
    """Users synced from WorkOS"""
    __tablename__ = 'users'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False)
    workos_user_id = Column(String(255), unique=True, nullable=False, index=True)
    email = Column(String(255), nullable=False, index=True)
    name = Column(String(255))
    role = Column(Enum(UserRole), default=UserRole.MEMBER)
    is_active = Column(Boolean, default=True)
    last_login_at = Column(DateTime(timezone=True))
    settings = Column(JSONB, default={})
    created_at = Column(DateTime(timezone=True), default=func.current_timestamp())
    updated_at = Column(DateTime(timezone=True), default=func.current_timestamp(), onupdate=func.current_timestamp())
    deleted_at = Column(DateTime(timezone=True))

    # Relationships
    organization = relationship("Organization", back_populates="users")
    api_keys_created = relationship("APIKey", back_populates="created_by")
    scans_triggered = relationship("Scan", back_populates="triggered_by")
    alerts_acknowledged = relationship("Alert", foreign_keys="Alert.acknowledged_by")
    audit_logs = relationship("AuditLog", back_populates="user")

    __table_args__ = (
        UniqueConstraint('organization_id', 'email'),
        Index('idx_users_org_id', 'organization_id'),
    )


class APIKey(Base):
    """API Keys for programmatic access"""
    __tablename__ = 'api_keys'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False)
    created_by_user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'))
    name = Column(String(255), nullable=False)
    key_hash = Column(String(255), nullable=False)  # bcrypt hash
    key_prefix = Column(String(20), nullable=False, index=True)
    permissions = Column(JSONB, default=["read"])
    last_used_at = Column(DateTime(timezone=True))
    expires_at = Column(DateTime(timezone=True))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=func.current_timestamp())
    revoked_at = Column(DateTime(timezone=True))

    # Relationships
    organization = relationship("Organization", back_populates="api_keys")
    created_by = relationship("User", back_populates="api_keys_created")
    audit_logs = relationship("AuditLog", back_populates="api_key")


# =====================================================
# MCP REPOSITORY MODELS
# =====================================================

class MCPRepository(Base):
    """Master repository records"""
    __tablename__ = 'mcp_repositories'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id', ondelete='SET NULL'))
    github_url = Column(String(500), unique=True, nullable=False, index=True)
    github_owner = Column(String(255), nullable=False)
    github_name = Column(String(255), nullable=False)
    display_name = Column(String(255))
    description = Column(Text)
    primary_language = Column(String(50))
    is_public = Column(Boolean, default=True)
    is_archived = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    tags = Column(JSONB, default=[])
    metadata = Column(JSONB, default={})
    first_seen_at = Column(DateTime(timezone=True), default=func.current_timestamp())
    last_checked_at = Column(DateTime(timezone=True))
    last_modified_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=func.current_timestamp())
    updated_at = Column(DateTime(timezone=True), default=func.current_timestamp(), onupdate=func.current_timestamp())
    deleted_at = Column(DateTime(timezone=True))

    # Relationships
    organization = relationship("Organization", back_populates="repositories")
    versions = relationship("RepositoryVersion", back_populates="repository", cascade="all, delete-orphan")
    metadata_records = relationship("RepositoryMetadata", back_populates="repository", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="repository", cascade="all, delete-orphan")
    scores = relationship("Score", back_populates="repository")
    score_history = relationship("ScoreHistory", back_populates="repository")
    detection_rules = relationship("DetectionRule", back_populates="repository", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="repository")

    __table_args__ = (
        Index('idx_mcp_repos_owner_name', 'github_owner', 'github_name'),
        Index('idx_mcp_repos_active', 'is_active'),
    )


class RepositoryVersion(Base):
    """Version tracking for each repository"""
    __tablename__ = 'repository_versions'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    repository_id = Column(UUID(as_uuid=True), ForeignKey('mcp_repositories.id', ondelete='CASCADE'), nullable=False)
    version_type = Column(String(50), nullable=False)  # commit, tag, release
    version_identifier = Column(String(255), nullable=False)
    commit_sha = Column(String(64), nullable=False)
    commit_message = Column(Text)
    commit_author = Column(String(255))
    commit_date = Column(DateTime(timezone=True))
    release_tag = Column(String(255))
    release_name = Column(String(255))
    is_latest = Column(Boolean, default=False)
    detected_at = Column(DateTime(timezone=True), default=func.current_timestamp())
    created_at = Column(DateTime(timezone=True), default=func.current_timestamp())

    # Relationships
    repository = relationship("MCPRepository", back_populates="versions")
    metadata_records = relationship("RepositoryMetadata", back_populates="version")
    scans = relationship("Scan", back_populates="version")
    scores = relationship("Score", back_populates="version")

    __table_args__ = (
        UniqueConstraint('repository_id', 'commit_sha'),
        Index('idx_repo_versions_repo_id', 'repository_id'),
        Index('idx_repo_versions_latest', 'repository_id', 'is_latest'),
    )


class RepositoryMetadata(Base):
    """GitHub metrics and metadata"""
    __tablename__ = 'repository_metadata'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    repository_id = Column(UUID(as_uuid=True), ForeignKey('mcp_repositories.id', ondelete='CASCADE'), nullable=False)
    version_id = Column(UUID(as_uuid=True), ForeignKey('repository_versions.id', ondelete='CASCADE'))
    stars_count = Column(Integer, default=0)
    forks_count = Column(Integer, default=0)
    watchers_count = Column(Integer, default=0)
    open_issues_count = Column(Integer, default=0)
    open_pr_count = Column(Integer, default=0)
    contributors_count = Column(Integer, default=0)
    commits_count = Column(Integer, default=0)
    branches_count = Column(Integer, default=0)
    releases_count = Column(Integer, default=0)
    topics = Column(JSONB, default=[])
    languages = Column(JSONB, default={})
    license = Column(String(100))
    default_branch = Column(String(100), default='main')
    created_at_github = Column(DateTime(timezone=True))
    updated_at_github = Column(DateTime(timezone=True))
    pushed_at_github = Column(DateTime(timezone=True))
    size_kb = Column(Integer)
    has_wiki = Column(Boolean, default=False)
    has_issues = Column(Boolean, default=True)
    has_downloads = Column(Boolean, default=True)
    collected_at = Column(DateTime(timezone=True), default=func.current_timestamp())
    created_at = Column(DateTime(timezone=True), default=func.current_timestamp())

    # Relationships
    repository = relationship("MCPRepository", back_populates="metadata_records")
    version = relationship("RepositoryVersion", back_populates="metadata_records")


# =====================================================
# SCANNING & SECURITY MODELS
# =====================================================

class Scan(Base):
    """Master scan records"""
    __tablename__ = 'scans'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    repository_id = Column(UUID(as_uuid=True), ForeignKey('mcp_repositories.id', ondelete='CASCADE'), nullable=False)
    version_id = Column(UUID(as_uuid=True), ForeignKey('repository_versions.id', ondelete='CASCADE'), nullable=False)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id', ondelete='SET NULL'))
    triggered_by_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'))
    scan_type = Column(Enum(ScanType), nullable=False)
    status = Column(Enum(ScanStatus), nullable=False)
    started_at = Column(DateTime(timezone=True), default=func.current_timestamp())
    completed_at = Column(DateTime(timezone=True))
    duration_seconds = Column(Integer)
    error_message = Column(Text)
    metadata = Column(JSONB, default={})
    created_at = Column(DateTime(timezone=True), default=func.current_timestamp())

    # Relationships
    repository = relationship("MCPRepository", back_populates="scans")
    version = relationship("RepositoryVersion", back_populates="scans")
    organization = relationship("Organization", back_populates="scans")
    triggered_by = relationship("User", back_populates="scans_triggered")
    semgrep_findings = relationship("SemgrepFinding", back_populates="scan", cascade="all, delete-orphan")
    trufflehog_secrets = relationship("TruffleHogSecret", back_populates="scan", cascade="all, delete-orphan")
    osv_vulnerabilities = relationship("OSVVulnerability", back_populates="scan", cascade="all, delete-orphan")
    sbom = relationship("SBOM", back_populates="scan", uselist=False, cascade="all, delete-orphan")
    score = relationship("Score", back_populates="scan", uselist=False, cascade="all, delete-orphan")
    detection_rules = relationship("DetectionRule", back_populates="scan")


class SemgrepFinding(Base):
    """Semgrep static analysis findings"""
    __tablename__ = 'scan_semgrep_findings'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey('scans.id', ondelete='CASCADE'), nullable=False)
    repository_id = Column(UUID(as_uuid=True), ForeignKey('mcp_repositories.id', ondelete='CASCADE'), nullable=False)
    rule_id = Column(String(255), nullable=False)
    severity = Column(Enum(Severity), nullable=False)
    category = Column(String(100))
    file_path = Column(Text, nullable=False)
    line_start = Column(Integer)
    line_end = Column(Integer)
    column_start = Column(Integer)
    column_end = Column(Integer)
    message = Column(Text)
    code_snippet = Column(Text)
    fix_suggestion = Column(Text)
    cwe_ids = Column(ARRAY(Integer))
    owasp_ids = Column(ARRAY(String(50)))
    metadata = Column(JSONB, default={})
    created_at = Column(DateTime(timezone=True), default=func.current_timestamp())

    # Relationships
    scan = relationship("Scan", back_populates="semgrep_findings")


class TruffleHogSecret(Base):
    """TruffleHog secret detection findings"""
    __tablename__ = 'scan_trufflehog_secrets'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey('scans.id', ondelete='CASCADE'), nullable=False)
    repository_id = Column(UUID(as_uuid=True), ForeignKey('mcp_repositories.id', ondelete='CASCADE'), nullable=False)
    detector_name = Column(String(100), nullable=False)
    detector_type = Column(String(50))
    severity = Column(Enum(Severity), nullable=False)
    confidence = Column(String(50))
    file_path = Column(Text, nullable=False)
    line_number = Column(Integer)
    commit_sha = Column(String(64))
    commit_author = Column(String(255))
    commit_date = Column(DateTime(timezone=True))
    secret_hash = Column(String(64), nullable=False)  # SHA256 for deduplication
    is_verified = Column(Boolean, default=False)
    is_excluded = Column(Boolean, default=False)
    raw_secret_encrypted = Column(LargeBinary)  # Encrypted with pgcrypto
    metadata = Column(JSONB, default={})
    created_at = Column(DateTime(timezone=True), default=func.current_timestamp())

    # Relationships
    scan = relationship("Scan", back_populates="trufflehog_secrets")

    __table_args__ = (
        UniqueConstraint('repository_id', 'secret_hash'),
    )


class OSVVulnerability(Base):
    """OSV vulnerability scanner findings"""
    __tablename__ = 'scan_osv_vulnerabilities'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey('scans.id', ondelete='CASCADE'), nullable=False)
    repository_id = Column(UUID(as_uuid=True), ForeignKey('mcp_repositories.id', ondelete='CASCADE'), nullable=False)
    vulnerability_id = Column(String(100), nullable=False)  # CVE-2021-1234, GHSA-xxx
    package_name = Column(String(255), nullable=False)
    package_ecosystem = Column(String(50))
    current_version = Column(String(100))
    fixed_version = Column(String(100))
    severity = Column(Enum(Severity), nullable=False)
    cvss_score = Column(Numeric(3, 1))
    cvss_vector = Column(String(255))
    cwe_ids = Column(ARRAY(Integer))
    published_date = Column(Date)
    modified_date = Column(Date)
    description = Column(Text)
    references = Column(JSONB, default=[])
    is_kev = Column(Boolean, default=False)  # CISA Known Exploited Vulnerability
    has_exploit = Column(Boolean, default=False)
    age_days = Column(Integer)
    metadata = Column(JSONB, default={})
    created_at = Column(DateTime(timezone=True), default=func.current_timestamp())

    # Relationships
    scan = relationship("Scan", back_populates="osv_vulnerabilities")


class SBOM(Base):
    """Software Bill of Materials"""
    __tablename__ = 'sboms'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey('scans.id', ondelete='CASCADE'), nullable=False)
    repository_id = Column(UUID(as_uuid=True), ForeignKey('mcp_repositories.id', ondelete='CASCADE'), nullable=False)
    format = Column(String(50), nullable=False)  # cyclonedx, spdx
    spec_version = Column(String(20))
    serial_number = Column(String(255))
    total_components = Column(Integer)
    direct_dependencies = Column(Integer)
    transitive_dependencies = Column(Integer)
    sbom_data = Column(JSONB, nullable=False)
    created_at = Column(DateTime(timezone=True), default=func.current_timestamp())

    # Relationships
    scan = relationship("Scan", back_populates="sbom")


# =====================================================
# SCORING MODELS
# =====================================================

class Score(Base):
    """Final aggregated scores"""
    __tablename__ = 'scores'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey('scans.id', ondelete='CASCADE'), nullable=False, unique=True)
    repository_id = Column(UUID(as_uuid=True), ForeignKey('mcp_repositories.id', ondelete='CASCADE'), nullable=False)
    version_id = Column(UUID(as_uuid=True), ForeignKey('repository_versions.id', ondelete='CASCADE'), nullable=False)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id', ondelete='SET NULL'))
    scoring_policy_id = Column(UUID(as_uuid=True), ForeignKey('scoring_policies.id', ondelete='SET NULL'))
    final_score = Column(Integer, CheckConstraint('final_score >= 300 AND final_score <= 850'), nullable=False)
    grade = Column(String(2))  # A+, A, B+, B, C, D, F
    risk_level = Column(Enum(RiskLevel))
    percentile = Column(Integer)
    created_at = Column(DateTime(timezone=True), default=func.current_timestamp())

    # Relationships
    scan = relationship("Scan", back_populates="score")
    repository = relationship("MCPRepository", back_populates="scores")
    version = relationship("RepositoryVersion", back_populates="scores")
    scoring_policy = relationship("ScoringPolicy")
    components = relationship("ScoreComponent", back_populates="score", uselist=False, cascade="all, delete-orphan")


class ScoreComponent(Base):
    """Component scores breakdown"""
    __tablename__ = 'score_components'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    score_id = Column(UUID(as_uuid=True), ForeignKey('scores.id', ondelete='CASCADE'), nullable=False, unique=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey('scans.id', ondelete='CASCADE'), nullable=False)
    hygiene_score = Column(Integer, CheckConstraint('hygiene_score >= 300 AND hygiene_score <= 850'), nullable=False)
    hygiene_weight = Column(Numeric(3, 2), default=0.25)
    hygiene_details = Column(JSONB, default={})
    tools_score = Column(Integer, CheckConstraint('tools_score >= 300 AND tools_score <= 850'), nullable=False)
    tools_weight = Column(Numeric(3, 2), default=0.35)
    tools_details = Column(JSONB, default={})
    vulnerability_score = Column(Integer, CheckConstraint('vulnerability_score >= 300 AND vulnerability_score <= 850'), nullable=False)
    vulnerability_weight = Column(Numeric(3, 2), default=0.40)
    vulnerability_details = Column(JSONB, default={})
    created_at = Column(DateTime(timezone=True), default=func.current_timestamp())

    # Relationships
    score = relationship("Score", back_populates="components")


class ScoreHistory(Base):
    """Historical score tracking (time-series data)"""
    __tablename__ = 'score_history'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    repository_id = Column(UUID(as_uuid=True), ForeignKey('mcp_repositories.id', ondelete='CASCADE'), nullable=False)
    score = Column(Integer, CheckConstraint('score >= 300 AND score <= 850'), nullable=False)
    hygiene_score = Column(Integer)
    tools_score = Column(Integer)
    vulnerability_score = Column(Integer)
    recorded_at = Column(Date, nullable=False)
    created_at = Column(DateTime(timezone=True), default=func.current_timestamp())

    # Relationships
    repository = relationship("MCPRepository", back_populates="score_history")

    __table_args__ = (
        UniqueConstraint('repository_id', 'recorded_at'),
        Index('idx_score_history_repo_date', 'repository_id', 'recorded_at'),
    )


class ScoringPolicy(Base):
    """Custom scoring policies per organization"""
    __tablename__ = 'scoring_policies'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id', ondelete='CASCADE'))
    name = Column(String(255), nullable=False)
    description = Column(Text)
    is_default = Column(Boolean, default=False)
    hygiene_weight = Column(Numeric(3, 2), default=0.25)
    tools_weight = Column(Numeric(3, 2), default=0.35)
    vulnerability_weight = Column(Numeric(3, 2), default=0.40)
    custom_rules = Column(JSONB, default={})
    tags = Column(JSONB, default=[])
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=func.current_timestamp())
    updated_at = Column(DateTime(timezone=True), default=func.current_timestamp(), onupdate=func.current_timestamp())

    # Relationships
    organization = relationship("Organization", back_populates="scoring_policies")
    scores = relationship("Score", back_populates="scoring_policy")

    __table_args__ = (
        CheckConstraint('ABS((hygiene_weight + tools_weight + vulnerability_weight) - 1.0) < 0.01'),
    )


# =====================================================
# DETECTION RULES MODEL
# =====================================================

class DetectionRule(Base):
    """Network detection rules for MCPs"""
    __tablename__ = 'detection_rules'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    repository_id = Column(UUID(as_uuid=True), ForeignKey('mcp_repositories.id', ondelete='CASCADE'), nullable=False)
    scan_id = Column(UUID(as_uuid=True), ForeignKey('scans.id', ondelete='SET NULL'))
    rule_type = Column(Enum(RuleType), nullable=False)
    rule_name = Column(String(255), nullable=False)
    rule_content = Column(Text, nullable=False)
    severity = Column(Enum(Severity))
    confidence = Column(String(50))
    description = Column(Text)
    tags = Column(JSONB, default=[])
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=func.current_timestamp())
    updated_at = Column(DateTime(timezone=True), default=func.current_timestamp(), onupdate=func.current_timestamp())

    # Relationships
    repository = relationship("MCPRepository", back_populates="detection_rules")
    scan = relationship("Scan", back_populates="detection_rules")


# =====================================================
# MONITORING & COMPLIANCE MODELS
# =====================================================

class AuditLog(Base):
    """Comprehensive audit logging"""
    __tablename__ = 'audit_logs'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id', ondelete='SET NULL'))
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'))
    api_key_id = Column(UUID(as_uuid=True), ForeignKey('api_keys.id', ondelete='SET NULL'))
    action = Column(String(100), nullable=False)
    resource_type = Column(String(50))
    resource_id = Column(UUID(as_uuid=True))
    ip_address = Column(INET)
    user_agent = Column(Text)
    request_id = Column(UUID(as_uuid=True))
    changes = Column(JSONB)
    metadata = Column(JSONB, default={})
    created_at = Column(DateTime(timezone=True), default=func.current_timestamp())

    # Relationships
    user = relationship("User", back_populates="audit_logs")
    api_key = relationship("APIKey", back_populates="audit_logs")


class Alert(Base):
    """Alerts and notifications"""
    __tablename__ = 'alerts'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False)
    repository_id = Column(UUID(as_uuid=True), ForeignKey('mcp_repositories.id', ondelete='CASCADE'))
    alert_type = Column(String(50), nullable=False)
    severity = Column(Enum(Severity), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    details = Column(JSONB, default={})
    is_acknowledged = Column(Boolean, default=False)
    acknowledged_by = Column(UUID(as_uuid=True), ForeignKey('users.id'))
    acknowledged_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=func.current_timestamp())

    # Relationships
    organization = relationship("Organization", back_populates="alerts")
    repository = relationship("MCPRepository", back_populates="alerts")
    acknowledged_by_user = relationship("User", foreign_keys=[acknowledged_by])