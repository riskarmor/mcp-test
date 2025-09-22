"""
Security Configuration Module
==============================
Centralized security configuration and settings management.

Provides secure configuration loading, validation, and access control
for all security-related settings in the MCP system.

Author: MCP Security Team
"""

import os
import json
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class SecurityLevel(Enum):
    """System security levels."""
    LOW = "low"          # Development environment
    MEDIUM = "medium"    # Staging environment
    HIGH = "high"        # Production environment
    CRITICAL = "critical"  # High-security production


@dataclass
class SecurityConfig:
    """
    Security configuration container.

    Manages all security-related settings with validation and
    secure defaults for the MCP Security Analysis System.
    """

    # Security Level
    security_level: SecurityLevel = SecurityLevel.HIGH

    # Authentication Settings
    require_authentication: bool = True
    session_timeout_minutes: int = 30
    max_failed_logins: int = 5
    lockout_duration_minutes: int = 15

    # Authorization Settings
    enable_rbac: bool = True
    default_role: str = "viewer"

    # Database Security
    encrypt_database: bool = True
    database_encryption_key: Optional[str] = None
    use_row_level_security: bool = True
    connection_encryption: bool = True

    # Storage Security
    encrypt_storage: bool = True
    storage_encryption_algorithm: str = "AES-256-GCM"
    quarantine_enabled: bool = True
    quarantine_duration_hours: int = 24

    # File System Permissions
    repo_directory_permissions: int = 0o700  # Owner only
    cache_directory_permissions: int = 0o700
    log_directory_permissions: int = 0o750  # Owner + group read

    # Input Validation
    max_url_length: int = 2048
    max_path_length: int = 4096
    max_query_length: int = 10000
    allowed_github_domains: list = None

    # Rate Limiting
    enable_rate_limiting: bool = True
    rate_limit_requests_per_hour: int = 1000
    github_api_rate_limit: int = 4500  # Stay under 5000

    # Monitoring & Logging
    enable_security_monitoring: bool = True
    enable_audit_logging: bool = True
    log_sensitive_data: bool = False
    alert_on_suspicious_activity: bool = True

    # Subprocess Execution
    subprocess_timeout_seconds: int = 300
    max_subprocess_memory_mb: int = 2048
    allow_shell_commands: bool = False

    # Network Security
    verify_ssl_certificates: bool = True
    use_proxy: bool = False
    proxy_url: Optional[str] = None

    # Malware Scanning
    enable_malware_scanning: bool = True
    malware_scan_timeout_seconds: int = 60

    # Data Retention
    audit_log_retention_days: int = 2555  # 7 years
    scan_result_retention_days: int = 180
    repo_snapshot_retention_days: int = 90

    def __post_init__(self):
        """Initialize with secure defaults."""
        if self.allowed_github_domains is None:
            self.allowed_github_domains = [
                'github.com',
                'raw.githubusercontent.com',
                'api.github.com'
            ]

        # Generate encryption key if not provided
        if self.encrypt_database and not self.database_encryption_key:
            self.database_encryption_key = self._generate_encryption_key()

    @classmethod
    def from_environment(cls) -> 'SecurityConfig':
        """
        Load configuration from environment variables.

        Returns:
            SecurityConfig instance with environment-based settings
        """
        config = cls()

        # Security level
        level = os.getenv('MCP_SECURITY_LEVEL', 'high').lower()
        config.security_level = SecurityLevel(level)

        # Authentication
        config.require_authentication = os.getenv('MCP_REQUIRE_AUTH', 'true').lower() == 'true'
        config.session_timeout_minutes = int(os.getenv('MCP_SESSION_TIMEOUT', '30'))

        # Database
        config.encrypt_database = os.getenv('MCP_ENCRYPT_DB', 'true').lower() == 'true'
        config.database_encryption_key = os.getenv('MCP_DB_ENCRYPTION_KEY')

        # Storage
        config.encrypt_storage = os.getenv('MCP_ENCRYPT_STORAGE', 'true').lower() == 'true'

        # Rate limiting
        config.rate_limit_requests_per_hour = int(os.getenv('MCP_RATE_LIMIT', '1000'))

        # Monitoring
        config.enable_audit_logging = os.getenv('MCP_AUDIT_LOG', 'true').lower() == 'true'

        return config

    @classmethod
    def from_file(cls, config_path: str) -> 'SecurityConfig':
        """
        Load configuration from JSON file.

        Args:
            config_path: Path to configuration file

        Returns:
            SecurityConfig instance
        """
        config_path = Path(config_path)

        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        # Verify file permissions (should not be world-readable)
        stat = config_path.stat()
        if stat.st_mode & 0o004:
            logger.warning(f"Configuration file is world-readable: {config_path}")

        with open(config_path, 'r') as f:
            data = json.load(f)

        # Convert security level string to enum
        if 'security_level' in data:
            data['security_level'] = SecurityLevel(data['security_level'])

        return cls(**data)

    def validate(self) -> bool:
        """
        Validate configuration settings.

        Returns:
            True if configuration is valid

        Raises:
            ValueError: If configuration is invalid
        """
        # Validate security level settings
        if self.security_level == SecurityLevel.CRITICAL:
            if not self.require_authentication:
                raise ValueError("Authentication required for CRITICAL security level")
            if not self.encrypt_database:
                raise ValueError("Database encryption required for CRITICAL security level")
            if not self.encrypt_storage:
                raise ValueError("Storage encryption required for CRITICAL security level")
            if not self.enable_audit_logging:
                raise ValueError("Audit logging required for CRITICAL security level")

        # Validate rate limits
        if self.rate_limit_requests_per_hour < 1:
            raise ValueError("Rate limit must be at least 1 request per hour")

        if self.github_api_rate_limit > 5000:
            raise ValueError("GitHub API rate limit cannot exceed 5000 per hour")

        # Validate timeouts
        if self.subprocess_timeout_seconds < 1:
            raise ValueError("Subprocess timeout must be at least 1 second")

        if self.session_timeout_minutes < 1:
            raise ValueError("Session timeout must be at least 1 minute")

        # Validate file permissions
        if self.repo_directory_permissions & 0o077:
            logger.warning("Repository directory permissions allow group/other access")

        return True

    def _generate_encryption_key(self) -> str:
        """
        Generate a secure encryption key.

        Returns:
            Hex-encoded encryption key
        """
        # In production, this should use a proper KMS or secret manager
        import secrets
        return secrets.token_hex(32)  # 256-bit key

    def get_secure_paths(self) -> Dict[str, Path]:
        """
        Get secure directory paths with proper permissions.

        Returns:
            Dictionary of secure paths
        """
        base_dir = Path(os.getenv('MCP_BASE_DIR', '/opt/mcp'))

        paths = {
            'repos': base_dir / 'repos',
            'quarantine': base_dir / 'quarantine',
            'cache': base_dir / 'cache',
            'logs': base_dir / 'logs',
            'audit': base_dir / 'audit',
            'database': base_dir / 'database'
        }

        # Create directories with secure permissions
        for name, path in paths.items():
            path.mkdir(parents=True, exist_ok=True)

            # Set appropriate permissions
            if name in ['repos', 'quarantine', 'cache']:
                path.chmod(self.repo_directory_permissions)
            elif name in ['logs', 'audit']:
                path.chmod(self.log_directory_permissions)
            else:
                path.chmod(0o700)  # Default to owner-only

        return paths

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert configuration to dictionary (for serialization).

        Returns:
            Dictionary representation
        """
        data = {}
        for key, value in self.__dict__.items():
            if key.startswith('_'):
                continue
            if isinstance(value, Enum):
                data[key] = value.value
            elif key in ['database_encryption_key', 'proxy_url']:
                # Don't serialize sensitive data
                data[key] = '***REDACTED***' if value else None
            else:
                data[key] = value
        return data

    def apply_hardening(self) -> None:
        """Apply security hardening based on security level."""
        if self.security_level in [SecurityLevel.HIGH, SecurityLevel.CRITICAL]:
            # Force strict settings
            self.require_authentication = True
            self.enable_rbac = True
            self.encrypt_database = True
            self.encrypt_storage = True
            self.enable_audit_logging = True
            self.verify_ssl_certificates = True
            self.allow_shell_commands = False
            self.log_sensitive_data = False

            # Tighten limits
            self.max_failed_logins = 3
            self.session_timeout_minutes = 15
            self.subprocess_timeout_seconds = 120

            logger.info(f"Applied security hardening for {self.security_level.value} level")


# Global configuration instance
_config: Optional[SecurityConfig] = None


def get_security_config() -> SecurityConfig:
    """
    Get the global security configuration instance.

    Returns:
        SecurityConfig instance
    """
    global _config

    if _config is None:
        # Try loading from environment first
        _config = SecurityConfig.from_environment()

        # Validate configuration
        _config.validate()

        # Apply hardening
        _config.apply_hardening()

        logger.info(f"Security configuration loaded: level={_config.security_level.value}")

    return _config


def set_security_config(config: SecurityConfig) -> None:
    """
    Set the global security configuration.

    Args:
        config: SecurityConfig instance to use
    """
    global _config

    # Validate before setting
    config.validate()
    config.apply_hardening()

    _config = config
    logger.info(f"Security configuration updated: level={config.security_level.value}")