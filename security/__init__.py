"""
MCP Security Layer
==================
Comprehensive security controls for the MCP Security Analysis System.

This module provides defense-in-depth security for processing untrusted
public repositories while maintaining data integrity and confidentiality.

Author: MCP Security Team
"""

from .config import SecurityConfig
from .validators import (
    validate_github_url,
    validate_file_path,
    sanitize_command_input,
    validate_sql_input
)
from .database import SecureDatabase
from .storage import SecureStorage
from .auth import AuthenticationManager
from .rbac import AuthorizationManager
from .monitor import SecurityMonitor
from .audit import AuditLogger

__all__ = [
    'SecurityConfig',
    'validate_github_url',
    'validate_file_path',
    'sanitize_command_input',
    'validate_sql_input',
    'SecureDatabase',
    'SecureStorage',
    'AuthenticationManager',
    'AuthorizationManager',
    'SecurityMonitor',
    'AuditLogger'
]

# Version
__version__ = '1.0.0'