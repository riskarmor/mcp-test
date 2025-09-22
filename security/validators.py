"""
Input Validation Module
========================
Comprehensive input validation and sanitization for security.

Prevents common injection attacks including:
- Command injection
- Path traversal
- SQL injection
- URL manipulation
- Script injection

Author: MCP Security Team
"""

import re
import shlex
import urllib.parse
from pathlib import Path
from typing import Optional, List, Tuple, Any
import logging

logger = logging.getLogger(__name__)


class ValidationError(Exception):
    """Custom exception for validation failures."""
    pass


# ================================================================================
# URL VALIDATION
# ================================================================================

def validate_github_url(url: str, allow_private: bool = False) -> str:
    """
    Validate and sanitize GitHub repository URL.

    Args:
        url: URL to validate
        allow_private: Whether to allow private repository URLs

    Returns:
        Sanitized URL

    Raises:
        ValidationError: If URL is invalid or malicious
    """
    if not url:
        raise ValidationError("URL cannot be empty")

    # Length check
    if len(url) > 2048:
        raise ValidationError("URL exceeds maximum length")

    # Parse URL
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as e:
        raise ValidationError(f"Invalid URL format: {e}")

    # Validate scheme
    if parsed.scheme not in ['http', 'https', 'git']:
        raise ValidationError(f"Invalid URL scheme: {parsed.scheme}")

    # Validate domain
    allowed_domains = [
        'github.com',
        'www.github.com',
        'api.github.com',
        'raw.githubusercontent.com',
        'gist.github.com'
    ]

    if parsed.netloc not in allowed_domains:
        raise ValidationError(f"Invalid GitHub domain: {parsed.netloc}")

    # Validate path format (should be /owner/repo format)
    path_pattern = r'^/[a-zA-Z0-9][\w.-]{0,38}/[\w.-]{1,100}(?:\.git)?/?$'
    if not re.match(path_pattern, parsed.path):
        raise ValidationError(f"Invalid repository path format: {parsed.path}")

    # Check for path traversal attempts
    if '..' in parsed.path or '~' in parsed.path:
        raise ValidationError("Path traversal attempt detected")

    # Check for suspicious patterns
    suspicious_patterns = [
        r'%00',  # Null byte
        r'%0[dD]',  # Carriage return
        r'%0[aA]',  # Line feed
        r'<script',  # Script injection
        r'javascript:',  # JavaScript protocol
        r'data:',  # Data protocol
    ]

    url_lower = url.lower()
    for pattern in suspicious_patterns:
        if re.search(pattern, url_lower):
            raise ValidationError(f"Suspicious pattern detected: {pattern}")

    # Reconstruct clean URL
    clean_url = f"https://github.com{parsed.path}"

    logger.debug(f"Validated GitHub URL: {clean_url}")
    return clean_url


# ================================================================================
# FILE PATH VALIDATION
# ================================================================================

def validate_file_path(path: str, base_dir: Optional[str] = None,
                       must_exist: bool = False) -> Path:
    """
    Validate and sanitize file system path.

    Args:
        path: Path to validate
        base_dir: Base directory to restrict access to
        must_exist: Whether the path must already exist

    Returns:
        Validated Path object

    Raises:
        ValidationError: If path is invalid or attempts traversal
    """
    if not path:
        raise ValidationError("Path cannot be empty")

    # Length check
    if len(path) > 4096:
        raise ValidationError("Path exceeds maximum length")

    # Convert to Path object and resolve
    try:
        path_obj = Path(path).resolve()
    except Exception as e:
        raise ValidationError(f"Invalid path: {e}")

    # Check for null bytes
    if '\x00' in str(path_obj):
        raise ValidationError("Null byte in path")

    # If base_dir is specified, ensure path is within it
    if base_dir:
        base_path = Path(base_dir).resolve()
        try:
            path_obj.relative_to(base_path)
        except ValueError:
            raise ValidationError(f"Path escapes base directory: {base_dir}")

    # Check if path exists if required
    if must_exist and not path_obj.exists():
        raise ValidationError(f"Path does not exist: {path_obj}")

    # Check for suspicious file names
    suspicious_names = [
        '.bashrc', '.zshrc', '.profile',  # Shell configs
        '.ssh', 'id_rsa', 'id_dsa',  # SSH keys
        '.aws', '.azure', '.gcloud',  # Cloud credentials
        'passwd', 'shadow', 'sudoers',  # System files
    ]

    if path_obj.name in suspicious_names:
        logger.warning(f"Suspicious file name accessed: {path_obj.name}")

    return path_obj


# ================================================================================
# COMMAND SANITIZATION
# ================================================================================

def sanitize_command_input(command: str, args: List[str],
                          allow_shell: bool = False) -> Tuple[str, List[str]]:
    """
    Sanitize command and arguments for subprocess execution.

    Args:
        command: Command to execute
        args: List of arguments
        allow_shell: Whether to allow shell execution (dangerous!)

    Returns:
        Tuple of (sanitized_command, sanitized_args)

    Raises:
        ValidationError: If command or arguments are malicious
    """
    if not command:
        raise ValidationError("Command cannot be empty")

    # Never allow shell=True in production
    if allow_shell:
        logger.warning("Shell execution requested - this is dangerous!")

    # Validate command path
    command_path = validate_file_path(command, must_exist=True)

    # Check if command is in allowed list
    allowed_commands = [
        'git', 'cdxgen', 'syft', 'osv-scanner', 'trufflehog',
        'semgrep', 'python3', 'node', 'npm'
    ]

    command_name = command_path.name
    if command_name not in allowed_commands:
        logger.warning(f"Non-standard command execution: {command_name}")

    # Sanitize arguments
    sanitized_args = []
    for arg in args:
        # Check for shell metacharacters
        if re.search(r'[;&|<>`$(){}[\]!*?~]', arg):
            # Quote the argument
            arg = shlex.quote(arg)

        # Check for null bytes
        if '\x00' in arg:
            raise ValidationError("Null byte in argument")

        # Check length
        if len(arg) > 1024:
            raise ValidationError("Argument exceeds maximum length")

        sanitized_args.append(arg)

    return str(command_path), sanitized_args


# ================================================================================
# SQL INPUT VALIDATION
# ================================================================================

def validate_sql_input(value: Any, param_type: str = 'string',
                      max_length: int = 1000) -> Any:
    """
    Validate input for SQL queries.

    Args:
        value: Value to validate
        param_type: Expected type ('string', 'int', 'float', 'bool', 'uuid')
        max_length: Maximum length for strings

    Returns:
        Validated value

    Raises:
        ValidationError: If value is invalid or potentially malicious
    """
    if value is None:
        return None

    if param_type == 'string':
        if not isinstance(value, str):
            raise ValidationError(f"Expected string, got {type(value)}")

        # Length check
        if len(value) > max_length:
            raise ValidationError(f"String exceeds maximum length: {max_length}")

        # Check for SQL injection patterns
        sql_patterns = [
            r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|FROM|WHERE)\b)',
            r'(--|#|/\*|\*/)',  # SQL comments
            r"('|\"|;|\\x00|\\n|\\r)",  # Quotes and special chars
            r'(\bOR\b.*=.*)',  # OR conditions
            r'(xp_|sp_)',  # SQL Server stored procedures
        ]

        value_upper = value.upper()
        for pattern in sql_patterns:
            if re.search(pattern, value_upper, re.IGNORECASE):
                logger.warning(f"Potential SQL injection pattern detected: {pattern}")
                raise ValidationError("Suspicious SQL pattern detected")

        return value

    elif param_type == 'int':
        try:
            return int(value)
        except (ValueError, TypeError):
            raise ValidationError(f"Invalid integer value: {value}")

    elif param_type == 'float':
        try:
            return float(value)
        except (ValueError, TypeError):
            raise ValidationError(f"Invalid float value: {value}")

    elif param_type == 'bool':
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ('true', '1', 'yes', 'on')
        return bool(value)

    elif param_type == 'uuid':
        import uuid
        try:
            return str(uuid.UUID(str(value)))
        except ValueError:
            raise ValidationError(f"Invalid UUID: {value}")

    else:
        raise ValidationError(f"Unknown parameter type: {param_type}")


# ================================================================================
# REPOSITORY NAME VALIDATION
# ================================================================================

def validate_repo_name(name: str) -> str:
    """
    Validate repository name.

    Args:
        name: Repository name to validate

    Returns:
        Validated name

    Raises:
        ValidationError: If name is invalid
    """
    if not name:
        raise ValidationError("Repository name cannot be empty")

    # GitHub repository name rules
    # - Can only contain alphanumeric characters, hyphens, underscores, and periods
    # - Cannot start with a period
    # - Maximum 100 characters
    if len(name) > 100:
        raise ValidationError("Repository name exceeds maximum length")

    if name.startswith('.'):
        raise ValidationError("Repository name cannot start with a period")

    if not re.match(r'^[\w.-]+$', name):
        raise ValidationError("Repository name contains invalid characters")

    return name


# ================================================================================
# JSON VALIDATION
# ================================================================================

def validate_json_input(json_str: str, max_size: int = 10485760) -> dict:
    """
    Validate and parse JSON input.

    Args:
        json_str: JSON string to validate
        max_size: Maximum allowed size in bytes (default 10MB)

    Returns:
        Parsed JSON object

    Raises:
        ValidationError: If JSON is invalid or too large
    """
    if not json_str:
        raise ValidationError("JSON input cannot be empty")

    # Size check
    if len(json_str) > max_size:
        raise ValidationError(f"JSON exceeds maximum size: {max_size} bytes")

    # Check for suspicious patterns before parsing
    suspicious = [
        '__proto__',  # Prototype pollution
        'constructor',  # Constructor manipulation
        '$where',  # MongoDB injection
        'javascript:',  # XSS
    ]

    for pattern in suspicious:
        if pattern in json_str:
            raise ValidationError(f"Suspicious pattern in JSON: {pattern}")

    # Parse JSON
    import json
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ValidationError(f"Invalid JSON: {e}")

    return data


# ================================================================================
# GENERAL SANITIZATION
# ================================================================================

def sanitize_for_logging(value: str, max_length: int = 500) -> str:
    """
    Sanitize value for safe logging.

    Args:
        value: Value to sanitize
        max_length: Maximum length for output

    Returns:
        Sanitized string safe for logging
    """
    if not value:
        return ""

    # Convert to string
    value = str(value)

    # Truncate if too long
    if len(value) > max_length:
        value = value[:max_length] + "...[truncated]"

    # Remove control characters
    value = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', value)

    # Redact potential secrets
    secret_patterns = [
        (r'\b[A-Za-z0-9+/]{40}\b', '[REDACTED-KEY]'),  # Base64 keys
        (r'\b[a-f0-9]{40}\b', '[REDACTED-SHA1]'),  # SHA1
        (r'\b[a-f0-9]{64}\b', '[REDACTED-SHA256]'),  # SHA256
        (r'(password|token|key|secret|api)["\']?\s*[:=]\s*["\']?[\w\-]+',
         '[REDACTED-CREDENTIAL]'),
        (r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', '[REDACTED-CARD]'),  # Credit cards
    ]

    for pattern, replacement in secret_patterns:
        value = re.sub(pattern, replacement, value, flags=re.IGNORECASE)

    return value


def is_safe_filename(filename: str) -> bool:
    """
    Check if filename is safe for filesystem operations.

    Args:
        filename: Filename to check

    Returns:
        True if filename is safe
    """
    if not filename:
        return False

    # Check length
    if len(filename) > 255:
        return False

    # Check for path traversal
    if '..' in filename or '/' in filename or '\\' in filename:
        return False

    # Check for null bytes
    if '\x00' in filename:
        return False

    # Check for reserved names (Windows)
    reserved = [
        'CON', 'PRN', 'AUX', 'NUL',
        'COM1', 'COM2', 'COM3', 'COM4',
        'LPT1', 'LPT2', 'LPT3'
    ]

    if filename.upper() in reserved:
        return False

    # Check for unsafe characters
    if re.search(r'[<>:"|?*]', filename):
        return False

    return True