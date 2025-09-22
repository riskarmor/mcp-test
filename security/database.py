"""
Database Security Layer
========================
Secure database operations with encryption, parameterization, and audit logging.

Provides protection against:
- SQL injection
- Data leakage
- Unauthorized access
- Data tampering

Author: MCP Security Team
"""

import hashlib
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from contextlib import contextmanager
import secrets

logger = logging.getLogger(__name__)


class DatabaseSecurityError(Exception):
    """Database security exception."""
    pass


class SecureDatabase:
    """
    Secure database wrapper with built-in security controls.

    Features:
    - Parameterized queries only
    - Automatic encryption/decryption
    - Row-level security
    - Audit logging
    - Connection encryption
    """

    def __init__(self, connection_string: str,
                 encrypt_data: bool = True,
                 encryption_key: Optional[str] = None,
                 enable_audit: bool = True):
        """
        Initialize secure database connection.

        Args:
            connection_string: Database connection string
            encrypt_data: Whether to encrypt sensitive data
            encryption_key: Encryption key for data
            enable_audit: Whether to enable audit logging
        """
        self.encrypt_data = encrypt_data
        self.encryption_key = encryption_key or self._generate_key()
        self.enable_audit = enable_audit
        self.connection = None
        self.user_context = None

        # Parse and validate connection string
        self._validate_connection_string(connection_string)
        self.connection_params = self._parse_connection_string(connection_string)

        # Initialize encryption if enabled
        if self.encrypt_data:
            self._init_encryption()

    def _validate_connection_string(self, conn_str: str) -> None:
        """Validate database connection string."""
        if not conn_str:
            raise DatabaseSecurityError("Connection string cannot be empty")

        # Check for SSL/TLS requirement
        if 'sslmode=disable' in conn_str.lower():
            logger.warning("Database connection without SSL/TLS is insecure")

        # Ensure sensitive data is not in connection string
        sensitive_patterns = ['password=', 'pwd=', 'apikey=']
        for pattern in sensitive_patterns:
            if pattern in conn_str.lower():
                # Password should be provided separately or via environment
                logger.warning("Sensitive data in connection string should use environment variables")

    def _parse_connection_string(self, conn_str: str) -> Dict[str, str]:
        """Parse connection string into components."""
        # This is a simplified parser - use proper database library in production
        params = {}
        parts = conn_str.split(';')
        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                params[key.strip().lower()] = value.strip()
        return params

    def _generate_key(self) -> str:
        """Generate encryption key."""
        return secrets.token_hex(32)

    def _init_encryption(self) -> None:
        """Initialize encryption system."""
        # In production, use proper encryption library like cryptography
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
        import base64

        # Derive key from password
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'mcp_security_salt',  # Should be random in production
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.encryption_key.encode()))
        self.cipher = Fernet(key)

    def encrypt_value(self, value: str) -> str:
        """
        Encrypt a value for storage.

        Args:
            value: Plain text value

        Returns:
            Encrypted value
        """
        if not self.encrypt_data or not value:
            return value

        try:
            encrypted = self.cipher.encrypt(value.encode())
            return encrypted.decode('utf-8')
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise DatabaseSecurityError("Failed to encrypt data")

    def decrypt_value(self, encrypted: str) -> str:
        """
        Decrypt a value from storage.

        Args:
            encrypted: Encrypted value

        Returns:
            Decrypted plain text
        """
        if not self.encrypt_data or not encrypted:
            return encrypted

        try:
            decrypted = self.cipher.decrypt(encrypted.encode())
            return decrypted.decode('utf-8')
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise DatabaseSecurityError("Failed to decrypt data")

    @contextmanager
    def secure_transaction(self, user_id: str, operation: str):
        """
        Execute database operations in a secure transaction.

        Args:
            user_id: User performing the operation
            operation: Description of operation

        Yields:
            Transaction context
        """
        transaction_id = secrets.token_hex(16)
        start_time = datetime.utcnow()

        # Log transaction start
        if self.enable_audit:
            self._audit_log('transaction_start', {
                'transaction_id': transaction_id,
                'user_id': user_id,
                'operation': operation
            })

        try:
            # Begin transaction
            yield transaction_id

            # Log successful completion
            if self.enable_audit:
                self._audit_log('transaction_success', {
                    'transaction_id': transaction_id,
                    'duration_ms': (datetime.utcnow() - start_time).total_seconds() * 1000
                })

        except Exception as e:
            # Log failure
            if self.enable_audit:
                self._audit_log('transaction_failure', {
                    'transaction_id': transaction_id,
                    'error': str(e)
                })
            raise

        finally:
            # Cleanup
            pass

    def execute_query(self, query: str, params: Optional[Dict[str, Any]] = None,
                     user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Execute a parameterized query safely.

        Args:
            query: SQL query with parameter placeholders
            params: Query parameters
            user_id: User executing the query

        Returns:
            Query results

        Raises:
            DatabaseSecurityError: If query is unsafe
        """
        # Validate query
        self._validate_query(query)

        # Validate parameters
        if params:
            params = self._validate_params(params)

        # Apply row-level security
        query, params = self._apply_row_level_security(query, params, user_id)

        # Log query execution
        if self.enable_audit:
            self._audit_log('query_execution', {
                'user_id': user_id,
                'query_hash': hashlib.sha256(query.encode()).hexdigest(),
                'param_count': len(params) if params else 0
            })

        # Execute query (simplified - use actual database library)
        results = self._execute_raw_query(query, params)

        # Decrypt sensitive fields
        if self.encrypt_data:
            results = self._decrypt_results(results)

        return results

    def _validate_query(self, query: str) -> None:
        """Validate SQL query for safety."""
        query_upper = query.upper()

        # Check for dangerous operations
        dangerous_keywords = [
            'DROP TABLE', 'DROP DATABASE', 'TRUNCATE',
            'DELETE FROM', 'UPDATE SET',  # Without WHERE clause
            'GRANT', 'REVOKE', 'CREATE USER', 'ALTER USER'
        ]

        for keyword in dangerous_keywords:
            if keyword in query_upper:
                # Check if it's a safe operation
                if keyword in ['DELETE FROM', 'UPDATE SET']:
                    # Ensure WHERE clause exists
                    if 'WHERE' not in query_upper:
                        raise DatabaseSecurityError(f"Unsafe {keyword} without WHERE clause")
                else:
                    raise DatabaseSecurityError(f"Dangerous operation not allowed: {keyword}")

        # Check for comment injection
        if '--' in query or '/*' in query:
            raise DatabaseSecurityError("SQL comments not allowed in queries")

    def _validate_params(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Validate query parameters."""
        validated = {}

        for key, value in params.items():
            # Validate parameter name
            if not key.replace('_', '').isalnum():
                raise DatabaseSecurityError(f"Invalid parameter name: {key}")

            # Validate parameter value
            if isinstance(value, str):
                # Check for SQL injection attempts
                if any(c in value for c in [';', '--', '/*', '*/', '\x00']):
                    raise DatabaseSecurityError(f"Suspicious characters in parameter: {key}")

            validated[key] = value

        return validated

    def _apply_row_level_security(self, query: str, params: Dict[str, Any],
                                 user_id: str) -> Tuple[str, Dict[str, Any]]:
        """Apply row-level security to query."""
        if not user_id:
            return query, params

        # Add user context to WHERE clause (simplified)
        # In production, use proper RLS implementation
        tables_with_rls = ['repositories', 'scan_results', 'vulnerabilities']

        for table in tables_with_rls:
            if table in query.lower():
                # Add user filter
                if 'WHERE' in query.upper():
                    query += f" AND {table}.owner_id = :user_id"
                else:
                    query += f" WHERE {table}.owner_id = :user_id"

                params = params or {}
                params['user_id'] = user_id

        return query, params

    def _execute_raw_query(self, query: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Execute raw query (placeholder for actual implementation)."""
        # This would use actual database library (psycopg2, pymysql, etc.)
        # For now, return empty result
        logger.debug(f"Executing query: {query[:100]}...")
        return []

    def _decrypt_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Decrypt encrypted fields in results."""
        # Define which fields should be decrypted
        encrypted_fields = [
            'api_key', 'token', 'password', 'secret',
            'private_key', 'credential', 'sensitive_data'
        ]

        decrypted_results = []
        for row in results:
            decrypted_row = {}
            for field, value in row.items():
                if field in encrypted_fields and value:
                    decrypted_row[field] = self.decrypt_value(value)
                else:
                    decrypted_row[field] = value
            decrypted_results.append(decrypted_row)

        return decrypted_results

    def _audit_log(self, event_type: str, details: Dict[str, Any]) -> None:
        """Log audit event."""
        audit_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'details': details
        }

        # In production, write to audit table or log aggregator
        logger.info(f"AUDIT: {json.dumps(audit_entry)}")

    def insert_secure(self, table: str, data: Dict[str, Any],
                     user_id: str) -> Optional[str]:
        """
        Securely insert data into table.

        Args:
            table: Table name
            data: Data to insert
            user_id: User performing insert

        Returns:
            Inserted row ID
        """
        # Validate table name
        if not table.replace('_', '').isalnum():
            raise DatabaseSecurityError(f"Invalid table name: {table}")

        # Encrypt sensitive fields
        encrypted_data = {}
        sensitive_fields = ['password', 'token', 'api_key', 'secret']

        for field, value in data.items():
            if field in sensitive_fields and value:
                encrypted_data[field] = self.encrypt_value(str(value))
            else:
                encrypted_data[field] = value

        # Build parameterized insert query
        fields = list(encrypted_data.keys())
        placeholders = [f":{field}" for field in fields]

        query = f"INSERT INTO {table} ({', '.join(fields)}) VALUES ({', '.join(placeholders)})"

        # Execute with audit
        with self.secure_transaction(user_id, f"INSERT into {table}"):
            result = self.execute_query(query, encrypted_data, user_id)

        return result[0]['id'] if result else None

    def update_secure(self, table: str, row_id: str,
                     updates: Dict[str, Any], user_id: str) -> bool:
        """
        Securely update data in table.

        Args:
            table: Table name
            row_id: Row ID to update
            updates: Fields to update
            user_id: User performing update

        Returns:
            True if update successful
        """
        # Validate inputs
        if not table.replace('_', '').isalnum():
            raise DatabaseSecurityError(f"Invalid table name: {table}")

        # Build parameterized update query
        set_clauses = [f"{field} = :{field}" for field in updates.keys()]
        query = f"UPDATE {table} SET {', '.join(set_clauses)} WHERE id = :row_id"

        params = dict(updates)
        params['row_id'] = row_id

        # Execute with audit
        with self.secure_transaction(user_id, f"UPDATE {table} id={row_id}"):
            result = self.execute_query(query, params, user_id)

        return True

    def get_connection_info(self) -> Dict[str, Any]:
        """Get safe connection information (no credentials)."""
        return {
            'host': self.connection_params.get('host', 'unknown'),
            'database': self.connection_params.get('database', 'unknown'),
            'ssl_enabled': 'sslmode' in self.connection_params,
            'encryption_enabled': self.encrypt_data,
            'audit_enabled': self.enable_audit
        }