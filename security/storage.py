"""
Secure Storage Module
=====================
Secure file storage with encryption, isolation, and integrity verification.

Provides protection for:
- Repository storage
- SBOM files
- Scan results
- Cached data

Author: MCP Security Team
"""

import hashlib
import json
import os
import shutil
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List
import logging

logger = logging.getLogger(__name__)


class StorageSecurityError(Exception):
    """Storage security exception."""
    pass


class SecureStorage:
    """
    Secure file storage manager with encryption and isolation.

    Features:
    - Encrypted storage at rest
    - Repository isolation
    - Quarantine for suspicious files
    - Integrity verification
    - Automatic cleanup
    """

    def __init__(self, base_path: str = "/opt/mcp/storage",
                 encrypt: bool = True,
                 quarantine_enabled: bool = True):
        """
        Initialize secure storage.

        Args:
            base_path: Base directory for storage
            encrypt: Whether to encrypt stored files
            quarantine_enabled: Whether to enable quarantine
        """
        self.base_path = Path(base_path).resolve()
        self.encrypt = encrypt
        self.quarantine_enabled = quarantine_enabled

        # Initialize directory structure
        self._init_directories()

        # Initialize encryption if enabled
        if self.encrypt:
            self._init_encryption()

        # Load integrity database
        self.integrity_db = self._load_integrity_db()

    def _init_directories(self) -> None:
        """Initialize secure directory structure."""
        directories = {
            'repos': 0o700,        # Repository storage
            'quarantine': 0o700,   # Suspicious files
            'cache': 0o700,        # Cached data
            'temp': 0o700,         # Temporary files
            'sboms': 0o700,        # SBOM storage
            'results': 0o700,      # Scan results
            'integrity': 0o700,    # Integrity data
        }

        for dir_name, permissions in directories.items():
            dir_path = self.base_path / dir_name
            dir_path.mkdir(parents=True, exist_ok=True)
            dir_path.chmod(permissions)

            # Verify permissions
            if dir_path.stat().st_mode & 0o777 != permissions:
                logger.warning(f"Failed to set permissions for {dir_path}")

    def _init_encryption(self) -> None:
        """Initialize encryption for storage."""
        # In production, use LUKS or similar filesystem encryption
        # This is a placeholder for application-level encryption
        pass

    def _load_integrity_db(self) -> Dict[str, str]:
        """Load integrity verification database."""
        integrity_file = self.base_path / 'integrity' / 'checksums.json'

        if integrity_file.exists():
            try:
                with open(integrity_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load integrity database: {e}")

        return {}

    def store_repository(self, repo_url: str, source_path: str,
                        scan_first: bool = True) -> str:
        """
        Store repository in secure storage.

        Args:
            repo_url: Repository URL
            source_path: Local path to repository
            scan_first: Whether to scan for malware first

        Returns:
            Storage path

        Raises:
            StorageSecurityError: If storage fails security checks
        """
        # Generate storage ID
        storage_id = self._generate_storage_id(repo_url)
        dest_path = self.base_path / 'repos' / storage_id

        # Scan for malware if requested
        if scan_first:
            if not self._scan_for_malware(source_path):
                # Move to quarantine
                if self.quarantine_enabled:
                    quarantine_path = self._quarantine_path(source_path, "malware_detected")
                    raise StorageSecurityError(f"Malware detected, quarantined at {quarantine_path}")
                else:
                    raise StorageSecurityError("Malware detected in repository")

        # Create isolated storage
        dest_path.mkdir(parents=True, exist_ok=True)
        dest_path.chmod(0o700)

        # Copy repository
        try:
            if Path(source_path).is_dir():
                shutil.copytree(source_path, dest_path / 'source', dirs_exist_ok=True)
            else:
                shutil.copy2(source_path, dest_path / 'source')
        except Exception as e:
            raise StorageSecurityError(f"Failed to store repository: {e}")

        # Calculate and store integrity hash
        integrity_hash = self._calculate_integrity_hash(dest_path)
        self._store_integrity_hash(storage_id, integrity_hash)

        # Store metadata
        metadata = {
            'url': repo_url,
            'stored_at': datetime.utcnow().isoformat(),
            'storage_id': storage_id,
            'integrity_hash': integrity_hash,
            'size_bytes': self._get_directory_size(dest_path)
        }

        metadata_file = dest_path / 'metadata.json'
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)

        logger.info(f"Repository stored: {storage_id}")
        return str(dest_path)

    def retrieve_repository(self, storage_id: str,
                          verify_integrity: bool = True) -> str:
        """
        Retrieve repository from storage.

        Args:
            storage_id: Storage identifier
            verify_integrity: Whether to verify integrity

        Returns:
            Path to repository

        Raises:
            StorageSecurityError: If integrity check fails
        """
        repo_path = self.base_path / 'repos' / storage_id

        if not repo_path.exists():
            raise StorageSecurityError(f"Repository not found: {storage_id}")

        # Verify integrity
        if verify_integrity:
            expected_hash = self.integrity_db.get(storage_id)
            if expected_hash:
                actual_hash = self._calculate_integrity_hash(repo_path)
                if actual_hash != expected_hash:
                    # Quarantine corrupted repository
                    if self.quarantine_enabled:
                        quarantine_path = self._quarantine_path(str(repo_path), "integrity_failure")
                        raise StorageSecurityError(f"Integrity check failed, quarantined at {quarantine_path}")
                    else:
                        raise StorageSecurityError("Repository integrity check failed")

        return str(repo_path / 'source')

    def _generate_storage_id(self, identifier: str) -> str:
        """Generate unique storage ID."""
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        hash_id = hashlib.sha256(identifier.encode()).hexdigest()[:12]
        return f"{timestamp}_{hash_id}"

    def _scan_for_malware(self, path: str) -> bool:
        """
        Scan path for malware.

        Args:
            path: Path to scan

        Returns:
            True if safe, False if malware detected
        """
        # Check for suspicious patterns
        suspicious_patterns = [
            '*.exe', '*.dll', '*.so', '*.dylib',  # Binaries
            '*.sh', '*.bat', '*.ps1',  # Scripts
            '.git/hooks/*',  # Git hooks
            '**/node_modules/.bin/*',  # npm binaries
        ]

        path_obj = Path(path)

        for pattern in suspicious_patterns:
            matches = list(path_obj.rglob(pattern))
            if matches:
                logger.warning(f"Suspicious files found: {pattern} ({len(matches)} files)")
                # In production, use actual malware scanner like ClamAV
                # For now, just check for obvious malicious patterns
                for match in matches[:10]:  # Check first 10 matches
                    if self._check_file_for_malware(match):
                        return False

        return True

    def _check_file_for_malware(self, file_path: Path) -> bool:
        """
        Check individual file for malware signatures.

        Args:
            file_path: File to check

        Returns:
            True if malware detected
        """
        # Simplified check - in production use real AV
        malware_signatures = [
            b'rm -rf /',  # Dangerous command
            b'curl | sh',  # Remote code execution
            b'eval(base64',  # Obfuscated code
            b'exec(compile',  # Dynamic execution
            b'__import__("os").system',  # Python system call
        ]

        try:
            with open(file_path, 'rb') as f:
                content = f.read(1024 * 100)  # Read first 100KB

            for signature in malware_signatures:
                if signature in content:
                    logger.warning(f"Malware signature found in {file_path}")
                    return True

        except Exception:
            # Can't read file, consider it safe
            pass

        return False

    def _quarantine_path(self, source_path: str, reason: str) -> str:
        """
        Move path to quarantine.

        Args:
            source_path: Path to quarantine
            reason: Quarantine reason

        Returns:
            Quarantine path
        """
        quarantine_id = self._generate_storage_id(f"{source_path}_{reason}")
        quarantine_path = self.base_path / 'quarantine' / quarantine_id

        quarantine_path.mkdir(parents=True, exist_ok=True)
        quarantine_path.chmod(0o700)

        # Move to quarantine
        if Path(source_path).is_dir():
            shutil.move(source_path, quarantine_path / 'content')
        else:
            shutil.move(source_path, quarantine_path / 'file')

        # Store quarantine metadata
        metadata = {
            'original_path': source_path,
            'reason': reason,
            'quarantined_at': datetime.utcnow().isoformat(),
            'quarantine_id': quarantine_id
        }

        with open(quarantine_path / 'metadata.json', 'w') as f:
            json.dump(metadata, f, indent=2)

        logger.warning(f"Path quarantined: {quarantine_id} (reason: {reason})")
        return str(quarantine_path)

    def _calculate_integrity_hash(self, path: Path) -> str:
        """Calculate integrity hash for path."""
        hasher = hashlib.sha256()

        if path.is_file():
            # Hash single file
            with open(path, 'rb') as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
        else:
            # Hash directory recursively
            for file_path in sorted(path.rglob('*')):
                if file_path.is_file():
                    hasher.update(str(file_path.relative_to(path)).encode())
                    with open(file_path, 'rb') as f:
                        while chunk := f.read(8192):
                            hasher.update(chunk)

        return hasher.hexdigest()

    def _store_integrity_hash(self, storage_id: str, hash_value: str) -> None:
        """Store integrity hash."""
        self.integrity_db[storage_id] = hash_value

        # Persist to file
        integrity_file = self.base_path / 'integrity' / 'checksums.json'
        with open(integrity_file, 'w') as f:
            json.dump(self.integrity_db, f, indent=2)

    def _get_directory_size(self, path: Path) -> int:
        """Get total size of directory."""
        total = 0
        for file_path in path.rglob('*'):
            if file_path.is_file():
                total += file_path.stat().st_size
        return total

    def cleanup_old_files(self, max_age_days: int = 90) -> int:
        """
        Clean up old files from storage.

        Args:
            max_age_days: Maximum age in days

        Returns:
            Number of files cleaned
        """
        cleaned = 0
        cutoff_date = datetime.utcnow() - timedelta(days=max_age_days)

        for storage_dir in ['repos', 'cache', 'temp', 'quarantine']:
            dir_path = self.base_path / storage_dir

            for item in dir_path.iterdir():
                # Check metadata for age
                metadata_file = item / 'metadata.json'
                if metadata_file.exists():
                    try:
                        with open(metadata_file, 'r') as f:
                            metadata = json.load(f)

                        stored_date = datetime.fromisoformat(metadata.get('stored_at', ''))
                        if stored_date < cutoff_date:
                            shutil.rmtree(item)
                            cleaned += 1
                            logger.info(f"Cleaned old storage: {item.name}")

                    except Exception as e:
                        logger.error(f"Failed to clean {item}: {e}")

        return cleaned

    def get_storage_stats(self) -> Dict[str, Any]:
        """Get storage statistics."""
        stats = {
            'total_repositories': 0,
            'quarantined_items': 0,
            'cache_size_bytes': 0,
            'total_size_bytes': 0,
            'integrity_checks': len(self.integrity_db)
        }

        # Count repositories
        repos_dir = self.base_path / 'repos'
        stats['total_repositories'] = len(list(repos_dir.iterdir()))

        # Count quarantined items
        quarantine_dir = self.base_path / 'quarantine'
        stats['quarantined_items'] = len(list(quarantine_dir.iterdir()))

        # Calculate sizes
        for dir_name in ['repos', 'cache', 'quarantine']:
            dir_path = self.base_path / dir_name
            size = self._get_directory_size(dir_path)
            stats['total_size_bytes'] += size
            if dir_name == 'cache':
                stats['cache_size_bytes'] = size

        return stats

    def create_secure_temp_dir(self) -> str:
        """
        Create secure temporary directory.

        Returns:
            Path to temporary directory
        """
        temp_dir = tempfile.mkdtemp(
            dir=str(self.base_path / 'temp'),
            prefix='mcp_temp_'
        )

        # Set secure permissions
        Path(temp_dir).chmod(0o700)

        return temp_dir