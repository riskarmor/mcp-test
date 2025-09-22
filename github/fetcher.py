"""
Secure GitHub Repository Fetcher
=================================
Safely fetches and processes public GitHub repositories.

Provides:
- Rate-limited fetching
- Shallow cloning for efficiency
- Malware scanning
- Quarantine for suspicious repos

Author: MCP Security Team
"""

import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List
import logging

# Import security modules
from ..security.validators import validate_github_url, validate_file_path
from ..security.storage import SecureStorage

logger = logging.getLogger(__name__)


class GitHubFetchError(Exception):
    """GitHub fetch exception."""
    pass


class RateLimiter:
    """Rate limiter for API calls."""

    def __init__(self, max_calls: int = 4500, period: int = 3600):
        """
        Initialize rate limiter.

        Args:
            max_calls: Maximum calls allowed
            period: Period in seconds
        """
        self.max_calls = max_calls
        self.period = period
        self.calls = []

    async def acquire(self) -> None:
        """Acquire rate limit slot."""
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self.period)

        # Remove old calls
        self.calls = [call_time for call_time in self.calls if call_time > cutoff]

        # Check if we're at limit
        if len(self.calls) >= self.max_calls:
            # Calculate wait time
            oldest_call = min(self.calls)
            wait_time = (oldest_call + timedelta(seconds=self.period) - now).total_seconds()

            if wait_time > 0:
                logger.info(f"Rate limit reached, waiting {wait_time:.1f} seconds")
                await asyncio.sleep(wait_time)

        # Record this call
        self.calls.append(now)


class SecureGitHubFetcher:
    """
    Secure GitHub repository fetcher with safety controls.

    Features:
    - Rate limiting to respect GitHub API limits
    - Shallow cloning for efficiency
    - Malware scanning before storage
    - Quarantine for suspicious repositories
    - Token management for higher rate limits
    """

    def __init__(self, github_token: Optional[str] = None,
                 storage_path: str = "/opt/mcp/storage",
                 max_repo_size_mb: int = 500,
                 enable_malware_scan: bool = True):
        """
        Initialize GitHub fetcher.

        Args:
            github_token: Optional GitHub token for higher rate limits
            storage_path: Base path for storage
            max_repo_size_mb: Maximum repository size to fetch
            enable_malware_scan: Whether to scan for malware
        """
        self.github_token = github_token or os.getenv('GITHUB_TOKEN')
        self.storage = SecureStorage(storage_path)
        self.max_repo_size = max_repo_size_mb * 1024 * 1024  # Convert to bytes
        self.enable_malware_scan = enable_malware_scan

        # Initialize rate limiter
        # With token: 5000/hour, without: 60/hour
        max_calls = 4500 if self.github_token else 50
        self.rate_limiter = RateLimiter(max_calls=max_calls)

        # Statistics
        self.stats = {
            'fetched': 0,
            'failed': 0,
            'quarantined': 0,
            'skipped': 0
        }

    async def fetch_repository(self, repo_url: str,
                              shallow: bool = True,
                              branch: Optional[str] = None) -> str:
        """
        Fetch a public GitHub repository safely.

        Args:
            repo_url: GitHub repository URL
            shallow: Whether to do shallow clone
            branch: Specific branch to fetch

        Returns:
            Path to fetched repository

        Raises:
            GitHubFetchError: If fetch fails
        """
        # Validate URL
        try:
            clean_url = validate_github_url(repo_url)
        except Exception as e:
            raise GitHubFetchError(f"Invalid GitHub URL: {e}")

        # Apply rate limiting
        await self.rate_limiter.acquire()

        # Create temporary directory for cloning
        temp_dir = self.storage.create_secure_temp_dir()

        try:
            # Clone repository
            logger.info(f"Fetching repository: {clean_url}")
            await self._clone_repository(clean_url, temp_dir, shallow, branch)

            # Check repository size
            repo_size = self._get_directory_size(Path(temp_dir))
            if repo_size > self.max_repo_size:
                raise GitHubFetchError(f"Repository too large: {repo_size / 1024 / 1024:.1f}MB")

            # Scan for malware if enabled
            if self.enable_malware_scan:
                if not await self._scan_repository(temp_dir):
                    # Quarantine suspicious repository
                    quarantine_path = self._quarantine_repository(temp_dir, clean_url, "malware_detected")
                    self.stats['quarantined'] += 1
                    raise GitHubFetchError(f"Repository quarantined: {quarantine_path}")

            # Sanitize repository
            await self._sanitize_repository(temp_dir)

            # Store in secure storage
            storage_path = self.storage.store_repository(clean_url, temp_dir, scan_first=False)

            self.stats['fetched'] += 1
            logger.info(f"Repository fetched successfully: {storage_path}")

            return storage_path

        except Exception as e:
            self.stats['failed'] += 1
            # Clean up temp directory
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise GitHubFetchError(f"Failed to fetch repository: {e}")

    async def _clone_repository(self, url: str, dest: str,
                               shallow: bool, branch: Optional[str]) -> None:
        """Clone repository using git."""
        cmd = ['git', 'clone']

        # Add authentication if token available
        if self.github_token:
            # Use token in URL (be careful not to log this!)
            url = url.replace('https://', f'https://{self.github_token}@')

        # Shallow clone for efficiency
        if shallow:
            cmd.extend(['--depth', '1'])

        # Specific branch
        if branch:
            cmd.extend(['--branch', branch])

        # Add URL and destination
        cmd.extend([url, dest])

        # Execute git clone
        try:
            # Don't log the full command (contains token)
            logger.debug(f"Cloning repository to {dest}")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'}  # Disable prompts
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=300  # 5 minute timeout
            )

            if process.returncode != 0:
                # Clean error message (remove token if present)
                error_msg = stderr.decode().replace(self.github_token, '***') if self.github_token else stderr.decode()
                raise GitHubFetchError(f"Git clone failed: {error_msg}")

        except asyncio.TimeoutError:
            raise GitHubFetchError("Repository clone timed out")

    async def _scan_repository(self, repo_path: str) -> bool:
        """
        Scan repository for malware and suspicious content.

        Args:
            repo_path: Path to repository

        Returns:
            True if safe, False if suspicious
        """
        suspicious_files = [
            '**/*.exe', '**/*.dll', '**/*.so',  # Binaries
            '**/*.zip', '**/*.rar', '**/*.7z',  # Archives
            '**/Makefile',  # Build files that could compile malware
            '**/*.bat', '**/*.ps1', '**/*.sh',  # Scripts
        ]

        repo_path_obj = Path(repo_path)
        total_suspicious = 0

        for pattern in suspicious_files:
            matches = list(repo_path_obj.glob(pattern))
            if matches:
                total_suspicious += len(matches)
                logger.warning(f"Found {len(matches)} {pattern} files")

        # If too many suspicious files, consider it risky
        if total_suspicious > 10:
            logger.warning(f"Too many suspicious files: {total_suspicious}")
            return False

        # Check for known malware patterns in common files
        common_files = ['setup.py', 'package.json', 'Makefile', 'install.sh']
        for filename in common_files:
            file_path = repo_path_obj / filename
            if file_path.exists():
                if self._check_file_patterns(file_path):
                    return False

        return True

    def _check_file_patterns(self, file_path: Path) -> bool:
        """Check file for malicious patterns."""
        malicious_patterns = [
            b'curl | sh',  # Remote code execution
            b'wget -O- | bash',  # Remote code execution
            b'rm -rf /',  # Dangerous deletion
            b':(){ :|:& };:',  # Fork bomb
            b'dd if=/dev/zero',  # Disk wiper
            b'chmod 777 /',  # Dangerous permission change
            b'base64 -d | sh',  # Obfuscated execution
        ]

        try:
            with open(file_path, 'rb') as f:
                content = f.read(100000)  # Read first 100KB

            for pattern in malicious_patterns:
                if pattern in content:
                    logger.warning(f"Malicious pattern found in {file_path}")
                    return True

        except Exception:
            pass

        return False

    async def _sanitize_repository(self, repo_path: str) -> None:
        """
        Sanitize repository by removing dangerous files.

        Args:
            repo_path: Path to repository
        """
        # Remove git hooks (could execute arbitrary code)
        hooks_dir = Path(repo_path) / '.git' / 'hooks'
        if hooks_dir.exists():
            shutil.rmtree(hooks_dir)
            logger.info("Removed git hooks")

        # Remove executable permissions from scripts
        dangerous_extensions = ['.sh', '.bat', '.ps1', '.command']
        for ext in dangerous_extensions:
            for script in Path(repo_path).rglob(f'*{ext}'):
                script.chmod(0o644)  # Remove execute permission

        # Remove symbolic links (could point outside repo)
        for item in Path(repo_path).rglob('*'):
            if item.is_symlink():
                item.unlink()
                logger.info(f"Removed symlink: {item}")

    def _quarantine_repository(self, repo_path: str, repo_url: str, reason: str) -> str:
        """Quarantine suspicious repository."""
        quarantine_id = hashlib.sha256(f"{repo_url}_{datetime.utcnow()}".encode()).hexdigest()[:12]
        quarantine_path = Path(self.storage.base_path) / 'quarantine' / quarantine_id

        quarantine_path.mkdir(parents=True, exist_ok=True)
        shutil.move(repo_path, quarantine_path / 'repo')

        # Write quarantine metadata
        metadata = {
            'url': repo_url,
            'reason': reason,
            'quarantined_at': datetime.utcnow().isoformat(),
            'id': quarantine_id
        }

        with open(quarantine_path / 'metadata.json', 'w') as f:
            json.dump(metadata, f, indent=2)

        logger.warning(f"Repository quarantined: {quarantine_id} ({reason})")
        return str(quarantine_path)

    def _get_directory_size(self, path: Path) -> int:
        """Get total size of directory."""
        total = 0
        for item in path.rglob('*'):
            if item.is_file():
                total += item.stat().st_size
        return total

    async def fetch_batch(self, repo_urls: List[str],
                         max_concurrent: int = 5) -> Dict[str, Any]:
        """
        Fetch multiple repositories concurrently.

        Args:
            repo_urls: List of repository URLs
            max_concurrent: Maximum concurrent fetches

        Returns:
            Results dictionary
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        results = {'success': [], 'failed': []}

        async def fetch_with_limit(url):
            async with semaphore:
                try:
                    path = await self.fetch_repository(url)
                    results['success'].append({'url': url, 'path': path})
                except Exception as e:
                    results['failed'].append({'url': url, 'error': str(e)})

        tasks = [fetch_with_limit(url) for url in repo_urls]
        await asyncio.gather(*tasks)

        return results

    def get_stats(self) -> Dict[str, int]:
        """Get fetcher statistics."""
        return self.stats.copy()