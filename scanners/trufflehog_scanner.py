#!/usr/bin/env python3
"""
TruffleHog Secret Scanner Integration
======================================
Integrates TruffleHog secret detection into the MCP Risk Scoring component.
Scans repositories for exposed secrets, API keys, and credentials.

TruffleHog detects:
- API keys (AWS, Azure, GCP, GitHub, etc.)
- Database credentials
- Private keys and certificates
- OAuth tokens
- Webhook URLs
- Custom regex patterns

Author: MCP Security Scanner
Version: 2.0
"""

import asyncio
import json
import logging
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
)
logger = logging.getLogger(__name__)


# ================================================================================
# DATA MODELS
# ================================================================================

class SecretSeverity(Enum):
    """
    Severity levels for detected secrets.

    Mapped to FICO score deductions:
    - CRITICAL: Active, verified secrets (e.g., valid AWS keys)
    - HIGH: Unverified but likely valid secrets
    - MEDIUM: Potentially sensitive but uncertain
    - LOW: Weak patterns or likely false positives
    """
    CRITICAL = "critical"  # Verified, active credentials
    HIGH = "high"          # High-confidence secrets
    MEDIUM = "medium"      # Potential secrets
    LOW = "low"            # Low-confidence matches


@dataclass
class SecretFinding:
    """
    Container for a detected secret from TruffleHog.

    Attributes:
        detector_name: Type of secret detected (e.g., "AWS", "GitHub", "Generic")
        severity: Severity level based on verification and type
        file_path: Path to file containing the secret
        line_number: Line where secret was found
        commit_hash: Git commit containing the secret (if applicable)
        secret_type: Specific type of secret (e.g., "aws_access_key_id")
        redacted_secret: Partially redacted version for safe display
        verified: Whether the secret was verified as active
        metadata: Additional context from TruffleHog
        first_found: When the secret was first introduced
        last_found: Most recent occurrence
    """
    detector_name: str
    severity: SecretSeverity
    file_path: str
    line_number: int
    commit_hash: Optional[str] = None
    secret_type: Optional[str] = None
    redacted_secret: Optional[str] = None
    verified: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    first_found: Optional[str] = None
    last_found: Optional[str] = None

    def get_fico_deduction(self) -> int:
        """
        Calculate FICO score deduction for this secret finding.

        Secrets are treated as critical security issues:
        - Verified secrets: -200 points (worse than critical)
        - High-confidence: -150 points
        - Medium-confidence: -80 points
        - Low-confidence: -30 points
        """
        if self.verified:
            return 200  # Verified secrets are extremely critical

        deduction_map = {
            SecretSeverity.CRITICAL: 180,
            SecretSeverity.HIGH: 150,
            SecretSeverity.MEDIUM: 80,
            SecretSeverity.LOW: 30
        }
        return deduction_map.get(self.severity, 30)

    def get_display_string(self) -> str:
        """Get safe display string for reporting."""
        return f"[{self.detector_name}] {self.secret_type or 'Secret'} in {self.file_path}:{self.line_number}"


@dataclass
class SecretScanResult:
    """
    Container for complete TruffleHog scan results.

    Attributes:
        repository: Repository identifier
        total_secrets: Total number of secrets found
        verified_count: Number of verified/active secrets
        findings: List of all secret findings
        scan_duration: Time taken to scan in seconds
        scanned_at: Timestamp of scan
        metadata: Additional scan metadata
    """
    repository: str
    total_secrets: int
    verified_count: int
    findings: List[SecretFinding]
    scan_duration: float
    scanned_at: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_total_deduction(self) -> int:
        """Calculate total FICO score deduction for all secrets."""
        return sum(finding.get_fico_deduction() for finding in self.findings)

    def get_severity_counts(self) -> Dict[str, int]:
        """Get count of findings by severity."""
        counts = {s.value: 0 for s in SecretSeverity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts


# ================================================================================
# TRUFFLEHOG SCANNER
# ================================================================================

class TruffleHogScanner:
    """
    TruffleHog integration for secret detection in MCP repositories.

    Features:
    - Git history scanning (all commits)
    - Filesystem scanning (current state)
    - Verification of detected secrets
    - Custom regex patterns for MCP-specific secrets
    - Entropy-based detection
    - Multiple detector support (700+ detectors)
    - Smart exclusion of non-relevant directories
    """

    # Directories to exclude from scanning (reduce false positives)
    EXCLUDED_PATHS = [
        # Version control
        r"\.git/",
        r"\.svn/",
        r"\.hg/",

        # Dependencies and packages
        r"node_modules/",
        r"vendor/",
        r"venv/",
        r"\.venv/",
        r"env/",
        r"\.env/",
        r"virtualenv/",
        r"__pycache__/",
        r"\.pytest_cache/",
        r"\.tox/",
        r"site-packages/",
        r"dist-packages/",

        # Build artifacts and compiled files
        r"build/",
        r"dist/",
        r"target/",
        r"out/",
        r"bin/",
        r"obj/",
        r"\.next/",
        r"\.nuxt/",
        r"\.output/",
        r"_build/",
        r"cmake-build-.*/",

        # IDE and editor files
        r"\.idea/",
        r"\.vscode/",
        r"\.vs/",
        r"\.sublime-",
        r"\.atom/",
        r"\.eclipse/",
        r"\*.swp",
        r"\*~",
        r"\.DS_Store",

        # Test coverage and reports
        r"coverage/",
        r"\.coverage",
        r"htmlcov/",
        r"\.nyc_output/",
        r"test-results/",
        r"junit\.xml",

        # Documentation builds
        r"docs/_build/",
        r"docs/\.build/",
        r"site/",
        r"public/",
        r"_site/",

        # Package manager files with hashes
        r"package-lock\.json",
        r"yarn\.lock",
        r"poetry\.lock",
        r"Pipfile\.lock",
        r"composer\.lock",
        r"Gemfile\.lock",
        r"go\.sum",
        r"cargo\.lock",

        # Binary and media files
        r"\*\.pyc",
        r"\*\.pyo",
        r"\*\.pyd",
        r"\*\.so",
        r"\*\.dll",
        r"\*\.dylib",
        r"\*\.exe",
        r"\*\.o",
        r"\*\.a",
        r"\*\.lib",
        r"\*\.png",
        r"\*\.jpg",
        r"\*\.jpeg",
        r"\*\.gif",
        r"\*\.ico",
        r"\*\.svg",
        r"\*\.pdf",
        r"\*\.zip",
        r"\*\.tar",
        r"\*\.gz",
        r"\*\.rar",
        r"\*\.7z",

        # Minified files (often cause false positives)
        r"\*\.min\.js",
        r"\*\.min\.css",
        r"\*-min\.js",
        r"\*-min\.css",

        # Cache directories
        r"\.cache/",
        r"\.npm/",
        r"\.yarn/",
        r"\.pnpm-store/",
        r"\.cargo/",
        r"\.gradle/",
        r"\.m2/",

        # Log files
        r"\*\.log",
        r"logs/",

        # Temporary files
        r"tmp/",
        r"temp/",
        r"\.tmp/",
        r"\.temp/",

        # === ADDITIONAL EXCLUSIONS FOR MCP REPOS ===

        # Database files and dumps
        r"\*\.db",
        r"\*\.sqlite",
        r"\*\.sqlite3",
        r"\*\.dump",
        r"\*\.sql\.gz",
        r"\*\.bak",
        r"\*\.backup",

        # Docker and container artifacts
        r"\.dockerignore",
        r"docker-compose\.override\.yml",
        r"\.docker/",
        r"containers/",

        # Terraform and infrastructure
        r"\.terraform/",
        r"\*\.tfstate",
        r"\*\.tfstate\.backup",
        r"\.terraformrc",
        r"terraform\.tfvars",

        # Kubernetes
        r"\.kube/",
        r"kubeconfig",
        r"\.helm/",
        r"charts/",

        # Cloud provider files
        r"\.aws/",
        r"\.azure/",
        r"\.gcloud/",
        r"\.gcp/",

        # CI/CD artifacts
        r"\.github/workflows/",  # May contain secrets but in YAML format
        r"\.gitlab-ci-cache/",
        r"\.circleci/",
        r"\.travis/",
        r"\.jenkins/",
        r"\.buildkite/",

        # Python specific
        r"\.pypirc",
        r"pip-wheel-metadata/",
        r"\.Python",
        r"\*\.egg-info/",
        r"\*\.egg",
        r"\.eggs/",
        r"develop-eggs/",
        r"wheels/",
        r"share/python-wheels/",

        # JavaScript/Node specific
        r"\.npm-debug\.log",
        r"npm-debug\.log\*",
        r"yarn-debug\.log\*",
        r"yarn-error\.log\*",
        r"lerna-debug\.log\*",
        r"\.pnpm-debug\.log\*",
        r"bower_components/",
        r"jspm_packages/",
        r"web_modules/",
        r"\.cache-loader/",
        r"\.parcel-cache/",
        r"\.next/",
        r"\.nuxt/",
        r"\.gatsby/",
        r"\.vuepress/dist/",
        r"\.serverless/",
        r"\.fusebox/",
        r"\.dynamodb/",
        r"\.tern-port",
        r"\.yarn-integrity",

        # Ruby specific
        r"\.bundle/",
        r"\.gem/",
        r"\.rbenv/",
        r"\.rvm/",

        # Go specific
        r"\.go/",
        r"go\.work\.sum",

        # Rust specific
        r"target/",
        r"Cargo\.lock",
        r"\*\.rs\.bk",

        # Java/Kotlin specific
        r"\.mvn/",
        r"\.gradle/",
        r"gradle/",
        r"gradlew",
        r"gradlew\.bat",
        r"\*\.jar",
        r"\*\.war",
        r"\*\.ear",
        r"\*\.class",
        r"hs_err_pid\*",

        # .NET specific
        r"\.dotnet/",
        r"\.nuget/",
        r"packages/",
        r"\*\.nupkg",
        r"\*\.snupkg",
        r"\.vs/",
        r"bin/",
        r"obj/",

        # Mobile development
        r"\.android/",
        r"\.ios/",
        r"Pods/",
        r"\.cocoapods/",
        r"DerivedData/",
        r"\*\.xcworkspace/",
        r"\*\.xcodeproj/",
        r"\.flutter/",
        r"\.dart_tool/",

        # ML/Data Science
        r"\.ipynb_checkpoints/",
        r"\*\.h5",
        r"\*\.hdf5",
        r"\*\.pkl",
        r"\*\.pickle",
        r"\*\.model",
        r"\*\.ckpt",
        r"\*\.pth",
        r"mlruns/",
        r"\.mlflow/",
        r"tensorboard/",
        r"wandb/",

        # Documentation generation
        r"_book/",
        r"\.docusaurus/",
        r"\.sphinx/",
        r"doxygen/",
        r"typedoc/",

        # OS specific
        r"Thumbs\.db",
        r"ehthumbs\.db",
        r"Desktop\.ini",
        r"\$RECYCLE\.BIN/",
        r"\.Spotlight-V100",
        r"\.Trashes",
        r"\.fseventsd",
        r"\.VolumeIcon\.icns",
        r"\.com\.apple\.timemachine\*",
        r"\.AppleDouble",
        r"\.LSOverride",
        r"\.apdisk",

        # Backup files
        r"\*~",
        r"\*\.orig",
        r"\*\.rej",
        r"\*\.bak",
        r"\*\.old",
        r"\*\.save",
        r"\#\*\#",
        r"\.#\*",

        # Lock files and checksums
        r"checksums\.txt",
        r"SHA256SUMS",
        r"MD5SUMS",
        r"\*\.sha1",
        r"\*\.sha256",
        r"\*\.md5",

        # Large data files
        r"\*\.csv",
        r"\*\.tsv",
        r"\*\.parquet",
        r"\*\.feather",
        r"\*\.arrow",
        r"data/",
        r"datasets/",

        # Compressed archives (may contain other repos)
        r"\*\.tar\.gz",
        r"\*\.tar\.bz2",
        r"\*\.tar\.xz",
        r"\*\.tgz",
        r"\*\.tbz2",
        r"\*\.txz",

        # MCP-specific patterns to ignore
        r"mcp-servers/",  # If it's a directory of multiple servers
        r"examples/data/",  # Example data files
        r"test-data/",
        r"mock-data/",
        r"sample-output/",
    ]

    # File patterns that should be scanned (even if they match exclusions)
    INCLUDE_PATTERNS = [
        # Environment and config files
        r"\.env$",  # .env files should be scanned
        r"\.env\.",  # .env.* files
        r"config.*\.(js|json|yaml|yml|toml|ini|conf|cfg)$",  # Config files
        r"settings.*\.(py|js|json|yaml|yml)$",  # Settings files

        # Secret/credential files
        r"credentials\.(json|yml|yaml|ini|conf)$",
        r"secrets\.(json|yml|yaml|ini|conf)$",
        r"auth\.(json|yml|yaml|ini|conf)$",
        r"api[_-]?keys?\.(json|yml|yaml|ini|conf)$",

        # Cloud provider config
        r"aws[_-]?config",
        r"gcp[_-]?config",
        r"azure[_-]?config",

        # Database config
        r"database\.(yml|yaml|json|conf)$",
        r"db[_-]?config\.(yml|yaml|json|conf)$",

        # Docker/K8s files that might have secrets
        r"docker-compose\.(yml|yaml)$",
        r"values\.(yaml|yml)$",  # Helm values

        # MCP-specific config files
        r"mcp\.json$",
        r"mcp[_-]?config\.(json|yml|yaml|toml)$",
        r"mcp[_-]?server\.(json|yml|yaml|toml)$",

        # Connection strings and URLs
        r"connections?\.(json|yml|yaml|ini|conf)$",
        r"endpoints?\.(json|yml|yaml|ini|conf)$",
    ]

    # Known secret types and their severity mappings
    SECRET_SEVERITY_MAP = {
        # Critical - verified or highly sensitive
        "aws": SecretSeverity.CRITICAL,
        "gcp": SecretSeverity.CRITICAL,
        "azure": SecretSeverity.CRITICAL,
        "github": SecretSeverity.CRITICAL,
        "gitlab": SecretSeverity.CRITICAL,
        "slack": SecretSeverity.HIGH,
        "stripe": SecretSeverity.CRITICAL,
        "sendgrid": SecretSeverity.HIGH,
        "mailgun": SecretSeverity.HIGH,
        "twilio": SecretSeverity.HIGH,
        "npm": SecretSeverity.HIGH,
        "pypi": SecretSeverity.HIGH,

        # Medium - potentially sensitive
        "generic": SecretSeverity.MEDIUM,
        "jwt": SecretSeverity.MEDIUM,
        "oauth": SecretSeverity.MEDIUM,
        "webhook": SecretSeverity.MEDIUM,

        # Low - likely false positives
        "generic_api_key": SecretSeverity.LOW
    }

    def __init__(self,
                 verify_secrets: bool = False,  # Default False for public repos
                 scan_history: bool = True,
                 custom_patterns: Optional[List[Dict]] = None,
                 exclude_paths: Optional[List[str]] = None,
                 include_paths: Optional[List[str]] = None):
        """
        Initialize TruffleHog scanner.

        Args:
            verify_secrets: Whether to verify detected secrets are active
                           (Default False for ethical scanning of public repos)
            scan_history: Whether to scan git history or just current state
            custom_patterns: Additional regex patterns for MCP-specific secrets
            exclude_paths: Additional paths to exclude from scanning
            include_paths: Additional paths to forcibly include
        """
        self.verify_secrets = verify_secrets
        self.scan_history = scan_history
        self.custom_patterns = custom_patterns or []

        # Combine default and custom exclusions
        self.excluded_paths = self.EXCLUDED_PATHS.copy()
        if exclude_paths:
            self.excluded_paths.extend(exclude_paths)

        # Include patterns override exclusions
        self.include_patterns = self.INCLUDE_PATTERNS.copy()
        if include_paths:
            self.include_patterns.extend(include_paths)

        # Verify TruffleHog installation
        self._verify_trufflehog()

        logger.info(f"Initialized TruffleHog Scanner")
        logger.info(f"Verification: {verify_secrets}, History scan: {scan_history}")
        logger.info(f"Excluded paths: {len(self.excluded_paths)} patterns")
        logger.info(f"Forced includes: {len(self.include_patterns)} patterns")

    def _verify_trufflehog(self):
        """Verify TruffleHog is installed and accessible."""
        try:
            result = subprocess.run(
                ["trufflehog", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                raise RuntimeError("TruffleHog is not properly installed")
            logger.info(f"TruffleHog version: {result.stdout.strip()}")
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            raise RuntimeError(
                f"TruffleHog is not available: {e}\n"
                "Install with: pip install truffleHog3 or brew install trufflehog"
            )

    def _get_exclusion_patterns_file(self) -> str:
        """
        Create a temporary file with exclusion patterns for TruffleHog.

        Returns:
            Path to the exclusion patterns file
        """
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for pattern in self.excluded_paths:
                f.write(f"{pattern}\n")
            return f.name

    def _should_scan_file(self, file_path: str) -> bool:
        """
        Check if a file should be scanned based on inclusion/exclusion rules.

        Args:
            file_path: Path to check

        Returns:
            True if file should be scanned, False otherwise
        """
        import re

        # Check if file matches any include pattern (overrides exclusions)
        for pattern in self.include_patterns:
            if re.search(pattern, file_path):
                return True

        # Check if file matches any exclude pattern
        for pattern in self.excluded_paths:
            if re.search(pattern, file_path):
                return False

        return True  # Default to scanning

    async def scan_repository(self, repo_path: str) -> SecretScanResult:
        """
        Scan a repository for secrets using TruffleHog.

        Performs comprehensive secret detection including:
        1. Git history scanning (if enabled)
        2. Current filesystem scanning
        3. Secret verification (if enabled)
        4. Custom pattern matching

        Args:
            repo_path: Path to the repository to scan

        Returns:
            SecretScanResult with all detected secrets
        """
        repo_path = Path(repo_path).resolve()
        if not repo_path.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")

        logger.info(f"Starting TruffleHog scan for: {repo_path.name}")
        start_time = datetime.now()

        # Determine scan mode
        if self.scan_history and (repo_path / ".git").exists():
            findings = await self._scan_git_history(repo_path)
        else:
            findings = await self._scan_filesystem(repo_path)

        # Apply custom patterns if provided
        if self.custom_patterns:
            custom_findings = await self._scan_custom_patterns(repo_path)
            findings.extend(custom_findings)

        # Calculate scan duration
        duration = (datetime.now() - start_time).total_seconds()

        # Count verified secrets
        verified_count = sum(1 for f in findings if f.verified)

        logger.info(f"TruffleHog found {len(findings)} secrets ({verified_count} verified)")

        return SecretScanResult(
            repository=repo_path.name,
            total_secrets=len(findings),
            verified_count=verified_count,
            findings=findings,
            scan_duration=duration,
            scanned_at=datetime.now(timezone.utc).isoformat(),
            metadata={
                "scan_mode": "git" if self.scan_history else "filesystem",
                "verification_enabled": self.verify_secrets,
                "custom_patterns": len(self.custom_patterns)
            }
        )

    async def _scan_git_history(self, repo_path: Path) -> List[SecretFinding]:
        """
        Scan entire git history for secrets.

        Uses TruffleHog's git mode to scan all commits, branches, and tags.
        """
        logger.info("Scanning git history for secrets")

        try:
            # Build TruffleHog command with exclusions
            cmd = [
                "trufflehog",
                "git",
                f"file://{repo_path}",
                "--json",
                "--no-update",
                # Exclude non-relevant paths even in git history
                "--exclude-paths", self._get_exclusion_patterns_file()
            ]

            if self.verify_secrets:
                cmd.append("--verify")

            # Run TruffleHog
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                cwd=repo_path
            )

            # Parse results
            findings = []
            for line in result.stdout.splitlines():
                if line.strip():
                    try:
                        finding = self._parse_trufflehog_finding(json.loads(line))
                        if finding:
                            findings.append(finding)
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to parse TruffleHog output: {line[:100]}")

            return findings

        except subprocess.TimeoutExpired:
            logger.error("TruffleHog scan timed out")
            return []
        except Exception as e:
            logger.error(f"TruffleHog git scan failed: {e}")
            return []

    async def _scan_filesystem(self, repo_path: Path) -> List[SecretFinding]:
        """
        Scan current filesystem state for secrets.

        Uses TruffleHog's filesystem mode for repositories without git history.
        Excludes non-relevant directories to reduce false positives.
        """
        logger.info("Scanning filesystem for secrets")

        try:
            # Build TruffleHog command with exclusions
            cmd = [
                "trufflehog",
                "filesystem",
                str(repo_path),
                "--json",
                "--no-update",
                # Exclude directories that typically contain hashes/artifacts
                "--exclude-paths", self._get_exclusion_patterns_file()
            ]

            if self.verify_secrets:
                cmd.append("--verify")

            # Run TruffleHog
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=repo_path
            )

            # Parse results
            findings = []
            for line in result.stdout.splitlines():
                if line.strip():
                    try:
                        finding = self._parse_trufflehog_finding(json.loads(line))
                        if finding:
                            findings.append(finding)
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to parse TruffleHog output: {line[:100]}")

            return findings

        except subprocess.TimeoutExpired:
            logger.error("TruffleHog scan timed out")
            return []
        except Exception as e:
            logger.error(f"TruffleHog filesystem scan failed: {e}")
            return []

    async def _scan_custom_patterns(self, repo_path: Path) -> List[SecretFinding]:
        """
        Scan for MCP-specific secrets using custom regex patterns.

        Custom patterns for MCP might include:
        - MCP API keys
        - Model provider tokens
        - Custom authentication tokens
        """
        logger.info(f"Scanning with {len(self.custom_patterns)} custom patterns")
        findings = []

        # Would implement custom regex scanning here
        # This is a placeholder for the custom pattern logic

        return findings

    def _is_likely_false_positive(self, finding: Dict) -> bool:
        """
        Check if a finding is likely a false positive.

        Filters out:
        - Example/documentation secrets
        - Test fixtures
        - Hash values that look like secrets
        - Common placeholders

        Args:
            finding: Raw TruffleHog finding

        Returns:
            True if likely false positive
        """
        raw_secret = finding.get("Raw", "").lower()
        file_path = ""

        # Extract file path from metadata
        source_data = finding.get("SourceMetadata", {}).get("Data", {})
        if "Git" in source_data:
            file_path = source_data["Git"].get("file", "").lower()
        elif "Filesystem" in source_data:
            file_path = source_data["Filesystem"].get("file", "").lower()

        # Check for test/example files
        test_indicators = [
            "test", "tests", "testing", "spec", "specs",
            "example", "examples", "sample", "samples",
            "demo", "demos", "tutorial", "documentation",
            "mock", "mocks", "fixture", "fixtures",
            ".test.", ".spec.", "_test.", "_spec."
        ]

        for indicator in test_indicators:
            if indicator in file_path:
                logger.debug(f"Likely test/example file: {file_path}")
                return True

        # Check for common placeholder patterns
        placeholder_patterns = [
            "xxxxxxx", "yyyyyyy", "zzzzzzz",
            "1234567", "abcdefg", "0000000",
            "example", "sample", "dummy", "fake",
            "placeholder", "your-", "my-", "todo",
            "replace", "changeme", "default",
            "<your", "<insert", "<add", "<put",
            "{{", "}}", "${", "<%", "%>",  # Template variables
        ]

        for pattern in placeholder_patterns:
            if pattern in raw_secret:
                logger.debug(f"Likely placeholder: {raw_secret[:20]}...")
                return True

        # Check if it's a hash value (40 hex chars = SHA1, 64 = SHA256)
        import re
        if re.match(r'^[a-f0-9]{40}$', raw_secret) or re.match(r'^[a-f0-9]{64}$', raw_secret):
            # Could be a git commit hash or file hash, not a secret
            if "commit" not in finding.get("DetectorName", "").lower():
                logger.debug(f"Likely hash value: {raw_secret[:20]}...")
                return True

        # Check for localhost/development URLs
        dev_indicators = ["localhost", "127.0.0.1", "0.0.0.0", "host.docker.internal"]
        for indicator in dev_indicators:
            if indicator in raw_secret:
                logger.debug(f"Likely development URL: {raw_secret[:30]}...")
                return True

        return False

    def _parse_trufflehog_finding(self, result: Dict) -> Optional[SecretFinding]:
        """
        Parse a TruffleHog JSON finding into SecretFinding object.

        TruffleHog output format:
        {
            "DetectorType": "AWS",
            "DetectorName": "AWS",
            "Verified": true,
            "Raw": "AKIA...",
            "Redacted": "AKIA************",
            "SourceMetadata": {
                "Data": {
                    "Git": {
                        "commit": "abc123",
                        "file": "config.py",
                        "line": 42
                    }
                }
            }
        }
        """
        # Filter out likely false positives
        if self._is_likely_false_positive(result):
            return None

        try:
            # Extract detector info
            detector_name = result.get("DetectorName", "Unknown")
            detector_type = result.get("DetectorType", "").lower()
            verified = result.get("Verified", False)

            # Determine severity
            severity = self._determine_severity(detector_type, verified)

            # Extract location info
            source_data = result.get("SourceMetadata", {}).get("Data", {})

            # Handle git source
            if "Git" in source_data:
                git_data = source_data["Git"]
                file_path = git_data.get("file", "unknown")
                line_number = git_data.get("line", 0)
                commit_hash = git_data.get("commit", "")
            # Handle filesystem source
            elif "Filesystem" in source_data:
                fs_data = source_data["Filesystem"]
                file_path = fs_data.get("file", "unknown")
                line_number = fs_data.get("line", 0)
                commit_hash = None
            else:
                file_path = "unknown"
                line_number = 0
                commit_hash = None

            return SecretFinding(
                detector_name=detector_name,
                severity=severity,
                file_path=file_path,
                line_number=line_number,
                commit_hash=commit_hash,
                secret_type=detector_type,
                redacted_secret=result.get("Redacted"),
                verified=verified,
                metadata={
                    "raw_length": len(result.get("Raw", "")),
                    "decoder": result.get("DecoderName"),
                    "extra": result.get("Extra", {})
                }
            )

        except Exception as e:
            logger.warning(f"Failed to parse TruffleHog finding: {e}")
            return None

    def _determine_severity(self, detector_type: str, verified: bool) -> SecretSeverity:
        """
        Determine severity based on secret type and verification status.

        Args:
            detector_type: Type of detector that found the secret
            verified: Whether the secret was verified as active

        Returns:
            Appropriate SecretSeverity level
        """
        # Verified secrets are always critical
        if verified:
            return SecretSeverity.CRITICAL

        # Check our severity map
        for key, severity in self.SECRET_SEVERITY_MAP.items():
            if key in detector_type.lower():
                return severity

        # Default to medium for unknown types
        return SecretSeverity.MEDIUM

    def generate_summary(self, result: SecretScanResult) -> str:
        """
        Generate a human-readable summary of scan results.

        Args:
            result: SecretScanResult to summarize

        Returns:
            Formatted summary string
        """
        summary = []
        summary.append(f"TruffleHog Secret Scan Summary")
        summary.append("=" * 50)
        summary.append(f"Repository: {result.repository}")
        summary.append(f"Total Secrets Found: {result.total_secrets}")
        summary.append(f"Verified Active Secrets: {result.verified_count}")
        summary.append(f"Scan Duration: {result.scan_duration:.2f} seconds")

        # Severity breakdown
        severity_counts = result.get_severity_counts()
        summary.append("\nSeverity Breakdown:")
        for severity, count in severity_counts.items():
            if count > 0:
                summary.append(f"  {severity.upper()}: {count}")

        # FICO impact
        total_deduction = result.get_total_deduction()
        summary.append(f"\nFICO Score Impact: -{total_deduction} points")

        # Top findings
        if result.findings:
            summary.append("\nTop Secret Findings:")
            for finding in result.findings[:5]:
                status = "✓ VERIFIED" if finding.verified else ""
                summary.append(f"  [{finding.severity.value.upper()}] {finding.get_display_string()} {status}")

        return "\n".join(summary)


# ================================================================================
# INTEGRATION WITH MCP SECURITY SCANNER
# ================================================================================

class CombinedRiskScanner:
    """
    Combined risk scanner that integrates Semgrep and TruffleHog results.

    Provides unified risk scoring by combining:
    - Static code analysis (Semgrep)
    - Secret detection (TruffleHog)

    The combined score reflects both code vulnerabilities and exposed secrets.
    """

    def __init__(self,
                 semgrep_scanner=None,
                 trufflehog_scanner: Optional[TruffleHogScanner] = None):
        """
        Initialize combined scanner.

        Args:
            semgrep_scanner: Semgrep scanner instance
            trufflehog_scanner: TruffleHog scanner instance
        """
        self.semgrep_scanner = semgrep_scanner
        self.trufflehog_scanner = trufflehog_scanner or TruffleHogScanner()

    async def scan_repository(self, repo_path: str) -> Dict[str, Any]:
        """
        Perform combined security scan with both tools.

        Args:
            repo_path: Path to repository

        Returns:
            Combined results with unified FICO score
        """
        results = {
            "repository": Path(repo_path).name,
            "scanned_at": datetime.now(timezone.utc).isoformat()
        }

        # Run Semgrep scan (if available)
        if self.semgrep_scanner:
            logger.info("Running Semgrep security scan")
            semgrep_result = await self.semgrep_scanner.scan_repository(repo_path)
            results["semgrep"] = semgrep_result

        # Run TruffleHog scan
        logger.info("Running TruffleHog secret scan")
        trufflehog_result = await self.trufflehog_scanner.scan_repository(repo_path)
        results["trufflehog"] = trufflehog_result

        # Calculate combined risk score
        results["combined_score"] = self._calculate_combined_score(
            semgrep_result if self.semgrep_scanner else None,
            trufflehog_result
        )

        return results

    def _calculate_combined_score(self,
                                  semgrep_result: Optional[Any],
                                  trufflehog_result: SecretScanResult) -> Dict[str, Any]:
        """
        Calculate combined FICO score from both scanners.

        Secrets are treated as critical security issues and heavily
        impact the final score.

        Args:
            semgrep_result: Results from Semgrep scan
            trufflehog_result: Results from TruffleHog scan

        Returns:
            Combined scoring information
        """
        base_score = 850
        total_deduction = 0

        # Add Semgrep deductions (if available)
        if semgrep_result:
            total_deduction += semgrep_result.raw_deduction

        # Add TruffleHog deductions (secrets are critical)
        secret_deduction = trufflehog_result.get_total_deduction()
        total_deduction += secret_deduction

        # Calculate final score
        final_score = max(300, base_score - total_deduction)

        # Cap at 579 if verified secrets found
        if trufflehog_result.verified_count > 0:
            final_score = min(final_score, 579)

        return {
            "fico_score": final_score,
            "total_deduction": total_deduction,
            "semgrep_deduction": semgrep_result.raw_deduction if semgrep_result else 0,
            "secret_deduction": secret_deduction,
            "has_verified_secrets": trufflehog_result.verified_count > 0,
            "total_findings": (
                (len(semgrep_result.findings) if semgrep_result else 0) +
                trufflehog_result.total_secrets
            )
        }


# ================================================================================
# MAIN ENTRY POINT
# ================================================================================

async def main():
    """
    Example usage of TruffleHog scanner.
    """
    # Initialize scanner
    scanner = TruffleHogScanner(
        verify_secrets=True,
        scan_history=True
    )

    # Example: Scan a repository
    repo_path = "/path/to/mcp/repository"

    if Path(repo_path).exists():
        try:
            # Run secret scan
            result = await scanner.scan_repository(repo_path)

            # Print summary
            print(scanner.generate_summary(result))

            # Show FICO impact
            print(f"\nTotal FICO Deduction: -{result.get_total_deduction()} points")

            # Example of combined scanning
            print("\n" + "="*50)
            print("Combined Risk Scanning Example")
            print("="*50)

            combined = CombinedRiskScanner(
                semgrep_scanner=None,  # Would pass actual scanner
                trufflehog_scanner=scanner
            )

            combined_result = await combined.scan_repository(repo_path)
            print(f"Combined FICO Score: {combined_result['combined_score']['fico_score']}")

        except Exception as e:
            logger.error(f"Scan failed: {e}")
            raise
    else:
        print(f"Repository not found: {repo_path}")
        print("Please provide a valid repository path")


if __name__ == "__main__":
    asyncio.run(main())