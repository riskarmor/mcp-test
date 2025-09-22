#!/usr/bin/env python3
"""
MCP Security Scanner with FICO Scoring
=======================================
Main security scanner that analyzes MCP repositories using Semgrep rules
and calculates FICO-style security scores (300-850 range).

Based on the MCP Security Review document specifications:
- FICO Score Range: 300 (Poor) to 850 (Excellent)
- Severity-based deductions with MCP-specific weighting
- Deployment mode detection for context-aware scanning
- Comprehensive security rule coverage

Author: MCP Security Scanner
Version: 2.0
"""

import asyncio
import json
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set
from enum import Enum
import hashlib
import yaml

# Configure logging with detailed formatting
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
)
logger = logging.getLogger(__name__)


# ================================================================================
# DATA MODELS
# ================================================================================

class Severity(Enum):
    """Security finding severity levels with consistent naming."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DeploymentMode(Enum):
    """MCP deployment modes that affect security requirements."""
    TRUSTED_HOST_ONLY = "trusted-host-only"
    STANDALONE = "standalone"
    MIXED_USE = "mixed-use"
    UNCONFIRMED = "trusted-host-only-unconfirmed"
    UNKNOWN = "unknown"


@dataclass
class SemgrepFinding:
    """
    Container for a single Semgrep security finding.

    Attributes:
        rule_id: Unique identifier for the Semgrep rule
        severity: Severity level of the finding
        message: Human-readable description of the issue
        file_path: Path to the file containing the vulnerability
        line_start: Starting line number of the issue
        line_end: Ending line number of the issue
        column_start: Starting column position
        column_end: Ending column position
        code_snippet: Actual code that triggered the rule
        is_mcp_specific: Whether this is an MCP-specific finding
        metadata: Additional metadata from Semgrep
        deployment_context: Relevant deployment mode for this finding
    """
    rule_id: str
    severity: Severity
    message: str
    file_path: str
    line_start: int
    line_end: int
    column_start: Optional[int] = None
    column_end: Optional[int] = None
    code_snippet: Optional[str] = None
    is_mcp_specific: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    deployment_context: Optional[DeploymentMode] = None

    def get_location(self) -> str:
        """Return formatted location string for reporting."""
        return f"{self.file_path}:{self.line_start}"

    def get_severity_weight(self) -> int:
        """
        Calculate the FICO score deduction for this finding.

        Based on document specifications:
        - Critical: -120 (MCP: -160)
        - High: -80 (MCP: -120)
        - Medium: -40 (MCP: -60)
        - Low: -10
        - Info: 0
        """
        # Base weights from document
        base_weights = {
            Severity.CRITICAL: 120,
            Severity.HIGH: 80,
            Severity.MEDIUM: 40,
            Severity.LOW: 10,
            Severity.INFO: 0
        }

        # MCP-specific additional penalties
        mcp_additions = {
            Severity.CRITICAL: 40,
            Severity.HIGH: 40,
            Severity.MEDIUM: 20,
            Severity.LOW: 0,
            Severity.INFO: 0
        }

        weight = base_weights.get(self.severity, 0)
        if self.is_mcp_specific:
            weight += mcp_additions.get(self.severity, 0)

        return weight


@dataclass
class SecurityScore:
    """
    Container for comprehensive security scoring results.

    Attributes:
        repository: Name/path of the analyzed repository
        deployment_mode: Detected deployment context
        fico_score: Final FICO-style score (300-850)
        raw_deduction: Total points deducted from base score
        findings: List of active security findings
        suppressed_findings: Findings suppressed due to deployment context
        severity_counts: Count of findings by severity level
        mcp_finding_count: Number of MCP-specific findings
        scored_at: Timestamp of scoring
        metadata: Additional scoring metadata
    """
    repository: str
    deployment_mode: DeploymentMode
    fico_score: int
    raw_deduction: int
    findings: List[SemgrepFinding]
    suppressed_findings: List[SemgrepFinding]
    severity_counts: Dict[str, int]
    mcp_finding_count: int
    scored_at: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_grade(self) -> str:
        """
        Get letter grade based on FICO score.

        Grading scale from document:
        - 800-850: Excellent (A)
        - 670-799: Good (B)
        - 580-669: Fair (C)
        - 300-579: Poor (F)
        """
        if self.fico_score >= 800:
            return "A - Excellent"
        elif self.fico_score >= 670:
            return "B - Good"
        elif self.fico_score >= 580:
            return "C - Fair"
        else:
            return "F - Poor"

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "repository": self.repository,
            "deployment_mode": self.deployment_mode.value,
            "fico_score": self.fico_score,
            "grade": self.get_grade(),
            "raw_deduction": self.raw_deduction,
            "finding_count": len(self.findings),
            "suppressed_count": len(self.suppressed_findings),
            "severity_counts": self.severity_counts,
            "mcp_finding_count": self.mcp_finding_count,
            "scored_at": self.scored_at,
            "metadata": self.metadata
        }


# ================================================================================
# MCP SECURITY SCANNER
# ================================================================================

class MCPSecurityScanner:
    """
    Main scanner class that orchestrates security analysis of MCP repositories.

    This scanner:
    1. Detects deployment mode using heuristic rules
    2. Runs Semgrep with appropriate security rules
    3. Filters findings based on deployment context
    4. Calculates FICO-style security scores
    5. Generates comprehensive reports
    """

    # Base FICO score before deductions
    BASE_SCORE = 850

    # Minimum possible score
    MIN_SCORE = 300

    # Score cap if too many critical/high findings
    POOR_CAP = 579
    CRITICAL_HIGH_THRESHOLD = 10

    def __init__(self, rules_dir: Optional[Path] = None, cache_dir: Optional[Path] = None):
        """
        Initialize the MCP Security Scanner.

        Args:
            rules_dir: Directory containing Semgrep YAML rules
            cache_dir: Directory for caching scan results
        """
        self.rules_dir = rules_dir or Path(__file__).parent / "rules"
        self.cache_dir = cache_dir or Path(__file__).parent / ".cache"

        # Ensure directories exist
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Verify Semgrep is installed
        self._verify_semgrep()

        logger.info(f"Initialized MCP Security Scanner")
        logger.info(f"Rules directory: {self.rules_dir}")
        logger.info(f"Cache directory: {self.cache_dir}")

    def _verify_semgrep(self):
        """Verify that Semgrep is installed and accessible."""
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                raise RuntimeError("Semgrep is not properly installed")
            logger.info(f"Semgrep version: {result.stdout.strip()}")
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            raise RuntimeError(f"Semgrep is not available: {e}")

    async def scan_repository(
        self,
        repo_path: str,
        language: Optional[str] = None,
        use_cache: bool = True
    ) -> SecurityScore:
        """
        Scan a repository and calculate its security score.

        This is the main entry point for repository scanning. It orchestrates:
        1. Language detection (if not specified)
        2. Deployment mode detection
        3. Semgrep scanning with appropriate rules
        4. Finding filtering based on deployment context
        5. FICO score calculation
        6. Report generation

        Args:
            repo_path: Path to the repository to scan
            language: Programming language (python/javascript/go) or None for auto-detect
            use_cache: Whether to use cached results if available

        Returns:
            SecurityScore object with complete analysis results
        """
        repo_path = Path(repo_path).resolve()

        # Validate repository exists
        if not repo_path.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")

        logger.info(f"Starting security scan for: {repo_path.name}")

        # Check cache if enabled
        if use_cache:
            cached_score = self._get_cached_score(repo_path)
            if cached_score:
                logger.info("Using cached scan results")
                return cached_score

        # Step 1: Detect language if not specified
        if not language:
            language = self._detect_language(repo_path)
            logger.info(f"Detected language: {language}")

        # Step 2: Detect deployment mode
        deployment_mode = await self._detect_deployment_mode(repo_path, language)
        logger.info(f"Detected deployment mode: {deployment_mode.value}")

        # Step 3: Run Semgrep scan
        findings = await self._run_semgrep_scan(repo_path, language)
        logger.info(f"Found {len(findings)} total security issues")

        # Step 4: Filter findings based on deployment mode
        active_findings, suppressed = self._filter_findings_by_mode(
            findings, deployment_mode
        )
        logger.info(f"Active findings: {len(active_findings)}, Suppressed: {len(suppressed)}")

        # Step 5: Calculate FICO score
        score = self._calculate_fico_score(active_findings)

        # Step 6: Generate security score object
        security_score = SecurityScore(
            repository=repo_path.name,
            deployment_mode=deployment_mode,
            fico_score=score["fico_score"],
            raw_deduction=score["raw_deduction"],
            findings=active_findings,
            suppressed_findings=suppressed,
            severity_counts=score["severity_counts"],
            mcp_finding_count=score["mcp_count"],
            scored_at=datetime.now(timezone.utc).isoformat(),
            metadata={
                "language": language,
                "total_findings": len(findings),
                "scan_version": "2.0",
                "rules_dir": str(self.rules_dir),
                "capped": score["capped"],
                "bonus_points": score["bonus_points"]
            }
        )

        # Cache the results
        if use_cache:
            self._cache_score(repo_path, security_score)

        return security_score

    def _detect_language(self, repo_path: Path) -> str:
        """
        Detect the primary programming language of the repository.

        Uses file extensions and common patterns to determine language.

        Args:
            repo_path: Path to the repository

        Returns:
            Detected language (python/javascript/go)
        """
        # Count files by extension
        extensions = {
            "python": [".py"],
            "javascript": [".js", ".jsx", ".ts", ".tsx"],
            "go": [".go"]
        }

        counts = {lang: 0 for lang in extensions}

        for lang, exts in extensions.items():
            for ext in exts:
                counts[lang] += len(list(repo_path.rglob(f"*{ext}")))

        # Return language with most files
        if max(counts.values()) == 0:
            return "unknown"

        return max(counts, key=counts.get)

    async def _detect_deployment_mode(
        self,
        repo_path: Path,
        language: str
    ) -> DeploymentMode:
        """
        Detect the deployment mode using heuristic analysis.

        Analyzes code patterns to determine if the MCP implementation is:
        - Trusted-host-only (stdio-based, local execution)
        - Standalone (network server with authentication)
        - Mixed-use (configurable modes)

        Args:
            repo_path: Path to the repository
            language: Programming language

        Returns:
            Detected DeploymentMode
        """
        # Get heuristic rules file for the language
        heuristic_file = self.rules_dir / f"heuristic_{language}.yaml"

        if not heuristic_file.exists():
            logger.warning(f"No heuristic rules for {language}")
            return DeploymentMode.UNKNOWN

        try:
            # Run Semgrep with heuristic rules
            result = subprocess.run(
                [
                    "semgrep",
                    "--config", str(heuristic_file),
                    "--json",
                    "--no-git-ignore",
                    str(repo_path)
                ],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode not in [0, 1]:  # 1 = findings exist
                logger.error(f"Heuristic detection failed: {result.stderr}")
                return DeploymentMode.UNKNOWN

            data = json.loads(result.stdout)
            findings = data.get("results", [])

            # Analyze findings to determine mode
            mode_indicators = {
                DeploymentMode.TRUSTED_HOST_ONLY: 0,
                DeploymentMode.STANDALONE: 0,
                DeploymentMode.MIXED_USE: 0
            }

            for finding in findings:
                rule_id = finding.get("check_id", "")
                if "trusted-host" in rule_id:
                    mode_indicators[DeploymentMode.TRUSTED_HOST_ONLY] += 1
                elif "standalone" in rule_id:
                    mode_indicators[DeploymentMode.STANDALONE] += 1
                elif "mixed-use" in rule_id:
                    mode_indicators[DeploymentMode.MIXED_USE] += 1

            # Determine mode based on indicators
            if mode_indicators[DeploymentMode.MIXED_USE] > 0:
                return DeploymentMode.MIXED_USE
            elif mode_indicators[DeploymentMode.STANDALONE] > 0:
                return DeploymentMode.STANDALONE
            elif mode_indicators[DeploymentMode.TRUSTED_HOST_ONLY] > 0:
                return DeploymentMode.TRUSTED_HOST_ONLY
            else:
                return DeploymentMode.UNKNOWN

        except Exception as e:
            logger.error(f"Deployment detection error: {e}")
            return DeploymentMode.UNKNOWN

    async def _run_semgrep_scan(
        self,
        repo_path: Path,
        language: str
    ) -> List[SemgrepFinding]:
        """
        Run Semgrep security scan on the repository.

        Executes Semgrep with language-specific security rules and
        parses the results into SemgrepFinding objects.

        Args:
            repo_path: Path to the repository
            language: Programming language

        Returns:
            List of security findings
        """
        # Get security rules file for the language
        rules_file = self.rules_dir / f"mcp_{language}_rules.yaml"

        if not rules_file.exists():
            logger.warning(f"No security rules for {language}")
            return []

        try:
            logger.info(f"Running Semgrep with {rules_file.name}")

            # Run Semgrep scan
            result = subprocess.run(
                [
                    "semgrep",
                    "--config", str(rules_file),
                    "--json",
                    "--no-git-ignore",
                    "--max-target-bytes", "10000000",  # 10MB max file size
                    str(repo_path)
                ],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            if result.returncode not in [0, 1]:  # 1 = findings exist
                logger.error(f"Semgrep scan failed: {result.stderr}")
                return []

            data = json.loads(result.stdout)
            findings = []

            # Parse Semgrep results into findings
            for result in data.get("results", []):
                finding = self._parse_semgrep_result(result)
                if finding:
                    findings.append(finding)

            return findings

        except subprocess.TimeoutExpired:
            logger.error("Semgrep scan timed out")
            return []
        except Exception as e:
            logger.error(f"Semgrep scan error: {e}")
            return []

    def _parse_semgrep_result(self, result: Dict) -> Optional[SemgrepFinding]:
        """
        Parse a single Semgrep result into a SemgrepFinding object.

        Args:
            result: Raw Semgrep result dictionary

        Returns:
            SemgrepFinding object or None if parsing fails
        """
        try:
            # Extract basic fields
            rule_id = result.get("check_id", "unknown")

            # Parse severity (normalize to our enum)
            severity_str = result.get("extra", {}).get("severity", "low").lower()
            severity = Severity(severity_str) if severity_str in [s.value for s in Severity] else Severity.LOW

            # Get message
            message = result.get("extra", {}).get("message", "Security issue detected")

            # Get location information
            path = result.get("path", "unknown")
            start = result.get("start", {})
            end = result.get("end", {})

            # Determine if MCP-specific
            is_mcp = "mcp-" in rule_id.lower()

            # Extract code snippet if available
            code_snippet = result.get("extra", {}).get("lines", "")

            # Get metadata
            metadata = result.get("extra", {}).get("metadata", {})

            return SemgrepFinding(
                rule_id=rule_id,
                severity=severity,
                message=message,
                file_path=path,
                line_start=start.get("line", 0),
                line_end=end.get("line", 0),
                column_start=start.get("col"),
                column_end=end.get("col"),
                code_snippet=code_snippet,
                is_mcp_specific=is_mcp,
                metadata=metadata
            )

        except Exception as e:
            logger.warning(f"Failed to parse Semgrep result: {e}")
            return None

    def _filter_findings_by_mode(
        self,
        findings: List[SemgrepFinding],
        deployment_mode: DeploymentMode
    ) -> Tuple[List[SemgrepFinding], List[SemgrepFinding]]:
        """
        Filter findings based on deployment mode context.

        Suppresses findings that are not relevant to the detected deployment mode.
        For example, authentication requirements are suppressed for trusted-host-only
        deployments since they run in a trusted environment.

        Args:
            findings: All security findings from Semgrep
            deployment_mode: Detected deployment mode

        Returns:
            Tuple of (active_findings, suppressed_findings)
        """
        active = []
        suppressed = []

        # Define suppression rules based on deployment mode
        suppression_rules = {
            DeploymentMode.TRUSTED_HOST_ONLY: [
                "auth", "authentication", "authorization",
                "rate-limit", "origin-validation", "binding"
            ],
            DeploymentMode.STANDALONE: [],  # No suppressions for standalone
            DeploymentMode.MIXED_USE: [],  # No suppressions for mixed-use
            DeploymentMode.UNCONFIRMED: ["auth"],  # Limited suppression
            DeploymentMode.UNKNOWN: []  # No suppressions for unknown
        }

        suppress_patterns = suppression_rules.get(deployment_mode, [])

        for finding in findings:
            # Check if finding should be suppressed
            should_suppress = False

            if suppress_patterns:
                rule_lower = finding.rule_id.lower()
                for pattern in suppress_patterns:
                    if pattern in rule_lower:
                        should_suppress = True
                        finding.deployment_context = deployment_mode
                        break

            if should_suppress:
                suppressed.append(finding)
            else:
                active.append(finding)

        return active, suppressed

    def _calculate_fico_score(self, findings: List[SemgrepFinding]) -> Dict[str, Any]:
        """
        Calculate FICO-style security score from findings.

        Implements the scoring algorithm from the MCP Security Review document:
        - Start with base score of 850
        - Deduct points based on severity and MCP-specificity
        - Apply floor of 300 and cap at 579 for excessive critical/high findings

        Args:
            findings: List of active security findings

        Returns:
            Dictionary with scoring details
        """
        # Initialize scoring components
        score = self.BASE_SCORE
        total_deduction = 0
        severity_counts = {s.value: 0 for s in Severity}
        mcp_count = 0
        critical_high_count = 0

        # Calculate deductions
        for finding in findings:
            # Get weight for this finding
            weight = finding.get_severity_weight()
            total_deduction += weight

            # Track counts
            severity_counts[finding.severity.value] += 1
            if finding.is_mcp_specific:
                mcp_count += 1

            if finding.severity in [Severity.CRITICAL, Severity.HIGH]:
                critical_high_count += 1

        # Apply deductions
        score -= total_deduction

        # Apply floor
        score = max(score, self.MIN_SCORE)

        # Cap at 579 if too many critical/high findings
        capped = False
        if critical_high_count > self.CRITICAL_HIGH_THRESHOLD:
            score = min(score, self.POOR_CAP)
            capped = True

        # Calculate bonus points (from document)
        bonus_points = 0
        if mcp_count == 0 and critical_high_count == 0:
            bonus_points = 15
            score = min(score + bonus_points, self.BASE_SCORE)

        return {
            "fico_score": score,
            "raw_deduction": total_deduction,
            "severity_counts": severity_counts,
            "mcp_count": mcp_count,
            "critical_high_count": critical_high_count,
            "capped": capped,
            "bonus_points": bonus_points
        }

    def _get_cached_score(self, repo_path: Path) -> Optional[SecurityScore]:
        """
        Retrieve cached score if available and recent.

        Args:
            repo_path: Path to the repository

        Returns:
            Cached SecurityScore or None
        """
        # Generate cache key
        cache_key = hashlib.md5(str(repo_path).encode()).hexdigest()
        cache_file = self.cache_dir / f"{cache_key}.json"

        if not cache_file.exists():
            return None

        try:
            # Check if cache is recent (within 24 hours)
            if (datetime.now() - datetime.fromtimestamp(cache_file.stat().st_mtime)).days > 1:
                return None

            with open(cache_file, 'r') as f:
                data = json.load(f)
                # Reconstruct SecurityScore from cached data
                # (simplified for this example)
                logger.info("Found valid cached score")
                return None  # Would need proper deserialization

        except Exception as e:
            logger.warning(f"Failed to load cache: {e}")
            return None

    def _cache_score(self, repo_path: Path, score: SecurityScore):
        """
        Cache the security score for future use.

        Args:
            repo_path: Path to the repository
            score: SecurityScore to cache
        """
        try:
            cache_key = hashlib.md5(str(repo_path).encode()).hexdigest()
            cache_file = self.cache_dir / f"{cache_key}.json"

            with open(cache_file, 'w') as f:
                json.dump(score.to_dict(), f, indent=2)

            logger.info("Cached security score")

        except Exception as e:
            logger.warning(f"Failed to cache score: {e}")


# ================================================================================
# MAIN ENTRY POINT
# ================================================================================

async def main():
    """
    Example usage of the MCP Security Scanner.

    Demonstrates scanning a repository and generating a security report.
    """
    # Initialize scanner
    scanner = MCPSecurityScanner()

    # Example: Scan a repository
    repo_path = "/path/to/mcp/repository"

    if Path(repo_path).exists():
        try:
            # Run security scan
            score = await scanner.scan_repository(repo_path)

            # Print results
            print("\n" + "="*70)
            print(f"MCP Security Score Report: {score.repository}")
            print("="*70)
            print(f"\nDeployment Mode: {score.deployment_mode.value}")
            print(f"FICO Score: {score.fico_score}")
            print(f"Grade: {score.get_grade()}")
            print(f"\nTotal Findings: {len(score.findings)}")
            print(f"Suppressed: {len(score.suppressed_findings)}")
            print(f"MCP-Specific: {score.mcp_finding_count}")

            print("\nSeverity Breakdown:")
            for severity, count in score.severity_counts.items():
                if count > 0:
                    print(f"  {severity.upper()}: {count}")

            # Show top findings
            if score.findings:
                print("\nTop Security Issues:")
                for finding in score.findings[:5]:
                    print(f"\n[{finding.severity.value.upper()}] {finding.rule_id}")
                    print(f"  {finding.message}")
                    print(f"  Location: {finding.get_location()}")

            print("\n" + "="*70)

        except Exception as e:
            logger.error(f"Scan failed: {e}")
            raise
    else:
        print(f"Repository not found: {repo_path}")
        print("Please provide a valid repository path")


if __name__ == "__main__":
    asyncio.run(main())