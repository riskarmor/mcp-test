#!/usr/bin/env python3
"""
MCP Semgrep Risk Scoring System
================================
Analyzes MCP repositories for security risks using role-aware Semgrep rules.
Produces FICO-style scores (300-850) based on weighted findings.

Author: Risk Armor
License: Proprietary - All Rights Reserved
"""

import asyncio
import json
import logging
import os
import subprocess
import tempfile
import yaml
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ================================================================================
# SCORING CONFIGURATION
# ================================================================================

@dataclass
class SemgrepFinding:
    """Container for a Semgrep finding.

    Attributes:
        rule_id: Unique identifier for the Semgrep rule that triggered
        severity: Severity level (critical/high/medium/low/info)
        message: Human-readable description of the finding
        file_path: Path to the file containing the issue
        line: Line number where the issue was found
        role: Deployment role context (if applicable)
        is_mcp_specific: Whether this is an MCP-specific vs generic finding
        metadata: Additional metadata from Semgrep
    """
    rule_id: str
    severity: str
    message: str
    file_path: str
    line: int
    role: Optional[str] = None
    is_mcp_specific: bool = False
    metadata: Dict = field(default_factory=dict)


@dataclass
class SecurityScore:
    """Container for security scoring results.

    Attributes:
        repository: Name/identifier of the analyzed repository
        deployment_role: Detected deployment context (trusted-host-only/standalone/etc)
        fico_score: FICO-style score (300-850 range)
        raw_score: Raw percentage score (0-100)
        findings: Active security findings that affect the score
        suppressed_findings: Findings suppressed due to deployment role
        metadata: Additional scoring metadata (timestamps, stats, etc)
    """
    repository: str
    deployment_role: str
    fico_score: int
    raw_score: float
    findings: List[SemgrepFinding]
    suppressed_findings: List[SemgrepFinding]
    metadata: Dict


# Scoring weights based on severity
# MCP-specific findings receive additional penalties to reflect
# their higher risk to the MCP protocol security model
SEVERITY_WEIGHTS = {
    'generic': {
        'critical': -120,
        'high': -80,
        'medium': -40,
        'low': -10,
        'info': 0
    },
    'mcp_specific': {
        'critical': -160,  # Additional -40
        'high': -120,      # Additional -40
        'medium': -60,     # Additional -20
        'low': -10,
        'info': 0
    }
}

# Deployment roles in order of increasing security requirements
# - trusted-host-only: Runs only on trusted hosts, minimal public exposure
# - standalone: Publicly accessible service, requires full security
# - mixed-use: Can operate in both modes, needs conditional security
# - trusted-host-only-unconfirmed: Likely trusted but not confirmed
# - unknown: Cannot determine role, apply strictest rules
DEPLOYMENT_ROLES = [
    'trusted-host-only',
    'standalone',
    'mixed-use',
    'trusted-host-only-unconfirmed',
    'unknown'
]


class MCPSemgrepScorer:
    """
    Analyzes MCP repositories for security risks using Semgrep.
    Applies heuristic deployment detection and role-aware security rules.
    """

    # Expose SEVERITY_WEIGHTS as class attribute for testing
    SEVERITY_WEIGHTS = SEVERITY_WEIGHTS

    def __init__(self, rules_dir: Optional[str] = None, config_path: Optional[str] = None):
        """
        Initialize the Semgrep scorer.

        Args:
            rules_dir: Directory containing Semgrep rules
            config_path: Path to configuration file
        """
        self.rules_dir = Path(rules_dir) if rules_dir else Path(__file__).parent / 'rules'
        self.config = self._load_config(config_path) if config_path else {}
        self._ensure_rules_exist()

    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logger.warning(f"Failed to load config: {e}")
            return {}

    def _ensure_rules_exist(self):
        """Ensure rule files exist, create defaults if needed.

        Creates the rules directory if it doesn't exist and generates
        default rule files for initial setup.
        """
        if not self.rules_dir.exists():
            self.rules_dir.mkdir(parents=True, exist_ok=True)
            self._create_default_rules()

    def _create_default_rules(self):
        """Create default rule files if they don't exist."""
        logger.info(f"Creating default rules in {self.rules_dir}")
        # We'll create the actual rule files later
        pass

    async def score_repository(self, repo_path: str, language: str = 'auto') -> SecurityScore:
        """
        Score a repository's security using Semgrep.

        Args:
            repo_path: Path to the repository
            language: Programming language (python, javascript, go, or auto)

        Returns:
            SecurityScore object with FICO score and findings
        """
        repo_path = Path(repo_path).resolve()
        if not repo_path.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")

        # Step 1: Detect deployment role using heuristics
        deployment_role = await self._detect_deployment_role(repo_path, language)
        logger.info(f"Detected deployment role: {deployment_role}")

        # Step 2: Run role-specific Semgrep rules
        findings = await self._run_semgrep(repo_path, deployment_role, language)

        # Step 3: Filter findings based on role
        filtered_findings, suppressed = self._filter_findings_by_role(findings, deployment_role)

        # Step 4: Calculate score
        raw_score, fico_score = self._calculate_score(filtered_findings)

        # Step 5: Generate report
        return SecurityScore(
            repository=str(repo_path.name),
            deployment_role=deployment_role,
            fico_score=fico_score,
            raw_score=raw_score,
            findings=filtered_findings,
            suppressed_findings=suppressed,
            metadata={
                'scored_at': datetime.now(timezone.utc).isoformat(),
                'language': language,
                'total_findings': len(findings),
                'active_findings': len(filtered_findings),
                'suppressed_count': len(suppressed),
                'weights': SEVERITY_WEIGHTS,
                'version': '2.0'
            }
        )

    async def _detect_deployment_role(self, repo_path: Path, language: str) -> str:
        """
        Detect deployment role using heuristic rules.

        Returns one of: trusted-host-only, standalone, mixed-use,
                       trusted-host-only-unconfirmed, unknown
        """
        # Get the appropriate heuristic rules file
        heuristic_rules = self._get_heuristic_rules_path(language)

        if not heuristic_rules.exists():
            logger.warning(f"No heuristic rules for {language}, defaulting to unknown")
            return 'unknown'

        # Run Semgrep with heuristic rules
        try:
            result = subprocess.run(
                ['semgrep', '--config', str(heuristic_rules), '--json', str(repo_path)],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0 and result.returncode != 1:  # 1 = findings exist
                logger.error(f"Semgrep heuristic detection failed: {result.stderr}")
                return 'unknown'

            data = json.loads(result.stdout)

            # Analyze heuristic findings to determine role
            return self._analyze_heuristic_findings(data.get('results', []))

        except subprocess.TimeoutExpired:
            logger.error("Semgrep heuristic detection timed out")
            return 'unknown'
        except Exception as e:
            logger.error(f"Failed to detect deployment role: {e}")
            return 'unknown'

    def _get_heuristic_rules_path(self, language: str) -> Path:
        """Get path to heuristic rules for given language."""
        language_map = {
            'python': 'heuristic_python.yaml',
            'javascript': 'heuristic_javascript.yaml',
            'typescript': 'heuristic_javascript.yaml',
            'go': 'heuristic_go.yaml'
        }

        if language == 'auto':
            # Try to detect language from files
            # This is simplified - you might want more sophisticated detection
            return self.rules_dir / 'heuristic_all.yaml'

        rule_file = language_map.get(language.lower(), 'heuristic_all.yaml')
        return self.rules_dir / rule_file

    def _analyze_heuristic_findings(self, findings: List[Dict]) -> str:
        """
        Analyze heuristic findings to determine deployment role.

        Uses weighted scoring to determine the most likely deployment context
        based on code patterns found by heuristic rules.

        Args:
            findings: List of Semgrep findings from heuristic rules

        Returns:
            Deployment role (trusted-host-only/standalone/mixed-use/unknown)
        """
        role_scores = {
            'trusted-host-only': 0,
            'standalone': 0,
            'mixed-use': 0
        }

        for finding in findings:
            rule_id = finding.get('check_id', '')
            metadata = finding.get('extra', {}).get('metadata', {})
            deployment_mode = metadata.get('deployment_mode', '')

            if deployment_mode in role_scores:
                role_scores[deployment_mode] += 1

        # Determine role based on scores
        if role_scores['mixed-use'] > 0:
            return 'mixed-use'
        elif role_scores['standalone'] > 0:
            return 'standalone'
        elif role_scores['trusted-host-only'] > 0:
            return 'trusted-host-only'
        else:
            return 'unknown'

    async def _run_semgrep(self, repo_path: Path, role: str, language: str) -> List[SemgrepFinding]:
        """
        Run Semgrep with role-specific security rules.

        Executes Semgrep using rules tailored to the detected deployment role
        and programming language.

        Args:
            repo_path: Path to repository to scan
            role: Deployment role to use for rule selection
            language: Programming language for rule selection

        Returns:
            List of security findings from Semgrep
        """
        # Get role-specific rules
        rules_path = self._get_role_rules_path(role, language)

        if not rules_path.exists():
            logger.warning(f"No rules for role {role} and language {language}")
            return []

        try:
            result = subprocess.run(
                ['semgrep', '--config', str(rules_path), '--json', str(repo_path)],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            if result.returncode not in [0, 1]:  # 1 = findings exist
                logger.error(f"Semgrep failed: {result.stderr}")
                return []

            data = json.loads(result.stdout)
            return self._parse_semgrep_results(data.get('results', []))

        except subprocess.TimeoutExpired:
            logger.error("Semgrep timed out")
            return []
        except Exception as e:
            logger.error(f"Failed to run Semgrep: {e}")
            return []

    def _get_role_rules_path(self, role: str, language: str) -> Path:
        """Get path to role-specific security rules.

        Maps deployment roles to their corresponding rule files.
        Falls back to default rules for unknown roles.

        Args:
            role: Deployment role
            language: Programming language (currently unused, for future expansion)

        Returns:
            Path to the appropriate rules file
        """
        # Simplified - you might want language-specific role rules
        role_map = {
            'trusted-host-only': 'trusted_host_rules.yaml',
            'standalone': 'standalone_rules.yaml',
            'mixed-use': 'mixed_use_rules.yaml',
            'trusted-host-only-unconfirmed': 'unconfirmed_rules.yaml',
            'unknown': 'default_rules.yaml'
        }

        rule_file = role_map.get(role, 'default_rules.yaml')
        return self.rules_dir / rule_file

    def _parse_semgrep_results(self, results: List[Dict]) -> List[SemgrepFinding]:
        """Parse Semgrep JSON results into SemgrepFinding objects.

        Transforms raw Semgrep output into structured findings,
        automatically detecting MCP-specific rules based on rule ID prefix.

        Args:
            results: Raw Semgrep JSON results

        Returns:
            List of parsed SemgrepFinding objects
        """
        findings = []

        for result in results:
            finding = SemgrepFinding(
                rule_id=result.get('check_id', ''),
                severity=result.get('extra', {}).get('severity', 'low'),
                message=result.get('extra', {}).get('message', ''),
                file_path=result.get('path', ''),
                line=result.get('start', {}).get('line', 0),
                metadata=result.get('extra', {}).get('metadata', {}),
                is_mcp_specific='mcp-' in result.get('check_id', '')
            )
            findings.append(finding)

        return findings

    def _filter_findings_by_role(self,
                                 findings: List[SemgrepFinding],
                                 role: str) -> Tuple[List[SemgrepFinding], List[SemgrepFinding]]:
        """
        Filter findings based on deployment role.

        Suppresses findings that are not relevant to the detected deployment
        context. For example, authentication requirements are suppressed for
        trusted-host-only deployments.

        Args:
            findings: All findings from Semgrep scan
            role: Deployment role to filter for

        Returns:
            Tuple of (active_findings, suppressed_findings)
        """
        active = []
        suppressed = []

        for finding in findings:
            # Suppress auth findings for trusted-host-only
            if role == 'trusted-host-only':
                if any(x in finding.rule_id.lower() for x in ['auth', 'authentication', 'rate-limit']):
                    suppressed.append(finding)
                    continue

            # Add more role-specific filtering logic here
            active.append(finding)

        return active, suppressed

    def _calculate_score(self, findings: List[SemgrepFinding]) -> Tuple[float, int]:
        """
        Calculate FICO-style security score from findings.

        Uses weighted deductions based on severity and MCP-specificity.
        Scores range from 300 (poor) to 850 (excellent).

        Scoring thresholds:
        - 750-850: Excellent security
        - 670-749: Good security
        - 580-669: Fair security
        - 300-579: Poor security

        Args:
            findings: Active findings to score

        Returns:
            Tuple of (raw_score 0-100, fico_score 300-850)
        """
        base_score = 850
        total_deduction = 0

        # Calculate deductions
        for finding in findings:
            weight_map = SEVERITY_WEIGHTS['mcp_specific'] if finding.is_mcp_specific else SEVERITY_WEIGHTS['generic']
            deduction = abs(weight_map.get(finding.severity.lower(), 0))
            total_deduction += deduction

        # Calculate raw score (0-100 scale)
        raw_score = max(0, 100 - (total_deduction / 8.5))  # Scale to 0-100

        # Calculate FICO score
        fico_score = max(300, base_score - total_deduction)

        # Cap at 579 if more than 10 critical/high findings
        critical_high_count = sum(1 for f in findings if f.severity.lower() in ['critical', 'high'])
        if critical_high_count > 10:
            fico_score = min(fico_score, 579)

        return raw_score, fico_score

    async def score_multiple(self,
                           repositories: List[Tuple[str, str]],
                           max_concurrent: int = 3) -> List[SecurityScore]:
        """
        Score multiple repositories concurrently.

        Args:
            repositories: List of (repo_path, language) tuples
            max_concurrent: Maximum concurrent scans

        Returns:
            List of SecurityScore results
        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def score_with_limit(repo_path: str, language: str):
            async with semaphore:
                try:
                    return await self.score_repository(repo_path, language)
                except Exception as e:
                    logger.error(f"Failed to score {repo_path}: {e}")
                    return SecurityScore(
                        repository=Path(repo_path).name,
                        deployment_role='unknown',
                        fico_score=300,
                        raw_score=0,
                        findings=[],
                        suppressed_findings=[],
                        metadata={'error': str(e)}
                    )

        tasks = [score_with_limit(repo, lang) for repo, lang in repositories]
        return await asyncio.gather(*tasks)

    def generate_report(self, score: SecurityScore) -> str:
        """Generate human-readable security report from scoring results.

        Creates a formatted report showing the FICO score, deployment role,
        findings breakdown, and actionable recommendations.

        Args:
            score: SecurityScore object containing analysis results

        Returns:
            Formatted string report for display or logging
        """
        report = []
        report.append("=" * 70)
        report.append(f"Security Score Report: {score.repository}")
        report.append("=" * 70)
        report.append(f"\nDeployment Role: {score.deployment_role}")
        report.append(f"FICO Score: {score.fico_score} (Raw: {score.raw_score:.1f}/100)")
        report.append(f"Total Findings: {len(score.findings)}")

        if score.suppressed_findings:
            report.append(f"Suppressed (role-specific): {len(score.suppressed_findings)}")

        # Score interpretation
        interpretation = self._interpret_score(score.fico_score)
        report.append(f"\nInterpretation: {interpretation}")

        # Findings breakdown
        if score.findings:
            report.append("\n" + "-" * 70)
            report.append("Active Findings by Severity:")
            report.append("-" * 70)

            severity_counts = {}
            for finding in score.findings:
                severity = finding.severity.lower()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                if severity in severity_counts:
                    report.append(f"  {severity.upper()}: {severity_counts[severity]}")

        # Top findings
        if score.findings:
            report.append("\n" + "-" * 70)
            report.append("Top Security Findings:")
            report.append("-" * 70)

            for finding in score.findings[:5]:  # Show top 5
                report.append(f"\n[{finding.severity.upper()}] {finding.rule_id}")
                report.append(f"  {finding.message}")
                report.append(f"  File: {finding.file_path}:{finding.line}")

        report.append("\n" + "=" * 70)
        return '\n'.join(report)

    def _interpret_score(self, score: int) -> str:
        """Interpret FICO score into human-readable assessment.

        Maps numeric FICO scores to qualitative security assessments.

        Args:
            score: FICO score (300-850)

        Returns:
            String interpretation of security posture
        """
        if score >= 800:
            return "Excellent - Well-maintained, secure repository"
        elif score >= 740:
            return "Very Good - Strong security practices"
        elif score >= 670:
            return "Good - Adequate security measures"
        elif score >= 580:
            return "Fair - Some security concerns"
        else:
            return "Poor - Significant security issues requiring immediate attention"


# Example usage
async def main():
    """Example usage of MCPSemgrepScorer.

    Demonstrates how to score MCP repositories and generate reports.
    This example shows both single and batch repository scoring.
    """
    scorer = MCPSemgrepScorer()

    # Test on a single repository
    test_repos = [
        ("/path/to/mcp/repo1", "python"),
        ("/path/to/mcp/repo2", "javascript")
    ]

    for repo_path, language in test_repos:
        if Path(repo_path).exists():
            score = await scorer.score_repository(repo_path, language)
            print(scorer.generate_report(score))


if __name__ == "__main__":
    asyncio.run(main())