#!/usr/bin/env python3
"""
Tools Score Calculator
======================
Combines findings from multiple security tools (Semgrep, TruffleHog)
into a unified FICO-style Tools Score (300-850).

Weight Distribution:
- Semgrep (Code Issues): 60%
- TruffleHog (Secrets): 40%
"""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class FindingSeverity(Enum):
    """Unified severity levels for tool findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ToolFinding:
    """Represents a finding from any security tool."""
    tool: str
    severity: FindingSeverity
    category: str
    message: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    verified: bool = False  # For secrets
    deduction: int = 0  # FICO points to deduct


class MCPToolsScorer:
    """
    Calculate Tools Score from Semgrep and TruffleHog findings.

    This scorer combines static code analysis results from Semgrep with
    secret detection findings from TruffleHog to produce a unified security
    score that reflects code quality and secret hygiene.

    Outputs FICO-style score (300-850) for consistency with other scorers.

    Score Interpretation:
    - 800-850: Excellent - Very few or no security issues
    - 740-799: Very Good - Minor issues present
    - 670-739: Good - Some issues need attention
    - 580-669: Fair - Multiple issues require remediation
    - 500-579: Poor - Significant security issues
    - 300-499: Very Poor - Critical issues require immediate action
    """

    def __init__(self):
        """Initialize the Tools Scorer with scoring parameters."""
        # Maximum possible deduction (850 - 300 = 550 points)
        self.max_deduction = 550

        # Weight distribution
        self.weights = {
            'semgrep': 0.6,  # 60% for code issues
            'trufflehog': 0.4  # 40% for secrets
        }

        # Semgrep severity deductions (out of 330 points max for Semgrep)
        self.semgrep_deductions = {
            'critical': 80,
            'high': 50,
            'medium': 20,
            'low': 5,
            'info': 1
        }

        # TruffleHog severity deductions (out of 220 points max for TruffleHog)
        self.trufflehog_deductions = {
            'verified': {
                'critical': 200,  # Verified secrets are extremely serious
                'high': 180,
                'medium': 150,
                'low': 100
            },
            'unverified': {
                'critical': 100,
                'high': 80,
                'medium': 50,
                'low': 20
            }
        }

    def calculate_score(self, semgrep_findings: List[Dict],
                       trufflehog_findings: List[Dict]) -> Dict[str, Any]:
        """
        Calculate the combined Tools Score from security tool findings.

        This method processes findings from both Semgrep (static code analysis)
        and TruffleHog (secret detection), applies severity-based deductions,
        and generates a FICO-style score that represents the overall security
        posture from a tools perspective.

        Args:
            semgrep_findings: List of Semgrep finding dictionaries containing:
                - severity: Finding severity level (critical/high/medium/low/info)
                - category: Type of security issue
                - message: Description of the finding
            trufflehog_findings: List of TruffleHog finding dictionaries containing:
                - severity: Secret severity level
                - verified: Boolean indicating if secret is verified
                - detector: Type of secret detected

        Returns:
            Dictionary containing:
                - fico_score: Final FICO score (300-850)
                - components: Breakdown by tool with subscores
                - total_findings: Total number of findings
                - critical_findings: Count of critical/high severity issues
        """
        # Process Semgrep findings
        semgrep_deduction = self._calculate_semgrep_deduction(semgrep_findings)
        semgrep_subscore = self._calculate_subscore(semgrep_deduction, self.weights['semgrep'])

        # Process TruffleHog findings
        trufflehog_deduction = self._calculate_trufflehog_deduction(trufflehog_findings)
        trufflehog_subscore = self._calculate_subscore(trufflehog_deduction, self.weights['trufflehog'])

        # Calculate weighted total deduction
        total_weighted_deduction = (
            semgrep_deduction * self.weights['semgrep'] +
            trufflehog_deduction * self.weights['trufflehog']
        )

        # Calculate FICO score (850 minus deductions, minimum 300)
        fico_score = max(300, 850 - int(total_weighted_deduction))

        return {
            'fico_score': fico_score,
            'components': {
                'semgrep': {
                    'findings_count': len(semgrep_findings),
                    'deduction': semgrep_deduction,
                    'subscore': semgrep_subscore,
                    'weight': self.weights['semgrep']
                },
                'trufflehog': {
                    'findings_count': len(trufflehog_findings),
                    'deduction': trufflehog_deduction,
                    'subscore': trufflehog_subscore,
                    'weight': self.weights['trufflehog'],
                    'verified_count': sum(1 for f in trufflehog_findings if f.get('verified', False))
                }
            },
            'total_findings': len(semgrep_findings) + len(trufflehog_findings),
            'critical_findings': self._count_critical_findings(semgrep_findings, trufflehog_findings)
        }

    def _calculate_semgrep_deduction(self, findings: List[Dict]) -> int:
        """
        Calculate total deduction from Semgrep findings.

        Args:
            findings: List of Semgrep finding dictionaries

        Returns:
            Total deduction points
        """
        if not findings:
            return 0

        total_deduction = 0

        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            deduction = self.semgrep_deductions.get(severity, 1)
            total_deduction += deduction

        # Cap at maximum possible deduction for Semgrep (60% of 550)
        max_semgrep_deduction = int(self.max_deduction * self.weights['semgrep'])
        return min(total_deduction, max_semgrep_deduction)

    def _calculate_trufflehog_deduction(self, findings: List[Dict]) -> int:
        """
        Calculate total deduction from TruffleHog findings.

        Args:
            findings: List of TruffleHog finding dictionaries

        Returns:
            Total deduction points
        """
        if not findings:
            return 0

        total_deduction = 0

        for finding in findings:
            severity = finding.get('severity', 'low').lower()
            verified = finding.get('verified', False)

            if verified:
                deduction = self.trufflehog_deductions['verified'].get(severity, 20)
            else:
                deduction = self.trufflehog_deductions['unverified'].get(severity, 10)

            total_deduction += deduction

        # Cap at maximum possible deduction for TruffleHog (40% of 550)
        max_trufflehog_deduction = int(self.max_deduction * self.weights['trufflehog'])
        return min(total_deduction, max_trufflehog_deduction)

    def _calculate_subscore(self, deduction: int, weight: float) -> int:
        """
        Calculate a subscore for a component.

        Args:
            deduction: Points deducted
            weight: Weight of this component

        Returns:
            Subscore in FICO range
        """
        max_component_deduction = int(self.max_deduction * weight)
        if max_component_deduction == 0:
            return 850

        # Calculate percentage of max deduction used
        deduction_ratio = min(1.0, deduction / max_component_deduction)

        # Convert to FICO scale
        subscore = 850 - int(deduction_ratio * 550)
        return max(300, subscore)

    def _count_critical_findings(self, semgrep_findings: List[Dict],
                                 trufflehog_findings: List[Dict]) -> int:
        """
        Count critical and high severity findings.

        Args:
            semgrep_findings: Semgrep findings
            trufflehog_findings: TruffleHog findings

        Returns:
            Count of critical/high findings
        """
        count = 0

        # Count Semgrep critical/high
        for finding in semgrep_findings:
            severity = finding.get('severity', '').lower()
            if severity in ['critical', 'high']:
                count += 1

        # Count TruffleHog critical/high or any verified
        for finding in trufflehog_findings:
            severity = finding.get('severity', '').lower()
            verified = finding.get('verified', False)
            if verified or severity in ['critical', 'high']:
                count += 1

        return count

    async def score_from_scan_results(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate score from combined scan results.

        Args:
            scan_results: Dictionary containing 'semgrep' and 'trufflehog' results

        Returns:
            Tools score with FICO rating
        """
        semgrep_findings = scan_results.get('semgrep', {}).get('findings', [])
        trufflehog_findings = scan_results.get('trufflehog', {}).get('findings', [])

        score_result = self.calculate_score(semgrep_findings, trufflehog_findings)

        # Add interpretation
        score_result['interpretation'] = self._interpret_score(score_result['fico_score'])

        return score_result

    def _interpret_score(self, fico_score: int) -> str:
        """
        Provide interpretation of the FICO score.

        Args:
            fico_score: FICO score (300-850)

        Returns:
            Human-readable interpretation
        """
        if fico_score >= 800:
            return "Excellent - Very few security issues detected"
        elif fico_score >= 740:
            return "Very Good - Minor security issues present"
        elif fico_score >= 670:
            return "Good - Some security issues need attention"
        elif fico_score >= 580:
            return "Fair - Multiple security issues require remediation"
        elif fico_score >= 500:
            return "Poor - Significant security issues found"
        else:
            return "Very Poor - Critical security issues require immediate action"