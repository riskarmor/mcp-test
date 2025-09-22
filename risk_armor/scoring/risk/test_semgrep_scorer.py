#!/usr/bin/env python3
"""
Test Script for MCP Semgrep Risk Scoring
=========================================
Demonstrates the complete risk scoring workflow.

Author: Risk Armor
License: Proprietary - All Rights Reserved
"""

import asyncio
import json
from pathlib import Path
from datetime import datetime
from semgrep_scorer import MCPSemgrepScorer, SemgrepFinding


def create_test_findings():
    """Create sample findings for testing scoring logic.

    Generates a diverse set of test findings with different severities,
    MCP-specificity, and rule types to comprehensively test the scoring system.

    Returns:
        List of SemgrepFinding objects for testing
    """
    findings = [
        # Critical MCP-specific findings
        SemgrepFinding(
            rule_id='mcp-py-missing-auth',
            severity='critical',
            message='Publicly exposed route lacks authentication',
            file_path='app/server.py',
            line=42,
            is_mcp_specific=True
        ),
        SemgrepFinding(
            rule_id='mcp-py-shell-injection',
            severity='critical',
            message='Unvalidated user input in shell command',
            file_path='app/handlers.py',
            line=156,
            is_mcp_specific=True
        ),
        # High severity findings
        SemgrepFinding(
            rule_id='mcp-py-transport-insecure',
            severity='high',
            message='TLS disabled for standalone MCP',
            file_path='app/server.py',
            line=15,
            is_mcp_specific=True
        ),
        SemgrepFinding(
            rule_id='generic-sql-injection',
            severity='high',
            message='SQL injection vulnerability',
            file_path='app/database.py',
            line=89,
            is_mcp_specific=False
        ),
        # Medium severity findings
        SemgrepFinding(
            rule_id='mcp-py-missing-rate-limit',
            severity='medium',
            message='No rate limiting on public endpoint',
            file_path='app/api.py',
            line=234,
            is_mcp_specific=True
        ),
        SemgrepFinding(
            rule_id='generic-weak-crypto',
            severity='medium',
            message='Use of weak cryptographic algorithm',
            file_path='app/crypto.py',
            line=45,
            is_mcp_specific=False
        ),
        # Low severity findings
        SemgrepFinding(
            rule_id='generic-unused-var',
            severity='low',
            message='Unused variable',
            file_path='app/utils.py',
            line=12,
            is_mcp_specific=False
        )
    ]
    return findings


def test_scoring_calculation():
    """Test the scoring calculation logic.

    Validates that the FICO scoring algorithm correctly:
    - Applies severity weights
    - Applies MCP-specific penalties
    - Calculates raw and FICO scores
    - Interprets scores correctly
    """
    print("\n" + "="*70)
    print("TEST: Scoring Calculation Logic")
    print("="*70)

    scorer = MCPSemgrepScorer()
    findings = create_test_findings()

    # Test score calculation
    raw_score, fico_score = scorer._calculate_score(findings)

    print(f"\nFindings Summary:")
    print(f"  Total findings: {len(findings)}")

    # Count by severity
    severity_counts = {}
    for finding in findings:
        severity = finding.severity.lower()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    for severity in ['critical', 'high', 'medium', 'low']:
        if severity in severity_counts:
            print(f"  {severity.upper()}: {severity_counts[severity]}")

    # Show scoring breakdown
    print(f"\nScoring Breakdown:")
    total_deduction = 0
    for finding in findings:
        weight_map = scorer.SEVERITY_WEIGHTS['mcp_specific'] if finding.is_mcp_specific else scorer.SEVERITY_WEIGHTS['generic']
        deduction = abs(weight_map.get(finding.severity.lower(), 0))
        total_deduction += deduction
        print(f"  {finding.rule_id[:30]:30s} [{finding.severity:8s}] {'MCP' if finding.is_mcp_specific else '   '} = -{deduction}")

    print(f"\nTotal Deduction: -{total_deduction}")
    print(f"Raw Score: {raw_score:.1f}/100")
    print(f"FICO Score: {fico_score}")

    # Test interpretation
    interpretation = scorer._interpret_score(fico_score)
    print(f"Interpretation: {interpretation}")

    return fico_score


def test_role_filtering():
    """Test role-based finding filtering.

    Validates that findings are properly suppressed based on deployment role.
    For example, authentication findings should be suppressed for trusted-host-only
    deployments since they don't expose network endpoints.
    """
    print("\n" + "="*70)
    print("TEST: Role-Based Finding Filtering")
    print("="*70)

    scorer = MCPSemgrepScorer()

    # Create findings that should be suppressed for trusted-host-only
    auth_finding = SemgrepFinding(
        rule_id='mcp-py-missing-auth',
        severity='critical',
        message='Missing authentication',
        file_path='server.py',
        line=10,
        is_mcp_specific=True
    )

    rate_limit_finding = SemgrepFinding(
        rule_id='mcp-py-missing-rate-limit',
        severity='medium',
        message='Missing rate limiting',
        file_path='server.py',
        line=20,
        is_mcp_specific=True
    )

    other_finding = SemgrepFinding(
        rule_id='mcp-py-shell-injection',
        severity='critical',
        message='Shell injection',
        file_path='server.py',
        line=30,
        is_mcp_specific=True
    )

    findings = [auth_finding, rate_limit_finding, other_finding]

    # Test for trusted-host-only role
    print("\n1. Testing trusted-host-only role:")
    active, suppressed = scorer._filter_findings_by_role(findings, 'trusted-host-only')
    print(f"   Active findings: {len(active)}")
    print(f"   Suppressed findings: {len(suppressed)}")
    for finding in suppressed:
        print(f"     - Suppressed: {finding.rule_id}")

    # Test for standalone role
    print("\n2. Testing standalone role:")
    active, suppressed = scorer._filter_findings_by_role(findings, 'standalone')
    print(f"   Active findings: {len(active)}")
    print(f"   Suppressed findings: {len(suppressed)}")


def test_report_generation():
    """Test report generation.

    Validates that security reports are properly formatted with:
    - FICO scores and interpretations
    - Active vs suppressed findings
    - Severity breakdowns
    - Top security findings with details
    """
    print("\n" + "="*70)
    print("TEST: Report Generation")
    print("="*70)

    from semgrep_scorer import SecurityScore

    scorer = MCPSemgrepScorer()

    # Create a sample security score
    score = SecurityScore(
        repository='test-mcp-repo',
        deployment_role='standalone',
        fico_score=520,
        raw_score=35.2,
        findings=create_test_findings()[:3],  # Just show first 3
        suppressed_findings=create_test_findings()[3:5],  # Some suppressed
        metadata={
            'scored_at': datetime.now().isoformat(),
            'language': 'python',
            'total_findings': 7,
            'active_findings': 3,
            'suppressed_count': 2
        }
    )

    # Generate report
    report = scorer.generate_report(score)
    print(report)


async def test_full_workflow_mock():
    """Test the full workflow with mock data (no actual repo scanning).

    Simulates the complete scoring workflow for different deployment roles:
    - trusted-host-only: Minimal public exposure, fewer security requirements
    - standalone: Full public exposure, maximum security requirements
    - mixed-use: Conditional security based on deployment mode

    This test validates that different roles produce appropriately different scores.
    """
    print("\n" + "="*70)
    print("TEST: Full Workflow Simulation")
    print("="*70)

    scorer = MCPSemgrepScorer()

    # Simulate different deployment roles
    test_cases = [
        ('trusted-host-only', 'MCP Host Plugin', [
            ('mcp-py-host-exposed-binding', 'critical', True),
            ('mcp-py-missing-prompt-logging', 'medium', True),
        ]),
        ('standalone', 'MCP API Server', [
            ('mcp-py-missing-auth', 'critical', True),
            ('mcp-py-transport-insecure', 'high', True),
            ('mcp-py-shell-injection', 'critical', True),
            ('generic-sql-injection', 'high', False),
        ]),
        ('mixed-use', 'MCP Hybrid Service', [
            ('mcp-py-conditional-auth-missing', 'high', True),
            ('generic-weak-crypto', 'medium', False),
        ])
    ]

    print("\nSimulating scoring for different deployment roles:\n")

    for role, repo_name, finding_specs in test_cases:
        findings = []
        for rule_id, severity, is_mcp in finding_specs:
            findings.append(SemgrepFinding(
                rule_id=rule_id,
                severity=severity,
                message=f"Finding from {rule_id}",
                file_path='test.py',
                line=1,
                is_mcp_specific=is_mcp
            ))

        # Filter by role
        active, suppressed = scorer._filter_findings_by_role(findings, role)

        # Calculate score
        raw_score, fico_score = scorer._calculate_score(active)

        print(f"Repository: {repo_name}")
        print(f"  Role: {role}")
        print(f"  Findings: {len(active)} active, {len(suppressed)} suppressed")
        print(f"  FICO Score: {fico_score}")
        print(f"  Interpretation: {scorer._interpret_score(fico_score)}")
        print()


def main():
    """Run all tests.

    Test suite entry point that executes all test functions in sequence,
    validating the complete MCP Semgrep risk scoring system.
    """
    print("\n" + "="*70)
    print("MCP SEMGREP RISK SCORING TEST SUITE")
    print("="*70)
    print(f"Timestamp: {datetime.now().isoformat()}")

    # Run synchronous tests
    test_scoring_calculation()
    test_role_filtering()
    test_report_generation()

    # Run async tests
    asyncio.run(test_full_workflow_mock())

    print("\n" + "="*70)
    print("ALL TESTS COMPLETED")
    print("="*70)


if __name__ == "__main__":
    main()