#!/usr/bin/env python3
"""
Test script for MCP Hygiene Scoring System
Validates scoring logic and provides examples.
"""

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from typing import List, Tuple

# Check for required environment variable
if not os.getenv('GITHUB_TOKEN'):
    print("Error: GITHUB_TOKEN environment variable is required")
    print("Set it with: export GITHUB_TOKEN='your-github-token'")
    sys.exit(1)

# Import the scorer
try:
    from mcp_hygiene_score import MCPHygieneScorer, SCORING_WEIGHTS, MCP_THRESHOLDS
except ImportError:
    print("Error: Could not import mcp_hygiene_score module")
    print("Make sure mcp_hygiene_score.py is in the same directory")
    sys.exit(1)


def print_score_interpretation(fico_score: int) -> str:
    """Interpret FICO-style score."""
    if fico_score >= 800:
        return "Excellent - Well-maintained, active repository"
    elif fico_score >= 740:
        return "Very Good - Strong maintenance practices"
    elif fico_score >= 670:
        return "Good - Adequate maintenance"
    elif fico_score >= 580:
        return "Fair - Some maintenance concerns"
    elif fico_score >= 500:
        return "Poor - Significant maintenance issues"
    else:
        return "Very Poor - Severely lacking maintenance"


def validate_weights() -> bool:
    """Validate that scoring weights sum to 1.0."""
    total = sum(SCORING_WEIGHTS.values())
    if abs(total - 1.0) > 0.001:
        print(f"ERROR: Scoring weights sum to {total}, should be 1.0")
        return False
    return True


def print_detailed_report(result: dict) -> None:
    """Print detailed scoring report."""
    print("\n" + "="*70)
    print(f"Repository: {result['repository']}")
    print("="*70)

    # Main scores
    print(f"\nFICO Score: {result['fico_score']} - {print_score_interpretation(result['fico_score'])}")
    print(f"Raw Score: {result['raw_score']}/100")

    # Component breakdown
    print("\n" + "-"*70)
    print("Component Breakdown:")
    print("-"*70)
    print(f"{'Component':<25} {'Score':<8} {'Weight':<8} {'Weighted':<10} {'Status'}")
    print("-"*70)

    for component, score in result['components'].items():
        if component == '_metadata':
            continue
        weight = SCORING_WEIGHTS[component]
        weighted = score * weight * 100

        # Status indicator
        if score >= 0.8:
            status = "✓ Excellent"
        elif score >= 0.6:
            status = "● Good"
        elif score >= 0.4:
            status = "○ Fair"
        else:
            status = "✗ Poor"

        print(f"{component:<25} {score:<8.2f} {weight:<8.2f} {weighted:<10.2f} {status}")

    # Metadata if available
    if '_metadata' in result['components']:
        meta = result['components']['_metadata']
        print("\n" + "-"*70)
        print("Repository Statistics:")
        print("-"*70)
        print(f"  Repository age:        {meta['repo_age_days']} days")
        print(f"  Recent PRs (90 days):  {meta['recent_pr_count']}")
        print(f"  Stale PRs:            {meta['stale_pr_count']}")
        print(f"  Stale issues:         {meta['stale_issue_count']}")
        print(f"  Contributors (90d):    {meta['contributor_count']}")
        print(f"  Days since last push:  {meta['days_since_push']}")
        print(f"  Has releases:         {'Yes' if meta['has_releases'] else 'No'}")

    # Recommendations
    print("\n" + "-"*70)
    print("Improvement Recommendations:")
    print("-"*70)

    recommendations = []
    comps = result['components']

    if comps.get('community_files', 0) < 0.8:
        recommendations.append("• Add missing community files (README, LICENSE, CONTRIBUTING, CODE_OF_CONDUCT)")

    if comps.get('branch_protection', 0) < 0.5:
        recommendations.append("• Enable branch protection rules on the default branch")

    if comps.get('pr_activity', 0) < 0.5:
        recommendations.append("• Increase PR activity - aim for at least 2 PRs per 90 days")

    if comps.get('commit_recency', 0) < 0.5:
        recommendations.append("• Repository appears inactive - consider archiving if no longer maintained")

    if comps.get('pr_reviewed', 0) < 0.5:
        recommendations.append("• Improve PR review practices - ensure PRs get reviewed before merging")

    if comps.get('pr_descriptive', 0) < 0.5:
        recommendations.append("• Encourage detailed PR descriptions (minimum 50 characters)")

    if comps.get('repo_cleanliness', 0) < 0.8:
        if '_metadata' in comps:
            if comps['_metadata']['stale_pr_count'] > 0:
                recommendations.append(f"• Close or merge {comps['_metadata']['stale_pr_count']} stale PRs")
            if comps['_metadata']['stale_issue_count'] > 0:
                recommendations.append(f"• Address {comps['_metadata']['stale_issue_count']} stale issues")

    if comps.get('release_recency', 0) < 0.5:
        recommendations.append("• Consider creating releases to mark stable versions")

    if comps.get('contributors', 0) < 0.5:
        recommendations.append("• Encourage more contributors - currently below minimum threshold")

    if recommendations:
        for rec in recommendations:
            print(rec)
    else:
        print("✓ Repository is well-maintained! No critical improvements needed.")


async def test_single_repo():
    """Test scoring a single repository."""
    print("\n" + "="*70)
    print("TEST: Single Repository Scoring")
    print("="*70)

    scorer = MCPHygieneScorer()
    result = await scorer.score_repository("modelcontextprotocol", "servers")

    if "error" in result:
        print(f"Error scoring repository: {result['error']}")
        return False

    print_detailed_report(result)
    return True


async def test_multiple_repos():
    """Test scoring multiple repositories concurrently."""
    print("\n" + "="*70)
    print("TEST: Multiple Repository Scoring (Concurrent)")
    print("="*70)

    test_repos = [
        ("modelcontextprotocol", "servers"),
        ("modelcontextprotocol", "typescript-sdk"),
        ("modelcontextprotocol", "python-sdk"),
    ]

    scorer = MCPHygieneScorer()
    results = await scorer.score_multiple(test_repos)

    print(f"\nScored {len(results)} repositories concurrently:")
    print("-"*70)
    print(f"{'Repository':<40} {'FICO Score':<12} {'Interpretation'}")
    print("-"*70)

    for result in results:
        if "error" not in result:
            interp = print_score_interpretation(result['fico_score'])
            print(f"{result['repository']:<40} {result['fico_score']:<12} {interp}")
        else:
            print(f"{result['repository']:<40} ERROR: {result['error']}")

    return True


async def test_with_config():
    """Test scoring with configuration overrides."""
    print("\n" + "="*70)
    print("TEST: Scoring with Configuration Overrides")
    print("="*70)

    # Check if config file exists
    if not os.path.exists("config.yaml"):
        print("No config.yaml found - skipping config test")
        return True

    scorer = MCPHygieneScorer(config_path="config.yaml")
    result = await scorer.score_repository("modelcontextprotocol", "servers")

    if "error" in result:
        print(f"Error scoring repository: {result['error']}")
        return False

    print(f"Repository: {result['repository']}")
    print(f"FICO Score: {result['fico_score']}")
    print(f"Config file loaded successfully")
    return True


async def test_error_handling():
    """Test error handling for non-existent repository."""
    print("\n" + "="*70)
    print("TEST: Error Handling")
    print("="*70)

    scorer = MCPHygieneScorer()
    result = await scorer.score_repository("this-org-does-not-exist", "fake-repo-12345")

    if "error" in result:
        print(f"✓ Error handled correctly: {result['error'][:100]}...")
        print(f"✓ Fallback FICO score: {result['fico_score']} (should be 300)")
        return result['fico_score'] == 300
    else:
        print("✗ Error not detected for non-existent repository")
        return False


async def run_all_tests():
    """Run all test cases."""
    print("\n" + "="*70)
    print("MCP HYGIENE SCORING SYSTEM - TEST SUITE")
    print("="*70)
    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")

    # Validate configuration
    print("\nValidating scoring weights...")
    if not validate_weights():
        print("✗ Weight validation failed")
        return False
    print("✓ Weights sum to 1.0")

    # Run test cases
    test_results = []

    print("\nRunning test cases...")
    test_results.append(("Single Repository", await test_single_repo()))
    test_results.append(("Multiple Repositories", await test_multiple_repos()))
    test_results.append(("Configuration Override", await test_with_config()))
    test_results.append(("Error Handling", await test_error_handling()))

    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)

    all_passed = True
    for test_name, passed in test_results:
        status = "✓ PASSED" if passed else "✗ FAILED"
        print(f"{test_name:<30} {status}")
        if not passed:
            all_passed = False

    print("="*70)
    if all_passed:
        print("ALL TESTS PASSED ✓")
    else:
        print("SOME TESTS FAILED ✗")

    return all_passed


async def main():
    """Main test runner."""
    try:
        success = await run_all_tests()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())