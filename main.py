#!/usr/bin/env python3
"""
MCP Security Analysis System - Main Orchestrator
=================================================
Analyzes and scores 13,016+ public GitHub repositories for security vulnerabilities.

This is the main entry point for the MCP Security Analysis System, which provides:
- Repository fetching from GitHub
- SBOM generation for dependency analysis
- Multi-tool security scanning (Semgrep, TruffleHog, OSV)
- FICO-style scoring (300-850 range)
- Comprehensive reporting

Author: MCP Security Team
"""

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import security modules
from security.config import SecurityConfig, SecurityLevel, get_security_config
from security.validators import validate_github_url
from github.fetcher import SecureGitHubFetcher

# Import scanners
from scanners.semgrep_scanner import MCPSecurityScanner
from scanners.trufflehog_scanner import TruffleHogScanner
from scanners.sbom_generator import SBOMGenerator, GeneratorType, SBOMFormat
from scanners.osv_scanner import OSVScanner

# Import scoring modules
from scoring.hygiene_scorer import MCPHygieneScorer
from scoring.tools_scorer import MCPToolsScorer
from scoring.vulnerability_scorer import VulnerabilityTimeScorer
from scoring.aggregator import ScoreAggregator

# Import reporting
from reports.generator import ReportGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class MCPSecurityOrchestrator:
    """
    Main orchestrator for the MCP Security Analysis System.

    Coordinates all security scanning, scoring, and reporting activities.
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the orchestrator.

        Args:
            config_path: Path to configuration file
        """
        # Load security configuration
        if config_path:
            self.config = SecurityConfig.from_file(config_path)
        else:
            self.config = get_security_config()

        # Get settings from environment
        self.github_token = os.getenv('GITHUB_TOKEN')
        self.storage_path = os.getenv('MCP_STORAGE_PATH', '/opt/mcp/storage')

        # Initialize components
        self.github_fetcher = SecureGitHubFetcher(
            github_token=self.github_token,
            storage_path=self.storage_path
        )

        # Initialize scanners
        self.semgrep_scanner = MCPSecurityScanner(
            rules_dir="rules/semgrep",
            custom_rules=self.config.custom_rules
        )

        self.trufflehog_scanner = TruffleHogScanner(
            verify_secrets=False,  # Never verify in public repos
            scan_history=True
        )

        self.sbom_generator = SBOMGenerator(
            generator_type=GeneratorType.CDXGEN,
            output_format=SBOMFormat.CYCLONEDX
        )

        self.osv_scanner = OSVScanner(
            check_kev=True,
            min_cvss=0.0
        )

        # Initialize scorers
        self.hygiene_scorer = MCPHygieneScorer()
        self.tools_scorer = MCPToolsScorer()
        self.vulnerability_scorer = VulnerabilityTimeScorer()
        self.score_aggregator = ScoreAggregator()

        # Initialize report generator
        self.report_generator = ReportGenerator()

        # Statistics
        self.stats = {
            'repos_analyzed': 0,
            'repos_failed': 0,
            'total_vulnerabilities': 0,
            'total_secrets': 0,
            'start_time': datetime.utcnow()
        }

    async def analyze_repository(self, repo_url: str) -> Dict[str, Any]:
        """
        Analyze a single repository.

        Args:
            repo_url: GitHub repository URL

        Returns:
            Complete analysis results
        """
        try:
            # Validate URL
            clean_url = validate_github_url(repo_url)
            logger.info(f"Analyzing repository: {clean_url}")

            # Fetch repository
            repo_path = await self.github_fetcher.fetch_repository(clean_url)

            # Generate SBOM
            sbom_path = await self._generate_sbom(repo_path)

            # Run security scans in parallel
            scan_results = await asyncio.gather(
                self._run_semgrep_scan(repo_path),
                self._run_trufflehog_scan(repo_path),
                self._run_osv_scan(sbom_path) if sbom_path else self._empty_osv_result(),
                return_exceptions=True
            )

            # Handle scan results
            semgrep_result = scan_results[0] if not isinstance(scan_results[0], Exception) else {}
            trufflehog_result = scan_results[1] if not isinstance(scan_results[1], Exception) else {}
            osv_result = scan_results[2] if not isinstance(scan_results[2], Exception) else {}

            # Calculate scores
            scores = self._calculate_scores(
                semgrep_result,
                trufflehog_result,
                osv_result,
                repo_url
            )

            # Generate report
            report = self.report_generator.generate(
                repo_url=repo_url,
                scan_results={
                    'semgrep': semgrep_result,
                    'trufflehog': trufflehog_result,
                    'osv': osv_result
                },
                scores=scores
            )

            # Update statistics
            self.stats['repos_analyzed'] += 1
            self.stats['total_vulnerabilities'] += osv_result.get('total_vulnerabilities', 0)
            self.stats['total_secrets'] += len(trufflehog_result.get('findings', []))

            return {
                'repository': repo_url,
                'status': 'success',
                'scores': scores,
                'report': report,
                'scan_results': {
                    'semgrep': semgrep_result,
                    'trufflehog': trufflehog_result,
                    'osv': osv_result
                }
            }

        except Exception as e:
            logger.error(f"Failed to analyze {repo_url}: {e}")
            self.stats['repos_failed'] += 1
            return {
                'repository': repo_url,
                'status': 'failed',
                'error': str(e)
            }

    async def analyze_batch(self, repo_urls: List[str],
                           max_concurrent: int = 5) -> List[Dict[str, Any]]:
        """
        Analyze multiple repositories concurrently.

        Args:
            repo_urls: List of repository URLs
            max_concurrent: Maximum concurrent analyses

        Returns:
            List of analysis results
        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def analyze_with_limit(url):
            async with semaphore:
                return await self.analyze_repository(url)

        tasks = [analyze_with_limit(url) for url in repo_urls]
        results = await asyncio.gather(*tasks)

        return results

    async def _generate_sbom(self, repo_path: str) -> Optional[str]:
        """Generate SBOM for repository."""
        try:
            result = self.sbom_generator.generate(repo_path)
            if result['status'] == 'success':
                return result['sbom_path']
        except Exception as e:
            logger.warning(f"SBOM generation failed: {e}")
        return None

    async def _run_semgrep_scan(self, repo_path: str) -> Dict[str, Any]:
        """Run Semgrep security scan."""
        return self.semgrep_scanner.scan_repository(repo_path)

    async def _run_trufflehog_scan(self, repo_path: str) -> Dict[str, Any]:
        """Run TruffleHog secret scan."""
        return self.trufflehog_scanner.scan_repository(repo_path)

    async def _run_osv_scan(self, sbom_path: str) -> Dict[str, Any]:
        """Run OSV vulnerability scan."""
        # OSV scanner has scan_sbom method, not scan_from_sbom
        result = await self.osv_scanner.scan_sbom(sbom_path)
        # Convert OSVScanResult to dict for compatibility
        return result.to_dict()

    async def _empty_osv_result(self) -> Dict[str, Any]:
        """Return empty OSV result when SBOM unavailable."""
        return {'vulnerabilities': [], 'total_vulnerabilities': 0}

    def _calculate_scores(self, semgrep_result: Dict, trufflehog_result: Dict,
                         osv_result: Dict, repo_url: str) -> Dict[str, Any]:
        """
        Calculate all security scores using the three-component system.

        This method orchestrates the scoring process by:
        1. Calculating hygiene score from GitHub repository metrics
        2. Calculating tools score from Semgrep and TruffleHog findings
        3. Calculating vulnerability score from OSV scan results
        4. Aggregating all three scores into a final FICO score

        The final score uses weighted averaging:
        - Hygiene: 25% (repository health)
        - Tools: 35% (code issues and secrets)
        - Vulnerability: 40% (known CVEs with time decay)

        Args:
            semgrep_result: Semgrep scan results with findings
            trufflehog_result: TruffleHog scan results with findings
            osv_result: OSV scan results with vulnerabilities
            repo_url: GitHub repository URL

        Returns:
            Dictionary containing:
                - final_score: Aggregated FICO score (300-850)
                - hygiene_score: GitHub health metrics score
                - tools_score: Combined Semgrep + TruffleHog score
                - vulnerability_score: Time-decay vulnerability score
                - components: Weight distribution
        """
        # Parse repo URL to get owner and name for hygiene scorer
        from urllib.parse import urlparse
        parsed = urlparse(repo_url)
        path_parts = parsed.path.strip('/').split('/')
        owner = path_parts[0] if len(path_parts) > 0 else 'unknown'
        repo = path_parts[1] if len(path_parts) > 1 else 'unknown'

        # Calculate individual scores
        # Hygiene scorer needs repo owner/name, not scan results
        hygiene_score = asyncio.run(self.hygiene_scorer.score_repository(owner, repo))

        # Tools scorer combines Semgrep and TruffleHog findings
        tools_score_result = self.tools_scorer.calculate_score(
            semgrep_result.get('findings', []),
            trufflehog_result.get('findings', [])
        )
        tools_score = tools_score_result['fico_score']

        # Vulnerability scorer processes OSV results
        vulnerability_score_result = self.vulnerability_scorer.calculate_score(
            osv_result,  # Pass the full result dict, not just vulnerabilities
            repo_url
        )
        vulnerability_score = vulnerability_score_result.fico_score

        # Aggregate scores using FICO values
        final_score = self.score_aggregator.aggregate_scores({
            'hygiene': hygiene_score.get('fico_score', 600),
            'tools': tools_score,
            'vulnerability': vulnerability_score
        })

        return {
            'final_score': final_score,
            'hygiene_score': hygiene_score,
            'tools_score': tools_score_result,
            'vulnerability_score': vulnerability_score_result.to_dict(),
            'components': {
                'hygiene_weight': 0.25,
                'tools_weight': 0.35,
                'vulnerability_weight': 0.40
            }
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get current statistics."""
        runtime = (datetime.utcnow() - self.stats['start_time']).total_seconds()
        return {
            **self.stats,
            'runtime_seconds': runtime,
            'success_rate': (self.stats['repos_analyzed'] /
                           (self.stats['repos_analyzed'] + self.stats['repos_failed'])
                           if (self.stats['repos_analyzed'] + self.stats['repos_failed']) > 0
                           else 0)
        }


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='MCP Security Analysis System'
    )
    parser.add_argument(
        'action',
        choices=['analyze', 'batch', 'stats'],
        help='Action to perform'
    )
    parser.add_argument(
        '--repo',
        help='Repository URL for single analysis'
    )
    parser.add_argument(
        '--repos-file',
        help='File containing repository URLs (one per line)'
    )
    parser.add_argument(
        '--config',
        help='Configuration file path'
    )
    parser.add_argument(
        '--output',
        help='Output file for results'
    )
    parser.add_argument(
        '--max-concurrent',
        type=int,
        default=5,
        help='Maximum concurrent analyses'
    )

    args = parser.parse_args()

    # Initialize orchestrator
    orchestrator = MCPSecurityOrchestrator(config_path=args.config)

    if args.action == 'analyze':
        if not args.repo:
            print("Error: --repo required for analyze action")
            sys.exit(1)

        # Analyze single repository
        result = await orchestrator.analyze_repository(args.repo)

        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(result, f, indent=2)
        else:
            print(json.dumps(result, indent=2))

    elif args.action == 'batch':
        if not args.repos_file:
            print("Error: --repos-file required for batch action")
            sys.exit(1)

        # Load repository URLs
        with open(args.repos_file, 'r') as f:
            repo_urls = [line.strip() for line in f if line.strip()]

        logger.info(f"Analyzing {len(repo_urls)} repositories...")

        # Analyze batch
        results = await orchestrator.analyze_batch(
            repo_urls,
            max_concurrent=args.max_concurrent
        )

        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
        else:
            print(json.dumps(results, indent=2))

    elif args.action == 'stats':
        stats = orchestrator.get_statistics()
        print(json.dumps(stats, indent=2))


if __name__ == '__main__':
    asyncio.run(main())