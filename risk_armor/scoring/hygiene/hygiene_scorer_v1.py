#!/usr/bin/env python3
"""
MCP Repository Hygiene Scoring System
Analyzes GitHub repositories for maintenance and health metrics.
Produces FICO-style scores (300-850) based on weighted components.
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple
import yaml

# Third-party imports
try:
    from gql import Client, gql
    from gql.transport.aiohttp import AIOHTTPTransport
    from dotenv import load_dotenv
except ImportError:
    print("Error: Required packages not installed.")
    print("Please run: pip install gql aiohttp python-dotenv pyyaml")
    sys.exit(1)

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# GitHub API configuration
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
if not GITHUB_TOKEN:
    logger.error("GITHUB_TOKEN environment variable is required")
    sys.exit(1)

# Scoring weights (total = 1.00)
SCORING_WEIGHTS = {
    "community_files": 0.15,      # README, LICENSE, CONTRIBUTING, CODE_OF_CONDUCT
    "branch_protection": 0.10,     # Default branch protection
    "young_repo": 0.05,            # Bonus for new repos
    "pr_activity": 0.10,           # Recent PR merge activity
    "commit_recency": 0.10,        # Recent commit activity
    "pr_reviewed": 0.10,           # PRs with reviews
    "pr_descriptive": 0.10,        # PR quality (description length)
    "repo_cleanliness": 0.10,      # No stale PRs/issues
    "release_recency": 0.10,       # Recent releases
    "contributors": 0.10           # Active contributor count
}

# MCP-specific thresholds (more lenient than typical repos)
MCP_THRESHOLDS = {
    "healthy_pr_count_90d": 2,     # 2+ PRs in 90 days is healthy for MCP
    "stale_pr_days": 60,           # PR considered stale after 60 days
    "stale_issue_days": 90,        # Issue considered stale after 90 days
    "min_pr_description": 50,      # Minimum PR description length
    "recent_commit_days": 30,      # Days to consider commit "recent"
    "recent_release_days": 90,     # Days to consider release "recent"
    "min_contributors": 2           # Minimum contributors for full score
}

# GraphQL query for comprehensive repo metrics
REPO_METRICS_QUERY = gql("""
query RepoMetrics($owner: String!, $name: String!, $since: DateTime!) {
  repository(owner: $owner, name: $name) {
    createdAt
    pushedAt
    defaultBranchRef {
      name
      branchProtectionRule {
        id
        requiresApprovingReviews
        requiresCodeOwnerReviews
        dismissesStaleReviews
        requiresStatusChecks
      }
    }

    # Community files
    readme: object(expression: "HEAD:README.md") { ... on Blob { id } }
    readmeAlt: object(expression: "HEAD:README") { ... on Blob { id } }
    readmeRst: object(expression: "HEAD:README.rst") { ... on Blob { id } }
    license: object(expression: "HEAD:LICENSE") { ... on Blob { id } }
    licenseMd: object(expression: "HEAD:LICENSE.md") { ... on Blob { id } }
    contributing: object(expression: "HEAD:CONTRIBUTING.md") { ... on Blob { id } }
    codeOfConduct: object(expression: "HEAD:CODE_OF_CONDUCT.md") { ... on Blob { id } }

    # Recent merged PRs (last 90 days)
    mergedPRs: pullRequests(
      last: 100
      states: MERGED
      orderBy: {field: UPDATED_AT, direction: DESC}
    ) {
      totalCount
      nodes {
        mergedAt
        createdAt
        bodyText
        reviews { totalCount }
        author { login }
      }
    }

    # Open/stale PRs
    openPRs: pullRequests(states: OPEN, last: 100) {
      totalCount
      nodes {
        createdAt
        updatedAt
        isDraft
      }
    }

    # Open/stale issues
    openIssues: issues(states: OPEN, last: 100) {
      totalCount
      nodes {
        createdAt
        updatedAt
      }
    }

    # Recent releases
    releases(last: 10, orderBy: {field: CREATED_AT, direction: DESC}) {
      totalCount
      nodes {
        publishedAt
        tagName
      }
    }

    # Contributors (via recent commits)
    defaultBranchRef2: defaultBranchRef {
      target {
        ... on Commit {
          history(since: $since, first: 100) {
            totalCount
            nodes {
              author {
                user { login }
                email
                name
              }
              committedDate
            }
          }
        }
      }
    }
  }
}
""")


class MCPHygieneScorer:
    """Calculates hygiene scores for MCP repositories."""

    def __init__(self, config_path: Optional[str] = None):
        """Initialize scorer with optional config overrides."""
        self.config = self._load_config(config_path) if config_path else {}
        self.client = self._create_graphql_client()

    def _load_config(self, config_path: str) -> Dict:
        """Load configuration overrides from YAML file."""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logger.warning(f"Failed to load config from {config_path}: {e}")
            return {}

    def _create_graphql_client(self) -> Client:
        """Create GraphQL client with authentication."""
        transport = AIOHTTPTransport(
            url="https://api.github.com/graphql",
            headers={"Authorization": f"Bearer {GITHUB_TOKEN}"}
        )
        return Client(transport=transport, fetch_schema_from_transport=False)

    async def score_repository(self, owner: str, repo: str) -> Dict:
        """
        Score a repository's hygiene.

        Returns dict with:
        - fico_score: 300-850 score
        - raw_score: 0-100 score
        - components: Individual component scores
        - metadata: Additional context
        """
        try:
            # Fetch repository data
            metrics = await self._fetch_repo_metrics(owner, repo)

            # Calculate component scores
            components = await self._calculate_components(metrics)

            # Apply manual overrides if configured
            components = self._apply_overrides(f"{owner}/{repo}", components)

            # Calculate weighted score
            raw_score = self._calculate_weighted_score(components)

            # Convert to FICO scale
            fico_score = self._to_fico_scale(raw_score)

            return {
                "repository": f"{owner}/{repo}",
                "fico_score": fico_score,
                "raw_score": round(raw_score, 2),
                "components": components,
                "metadata": {
                    "scored_at": datetime.now(timezone.utc).isoformat(),
                    "weights": SCORING_WEIGHTS,
                    "thresholds": MCP_THRESHOLDS
                }
            }

        except Exception as e:
            logger.error(f"Failed to score {owner}/{repo}: {e}")
            return self._error_response(owner, repo, str(e))

    async def _fetch_repo_metrics(self, owner: str, repo: str) -> Dict:
        """Fetch comprehensive repository metrics via GraphQL."""
        since_date = datetime.now(timezone.utc) - timedelta(days=90)

        try:
            result = await self.client.execute_async(
                REPO_METRICS_QUERY,
                variable_values={
                    "owner": owner,
                    "name": repo,
                    "since": since_date.isoformat()
                }
            )
            return result["repository"]
        except Exception as e:
            logger.error(f"GraphQL query failed for {owner}/{repo}: {e}")
            raise

    async def _calculate_components(self, metrics: Dict) -> Dict[str, float]:
        """Calculate individual scoring components."""
        components = {}
        now = datetime.now(timezone.utc)

        # 1. Community files (0-1)
        community_files = 0
        if any([metrics.get('readme'), metrics.get('readmeAlt'), metrics.get('readmeRst')]):
            community_files += 0.4
        if metrics.get('license') or metrics.get('licenseMd'):
            community_files += 0.3
        if metrics.get('contributing'):
            community_files += 0.15
        if metrics.get('codeOfConduct'):
            community_files += 0.15
        components['community_files'] = community_files

        # 2. Branch protection (0-1)
        branch_protection = 0
        if metrics.get('defaultBranchRef', {}).get('branchProtectionRule'):
            rule = metrics['defaultBranchRef']['branchProtectionRule']
            if rule.get('requiresApprovingReviews'):
                branch_protection += 0.4
            if rule.get('requiresCodeOwnerReviews'):
                branch_protection += 0.2
            if rule.get('dismissesStaleReviews'):
                branch_protection += 0.2
            if rule.get('requiresStatusChecks'):
                branch_protection += 0.2
        components['branch_protection'] = branch_protection

        # 3. Young repo bonus (0-1)
        created_at = datetime.fromisoformat(metrics['createdAt'].replace('Z', '+00:00'))
        repo_age_days = (now - created_at).days
        young_repo_score = max(0, 1 - (repo_age_days / 180)) if repo_age_days < 180 else 0
        components['young_repo'] = young_repo_score

        # 4. PR activity (0-1)
        merged_prs = metrics.get('mergedPRs', {}).get('nodes', [])
        recent_prs = [
            pr for pr in merged_prs
            if pr.get('mergedAt') and
            (now - datetime.fromisoformat(pr['mergedAt'].replace('Z', '+00:00'))).days <= 90
        ]
        pr_activity_score = min(1.0, len(recent_prs) / MCP_THRESHOLDS['healthy_pr_count_90d'])
        components['pr_activity'] = pr_activity_score

        # 5. Commit recency (0-1)
        pushed_at = datetime.fromisoformat(metrics['pushedAt'].replace('Z', '+00:00'))
        days_since_push = (now - pushed_at).days
        commit_recency_score = max(0, 1 - (days_since_push / MCP_THRESHOLDS['recent_commit_days']))
        components['commit_recency'] = min(1.0, commit_recency_score)

        # 6. PR review rate (0-1)
        if recent_prs:
            reviewed_prs = sum(1 for pr in recent_prs if pr.get('reviews', {}).get('totalCount', 0) > 0)
            pr_reviewed_score = reviewed_prs / len(recent_prs)
        else:
            pr_reviewed_score = 0.5  # Neutral if no recent PRs
        components['pr_reviewed'] = pr_reviewed_score

        # 7. PR quality/descriptiveness (0-1)
        if recent_prs:
            quality_prs = sum(
                1 for pr in recent_prs
                if len(pr.get('bodyText', '')) >= MCP_THRESHOLDS['min_pr_description']
            )
            pr_quality_score = quality_prs / len(recent_prs)
        else:
            pr_quality_score = 0.5  # Neutral if no recent PRs
        components['pr_descriptive'] = pr_quality_score

        # 8. Repository cleanliness - no stale PRs/issues (0-1)
        stale_pr_threshold = now - timedelta(days=MCP_THRESHOLDS['stale_pr_days'])
        stale_issue_threshold = now - timedelta(days=MCP_THRESHOLDS['stale_issue_days'])

        open_prs = metrics.get('openPRs', {}).get('nodes', [])
        stale_prs = sum(
            1 for pr in open_prs
            if not pr.get('isDraft') and
            datetime.fromisoformat(pr['createdAt'].replace('Z', '+00:00')) < stale_pr_threshold
        )

        open_issues = metrics.get('openIssues', {}).get('nodes', [])
        stale_issues = sum(
            1 for issue in open_issues
            if datetime.fromisoformat(issue['createdAt'].replace('Z', '+00:00')) < stale_issue_threshold
        )

        # Calculate cleanliness score (penalize for stale items)
        total_stale = stale_prs + stale_issues
        cleanliness_score = max(0, 1 - (total_stale * 0.1))  # -0.1 per stale item
        components['repo_cleanliness'] = cleanliness_score

        # 9. Release recency (0-1)
        releases = metrics.get('releases', {}).get('nodes', [])
        if releases and releases[0].get('publishedAt'):
            last_release = datetime.fromisoformat(releases[0]['publishedAt'].replace('Z', '+00:00'))
            days_since_release = (now - last_release).days
            release_score = max(0, 1 - (days_since_release / MCP_THRESHOLDS['recent_release_days']))
        else:
            release_score = 0.3 if repo_age_days < 90 else 0  # More lenient for new repos
        components['release_recency'] = min(1.0, release_score)

        # 10. Active contributors (0-1)
        commits = metrics.get('defaultBranchRef2', {}).get('target', {}).get('history', {}).get('nodes', [])
        unique_contributors = set()
        for commit in commits:
            author = commit.get('author', {})
            if author.get('user', {}).get('login'):
                unique_contributors.add(author['user']['login'])
            elif author.get('email'):
                unique_contributors.add(author['email'])

        contributor_count = len(unique_contributors)
        contributor_score = min(1.0, contributor_count / MCP_THRESHOLDS['min_contributors'])
        components['contributors'] = contributor_score

        # Store additional metadata
        components['_metadata'] = {
            'repo_age_days': repo_age_days,
            'recent_pr_count': len(recent_prs),
            'stale_pr_count': stale_prs,
            'stale_issue_count': stale_issues,
            'contributor_count': contributor_count,
            'days_since_push': days_since_push,
            'has_releases': len(releases) > 0
        }

        return components

    def _apply_overrides(self, repo_name: str, components: Dict[str, float]) -> Dict[str, float]:
        """Apply manual score overrides from configuration."""
        if repo_name in self.config.get('overrides', {}):
            overrides = self.config['overrides'][repo_name]
            for component, value in overrides.items():
                if component in components and component != '_metadata':
                    old_value = components[component]
                    components[component] = max(0, min(1, value))
                    logger.info(f"Override applied for {repo_name}/{component}: {old_value:.2f} -> {value:.2f}")
        return components

    def _calculate_weighted_score(self, components: Dict[str, float]) -> float:
        """Calculate weighted score from components (0-100)."""
        total_score = 0
        for component, weight in SCORING_WEIGHTS.items():
            score = components.get(component, 0)
            total_score += score * weight * 100
        return total_score

    def _to_fico_scale(self, raw_score: float) -> int:
        """Convert 0-100 score to FICO scale (300-850)."""
        # FICO range is 300-850 (550 point range)
        return round(300 + (raw_score / 100.0) * 550)

    def _error_response(self, owner: str, repo: str, error: str) -> Dict:
        """Generate error response with minimum viable score."""
        return {
            "repository": f"{owner}/{repo}",
            "fico_score": 300,  # Minimum FICO score
            "raw_score": 0,
            "error": error,
            "components": {k: 0 for k in SCORING_WEIGHTS.keys()},
            "metadata": {
                "scored_at": datetime.now(timezone.utc).isoformat(),
                "error": True
            }
        }

    async def score_multiple(self, repositories: List[Tuple[str, str]]) -> List[Dict]:
        """Score multiple repositories concurrently."""
        tasks = [
            self.score_repository(owner, repo)
            for owner, repo in repositories
        ]
        return await asyncio.gather(*tasks)


async def main():
    """Example usage and testing."""
    # Initialize scorer
    scorer = MCPHygieneScorer(config_path="config.yaml")

    # Test repositories (MCP-related)
    test_repos = [
        ("modelcontextprotocol", "servers"),
        ("modelcontextprotocol", "typescript-sdk"),
        ("modelcontextprotocol", "python-sdk"),
    ]

    print("\n" + "="*60)
    print("MCP Repository Hygiene Scoring System")
    print("="*60 + "\n")

    # Score repositories
    for owner, repo in test_repos:
        print(f"\nScoring: {owner}/{repo}")
        print("-" * 40)

        result = await scorer.score_repository(owner, repo)

        if "error" in result:
            print(f"Error: {result['error']}")
            continue

        print(f"FICO Score: {result['fico_score']} (Raw: {result['raw_score']}/100)")
        print("\nComponent Breakdown:")

        for component, score in result['components'].items():
            if component == '_metadata':
                continue
            weight = SCORING_WEIGHTS[component]
            weighted = score * weight * 100
            print(f"  {component:20s}: {score:5.2f} x {weight:.2f} = {weighted:5.2f}")

        if '_metadata' in result['components']:
            meta = result['components']['_metadata']
            print("\nRepository Stats:")
            print(f"  Age: {meta['repo_age_days']} days")
            print(f"  Recent PRs (90d): {meta['recent_pr_count']}")
            print(f"  Stale PRs: {meta['stale_pr_count']}")
            print(f"  Stale Issues: {meta['stale_issue_count']}")
            print(f"  Contributors (90d): {meta['contributor_count']}")
            print(f"  Days since push: {meta['days_since_push']}")
            print(f"  Has releases: {meta['has_releases']}")

    print("\n" + "="*60)
    print("Scoring complete!")
    print("="*60 + "\n")


if __name__ == "__main__":
    asyncio.run(main())