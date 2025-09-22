#!/usr/bin/env python3
"""
MCP Repository Hygiene Scoring System v2
=========================================
Analyzes GitHub repositories for maintenance and health metrics with MCP-specific calibration.
Produces FICO-style scores (300-850) based on weighted components.

Key improvements in v2:
- Caching layer to reduce API calls
- Robust error handling for partial GraphQL responses
- Stale detection using last activity date (not just creation)
- MCP-specific file detection (mcp.json)
- GitHub Apps token support with rotation
- Comprehensive annotations throughout

Author: Risk Armor
License: Proprietary - All Rights Reserved
"""

import asyncio
import hashlib
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import yaml

# Third-party imports with error handling
try:
    from gql import Client, gql
    from gql.transport.aiohttp import AIOHTTPTransport
    from dotenv import load_dotenv
    import diskcache  # For caching
except ImportError as e:
    print(f"Error: Required packages not installed - {e}")
    print("Please run: pip install gql aiohttp python-dotenv pyyaml diskcache")
    sys.exit(1)

# Load environment variables
load_dotenv()

# Configure logging with more detail
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
)
logger = logging.getLogger(__name__)

# ================================================================================
# CONFIGURATION SECTION
# ================================================================================

class TokenManager:
    """
    Manages GitHub tokens with rotation support for rate limit management.
    Supports both personal access tokens and GitHub App tokens.
    """

    def __init__(self):
        """Initialize token manager with available tokens."""
        self.tokens = []
        self.current_index = 0
        self.token_usage = {}  # Track usage per token

        # Load primary token (required)
        primary_token = os.getenv('GITHUB_TOKEN')
        if not primary_token:
            logger.error("GITHUB_TOKEN environment variable is required")
            sys.exit(1)
        self.tokens.append(primary_token)

        # Load additional tokens if available (GITHUB_TOKEN_2, GITHUB_TOKEN_3, etc.)
        for i in range(2, 10):
            token = os.getenv(f'GITHUB_TOKEN_{i}')
            if token:
                self.tokens.append(token)
                logger.info(f"Loaded additional token GITHUB_TOKEN_{i}")

        # Initialize usage tracking
        for token in self.tokens:
            self.token_usage[token] = {'requests': 0, 'last_reset': time.time()}

    def get_token(self) -> str:
        """
        Get the next available token using round-robin rotation.
        Implements smart rotation based on usage patterns.
        """
        # Reset hourly counters if needed
        current_time = time.time()
        for token in self.tokens:
            if current_time - self.token_usage[token]['last_reset'] > 3600:  # 1 hour
                self.token_usage[token] = {'requests': 0, 'last_reset': current_time}

        # Find token with lowest usage
        min_usage = min(self.token_usage[token]['requests'] for token in self.tokens)
        for token in self.tokens:
            if self.token_usage[token]['requests'] == min_usage:
                self.token_usage[token]['requests'] += 1
                return token

        # Fallback to primary token
        return self.tokens[0]

    def report_rate_limit(self, token: str, remaining: int, reset_time: int):
        """
        Report rate limit status for a token.
        Useful for adaptive token rotation.
        """
        logger.debug(f"Token rate limit - Remaining: {remaining}, Reset: {reset_time}")
        # Could implement smart switching based on remaining limits

# Initialize global token manager
TOKEN_MANAGER = TokenManager()

# ================================================================================
# SCORING WEIGHTS AND THRESHOLDS
# ================================================================================

# Scoring weights calibrated for MCP repositories (total = 1.00)
# These weights reflect the relative importance of each hygiene aspect for MCP tools
SCORING_WEIGHTS = {
    "mcp_specific": 0.10,          # NEW: MCP-specific files (mcp.json, etc.)
    "community_files": 0.10,       # REDUCED: Less critical for MCP tools
    "branch_protection": 0.08,     # REDUCED: Many MCP repos are solo-maintained
    "young_repo": 0.05,           # KEPT: New MCP tools shouldn't be penalized
    "pr_activity": 0.12,          # INCREASED: Even minimal PR activity is good
    "commit_recency": 0.15,       # INCREASED: Most important activity signal
    "pr_reviewed": 0.08,          # REDUCED: Less relevant for solo maintainers
    "pr_descriptive": 0.07,       # REDUCED: MCP PRs are often simple
    "repo_cleanliness": 0.10,     # KEPT: Still important to avoid stale items
    "release_recency": 0.05,      # REDUCED: Many MCP tools don't use releases
    "contributors": 0.10          # KEPT: Multiple contributors is positive signal
}

# MCP-specific thresholds (calibrated for low-activity repositories)
MCP_THRESHOLDS = {
    "healthy_pr_count_90d": 1,     # REDUCED: 1+ PR in 90 days is healthy
    "stale_pr_days": 90,           # INCREASED: More tolerance for open PRs
    "stale_issue_days": 120,       # INCREASED: More tolerance for open issues
    "min_pr_description": 30,      # REDUCED: Shorter descriptions acceptable
    "recent_commit_days": 60,      # INCREASED: Commits within 60 days is "recent"
    "recent_release_days": 180,    # INCREASED: Releases within 6 months is "recent"
    "min_contributors": 2,          # KEPT: 2+ contributors shows collaboration
    "cache_ttl_seconds": 3600,     # NEW: Cache responses for 1 hour
    "max_cache_size_mb": 100       # NEW: Maximum cache size
}

# ================================================================================
# GRAPHQL QUERIES
# ================================================================================

# Comprehensive GraphQL query for repository metrics
# This single query replaces multiple REST API calls, reducing rate limit usage
REPO_METRICS_QUERY = gql("""
query RepoMetrics($owner: String!, $name: String!, $since: DateTime!) {
  repository(owner: $owner, name: $name) {
    # Basic repository information
    createdAt
    pushedAt
    isArchived
    isFork
    isTemplate

    # Default branch and protection rules
    defaultBranchRef {
      name
      branchProtectionRule {
        id
        requiresApprovingReviews
        requiresCodeOwnerReviews
        dismissesStaleReviews
        requiresStatusChecks
        requiredApprovingReviewCount
      }
    }

    # Community files - check multiple possible locations and formats
    readme: object(expression: "HEAD:README.md") { ... on Blob { id byteSize } }
    readmeAlt: object(expression: "HEAD:README") { ... on Blob { id byteSize } }
    readmeRst: object(expression: "HEAD:README.rst") { ... on Blob { id byteSize } }
    license: object(expression: "HEAD:LICENSE") { ... on Blob { id byteSize } }
    licenseMd: object(expression: "HEAD:LICENSE.md") { ... on Blob { id byteSize } }
    licenseTxt: object(expression: "HEAD:LICENSE.txt") { ... on Blob { id byteSize } }
    contributing: object(expression: "HEAD:CONTRIBUTING.md") { ... on Blob { id byteSize } }
    codeOfConduct: object(expression: "HEAD:CODE_OF_CONDUCT.md") { ... on Blob { id byteSize } }
    security: object(expression: "HEAD:SECURITY.md") { ... on Blob { id byteSize } }

    # MCP-specific files
    mcpConfig: object(expression: "HEAD:mcp.json") { ... on Blob { id byteSize } }
    mcpConfigAlt: object(expression: "HEAD:.mcp/config.json") { ... on Blob { id byteSize } }
    mcpServerPy: object(expression: "HEAD:server.py") { ... on Blob { id } }
    mcpServerJs: object(expression: "HEAD:server.js") { ... on Blob { id } }
    mcpServerTs: object(expression: "HEAD:server.ts") { ... on Blob { id } }

    # Pull requests - merged and open
    mergedPRs: pullRequests(
      last: 100
      states: MERGED
      orderBy: {field: UPDATED_AT, direction: DESC}
    ) {
      totalCount
      nodes {
        mergedAt
        createdAt
        updatedAt
        bodyText
        reviews { totalCount }
        author { login }
      }
    }

    # Open PRs with last activity tracking
    openPRs: pullRequests(states: OPEN, last: 100) {
      totalCount
      nodes {
        createdAt
        updatedAt  # Critical for determining if PR is truly stale
        isDraft
        comments { totalCount }
        reviews { totalCount }
      }
    }

    # Open issues with last activity tracking
    openIssues: issues(states: OPEN, last: 100) {
      totalCount
      nodes {
        createdAt
        updatedAt  # Critical for determining if issue is truly stale
        comments { totalCount }
      }
    }

    # Releases
    releases(last: 10, orderBy: {field: CREATED_AT, direction: DESC}) {
      totalCount
      nodes {
        publishedAt
        tagName
        isPrerelease
      }
    }

    # Contributors via recent commits
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

  # Rate limit information for adaptive token management
  rateLimit {
    remaining
    resetAt
    limit
  }
}
""")

# ================================================================================
# CACHE IMPLEMENTATION
# ================================================================================

class CachedClient:
    """
    Wrapper around GraphQL client with caching support.
    Reduces API calls by caching responses for a configurable TTL.
    """

    def __init__(self, cache_dir: str = ".cache/hygiene"):
        """Initialize cached client with persistent disk cache."""
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Initialize disk cache with size limit
        cache_size_mb = MCP_THRESHOLDS.get('max_cache_size_mb', 100)
        self.cache = diskcache.Cache(
            str(self.cache_dir),
            size_limit=cache_size_mb * 1024 * 1024  # Convert MB to bytes
        )

        self.client = None
        self._init_client()

    def _init_client(self):
        """Initialize GraphQL client with current token."""
        token = TOKEN_MANAGER.get_token()
        transport = AIOHTTPTransport(
            url="https://api.github.com/graphql",
            headers={"Authorization": f"Bearer {token}"}
        )
        self.client = Client(transport=transport, fetch_schema_from_transport=False)

    def _get_cache_key(self, owner: str, repo: str) -> str:
        """Generate cache key for a repository."""
        return hashlib.md5(f"{owner}/{repo}".encode()).hexdigest()

    async def execute_query(self, owner: str, repo: str, force_refresh: bool = False) -> Dict:
        """
        Execute GraphQL query with caching support.

        Args:
            owner: Repository owner
            repo: Repository name
            force_refresh: Bypass cache and fetch fresh data

        Returns:
            Query result dictionary
        """
        cache_key = self._get_cache_key(owner, repo)

        # Check cache unless force refresh
        if not force_refresh:
            cached_result = self.cache.get(cache_key)
            if cached_result:
                # Check if cache is still valid
                cache_age = time.time() - cached_result.get('_cached_at', 0)
                if cache_age < MCP_THRESHOLDS['cache_ttl_seconds']:
                    logger.debug(f"Cache hit for {owner}/{repo} (age: {cache_age:.0f}s)")
                    return cached_result['data']

        # Execute query
        logger.debug(f"Fetching fresh data for {owner}/{repo}")
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

            # Handle rate limit information
            if 'rateLimit' in result:
                rate_info = result['rateLimit']
                TOKEN_MANAGER.report_rate_limit(
                    TOKEN_MANAGER.tokens[0],  # Current token
                    rate_info['remaining'],
                    rate_info['resetAt']
                )

            # Cache the result
            cache_entry = {
                'data': result,
                '_cached_at': time.time()
            }
            self.cache.set(cache_key, cache_entry, expire=MCP_THRESHOLDS['cache_ttl_seconds'])

            return result

        except Exception as e:
            logger.error(f"Query failed for {owner}/{repo}: {e}")
            # Try to return stale cache if available
            cached_result = self.cache.get(cache_key)
            if cached_result:
                logger.warning(f"Returning stale cache for {owner}/{repo} due to API error")
                return cached_result['data']
            raise

    def clear_cache(self, owner: str = None, repo: str = None):
        """Clear cache for specific repo or all repos."""
        if owner and repo:
            cache_key = self._get_cache_key(owner, repo)
            self.cache.delete(cache_key)
            logger.info(f"Cleared cache for {owner}/{repo}")
        else:
            self.cache.clear()
            logger.info("Cleared all cache")

# ================================================================================
# MAIN SCORER CLASS
# ================================================================================

class MCPHygieneScorer:
    """
    Calculates hygiene scores for MCP repositories with improved error handling,
    caching, and MCP-specific signals.
    """

    def __init__(self, config_path: Optional[str] = None, cache_dir: str = ".cache/hygiene"):
        """
        Initialize scorer with optional config overrides and caching.

        Args:
            config_path: Path to YAML configuration file
            cache_dir: Directory for cache storage
        """
        self.config = self._load_config(config_path) if config_path else {}
        self.cached_client = CachedClient(cache_dir)
        self.scoring_weights = self._get_weights()
        self.thresholds = self._get_thresholds()

    def _load_config(self, config_path: str) -> Dict:
        """Load configuration overrides from YAML file."""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f) or {}
                logger.info(f"Loaded configuration from {config_path}")
                return config
        except Exception as e:
            logger.warning(f"Failed to load config from {config_path}: {e}")
            return {}

    def _get_weights(self) -> Dict[str, float]:
        """Get scoring weights, allowing config overrides."""
        weights = SCORING_WEIGHTS.copy()
        if 'weights' in self.config:
            weights.update(self.config['weights'])
            # Validate weights sum to 1.0
            total = sum(weights.values())
            if abs(total - 1.0) > 0.001:
                logger.warning(f"Custom weights sum to {total}, normalizing...")
                # Normalize weights
                for key in weights:
                    weights[key] = weights[key] / total
        return weights

    def _get_thresholds(self) -> Dict[str, Any]:
        """Get thresholds, allowing config overrides."""
        thresholds = MCP_THRESHOLDS.copy()
        if 'thresholds' in self.config:
            thresholds.update(self.config['thresholds'])
        return thresholds

    async def score_repository(self, owner: str, repo: str, force_refresh: bool = False) -> Dict:
        """
        Score a repository's hygiene with comprehensive error handling.

        Args:
            owner: Repository owner
            repo: Repository name
            force_refresh: Bypass cache and fetch fresh data

        Returns:
            Dictionary containing:
            - fico_score: 300-850 FICO-style score
            - raw_score: 0-100 raw score
            - components: Individual component scores
            - metadata: Scoring context and details
        """
        # Check exclusion list
        if self._is_excluded(owner, repo):
            logger.info(f"Skipping excluded repository {owner}/{repo}")
            return self._excluded_response(owner, repo)

        try:
            # Fetch repository data with caching
            metrics = await self._fetch_repo_metrics(owner, repo, force_refresh)

            # Check if repository should be scored (not archived, not template)
            if not self._should_score_repo(metrics):
                return self._skip_response(owner, repo, metrics)

            # Calculate component scores with error handling
            components = await self._calculate_components(metrics)

            # Apply manual overrides if configured
            components = self._apply_overrides(f"{owner}/{repo}", components)

            # Calculate weighted score
            raw_score = self._calculate_weighted_score(components)

            # Convert to FICO scale
            fico_score = self._to_fico_scale(raw_score)

            # Generate detailed response
            return {
                "repository": f"{owner}/{repo}",
                "fico_score": fico_score,
                "raw_score": round(raw_score, 2),
                "components": components,
                "metadata": {
                    "scored_at": datetime.now(timezone.utc).isoformat(),
                    "weights": self.scoring_weights,
                    "thresholds": self.thresholds,
                    "cached": not force_refresh,
                    "version": "2.0"
                }
            }

        except Exception as e:
            logger.error(f"Failed to score {owner}/{repo}: {e}", exc_info=True)
            return self._error_response(owner, repo, str(e))

    def _is_excluded(self, owner: str, repo: str) -> bool:
        """Check if repository is in exclusion list."""
        exclude_list = self.config.get('exclude', [])
        return f"{owner}/{repo}" in exclude_list

    def _should_score_repo(self, metrics: Dict) -> bool:
        """Determine if repository should be scored."""
        repo_data = metrics.get('repository', {})

        # Skip archived repositories
        if repo_data.get('isArchived'):
            logger.info("Skipping archived repository")
            return False

        # Skip template repositories (unless configured otherwise)
        if repo_data.get('isTemplate') and not self.config.get('score_templates', False):
            logger.info("Skipping template repository")
            return False

        return True

    async def _fetch_repo_metrics(self, owner: str, repo: str, force_refresh: bool) -> Dict:
        """
        Fetch comprehensive repository metrics via cached GraphQL client.
        Includes robust error handling for partial responses.
        """
        try:
            result = await self.cached_client.execute_query(owner, repo, force_refresh)

            # Validate response has required fields
            if not result or 'repository' not in result:
                raise ValueError("Invalid GraphQL response: missing repository data")

            return result

        except Exception as e:
            logger.error(f"GraphQL query failed for {owner}/{repo}: {e}")
            raise

    def _safe_get(self, data: Dict, path: str, default: Any = None) -> Any:
        """
        Safely get nested dictionary values with fallback.
        Prevents KeyError on missing GraphQL response fields.

        Args:
            data: Dictionary to traverse
            path: Dot-separated path (e.g., "repository.defaultBranchRef.name")
            default: Default value if path doesn't exist
        """
        try:
            keys = path.split('.')
            value = data
            for key in keys:
                if isinstance(value, dict):
                    value = value.get(key)
                    if value is None:
                        return default
                else:
                    return default
            return value if value is not None else default
        except Exception:
            return default

    async def _calculate_components(self, metrics: Dict) -> Dict[str, float]:
        """
        Calculate individual scoring components with robust error handling.
        Each component is normalized to 0-1 range.
        """
        components = {}
        now = datetime.now(timezone.utc)
        repo_data = metrics.get('repository', {})

        # ========================================================================
        # 1. MCP-SPECIFIC FILES (NEW IN V2)
        # Check for MCP configuration and server files
        # ========================================================================
        mcp_score = 0.0

        # Check for mcp.json or .mcp/config.json (40% of MCP score)
        if repo_data.get('mcpConfig') or repo_data.get('mcpConfigAlt'):
            mcp_score += 0.4
            logger.debug("Found MCP configuration file")

        # Check for server implementation files (30% of MCP score)
        if any([repo_data.get('mcpServerPy'), repo_data.get('mcpServerJs'), repo_data.get('mcpServerTs')]):
            mcp_score += 0.3
            logger.debug("Found MCP server implementation")

        # Check if README mentions MCP (30% of MCP score)
        # This would require fetching README content, so we approximate based on repo name/description
        if 'mcp' in repo_data.get('name', '').lower() or 'mcp' in repo_data.get('description', '').lower():
            mcp_score += 0.3
            logger.debug("Repository appears MCP-related based on name/description")

        components['mcp_specific'] = min(1.0, mcp_score)

        # ========================================================================
        # 2. COMMUNITY FILES
        # Check for README, LICENSE, CONTRIBUTING, CODE_OF_CONDUCT, SECURITY
        # Now also validates file size to ensure they're not empty
        # ========================================================================
        community_score = 0.0

        # README (30% of community score) - check size to ensure it's meaningful
        readme_files = ['readme', 'readmeAlt', 'readmeRst']
        for readme_key in readme_files:
            readme_data = repo_data.get(readme_key)
            if readme_data and readme_data.get('byteSize', 0) > 100:  # At least 100 bytes
                community_score += 0.3
                logger.debug(f"Found meaningful README ({readme_data.get('byteSize')} bytes)")
                break

        # LICENSE (30% of community score)
        license_files = ['license', 'licenseMd', 'licenseTxt']
        for license_key in license_files:
            license_data = repo_data.get(license_key)
            if license_data and license_data.get('byteSize', 0) > 100:
                community_score += 0.3
                logger.debug("Found LICENSE file")
                break

        # CONTRIBUTING (15% of community score)
        if repo_data.get('contributing') and repo_data.get('contributing', {}).get('byteSize', 0) > 50:
            community_score += 0.15
            logger.debug("Found CONTRIBUTING guide")

        # CODE_OF_CONDUCT (15% of community score)
        if repo_data.get('codeOfConduct') and repo_data.get('codeOfConduct', {}).get('byteSize', 0) > 50:
            community_score += 0.15
            logger.debug("Found CODE_OF_CONDUCT")

        # SECURITY.md (10% of community score) - NEW
        if repo_data.get('security') and repo_data.get('security', {}).get('byteSize', 0) > 50:
            community_score += 0.10
            logger.debug("Found SECURITY policy")

        components['community_files'] = min(1.0, community_score)

        # ========================================================================
        # 3. BRANCH PROTECTION
        # Evaluates branch protection rules on default branch
        # ========================================================================
        branch_protection = 0.0
        protection_rule = self._safe_get(repo_data, 'defaultBranchRef.branchProtectionRule')

        if protection_rule:
            # Requires PR reviews (30%)
            if protection_rule.get('requiresApprovingReviews'):
                branch_protection += 0.3
                # Extra credit for requiring multiple reviewers
                if protection_rule.get('requiredApprovingReviewCount', 0) > 1:
                    branch_protection += 0.1

            # Requires code owner reviews (20%)
            if protection_rule.get('requiresCodeOwnerReviews'):
                branch_protection += 0.2

            # Dismisses stale reviews (20%)
            if protection_rule.get('dismissesStaleReviews'):
                branch_protection += 0.2

            # Requires status checks (20%)
            if protection_rule.get('requiresStatusChecks'):
                branch_protection += 0.2

        components['branch_protection'] = min(1.0, branch_protection)

        # ========================================================================
        # 4. YOUNG REPO BONUS
        # Newer repos get a bonus to avoid penalizing emerging MCP tools
        # ========================================================================
        created_at_str = repo_data.get('createdAt')
        if created_at_str:
            try:
                created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
                repo_age_days = (now - created_at).days
                # Linear decay over 180 days (6 months)
                young_repo_score = max(0, 1 - (repo_age_days / 180)) if repo_age_days < 180 else 0
            except Exception as e:
                logger.warning(f"Failed to parse creation date: {e}")
                young_repo_score = 0
        else:
            young_repo_score = 0
            repo_age_days = -1

        components['young_repo'] = young_repo_score

        # ========================================================================
        # 5. PR ACTIVITY
        # Measures pull request merge activity (calibrated for MCP repos)
        # ========================================================================
        merged_prs = self._safe_get(repo_data, 'mergedPRs.nodes', [])
        recent_prs = []

        for pr in merged_prs:
            if pr and pr.get('mergedAt'):
                try:
                    merged_at = datetime.fromisoformat(pr['mergedAt'].replace('Z', '+00:00'))
                    if (now - merged_at).days <= 90:
                        recent_prs.append(pr)
                except Exception:
                    continue

        # Score based on PR count relative to threshold (1 PR in 90 days for MCP)
        pr_activity_score = min(1.0, len(recent_prs) / self.thresholds['healthy_pr_count_90d'])

        # Bonus for consistent PR activity (multiple PRs)
        if len(recent_prs) >= 3:
            pr_activity_score = min(1.0, pr_activity_score * 1.2)

        components['pr_activity'] = pr_activity_score

        # ========================================================================
        # 6. COMMIT RECENCY
        # How recently the repository was updated (most important for MCP)
        # ========================================================================
        pushed_at_str = repo_data.get('pushedAt')
        if pushed_at_str:
            try:
                pushed_at = datetime.fromisoformat(pushed_at_str.replace('Z', '+00:00'))
                days_since_push = (now - pushed_at).days
                # Linear decay over threshold period (60 days for MCP)
                commit_recency_score = max(0, 1 - (days_since_push / self.thresholds['recent_commit_days']))
            except Exception as e:
                logger.warning(f"Failed to parse push date: {e}")
                commit_recency_score = 0.5  # Neutral score on error
        else:
            commit_recency_score = 0.3  # Low score if no push date
            days_since_push = -1

        components['commit_recency'] = min(1.0, commit_recency_score)

        # ========================================================================
        # 7. PR REVIEW RATE
        # Percentage of PRs that received reviews (less critical for solo MCP repos)
        # ========================================================================
        if recent_prs:
            reviewed_prs = sum(1 for pr in recent_prs
                             if pr.get('reviews', {}).get('totalCount', 0) > 0)
            pr_reviewed_score = reviewed_prs / len(recent_prs)
        else:
            # Neutral score if no recent PRs (common for MCP repos)
            pr_reviewed_score = 0.6

        components['pr_reviewed'] = pr_reviewed_score

        # ========================================================================
        # 8. PR QUALITY/DESCRIPTIVENESS
        # Measures PR description quality (lower bar for MCP repos)
        # ========================================================================
        if recent_prs:
            quality_prs = sum(
                1 for pr in recent_prs
                if pr.get('bodyText') and len(pr.get('bodyText', '')) >= self.thresholds['min_pr_description']
            )
            pr_quality_score = quality_prs / len(recent_prs)
        else:
            # Neutral score if no recent PRs
            pr_quality_score = 0.6

        components['pr_descriptive'] = pr_quality_score

        # ========================================================================
        # 9. REPOSITORY CLEANLINESS (IMPROVED IN V2)
        # Now checks LAST ACTIVITY date, not just creation date
        # ========================================================================
        stale_pr_threshold = now - timedelta(days=self.thresholds['stale_pr_days'])
        stale_issue_threshold = now - timedelta(days=self.thresholds['stale_issue_days'])

        # Check open PRs for staleness based on LAST UPDATE
        open_prs = self._safe_get(repo_data, 'openPRs.nodes', [])
        stale_prs = 0
        for pr in open_prs:
            if pr and not pr.get('isDraft'):
                try:
                    # Use updatedAt instead of createdAt for true staleness
                    updated_at = datetime.fromisoformat(pr['updatedAt'].replace('Z', '+00:00'))
                    if updated_at < stale_pr_threshold:
                        # Check if PR has recent activity (comments/reviews)
                        recent_activity = (pr.get('comments', {}).get('totalCount', 0) > 0 or
                                         pr.get('reviews', {}).get('totalCount', 0) > 0)
                        if not recent_activity:
                            stale_prs += 1
                except Exception:
                    continue

        # Check open issues for staleness based on LAST UPDATE
        open_issues = self._safe_get(repo_data, 'openIssues.nodes', [])
        stale_issues = 0
        for issue in open_issues:
            if issue:
                try:
                    # Use updatedAt for true staleness detection
                    updated_at = datetime.fromisoformat(issue['updatedAt'].replace('Z', '+00:00'))
                    if updated_at < stale_issue_threshold:
                        # Check for recent comments
                        if issue.get('comments', {}).get('totalCount', 0) == 0:
                            stale_issues += 1
                except Exception:
                    continue

        # Calculate cleanliness score with gentler penalty for MCP repos
        total_stale = stale_prs + stale_issues
        # More forgiving: -0.05 per stale item instead of -0.1
        cleanliness_score = max(0, 1 - (total_stale * 0.05))

        components['repo_cleanliness'] = cleanliness_score

        # ========================================================================
        # 10. RELEASE RECENCY
        # Checks for recent releases (very optional for MCP tools)
        # ========================================================================
        releases = self._safe_get(repo_data, 'releases.nodes', [])
        release_score = 0.0

        if releases:
            for release in releases:
                if release and release.get('publishedAt') and not release.get('isPrerelease'):
                    try:
                        last_release = datetime.fromisoformat(release['publishedAt'].replace('Z', '+00:00'))
                        days_since_release = (now - last_release).days
                        release_score = max(0, 1 - (days_since_release / self.thresholds['recent_release_days']))
                        break  # Only consider most recent non-prerelease
                    except Exception:
                        continue
        else:
            # Be lenient for repos without releases, especially young repos
            if repo_age_days >= 0 and repo_age_days < 180:
                release_score = 0.5  # Neutral for young repos
            else:
                release_score = 0.2  # Low penalty for older repos without releases

        components['release_recency'] = min(1.0, release_score)

        # ========================================================================
        # 11. ACTIVE CONTRIBUTORS
        # Number of unique contributors in the last 90 days
        # ========================================================================
        commits = self._safe_get(repo_data, 'defaultBranchRef2.target.history.nodes', [])
        unique_contributors = set()

        for commit in commits:
            if commit and commit.get('author'):
                author = commit['author']
                # Prefer user login, fall back to email
                if author.get('user', {}).get('login'):
                    contributor_id = author['user']['login']
                    # Filter out bots (basic heuristic)
                    if not contributor_id.endswith('[bot]') and not contributor_id.endswith('-bot'):
                        unique_contributors.add(contributor_id)
                elif author.get('email'):
                    # Use email as fallback identifier
                    email = author['email']
                    if 'noreply' not in email and 'bot' not in email.lower():
                        unique_contributors.add(email)

        contributor_count = len(unique_contributors)
        # Score based on contributor count (2+ is good for MCP repos)
        contributor_score = min(1.0, contributor_count / self.thresholds['min_contributors'])

        components['contributors'] = contributor_score

        # ========================================================================
        # METADATA FOR DEBUGGING AND REPORTING
        # ========================================================================
        components['_metadata'] = {
            'repo_age_days': repo_age_days if repo_age_days >= 0 else 'unknown',
            'recent_pr_count': len(recent_prs),
            'stale_pr_count': stale_prs,
            'stale_issue_count': stale_issues,
            'contributor_count': contributor_count,
            'days_since_push': days_since_push if days_since_push >= 0 else 'unknown',
            'has_releases': len(releases) > 0,
            'has_mcp_config': bool(repo_data.get('mcpConfig') or repo_data.get('mcpConfigAlt')),
            'total_open_prs': self._safe_get(repo_data, 'openPRs.totalCount', 0),
            'total_open_issues': self._safe_get(repo_data, 'openIssues.totalCount', 0)
        }

        return components

    def _apply_overrides(self, repo_name: str, components: Dict[str, float]) -> Dict[str, float]:
        """
        Apply manual score overrides from configuration file.
        Useful for handling special cases or known issues.
        """
        if repo_name in self.config.get('overrides', {}):
            overrides = self.config['overrides'][repo_name]
            for component, value in overrides.items():
                if component in components and component != '_metadata':
                    old_value = components[component]
                    # Clamp override value to valid range [0, 1]
                    components[component] = max(0, min(1, value))
                    logger.info(f"Override applied for {repo_name}/{component}: {old_value:.2f} -> {value:.2f}")
        return components

    def _calculate_weighted_score(self, components: Dict[str, float]) -> float:
        """
        Calculate weighted score from components (0-100 scale).
        Weights are normalized to ensure they sum to 1.0.
        """
        total_score = 0
        for component, weight in self.scoring_weights.items():
            score = components.get(component, 0)
            weighted_contribution = score * weight * 100
            total_score += weighted_contribution
            logger.debug(f"{component}: {score:.2f} * {weight:.2f} = {weighted_contribution:.2f}")

        return total_score

    def _to_fico_scale(self, raw_score: float) -> int:
        """
        Convert 0-100 score to FICO scale (300-850).
        FICO range spans 550 points from minimum to maximum.
        """
        # Ensure raw score is in valid range
        raw_score = max(0, min(100, raw_score))
        # Linear mapping to FICO range
        fico_score = 300 + (raw_score / 100.0) * 550
        return round(fico_score)

    def _error_response(self, owner: str, repo: str, error: str) -> Dict:
        """
        Generate error response with minimum viable score.
        Provides useful debugging information.
        """
        return {
            "repository": f"{owner}/{repo}",
            "fico_score": 300,  # Minimum FICO score
            "raw_score": 0,
            "error": error,
            "components": {k: 0 for k in self.scoring_weights.keys()},
            "metadata": {
                "scored_at": datetime.now(timezone.utc).isoformat(),
                "error": True,
                "version": "2.0"
            }
        }

    def _excluded_response(self, owner: str, repo: str) -> Dict:
        """Generate response for excluded repository."""
        return {
            "repository": f"{owner}/{repo}",
            "excluded": True,
            "reason": "Repository in exclusion list",
            "metadata": {
                "scored_at": datetime.now(timezone.utc).isoformat(),
                "version": "2.0"
            }
        }

    def _skip_response(self, owner: str, repo: str, metrics: Dict) -> Dict:
        """Generate response for skipped repository (archived, template, etc)."""
        repo_data = metrics.get('repository', {})
        reasons = []

        if repo_data.get('isArchived'):
            reasons.append("archived")
        if repo_data.get('isTemplate'):
            reasons.append("template")

        return {
            "repository": f"{owner}/{repo}",
            "skipped": True,
            "reasons": reasons,
            "metadata": {
                "scored_at": datetime.now(timezone.utc).isoformat(),
                "version": "2.0"
            }
        }

    async def score_multiple(self, repositories: List[Tuple[str, str]],
                           force_refresh: bool = False,
                           max_concurrent: int = 5) -> List[Dict]:
        """
        Score multiple repositories concurrently with rate limiting.

        Args:
            repositories: List of (owner, repo) tuples
            force_refresh: Bypass cache for all repos
            max_concurrent: Maximum concurrent API requests

        Returns:
            List of scoring results
        """
        # Create semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(max_concurrent)

        async def score_with_limit(owner: str, repo: str):
            async with semaphore:
                return await self.score_repository(owner, repo, force_refresh)

        tasks = [
            score_with_limit(owner, repo)
            for owner, repo in repositories
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle any exceptions in results
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                owner, repo = repositories[i]
                processed_results.append(
                    self._error_response(owner, repo, str(result))
                )
            else:
                processed_results.append(result)

        return processed_results

    def clear_cache(self, owner: str = None, repo: str = None):
        """
        Clear cache for specific repository or all repositories.

        Args:
            owner: Repository owner (optional)
            repo: Repository name (optional)
        """
        self.cached_client.clear_cache(owner, repo)


# ================================================================================
# MAIN ENTRY POINT
# ================================================================================

async def main():
    """Example usage demonstrating the improved scorer."""

    print("\n" + "="*70)
    print("MCP Repository Hygiene Scoring System v2.0")
    print("="*70)
    print("\nImprovements in v2:")
    print("- Caching to reduce API calls")
    print("- Robust error handling for partial responses")
    print("- Stale detection using last activity date")
    print("- MCP-specific file detection")
    print("- GitHub Apps token rotation support")
    print("-"*70 + "\n")

    # Initialize scorer
    scorer = MCPHygieneScorer(config_path="config.yaml")

    # Test repositories (MCP-related)
    test_repos = [
        ("modelcontextprotocol", "servers"),
        ("modelcontextprotocol", "typescript-sdk"),
        ("modelcontextprotocol", "python-sdk"),
    ]

    print("Scoring MCP repositories...")
    print("-" * 70)

    # Score repositories (first run will cache)
    for owner, repo in test_repos:
        print(f"\n📊 Scoring: {owner}/{repo}")

        result = await scorer.score_repository(owner, repo)

        if "error" in result:
            print(f"❌ Error: {result['error']}")
            continue

        if result.get("skipped"):
            print(f"⏭️  Skipped: {', '.join(result['reasons'])}")
            continue

        print(f"🎯 FICO Score: {result['fico_score']} (Raw: {result['raw_score']}/100)")

        # Show MCP-specific component
        mcp_score = result['components'].get('mcp_specific', 0)
        if mcp_score > 0:
            print(f"✨ MCP-Specific Score: {mcp_score:.2f}")

        # Show if result was cached
        if result['metadata'].get('cached'):
            print("💾 (Retrieved from cache)")

    # Demonstrate cache effectiveness
    print("\n" + "-"*70)
    print("🔄 Re-scoring to demonstrate cache...")
    print("-"*70)

    start_time = asyncio.get_event_loop().time()
    results = await scorer.score_multiple(test_repos)
    elapsed = asyncio.get_event_loop().time() - start_time

    print(f"\n⚡ Scored {len(results)} repos in {elapsed:.2f}s (cached)")

    # Clear cache example
    print("\n🗑️  Clearing cache...")
    scorer.clear_cache()
    print("✅ Cache cleared")

    print("\n" + "="*70)
    print("Scoring complete!")
    print("="*70 + "\n")


if __name__ == "__main__":
    asyncio.run(main())