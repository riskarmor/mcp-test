"""
Score Aggregator
================
Combines three-pillar scores into final FICO-style security score.

Author: MCP Security Team
"""

from typing import Dict, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class SecurityScore:
    """Container for three-pillar security scores."""
    hygiene_score: int
    tools_score: int
    vulnerability_score: int
    final_score: int  # FICO-style 300-850

    def to_dict(self) -> Dict:
        return {
            'hygiene_score': self.hygiene_score,
            'tools_score': self.tools_score,
            'vulnerability_score': self.vulnerability_score,
            'final_score': self.final_score
        }


class ScoreAggregator:
    """
    Aggregates three-pillar scores into final security score.

    Default weights (security-focused):
    - Hygiene: 25%
    - Tools: 35%
    - Vulnerability: 40%
    """

    DEFAULT_WEIGHTS = {
        'hygiene': 0.25,
        'tools': 0.35,
        'vulnerability': 0.40
    }

    def __init__(self, weights: Optional[Dict[str, float]] = None):
        """Initialize aggregator with custom or default weights."""
        self.weights = weights or self.DEFAULT_WEIGHTS
        self._validate_weights()

    def _validate_weights(self):
        """Ensure weights sum to 1.0."""
        total = sum(self.weights.values())
        if abs(total - 1.0) > 0.001:
            logger.warning(f"Weights sum to {total}, normalizing...")
            for key in self.weights:
                self.weights[key] = self.weights[key] / total

    def aggregate(self, hygiene: int, tools: int, vulnerability: int) -> SecurityScore:
        """
        Aggregate three FICO scores into final weighted score.

        This method takes the three component scores and combines them using
        configurable weights to produce a final security score. The weighting
        reflects the relative importance of each security aspect:
        - Hygiene (25%): Repository health and maintenance
        - Tools (35%): Code issues and secrets found by scanners
        - Vulnerability (40%): Known CVEs and their age

        The calculation process:
        1. Validate input scores are in FICO range (300-850)
        2. Normalize each score to 0-1 range
        3. Apply weights and calculate weighted average
        4. Convert back to FICO scale

        Args:
            hygiene: Hygiene FICO score (300-850) from GitHub metrics
            tools: Tools FICO score (300-850) from Semgrep + TruffleHog
            vulnerability: Vulnerability FICO score (300-850) from OSV

        Returns:
            SecurityScore object containing all component scores and final score
        """
        # Validate input scores are in FICO range
        for score, name in [(hygiene, 'hygiene'), (tools, 'tools'), (vulnerability, 'vulnerability')]:
            if not 300 <= score <= 850:
                logger.warning(f"{name} score {score} outside FICO range, clamping")
                score = max(300, min(850, score))

        # Normalize FICO scores to 0-1 range
        hygiene_norm = (hygiene - 300) / 550
        tools_norm = (tools - 300) / 550
        vulnerability_norm = (vulnerability - 300) / 550

        # Calculate weighted average
        final_norm = (
            hygiene_norm * self.weights['hygiene'] +
            tools_norm * self.weights['tools'] +
            vulnerability_norm * self.weights['vulnerability']
        )

        # Convert back to FICO scale
        final_score = round(300 + final_norm * 550)

        return SecurityScore(
            hygiene_score=hygiene,
            tools_score=tools,
            vulnerability_score=vulnerability,
            final_score=final_score
        )

    def aggregate_scores(self, scores: Dict[str, int]) -> int:
        """
        Aggregate scores from dictionary format (compatibility method for main.py).

        This is a convenience wrapper around the aggregate() method that accepts
        scores in dictionary format, making it easier to integrate with the main
        orchestrator which collects scores from different sources.

        Args:
            scores: Dictionary containing component scores:
                - 'hygiene': Hygiene FICO score (300-850)
                - 'tools': Tools FICO score (300-850)
                - 'vulnerability': Vulnerability FICO score (300-850)

        Returns:
            Final FICO score as integer (300-850 range)

        Example:
            >>> agg = ScoreAggregator()
            >>> scores = {'hygiene': 750, 'tools': 650, 'vulnerability': 600}
            >>> final_score = agg.aggregate_scores(scores)
            >>> print(final_score)  # 655 (weighted average)
        """
        result = self.aggregate(
            hygiene=scores.get('hygiene', 600),
            tools=scores.get('tools', 600),
            vulnerability=scores.get('vulnerability', 600)
        )
        return result.final_score