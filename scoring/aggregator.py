"""
Score Aggregator
================
Combines three-pillar scores into final FICO-style security score.

Author: Risk Armor
License: Proprietary - All Rights Reserved
"""

from typing import Dict, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class SecurityScore:
    """Container for three-pillar security scores."""
    hygiene_score: float
    risk_score: float
    vulnerability_score: float
    final_score: int  # FICO-style 300-850

    def to_dict(self) -> Dict:
        return {
            'hygiene_score': self.hygiene_score,
            'risk_score': self.risk_score,
            'vulnerability_score': self.vulnerability_score,
            'final_score': self.final_score
        }


class ScoreAggregator:
    """
    Aggregates three-pillar scores into final security score.

    Default weights:
    - Hygiene: 30%
    - Risk: 40%
    - Vulnerability: 30%
    """

    DEFAULT_WEIGHTS = {
        'hygiene': 0.30,
        'risk': 0.40,
        'vulnerability': 0.30
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

    def aggregate(self, hygiene: int, risk: int, vulnerability: int) -> SecurityScore:
        """
        Aggregate three FICO scores into final score.

        Args:
            hygiene: Hygiene FICO score (300-850)
            risk: Risk FICO score (300-850)
            vulnerability: Vulnerability FICO score (300-850)

        Returns:
            SecurityScore object with all scores
        """
        # Normalize FICO scores to 0-1 range
        hygiene_norm = (hygiene - 300) / 550
        risk_norm = (risk - 300) / 550
        vulnerability_norm = (vulnerability - 300) / 550

        # Calculate weighted average
        final_norm = (
            hygiene_norm * self.weights['hygiene'] +
            risk_norm * self.weights['risk'] +
            vulnerability_norm * self.weights['vulnerability']
        )

        # Convert back to FICO scale
        final_score = round(300 + final_norm * 550)

        return SecurityScore(
            hygiene_score=hygiene,
            risk_score=risk,
            vulnerability_score=vulnerability,
            final_score=final_score
        )