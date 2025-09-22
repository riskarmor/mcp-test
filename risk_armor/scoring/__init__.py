#!/usr/bin/env python3
"""
Risk Armor Scoring Modules
==========================

Three-pillar scoring system for comprehensive repository security analysis:

Pillars:
1. Hygiene: Repository health, maintenance quality, and best practices
2. Risk: Security vulnerability detection with role-aware analysis
3. Vulnerability: CVE and dependency vulnerability scanning (future)

Each pillar produces FICO-style scores (300-850) that can be combined
for an overall security assessment.

Author: Risk Armor
License: Proprietary - All Rights Reserved
"""

from .hygiene.hygiene_scorer import MCPHygieneScorer
from .risk.semgrep_scorer import MCPSemgrepScorer

__all__ = ['MCPHygieneScorer', 'MCPSemgrepScorer']