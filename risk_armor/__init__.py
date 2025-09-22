#!/usr/bin/env python3
"""
Risk Armor Security Analysis Platform
======================================

Comprehensive three-pillar security analysis platform for MCP repositories:

1. Hygiene Scoring: Repository health and maintenance quality
2. Risk Scoring: Security vulnerability detection with role-aware analysis
3. Vulnerability Scoring: (Future) CVE and dependency vulnerability analysis

The platform provides FICO-style scoring (300-850) with MCP-specific weightings
and role-aware security requirements based on deployment context.

Author: Risk Armor
License: Proprietary - All Rights Reserved
"""

__version__ = "2.0.0"
__author__ = "Risk Armor"

from risk_armor.scoring.hygiene.hygiene_scorer import MCPHygieneScorer
from risk_armor.scoring.risk.semgrep_scorer import MCPSemgrepScorer

__all__ = ['MCPHygieneScorer', 'MCPSemgrepScorer']