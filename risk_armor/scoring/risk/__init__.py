#!/usr/bin/env python3
"""
Risk Scoring Module - MCP Security Analysis
============================================

Provides comprehensive security risk scoring for MCP repositories using
Semgrep-based static analysis with role-aware detection and FICO-style scoring.

Key Features:
- Heuristic deployment role detection (no manifest files required)
- Role-aware security rule application
- FICO-style scoring (300-850 range)
- MCP-specific vulnerability weighting
- Multi-language support (Python, JavaScript/TypeScript, Go)

Author: Risk Armor
License: Proprietary - All Rights Reserved
"""

from .semgrep_scorer import MCPSemgrepScorer, SemgrepFinding, SecurityScore

__all__ = ['MCPSemgrepScorer', 'SemgrepFinding', 'SecurityScore']