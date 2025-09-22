#!/usr/bin/env python3
"""
MCP Security Report Generator
==============================
Generates comprehensive security reports from MCP scan results.
Supports multiple output formats: HTML, Markdown, JSON, and CSV.

Based on FICO scoring model (300-850) with detailed findings,
remediation guidance, and trend analysis.

Author: MCP Security Scanner
Version: 2.0
"""

import json
import csv
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import asdict
import html


class ReportGenerator:
    """
    Generates security reports in multiple formats from scan results.

    Features:
    - Multiple output formats (HTML, Markdown, JSON, CSV)
    - Detailed findings with remediation guidance
    - Score interpretation and trend analysis
    - Executive summaries and technical details
    - Compliance mapping to security standards
    """

    # FICO score interpretation thresholds
    SCORE_RANGES = {
        "Excellent": (800, 850),
        "Very Good": (740, 799),
        "Good": (670, 739),
        "Fair": (580, 669),
        "Poor": (300, 579)
    }

    # Remediation priority based on severity
    REMEDIATION_PRIORITY = {
        "critical": 1,
        "high": 2,
        "medium": 3,
        "low": 4,
        "info": 5
    }

    def __init__(self, output_dir: Optional[Path] = None):
        """
        Initialize the report generator.

        Args:
            output_dir: Directory for saving generated reports
        """
        self.output_dir = output_dir or Path.cwd() / "reports"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(
        self,
        score_data: Dict[str, Any],
        format: str = "html",
        include_suppressed: bool = False
    ) -> str:
        """
        Generate a security report in the specified format.

        Args:
            score_data: SecurityScore data dictionary
            format: Output format (html/markdown/json/csv)
            include_suppressed: Whether to include suppressed findings

        Returns:
            Path to the generated report file
        """
        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        repo_name = score_data.get("repository", "unknown").replace("/", "_")
        filename = f"mcp_security_report_{repo_name}_{timestamp}.{format}"
        filepath = self.output_dir / filename

        # Generate report based on format
        if format == "html":
            content = self._generate_html_report(score_data, include_suppressed)
        elif format == "markdown":
            content = self._generate_markdown_report(score_data, include_suppressed)
        elif format == "json":
            content = self._generate_json_report(score_data)
        elif format == "csv":
            self._generate_csv_report(score_data, filepath)
            return str(filepath)
        else:
            raise ValueError(f"Unsupported format: {format}")

        # Write report to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

        return str(filepath)

    def _generate_html_report(self, data: Dict, include_suppressed: bool) -> str:
        """
        Generate an HTML report with styling and interactivity.

        Features rich formatting, charts, and interactive elements.
        """
        # Get score interpretation
        score = data["fico_score"]
        grade = data["grade"]
        interpretation = self._get_score_interpretation(score)

        # Build HTML report
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP Security Report - {html.escape(data['repository'])}</title>
    <style>
        /* Modern, professional styling */
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}

        /* Header with gradient */
        .header {{
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}

        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 300;
        }}

        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
        }}

        /* Score display card */
        .score-card {{
            background: white;
            margin: -30px 40px 40px;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-around;
            align-items: center;
        }}

        .score-display {{
            text-align: center;
        }}

        .score-number {{
            font-size: 4em;
            font-weight: bold;
            background: {self._get_score_color_gradient(score)};
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}

        .score-label {{
            font-size: 1.2em;
            color: #666;
            margin-top: 10px;
        }}

        .grade {{
            font-size: 3em;
            font-weight: bold;
            color: {self._get_grade_color(grade)};
        }}

        /* Main content area */
        .content {{
            padding: 40px;
        }}

        .section {{
            margin-bottom: 40px;
        }}

        .section-title {{
            font-size: 1.8em;
            color: #2c3e50;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #ecf0f1;
        }}

        /* Statistics grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}

        .stat-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            transition: transform 0.3s;
        }}

        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }}

        .stat-value {{
            font-size: 2em;
            font-weight: bold;
            color: #2c3e50;
        }}

        .stat-label {{
            color: #7f8c8d;
            margin-top: 5px;
        }}

        /* Severity breakdown */
        .severity-breakdown {{
            display: flex;
            justify-content: space-around;
            margin: 30px 0;
        }}

        .severity-item {{
            text-align: center;
            padding: 15px;
        }}

        .severity-count {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }}

        .severity-critical {{ color: #e74c3c; }}
        .severity-high {{ color: #e67e22; }}
        .severity-medium {{ color: #f39c12; }}
        .severity-low {{ color: #3498db; }}
        .severity-info {{ color: #95a5a6; }}

        /* Findings table */
        .findings-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}

        .findings-table th {{
            background: #34495e;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: normal;
        }}

        .findings-table td {{
            padding: 15px;
            border-bottom: 1px solid #ecf0f1;
        }}

        .findings-table tr:hover {{
            background: #f8f9fa;
        }}

        /* Badges */
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 500;
        }}

        .badge-critical {{
            background: #e74c3c;
            color: white;
        }}

        .badge-high {{
            background: #e67e22;
            color: white;
        }}

        .badge-medium {{
            background: #f39c12;
            color: white;
        }}

        .badge-low {{
            background: #3498db;
            color: white;
        }}

        .badge-info {{
            background: #95a5a6;
            color: white;
        }}

        .badge-mcp {{
            background: #9b59b6;
            color: white;
        }}

        /* Remediation section */
        .remediation-card {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 20px;
            margin: 20px 0;
            border-radius: 4px;
        }}

        .remediation-title {{
            font-weight: bold;
            color: #856404;
            margin-bottom: 10px;
        }}

        /* Footer */
        .footer {{
            background: #2c3e50;
            color: white;
            padding: 20px;
            text-align: center;
            font-size: 0.9em;
        }}

        /* Responsive design */
        @media (max-width: 768px) {{
            .score-card {{
                flex-direction: column;
            }}

            .stats-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🔒 MCP Security Report</h1>
            <div class="subtitle">{html.escape(data['repository'])}</div>
            <div class="subtitle">Generated: {data['scored_at']}</div>
        </div>

        <!-- Score Card -->
        <div class="score-card">
            <div class="score-display">
                <div class="score-number">{score}</div>
                <div class="score-label">FICO Score</div>
            </div>
            <div class="score-display">
                <div class="grade">{grade.split(' - ')[0]}</div>
                <div class="score-label">Security Grade</div>
            </div>
            <div class="score-display">
                <div style="font-size: 1.5em; color: #7f8c8d;">
                    {interpretation}
                </div>
                <div class="score-label">Assessment</div>
            </div>
        </div>

        <!-- Main Content -->
        <div class="content">
            <!-- Executive Summary -->
            <div class="section">
                <h2 class="section-title">📊 Executive Summary</h2>
                <p style="font-size: 1.1em; line-height: 1.8;">
                    The repository <strong>{html.escape(data['repository'])}</strong> has been analyzed
                    for security vulnerabilities using MCP-specific and general security rules.
                    The scan detected <strong>{data['finding_count']} active security issues</strong>
                    across the codebase, resulting in a FICO security score of <strong>{score}</strong>.
                </p>
                {self._generate_executive_insights_html(data)}
            </div>

            <!-- Deployment Context -->
            <div class="section">
                <h2 class="section-title">🚀 Deployment Context</h2>
                <p>
                    Detected Mode: <strong>{data['deployment_mode']}</strong>
                </p>
                <p style="margin-top: 10px; color: #666;">
                    {self._get_deployment_mode_description(data['deployment_mode'])}
                </p>
                {f'<p style="margin-top: 10px;">Suppressed Findings: <strong>{data["suppressed_count"]}</strong> (not relevant for this deployment mode)</p>' if data['suppressed_count'] > 0 else ''}
            </div>

            <!-- Statistics -->
            <div class="section">
                <h2 class="section-title">📈 Security Metrics</h2>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-value">{data['finding_count']}</div>
                        <div class="stat-label">Total Findings</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{data['mcp_finding_count']}</div>
                        <div class="stat-label">MCP-Specific</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{data['raw_deduction']}</div>
                        <div class="stat-label">Points Deducted</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{data.get('metadata', {}).get('language', 'auto')}</div>
                        <div class="stat-label">Language</div>
                    </div>
                </div>

                <!-- Severity Breakdown -->
                <h3 style="margin-top: 30px; margin-bottom: 20px;">Severity Distribution</h3>
                <div class="severity-breakdown">
                    {self._generate_severity_breakdown_html(data['severity_counts'])}
                </div>
            </div>

            <!-- Top Findings -->
            <div class="section">
                <h2 class="section-title">⚠️ Security Findings</h2>
                {self._generate_findings_table_html(data.get('findings', [])[:20])}
            </div>

            <!-- Remediation Guidance -->
            <div class="section">
                <h2 class="section-title">🔧 Remediation Guidance</h2>
                {self._generate_remediation_html(data)}
            </div>

            <!-- Compliance Mapping -->
            <div class="section">
                <h2 class="section-title">📋 Compliance Mapping</h2>
                {self._generate_compliance_html(data)}
            </div>
        </div>

        <!-- Footer -->
        <div class="footer">
            <p>MCP Security Scanner v2.0 | FICO Scoring Model</p>
            <p>Based on MCP Security Review specifications</p>
            <p style="margin-top: 10px; opacity: 0.8;">
                Report generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </p>
        </div>
    </div>
</body>
</html>
"""
        return html_content

    def _generate_markdown_report(self, data: Dict, include_suppressed: bool) -> str:
        """
        Generate a Markdown report for documentation and version control.

        Suitable for README files and documentation systems.
        """
        score = data["fico_score"]
        grade = data["grade"]
        interpretation = self._get_score_interpretation(score)

        md_content = f"""# MCP Security Report

## Repository: {data['repository']}

**Generated:** {data['scored_at']}
**Deployment Mode:** {data['deployment_mode']}
**Language:** {data.get('metadata', {}).get('language', 'auto')}

---

## 📊 Security Score

### FICO Score: **{score}** / 850

**Grade:** {grade}
**Assessment:** {interpretation}

---

## 📈 Summary Statistics

| Metric | Value |
|--------|-------|
| Total Findings | {data['finding_count']} |
| MCP-Specific | {data['mcp_finding_count']} |
| Suppressed | {data['suppressed_count']} |
| Points Deducted | {data['raw_deduction']} |

### Severity Breakdown

| Severity | Count |
|----------|-------|
| Critical | {data['severity_counts'].get('critical', 0)} |
| High | {data['severity_counts'].get('high', 0)} |
| Medium | {data['severity_counts'].get('medium', 0)} |
| Low | {data['severity_counts'].get('low', 0)} |
| Info | {data['severity_counts'].get('info', 0)} |

---

## ⚠️ Top Security Findings

"""

        # Add top findings
        if data.get('findings'):
            for i, finding in enumerate(data['findings'][:10], 1):
                md_content += f"""
### {i}. [{finding['severity'].upper()}] {finding['rule_id']}

**Message:** {finding['message']}
**Location:** `{finding['file_path']}:{finding['line_start']}`
**MCP-Specific:** {'Yes' if finding.get('is_mcp_specific') else 'No'}

"""

        # Add remediation guidance
        md_content += """
---

## 🔧 Remediation Priorities

Based on the findings, here are the recommended remediation priorities:

"""
        md_content += self._generate_remediation_priorities_markdown(data)

        # Add compliance section
        md_content += """
---

## 📋 Compliance Status

"""
        md_content += self._generate_compliance_markdown(data)

        # Add footer
        md_content += f"""
---

*Report generated by MCP Security Scanner v2.0*
*FICO Scoring Model (300-850 range)*
*Based on MCP Security Review specifications*
"""

        return md_content

    def _generate_json_report(self, data: Dict) -> str:
        """
        Generate a JSON report for programmatic processing.

        Includes all data for integration with other tools.
        """
        # Enhance with additional metadata
        report_data = {
            "metadata": {
                "report_version": "2.0",
                "generated_at": datetime.now().isoformat(),
                "scoring_model": "FICO",
                "score_range": {"min": 300, "max": 850}
            },
            "summary": {
                "repository": data["repository"],
                "deployment_mode": data["deployment_mode"],
                "fico_score": data["fico_score"],
                "grade": data["grade"],
                "interpretation": self._get_score_interpretation(data["fico_score"])
            },
            "statistics": {
                "total_findings": data["finding_count"],
                "mcp_specific": data["mcp_finding_count"],
                "suppressed": data["suppressed_count"],
                "raw_deduction": data["raw_deduction"],
                "severity_counts": data["severity_counts"]
            },
            "findings": data.get("findings", []),
            "suppressed_findings": data.get("suppressed_findings", []) if "suppressed_findings" in data else [],
            "scan_metadata": data.get("metadata", {})
        }

        return json.dumps(report_data, indent=2, default=str)

    def _generate_csv_report(self, data: Dict, filepath: Path):
        """
        Generate a CSV report for spreadsheet analysis.

        Creates a findings-focused CSV for easy filtering and sorting.
        """
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            fieldnames = [
                'severity', 'rule_id', 'message', 'file_path', 'line',
                'is_mcp_specific', 'deployment_context', 'status'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            # Write active findings
            for finding in data.get('findings', []):
                writer.writerow({
                    'severity': finding['severity'],
                    'rule_id': finding['rule_id'],
                    'message': finding['message'],
                    'file_path': finding['file_path'],
                    'line': finding['line_start'],
                    'is_mcp_specific': 'Yes' if finding.get('is_mcp_specific') else 'No',
                    'deployment_context': finding.get('deployment_context', ''),
                    'status': 'Active'
                })

            # Write suppressed findings if requested
            for finding in data.get('suppressed_findings', []):
                writer.writerow({
                    'severity': finding['severity'],
                    'rule_id': finding['rule_id'],
                    'message': finding['message'],
                    'file_path': finding['file_path'],
                    'line': finding['line_start'],
                    'is_mcp_specific': 'Yes' if finding.get('is_mcp_specific') else 'No',
                    'deployment_context': finding.get('deployment_context', ''),
                    'status': 'Suppressed'
                })

    # ================================================================================
    # HELPER METHODS
    # ================================================================================

    def _get_score_interpretation(self, score: int) -> str:
        """Get human-readable interpretation of FICO score."""
        if score >= 800:
            return "Excellent - Production-ready security posture"
        elif score >= 740:
            return "Very Good - Strong security with minor issues"
        elif score >= 670:
            return "Good - Adequate security, some improvements needed"
        elif score >= 580:
            return "Fair - Moderate security concerns requiring attention"
        else:
            return "Poor - Significant security issues requiring immediate action"

    def _get_score_color_gradient(self, score: int) -> str:
        """Get color gradient for score display."""
        if score >= 800:
            return "linear-gradient(135deg, #00b09b, #96c93d)"
        elif score >= 670:
            return "linear-gradient(135deg, #f2994a, #f2c94c)"
        elif score >= 580:
            return "linear-gradient(135deg, #f39c12, #e67e22)"
        else:
            return "linear-gradient(135deg, #eb3349, #f45c43)"

    def _get_grade_color(self, grade: str) -> str:
        """Get color for grade display."""
        if "A" in grade:
            return "#27ae60"
        elif "B" in grade:
            return "#3498db"
        elif "C" in grade:
            return "#f39c12"
        else:
            return "#e74c3c"

    def _get_deployment_mode_description(self, mode: str) -> str:
        """Get description of deployment mode."""
        descriptions = {
            "trusted-host-only": "Runs only on trusted hosts with stdio transport, minimal network exposure",
            "standalone": "Network-accessible service with full authentication and security requirements",
            "mixed-use": "Supports both trusted and standalone modes via configuration",
            "trusted-host-only-unconfirmed": "Appears to be trusted-host but requires confirmation",
            "unknown": "Deployment mode could not be determined, applying strictest security rules"
        }
        return descriptions.get(mode, "Unknown deployment mode")

    def _generate_executive_insights_html(self, data: Dict) -> str:
        """Generate executive insights for HTML report."""
        insights = []

        # Critical/High finding insight
        critical_high = data['severity_counts'].get('critical', 0) + data['severity_counts'].get('high', 0)
        if critical_high > 0:
            insights.append(f"⚠️ <strong>{critical_high} critical/high severity issues</strong> require immediate attention")

        # MCP-specific insight
        if data['mcp_finding_count'] > 0:
            insights.append(f"🔍 <strong>{data['mcp_finding_count']} MCP-specific violations</strong> affect protocol compliance")

        # Suppressed findings insight
        if data['suppressed_count'] > 0:
            insights.append(f"✓ <strong>{data['suppressed_count']} findings suppressed</strong> based on deployment context")

        if not insights:
            insights.append("✓ No critical security issues detected")

        html = "<div style='margin-top: 20px;'><ul style='line-height: 2;'>"
        for insight in insights:
            html += f"<li>{insight}</li>"
        html += "</ul></div>"

        return html

    def _generate_severity_breakdown_html(self, counts: Dict) -> str:
        """Generate severity breakdown HTML."""
        severities = ['critical', 'high', 'medium', 'low', 'info']
        html = ""

        for severity in severities:
            count = counts.get(severity, 0)
            html += f"""
            <div class="severity-item">
                <div class="severity-count severity-{severity}">{count}</div>
                <div style="text-transform: uppercase; font-size: 0.9em;">{severity}</div>
            </div>
            """

        return html

    def _generate_findings_table_html(self, findings: List[Dict]) -> str:
        """Generate findings table HTML."""
        if not findings:
            return "<p>No security findings detected.</p>"

        html = """
        <table class="findings-table">
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Rule ID</th>
                    <th>Message</th>
                    <th>Location</th>
                    <th>Type</th>
                </tr>
            </thead>
            <tbody>
        """

        for finding in findings:
            severity = finding['severity']
            is_mcp = finding.get('is_mcp_specific', False)

            html += f"""
            <tr>
                <td><span class="badge badge-{severity}">{severity.upper()}</span></td>
                <td><code>{html.escape(finding['rule_id'])}</code></td>
                <td>{html.escape(finding['message'])}</td>
                <td><code>{html.escape(finding['file_path'])}:{finding['line_start']}</code></td>
                <td>
                    {f'<span class="badge badge-mcp">MCP</span>' if is_mcp else '<span class="badge" style="background: #ecf0f1; color: #7f8c8d;">General</span>'}
                </td>
            </tr>
            """

        html += """
            </tbody>
        </table>
        """

        return html

    def _generate_remediation_html(self, data: Dict) -> str:
        """Generate remediation guidance HTML."""
        html = """
        <div class="remediation-card">
            <div class="remediation-title">Priority Actions</div>
            <ol style="margin-left: 20px; line-height: 1.8;">
        """

        # Priority 1: Critical findings
        critical_count = data['severity_counts'].get('critical', 0)
        if critical_count > 0:
            html += f"<li><strong>Fix {critical_count} critical issues immediately</strong> - These pose immediate security risks</li>"

        # Priority 2: High findings
        high_count = data['severity_counts'].get('high', 0)
        if high_count > 0:
            html += f"<li><strong>Address {high_count} high severity issues</strong> - These are serious vulnerabilities</li>"

        # Priority 3: MCP-specific
        if data['mcp_finding_count'] > 0:
            html += f"<li><strong>Review {data['mcp_finding_count']} MCP-specific findings</strong> - Critical for protocol compliance</li>"

        # Priority 4: Medium findings
        medium_count = data['severity_counts'].get('medium', 0)
        if medium_count > 0:
            html += f"<li>Plan remediation for {medium_count} medium severity issues</li>"

        html += """
            </ol>
        </div>

        <h3 style="margin-top: 30px;">Recommended Tools</h3>
        <ul style="line-height: 1.8;">
            <li>Use <code>semgrep --autofix</code> for automated fixes where available</li>
            <li>Run <code>mcp_security_scanner.py</code> after fixes to verify improvements</li>
            <li>Consider implementing pre-commit hooks for continuous security checking</li>
        </ul>
        """

        return html

    def _generate_compliance_html(self, data: Dict) -> str:
        """Generate compliance mapping HTML."""
        html = """
        <table class="findings-table">
            <thead>
                <tr>
                    <th>Standard</th>
                    <th>Requirement</th>
                    <th>Status</th>
                    <th>Findings</th>
                </tr>
            </thead>
            <tbody>
        """

        # Map findings to compliance standards
        compliance_mapping = {
            "OWASP Top 10": {
                "A01:2021 - Broken Access Control": data['severity_counts'].get('critical', 0) + data['severity_counts'].get('high', 0),
                "A02:2021 - Cryptographic Failures": 0,  # Would need specific rule mapping
                "A03:2021 - Injection": 0,  # Would need specific rule mapping
            },
            "CWE Top 25": {
                "CWE-306: Missing Authentication": 0,  # Would need specific rule mapping
                "CWE-502: Deserialization": 0,  # Would need specific rule mapping
            },
            "MCP Protocol": {
                "Authentication Required": data['mcp_finding_count'],
                "Transport Security": 0,  # Would need specific rule mapping
                "Origin Validation": 0,  # Would need specific rule mapping
            }
        }

        for standard, requirements in compliance_mapping.items():
            for requirement, count in requirements.items():
                status = "✓ Pass" if count == 0 else f"⚠️ {count} issues"
                status_color = "#27ae60" if count == 0 else "#e74c3c"

                html += f"""
                <tr>
                    <td><strong>{standard}</strong></td>
                    <td>{requirement}</td>
                    <td style="color: {status_color};">{status}</td>
                    <td>{count}</td>
                </tr>
                """

        html += """
            </tbody>
        </table>
        """

        return html

    def _generate_remediation_priorities_markdown(self, data: Dict) -> str:
        """Generate remediation priorities for Markdown."""
        priorities = []

        critical = data['severity_counts'].get('critical', 0)
        high = data['severity_counts'].get('high', 0)
        medium = data['severity_counts'].get('medium', 0)

        if critical > 0:
            priorities.append(f"1. **Critical Issues ({critical})** - Fix immediately")
        if high > 0:
            priorities.append(f"2. **High Severity ({high})** - Address within 24-48 hours")
        if data['mcp_finding_count'] > 0:
            priorities.append(f"3. **MCP-Specific ({data['mcp_finding_count']})** - Required for protocol compliance")
        if medium > 0:
            priorities.append(f"4. **Medium Severity ({medium})** - Plan for next release")

        return "\n".join(priorities) if priorities else "No immediate remediation required."

    def _generate_compliance_markdown(self, data: Dict) -> str:
        """Generate compliance section for Markdown."""
        score = data['fico_score']

        compliance = []
        compliance.append(f"- **MCP Protocol Compliance:** {'✓ Pass' if data['mcp_finding_count'] == 0 else f'⚠️ {data[\"mcp_finding_count\"]} violations'}")
        compliance.append(f"- **Production Readiness:** {'✓ Ready' if score >= 670 else '⚠️ Not Ready'}")
        compliance.append(f"- **Security Baseline:** {'✓ Met' if score >= 580 else '❌ Not Met'}")

        return "\n".join(compliance)


# ================================================================================
# MAIN ENTRY POINT
# ================================================================================

def main():
    """
    Example usage of the Report Generator.
    """
    # Sample data (would come from actual scanner)
    sample_data = {
        "repository": "example-mcp-server",
        "deployment_mode": "standalone",
        "fico_score": 725,
        "grade": "B - Good",
        "raw_deduction": 125,
        "finding_count": 15,
        "suppressed_count": 3,
        "severity_counts": {
            "critical": 1,
            "high": 2,
            "medium": 5,
            "low": 7,
            "info": 0
        },
        "mcp_finding_count": 8,
        "scored_at": datetime.now().isoformat(),
        "metadata": {
            "language": "python",
            "scan_version": "2.0"
        },
        "findings": [
            {
                "rule_id": "mcp-py-missing-auth",
                "severity": "high",
                "message": "MCP endpoint lacks authentication",
                "file_path": "server.py",
                "line_start": 42,
                "is_mcp_specific": True
            }
        ]
    }

    # Generate reports
    generator = ReportGenerator()

    # Generate HTML report
    html_path = generator.generate_report(sample_data, format="html")
    print(f"HTML report generated: {html_path}")

    # Generate Markdown report
    md_path = generator.generate_report(sample_data, format="markdown")
    print(f"Markdown report generated: {md_path}")

    # Generate JSON report
    json_path = generator.generate_report(sample_data, format="json")
    print(f"JSON report generated: {json_path}")


if __name__ == "__main__":
    main()