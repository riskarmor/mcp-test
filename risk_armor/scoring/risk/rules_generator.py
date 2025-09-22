#!/usr/bin/env python3
"""
Semgrep Rules Generator for MCP
================================
Generates and manages Semgrep rules for different languages and deployment roles.

Author: Risk Armor
License: Proprietary - All Rights Reserved
"""

import yaml
from pathlib import Path
from typing import Dict, List, Any


class MCPRulesGenerator:
    """Generates Semgrep rules for MCP security analysis.

    This class creates both heuristic rules (for deployment role detection)
    and security rules (for vulnerability detection) tailored to different
    MCP deployment contexts.
    """

    def __init__(self, output_dir: str = None):
        """Initialize rules generator.

        Args:
            output_dir: Directory to save generated rules (defaults to ./rules)
        """
        self.output_dir = Path(output_dir) if output_dir else Path(__file__).parent / 'rules'
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_all_rules(self):
        """Generate all rule files.

        Creates the complete set of Semgrep rules including:
        - Heuristic rules for deployment detection
        - Role-specific security rules
        - Default fallback rules
        """
        # Generate heuristic rules
        self.generate_heuristic_rules()

        # Generate role-specific rules
        self.generate_role_specific_rules()

        print(f"✅ Generated all rules in {self.output_dir}")

    def generate_heuristic_rules(self):
        """Generate heuristic deployment detection rules.

        These rules analyze code patterns to infer the deployment context
        without requiring explicit manifest files.
        """
        # Python heuristics
        self._save_rules('heuristic_python.yaml', self._get_python_heuristic_rules())

        # JavaScript/TypeScript heuristics
        self._save_rules('heuristic_javascript.yaml', self._get_javascript_heuristic_rules())

        # Go heuristics
        self._save_rules('heuristic_go.yaml', self._get_go_heuristic_rules())

    def generate_role_specific_rules(self):
        """Generate role-specific security rules.

        Creates different rule sets tailored to each deployment context,
        with appropriate suppressions for non-applicable security concerns.
        """
        # Trusted-host-only rules
        self._save_rules('trusted_host_rules.yaml', self._get_trusted_host_rules())

        # Standalone rules
        self._save_rules('standalone_rules.yaml', self._get_standalone_rules())

        # Mixed-use rules
        self._save_rules('mixed_use_rules.yaml', self._get_mixed_use_rules())

        # Default/unknown rules
        self._save_rules('default_rules.yaml', self._get_default_rules())

    def _save_rules(self, filename: str, rules: Dict):
        """Save rules to YAML file.

        Args:
            filename: Name of the YAML file to create
            rules: Dictionary containing Semgrep rules
        """
        filepath = self.output_dir / filename
        with open(filepath, 'w') as f:
            yaml.dump(rules, f, default_flow_style=False, sort_keys=False)
        print(f"  📝 Created {filepath}")

    # ================================================================================
    # PYTHON RULES
    # ================================================================================

    def _get_python_heuristic_rules(self) -> Dict:
        """Get Python heuristic detection rules.

        Creates rules that detect deployment context based on Python code patterns:
        - stdio usage indicates trusted-host-only
        - network binding with auth indicates standalone
        - conditional auth indicates mixed-use

        Returns:
            Dictionary of Semgrep rules for Python heuristic detection
        """
        return {
            'rules': [
                # Trusted-host-only detection
                {
                    'id': 'mcp-py-heuristic-trusted-host-only',
                    'message': 'Heuristic: MCP appears to be trusted-host-only (stdio-only, no network/server, no auth detected).',
                    'severity': 'INFO',
                    'languages': ['python'],
                    'patterns': [
                        {'pattern-either': [
                            {'pattern': 'import sys\nsys.stdin'},
                            {'pattern': 'get_stdio_transport()'},
                            {'pattern': '$VAR = MCPServer(stdio=...)'}
                        ]},
                        {'pattern-not': 'app.run(host=...)'},
                        {'pattern-not': 'bind("0.0.0.0", ...)'},
                        {'pattern-not': 'if "Authorization" in ...'}
                    ],
                    'metadata': {
                        'deployment_mode': 'trusted-host-only',
                        'category': 'heuristic'
                    }
                },
                # Standalone detection
                {
                    'id': 'mcp-py-heuristic-standalone',
                    'message': 'Heuristic: MCP runs as a network server with auth (likely standalone).',
                    'severity': 'INFO',
                    'languages': ['python'],
                    'pattern-either': [
                        {'patterns': [
                            {'pattern-either': [
                                {'pattern': 'app.run(host="0.0.0.0")'},
                                {'pattern': 'bind("0.0.0.0", ...)'},
                                {'pattern': 'HTTPServer((\'\', $PORT), $HANDLER)'}
                            ]},
                            {'pattern-either': [
                                {'pattern': 'if "Authorization" in request.headers:'},
                                {'pattern': 'def $FUNC(..., $USER = Depends($AUTH_FUNC)):'},
                                {'pattern': 'if config.security.auth.enabled:'},
                                {'pattern': '@require_auth'}
                            ]}
                        ]}
                    ],
                    'metadata': {
                        'deployment_mode': 'standalone',
                        'category': 'heuristic'
                    }
                },
                # Mixed-use detection
                {
                    'id': 'mcp-py-heuristic-mixed-use',
                    'message': 'Heuristic: MCP supports both trusted-host and public server modes.',
                    'severity': 'INFO',
                    'languages': ['python'],
                    'pattern-either': [
                        {'pattern': 'if os.environ.get("MCP_MODE") == "standalone":\n    $SECURE = True'},
                        {'pattern': 'if config.public_enabled:\n    app.run(host="0.0.0.0")'},
                        {'pattern': 'if $CONFIG.auth.enabled:'}
                    ],
                    'metadata': {
                        'deployment_mode': 'mixed-use',
                        'category': 'heuristic'
                    }
                }
            ]
        }

    def _get_javascript_heuristic_rules(self) -> Dict:
        """Get JavaScript/TypeScript heuristic detection rules.

        Creates rules that detect deployment context based on JS/TS code patterns:
        - readline/stdin usage indicates trusted-host-only
        - Express/HTTP servers with auth indicate standalone
        - Environment-based mode switching indicates mixed-use

        Returns:
            Dictionary of Semgrep rules for JavaScript/TypeScript heuristic detection
        """
        return {
            'rules': [
                # Trusted-host-only detection
                {
                    'id': 'mcp-js-heuristic-trusted-host-only',
                    'message': 'Heuristic: Likely trusted-host-only MCP (stdio, no server, no auth).',
                    'severity': 'INFO',
                    'languages': ['javascript', 'typescript'],
                    'patterns': [
                        {'pattern-either': [
                            {'pattern': 'require(\'readline\')'},
                            {'pattern': 'process.stdin'},
                            {'pattern': 'import readline from \'readline\''}
                        ]},
                        {'pattern-not': 'app.listen($PORT, "0.0.0.0")'},
                        {'pattern-not': 'server.listen($PORT, "0.0.0.0")'},
                        {'pattern-not': 'if (req.headers.authorization)'}
                    ],
                    'metadata': {
                        'deployment_mode': 'trusted-host-only',
                        'category': 'heuristic'
                    }
                },
                # Standalone detection
                {
                    'id': 'mcp-js-heuristic-standalone',
                    'message': 'Heuristic: MCP network server with auth — likely standalone.',
                    'severity': 'INFO',
                    'languages': ['javascript', 'typescript'],
                    'pattern-either': [
                        {'patterns': [
                            {'pattern-either': [
                                {'pattern': 'app.listen($PORT, "0.0.0.0")'},
                                {'pattern': 'server.listen($PORT, "0.0.0.0")'}
                            ]},
                            {'pattern-either': [
                                {'pattern': 'if (req.headers.authorization)'},
                                {'pattern': 'authenticate(...)'},
                                {'pattern': 'apiKey = req.header("X-API-Key")'}
                            ]}
                        ]}
                    ],
                    'metadata': {
                        'deployment_mode': 'standalone',
                        'category': 'heuristic'
                    }
                },
                # Mixed-use detection
                {
                    'id': 'mcp-js-heuristic-mixed-use',
                    'message': 'Heuristic: MCP supports both host and network modes.',
                    'severity': 'INFO',
                    'languages': ['javascript', 'typescript'],
                    'pattern-either': [
                        {'pattern': 'if (process.env.MCP_MODE === "standalone") {\n    app.listen($PORT, "0.0.0.0")\n}'},
                        {'pattern': 'if (config.public) {\n    // ... start network server\n}'},
                        {'pattern': 'if (authEnabled) { app.use(authMiddleware) }'}
                    ],
                    'metadata': {
                        'deployment_mode': 'mixed-use',
                        'category': 'heuristic'
                    }
                }
            ]
        }

    def _get_go_heuristic_rules(self) -> Dict:
        """Get Go heuristic detection rules.

        Creates rules that detect deployment context based on Go code patterns:
        - os.Stdin usage indicates trusted-host-only
        - net.Listen/http.ListenAndServe with auth indicate standalone
        - Conditional server startup indicates mixed-use

        Returns:
            Dictionary of Semgrep rules for Go heuristic detection
        """
        return {
            'rules': [
                # Trusted-host-only detection
                {
                    'id': 'mcp-go-heuristic-trusted-host-only',
                    'message': 'Heuristic: Likely trusted-host-only MCP (stdio, no net.Listener, no auth).',
                    'severity': 'INFO',
                    'languages': ['go'],
                    'patterns': [
                        {'pattern-either': [
                            {'pattern': 'os.Stdin'},
                            {'pattern': 'bufio.NewReader(os.Stdin)'}
                        ]},
                        {'pattern-not': 'net.Listen("tcp", ...)'},
                        {'pattern-not': 'http.ListenAndServe(":$PORT", ...)'},
                        {'pattern-not': 'if req.Header.Get("Authorization") != ""'}
                    ],
                    'metadata': {
                        'deployment_mode': 'trusted-host-only',
                        'category': 'heuristic'
                    }
                },
                # Standalone detection
                {
                    'id': 'mcp-go-heuristic-standalone',
                    'message': 'Heuristic: MCP Go network server — likely standalone.',
                    'severity': 'INFO',
                    'languages': ['go'],
                    'pattern-either': [
                        {'patterns': [
                            {'pattern-either': [
                                {'pattern': 'net.Listen("tcp", "0.0.0.0:$PORT")'},
                                {'pattern': 'http.ListenAndServe(":$PORT", ...)'}
                            ]},
                            {'pattern-either': [
                                {'pattern': 'if req.Header.Get("Authorization") != ""'},
                                {'pattern': 'apiKey := req.Header.Get("X-API-Key")'}
                            ]}
                        ]}
                    ],
                    'metadata': {
                        'deployment_mode': 'standalone',
                        'category': 'heuristic'
                    }
                }
            ]
        }

    # ================================================================================
    # ROLE-SPECIFIC RULES
    # ================================================================================

    def _get_trusted_host_rules(self) -> Dict:
        """Get trusted-host-only security rules.

        Security rules for MCPs that run only on trusted hosts.
        Key concerns: preventing network exposure, ensuring audit logging.

        Returns:
            Dictionary of Semgrep security rules for trusted-host deployments
        """
        return {
            'rules': [
                # Python rules
                {
                    'id': 'mcp-py-host-exposed-binding',
                    'message': 'Plugin binds to public interface despite being trusted-host-only.',
                    'severity': 'ERROR',
                    'languages': ['python'],
                    'pattern-either': [
                        {'pattern': 'app.run(host="0.0.0.0")'},
                        {'pattern': 'server.bind(("0.0.0.0", $PORT))'},
                        {'pattern': 'HTTPServer((\'\', $PORT), $HANDLER)'}
                    ],
                    'metadata': {'category': 'security', 'role': 'trusted-host-only'}
                },
                {
                    'id': 'mcp-py-missing-prompt-logging',
                    'message': 'Prompt or tool invocation not logged for internal audit.',
                    'severity': 'WARNING',
                    'languages': ['python'],
                    'pattern-not-inside': 'logging.info("Prompt" ...)',
                    'metadata': {'category': 'audit', 'role': 'trusted-host-only'}
                },
                # JavaScript rules
                {
                    'id': 'mcp-js-host-exposed-binding',
                    'message': 'Plugin binds to public interface (0.0.0.0) despite being trusted-host-only.',
                    'severity': 'ERROR',
                    'languages': ['javascript', 'typescript'],
                    'pattern-either': [
                        {'pattern': 'app.listen($PORT, "0.0.0.0")'},
                        {'pattern': 'server.listen($PORT, "0.0.0.0")'}
                    ],
                    'metadata': {'category': 'security', 'role': 'trusted-host-only'}
                },
                # Go rules
                {
                    'id': 'mcp-go-host-exposed-binding',
                    'message': 'Trusted-host-only MCP must NOT bind to 0.0.0.0.',
                    'severity': 'ERROR',
                    'languages': ['go'],
                    'pattern-either': [
                        {'pattern': 'net.Listen("tcp", "0.0.0.0:$PORT")'},
                        {'pattern': 'http.ListenAndServe("0.0.0.0:$PORT", ...)'}
                    ],
                    'metadata': {'category': 'security', 'role': 'trusted-host-only'}
                }
            ]
        }

    def _get_standalone_rules(self) -> Dict:
        """Get standalone deployment security rules.

        Security rules for MCPs exposed to public networks.
        Key concerns: authentication, authorization, injection prevention, TLS.

        Returns:
            Dictionary of Semgrep security rules for standalone deployments
        """
        return {
            'rules': [
                # Python rules
                {
                    'id': 'mcp-py-missing-auth',
                    'message': 'Publicly exposed route lacks authentication or RBAC enforcement.',
                    'severity': 'ERROR',
                    'languages': ['python'],
                    'patterns': [
                        {'pattern': '@app.route(...)\ndef $FUNC(...):\n    ...'},
                        {'pattern-not-inside': 'if "Authorization" in request.headers'},
                        {'pattern-not-inside': '@require_auth'}
                    ],
                    'metadata': {'category': 'security', 'role': 'standalone'}
                },
                {
                    'id': 'mcp-py-transport-insecure',
                    'message': 'TLS disabled or not enforced for standalone MCP.',
                    'severity': 'ERROR',
                    'languages': ['python'],
                    'pattern-either': [
                        {'pattern': 'requests.get(..., verify=False)'},
                        {'pattern': 'app.run(ssl_context=None)'},
                        {'pattern': 'client.connect(ssl=False)'}
                    ],
                    'metadata': {'category': 'security', 'role': 'standalone'}
                },
                {
                    'id': 'mcp-py-shell-injection',
                    'message': 'Unvalidated user input used in a shell/system command.',
                    'severity': 'ERROR',
                    'languages': ['python'],
                    'pattern-either': [
                        {'pattern': 'subprocess.call($USER_INPUT, shell=True)'},
                        {'pattern': 'os.system($USER_INPUT)'}
                    ],
                    'metadata': {'category': 'injection', 'role': 'standalone'}
                },
                # JavaScript rules
                {
                    'id': 'mcp-js-missing-auth',
                    'message': 'Public route lacks authentication (missing RBAC/enforcement).',
                    'severity': 'ERROR',
                    'languages': ['javascript', 'typescript'],
                    'patterns': [
                        {'pattern': 'app.$METHOD($ROUTE, $HANDLER)'},
                        {'pattern-not-inside': 'if (req.headers.authorization)'},
                        {'pattern-not-inside': 'authenticate(...)'},
                        {'pattern-not-inside': 'authorize(...)'}
                    ],
                    'metadata': {'category': 'security', 'role': 'standalone'}
                },
                {
                    'id': 'mcp-js-shell-injection',
                    'message': 'Untrusted input passed to exec/spawn/shell.',
                    'severity': 'ERROR',
                    'languages': ['javascript', 'typescript'],
                    'pattern-either': [
                        {'pattern': 'child_process.exec($USER_INPUT)'},
                        {'pattern': 'child_process.execSync($USER_INPUT)'},
                        {'pattern': 'require(\'child_process\').spawn($USER_INPUT)'}
                    ],
                    'metadata': {'category': 'injection', 'role': 'standalone'}
                },
                # Go rules
                {
                    'id': 'mcp-go-missing-auth',
                    'message': 'Exposed HTTP handler lacks authentication/RBAC.',
                    'severity': 'ERROR',
                    'languages': ['go'],
                    'patterns': [
                        {'pattern': 'func $HANDLER(w http.ResponseWriter, r *http.Request) {\n    ...\n}'},
                        {'pattern-not-inside': 'if r.Header.Get("Authorization") != ""'}
                    ],
                    'metadata': {'category': 'security', 'role': 'standalone'}
                },
                {
                    'id': 'mcp-go-shell-injection',
                    'message': 'Untrusted input is passed to shell/exec.Command.',
                    'severity': 'ERROR',
                    'languages': ['go'],
                    'pattern-either': [
                        {'pattern': 'exec.Command($USER_INPUT)'},
                        {'pattern': 'exec.CommandContext($CTX, $USER_INPUT)'}
                    ],
                    'metadata': {'category': 'injection', 'role': 'standalone'}
                }
            ]
        }

    def _get_mixed_use_rules(self) -> Dict:
        """Get mixed-use deployment security rules.

        Security rules for MCPs that can operate in both trusted and public modes.
        Key concern: ensuring proper conditional security based on deployment mode.

        Returns:
            Dictionary of Semgrep security rules for mixed-use deployments
        """
        return {
            'rules': [
                # Python rules
                {
                    'id': 'mcp-py-conditional-auth-missing',
                    'message': 'MCP server supports public access but lacks mode-check-based authentication.',
                    'severity': 'ERROR',
                    'languages': ['python'],
                    'patterns': [
                        {'pattern': '@app.route(...)\ndef $FUNC(...):\n    ...'},
                        {'pattern-not-inside': 'if os.environ.get("MCP_MODE") == "standalone":\n    if "Authorization" in request.headers:'}
                    ],
                    'metadata': {'category': 'security', 'role': 'mixed-use'}
                },
                # JavaScript rules
                {
                    'id': 'mcp-js-conditional-auth-missing',
                    'message': 'Conditional (mode-based) authentication missing for mixed-use MCP.',
                    'severity': 'ERROR',
                    'languages': ['javascript', 'typescript'],
                    'patterns': [
                        {'pattern': 'app.$METHOD($ROUTE, $HANDLER)'},
                        {'pattern-not-inside': 'if (process.env.MCP_MODE === "standalone" && req.headers.authorization)'}
                    ],
                    'metadata': {'category': 'security', 'role': 'mixed-use'}
                },
                # Go rules
                {
                    'id': 'mcp-go-conditional-auth-missing',
                    'message': 'Conditional auth missing for standalone mode.',
                    'severity': 'ERROR',
                    'languages': ['go'],
                    'patterns': [
                        {'pattern': 'func $HANDLER(w http.ResponseWriter, r *http.Request) {\n    ...\n}'},
                        {'pattern-not-inside': 'if os.Getenv("MCP_MODE") == "standalone" && r.Header.Get("Authorization") != ""'}
                    ],
                    'metadata': {'category': 'security', 'role': 'mixed-use'}
                }
            ]
        }

    def _get_default_rules(self) -> Dict:
        """Get default/unknown deployment security rules.

        Conservative security rules applied when deployment context cannot be determined.
        Assumes worst-case scenario and applies strictest security requirements.

        Returns:
            Dictionary of Semgrep security rules for unknown deployments
        """
        return {
            'rules': [
                # Apply conservative defaults for all languages
                {
                    'id': 'mcp-py-insecure-default-binding',
                    'message': 'No role detected and app exposed to 0.0.0.0 — deny by policy.',
                    'severity': 'ERROR',
                    'languages': ['python'],
                    'pattern': 'app.run(host="0.0.0.0")',
                    'metadata': {'category': 'security', 'role': 'unknown'}
                },
                {
                    'id': 'mcp-js-insecure-default-binding',
                    'message': 'No role detected and app exposed to 0.0.0.0 — blocked by policy.',
                    'severity': 'ERROR',
                    'languages': ['javascript', 'typescript'],
                    'pattern-either': [
                        {'pattern': 'app.listen($PORT, "0.0.0.0")'},
                        {'pattern': 'server.listen($PORT, "0.0.0.0")'}
                    ],
                    'metadata': {'category': 'security', 'role': 'unknown'}
                },
                {
                    'id': 'mcp-go-insecure-default-binding',
                    'message': 'No role detected and server binds to public interface.',
                    'severity': 'ERROR',
                    'languages': ['go'],
                    'pattern-either': [
                        {'pattern': 'http.ListenAndServe("0.0.0.0:$PORT", ...)'},
                        {'pattern': 'net.Listen("tcp", "0.0.0.0:$PORT")'}
                    ],
                    'metadata': {'category': 'security', 'role': 'unknown'}
                }
            ]
        }


def main():
    """Generate all Semgrep rules.

    Entry point for rule generation. Creates all necessary Semgrep rule files
    for MCP security analysis across different languages and deployment contexts.
    """
    generator = MCPRulesGenerator()
    generator.generate_all_rules()


if __name__ == "__main__":
    main()