"""
OSV Scanner Tool
================
Scans Software Bill of Materials (SBOM) files for known vulnerabilities using the OSV database.

This is a standalone tool that consumes SBOM files (CycloneDX or SPDX format) and identifies
vulnerabilities with detailed metadata including CVSS scores, age, and exploit availability.

Author: MCP Security Team
"""

import asyncio
import json
import logging
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum
import hashlib

logger = logging.getLogger(__name__)


class VulnerabilitySeverity(Enum):
    """Vulnerability severity levels based on CVSS scores."""
    CRITICAL = "critical"  # 9.0-10.0
    HIGH = "high"          # 7.0-8.9
    MEDIUM = "medium"      # 4.0-6.9
    LOW = "low"            # 0.1-3.9
    UNKNOWN = "unknown"    # No CVSS score


@dataclass
class VulnerabilityFinding:
    """Individual vulnerability finding from OSV scan."""
    package_name: str
    current_version: str
    fixed_version: Optional[str]
    cve_id: str
    cvss_score: float
    severity: VulnerabilitySeverity
    published_date: datetime
    ecosystem: str
    description: str
    age_days: int  # Days since vulnerability was published
    is_kev: bool  # Is in CISA Known Exploited Vulnerabilities
    exploit_available: bool
    references: List[str] = field(default_factory=list)
    affected_functions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'package_name': self.package_name,
            'current_version': self.current_version,
            'fixed_version': self.fixed_version,
            'cve_id': self.cve_id,
            'cvss_score': self.cvss_score,
            'severity': self.severity.value,
            'published_date': self.published_date.isoformat(),
            'ecosystem': self.ecosystem,
            'description': self.description,
            'age_days': self.age_days,
            'is_kev': self.is_kev,
            'exploit_available': self.exploit_available,
            'references': self.references,
            'affected_functions': self.affected_functions
        }


@dataclass
class OSVScanResult:
    """Result of OSV vulnerability scanning."""
    sbom_path: str
    scan_date: datetime
    vulnerabilities: List[VulnerabilityFinding]
    total_packages: int
    vulnerable_packages: int
    scan_duration: float
    severity_counts: Dict[str, int]
    success: bool
    error_message: Optional[str] = None
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'sbom_path': self.sbom_path,
            'scan_date': self.scan_date.isoformat(),
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'total_packages': self.total_packages,
            'vulnerable_packages': self.vulnerable_packages,
            'scan_duration': self.scan_duration,
            'severity_counts': self.severity_counts,
            'success': self.success,
            'error_message': self.error_message,
            'metadata': self.metadata
        }


class OSVScanner:
    """
    OSV Scanner for vulnerability detection in SBOM files.

    Consumes SBOM files and queries the OSV database for known vulnerabilities,
    enriching results with CVSS scores, age, and exploit availability.
    """

    # CISA Known Exploited Vulnerabilities catalog URL
    KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    # Local database path for offline mode
    DEFAULT_LOCAL_DB = Path.home() / ".osv" / "database"

    def __init__(self,
                 offline_mode: bool = False,
                 local_db_path: Optional[Path] = None,
                 check_kev: bool = True,
                 min_cvss: float = 0.0,
                 cache_dir: Optional[Path] = None,
                 cache_ttl_hours: int = 24):
        """
        Initialize OSV Scanner.

        Args:
            offline_mode: Use local OSV database instead of API
            local_db_path: Path to local OSV database
            check_kev: Check CISA Known Exploited Vulnerabilities
            min_cvss: Minimum CVSS score to report
            cache_dir: Directory for caching scan results
            cache_ttl_hours: Cache time-to-live in hours
        """
        self.offline_mode = offline_mode
        self.local_db_path = local_db_path or self.DEFAULT_LOCAL_DB
        self.check_kev = check_kev
        self.min_cvss = min_cvss
        self.cache_dir = cache_dir or Path(".cache/osv")
        self.cache_ttl = timedelta(hours=cache_ttl_hours)

        # Create cache directory
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Load KEV catalog if enabled
        self.kev_cves = set()
        if self.check_kev:
            self._load_kev_catalog()

        # Verify OSV scanner is installed
        self._verify_osv_installed()

    def _verify_osv_installed(self):
        """Verify that OSV scanner is installed."""
        try:
            result = subprocess.run(
                ["osv-scanner", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode != 0:
                raise RuntimeError("osv-scanner is not properly installed")

        except FileNotFoundError:
            raise RuntimeError(
                "osv-scanner is not installed. "
                "Install with: go install github.com/google/osv-scanner/cmd/osv-scanner@latest "
                "or download from: https://github.com/google/osv-scanner/releases"
            )

    def _load_kev_catalog(self):
        """Load CISA Known Exploited Vulnerabilities catalog."""
        try:
            import urllib.request

            cache_file = self.cache_dir / "kev_catalog.json"

            # Check cache
            if cache_file.exists():
                age = datetime.now() - datetime.fromtimestamp(cache_file.stat().st_mtime)
                if age < timedelta(days=1):
                    with open(cache_file, 'r') as f:
                        data = json.load(f)
                        self.kev_cves = {v.get('cveID') for v in data.get('vulnerabilities', [])}
                        logger.info(f"Loaded {len(self.kev_cves)} KEV entries from cache")
                        return

            # Download fresh catalog
            with urllib.request.urlopen(self.KEV_CATALOG_URL) as response:
                data = json.loads(response.read())

            # Extract CVE IDs
            self.kev_cves = {v.get('cveID') for v in data.get('vulnerabilities', [])}

            # Cache for next time
            with open(cache_file, 'w') as f:
                json.dump(data, f)

            logger.info(f"Loaded {len(self.kev_cves)} KEV entries")

        except Exception as e:
            logger.warning(f"Could not load KEV catalog: {e}")
            self.kev_cves = set()

    def _get_cache_path(self, sbom_path: Path) -> Path:
        """Get cache file path for SBOM scan results."""
        sbom_hash = hashlib.md5(str(sbom_path).encode()).hexdigest()
        cache_file = self.cache_dir / f"osv_{sbom_hash}.json"
        return cache_file

    def _is_cache_valid(self, cache_path: Path) -> bool:
        """Check if cached results are still valid."""
        if not cache_path.exists():
            return False

        cache_age = datetime.now() - datetime.fromtimestamp(cache_path.stat().st_mtime)
        return cache_age < self.cache_ttl

    async def scan_sbom(self, sbom_path: str) -> OSVScanResult:
        """
        Scan SBOM file for vulnerabilities.

        Args:
            sbom_path: Path to SBOM file (CycloneDX or SPDX format)

        Returns:
            OSVScanResult with vulnerability findings
        """
        sbom_path = Path(sbom_path).resolve()

        # Check cache
        cache_path = self._get_cache_path(sbom_path)
        if self._is_cache_valid(cache_path):
            logger.info(f"Using cached OSV results for {sbom_path}")
            with open(cache_path, 'r') as f:
                cached_data = json.load(f)
                # Reconstruct result from cache
                result = OSVScanResult(
                    sbom_path=cached_data['sbom_path'],
                    scan_date=datetime.fromisoformat(cached_data['scan_date']),
                    vulnerabilities=[self._dict_to_finding(v) for v in cached_data['vulnerabilities']],
                    total_packages=cached_data['total_packages'],
                    vulnerable_packages=cached_data['vulnerable_packages'],
                    scan_duration=cached_data['scan_duration'],
                    severity_counts=cached_data['severity_counts'],
                    success=cached_data['success'],
                    error_message=cached_data.get('error_message'),
                    metadata=cached_data.get('metadata', {})
                )
                return result

        start_time = datetime.now()

        # Count total packages in SBOM
        total_packages = self._count_packages_in_sbom(sbom_path)

        # Run OSV scanner
        osv_output = await self._run_osv_scanner(sbom_path)

        if not osv_output['success']:
            return OSVScanResult(
                sbom_path=str(sbom_path),
                scan_date=datetime.now(),
                vulnerabilities=[],
                total_packages=total_packages,
                vulnerable_packages=0,
                scan_duration=(datetime.now() - start_time).total_seconds(),
                severity_counts={},
                success=False,
                error_message=osv_output.get('error')
            )

        # Parse OSV output
        vulnerabilities = self._parse_osv_output(osv_output['output'])

        # Filter by minimum CVSS
        vulnerabilities = [v for v in vulnerabilities if v.cvss_score >= self.min_cvss]

        # Count severity levels
        severity_counts = self._count_severities(vulnerabilities)

        # Count unique vulnerable packages
        vulnerable_packages = len(set(v.package_name for v in vulnerabilities))

        # Create result
        result = OSVScanResult(
            sbom_path=str(sbom_path),
            scan_date=datetime.now(),
            vulnerabilities=vulnerabilities,
            total_packages=total_packages,
            vulnerable_packages=vulnerable_packages,
            scan_duration=(datetime.now() - start_time).total_seconds(),
            severity_counts=severity_counts,
            success=True,
            metadata={
                'offline_mode': self.offline_mode,
                'kev_checked': self.check_kev,
                'min_cvss': self.min_cvss
            }
        )

        # Cache result
        with open(cache_path, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)

        return result

    def _dict_to_finding(self, d: Dict) -> VulnerabilityFinding:
        """Convert dictionary to VulnerabilityFinding."""
        return VulnerabilityFinding(
            package_name=d['package_name'],
            current_version=d['current_version'],
            fixed_version=d.get('fixed_version'),
            cve_id=d['cve_id'],
            cvss_score=d['cvss_score'],
            severity=VulnerabilitySeverity(d['severity']),
            published_date=datetime.fromisoformat(d['published_date']),
            ecosystem=d['ecosystem'],
            description=d['description'],
            age_days=d['age_days'],
            is_kev=d['is_kev'],
            exploit_available=d['exploit_available'],
            references=d.get('references', []),
            affected_functions=d.get('affected_functions', [])
        )

    async def _run_osv_scanner(self, sbom_path: Path) -> Dict:
        """Run OSV scanner on SBOM file."""
        # Build OSV scanner command
        cmd = [
            "osv-scanner",
            "--sbom", str(sbom_path),
            "--format", "json"
        ]

        if self.offline_mode:
            cmd.extend(["--offline", "--local-db", str(self.local_db_path)])

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=300  # 5 minute timeout
            )

            if process.returncode == 0 or process.returncode == 1:
                # OSV returns 1 if vulnerabilities found, 0 if none
                return {
                    'success': True,
                    'output': stdout.decode()
                }
            else:
                logger.error(f"OSV scanner failed: {stderr.decode()}")
                return {
                    'success': False,
                    'error': stderr.decode()
                }

        except asyncio.TimeoutError:
            return {
                'success': False,
                'error': "OSV scan timed out after 5 minutes"
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def _parse_osv_output(self, osv_output: str) -> List[VulnerabilityFinding]:
        """Parse OSV scanner JSON output."""
        findings = []

        try:
            data = json.loads(osv_output)

            # Handle different OSV output formats
            results = data.get('results', [])

            for result in results:
                # Each result corresponds to a scanned file/SBOM
                for package_result in result.get('packages', []):
                    package_info = package_result.get('package', {})

                    for group in package_result.get('groups', []):
                        # Each group contains related vulnerabilities
                        for vuln_id in group.get('ids', []):
                            finding = self._create_finding(
                                package_info,
                                vuln_id,
                                group.get('max_severity')
                            )
                            if finding:
                                findings.append(finding)

                    # Also handle vulnerabilities not in groups
                    for vuln in package_result.get('vulnerabilities', []):
                        finding = self._create_finding(
                            package_info,
                            vuln,
                            vuln.get('severity')
                        )
                        if finding:
                            findings.append(finding)

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse OSV output: {e}")
        except Exception as e:
            logger.error(f"Error processing OSV output: {e}")

        return findings

    def _create_finding(self, package_info: Dict, vuln_data: Dict, severity_data: any) -> Optional[VulnerabilityFinding]:
        """Create VulnerabilityFinding from OSV data."""
        try:
            # Extract vulnerability ID (could be CVE or other format)
            if isinstance(vuln_data, str):
                vuln_id = vuln_data
                vuln_details = {}
            else:
                vuln_id = vuln_data.get('id', '')
                vuln_details = vuln_data

            # Skip if not CVE (for consistency)
            cve_id = vuln_id if vuln_id.startswith('CVE-') else f"OSV-{vuln_id}"

            # Extract CVSS score
            cvss_score = 0.0
            if isinstance(severity_data, dict):
                cvss_score = severity_data.get('score', 0.0)
            elif vuln_details.get('database_specific', {}).get('severity'):
                # Try to extract CVSS from database_specific
                severity_info = vuln_details['database_specific']['severity']
                if isinstance(severity_info, dict):
                    cvss_score = severity_info.get('score', 0.0)

            # Determine severity from CVSS score
            severity = self._cvss_to_severity(cvss_score)

            # Calculate age
            published_date = datetime.now()  # Default to now
            if vuln_details.get('published'):
                try:
                    published_date = datetime.fromisoformat(vuln_details['published'].replace('Z', '+00:00'))
                except:
                    pass

            age_days = (datetime.now() - published_date).days

            # Check if in KEV
            is_kev = cve_id in self.kev_cves

            # Check for exploit availability
            exploit_available = is_kev or self._check_exploit_availability(vuln_details)

            # Extract package details
            package_name = package_info.get('name', 'unknown')
            current_version = package_info.get('version', 'unknown')
            ecosystem = package_info.get('ecosystem', 'unknown')

            # Get fixed version if available
            fixed_version = None
            if vuln_details.get('affected'):
                for affected in vuln_details['affected']:
                    if affected.get('ranges'):
                        for range_info in affected['ranges']:
                            if range_info.get('events'):
                                for event in range_info['events']:
                                    if event.get('fixed'):
                                        fixed_version = event['fixed']
                                        break

            # Get description
            description = vuln_details.get('summary', vuln_details.get('details', 'No description available'))

            # Get references
            references = []
            if vuln_details.get('references'):
                references = [ref.get('url', '') for ref in vuln_details['references'] if ref.get('url')]

            return VulnerabilityFinding(
                package_name=package_name,
                current_version=current_version,
                fixed_version=fixed_version,
                cve_id=cve_id,
                cvss_score=cvss_score,
                severity=severity,
                published_date=published_date,
                ecosystem=ecosystem,
                description=description[:500],  # Limit description length
                age_days=age_days,
                is_kev=is_kev,
                exploit_available=exploit_available,
                references=references[:5],  # Limit references
                affected_functions=[]
            )

        except Exception as e:
            logger.warning(f"Could not create finding: {e}")
            return None

    def _cvss_to_severity(self, cvss_score: float) -> VulnerabilitySeverity:
        """Convert CVSS score to severity level."""
        if cvss_score >= 9.0:
            return VulnerabilitySeverity.CRITICAL
        elif cvss_score >= 7.0:
            return VulnerabilitySeverity.HIGH
        elif cvss_score >= 4.0:
            return VulnerabilitySeverity.MEDIUM
        elif cvss_score > 0:
            return VulnerabilitySeverity.LOW
        else:
            return VulnerabilitySeverity.UNKNOWN

    def _check_exploit_availability(self, vuln_details: Dict) -> bool:
        """Check if exploit is available for vulnerability."""
        # Check references for exploit indicators
        if vuln_details.get('references'):
            exploit_keywords = ['exploit', 'poc', 'proof-of-concept', 'metasploit']
            for ref in vuln_details['references']:
                url = ref.get('url', '').lower()
                if any(keyword in url for keyword in exploit_keywords):
                    return True

        # Check database_specific for exploit flag
        if vuln_details.get('database_specific', {}).get('exploit_available'):
            return True

        return False

    def _count_packages_in_sbom(self, sbom_path: Path) -> int:
        """Count total packages in SBOM file."""
        try:
            with open(sbom_path, 'r') as f:
                sbom_data = json.load(f)

            # CycloneDX format
            if 'components' in sbom_data:
                return len(sbom_data['components'])

            # SPDX format
            elif 'packages' in sbom_data:
                return len(sbom_data['packages'])

            return 0

        except Exception as e:
            logger.warning(f"Could not count packages in SBOM: {e}")
            return 0

    def _count_severities(self, vulnerabilities: List[VulnerabilityFinding]) -> Dict[str, int]:
        """Count vulnerabilities by severity level."""
        counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'unknown': 0
        }

        for vuln in vulnerabilities:
            counts[vuln.severity.value] += 1

        return counts

    async def update_local_database(self):
        """Update local OSV database for offline mode."""
        logger.info("Updating local OSV database...")

        try:
            # Create database directory
            self.local_db_path.mkdir(parents=True, exist_ok=True)

            # Run OSV scanner update
            cmd = ["osv-scanner", "--update-offline-database", str(self.local_db_path)]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                logger.info("Local OSV database updated successfully")
                return True
            else:
                logger.error(f"Failed to update database: {stderr.decode()}")
                return False

        except Exception as e:
            logger.error(f"Error updating database: {e}")
            return False

    def check_kev_status(self, cve_id: str) -> bool:
        """
        Check if CVE is in CISA Known Exploited Vulnerabilities.

        Args:
            cve_id: CVE identifier

        Returns:
            True if CVE is in KEV catalog
        """
        return cve_id in self.kev_cves


async def main():
    """Example usage of OSV Scanner."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python osv_scanner.py <sbom_file>")
        sys.exit(1)

    sbom_path = sys.argv[1]

    # Initialize scanner
    scanner = OSVScanner(
        offline_mode=False,
        check_kev=True,
        min_cvss=0.0
    )

    # Scan SBOM
    print(f"Scanning SBOM: {sbom_path}")
    result = await scanner.scan_sbom(sbom_path)

    # Display results
    print(f"\n✅ OSV Scan Complete")
    print(f"Total packages: {result.total_packages}")
    print(f"Vulnerable packages: {result.vulnerable_packages}")
    print(f"Total vulnerabilities: {len(result.vulnerabilities)}")
    print(f"\nSeverity breakdown:")
    for severity, count in result.severity_counts.items():
        print(f"  {severity.upper()}: {count}")

    # Show top vulnerabilities
    if result.vulnerabilities:
        print(f"\nTop 5 vulnerabilities by CVSS:")
        sorted_vulns = sorted(result.vulnerabilities, key=lambda v: v.cvss_score, reverse=True)
        for vuln in sorted_vulns[:5]:
            kev_flag = "🚨 KEV" if vuln.is_kev else ""
            print(f"  {vuln.cve_id} ({vuln.cvss_score}) - {vuln.package_name} {vuln.current_version} {kev_flag}")
            print(f"    Age: {vuln.age_days} days | Fix: {vuln.fixed_version or 'No fix available'}")

    if not result.success:
        print(f"\n⚠️ Error: {result.error_message}")


if __name__ == "__main__":
    asyncio.run(main())