"""
SBOM Generator Tool
===================
Generates Software Bill of Materials (SBOM) for MCP repositories using cdxgen or syft.

This is a standalone tool that creates comprehensive SBOMs in CycloneDX or SPDX format,
supporting multiple programming languages and package managers.

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
from typing import Dict, List, Optional, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class GeneratorType(Enum):
    """Supported SBOM generator types."""
    CDXGEN = "cdxgen"
    SYFT = "syft"


class SBOMFormat(Enum):
    """Supported SBOM output formats."""
    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"


@dataclass
class SBOMResult:
    """Result of SBOM generation."""
    sbom_path: str
    format: str  # "cyclonedx" or "spdx"
    component_count: int
    languages_detected: List[str]
    generation_time: float
    generator_used: str  # "cdxgen" or "syft"
    repository: str
    generated_at: str
    success: bool
    error_message: Optional[str] = None
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'sbom_path': self.sbom_path,
            'format': self.format,
            'component_count': self.component_count,
            'languages_detected': self.languages_detected,
            'generation_time': self.generation_time,
            'generator_used': self.generator_used,
            'repository': self.repository,
            'generated_at': self.generated_at,
            'success': self.success,
            'error_message': self.error_message,
            'metadata': self.metadata
        }


class SBOMGenerator:
    """
    SBOM Generator for creating Software Bill of Materials.

    Supports multiple generators (cdxgen, syft) and formats (CycloneDX, SPDX).
    Optimized for multi-language repositories with automatic package manager detection.
    """

    # Package manager detection patterns
    PACKAGE_MANAGERS = {
        'javascript': ['package.json', 'yarn.lock', 'pnpm-lock.yaml', 'package-lock.json'],
        'python': ['requirements.txt', 'setup.py', 'pyproject.toml', 'Pipfile', 'poetry.lock'],
        'go': ['go.mod', 'go.sum'],
        'java': ['pom.xml', 'build.gradle', 'build.gradle.kts'],
        'ruby': ['Gemfile', 'Gemfile.lock'],
        'rust': ['Cargo.toml', 'Cargo.lock'],
        'php': ['composer.json', 'composer.lock'],
        'dotnet': ['*.csproj', '*.fsproj', '*.vbproj', 'packages.config', 'project.json'],
        'swift': ['Package.swift', 'Package.resolved'],
        'kotlin': ['build.gradle.kts'],
        'dart': ['pubspec.yaml', 'pubspec.lock'],
        'elixir': ['mix.exs', 'mix.lock'],
        'haskell': ['*.cabal', 'stack.yaml'],
        'scala': ['build.sbt'],
        'clojure': ['project.clj', 'deps.edn']
    }

    def __init__(self,
                 generator_type: GeneratorType = GeneratorType.CDXGEN,
                 output_format: SBOMFormat = SBOMFormat.CYCLONEDX,
                 include_dev_deps: bool = False,
                 deep_scan: bool = True,
                 cache_dir: Optional[Path] = None,
                 cache_ttl_hours: int = 24):
        """
        Initialize SBOM Generator.

        Args:
            generator_type: Which SBOM generator to use (cdxgen or syft)
            output_format: Output format (cyclonedx or spdx)
            include_dev_deps: Include development dependencies
            deep_scan: Perform deep dependency analysis
            cache_dir: Directory for caching SBOMs
            cache_ttl_hours: Cache time-to-live in hours
        """
        self.generator_type = generator_type
        self.output_format = output_format
        self.include_dev_deps = include_dev_deps
        self.deep_scan = deep_scan
        self.cache_dir = cache_dir or Path(".cache/sbom")
        self.cache_ttl = timedelta(hours=cache_ttl_hours)

        # Create cache directory
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Verify generator is installed
        self._verify_generator_installed()

    def _verify_generator_installed(self):
        """Verify that the selected SBOM generator is installed."""
        try:
            if self.generator_type == GeneratorType.CDXGEN:
                result = subprocess.run(
                    ["cdxgen", "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
            else:  # syft
                result = subprocess.run(
                    ["syft", "version"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

            if result.returncode != 0:
                raise RuntimeError(f"{self.generator_type.value} is not properly installed")

        except FileNotFoundError:
            raise RuntimeError(
                f"{self.generator_type.value} is not installed. "
                f"Install with: npm install -g @cyclonedx/cdxgen (for cdxgen) "
                f"or brew install syft (for syft)"
            )

    def detect_package_managers(self, repo_path: Path) -> List[str]:
        """
        Detect package managers used in the repository.

        Args:
            repo_path: Path to repository

        Returns:
            List of detected programming languages/package managers
        """
        detected = []

        for language, patterns in self.PACKAGE_MANAGERS.items():
            for pattern in patterns:
                # Handle glob patterns
                if '*' in pattern:
                    matches = list(repo_path.rglob(pattern))
                else:
                    matches = list(repo_path.rglob(pattern))

                if matches:
                    detected.append(language)
                    break

        return list(set(detected))  # Remove duplicates

    def _get_cache_path(self, repo_path: Path) -> Path:
        """Get cache file path for a repository."""
        import hashlib
        repo_hash = hashlib.md5(str(repo_path).encode()).hexdigest()
        cache_file = self.cache_dir / f"{repo_hash}_{self.generator_type.value}_{self.output_format.value}.json"
        return cache_file

    def _is_cache_valid(self, cache_path: Path) -> bool:
        """Check if cached SBOM is still valid."""
        if not cache_path.exists():
            return False

        # Check age
        cache_age = datetime.now() - datetime.fromtimestamp(cache_path.stat().st_mtime)
        return cache_age < self.cache_ttl

    async def generate_sbom(self, repo_path: str) -> SBOMResult:
        """
        Generate SBOM for a repository.

        Args:
            repo_path: Path to repository

        Returns:
            SBOMResult with generation details
        """
        repo_path = Path(repo_path).resolve()

        # Check cache
        cache_path = self._get_cache_path(repo_path)
        if self._is_cache_valid(cache_path):
            logger.info(f"Using cached SBOM for {repo_path}")
            with open(cache_path, 'r') as f:
                cached_result = json.load(f)
                return SBOMResult(**cached_result)

        start_time = datetime.now()

        # Detect package managers
        languages = self.detect_package_managers(repo_path)
        logger.info(f"Detected languages/package managers: {languages}")

        # Generate SBOM
        if self.generator_type == GeneratorType.CDXGEN:
            result = await self._generate_with_cdxgen(repo_path, languages)
        else:
            result = await self._generate_with_syft(repo_path)

        # Calculate generation time
        generation_time = (datetime.now() - start_time).total_seconds()

        # Parse SBOM to get component count
        component_count = self._count_components(result['sbom_path'])

        # Create result
        sbom_result = SBOMResult(
            sbom_path=result['sbom_path'],
            format=self.output_format.value,
            component_count=component_count,
            languages_detected=languages,
            generation_time=generation_time,
            generator_used=self.generator_type.value,
            repository=str(repo_path),
            generated_at=datetime.now().isoformat(),
            success=result['success'],
            error_message=result.get('error'),
            metadata={
                'include_dev_deps': self.include_dev_deps,
                'deep_scan': self.deep_scan
            }
        )

        # Cache result
        with open(cache_path, 'w') as f:
            json.dump(sbom_result.to_dict(), f, indent=2)

        return sbom_result

    async def _generate_with_cdxgen(self, repo_path: Path, languages: List[str]) -> Dict:
        """Generate SBOM using cdxgen."""
        output_file = repo_path / f"sbom-cdx-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"

        # Build cdxgen command
        cmd = [
            "cdxgen",
            "-o", str(output_file),
            "--spec-version", "1.5"
        ]

        # Add type hints for better detection
        if languages:
            # cdxgen supports type hints for better accuracy
            type_map = {
                'javascript': 'js',
                'python': 'python',
                'go': 'go',
                'java': 'java',
                'ruby': 'ruby',
                'rust': 'rust',
                'php': 'php',
                'dotnet': 'dotnet'
            }
            for lang in languages:
                if lang in type_map:
                    cmd.extend(["-t", type_map[lang]])

        # Add flags
        if self.deep_scan:
            cmd.append("--deep")

        if not self.include_dev_deps:
            cmd.append("--no-dev")

        if self.output_format == SBOMFormat.SPDX:
            # cdxgen primarily outputs CycloneDX, would need conversion
            cmd.extend(["--format", "spdx"])

        # Execute
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=str(repo_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=300  # 5 minute timeout
            )

            if process.returncode == 0:
                return {
                    'sbom_path': str(output_file),
                    'success': True
                }
            else:
                logger.error(f"cdxgen failed: {stderr.decode()}")
                return {
                    'sbom_path': str(output_file),
                    'success': False,
                    'error': stderr.decode()
                }

        except asyncio.TimeoutError:
            logger.error("cdxgen timed out")
            return {
                'sbom_path': str(output_file),
                'success': False,
                'error': "Generation timed out after 5 minutes"
            }
        except Exception as e:
            logger.error(f"cdxgen error: {e}")
            return {
                'sbom_path': str(output_file),
                'success': False,
                'error': str(e)
            }

    async def _generate_with_syft(self, repo_path: Path) -> Dict:
        """Generate SBOM using syft."""
        output_file = repo_path / f"sbom-syft-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"

        # Build syft command
        format_map = {
            SBOMFormat.CYCLONEDX: "cyclonedx-json",
            SBOMFormat.SPDX: "spdx-json"
        }

        cmd = [
            "syft",
            str(repo_path),
            "-o", f"{format_map[self.output_format]}={output_file}"
        ]

        # Execute
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=300
            )

            if process.returncode == 0:
                return {
                    'sbom_path': str(output_file),
                    'success': True
                }
            else:
                logger.error(f"syft failed: {stderr.decode()}")
                return {
                    'sbom_path': str(output_file),
                    'success': False,
                    'error': stderr.decode()
                }

        except Exception as e:
            logger.error(f"syft error: {e}")
            return {
                'sbom_path': str(output_file),
                'success': False,
                'error': str(e)
            }

    def _count_components(self, sbom_path: str) -> int:
        """Count components in SBOM file."""
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
            logger.warning(f"Could not count components: {e}")
            return 0

    def validate_sbom(self, sbom_path: str) -> bool:
        """
        Validate SBOM file format and content.

        Args:
            sbom_path: Path to SBOM file

        Returns:
            True if valid, False otherwise
        """
        try:
            with open(sbom_path, 'r') as f:
                sbom_data = json.load(f)

            # Basic validation
            if self.output_format == SBOMFormat.CYCLONEDX:
                # CycloneDX validation
                required = ['bomFormat', 'specVersion', 'components']
                return all(field in sbom_data for field in required)
            else:
                # SPDX validation
                required = ['spdxVersion', 'packages']
                return all(field in sbom_data for field in required)

        except Exception as e:
            logger.error(f"SBOM validation failed: {e}")
            return False


async def main():
    """Example usage of SBOM Generator."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python sbom_generator.py <repository_path>")
        sys.exit(1)

    repo_path = sys.argv[1]

    # Initialize generator
    generator = SBOMGenerator(
        generator_type=GeneratorType.CDXGEN,
        output_format=SBOMFormat.CYCLONEDX,
        include_dev_deps=False,
        deep_scan=True
    )

    # Generate SBOM
    print(f"Generating SBOM for {repo_path}...")
    result = await generator.generate_sbom(repo_path)

    # Display results
    print(f"\n✅ SBOM Generation Complete")
    print(f"Format: {result.format}")
    print(f"Generator: {result.generator_used}")
    print(f"Components: {result.component_count}")
    print(f"Languages: {', '.join(result.languages_detected)}")
    print(f"Time: {result.generation_time:.2f} seconds")
    print(f"Output: {result.sbom_path}")

    if not result.success:
        print(f"⚠️ Error: {result.error_message}")


if __name__ == "__main__":
    asyncio.run(main())