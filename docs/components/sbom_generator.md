# SBOM Generator Component

## Component Overview

The SBOM Generator Component is a standalone tool for creating Software Bill of Materials (SBOM) for MCP repositories. It supports multiple SBOM generators (cdxgen, syft) and output formats (CycloneDX, SPDX), with automatic detection of programming languages and package managers.

### Purpose
Generate comprehensive SBOMs for vulnerability scanning and supply chain analysis, supporting 15+ programming languages and package managers with intelligent caching and multi-format output.

### Position in System Architecture
```
┌─────────────────────────────────────────────────┐
│          MCP Security Analysis System           │
├─────────────────────────────────────────────────┤
│                                                  │
│       Vulnerability Scoring Pipeline (30%)      │
│       ┌──────────────────────────────┐         │
│       │                              │         │
│       │     ┌─────────────┐         │         │
│       │     │    SBOM     │         │         │
│       │     │  Generator  │ ◄── THIS          │
│       │     └─────────────┘         │         │
│       │            │                 │         │
│       │            ▼                 │         │
│       │     ┌─────────────┐         │         │
│       │     │     OSV     │         │         │
│       │     │   Scanner   │         │         │
│       │     └─────────────┘         │         │
│       │            │                 │         │
│       │            ▼                 │         │
│       │     ┌─────────────┐         │         │
│       │     │ Time-Decay  │         │         │
│       │     │   Scorer    │         │         │
│       │     └─────────────┘         │         │
│       │                              │         │
│       └──────────────────────────────┘         │
└─────────────────────────────────────────────────┘
```

## Files Created

### 1. Core Generator
- **File**: `/mnt/prod/mcp/sbom_generator.py` (400+ lines)
- **Purpose**: SBOM generation with multi-tool support
- **Key Features**:
  - Auto-detect 15+ package managers
  - Support cdxgen and syft generators
  - CycloneDX and SPDX formats
  - Smart caching (24-hour TTL)
  - Deep dependency scanning
  - Monorepo support

### 2. Key Classes

#### `SBOMGenerator`
Main generator class with flexible configuration:
```python
class SBOMGenerator:
    def __init__(self,
                 generator_type: GeneratorType = GeneratorType.CDXGEN,
                 output_format: SBOMFormat = SBOMFormat.CYCLONEDX,
                 include_dev_deps: bool = False,
                 deep_scan: bool = True,
                 cache_dir: Optional[Path] = None,
                 cache_ttl_hours: int = 24)
```

#### `SBOMResult`
SBOM generation result:
```python
@dataclass
class SBOMResult:
    sbom_path: str
    format: str  # "cyclonedx" or "spdx"
    component_count: int
    languages_detected: List[str]
    generation_time: float
    generator_used: str  # "cdxgen" or "syft"
```

## Installation Guide

### Prerequisites

#### For cdxgen (Recommended for multi-language):
```bash
# Install Node.js first, then:
npm install -g @cyclonedx/cdxgen

# Verify installation
cdxgen --version
```

#### For syft (Recommended for containers):
```bash
# macOS
brew install syft

# Linux
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Verify installation
syft version
```

## Language Support Matrix

### Package Managers Detected

| Language | Package Files | Recommended Generator |
|----------|--------------|----------------------|
| **JavaScript/TypeScript** | package.json, yarn.lock, pnpm-lock.yaml | cdxgen |
| **Python** | requirements.txt, setup.py, pyproject.toml, Pipfile, poetry.lock | cdxgen |
| **Go** | go.mod, go.sum | cdxgen |
| **Java** | pom.xml, build.gradle, build.gradle.kts | cdxgen |
| **Ruby** | Gemfile, Gemfile.lock | cdxgen |
| **Rust** | Cargo.toml, Cargo.lock | cdxgen |
| **PHP** | composer.json, composer.lock | cdxgen |
| **.NET** | *.csproj, packages.config, project.json | cdxgen |
| **Swift** | Package.swift, Package.resolved | cdxgen |
| **Kotlin** | build.gradle.kts | cdxgen |
| **Dart** | pubspec.yaml, pubspec.lock | cdxgen |
| **Elixir** | mix.exs, mix.lock | cdxgen |
| **Haskell** | *.cabal, stack.yaml | cdxgen |
| **Scala** | build.sbt | cdxgen |
| **Clojure** | project.clj, deps.edn | cdxgen |
| **Container Images** | Dockerfile, container layers | syft |

## Usage Examples

### Basic SBOM Generation

```python
from sbom_generator import SBOMGenerator, GeneratorType, SBOMFormat
import asyncio

async def generate_basic_sbom():
    generator = SBOMGenerator()
    result = await generator.generate_sbom("/path/to/repo")
    print(f"Generated SBOM: {result.sbom_path}")
    print(f"Components found: {result.component_count}")

asyncio.run(generate_basic_sbom())
```

### Advanced Configuration

```python
# For comprehensive scanning with dev dependencies
generator = SBOMGenerator(
    generator_type=GeneratorType.CDXGEN,
    output_format=SBOMFormat.CYCLONEDX,
    include_dev_deps=True,  # Include dev dependencies
    deep_scan=True,         # Deep transitive analysis
    cache_ttl_hours=48      # Cache for 2 days
)

# For container image scanning
container_gen = SBOMGenerator(
    generator_type=GeneratorType.SYFT,
    output_format=SBOMFormat.SPDX
)
```

### Batch Processing

```python
async def batch_generate_sboms(repo_paths: List[str]):
    generator = SBOMGenerator()
    results = []

    for repo_path in repo_paths:
        print(f"Processing {repo_path}...")
        result = await generator.generate_sbom(repo_path)
        results.append(result)

        if not result.success:
            print(f"⚠️ Failed: {result.error_message}")

    return results
```

### Command Line Usage

```bash
# Basic usage
python sbom_generator.py /path/to/repository

# With options (when CLI flags are added)
python sbom_generator.py /path/to/repo --format spdx --generator syft
```

## Configuration Options

### Generator Types

#### cdxgen (Default)
**Pros:**
- Best multi-language support
- Deep transitive dependency analysis
- Active development by OWASP
- Supports 15+ ecosystems

**Cons:**
- Requires Node.js
- Slower for large monorepos
- May miss some native binaries

#### syft
**Pros:**
- Excellent for container images
- Fast scanning
- Good binary detection
- No runtime dependencies

**Cons:**
- Less accurate for some languages
- Limited transitive dependency analysis
- May miss development dependencies

### Output Formats

#### CycloneDX (Default)
- OWASP standard
- Rich component metadata
- Better vulnerability mapping
- Supports services and dependencies

#### SPDX
- Linux Foundation standard
- Better license information
- ISO/IEC standard
- Wider tool compatibility

### Caching Strategy

SBOMs are cached to improve performance:
- Default TTL: 24 hours
- Cache key: MD5(repo_path + generator + format)
- Location: `.cache/sbom/`
- Automatic cleanup of expired entries

## Performance Characteristics

### Scanning Speed

| Repository Size | cdxgen Time | syft Time | Component Count |
|----------------|-------------|-----------|-----------------|
| Small (<100 deps) | 5-10 seconds | 2-5 seconds | 50-100 |
| Medium (100-500 deps) | 20-40 seconds | 10-20 seconds | 200-500 |
| Large (500+ deps) | 60-120 seconds | 30-60 seconds | 500-2000 |
| Monorepo | 120-300 seconds | 60-120 seconds | 1000-5000 |

### Resource Usage

- **Memory**: 200MB - 1GB depending on repository size
- **CPU**: Single core for cdxgen, multi-core for syft
- **Disk**: 10-100MB per SBOM file
- **Network**: Minimal (only for package metadata)

### Optimization Tips

1. **Use caching** for repeated scans
2. **Exclude dev dependencies** if not needed
3. **Use syft for containers**, cdxgen for source
4. **Parallel processing** for multiple repos
5. **Set appropriate timeouts** for large repos

## Troubleshooting

### Common Issues

#### 1. Generator Not Found
```
RuntimeError: cdxgen is not installed
```
**Solution**: Install the generator using the installation guide above

#### 2. Timeout on Large Repository
```
Generation timed out after 5 minutes
```
**Solution**: Increase timeout or use shallow scanning:
```python
generator = SBOMGenerator(deep_scan=False)
```

#### 3. Empty SBOM Generated
**Possible causes:**
- No supported package files found
- Wrong generator for repository type
- Corrupted package lock files

**Solution**: Check detected languages and use appropriate generator

#### 4. High Memory Usage
**Solution**: Process repositories sequentially instead of parallel:
```python
# Limit concurrent operations
semaphore = asyncio.Semaphore(2)
```

## Best Practices

### 1. Choose the Right Generator
- Use **cdxgen** for source code repositories
- Use **syft** for container images and binaries
- Consider both for comprehensive coverage

### 2. Optimize for Your Use Case
```python
# For vulnerability scanning (exclude dev deps)
generator = SBOMGenerator(include_dev_deps=False)

# For license compliance (include everything)
generator = SBOMGenerator(include_dev_deps=True, deep_scan=True)

# For quick assessment (shallow scan)
generator = SBOMGenerator(deep_scan=False, cache_ttl_hours=168)
```

### 3. Handle Monorepos
```python
# Detect and handle monorepos specially
languages = generator.detect_package_managers(repo_path)
if len(languages) > 3:
    # Likely a monorepo, adjust settings
    generator = SBOMGenerator(
        deep_scan=False,  # Faster for monorepos
        cache_ttl_hours=48  # Cache longer
    )
```

### 4. Validate Output
```python
# Always validate generated SBOMs
if generator.validate_sbom(result.sbom_path):
    print("✅ Valid SBOM generated")
else:
    print("⚠️ Invalid SBOM, regenerating...")
```

## Integration with OSV Scanner

The SBOM Generator produces output that feeds directly into the OSV Scanner:

```python
# Step 1: Generate SBOM
sbom_gen = SBOMGenerator()
sbom_result = await sbom_gen.generate_sbom(repo_path)

# Step 2: Pass to OSV Scanner
from osv_scanner import OSVScanner
osv = OSVScanner()
vulnerabilities = await osv.scan_sbom(sbom_result.sbom_path)
```

## API Reference

### SBOMGenerator Methods

#### `__init__(...)`
Initialize the generator with configuration options.

#### `generate_sbom(repo_path: str) -> SBOMResult`
Generate SBOM for the specified repository.

#### `detect_package_managers(repo_path: Path) -> List[str]`
Detect which package managers are used in the repository.

#### `validate_sbom(sbom_path: str) -> bool`
Validate the structure and content of an SBOM file.

## Future Enhancements

1. **Additional Generators**
   - Add support for Microsoft SBOM Tool
   - Integrate Tern for better container analysis

2. **Enhanced Detection**
   - Binary component detection
   - License extraction improvement
   - Dependency relationship mapping

3. **Performance**
   - Incremental SBOM generation
   - Distributed scanning for large repos
   - Smart caching based on file changes

4. **Features**
   - SBOM signing and attestation
   - Format conversion utilities
   - Dependency graph visualization

## Dependencies

### Python Requirements
```python
# Built-in modules only
import asyncio
import json
import logging
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
from enum import Enum
```

### System Requirements
- Python 3.7+
- cdxgen or syft installed
- 1GB RAM minimum
- Write access for cache directory

## Component Boundaries

### What This Component Does
- ✅ Generate SBOMs in multiple formats
- ✅ Auto-detect package managers
- ✅ Cache results for performance
- ✅ Validate SBOM structure
- ✅ Support multiple generators

### What This Component Does NOT Do
- ❌ Scan for vulnerabilities (OSV Scanner's job)
- ❌ Calculate security scores (Scorer's job)
- ❌ Fix vulnerable dependencies
- ❌ Upload SBOMs to external services
- ❌ Modify project dependencies

## Testing

### Unit Tests
```python
def test_package_manager_detection():
    generator = SBOMGenerator()
    test_repo = Path("test_data/multi_language_repo")
    languages = generator.detect_package_managers(test_repo)
    assert "python" in languages
    assert "javascript" in languages
```

### Integration Tests
- Test with real repositories
- Verify SBOM validation
- Check cache functionality
- Measure generation times

## Maintenance

### Updating Generators
```bash
# Update cdxgen
npm update -g @cyclonedx/cdxgen

# Update syft
brew upgrade syft
```

### Cache Management
```python
# Clear old cache entries
from pathlib import Path
import time

cache_dir = Path(".cache/sbom")
for cache_file in cache_dir.glob("*.json"):
    age_days = (time.time() - cache_file.stat().st_mtime) / 86400
    if age_days > 7:
        cache_file.unlink()
```

---

*This component is part of the MCP Security Analysis System and provides SBOM generation capabilities that feed into the OSV vulnerability scanner for comprehensive security assessment.*