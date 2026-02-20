# osvcheck

[![Python Tests](https://img.shields.io/github/actions/workflow/status/deeprave/osvcheck/python-test.yml?branch=main&label=tests)](https://github.com/deeprave/osvcheck/actions/workflows/python-test.yml)
[![PyPI version](https://img.shields.io/pypi/v/osvcheck)](https://pypi.org/project/osvcheck/)
[![Python versions](https://img.shields.io/pypi/pyversions/osvcheck)](https://pypi.org/project/osvcheck/)
[![Downloads](https://img.shields.io/pypi/dm/osvcheck)](https://pypi.org/project/osvcheck/)
[![Security](https://img.shields.io/github/actions/workflow/status/deeprave/osvcheck/codeql.yml?branch=main&label=security&logo=github)](https://github.com/deeprave/osvcheck/security/code-scanning)
[![Maintenance](https://img.shields.io/badge/maintained-yes-green.svg)](https://github.com/deeprave/osvcheck/graphs/commit-activity)

Lightweight vulnerability scanner for Python dependencies using the OSV database.

osvcheck scans your Python project's dependencies for known security vulnerabilities by querying the [OSV (Open Source Vulnerabilities)](https://osv.dev) database. It's designed for source-level checking during development and CI/CD pipelines.

**Key features:**
- Zero runtime dependencies (stdlib only)
- Auto-detects package manager (uv.lock, uv, or pip)
- Smart caching (12-48 hour TTL) minimizes API calls
- Distinguishes direct vs indirect vulnerabilities
- Optional rich integration for enhanced output (auto-detected if installed)

## Installation

Install via pip or uv, or add to your project's dev dependencies.

## Usage

```bash
# Scan current project
osvcheck

# Logging options
osvcheck -v              # Verbose (debug) output
osvcheck -q              # Quiet (warnings/errors only)
osvcheck --log-json      # JSON format logs
osvcheck --log-file FILE # Write logs to file

# Color control
osvcheck --color         # Force color output
osvcheck --no-color      # Disable color output
```

**Exit codes:**
- `0` - No vulnerabilities found
- `1` - Indirect dependency vulnerabilities only
- `2` - Direct dependency vulnerabilities found

**As a Pre-commit hook:**

Add to `.pre-commit-config.yaml`:
```yaml
- repo: https://github.com/deeprave/osvcheck
  rev: v1.0.0b1
  hooks:
    - id: osvcheck
```

**CI/CD integration:**
```bash
# Fail only on direct vulnerabilities
osvcheck || [ $? -eq 1 ]

# Fail on any vulnerabilities
osvcheck
```

## Features

- Scans Python dependencies for known security vulnerabilities
- Uses the OSV (Open Source Vulnerabilities) database
- Multi-environment support with auto-detection:
  - Uses `uv.lock` if present and up-to-date (fastest)
  - Falls back to `uv pip list` if uv is available
  - Falls back to `pip list` if pip is available
- Smart caching with 12-48 hour randomized TTL
- Distinguishes between direct and indirect dependency vulnerabilities
- Zero runtime dependencies (Python stdlib only)
- Optional rich integration for enhanced output (auto-detected if already installed)

## License

MIT License - See LICENSE file for details.
