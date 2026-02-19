# osvcheck

Security vulnerability scanner for Python dependencies using the OSV database.

## Installation

### Via uvx (recommended for one-off use)

```bash
uvx osvcheck
```

### Via pip

```bash
pip install osvcheck
```

### For development

```bash
git clone <repository-url>
cd osvcheck
uv sync
```

## Usage

```bash
# Scan current project
osvcheck

# Show help
osvcheck --help
```

## Features

- Scans Python dependencies for known security vulnerabilities
- Uses the OSV (Open Source Vulnerabilities) database
- Fast and lightweight
- No configuration required

## Configuration

Configuration options will be documented here once implemented via `[tool.osvcheck]` in pyproject.toml.

## License

MIT License - See LICENSE file for details.
