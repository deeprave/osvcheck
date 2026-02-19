"""Dependency parsing from pyproject.toml."""

import re
import tomllib
from pathlib import Path
from typing import List


def parse_package_name(dep_spec: str) -> str:
    """Extract package name from dependency specifier.

    Examples:
        'requests>=2.0' -> 'requests'
        'django[extra]~=4.0' -> 'django'
    """
    return re.split(r"[<>=\[~!]", dep_spec)[0].strip().lower()


def get_direct_dependencies(pyproject_path: Path) -> List[str]:
    """Get list of direct dependency names from pyproject.toml."""
    try:
        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)
        deps = data.get("project", {}).get("dependencies", [])
        return [parse_package_name(dep) for dep in deps]
    except Exception:
        return []


def is_direct_dependency(pkg_name: str, direct_deps: List[str]) -> bool:
    """Check if package is a direct dependency."""
    return pkg_name.lower() in direct_deps
