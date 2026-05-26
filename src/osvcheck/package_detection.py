"""Package manager detection and package listing."""

import importlib.util
import json
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Dict, List


def is_uv_lock_current(project_root: Path) -> bool:
    """Check if uv.lock is up-to-date with pyproject.toml."""
    uv_lock = project_root / "uv.lock"
    pyproject = project_root / "pyproject.toml"

    if not uv_lock.exists() or not pyproject.exists():
        return False

    if is_uv_available():
        try:
            result = subprocess.run(
                ["uv", "lock", "--check"],
                cwd=project_root,
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode in (0, 1):
                return result.returncode == 0
        except (subprocess.SubprocessError, OSError):
            pass

    return uv_lock.stat().st_mtime >= pyproject.stat().st_mtime


def parse_uv_lock(uv_lock_path: Path) -> List[Dict[str, str]]:
    """Parse uv.lock and extract package list."""
    try:
        with open(uv_lock_path, "rb") as f:
            data = tomllib.load(f)

        packages = []
        for pkg in data.get("package", []):
            packages.append({"name": pkg["name"], "version": pkg["version"]})

        return packages
    except Exception:
        return []


def is_uv_available() -> bool:
    """Check if uv command is available."""
    return shutil.which("uv") is not None


def is_pip_available() -> bool:
    """Check if pip module is available."""
    return importlib.util.find_spec("pip") is not None


def get_packages_via_uv() -> List[Dict[str, str]]:
    """Get packages using uv pip list."""
    try:
        result = subprocess.run(
            ["uv", "pip", "list", "--format", "json"],
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(result.stdout)
    except Exception:
        return []


def get_packages_via_pip() -> List[Dict[str, str]]:
    """Get packages using pip list."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format", "json"],
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(result.stdout)
    except Exception:
        return []
