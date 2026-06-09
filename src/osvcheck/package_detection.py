"""Package manager detection and package listing."""

import importlib.util
import json
import shutil
import fnmatch
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Dict, List, Optional


def _read_pyproject(path: Path) -> dict:
    """Read a pyproject.toml file safely."""
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return {}


def _is_workspace_member(
    project_root: Path, workspace_root: Path, members: List[str]
) -> bool:
    """Check whether project_root is listed as a workspace member."""
    try:
        relative = project_root.resolve().relative_to(workspace_root.resolve())
    except ValueError:
        return False

    relative_posix = relative.as_posix()

    if relative_posix == ".":
        return any(member.strip() in {".", "./", ""} for member in members)

    for member in members:
        normalized_member = str(member).strip().replace("\\", "/").strip()
        if normalized_member == ".":
            continue
        if fnmatch.fnmatch(relative_posix, normalized_member):
            return True

    return False


def find_uv_lock_path(project_root: Path) -> Optional[Path]:
    """Find the uv.lock file for a project, including uv workspace members."""
    local_lock = project_root / "uv.lock"
    if local_lock.exists():
        return local_lock

    for candidate_root in [project_root, *project_root.parents]:
        candidate_pyproject = candidate_root / "pyproject.toml"
        if not candidate_pyproject.exists():
            continue

        data = _read_pyproject(candidate_pyproject)
        members = (
            data.get("tool", {}).get("uv", {}).get("workspace", {}).get("members", [])
        )
        if not isinstance(members, list):
            continue

        candidate_lock = candidate_root / "uv.lock"
        if not candidate_lock.exists():
            continue

        if _is_workspace_member(project_root, candidate_root, members):
            return candidate_lock

    return None


def is_uv_lock_current(project_root: Path, uv_lock: Optional[Path] = None) -> bool:
    """Check if uv.lock is up-to-date with its pyproject.toml."""
    if uv_lock is None:
        uv_lock = project_root / "uv.lock"
    else:
        project_root = uv_lock.parent

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
