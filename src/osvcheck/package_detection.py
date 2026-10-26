"""Package manager detection and package listing."""

import fnmatch
import importlib.util
import json
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path


class PackageListingError(RuntimeError):
    """Raised when a package manager cannot list an environment's packages."""


def _read_pyproject(path: Path) -> dict:
    """Read a pyproject.toml file safely."""
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return {}


def _is_workspace_member(
    project_root: Path, workspace_root: Path, members: list[str]
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


def find_uv_lock_path(project_root: Path) -> Path | None:
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


def is_uv_lock_current(project_root: Path, uv_lock: Path | None = None) -> bool:
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
        except (subprocess.SubprocessError, OSError, UnicodeDecodeError):
            pass

    return uv_lock.stat().st_mtime >= pyproject.stat().st_mtime


def parse_uv_lock(uv_lock_path: Path) -> list[dict[str, str]]:
    """Parse uv.lock and extract package list."""
    try:
        with open(uv_lock_path, "rb") as f:
            data = tomllib.load(f)

        packages = []
        for pkg in data.get("package", []):
            packages.append({"name": pkg["name"], "version": pkg["version"]})

        return packages
    except (
        OSError,
        UnicodeDecodeError,
        tomllib.TOMLDecodeError,
        AttributeError,
        KeyError,
        TypeError,
    ):
        return []


def is_uv_available() -> bool:
    """Check if uv command is available."""
    return shutil.which("uv") is not None


def find_venv_python(venv_path: Path) -> Path | None:
    """Return a virtual environment's Python interpreter, if present."""
    for executable in (
        venv_path / "bin" / "python",
        venv_path / "bin" / "python3",
        venv_path / "Scripts" / "python.exe",
        venv_path / "Scripts" / "python3.exe",
    ):
        if executable.is_file():
            return executable
    return None


def find_local_virtualenvs(project_root: Path) -> list[Path]:
    """Find immediate-child virtual environments identified by standard markers."""
    return [
        candidate
        for candidate in sorted(project_root.iterdir())
        if candidate.is_dir()
        and (candidate / "pyvenv.cfg").is_file()
        and ((candidate / "lib").is_dir() or (candidate / "Lib").is_dir())
    ]


def is_uv_managed_virtualenv(venv_path: Path) -> bool:
    """Return whether a virtual environment was created by uv."""
    try:
        return any(
            line.startswith("uv =")
            for line in (venv_path / "pyvenv.cfg").read_text().splitlines()
        )
    except OSError:
        return False


def is_pip_available(python_executable: Path | None = None) -> bool:
    """Check if pip module is available."""
    if python_executable is not None:
        try:
            result = subprocess.run(
                [str(python_executable), "-m", "pip", "--version"],
                capture_output=True,
                text=True,
                check=False,
            )
            return result.returncode == 0
        except (OSError, UnicodeDecodeError):
            return False
    return importlib.util.find_spec("pip") is not None


def get_packages_via_uv(
    python_executable: Path | None = None,
) -> list[dict[str, str]]:
    """Get packages using uv pip list."""
    command = ["uv", "pip", "list", "--format", "json"]
    if python_executable is not None:
        command.extend(["--python", str(python_executable)])
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(result.stdout)
    except (
        OSError,
        UnicodeDecodeError,
        subprocess.SubprocessError,
        json.JSONDecodeError,
    ) as error:
        raise PackageListingError("Unable to list packages with uv") from error


def get_packages_via_pip(
    python_executable: Path | None = None,
) -> list[dict[str, str]]:
    """Get packages using pip list."""
    if python_executable is None:
        python_executable = Path(sys.executable)
    try:
        result = subprocess.run(
            [str(python_executable), "-m", "pip", "list", "--format", "json"],
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(result.stdout)
    except (
        OSError,
        UnicodeDecodeError,
        subprocess.SubprocessError,
        json.JSONDecodeError,
    ) as error:
        raise PackageListingError("Unable to list packages with pip") from error
