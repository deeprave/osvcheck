#!/usr/bin/env python
"""osvcheck - Lightweight vulnerability scanner for Python dependencies."""

from pathlib import Path
from typing import Optional, Tuple

from .cache import load_cache, save_cache
from .dependencies import get_direct_dependencies
from .osv import OSVClient
from .package_detection import is_pip_available, is_uv_available, is_uv_lock_current
from .scanner import (
    PackageLister,
    PackageScanner,
    PipPackageLister,
    UvLockPackageLister,
    UvPackageLister,
)

CACHE_FILE = Path(".osvcheck_cache")


def detect_package_lister() -> Tuple[PackageLister, Optional[str]]:
    """Detect and return appropriate package lister.

    Returns:
        Tuple of (PackageLister, warning_message)
    """
    project_root = Path.cwd()
    pyproject = project_root / "pyproject.toml"
    uv_lock = project_root / "uv.lock"
    warning = None

    # If no pyproject.toml, not a uv project - require pip
    if not pyproject.exists():
        if is_pip_available():
            return PipPackageLister(), None
        raise RuntimeError(
            "No pyproject.toml found and pip is not available.\n"
            "osvcheck requires either:\n"
            "  - A pyproject.toml-based project with uv or pip\n"
            "  - pip installed for scanning arbitrary environments\n"
        )

    # pyproject.toml exists - check uv.lock
    if uv_lock.exists():
        if is_uv_lock_current(project_root):
            return UvLockPackageLister(uv_lock), None
        else:
            warning = "Warning: uv.lock is out of date with pyproject.toml"

    # Try uv
    if is_uv_available():
        return UvPackageLister(), warning

    # Try pip
    if is_pip_available():
        return PipPackageLister(), warning

    # Fail
    raise RuntimeError(
        "No package manager found.\n"
        "osvcheck requires either:\n"
        "  - uv (recommended): https://github.com/astral-sh/uv\n"
        "  - pip (usually included with Python)\n\n"
        "Ensure one is installed and available."
    )


def report_results(
    direct_vulnerable: list[str], indirect_vulnerable: list[str]
) -> None:
    """Print vulnerability scan results."""
    for pkg_name in direct_vulnerable:
        print(f"⚠️  [DIRECT] {pkg_name}: vulnerabilities found")

    for pkg_name in indirect_vulnerable:
        print(f"  ⚠️ [indirect] {pkg_name}: vulnerabilities found")

    v_direct = len(direct_vulnerable)
    v_indirect = len(indirect_vulnerable)

    if v_direct or v_indirect:
        print("\nVulnerabilities found!")
    if v_direct:
        print(f"  - {v_direct} direct dependency vulnerabilities:")
        print(f"    {', '.join(direct_vulnerable)}")
    if v_indirect:
        print(f"  - {v_indirect} indirect dependency vulnerabilities:")
        print(f"    {', '.join(indirect_vulnerable)}")


def determine_exit_code(
    direct_vulnerable: list[str], indirect_vulnerable: list[str]
) -> int:
    """Determine exit code based on vulnerabilities found."""
    if direct_vulnerable:
        return 2
    if indirect_vulnerable:
        return 1
    return 0


def main() -> None:
    """Main entry point for osvcheck."""
    # Detect package manager
    package_lister, warning = detect_package_lister()

    if warning:
        print(f"⚠️  {warning}\n")

    # Load dependencies if pyproject.toml exists
    pyproject = Path("pyproject.toml")
    direct_deps = get_direct_dependencies(pyproject) if pyproject.exists() else []

    # Load cache
    cache = load_cache(CACHE_FILE)

    # Setup scanner
    osv_client = OSVClient()
    scanner = PackageScanner(osv_client, package_lister)

    # Get package count for display
    all_packages = package_lister.list_packages()
    if direct_deps:
        print(
            f"Checking {len(all_packages)} packages ({len(direct_deps)} direct dependencies)...\n"
        )
    else:
        print(f"Checking {len(all_packages)} packages...\n")

    # Scan for vulnerabilities
    direct_vulnerable, indirect_vulnerable = scanner.scan_packages(direct_deps, cache)

    # Save cache and report
    save_cache(cache, CACHE_FILE)
    report_results(direct_vulnerable, indirect_vulnerable)

    # Exit with appropriate code
    exit(determine_exit_code(direct_vulnerable, indirect_vulnerable))


if __name__ == "__main__":
    main()
