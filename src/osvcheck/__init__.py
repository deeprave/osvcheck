#!/usr/bin/env python
"""osvcheck - Lightweight vulnerability scanner for Python dependencies."""

from pathlib import Path

from .cache import load_cache, save_cache
from .dependencies import get_direct_dependencies
from .osv import OSVClient
from .scanner import PackageScanner, UvPackageLister

CACHE_FILE = Path(".osvcheck_cache")


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
    # Load dependencies and cache
    direct_deps = get_direct_dependencies(Path("pyproject.toml"))
    cache = load_cache(CACHE_FILE)

    # Setup scanner
    osv_client = OSVClient()
    package_lister = UvPackageLister()
    scanner = PackageScanner(osv_client, package_lister)

    # Get package count for display
    all_packages = package_lister.list_packages()
    print(
        f"Checking {len(all_packages)} packages ({len(direct_deps)} direct dependencies)...\n"
    )

    # Scan for vulnerabilities
    direct_vulnerable, indirect_vulnerable = scanner.scan_packages(direct_deps, cache)

    # Save cache and report
    save_cache(cache, CACHE_FILE)
    report_results(direct_vulnerable, indirect_vulnerable)

    # Exit with appropriate code
    exit(determine_exit_code(direct_vulnerable, indirect_vulnerable))


if __name__ == "__main__":
    main()
