#!/usr/bin/env python
"""osvcheck - Lightweight vulnerability scanner for Python dependencies."""

import logging
from importlib.metadata import version, PackageNotFoundError
from pathlib import Path
from typing import Optional, Tuple

try:
    __version__ = version("osvcheck")
except PackageNotFoundError:
    __version__ = "unknown"

from .cache import load_cache, save_cache
from .cli import get_cli_exceptions, get_log_level, parse_args
from .config import load_exceptions
from .dependencies import get_direct_dependencies
from .log import setup_logging
from .osv import OSVClient
from .package_detection import (
    find_uv_lock_path,
    is_pip_available,
    is_uv_available,
    is_uv_lock_current,
)
from .scanner import (
    PackageLister,
    PackageScanner,
    PipPackageLister,
    UvLockPackageLister,
    UvPackageLister,
)

CACHE_FILE = Path(".osvcheck_cache")
logger = logging.getLogger("osvcheck")


def detect_package_lister() -> Tuple[PackageLister, Optional[str]]:
    """Detect and return appropriate package lister.

    Returns:
        Tuple of (PackageLister, warning_message)
    """
    project_root = Path.cwd()
    pyproject = project_root / "pyproject.toml"
    uv_lock = find_uv_lock_path(project_root)
    warning = None

    logger.debug("Detecting package manager...")
    logger.debug("  pyproject.toml exists: %s", pyproject.exists())
    logger.debug("  uv.lock path: %s", uv_lock)

    # If no pyproject.toml, not a uv project - require pip
    if not pyproject.exists():
        logger.debug("  No pyproject.toml found")
        if is_pip_available():
            logger.debug("  Selected package lister: PipPackageLister")
            return PipPackageLister(), None
        raise RuntimeError(
            "No pyproject.toml found and pip is not available.\n"
            "osvcheck requires either:\n"
            "  - A pyproject.toml-based project with uv or pip\n"
            "  - pip installed for scanning arbitrary environments\n"
        )

    # pyproject.toml exists - check uv.lock
    if uv_lock is not None:
        if is_uv_lock_current(project_root, uv_lock=uv_lock):
            logger.debug("  uv.lock is current")
            logger.debug("  Selected package lister: UvLockPackageLister")
            return UvLockPackageLister(uv_lock), None
        else:
            logger.debug("  uv.lock is stale")
            warning = "uv.lock is out of date with pyproject.toml"

    # Try uv
    logger.debug("  uv available: %s", is_uv_available())
    if is_uv_available():
        logger.debug("  Selected package lister: UvPackageLister")
        return UvPackageLister(), warning

    # Try pip
    logger.debug("  pip available: %s", is_pip_available())
    if is_pip_available():
        logger.debug("  Selected package lister: PipPackageLister")
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
    """Report vulnerability scan results."""
    for pkg_name in direct_vulnerable:
        logger.warning("⚠️  [DIRECT] %s: vulnerabilities found", pkg_name)

    for pkg_name in indirect_vulnerable:
        logger.warning("  ⚠️ [indirect] %s: vulnerabilities found", pkg_name)

    v_direct = len(direct_vulnerable)
    v_indirect = len(indirect_vulnerable)

    if v_direct or v_indirect:
        logger.info("")
        logger.info("Vulnerabilities found!")
    if v_direct:
        logger.info("  - %d direct dependency vulnerabilities:", v_direct)
        logger.info("    %s", ", ".join(direct_vulnerable))
    if v_indirect:
        logger.info("  - %d indirect dependency vulnerabilities:", v_indirect)
        logger.info("    %s", ", ".join(indirect_vulnerable))

    if not v_direct and not v_indirect:
        logger.info("No vulnerabilities found.")


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
    # Parse CLI arguments
    args = parse_args()

    # Setup logging
    log_level = get_log_level(args)
    setup_logging(
        level=log_level,
        log_file=args.log_file,
        use_json=args.log_json,
        use_color=args.color,
        use_rich=not args.log_json and args.color is not False,
    )

    logger.debug("Starting osvcheck")

    # Detect package manager
    package_lister, warning = detect_package_lister()

    if warning:
        logger.warning(warning)

    # Load dependencies if pyproject.toml exists
    pyproject = Path("pyproject.toml")
    direct_deps = get_direct_dependencies(pyproject) if pyproject.exists() else []
    logger.debug("Loaded %d direct dependencies", len(direct_deps))

    # Load cache
    logger.debug("Loading cache from %s", CACHE_FILE)
    cache = load_cache(CACHE_FILE)
    logger.debug("Cache loaded with %d entries", len(cache))

    # Setup scanner
    osv_client = OSVClient()
    scanner = PackageScanner(osv_client, package_lister)

    # Get package count for display
    all_packages = package_lister.list_packages()
    if direct_deps:
        logger.info(
            "Checking %d packages (%d direct dependencies)...",
            len(all_packages),
            len(direct_deps),
        )
    else:
        logger.info("Checking %d packages...", len(all_packages))

    # Load exceptions: config file (with expiry) + CLI (no expiry required)
    exceptions = load_exceptions(Path.cwd())
    cli_exceptions = set(get_cli_exceptions(args))
    if exceptions:
        logger.debug("Loaded %d exception(s) from config", len(exceptions))
    if cli_exceptions:
        logger.debug("CLI exceptions: %s", ", ".join(sorted(cli_exceptions)))

    # Scan for vulnerabilities
    direct_vulnerable, indirect_vulnerable = scanner.scan_packages(direct_deps, cache)

    # Apply exceptions: warn on expired config exceptions, suppress active ones and CLI ones
    if exceptions or cli_exceptions:
        active = {e.package for e in exceptions if e.is_active()} | cli_exceptions
        for e in exceptions:
            if not e.is_active():
                reason_str = f" ({e.reason})" if e.reason else ""
                logger.warning(
                    "  [expired exception] %s: expired %s%s — vulnerability will be reported",
                    e.package,
                    e.expires.isoformat(),
                    reason_str,
                )
        for pkg in direct_vulnerable + indirect_vulnerable:
            pkg_lower = pkg.lower()
            if pkg_lower in active:
                if pkg_lower in cli_exceptions:
                    logger.info("  [ignored] %s: suppressed via -x/--exception", pkg)
                else:
                    e = next(ex for ex in exceptions if ex.package == pkg_lower)
                    reason_str = f" ({e.reason})" if e.reason else ""
                    logger.info(
                        "  [ignored] %s: suppressed until %s%s",
                        pkg,
                        e.expires.isoformat(),
                        reason_str,
                    )
        direct_vulnerable = [p for p in direct_vulnerable if p.lower() not in active]
        indirect_vulnerable = [
            p for p in indirect_vulnerable if p.lower() not in active
        ]

    # Log statistics
    logger.info(
        "Queries: %d, %d packages",
        scanner.stats.api_queries,
        scanner.stats.cache_misses,
    )
    next_expiry = scanner.stats.get_next_expiry_str()
    expiry_str = f", next expiry: {next_expiry}" if next_expiry else ""
    logger.debug("Cache entries: %d%s", len(cache), expiry_str)

    # Save cache and report
    save_cache(cache, CACHE_FILE)
    logger.debug("Cache saved to %s", CACHE_FILE)

    report_results(direct_vulnerable, indirect_vulnerable)

    # Exit with appropriate code
    exit(determine_exit_code(direct_vulnerable, indirect_vulnerable))


if __name__ == "__main__":
    main()
