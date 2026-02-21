"""Package scanning logic."""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Tuple

from .cache import get_cached_result, update_cache
from .dependencies import is_direct_dependency
from .package_detection import get_packages_via_pip, get_packages_via_uv, parse_uv_lock

logger = logging.getLogger("osvcheck")


class ScanStatistics:
    """Track scanning statistics."""

    def __init__(self) -> None:
        self.cache_hits = 0
        self.cache_misses = 0
        self.api_queries = 0
        self.packages_scanned = 0
        self.next_expiry: Optional[float] = None

    def update_next_expiry(self, expires_at: float) -> None:
        """Update next expiry time."""
        if self.next_expiry is None or expires_at < self.next_expiry:
            self.next_expiry = expires_at

    def get_next_expiry_str(self) -> Optional[str]:
        """Get formatted next expiry time."""
        if self.next_expiry:
            return datetime.fromtimestamp(self.next_expiry).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        return None


class PackageLister(Protocol):
    """Protocol for listing installed packages."""

    def list_packages(self) -> List[Dict[str, str]]:
        """Return list of installed packages with 'name' and 'version' keys."""
        ...


class UvLockPackageLister:
    """Package lister using uv.lock file."""

    def __init__(self, uv_lock_path: Path):
        self.uv_lock_path = uv_lock_path

    def list_packages(self) -> List[Dict[str, str]]:
        """Get packages from uv.lock."""
        return parse_uv_lock(self.uv_lock_path)


class UvPackageLister:
    """Package lister using uv pip list."""

    def list_packages(self) -> List[Dict[str, str]]:
        """Get all installed packages using uv."""
        return get_packages_via_uv()


class PipPackageLister:
    """Package lister using pip list."""

    def list_packages(self) -> List[Dict[str, str]]:
        """Get all installed packages using pip."""
        return get_packages_via_pip()


class PackageScanner:
    """Coordinates vulnerability scanning of packages."""

    def __init__(self, osv_client: Any, package_lister: PackageLister):
        self.osv_client = osv_client
        self.package_lister = package_lister
        self.stats = ScanStatistics()

    def scan_packages(
        self, direct_deps: List[str], cache: Dict[str, Dict[str, Any]]
    ) -> Tuple[List[str], List[str]]:
        """Scan packages for vulnerabilities.

        Returns:
            Tuple of (direct_vulnerable, indirect_vulnerable) package names.
        """
        all_packages = self.package_lister.list_packages()
        direct_vulnerable: List[str] = []
        indirect_vulnerable: List[str] = []

        # Calculate next expiry from cache
        for entry in cache.values():
            if "expires_at" in entry:
                self.stats.update_next_expiry(entry["expires_at"])

        # Separate cached and uncached packages
        uncached_packages = []
        for pkg in all_packages:
            pkg_name = pkg["name"]
            pkg_version = pkg["version"]
            is_direct = is_direct_dependency(pkg_name, direct_deps)

            self.stats.packages_scanned += 1

            cached = get_cached_result(cache, pkg_name, pkg_version)
            if cached:
                self.stats.cache_hits += 1
                dep_type = "direct" if is_direct else "indirect"
                logger.debug("  %s:%s cache hit (%s)", pkg_name, pkg_version, dep_type)
                if cached in ("direct", "indirect"):
                    (direct_vulnerable if is_direct else indirect_vulnerable).append(
                        pkg_name
                    )
            else:
                self.stats.cache_misses += 1
                dep_type = "direct" if is_direct else "indirect"
                logger.debug("  %s:%s cache miss (%s)", pkg_name, pkg_version, dep_type)
                uncached_packages.append((pkg_name, pkg_version, is_direct))

        # Batch query uncached packages
        logger.info(
            "Cache scan: %d packages processed, %d hits (skipped), %d misses",
            len(all_packages),
            self.stats.cache_hits,
            self.stats.cache_misses,
        )

        if uncached_packages:
            batch_size = 256
            for i in range(0, len(uncached_packages), batch_size):
                batch = uncached_packages[i : i + batch_size]
                pkg_tuples = [(name, ver) for name, ver, _ in batch]

                logger.debug(
                    "  Batch querying %d packages (batch %d/%d)",
                    len(pkg_tuples),
                    i // batch_size + 1,
                    (len(uncached_packages) + batch_size - 1) // batch_size,
                )

                self.stats.api_queries += 1
                results = self.osv_client.check_vulnerabilities_batch(pkg_tuples)

                for (pkg_name, pkg_version, is_direct), has_vuln in zip(
                    batch, [results.get((n, v), False) for n, v in pkg_tuples]
                ):
                    vuln_status = "vulnerability" if has_vuln else "no vulnerability"
                    logger.debug("  %s:%s %s", pkg_name, pkg_version, vuln_status)
                    vuln_type = (
                        ("direct" if is_direct else "indirect") if has_vuln else None
                    )
                    update_cache(cache, pkg_name, pkg_version, vuln_type)

                    if has_vuln:
                        (
                            direct_vulnerable if is_direct else indirect_vulnerable
                        ).append(pkg_name)

        return direct_vulnerable, indirect_vulnerable
