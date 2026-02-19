"""Package scanning logic."""

from pathlib import Path
from typing import Any, Dict, List, Protocol, Tuple

from .cache import get_cached_result, update_cache
from .dependencies import is_direct_dependency
from .package_detection import get_packages_via_pip, get_packages_via_uv, parse_uv_lock


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

    def scan_packages(
        self, direct_deps: List[str], cache: Dict[str, Dict[str, Any]]
    ) -> Tuple[List[str], List[str]]:
        """Scan packages for vulnerabilities.

        Returns:
            Tuple of (direct_vulnerable, indirect_vulnerable) package names.
        """
        all_packages = self.package_lister.list_packages()
        direct_vulnerable = []
        indirect_vulnerable = []

        for pkg in all_packages:
            pkg_name = pkg["name"]
            pkg_version = pkg["version"]
            is_direct = is_direct_dependency(pkg_name, direct_deps)

            # Check cache first
            cached = get_cached_result(cache, pkg_name, pkg_version)
            if cached:
                has_vuln = cached in ("direct", "indirect")
            else:
                # Query API
                has_vuln = self.osv_client.check_vulnerability(pkg_name, pkg_version)
                vuln_type = (
                    ("direct" if is_direct else "indirect") if has_vuln else None
                )
                update_cache(cache, pkg_name, pkg_version, vuln_type)

            if has_vuln:
                if is_direct:
                    direct_vulnerable.append(pkg_name)
                else:
                    indirect_vulnerable.append(pkg_name)

        return direct_vulnerable, indirect_vulnerable
