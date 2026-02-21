"""Tests for scanner logic."""

from typing import Dict, List, Tuple

from osvcheck.scanner import PackageScanner


class FakeOSVClient:
    """Fake OSV client for testing."""

    def __init__(self, vulnerable_packages: set[str]):
        self.vulnerable_packages = vulnerable_packages

    def check_vulnerability(self, pkg_name: str, pkg_version: str) -> bool:
        return pkg_name in self.vulnerable_packages

    def check_vulnerabilities_batch(
        self, packages: List[Tuple[str, str]]
    ) -> Dict[Tuple[str, str], bool]:
        return {(name, ver): name in self.vulnerable_packages for name, ver in packages}


class FakePackageLister:
    """Fake package lister for testing."""

    def __init__(self, packages: List[Dict[str, str]]):
        self.packages = packages

    def list_packages(self) -> List[Dict[str, str]]:
        return self.packages


def test_scanner_identifies_direct_vulnerabilities():
    osv_client = FakeOSVClient({"vulnerable-pkg"})
    package_lister = FakePackageLister(
        [
            {"name": "vulnerable-pkg", "version": "1.0"},
            {"name": "safe-pkg", "version": "2.0"},
        ]
    )

    scanner = PackageScanner(osv_client, package_lister)
    direct, indirect = scanner.scan_packages(["vulnerable-pkg"], {})

    assert direct == ["vulnerable-pkg"]
    assert indirect == []


def test_scanner_identifies_indirect_vulnerabilities():
    osv_client = FakeOSVClient({"transitive-vuln"})
    package_lister = FakePackageLister(
        [
            {"name": "my-pkg", "version": "1.0"},
            {"name": "transitive-vuln", "version": "2.0"},
        ]
    )

    scanner = PackageScanner(osv_client, package_lister)
    direct, indirect = scanner.scan_packages(["my-pkg"], {})

    assert direct == []
    assert indirect == ["transitive-vuln"]


def test_scanner_uses_cache():
    osv_client = FakeOSVClient(set())
    package_lister = FakePackageLister(
        [
            {"name": "cached-pkg", "version": "1.0"},
        ]
    )

    cache = {"cached-pkg:1.0": {"dep_type": "direct", "expires_at": 9999999999}}

    scanner = PackageScanner(osv_client, package_lister)
    direct, indirect = scanner.scan_packages(["cached-pkg"], cache)

    assert direct == ["cached-pkg"]
    assert indirect == []
    assert scanner.stats.cache_hits == 1
    assert scanner.stats.cache_misses == 0
    assert scanner.stats.api_queries == 0


def test_scanner_cache_hit_clean_package():
    osv_client = FakeOSVClient(set())
    package_lister = FakePackageLister(
        [
            {"name": "clean-pkg", "version": "1.0"},
        ]
    )

    cache = {"clean-pkg:1.0": {"dep_type": None, "expires_at": 9999999999}}

    scanner = PackageScanner(osv_client, package_lister)
    direct, indirect = scanner.scan_packages(["clean-pkg"], cache)

    assert direct == []
    assert indirect == []
    assert scanner.stats.cache_hits == 1
    assert scanner.stats.cache_misses == 0
    assert scanner.stats.api_queries == 0


def test_scanner_no_vulnerabilities():
    osv_client = FakeOSVClient(set())
    package_lister = FakePackageLister(
        [
            {"name": "safe-pkg", "version": "1.0"},
        ]
    )

    scanner = PackageScanner(osv_client, package_lister)
    direct, indirect = scanner.scan_packages(["safe-pkg"], {})

    assert direct == []
    assert indirect == []


def test_scanner_batches_uncached_packages():
    osv_client = FakeOSVClient({"vuln-pkg-1", "vuln-pkg-3"})
    package_lister = FakePackageLister(
        [
            {"name": "vuln-pkg-1", "version": "1.0"},
            {"name": "safe-pkg-2", "version": "2.0"},
            {"name": "vuln-pkg-3", "version": "3.0"},
        ]
    )

    scanner = PackageScanner(osv_client, package_lister)
    direct, indirect = scanner.scan_packages(["vuln-pkg-1"], {})

    assert direct == ["vuln-pkg-1"]
    assert indirect == ["vuln-pkg-3"]
    assert scanner.stats.api_queries == 1
