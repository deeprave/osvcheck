"""Tests for scanner logic."""

from typing import Dict, List

from osvcheck.scanner import PackageScanner


class FakeOSVClient:
    """Fake OSV client for testing."""

    def __init__(self, vulnerable_packages: set[str]):
        self.vulnerable_packages = vulnerable_packages

    def check_vulnerability(self, pkg_name: str, pkg_version: str) -> bool:
        return pkg_name in self.vulnerable_packages


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

    cache = {"cached-pkg:1.0": {"vuln_type": "direct", "expires_at": 9999999999}}

    scanner = PackageScanner(osv_client, package_lister)
    direct, indirect = scanner.scan_packages(["cached-pkg"], cache)

    assert direct == ["cached-pkg"]
    assert indirect == []


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
