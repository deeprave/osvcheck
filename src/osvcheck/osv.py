"""OSV API client for vulnerability checking."""

import json
import urllib.request
from typing import Dict, List, Tuple


class OSVClient:
    """Client for querying the OSV vulnerability database."""

    def __init__(self, api_url: str = "https://api.osv.dev/v1"):
        self.api_url = api_url

    def check_vulnerability(self, pkg_name: str, pkg_version: str) -> bool:
        """Check if package version has known vulnerabilities.

        Returns:
            True if vulnerabilities found, False otherwise.
        """
        query = {
            "package": {"ecosystem": "PyPI", "name": pkg_name},
            "version": pkg_version,
        }

        req = urllib.request.Request(
            f"{self.api_url}/query",
            data=json.dumps(query).encode(),
            headers={"Content-Type": "application/json"},
        )

        try:
            if not req.full_url.startswith("https://"):
                raise ValueError("Only HTTPS URLs are allowed for security")

            with urllib.request.urlopen(req) as response:  # nosec B310
                result = json.loads(response.read())
                return bool(result.get("vulns", []))
        except Exception:
            return False

    def check_vulnerabilities_batch(
        self, packages: List[Tuple[str, str]]
    ) -> Dict[Tuple[str, str], bool]:
        """Check multiple packages for vulnerabilities in a single request.

        Args:
            packages: List of (pkg_name, pkg_version) tuples

        Returns:
            Dict mapping (pkg_name, pkg_version) to vulnerability status
        """
        queries = [
            {"package": {"ecosystem": "PyPI", "name": name}, "version": version}
            for name, version in packages
        ]

        req = urllib.request.Request(
            f"{self.api_url}/querybatch",
            data=json.dumps({"queries": queries}).encode(),
            headers={"Content-Type": "application/json"},
        )

        try:
            if not req.full_url.startswith("https://"):
                raise ValueError("Only HTTPS URLs are allowed for security")

            with urllib.request.urlopen(req) as response:  # nosec B310
                result = json.loads(response.read())
                return {
                    packages[i]: bool(r.get("vulns", []))
                    for i, r in enumerate(result.get("results", []))
                }
        except Exception:
            return {pkg: False for pkg in packages}
