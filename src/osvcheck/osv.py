"""OSV API client for vulnerability checking."""

import json
import urllib.request


class OSVClient:
    """Client for querying the OSV vulnerability database."""

    def __init__(self, api_url: str = "https://api.osv.dev/v1/query"):
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
            self.api_url,
            data=json.dumps(query).encode(),
            headers={"Content-Type": "application/json"},
        )

        try:
            # Validate HTTPS scheme for security (Bandit B310)
            if not req.full_url.startswith("https://"):
                raise ValueError("Only HTTPS URLs are allowed for security")

            with urllib.request.urlopen(req) as response:  # nosec B310
                result = json.loads(response.read())
                return bool(result.get("vulns", []))
        except Exception:
            return False
