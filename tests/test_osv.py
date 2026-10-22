"""Tests for OSV API failure handling."""

from http.client import IncompleteRead
from unittest.mock import patch

from osvcheck.osv import OSVClient


def test_single_query_returns_false_on_http_exception():
    """An incomplete HTTP response does not abort a single-package scan."""
    with patch(
        "osvcheck.osv.urllib.request.urlopen",
        side_effect=IncompleteRead(b"", 1),
    ):
        assert OSVClient().check_vulnerability("example", "1.0.0") is False


def test_batch_query_returns_empty_results_on_http_exception():
    """An incomplete HTTP response does not abort a batch scan."""
    packages = [("example", "1.0.0")]
    with patch(
        "osvcheck.osv.urllib.request.urlopen",
        side_effect=IncompleteRead(b"", 1),
    ):
        assert OSVClient().check_vulnerabilities_batch(packages) == {
            ("example", "1.0.0"): False
        }
