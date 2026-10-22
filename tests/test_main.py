"""Tests for CLI orchestration."""

import logging
from argparse import Namespace
from datetime import date, timedelta
from types import SimpleNamespace

import pytest

import osvcheck
from osvcheck.config import PackageException


def test_main_prefers_active_exception_over_expired_duplicate(monkeypatch, caplog):
    """A permanent exception suppresses reporting from an expired duplicate."""
    args = Namespace(log_file=None, log_json=False, color=None)
    scanner = SimpleNamespace(
        scan_packages=lambda direct_deps, cache: ([], ["certifi"]),
        stats=SimpleNamespace(
            api_queries=0,
            cache_misses=0,
            get_next_expiry_str=lambda: None,
        ),
    )
    exceptions = [
        PackageException("certifi", expires=date.today() - timedelta(days=1)),
        PackageException("certifi"),
    ]

    monkeypatch.setattr(osvcheck, "parse_args", lambda: args)
    monkeypatch.setattr(osvcheck, "get_log_level", lambda args: logging.INFO)
    monkeypatch.setattr(osvcheck, "setup_logging", lambda **kwargs: logging.getLogger())
    monkeypatch.setattr(
        osvcheck,
        "detect_package_lister",
        lambda: (SimpleNamespace(list_packages=list), None),
    )
    monkeypatch.setattr(osvcheck, "get_direct_dependencies", lambda path: [])
    monkeypatch.setattr(osvcheck, "load_cache", lambda path: {})
    monkeypatch.setattr(osvcheck, "load_exceptions", lambda path: exceptions)
    monkeypatch.setattr(osvcheck, "get_cli_exceptions", lambda args: [])
    monkeypatch.setattr(osvcheck, "PackageScanner", lambda *args: scanner)
    monkeypatch.setattr(osvcheck, "save_cache", lambda cache, path: None)

    with (
        caplog.at_level(logging.INFO, logger="osvcheck"),
        pytest.raises(SystemExit) as result,
    ):
        osvcheck.main()

    assert result.value.code == 0
    assert "suppressed permanently" in caplog.text
    assert "expired exception" not in caplog.text
