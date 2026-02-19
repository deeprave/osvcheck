"""Tests for package detection."""

import time

from osvcheck.package_detection import is_uv_lock_current, parse_uv_lock


def test_parse_uv_lock(tmp_path):
    """Test parsing uv.lock file."""
    uv_lock = tmp_path / "uv.lock"
    uv_lock.write_text(
        """
[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "urllib3"
version = "2.0.0"
"""
    )

    packages = parse_uv_lock(uv_lock)
    assert len(packages) == 2
    assert packages[0] == {"name": "requests", "version": "2.31.0"}
    assert packages[1] == {"name": "urllib3", "version": "2.0.0"}


def test_parse_uv_lock_missing_file(tmp_path):
    """Test parsing missing uv.lock file."""
    uv_lock = tmp_path / "missing.lock"
    packages = parse_uv_lock(uv_lock)
    assert packages == []


def test_is_uv_lock_current(tmp_path):
    """Test uv.lock staleness detection."""
    uv_lock = tmp_path / "uv.lock"
    pyproject = tmp_path / "pyproject.toml"

    # Create pyproject first
    pyproject.write_text("[project]\nname = 'test'")
    time.sleep(0.01)

    # Create uv.lock after (current)
    uv_lock.write_text("[[package]]")

    assert is_uv_lock_current(tmp_path)


def test_is_uv_lock_stale(tmp_path):
    """Test detecting stale uv.lock."""
    uv_lock = tmp_path / "uv.lock"
    pyproject = tmp_path / "pyproject.toml"

    # Create uv.lock first
    uv_lock.write_text("[[package]]")
    time.sleep(0.01)

    # Update pyproject after (makes lock stale)
    pyproject.write_text("[project]\nname = 'test'")

    assert not is_uv_lock_current(tmp_path)


def test_is_uv_lock_current_missing_files(tmp_path):
    """Test when files don't exist."""
    assert not is_uv_lock_current(tmp_path)
