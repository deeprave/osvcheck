"""Tests for package detection."""

import subprocess
import time

import pytest

from osvcheck import package_detection


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

    packages = package_detection.parse_uv_lock(uv_lock)
    assert len(packages) == 2
    assert packages[0] == {"name": "requests", "version": "2.31.0"}
    assert packages[1] == {"name": "urllib3", "version": "2.0.0"}


def test_parse_uv_lock_missing_file(tmp_path):
    """Test parsing missing uv.lock file."""
    uv_lock = tmp_path / "missing.lock"
    packages = package_detection.parse_uv_lock(uv_lock)
    assert packages == []


@pytest.mark.parametrize(
    ("uv_returncode", "expected"),
    [(0, True), (1, False)],
    ids=["current", "stale"],
)
def test_is_uv_lock_current_uses_uv_lock_check(
    tmp_path, monkeypatch, uv_returncode, expected
):
    """Use uv's own lock check when uv is available."""
    uv_lock = tmp_path / "uv.lock"
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = 'test'")
    uv_lock.write_text("[[package]]")

    monkeypatch.setattr(package_detection, "is_uv_available", lambda: True)

    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, uv_returncode)

    monkeypatch.setattr(package_detection.subprocess, "run", fake_run)

    assert package_detection.is_uv_lock_current(tmp_path) is expected
    assert calls == [
        (
            ["uv", "lock", "--check"],
            {
                "cwd": tmp_path,
                "capture_output": True,
                "text": True,
                "check": False,
            },
        )
    ]


@pytest.mark.parametrize(
    ("lock_after_pyproject", "expected"),
    [(True, True), (False, False)],
    ids=["lock-newer", "pyproject-newer"],
)
def test_is_uv_lock_current_falls_back_to_mtime_when_uv_is_unavailable(
    tmp_path, monkeypatch, lock_after_pyproject, expected
):
    """Fall back to mtime comparison when uv is unavailable."""
    uv_lock = tmp_path / "uv.lock"
    pyproject = tmp_path / "pyproject.toml"

    monkeypatch.setattr(package_detection, "is_uv_available", lambda: False)

    if lock_after_pyproject:
        pyproject.write_text("[project]\nname = 'test'")
        time.sleep(0.01)
        uv_lock.write_text("[[package]]")
    else:
        uv_lock.write_text("[[package]]")
        time.sleep(0.01)
        pyproject.write_text("[project]\nname = 'test'")

    assert package_detection.is_uv_lock_current(tmp_path) is expected


@pytest.mark.parametrize(
    ("lock_after_pyproject", "expected"),
    [(True, True), (False, False)],
    ids=["lock-newer", "pyproject-newer"],
)
def test_is_uv_lock_current_falls_back_to_mtime_for_unexpected_uv_exit(
    tmp_path, monkeypatch, lock_after_pyproject, expected
):
    """Fall back to mtime comparison for unexpected uv return codes."""
    uv_lock = tmp_path / "uv.lock"
    pyproject = tmp_path / "pyproject.toml"

    monkeypatch.setattr(package_detection, "is_uv_available", lambda: True)

    if lock_after_pyproject:
        pyproject.write_text("[project]\nname = 'test'")
        time.sleep(0.01)
        uv_lock.write_text("[[package]]")
    else:
        uv_lock.write_text("[[package]]")
        time.sleep(0.01)
        pyproject.write_text("[project]\nname = 'test'")

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 2)

    monkeypatch.setattr(package_detection.subprocess, "run", fake_run)

    assert package_detection.is_uv_lock_current(tmp_path) is expected


@pytest.mark.parametrize(
    "uv_error",
    [OSError("uv failed"), subprocess.SubprocessError("uv failed")],
    ids=["os-error", "subprocess-error"],
)
def test_is_uv_lock_current_falls_back_to_mtime_when_uv_check_fails(
    tmp_path, monkeypatch, uv_error
):
    """Fall back to mtime comparison if invoking uv fails."""
    uv_lock = tmp_path / "uv.lock"
    pyproject = tmp_path / "pyproject.toml"

    pyproject.write_text("[project]\nname = 'test'")
    time.sleep(0.01)
    uv_lock.write_text("[[package]]")

    monkeypatch.setattr(package_detection, "is_uv_available", lambda: True)

    def fake_run(command, **kwargs):
        raise uv_error

    monkeypatch.setattr(package_detection.subprocess, "run", fake_run)

    assert package_detection.is_uv_lock_current(tmp_path)


def test_is_uv_lock_current_does_not_hide_unexpected_uv_check_errors(
    tmp_path, monkeypatch
):
    """Only expected subprocess failures fall back to mtime comparison."""
    uv_lock = tmp_path / "uv.lock"
    pyproject = tmp_path / "pyproject.toml"

    pyproject.write_text("[project]\nname = 'test'")
    uv_lock.write_text("[[package]]")

    monkeypatch.setattr(package_detection, "is_uv_available", lambda: True)

    def fake_run(command, **kwargs):
        raise TypeError("programming error")

    monkeypatch.setattr(package_detection.subprocess, "run", fake_run)

    with pytest.raises(TypeError, match="programming error"):
        package_detection.is_uv_lock_current(tmp_path)


def test_is_uv_lock_current_missing_files(tmp_path):
    """Test when files don't exist."""
    assert not package_detection.is_uv_lock_current(tmp_path)
