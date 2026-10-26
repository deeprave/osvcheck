"""Tests for CLI orchestration."""

import logging
from argparse import Namespace
from datetime import date, timedelta
from types import SimpleNamespace

import pytest

import osvcheck
from osvcheck.config import PackageException
from osvcheck.scanner import PipPackageLister, UvPackageLister


def create_virtualenv(root, name):
    venv = root / name
    venv.mkdir()
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\n")
    (venv / "lib").mkdir()
    bin_dir = venv / "bin"
    bin_dir.mkdir()
    (bin_dir / "python").touch()
    return venv


def create_uv_virtualenv(root, name):
    venv = create_virtualenv(root, name)
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\nuv = 0.13.5\n")
    return venv


def test_detect_package_lister_prefers_explicit_python(monkeypatch, tmp_path):
    explicit_python = tmp_path / "custom-python"
    explicit_python.touch()
    venv = create_virtualenv(tmp_path, "myvirtualenv")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(osvcheck, "is_pip_available", lambda executable: True)

    lister, warning = osvcheck.detect_package_lister(
        python_executable=explicit_python,
        venv_path=venv,
    )

    assert isinstance(lister, PipPackageLister)
    assert lister.python_executable == explicit_python
    assert warning is None


def test_detect_package_lister_uses_virtual_env(monkeypatch, tmp_path):
    venv = create_virtualenv(tmp_path, "myvirtualenv")
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'test'\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("VIRTUAL_ENV", str(venv))
    monkeypatch.setattr(osvcheck, "is_pip_available", lambda executable: True)

    lister, warning = osvcheck.detect_package_lister()

    assert isinstance(lister, PipPackageLister)
    assert lister.python_executable == venv / "bin" / "python"
    assert warning is None


def test_detect_package_lister_uses_uv_for_virtual_env_without_pip(
    monkeypatch, tmp_path
):
    venv = create_virtualenv(tmp_path, "myvirtualenv")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("VIRTUAL_ENV", str(venv))
    monkeypatch.setattr(osvcheck, "is_pip_available", lambda executable: False)
    monkeypatch.setattr(osvcheck, "is_uv_available", lambda: True)

    lister, warning = osvcheck.detect_package_lister()

    assert isinstance(lister, UvPackageLister)
    assert warning == (
        f"pip is not available for {venv / 'bin' / 'python'}; scanning with uv instead.\n"
        f"Run: {venv / 'bin' / 'python'} -m ensurepip to enable pip scanning."
    )


def test_detect_package_lister_uses_uv_for_uv_managed_virtual_env(
    monkeypatch, tmp_path
):
    venv = create_uv_virtualenv(tmp_path, "myvirtualenv")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("VIRTUAL_ENV", str(venv))

    lister, warning = osvcheck.detect_package_lister()

    assert isinstance(lister, UvPackageLister)
    assert warning is None


def test_detect_package_lister_requires_selection_for_multiple_virtualenvs(
    monkeypatch, tmp_path
):
    create_virtualenv(tmp_path, "first")
    create_virtualenv(tmp_path, "second")
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'test'\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("VIRTUAL_ENV", raising=False)

    with pytest.raises(RuntimeError, match="Use --venv or --python"):
        osvcheck.detect_package_lister()


def test_detect_package_lister_rejects_local_virtualenv_without_python(
    monkeypatch, tmp_path
):
    venv = create_virtualenv(tmp_path, "myvirtualenv")
    (venv / "bin" / "python").unlink()
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("VIRTUAL_ENV", raising=False)

    with pytest.raises(RuntimeError, match="No Python interpreter found"):
        osvcheck.detect_package_lister()


def test_detect_package_lister_uses_uv_for_local_virtualenv_without_pip(
    monkeypatch, tmp_path
):
    venv = create_virtualenv(tmp_path, "myvirtualenv")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("VIRTUAL_ENV", raising=False)
    monkeypatch.setattr(osvcheck, "is_pip_available", lambda executable: False)
    monkeypatch.setattr(osvcheck, "is_uv_available", lambda: True)

    lister, warning = osvcheck.detect_package_lister()

    assert isinstance(lister, UvPackageLister)
    assert warning == (
        f"pip is not available for {venv / 'bin' / 'python'}; scanning with uv instead.\n"
        f"Run: {venv / 'bin' / 'python'} -m ensurepip to enable pip scanning."
    )


def test_detect_package_lister_reports_how_to_install_missing_pip(
    monkeypatch, tmp_path
):
    explicit_python = tmp_path / "custom-python"
    explicit_python.touch()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(osvcheck, "is_pip_available", lambda executable: False)

    with pytest.raises(RuntimeError, match=r"custom-python -m ensurepip"):
        osvcheck.detect_package_lister(python_executable=explicit_python)


def test_main_prefers_active_exception_over_expired_duplicate(monkeypatch, caplog):
    """A permanent exception suppresses reporting from an expired duplicate."""
    args = Namespace(log_file=None, log_json=False, color=None, python=None, venv=None)
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
        lambda **kwargs: (SimpleNamespace(list_packages=list), None),
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
