"""Tests for configuration loading."""

from datetime import date, timedelta
from pathlib import Path

from osvcheck.config import load_exceptions

FUTURE = (date.today() + timedelta(days=90)).isoformat()
PAST = (date.today() - timedelta(days=1)).isoformat()


def write_toml(path: Path, content: str) -> None:
    path.write_text(content)


# ---------------------------------------------------------------------------
# Basic loading
# ---------------------------------------------------------------------------


def test_no_config_files(tmp_path):
    assert load_exceptions(tmp_path) == []


def test_osvcheck_toml_no_exceptions_section(tmp_path):
    write_toml(tmp_path / "osvcheck.toml", "")
    assert load_exceptions(tmp_path) == []


def test_osvcheck_toml_single_exception(tmp_path):
    write_toml(
        tmp_path / "osvcheck.toml",
        f"[exceptions]\nrequests = {{ expires = {FUTURE} }}\n",
    )
    result = load_exceptions(tmp_path)
    assert len(result) == 1
    assert result[0].package == "requests"
    assert result[0].is_active()
    assert result[0].reason is None


def test_osvcheck_toml_with_reason(tmp_path):
    write_toml(
        tmp_path / "osvcheck.toml",
        f'[exceptions]\nurllib3 = {{ expires = {FUTURE}, reason = "CVE-2023-99" }}\n',
    )
    assert load_exceptions(tmp_path)[0].reason == "CVE-2023-99"


def test_osvcheck_toml_multiple_exceptions(tmp_path):
    write_toml(
        tmp_path / "osvcheck.toml",
        f'[exceptions]\ndjango = {{ expires = {FUTURE}, reason = "some cve" }}\n'
        f'requests = {{ expires = {FUTURE}, reason = "they are lazy bums" }}\n',
    )
    result = load_exceptions(tmp_path)
    assert len(result) == 2
    packages = {e.package for e in result}
    assert packages == {"django", "requests"}


def test_pyproject_toml_exceptions(tmp_path):
    write_toml(
        tmp_path / "pyproject.toml",
        f"[tool.osvcheck.exceptions]\npillow = {{ expires = {FUTURE} }}\n",
    )
    result = load_exceptions(tmp_path)
    assert len(result) == 1
    assert result[0].package == "pillow"


def test_pyproject_toml_no_osvcheck_section(tmp_path):
    write_toml(tmp_path / "pyproject.toml", "[project]\nname = 'myapp'\n")
    assert load_exceptions(tmp_path) == []


def test_osvcheck_toml_takes_precedence(tmp_path):
    write_toml(
        tmp_path / "osvcheck.toml",
        f"[exceptions]\nfrom-standalone = {{ expires = {FUTURE} }}\n",
    )
    write_toml(
        tmp_path / "pyproject.toml",
        f"[tool.osvcheck.exceptions]\nfrom-pyproject = {{ expires = {FUTURE} }}\n",
    )
    result = load_exceptions(tmp_path)
    assert len(result) == 1
    assert result[0].package == "from-standalone"


def test_package_name_lowercased(tmp_path):
    write_toml(
        tmp_path / "osvcheck.toml",
        f"[exceptions]\nDjango = {{ expires = {FUTURE} }}\n",
    )
    assert load_exceptions(tmp_path)[0].package == "django"


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------


def test_active_exception(tmp_path):
    write_toml(
        tmp_path / "osvcheck.toml",
        f"[exceptions]\nrequests = {{ expires = {FUTURE} }}\n",
    )
    assert load_exceptions(tmp_path)[0].is_active()


def test_expired_exception(tmp_path):
    write_toml(
        tmp_path / "osvcheck.toml",
        f"[exceptions]\nrequests = {{ expires = {PAST} }}\n",
    )
    result = load_exceptions(tmp_path)
    assert len(result) == 1
    assert not result[0].is_active()


def test_mixed_active_and_expired(tmp_path):
    write_toml(
        tmp_path / "osvcheck.toml",
        f"[exceptions]\nactive-pkg = {{ expires = {FUTURE} }}\nexpired-pkg = {{ expires = {PAST} }}\n",
    )
    result = load_exceptions(tmp_path)
    assert len(result) == 2
    assert any(e.package == "active-pkg" and e.is_active() for e in result)
    assert any(e.package == "expired-pkg" and not e.is_active() for e in result)


# ---------------------------------------------------------------------------
# Invalid / missing fields are skipped
# ---------------------------------------------------------------------------


def test_missing_expires_skipped(tmp_path):
    write_toml(
        tmp_path / "osvcheck.toml",
        "[exceptions]\nrequests = { reason = 'no expiry set' }\n",
    )
    assert load_exceptions(tmp_path) == []


def test_string_date_accepted(tmp_path):
    # Quoted ISO string should also parse correctly
    write_toml(
        tmp_path / "osvcheck.toml",
        f'[exceptions]\nrequests = {{ expires = "{FUTURE}" }}\n',
    )
    result = load_exceptions(tmp_path)
    assert len(result) == 1
    assert result[0].is_active()
