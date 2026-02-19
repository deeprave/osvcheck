"""Tests for dependency parsing."""

from osvcheck.dependencies import (
    get_direct_dependencies,
    is_direct_dependency,
    parse_package_name,
)


def test_parse_package_name():
    assert parse_package_name("requests") == "requests"
    assert parse_package_name("requests>=2.0") == "requests"
    assert parse_package_name("Django~=4.2.0") == "django"
    assert parse_package_name("flask[extra]>=1.0") == "flask"
    assert parse_package_name("pytest!=7.0.0") == "pytest"


def test_get_direct_dependencies(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("""
[project]
name = "test"
dependencies = [
    "requests>=2.0",
    "Django~=4.2",
    "flask[extra]",
]
""")
    
    deps = get_direct_dependencies(pyproject)
    assert deps == ["requests", "django", "flask"]


def test_get_direct_dependencies_no_deps(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("""
[project]
name = "test"
""")
    
    deps = get_direct_dependencies(pyproject)
    assert deps == []


def test_get_direct_dependencies_missing_file(tmp_path):
    pyproject = tmp_path / "missing.toml"
    deps = get_direct_dependencies(pyproject)
    assert deps == []


def test_is_direct_dependency():
    direct_deps = ["requests", "django", "flask"]
    
    assert is_direct_dependency("requests", direct_deps)
    assert is_direct_dependency("Django", direct_deps)
    assert not is_direct_dependency("pytest", direct_deps)
