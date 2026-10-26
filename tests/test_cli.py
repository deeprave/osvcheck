"""Tests for command-line parsing."""

from pathlib import Path

from osvcheck.cli import parse_args


def test_parse_args_accepts_python_and_venv_paths(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        ["osvcheck", "--python", "/tmp/python", "--venv", "/tmp/venv"],
    )

    args = parse_args()

    assert args.python == Path("/tmp/python")
    assert args.venv == Path("/tmp/venv")
