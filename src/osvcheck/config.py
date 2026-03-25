"""Configuration loading for osvcheck."""

import tomllib
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import List, Optional


@dataclass
class PackageException:
    """A single package exception entry."""

    package: str
    expires: date
    reason: Optional[str] = None

    def is_active(self) -> bool:
        """Return True if the exception has not yet expired."""
        return date.today() <= self.expires


def _parse_exceptions(raw: object) -> List[PackageException]:
    """Parse exceptions from a {package: {expires, reason?}} dict."""
    if not isinstance(raw, dict):
        return []

    result = []
    for package, entry in raw.items():
        if not isinstance(entry, dict):
            continue

        expires = entry.get("expires")
        if expires is None:
            continue
        # Native TOML dates arrive as datetime.date; accept ISO strings too
        if isinstance(expires, str):
            try:
                expires = date.fromisoformat(expires)
            except ValueError:
                continue
        if not isinstance(expires, date):
            continue

        reason = entry.get("reason")
        result.append(
            PackageException(
                package=package.strip().lower(),
                expires=expires,
                reason=reason if isinstance(reason, str) else None,
            )
        )

    return result


def load_exceptions(project_root: Path) -> List[PackageException]:
    """Load package exceptions from osvcheck.toml or pyproject.toml.

    Format (osvcheck.toml)::

        [exceptions]
        requests = { expires = 2026-06-01, reason = "waiting for upstream" }
        django   = { expires = 2026-04-20, reason = "some cve" }

    Format (pyproject.toml)::

        [tool.osvcheck.exceptions]
        requests = { expires = 2026-06-01, reason = "waiting for upstream" }
        django   = { expires = 2026-04-20, reason = "some cve" }

    osvcheck.toml takes precedence if both files exist.

    Exceptions whose ``expires`` date has passed are returned but marked
    inactive — callers should warn the user and not suppress those packages.
    """
    osvcheck_toml = project_root / "osvcheck.toml"
    if osvcheck_toml.exists():
        try:
            with open(osvcheck_toml, "rb") as f:
                data = tomllib.load(f)
            return _parse_exceptions(data.get("exceptions", {}))
        except Exception:
            return []

    pyproject = project_root / "pyproject.toml"
    if pyproject.exists():
        try:
            with open(pyproject, "rb") as f:
                data = tomllib.load(f)
            raw = data.get("tool", {}).get("osvcheck", {}).get("exceptions", {})
            return _parse_exceptions(raw)
        except Exception:
            return []

    return []
