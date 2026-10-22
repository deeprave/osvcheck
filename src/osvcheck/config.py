"""Configuration loading for osvcheck."""

import tomllib
from dataclasses import dataclass
from datetime import date
from pathlib import Path


@dataclass
class PackageException:
    """A single package exception entry."""

    package: str
    expires: date | None = None
    reason: str | None = None

    def is_active(self) -> bool:
        """Return True if the exception is permanent or has not yet expired."""
        return self.expires is None or date.today() <= self.expires

    def is_permanent(self) -> bool:
        """Return True if the exception does not expire."""
        return self.expires is None


def _parse_exceptions(raw: object) -> list[PackageException]:
    """Parse exceptions from a {package: {expires | permanent, reason?}} dict."""
    if not isinstance(raw, dict):
        return []

    result = []
    for package, entry in raw.items():
        if not isinstance(entry, dict):
            continue

        expires = entry.get("expires")
        permanent = entry.get("permanent")
        if permanent is True:
            if expires is not None:
                continue
        elif expires is None:
            continue
        else:
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


def load_exceptions(project_root: Path) -> list[PackageException]:
    """Load package exceptions from osvcheck.toml or pyproject.toml.

    Format (osvcheck.toml)::

        [exceptions]
        requests = { expires = 2026-06-01, reason = "waiting for upstream" }
        django   = { expires = 2026-04-20, reason = "some cve" }
        certifi  = { permanent = true, reason = "httpx uses the system keychain" }

    Format (pyproject.toml)::

        [tool.osvcheck.exceptions]
        requests = { expires = 2026-06-01, reason = "waiting for upstream" }
        django   = { expires = 2026-04-20, reason = "some cve" }
        certifi  = { permanent = true, reason = "httpx uses the system keychain" }

    osvcheck.toml takes precedence if both files exist.

    Each exception must specify exactly one of ``expires`` or
    ``permanent = true``.

    Exceptions whose ``expires`` date has passed are returned but marked
    inactive — callers should warn the user and not suppress those packages.
    """
    osvcheck_toml = project_root / "osvcheck.toml"
    if osvcheck_toml.exists():
        try:
            with open(osvcheck_toml, "rb") as f:
                data = tomllib.load(f)
            return _parse_exceptions(data.get("exceptions", {}))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, AttributeError):
            return []

    pyproject = project_root / "pyproject.toml"
    if pyproject.exists():
        try:
            with open(pyproject, "rb") as f:
                data = tomllib.load(f)
            raw = data.get("tool", {}).get("osvcheck", {}).get("exceptions", {})
            return _parse_exceptions(raw)
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, AttributeError):
            return []

    return []
