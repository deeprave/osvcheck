"""Cache operations for vulnerability scan results."""

import json
import random
import time
from pathlib import Path
from typing import Any

CACHE_MIN_TTL = 12 * 3600  # 12 hours in seconds
CACHE_MAX_TTL = 48 * 3600  # 48 hours in seconds


def get_cache_key(pkg_name: str, pkg_version: str) -> str:
    """Generate cache key for a package."""
    return f"{pkg_name}:{pkg_version}"


def is_cache_entry_valid(entry: dict[str, Any], current_time: float) -> bool:
    """Check if cache entry is still valid."""
    return entry.get("expires_at", 0) > current_time


def generate_cache_ttl() -> int:
    """Generate random TTL between min and max."""
    return random.randint(CACHE_MIN_TTL, CACHE_MAX_TTL)


def load_cache(cache_file: Path) -> dict[str, dict[str, Any]]:
    """Load cache from file, removing expired entries."""
    if not cache_file.exists():
        return {}

    try:
        with open(cache_file, "r") as f:
            cache = json.load(f)

        # Remove expired entries
        current_time = time.time()
        return {k: v for k, v in cache.items() if is_cache_entry_valid(v, current_time)}
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        AttributeError,
        TypeError,
    ):
        return {}


def save_cache(cache: dict[str, dict[str, Any]], cache_file: Path) -> None:
    """Save cache to file."""
    try:
        with open(cache_file, "w") as f:
            json.dump(cache, f, indent=2)
    except (OSError, TypeError, ValueError):
        return


def get_cached_result(
    cache: dict[str, dict[str, Any]], pkg_name: str, pkg_version: str
) -> tuple[bool, str | None]:
    """Get cached vulnerability result for a package.

    Returns:
        Tuple of (found, dep_type) where found indicates if entry exists in cache.
    """
    cache_key = get_cache_key(pkg_name, pkg_version)
    cached_entry = cache.get(cache_key)
    if cached_entry is None:
        return (False, None)
    return (True, cached_entry.get("dep_type"))


def update_cache(
    cache: dict[str, dict[str, Any]],
    pkg_name: str,
    pkg_version: str,
    dep_type: str | None,
) -> None:
    """Update cache with vulnerability result."""
    cache_key = get_cache_key(pkg_name, pkg_version)
    ttl = generate_cache_ttl()
    cache[cache_key] = {"dep_type": dep_type, "expires_at": time.time() + ttl}
