"""Cache operations for vulnerability scan results."""

import json
import random
import time
from pathlib import Path
from typing import Any, Dict, Optional

CACHE_MIN_TTL = 12 * 3600  # 12 hours in seconds
CACHE_MAX_TTL = 48 * 3600  # 48 hours in seconds


def get_cache_key(pkg_name: str, pkg_version: str) -> str:
    """Generate cache key for a package."""
    return f"{pkg_name}:{pkg_version}"


def is_cache_entry_valid(entry: Dict[str, Any], current_time: float) -> bool:
    """Check if cache entry is still valid."""
    return entry.get("expires_at", 0) > current_time


def generate_cache_ttl() -> int:
    """Generate random TTL between min and max."""
    return random.randint(CACHE_MIN_TTL, CACHE_MAX_TTL)


def load_cache(cache_file: Path) -> Dict[str, Dict[str, Any]]:
    """Load cache from file, removing expired entries."""
    if not cache_file.exists():
        return {}

    try:
        with open(cache_file, "r") as f:
            cache = json.load(f)

        # Remove expired entries
        current_time = time.time()
        return {k: v for k, v in cache.items() if is_cache_entry_valid(v, current_time)}
    except Exception:
        return {}


def save_cache(cache: Dict[str, Dict[str, Any]], cache_file: Path) -> None:
    """Save cache to file."""
    try:
        with open(cache_file, "w") as f:
            json.dump(cache, f, indent=2)
    except Exception:
        pass


def get_cached_result(
    cache: Dict[str, Dict[str, Any]], pkg_name: str, pkg_version: str
) -> Optional[str]:
    """Get cached vulnerability result for a package."""
    cache_key = get_cache_key(pkg_name, pkg_version)
    cached_entry = cache.get(cache_key)
    return cached_entry.get("vuln_type") if cached_entry else None


def update_cache(
    cache: Dict[str, Dict[str, Any]],
    pkg_name: str,
    pkg_version: str,
    vuln_type: Optional[str],
) -> None:
    """Update cache with vulnerability result."""
    cache_key = get_cache_key(pkg_name, pkg_version)
    ttl = generate_cache_ttl()
    cache[cache_key] = {"vuln_type": vuln_type, "expires_at": time.time() + ttl}
