"""Tests for cache operations."""

import time

from osvcheck.cache import (
    generate_cache_ttl,
    get_cache_key,
    get_cached_result,
    is_cache_entry_valid,
    load_cache,
    save_cache,
    update_cache,
    CACHE_MIN_TTL,
    CACHE_MAX_TTL,
)


def test_get_cache_key():
    assert get_cache_key("requests", "2.28.0") == "requests:2.28.0"
    assert get_cache_key("Django", "4.2.0") == "Django:4.2.0"


def test_is_cache_entry_valid():
    current = time.time()

    valid_entry = {"expires_at": current + 1000}
    assert is_cache_entry_valid(valid_entry, current)

    expired_entry = {"expires_at": current - 1}
    assert not is_cache_entry_valid(expired_entry, current)


def test_generate_cache_ttl():
    ttl = generate_cache_ttl()
    assert CACHE_MIN_TTL <= ttl <= CACHE_MAX_TTL


def test_load_cache_missing_file(tmp_path):
    cache_file = tmp_path / "missing.json"
    cache = load_cache(cache_file)
    assert cache == {}


def test_load_cache_removes_expired_entries(tmp_path):
    cache_file = tmp_path / "cache.json"
    current = time.time()

    cache_file.write_text(
        '{"valid:1.0": {"dep_type": "direct", "expires_at": '
        + str(current + 1000)
        + '}, "expired:1.0": {"dep_type": "indirect", "expires_at": '
        + str(current - 1)
        + "}}"
    )

    cache = load_cache(cache_file)
    assert "valid:1.0" in cache
    assert "expired:1.0" not in cache


def test_save_and_load_cache(tmp_path):
    cache_file = tmp_path / "cache.json"
    cache = {"pkg:1.0": {"dep_type": "direct", "expires_at": time.time() + 1000}}

    save_cache(cache, cache_file)
    loaded = load_cache(cache_file)

    assert "pkg:1.0" in loaded
    assert loaded["pkg:1.0"]["dep_type"] == "direct"


def test_get_cached_result():
    cache = {"pkg:1.0": {"dep_type": "direct", "expires_at": time.time() + 1000}}

    assert get_cached_result(cache, "pkg", "1.0") == (True, "direct")
    assert get_cached_result(cache, "missing", "1.0") == (False, None)


def test_update_cache():
    cache = {}
    update_cache(cache, "pkg", "1.0", "indirect")

    assert "pkg:1.0" in cache
    assert cache["pkg:1.0"]["dep_type"] == "indirect"
    assert cache["pkg:1.0"]["expires_at"] > time.time()
