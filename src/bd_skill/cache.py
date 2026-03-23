"""
Caching layer for Black Duck API responses.

Provides two cache types:
- ResponseCache: caches full API response dicts keyed by method name and call
  arguments, avoiding redundant HTTP round-trips for repeated identical queries.
- NameCache: caches project and version name-to-resource-dict lookups so that
  resolving a project/version by name doesn't require an API call every time.

Both caches use TTL-based eviction (default 5 minutes) so stale data is
automatically discarded.
"""

import json

from cachetools import TTLCache

# Sentinel object used to distinguish "not in cache" from a cached None value.
_SENTINEL = object()


class ResponseCache:
    """TTL cache for full API response dicts, keyed by method name + kwargs."""

    def __init__(self, ttl: int = 300, maxsize: int = 1000):
        self._store: TTLCache = TTLCache(maxsize=maxsize, ttl=ttl)

    @staticmethod
    def _make_key(method_name: str, **kwargs) -> str:
        """Build a deterministic cache key by JSON-serializing kwargs with sorted keys."""
        normalised = json.dumps(kwargs, sort_keys=True, default=str)
        return f"{method_name}:{normalised}"

    def get(self, method_name: str, **kwargs):
        """Return the cached result, or _SENTINEL if not present."""
        return self._store.get(self._make_key(method_name, **kwargs), _SENTINEL)

    def put(self, result, method_name: str, **kwargs) -> None:
        """Store a result in the cache under the given method + kwargs key."""
        self._store[self._make_key(method_name, **kwargs)] = result

    def invalidate_all(self) -> None:
        """Drop every entry from the cache."""
        self._store.clear()


class NameCache:
    """TTL cache for project/version name-to-resource mappings.

    Keeps two separate stores so that their sizes and eviction can be
    managed independently (there are typically many more versions than
    projects).
    """

    def __init__(self, ttl: int = 300, max_projects: int = 500, max_versions: int = 2000):
        self._projects: TTLCache = TTLCache(maxsize=max_projects, ttl=ttl)
        # Versions are keyed by a (project_name, version_name) tuple.
        self._versions: TTLCache = TTLCache(maxsize=max_versions, ttl=ttl)

    def get_project(self, name_lower: str) -> dict | None:
        """Look up a project resource dict by its lowercased name."""
        return self._projects.get(name_lower)

    def put_project(self, name_lower: str, resource: dict) -> None:
        """Cache a project resource dict under its lowercased name."""
        self._projects[name_lower] = resource

    def get_version(self, project_lower: str, version_lower: str) -> dict | None:
        """Look up a version resource dict by lowercased project + version name."""
        return self._versions.get((project_lower, version_lower))

    def put_version(self, project_lower: str, version_lower: str, resource: dict) -> None:
        """Cache a version resource dict under its composite key."""
        self._versions[(project_lower, version_lower)] = resource

    def invalidate_project(self, name_lower: str) -> None:
        """Remove a single project entry from the cache."""
        self._projects.pop(name_lower, None)

    def invalidate_all(self) -> None:
        """Drop all project and version entries."""
        self._projects.clear()
        self._versions.clear()
