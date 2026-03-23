import json

from cachetools import TTLCache

_SENTINEL = object()


class ResponseCache:
    """TTL cache for full API response dicts, keyed by method name + kwargs."""

    def __init__(self, ttl: int = 300, maxsize: int = 1000):
        self._store: TTLCache = TTLCache(maxsize=maxsize, ttl=ttl)

    @staticmethod
    def _make_key(method_name: str, **kwargs) -> str:
        normalised = json.dumps(kwargs, sort_keys=True, default=str)
        return f"{method_name}:{normalised}"

    def get(self, method_name: str, **kwargs):
        return self._store.get(self._make_key(method_name, **kwargs), _SENTINEL)

    def put(self, result, method_name: str, **kwargs) -> None:
        self._store[self._make_key(method_name, **kwargs)] = result

    def invalidate_all(self) -> None:
        self._store.clear()


class NameCache:
    """Thread-safe TTL cache for project/version name-to-resource mappings."""

    def __init__(self, ttl: int = 300, max_projects: int = 500, max_versions: int = 2000):
        self._projects: TTLCache = TTLCache(maxsize=max_projects, ttl=ttl)
        self._versions: TTLCache = TTLCache(maxsize=max_versions, ttl=ttl)

    def get_project(self, name_lower: str) -> dict | None:
        return self._projects.get(name_lower)

    def put_project(self, name_lower: str, resource: dict) -> None:
        self._projects[name_lower] = resource

    def get_version(self, project_lower: str, version_lower: str) -> dict | None:
        return self._versions.get((project_lower, version_lower))

    def put_version(self, project_lower: str, version_lower: str, resource: dict) -> None:
        self._versions[(project_lower, version_lower)] = resource

    def invalidate_project(self, name_lower: str) -> None:
        self._projects.pop(name_lower, None)

    def invalidate_all(self) -> None:
        self._projects.clear()
        self._versions.clear()
