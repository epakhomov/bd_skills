"""
Multi-profile support for connecting to multiple Black Duck instances.

Loads named profiles from ``~/.blackduck/profiles.yaml`` and manages a
registry of lazily-created :class:`BlackDuckClient` instances.  Falls back
to environment variables (``BLACKDUCK_URL`` / ``BLACKDUCK_TOKEN``) when no
profiles file exists, preserving full backward compatibility.
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel

from .client import BlackDuckClient

PROFILES_PATH = Path.home() / ".blackduck" / "profiles.yaml"


class ProfileConfig(BaseModel):
    """Configuration for a single Black Duck connection."""

    url: str
    token: str
    tls_verify: bool = True
    timeout: int = 30
    cache_ttl: int = 300


class ProfilesFile(BaseModel):
    """Top-level schema for ``~/.blackduck/profiles.yaml``."""

    profiles: dict[str, ProfileConfig]
    default: str | None = None


def load_profiles(path: Path = PROFILES_PATH) -> ProfilesFile | None:
    """Read and validate the profiles YAML file.

    Returns ``None`` if the file does not exist.  Raises on parse or
    validation errors so the caller gets a clear message.
    """
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    if data is None:
        return None
    return ProfilesFile.model_validate(data)


class ProfileRegistry:
    """Manages multiple :class:`BlackDuckClient` instances keyed by profile name."""

    def __init__(self) -> None:
        self._clients: dict[str, BlackDuckClient] = {}
        self._profiles: dict[str, ProfileConfig] = {}
        self._active: str = ""
        self._loaded = False

    # ── bootstrap ───────────────────────────────────────────────

    def _ensure_loaded(self) -> None:
        """Load profiles on first access (lazy)."""
        if self._loaded:
            return
        self._loaded = True

        pf = load_profiles()
        if pf is not None:
            self._profiles = dict(pf.profiles)
            if pf.default and pf.default in self._profiles:
                self._active = pf.default
            elif self._profiles:
                self._active = next(iter(self._profiles))
            return

        # Fallback: build a synthetic profile from env vars
        url = os.environ.get("BLACKDUCK_URL", "")
        token = os.environ.get("BLACKDUCK_TOKEN", "")
        if not url or not token:
            raise RuntimeError(
                "No profiles file found at ~/.blackduck/profiles.yaml and "
                "BLACKDUCK_URL / BLACKDUCK_TOKEN environment variables are not set. "
                "Please create a profiles file or set the environment variables."
            )
        self._profiles["default"] = ProfileConfig(
            url=url,
            token=token,
            tls_verify=os.environ.get("BLACKDUCK_TLS_VERIFY", "true").lower() == "true",
            timeout=int(os.environ.get("BD_TIMEOUT_SECONDS", "30")),
            cache_ttl=int(os.environ.get("CACHE_TTL_SECONDS", "300")),
        )
        self._active = "default"

    # ── public API ──────────────────────────────────────────────

    def get_client(self) -> BlackDuckClient:
        """Return the :class:`BlackDuckClient` for the active profile."""
        self._ensure_loaded()
        if self._active not in self._clients:
            cfg = self._profiles[self._active]
            self._clients[self._active] = BlackDuckClient(
                url=cfg.url,
                token=cfg.token,
                verify_ssl=cfg.tls_verify,
                timeout=cfg.timeout,
                cache_ttl=cfg.cache_ttl,
            )
        return self._clients[self._active]

    def switch(self, profile_name: str) -> None:
        """Switch the active profile.  Raises if the name is unknown."""
        self._ensure_loaded()
        if profile_name not in self._profiles:
            available = ", ".join(sorted(self._profiles))
            raise ValueError(
                f"Unknown profile '{profile_name}'. Available profiles: {available}"
            )
        self._active = profile_name

    def list_profiles(self) -> list[dict[str, str | bool]]:
        """Return profile names with their server URLs and active status."""
        self._ensure_loaded()
        return [
            {
                "name": name,
                "url": cfg.url,
                "active": name == self._active,
            }
            for name, cfg in self._profiles.items()
        ]

    @property
    def active_profile(self) -> str:
        self._ensure_loaded()
        return self._active

    @property
    def active_url(self) -> str:
        self._ensure_loaded()
        return self._profiles[self._active].url
