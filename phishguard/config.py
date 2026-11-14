"""Application configuration loaded from environment variables / .env."""

from __future__ import annotations

import os


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


class Config:
    VT_API_KEY = os.getenv("VT_API_KEY", "").strip() or None
    GSB_API_KEY = os.getenv("GSB_API_KEY", "").strip() or None
    ALLOW_PRIVATE_TARGETS = _bool("ALLOW_PRIVATE_TARGETS")
    TASK_TIMEOUT = float(os.getenv("TASK_TIMEOUT", "20"))
    CACHE_TTL = int(os.getenv("CACHE_TTL", "300"))
    MAX_CONTENT_LENGTH = 16 * 1024  # requests carry a single URL
    JSON_SORT_KEYS = False
    # Analyses allowed per IP per minute (0 disables). Set it when exposed publicly.
    RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "0"))
    # Number of reverse proxies in front of the app (e.g. 1 on Render) so the real client IP is used.
    TRUSTED_PROXIES = int(os.getenv("TRUSTED_PROXIES", "0"))


class TestConfig(Config):
    TESTING = True
    VT_API_KEY = None
    GSB_API_KEY = None
    CACHE_TTL = 0
    RATE_LIMIT_PER_MINUTE = 0
    TRUSTED_PROXIES = 0
