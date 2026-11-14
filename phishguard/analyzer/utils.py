"""Shared helpers: URL normalisation, indicators, string metrics, dates."""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlparse

from .constants import SEVERITY_LABELS

MAX_URL_LENGTH = 2048
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


class InvalidURLError(ValueError):
    """Raised when user input cannot be analysed."""


def indicator(category: str, severity: str, points: int, title: str, detail: str = "") -> dict:
    return {
        "category": category,
        "severity": severity,
        "severity_label": SEVERITY_LABELS.get(severity, severity),
        "points": points,
        "title": title,
        "detail": detail,
    }


def normalize_url(raw: str | None) -> tuple[str, list[str]]:
    """Validate and normalise user input. Returns ``(url, notes)``."""
    notes: list[str] = []
    if not raw or not raw.strip():
        raise InvalidURLError("الرجاء إدخال رابط.")
    url = raw.strip()
    if len(url) > MAX_URL_LENGTH:
        raise InvalidURLError(f"الرابط أطول من {MAX_URL_LENGTH} حرفاً.")

    # Re-fang defanged URLs shared by security teams: hxxp://evil[.]com
    refanged = re.sub(r"^hxxp", "http", url, flags=re.I).replace("[.]", ".").replace("(.)", ".")
    if refanged != url:
        url = refanged
        notes.append("تم تحويل الرابط من الصيغة المعطّلة (defanged) إلى الصيغة العادية.")

    if url.lower().startswith(("javascript:", "data:", "vbscript:", "file:")):
        raise InvalidURLError("هذا النوع من الروابط غير مدعوم (javascript/data/file).")
    if not _SCHEME_RE.match(url):
        url = "https://" + url
        notes.append("لم يتم تحديد البروتوكول، تم افتراض https://")

    parsed = urlparse(url)
    if parsed.scheme.lower() not in ("http", "https"):
        raise InvalidURLError("يدعم المحلل روابط http و https فقط.")
    if not parsed.hostname:
        raise InvalidURLError("تعذّر استخراج اسم النطاق من الرابط.")
    try:
        parsed.port  # noqa: B018 - raises ValueError on an invalid port
    except ValueError as exc:
        raise InvalidURLError("رقم المنفذ (port) في الرابط غير صالح.") from exc
    return url, notes


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def is_non_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_multicast or addr.is_unspecified)


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def to_datetime(value) -> datetime | None:
    """python-whois may return a datetime, a list of datetimes, or a string."""
    if isinstance(value, (list, tuple)):
        value = next((v for v in value if isinstance(v, datetime)), value[0] if value else None)
    if isinstance(value, str):
        for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%d-%b-%Y", "%Y.%m.%d"):
            try:
                value = datetime.strptime(value.strip(), fmt)
                break
            except ValueError:
                continue
        else:
            return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return None


def first(value):
    if isinstance(value, (list, tuple, set)):
        return next(iter(value), None)
    return value
