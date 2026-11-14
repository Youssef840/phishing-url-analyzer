"""Orchestrates every check, scores the result and returns a report."""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

import tldextract

from . import dns_check, heuristics, reputation, ssl_check, whois_check
from .constants import MALICIOUS_THRESHOLD, SUSPICIOUS_THRESHOLD, VERDICTS
from .utils import is_ip, normalize_url

# Use the public-suffix snapshot bundled with tldextract (no network fetch).
_extract = tldextract.TLDExtract(suffix_list_urls=())


@dataclass(frozen=True)
class AnalyzerSettings:
    vt_api_key: str | None = None
    gsb_api_key: str | None = None
    allow_private_targets: bool = False
    task_timeout: float = 20.0
    cache_ttl: int = 300


class _TTLCache:
    def __init__(self, max_items: int = 256):
        self._data: dict[str, tuple[float, dict]] = {}
        self._lock = threading.Lock()
        self._max = max_items

    def get(self, key: str, ttl: int) -> dict | None:
        with self._lock:
            item = self._data.get(key)
            if item and time.time() - item[0] < ttl:
                return item[1]
            self._data.pop(key, None)
            return None

    def set(self, key: str, value: dict) -> None:
        with self._lock:
            if len(self._data) >= self._max:
                self._data.pop(next(iter(self._data)))
            self._data[key] = (time.time(), value)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()


cache = _TTLCache()


def _verdict(score: int, forced_malicious: bool) -> str:
    if forced_malicious or score >= MALICIOUS_THRESHOLD:
        return "malicious"
    if score >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "safe"


def analyze_url(raw_url: str, settings: AnalyzerSettings | None = None, use_cache: bool = True) -> dict:
    """Analyse ``raw_url`` and return a JSON-serialisable report.

    Raises :class:`InvalidURLError` (a ``ValueError``) for unusable input.
    """
    settings = settings or AnalyzerSettings()
    started = time.perf_counter()
    url, notes = normalize_url(raw_url)

    if use_cache and settings.cache_ttl > 0:
        cached = cache.get(url, settings.cache_ttl)
        if cached:
            return {**cached, "cached": True}

    parsed = urlparse(url)
    host = parsed.hostname.lower().strip("[]")
    ext = _extract(host)
    host_is_ip = is_ip(host)
    domain = host if host_is_ip or not ext.suffix else f"{ext.domain}.{ext.suffix}".lower()
    https_port = parsed.port if (parsed.scheme == "https" and parsed.port) else 443

    # DNS first: we need it to decide whether connecting out is safe (SSRF guard).
    dns_info = dns_check.check_dns(host)
    block_connect = dns_info.get("private") and not settings.allow_private_targets

    pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="phishguard")
    futures = {
        "vt": pool.submit(reputation.check_virustotal, url, settings.vt_api_key),
        "gsb": pool.submit(reputation.check_safebrowsing, url, settings.gsb_api_key),
    }
    if not host_is_ip:
        futures["whois"] = pool.submit(whois_check.check_whois, domain)
    if not block_connect:
        futures["ssl"] = pool.submit(ssl_check.check_ssl, host, https_port)

    done, _ = wait(futures.values(), timeout=settings.task_timeout)
    results: dict[str, dict] = {}
    for name, fut in futures.items():
        if fut in done:
            try:
                results[name] = fut.result()
            except Exception as exc:  # defensive: never let one check break the report
                results[name] = {"error": f"خطأ غير متوقع ({exc.__class__.__name__})."}
        else:
            results[name] = {"error": "انتهت مهلة الفحص."}
    pool.shutdown(wait=False, cancel_futures=True)

    whois_info = results.get("whois") or {
        "domain": domain, "available": False, "error": "عنوان IP - لا ينطبق فحص WHOIS."}
    ssl_info = results.get("ssl") or {
        "host": host, "reachable": False, "valid": False, "skipped": True,
        "error": "تم تخطي فحص SSL لأن الهدف عنوان داخلي (حماية SSRF)."}
    vt_info = results["vt"]
    gsb_info = results["gsb"]

    indicators = heuristics.heuristic_checks(url, parsed, ext)
    if not host_is_ip:
        indicators += whois_check.whois_indicators(whois_info)
    indicators += ssl_check.ssl_indicators(ssl_info, parsed.scheme)
    indicators += dns_check.dns_indicators(dns_info, host)
    rep_ind, forced = reputation.reputation_indicators(vt_info, gsb_info)
    indicators += rep_ind
    indicators.sort(key=lambda i: i["points"], reverse=True)

    score = min(100, sum(i["points"] for i in indicators))
    verdict = _verdict(score, forced)

    report = {
        "input": raw_url,
        "url": url,
        "host": host,
        "domain": domain,
        "is_ip": host_is_ip,
        "score": score,
        "verdict": verdict,
        "verdict_info": VERDICTS[verdict],
        "indicators": indicators,
        "risk_count": sum(1 for i in indicators if i["points"] > 0),
        "whois": whois_info,
        "ssl": ssl_info,
        "dns": dns_info,
        "reputation": {"virustotal": vt_info, "safebrowsing": gsb_info},
        "notes": notes,
        "analyzed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_sec": round(time.perf_counter() - started, 2),
        "cached": False,
    }
    if use_cache and settings.cache_ttl > 0:
        cache.set(url, report)
    return report
