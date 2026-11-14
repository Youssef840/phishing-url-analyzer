"""DNS resolution check."""

from __future__ import annotations

import socket

from .utils import indicator, is_ip, is_non_public_ip

CAT = "dns"


def check_dns(host: str) -> dict:
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError) as exc:
        reason = getattr(exc, "strerror", None) or exc.__class__.__name__
        return {"resolves": False, "ips": [], "error": f"النطاق لا يُحل في DNS ({reason})."}
    ips = sorted({i[4][0] for i in infos})
    return {"resolves": True, "ips": ips[:8], "private": any(is_non_public_ip(ip) for ip in ips)}


def dns_indicators(info: dict | None, host: str) -> list[dict]:
    if not info:
        return []
    if not info.get("resolves") and not is_ip(host):
        return [indicator(CAT, "medium", 10, "النطاق لا يُحل في DNS", "قد يكون محذوفاً أو موقع تصيد تم إغلاقه.")]
    if info.get("private"):
        return [indicator(CAT, "medium", 10, "الرابط يشير إلى عنوان داخلي/خاص", ", ".join(info.get("ips", [])))]
    return []
