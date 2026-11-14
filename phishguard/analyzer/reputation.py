"""Optional reputation lookups: VirusTotal v3 and Google Safe Browsing v4."""

from __future__ import annotations

import base64

import requests

from .utils import indicator

CAT = "reputation"
HTTP_TIMEOUT = 10
USER_AGENT = "PhishGuard-URL-Analyzer/1.0"


def check_virustotal(url: str, api_key: str | None) -> dict:
    if not api_key:
        return {"enabled": False, "status": "disabled", "message": "غير مفعّل - أضف VT_API_KEY في ملف .env"}
    headers = {"x-apikey": api_key, "accept": "application/json", "user-agent": USER_AGENT}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=HTTP_TIMEOUT)
        if r.status_code == 404:
            sub = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers,
                                data={"url": url}, timeout=HTTP_TIMEOUT)
            sub.raise_for_status()
            return {"enabled": True, "status": "submitted",
                    "message": "الرابط غير موجود في قاعدة VirusTotal وتم إرساله للفحص، أعد التحليل بعد دقيقة."}
        if r.status_code == 401:
            return {"enabled": True, "status": "error", "message": "مفتاح VirusTotal غير صالح."}
        if r.status_code == 429:
            return {"enabled": True, "status": "error", "message": "تم تجاوز حد الطلبات في VirusTotal."}
        r.raise_for_status()
        attrs = r.json()["data"]["attributes"]
    except (requests.RequestException, KeyError, ValueError) as exc:
        return {"enabled": True, "status": "error", "message": f"خطأ في الاتصال بـ VirusTotal ({exc.__class__.__name__})."}

    stats = attrs.get("last_analysis_stats", {})
    flagged_by = [name for name, res in attrs.get("last_analysis_results", {}).items()
                  if res.get("category") in ("malicious", "suspicious")]
    return {
        "enabled": True,
        "status": "ok",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "flagged_by": flagged_by[:12],
        "reputation": attrs.get("reputation"),
        "permalink": f"https://www.virustotal.com/gui/url/{url_id}",
    }


def check_safebrowsing(url: str, api_key: str | None) -> dict:
    if not api_key:
        return {"enabled": False, "status": "disabled", "message": "غير مفعّل - أضف GSB_API_KEY في ملف .env"}
    body = {
        "client": {"clientId": "phishguard-url-analyzer", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        r = requests.post("https://safebrowsing.googleapis.com/v4/threatMatches:find",
                          params={"key": api_key}, json=body, timeout=HTTP_TIMEOUT)
        if r.status_code in (400, 403):
            return {"enabled": True, "status": "error", "message": "مفتاح Google Safe Browsing غير صالح أو غير مفعّل."}
        r.raise_for_status()
        matches = r.json().get("matches", [])
    except (requests.RequestException, ValueError) as exc:
        return {"enabled": True, "status": "error", "message": f"خطأ في الاتصال بـ Safe Browsing ({exc.__class__.__name__})."}
    return {"enabled": True, "status": "ok", "listed": bool(matches),
            "threats": sorted({m.get("threatType") for m in matches if m.get("threatType")})}


def reputation_indicators(vt: dict | None, gsb: dict | None) -> tuple[list[dict], bool]:
    """Returns (indicators, force_malicious)."""
    ind: list[dict] = []
    force = False
    if vt and vt.get("status") == "ok":
        mal, sus = vt.get("malicious", 0), vt.get("suspicious", 0)
        if mal >= 2:
            ind.append(indicator(CAT, "high", 60, "مُصنّف ضاراً في VirusTotal", f"{mal} محرك فحص صنّفه ضاراً."))
            force = True
        elif mal == 1 or sus >= 1:
            ind.append(indicator(CAT, "medium", 25, "اشتباه في VirusTotal", f"ضار: {mal} / مشبوه: {sus}"))
        else:
            ind.append(indicator(CAT, "info", 0, "نظيف في VirusTotal", f"{vt.get('harmless', 0)} محرك صنّفه آمناً."))
    if gsb and gsb.get("status") == "ok":
        if gsb.get("listed"):
            ind.append(indicator(CAT, "high", 70, "مدرج في القائمة السوداء لـ Google Safe Browsing",
                                 "، ".join(gsb.get("threats", []))))
            force = True
        else:
            ind.append(indicator(CAT, "info", 0, "غير مدرج في Google Safe Browsing"))
    return ind, force
