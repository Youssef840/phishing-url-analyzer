"""WHOIS lookup: domain age, registrar and expiry."""

from __future__ import annotations

from datetime import datetime, timezone

import whois

from .utils import first, indicator, to_datetime

CAT = "whois"


def check_whois(domain: str) -> dict:
    result: dict = {"domain": domain, "available": False}
    try:
        w = whois.whois(domain)
    except Exception as exc:  # network errors, unsupported TLDs, rate limits
        result["error"] = f"تعذّر جلب بيانات WHOIS ({exc.__class__.__name__})."
        return result

    created = to_datetime(w.get("creation_date"))
    expires = to_datetime(w.get("expiration_date"))
    updated = to_datetime(w.get("updated_date"))
    now = datetime.now(timezone.utc)

    result.update({
        "available": bool(created or w.get("registrar")),
        "registrar": first(w.get("registrar")),
        "creation_date": created.isoformat() if created else None,
        "expiration_date": expires.isoformat() if expires else None,
        "updated_date": updated.isoformat() if updated else None,
        "age_days": (now - created).days if created else None,
        "days_to_expiry": (expires - now).days if expires else None,
        "country": first(w.get("country")),
        "org": first(w.get("org")),
        "name_servers": sorted({str(n).lower().rstrip(".") for n in (w.get("name_servers") or [])})[:6],
    })
    if created and expires:
        result["registration_years"] = round((expires - created).days / 365, 1)
    if not result["available"]:
        result["error"] = "لا توجد بيانات WHOIS متاحة لهذا النطاق (قد تكون مخفية أو الامتداد غير مدعوم)."
    return result


def whois_indicators(info: dict | None) -> list[dict]:
    ind: list[dict] = []
    if not info or not info.get("available"):
        ind.append(indicator(CAT, "low", 5, "بيانات WHOIS غير متاحة", (info or {}).get("error", "")))
        return ind

    age = info.get("age_days")
    if age is None:
        ind.append(indicator(CAT, "low", 5, "تاريخ تسجيل النطاق غير معروف"))
    elif age < 30:
        ind.append(indicator(CAT, "high", 30, "نطاق حديث جداً",
                             f"عمر النطاق {age} يوماً فقط (أغلب نطاقات التصيد عمرها أيام)."))
    elif age < 180:
        ind.append(indicator(CAT, "medium", 15, "نطاق حديث", f"عمر النطاق {age} يوماً."))
    elif age < 365:
        ind.append(indicator(CAT, "low", 5, "نطاق عمره أقل من سنة", f"{age} يوماً."))
    else:
        ind.append(indicator(CAT, "info", 0, "نطاق قديم ومستقر", f"عمر النطاق {age // 365} سنة تقريباً."))

    years = info.get("registration_years")
    if years is not None and years <= 1.05 and (age or 0) < 365:
        ind.append(indicator(CAT, "low", 5, "تسجيل لمدة سنة واحدة فقط", "المواقع المشروعة غالباً تُسجل لسنوات."))

    dte = info.get("days_to_expiry")
    if dte is not None and dte < 0:
        ind.append(indicator(CAT, "medium", 10, "النطاق منتهي الصلاحية", f"انتهى منذ {-dte} يوماً."))
    return ind
