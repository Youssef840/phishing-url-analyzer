"""Lexical checks performed on the URL string itself (no network access)."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, unquote

from .constants import (
    BRANDS,
    DANGEROUS_EXTENSIONS,
    HOMOGLYPHS,
    PHISH_KEYWORDS,
    SHORTENERS,
    SUSPICIOUS_TLDS,
)
from .utils import indicator, is_ip, levenshtein, shannon_entropy

CAT = "heuristics"


def _deobfuscate(label: str) -> str:
    return label.translate(HOMOGLYPHS).replace("rn", "m").replace("vv", "w")


def _brand_checks(sld: str, subdomain: str, path_query: str, registered: str) -> list[dict]:
    """Detect homoglyphs, typosquatting and brand names used on a foreign domain."""
    if sld in BRANDS:
        return []

    normalized = _deobfuscate(sld).replace("-", "")
    tokens = [_deobfuscate(t) for t in re.split(r"[-_]", sld) if t]

    for brand in BRANDS:
        if normalized == brand:
            return [indicator(CAT, "high", 35, "انتحال علامة تجارية بأحرف متشابهة",
                              f"'{sld}' يحاكي '{brand}' باستبدال أحرف بأرقام أو رموز.")]
    for brand in BRANDS:
        max_dist = 1 if len(brand) <= 5 else 2
        dist = levenshtein(normalized, brand)
        if 0 < dist <= max_dist and abs(len(normalized) - len(brand)) <= max_dist:
            return [indicator(CAT, "high", 30, "تشابه إملائي مع علامة تجارية (Typosquatting)",
                              f"'{sld}' قريب جداً من '{brand}' (فرق {dist} حرف).")]
    for brand in BRANDS:
        if brand in tokens:
            return [indicator(CAT, "high", 25, "اسم علامة تجارية مدمج في نطاق غير رسمي",
                              f"النطاق '{registered}' يحتوي '{brand}' لكنه ليس النطاق الرسمي.")]
    for brand in BRANDS:
        if len(brand) >= 5 and brand in normalized:
            return [indicator(CAT, "medium", 12, "النطاق قد يتضمن اسم علامة تجارية",
                              f"'{sld}' يحتوي '{brand}'.")]

    zone = f"{subdomain} {path_query}"
    for brand in BRANDS:
        if len(brand) >= 4 and re.search(rf"(?<![a-z]){re.escape(brand)}(?![a-z])", zone):
            return [indicator(CAT, "high", 25, "اسم علامة تجارية في النطاق الفرعي أو المسار",
                              f"'{brand}' يظهر في الرابط لكن النطاق الفعلي هو '{registered}'.")]
    return []


def heuristic_checks(url: str, parsed, ext) -> list[dict]:
    ind: list[dict] = []
    host = (parsed.hostname or "").lower()
    netloc = parsed.netloc
    sld = ext.domain.lower()
    subdomain = ext.subdomain.lower()
    path_query = f"{parsed.path}?{parsed.query}".lower()
    registered = f"{sld}.{ext.suffix}".lower() if ext.suffix else host
    host_is_ip = is_ip(host)

    # --- Length -------------------------------------------------------------
    if len(url) >= 100:
        ind.append(indicator(CAT, "medium", 15, "رابط طويل جداً",
                             f"طول الرابط {len(url)} حرفاً (روابط التصيد غالباً طويلة لإخفاء النطاق الحقيقي)."))
    elif len(url) >= 75:
        ind.append(indicator(CAT, "low", 7, "رابط طويل", f"طول الرابط {len(url)} حرفاً."))

    # --- '@' trick: the browser ignores everything before '@' in the authority
    if "@" in netloc:
        real = netloc.rsplit("@", 1)[1]
        ind.append(indicator(CAT, "high", 25, "وجود الرمز @ في عنوان النطاق",
                             f"المتصفح سيتجاهل ما قبل @ ويتوجه فعلياً إلى: {real}"))
    elif "@" in url.split("://", 1)[-1]:
        ind.append(indicator(CAT, "low", 3, "وجود الرمز @ في مسار الرابط",
                             "قد يكون طبيعياً (مثل صفحات المستخدمين) لكنه يُستخدم أحياناً للتمويه."))

    # --- Raw or obfuscated IP ---------------------------------------------------
    if host_is_ip:
        ind.append(indicator(CAT, "high", 25, "استخدام عنوان IP مباشرة بدل اسم نطاق", f"المضيف: {host}"))
    elif re.fullmatch(r"(0x[0-9a-f]+|\d{8,})", host):
        ind.append(indicator(CAT, "high", 30, "عنوان IP مُشفَّر (عشري/ست عشري)", f"المضيف {host} هو عنوان IP مموّه."))

    # --- Transport ----------------------------------------------------------------
    if parsed.port and parsed.port not in (80, 443):
        ind.append(indicator(CAT, "medium", 10, "منفذ غير قياسي", f"المنفذ المستخدم: {parsed.port}"))
    if parsed.scheme.lower() != "https":
        ind.append(indicator(CAT, "medium", 10, "الرابط لا يستخدم HTTPS", "البيانات تُرسل بدون تشفير."))

    # --- IDN / homograph ------------------------------------------------------------
    if any(label.startswith("xn--") for label in host.split(".")):
        try:
            decoded = host.encode("ascii").decode("idna")
        except UnicodeError:
            decoded = host
        ind.append(indicator(CAT, "high", 20, "نطاق Punycode (IDN)",
                             f"قد يحاكي نطاقاً معروفاً بأحرف متشابهة. الشكل المعروض: {decoded}"))
    if any(ord(ch) > 127 for ch in host):
        ind.append(indicator(CAT, "high", 20, "أحرف غير لاتينية في النطاق",
                             "قد تكون أحرفاً متشابهة شكلاً (مثل а الروسية بدل a)."))

    # --- Domain reputation by shape ------------------------------------------------
    if registered in SHORTENERS or host in SHORTENERS:
        ind.append(indicator(CAT, "medium", 12, "خدمة اختصار روابط", "الرابط المختصر يخفي الوجهة الحقيقية."))

    tld = ext.suffix.rsplit(".", 1)[-1].lower() if ext.suffix else ""
    if tld in SUSPICIOUS_TLDS:
        ind.append(indicator(CAT, "medium", 10, "امتداد نطاق عالي الخطورة",
                             f".{tld} من الامتدادات الأكثر استخداماً في التصيد."))

    if subdomain and not host_is_ip:
        depth = len([p for p in subdomain.split(".") if p])
        if depth >= 3:
            ind.append(indicator(CAT, "medium", 10, "عدد كبير من النطاقات الفرعية", f"{depth} مستويات: {subdomain}"))
        elif depth == 2 and not subdomain.startswith("www."):
            ind.append(indicator(CAT, "low", 4, "نطاقات فرعية متعددة", subdomain))

    if sld.count("-") >= 2 or host.count("-") >= 4:
        ind.append(indicator(CAT, "medium", 8, "كثرة الشرطات (-) في النطاق", host))
    elif "-" in sld:
        ind.append(indicator(CAT, "low", 4, "وجود شرطة في اسم النطاق", sld))

    if not host_is_ip:
        if sum(ch.isdigit() for ch in sld) >= 4:
            ind.append(indicator(CAT, "low", 5, "أرقام كثيرة في اسم النطاق", sld))
        if len(sld) >= 12 and shannon_entropy(sld) > 3.8:
            ind.append(indicator(CAT, "low", 6, "اسم نطاق عشوائي المظهر",
                                 f"إنتروبيا مرتفعة ({shannon_entropy(sld):.2f}) للاسم {sld}"))
        ind.extend(_brand_checks(sld, subdomain, path_query, registered))

    # --- Content of the URL ----------------------------------------------------------
    scan_zone = f"{subdomain} {unquote(path_query)}"
    hits = sorted({kw for kw in PHISH_KEYWORDS if kw in scan_zone})
    if hits:
        ind.append(indicator(CAT, "medium" if len(hits) >= 2 else "low", min(4 * len(hits), 16),
                             "كلمات مفتاحية شائعة في التصيد", "، ".join(hits)))

    if "//" in parsed.path:
        ind.append(indicator(CAT, "medium", 8, "وجود // داخل المسار", "يُستخدم أحياناً لإعادة التوجيه إلى موقع آخر."))
    for key, values in parse_qs(parsed.query).items():
        if any(re.match(r"^(https?:)?//", unquote(v), re.I) for v in values):
            ind.append(indicator(CAT, "medium", 10, "إعادة توجيه مفتوحة (Open Redirect)",
                                 f"المعامل '{key}' يحتوي رابطاً خارجياً."))
            break

    if url.count("%") >= 5:
        ind.append(indicator(CAT, "low", 5, "ترميز مفرط (%) في الرابط", f"{url.count('%')} رموز مُرمّزة."))
    if parsed.path.lower().endswith(DANGEROUS_EXTENSIONS):
        ind.append(indicator(CAT, "high", 15, "الرابط يشير لملف تنفيذي", parsed.path.rsplit("/", 1)[-1]))

    return ind
