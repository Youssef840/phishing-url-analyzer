"""Live SSL/TLS certificate inspection."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from .utils import indicator

CAT = "ssl"
SOCKET_TIMEOUT = 6


def _parse_name(seq) -> dict:
    out: dict = {}
    for rdn in seq or ():
        for key, value in rdn:
            out[key] = value
    return out


def check_ssl(host: str, port: int = 443) -> dict:
    result: dict = {"host": host, "port": port, "reachable": False, "valid": False}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=SOCKET_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                result.update(reachable=True, valid=True, tls_version=tls.version(), cipher=tls.cipher()[0])
    except ssl.SSLCertVerificationError as exc:
        result.update(reachable=True, error=f"فشل التحقق من الشهادة: {exc.verify_message or exc}")
        return result
    except ssl.SSLError as exc:
        result.update(reachable=True, error=f"خطأ في اتصال TLS: {exc.reason or exc}")
        return result
    except TimeoutError:
        result["error"] = f"انتهت مهلة الاتصال بالمنفذ {port}."
        return result
    except OSError as exc:
        result["error"] = f"تعذّر الاتصال عبر HTTPS ({exc.strerror or exc.__class__.__name__})."
        return result

    subject = _parse_name(cert.get("subject"))
    issuer = _parse_name(cert.get("issuer"))
    not_before = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), timezone.utc)
    not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
    now = datetime.now(timezone.utc)
    result.update({
        "subject_cn": subject.get("commonName"),
        "issuer_cn": issuer.get("commonName"),
        "issuer_org": issuer.get("organizationName"),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_remaining": (not_after - now).days,
        "cert_age_days": (now - not_before).days,
        "san": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:10],
    })
    return result


def ssl_indicators(info: dict | None, scheme: str) -> list[dict]:
    ind: list[dict] = []
    if not info or info.get("skipped"):
        return ind
    if not info.get("reachable"):
        sev, pts = ("medium", 10) if scheme == "https" else ("low", 5)
        ind.append(indicator(CAT, sev, pts, "لا يوجد اتصال HTTPS متاح", info.get("error", "")))
        return ind
    if not info.get("valid"):
        ind.append(indicator(CAT, "high", 30, "شهادة SSL غير صالحة", info.get("error", "")))
        return ind

    days = info.get("days_remaining")
    if days is not None and days < 7:
        ind.append(indicator(CAT, "medium", 8, "الشهادة على وشك الانتهاء", f"متبقٍ {days} يوماً."))
    age = info.get("cert_age_days")
    if age is not None and age <= 3:
        ind.append(indicator(CAT, "low", 5, "شهادة صادرة حديثاً جداً", f"صدرت منذ {age} يوماً."))
    if not ind:
        issuer = info.get("issuer_org") or info.get("issuer_cn")
        ind.append(indicator(CAT, "info", 0, "شهادة SSL صالحة وموثوقة", f"صادرة من {issuer} - {info.get('tls_version')}"))
    return ind
