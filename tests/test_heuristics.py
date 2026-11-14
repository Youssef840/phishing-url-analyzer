from urllib.parse import urlparse

import pytest

from phishguard.analyzer.engine import _extract
from phishguard.analyzer.heuristics import heuristic_checks
from phishguard.analyzer.utils import InvalidURLError, levenshtein, normalize_url


def titles(url):
    parsed = urlparse(url)
    return {i["title"] for i in heuristic_checks(url, parsed, _extract(parsed.hostname))}


def test_clean_url_has_no_indicators():
    assert titles("https://www.google.com/") == set()


def test_at_sign_in_authority():
    assert "وجود الرمز @ في عنوان النطاق" in titles("http://google.com@evil.tk/")


def test_raw_ip():
    assert "استخدام عنوان IP مباشرة بدل اسم نطاق" in titles("http://192.168.10.5/login")


def test_decimal_ip():
    assert "عنوان IP مُشفَّر (عشري/ست عشري)" in titles("http://3232235777/")


def test_homoglyph_brand():
    assert "انتحال علامة تجارية بأحرف متشابهة" in titles("https://paypa1.com/")


def test_typosquatting():
    assert "تشابه إملائي مع علامة تجارية (Typosquatting)" in titles("https://micosoft.com/")


def test_brand_token_on_foreign_domain():
    assert "اسم علامة تجارية مدمج في نطاق غير رسمي" in titles("https://paypal-secure.com/")


def test_brand_in_subdomain():
    assert "اسم علامة تجارية في النطاق الفرعي أو المسار" in titles("https://paypal.com.account-check.net/")


def test_no_false_positive_on_embedded_word():
    found = titles("https://pineapple.com/")
    assert "اسم علامة تجارية مدمج في نطاق غير رسمي" not in found
    assert "انتحال علامة تجارية بأحرف متشابهة" not in found


def test_suspicious_tld_and_keywords():
    found = titles("http://secure-update.xyz/login/verify")
    assert "امتداد نطاق عالي الخطورة" in found
    assert "كلمات مفتاحية شائعة في التصيد" in found
    assert "الرابط لا يستخدم HTTPS" in found


def test_shortener():
    assert "خدمة اختصار روابط" in titles("https://bit.ly/abc")


def test_punycode():
    assert "نطاق Punycode (IDN)" in titles("https://xn--pple-43d.com/")


def test_open_redirect():
    assert "إعادة توجيه مفتوحة (Open Redirect)" in titles("https://site.com/r?next=https://evil.com")


def test_executable_download():
    assert "الرابط يشير لملف تنفيذي" in titles("https://files.example.com/invoice.exe")


@pytest.mark.parametrize("raw", ["", "   ", "javascript:alert(1)", "ftp://x.com", "http://x.com:99999"])
def test_invalid_urls(raw):
    with pytest.raises(InvalidURLError):
        normalize_url(raw)


def test_normalize_adds_scheme_and_refangs():
    url, notes = normalize_url("hxxp://evil[.]com/x")
    assert url == "http://evil.com/x" and notes
    url, _ = normalize_url("example.com")
    assert url == "https://example.com"


def test_levenshtein():
    assert levenshtein("paypal", "paypai") == 1
    assert levenshtein("abc", "abc") == 0
