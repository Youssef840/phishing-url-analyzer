from phishguard.analyzer import AnalyzerSettings, analyze_url

S = AnalyzerSettings(cache_ttl=0)


def test_legit_site_is_safe(offline):
    r = analyze_url("https://www.google.com", S)
    assert r["verdict"] == "safe"
    assert r["score"] < 30


def test_phishing_url_is_malicious(offline):
    offline["whois"] = {**offline["whois"], "age_days": 3, "registration_years": 1}
    offline["ssl"] = {"reachable": False, "valid": False, "error": "refused"}
    r = analyze_url("http://paypa1-secure-login.xyz/verify/account", S)
    assert r["verdict"] == "malicious"
    assert r["score"] >= 60


def test_moderate_signals_are_suspicious(offline):
    offline["whois"] = {**offline["whois"], "age_days": 90}
    r = analyze_url("https://my-shop-deals.com/login/verify", S)
    assert r["verdict"] == "suspicious", r["indicators"]


def test_blacklist_forces_malicious(offline):
    offline["gsb"] = {"enabled": True, "status": "ok", "listed": True, "threats": ["SOCIAL_ENGINEERING"]}
    r = analyze_url("https://www.google.com", S)
    assert r["verdict"] == "malicious"


def test_virustotal_detection(offline):
    offline["vt"] = {"enabled": True, "status": "ok", "malicious": 5, "suspicious": 0, "harmless": 60}
    assert analyze_url("https://www.example.org", S)["verdict"] == "malicious"


def test_private_target_skips_ssl(offline):
    offline["dns"] = {"resolves": True, "ips": ["10.0.0.5"], "private": True}
    r = analyze_url("https://intranet.example.com", S)
    assert r["ssl"]["skipped"] is True


def test_score_is_capped(offline):
    offline["whois"] = {**offline["whois"], "age_days": 1}
    offline["vt"] = {"enabled": True, "status": "ok", "malicious": 9, "suspicious": 2, "harmless": 0}
    r = analyze_url("http://user@paypa1-login-verify.tk:8080//secure/account/update.exe", S)
    assert r["score"] == 100


def test_cache(offline):
    cached = AnalyzerSettings(cache_ttl=60)
    first = analyze_url("https://www.google.com", cached)
    second = analyze_url("https://www.google.com", cached)
    assert first["cached"] is False and second["cached"] is True
