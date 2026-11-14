"""Shared fixtures. All network checks are stubbed so tests are fast and offline."""

import pytest

from phishguard import create_app
from phishguard.analyzer import dns_check, engine, reputation, ssl_check, whois_check


@pytest.fixture
def offline(monkeypatch):
    """Replace every network-bound check with a configurable fake."""
    state = {
        "whois": {"domain": "x", "available": True, "age_days": 4000, "registrar": "Test Registrar",
                  "creation_date": "2010-01-01T00:00:00+00:00", "registration_years": 20},
        "ssl": {"host": "x", "reachable": True, "valid": True, "issuer_org": "Test CA",
                "tls_version": "TLSv1.3", "days_remaining": 200, "cert_age_days": 60,
                "not_before": "2026-01-01", "not_after": "2027-01-01", "san": []},
        "dns": {"resolves": True, "ips": ["93.184.216.34"], "private": False},
        "vt": {"enabled": False, "status": "disabled"},
        "gsb": {"enabled": False, "status": "disabled"},
    }
    monkeypatch.setattr(whois_check, "check_whois", lambda d: {**state["whois"], "domain": d})
    monkeypatch.setattr(ssl_check, "check_ssl", lambda h, p=443: {**state["ssl"], "host": h})
    monkeypatch.setattr(dns_check, "check_dns", lambda h: state["dns"])
    monkeypatch.setattr(reputation, "check_virustotal", lambda u, k: state["vt"])
    monkeypatch.setattr(reputation, "check_safebrowsing", lambda u, k: state["gsb"])
    engine.cache.clear()
    return state


@pytest.fixture
def client(offline):
    app = create_app("phishguard.config.TestConfig")
    return app.test_client()
