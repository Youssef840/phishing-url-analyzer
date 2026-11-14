from phishguard import create_app
from phishguard.config import TestConfig
from phishguard.ratelimit import RateLimiter


class LimitedConfig(TestConfig):
    RATE_LIMIT_PER_MINUTE = 2


def test_limiter_blocks_after_limit():
    limiter = RateLimiter(limit=2, window=60)
    assert limiter.allow("1.1.1.1")
    assert limiter.allow("1.1.1.1")
    assert not limiter.allow("1.1.1.1")
    assert limiter.allow("2.2.2.2")  # other clients are unaffected


def test_limiter_disabled_when_zero():
    limiter = RateLimiter(limit=0)
    assert all(limiter.allow("1.1.1.1") for _ in range(100))


def test_api_returns_429_when_limited(offline):
    client = create_app(LimitedConfig).test_client()
    for _ in range(2):
        assert client.post("/api/analyze", json={"url": "https://www.google.com"}).status_code == 200
    r = client.post("/api/analyze", json={"url": "https://www.google.com"})
    assert r.status_code == 429 and "error" in r.get_json()


def test_form_shows_message_when_limited(offline):
    client = create_app(LimitedConfig).test_client()
    for _ in range(2):
        client.post("/", data={"url": "https://www.google.com"})
    r = client.post("/", data={"url": "https://www.google.com"})
    assert r.status_code == 429
    assert "حاول مرة أخرى" in r.get_data(as_text=True)


class HeaderConfig(LimitedConfig):
    CLIENT_IP_HEADER = "CF-Connecting-IP"


def test_limit_uses_client_ip_header(offline):
    client = create_app(HeaderConfig).test_client()

    def hit(ip, peer):
        return client.post("/api/analyze", json={"url": "https://www.google.com"},
                           headers={"CF-Connecting-IP": ip}, environ_base={"REMOTE_ADDR": peer}).status_code

    # Same visitor through different edge IPs is still one client.
    assert hit("9.9.9.9", "10.0.0.1") == 200
    assert hit("9.9.9.9", "10.0.0.2") == 200
    assert hit("9.9.9.9", "10.0.0.3") == 429
    assert hit("8.8.8.8", "10.0.0.3") == 200


def test_health_is_never_limited(offline):
    client = create_app(LimitedConfig).test_client()
    assert all(client.get("/health").status_code == 200 for _ in range(10))
