def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.get_json()["status"] == "ok"


def test_index_page(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "محلل روابط التصيد" in r.get_data(as_text=True)
    assert "Content-Security-Policy" in r.headers


def test_form_submission_renders_report(client):
    r = client.post("/", data={"url": "https://www.google.com"})
    body = r.get_data(as_text=True)
    assert r.status_code == 200
    assert "آمن" in body and "WHOIS" in body


def test_form_invalid_url(client):
    r = client.post("/", data={"url": "javascript:alert(1)"})
    assert "غير مدعوم" in r.get_data(as_text=True)


def test_api_analyze(client):
    r = client.post("/api/analyze", json={"url": "http://192.168.1.5@login-microsoft.tk/update"})
    data = r.get_json()
    assert r.status_code == 200
    assert data["verdict"] in ("suspicious", "malicious")
    assert data["host"] == "login-microsoft.tk"


def test_api_bad_request(client):
    r = client.post("/api/analyze", json={})
    assert r.status_code == 400 and "error" in r.get_json()


def test_api_404_is_json(client):
    r = client.get("/api/nope")
    assert r.status_code == 404 and r.get_json()["error"]
