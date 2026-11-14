<div align="center">

# 🛡️ PhishGuard — Phishing URL Analyzer

**Analyze any URL in seconds and get an instant risk verdict: `Safe` · `Suspicious` · `Malicious`**

### 🌐 [Try it live → phishguard-x33e.onrender.com](https://phishguard-x33e.onrender.com)
<sub>Free hosting: the first visit after a quiet period can take about a minute to wake up.</sub>

[![CI](https://github.com/Youssef840/phishing-url-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/Youssef840/phishing-url-analyzer/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/flask-3.x-black?logo=flask)
![License](https://img.shields.io/badge/license-MIT-green)

<!-- Add a screenshot at docs/screenshot.png and uncomment: <img src="docs/screenshot.png" alt="PhishGuard screenshot" width="820"> -->

</div>

---

## ✨ Features

| Module | What it checks |
|---|---|
| **Lexical heuristics** | `@` in the authority, URL length, raw / decimal / hex IP hosts, non-standard ports, missing HTTPS, Punycode & non-Latin homographs, **brand impersonation** (`paypa1`, `micr0soft`), **typosquatting** (Levenshtein distance), brand names in sub-domains / paths, high-risk TLDs, URL shorteners, sub-domain depth, hyphens, random-looking names (Shannon entropy), phishing keywords, open redirects, heavy encoding, executable downloads |
| **WHOIS** | Creation date, **domain age**, expiry, registrar, country, name servers, registration length |
| **SSL / TLS** | Live handshake, chain & hostname verification, issuer, validity window, days remaining, TLS version, SANs |
| **DNS** | Resolution and private / internal IP detection |
| **Reputation (optional)** | **VirusTotal v3** and **Google Safe Browsing v4** — a blacklist hit forces a `Malicious` verdict |

Plus:
- 🌐 Clean Arabic RTL UI (Bootstrap 5) with a score ring, per-indicator breakdown, and JSON export
- 🔌 JSON REST API and 🖥️ CLI (with verdict-based exit codes for scripting)
- ⚡ Checks run concurrently under one shared time budget, with result caching
- 🔒 SSRF guard, strict CSP and security headers, secrets kept in `.env`
- ✅ Offline test suite (pytest) + GitHub Actions CI + Docker image

## 🧮 Scoring

Every finding adds risk points. The total is capped at 100:

| Score | Verdict |
|---|---|
| 0 – 29 | 🟢 **Safe** |
| 30 – 59 | 🟡 **Suspicious** |
| 60 – 100 | 🔴 **Malicious** |

## ☁️ Deploy online

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/Youssef840/phishing-url-analyzer)

One click deploys the Docker image on Render's free plan using [`render.yaml`](render.yaml), with a per-IP rate limit
(15 analyses/minute) and the private-IP guard enabled. Free instances sleep when idle, so the first request can take
about a minute.

## 🚀 Quick start

```bash
git clone https://github.com/Youssef840/phishing-url-analyzer.git
cd phishing-url-analyzer
python -m venv venv
# Windows: venv\Scripts\activate    |   Linux/macOS: source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # optional: add VT_API_KEY / GSB_API_KEY
python run.py
```

Open **http://127.0.0.1:5000**.

### Docker
```bash
docker build -t phishguard .
docker run -p 8000:8000 --env-file .env phishguard
```

## 🔌 API

```bash
curl -X POST http://127.0.0.1:5000/api/analyze \
     -H "Content-Type: application/json" \
     -d '{"url": "http://paypa1-secure-login.xyz/verify"}'
```

<details>
<summary>Example response (truncated)</summary>

```json
{
  "url": "http://paypa1-secure-login.xyz/verify",
  "domain": "paypa1-secure-login.xyz",
  "score": 87,
  "verdict": "malicious",
  "indicators": [
    { "category": "heuristics", "severity": "high", "points": 25,
      "title": "Brand name embedded in an unofficial domain" }
  ],
  "whois": { "age_days": null },
  "ssl": { "valid": false },
  "reputation": { "virustotal": { "status": "disabled" } }
}
```
</details>

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/analyze` | Body `{"url": "..."}` → full report |
| `GET` | `/health` | Liveness probe |

## 🖥️ CLI

```bash
python -m phishguard.cli https://example.com
python -m phishguard.cli https://example.com --json
```
Exit codes: `0` safe · `1` suspicious · `3` malicious · `2` invalid input.

## ⚙️ Configuration (`.env`)

| Variable | Default | Description |
|---|---|---|
| `VT_API_KEY` | — | VirusTotal API key |
| `GSB_API_KEY` | — | Google Safe Browsing API key |
| `ALLOW_PRIVATE_TARGETS` | `false` | Allow TLS checks against private IPs |
| `TASK_TIMEOUT` | `20` | Time budget for network checks (seconds) |
| `CACHE_TTL` | `300` | Report cache lifetime (seconds, `0` disables) |
| `HOST` / `PORT` | `127.0.0.1` / `5000` | Dev server binding |
| `RATE_LIMIT_PER_MINUTE` | `0` | Analyses allowed per IP per minute (`0` disables) |
| `TRUSTED_PROXIES` | `0` | Reverse proxies in front of the app, so the real client IP is used |
| `CLIENT_IP_HEADER` | — | Header holding the real client IP from a trusted edge (e.g. `CF-Connecting-IP`) |

## 🗂️ Project structure

```
phishing-url-analyzer/
├── phishguard/
│   ├── __init__.py          # Flask app factory + security headers
│   ├── config.py            # Environment-driven configuration
│   ├── routes.py            # Web UI + JSON API
│   ├── cli.py               # Command-line interface
│   ├── analyzer/
│   │   ├── engine.py        # Orchestration, scoring, caching
│   │   ├── heuristics.py    # Lexical URL checks
│   │   ├── whois_check.py   # Domain age / registrar
│   │   ├── ssl_check.py     # Certificate inspection
│   │   ├── dns_check.py     # Resolution + private IP detection
│   │   ├── reputation.py    # VirusTotal + Safe Browsing
│   │   ├── constants.py     # Brands, TLDs, keywords, thresholds
│   │   └── utils.py         # Normalisation & helpers
│   ├── templates/           # Jinja2 (Bootstrap 5 RTL)
│   └── static/              # CSS / JS / favicon
├── tests/                   # pytest suite (fully offline)
├── docs/                    # Screenshots
├── .github/workflows/ci.yml # Lint + tests on Python 3.10–3.12
├── Dockerfile
├── requirements.txt / requirements-dev.txt
├── pyproject.toml
└── run.py
```

## 🧪 Development

```bash
pip install -r requirements-dev.txt
pytest --cov=phishguard
ruff check .
```

## ⚠️ Disclaimer

PhishGuard is a heuristic, educational tool. A `Safe` verdict is **not** a guarantee. Always stay cautious with unexpected links.
The analyzer never renders the target page. It only performs DNS, WHOIS, a TLS handshake, and optional API lookups.

## 📄 License

[MIT](LICENSE)
