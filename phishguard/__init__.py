"""PhishGuard - Phishing URL Analyzer (Flask application factory)."""

from __future__ import annotations

from dotenv import load_dotenv
from flask import Flask

__version__ = "1.0.0"

load_dotenv()


def create_app(config_object: str | type | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_object or "phishguard.config.Config")
    app.json.ensure_ascii = False
    app.json.sort_keys = False

    from .routes import bp

    app.register_blueprint(bp)

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com; "
            "img-src 'self' data:; frame-ancestors 'none'",
        )
        return resp

    return app
