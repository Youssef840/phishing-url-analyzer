"""HTTP routes: web UI + JSON API."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, render_template, request

from . import __version__
from .analyzer import AnalyzerSettings, InvalidURLError, analyze_url
from .analyzer.constants import CATEGORY_LABELS

bp = Blueprint("main", __name__)

EXAMPLES = [
    "https://www.google.com",
    "http://paypa1-secure-login.xyz/verify/account",
    "http://192.168.1.5@login-microsoft.tk:8080/update",
    "https://expired.badssl.com",
]


def _settings() -> AnalyzerSettings:
    cfg = current_app.config
    return AnalyzerSettings(
        vt_api_key=cfg.get("VT_API_KEY"),
        gsb_api_key=cfg.get("GSB_API_KEY"),
        allow_private_targets=cfg.get("ALLOW_PRIVATE_TARGETS", False),
        task_timeout=cfg.get("TASK_TIMEOUT", 20.0),
        cache_ttl=cfg.get("CACHE_TTL", 300),
    )


RATE_LIMIT_MSG = "عدد طلبات كبير. حاول مرة أخرى بعد دقيقة."


def _rate_limited() -> bool:
    limiter = current_app.extensions["phishguard_limiter"]
    return not limiter.allow(request.remote_addr or "unknown")


@bp.route("/", methods=["GET", "POST"])
def index():
    report, error, url = None, None, ""
    status = 200
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if _rate_limited():
            error, status = RATE_LIMIT_MSG, 429
        else:
            try:
                report = analyze_url(url, _settings())
            except InvalidURLError as exc:
                error = str(exc)
    return render_template(
        "index.html",
        report=report,
        error=error,
        url=url,
        examples=EXAMPLES,
        categories=CATEGORY_LABELS,
        vt_enabled=bool(current_app.config.get("VT_API_KEY")),
        gsb_enabled=bool(current_app.config.get("GSB_API_KEY")),
        version=__version__,
    ), status


@bp.post("/api/analyze")
def api_analyze():
    """POST {"url": "..."} -> full JSON report."""
    if _rate_limited():
        return jsonify({"error": RATE_LIMIT_MSG}), 429
    data = request.get_json(silent=True) or {}
    url = data.get("url") or request.form.get("url", "")
    try:
        return jsonify(analyze_url(url, _settings()))
    except InvalidURLError as exc:
        return jsonify({"error": str(exc)}), 400


@bp.get("/health")
def health():
    return jsonify(status="ok", version=__version__)


@bp.app_errorhandler(404)
def not_found(_exc):
    if request.path.startswith("/api/"):
        return jsonify(error="Not found"), 404
    return render_template("index.html", error="الصفحة غير موجودة.", report=None, url="",
                           examples=EXAMPLES, categories=CATEGORY_LABELS, version=__version__), 404


@bp.app_errorhandler(413)
def too_large(_exc):
    return jsonify(error="الطلب كبير جداً."), 413
