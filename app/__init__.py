from __future__ import annotations

from flask import Flask, jsonify, request
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix

from app.config import Config, load_or_create_secret, validate_runtime_config


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    if not app.config.get("SECRET_KEY"):
        if app.config.get("UTAMO_ENVIRONMENT") == "production":
            raise RuntimeError("UTAMO_SECRET_KEY e obrigatoria em producao.")
        app.config["SECRET_KEY"] = load_or_create_secret()
    validate_runtime_config(app)

    trusted_proxy_hops = int(app.config.get("TRUSTED_PROXY_HOPS", 0))
    if trusted_proxy_hops:
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=trusted_proxy_hops,
            x_proto=trusted_proxy_hops,
        )

    from app.database.db import init_db

    init_db()

    from app.rf.smart_workflow import recover_interrupted_smart_scans

    recover_interrupted_smart_scans()

    from app.routes.admin import admin_bp
    from app.routes.api import api_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.rfid_routes import rfid_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(rfid_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(admin_bp)

    from app.security import init_security

    init_security(app)

    @app.after_request
    def secure_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        response.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        )
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'self'; connect-src 'self'; font-src 'self'; "
            "form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; "
            "object-src 'none'; script-src 'self'; style-src 'self'",
        )
        response.headers.setdefault("Cache-Control", "no-store")
        if request.is_secure:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000"
            )
        return response

    @app.errorhandler(RequestEntityTooLarge)
    def upload_too_large(_exc):
        payload = {
            "status": "error",
            "message": f"Arquivo acima do limite de {app.config['MAX_CONTENT_LENGTH']} bytes.",
        }
        if request.path.startswith("/api/"):
            return jsonify(payload), 413
        return payload["message"], 413

    return app
