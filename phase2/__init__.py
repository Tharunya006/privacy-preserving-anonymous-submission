"""Phase 2 -- Authentication & Authorization.

Owns the application factory for the unified Privacy Preserving Anonymous
Submission System.  ``create_app`` builds the one Flask app: Phase 2's
authentication, RBAC and dashboards plus the Phase 1 anonymous submission portal
(the ``submissions`` package), all sharing one SQLAlchemy database.  The entry
point is ``app.py`` (see ``docs/integration_notes.md``).
"""

from __future__ import annotations

import os
import warnings
from pathlib import Path

from flask import Flask, g, redirect, render_template, request, url_for

from .config import (
    INSTANCE_DIR,
    ensure_database_directory,
    generate_dev_secret,
    normalise_database_uri,
    resolve_config,
)
from .extensions import csrf, db

__version__ = "2.0.0"

# Endpoints a user with ``must_change_password`` may still reach.
PASSWORD_CHANGE_EXEMPT = {
    "auth.change_password",
    "auth.logout",
    "auth.login",
    "main.home",
    "main.unauthorized",
    "static",
    "phase2_static",
    # Public source pages never require an account, so never gate them.
    "source.submit",
    "source.status",
    "source.legacy_login",
}


def create_app(config_name: str | None = None, **overrides) -> Flask:
    """Application factory for the unified application."""
    app = Flask(
        __name__,
        instance_path=str(INSTANCE_DIR),
        template_folder="templates",
        static_folder="static",
        static_url_path="/phase2-static",
    )
    app.config.from_object(resolve_config(config_name))
    app.config.update(overrides)

    _resolve_secret_key(app)
    app.config["SQLALCHEMY_DATABASE_URI"] = normalise_database_uri(
        app.config["SQLALCHEMY_DATABASE_URI"]
    )
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    ensure_database_directory(app.config["SQLALCHEMY_DATABASE_URI"])

    db.init_app(app)
    csrf.init_app(app)

    from submissions import register_submissions

    register_submissions(app)
    register_phase2(app)
    _register_error_handlers(app)
    _register_security_headers(app)

    from .cli import register_cli

    register_cli(app)
    return app


def register_phase2(app: Flask, url_prefix: str = "") -> Flask:
    """Attach Phase 2 blueprints and hooks to *any* Flask app.

    Called by ``create_app``; kept separate so the auth layer can be mounted
    on any app.  It assumes ``db`` and ``csrf`` are already initialised.
    """
    from .blueprints import admin as admin_bp
    from .blueprints import auth as auth_bp
    from .blueprints import journalist as journalist_bp
    from .blueprints import main as main_bp
    from .security import current_user, load_current_user, reset_user_cache

    # The public landing page (which links to the submission portal) is only
    # registered when no other blueprint named "main" already owns the root.
    if "main" not in app.blueprints:
        app.register_blueprint(main_bp.bp, url_prefix=url_prefix or None)
    app.register_blueprint(auth_bp.bp, url_prefix=f"{url_prefix}/auth")
    app.register_blueprint(admin_bp.bp, url_prefix=f"{url_prefix}/admin")
    app.register_blueprint(journalist_bp.bp, url_prefix=f"{url_prefix}/journalist")

    @app.before_request
    def _phase2_load_user():
        reset_user_cache()
        load_current_user()

    @app.before_request
    def _phase2_force_password_change():
        """A user carrying a temporary password can go nowhere else."""
        user = g.get("current_user")
        if user is None or not user.must_change_password:
            return None
        if request.endpoint in PASSWORD_CHANGE_EXEMPT:
            return None
        if request.endpoint and request.endpoint.endswith(".static"):
            return None
        return redirect(url_for("auth.change_password"))

    @app.context_processor
    def _phase2_context():
        from .forms import EmptyForm
        from .models import Role, Status

        return {
            "current_user": current_user,
            # Render-only token holder: formdata=None so building it never reads
            # the request body (which would re-raise 413 on an oversize upload).
            "logout_form": EmptyForm(formdata=None),
            "Role": Role,
            "Status": Status,
            "phase2_version": __version__,
        }

    return app


def _resolve_secret_key(app: Flask) -> None:
    """Never ship a hard-coded key; fail loudly in production, warn in dev."""
    if app.config.get("SECRET_KEY"):
        return

    env = (os.environ.get("PHASE2_ENV") or "development").strip().lower()
    if env == "production":
        raise RuntimeError(
            "PHASE2_SECRET_KEY is not set. Refusing to start in production. "
            "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(48))\""
        )
    app.config["SECRET_KEY"] = generate_dev_secret()
    warnings.warn(
        "PHASE2_SECRET_KEY is not set - using a random development key. "
        "Sessions will not survive a restart. Copy .env.example to .env to fix.",
        RuntimeWarning,
        stacklevel=2,
    )


def _register_error_handlers(app: Flask) -> None:
    from .security import current_user

    @app.errorhandler(400)
    def _bad_request(error):
        return render_template("phase2/error.html", code=400,
                               message="Bad request.", user=current_user()), 400

    @app.errorhandler(403)
    def _forbidden(error):
        return render_template("phase2/unauthorized.html", user=current_user()), 403

    @app.errorhandler(404)
    def _not_found(error):
        return render_template("phase2/error.html", code=404,
                               message="Page not found.", user=current_user()), 404

    @app.errorhandler(405)
    def _method_not_allowed(error):
        return render_template("phase2/error.html", code=405,
                               message="Method not allowed.", user=current_user()), 405

    @app.errorhandler(413)
    def _too_large(error):
        limit_mb = app.config.get("EVIDENCE_MAX_BYTES", 0) // (1024 * 1024)
        return render_template("phase2/error.html", code=413,
                               message=f"The upload is too large. Evidence files may be "
                                       f"at most {limit_mb} MB.",
                               user=current_user()), 413

    @app.errorhandler(500)
    def _server_error(error):
        db.session.rollback()
        return render_template("phase2/error.html", code=500,
                               message="Something went wrong on our side. Please try again.",
                               user=current_user()), 500

    from flask_wtf.csrf import CSRFError

    @app.errorhandler(CSRFError)
    def _csrf_error(error):
        return (
            render_template(
                "phase2/error.html",
                code=400,
                message="Your form session expired or the CSRF token was invalid. "
                        "Please go back and try again.",
                user=current_user(),
            ),
            400,
        )


def _register_security_headers(app: Flask) -> None:
    @app.after_request
    def _headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            "script-src 'self'; form-action 'self'; frame-ancestors 'none'; "
            "base-uri 'self'",
        )
        response.headers.setdefault(
            "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
        )
        # Never cache authenticated pages, or the source pages that display a
        # submission token or a report's status.
        if request.path.startswith(("/auth", "/admin", "/journalist", "/submit", "/status")):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
            response.headers["Pragma"] = "no-cache"
        return response
