"""Public, unauthenticated pages."""

from __future__ import annotations

from flask import Blueprint, redirect, render_template, url_for

from ..security import current_user, dashboard_endpoint_for

bp = Blueprint("main", __name__)


@bp.route("/")
def home():
    """Landing page.

    Deliberately public: an anonymous source must be able to reach the system
    without an account, a login, or any identifying step.
    """
    return render_template("phase2/home.html", user=current_user())


@bp.route("/dashboard")
def dashboard_redirect():
    """Convenience route that sends each role to its own dashboard."""
    user = current_user()
    if user is None:
        return redirect(url_for("auth.login", next="/dashboard"))
    return redirect(url_for(dashboard_endpoint_for(user)))


@bp.route("/unauthorized")
def unauthorized():
    """Human-readable 403 page, also reachable directly."""
    return render_template("phase2/unauthorized.html", user=current_user()), 403
