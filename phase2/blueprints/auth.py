"""Authentication routes: login, logout, change password.

There is no registration endpoint here by design -- journalists are created by
an admin, and the first admin is created by the CLI bootstrap command.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from flask import (
    Blueprint,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)

from ..extensions import db
from ..forms import ChangePasswordForm, EmptyForm, LoginForm
from ..models import User, record_event
from ..security import (
    anonymous_only,
    current_user,
    dashboard_endpoint_for,
    is_safe_redirect_target,
    login_required,
    login_user,
    logout_user,
)
from ..services import burn_time_for_unknown_user, change_own_password

bp = Blueprint("auth", __name__, url_prefix="/auth")

# One message for every failure mode that involves credentials, so an attacker
# cannot tell "no such user" from "wrong password".
GENERIC_LOGIN_ERROR = "Invalid username or password."


def _client_ip() -> str | None:
    return request.headers.get("X-Forwarded-For", request.remote_addr)


def _next_is_for_role(user: User, next_url: str) -> bool:
    """Follow ``next`` only inside the user's own area, so an admin is never
    sent to a journalist page (or vice versa) just to be refused there.  This
    only chooses where to go; access is still checked by every route."""
    if not is_safe_redirect_target(next_url):
        return False
    other_area = "/journalist" if user.is_admin else "/admin"
    path = urlsplit(next_url).path
    return not (path == other_area or path.startswith(other_area + "/"))


@bp.route("/login", methods=["GET", "POST"])
@anonymous_only
def login():
    form = LoginForm()
    next_url = request.args.get("next") or request.form.get("next") or ""

    if form.validate_on_submit():
        username = User.normalize_username(form.username.data)
        user = User.get_by_username(username)
        ip = _client_ip()

        if user is None:
            burn_time_for_unknown_user()
            record_event(
                "login.failed", actor_username=username, detail="unknown user", ip_address=ip
            )
            flash(GENERIC_LOGIN_ERROR, "error")
            return render_template("phase2/login.html", form=form, next_url=next_url), 401

        password_ok = user.check_password(form.password.data or "")
        allowed, reason = user.can_login()

        if not password_ok:
            user.register_failed_login(
                current_app.config["MAX_FAILED_LOGINS"],
                current_app.config["LOCKOUT_MINUTES"],
            )
            record_event(
                "login.failed",
                actor_username=username,
                detail="bad password",
                ip_address=ip,
                commit=False,
            )
            db.session.commit()
            flash(GENERIC_LOGIN_ERROR, "error")
            return render_template("phase2/login.html", form=form, next_url=next_url), 401

        # Password is correct -- now the authorization gate.  PENDING and
        # DISABLED accounts are told why, because that is not a secret and the
        # user needs to know to contact the admin.
        if not allowed:
            record_event(
                "login.blocked",
                actor=user,
                target=user.username,
                detail=user.status,
                ip_address=ip,
            )
            flash(reason, "error")
            return render_template("phase2/login.html", form=form, next_url=next_url), 403

        user.register_successful_login()
        record_event(
            "login.success", actor=user, target=user.username, ip_address=ip, commit=False
        )
        db.session.commit()

        login_user(user)
        flash(f"Signed in as {user.username}.", "success")

        if user.must_change_password:
            return redirect(url_for("auth.change_password"))
        if _next_is_for_role(user, next_url):
            return redirect(next_url)
        return redirect(url_for(dashboard_endpoint_for(user)))

    if request.method == "POST":
        # Form-level validation failed (empty field, over-length, bad CSRF).
        return render_template("phase2/login.html", form=form, next_url=next_url), 400

    return render_template("phase2/login.html", form=form, next_url=next_url)


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    """POST-only so a stray <img src="/auth/logout"> cannot sign a user out."""
    form = EmptyForm()
    if not form.validate_on_submit():
        flash("Invalid logout request.", "error")
        return redirect(url_for("main.home"))

    user = g.current_user
    record_event("logout", actor=user, target=user.username, ip_address=_client_ip())
    logout_user()
    if request.form.get("switch") == "1":
        # "Switch account": the same logout, then the login page for the next user.
        flash("You have been signed out. Sign in with another account.", "success")
    else:
        flash("You have been signed out.", "success")
    return redirect(url_for("auth.login"))


@bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    user = g.current_user

    if form.validate_on_submit():
        ok = change_own_password(
            user,
            form.current_password.data or "",
            form.new_password.data or "",
            ip=_client_ip(),
        )
        if not ok:
            flash("Your current password is incorrect.", "error")
            return (
                render_template("phase2/change_password.html", form=form, user=user),
                400,
            )
        flash("Password updated successfully.", "success")
        return redirect(url_for(dashboard_endpoint_for(user)))

    status = 400 if request.method == "POST" else 200
    return render_template("phase2/change_password.html", form=form, user=user), status


@bp.route("/whoami")
@login_required
def whoami():
    """Small JSON endpoint the dashboards use to confirm the live session."""
    user = current_user()
    return {
        "username": user.username,
        "role": user.role,
        "status": user.status,
        "must_change_password": user.must_change_password,
    }
