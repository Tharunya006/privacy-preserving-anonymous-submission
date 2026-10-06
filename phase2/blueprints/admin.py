"""Admin-only routes.

Every view in this module is wrapped by ``@admin_required``.  The blueprint
also carries a ``before_request`` guard so a route added later without the
decorator is still protected -- defence in depth against a future mistake.
"""

from __future__ import annotations

from flask import (
    Blueprint,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)

from ..extensions import db
from ..forms import CreateJournalistForm, EmptyForm, ResetPasswordForm, StatusActionForm
from ..models import AuditLog, Role, Status, User, record_event
from ..security import admin_required, is_safe_redirect_target, role_required
from submissions.services import submission_counts

from ..services import (
    create_user,
    journalist_counts,
    list_journalists,
    reset_password,
    set_status,
)

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.before_request
@role_required(Role.ADMIN)
def require_admin():
    """Blanket gate for the whole blueprint."""
    return None


def _client_ip() -> str | None:
    return request.headers.get("X-Forwarded-For", request.remote_addr)


def _get_journalist_or_404(user_id: int) -> User:
    user = db.session.get(User, user_id)
    if user is None or user.role != Role.JOURNALIST.value:
        abort(404)
    return user


@bp.route("/")
@bp.route("/dashboard")
@admin_required
def dashboard():
    counts = journalist_counts()
    recent_events = list(
        db.session.execute(
            db.select(AuditLog).order_by(AuditLog.created_at.desc()).limit(10)
        ).scalars()
    )
    pending = list_journalists(Status.PENDING.value)
    return render_template(
        "phase2/admin_dashboard.html",
        user=g.current_user,
        counts=counts,
        pending=pending,
        recent_events=recent_events,
        action_form=StatusActionForm(),
        # Counts only: admins manage accounts and never read report content.
        submission_counts=submission_counts(),
    )


@bp.route("/journalists")
@admin_required
def manage_journalists():
    status_filter = request.args.get("status", "").strip().upper() or None
    if status_filter and status_filter not in {s.value for s in Status}:
        status_filter = None
    journalists = list_journalists(status_filter)
    return render_template(
        "phase2/manage_journalists.html",
        user=g.current_user,
        journalists=journalists,
        status_filter=status_filter,
        statuses=[s.value for s in Status],
        action_form=EmptyForm(),
        counts=journalist_counts(),
    )


@bp.route("/journalists/new", methods=["GET", "POST"])
@admin_required
def add_journalist():
    form = CreateJournalistForm()

    if form.validate_on_submit():
        status = Status.AUTHORIZED if form.authorize_now.data else Status.PENDING
        try:
            user = create_user(
                form.username.data or "",
                form.password.data or "",
                role=Role.JOURNALIST,
                status=status,
                display_name=form.display_name.data,
                email=form.email.data,
                must_change_password=True,
                created_by=g.current_user,
                commit=False,
            )
            record_event(
                "journalist.created",
                actor=g.current_user,
                target=user.username,
                detail=f"status={status.value}",
                ip_address=_client_ip(),
                commit=False,
            )
            db.session.commit()
        except ValueError as exc:
            db.session.rollback()
            form.username.errors = list(form.username.errors) + [str(exc)]
            return (
                render_template("phase2/add_journalist.html", form=form, user=g.current_user),
                400,
            )

        flash(
            f"Journalist '{user.username}' created with status {user.status}. "
            "They must change the temporary password at first sign-in.",
            "success",
        )
        return redirect(url_for("admin.manage_journalists"))

    status_code = 400 if request.method == "POST" else 200
    return (
        render_template("phase2/add_journalist.html", form=form, user=g.current_user),
        status_code,
    )


@bp.route("/journalists/<int:user_id>/status", methods=["POST"])
@admin_required
def change_status(user_id: int):
    """Authorize / disable / set-pending.  POST + CSRF token required."""
    form = EmptyForm()
    if not form.validate_on_submit():
        flash("Invalid or expired request. Please try again.", "error")
        return redirect(url_for("admin.manage_journalists"))

    target = _get_journalist_or_404(user_id)
    requested = (request.form.get("status") or "").strip().upper()
    if requested not in {s.value for s in Status}:
        flash("Unknown status requested.", "error")
        return redirect(url_for("admin.manage_journalists"))

    try:
        set_status(target, requested, actor=g.current_user, ip=_client_ip())
    except ValueError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return redirect(url_for("admin.manage_journalists"))

    flash(f"'{target.username}' is now {target.status}.", "success")
    return_to = request.form.get("return_to")
    if not is_safe_redirect_target(return_to):
        return_to = url_for("admin.manage_journalists")
    return redirect(return_to)


@bp.route("/journalists/<int:user_id>", methods=["GET"])
@admin_required
def journalist_detail(user_id: int):
    target = _get_journalist_or_404(user_id)
    events = list(
        db.session.execute(
            db.select(AuditLog)
            .filter_by(target=target.username)
            .order_by(AuditLog.created_at.desc())
            .limit(20)
        ).scalars()
    )
    return render_template(
        "phase2/journalist_detail.html",
        user=g.current_user,
        target=target,
        events=events,
        action_form=EmptyForm(),
        reset_form=ResetPasswordForm(),
    )


@bp.route("/journalists/<int:user_id>/reset-password", methods=["POST"])
@admin_required
def reset_journalist_password(user_id: int):
    target = _get_journalist_or_404(user_id)
    form = ResetPasswordForm()
    if not form.validate_on_submit():
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field}: {error}", "error")
        return redirect(url_for("admin.journalist_detail", user_id=user_id))

    reset_password(
        target,
        form.new_password.data or "",
        actor=g.current_user,
        ip=_client_ip(),
    )
    flash(
        f"Temporary password set for '{target.username}'. "
        "They must change it at next sign-in.",
        "success",
    )
    return redirect(url_for("admin.journalist_detail", user_id=user_id))


@bp.route("/audit")
@admin_required
def audit_log():
    events = list(
        db.session.execute(
            db.select(AuditLog).order_by(AuditLog.created_at.desc()).limit(100)
        ).scalars()
    )
    return render_template("phase2/audit_log.html", user=g.current_user, events=events)
