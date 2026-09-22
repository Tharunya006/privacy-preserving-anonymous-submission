"""Journalist / Authorized Receiver routes.

Only a user whose role is JOURNALIST *and* whose status is AUTHORIZED reaches
these views.  PENDING and DISABLED accounts are stopped at login, and an account
disabled mid-session is stopped on its next request by ``load_current_user``.
"""

from __future__ import annotations

from flask import Blueprint, g, render_template

from ..forms import EmptyForm
from ..models import Role
from ..security import journalist_required, role_required

bp = Blueprint("journalist", __name__, url_prefix="/journalist")


@bp.before_request
@role_required(Role.JOURNALIST)
def require_journalist():
    """Blanket gate for the whole blueprint."""
    return None


@bp.route("/")
@bp.route("/dashboard")
@journalist_required
def dashboard():
    return render_template(
        "phase2/journalist_dashboard.html",
        user=g.current_user,
        logout_form=EmptyForm(),
    )


@bp.route("/profile")
@journalist_required
def profile():
    return render_template("phase2/journalist_profile.html", user=g.current_user)


@bp.route("/inbox")
@journalist_required
def inbox():
    """Placeholder for the Phase 3/4 submission queue.

    The route exists now purely so the access-control boundary around it is
    written and tested in Phase 2; it holds no submission logic.
    """
    return render_template("phase2/journalist_inbox.html", user=g.current_user)
