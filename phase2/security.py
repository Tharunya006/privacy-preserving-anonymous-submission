"""Session handling and the RBAC enforcement layer.

Every protected view is guarded by one of the decorators below.  The checks run
on the **server** for each request and re-read the account from the database, so
hiding a button in a template is never what keeps a user out, and an account
that is disabled mid-session loses access on its very next request.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse

from flask import (
    abort,
    current_app,
    flash,
    g,
    redirect,
    request,
    session,
    url_for,
)

from .extensions import db
from .models import Role, Status, User, utcnow

SESSION_USER_ID = "uid"
SESSION_ROLE = "role"
SESSION_CREATED_AT = "created_at"
SESSION_LAST_SEEN = "last_seen"


# ---------------------------------------------------------------------------
# Session lifecycle
# ---------------------------------------------------------------------------
def login_user(user: User) -> None:
    """Start an authenticated session.

    ``session.clear()`` plus a brand new session cookie defeats session
    fixation: any value an attacker planted before login is discarded.
    """
    session.clear()
    session[SESSION_USER_ID] = user.id
    session[SESSION_ROLE] = user.role
    session[SESSION_CREATED_AT] = utcnow().isoformat()
    session[SESSION_LAST_SEEN] = utcnow().isoformat()
    session.permanent = True
    session.modified = True


def logout_user() -> None:
    """Destroy the session completely (no partial state left behind)."""
    session.clear()
    session.modified = True
    g.pop("current_user", None)


def _parse_ts(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def _session_expired() -> bool:
    minutes = current_app.config.get("PHASE2_IDLE_TIMEOUT_MINUTES", 15)
    if not minutes:
        return False
    last_seen = _parse_ts(session.get(SESSION_LAST_SEEN))
    if last_seen is None:
        return True
    return utcnow() - last_seen > timedelta(minutes=minutes)


def reset_user_cache() -> None:
    """Drop the per-request cache of the signed-in user.

    ``g`` is bound to the *application* context, not the request, and a single
    app context can serve several requests (this is exactly what a test client
    inside ``with app.app_context()`` does).  Clearing the cache at the start of
    every request stops one request's answer from leaking into the next.
    """
    g.pop("current_user", None)
    g.pop("session_expired", None)
    g.pop("access_revoked", None)


def load_current_user() -> User | None:
    """Resolve the session into a live ``User`` row, or ``None``.

    Registered as a ``before_request`` hook.  Re-reading from the database on
    every request is what makes "admin disables a journalist" take effect
    immediately instead of at the next login.
    """
    if "current_user" in g:
        return g.current_user

    g.current_user = None
    user_id = session.get(SESSION_USER_ID)
    if user_id is None:
        return None

    if _session_expired():
        logout_user()
        g.session_expired = True
        return None

    user = db.session.get(User, user_id)
    if user is None:
        logout_user()
        return None

    # The account must still be usable, and its role must match what the
    # session claims -- a role change forces re-authentication.
    if user.status != Status.AUTHORIZED.value or user.role != session.get(SESSION_ROLE):
        logout_user()
        g.access_revoked = True
        return None

    session[SESSION_LAST_SEEN] = utcnow().isoformat()
    session.modified = True
    g.current_user = user
    return user


def current_user() -> User | None:
    """Accessor used by views and templates."""
    return load_current_user()


def is_safe_redirect_target(target: str | None) -> bool:
    """Only allow relative, same-host redirects (blocks open redirects)."""
    if not target:
        return False
    if target.startswith("//") or "\\" in target:
        return False
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc:
        return False
    return target.startswith("/")


def dashboard_endpoint_for(user: User) -> str:
    return "admin.dashboard" if user.is_admin else "journalist.dashboard"


# ---------------------------------------------------------------------------
# Decorators -- the RBAC gate
# ---------------------------------------------------------------------------
def login_required(view):
    """Reject anyone without a valid, authorized session."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        user = load_current_user()
        if user is None:
            if g.pop("access_revoked", False):
                flash("Your access has changed. Please sign in again.", "error")
            elif g.pop("session_expired", False):
                flash("Your session timed out. Please sign in again.", "error")
            else:
                flash("Please sign in to continue.", "error")
            return redirect(url_for("auth.login", next=request.full_path.rstrip("?")))
        return view(*args, **kwargs)

    return wrapper


def role_required(*roles: Role | str):
    """Require an authenticated session **and** one of the given roles.

    A signed-in user with the wrong role gets 403 (via the unauthorized page),
    not a redirect to login -- they are authenticated but not permitted.
    """
    allowed = {r.value if isinstance(r, Role) else str(r) for r in roles}

    def decorator(view):
        @wraps(view)
        @login_required
        def wrapper(*args, **kwargs):
            user = g.current_user
            if user.role not in allowed:
                abort(403)
            return view(*args, **kwargs)

        return wrapper

    return decorator


def admin_required(view):
    """Shorthand for ``role_required(Role.ADMIN)``."""
    return role_required(Role.ADMIN)(view)


def journalist_required(view):
    """Authorized journalists only.

    ``load_current_user`` already guarantees ``status == AUTHORIZED``; the
    explicit re-check below documents the rule and protects against a future
    refactor loosening the loader.
    """

    @wraps(view)
    @role_required(Role.JOURNALIST)
    def wrapper(*args, **kwargs):
        if not g.current_user.is_authorized:
            abort(403)
        return view(*args, **kwargs)

    return wrapper


def anonymous_only(view):
    """Keep signed-in users off the login page."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        user = load_current_user()
        if user is not None:
            return redirect(url_for(dashboard_endpoint_for(user)))
        return view(*args, **kwargs)

    return wrapper
