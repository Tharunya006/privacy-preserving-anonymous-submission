"""Business logic shared by the blueprints and the CLI.

Keeping it here (rather than inside view functions) means the CLI bootstrap and
the admin dashboard create accounts through exactly the same code path, and the
rules stay testable without an HTTP request.
"""

from __future__ import annotations

from flask import current_app

from .extensions import db
from .models import Role, Status, User, record_event

# A throw-away hash compared against when the username does not exist, so a
# failed login costs roughly the same time either way (no user enumeration by
# timing).
_DUMMY_HASH: str | None = None


def _dummy_hash() -> str:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        placeholder = User()
        placeholder.set_password(
            "not-a-real-password", method=current_app.config["PASSWORD_HASH_METHOD"]
        )
        _DUMMY_HASH = placeholder.password_hash
    return _DUMMY_HASH


def burn_time_for_unknown_user() -> None:
    """Perform a hash comparison even when no such account exists."""
    from werkzeug.security import check_password_hash

    check_password_hash(_dummy_hash(), "not-a-real-password-either")


def create_user(
    username: str,
    password: str,
    *,
    role: Role | str = Role.JOURNALIST,
    status: Status | str = Status.PENDING,
    display_name: str | None = None,
    email: str | None = None,
    must_change_password: bool = True,
    created_by: User | None = None,
    commit: bool = True,
) -> User:
    """Create an account.  Raises ``ValueError`` on invalid or duplicate input."""
    username = User.normalize_username(username)
    if not User.username_is_valid(username):
        raise ValueError("Username must be 3-64 characters: letters, digits, . _ or -")
    if User.get_by_username(username) is not None:
        raise ValueError(f"Username '{username}' is already taken.")

    email_value = (email or "").strip().lower() or None
    if email_value:
        existing = db.session.execute(
            db.select(User).filter_by(email=email_value)
        ).scalar_one_or_none()
        if existing is not None:
            raise ValueError("That email is already registered.")

    user = User(
        username=username,
        display_name=(display_name or "").strip() or None,
        email=email_value,
        role=role.value if isinstance(role, Role) else str(role),
        status=status.value if isinstance(status, Status) else str(status),
        must_change_password=must_change_password,
        created_by_id=created_by.id if created_by else None,
    )
    user.set_password(password, method=current_app.config["PASSWORD_HASH_METHOD"])

    db.session.add(user)
    if commit:
        db.session.commit()
    return user


def create_admin(
    username: str, password: str, *, must_change_password: bool = False, **kwargs
) -> User:
    """Bootstrap helper -- admins are only ever created this way (never via HTTP)."""
    return create_user(
        username,
        password,
        role=Role.ADMIN,
        status=Status.AUTHORIZED,
        must_change_password=must_change_password,
        **kwargs,
    )


def set_status(
    user: User, new_status: Status | str, *, actor: User | None = None, ip: str | None = None
) -> User:
    """Change an account's status, with guard rails and an audit entry."""
    value = new_status.value if isinstance(new_status, Status) else str(new_status)
    if value not in {s.value for s in Status}:
        raise ValueError(f"Unknown status '{value}'.")
    if user.is_admin:
        raise ValueError("Admin accounts cannot be re-statused from the dashboard.")
    if actor is not None and actor.id == user.id:
        raise ValueError("You cannot change your own status.")

    previous = user.status
    user.status = value
    if value == Status.AUTHORIZED.value:
        # A fresh authorization clears any lockout left from earlier attempts.
        user.failed_login_attempts = 0
        user.locked_until = None

    record_event(
        f"status.{value.lower()}",
        actor=actor,
        target=user.username,
        detail=f"{previous} -> {value}",
        ip_address=ip,
        commit=False,
    )
    db.session.commit()
    return user


def reset_password(
    user: User,
    new_password: str,
    *,
    actor: User | None = None,
    ip: str | None = None,
    must_change_password: bool = True,
    allow_admin: bool = False,
    detail: str | None = None,
) -> User:
    """Password reset without the old password (admin dashboard or CLI).

    By default an admin account can only be reset by that same admin, so one
    admin cannot take over another through the web UI.  ``allow_admin`` lifts
    that guard and is passed only by the ``reset-password`` CLI command, whose
    operator already has shell access to the server and its database.
    """
    if user.is_admin and not allow_admin and (actor is None or actor.id != user.id):
        raise ValueError("Another admin's password cannot be reset from here.")
    user.set_password(new_password, method=current_app.config["PASSWORD_HASH_METHOD"])
    user.must_change_password = must_change_password
    user.failed_login_attempts = 0
    user.locked_until = None
    record_event(
        "password.reset",
        actor=actor,
        target=user.username,
        detail=detail,
        ip_address=ip,
        commit=False,
    )
    db.session.commit()
    return user


def change_own_password(
    user: User, current_password: str, new_password: str, *, ip: str | None = None
) -> bool:
    """Self-service password change.  Returns False if the old password is wrong."""
    if not user.check_password(current_password):
        record_event(
            "password.change_failed", actor=user, target=user.username, ip_address=ip
        )
        return False
    user.set_password(new_password, method=current_app.config["PASSWORD_HASH_METHOD"])
    user.must_change_password = False
    record_event(
        "password.changed", actor=user, target=user.username, ip_address=ip, commit=False
    )
    db.session.commit()
    return True


def list_journalists(status: str | None = None) -> list[User]:
    query = db.select(User).filter_by(role=Role.JOURNALIST.value)
    if status:
        query = query.filter_by(status=status)
    return list(db.session.execute(query.order_by(User.created_at.desc())).scalars())


def journalist_counts() -> dict[str, int]:
    counts = {s.value: 0 for s in Status}
    for user in list_journalists():
        counts[user.status] = counts.get(user.status, 0) + 1
    counts["TOTAL"] = sum(counts[s.value] for s in Status)
    return counts
