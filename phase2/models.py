"""Database models for Phase 2 (authentication & authorization).

Only the ``User`` and ``AuditLog`` tables are defined here.  Submission-related
tables belong to Phase 3 and can be added alongside these without changing
anything below: ``AuditLog.user_id`` and any future ``Submission.receiver_id``
both point at ``phase2_users.id``.
"""

from __future__ import annotations

import enum
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import CheckConstraint
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")


def utcnow() -> datetime:
    """Timezone-aware UTC now (naive-safe for SQLite storage)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Role(str, enum.Enum):
    """Roles recognised by the RBAC layer."""

    ADMIN = "ADMIN"
    JOURNALIST = "JOURNALIST"

    def __str__(self) -> str:  # makes templates/flash messages readable
        return self.value


class Status(str, enum.Enum):
    """Account lifecycle states."""

    PENDING = "PENDING"        # created by an admin, not yet allowed in
    AUTHORIZED = "AUTHORIZED"  # may log in and use the dashboard
    DISABLED = "DISABLED"      # revoked; login always refused

    def __str__(self) -> str:
        return self.value


class User(db.Model):
    """An authenticated account: an admin or a journalist/authorized receiver.

    Anonymous sources deliberately have **no** row in this table -- they never
    register or log in.
    """

    __tablename__ = "phase2_users"
    __table_args__ = (
        CheckConstraint(
            "role IN ('ADMIN', 'JOURNALIST')", name="ck_phase2_users_role"
        ),
        CheckConstraint(
            "status IN ('PENDING', 'AUTHORIZED', 'DISABLED')",
            name="ck_phase2_users_status",
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    display_name = db.Column(db.String(120), nullable=True)
    email = db.Column(db.String(200), unique=True, nullable=True)

    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default=Role.JOURNALIST.value)
    status = db.Column(db.String(20), nullable=False, default=Status.PENDING.value)

    must_change_password = db.Column(db.Boolean, nullable=False, default=False)
    failed_login_attempts = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    last_login_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    created_by_id = db.Column(
        db.Integer, db.ForeignKey("phase2_users.id"), nullable=True
    )

    created_by = db.relationship("User", remote_side=[id], backref="created_users")

    # ------------------------------------------------------------------
    # Password handling -- plaintext passwords are never stored or logged.
    # ------------------------------------------------------------------
    def set_password(self, password: str, method: str = "pbkdf2:sha256:600000") -> None:
        if not password:
            raise ValueError("Password must not be empty.")
        self.password_hash = generate_password_hash(password, method=method)

    def check_password(self, password: str) -> bool:
        if not self.password_hash or not password:
            return False
        return check_password_hash(self.password_hash, password)

    @property
    def password(self):  # pragma: no cover - guard only
        raise AttributeError("Passwords are write-only.")

    # ------------------------------------------------------------------
    # Role / status helpers -- the single source of truth for RBAC checks.
    # ------------------------------------------------------------------
    @property
    def is_admin(self) -> bool:
        return self.role == Role.ADMIN.value

    @property
    def is_journalist(self) -> bool:
        return self.role == Role.JOURNALIST.value

    @property
    def is_authorized(self) -> bool:
        return self.status == Status.AUTHORIZED.value

    @property
    def is_locked(self) -> bool:
        if self.locked_until is None:
            return False
        return self.locked_until > utcnow()

    def can_login(self) -> tuple[bool, str]:
        """Return ``(allowed, reason)``.  Reason is safe to show the user."""
        if self.status == Status.DISABLED.value:
            return False, "This account has been disabled. Contact the administrator."
        if self.status == Status.PENDING.value:
            return False, "This account is pending authorization by an administrator."
        if self.is_locked:
            return False, "This account is temporarily locked. Try again later."
        return True, ""

    # ------------------------------------------------------------------
    # Brute-force counters
    # ------------------------------------------------------------------
    def register_failed_login(self, max_attempts: int, lockout_minutes: int) -> None:
        self.failed_login_attempts = (self.failed_login_attempts or 0) + 1
        if self.failed_login_attempts >= max_attempts:
            self.locked_until = utcnow() + timedelta(minutes=lockout_minutes)
            self.failed_login_attempts = 0

    def register_successful_login(self) -> None:
        self.failed_login_attempts = 0
        self.locked_until = None
        self.last_login_at = utcnow()

    # ------------------------------------------------------------------
    @staticmethod
    def normalize_username(raw: str) -> str:
        return (raw or "").strip().lower()

    @staticmethod
    def username_is_valid(raw: str) -> bool:
        return bool(USERNAME_RE.match(raw or ""))

    @classmethod
    def get_by_username(cls, raw: str) -> "User | None":
        username = cls.normalize_username(raw)
        if not username:
            return None
        return db.session.execute(
            db.select(cls).filter_by(username=username)
        ).scalar_one_or_none()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<User {self.username} {self.role}/{self.status}>"


class AuditLog(db.Model):
    """Append-only trail of security-relevant events.

    Useful for the viva ("who authorized this journalist, and when?") and a
    natural place for Phase 3+ to record submission access.
    """

    __tablename__ = "phase2_audit_log"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("phase2_users.id"), nullable=True)
    actor_username = db.Column(db.String(64), nullable=True)
    action = db.Column(db.String(64), nullable=False)
    target = db.Column(db.String(120), nullable=True)
    detail = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<AuditLog {self.action} {self.target}>"


def record_event(
    action: str,
    *,
    actor: "User | None" = None,
    actor_username: str | None = None,
    target: str | None = None,
    detail: str | None = None,
    ip_address: str | None = None,
    commit: bool = True,
) -> AuditLog:
    """Write one audit row.  Never stores passwords or submission content."""
    entry = AuditLog(
        actor_id=actor.id if actor else None,
        actor_username=actor.username if actor else actor_username,
        action=action,
        target=target,
        detail=detail,
        ip_address=ip_address,
    )
    db.session.add(entry)
    if commit:
        db.session.commit()
    return entry
