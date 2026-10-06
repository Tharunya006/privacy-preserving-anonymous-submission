"""WTForms definitions.

Using Flask-WTF gives two things at once: declarative server-side validation
(never trust the browser) and automatic CSRF tokens on every POST.
"""

from __future__ import annotations

import re

from flask import current_app
from flask_wtf import FlaskForm
from wtforms import BooleanField, PasswordField, SelectField, StringField, SubmitField
from wtforms.validators import (
    DataRequired,
    EqualTo,
    Length,
    Optional,
    Regexp,
    ValidationError,
)

from .models import Role, Status, User

USERNAME_PATTERN = r"^[A-Za-z0-9_.-]+$"
USERNAME_MESSAGE = "Use letters, digits, dot, dash or underscore only."
# Pragmatic email check -- avoids pulling in an extra dependency.
EMAIL_PATTERN = r"^[^@\s]+@[^@\s.]+\.[^@\s]+$"
EMAIL_MESSAGE = "Enter a valid email address."


def password_policy_error(password: str) -> str | None:
    """Length + character-class policy.  Returns the problem, or ``None`` if OK.

    The single definition of the policy: the forms below and the CLI's
    ``reset-password`` command both call it.
    """
    minimum = current_app.config.get("PASSWORD_MIN_LENGTH", 10)

    if len(password) < minimum:
        return f"Password must be at least {minimum} characters long."
    if len(password) > 128:
        return "Password must be at most 128 characters long."
    checks = [
        (r"[a-z]", "one lowercase letter"),
        (r"[A-Z]", "one uppercase letter"),
        (r"[0-9]", "one digit"),
        (r"[^A-Za-z0-9]", "one special character"),
    ]
    missing = [label for pattern, label in checks if not re.search(pattern, password)]
    if missing:
        return "Password must contain at least " + ", ".join(missing) + "."
    return None


def validate_password_strength(form, field) -> None:
    """WTForms validator: the password policy, enforced server-side."""
    error = password_policy_error(field.data or "")
    if error:
        raise ValidationError(error)


class LoginForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[DataRequired(message="Username is required."), Length(max=64)],
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(message="Password is required."), Length(max=128)],
    )
    submit = SubmitField("Sign in")


class CreateJournalistForm(FlaskForm):
    """Admin-only form.  There is no public registration anywhere in Phase 2."""

    username = StringField(
        "Username",
        validators=[
            DataRequired(message="Username is required."),
            Length(min=3, max=64, message="Username must be 3-64 characters."),
            Regexp(USERNAME_PATTERN, message=USERNAME_MESSAGE),
        ],
    )
    display_name = StringField("Display name", validators=[Optional(), Length(max=120)])
    email = StringField(
        "Email (optional)",
        validators=[Optional(), Length(max=200), Regexp(EMAIL_PATTERN, message=EMAIL_MESSAGE)],
    )
    password = PasswordField(
        "Temporary password",
        validators=[DataRequired(message="A temporary password is required."),
                    validate_password_strength],
    )
    confirm_password = PasswordField(
        "Confirm password",
        validators=[
            DataRequired(message="Please confirm the password."),
            EqualTo("password", message="Passwords do not match."),
        ],
    )
    authorize_now = BooleanField("Authorize immediately")
    submit = SubmitField("Create journalist")

    def validate_username(self, field) -> None:
        username = User.normalize_username(field.data)
        if User.get_by_username(username) is not None:
            raise ValidationError("That username is already taken.")

    def validate_email(self, field) -> None:
        if not field.data:
            return
        from .extensions import db

        existing = db.session.execute(
            db.select(User).filter_by(email=field.data.strip().lower())
        ).scalar_one_or_none()
        if existing is not None:
            raise ValidationError("That email is already registered.")


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField(
        "Current password", validators=[DataRequired(message="Current password is required.")]
    )
    new_password = PasswordField(
        "New password",
        validators=[DataRequired(message="New password is required."),
                    validate_password_strength],
    )
    confirm_password = PasswordField(
        "Confirm new password",
        validators=[
            DataRequired(message="Please confirm the new password."),
            EqualTo("new_password", message="Passwords do not match."),
        ],
    )
    submit = SubmitField("Update password")

    def validate_new_password(self, field) -> None:
        if self.current_password.data and field.data == self.current_password.data:
            raise ValidationError("The new password must differ from the current one.")


class ResetPasswordForm(FlaskForm):
    """Admin resets a journalist's password to a new temporary one."""

    new_password = PasswordField(
        "New temporary password",
        validators=[DataRequired(message="A new password is required."),
                    validate_password_strength],
    )
    confirm_password = PasswordField(
        "Confirm password",
        validators=[
            DataRequired(message="Please confirm the password."),
            EqualTo("new_password", message="Passwords do not match."),
        ],
    )
    submit = SubmitField("Reset password")


class StatusActionForm(FlaskForm):
    """CSRF-protected state change: authorize / disable / re-enable."""

    action = SelectField(
        "Action",
        choices=[
            (Status.AUTHORIZED.value, "Authorize"),
            (Status.DISABLED.value, "Disable"),
            (Status.PENDING.value, "Set pending"),
        ],
        validators=[DataRequired()],
    )
    submit = SubmitField("Apply")


class EmptyForm(FlaskForm):
    """Bare CSRF token holder for simple POST buttons (e.g. logout)."""

    submit = SubmitField("Confirm")


ROLE_CHOICES = [(Role.JOURNALIST.value, "Journalist"), (Role.ADMIN.value, "Admin")]
