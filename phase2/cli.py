"""Flask CLI commands for the unified application.

The bootstrap admin is created here rather than through any web route: there is
no public admin registration, and the password is supplied by the operator at
the terminal (or through an environment variable for scripted setup) so it never
appears in the source tree.
"""

from __future__ import annotations

import getpass
import os
import secrets
import string
import sys

import click
from flask import Flask
from flask.cli import with_appcontext

from .extensions import db
from .forms import password_policy_error
from .models import Role, Status, User, record_event
from .services import create_admin, create_user, list_journalists, reset_password, set_status

ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*-_=+"


def generate_password(length: int = 16) -> str:
    """Cryptographically random password that satisfies the strength policy."""
    while True:
        candidate = "".join(secrets.choice(ALPHABET) for _ in range(length))
        if (
            any(c.islower() for c in candidate)
            and any(c.isupper() for c in candidate)
            and any(c.isdigit() for c in candidate)
            and any(not c.isalnum() for c in candidate)
        ):
            return candidate


def _prompt_password(env_var: str, label: str) -> str:
    """Read a password from the environment or, failing that, prompt twice."""
    from_env = os.environ.get(env_var)
    if from_env:
        return from_env
    if not sys.stdin.isatty():
        raise click.ClickException(
            f"No TTY available. Set {env_var} in the environment or use --generate-password."
        )
    first = getpass.getpass(f"{label}: ")
    second = getpass.getpass(f"Confirm {label}: ")
    if first != second:
        raise click.ClickException("Passwords do not match.")
    return first


def register_cli(app: Flask) -> None:
    app.cli.add_command(init_db_command)
    app.cli.add_command(create_admin_command)
    app.cli.add_command(create_journalist_command)
    app.cli.add_command(list_users_command)
    app.cli.add_command(set_status_command)
    app.cli.add_command(reset_password_command)


@click.command("init-db")
@click.option("--drop", is_flag=True, help="Drop every table first (destructive).")
@with_appcontext
def init_db_command(drop: bool) -> None:
    """Create every table: accounts, audit log, submissions and evidence."""
    if drop:
        click.confirm(
            "This deletes every account, audit record and anonymous submission. "
            "Evidence files on disk are not removed. Continue?",
            abort=True,
        )
        db.drop_all()
        click.echo("Dropped all tables.")
    db.create_all()
    click.echo("Database is ready.")


@click.command("create-admin")
@click.option("--username", prompt=True, help="Admin username.")
@click.option("--display-name", default=None, help="Optional display name.")
@click.option("--email", default=None, help="Optional email address.")
@click.option(
    "--generate-password",
    "auto_password",
    is_flag=True,
    help="Generate a strong random password and print it once.",
)
@with_appcontext
def create_admin_command(
    username: str,
    display_name: str | None,
    email: str | None,
    auto_password: bool,
) -> None:
    """Bootstrap the initial administrator account."""
    db.create_all()

    if User.get_by_username(username) is not None:
        raise click.ClickException(f"User '{username}' already exists.")

    if auto_password:
        password = generate_password()
    else:
        password = _prompt_password("PHASE2_ADMIN_PASSWORD", "Admin password")

    try:
        admin = create_admin(
            username,
            password,
            display_name=display_name,
            email=email,
            must_change_password=auto_password,
        )
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

    record_event(
        "admin.bootstrapped", actor=admin, target=admin.username, detail="created via CLI"
    )

    click.echo(f"Admin '{admin.username}' created (role=ADMIN, status=AUTHORIZED).")
    if auto_password:
        click.echo(f"Temporary password: {password}")
        click.echo(
            "Store it now - it is not shown again, and must be changed at first sign-in."
        )


@click.command("create-journalist")
@click.option("--username", prompt=True, help="Journalist username.")
@click.option("--display-name", default=None)
@click.option("--email", default=None)
@click.option("--authorize", is_flag=True, help="Create as AUTHORIZED instead of PENDING.")
@with_appcontext
def create_journalist_command(
    username: str, display_name: str | None, email: str | None, authorize: bool
) -> None:
    """Create a journalist from the terminal (same code path as the dashboard)."""
    db.create_all()
    password = generate_password()
    try:
        user = create_user(
            username,
            password,
            role=Role.JOURNALIST,
            status=Status.AUTHORIZED if authorize else Status.PENDING,
            display_name=display_name,
            email=email,
            must_change_password=True,
        )
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

    record_event("journalist.created", target=user.username, detail="created via CLI")
    click.echo(f"Journalist '{user.username}' created with status {user.status}.")
    click.echo(f"Temporary password: {password}")


@click.command("list-users")
@with_appcontext
def list_users_command() -> None:
    """Print every Phase 2 account."""
    users = list(db.session.execute(db.select(User).order_by(User.id)).scalars())
    if not users:
        click.echo("No accounts yet. Run 'create-admin' first.")
        return
    click.echo(f"{'ID':<4} {'USERNAME':<24} {'ROLE':<12} {'STATUS':<12} CREATED")
    for user in users:
        click.echo(
            f"{user.id:<4} {user.username:<24} {user.role:<12} {user.status:<12} "
            f"{user.created_at:%Y-%m-%d %H:%M}"
        )


@click.command("set-status")
@click.argument("username")
@click.argument("status", type=click.Choice([s.value for s in Status], case_sensitive=False))
@with_appcontext
def set_status_command(username: str, status: str) -> None:
    """Authorize, disable or re-pend a journalist from the terminal."""
    user = User.get_by_username(username)
    if user is None:
        raise click.ClickException(f"No such user: {username}")
    try:
        set_status(user, status.upper())
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"'{user.username}' is now {user.status}.")


@click.command("reset-password")
@click.option("--username", prompt=True, help="Account whose password is reset.")
@with_appcontext
def reset_password_command(username: str) -> None:
    """Set a new password for an existing admin or journalist.

    The password is typed twice with no echo, must satisfy the same policy as
    the web forms, and is stored only as a hash.  Any lockout is cleared.  A
    journalist must change the new password at next sign-in, because the
    operator now knows it; an admin resetting their own account does not.
    """
    user = User.get_by_username(username)
    if user is None:
        raise click.ClickException(f"No such user: {username}")

    def _check_policy(value: str) -> str:
        error = password_policy_error(value)
        if error:
            raise click.UsageError(error)  # click.prompt shows it and asks again
        return value

    password = click.prompt(
        "New password",
        hide_input=True,
        confirmation_prompt="Confirm new password",
        value_proc=_check_policy,
    )

    try:
        reset_password(
            user,
            password,
            must_change_password=user.is_journalist,
            allow_admin=True,
            detail="via CLI",
        )
    except ValueError as exc:
        db.session.rollback()
        raise click.ClickException(str(exc)) from exc

    click.echo(f"Password for '{user.username}' ({user.role}) has been reset.")
    if user.must_change_password:
        click.echo("They must change it at their next sign-in.")
    if user.status != Status.AUTHORIZED.value:
        click.echo(f"Note: the account is {user.status} and still cannot sign in.")


__all__ = [
    "register_cli",
    "generate_password",
    "init_db_command",
    "create_admin_command",
    "list_journalists",
]
