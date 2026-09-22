"""Shared pytest fixtures for the Phase 2 test suite.

Every test runs against a throw-away in-memory SQLite database, so the suite
never touches instance/phase2.db and leaves nothing behind.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault("PHASE2_ENV", "testing")

from phase2 import create_app  # noqa: E402
from phase2.extensions import db as _db  # noqa: E402
from phase2.models import Role, Status, User  # noqa: E402
from phase2.services import create_admin, create_user  # noqa: E402

ADMIN_USERNAME = "rootadmin"
ADMIN_PASSWORD = "AdminPass!2345"
JOURNALIST_PASSWORD = "Reporter!2345"


@pytest.fixture()
def app():
    application = create_app("testing")
    with application.app_context():
        _db.create_all()
        yield application
        _db.session.remove()
        _db.drop_all()


@pytest.fixture()
def db(app):
    return _db


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def admin(app):
    """An AUTHORIZED admin with a permanent password."""
    user = create_admin(ADMIN_USERNAME, ADMIN_PASSWORD, must_change_password=False)
    return user


@pytest.fixture()
def make_journalist(app):
    """Factory: build a journalist in any status."""

    def _make(
        username: str = "reporter1",
        password: str = JOURNALIST_PASSWORD,
        status: Status = Status.AUTHORIZED,
        must_change_password: bool = False,
        **kwargs,
    ) -> User:
        return create_user(
            username,
            password,
            role=Role.JOURNALIST,
            status=status,
            must_change_password=must_change_password,
            **kwargs,
        )

    return _make


@pytest.fixture()
def journalist(make_journalist):
    """A ready-to-use AUTHORIZED journalist."""
    return make_journalist()


# ---------------------------------------------------------------------------
# Helpers used across test modules
# ---------------------------------------------------------------------------
def login(client, username: str, password: str, follow_redirects: bool = True):
    return client.post(
        "/auth/login",
        data={"username": username, "password": password},
        follow_redirects=follow_redirects,
    )


def logout(client, follow_redirects: bool = True):
    return client.post("/auth/logout", data={}, follow_redirects=follow_redirects)


@pytest.fixture()
def login_as(client):
    """Sign the shared test client in as a given user."""

    def _login(username: str, password: str, follow_redirects: bool = True):
        return login(client, username, password, follow_redirects=follow_redirects)

    return _login
