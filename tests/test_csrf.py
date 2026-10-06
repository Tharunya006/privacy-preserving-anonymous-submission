"""CSRF protection tests.

The rest of the suite runs with ``WTF_CSRF_ENABLED = False`` so forms can be
posted directly.  This module turns protection back on and proves that a POST
without a valid token is refused.
"""

from __future__ import annotations

import re

import pytest

from phase2 import create_app
from phase2.extensions import db
from phase2.models import Status, User
from phase2.services import create_admin, create_user

ADMIN_USERNAME = "csrfadmin"
ADMIN_PASSWORD = "AdminPass!2345"
JOURNALIST_PASSWORD = "Reporter!2345"

TOKEN_RE = re.compile(rb'name="csrf_token"[^>]*value="([^"]+)"')


@pytest.fixture()
def csrf_app():
    """Same testing config, but with CSRF protection switched on."""
    app = create_app("testing", WTF_CSRF_ENABLED=True)
    with app.app_context():
        db.create_all()
        create_admin(ADMIN_USERNAME, ADMIN_PASSWORD, must_change_password=False)
        create_user(
            "csrfjourno",
            JOURNALIST_PASSWORD,
            status=Status.AUTHORIZED,
            must_change_password=False,
        )
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def csrf_client(csrf_app):
    return csrf_app.test_client()


def extract_token(html: bytes) -> str:
    match = TOKEN_RE.search(html)
    assert match, "no csrf_token found in the rendered form"
    return match.group(1).decode()


def login_with_token(client) -> None:
    page = client.get("/auth/login")
    token = extract_token(page.data)
    response = client.post(
        "/auth/login",
        data={
            "csrf_token": token,
            "username": ADMIN_USERNAME,
            "password": ADMIN_PASSWORD,
        },
        follow_redirects=True,
    )
    assert b"Admin dashboard" in response.data


class TestCsrfTokensArePresent:
    def test_login_form_includes_a_token(self, csrf_client):
        page = csrf_client.get("/auth/login")
        assert b'name="csrf_token"' in page.data

    def test_add_journalist_form_includes_a_token(self, csrf_client):
        login_with_token(csrf_client)
        page = csrf_client.get("/admin/journalists/new")
        assert b'name="csrf_token"' in page.data


class TestCsrfEnforcement:
    def test_login_without_token_is_refused(self, csrf_client):
        response = csrf_client.post(
            "/auth/login", data={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}
        )
        assert response.status_code == 400
        with csrf_client.session_transaction() as session:
            assert "uid" not in session

    def test_login_with_valid_token_succeeds(self, csrf_client):
        login_with_token(csrf_client)

    def test_create_journalist_without_token_is_refused(self, csrf_client, csrf_app):
        login_with_token(csrf_client)
        response = csrf_client.post(
            "/admin/journalists/new",
            data={
                "username": "notoken",
                "password": "SomePass!2345",
                "confirm_password": "SomePass!2345",
            },
        )
        assert response.status_code == 400
        assert User.get_by_username("notoken") is None

    def test_status_change_without_token_is_refused(self, csrf_client, csrf_app):
        """CSRFProtect rejects the request before the view ever runs."""
        login_with_token(csrf_client)
        target = User.get_by_username("csrfjourno")
        response = csrf_client.post(
            f"/admin/journalists/{target.id}/status", data={"status": "DISABLED"}
        )
        assert response.status_code == 400
        assert b"CSRF token was invalid" in response.data
        assert db.session.get(User, target.id).status == Status.AUTHORIZED.value

    def test_logout_without_token_is_refused(self, csrf_client):
        login_with_token(csrf_client)
        response = csrf_client.post("/auth/logout", data={})
        assert response.status_code == 400
        # Still signed in.
        assert csrf_client.get("/admin/dashboard").status_code == 200

    def test_forged_token_is_refused(self, csrf_client, csrf_app):
        login_with_token(csrf_client)
        response = csrf_client.post(
            "/admin/journalists/new",
            data={
                "csrf_token": "totally-made-up-token",
                "username": "forged",
                "password": "SomePass!2345",
                "confirm_password": "SomePass!2345",
            },
        )
        assert response.status_code == 400
        assert User.get_by_username("forged") is None


class TestCsrfOnAnonymousForms:
    """The source portal is public but still CSRF-protected (no account needed)."""

    def test_submit_form_includes_a_token(self, csrf_client):
        assert b'name="csrf_token"' in csrf_client.get("/submit").data

    def test_submission_without_token_is_refused(self, csrf_client, csrf_app):
        from submissions.models import Submission

        response = csrf_client.post("/submit", data={"title": "t", "content": "c"})
        assert response.status_code == 400
        assert db.session.query(Submission).count() == 0

    def test_submission_with_token_succeeds(self, csrf_client, csrf_app):
        from submissions.models import Submission

        token = extract_token(csrf_client.get("/submit").data)
        response = csrf_client.post(
            "/submit", data={"csrf_token": token, "title": "t", "content": "c"}
        )
        assert response.status_code == 200
        assert db.session.query(Submission).count() == 1
