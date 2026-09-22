"""Role-based access control tests.

These are the core Phase 2 assertions: the server decides what each role may
open, regardless of what the interface shows.
"""

from __future__ import annotations

import pytest

from phase2.extensions import db
from phase2.models import Status
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, JOURNALIST_PASSWORD, login

ADMIN_ROUTES = [
    "/admin/",
    "/admin/dashboard",
    "/admin/journalists",
    "/admin/journalists/new",
    "/admin/audit",
]

JOURNALIST_ROUTES = [
    "/journalist/",
    "/journalist/dashboard",
    "/journalist/profile",
    "/journalist/inbox",
]

PUBLIC_ROUTES = ["/", "/auth/login"]


class TestUnauthenticatedAccess:
    @pytest.mark.parametrize("route", ADMIN_ROUTES + JOURNALIST_ROUTES)
    def test_protected_routes_redirect_to_login(self, client, app, route):
        response = client.get(route, follow_redirects=False)
        assert response.status_code == 302
        assert "/auth/login" in response.headers["Location"]

    @pytest.mark.parametrize("route", PUBLIC_ROUTES)
    def test_public_routes_are_open(self, client, app, route):
        assert client.get(route).status_code == 200

    def test_home_page_needs_no_account(self, client, app):
        """An anonymous source must reach the site without logging in."""
        response = client.get("/")
        assert response.status_code == 200
        assert b"No account. No login." in response.data

    def test_admin_post_routes_reject_anonymous(self, client, journalist):
        response = client.post(
            f"/admin/journalists/{journalist.id}/status",
            data={"status": "AUTHORIZED"},
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert "/auth/login" in response.headers["Location"]
        # And nothing changed in the database.
        assert db.session.get(type(journalist), journalist.id).status == Status.AUTHORIZED.value


class TestJournalistCannotReachAdmin:
    @pytest.mark.parametrize("route", ADMIN_ROUTES)
    def test_admin_routes_forbidden_for_journalist(self, client, journalist, route):
        login(client, journalist.username, JOURNALIST_PASSWORD)
        response = client.get(route)
        assert response.status_code == 403
        assert b"Access denied" in response.data

    def test_journalist_cannot_create_accounts(self, client, journalist):
        login(client, journalist.username, JOURNALIST_PASSWORD)
        response = client.post(
            "/admin/journalists/new",
            data={
                "username": "sneaky",
                "password": "Sneaky!12345",
                "confirm_password": "Sneaky!12345",
            },
        )
        assert response.status_code == 403
        from phase2.models import User

        assert User.get_by_username("sneaky") is None

    def test_journalist_cannot_authorize_anyone(self, client, journalist, make_journalist):
        target = make_journalist("pendingone", status=Status.PENDING)
        login(client, journalist.username, JOURNALIST_PASSWORD)
        response = client.post(
            f"/admin/journalists/{target.id}/status", data={"status": "AUTHORIZED"}
        )
        assert response.status_code == 403
        assert db.session.get(type(target), target.id).status == Status.PENDING.value


class TestAdminCannotUseJournalistRoutes:
    @pytest.mark.parametrize("route", JOURNALIST_ROUTES)
    def test_journalist_routes_forbidden_for_admin(self, client, admin, route):
        """Roles are exclusive: an admin is not silently also a journalist."""
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        response = client.get(route)
        assert response.status_code == 403


class TestAuthorizedAccess:
    @pytest.mark.parametrize("route", ADMIN_ROUTES)
    def test_admin_can_open_admin_routes(self, client, admin, route):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        assert client.get(route).status_code == 200

    @pytest.mark.parametrize("route", JOURNALIST_ROUTES)
    def test_authorized_journalist_can_open_journalist_routes(
        self, client, journalist, route
    ):
        login(client, journalist.username, JOURNALIST_PASSWORD)
        assert client.get(route).status_code == 200

    def test_dashboard_redirect_routes_by_role(self, client, admin):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        response = client.get("/dashboard", follow_redirects=False)
        assert "/admin" in response.headers["Location"]

    def test_whoami_reports_the_live_role(self, client, journalist):
        login(client, journalist.username, JOURNALIST_PASSWORD)
        payload = client.get("/auth/whoami").get_json()
        assert payload["role"] == "JOURNALIST"
        assert payload["status"] == "AUTHORIZED"


class TestRoleChangeInvalidatesSession:
    def test_role_swap_forces_reauthentication(self, client, journalist):
        """A session that claims a role the account no longer has is discarded."""
        login(client, journalist.username, JOURNALIST_PASSWORD)
        journalist.role = "ADMIN"
        db.session.commit()

        response = client.get("/admin/dashboard", follow_redirects=False)
        assert response.status_code == 302
        assert "/auth/login" in response.headers["Location"]


class TestForcedPasswordChange:
    def test_temp_password_user_is_redirected_everywhere(self, client, make_journalist):
        user = make_journalist("tempjourno", must_change_password=True)
        login(client, user.username, JOURNALIST_PASSWORD)
        response = client.get("/journalist/dashboard", follow_redirects=False)
        assert response.status_code == 302
        assert "/auth/change-password" in response.headers["Location"]

    def test_access_restored_after_changing_password(self, client, make_journalist):
        user = make_journalist("tempjourno", must_change_password=True)
        login(client, user.username, JOURNALIST_PASSWORD)
        response = client.post(
            "/auth/change-password",
            data={
                "current_password": JOURNALIST_PASSWORD,
                "new_password": "BrandNew!98765",
                "confirm_password": "BrandNew!98765",
            },
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert client.get("/journalist/dashboard").status_code == 200
        assert db.session.get(type(user), user.id).must_change_password is False


class TestSecurityHeaders:
    def test_headers_present_on_public_pages(self, client, app):
        response = client.get("/")
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]

    def test_protected_pages_are_not_cached(self, client, admin):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        response = client.get("/admin/dashboard")
        assert "no-store" in response.headers["Cache-Control"]
