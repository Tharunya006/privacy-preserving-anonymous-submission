"""Login flow and staff layout: role-based landing, Switch account, and that the
new navigation / login page grant nothing by themselves."""

from __future__ import annotations

import re

import pytest

from phase2 import create_app
from phase2.extensions import db
from phase2.models import AuditLog
from phase2.services import create_admin
from submissions import services
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, JOURNALIST_PASSWORD, login


def _post_login(client, username, password, next_url=""):
    return client.post("/auth/login", data={"username": username, "password": password, "next": next_url},
                       follow_redirects=False)


class TestRoleLanding:
    def test_each_role_lands_on_its_own_dashboard(self, client, admin, journalist):
        assert _post_login(client, ADMIN_USERNAME, ADMIN_PASSWORD).headers["Location"].endswith("/admin/dashboard")
        client.post("/auth/logout")
        assert _post_login(client, journalist.username, JOURNALIST_PASSWORD).headers["Location"].endswith(
            "/journalist/dashboard")

    @pytest.mark.parametrize("next_url", ["/journalist/inbox", "/journalist", "//evil.example/x",
                                          "https://evil.example/admin/audit"])
    def test_admin_ignores_next_outside_own_area(self, client, admin, next_url):
        location = _post_login(client, ADMIN_USERNAME, ADMIN_PASSWORD, next_url).headers["Location"]
        assert location.endswith("/admin/dashboard")

    def test_journalist_ignores_next_into_admin_area(self, client, journalist):
        location = _post_login(client, journalist.username, JOURNALIST_PASSWORD, "/admin/audit").headers["Location"]
        assert location.endswith("/journalist/dashboard")

    def test_next_inside_own_area_is_still_followed(self, client, admin, journalist):
        assert _post_login(client, ADMIN_USERNAME, ADMIN_PASSWORD, "/admin/audit").headers["Location"].endswith(
            "/admin/audit")
        client.post("/auth/logout")
        assert _post_login(client, journalist.username, JOURNALIST_PASSWORD,
                           "/journalist/inbox").headers["Location"].endswith("/journalist/inbox")

    def test_login_page_has_no_role_selector(self, client):
        page = client.get("/auth/login").get_data(as_text=True)
        assert 'name="role"' not in page and "<select" not in page
        assert "page-login" in page


class TestSwitchAccount:
    def test_switch_ends_session_and_returns_to_login(self, client, admin, journalist):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        response = client.post("/auth/logout", data={"switch": "1"}, follow_redirects=True)
        assert response.request.path == "/auth/login"
        assert b"You have been signed out. Sign in with another account." in response.data
        # The old session is gone: no staff page is reachable any more.
        for url in ("/admin/dashboard", "/admin/security-analysis", "/journalist/dashboard"):
            assert "/auth/login" in client.get(url, follow_redirects=False).headers["Location"]
        assert db.session.execute(db.select(AuditLog).filter_by(action="logout")).scalars().first()

        # The next user gets only their own role's access.
        login(client, journalist.username, JOURNALIST_PASSWORD)
        assert client.get("/journalist/dashboard").status_code == 200
        assert client.get("/admin/dashboard", follow_redirects=False).status_code == 403

    def test_switch_is_post_only(self, client, admin):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        assert client.get("/auth/logout").status_code == 405
        assert client.get("/admin/dashboard").status_code == 200  # still signed in

    def test_staff_pages_offer_switch_and_logout_forms(self, client, admin):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        page = client.get("/admin/dashboard").get_data(as_text=True)
        forms = re.findall(r'<form method="post" action="/auth/logout"', page)
        assert len(forms) == 2
        assert "Switch account" in page and "Log out" in page
        assert 'name="switch" value="1"' in page


class TestSwitchAccountCsrf:
    @pytest.fixture()
    def csrf_client(self, tmp_path):
        # Requests run without an outer app context, as in a real browser:
        # Flask-WTF caches the CSRF token in ``g``, and a shared context would
        # reuse the token from before login (a test-harness artefact).
        app = create_app("testing", WTF_CSRF_ENABLED=True,
                         SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'csrf.db'}")
        with app.app_context():
            db.create_all()
            create_admin(ADMIN_USERNAME, ADMIN_PASSWORD, must_change_password=False)
        yield app.test_client()
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_switch_without_token_is_refused_and_session_kept(self, csrf_client):
        page = csrf_client.get("/auth/login").data
        token = re.search(rb'name="csrf_token"[^>]*value="([^"]+)"', page).group(1).decode()
        csrf_client.post("/auth/login", data={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD,
                                              "csrf_token": token})
        assert csrf_client.get("/admin/dashboard").status_code == 200
        refused = csrf_client.post("/auth/logout", data={"switch": "1"})
        assert refused.status_code == 400
        assert csrf_client.get("/admin/dashboard").status_code == 200

        dashboard = csrf_client.get("/admin/dashboard").data
        switch_form = dashboard[:dashboard.index(b'name="switch"')].rsplit(b"<form", 1)[1]
        token = re.search(rb'name="csrf_token" value="([^"]+)"', switch_form).group(1).decode()
        ok = csrf_client.post("/auth/logout", data={"switch": "1", "csrf_token": token}, follow_redirects=True)
        assert ok.request.path == "/auth/login" and b"Sign in with another account" in ok.data
        assert "/auth/login" in csrf_client.get("/admin/dashboard", follow_redirects=False).headers["Location"]


class TestNavigationGrantsNothing:
    def test_each_role_sees_only_its_own_navigation(self, client, admin, journalist):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        page = client.get("/admin/dashboard").get_data(as_text=True)
        assert 'href="/admin/security-analysis"' in page and 'href="/journalist/inbox"' not in page
        client.post("/auth/logout")
        login(client, journalist.username, JOURNALIST_PASSWORD)
        page = client.get("/journalist/dashboard").get_data(as_text=True)
        assert 'href="/journalist/inbox"' in page and 'href="/admin/' not in page
        for url in ("/admin/dashboard", "/admin/security-analysis", "/admin/audit"):
            assert client.get(url, follow_redirects=False).status_code == 403

    def test_public_pages_keep_public_layout(self, client):
        for url in ("/", "/submit", "/status"):
            page = client.get(url).get_data(as_text=True)
            assert 'class="layout-public"' in page and "page-login" not in page


class TestOverviewMetrics:
    def test_overview_shows_ciphertext_entropy_only(self, client, admin):
        submission, _ = services.create_submission("Overview title marker", "Overview body marker text")
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        page = client.get("/admin/security-analysis").get_data(as_text=True)
        assert "Text · entropy" in page and "Evidence · entropy" in page
        assert re.search(r'<span class="entropy">\d\.\d{3}</span>', page)
        assert "Overview title marker" not in page and "Overview body marker" not in page

    def test_legacy_text_entropy_is_withheld(self, client, admin):
        submission, _ = services.create_submission("x", "x")
        submission.content_sealed = "LEGACY-PLAINTEXT-OVERVIEW"
        db.session.commit()
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        page = client.get("/admin/security-analysis").get_data(as_text=True)
        assert "LEGACY-PLAINTEXT-OVERVIEW" not in page
        assert '<span class="entropy muted">withheld</span>' in page
