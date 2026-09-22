"""Authentication tests: login, invalid login, status gating, logout."""

from __future__ import annotations

from phase2.extensions import db
from phase2.models import AuditLog, Status, User
from tests.conftest import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    JOURNALIST_PASSWORD,
    login,
    logout,
)


class TestAdminLogin:
    def test_admin_can_log_in(self, client, admin):
        response = login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        assert response.status_code == 200
        assert b"Admin dashboard" in response.data

    def test_admin_login_is_case_insensitive_on_username(self, client, admin):
        response = login(client, ADMIN_USERNAME.upper(), ADMIN_PASSWORD)
        assert response.status_code == 200
        assert b"Admin dashboard" in response.data

    def test_successful_login_records_audit_event(self, client, admin):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        events = db.session.execute(
            db.select(AuditLog).filter_by(action="login.success")
        ).scalars().all()
        assert len(events) == 1
        assert events[0].target == ADMIN_USERNAME

    def test_login_updates_last_login_timestamp(self, client, admin):
        assert admin.last_login_at is None
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        assert db.session.get(User, admin.id).last_login_at is not None

    def test_session_cookie_is_httponly(self, client, admin):
        response = login(client, ADMIN_USERNAME, ADMIN_PASSWORD, follow_redirects=False)
        cookies = response.headers.getlist("Set-Cookie")
        session_cookie = next(c for c in cookies if c.startswith("phase2_session="))
        assert "HttpOnly" in session_cookie
        assert "SameSite=Lax" in session_cookie


class TestInvalidLogin:
    def test_wrong_password_is_rejected(self, client, admin):
        response = login(client, ADMIN_USERNAME, "WrongPassword!1", follow_redirects=False)
        assert response.status_code == 401
        assert b"Invalid username or password" in response.data

    def test_unknown_user_is_rejected(self, client, app):
        response = login(client, "ghost", "Whatever!12345", follow_redirects=False)
        assert response.status_code == 401
        assert b"Invalid username or password" in response.data

    def test_error_message_does_not_reveal_whether_user_exists(self, client, admin):
        unknown = login(client, "nosuchuser", "Whatever!12345", follow_redirects=False)
        wrong_pw = login(client, ADMIN_USERNAME, "Whatever!12345", follow_redirects=False)
        assert b"Invalid username or password" in unknown.data
        assert b"Invalid username or password" in wrong_pw.data
        assert unknown.status_code == wrong_pw.status_code == 401

    def test_empty_credentials_rejected(self, client, admin):
        response = client.post("/auth/login", data={"username": "", "password": ""})
        assert response.status_code == 400
        assert b"Username is required" in response.data

    def test_failed_login_increments_counter(self, client, admin):
        login(client, ADMIN_USERNAME, "Nope!123456", follow_redirects=False)
        assert db.session.get(User, admin.id).failed_login_attempts == 1

    def test_account_locks_after_repeated_failures(self, client, app, admin):
        limit = app.config["MAX_FAILED_LOGINS"]
        for _ in range(limit):
            login(client, ADMIN_USERNAME, "Nope!123456", follow_redirects=False)

        refreshed = db.session.get(User, admin.id)
        assert refreshed.is_locked is True

        # Even the correct password is refused while the lockout holds.
        response = login(client, ADMIN_USERNAME, ADMIN_PASSWORD, follow_redirects=False)
        assert response.status_code == 403
        assert b"temporarily locked" in response.data

    def test_failed_attempts_reset_after_success(self, client, admin):
        login(client, ADMIN_USERNAME, "Nope!123456", follow_redirects=False)
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        assert db.session.get(User, admin.id).failed_login_attempts == 0


class TestJournalistLoginByStatus:
    def test_authorized_journalist_can_log_in(self, client, journalist):
        response = login(client, journalist.username, JOURNALIST_PASSWORD)
        assert response.status_code == 200
        assert b"Journalist dashboard" in response.data

    def test_pending_journalist_is_blocked(self, client, make_journalist):
        user = make_journalist("pendingjourno", status=Status.PENDING)
        response = login(client, user.username, JOURNALIST_PASSWORD, follow_redirects=False)
        assert response.status_code == 403
        assert b"pending authorization" in response.data

    def test_disabled_journalist_is_blocked(self, client, make_journalist):
        user = make_journalist("disabledjourno", status=Status.DISABLED)
        response = login(client, user.username, JOURNALIST_PASSWORD, follow_redirects=False)
        assert response.status_code == 403
        assert b"disabled" in response.data

    def test_blocked_login_does_not_create_a_session(self, client, make_journalist):
        make_journalist("pendingjourno", status=Status.PENDING)
        login(client, "pendingjourno", JOURNALIST_PASSWORD, follow_redirects=False)
        response = client.get("/journalist/dashboard", follow_redirects=False)
        assert response.status_code == 302
        assert "/auth/login" in response.headers["Location"]

    def test_disabling_mid_session_revokes_access_immediately(
        self, client, journalist
    ):
        login(client, journalist.username, JOURNALIST_PASSWORD)
        assert client.get("/journalist/dashboard").status_code == 200

        journalist.status = Status.DISABLED.value
        db.session.commit()

        response = client.get("/journalist/dashboard", follow_redirects=False)
        assert response.status_code == 302
        assert "/auth/login" in response.headers["Location"]


class TestLogout:
    def test_logout_ends_the_session(self, client, admin):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        assert client.get("/admin/dashboard").status_code == 200

        response = logout(client)
        assert response.status_code == 200
        assert b"You have been signed out" in response.data

        after = client.get("/admin/dashboard", follow_redirects=False)
        assert after.status_code == 302
        assert "/auth/login" in after.headers["Location"]

    def test_logout_clears_the_session_cookie(self, client, admin):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        logout(client, follow_redirects=False)
        with client.session_transaction() as session:
            assert "uid" not in session

    def test_logout_requires_post(self, client, admin):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        response = client.get("/auth/logout")
        assert response.status_code == 405

    def test_logout_requires_authentication(self, client, app):
        response = client.post("/auth/logout", data={}, follow_redirects=False)
        assert response.status_code == 302
        assert "/auth/login" in response.headers["Location"]

    def test_logout_is_recorded(self, client, admin):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        logout(client)
        events = db.session.execute(
            db.select(AuditLog).filter_by(action="logout")
        ).scalars().all()
        assert len(events) == 1


class TestSessionBehaviour:
    def test_login_page_redirects_signed_in_users(self, client, admin):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        response = client.get("/auth/login", follow_redirects=False)
        assert response.status_code == 302
        assert "/admin" in response.headers["Location"]

    def test_session_is_rebuilt_on_login(self, client, admin):
        """Session fixation defence: pre-login session data must not survive."""
        with client.session_transaction() as session:
            session["planted"] = "attacker-value"
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        with client.session_transaction() as session:
            assert "planted" not in session
            assert session["uid"] == admin.id

    def test_next_parameter_cannot_redirect_off_site(self, client, admin):
        response = client.post(
            "/auth/login",
            data={
                "username": ADMIN_USERNAME,
                "password": ADMIN_PASSWORD,
                "next": "https://evil.example.com/steal",
            },
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert "evil.example.com" not in response.headers["Location"]
        assert "/admin" in response.headers["Location"]

    def test_next_parameter_allows_relative_path(self, client, journalist):
        response = client.post(
            "/auth/login",
            data={
                "username": journalist.username,
                "password": JOURNALIST_PASSWORD,
                "next": "/journalist/inbox",
            },
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/journalist/inbox")

    def test_stale_session_for_deleted_user_is_dropped(self, client, journalist):
        login(client, journalist.username, JOURNALIST_PASSWORD)
        db.session.delete(journalist)
        db.session.commit()
        response = client.get("/journalist/dashboard", follow_redirects=False)
        assert response.status_code == 302
        assert "/auth/login" in response.headers["Location"]


class TestIdleTimeout:
    def test_idle_session_expires(self, client, app, admin):
        """A session untouched for longer than the idle window is dropped."""
        from datetime import timedelta

        from phase2.models import utcnow

        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        assert client.get("/admin/dashboard").status_code == 200

        stale = utcnow() - timedelta(
            minutes=app.config["PHASE2_IDLE_TIMEOUT_MINUTES"] + 1
        )
        with client.session_transaction() as session:
            session["last_seen"] = stale.isoformat()

        response = client.get("/admin/dashboard", follow_redirects=True)
        assert b"session timed out" in response.data

    def test_activity_refreshes_the_idle_window(self, client, app, admin):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        with client.session_transaction() as session:
            first_seen = session["last_seen"]

        client.get("/admin/journalists")
        with client.session_transaction() as session:
            assert session["last_seen"] >= first_seen

    def test_corrupt_last_seen_value_is_treated_as_expired(self, client, admin):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        with client.session_transaction() as session:
            session["last_seen"] = "not-a-timestamp"
        response = client.get("/admin/dashboard", follow_redirects=False)
        assert response.status_code == 302
        assert "/auth/login" in response.headers["Location"]

    def test_tampered_session_cookie_is_rejected(self, client, admin):
        """The cookie is signed with SECRET_KEY; editing it invalidates it."""
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        cookie = client.get_cookie("phase2_session")
        assert cookie is not None
        client.set_cookie("phase2_session", cookie.value[:-6] + "AAAAAA")

        response = client.get("/admin/dashboard", follow_redirects=False)
        assert response.status_code == 302
        assert "/auth/login" in response.headers["Location"]
