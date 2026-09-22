"""Admin workflow tests: creating, authorizing and disabling journalists."""

from __future__ import annotations

from phase2.extensions import db
from phase2.models import AuditLog, Role, Status, User
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, JOURNALIST_PASSWORD, login

NEW_JOURNALIST = {
    "username": "newsroom.alice",
    "display_name": "Alice Reporter",
    "email": "alice@example.org",
    "password": "FirstPass!2345",
    "confirm_password": "FirstPass!2345",
}


class TestJournalistCreation:
    def test_admin_creates_a_pending_journalist(self, client, admin):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        response = client.post(
            "/admin/journalists/new", data=dict(NEW_JOURNALIST), follow_redirects=True
        )
        assert response.status_code == 200

        user = User.get_by_username("newsroom.alice")
        assert user is not None
        assert user.role == Role.JOURNALIST.value
        assert user.status == Status.PENDING.value
        assert user.must_change_password is True
        assert user.created_by_id == admin.id

    def test_admin_can_authorize_at_creation_time(self, client, admin):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        payload = dict(NEW_JOURNALIST, authorize_now="y")
        client.post("/admin/journalists/new", data=payload, follow_redirects=True)
        assert User.get_by_username("newsroom.alice").status == Status.AUTHORIZED.value

    def test_creation_is_audited(self, client, admin):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        client.post("/admin/journalists/new", data=dict(NEW_JOURNALIST))
        event = db.session.execute(
            db.select(AuditLog).filter_by(action="journalist.created")
        ).scalar_one()
        assert event.actor_username == ADMIN_USERNAME
        assert event.target == "newsroom.alice"

    def test_duplicate_username_is_rejected(self, client, admin, make_journalist):
        make_journalist("newsroom.alice")
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        response = client.post("/admin/journalists/new", data=dict(NEW_JOURNALIST))
        assert response.status_code == 400
        assert b"already taken" in response.data

    def test_username_is_normalized_to_lowercase(self, client, admin):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        payload = dict(NEW_JOURNALIST, username="MixedCase.Name")
        client.post("/admin/journalists/new", data=payload, follow_redirects=True)
        assert User.get_by_username("mixedcase.name") is not None

    def test_mismatched_confirmation_is_rejected(self, client, admin):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        payload = dict(NEW_JOURNALIST, confirm_password="Different!2345")
        response = client.post("/admin/journalists/new", data=payload)
        assert response.status_code == 400
        assert b"Passwords do not match" in response.data
        assert User.get_by_username("newsroom.alice") is None

    def test_weak_password_is_rejected(self, client, admin):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        payload = dict(NEW_JOURNALIST, password="short", confirm_password="short")
        response = client.post("/admin/journalists/new", data=payload)
        assert response.status_code == 400
        assert b"at least" in response.data
        assert User.get_by_username("newsroom.alice") is None

    def test_invalid_username_characters_rejected(self, client, admin):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        payload = dict(NEW_JOURNALIST, username="bad name!")
        response = client.post("/admin/journalists/new", data=payload)
        assert response.status_code == 400
        assert b"letters, digits" in response.data

    def test_admin_accounts_cannot_be_created_over_http(self, client, admin):
        """The create form has no role field; only journalists come out of it."""
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        payload = dict(NEW_JOURNALIST, role="ADMIN")
        client.post("/admin/journalists/new", data=payload, follow_redirects=True)
        assert User.get_by_username("newsroom.alice").role == Role.JOURNALIST.value

    def test_no_public_registration_endpoint_exists(self, app):
        rules = {rule.rule for rule in app.url_map.iter_rules()}
        for forbidden in ("/register", "/signup", "/auth/register", "/auth/signup"):
            assert forbidden not in rules


class TestAuthorization:
    def test_admin_authorizes_a_pending_journalist(self, client, admin, make_journalist):
        target = make_journalist("waiting", status=Status.PENDING)
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        response = client.post(
            f"/admin/journalists/{target.id}/status",
            data={"status": "AUTHORIZED"},
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert db.session.get(User, target.id).status == Status.AUTHORIZED.value

    def test_authorized_journalist_can_then_log_in(self, client, admin, make_journalist):
        target = make_journalist("waiting", status=Status.PENDING)
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        client.post(
            f"/admin/journalists/{target.id}/status",
            data={"status": "AUTHORIZED"},
            follow_redirects=True,
        )
        client.post("/auth/logout", data={}, follow_redirects=True)

        response = login(client, "waiting", JOURNALIST_PASSWORD)
        assert b"Journalist dashboard" in response.data

    def test_admin_disables_a_journalist(self, client, admin, journalist):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        client.post(
            f"/admin/journalists/{journalist.id}/status",
            data={"status": "DISABLED"},
            follow_redirects=True,
        )
        assert db.session.get(User, journalist.id).status == Status.DISABLED.value

    def test_disabled_journalist_cannot_log_in(self, client, admin, journalist):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        client.post(
            f"/admin/journalists/{journalist.id}/status",
            data={"status": "DISABLED"},
            follow_redirects=True,
        )
        client.post("/auth/logout", data={}, follow_redirects=True)

        response = login(client, journalist.username, JOURNALIST_PASSWORD,
                         follow_redirects=False)
        assert response.status_code == 403

    def test_authorizing_clears_a_lockout(self, client, admin, make_journalist, app):
        from datetime import timedelta

        from phase2.models import utcnow

        target = make_journalist("locked", status=Status.PENDING)
        target.locked_until = utcnow() + timedelta(minutes=30)
        target.failed_login_attempts = 3
        db.session.commit()

        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        client.post(
            f"/admin/journalists/{target.id}/status",
            data={"status": "AUTHORIZED"},
            follow_redirects=True,
        )
        refreshed = db.session.get(User, target.id)
        assert refreshed.locked_until is None
        assert refreshed.failed_login_attempts == 0

    def test_status_change_is_audited(self, client, admin, journalist):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        client.post(
            f"/admin/journalists/{journalist.id}/status",
            data={"status": "DISABLED"},
            follow_redirects=True,
        )
        event = db.session.execute(
            db.select(AuditLog).filter_by(action="status.disabled")
        ).scalar_one()
        assert event.actor_username == ADMIN_USERNAME
        assert event.detail == "AUTHORIZED -> DISABLED"

    def test_unknown_status_value_is_rejected(self, client, admin, journalist):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        client.post(
            f"/admin/journalists/{journalist.id}/status",
            data={"status": "SUPERUSER"},
            follow_redirects=True,
        )
        assert db.session.get(User, journalist.id).status == Status.AUTHORIZED.value

    def test_admin_cannot_restatus_another_admin(self, client, admin, app):
        from phase2.services import create_admin

        other = create_admin("secondadmin", "OtherAdmin!2345")
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        response = client.post(
            f"/admin/journalists/{other.id}/status",
            data={"status": "DISABLED"},
            follow_redirects=False,
        )
        assert response.status_code == 404  # not a journalist -> not manageable here
        assert db.session.get(User, other.id).status == Status.AUTHORIZED.value

    def test_status_change_on_unknown_user_is_404(self, client, admin):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        response = client.post(
            "/admin/journalists/9999/status", data={"status": "DISABLED"}
        )
        assert response.status_code == 404


class TestAdminPasswordReset:
    def test_admin_resets_a_journalist_password(self, client, admin, journalist):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        client.post(
            f"/admin/journalists/{journalist.id}/reset-password",
            data={"new_password": "ResetPass!2345", "confirm_password": "ResetPass!2345"},
            follow_redirects=True,
        )
        refreshed = db.session.get(User, journalist.id)
        assert refreshed.check_password("ResetPass!2345") is True
        assert refreshed.check_password(JOURNALIST_PASSWORD) is False
        assert refreshed.must_change_password is True


class TestAdminViews:
    def test_dashboard_shows_counts(self, client, admin, make_journalist):
        make_journalist("alpha", status=Status.PENDING)
        make_journalist("bravo", status=Status.AUTHORIZED)
        make_journalist("charlie", status=Status.DISABLED)
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        response = client.get("/admin/dashboard")
        assert response.status_code == 200
        assert b"Awaiting authorization" in response.data

    def test_manage_page_filters_by_status(self, client, admin, make_journalist):
        make_journalist("pendinga", status=Status.PENDING)
        make_journalist("authedb", status=Status.AUTHORIZED)
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        response = client.get("/admin/journalists?status=PENDING")
        assert b"pendinga" in response.data
        assert b"authedb" not in response.data

    def test_journalist_detail_page_renders(self, client, admin, journalist):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        response = client.get(f"/admin/journalists/{journalist.id}")
        assert response.status_code == 200
        assert journalist.username.encode() in response.data

    def test_audit_page_renders(self, client, admin):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        assert client.get("/admin/audit").status_code == 200
