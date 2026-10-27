"""Model-level tests: password hashing, status rules, validation."""

from __future__ import annotations

from datetime import timedelta

import pytest

from phase2.extensions import db
from phase2.models import Role, Status, User, utcnow
from phase2.services import change_own_password, create_admin, create_user, set_status


class TestPasswordHashing:
    def test_password_is_not_stored_in_plaintext(self, app):
        user = create_user("hashtest", "SuperSecret!2345")
        assert user.password_hash != "SuperSecret!2345"
        assert "SuperSecret" not in user.password_hash

    def test_hash_uses_a_recognised_algorithm(self, app):
        user = create_user("hashtest", "SuperSecret!2345")
        assert user.password_hash.startswith("pbkdf2:sha256")

    def test_correct_password_verifies(self, app):
        user = create_user("hashtest", "SuperSecret!2345")
        assert user.check_password("SuperSecret!2345") is True

    def test_wrong_password_fails(self, app):
        user = create_user("hashtest", "SuperSecret!2345")
        assert user.check_password("supersecret!2345") is False
        assert user.check_password("") is False
        assert user.check_password("nonsense") is False

    def test_same_password_produces_different_hashes(self, app):
        """Per-user random salt: identical passwords must not collide."""
        one = create_user("usera", "SamePass!2345")
        two = create_user("userb", "SamePass!2345")
        assert one.password_hash != two.password_hash

    def test_password_attribute_is_write_only(self, app):
        user = create_user("hashtest", "SuperSecret!2345")
        with pytest.raises(AttributeError):
            _ = user.password

    def test_empty_password_rejected(self, app):
        user = User(username="x")
        with pytest.raises(ValueError):
            user.set_password("")

    def test_changing_password_replaces_the_hash(self, app):
        user = create_user("hashtest", "SuperSecret!2345")
        original = user.password_hash
        assert change_own_password(user, "SuperSecret!2345", "BrandNew!98765") is True
        assert user.password_hash != original
        assert user.check_password("BrandNew!98765") is True
        assert user.check_password("SuperSecret!2345") is False

    def test_change_rejected_with_wrong_current_password(self, app):
        user = create_user("hashtest", "SuperSecret!2345")
        assert change_own_password(user, "WrongOne!2345", "BrandNew!98765") is False
        assert user.check_password("SuperSecret!2345") is True


class TestUserDefaults:
    def test_journalist_defaults_to_pending(self, app):
        user = create_user("defaulted", "SomePass!2345")
        assert user.role == Role.JOURNALIST.value
        assert user.status == Status.PENDING.value

    def test_admin_helper_creates_authorized_admin(self, app):
        admin = create_admin("bootadmin", "BootPass!2345")
        assert admin.role == Role.ADMIN.value
        assert admin.status == Status.AUTHORIZED.value
        assert admin.is_admin is True

    def test_created_at_is_populated(self, app):
        user = create_user("timestamped", "SomePass!2345")
        assert user.created_at is not None
        assert user.updated_at is not None

    def test_required_columns_exist(self, app):
        columns = {c.name for c in User.__table__.columns}
        assert {"id", "username", "password_hash", "role", "status", "created_at"} <= columns


class TestUsernameRules:
    def test_username_is_lowercased_and_trimmed(self, app):
        user = create_user("  MixedCase  ", "SomePass!2345")
        assert user.username == "mixedcase"

    def test_duplicate_username_rejected(self, app):
        create_user("taken", "SomePass!2345")
        with pytest.raises(ValueError, match="already taken"):
            create_user("TAKEN", "OtherPass!2345")

    def test_duplicate_email_rejected(self, app):
        create_user("one", "SomePass!2345", email="dup@example.org")
        with pytest.raises(ValueError, match="already registered"):
            create_user("two", "OtherPass!2345", email="DUP@example.org")

    @pytest.mark.parametrize("bad", ["ab", "has space", "semi;colon", "a" * 65, ""])
    def test_invalid_usernames_rejected(self, app, bad):
        with pytest.raises(ValueError):
            create_user(bad, "SomePass!2345")

    def test_lookup_by_username_is_case_insensitive(self, app):
        create_user("findme", "SomePass!2345")
        assert User.get_by_username("FINDME") is not None
        assert User.get_by_username("  FindMe ") is not None
        assert User.get_by_username("missing") is None


class TestStatusRules:
    def test_pending_cannot_log_in(self, app):
        user = create_user("pendinguser", "SomePass!2345", status=Status.PENDING)
        allowed, reason = user.can_login()
        assert allowed is False
        assert "pending" in reason.lower()

    def test_disabled_cannot_log_in(self, app):
        user = create_user("disableduser", "SomePass!2345", status=Status.DISABLED)
        allowed, reason = user.can_login()
        assert allowed is False
        assert "disabled" in reason.lower()

    def test_authorized_can_log_in(self, app):
        user = create_user("okuser", "SomePass!2345", status=Status.AUTHORIZED)
        assert user.can_login() == (True, "")

    def test_locked_account_cannot_log_in(self, app):
        user = create_user("lockeduser", "SomePass!2345", status=Status.AUTHORIZED)
        user.locked_until = utcnow() + timedelta(minutes=10)
        allowed, reason = user.can_login()
        assert allowed is False
        assert "locked" in reason.lower()

    def test_expired_lock_no_longer_blocks(self, app):
        user = create_user("expireduser", "SomePass!2345", status=Status.AUTHORIZED)
        user.locked_until = utcnow() - timedelta(minutes=1)
        assert user.is_locked is False
        assert user.can_login()[0] is True

    def test_set_status_transitions(self, app):
        user = create_user("mover", "SomePass!2345", status=Status.PENDING)
        set_status(user, Status.AUTHORIZED)
        assert user.status == Status.AUTHORIZED.value
        set_status(user, Status.DISABLED)
        assert user.status == Status.DISABLED.value

    def test_set_status_rejects_unknown_value(self, app):
        user = create_user("mover", "SomePass!2345")
        with pytest.raises(ValueError, match="Unknown status"):
            set_status(user, "SUPERUSER")

    def test_admin_status_is_protected(self, app):
        admin = create_admin("protectedadmin", "AdminPass!2345")
        with pytest.raises(ValueError, match="Admin accounts"):
            set_status(admin, Status.DISABLED)

    def test_admin_cannot_change_own_status(self, app):
        admin = create_admin("selfadmin", "AdminPass!2345")
        journalist = create_user("someone", "SomePass!2345")
        journalist.id = journalist.id  # sanity
        with pytest.raises(ValueError):
            set_status(admin, Status.DISABLED, actor=admin)


class TestLockoutCounters:
    def test_counter_increments_then_locks(self, app):
        user = create_user("counter", "SomePass!2345", status=Status.AUTHORIZED)
        user.register_failed_login(max_attempts=3, lockout_minutes=10)
        assert user.failed_login_attempts == 1
        assert user.is_locked is False

        user.register_failed_login(max_attempts=3, lockout_minutes=10)
        user.register_failed_login(max_attempts=3, lockout_minutes=10)
        assert user.is_locked is True

    def test_successful_login_clears_counters(self, app):
        user = create_user("counter", "SomePass!2345", status=Status.AUTHORIZED)
        user.register_failed_login(max_attempts=3, lockout_minutes=10)
        user.register_successful_login()
        assert user.failed_login_attempts == 0
        assert user.locked_until is None
        assert user.last_login_at is not None


class TestSchema:
    def test_tables_are_namespaced_for_phase2(self, app):
        """Phase 2's tables keep their prefix, so they never collide with Phase 1's.

        Since the integration both phases share one metadata, so the check is on
        the tables Phase 2 owns rather than on every table in the database.
        """
        from phase2.models import AuditLog

        assert User.__tablename__ == "phase2_users"
        assert AuditLog.__tablename__ == "phase2_audit_log"
        names = set(db.metadata.tables)
        phase1_tables = {"submissions", "submission_evidence",
                         # Phase 7 signatures live in the submissions package too.
                         "submission_signatures", "signing_settings"}
        assert {"phase2_users", "phase2_audit_log"} <= names
        assert phase1_tables <= names
        assert all(name.startswith("phase2_") for name in names - phase1_tables)
