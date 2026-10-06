"""CLI bootstrap tests: no hard-coded secrets, no public admin creation."""

from __future__ import annotations

from phase2.cli import generate_password
from phase2.models import Role, Status, User


class TestGeneratedPasswords:
    def test_generated_password_meets_the_policy(self):
        for _ in range(20):
            password = generate_password()
            assert len(password) >= 16
            assert any(c.islower() for c in password)
            assert any(c.isupper() for c in password)
            assert any(c.isdigit() for c in password)
            assert any(not c.isalnum() for c in password)

    def test_generated_passwords_are_unique(self):
        generated = {generate_password() for _ in range(50)}
        assert len(generated) == 50


class TestInitDbCommand:
    def test_init_db_creates_tables(self, app):
        runner = app.test_cli_runner()
        result = runner.invoke(args=["init-db"])
        assert result.exit_code == 0
        assert "ready" in result.output


class TestCreateAdminCommand:
    def test_create_admin_with_generated_password(self, app):
        runner = app.test_cli_runner()
        result = runner.invoke(
            args=["create-admin", "--username", "clibootadmin", "--generate-password"]
        )
        assert result.exit_code == 0, result.output

        admin = User.get_by_username("clibootadmin")
        assert admin is not None
        assert admin.role == Role.ADMIN.value
        assert admin.status == Status.AUTHORIZED.value
        assert admin.must_change_password is True

        # The printed password is the real one and is stored only as a hash.
        printed = [
            line.split(": ", 1)[1]
            for line in result.output.splitlines()
            if line.startswith("Temporary password: ")
        ][0]
        assert admin.check_password(printed) is True
        assert admin.password_hash != printed

    def test_create_admin_reads_password_from_environment(self, app, monkeypatch):
        monkeypatch.setenv("PHASE2_ADMIN_PASSWORD", "EnvAdmin!2345")
        runner = app.test_cli_runner()
        result = runner.invoke(args=["create-admin", "--username", "envadmin"])
        assert result.exit_code == 0, result.output
        assert User.get_by_username("envadmin").check_password("EnvAdmin!2345")

    def test_duplicate_admin_is_refused(self, app, monkeypatch):
        monkeypatch.setenv("PHASE2_ADMIN_PASSWORD", "EnvAdmin!2345")
        runner = app.test_cli_runner()
        runner.invoke(args=["create-admin", "--username", "envadmin"])
        result = runner.invoke(args=["create-admin", "--username", "envadmin"])
        assert result.exit_code != 0
        assert "already exists" in result.output


class TestJournalistCliCommands:
    def test_create_journalist_defaults_to_pending(self, app):
        runner = app.test_cli_runner()
        result = runner.invoke(args=["create-journalist", "--username", "clijourno"])
        assert result.exit_code == 0, result.output
        assert User.get_by_username("clijourno").status == Status.PENDING.value

    def test_set_status_command_authorizes(self, app):
        runner = app.test_cli_runner()
        runner.invoke(args=["create-journalist", "--username", "clijourno"])
        result = runner.invoke(args=["set-status", "clijourno", "AUTHORIZED"])
        assert result.exit_code == 0, result.output
        assert User.get_by_username("clijourno").status == Status.AUTHORIZED.value

    def test_set_status_on_unknown_user_fails(self, app):
        runner = app.test_cli_runner()
        result = runner.invoke(args=["set-status", "ghost", "AUTHORIZED"])
        assert result.exit_code != 0
        assert "No such user" in result.output

    def test_list_users_command(self, app, admin):
        runner = app.test_cli_runner()
        result = runner.invoke(args=["list-users"])
        assert result.exit_code == 0
        assert "rootadmin" in result.output
        # The hash must never be printed.
        assert "pbkdf2" not in result.output


class TestNoHardCodedSecrets:
    def test_no_secret_key_literal_in_source(self):
        import pathlib
        import re

        root = pathlib.Path(__file__).resolve().parent.parent / "phase2"
        pattern = re.compile(r'SECRET_KEY\s*=\s*["\'](?!\s*$)', re.IGNORECASE)
        offenders = []
        for path in root.rglob("*.py"):
            for lineno, line in enumerate(path.read_text().splitlines(), 1):
                if pattern.search(line) and "testing-only" not in line:
                    offenders.append(f"{path.name}:{lineno}")
        assert not offenders, f"hard-coded SECRET_KEY found at {offenders}"


class TestResetPasswordCommand:
    NEW_PASSWORD = "BrandNew!Pass42"

    def _reset(self, app, username, *passwords):
        runner = app.test_cli_runner()
        return runner.invoke(
            args=["reset-password", "--username", username],
            input="".join(f"{p}\n" for p in passwords),
        )

    def test_admin_password_is_reset(self, app, admin, client):
        from phase2.models import AuditLog
        from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, login

        result = self._reset(app, ADMIN_USERNAME, self.NEW_PASSWORD, self.NEW_PASSWORD)
        assert result.exit_code == 0, result.output
        assert "has been reset" in result.output

        user = User.get_by_username(ADMIN_USERNAME)
        assert user.check_password(self.NEW_PASSWORD)
        assert not user.check_password(ADMIN_PASSWORD)
        assert user.password_hash.startswith("pbkdf2:sha256:")
        assert user.must_change_password is False

        entry = AuditLog.query.filter_by(action="password.reset").one()
        assert entry.target == ADMIN_USERNAME
        assert entry.detail == "via CLI"

        # The new password works through the real login flow; the old one does not.
        assert b"Invalid username or password" in login(client, ADMIN_USERNAME, ADMIN_PASSWORD).data
        assert b"Admin dashboard" in login(client, ADMIN_USERNAME, self.NEW_PASSWORD).data

    def test_password_is_never_echoed(self, app, admin):
        result = self._reset(app, "rootadmin", self.NEW_PASSWORD, self.NEW_PASSWORD)
        assert self.NEW_PASSWORD not in result.output
        assert "pbkdf2" not in result.output

    def test_weak_password_is_refused_and_prompted_again(self, app, admin):
        from tests.conftest import ADMIN_PASSWORD

        result = self._reset(app, "rootadmin", "short")
        assert result.exit_code != 0
        assert "at least 10 characters" in result.output
        assert User.get_by_username("rootadmin").check_password(ADMIN_PASSWORD)

        result = self._reset(
            app, "rootadmin", "alllowercase123!", self.NEW_PASSWORD, self.NEW_PASSWORD
        )
        assert result.exit_code == 0, result.output
        assert "one uppercase letter" in result.output
        assert User.get_by_username("rootadmin").check_password(self.NEW_PASSWORD)

    def test_mismatched_confirmation_changes_nothing(self, app, admin):
        from tests.conftest import ADMIN_PASSWORD

        result = self._reset(app, "rootadmin", self.NEW_PASSWORD, "Different!Pass42")
        assert result.exit_code != 0
        assert User.get_by_username("rootadmin").check_password(ADMIN_PASSWORD)

    def test_unknown_user_fails(self, app):
        result = self._reset(app, "ghost", self.NEW_PASSWORD, self.NEW_PASSWORD)
        assert result.exit_code != 0
        assert "No such user" in result.output

    def test_journalist_reset_is_temporary_and_clears_lockout(self, app, journalist):
        from datetime import timedelta

        from phase2.extensions import db
        from phase2.models import utcnow

        journalist.locked_until = utcnow() + timedelta(minutes=10)
        journalist.failed_login_attempts = 3
        db.session.commit()

        result = self._reset(app, journalist.username, self.NEW_PASSWORD, self.NEW_PASSWORD)
        assert result.exit_code == 0, result.output
        assert "must change it" in result.output

        user = User.get_by_username(journalist.username)
        assert user.check_password(self.NEW_PASSWORD)
        assert user.must_change_password is True
        assert user.locked_until is None
        assert user.failed_login_attempts == 0

    def test_web_guard_on_admin_accounts_is_unchanged(self, app, admin):
        import pytest

        from phase2.services import reset_password

        with pytest.raises(ValueError, match="cannot be reset"):
            reset_password(admin, self.NEW_PASSWORD)
