"""Integration tests: the anonymous submission portal on top of Phase 2.

Covers the Phase 1 fixes made during the merge -- random hashed tokens, escaped
output, validation, private evidence storage, removed debug routes -- and the
journalist workflow that now reads submissions behind ``@journalist_required``.
"""

from __future__ import annotations

import io
import re
from pathlib import Path

import pytest

from phase2 import create_app
from phase2.extensions import db
from phase2.models import AuditLog
from submissions.models import Evidence, Submission, SubmissionStatus
from submissions.services import create_submission, find_by_token, hash_token
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, JOURNALIST_PASSWORD, login

TOKEN_RE = re.compile(rb"<code>([A-Za-z0-9_-]{32})</code>")
XSS = "<script>alert('x')</script>"


def submit(client, title="A report", content="Something happened.", evidence=None):
    data = {"title": title, "content": content}
    if evidence is not None:
        data["evidence"] = evidence
    return client.post("/submit", data=data, content_type="multipart/form-data")


def token_from(response) -> str:
    match = TOKEN_RE.search(response.data)
    assert match, "no token on the receipt page"
    return match.group(1).decode()


def check_status(client, token):
    return client.post("/status", data={"token": token})


# ---------------------------------------------------------------------------
# Anonymous source flow
# ---------------------------------------------------------------------------
class TestAnonymousSubmission:
    def test_pages_need_no_account(self, client):
        assert client.get("/submit").status_code == 200
        assert client.get("/status").status_code == 200

    def test_submit_then_check_status(self, client):
        response = submit(client, title="Budget fraud")
        assert response.status_code == 200
        token = token_from(response)

        status = check_status(client, token)
        assert status.status_code == 200
        assert b"Budget fraud" in status.data
        assert b"Submitted" in status.data

    def test_unknown_token_is_404(self, client):
        response = check_status(client, "not-a-real-token")
        assert response.status_code == 404
        assert b"Submission not found" in response.data

    def test_token_is_whitespace_tolerant(self, client):
        token = token_from(submit(client))
        assert check_status(client, f"  {token}  ").status_code == 200

    def test_source_pages_are_not_cached(self, client):
        response = submit(client)
        assert "no-store" in response.headers["Cache-Control"]


class TestTokens:
    def test_tokens_are_random_and_not_derived_from_title(self, client):
        first = token_from(submit(client, title="Same title"))
        second = token_from(submit(client, title="Same title"))
        assert first != second
        assert not first.startswith("TOKEN-")

    def test_duplicate_titles_do_not_crash(self, client):
        for _ in range(3):
            assert submit(client, title="Duplicate").status_code == 200
        assert db.session.query(Submission).filter_by(title="Duplicate").count() == 3

    def test_only_the_token_hash_is_stored(self, app):
        submission, token = create_submission("Title", "Body")
        assert submission.token_hash == hash_token(token)
        assert token not in submission.token_hash
        assert find_by_token(token).id == submission.id


class TestValidation:
    @pytest.mark.parametrize(
        "title,content",
        [("", "body"), ("title", ""), ("   ", "body"), ("x" * 201, "body"), ("t", "x" * 20001)],
    )
    def test_invalid_input_is_rejected(self, client, title, content):
        response = submit(client, title=title, content=content)
        assert response.status_code == 400
        assert db.session.query(Submission).count() == 0

    def test_empty_token_is_rejected(self, client):
        assert check_status(client, "").status_code == 400


class TestEscaping:
    def test_report_text_is_escaped_for_the_source(self, client):
        response = submit(client, title=XSS, content=XSS)
        assert XSS.encode() not in response.data
        assert b"&lt;script&gt;" in response.data

        status = check_status(client, token_from(response))
        assert XSS.encode() not in status.data

    def test_report_text_is_escaped_for_the_journalist(self, client, journalist):
        submit(client, title=XSS, content=XSS)
        submission = db.session.query(Submission).one()
        login(client, journalist.username, JOURNALIST_PASSWORD)

        for url in ("/journalist/inbox", f"/journalist/submissions/{submission.id}"):
            page = client.get(url)
            assert page.status_code == 200
            assert XSS.encode() not in page.data
            assert b"&lt;script&gt;" in page.data


class TestPrivacy:
    def test_no_source_ip_is_recorded(self, client):
        client.post(
            "/submit",
            data={"title": "t", "content": "c"},
            environ_base={"REMOTE_ADDR": "203.0.113.9"},
            headers={"X-Forwarded-For": "198.51.100.7"},
        )
        entry = db.session.query(AuditLog).filter_by(action="submission.created").one()
        assert entry.ip_address is None
        assert entry.actor_id is None
        for row in db.session.query(AuditLog):
            assert row.ip_address not in {"203.0.113.9", "198.51.100.7"}

    def test_audit_never_contains_the_token_or_content(self, client):
        token = token_from(submit(client, title="Secret title", content="Secret body"))
        for row in db.session.query(AuditLog):
            text = " ".join(filter(None, [row.target, row.detail, row.action]))
            assert token not in text
            assert "Secret" not in text


# ---------------------------------------------------------------------------
# Removed / replaced Phase 1 routes
# ---------------------------------------------------------------------------
class TestLegacyRoutes:
    @pytest.mark.parametrize("route", ["/test-submissions", "/test-db"])
    def test_debug_routes_are_gone(self, client, route):
        assert client.get(route).status_code == 404

    def test_old_login_redirects_to_phase2_login(self, client):
        response = client.get("/login", follow_redirects=False)
        assert response.status_code == 301
        assert response.headers["Location"].endswith("/auth/login")

    def test_home_links_to_the_portal(self, client):
        page = client.get("/")
        assert b'href="/submit"' in page.data
        assert b'href="/status"' in page.data


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------
class TestEvidence:
    def test_valid_file_is_stored_privately(self, app, client):
        response = submit(client, evidence=(io.BytesIO(b"plain evidence"), "John Smith report.txt"))
        assert response.status_code == 200
        evidence = db.session.query(Evidence).one()

        stored = Path(app.config["EVIDENCE_DIR"]) / evidence.stored_name
        assert stored.read_bytes() == b"plain evidence"
        assert stored.stat().st_mode & 0o077 == 0
        # The identifying original filename is not kept anywhere.
        assert "smith" not in evidence.stored_name.lower()
        assert "smith" not in evidence.download_name.lower()

    def test_disallowed_type_is_rejected(self, app, client):
        response = submit(client, evidence=(io.BytesIO(b"MZ..."), "payload.exe"))
        assert response.status_code == 400
        assert b"not accepted" in response.data
        assert db.session.query(Submission).count() == 0

    def test_empty_file_is_rejected(self, client):
        response = submit(client, evidence=(io.BytesIO(b""), "empty.txt"))
        assert response.status_code == 400

    def test_oversize_request_is_refused(self, tmp_path):
        app = create_app(
            "testing",
            EVIDENCE_DIR=str(tmp_path / "ev"),
            EVIDENCE_MAX_BYTES=1024,
            MAX_CONTENT_LENGTH=4096,
        )
        with app.app_context():
            db.create_all()
            response = submit(
                app.test_client(), evidence=(io.BytesIO(b"x" * 10_000), "big.txt")
            )
            assert response.status_code == 413
            assert db.session.query(Submission).count() == 0
            db.drop_all()

    def test_per_file_limit(self, tmp_path):
        app = create_app("testing", EVIDENCE_DIR=str(tmp_path / "ev"), EVIDENCE_MAX_BYTES=10)
        with app.app_context():
            db.create_all()
            response = submit(app.test_client(), evidence=(io.BytesIO(b"x" * 11), "a.txt"))
            assert response.status_code == 400
            assert b"too large" in response.data
            db.drop_all()

    def test_evidence_is_not_publicly_reachable(self, app, client):
        submit(client, evidence=(io.BytesIO(b"data"), "a.txt"))
        evidence = db.session.query(Evidence).one()
        url = f"/journalist/submissions/{evidence.submission_id}/evidence/{evidence.id}"
        response = client.get(url, follow_redirects=False)
        assert response.status_code == 302
        assert "/auth/login" in response.headers["Location"]
        for guess in (f"/phase2-static/{evidence.stored_name}", f"/evidence/{evidence.stored_name}"):
            assert client.get(guess).status_code == 404

    def test_journalist_downloads_as_attachment(self, client, journalist):
        submit(client, evidence=(io.BytesIO(b"<html>evil</html>"), "a.txt"))
        evidence = db.session.query(Evidence).one()
        login(client, journalist.username, JOURNALIST_PASSWORD)

        response = client.get(
            f"/journalist/submissions/{evidence.submission_id}/evidence/{evidence.id}"
        )
        assert response.status_code == 200
        assert response.data == b"<html>evil</html>"
        assert response.headers["Content-Type"] == "application/octet-stream"
        assert response.headers["Content-Disposition"].startswith("attachment")
        assert db.session.query(AuditLog).filter_by(action="evidence.downloaded").count() == 1

    def test_evidence_must_belong_to_the_submission(self, client, journalist):
        submit(client, evidence=(io.BytesIO(b"a"), "a.txt"))
        submit(client, title="other")
        evidence = db.session.query(Evidence).one()
        other = db.session.query(Submission).filter_by(title="other").one()
        login(client, journalist.username, JOURNALIST_PASSWORD)
        url = f"/journalist/submissions/{other.id}/evidence/{evidence.id}"
        assert client.get(url).status_code == 404


# ---------------------------------------------------------------------------
# Journalist workflow and RBAC
# ---------------------------------------------------------------------------
class TestJournalistWorkflow:
    def test_inbox_lists_submissions(self, client, journalist):
        submit(client, title="First report")
        login(client, journalist.username, JOURNALIST_PASSWORD)
        page = client.get("/journalist/inbox")
        assert page.status_code == 200
        assert b"First report" in page.data

    def test_inbox_status_filter(self, client, journalist):
        submit(client, title="Open one")
        submission = db.session.query(Submission).one()
        submission.status = SubmissionStatus.CLOSED.value
        db.session.commit()
        submit(client, title="New one")
        login(client, journalist.username, JOURNALIST_PASSWORD)

        page = client.get("/journalist/inbox?status=SUBMITTED")
        assert b"New one" in page.data
        assert b"Open one" not in page.data

    def test_viewing_is_audited(self, client, journalist):
        submit(client)
        submission = db.session.query(Submission).one()
        login(client, journalist.username, JOURNALIST_PASSWORD)
        client.get(f"/journalist/submissions/{submission.id}")
        entry = db.session.query(AuditLog).filter_by(action="submission.viewed").one()
        assert entry.actor_username == journalist.username
        assert entry.target == f"submission:{submission.id}"

    def test_status_change_reaches_the_source(self, client, journalist):
        token = token_from(submit(client))
        submission = db.session.query(Submission).one()
        login(client, journalist.username, JOURNALIST_PASSWORD)

        response = client.post(
            f"/journalist/submissions/{submission.id}/status",
            data={"status": "UNDER_REVIEW"},
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert db.session.get(Submission, submission.id).status == "UNDER_REVIEW"
        assert db.session.query(AuditLog).filter_by(
            action="submission.status_changed"
        ).one().detail == "SUBMITTED -> UNDER_REVIEW"

        client.post("/auth/logout")
        assert b"Under review" in check_status(client, token).data

    def test_invalid_status_is_refused(self, client, journalist):
        submit(client)
        submission = db.session.query(Submission).one()
        login(client, journalist.username, JOURNALIST_PASSWORD)
        client.post(f"/journalist/submissions/{submission.id}/status", data={"status": "DELETED"})
        assert db.session.get(Submission, submission.id).status == "SUBMITTED"

    def test_missing_submission_is_404(self, client, journalist):
        login(client, journalist.username, JOURNALIST_PASSWORD)
        assert client.get("/journalist/submissions/999").status_code == 404

    def test_dashboard_shows_counts(self, client, journalist):
        submit(client)
        login(client, journalist.username, JOURNALIST_PASSWORD)
        assert b"Submissions" in client.get("/journalist/dashboard").data


class TestSubmissionAccessControl:
    def test_anonymous_cannot_read_submissions(self, client):
        submit(client)
        submission = db.session.query(Submission).one()
        for url in (
            "/journalist/inbox",
            f"/journalist/submissions/{submission.id}",
        ):
            response = client.get(url, follow_redirects=False)
            assert response.status_code == 302
            assert "/auth/login" in response.headers["Location"]

    def test_anonymous_cannot_change_status(self, client):
        submit(client)
        submission = db.session.query(Submission).one()
        client.post(f"/journalist/submissions/{submission.id}/status", data={"status": "CLOSED"})
        assert db.session.get(Submission, submission.id).status == "SUBMITTED"

    def test_admin_cannot_read_submissions(self, client, admin):
        submit(client, title="Confidential")
        submission = db.session.query(Submission).one()
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        assert client.get(f"/journalist/submissions/{submission.id}").status_code == 403
        assert client.get("/journalist/inbox").status_code == 403
        dashboard = client.get("/admin/dashboard")
        assert dashboard.status_code == 200
        assert b"Confidential" not in dashboard.data

    def test_disabled_journalist_loses_access(self, client, journalist):
        submit(client)
        login(client, journalist.username, JOURNALIST_PASSWORD)
        assert client.get("/journalist/inbox").status_code == 200
        journalist.status = "DISABLED"
        db.session.commit()
        assert client.get("/journalist/inbox", follow_redirects=False).status_code == 302


class TestAdminRedirect:
    def test_status_change_ignores_offsite_return_to(self, client, admin, make_journalist):
        target = make_journalist(username="pending1", status="PENDING")
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        response = client.post(
            f"/admin/journalists/{target.id}/status",
            data={"status": "AUTHORIZED", "return_to": "https://evil.example/"},
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert "evil.example" not in response.headers["Location"]
