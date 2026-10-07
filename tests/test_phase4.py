"""Phase 4 -- the journalist / authorized-receiver workflow.

Dashboard and inbox access, submission viewing, the
Submitted -> Under review -> Closed workflow, audit logging, evidence access
(including path traversal), and XSS / IDOR / CSRF / information-leak checks.
"""

from __future__ import annotations

import io
import re

import pytest

from phase2 import create_app
from phase2.extensions import db
from phase2.models import AuditLog, Status
from phase2.services import create_user
from submissions.models import Evidence, Submission, SubmissionStatus
from submissions.services import (
    StatusTransitionError,
    create_submission,
    evidence_path,
    update_status,
)
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, JOURNALIST_PASSWORD, login

XSS = '<script>alert("x")</script><img src=x onerror=alert(1)>'
REPORT_TEXT = "Confidential report body that must never reach the audit log."


@pytest.fixture()
def submission(app):
    sub, _token = create_submission("Harbour contracts", REPORT_TEXT)
    return sub


@pytest.fixture()
def submission_with_evidence(app):
    sub, _token = create_submission("With evidence", "Body", ("txt", b"PLAIN-TEXT-EVIDENCE"))
    return sub


@pytest.fixture()
def journalist_client(client, journalist):
    login(client, journalist.username, JOURNALIST_PASSWORD)
    return client


def change_status(client, submission_id, status, **kwargs):
    return client.post(
        f"/journalist/submissions/{submission_id}/status", data={"status": status}, **kwargs
    )


def current_status(submission_id) -> str:
    db.session.expire_all()
    return db.session.get(Submission, submission_id).status


# ---------------------------------------------------------------------------
# 1. Dashboard and inbox
# ---------------------------------------------------------------------------
class TestDashboardAccess:
    ROUTES = ["/journalist/dashboard", "/journalist/inbox"]

    @pytest.mark.parametrize("route", ROUTES)
    def test_authorized_journalist_gets_in(self, journalist_client, route):
        assert journalist_client.get(route).status_code == 200

    @pytest.mark.parametrize("route", ROUTES)
    def test_anonymous_is_sent_to_login(self, client, route):
        response = client.get(route, follow_redirects=False)
        assert response.status_code == 302
        assert "/auth/login" in response.headers["Location"]

    @pytest.mark.parametrize("route", ROUTES)
    def test_admin_is_forbidden(self, client, admin, route):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        assert client.get(route).status_code == 403

    @pytest.mark.parametrize("status", [Status.PENDING, Status.DISABLED])
    def test_unauthorized_journalist_cannot_sign_in(self, client, make_journalist, status):
        user = make_journalist(username=f"j{status.value.lower()}", status=status)
        login(client, user.username, JOURNALIST_PASSWORD)
        response = client.get("/journalist/inbox", follow_redirects=False)
        assert response.status_code == 302

    def test_disabled_mid_session_loses_access(self, journalist_client, journalist, submission):
        assert journalist_client.get(f"/journalist/submissions/{submission.id}").status_code == 200
        journalist.status = Status.DISABLED.value
        db.session.commit()
        response = journalist_client.get(
            f"/journalist/submissions/{submission.id}", follow_redirects=False
        )
        assert response.status_code == 302
        assert "/auth/login" in response.headers["Location"]


class TestInbox:
    def test_shows_reference_title_date_and_status(self, journalist_client, submission):
        page = journalist_client.get("/journalist/inbox").data.decode()
        assert f"#{submission.id}" in page
        assert "Harbour contracts" in page
        assert submission.created_at.strftime("%Y-%m-%d %H:%M") in page
        assert "Submitted" in page

    def test_report_body_is_not_listed(self, journalist_client, submission):
        assert REPORT_TEXT.encode() not in journalist_client.get("/journalist/inbox").data

    @pytest.mark.parametrize("status", [s.value for s in SubmissionStatus])
    def test_filter_by_status(self, app, journalist_client, journalist, status):
        subs = {s.value: create_submission(f"title-{s.value}", "body")[0] for s in SubmissionStatus}
        update_status(subs["UNDER_REVIEW"], "UNDER_REVIEW", actor=journalist)
        update_status(subs["CLOSED"], "UNDER_REVIEW", actor=journalist)
        update_status(subs["CLOSED"], "CLOSED", actor=journalist)

        page = journalist_client.get(f"/journalist/inbox?status={status}").data.decode()
        for value in subs:
            assert (f"title-{value}" in page) == (value == status)

    @pytest.mark.parametrize("bad", ["' OR 1=1 --", "DELETED", "submitted;DROP TABLE submissions"])
    def test_unknown_filter_is_ignored_safely(self, journalist_client, submission, bad):
        response = journalist_client.get("/journalist/inbox", query_string={"status": bad})
        assert response.status_code == 200
        assert b"Harbour contracts" in response.data
        assert db.session.query(Submission).count() == 1

    def test_pagination(self, app, journalist_client):
        for i in range(30):
            create_submission(f"report-{i:02d}", "body")
        first = journalist_client.get("/journalist/inbox").data.decode()
        second = journalist_client.get("/journalist/inbox?page=2").data.decode()
        assert "report-29" in first and "report-00" not in first
        assert "report-00" in second and "report-29" not in second
        assert "Page 1 of 2" in first

    @pytest.mark.parametrize("page", ["0", "-5", "abc", "999"])
    def test_bad_page_numbers_do_not_error(self, journalist_client, submission, page):
        assert journalist_client.get(f"/journalist/inbox?page={page}").status_code == 200

    def test_dashboard_lists_new_submissions(self, journalist_client, submission):
        page = journalist_client.get("/journalist/dashboard").data
        assert b"New submissions" in page
        assert b"Harbour contracts" in page


# ---------------------------------------------------------------------------
# 2. Submission details and IDOR
# ---------------------------------------------------------------------------
class TestSubmissionDetail:
    def test_journalist_reads_the_report(self, journalist_client, submission):
        page = journalist_client.get(f"/journalist/submissions/{submission.id}")
        assert page.status_code == 200
        assert REPORT_TEXT.encode() in page.data

    def test_unknown_id_is_404(self, journalist_client):
        assert journalist_client.get("/journalist/submissions/424242").status_code == 404

    @pytest.mark.parametrize("bad", ["abc", "1.5", "-1", "1%20OR%201=1"])
    def test_non_integer_ids_are_404(self, journalist_client, submission, bad):
        assert journalist_client.get(f"/journalist/submissions/{bad}").status_code == 404

    def test_anonymous_gets_the_same_answer_for_real_and_fake_ids(self, client, submission):
        """No enumeration: the login gate answers before the record is looked up."""
        real = client.get(f"/journalist/submissions/{submission.id}", follow_redirects=False)
        fake = client.get("/journalist/submissions/424242", follow_redirects=False)
        assert real.status_code == fake.status_code == 302
        assert REPORT_TEXT.encode() not in real.data

    def test_admin_cannot_read_report_content(self, client, admin, submission):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        response = client.get(f"/journalist/submissions/{submission.id}")
        assert response.status_code == 403
        assert REPORT_TEXT.encode() not in response.data
        for page in ("/admin/dashboard", "/admin/audit"):
            assert REPORT_TEXT.encode() not in client.get(page).data

    def test_admin_sees_statistics(self, client, admin, submission):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        page = client.get("/admin/dashboard").data
        assert b"Anonymous submissions" in page
        assert b"Harbour contracts" not in page

    def test_no_source_identity_is_stored_or_shown(self, app, journalist_client):
        client = app.test_client()
        client.post(
            "/submit",
            data={"title": "ident", "content": "c"},
            environ_base={"REMOTE_ADDR": "203.0.113.50"},
            headers={"User-Agent": "SourceBrowser/9.9", "X-Forwarded-For": "198.51.100.23"},
        )
        sub = db.session.query(Submission).filter_by(title="ident").one()
        columns = set(Submission.__table__.columns.keys())
        assert columns == {"id", "token_hash", "title", "content", "status", "created_at", "updated_at"}

        page = journalist_client.get(f"/journalist/submissions/{sub.id}").data
        inbox = journalist_client.get("/journalist/inbox").data
        for marker in (b"203.0.113.50", b"198.51.100.23", b"SourceBrowser", sub.token_hash.encode()):
            assert marker not in page
            assert marker not in inbox

    def test_journalist_pages_are_not_cached(self, journalist_client, submission):
        response = journalist_client.get(f"/journalist/submissions/{submission.id}")
        assert "no-store" in response.headers["Cache-Control"]
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert "script-src 'self'" in response.headers["Content-Security-Policy"]


# ---------------------------------------------------------------------------
# 3. Status workflow
# ---------------------------------------------------------------------------
class TestStatusWorkflow:
    def test_full_forward_workflow(self, journalist_client, submission):
        assert change_status(journalist_client, submission.id, "UNDER_REVIEW").status_code == 302
        assert current_status(submission.id) == "UNDER_REVIEW"
        assert change_status(journalist_client, submission.id, "CLOSED").status_code == 302
        assert current_status(submission.id) == "CLOSED"

    @pytest.mark.parametrize(
        "steps,attempt",
        [
            ([], "CLOSED"),                              # skipping Under review
            ([], "SUBMITTED"),                           # no-op
            (["UNDER_REVIEW"], "SUBMITTED"),             # backwards
            (["UNDER_REVIEW"], "UNDER_REVIEW"),          # no-op
            (["UNDER_REVIEW", "CLOSED"], "UNDER_REVIEW"),  # reopening a closed report
            (["UNDER_REVIEW", "CLOSED"], "SUBMITTED"),
            ([], "DELETED"),                             # not a status at all
            ([], ""),
        ],
    )
    def test_invalid_transitions_are_refused(self, journalist_client, submission, steps, attempt):
        for step in steps:
            change_status(journalist_client, submission.id, step)
        before = current_status(submission.id)
        audit_before = db.session.query(AuditLog).filter_by(
            action="submission.status_changed"
        ).count()

        response = change_status(journalist_client, submission.id, attempt, follow_redirects=True)
        assert response.status_code == 200
        assert current_status(submission.id) == before
        assert db.session.query(AuditLog).filter_by(
            action="submission.status_changed"
        ).count() == audit_before

    def test_refusal_message_is_shown(self, journalist_client, submission):
        response = change_status(journalist_client, submission.id, "CLOSED", follow_redirects=True)
        assert b"cannot be moved to Closed" in response.data

    def test_page_offers_only_the_next_step(self, journalist_client, submission):
        page = journalist_client.get(f"/journalist/submissions/{submission.id}").data
        assert b'value="UNDER_REVIEW"' in page
        assert b'value="CLOSED"' not in page

        change_status(journalist_client, submission.id, "UNDER_REVIEW")
        change_status(journalist_client, submission.id, "CLOSED")
        page = journalist_client.get(f"/journalist/submissions/{submission.id}").data
        assert b"No further status changes" in page

    def test_concurrent_change_does_not_overwrite(self, app, journalist, submission):
        """Another journalist already moved the report on; our copy is stale.

        ``set_committed_value`` gives our object the old status *as loaded*
        (not as an unsaved edit), exactly like a request that read the row just
        before someone else changed it.
        """
        from sqlalchemy.orm.attributes import set_committed_value

        db.session.execute(
            db.text("UPDATE submissions SET status = 'CLOSED' WHERE id = :id"),
            {"id": submission.id},
        )
        db.session.commit()
        set_committed_value(submission, "status", "SUBMITTED")

        with pytest.raises(StatusTransitionError, match="updated by someone else"):
            update_status(submission, "UNDER_REVIEW", actor=journalist)
        assert current_status(submission.id) == "CLOSED"
        assert db.session.query(AuditLog).filter_by(
            action="submission.status_changed"
        ).count() == 0

    def test_status_is_visible_to_the_source(self, app, journalist_client):
        source = app.test_client()
        receipt = source.post("/submit", data={"title": "t", "content": "c"}).data
        token = re.search(rb"<code>([A-Za-z0-9_-]{32})</code>", receipt).group(1).decode()
        sub = db.session.query(Submission).one()

        change_status(journalist_client, sub.id, "UNDER_REVIEW")
        assert b"Under review" in source.post("/status", data={"token": token}).data
        change_status(journalist_client, sub.id, "CLOSED")
        assert b"Closed" in source.post("/status", data={"token": token}).data

    def test_anonymous_and_admin_cannot_change_status(self, client, admin, submission):
        change_status(client, submission.id, "UNDER_REVIEW")
        assert current_status(submission.id) == "SUBMITTED"
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        assert change_status(client, submission.id, "UNDER_REVIEW").status_code == 403
        assert current_status(submission.id) == "SUBMITTED"

    def test_get_is_not_allowed(self, journalist_client, submission):
        response = journalist_client.get(f"/journalist/submissions/{submission.id}/status")
        assert response.status_code == 405


# ---------------------------------------------------------------------------
# 4. Audit log
# ---------------------------------------------------------------------------
class TestAuditLog:
    def test_status_change_is_audited(self, journalist_client, journalist, submission):
        change_status(journalist_client, submission.id, "UNDER_REVIEW")
        entry = db.session.query(AuditLog).filter_by(action="submission.status_changed").one()
        assert entry.actor_username == journalist.username
        assert entry.target == f"submission:{submission.id}"
        assert entry.detail == "SUBMITTED -> UNDER_REVIEW"

    def test_history_is_shown_on_the_report(self, journalist_client, journalist, submission):
        change_status(journalist_client, submission.id, "UNDER_REVIEW")
        page = journalist_client.get(f"/journalist/submissions/{submission.id}").data
        assert b"SUBMITTED -&gt; UNDER_REVIEW" in page
        assert journalist.username.encode() in page

    def test_view_and_download_are_audited(self, journalist_client, submission_with_evidence):
        sub = submission_with_evidence
        evidence = sub.evidence[0]
        journalist_client.get(f"/journalist/submissions/{sub.id}")
        journalist_client.get(f"/journalist/submissions/{sub.id}/evidence/{evidence.id}")
        actions = {e.action for e in db.session.query(AuditLog)}
        assert {"submission.created", "submission.viewed", "evidence.downloaded"} <= actions

    def test_audit_holds_no_content_tokens_or_file_data(self, app, journalist_client):
        sub, token = create_submission("Secret title", REPORT_TEXT, ("txt", b"EVIDENCE-BYTES"))
        journalist_client.get(f"/journalist/submissions/{sub.id}")
        journalist_client.get(f"/journalist/submissions/{sub.id}/evidence/{sub.evidence[0].id}")
        change_status(journalist_client, sub.id, "UNDER_REVIEW")

        for entry in db.session.query(AuditLog):
            text = " ".join(
                str(v) for v in (entry.action, entry.target, entry.detail, entry.actor_username) if v
            )
            for secret in (token, sub.token_hash, "Secret title", REPORT_TEXT,
                           "EVIDENCE-BYTES", sub.evidence[0].stored_name, JOURNALIST_PASSWORD):
                assert secret not in text

    def test_source_events_have_no_ip_or_actor(self, app):
        client = app.test_client()
        client.post("/submit", data={"title": "t", "content": "c"},
                    environ_base={"REMOTE_ADDR": "203.0.113.77"})
        entry = db.session.query(AuditLog).filter_by(action="submission.created").one()
        assert entry.ip_address is None and entry.actor_id is None and entry.actor_username is None


# ---------------------------------------------------------------------------
# 5. Evidence access and path traversal
# ---------------------------------------------------------------------------
def evidence_url(sub_id, ev_id):
    return f"/journalist/submissions/{sub_id}/evidence/{ev_id}"


class TestEvidenceAccess:
    def test_journalist_downloads_as_attachment(self, journalist_client, submission_with_evidence):
        evidence = submission_with_evidence.evidence[0]
        response = journalist_client.get(evidence_url(submission_with_evidence.id, evidence.id))
        assert response.status_code == 200
        assert response.data == b"PLAIN-TEXT-EVIDENCE"
        assert response.headers["Content-Type"] == "application/octet-stream"
        disposition = response.headers["Content-Disposition"]
        assert disposition.startswith("attachment")
        assert f"submission-{submission_with_evidence.id}-evidence-{evidence.id}.txt" in disposition
        assert "no-store" in response.headers["Cache-Control"]

    def test_anonymous_and_admin_cannot_download(self, client, admin, submission_with_evidence):
        url = evidence_url(submission_with_evidence.id, submission_with_evidence.evidence[0].id)
        response = client.get(url, follow_redirects=False)
        assert response.status_code == 302
        assert b"PLAIN-TEXT-EVIDENCE" not in response.data
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        response = client.get(url)
        assert response.status_code == 403
        assert b"PLAIN-TEXT-EVIDENCE" not in response.data

    def test_disabled_journalist_cannot_download(self, journalist_client, journalist,
                                                 submission_with_evidence):
        url = evidence_url(submission_with_evidence.id, submission_with_evidence.evidence[0].id)
        journalist.status = Status.DISABLED.value
        db.session.commit()
        assert journalist_client.get(url, follow_redirects=False).status_code == 302

    def test_evidence_of_another_submission_is_404(self, journalist_client,
                                                  submission_with_evidence, submission):
        url = evidence_url(submission.id, submission_with_evidence.evidence[0].id)
        assert journalist_client.get(url).status_code == 404

    def test_missing_file_on_disk_is_404(self, app, journalist_client, submission_with_evidence):
        evidence = submission_with_evidence.evidence[0]
        evidence_path(evidence).unlink()
        assert journalist_client.get(
            evidence_url(submission_with_evidence.id, evidence.id)
        ).status_code == 404

    @pytest.mark.parametrize(
        "suffix",
        [
            "../../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "1/../../../app.py",
            "..\\..\\app.py",
            "%00",
        ],
    )
    def test_traversal_in_the_url_is_rejected(self, journalist_client, submission_with_evidence,
                                              suffix):
        response = journalist_client.get(
            f"/journalist/submissions/{submission_with_evidence.id}/evidence/{suffix}"
        )
        assert response.status_code == 404
        assert b"root:" not in response.data and b"import" not in response.data

    @pytest.mark.parametrize(
        "stored_name",
        ["../../app.py", "/etc/passwd", "..%2fapp.py", "abc.pdf", "0" * 32 + ".pdf/../x"],
    )
    def test_tampered_stored_name_is_never_served(self, app, journalist_client,
                                                  submission_with_evidence, stored_name):
        """Even a row edited directly in the database cannot point outside storage."""
        evidence = submission_with_evidence.evidence[0]
        evidence.stored_name = stored_name
        db.session.commit()
        assert evidence_path(evidence) is None
        response = journalist_client.get(evidence_url(submission_with_evidence.id, evidence.id))
        assert response.status_code == 404

    def test_evidence_is_not_reachable_through_static_routes(self, app, client,
                                                            submission_with_evidence):
        name = submission_with_evidence.evidence[0].stored_name
        for url in (f"/phase2-static/{name}", f"/static/{name}", f"/evidence/{name}",
                    f"/instance/evidence/{name}"):
            assert client.get(url).status_code == 404


# ---------------------------------------------------------------------------
# 6. XSS and CSRF
# ---------------------------------------------------------------------------
class TestXss:
    def test_title_and_body_are_escaped_everywhere(self, journalist_client):
        sub, _ = create_submission(XSS, XSS)
        for url in ("/journalist/dashboard", "/journalist/inbox",
                    f"/journalist/submissions/{sub.id}"):
            page = journalist_client.get(url).data
            assert b"<script>alert" not in page, url
            assert b"<img src=x" not in page, url
            assert b"&lt;script&gt;" in page, url


class TestCsrf:
    """CSRF is on here.  Requests run outside a long-lived app context, as in
    production: Flask-WTF caches the token on ``g`` (app-context scoped), and
    login rebuilds the session, so a shared context would re-serve a stale token.
    """

    @pytest.fixture()
    def csrf_app(self, tmp_path):
        app = create_app("testing", WTF_CSRF_ENABLED=True, EVIDENCE_DIR=str(tmp_path / "ev"))
        with app.app_context():
            db.create_all()
            create_user("csrfj", JOURNALIST_PASSWORD, status=Status.AUTHORIZED,
                        must_change_password=False)
            submission_id = create_submission("t", "c")[0].id
        yield app, submission_id
        with app.app_context():
            db.session.remove()
            db.drop_all()

    @staticmethod
    def _token(html: bytes) -> str:
        return re.search(rb'name="csrf_token"[^>]*value="([^"]+)"', html).group(1).decode()

    def _status(self, app, submission_id) -> str:
        with app.app_context():
            return db.session.get(Submission, submission_id).status

    def test_status_change_requires_a_csrf_token(self, csrf_app):
        app, sid = csrf_app
        client = app.test_client()
        client.post("/auth/login", data={
            "csrf_token": self._token(client.get("/auth/login").data),
            "username": "csrfj", "password": JOURNALIST_PASSWORD,
        })

        for data in ({"status": "UNDER_REVIEW"},
                     {"status": "UNDER_REVIEW", "csrf_token": "forged-token"}):
            response = client.post(f"/journalist/submissions/{sid}/status", data=data)
            assert response.status_code == 400
            assert self._status(app, sid) == "SUBMITTED"

        token = self._token(client.get(f"/journalist/submissions/{sid}").data)
        response = client.post(f"/journalist/submissions/{sid}/status",
                               data={"csrf_token": token, "status": "UNDER_REVIEW"})
        assert response.status_code == 302
        assert self._status(app, sid) == "UNDER_REVIEW"
