"""Phase 6 -- real-time WebSocket (Flask-SocketIO) notifications.

Who may connect, what is (and is never) sent, revocation mid-connection,
same-origin enforcement, the locally served client, and a full Phase 1-6 run.
"""

from __future__ import annotations

import hashlib
import io
import re
from datetime import timedelta
from pathlib import Path

import pytest
from PIL import Image

from phase2 import socket_events
from phase2.extensions import db, socketio
from phase2.models import Status
from submissions.models import Submission
from submissions.services import create_submission, read_evidence_file
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, JOURNALIST_PASSWORD, login

ROOT = Path(__file__).resolve().parent.parent
VENDORED_CLIENT = ROOT / "phase2" / "static" / "phase2" / "vendor" / "socket.io.min.js"
# SHA-256 of socket.io-client 4.8.1 dist/socket.io.min.js (npm tarball verified
# against the registry's sha512 integrity value when it was vendored).
VENDORED_CLIENT_SHA256 = "b0e735814f8dcfecd6cdb8a7ce95a297a7e1e5f2727a29e6f5901801d52fa0c5"

SECRET_TITLE = "Dock 4 customs bribes"
SECRET_BODY = "Inspector takes cash for every unchecked container."


@pytest.fixture(autouse=True)
def _clean_registry():
    with socket_events._lock:
        socket_events._connections.clear()
    yield
    with socket_events._lock:
        socket_events._connections.clear()


def socket_for(app, http_client):
    """A Socket.IO test client that shares the HTTP client's session cookie."""
    return socketio.test_client(app, flask_test_client=http_client)


def events(sock, name=None):
    received = sock.get_received()
    return [e for e in received if name is None or e["name"] == name]


def submit(client, title=SECRET_TITLE, content=SECRET_BODY, evidence=None):
    data = {"title": title, "content": content}
    if evidence is not None:
        data["evidence"] = evidence
    return client.post("/submit", data=data, content_type="multipart/form-data")


@pytest.fixture()
def journalist_socket(app, client, journalist):
    login(client, journalist.username, JOURNALIST_PASSWORD)
    sock = socket_for(app, client)
    assert sock.is_connected()
    yield sock
    if sock.is_connected():
        sock.disconnect()


# ---------------------------------------------------------------------------
# Who may connect
# ---------------------------------------------------------------------------
class TestConnectionAuthorization:
    def test_authorized_journalist_connects(self, journalist_socket):
        assert socket_events.connected_count() == 1

    def test_anonymous_visitor_is_refused(self, app, client):
        sock = socket_for(app, client)
        assert not sock.is_connected()
        assert socket_events.connected_count() == 0

    def test_admin_is_refused(self, app, client, admin):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        assert not socket_for(app, client).is_connected()

    def test_journalist_with_temporary_password_is_refused(self, app, client, make_journalist):
        user = make_journalist(username="tempjourno", must_change_password=True)
        login(client, user.username, JOURNALIST_PASSWORD)
        assert not socket_for(app, client).is_connected()

    def test_disabled_journalist_is_refused(self, app, client, journalist):
        login(client, journalist.username, JOURNALIST_PASSWORD)
        journalist.status = Status.DISABLED.value
        db.session.commit()
        assert not socket_for(app, client).is_connected()

    def test_idle_expired_session_is_refused(self, app, client, journalist):
        login(client, journalist.username, JOURNALIST_PASSWORD)
        with client.session_transaction() as session:
            session["last_seen"] = "2000-01-01T00:00:00"
        assert not socket_for(app, client).is_connected()

    def test_forged_cookie_is_refused(self, app, client, journalist):
        client.set_cookie("phase2_session", "forged.value.here", domain="localhost")
        assert not socket_for(app, client).is_connected()


class TestSameOriginOnly:
    """Cross-site WebSocket hijacking: Socket.IO rejects foreign Origins."""

    HANDSHAKE = "/socket.io/?EIO=4&transport=polling"

    def test_foreign_origin_is_rejected(self, client):
        response = client.get(self.HANDSHAKE, headers={"Origin": "https://evil.example"})
        assert response.status_code == 400

    def test_same_origin_handshake_is_accepted(self, client):
        response = client.get(self.HANDSHAKE, headers={"Origin": "http://localhost"})
        assert response.status_code == 200
        assert b'"sid"' in response.data


# ---------------------------------------------------------------------------
# What is sent
# ---------------------------------------------------------------------------
class TestEvents:
    def test_new_submission_is_announced_without_content(self, app, journalist_socket):
        source = app.test_client()
        response = submit(source, evidence=(io.BytesIO(b"evidence text"), "notes.txt"))
        assert response.status_code == 200
        token = re.search(rb"<code>([A-Za-z0-9_-]{32})</code>", response.data).group(1).decode()

        received = events(journalist_socket, "new_submission")
        assert len(received) == 1
        payload = received[0]["args"][0]
        assert payload == {"message": socket_events.NEW_SUBMISSION_MESSAGE}
        wire = repr(received)
        for secret in (SECRET_TITLE, SECRET_BODY, token, "evidence text", "notes.txt"):
            assert secret not in wire

    def test_status_change_reaches_other_journalists(self, app, client, journalist,
                                                     make_journalist):
        submission, _ = create_submission(SECRET_TITLE, SECRET_BODY)
        other = make_journalist(username="colleague")
        other_http = app.test_client()
        login(other_http, other.username, JOURNALIST_PASSWORD)
        watcher = socket_for(app, other_http)
        assert watcher.is_connected()

        login(client, journalist.username, JOURNALIST_PASSWORD)
        client.post(f"/journalist/submissions/{submission.id}/status",
                    data={"status": "UNDER_REVIEW"})

        received = events(watcher, "submission_status_changed")
        assert len(received) == 1
        payload = received[0]["args"][0]
        assert payload == {"id": submission.id, "status": "UNDER_REVIEW",
                           "message": f"Submission #{submission.id} is now Under review."}
        assert SECRET_TITLE not in repr(received)

    def test_refused_status_change_sends_nothing(self, app, client, journalist_socket):
        submission, _ = create_submission(SECRET_TITLE, SECRET_BODY)
        client.post(f"/journalist/submissions/{submission.id}/status", data={"status": "CLOSED"})
        assert events(journalist_socket, "submission_status_changed") == []

    def test_admins_and_anonymous_receive_nothing(self, app, client, admin):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        admin_sock = socket_for(app, client)
        anon_sock = socket_for(app, app.test_client())
        submit(app.test_client())
        for sock in (admin_sock, anon_sock):
            assert not sock.is_connected()
        assert socket_events.connected_count() == 0

    def test_notification_failure_never_breaks_a_submission(self, app, client, monkeypatch,
                                                            journalist_socket):
        def broken(*args, **kwargs):
            raise RuntimeError("socket layer down")

        monkeypatch.setattr(socketio, "emit", broken)
        response = submit(app.test_client())
        assert response.status_code == 200
        assert db.session.query(Submission).count() == 1


# ---------------------------------------------------------------------------
# Revocation while connected
# ---------------------------------------------------------------------------
@pytest.fixture()
def emitted(monkeypatch):
    """Record every server-side emit (the test client cannot be read once the
    server has disconnected it)."""
    calls = []
    real = socketio.emit

    def spy(event, *args, **kwargs):
        calls.append((event, kwargs.get("to")))
        return real(event, *args, **kwargs)

    monkeypatch.setattr(socketio, "emit", spy)
    return calls


class TestRevocation:
    @pytest.mark.parametrize("change", ["disable", "pending", "temp_password"])
    def test_revoked_journalist_is_disconnected_before_the_next_event(
        self, app, journalist, journalist_socket, emitted, change
    ):
        if change == "disable":
            journalist.status = Status.DISABLED.value
        elif change == "pending":
            journalist.status = Status.PENDING.value
        else:
            journalist.must_change_password = True
        db.session.commit()

        submit(app.test_client())
        assert [e for e in emitted if e[0] == "new_submission"] == []
        assert not journalist_socket.is_connected()
        assert socket_events.connected_count() == 0

    def test_socket_older_than_the_session_lifetime_is_disconnected(
        self, app, journalist_socket, emitted
    ):
        app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(seconds=-1)
        submit(app.test_client())
        assert [e for e in emitted if e[0] == "new_submission"] == []
        assert not journalist_socket.is_connected()

    def test_still_authorized_journalist_stays_connected(self, app, journalist_socket, emitted):
        submit(app.test_client())
        assert [e[0] for e in emitted] == ["new_submission"]
        assert journalist_socket.is_connected()


# ---------------------------------------------------------------------------
# Client delivery and privacy of the public pages
# ---------------------------------------------------------------------------
class TestClientDelivery:
    @pytest.mark.parametrize("url", ["/", "/submit", "/status", "/auth/login"])
    def test_public_pages_load_no_socket_client(self, client, url):
        page = client.get(url).data
        assert b"socket.io" not in page
        assert b'data-realtime="on"' not in page

    def test_admin_pages_load_no_socket_client(self, client, admin):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        assert b"socket.io" not in client.get("/admin/dashboard").data

    def test_journalist_pages_load_the_local_client(self, client, journalist):
        login(client, journalist.username, JOURNALIST_PASSWORD)
        page = client.get("/journalist/dashboard").data
        assert b'src="/phase2-static/phase2/vendor/socket.io.min.js"' in page
        assert b'data-realtime="on"' in page
        assert b"cdn.socket.io" not in page and b"https://" not in page

    def test_csp_still_allows_only_self(self, client, journalist):
        login(client, journalist.username, JOURNALIST_PASSWORD)
        csp = client.get("/journalist/dashboard").headers["Content-Security-Policy"]
        assert "script-src 'self';" in csp
        assert "cdn" not in csp and "http" not in csp

    def test_vendored_client_is_the_verified_release(self, client):
        data = VENDORED_CLIENT.read_bytes()
        assert hashlib.sha256(data).hexdigest() == VENDORED_CLIENT_SHA256
        assert data.startswith(b"/*!\n * Socket.IO v4.8.1")
        assert b"eval(" not in data  # runs under the strict CSP
        assert client.get("/phase2-static/phase2/vendor/socket.io.min.js").status_code == 200


# ---------------------------------------------------------------------------
# All six phases together
# ---------------------------------------------------------------------------
def test_phase1_to_phase6_end_to_end(app, client, journalist):
    # Phase 2 + 6: an authorized journalist is listening.
    login(client, journalist.username, JOURNALIST_PASSWORD)
    sock = socket_for(app, client)
    assert sock.is_connected()

    # Phase 1 + 3: an anonymous source submits a photo carrying GPS metadata.
    image = Image.new("RGB", (40, 30), (10, 120, 200))
    exif = Image.Exif()
    exif[0x0110] = "E2E-Camera-Model"
    exif.get_ifd(0x8825)[2] = (51.0, 30.0, 12.0)
    buffer = io.BytesIO()
    image.save(buffer, format="JPEG", exif=exif)
    source = app.test_client()
    receipt = submit(source, evidence=(io.BytesIO(buffer.getvalue()), "IMG_0042.jpg"))
    assert receipt.status_code == 200
    token = re.search(rb"<code>([A-Za-z0-9_-]{32})</code>", receipt.data).group(1).decode()

    # Phase 6: the journalist is notified, without content.
    notice = events(sock, "new_submission")
    assert len(notice) == 1 and SECRET_TITLE not in repr(notice)

    # Phase 5: stored encrypted; Phase 3: the stored image carries no metadata.
    submission = db.session.query(Submission).one()
    assert SECRET_TITLE not in submission.title_sealed
    clean = read_evidence_file(submission.evidence[0])
    assert b"E2E-Camera-Model" not in clean
    assert not Image.open(io.BytesIO(clean)).getexif()

    # Phase 4: read, download, move through the workflow.
    assert SECRET_BODY.encode() in client.get(f"/journalist/submissions/{submission.id}").data
    download = client.get(f"/journalist/submissions/{submission.id}/evidence/"
                          f"{submission.evidence[0].id}")
    assert download.status_code == 200 and download.data == clean
    client.post(f"/journalist/submissions/{submission.id}/status", data={"status": "UNDER_REVIEW"})

    # Phase 1: the source sees the change; the current step is "Under review".
    status = source.post("/status", data={"token": token}).data.decode()
    current = re.search(r'aria-current="step">.*?<span class="step-label">([^<]+)<', status, re.S)
    assert current and current.group(1) == "Under review"
    sock.disconnect()


# ---------------------------------------------------------------------------
# HTTPS (needed for the protected-traffic configuration)
# ---------------------------------------------------------------------------
class TestHttpsForms:
    """Regression: with "Referrer-Policy: no-referrer" every form failed over
    HTTPS, because Flask-WTF's strict HTTPS CSRF check needs a same-origin
    Referer.  The policy is now "same-origin"."""

    @pytest.fixture()
    def csrf_app(self, tmp_path):
        from phase2 import create_app

        app = create_app("testing", WTF_CSRF_ENABLED=True, EVIDENCE_DIR=str(tmp_path / "ev"))
        with app.app_context():
            db.create_all()
        yield app
        with app.app_context():
            db.drop_all()

    def _post_submit(self, client, headers):
        page = client.get("/submit", base_url="https://localhost")
        token = re.search(rb'name="csrf_token" type="hidden" value="([^"]+)"', page.data).group(1)
        return client.post("/submit", base_url="https://localhost", headers=headers,
                           data={"csrf_token": token.decode(), "title": "t", "content": "c"})

    def test_referrer_policy_is_same_origin(self, client):
        response = client.get("/")
        assert response.headers["Referrer-Policy"] == "same-origin"
        assert b'<meta name="referrer" content="same-origin">' in response.data

    def test_form_works_over_https_with_a_same_origin_referer(self, csrf_app):
        response = self._post_submit(csrf_app.test_client(),
                                     {"Referer": "https://localhost/submit"})
        assert response.status_code == 200
        assert b"Report received" in response.data

    @pytest.mark.parametrize("headers", [{}, {"Referer": "https://evil.example/form"}])
    def test_missing_or_foreign_referer_is_still_refused_over_https(self, csrf_app, headers):
        assert self._post_submit(csrf_app.test_client(), headers).status_code == 400
