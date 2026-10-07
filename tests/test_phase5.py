"""Phase 5 -- AES-256-GCM encryption, HMAC-SHA-256 integrity, timestamp/replay
protection and key management, plus the journalist read path built on them.
"""

from __future__ import annotations

import base64
import io
import re
import secrets
import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest
from PIL import Image

from phase2 import create_app
from phase2.extensions import db
from phase2.models import AuditLog, Status, utcnow
from submissions import crypto
from submissions.crypto import (
    IntegrityCheckError,
    KeyConfigurationError,
    Keys,
    StaleDataError,
    load_keys,
    open_package,
    open_text,
    parse_key,
    seal,
    seal_text,
)
from submissions.models import Evidence, Submission
from submissions.services import (
    create_submission,
    evidence_path,
    open_report,
    open_title,
    protection_keys,
    read_evidence_file,
)
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, JOURNALIST_PASSWORD, login

ROOT = Path(__file__).resolve().parent.parent
TITLE = "Harbour bribery"
BODY = "The port authority took payments on 3 March. Secret body text."
NOW = utcnow()


def random_keys() -> Keys:
    return Keys(encryption=secrets.token_bytes(32), mac=secrets.token_bytes(32))


KEYS = random_keys()
CTX = {"purpose": "test.field", "binding": "record-1"}


def sealed(plaintext=b"secret evidence bytes", keys=KEYS, ts=NOW, **ctx):
    return seal(keys, plaintext, timestamp=ts, **{**CTX, **ctx})


def opened(package, keys=KEYS, expected=NOW, **ctx):
    return open_package(keys, package, expected_timestamp=expected, **{**CTX, **ctx})


def flip(package: bytes, index: int) -> bytes:
    data = bytearray(package)
    data[index] ^= 0x01
    return bytes(data)


HEADER, NONCE = 11, 12  # "P5" + version + 8-byte timestamp; 96-bit nonce


# ---------------------------------------------------------------------------
# 1. AES-256-GCM encryption and decryption
# ---------------------------------------------------------------------------
class TestEncryption:
    def test_round_trip(self):
        assert opened(sealed(b"evidence \x00\xff bytes")) == b"evidence \x00\xff bytes"

    def test_text_round_trip(self):
        value = seal_text(KEYS, "Café – report", timestamp=NOW, **CTX)
        assert value.startswith("p5:")
        assert open_text(KEYS, value, expected_timestamp=NOW, **CTX) == "Café – report"

    def test_ciphertext_hides_the_plaintext(self):
        package = sealed(b"VERY-SECRET-PLAINTEXT" * 4)
        assert b"VERY-SECRET" not in package
        assert b"VERY-SECRET" not in base64.urlsafe_b64decode(
            seal_text(KEYS, "VERY-SECRET", timestamp=NOW, **CTX)[3:]
        )

    def test_package_layout(self):
        package = sealed(b"x" * 100)
        assert package[:2] == b"P5" and package[2] == 1
        assert len(package) == HEADER + NONCE + 100 + 16 + 32  # + GCM tag + HMAC

    def test_uses_aes_256(self, monkeypatch):
        key_lengths = []
        real = crypto.AESGCM

        def spy(key):
            key_lengths.append(len(key))
            return real(key)

        monkeypatch.setattr(crypto, "AESGCM", spy)
        opened(sealed())
        assert key_lengths == [32, 32]  # 256-bit key for encrypt and decrypt


class TestNonces:
    def test_fresh_random_nonce_for_every_encryption(self):
        packages = [sealed(b"same plaintext") for _ in range(200)]
        nonces = {p[HEADER:HEADER + NONCE] for p in packages}
        assert len(nonces) == 200
        assert len(set(packages)) == 200  # same input, never the same output

    def test_nonce_comes_from_the_os_csprng(self, monkeypatch):
        calls = []
        real = crypto.os.urandom

        def spy(n):
            calls.append(n)
            return real(n)

        monkeypatch.setattr(crypto.os, "urandom", spy)
        package = sealed()
        assert calls == [12]
        assert len(package[HEADER:HEADER + NONCE]) == 12


# ---------------------------------------------------------------------------
# 2. HMAC-SHA-256 integrity, verified before decryption
# ---------------------------------------------------------------------------
class TestIntegrity:
    @pytest.mark.parametrize(
        "region,index",
        [
            ("timestamp", 5),
            ("nonce", HEADER + 3),
            ("ciphertext", HEADER + NONCE + 2),
            ("gcm tag", -32 - 3),
            ("hmac", -1),
        ],
    )
    def test_any_modification_is_detected_by_hmac(self, region, index):
        with pytest.raises(IntegrityCheckError) as info:
            opened(flip(sealed(), index))
        assert info.value.reason == "hmac", region

    @pytest.mark.parametrize("index", [0, 1, 2])  # magic / version
    def test_header_modification_is_rejected(self, index):
        with pytest.raises(IntegrityCheckError) as info:
            opened(flip(sealed(), index))
        assert info.value.reason in ("malformed", "hmac")

    @pytest.mark.parametrize("cut", [0, 10, HEADER + NONCE, -1])
    def test_truncation_is_rejected(self, cut):
        with pytest.raises(IntegrityCheckError):
            opened(sealed()[:cut])

    def test_appended_bytes_are_rejected(self):
        with pytest.raises(IntegrityCheckError):
            opened(sealed() + b"\x00")

    def test_wrong_hmac_key(self):
        wrong = Keys(encryption=KEYS.encryption, mac=secrets.token_bytes(32))
        with pytest.raises(IntegrityCheckError) as info:
            opened(sealed(), keys=wrong)
        assert info.value.reason == "hmac"

    def test_wrong_encryption_key(self):
        wrong = Keys(encryption=secrets.token_bytes(32), mac=KEYS.mac)
        with pytest.raises(IntegrityCheckError) as info:
            opened(sealed(), keys=wrong)
        assert info.value.reason == "decrypt"

    @pytest.mark.parametrize("ctx", [{"purpose": "other.field"}, {"binding": "record-2"}])
    def test_package_is_bound_to_its_context(self, ctx):
        with pytest.raises(IntegrityCheckError) as info:
            opened(sealed(), **ctx)
        assert info.value.reason == "hmac"

    def test_hmac_is_checked_before_any_decryption(self, monkeypatch):
        attempts = []
        real = crypto.AESGCM

        class Spy:
            def __init__(self, key):
                self.inner = real(key)

            def encrypt(self, *a):
                return self.inner.encrypt(*a)

            def decrypt(self, *a):
                attempts.append(1)
                return self.inner.decrypt(*a)

        monkeypatch.setattr(crypto, "AESGCM", Spy)
        package = sealed()
        for bad in (flip(package, HEADER + NONCE + 1), flip(package, -1)):
            with pytest.raises(IntegrityCheckError):
                opened(bad)
        with pytest.raises(StaleDataError):  # timestamp check also precedes decryption
            opened(package, expected=NOW + timedelta(seconds=1))
        assert attempts == []
        opened(package)
        assert attempts == [1]

    def test_comparison_is_constant_time(self, monkeypatch):
        used = []
        real = crypto.hmac.compare_digest

        def spy(a, b):
            used.append(True)
            return real(a, b)

        monkeypatch.setattr(crypto.hmac, "compare_digest", spy)
        opened(sealed())
        assert used


# ---------------------------------------------------------------------------
# 3. Timestamp and replay protection
# ---------------------------------------------------------------------------
class TestTimestampAndReplay:
    def test_timestamp_is_inside_the_protected_package(self):
        assert crypto.package_timestamp(sealed(ts=NOW)) == NOW

    def test_package_from_another_time_is_stale(self):
        old = sealed(ts=NOW - timedelta(days=3))
        with pytest.raises(StaleDataError):
            opened(old, expected=NOW)

    def test_future_timestamp_is_rejected(self):
        future = NOW + timedelta(hours=2)
        with pytest.raises(StaleDataError, match="future"):
            open_package(KEYS, sealed(ts=future), expected_timestamp=future, now=NOW, **CTX)

    def test_small_clock_skew_is_tolerated(self):
        ahead = NOW + timedelta(seconds=30)
        assert open_package(KEYS, sealed(ts=ahead), expected_timestamp=ahead, now=NOW, **CTX)

    def test_stale_error_is_an_integrity_error(self):
        assert issubclass(StaleDataError, IntegrityCheckError)

    def test_record_timestamp_matches_and_is_preserved(self, app):
        submission, _ = create_submission(TITLE, BODY)
        package = base64.urlsafe_b64decode(submission.title_sealed[3:])
        assert crypto.package_timestamp(package) == submission.created_at

    def test_replayed_package_in_the_record_is_detected(self, app):
        """A package re-used after the record's time changed is stale."""
        submission, _ = create_submission(TITLE, BODY)
        submission.created_at = submission.created_at - timedelta(minutes=5)
        db.session.commit()
        with pytest.raises(StaleDataError):
            open_title(submission)


# ---------------------------------------------------------------------------
# 4. Key management
# ---------------------------------------------------------------------------
GOOD = secrets.token_urlsafe(32)
OTHER = secrets.token_urlsafe(32)


class TestKeys:
    def test_valid_keys_load(self):
        keys = load_keys(GOOD, OTHER)
        assert len(keys.encryption) == len(keys.mac) == 32
        assert "redacted" in repr(keys) and GOOD not in repr(keys)

    def test_padded_base64_is_accepted(self):
        assert len(parse_key(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(), "K")) == 32

    @pytest.mark.parametrize(
        "value,message",
        [
            (None, "not set"),
            ("", "not set"),
            ("   ", "not set"),
            ("replace-me-with-output-of-token_urlsafe-32", "32 bytes"),
            ("not base64!!", "base64url"),
            (secrets.token_urlsafe(16), "32 bytes"),        # 128-bit key
            (secrets.token_urlsafe(64), "32 bytes"),        # too long
            (base64.urlsafe_b64encode(bytes(32)).decode(), "does not look random"),
        ],
    )
    def test_invalid_keys_are_rejected(self, value, message):
        with pytest.raises(KeyConfigurationError, match=message):
            parse_key(value, "PHASE5_ENCRYPTION_KEY")

    def test_the_two_keys_must_differ(self):
        with pytest.raises(KeyConfigurationError, match="different"):
            load_keys(GOOD, GOOD)

    @pytest.mark.parametrize(
        "overrides",
        [
            {"PHASE5_ENCRYPTION_KEY": None},
            {"PHASE5_HMAC_KEY": ""},
            {"PHASE5_ENCRYPTION_KEY": "short"},
            {"PHASE5_HMAC_KEY": secrets.token_urlsafe(16)},
            {"PHASE5_ENCRYPTION_KEY": GOOD, "PHASE5_HMAC_KEY": GOOD},
        ],
    )
    def test_app_refuses_to_start_without_valid_keys(self, overrides):
        with pytest.raises(RuntimeError, match="Refusing to start") as info:
            create_app("testing", **overrides)
        for value in overrides.values():
            if value and len(value) > 10:
                assert value not in str(info.value)  # key material never echoed

    def test_keys_are_not_left_in_app_config(self):
        app = create_app("testing")
        assert "PHASE5_ENCRYPTION_KEY" not in app.config
        assert "PHASE5_HMAC_KEY" not in app.config
        assert isinstance(app.extensions["phase5_keys"], Keys)

    def test_env_example_placeholders_do_not_validate(self):
        text = (ROOT / ".env.example").read_text()
        values = dict(re.findall(r"^(PHASE5_(?:ENCRYPTION|HMAC)_KEY)=(.*)$", text, re.M))
        assert set(values) == {"PHASE5_ENCRYPTION_KEY", "PHASE5_HMAC_KEY"}
        for name, value in values.items():
            with pytest.raises(KeyConfigurationError):
                parse_key(value, name)

    def test_no_key_literals_in_the_source(self):
        pattern = re.compile(r"PHASE5_(ENCRYPTION|HMAC)_KEY\s*=\s*[\"'][A-Za-z0-9_-]{20,}")
        offenders = [
            str(path) for folder in ("phase2", "submissions", "database")
            for path in (ROOT / folder).rglob("*.py")
            if pattern.search(path.read_text())
        ] + [str(ROOT / "app.py")] * bool(pattern.search((ROOT / "app.py").read_text()))
        assert not offenders


# ---------------------------------------------------------------------------
# 5. Protected storage
# ---------------------------------------------------------------------------
@pytest.fixture()
def file_app(tmp_path):
    """A real on-disk SQLite database, so raw file bytes can be inspected."""
    app = create_app(
        "testing",
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{(tmp_path / 'p5.db').as_posix()}",
        EVIDENCE_DIR=str(tmp_path / "evidence"),
    )
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def png_bytes() -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", (8, 8), (9, 99, 199)).save(buffer, format="PNG")
    return buffer.getvalue()


class TestProtectedStorage:
    def test_database_file_holds_no_plaintext_or_keys(self, file_app, tmp_path):
        create_submission(TITLE, BODY, ("txt", b"EVIDENCE-PLAINTEXT-MARKER"))
        db.session.remove()
        raw = (tmp_path / "p5.db").read_bytes()
        for marker in (TITLE, BODY, "EVIDENCE-PLAINTEXT-MARKER"):
            assert marker.encode() not in raw
        keys = protection_keys()
        for key in (keys.encryption, keys.mac):
            assert key not in raw
            assert base64.urlsafe_b64encode(key).rstrip(b"=") not in raw
        dump = "\n".join(sqlite3.connect(tmp_path / "p5.db").iterdump())
        assert "'p5:" in dump  # title/content columns hold protected packages

    def test_evidence_file_holds_no_plaintext(self, file_app):
        submission, _ = create_submission(TITLE, BODY, ("png", png_bytes()))
        evidence = submission.evidence[0]
        on_disk = evidence_path(evidence).read_bytes()
        plaintext = read_evidence_file(evidence)
        assert on_disk.startswith(b"P5")
        assert plaintext.startswith(b"\x89PNG") and b"\x89PNG" not in on_disk
        assert evidence.size_bytes == len(plaintext)

    def test_legacy_plaintext_is_never_displayed(self, app):
        submission, _ = create_submission(TITLE, BODY)
        submission.title_sealed = "plaintext injected straight into the DB"
        db.session.commit()
        with pytest.raises(IntegrityCheckError) as info:
            open_title(submission)
        assert info.value.reason == "malformed"


# ---------------------------------------------------------------------------
# 6. Authorization flow around decryption
# ---------------------------------------------------------------------------
@pytest.fixture()
def report(app):
    submission, token = create_submission(TITLE, BODY, ("txt", b"EVIDENCE-PLAINTEXT"))
    return submission, token


def detail(submission):
    return f"/journalist/submissions/{submission.id}"


def download(submission):
    return f"/journalist/submissions/{submission.id}/evidence/{submission.evidence[0].id}"


class TestAccess:
    def test_authorized_journalist_reads_decrypted_report(self, client, journalist, report):
        submission, _ = report
        login(client, journalist.username, JOURNALIST_PASSWORD)
        page = client.get(detail(submission)).data
        assert TITLE.encode() in page and BODY.encode() in page
        assert b"p5:" not in page
        assert TITLE.encode() in client.get("/journalist/inbox").data
        assert client.get(download(submission)).data == b"EVIDENCE-PLAINTEXT"

    def test_anonymous_is_refused_before_any_decryption(self, client, report, monkeypatch):
        import phase2.blueprints.journalist as views

        def boom(*a, **k):
            raise AssertionError("decryption attempted before authorization")

        monkeypatch.setattr(views, "open_report", boom)
        monkeypatch.setattr(views, "read_evidence_file", boom)
        monkeypatch.setattr(views, "try_open_title", boom)
        submission, _ = report
        for url in (detail(submission), download(submission), "/journalist/inbox"):
            response = client.get(url, follow_redirects=False)
            assert response.status_code == 302
            assert BODY.encode() not in response.data

    def test_admin_gets_no_plaintext(self, client, admin, report, monkeypatch):
        import phase2.blueprints.journalist as views

        monkeypatch.setattr(views, "open_report", lambda *a: pytest.fail("decrypted for admin"))
        submission, _ = report
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        assert client.get(detail(submission)).status_code == 403
        assert client.get(download(submission)).status_code == 403
        for page in ("/admin/dashboard", "/admin/audit", "/admin/journalists"):
            body = client.get(page).data
            assert TITLE.encode() not in body and BODY.encode() not in body

    def test_disabled_journalist_is_refused(self, client, journalist, report):
        submission, _ = report
        login(client, journalist.username, JOURNALIST_PASSWORD)
        journalist.status = Status.DISABLED.value
        db.session.commit()
        for url in (detail(submission), download(submission)):
            response = client.get(url, follow_redirects=False)
            assert response.status_code == 302
            assert BODY.encode() not in response.data

    def test_pending_journalist_is_refused(self, client, make_journalist, report):
        submission, _ = report
        user = make_journalist(username="pending9", status=Status.PENDING)
        login(client, user.username, JOURNALIST_PASSWORD)
        assert client.get(detail(submission), follow_redirects=False).status_code == 302


class TestTamperedDataInTheApp:
    def test_tampered_report_is_refused_and_audited(self, client, journalist, report):
        submission, _ = report
        package = bytearray(base64.urlsafe_b64decode(submission.content_sealed[3:]))
        package[HEADER + NONCE + 4] ^= 0x01
        submission.content_sealed = "p5:" + base64.urlsafe_b64encode(bytes(package)).decode()
        db.session.commit()

        login(client, journalist.username, JOURNALIST_PASSWORD)
        response = client.get(detail(submission))
        assert response.status_code == 409
        assert BODY.encode() not in response.data
        entry = db.session.query(AuditLog).filter_by(action="submission.integrity_failed").one()
        assert entry.detail == "hmac" and entry.actor_username == journalist.username
        assert db.session.query(AuditLog).filter_by(action="submission.viewed").count() == 0

    def test_swapped_ciphertext_between_records_is_detected(self, client, journalist, app):
        first, _ = create_submission("First title", "First body")
        second, _ = create_submission("Second title", "Second body")
        second.title_sealed, second.content_sealed = first.title_sealed, first.content_sealed
        db.session.commit()

        login(client, journalist.username, JOURNALIST_PASSWORD)
        assert client.get(detail(second)).status_code == 409
        assert client.get(detail(first)).status_code == 200
        inbox = client.get("/journalist/inbox").data
        assert b"integrity check failed" in inbox and b"First title" in inbox

    def test_tampered_evidence_is_refused(self, app, client, journalist, report):
        submission, _ = report
        path = evidence_path(submission.evidence[0])
        path.write_bytes(flip(path.read_bytes(), 20))
        login(client, journalist.username, JOURNALIST_PASSWORD)
        response = client.get(download(submission))
        assert response.status_code == 409
        assert b"EVIDENCE-PLAINTEXT" not in response.data
        assert db.session.query(AuditLog).filter_by(action="evidence.integrity_failed").count() == 1
        assert db.session.query(AuditLog).filter_by(action="evidence.downloaded").count() == 0

    def test_swapped_evidence_files_are_detected(self, app, client, journalist):
        a, _ = create_submission("a", "a", ("txt", b"FILE-A"))
        b, _ = create_submission("b", "b", ("txt", b"FILE-B"))
        path_a, path_b = evidence_path(a.evidence[0]), evidence_path(b.evidence[0])
        data_a, data_b = path_a.read_bytes(), path_b.read_bytes()
        path_a.write_bytes(data_b)
        path_b.write_bytes(data_a)
        login(client, journalist.username, JOURNALIST_PASSWORD)
        assert client.get(download(a)).status_code == 409
        assert client.get(download(b)).status_code == 409

    def test_source_status_survives_tampering_without_leaking(self, client, report):
        submission, token = report
        submission.title_sealed = submission.title_sealed[:-6] + "AAAAAA"
        db.session.commit()
        page = client.post("/status", data={"token": token})
        assert page.status_code == 200
        assert b"integrity check failed" in page.data and b"Submitted" in page.data
        entry = db.session.query(AuditLog).filter_by(action="submission.integrity_failed").one()
        assert entry.ip_address is None and entry.actor_id is None


# ---------------------------------------------------------------------------
# 7. Audit log stays free of secrets
# ---------------------------------------------------------------------------
def test_audit_log_holds_no_plaintext_ciphertext_or_keys(client, journalist, report):
    submission, token = report
    login(client, journalist.username, JOURNALIST_PASSWORD)
    client.get(detail(submission))
    client.get(download(submission))
    client.post(f"/journalist/submissions/{submission.id}/status", data={"status": "UNDER_REVIEW"})
    keys = protection_keys()
    secrets_to_hide = [TITLE, BODY, "EVIDENCE-PLAINTEXT", token, submission.title_sealed[:40],
                       base64.urlsafe_b64encode(keys.encryption).decode().rstrip("=")]
    for entry in db.session.query(AuditLog):
        text = " ".join(str(v) for v in (entry.action, entry.target, entry.detail) if v)
        for value in secrets_to_hide:
            assert value not in text


# ---------------------------------------------------------------------------
# 8. Data stored before Phase 5
# ---------------------------------------------------------------------------
class TestProtectLegacyData:
    def _legacy(self, app):
        submission, _ = create_submission(TITLE, BODY)
        submission.title_sealed, submission.content_sealed = TITLE, BODY  # pre-Phase-5 row
        directory = Path(app.config["EVIDENCE_DIR"])
        directory.mkdir(parents=True, exist_ok=True)
        image = Image.new("RGB", (8, 8))
        exif = Image.Exif()
        exif[0x0110] = "LegacyCameraModel"
        buffer = io.BytesIO()
        image.save(buffer, format="JPEG", exif=exif)
        files = {"jpg": buffer.getvalue(), "pdf": b"%PDF-1.7 /Author (Legacy)"}
        rows = []
        for ext, data in files.items():
            name = f"{secrets.token_hex(16)}.{ext}"
            (directory / name).write_bytes(data)
            rows.append(Evidence(submission_id=submission.id, stored_name=name,
                                 extension=ext, size_bytes=len(data)))
        db.session.add_all(rows)
        db.session.commit()
        return submission, rows

    def test_dry_run_changes_nothing(self, app):
        submission, rows = self._legacy(app)
        result = app.test_cli_runner().invoke(args=["protect-legacy-data", "--dry-run"])
        assert result.exit_code == 0, result.output
        assert "1 report(s) and 2 evidence file(s) would be encrypted" in result.output
        db.session.expire_all()
        assert db.session.get(Submission, submission.id).title_sealed == TITLE

    def test_encrypts_scrubs_and_is_idempotent(self, app, client, journalist):
        submission, rows = self._legacy(app)
        runner = app.test_cli_runner()
        result = runner.invoke(args=["protect-legacy-data"])
        assert result.exit_code == 0, result.output
        assert ".pdf: metadata NOT removed" in result.output

        db.session.expire_all()
        submission = db.session.get(Submission, submission.id)
        assert open_report(submission).content == BODY
        jpg, pdf = (db.session.get(Evidence, r.id) for r in rows)
        clean = read_evidence_file(jpg)
        assert b"LegacyCameraModel" not in clean  # scrubbed, then encrypted
        assert b"LegacyCameraModel" not in evidence_path(jpg).read_bytes()
        assert read_evidence_file(pdf).startswith(b"%PDF")  # encrypted as-is
        assert len(list(Path(app.config["EVIDENCE_DIR"]).iterdir())) == 2  # originals gone

        login(client, journalist.username, JOURNALIST_PASSWORD)
        assert BODY.encode() in client.get(detail(submission)).data

        again = runner.invoke(args=["protect-legacy-data"])
        assert "0 report(s) and 0 evidence file(s) encrypted" in again.output


# ---------------------------------------------------------------------------
# 9. End to end, Phase 1-5 together
# ---------------------------------------------------------------------------
def test_full_workflow_end_to_end(app, client, journalist):
    image = Image.new("RGB", (30, 20), (1, 2, 3))
    exif = Image.Exif()
    exif[0x0110] = "E2E-Camera"
    exif.get_ifd(0x8825)[2] = (51.0, 30.0, 0.0)
    buffer = io.BytesIO()
    image.save(buffer, format="JPEG", exif=exif)

    receipt = client.post("/submit", data={
        "title": "E2E title", "content": "E2E body",
        "evidence": (io.BytesIO(buffer.getvalue()), "gps.jpg"),
    }, content_type="multipart/form-data")
    assert receipt.status_code == 200 and b"E2E title" in receipt.data
    token = re.search(rb"<code>([A-Za-z0-9_-]{32})</code>", receipt.data).group(1).decode()

    sub = db.session.query(Submission).one()
    assert "E2E" not in sub.title_sealed + sub.content_sealed  # encrypted at rest

    login(client, journalist.username, JOURNALIST_PASSWORD)
    assert b"E2E title" in client.get("/journalist/inbox").data
    assert b"E2E body" in client.get(detail(sub)).data
    downloaded = client.get(download(sub)).data
    with Image.open(io.BytesIO(downloaded)) as clean:
        assert clean.size == (30, 20) and not clean.getexif()  # Phase 3 still applies
    client.post(f"/journalist/submissions/{sub.id}/status", data={"status": "UNDER_REVIEW"})
    client.post("/auth/logout")

    status = client.post("/status", data={"token": token})
    assert b"E2E title" in status.data and b"Under review" in status.data
