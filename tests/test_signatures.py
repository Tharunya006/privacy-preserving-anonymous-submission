"""Phase 7: server-side RSA-PSS signatures over accepted submissions.

Keys used here are generated into pytest's temporary directories (or held in
memory) and thrown away; the real signing key is never read.
"""

from __future__ import annotations

import base64
import io
import stat
from contextlib import contextmanager
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from PIL import Image
from sqlalchemy.exc import IntegrityError

from phase2 import create_app
from phase2.extensions import db
from phase2.models import AuditLog
from phase2.services import create_admin
from submissions import services, signing
from submissions.models import Evidence, SigningSettings, Submission, SubmissionSignature
from submissions.models import SubmissionStatus
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, JOURNALIST_PASSWORD, login

PASSPHRASE = "test-only-passphrase-123"
OVERVIEW = "/admin/security-analysis"


def png(size=(24, 16)) -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", size, (200, 30, 90)).save(buffer, "PNG")
    return buffer.getvalue()


def status(submission) -> str:
    return services.verify_submission_signature(submission)["status"]


def signature_row(submission) -> SubmissionSignature:
    return db.session.execute(db.select(SubmissionSignature).filter_by(submission_id=submission.id)).scalar_one()


@pytest.fixture(scope="module")
def key_files(tmp_path_factory):
    """Two independent encrypted key pairs (A and B), outside the project."""
    out = {}
    for name in ("a", "b"):
        directory = tmp_path_factory.mktemp(f"keys-{name}")
        private_path, public_path, key_id = signing.generate_key_files(directory, PASSPHRASE)
        out[name] = {"private": private_path, "public": public_path, "key_id": key_id}
    return out


@contextmanager
def file_app(tmp_path, **overrides):
    """An app on a file database (shared between app instances) using real key files."""
    config = {"SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'shared.db'}",
              "EVIDENCE_DIR": str(tmp_path / "evidence"), "PHASE7_SIGNING_EPHEMERAL_TEST_KEY": False}
    config.update(overrides)
    application = create_app("testing", **config)
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()


@pytest.fixture()
def report(app):
    submission, _ = services.create_submission("Signed title MARKER-T", "Signed body MARKER-B", ("png", png()))
    return submission


# ---------------------------------------------------------------------------
# Signing at intake
# ---------------------------------------------------------------------------
class TestSigningAtIntake:
    def test_every_new_submission_is_signed_and_valid(self, app):
        plain, _ = services.create_submission("t", "body")
        with_file, _ = services.create_submission("t2", "body2", ("png", png()))
        for submission in (plain, with_file):
            record = signature_row(submission)
            assert record.algorithm == "RSASSA-PSS-SHA256"
            assert record.manifest_version == 1 and record.signature_format == 1
            assert record.key_id == app.extensions["signing_keys"].key_id and len(record.key_id) == 32
            assert len(record.signature) == 3072 // 8
            assert status(submission) == "valid"

    def test_first_signed_submission_sets_the_required_from_marker(self, app):
        first, _ = services.create_submission("t", "b")
        services.create_submission("t", "b")
        assert db.session.get(SigningSettings, 1).required_from_submission_id == first.id
        assert db.session.query(SigningSettings).count() == 1

    def test_signing_does_not_change_the_encrypted_data(self, app, report):
        opened = services.open_report(report)
        assert opened.title == "Signed title MARKER-T" and opened.content == "Signed body MARKER-B"
        assert services.read_evidence_file(report.evidence[0]).startswith(b"\x89PNG")

    def test_signature_is_randomized_pss(self, app, report):
        keys = app.extensions["signing_keys"]
        record = signature_row(report)
        manifest = services._manifest_for(report, record.key_id, record.signed_at)
        again = signing.sign_manifest(keys, manifest)
        assert again != record.signature
        assert signing.verify_manifest(keys.trusted[record.key_id], again, manifest)

    def test_only_one_signature_row_per_submission(self, app, report):
        duplicate = SubmissionSignature(submission_id=report.id, manifest_version=1, algorithm=signing.ALGORITHM,
                                        signature_format=1, key_id="0" * 32, signed_at=report.created_at,
                                        signature=b"x")
        db.session.add(duplicate)
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()
        assert status(report) == "valid"

    def test_status_changes_do_not_break_the_signature(self, app, report):
        report.status = SubmissionStatus.UNDER_REVIEW
        db.session.commit()
        assert status(report) == "valid"


# ---------------------------------------------------------------------------
# Tampering is detected
# ---------------------------------------------------------------------------
class TestTampering:
    def test_modified_title_envelope(self, app, report):
        other, _ = services.create_submission("Other title", "Other body")
        report.title_sealed = other.title_sealed          # a valid envelope, but not the signed one
        db.session.commit()
        assert status(report) == "invalid"

    def test_modified_content_envelope(self, app, report):
        raw = bytearray(signing.text_envelope(report.content_sealed))
        raw[-1] ^= 0x01
        report.content_sealed = "p5:" + base64.urlsafe_b64encode(bytes(raw)).decode("ascii")
        db.session.commit()
        assert status(report) == "invalid"

    def test_unreadable_text_value_is_not_valid(self, app, report):
        report.title_sealed = "plain text"
        db.session.commit()
        assert status(report) == "invalid"

    def test_modified_evidence_bytes(self, app, report):
        path = services.evidence_path(report.evidence[0])
        data = bytearray(path.read_bytes())
        data[40] ^= 0x01
        path.write_bytes(bytes(data))
        assert status(report) == "invalid"

    def test_substituted_evidence_file(self, app, report):
        other, _ = services.create_submission("t", "b", ("png", png((30, 30))))
        services.evidence_path(report.evidence[0]).write_bytes(services.evidence_path(other.evidence[0]).read_bytes())
        assert status(report) == "invalid"

    def test_evidence_row_pointed_at_another_file(self, app, report):
        other, _ = services.create_submission("t", "b", ("png", png((30, 30))))
        copy = services.evidence_path(other.evidence[0]).with_name("0" * 32 + ".png")
        copy.write_bytes(services.evidence_path(other.evidence[0]).read_bytes())
        report.evidence[0].stored_name = copy.name      # a genuine package, but not the signed one
        db.session.commit()
        assert status(report) == "invalid"

    def test_swapped_evidence_between_reports(self, app, report):
        other, _ = services.create_submission("t", "b", ("png", png((30, 30))))
        mine, theirs = report.evidence[0], other.evidence[0]
        mine.submission_id, theirs.submission_id = other.id, report.id
        db.session.commit()
        db.session.expire_all()
        assert status(db.session.get(Submission, report.id)) == "invalid"
        assert status(db.session.get(Submission, other.id)) == "invalid"

    def test_omitted_evidence(self, app, report):
        db.session.delete(report.evidence[0])
        db.session.commit()
        assert status(report) == "invalid"

    def test_added_evidence(self, app, report):
        extra = services.write_evidence_file("png", png((8, 8)), report.created_at)
        report.evidence.append(Evidence(stored_name=extra.name, extension="png", size_bytes=10,
                                        created_at=report.created_at))
        db.session.commit()
        assert status(report) == "invalid"

    def test_missing_evidence_file(self, app, report):
        services.evidence_path(report.evidence[0]).unlink()
        assert status(report) == "invalid"

    @pytest.mark.parametrize("change", ["created_at", "size_bytes", "evidence_created_at", "extension"])
    def test_modified_signed_metadata(self, app, report, change):
        from datetime import timedelta
        if change == "created_at":
            report.created_at = report.created_at + timedelta(microseconds=1)
        elif change == "size_bytes":
            report.evidence[0].size_bytes += 1
        elif change == "evidence_created_at":
            report.evidence[0].created_at = report.evidence[0].created_at + timedelta(seconds=1)
        else:
            report.evidence[0].extension = "gif"
        db.session.commit()
        assert status(report) == "invalid"

    def test_manifest_is_independent_of_evidence_order(self):
        from datetime import datetime
        when = datetime(2026, 1, 1)
        a = signing.EvidenceEntry(1, "a.png", "png", 3, when, b"aaa")
        b = signing.EvidenceEntry(2, "b.png", "png", 3, when, b"bbb")
        args = dict(key_id="0" * 32, submission_id=1, created_at=when, signed_at=when,
                    title_envelope=b"t", content_envelope=b"c")
        assert signing.build_manifest(**args, evidence=[a, b]) == signing.build_manifest(**args, evidence=[b, a])
        swapped = signing.EvidenceEntry(1, "a.png", "png", 3, when, b"bbb")
        assert signing.build_manifest(**args, evidence=[a, b]) != signing.build_manifest(**args, evidence=[swapped, b])


# ---------------------------------------------------------------------------
# Signature records and keys
# ---------------------------------------------------------------------------
class TestSignatureRecords:
    def test_flipped_signature_bit_is_invalid(self, app, report):
        record = signature_row(report)
        record.signature = bytes([record.signature[0] ^ 0x01]) + record.signature[1:]
        db.session.commit()
        assert status(report) == "invalid"

    def test_truncated_signature_is_malformed(self, app, report):
        record = signature_row(report)
        record.signature = record.signature[:-1]
        db.session.commit()
        assert status(report) == "malformed"

    @pytest.mark.parametrize("field,value", [("algorithm", "RSA-PKCS1v15-SHA256"), ("manifest_version", 2),
                                             ("signature_format", 9), ("signature", b"")])
    def test_unsupported_record_is_malformed(self, app, report, field, value):
        setattr(signature_row(report), field, value)
        db.session.commit()
        assert status(report) == "malformed"

    def test_unknown_key_id(self, app, report):
        signature_row(report).key_id = "f" * 32
        db.session.commit()
        assert status(report) == "unknown_key"

    def test_wrong_public_key_is_invalid(self, app, report, monkeypatch):
        keys = app.extensions["signing_keys"]
        stranger = rsa.generate_private_key(public_exponent=65537, key_size=3072).public_key()
        monkeypatch.setattr(keys, "trusted", {keys.key_id: stranger})
        assert status(report) == "invalid"

    def test_missing_signature_for_a_new_report(self, app, report):
        db.session.delete(signature_row(report))
        db.session.commit()
        assert status(report) == "missing"

    def test_legacy_reports_stay_unsigned(self, app):
        old, _ = services.create_submission("old", "old")
        db.session.delete(signature_row(old))
        db.session.delete(db.session.get(SigningSettings, 1))     # as before Phase 7
        db.session.commit()
        new, _ = services.create_submission("new", "new")
        assert status(old) == "legacy"
        assert status(new) == "valid"
        assert db.session.get(SigningSettings, 1).required_from_submission_id == new.id

    def test_unexpected_errors_are_never_valid(self, app, report, monkeypatch):
        def boom(*_args, **_kwargs):
            raise RuntimeError("boom")
        monkeypatch.setattr(signing, "verify_manifest", boom)
        from phase2.blueprints import admin as admin_blueprint
        assert admin_blueprint._signature(report)["status"] == "error"


# ---------------------------------------------------------------------------
# Failures roll back completely
# ---------------------------------------------------------------------------
def _nothing_stored(app) -> bool:
    evidence_dir = Path(app.config["EVIDENCE_DIR"])
    files = list(evidence_dir.iterdir()) if evidence_dir.exists() else []
    events = db.session.query(AuditLog).filter_by(action="submission.created").count()
    return (db.session.query(Submission).count() == 0 and db.session.query(Evidence).count() == 0
            and db.session.query(SubmissionSignature).count() == 0 and not files and events == 0)


class TestFailures:
    def test_signing_failure_stores_nothing(self, app, monkeypatch):
        def fail(*_args, **_kwargs):
            raise ValueError("signing broke")
        monkeypatch.setattr(signing, "sign_manifest", fail)
        with pytest.raises(signing.SigningFailed):
            services.create_submission("t", "b", ("png", png()))
        assert _nothing_stored(app)

    def test_commit_failure_stores_nothing(self, app, monkeypatch):
        real_commit = db.session.commit

        def fail():
            raise IntegrityError("commit", {}, Exception("disk full"))
        monkeypatch.setattr(db.session, "commit", fail)
        with pytest.raises(IntegrityError):
            services.create_submission("t", "b", ("png", png()))
        monkeypatch.setattr(db.session, "commit", real_commit)
        assert _nothing_stored(app)

    def test_retry_after_a_failure_succeeds(self, app, monkeypatch):
        calls = {"n": 0}
        real = signing.sign_manifest

        def flaky(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise ValueError("transient")
            return real(*args, **kwargs)
        monkeypatch.setattr(signing, "sign_manifest", flaky)
        with pytest.raises(signing.SigningFailed):
            services.create_submission("t", "b")
        submission, _ = services.create_submission("t", "b")
        assert status(submission) == "valid"
        assert db.session.query(Submission).count() == 1

    def test_signing_failure_on_the_web_form_returns_503(self, app, client, monkeypatch):
        def fail(*_args, **_kwargs):
            raise ValueError("signing broke")
        monkeypatch.setattr(signing, "sign_manifest", fail)
        response = client.post("/submit", data={"title": "t", "content": "body text"})
        assert response.status_code == 503
        assert b"temporarily unavailable" in response.data
        assert b"signing broke" not in response.data
        assert _nothing_stored(app)


# ---------------------------------------------------------------------------
# Key configuration
# ---------------------------------------------------------------------------
class TestKeyConfiguration:
    def test_no_key_starts_but_refuses_submissions(self, tmp_path):
        with file_app(tmp_path) as application:
            assert not application.extensions["signing_keys"].can_sign
            with pytest.raises(signing.SigningUnavailable):
                services.create_submission("t", "b", ("png", png()))
            response = application.test_client().post(
                "/submit", data={"title": "t", "content": "body text",
                                 "evidence": (io.BytesIO(png()), "e.png")},
                content_type="multipart/form-data")
            assert response.status_code == 503
            assert b"temporarily unavailable" in response.data
            assert _nothing_stored(application)
            assert application.test_client().get("/submit").status_code == 200

    def test_real_key_file_signs_and_hides_the_passphrase(self, tmp_path, key_files):
        with file_app(tmp_path, PHASE7_SIGNING_KEY_FILE=str(key_files["a"]["private"]),
                      PHASE7_SIGNING_KEY_PASSPHRASE=PASSPHRASE) as application:
            keys = application.extensions["signing_keys"]
            assert keys.can_sign and keys.key_id == key_files["a"]["key_id"]
            assert "PHASE7_SIGNING_KEY_PASSPHRASE" not in application.config
            assert PASSPHRASE not in repr(dict(application.config))
            assert "PRIVATE" not in repr(keys) and keys.key_id in repr(keys)
            submission, _ = services.create_submission("t", "b")
            assert status(submission) == "valid"

    def test_key_file_is_stored_encrypted(self, key_files):
        pem = key_files["a"]["private"].read_bytes()
        assert b"ENCRYPTED PRIVATE KEY" in pem
        with pytest.raises(TypeError):
            serialization.load_pem_private_key(pem, None)
        assert stat.S_IMODE(key_files["a"]["private"].stat().st_mode) == 0o600

    @pytest.mark.parametrize("problem", ["wrong-passphrase", "no-passphrase", "missing-file", "not-a-key",
                                         "readable-by-others", "too-small", "trusted-dir-writable"])
    def test_unusable_configuration_refuses_to_start(self, tmp_path, key_files, problem):
        key, passphrase, trusted = str(key_files["a"]["private"]), PASSPHRASE, None
        if problem == "wrong-passphrase":
            passphrase = "not-the-passphrase"
        elif problem == "no-passphrase":
            passphrase = None
        elif problem == "missing-file":
            key = str(tmp_path / "nope.pem")
        elif problem == "not-a-key":
            junk = tmp_path / "junk.pem"
            junk.write_bytes(b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n")
            junk.chmod(0o600)
            key = str(junk)
        elif problem == "readable-by-others":
            copy = tmp_path / "copy.pem"
            copy.write_bytes(key_files["a"]["private"].read_bytes())
            copy.chmod(0o644)
            key = str(copy)
        elif problem == "too-small":
            small = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            path = tmp_path / "small.pem"
            path.write_bytes(small.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                 serialization.BestAvailableEncryption(PASSPHRASE.encode())))
            path.chmod(0o600)
            key = str(path)
        else:
            trusted_dir = tmp_path / "trusted"
            trusted_dir.mkdir()
            trusted_dir.chmod(0o777)
            trusted = str(trusted_dir)
        with pytest.raises(RuntimeError) as excinfo:
            create_app("testing", PHASE7_SIGNING_EPHEMERAL_TEST_KEY=False, PHASE7_SIGNING_KEY_FILE=key,
                       PHASE7_SIGNING_KEY_PASSPHRASE=passphrase, PHASE7_TRUSTED_PUBLIC_KEY_DIR=trusted,
                       EVIDENCE_DIR=str(tmp_path / "evidence"))
        assert "Refusing to start" in str(excinfo.value)
        assert PASSPHRASE not in str(excinfo.value)

    def test_key_rotation_keeps_old_signatures_verifiable(self, tmp_path, key_files):
        with file_app(tmp_path, PHASE7_SIGNING_KEY_FILE=str(key_files["a"]["private"]),
                      PHASE7_SIGNING_KEY_PASSPHRASE=PASSPHRASE):
            old_id = services.create_submission("old", "old")[0].id

        trusted = tmp_path / "trusted"
        trusted.mkdir(mode=0o755)
        (trusted / "retired-a.pem").write_bytes(key_files["a"]["public"].read_bytes())
        with file_app(tmp_path, PHASE7_SIGNING_KEY_FILE=str(key_files["b"]["private"]),
                      PHASE7_SIGNING_KEY_PASSPHRASE=PASSPHRASE, PHASE7_TRUSTED_PUBLIC_KEY_DIR=str(trusted)):
            new = services.create_submission("new", "new")[0]
            old = db.session.get(Submission, old_id)
            assert signature_row(old).key_id == key_files["a"]["key_id"]
            assert signature_row(new).key_id == key_files["b"]["key_id"]
            assert status(old) == "valid" and status(new) == "valid"

        # Without the retired public key, the old signature cannot be checked: never "valid".
        with file_app(tmp_path, PHASE7_SIGNING_KEY_FILE=str(key_files["b"]["private"]),
                      PHASE7_SIGNING_KEY_PASSPHRASE=PASSPHRASE):
            assert status(db.session.get(Submission, old_id)) == "unknown_key"

    def test_verification_only_without_a_private_key(self, tmp_path, key_files):
        with file_app(tmp_path, PHASE7_SIGNING_KEY_FILE=str(key_files["a"]["private"]),
                      PHASE7_SIGNING_KEY_PASSPHRASE=PASSPHRASE):
            report_id = services.create_submission("t", "b")[0].id
        trusted = tmp_path / "trusted"
        trusted.mkdir(mode=0o755)
        (trusted / "a.pem").write_bytes(key_files["a"]["public"].read_bytes())
        with file_app(tmp_path, PHASE7_TRUSTED_PUBLIC_KEY_DIR=str(trusted)) as application:
            assert not application.extensions["signing_keys"].can_sign
            assert status(db.session.get(Submission, report_id)) == "valid"


# ---------------------------------------------------------------------------
# Admin UI and access control
# ---------------------------------------------------------------------------
class TestAdminUI:
    def test_overview_shows_a_signature_column(self, app, client, admin, report):
        legacy, _ = services.create_submission("legacy", "legacy")
        db.session.delete(signature_row(legacy))
        db.session.get(SigningSettings, 1).required_from_submission_id = legacy.id + 1
        db.session.commit()
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        page = client.get(OVERVIEW).get_data(as_text=True)
        assert "<th>Signature</th>" in page
        assert "Valid" in page and "Unsigned (legacy)" in page

    def test_report_page_shows_the_signature_panel(self, app, client, admin, report):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        page = client.get(f"{OVERVIEW}/submissions/{report.id}").get_data(as_text=True)
        record = signature_row(report)
        assert "Digital signature" in page and "Valid" in page
        assert record.key_id in page and "RSASSA-PSS-SHA256" in page

    def test_tampering_is_shown_on_both_pages(self, app, client, admin, report):
        services.evidence_path(report.evidence[0]).write_bytes(b"replaced")
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        assert "Invalid" in client.get(OVERVIEW).get_data(as_text=True)
        assert "Invalid" in client.get(f"{OVERVIEW}/submissions/{report.id}").get_data(as_text=True)

    def test_pages_reveal_no_secrets_or_plaintext(self, app, client, admin, report):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        record = signature_row(report)
        for url in (OVERVIEW, f"{OVERVIEW}/submissions/{report.id}"):
            page = client.get(url).get_data(as_text=True)
            assert "MARKER-T" not in page and "MARKER-B" not in page
            assert report.token_hash not in page
            assert record.signature.hex() not in page
            assert base64.b64encode(record.signature).decode() not in page
            assert "PRIVATE KEY" not in page

    def test_anonymous_users_are_sent_to_login(self, app, client, report):
        for url in (OVERVIEW, f"{OVERVIEW}/submissions/{report.id}"):
            response = client.get(url)
            assert response.status_code == 302 and "/auth/login" in response.headers["Location"]

    def test_journalists_are_forbidden(self, app, client, journalist, report):
        login(client, journalist.username, JOURNALIST_PASSWORD)
        for url in (OVERVIEW, f"{OVERVIEW}/submissions/{report.id}"):
            assert client.get(url).status_code == 403

    def test_journalist_pages_are_unchanged(self, app, client, journalist, report):
        login(client, journalist.username, JOURNALIST_PASSWORD)
        page = client.get(f"/journalist/submissions/{report.id}").get_data(as_text=True)
        assert "MARKER-T" in page                     # journalists still read the decrypted report
        assert "Digital signature" not in page and "Signature" not in page


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
class TestCli:
    def test_verify_signatures_all_good(self, app, report):
        result = app.test_cli_runner().invoke(args=["verify-signatures"])
        assert result.exit_code == 0
        assert f"{report.reference}: Valid" in result.output
        assert signature_row(report).signature.hex() not in result.output

    def test_verify_signatures_reports_problems_and_fails(self, app, report):
        services.evidence_path(report.evidence[0]).write_bytes(b"replaced")
        result = app.test_cli_runner().invoke(args=["verify-signatures"])
        assert result.exit_code == 1
        assert f"{report.reference}: Invalid" in result.output

    def test_verify_signatures_accepts_legacy(self, app):
        old, _ = services.create_submission("old", "old")
        db.session.delete(signature_row(old))
        db.session.get(SigningSettings, 1).required_from_submission_id = old.id + 1
        db.session.commit()
        result = app.test_cli_runner().invoke(args=["verify-signatures"])
        assert result.exit_code == 0 and "Unsigned (legacy)" in result.output

    def test_generate_signing_key(self, app, tmp_path):
        out = tmp_path / "new-keys"
        result = app.test_cli_runner().invoke(args=["generate-signing-key", "--out-dir", str(out)],
                                              input=f"{PASSPHRASE}\n{PASSPHRASE}\n")
        assert result.exit_code == 0, result.output
        private = [p for p in out.glob("signing-*.pem") if not p.name.endswith(".pub.pem")]
        assert len(private) == 1 and stat.S_IMODE(private[0].stat().st_mode) == 0o600
        assert stat.S_IMODE(out.stat().st_mode) == 0o700
        assert PASSPHRASE not in result.output and "PHASE7_SIGNING_KEY_FILE=" in result.output
        assert signing.load_signing_keys(str(private[0]), PASSPHRASE, None).can_sign

    def test_generate_signing_key_refuses_the_project_directory(self, app):
        project = Path(app.root_path).resolve().parent
        target = project / "instance" / "should-not-exist"
        result = app.test_cli_runner().invoke(args=["generate-signing-key", "--out-dir", str(target)],
                                              input=f"{PASSPHRASE}\n{PASSPHRASE}\n")
        assert result.exit_code != 0 and "outside the project" in result.output
        assert not target.exists()

    def test_generate_signing_key_refuses_a_short_passphrase(self, app, tmp_path):
        result = app.test_cli_runner().invoke(args=["generate-signing-key", "--out-dir", str(tmp_path / "k")],
                                              input="short\nshort\n")
        assert result.exit_code != 0 and "12 characters" in result.output
        assert not (tmp_path / "k").exists()

    def test_scrub_evidence_skips_signed_reports(self, app, report):
        path = services.evidence_path(report.evidence[0])
        before = path.read_bytes()
        result = app.test_cli_runner().invoke(args=["scrub-evidence"])
        assert "signed report - skipped" in result.output
        assert path.read_bytes() == before and status(report) == "valid"
