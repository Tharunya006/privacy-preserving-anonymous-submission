"""Business logic for anonymous submissions.

Shared by the public source routes, the journalist views and the CLI helpers so
the rules (validation, token handling, evidence storage, auditing) live in one
place and are testable without an HTTP request.

Phase 5: everything sensitive is sealed here before it is stored (title, body,
evidence) and only opened here, through ``submissions.crypto.open_package``,
which verifies HMAC-SHA-256 and the timestamp before it decrypts.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from flask import current_app
from sqlalchemy.exc import IntegrityError
from werkzeug.datastructures import FileStorage
from werkzeug.security import safe_join
from werkzeug.utils import secure_filename

from phase2.extensions import db
from phase2.models import AuditLog, User, record_event, utcnow

from . import signing
from .models import (
    STATUS_LABELS,
    Evidence,
    SigningSettings,
    Submission,
    SubmissionSignature,
    SubmissionStatus,
)
from .crypto import (
    IntegrityCheckError,
    Keys,
    ProtectionError,
    open_package,
    open_text,
    seal,
    seal_text,
)
from .scrubber import SCRUBBABLE_EXTENSIONS, ScrubError, scrub_evidence

# What each protected value is; bound into its HMAC and AES-GCM associated data.
PURPOSE_TITLE = "submission.title"
PURPOSE_CONTENT = "submission.content"
PURPOSE_EVIDENCE = "evidence.file"

TITLE_MAX_LENGTH = 200
CONTENT_MAX_LENGTH = 20_000
TOKEN_MAX_LENGTH = 128

# 24 random bytes -> 32 URL-safe characters (192 bits): infeasible to guess.
TOKEN_BYTES = 24

# Only types whose metadata can be removed (Phase 3): images are re-encoded
# without metadata, plain text has none.  PDF / office documents are refused.
ALLOWED_EVIDENCE_EXTENSIONS = SCRUBBABLE_EXTENSIONS


# The only shape a stored evidence name can take (see write_evidence_file).
STORED_NAME_RE = re.compile(r"^[0-9a-f]{32}\.[a-z0-9]{1,10}$")

INBOX_PAGE_SIZE = 25

# The journalist workflow: Submitted -> Under review -> Closed, one step at a
# time and forward only.  Closed is final.
ALLOWED_TRANSITIONS: dict[str, tuple[str, ...]] = {
    SubmissionStatus.SUBMITTED.value: (SubmissionStatus.UNDER_REVIEW.value,),
    SubmissionStatus.UNDER_REVIEW.value: (SubmissionStatus.CLOSED.value,),
    SubmissionStatus.CLOSED.value: (),
}


class EvidenceError(ValueError):
    """An uploaded evidence file was rejected.  The message is safe to show."""


class StatusTransitionError(ValueError):
    """A status change outside the workflow.  The message is safe to show."""


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------
def generate_token() -> str:
    """A cryptographically random submission token (``secrets``, not ``random``)."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_token(token: str) -> str:
    """Only this digest is stored, so a database leak does not leak tokens."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def find_by_token(raw_token: str | None) -> Submission | None:
    token = (raw_token or "").strip()
    if not token or len(token) > TOKEN_MAX_LENGTH:
        return None
    return db.session.execute(
        db.select(Submission).filter_by(token_hash=hash_token(token))
    ).scalar_one_or_none()


# ---------------------------------------------------------------------------
# Evidence files
# ---------------------------------------------------------------------------
def evidence_dir() -> Path:
    return Path(current_app.config["EVIDENCE_DIR"])


def read_evidence(upload: FileStorage | None) -> tuple[str, bytes] | None:
    """Validate an uploaded file.  Returns ``(extension, data)`` or ``None``.

    The client-supplied filename is used only to read the extension; it never
    becomes part of a path on disk.
    """
    if upload is None or not getattr(upload, "filename", None):
        return None

    name = secure_filename(upload.filename)
    extension = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if extension not in ALLOWED_EVIDENCE_EXTENSIONS:
        allowed = ", ".join(sorted(ALLOWED_EVIDENCE_EXTENSIONS))
        raise EvidenceError(f"That file type is not accepted. Allowed types: {allowed}.")

    limit = current_app.config["EVIDENCE_MAX_BYTES"]
    data = upload.stream.read(limit + 1)
    if not data:
        raise EvidenceError("The evidence file is empty.")
    if len(data) > limit:
        raise EvidenceError(
            f"The evidence file is too large (maximum {limit // (1024 * 1024)} MB)."
        )
    return extension, data


# ---------------------------------------------------------------------------
# Phase 5 protection helpers
# ---------------------------------------------------------------------------
def protection_keys() -> Keys:
    return current_app.extensions["phase5_keys"]


def _max_skew() -> int:
    return current_app.config.get("PHASE5_MAX_CLOCK_SKEW_SECONDS", 300)


def _evidence_binding(stored_name: str, extension: str) -> str:
    return f"{stored_name}|{extension}"


@dataclass(frozen=True)
class OpenedReport:
    """Decrypted, verified report text -- only ever held in memory."""

    title: str
    content: str


def _open_field(submission: Submission, value: str | None, purpose: str) -> str:
    return open_text(
        protection_keys(), value, purpose=purpose, binding=submission.token_hash,
        expected_timestamp=submission.created_at, max_skew_seconds=_max_skew(),
    )


def open_title(submission: Submission) -> str:
    """Verify, then decrypt the title.  Raises ``IntegrityCheckError``."""
    return _open_field(submission, submission.title_sealed, PURPOSE_TITLE)


def open_report(submission: Submission) -> OpenedReport:
    """Verify, then decrypt title and body.  Raises ``IntegrityCheckError``."""
    return OpenedReport(
        title=_open_field(submission, submission.title_sealed, PURPOSE_TITLE),
        content=_open_field(submission, submission.content_sealed, PURPOSE_CONTENT),
    )


def try_open_title(submission: Submission) -> str | None:
    """For list views: ``None`` instead of an exception when a row fails."""
    try:
        return open_title(submission)
    except ProtectionError:
        return None


def seal_submission_fields(submission: Submission, title: str, content: str) -> None:
    """Protect title and body for this row (token hash + creation time bound in)."""
    keys = protection_keys()
    common = {"binding": submission.token_hash, "timestamp": submission.created_at}
    submission.title_sealed = seal_text(keys, title, purpose=PURPOSE_TITLE, **common)
    submission.content_sealed = seal_text(keys, content, purpose=PURPOSE_CONTENT, **common)


# ---------------------------------------------------------------------------
# Evidence storage (files hold protected packages, never plaintext)
# ---------------------------------------------------------------------------
def write_evidence_file(extension: str, data: bytes, created_at: datetime) -> Path:
    """Seal already-scrubbed ``data`` and write it under a new random name."""
    directory = evidence_dir()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    name = f"{secrets.token_hex(16)}.{extension}"
    package = seal(
        protection_keys(), data, purpose=PURPOSE_EVIDENCE,
        binding=_evidence_binding(name, extension), timestamp=created_at,
    )
    path = directory / name
    # "x" refuses to overwrite: a random-name collision fails loudly instead.
    with path.open("xb") as handle:
        handle.write(package)
    os.chmod(path, 0o600)
    return path


def evidence_path(evidence: Evidence) -> Path | None:
    """Where an evidence file lives, or ``None`` if its stored name is not one
    this application generated (a tampered row can never point elsewhere)."""
    if not STORED_NAME_RE.fullmatch(evidence.stored_name or ""):
        return None
    joined = safe_join(str(evidence_dir()), evidence.stored_name)
    return Path(joined) if joined else None


def read_evidence_file(evidence: Evidence) -> bytes:
    """Verify, then decrypt one evidence file.

    Raises ``FileNotFoundError`` if it is missing and ``IntegrityCheckError``
    if it fails verification (including legacy, unprotected files).
    """
    path = evidence_path(evidence)
    if path is None or not path.is_file():
        raise FileNotFoundError("Evidence file is missing.")
    return open_package(
        protection_keys(), path.read_bytes(), purpose=PURPOSE_EVIDENCE,
        binding=_evidence_binding(evidence.stored_name, evidence.extension),
        expected_timestamp=evidence.created_at, max_skew_seconds=_max_skew(),
    )


# ---------------------------------------------------------------------------
# Submissions
# ---------------------------------------------------------------------------
def _clean_text(value: str | None, label: str, maximum: int) -> str:
    text = (value or "").strip()
    if not text:
        raise ValueError(f"{label} is required.")
    if len(text) > maximum:
        raise ValueError(f"{label} must be at most {maximum} characters.")
    return text


def create_submission(
    title: str, content: str, evidence: tuple[str, bytes] | None = None
) -> tuple[Submission, str]:
    """Store a new anonymous report.  Returns ``(submission, token)``.

    The token is returned exactly once, for the receipt page; it is not stored.
    Nothing about the source (IP, session, user agent) is recorded.

    Evidence is scrubbed of metadata here, in memory, before any database or
    disk write -- every caller goes through this, so unscrubbed evidence cannot
    be stored.  If it cannot be cleaned, ``EvidenceError`` is raised and nothing
    at all is saved.

    Phase 5: title, body and (scrubbed) evidence are then sealed -- AES-256-GCM
    plus HMAC-SHA-256 -- with the record's creation time as the protected
    timestamp.  Plaintext never reaches the database or the disk.
    """
    title = _clean_text(title, "Title", TITLE_MAX_LENGTH)
    content = _clean_text(content, "Report", CONTENT_MAX_LENGTH)
    # Phase 7: refuse before anything is written if the server cannot sign.
    if not signing_keys().can_sign:
        raise signing.SigningUnavailable("No signing key is configured.")

    if evidence is not None:
        raw_extension, raw_data = evidence
        try:
            evidence = scrub_evidence(raw_extension, raw_data)
        except ScrubError as exc:
            raise EvidenceError(str(exc)) from exc

    created_at = utcnow()
    for _ in range(3):
        token = generate_token()
        submission = Submission(
            token_hash=hash_token(token), created_at=created_at, updated_at=created_at
        )
        seal_submission_fields(submission, title, content)
        db.session.add(submission)
        try:
            db.session.flush()
            break
        except IntegrityError:  # a 192-bit collision: practically impossible
            db.session.rollback()
    else:
        raise RuntimeError("Could not allocate a unique submission token.")

    written: Path | None = None
    try:
        if evidence is not None:
            extension, data = evidence  # already scrubbed above
            written = write_evidence_file(extension, data, created_at)
            submission.evidence.append(
                Evidence(stored_name=written.name, extension=extension,
                         size_bytes=len(data), created_at=created_at)
            )
        record_event(
            "submission.created",
            target=submission.reference,
            detail=f"evidence={len(submission.evidence)}",
            commit=False,
        )
        db.session.flush()            # evidence ids are part of the signed manifest
        sign_submission(submission)   # same transaction: stored together or not at all
        db.session.commit()
    except Exception:
        db.session.rollback()
        if written is not None:
            written.unlink(missing_ok=True)
        raise
    return submission, token


def get_submission(submission_id: int) -> Submission | None:
    return db.session.get(Submission, submission_id)


def paginate_submissions(status: str | None = None, page: int = 1,
                         per_page: int = INBOX_PAGE_SIZE):
    """One page of the inbox, newest first (a Flask-SQLAlchemy Pagination)."""
    query = db.select(Submission)
    if status:
        query = query.filter_by(status=status)
    query = query.order_by(Submission.created_at.desc(), Submission.id.desc())
    return db.paginate(query, page=max(page, 1), per_page=per_page, error_out=False)


def latest_submissions(status: str | None = None, limit: int = 5) -> list[Submission]:
    query = db.select(Submission)
    if status:
        query = query.filter_by(status=status)
    query = query.order_by(Submission.created_at.desc(), Submission.id.desc()).limit(limit)
    return list(db.session.execute(query).scalars())


def submission_counts() -> dict[str, int]:
    counts = {s.value: 0 for s in SubmissionStatus}
    rows = db.session.execute(
        db.select(Submission.status, db.func.count(Submission.id)).group_by(Submission.status)
    )
    for status, total in rows:
        counts[status] = total
    counts["TOTAL"] = sum(counts[s.value] for s in SubmissionStatus)
    return counts


def next_statuses(submission: Submission) -> list[SubmissionStatus]:
    """The statuses this submission may move to next (empty once Closed)."""
    return [SubmissionStatus(s) for s in ALLOWED_TRANSITIONS.get(submission.status, ())]


def status_history(submission: Submission) -> list[AuditLog]:
    """Status changes for one submission, oldest first, from the audit log."""
    return list(
        db.session.execute(
            db.select(AuditLog)
            .filter_by(action="submission.status_changed", target=submission.reference)
            .order_by(AuditLog.created_at, AuditLog.id)
        ).scalars()
    )


def update_status(
    submission: Submission,
    new_status: SubmissionStatus | str,
    *,
    actor: User,
    ip: str | None = None,
) -> Submission:
    """Move a report one step through the workflow, with an audit entry.

    The change is a conditional UPDATE (``WHERE status = <previous>``), so if two
    journalists act on the same report at once only the first one wins and the
    second gets a clear error instead of silently overwriting it.
    """
    value = new_status.value if isinstance(new_status, SubmissionStatus) else str(new_status)
    if value not in {s.value for s in SubmissionStatus}:
        raise StatusTransitionError(f"Unknown submission status '{value}'.")

    previous = submission.status
    if value not in ALLOWED_TRANSITIONS.get(previous, ()):
        raise StatusTransitionError(
            f"A {STATUS_LABELS.get(previous, previous)} submission cannot be moved to "
            f"{STATUS_LABELS[value]}."
        )

    result = db.session.execute(
        db.update(Submission)
        .where(Submission.id == submission.id, Submission.status == previous)
        .values(status=value, updated_at=utcnow())
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        db.session.rollback()
        raise StatusTransitionError(
            "This submission was updated by someone else. Reload the page and try again."
        )
    record_event(
        "submission.status_changed",
        actor=actor,
        target=submission.reference,
        detail=f"{previous} -> {value}",
        ip_address=ip,
        commit=False,
    )
    db.session.commit()
    db.session.refresh(submission)
    return submission


# ---------------------------------------------------------------------------
# Phase 7: server signatures over accepted submissions
# ---------------------------------------------------------------------------
def signing_keys() -> signing.SigningKeys:
    return current_app.extensions["signing_keys"]


def _manifest_for(submission: Submission, key_id: str, signed_at: datetime) -> bytes:
    """The signed manifest, built from the STORED bytes: the text columns as
    stored and each evidence file as stored on disk.  Raises ValueError /
    FileNotFoundError if stored data is not in the signable form."""
    entries = []
    for evidence in submission.evidence:
        path = evidence_path(evidence)
        if path is None:
            raise ValueError("evidence file name is not valid")
        entries.append(signing.EvidenceEntry(
            id=evidence.id, stored_name=evidence.stored_name, extension=evidence.extension,
            size_bytes=evidence.size_bytes, created_at=evidence.created_at, envelope=path.read_bytes()))
    return signing.build_manifest(
        key_id=key_id, submission_id=submission.id, created_at=submission.created_at, signed_at=signed_at,
        title_envelope=signing.text_envelope(submission.title_sealed),
        content_envelope=signing.text_envelope(submission.content_sealed), evidence=entries)


def sign_submission(submission: Submission) -> SubmissionSignature:
    """Sign a just-accepted submission inside the caller's transaction (no commit here)."""
    keys = signing_keys()
    if not keys.can_sign:
        raise signing.SigningUnavailable("No signing key is configured.")
    signed_at = utcnow()
    try:
        signature = signing.sign_manifest(keys, _manifest_for(submission, keys.key_id, signed_at))
    except (ValueError, OSError) as exc:
        # Not a ValueError, so the route never shows it as a form error.
        raise signing.SigningFailed("The submission could not be signed.") from exc
    record = SubmissionSignature(
        submission_id=submission.id, manifest_version=signing.MANIFEST_VERSION,
        algorithm=signing.ALGORITHM, signature_format=signing.SIGNATURE_FORMAT, key_id=keys.key_id,
        signed_at=signed_at, signature=signature)
    db.session.add(record)
    if db.session.get(SigningSettings, 1) is None:
        # The first signed submission: every later one must be signed too.
        db.session.add(SigningSettings(id=1, required_from_submission_id=submission.id))
    return record


SIGNATURE_STATUSES = {
    "valid": "Valid",
    "invalid": "Invalid",
    "missing": "Missing signature",
    "unknown_key": "Unknown key",
    "legacy": "Unsigned (legacy)",
    "malformed": "Malformed signature record",
    "error": "Verification error",
}


def verify_submission_signature(submission: Submission) -> dict:
    """Verify a submission's signature against its CURRENT stored bytes, with
    the trusted PUBLIC key for the recorded key ID.  Nothing is decrypted and
    the private key is not used.  Only "valid" means valid; every other
    outcome -- including errors and unknown keys -- is reported as such."""
    record = db.session.execute(
        db.select(SubmissionSignature).filter_by(submission_id=submission.id)).scalar()
    result = {"status": None, "key_id": None, "signed_at": None, "algorithm": None,
              "manifest_version": None, "reason": None}
    if record is None:
        settings = db.session.get(SigningSettings, 1)
        if settings is None or submission.id < settings.required_from_submission_id:
            result.update(status="legacy", reason="Accepted before signing was introduced; never signed.")
        else:
            result.update(status="missing", reason="This report should have a signature, but none is stored.")
        return result
    result.update(key_id=record.key_id, signed_at=record.signed_at, algorithm=record.algorithm,
                  manifest_version=record.manifest_version)
    if (record.algorithm != signing.ALGORITHM or record.signature_format != signing.SIGNATURE_FORMAT
            or record.manifest_version != signing.MANIFEST_VERSION or not record.signature):
        result.update(status="malformed", reason="Unsupported or incomplete signature record.")
        return result
    public_key = signing_keys().trusted.get(record.key_id)
    if public_key is None:
        result.update(status="unknown_key", reason="The signing key ID is not in the trusted key set.")
        return result
    if len(record.signature) != public_key.key_size // 8:
        result.update(status="malformed", reason="The signature has the wrong length for this key.")
        return result
    try:
        manifest = _manifest_for(submission, record.key_id, record.signed_at)
    except (ValueError, OSError):
        result.update(status="invalid", reason="Signed stored data is missing or no longer in its signed form.")
        return result
    if signing.verify_manifest(public_key, record.signature, manifest):
        result.update(status="valid", reason="The signed stored data is unchanged since signing.")
    else:
        result.update(status="invalid", reason="The stored data or the signature changed after signing.")
    return result


def is_signed(submission_id: int) -> bool:
    return db.session.execute(
        db.select(SubmissionSignature.id).filter_by(submission_id=submission_id)).first() is not None
