"""Business logic for anonymous submissions.

Shared by the public source routes, the journalist views and the CLI helpers so
the rules (validation, token handling, evidence storage, auditing) live in one
place and are testable without an HTTP request.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
from pathlib import Path

from flask import current_app
from sqlalchemy.exc import IntegrityError
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from phase2.extensions import db
from phase2.models import AuditLog, User, record_event, utcnow

from .models import STATUS_LABELS, Evidence, Submission, SubmissionStatus
from .scrubber import SCRUBBABLE_EXTENSIONS, ScrubError, scrub_evidence

TITLE_MAX_LENGTH = 200
CONTENT_MAX_LENGTH = 20_000
TOKEN_MAX_LENGTH = 128

# 24 random bytes -> 32 URL-safe characters (192 bits): infeasible to guess.
TOKEN_BYTES = 24

# Only types whose metadata can be removed (Phase 3): images are re-encoded
# without metadata, plain text has none.  PDF / office documents are refused.
ALLOWED_EVIDENCE_EXTENSIONS = SCRUBBABLE_EXTENSIONS


# The only shape a stored evidence name can take (see _write_evidence_file).
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


def _write_evidence_file(extension: str, data: bytes) -> Path:
    directory = evidence_dir()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / f"{secrets.token_hex(16)}.{extension}"
    # "x" refuses to overwrite: a random-name collision fails loudly instead.
    with path.open("xb") as handle:
        handle.write(data)
    os.chmod(path, 0o600)
    return path


def evidence_path(evidence: Evidence) -> Path | None:
    """Where an evidence file lives, or ``None`` if its stored name is not one
    this application generated (a tampered row can never point elsewhere)."""
    if not STORED_NAME_RE.fullmatch(evidence.stored_name or ""):
        return None
    return evidence_dir() / evidence.stored_name


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
    """
    title = _clean_text(title, "Title", TITLE_MAX_LENGTH)
    content = _clean_text(content, "Report", CONTENT_MAX_LENGTH)

    if evidence is not None:
        raw_extension, raw_data = evidence
        try:
            evidence = scrub_evidence(raw_extension, raw_data)
        except ScrubError as exc:
            raise EvidenceError(str(exc)) from exc

    for _ in range(3):
        token = generate_token()
        submission = Submission(token_hash=hash_token(token), title=title, content=content)
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
            written = _write_evidence_file(extension, data)
            submission.evidence.append(
                Evidence(stored_name=written.name, extension=extension, size_bytes=len(data))
            )
        record_event(
            "submission.created",
            target=submission.reference,
            detail=f"evidence={len(submission.evidence)}",
            commit=False,
        )
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
