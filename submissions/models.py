"""Database models for anonymous submissions.

A submission carries **no** link to a source identity: there is no user id, no
IP address and no session reference.  The only handle a source keeps is the
random token shown once on the receipt page, and only its SHA-256 hash is
stored here.
"""

from __future__ import annotations

import enum

from sqlalchemy import CheckConstraint

from phase2.extensions import db
from phase2.models import utcnow


class SubmissionStatus(str, enum.Enum):
    """Where a report is in the journalists' workflow."""

    SUBMITTED = "SUBMITTED"        # received, not yet opened
    UNDER_REVIEW = "UNDER_REVIEW"  # a journalist is working on it
    CLOSED = "CLOSED"              # review finished

    def __str__(self) -> str:
        return self.value

    @property
    def label(self) -> str:
        return STATUS_LABELS[self.value]


STATUS_LABELS = {
    SubmissionStatus.SUBMITTED.value: "Submitted",
    SubmissionStatus.UNDER_REVIEW.value: "Under review",
    SubmissionStatus.CLOSED.value: "Closed",
}


class Submission(db.Model):
    __tablename__ = "submissions"
    __table_args__ = (
        CheckConstraint(
            "status IN ('SUBMITTED', 'UNDER_REVIEW', 'CLOSED')",
            name="ck_submissions_status",
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    # SHA-256 of the source's token; the token itself is never stored.
    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    status = db.Column(
        db.String(20), nullable=False, default=SubmissionStatus.SUBMITTED.value, index=True
    )
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    evidence = db.relationship(
        "Evidence",
        back_populates="submission",
        cascade="all, delete-orphan",
        order_by="Evidence.id",
    )

    @property
    def status_label(self) -> str:
        return STATUS_LABELS.get(self.status, self.status)

    @property
    def reference(self) -> str:
        """Internal reference used in the audit log -- never the token."""
        return f"submission:{self.id}"

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Submission {self.id} {self.status}>"


class Evidence(db.Model):
    """A file attached to a submission.

    The file is stored under a random name in the private evidence directory.
    The source's original filename is deliberately **not** kept, because it can
    identify the person or machine that produced it.
    """

    __tablename__ = "submission_evidence"

    id = db.Column(db.Integer, primary_key=True)
    submission_id = db.Column(
        db.Integer, db.ForeignKey("submissions.id"), nullable=False, index=True
    )
    stored_name = db.Column(db.String(64), unique=True, nullable=False)
    extension = db.Column(db.String(10), nullable=False)
    size_bytes = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    submission = db.relationship("Submission", back_populates="evidence")

    @property
    def download_name(self) -> str:
        return f"submission-{self.submission_id}-evidence-{self.id}.{self.extension}"

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Evidence {self.id} of submission {self.submission_id}>"
