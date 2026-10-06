"""WTForms for the submission portal and the journalist workflow.

Flask-WTF gives every form server-side validation and a CSRF token, exactly as
the Phase 2 forms do.
"""

from __future__ import annotations

from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import SelectField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length

from .models import STATUS_LABELS
from .services import CONTENT_MAX_LENGTH, TITLE_MAX_LENGTH, TOKEN_MAX_LENGTH


class SubmissionForm(FlaskForm):
    title = StringField(
        "Report title",
        validators=[
            DataRequired(message="A title is required."),
            Length(max=TITLE_MAX_LENGTH,
                   message=f"Title must be at most {TITLE_MAX_LENGTH} characters."),
        ],
    )
    content = TextAreaField(
        "Report",
        validators=[
            DataRequired(message="The report text is required."),
            Length(max=CONTENT_MAX_LENGTH,
                   message=f"Report must be at most {CONTENT_MAX_LENGTH} characters."),
        ],
    )
    # Type and size are validated in services.read_evidence.
    evidence = FileField("Evidence (optional)")
    submit = SubmitField("Submit report")


class StatusLookupForm(FlaskForm):
    token = StringField(
        "Submission token",
        validators=[
            DataRequired(message="Enter the token from your receipt."),
            Length(max=TOKEN_MAX_LENGTH, message="That is not a valid token."),
        ],
    )
    submit = SubmitField("Check status")


class SubmissionStatusForm(FlaskForm):
    """Journalist-only: move a report through the workflow."""

    status = SelectField(
        "Status",
        choices=list(STATUS_LABELS.items()),
        validators=[DataRequired()],
    )
    submit = SubmitField("Update status")
