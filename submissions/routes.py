"""Public routes for anonymous sources.

None of these views requires, reads or creates an account.  Responses are
rendered through Jinja templates (auto-escaped), never built from f-strings, so
report text cannot inject markup.
"""

from __future__ import annotations

from flask import Blueprint, current_app, redirect, render_template, request, url_for
from phase2.models import record_event
from phase2.socket_events import notify_new_submission

from .forms import StatusLookupForm, SubmissionForm
from .signing import SigningFailed, SigningUnavailable
from .services import (
    EvidenceError,
    ProtectionError,
    create_submission,
    find_by_token,
    open_title,
    read_evidence,
)

bp = Blueprint("source", __name__, template_folder="templates")


@bp.route("/submit", methods=["GET", "POST"])
def submit():
    form = SubmissionForm()

    if form.validate_on_submit():
        try:
            evidence = read_evidence(form.evidence.data)
            # Metadata is scrubbed inside create_submission, before storage.
            submission, token = create_submission(
                form.title.data, form.content.data, evidence
            )
        except (SigningUnavailable, SigningFailed):
            # Phase 7: every accepted report must be signed.  Nothing was
            # stored; the reason is logged server-side, not shown.
            current_app.logger.warning("Submission refused: server signing is unavailable.")
            return render_template("submissions/submit.html", form=form, unavailable=True), 503
        except EvidenceError as exc:
            form.evidence.errors = list(form.evidence.errors) + [str(exc)]
            return render_template("submissions/submit.html", form=form), 400
        except ValueError as exc:
            form.content.errors = list(form.content.errors) + [str(exc)]
            return render_template("submissions/submit.html", form=form), 400

        # Phase 6: content-free real-time notice to authorized journalists.
        # Sent only after the submission is committed; it cannot fail the request.
        notify_new_submission()

        # Rendered directly (not via redirect + flash) so the token never sits
        # in a URL or in the readable session cookie.  The title shown is the
        # one just typed, still in memory -- the stored copy is encrypted.
        return render_template(
            "submissions/receipt.html", token=token, submission=submission,
            title=form.title.data.strip(),
        )

    status_code = 400 if request.method == "POST" else 200
    return render_template("submissions/submit.html", form=form), status_code


@bp.route("/status", methods=["GET", "POST"])
def status():
    """Token lookup.  POST keeps the token out of URLs and server logs."""
    form = StatusLookupForm()

    if form.validate_on_submit():
        submission = find_by_token(form.token.data)
        if submission is None:
            return (
                render_template(
                    "submissions/status.html", form=StatusLookupForm(formdata=None),
                    not_found=True,
                ),
                404,
            )
        try:
            title = open_title(submission)  # HMAC + timestamp verified, then decrypted
        except ProtectionError as exc:
            # Integrity failure: show the status, never unverified data.  Audited
            # without any source identifier (no IP, no actor).
            record_event("submission.integrity_failed", target=submission.reference,
                         detail=f"source status lookup: {getattr(exc, 'reason', 'error')}")
            title = None
        return render_template(
            "submissions/status.html", form=StatusLookupForm(formdata=None),
            submission=submission, title=title,
        )

    status_code = 400 if request.method == "POST" else 200
    return render_template("submissions/status.html", form=form), status_code


@bp.route("/login")
def legacy_login():
    """Phase 1's receiver login URL now leads to the Phase 2 sign-in page."""
    return redirect(url_for("auth.login"), code=301)
