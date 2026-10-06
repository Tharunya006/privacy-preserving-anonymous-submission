"""Public routes for anonymous sources.

None of these views requires, reads or creates an account.  Responses are
rendered through Jinja templates (auto-escaped), never built from f-strings, so
report text cannot inject markup.
"""

from __future__ import annotations

from flask import Blueprint, redirect, render_template, request, url_for

from .forms import StatusLookupForm, SubmissionForm
from .services import EvidenceError, create_submission, find_by_token, read_evidence

bp = Blueprint("source", __name__, template_folder="templates")


@bp.route("/submit", methods=["GET", "POST"])
def submit():
    form = SubmissionForm()

    if form.validate_on_submit():
        try:
            evidence = read_evidence(form.evidence.data)
        except EvidenceError as exc:
            form.evidence.errors = list(form.evidence.errors) + [str(exc)]
            return render_template("submissions/submit.html", form=form), 400

        try:
            submission, token = create_submission(
                form.title.data, form.content.data, evidence
            )
        except ValueError as exc:
            form.content.errors = list(form.content.errors) + [str(exc)]
            return render_template("submissions/submit.html", form=form), 400

        # Rendered directly (not via redirect + flash) so the token never sits
        # in a URL or in the readable session cookie.
        return render_template(
            "submissions/receipt.html", token=token, submission=submission
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
        return render_template(
            "submissions/status.html", form=StatusLookupForm(formdata=None),
            submission=submission,
        )

    status_code = 400 if request.method == "POST" else 200
    return render_template("submissions/status.html", form=form), status_code


@bp.route("/login")
def legacy_login():
    """Phase 1's receiver login URL now leads to the Phase 2 sign-in page."""
    return redirect(url_for("auth.login"), code=301)
