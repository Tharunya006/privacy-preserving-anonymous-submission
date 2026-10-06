"""Journalist / Authorized Receiver routes.

Only a user whose role is JOURNALIST *and* whose status is AUTHORIZED reaches
these views.  PENDING and DISABLED accounts are stopped at login, and an account
disabled mid-session is stopped on its next request by ``load_current_user``.

This is also where anonymous submissions are read (Phase 4): the inbox, the
report view, the Submitted -> Under review -> Closed workflow and evidence
downloads.  Opening a report, changing its status and downloading evidence are
all written to the audit log -- without report content, tokens or file data.
"""

from __future__ import annotations

from flask import (
    Blueprint,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)

from submissions.forms import SubmissionStatusForm
from submissions.models import Evidence, SubmissionStatus
from submissions.services import (
    StatusTransitionError,
    evidence_dir,
    evidence_path,
    get_submission,
    latest_submissions,
    next_statuses,
    paginate_submissions,
    status_history,
    submission_counts,
    update_status,
)

from ..extensions import db
from ..forms import EmptyForm
from ..models import Role, record_event
from ..security import journalist_required, role_required

bp = Blueprint("journalist", __name__, url_prefix="/journalist")


@bp.before_request
@role_required(Role.JOURNALIST)
def require_journalist():
    """Blanket gate for the whole blueprint."""
    return None


def _client_ip() -> str | None:
    return request.headers.get("X-Forwarded-For", request.remote_addr)


def _get_submission_or_404(submission_id: int):
    submission = get_submission(submission_id)
    if submission is None:
        abort(404)
    return submission


@bp.route("/")
@bp.route("/dashboard")
@journalist_required
def dashboard():
    return render_template(
        "phase2/journalist_dashboard.html",
        user=g.current_user,
        logout_form=EmptyForm(),
        submission_counts=submission_counts(),
        new_submissions=latest_submissions(SubmissionStatus.SUBMITTED.value),
    )


@bp.route("/profile")
@journalist_required
def profile():
    return render_template("phase2/journalist_profile.html", user=g.current_user)


@bp.route("/inbox")
@journalist_required
def inbox():
    """The anonymous submission queue, newest first, filtered and paginated.

    Unknown filter values and page numbers fall back to safe defaults; they are
    never interpolated into SQL.
    """
    statuses = [s.value for s in SubmissionStatus]
    status_filter = request.args.get("status", "").strip().upper() or None
    if status_filter not in statuses:
        status_filter = None
    page = request.args.get("page", 1, type=int) or 1
    pagination = paginate_submissions(status_filter, page=page)
    return render_template(
        "phase2/journalist_inbox.html",
        user=g.current_user,
        submissions=pagination.items,
        pagination=pagination,
        status_filter=status_filter,
        statuses=[SubmissionStatus(s) for s in statuses],
        counts=submission_counts(),
    )


@bp.route("/submissions/<int:submission_id>")
@journalist_required
def submission_detail(submission_id: int):
    submission = _get_submission_or_404(submission_id)
    record_event(
        "submission.viewed",
        actor=g.current_user,
        target=submission.reference,
        ip_address=_client_ip(),
    )
    return render_template(
        "phase2/journalist_submission.html",
        user=g.current_user,
        submission=submission,
        status_form=SubmissionStatusForm(),
        next_statuses=next_statuses(submission),
        history=status_history(submission),
    )


@bp.route("/submissions/<int:submission_id>/status", methods=["POST"])
@journalist_required
def update_submission_status(submission_id: int):
    """POST + CSRF token required."""
    submission = _get_submission_or_404(submission_id)
    form = SubmissionStatusForm()
    if not form.validate_on_submit():
        flash("Invalid or expired request. Please try again.", "error")
        return redirect(url_for("journalist.submission_detail", submission_id=submission_id))

    try:
        update_status(submission, form.status.data, actor=g.current_user, ip=_client_ip())
    except StatusTransitionError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return redirect(url_for("journalist.submission_detail", submission_id=submission_id))

    flash(f"Submission #{submission.id} is now {submission.status_label}.", "success")
    return redirect(url_for("journalist.submission_detail", submission_id=submission_id))


@bp.route("/submissions/<int:submission_id>/evidence/<int:evidence_id>")
@journalist_required
def download_evidence(submission_id: int, evidence_id: int):
    """Evidence is always downloaded, never rendered inline in the browser."""
    evidence = db.session.get(Evidence, evidence_id)
    if evidence is None or evidence.submission_id != submission_id:
        abort(404)
    path = evidence_path(evidence)
    if path is None or not path.is_file():
        abort(404)

    record_event(
        "evidence.downloaded",
        actor=g.current_user,
        target=evidence.submission.reference,
        detail=f"evidence={evidence.id}",
        ip_address=_client_ip(),
    )
    # send_from_directory refuses any name that escapes the evidence directory.
    return send_from_directory(
        evidence_dir(),
        evidence.stored_name,
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=evidence.download_name,
        max_age=0,
    )
