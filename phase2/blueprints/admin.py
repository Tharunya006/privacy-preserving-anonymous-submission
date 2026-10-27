"""Admin-only routes.

Every view in this module is wrapped by ``@admin_required``.  The blueprint
also carries a ``before_request`` guard so a route added later without the
decorator is still protected -- defence in depth against a future mistake.
"""

from __future__ import annotations

import base64
import logging
import math

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)

from ..extensions import db
from ..forms import CreateJournalistForm, EmptyForm, ResetPasswordForm, StatusActionForm
from ..models import AuditLog, Role, Status, User, record_event
from ..security import admin_required, is_safe_redirect_target, role_required
from submissions import hash_analysis, hash_jobs, signature_analysis
from submissions import security_analysis as analysis
from submissions.crypto import MAGIC, is_sealed_text
from submissions.models import Evidence, Submission
from submissions.services import SIGNATURE_STATUSES, evidence_path, submission_counts, verify_submission_signature

from ..services import (
    create_user,
    journalist_counts,
    list_journalists,
    reset_password,
    set_status,
)

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.before_request
@role_required(Role.ADMIN)
def require_admin():
    """Blanket gate for the whole blueprint."""
    return None


def _client_ip() -> str | None:
    return request.headers.get("X-Forwarded-For", request.remote_addr)


def _get_journalist_or_404(user_id: int) -> User:
    user = db.session.get(User, user_id)
    if user is None or user.role != Role.JOURNALIST.value:
        abort(404)
    return user


@bp.route("/")
@bp.route("/dashboard")
@admin_required
def dashboard():
    counts = journalist_counts()
    recent_events = list(
        db.session.execute(
            db.select(AuditLog).order_by(AuditLog.created_at.desc()).limit(10)
        ).scalars()
    )
    pending = list_journalists(Status.PENDING.value)
    return render_template(
        "phase2/admin_dashboard.html",
        user=g.current_user,
        counts=counts,
        pending=pending,
        recent_events=recent_events,
        action_form=StatusActionForm(),
        # Counts only: admins manage accounts and never read report content.
        submission_counts=submission_counts(),
    )


@bp.route("/journalists")
@admin_required
def manage_journalists():
    status_filter = request.args.get("status", "").strip().upper() or None
    if status_filter and status_filter not in {s.value for s in Status}:
        status_filter = None
    journalists = list_journalists(status_filter)
    return render_template(
        "phase2/manage_journalists.html",
        user=g.current_user,
        journalists=journalists,
        status_filter=status_filter,
        statuses=[s.value for s in Status],
        action_form=EmptyForm(),
        counts=journalist_counts(),
    )


@bp.route("/journalists/new", methods=["GET", "POST"])
@admin_required
def add_journalist():
    form = CreateJournalistForm()

    if form.validate_on_submit():
        status = Status.AUTHORIZED if form.authorize_now.data else Status.PENDING
        try:
            user = create_user(
                form.username.data or "",
                form.password.data or "",
                role=Role.JOURNALIST,
                status=status,
                display_name=form.display_name.data,
                email=form.email.data,
                must_change_password=True,
                created_by=g.current_user,
                commit=False,
            )
            record_event(
                "journalist.created",
                actor=g.current_user,
                target=user.username,
                detail=f"status={status.value}",
                ip_address=_client_ip(),
                commit=False,
            )
            db.session.commit()
        except ValueError as exc:
            db.session.rollback()
            form.username.errors = list(form.username.errors) + [str(exc)]
            return (
                render_template("phase2/add_journalist.html", form=form, user=g.current_user),
                400,
            )

        flash(
            f"Journalist '{user.username}' created with status {user.status}. "
            "They must change the temporary password at first sign-in.",
            "success",
        )
        return redirect(url_for("admin.manage_journalists"))

    status_code = 400 if request.method == "POST" else 200
    return (
        render_template("phase2/add_journalist.html", form=form, user=g.current_user),
        status_code,
    )


@bp.route("/journalists/<int:user_id>/status", methods=["POST"])
@admin_required
def change_status(user_id: int):
    """Authorize / disable / set-pending.  POST + CSRF token required."""
    form = EmptyForm()
    if not form.validate_on_submit():
        flash("Invalid or expired request. Please try again.", "error")
        return redirect(url_for("admin.manage_journalists"))

    target = _get_journalist_or_404(user_id)
    requested = (request.form.get("status") or "").strip().upper()
    if requested not in {s.value for s in Status}:
        flash("Unknown status requested.", "error")
        return redirect(url_for("admin.manage_journalists"))

    try:
        set_status(target, requested, actor=g.current_user, ip=_client_ip())
    except ValueError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return redirect(url_for("admin.manage_journalists"))

    flash(f"'{target.username}' is now {target.status}.", "success")
    return_to = request.form.get("return_to")
    if not is_safe_redirect_target(return_to):
        return_to = url_for("admin.manage_journalists")
    return redirect(return_to)


@bp.route("/journalists/<int:user_id>", methods=["GET"])
@admin_required
def journalist_detail(user_id: int):
    target = _get_journalist_or_404(user_id)
    events = list(
        db.session.execute(
            db.select(AuditLog)
            .filter_by(target=target.username)
            .order_by(AuditLog.created_at.desc())
            .limit(20)
        ).scalars()
    )
    return render_template(
        "phase2/journalist_detail.html",
        user=g.current_user,
        target=target,
        events=events,
        action_form=EmptyForm(),
        reset_form=ResetPasswordForm(),
    )


@bp.route("/journalists/<int:user_id>/reset-password", methods=["POST"])
@admin_required
def reset_journalist_password(user_id: int):
    target = _get_journalist_or_404(user_id)
    form = ResetPasswordForm()
    if not form.validate_on_submit():
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field}: {error}", "error")
        return redirect(url_for("admin.journalist_detail", user_id=user_id))

    reset_password(
        target,
        form.new_password.data or "",
        actor=g.current_user,
        ip=_client_ip(),
    )
    flash(
        f"Temporary password set for '{target.username}'. "
        "They must change it at next sign-in.",
        "success",
    )
    return redirect(url_for("admin.journalist_detail", user_id=user_id))


@bp.route("/audit")
@admin_required
def audit_log():
    events = list(
        db.session.execute(
            db.select(AuditLog).order_by(AuditLog.created_at.desc()).limit(100)
        ).scalars()
    )
    return render_template("phase2/audit_log.html", user=g.current_user, events=events)


# ---------------------------------------------------------------------------
# Security analysis (admin-only, ciphertext-only for real reports)
#
# These views read stored values and stored evidence *bytes* and parse the
# protected-package format.  They never call the decryption functions and never
# receive a key: admins see ciphertext, never report content.  Pre-Phase-5
# records that are still plaintext are withheld.  Metrics that need plaintext
# run on synthetic data with throwaway keys (``analysis_experiments``).
# ---------------------------------------------------------------------------
log = logging.getLogger(__name__)


def _stored_evidence_bytes(evidence: Evidence) -> bytes | None:
    """The file exactly as stored on disk (an encrypted package); never decrypted."""
    path = evidence_path(evidence)
    if path is None or not path.is_file():
        return None
    return path.read_bytes()


def _evidence_state(evidence: Evidence) -> str:
    path = evidence_path(evidence)
    if path is None or not path.is_file():
        return "missing"
    with path.open("rb") as handle:
        return "encrypted" if handle.read(len(MAGIC)) == MAGIC else "legacy"


def _audit_analysis_view(target: str, detail: str | None = None) -> None:
    # Only the page that was opened -- never ciphertext, sizes or content.
    record_event("analysis.viewed", actor=g.current_user, target=target, detail=detail,
                 ip_address=_client_ip())


def _attempt(label: str, fn, *args, **kwargs):
    """Run one analysis step; a failure is shown on the page, not raised."""
    try:
        return fn(*args, **kwargs), None
    except Exception:  # pragma: no cover - defensive: the page must still render
        log.exception("security analysis step failed: %s", label)
        return None, f"{label} could not be computed."


# Evidence type -> image format for the matched scrubbing comparison (MSE/PSNR/SSIM).
_EVIDENCE_IMAGE_FORMATS = {"png": "PNG", "gif": "GIF", "jpg": "JPEG", "jpeg": "JPEG", "webp": "WEBP"}


def _signature(submission: Submission) -> dict:
    """Phase 7 signature status (public key only).  An unexpected failure is
    reported as "error" -- never as valid."""
    result, _ = _attempt(f"Signature verification for {submission.reference}",
                         verify_submission_signature, submission)
    result = result or {"status": "error", "key_id": None, "signed_at": None, "algorithm": None,
                        "manifest_version": None, "reason": "The signature could not be checked."}
    result["label"] = SIGNATURE_STATUSES[result["status"]]
    return result


def _evidence_picture_mode(evidence: Evidence) -> str:
    """How an evidence file's ciphertext is drawn: image files as RGB colour
    noise (3 bytes per pixel), text files as grayscale (1 byte per pixel).

    Chosen from the file type alone -- nothing is decrypted.  The ciphertext
    carries no colour from the original (any tint would be a leak), so a
    grayscale photo is drawn as colour noise too."""
    return "RGB" if evidence.extension in _EVIDENCE_IMAGE_FORMATS else "L"


def _experiment_side(size_bytes: int) -> int:
    """Synthetic test image with about as many pixels as the file has bytes,
    kept between 64x64 and 256x256 so the page stays fast."""
    return max(64, min(analysis.CIPHER_IMAGE_SIDE, math.isqrt(max(size_bytes, 1))))


def _stored_items(submission: Submission) -> list[dict]:
    """Every stored item of a report -- the single reader used by all analysis
    pages.  For encrypted items: the envelope (exact stored package bytes) and
    its parsed parts.  Legacy (unencrypted) items are identified by their format
    only and never processed.  No key is used and nothing is decrypted."""
    items = []
    for key, label, value in (("title", "Title", submission.title_sealed),
                              ("content", "Report text", submission.content_sealed)):
        if not is_sealed_text(value):
            items.append({"key": key, "label": label, "kind": "text", "state": "legacy",
                          "envelope": None, "parsed": None, "record_time": submission.created_at})
            continue
        envelope = analysis.stored_text_envelope(value)
        parsed = analysis.parse_package(envelope) if envelope else None
        items.append({"key": key, "label": label, "kind": "text",
                      "state": "encrypted" if parsed else "malformed",
                      "envelope": envelope if parsed else None, "parsed": parsed,
                      "record_time": submission.created_at})
    for evidence in submission.evidence:
        raw = _stored_evidence_bytes(evidence)
        if raw is None:
            state, parsed = "missing", None
        elif not raw.startswith(MAGIC):
            state, parsed = "legacy", None          # unencrypted: not processed
        else:
            parsed = analysis.parse_package(raw)
            state = "encrypted" if parsed is not None else "malformed"
        items.append({"key": f"evidence-{evidence.id}", "label": f"Evidence #{evidence.id}", "kind": "evidence",
                      "evidence": evidence, "state": state, "envelope": raw if parsed else None,
                      "parsed": parsed, "record_time": evidence.created_at})
    return items


def _overview_entropy(submission: Submission) -> tuple[float | None, list[float | None]]:
    """Key metric for the overview: entropy of the stored ciphertext payload of
    the report text and of each evidence file (first MAX_STAT_BYTES).  Legacy,
    missing or malformed items give ``None``."""
    items = _stored_items(submission)

    def payload_entropy(item):
        parsed = item["parsed"]
        return (analysis.shannon_entropy(parsed.ciphertext[:analysis.MAX_STAT_BYTES])
                if item["state"] == "encrypted" and parsed.ciphertext else None)

    content = next(i for i in items if i["key"] == "content")
    return payload_entropy(content), [payload_entropy(i) for i in items if i["kind"] == "evidence"]


def _representations(submission: Submission, known_stats: dict | None = None) -> list[dict]:
    rows = []
    for item in _stored_items(submission):
        row = {"key": item["key"], "label": item["label"], "state": item["state"]}
        if item["state"] == "encrypted":
            row.update(analysis.stored_representations(item["envelope"], (known_stats or {}).get(item["key"])))
        rows.append(row)
    return rows


@bp.route("/security-analysis")
@admin_required
def analysis_overview():
    rows = []
    for submission in db.session.execute(
        db.select(Submission).order_by(Submission.id.desc())
    ).scalars():
        entropy, _ = _attempt(f"Overview metrics for {submission.reference}", _overview_entropy, submission)
        text_entropy, evidence_entropy = entropy or (None, [None] * len(submission.evidence))
        rows.append({
            "submission": submission,
            "text_state": "encrypted" if is_sealed_text(submission.title_sealed)
            and is_sealed_text(submission.content_sealed) else "legacy",
            "evidence_states": [_evidence_state(e) for e in submission.evidence],
            "text_entropy": text_entropy,
            "evidence_entropy": evidence_entropy,
            "signature": _signature(submission),
        })
    _audit_analysis_view("overview")
    return render_template("phase2/analysis_overview.html", user=g.current_user, rows=rows,
                           counts=submission_counts())


@bp.route("/security-analysis/submissions/<int:submission_id>")
@admin_required
def analysis_report(submission_id: int):
    submission = db.session.get(Submission, submission_id)
    if submission is None:
        abort(404)
    errors = []
    title, err = _attempt("Title analysis", analysis.analyse_stored_text, submission.title_sealed)
    errors += [err] if err else []
    content, err = _attempt("Report analysis", analysis.analyse_stored_text, submission.content_sealed)
    errors += [err] if err else []
    evidence = []
    for item in submission.evidence:
        result, err = _attempt(f"Evidence #{item.id} analysis", analysis.analyse_stored_file,
                               _stored_evidence_bytes(item))
        errors += [err] if err else []
        result = result or {"state": "error"}
        if result["state"] == "encrypted":
            # Adjacent-pixel correlation of exactly the cipher-image shown on the page
            # (per colour channel and averaged for RGB pictures).
            ciphertext = result["parsed"].ciphertext
            mode = _evidence_picture_mode(item)
            channels = 3 if mode == "RGB" else 1
            side = min(analysis.CIPHER_IMAGE_SIDE, math.isqrt(len(ciphertext) // channels))
            used = side * side * channels
            correlation = None
            if side >= 2:
                per_channel = analysis._channel_correlations(ciphertext[:used], side, side, channels)
                correlation = analysis._mean_correlation(per_channel)
            result["cipher_image"] = {"side": side, "bytes_used": used, "mode": mode,
                                      "correlation": correlation}
        evidence.append((item, result))

    # Metrics that need the original data or a key (avalanche, key sensitivity,
    # NPCR/UACI, MSE/PSNR/SSIM): a controlled experiment on synthetic data of the
    # same size, encrypted with temporary keys.  The page labels these as
    # experiments -- never as measurements of this report.  No real data is
    # decrypted and no production key is used.
    for label, result in (("Title", title), ("Report text", content)):
        if result and result.get("state") == "encrypted":
            result["experiment"], err = _attempt(
                f"{label} experiment", analysis.text_experiments,
                trials=16, sample_bytes=len(result["parsed"].ciphertext))
            errors += [err] if err else []
    for item, result in evidence:
        if result.get("state") == "encrypted":
            image_format = _EVIDENCE_IMAGE_FORMATS.get(item.extension)
            result["experiment_is_image"] = image_format is not None
            result["experiment"], err = _attempt(
                f"Evidence #{item.id} experiment", analysis.image_experiments,
                side=_experiment_side(item.size_bytes),
                scrub_formats=(image_format,) if image_format else ())
            errors += [err] if err else []

    # Stored representations of every item: envelope and payload, each with size,
    # SHA-256, histogram and entropy.  Payload statistics already computed above
    # are reused.  Legacy items are listed by state only.
    known_stats = {"title": (title or {}).get("stats"), "content": (content or {}).get("stats")}
    known_stats.update({f"evidence-{item.id}": result.get("stats") for item, result in evidence})
    representations, err = _attempt("Stored representations", _representations, submission, known_stats)
    errors += [err] if err else []

    # Performance on synthetic data of the same sizes (no real data is decrypted).
    sizes = []
    for label, result in (("title", title), ("report text", content)):
        if result and result.get("state") == "encrypted":
            sizes.append((f"{label} ({len(result['parsed'].ciphertext):,} B)",
                          len(result["parsed"].ciphertext)))
    for item, result in evidence:
        if result.get("state") == "encrypted":
            sizes.append((f"evidence #{item.id} ({item.size_bytes:,} B)", item.size_bytes))
    perf, err = _attempt("Performance measurement", analysis.performance, sizes)
    errors += [err] if err else []

    _audit_analysis_view(submission.reference)
    return render_template("phase2/analysis_report.html", user=g.current_user,
                           submission=submission, title=title, content=content,
                           evidence=evidence, performance=perf or [], errors=errors,
                           representations=representations or [], signature=_signature(submission))


@bp.route("/security-analysis/submissions/<int:submission_id>/evidence/<int:evidence_id>/cipher.png")
@admin_required
def analysis_cipher_image(submission_id: int, evidence_id: int):
    """A picture of the stored encrypted bytes: up to 256x256 pixels, colour
    noise for image files (3 bytes per pixel), grayscale for text files."""
    evidence = db.session.get(Evidence, evidence_id)
    if evidence is None or evidence.submission_id != submission_id:
        abort(404)
    raw = _stored_evidence_bytes(evidence)
    parsed = analysis.parse_package(raw) if raw else None
    if parsed is None:  # missing, legacy plaintext or malformed: nothing is shown
        abort(404)
    try:
        png, _, _ = analysis.cipher_image_png(parsed.ciphertext, mode=_evidence_picture_mode(evidence))
    except ValueError:  # empty ciphertext: nothing to draw
        abort(404)
    return Response(png, mimetype="image/png")


@bp.route("/security-analysis/experiments")
@admin_required
def analysis_experiments():
    errors = []
    text, err = _attempt("Text experiments", analysis.text_experiments)
    errors += [err] if err else []
    image, err = _attempt("Image experiments", analysis.image_experiments)
    errors += [err] if err else []
    perf, err = _attempt("Performance measurement", analysis.performance, [
        ("title-sized text (200 B)", 200), ("max report text (20 KB)", 20_000),
        ("1 MB", 1_000_000), ("max evidence (10 MB)", 10_000_000)])
    errors += [err] if err else []
    signature, err = _attempt("Signature experiment", signature_analysis.rsa_pss_experiment)
    errors += [err] if err else []
    images = {}
    if image:
        images = {name: "data:image/png;base64," + base64.b64encode(image[key]).decode()
                  for name, key in (("plain", "plain_png"), ("cipher", "cipher_png"))}
    _audit_analysis_view("experiments")
    return render_template("phase2/analysis_experiments.html", user=g.current_user,
                           text=text, image=image, images=images, performance=perf or [],
                           signature=signature, errors=errors)


@bp.route("/security-analysis/hashing")
@admin_required
def analysis_hashing():
    """SHA-256 hashing analysis on SYNTHETIC messages only: correlation tests and
    bounded preimage / second-preimage toys.  No stored hash, token, HMAC, tag or
    key is read; the database is not queried."""
    errors = []
    results = {}
    for key, label, fn in (
        ("sac", "Strict avalanche test", hash_analysis.strict_avalanche),
        ("modifications", "Modified-message analysis", hash_analysis.modification_analysis),
        ("preimage", "Preimage toy", hash_analysis.preimage_toy),
        ("second_preimage", "Second-preimage toy", hash_analysis.second_preimage_toy),
        ("restricted", "Restricted candidate space", hash_analysis.restricted_space_demo),
    ):
        results[key], err = _attempt(label, fn)
        errors += [err] if err else []
    reports = [{"submission": s, "items": _item_states(s)} for s in db.session.execute(
        db.select(Submission).order_by(Submission.id.desc())).scalars()]
    _audit_analysis_view("hashing")
    return render_template("phase2/analysis_hashing.html", user=g.current_user, errors=errors,
                           seed=hash_analysis.DEFAULT_SEED, reports=reports, **results)


# ---------------------------------------------------------------------------
# Per-report SHA-256 hashing analysis (admin only)
#
# Input: each item's stored AES-GCM ciphertext BODY (header, nonce, GCM tag and
# HMAC removed).  Never plaintext, never a key.  Legacy (unencrypted) items are
# listed but not processed at all.  No digest of stored data is shown, and the
# authentication values (GCM tag, HMAC) are reported as present/length only.
# ---------------------------------------------------------------------------
_INTEGRITY_EVENTS = ("submission.integrity_failed", "evidence.integrity_failed")


def _item_states(submission: Submission) -> list[dict]:
    """Cheap state of every stored item (for the report list): no parsing of files."""
    items = [{"label": label, "state": "encrypted" if is_sealed_text(value) else "legacy"}
             for label, value in (("Title", submission.title_sealed), ("Report text", submission.content_sealed))]
    items += [{"label": f"Evidence #{e.id}", "state": _evidence_state(e)} for e in submission.evidence]
    return items


@bp.route("/security-analysis/submissions/<int:submission_id>/hashing")
@admin_required
def analysis_report_hashing(submission_id: int):
    submission = db.session.get(Submission, submission_id)
    if submission is None:
        abort(404)
    errors = []
    items, err = _attempt("Reading the stored items", _stored_items, submission)
    errors += [err] if err else []
    for item in items or []:
        parsed = item.pop("parsed")
        if item["state"] != "encrypted":
            continue
        ciphertext = parsed.ciphertext
        item["structure"] = {
            "version": parsed.version, "ciphertext_bytes": len(ciphertext),
            "tag_bytes": len(parsed.tag), "mac_bytes": len(parsed.mac), "package_bytes": parsed.package_size,
            "time_matches_record": parsed.timestamp == item["record_time"],
        }
        if not ciphertext:
            item["state"] = "empty"
            continue
        item["avalanche"], err = _attempt(f"{item['label']} avalanche test", hash_analysis.input_avalanche, ciphertext)
        errors += [err] if err else []
        item["modifications"], err = _attempt(f"{item['label']} modified-message analysis",
                                              hash_analysis.sized_modification_analysis, len(ciphertext))
        errors += [err] if err else []
    history = db.session.execute(
        db.select(AuditLog).where(AuditLog.target == submission.reference,
                                  AuditLog.action.in_(_INTEGRITY_EVENTS))
        .order_by(AuditLog.created_at.desc())).scalars().all()
    _audit_analysis_view(submission.reference, detail="hashing")
    return render_template("phase2/analysis_report_hashing.html", user=g.current_user, submission=submission,
                           items=items or [], history=history, errors=errors,
                           jobs=_hash_jobs().jobs_for(submission.reference),
                           experiment_items=[(i["key"], i["label"]) for i in items or [] if i["state"] == "encrypted"],
                           allowed_bits=hash_jobs.ALLOWED_BITS, kinds=hash_jobs.KINDS, job_limits={
                               "budget_factor": hash_jobs.BUDGET_FACTOR, "time_limit": hash_jobs.SEARCH_TIME_LIMIT,
                               "wall_timeout": hash_jobs.WALL_TIMEOUT, "max_pending": hash_jobs.MAX_PENDING,
                               "cooldown": hash_jobs.COOLDOWN},
                           alpha=hash_analysis.ALPHA, flips=256, input_cap=hash_analysis.INPUT_CAP,
                           sized_cap=hash_analysis.SIZED_CAP)


def _hash_jobs() -> hash_jobs.HashJobManager:
    """One bounded experiment queue per application instance."""
    return current_app.extensions.setdefault("hash_jobs", hash_jobs.HashJobManager())


@bp.route("/security-analysis/submissions/<int:submission_id>/hashing/experiments", methods=["POST"])
@admin_required
def analysis_hash_experiment(submission_id: int):
    """Enqueue a bounded truncated-SHA-256 experiment on one stored ENCRYPTED
    representation of this report.  POST + CSRF only.  The search runs in the
    isolated worker process, never in this request.  The bytes are chosen here
    from the stored item -- the request cannot supply its own."""
    submission = db.session.get(Submission, submission_id)
    if submission is None:
        abort(404)
    back = redirect(url_for("admin.analysis_report_hashing", submission_id=submission_id) + "#experiments")
    item_key = request.form.get("item", "")
    representation = request.form.get("representation", "")
    kind = request.form.get("kind", "")
    try:
        bits = int(request.form.get("bits", ""))
    except ValueError:
        bits = -1
    if (kind not in hash_jobs.KINDS or bits not in hash_jobs.ALLOWED_BITS
            or representation not in ("envelope", "payload")):
        flash("Invalid experiment settings.", "error")
        return back
    item = next((i for i in _stored_items(submission) if i["key"] == item_key), None)
    if item is None or item["state"] != "encrypted":
        flash("Experiments run only on encrypted items of this report.", "error")
        return back
    data = item["envelope"] if representation == "envelope" else item["parsed"].ciphertext
    try:
        _hash_jobs().submit(admin_id=g.current_user.id, reference=submission.reference, item_key=item_key,
                            item_label=item["label"], representation=representation, data=data,
                            kind=kind, bits=bits)
    except hash_jobs.JobRejected as exc:
        flash(str(exc), "warn")
        return back
    except ValueError:
        flash("This item has no bytes to analyse.", "error")
        return back
    record_event("analysis.hash_experiment", actor=g.current_user, target=submission.reference,
                 detail=f"{item_key} {representation} {kind} t={bits}", ip_address=_client_ip())
    flash("Experiment queued. It runs in a separate worker; refresh this page for the result.", "success")
    return back
