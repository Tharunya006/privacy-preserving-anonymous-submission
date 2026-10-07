"""CLI for data stored before Phase 3 (metadata scrubbing) or Phase 5 (encryption).

Files written before Phase 5 are plain bytes, not protected packages; both
commands recognise them by their missing package header ("malformed").  Normal
request handling never accepts such data -- only these operator commands do,
and only to clean and encrypt it.
"""

from __future__ import annotations

from pathlib import Path

import click
from flask.cli import with_appcontext

from phase2.extensions import db
from phase2.models import record_event

from .crypto import IntegrityCheckError, is_sealed_text
from .models import Evidence, Submission
from .scrubber import (
    IMAGE_FORMATS,
    SCRUBBABLE_EXTENSIONS,
    ScrubError,
    assert_image_is_clean,
    clean_text,
    scrub_evidence,
)
from .services import (
    evidence_path,
    read_evidence_file,
    seal_submission_fields,
    write_evidence_file,
)


def _load_evidence(evidence: Evidence) -> tuple[bytes, bool] | str:
    """``(plaintext, is_legacy)``, or a reason string if it cannot be used."""
    path = evidence_path(evidence)
    if path is None or not path.is_file():
        return "file missing"
    try:
        return read_evidence_file(evidence), False
    except IntegrityCheckError as exc:
        if exc.reason == "malformed":  # no package header: stored before Phase 5
            return path.read_bytes(), True
        return f"failed its integrity check ({exc.reason})"


def _replace_evidence_file(evidence: Evidence, extension: str, data: bytes,
                           action: str) -> None:
    """Seal ``data`` under a new name, point the row at it, delete the old file."""
    old_path = evidence_path(evidence)
    new_path = write_evidence_file(extension, data, evidence.created_at)
    try:
        evidence.stored_name = new_path.name
        evidence.extension = extension
        evidence.size_bytes = len(data)
        record_event(action, target=evidence.submission.reference,
                     detail=f"evidence={evidence.id}", commit=False)
        db.session.commit()
    except Exception:
        db.session.rollback()
        new_path.unlink(missing_ok=True)
        raise
    if old_path is not None:
        Path(old_path).unlink(missing_ok=True)


def _is_clean(extension: str, data: bytes) -> bool:
    try:
        if extension in IMAGE_FORMATS:
            assert_image_is_clean(data)
            return True
        return clean_text(data) == data
    except ScrubError:
        return False


@click.command("scrub-evidence")
@click.option("--dry-run", is_flag=True, help="Report what would change; write nothing.")
@with_appcontext
def scrub_evidence_command(dry_run: bool) -> None:
    """Remove metadata from stored evidence (Phase 3), e.g. pre-Phase-3 uploads.

    Each file that still carries metadata is cleaned, encrypted (Phase 5) under
    a new random name, and the old file is deleted.  Files that cannot be
    cleaned (e.g. PDF or office documents) are only reported.
    """
    cleaned = unchanged = skipped = 0
    for evidence in db.session.execute(db.select(Evidence).order_by(Evidence.id)).scalars():
        label = f"evidence #{evidence.id} (submission #{evidence.submission_id})"
        loaded = _load_evidence(evidence)
        if isinstance(loaded, str):
            click.echo(f"{label}: {loaded} - skipped")
            skipped += 1
            continue
        data, _legacy = loaded
        if evidence.extension not in SCRUBBABLE_EXTENSIONS:
            click.echo(f"{label}: .{evidence.extension} cannot be cleaned - review it manually")
            skipped += 1
            continue
        if _is_clean(evidence.extension, data):
            # Re-encoding a clean JPEG would only lose quality on every run.
            unchanged += 1
            continue
        try:
            extension, clean = scrub_evidence(evidence.extension, data)
        except ScrubError as exc:
            click.echo(f"{label}: {exc} - skipped")
            skipped += 1
            continue
        if dry_run:
            click.echo(f"{label}: would be cleaned")
        else:
            _replace_evidence_file(evidence, extension, clean, "evidence.scrubbed")
            click.echo(f"{label}: cleaned")
        cleaned += 1

    verb = "would be cleaned" if dry_run else "cleaned"
    click.echo(f"{cleaned} {verb}, {unchanged} already clean, {skipped} skipped.")


@click.command("protect-legacy-data")
@click.option("--dry-run", is_flag=True, help="Report what would change; write nothing.")
@with_appcontext
def protect_legacy_data_command(dry_run: bool) -> None:
    """Encrypt report text and evidence stored before Phase 5.

    Legacy images and text are scrubbed of metadata first.  Legacy files that
    cannot be scrubbed (e.g. PDFs) are still encrypted, with a warning, because
    encrypted is strictly better than plaintext.  Safe to re-run.
    """
    reports = files = warnings = 0

    for submission in db.session.execute(db.select(Submission).order_by(Submission.id)).scalars():
        title_done = is_sealed_text(submission.title_sealed)
        content_done = is_sealed_text(submission.content_sealed)
        if title_done and content_done:
            continue
        label = f"submission #{submission.id}"
        if title_done != content_done:
            click.echo(f"{label}: partly protected - inconsistent, review it manually")
            warnings += 1
            continue
        reports += 1
        if dry_run:
            click.echo(f"{label}: report text would be encrypted")
            continue
        seal_submission_fields(submission, submission.title_sealed or "",
                               submission.content_sealed or "")
        record_event("legacy.protected", target=submission.reference,
                     detail="report text", commit=False)
        db.session.commit()
        click.echo(f"{label}: report text encrypted")

    for evidence in db.session.execute(db.select(Evidence).order_by(Evidence.id)).scalars():
        label = f"evidence #{evidence.id} (submission #{evidence.submission_id})"
        loaded = _load_evidence(evidence)
        if isinstance(loaded, str):
            if loaded != "file missing":
                click.echo(f"{label}: {loaded} - skipped")
                warnings += 1
            continue
        data, legacy = loaded
        if not legacy:
            continue
        extension = evidence.extension
        note = ""
        if extension in SCRUBBABLE_EXTENSIONS:
            try:
                extension, data = scrub_evidence(extension, data)
            except ScrubError as exc:
                note = f" (not scrubbed: {exc})"
                warnings += 1
        else:
            note = f" (.{extension}: metadata NOT removed - review it manually)"
            warnings += 1
        files += 1
        if dry_run:
            click.echo(f"{label}: would be encrypted{note}")
            continue
        _replace_evidence_file(evidence, extension, data, "legacy.protected")
        click.echo(f"{label}: encrypted{note}")

    verb = "would be encrypted" if dry_run else "encrypted"
    click.echo(f"{reports} report(s) and {files} evidence file(s) {verb}; {warnings} warning(s).")
