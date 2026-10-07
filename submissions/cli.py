"""CLI for evidence that was stored before metadata scrubbing existed."""

from __future__ import annotations

import click
from flask.cli import with_appcontext

from phase2.extensions import db
from phase2.models import record_event

from .models import Evidence
from .scrubber import (
    IMAGE_FORMATS,
    SCRUBBABLE_EXTENSIONS,
    ScrubError,
    assert_image_is_clean,
    scrub_evidence,
)
from .services import _write_evidence_file, evidence_path


@click.command("scrub-evidence")
@click.option("--dry-run", is_flag=True, help="Report what would change; write nothing.")
@with_appcontext
def scrub_evidence_command(dry_run: bool) -> None:
    """Remove metadata from evidence stored before Phase 3 scrubbing.

    Each cleanable file is rewritten under a new random name and the old file is
    deleted.  Files that cannot be cleaned (e.g. PDF or office documents) are
    only reported -- nothing is deleted automatically.
    """
    cleaned = unchanged = skipped = 0
    for evidence in db.session.execute(db.select(Evidence).order_by(Evidence.id)).scalars():
        label = f"evidence #{evidence.id} (submission #{evidence.submission_id})"
        path = evidence_path(evidence)
        if path is None or not path.is_file():
            click.echo(f"{label}: file missing - skipped")
            skipped += 1
            continue
        if evidence.extension not in SCRUBBABLE_EXTENSIONS:
            click.echo(f"{label}: .{evidence.extension} cannot be cleaned - review it manually")
            skipped += 1
            continue

        original = path.read_bytes()
        if evidence.extension in IMAGE_FORMATS and _is_clean_image(original):
            # Re-encoding a clean JPEG would only lose quality on every run.
            unchanged += 1
            continue
        try:
            extension, clean = scrub_evidence(evidence.extension, original)
        except ScrubError as exc:
            click.echo(f"{label}: {exc} - skipped")
            skipped += 1
            continue
        if clean == original:
            unchanged += 1
            continue
        if dry_run:
            click.echo(f"{label}: would be cleaned")
            cleaned += 1
            continue

        new_path = _write_evidence_file(extension, clean)
        try:
            evidence.stored_name = new_path.name
            evidence.extension = extension
            evidence.size_bytes = len(clean)
            record_event(
                "evidence.scrubbed",
                target=evidence.submission.reference,
                detail=f"evidence={evidence.id}",
                commit=False,
            )
            db.session.commit()
        except Exception:
            db.session.rollback()
            new_path.unlink(missing_ok=True)
            raise
        path.unlink(missing_ok=True)
        click.echo(f"{label}: cleaned")
        cleaned += 1

    verb = "would be cleaned" if dry_run else "cleaned"
    click.echo(f"{cleaned} {verb}, {unchanged} already clean, {skipped} skipped.")


def _is_clean_image(data: bytes) -> bool:
    try:
        assert_image_is_clean(data)
    except ScrubError:
        return False
    return True
