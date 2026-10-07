"""Anonymous submission portal (Phase 1, integrated with Phase 2).

Sources submit reports and check their status here without an account, a login
or any identifying step.  The receiving side -- the journalist inbox -- lives in
the Phase 2 ``journalist`` blueprint, behind ``@journalist_required``.

Tables are defined on Phase 2's shared ``db`` so the whole system uses one
database.
"""

from __future__ import annotations

import io

from flask import Flask, Request


class InMemoryUploadRequest(Request):
    """Keep uploaded files in memory instead of spooling them to disk.

    Werkzeug writes any upload over 500 KB to a temporary file before the view
    runs, which would put the *unscrubbed* evidence on disk, however briefly.
    Holding it in memory instead is bounded by ``MAX_CONTENT_LENGTH`` (evidence
    limit + 1 MB), which Werkzeug enforces before the body is read.
    """

    def _get_file_stream(self, total_content_length, content_type, filename=None,
                         content_length=None):
        return io.BytesIO()


KEY_HELP = (
    'Generate each key with: python -c "import secrets; print(secrets.token_urlsafe(32))" '
    "and set PHASE5_ENCRYPTION_KEY and PHASE5_HMAC_KEY (two different values) in .env."
)


def register_submissions(app: Flask) -> Flask:
    """Attach the public source routes and register the submission tables.

    Also loads the Phase 5 keys.  Missing or invalid keys stop the application
    from starting at all: running without them would mean either storing
    reports in plaintext or being unable to read them, so failing loudly is
    the only safe option.
    """
    from . import models  # noqa: F401  -- registers the tables on the shared metadata
    from .cli import protect_legacy_data_command, scrub_evidence_command
    from .crypto import KeyConfigurationError, load_keys
    from .routes import bp

    try:
        keys = load_keys(app.config.get("PHASE5_ENCRYPTION_KEY"),
                         app.config.get("PHASE5_HMAC_KEY"))
    except KeyConfigurationError as exc:
        raise RuntimeError(
            f"Phase 5 key configuration error: {exc} Refusing to start. {KEY_HELP}"
        ) from exc
    # Keep the decoded keys out of app.config (which is easy to dump by accident).
    app.config.pop("PHASE5_ENCRYPTION_KEY", None)
    app.config.pop("PHASE5_HMAC_KEY", None)
    app.extensions["phase5_keys"] = keys

    app.request_class = InMemoryUploadRequest
    app.register_blueprint(bp)
    app.cli.add_command(scrub_evidence_command)
    app.cli.add_command(protect_legacy_data_command)
    return app
