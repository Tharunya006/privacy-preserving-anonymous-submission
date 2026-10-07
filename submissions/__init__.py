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


def register_submissions(app: Flask) -> Flask:
    """Attach the public source routes and register the submission tables."""
    from . import models  # noqa: F401  -- registers the tables on the shared metadata
    from .cli import scrub_evidence_command
    from .routes import bp

    app.request_class = InMemoryUploadRequest
    app.register_blueprint(bp)
    app.cli.add_command(scrub_evidence_command)
    return app
