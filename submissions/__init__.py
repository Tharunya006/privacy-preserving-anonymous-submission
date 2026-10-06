"""Anonymous submission portal (Phase 1, integrated with Phase 2).

Sources submit reports and check their status here without an account, a login
or any identifying step.  The receiving side -- the journalist inbox -- lives in
the Phase 2 ``journalist`` blueprint, behind ``@journalist_required``.

Tables are defined on Phase 2's shared ``db`` so the whole system uses one
database.
"""

from __future__ import annotations

from flask import Flask


def register_submissions(app: Flask) -> Flask:
    """Attach the public source routes and register the submission tables."""
    from . import models  # noqa: F401  -- registers the tables on the shared metadata
    from .routes import bp

    app.register_blueprint(bp)
    return app
