#!/usr/bin/env python3
"""Entry point for the Privacy Preserving Anonymous Submission System.

One Flask application, one database: the Phase 1 anonymous submission portal
(``submissions`` package) and the Phase 2 authentication, RBAC and dashboards
(``phase2`` package) are assembled by ``phase2.create_app``.

Usage
-----
    flask --app app init-db
    flask --app app create-admin --username admin
    python app.py                   # or: flask --app app run --port 5001
"""

from __future__ import annotations

import os

from phase2 import create_app
from phase2.extensions import socketio

app = create_app()


if __name__ == "__main__":
    # Port 5001 by default: on macOS, port 5000 is taken by the AirPlay receiver.
    port = int(os.environ.get("PHASE2_PORT", "5001"))
    host = os.environ.get("PHASE2_HOST", "127.0.0.1")
    debug = (os.environ.get("PHASE2_ENV", "development").lower() == "development")
    socketio.run(app, host=host, port=port, debug=debug)
