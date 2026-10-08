#!/usr/bin/env python3
"""Entry point for the Privacy Preserving Anonymous Submission System.

One Flask application, one database: the Phase 1 anonymous submission portal
(``submissions`` package) and the Phase 2 authentication, RBAC and dashboards
(``phase2`` package) are assembled by ``phase2.create_app``.  Phase 6 adds
Flask-SocketIO, so the app is started through ``socketio.run``.

Usage
-----
    flask --app app init-db
    flask --app app create-admin --username admin
    python app.py                   # http://127.0.0.1:5001

Optional TLS (HTTPS + WSS), e.g. for the Phase 6 protected-traffic comparison:
    PHASE6_TLS=adhoc python app.py                     # throw-away self-signed cert
    PHASE6_TLS_CERT=cert.pem PHASE6_TLS_KEY=key.pem python app.py
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

    ssl_context = None
    if os.environ.get("PHASE6_TLS_CERT") and os.environ.get("PHASE6_TLS_KEY"):
        ssl_context = (os.environ["PHASE6_TLS_CERT"], os.environ["PHASE6_TLS_KEY"])
    elif os.environ.get("PHASE6_TLS", "").lower() == "adhoc":
        ssl_context = "adhoc"  # self-signed, regenerated on every start: demo only

    # This is Werkzeug's development server (as app.run was before Phase 6);
    # Flask-SocketIO requires the explicit opt-in to use it outside debug mode.
    # Use a production WSGI server for a real deployment.
    socketio.run(
        app, host=host, port=port, debug=debug, use_reloader=False,
        allow_unsafe_werkzeug=True, ssl_context=ssl_context,
    )
