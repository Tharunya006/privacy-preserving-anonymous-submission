#!/usr/bin/env python3
"""Standalone entry point for PHASE 2 (Authentication & Authorization).

Phase 1 keeps its own ``app.py``; this file exists so Phase 2 can be developed
and demonstrated independently.  Nothing in Phase 1 is imported or modified.

Usage
-----
    flask --app phase2_app init-db
    flask --app phase2_app create-admin --username admin
    python phase2_app.py            # or: flask --app phase2_app run
"""

from __future__ import annotations

import os

from phase2 import create_app

app = create_app()


if __name__ == "__main__":
    # Port 5001 by default so it never collides with Phase 1 on 5000.
    port = int(os.environ.get("PHASE2_PORT", "5001"))
    host = os.environ.get("PHASE2_HOST", "127.0.0.1")
    debug = (os.environ.get("PHASE2_ENV", "development").lower() == "development")
    app.run(host=host, port=port, debug=debug)
