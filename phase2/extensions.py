"""Shared Flask extension objects.

The single ``db`` instance here backs the whole application: Phase 2's account
and audit tables and the ``submissions`` package's tables live in one database.
"""

from __future__ import annotations

from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_socketio import SocketIO

db = SQLAlchemy()
csrf = CSRFProtect()
socketio = SocketIO()
