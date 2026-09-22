"""Shared Flask extension objects for Phase 2.

These live in their own module so that, at merge time, Phase 2 can be pointed
at Phase 1's SQLAlchemy instance instead of its own (see
``docs/integration_notes.md``).
"""

from __future__ import annotations

from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
csrf = CSRFProtect()
