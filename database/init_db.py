"""Create every table of the unified database.

Kept so Phase 1's ``python database/init_db.py`` still works.  It is equivalent
to ``flask --app app init-db``: both create the account, audit and submission
tables in the one SQLAlchemy database (default ``instance/phase2.db``).
Existing tables and rows are left untouched.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from phase2 import create_app  # noqa: E402
from phase2.extensions import db  # noqa: E402


def create_database():
    app = create_app()
    with app.app_context():
        db.create_all()
        print(f"Database ready: {app.config['SQLALCHEMY_DATABASE_URI']}")


if __name__ == "__main__":
    create_database()
