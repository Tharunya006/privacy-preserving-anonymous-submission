"""Insert a demo anonymous submission into the unified database.

Phase 1's version also inserted a receiver account with a plaintext password;
accounts are now created only through the hashed-password CLI commands
(``flask --app app create-admin`` / ``create-journalist``).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from phase2 import create_app  # noqa: E402
from phase2.extensions import db  # noqa: E402
from submissions.services import create_submission  # noqa: E402


def seed():
    app = create_app()
    with app.app_context():
        db.create_all()
        submission, token = create_submission(
            "Test Anonymous Report",
            "This is a test submission created by database/seed_db.py.",
        )
        print(f"Demo submission #{submission.id} created.")
        print(f"Its status token (shown once): {token}")


if __name__ == "__main__":
    seed()
