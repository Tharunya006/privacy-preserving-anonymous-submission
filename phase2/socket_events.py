"""Phase 6 real-time events for authorized journalists."""

from __future__ import annotations

from flask_socketio import join_room

from .extensions import socketio
from .models import Role
from .security import load_current_user


JOURNALIST_ROOM = "journalists"


@socketio.on("connect")
def handle_connect(auth=None):
    """Allow only authorized journalists to establish a SocketIO session."""
    user = load_current_user()

    if (
        user is None
        or user.role != Role.JOURNALIST.value
        or not user.is_authorized
    ):
        return False

    join_room(JOURNALIST_ROOM)
    print(f"Phase 6 SocketIO: journalist connected: {user.username}")


@socketio.on("disconnect")
def handle_disconnect():
    """SocketIO disconnect handler."""
    return None


def notify_new_submission() -> None:
    """Notify authorized journalist clients after a submission is committed.

    No report content, anonymous token, evidence, or cryptographic material
    is sent through this event.
    """
    socketio.emit(
        "new_submission",
        {
            "message": "A new anonymous submission has been received."
        },
        to=JOURNALIST_ROOM,
    )