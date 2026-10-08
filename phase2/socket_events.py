"""Phase 6 real-time events for authorized journalists (Flask-SocketIO).

Originally implemented by Bhavya (origin/bhavya/phase6): an authenticated
``connect`` handler that only admits authorized journalists, a "journalists"
room, and a content-free ``new_submission`` event.  Completed here with:

* re-authorization on every delivery: each connected socket's account is
  re-read from the database before an event is sent to it, so a journalist who
  is disabled, re-pended or demoted mid-connection is disconnected instead of
  continuing to receive events (the same rule ``load_current_user`` applies to
  every HTTP request);
* a maximum socket age equal to the session lifetime;
* journalists holding a temporary password are refused, as they are on HTTP;
* a ``submission_status_changed`` event;
* delivery failures can never break a source's submission.

What travels over the socket: a fixed message, a submission reference number
and a status.  Never report titles or text, tokens, evidence, keys or anything
about the source.  The browser client is served from our own origin (no CDN),
and Socket.IO's same-origin check refuses cross-site WebSocket connections.
"""

from __future__ import annotations

import logging
import threading
from datetime import timedelta

from flask import current_app, request

from .extensions import db, socketio
from .models import Role, Status, User, utcnow
from .security import load_current_user, reset_user_cache

log = logging.getLogger(__name__)

JOURNALIST_ROOM = "journalists"
NEW_SUBMISSION_MESSAGE = "A new anonymous submission has been received."

# sid -> (user id, connected at).  Guarded by a lock: Socket.IO handlers and
# HTTP requests run on different threads.
_connections: dict[str, tuple[int, object]] = {}
_lock = threading.Lock()


def _may_receive(user: User | None) -> bool:
    return (
        user is not None
        and user.role == Role.JOURNALIST.value
        and user.status == Status.AUTHORIZED.value
        and not user.must_change_password
    )


@socketio.on("connect")
def handle_connect(auth=None):
    """Admit only signed-in, authorized journalists (session cookie checked)."""
    reset_user_cache()
    user = load_current_user()  # same session + idle-timeout + status checks as HTTP
    if not _may_receive(user):
        return False  # Socket.IO refuses the connection
    with _lock:
        _connections[request.sid] = (user.id, utcnow())
    from flask_socketio import join_room

    join_room(JOURNALIST_ROOM)
    return None


@socketio.on("disconnect")
def handle_disconnect(*_args):
    with _lock:
        _connections.pop(request.sid, None)


def connected_count() -> int:
    with _lock:
        return len(_connections)


def _authorized_recipients() -> list[str]:
    """Socket ids still allowed to receive events; disconnect the rest."""
    lifetime = current_app.config.get("PERMANENT_SESSION_LIFETIME", timedelta(minutes=30))
    now = utcnow()
    with _lock:
        snapshot = list(_connections.items())

    allowed, revoked = [], []
    for sid, (user_id, connected_at) in snapshot:
        user = db.session.get(User, user_id)
        if _may_receive(user) and now - connected_at <= lifetime:
            allowed.append(sid)
        else:
            revoked.append(sid)

    for sid in revoked:
        with _lock:
            _connections.pop(sid, None)
        try:
            socketio.server.disconnect(sid, namespace="/")
        except Exception:  # pragma: no cover - already gone
            log.debug("socket %s already disconnected", sid)
    return allowed


def _deliver(event: str, payload: dict) -> int:
    """Send ``payload`` to every currently authorized journalist socket."""
    try:
        recipients = _authorized_recipients()
        for sid in recipients:
            socketio.emit(event, payload, to=sid, namespace="/")
        return len(recipients)
    except Exception:  # never let a notification break the caller
        log.exception("real-time %s notification failed", event)
        return 0


def notify_new_submission() -> int:
    """Called after a submission is committed.  Content-free by design."""
    return _deliver("new_submission", {"message": NEW_SUBMISSION_MESSAGE})


def notify_status_changed(submission_id: int, status: str, label: str) -> int:
    """Called after a journalist changes a submission's status."""
    return _deliver(
        "submission_status_changed",
        {
            "id": submission_id,
            "status": status,
            "message": f"Submission #{submission_id} is now {label}.",
        },
    )
