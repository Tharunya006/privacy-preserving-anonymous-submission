"""Phase 6: capture the same workflow over unprotected and protected transport.

Runs the real application twice, on a throw-away database with throw-away keys:

* ``http``  - plain HTTP + WebSocket (ws://): unprotected transport
* ``https`` - TLS (HTTPS + wss://, Werkzeug ad-hoc self-signed certificate)

Each run drives an identical scripted workflow through ``RecordingProxy``:

1. a journalist signs in and opens the Socket.IO WebSocket;
2. an anonymous source submits a report with a photo carrying EXIF/GPS data;
3. the journalist receives the real-time notification, reads the report,
   downloads the evidence and moves it to "Under review" (second event);
4. the source checks the status with the token.

Outputs (git-ignored, regenerate any time):
  analysis/results/http_unprotected.pcap
  analysis/results/https_protected.pcap
  analysis/results/capture_meta.json   - marker values, client timings, storage scan

Usage:  python -m analysis.traffic_capture
Then:   python -m analysis.traffic_analysis
"""

from __future__ import annotations

import io
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import warnings
from pathlib import Path

import requests
import socketio as sio_client
from PIL import Image

from analysis.recorder import RecordingProxy, write_pcap

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "analysis" / "results"

MARKERS = {
    "report_title": "P6MARK-TITLE-harbour-ledger",
    "report_body": "P6MARK-BODY-container-27-was-never-inspected",
    "photo_exif_camera": "P6MARK-CAMERA-SERIAL-7741",
}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(port: int, timeout: float = 20) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise RuntimeError(f"server did not start on port {port}")


def _photo_with_metadata() -> bytes:
    image = Image.new("RGB", (320, 240), (30, 110, 160))
    exif = Image.Exif()
    exif[0x0110] = MARKERS["photo_exif_camera"]
    exif.get_ifd(0x8825)[2] = (51.0, 30.0, 12.0)
    buffer = io.BytesIO()
    image.save(buffer, format="JPEG", exif=exif)
    return buffer.getvalue()


def _csrf(html: str) -> str:
    return re.search(r'name="csrf_token" type="hidden" value="([^"]+)"', html).group(1)


def run_mode(mode: str, workdir: Path) -> dict:
    tls = mode == "https"
    port = _free_port()
    env = dict(os.environ)
    env.update({
        "PHASE2_DATABASE_URI": f"sqlite:///{(workdir / f'{mode}.db').as_posix()}",
        "PHASE2_EVIDENCE_DIR": str(workdir / f"{mode}-evidence"),
        "PHASE2_SECRET_KEY": secrets.token_urlsafe(48),
        "PHASE5_ENCRYPTION_KEY": secrets.token_urlsafe(32),
        "PHASE5_HMAC_KEY": secrets.token_urlsafe(32),
        "PHASE2_ENV": "production",
        "PHASE2_COOKIE_SECURE": "true" if tls else "false",
        "PHASE2_PORT": str(port),
    })
    if tls:
        env["PHASE6_TLS"] = "adhoc"
    journalist_password = "Cap!" + secrets.token_urlsafe(12) + "9a"

    seed = (
        "from phase2 import create_app\n"
        "from phase2.extensions import db\n"
        "from phase2.services import create_user\n"
        "import sys\n"
        "app = create_app()\n"
        "with app.app_context():\n"
        "    db.create_all()\n"
        "    create_user('capture-journalist', sys.argv[1], status='AUTHORIZED',"
        " must_change_password=False)\n"
    )
    subprocess.run([sys.executable, "-c", seed, journalist_password], cwd=ROOT, env=env, check=True)
    server = subprocess.Popen([sys.executable, "app.py"], cwd=ROOT, env=env,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proxy = None
    try:
        _wait_for_port(port)
        proxy = RecordingProxy(port).start()
        base = f"{'https' if tls else 'http'}://127.0.0.1:{proxy.port}"
        timings: dict[str, float] = {}

        def timed(name, fn, *a, **kw):
            t0 = time.perf_counter()
            result = fn(*a, **kw)
            timings[name] = round((time.perf_counter() - t0) * 1000, 2)
            return result

        warnings.filterwarnings("ignore", message="Unverified HTTPS request")
        journalist = requests.Session()
        journalist.verify = False  # throw-away self-signed demo certificate
        # Browsers send a same-origin Referer under the app's Referrer-Policy;
        # Flask-WTF requires it for form posts over HTTPS.
        journalist.headers["Referer"] = f"{base}/"
        page = timed("journalist GET /auth/login", journalist.get, f"{base}/auth/login")
        timed("journalist POST /auth/login", journalist.post, f"{base}/auth/login", data={
            "csrf_token": _csrf(page.text), "username": "capture-journalist",
            "password": journalist_password,
        })

        received: list[tuple[str, dict]] = []
        got_event = threading.Event()
        sock = sio_client.Client(http_session=journalist, ssl_verify=not tls, reconnection=False)

        @sock.on("new_submission")
        def _new(data):
            received.append(("new_submission", data))
            got_event.set()

        @sock.on("submission_status_changed")
        def _changed(data):
            received.append(("submission_status_changed", data))
            got_event.set()

        timed("journalist WebSocket connect", sock.connect, base, transports=["websocket"],
              wait_timeout=10)

        source = requests.Session()
        source.verify = False
        source.headers["Referer"] = f"{base}/"
        form = timed("source GET /submit", source.get, f"{base}/submit")
        photo = _photo_with_metadata()
        receipt = timed("source POST /submit (with photo)", source.post, f"{base}/submit",
                        data={"csrf_token": _csrf(form.text), "title": MARKERS["report_title"],
                              "content": MARKERS["report_body"]},
                        files={"evidence": ("IMG_2041.jpg", photo, "image/jpeg")})
        token = re.search(r"<code>([A-Za-z0-9_-]{32})</code>", receipt.text).group(1)
        got_event.wait(5)
        got_event.clear()

        timed("journalist GET inbox", journalist.get, f"{base}/journalist/inbox")
        detail = timed("journalist GET report", journalist.get, f"{base}/journalist/submissions/1")
        timed("journalist GET evidence", journalist.get,
              f"{base}/journalist/submissions/1/evidence/1")
        timed("journalist POST status", journalist.post,
              f"{base}/journalist/submissions/1/status",
              data={"csrf_token": _csrf(detail.text), "status": "UNDER_REVIEW"})
        got_event.wait(5)

        status_page = timed("source GET /status", source.get, f"{base}/status")
        timed("source POST /status", source.post, f"{base}/status",
              data={"csrf_token": _csrf(status_page.text), "token": token})

        sock.disconnect()
        journalist.close()
        source.close()
        time.sleep(0.3)
        proxy.stop()

        RESULTS.mkdir(parents=True, exist_ok=True)
        pcap = RESULTS / ("https_protected.pcap" if tls else "http_unprotected.pcap")
        packets = write_pcap(pcap, proxy.connections, 443 if tls else 80)
        session_cookie = journalist.cookies.get("phase2_session") or ""

        return {
            "mode": mode,
            "pcap": str(pcap.relative_to(ROOT)),
            "packets_written": packets,
            "connections": len(proxy.connections),
            "client_timings_ms": timings,
            "websocket_events_received": received,
            # Values searched for in the capture (the password is only reported
            # as found / not found, never written out).
            "search_values": {
                **MARKERS,
                "submission_token": token,
                "journalist_session_cookie": session_cookie,
            },
            "secret_values": {"journalist_password": journalist_password},
            "photo_bytes_uploaded": len(photo),
            "storage_scan": _scan_storage(workdir, mode, {**MARKERS, "submission_token": token}),
        }
    finally:
        if proxy and proxy._thread.is_alive():
            proxy.stop()
        server.terminate()
        server.wait(10)


def _scan_storage(workdir: Path, mode: str, values: dict) -> dict:
    """Phase 5 check: is any marker readable in the stored database / evidence?"""
    blobs = {"database": (workdir / f"{mode}.db").read_bytes()}
    evidence = workdir / f"{mode}-evidence"
    blobs["evidence files"] = b"".join(p.read_bytes() for p in evidence.iterdir()) if evidence.exists() else b""
    return {
        where: {name: value.encode() in data for name, value in values.items()}
        for where, data in blobs.items()
    }


def main() -> None:
    workdir = Path(tempfile.mkdtemp(prefix="ppass-capture-"))
    try:
        runs = [run_mode("http", workdir), run_mode("https", workdir)]
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    meta = {"captured_at": time.strftime("%Y-%m-%d %H:%M:%S %Z"), "runs": runs}
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "capture_meta.json").write_text(json.dumps(meta, indent=2))
    for run in runs:
        print(f"{run['mode']:5}  {run['pcap']}  packets={run['packets_written']}  "
              f"connections={run['connections']}  ws_events={len(run['websocket_events_received'])}")


if __name__ == "__main__":
    main()
