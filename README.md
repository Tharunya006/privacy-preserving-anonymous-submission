# privacy-preserving-anonymous-submission
Privacy Preserving Anonymous Submission System - Project

---

One Flask application with one database:

* **Anonymous sources** submit reports (with optional evidence) and check their
  status using a random token — no account, no login, no IP stored. Hidden
  image metadata (GPS, camera details, timestamps) is removed before storage,
  and reports and evidence are stored encrypted (AES-256-GCM + HMAC-SHA-256).
* **Authorized journalists** sign in to read reports, download evidence and
  update each report's status.
* **Administrators** create, authorize and disable journalist accounts,
  review the audit log, and view a ciphertext-only security analysis of the
  stored encryption (never report content).

**All six phases are integrated** into one application with one database:

| Phase | What it provides |
|---|---|
| 1 | Anonymous submission portal (`/submit`, `/status`) |
| 2 | Authentication, RBAC, secure sessions, CSRF, lockout, audit logging |
| 3 | Evidence metadata scrubbing (EXIF/GPS/XMP/ICC removed with Pillow before storage) |
| 4 | Journalist inbox, report view, `Submitted → Under review → Closed` workflow, evidence download |
| 5 | Server-side encryption at rest (AES-256-GCM), HMAC-SHA-256 integrity, timestamp/replay protection |
| 6 | Real-time WebSocket notifications for journalists (Flask-SocketIO); Wireshark/PyShark traffic analysis (protected vs unprotected, packet size, timing, overhead); crypto/scrubbing timing benchmarks |

Phase 5 is **application-level (server-side) encryption**, not end-to-end: the
server holds the keys so authorized journalists can read reports. See
[`docs/phase5.md`](docs/phase5.md).

See [`docs/integration_notes.md`](docs/integration_notes.md).

### Quick start

```bash
python -m venv .venv
source .venv/bin/activate              # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"   # paste into PHASE2_SECRET_KEY
python -c "import secrets; print(secrets.token_urlsafe(32))"   # paste into PHASE5_ENCRYPTION_KEY
python -c "import secrets; print(secrets.token_urlsafe(32))"   # paste into PHASE5_HMAC_KEY (a different value)

flask --app app init-db
flask --app app create-admin --username admin
flask --app app generate-signing-key --out-dir ~/ppass-signing-keys   # then add the printed lines to .env
python app.py                          # http://127.0.0.1:5001
```

The app **refuses to start** until both Phase 5 keys are set and valid. Back
them up separately from the database: without them stored reports cannot be
decrypted.

### Upgrading an existing checkout

Phase 3 adds Pillow and Phase 5 adds `cryptography`. Data stored before Phase 5
is plaintext and must be encrypted once (Phase 5 keys must be in `.env` first).
After pulling:

```bash
pip install -r requirements.txt
flask --app app init-db                # no-op for existing tables
flask --app app protect-legacy-data    # encrypt pre-Phase-5 reports/evidence (use --dry-run first)
flask --app app scrub-evidence         # clean older evidence (use --dry-run first)
flask --app app generate-signing-key --out-dir ~/ppass-signing-keys   # Phase 7, once
flask --app app verify-signatures      # check every report's signature
```

Phase 7 signs every newly accepted report; older reports stay "Unsigned
(legacy)". Without a signing key the app starts but refuses new reports.

### Phase 6 analysis (optional)

```bash
pip install -r analysis/requirements.txt       # PyShark etc.; also install Wireshark (tshark)
python -m analysis.benchmark                   # crypto + scrubbing timings -> analysis/results/benchmark.md
python -m analysis.traffic_capture             # HTTP vs HTTPS run of the same workflow -> pcaps
python -m analysis.traffic_analysis            # PyShark report -> analysis/results/traffic_report.md
PHASE6_TLS=adhoc python app.py                 # run the app over HTTPS/WSS (demo certificate)
```

The application never claims network anonymity: serve it over HTTPS, and see
[`docs/phase6.md`](docs/phase6.md) for what is and is not protected on the wire.

### Tests

```bash
pytest
```

### Documentation

* [`docs/integration_notes.md`](docs/integration_notes.md) — final architecture,
  database, routes, and how to run the integrated application
* [`docs/phase2.md`](docs/phase2.md) — authentication, RBAC and security
  measures in depth
* [`docs/phase3.md`](docs/phase3.md) — evidence metadata scrubbing: how it
  works, what was ported from `origin/bhavya/phase3`, cleaning older evidence
* [`docs/phase5.md`](docs/phase5.md) — AES-256-GCM, nonces, HMAC-SHA-256,
  timestamp/replay protection, key management, encryption/authorization flow,
  limitations
* [`docs/phase4.md`](docs/phase4.md) — journalist workflow, status rules,
  evidence access and Phase 4 security
* [`docs/signatures.md`](docs/signatures.md) — Phase 7 server signatures:
  what is signed, what a valid signature proves, key custody and rotation
* [`docs/phase6.md`](docs/phase6.md) — WebSocket notifications, traffic analysis
  (Wireshark/PyShark), timing results, image colour-mode behaviour, limitations
* [`docs/security_analysis.md`](docs/security_analysis.md) — admin security
  analysis: ciphertext-only metrics for real reports, controlled experiments
  (entropy, avalanche, NPCR/UACI, PSNR/SSIM, …), performance
