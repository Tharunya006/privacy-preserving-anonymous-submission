# privacy-preserving-anonymous-submission
Privacy Preserving Anonymous Submission System - Project

---

One Flask application with one database:

* **Anonymous sources** submit reports (with optional evidence) and check their
  status using a random token — no account, no login, no IP stored. Hidden
  image metadata (GPS, camera details, timestamps) is removed before storage.
* **Authorized journalists** sign in to read reports, download evidence and
  update each report's status.
* **Administrators** create, authorize and disable journalist accounts and
  review the audit log.

**Phase 1 + Phase 2 + Phase 3 + Phase 4 are integrated** into one application
with one database:

| Phase | What it provides |
|---|---|
| 1 | Anonymous submission portal (`/submit`, `/status`) |
| 2 | Authentication, RBAC, secure sessions, CSRF, lockout, audit logging |
| 3 | Evidence metadata scrubbing (EXIF/GPS/XMP/ICC removed with Pillow before storage) |
| 4 | Journalist inbox, report view, `Submitted → Under review → Closed` workflow, evidence download |

See [`docs/integration_notes.md`](docs/integration_notes.md).

### Quick start

```bash
python -m venv .venv
source .venv/bin/activate              # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"   # paste into PHASE2_SECRET_KEY

flask --app app init-db
flask --app app create-admin --username admin
python app.py                          # http://127.0.0.1:5001
```

### Upgrading an existing checkout

Phase 3 adds Pillow, and evidence uploaded before Phase 3 was stored with its
metadata. After pulling:

```bash
pip install -r requirements.txt
flask --app app init-db                # no-op for existing tables
flask --app app scrub-evidence         # clean older evidence (use --dry-run first)
```

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
* [`docs/phase4.md`](docs/phase4.md) — journalist workflow, status rules,
  evidence access and Phase 4 security
