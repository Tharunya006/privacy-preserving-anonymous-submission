# privacy-preserving-anonymous-submission
Privacy Preserving Anonymous Submission System - Project

---

One Flask application with one database:

* **Anonymous sources** submit reports (with optional evidence) and check their
  status using a random token — no account, no login, no IP stored.
* **Authorized journalists** sign in to read reports, download evidence and
  update each report's status.
* **Administrators** create, authorize and disable journalist accounts and
  review the audit log.

Phase 1 (the submission portal), Phase 2 (authentication, RBAC, secure
sessions, CSRF, lockout, audit logging) and Phase 4 (journalist inbox, report
view, `Submitted → Under review → Closed` workflow, evidence download) are
integrated; see [`docs/integration_notes.md`](docs/integration_notes.md).

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

### Tests

```bash
pytest
```

### Documentation

* [`docs/integration_notes.md`](docs/integration_notes.md) — final architecture,
  database, routes, and how to run the integrated application
* [`docs/phase2.md`](docs/phase2.md) — authentication, RBAC and security
  measures in depth
* [`docs/phase4.md`](docs/phase4.md) — journalist workflow, status rules,
  evidence access and Phase 4 security
