# privacy-preserving-anonymous-submission
Privacy Preserving Anonymous Submission System - Project

---

## Phase 2 — Authentication & Authorization

Phase 2 adds the identity and access-control layer: admin and journalist
authentication, role-based access control, secure sessions, and the admin
dashboard for managing journalist accounts. Anonymous sources deliberately
require no account and no login.

Phase 2 runs independently of Phase 1 and does not modify any Phase 1 file.

### Quick start

```bash
python -m venv .venv
source .venv/bin/activate              # Windows: .venv\Scripts\activate
pip install -r requirements-phase2.txt

cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"   # paste into PHASE2_SECRET_KEY

flask --app phase2_app init-db
flask --app phase2_app create-admin --username admin
python phase2_app.py                   # http://127.0.0.1:5001
```

### Tests

```bash
pytest
```

### Documentation

* [`docs/phase2.md`](docs/phase2.md) — architecture, authentication, RBAC,
  database schema, routes, security measures
* [`docs/integration_notes.md`](docs/integration_notes.md) — how Phase 2 merges
  into Phase 1, and which files belong to which phase
