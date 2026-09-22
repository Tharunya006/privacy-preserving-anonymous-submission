# Integration Notes — merging Phase 2 into Phase 1

This document is for the moment the two phases are brought together. It lists
which files belong to whom, why nothing currently collides, and the exact steps
to merge.

---

## 1. File ownership

### Files that belong to Phase 2 (mine — safe to change)

```
phase2_app.py                    standalone entry point
phase2/                          the entire package
  ├── __init__.py, config.py, extensions.py, models.py
  ├── security.py, forms.py, services.py, cli.py
  ├── blueprints/{__init__,main,auth,admin,journalist}.py
  ├── templates/phase2/*.html    (13 templates)
  └── static/phase2/{style.css,app.js}
tests/                           conftest.py + 5 test modules
docs/phase2.md
docs/integration_notes.md        this file
requirements-phase2.txt
pytest.ini
.env.example
instance/phase2.db               generated locally, git-ignored
```

### Files that belong to Phase 1 (teammate's — do not edit)

```
app.py                  Phase 1 application entry point
config.py               Phase 1 configuration (root level)
models.py               Phase 1 models (root level)
templates/              Phase 1 templates (root level)
static/                 Phase 1 static assets (root level)
requirements.txt        Phase 1 dependencies
instance/<phase1>.db    Phase 1 database
```

Phase 2 creates **none** of these. At the time Phase 2 was written the
repository contained only `README.md`, so these names were left free on purpose.

### Shared files (coordinate before editing)

| File | Rule |
|---|---|
| `.gitignore` | Phase 2 wrote a complete one. Append Phase 1 entries; don't replace. |
| `README.md` | Append a Phase 2 section; leave Phase 1's text alone. |
| `requirements.txt` | Phase 1's. Merge `requirements-phase2.txt` into it at merge time. |

---

## 2. Why there are no collisions today

| Namespace | Phase 1 | Phase 2 |
|---|---|---|
| Entry point | `app.py` | `phase2_app.py` |
| Dev port | 5000 | 5001 |
| Database file | e.g. `instance/app.db` | `instance/phase2.db` |
| Table names | whatever Phase 1 chooses | `phase2_users`, `phase2_audit_log` |
| URL prefixes | `/` and its own routes | `/auth`, `/admin`, `/journalist` |
| Templates | `templates/*.html` | `phase2/templates/phase2/*.html` |
| Static | `static/*` | `phase2/static/phase2/*` |
| Config env vars | Phase 1's own | all prefixed `PHASE2_` |
| Session cookie | Flask default `session` | `phase2_session` |
| Requirements | `requirements.txt` | `requirements-phase2.txt` |

The template subfolder matters most: Phase 2 templates are referenced as
`phase2/login.html`, never `login.html`. Even after both template directories
are merged into one, a Phase 1 `login.html` and a Phase 2 `phase2/login.html`
remain distinct files.

`tests/test_models.py::TestSchema::test_tables_are_namespaced_for_phase2`
fails the build if a Phase 2 table ever loses its prefix.

---

## 3. The merge hook

`phase2/__init__.py` exposes:

```python
def register_phase2(app, url_prefix: str = "") -> Flask
```

It attaches every Phase 2 blueprint, request hook, and template context to an
**existing** Flask app. It assumes `db` and `csrf` are already initialised on
that app. `create_app()` (the standalone factory) is simply a thin wrapper that
builds an app and then calls it — so the merged path is exercised by every test
in the suite.

---

## 4. Merge procedure

### Step 0 — before touching anything

```bash
git checkout -b integration/phase1-phase2
pytest                      # Phase 2 must be green before you start
```

### Step 1 — dependencies

Fold `requirements-phase2.txt` into Phase 1's `requirements.txt`
(`Flask-SQLAlchemy`, `Flask-WTF`, `python-dotenv`, `pytest`), then delete the
Phase 2 file. Flask itself will already be there.

### Step 2 — one SQLAlchemy instance

Phase 2 owns `phase2/extensions.py`:

```python
db = SQLAlchemy()
csrf = CSRFProtect()
```

If Phase 1 has its own `db` in `models.py` or `app.py`, keep **Phase 1's** and
make Phase 2 import it. Edit `phase2/extensions.py` only — nothing else in
Phase 2 references SQLAlchemy directly:

```python
# phase2/extensions.py  (after merge)
from models import db              # Phase 1's SQLAlchemy() instance
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()
```

Both sets of tables then live in one metadata and one `db.create_all()`. The
`phase2_` prefix keeps them apart.

### Step 3 — register Phase 2 on Phase 1's app

Add these lines to Phase 1's `app.py`, after `db.init_app(app)`:

```python
from flask_wtf.csrf import CSRFProtect
from phase2 import register_phase2
from phase2.cli import register_cli

csrf = CSRFProtect()
csrf.init_app(app)               # if Phase 1 does not already do this
register_phase2(app)             # mounts /auth, /admin, /journalist
register_cli(app)                # init-db, create-admin, ...
```

`register_phase2` skips its own `/` route when Phase 1 already registered a
blueprint named `main`, so Phase 1 keeps the landing page. If Phase 1's home
blueprint has a different name, either rename it to `main` or delete the
`main` registration line inside `register_phase2`.

### Step 4 — configuration

Merge `.env.example` into Phase 1's. Every Phase 2 key is prefixed `PHASE2_`,
so nothing overlaps. Required at minimum:

```
PHASE2_SECRET_KEY=<48 random url-safe bytes>
```

Phase 1's `SECRET_KEY` becomes the app's signing key once merged; Phase 2's
`_resolve_secret_key` only runs inside `create_app()`, which is no longer used.
Make sure Phase 1 sets a real `SECRET_KEY` from the environment — the session
cookie's integrity depends on it.

### Step 5 — templates and static files

Two options:

* **Keep them separate (recommended, zero risk).** Blueprints already carry
  their own `template_folder`/`static_folder`, so Phase 2 templates keep
  resolving from `phase2/templates/`. Nothing to do.
* **Move into the shared folders.** Copy `phase2/templates/phase2/` →
  `templates/phase2/` and `phase2/static/phase2/` → `static/phase2/`. The
  subfolder name keeps every path unique; no `render_template` call changes.

If Phase 1 has its own `base.html` and you want one shared look, make
`phase2/base.html` extend it and move the nav/flash blocks across. This is
cosmetic — no access-control logic lives in the templates.

### Step 6 — database

```bash
flask --app app init-db                 # creates Phase 1 + Phase 2 tables
flask --app app create-admin --username admin
```

Existing Phase 2 data does not migrate automatically. For a college project the
clean path is to recreate the database and re-run `create-admin`. If data must
be preserved, the two tables can be copied across with `sqlite3`:

```bash
sqlite3 instance/phase2.db ".dump phase2_users phase2_audit_log" \
  | sqlite3 instance/app.db
```

### Step 7 — verify

```bash
pytest                    # the whole suite must still pass
```

`tests/conftest.py` builds its app with `create_app("testing")`. After the
merge, point it at Phase 1's factory (or keep `create_app` alive purely for
tests — it is only ~30 lines and costs nothing).

Then check by hand: sign in as admin, create a journalist, authorize them, sign
in as that journalist, confirm they get 403 on `/admin/dashboard`, and confirm
the Phase 1 home page still renders.

---

## 5. Protecting Phase 1 and Phase 3+ routes

Once merged, any route in the app can reuse the Phase 2 gate:

```python
from phase2.security import admin_required, journalist_required, current_user

@app.route("/submissions/<token>")
@journalist_required                       # AUTHORIZED journalists only
def view_submission(token):
    receiver = current_user()
    ...
```

This is exactly how Phase 4 (receiver workflow) should protect its views —
never by checking `session["role"]` by hand in a view.

## 6. Hooks Phase 3 will want

| Need | Provided by Phase 2 |
|---|---|
| "Which journalist is acting?" | `phase2.security.current_user()` |
| "Only authorized receivers" | `@journalist_required` |
| Link a submission to a receiver | `ForeignKey("phase2_users.id")` |
| Record who opened a submission | `phase2.models.record_event(...)` |
| Keep the source anonymous | the source path never touches `phase2_users` |

**One rule for Phase 3:** the anonymous submission route must never be wrapped
in `@login_required`, and no submission may be linked to a source identity. The
`User` table is for *receivers* only. `docs/phase2.md` §8 notes the matching
caution about IP addresses in the audit log.

---

## 7. Merge checklist

- [ ] Branch created, Phase 2 suite green before starting
- [ ] `requirements-phase2.txt` folded into `requirements.txt`
- [ ] `phase2/extensions.py` points at Phase 1's `db`
- [ ] `register_phase2(app)` + `register_cli(app)` called in Phase 1's `app.py`
- [ ] `CSRFProtect` initialised exactly once
- [ ] `SECRET_KEY` read from the environment, not hard-coded
- [ ] `.env.example` merged; real `.env` still git-ignored
- [ ] Database recreated; `create-admin` re-run
- [ ] `pytest` green after the merge
- [ ] Manual check: admin flow, journalist flow, 403 boundary, Phase 1 home page
- [ ] No Phase 1 file modified beyond `app.py`, `.gitignore`, `README.md`,
      `requirements.txt`
