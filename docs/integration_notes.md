# Integration Notes — Phases 1–6

Phase 1 (anonymous submission portal), Phase 2 (authentication &
authorization), Phase 3 (evidence metadata scrubbing — see
[`phase3.md`](phase3.md)), Phase 4 (journalist workflow — see
[`phase4.md`](phase4.md)), Phase 5 (server-side encryption and integrity —
see [`phase5.md`](phase5.md)) and Phase 6 (real-time WebSocket notifications
and traffic analysis — see [`phase6.md`](phase6.md)) are integrated into **one
Flask application** backed by **one database**. This document describes the final architecture, what changed
during the integration, and how to run the result.

---

## 1. How to run

```bash
python -m venv .venv
source .venv/bin/activate              # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env                   # then set PHASE2_SECRET_KEY:
python -c "import secrets; print(secrets.token_urlsafe(48))"

flask --app app init-db                # creates every table (safe to re-run)
flask --app app create-admin --username admin
python app.py                          # http://127.0.0.1:5001
```

Other commands:

```bash
flask --app app create-journalist --username alice [--authorize]
flask --app app set-status alice AUTHORIZED
flask --app app reset-password --username admin   # prompts twice, no echo
flask --app app list-users
flask --app app scrub-evidence [--dry-run]        # clean evidence stored before Phase 3
flask --app app protect-legacy-data [--dry-run]   # encrypt data stored before Phase 5
python database/init_db.py             # same as `flask --app app init-db`
python database/seed_db.py             # adds one demo submission, prints its token
pytest                                 # full test suite
```

An existing `instance/phase2.db` keeps working: `init-db` adds the new
submission tables next to the existing accounts and audit log without touching
them.

---

## 2. Architecture

```
app.py                         the single entry point  -> phase2.create_app()
│
├── phase2/                    authentication, RBAC, dashboards (Phase 2)
│   ├── __init__.py            create_app(): builds the ONE app, registers
│   │                          submissions + Phase 2 blueprints, error handlers,
│   │                          security headers, CLI
│   ├── config.py              all settings from the environment (PHASE2_*)
│   ├── extensions.py          the one `db` (SQLAlchemy) and `csrf` instance
│   ├── models.py              User, AuditLog
│   ├── security.py            sessions + @login_required / @admin_required /
│   │                          @journalist_required
│   ├── blueprints/
│   │   ├── main.py            "/"            public home page
│   │   ├── auth.py            "/auth"        login, logout, change password
│   │   ├── admin.py           "/admin"       ADMIN only
│   │   └── journalist.py      "/journalist"  AUTHORIZED JOURNALIST only —
│   │                                         includes the submission inbox
│   ├── templates/phase2/      shared base layout + Phase 2 pages
│   └── static/phase2/         style.css, app.js
│
├── submissions/               anonymous submission portal (Phase 1, rebuilt)
│   ├── __init__.py            register_submissions(app); in-memory upload request
│   ├── models.py              Submission, Evidence (on phase2's `db`)
│   ├── services.py            tokens, validation, evidence storage, workflow
│   ├── scrubber.py            Phase 3: metadata removal (Pillow) before storage
│   ├── crypto.py              Phase 5: AES-256-GCM + HMAC-SHA-256 + timestamp
│   ├── cli.py                 scrub-evidence (clean pre-Phase-3 evidence)
│   ├── forms.py               WTForms (validation + CSRF)
│   ├── routes.py              "source" blueprint: /submit, /status, /login
│   └── templates/submissions/ submit, receipt, status pages
│
├── database/                  init_db.py / seed_db.py — thin wrappers
└── tests/                     the whole suite (Phase 2 + integration)
```

### Request flow

```
anonymous source ── /submit, /status ──► submissions.routes ──► submissions.services ─┐
                                                                                       ├─► db (instance/phase2.db)
journalist ── /auth/login ──► Phase 2 session ── /journalist/* ──► journalist bp ─────┤
                                   (@journalist_required, re-checked every request)    │
admin ── /admin/* (@admin_required) — accounts, audit log, submission COUNTS only ─────┘
```

---

## 3. Database

One SQLAlchemy database, default `instance/phase2.db` (git-ignored; override
with `PHASE2_DATABASE_URI`). Phase 1's separate `database/app.db` and its raw
`sqlite3` access are retired.

| Table | Owner | Purpose |
|---|---|---|
| `phase2_users` | Phase 2 | admin and journalist accounts (hashed passwords) |
| `phase2_audit_log` | Phase 2 | append-only security and workflow events |
| `submissions` | submissions | anonymous reports — title and body stored encrypted (Phase 5) |
| `submission_evidence` | submissions | evidence file metadata — the files hold encrypted packages (Phase 5) |

Phase 1's plaintext `users` table no longer exists: `phase2_users` is the only
account table.

### `submissions`

| Column | Notes |
|---|---|
| `id` | primary key; the internal reference (`submission:<id>`) used in the audit log |
| `token_hash` | SHA-256 of the source's token, unique. The token itself is never stored |
| `title` | ≤ 200 characters, not unique (duplicate titles are fine) |
| `content` | ≤ 20 000 characters |
| `status` | `SUBMITTED` / `UNDER_REVIEW` / `CLOSED` (CHECK constraint) |
| `created_at`, `updated_at` | UTC |

No user id, IP address, session id or user agent is stored, and there is no
foreign key to `phase2_users`: a report is never linked to an identity.

### `submission_evidence`

`id`, `submission_id` (FK), `stored_name` (random, unique), `extension`,
`size_bytes`, `created_at`. The source's original filename is **not** kept — it
can identify a person or machine. The stored file is the **scrubbed** one
(Phase 3): images re-encoded without EXIF/GPS/XMP/ICC/comments/text chunks,
or plain UTF-8 text. Only JPEG, PNG, GIF, WebP, TXT and CSV are accepted.

Files live in `instance/evidence/` (override with `PHASE2_EVIDENCE_DIR`),
outside every static folder, with `0600` permissions.

---

## 4. Authentication and authorization

Phase 2's system is the only one:

| Who | Account? | Can reach |
|---|---|---|
| Anonymous source | **none** | `/`, `/submit`, `/status` |
| Journalist (AUTHORIZED) | yes | `/journalist/*` — inbox, reports, evidence, status updates |
| Admin | yes (CLI bootstrap) | `/admin/*` — accounts, audit log, submission counts |

* Admins do **not** read report content. Roles are exclusive, so an admin gets
  403 on `/journalist/*`.
* PBKDF2 password hashing, lockout, idle timeout, session-fixation defence,
  CSRF, security headers and the audit log apply to the whole app unchanged.
* The public source forms are CSRF-protected too. The CSRF token lives in the
  session cookie, which holds nothing that identifies the source.

---

## 5. Routes

| Method | Route | Access |
|---|---|---|
| GET | `/` | public |
| GET/POST | `/submit` | public, CSRF — returns the token once on a receipt page |
| GET/POST | `/status` | public, CSRF — token lookup via POST (never in a URL) |
| GET | `/login` | public — 301 to `/auth/login` (Phase 1's old URL) |
| * | `/auth/*`, `/admin/*`, `/dashboard`, `/unauthorized` | as in `docs/phase2.md` |
| GET | `/journalist/inbox[?status=…&page=…]` | JOURNALIST + AUTHORIZED |
| GET | `/journalist/submissions/<id>` | JOURNALIST + AUTHORIZED — audited `submission.viewed` |
| POST | `/journalist/submissions/<id>/status` | JOURNALIST + AUTHORIZED, CSRF — one step of Submitted → Under review → Closed, audited |
| GET | `/journalist/submissions/<id>/evidence/<eid>` | JOURNALIST + AUTHORIZED — audited, attachment only |

Removed: Phase 1's `/test-db` and `/test-submissions` debug routes (the latter
published every submission to anyone).

---

## 6. What the integration fixed in Phase 1

| Phase 1 issue | Fix |
|---|---|
| Plaintext passwords in `users`, login by `WHERE password = ?` | Table and login removed; Phase 2's hashed accounts and `/auth/login` are used. `/login` redirects there |
| Seed script created `admin` / `test123` | `seed_db.py` now only adds a demo submission; accounts come from the CLI |
| Token was `TOKEN-` + title (guessable) | `secrets.token_urlsafe(24)` (192 bits); only its SHA-256 is stored |
| Duplicate title crashed with `IntegrityError` (500) | Token no longer derived from the title |
| XSS: report text placed into f-string HTML | All output through auto-escaped Jinja templates |
| Public `/test-submissions` listed every report | Removed; reports only via `/journalist/*` |
| No validation / error handling | WTForms validation (required, length), 400 on bad input, 404 for unknown tokens, 413 for oversize uploads, generic 500 page |
| No CSRF protection | Flask-WTF CSRF on every form, including the public ones |
| Evidence field silently did nothing (no `enctype`) | Uploads work: extension allow-list, per-file size limit, metadata scrubbing (Phase 3), random names, private directory, journalist-only attachment download |
| Raw `sqlite3` with a cwd-relative path | SQLAlchemy on the shared, cwd-independent database |
| `requirements.txt` was UTF-16 (git treated it as binary) | Converted to UTF-8; Phase 2 requirements folded in |

Also fixed while integrating:

* Phase 2 `admin.change_status` redirected to an unchecked `return_to` form
  field (open redirect) — now validated with `is_safe_redirect_target`.
* `normalise_database_uri` followed symlinks (`Path.resolve()`), turning
  `/tmp/...` into `/private/tmp/...` on macOS — now normalised lexically.
* Error pages raised a second 413 while rendering on an oversize POST — the
  layout's logout form no longer reads the request body.

---

## 7. Configuration

All settings come from the environment (`.env`, git-ignored); see
`.env.example`. New in the integration, both optional:

| Variable | Default | Meaning |
|---|---|---|
| `PHASE2_EVIDENCE_DIR` | `instance/evidence` | private evidence storage |
| `PHASE2_EVIDENCE_MAX_MB` | `10` | per-file limit; the request limit is this + 1 MB |
| `PHASE5_ENCRYPTION_KEY` | **required** | AES-256 key, base64url of 32 random bytes |
| `PHASE5_HMAC_KEY` | **required** | HMAC-SHA-256 key, a different base64url 32-byte value |
| `PHASE5_MAX_CLOCK_SKEW_SECONDS` | `300` | how far in the future a protected timestamp may be |
| `PHASE6_TLS` | unset | `adhoc` serves HTTPS/WSS with a throw-away self-signed certificate (demo) |
| `PHASE6_TLS_CERT`, `PHASE6_TLS_KEY` | unset | serve HTTPS/WSS with your certificate and key |

`PHASE2_PORT` defaults to 5001 (macOS reserves 5000 for AirPlay).

---

## 8. Not implemented (by decision)

* **Network anonymity** (Tor/onion routing, padding, dummy traffic, random
  delays). The app stores no source IP, but the network and the server's access
  log see it. See `phase6.md` §8.

---

## 9. Merge checklist (completed)

- [x] One entry point (`app.py`), one factory (`phase2.create_app`)
- [x] One SQLAlchemy `db`; Phase 1 tables on it
- [x] `requirements-phase2.txt` folded into `requirements.txt`
- [x] `CSRFProtect` initialised exactly once
- [x] `SECRET_KEY` read from the environment, never hard-coded
- [x] `.env.example` updated; `.env`, `instance/` and `*.db` still git-ignored
- [x] Phase 1 templates rebuilt on the shared layout
- [x] `pytest` green
