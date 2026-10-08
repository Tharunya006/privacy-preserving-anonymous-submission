# Phase 4 — Journalist Workflow (Authorized Receiver)

Phase 4 gives authorized journalists everything they need to work with
anonymous submissions: a real inbox, the report view, secure evidence download,
and the `Submitted → Under review → Closed` status workflow. It is built
**into** the integrated application (Phase 1 + 2 + 3 + 4) — same Flask app, same
database, same authentication, RBAC, CSRF and session system, same audit log.

---

## 1. How to run

```bash
python -m venv .venv
source .venv/bin/activate              # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env                   # then set PHASE2_SECRET_KEY:
python -c "import secrets; print(secrets.token_urlsafe(48))"

flask --app app init-db                # safe to re-run; Phase 4 adds no tables
flask --app app create-admin --username admin
python app.py                          # http://127.0.0.1:5001
```

To try the workflow end to end:

1. Sign in as the admin at `/auth/login` → **Add journalist**, tick
   *Authorize immediately* (or `flask --app app create-journalist --username
   alice --authorize`, which prints a temporary password).
2. In a private window, submit a report at `/submit` and keep the token.
3. Sign in as the journalist (change the temporary password when asked) →
   **Inbox** → open the report → **Mark as Under review** → **Mark as Closed**.
4. Check the token at `/status`: the source sees each status change.
5. As the admin, open **Audit** to see `submission.viewed`,
   `submission.status_changed` and `evidence.downloaded` — with no report
   content.

Tests: `pytest` (all), `pytest tests/test_phase4.py` (Phase 4 only).

---

## 2. Features

### Journalist dashboard — `/journalist/dashboard`

* Counts by status (total, new, under review, closed).
* The five newest **Submitted** reports, linking straight to each one.

### Inbox — `/journalist/inbox`

* Reference (`#id`), title, status, number of evidence files, received and
  last-updated time (UTC). Newest first.
* Filter by status: `?status=SUBMITTED|UNDER_REVIEW|CLOSED`. Anything else is
  ignored and shows all — never interpolated into SQL.
* Paginated, 25 per page (`?page=N`; invalid or out-of-range pages are safe).
* Report bodies are **not** shown in the list.

### Submission view — `/journalist/submissions/<id>`

* Title, full report text (escaped, line breaks preserved), timestamps,
  evidence list, and the status history (who changed what, when) from the
  audit log.
* Every opening is audited as `submission.viewed`.

### Status workflow — `POST /journalist/submissions/<id>/status`

```
SUBMITTED ──► UNDER_REVIEW ──► CLOSED   (final)
```

* One step at a time, forward only. Skipping (Submitted → Closed), going back,
  re-applying the current status, re-opening a closed report and unknown values
  are all refused with a message, and nothing is written.
* The page offers only the valid next step as a button; closing asks for
  confirmation.
* The change is a **conditional UPDATE** (`… WHERE status = <previous>`). If two
  journalists act on the same report at once, the second gets "updated by
  someone else" instead of silently overwriting the first.
* Each change is audited as `submission.status_changed` with
  `detail = "<OLD> -> <NEW>"`, the journalist as actor, and the target
  `submission:<id>`.
* The source sees the new status at `/status`.

### Evidence — `GET /journalist/submissions/<id>/evidence/<evidence_id>`

Reuses the existing evidence storage (random names in `instance/evidence/`,
outside every static folder). Every stored file has already had its metadata
removed by Phase 3 (see [`phase3.md`](phase3.md)). Downloads are:

* journalist-only, audited as `evidence.downloaded`;
* always `Content-Disposition: attachment` with
  `Content-Type: application/octet-stream` and `X-Content-Type-Options: nosniff`,
  so nothing is rendered in the browser;
* named `submission-<id>-evidence-<eid>.<ext>` — the source's original
  filename was never stored.

---

## 3. Access control

| Who | Dashboard / inbox / report / evidence / status change |
|---|---|
| Anonymous visitor | 302 → `/auth/login` (same answer whether the id exists or not) |
| Journalist, `AUTHORIZED` | allowed |
| Journalist, `PENDING` or `DISABLED` | cannot sign in; disabled mid-session → logged out on the next request |
| Admin | 403 — admins manage accounts and see **counts only** on `/admin/dashboard` |

Two independent gates guard every route: the `journalist` blueprint's
`before_request` (`role_required(JOURNALIST)`) and `@journalist_required` on
each view. The account is re-read from the database on every request.

---

## 4. Security and privacy

| Threat | Defence |
|---|---|
| Source identification | Submissions store no user id, IP, session id or user agent, and have no FK to `phase2_users`. Submission audit events carry no IP or actor. The token is stored only as a SHA-256 hash |
| IDOR | All authorized journalists share one inbox by design; every route checks role + status first. Evidence must belong to the submission in the URL (`evidence.submission_id == id`, else 404). Integer route converters reject non-numeric ids |
| Enumeration | Anonymous requests are answered by the login gate before any lookup |
| Path traversal | Ids in URLs are integers; files are served with `send_from_directory` (rejects escapes); stored names must match `^[0-9a-f]{32}\.[a-z0-9]{1,10}$`, so even a tampered database row cannot point at another file |
| Direct file access | Evidence lives under `instance/`, never under a static route |
| XSS | Jinja auto-escaping on every page; strict CSP (`script-src 'self'`); evidence never rendered inline |
| CSRF | Flask-WTF token on the status form (and every other form); status changes are POST-only |
| SQL injection | SQLAlchemy ORM / bound parameters only; filter values are whitelisted |
| Caching / leakage | `Cache-Control: no-store` on all `/journalist/*` responses, including downloads; generic error pages |
| Audit log leakage | Entries hold actions, `submission:<id>` references and status names only — never report text, titles, tokens, token hashes, file names or file contents |
| Lost updates | Conditional UPDATE on status changes |

---

## 5. Database

Phase 4 adds **no tables and no columns**. It uses:

* `submissions.status` (CHECK: `SUBMITTED`, `UNDER_REVIEW`, `CLOSED`) and
  `submissions.updated_at`, set on each status change;
* `submission_evidence` for downloads;
* `phase2_audit_log` for `submission.viewed`, `submission.status_changed` and
  `evidence.downloaded`, and for the status history shown on each report.

An existing `instance/phase2.db` needs no migration.

---

## 6. Code map

| File | Phase 4 role |
|---|---|
| `phase2/blueprints/journalist.py` | dashboard, inbox, report view, status change, evidence download |
| `submissions/services.py` | `ALLOWED_TRANSITIONS`, `next_statuses`, `update_status` (validated, conditional), `status_history`, `paginate_submissions`, `latest_submissions`, `evidence_path` (name check) |
| `submissions/forms.py` | `SubmissionStatusForm` (CSRF) |
| `phase2/templates/phase2/journalist_*.html` | dashboard, inbox, report pages |
| `phase2/blueprints/admin.py` | submission counts on the admin dashboard |
| `tests/test_phase4.py` | 73 Phase 4 tests |

---

## 7. Limitations (later phases)

* Encryption at rest and integrity checks are added by Phase 5
  ([`phase5.md`](phase5.md)); every journalist view verifies, then decrypts.
* Real-time notifications are added by Phase 6 (`phase6.md`); traffic-analysis
  defences (padding, delays, Tor) are not implemented.
* A closed report cannot be reopened; there is no per-journalist assignment —
  every authorized journalist sees every report.
* Timestamps are precise to the second, which could help correlate a report
  with network logs.
