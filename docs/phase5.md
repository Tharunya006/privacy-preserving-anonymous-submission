# Phase 5 — Encryption, Integrity and Replay Protection

Phase 5 protects report text and evidence **at rest** with AES-256 encryption,
HMAC-SHA-256 integrity, and a protected timestamp that detects stale or replayed
data. It is built into the integrated application (Phases 1–5, one Flask app,
one database).

> **What kind of encryption this is.** This is **application-level
> (server-side) encryption**, not end-to-end encryption. The server holds both
> keys, so the running application can decrypt — which is how authorized
> journalists read reports. It protects against anyone who obtains the
> database file, a backup or the evidence directory **without** the keys, and
> it makes any tampering with stored data detectable. It does **not** protect
> against an attacker who controls the running server or its environment.

---

## 1. Setup and run

```bash
pip install -r requirements.txt                     # adds `cryptography`

# Generate two DIFFERENT keys (run the command twice):
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Put them in `.env` (git-ignored — never commit it):

```
PHASE5_ENCRYPTION_KEY=<first value>
PHASE5_HMAC_KEY=<second value>
```

Then:

```bash
flask --app app init-db
flask --app app protect-legacy-data --dry-run       # only if you have pre-Phase-5 data
flask --app app protect-legacy-data
python app.py                                        # http://127.0.0.1:5001
```

**Back the keys up separately from the database.** Losing either key makes
every stored report and evidence file permanently unreadable; that is the point
of the encryption.

---

## 2. Cryptographic design

All primitives come from `cryptography` (pyca) and the Python standard library;
nothing is hand-rolled.

| Element | Choice |
|---|---|
| Encryption | **AES-256-GCM** (`cryptography.hazmat.primitives.ciphers.aead.AESGCM`), 256-bit key |
| Nonce / IV | **96-bit, fresh for every encryption**, from `os.urandom` (the OS CSPRNG). Never hard-coded, counted or reused. Collision probability stays negligible far beyond this system's volume (birthday bound ≈ 2⁴⁸ encryptions per key) |
| Integrity | **HMAC-SHA-256** (`hmac` + `hashlib`) with a **separate** 256-bit key, over the whole package (encrypt-then-MAC) |
| MAC comparison | `hmac.compare_digest` (constant time) |
| Timestamp | 64-bit microseconds since the epoch, inside the authenticated header |
| Context binding | purpose + record identity in both the HMAC input and the GCM associated data |

### Package format

```
"P5" | version (1 B) | timestamp µs (8 B) | nonce (12 B) | ciphertext + GCM tag (n + 16 B) | HMAC-SHA-256 (32 B)
```

* **HMAC input:** `"PPASS-P5-HMAC\0" ‖ len‖purpose ‖ len‖binding ‖ header ‖ nonce ‖ ciphertext`
* **GCM associated data:** `"PPASS-P5-AAD\0" ‖ len‖purpose ‖ len‖binding ‖ header`

Length-prefixing and the domain labels make the encodings unambiguous.

GCM is itself authenticated encryption. The extra HMAC-SHA-256 layer is the
project's required integrity mechanism. It is keyed independently and checked
**first**, so a forged or altered package is rejected before the cipher is
touched.

### What is bound to what

| Data | Purpose | Binding (record identity) | Protected timestamp |
|---|---|---|---|
| report title | `submission.title` | the submission's token hash | `submissions.created_at` |
| report body | `submission.content` | the submission's token hash | `submissions.created_at` |
| evidence file | `evidence.file` | `<stored_name>|<extension>` | `submission_evidence.created_at` |

So a valid package copied into another submission, swapped between title and
body, or moved to another evidence file fails HMAC verification.

---

## 3. Encryption flow (anonymous source → storage)

```
POST /submit (no account, CSRF)
  → validate title / body / file type & size
  → Phase 3: scrub image metadata in memory
  → created_at = now (µs)
  → seal(title), seal(body)       AES-256-GCM, fresh nonce each, HMAC-SHA-256, timestamp = created_at
  → seal(evidence bytes)          same, bound to the new random file name
  → store: submissions.title / .content = "p5:" + base64url(package)
           instance/evidence/<random>.<ext> = package bytes (0600)
```

Plaintext never reaches the database or the disk. Uploads are held in memory
(Phase 3), scrubbed, encrypted, and only then written.

## 4. Decryption / authorization flow (journalist)

```
request
  → authenticate        signed session, re-read from the DB every request
  → authorize           blueprint gate + @journalist_required (JOURNALIST + AUTHORIZED)
  → retrieve            protected row / file (evidence must belong to the submission in the URL)
  → verify HMAC-SHA-256 constant time; failure → stop
  → validate timestamp  not in the future (> skew); equals the record's created_at
  → decrypt AES-256-GCM tag checked again
  → display / download  escaped HTML; evidence as an attachment, from memory
```

Authorization comes **before** any cryptographic work. Anonymous users,
admins, and pending or disabled journalists never trigger a decryption (the
tests assert this). Admins still see **counts only**. Being an admin grants no
access to plaintext.

If any check fails, nothing is shown. The journalist gets a 409 page, the event
is audited as `submission.integrity_failed` or `evidence.integrity_failed`
(with the reason: `malformed`, `hmac`, `timestamp` or `decrypt`), and inbox
rows that fail show "integrity check failed" while the rest of the inbox keeps
working. The source's `/status` page still shows the status but not the title,
and that audit entry carries no IP and no actor.

Reads **never fall back to plaintext**: an unprotected value in a protected
column is treated as tampering.

---

## 5. Timestamp and replay protection

Every package carries its timestamp inside the HMAC-protected header, and that
timestamp is the creation time of the record it belongs to. On every read:

1. **Modified timestamp** → the HMAC fails.
2. **Future-dated** (more than `PHASE5_MAX_CLOCK_SKEW_SECONDS`, default 300 s,
   ahead of the server clock) → rejected as stale/invalid.
3. **Different time from its record** → rejected as stale or replayed. This
   catches an authentic package that was sealed at another time (for example,
   an older copy restored from a backup) being substituted into a record, or a
   record whose `created_at` was altered.

This is replay protection for **stored** data. The protected timestamp is
internal: sources and journalists still see the normal "Submitted / Received /
Last updated" times. There is no maximum age, because a report must stay
readable however long it has been stored.

---

## 6. Key management

| Rule | How |
|---|---|
| Keys come only from the environment | `PHASE5_ENCRYPTION_KEY`, `PHASE5_HMAC_KEY` (read via `.env` / environment in `phase2/config.py`) |
| Never hard-coded | No key literals in the source (a test scans for them). The test suite generates fresh random keys on every run |
| Never stored in SQLite | Keys are not written anywhere by the app. A test inspects the raw database file for them |
| Validated | base64url text decoding to exactly 32 bytes (256 bits). Obvious placeholders (e.g. all-zero bytes) are rejected, and the two keys must differ |
| Fail safely | Missing or invalid keys → the app **refuses to start** (every environment) with instructions. Error messages never contain key material |
| Not lying around | After validation the keys are removed from `app.config` and kept only in `app.extensions["phase5_keys"]`, whose `repr` is redacted |
| Separation | Independent keys for encryption and for HMAC |

**Rotation** is not automated. Changing a key makes existing data unreadable,
so re-encrypting under new keys is a future task. The format's version byte
leaves room for it.

---

## 7. Storage and schema

* **No new tables and no new columns.** `submissions.title` and
  `submissions.content` keep their names and now hold `p5:` + base64url
  packages. SQLite does not enforce the old `VARCHAR(200)` length, so existing
  databases need no migration of the schema. In the model the attributes are
  renamed to `title_sealed` / `content_sealed` (and the title type widened to
  `Text`), so nothing can read them as plaintext by mistake.
* Evidence files in `instance/evidence/` hold packages, not images.
  `submission_evidence.size_bytes` is the size of the scrubbed plaintext.
* Evidence stays private: random names, a `0700` directory, `0600` files, no
  static route. Downloads are decrypted in memory and streamed as attachments.
* `token_hash`, `status` and the timestamps stay in plaintext, because they are
  needed for lookup, filtering and counts. None identifies the source.

### Data stored before Phase 5

Older rows and files are plaintext, and the application refuses to show them
(they fail verification). Encrypt them once:

```bash
flask --app app protect-legacy-data --dry-run
flask --app app protect-legacy-data
```

Legacy images and text are scrubbed of metadata (Phase 3) first. Files that
cannot be scrubbed (e.g. PDFs from before Phase 3) are encrypted anyway, with a
warning. Each run is audited (`legacy.protected`) and safe to repeat.

---

## 8. Tests

`tests/test_phase5.py` (69 tests) covers:

* round trips for text and bytes; ciphertext hides the plaintext; AES-256 key size
* a unique nonce per encryption, taken from `os.urandom`
* tampering with the timestamp, nonce, ciphertext, GCM tag, HMAC, header, length
* wrong HMAC key (→ `hmac`), wrong encryption key (→ `decrypt`), context binding
* **HMAC and timestamp checked before any decryption** (decrypt is never called on a bad package); constant-time comparison is used
* stale, replayed and future-dated packages
* missing, short, long, non-base64, placeholder and identical keys; the app refuses to start; keys absent from `app.config`, the database file and the source
* raw database and evidence bytes contain no plaintext
* journalist access; anonymous/admin/pending/disabled users refused **before** decryption
* tampered or swapped reports and evidence in the running app; audit entries contain no secrets
* `protect-legacy-data`; a full Phase 1→5 end-to-end flow

The critical checks were also **mutation-tested**: removing the HMAC check,
removing the replay check, reusing a fixed nonce, or adding a plaintext fallback
each makes the Phase 5 tests fail.

---

## 9. Security limitations

* **Server-side, not end-to-end.** Whoever controls the running server (or can
  read its environment) can decrypt everything. Admins cannot do so through the
  application, but a server operator can.
* **Keys live in environment variables** on the same machine as the data.
  There is no hardware security module or key management service.
* **No automated key rotation**, and no per-record keys.
* **Metadata stays visible:** row count, status, timestamps and evidence file
  sizes (ciphertext length ≈ plaintext length) are not hidden.
* **Replay protection covers stored data.** It does not stop a captured
  submission request from being re-sent to create a duplicate report (CSRF
  tokens limit this to the same session).
* Decrypted data exists in server memory while a page or download is served.
* Deleting or replacing a file does not securely erase the old disk blocks.
* No transport security is added here: run behind HTTPS (and set
  `PHASE2_COOKIE_SECURE=true`). Phase 6 (WebSockets / traffic analysis / Tor)
  is not implemented.
