# Phase 7 — Server signatures for accepted submissions

Every report accepted from now on is signed by the server with **RSA-PSS +
SHA-256** (MGF1-SHA-256, 32-byte salt, RSA-3072). The signature is created in
the same database transaction that stores the report, so a report is stored
signed or not at all.

## What a valid signature proves — and what it does not

**Proves:** the signed stored data (the encrypted title, the encrypted report
text, every stored evidence file and the metadata listed below) has not changed
since the server accepted the report, and it was signed with a key this server
trusts.

**Does not prove:**

* who submitted it — sources stay anonymous; nothing about the source is signed;
* that the report is true;
* anything against someone who controls the server *and* its private key — they
  could sign different data. Keep the key file and passphrase secret.

Status changes (Submitted → Under review → Closed) and `updated_at` are **not**
signed, because they change during normal work.

## Exactly what is signed (manifest v1)

```
"PPASS-SUBMISSION-MANIFEST\0" || version (1 byte)
then, in this order, each field = len(name) u16 || name || len(value) u32 || value:
  algorithm            "RSASSA-PSS-SHA256"
  key_id               signing key ID (32 hex chars)
  submission_id        u64
  created_at           u64, microseconds since the epoch (UTC)
  signed_at            u64, microseconds
  title_envelope_sha256    SHA-256 of the stored encrypted title package
  content_envelope_sha256  SHA-256 of the stored encrypted report package
  evidence_count       u32
  per evidence file, sorted by id:
    evidence_id, stored_name, extension, size_bytes, evidence_created_at,
    evidence_envelope_sha256 (SHA-256 of the stored file)
```

"Package" means the exact stored Phase 5 bytes (AES-256-GCM + HMAC). The
manifest is built from what is stored, so verification needs **no decryption
and no Phase 5 key** — only the public key. The token hash is not included
(it is already bound into each package's HMAC).

The signature is stored in its own table, `submission_signatures`
(one row per report: key ID, algorithm, manifest version, signed time,
signature bytes). The private key is never stored in the database.

## Verification results

| Result | Meaning |
|---|---|
| Valid | Stored data unchanged since signing; trusted key. |
| Invalid | Data, metadata, evidence (changed, swapped, missing, added) or signature changed. |
| Missing signature | A report from after signing started has no signature. |
| Unknown key | Signed with a key that is not trusted here (e.g. retired key not installed). |
| Unsigned (legacy) | Accepted before Phase 7; never signed (no backfill). |
| Malformed signature record | Unsupported algorithm/version or wrong signature length. |
| Verification error | The check itself failed. |

Only **Valid** is valid. Anything else means: treat the stored data as unverified.
"Legacy" is decided by the `signing_settings` marker: the ID of the first
signed report. Lower IDs are legacy; higher IDs without a signature are "Missing".

## Where it appears

* **Admin → Security analysis** (`/admin/security-analysis`): a *Signature*
  column with one badge per report.
* **Admin → Security analysis → Analyse** (`/admin/security-analysis/submissions/<id>`):
  a *Digital signature* panel — result, reason, key ID, algorithm, signed time,
  manifest version and an explanation. The signature bytes and the manifest are
  not shown.
* Journalist pages are unchanged.
* CLI: `flask --app app verify-signatures` (exit code 1 if any report is not
  Valid or Unsigned (legacy)).

## Key setup

```bash
flask --app app generate-signing-key --out-dir ~/ppass-signing-keys
```

You are asked for a passphrase (twice, hidden, at least 12 characters). The
command refuses a directory inside the project, writes
`signing-<keyid>.pem` (encrypted PKCS#8, mode 600) and
`signing-<keyid>.pub.pem`, and prints the lines to add to `.env`:

```
PHASE7_SIGNING_KEY_FILE=/absolute/path/signing-<keyid>.pem
PHASE7_SIGNING_KEY_PASSPHRASE=<your passphrase>
```

Then run `flask --app app init-db` (creates the two new tables) and restart.

Startup rules:

* No key configured → the app starts, but `/submit` answers "temporarily
  unavailable" (HTTP 503) and stores nothing.
* Key configured but unusable (missing file, wrong passphrase, file readable by
  group/others, not RSA, < 3072 bits) → the app refuses to start.
* The passphrase is removed from the Flask config after loading; no key is ever
  generated automatically (tests use an in-memory key only).

The key ID is the first 16 bytes (hex) of SHA-256 over the public key, so it
always matches the key.

## Key rotation

1. Generate a new key pair; point `PHASE7_SIGNING_KEY_FILE` at the new key.
2. Copy the **old public key** (`signing-<oldid>.pub.pem`) into a directory and
   set `PHASE7_TRUSTED_PUBLIC_KEY_DIR` to it (directory not writable by
   others).
3. Restart. New reports are signed with the new key; old reports still verify.
   Without the old public key they show "Unknown key", never "Valid".

A server with only the trusted directory (no private key) can still verify.

## Interaction with other commands

* `scrub-evidence` **skips signed reports** (their evidence was cleaned at
  intake; rewriting it would invalidate the signature).
* `protect-legacy-data` only touches pre-Phase-5 data, which is unsigned.

## Failure handling

* Signing or commit fails → the transaction is rolled back and the evidence
  file just written is removed; the source sees "temporarily unavailable";
  nothing is stored (no report, evidence, signature or audit entry).
* Two first-ever submissions racing to create the marker row: one commit fails
  with a unique-key error and that submission is rolled back (the source can
  retry). This can only happen once.

## Files

`submissions/signing.py` (keys, manifest, sign/verify),
`submissions/services.py` (`sign_submission`, `verify_submission_signature`),
`submissions/models.py` (`SubmissionSignature`, `SigningSettings`),
`submissions/cli.py` (commands), `phase2/blueprints/admin.py` + templates (UI),
`tests/test_signatures.py`.
