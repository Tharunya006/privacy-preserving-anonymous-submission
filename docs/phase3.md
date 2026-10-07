# Phase 3 — Anonymous Submission with Evidence Metadata Scrubbing

Phase 3 makes evidence uploads safe for an anonymous source: hidden metadata
that could identify them — GPS position, camera make/model/serial number, date
taken, editing software, author names — is removed **before** the file is
stored, and only the cleaned file is ever kept.

It is ported into the integrated application (Phase 1 + 2 + 3 + 4 in one Flask
app and one database); it does not add a second app, route set or database.

---

## 1. Where it came from, and what changed

The original work is commit `a1dcabb` on `origin/bhavya/phase3`. It was written
against the pre-integration Phase 1 `app.py`, so it was **ported, not merged**.

| Kept from `origin/bhavya/phase3` | Why |
|---|---|
| Pillow-based scrubbing: decode the image, copy only the pixels into a new image, save that | The right core technique — nothing but pixels survives |
| Image allow-list `.jpg .jpeg .png .gif .webp` | Same accepted image types |
| Scrub first, keep only the cleaned file | Same rule, enforced more strictly (below) |

| Not ported | Reason |
|---|---|
| Raw-`sqlite3` `app.py`, `database/app.db`, old templates, `/test-submissions`, plaintext `/login` | Replaced during the Phase 1/2 integration (XSS, plaintext passwords, public data dump) |
| Token `"SUB-" + token_hex(8)` stored in plaintext | Weaker than the existing 192-bit token stored only as a SHA-256 hash |
| Storage in `uploads/<token>/<original filename>` | Put the source's token on disk and kept the identifying original filename, with no database record or access control. Evidence stays in `instance/evidence/` under random names, served only to authorized journalists |
| `temp_<name>` copy of the **original** written to disk before scrubbing | The unscrubbed file reached the disk, and was left behind if scrubbing failed. Scrubbing is now done entirely in memory |

Problems fixed in `metadata_scrubber.py` while porting it:

| Problem in the original | Fix in `submissions/scrubber.py` |
|---|---|
| No error handling — a corrupt or fake image crashed the request (and left the temp original behind) | Every decoder error becomes a `ScrubError` with a safe message; the upload is refused and nothing is stored |
| No decompression-bomb protection | A pixel limit (40 MP) is checked from the header before decoding, and Pillow's bomb warning is treated as an error |
| Palette (`P`) images lost their palette (colours scrambled) and transparency | Palette and transparency index are copied explicitly |
| EXIF orientation dropped without being applied — photos came out sideways | `ImageOps.exif_transpose` is applied to the pixels first |
| Content not checked against its extension | The real format is detected from the content; a PDF renamed `.jpg` is refused, a JPEG named `.png` is stored as `.jpg` |
| No proof the output is clean | The output is decoded again; any EXIF, XMP, ICC, comment, PNG text chunk or unexpected JPEG APP segment causes rejection |
| Slow `list(image.getdata())` | `Image.frombytes(mode, size, image.tobytes())` |
| `Pillow` missing from the requirements | Added: `Pillow>=12.0,<13.0` |

---

## 2. How scrubbing works

```
browser ──multipart──► InMemoryUploadRequest   upload held in memory (never spooled to disk)
                          │
                          ▼
            services.read_evidence             allow-list + size limit (10 MB)
                          │
                          ▼
            services.create_submission ──► scrubber.scrub_evidence(ext, bytes)
                          │                   ├─ image: identify real format, verify(),
                          │                   │         pixel limit, first frame,
                          │                   │         exif_transpose, copy pixels into a
                          │                   │         new image, re-encode,
                          │                   │         assert_image_is_clean()
                          │                   ├─ txt/csv: strict UTF-8, no NUL, drop BOM
                          │                   └─ anything else: refused
                          ▼
            only the cleaned bytes ──► instance/evidence/<random>.<ext>  (0600)
                                   └─► submission_evidence row (size of the cleaned file)
```

* **Images (JPEG, PNG, GIF, WebP).** A brand-new image object is created from
  the raw pixel data, so its metadata dictionary is empty, and that is what gets
  encoded. EXIF (with the GPS IFD), XMP, IPTC, ICC profiles, JPEG `COM`
  comments and PNG `tEXt`/`iTXt`/`zTXt` chunks are all dropped — not by
  deleting known tags, but because only pixels are copied. JPEG and WebP are
  re-encoded at quality 95; PNG and GIF are lossless. Animated GIF/WebP keep
  only their first frame.
* **Plain text (TXT, CSV).** No embedded metadata exists; the file must be valid
  UTF-8 without NUL bytes (so an image or binary renamed `.txt` is refused).
* **PDF, Word, Excel, ODT and everything else are refused.** Their author and
  software metadata cannot be removed with Pillow, so storing them would break
  "save only the cleaned evidence".
* Scrubbing happens inside `create_submission`, before any database or disk
  write, so every code path (web form, `seed_db.py`, tests) gets it.
* The original is never written to disk. Werkzeug normally spools uploads over
  500 KB to a temporary file; `InMemoryUploadRequest` keeps them in memory
  instead (bounded by `MAX_CONTENT_LENGTH`, 11 MB).
* If anything fails, the source sees a clear message (400) and **nothing** is
  stored: no file, no submission, no audit entry.

The submit page tells sources that metadata is removed automatically — and that
this cannot hide what is *visible* in a picture (faces, reflections, screens).

---

## 3. Evidence stored before Phase 3

Evidence uploaded before this change was stored as uploaded. Clean it with:

```bash
flask --app app scrub-evidence --dry-run     # report only
flask --app app scrub-evidence               # clean in place
```

Images carrying metadata are re-encoded under a new random name and the old
file is deleted (audited as `evidence.scrubbed`); images that are already clean
are left alone, so the command is safe to re-run. Files that cannot be cleaned
(e.g. PDFs from before Phase 3) are **reported, never deleted** — review them
by hand.

---

## 4. Database

No schema change. `submission_evidence.size_bytes` and `extension` describe the
cleaned file. `scrub-evidence` updates `stored_name`, `extension` and
`size_bytes` for files it cleans.

---

## 5. Tests

`tests/test_phase3.py` (53 tests):

* metadata removal for JPEG, PNG, WebP and GIF — EXIF, GPS IFD, XMP, ICC,
  comments, PNG text chunks — checked both by decoding and by searching the raw
  bytes for the identifying strings;
* orientation applied; PNG pixels and palette/transparency preserved; CMYK JPEG;
  animated GIF; real format decides the stored extension;
* corrupt, truncated, fake and disallowed files refused; decompression bomb
  (a 60-byte PNG declaring 100 000 × 100 000) refused before decoding;
* through HTTP: exactly one file stored and it is the clean one; nothing stored
  on rejection; uploads above 500 KB never touch a temporary file;
* journalist download returns the clean image; Phase 2 access control and the
  Phase 4 workflow and audit log still behave; no filename or metadata in the
  audit log;
* `scrub-evidence`: dry run, cleaning, document reporting, idempotency.

Run: `pytest tests/test_phase3.py`, or `pytest` for the whole suite.

---

## 6. Limitations

* Only metadata is removed. Visible content (faces, reflections, documents in
  frame), and statistical traces such as sensor noise or JPEG quantisation
  tables, can still identify a camera or person.
* JPEG/WebP evidence is re-encoded (quality 95), so it is not byte-identical to
  the original; animated images keep only the first frame.
* PDF and office documents are not accepted at all.
* Evidence is not encrypted at rest — that is Phase 5.
* Overwriting/deleting files on disk does not securely erase the underlying
  storage blocks.
