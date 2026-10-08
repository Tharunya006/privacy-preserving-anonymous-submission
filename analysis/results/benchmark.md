# Phase 6 timing benchmark (generated)

Machine: macOS-26.4.1-arm64-arm-64bit-Mach-O (arm64), Python 3.13.14, cryptography 50.0.2, Pillow 12.3.0. Measured 2026-10-08 23:53:34. Median of repeated runs after a warm-up; times in milliseconds.

## Cryptographic primitives

| Data size | AES-256-GCM encrypt | AES-256-GCM decrypt | HMAC-SHA-256 | SHA-256 |
|---|---|---|---|---|
| title (200 B) | 0.001 | 0.0003 | 0.0008 | 0.0003 |
| max report (20 KB) | 0.0031 | 0.0024 | 0.0065 | 0.006 |
| 1 MB | 0.1012 | 0.0996 | 0.2915 | 0.2909 |
| max evidence (10 MB) | 1.0206 | 1.0127 | 2.9192 | 2.9073 |

## Phase 5 protected package (as used for reports and evidence)

`seal` = fresh nonce + AES-256-GCM + HMAC-SHA-256 over header/nonce/ciphertext. `open` = HMAC check (constant time) -> timestamp check -> AES-GCM decrypt. `reject tampered` = time to refuse a package with one flipped bit (stops at the HMAC).

| Data size | seal | open (verify + decrypt) | reject tampered | size overhead |
|---|---|---|---|---|
| title (200 B) | 0.0037 | 0.0037 | 0.0018 | +71 B |
| max report (20 KB) | 0.0125 | 0.0126 | 0.0088 | +71 B |
| 1 MB | 0.4323 | 0.4299 | 0.3412 | +71 B |
| max evidence (10 MB) | 4.436 | 4.4263 | 3.6157 | +71 B |

Text columns: a 200-character title is stored as 367 characters (71-byte package overhead, then base64url (x4/3) plus the 'p5:' prefix).

## Hashing

| Operation | median ms |
|---|---|
| Submission token: generate (192-bit) + SHA-256 | 0.0012 |
| Password hash, PBKDF2-SHA256 600 000 iterations | 75.1894 |
| Password verify (same cost, by design) | 74.768 |

## Metadata scrubbing (Phase 3)

| Image (with EXIF + GPS) | input | stored | scrub time (ms) |
|---|---|---|---|
| JPEG 640x480 | 184,548 B | 244,097 B | 2.2011 |
| JPEG 1920x1080 (2 MP) | 1,242,067 B | 1,643,660 B | 14.6431 |
| JPEG 4032x3024 (12 MP phone photo) | 7,294,025 B | 9,655,782 B | 86.5576 |
| PNG RGBA 1920x1080 | 3,377,382 B | 3,377,250 B | 153.1311 |

## Total processing overhead per submission

`create_submission` end to end: validation, scrubbing, three seals, database insert, audit entry and commit. The evidence file is written to disk; the database is the in-memory SQLite of the testing configuration, so SQLite file-write latency is not included.

| Submission | median ms | p95 ms |
|---|---|---|
| text only (20 KB report) | 0.2628 | 0.3585 |
| with 12 MP JPEG evidence | 93.9171 | 96.572 |

Note: JPEG/WebP evidence is re-encoded at quality 95, so the stored image can be larger than the upload (as for these noisy test photos).

Breakdown of the 12 MP case (median ms): metadata scrubbing 86.5576, seal title + report 0.0162, seal scrubbed photo 4.2903; the rest is database and file I/O.
