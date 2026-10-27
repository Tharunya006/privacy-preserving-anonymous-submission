# Security Analysis (admin)

Admin-only pages that **measure** properties of the Phase 5 encryption: the
stored ciphertext of real reports, plus controlled experiments for the metrics
that need plaintext or keys. Nothing here changes the encryption, keys, schema
or stored data.

> **Statistics do not prove security.** An entropy near 8 bits, a flat
> histogram or near-zero correlation shows only that no pattern is *visible* in
> the ciphertext. Security rests on AES-256-GCM and HMAC-SHA-256 being sound,
> the keys staying secret, and nonces never repeating.

---

## 1. Pages and access

| Route | Shows |
|---|---|
| `GET /admin/security-analysis` | every stored report: reference, status, date, whether its text and evidence are encrypted, legacy or missing |
| `GET /admin/security-analysis/submissions/<id>` | stored ciphertext of the title and body, package parts, ciphertext-only metrics, cipher-image of each evidence file, size-matched performance |
| `GET /admin/security-analysis/submissions/<id>/evidence/<eid>/cipher.png` | the first 256×256 stored ciphertext bytes as a grayscale PNG |
| `GET /admin/security-analysis/experiments` | text and image metrics on synthetic data with temporary keys, plus performance |
| `GET /admin/security-analysis/hashing` | SHA-256 hashing analysis on synthetic messages, and a list of every report (see §7) |
| `GET /admin/security-analysis/submissions/<id>/hashing` | per-report SHA-256 analysis of the stored ciphertext and how the report's integrity is protected (see §8) |

* **Admins only.** Each route has `@admin_required`, and the admin blueprint's
  `before_request` gate applies too. Anonymous users are redirected to the login
  page, and journalists get 403.
* **Ciphertext only, never plaintext.** The views read the stored value or the
  stored file bytes and split the `P5` package into its parts
  (`submissions/security_analysis.py: parse_package`). No key is involved. They
  do not import or call `open_report`, `open_title` or `read_evidence_file`, and
  the tests fail if any of these is called or if a production key reaches
  `open_package`.
* **Legacy records are withheld.** A title, body or file stored before Phase 5
  is still plaintext. It is labelled "Legacy unencrypted record: stored value
  withheld" and never displayed or visualised (its `cipher.png` is a 404).
  Missing or malformed files are labelled instead of raising an error.
* **Audited.** Each page view writes `analysis.viewed` with the admin, the page
  (`overview`, `experiments` or `submission:<id>`) and the IP address. No
  ciphertext, sizes or content are recorded. The cipher-image is not audited
  separately because it is loaded by the report page.
* **Not cached.** `/admin/*` responses carry `Cache-Control: no-store`. The
  cipher-image needs an admin session, and evidence is never served statically.
* **Read-only.** No record or file is written, re-encrypted or migrated. A test
  compares every row and every file (hash and modification time) before and
  after visiting all the pages.

The admin dashboard text now says admins see counts and ciphertext, never
report content.

---

## 2. Which metrics run where

Every one of the 13 metrics shows a number on each report page. Each row is
labelled with where its value comes from:

| Metric | Report page | Label | Experiments page |
|---|---|---|---|
| **Text:** entropy, frequency (χ²), correlation | measured on this report's stored ciphertext | *This report* | ✓ (also against the plaintext) |
| **Text:** avalanche effect, key sensitivity | controlled experiment on synthetic text **of the same length** as this title / text | *Synthetic experiment* | ✓ (2,048 bytes) |
| **Image:** histogram, entropy, pixel correlation | measured on this file's stored ciphertext and its cipher-image | *This report* | ✓ (original vs encrypted) |
| **Image:** NPCR, UACI, key sensitivity, MSE/PSNR, SSIM | controlled experiment on a synthetic image **sized to this file** (√bytes per side, 64–256 px), scrubbing comparison in **this file's format** | *Synthetic experiment* | ✓ (128×128, PNG and JPEG) |
| Performance | size-matched synthetic data | — | 200 B, 20 KB, 1 MB, 10 MB |

A *Synthetic experiment* value describes the encryption method on data like
this report's; it is never presented as a measurement of the report itself.
All security metrics and experiments are **admin-only**: the journalist report
page shows the report, its evidence and the status workflow, and no metrics.

**Controlled experiments** use generated data: an English sentence repeated to
2,048 bytes, and a 128×128 gradient with shapes. They are encrypted with
`crypto.Keys(os.urandom(32), os.urandom(32))`, keys that exist only during the
request. The production keys are never read (a test makes `protection_keys()`
fail).

**Real evidence** is the encrypted *file* (PNG/JPEG bytes after metadata
scrubbing), not raw pixels. Its "image" metrics therefore describe the
ciphertext bytes. In the experiment, raw pixels are encrypted, so the
ciphertext is itself a cipher-image of the same size.

### Why the avalanche and NPCR results show two cases

AES-GCM is AES in counter mode plus a GHASH tag. With the **same key and
nonce**, flipping one plaintext bit flips exactly one ciphertext bit. It has
no diffusion by design. Its security comes from never reusing a nonce. The
experiments therefore report:

* **Fixed nonce:** an isolated test that calls `AESGCM` directly. Production
  never does this. Ciphertext change ≈ 1 bit, and the tag changes ≈ 50 %.
* **Production:** `crypto.seal` with a fresh random nonce. The whole package
  changes ≈ 50 %, and NPCR/UACI reach their ideal values.

### MSE / PSNR / SSIM

These measure **fidelity, not secrecy**, so they are used only to compare two
versions of the same image:

1. original vs decrypted (round trip): must be identical;
2. original PNG vs metadata-scrubbed PNG (Phase 3, lossless): must be identical;
3. uploaded JPEG vs metadata-scrubbed JPEG (Phase 3 re-encodes at quality 95):
   a small, measurable loss.

Comparing an image with its ciphertext by PSNR/SSIM is not meaningful and is not
done.

---

## 3. Methods

| Metric | Method | Unit / ideal |
|---|---|---|
| Entropy | Shannon, H = −Σ p·log₂p over byte values | bits/byte. 8 is the maximum, and n bytes can reach at most log₂ n |
| Frequency | 256-bin histogram and χ² against uniform | χ² ≈ 255 for uniform, with 293.25 the p = 0.05 critical value (255 degrees of freedom). Meaningful only from 1,280 bytes |
| Correlation | Pearson: each byte vs the next; plaintext vs ciphertext byte-by-byte | −1 … 1, ideal ≈ 0 |
| Pixel correlation | Pearson over all adjacent pairs, horizontal / vertical / diagonal | natural images ≈ 0.9+, cipher ≈ 0 |
| Avalanche | flip one plaintext bit (32 positions) and take the mean % of output bits changed. Both packages use the same timestamp; the fixed 11-byte header is excluded, so nonce, ciphertext, tag and HMAC are compared | % (≈ 50 for diffusion) |
| Key sensitivity | flip one key bit (32 positions) and take the mean % changed. Then open a package with the changed key | ≈ 50 %. Every attempt must be rejected |
| NPCR / UACI | one pixel changed by one level, then compare the two cipher-images | % (ideal 99.61 / 33.46) |
| MSE / PSNR | mean squared error; PSNR = 10·log₁₀(255²/MSE) | MSE in levels², PSNR in dB (∞ when identical) |
| SSIM | Wang et al. (2004), 8×8 windows, stride 4, on 8-bit luminance | 0 … 1, 1 = identical |
| Performance | `seal` / `open_package` (including the HMAC and timestamp checks), median of 5 runs (3 above 1 MB), `time.perf_counter_ns` | ms and MB/s (10⁶ B/s) |

Statistics on ciphertext over 2 MiB use its first 2 MiB (the page says so).
Correlation is sampled to at most 200,000 pairs. Everything is plain Python
plus Pillow and `cryptography`. No dependency was added.

---

## 4. Example results (one run on the development Mac)

Values are re-measured on every page load and vary slightly between runs.

| Metric | Measured |
|---|---|
| Text entropy | plaintext 4.377 → ciphertext 7.905 bits/byte (max 8) |
| Text χ² | plaintext 33,532 → ciphertext 259.8 |
| Text correlation | plaintext↔ciphertext −0.001; ciphertext serial 0.000 |
| Avalanche | fixed nonce: ciphertext 0.0061 % (one bit), tag 48.7 %; production package 49.8 % |
| Key sensitivity (text) | ciphertext 49.9 %, HMAC 49.5 %; 32/32 wrong encryption keys and 32/32 wrong HMAC keys rejected |
| Image entropy | 6.119 → 7.989 bits |
| Image χ² | 161,881 → 242.7 |
| Pixel correlation H / V / D | original 0.967 / 0.965 / 0.932 → encrypted −0.014 / 0.003 / 0.006 |
| NPCR / UACI | fixed nonce 0.0061 % / 0.00002 %; production 99.66 % / 33.12 % |
| Key sensitivity (image) | NPCR 99.56 %, UACI 33.13 %, 49.7 % bits; wrong key rejected |
| MSE / PSNR / SSIM | round trip 0 / ∞ / 1; scrubbed PNG 0 / ∞ / 1; scrubbed JPEG 0.924 / 48.48 dB / 0.9967 |
| Performance | 20 KB: 0.013 ms each way; 10 MB: encrypt 4.48 ms, decrypt 4.50 ms (≈ 2.2 GB/s) |

---

## 5. Limitations

* Statistical tests can reveal bias but cannot prove security (see the top of
  this page).
* Short values (a title is often under 100 bytes) cannot reach 8 bits/byte, and
  χ² is not meaningful for them. The page marks this.
* Avalanche, key sensitivity, NPCR/UACI and MSE/PSNR/SSIM are measured on
  synthetic data sized to each report (labelled *Synthetic experiment*).
  Measuring them on the real report would require decrypting it and using the
  production keys, which this feature never does.
* An evidence image's pixel size is not known without decrypting it, so the
  synthetic image is sized from the file's byte count, not its dimensions.
* Empty input has no defined value: the functions return `None` (shown as
  "n/a"), never a stand-in 0 or 1. PSNR is ∞ for identical images (MSE = 0),
  which is its correct value.
* Timings depend on the machine, its load and AES hardware support. They cover
  encryption only, not Phase 3 scrubbing or network time.
* The overview lists per-report metadata (reference, status, dates, encryption
  state) to admins. This metadata was already stored in plaintext (Phase 5 §9),
  but it was previously shown to admins only as counts.

## 6. Files

| File | Role |
|---|---|
| `submissions/security_analysis.py` | metrics, package parsing (no keys), experiments, performance |
| `submissions/hash_analysis.py` | SHA-256 hashing analysis on synthetic, seeded messages (no database, keys or services) |
| `phase2/blueprints/admin.py` | the six routes (appended; existing routes unchanged) |
| `phase2/templates/phase2/analysis_*.html`, `_analysis_ui.html` | pages and SVG charts (CSP-compatible: no inline styles or scripts) |
| `phase2/templates/phase2/base.html`, `admin_dashboard.html` | nav link; dashboard wording |
| `phase2/static/phase2/style.css` | styles appended at the end |
| `tests/test_security_analysis.py` | metrics, parsing, experiments, access, no plaintext, no production keys, legacy, audit, read-only |
| `tests/test_hash_analysis.py` | hashing methodology (incl. weak functions detected), toy attacks, isolation, access, audit |
| `tests/test_journalist_metrics.py` | the journalist page shows no metrics and runs no analysis; admin keeps them |

## 7. Hashing analysis (`/admin/security-analysis/hashing`)

Admin only, audited as `analysis.viewed` / `hashing`. Every message is
synthetic and generated from a fixed seed (`hash_analysis.DEFAULT_SEED`); no
stored token hash, HMAC, GCM tag, key or report is read, and the database is
not queried. The whole page takes well under a second.

| Section | Method | Ideal value |
|---|---|---|
| Hash correlation (strict avalanche criterion) | 64 random 64-byte messages × 128 evenly spaced input bits flipped (8,192 flips); per output bit: flip rate | mean 0.5 (z-score shown); largest per-bit deviation within ≈ SE·√(2 ln 512); χ² over the 256 bits (256 df) with p ≥ 0.001 |
| Digest correlation | phi coefficient between the bits of the two digests of each flipped pair | 0 (SE = 1/√(bit pairs)) |
| Hamming distance | differing digest bits per pair | Binomial(256, ½): mean 128, SD 8 |
| Modified messages | 1,000 synthetic sentences per change: one bit flipped, one character changed, one byte appended, two words swapped | mean 128, SD 8, φ ≈ 0 |
| Preimage toy | SHA-256 **truncated** to 8, 12, 16 bits; brute-force a message matching a secret message's truncated digest (64 / 32 / 16 searches) | mean attempts ≈ 2ᵗ (± 2ᵗ/√searches) |
| Second-preimage toy | same truncations; find m₂ ≠ m₁ with the same truncated digest | ≈ 2ᵗ |
| Restricted candidate space | full SHA-256 of a synthetic 4-digit PIN: all 10,000 candidates tried | recovered at once — contrast with the app's 192-bit tokens |

The p-value uses the Wilson–Hilferty approximation (no SciPy). The tests run
the same code against deliberately weak functions (copying the input, XOR
folding) and require them to be flagged, so the method is shown to detect bias.

The page also distinguishes the four mechanisms: SHA-256 (unkeyed fingerprint;
token storage, inside HMAC and PBKDF2), HMAC-SHA-256 (keyed; every stored
package, checked before decryption), the AES-GCM tag (keyed, GHASH-based;
checked during decryption) and digital signatures (public-key; RSA-PSS over
every newly accepted report since Phase 7 -- see [`signatures.md`](signatures.md)).

**Limits:** passing these tests does not prove SHA-256 secure; samples are
small; the attacks are generic brute force on truncated toys; the 256-bit
estimate assumes classical brute force (Grover: ≈ 2¹²⁸ steps); collision
resistance (≈ 2¹²⁸) is not tested.

**Refined methodology (applies to §7 and §8).** Under the ideal-hash model the
digest of every different input is an independent uniform 256-bit string, so a
one-bit input change flips each output bit with probability ½, independently.
Four consequences are tested at α = 0.001 each:

| Test | Statistic | Ideal |
|---|---|---|
| Balance | mean flip rate, z-test | 0.5 |
| Per output bit | χ² over the 256 flip counts (256 df) | p ≥ 0.001 |
| Independence | variance of the Hamming distance, (T−1)s²/64 vs χ²(T−1), two-sided | 64 |
| Relation | φ between the two digests' bits, z-test | 0 |

The independence test was added because a function whose output repeats half
of itself has a perfect flip rate but dependent output bits; the tests show it
is flagged. Outcomes read "no evidence of deviation", "deviation flagged" or
"too few flips to judge" (under 64 flips) — never "secure". Four tests per
input give about a 0.4 % false-alarm rate per input.

## 8. Per-report hashing analysis (`/admin/security-analysis/submissions/<id>/hashing`)

Admin only, audited as `analysis.viewed` (target = the report reference, detail
`hashing`). Every report is listed on the Hashing page and has its own page.

* **Ciphertext analysis** — input: each item's stored AES-GCM ciphertext body
  (header, nonce, GCM tag and HMAC removed; evidence: first 1 MiB). Up to 256
  evenly spaced bits are flipped; the four tests above are applied. Only
  statistics are returned — no digest of stored data.
* **Synthetic messages** — generated sentences of the same length as each item
  (up to 16 KiB), changed four ways; Hamming distance and φ.
* **Plaintext analysis** — none. Legacy (unencrypted) items are listed but not
  processed at all; missing or malformed files are labelled.
* **Integrity** — key-free consistency checks only (package structure; header
  timestamp equals the record's time). The GCM tag and HMAC are shown as
  present/length, never their values. Authenticity is **not** verified on this
  page: that needs the server's HMAC key and happens whenever a journalist opens
  the report or downloads evidence. Integrity failures recorded in the audit log
  are shown as history, explicitly not as a current verification.
* **Preimage / second preimage** — not measured per report (the cost is ~2²⁵⁶
  for any input); the page links to the bounded toys in §7.

**Limits:** SHA-256 behaves the same for every input, so every report is
expected to look ideal — these are not per-report security scores; one input
and ≤256 flips per item; first-order statistics only.

## 9. Authentication values and colour images

* The admin report page shows the **ciphertext body** only. The GCM tag and the
  HMAC are shown as "present · N bytes · value hidden"; the full stored value
  (which contains them) is never sent to the browser.
* Image experiments keep colour: a colour image is encrypted as its RGB bytes
  (3 per pixel) and both the original and the encrypted noise are shown in
  colour; a grayscale image stays one byte per pixel. Histogram, entropy, NPCR
  and UACI use every channel value; pixel correlation is per channel and
  averaged; MSE/PSNR/SSIM compare brightness.
* Real evidence pictures: **image files** (PNG, JPEG, GIF, WebP) are drawn as
  **colour noise** — each 3 ciphertext bytes form one RGB pixel; text files
  (TXT, CSV) as grayscale. The mode comes from the file type alone; nothing is
  decrypted, so a grayscale photo is also drawn as colour noise. The colours
  are random: correctly encrypted data carries no colour or tint from the
  original (a visible tint would be an information leak). The pixel
  correlation shown for the picture is per channel, averaged.

## 10. Metrics audit (corrections)

**Stored representations (report page, actual data, admin only).** For every
encrypted item: the **envelope** (complete stored package — for text the
base64url-decoded column, for evidence the file) and the **payload** (AES-GCM
ciphertext only; envelope = payload + 71 bytes), each with size, SHA-256 (all
bytes), byte distribution and entropy (first 2 MiB). The digest is of stored
*encrypted* bytes — never of the original — and is not proof of authenticity.
Equal digests mean identical stored bytes, so a digest can link copies of the
same stored item (backups, exports) to the report; fresh nonces mean repeated
content gives different digests. Digests appear only on admin pages — never in
logs, URLs or the audit log. Legacy items are listed and never hashed.

**Real-target truncated-digest experiments (per-report page).** Target: first
*t* ∈ {8, 12, 16, 20} bits of SHA-256 of one stored representation (envelope or
payload). Preimage candidates: `"ppass-preimage-candidate:" + counter`;
second-preimage candidates: `stored bytes + "|ppass-second-preimage:" + counter`
(always different from the original). Budget ≤ 16·2ᵗ attempts, 20 s of search;
the worker is killed after 45 s. The request only validates and enqueues
(POST + CSRF, audited without digests); the search runs in a separate process
(`python -I -S submissions/hash_worker.py`: standard library only, clean
environment, CPU-time limit, never imports the app or `.env`). One job at a
time, ≤ 3 queued or running, 10 s cooldown per admin; results in memory only.
Every match is re-verified by the worker and independently by the server.
"Budget exhausted" / "time limit reached" are reported as such. Truncated
experiments do not break SHA-256 and are not security scores.

**Digital signatures.** Since Phase 7 the server signs every newly accepted
report ([`signatures.md`](signatures.md)); the overview has a Signature column
and each report page a "Digital signature" panel. Separately, the Controlled
experiments page runs an RSA-PSS (SHA-256, MGF1-SHA-256, 32-byte salt,
3072-bit) experiment with key pairs created and discarded per page load:
sign/verify timings, and rejection of a modified message, an altered signature
and a wrong public key.

**Corrected experiment labels.** Avalanche, NPCR and UACI are now shown as
**controlled diagnostics with a fixed nonce** (AES-GCM: one ciphertext bit /
value changes by design; the GCM tag changes ~50 %) — not security scores.
Nonce randomization is shown separately with a control (the same input
encrypted twice): ~50 % / NPCR ~99.6 % even with no input change, so those
numbers reflect the random nonce, not diffusion. The evidence picture's
histogram and correlation are labelled as ciphertext byte statistics, not
image pixels. Image experiment inputs: raw 8-bit RGB (or grayscale) pixel
bytes, row-major, no file format or compression.

