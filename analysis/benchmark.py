"""Phase 6: timing of the cryptography and metadata scrubbing actually used.

Measures, on this machine, with the project's own code paths:

* AES-256-GCM encrypt / decrypt, HMAC-SHA-256 and SHA-256 at the real size
  limits (a title, the 20 000-character report limit, 1 MB, the 10 MB evidence
  limit);
* the full Phase 5 package: ``seal`` (nonce + AES-256-GCM + HMAC-SHA-256 +
  timestamp header) and ``open_package`` (HMAC check -> timestamp check ->
  decrypt), plus its size overhead;
* submission-token generation + SHA-256 hashing, and the PBKDF2 password hash;
* Phase 3 metadata scrubbing of realistic photos;
* end-to-end ``create_submission`` (validation + scrub + seal + database).

Usage:  python -m analysis.benchmark            (writes analysis/results/benchmark.{md,json})
        python -m analysis.benchmark --quick    (fewer iterations)
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import io
import json
import os
import platform
import secrets
import statistics
import tempfile
import time
from pathlib import Path

import cryptography
import PIL
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "analysis" / "results"

SIZES = [("title (200 B)", 200), ("max report (20 KB)", 20_000),
         ("1 MB", 1_000_000), ("max evidence (10 MB)", 10_000_000)]


def timeit(fn, runs: int) -> dict:
    fn()  # warm-up
    samples = []
    for _ in range(runs):
        t0 = time.perf_counter_ns()
        fn()
        samples.append((time.perf_counter_ns() - t0) / 1e6)
    samples.sort()
    return {"runs": runs, "median_ms": round(statistics.median(samples), 4),
            "mean_ms": round(statistics.fmean(samples), 4),
            "p95_ms": round(samples[min(len(samples) - 1, int(0.95 * len(samples)))], 4)}


def runs_for(size: int, quick: bool) -> int:
    base = 2000 if size <= 20_000 else (40 if size <= 1_000_000 else 8)
    return max(3, base // (10 if quick else 1))


def photo(width: int, height: int, fmt: str = "JPEG") -> bytes:
    """A photo-like test image (gradient + sensor-style noise) with EXIF + GPS."""
    gradient = Image.linear_gradient("L").resize((width, height))
    noise = Image.effect_noise((width, height), 40)
    image = Image.merge("RGB", (gradient, noise, Image.blend(gradient, noise, 0.5)))
    if fmt == "PNG":
        image = image.convert("RGBA")
    exif = Image.Exif()
    exif[0x010F], exif[0x0110] = "BenchMake", "BenchModel-SN-001"
    exif.get_ifd(0x8825)[2] = (51.0, 30.0, 12.0)
    buffer = io.BytesIO()
    image.save(buffer, format=fmt, exif=exif, **({"quality": 90} if fmt == "JPEG" else {}))
    return buffer.getvalue()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()
    quick = args.quick

    os.environ.setdefault("PHASE2_ENV", "testing")
    from phase2 import create_app
    from phase2.extensions import db
    from phase2.models import utcnow
    from phase2.services import create_user
    from submissions import crypto
    from submissions.scrubber import scrub_evidence
    from submissions.services import create_submission, generate_token, hash_token

    evidence_dir = tempfile.mkdtemp(prefix="ppass-bench-")
    app = create_app("testing", EVIDENCE_DIR=evidence_dir,
                     PASSWORD_HASH_METHOD="pbkdf2:sha256:600000")  # production strength
    results: dict = {"machine": {
        "platform": platform.platform(), "machine": platform.machine(),
        "python": platform.python_version(), "cryptography": cryptography.__version__,
        "pillow": PIL.__version__, "measured_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }}

    with app.app_context():
        db.create_all()
        keys = app.extensions["phase5_keys"]
        aes = AESGCM(keys.encryption)
        now = utcnow()

        prim, package = [], []
        for label, size in SIZES:
            data = secrets.token_bytes(size)
            n = runs_for(size, quick)
            nonce = os.urandom(12)
            ct = aes.encrypt(nonce, data, b"aad")
            prim.append({
                "size": label, "bytes": size,
                "aes_256_gcm_encrypt": timeit(lambda: aes.encrypt(os.urandom(12), data, b"aad"), n),
                "aes_256_gcm_decrypt": timeit(lambda: aes.decrypt(nonce, ct, b"aad"), n),
                "hmac_sha256": timeit(lambda: hmac.new(keys.mac, data, hashlib.sha256).digest(), n),
                "sha256": timeit(lambda: hashlib.sha256(data).digest(), n),
            })
            ctx = {"purpose": "bench", "binding": "record-1"}
            pkg = crypto.seal(keys, data, timestamp=now, **ctx)
            package.append({
                "size": label, "bytes": size, "package_bytes": len(pkg),
                "overhead_bytes": len(pkg) - size,
                "seal": timeit(lambda: crypto.seal(keys, data, timestamp=now, **ctx), n),
                "open_verified": timeit(lambda: crypto.open_package(
                    keys, pkg, expected_timestamp=now, **ctx), n),
                "reject_tampered": timeit(lambda: _expect_fail(
                    crypto, keys, pkg[:-1] + bytes([pkg[-1] ^ 1]), now, ctx), n),
            })
        results["primitives"] = prim
        results["phase5_package"] = package

        title = "x" * 200
        sealed_text = crypto.seal_text(keys, title, purpose="t", binding="b", timestamp=now)
        results["text_storage_overhead"] = {
            "plaintext_chars": len(title), "stored_chars": len(sealed_text),
            "note": "71-byte package overhead, then base64url (x4/3) plus the 'p5:' prefix",
        }
        results["token"] = {
            "generate_plus_sha256": timeit(lambda: hash_token(generate_token()), 2000 // (10 if quick else 1)),
        }
        user = create_user("bench-user", "Bench!Password1", status="AUTHORIZED",
                           must_change_password=False)
        results["password_pbkdf2_sha256_600k"] = {
            "hash": timeit(lambda: user.set_password("Bench!Password1"), 3),
            "verify": timeit(lambda: user.check_password("Bench!Password1"), 3),
        }

        scrub = []
        for label, w, h, fmt in [("JPEG 640x480", 640, 480, "JPEG"),
                                 ("JPEG 1920x1080 (2 MP)", 1920, 1080, "JPEG"),
                                 ("JPEG 4032x3024 (12 MP phone photo)", 4032, 3024, "JPEG"),
                                 ("PNG RGBA 1920x1080", 1920, 1080, "PNG")]:
            data = photo(w, h, fmt)
            ext = "jpg" if fmt == "JPEG" else "png"
            out_ext, clean = scrub_evidence(ext, data)
            scrub.append({"image": label, "input_bytes": len(data), "output_bytes": len(clean),
                          "scrub": timeit(lambda: scrub_evidence(ext, data), 3 if quick else 8)})
        results["metadata_scrubbing"] = scrub

        big_photo = photo(4032, 3024)
        report = "r" * 20_000
        results["end_to_end_create_submission"] = {
            "text only (20 KB report)": timeit(lambda: create_submission("t", report), 20 if quick else 100),
            "with 12 MP JPEG evidence": timeit(lambda: create_submission("t", report, ("jpg", big_photo)),
                                               3 if quick else 8),
        }
        _, clean_big = scrub_evidence("jpg", big_photo)  # scrubbed once, outside the timer
        results["breakdown_12mp_submission_ms"] = {
            "metadata scrubbing": scrub[2]["scrub"]["median_ms"],
            "seal title + report": round(package[0]["seal"]["median_ms"] + package[1]["seal"]["median_ms"], 4),
            "seal scrubbed photo": timeit(
                lambda: crypto.seal(keys, clean_big, timestamp=now, purpose="e", binding="b"),
                3 if quick else 8)["median_ms"],
        }
        db.session.remove()
        db.drop_all()

    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "benchmark.json").write_text(json.dumps(results, indent=2))
    (RESULTS / "benchmark.md").write_text(render(results))
    print((RESULTS / "benchmark.md").read_text())


def _expect_fail(crypto, keys, pkg, now, ctx):
    try:
        crypto.open_package(keys, pkg, expected_timestamp=now, **ctx)
    except crypto.IntegrityCheckError:
        return
    raise AssertionError("tampered package was accepted")


def render(r: dict) -> str:
    m = r["machine"]
    out = ["# Phase 6 timing benchmark (generated)", "",
           f"Machine: {m['platform']} ({m['machine']}), Python {m['python']}, "
           f"cryptography {m['cryptography']}, Pillow {m['pillow']}. Measured {m['measured_at']}. "
           "Median of repeated runs after a warm-up; times in milliseconds.", "",
           "## Cryptographic primitives", "",
           "| Data size | AES-256-GCM encrypt | AES-256-GCM decrypt | HMAC-SHA-256 | SHA-256 |",
           "|---|---|---|---|---|"]
    for p in r["primitives"]:
        out.append(f"| {p['size']} | {p['aes_256_gcm_encrypt']['median_ms']} | "
                   f"{p['aes_256_gcm_decrypt']['median_ms']} | {p['hmac_sha256']['median_ms']} | "
                   f"{p['sha256']['median_ms']} |")
    out += ["", "## Phase 5 protected package (as used for reports and evidence)", "",
            "`seal` = fresh nonce + AES-256-GCM + HMAC-SHA-256 over header/nonce/ciphertext. "
            "`open` = HMAC check (constant time) -> timestamp check -> AES-GCM decrypt. "
            "`reject tampered` = time to refuse a package with one flipped bit (stops at the HMAC).", "",
            "| Data size | seal | open (verify + decrypt) | reject tampered | size overhead |",
            "|---|---|---|---|---|"]
    for p in r["phase5_package"]:
        out.append(f"| {p['size']} | {p['seal']['median_ms']} | {p['open_verified']['median_ms']} | "
                   f"{p['reject_tampered']['median_ms']} | +{p['overhead_bytes']} B |")
    t = r["text_storage_overhead"]
    out += ["", f"Text columns: a {t['plaintext_chars']}-character title is stored as "
            f"{t['stored_chars']} characters ({t['note']}).", "",
            "## Hashing", "",
            "| Operation | median ms |", "|---|---|",
            f"| Submission token: generate (192-bit) + SHA-256 | {r['token']['generate_plus_sha256']['median_ms']} |",
            f"| Password hash, PBKDF2-SHA256 600 000 iterations | {r['password_pbkdf2_sha256_600k']['hash']['median_ms']} |",
            f"| Password verify (same cost, by design) | {r['password_pbkdf2_sha256_600k']['verify']['median_ms']} |",
            "", "## Metadata scrubbing (Phase 3)", "",
            "| Image (with EXIF + GPS) | input | stored | scrub time (ms) |", "|---|---|---|---|"]
    for s in r["metadata_scrubbing"]:
        out.append(f"| {s['image']} | {s['input_bytes']:,} B | {s['output_bytes']:,} B | {s['scrub']['median_ms']} |")
    e = r["end_to_end_create_submission"]
    out += ["", "## Total processing overhead per submission", "",
            "`create_submission` end to end: validation, scrubbing, three seals, database insert, "
            "audit entry and commit. The evidence file is written to disk; the database is the "
            "in-memory SQLite of the testing configuration, so SQLite file-write latency is not "
            "included.", "",
            "| Submission | median ms | p95 ms |", "|---|---|---|"]
    for name, v in e.items():
        out.append(f"| {name} | {v['median_ms']} | {v['p95_ms']} |")
    b = r["breakdown_12mp_submission_ms"]
    out += ["", "Note: JPEG/WebP evidence is re-encoded at quality 95, so the stored image can be "
            "larger than the upload (as for these noisy test photos).", "",
            "Breakdown of the 12 MP case (median ms): " +
            ", ".join(f"{k} {v}" for k, v in b.items()) +
            "; the rest is database and file I/O.", ""]
    return "\n".join(out)


if __name__ == "__main__":
    main()
